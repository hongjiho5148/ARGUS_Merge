"""Orchestrate guideline 2-1 malicious file upload scan (httpx + optional ZAP)."""

from __future__ import annotations

import importlib.util
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.services.zap_util import ZapNotAvailableError
from diagnosis.context import DiagnosisContext
from diagnosis.probe_auth import (
    all_account_auths_with_meta,
    primary_account_auth,
    probe_request_headers,
    session_auth_mode,
    session_probe_tag,
)
from diagnosis.result import DiagnosisFinding

_MODULE_DIR = Path(__file__).resolve().parent


def _load_local(name: str):
    path = _MODULE_DIR / f"{name}.py"
    mod_name = f"diag_g21_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


_transport = _load_local("transport")


@dataclass
class ScanOptions:
    timeout: float = 15.0
    default_allowed_extensions: list[str] = field(
        default_factory=lambda: ["jpg", "jpeg", "png", "gif", "webp"]
    )
    max_targets: int = 20
    max_requests: int = 0          # 0 = 무제한; 양수 = 총 요청 수 상한
    httpx_enabled: bool = True
    zap_enabled: bool = False
    zap_passive_wait_seconds: int = 60
    interval_sec: float = 0.0      # 요청 간 딜레이(초) — 0이면 딜레이 없음
    enable_auth_modes: bool = True  # False 시 anonymous 패스만 실행


@dataclass
class ScanResult:
    findings: list[DiagnosisFinding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    status: str = "pass"
    message: str = ""


def _scan_options(raw: dict[str, Any]) -> ScanOptions:
    cfg = raw.get("diagnosis_2_1") or {}
    allowed = cfg.get("allowed_extensions") or ["jpg", "jpeg", "png", "gif", "webp"]
    raw_max_req = cfg.get("max_requests", 0)
    max_requests = max(0, int(raw_max_req)) if raw_max_req is not None else 0
    return ScanOptions(
        timeout=float(cfg.get("timeout", 15.0)),
        default_allowed_extensions=[str(e) for e in allowed],
        max_targets=max(1, min(int(cfg.get("max_targets", 20)), 200)),
        max_requests=max_requests,
        httpx_enabled=bool(cfg.get("httpx_enabled", True)),
        zap_enabled=bool(cfg.get("zap_enabled", False)),
        zap_passive_wait_seconds=int(cfg.get("zap_passive_wait_seconds", 60)),
        interval_sec=max(0.0, min(float(cfg.get("interval_sec", 0.0)), 5.0)),
        enable_auth_modes=bool(cfg.get("enable_auth_modes", True)),
    )


def _build_passes(
    auth_sessions: list[dict[str, Any]],
    *,
    enable_auth_modes: bool,
) -> list[tuple[str, dict[str, Any] | None]]:
    """anonymous 패스 + (enable_auth_modes가 True인 경우) 인증 세션 패스 목록 반환."""
    passes: list[tuple[str, dict[str, Any] | None]] = [("anonymous", None)]
    if enable_auth_modes:
        for session in auth_sessions:
            passes.append((session_auth_mode(session), session))
    return passes


def _collapse_findings_by_role_feature(
    items: list[DiagnosisFinding],
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    """Collapse duplicate findings by role/function while preserving evidence detail."""
    groups: dict[str, DiagnosisFinding] = {}
    url_sets: dict[str, set[str]] = {}
    ext_sets: dict[str, set[str]] = {}
    method_sets: dict[str, set[str]] = {}
    role_counts: dict[str, int] = {}

    for f in items:
        ev = f.evidence or {}
        role = str(ev.get("business_role") or "user")
        role_counts[role] = role_counts.get(role, 0) + 1
        key = (
            f"{ev.get('engine')}|{ev.get('auth_mode', 'anonymous')}|{f.severity}|"
            f"{ev.get('finding_type')}|{ev.get('reason')}|{role}|"
            f"{ev.get('feature_key') or ev.get('endpoint_id')}|{ev.get('file_field')}|"
            f"{ev.get('technique')}"
        )
        url = str(ev.get("url") or "")
        ext = str(ev.get("extension") or "")
        method = str(ev.get("method") or "")
        if key not in groups:
            groups[key] = f
            url_sets[key] = {url} if url else set()
            ext_sets[key] = {ext} if ext else set()
            method_sets[key] = {method} if method else set()
            continue
        if url:
            url_sets[key].add(url)
        if ext:
            ext_sets[key].add(ext)
        if method:
            method_sets[key].add(method)

    collapsed: list[DiagnosisFinding] = []
    raw_issues = 0
    for key, f in groups.items():
        urls = sorted(u for u in url_sets[key] if u)
        exts = sorted(e for e in ext_sets[key] if e)
        methods = sorted(m for m in method_sets[key] if m)
        raw_issues += max(1, len(urls), len(exts), len(methods))
        ev = dict(f.evidence or {})
        ev["affected_urls"] = urls
        ev["affected_count"] = len(urls) if urls else 1
        ev["affected_extensions"] = exts
        ev["affected_extension_count"] = len(exts) if exts else 1
        ev["affected_methods"] = methods
        ev["affected_method_count"] = len(methods) if methods else 1

        message = f.message
        is_ext_bypass = str(ev.get("reason") or "").startswith("disallowed_extension_accepted")
        if is_ext_bypass and len(exts) > 1:
            ext_display = ", ".join(f".{e}" for e in exts)
            label = str(ev.get("feature_label") or (urls[0] if urls else ev.get("url", "")))
            message = (
                f"[2-1][{ev.get('engine')}][{ev.get('auth_mode', 'anonymous')}] "
                f"disallowed extensions accepted ({len(exts)}: {ext_display}) "
                f"-- {ev.get('technique')} -- {label}"
            )
        elif len(exts) > 1:
            message = f"{message} ({len(exts)} extensions)"

        if len(urls) > 1:
            message = f"{message} ({len(urls)} URLs)"
        collapsed.append(DiagnosisFinding(severity=f.severity, message=message, evidence=ev))

    return collapsed, {
        "raw_issues": raw_issues,
        "collapsed_issues": len(collapsed),
        "findings_by_role": role_counts,
    }


def _overall_status(findings: list[DiagnosisFinding]) -> str:
    severities = {f.severity for f in findings if f.severity in ("high", "medium", "low")}
    if "high" in severities or "medium" in severities:
        return "fail"
    if "low" in severities:
        return "warn"
    return "pass"


def _run_phase(
    *,
    transport: Any,
    engine: str,
    targets: list[Any],
    payloads_by_target: dict[int, list[Any]],
    passes: list[tuple[str, dict[str, Any] | None]],
    probes_mod: Any,
    rules_mod: Any,
    multipart_mod: Any,
    opts: ScanOptions,
    progress_cb_factory: Any,
    budget: Any = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    findings: list[DiagnosisFinding] = []
    per_pass_stats: list[dict[str, Any]] = []
    requested_urls: set[str] = set()
    # run_upload_probes가 타겟별로 0..len(payloads) 진행을 보고하므로,
    # phase_done 오프셋 없이는 콜백이 타겟마다 0부터 다시 시작하게 된다.
    phase_done = 0

    for auth_label, session in passes:
        request_headers = probe_request_headers(session) if session else None
        account_email = str(session.get("email") or "") if session else None
        login_label = str(session.get("login_label") or "") if session else None

        pass_findings: list[DiagnosisFinding] = []
        pass_requests = 0
        base_cb = progress_cb_factory(f"{engine}:{auth_label}")
        for target in targets:
            payloads = payloads_by_target[id(target)]
            target_base = phase_done

            def _target_progress(target_base: int = target_base, **kw: Any) -> None:
                local_done = int(kw.get("endpoints_done") or 0)
                base_cb(
                    endpoints_done=target_base + local_done,
                    endpoints_total=kw.get("endpoints_total"),
                    endpoint_id=kw.get("endpoint_id"),
                )

            t_findings, t_stats = probes_mod.run_upload_probes(
                [target],
                payloads,
                transport=transport,
                engine=engine,
                rules_mod=rules_mod,
                multipart_mod=multipart_mod,
                timeout=opts.timeout,
                auth_mode=auth_label,
                request_headers=request_headers,
                account_email=account_email or None,
                login_label=login_label or None,
                interval_sec=opts.interval_sec,
                budget=budget,
                on_progress=_target_progress,
            )
            phase_done = target_base + len(payloads)
            pass_findings.extend(t_findings)
            pass_requests += int(t_stats.get("requests_sent", 0))
            requested_urls.update(t_stats.get("requested_urls") or [])
            if budget and budget.exhausted():
                break

        findings.extend(pass_findings)
        per_pass_stats.append(
            {
                "engine": engine,
                "auth_mode": auth_label,
                "account_email": account_email,
                "login_label": login_label,
                "requests_sent": pass_requests,
                "issues": len(pass_findings),
            }
        )
        if budget and budget.exhausted():
            break

    return findings, {"passes": per_pass_stats, "requested_urls": sorted(requested_urls)}


def run_g21_scan(ctx: DiagnosisContext, module_dir: Path) -> ScanResult:
    from app.services import diagnosis_progress as dp

    _ = module_dir
    opts = _scan_options(ctx.raw_config)

    targets_mod = _load_local("targets")
    payloads_mod = _load_local("payloads")
    probes_mod = _load_local("probes")
    rules_mod = _load_local("rules")
    multipart_mod = _load_local("multipart")

    targets, target_meta = targets_mod.build_upload_targets(
        ctx.raw_config,
        data_dir=ctx.data_dir,
        default_allowed_extensions=opts.default_allowed_extensions,
    )
    if not targets:
        return ScanResult(
            status="skipped",
            message=(
                "No upload endpoint configured/discovered — set "
                "diagnosis_2_1.upload_endpoints or build the attack surface first"
            ),
            stats={"targets": 0, **target_meta},
        )
    if len(targets) > opts.max_targets:
        targets = targets[: opts.max_targets]
        target_meta["truncated_to"] = opts.max_targets

    rules_defaults = payloads_mod.load_extension_rules()
    payloads_by_target: dict[int, list[Any]] = {
        id(target): payloads_mod.build_upload_payloads(
            target.allowed_extensions, rules=rules_defaults
        )
        for target in targets
    }

    auth_sessions, _auth_meta = all_account_auths_with_meta(ctx.raw_config, data_dir=ctx.data_dir)
    auth_configured = len(auth_sessions) > 0
    passes = _build_passes(auth_sessions, enable_auth_modes=opts.enable_auth_modes)

    payloads_per_pass = sum(len(p) for p in payloads_by_target.values())
    phase_count = (1 if opts.httpx_enabled else 0) + (1 if opts.zap_enabled else 0)
    grand_total = payloads_per_pass * len(passes) * max(phase_count, 1)

    dp.update(
        phase="preparing",
        message=f"2-1: {grand_total} upload probe(s) 준비 중",
        endpoints_total=len(targets),
    )
    progress_offset = 0

    def _progress_factory(label: str):
        def _cb(**kw: Any) -> None:
            nonlocal progress_offset
            local_done = int(kw.get("endpoints_done") or 0)
            done = progress_offset + local_done
            item = str(kw.get("endpoint_id") or label)
            dp.update(
                phase="httpx" if label.startswith("httpx") else "zap",
                message=f"[{label}] upload {done}/{grand_total} · {item[:80]}",
                endpoints_done=done,
                endpoints_total=grand_total,
            )

        return _cb

    stats: dict[str, Any] = dict(target_meta)
    findings: list[DiagnosisFinding] = []
    
    budget = probes_mod.RequestBudget(max_requests=opts.max_requests) if opts.max_requests > 0 else None

    if opts.httpx_enabled:
        dp.update(phase="httpx", message=f"httpx Phase — {len(targets)} upload endpoint(s)")
        with _transport.HttpxTransport(timeout=opts.timeout) as httpx_transport:
            httpx_findings, httpx_phase_stats = _run_phase(
                transport=httpx_transport,
                engine="httpx",
                targets=targets,
                payloads_by_target=payloads_by_target,
                passes=passes,
                probes_mod=probes_mod,
                rules_mod=rules_mod,
                multipart_mod=multipart_mod,
                opts=opts,
                progress_cb_factory=_progress_factory,
                budget=budget,
            )
        findings.extend(httpx_findings)
        progress_offset += payloads_per_pass * len(passes)
        stats["httpx"] = httpx_phase_stats
        stats["httpx"]["findings"] = len(httpx_findings)

    zap_ran = False
    if opts.zap_enabled:
        zap_scan_mod = _load_local("zap_scan")
        # ZAP Replacer에 적용할 대표 인증 세션 (첫 번째 계정)
        primary_auth = primary_account_auth(ctx.raw_config, data_dir=ctx.data_dir)
        try:
            dp.update(phase="zap", message="ZAP Phase — upload probe via ZAP proxy")
            zap, zap_transport, proxy = zap_scan_mod.open_zap_transport(
                ctx.raw_config, auth=primary_auth
            )
            reset_before = zap_scan_mod.reset_workspace(zap, session_name="argus-g21-start")
            zap_findings, zap_phase_stats = _run_phase(
                transport=zap_transport,
                engine="zap",
                targets=targets,
                payloads_by_target=payloads_by_target,
                passes=passes,
                probes_mod=probes_mod,
                rules_mod=rules_mod,
                multipart_mod=multipart_mod,
                opts=opts,
                progress_cb_factory=_progress_factory,
                budget=budget,
            )
            pending = zap_scan_mod.wait_for_passive_scan(
                zap, max_seconds=opts.zap_passive_wait_seconds
            )
            supplemental = zap_scan_mod.collect_supplemental_findings(
                zap, set(zap_phase_stats.get("requested_urls") or [])
            )
            zap_findings.extend(supplemental)
            reset_after = zap_scan_mod.reset_workspace(zap, session_name="argus-g21-done")

            findings.extend(zap_findings)
            stats["zap"] = {
                **zap_phase_stats,
                "zap_proxy": proxy,
                "findings": len(zap_findings),
                "supplemental_findings": len(supplemental),
                "passive_records_pending": pending,
                "workspace_reset_before": reset_before,
                "workspace_reset_after": reset_after,
            }
            zap_ran = True
        except ZapNotAvailableError as exc:
            stats["zap"] = {"error": str(exc)}
        except Exception as exc:  # pragma: no cover - ZAP is an optional external dep
            stats["zap"] = {"error": str(exc)}

    findings, collapse_stats = _collapse_findings_by_role_feature(findings)

    stats.update(collapse_stats)
    stats["timeout"] = opts.timeout
    stats["default_allowed_extensions"] = opts.default_allowed_extensions
    stats["auth_configured"] = auth_configured
    stats["auth_sessions"] = len(auth_sessions)
    stats["targets_probed"] = len(targets)
    stats["interval_sec"] = opts.interval_sec
    stats["enable_auth_modes"] = opts.enable_auth_modes
    stats["max_requests"] = opts.max_requests
    if budget and budget.exhausted():
        stats["budget_exhausted"] = True

    status = _overall_status(findings)
    collapsed = collapse_stats.get("collapsed_issues", 0)
    if status == "pass":
        message = f"No unblocked malicious upload on {len(targets)} endpoint(s)"
    else:
        message = (
            f"Malicious upload exposure: {collapsed} unique issue(s) "
            f"on {len(targets)} endpoint(s)"
        )
    if opts.enable_auth_modes and auth_sessions:
        tags = ", ".join(session_probe_tag(s) for s in auth_sessions)
        message += f" — auth passes ({tags})"
    elif not auth_configured:
        message += " — auth pass skipped (no test account)"
    if opts.zap_enabled and not zap_ran:
        message += " (ZAP skipped/unavailable — httpx only)"

    return ScanResult(findings=findings, stats=stats, status=status, message=message)
