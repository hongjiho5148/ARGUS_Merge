"""Orchestrate guideline 2-1 malicious file upload scan (httpx + optional ZAP)."""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.services.zap_util import ZapNotAvailableError
from diagnosis.context import DiagnosisContext
from diagnosis.probe_auth import (
    all_account_auths_with_meta,
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
    httpx_enabled: bool = True
    zap_enabled: bool = False
    zap_passive_wait_seconds: int = 60


@dataclass
class ScanResult:
    findings: list[DiagnosisFinding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    status: str = "pass"
    message: str = ""


def _scan_options(raw: dict[str, Any]) -> ScanOptions:
    cfg = raw.get("diagnosis_2_1") or {}
    allowed = cfg.get("allowed_extensions") or ["jpg", "jpeg", "png", "gif", "webp"]
    return ScanOptions(
        timeout=float(cfg.get("timeout", 15.0)),
        default_allowed_extensions=[str(e) for e in allowed],
        max_targets=max(1, min(int(cfg.get("max_targets", 20)), 200)),
        httpx_enabled=bool(cfg.get("httpx_enabled", True)),
        zap_enabled=bool(cfg.get("zap_enabled", False)),
        zap_passive_wait_seconds=int(cfg.get("zap_passive_wait_seconds", 60)),
    )


def _collapse_findings(items: list[DiagnosisFinding]) -> tuple[list[DiagnosisFinding], dict[str, int]]:
    """Collapse duplicate findings across auth passes/URLs — but keep every
    distinct bypassed extension visible. Grouping by (endpoint, technique)
    without also tracking extension would silently merge e.g. a ``.php`` and
    a ``.jsp`` bypass on the same endpoint into a single "only .php" finding,
    hiding that every other dangerous extension was accepted too.
    """
    groups: dict[str, DiagnosisFinding] = {}
    url_sets: dict[str, set[str]] = {}
    ext_sets: dict[str, set[str]] = {}

    for f in items:
        ev = f.evidence or {}
        key = (
            f"{ev.get('engine')}|{ev.get('auth_mode', 'anonymous')}|{f.severity}|"
            f"{ev.get('reason')}|{ev.get('endpoint_id')}|{ev.get('technique')}"
        )
        url = str(ev.get("url") or "")
        ext = str(ev.get("extension") or "")
        if key not in groups:
            groups[key] = f
            url_sets[key] = {url} if url else set()
            ext_sets[key] = {ext} if ext else set()
            continue
        if url:
            url_sets[key].add(url)
        if ext:
            ext_sets[key].add(ext)

    collapsed: list[DiagnosisFinding] = []
    raw_issues = 0
    for key, f in groups.items():
        urls = sorted(u for u in url_sets[key] if u)
        exts = sorted(e for e in ext_sets[key] if e)
        raw_issues += max(1, len(urls), len(exts))
        ev = dict(f.evidence or {})
        ev["affected_urls"] = urls
        ev["affected_count"] = len(urls) if urls else 1
        ev["affected_extensions"] = exts
        ev["affected_extension_count"] = len(exts) if exts else 1

        message = f.message
        if len(exts) > 1:
            ext_display = ", ".join(f".{e}" for e in exts)
            label = f"{ev.get('method', '')} {urls[0] if urls else ev.get('url', '')}".strip()
            message = (
                f"[2-1][{ev.get('engine')}][{ev.get('auth_mode', 'anonymous')}] "
                f"허용되지 않은 확장자 {len(exts)}개({ext_display}) 업로드가 모두 차단되지 않음 — "
                f"{ev.get('technique')} · {label}"
            )
        if len(urls) > 1:
            message = f"{message} ({len(urls)} URL)"
        collapsed.append(DiagnosisFinding(severity=f.severity, message=message, evidence=ev))

    return collapsed, {"raw_issues": raw_issues, "collapsed_issues": len(collapsed)}


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
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    findings: list[DiagnosisFinding] = []
    per_pass_stats: list[dict[str, Any]] = []
    requested_urls: set[str] = set()
    # probes_mod.run_upload_probes is called once per target and reports its
    # own 0..len(payloads) progress each time — without this running offset,
    # the callback below would reset to 0 for every target instead of
    # climbing monotonically across the whole phase.
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
                on_progress=_target_progress,
            )
            phase_done = target_base + len(payloads)
            pass_findings.extend(t_findings)
            pass_requests += int(t_stats.get("requests_sent", 0))
            requested_urls.update(t_stats.get("requested_urls") or [])

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

    return findings, {"passes": per_pass_stats, "requested_urls": sorted(requested_urls)}


def run_g21_scan(ctx: DiagnosisContext, module_dir: Path) -> ScanResult:
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
        id(target): payloads_mod.build_upload_payloads(target.allowed_extensions, rules=rules_defaults)
        for target in targets
    }

    auth_sessions, _auth_meta = all_account_auths_with_meta(ctx.raw_config, data_dir=ctx.data_dir)
    auth_configured = len(auth_sessions) > 0
    passes: list[tuple[str, dict[str, Any] | None]] = [("anonymous", None)] + [
        (session_auth_mode(s), s) for s in auth_sessions
    ]

    from diagnosis.progress_reporter import phase, prepare

    payloads_per_pass = sum(len(p) for p in payloads_by_target.values())
    phase_count = (1 if opts.httpx_enabled else 0) + (1 if opts.zap_enabled else 0)
    grand_total = payloads_per_pass * len(passes) * max(phase_count, 1)
    prepare(grand_total, f"2-1: {grand_total} upload probe(s)")
    progress_offset = 0

    def _progress_factory(label: str):
        def _cb(**kw: Any) -> None:
            nonlocal progress_offset
            local_done = int(kw.get("endpoints_done") or 0)
            done = progress_offset + local_done
            item = str(kw.get("endpoint_id") or label)
            phase(
                f"uploads {done}/{grand_total} · {label} · {item}",
                phase_name="httpx" if label.startswith("httpx") else "zap",
                done=done,
                total=grand_total,
            )

        return _cb

    stats: dict[str, Any] = dict(target_meta)
    findings: list[DiagnosisFinding] = []

    if opts.httpx_enabled:
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
            )
        findings.extend(httpx_findings)
        progress_offset += payloads_per_pass * len(passes)
        stats["httpx"] = httpx_phase_stats
        stats["httpx"]["findings"] = len(httpx_findings)

    zap_ran = False
    if opts.zap_enabled:
        zap_scan_mod = _load_local("zap_scan")
        try:
            zap, zap_transport, proxy = zap_scan_mod.open_zap_transport(ctx.raw_config)
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
        except Exception as exc:  # pragma: no cover - defensive, ZAP is an optional external dep
            stats["zap"] = {"error": str(exc)}

    findings, collapse_stats = _collapse_findings(findings)

    stats.update(collapse_stats)
    stats["timeout"] = opts.timeout
    stats["default_allowed_extensions"] = opts.default_allowed_extensions
    stats["auth_configured"] = auth_configured
    stats["auth_sessions"] = len(auth_sessions)
    stats["targets_probed"] = len(targets)

    status = _overall_status(findings)
    collapsed = collapse_stats.get("collapsed_issues", 0)
    if status == "pass":
        message = f"No unblocked malicious upload on {len(targets)} endpoint(s)"
    else:
        message = f"Malicious upload exposure: {collapsed} unique issue(s) on {len(targets)} endpoint(s)"
    if auth_sessions:
        tags = ", ".join(session_probe_tag(s) for s in auth_sessions)
        message += f" — auth passes ({tags})"
    elif not auth_configured:
        message += " — auth pass skipped (no test account)"
    if opts.zap_enabled and not zap_ran:
        message += " (ZAP skipped/unavailable — httpx only)"

    return ScanResult(findings=findings, stats=stats, status=status, message=message)
