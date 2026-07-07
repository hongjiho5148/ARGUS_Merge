"""Cross-account IDOR probes on 2-2 download/export candidates (guideline 2-2 v2)."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path
from typing import Any

from app.services.zap_util import probe_url
from diagnosis.replay.recorder import ReplaySession
from diagnosis.result import DiagnosisFinding
from inventory.net import probe_base_url
from inventory.probe_build import build_probe_request
from inventory.schema import Endpoint
from parsers.parse_endpoints import DEFAULT_PATH_PARAMS

_DIR = Path(__file__).resolve().parent
_PATH_PARAM_RE = re.compile(r"\{([a-zA-Z0-9_]+)\}")
MAX_PARAM_SETS = 5


def _load_auth_access():
    import sys

    mod_name = "diag_g22_idor_auth"
    spec = importlib.util.spec_from_file_location(mod_name, _DIR / "auth_access.py")
    if spec is None or spec.loader is None:
        raise ImportError("Cannot load auth_access")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


_aa = _load_auth_access()
AuthProbeSnapshot = _aa.AuthProbeSnapshot
is_download_like = _aa.is_download_like


def path_param_names(ep: Endpoint) -> list[str]:
    from_params = [inp.name for inp in ep.request_params if inp.in_ == "path"]
    if from_params:
        return from_params
    return _PATH_PARAM_RE.findall(ep.path)


def is_idor_candidate(ep: Endpoint) -> bool:
    """Endpoint has a path placeholder suitable for cross-account ID replay."""
    if "{" not in ep.path:
        return False
    lower = ep.path.lower()
    if any(k in lower for k in ("export", "download", "report", "attach", "file")):
        return True
    for name in path_param_names(ep):
        if name in DEFAULT_PATH_PARAMS or name.endswith("Id") or name.endswith("_id"):
            return True
    return False


def _normalize_seeds(raw: dict[str, Any] | None) -> dict[str, Any]:
    if not raw:
        return {}
    out: dict[str, Any] = {}
    for key, val in raw.items():
        if isinstance(val, dict):
            out[str(key)] = {str(k): str(v) for k, v in val.items()}
        elif isinstance(val, list):
            out[str(key)] = [str(v) for v in val if v is not None and str(v).strip()]
        elif val is not None and str(val).strip():
            out[str(key)] = [str(val)]
    return out


def path_param_sets(ep: Endpoint, *, seeds: dict[str, Any]) -> list[dict[str, str]]:
    """Build up to MAX_PARAM_SETS concrete path-param maps for an endpoint."""
    names = path_param_names(ep)
    if not names:
        return []

    base: dict[str, str] = {}
    for inp in ep.request_params:
        if inp.in_ == "path" and inp.sample is not None:
            base[inp.name] = str(inp.sample)
    for name in names:
        if name not in base:
            base[name] = DEFAULT_PATH_PARAMS.get(name, "1")

    sets: list[dict[str, str]] = [dict(base)]
    seen = {tuple(sorted(base.items()))}

    for name in names:
        seed_vals = seeds.get(name, [])
        if not isinstance(seed_vals, list):
            continue
        for val in seed_vals:
            variant = dict(base)
            variant[name] = str(val)
            key = tuple(sorted(variant.items()))
            if key in seen:
                continue
            seen.add(key)
            sets.append(variant)
            if len(sets) >= MAX_PARAM_SETS:
                return sets

    path_seeds = seeds.get(ep.path) or seeds.get(ep.path.rstrip("/"))
    if isinstance(path_seeds, dict):
        variant = dict(base)
        variant.update({str(k): str(v) for k, v in path_seeds.items()})
        key = tuple(sorted(variant.items()))
        if key not in seen:
            sets.append(variant)

    return sets[:MAX_PARAM_SETS]


def _probe_endpoint(
    transport: Any,
    ep: Endpoint,
    *,
    auth: dict[str, Any] | None,
    auth_mode: str,
    path_params: dict[str, str],
    account_email: str | None = None,
) -> AuthProbeSnapshot:
    probe = build_probe_request(
        ep,
        probe_base_fn=probe_url,
        account_auth=auth,
        path_param_defaults=path_params,
    )
    method = probe["method"]
    url = probe["url"]
    headers = dict(probe.get("headers") or {})
    body_str = probe.get("body") or ""
    body_bytes = body_str.encode("utf-8") if body_str else None

    resp = transport.request(method, url, headers, body_bytes, follow_redirects=True)
    if resp.error:
        return AuthProbeSnapshot(
            auth_mode=auth_mode,
            http_status=None,
            body=b"",
            headers={},
            url=url,
            account_email=account_email,
            error=resp.error,
        )
    return AuthProbeSnapshot(
        auth_mode=auth_mode,
        http_status=resp.status,
        body=resp.body,
        headers=resp.headers,
        url=url,
        account_email=account_email,
    )


def classify_idor(
    *,
    path: str,
    path_params: dict[str, str],
    owner: AuthProbeSnapshot,
    other: AuthProbeSnapshot,
) -> tuple[str, str, dict[str, Any]] | None:
    """
    Return (severity, trigger, meta) when account B accesses owner A's download-like resource.
    None = no IDOR (owner has no file, or other correctly denied).
    """
    owner_dl, owner_signal = is_download_like(
        http_status=owner.http_status,
        body=owner.body,
        headers=owner.headers,
        path=path,
    )
    if not owner_dl:
        return None

    other_dl, other_signal = is_download_like(
        http_status=other.http_status,
        body=other.body,
        headers=other.headers,
        path=path,
    )
    if not other_dl:
        return None

    same_body = owner.fingerprint["sha256"] == other.fingerprint["sha256"]
    meta: dict[str, Any] = {
        "path_params": path_params,
        "owner_http_status": owner.http_status,
        "owner_signal": owner_signal,
        "owner_sha256": owner.fingerprint["sha256"],
        "owner_size": owner.fingerprint["size"],
        "owner_url": owner.url,
        "owner_email": owner.account_email,
        "other_http_status": other.http_status,
        "other_signal": other_signal,
        "other_sha256": other.fingerprint["sha256"],
        "other_size": other.fingerprint["size"],
        "other_url": other.url,
        "other_email": other.account_email,
        "bodies_identical": same_body,
    }

    severity = "high" if same_body else "medium"
    if any(k in path.lower() for k in ("admin", "internal", "private", "backup")):
        severity = "high"

    trigger = "idor_same_file_cross_account" if same_body else "idor_download_cross_account"
    return severity, trigger, meta


IDOR_TRIGGER_LABELS: dict[str, str] = {
    "idor_same_file_cross_account": (
        "Account B received the same file/download as account A for another user's resource ID"
    ),
    "idor_download_cross_account": (
        "Account B received a download-like response for account A's resource ID"
    ),
}


def _build_idor_finding(
    ep: Endpoint,
    *,
    severity: str,
    trigger: str,
    meta: dict[str, Any],
    owner: AuthProbeSnapshot,
    other: AuthProbeSnapshot,
    engine: str,
    owner_auth: dict[str, Any],
    other_auth: dict[str, Any],
    replay_session: ReplaySession | None = None,
) -> DiagnosisFinding:
    snippet = _aa._tf.evidence_snippet(other.headers, other.body)
    evidence: dict[str, Any] = {
        "source": engine,
        "engine": engine,
        "analysis_mode": "unified",
        "rule_id": "2-2-idor",
        "classification": "B" if severity == "high" else "A",
        "trigger": trigger,
        "trigger_label": IDOR_TRIGGER_LABELS.get(trigger, trigger),
        "related_sections": ["4-4", "4-5"],
        "method": ep.method,
        "path": ep.path,
        "base_url": probe_base_url(ep.base_url or ""),
        "http_status": other.http_status,
        **snippet,
        **meta,
    }

    msg = (
        f"[{'B' if severity == 'high' else 'A'}] IDOR on {ep.method} {ep.path} "
        f"({owner.account_email} resource → {other.account_email} HTTP {other.http_status})"
    )
    finding = DiagnosisFinding(severity=severity, message=msg, evidence=evidence)

    if replay_session and severity in ("medium", "high"):
        rec = replay_session.recorder(
            rule_id="2-2-idor",
            path=ep.path,
            trigger=trigger,
        )
        rec.set_auth("authenticated", account_email=owner.account_email)
        rec.append_ui_flow(method=ep.method, path=ep.path)
        owner_probe = build_probe_request(
            ep,
            probe_base_fn=probe_url,
            account_auth=owner_auth,
            path_param_defaults=meta.get("path_params") or {},
        )
        s_owner = rec.record_http_from_probe(
            "owner",
            label=f"Owner probe ({owner.account_email})",
            probe=owner_probe,
            response_status=owner.http_status,
            response_headers=owner.headers,
            response_body=owner.body,
            auth_mode="authenticated",
            account_email=owner.account_email,
        )
        rec.set_auth("authenticated", account_email=other.account_email)
        rec.append_ui_flow(method=ep.method, path=ep.path)
        other_probe = build_probe_request(
            ep,
            probe_base_fn=probe_url,
            account_auth=other_auth,
            path_param_defaults=meta.get("path_params") or {},
        )
        s_other = rec.record_http_from_probe(
            "other",
            label=f"Cross-account probe ({other.account_email})",
            probe=other_probe,
            response_status=other.http_status,
            response_headers=other.headers,
            response_body=other.body,
            auth_mode="authenticated",
            account_email=other.account_email,
        )
        rec.record_compare(s_owner, s_other, label="Owner vs cross-account download")
        return rec.attach_to(finding)

    return finding


def _distinct_accounts(sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for session in sessions:
        email = str(session.get("email") or "").strip().lower()
        if not email or email in seen:
            continue
        seen.add(email)
        out.append(session)
    return out


def run_idor_probes(
    candidates: list[Endpoint],
    *,
    account_auths: list[dict[str, Any]],
    transport: Any,
    engine: str,
    idor_seeds: dict[str, Any] | None = None,
    timeout: float = 12.0,
    replay_session: ReplaySession | None = None,
    login_report: dict[str, Any] | None = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    """Probe 2-2 candidates with owner account IDs, then replay as other accounts."""
    from diagnosis.endpoint_auth_passes import filter_sessions_for_endpoint

    _ = timeout
    findings: list[DiagnosisFinding] = []
    seeds = _normalize_seeds(idor_seeds)
    idor_eps = [ep for ep in candidates if is_idor_candidate(ep)]

    accounts = _distinct_accounts(account_auths)

    stats: dict[str, Any] = {
        "engine": engine,
        "idor_candidates": len(idor_eps),
        "accounts": len(accounts),
        "probed": 0,
        "owner_hits": 0,
        "findings": 0,
        "skipped_insufficient_accounts": len(accounts) < 2,
    }

    if len(accounts) < 2 or not idor_eps:
        return findings, stats

    for ep in idor_eps:
        ep_accounts = _distinct_accounts(
            filter_sessions_for_endpoint(ep, account_auths, login_report)
        )
        if login_report is None and len(ep_accounts) < 2:
            ep_accounts = accounts
        if len(ep_accounts) < 2:
            continue
        owner = ep_accounts[0]
        others = ep_accounts[1:]
        owner_email = str(owner.get("email") or "")
        param_sets = path_param_sets(ep, seeds=seeds)
        if not param_sets:
            continue

        for path_params in param_sets:
            owner_snap = _probe_endpoint(
                transport,
                ep,
                auth=owner,
                auth_mode=f"owner:{owner_email}",
                path_params=path_params,
                account_email=owner_email,
            )
            stats["probed"] += 1

            owner_dl, _ = is_download_like(
                http_status=owner_snap.http_status,
                body=owner_snap.body,
                headers=owner_snap.headers,
                path=ep.path,
            )
            if not owner_dl:
                continue

            stats["owner_hits"] = stats.get("owner_hits", 0) + 1

            for other in others:
                other_email = str(other.get("email") or "")
                other_snap = _probe_endpoint(
                    transport,
                    ep,
                    auth=other,
                    auth_mode=f"other:{other_email}",
                    path_params=path_params,
                    account_email=other_email,
                )
                result = classify_idor(
                    path=ep.path,
                    path_params=path_params,
                    owner=owner_snap,
                    other=other_snap,
                )
                if result is None:
                    continue

                severity, trigger, meta = result
                if owner_snap.error:
                    meta["owner_error"] = owner_snap.error
                if other_snap.error:
                    meta["other_error"] = other_snap.error

                findings.append(
                    _build_idor_finding(
                        ep,
                        severity=severity,
                        trigger=trigger,
                        meta=meta,
                        owner=owner_snap,
                        other=other_snap,
                        engine=engine,
                        owner_auth=owner,
                        other_auth=other,
                        replay_session=replay_session,
                    )
                )

    stats["findings"] = len(findings)
    return findings, stats
