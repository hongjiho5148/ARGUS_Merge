"""ARGUS 1-1 scanner orchestration.

The 1-1 module owns the scan loop, entered through ``run_g11_scan()``. It
delegates the actual scan to the ``zap_runner`` engine (per account/pass) and
reads back the findings zap_runner writes, then de-duplicates them. The
finding shape is built in one place only — ``zap_runner``'s report builder.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any
from urllib.parse import urlparse



_MODULE_DIR = Path(__file__).resolve().parent


def _load_sibling(name: str):
    spec = importlib.util.spec_from_file_location(f"diag_g11_{name}", _MODULE_DIR / f"{name}.py")
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Failed to load {name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


zap_runner = _load_sibling("zap_runner")


scan_status = {
    "is_running": False,
    "progress": 0,
    "message": "Ready",
    "result_file": None,
    "log_file": None,
    "total_alerts": 0,
}


class _Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for stream in self.streams:
            try:
                if not getattr(stream, "closed", False):
                    stream.write(data)
                    stream.flush()
            except (ValueError, OSError):
                pass

    def flush(self):
        for stream in self.streams:
            try:
                if not getattr(stream, "closed", False):
                    stream.flush()
            except (ValueError, OSError):
                pass


@dataclass
class ScanResult:
    status: str
    findings: list[Any] = field(default_factory=list)
    message: str = ""


def _log(message: str) -> None:
    print(message, flush=True)


def update_status(is_running=None, progress=None, message=None, result_file=None, log_file=None, total_alerts=None):
    if is_running is not None:
        scan_status["is_running"] = is_running
    if progress is not None:
        scan_status["progress"] = progress
    if message is not None:
        scan_status["message"] = message
    if result_file is not None:
        scan_status["result_file"] = result_file
    if log_file is not None:
        scan_status["log_file"] = log_file
    if total_alerts is not None:
        scan_status["total_alerts"] = total_alerts
    try:
        from app.services import diagnosis_progress as dp

        if is_running is False:
            if progress == 100:
                # Don't mark the run finished here — the orchestrator
                # (_run_module) finishes only AFTER evidence-screenshot capture,
                # so the UI reports completion once screenshots exist, not the
                # moment the scan engine stops. Keep running=True and hand off to
                # the screenshot phase.
                dp.update(
                    phase="screenshot",
                    message="스캔 완료 — 증거 스크린샷 생성 중…",
                    percent=98,
                )
            elif message:
                dp.fail(message)
        else:
            dp.update(
                phase="running",
                message=message,
                percent=progress,
            )
    except Exception:
        pass


def _read_json(path: Path):
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _load_api_tree(data_dir: Path):
    for name in ["api-tree-verified.json", "api-tree-ready.json", "api-tree.json"]:
        value = _read_json(data_dir / name)
        if value:
            return value, name
    return None, ""


def _normalize_endpoint_path(url_or_path: str, base_url: str) -> str:
    value = str(url_or_path or "").strip()
    if not value:
        return "/"
    if value.startswith("http://") or value.startswith("https://"):
        value = urlparse(value).path or "/"
    elif value.startswith(base_url):
        value = value[len(base_url):] or "/"
    return value.split("?", 1)[0] or "/"


def _base_key(url: str) -> str:
    return str(url or "").strip().rstrip("/").lower()


def _schema_from_api_tree_param(param: dict) -> dict:
    schema = param.get("schema")
    if isinstance(schema, dict) and schema:
        return schema
    raw_type = str(param.get("type") or "string").lower()
    if raw_type in {"int", "integer", "long"}:
        schema = {"type": "integer"}
    elif raw_type in {"float", "double", "number"}:
        schema = {"type": "number"}
    elif raw_type in {"bool", "boolean"}:
        schema = {"type": "boolean"}
    elif raw_type in {"list", "array"}:
        schema = {"type": "array", "items": {"type": "string"}}
    elif raw_type == "object":
        schema = {"type": "object", "properties": {}}
    else:
        schema = {"type": "string"}
    if param.get("sample") not in (None, ""):
        schema["example"] = param.get("sample")
    return schema


def _looks_like_file_field(name: str, schema: dict | None = None) -> bool:
    field = re.sub(r"[^a-z0-9]", "", str(name or "").lower())
    schema = schema or {}
    schema_type = str(schema.get("type") or "").lower()
    schema_format = str(schema.get("format") or "").lower()
    items = schema.get("items") if isinstance(schema.get("items"), dict) else {}
    item_format = str(items.get("format") or "").lower()
    if schema_type == "string" and schema_format == "binary":
        return True
    if schema_type == "array" and item_format == "binary":
        return True
    return any(token in field for token in ["image", "images", "photo", "photos", "file", "files", "upload", "attachment"])


def _api_tree_endpoint_to_openapi_detail(ep: dict) -> dict:
    detail = ep.get("openapi")
    if isinstance(detail, dict) and (detail.get("parameters") or detail.get("requestBody")):
        return detail

    detail = dict(detail or {})
    parameters = list(detail.get("parameters") or [])
    json_properties: dict[str, dict] = {}
    json_required: list[str] = []
    form_properties: dict[str, dict] = {}
    form_required: list[str] = []
    request_header_content_types = {
        str(header.get("sample") or header.get("value") or "").lower()
        for header in ep.get("request_headers", []) or []
        if str(header.get("name") or "").lower() == "content-type"
    }
    prefers_multipart = any("multipart/form-data" in value for value in request_header_content_types)

    for param in ep.get("request_params", []) or []:
        if not isinstance(param, dict):
            continue
        name = param.get("name")
        if not name:
            continue
        location = str(param.get("in") or param.get("location") or "query").lower()
        schema = _schema_from_api_tree_param(param)
        required = bool(param.get("required", False))
        if location in {"query", "path", "header", "cookie"}:
            parameters.append({"name": name, "in": location, "required": required, "schema": schema})
        elif location in {"body", "json"} and not prefers_multipart:
            json_properties[name] = schema
            if required:
                json_required.append(name)
        elif location in {"body", "form", "formdata", "multipart"}:
            if prefers_multipart and _looks_like_file_field(name, schema):
                schema = {"type": "array", "items": {"type": "string", "format": "binary"}}
            form_properties[name] = schema
            if required:
                form_required.append(name)

    if parameters:
        detail["parameters"] = parameters

    content = ((detail.get("requestBody") or {}).get("content") or {}).copy()
    if json_properties and "application/json" not in content:
        json_schema = {"type": "object", "properties": json_properties}
        if json_required:
            json_schema["required"] = json_required
        content["application/json"] = {"schema": json_schema}
    if form_properties and "multipart/form-data" not in content:
        form_schema = {"type": "object", "properties": form_properties}
        if form_required:
            form_schema["required"] = form_required
        content["multipart/form-data"] = {"schema": form_schema}
    if content:
        detail["requestBody"] = {"content": content}

    detail.setdefault("responses", {})
    return detail


def _endpoints_by_base_from_api_tree(
    api_tree: Any,
    allowed_base_urls: list[str] | None = None,
) -> tuple[dict[str, dict], dict]:
    grouped: dict[str, dict] = {}
    if not isinstance(api_tree, dict):
        return grouped, {}
    allowed = {_base_key(u) for u in allowed_base_urls or [] if str(u or "").strip()}
    canonical = {_base_key(u): str(u).strip().rstrip("/") for u in allowed_base_urls or []}
    for ep in api_tree.get("endpoints", []):
        if not isinstance(ep, dict):
            continue
        raw_base = str(ep.get("base_url") or "").strip().rstrip("/")
        base_key = _base_key(raw_base)
        if allowed and base_key not in allowed:
            continue
        base_url = canonical.get(base_key, raw_base)
        if not base_url:
            continue
        path = ep.get("path") or ep.get("url") or ep.get("endpoint")
        method = str(ep.get("method") or "GET").lower()
        if path:
            grouped.setdefault(base_url, {}).setdefault(_normalize_endpoint_path(path, base_url), {})[method] = _api_tree_endpoint_to_openapi_detail(ep)
    return grouped, api_tree.get("components") or {}


def _dedupe_findings(findings: list[dict]) -> list[dict]:
    """Collapse duplicate findings produced across per-account scan passes.

    The same endpoint gets scanned once per account plus once in the
    cross-account pass, so an identical vulnerability can be reported several
    times. Two findings are "the same" only when they share vuln type, URL,
    parameter, method AND account role — keeping the role in the key means a
    regular user's stored XSS and an admin's stored XSS on the same endpoint
    stay as two distinct findings (which is the whole point of scanning every
    account), while true repeats collapse to one."""
    seen: set[tuple] = set()
    deduped: list[dict] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        key = (
            str(finding.get("vuln_type") or ""),
            str(finding.get("url") or "").rstrip("/"),
            str(finding.get("param") or ""),
            str(finding.get("method") or "").upper(),
            str(finding.get("account_role") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def _is_csrf_finding(finding: dict) -> bool:
    label = f"{finding.get('vuln_type') or ''} {finding.get('alert') or ''}"
    return "csrf" in label.lower()


def _safe_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _csrf_group_key(finding: dict) -> tuple:
    defenses = finding.get("csrf_defenses") if isinstance(finding.get("csrf_defenses"), dict) else {}
    return (
        str(finding.get("vuln_type") or "CSRF"),
        str(finding.get("alert") or ""),
        str(finding.get("risk") or finding.get("severity") or ""),
        str(finding.get("confidence") or ""),
        bool(defenses.get("origin_referer_bypass")),
        bool(defenses.get("csrf_token_absent")),
        bool(defenses.get("unsafe_samesite")),
        _safe_int(defenses.get("failed_count")),
    )


def _group_csrf_findings(findings: list[dict]) -> list[dict]:
    """Collapse repeated CSRF findings into one diagnosis item.

    CSRF findings usually share the same root cause and remediation; the useful
    per-endpoint data is the URL/method/parameter/status. Keep one
    representative finding for request/response evidence and carry every
    affected endpoint in structured fields for the frontend/report document.
    """
    groups: dict[tuple, list[dict]] = {}
    passthrough: list[dict] = []
    for finding in findings:
        if isinstance(finding, dict) and _is_csrf_finding(finding):
            groups.setdefault(_csrf_group_key(finding), []).append(finding)
        else:
            passthrough.append(finding)

    grouped: list[dict] = []
    for rows in groups.values():
        representative = dict(rows[0])
        occurrences = []
        affected_urls: list[str] = []
        affected_parameters: list[str] = []
        methods: set[str] = set()
        statuses: set[str] = set()
        roles: set[str] = set()
        for row in rows:
            method = str(row.get("method") or "").upper()
            url = str(row.get("url") or "")
            param = str(row.get("param") or "")
            attack = str(row.get("attack") or "")
            status = row.get("status_code")
            role = str(row.get("account_role") or "")
            if method:
                methods.add(method)
            if url:
                affected_urls.append(f"{method} {url}".strip())
            if param and param not in affected_parameters:
                affected_parameters.append(param)
            if status is not None:
                statuses.add(str(status))
            if role:
                roles.add(role)
            occurrences.append(
                {
                    "method": method,
                    "url": url,
                    "param": param,
                    "attack": attack,
                    "status_code": status,
                    "account_role": role,
                    "csrf_defenses": row.get("csrf_defenses") or {},
                    "evidence_request": row.get("evidence_request", ""),
                    "evidence_response": row.get("evidence_response", ""),
                    "validation_status": row.get("validation_status", ""),
                    "validation_reason": row.get("validation_reason", ""),
                    "confidence": row.get("confidence", ""),
                    "risk": row.get("risk", ""),
                }
            )

        representative["message"] = "CSRF"
        representative["vuln_type"] = "CSRF"
        representative["grouped"] = True
        representative["grouping_reason"] = "CSRF findings share the same defense failure; affected endpoints are listed together."
        representative["occurrence_count"] = len(rows)
        representative["csrf_occurrences"] = occurrences
        representative["affected_urls"] = affected_urls
        representative["affected_parameters"] = affected_parameters
        representative["affected_methods"] = sorted(methods)
        representative["account_roles"] = sorted(roles)
        representative["status_codes"] = sorted(statuses)
        if len(rows) > 1:
            representative["url_summary"] = f"{len(rows)} affected endpoints"
            representative["param_summary"] = ", ".join(affected_parameters) if affected_parameters else "Referer/Token"
            representative["attack_summary"] = "CSRF defense bypass across multiple endpoints"
            representative["evidence_request"] = rows[0].get("evidence_request", "")
            representative["evidence_response"] = rows[0].get("evidence_response", "")
        grouped.append(representative)

    return passthrough + grouped


def run_g11_scan(ctx, module_dir: Path) -> ScanResult:
    raw_config = getattr(ctx, "raw_config", {}) or {}
    g11_config = raw_config.get("diagnosis_1_1") or raw_config.get("g11") or {}
    zap_runner.extra_skip_path_markers = tuple(
        str(marker).lower() for marker in (g11_config.get("extra_skip_path_markers") or []) if str(marker).strip()
    )
    zap_runner.session_cookie_fallback = str(g11_config.get("session_cookie_fallback") or "accessToken")
    target_url = g11_config.get("target_url") or raw_config.get("target_url")
    auth_tokens = g11_config.get("auth_tokens") or raw_config.get("auth_tokens") or []

    data_dir = Path(getattr(ctx, "data_dir", "data"))
    dashboard_base_urls: list[str] = []
    if not target_url and auth_tokens:
        target_url = auth_tokens[0].get("base_url")
    if not target_url:
        try:
            from diagnosis.replay.normalize import collect_probe_base_urls, dedupe_probe_bases
            dashboard_base_urls, _ = dedupe_probe_bases(collect_probe_base_urls(raw_config))
            if dashboard_base_urls:
                target_url = dashboard_base_urls[0]
        except Exception:
            target_url = None
    if not target_url:
        return ScanResult(status="skipped", message="No target_url found for diagnosis 1-1.")

    if not auth_tokens:
        try:
            from diagnosis.probe_auth import all_account_auths_with_meta
            sessions, _meta = all_account_auths_with_meta(raw_config, data_dir=data_dir, refresh=True)
            auth_tokens = [
                {
                    "role": session.get("role") or session.get("email") or "account",
                    "token": session.get("token") or session.get("access_token"),
                    "base_url": session.get("base_url") or target_url,
                    "cookies": session.get("cookies") or {},
                    "cookie_attrs": session.get("cookie_attrs") or {},
                    "set_cookie_headers": session.get("set_cookie_lines") or [],
                    "login_url": session.get("login_url") or "",
                    "claims": session.get("claims") or {},
                    "token_source": session.get("token_source") or session.get("delivery") or "",
                    "token_field": session.get("token_field") or session.get("cookie_name") or "",
                    "email": session.get("email") or "",
                }
                for session in sessions
                if session.get("token") or session.get("access_token") or session.get("cookies")
            ]
        except Exception:
            auth_tokens = []

    if os.path.exists("/.dockerenv"):
        if isinstance(target_url, str):
            target_url = target_url.replace("localhost", "host.docker.internal").replace("127.0.0.1", "host.docker.internal")
        dashboard_base_urls = [u.replace("localhost", "host.docker.internal").replace("127.0.0.1", "host.docker.internal") for u in dashboard_base_urls if isinstance(u, str)]
        if isinstance(auth_tokens, list):
            for token in auth_tokens:
                for k in ["target_url", "base_url"]:
                    if k in token and isinstance(token[k], str):
                        token[k] = token[k].replace("localhost", "host.docker.internal").replace("127.0.0.1", "host.docker.internal")

    allowed_base_urls = dashboard_base_urls or [target_url]
    api_tree, source_name = _load_api_tree(data_dir)
    endpoints_by_base, components = _endpoints_by_base_from_api_tree(api_tree, allowed_base_urls) if api_tree else ({}, {})

    allowed_keys = {_base_key(u) for u in allowed_base_urls if str(u or "").strip()}
    if allowed_keys:
        auth_tokens = [
            dict(account, base_url=account.get("base_url") or target_url)
            for account in auth_tokens
            if _base_key(account.get("base_url") or target_url) in allowed_keys
        ]

    result_dir = Path(getattr(ctx, "report_dir", data_dir / "report" / "1-1"))
    result_dir.mkdir(parents=True, exist_ok=True)
    log_path = result_dir / "g11_scan.log"
    update_status(log_file=str(log_path))

    findings: list[dict] = []
    scan_bases = list(endpoints_by_base) or [target_url]
    with log_path.open("w", encoding="utf-8", errors="replace") as log_stream:
        tee_out = _Tee(sys.stdout, log_stream)
        tee_err = _Tee(sys.stderr, log_stream)
        with contextlib.redirect_stdout(tee_out), contextlib.redirect_stderr(tee_err):
            _log(f"[G11] log_file={log_path}")
            _log(f"[G11] started_at={time.strftime('%Y-%m-%dT%H:%M:%S%z')}")
            result_path = result_dir / "zap_report_summary_web_ui.json"
            for base_url in scan_bases:
                base_key = _base_key(base_url)
                base_auth_tokens = [
                    account
                    for account in auth_tokens
                    if _base_key(account.get("base_url") or base_url) == base_key
                ]
                legacy_accounts = base_auth_tokens or [{"role": "anonymous", "token": None, "base_url": base_url}]
                for account in legacy_accounts:
                    account["base_url"] = account.get("base_url") or base_url
                    account["validated_endpoints"] = endpoints_by_base.get(base_url, {}) or account.get("validated_endpoints", {})
                    account["swagger_components"] = components or account.get("swagger_components", {})

                # Scan once per account so *every* registered account is the
                # primary (its own token drives the whole XSS/CSRF injection),
                # not just the single highest-privilege one. Without this,
                # "my-data" endpoints like /members/me/profile were only ever
                # tested as the admin, so a regular user's own stored-XSS
                # (which needs that user's session) was never found.
                #
                # NOTE: an extra all-accounts pass would also catch
                # cross-account (cross-role) stored XSS — a payload one role
                # stores being read by another — but that roughly doubles the
                # request volume (each stored-XSS check broadcasts a GET to
                # every endpoint), which was overloading the target server and
                # making it drop the reflection-verification GETs (posts XSS
                # was stored but never confirmed). Per-account passes alone
                # keep the server stable; the cross-account pass is dropped.
                scan_passes: list[list[dict]] = [[account] for account in legacy_accounts]

                for pass_accounts in scan_passes:
                    pass_label = ",".join(
                        str(a.get("role") or a.get("email") or "account") for a in pass_accounts
                    )
                    _log(f"[G11] scan pass accounts=[{pass_label}] base={base_url}")
                    # Clear any prior pass's result so a pass that finds
                    # nothing can't re-import the previous pass's findings.
                    if result_path.exists():
                        try:
                            result_path.unlink()
                        except OSError:
                            pass

                    before = Path.cwd()
                    previous_result_dir_override = getattr(zap_runner, "result_dir_override", None)
                    try:
                        os.chdir(result_dir.parent)
                        zap_runner.scan_status = scan_status
                        zap_runner.result_dir_override = str(result_dir.resolve())
                        zap_runner.run_zap_scan(base_url, pass_accounts)
                    finally:
                        zap_runner.result_dir_override = previous_result_dir_override
                        os.chdir(before)

                    if result_path.is_file():
                        try:
                            loaded = json.loads(result_path.read_text(encoding="utf-8"))
                            if isinstance(loaded, list):
                                findings.extend(loaded)
                                _log(f"[G11] pass [{pass_label}] produced {len(loaded)} findings")
                        except Exception as exc:
                            _log(f"[G11] failed to read legacy result {result_path}: {exc}")
            # De-duplicate across per-account passes: the same endpoint tested
            # by several accounts (or re-seen in the cross-account pass) should
            # not produce duplicate findings — but keep genuinely distinct ones
            # (same URL, *different account role* = a real separate finding).
            findings = _group_csrf_findings(_dedupe_findings(findings))
            _log(f"[G11] finished_at={time.strftime('%Y-%m-%dT%H:%M:%S%z')}")
    source_msg = f" api_tree={source_name}" if source_name else ""
    status = "fail" if findings else "pass"
    return ScanResult(status=status, findings=findings, message=f"1-1 scan completed.{source_msg} findings={len(findings)}")


