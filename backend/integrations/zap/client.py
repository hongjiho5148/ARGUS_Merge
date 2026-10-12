"""ZAP connection helpers for ARGUS discover."""

from __future__ import annotations

import json
import os
import re
import time
import urllib.request
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from inventory.net import _probe_host, probe_url as _probe_url_impl


def probe_url(url: str) -> str:
    return _probe_url_impl(url)


@dataclass
class ZapHttpResponse:
    status: int | None
    headers: dict[str, str]
    body: bytes


class ZapNotAvailableError(Exception):
    pass


def is_zap_running(proxy: str, timeout: int = 3) -> bool:
    api = f"{proxy.rstrip('/')}/JSON/core/view/version/"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(api, timeout=2) as resp:
                if resp.status != 200:
                    return False
                body = json.loads(resp.read().decode())
                if isinstance(body, dict) and body.get("version"):
                    return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def zap_proxy_candidates(configured_proxy: str = "") -> list[str]:
    """Ordered list of ZAP API URLs to try (env → config → docker service → host)."""
    seen: set[str] = set()
    out: list[str] = []

    def add(url: str) -> None:
        u = (url or "").strip().rstrip("/")
        if not u or u in seen:
            return
        seen.add(u)
        out.append(u)

    add(os.environ.get("ZAP_PROXY", ""))
    add(configured_proxy)
    add("http://zap:8090")
    probe_host = _probe_host()
    if probe_host:
        add(f"http://{probe_host}:8090")
    add("http://127.0.0.1:8090")
    add("http://localhost:8090")
    return out


def wait_for_zap(
    candidates: list[str],
    *,
    timeout: int = 90,
    on_progress: Any | None = None,
) -> str | None:
    """Block until ZAP responds on one of the candidate URLs, or return None."""
    if not candidates:
        return None

    deadline = time.time() + timeout
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        for proxy in candidates:
            if is_zap_running(proxy, timeout=2):
                return proxy
        remaining = max(0, int(deadline - time.time()))
        if on_progress:
            on_progress(
                f"Waiting for ZAP ({', '.join(_short_proxy(c) for c in candidates[:2])}…) {remaining}s"
            )
        time.sleep(min(3, max(1, remaining)))
    return None


def _short_proxy(proxy: str) -> str:
    parsed = urlparse(proxy)
    host = parsed.hostname or proxy
    port = f":{parsed.port}" if parsed.port else ""
    return f"{host}{port}"


def ensure_zap_proxy(
    zap_cfg: dict[str, Any],
    *,
    on_progress: Any | None = None,
) -> str:
    """Resolve a working ZAP proxy URL or raise ZapNotAvailableError."""
    configured = str(zap_cfg.get("proxy") or "http://127.0.0.1:8090")
    wait_seconds = int(zap_cfg.get("wait_seconds", 90))
    auto_wait = bool(zap_cfg.get("auto_wait", True))

    candidates = zap_proxy_candidates(configured)
    for proxy in candidates:
        if is_zap_running(proxy, timeout=2):
            return proxy

    if not auto_wait:
        tried = ", ".join(_short_proxy(c) for c in candidates)
        raise ZapNotAvailableError(f"ZAP is not running (tried {tried})")

    found = wait_for_zap(candidates, timeout=wait_seconds, on_progress=on_progress)
    if found:
        return found

    tried = ", ".join(_short_proxy(c) for c in candidates)
    raise ZapNotAvailableError(
        f"ZAP did not become ready within {wait_seconds}s (tried {tried}). "
        "Start ZAP on port 8090 or run: docker compose up -d zap"
    )


def connect_zap(proxy: str, api_key: str = "") -> Any:
    from zapv2 import ZAPv2

    return ZAPv2(apikey=api_key, proxies={"http": proxy, "https": proxy})


def stop_zap_scans(zap: Any) -> None:
    """Stop any in-flight ZAP scans before resetting workspace state."""
    for module_name, method_names in (
        ("ascan", ("stop_all_scans",)),
        ("spider", ("stop_all_scans",)),
    ):
        mod = getattr(zap, module_name, None)
        if mod is None:
            continue
        for name in method_names:
            fn = getattr(mod, name, None)
            if fn is None:
                continue
            try:
                fn()
            except Exception:
                pass
    ajax = getattr(zap, "ajaxSpider", None)
    if ajax is not None:
        try:
            ajax.stop()
        except Exception:
            pass


def reset_zap_workspace(zap: Any, *, session_name: str = "argus-scan") -> dict[str, Any]:
    """
    Clear ZAP alerts, site tree, and message history.

    Uses newSession(overwrite=True) so each diagnosis module run starts from a clean
    slate and does not inherit alerts/history from prior 2-2 or 7-2 runs.
    """
    stop_zap_scans(zap)
    stats: dict[str, Any] = {"session_name": session_name}

    try:
        zap.core.delete_all_alerts()
        stats["alerts_cleared"] = True
    except Exception as exc:
        stats["alerts_cleared"] = False
        stats["alerts_error"] = str(exc)

    session_ok = False
    for overwrite in (True, "true"):
        try:
            zap.core.new_session(name=session_name, overwrite=overwrite)
            session_ok = True
            break
        except Exception as exc:
            stats["new_session_error"] = str(exc)
    stats["new_session"] = session_ok

    try:
        zap.core.run_garbage_collection()
        stats["gc"] = True
    except Exception:
        stats["gc"] = False

    return stats


def select_seed_urls(
    probe_targets: list[dict[str, str]],
    cap: int,
    *,
    priority_urls: list[str] | None = None,
) -> list[str]:
    """Sample probe URLs for ZAP seed; priority URLs (e.g. httpx hits) are always first."""
    priority = [u for u in dict.fromkeys(priority_urls or []) if u]
    seen: set[str] = set(priority)
    rest: list[str] = []
    for target in probe_targets:
        url = str(target.get("probe_url") or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        rest.append(url)

    if cap <= 0:
        return priority + rest
    if len(priority) >= cap:
        return priority[:cap]

    rest_cap = cap - len(priority)
    if len(rest) <= rest_cap:
        return priority + rest

    step = max(1, len(rest) // rest_cap)
    sampled_rest: list[str] = []
    for i in range(0, len(rest), step):
        sampled_rest.append(rest[i])
        if len(sampled_rest) >= rest_cap:
            break
    return priority + sampled_rest


def seed_probe_urls(zap: Any, urls: list[str]) -> int:
    count = 0
    for url in urls:
        try:
            zap.urlopen(probe_url(url))
            count += 1
        except Exception:
            continue
    return count


def wait_for_passive_scan(zap: Any, *, max_seconds: int = 90) -> int:
    """Wait until ZAP passive scanner finishes processing seeded responses."""
    deadline = time.time() + max_seconds
    last_remaining = 0
    while time.time() < deadline:
        try:
            last_remaining = int(zap.pscan.records_to_scan)
        except Exception:
            break
        if last_remaining <= 0:
            break
        time.sleep(1)
    return last_remaining


def apply_auth_to_zap(zap: Any, auth: dict[str, Any] | None) -> None:
    if not auth or not auth.get("token"):
        return

    try:
        zap.replacer.remove_rule(description="AutoLoginHeader")
    except Exception:
        pass

    delivery = auth.get("delivery", "bearer")
    token = auth["token"]

    if delivery == "cookie":
        cookie_name = auth.get("cookie_name") or "accessToken"
        replacement = f"{cookie_name}={token}; Path=/"
        match_string = "Cookie"
    else:
        replacement = token if str(token).startswith("Bearer ") else f"Bearer {token}"
        match_string = "Authorization"

    zap.replacer.add_rule(
        description="AutoLoginHeader",
        enabled=True,
        matchtype="REQ_HEADER",
        matchregex=False,
        matchstring=match_string,
        replacement=replacement,
    )


def run_spider(zap: Any, start_url: str, *, max_seconds: int = 120, on_tick: Any | None = None) -> None:
    scan_id = zap.spider.scan(url=start_url, maxchildren=50, recurse=True)
    deadline = time.time() + max_seconds
    started = time.time()
    while time.time() < deadline:
        elapsed = int(time.time() - started)
        if on_tick:
            on_tick(elapsed, max_seconds)
        try:
            progress = int(zap.spider.status(scan_id))
        except Exception:
            break
        if progress >= 100:
            break
        time.sleep(1)
    if time.time() >= deadline:
        try:
            zap.spider.stop(scan_id)
        except Exception:
            pass


def run_ajax_spider(
    zap: Any,
    start_url: str,
    *,
    max_seconds: int = 120,
    on_tick: Any | None = None,
) -> None:
    try:
        zap.ajaxSpider.scan(start_url)
    except Exception:
        return
    deadline = time.time() + max_seconds
    started = time.time()
    while time.time() < deadline:
        elapsed = int(time.time() - started)
        if on_tick:
            on_tick(elapsed, max_seconds)
        try:
            status = str(zap.ajaxSpider.status)
        except Exception:
            break
        if status != "running":
            break
        time.sleep(2)
    if time.time() >= deadline:
        try:
            zap.ajaxSpider.stop()
        except Exception:
            pass


def collect_site_urls(zap: Any, base_url: str) -> set[str]:
    probe_base = probe_url(base_url.rstrip("/"))
    try:
        urls = zap.core.urls(baseurl=probe_base)
    except Exception:
        urls = []
    return {str(u) for u in (urls or [])}


def collect_message_index(zap: Any) -> dict[tuple[str, str], int]:
    """Map (METHOD, url) -> latest HTTP status from ZAP history."""
    index: dict[tuple[str, str], int] = {}
    for obs in collect_traffic_observations(zap):
        index[(obs.method, obs.url)] = obs.http_status or 0
    return index


def collect_traffic_observations(zap: Any, *, max_messages: int = 10000) -> list[Any]:
    """Collect parsed traffic including query/body parameters."""
    from inventory.traffic_params import TrafficObservation, observation_from_message

    observations: list[TrafficObservation] = []
    seen: set[tuple[str, str, str]] = set()
    start = 0
    page = 100

    while start < max_messages:
        try:
            batch = zap.core.messages(start=start, count=page)
        except Exception:
            break
        if not batch:
            break

        for msg in batch:
            try:
                mid = msg.get("id")
                if mid is not None:
                    full = zap.core.message(mid)
                else:
                    full = msg
                header = str(full.get("requestHeader", ""))
                body = str(full.get("requestBody", "") or "")
                method = str(full.get("method", "") or header.split("\n", 1)[0].split()[0])
                url = str(full.get("url", "") or header.split("\n", 1)[0].split()[1])
                status_raw = str(full.get("responseHeader", "HTTP/1.1 0"))
                try:
                    http_status = int(status_raw.split("\n", 1)[0].split()[1])
                except Exception:
                    http_status = None

                response_body = str(full.get("responseBody", "") or "")
                obs = observation_from_message(
                    method,
                    url,
                    header,
                    body,
                    response_header=str(full.get("responseHeader", "")),
                    response_body=response_body,
                )
                if not obs:
                    continue
                dedupe_key = (obs.method, obs.path, str(sorted(obs.query_params.items())))
                if (
                    dedupe_key in seen
                    and not obs.json_body_fields
                    and not obs.form_fields
                    and not obs.response_json_body_fields
                ):
                    continue
                seen.add(dedupe_key)
                obs.http_status = http_status
                observations.append(obs)
            except Exception:
                continue

        if len(batch) < page:
            break
        start += page

    return observations


def normalize_path(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    return path.rstrip("/") or "/"


def _parse_zap_response_status(response_header: str) -> int | None:
    try:
        line = str(response_header or "").split("\n", 1)[0].strip()
        return int(line.split()[1])
    except Exception:
        return None


def _parse_send_request_response(resp: Any) -> int | None:
    full = parse_send_request_full(resp)
    return full.status if full else None


def parse_http_response_headers(header_block: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in str(header_block or "").replace("\r\n", "\n").split("\n")[1:]:
        if not line.strip():
            break
        if ":" in line:
            key, val = line.split(":", 1)
            headers[key.strip()] = val.strip()
    return headers


def _response_dict_from_send_result(resp: Any) -> dict[str, Any] | None:
    if resp is None:
        return None
    if isinstance(resp, list) and resp:
        first = resp[0]
        if isinstance(first, dict):
            return first
        return {"responseHeader": str(first)}
    if isinstance(resp, dict):
        return resp
    return {"responseHeader": str(resp)}


def _response_body_to_bytes(body_raw: Any) -> bytes:
    if body_raw is None:
        return b""
    if isinstance(body_raw, bytes):
        return body_raw
    return str(body_raw).encode("latin-1", errors="replace")


def parse_send_request_full(resp: Any) -> ZapHttpResponse | None:
    """Parse ZAP core sendRequest response into status, headers, and raw body bytes."""
    data = _response_dict_from_send_result(resp)
    if data is None:
        return None
    header_block = str(data.get("responseHeader") or "")
    status = _parse_zap_response_status(header_block)
    return ZapHttpResponse(
        status=status,
        headers=parse_http_response_headers(header_block),
        body=_response_body_to_bytes(data.get("responseBody")),
    )


def zap_send_raw_request_full(zap: Any, raw: str) -> ZapHttpResponse | None:
    """Send raw HTTP via ZAP and return full response (for hybrid 2-2 analysis)."""
    for method_name in ("send_request", "sendRequest"):
        fn = getattr(zap.core, method_name, None)
        if fn is None:
            continue
        try:
            return parse_send_request_full(fn(raw, followredirects="true"))
        except Exception:
            continue
    return None


def _zap_send_raw_request(zap: Any, raw: str) -> int | None:
    """Send raw HTTP via ZAP API; supports python-owasp-zap-v2.4 send_request (snake_case)."""
    full = zap_send_raw_request_full(zap, raw)
    return full.status if full else None


def replay_inventory_probes(
    zap: Any,
    tree: Any,
    *,
    account_auths: list[Any] | None = None,
    include_anonymous: bool = True,
    max_probes: int = 0,
    on_progress: Any | None = None,
) -> list[dict[str, Any]]:
    """Send a live probe for every safe endpoint × each auth pass via ZAP (unsafe ones are skipped)."""
    from app.services.auth_probe_service import auth_passes
    from diagnosis.safety import is_dangerous_endpoint
    from inventory.probe_build import build_probe_request, format_raw_http_request

    endpoints = tree.endpoints
    limit = len(endpoints) if max_probes <= 0 else min(max_probes, len(endpoints))
    passes = auth_passes(account_auths or [], include_anonymous=include_anonymous)
    results: list[dict[str, Any]] = []
    total = limit * len(passes)
    done = 0

    for account_auth, auth_mode in passes:
        for ep in endpoints[:limit]:
            blocked, reason = is_dangerous_endpoint(ep.method, ep.path)
            if blocked:
                results.append(
                    {
                        "endpoint_id": ep.endpoint_id,
                        "method": ep.method.upper(),
                        "path": ep.path,
                        "base_url": ep.base_url,
                        "url": f"{ep.base_url}{ep.path}",
                        "http_status": None,
                        "skipped_unsafe": True,
                        "skip_reason": reason,
                        "auth_mode": auth_mode,
                        "account_email": account_auth.get("email") if account_auth else None,
                        "login_url": account_auth.get("login_url") if account_auth else None,
                    }
                )
                done += 1
                continue
            probe = build_probe_request(
                ep,
                probe_base_fn=probe_url,
                account_auth=account_auth,
            )
            raw = format_raw_http_request(probe)
            http_status = _zap_send_raw_request(zap, raw)

            results.append(
                {
                    "endpoint_id": ep.endpoint_id,
                    "method": ep.method.upper(),
                    "path": ep.path,
                    "base_url": ep.base_url,
                    "url": probe["url"],
                    "http_status": http_status,
                    "auth_mode": auth_mode,
                    "account_email": account_auth.get("email") if account_auth else None,
                    "login_url": account_auth.get("login_url") if account_auth else None,
                }
            )
            done += 1
            if on_progress and done % 25 == 0:
                on_progress(done, total)

    return results
