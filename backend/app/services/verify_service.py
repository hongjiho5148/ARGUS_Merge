"""Probe built inventory endpoints and produce a verified final api-tree."""

from __future__ import annotations

import asyncio
import json
import logging
import time
import logging
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from app.services.auth_probe_service import (
    auth_passes,
    build_login_entry_report,
    login_all_accounts,
)
from app.services.probe_report import endpoint_keeps_in_inventory, group_probe_results, summarize_probe_results
from app.services.test_accounts_service import load_test_accounts
from inventory.enrich_from_traffic import enrich_from_probe_response
from inventory.merge import merge_endpoints, restore_reference_samples
from inventory.net import probe_base_url
from inventory.probe_build import build_probe_request
from inventory.schema import ApiTree, Endpoint, InventoryMeta
from inventory.merge import merge_endpoint_headers
from inventory.traffic_params import (
    build_request_header_block,
    headers_from_observation,
    observation_from_message,
    observation_to_request_params,
    observation_to_response_params,
)

from diagnosis.safety import is_dangerous_endpoint

logger = logging.getLogger("uvicorn.error")
logger.setLevel(logging.INFO)

logger = logging.getLogger("uvicorn.error")
logger.setLevel(logging.INFO)

def _build_request(
    ep: Endpoint,
    account_auth: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return build_probe_request(
        ep,
        probe_base_fn=probe_base_url,
        account_auth=account_auth,
    )


def _classify(http_status: int | None, error: str | None) -> tuple[str, bool, bool]:
    """Return status label, include_in_final, params_ok."""
    if error:
        return "unreachable", False, False
    if http_status is None:
        return "error", False, False
    if http_status == 404:
        return "not_found", False, False
    if http_status == 405:
        return "method_not_allowed", False, False
    if http_status in (401, 403):
        return "confirmed", True, True
    if 200 <= http_status < 400:
        return "confirmed", True, True
    if http_status in (400, 422):
        return "params_issue", True, False
    if http_status >= 500:
        return "server_error", True, True
    return "unknown", False, False


def _note(http_status: int | None, error: str | None, status: str) -> str:
    if error:
        return error[:200]
    notes = {
        "confirmed": "Endpoint responded",
        "params_issue": "Route exists; check parameters",
        "not_found": "404 Not Found",
        "method_not_allowed": "405 Method Not Allowed",
        "server_error": f"Server error ({http_status})",
        "unreachable": "Connection failed",
        "unknown": f"Unexpected status ({http_status})",
    }
    if status == "confirmed" and http_status in (401, 403):
        return "Auth required — route exists"
    return notes.get(status, "")


def _skipped_unsafe_row(
    ep: Endpoint,
    reason: str,
    *,
    account_auth: dict[str, Any] | None,
    auth_mode: str,
) -> dict[str, Any]:
    return {
        "endpoint_id": ep.endpoint_id,
        "method": ep.method.upper(),
        "path": ep.path,
        "base_url": ep.base_url,
        "url": f"{ep.base_url}{ep.path}",
        "http_status": None,
        "status": "skipped_unsafe",
        "params_ok": True,
        "include_in_final": True,
        "discovered": False,
        "auth_mode": auth_mode,
        "account_email": account_auth.get("email") if account_auth else None,
        "login_url": account_auth.get("login_url") if account_auth else None,
        "login_label": account_auth.get("login_label") if account_auth else None,
        "params_enriched": 0,
        "note": f"Not probed (safety): {reason}",
    }


async def _probe(
    client: httpx.AsyncClient,
    ep: Endpoint,
    *,
    account_auth: dict[str, Any] | None = None,
    auth_mode: str = "anonymous",
) -> dict[str, Any]:
    blocked, reason = is_dangerous_endpoint(ep.method, ep.path)
    if blocked:
        return _skipped_unsafe_row(ep, reason, account_auth=account_auth, auth_mode=auth_mode)
    probe = _build_request(ep, account_auth=account_auth)
    method = probe["method"]
    url = probe["url"]
    headers = dict(probe["headers"])
    body_str = probe.get("body") or ""
    params_enriched = 0
    try:
        req_kwargs: dict[str, Any] = {
            "method": method,
            "url": url,
            "headers": headers,
            "timeout": 8.0,
            "follow_redirects": True,
        }
        if body_str:
            req_kwargs["content"] = body_str.encode("utf-8")
        resp = await client.request(**req_kwargs)

        ctype = headers.get("Content-Type", "application/json" if body_str else "")
        if body_str and "Content-Type" not in headers and "content-type" not in headers:
            headers["Content-Type"] = ctype
        fake_header = build_request_header_block(method, url, headers)
        response_header = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(
            f"{name}: {value}" for name, value in resp.headers.items()
        )
        obs = observation_from_message(
            method,
            url,
            fake_header,
            body_str,
            response_header=response_header,
            response_body=resp.text,
        )
        if obs:
            before_params = len(ep.request_params) + len(ep.response_params)
            before_headers = len(ep.request_headers) + len(ep.response_headers)
            merge_endpoints(
                ep,
                Endpoint(
                    method=ep.method,
                    path=ep.path,
                    base_url=ep.base_url,
                    request_params=observation_to_request_params(obs, source="probe"),
                    response_params=observation_to_response_params(obs, source="probe"),
                ),
            )
            req_hdrs, resp_hdrs = headers_from_observation(obs, "probe")
            merge_endpoint_headers(ep, req_hdrs, resp_hdrs)
            params_enriched += max(0, (len(ep.request_params) + len(ep.response_params)) - before_params)
            params_enriched += max(0, (len(ep.request_headers) + len(ep.response_headers)) - before_headers)

        if resp.status_code in (400, 422):
            params_enriched += enrich_from_probe_response(ep, resp.text, source="probe")

        status, include, params_ok = _classify(resp.status_code, None)
        return {
            "endpoint_id": ep.endpoint_id,
            "method": ep.method.upper(),
            "path": ep.path,
            "base_url": ep.base_url,
            "url": url,
            "http_status": resp.status_code,
            "status": status,
            "params_ok": params_ok,
            "include_in_final": include,
            "discovered": False,
            "auth_mode": auth_mode,
            "account_email": account_auth.get("email") if account_auth else None,
            "login_url": account_auth.get("login_url") if account_auth else None,
            "login_label": account_auth.get("login_label") if account_auth else None,
            "params_enriched": params_enriched,
            "note": _note(resp.status_code, None, status),
        }
    except httpx.RequestError as exc:
        status, include, params_ok = _classify(None, str(exc))
        return {
            "endpoint_id": ep.endpoint_id,
            "method": ep.method.upper(),
            "path": ep.path,
            "base_url": ep.base_url,
            "url": url,
            "http_status": None,
            "status": status,
            "params_ok": params_ok,
            "include_in_final": include,
            "discovered": False,
            "auth_mode": auth_mode,
            "account_email": account_auth.get("email") if account_auth else None,
            "login_url": account_auth.get("login_url") if account_auth else None,
            "login_label": account_auth.get("login_label") if account_auth else None,
            "params_enriched": params_enriched,
            "note": _note(None, str(exc), status),
        }


async def verify_inventory_async(
    tree: ApiTree,
    *,
    concurrency: int = 12,
    auth_cfg: dict[str, Any] | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    started = time.monotonic()
    probe_endpoints = list(tree.endpoints)
    logger.info(
        "verify httpx started: endpoints=%d concurrency=%d auth_configured=%s",
        len(probe_endpoints),
        concurrency,
        bool(auth_cfg),
    )
    logger.info(
        "verify httpx started: endpoints=%d concurrency=%d auth_configured=%s",
        len(probe_endpoints),
        concurrency,
        bool(auth_cfg),
    )

    account_auths: list[dict[str, Any]] = []
    accounts: list[dict[str, str]] = []
    if auth_cfg:
        login_started = time.monotonic()
        login_started = time.monotonic()
        accounts = load_test_accounts()["accounts"]
        account_auths = login_all_accounts(auth_cfg, accounts)
        logger.info(
            "verify login finished: accounts=%d authenticated=%d elapsed=%.2fs",
            len(accounts),
            len(account_auths),
            time.monotonic() - login_started,
        )
        logger.info(
            "verify login finished: accounts=%d authenticated=%d elapsed=%.2fs",
            len(accounts),
            len(account_auths),
            time.monotonic() - login_started,
        )

    passes = auth_passes(account_auths, include_anonymous=True)

    sem = asyncio.Semaphore(concurrency)
    merge_locks: dict[str, asyncio.Lock] = {}

    async with httpx.AsyncClient() as client:

        def merge_lock(endpoint_id: str) -> asyncio.Lock:
            if endpoint_id not in merge_locks:
                merge_locks[endpoint_id] = asyncio.Lock()
            return merge_locks[endpoint_id]

        async def run_pass(ep: Endpoint, account_auth: dict[str, Any] | None, auth_mode: str) -> dict[str, Any]:
            async with sem:
                work = Endpoint.from_dict(ep.to_dict())
                result = await _probe(
                    client,
                    work,
                    account_auth=account_auth,
                    auth_mode=auth_mode,
                )
                async with merge_lock(ep.endpoint_id):
                    merge_endpoints(ep, work)
                return result

        tasks = [
            run_pass(ep, account_auth, auth_mode)
            for ep in probe_endpoints
            for account_auth, auth_mode in passes
        ]
        results = list(await asyncio.gather(*tasks))

    logger.info(
        "verify endpoint probes finished: probe_runs=%d elapsed=%.2fs",
        len(results),
        time.monotonic() - started,
    )

    logger.info(
        "verify endpoint probes finished: probe_runs=%d elapsed=%.2fs",
        len(results),
        time.monotonic() - started,
    )

    grouped = group_probe_results(results)

    verified_endpoints: list[Endpoint] = []
    for ep in probe_endpoints:
        ep_rows = grouped.get(ep.endpoint_id, [])
        if ep_rows and endpoint_keeps_in_inventory(ep, ep_rows):
            verified_endpoints.append(ep)

    params_enriched = sum(int(r.get("params_enriched") or 0) for r in results)
    endpoint_summary = summarize_probe_results(results)
    endpoint_summary["verified_count"] = len(verified_endpoints)
    logger.info(
        "verify summary: probe_runs=%d endpoints_probed=%d confirmed=%d "
        "params_issues=%d rejected=%d verified=%d params_enriched=%d elapsed=%.2fs",
        endpoint_summary["probe_runs"],
        endpoint_summary["endpoints_probed"],
        endpoint_summary["confirmed"],
        endpoint_summary["params_issues"],
        endpoint_summary["rejected"],
        len(verified_endpoints),
        params_enriched,
        time.monotonic() - started,
    )
    logger.info(
        "verify summary: probe_runs=%d endpoints_probed=%d confirmed=%d "
        "params_issues=%d rejected=%d verified=%d params_enriched=%d elapsed=%.2fs",
        endpoint_summary["probe_runs"],
        endpoint_summary["endpoints_probed"],
        endpoint_summary["confirmed"],
        endpoint_summary["params_issues"],
        endpoint_summary["rejected"],
        len(verified_endpoints),
        params_enriched,
        time.monotonic() - started,
    )

    verified_tree = ApiTree(
        meta=InventoryMeta(
            app_name=tree.meta.app_name,
            sources_used=sorted(set(tree.meta.sources_used)),
            sources_missing=tree.meta.sources_missing,
        ),
        endpoints=verified_endpoints,
    )

    login_entry_report = (
        build_login_entry_report(auth_cfg or {}, accounts, account_auths) if auth_cfg else None
    )

    return {
        "checked_at": datetime.now(UTC).isoformat(),
        "probe_runs": endpoint_summary["probe_runs"],
        "endpoints_probed": endpoint_summary["endpoints_probed"],
        "total_checked": endpoint_summary["endpoints_probed"],
        "confirmed": endpoint_summary["confirmed"],
        "params_issues": endpoint_summary["params_issues"],
        "rejected": endpoint_summary["rejected"],
        "verified_count": len(verified_endpoints),
        "final_count": len(verified_endpoints),
        "discovered_count": 0,
        "params_enriched": params_enriched,
        "accounts_logged_in": len(account_auths),
        "account_auths": account_auths,
        "login_entry_report": login_entry_report,
        "results": results,
        "verified_tree": verified_tree,
    }


def verify_inventory(tree: ApiTree, *, auth_cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    return asyncio.run(verify_inventory_async(tree, auth_cfg=auth_cfg))


def persist_verification(data_dir: Path, payload: dict[str, Any], *, original_tree: ApiTree) -> dict[str, str]:
    data_dir.mkdir(parents=True, exist_ok=True)
    report_path = data_dir / "verify-report.json"
    verified_path = data_dir / "api-tree-verified.json"
    api_tree_path = data_dir / "api-tree.json"

    verified_tree: ApiTree = payload["verified_tree"]
    restored_samples = restore_reference_samples(verified_tree, original_tree)
    verified_count = len(verified_tree.endpoints)
    should_persist_tree = verified_count > 0 or int(payload.get("params_enriched", 0)) > 0
    if not should_persist_tree:
        warning = (
            "Verify produced 0 verified endpoints; api-tree-verified.json was not "
            "updated and the previous verified inventory was retained."
        )
        payload["warning"] = warning
        payload["error"] = "verify_empty_result"
        logger.warning(
            "verify produced 0 verified endpoints, api-tree-verified.json was not updated"
        )

    report = {
        "checked_at": payload["checked_at"],
        "summary": {
            "total_checked": payload["total_checked"],
            "confirmed": payload["confirmed"],
            "params_issues": payload["params_issues"],
            "rejected": payload["rejected"],
            "verified_count": payload["verified_count"],
            "final_count": payload.get("final_count", payload["verified_count"]),
            "discovered_count": payload.get("discovered_count", 0),
            "params_enriched": payload.get("params_enriched", 0),
            "probe_runs": payload.get("probe_runs", payload.get("total_checked", 0)),
            "endpoints_probed": payload.get("endpoints_probed", payload.get("verified_count", 0)),
            "accounts_logged_in": payload.get("accounts_logged_in", 0),
            "persisted": should_persist_tree,
            "persisted": should_persist_tree,
        },
        "results": payload["results"],
    }
    if payload.get("warning"):
        report["warning"] = payload["warning"]
    if payload.get("error"):
        report["error"] = payload["error"]
    if payload.get("warning"):
        report["warning"] = payload["warning"]
    if payload.get("error"):
        report["error"] = payload["error"]
    if payload.get("login_entry_report") is not None:
        report["login_entry_report"] = payload["login_entry_report"]
    if payload.get("account_auths"):
        report["account_auths"] = payload["account_auths"]
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    artifacts: dict[str, str] = {"verify_report": str(report_path)}
    if should_persist_tree:
        verified_tree.save(verified_path)
        verified_tree.save(api_tree_path)
        artifacts["api_tree_verified"] = str(verified_path)
        artifacts["api_tree"] = str(api_tree_path)
        if restored_samples:
            artifacts["samples_restored"] = str(restored_samples)
    else:
        original_tree.save(api_tree_path)
        artifacts["api_tree"] = str(api_tree_path)

    return artifacts


def merge_verification_payloads(zap_payload: dict, httpx_payload: dict) -> dict:
    """Combine ZAP discover with httpx probe enrichments (inputs + 422 fields)."""
    merged = dict(zap_payload)
    merged["verified_tree"] = httpx_payload["verified_tree"]
    merged["results"] = list(zap_payload.get("results") or []) + list(httpx_payload.get("results") or [])
    merged["params_enriched"] = int(zap_payload.get("params_enriched", 0)) + int(
        httpx_payload.get("params_enriched", 0)
    )
    merged["probe_runs"] = int(zap_payload.get("probe_runs", 0)) + int(httpx_payload.get("probe_runs", 0))
    merged["verified_count"] = len(httpx_payload["verified_tree"].endpoints)
    merged["final_count"] = int(httpx_payload.get("final_count", merged["verified_count"]))
    merged["mode"] = "zap_discover+probe"
    if httpx_payload.get("login_entry_report") is not None:
        merged["login_entry_report"] = httpx_payload["login_entry_report"]
    if httpx_payload.get("account_auths"):
        merged["account_auths"] = httpx_payload["account_auths"]
    return merged
