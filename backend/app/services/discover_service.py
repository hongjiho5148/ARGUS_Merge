"""ZAP-based active discovery: login, OpenAPI import, seeds, spider, merge."""

from __future__ import annotations

import json
import logging
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from app.services import discover_progress
from app.services.auth_probe_service import login_all_accounts
from app.services.probe_report import (
    dedupe_probe_results,
    endpoint_keeps_in_inventory,
    group_probe_results,
    summarize_probe_results,
)
from app.services.base_urls_service import resolved_base_url_strings
from app.services.test_accounts_service import load_test_accounts
from app.services.verify_service import _classify, _note
from app.services.zap_util import (
    apply_auth_to_zap,
    collect_site_urls,
    collect_traffic_observations,
    connect_zap,
    ensure_zap_proxy,
    probe_url,
    replay_inventory_probes,
    run_ajax_spider,
    run_spider,
    ZapNotAvailableError,
)
from inventory.enrich_from_traffic import enrich_tree_from_built_probes, enrich_tree_from_observations
from inventory.merge import merge_trees
from inventory.load import find_openapi_specs
from inventory.schema import ApiTree, Endpoint, InventoryMeta, build_full_url

logger = logging.getLogger("uvicorn.error")
logger.setLevel(logging.INFO)


def _load_raw_config(config_path: Path) -> dict[str, Any]:
    if not config_path.is_file():
        return {}
    return yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}



def _origin_key(url: str) -> str:
    """scheme://host:port with the local aliases collapsed, so a saved
    ``localhost:5173`` matches the runtime ``host.docker.internal:5173``."""
    parsed = urlparse(str(url or "").strip())
    host = (parsed.hostname or "").lower()
    if host in {"127.0.0.1", "host.docker.internal"}:
        host = "localhost"
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme or 'http'}://{host}{port}"


def _saved_kinds() -> dict[str, str]:
    from app.services.base_urls_service import load_base_urls

    try:
        return {_origin_key(e["url"]): (e.get("kind") or "api") for e in load_base_urls()["urls"]}
    except Exception:
        return {}


def _frontend_base(bases: list[str]) -> str | None:
    kinds = _saved_kinds()
    registered = [b for b in bases if kinds.get(_origin_key(b)) in {"frontend", "api-and-frontend"}]
    if registered:
        return registered[0].rstrip("/")
    # Nothing marked as a frontend in the Base URLs panel (older setups): fall
    # back to the common dev-server port.
    for base in bases:
        if ":5173" in base or base.endswith(":5173"):
            return base.rstrip("/")
    return None


def _api_bases(bases: list[str]) -> list[str]:
    kinds = _saved_kinds()
    if any(kinds.get(_origin_key(b)) in {"frontend", "api-and-frontend"} for b in bases):
        return [b.rstrip("/") for b in bases if kinds.get(_origin_key(b)) in {"api", "api-and-frontend", None}]
    out: list[str] = []
    for base in bases:
        if ":8080" in base or ":8081" in base:
            out.append(base.rstrip("/"))
    return out or [b.rstrip("/") for b in bases if "5173" not in b]


def _rows_from_probe_results(probe_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for pr in probe_results:
        http_status = pr.get("http_status")
        if pr.get("skipped_unsafe"):
            rows.append(
                {
                    "endpoint_id": pr["endpoint_id"],
                    "method": pr["method"],
                    "path": pr["path"],
                    "base_url": pr["base_url"],
                    "url": pr["url"],
                    "http_status": None,
                    "status": "skipped_unsafe",
                    "params_ok": True,
                    "include_in_final": True,
                    "discovered": False,
                    "note": f"Not probed (safety): {pr.get('skip_reason', '')}",
                    "source": "zap_discover",
                }
            )
            continue
        status, include, params_ok = _classify(http_status, None)
        rows.append(
            {
                "endpoint_id": pr["endpoint_id"],
                "method": pr["method"],
                "path": pr["path"],
                "base_url": pr["base_url"],
                "url": pr["url"],
                "http_status": http_status,
                "status": status,
                "params_ok": params_ok,
                "include_in_final": include,
                "discovered": False,
                "note": _note(http_status, None, status),
                "source": "zap_discover",
            }
        )
    return rows


def _urls_to_new_endpoints(urls: set[str], existing_ids: set[str], bases: list[str]) -> list[Endpoint]:
    new_eps: list[Endpoint] = []
    for raw_url in sorted(urls):
        parsed = urlparse(raw_url)
        base = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
        if not any(probe_url(b.rstrip("/")) == base for b in bases):
            continue
        path = parsed.path or "/"
        method = "GET"
        eid = f"{base.replace('http://', 'http://localhost:')}:{method}:{path}"
        # normalize id to match inventory localhost convention
        for b in bases:
            if probe_url(b.rstrip("/")) == base:
                base = b.rstrip("/")
                break
        eid = f"{base}:{method}:{path}"
        if eid in existing_ids:
            continue
        if not path.startswith("/"):
            continue
        new_eps.append(
            Endpoint(
                method=method,
                path=path,
                base_url=base,
                request_params=[],
                sources=["zap_discover"],
                # callers pass API origins only (frontend dev-proxy traffic is excluded)
                kind="api",
            )
        )
        existing_ids.add(eid)
    return new_eps


def discover_inventory_sync(
    tree: ApiTree,
    *,
    data_dir: Path,
    config_path: Path,
    spider_enabled: bool | None = None,
    ajax_spider_enabled: bool | None = None,
    seed_requestor: bool | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    raw_cfg = _load_raw_config(config_path)
    discover_progress.reset(total_steps=6)
    discover_progress.persist(data_dir)

    bases = resolved_base_url_strings() or sorted({ep.base_url for ep in tree.endpoints})
    frontend = _frontend_base(bases)
    api_bases = _api_bases(bases)
    logger.info(
        "ZAP verify started: endpoints=%d bases=%s api_bases=%s frontend=%s",
        len(tree.endpoints),
        bases,
        api_bases,
        frontend,
    )

    zap_cfg = raw_cfg.get("zap") or {}
    discover_cfg = dict(raw_cfg.get("discover") or {})
    if spider_enabled is not None:
        discover_cfg["spider_enabled"] = spider_enabled
    if ajax_spider_enabled is not None:
        discover_cfg["ajax_spider_enabled"] = ajax_spider_enabled
    if seed_requestor is not None:
        discover_cfg["seed_requestor"] = seed_requestor
    auth_cfg = raw_cfg.get("auth") or {}

    proxy = str(zap_cfg.get("proxy") or "http://127.0.0.1:8090")
    api_key = str(zap_cfg.get("api_key") or "")

    def _zap_progress(msg: str) -> None:
        discover_progress.update(phase="zap", message=msg, step=1)
        discover_progress.persist(data_dir)

    discover_progress.update(phase="zap", message="Connecting to ZAP…", step=1)
    discover_progress.persist(data_dir)
    proxy = ensure_zap_proxy(zap_cfg, on_progress=_zap_progress)

    zap = connect_zap(proxy, api_key)

    # Step 1 — login all saved test accounts
    discover_progress.update(phase="login", message="Logging in with saved test accounts…", step=1)
    discover_progress.persist(data_dir)
    accounts = load_test_accounts()["accounts"]
    login_started = time.monotonic()
    account_auths = login_all_accounts(auth_cfg, accounts)
    logger.info(
        "ZAP verify login finished: accounts=%d authenticated=%d elapsed=%.2fs",
        len(accounts),
        len(account_auths),
        time.monotonic() - login_started,
    )
    if account_auths:
        apply_auth_to_zap(zap, account_auths[0])
        emails = ", ".join(str(a.get("email", "")) for a in account_auths[:3])
        suffix = "…" if len(account_auths) > 3 else ""
        discover_progress.update(
            phase="login",
            message=f"Logged in {len(account_auths)} account(s): {emails}{suffix}",
        )
    else:
        discover_progress.update(phase="login", message="No accounts logged in — anonymous probe only")
    discover_progress.persist(data_dir)

    # Step 2 — OpenAPI import per API base
    discover_progress.update(phase="openapi", message="Importing Swagger into ZAP…", step=2)
    discover_progress.persist(data_dir)
    openapi_paths = find_openapi_specs(data_dir)
    if discover_cfg.get("openapi_import", True) and openapi_paths:
        for openapi_path in openapi_paths:
            for base in api_bases:
                target = probe_url(base)
                try:
                    zap.openapi.import_file(str(openapi_path), target)
                except Exception:
                    try:
                        zap.openapi.import_url(f"{target}/v3/api-docs", target)
                    except Exception:
                        pass

    # Step 3 — replay every endpoint (GET/POST/PUT/PATCH/DELETE) through ZAP
    discover_progress.update(
        phase="seeds",
        message="Probing all endpoints via ZAP (every HTTP method)…",
        step=3,
    )
    discover_progress.persist(data_dir)
    max_seeds = int(discover_cfg.get("max_seeds", 0))
    if discover_cfg.get("seed_requestor", True):
        seed_started = time.monotonic()

        def _seed_progress(done: int, total: int) -> None:
            discover_progress.update(
                phase="seeds",
                message=f"Probing endpoints… {done}/{total}",
            )
            discover_progress.persist(data_dir)

        probe_results = replay_inventory_probes(
            zap,
            tree,
            max_probes=max_seeds,
            account_auths=account_auths,
            include_anonymous=True,
            on_progress=_seed_progress,
        )
        logger.info(
            "ZAP endpoint probes finished: runs=%d responses=%d elapsed=%.2fs",
            len(probe_results),
            sum(1 for row in probe_results if row.get("http_status") is not None),
            time.monotonic() - seed_started,
        )
        discover_progress.update(
            phase="seeds",
            message=f"Probed {len(probe_results)} request(s) (guest + {len(account_auths)} account(s))",
        )
        discover_progress.persist(data_dir)
    else:
        probe_results = []

    # Step 4 — spider WEB
    run_spiders = bool(discover_cfg.get("spider_enabled")) or bool(discover_cfg.get("ajax_spider_enabled"))
    if run_spiders and frontend:
        spider_max = int(discover_cfg.get("spider_max_seconds", 90))
        ajax_max = int(discover_cfg.get("ajax_spider_max_seconds", 90))
        web_url = probe_url(frontend)

        def _spider_tick(elapsed: int, limit: int) -> None:
            discover_progress.update(
                phase="spider",
                message=f"Spidering {frontend}… ({elapsed}s / max {limit}s)",
            )
            discover_progress.persist(data_dir)

        discover_progress.update(phase="spider", message=f"Spidering {frontend}…", step=4)
        discover_progress.persist(data_dir)
        if discover_cfg.get("spider_enabled"):
            spider_started = time.monotonic()
            run_spider(zap, web_url, max_seconds=spider_max, on_tick=_spider_tick)
            logger.info(
                "ZAP spider finished: base=%s max_seconds=%d elapsed=%.2fs",
                frontend,
                spider_max,
                time.monotonic() - spider_started,
            )
        if discover_cfg.get("ajax_spider_enabled"):

            def _ajax_tick(elapsed: int, limit: int) -> None:
                discover_progress.update(
                    phase="spider",
                    message=f"Ajax spider {frontend}… ({elapsed}s / max {limit}s)",
                )
                discover_progress.persist(data_dir)

            discover_progress.update(phase="spider", message=f"Ajax spider {frontend}…", step=4)
            discover_progress.persist(data_dir)
            ajax_started = time.monotonic()
            run_ajax_spider(zap, web_url, max_seconds=ajax_max, on_tick=_ajax_tick)
            ajax_elapsed = time.monotonic() - ajax_started
            logger.info(
                "ZAP Ajax spider finished: base=%s max_seconds=%d elapsed=%.2fs timed_out=%s",
                frontend,
                ajax_max,
                ajax_elapsed,
                ajax_elapsed >= ajax_max,
            )

    # Step 5 — collect ZAP URLs
    discover_progress.update(phase="collect", message="Collecting URLs from ZAP Sites tree…", step=5)
    discover_progress.persist(data_dir)
    all_site_urls: set[str] = set()
    collect_started = time.monotonic()
    # The frontend tree contains every dev-proxy request and can grow very
    # large. Only registered backend origins can become inventory API rows;
    # Ajax traffic that actually reached those origins remains visible there.
    for base in api_bases:
        all_site_urls |= collect_site_urls(zap, base)
    traffic_obs = collect_traffic_observations(zap)
    logger.info(
        "ZAP collection finished: api_bases=%s urls=%d traffic_observations=%d elapsed=%.2fs",
        api_bases,
        len(all_site_urls),
        len(traffic_obs),
        time.monotonic() - collect_started,
    )

    # Step 6 — classify + merge new endpoints + enrich params from traffic
    discover_progress.update(
        phase="merge",
        message=f"Enriching parameters from {len(traffic_obs)} traffic observation(s)…",
        step=6,
    )
    discover_progress.persist(data_dir)

    seed_enriched = 0
    if discover_cfg.get("seed_requestor", True):
        seed_enriched = enrich_tree_from_built_probes(
            tree,
            account_auths,
            include_anonymous=True,
            source="zap_probe",
        )

    enriched_tree, params_enriched = enrich_tree_from_observations(
        tree,
        traffic_obs,
        source="zap_traffic",
    )
    params_enriched += seed_enriched

    results = _rows_from_probe_results(probe_results)
    grouped = group_probe_results(results)

    existing_ids = {ep.endpoint_id for ep in enriched_tree.endpoints}
    # Only backend origins explicitly present in the Attack Surface Map may
    # contribute discovered API endpoints.  In particular, do not turn API
    # calls observed through a frontend dev proxy into separate :5173 rows.
    new_eps = _urls_to_new_endpoints(all_site_urls, existing_ids, api_bases)
    discovered_tree = merge_trees(
        [enriched_tree, ApiTree(meta=enriched_tree.meta, endpoints=new_eps)],
        app_name=tree.meta.app_name,
    )

    verified_endpoints: list[Endpoint] = []
    for ep in enriched_tree.endpoints:
        ep_rows = grouped.get(ep.endpoint_id, [])
        if endpoint_keeps_in_inventory(ep, ep_rows):
            verified_endpoints.append(ep)
    for ep in new_eps:
        verified_endpoints.append(ep)

    verified_tree = ApiTree(
        meta=InventoryMeta(
            app_name=tree.meta.app_name,
            sources_used=sorted(
                set(enriched_tree.meta.sources_used + (["zap_discover"] if new_eps else []) + (["zap_traffic"] if params_enriched else []))
            ),
            sources_missing=tree.meta.sources_missing,
        ),
        endpoints=verified_endpoints,
    )

    discovered_results: list[dict[str, Any]] = []
    for ep in new_eps:
        url = build_full_url(probe_url(ep.base_url), ep.path)
        discovered_results.append(
            {
                "endpoint_id": ep.endpoint_id,
                "method": ep.method.upper(),
                "path": ep.path,
                "base_url": ep.base_url,
                "url": url,
                "http_status": 200,
                "status": "confirmed",
                "params_ok": True,
                "include_in_final": True,
                "discovered": True,
                "note": "New via ZAP discover",
                "source": "zap_discover",
            }
        )

    all_results = results + discovered_results
    endpoint_summary = summarize_probe_results(all_results)
    discovered_count = endpoint_summary["discovered_count"]
    final_count = endpoint_summary["final_count"]
    logger.info(
        "ZAP verify summary: probe_runs=%d endpoints_probed=%d confirmed=%d "
        "rejected=%d verified=%d discovered=%d params_enriched=%d elapsed=%.2fs",
        endpoint_summary["probe_runs"],
        endpoint_summary["endpoints_probed"],
        endpoint_summary["confirmed"],
        endpoint_summary["rejected"],
        len(verified_endpoints),
        discovered_count,
        params_enriched,
        time.monotonic() - started,
    )
    deduped = dedupe_probe_results(all_results)

    confirmed = sum(1 for r in deduped if r.get("status") == "confirmed")
    params_issues = sum(1 for r in deduped if r.get("status") == "params_issue")
    rejected = endpoint_summary["rejected"]

    discover_progress.finish(
        f"ZAP discover complete — {len(verified_endpoints)} endpoints "
        f"({discovered_count} new URL(s), {params_enriched} param enrichments)."
    )
    discover_progress.persist(data_dir)

    return {
        "mode": "zap_discover",
        "checked_at": datetime.now(UTC).isoformat(),
        "probe_runs": endpoint_summary["probe_runs"],
        "endpoints_probed": endpoint_summary["endpoints_probed"],
        "total_checked": endpoint_summary["endpoints_probed"],
        "confirmed": confirmed,
        "params_issues": params_issues,
        "rejected": rejected,
        "verified_count": len(verified_endpoints),
        "final_count": final_count,
        "discovered_count": discovered_count,
        "newly_discovered": discovered_count,
        "zap_urls_collected": len(all_site_urls),
        "traffic_observations": len(traffic_obs),
        "params_enriched": params_enriched,
        "accounts_logged_in": len(account_auths),
        "auth_applied": len(account_auths) > 0,
        "results": all_results,
        "verified_tree": verified_tree,
        "discovered_tree": discovered_tree,
    }


async def discover_inventory_async(
    tree: ApiTree,
    *,
    data_dir: Path,
    config_path: Path,
    spider_enabled: bool | None = None,
    ajax_spider_enabled: bool | None = None,
    seed_requestor: bool | None = None,
) -> dict[str, Any]:
    import asyncio

    return await asyncio.to_thread(
        discover_inventory_sync,
        tree,
        data_dir=data_dir,
        config_path=config_path,
        spider_enabled=spider_enabled,
        ajax_spider_enabled=ajax_spider_enabled,
        seed_requestor=seed_requestor,
    )
