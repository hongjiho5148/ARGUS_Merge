"""Build ScanTarget list from verified api-tree (same pattern as 2-2 / 1-5)."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from app.services.zap_util import probe_url
from diagnosis.replay.normalize import FRONTEND_PORTS, filter_endpoints_by_probe_bases
from inventory.load import load_api_tree
from inventory.schema import Endpoint, InputParam

try:
    from .models import InputSource, ParamLocation, ScanParam, ScanTarget
    from .sample_values import pick_sample_value
except ImportError:
    _module_dir = Path(__file__).resolve().parent
    _models_spec = importlib.util.spec_from_file_location("diag_g12_models", _module_dir / "models.py")
    _samples_spec = importlib.util.spec_from_file_location("diag_g12_sample_values", _module_dir / "sample_values.py")
    if _models_spec is None or _models_spec.loader is None or _samples_spec is None or _samples_spec.loader is None:
        raise
    _models = importlib.util.module_from_spec(_models_spec)
    _models_spec.loader.exec_module(_models)
    _samples = importlib.util.module_from_spec(_samples_spec)
    _samples_spec.loader.exec_module(_samples)
    InputSource = _models.InputSource
    ParamLocation = _models.ParamLocation
    ScanParam = _models.ScanParam
    ScanTarget = _models.ScanTarget
    pick_sample_value = _samples.pick_sample_value

_LOCATION_MAP = {
    "query": ParamLocation.QUERY,
    "path": ParamLocation.PATH,
    "body": ParamLocation.BODY,
    "form": ParamLocation.BODY,
    "header": ParamLocation.HEADER,
    "cookie": ParamLocation.HEADER,
}


def _param_location(param: InputParam) -> ParamLocation:
    return _LOCATION_MAP.get(param.in_, ParamLocation.QUERY)


def _sample_value(param: InputParam) -> str:
    return pick_sample_value(param.name, param_type=param.type, sample=param.sample)


def _is_api_base(base_url: str) -> bool:
    parsed = urlparse(base_url)
    port = parsed.port
    if port is None:
        port = 443 if (parsed.scheme or "http") == "https" else 80
    return port not in FRONTEND_PORTS


def _endpoint_rank(ep: Endpoint) -> tuple[int, int, int, str]:
    """Prefer API backends (8080/8081) and endpoints that have injectable params."""
    param_count = len(ep.request_params or [])
    return (
        1 if _is_api_base(ep.base_url) else 0,
        1 if param_count > 0 else 0,
        param_count,
        ep.endpoint_id,
    )


def endpoint_to_scan_target(ep: Endpoint) -> ScanTarget:
    params = [
        ScanParam(
            name=p.name,
            location=_param_location(p),
            required=bool(p.required),
            sample_value=_sample_value(p),
        )
        for p in ep.request_params
        if p.role != "meta"
    ]
    probed_base = probe_url(ep.base_url.rstrip("/"))
    return ScanTarget(
        method=ep.method.upper(),
        base_url=probed_base.rstrip("/"),
        path=ep.path if ep.path.startswith("/") else f"/{ep.path}",
        params=params,
        tags=list(ep.tags),
        allowed_roles=list(ep.auth),
        source=InputSource.API_LIST,
        raw=ep.endpoint_id,
        content_type="application/json",
    )


def load_scan_targets(
    data_dir: Path,
    raw_config: dict[str, Any],
    *,
    max_targets: int,
    scan_all: bool,
) -> tuple[list[ScanTarget], dict[str, Any]]:
    tree = load_api_tree(data_dir)
    if tree is None or not tree.endpoints:
        return [], {"error": "no_api_tree"}

    scoped = filter_endpoints_by_probe_bases(tree.endpoints, raw_config)
    if not scoped:
        return [], {
            "error": "no_matching_base_urls",
            "inventory_endpoints": len(tree.endpoints),
        }

    api_eps = [ep for ep in scoped if ep.kind == "api" and _is_api_base(ep.base_url)]
    if not api_eps:
        api_eps = [ep for ep in scoped if ep.kind == "api"]

    ranked = sorted(api_eps, key=_endpoint_rank, reverse=True)
    if not scan_all and max_targets > 0:
        ranked = ranked[:max_targets]

    targets = [endpoint_to_scan_target(ep) for ep in ranked]
    with_params = sum(1 for t in targets if t.params)

    meta = {
        "target_source": "api_tree",
        "inventory_endpoints": len(tree.endpoints),
        "scoped_endpoints": len(scoped),
        "api_backend_endpoints": len(api_eps),
        "scan_targets": len(targets),
        "targets_with_params": with_params,
    }
    return targets, meta
