"""Collect file-upload probe targets for 2-1.

Two sources, in priority order:

1. **Explicit config** (``diagnosis_2_1.upload_endpoints`` in config.yaml) —
   when present, ONLY these endpoints are tested (per-endpoint mapping, no
   auto-discovered extras mixed in). This is how a caller pins the scan to a
   specific endpoint instead of scanning the whole inventory.
2. **Inventory auto-discovery** (api-tree) — endpoints tagged
   ``multipart/form-data`` or with a file-like body param, used only when no
   explicit endpoint list is configured.

Nothing here is specific to a single business role (e.g. "seller") — any
non-file field required by the endpoint (seller id, member id, ...) is
resolved generically from the api-tree sample value captured when the attack
surface was built, or from an explicit ``extra_fields`` override in config.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from diagnosis.replay.normalize import collect_probe_base_urls, dedupe_probe_bases
from inventory.load import load_api_tree
from inventory.net import probe_base_url
from inventory.probe_build import sample_value
from inventory.schema import ApiTree, Endpoint, split_path_query
from parsers.parse_endpoints import materialize_path_params

_FILE_FIELD_NAME = re.compile(
    r"(?i)^(images?|files?|photos?|pictures?|thumbnails?|avatars?|attachments?|uploads?)$"
)
_UPLOAD_METHODS = ("POST", "PUT")

# 경로 마지막 세그먼트가 아래 키워드 중 하나이면 업로드 엔드포인트가 아닌 액션 경로임.
# probe 아티팩트로 multipart Content-Type 헤더가 기록돼 있어도 제외한다.
_NON_UPLOAD_ACTION_SUFFIXES = re.compile(
    r"(?i)/("
    r"likes?|comments?|replies|restore|approve|reject|cancel|confirm"
    r"|activate|deactivate|enable|disable|publish|unpublish|archive"
    r"|follow|unfollow|bookmark|unbookmark|favorite|unfavorite"
    r"|view|views|read|reads|share|shares|report|reports"
    r"|count|counts|stat|stats|status|check|verify|validate"
    r")$"
)


@dataclass
class UploadTarget:
    base_url: str
    method: str
    path: str
    url: str
    label: str
    file_field: str
    extra_fields: dict[str, str] = field(default_factory=dict)  # multipart body 파라미터
    query_params: dict[str, str] = field(default_factory=dict)  # URL query string 파라미터
    allowed_extensions: list[str] | None = None
    source: str = "inventory"
    endpoint_id: str = ""
    business_role: str = "user"
    feature_key: str = "file_upload"
    feature_label: str = "File upload"


def _business_role(path: str) -> str:
    lowered = path.lower()
    if "/admin/" in lowered or lowered.startswith("/admin"):
        return "admin"
    if "/seller/" in lowered or lowered.startswith("/seller"):
        return "seller"
    return "user"


def _feature_key(path: str, file_field: str) -> str:
    lowered = path.lower()
    field = re.sub(r"[^a-z0-9]+", "_", file_field.lower()).strip("_") or "file"
    if "/posts" in lowered:
        return f"posts_{field}"
    if "/accommodations" in lowered:
        return f"accommodations_{field}"
    if "/cars" in lowered:
        return f"cars_{field}"
    normalized = re.sub(r"\{[^}]+\}", "id", lowered)
    normalized = re.sub(r"[^a-z0-9]+", "_", normalized).strip("_")
    return f"{normalized}_{field}" if normalized else f"upload_{field}"


def _feature_label(path: str, file_field: str) -> str:
    lowered = path.lower()
    if "/posts" in lowered:
        return f"Posts / {file_field}"
    if "/accommodations" in lowered:
        return f"Accommodations / {file_field}"
    if "/cars" in lowered:
        return f"Cars / {file_field}"
    return f"{path} / {file_field}"


def collect_base_urls(raw_config: dict[str, Any] | None) -> list[str]:
    deduped, _ = dedupe_probe_bases(collect_probe_base_urls(raw_config))
    return deduped


def _has_multipart_header(ep: Endpoint) -> bool:
    for h in ep.request_headers:
        if h.name.lower() == "content-type" and "multipart" in (h.sample or "").lower():
            return True
    return False


def _find_file_field(ep: Endpoint) -> str | None:
    candidates = [
        p
        for p in ep.request_params
        if p.in_ in ("body", "form") and _FILE_FIELD_NAME.search(p.name or "")
    ]
    if not candidates:
        return None
    # Prefer plural/array file fields (bulk image upload) over a lone match.
    for p in candidates:
        if p.type == "array":
            return p.name
    return candidates[0].name


def _form_fields_from_endpoint(ep: Endpoint, file_field: str) -> dict[str, str]:
    """multipart body에 포함할 form/body 파라미터 (file_field 제외)."""
    fields: dict[str, str] = {}
    seen_names: set[str] = set()
    for p in ep.request_params:
        if p.in_ not in ("body", "form"):
            continue
        if p.name == file_field or p.role != "input":
            continue
        if p.type == "array":
            continue
        if p.name in seen_names:
            continue
        seen_names.add(p.name)
        fields[p.name] = str(sample_value(p))
    return fields


def _query_params_from_endpoint(ep: Endpoint, file_field: str) -> dict[str, str]:
    """URL query string에 붙일 query 파라미터. 이미 form 파라미터로 취급된 파라미터는 제외."""
    form_names = {
        p.name for p in ep.request_params
        if p.in_ in ("body", "form") and p.name != file_field
    }
    fields: dict[str, str] = {}
    seen_names: set[str] = set()
    for p in ep.request_params:
        if p.in_ != "query":
            continue
        if p.name == file_field or p.role != "input":
            continue
        if p.type == "array":
            continue
        # form 파라미터로 이미 커버되는 것은 query에 중복 추가하지 않음
        if p.name in form_names:
            continue
        if p.name in seen_names:
            continue
        seen_names.add(p.name)
        fields[p.name] = str(sample_value(p))
    return fields


# 없어진 이름으로 호용 - 이전 코드 호환성 유지
def _extra_fields_from_endpoint(ep: Endpoint, file_field: str) -> dict[str, str]:
    return _form_fields_from_endpoint(ep, file_field)


def _is_non_upload_action(path: str) -> bool:
    """경로 마지막 세그먼트가 좋아요/댓글/복구 등 비업로드 액션이면 True."""
    return bool(_NON_UPLOAD_ACTION_SUFFIXES.search(path))


def discover_upload_endpoints(tree: ApiTree) -> list[Endpoint]:
    found: list[Endpoint] = []
    for ep in tree.endpoints:
        if ep.kind != "api" or ep.method.upper() not in _UPLOAD_METHODS:
            continue
        # 명확한 비업로드 액션 경로는 multipart 헤더 probe 아티팩트가 있어도 제외
        if _is_non_upload_action(ep.path):
            continue
        # 실제 파일 파라미터가 있으면 업로드 엔드포인트로 확정
        if _find_file_field(ep):
            found.append(ep)
            continue
        # multipart 헤더 기록이 있지만 파일 파라미터가 없는 경우:
        # probe 아티팩트일 가능성이 있으므로, 파라미터 구성이 명확한 경우에만 포함
        if _has_multipart_header(ep):
            # 파라미터가 아예 없거나 body/form 파라미터가 있으면 포함
            body_form_params = [p for p in ep.request_params if p.in_ in ("body", "form")]
            if body_form_params:
                found.append(ep)
    return found


def _endpoint_path(ep: Endpoint) -> str:
    path, _ = split_path_query(ep.path)
    path = path or "/"
    if "{" not in path:
        return path
    path_defaults = {
        p.name: str(sample_value(p)) for p in ep.request_params if p.in_ == "path"
    }
    return materialize_path_params(path, path_defaults)


def _from_inventory(
    raw_config: dict[str, Any] | None,
    *,
    data_dir: Path | None,
    default_allowed_extensions: list[str],
) -> tuple[list[UploadTarget], dict[str, Any]]:
    bases = collect_base_urls(raw_config)
    meta: dict[str, Any] = {"source": "inventory", "base_urls": len(bases)}
    if not bases:
        return [], meta

    tree = load_api_tree(data_dir)
    if not tree or not tree.endpoints:
        meta["inventory_missing"] = True
        return [], meta

    endpoints = discover_upload_endpoints(tree)
    meta["inventory_endpoints"] = len(tree.endpoints)
    meta["upload_endpoints_found"] = len(endpoints)

    tree_bases = {ep.base_url.rstrip("/").lower() for ep in endpoints}
    out: list[UploadTarget] = []
    seen: set[str] = set()
    for ep in endpoints:
        path = _endpoint_path(ep)
        file_field = _find_file_field(ep) or "file"
        extra_fields = _form_fields_from_endpoint(ep, file_field)
        query_params = _query_params_from_endpoint(ep, file_field)
        target_bases = (
            [ep.base_url] if ep.base_url.rstrip("/").lower() in tree_bases else bases
        )
        for base in target_bases or bases:
            probe_base = probe_base_url(base)
            base_url_path = f"{probe_base.rstrip('/')}{path}"
            # query params를 URL에 주입
            if query_params:
                from urllib.parse import urlencode
                base_url_path = f"{base_url_path}?{urlencode(query_params)}"
            url = base_url_path
            key = f"{ep.method.upper()}:{probe_base.rstrip('/')}{path}"
            if key in seen:
                continue
            seen.add(key)
            out.append(
                UploadTarget(
                    base_url=base,
                    method=ep.method.upper(),
                    path=path,
                    url=url,
                    label=f"{ep.method.upper()} {base}{path}",
                    file_field=file_field,
                    extra_fields=extra_fields,
                    query_params=query_params,
                    allowed_extensions=list(default_allowed_extensions),
                    source="inventory",
                    endpoint_id=ep.endpoint_id,
                    business_role=_business_role(path),
                    feature_key=_feature_key(path, file_field),
                    feature_label=_feature_label(path, file_field),
                )
            )
    meta["targets"] = len(out)
    return out, meta


def _from_config(
    raw_config: dict[str, Any] | None,
    entries: list[dict[str, Any]],
    *,
    default_allowed_extensions: list[str],
) -> tuple[list[UploadTarget], dict[str, Any]]:
    bases = collect_base_urls(raw_config)
    out: list[UploadTarget] = []
    for entry in entries:
        method = str(entry.get("method") or "POST").upper()
        path = str(entry.get("path") or "").strip()
        if not path:
            continue
        if not path.startswith("/"):
            path = f"/{path}"
        file_field = str(entry.get("file_field") or "file")
        extra_fields = {str(k): str(v) for k, v in (entry.get("extra_fields") or {}).items()}
        allowed = [str(e) for e in entry.get("allowed_extensions") or []] or list(
            default_allowed_extensions
        )
        configured_base = entry.get("base_url")
        target_bases = [str(configured_base)] if configured_base else bases
        for base in target_bases:
            probe_base = probe_base_url(base)
            url = f"{probe_base.rstrip('/')}{path}"
            out.append(
                UploadTarget(
                    base_url=base,
                    method=method,
                    path=path,
                    url=url,
                    label=f"{method} {base}{path}",
                    file_field=file_field,
                    extra_fields=extra_fields,
                    allowed_extensions=allowed,
                    source="config",
                    endpoint_id=f"{base.rstrip('/')}:{method}:{path}",
                    business_role=_business_role(path),
                    feature_key=_feature_key(path, file_field),
                    feature_label=_feature_label(path, file_field),
                )
            )
    return out, {"source": "config", "configured_endpoints": len(entries), "targets": len(out)}


def build_upload_targets(
    raw_config: dict[str, Any] | None,
    *,
    data_dir: Path | None = None,
    default_allowed_extensions: list[str] | None = None,
) -> tuple[list[UploadTarget], dict[str, Any]]:
    """Resolve probe targets. Explicit config endpoints take exclusive
    priority over inventory auto-discovery — see module docstring."""
    raw = raw_config or {}
    cfg = raw.get("diagnosis_2_1") or {}
    default_allowed = default_allowed_extensions or ["jpg", "jpeg", "png", "gif", "webp"]

    entries = cfg.get("upload_endpoints") or []
    if entries:
        return _from_config(raw, entries, default_allowed_extensions=default_allowed)

    return _from_inventory(raw, data_dir=data_dir, default_allowed_extensions=default_allowed)
