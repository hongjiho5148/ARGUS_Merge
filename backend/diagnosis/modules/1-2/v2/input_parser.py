"""
ARGUS - SSRF / File Inclusion 진단 모듈

"Build Attack Tree" 모달에서 선택 가능한 3가지 입력 소스를 각각 파싱합니다.
  1) URL List  : 줄바꿈으로 구분된 전체 URL 텍스트
  2) API List  : "METHOD endpoint" 형식 텍스트 (Postman/Insomnia export 등에서 흔한 형태)
  3) Swagger   : OpenAPI/Swagger JSON (URL 또는 업로드 파일 경로)
"""

import json
import re
from typing import Dict, List, Optional, Union

import requests

from models import ScanTarget, ScanParam, ParamLocation, InputSource


def _operation_roles(path: str, detail: dict) -> List[str]:
    """Read declarative role metadata only; never infer roles from product URLs."""
    raw_roles = (
        detail.get("x-roles")
        or detail.get("x-allowed-roles")
        or detail.get("x-role")
        or []
    )
    if isinstance(raw_roles, str):
        raw_roles = [raw_roles]

    roles: List[str] = []
    for value in raw_roles:
        role = str(value).strip()
        if role and role.casefold() not in {r.casefold() for r in roles}:
            roles.append(role)
    return roles


def filter_targets_by_role(targets: List[ScanTarget], role: str,
                           access_decisions: Optional[Dict[tuple, bool]] = None,
                           role_aliases: Optional[List[str]] = None) -> List[ScanTarget]:
    """Filter with x-roles first and token-probe decisions second."""
    if not role or role.casefold() == "all":
        return targets

    def role_key(value: str) -> str:
        key = value.strip().casefold()
        return key[5:] if key.startswith("role_") else key

    aliases = {role_key(role), *(role_key(r) for r in role_aliases or [])}
    selected = []
    for target in targets:
        if target.allowed_roles:
            if not aliases.intersection(role_key(r) for r in target.allowed_roles):
                continue

        key = (target.method, target.full_url)
        if access_decisions is None or access_decisions.get(key, True):
            selected.append(target)
    return selected


# --------------------------------------------------------------------------
# 1) URL List 파서
# --------------------------------------------------------------------------
def parse_url_list(raw_text: str) -> List[ScanTarget]:
    """
    줄바꿈으로 구분된 URL 목록을 파싱합니다.
    빈 줄, 주석(#으로 시작), 잘못된 URL은 무시합니다.

    예시 입력:
        https://target.com/view?file=a.pdf
        https://target.com/proxy?url=http://internal/api
    """
    targets: List[ScanTarget] = []

    for line in raw_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not re.match(r"^https?://", line, re.IGNORECASE):
            continue  # 스킴이 없는 라인은 건너뜀
        try:
            targets.append(ScanTarget.from_raw_url(line))
        except Exception as e:
            print(f"[URL List 파싱 실패] {line} -> {e}")

    return targets


# --------------------------------------------------------------------------
# 2) API List 파서
# --------------------------------------------------------------------------
# 지원 형식 예시:
#   GET  https://target.com/api/v1/files?path=report.pdf
#   POST https://target.com/api/v1/webhook  {"callbackUrl": "http://x.com"}
#   PUT  /api/v1/profile/avatar  {"imageUrl": "http://x.com/a.png"}   (base_url 별도 지정)
API_LINE_PATTERN = re.compile(
    r"^(?P<method>GET|POST|PUT|DELETE|PATCH)\s+"
    r"(?P<url>\S+)"
    r"(?:\s+(?P<body>\{.*\}))?$",
    re.IGNORECASE,
)


def parse_api_list(raw_text: str, default_base_url: str = "") -> List[ScanTarget]:
    """
    "METHOD URL [JSON_BODY]" 형식의 API 목록을 파싱합니다.
    URL이 절대경로(https://...)가 아니면 default_base_url을 붙입니다.
    JSON body가 있으면 body 내부 키도 ScanParam(location=BODY)으로 추출합니다.
    """
    targets: List[ScanTarget] = []

    for line in raw_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        match = API_LINE_PATTERN.match(line)
        if not match:
            print(f"[API List 파싱 실패 - 형식 불일치] {line}")
            continue

        method = match.group("method").upper()
        url = match.group("url")
        body_str = match.group("body")

        # base_url 결정
        if url.startswith("http://") or url.startswith("https://"):
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            path = parsed.path or "/"
            query_params = parse_qs(parsed.query)
        else:
            if not default_base_url:
                print(f"[API List 파싱 경고] 절대경로가 아니지만 default_base_url 미지정: {url}")
                continue
            base_url = default_base_url
            path = url if url.startswith("/") else f"/{url}"
            query_params = {}

        params = [
            ScanParam(name=k, location=ParamLocation.QUERY,
                      sample_value=v[0] if v else None)
            for k, v in query_params.items()
        ]

        # JSON body 파라미터 추출
        if body_str:
            try:
                body_json = json.loads(body_str)
                for k, v in body_json.items():
                    params.append(
                        ScanParam(name=k, location=ParamLocation.BODY,
                                  sample_value=str(v))
                    )
            except json.JSONDecodeError:
                print(f"[API List 파싱 경고] body JSON 파싱 실패: {body_str}")

        targets.append(
            ScanTarget(
                method=method,
                base_url=base_url,
                path=path,
                params=params,
                source=InputSource.API_LIST,
                raw=line,
            )
        )

    return targets


# --------------------------------------------------------------------------
# 3) Swagger / OpenAPI 파서
# --------------------------------------------------------------------------
def _resolve_swagger_source(source: str, auth_headers: Optional[Dict[str, str]] = None) -> dict:
    """
    source가 URL이면 GET 요청으로 가져오고, 로컬 파일 경로면 직접 읽습니다.
    """
    if source.startswith("http://") or source.startswith("https://"):
        resp = requests.get(source, timeout=10, headers=auth_headers or None)
        resp.raise_for_status()
        return resp.json()
    else:
        with open(source, "r", encoding="utf-8") as f:
            return json.load(f)


def _resolve_schema_ref(spec: dict, schema: dict) -> dict:
    if not isinstance(schema, dict):
        return {}
    ref = schema.get("$ref")
    if not ref:
        return schema
    if not ref.startswith("#/"):
        return schema

    current = spec
    for part in ref.lstrip("#/").split("/"):
        current = current.get(part, {})
        if not isinstance(current, dict):
            return schema
    return current


def _schema_sample_value(name: str, schema: Optional[dict]) -> str:
    schema = schema or {}
    if "default" in schema:
        return str(schema["default"])
    if "example" in schema:
        return str(schema["example"])
    if schema.get("enum"):
        return str(schema["enum"][0])

    name_lower = name.lower()
    schema_type = schema.get("type", "string")
    fmt = schema.get("format", "")

    if schema_type in ("integer", "number") or fmt in ("int32", "int64", "double", "float"):
        return "0" if name_lower in {"page"} else "1"
    if schema_type == "boolean":
        return "false"
    if "date-time" == fmt:
        return "2026-06-30T00:00:00"
    if "date" == fmt:
        return "2026-06-30"
    if "email" in name_lower:
        return "argus@example.com"
    if "phone" in name_lower:
        return "010-1234-5678"
    normalized_name = re.sub(r"[^a-z0-9]", "", name_lower)
    if normalized_name.endswith("url") or normalized_name in {"uri", "link", "src"}:
        return "https://example.com/argus-baseline.png"
    if name_lower.endswith("id") or name_lower in {"id", "memberid", "sellerid", "userid"}:
        return "1"
    if "type" in name_lower:
        return "REVIEW"
    if "status" in name_lower:
        return "ACTIVE"
    return "argus-test"


def _extract_body_params(spec: dict, schema: dict,
                         required_names: Optional[List[str]] = None,
                         location: ParamLocation = ParamLocation.BODY) -> List[ScanParam]:
    """Expand an object schema into sibling parameters at the requested location."""
    schema = _resolve_schema_ref(spec, schema)
    required = set(required_names or schema.get("required", []) or [])

    if schema.get("type") == "array":
        item_schema = _resolve_schema_ref(spec, schema.get("items", {}))
        return _extract_body_params(
            spec, item_schema, required_names=required_names, location=location
        )

    properties = schema.get("properties", {})
    sibling_names = list(properties)
    sibling_formats = []
    for sibling_schema in properties.values():
        sibling = _resolve_schema_ref(spec, sibling_schema)
        sibling_format = sibling.get("format", "").lower()
        if sibling_format:
            sibling_formats.append(sibling_format)
        if sibling.get("type") == "array":
            item_schema = _resolve_schema_ref(spec, sibling.get("items", {}))
            item_format = item_schema.get("format", "").lower()
            if item_format:
                sibling_formats.append(item_format)

    params: List[ScanParam] = []
    for prop_name, prop_schema in properties.items():
        resolved = _resolve_schema_ref(spec, prop_schema)
        # Preserve just enough parent-object context for semantic triage after
        # the object schema is flattened into individual ScanParam instances.
        resolved = dict(resolved)
        if resolved.get("type") == "array" and resolved.get("items"):
            resolved["items"] = _resolve_schema_ref(spec, resolved["items"])
        resolved["x-argus-sibling-formats"] = sibling_formats
        resolved["x-argus-sibling-names"] = sibling_names
        params.append(
            ScanParam(
                name=prop_name,
                location=location,
                sample_value=_schema_sample_value(prop_name, resolved),
                required=prop_name in required,
                schema=resolved,
            )
        )
    return params


def _deduplicate_params(params: List[ScanParam]) -> List[ScanParam]:
    """Keep one parameter per HTTP location/name while preserving OpenAPI order."""
    unique: List[ScanParam] = []
    seen = set()
    for param in params:
        key = (param.location, param.name.casefold())
        if key in seen:
            continue
        seen.add(key)
        unique.append(param)
    return unique


def parse_swagger(source: str, host_override: str = "",
                  auth_headers: Optional[Dict[str, str]] = None) -> List[ScanTarget]:
    """
    Swagger(OpenAPI 2.0/3.0) 스펙을 파싱하여 ScanTarget 리스트를 생성합니다.

    source        : Swagger JSON URL 또는 로컬 파일 경로
    host_override : 스펙 내 host/servers 정보 대신 실제 대상 서버를 강제 지정할 때 사용
                     (예: 로컬 개발 스펙을 도커 컨테이너 배포 주소로 스캔하고 싶을 때)
    """
    spec = _resolve_swagger_source(source, auth_headers=auth_headers)
    targets: List[ScanTarget] = []

    # base_url 결정: OpenAPI 3.0 (servers) vs Swagger 2.0 (host+basePath)
    if host_override:
        base_url = host_override.rstrip("/")
    elif "servers" in spec and spec["servers"]:
        base_url = spec["servers"][0]["url"].rstrip("/")
    elif "host" in spec:
        scheme = spec.get("schemes", ["https"])[0]
        base_path = spec.get("basePath", "")
        base_url = f"{scheme}://{spec['host']}{base_path}".rstrip("/")
    else:
        base_url = ""
        print("[Swagger 파싱 경고] base_url을 찾을 수 없습니다. host_override를 지정하세요.")

    for path, methods in spec.get("paths", {}).items():
        for method, detail in methods.items():
            if method.upper() not in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                continue  # parameters, summary 등 메타 필드 스킵

            common_params: List[ScanParam] = []

            # 2.0 / 3.0 공통: parameters 배열 (query, path, header)
            for p in detail.get("parameters", []):
                loc_str = p.get("in", "query")
                try:
                    location = ParamLocation(loc_str)
                except ValueError:
                    location = ParamLocation.QUERY
                schema = _resolve_schema_ref(spec, p.get("schema", {}))
                name = p.get("name", "")
                if schema.get("type") == "object" and location in {
                    ParamLocation.QUERY, ParamLocation.PATH, ParamLocation.HEADER
                }:
                    common_params.extend(_extract_body_params(
                        spec, schema, location=location
                    ))
                    continue
                common_params.append(
                    ScanParam(
                        name=name,
                        location=location,
                        sample_value=_schema_sample_value(name, schema),
                        required=bool(p.get("required", False)),
                        schema=schema,
                    )
                )

            # OpenAPI 3.0: requestBody -> body 파라미터 추출
            request_body = detail.get("requestBody", {})
            content = request_body.get("content", {})
            media_variants = list(content.items()) or [("", {})]
            for media_type, media_obj in media_variants:
                params = list(common_params)
                schema = media_obj.get("schema", {})
                if schema:
                    params.extend(_extract_body_params(spec, schema))

                targets.append(
                    ScanTarget(
                        method=method.upper(),
                        base_url=base_url,
                        path=path,
                        params=_deduplicate_params(params),
                        tags=list(detail.get("tags", [])),
                        allowed_roles=_operation_roles(path, detail),
                        source=InputSource.SWAGGER,
                        raw=f"{method.upper()} {path} [{media_type or 'no-body'}]",
                        content_type=media_type,
                    )
                )

    return targets


# --------------------------------------------------------------------------
# 통합 엔트리포인트
# --------------------------------------------------------------------------
def parse_inputs(
    url_list_text: str = "",
    api_list_text: str = "",
    swagger_source: str = "",
    default_base_url: str = "",
    swagger_host_override: str = "",
    auth_headers: Optional[Dict[str, str]] = None,
) -> List[ScanTarget]:
    """
    Build Attack Tree 모달에서 체크된 입력들을 모두 병합하여 ScanTarget 리스트를 반환합니다.
    체크되지 않은 입력은 빈 문자열로 두면 자동으로 스킵됩니다.
    """
    targets: List[ScanTarget] = []

    if url_list_text.strip():
        targets.extend(parse_url_list(url_list_text))

    if api_list_text.strip():
        targets.extend(parse_api_list(api_list_text, default_base_url=default_base_url))

    if swagger_source.strip():
        targets.extend(parse_swagger(swagger_source, host_override=swagger_host_override,
                                     auth_headers=auth_headers))

    # 같은 URL의 request media type별 ScanTarget은 서로 다른 주입 대상입니다.
    seen = set()
    unique_targets = []
    for t in targets:
        key = (t.method, t.full_url, t.content_type.lower())
        if key not in seen:
            seen.add(key)
            unique_targets.append(t)

    return unique_targets
