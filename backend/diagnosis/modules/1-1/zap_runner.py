import time
import os
import json
import html
import re
import base64
import hashlib
import urllib.parse
import requests
from datetime import date, datetime, timedelta, timezone
from zapv2 import ZAPv2

_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_sibling_module(name: str):
    import importlib.util

    path = os.path.join(_MODULE_DIR, f"{name}.py")
    spec = importlib.util.spec_from_file_location(f"diag_g11_legacy_{name}", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Failed to load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


report_helpers = _load_sibling_module("report")
classify_alert = report_helpers.classify_alert
KOREAN_REMEDIATIONS = report_helpers.KOREAN_REMEDIATIONS
csrf_scanner = _load_sibling_module("csrf_scanner")
payload_catalog = _load_sibling_module("payloads")
XSS_PAYLOADS = payload_catalog.XSS_PAYLOADS


# 전역 스캔 상태 관리
scan_status = {
    "is_running": False,
    "progress": 0,
    "message": "Ready",
    "result_file": None,
    "log_file": None,
    "total_alerts": 0
}

def _bounded_get(url, *, headers=None, params=None, timeout=4, max_bytes=524288, retries=2, retry_wait=1.5):
    """GET with a bounded response body so streaming/large endpoints cannot stall scans.

    Retries on connection errors: under the per-account scan load the target
    server intermittently drops connections, and a dropped reflection-
    verification GET would silently lose a real stored-XSS finding (the payload
    was stored but never confirmed). A couple of short-waited retries ride out
    those transient drops instead."""
    for attempt in range(retries + 1):
        try:
            res = requests.get(
                url,
                headers=headers,
                params=params,
                timeout=timeout,
                stream=True,
            )
            break
        except requests.exceptions.RequestException:
            if attempt < retries:
                time.sleep(retry_wait)
                continue
            raise
    chunks = []
    total = 0
    # Cap not just the body *size* but the time spent reading it: an endpoint
    # that has accumulated thousands of test records (e.g. GET /api/v1/posts
    # after many scan runs seed posts and DELETE cleanup is disabled) can take
    # far longer to stream than the connect timeout, hanging the whole scan on
    # one URL. Once the read deadline passes, keep what we have and move on.
    read_deadline = time.monotonic() + max(timeout, 4) * 2
    try:
        for chunk in res.iter_content(chunk_size=16384):
            if time.monotonic() > read_deadline:
                break
            if not chunk:
                continue
            remaining = max_bytes - total
            if remaining <= 0:
                break
            chunks.append(chunk[:remaining])
            total += len(chunks[-1])
            if total >= max_bytes:
                break
    except requests.exceptions.RequestException:
        pass
    finally:
        res.close()
    res._content = b"".join(chunks)
    return res

result_dir_override = None

# Set per scan by scanner.py from the ``diagnosis_1_1`` config block, so
# target-specific endpoint names / cookie names don't have to live in code.
extra_skip_path_markers: tuple = ()
session_cookie_fallback = "accessToken"

STATE_TRANSITION_PATH_MARKERS = (
    "/close", "/reopen", "/approve", "/reject", "/suspend", "/ban", "/unban",
    "/cancel", "/delete", "/payment",
)
ACCOUNT_UTILITY_PATH_MARKERS = (
    "/auth/", "/login", "/logout", "/password",
)
STORED_SCAN_SKIP_PATH_MARKERS = (
    "/auth/", "/login", "/logout",
    "/email/send", "/email/verify", "/check-email", "/check-nickname",
)

def update_status(is_running=None, progress=None, message=None, result_file=None, log_file=None, total_alerts=None):
    if is_running is not None: scan_status["is_running"] = is_running
    if progress is not None: scan_status["progress"] = progress
    if message is not None: scan_status["message"] = message
    if result_file is not None: scan_status["result_file"] = result_file
    if log_file is not None: scan_status["log_file"] = log_file
    if total_alerts is not None: scan_status["total_alerts"] = total_alerts
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

import difflib
import copy

def normalize_reflection_text(value: str = "") -> str:
    if not value:
        return ""
    text = str(value)
    for _ in range(2):
        text = html.unescape(urllib.parse.unquote_plus(text))
        text = (
            text.replace("\\/", "/")
                .replace("\\u003c", "<")
                .replace("\\u003C", "<")
                .replace("\\u003e", ">")
                .replace("\\u003E", ">")
                .replace("\\u002f", "/")
                .replace("\\u002F", "/")
        )
    return text

def get_payload_reflection(payload, response_body, baseline_body=None):
    if not payload or not response_body:
        return None

    # Baseline이 지정된 경우 diff 분석을 수행해 새로 추가된 영역만 분리
    active_text = response_body
    if baseline_body:
        try:
            # difflib.ndiff를 활용해 추가(+)된 라인 및 문자들을 결합하여 새로 유입된 문자열 추출
            diff = difflib.ndiff(baseline_body.splitlines(keepends=True), response_body.splitlines(keepends=True))
            added_lines = [line[2:] for line in diff if line.startswith('+ ')]
            active_text = "".join(added_lines)
            if not active_text.strip():
                # 추가된 신규 텍스트가 없는 경우 반사되지 않은 것으로 확정
                return None
        except Exception:
            active_text = response_body

    payload_variants = dict.fromkeys([
        payload,
        normalize_reflection_text(payload),
        html.escape(payload),
        html.escape(payload, quote=False),
        urllib.parse.quote(payload),
        urllib.parse.quote_plus(payload),
        payload.replace("/", "\\/"),
        payload.replace("<", "\\u003c").replace(">", "\\u003e"),
        payload.replace("<", "\\u003C").replace(">", "\\u003E"),
        payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("/", "\\/"),
        payload.replace("<", "\\u003C").replace(">", "\\u003E").replace("/", "\\/"),
    ])
    body_variants = {
        active_text,
        normalize_reflection_text(active_text),
    }

    for body in body_variants:
        for variant in payload_variants:
            normalized_variant = normalize_reflection_text(variant)
            if normalized_variant and normalized_variant.lower() in body.lower():
                return variant
    return None

def is_payload_reflected(payload, response_body, baseline_body=None):
    return get_payload_reflection(payload, response_body, baseline_body) is not None

def find_json_keypaths_containing(value, payload, prefix=""):
    matches = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            matches.extend(find_json_keypaths_containing(child, payload, path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            path = f"{prefix}.{index}" if prefix else str(index)
            matches.extend(find_json_keypaths_containing(child, payload, path))
    elif isinstance(value, str) and payload in value:
        matches.append(prefix)
    return matches

def normalize_response_param_path(path):
    parts = [part for part in str(path).split(".") if part and not part.isdigit()]
    if parts and parts[0] in {"data", "items", "result", "results"}:
        parts = parts[1:]
    if parts and parts[0].endswith("s") and len(parts) > 1:
        parts = parts[1:]
    return ".".join(parts) if parts else path

def infer_reflected_response_params(response, payload):
    try:
        body = response.json()
    except Exception:
        return []
    params = []
    for path in find_json_keypaths_containing(body, payload):
        normalized = normalize_response_param_path(path)
        if normalized and normalized not in params:
            params.append(normalized)
    return params

def detect_xss_reflection_context(payload, response_body):
    if not payload or not response_body:
        return "unknown"

    bodies = [
        response_body,
        html.unescape(response_body),
        urllib.parse.unquote_plus(response_body),
    ]
    payload_re = re.escape(payload)
    for body in bodies:
        if re.search(r"<[^>]+\s[\w:-]+\s*=\s*(['\"])" + payload_re + r"\1", body, re.IGNORECASE):
            return "HTML attribute"
        if re.search(r">\s*" + payload_re + r"\s*<", body, re.IGNORECASE):
            return "HTML body"
        if re.search(r"(['\"])" + payload_re + r"\1", body, re.IGNORECASE):
            return "JSON/String value"
    return "encoded/reflected"

def classify_xss_response(payload, response_body, content_type, method="GET", is_mutation=False, response_headers=None, baseline_body=None):
    if not payload or not response_body:
        return None

    response_lower = response_body.lower()
    decoded_response_body = normalize_reflection_text(response_body)
    decoded_response_lower = decoded_response_body.lower()
    content_type_lower = (content_type or "").lower()
    source_indicators = ["location", "search", "document.cookie", "document.location", "url", "query", "param", "input"]
    dom_sink_patterns = [
        "document.write",
        "document.writeln",
        "innerhtml",
        "outerhtml",
        "insertadjacenthtml",
        "eval(",
        "settimeout(",
        "setinterval(",
        "window.location",
        "document.location",
        "location.href",
        "appendchild",
        "insertbefore",
    ]
    # 응답 본문에 페이로드가 실행 가능한 형태로 반사되었는지 판별하는 마커
    executable_markers = ["<script", "</script>", "onerror=", "onload=", "onclick=", "javascript:", "<svg", "<img", "<iframe"]

    reflected_variant = get_payload_reflection(payload, response_body, baseline_body)
    has_payload_in_body = reflected_variant is not None
    has_dom_sink = any(pattern in decoded_response_lower for pattern in dom_sink_patterns)
    has_source_indicator = any(indicator in decoded_response_lower for indicator in source_indicators)
    has_user_input_reference = "userinput" in response_lower or "input" in response_lower
    has_executable_marker = any(marker in decoded_response_lower for marker in executable_markers)

    # ── DOM XSS 의심 패턴 (정적 분석으로는 확정 불가 → Informational 강등) ──────────────
    # DOM XSS 실제 탐지는 Playwright 헤드리스 브라우저를 통한 동적 실행 검증만 가능.
    # 여기서는 "의심 패턴이 발견됨"을 리포팅하고 Playwright 위임 힌트를 남긴다.
    if has_dom_sink and (has_source_indicator or has_user_input_reference) and (has_payload_in_body or has_executable_marker):
        detected_sinks = ", ".join([p for p in dom_sink_patterns if p in response_lower])
        return {
            "kind": "dom_suspect",
            "custom_type": "DOM_XSS_SUSPECT",
            "risk": "Informational",
            "confidence": "Low",
            "alert": "[정적 분석] DOM XSS 의심 패턴 감지 — Playwright 동적 검증 필요",
            "description": (
                "응답 본문에서 DOM 삽입 지점과 사용자 입력 경로 신호가 동시에 발견되었습니다. "
                "단, 정적 텍스트 분석으로는 실제 취약 여부를 확정할 수 없습니다. "
                "Playwright 헤드리스 브라우저에서 페이지를 직접 로드하고 alert() 발화 여부를 모니터링하는 동적 검증이 필요합니다."
            ),
            "evidence": f"응답 본문에 DOM 삽입 지점({detected_sinks})이 감지되었습니다.",
            "playwright_action": "url_param_injection",
        }

    if not has_payload_in_body:
        return None

    is_html_context = "html" in content_type_lower
    is_json_context = "json" in content_type_lower
    reflection_context = detect_xss_reflection_context(payload, response_body)

    # ── Reflected XSS ──────────────────────────────────────────────────────────────────
    # POST/PUT 등 쓰기 메서드라도 응답에 페이로드가 에코백 되면 Reflected XSS.
    # 진짜 Stored XSS는 POST 저장 후 GET 재조회 응답에서만 판정 가능하며,
    # 해당 로직은 run_zap_scan() 내부의 2단계 저장-재조회 루프에서 별도 처리한다.
    if (is_html_context or is_json_context) and has_executable_marker:
        if is_html_context:
            risk = "Medium"
            confidence = "High"
            desc = (
                "응답 본문에 XSS 공격 페이로드가 HTML 인코딩 없이 그대로 반사되었습니다. "
                "프론트엔드에서 직접 화면에 출력하거나 innerHTML 등으로 이 값을 렌더링할 경우 브라우저 런타임에서 즉시 악성 스크립트가 실행됩니다. "
                f"(Content-Type: {content_type}, Context: {reflection_context})"
            )
            sol = "특수 문자(<, >, &, \", ')가 입력되거나 출력되는 시점에 HTML Entity Escape 처리를 적용하여 브라우저가 스크립트로 오인하지 않도록 차단하십시오."
        else:
            # JSON context 내 반사 케이스 (프론트엔드 바인딩 위협)
            risk = "Low"
            confidence = "Medium"
            desc = (
                "요청으로 전송된 XSS 페이로드가 API 응답 JSON 데이터 내에 필터링 없이 그대로 출력되었습니다. "
                "모던 프론트엔드 프레임워크(React, Vue 등)의 기본 이스케이프 정책 덕분에 브라우저에서의 실제 실행은 제한될 수 있습니다. "
                "다만, dangerouslySetInnerHTML, v-html과 같은 안전하지 않은 속성 바인딩을 사용하거나, WebView/이메일 템플릿 등으로 활용 영역이 확장될 경우 즉시 XSS 공격 경로로 이어질 위험이 존재합니다. (서버 측의 2차 방어선 누락)"
            )
            sol = "프론트엔드 수준의 방어에만 의존하지 말고, 서버 측 인풋 유효성 검증 단(XssEscapeServletFilter 등) 또는 JSON Response 직렬화 단계에서 특수 문자 필터링을 적용하여 일관적인 데이터 보안 상태를 유지하십시오."

        return {
            "kind": "reflected",
            "custom_type": "40012",
            "risk": risk,
            "confidence": confidence,
            "alert": "Reflected Cross-Site Scripting (Reflected XSS) Vulnerability",
            "description": desc,
            "solution": sol,
            "evidence": f"Response body reflected payload variant '{reflected_variant}' from original payload '{payload}'.",
            "reflection_context": reflection_context,
            "reflected_variant": reflected_variant,
        }

    return None

def resolve_schema_ref(schema: dict, components: dict | None = None) -> dict:
    if not isinstance(schema, dict):
        return schema
    ref = schema.get("$ref")
    if not ref or not components:
        return schema
    if not ref.startswith("#/components/schemas/"):
        return schema
    schema_name = ref.rsplit("/", 1)[-1]
    return components.get("schemas", {}).get(schema_name, schema)

def extract_injectable_keypaths(schema: dict, prefix: str = "", components: dict | None = None) -> list[str]:
    """JSON 스키마를 재귀적으로 탐색하여 string 타입의 모든 키 경로(Dot-notation)를 추출합니다."""
    schema = resolve_schema_ref(schema, components)
    paths = []
    if not isinstance(schema, dict):
        return paths

    properties = schema.get("properties", {})
    for k, v in properties.items():
        full_key = f"{prefix}.{k}" if prefix else k
        v = resolve_schema_ref(v, components)
        p_type = get_schema_type(v, components)
        
        if is_xss_injectable_schema(v, k, components):
            paths.append(full_key)
        elif p_type == "object":
            paths.extend(extract_injectable_keypaths(v, full_key, components))
        elif p_type == "array":
            # 배열 내 아이템이 객체인 경우 처리
            items_schema = resolve_schema_ref(v.get("items", {}), components)
            if isinstance(items_schema, dict) and get_schema_type(items_schema, components) == "object":
                paths.extend(extract_injectable_keypaths(items_schema, f"{full_key}.0", components))
    return paths

def schema_for_keypath(schema: dict, keypath: str, components: dict | None = None) -> dict:
    current = resolve_schema_ref(schema, components)
    for part in str(keypath or "").split("."):
        if not isinstance(current, dict):
            return {}
        current = resolve_schema_ref(current, components)
        if part.isdigit():
            current = resolve_schema_ref(current.get("items", {}), components)
            continue
        if get_schema_type(current, components) == "array":
            current = resolve_schema_ref(current.get("items", {}), components)
        properties = current.get("properties", {}) if isinstance(current, dict) else {}
        current = resolve_schema_ref(properties.get(part, {}), components)
    return current if isinstance(current, dict) else {}

def set_nested_value_by_keypath(target_dict: dict, keypath: str, value: any) -> dict:
    """점(.)으로 구분된 키 경로에 맞춰 중첩 딕셔너리에 값을 대입합니다."""
    parts = keypath.split(".")
    curr = target_dict
    for idx, part in enumerate(parts[:-1]):
        next_part = parts[idx + 1]
        if isinstance(curr, list):
            list_idx = int(part)
            while len(curr) <= list_idx:
                curr.append({} if not next_part.isdigit() else [])
            curr = curr[list_idx]
            continue
        if part not in curr or not isinstance(curr[part], (dict, list)):
            curr[part] = [] if next_part.isdigit() else {}
        curr = curr[part]
    last = parts[-1]
    if isinstance(curr, list):
        list_idx = int(last)
        while len(curr) <= list_idx:
            curr.append(None)
        curr[list_idx] = value
    else:
        curr[last] = value
    return target_dict

def get_schema_type(schema: dict, components: dict | None = None) -> str:
    schema = resolve_schema_ref(schema, components)
    if not isinstance(schema, dict):
        return "unknown"
    schema_type = schema.get("type")
    if isinstance(schema_type, list):
        return next((t for t in schema_type if t != "null"), "unknown")
    if schema_type:
        return schema_type
    for key in ["oneOf", "anyOf", "allOf"]:
        variants = schema.get(key)
        if isinstance(variants, list) and variants:
            return get_schema_type(variants[0], components)
    return "unknown"

def normalized_field_name(param_name: str = "") -> str:
    return re.sub(r"[^a-z0-9]", "", str(param_name or "").lower())

def is_sensitive_or_nontext_field(param_name: str = "") -> bool:
    pn = normalized_field_name(param_name)
    sensitive_tokens = [
        "password", "passwd", "pwd", "secret", "token", "accesstoken", "refreshtoken",
        "authorization", "auth", "otp", "verificationcode", "emailcode", "csrf",
        "session", "cookie", "credential", "key",
    ]
    strict_tokens = [
        "phone", "tel", "mobile", "zipcode", "postcode", "birth",
        "uuid", "number", "count", "amount", "price", "rate", "capacity",
    ]
    if any(token in pn for token in sensitive_tokens + strict_tokens):
        return True
    if pn in {"id", "ids"} or pn.endswith("id") or pn.endswith("ids"):
        return True
    if pn in {
        "date", "datetime", "time", "timestamp", "startdate", "enddate",
        "createdat", "updatedat", "deletedat", "openedat", "closedat",
        "birthdate", "birthtime",
    }:
        return True
    return False

def is_xss_injectable_schema(schema: dict, param_name: str = "", components: dict | None = None) -> bool:
    schema = resolve_schema_ref(schema, components)
    if not schema and param_name and not is_sensitive_or_nontext_field(param_name):
        schema = {"type": "string"}
    if not isinstance(schema, dict):
        return False
    if is_sensitive_or_nontext_field(param_name):
        return False
    if schema.get("enum"):
        return False
    if get_schema_type(schema, components) != "string":
        return False
    if (schema.get("format") or "").lower() in {"date", "date-time", "byte", "binary", "uuid"}:
        return False
    return True

def looks_like_file_field(param_name: str = "", schema: dict | None = None, components: dict | None = None) -> bool:
    schema = resolve_schema_ref(schema or {}, components)
    prop_type = get_schema_type(schema, components)
    prop_format = (schema.get("format") or "").lower() if isinstance(schema, dict) else ""
    items_schema = resolve_schema_ref(schema.get("items", {}), components) if isinstance(schema, dict) else {}
    item_format = (items_schema.get("format") or "").lower() if isinstance(items_schema, dict) else ""
    if prop_type == "string" and prop_format == "binary":
        return True
    if prop_type == "array" and item_format == "binary":
        return True
    field = normalized_field_name(param_name)
    return any(token in field for token in ["image", "images", "photo", "photos", "file", "files", "upload", "attachment"])

def payloads_for_xss_field(param_name: str = "", schema: dict | None = None, components: dict | None = None) -> list:
    schema = resolve_schema_ref(schema or {}, components)
    if not schema and param_name and not is_sensitive_or_nontext_field(param_name):
        schema = {"type": "string"}
    fmt = (schema.get("format") or "").lower() if isinstance(schema, dict) else ""
    pn = normalized_field_name(param_name)

    if is_sensitive_or_nontext_field(param_name):
        return []
    if fmt == "email" or "email" in pn:
        return [
            '"xss<img src=x onerror=alert(1)>"@example.com',
            '"xss<script>alert(1)</script>"@example.com',
        ]
    if any(token in pn for token in ["url", "uri", "link", "homepage", "website", "redirect"]):
        return [
            "javascript:alert(1)",
            "https://example.com/%3Cscript%3Ealert(1)%3C/script%3E",
            "https://example.com/\"><script>alert(1)</script>",
        ]
    return XSS_PAYLOADS

def make_unique_xss_payload(base_payload: str, param_name: str = "") -> str:
    marker_source = f"{param_name}:{time.time_ns()}:{base_payload}"
    marker_hash = hashlib.sha1(marker_source.encode("utf-8", errors="ignore")).hexdigest()[:10]
    safe_param = re.sub(r"[^A-Za-z0-9_]", "_", str(param_name or "field"))[:24] or "field"
    marker = f"ARGUS_{safe_param}_{marker_hash}"

    replacements = [
        ("alert(1)", f"alert('{marker}')"),
        ("alert(1);", f"alert('{marker}');"),
    ]
    for old, new in replacements:
        if old in base_payload:
            return base_payload.replace(old, new)
    if "javascript:" in base_payload.lower():
        return f"javascript:alert('{marker}')"
    return f"<img src=x onerror=alert('{marker}')>"

def default_value_for_schema(schema: dict, components: dict | None = None, param_name: str = ""):
    schema = resolve_schema_ref(schema, components)
    if not isinstance(schema, dict):
        return None
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    if schema.get("enum"):
        return schema["enum"][0]

    schema_type = get_schema_type(schema, components)
    fmt = (schema.get("format", "") or "").lower()
    pn = normalized_field_name(param_name)
    if schema_type == "integer":
        minimum = schema.get("minimum")
        if minimum is None:
            minimum = schema.get("min")
        try:
            value = int(minimum) if minimum is not None else 1
        except Exception:
            value = 1
        if schema.get("exclusiveMinimum") is True:
            value += 1
        if any(token in pn for token in ["recruitcount", "membercount", "capacity", "personnel", "peoplecount", "guest"]):
            value = max(value, 2)
        return value
    if schema_type == "number":
        minimum = schema.get("minimum")
        try:
            value = float(minimum) if minimum is not None else 1.0
        except Exception:
            value = 1.0
        if schema.get("exclusiveMinimum") is True:
            value += 1.0
        return value
    if schema_type == "boolean":
        return True
    if schema_type == "array":
        item_default = default_value_for_schema(schema.get("items", {}), components, param_name)
        return [item_default] if item_default is not None else []
    if schema_type == "object":
        return build_default_payload_from_schema(schema, components)
    if fmt == "date" or any(token in pn for token in ["enddate", "duedate", "deadline", "closedate", "checkout"]):
        days = 30 if any(token in pn for token in ["enddate", "duedate", "deadline", "closedate", "checkout"]) else 1
        return (date.today() + timedelta(days=days)).isoformat()
    if fmt == "date-time":
        return (datetime.now(timezone.utc) + timedelta(days=1)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if schema_type == "unknown":
        return None

    if "email" in pn:
        return "fuzz-test@example.com"
    if "password" in pn or "pwd" in pn:
        return "SecurePass123!"
    if any(token in pn for token in ["phone", "tel", "mobile", "contact"]):
        return "010-1234-5678"
    if "nickname" in pn:
        return "safeNickname"
    if "representative" in pn or "holder" in pn:
        return "HongGildong"
    if "businessnumber" in pn or "accountnumber" in pn or "business_number" in pn or "account_number" in pn:
        return "1234567890"
    if any(token in pn for token in ["startdate", "checkin"]):
        return (date.today() + timedelta(days=1)).isoformat()
    if "category" in pn:
        return "GENERAL"

    min_len = schema.get("minLength") or schema.get("min_length") or 0
    try:
        min_len = int(min_len)
    except Exception:
        min_len = 0
    value = "safe"
    if min_len > len(value):
        value = value + ("x" * (min_len - len(value)))

    max_len = schema.get("maxLength") or schema.get("max_length")
    try:
        if max_len is not None and len(value) > int(max_len):
            value = value[:int(max_len)]
    except Exception:
        pass
    return value

def default_value_for_query_param(param_name: str, schema: dict, components: dict | None = None):
    if get_schema_type(schema, components) in {"object", "array", "unknown"}:
        return None
    return default_value_for_schema(schema, components, param_name)

def _is_profile_endpoint(api_url: str | None) -> bool:
    """True when the URL is the authenticated user's own single-record
    resource (a profile / "my info" endpoint). Matched as substrings so
    ``/members/me/profile``, ``/api/v1/me``, ``/mypage/info`` etc. are all
    recognised, instead of keying on the literal word "profile" alone."""
    low = str(api_url or "").lower()
    return (
        "profile" in low
        or "/me/" in low
        or low.rstrip("/").endswith("/me")
        or "mypage" in low
        or "myinfo" in low
    )

# Tokens that mark a profile-update field as authentication-critical.
# Matched as substrings (after stripping separators) rather than an exact
# name list, so variants like newPassword / current_password / userEmail /
# passwordConfirm are all covered without enumerating every spelling — these
# are generic auth field-name tokens, not any one app's schema. Overwriting
# such a field — even with a benign "safe" default — locks us out of the
# account (password stops matching, or the login identifier changes). Profile
# updates are PATCH (partial), so simply not sending the field leaves the
# stored value intact.
_LOGIN_CRITICAL_TOKENS = ("password", "passwd", "pwd", "email", "loginid", "username")


def _is_login_critical_field(key: str) -> bool:
    collapsed = re.sub(r"[^a-z0-9]", "", str(key or "").lower())
    return any(token in collapsed for token in _LOGIN_CRITICAL_TOKENS)


def stabilize_profile_payload(payload: dict | None, api_url: str, role: str | None, *, preserve: set[str] | None = None) -> None:
    """Keep a profile-update baseline from locking us out of the account:
    never send login-critical fields (password/email/...), so testing a
    profile's stored XSS leaves the account's credentials intact.

    Uniqueness of non-tested fields (a profile whose nickname/handle has a
    UNIQUE constraint would reject a shared sample) is handled generically by
    ``preserve_current_profile_values``, which keeps every non-tested field at
    its *current* stored value — so no field name has to be special-cased here."""
    if not isinstance(payload, dict):
        return
    if not _is_profile_endpoint(api_url):
        return
    preserve = preserve or set()
    for key in list(payload.keys()):
        if key in preserve:
            continue
        if _is_login_critical_field(key):
            # Drop it — a PATCH without the field leaves the stored value
            # (the real password / email) untouched.
            payload.pop(key, None)
            continue


def preserve_current_profile_values(payload: dict | None, api_url: str, headers: dict | None, tested_param: str) -> None:
    """Keep a profile update from clobbering fields it isn't testing.

    A profile is one shared record, so testing stored XSS field-by-field
    (name, then nickname, ...) would otherwise overwrite each earlier field's
    payload with a benign default, leaving only the last one in the DB. Read
    the *current* profile and copy every non-tested, non-login field's current
    value into this request, so a payload a previous scan stored in another
    field survives. App-neutral: unwraps a common ``{...,"data":{...}}``
    envelope, keeps the tested field and login-critical fields untouched, and
    silently no-ops on any error or non-profile endpoint."""
    if not isinstance(payload, dict) or not _is_profile_endpoint(api_url):
        return
    try:
        resp = requests.get(api_url, headers=headers or {}, timeout=5)
        body = resp.json()
    except Exception:
        return
    data = body.get("data") if isinstance(body, dict) and isinstance(body.get("data"), dict) else body
    if not isinstance(data, dict):
        return
    tested_top = str(tested_param or "").split(".", 1)[0].replace("[0]", "")
    for key, value in data.items():
        if key == tested_top or key not in payload:
            continue
        if _is_login_critical_field(key) or isinstance(value, (dict, list)):
            continue
        payload[key] = value


def build_default_payload_from_schema(schema: dict, components: dict | None = None) -> dict:
    schema = resolve_schema_ref(schema, components)
    payload = {}
    if not isinstance(schema, dict):
        return payload
    for key, prop_schema in schema.get("properties", {}).items():
        default_value = default_value_for_schema(prop_schema, components, key)
        if default_value is not None:
            payload[key] = default_value
    return payload

def build_required_payload_from_schema(schema: dict, components: dict | None = None) -> dict:
    schema = resolve_schema_ref(schema, components)
    payload = {}
    if not isinstance(schema, dict):
        return payload
    required = set(schema.get("required") or [])
    for key, prop_schema in (schema.get("properties") or {}).items():
        if key not in required:
            continue
        default_value = default_value_for_schema(prop_schema, components, key)
        if default_value is not None:
            payload[key] = default_value
    return payload

def build_query_defaults_from_details(details: dict | None, components: dict | None = None) -> dict:
    params = {}
    for param in (details or {}).get("parameters", []) or []:
        if not isinstance(param, dict) or str(param.get("in") or "query").lower() != "query":
            continue
        name = param.get("name")
        if not name:
            continue
        schema = dict(param.get("schema") or {})
        for sample_key in ("example", "default", "sample"):
            if param.get(sample_key) not in (None, "") and sample_key not in schema:
                schema["example" if sample_key == "sample" else sample_key] = param.get(sample_key)
                break
        default_value = default_value_for_query_param(name, schema, components)
        if default_value is not None:
            params[name] = default_value
    return params

def is_resource_identifier_key(key: str = "") -> bool:
    normalized = normalized_field_name(key)
    return normalized == "id" or normalized.endswith("id") or normalized in {"uuid", "key", "no", "seq"}

def is_resource_identifier_value(value) -> bool:
    if value is None or isinstance(value, bool):
        return False
    text = str(value).strip()
    if not text or len(text) > 128:
        return False
    return bool(
        re.fullmatch(r"\d+", text)
        or re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", text)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}", text)
    )

def extract_id_from_response(resp_json, depth=0):
    if depth > 3:
        return None
    if isinstance(resp_json, dict):
        for key, value in resp_json.items():
            if is_resource_identifier_key(key) and is_resource_identifier_value(value):
                return value
        for value in resp_json.values():
            result = extract_id_from_response(value, depth + 1)
            if result is not None:
                return result
    elif isinstance(resp_json, list):
        for value in resp_json:
            result = extract_id_from_response(value, depth + 1)
            if result is not None:
                return result
    return None

def extract_id_near_payload(value, payload: str, depth=0):
    if depth > 6 or value is None:
        return None
    if isinstance(value, dict):
        contains_payload = bool(payload and payload in json.dumps(value, ensure_ascii=False))
        if contains_payload:
            found = extract_id_from_response(value)
            if found is not None:
                return found
        for child in value.values():
            result = extract_id_near_payload(child, payload, depth + 1)
            if result is not None:
                return result
    elif isinstance(value, list):
        for child in value:
            result = extract_id_near_payload(child, payload, depth + 1)
            if result is not None:
                return result
    return None

def extract_id_from_url(url: str):
    try:
        path_value = urllib.parse.urlparse(url).path
    except Exception:
        path_value = str(url or "")
    for segment in reversed(path_value.strip("/").split("/")):
        if re.fullmatch(r"\d+", segment or ""):
            return segment
    return None

def extract_id_from_location(response):
    if response is None:
        return None
    location = ""
    try:
        location = response.headers.get("Location") or response.headers.get("location") or ""
    except Exception:
        return None
    if not location:
        return None
    return extract_id_from_url(location)

def extract_session_cookie_name(set_cookie_header: str) -> str | None:
    if not set_cookie_header:
        return None
    for part in set_cookie_header.split(";"):
        part = part.strip()
        if "=" in part:
            name = part.split("=", 1)[0].strip()
            if any(k in name.lower() for k in ["token", "session", "auth", "jsessionid", "sid"]):
                return name
    return None

def check_csrf_token_absence(response):
    body = (getattr(response, "text", "") or "").lower()
    headers = {k.lower(): v for k, v in getattr(response, "headers", {}).items()}
    return not (
        "csrf" in body
        or "xsrf" in body
        or "x-csrf-token" in headers
        or "x-xsrf-token" in headers
    )

def build_cookie_header_from_account(account: dict | None) -> str:
    cookies = (account or {}).get("cookies") or {}
    if not isinstance(cookies, dict):
        return ""
    return "; ".join(f"{name}={value}" for name, value in cookies.items() if name and value is not None)

def build_auth_headers(token: str | None = None, account: dict | None = None, mode: str | None = None) -> dict:
    mode = (mode or (account or {}).get("auth_mode") or "both").lower()
    headers = {}

    if mode in {"header", "bearer", "both"} and token:
        headers["Authorization"] = f"Bearer {str(token).replace('Bearer ', '').strip()}"
    elif mode in {"authorization_raw", "raw"} and token:
        headers["Authorization"] = str(token).replace("Bearer ", "").strip()
    elif mode == "x_auth_token" and token:
        headers["X-Auth-Token"] = str(token).replace("Bearer ", "").strip()
    elif mode == "access_token_header" and token:
        headers["access-token"] = str(token).replace("Bearer ", "").strip()
    elif mode == "access_token_camel_header" and token:
        headers["accessToken"] = str(token).replace("Bearer ", "").strip()

    if mode in {"cookie", "both"}:
        cookie_header = build_cookie_header_from_account(account)
        if cookie_header:
            headers["Cookie"] = cookie_header

    return headers

def jwt_debug_summary(token: str | None) -> str:
    if not token:
        return "no-token"
    try:
        clean_token, payload = decode_jwt_claims(token)
        safe_claims = {
            key: payload.get(key)
            for key in ["sub", "auth", "role", "roles", "scope", "iss", "aud", "iat", "exp"]
            if key in payload
        }
        fingerprint = hashlib.sha256(clean_token.encode("utf-8")).hexdigest()[:12]
        return f"fingerprint={fingerprint}, claims={safe_claims}"
    except Exception as exc:
        return f"jwt-debug-failed: {exc}"

def decode_jwt_claims(token: str | None) -> tuple[str, dict]:
    if not token:
        return "", {}
    clean_token = str(token).replace("Bearer ", "").strip()
    parts = clean_token.split(".")
    if len(parts) < 2:
        return clean_token, {}
    payload_segment = parts[1] + "=" * (-len(parts[1]) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_segment.encode("utf-8")).decode("utf-8"))
    return clean_token, payload

def summarize_response_for_log(response, max_len: int = 180) -> str:
    if response is None:
        return ""
    try:
        data = response.json()
        if isinstance(data, dict):
            pieces = []
            error = data.get("error")
            if isinstance(error, dict) and error.get("code"):
                pieces.append(str(error.get("code")))
            for key in ["message", "error", "detail"]:
                value = data.get(key)
                if isinstance(value, str) and value:
                    pieces.append(value)
            if pieces:
                return " | ".join(pieces)[:max_len]
    except Exception:
        pass
    return ((getattr(response, "text", "") or "").replace("\n", " ").replace("\r", " "))[:max_len]

def has_unsafe_samesite_cookie(account: dict | None, response_set_cookie: str = "") -> bool:
    attrs = (account or {}).get("cookie_attrs") or {}
    if isinstance(attrs, dict) and attrs:
        for meta in attrs.values():
            samesite = ""
            if isinstance(meta, dict):
                samesite = str(meta.get("samesite") or "").lower()
            if samesite not in ["lax", "strict"]:
                return True
        return False

    lowered = (response_set_cookie or "").lower()
    if "samesite=lax" in lowered or "samesite=strict" in lowered:
        return False
    return True

def detect_session_cookie(target_url: str, auth_token: str, validated_endpoints: dict = None) -> str:
    """Set-Cookie 헤더에서 세션 쿠키명(예: accessToken, JSESSIONID 등)을 자동으로 추출합니다.
    
    인증 유무나 CSRF 취약 여부 자체는 본 함수에서 판단하지 않고,
    이후 스캔 단계에서 이 쿠키만을 실어 요청을 재현하여 판단합니다.
    """
    if validated_endpoints:
        auth_paths = [
            p for p in validated_endpoints
            if any(k in p.lower() for k in ["auth", "login", "signin", "token", "oauth", "session"])
        ]
        probe_paths = auth_paths if auth_paths else list(validated_endpoints.keys())[:5]
    else:
        probe_paths = ["/"]

    headers = {}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    for path in probe_paths:
        try:
            res = requests.get(
                f"{target_url.rstrip('/')}{path}",
                headers=headers,
                timeout=3,
                allow_redirects=True,
            )
            set_cookie = res.headers.get("Set-Cookie", "")
            cookie_name = extract_session_cookie_name(set_cookie)
            if cookie_name:
                print(f"[CSRF] 세션 쿠키 이름 검출 성공: {path} → {cookie_name}")
                return cookie_name
        except Exception:
            continue

    return session_cookie_fallback

def run_zap_scan(target_url: str, auth_tokens: list):
    """
    auth_tokens: [{"role": "user"|"seller"|"admin", "token": "<jwt>..."}, ...]
    빈 리스트이면 비인증 스캔으로 동작.
    """

    update_status(is_running=True, progress=0, message="ZAP 연결 및 포트 탐색 중...", result_file=None, total_alerts=0)
    
    # 1. 포트 자동 탐색 (ZAP_PROXY 환경 변수 우선, 없으면 8889, 8090)
    zap = None
    zap_proxy_env = os.environ.get("ZAP_PROXY")
    proxy_urls = [zap_proxy_env] if zap_proxy_env else [f"http://127.0.0.1:{p}" for p in [8889, 8090]]
    
    for proxy_url in proxy_urls:
        try:
            temp_zap = ZAPv2(proxies={'http': proxy_url, 'https': proxy_url})
            # 간단한 API 호출로 연결 테스트
            temp_zap.core.version
            zap = temp_zap
            print(f"[+] ZAP Connected successfully to {proxy_url}")
            break
        except Exception:
            continue
            
    if not zap:
        update_status(is_running=False, message="에러 발생: ZAP 프록시 서버(포트 8090 또는 도커 컨테이너)에 연결할 수 없습니다. ZAP이 켜져 있는지 확인해 주세요.")
        return

    try:
        # ── 다중 토큰 편의 변수 ───────────────────────────────────────────────
        # 권한 우선순위: admin > seller > user (ZAP 기본 인증에 사용할 대표 토큰)
        def account_role_rank(account: dict | None) -> int:
            role_text = str((account or {}).get("role", "")).lower()
            claims_text = str((account or {}).get("claims", {}) or {}).lower()
            joined = f"{role_text} {claims_text}"
            if "admin" in joined:
                return 0
            if "seller" in joined:
                return 1
            if "user" in joined:
                return 2
            return 3

        auth_tokens = sorted(auth_tokens or [], key=account_role_rank)
        primary_token = None
        primary_role = "anonymous"
        primary_account = None
        for priority_role in ["admin", "seller", "user"]:
            for t in auth_tokens:
                if priority_role in str(t.get("role", "")).lower() or priority_role in str(t.get("claims", {}) or {}).lower():
                    primary_token = t["token"]
                    primary_role = t.get("role", priority_role)
                    primary_account = t
                    break
            if primary_token:
                break
        if not primary_token and auth_tokens:
            primary_token = auth_tokens[0]["token"]
            primary_role = auth_tokens[0].get("role", "account")
            primary_account = auth_tokens[0]

        if auth_tokens:
            print(
                "[Auth] runner received accounts: "
                + ", ".join(f"{t.get('role', 'account')}@{t.get('base_url', target_url)}" for t in auth_tokens)
            )
            for t in auth_tokens:
                if t.get("token") and not t.get("claims"):
                    try:
                        _, token_claims = decode_jwt_claims(t.get("token"))
                        t["claims"] = token_claims
                    except Exception:
                        t["claims"] = {}
                print(f"[Auth] runner token claims for {t.get('role', 'account')}: {jwt_debug_summary(t.get('token'))}")
            print(f"[Auth] primary account for ZAP replacer: {primary_role}")

        # 엔드포인트별 최적 토큰 선택 캐시 (403 피하는 토큰 자동 탐색)
        try:
            zap.replacer.remove_rule(description="AutoLoginHeader")
            zap.replacer.remove_rule(description="AutoLoginCookie")
            print("[AuthMode] cleared stale ZAP auth replacer rules")
        except Exception:
            pass

        _token_cache = {}
        _path_param_cache = {}

        def extract_id_candidates_from_json(data, param_name: str, depth: int = 0) -> list:
            if depth > 5:
                return []

            candidates = []
            preferred_keys = [
                param_name,
                param_name.replace("Id", "ID"),
                param_name.replace("_id", "Id"),
                "id",
                "uuid",
                "key",
                "no",
                "seq",
            ]
            if isinstance(data, dict):
                for key in preferred_keys:
                    if key in data and data[key] is not None:
                        candidates.append(data[key])
                for value in data.values():
                    candidates.extend(extract_id_candidates_from_json(value, param_name, depth + 1))
            elif isinstance(data, list):
                for item in data[:10]:
                    candidates.extend(extract_id_candidates_from_json(item, param_name, depth + 1))

            deduped = []
            for value in candidates:
                value = str(value)
                if value and value not in deduped:
                    deduped.append(value)
            return deduped

        def resource_hint_for_param(param_name: str) -> str:
            return re.sub(r"(_?id|Id|ID)$", "", param_name).lower()

        def plural_resource_hints(hint: str) -> list:
            if not hint:
                return []
            hints = [hint]
            if hint.endswith("y"):
                hints.append(f"{hint[:-1]}ies")
            elif not hint.endswith("s"):
                hints.append(f"{hint}s")
            return list(dict.fromkeys(hints))

        def resolve_path_with_known_values(path: str, known_values: dict) -> str | None:
            resolved = path
            for param in re.findall(r"\{([^}]+)\}", resolved):
                if param not in known_values:
                    return None
                resolved = resolved.replace(f"{{{param}}}", str(known_values[param]))
            return resolved

        def path_param_matches_identifier(param_name: str, value) -> bool:
            if value is None or isinstance(value, bool):
                return False
            return is_resource_identifier_value(value)

        def request_parts_from_openapi(details: dict | None, components: dict | None, account: dict, token: str, base_url: str):
            details = details or {}
            req_params = build_query_defaults_from_details(details, components)
            for query_param in list(req_params):
                resolved_identity = resolve_identity_query_param(query_param, account, token, base_url)
                if resolved_identity is not None:
                    req_params[query_param] = resolved_identity

            req_json = None
            req_data = None
            req_files = None
            req_headers = build_auth_headers(token, account)
            body_spec = details.get("requestBody", {}) or {}
            content = body_spec.get("content", {}) or {}
            if "application/json" in content:
                json_schema = content.get("application/json", {}).get("schema", {}) or {}
                req_json = build_default_payload_from_schema(resolve_schema_ref(json_schema, components), components)
                if req_json:
                    req_headers["Content-Type"] = "application/json"
            elif "multipart/form-data" in content:
                multipart_schema = resolve_schema_ref(
                    content.get("multipart/form-data", {}).get("schema", {}) or {},
                    components,
                )
                req_data = {}
                file_keys = []
                for prop_name, prop_meta in (multipart_schema.get("properties") or {}).items():
                    if looks_like_file_field(prop_name, prop_meta, components):
                        file_keys.append(prop_name)
                        continue
                    default_value = default_value_for_schema(prop_meta, components, prop_name)
                    if default_value is not None:
                        req_data[prop_name] = default_value
                if file_keys:
                    png_1x1 = base64.b64decode(
                        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMB/ax"
                        "p3n8AAAAASUVORK5CYII="
                    )
                    req_files = {key: ("argus-test.png", png_1x1, "image/png") for key in file_keys}
                for ct_key in [k for k in req_headers.keys() if k.lower() == "content-type"]:
                    req_headers.pop(ct_key, None)
            return req_headers, req_params, req_json, req_data, req_files

        def extract_id_from_response_or_location(response, param_name: str):
            found = extract_id_from_url(getattr(response, "url", ""))
            if path_param_matches_identifier(param_name, found):
                return found
            found = extract_id_from_location(response)
            if path_param_matches_identifier(param_name, found):
                return found
            try:
                for candidate in extract_id_candidates_from_json(response.json(), param_name):
                    if path_param_matches_identifier(param_name, candidate):
                        return candidate
            except Exception:
                pass
            return None

        def discover_path_param_values_by_create(param_name: str, t_base: str, token: str, account: dict, known_values: dict, endpoints: dict, hint_variants: list) -> list:
            role = (account or {}).get("role", "account")
            auth_components = account.get("swagger_components") or swagger_components
            created = []

            for ep_path, ep_methods in (endpoints or {}).items():
                post_details = ep_methods.get("post")
                if not post_details:
                    continue
                if hint_variants and not any(h in ep_path.lower() for h in hint_variants):
                    continue
                resolved_ep_path = resolve_path_with_known_values(ep_path, known_values)
                if not resolved_ep_path:
                    continue
                normalized_path = resolved_ep_path.lower()
                if any(
                    marker in normalized_path
                    for marker in (*ACCOUNT_UTILITY_PATH_MARKERS, *STATE_TRANSITION_PATH_MARKERS, *extra_skip_path_markers)
                ):
                    continue

                headers, req_params, req_json, req_data, req_files = request_parts_from_openapi(
                    post_details,
                    auth_components,
                    account,
                    token,
                    t_base,
                )
                if not (req_json or req_data or req_files or req_params):
                    continue
                try:
                    create_res = requests.post(
                        f"{t_base}{resolved_ep_path}",
                        headers=headers,
                        params=req_params or None,
                        json=req_json if req_json is not None else None,
                        data=req_data if req_data else None,
                        files=req_files if req_files else None,
                        timeout=4,
                    )
                except Exception as exc:
                    print(f"[PathParam] create probe failed for {param_name} via {resolved_ep_path}: {exc}")
                    continue
                if not (200 <= create_res.status_code < 300):
                    continue
                found = extract_id_from_response_or_location(create_res, param_name)
                if found is not None:
                    created.append(str(found))
                    print(f"[PathParam] {param_name} created candidate for '{role}' via {resolved_ep_path}: {found}")
                    break

            return created

        def discover_path_param_values(param_name: str, t_base: str, token: str, account: dict, known_values: dict, endpoints: dict) -> list:
            role = (account or {}).get("role", "account")
            cache_key = f"{role}:{t_base}:{param_name}:{json.dumps(known_values, sort_keys=True, default=str)}"
            if cache_key in _path_param_cache:
                return _path_param_cache[cache_key]

            hint = resource_hint_for_param(param_name)
            hint_variants = plural_resource_hints(hint)
            auth_headers = build_auth_headers(token, account)
            discovered = []

            probe_paths = []
            for hint_value in hint_variants:
                probe_paths.extend([f"/api/{hint_value}", f"/admin/{hint_value}"])

            for ep_path, ep_methods in (endpoints or {}).items():
                if "get" not in ep_methods:
                    continue
                if hint_variants and not any(h in ep_path.lower() for h in hint_variants):
                    continue
                probe_paths.append(ep_path)

            for ep_path in dict.fromkeys(probe_paths):

                resolved_ep_path = resolve_path_with_known_values(ep_path, known_values)
                if not resolved_ep_path:
                    continue

                try:
                    probe_params = build_query_defaults_from_details(
                        ep_methods.get("get") or {},
                        account.get("swagger_components") or swagger_components,
                    )
                    for query_param in list(probe_params):
                        resolved_identity = resolve_identity_query_param(query_param, account, token, t_base)
                        if resolved_identity is not None:
                            probe_params[query_param] = resolved_identity
                    resp = requests.get(
                        f"{t_base}{resolved_ep_path}",
                        headers=auth_headers,
                        params=probe_params or None,
                        timeout=3,
                    )
                    if not (200 <= resp.status_code < 400):
                        continue
                    discovered.extend(extract_id_candidates_from_json(resp.json(), param_name))
                except Exception:
                    continue

                if discovered:
                    break

            if not discovered:
                discovered.extend(
                    discover_path_param_values_by_create(
                        param_name,
                        t_base,
                        token,
                        account,
                        known_values,
                        endpoints,
                        hint_variants,
                    )
                )

            deduped = []
            for value in discovered:
                if value not in deduped:
                    deduped.append(value)
            _path_param_cache[cache_key] = deduped
            if deduped:
                print(f"[PathParam] {param_name} candidates for '{role}': {', '.join(deduped[:5])}")
            elif hint_variants:
                print(f"[PathParam] {param_name} no candidates for '{role}' via {', '.join(list(dict.fromkeys(probe_paths))[:5])}")
            return deduped

        def build_resolved_path_candidates(path_only: str, t_base: str, token: str, account: dict, endpoints: dict, allow_static_fallback: bool = True) -> list:
            params = re.findall(r"\{([^}]+)\}", path_only)
            if not params:
                return [path_only]

            candidates = [("", {})]
            for param in params:
                next_candidates = []
                for _, known_values in candidates:
                    values = discover_path_param_values(param, t_base, token, account, known_values, endpoints)
                    if allow_static_fallback and "1" not in values:
                        values.append("1")
                    if not values:
                        print(
                            f"[PathParam] unresolved {param} for {path_only}; "
                            "skip unresolved template instead of using static fallback"
                        )
                        continue
                    for value in values[:5]:
                        updated_values = dict(known_values)
                        updated_values[param] = value
                        resolved = path_only
                        for known_param, known_value in updated_values.items():
                            resolved = resolved.replace(f"{{{known_param}}}", str(known_value))
                        next_candidates.append((resolved, updated_values))
                candidates = next_candidates[:10]

            resolved_paths = []
            for resolved, _ in candidates:
                if "{" not in resolved and resolved not in resolved_paths:
                    resolved_paths.append(resolved)
            if resolved_paths:
                return resolved_paths
            return [re.sub(r"\{[^}]+\}", "1", path_only)] if allow_static_fallback else []

        def select_token(api_url: str, method: str, preferred_account: dict | None = None) -> tuple:
            """각 엔드포인트에 대해 접근 가능한 (token, base_url, role) 튜플 반환.

            - preferred_account가 있으면 해당 계정만 평가하여 계정별 스캔을 강제함.
            - preferred_account가 없으면 입력된 auth_tokens 순서대로 시도함.
            - 계정별 base_url이 다른 경우, 해당 base_url로 재구성한 URL을 probe함.
            - 2xx/3xx 응답만 접근 성공으로 간주하고 4xx/5xx는 다음 계정을 계속 시도함.
            - 반환값: (token, effective_base_url, role_label)
            """
            preferred_role = (preferred_account or {}).get("role", "")
            cache_key = f"{preferred_role}_{method}_{api_url}"
            if cache_key in _token_cache:
                return _token_cache[cache_key]

            from urllib.parse import urlparse
            path_only = urlparse(api_url).path

            candidate_tokens = [preferred_account] if preferred_account else auth_tokens
            best_unverified_url = None
            for t in candidate_tokens:
                if not t:
                    continue
                token  = t["token"]
                role   = t.get("role", "account")
                t_base = t.get("base_url", target_url).rstrip("/")
                if not token:
                    result = (None, t_base, role, f"{t_base}{path_only}")
                    _token_cache[cache_key] = result
                    print(f"[TokenSelect] {method} {t_base}{path_only} → '{role}' (no auth)")
                    return result
                # 1. Path parameters translation using account-readable IDs when possible.
                resolved_path_candidates = build_resolved_path_candidates(
                    path_only,
                    t_base,
                    token,
                    t,
                    t.get("validated_endpoints", {}),
                    allow_static_fallback=method.upper() not in {"POST", "PUT", "PATCH"},
                )
                t_endpoints = t.get("validated_endpoints", {})
                t_swagger = t.get("swagger_components", {}) or swagger_components

                if resolved_path_candidates and best_unverified_url is None:
                    best_unverified_url = f"{t_base}{resolved_path_candidates[0]}"
                if method.upper() in {"POST", "PUT", "PATCH"}:
                    probe_url = best_unverified_url or f"{t_base}{path_only}"
                    result = (token, t_base, role, probe_url)
                    _token_cache[cache_key] = result
                    print(f"[TokenSelect] {method} {probe_url} -> '{role}' (mutation probe skipped)")
                    return result
                try:
                    probe_headers = build_auth_headers(token, t)

                    # 2. Build smart default body and query parameters from OpenAPI schemas if available for POST/PUT/PATCH
                    req_json = None
                    req_data = None
                    req_files = None
                    req_params = {}
                    if method.upper() in ["POST", "PUT", "PATCH"]:
                        # find path schema in endpoints metadata
                        matched_path_spec = None
                        for ep_path, ep_methods in t_endpoints.items():
                            if ep_path.rstrip("/") == path_only.rstrip("/"):
                                matched_path_spec = ep_methods.get(method.lower())
                                break
                        if matched_path_spec:
                            spec_params = matched_path_spec.get("parameters", [])
                            for p_spec in spec_params:
                                if isinstance(p_spec, dict) and p_spec.get("in") == "query":
                                    p_name = p_spec.get("name")
                                    p_schema = p_spec.get("schema", {})
                                    if p_name:
                                        req_params[p_name] = default_value_for_schema(p_schema, t_swagger, p_name)

                            # 2-2. Extract body
                            req_body_spec = matched_path_spec.get("requestBody", {})
                            if req_body_spec:
                                content = req_body_spec.get("content", {})
                                if "application/json" in content:
                                    req_json = {}
                                    json_schema = content.get("application/json", {}).get("schema", {})
                                    req_json = build_default_payload_from_schema(json_schema, t_swagger)
                                elif "multipart/form-data" in content:
                                    req_data = {}
                                    req_files = {}
                                    multipart_schema = resolve_schema_ref(
                                        content.get("multipart/form-data", {}).get("schema", {}),
                                        t_swagger,
                                    )
                                    for prop_name, prop_meta in multipart_schema.get("properties", {}).items():
                                        prop_type = get_schema_type(prop_meta, t_swagger)
                                        items_schema = resolve_schema_ref(prop_meta.get("items", {}), t_swagger)
                                        item_format = (items_schema.get("format") or "").lower() if isinstance(items_schema, dict) else ""
                                        if (
                                            (prop_type == "string" and (prop_meta.get("format") or "").lower() == "binary")
                                            or (prop_type == "array" and item_format == "binary")
                                        ):
                                            req_files[prop_name] = ("", b"", "application/octet-stream")
                                        else:
                                            req_data[prop_name] = default_value_for_schema(prop_meta, t_swagger, prop_name)

                    last_probe = None
                    last_probe_url = ""
                    for resolved_path in resolved_path_candidates:
                        probe_url = f"{t_base}{resolved_path}"
                        probe = requests.request(
                            method, probe_url,
                            headers=probe_headers,
                            params=req_params if req_params else None,
                            json=req_json,
                            data=req_data,
                            files=req_files,
                            timeout=3,
                        )
                        last_probe = probe
                        last_probe_url = probe_url
                        if 200 <= probe.status_code < 400:
                            result = (token, t_base, role, probe_url)
                            _token_cache[cache_key] = result
                            print(f"[TokenSelect] {method} {probe_url} → '{role}' ({probe.status_code})")
                            return result
                    if last_probe is not None:
                        print(
                            f"[TokenSelect] skip {method} {last_probe_url} → '{role}' "
                            f"({last_probe.status_code}) {summarize_response_for_log(last_probe)}"
                        )
                except Exception:
                    continue

            # 모든 토큰 실패 → 대표 토큰 반환
            if preferred_account:
                fallback_base = preferred_account.get("base_url", target_url).rstrip("/")
                fallback_url = best_unverified_url or f"{fallback_base}{re.sub(r'{[^}]+}', '1', path_only)}"
                return (
                    preferred_account.get("token"),
                    fallback_base,
                    preferred_account.get("role", "account"),
                    fallback_url,
                )
            fallback_base = target_url.rstrip("/")
            fallback_url = best_unverified_url or f"{fallback_base}{re.sub(r'{[^}]+}', '1', path_only)}"
            return (primary_token, fallback_base, primary_role, fallback_url)

        _identity_param_cache = {}

        def extract_identity_value(data, param_name: str):
            wanted = normalized_field_name(param_name)
            if isinstance(data, dict):
                for key, value in data.items():
                    normalized_key = normalized_field_name(key)
                    if value is not None and normalized_key == wanted:
                        return value
                for value in data.values():
                    found = extract_identity_value(value, param_name)
                    if found is not None:
                        return found
            elif isinstance(data, list):
                for item in data[:5]:
                    found = extract_identity_value(item, param_name)
                    if found is not None:
                        return found
            return None

        def resolve_identity_query_param(param_name: str, account: dict, token: str | None, base_url: str):
            normalized_param = normalized_field_name(param_name)
            if not (normalized_param == "id" or normalized_param.endswith("id")):
                return None
            cache_key = f"{account.get('role', 'account')}:{base_url}:{normalized_param}"
            if cache_key in _identity_param_cache:
                return _identity_param_cache[cache_key]

            claim_value = extract_identity_value(account.get("claims") or {}, param_name)
            if claim_value is not None:
                _identity_param_cache[cache_key] = claim_value
                return claim_value

            headers = build_auth_headers(token or account.get("token"), account)
            probe_paths = []
            for ep_path, ep_methods in (account.get("validated_endpoints") or {}).items():
                if "get" not in ep_methods or "{" in ep_path:
                    continue
                lowered = ep_path.lower()
                if "/me" in lowered or "profile" in lowered or "account" in lowered:
                    probe_paths.append(ep_path)

            for ep_path in list(dict.fromkeys(probe_paths))[:8]:
                try:
                    res = requests.get(f"{base_url.rstrip('/')}/{ep_path.lstrip('/')}", headers=headers, timeout=3)
                    if not (200 <= res.status_code < 400):
                        continue
                    value = extract_identity_value(res.json(), param_name)
                    if value is not None:
                        _identity_param_cache[cache_key] = value
                        print(f"[ParamResolve] {param_name}={value} from {ep_path} for {account.get('role', 'account')}")
                        return value
                except Exception:
                    continue

            _identity_param_cache[cache_key] = None
            return None

        update_status(progress=5, message="입력된 API/URL 리스트 분석 및 취합 중...")
        
        # --- 계정별 개별 API 명세 수집 함수 정의 ---
        def candidate_data_dirs() -> list[str]:
            dirs = []
            for value in [result_dir_override, os.environ.get("ARGUS_DATA_DIR"), os.environ.get("DATA_DIR")]:
                if not value:
                    continue
                normalized = os.path.abspath(value)
                parts = normalized.split(os.sep)
                if "report" in parts:
                    normalized = os.sep.join(parts[:parts.index("report")])
                dirs.append(normalized)
            cwd = os.getcwd()
            dirs.extend([
                os.path.abspath(os.path.join(cwd, "data")),
                os.path.abspath(os.path.join(cwd, "backend", "data")),
                os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "data")),
            ])
            deduped = []
            for path_value in dirs:
                if path_value and path_value not in deduped:
                    deduped.append(path_value)
            return deduped

        def load_openapi_catalog_from_uploads() -> tuple[dict, dict]:
            catalog_endpoints = {}
            catalog_components = {}
            newest_specs = []
            for data_dir in candidate_data_dirs():
                uploads_dir = os.path.join(data_dir, "uploads")
                if not os.path.isdir(uploads_dir):
                    continue
                specs = []
                for root, _, files in os.walk(uploads_dir):
                    for filename in files:
                        lowered = filename.lower()
                        if lowered.startswith("openapi") and lowered.endswith(".json"):
                            specs.append(os.path.join(root, filename))
                if specs:
                    newest_parent = os.path.dirname(max(specs, key=lambda p: os.path.getmtime(p)))
                    newest_specs = sorted(p for p in specs if os.path.dirname(p) == newest_parent)
                    break

            for spec_path in newest_specs:
                try:
                    with open(spec_path, "r", encoding="utf-8") as spec_file:
                        sw_data = json.load(spec_file)
                except Exception:
                    continue
                for path_key, methods in (sw_data.get("paths") or {}).items():
                    if not isinstance(methods, dict):
                        continue
                    catalog_endpoints.setdefault(path_key, {})
                    for method_key, details in methods.items():
                        if str(method_key).lower() in ["get", "post", "put", "delete", "options", "head", "patch"]:
                            catalog_endpoints[path_key][str(method_key).lower()] = details
                components = sw_data.get("components")
                if isinstance(components, dict):
                    for comp_type, comp_schemas in components.items():
                        if isinstance(comp_schemas, dict):
                            catalog_components.setdefault(comp_type, {}).update(comp_schemas)
            if catalog_endpoints:
                print(f"[OpenAPI] enriched endpoint details from uploaded specs: {len(catalog_endpoints)} paths")
            return catalog_endpoints, catalog_components

        uploaded_openapi_endpoints, uploaded_openapi_components = load_openapi_catalog_from_uploads()

        def build_endpoints_for_account(account: dict) -> tuple[dict, dict]:
            c_endpoints = {}
            s_components = {}
            op_url = account.get("openapi_url", "")
            u_list = account.get("url_list_str", "")
            a_list = account.get("api_list_str", "")
            b_url = account.get("base_url", target_url)
            
            # (A) Swagger OpenAPI 로드
            if op_url and op_url.strip():
                specs = [s.strip() for s in op_url.replace(',', '\n').split('\n') if s.strip()]
                for spec in specs:
                    sw_data = None
                    if spec.startswith("http"):
                        try:
                            zap.openapi.import_url(spec, b_url)
                            r = requests.get(spec, timeout=5)
                            if r.status_code == 200:
                                sw_data = r.json()
                        except:
                            pass
                    else:
                        local_path = os.path.abspath(spec)
                        if os.path.exists(local_path):
                            try:
                                zap.openapi.import_file(local_path, b_url)
                                with open(local_path, "r", encoding="utf-8") as f:
                                    sw_data = json.load(f)
                            except:
                                pass
                    
                    if sw_data and "paths" in sw_data:
                        for path, methods in sw_data["paths"].items():
                            c_endpoints.setdefault(path, {})
                            for method, details in methods.items():
                                if method.lower() in ["get", "post", "put", "delete", "options", "head", "patch"]:
                                    c_endpoints[path][method.lower()] = details
                        if "components" in sw_data and isinstance(sw_data["components"], dict):
                            for comp_type, comp_schemas in sw_data["components"].items():
                                s_components.setdefault(comp_type, {})
                                if isinstance(comp_schemas, dict):
                                    s_components[comp_type].update(comp_schemas)
            
            # (B) URL List
            if u_list and u_list.strip():
                for u in u_list.splitlines():
                    u = u.strip()
                    if not u: continue
                    path = u
                    if u.startswith(b_url):
                        path = u[len(b_url):]
                    path = path.split("?")[0]
                    c_endpoints.setdefault(path, {})
                    if "get" not in c_endpoints[path]:
                        c_endpoints[path]["get"] = {"parameters": [], "responses": {}}
                        
            # (C) API List
            if a_list and a_list.strip():
                for item in a_list.splitlines():
                    item = item.strip()
                    if not item: continue
                    parts = item.split(None, 1)
                    if len(parts) == 2:
                        method = parts[0].lower()
                        path = parts[1].strip()
                        if path.startswith(b_url):
                            path = path[len(b_url):]
                        path = path.split("?")[0]
                        c_endpoints.setdefault(path, {})
                        c_endpoints[path][method] = {"parameters": [], "responses": {}}
            return c_endpoints, s_components

        # 우선 스캔 시작 전 모든 계정의 개별 endpoints 수집
        for account in auth_tokens:
            existing_endpoints = account.get("validated_endpoints") if isinstance(account.get("validated_endpoints"), dict) else {}
            existing_components = account.get("swagger_components") if isinstance(account.get("swagger_components"), dict) else {}
            c_end, s_comp = build_endpoints_for_account(account)
            merged_endpoints = dict(existing_endpoints)
            for ep_path, methods in c_end.items():
                merged_endpoints.setdefault(ep_path, {}).update(methods or {})
            for ep_path, methods in uploaded_openapi_endpoints.items():
                merged_endpoints.setdefault(ep_path, {}).update(methods or {})
            merged_components = dict(existing_components)
            for comp_type, comp_schemas in s_comp.items():
                if isinstance(comp_schemas, dict):
                    merged_components.setdefault(comp_type, {}).update(comp_schemas)
            for comp_type, comp_schemas in uploaded_openapi_components.items():
                if isinstance(comp_schemas, dict):
                    merged_components.setdefault(comp_type, {}).update(comp_schemas)
            account["validated_endpoints"] = merged_endpoints
            account["swagger_components"] = merged_components
            print(
                f"[Debug] Loaded {len(merged_endpoints)} endpoints for account '{account.get('role')}' "
                f"(preloaded={len(existing_endpoints)}, discovered={len(c_end)})"
            )
            
        # 미인증 스캔이 필요할 때를 위해 validated_endpoints 글로벌 폴백을 첫번째 계정이나 빈 값으로 초기화
        validated_endpoints = auth_tokens[0]["validated_endpoints"] if auth_tokens else {}
        swagger_components = auth_tokens[0]["swagger_components"] if auth_tokens else {}

        def auth_probe_paths(endpoints: dict, account: dict) -> list:
            paths = []
            excluded = ["login", "signup", "register", "refresh", "logout", "check-", "find-", "reset-password"]
            preferred = [
                "me",
                "profile",
                "account",
                "user",
                "member",
                "application",
                "notification",
                "dashboard",
                "setting",
                "order",
                "reservation",
            ]
            role = account.get("role", "account")
            role_lower = (role or "").lower()
            base_url = account.get("base_url", target_url)
            
            # role, token claims, or account base URL can identify an admin reader account.
            token_claims = account.get("claims", {}) or {}
            claims_str = str(token_claims).lower()
            base_url_text = str(base_url).lower()
            
            is_admin = (
                "admin" in role_lower
                or "admin" in claims_str
                or "admin" in base_url_text
            )
            
            if is_admin:
                preferred = [
                    "admin",
                    "dashboard",
                    "member",
                    "user",
                    "settlement",
                    "reservation",
                    "report",
                    "me",
                    "profile",
                ]

            for ep_path, ep_methods in endpoints.items():
                if "get" not in ep_methods:
                    continue
                lowered = ep_path.lower()
                if "{" in ep_path:
                    continue
                if any(marker in lowered for marker in excluded):
                    continue
                if is_admin and "admin" not in lowered:
                    continue
                if not is_admin and "admin" in lowered:  # 일반 유저가 어드민 경로를 검증하는 것 방어
                    continue
                if any(marker in lowered for marker in preferred):
                    paths.append(ep_path)

            for ep_path, ep_methods in endpoints.items():
                if len(paths) >= 12:
                    break
                lowered = ep_path.lower()
                if "get" not in ep_methods or "{" in ep_path:
                    continue
                if any(marker in lowered for marker in excluded):
                    continue
                if is_admin and "admin" not in lowered:
                    continue
                if not is_admin and "admin" in lowered:
                    continue
                if ep_path not in paths:
                    paths.append(ep_path)

            return list(dict.fromkeys(paths))[:12]

        def detect_account_auth_mode(account: dict) -> str:
            token = account.get("token")
            base_url = account.get("base_url", target_url).rstrip("/")
            role = account.get("role", "account")
            token_source = (account.get("token_source") or "").lower()
            token_field = account.get("token_field") or ""
            has_cookie = bool(build_cookie_header_from_account(account))
            candidates = auth_probe_paths(account.get("validated_endpoints", {}), account)
            if not candidates:
                if token_source == "cookie" or has_cookie:
                    return "cookie"
                if token_source in {"json", "header"}:
                    return "header"
                return "both"

            if token_source == "cookie":
                modes = [("cookie", "Cookie")]
                if token:
                    modes.extend([
                        ("header", "Authorization Bearer"),
                        ("authorization_raw", "Authorization raw"),
                        ("x_auth_token", "X-Auth-Token"),
                        ("access_token_header", "access-token"),
                        ("access_token_camel_header", "accessToken"),
                    ])
                modes.append(("both", "Authorization+Cookie"))
            elif token_source in {"json", "header"}:
                modes = [
                    ("header", "Authorization Bearer"),
                    ("authorization_raw", "Authorization raw"),
                    ("x_auth_token", "X-Auth-Token"),
                    ("access_token_header", "access-token"),
                    ("access_token_camel_header", "accessToken"),
                ]
                if has_cookie:
                    modes.extend([("cookie", "Cookie"), ("both", "Authorization+Cookie")])
                else:
                    modes.append(("both", "Authorization+Cookie"))
            elif has_cookie:
                modes = [
                    ("cookie", "Cookie"),
                    ("header", "Authorization Bearer"),
                    ("authorization_raw", "Authorization raw"),
                    ("x_auth_token", "X-Auth-Token"),
                    ("access_token_header", "access-token"),
                    ("access_token_camel_header", "accessToken"),
                    ("both", "Authorization+Cookie"),
                ]
            else:
                modes = [
                    ("header", "Authorization Bearer"),
                    ("authorization_raw", "Authorization raw"),
                    ("x_auth_token", "X-Auth-Token"),
                    ("access_token_header", "access-token"),
                    ("access_token_camel_header", "accessToken"),
                    ("both", "Authorization+Cookie"),
                ]

            seen_modes = set()
            modes = [(mode, label) for mode, label in modes if not (mode in seen_modes or seen_modes.add(mode))]
            print(
                f"[AuthMode] {role}: login response suggests "
                f"token_source={token_source or 'unknown'}"
                f"{f'({token_field})' if token_field else ''}, cookies={'yes' if has_cookie else 'no'}"
            )
            for mode, label in modes:
                headers = build_auth_headers(token, account, mode)
                if not headers:
                    continue
                for path in candidates:
                    try:
                        url = f"{base_url}{path}"
                        no_auth_resp = requests.get(url, timeout=3)
                        resp = requests.get(url, headers=headers, timeout=3)
                    except Exception:
                        continue
                    if 200 <= resp.status_code < 400 and no_auth_resp.status_code in [401, 403]:
                        print(
                            f"[AuthMode] {role}: verified {label} by protected GET {url} "
                            f"(no-auth {no_auth_resp.status_code} -> auth {resp.status_code})"
                        )
                        return mode
                    if 200 <= resp.status_code < 400 and 200 <= no_auth_resp.status_code < 400:
                        print(
                            f"[AuthMode] {role}: {label} not proven by public GET {url} "
                            f"(no-auth {no_auth_resp.status_code}, auth {resp.status_code})"
                        )
                    else:
                        print(
                            f"[AuthMode] {role}: {label} rejected by GET {url} "
                            f"(no-auth {no_auth_resp.status_code}, auth {resp.status_code})"
                        )

            print(f"[AuthMode] {role}: could not prove a single mode; disabling this account")
            account["auth_unverified"] = True
            return "disabled"

        had_auth_accounts = bool(auth_tokens)
        for account in auth_tokens:
            account["auth_mode"] = detect_account_auth_mode(account)
        auth_tokens = [account for account in auth_tokens if not account.get("auth_unverified")]
        if primary_account and primary_account.get("auth_unverified"):
            primary_account = auth_tokens[0] if auth_tokens else None
            primary_token = primary_account.get("token") if primary_account else None
            primary_role = primary_account.get("role", "anonymous") if primary_account else "anonymous"
        if had_auth_accounts and not auth_tokens:
            print("[AuthMode] no verified authenticated account remains; stopping scan to avoid unsafe fallback requests")
            update_status(is_running=False, message="인증 검증 실패: 보호 API에서 401이 반환되어 스캔을 중단했습니다.")
            return

        if primary_account:
            primary_token = primary_account.get("token")
            primary_role = primary_account.get("role", primary_role)

        def configure_zap_auth_replacer(account: dict | None):
            try:
                zap.replacer.remove_rule(description="AutoLoginHeader")
                zap.replacer.remove_rule(description="AutoLoginCookie")
            except Exception:
                pass

            if not account:
                return

            token = account.get("token")
            mode = (account.get("auth_mode") or "both").lower()
            role = account.get("role", "account")

            if mode in {"header", "both", "authorization_raw", "x_auth_token", "access_token_header", "access_token_camel_header"} and token:
                clean_token = str(token).replace("Bearer ", "").strip()
                header_name = "Authorization"
                header_value = f"Bearer {clean_token}"
                if mode == "authorization_raw":
                    header_value = clean_token
                elif mode == "x_auth_token":
                    header_name = "X-Auth-Token"
                    header_value = clean_token
                elif mode == "access_token_header":
                    header_name = "access-token"
                    header_value = clean_token
                elif mode == "access_token_camel_header":
                    header_name = "accessToken"
                    header_value = clean_token
                zap.replacer.add_rule(
                    description="AutoLoginHeader",
                    enabled=True,
                    matchtype="REQ_HEADER",
                    matchregex=False,
                    matchstring=header_name,
                    replacement=header_value,
                )

            if mode in {"cookie", "both"}:
                cookie_header = build_cookie_header_from_account(account)
                if not cookie_header and token:
                    session_cookie_name = detect_session_cookie(target_url, token, validated_endpoints)
                    cookie_header = f"{session_cookie_name}={str(token).replace('Bearer ', '').strip()}"
                if cookie_header:
                    zap.replacer.add_rule(
                        description="AutoLoginCookie",
                        enabled=True,
                        matchtype="REQ_HEADER",
                        matchregex=False,
                        matchstring="Cookie",
                        replacement=cookie_header,
                    )

            print(f"[AuthMode] ZAP replacer configured for {role}: {mode}")

        configure_zap_auth_replacer(primary_account)

        def format_http_request(req_obj):
            try:
                hdrs = "\n".join(f'  "{k}": "{v}"' for k, v in req_obj.headers.items())
                body = req_obj.body
                if isinstance(body, bytes):
                    body = body.decode("utf-8", errors="ignore")
                body_str = body if body else ""
                return f"{req_obj.method} {req_obj.url}\n\nHeaders:\n{{\n{hdrs}\n}}\n\nBody:\n{body_str}"
            except Exception as e:
                return f"Request formatting error: {e}"

        def find_containing_record(body: str, needle: str):
            """If body is JSON and needle lives inside one specific object in
            a list (e.g. one post out of a feed array), return that object
            alone, pretty-printed — a whole valid record instead of an
            arbitrary character slice that could cut a JSON object in half."""
            try:
                data = json.loads(body)
            except (ValueError, TypeError):
                return None

            def _search(node):
                if isinstance(node, dict):
                    try:
                        serialized = json.dumps(node, ensure_ascii=False)
                    except (TypeError, ValueError):
                        return None
                    if needle not in serialized:
                        return None
                    for value in node.values():
                        deeper = _search(value)
                        if deeper is not None:
                            return deeper
                    return node
                if isinstance(node, list):
                    for item in node:
                        found = _search(item)
                        if found is not None:
                            return found
                return None

            record = _search(data)
            if record is None:
                return None
            try:
                pretty = json.dumps(record, ensure_ascii=False, indent=2)
            except (TypeError, ValueError):
                return None
            return f"(취약점이 발견된 항목만 표시, 전체 응답에서 발췌)\n{pretty}"

        def windowed_body(body: str, needle: str = "", context: int = 800, max_len: int = 3000) -> str:
            """Keep the evidence readable without losing the payload: save
            just the JSON record containing it (falling back to a character
            window) instead of the first N characters, so a payload stored
            deep in a list response isn't truncated away."""
            if not body or len(body) <= max_len:
                return body
            if needle:
                record = find_containing_record(body, needle)
                if record is not None:
                    return record
                idx = body.find(needle)
                if idx != -1:
                    start = max(0, idx - context)
                    end = min(len(body), idx + len(needle) + context)
                    prefix = "... (앞부분 생략) ...\n" if start > 0 else ""
                    suffix = "\n... (뒷부분 생략, 취약점 증거 주변만 저장됨) ..." if end < len(body) else ""
                    return f"{prefix}{body[start:end]}{suffix}"
            return body[:max_len] + "\n... (뒷부분 생략, 응답이 너무 길어 앞부분만 저장됨) ..."

        def format_http_response(res_obj, needle: str = ""):
            try:
                hdrs = "\n".join(f'  "{k}": "{v}"' for k, v in res_obj.headers.items())
                body_str = windowed_body(res_obj.text if res_obj.text else "", needle)
                return f"HTTP/1.1 {res_obj.status_code} {res_obj.reason}\n\nHeaders:\n{{\n{hdrs}\n}}\n\nBody:\n{body_str}"
            except Exception as e:
                return f"Response formatting error: {e}"

        def is_dangerous_endpoint(method: str, path: str, details: dict | None = None) -> tuple[bool, str]:
            method_upper = (method or "").upper()
            normalized_path = "/" + (path or "").lower().lstrip("/")
            details = details or {}

            # 1. DELETE 메소드는 데이터 파괴 및 세션 단절 위협이 극도로 높아 강제 스킵
            if method_upper == "DELETE":
                return True, "DELETE requests are skipped to protect active session and data integrity"

            # 2. Swagger details 정보 내 한글/영문 메타데이터 정적 분석
            summary = str(details.get("summary") or "").lower()
            description = str(details.get("description") or "").lower()
            
            critical_keywords = [
                "withdraw", "탈퇴", 
                "password-change", "change-password", "비밀번호 변경", "비밀번호변경",
                "logout", "로그아웃",
                "delete-account", "계정삭제", "계정 삭제"
            ]
            
            # 설명문이나 요약 정보에서 탈퇴, 비번변경, 로그아웃 등 위험 단어 매칭 시 차단
            if any(k in summary or k in description for k in critical_keywords):
                return True, f"API metadata (summary/description) matches safety block word"

            # 3. Request Body 내부의 스키마 분석 (오직 패스워드 변경 관련 전용 파라미터들로만 바인딩이 구성된 전용 변경 API만 차단)
            body_spec = details.get("requestBody", {}) or {}
            content = body_spec.get("content", {}) or {}
            json_schema = content.get("application/json", {}).get("schema", {}) or {}
            # schema reference 해결
            resolved_schema = resolve_schema_ref(json_schema, swagger_components)
            properties = resolved_schema.get("properties", {}) or {}
            
            password_indicators = ["newpassword", "currentpassword", "confirmpassword", "oldpassword", "password"]
            has_password_field = False
            has_normal_field = False
            for prop in properties.keys():
                if any(ind in prop.lower() for ind in password_indicators):
                    has_password_field = True
                else:
                    has_normal_field = True

            # 패스워드 필드가 포함되어 있으며, 프로필명/닉네임 등 일반 필드가 '전혀 없는' 순수 패스워드 변경용 API만 차단
            if has_password_field and not has_normal_field:
                return True, "Request body is restricted to sensitive credential modification only"

            # 4. 그 외 단순 상태 변경(승인/반려 등)이나 프로필 수정(/me/profile)은 스캔 진행 허용
            if any(marker in normalized_path for marker in extra_skip_path_markers):
                return True, "Endpoint matches a configured skip marker (diagnosis_1_1.extra_skip_path_markers)"
            if method_upper == "PATCH" and any(marker in normalized_path for marker in STATE_TRANSITION_PATH_MARKERS):
                return True, "State-transition endpoint is protected from active scanning"

            return False, ""

        def extract_request_parts(req_obj, body_json=None, query_params=None):
            """Playwright / Selenium 자동화 재현을 위해 요청 구성 요소를 파싱된 딕셔너리로 반환합니다."""
            try:
                # 헤더 딕셔너리 (Playwright 재현 시 headers 옵션에 그대로 전달)
                parsed_headers = dict(req_obj.headers)

                # 바디: 이미 python dict 형태로 전달된 경우 그대로 사용, 아니면 raw body 파싱 시도
                parsed_body = None
                if body_json is not None:
                    parsed_body = body_json
                else:
                    raw_body = req_obj.body
                    if isinstance(raw_body, bytes):
                        raw_body = raw_body.decode("utf-8", errors="ignore")
                    if raw_body:
                        try:
                            parsed_body = json.loads(raw_body)
                        except Exception:
                            parsed_body = raw_body  # JSON 파싱 실패 시 raw 문자열 유지

                parsed_query = query_params or {}

                content_type = parsed_headers.get("Content-Type", parsed_headers.get("content-type", ""))
                auth_header = parsed_headers.get("Authorization", parsed_headers.get("authorization", ""))
                cookie_header = parsed_headers.get("Cookie", parsed_headers.get("cookie", ""))

                # Playwright fetch() 재현용 스크립트 스텁 생성
                body_snippet = json.dumps(parsed_body, ensure_ascii=False) if isinstance(parsed_body, dict) else repr(parsed_body)
                query_snippet = ("?" + "&".join(f"{k}={v}" for k, v in parsed_query.items())) if parsed_query else ""
                replay_script = (
                    f"// [Playwright] 재현 테스트 스크립트\n"
                    f"const response = await request.fetch('{req_obj.url}{query_snippet}', {{\n"
                    f"  method: '{req_obj.method}',\n"
                    f"  headers: {{\n"
                    f"    'Content-Type': '{content_type}',\n"
                    f"    'Authorization': '{auth_header}',\n"
                    f"    'Cookie': '{cookie_header}'\n"
                    f"  }},\n"
                    f"  data: {body_snippet}\n"
                    f"}});\n"
                    f"// 검증: 응답 본문 내 공격 페이로드 반사 확인\n"
                    f"const body = await response.text();\n"
                    f"expect(body).toContain('/* 공격 페이로드 삽입 */');"
                )

                return {
                    "parsed_request_headers": parsed_headers,
                    "parsed_request_body": parsed_body,
                    "parsed_request_query": parsed_query,
                    "auth_token_used": auth_header,
                    "login_required": bool(auth_header),
                    "replay_script": replay_script,
                }
            except Exception as e:
                return {
                    "parsed_request_headers": {},
                    "parsed_request_body": None,
                    "parsed_request_query": {},
                    "auth_token_used": "",
                    "login_required": False,
                    "replay_script": f"// extract_request_parts error: {e}",
                }

        custom_alerts = []
        cross_role_stored_seen = set()

        scan_accounts = auth_tokens if auth_tokens else [{"role": "anonymous", "token": None, "base_url": target_url}]
        def is_admin_account(account: dict) -> bool:
            role_text = str(account.get("role", "")).lower()
            base_url_text = str(account.get("base_url", "")).lower()
            claims_text = str(account.get("claims", {}) or {}).lower()
            return bool(account.get("token")) and (
                "admin" in role_text
                or "admin" in claims_text
                or "admin" in base_url_text
            )

        def account_role_text(account: dict | None) -> str:
            account = account or {}
            return " ".join(
                str(value or "").lower()
                for value in [
                    account.get("role"),
                    account.get("base_url"),
                    account.get("claims", {}),
                    account.get("email"),
                ]
            )

        def endpoint_role_priority(path_value: str, account: dict | None) -> tuple[int, str]:
            lowered = str(path_value or "").lower()
            role_text = account_role_text(account)
            is_admin = "admin" in role_text
            is_seller = "seller" in role_text
            if is_admin and re.search(r"(^|/)admin(s)?(/|$)", lowered):
                return (0, lowered)
            if is_seller and re.search(r"(^|/)seller(s)?(/|$)", lowered):
                return (0, lowered)
            if not is_admin and re.search(r"(^|/)admin(s)?(/|$)", lowered):
                return (3, lowered)
            if not is_seller and re.search(r"(^|/)seller(s)?(/|$)", lowered):
                return (3, lowered)
            return (1, lowered)

        admin_accounts = [account for account in auth_tokens if is_admin_account(account)]
        if admin_accounts:
            print(
                "[CROSS-ROLE STORED XSS] admin reader accounts: "
                + ", ".join(
                    f"{account.get('role', 'account')}@{account.get('base_url', target_url)}"
                    for account in admin_accounts
                )
            )
        else:
            print("[CROSS-ROLE STORED XSS] no admin reader account detected")

        def resource_tokens_from_path(path_value: str) -> set[str]:
            ignored = {
                "api", "v1", "v2", "admin", "admins", "seller", "sellers",
                "me", "auth", "login", "logout", "search", "check",
            }
            tokens = set()
            for segment in (path_value or "").split("/"):
                segment = segment.strip("{} ").lower()
                if not segment or segment in ignored or segment.startswith("{"):
                    continue
                if re.fullmatch(r"\d+", segment):
                    continue
                tokens.add(segment)
                if segment.endswith("ies") and len(segment) > 3:
                    tokens.add(segment[:-3] + "y")
                elif segment.endswith("s") and len(segment) > 1:
                    tokens.add(segment[:-1])
            if "profile" in tokens:
                tokens.update({"user", "users", "member", "members", "account", "accounts"})
            return tokens

        def cross_account_read_candidates_for_post(post_path: str, resource_id, writer_account: dict | None = None) -> list[tuple[dict, str, str, dict]]:
            post_tokens = resource_tokens_from_path(post_path)
            candidates = []
            writer_role = (writer_account or {}).get("role")
            writer_token = (writer_account or {}).get("token")
            reader_accounts = auth_tokens if auth_tokens else []
            for reader_account in reader_accounts:
                if writer_account and (
                    reader_account.get("token") == writer_token
                    or reader_account.get("role") == writer_role
                ):
                    continue
                reader_base = reader_account.get("base_url", target_url).rstrip("/")
                reader_endpoints = reader_account.get("validated_endpoints", validated_endpoints)
                for get_path, get_methods in reader_endpoints.items():
                    if "get" not in get_methods:
                        continue
                    lowered = get_path.lower()
                    get_tokens = resource_tokens_from_path(get_path)
                    if post_tokens and not (post_tokens & get_tokens):
                        continue
                    if "{" in get_path:
                        if not resource_id:
                            continue
                        resolved_path = re.sub(r"\{[^}]+\}", str(resource_id), get_path)
                    else:
                        resolved_path = get_path
                    reader_url = f"{reader_base}/{resolved_path.lstrip('/')}"
                    reader_params = build_query_defaults_from_details(get_methods.get("get") or {}, swagger_components)
                    for param_name in list(reader_params):
                        resolved_identity = resolve_identity_query_param(param_name, reader_account, reader_account.get("token"), reader_base)
                        if resolved_identity is not None:
                            reader_params[param_name] = resolved_identity
                    score = 0
                    if is_admin_account(reader_account) or "admin" in lowered:
                        score += 40
                    if resource_id and str(resource_id) in reader_url:
                        score += 20
                    if get_tokens & post_tokens:
                        score += 10
                    if get_path.rstrip("/") == post_path.rstrip("/"):
                        score += 12
                    elif get_path.rstrip("/").endswith(post_path.rstrip("/").split("/")[-1]):
                        score += 8
                    candidates.append((score, reader_account, get_path, reader_url, reader_params))

            deduped = []
            seen = set()
            for _, reader_account, get_path, reader_url, reader_params in sorted(candidates, key=lambda item: item[0], reverse=True):
                key = (reader_account.get("role"), reader_url, tuple(sorted(reader_params.items())))
                if key not in seen:
                    seen.add(key)
                    deduped.append((reader_account, get_path, reader_url, reader_params))
            return deduped[:20]

        def reflected_near_resource_id(response_text: str, payload: str, resource_id) -> bool:
            if not is_payload_reflected(payload, response_text):
                return False
            if not resource_id:
                return True
            rid = str(resource_id)
            if rid not in response_text:
                return False
            idx = response_text.find(rid)
            start_clip = max(0, idx - 250)
            end_clip = min(len(response_text), idx + 750)
            return payload in response_text[start_clip:end_clip]

        def discover_resource_id_from_readers(post_path: str, payload: str, writer_account: dict | None, get_endpoint_items: list[tuple[str, dict]]) -> tuple[object | None, str]:
            post_tokens = resource_tokens_from_path(post_path)
            reader_base = (writer_account or {}).get("base_url", target_url).rstrip("/")
            reader_headers = build_auth_headers((writer_account or {}).get("token"), writer_account)
            for get_path, get_methods in get_endpoint_items:
                if "get" not in get_methods or "{" in get_path:
                    continue
                get_tokens = resource_tokens_from_path(get_path)
                if post_tokens and not (post_tokens & get_tokens):
                    continue
                reader_url = f"{reader_base}/{get_path.lstrip('/')}"
                reader_params = build_query_defaults_from_details(get_methods.get("get") or {}, swagger_components)
                for param_name in list(reader_params):
                    resolved_identity = resolve_identity_query_param(
                        param_name,
                        writer_account,
                        (writer_account or {}).get("token"),
                        reader_base,
                    )
                    if resolved_identity is not None:
                        reader_params[param_name] = resolved_identity
                try:
                    reader_res = _bounded_get(
                        reader_url,
                        headers=reader_headers,
                        params=reader_params or None,
                        timeout=4,
                    )
                except Exception as exc:
                    print(f"[STORED XSS DEBUG] resource-id discovery GET fail on {reader_url}: {exc}")
                    continue
                if not (200 <= reader_res.status_code < 400):
                    continue
                if not is_payload_reflected(payload, reader_res.text):
                    continue
                try:
                    found_id = extract_id_near_payload(reader_res.json(), payload)
                except Exception:
                    found_id = None
                if found_id is not None:
                    return found_id, reader_url
            return None, ""

        def verify_cross_account_stored_xss(post_path: str, post_url: str, resource_id, payload: str, param_name: str, writer_account: dict | None, writer_role: str):
            if not auth_tokens or len(auth_tokens) < 2:
                return
            for reader_account, reader_path, reader_url, reader_params in cross_account_read_candidates_for_post(post_path, resource_id, writer_account):
                reader_role = reader_account.get("role", "reader")
                seen_key = (post_url, reader_url, payload, str(resource_id), reader_role)
                if seen_key in cross_role_stored_seen:
                    continue
                cross_role_stored_seen.add(seen_key)
                try:
                    reader_headers = build_auth_headers(reader_account.get("token"), reader_account)
                    reader_res = requests.get(reader_url, headers=reader_headers, params=reader_params or None, timeout=4)
                except Exception as ce:
                    print(f"[CROSS-ACCOUNT STORED XSS DEBUG] reader GET fail on {reader_url} params={reader_params}: {ce}")
                    continue
                if not (200 <= reader_res.status_code < 400):
                    print(
                        f"[CROSS-ACCOUNT STORED XSS DEBUG] reader GET {reader_url} returned "
                        f"{reader_res.status_code}. Params: {reader_params}. Response: {summarize_response_for_log(reader_res)}"
                    )
                    continue
                url_has_resource = bool(resource_id and str(resource_id) in reader_url)
                if url_has_resource:
                    reflected = is_payload_reflected(payload, reader_res.text)
                else:
                    reflected = reflected_near_resource_id(reader_res.text, payload, resource_id)
                if not reflected:
                    continue

                reader_content_type = reader_res.headers.get("Content-Type", "").lower()
                print(
                    f"[CROSS-ACCOUNT STORED XSS] !!! CONFIRMED writer '{writer_role}' -> "
                    f"reader '{reader_role}' on {reader_url} (payload '{payload}' reflected) !!!"
                )
                response_params = infer_reflected_response_params(reader_res, payload)
                custom_alerts.append({
                    "alert": "Cross-Account Stored Cross-Site Scripting (Stored XSS) Vulnerability",
                    "url": reader_url,
                    "method": "GET",
                    "risk": "High",
                    "confidence": "High",
                    "param": param_name,
                    "reflected_response_params": response_params,
                    "attack": payload,
                    "status_code": reader_res.status_code,
                    "evidence": (
                        f"Payload stored by {writer_role} via mutation request {post_url} was reflected "
                        f"when read by {reader_role} via GET {reader_url}."
                    ),
                    "custom_type": "40014",
                    "evidence_request": format_http_request(reader_res.request),
                    "evidence_response": format_http_response(reader_res, payload),
                    "expected_status_code": reader_res.status_code,
                    "expected_evidence_in_response": payload,
                    "cross_account_writer_role": writer_role,
                    "cross_account_reader_role": reader_role,
                    "cross_account_write_url": post_url,
                    "cross_account_read_url": reader_url,
                    "screenshot_on": "page_loaded",
                    "description": (
                        f"Input stored by one account boundary ({writer_role}) through {post_url} "
                        f"was later returned to another account boundary ({reader_role}) through "
                        f"{reader_url} without output encoding. "
                        f"(GET response Content-Type: {reader_content_type})"
                    )
                })

        print("[Auth] scan account order: " + ", ".join(f"{a.get('role', 'account')}@{a.get('base_url', target_url)}" for a in scan_accounts))

        for scan_account in scan_accounts:
            account_endpoints = scan_account.get("validated_endpoints", validated_endpoints)
            account_swagger_components = scan_account.get("swagger_components") or swagger_components
            ordered_account_endpoints = sorted(
                account_endpoints.items(),
                key=lambda item: endpoint_role_priority(item[0], scan_account),
            )
            for path, methods in ordered_account_endpoints:
                for method, details in methods.items():
                    # 기본 api_url은 primary target 기준으로 구성 (select_token 내 path 추출용)
                    blocked, block_reason = is_dangerous_endpoint(method, path, details)
                    if blocked:
                        print(f"[Safety] skip {method.upper()} {path}: {block_reason}")
                        continue

                    api_url = f"{target_url.rstrip('/')}/{path.lstrip('/')}"
    
                    # 이 엔드포인트에 대해 최적 토큰 + 실제 서비스 base_url + role 선택
                    best_token, best_base, best_role, selected_api_url = select_token(api_url, method.upper(), scan_account)
    
                    api_url = selected_api_url
    
                    # 이 엔드포인트 스캔 시작 전 alert 개수 스냅샷 (끝에서 account_role 일괄 태깅용)
                    _alerts_snapshot = len(custom_alerts)
    
                    # (1) [SK 쉴더스 1-1] CSRF 공격 가능성 정밀 진단
                    # 중요 상태 변경을 일으키는 모든 POST/PUT/DELETE/PATCH API를 점검합니다.
                    if method.lower() in ["post", "put", "delete", "patch"]:
                        csrf_json_body = {}
                        csrf_body_spec = details.get("requestBody", {}) if isinstance(details, dict) else {}
                        csrf_content = csrf_body_spec.get("content", {}) if isinstance(csrf_body_spec, dict) else {}
                        if "application/json" in csrf_content:
                            csrf_schema = csrf_content.get("application/json", {}).get("schema", {})
                            csrf_json_body = build_default_payload_from_schema(
                                resolve_schema_ref(csrf_schema, account_swagger_components),
                                account_swagger_components,
                            )
                            
                        # Use the account authentication headers as the real request baseline.
                        # Do not exclude cookie or Authorization modes up front; judge the three CSRF defenses below.
                        csrf_base_headers = build_auth_headers(best_token, scan_account)
                        if csrf_json_body:
                            csrf_base_headers["Content-Type"] = "application/json"
                        cookie_auth_header = build_cookie_header_from_account(scan_account)
                        try:
                            custom_alerts.extend(
                                csrf_scanner.scan_csrf_endpoint(
                                    method=method,
                                    api_url=api_url,
                                    body_json=csrf_json_body,
                                    base_headers=csrf_base_headers,
                                    scan_account=scan_account,
                                    cookie_auth_header=cookie_auth_header,
                                    check_csrf_token_absence=check_csrf_token_absence,
                                    has_unsafe_samesite_cookie=has_unsafe_samesite_cookie,
                                    extract_request_parts=extract_request_parts,
                                    format_http_request=format_http_request,
                                    format_http_response=format_http_response,
                                )
                            )
                        except Exception as ce:
                            print(f"CSRF Custom scan skip for {api_url}: {ce}")


                    # (2) [SK 쉴더스 1-1] XSS 공격 가능성 정밀 진단
                    # 다중 페이로드를 순회하여 WAF/필터 우회 변형 포함 탐지. 첫 검출 즉시 중단.
                    xss_headers = build_auth_headers(best_token, scan_account)
    
                    # Swagger에 정의된 파라미터 정보 추출 (루프 밖에서 1회만 수행)
                    parameters = details.get("parameters", [])
                    request_body_spec = details.get("requestBody", {})
    
                    base_test_params = {}
                    base_test_param_schemas = {}
                    base_param_defaults = {}
                    base_test_json_keys = []
                    base_test_json_schemas = {}
                    base_json_defaults = {}
                    base_json_required_defaults = {}
                    base_test_multipart_keys = []
                    base_test_multipart_schemas = {}
                    base_multipart_defaults = {}
                    base_multipart_required_defaults = {}
                    base_multipart_file_keys = []
    
                    for param_meta in parameters:
                        p_name = param_meta.get("name")
                        p_in = param_meta.get("in", "query")
                        p_schema = param_meta.get("schema")
                        if p_name and p_in == "query":
                            default_value = default_value_for_query_param(p_name, p_schema, account_swagger_components)
                            if default_value is not None:
                                base_param_defaults[p_name] = default_value
                            if is_xss_injectable_schema(p_schema, p_name, account_swagger_components):
                                base_test_params[p_name] = None  # XSS payload is injected only into string query params.
                                base_test_param_schemas[p_name] = resolve_schema_ref(p_schema or {}, account_swagger_components)
    
                    base_test_enum_defaults = {}
                    is_multipart_request = False
                    if request_body_spec:
                        content = request_body_spec.get("content", {})
                        if "multipart/form-data" in content:
                            is_multipart_request = True
                            multipart_schema = resolve_schema_ref(
                                content.get("multipart/form-data", {}).get("schema", {}),
                                account_swagger_components,
                            )
                            required_multipart_props = set(multipart_schema.get("required") or [])
                            for prop_name, prop_meta in multipart_schema.get("properties", {}).items():
                                default_multipart_value = default_value_for_schema(prop_meta, account_swagger_components, prop_name)
                                base_multipart_defaults[prop_name] = default_multipart_value
                                if prop_name in required_multipart_props:
                                    base_multipart_required_defaults[prop_name] = default_multipart_value
                                if looks_like_file_field(prop_name, prop_meta, account_swagger_components):
                                    base_multipart_file_keys.append(prop_name)
                                if is_xss_injectable_schema(prop_meta, prop_name, account_swagger_components):
                                    base_test_multipart_keys.append(prop_name)
                                    base_test_multipart_schemas[prop_name] = resolve_schema_ref(prop_meta, account_swagger_components)
                                if "enum" in prop_meta and prop_meta["enum"]:
                                    base_test_enum_defaults[prop_name] = prop_meta["enum"][0]
                        elif "application/json" in content:
                            json_schema = content.get("application/json", {}).get("schema", {})
                            resolved_json_schema = resolve_schema_ref(json_schema, account_swagger_components)
                            base_test_json_keys = extract_injectable_keypaths(resolved_json_schema, components=account_swagger_components)
                            base_test_json_schemas = {
                                keypath: schema_for_keypath(resolved_json_schema, keypath, account_swagger_components)
                                for keypath in base_test_json_keys
                            }
                            base_json_defaults = build_default_payload_from_schema(resolved_json_schema, account_swagger_components)
                            base_json_required_defaults = build_required_payload_from_schema(resolved_json_schema, account_swagger_components)
                            for prop_name, prop_meta in resolved_json_schema.get("properties", {}).items():
                                if "enum" in prop_meta and prop_meta["enum"]:
                                    base_test_enum_defaults[prop_name] = prop_meta["enum"][0]

                    for param_name in list(base_param_defaults):
                        resolved_identity = resolve_identity_query_param(param_name, scan_account, best_token, best_base)
                        if resolved_identity is not None:
                            base_param_defaults[param_name] = resolved_identity

                    def multipart_files_for_request():
                        if not base_multipart_file_keys:
                            return None
                        # Match real multipart upload flows: if the OpenAPI request declares file
                        # fields, include a harmless 1x1 PNG even when the field is optional.
                        png_1x1 = base64.b64decode(
                            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMB/ax"
                            "p3n8AAAAASUVORK5CYII="
                        )
                        return {
                            key: ("argus-test.png", png_1x1, "image/png")
                            for key in base_multipart_file_keys
                        }
    
                    # Path parameters have already been resolved by select_token using readable IDs.
                    resolved_api_url = api_url

                    # 고도화 6: Baseline 사전 요청 전송 (Diff 기반 오탐 방지 목적)
                    baseline_params = dict(base_param_defaults)
                    baseline_json = copy.deepcopy(base_json_defaults or base_json_required_defaults)
                    for k in base_test_json_keys:
                        top_key = k.split(".", 1)[0].replace("[0]", "")
                        if top_key not in baseline_json:
                            continue
                        prop_name = k.split(".")[-1]
                        dummy_val = default_value_for_schema(base_test_json_schemas.get(k, {"type": "string"}), account_swagger_components, prop_name)
                        set_nested_value_by_keypath(baseline_json, k, dummy_val)
                    stabilize_profile_payload(baseline_json, resolved_api_url, best_role)
                    # Keep the baseline probe from failing a UNIQUE-constrained
                    # profile field (e.g. nickname) with "already in use": copy
                    # the account's own current field values in, so the baseline
                    # PATCH is accepted and the stored-XSS scan isn't skipped on a
                    # 400. Mirrors what the store request does below; app-neutral
                    # (no field name hardcoded) and no-ops off profile endpoints.
                    preserve_current_profile_values(baseline_json, resolved_api_url, xss_headers, "")
                    baseline_multipart = dict(base_multipart_defaults or base_multipart_required_defaults)
                    for k in base_test_multipart_keys:
                        if k not in baseline_multipart:
                            continue
                        dummy_val = default_value_for_schema({"type": "string"}, account_swagger_components, k)
                        baseline_multipart[k] = base_test_enum_defaults.get(k, dummy_val)
    
                    baseline_status = None
                    try:
                        req_headers = {**xss_headers}
                        if not is_multipart_request and base_test_json_keys:
                            req_headers["Content-Type"] = "application/json"
                        elif is_multipart_request:
                            # requests가 자동으로 boundary를 가진 Content-Type 헤더를 채우도록 대소문자 구분 없이 소거
                            for ct_key in [k for k in req_headers.keys() if k.lower() == "content-type"]:
                                req_headers.pop(ct_key, None)
    
                        res_base = requests.request(
                            method=method.upper(),
                            url=resolved_api_url,
                            params=baseline_params if baseline_params else None,
                            json=baseline_json if (baseline_json and not is_multipart_request) else None,
                            data=baseline_multipart if (is_multipart_request and baseline_multipart) else None,
                            files=multipart_files_for_request() if is_multipart_request else None,
                            headers=req_headers,
                            timeout=4
                        )
                        baseline_status = res_base.status_code
                        print(
                            f"[HTTP TRACE] baseline {method.upper()} {resolved_api_url} "
                            f"role={best_role} status={res_base.status_code} "
                            f"params={baseline_params or {}} "
                            f"json_keys={list(baseline_json.keys()) if isinstance(baseline_json, dict) and baseline_json else []} "
                            f"multipart_keys={list(baseline_multipart.keys()) if baseline_multipart else []} "
                            f"file_keys={base_multipart_file_keys if is_multipart_request else []} "
                            f"content_type={res_base.headers.get('Content-Type', '')} "
                            f"response={summarize_response_for_log(res_base, 300)}"
                        )
                    except Exception as be:
                        print(f"[XSS Baseline DEBUG] Failed to get baseline response: {be}")

                    if baseline_status in [401, 403]:
                        print(f"[XSS DEBUG] skip fuzzing -> {method.upper()} {resolved_api_url} baseline returned {baseline_status} for account '{best_role}'")
                        continue
    
                    # ── XSS 고도화 3단계: HTTP 헤더 인젝션 XSS (Header Injection) ──
                    # User-Agent, Referer, X-Forwarded-For 등 클라이언트 전송 헤더가 응답 페이지나 에러 출력에 그대로 반사되는 취약점을 진단합니다.
                    INJECTABLE_HEADERS = [
                        "User-Agent",
                        "Referer",
                        "X-Forwarded-For",
                        "X-Real-IP",
                        "X-Custom-Header",
                    ]
    
                    for header_name in INJECTABLE_HEADERS:
                        header_payload = "<script>alert('header')</script>"
                        inject_headers = {**xss_headers, header_name: header_payload}
                        
                        # Origin이나 Referer의 경우 타 도메인 검증에 영향이 없도록 Referer 헤더 인젝션 시에만 덮어씀
                        if header_name == "Referer":
                            inject_headers["Referer"] = header_payload
                            
                        try:
                            res_hdr = requests.request(
                                method=method.upper(),
                                url=api_url,
                                headers=inject_headers,
                                timeout=4
                            )
                            content_type = res_hdr.headers.get("Content-Type", "").lower()
    
                            # 4xx/5xx 에러 응답은 XSS로 처리하지 않음
                            if res_hdr.status_code >= 400:
                                continue
    
                            hdr_xss_result = classify_xss_response(
                                payload=header_payload,
                                response_body=res_hdr.text,
                                content_type=content_type,
                                method=method.upper(),
                                is_mutation=False,
                                response_headers=res_hdr.headers,
                            )
                            
                            if hdr_xss_result:
                                print(f"[XSS DEBUG] !!! HEADER XSS DETECTED on {api_url} via {header_name} !!!")
                                hdr_req_parts = extract_request_parts(res_hdr.request)
                                custom_alerts.append({
                                    "alert": f"Header-based Cross-Site Scripting (XSS) via {header_name}",
                                    "url": api_url,
                                    "method": method.upper(),
                                    "risk": "Medium",
                                    "confidence": "High",
                                    "param": header_name,
                                    "attack": header_payload,
                                    "status_code": res_hdr.status_code,
                                    "evidence": f"HTTP 요청 헤더 '{header_name}'에 주입된 페이로드가 응답 본문에 그대로 실행 가능한 형태로 반사됨",
                                    "custom_type": "40012",
                                    "evidence_request": format_http_request(res_hdr.request),
                                    "evidence_response": format_http_response(res_hdr, header_payload),
                                    "parsed_request_headers": hdr_req_parts["parsed_request_headers"],
                                    "parsed_request_body": hdr_req_parts["parsed_request_body"],
                                    "parsed_request_query": hdr_req_parts["parsed_request_query"],
                                    "auth_token_used": hdr_req_parts["auth_token_used"],
                                    "login_required": hdr_req_parts["login_required"],
                                    "expected_status_code": res_hdr.status_code,
                                    "expected_evidence_in_response": header_payload,
                                    "screenshot_on": "response_received",
                                    "replay_script": hdr_req_parts["replay_script"],
                                    "description": f"요청 헤더 '{header_name}' 값을 통해 입력한 악성 스크립트가 적절한 필터링 없이 화면에 출력되어 XSS 공격에 악용될 수 있습니다.",
                                    "solution": f"로그 화면 또는 에러 메시지 출력 페이지에서 '{header_name}' 헤더 값을 렌더링할 때 특수 문자(<, >, &, \")를 인코딩 처리(HTML Entity Escape) 하십시오."
                                })
                                break # 하나의 헤더에서 발생이 증명되면 중단
                        except Exception:
                            continue
    
                    # ── Stored XSS 2단계 검증 (POST→GET 재조회) ───────────────────────────────
                    # POST 엔드포인트에서 4종의 페이로드 저장 시도 후, 모든 GET 엔드포인트에 대해 자원 ID를 대입하여 브로드캐스트 조회
                    if method.lower() in {"post", "put", "patch"}:
                        # 고도화 2: 1종이 아닌 상위 4종의 주요 XSS 변형군으로 저장 시도
                        path_lower_for_stored = str(path or api_url).lower()
                        stored_skip_markers = (*STORED_SCAN_SKIP_PATH_MARKERS, *extra_skip_path_markers)
                        if baseline_status is None or baseline_status >= 400:
                            print(
                                f"[STORED XSS DEBUG] skip stored scan -> {method.upper()} {api_url}: "
                                f"baseline status {baseline_status}"
                            )
                            continue
                        if any(marker in path_lower_for_stored for marker in stored_skip_markers):
                            print(
                                f"[STORED XSS DEBUG] skip stored scan -> {method.upper()} {api_url}: "
                                "auth/account utility endpoint"
                            )
                            continue
                        stored_targets = []
                        for q_param in base_test_params.keys():
                            stored_targets.append(("query", q_param, base_test_param_schemas.get(q_param, {"type": "string"})))
                        for j_key in base_test_json_keys:
                            stored_targets.append(("json", j_key, base_test_json_schemas.get(j_key, {"type": "string"})))
                        for m_key in base_test_multipart_keys:
                            stored_targets.append(("multipart", m_key, base_test_multipart_schemas.get(m_key, {"type": "string"})))
                        stored_trials = []
                        for target_type, target_param, target_schema in stored_targets:
                            for base_stored_payload in payloads_for_xss_field(target_param, target_schema, account_swagger_components)[:4]:
                                stored_payload = make_unique_xss_payload(base_stored_payload, target_param)
                                stored_trials.append((target_type, target_param, stored_payload))
                        # Stored XSS는 원인 필드 추적을 위해 한 번에 하나의 파라미터에만 payload를 저장한다.
                        for target_type, target_param, stored_payload in stored_trials:
                            store_params = dict(base_param_defaults)
                            if target_type == "query":
                                store_params[target_param] = stored_payload

                            store_json = copy.deepcopy(base_json_defaults or base_json_required_defaults)
                            for k in base_test_json_keys:
                                top_key = k.split(".", 1)[0].replace("[0]", "")
                                if target_type != "json" and top_key not in store_json:
                                    continue
                                prop_name = k.split(".")[-1]
                                dummy_val = default_value_for_schema(base_test_json_schemas.get(k, {"type": "string"}), account_swagger_components, prop_name)
                                set_nested_value_by_keypath(store_json, k, base_test_enum_defaults.get(prop_name, dummy_val))
                            if target_type == "json":
                                set_nested_value_by_keypath(store_json, target_param, stored_payload)
                            preserve_json_keys = {target_param.split(".", 1)[0].replace("[0]", "")} if target_type == "json" else set()
                            stabilize_profile_payload(store_json, resolved_api_url, best_role, preserve=preserve_json_keys)
                            # (a) Keep the *other* profile fields at their current
                            # stored values (which may hold another finding's
                            # payload) instead of resetting them to "safe", so
                            # per-field profile stored-XSS findings don't overwrite
                            # each other — every field's payload survives in the DB.
                            preserve_current_profile_values(store_json, resolved_api_url, xss_headers, target_param if target_type == "json" else "")
                            
                            store_multipart = dict(base_multipart_defaults or base_multipart_required_defaults)
                            for k in base_test_multipart_keys:
                                if target_type != "multipart" and k not in store_multipart:
                                    continue
                                dummy_val = default_value_for_schema({"type": "string"}, account_swagger_components, k)
                                store_multipart[k] = base_test_enum_defaults.get(k, dummy_val)
                            if target_type == "multipart":
                                store_multipart[target_param] = stored_payload
                                
                            try:
                                post_headers = {**xss_headers}
                                if not is_multipart_request and base_test_json_keys:
                                    post_headers["Content-Type"] = "application/json"
                                elif is_multipart_request:
                                    post_headers.pop("Content-Type", None)

                                # [Stored XSS 오탐 방지] POST 저장 전에 미리 모든 GET 엔드포인트의 Baseline 상태를 백업
                                #
                                # 경로에 {id}가 있는 개별 조회 엔드포인트는 수정(PUT/PATCH)과 신규 등록(POST)을
                                # 구분해서 처리한다:
                                #   - 수정: api_url 자체에 이미 대상 리소스의 진짜 ID가 있으므로, 그 ID로
                                #     baseline을 잡으면 "같은 자원의 진짜 전/후" 비교가 된다.
                                #   - 신규 등록: 새로 생길 ID를 아직 모르므로, 존재하는 다른 자원(예: 1번)을
                                #     대신 baseline으로 쓰면 "같은 자원의 전/후"가 아니라 "무관한 두 자원의
                                #     비교"가 되어 버린다. payload가 고유 문자열이라 탐지 자체는 되지만, 반대로
                                #     그 무관한 자원에 우연히 겹치는 내용이 있으면 진짜 반사를 diff가 지워버려
                                #     미탐이 날 수도 있다. 그래서 이 경우 baseline을 아예 안 만들고, 이후
                                #     get_payload_reflection이 baseline 없이 응답 전체에서 직접 검색하도록
                                #     둔다(diff 단계만 건너뛸 뿐, POST -> 재조회 -> 판정 흐름 자체는 그대로다).
                                edit_target_id = extract_id_from_url(api_url) if method.upper() in ("PUT", "PATCH") else None
                                get_baselines = {}
                                get_endpoint_items = [
                                    (get_path, get_methods)
                                    for get_path, get_methods in account_endpoints.items()
                                    if "get" in get_methods
                                ]
                                print(
                                    f"[STORED XSS DEBUG] preparing GET baselines for {method.upper()} {api_url} "
                                    f"payload_param={target_param} get_endpoints={len(get_endpoint_items)} "
                                    f"edit_target_id={edit_target_id}"
                                )
                                update_status(
                                    progress=55,
                                    message=(
                                        "Stored XSS baseline collection: "
                                        f"{method.upper()} {api_url} ({len(get_endpoint_items)} GET endpoints)"
                                    ),
                                )
                                for idx_get, (get_path, get_methods) in enumerate(get_endpoint_items, start=1):
                                    if idx_get == 1 or idx_get % 20 == 0 or idx_get == len(get_endpoint_items):
                                        print(
                                            f"[STORED XSS DEBUG] baseline progress {idx_get}/{len(get_endpoint_items)} "
                                            f"for {method.upper()} {api_url}"
                                        )
                                    if "get" not in get_methods:
                                        continue
                                    import re as _re
                                    if "{" in get_path:
                                        if edit_target_id is None:
                                            # 신규 등록: 이 경로의 진짜 "이전 상태"를 구할 방법이 없으므로
                                            # baseline을 만들지 않고 스킵한다(무관한 자원 대체 금지).
                                            continue
                                        # 수정: 실제 대상 ID로 치환해 같은 자원의 baseline을 확보한다.
                                        tmp_path = _re.sub(r"\{[^}]+\}", str(edit_target_id), get_path)
                                    else:
                                        tmp_path = get_path
                                    tmp_url = f"{best_base.rstrip('/')}/{tmp_path.lstrip('/')}"
                                    tmp_params = build_query_defaults_from_details(get_methods.get("get") or {}, account_swagger_components)
                                    try:
                                        tmp_res = _bounded_get(
                                            tmp_url,
                                            headers=xss_headers,
                                            params=tmp_params or None,
                                            timeout=3,
                                        )
                                        if tmp_res.status_code == 200:
                                            get_baselines[get_path] = tmp_res.text
                                    except Exception:
                                        pass

                                post_res = requests.request(
                                    method.upper(),
                                    api_url,
                                    params=store_params if store_params else None,
                                    json=store_json if (store_json and not is_multipart_request) else None,
                                    data=store_multipart if (is_multipart_request and store_multipart) else None,
                                    files=multipart_files_for_request() if is_multipart_request else None,
                                    headers=post_headers,
                                    timeout=4
                                )
                                if post_res.status_code in [200, 201]:
                                    # 생성된 리소스 ID 추출
                                    resource_id = extract_id_from_url(api_url)
                                    if not resource_id:
                                        resource_id = extract_id_from_location(post_res)
                                    try:
                                        resp_json = post_res.json()
                                        if not resource_id:
                                            resource_id = extract_id_from_response(resp_json)
                                    except Exception:
                                        pass
                                    if not resource_id:
                                        resource_id, discovery_url = discover_resource_id_from_readers(
                                            path,
                                            stored_payload,
                                            scan_account,
                                            get_endpoint_items,
                                        )
                                        if resource_id:
                                            print(
                                                f"[STORED XSS DEBUG] resource_id discovered from list GET "
                                                f"{discovery_url}: {resource_id}"
                                            )
                                    verify_cross_account_stored_xss(
                                        post_path=path,
                                        post_url=api_url,
                                        resource_id=resource_id,
                                        payload=stored_payload,
                                        param_name=target_param,
                                        writer_account=scan_account,
                                        writer_role=best_role,
                                    )
    
                                    # 모든 GET 엔드포인트를 순회하며 치환 및 조회
                                    for idx_get, (get_path, get_methods) in enumerate(get_endpoint_items, start=1):
                                        if idx_get == 1 or idx_get % 20 == 0 or idx_get == len(get_endpoint_items):
                                            print(
                                                f"[STORED XSS DEBUG] broadcast verification progress "
                                                f"{idx_get}/{len(get_endpoint_items)} for {method.upper()} {api_url}"
                                            )
                                        if "get" not in get_methods:
                                            continue
                                        
                                        if resource_id and "{" in get_path:
                                            resolved_path = _re.sub(r"\{[^}]+\}", str(resource_id), get_path)
                                        elif "{" in get_path:
                                            print(
                                                f"[STORED XSS DEBUG] skip templated GET without resource_id: "
                                                f"{get_path}"
                                            )
                                            continue
                                        else:
                                            resolved_path = get_path

                                        get_url = f"{best_base.rstrip('/')}/{resolved_path.lstrip('/')}"
                                        get_params = build_query_defaults_from_details(get_methods.get("get") or {}, account_swagger_components)
                                        try:
                                            print(
                                                f"[STORED XSS DEBUG] broadcast GET {idx_get}/{len(get_endpoint_items)} "
                                                f"{get_url}"
                                            )
                                            get_res = _bounded_get(
                                                get_url,
                                                headers=xss_headers,
                                                params=get_params or None,
                                                timeout=4,
                                            )
                                            specific_baseline = get_baselines.get(get_path)
                                            
                                            if is_payload_reflected(stored_payload, get_res.text, specific_baseline):
                                                # [Strict Stored XSS Verification]
                                                # 1) 개별 조회 주소(GET /api/v1/posts/4)인 경우 -> 신뢰 가능
                                                # 2) 목록 조회 주소(GET /api/v1/posts)인 경우 -> 응답 본문 내에 방금 생성한 resource_id가 포함되어 있어야 하며,
                                                #    그 resource_id 근처(앞 100자 ~ 뒤 350자)에 stored_payload가 발견되는지 검증하여 타 API 영향에 따른 오탐 차단
                                                is_legit_stored_xss = False
                                                if resource_id:
                                                    str_res_id = str(resource_id)
                                                    if str_res_id in resolved_path:  # 개별 리소스 조회 경로 매칭 완료
                                                        is_legit_stored_xss = True
                                                    elif str_res_id in get_res.text: # 목록형 응답
                                                        idx = get_res.text.find(str_res_id)
                                                        start_clip = max(0, idx - 100)
                                                        end_clip = min(len(get_res.text), idx + 350)
                                                        context_area = get_res.text[start_clip:end_clip]
                                                        if stored_payload in context_area:
                                                            is_legit_stored_xss = True
                                                else:
                                                    # 만약 resource_id 획득이 실패한 API의 경우, POST 경로와 GET 경로의 연관성이 높을 때만 폴백 인정
                                                    if api_url.rstrip("/").split("/")[-1] in get_url:
                                                        is_legit_stored_xss = True

                                                if is_legit_stored_xss:
                                                    get_content_type = get_res.headers.get("Content-Type", "").lower()
                                                    print(f"[STORED XSS] !!! CONFIRMED on {get_url} (Stored payload '{stored_payload}' reflected) !!!")
                                                    
                                                    response_params = infer_reflected_response_params(get_res, stored_payload)
                                                    custom_alerts.append({
                                                        "alert": "Stored Cross-Site Scripting (Stored XSS) Vulnerability",
                                                        "url": get_url,
                                                        "method": "GET",
                                                        "risk": "High",
                                                        "confidence": "High",
                                                        "param": target_param,
                                                        "reflected_response_params": response_params,
                                                        "attack": stored_payload,
                                                        "status_code": get_res.status_code,
                                                        "evidence": f"{method.upper()} {api_url} 저장 후 GET {get_url} 재조회 응답에 페이로드 '{stored_payload}'가 반사됨",
                                                        "custom_type": "40014",
                                                        "evidence_request": format_http_request(get_res.request),
                                                        "evidence_response": format_http_response(get_res, stored_payload),
                                                        "expected_status_code": get_res.status_code,
                                                        "expected_evidence_in_response": stored_payload,
                                                        "screenshot_on": "page_loaded",
                                                        "description": (
                                                            f"{method.upper()} {api_url}로 저장된 입력값이 GET {get_url} 재조회 시 HTML 인코딩 없이 그대로 반사되었습니다. "
                                                            f"이는 Stored(Persistent) XSS로 다른 사용자에게도 스크립트가 실행될 수 있습니다. "
                                                            f"(GET 응답 Content-Type: {get_content_type})"
                                                        )
                                                    })
                                                    break # 이 페이로드로 취약성이 확인되면 GET 순회 중단
                                        except Exception as get_err:
                                            print(f"[STORED XSS DEBUG] Broadcast GET fail on {get_url}: {get_err}")
                                            continue
    
                                    # Cleanup: 생성한 테스트 리소스 즉시 삭제 시도
                                    if resource_id:
                                        try:
                                            delete_url = f"{api_url.rstrip('/')}/{resource_id}"
                                            print(f"[Safety] skip cleanup DELETE {delete_url}: DELETE requests are disabled")
                                        except Exception:
                                            pass
                                else:
                                    print(
                                        f"[STORED XSS DEBUG] store failed -> {method.upper()} {api_url} "
                                        f"status {post_res.status_code}. Response: {summarize_response_for_log(post_res)}"
                                    )
                                            
                            except Exception as se:
                                print(f"Stored XSS 2-step scan payload trial fail for {api_url}: {se}")

                    for _i in range(_alerts_snapshot, len(custom_alerts)):
                        custom_alerts[_i].setdefault("account_role", best_role)

        update_status(progress=90, message="결과 수집 및 리포트 생성 중...")
        
        raw_alerts = zap.core.alerts(baseurl=target_url, start=0, count=9999)
        
        # ZAP 원본 Alert 중 XSS 및 CSRF 관련 항목만 필터링 (기타 패시브 스캔 노이즈 제거)
        # 고도화 1-1: 단순 confidence가 "Low"라고 다 자르는 게 아니라, application/json + nosniff 조합인 경우(XSS 차단 성립)만 확정 오탐으로 간주하여 필터링함.
        allowed_plugin_ids = ["40012", "40014", "40016", "40017"]
        filtered_raw_alerts = []
        for a in raw_alerts:
            p_id = a.get("pluginId")
            if p_id in allowed_plugin_ids:
                if p_id in ["40012", "40014"] and a.get("confidence", "").lower() == "low":
                    # 상세 패킷 정보에서 실제 nosniff + json 여부 체크
                    msg_id = a.get("messageId")
                    is_safe_json_context = False
                    if msg_id:
                        try:
                            msg_detail = zap.core.message(msg_id)
                            res_header = msg_detail.get("responseHeader", "").lower()
                            if "application/json" in res_header and "nosniff" in res_header:
                                is_safe_json_context = True
                        except Exception:
                            pass
                    
                    if is_safe_json_context:
                        # 실행 불가 맥락이므로 오탐 차단
                        continue
                filtered_raw_alerts.append(a)
        
        # Merge manually verified 1-1 custom findings.
        all_raw_alerts = filtered_raw_alerts + custom_alerts
        
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # [중복 제거 및 그룹화 로직] 
        # - 일반 취약점: URL + Method + 취약점 종류(PluginId/CustomType)가 같으면 하나로 병합
        # - 보안 헤더 누락: 헤더 종류별로 1건만 대표 리포팅, 중복 URL 목록은 affected_urls에 누적
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        grouped_alerts = {}
        cors_reflection_types = {"CORS_ORIGIN_REFLECTION"}

        for a in all_raw_alerts:
            url = a.get("url", "")
            method = a.get("method", "GET")
            plugin_id = a.get("pluginId", "")
            custom_type = a.get("custom_type", "")
            account_role = a.get("account_role", "")
            key_id = custom_type if custom_type else plugin_id
            
            if not key_id:
                continue

            # 고도화 2-1: 전역 1건 묶기 규칙
            if key_id in cors_reflection_types:
                unique_key = "GLOBAL_CORS_ORIGIN_REFLECTION"
            elif custom_type == "40014" and a.get("cross_account_reader_role"):
                reader_role = a.get("cross_account_reader_role", "")
                param_name = a.get("param", "")
                unique_key = f"{account_role}_{reader_role}_{method}_{url}_{key_id}_{param_name}"
            else:
                param_name = a.get("param", "")
                unique_key = f"{account_role}_{method}_{url}_{key_id}_{param_name}"
                
            param_name = a.get("param", "")
            
            if unique_key not in grouped_alerts:
                grouped_alerts[unique_key] = a
                grouped_alerts[unique_key]["occurrence_count"] = 1
                grouped_alerts[unique_key]["affected_parameters"] = [param_name] if param_name else []
                grouped_alerts[unique_key]["account_roles"] = [account_role] if account_role else []
                if account_role:
                    grouped_alerts[unique_key]["account_role"] = account_role
                grouped_alerts[unique_key]["affected_urls"] = [f"{method} {url}"]
                grouped_alerts[unique_key]["evidence_request"] = a.get("evidence_request", "")
                grouped_alerts[unique_key]["evidence_response"] = a.get("evidence_response", "")
                init_payloads = a.get("successful_attack_payloads", [])
                if not init_payloads and a.get("attack"):
                    init_payloads = [a.get("attack")]
                grouped_alerts[unique_key]["successful_attack_payloads"] = list(init_payloads)
            else:
                grouped_alerts[unique_key]["occurrence_count"] += 1
                current_url = f"{method} {url}"
                if current_url not in grouped_alerts[unique_key]["affected_urls"]:
                    grouped_alerts[unique_key]["affected_urls"].append(current_url)
                    
                if param_name and param_name not in grouped_alerts[unique_key]["affected_parameters"]:
                    grouped_alerts[unique_key]["affected_parameters"].append(param_name)

                account_roles = grouped_alerts[unique_key].setdefault("account_roles", [])
                if account_role and account_role not in account_roles:
                    account_roles.append(account_role)
                    grouped_alerts[unique_key]["account_role"] = ", ".join(account_roles)
                    
                # 증거 패킷 업데이트 (대표값 확보)
                if not grouped_alerts[unique_key]["evidence_request"] and a.get("evidence_request"):
                    grouped_alerts[unique_key]["evidence_request"] = a.get("evidence_request")
                    grouped_alerts[unique_key]["evidence_response"] = a.get("evidence_response")
                    
                # 성공 페이로드 리스트 병합 (중복 제거)
                existing_payloads = grouped_alerts[unique_key].get("successful_attack_payloads", [])
                new_payloads = a.get("successful_attack_payloads", [])
                if not new_payloads and a.get("attack"):
                    new_payloads = [a.get("attack")]
                combined = list(set(existing_payloads + new_payloads))
                try:
                    grouped_alerts[unique_key]["successful_attack_payloads"] = sorted(combined, key=lambda p: XSS_PAYLOADS.index(p) if p in XSS_PAYLOADS else 999)
                except Exception:
                    grouped_alerts[unique_key]["successful_attack_payloads"] = combined

        print(f"[DEBUG] custom_alerts: {len(custom_alerts)}건")
        print(f"[DEBUG] filtered_raw_alerts: {len(filtered_raw_alerts)}건")
        print(f"[DEBUG] all_raw_alerts: {len(all_raw_alerts)}건")
        print(f"[DEBUG] grouped_alerts: {len(grouped_alerts)}건")
        for k, v in grouped_alerts.items():
            print(f"  - {k}: {v.get('alert','')[:50]}")
        final_alerts = list(grouped_alerts.values())

        re_mapped_alerts = []
        for alert in final_alerts:
            alert_name = alert.get("alert", "")
            writer_role = alert.get("cross_account_writer_role")
            reader_role = alert.get("cross_account_reader_role")
            if alert.get("custom_type") == "40014" and writer_role and reader_role:
                suffix = f" (작성: {writer_role}, 열람: {reader_role})"
                if suffix not in alert_name:
                    alert_name += suffix
                    
            param_name = alert.get("param", "")
            attack_val = alert.get("attack", "")
            description = alert.get("description", "")
            plugin_id = alert.get("pluginId", "")
            custom_type = alert.get("custom_type", "")
            key_id = custom_type if custom_type else plugin_id

            allowed_1_1_custom_types = {
                "40012",
                "40014",
                "STORED_XSS_CUSTOM",
                "DOM_XSS_CUSTOM",
                "DOM_XSS_SUSPECT",
                "CSRF_CUSTOM",
                "CORS_ORIGIN_REFLECTION",
            }
            if custom_type and custom_type not in allowed_1_1_custom_types:
                continue
            
            # ZAP 기본 Alert이고 messageId가 존재하는 경우, 실제 HTTP 패킷 조회
            evidence_req = alert.get("evidence_request", "")
            evidence_res = alert.get("evidence_response", "")
            msg_id = alert.get("messageId")
            
            status_code = alert.get("status_code", 0)
            if msg_id and not evidence_req and not evidence_res:
                try:
                    msg_detail = zap.core.message(msg_id)
                    if msg_detail:
                        req_header = msg_detail.get("requestHeader", "").strip()
                        req_body = msg_detail.get("requestBody", "").strip()
                        res_header = msg_detail.get("responseHeader", "").strip()
                        res_body = msg_detail.get("responseBody", "").strip()
                        
                        evidence_req = f"{req_header}\n\n{req_body}".strip()
                        evidence_res = f"{res_header}\n\n{res_body}".strip()
                        
                        # 응답 헤더로부터 상태 코드 추출 시도 (예: "HTTP/1.1 500")
                        try:
                            first_line = res_header.split("\r\n")[0] if res_header else ""
                            parts = first_line.split(" ")
                            if len(parts) > 1:
                                status_code = int(parts[1])
                        except Exception:
                            pass
                except Exception as me:
                    print(f"Failed to fetch HTTP message detail for alert (msg_id: {msg_id}): {me}")
            
            if not status_code and evidence_res:
                try:
                    first_line = evidence_res.split("\n")[0].strip()
                    parts = first_line.split(" ")
                    if len(parts) > 1:
                        status_code = int(parts[1])
                except Exception:
                    pass
                    
            ko_info = KOREAN_REMEDIATIONS.get(key_id, {})
            
            vuln_id, vuln_type, severity, vuln_desc = classify_alert(
                alert_name,
                param_name,
                attack_val,
                description,
                custom_type=custom_type or plugin_id,
            )
            
            # 만약 ZAP에서 내려온 기본 evidence가 비어있고 XSS 등 반사 유형이라면 응답 바디에서 공격 페이로드 전후 맥락을 찾아 증거로 설정
            alert_evidence = alert.get("evidence", "")
            if not alert_evidence and attack_val and attack_val in evidence_res:
                try:
                    idx = evidence_res.find(attack_val)
                    start_idx = max(0, idx - 80)
                    end_idx = min(len(evidence_res), idx + len(attack_val) + 80)
                    context_clip = evidence_res[start_idx:end_idx]
                    alert_evidence = f"... {context_clip.strip()} ..."
                except Exception:
                    pass
            
            # ── 정탐/오탐 자동 판별 분석 필드 추가 ──
            val_status = "True Positive"
            val_reason = "동작 검증 완료"

            k_type = custom_type or plugin_id
            if k_type == "40014" or k_type == "STORED_XSS_CUSTOM":
                val_status = "True Positive"
                val_reason = "POST 요청을 통한 데이터 저장 및 GET 재조회 응답에서의 영구 스크립트 유출 확인 (정탐). 단, 실제 브라우저 렌더링 시 프론트엔드(React/Vue 등)의 자동 이스케이프 설정에 따라 공격 성공 여부가 달라질 수 있으므로 프론트 연동 테스트를 통한 최종 확정이 필요합니다."
            elif k_type == "CSRF_CUSTOM":
                val_status = "True Positive"
                val_reason = "조작되거나 누락된 Referer/Token 조건에서 중요 상태 변경 API 호출이 수용됨 (정탐). 단, 실제 브라우저 환경의 SameSite 쿠키 정책 및 CORS/Origin 설정에 따라 공격 발화 여부가 달라질 수 있으므로 추가 확인이 필요합니다."
            elif k_type == "CORS_ORIGIN_REFLECTION":
                val_status = "True Positive"
                val_reason = "요청에 실어 보낸 임의의 공격용 Origin 헤더가 ACAO 응답 헤더에 그대로 반사되고 Credentials가 허용됨 (정탐)"
            elif k_type == "40012":
                res_ct = alert.get("Content-Type", "").lower() or ("json" if "application/json" in evidence_res.lower() else "")
                if "json" in res_ct or "application/json" in evidence_res.lower():
                    val_status = "Potential"
                    val_reason = "API 응답(JSON) 내에 페이로드 에코백 확인. React/Vue 등의 이스케이프 설정에 따라 실제 실행 가능성이 달라짐 (잠재적 취약)"
                else:
                    val_status = "True Positive"
                    val_reason = "HTML 본문 내에 인코딩 처리가 생략된 스크립트 문법이 그대로 반사되어 즉시 런타임 실행 가능함 (정탐)"
            elif k_type == "DOM_XSS_SUSPECT":
                val_status = "Suspected"
                val_reason = "정적 텍스트 분석 상 브라우저 입력 소스(Source) 및 취약 함수(Sink)의 동시 노출 확인. 동적 발화 검증 필요 (의심)"

            re_mapped_alerts.append({
                "vuln_id": vuln_id,
                "vuln_type": vuln_type,
                "severity": severity,
                "vuln_description": vuln_desc,
                "validation_status": val_status,
                "validation_reason": val_reason,
                "alert": alert_name,
                "url": alert.get("url", ""),
                "method": alert.get("method", "GET"),
                "risk": alert.get("risk", "Medium"),
                "confidence": alert.get("confidence", "Medium"),
                "param": param_name,
                "attack": attack_val,
                "status_code": status_code,
                "evidence": alert_evidence,
                "evidence_request": evidence_req,
                "evidence_response": evidence_res,
                "csrf_defenses": alert.get("csrf_defenses", {}),
                "description": description,
                "occurrence_count": alert.get("occurrence_count", 1),
                "account_role": alert.get("account_role", ""),
                "account_roles": alert.get("account_roles", []),
                "affected_parameters": alert.get("affected_parameters", []),
                "reflected_response_params": alert.get("reflected_response_params", []),
                "affected_urls": alert.get("affected_urls", []),
                "auth_acceptance_mode": alert.get("auth_acceptance_mode", ""),
                "auth_acceptance_statuses": alert.get("auth_acceptance_statuses", {}),
                "cookie_source": alert.get("cookie_source", ""),
                "cross_account_writer_role": alert.get("cross_account_writer_role", ""),
                "cross_account_reader_role": alert.get("cross_account_reader_role", ""),
                "cross_account_write_url": alert.get("cross_account_write_url", ""),
                "cross_account_read_url": alert.get("cross_account_read_url", ""),
                "remediation_summary": ko_info.get("summary", ""),
                "remediation_cause": ko_info.get("cause", "").replace("{param}", param_name),
                "remediation_guide": ko_info.get("action_guide", ""),
                "remediation_code": ko_info.get("code_example", "")
            })
            
        # [요구사항 반영] XSS 및 CSRF 관련 취약점만 리포팅하도록 필터링
        xss_csrf_alerts = []
        for a in re_mapped_alerts:
            v_type = a.get("vuln_type", "").lower()
            a_name = a.get("alert", "").lower()
            if "xss" in v_type or "csrf" in v_type or "xss" in a_name or "csrf" in a_name or "cross-site" in a_name:
                xss_csrf_alerts.append(a)
        
        re_mapped_alerts = xss_csrf_alerts

        update_status(total_alerts=len(re_mapped_alerts))
        
        role = "web_ui"
        result_dir = result_dir_override or "results"
        os.makedirs(result_dir, exist_ok=True)
        summary_filename = f"{result_dir}/zap_report_summary_{role}.json"
        
        with open(summary_filename, "w", encoding="utf-8") as f:
            json.dump(re_mapped_alerts, f, ensure_ascii=False, indent=4)
            
        # JSONC (주석이 포함된 상세 리포트) 추가 생성 로직
        filtered_jsonc_filename = f"{result_dir}/zap_report_summary_{role}_filtered.jsonc"
        try:
            # 유효한 경고 전체 수집 (False Positive 제외하고 Informational 등급도 정상 포함)
            meaningful_alerts = [a for a in re_mapped_alerts if a.get("severity") != "-" and a.get("risk") != "False Positive"]
            
            tp_count = sum(1 for a in meaningful_alerts if a.get("validation_status") == "True Positive")
            pot_count = sum(1 for a in meaningful_alerts if a.get("validation_status") == "Potential")
            susp_count = sum(1 for a in meaningful_alerts if a.get("validation_status") == "Suspected")
            fp_count = len(re_mapped_alerts) - len(meaningful_alerts)

            with open(filtered_jsonc_filename, "w", encoding="utf-8") as jf:
                jf.write("// =====================================================================\n")
                jf.write("// ZAP(OWASP) 및 커스텀 스캔 결과 리포트 - 상세 취약점 필터링본 (.jsonc)\n")
                jf.write(f"// [취약점 통계]\n")
                jf.write(f"//  - 총 발견 취약점: {len(meaningful_alerts)}개\n")
                jf.write(f"//  - 1. 정탐 확정 (True Positive): {tp_count}개\n")
                jf.write(f"//  - 2. 잠재적 취약 (Potential): {pot_count}개 (프론트엔드 방어 여부에 따라 유동적)\n")
                jf.write(f"//  - 3. 취약점 의심 (Suspected): {susp_count}개 (동적/추가 검증 권장)\n")
                jf.write(f"//  - 4. 오탐 필터링 (False Positive): {fp_count}개 차단 완료\n")
                jf.write("// =====================================================================\n")
                jf.write("[\n")
                
                for idx, a in enumerate(meaningful_alerts):
                    jf.write("    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
                    writer_role = a.get("cross_account_writer_role")
                    reader_role = a.get("cross_account_reader_role")
                    roles_str = f" (작성: {writer_role}, 열람: {reader_role})" if writer_role and reader_role else ""
                    jf.write(f"    // 【{idx + 1}번 항목】 공격 분류: {a.get('vuln_id')} - {a.get('vuln_type')}{roles_str} (위험 등급: {a.get('risk')})\n")
                    jf.write(f"    // 💡 위협 설명: {a.get('vuln_description')}\n")
                    
                    guide_lines = a.get("remediation_guide", "").split("\n")
                    if guide_lines and guide_lines[0]:
                        jf.write("    // 🛠️ 조치 가이드:\n")
                        for gl in guide_lines:
                            jf.write(f"    //    {gl}\n")
                            
                    jf.write("    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
                    
                    item_json = json.dumps(a, ensure_ascii=False, indent=12)
                    item_json_formatted = "    " + item_json.strip()
                    
                    jf.write(item_json_formatted)
                    if idx < len(meaningful_alerts) - 1:
                        jf.write(",\n")
                    else:
                        jf.write("\n")
                        
                jf.write("]\n")
            print(f"[+] JSONC report generated successfully at {filtered_jsonc_filename}")
        except Exception as je:
            print(f"[-] Fail to generate JSONC report: {je}")
            
        update_status(is_running=False, progress=100, message="스캔이 성공적으로 완료되었습니다.", result_file=summary_filename)
        print(f"[+] Scan completed. Report saved to {summary_filename}")
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        update_status(is_running=False, message=f"스캔 오류 발생: {str(e)}")

