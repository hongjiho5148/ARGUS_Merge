"""schema payloads helpers split out of zap_runner.py (code moved verbatim)."""

from datetime import date
from datetime import datetime
from datetime import timedelta
from datetime import timezone
import hashlib
import importlib.util
import os
import re
import requests
import sys
import time


def _sibling(name):
    key = f"diag_g11_split_{name}"
    module = sys.modules.get(key)
    if module is None:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"{name}.py")
        spec = importlib.util.spec_from_file_location(key, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[key] = module
        spec.loader.exec_module(module)
    return module

XSS_PAYLOADS = _sibling("payloads").XSS_PAYLOADS

_LOGIN_CRITICAL_TOKENS = ("password", "passwd", "pwd", "email", "loginid", "username")


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
