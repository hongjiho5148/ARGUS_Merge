"""request helpers helpers split out of zap_runner.py (code moved verbatim)."""

import base64
import hashlib
import importlib.util
import json
import os
import re
import sys
import urllib.parse


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

normalized_field_name = _sibling("schema_payloads").normalized_field_name


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
