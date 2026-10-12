import json
from pathlib import Path
from typing import Any

NOISE_KEYS = {"timestamp", "traceId", "trace_id", "requestId", "request_id", "serverTime", "time", "createdAt", "updatedAt"}

def _read_api_tree(data_dir: Path) -> dict[str, Any] | None:
    for name in ["api-tree-verified.json", "api-tree-ready.json", "api-tree.json"]:
        path = data_dir / name
        if path.is_file():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception as e:
                print(f"    [Error] Exception reading {name}: {e}")
    return None

def _extract_recursive(data: Any, result: dict[str, list[Any]]):
    if isinstance(data, dict):
        for k, v in data.items():
            k_lower = k.lower()
            if "id" in k_lower and isinstance(v, (int, str)) and v:
                result.setdefault(k, []).append(v)
            _extract_recursive(v, result)
    elif isinstance(data, list):
        for item in data:
            _extract_recursive(item, result)

def extract_ids_from_response(data: Any) -> dict[str, list[Any]]:
    result = {}
    _extract_recursive(data, result)
    for k in result:
        result[k] = list(set(result[k]))
    return result

def json_field_matches(data: Any, key: str, expected: str) -> bool:
    if isinstance(data, dict):
        for k, v in data.items():
            if k.lower() == key.lower() and str(v) == expected:
                return True
            if json_field_matches(v, key, expected):
                return True
    elif isinstance(data, list):
        for item in data:
            if json_field_matches(item, key, expected):
                return True
    return False



_LOGIN_FORM_MARKERS = ('type="password"', "type='password'", "type=password")
_SPA_SHELL_MARKERS = ('id="root"', "id='root'", 'id="app"', "id='app'", 'id="__next"')


def judge_vertical_access(
    status_code: int,
    body: str,
    content_type: str = "",
    denial_keywords: list[str] | None = None,
) -> tuple[bool, str]:
    """Did a non-admin session really reach an admin-only resource?

    Returns (vulnerable, reason). Redirects must be disabled by the caller so a
    3xx (typically "go to the login page") is read as access denied instead of
    being followed into a 200 login page.
    """
    if status_code not in {200, 201, 204}:
        return False, f"status {status_code} (denied or redirected)"
    lowered = (body or "").lower()
    if any(str(k).lower() in lowered for k in (denial_keywords or [])):
        return False, "response carries a denial message"
    if "html" in (content_type or "").lower():
        if any(marker in lowered for marker in _LOGIN_FORM_MARKERS):
            return False, "response is a login form"
        if any(marker in lowered for marker in _SPA_SHELL_MARKERS):
            return False, "response is a front-end page shell, not endpoint data"
    return True, "admin-only endpoint answered a non-admin session"
