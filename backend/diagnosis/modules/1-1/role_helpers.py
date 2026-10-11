"""role helpers helpers split out of zap_runner.py (code moved verbatim)."""

import importlib.util
import os
import re
import sys


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

is_payload_reflected = _sibling("xss_judgement").is_payload_reflected


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
