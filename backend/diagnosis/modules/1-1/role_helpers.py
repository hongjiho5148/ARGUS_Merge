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


# Privilege tiers, most privileged first. The words are matched against an
# account's role / token claims and against path segments, so they only need to
# name the roles a target uses; override them with ``diagnosis_1_1.role_tiers``
# in config for a site whose role vocabulary differs.
DEFAULT_ROLE_TIERS: tuple[tuple[str, ...], ...] = (
    ("admin", "administrator", "superuser", "super_admin", "root", "staff", "operator"),
    ("seller", "vendor", "merchant", "partner"),
)
_ORDINARY_ROLE_WORDS = ("user", "member", "customer", "client", "account")
_role_tiers: tuple[tuple[str, ...], ...] = DEFAULT_ROLE_TIERS


def configure_role_tiers(tiers) -> None:
    """Set the privilege tiers (list of word lists, most privileged first);
    ``None`` restores the defaults."""
    global _role_tiers
    cleaned = tuple(
        tuple(str(word).strip().lower() for word in tier if str(word).strip())
        for tier in (tiers or [])
        if tier
    )
    _role_tiers = cleaned or DEFAULT_ROLE_TIERS


def _tier_words(index: int) -> tuple[str, ...]:
    return _role_tiers[index] if index < len(_role_tiers) else ()


def _segment_regex(words: tuple[str, ...]):
    if not words:
        return None
    alternatives = "|".join(re.escape(word) for word in words)
    return re.compile(rf"(^|/)({alternatives})(s)?(/|$)")


def account_role_rank(account: dict | None) -> int:
    role_text = str((account or {}).get("role", "")).lower()
    claims_text = str((account or {}).get("claims", {}) or {}).lower()
    joined = f"{role_text} {claims_text}"
    for rank, words in enumerate(_role_tiers):
        if any(word in joined for word in words):
            return rank
    if any(word in joined for word in _ORDINARY_ROLE_WORDS):
        return len(_role_tiers)
    return len(_role_tiers) + 1


def is_admin_account(account: dict) -> bool:
    """True for the top privilege tier (platform administrators)."""
    role_text = str(account.get("role", "")).lower()
    base_url_text = str(account.get("base_url", "")).lower()
    claims_text = str(account.get("claims", {}) or {}).lower()
    words = _tier_words(0)
    return bool(account.get("token")) and any(
        word in role_text or word in claims_text or word in base_url_text for word in words
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
    """Order endpoints so a privileged account tests the paths of its own tier
    first and an ordinary account tests tier-specific paths last."""
    lowered = str(path_value or "").lower()
    role_text = account_role_text(account)
    tiers = [
        (_segment_regex(words), any(word in role_text for word in words))
        for words in _role_tiers
    ]
    for pattern, account_has_tier in tiers:
        if pattern and account_has_tier and pattern.search(lowered):
            return (0, lowered)
    for pattern, account_has_tier in tiers:
        if pattern and not account_has_tier and pattern.search(lowered):
            return (3, lowered)
    return (1, lowered)


def resource_tokens_from_path(path_value: str) -> set[str]:
    role_words = {word for tier in _role_tiers for word in tier}
    ignored = {
        "api", "v1", "v2", "me", "auth", "login", "logout", "search", "check",
        *role_words, *(f"{word}s" for word in role_words),
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
