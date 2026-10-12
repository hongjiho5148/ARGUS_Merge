"""Shared safety policy: endpoints ARGUS must never call with a live request.

Verify, Discover and the scanning modules all send real traffic to the target.
Anything that can destroy data, end a session, change credentials or move an
approval/payment state is judged here once, instead of each caller keeping its
own (diverging) list.
"""

from __future__ import annotations

from typing import Any

DESTRUCTIVE_METHODS = frozenset({"DELETE"})

# Path segments that mark a state-changing or credential-affecting operation.
# Matched against whole path segments ("ban" matches /users/ban but not /banners).
UNSAFE_PATH_MARKERS = (
    "reset-password", "reset_password", "resetpassword", "forgot-password", "find-password",
    "change-password", "password-change", "update-password", "change_password",
    "withdraw", "withdrawal", "unregister", "deactivate", "delete-account", "leave",
    "logout", "signout", "sign-out",
    "delete", "remove", "destroy", "purge", "restore",
    "approve", "reject", "ban", "unban", "suspend", "block", "unblock",
    "close", "reopen", "cancel", "refund", "payment", "pay", "checkout", "settle", "finalize",
    "transfer", "trigger",
)

# Words in OpenAPI summary/description (when available) that mark the same thing.
UNSAFE_META_KEYWORDS = (
    "withdraw", "탈퇴", "password-change", "change-password", "비밀번호 변경", "비밀번호변경",
    "reset password", "비밀번호 재설정", "logout", "로그아웃", "delete-account", "계정삭제", "계정 삭제",
)

_PASSWORD_FIELDS = ("newpassword", "currentpassword", "confirmpassword", "oldpassword", "password")


def _normalize(path: str) -> str:
    return "/" + str(path or "").lower().split("?", 1)[0].lstrip("/")


def _has_marker(path: str, markers: tuple[str, ...]) -> str | None:
    segments = [seg for seg in path.split("/") if seg]
    for marker in markers:
        token = marker.strip("/")
        if not token:
            continue
        if "/" in token:
            if token in path:
                return marker
            continue
        for seg in segments:
            if seg == token or seg.startswith(token + "-") or seg.startswith(token + "_"):
                return marker
    return None


def is_dangerous_endpoint(
    method: str,
    path: str,
    details: dict[str, Any] | None = None,
    *,
    extra_markers: tuple[str, ...] = (),
    password_only_body: bool = False,
) -> tuple[bool, str]:
    """Return (blocked, reason). GET/HEAD/OPTIONS are never blocked by path alone."""
    method_upper = (method or "").upper()
    normalized = _normalize(path)
    details = details or {}

    if method_upper in DESTRUCTIVE_METHODS:
        return True, f"{method_upper} requests are never sent (data/session integrity)"

    if method_upper in {"GET", "HEAD", "OPTIONS"}:
        marker = _has_marker(normalized, tuple(m.lower() for m in extra_markers))
        return (True, f"matches configured skip marker '{marker}'") if marker else (False, "")

    marker = _has_marker(normalized, UNSAFE_PATH_MARKERS + tuple(m.lower() for m in extra_markers))
    if marker:
        return True, f"state-changing endpoint (path contains '{marker}')"

    meta = f"{details.get('summary') or ''} {details.get('description') or ''}".lower()
    keyword = next((k for k in UNSAFE_META_KEYWORDS if k in meta), None)
    if keyword:
        return True, f"API metadata matches safety word '{keyword}'"

    if password_only_body:
        return True, "request body only carries credential fields"

    return False, ""


def properties_are_password_only(property_names: list[str]) -> bool:
    """True when a body has credential fields and nothing else (a dedicated password-change API)."""
    has_password = False
    has_other = False
    for name in property_names:
        if any(token in str(name).lower() for token in _PASSWORD_FIELDS):
            has_password = True
        else:
            has_other = True
    return has_password and not has_other
