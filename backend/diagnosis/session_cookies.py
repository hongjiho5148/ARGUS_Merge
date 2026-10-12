"""Cookies and their attributes for a login session, read from what the login returned.

A session built by ``resolve_account_auths`` carries the raw ``Set-Cookie`` lines
(``set_cookie_lines``) and, for cookie-delivered tokens, the cookie name and token,
but not always a ready-made ``cookies`` dict. Modules that need the cookies (CSRF
assessment, cookie-mode request replay) derive them here, from the login response
itself rather than from a guessed cookie name.
"""

from __future__ import annotations

from typing import Any


def parse_set_cookie(line: str) -> tuple[str, str, dict[str, Any]] | None:
    """``name=value; Path=/; Secure; SameSite=None`` -> (name, value, attributes)."""
    parts = [part.strip() for part in str(line or "").split(";") if part.strip()]
    if not parts or "=" not in parts[0]:
        return None
    name, value = parts[0].split("=", 1)
    attrs: dict[str, Any] = {}
    for part in parts[1:]:
        key, _, raw = part.partition("=")
        key = key.strip().lower()
        if key in ("secure", "httponly"):
            attrs[key] = True
        elif key in ("samesite", "path", "domain", "max-age", "expires"):
            attrs[key.replace("-", "_")] = raw.strip()
    return name.strip(), value, attrs


def cookies_from_session(session: dict[str, Any] | None) -> tuple[dict[str, str], dict[str, dict[str, Any]]]:
    """Return ``(cookies, cookie_attrs)`` for a session.

    Order of preference: an explicit ``cookies`` dict, the ``Set-Cookie`` lines of
    the login response, and finally the session token under the cookie name the
    login reported when the token is delivered as a cookie."""
    session = session or {}
    cookies: dict[str, str] = {}
    attrs: dict[str, dict[str, Any]] = {}

    explicit = session.get("cookies")
    if isinstance(explicit, dict):
        cookies.update({str(k): str(v) for k, v in explicit.items() if k and v is not None})
    explicit_attrs = session.get("cookie_attrs")
    if isinstance(explicit_attrs, dict):
        attrs.update({str(k): dict(v) for k, v in explicit_attrs.items() if isinstance(v, dict)})

    lines = session.get("set_cookie_lines") or session.get("set_cookie_headers") or []
    if isinstance(lines, str):
        lines = [lines]
    for line in lines:
        parsed = parse_set_cookie(line)
        if not parsed:
            continue
        name, value, cookie_attrs = parsed
        if value == "" or cookie_attrs.get("max_age") == "0":
            continue  # a cookie the server is clearing, not setting
        cookies.setdefault(name, value)
        attrs.setdefault(name, cookie_attrs)

    if not cookies and str(session.get("delivery") or "").lower() == "cookie":
        name = str(session.get("cookie_name") or "").strip()
        token = str(session.get("token") or session.get("access_token") or "").replace("Bearer ", "").strip()
        if name and token:
            cookies[name] = token
    return cookies, attrs
