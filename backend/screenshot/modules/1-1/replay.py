"""Live CSRF replay helpers.

The victim login is performed through the *browser context's* request API
(``BrowserContext.request``), not a standalone request context, so any
``Set-Cookie`` from the login response lands in the same cookie jar that
subsequent pages in that context (including the attacker lure page) will
carry — that shared jar is exactly what a CSRF exploit relies on.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import yaml

from credentials import ReplayCredential, saved_credentials_for_role
from request_text import extract_body, extract_content_type
from route_discovery import frontend_base_url


def _backend_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def _api_tree_paths() -> list[Path]:
    data_dir = _backend_root() / "data"
    return [
        data_dir / "api-tree-verified.json",
        data_dir / "api-tree-ready.json",
        data_dir / "api-tree.json",
    ]


def _runtime_url(url: str) -> str:
    override_base = os.getenv("ARGUS_SCREENSHOT_API_BASE", "").strip().rstrip("/")
    parts = urlsplit(str(url or ""))
    if override_base:
        override = urlsplit(override_base)
        return urlunsplit(
            (
                override.scheme or parts.scheme or "http",
                override.netloc or parts.netloc,
                parts.path,
                parts.query,
                parts.fragment,
            )
        )
    if not sys.platform.startswith("linux") and parts.hostname == "host.docker.internal":
        netloc = f"localhost:{parts.port}" if parts.port else "localhost"
        return urlunsplit((parts.scheme or "http", netloc, parts.path, parts.query, parts.fragment))
    return str(url or "")


def _auth_fields() -> tuple[str, str]:
    for name in ("config.docker.yaml", "config.yaml"):
        cfg = _read_yaml(_backend_root() / name)
        auth = cfg.get("auth") or {}
        id_field = str(auth.get("id_field") or "").strip()
        pw_field = str(auth.get("pw_field") or "").strip()
        if id_field and pw_field:
            return id_field, pw_field
    return "email", "password"


# Path substrings that mark an endpoint as a login/session-creation route.
# Matched as substrings so ``/api/v1/auth/login``, ``/signin``, ``/session``,
# etc. are all recognised without requiring any one app's exact wording — the
# previous ``"login" AND "auth"`` rule only matched apps that spell it exactly
# like ONDE's ``/auth/login``.
_LOGIN_PATH_TOKENS = ("login", "signin", "sign-in", "session", "authenticate")


def _login_candidates_from_api_tree(target_url: str, role: str | None) -> list[str]:
    normalized_role = str(role or "").strip().lower().replace("role_", "")
    target = urlsplit(_runtime_url(target_url))
    candidates: list[tuple[int, str]] = []

    for path in _api_tree_paths():
        if not path.exists():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        for endpoint in payload.get("endpoints") or []:
            if not isinstance(endpoint, dict):
                continue
            method = str(endpoint.get("method") or "").upper()
            raw_path = str(endpoint.get("path") or endpoint.get("url") or "").strip()
            if method and method != "POST":
                continue
            parsed_endpoint = urlsplit(raw_path)
            endpoint_path = parsed_endpoint.path if parsed_endpoint.scheme else raw_path
            endpoint_path = endpoint_path if endpoint_path.startswith("/") else f"/{endpoint_path}"
            if not any(token in endpoint_path.lower() for token in _LOGIN_PATH_TOKENS):
                continue

            base = str(endpoint.get("base_url") or "").strip()
            if parsed_endpoint.scheme and parsed_endpoint.netloc:
                url = raw_path
            else:
                endpoint_base = urlsplit(_runtime_url(base)) if base else target
                url = urlunsplit(
                    (
                        endpoint_base.scheme or target.scheme or "http",
                        endpoint_base.netloc or target.netloc,
                        endpoint_path,
                        "",
                        "",
                    )
                )

            score = 10
            lowered = endpoint_path.lower()
            if normalized_role and normalized_role in lowered:
                score += 30
            if normalized_role == "admin" and "admin" not in lowered:
                score -= 20
            if normalized_role != "admin" and "admin" in lowered:
                score -= 10
            if urlsplit(_runtime_url(url)).netloc == target.netloc:
                score += 5
            candidates.append((score, _runtime_url(url)))

    seen: set[str] = set()
    ordered: list[str] = []
    for _, url in sorted(candidates, key=lambda item: item[0], reverse=True):
        if url not in seen:
            ordered.append(url)
            seen.add(url)
    return ordered


def _login_url(target_url: str, role: str | None) -> str:
    discovered = _login_candidates_from_api_tree(target_url, role)
    if discovered:
        return discovered[0]

    parts = urlsplit(_runtime_url(target_url))
    normalized = str(role or "").strip().lower().replace("role_", "")
    path = "/api/v1/auth/admin/login" if normalized == "admin" else "/api/v1/auth/login"
    return urlunsplit((parts.scheme or "http", parts.netloc, path, "", ""))


def login_victim(context_request: Any, target_url: str, account_role: str | None) -> dict[str, Any]:
    """Log in with saved frontend test accounts until one succeeds."""
    credentials = saved_credentials_for_role(account_role)
    if not credentials:
        return {
            "role": str(account_role or ""),
            "email": "",
            "status": None,
            "ok": False,
            "error": "no saved test accounts found",
        }

    url = _login_url(target_url, account_role)
    id_field, pw_field = _auth_fields()
    attempts: list[dict[str, Any]] = []
    for credential in credentials:
        try:
            response = context_request.post(
                url,
                data={id_field: credential.email, pw_field: credential.password},
                timeout=15_000,
            )
            attempts.append({"email": credential.email, "status": response.status, "ok": response.ok})
            if response.ok:
                return {
                    "role": str(account_role or credential.role),
                    "email": credential.email,
                    "status": response.status,
                    "ok": True,
                    "attempts": attempts,
                }
        except Exception as exc:
            attempts.append({"email": credential.email, "ok": False, "error": str(exc)})

    return {
        "role": str(account_role or ""),
        "email": "",
        "status": attempts[-1].get("status") if attempts else None,
        "ok": False,
        "attempts": attempts,
    }


def _log(message: str) -> None:
    print(f"[ui-login] {message}", flush=True)


def _path_of_url(url: str) -> str:
    return urlsplit(str(url or "")).path or "/"


_UI_LOGIN_DEFAULTS: dict[str, Any] = {
    "trigger_words": ["로그인", "login", "sign in", "log in"],
    "container_selector": '[class*="modal" i], [role="dialog"]',
    "email_selector": 'input[type="email"], input[name*="email" i], input[autocomplete="username"], input[type="text"]',
    "password_selector": 'input[type="password"]',
    # role keyword -> the page the app lands that role on after login; empty
    # unless configured (screenshot.ui_login.role_landing_paths), since where a
    # role lands is a per-site convention
    "role_landing_paths": {},
    "error_paths": ["/401", "/403"],
    "api_path_marker": "/api/",
}


def _ui_login_config() -> dict[str, Any]:
    """UI-login assumptions (login trigger text, form selectors, per-role
    landing pages, error routes) are target-app conventions, so they can be
    overridden under ``screenshot.ui_login`` in config.yaml; anything not set
    keeps the default above."""
    merged = dict(_UI_LOGIN_DEFAULTS)
    for name in ("config.docker.yaml", "config.yaml"):
        override = ((_read_yaml(_backend_root() / name).get("screenshot") or {}).get("ui_login")) or {}
        if override:
            merged.update({key: value for key, value in override.items() if value})
            break
    return merged


def _find_login_form(page, cfg: dict[str, Any]):
    """Locate the visible login form and return ``(email_input, password_input)``.

    Login UIs are either a modal/dialog opened by a trigger or a page of their
    own (``/login``), so try the modal first and then the whole page. The email
    input is looked up inside the password field's own ``<form>`` — a header
    search box on the same page must not be mistaken for it."""
    for container in (cfg["container_selector"], None):
        scope = page.locator(container).last if container else page
        password_input = scope.locator(cfg["password_selector"]).first
        try:
            if not password_input.is_visible(timeout=1_500):
                continue
        except Exception:
            continue
        form = password_input.locator("xpath=ancestor::form[1]")
        try:
            form_scope = form if form.count() else scope
        except Exception:
            form_scope = scope
        return form_scope.locator(cfg["email_selector"]).first, password_input
    return None, None


def _normalize_wanted_role(role: str | None) -> str:
    return str(role or "").strip().lower().replace("role_", "")


def _role_matches_landing(wanted: str, landed_path: str, cfg: dict[str, Any] | None = None) -> bool:
    """The app itself redirects to a role-specific default page right after
    login — use that as the ground truth for "is this the right account",
    since the saved test accounts have no role field to read directly.
    ``wanted`` is a finding's ``account_role`` (USER / SELLER / SUPER_ADMIN /
    ...), matched by category via the configured ``role_landing_paths`` (any
    role not listed is treated as a normal user who must NOT land on one of
    those role-specific pages)."""
    cfg = cfg or _ui_login_config()
    if landed_path in cfg["error_paths"]:
        return False
    landing_paths = cfg["role_landing_paths"]
    for role_key, landing in landing_paths.items():
        if role_key in wanted:
            return landed_path.startswith(landing)
    return not any(landed_path.startswith(landing) for landing in landing_paths.values())


def login_via_ui(page, account_role: str | None, victim_email: str | None = None) -> dict[str, Any]:
    """Log in through the real browser UI — click a login trigger, fill the
    email/password inputs, submit — instead of a raw API POST.

    Some SPAs only persist the parts of the session their *own* route
    guards actually check (a client-side auth store, extra non-HttpOnly
    cookies the app writes itself) as a side effect of the real login form
    submitting. An API-level POST can return 200 and still leave every
    protected route looking logged-out, because the app's own login
    handler — the thing that actually flips the "logged in" state — never
    ran. Driving the real form sidesteps needing to know any of that.

    The saved test accounts have no role tag, so which one is "the seller
    account" isn't known ahead of time either — try each until the app's
    own post-login redirect lands somewhere consistent with the role this
    finding needs (see ``_role_matches_landing``), clearing cookies between
    attempts so a rejected try doesn't leak into the next one.
    """
    credentials = saved_credentials_for_role(account_role)
    if not credentials:
        return {"ok": False, "reason": "no saved test accounts found"}

    cfg = _ui_login_config()
    wanted = _normalize_wanted_role(account_role)
    victim = str(victim_email or "").strip().lower()
    # If the finding's own evidence names the exact victim account (a
    # "my-profile" stored XSS records the owning user's email), log in as
    # *that* account first — the payload only renders on that specific user's
    # page, so the right role isn't enough, it has to be the right user.
    if victim:
        credentials = sorted(credentials, key=lambda c: c.email.strip().lower() != victim)
    base = frontend_base_url()
    attempts: list[dict[str, Any]] = []

    # The app's own axios interceptor hard-redirects the whole page
    # (window.location.assign) to /401 or /403 on *any* API error response,
    # completely independent of the role-guard check on the destination
    # route. That means a landing on /403 doesn't necessarily mean "wrong
    # role" — it can just as easily mean some unrelated request (e.g. the
    # post-login profile fetch) got rejected. Track failing API responses
    # per attempt so that distinction is visible in the logs instead of
    # guessed at.
    api_errors: list[dict[str, Any]] = []

    def _on_response(response: Any) -> None:
        try:
            if response.status >= 400 and cfg["api_path_marker"] in response.url:
                api_errors.append({"url": response.url, "status": response.status})
                _log(f"api error during login: {response.status} {response.url}")
        except Exception:
            pass

    page.on("response", _on_response)

    try:
        for credential in credentials:
            api_errors.clear()
            try:
                page.context.clear_cookies()
            except Exception:
                pass
            try:
                page.goto(f"{base}/", wait_until="domcontentloaded", timeout=15_000)
                page.wait_for_timeout(800)
            except Exception as exc:
                attempts.append({"email": credential.email, "ok": False, "reason": f"navigation failed: {exc}"})
                continue

            trigger = None
            for word in cfg["trigger_words"]:
                candidate = page.get_by_text(word, exact=False)
                try:
                    if candidate.count():
                        trigger = candidate.first
                        break
                except Exception:
                    continue
            if trigger is None:
                # no trigger on the landing page: the login may be its own route
                try:
                    page.goto(f"{base}/login", wait_until="domcontentloaded", timeout=15_000)
                    page.wait_for_timeout(800)
                except Exception:
                    pass

            try:
                if trigger is not None:
                    trigger.click(timeout=3000)
                    page.wait_for_timeout(800)
                # Scope to the just-opened modal/dialog, not the whole page —
                # the page underneath can have its own unrelated
                # type="email"/type="submit" elements (e.g. a search form), and
                # picking the first DOM match rather than the one actually
                # inside the modal clicks the wrong thing (previously: a
                # search button behind the modal backdrop, timing out instead
                # of submitting the login form).
                email_input, password_input = _find_login_form(page, cfg)
                if email_input is None:
                    attempts.append({"email": credential.email, "ok": False, "reason": "no login form found"})
                    continue
                email_input.fill(credential.email, timeout=3000)
                password_input.fill(credential.password, timeout=3000)
                # Press Enter in the password field to submit the <form>
                # natively, instead of hunting for "the" submit button —
                # sidesteps the same ambiguity for the submit control.
                password_input.press("Enter", timeout=3000)
                page.wait_for_timeout(1_500)
            except Exception as exc:
                attempts.append({"email": credential.email, "ok": False, "reason": f"form interaction failed: {exc}"})
                continue

            still_on_login_form = False
            try:
                still_on_login_form = page.locator(cfg["password_selector"]).first.is_visible(timeout=500)
            except Exception:
                pass
            # "Password field is gone" is not proof of a successful login —
            # some apps hard-redirect the *whole page* to an error route on
            # any failed API call (including the login call itself), which
            # also makes the password field disappear. Cross-check against
            # the actual login request's own response status, which is
            # unambiguous either way.
            login_error = next(
                (err for err in api_errors if "login" in _path_of_url(err["url"]).lower()),
                None,
            )
            landed_on = page.url
            landed_path = urlsplit(landed_on).path or "/"
            result = {
                "email": credential.email,
                "role": credential.role,
                "ok": not still_on_login_form and login_error is None,
                "landed_on": landed_on,
                "api_errors": list(api_errors),
            }
            attempts.append(result)
            if login_error is not None:
                _log(
                    f"{credential.email}: login request itself failed "
                    f"({login_error['status']} {login_error['url']}) — treating as a "
                    f"failed login, not a role mismatch"
                )
            elif landed_path in cfg["error_paths"] and api_errors:
                _log(
                    f"{credential.email} landed on {landed_path} — likely caused by "
                    f"a *different* API error, not the login itself: {api_errors}"
                )
            # An exact victim-email match is the strongest signal — accept it
            # without also requiring the role-landing heuristic (the specific
            # user is exactly who we need, whatever page they land on).
            if result["ok"] and victim and credential.email.strip().lower() == victim:
                result["role_matched"] = True
                result["matched_by"] = "email"
                result["attempts"] = len(attempts)
                _log(f"logged in as victim {credential.email} (exact email match)")
                return result
            if result["ok"] and not victim and _role_matches_landing(wanted, landed_path, cfg):
                result["role_matched"] = True
                result["matched_by"] = "role"
                result["attempts"] = len(attempts)
                return result

        # No account's landing page matched the requested role — return the
        # last attempt so the caller still has *some* session to work with,
        # flagged so callers/manifests can tell it wasn't a confirmed match.
        last = dict(attempts[-1]) if attempts else {"ok": False, "reason": "no accounts tried"}
        last["role_matched"] = False
        last["attempts"] = len(attempts)
        return last
    finally:
        try:
            page.remove_listener("response", _on_response)
        except Exception:
            pass


def forged_request(case_url: str, case_method: str, request_text: str) -> dict[str, str]:
    """Recover the (url, method, body, content_type) to replay, reconstructing
    the body from the scanner's recorded evidence text."""
    return {
        "url": _runtime_url(case_url),
        "method": (case_method or "POST").upper(),
        "body": extract_body(request_text),
        "content_type": extract_content_type(request_text),
    }
