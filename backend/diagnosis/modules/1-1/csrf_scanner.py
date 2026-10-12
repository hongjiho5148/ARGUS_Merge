"""CSRF assessment for ARGUS 1-1.

CSRF only exists when the browser attaches credentials on its own (cookies).
A header-token API (Authorization: Bearer ...) cannot be driven cross-site, so
the assessment checks that precondition first and only then sends requests:

    1. ambient (cookie-only) authentication?       -> else NOT_APPLICABLE
    2. SameSite protection on the session cookie?  -> Lax/Strict => DEFENDED
    3. endpoint too dangerous to call for real?    -> CANDIDATE (not verified)
    4. normal cookie-only request succeeds?        -> else INCONCLUSIVE
    5. forged-Origin simple request vs. a normal one -> accepted => CONFIRMED, rejected => DEFENDED
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlencode

import requests

CONFIRMED = "confirmed"
CANDIDATE = "candidate"
DEFENDED = "defended"
NOT_APPLICABLE = "not_applicable"
INCONCLUSIVE = "inconclusive"

FORGED_ORIGIN = "http://evil-attacker.local"
FORGED_REFERER = "http://evil-attacker.local/exploit.html"


@dataclass
class CsrfVerdict:
    status: str
    reason: str
    failed_count: int = 0
    details: dict = field(default_factory=dict)


def _is_success(status_code: int) -> bool:
    return 200 <= status_code < 300


def cookie_header(cookies: dict | None) -> str:
    return "; ".join(f"{name}={value}" for name, value in (cookies or {}).items() if name and value is not None)


def detect_ambient_cookie_auth(
    cookies: dict | None,
    probe_urls: list[str],
    *,
    request_fn=requests.request,
    timeout: float = 4.0,
) -> tuple[bool | None, str]:
    """Does a protected GET succeed with the session cookies alone?

    True  -> browser-attached cookies authenticate the user (CSRF is possible)
    False -> cookies alone do not authenticate (header-token API)
    None  -> could not tell
    """
    header = cookie_header(cookies)
    if not header:
        return False, "login issued no session cookie"
    for url in probe_urls[:4]:
        try:
            anonymous = request_fn(method="GET", url=url, timeout=timeout, allow_redirects=False)
            with_cookies = request_fn(
                method="GET", url=url, headers={"Cookie": header}, timeout=timeout, allow_redirects=False
            )
        except requests.RequestException:
            continue
        if anonymous.status_code not in (401, 403):
            continue
        if _is_success(with_cookies.status_code):
            return True, f"GET {url}: anonymous {anonymous.status_code} -> cookies only {with_cookies.status_code}"
        if with_cookies.status_code in (401, 403):
            return False, f"GET {url}: cookies alone are rejected ({with_cookies.status_code})"
    return None, "no protected GET endpoint could confirm cookie-only authentication"


def samesite_is_weak(account: dict | None, response_set_cookie: str = "") -> bool:
    attrs = (account or {}).get("cookie_attrs") or {}
    if isinstance(attrs, dict) and attrs:
        for meta in attrs.values():
            samesite = str(meta.get("samesite") or "").lower() if isinstance(meta, dict) else ""
            if samesite not in ("lax", "strict"):
                return True
        return False
    lowered = (response_set_cookie or "").lower()
    return not ("samesite=lax" in lowered or "samesite=strict" in lowered)


def _simple_request_kwargs(body_json: dict, content_style: str) -> dict:
    """Body encoded the way a cross-site <form> / text/plain fetch can send it (no CORS preflight)."""
    if content_style == "form":
        flat = {k: v for k, v in (body_json or {}).items() if isinstance(v, (str, int, float, bool))}
        return {"data": urlencode(flat), "content_type": "application/x-www-form-urlencoded"}
    import json

    return {"data": json.dumps(body_json or {}), "content_type": "text/plain"}


def assess_csrf(
    *,
    method: str,
    api_url: str,
    body_json: dict,
    cookies: dict | None,
    ambient_auth: bool | None,
    samesite_weak: bool,
    dangerous: bool = False,
    request_fn=requests.request,
    timeout: float = 4.0,
) -> tuple[CsrfVerdict, dict]:
    """Return (verdict, evidence) where evidence holds the requests used as proof."""
    evidence: dict = {}
    if ambient_auth is False:
        return CsrfVerdict(NOT_APPLICABLE, "session is not carried by browser cookies (header-token API)"), evidence
    if ambient_auth is None:
        return CsrfVerdict(INCONCLUSIVE, "could not determine whether cookies alone authenticate"), evidence
    if not samesite_weak:
        return CsrfVerdict(DEFENDED, "session cookie is SameSite=Lax/Strict"), evidence
    if dangerous:
        return (
            CsrfVerdict(
                CANDIDATE,
                "cookie-authenticated and SameSite is not enforced, but the endpoint is state-destructive "
                "so no live request was sent - verify manually",
                failed_count=2,
                details={
                    "origin_referer_bypass": None,
                    "csrf_token_absent": None,
                    "unsafe_samesite": True,
                    "has_cookie_session": True,
                },
            ),
            evidence,
        )

    header = cookie_header(cookies)
    method_upper = method.upper()

    def send(extra_headers: dict, style: str) -> requests.Response:
        spec = _simple_request_kwargs(body_json, style)
        headers = {"Cookie": header, "Content-Type": spec["content_type"], **extra_headers}
        return request_fn(
            method=method_upper, url=api_url, data=spec["data"], headers=headers, timeout=timeout, allow_redirects=False
        )

    results: dict[str, int] = {}
    baseline_ok = False
    accepted = False
    for style in ("form", "text"):
        try:
            baseline = send({}, style)
        except requests.RequestException:
            continue
        results[f"baseline:{style}"] = baseline.status_code
        if not _is_success(baseline.status_code):
            continue
        baseline_ok = True
        try:
            forged = send({"Origin": FORGED_ORIGIN, "Referer": FORGED_REFERER}, style)
        except requests.RequestException:
            continue
        results[f"forged_origin:{style}"] = forged.status_code
        if _is_success(forged.status_code):
            accepted = True
            evidence["accepted_request"] = {"label": "forged_origin", "style": style, "response": forged}
            break

    if not baseline_ok:
        return (
            CsrfVerdict(
                INCONCLUSIVE,
                "the normal cookie-only request was not accepted, so a forged one cannot be judged",
                details={"cross_site_results": results},
            ),
            evidence,
        )
    details = {
        "cross_site_results": results,
        "origin_referer_bypass": accepted,
        "csrf_token_absent": accepted,
        "unsafe_samesite": True,
        "has_cookie_session": True,
        "tampered_ref_status": next((v for k, v in results.items() if k.startswith("forged_origin")), None),
        "no_ref_status": next((v for k, v in results.items() if k.startswith("baseline")), None),
    }
    if accepted:
        return (
            CsrfVerdict(
                CONFIRMED,
                "a cookie-authenticated state change was accepted with a forged Origin/Referer as a simple "
                "request: no origin validation and no anti-CSRF token",
                failed_count=3,
                details=details,
            ),
            evidence,
        )
    return CsrfVerdict(DEFENDED, "the forged Origin/Referer request was rejected", details=details), evidence


def build_alert(
    verdict: CsrfVerdict,
    *,
    method: str,
    api_url: str,
    evidence: dict,
    extract_request_parts,
    format_http_request,
    format_http_response,
    body_json: dict,
) -> dict | None:
    """Turn a CONFIRMED/CANDIDATE verdict into the finding dict the report builder expects."""
    if verdict.status not in (CONFIRMED, CANDIDATE):
        return None
    proof = evidence.get("accepted_request")
    response = proof["response"] if proof else None
    parts = (
        extract_request_parts(response.request, body_json=body_json, query_params=None)
        if response is not None
        else {
            "parsed_request_headers": {}, "parsed_request_body": body_json, "parsed_request_query": None,
            "auth_token_used": False, "login_required": True, "replay_script": "",
        }
    )
    confirmed = verdict.status == CONFIRMED
    defenses = {
        "verdict": verdict.status,
        "reason": verdict.reason,
        "failed_count": verdict.failed_count,
        **verdict.details,
    }
    return {
        "alert": "Cross-Site Request Forgery (CSRF) Vulnerability - Confirmed"
        if confirmed
        else "Cross-Site Request Forgery (CSRF) Vulnerability - Potential/Bypass",
        "url": api_url,
        "method": method.upper(),
        "risk": "High" if confirmed else "Medium",
        "confidence": "High" if confirmed else "Medium",
        "param": "Origin/Referer/SameSite",
        "attack": proof["label"] if proof else "not sent (state-destructive endpoint)",
        "custom_type": "CSRF_CUSTOM",
        "evidence_request": format_http_request(response.request) if response is not None else "",
        "evidence_response": format_http_response(response) if response is not None else "",
        "parsed_request_headers": parts["parsed_request_headers"],
        "parsed_request_body": parts["parsed_request_body"],
        "parsed_request_query": parts["parsed_request_query"],
        "auth_token_used": parts["auth_token_used"],
        "login_required": parts["login_required"],
        "expected_status_code": response.status_code if response is not None else None,
        "csrf_defenses": defenses,
        "screenshot_on": "response_received",
        "replay_script": parts["replay_script"],
        "description": verdict.reason,
        "solution": (
            "1. Validate Origin/Referer and reject missing or foreign origins. "
            "2. Require an anti-CSRF token on state-changing requests. "
            "3. Set the session cookie to SameSite=Lax or SameSite=Strict."
        ),
    }
