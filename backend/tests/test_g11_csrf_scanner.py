"""1-1 CSRF assessment: preconditions first, active requests only when they can matter."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import requests

_CSRF = Path(__file__).resolve().parents[1] / "diagnosis" / "modules" / "1-1" / "csrf_scanner.py"


@pytest.fixture(scope="module")
def csrf():
    spec = importlib.util.spec_from_file_location("diag_g11_csrf_test", _CSRF)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class FakeResponse:
    def __init__(self, status_code, headers=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.request = object()
        self.text = ""


class Server:
    """Scripted target: decides a status per request from its headers."""

    def __init__(self, *, normal=200, forged=200):
        self.normal, self.forged = normal, forged
        self.calls: list[dict] = []

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        headers = kwargs.get("headers") or {}
        if headers.get("Origin") == "http://evil-attacker.local":
            return FakeResponse(self.forged)
        return FakeResponse(self.normal)


def _assess(csrf, server, **overrides):
    args = dict(
        method="post",
        api_url="http://target/api/orders",
        body_json={"name": "x", "count": 2, "tags": ["a"]},
        cookies={"session": "abc"},
        ambient_auth=True,
        samesite_weak=True,
        request_fn=server,
    )
    args.update(overrides)
    return csrf.assess_csrf(**args)


# ---- preconditions (no request may be sent) --------------------------------
def test_header_token_api_is_not_applicable(csrf):
    server = Server()
    verdict, _ = _assess(csrf, server, ambient_auth=False)
    assert verdict.status == csrf.NOT_APPLICABLE
    assert server.calls == []


def test_unknown_ambient_auth_is_inconclusive(csrf):
    server = Server()
    verdict, _ = _assess(csrf, server, ambient_auth=None)
    assert verdict.status == csrf.INCONCLUSIVE
    assert server.calls == []


def test_samesite_lax_or_strict_is_defended_without_requests(csrf):
    server = Server()
    verdict, _ = _assess(csrf, server, samesite_weak=False)
    assert verdict.status == csrf.DEFENDED
    assert server.calls == []


def test_dangerous_endpoint_becomes_unverified_candidate_without_requests(csrf):
    server = Server()
    verdict, _ = _assess(csrf, server, dangerous=True)
    assert verdict.status == csrf.CANDIDATE
    assert server.calls == []
    assert verdict.details["origin_referer_bypass"] is None


# ---- active assessment -----------------------------------------------------
def test_forged_origin_accepted_is_confirmed(csrf):
    verdict, evidence = _assess(csrf, Server(normal=200, forged=200))
    assert verdict.status == csrf.CONFIRMED
    assert verdict.details["origin_referer_bypass"] is True
    assert "accepted_request" in evidence


def test_forged_origin_rejected_is_defended(csrf):
    verdict, _ = _assess(csrf, Server(normal=200, forged=403))
    assert verdict.status == csrf.DEFENDED


def test_failing_normal_request_is_inconclusive_not_defended(csrf):
    verdict, _ = _assess(csrf, Server(normal=400, forged=400))
    assert verdict.status == csrf.INCONCLUSIVE


def test_requests_use_cookies_only_and_simple_content_types(csrf):
    server = Server(normal=200, forged=200)
    _assess(csrf, server)
    for call in server.calls:
        headers = call["headers"]
        assert "Authorization" not in headers
        assert headers["Cookie"] == "session=abc"
        assert headers["Content-Type"] in {"application/x-www-form-urlencoded", "text/plain"}
        assert call["allow_redirects"] is False


def test_baseline_is_sent_before_the_forged_request(csrf):
    server = Server(normal=200, forged=403)
    _assess(csrf, server)
    assert "Origin" not in server.calls[0]["headers"]
    assert server.calls[1]["headers"]["Origin"] == "http://evil-attacker.local"


# ---- ambient authentication probe -----------------------------------------
class Probe:
    def __init__(self, anonymous, with_cookies):
        self.anonymous, self.with_cookies = anonymous, with_cookies

    def __call__(self, **kwargs):
        return FakeResponse(self.with_cookies if (kwargs.get("headers") or {}).get("Cookie") else self.anonymous)


def test_cookie_only_access_means_ambient_auth(csrf):
    ok, reason = csrf.detect_ambient_cookie_auth({"s": "1"}, ["http://t/api/me"], request_fn=Probe(401, 200))
    assert ok is True and "cookies only 200" in reason


def test_cookies_rejected_means_header_token_api(csrf):
    ok, _ = csrf.detect_ambient_cookie_auth({"s": "1"}, ["http://t/api/me"], request_fn=Probe(401, 401))
    assert ok is False


def test_no_cookie_issued_means_not_ambient(csrf):
    ok, reason = csrf.detect_ambient_cookie_auth({}, ["http://t/api/me"], request_fn=Probe(401, 200))
    assert ok is False and "no session cookie" in reason


def test_public_endpoint_cannot_prove_anything(csrf):
    ok, _ = csrf.detect_ambient_cookie_auth({"s": "1"}, ["http://t/api/public"], request_fn=Probe(200, 200))
    assert ok is None


def test_probe_survives_network_errors(csrf):
    def boom(**kwargs):
        raise requests.ConnectionError("down")

    ok, _ = csrf.detect_ambient_cookie_auth({"s": "1"}, ["http://t/api/me"], request_fn=boom)
    assert ok is None


# ---- SameSite and alert building ------------------------------------------
def test_samesite_from_cookie_attributes(csrf):
    assert csrf.samesite_is_weak({"cookie_attrs": {"s": {"samesite": "Lax"}}}) is False
    assert csrf.samesite_is_weak({"cookie_attrs": {"s": {"samesite": "None"}}}) is True
    assert csrf.samesite_is_weak({"cookie_attrs": {"s": {}}}) is True
    assert csrf.samesite_is_weak({}, "s=1; SameSite=Strict") is False
    assert csrf.samesite_is_weak({}, "s=1") is True


def _alert(csrf, verdict, evidence):
    return csrf.build_alert(
        verdict,
        method="post",
        api_url="http://target/api/orders",
        evidence=evidence,
        extract_request_parts=lambda req, **kw: {
            "parsed_request_headers": {}, "parsed_request_body": None, "parsed_request_query": None,
            "auth_token_used": False, "login_required": True, "replay_script": "",
        },
        format_http_request=lambda r: "request",
        format_http_response=lambda r: "response",
        body_json={},
    )


def test_confirmed_alert_is_high(csrf):
    verdict, evidence = _assess(csrf, Server(normal=200, forged=200))
    alert = _alert(csrf, verdict, evidence)
    assert (alert["risk"], alert["confidence"]) == ("High", "High")
    assert alert["csrf_defenses"]["verdict"] == "confirmed"
    assert alert["csrf_defenses"]["failed_count"] == 3


def test_candidate_alert_is_medium_and_marks_nothing_sent(csrf):
    verdict, evidence = _assess(csrf, Server(), dangerous=True)
    alert = _alert(csrf, verdict, evidence)
    assert alert["risk"] == "Medium"
    assert alert["evidence_request"] == ""
    assert "not sent" in alert["attack"]


@pytest.mark.parametrize("kwargs", [{"ambient_auth": False}, {"samesite_weak": False}, {"ambient_auth": None}])
def test_non_findings_produce_no_alert(csrf, kwargs):
    verdict, evidence = _assess(csrf, Server(), **kwargs)
    assert _alert(csrf, verdict, evidence) is None
