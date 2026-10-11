"""1-1 CSRF severity rules: how many of the 3 defenses failed decides the finding."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_CSRF = Path(__file__).resolve().parents[1] / "diagnosis" / "modules" / "1-1" / "csrf_scanner.py"


@pytest.fixture(scope="module")
def csrf():
    spec = importlib.util.spec_from_file_location("diag_g11_csrf_test", _CSRF)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeResponse:
    def __init__(self, status_code, headers=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.request = object()
        self.text = ""


def _run(csrf, monkeypatch, *, tampered, no_ref, token_absent, unsafe_samesite,
         cookie_auth="", base_headers=None):
    responses = iter([FakeResponse(tampered), FakeResponse(no_ref)])
    sent = []

    def fake_request(**kwargs):
        sent.append(kwargs)
        return next(responses)

    monkeypatch.setattr(csrf.requests, "request", fake_request)
    alerts = csrf.scan_csrf_endpoint(
        method="post",
        api_url="http://target/api/v1/orders",
        body_json={"a": 1},
        base_headers=base_headers or {"Authorization": "Bearer t", "Origin": "http://target", "Referer": "http://target/"},
        scan_account={},
        cookie_auth_header=cookie_auth,
        check_csrf_token_absence=lambda res: token_absent,
        has_unsafe_samesite_cookie=lambda account, set_cookie: unsafe_samesite,
        extract_request_parts=lambda req, **kw: {
            "parsed_request_headers": {}, "parsed_request_body": None, "parsed_request_query": None,
            "auth_token_used": False, "login_required": False, "replay_script": "",
        },
        format_http_request=lambda req: "request",
        format_http_response=lambda res: "response",
    )
    return alerts, sent


def test_three_failed_defenses_is_high(csrf, monkeypatch):
    alerts, _ = _run(csrf, monkeypatch, tampered=200, no_ref=200, token_absent=True,
                     unsafe_samesite=True, cookie_auth="session=abc")
    assert len(alerts) == 1
    assert alerts[0]["risk"] == "High"
    assert alerts[0]["csrf_defenses"]["failed_count"] == 3


def test_two_failed_defenses_is_medium(csrf, monkeypatch):
    alerts, _ = _run(csrf, monkeypatch, tampered=200, no_ref=200, token_absent=True, unsafe_samesite=False)
    assert len(alerts) == 1
    assert alerts[0]["risk"] == "Medium"
    assert alerts[0]["csrf_defenses"]["failed_count"] == 2


def test_one_failed_defense_creates_no_finding(csrf, monkeypatch):
    alerts, _ = _run(csrf, monkeypatch, tampered=200, no_ref=200, token_absent=False, unsafe_samesite=False)
    assert alerts == []


def test_server_rejecting_forged_origin_with_one_other_failure_creates_no_finding(csrf, monkeypatch):
    alerts, _ = _run(csrf, monkeypatch, tampered=403, no_ref=403, token_absent=True, unsafe_samesite=False)
    assert alerts == []


def test_two_non_origin_failures_still_count_even_when_origin_check_works(csrf, monkeypatch):
    alerts, _ = _run(csrf, monkeypatch, tampered=403, no_ref=403, token_absent=True, unsafe_samesite=True,
                     cookie_auth="session=abc")
    assert [a["risk"] for a in alerts] == ["Medium"]
    assert alerts[0]["csrf_defenses"]["origin_referer_bypass"] is False


def test_method_not_allowed_counts_as_passed(csrf):
    assert csrf._is_passed(405) is True
    assert csrf._is_passed(200) is True
    assert csrf._is_passed(403) is False


def test_csrf_token_header_in_request_means_token_not_absent(csrf, monkeypatch):
    alerts, _ = _run(csrf, monkeypatch, tampered=200, no_ref=200, token_absent=True, unsafe_samesite=False,
                     base_headers={"X-CSRF-Token": "abc"})
    assert alerts == []


def test_two_variants_are_sent_forged_and_stripped(csrf, monkeypatch):
    _, sent = _run(csrf, monkeypatch, tampered=403, no_ref=403, token_absent=False, unsafe_samesite=False)
    forged, stripped = sent[0]["headers"], sent[1]["headers"]
    assert forged["Origin"] == "http://evil-attacker.local"
    assert forged["Referer"].startswith("http://evil-attacker.local")
    assert "Origin" not in stripped and "Referer" not in stripped
    assert stripped["Authorization"] == "Bearer t"
