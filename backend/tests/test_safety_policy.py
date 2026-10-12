"""Shared safety policy: unsafe endpoints must never receive a live probe."""

from __future__ import annotations

import asyncio

import pytest

from app.services import probe_report, verify_service
from diagnosis.safety import is_dangerous_endpoint, properties_are_password_only
from inventory.schema import Endpoint


@pytest.mark.parametrize(
    "method, path",
    [
        ("DELETE", "/api/users/me"),
        ("POST", "/api/auth/reset-password"),
        ("POST", "/api/auth/logout"),
        ("POST", "/admin/users/delete/1"),
        ("POST", "/admin/projects/restore/{id}"),
        ("PATCH", "/api/projects/{projectId}/close"),
        ("PATCH", "/api/applications/{applicationId}/status/approve"),
        ("POST", "/api/orders/{id}/cancel"),
        ("PUT", "/api/members/change-password"),
        ("POST", "/api/settlements/trigger"),
    ],
)
def test_state_changing_endpoints_are_blocked(method, path):
    blocked, reason = is_dangerous_endpoint(method, path)
    assert blocked, f"{method} {path} should be blocked"
    assert reason


@pytest.mark.parametrize(
    "method, path",
    [
        ("GET", "/api/projects"),
        ("GET", "/api/users/me"),
        ("POST", "/api/auth/login"),
        ("POST", "/api/auth/signup"),
        ("POST", "/api/projects"),
        ("PATCH", "/api/users/me"),
        ("POST", "/api/banners"),
        ("GET", "/api/auth/check-email"),
    ],
)
def test_normal_endpoints_are_allowed(method, path):
    assert is_dangerous_endpoint(method, path) == (False, "")


def test_markers_match_whole_segments_only():
    assert is_dangerous_endpoint("POST", "/api/banners")[0] is False
    assert is_dangerous_endpoint("POST", "/api/users/ban")[0] is True
    assert is_dangerous_endpoint("POST", "/api/payments/history")[0] is False
    assert is_dangerous_endpoint("POST", "/api/payment/confirm")[0] is True


def test_get_is_only_blocked_by_configured_markers():
    assert is_dangerous_endpoint("GET", "/api/orders/cancel-policy")[0] is False
    assert is_dangerous_endpoint("GET", "/api/internal/dump", extra_markers=("/internal",))[0] is True


def test_extra_markers_extend_the_policy():
    assert is_dangerous_endpoint("POST", "/api/backoffice/sync")[0] is False
    assert is_dangerous_endpoint("POST", "/api/backoffice/sync", extra_markers=("/backoffice",))[0] is True


def test_metadata_keywords_block_even_when_the_path_looks_harmless():
    details = {"summary": "회원 탈퇴 처리"}
    assert is_dangerous_endpoint("POST", "/api/members/process", details)[0] is True


def test_password_only_body_detection():
    assert properties_are_password_only(["currentPassword", "newPassword"]) is True
    assert properties_are_password_only(["nickname", "newPassword"]) is False
    assert properties_are_password_only([]) is False
    assert is_dangerous_endpoint("PATCH", "/api/members/me/secret", password_only_body=True)[0] is True


class _FailingClient:
    def __init__(self):
        self.calls = 0

    async def request(self, **kwargs):
        self.calls += 1
        raise AssertionError("an unsafe endpoint must not be called")


def test_verify_probe_skips_unsafe_endpoint_without_sending_a_request():
    ep = Endpoint(method="POST", path="/api/auth/reset-password", base_url="http://localhost:8080")
    client = _FailingClient()
    row = asyncio.run(verify_service._probe(client, ep))
    assert client.calls == 0
    assert row["status"] == "skipped_unsafe"
    assert row["http_status"] is None
    assert row["include_in_final"] is True
    assert "safety" in row["note"].lower()


def test_skipped_endpoints_stay_in_the_verified_inventory():
    ep = Endpoint(method="POST", path="/api/auth/reset-password", base_url="http://localhost:8080")
    row = asyncio.run(verify_service._probe(_FailingClient(), ep))
    assert probe_report.endpoint_keeps_in_inventory(ep, [row]) is True
    summary = probe_report.summarize_probe_results([row])
    assert summary["skipped_unsafe"] == 1
    assert summary["rejected"] == 0
