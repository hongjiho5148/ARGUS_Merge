"""Tests for verify session cache and fast diagnosis login."""

from __future__ import annotations

import json
from pathlib import Path

from app.services.auth_probe_service import (
    dedupe_account_auths,
    load_cached_account_auths,
    login_urls_for_account,
    resolve_account_auths,
)


def test_login_urls_for_account_uses_successful_only():
    entries = [
        {"url": "http://x/api/v1/auth/login"},
        {"url": "http://x/api/v1/auth/admin/login"},
    ]
    report = {
        "accounts": [
            {
                "email": "seller@ex.com",
                "successful_login_urls": ["http://x/api/v1/auth/login"],
                "failed_login_urls": ["http://x/api/v1/auth/admin/login"],
            }
        ]
    }
    urls = login_urls_for_account({"email": "seller@ex.com", "password": "p"}, entries, report)
    assert urls == ["http://x/api/v1/auth/login"]


def test_login_urls_retries_all_when_report_contains_only_failures():
    entries = [
        {"url": "http://x/api/v1/auth/login"},
        {"url": "http://x/api/v1/auth/admin/login"},
    ]
    report = {
        "accounts": [
            {
                "email": "bad@ex.com",
                "successful_login_urls": [],
                "failed_login_urls": [
                    "http://x/api/v1/auth/login",
                    "http://x/api/v1/auth/admin/login",
                ],
            }
        ]
    }
    urls = login_urls_for_account({"email": "bad@ex.com", "password": "p"}, entries, report)
    assert urls == [entry["url"] for entry in entries]


def test_login_urls_does_not_apply_stale_failures_to_new_origins():
    entries = [
        {"url": "http://api:8080/api/v1/auth/login"},
        {"url": "http://api:8080/api/v1/auth/admin/login"},
    ]
    report = {
        "accounts": [
            {
                "email": "a@ex.com",
                "successful_login_urls": [],
                "failed_login_urls": [
                    "http://frontend:5173/api/v1/auth/login",
                    "http://frontend:5173/api/v1/auth/admin/login",
                ],
            }
        ]
    }
    urls = login_urls_for_account({"email": "a@ex.com", "password": "p"}, entries, report)
    assert urls == [entry["url"] for entry in entries]


def test_load_cached_account_auths_from_verify_report(tmp_path: Path):
    report = {
        "checked_at": "2026-01-01T00:00:00+00:00",
        "account_auths": [
            {
                "email": "a@ex.com",
                "token": "tok1",
                "login_url": "http://x/login",
                "login_label": "login",
                "delivery": "cookie",
                "cookie_name": "accessToken",
            }
        ],
    }
    (tmp_path / "verify-report.json").write_text(json.dumps(report), encoding="utf-8")
    cached = load_cached_account_auths(tmp_path)
    assert len(cached) == 1
    assert cached[0]["email"] == "a@ex.com"


def test_resolve_account_auths_uses_cache_without_live_login(tmp_path: Path, monkeypatch):
    report = {
        "checked_at": "2026-01-01T00:00:00+00:00",
        "login_entry_report": {"accounts": []},
        "account_auths": [
            {
                "email": "a@ex.com",
                "token": "tok1",
                "login_url": "http://x/login",
                "login_label": "login",
                "delivery": "cookie",
                "cookie_name": "accessToken",
            }
        ],
    }
    (tmp_path / "verify-report.json").write_text(json.dumps(report), encoding="utf-8")

    def fail_login(*_args, **_kwargs):
        raise AssertionError("live login should not run when cache exists")

    monkeypatch.setattr("app.services.auth_probe_service.login_all_accounts", fail_login)

    sessions, meta = resolve_account_auths(
        {"id_field": "email"},
        [{"email": "a@ex.com", "password": "x"}],
        data_dir=tmp_path,
    )
    assert len(sessions) == 1
    assert meta["source"] == "verify_cache"


def test_dedupe_account_auths():
    sessions = [
        {"email": "a@ex.com", "login_url": "http://x/login", "token": "1"},
        {"email": "a@ex.com", "login_url": "http://x/login", "token": "1"},
    ]
    assert len(dedupe_account_auths(sessions)) == 1
