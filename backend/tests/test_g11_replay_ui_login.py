"""1-1 evidence capture: role-landing judgement and URL mapping for the UI login."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_CAPTURE_DIR = Path(__file__).resolve().parents[1] / "screenshot" / "modules" / "1-1"
_BARE_MODULES = ("models", "credentials", "request_text", "route_discovery", "replay")


@pytest.fixture(scope="module")
def replay():
    saved = {name: sys.modules.pop(name, None) for name in _BARE_MODULES}
    sys.path.insert(0, str(_CAPTURE_DIR))
    try:
        spec = importlib.util.spec_from_file_location("diag_g11_replay_test", _CAPTURE_DIR / "replay.py")
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        yield mod
    finally:
        sys.path.remove(str(_CAPTURE_DIR))
        for name in _BARE_MODULES:
            sys.modules.pop(name, None)
            if saved[name] is not None:
                sys.modules[name] = saved[name]


DEFAULT_CFG = {
    "role_landing_paths": {"seller": "/seller", "admin": "/admin"},
    "error_paths": ["/401", "/403"],
}


@pytest.mark.parametrize(
    "wanted, landed, expected",
    [
        ("seller", "/seller/dashboard", True),
        ("seller", "/", False),
        ("super_admin", "/admin", True),
        ("super_admin", "/seller", False),
        ("user", "/", True),
        ("user", "/seller", False),
        ("user", "/admin/members", False),
    ],
)
def test_role_matches_landing(replay, wanted, landed, expected):
    assert replay._role_matches_landing(wanted, landed, DEFAULT_CFG) is expected


@pytest.mark.parametrize("wanted", ["seller", "super_admin", "user"])
@pytest.mark.parametrize("error_path", ["/401", "/403"])
def test_error_landing_never_matches_any_role(replay, wanted, error_path):
    assert replay._role_matches_landing(wanted, error_path, DEFAULT_CFG) is False


def test_custom_landing_paths_are_respected(replay):
    cfg = {"role_landing_paths": {"owner": "/owner"}, "error_paths": ["/denied"]}
    assert replay._role_matches_landing("owner", "/owner/home", cfg) is True
    assert replay._role_matches_landing("user", "/owner/home", cfg) is False
    assert replay._role_matches_landing("owner", "/denied", cfg) is False


def test_normalize_wanted_role(replay):
    assert replay._normalize_wanted_role("ROLE_SELLER") == "seller"
    assert replay._normalize_wanted_role(None) == ""


def test_runtime_url_keeps_original_port(replay, monkeypatch):
    monkeypatch.delenv("ARGUS_SCREENSHOT_API_BASE", raising=False)
    monkeypatch.setattr(replay.sys, "platform", "win32")
    assert replay._runtime_url("http://host.docker.internal:9090/api/x?q=1") == "http://localhost:9090/api/x?q=1"
    assert replay._runtime_url("http://host.docker.internal/api/x") == "http://localhost/api/x"


def test_runtime_url_untouched_on_linux(replay, monkeypatch):
    monkeypatch.delenv("ARGUS_SCREENSHOT_API_BASE", raising=False)
    monkeypatch.setattr(replay.sys, "platform", "linux")
    url = "http://host.docker.internal:8080/api/x"
    assert replay._runtime_url(url) == url
