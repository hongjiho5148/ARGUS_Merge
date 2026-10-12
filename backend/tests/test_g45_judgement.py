"""4-5 privilege-escalation judgement rules."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_MODULE_DIR = Path(__file__).resolve().parents[1] / "diagnosis" / "modules" / "4-5"


def _load(name: str, alias: str):
    spec = importlib.util.spec_from_file_location(alias, _MODULE_DIR / f"{name}.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def utils():
    return _load("g45_utils", "diag_g45_utils_test")


@pytest.fixture(scope="module")
def scanner():
    sys.path.insert(0, str(_MODULE_DIR))
    try:
        return _load("scanner", "diag_g45_scanner_test")
    finally:
        sys.path.remove(str(_MODULE_DIR))


class TestJsonFieldMatches:
    def test_top_level_value_echoed(self, utils):
        assert utils.json_field_matches({"role": "ADMIN"}, "role", "ADMIN") is True

    def test_nested_value_echoed(self, utils):
        assert utils.json_field_matches({"data": {"user": {"role": "ADMIN"}}}, "role", "ADMIN") is True

    def test_value_inside_list_echoed(self, utils):
        assert utils.json_field_matches({"items": [{"id": 1}, {"role": "ADMIN"}]}, "role", "ADMIN") is True

    def test_key_match_is_case_insensitive(self, utils):
        assert utils.json_field_matches({"Role": "ADMIN"}, "role", "ADMIN") is True

    def test_value_compared_as_string(self, utils):
        assert utils.json_field_matches({"level": 1}, "level", "1") is True

    def test_server_ignored_the_value(self, utils):
        assert utils.json_field_matches({"role": "USER"}, "role", "ADMIN") is False

    def test_field_absent(self, utils):
        assert utils.json_field_matches({"name": "x"}, "role", "ADMIN") is False

    def test_non_container_input(self, utils):
        assert utils.json_field_matches("ADMIN", "role", "ADMIN") is False


class TestAdminEndpointDetection:
    @pytest.mark.parametrize(
        "ep",
        [
            {"path": "/api/v1/admin/posts", "base_url": "http://x"},
            {"path": "/admin-api/api/v1/members", "base_url": "http://x"},
            {"path": "/api/v1/manage/users", "base_url": "http://x"},
            {"path": "/api/v1/members", "base_url": "https://admin.example.com"},
        ],
    )
    def test_admin_endpoints(self, scanner, ep):
        assert scanner._is_admin_endpoint(ep, []) is True

    @pytest.mark.parametrize(
        "ep",
        [
            {"path": "/api/v1/posts", "base_url": "http://x"},
            {"path": "/api/v1/{management-functions}", "base_url": "http://x"},
            {"path": "/api/v1/members", "base_url": "http://host.docker.internal:8080"},
        ],
    )
    def test_non_admin_endpoints(self, scanner, ep):
        assert scanner._is_admin_endpoint(ep, []) is False

    def test_configured_marker_extends_detection(self, scanner):
        ep = {"path": "/api/v1/backoffice/users", "base_url": "http://x"}
        assert scanner._is_admin_endpoint(ep, []) is False
        assert scanner._is_admin_endpoint(ep, ["/backoffice"]) is True


class TestConfigExtension:
    def test_extend_unique_appends_without_duplicates(self, scanner):
        assert scanner._extend_unique(["a", "b"], ["b", " c ", ""]) == ["a", "b", "c"]

    def test_extend_unique_ignores_non_list(self, scanner):
        assert scanner._extend_unique(["a"], "not-a-list") == ["a"]


class TestVerticalAccessJudgement:
    DENIAL = ["forbidden", "권한"]

    def test_redirect_is_denied(self, utils):
        vulnerable, _ = utils.judge_vertical_access(302, "", "text/html", self.DENIAL)
        assert vulnerable is False

    @pytest.mark.parametrize("status", [401, 403, 404, 500])
    def test_error_statuses_are_denied(self, utils, status):
        assert utils.judge_vertical_access(status, "x", "application/json", self.DENIAL)[0] is False

    def test_denial_message_in_a_200_is_denied(self, utils):
        body = '{"success": false, "message": "권한이 없습니다"}'
        assert utils.judge_vertical_access(200, body, "application/json", self.DENIAL)[0] is False

    def test_login_form_page_is_not_admin_access(self, utils):
        body = '<html><form><input type="password" name="pw"></form></html>'
        vulnerable, reason = utils.judge_vertical_access(200, body, "text/html;charset=UTF-8", self.DENIAL)
        assert vulnerable is False and "login" in reason

    def test_spa_shell_is_not_endpoint_data(self, utils):
        body = '<!doctype html><div id="root"></div>'
        assert utils.judge_vertical_access(200, body, "text/html", self.DENIAL)[0] is False

    def test_json_admin_data_is_flagged(self, utils):
        body = '{"success": true, "data": {"members": [{"id": 1}]}}'
        vulnerable, _ = utils.judge_vertical_access(200, body, "application/json", self.DENIAL)
        assert vulnerable is True

    def test_html_admin_page_without_login_form_is_flagged(self, utils):
        body = "<html><h1>User management</h1><table></table></html>"
        assert utils.judge_vertical_access(200, body, "text/html", self.DENIAL)[0] is True

    def test_204_counts_as_access(self, utils):
        assert utils.judge_vertical_access(204, "", "", self.DENIAL)[0] is True
