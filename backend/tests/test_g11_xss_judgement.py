"""1-1 XSS judgement rules: reflection matching and response classification."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_ZAP_RUNNER = Path(__file__).resolve().parents[1] / "diagnosis" / "modules" / "1-1" / "zap_runner.py"


@pytest.fixture(scope="module")
def zr():
    spec = importlib.util.spec_from_file_location("diag_g11_zap_runner_test", _ZAP_RUNNER)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


PAYLOAD = "<script>alert(1)</script>"


class TestNormalizeReflectionText:
    def test_decodes_html_entities_and_url_encoding(self, zr):
        assert zr.normalize_reflection_text("&lt;script&gt;") == "<script>"
        assert zr.normalize_reflection_text("%3Cscript%3E") == "<script>"

    def test_decodes_json_unicode_escapes(self, zr):
        assert zr.normalize_reflection_text("\\u003cscript\\u003e") == "<script>"

    def test_empty_value(self, zr):
        assert zr.normalize_reflection_text("") == ""


class TestPayloadReflection:
    def test_raw_reflection_is_found(self, zr):
        assert zr.get_payload_reflection(PAYLOAD, f"<p>{PAYLOAD}</p>") == PAYLOAD

    def test_html_escaped_reflection_is_found(self, zr):
        body = "<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>"
        assert zr.get_payload_reflection(PAYLOAD, body) is not None

    def test_json_unicode_escaped_reflection_is_found(self, zr):
        body = '{"name":"\\u003cscript\\u003ealert(1)\\u003c\\/script\\u003e"}'
        assert zr.get_payload_reflection(PAYLOAD, body) is not None

    def test_not_reflected(self, zr):
        assert zr.get_payload_reflection(PAYLOAD, "<p>hello</p>") is None

    def test_empty_inputs(self, zr):
        assert zr.get_payload_reflection("", "body") is None
        assert zr.get_payload_reflection(PAYLOAD, "") is None

    def test_unchanged_baseline_means_no_reflection(self, zr):
        body = f"<p>{PAYLOAD}</p>"
        assert zr.get_payload_reflection(PAYLOAD, body, baseline_body=body) is None

    def test_only_newly_added_content_counts(self, zr):
        baseline = f"<li>old</li>\n<li>{PAYLOAD}</li>\n"
        after = baseline + f"<li>{PAYLOAD}</li>\n"
        assert zr.get_payload_reflection(PAYLOAD, after, baseline_body=baseline) == PAYLOAD

    def test_payload_present_only_in_baseline_is_ignored(self, zr):
        baseline = f"<li>{PAYLOAD}</li>\n"
        after = f"<li>{PAYLOAD}</li>\n<li>other</li>\n"
        assert zr.get_payload_reflection(PAYLOAD, after, baseline_body=baseline) is None


class TestReflectionContext:
    def test_html_attribute(self, zr):
        assert zr.detect_xss_reflection_context("xss", '<input value="xss">') == "HTML attribute"

    def test_html_body(self, zr):
        assert zr.detect_xss_reflection_context("xss", "<div> xss </div>") == "HTML body"

    def test_json_string(self, zr):
        assert zr.detect_xss_reflection_context("xss", '{"a":"xss"}') == "JSON/String value"

    def test_encoded_fallback(self, zr):
        assert zr.detect_xss_reflection_context("xss", "prefix xss suffix") == "encoded/reflected"


class TestClassifyXssResponse:
    def test_html_reflection_with_executable_marker_is_medium(self, zr):
        result = zr.classify_xss_response(PAYLOAD, f"<p>{PAYLOAD}</p>", "text/html")
        assert result["kind"] == "reflected"
        assert (result["risk"], result["confidence"]) == ("Medium", "High")

    def test_json_reflection_is_downgraded_to_low(self, zr):
        body = f'{{"name": "{PAYLOAD}"}}'
        result = zr.classify_xss_response(PAYLOAD, body, "application/json")
        assert result["kind"] == "reflected"
        assert (result["risk"], result["confidence"]) == ("Low", "Medium")

    def test_non_html_non_json_content_type_is_ignored(self, zr):
        assert zr.classify_xss_response(PAYLOAD, f"echo {PAYLOAD}", "text/plain") is None

    def test_reflection_without_executable_marker_is_ignored(self, zr):
        payload = "ARGUS_name_abc123"
        assert zr.classify_xss_response(payload, f"<p>{payload}</p>", "text/html") is None

    def test_payload_absent_returns_none(self, zr):
        assert zr.classify_xss_response(PAYLOAD, "<p>hello</p>", "text/html") is None

    def test_empty_inputs_return_none(self, zr):
        assert zr.classify_xss_response("", "body", "text/html") is None
        assert zr.classify_xss_response(PAYLOAD, "", "text/html") is None

    def test_baseline_suppresses_pre_existing_reflection(self, zr):
        body = f"<p>{PAYLOAD}</p>"
        assert zr.classify_xss_response(PAYLOAD, body, "text/html", baseline_body=body) is None

    def test_dom_sink_with_source_is_informational_never_confirmed(self, zr):
        body = f"<script>var q = location.search; el.innerHTML = q; // {PAYLOAD}</script>"
        result = zr.classify_xss_response(PAYLOAD, body, "text/html")
        assert result["kind"] == "dom_suspect"
        assert result["custom_type"] == "DOM_XSS_SUSPECT"
        assert (result["risk"], result["confidence"]) == ("Informational", "Low")


class TestDefaultValues:
    def test_default_string_satisfies_common_min_length_rules(self, zr):
        assert len(zr.default_value_for_schema({"type": "string"}, {}, "title")) >= 5

    def test_declared_min_length_is_respected(self, zr):
        assert len(zr.default_value_for_schema({"type": "string", "minLength": 12}, {}, "title")) == 12

    def test_declared_max_length_wins(self, zr):
        assert len(zr.default_value_for_schema({"type": "string", "maxLength": 3}, {}, "title")) == 3

    def test_example_and_enum_take_priority(self, zr):
        assert zr.default_value_for_schema({"type": "string", "example": "hello"}, {}, "x") == "hello"
        assert zr.default_value_for_schema({"type": "string", "enum": ["A", "B"]}, {}, "x") == "A"


class TestPreserveProfileValues:
    class _Resp:
        def __init__(self, data):
            self._data = data

        def json(self):
            return {"data": self._data}

    def _preserve(self, zr, monkeypatch, current, payload, tested=""):
        import requests

        monkeypatch.setattr(requests, "get", lambda *a, **k: self._Resp(current))
        zr.preserve_current_profile_values(payload, "http://t/api/users/me", {}, tested)
        return payload

    def test_scalar_lists_are_copied_so_whitelisted_values_survive(self, zr, monkeypatch):
        payload = {"nickname": "x", "techStacks": ["1"]}
        self._preserve(zr, monkeypatch, {"nickname": "aga", "techStacks": ["Java"]}, payload)
        assert payload == {"nickname": "aga", "techStacks": ["Java"]}

    def test_lists_of_objects_and_nested_objects_are_not_copied(self, zr, monkeypatch):
        payload = {"items": [{"a": 1}], "meta": {"k": 1}, "name": "x"}
        self._preserve(zr, monkeypatch, {"items": [{"a": 2}], "meta": {"k": 2}, "name": "real"}, payload)
        assert payload == {"items": [{"a": 1}], "meta": {"k": 1}, "name": "real"}

    def test_the_tested_field_is_left_alone(self, zr, monkeypatch):
        payload = {"techStacks": ["<script>"], "nickname": "x"}
        self._preserve(zr, monkeypatch, {"techStacks": ["Java"], "nickname": "aga"}, payload, tested="techStacks")
        assert payload["techStacks"] == ["<script>"]


class TestDefaultsAreNotSiteSpecific:
    def _value(self, zr, name, schema=None):
        return zr.default_value_for_schema(schema or {"type": "string"}, {}, name)

    def test_universal_concepts_still_get_sensible_values(self, zr):
        assert "@" in self._value(zr, "email")
        assert self._value(zr, "phoneNumber").isdigit()
        assert len(self._value(zr, "password")) >= 8
        assert self._value(zr, "endDate").count("-") == 2

    def test_site_vocabulary_is_left_to_the_schema_or_repair(self, zr):
        for name in ("category", "representative", "accountNumber", "nickname", "recruitCount", "guestCount"):
            value = self._value(zr, name, {"type": "integer"} if name.endswith("Count") else None)
            assert value in ("safetest", 1), (name, value)

    def test_names_that_merely_contain_tel_or_date_are_not_treated_as_phone_or_date(self, zr):
        assert self._value(zr, "hotelName") == "safetest"
        assert self._value(zr, "candidateName") == "safetest"
        assert self._value(zr, "updatedBy") == "safetest"

    def test_schema_constraints_drive_numbers(self, zr):
        assert self._value(zr, "anything", {"type": "integer", "minimum": 5}) == 5
