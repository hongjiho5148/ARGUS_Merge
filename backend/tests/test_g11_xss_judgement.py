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
