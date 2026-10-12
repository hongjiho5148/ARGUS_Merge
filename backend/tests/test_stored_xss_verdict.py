"""Three-level Stored XSS verdict: response grade + browser evidence."""

from diagnosis import stored_xss_verdict as v

PAYLOAD = "<img src=x onerror=alert('ARGUS_title_ab12cd34ef')>"


def test_json_response_is_candidate_and_html_is_high():
    assert v.grade_response("application/json;charset=UTF-8") == v.CANDIDATE
    assert v.grade_response("text/html; charset=utf-8") == v.HIGH
    assert v.grade_response("") == v.CANDIDATE


def test_event_handler_payloads_are_tried_first_and_order_is_stable():
    payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>", "<iframe src=javascript:alert(1)>"]
    assert v.order_for_browser_proof(payloads) == [payloads[1], payloads[2], payloads[0], payloads[3]]


def test_browser_execution_confirms():
    dialogs = [{"type": "alert", "message": "ARGUS_title_ab12cd34ef"}]
    status = v.browser_status_from_capture(dialogs, None, PAYLOAD)
    assert status == v.BROWSER_EXECUTED
    assert v.final_level(v.CANDIDATE, status) == v.CONFIRMED


def test_foreign_alert_is_not_proof():
    dialogs = [{"type": "alert", "message": "welcome back"}]
    assert v.browser_status_from_capture(dialogs, {"found": False}, PAYLOAD) == v.BROWSER_NOT_FOUND


def test_payload_shown_as_text_downgrades_even_html_findings():
    status = v.browser_status_from_capture([], {"found": True, "via": "text"}, PAYLOAD)
    assert status == v.BROWSER_INERT_TEXT
    assert v.final_level(v.HIGH, status) == v.CANDIDATE


def test_unreachable_page_keeps_response_level():
    status = v.browser_status_from_capture([], None, PAYLOAD)
    assert status == v.BROWSER_NOT_FOUND
    assert v.final_level(v.HIGH, status) == v.HIGH
    assert v.final_level(v.CANDIDATE, v.BROWSER_NOT_CHECKED) == v.CANDIDATE


def test_rating_per_level():
    assert v.rating(v.CANDIDATE) == ("Medium", "Medium", "Potential")
    assert v.rating(v.HIGH)[2] == "True Positive"
    assert v.rating(v.CONFIRMED) == ("High", "High", "True Positive")


def test_reason_mentions_the_actual_basis():
    assert "실행됨" in v.reason(v.CONFIRMED, v.BROWSER_EXECUTED)
    assert "이스케이프된 텍스트" in v.reason(v.CANDIDATE, v.BROWSER_INERT_TEXT)
    assert "JSON" in v.reason(v.CANDIDATE, v.BROWSER_NOT_FOUND)
    assert "HTML" in v.reason(v.HIGH, v.BROWSER_NOT_FOUND)
    assert all("서버 측 입력 검증" in v.reason(level, status) for level, status in (
        (v.CANDIDATE, v.BROWSER_NOT_FOUND), (v.CANDIDATE, v.BROWSER_INERT_TEXT), (v.HIGH, v.BROWSER_NOT_FOUND)))


# ---- applying capture results to a report ----------------------------------
def _report(*evidences):
    from diagnosis.result import DiagnosisFinding, SectionReport

    return SectionReport(
        section_id="1-1", title="t", chapter=1, status="fail", implemented=True,
        findings=[DiagnosisFinding(message="Stored XSS", evidence=e) for e in evidences],
    )


def _evidence(**overrides):
    base = {
        "vuln_type": "Stored XSS", "url": "http://t/api/items/", "param": "title", "account_role": "USER",
        "xss_level": "candidate", "risk": "Medium", "confidence": "Medium", "validation_status": "Potential",
    }
    base.update(overrides)
    return base


def _summary(status, **match_overrides):
    match = {"vuln_type": "Stored XSS", "url": "http://t/api/items", "param": "title", "account_role": "USER"}
    match.update(match_overrides)
    return {"results": [{"ok": True, "match": match, "browser_verification": {"status": status}}]}


def test_executed_in_browser_promotes_candidate_to_confirmed():
    from app.services.diagnosis_service import apply_g11_browser_verdicts

    report = _report(_evidence())
    assert apply_g11_browser_verdicts(report, _summary("executed")) == 1
    evidence = report.findings[0].evidence
    assert evidence["xss_level"] == "confirmed"
    assert (evidence["risk"], evidence["confidence"], evidence["validation_status"]) == ("High", "High", "True Positive")
    assert evidence["xss_level_by_response"] == "candidate"


def test_inert_text_demotes_html_finding_to_candidate():
    from app.services.diagnosis_service import apply_g11_browser_verdicts

    report = _report(_evidence(xss_level="high", risk="High", validation_status="True Positive"))
    apply_g11_browser_verdicts(report, _summary("inert_text"))
    evidence = report.findings[0].evidence
    assert (evidence["xss_level"], evidence["validation_status"]) == ("candidate", "Potential")


def test_findings_without_a_capture_row_are_untouched():
    from app.services.diagnosis_service import apply_g11_browser_verdicts

    report = _report(_evidence(), _evidence(param="content"))
    assert apply_g11_browser_verdicts(report, _summary("executed", param="other")) == 0
    assert report.findings[0].evidence["xss_level"] == "candidate"


def test_selector_captures_stored_xss_candidates_but_not_other_potentials():
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "screenshot" / "modules" / "1-1" / "selector.py"
    spec = importlib.util.spec_from_file_location("sel_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.is_capturable({"evidence": {"vuln_type": "Stored XSS", "validation_status": "Potential"}})
    assert not mod.is_capturable({"evidence": {"vuln_type": "CSRF", "validation_status": "Potential"}})
