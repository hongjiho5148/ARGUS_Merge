"""1-1 baseline repair: read the server's validation message, fix the field, retry."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[1] / "diagnosis" / "modules" / "1-1" / "baseline_repair.py"


@pytest.fixture(scope="module")
def br():
    spec = importlib.util.spec_from_file_location("diag_g11_baseline_repair_test", _PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class Resp:
    def __init__(self, status, body=None):
        self.status_code = status
        self.text = json.dumps(body) if body is not None else ""


def spring_error(code, message, field_errors=None):
    return {"success": False, "error": {"code": code, "message": message, "fieldErrors": field_errors}}


# ---- reading the error --------------------------------------------------------
def test_spring_field_errors(br):
    text = json.dumps(spring_error("VALID_001", "bad", [{"field": "phoneNumber", "message": "하이픈(-) 없이 숫자만 입력해주세요.", "rejectedValue": "010-1"}]))
    errors = br.extract_field_errors(text)
    assert [(e.field, e.message) for e in errors] == [("phoneNumber", "하이픈(-) 없이 숫자만 입력해주세요.")]


def test_pydantic_style_errors(br):
    text = json.dumps({"detail": [{"loc": ["body", "age"], "msg": "ensure this value is greater than 0", "type": "value_error"}]})
    assert [e.field for e in br.extract_field_errors(text)] == ["age"]


def test_drf_style_errors(br):
    text = json.dumps({"email": ["Enter a valid email address."], "name": ["This field is required."]})
    assert {e.field for e in br.extract_field_errors(text)} == {"email", "name"}


def test_message_only_error_has_no_field(br):
    errors = br.extract_field_errors(json.dumps(spring_error("USER_007", "닉네임은 2~10자의 영문, 숫자, 한글만 가능합니다")))
    assert errors[0].field == "" and "닉네임" in errors[0].message


def test_plain_text_error(br):
    assert br.extract_field_errors("phone must be 11 digits")[0].message.startswith("phone")


# ---- matching a message to a field -------------------------------------------
def test_concept_word_matches_field_by_meaning(br):
    error = br.FieldError("", "전화번호 형식이 올바르지 않습니다 (숫자 11자)")
    assert br.match_fields(error, ["name", "phoneNumber"]) == ["phoneNumber"]


def test_field_key_in_message_matches(br):
    assert br.match_fields(br.FieldError("", "nickname is too long"), ["nickname", "email"]) == ["nickname"]


def test_nested_field_is_matched_by_leaf(br):
    assert br.match_fields(br.FieldError("phone", "x"), ["profile.phone", "profile.name"]) == ["profile.phone"]


# ---- producing values ---------------------------------------------------------
def test_hyphen_free_digits(br):
    assert br.propose_value(br.FieldError("phoneNumber", "하이픈(-) 없이 숫자만 입력해주세요."), "010-1234-5678") == "01012345678"


def test_digits_with_exact_length_pads_or_truncates(br):
    error = br.FieldError("phone", "전화번호 형식이 올바르지 않습니다 (숫자 11자)")
    assert len(br.propose_value(error, "0101234")) == 11
    assert br.propose_value(error, "010123456789012") == "01012345678"


def test_length_range_and_charset(br):
    error = br.FieldError("", "닉네임은 2~10자의 영문, 숫자, 한글만 가능합니다")
    value = br.propose_value(error, "argus-probe")
    assert 2 <= len(value) <= 10 and value.isalnum()


def test_minimum_and_maximum_phrases(br):
    assert len(br.propose_value(br.FieldError("t", "최소 8자 이상이어야 합니다"), "abc")) >= 8
    assert len(br.propose_value(br.FieldError("t", "must be at most 5 characters"), "abcdefgh")) == 5
    assert br.propose_value(br.FieldError("n", "must be at least 2"), 1) == 2


def test_duplicate_gets_a_unique_value_that_keeps_its_shape(br):
    mail = br.propose_value(br.FieldError("email", "이미 사용 중인 이메일입니다"), "a@example.com")
    assert mail.endswith("@example.com") and mail != "a@example.com"
    nick = br.propose_value(br.FieldError("nickname", "이미 사용 중인 닉네임 (2~10자)"), "safeNickname")
    assert nick != "safeNickname" and len(nick) <= 10


def test_unknown_rule_leaves_value_alone(br):
    assert br.propose_value(br.FieldError("x", "something odd"), "keep") == "keep"
    assert br.propose_value(br.FieldError("x", "숫자 3자"), True) is True


# ---- the retry loop -------------------------------------------------------------
def mate_like_server(params, body):
    """Rejects a hyphenated phone, then a long/hyphenated nickname."""
    phone = str(body.get("phoneNumber", ""))
    if not phone.isdigit():
        return Resp(400, spring_error("VALID_001", "입력값이 올바르지 않습니다", [{"field": "phoneNumber", "message": "하이픈(-) 없이 숫자만 입력해주세요."}]))
    nickname = str(body.get("nickname", ""))
    if not (2 <= len(nickname) <= 10 and nickname.isalnum()):
        return Resp(400, spring_error("USER_007", "닉네임은 2~10자의 영문, 숫자, 한글만 가능합니다"))
    return Resp(201, {"success": True})


def test_loop_repairs_both_errors_in_sequence(br):
    body = {"email": "a@example.com", "nickname": "argus-probe", "phoneNumber": "010-1234-5678"}
    result = br.repair_request(mate_like_server, {}, body)
    assert result.status == 201 and result.rounds == 2
    assert body["phoneNumber"] == "01012345678" and body["nickname"].isalnum()
    assert body["email"] == "a@example.com"  # untouched
    assert {c["field"] for c in result.changes} == {"phoneNumber", "nickname"}


def test_query_parameters_are_repaired_too(br):
    def server(params, body):
        phone = str(params.get("phoneNumber", ""))
        if len(phone) == 11 and phone.isdigit():
            return Resp(200, {"ok": True})
        return Resp(400, spring_error("VALID_003", "전화번호 형식이 올바르지 않습니다 (숫자 11자)"))

    params = {"phoneNumber": "010-1234-5678", "userId": 1}
    result = br.repair_request(server, params, {})
    assert result.status == 200 and params["phoneNumber"] == "01012345678" and params["userId"] == 1


def test_non_validation_failures_are_not_retried(br):
    calls = []

    def server(params, body):
        calls.append(1)
        return Resp(500, spring_error("SERVER_001", "서버 내부 오류"))

    result = br.repair_request(server, {}, {"a": "b"})
    assert result.status == 500 and len(calls) == 1 and result.changes == []


def test_gives_up_after_max_rounds(br):
    calls = []

    def server(params, body):
        calls.append(1)
        return Resp(400, spring_error("VALID_001", "x", [{"field": "name", "message": "최소 100자 이상"}]))

    br.repair_request(server, {}, {"name": "a"}, max_rounds=3)
    assert len(calls) <= 4


def test_unrepairable_validation_error_stops_without_looping(br):
    calls = []

    def server(params, body):
        calls.append(1)
        return Resp(400, spring_error("APPLY_004", "이미 지원한 프로젝트입니다"))

    result = br.repair_request(server, {}, {"message": "hello"})
    assert result.status == 400 and len(calls) <= 2
