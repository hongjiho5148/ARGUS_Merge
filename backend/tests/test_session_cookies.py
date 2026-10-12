"""Session cookies are derived from the login response, not guessed."""

from diagnosis.session_cookies import cookies_from_session, parse_set_cookie

ACCESS = "accessToken=abc.def.ghi; Path=/; Max-Age=3600; Expires=Mon, 12 Oct 2026 07:00:00 GMT; Secure; HttpOnly; SameSite=None"
REFRESH = "refreshToken=rrr; Path=/; Max-Age=604800; Secure; HttpOnly; SameSite=Lax"


def test_parse_set_cookie_reads_value_and_attributes():
    name, value, attrs = parse_set_cookie(ACCESS)
    assert (name, value) == ("accessToken", "abc.def.ghi")
    assert attrs["samesite"] == "None" and attrs["secure"] and attrs["httponly"] and attrs["path"] == "/"


def test_value_containing_equals_sign_survives():
    assert parse_set_cookie("sid=a=b==; Path=/")[1] == "a=b=="


def test_set_cookie_lines_become_cookies_and_attributes():
    cookies, attrs = cookies_from_session({"set_cookie_lines": [ACCESS, REFRESH]})
    assert cookies == {"accessToken": "abc.def.ghi", "refreshToken": "rrr"}
    assert attrs["accessToken"]["samesite"] == "None" and attrs["refreshToken"]["samesite"] == "Lax"


def test_explicit_cookies_win_over_parsed_lines():
    cookies, _ = cookies_from_session({"cookies": {"accessToken": "explicit"}, "set_cookie_lines": [ACCESS]})
    assert cookies["accessToken"] == "explicit"


def test_cookie_the_server_is_clearing_is_ignored():
    cookies, _ = cookies_from_session({"set_cookie_lines": ["sid=; Path=/; Max-Age=0", "other=1; Path=/"]})
    assert cookies == {"other": "1"}


def test_cookie_delivered_token_falls_back_to_the_reported_cookie_name():
    cookies, attrs = cookies_from_session({"delivery": "cookie", "cookie_name": "session", "token": "Bearer tok"})
    assert cookies == {"session": "tok"} and attrs == {}


def test_bearer_sessions_have_no_cookies():
    assert cookies_from_session({"delivery": "bearer", "cookie_name": "session", "token": "tok"}) == ({}, {})
    assert cookies_from_session(None) == ({}, {})


def test_malformed_lines_are_skipped():
    assert cookies_from_session({"set_cookie_lines": ["", "nonsense", None]}) == ({}, {})
