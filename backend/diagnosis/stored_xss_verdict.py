"""Three-level Stored XSS verdict shared by the scanner, capture and report steps.

    candidate  server-side storage weakness: the payload is stored and returned
               unchanged, but the response is data (JSON), so whether it runs
               depends on how a client renders it (still a finding: no input
               validation / output encoding on the server)
    high       payload came back unescaped inside an HTML document
    confirmed  a real browser executed the payload (alert dialog fired)

Browser evidence can only raise a finding to ``confirmed`` or lower it to
``candidate`` (the page showed the payload as inert text); when the page could
not be inspected the response-based level stands.
"""

from __future__ import annotations

import re

CANDIDATE = "candidate"
HIGH = "high"
CONFIRMED = "confirmed"

BROWSER_EXECUTED = "executed"
BROWSER_INERT_TEXT = "inert_text"
BROWSER_NOT_FOUND = "not_found"
BROWSER_NOT_CHECKED = "not_checked"

_EVENT_HANDLER_RE = re.compile(r"\bon[a-z]+\s*=", re.IGNORECASE)
_MARKER_RE = re.compile(r"ARGUS_[A-Za-z0-9_]+")

# risk, confidence, validation_status per level
_LEVEL_RATING = {
    CANDIDATE: ("Medium", "Medium", "Potential"),
    HIGH: ("High", "Medium", "True Positive"),
    CONFIRMED: ("High", "High", "True Positive"),
}


def grade_response(content_type: str) -> str:
    """Response-only level: HTML is directly renderable, anything else is data."""
    return HIGH if "html" in str(content_type or "").lower() else CANDIDATE


def runs_without_user_gesture(payload: str) -> bool:
    """Event-handler payloads fire when inserted via innerHTML; <script> tags do not."""
    return bool(_EVENT_HANDLER_RE.search(payload or ""))


def order_for_browser_proof(payloads: list[str]) -> list[str]:
    """Stable sort that tries payloads able to run through innerHTML first."""
    return sorted(payloads, key=lambda p: 0 if runs_without_user_gesture(p) else 1)


def final_level(response_level: str, browser_status: str) -> str:
    if browser_status == BROWSER_EXECUTED:
        return CONFIRMED
    if browser_status == BROWSER_INERT_TEXT:
        return CANDIDATE
    return response_level if response_level in _LEVEL_RATING else CANDIDATE


def rating(level: str) -> tuple[str, str, str]:
    """(risk, confidence, validation_status) for a level."""
    return _LEVEL_RATING.get(level, _LEVEL_RATING[CANDIDATE])


_SERVER_SIDE_FIX = "서버 측 입력 검증과 출력 인코딩(새니타이징)을 적용하세요."


def reason(level: str, browser_status: str) -> str:
    if level == CONFIRMED:
        return "POST로 저장한 payload가 조회 화면을 연 실제 브라우저에서 실행됨(alert 다이얼로그 발생)을 확인했습니다."
    if browser_status == BROWSER_INERT_TEXT:
        return (
            "서버가 입력을 검증하지 않고 payload를 그대로 저장·반환합니다. 현재 프론트는 이를 이스케이프된 텍스트로만 "
            "표시해 브라우저에서 실행되지는 않았으나, 다른 클라이언트나 innerHTML 등 다른 렌더링 경로에서는 실행될 수 있습니다. "
            + _SERVER_SIDE_FIX
        )
    if level == HIGH:
        return (
            "payload가 HTML 응답 본문에 이스케이프 없이 반사됩니다. "
            "브라우저 실행 확인은 이루어지지 않았습니다(화면을 찾지 못했거나 캡처 미수행). " + _SERVER_SIDE_FIX
        )
    return (
        "서버가 입력을 검증하지 않고 payload를 조회 API(JSON) 응답에 변형 없이 저장·반환합니다. "
        "프론트엔드 렌더링 방식에 따라 실행 여부가 달라지며 브라우저 실행은 확인되지 않았습니다. " + _SERVER_SIDE_FIX
    )


def browser_status_from_capture(dialogs: list[dict] | None, payload_scroll: dict | None, payload: str) -> str:
    """Interpret what the capture browser saw while the page was open."""
    found = _MARKER_RE.search(payload or "")
    marker = found.group(0) if found else ""
    for event in dialogs or []:
        # A dialog only counts when it carries this payload's own marker, so an
        # alert raised by the site itself is not mistaken for the injected script.
        if not marker or marker in str(event.get("message") or ""):
            return BROWSER_EXECUTED
    if isinstance(payload_scroll, dict) and payload_scroll.get("found"):
        return BROWSER_INERT_TEXT
    return BROWSER_NOT_FOUND
