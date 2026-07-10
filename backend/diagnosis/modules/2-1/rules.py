"""Classify upload probe responses for 2-1 (악성코드파일 업로드).

Two independent checks, matching the two in-scope review conditions:

1. ``classify_extension_bypass``  — [조건 1] 허용되지 않은 확장자 차단 여부
2. ``detect_path_exposure``       — [조건 2] 업로드 경로/주소 노출 여부

[조건 3] 실행 권한 제한(파일시스템 실행 비트)은 HTTP 블랙박스 진단으로 관측이
불가능한 영역이라 범위에서 제외됐다 — 확인해봤던 execution-hint 휴리스틱은 제거함.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

_REJECT_STATUS = {400, 401, 403, 404, 405, 406, 409, 413, 415, 422}
_SERVER_ERROR_STATUS = {500, 501, 502, 503}

_FAILURE_MARKERS = re.compile(
    r'"success"\s*:\s*false|"error"\s*:|"status"\s*:\s*"?(error|fail(ed)?)"?', re.IGNORECASE
)

_UNIX_ABS_PATH = re.compile(
    r"(?<![\w./])(/(?:home|var|usr|opt|srv|app|data|etc|tmp|mnt)/[A-Za-z0-9_\-./]{2,})"
)
_WINDOWS_PATH = re.compile(r"[A-Za-z]:\\\\?[A-Za-z0-9_\-\\/. ]{2,}")
_INTERNAL_HOST = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}|127\.0\.0\.1|localhost|host\.docker\.internal)\b",
    re.IGNORECASE,
)
_JAVA_STACK_TRACE = re.compile(r"\bat [\w.$]+\([\w.]+\.java:\d+\)")

_URL_LIKE_KEY = re.compile(r"(?i)(url|path|location|filepath|key|storagepath)$")


@dataclass
class ExtensionIssue:
    severity: str
    reason: str
    accepted: bool


@dataclass
class ExposureIssue:
    severity: str
    kind: str
    sample: str
    location: str = "body"


def _looks_rejected(status: int | None, body: str) -> bool:
    if status is None:
        return True
    if status in _REJECT_STATUS:
        return True
    if status in _SERVER_ERROR_STATUS:
        return True
    if 200 <= status < 300 and body and _FAILURE_MARKERS.search(body):
        return True
    return False


def classify_extension_bypass(
    *,
    technique: str,
    expect_reject: bool,
    http_status: int | None,
    body: str,
) -> ExtensionIssue | None:
    """Return an issue when a disallowed-extension payload was NOT rejected."""
    if not expect_reject:
        # Baseline valid upload — flag only if the server rejected a legit file
        # (helps interpret every other finding: if baseline itself fails, the
        # endpoint/auth/fields are probably wrong rather than a real filter).
        if _looks_rejected(http_status, body):
            return ExtensionIssue(
                severity="info",
                reason="baseline_upload_rejected",
                accepted=False,
            )
        return None

    rejected = _looks_rejected(http_status, body)
    if rejected:
        return None

    if http_status is not None and 200 <= http_status < 300:
        return ExtensionIssue(
            severity="high",
            reason=f"disallowed_extension_accepted:{technique}",
            accepted=True,
        )

    # Anything else (3xx, unexpected 4xx not in reject set) — inconclusive, not a finding.
    return None


def _iter_string_values(obj: Any):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and _URL_LIKE_KEY.search(str(k)):
                yield v
            else:
                yield from _iter_string_values(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from _iter_string_values(item)


def _scan_text_for_paths(text: str, *, location: str) -> ExposureIssue | None:
    m = _WINDOWS_PATH.search(text)
    if m:
        return ExposureIssue(
            severity="medium", kind="windows_filesystem_path", sample=m.group(0), location=location
        )
    m = _UNIX_ABS_PATH.search(text)
    if m:
        return ExposureIssue(
            severity="medium", kind="unix_filesystem_path", sample=m.group(0), location=location
        )
    m = _INTERNAL_HOST.search(text)
    if m:
        return ExposureIssue(
            severity="low", kind="internal_host_or_ip", sample=m.group(0), location=location
        )
    return None


def detect_path_exposure(
    body: str, content_type: str = "", headers: dict[str, str] | None = None
) -> ExposureIssue | None:
    """[조건 2] 응답 본문 또는 헤더에 서버 내부 경로/사설 주소가 불필요하게
    노출되는지 확인.

    헤더는 ``Location``, ``X-File-Path`` 처럼 이름이 url/path/location 류로
    끝나는 것만 검사한다 — CORS(``Access-Control-Allow-Origin``) 같은 흔한
    헤더까지 다 뒤지면 개발용 localhost 오리진 하나로 모든 요청이 오탐 나기
    때문에, 본문 JSON 키 필터링과 동일한 ``_URL_LIKE_KEY`` 기준으로 좁힌다.
    """
    if headers:
        for name, value in headers.items():
            if not value or not _URL_LIKE_KEY.search(name):
                continue
            issue = _scan_text_for_paths(value, location=f"header:{name}")
            if issue:
                return issue

    if not body:
        return None

    candidates: list[str] = [body]
    if "json" in content_type.lower():
        try:
            parsed = json.loads(body)
            candidates = list(_iter_string_values(parsed)) or [body]
        except (json.JSONDecodeError, ValueError):
            pass

    for text in candidates:
        issue = _scan_text_for_paths(text, location="body")
        if issue:
            return issue

    m = _JAVA_STACK_TRACE.search(body)
    if m:
        return ExposureIssue(severity="medium", kind="stack_trace", sample=m.group(0), location="body")

    return None


