"""Repair a rejected baseline request from the server's own validation message.

The scanner builds a "normal" request from the API spec and only injects payloads
when that request is accepted. A 400/422 normally means the sample values broke a
rule the spec does not describe (no hyphens in phone numbers, 2-10 character
nicknames, a unique e-mail, ...). The error response usually states the rule, so
read it, adjust the offending fields and retry a few times before giving up.

Only the values of fields already present in the request are changed, and never
anything but 400/409/422 responses are acted on, so a repair cannot widen what the
scanner sends.
"""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass, field
from typing import Any, Callable

REPAIRABLE_STATUSES = (400, 409, 422)
MAX_ROUNDS = 4

_FIELD_KEYS = ("field", "name", "property", "propertyPath", "path", "param", "parameter", "pointer")
_MESSAGE_KEYS = ("message", "defaultMessage", "msg", "reason", "error", "description", "detail")

# Generic words (Korean and English) that point at a field by meaning, so a
# message that names the concept but not the JSON key can still be matched.
_CONCEPT_TOKENS: dict[str, tuple[str, ...]] = {
    "전화": ("phone", "tel", "mobile"), "휴대": ("phone", "mobile", "tel"), "연락처": ("contact", "phone", "tel"),
    "이메일": ("email", "mail"), "메일": ("email", "mail"),
    "비밀번호": ("password", "pwd", "passwd"), "패스워드": ("password", "pwd"),
    "닉네임": ("nickname", "nick"), "이름": ("name",), "제목": ("title", "subject"), "내용": ("content", "body", "message"),
    "마감": ("end", "deadline", "due", "expire"), "시작": ("start", "begin"), "날짜": ("date",), "생년": ("birth",),
    "인원": ("count", "capacity", "member"), "금액": ("price", "amount", "cost"), "주소": ("address", "addr"),
    "링크": ("link", "url"), "번호": ("number", "no"),
}

_DUPLICATE_RE = re.compile(r"already|duplicate|exists|in use|taken|unique|이미|중복|사용 중|사용중", re.IGNORECASE)
_NO_HYPHEN_RE = re.compile(r"하이픈|hyphen|dash|대시|\(-\)|'-'|\"-\"", re.IGNORECASE)
_NO_SPACE_RE = re.compile(r"공백[^.,]{0,6}(없|제외|불가)|without (any )?(space|whitespace)|no (space|whitespace)", re.IGNORECASE)
_DIGITS_ONLY_RE = re.compile(r"숫자만|숫자\s*\d+\s*자|only digits|digits only|numeric(al)? only|numbers only", re.IGNORECASE)
_LETTERS_NUMBERS_RE = re.compile(r"영문|한글|letters|alphanumeric|alpha-?numeric", re.IGNORECASE)
_RANGE_RES = (
    re.compile(r"(\d+)\s*[~\-–～]\s*(\d+)\s*(?:자|글자|characters?|chars?|길이|digits?)?"),
    re.compile(r"between\s+(\d+)\s+and\s+(\d+)", re.IGNORECASE),
    re.compile(r"(\d+)\s*(?:자|글자)?\s*(?:이상)\s*(?:,|및|~)?\s*(\d+)\s*(?:자|글자)?\s*(?:이하)"),
)
_MIN_RES = (
    re.compile(r"(?:at least|min(?:imum)?(?: of)?|최소)\s*(\d+)", re.IGNORECASE),
    re.compile(r"(\d+)\s*(?:자|글자|characters?|chars?)?\s*이상", re.IGNORECASE),
)
_MAX_RES = (
    re.compile(r"(?:at most|max(?:imum)?(?: of)?|최대)\s*(\d+)", re.IGNORECASE),
    re.compile(r"(\d+)\s*(?:자|글자|characters?|chars?)?\s*이하", re.IGNORECASE),
)
_EXACT_RE = re.compile(r"(?:숫자|digits?|exactly)\s*(\d+)\s*(?:자|글자|digits?|characters?)?", re.IGNORECASE)


@dataclass
class FieldError:
    field: str  # "" when the message names no field
    message: str


@dataclass
class RepairResult:
    status: int | None
    response: Any = None
    changes: list[dict] = field(default_factory=list)
    rounds: int = 0


# ---- reading the error ------------------------------------------------------
def _leaf(name: str) -> str:
    text = str(name or "").strip()
    text = re.sub(r"^(body|query|path|form)[./\[]", "", text, flags=re.IGNORECASE).strip("[]")
    return text.split(".")[-1].replace("[0]", "") if text else ""


def _pick(mapping: dict, keys: tuple[str, ...]) -> str:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, (str, int)) and str(value).strip():
            return str(value)
    return ""


def _collect(node: Any, out: list[FieldError], depth: int = 0) -> None:
    if depth > 5:
        return
    if isinstance(node, list):
        for item in node:
            if isinstance(item, dict):
                loc = item.get("loc")
                name = _leaf(loc[-1]) if isinstance(loc, list) and loc else _leaf(_pick(item, _FIELD_KEYS))
                message = _pick(item, _MESSAGE_KEYS)
                if message and (name or "msg" in item or "defaultMessage" in item):
                    out.append(FieldError(name, message))
                    continue
            _collect(item, out, depth + 1)
    elif isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, str) and key not in _MESSAGE_KEYS and key not in {"code", "timestamp", "path", "status", "success"}:
                if depth and value.strip():
                    out.append(FieldError(_leaf(key), value))
            elif isinstance(value, list) and value and all(isinstance(v, str) for v in value) and key not in _MESSAGE_KEYS:
                out.extend(FieldError(_leaf(key), v) for v in value)
            else:
                _collect(value, out, depth + 1)


def extract_field_errors(response_text: str) -> list[FieldError]:
    """Field-level errors from the common shapes (Spring fieldErrors, pydantic
    loc/msg, DRF {field: [msg]}, {errors: {field: msg}}); when none are
    structured, the top-level message becomes one field-less error."""
    try:
        data = json.loads(response_text or "")
    except (TypeError, ValueError):
        return [FieldError("", response_text.strip()[:300])] if (response_text or "").strip() else []
    errors: list[FieldError] = []
    _collect(data, errors)
    errors = [e for e in errors if e.message]
    if errors:
        return errors
    nodes = [data] + ([data.get("error")] if isinstance(data, dict) and isinstance(data.get("error"), dict) else [])
    for node in nodes:
        if isinstance(node, dict):
            message = _pick(node, ("message", "msg", "detail", "error_description"))
            if message:
                return [FieldError("", message)]
    return []


# ---- deciding which field a message is about --------------------------------
def _normalized(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name or "").lower())


def match_fields(error: FieldError, paths: list[str]) -> list[str]:
    """Request fields (as dotted paths) this error is about: the named one, else
    fields whose key appears in the message or matches a concept word in it.
    Keys are compared by their last path segment."""
    leaves = {path: _normalized(path.split(".")[-1]) for path in paths}
    if error.field:
        wanted = _normalized(error.field)
        exact = [p for p, leaf in leaves.items() if leaf == wanted]
        if exact:
            return exact
        return [p for p, leaf in leaves.items() if wanted and leaf and (wanted in leaf or leaf in wanted)]
    message = error.message.lower()
    squashed = re.sub(r"[^a-z0-9]", "", message)
    hits = [p for p, leaf in leaves.items() if len(leaf) >= 3 and leaf in squashed]
    for concept, tokens in _CONCEPT_TOKENS.items():
        if concept in error.message:
            hits.extend(p for p, leaf in leaves.items() if p not in hits and any(t in leaf for t in tokens))
    return hits


# ---- producing a value that satisfies the rule ------------------------------
def _bounds(message: str) -> tuple[int | None, int | None]:
    for pattern in _RANGE_RES:
        found = pattern.search(message)
        if found:
            low, high = int(found.group(1)), int(found.group(2))
            if low <= high:
                return low, high
    low = next((int(m.group(1)) for p in _MIN_RES if (m := p.search(message))), None)
    high = next((int(m.group(1)) for p in _MAX_RES if (m := p.search(message))), None)
    if low is None and high is None:
        exact = _EXACT_RE.search(message)
        if exact:
            return int(exact.group(1)), int(exact.group(1))
    return low, high


def _fit_length(value: str, low: int | None, high: int | None, filler: str) -> str:
    if high is not None and len(value) > high:
        value = value[:high]
    if low is not None and len(value) < low:
        value = value + (filler * low)[: low - len(value)]
    return value


def _unique_suffix(value: str, high: int | None) -> str:
    tail = secrets.token_hex(2)
    if "@" in value:
        local, _, domain = value.partition("@")
        return f"{local.split('+')[0]}+{tail}@{domain}"
    head = value[: max(1, (high - len(tail)) if high else len(value))]
    return f"{head}{tail}"


def propose_value(error: FieldError, current: Any) -> Any:
    """A replacement for ``current`` that satisfies the rule in the message, or
    ``current`` unchanged when no rule could be read."""
    message = error.message
    if isinstance(current, bool) or current is None or isinstance(current, (dict, list)):
        return current
    low, high = _bounds(message)

    if isinstance(current, (int, float)):
        if low is not None and current < low:
            return low
        if high is not None and current > high:
            return high
        if re.search(r"양수|positive|0\s*보다|greater than 0", message, re.IGNORECASE) and current <= 0:
            return 1
        return current

    value = str(current)
    changed = value
    if _DUPLICATE_RE.search(message):
        changed = _unique_suffix(changed, high)
    if _NO_HYPHEN_RE.search(message):
        changed = changed.replace("-", "")
    if _NO_SPACE_RE.search(message):
        changed = re.sub(r"\s+", "", changed)
    if _DIGITS_ONLY_RE.search(message):
        digits = re.sub(r"\D", "", changed)
        changed = _fit_length(digits, low, high, "1234567890")
    elif _LETTERS_NUMBERS_RE.search(message) and not re.search(r"특수문자|special", message, re.IGNORECASE):
        cleaned = re.sub(r"[^0-9A-Za-z가-힣]", "", changed)
        changed = _fit_length(cleaned, low, high, "a1")
    elif low is not None or high is not None:
        changed = _fit_length(changed, low, high, "a1")
    if re.search(r"이메일|e-?mail", message, re.IGNORECASE) and "@" not in changed:
        changed = f"argus{secrets.token_hex(2)}@example.com"
    return changed


# ---- applying and retrying --------------------------------------------------
def _get_path(container: dict, path: str) -> tuple[dict, str] | None:
    """Locate ``path`` ("a.b" or top-level "a") in a nested dict."""
    node = container
    parts = path.split(".")
    for part in parts[:-1]:
        node = node.get(part) if isinstance(node, dict) else None
        if not isinstance(node, dict):
            return None
    return (node, parts[-1]) if isinstance(node, dict) and parts[-1] in node else None


def _flat_names(container: dict, prefix: str = "") -> list[str]:
    names: list[str] = []
    for key, value in container.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            names.extend(_flat_names(value, f"{path}."))
        else:
            names.append(path)
    return names


def repair_once(errors: list[FieldError], params: dict, body: dict) -> list[dict]:
    """Apply what the errors say to ``params`` / ``body`` in place."""
    changes: list[dict] = []
    for container_name, container in (("body", body), ("query", params)):
        if not isinstance(container, dict) or not container:
            continue
        names = _flat_names(container)
        for error in errors:
            for path in match_fields(error, names):
                located = _get_path(container, path)
                if located is None:
                    continue
                node, key = located
                before = node[key]
                after = propose_value(error, before)
                if after != before:
                    node[key] = after
                    changes.append({"in": container_name, "field": path, "from": before, "to": after, "because": error.message[:120]})
    return changes


def repair_request(
    send: Callable[[dict, dict], Any],
    params: dict | None,
    body: dict | None,
    *,
    max_rounds: int = MAX_ROUNDS,
) -> RepairResult:
    """Send, and while the server answers 400/409/422, repair and resend.

    ``send(params, body)`` returns an object with ``status_code`` and ``text``.
    ``params`` and ``body`` are updated in place with the accepted values."""
    params = params if params is not None else {}
    body = body if body is not None else {}
    response = send(params, body)
    result = RepairResult(status=getattr(response, "status_code", None), response=response)
    for _ in range(max_rounds):
        if result.status not in REPAIRABLE_STATUSES:
            break
        errors = extract_field_errors(getattr(response, "text", "") or "")
        changes = repair_once(errors, params, body)
        if not changes:
            break
        result.changes.extend(changes)
        result.rounds += 1
        response = send(params, body)
        result.status = getattr(response, "status_code", None)
        result.response = response
    return result
