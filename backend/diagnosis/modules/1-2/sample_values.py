"""Shared sample-value heuristics for injection scan target building."""

from __future__ import annotations

GENERIC_SAMPLES = frozenset({"", "argus-test", "test", "null", "undefined"})

# Common API enum-like query/body fields when OpenAPI sample is missing.
PARAM_NAME_FALLBACKS: dict[str, tuple[str, ...]] = {
    "type": ("REVIEW", "PHOTO", "POST", "NOTICE"),
    "status": ("ACTIVE", "PUBLISHED", "OPEN", "ENABLED"),
    "role": ("USER", "MEMBER", "GUEST"),
    "category": ("GENERAL", "DEFAULT"),
    "sort": ("createdAt", "id", "name"),
    "order": ("desc", "asc"),
    "state": ("ACTIVE", "OPEN"),
}


def is_generic_sample(value: str | None) -> bool:
    if value is None:
        return True
    return str(value).strip().lower() in GENERIC_SAMPLES


def fallback_samples_for_name(name: str, *, param_type: str = "string") -> list[str]:
    key = name.lower()
    if key in PARAM_NAME_FALLBACKS:
        return list(PARAM_NAME_FALLBACKS[key])
    if param_type in ("integer", "number"):
        return ["0", "1", "20"]
    if key.endswith("id"):
        return ["1"]
    if param_type == "boolean":
        return ["false", "true"]
    return []


def pick_sample_value(
    name: str,
    *,
    param_type: str = "string",
    sample: str | None = None,
) -> str:
    # API Tree에 명시된 example 값 사용
    # string 같은 무의미 값 제외
    if sample is not None and str(sample).strip() and not is_generic_sample(sample):
        return str(sample)
    # 파라미터 이름으로 정상값 추측 (ex: sort -> "createdAt")
    key = name.lower()
    fallbacks = fallback_samples_for_name(key, param_type=param_type)
    if fallbacks:
        return fallbacks[0]
    # 타입보고 정상값 예측 후 넣기
    if param_type in ("integer", "number"):
        return "1"
    if param_type == "boolean":
        return "false"
    # 이름이  ~id로 끝난다면 식별자로 보고 1
    if key.endswith("id"):
        return "1"
    # 모두 실패 시 최후의 기본값
    return "argus-test"


def alternate_samples(
    name: str,
    *,
    param_type: str = "string",
    current: str | None = None,
) -> list[str]:
    """Ordered candidates for baseline stabilization retries."""
    seen: list[str] = []

    def add(value: str | None) -> None:
        if value is None:
            return
        text = str(value).strip()
        if not text or text in seen:
            return
        seen.append(text)

    add(current)
    for value in fallback_samples_for_name(name, param_type=param_type):
        add(value)
    if param_type in ("integer", "number"):
        for value in ("0", "1", "20"):
            add(value)
    elif param_type == "boolean":
        add("false")
        add("true")
    elif name.lower().endswith("id"):
        add("1")
    add("argus-test")
    return seen
