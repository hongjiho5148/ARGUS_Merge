"""xss judgement helpers split out of zap_runner.py (code moved verbatim)."""

import difflib
import html
import re
import urllib.parse


def normalize_reflection_text(value: str = "") -> str:
    if not value:
        return ""
    text = str(value)
    for _ in range(2):
        text = html.unescape(urllib.parse.unquote_plus(text))
        text = (
            text.replace("\\/", "/")
                .replace("\\u003c", "<")
                .replace("\\u003C", "<")
                .replace("\\u003e", ">")
                .replace("\\u003E", ">")
                .replace("\\u002f", "/")
                .replace("\\u002F", "/")
        )
    return text


def get_payload_reflection(payload, response_body, baseline_body=None):
    if not payload or not response_body:
        return None

    # Baseline이 지정된 경우 diff 분석을 수행해 새로 추가된 영역만 분리
    active_text = response_body
    if baseline_body:
        try:
            # difflib.ndiff를 활용해 추가(+)된 라인 및 문자들을 결합하여 새로 유입된 문자열 추출
            diff = difflib.ndiff(baseline_body.splitlines(keepends=True), response_body.splitlines(keepends=True))
            added_lines = [line[2:] for line in diff if line.startswith('+ ')]
            active_text = "".join(added_lines)
            if not active_text.strip():
                # 추가된 신규 텍스트가 없는 경우 반사되지 않은 것으로 확정
                return None
        except Exception:
            active_text = response_body

    payload_variants = dict.fromkeys([
        payload,
        normalize_reflection_text(payload),
        html.escape(payload),
        html.escape(payload, quote=False),
        urllib.parse.quote(payload),
        urllib.parse.quote_plus(payload),
        payload.replace("/", "\\/"),
        payload.replace("<", "\\u003c").replace(">", "\\u003e"),
        payload.replace("<", "\\u003C").replace(">", "\\u003E"),
        payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("/", "\\/"),
        payload.replace("<", "\\u003C").replace(">", "\\u003E").replace("/", "\\/"),
    ])
    body_variants = {
        active_text,
        normalize_reflection_text(active_text),
    }

    for body in body_variants:
        for variant in payload_variants:
            normalized_variant = normalize_reflection_text(variant)
            if normalized_variant and normalized_variant.lower() in body.lower():
                return variant
    return None


def is_payload_reflected(payload, response_body, baseline_body=None):
    return get_payload_reflection(payload, response_body, baseline_body) is not None


def find_json_keypaths_containing(value, payload, prefix=""):
    matches = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            matches.extend(find_json_keypaths_containing(child, payload, path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            path = f"{prefix}.{index}" if prefix else str(index)
            matches.extend(find_json_keypaths_containing(child, payload, path))
    elif isinstance(value, str) and payload in value:
        matches.append(prefix)
    return matches


def normalize_response_param_path(path):
    parts = [part for part in str(path).split(".") if part and not part.isdigit()]
    if parts and parts[0] in {"data", "items", "result", "results"}:
        parts = parts[1:]
    if parts and parts[0].endswith("s") and len(parts) > 1:
        parts = parts[1:]
    return ".".join(parts) if parts else path


def infer_reflected_response_params(response, payload):
    try:
        body = response.json()
    except Exception:
        return []
    params = []
    for path in find_json_keypaths_containing(body, payload):
        normalized = normalize_response_param_path(path)
        if normalized and normalized not in params:
            params.append(normalized)
    return params


def detect_xss_reflection_context(payload, response_body):
    if not payload or not response_body:
        return "unknown"

    bodies = [
        response_body,
        html.unescape(response_body),
        urllib.parse.unquote_plus(response_body),
    ]
    payload_re = re.escape(payload)
    for body in bodies:
        if re.search(r"<[^>]+\s[\w:-]+\s*=\s*(['\"])" + payload_re + r"\1", body, re.IGNORECASE):
            return "HTML attribute"
        if re.search(r">\s*" + payload_re + r"\s*<", body, re.IGNORECASE):
            return "HTML body"
        if re.search(r"(['\"])" + payload_re + r"\1", body, re.IGNORECASE):
            return "JSON/String value"
    return "encoded/reflected"


def classify_xss_response(payload, response_body, content_type, method="GET", is_mutation=False, response_headers=None, baseline_body=None):
    if not payload or not response_body:
        return None

    response_lower = response_body.lower()
    decoded_response_body = normalize_reflection_text(response_body)
    decoded_response_lower = decoded_response_body.lower()
    content_type_lower = (content_type or "").lower()
    source_indicators = ["location", "search", "document.cookie", "document.location", "url", "query", "param", "input"]
    dom_sink_patterns = [
        "document.write",
        "document.writeln",
        "innerhtml",
        "outerhtml",
        "insertadjacenthtml",
        "eval(",
        "settimeout(",
        "setinterval(",
        "window.location",
        "document.location",
        "location.href",
        "appendchild",
        "insertbefore",
    ]
    # 응답 본문에 페이로드가 실행 가능한 형태로 반사되었는지 판별하는 마커
    executable_markers = ["<script", "</script>", "onerror=", "onload=", "onclick=", "javascript:", "<svg", "<img", "<iframe"]

    reflected_variant = get_payload_reflection(payload, response_body, baseline_body)
    has_payload_in_body = reflected_variant is not None
    has_dom_sink = any(pattern in decoded_response_lower for pattern in dom_sink_patterns)
    has_source_indicator = any(indicator in decoded_response_lower for indicator in source_indicators)
    has_user_input_reference = "userinput" in response_lower or "input" in response_lower
    has_executable_marker = any(marker in decoded_response_lower for marker in executable_markers)

    # ── DOM XSS 의심 패턴 (정적 분석으로는 확정 불가 → Informational 강등) ──────────────
    # DOM XSS 실제 탐지는 Playwright 헤드리스 브라우저를 통한 동적 실행 검증만 가능.
    # 여기서는 "의심 패턴이 발견됨"을 리포팅하고 Playwright 위임 힌트를 남긴다.
    if has_dom_sink and (has_source_indicator or has_user_input_reference) and (has_payload_in_body or has_executable_marker):
        detected_sinks = ", ".join([p for p in dom_sink_patterns if p in response_lower])
        return {
            "kind": "dom_suspect",
            "custom_type": "DOM_XSS_SUSPECT",
            "risk": "Informational",
            "confidence": "Low",
            "alert": "[정적 분석] DOM XSS 의심 패턴 감지 — Playwright 동적 검증 필요",
            "description": (
                "응답 본문에서 DOM 삽입 지점과 사용자 입력 경로 신호가 동시에 발견되었습니다. "
                "단, 정적 텍스트 분석으로는 실제 취약 여부를 확정할 수 없습니다. "
                "Playwright 헤드리스 브라우저에서 페이지를 직접 로드하고 alert() 발화 여부를 모니터링하는 동적 검증이 필요합니다."
            ),
            "evidence": f"응답 본문에 DOM 삽입 지점({detected_sinks})이 감지되었습니다.",
            "playwright_action": "url_param_injection",
        }

    if not has_payload_in_body:
        return None

    is_html_context = "html" in content_type_lower
    is_json_context = "json" in content_type_lower
    reflection_context = detect_xss_reflection_context(payload, response_body)

    # ── Reflected XSS ──────────────────────────────────────────────────────────────────
    # POST/PUT 등 쓰기 메서드라도 응답에 페이로드가 에코백 되면 Reflected XSS.
    # 진짜 Stored XSS는 POST 저장 후 GET 재조회 응답에서만 판정 가능하며,
    # 해당 로직은 run_zap_scan() 내부의 2단계 저장-재조회 루프에서 별도 처리한다.
    if (is_html_context or is_json_context) and has_executable_marker:
        if is_html_context:
            risk = "Medium"
            confidence = "High"
            desc = (
                "응답 본문에 XSS 공격 페이로드가 HTML 인코딩 없이 그대로 반사되었습니다. "
                "프론트엔드에서 직접 화면에 출력하거나 innerHTML 등으로 이 값을 렌더링할 경우 브라우저 런타임에서 즉시 악성 스크립트가 실행됩니다. "
                f"(Content-Type: {content_type}, Context: {reflection_context})"
            )
            sol = "특수 문자(<, >, &, \", ')가 입력되거나 출력되는 시점에 HTML Entity Escape 처리를 적용하여 브라우저가 스크립트로 오인하지 않도록 차단하십시오."
        else:
            # JSON context 내 반사 케이스 (프론트엔드 바인딩 위협)
            risk = "Low"
            confidence = "Medium"
            desc = (
                "요청으로 전송된 XSS 페이로드가 API 응답 JSON 데이터 내에 필터링 없이 그대로 출력되었습니다. "
                "모던 프론트엔드 프레임워크(React, Vue 등)의 기본 이스케이프 정책 덕분에 브라우저에서의 실제 실행은 제한될 수 있습니다. "
                "다만, dangerouslySetInnerHTML, v-html과 같은 안전하지 않은 속성 바인딩을 사용하거나, WebView/이메일 템플릿 등으로 활용 영역이 확장될 경우 즉시 XSS 공격 경로로 이어질 위험이 존재합니다. (서버 측의 2차 방어선 누락)"
            )
            sol = "프론트엔드 수준의 방어에만 의존하지 말고, 서버 측 인풋 유효성 검증 단(XssEscapeServletFilter 등) 또는 JSON Response 직렬화 단계에서 특수 문자 필터링을 적용하여 일관적인 데이터 보안 상태를 유지하십시오."

        return {
            "kind": "reflected",
            "custom_type": "40012",
            "risk": risk,
            "confidence": confidence,
            "alert": "Reflected Cross-Site Scripting (Reflected XSS) Vulnerability",
            "description": desc,
            "solution": sol,
            "evidence": f"Response body reflected payload variant '{reflected_variant}' from original payload '{payload}'.",
            "reflection_context": reflection_context,
            "reflected_variant": reflected_variant,
        }

    return None
