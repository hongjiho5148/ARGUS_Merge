"""http evidence helpers split out of zap_runner.py (code moved verbatim)."""

import json


def format_http_request(req_obj):
    try:
        hdrs = "\n".join(f'  "{k}": "{v}"' for k, v in req_obj.headers.items())
        body = req_obj.body
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="ignore")
        body_str = body if body else ""
        return f"{req_obj.method} {req_obj.url}\n\nHeaders:\n{{\n{hdrs}\n}}\n\nBody:\n{body_str}"
    except Exception as e:
        return f"Request formatting error: {e}"


def find_containing_record(body: str, needle: str):
    """If body is JSON and needle lives inside one specific object in
    a list (e.g. one post out of a feed array), return that object
    alone, pretty-printed — a whole valid record instead of an
    arbitrary character slice that could cut a JSON object in half."""
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return None

    def _search(node):
        if isinstance(node, dict):
            try:
                serialized = json.dumps(node, ensure_ascii=False)
            except (TypeError, ValueError):
                return None
            if needle not in serialized:
                return None
            for value in node.values():
                deeper = _search(value)
                if deeper is not None:
                    return deeper
            return node
        if isinstance(node, list):
            for item in node:
                found = _search(item)
                if found is not None:
                    return found
        return None

    record = _search(data)
    if record is None:
        return None
    try:
        pretty = json.dumps(record, ensure_ascii=False, indent=2)
    except (TypeError, ValueError):
        return None
    return f"(취약점이 발견된 항목만 표시, 전체 응답에서 발췌)\n{pretty}"


def windowed_body(body: str, needle: str = "", context: int = 800, max_len: int = 3000) -> str:
    """Keep the evidence readable without losing the payload: save
    just the JSON record containing it (falling back to a character
    window) instead of the first N characters, so a payload stored
    deep in a list response isn't truncated away."""
    if not body or len(body) <= max_len:
        return body
    if needle:
        record = find_containing_record(body, needle)
        if record is not None:
            return record
        idx = body.find(needle)
        if idx != -1:
            start = max(0, idx - context)
            end = min(len(body), idx + len(needle) + context)
            prefix = "... (앞부분 생략) ...\n" if start > 0 else ""
            suffix = "\n... (뒷부분 생략, 취약점 증거 주변만 저장됨) ..." if end < len(body) else ""
            return f"{prefix}{body[start:end]}{suffix}"
    return body[:max_len] + "\n... (뒷부분 생략, 응답이 너무 길어 앞부분만 저장됨) ..."


def format_http_response(res_obj, needle: str = ""):
    try:
        hdrs = "\n".join(f'  "{k}": "{v}"' for k, v in res_obj.headers.items())
        body_str = windowed_body(res_obj.text if res_obj.text else "", needle)
        return f"HTTP/1.1 {res_obj.status_code} {res_obj.reason}\n\nHeaders:\n{{\n{hdrs}\n}}\n\nBody:\n{body_str}"
    except Exception as e:
        return f"Response formatting error: {e}"


def extract_request_parts(req_obj, body_json=None, query_params=None):
    """Playwright / Selenium 자동화 재현을 위해 요청 구성 요소를 파싱된 딕셔너리로 반환합니다."""
    try:
        # 헤더 딕셔너리 (Playwright 재현 시 headers 옵션에 그대로 전달)
        parsed_headers = dict(req_obj.headers)

        # 바디: 이미 python dict 형태로 전달된 경우 그대로 사용, 아니면 raw body 파싱 시도
        parsed_body = None
        if body_json is not None:
            parsed_body = body_json
        else:
            raw_body = req_obj.body
            if isinstance(raw_body, bytes):
                raw_body = raw_body.decode("utf-8", errors="ignore")
            if raw_body:
                try:
                    parsed_body = json.loads(raw_body)
                except Exception:
                    parsed_body = raw_body  # JSON 파싱 실패 시 raw 문자열 유지

        parsed_query = query_params or {}

        content_type = parsed_headers.get("Content-Type", parsed_headers.get("content-type", ""))
        auth_header = parsed_headers.get("Authorization", parsed_headers.get("authorization", ""))
        cookie_header = parsed_headers.get("Cookie", parsed_headers.get("cookie", ""))

        # Playwright fetch() 재현용 스크립트 스텁 생성
        body_snippet = json.dumps(parsed_body, ensure_ascii=False) if isinstance(parsed_body, dict) else repr(parsed_body)
        query_snippet = ("?" + "&".join(f"{k}={v}" for k, v in parsed_query.items())) if parsed_query else ""
        replay_script = (
            f"// [Playwright] 재현 테스트 스크립트\n"
            f"const response = await request.fetch('{req_obj.url}{query_snippet}', {{\n"
            f"  method: '{req_obj.method}',\n"
            f"  headers: {{\n"
            f"    'Content-Type': '{content_type}',\n"
            f"    'Authorization': '{auth_header}',\n"
            f"    'Cookie': '{cookie_header}'\n"
            f"  }},\n"
            f"  data: {body_snippet}\n"
            f"}});\n"
            f"// 검증: 응답 본문 내 공격 페이로드 반사 확인\n"
            f"const body = await response.text();\n"
            f"expect(body).toContain('/* 공격 페이로드 삽입 */');"
        )

        return {
            "parsed_request_headers": parsed_headers,
            "parsed_request_body": parsed_body,
            "parsed_request_query": parsed_query,
            "auth_token_used": auth_header,
            "login_required": bool(auth_header),
            "replay_script": replay_script,
        }
    except Exception as e:
        return {
            "parsed_request_headers": {},
            "parsed_request_body": None,
            "parsed_request_query": {},
            "auth_token_used": "",
            "login_required": False,
            "replay_script": f"// extract_request_parts error: {e}",
        }
