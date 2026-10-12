import base64
import json
from typing import Any
import requests

from inventory.net import probe_url

def get_headers(token: str, cookie_name: str | None = None, delivery: str | None = None) -> dict[str, str]:
    token_str = str(token or "").strip()
    if not token_str:
        return {}
    delivery = str(delivery or "").lower()
    if delivery and delivery != "cookie":
        if token_str.startswith("Bearer "):
            token_str = token_str[len("Bearer "):].strip()
        return {"Authorization": f"Bearer {token_str}"}
    if cookie_name:
        return {"Cookie": f"{cookie_name}={token_str}"}
    if "=" in token_str and ";" not in token_str:
        return {"Cookie": token_str}
    # Neither a cookie name nor a delivery hint is known: a bearer header is the
    # common convention; guessing a cookie name would be tied to one site.
    return {"Authorization": f"Bearer {token_str}"}


def auth_headers_for_session(session: dict[str, Any] | None) -> dict[str, str]:
    if not session:
        return {}
    return get_headers(
        session.get("token", ""),
        str(session.get("cookie_name") or "") or None,
        str(session.get("delivery") or "") or None,
    )

def get_dynamic_user_id(
    account: dict,
    endpoints: list[dict],
    base_url_global: str,
    auth_headers: dict,
    logger=None,
    *,
    timeout: float = 5.0,
) -> str | None:
    """3단계 전략으로 대상 유저의 식별자를 동적으로 추출합니다."""
    # 1. 수동 설정값 확인
    raw_id = account.get("account_raw", {}).get("id")
    if raw_id and not ("-" in str(raw_id) and len(str(raw_id)) == 36):
        # UUID 형태가 아니라면(진짜 식별자일 확률 높음) 우선 사용
        if logger:
            logger(f"    [Dynamic ID] Step 1: Using configured raw ID -> {raw_id}")
        return str(raw_id)

    # 2. 프로필 API 조회 (세션 쿠키 플랫폼 완벽 대응)
    if logger:
        logger("    [Dynamic ID] Step 2: Hitting Profile API to extract ID from JSON...")
    profile_eps = [ep for ep in endpoints if any(k in ep.get("path", "").lower() for k in ["/me", "/profile", "/user/info"])]
    for ep in profile_eps:
        if ep.get("method", "GET").upper() != "GET": continue
        url = ep.get("base_url", base_url_global) + ep.get("path", "")
        try:
            res = requests.get(probe_url(url), headers=auth_headers, timeout=timeout, verify=False)
            if res.status_code == 200:
                data = res.json()
                # 우선순위: id -> userId -> memberId -> sub
                for key in ["id", "userId", "memberId", "member_id", "user_id", "sub"]:
                    val = data.get(key)
                    if val:
                        if logger:
                            logger(f"    [Dynamic ID] Step 2 Success: Extracted {val} from {url} response.")
                        return str(val)
        except Exception as e:
            print(f"    [Error] Exception hitting profile API: {e}")

    # 3. JWT 디코딩 (최후의 수단)
    if logger:
        logger("    [Dynamic ID] Step 3: Decoding JWT Token as fallback...")
    token = account.get("token", "")
    if token.count(".") == 2: # JWT 형태
        try:
            payload_b64 = token.split(".")[1]
            payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
            payload_json = json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))
            for key in ["id", "userId", "memberId", "sub"]:
                val = payload_json.get(key)
                if val:
                    if logger:
                        logger(f"    [Dynamic ID] Step 3 Success: Extracted {val} from JWT payload.")
                    return str(val)
        except Exception as e:
            if logger:
                logger(f"    [Dynamic ID] JWT Decoding failed: {e}")

    if logger:
        logger("    [Dynamic ID] Failed to dynamically extract User ID. Falling back to configured UUID if any.")
    return str(raw_id) if raw_id else None
