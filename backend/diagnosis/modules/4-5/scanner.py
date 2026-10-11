"""Orchestrate guideline 4-5 Access Control (Privilege Escalation) scan."""

from __future__ import annotations

import json
import requests
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from app.services.auth_probe_service import login_all_accounts
from diagnosis.context import DiagnosisContext
from diagnosis.result import DiagnosisFinding
from app.services import diagnosis_progress as dp

import sys
_MODULE_DIR = Path(__file__).resolve().parent
if str(_MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(_MODULE_DIR))

from g45_models import ScanResult
from g45_utils import _read_api_tree, json_field_matches
from g45_auth import auth_headers_for_session, get_dynamic_user_id
from g45_payloads import safe_body
from g45_discovery import build_resource_inventory, active_discovery_inventory
from inventory.net import probe_url

VALID_PROBE_MODES = {"base_only", "sample", "full"}

_ADMIN_PATH_RE = re.compile(r"(^|/)(admin|manage|management)[a-z0-9_\-]*(/|$)")
_DENIAL_KEYWORDS = [
    "권한", "접근 권한", "인증이 필요", "denied", "access denied", "unauthorized",
    "unauthenticated", "forbidden", "not allowed", "login required", "fail",
]
_PRIVILEGE_PARAM_KEYWORDS = [
    "role", "admin", "authority", "group", "usertype", "level",
    "permission", "privilege", "scope", "superuser",
]
_PRIVILEGE_PAYLOADS = [
    "ADMIN", "admin", "ROLE_ADMIN", "role_admin", "SUPER_ADMIN", "ROLE_SUPER_ADMIN",
    "administrator", "root", "true", "1",
]


def _extend_unique(defaults: list[str], extra) -> list[str]:
    merged = list(defaults)
    for item in extra if isinstance(extra, list) else []:
        text = str(item).strip()
        if text and text not in merged:
            merged.append(text)
    return merged


def _is_admin_endpoint(ep: dict, extra_markers: list[str]) -> bool:
    path = str(ep.get("path", "")).lower()
    if _ADMIN_PATH_RE.search(path) or any(marker.lower() in path for marker in extra_markers):
        return True
    host = (urlsplit(str(ep.get("base_url", ""))).hostname or "").lower()
    return host.split(".")[0].startswith("admin")


def _positive_int(value, default: int | None = None) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _float_in_range(value, default: float, *, low: float = 1.0, high: float = 60.0) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(parsed, high))


def _select_endpoints(endpoints: list[dict], *, probe_mode: str, sample_size: int | None, max_endpoints: int | None) -> list[dict]:
    if probe_mode == "sample" and sample_size:
        endpoints = endpoints[:sample_size]
    if max_endpoints:
        endpoints = endpoints[:max_endpoints]
    return endpoints


def _first_inventory_value(inventory: dict, preferred_keys: list[str]) -> str | None:
    normalized = {str(k).lower(): v for k, v in inventory.items()}
    for key in preferred_keys:
        values = normalized.get(key.lower())
        if values:
            return str(values[0])
    return None


def run_g45_scan(ctx: DiagnosisContext, module_dir: Path) -> ScanResult:
    stats = {"scanned_endpoints": 0, "admin_endpoints": 0}
    findings = []
    
    # 1. Load accounts
    raw = ctx.raw_config or {}
    options = raw.get("diagnosis_4_5") or {}
    if not isinstance(options, dict):
        options = {}
    probe_mode = str(options.get("probe_mode") or "full").strip().lower()
    if probe_mode not in VALID_PROBE_MODES:
        probe_mode = "full"
    sample_size = _positive_int(options.get("sample_size"), 50)
    max_endpoints = _positive_int(options.get("max_endpoints"))
    timeout = _float_in_range(options.get("timeout"), 5.0)
    admin_path_markers = _extend_unique([], options.get("admin_path_markers"))
    denial_keywords = _extend_unique(_DENIAL_KEYWORDS, options.get("denial_keywords"))
    privilege_param_keywords = _extend_unique(_PRIVILEGE_PARAM_KEYWORDS, options.get("privilege_param_keywords"))
    privilege_payloads = _extend_unique(_PRIVILEGE_PAYLOADS, options.get("privilege_payloads"))

    auth_cfg = raw.get("auth") or {}
    accounts = auth_cfg.get("accounts") or []
    data_dir = Path(getattr(ctx, "data_dir", "data"))
    
    if not accounts:
        test_accounts_path = data_dir / "test-accounts.json"
        if test_accounts_path.is_file():
            try:
                accounts = json.loads(test_accounts_path.read_text(encoding="utf-8")).get("accounts", [])
            except Exception as e:
                print(f"    [Error] Exception reading test-accounts.json: {e}")

    logins = login_all_accounts(auth_cfg, accounts)
    admin_logins = []
    user_logins = []
    for login in logins:
        email = login.get("email")
        account = next((a for a in accounts if a.get("email") == email), {})
        role = str(account.get("role", "")).upper()
        if not role:
            role = "ADMIN" if "admin" in email.lower() else "USER"
        
        # Attach raw account data for ID lookup
        login["account_raw"] = account
            
        if "ADMIN" in role:
            admin_logins.append(login)
        else:
            user_logins.append(login)
            
    if not user_logins:
        return ScanResult(status="skipped", message="4-5 scan skipped: needs at least 1 USER account.")
        
    api_tree = _read_api_tree(data_dir)
    all_endpoints = api_tree.get("endpoints", []) if api_tree else []
    endpoints = _select_endpoints(
        all_endpoints,
        probe_mode=probe_mode,
        sample_size=sample_size,
        max_endpoints=max_endpoints,
    )
    
    admin_endpoints = [ep for ep in endpoints if _is_admin_endpoint(ep, admin_path_markers)]
    stats["admin_endpoints"] = len(admin_endpoints)
    stats["scanned_endpoints"] = len(endpoints)
    stats["total_inventory_endpoints"] = len(all_endpoints)
    stats["probe_mode"] = probe_mode
    stats["sample_size"] = sample_size
    stats["max_endpoints"] = max_endpoints
    stats["timeout"] = timeout
    
    report_dir = data_dir / "report" / "4-5"
    report_dir.mkdir(parents=True, exist_ok=True)
    log_file_path = report_dir / "g45_scan.log"
    
    # 매 진단 시작 시 기존 로그 파일 초기화
    if log_file_path.exists():
        try:
            log_file_path.unlink()
        except OSError:
            pass
    
    def _log(msg: str):
        formatted_msg = f"[{datetime.now().isoformat()}] {msg}"
        with open(log_file_path, "a", encoding="utf-8") as f:
            f.write(f"{formatted_msg}\n")
        print(formatted_msg)
        
    _log(
        "Starting Advanced 4-5 Access Control scan "
        f"(mode={probe_mode}, selected={len(endpoints)}/{len(all_endpoints)}, timeout={timeout}s)"
    )
    
    user_a = user_logins[0]
    user_a_headers = auth_headers_for_session(user_a)
    
    # [Phase 0] Vertical PrivEsc
    if admin_endpoints:
        _log(f"Phase 0: Testing {len(admin_endpoints)} admin endpoints for vertical privilege escalation")
        for i, ep in enumerate(admin_endpoints):
            method = ep.get("method", "GET")
            url = ep.get("base_url", "") + ep.get("path", "")
            _log(f"    [Phase 0] Testing {method} {url} ...")
            try:
                res = requests.request(method, probe_url(url), headers=user_a_headers, timeout=timeout, verify=False)
                if res.status_code in {200, 201, 204}:
                    res_text_lower = res.text.lower()
                    if any(k.lower() in res_text_lower for k in denial_keywords):
                        continue
                        
                    _log(f"    -> {method} {url} : Vulnerable to Vertical PrivEsc!")
                    findings.append(DiagnosisFinding(
                        severity="high",
                        message="Vertical Privilege Escalation Detected",
                        evidence={
                            "url": url, 
                            "method": method, 
                            "status_code": res.status_code,
                            "remediation": (
                                "**[조치 방안]**\n"
                                "해당 관리자 API에 대해 철저한 Role 기반 인가(Authorization) 필터가 적용되어 있는지 확인하세요.\n\n"
                                "---\n"
                                "⚠️ **[스캐너 한계 및 수동 진단 가이드]**\n"
                                "1. **상태 코드 오탐지**: 서버가 에러 메시지나 리다이렉션을 `200 OK`로 반환하는 잘못된 관행을 가진 경우 오탐일 수 있습니다.\n"
                                "2. **수동 확인법**: 포스트맨(Postman) 등으로 일반 유저 토큰을 사용해 해당 API를 직접 호출해보고, 실제 관리자 전용 데이터가 노출되거나 변경되었는지 눈으로 확인해야 합니다."
                            )
                        }
                    ))
            except Exception as e:
                _log(f"    [Error] Phase 0 Vertical PrivEsc: {e}")
            
    if probe_mode == "base_only":
        _log("Skipping Phase 1~4: probe_mode=base_only only checks admin/manage endpoints.")
        return ScanResult(findings=findings, stats=stats, status="fail" if findings else "pass")

    # Need User B for horizontal tests
    if len(user_logins) < 2:
        _log("Skipping Phase 1~3: Requires at least 2 USER accounts for IDOR testing.")
        return ScanResult(findings=findings, stats=stats, status="fail" if findings else "pass")
        
    user_b = user_logins[1]
    user_b_headers = auth_headers_for_session(user_b)
    user_b_token = user_b.get("token", "")
    
    base_url_global = endpoints[0].get("base_url", "") if endpoints else ""
    
    # [Phase 0.5] Extract Dynamic User B ID
    _log("Phase 0.5: Dynamically Extracting User B's Identifier")
    user_b_dynamic_id = get_dynamic_user_id(
        user_b,
        endpoints,
        base_url_global,
        user_b_headers,
        _log,
        timeout=timeout,
    )
    
    # [Phase 1] Discovery
    _log("Phase 1: Discovery (Building B's Resource Inventory)")
    b_inventory = build_resource_inventory(
        user_b_headers,
        endpoints,
        base_url_global,
        _log,
        timeout=timeout,
    )
    created_resources = []
        
    _log("    Building A's Resource Inventory for noise filtering...")
    a_inventory = build_resource_inventory(
        user_a_headers,
        endpoints,
        base_url_global,
        _log,
        timeout=timeout,
    )
        
    filtered_b_inventory = {}
    for k, v_list in b_inventory.items():
        a_list = a_inventory.get(k, [])
        unique_v = [v for v in v_list if v not in a_list]
        if unique_v:
            filtered_b_inventory[k] = unique_v
            
    b_inventory = filtered_b_inventory
    
    if not b_inventory:
        _log("    Passive discovery yielded no UNIQUE IDs. Starting Active Discovery (POST)...")
        b_inventory = active_discovery_inventory(
            user_b_headers,
            endpoints,
            base_url_global,
            created_resources,
            _log,
            timeout=timeout,
        )
        if b_inventory:
            # Re-filter after active discovery just in case
            a_inventory = active_discovery_inventory(
                user_a_headers,
                endpoints,
                base_url_global,
                created_resources,
                _log,
                timeout=timeout,
            )
            for k, v_list in b_inventory.items():
                a_list = a_inventory.get(k, [])
                unique_v = [v for v in v_list if v not in a_list]
                if unique_v:
                    filtered_b_inventory[k] = unique_v
            b_inventory = filtered_b_inventory
    # 로그 폭탄 방지: 각 키별로 최대 5개까지만 출력하고 개수 표시
    b_inventory_summary = {k: f"[{len(v)} items] {v[:5]}..." if len(v) > 5 else v for k, v in b_inventory.items()}
    _log(f"    B Inventory built (filtered): {b_inventory_summary}")
    hidden_query_user_b_id = _first_inventory_value(
        b_inventory,
        ["memberId", "member_id", "userId", "user_id", "accountId", "account_id", "id"],
    ) or user_b_dynamic_id
    if hidden_query_user_b_id and hidden_query_user_b_id != user_b_dynamic_id:
        _log(
            "    [Dynamic ID] Using B inventory identifier for hidden query "
            f"tests -> {hidden_query_user_b_id} (fallback was {user_b_dynamic_id})"
        )
    
    # [Phase 2] Exploitation (2 Cases)
    _log(f"Phase 2: IDOR Testing (2 Cases)")
    
    for ep in endpoints:
        method = ep.get("method", "GET").upper()
        path = ep.get("path", "")
        url_template = ep.get("base_url", base_url_global) + path

        if "{" in path and "}" in path:
            if not b_inventory:
                _log(f"    [Phase 2 Case 1] Skipping {method} {url_template} (No Resource IDs found to test)")
            else:
                # Case 1: Explicit Path ID Substitution
                # Find a matching ID type from inventory (heuristic: path contains 'post' -> postId)
                b_ids_to_test = []
                path_lower = path.lower()
                for inv_k, inv_v in b_inventory.items():
                    key_normalized = re.sub(r"(?i)id$", "", inv_k.lower())
                    if not key_normalized:
                        continue
                    if key_normalized in path_lower or inv_k.lower() in path_lower:
                        b_ids_to_test.extend(inv_v)
                if not b_ids_to_test:
                    b_ids_to_test = [v for inv_k, vals in b_inventory.items() if inv_k.lower() == "id" for v in vals]

                if len(re.findall(r"\{[^}]+\}", path)) == 1:
                    for b_id in set(b_ids_to_test[:3]):  # Test up to 3 IDs
                        test_url = re.sub(r'\{[^}]+\}', str(b_id), url_template, count=1)

                        if method in ("GET", "POST", "PUT", "PATCH"):
                            _log(f"    [Phase 2 Case 1] Testing {method} {test_url} ...")
                            try:
                                if method == "GET":
                                    res = requests.get(probe_url(test_url), headers=user_a_headers, timeout=timeout, verify=False)
                                    is_vulnerable = res.status_code == 200
                                    action_label = "조회(Read)"
                                    manual_hint = (
                                        "1. **Public/공용 API 오탐**: 블로그 글, 공지사항처럼 원래 누구나 볼 수 있는 리소스(Public Data)인 경우 취약점이 아닙니다. 스캐너는 비즈니스 맥락(이게 비밀글인지 공지글인지)을 완벽히 이해하지 못합니다.\n"
                                        "2. **수동 확인법**: 노출된 데이터가 실제로 '타인에게 보여선 안 되는 민감한 개인정보'가 맞는지 직접 판단해야 합니다."
                                    )
                                else:
                                    body = safe_body(ep)
                                    res = requests.request(method, probe_url(test_url), headers=user_a_headers, json=body, timeout=timeout, verify=False)
                                    is_vulnerable = res.status_code in {200, 201, 204}
                                    action_label = "변경(Write)"
                                    manual_hint = (
                                        "1. **응답 성공 ≠ 실제 반영**: 서버가 요청을 승인(2xx)했어도 실제로 데이터가 바뀌지 않았을 수 있습니다. User B 계정으로 다시 조회해 값이 실제로 변경·생성됐는지 확인하세요.\n"
                                        "2. **수동 확인법**: 재현 시 더미 값이 아니라 실제로 의미 있는 필드를 조작해, 진짜로 소유권 검증이 빠졌는지 다시 검증해야 합니다."
                                    )

                                if is_vulnerable:
                                    _log(f"    [Case 1 IDOR] {method} {test_url} -> VULNERABLE ({action_label})")
                                    findings.append(DiagnosisFinding(
                                        severity="high",
                                        message=f"Horizontal Privilege Escalation (Case 1: Path/Query IDOR - {action_label})",
                                        evidence={
                                            "rule_id": "idor_horizontal_case1",
                                            "url": test_url,
                                            "method": method,
                                            "description": f"[수동 검증 필수] 정상 토큰(User A)으로 제3자(User B)의 명시적 리소스 ID에 {method} 요청을 보내 {res.status_code}을 받았습니다.",
                                            "attack_payload": f"User A token {method} Resource ID: {b_id}",
                                            "target_role": "Resource Owner",
                                            "bypassed_role": "Other User (Attacker)",
                                            "remediation": (
                                                "**[조치 방안]**\n"
                                                "해당 리소스가 작성자 본인만 열람·수정 가능한 경우, 대상 객체의 소유자 ID와 현재 로그인한 유저의 ID가 일치하는지 검증하는 인가(ACL) 로직을 추가하세요.\n\n"
                                                "---\n"
                                                "⚠️ **[스캐너 한계 및 수동 진단 가이드]**\n"
                                                f"{manual_hint}"
                                            ),
                                            "status_code": res.status_code
                                        }
                                    ))
                            except Exception as e:
                                _log(f"    [Error] Phase 2 Case 1 IDOR request failed: {e}")
                    
        # Case 2: Hidden Query IDOR (Generic Personal API Test)
        if method == "GET" and "{" not in path:
            try:
                res_a_base = requests.get(probe_url(url_template), headers=user_a_headers, timeout=timeout, verify=False)
                
                if res_a_base.status_code == 200 and hidden_query_user_b_id:
                    # 스킵 로직 제거: 빈 배열이라도 강제로 파라미터를 찔러서 데이터가 딸려오는지 확인
                    hidden_params = ["userId", "user_id", "memberId", "member_id", "accountId", "id"]
                    
                    for param in hidden_params:
                            test_url = f"{url_template}?{param}={hidden_query_user_b_id}"
                            
                            _log(f"    [Phase 2 Case 2] Testing {method} {test_url} ...")
                            res_injected = requests.get(probe_url(test_url), headers=user_a_headers, timeout=timeout, verify=False)
                            
                            if res_injected.status_code == 200:
                                injected_len = len(res_injected.content)
                                
                                # 3단계: 해킹 성공 여부 판단 (의미론적 추적 - Semantic Diffing)
                                b_identifiers = []
                                if hidden_query_user_b_id: b_identifiers.append(str(hidden_query_user_b_id))
                                if user_b_dynamic_id and user_b_dynamic_id != hidden_query_user_b_id:
                                    b_identifiers.append(str(user_b_dynamic_id))
                                if user_b.get("email"): b_identifiers.append(str(user_b.get("email")))
                                if user_b.get("nickname"): b_identifiers.append(str(user_b.get("nickname")))
                                
                                if not b_identifiers:
                                    _log("    [Phase 2 Case 2] Skipped: No User B identifiers available to verify leakage.")
                                    break  # No identifiers to verify, so skip testing further parameters for this endpoint
                                
                                # A의 기본 응답에 B의 식별자가 이미 들어있다면 원래 볼 수 있는 정보임 (공용 게시판 등)
                                already_visible = any(b_id in res_a_base.text for b_id in b_identifiers if b_id)
                                
                                if not already_visible:
                                    leaked_identifiers = [b_id for b_id in b_identifiers if b_id and b_id in res_injected.text]
                                    
                                    if leaked_identifiers:
                                        _log(f"    [Hidden Query IDOR] {test_url} -> VULNERABLE (Leaked: {leaked_identifiers})")
                                        findings.append(DiagnosisFinding(
                                            severity="high",
                                            message="Horizontal Privilege Escalation (Case 2: Hidden Query IDOR)",
                                            evidence={
                                                "rule_id": "idor_horizontal_case2",
                                                "url": test_url,
                                                "method": method,
                                                "description": (
                                                    "**[수동 검증 필수]**\n\n"
                                                    f"개인화된 API(`{url_template}`)에 숨겨진 식별자 파라미터(`{param}={hidden_query_user_b_id}`)를 쿼리에 강제 주입한 결과, "
                                                    f"정상 토큰(User A) 소유자에게 허용되지 않은 타겟 유저(User B)의 민감 정보({leaked_identifiers})가 노출되어 권한 우회(BOLA)에 성공한 것으로 강하게 의심됩니다."
                                                ),
                                                "attack_payload": (
                                                    "```http\n"
                                                    f"{method} {test_url}\n"
                                                    "```"
                                                ),
                                                "target_role": "Resource Owner",
                                                "bypassed_role": "Other User (Attacker)",
                                                "remediation": (
                                                    "**[조치 방안]**\n"
                                                    f"1. 불필요하게 `{param}` 같은 파라미터를 추가로 입력받지 마세요.\n"
                                                    f"2. 파라미터를 받아야만 한다면, 요청한 `{param}` 값이 현재 로그인된 토큰의 식별자와 일치하는지 백엔드에서 반드시 검증해야 합니다.\n\n"
                                                    "---\n"
                                                    "⚠️ **[스캐너 한계 및 수동 진단 가이드]**\n"
                                                    "1. **캐시(Cache) 노이즈**: 드물지만 서버 캐싱 설정 오류로 인해 우연히 이전 요청(User B)의 결과가 User A에게 반환된 것일 수도 있습니다.\n"
                                                    "2. **수동 확인법**: 버프스위트(Burp Suite) 프록시를 일시정지시키고 수동으로 해당 파라미터에 다른 유저 번호를 1부터 100까지(Intruder) 대입해 보며 남의 정보가 일관되게 털려 나오는지 증명해야 합니다."
                                                ),
                                                "status_code": res_injected.status_code
                                            }
                                        ))
                                        break # 하나라도 성공하면 다음 파라미터 주입 생략
            except Exception as e:
                print(f"    [Error] Exception during Phase 2 IDOR test: {e}")

    # [Phase 4] Targeted Mass Assignment (명시적 권한 파라미터 조작)
    _log("Phase 4: Targeted Mass Assignment Testing")
    target_param_keywords = privilege_param_keywords
    admin_payloads = privilege_payloads
    
    for ep in endpoints:
        method = ep.get("method", "GET").upper()
        if method not in {"POST", "PUT", "PATCH"}:
            continue
            
        path = ep.get("path", "")
        url_template = ep.get("base_url", base_url_global) + path
        
        req_params = ep.get("request_params", [])
        vuln_params = [p for p in req_params if any(k in p.get("name", "").lower() for k in target_param_keywords)]
        
        if not vuln_params:
            continue
            
        _log(f"    [Phase 4] Found targeted parameters in {method} {path} -> {[p.get('name') for p in vuln_params]}")
        
        for p in vuln_params:
            param_name = p.get("name")
            for payload in admin_payloads:
                test_url = url_template
                body = safe_body(ep)
                
                if p.get("in") == "query":
                    test_url = f"{url_template}?{param_name}={payload}"
                else:
                    body[param_name] = payload
                    
                _log(f"    [Phase 4] Testing {method} {test_url} (Injecting {param_name}={payload}) ...")
                try:
                    res = requests.request(method, probe_url(test_url), headers=user_a_headers, json=body, timeout=timeout, verify=False)
                    if res.status_code in {200, 201}:
                        found_payload = False
                        try:
                            res_json = res.json()
                            found_payload = json_field_matches(res_json, param_name, str(payload))
                        except Exception:
                            res_text = res.text.lower()
                            found_payload = f'"{param_name.lower()}"' in res_text and str(payload).lower() in res_text
                        if found_payload:
                            req_snippet = (
                                f"```json\n{{\n"
                                f"  ... (정상 파라미터 생략),\n"
                                f"  \"{param_name}\": \"{payload}\"   <-- 🚨 [권한 상승 파라미터 몰래 주입]\n"
                                f"}}\n```"
                            ) if p.get("in") != "query" else (
                                f"```http\n"
                                f"{method} {url_template}?{param_name}={payload}   <-- 🚨 [쿼리에 권한 상승 파라미터 주입]\n"
                                f"```"
                            )
                            
                            res_snippet = (
                                f"```json\n{{\n"
                                f"  ... (생략),\n"
                                f"  \"{param_name}\": \"{payload}\"   <-- 💥 [서버가 필터링 없이 그대로 승인/저장함!]\n"
                                f"}}\n```"
                            )

                            findings.append(DiagnosisFinding(
                                severity="critical",
                                message="Mass Assignment (Role Fuzzing / Privilege Escalation)",
                                evidence={
                                    "rule_id": "mass_assignment_privesc",
                                    "url": test_url,
                                    "method": method,
                                    "description": (
                                        "**[수동 검증 필수]**\n\n"
                                        f"API 문서에 노출된 `{param_name}` 파라미터에 악성 권한값(`{payload}`)을 강제로 주입하여 요청한 결과, "
                                        "서버가 이를 필터링하지 않고 그대로 승인 및 저장한 정황이 발견되었습니다. (응답 결과에 권한 덮어쓰기 반영됨)"
                                    ),
                                    "attack_payload": (
                                        "### 1. 조작된 공격 요청 (Request)\n"
                                        f"{req_snippet}\n\n"
                                        "### 2. 서버의 취약한 응답 (Response)\n"
                                        f"{res_snippet}"
                                    ),
                                    "target_role": "System Admin",
                                    "bypassed_role": "Normal User",
                                    "remediation": (
                                        "**[조치 방안]**\n"
                                        "1. **DTO 분리**: 사용자 입력을 받는 Request DTO와 내부 Entity를 철저히 분리하세요. 예를 들어 회원가입용 `SignupRequest`에는 `role` 필드를 아예 제거해야 합니다.\n"
                                        "2. **필드 무시**: 프레임워크 기능(`@JsonIgnore`, `@JsonProperty(access = Access.READ_ONLY)`)을 사용하여 클라이언트가 직접 수정해서는 안 되는 민감한 필드는 바인딩을 원천 차단해야 합니다.\n\n"
                                        "---\n"
                                        "⚠️ **[스캐너 한계 및 수동 진단 가이드]**\n"
                                        "1. **응답 미러링(Mirroring) 오탐**: 서버가 요청받은 데이터를 단순히 그대로 응답(Echo)할 뿐, DB에는 정상적인 사용자 권한으로 저장했을 수 있습니다.\n"
                                        "2. **수동 확인법**: 해당 계정으로 로그인 후 관리자만 접근 가능한 기능(예: 관리자 대시보드, 전체 유저 조회)을 호출하여 실제로 권한 상승이 이루어졌는지 직접 검증해야 합니다."
                                    ),
                                    "status_code": res.status_code
                                }
                            ))
                            # 하나라도 성공하면 해당 API에 대한 추가 공격 중지
                            break
                except Exception as e:
                    print(f"    [Error] Exception during Phase 4 Targeted Mass Assignment: {e}")
                
    # [Phase 3] Cleanup
    _log("Phase 3: Cleanup")
    for cr in created_resources:
        url = cr["url"]
        for k, v_list in cr["ids"].items():
            for v in v_list:
                del_url = f"{url}/{v}"
                try:
                    requests.delete(probe_url(del_url), headers=user_b_headers, timeout=min(timeout, 10.0), verify=False)
                    _log(f"    [Cleanup] Deleted {del_url}")
                except Exception as e:
                    print(f"    [Error] Exception during Cleanup: {e}")

    status = "fail" if findings else "pass"
    message = f"4-5 scan completed: {len(findings)} issues found." if findings else "4-5 scan completed: No privilege escalation found."
    return ScanResult(findings=findings, stats=stats, status=status, message=message)
