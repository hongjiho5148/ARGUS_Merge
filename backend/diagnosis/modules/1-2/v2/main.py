"""
ARGUS v2 - Injection Pipeline Main Orchestrator
"""

import argparse
import json
import sys
from collections import Counter
from datetime import datetime
from urllib.parse import urlencode, urlsplit, urlunsplit

import requests

from input_parser import parse_swagger
from models import DetectionResult, InjectionType, VerificationStatus
from payload_injector import CommandInjector, GenericInjectionInjector, NoSqlInjector, SqliInjector, SstiInjector, XmlXPathInjector
from zap_engine import ZapEngine


UNSAFE_METHODS = {"DELETE", "PATCH"}


def _auth_headers(jwt_token: str) -> dict:
    if not jwt_token:
        return {}
    auth_val = jwt_token if jwt_token.lower().startswith("bearer") else f"Bearer {jwt_token}"
    return {"Authorization": auth_val}


def _injector_map(jwt_token: str, verification_mode: str) -> dict:
    return {
        InjectionType.SQL: SqliInjector(jwt_token=jwt_token, verification_mode=verification_mode),
        InjectionType.COMMAND: CommandInjector(jwt_token=jwt_token, verification_mode=verification_mode),
        InjectionType.NOSQL: NoSqlInjector(jwt_token=jwt_token, verification_mode=verification_mode),
        InjectionType.SSTI: SstiInjector(jwt_token=jwt_token, verification_mode=verification_mode),
        InjectionType.XPATH: XmlXPathInjector(jwt_token=jwt_token, verification_mode=verification_mode),
        InjectionType.XML: XmlXPathInjector(jwt_token=jwt_token, verification_mode=verification_mode),
        InjectionType.GENERIC: GenericInjectionInjector(jwt_token=jwt_token, verification_mode=verification_mode),
    }


def _parse_direct_types(raw_value: str) -> list:
    if raw_value.strip().lower() == "all":
        return list(InjectionType)

    selected = []
    for value in raw_value.split(","):
        key = value.strip().upper()
        if not key:
            continue
        try:
            selected.append(InjectionType[key])
        except KeyError:
            valid = ", ".join(t.name for t in InjectionType)
            raise ValueError(f"Unknown direct injection type '{value}'. Valid values: {valid}, all")
    return selected or [InjectionType.SQL]


def _target_request(target, active_param_name: str = "") -> tuple:
    path = target.path
    query_params = []
    body_params = {}
    headers = {"Content-Type": target.content_type or "application/json"}

    for param in target.params:
        sample = param.sample_value if param.sample_value is not None else "argus-test"
        if param.location.value == "path":
            if param.name != active_param_name:
                path = path.replace("{" + param.name + "}", str(sample))
        elif param.location.value == "query":
            query_params.append((param.name, str(sample)))
        elif param.location.value == "body":
            body_params[param.name] = sample
        elif param.location.value == "header":
            headers[param.name] = str(sample)

    url = f"{target.base_url.rstrip('/')}{path}"
    if query_params:
        parsed = urlsplit(url)
        extra_query = urlencode(query_params, doseq=True)
        query = "&".join(part for part in [parsed.query, extra_query] if part)
        url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))

    body = ""
    content_type = (target.content_type or "").lower()
    if body_params:
        if "x-www-form-urlencoded" in content_type:
            body = urlencode(body_params, doseq=True)
        else:
            headers["Content-Type"] = target.content_type or "application/json"
            body = json.dumps(body_params, ensure_ascii=False, separators=(",", ":"))

    return url, body, headers


def _direct_results_from_swagger(args, jwt_token: str) -> list:
    if not args.swagger:
        print("[DIRECT] Swagger/OpenAPI URL이 없어 direct 검증을 건너뜁니다.")
        return []

    direct_types = _parse_direct_types(args.direct_types)
    targets = parse_swagger(
        args.swagger,
        host_override=args.target,
        auth_headers=_auth_headers(jwt_token),
    )
    print(f"[DIRECT] Swagger에서 {len(targets)}개 API operation을 파싱했습니다.")

    injectors = _injector_map(jwt_token, args.verification_mode)
    results = []
    skipped_methods = 0
    skipped_params = 0

    for target in targets:
        method = target.method.upper()
        if method in UNSAFE_METHODS and not args.direct_include_unsafe:
            skipped_methods += 1
            continue

        for param in target.params:
            if param.location.value not in {"query", "path", "body", "header"}:
                skipped_params += 1
                continue

            raw_url, raw_body, raw_headers = _target_request(target, active_param_name=param.name)
            raw_headers.update(_auth_headers(jwt_token))

            for injection_type in direct_types:
                result = injectors[injection_type].verify_zap_alert(
                    # DetectionResult is intentionally reused here: direct mode
                    # builds the same request shape that ZAP alerts provide.
                    DetectionResult(
                        method=method,
                        url=raw_url,
                        param=param.name,
                        risk="UNKNOWN",
                        plugin_id="ARGUS_DIRECT",
                        plugin_name=f"ARGUS Direct {injection_type.value}",
                        injection_type=injection_type,
                        has_zap=False,
                        raw_request_body=raw_body,
                        raw_request_url=raw_url,
                        raw_request_headers=raw_headers,
                    )
                )
                keep_statuses = {
                    VerificationStatus.VERIFIED,
                    VerificationStatus.SUSPECTED,
                    VerificationStatus.ERROR,
                }
                if args.direct_keep_all or result.verification_status in keep_statuses:
                    results.append(result)

    if skipped_methods:
        print(f"[DIRECT] DELETE/PATCH operation {skipped_methods}개는 기본 정책으로 건너뛰었습니다. 포함하려면 --direct-include-unsafe를 사용하세요.")
    if skipped_params:
        print(f"[DIRECT] 지원하지 않는 위치의 파라미터 {skipped_params}개를 건너뛰었습니다.")
    print(f"[DIRECT] direct 검증 결과 {len(results)}건을 수집했습니다.")
    return results


def _dedupe_results(results: list) -> list:
    merged = []
    seen = set()
    for result in results:
        key = (result.method, result.url, result.param, result.injection_type, result.plugin_id)
        if key in seen:
            continue
        seen.add(key)
        merged.append(result)
    return merged


def _method_status(result: DetectionResult, name: str) -> str:
    return (result.verification_methods.get(name) or {}).get("status", "")


def _matched_patterns(result: DetectionResult) -> list:
    return (result.verification_methods.get("error_based") or {}).get("matched_patterns", []) or []


def _annotate_result(result: DetectionResult) -> DetectionResult:
    time_verified = _method_status(result, "time_based") == VerificationStatus.VERIFIED.value
    boolean_verified = _method_status(result, "boolean_based") == VerificationStatus.VERIFIED.value
    error_verified = _method_status(result, "error_based") == VerificationStatus.VERIFIED.value
    error_suspected = _method_status(result, "error_based") == VerificationStatus.SUSPECTED.value
    matched_patterns = _matched_patterns(result)
    zap_confirmed = result.has_zap and result.verification_status == VerificationStatus.VERIFIED

    if result.verification_status == VerificationStatus.VERIFIED and time_verified:
        result.classification = "CONFIRMED_INJECTION_TIME_BASED"
        result.confidence = "HIGH"
        result.argus_risk = "HIGH"
        result.related_issue = "SQL Injection / Time-based Blind SQL Injection"
        result.why_injection = "페이로드 입력 후 기준 요청보다 의미 있는 시간 지연이 재현되어 DB 함수 실행 가능성을 강하게 시사합니다."
        result.risk_comment = "시간 기반 증거는 단순 입력 검증 오류보다 SQL Injection 근거가 강합니다."
        result.reporting_guidance = "정탐 항목으로 우선 보고하고, 해당 파라미터의 쿼리 바인딩/동적 SQL 사용 여부를 코드에서 확인하세요."
    elif result.verification_status == VerificationStatus.VERIFIED and boolean_verified:
        result.classification = "CONFIRMED_INJECTION_BOOLEAN_BASED"
        result.confidence = "HIGH"
        result.argus_risk = "HIGH"
        result.related_issue = "SQL Injection / Boolean-based Blind SQL Injection"
        result.why_injection = "참/거짓 조건 페이로드에 따라 응답이 안정적으로 달라져 조건식이 서버 처리 흐름에 영향을 준 것으로 판단됩니다."
        result.risk_comment = "응답 차이가 재현되므로 단순 500 오류보다 신뢰도가 높습니다."
        result.reporting_guidance = "정탐 후보로 보고하고, 실제 데이터 조회 조건에 사용자 입력이 연결되는지 확인하세요."
    elif result.verification_status == VerificationStatus.VERIFIED and error_verified and matched_patterns:
        result.classification = "CONFIRMED_INJECTION_ERROR_PATTERN"
        result.confidence = "HIGH"
        result.argus_risk = "HIGH"
        result.related_issue = "SQL Injection / Error-based Injection"
        result.why_injection = "응답 본문에서 SQL/명령/XML 파서 계열 오류 패턴이 새로 확인되었습니다."
        result.risk_comment = "DB 또는 파서 오류가 노출되어 Injection 가능성과 정보 노출 위험이 함께 있습니다."
        result.reporting_guidance = "정탐 항목으로 보고하고, 에러 메시지 노출 차단과 파라미터 바인딩 적용을 함께 권고하세요."
    elif result.verification_status == VerificationStatus.VERIFIED and error_verified:
        result.classification = "WEAK_SERVER_ERROR_CONFIRMED_LEGACY"
        result.confidence = "MEDIUM"
        result.argus_risk = "MEDIUM"
        result.related_issue = "Potential Injection / Server Error Handling"
        result.why_injection = "페이로드 입력 시 5xx 응답이 재현되었지만 DB 고유 오류 패턴은 확인되지 않았습니다."
        result.risk_comment = "SQL Injection 정탐으로 단정하기보다 서버 예외 유발 지점으로 분류하는 것이 안전합니다."
        result.reporting_guidance = "의심 항목으로 보고하고 서버 로그에서 SQL 예외인지, 타입 변환/검증 예외인지 추가 확인하세요."
    elif result.verification_status == VerificationStatus.SUSPECTED and error_suspected:
        result.classification = "SUSPECTED_SERVER_ERROR_SIGNAL"
        result.confidence = "LOW"
        result.argus_risk = "MEDIUM"
        result.related_issue = "Potential Injection / Input Validation / Server Error Handling"
        result.why_injection = "인젝션 페이로드 입력으로 5xx 응답 변화가 발생했지만 SQL 에러 패턴, boolean 차이, 시간 지연은 확인되지 않았습니다."
        result.risk_comment = "NumberFormatException, enum/date 파싱 실패, validation 누락 등 입력 처리 오류일 수 있어 SQLi와 분리해 봐야 합니다."
        result.reporting_guidance = "SQL Injection 확정이 아니라 '인젝션 의심 및 입력 검증 미흡' 항목으로 보고하고 서버 로그 기반 후속 검증을 권장하세요."
    elif result.verification_status == VerificationStatus.SUSPECTED:
        result.classification = "SUSPECTED_INJECTION"
        result.confidence = "LOW"
        result.argus_risk = "MEDIUM" if result.has_zap else "LOW"
        result.related_issue = "Potential Injection"
        result.why_injection = "자동 검증에서 확정 증거는 부족하지만 ZAP 또는 direct 검증에서 의심 신호가 남았습니다."
        result.risk_comment = "추가 수동 검증 전까지 정탐으로 단정하지 않는 것이 좋습니다."
        result.reporting_guidance = "의심 항목으로 분리하고, 재현 요청/서버 로그/DB 쿼리 흐름을 함께 확인하세요."
    elif result.verification_status == VerificationStatus.FALSE_POSITIVE:
        result.classification = "NOT_REPRODUCED"
        result.confidence = "LOW"
        result.argus_risk = "INFO"
        result.related_issue = "Not Reproduced"
        result.why_injection = "error, boolean, time 기반 검증에서 재현 가능한 Injection 증거가 확인되지 않았습니다."
        result.risk_comment = "현재 결과만으로는 Injection 위험을 보고하기 어렵습니다."
        result.reporting_guidance = "기본 보고서에서는 제외하거나 부록/오탐 목록에만 남기세요."
    elif result.verification_status == VerificationStatus.UNVERIFIABLE:
        result.classification = "UNVERIFIABLE"
        result.confidence = "UNKNOWN"
        result.argus_risk = "INFO"
        result.related_issue = "Verification Gap"
        result.why_injection = "요청 재구성 또는 기준 요청 생성에 실패해 검증을 완료하지 못했습니다."
        result.risk_comment = "도구가 판단할 수 없는 상태이므로 수동 재현이 필요합니다."
        result.reporting_guidance = "스캐너 한계 또는 Swagger 샘플값 부족으로 분리해 기록하세요."
    else:
        result.classification = "VERIFICATION_ERROR"
        result.confidence = "UNKNOWN"
        result.argus_risk = "INFO"
        result.related_issue = "Scanner Error"
        result.why_injection = "검증 중 예외가 발생해 Injection 여부를 판단하지 못했습니다."
        result.risk_comment = "대상 취약점보다 스캐너 실행 오류일 가능성이 큽니다."
        result.reporting_guidance = "오류 원인을 수정한 뒤 재검증하세요."

    if zap_confirmed:
        result.reporting_guidance += " ZAP 탐지와 ARGUS 재검증이 함께 존재하므로 우선순위를 높게 두세요."
    return result


def _print_result_status(verified_result):
    if verified_result.verification_status == VerificationStatus.VERIFIED:
        print("   -> [위험] 정탐(True Positive) 확인됨!")
    elif verified_result.verification_status == VerificationStatus.SUSPECTED:
        print(f"   -> [의심] {verified_result.verification_reason}")
    elif verified_result.verification_status == VerificationStatus.FALSE_POSITIVE:
        print("   -> [오탐] error/boolean/time 검증에서 증거가 확인되지 않음.")
    elif verified_result.verification_status == VerificationStatus.UNVERIFIABLE:
        print(f"   -> [검증불가] {verified_result.verification_reason}")
    else:
        print(f"   -> [{verified_result.verification_status}] {verified_result.verification_reason}")


def main():
    parser = argparse.ArgumentParser(description="ARGUS v2 Injection Pipeline")
    parser.add_argument("--target", required=True, help="Base Target URL (e.g., http://localhost:8080)")
    parser.add_argument("--swagger", required=False, default="", help="Swagger JSON URL (e.g., http://localhost:8080/v3/api-docs)")
    parser.add_argument("--jwt", required=False, default="", help="JWT Token for authentication")
    parser.add_argument("--email", required=False, default="", help="Login email for automatic token extraction")
    parser.add_argument("--password", required=False, default="", help="Login password")
    parser.add_argument("--login-url", required=False, default="", help="Login endpoint URL (e.g., http://localhost:8080/api/v1/auth/login)")
    parser.add_argument("--output-prefix", required=False, default="findings_injection", help="Output JSON filename prefix")
    parser.add_argument("--direct", action="store_true", help="Directly verify Swagger/OpenAPI params instead of relying only on ZAP alerts")
    parser.add_argument("--skip-zap", action="store_true", help="Skip ZAP spider/active scan and run direct verification only")
    parser.add_argument("--direct-types", default="SQL", help="Comma-separated direct verification types (default: SQL, or use all)")
    parser.add_argument("--direct-keep-all", action="store_true", help="Keep direct false-positive results in the output JSON")
    parser.add_argument("--direct-include-unsafe", action="store_true", help="Include PATCH/DELETE operations in direct verification")
    parser.add_argument(
        "--verification-mode",
        choices=["strict", "balanced", "aggressive"],
        default="balanced",
        help="strict/balanced keeps reproduced evidence only; aggressive preserves inconclusive high-risk ZAP alerts as SUSPECTED",
    )

    args = parser.parse_args()

    print("==================================================")
    print(" ARGUS v2 - Injection Pipeline Started")
    print(f" Target : {args.target}")
    print(f" Swagger: {args.swagger}")
    print(f" Mode   : {args.verification_mode}")
    print(f" Direct : {args.direct}")
    print("==================================================\n")

    jwt_token = args.jwt
    if not jwt_token and args.email and args.password and args.login_url:
        print(f"[INFO] 자동 로그인을 시도합니다: {args.login_url}")
        try:
            resp = requests.post(args.login_url, json={"email": args.email, "password": args.password}, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("success") and data.get("data"):
                    jwt_token = data["data"].get("accessToken", "")
                if not jwt_token:
                    jwt_token = resp.cookies.get("accessToken", "")

                if jwt_token:
                    print("[SUCCESS] 자동 로그인 성공! 토큰을 획득했습니다.")
                else:
                    print("[ERROR] 로그인 성공했으나 토큰을 찾을 수 없습니다.")
            else:
                print(f"[ERROR] 로그인 실패 (HTTP {resp.status_code}): {resp.text}")
                sys.exit(1)
        except Exception as exc:
            print(f"[ERROR] 로그인 요청 중 예외 발생: {exc}")
            sys.exit(1)

    zap_results = []
    if not args.skip_zap:
        engine = ZapEngine()
        engine.configure_scan(target_url=args.target, swagger_url=args.swagger, jwt_token=jwt_token)
        zap_results = engine.run_active_scan(target_url=args.target)
        if not zap_results:
            print("[INFO] ZAP에서 발견된 Injection 의심 알림이 없습니다.")
        else:
            print(f"\n[INFO] ZAP에서 총 {len(zap_results)}개의 Injection 의심 알림 발견. 정밀 검증을 시작합니다...")

    injector_map = _injector_map(jwt_token, args.verification_mode)
    final_results = []
    status_counts = Counter()
    direct_count = 0

    for idx, result in enumerate(zap_results):
        print(f"  [{idx + 1}/{len(zap_results)}] 검증 중: {result.method} {result.url} (Param: {result.param}) - {result.injection_type}")
        injector = injector_map.get(result.injection_type)
        if injector:
            verified_result = injector.verify_zap_alert(result)
        else:
            reason = f"지원되지 않는 Injection 타입: {result.injection_type}"
            print(f"   -> [검증불가] {reason}")
            result.verification_status = VerificationStatus.UNVERIFIABLE
            result.verification_reason = reason
            result.evidence = reason
            verified_result = result

        final_results.append(verified_result)
        status = verified_result.verification_status
        status_counts[status.value if isinstance(status, VerificationStatus) else str(status)] += 1

        _print_result_status(verified_result)

    if args.direct:
        try:
            direct_results = _direct_results_from_swagger(args, jwt_token)
        except Exception as exc:
            print(f"[DIRECT][ERROR] direct 검증 준비 중 오류 발생: {exc}")
            direct_results = []

        for result in direct_results:
            final_results.append(result)
            status = result.verification_status
            status_counts[status.value if isinstance(status, VerificationStatus) else str(status)] += 1
        direct_count = len(direct_results)

    final_results = _dedupe_results(final_results)
    final_results = [_annotate_result(result) for result in final_results]
    status_counts = Counter()
    classification_counts = Counter()
    for result in final_results:
        status = result.verification_status
        status_counts[status.value if isinstance(status, VerificationStatus) else str(status)] += 1
        classification_counts[result.classification] += 1

    if not final_results:
        print("[INFO] 저장할 Injection 결과가 없습니다.")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"{args.output_prefix}_{timestamp}.json"
    output_data = [result.to_dict() for result in final_results]

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output_data, f, ensure_ascii=False, indent=4)

    print("\n==================================================")
    print(" 스캔 및 검증 파이프라인 완료!")
    print(f" - 전체 ZAP 의심 알림: {len(zap_results)} 건")
    print(f" - Direct 검증 결과: {direct_count} 건")
    print(f" - 최종 저장 결과: {len(final_results)} 건")
    print(f" - 교차 검증된 정탐: {status_counts.get(VerificationStatus.VERIFIED.value, 0)} 건")
    print(f" - 의심 유지: {status_counts.get(VerificationStatus.SUSPECTED.value, 0)} 건")
    print(f" - 오탐 분류: {status_counts.get(VerificationStatus.FALSE_POSITIVE.value, 0)} 건")
    print(f" - 검증불가: {status_counts.get(VerificationStatus.UNVERIFIABLE.value, 0)} 건")
    print(f" - 검증 오류: {status_counts.get(VerificationStatus.ERROR.value, 0)} 건")
    for classification, count in classification_counts.most_common():
        print(f" - {classification}: {count} 건")
    print(f" - 결과 파일 저장됨: {output_file}")
    print("==================================================")


if __name__ == "__main__":
    main()
