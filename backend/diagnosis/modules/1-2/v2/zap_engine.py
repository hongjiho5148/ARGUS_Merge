"""
ARGUS v2 - SQL Injection ZAP Engine
"""

import os
import re
import time
from typing import Dict, List, Tuple
from urllib.parse import urlparse

from zapv2 import ZAPv2

from models import DetectionResult, InjectionType


class ZapEngine:
    SQLI_PLUGIN_IDS = {
        "40018",  # SQL Injection
        "40019",  # SQL Injection - MySQL
        "40020",  # SQL Injection - Hypersonic SQL
        "40021",  # SQL Injection - Oracle
        "40022",  # SQL Injection - PostgreSQL
        "40024",  # SQL Injection - SQLite
        "40027",  # SQL Injection - MsSQL (time based)
        "90018",  # Advanced SQL Injection
    }
    COMMAND_PLUGIN_IDS = {
        "10048",  # Shell Shock remote code execution
        "90019",  # Server Side Code Injection
        "90020",  # Remote OS Command Injection
        "90037",  # Remote OS Command Injection (time based)
    }
    XPATH_PLUGIN_IDS = {
        "90021",  # XPath Injection
    }
    XML_PLUGIN_IDS = {
        "90017",  # XSLT Injection
        "90023",  # XML External Entity Attack
        "90029",  # SOAP XML Injection
    }
    GENERIC_INJECTION_PLUGIN_IDS = {
        "40003",  # CRLF Injection
        "40009",  # Server Side Include
    }
    SSTI_PLUGIN_IDS = {
        "90035",  # Server Side Template Injection
        "90036",  # Server Side Template Injection (blind)
    }
    INJECTION_PLUGIN_IDS = (
        SQLI_PLUGIN_IDS
        | COMMAND_PLUGIN_IDS
        | XPATH_PLUGIN_IDS
        | XML_PLUGIN_IDS
        | SSTI_PLUGIN_IDS
        | GENERIC_INJECTION_PLUGIN_IDS
    )

    def __init__(self, proxy_address: str = "127.0.0.1:8090", api_key: str = "argus_secret_key"):
        self.proxy_address = proxy_address
        self.api_key = api_key
        self.zap = ZAPv2(
            apikey=api_key,
            proxies={"http": f"http://{proxy_address}", "https": f"http://{proxy_address}"},
        )
        self.policy_name = "Argus_Injection_Policy"

    def log(self, message: str):
        print(f"[ZAP] {message}")

    def configure_scan(self, target_url: str, swagger_url: str = "", jwt_token: str = ""):
        self.log("Injection 스캔 정책을 초기화합니다 (INSANE / LOW)...")
        try:
            self.zap.ascan.remove_scan_policy(scanpolicyname=self.policy_name)
        except Exception:
            pass
        self.zap.ascan.add_scan_policy(scanpolicyname=self.policy_name, alertthreshold="LOW", attackstrength="INSANE")
        self.zap.ascan.disable_all_scanners(scanpolicyname=self.policy_name)

        for pid in sorted(self.INJECTION_PLUGIN_IDS):
            self.zap.ascan.enable_scanners(ids=pid, scanpolicyname=self.policy_name)
            self.zap.ascan.set_scanner_attack_strength(id=pid, attackstrength="INSANE", scanpolicyname=self.policy_name)
            self.zap.ascan.set_scanner_alert_threshold(id=pid, alertthreshold="LOW", scanpolicyname=self.policy_name)

        try:
            self.zap.core.delete_all_alerts()
            self.log("기존 ZAP alert를 초기화했습니다.")
        except Exception:
            self.log("기존 alert 초기화 API를 사용할 수 없어 계속 진행합니다.")

        self.zap.replacer.remove_rule(description="Auth_JWT")
        if jwt_token:
            self.log("JWT 인증 토큰을 ZAP Replacer에 등록합니다.")
            auth_value = jwt_token if jwt_token.lower().startswith("bearer") else f"Bearer {jwt_token}"
            self.zap.replacer.add_rule(
                description="Auth_JWT",
                enabled=True,
                matchtype="REQ_HEADER",
                matchregex=False,
                matchstring="Authorization",
                replacement=auth_value,
            )

        if swagger_url:
            self.log(f"OpenAPI/Swagger 명세를 임포트합니다: {swagger_url}")
            if swagger_url.startswith(("http://", "https://")):
                self.zap.openapi.import_url(swagger_url, target_url)
            else:
                self.zap.openapi.import_file(os.path.abspath(swagger_url), target_url)
            time.sleep(2)

        self.log(f"Spider 크롤러를 실행합니다: {target_url}")
        scan_id = self.zap.spider.scan(url=target_url, maxchildren=10)
        while int(self.zap.spider.status(scan_id)) < 100:
            time.sleep(1)
        time.sleep(2)

    def run_active_scan(self, target_url: str) -> List[DetectionResult]:
        self.log(f"Active Scan (Injection) 시작: {target_url}")
        scan_id = self.zap.ascan.scan(url=target_url, recurse=True, scanpolicyname=self.policy_name)
        while int(self.zap.ascan.status(scan_id)) < 100:
            time.sleep(2)
        self.log("Active Scan 완료. 결과를 수집합니다.")
        return self._collect_results(target_url)

    def _parse_request_header(self, request_header: str, fallback_url: str) -> Tuple[str, Dict[str, str]]:
        raw_request_url = fallback_url
        headers: Dict[str, str] = {}
        if not request_header:
            return raw_request_url, headers

        lines = request_header.split("\n")
        if len(lines) == 1:
            lines = request_header.split("\n")

        if lines:
            parts = lines[0].split(" ")
            if len(parts) >= 2:
                raw_request_url = parts[1]

        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            key, value = line.split(":", 1)
            if key.lower() in {"host", "content-length"}:
                continue
            headers[key.strip()] = value.strip()
        return raw_request_url, headers

    def _absolute_request_url(self, request_url: str, alert_url: str) -> str:
        if request_url.startswith("http://") or request_url.startswith("https://"):
            return request_url
        parsed = urlparse(alert_url)
        if request_url.startswith("/"):
            return f"{parsed.scheme}://{parsed.netloc}{request_url}"
        return alert_url

    def _collect_results(self, target_url: str) -> List[DetectionResult]:
        alerts = self.zap.core.alerts(baseurl=target_url)
        results: List[DetectionResult] = []
        seen = set()

        for alert in alerts:
            plugin_id = str(alert.get("pluginId", ""))
            if plugin_id not in self.INJECTION_PLUGIN_IDS:
                continue
            if alert.get("risk") not in ["High", "Medium"]:
                continue

            method = alert.get("method", "GET")
            url = alert.get("url", "")
            param = alert.get("param", "")
            attack = alert.get("attack", "")
            message_id = alert.get("messageId", "")
            raw_request_body = ""
            raw_request_url = url
            raw_request_headers: Dict[str, str] = {}

            if message_id:
                try:
                    msg = self.zap.core.message(message_id)
                    raw_request_body = msg.get("requestBody", "")
                    parsed_url, parsed_headers = self._parse_request_header(msg.get("requestHeader", ""), url)
                    raw_request_url = self._absolute_request_url(parsed_url, url)
                    raw_request_headers = parsed_headers
                except Exception as exc:
                    self.log(f"메시지 {message_id} 원본 요청 수집 실패: {exc}")

            dedupe_key = (plugin_id, method, url, param, attack, raw_request_body, raw_request_url)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)

            delay_ms = 0
            other_info = alert.get("other", "")
            match = re.search(r"took \[(\d+)\] milliseconds", other_info or "")
            if match:
                delay_ms = int(match.group(1))

            if plugin_id in self.SSTI_PLUGIN_IDS:
                injection_type = InjectionType.SSTI
            elif plugin_id in self.COMMAND_PLUGIN_IDS:
                injection_type = InjectionType.COMMAND
            elif plugin_id in self.XPATH_PLUGIN_IDS:
                injection_type = InjectionType.XPATH
            elif plugin_id in self.XML_PLUGIN_IDS:
                injection_type = InjectionType.XML
            elif plugin_id in self.GENERIC_INJECTION_PLUGIN_IDS:
                injection_type = InjectionType.GENERIC
            else:
                injection_type = InjectionType.SQL
            results.append(
                DetectionResult(
                    method=method,
                    url=url,
                    param=param,
                    risk=alert.get("risk", "High").upper(),
                    plugin_id=plugin_id,
                    plugin_name=alert.get("alert", ""),
                    injection_type=injection_type,
                    has_zap=True,
                    zap_payload=attack,
                    zap_time_delay_ms=delay_ms,
                    evidence=alert.get("evidence", ""),
                    description=alert.get("description", ""),
                    solution=alert.get("solution", ""),
                    raw_request_body=raw_request_body,
                    raw_request_url=raw_request_url,
                    raw_request_headers=raw_request_headers,
                )
            )
        return results
