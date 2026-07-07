"""
ARGUS v2 - SQL Injection ZAP Engine (from feature/injection-scan — rules unchanged).
"""

from __future__ import annotations

import importlib.util
import os
import re
import time
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import urlparse

import requests
from zapv2 import ZAPv2

try:
    from .models import DetectionResult, InjectionType
except ImportError:
    _models_path = Path(__file__).with_name("models.py")
    _spec = importlib.util.spec_from_file_location("diag_g12_models", _models_path)
    if _spec is None or _spec.loader is None:
        raise
    _models = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_models)
    DetectionResult = _models.DetectionResult
    InjectionType = _models.InjectionType


class ZapEngine:
    SQLI_PLUGIN_IDS = {
        "40018",
        "40019",
        "40020",
        "40021",
        "40022",
        "40024",
        "40027",
        "90018",
    }
    COMMAND_PLUGIN_IDS = {
        "10048",
        "90019",
        "90020",
        "90037",
    }
    XPATH_PLUGIN_IDS = {
        "90021",
    }
    XML_PLUGIN_IDS = {
        "90017",
        "90023",
        "90029",
    }
    GENERIC_INJECTION_PLUGIN_IDS = {
        "40003",
        "40009",
    }
    SSTI_PLUGIN_IDS = {
        "90035",
        "90036",
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

    def log(self, message: str) -> None:
        print(f"[ZAP] {message}")

    def _openapi_import(self, swagger_url: str, target_url: str) -> None:
        action = "importUrl" if swagger_url.startswith(("http://", "https://")) else "importFile"
        spec_key = "url" if action == "importUrl" else "file"
        spec_value = swagger_url if action == "importUrl" else os.path.abspath(swagger_url)
        endpoint = f"http://{self.proxy_address}/JSON/openapi/action/{action}/"
        params = {
            "apikey": self.api_key,
            spec_key: spec_value,
            "target": target_url,
        }
        last_error: Exception | None = None
        for attempt in range(1, 3):
            try:
                session = requests.Session()
                session.trust_env = False
                response = session.get(endpoint, params=params, timeout=60)
                response.raise_for_status()
                payload = response.json()
                if payload.get("Result") == "OK":
                    return
                self.log(f"OpenAPI import response: {payload}")
                return
            except requests.RequestException as exc:
                last_error = exc
                self.log(f"OpenAPI import attempt {attempt}/2 failed: {exc}")
                time.sleep(2)
        raise RuntimeError(f"OpenAPI import failed: {last_error}")

    def configure_scan(
        self,
        target_url: str,
        swagger_url: str = "",
        jwt_token: str = "",
        session_headers: Dict[str, str] | None = None,
    ) -> None:
        self.log("Injection scan policy init (INSANE / LOW)...")
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
            self.log("Cleared existing ZAP alerts.")
        except Exception:
            self.log("Could not clear alerts via API; continuing.")

        self.zap.replacer.remove_rule(description="Auth_JWT")
        self.zap.replacer.remove_rule(description="Auth_Cookie")
        headers = session_headers or {}
        cookie_val = headers.get("Cookie") or headers.get("cookie")
        if cookie_val:
            self.log("Registering Cookie with ZAP Replacer.")
            self.zap.replacer.add_rule(
                description="Auth_Cookie",
                enabled=True,
                matchtype="REQ_HEADER",
                matchregex=False,
                matchstring="Cookie",
                replacement=str(cookie_val),
            )
        if jwt_token:
            self.log("Registering JWT with ZAP Replacer.")
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
            self.log(f"Importing OpenAPI spec: {swagger_url}")
            self._openapi_import(swagger_url, target_url)
            time.sleep(2)

        self.log("Using imported OpenAPI spec as fixed ZAP scan targets.")

    def run_active_scan(self, target_url: str, *, max_minutes: int = 30, progress_cb=None) -> List[DetectionResult]:
        self.log(f"Active Scan (Injection) start: {target_url}")
        scan_id = self.zap.ascan.scan(url=target_url, recurse=True, scanpolicyname=self.policy_name)
        self.log(f"Active Scan id: {scan_id}")
        deadline = time.time() + max(1, max_minutes) * 60
        last_status = -1
        unavailable_reads = 0
        while True:
            raw_status = self.zap.ascan.status(scan_id)
            try:
                status = int(raw_status)
            except (TypeError, ValueError):
                unavailable_reads += 1
                self.log(f"Active scan status unavailable for id={scan_id}: {raw_status}")
                if unavailable_reads >= 5:
                    self.log("Active scan status stayed unavailable; continuing with collected alerts only.")
                    break
                time.sleep(2)
                continue
            unavailable_reads = 0
            if status != last_status and progress_cb:
                progress_cb(status, target_url)
                last_status = status
            if status >= 100:
                break
            if time.time() >= deadline:
                self.log(f"Active scan deadline ({max_minutes}m) reached.")
                break
            time.sleep(2)
        if progress_cb:
            progress_cb(100, target_url)
        self.log("Active Scan complete. Collecting results.")
        return self._collect_results(target_url)

    def _parse_request_header(self, request_header: str, fallback_url: str) -> Tuple[str, Dict[str, str]]:
        raw_request_url = fallback_url
        headers: Dict[str, str] = {}
        if not request_header:
            return raw_request_url, headers

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
                    self.log(f"Failed to collect message {message_id}: {exc}")

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
