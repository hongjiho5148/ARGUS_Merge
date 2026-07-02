import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from models import DetectionResult, InjectionType, VerificationStatus
from payload_injector import SqliInjector

FIXTURE = Path(__file__).parent / "fixtures" / "onde_verified_4.json"

EXPECTED_VERIFIED_KEYS = {
    ("GET", "/api/v1/posts", "status", "40018"),
    ("GET", "/api/v1/posts", "status", "40019"),
    ("GET", "/api/v1/properties", "swLng", "40024"),
    ("GET", "/api/v1/posts", "status", "40024"),
}


def load_fixture():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def path_of(url):
    from urllib.parse import urlsplit

    return urlsplit(url).path


def test_onde_verified_4_baseline_is_pinned():
    findings = load_fixture()
    assert len(findings) == 4

    actual = {(f["method"], path_of(f["url"]), f["param"], f["plugin_id"]) for f in findings}
    assert actual == EXPECTED_VERIFIED_KEYS

    for finding in findings:
        assert finding["verification_status"] == VerificationStatus.VERIFIED.value
        assert finding["cross_validated"] is True
        assert finding["verification_methods"]["baseline"]["status"] == VerificationStatus.VERIFIED.value
        assert finding["verification_methods"]["error_based"]["status"] == VerificationStatus.VERIFIED.value

    posts = [f for f in findings if path_of(f["url"]) == "/api/v1/posts"]
    assert len(posts) == 3
    assert all(f["verification_methods"]["time_based"]["status"] == VerificationStatus.VERIFIED.value for f in posts)


def test_rebuilds_onde_verified_4_query_parameters():
    injector = SqliInjector()
    for finding in load_fixture():
        result = DetectionResult(
            method=finding["method"],
            url=finding["url"],
            param=finding["param"],
            risk=finding["risk"],
            plugin_id=finding["plugin_id"],
            plugin_name=finding["plugin_name"],
            injection_type=InjectionType.SQL,
            zap_payload=finding.get("zap_payload", ""),
            raw_request_body=finding.get("raw_request_body", ""),
            raw_request_url=finding.get("raw_request_url", finding["url"]),
            raw_request_headers=finding.get("raw_request_headers", {}),
        )
        url, body, changed, location = injector._build_variant(result, "ARGUS_REGRESSION")
        assert changed, finding
        assert location in {"query", "zap_attack_literal"}
        assert "ARGUS_REGRESSION" in url or "ARGUS_REGRESSION" in body


def test_rebuilds_path_parameters():
    injector = SqliInjector()
    result = DetectionResult(
        method="GET",
        url="http://localhost:8080/admin/users/{id}",
        param="id",
        risk="HIGH",
        plugin_name="SQL Injection",
        plugin_id="40018",
        injection_type=InjectionType.SQL,
        raw_request_url="http://localhost:8080/admin/users/{id}",
    )

    url, body, changed, location = injector._build_variant(result, "ARGUS_PATH")

    assert changed is True
    assert location == "path"
    assert url == "http://localhost:8080/admin/users/ARGUS_PATH"
    assert body == ""


def test_rebuilds_form_urlencoded_body_parameters():
    injector = SqliInjector()
    result = DetectionResult(
        method="POST",
        url="http://localhost:8080/admin/login",
        param="password",
        risk="HIGH",
        plugin_name="SQL Injection",
        plugin_id="40024",
        injection_type=InjectionType.SQL,
        raw_request_body="username=ZAP&password=case+randomblob%28100000%29",
        raw_request_url="http://localhost:8080/admin/login",
        raw_request_headers={"content-type": "application/x-www-form-urlencoded"},
    )

    url, body, changed, location = injector._build_variant(result, "ARGUS_FORM")

    assert url == "http://localhost:8080/admin/login"
    assert changed is True
    assert location == "form_body"
    assert body == "username=ZAP&password=ARGUS_FORM"


def test_rebuilds_header_parameters_for_probe_requests():
    injector = SqliInjector()
    result = DetectionResult(
        method="GET",
        url="http://localhost:8080/api/projects",
        param="User-Agent",
        risk="HIGH",
        plugin_name="SQL Injection",
        plugin_id="40018",
        injection_type=InjectionType.SQL,
        raw_request_url="http://localhost:8080/api/projects",
        raw_request_headers={"User-Agent": "ZAP", "accept": "*/*"},
    )

    headers = injector._request_headers(result)
    url, body, probe_headers, changed, location = injector._build_probe_variant(result, "ARGUS_HEADER", headers)

    assert url == "http://localhost:8080/api/projects"
    assert body == ""
    assert changed is True
    assert location == "header"
    assert probe_headers["User-Agent"] == "ARGUS_HEADER"
    assert probe_headers["accept"] == "*/*"


def test_rebuilds_xml_xpath_payloads_have_specific_type():
    from payload_injector import XmlXPathInjector

    injector = XmlXPathInjector()
    result = DetectionResult(
        method="GET",
        url="http://localhost:8080/search?expr=book",
        param="expr",
        risk="HIGH",
        plugin_name="XPath Injection",
        plugin_id="90021",
        injection_type=InjectionType.XPATH,
        raw_request_url="http://localhost:8080/search?expr=book",
    )

    url, body, changed, location = injector._build_variant(result, "' or '1'='1")

    assert changed is True
    assert location == "query"
    assert "expr=%27+or+%271%27%3D%271" in url
    assert body == ""
