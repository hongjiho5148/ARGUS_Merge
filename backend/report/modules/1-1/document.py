from __future__ import annotations

import base64
import html
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml


BACKEND_ROOT = Path(__file__).resolve().parents[3]
SK_SHIELDUS_G11_GUIDE = (
    BACKEND_ROOT
    / "diagnosis"
    / "modules"
    / "1-1"
    / "assets"
    / "sk_shieldus_g11_response.md"
)

CSRF_GUIDE = """1. CSRF Token 적용

서버는 예측 불가능한 CSRF Token을 발급해야 합니다.
POST, PUT, PATCH, DELETE 등 상태 변경 요청마다 CSRF Token을 검증해야 합니다.
Token은 사용자 세션과 연결되어야 하며, 요청 본문 또는 전용 헤더(`X-CSRF-Token`, `X-XSRF-Token`)로 전달하도록 구성합니다.
Token이 없거나 일치하지 않으면 요청을 거부해야 합니다.

2. Origin / Referer 검증

상태 변경 API는 `Origin` 또는 `Referer` 헤더를 검증해야 합니다.
허용된 도메인에서 온 요청만 처리하고, 외부 Origin 또는 누락된 Origin/Referer 요청은 차단합니다.
일부 환경에서 Referer가 제거될 수 있으므로 `Origin` 검증을 우선 적용하고 Referer는 보조 검증으로 사용하는 것이 좋습니다.

3. SameSite Cookie 설정

세션 쿠키에는 `SameSite=Lax` 또는 `SameSite=Strict`를 설정합니다.
인증 쿠키에는 함께 `HttpOnly`, `Secure` 옵션도 적용합니다.

예시:
`Set-Cookie: SESSION=...; HttpOnly; Secure; SameSite=Lax`

4. CORS Credential 제한

`Access-Control-Allow-Credentials: true`를 사용하는 경우, `Access-Control-Allow-Origin: *`를 사용하지 않습니다.
허용 Origin을 명시적으로 제한하고, 신뢰할 수 있는 프론트엔드 도메인만 허용합니다.

5. 중요 기능 추가 보호

결제, 예약, 회원정보 변경, 비밀번호 변경, 권한 변경 등 민감한 기능은 CSRF Token 외에도 추가 확인 절차를 둡니다.
예: 비밀번호 재입력, OTP, 재인증, 사용자 확인 팝업 등

6. GET 요청으로 상태 변경 금지

GET 요청은 조회 용도로만 사용합니다.
상태 변경은 반드시 POST, PUT, PATCH, DELETE 등 명확한 메서드로 처리하고, 해당 요청에 CSRF 방어를 적용합니다.
"""
 

def _value(value: Any, fallback: str = "-") -> str:
    if value is None or value == "":
        return fallback
    return str(value)


def _esc(value: Any) -> str:
    return html.escape(_value(value), quote=True)


def _slug(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9]+", "-", str(value or "").strip())
    return text.strip("-") or "x"


def _finding_id_prefix(evidence: dict[str, Any]) -> str:
    vuln_type = _value(evidence.get("vuln_type"), "").strip()
    method = _value(evidence.get("method"), "GET").upper()
    url = _value(evidence.get("url"), "/").rstrip("/") or "/"
    path = urlsplit(url).path.strip("/") or "root"
    param = _value(evidence.get("param"), "").lower()
    role = _value(evidence.get("account_role"), "").strip().upper()
    parts = [vuln_type, method, path, param]
    if role:
        parts.append(role)
    return "1-1_" + "_".join(_slug(part) for part in parts) + "_"


def _load_capture_results(evidence_root: Path) -> dict[str, list[dict[str, Any]]]:
    summary_path = evidence_root / "capture-summary.json"
    if not summary_path.is_file():
        return {}
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except Exception:
        return {}

    results: dict[str, list[dict[str, Any]]] = {}
    for row in summary.get("results") or []:
        if not isinstance(row, dict):
            continue
        finding_id = str(row.get("finding_id") or "")
        artifacts = row.get("artifacts") or []
        if finding_id and isinstance(artifacts, list):
            results[finding_id] = [item for item in artifacts if isinstance(item, dict)]
    return results


def _image_data_uri(path: Path) -> str | None:
    if not path.is_file():
        return None
    suffix = path.suffix.lower()
    mime = "image/png"
    if suffix in {".jpg", ".jpeg"}:
        mime = "image/jpeg"
    elif suffix == ".webp":
        mime = "image/webp"
    return f"data:{mime};base64,{base64.b64encode(path.read_bytes()).decode('ascii')}"


def _finding_images(
    evidence_root: Path,
    capture_results: dict[str, list[dict[str, Any]]],
    evidence: dict[str, Any],
) -> list[tuple[str, str]]:
    prefix = _finding_id_prefix(evidence)
    finding_id = next((key for key in capture_results if key.startswith(prefix)), "")
    if not finding_id:
        return []

    images: list[tuple[str, str]] = []
    root = evidence_root.resolve()
    for artifact in capture_results.get(finding_id, []):
        raw_path = str(artifact.get("path") or "")
        if not raw_path.lower().endswith((".png", ".jpg", ".jpeg", ".webp")):
            continue
        marker = "/evidence/"
        rel_path = raw_path.split(marker, 1)[1] if marker in raw_path else raw_path
        image_path = (evidence_root / rel_path).resolve()
        try:
            image_path.relative_to(root)
        except ValueError:
            continue
        data_uri = _image_data_uri(image_path)
        if data_uri:
            images.append((str(artifact.get("kind") or "evidence"), data_uri))
    return images


def _csrf_block(evidence: dict[str, Any]) -> str:
    if not _is_csrf_evidence(evidence):
        return ""
    csrf = evidence.get("csrf_defenses")
    if not isinstance(csrf, dict):
        return ""
    verdict_labels = {"confirmed": "확정", "candidate": "후보 (수동 확인 필요)"}
    verdict = verdict_labels.get(str(csrf.get("verdict") or ""))
    verdict_line = (
        f'<span>판정: {_esc(verdict)} - {_esc(csrf.get("reason"))}</span>'
        if verdict and csrf.get("reason")
        else ""
    )
    return f"""
      <div class="csrf">
        <strong>CSRF 방어 확인</strong>
        {verdict_line}
        <span>Origin/Referer 우회:{_esc(csrf.get("origin_referer_bypass"))}</span>
        <span>CSRF Token 부재: {_esc(csrf.get("csrf_token_absent"))}</span>
        <span>SameSite 미흡: {_esc(csrf.get("unsafe_samesite"))}</span>
        <span>실패 방어 수: {_esc(csrf.get("failed_count"))}</span>
      </div>
    """


_XSS_LEVEL_LABELS = {
    "candidate": "서버 저장 취약 (필터링 없이 저장·반환, 현재 화면에서 실행 미확인)",
    "high": "실행 가능성 높음 (HTML 응답에 이스케이프 없이 반사)",
    "confirmed": "실행 확정 (브라우저에서 스크립트 실행 확인)",
}
_BROWSER_STATUS_LABELS = {
    "executed": "alert 다이얼로그 발생 (실행 확인)",
    "inert_text": "화면에 이스케이프된 텍스트로만 표시 (실행 안 됨)",
    "not_found": "화면에서 payload를 찾지 못함",
    "not_checked": "브라우저 확인 미수행",
}


def _xss_level_block(evidence: dict[str, Any]) -> str:
    level = str(evidence.get("xss_level") or "")
    if _is_csrf_evidence(evidence) or level not in _XSS_LEVEL_LABELS:
        return ""
    browser = evidence.get("browser_verification")
    status = str(browser.get("status") or "") if isinstance(browser, dict) else ""
    browser_line = (
        f"<span>브라우저 검증: {_esc(_BROWSER_STATUS_LABELS.get(status, status))}</span>" if status else ""
    )
    return f"""
      <div class="csrf">
        <strong>Stored XSS 판정 등급</strong>
        <span>등급: {_esc(_XSS_LEVEL_LABELS[level])}</span>
        {browser_line}
      </div>
    """


def _is_csrf_evidence(evidence: dict[str, Any]) -> bool:
    label = f"{evidence.get('vuln_type') or ''} {evidence.get('alert') or ''}"
    return "csrf" in label.lower()


def _load_sk_shieldus_guide() -> str:
    if not SK_SHIELDUS_G11_GUIDE.is_file():
        return ""
    return SK_SHIELDUS_G11_GUIDE.read_text(encoding="utf-8").strip()


def _guide_for_finding(evidence: dict[str, Any]) -> str:
    if _is_csrf_evidence(evidence):
        return CSRF_GUIDE
    return (
        _load_sk_shieldus_guide()
        or str(evidence.get("sk_shieldus_guide") or "")
        or str(evidence.get("remediation_guide") or "")
        or str(evidence.get("remediation_summary") or "")
        or "SK쉴더스 가이드 문구가 제공되면 이 영역에 반영합니다."
    )


def _inline_markdown(text: str) -> str:
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", _esc(text))


def _guide_to_html(markdown: str) -> str:
    lines = [line.rstrip() for line in markdown.splitlines()]
    html_parts: list[str] = []
    paragraph: list[str] = []
    bullet_items: list[str] = []
    table_rows: list[list[str]] = []

    def flush_paragraph() -> None:
        nonlocal paragraph
        if paragraph:
            html_parts.append(f"<p>{_inline_markdown(' '.join(paragraph))}</p>")
            paragraph = []

    def flush_bullets() -> None:
        nonlocal bullet_items
        if bullet_items:
            html_parts.append("<ul>" + "".join(f"<li>{item}</li>" for item in bullet_items) + "</ul>")
            bullet_items = []

    def flush_table() -> None:
        nonlocal table_rows
        if not table_rows:
            return
        rows = [row for row in table_rows if not all(set(cell) <= {"-"} for cell in row)]
        if rows:
            head, *body = rows
            html_parts.append(
                "<table class='guide-table'><thead><tr>"
                + "".join(f"<th>{_inline_markdown(cell)}</th>" for cell in head)
                + "</tr></thead><tbody>"
                + "".join(
                    "<tr>" + "".join(f"<td>{_inline_markdown(cell)}</td>" for cell in row) + "</tr>"
                    for row in body
                )
                + "</tbody></table>"
            )
        table_rows = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            flush_paragraph()
            flush_bullets()
            flush_table()
            continue

        if stripped.startswith("|") and stripped.endswith("|"):
            flush_paragraph()
            flush_bullets()
            table_rows.append([cell.strip() for cell in stripped.strip("|").split("|")])
            continue
        flush_table()

        if re.match(r"^\d+\.\s+", stripped):
            flush_paragraph()
            flush_bullets()
            title = re.sub(r"^\d+\.\s+", "", stripped)
            html_parts.append(f"<h4>{_inline_markdown(title)}</h4>")
            continue

        if stripped.endswith(":") and len(stripped) < 40:
            flush_paragraph()
            flush_bullets()
            html_parts.append(f"<h5>{_inline_markdown(stripped[:-1])}</h5>")
            continue

        if stripped.startswith("- "):
            flush_paragraph()
            bullet_items.append(_inline_markdown(stripped[2:]))
            continue

        paragraph.append(stripped)

    flush_paragraph()
    flush_bullets()
    flush_table()
    return "<div class='guide'>" + "".join(html_parts) + "</div>"


def _detection_method_text(evidence: dict[str, Any]) -> str:
    if _is_csrf_evidence(evidence):
        return (
            "상태 변경 요청에서 Origin/Referer 헤더를 제거하거나 변조한 요청을 재전송하고, "
            "CSRF Token 누락 및 SameSite Cookie 설정 미흡 조건에서도 요청이 수락되는지 확인했습니다."
        )
    return (
        "입력 파라미터에 XSS 페이로드를 주입한 뒤 데이터를 저장하고, 동일 리소스를 다시 조회하여 "
        "응답 또는 화면에 스크립트가 실행 가능한 형태로 남아 있는지 확인했습니다."
    )


def _result_reason_text(finding: dict[str, Any], evidence: dict[str, Any]) -> str:
    return _value(
        evidence.get("validation_reason")
        or evidence.get("evidence")
        or evidence.get("vuln_description")
        or evidence.get("description")
        or finding.get("message"),
        "탐지 요청 결과 취약 조건이 확인되었습니다.",
    )


def _result_table_html(finding: dict[str, Any], evidence: dict[str, Any]) -> str:
    occurrences = evidence.get("csrf_occurrences")
    if _is_csrf_evidence(evidence) and isinstance(occurrences, list) and occurrences:
        rows = []
        for item in occurrences:
            if not isinstance(item, dict):
                continue
            rows.append(
                "<tr>"
                f"<td>{_esc(item.get('method') or evidence.get('method'))}</td>"
                f"<td>{_esc(item.get('url') or evidence.get('url'))}</td>"
                f"<td>{_esc(item.get('param') or evidence.get('param'))}</td>"
                "</tr>"
            )
        if rows:
            return (
                "<table>"
                "<tr><th>Method</th><th>URL</th><th>Parameter</th></tr>"
                + "".join(rows)
                + "</table>"
            )

    return f"""
      <table>
        <tr><th>Method</th><td>{_esc(evidence.get("method"))}</td></tr>
        <tr><th>URL</th><td>{_esc(evidence.get("url"))}</td></tr>
        <tr><th>Parameter</th><td>{_esc(evidence.get("param"))}</td></tr>
      </table>
    """


def _manual_verification_html(evidence: dict[str, Any]) -> str:
    if _is_csrf_evidence(evidence):
        note = (
            "CSRF 자동 진단은 Origin/Referer 제거 또는 변조, CSRF Token 누락, SameSite Cookie 미흡 조건에서 "
            "상태 변경 요청이 수락되는지를 기준으로 취약 가능성을 판단합니다. 다만 인증 방식, 세션 쿠키의 SameSite 설정, "
            "CORS preflight 발생 여부, 요청 Content-Type에 따라 실제 악용 가능성이 달라질 수 있으므로 수동 진단이 필요합니다."
        )
        reason = (
            "CSRF는 브라우저의 SameSite 정책, 실제 프론트엔드 요청 방식, CORS preflight 발생 여부에 따라 "
            "공격 성공 여부가 달라질 수 있습니다. 따라서 Burp Suite Repeater 또는 CSRF PoC로 피해자 로그인 세션에서 "
            "Origin/Referer 제거·변조 및 CSRF Token 제거·변조 조건을 재현해야 합니다."
        )
    else:
        note = (
            "Stored XSS 자동 진단은 페이로드 저장 및 재조회 응답을 기준으로 취약 가능성을 판단합니다. "
            "다만 프론트엔드 렌더링 방식, HTML escaping/sanitizing 처리, CSP 정책, 사용자 권한에 따라 "
            "실제 스크립트 실행 여부가 달라질 수 있으므로 수동 진단이 필요합니다."
        )
        reason = (
            "XSS는 응답에 페이로드가 남아 있어도 프론트엔드 렌더링 방식이나 escaping 정책에 따라 실제 실행 여부가 달라질 수 있습니다. "
            "따라서 브라우저에서 해당 URL을 열어 스크립트 실행, DOM 반영, 저장 데이터 재조회 여부를 수동으로 확인해야 합니다."
        )
    return f"""
      <div class="manual-check">
        <strong>수동 진단 필요</strong>
        <p>{_esc(note)}</p>
        <p><b>근거:</b> {_esc(reason)}</p>
      </div>
    """


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = str(finding.get("severity") or "").lower()
        if severity in counts:
            counts[severity] += 1
        elif severity in {"중요", "상", "높음"}:
            counts["high"] += 1
        elif severity in {"중", "보통"}:
            counts["medium"] += 1
        elif severity in {"하", "낮음"}:
            counts["low"] += 1
        else:
            counts["info"] += 1
    return counts


def _vulnerability_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"XSS": 0, "CSRF": 0, "Other": 0}
    for finding in findings:
        evidence = dict(finding.get("evidence") or {})
        label = str(evidence.get("vuln_type") or finding.get("message") or "")
        if "csrf" in label.lower():
            counts["CSRF"] += 1
        elif "xss" in label.lower() or "script" in label.lower():
            counts["XSS"] += 1
        else:
            counts["Other"] += 1
    return counts


def _cover_html(report: dict[str, Any], generated_at: str, finding_count: int) -> str:
    return f"""
    <section class="cover">
      <div class="cover-kicker">ARGUS Security Diagnosis Report</div>
      <h1>1-1 입력 데이터 검증 및 표현 취약점 진단 결과서</h1>
      <p class="cover-subtitle">XSS / CSRF 진단 결과와 증거 이미지, 대응방안을 정리한 보고서입니다.</p>
      <dl class="cover-meta">
        <dt>진단 항목</dt><dd>1-1</dd>
        <dt>진단 대상</dt><dd>XSS / CSRF attack surface</dd>
        <dt>진단 상태</dt><dd>{_esc(report.get("status"))}</dd>
        <dt>생성 일시</dt><dd>{_esc(generated_at)}</dd>
        <dt>취약점 수</dt><dd>{finding_count}</dd>
      </dl>
    </section>
    """


def _summary_html(report_findings: list[dict[str, Any]]) -> str:
    severity = _severity_counts(report_findings)
    vuln = _vulnerability_counts(report_findings)
    rows = []
    for index, finding in enumerate(report_findings, start=1):
        evidence = dict(finding.get("evidence") or {})
        title = evidence.get("vuln_type") or finding.get("message") or "Finding"
        rows.append(
            "<tr>"
            f"<td>{index}</td>"
            f"<td>{_esc(title)}</td>"
            f"<td>{_esc(finding.get('severity'))}</td>"
            f"<td>{_esc(evidence.get('method'))}</td>"
            f"<td>{_esc(evidence.get('url'))}</td>"
            f"<td>{_esc(evidence.get('param'))}</td>"
            "</tr>"
        )

    return f"""
    <section class="summary">
      <h2>진단 결과 요약</h2>
      <div class="summary-grid">
        <div class="summary-card"><strong>{len(report_findings)}</strong><span>전체 취약점</span></div>
        <div class="summary-card"><strong>{vuln["XSS"]}</strong><span>XSS</span></div>
        <div class="summary-card"><strong>{vuln["CSRF"]}</strong><span>CSRF</span></div>
        <div class="summary-card"><strong>{severity["high"] + severity["critical"]}</strong><span>High 이상</span></div>
      </div>
      <table class="summary-table">
        <tr><th>No</th><th>취약점명</th><th>Severity</th><th>Method</th><th>URL</th><th>Parameter</th></tr>
        {"".join(rows) or "<tr><td colspan='6'>표시할 취약점이 없습니다.</td></tr>"}
      </table>
    </section>
    """


def _finding_html(
    index: int,
    finding: dict[str, Any],
    evidence_root: Path,
    capture_results: dict[str, list[dict[str, Any]]],
) -> str:
    evidence = dict(finding.get("evidence") or {})
    title = evidence.get("vuln_type") or finding.get("message") or "Finding"
    images = _finding_images(evidence_root, capture_results, evidence)
    image_html = ""
    if images:
        image_html = "<div class='images'>" + "".join(
            f"""
            <figure>
              <img src="{src}" alt="{_esc(kind)} evidence">
              <figcaption>{_esc("실제 화면 증거" if kind == "site" else "요청/응답 증거")}</figcaption>
            </figure>
            """
            for kind, src in images
        ) + "</div>"
    else:
        image_html = "<p class='muted'>캡처 이미지가 연결되지 않았습니다.</p>"

    guide = _guide_for_finding(evidence)

    return f"""
    <section class="finding">
      <h2>{index}. {_esc(title)}</h2>
      <h3>문제점</h3>
      <div class="problem">
        <p>{_esc(_detection_method_text(evidence))}</p>
        <p>{_esc(_result_reason_text(finding, evidence))}</p>
      </div>
      {_manual_verification_html(evidence)}
      <h4 class="table-title">관련 URL</h4>
      {_result_table_html(finding, evidence)}
      {_csrf_block(evidence)}
      {_xss_level_block(evidence)}
      <h3>증거 이미지</h3>
      {image_html}
      <h3>대응방안 (SK 가이드라인)</h3>
      {_guide_to_html(str(guide))}
    </section>
    """

def _html_to_pdf(html_content: str, output_path: Path) -> None:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError("Playwright is required to generate PDF reports.") from exc

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            page = browser.new_page(viewport={"width": 1280, "height": 720})
            page.set_content(html_content, wait_until="networkidle")
            page.pdf(
                path=str(output_path),
                format="A4",
                print_background=True,
                margin={"top": "14mm", "right": "12mm", "bottom": "14mm", "left": "12mm"},
            )
        finally:
            browser.close()


def generate_report_document(report_dir: Path) -> Path:
    report_path = report_dir / "latest.yaml"
    if not report_path.is_file():
        raise FileNotFoundError(str(report_path))

    evidence_root = report_dir / "evidence"
    report = yaml.safe_load(report_path.read_text(encoding="utf-8")) or {}
    capture_results = _load_capture_results(evidence_root)
    findings = [
        row for row in (report.get("findings") or [])
        if isinstance(row, dict) and not ((row.get("evidence") or {}).get("screenshot_capture"))
    ]
    report_findings = [
        row for row in findings
        if str(row.get("severity") or "").lower() not in {"info", "pass"}
    ] or findings

    detail_body = "\n".join(
        _finding_html(index, finding, evidence_root, capture_results)
        for index, finding in enumerate(report_findings, start=1)
    )
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    body = (
        _cover_html(report, generated_at, len(report_findings))
        + _summary_html(report_findings)
        + (detail_body or "<p class='muted'>표시할 진단 결과가 없습니다.</p>")
    )
    html_content = f"""<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <title>ARGUS 1-1 진단 결과서</title>
  <style>
    body {{ margin: 0; background: #f6f8fb; color: #172033; font-family: Arial, 'Malgun Gothic', sans-serif; font-size: 14px; }}
    main {{ max-width: 980px; margin: 0 auto; padding: 32px 24px 56px; }}
    header {{ margin-bottom: 24px; border-bottom: 2px solid #172033; padding-bottom: 16px; }}
    h1 {{ margin: 0 0 8px; font-size: 28px; }}
    h2 {{ margin: 0 0 18px; font-size: 20px; color: #991b1b; }}
    h3 {{ margin: 22px 0 9px; padding-bottom: 5px; border-bottom: 1px solid #e2e8f0; font-size: 15px; color: #1f2937; }}
    h4.table-title {{ margin: 14px 0 7px; font-size: 12px; color: #64748b; }}
    .meta {{ color: #64748b; font-size: 13px; }}
    .cover {{ min-height: 820px; display: flex; flex-direction: column; justify-content: center; padding: 36px; background: #fff; border: 1px solid #d9e2ef; border-radius: 8px; page-break-after: always; }}
    .cover-kicker {{ margin-bottom: 18px; color: #2563eb; font-size: 13px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }}
    .cover h1 {{ max-width: 760px; margin: 0; color: #111827; font-size: 34px; line-height: 1.25; }}
    .cover-subtitle {{ margin-top: 16px; color: #475569; font-size: 16px; }}
    .cover-meta {{ display: grid; grid-template-columns: 120px 1fr; gap: 8px 16px; margin-top: 44px; max-width: 620px; }}
    .cover-meta dt {{ color: #64748b; font-weight: 700; }}
    .cover-meta dd {{ margin: 0; color: #172033; }}
    .summary {{ margin: 24px 0; padding: 24px; background: #fff; border: 1px solid #d9e2ef; border-radius: 8px; page-break-after: always; }}
    .summary-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 16px 0 20px; }}
    .summary-card {{ padding: 14px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; }}
    .summary-card strong {{ display: block; color: #0f172a; font-size: 24px; }}
    .summary-card span {{ color: #64748b; font-size: 12px; }}
    .summary-table th {{ width: auto; }}
    .finding {{ margin: 24px 0; padding: 24px; background: #fff; border: 1px solid #d9e2ef; border-radius: 6px; page-break-inside: avoid; }}
    .problem {{ display: grid; gap: 8px; padding: 12px 14px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; }}
    .manual-check {{ display: grid; gap: 7px; margin-top: 12px; padding: 12px 14px; background: #fff7ed; border: 1px solid #fed7aa; border-radius: 6px; }}
    .manual-check strong {{ color: #9a3412; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th {{ width: 130px; background: #eef3f8; text-align: left; color: #475569; }}
    th, td {{ border: 1px solid #d9e2ef; padding: 8px 10px; vertical-align: top; word-break: break-all; }}
    code {{ font-family: Consolas, monospace; }}
    p {{ margin: 0; line-height: 1.65; white-space: pre-wrap; }}
    ul {{ margin: 8px 0 0 18px; padding: 0; line-height: 1.65; }}
    li {{ margin: 3px 0; }}
    .images {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px; margin-top: 8px; }}
    figure {{ margin: 0; border: 1px solid #d9e2ef; background: #f8fafc; }}
    img {{ display: block; width: 100%; height: auto; }}
    figcaption {{ padding: 7px 9px; color: #64748b; font-size: 12px; border-top: 1px solid #d9e2ef; }}
    .csrf {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 6px; padding: 12px; background: #fff7ed; border: 1px solid #fed7aa; font-size: 13px; }}
    .csrf strong {{ grid-column: 1 / -1; }}
    .guide {{ display: grid; gap: 12px; }}
    .guide h4 {{ margin: 8px 0 0; padding: 9px 12px; background: #e8f1fb; border-left: 4px solid #2563eb; font-size: 14px; color: #1e3a8a; }}
    .guide h5 {{ margin: 3px 0 0; font-size: 13px; color: #334155; }}
    .guide p {{ margin: 0; }}
    .guide-table th {{ width: auto; text-align: center; }}
    .guide-table td {{ text-align: center; }}
    .guide code {{ display: inline-block; margin: 2px 2px 2px 0; padding: 2px 5px; border-radius: 4px; background: #eef2ff; color: #3730a3; font-size: 12px; }}
    .muted {{ color: #64748b; }}
    @media print {{ body {{ background: #fff; }} main {{ padding: 0; }} .finding {{ border-color: #999; }} }}
  </style>
</head>
<body>
  <main>
    {body or "<p class='muted'>표시할 진단 결과가 없습니다.</p>"}
  </main>
</body>
</html>
"""
    output_path = report_dir / "diagnosis-result.pdf"
    _html_to_pdf(html_content, output_path)
    return output_path


generate_g11_report_document = generate_report_document
