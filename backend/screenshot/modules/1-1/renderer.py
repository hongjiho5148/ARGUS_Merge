"""Render deterministic pages and small overlays for 1-1 (Stored XSS / CSRF) evidence."""

from __future__ import annotations

import html
import re

from models import EvidenceCase
from redaction import redact_text


def _esc(value: object) -> str:
    return html.escape(str(value if value is not None else ""))


def _highlight(escaped_text: str, needles: list[str]) -> str:
    """Wrap each needle (already-present, un-escaped source string) in a red
    <mark> inside the already-escaped text, so the evidence panel visually
    points at *why* this is a finding — the injected payload, or the accepted
    response status for a CSRF. Needles are escaped the same way as the body
    before matching so they line up."""
    out = escaped_text
    for needle in needles:
        source = str(needle or "").strip()
        if not source:
            continue
        escaped_needle = _esc(source)
        if escaped_needle and escaped_needle in out and "<mark" not in escaped_needle:
            out = out.replace(escaped_needle, f'<mark class="hit">{escaped_needle}</mark>')
    return out


_EVIDENCE_PAGE_CSS = """
* { box-sizing: border-box; }
html, body { width: 1280px; height: 720px; margin: 0; overflow: hidden; }
body { background: #0b111a; color: #d8e0ea; font-family: Arial, "Noto Sans KR", sans-serif; }
.shell { height: 720px; padding: 24px; display: grid; grid-template-rows: auto 1fr; gap: 16px; }
.top { border: 1px solid #233248; background: #101927; border-radius: 8px; padding: 14px 16px; }
.kicker { color: #00f5c8; font-size: 12px; font-weight: 800; letter-spacing: .04em; text-transform: uppercase; }
.title { margin-top: 8px; display: flex; align-items: baseline; gap: 12px; min-width: 0; }
.title b { color: #f3f7fb; font-size: 20px; white-space: nowrap; }
.title span { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  color: #91a2ba; font: 12px ui-monospace, SFMono-Regular, Menlo, monospace; }
.meta { margin-top: 10px; display: grid; grid-template-columns: 120px 1fr 120px 1fr; gap: 7px 12px;
  color: #91a2ba; font: 12px ui-monospace, SFMono-Regular, Menlo, monospace; }
.meta strong { color: #e3ebf5; font-weight: 700; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.panels { min-height: 0; display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.panel { min-width: 0; min-height: 0; border: 1px solid #233248; background: #0f1724; border-radius: 8px;
  display: grid; grid-template-rows: 38px 1fr; overflow: hidden; }
.panel h2 { margin: 0; padding: 11px 14px; background: #151f30; color: #8be59f; font-size: 13px; }
pre { margin: 0; padding: 14px; overflow: hidden; white-space: pre-wrap; overflow-wrap: anywhere;
  color: #d8e0ea; font: 11px/1.45 ui-monospace, SFMono-Regular, Menlo, monospace; }
mark.hit { background: #ff2d55; color: #fff; padding: 0 2px; border-radius: 2px; font-weight: 700; }
.verdict { margin-top: 12px; border-top: 1px solid #233248; padding-top: 10px; }
.verdict .vh { color: #ffb84d; font-size: 12px; font-weight: 800; letter-spacing: .03em; text-transform: uppercase; }
.verdict ul { list-style: none; margin: 8px 0 0; padding: 0; display: grid; gap: 5px; }
.verdict li { display: grid; grid-template-columns: 18px 132px 1fr; align-items: baseline; gap: 8px;
  font: 12px ui-monospace, SFMono-Regular, Menlo, monospace; }
.verdict li .mk { font-weight: 800; text-align: center; }
.verdict li.bad .mk { color: #ff2d55; }
.verdict li.ok .mk { color: #22c55e; }
.verdict li .nm { color: #e3ebf5; font-weight: 700; }
.verdict li .dt { color: #91a2ba; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.verdict .vc { margin-top: 9px; color: #ffd7de; background: #2a1520; border: 1px solid #5a2130;
  border-radius: 6px; padding: 7px 10px; font: 12px/1.4 Arial, "Noto Sans KR", sans-serif; font-weight: 700; }
"""


def _fit_font_size(text: str) -> float:
    """Shrink the panel font as text grows so the whole (windowed) evidence
    body stays visible in the fixed-height ``<pre>`` instead of being
    clipped by ``overflow: hidden``. Sized against the panel's ~580x460px
    text area at the base 11px/1.45 line-height."""
    length = len(text)
    if length <= 1600:
        return 11
    if length <= 2400:
        return 9.5
    if length <= 3200:
        return 8.2
    if length <= 4200:
        return 7
    return 6


def _csrf_verdict_html(case: EvidenceCase) -> str:
    """A compact "why is this a finding" panel for CSRF: the 3-defense verdict
    the scanner already computed (which of Origin/Referer validation, anti-CSRF
    token, SameSite cookie failed) so the evidence explains the problem instead
    of only showing an accepted request/response with no baseline to compare."""
    if case.vuln_type != "CSRF":
        return ""
    d = case.metadata.get("csrf_defenses") if isinstance(case.metadata, dict) else None
    if not isinstance(d, dict) or not d:
        return ""

    tampered = d.get("tampered_ref_status")
    no_ref = d.get("no_ref_status")
    failed = d.get("failed_count")
    has_cookie = bool(d.get("has_cookie_session"))
    rows = [
        (
            d.get("origin_referer_bypass"),
            "Origin/Referer 검증",
            f"위조 Origin/Referer 요청을 수락 (위조 {tampered}, 기준선 {no_ref})"
            if tampered is not None
            else "미검증 (상태 파괴 엔드포인트라 요청을 보내지 않음)",
        ),
        (
            d.get("csrf_token_absent"),
            "anti-CSRF 토큰",
            "요청에 CSRF 토큰 없음, 서버도 요구하지 않음",
        ),
        (
            d.get("unsafe_samesite"),
            "SameSite 쿠키",
            "세션 쿠키에 SameSite=Lax/Strict 미설정"
            if has_cookie
            else "쿠키 세션 아님 — 해당 없음",
        ),
    ]
    items = []
    for failed_flag, name, detail in rows:
        cls = "bad" if failed_flag else "ok"
        mark = "✗" if failed_flag else "✓"
        items.append(
            f'<li class="{cls}"><span class="mk">{mark}</span>'
            f'<span class="nm">{_esc(name)}</span>'
            f'<span class="dt">{_esc(detail)}</span></li>'
        )
    verdict_labels = {"confirmed": "확정", "candidate": "후보(수동 확인 필요)"}
    verdict = d.get("verdict")
    if verdict in verdict_labels and d.get("reason"):
        conclusion = f"판정: {verdict_labels[verdict]} — {d.get('reason')}"
    elif isinstance(failed, int) and failed >= 2:
        conclusion = f"{failed}/3 방어 실패 → 공격자 페이지가 피해자 세션으로 이 요청을 몰래 성공시킬 수 있음"
    else:
        conclusion = f"{failed}/3 방어 실패"
    return (
        '<div class="verdict">'
        '<div class="vh">CSRF 방어 3종 검사 결과</div>'
        f'<ul>{"".join(items)}</ul>'
        f'<div class="vc">{_esc(conclusion)}</div>'
        "</div>"
    )


def render_evidence_page(case: EvidenceCase) -> str:
    """Standalone Request/Response evidence page, not an overlay."""
    exchange = case.exchange
    request_text = redact_text(exchange.request_text)
    response_text = redact_text(exchange.response_text)
    target = exchange.display_url or exchange.url
    request_heading = "Request (attack)" if case.vuln_type == "Stored XSS" else "Request"
    request_font = _fit_font_size(request_text)
    response_font = _fit_font_size(response_text)

    # Red-highlight the evidence's smoking gun — the exact bytes that make this
    # a finding.
    if case.vuln_type == "Stored XSS":
        # The injected payload (and its ARGUS marker) wherever it's reflected.
        marker_match = re.search(r"ARGUS_[A-Za-z0-9_]+", case.payload or "")
        req_needles = [case.payload, marker_match.group(0) if marker_match else ""]
        resp_needles = list(req_needles)
    else:
        # CSRF: the "why" is a state-changing request authenticated *only* by
        # the victim's ambient session (Authorization / Cookie headers) — with
        # no anti-CSRF token — being accepted. Mark those session headers in
        # the request and the accepted status line in the response.
        req_needles = ['"Authorization"', '"authorization"', '"Cookie"', '"cookie"']
        resp_needles = []
        status_match = re.search(r"HTTP/\d(?:\.\d)?\s+\d{3}[^\n]*", response_text)
        if status_match:
            resp_needles.append(status_match.group(0).strip())
    request_html = _highlight(_esc(request_text), req_needles)
    response_html = _highlight(_esc(response_text), resp_needles)
    verdict_html = _csrf_verdict_html(case)

    return f"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<title>ARGUS Evidence {_esc(case.finding_id)}</title>
<style>{_EVIDENCE_PAGE_CSS}</style>
</head>
<body>
  <main class="shell">
    <section class="top">
      <div class="kicker">ARGUS Evidence</div>
      <div class="title"><b>{_esc(case.vuln_type)}</b><span>{_esc(target)}</span></div>
      <div class="meta">
        <span>finding</span><strong>{_esc(case.finding_id)}</strong>
        <span>status</span><strong>{_esc(exchange.status_code or "-")}</strong>
        <span>param</span><strong>{_esc(case.parameter)}</strong>
        <span>payload</span><strong>{_esc(case.payload)}</strong>
      </div>
      {verdict_html}
    </section>
    <section class="panels">
      <article class="panel"><h2>{_esc(request_heading)}</h2><pre style="font-size:{request_font}px">{request_html}</pre></article>
      <article class="panel"><h2>Response</h2><pre style="font-size:{response_font}px">{response_html}</pre></article>
    </section>
  </main>
</body>
</html>"""


def render_session_badge(case: EvidenceCase) -> tuple[str, str]:
    """Small top banner marking a screenshot as the victim's authenticated session."""
    css = """
#argus-session-badge { position: fixed !important; top: 12px !important; right: 12px !important;
  z-index: 2147483647 !important; background: #191b1e !important; color: #e4e8ec !important;
  border: 1px solid #7b5ce7 !important; border-radius: 8px !important; padding: 8px 14px !important;
  font: 12px ui-monospace, monospace !important; box-shadow: 0 4px 14px rgba(0,0,0,.4) !important; }
#argus-session-badge b { color: #9d84f0 !important; }
"""
    markup = (
        f'<div id="argus-session-badge"><b>피해자 세션</b> role={_esc(case.account_role or "-")} '
        f"&nbsp;finding={_esc(case.finding_id)}</div>"
    )
    return css, markup


