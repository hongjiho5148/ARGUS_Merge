"""Playwright screenshot engine for 1-1 (Stored XSS / CSRF) evidence."""

from __future__ import annotations

import re
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

from models import AttackerSubmission, CaptureArtifact, EvidenceCase
from redaction import redact_text
from renderer import render_evidence_page, render_session_badge
from route_discovery import (
    click_element_by_id,
    click_element_by_index,
    click_element_by_text,
    discover_site_url,
    frontend_base_url,
)
from replay import forged_request, login_via_ui, login_victim


def _load_stored_xss_verdict():
    """Shared verdict rules live in the diagnosis package; load them by path so
    this standalone capture process does not import the whole package."""
    import importlib.util

    path = Path(__file__).resolve().parents[3] / "diagnosis" / "stored_xss_verdict.py"
    spec = importlib.util.spec_from_file_location("argus_stored_xss_verdict", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_verdict = _load_stored_xss_verdict()
BROWSER_NOT_CHECKED = _verdict.BROWSER_NOT_CHECKED
browser_status_from_capture = _verdict.browser_status_from_capture


_EMAIL_IN_BODY_RE = re.compile(r'"email"\s*:\s*"([^"]+)"')


def _victim_email_from_case(case: EvidenceCase) -> str:
    """The account a stored-XSS payload was saved under, recovered from the
    finding's own recorded response. A "my-profile" stored XSS (GET
    /members/me/profile) echoes the owning user's email in its body, so the
    screenshot can log in as exactly that user — the payload only renders on
    that specific user's page, so the right role isn't enough. Returns "" when
    the response carries no email (e.g. a public post/comment), in which case
    the caller falls back to role-based account selection."""
    match = _EMAIL_IN_BODY_RE.search(case.exchange.response_text or "")
    return match.group(1) if match else ""


def _frontend_base_url() -> str:
    return frontend_base_url()


def _ui_url_for(case: EvidenceCase) -> str:
    """Return the configured frontend fallback URL.

    The capture module is intentionally app-neutral. If a scanner later records
    an exact UI URL for a finding, prefer it; otherwise use the configured
    frontend root. Stored XSS captures try network-based route discovery before
    falling back here.
    """
    explicit = str(case.metadata.get("ui_url") or case.metadata.get("page_url") or "").strip()
    if explicit:
        return explicit
    base = _frontend_base_url()
    return f"{base}/"


def _site_url_for(case: EvidenceCase, context) -> str:
    explicit = str(case.metadata.get("ui_url") or case.metadata.get("page_url") or "").strip()
    if explicit:
        case.metadata["route_discovery"] = {
            "url": explicit,
            "source": "finding_metadata",
            "fallback": False,
        }
        return explicit

    discovered = discover_site_url(context, case)
    case.metadata["route_discovery"] = discovered
    return str(discovered.get("url") or _ui_url_for(case))


def _goto_site(page, case: EvidenceCase, ui_url: str) -> None:
    """Navigate to the discovered page and, if reaching the actual content
    required clicking into a specific list item during discovery (e.g. a
    post's comments), replay that same click here."""
    discovery = case.metadata.get("route_discovery") or {}
    # An index click is replayed from the page it was found on (``route``), not
    # from the page the click ended up on (``url``).
    start_url = str(discovery.get("route") or "") if discovery.get("click_index") is not None else ""
    page.goto(start_url if start_url.startswith("http") else ui_url, wait_until="domcontentloaded", timeout=20_000)
    page.wait_for_timeout(1_200)
    click_id = str(discovery.get("click_id") or "").strip()
    click_text = str(discovery.get("click_text") or "").strip()
    click_index = discovery.get("click_index")
    if click_index is not None:
        clicked = click_element_by_index(page, int(click_index))
        case.metadata["route_click_replay"] = {"click_index": click_index, "ok": bool(clicked)}
        page.wait_for_timeout(1_000)
    elif click_id:
        clicked = click_element_by_id(page, click_id)
        case.metadata["route_click_replay"] = {"click_id": click_id, "ok": bool(clicked)}
        page.wait_for_timeout(1_000)
    elif click_text:
        clicked = click_element_by_text(page, click_text)
        case.metadata["route_click_replay"] = {"click_text": click_text, "ok": bool(clicked)}
        page.wait_for_timeout(1_000)


def _inject_overlay(page, css: str, markup: str) -> None:
    page.evaluate(
        """({css, markup}) => {
          document.getElementById('argus-evidence-root')?.remove();
          const root = document.createElement('div');
          root.id = 'argus-evidence-root';
          const style = document.createElement('style');
          style.textContent = css;
          root.appendChild(style);
          const body = document.createElement('div');
          body.innerHTML = markup;
          while (body.firstChild) root.appendChild(body.firstChild);
          document.documentElement.appendChild(root);
        }""",
        {"css": css, "markup": markup},
    )


def _scroll_to_payload(page, payload: str, param: str = "") -> dict:
    """Scroll the actual injected payload text into view, instead of a
    generic hero heuristic, so the screenshot shows exactly where the
    malicious content renders on the page. Also tries the payload's
    ``ARGUS_...`` marker token alone, since the surrounding markup/quotes
    can be re-escaped differently by the frontend than the raw payload."""
    return page.evaluate(
        """(payload) => {
          if (!payload) return {found: false, reason: 'no_payload'};
          const marker = (/ARGUS_[A-Za-z0-9_]+/.exec(payload) || [])[0];
          // The scanner stores several payload variants per field, each with a
          // different random suffix; the one left in the DB (and shown on the
          // page) may not be the exact variant this finding recorded. Fall back
          // to the field-scoped prefix (e.g. "ARGUS_name") so the right field's
          // payload still matches regardless of which variant's suffix survived.
          const markerPrefix = (/ARGUS_[a-z]+/i.exec(payload) || [])[0];
          const candidates = [payload, marker, markerPrefix].filter(Boolean);

          const highlight = (el) => {
            try {
              el.style.outline = '3px solid #ff0044';
              el.style.outlineOffset = '2px';
              el.style.boxShadow = '0 0 0 3px rgba(255,0,68,0.35)';
            } catch (e) {}
          };
          const reveal = (el) => {
            // The payload may live in a collapsed/off-screen section; make
            // sure the element is scrolled into the middle of the viewport.
            el.scrollIntoView({block: 'center', inline: 'nearest'});
          };

          // 1. Visible text nodes (payload rendered as page text).
          const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
          let node;
          while ((node = walker.nextNode())) {
            const text = node.nodeValue || '';
            for (const needle of candidates) {
              if (needle && text.includes(needle)) {
                const el = node.parentElement;
                if (el) { reveal(el); highlight(el); return {found: true, matched: needle, tag: el.tagName, via: 'text'}; }
              }
            }
          }

          // 2. Form-field values and attributes (payload stored in an
          //    <input value="...">, a title/placeholder/alt, etc.) — these
          //    are NOT text nodes, so the TreeWalker above never sees them.
          //    A profile-name XSS shows up here, not in step 1.
          const attrEls = document.querySelectorAll(
            'input, textarea, select, [value], [placeholder], [title], [alt], [aria-label]'
          );
          for (const el of attrEls) {
            const vals = [
              el.value,
              el.getAttribute && el.getAttribute('value'),
              el.getAttribute && el.getAttribute('placeholder'),
              el.getAttribute && el.getAttribute('title'),
              el.getAttribute && el.getAttribute('alt'),
              el.getAttribute && el.getAttribute('aria-label'),
            ];
            for (const v of vals) {
              if (!v) continue;
              for (const needle of candidates) {
                if (needle && String(v).includes(needle)) {
                  reveal(el); highlight(el);
                  return {found: true, matched: needle, tag: el.tagName, via: 'attribute'};
                }
              }
            }
          }
          return {found: false, reason: 'not_in_dom'};
        }""",
        payload,
    )


def _scroll_past_common_hero(page) -> dict:
    """Move below a generic first-viewport hero when real page content starts
    further down. Keeps short pages untouched."""
    return page.evaluate(
        """() => {
          const viewport = window.innerHeight || 720;
          const doc = document.documentElement;
          const body = document.body;
          const maxScroll = Math.max(0, (doc.scrollHeight || body.scrollHeight || 0) - viewport);
          if (maxScroll < 160) return {scrolled: false, y: 0, reason: 'short_page'};

          const selectors = ['main > section', 'section', '[role="main"] > *', 'article', '.hero'];
          const candidates = [];
          for (const selector of selectors) {
            for (const el of document.querySelectorAll(selector)) {
              const rect = el.getBoundingClientRect();
              if (rect.height < 80 || rect.width < 320) continue;
              const top = rect.top + window.scrollY;
              if (top > 120) candidates.push({top, height: rect.height, selector});
            }
          }

          candidates.sort((a, b) => a.top - b.top);
          let target = candidates.find((item) => item.top >= viewport * 0.55 && item.top <= viewport * 1.35);
          if (!target) {
            const first = candidates[0];
            if (first && first.height >= viewport * 0.55) {
              target = candidates.find((item) => item.top > first.top + Math.min(first.height, viewport * 1.1));
            }
          }
          if (!target) return {scrolled: false, y: 0, reason: 'no_hero_candidate'};

          const y = Math.max(0, Math.min(Math.round(target.top - 48), maxScroll));
          if (y < 120) return {scrolled: false, y: 0, reason: 'target_too_close'};
          window.scrollTo(0, y);
          return {scrolled: true, y, reason: 'content_after_hero', selector: target.selector};
        }"""
    )


def _os_screenshot(path: Path) -> bool:
    """Real OS-level screen capture of the browser window (address bar and
    all), used when ``scrot`` (Linux/X11) isn't installed. This is what
    actually shows the real URL — no fabricated overlay needed.

    Grabs the whole screen rather than a fixed 1280x720 box: OS window chrome
    (title bar) and Windows DPI scaling both shift where the browser window
    (and its address bar) actually lands, so a fixed top-left crop was
    cutting the address bar off.
    """
    try:
        from PIL import ImageGrab
    except ImportError:
        return False
    try:
        image = ImageGrab.grab(all_screens=True)
        image.save(str(path))
        return True
    except Exception:
        try:
            image = ImageGrab.grab()
            image.save(str(path))
            return True
        except Exception:
            return False


def _screenshot(page, path: Path) -> None:
    # Every stage is guarded so one failing capture can't abort the whole run.
    # scrot / the X11 display can die mid-run (Broken pipe), and previously any
    # error other than "scrot not installed" propagated and killed every
    # remaining finding's capture. Fall through scrot -> OS grab -> Playwright
    # page screenshot, and if even that fails, give up on this one image
    # rather than crashing the batch.
    try:
        page.emulate_media(reduced_motion="reduce")
        page.evaluate("document.fonts.ready")
        page.bring_to_front()
        page.wait_for_timeout(250)
    except Exception:
        pass
    try:
        subprocess.run(["scrot", "--overwrite", str(path)], check=True, timeout=20)
        if path.exists():
            return
    except (FileNotFoundError, subprocess.SubprocessError, OSError, BrokenPipeError):
        pass
    try:
        if _os_screenshot(path):
            return
    except Exception:
        pass
    # Last resort: page-content-only screenshot (no browser chrome/address bar).
    try:
        page.screenshot(path=str(path))
    except Exception as exc:
        print(f"[screenshot] all capture methods failed for {path.name}: {exc}", flush=True)


def _scrot_screenshot(path: Path) -> bool:
    try:
        subprocess.run(["scrot", "--overwrite", str(path)], check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return _os_screenshot(path)


def _safe_response_text(response) -> str:
    """Some endpoints (e.g. a report export) return a binary body (PDF,
    xlsx, ...) rather than text/JSON. ``APIResponse.text()`` assumes UTF-8
    and raises ``UnicodeDecodeError`` on those — describe the body instead
    of crashing the whole capture run."""
    content_type = str(response.headers.get("content-type") or "").lower()
    looks_textual = any(marker in content_type for marker in ("text", "json", "xml", "javascript", "html")) or not content_type
    if looks_textual:
        try:
            return response.text()
        except UnicodeDecodeError:
            pass
    try:
        body = response.body()
    except Exception:
        body = b""
    return f"<binary response, content-type={content_type or 'unknown'}, {len(body)} bytes>"


def _capture_dialog(dialog, path: Path, events: list[dict[str, str]]) -> None:
    events.append({"type": dialog.type, "message": dialog.message})
    time.sleep(0.7)
    captured = _scrot_screenshot(path)
    events[-1]["screenshot"] = str(path) if captured else ""
    dialog.dismiss()


def _capture_static_evidence(case: EvidenceCase, context, output_dir: Path) -> list[CaptureArtifact]:
    """Site + Request/Response overlay, using the scanner's recorded evidence
    text as-is. Used for Stored XSS always, and for CSRF when live replay is
    disabled (``--no-replay``)."""
    artifacts: list[CaptureArtifact] = []
    # Log the victim in before route discovery/navigation so role-gated
    # content (e.g. a seller-only listing) actually renders, and so the
    # discovery probe below sees the same authenticated pages a real user
    # would.
    case.metadata["login"] = login_victim(context.request, case.exchange.url, case.account_role)
    ui_url = _site_url_for(case, context)

    # If route discovery couldn't find a real frontend page for this finding
    # and fell back to the site root, the API is vulnerable but the frontend
    # has no screen that reaches it (e.g. a seller registration endpoint with
    # no seller-portal UI). Capturing the root here would just show an
    # unrelated home page that reads as misleading evidence — so skip the site
    # shot and keep only the request/response evidence, same as CSRF.
    route_info = case.metadata.get("route_discovery") or {}
    # ``route`` can be a bare path ("/mypage") or a full URL
    # ("http://localhost:5173/") depending on which phase produced it — reduce
    # both to a path before the root check.
    # Judge on the page actually *landed on* (``url``), not ``route`` — for a
    # click-through result ``route`` is the starting candidate (e.g. root),
    # while ``url`` is where the click ended up (e.g. /feed, /mypage).
    url_val = str(route_info.get("url") or route_info.get("route") or "")
    best_route = (urlsplit(url_val).path if "://" in url_val else url_val).rstrip("/")
    # A page counts as "mapped" (worth a screenshot) when route discovery found
    # a specific non-root page for it, OR when the payload is actually visible
    # on the page it landed on (content_match) — that visible payload is the
    # real proof even if it happened to be the home page (e.g. a seller's
    # dashboard table on root). A bare-root request-match with no visible
    # payload is just the home page calling many APIs, not this finding's
    # screen, so it's treated as unmapped: evidence only.
    has_content_match = bool(route_info.get("content_match"))
    site_mapped = has_content_match or (
        (not route_info.get("fallback", True)) and best_route not in ("", "/")
    )

    # A "my-record" stored XSS (profile / members/me) renders only on the
    # owning account's *own* page, so it must be captured while logged in as
    # exactly that victim (email-matched). If login fell back to a different
    # account — e.g. SUPER_ADMIN can't log into the customer frontend, so it
    # lands on the seller session — the page would show the wrong user's data
    # (seller's profile, not the admin's), which is misleading. In that case
    # skip the site shot and keep only the request/response evidence.
    # "own record" endpoints follow a REST convention — a "/me" segment or a
    # "profile" resource — not any one app's schema (works for /users/me,
    # /account/me, /members/me/profile, ...). No app-specific names.
    url_lower = str(case.exchange.url).lower()
    is_self_record = "profile" in url_lower or "/me/" in url_lower or url_lower.rstrip("/").endswith("/me")
    ui_login = case.metadata.get("ui_login") or {}
    if is_self_record and ui_login.get("matched_by") != "email":
        site_mapped = False
        case.metadata["site_skip_reason"] = "self-record finding, not logged in as the exact victim account"

    case.metadata["site_mapped"] = site_mapped
    if case.vuln_type == "Stored XSS" and not site_mapped:
        case.metadata["browser_verification"] = {
            "status": BROWSER_NOT_CHECKED,
            "reason": case.metadata.get("site_skip_reason") or "no frontend page found for this API",
        }

    if site_mapped:
        dialog_events: list[dict[str, str]] = []
        alert_path = output_dir / "01_site_alert.png"
        page = context.new_page()
        page.on("dialog", lambda dialog: _capture_dialog(dialog, alert_path, dialog_events))
        _goto_site(page, case, ui_url)
        try:
            page.wait_for_load_state("networkidle", timeout=5_000)
        except Exception:
            pass
        if alert_path.exists():
            artifacts.append(CaptureArtifact(kind="site_alert", path=str(alert_path)))
        if dialog_events:
            case.metadata["dialogs"] = dialog_events

        payload_scroll = _scroll_to_payload(page, case.payload, case.parameter) if case.vuln_type == "Stored XSS" else None
        if payload_scroll and payload_scroll.get("found"):
            case.metadata["site_scroll"] = {"payload_scroll": payload_scroll}
        else:
            case.metadata["site_scroll"] = {
                "payload_scroll": payload_scroll,
                "hero_scroll": _scroll_past_common_hero(page),
            }
        if case.vuln_type == "Stored XSS":
            case.metadata["browser_verification"] = {
                "status": browser_status_from_capture(dialog_events, payload_scroll, case.payload),
                "dialogs": dialog_events,
                "payload_found_in_dom": bool(payload_scroll and payload_scroll.get("found")),
                "page": page.url,
            }
        path = output_dir / "01_site.png"
        _screenshot(page, path)
        artifacts.append(CaptureArtifact(kind="site", path=str(path)))
        page.close()

    # Request/response evidence — always. Sole image (01_) when the site was
    # skipped, second image (02_) when a real page was captured.
    evidence_name = "02_evidence.png" if site_mapped else "01_evidence.png"
    page = context.new_page()
    page.set_content(render_evidence_page(case), wait_until="domcontentloaded")
    path = output_dir / evidence_name
    _screenshot(page, path)
    artifacts.append(CaptureArtifact(kind="evidence", path=str(path)))
    page.close()
    return artifacts


def _capture_csrf(case: EvidenceCase, context, output_dir: Path) -> tuple[list[CaptureArtifact], AttackerSubmission, dict]:
    """Log the victim in, capture the real target page before the forged
    request, fire the forged request through the victim's own (shared)
    cookie jar, then capture the same real page again to show the resulting
    state change. No fabricated attacker-site page is rendered — the point
    is to show what the vulnerable app itself does, not a fake lure UI."""
    # CSRF evidence is purely the request/response: the forged request is
    # accepted by the server using the victim's own authenticated session.
    # No frontend screenshot is taken — a victim before/after page shot would
    # at best show an unrelated screen and read as misleading evidence, so
    # CSRF findings get only the request/response evidence image.
    artifacts: list[CaptureArtifact] = []
    login = login_victim(context.request, case.exchange.url, case.account_role)

    forged = forged_request(case.exchange.url, case.exchange.method, case.exchange.request_text)
    headers = {"Content-Type": forged["content_type"]} if forged.get("content_type") else {}
    started = time.perf_counter()
    response = context.request.fetch(
        forged["url"],
        method=forged["method"],
        headers=headers,
        data=forged["body"],
        timeout=20_000,
        fail_on_status_code=False,
    )
    elapsed_ms = (time.perf_counter() - started) * 1000
    submission = AttackerSubmission(
        target_url=forged["url"],
        method=forged["method"],
        request_body=redact_text(forged["body"]),
        status_code=response.status,
        response_text=redact_text(_safe_response_text(response)[:4000]),
        elapsed_ms=elapsed_ms,
    )

    # The actual request/response the scanner used to prove this finding
    # (saved in latest.yaml) — the sole, and sufficient, CSRF evidence.
    page = context.new_page()
    page.set_content(render_evidence_page(case), wait_until="domcontentloaded")
    path = output_dir / "01_evidence.png"
    _screenshot(page, path)
    artifacts.append(CaptureArtifact(kind="evidence", path=str(path)))
    page.close()

    return artifacts, submission, login


def capture_case(case: EvidenceCase, output_dir: Path, *, perform_replay: bool = True) -> list[CaptureArtifact]:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError(
            "Playwright is required for evidence capture. "
            "Install dependencies and run `playwright install chromium`."
        ) from exc

    output_dir.mkdir(parents=True, exist_ok=True)
    for previous in output_dir.glob("*.png"):
        previous.unlink()

    with sync_playwright() as playwright:
        launch_args = [
            "--window-position=0,0",
            "--window-size=1280,720",
            "--force-device-scale-factor=1",
        ]
        if sys.platform.startswith("linux"):
            try:
                host_gateway = socket.gethostbyname("host.docker.internal")
                launch_args.insert(0, f"--host-resolver-rules=MAP localhost {host_gateway}")
            except socket.gaierror:
                pass  # not running inside the Docker capture container; use normal localhost resolution
        browser = playwright.chromium.launch(headless=False, args=launch_args)
        context = browser.new_context(no_viewport=True, locale="ko-KR")

        # Log in through the real UI once per context. Cookies persist for
        # the whole context, and this app re-hydrates its client-side auth
        # store from cookies on every fresh page load — so every page
        # opened afterward (route discovery probes, capture screenshots)
        # sees a properly logged-in session without repeating this.
        login_page = context.new_page()
        victim_email = _victim_email_from_case(case)
        ui_login = login_via_ui(login_page, case.account_role, victim_email)
        case.metadata["ui_login"] = ui_login
        print(f"[ui-login] {case.finding_id}: {ui_login}", flush=True)
        login_page.close()

        if case.vuln_type == "CSRF" and perform_replay:
            artifacts, submission, login = _capture_csrf(case, context, output_dir)
            case.attacker_submission = submission
            case.metadata["login"] = login
        elif case.vuln_type in {"Stored XSS", "CSRF"}:
            artifacts = _capture_static_evidence(case, context, output_dir)
        else:
            raise ValueError(f"Unsupported vuln_type for 1-1 capture: {case.vuln_type}")

        context.close()
        browser.close()

    return artifacts
