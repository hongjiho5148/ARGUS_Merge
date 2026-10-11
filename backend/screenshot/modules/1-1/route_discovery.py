"""Frontend route discovery for 1-1 evidence screenshots.

The scanner knows the API request that proved a finding. This module tries to
find the frontend page that naturally calls that API by visiting configured
frontend routes and watching Playwright network requests.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import yaml

from models import EvidenceCase


def _log(message: str) -> None:
    print(f"[route-discovery] {message}", flush=True)

_DYNAMIC_SEGMENT_RE = re.compile(
    r"^(?:\d+|[0-9a-fA-F]{8,}(?:-[0-9a-fA-F]{4,})*)$"
)
# HTTP-status error routes an SPA registers (/401, /403, /404, /500, /503, ...).
_ERROR_PAGE_RE = re.compile(r"^/[1-5]\d\d$")
_STATIC_SUFFIXES = (
    ".css",
    ".js",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".woff",
    ".woff2",
    ".ttf",
)


def _backend_root() -> Path:
    # /app/screenshot/modules/1-1 -> /app
    return Path(__file__).resolve().parents[3]


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError:
        return {}
    except Exception:
        return {}


_FALLBACK_FRONTEND_BASE = "http://localhost:5173"
_DEFAULT_FRONTEND_PORTS = ("5173", "5174")


def _configured_frontend_base() -> str:
    explicit = str(os.getenv("ARGUS_SCREENSHOT_FRONTEND_BASE") or "").strip()
    if explicit:
        return explicit

    root = _backend_root()
    for name in ("config.docker.yaml", "config.yaml"):
        cfg = _read_yaml(root / name)
        base = str(((cfg.get("inventory") or {}).get("markdown") or {}).get("frontend_base_url") or "").strip()
        if base:
            return base
    return ""


def frontend_base_url() -> str:
    explicit = str(os.getenv("ARGUS_SCREENSHOT_FRONTEND_BASE") or "").strip()
    if explicit:
        return explicit.rstrip("/")

    configured = _configured_frontend_base()
    if configured:
        return _docker_reachable_url(configured).rstrip("/")

    discovered = _frontend_base_from_api_tree()
    if discovered:
        return _docker_reachable_url(discovered).rstrip("/")

    return _docker_reachable_url(_FALLBACK_FRONTEND_BASE).rstrip("/")


def _docker_reachable_url(raw: str) -> str:
    """Docker reachability for the frontend dev server has two different
    fixes depending on the hostname, and they are NOT interchangeable:

    - "localhost" is remapped to the host machine at the *browser network
      layer*, via Chrome's ``--host-resolver-rules=MAP localhost ...``
      launch flag (engine.py). The URL text is left as "localhost"
      untouched — that matters because rewriting it here would also change
      the Origin/Referer header the browser presents to the target app's
      own backend. Some apps validate that header on sensitive endpoints
      (this one included — there's a CSRF finding specifically about a
      referer/token check on its login endpoint), and a rewritten Origin
      like "host.docker.internal:5173" fails that check even with correct
      credentials, while a real "localhost:5173" origin (what a manual
      browser session naturally sends) passes.
    - "127.0.0.1" has no equivalent resolver-rule, so it's still rewritten
      to host.docker.internal here — the only way to make it reachable at
      all from inside the container.
    """
    parsed = urlsplit(raw)
    if parsed.hostname != "127.0.0.1":
        return raw

    running_in_docker = os.getenv("ARGUS_PROBE_HOST") == "host.docker.internal" or Path("/app").exists()
    if not running_in_docker:
        return raw

    host = "host.docker.internal"
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme, host, parsed.path, parsed.query, parsed.fragment))


def _api_tree_paths() -> list[Path]:
    data_dir = _backend_root() / "data"
    return [
        data_dir / "api-tree-verified.json",
        data_dir / "api-tree-ready.json",
        data_dir / "api-tree.json",
    ]


def _frontend_base_from_api_tree() -> str:
    for path in _api_tree_paths():
        if not path.exists():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        for endpoint in payload.get("endpoints") or []:
            if not isinstance(endpoint, dict) or not _is_frontend_endpoint(endpoint):
                continue
            raw = str(endpoint.get("base_url") or endpoint.get("url") or "").strip()
            if not raw:
                continue
            parsed = urlsplit(raw)
            if parsed.scheme and parsed.netloc:
                return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    return ""


def _normalize_netloc(netloc: str) -> str:
    return str(netloc or "").replace("host.docker.internal", "localhost")


def _frontend_routes_from_api_tree(base: str) -> list[str]:
    """Frontend routes ARGUS's own inventory pipeline already found
    (api-tree.json's ``kind == "frontend"`` rows). This isn't a
    hand-written route table — it's generated per-target by ARGUS's own
    probing/crawling during inventory collection, so reading it is no less
    generic than our own live crawl; it's just often faster and more
    complete when it's available, and a no-op (empty list) when it isn't."""
    base_netloc = _normalize_netloc(urlsplit(base).netloc)
    routes: list[str] = []
    seen: set[str] = set()
    for path in _api_tree_paths():
        if not path.exists():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        for endpoint in payload.get("endpoints") or []:
            if not isinstance(endpoint, dict) or not _is_frontend_endpoint(endpoint):
                continue
            row_netloc = _normalize_netloc(urlsplit(str(endpoint.get("base_url") or "")).netloc)
            if row_netloc != base_netloc:
                continue
            route = str(endpoint.get("path") or "").strip()
            if not route or not route.startswith("/") or route.startswith("/api/"):
                continue
            if route not in seen:
                seen.add(route)
                routes.append(route)
    return routes


def _examples_dirs() -> list[Path]:
    candidates = [
        Path("/workspace/examples"),  # docker-compose: "..:/workspace:ro", if the repo IS workspace root
        _backend_root().parent / "examples",  # local dev: backend/../examples
    ]
    workspace = Path("/workspace")
    if workspace.is_dir():
        try:
            # "..:/workspace:ro" is relative to the compose file's own
            # directory (the repo root), so /workspace is actually the
            # repo's *parent* — sibling checkouts included — and the repo
            # itself shows up one level down as /workspace/<repo-name>.
            # The repo folder name isn't known ahead of time (it's
            # whatever the checkout happens to be called), so glob for it
            # instead of hardcoding one.
            candidates.extend(sorted(workspace.glob("*/examples")))
        except OSError:
            pass
    seen: set[Path] = set()
    dirs: list[Path] = []
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if resolved in seen or not candidate.is_dir():
            continue
        seen.add(resolved)
        dirs.append(candidate)
    return dirs


def _routes_from_plain_list(path: Path) -> list[str]:
    routes: list[str] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return routes
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # gen_onde_lists_from_swagger.py's "*.params.txt" format is
        # "/path | param, param" — the route is just the part before "|".
        route = line.split("|", 1)[0].strip()
        if route.startswith("/"):
            routes.append(route)
    return routes


def _frontend_routes_from_examples() -> list[str]:
    """Per-target frontend route lists a teammate supplies when onboarding a
    new app (e.g. ``examples/onde-url-list.txt``) — this is the team's
    existing convention for handing ARGUS a target's frontend routes, found
    generically by globbing for "*url-list*.txt" rather than a hardcoded
    per-target filename, so a different target's differently-named list
    still gets picked up the same way."""
    routes: list[str] = []
    seen: set[str] = set()
    for examples_dir in _examples_dirs():
        for txt_path in sorted(examples_dir.glob("*url-list*.txt")):
            for route in _routes_from_plain_list(txt_path):
                if route not in seen:
                    seen.add(route)
                    routes.append(route)
    return routes


def _is_frontend_endpoint(endpoint: dict[str, Any]) -> bool:
    kind = str(endpoint.get("kind") or "").lower()
    if "front" in kind or kind in {"page", "route", "ui"}:
        return True
    sources = " ".join(str(item) for item in endpoint.get("sources") or [])
    if "frontend" in sources.lower():
        return True
    base = str(endpoint.get("base_url") or endpoint.get("url") or "").lower()
    ports = set(_DEFAULT_FRONTEND_PORTS)
    configured_port = urlsplit(_configured_frontend_base()).port
    if configured_port:
        ports.add(str(configured_port))
    return any(f":{port}" in base for port in ports)


def _extract_internal_links(page, base_netloc: str) -> list[str]:
    """Pull same-origin ``<a href>`` targets out of the rendered page — this
    is how the crawl actually discovers pages like ``/feed`` or ``/seller``
    instead of relying on any pre-supplied route list."""
    try:
        hrefs = page.eval_on_selector_all(
            "a[href]", "els => els.map(e => e.getAttribute('href'))"
        )
    except Exception:
        return []
    routes: list[str] = []
    for href in hrefs or []:
        href = str(href or "").strip()
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
            continue
        parsed = urlsplit(href)
        if parsed.scheme and parsed.netloc and parsed.netloc != base_netloc:
            continue  # external link
        path = parsed.path or "/"
        if not path.startswith("/") or path.startswith("/api/"):
            continue
        routes.append(path)
    return routes


def _discover_button_routes(page, base_netloc: str, origin_url: str) -> list[str]:
    """Some SPA navigation is a ``<button onClick={() => navigate(...)}>``
    (React Router's programmatic navigation) rather than a real ``<a href>``
    — ``_extract_internal_links`` can't see those at all. Click candidate
    nav buttons instead and watch where the URL actually lands (client-side
    routing changes ``page.url`` without a full reload), returning to
    ``origin_url`` between attempts so each click starts from a clean page."""
    discovered: list[str] = []
    try:
        buttons = page.locator("header button, nav button, [role='navigation'] button")
        count = min(buttons.count(), 12)
    except Exception as exc:
        _log(f"button-discovery: locator failed: {exc}")
        return discovered
    _log(f"button-discovery: found {count} nav button(s) to try")
    for i in range(count):
        try:
            button = buttons.nth(i)
            label = (button.inner_text(timeout=500) or "").strip().lower()
        except Exception:
            continue
        if not label or any(word in label for word in _DANGEROUS_CLICK_WORDS):
            continue
        try:
            before_url = page.url
            button.click(timeout=2000)
            page.wait_for_timeout(500)
            after_url = page.url
            if after_url != before_url:
                parsed = urlsplit(after_url)
                if parsed.netloc == base_netloc:
                    path = parsed.path or "/"
                    if path not in discovered:
                        discovered.append(path)
            if page.url != origin_url:
                page.goto(origin_url, wait_until="domcontentloaded", timeout=10_000)
                page.wait_for_timeout(300)
        except Exception:
            continue
    _log(f"button-discovery: discovered routes {discovered}")
    return discovered


def _path_of(url: str) -> str:
    return urlsplit(str(url or "")).path or "/"


def _segments(path: str) -> list[str]:
    return [segment for segment in path.strip("/").split("/") if segment]


def _normalized_segments(path: str) -> list[str]:
    normalized: list[str] = []
    for segment in _segments(path):
        normalized.append("{id}" if _DYNAMIC_SEGMENT_RE.match(segment) else segment)
    return normalized


_API_PREFIX_SEGMENTS = {"api", "v1", "v2", "v3"}


def _derive_candidate_routes(case: EvidenceCase) -> list[str]:
    """Guess plausible frontend routes directly from the target API path's
    own segments (e.g. .../api/v1/seller/accommodations -> try /seller).
    Some routes (an admin/seller portal) have no clickable path to them
    anywhere in the UI at all, so crawling alone can never reach them — this
    is a generic heuristic seed, not an ONDE-specific route table, and every
    guess is still verified the same way as any other candidate: by
    actually navigating there and checking what it calls/shows."""
    candidates: list[str] = []
    for segment in _segments(_path_of(case.exchange.url)):
        if segment.lower() in _API_PREFIX_SEGMENTS or _DYNAMIC_SEGMENT_RE.match(segment):
            continue
        route = f"/{segment}"
        if route not in candidates:
            candidates.append(route)
    return candidates


def _json_body_from_response(response_text: str) -> Any | None:
    """Recover the JSON body from the scanner's pre-formatted response text
    (the same "...\\n\\nBody:\\n{body}" layout ``request_text.py`` parses for
    requests). When the scanner windows a long response down to just the
    record containing the payload, it can prepend a human-readable comment
    line before the JSON — skip to the first '{' or '[' rather than assuming
    the JSON starts exactly at the separator."""
    text = response_text or ""
    if "\n\nBody:\n" not in text:
        return None
    body = text.split("\n\nBody:\n", 1)[1]
    starts = [i for i in (body.find("{"), body.find("[")) if i != -1]
    if not starts:
        return None
    try:
        return json.loads(body[min(starts):])
    except Exception:
        return None


def _numeric_ids_from_json(node: Any, depth: int = 0) -> list[str]:
    """Pull plausible resource ids out of a JSON evidence record: any key
    containing "id" (case-insensitive) with a numeric-looking value. This is
    a generic REST convention (postId, commentId, id, ...), not a per-app
    schema, so it works the same regardless of the target's own field
    naming."""
    if depth > 4:
        return []
    ids: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if "id" in key.lower() and isinstance(value, (int, str)) and str(value).strip().isdigit():
                ids.append(str(value).strip())
            ids.extend(_numeric_ids_from_json(value, depth + 1))
    elif isinstance(node, list):
        for item in node:
            ids.extend(_numeric_ids_from_json(item, depth + 1))
    return ids


def _resource_ids_from_evidence(case: EvidenceCase) -> list[str]:
    """Best-effort resource id recovery from the scanner's own recorded
    evidence response. A finding's own URL is sometimes a bare list endpoint
    (.../api/v1/posts, no id in the path at all) — for those, the only way
    to know *which* list item to click into is the id inside the specific
    record the payload actually lives in, which the scanner already
    captured as evidence."""
    body = _json_body_from_response(case.exchange.response_text)
    if body is None:
        return []
    seen: set[str] = set()
    ordered: list[str] = []
    for rid in _numeric_ids_from_json(body):
        if rid not in seen:
            seen.add(rid)
            ordered.append(rid)
    return ordered


def _content_needles(case: EvidenceCase) -> list[str]:
    """Distinctive text to look for directly in a candidate page's rendered
    body — the strongest possible signal that we've found the right page,
    since it means the exploited content is genuinely visible there (not
    just "this page calls a similar-looking API")."""
    if case.vuln_type != "Stored XSS" or not case.payload:
        return []
    needles = [case.payload]
    marker = re.search(r"ARGUS_[A-Za-z0-9_]+", case.payload)
    if marker:
        needles.append(marker.group(0))
    return needles


def _page_contains_text(page, needles: list[str]) -> str | None:
    needles = [n for n in needles if n]
    if not needles:
        return None
    try:
        body_text = page.inner_text("body")
    except Exception:
        return None
    for needle in needles:
        if needle in body_text:
            return needle
    return None


def _canonical_api_path(path: str) -> str:
    """Strip a dev-server proxy prefix (e.g. Vite's ``/user-api/api/v1/...``
    -> ``/api/v1/...``) so requests observed through the frontend's own
    proxy still compare equal to the finding's raw backend path. Without
    this, every request the frontend fires scores as a partial/segment
    match at best (never the full exact-match bonus), which lets an
    unrelated page tie with the actual right one and win by visit order."""
    idx = path.find("/api/")
    return path[idx:] if idx > 0 else path


def _request_matches_target(case: EvidenceCase, url: str) -> bool:
    """The 1-2 module's entire page-selection rule, as one predicate: does
    this observed request hit the finding's *exact* API path?

    No partial credit, no segment-overlap scoring — a page either calls the
    target endpoint or it doesn't. Scoring was the whole source of trouble:
    a header/wallet widget's sibling call (.../members/me/mileage) partially
    matched .../members/me/profile on every single page, so nothing could
    tell the pages apart and root always won by visit order. An exact match
    is unambiguous.

    Dynamic ids are normalised so an observed ``/posts/3860/comments`` still
    matches a ``/posts/{id}/comments`` target. The HTTP method is ignored on
    purpose — the frontend often fetches via GET what the finding recorded
    as a POST/PUT, and the path alone identifies the page."""
    target_path = _canonical_api_path(_path_of(case.exchange.url)).rstrip("/")
    seen_path = _canonical_api_path(_path_of(url)).rstrip("/")
    if not target_path or not seen_path:
        return False
    if seen_path == target_path:
        return True
    return _normalized_segments(seen_path) == _normalized_segments(target_path)


def _request_matches_target_exact(case: EvidenceCase, url: str) -> bool:
    """Same path as the target with the *same* dynamic ids — not just the
    same shape. For a /posts/3860/comments finding this is True only for
    /posts/3860/comments, not /posts/9999/comments. Used during click-through
    so brute-force clicking through a feed doesn't stop on the first post that
    merely calls *a* comments endpoint; it has to reach the specific post the
    payload actually lives in."""
    target = _canonical_api_path(_path_of(case.exchange.url)).rstrip("/")
    seen = _canonical_api_path(_path_of(url)).rstrip("/")
    return bool(target) and bool(seen) and target == seen


def _request_is_ancestor_of_target(case: EvidenceCase, url: str) -> bool:
    """Does this request hit a *parent* of the finding's API path? The page
    that lists items (``/api/v1/posts``) is the one you click through to
    reach a single item's detail (``/api/v1/posts/{id}/comments``); the page
    that shows a profile summary (``/api/v1/members/me``) is where a "manage
    profile" tab lives that loads ``/api/v1/members/me/profile``. So the page
    calling an ancestor path is exactly where click-through should start — a
    generic way to find "which listing/parent screen leads to this content"
    without knowing the app's routes."""
    target = _normalized_segments(_canonical_api_path(_path_of(case.exchange.url)))
    seen = _normalized_segments(_canonical_api_path(_path_of(url)))
    # Need a real API path (at least /api/vN/<resource>) and a strict prefix
    # relationship — the observed path is shorter and matches segment-for-
    # segment up to its own length.
    if len(seen) < 3 or len(seen) >= len(target):
        return False
    return target[: len(seen)] == seen


def _strip_api_prefix(segments: list[str]) -> list[str]:
    i = 0
    while i < len(segments) and segments[i].lower() in _API_PREFIX_SEGMENTS:
        i += 1
    return segments[i:]


def _request_shares_resource_scope(case: EvidenceCase, url: str) -> bool:
    """Does this request live under the same resource scope as the target,
    even if neither path is an ancestor of the other? The account screen
    (/mypage) typically fires several sibling calls at once —
    ``/members/me/reservations``, ``/members/me/wallet``, ... — and never the
    bare ``/members/me`` parent, so strict-ancestor matching misses it. But
    those siblings share the ``members/me`` prefix with a
    ``/members/me/profile`` finding, which is enough to identify the screen
    the finding's content lives on. Requires at least two shared leading
    resource segments (after the /api/vN/ boilerplate) so unrelated
    ``/members/<other>`` calls don't match."""
    target = _strip_api_prefix(_normalized_segments(_canonical_api_path(_path_of(case.exchange.url))))
    seen = _strip_api_prefix(_normalized_segments(_canonical_api_path(_path_of(url))))
    if len(target) < 2 or len(seen) < 2:
        return False
    shared = 0
    for a, b in zip(target, seen):
        if a != b:
            break
        shared += 1
    return shared >= 2


_DANGEROUS_CLICK_WORDS = (
    "삭제", "차단", "신고", "결제", "취소", "탈퇴", "로그아웃", "환불", "정지",
    "delete", "cancel", "block", "report", "payment", "refund", "withdraw", "logout", "ban",
)


def _click_matching(page, needle: str) -> dict[str, Any] | None:
    """Find and click a visible element that references ``needle`` (a link
    href, a data-id-ish attribute, or plain visible text — e.g. a post card
    in a feed list), skipping anything that reads like a destructive
    action. This is what lets discovery reach content that only loads after
    a click (a post's comments, a detail view, ...) without knowing
    anything about the app's specific markup ahead of time. ``needle`` can
    be a URL resource id or an actual content string (the payload/marker)."""
    if not needle:
        return None
    locator = page.locator(
        f'a[href*="{needle}"], [data-id="{needle}"], [id*="{needle}"]'
    ).or_(page.get_by_text(needle, exact=False))
    try:
        count = min(locator.count(), 5)
    except Exception:
        return None
    for i in range(count):
        element = locator.nth(i)
        try:
            label = (element.inner_text(timeout=800) or "").strip().lower()
        except Exception:
            label = ""
        if any(word in label for word in _DANGEROUS_CLICK_WORDS):
            continue
        try:
            element.scroll_into_view_if_needed(timeout=2000)
            element.click(timeout=3000)
            return {"clicked": needle, "label": label[:80]}
        except Exception:
            continue
    return None


def click_element_by_id(page, resource_id: str) -> dict[str, Any] | None:
    result = _click_matching(page, resource_id)
    if not result:
        return None
    return {"clicked_id": resource_id, "label": result.get("label", "")}


def click_element_by_text(page, text: str) -> dict[str, Any] | None:
    result = _click_matching(page, text)
    if not result:
        return None
    return {"clicked_text": text, "label": result.get("label", "")}


# Clickable candidates for brute-force discovery. Deliberately broad and
# app-agnostic: a "post card" is frequently a plain <div onClick=...> with no
# href/button/role at all (React synthetic handler), distinguishable only by a
# card-ish class or a cursor-pointer style. So match the card/list containers
# themselves, not just links inside them, plus real links/buttons/tabs. Every
# candidate is still verified by clicking and observing the result, so false
# positives here just cost an extra probe, not a wrong answer.
_BRUTE_CLICK_SELECTOR = (
    "a[href], article, [class*='card'], [class*='post'], [class*='item'], "
    "[class*='cursor-pointer'], [role='button'], [role='tab'], [role='link'], "
    "button, [class*='tab']"
)


def _brute_force_click_discovery(
    context, page_url: str, case: EvidenceCase, max_tries: int = 15
) -> dict[str, Any] | None:
    """Last-resort click discovery for content behind an element that is
    neither the finding's resource id nor the payload text — e.g. a "프로필
    관리 / manage profile" tab, or a feed post card whose id isn't exposed in
    any attribute. Enumerate the page's clickable elements (list-item links,
    tabs, buttons) and try them one by one on a *fresh* page each time, then
    check whether the click made the target API fire or the payload appear.

    A fresh page per attempt avoids stale-locator / dirty-state problems: a
    click mutates or navigates the DOM, so re-locating "the next candidate"
    on the same page is unreliable; re-loading and indexing by position is
    stable. It costs one navigation per try, hence the ``max_tries`` cap."""
    needles = _content_needles(case)

    # Count candidates once on a throwaway page so we know how many indices
    # to iterate — the elements themselves are re-located per attempt.
    probe = context.new_page()
    total = 0
    try:
        probe.goto(page_url, wait_until="domcontentloaded", timeout=15_000)
        probe.wait_for_timeout(800)
        total = probe.locator(_BRUTE_CLICK_SELECTOR).count()
    except Exception:
        total = 0
    finally:
        probe.close()
    _log(f"brute-force: {total} clickable element(s) on {page_url} (trying up to {max_tries})")
    if not total:
        return None

    # A click that fires the exact target API but whose payload we can't see
    # on the page (e.g. the profile-manage tab, whose field is empty until the
    # payload is present; or a listing before drilling into a post). Held as a
    # fallback: a visible payload (content_match) always wins, but if nothing
    # surfaces one, this at least lands on the right screen instead of root.
    best_exact_hit: dict[str, Any] | None = None

    for i in range(min(total, max_tries)):
        page = context.new_page()
        observed: list[dict[str, str]] = []
        page.on("request", lambda req: observed.append({"method": req.method, "url": req.url}))
        try:
            page.goto(page_url, wait_until="domcontentloaded", timeout=15_000)
            page.wait_for_timeout(700)
            element = page.locator(_BRUTE_CLICK_SELECTOR).nth(i)
            try:
                label = (element.inner_text(timeout=500) or "").strip()
            except Exception:
                label = ""
            if any(word in label.lower() for word in _DANGEROUS_CLICK_WORDS):
                continue
            element.scroll_into_view_if_needed(timeout=1_500)
            element.click(timeout=2_500)
            page.wait_for_timeout(1_200)
            content_match = _page_contains_text(page, needles)
            exact_req = next((r for r in observed if _request_matches_target_exact(case, r["url"])), None)
            shape_req = next((r for r in observed if _request_matches_target(case, r["url"])), None)
            _log(
                f"brute-force try #{i} label={label[:30]!r} -> url={page.url} "
                f"content_match={bool(content_match)} exact_req={bool(exact_req)} "
                f"shape_req={bool(shape_req)}"
            )
            # Accept in priority order:
            #   1. the payload is actually visible on the resulting page,
            #   2. the click fired the *exact* target URL (same dynamic id) —
            #      this is the specific post/record the payload lives in,
            #   3. only when there's no payload text to confirm against (CSRF,
            #      no recoverable payload) fall back to a same-shape match.
            # Never stop on a same-shape-only match while a payload exists:
            # that's how brute-force used to settle on the wrong feed post
            # (any post calls *a* /posts/{id}/comments) instead of clicking
            # through to the one that actually holds the injected content.
            if content_match:
                return {
                    "url": page.url,
                    "route": page_url,
                    "matched_request": {"method": "PAGE_CONTENT", "url": page.url},
                    "content_match": content_match,
                    "click_text": label[:80],
                }
            # With payload text to verify (content_needles), an exact API call
            # alone is NOT enough: a list endpoint (/api/v1/posts) fires from
            # the feed listing, but the payload lives in a single post's detail
            # body — stopping on the list call would capture the list, not the
            # post. Require the payload to be visible; keep clicking otherwise.
            # Only trust a request match when there's no payload to confirm
            # against (CSRF, no recoverable payload).
            if exact_req is not None:
                if not needles:
                    return {
                        "url": page.url,
                        "route": page_url,
                        "matched_request": exact_req,
                        "click_text": label[:80],
                    }
                # Payload not visible here, but this click hit the exact target
                # API — remember it and keep looking for a visible payload.
                if best_exact_hit is None:
                    best_exact_hit = {
                        "url": page.url,
                        "route": page_url,
                        "matched_request": exact_req,
                        "click_text": label[:80],
                    }
            if not needles and shape_req is not None:
                return {
                    "url": page.url,
                    "route": page_url,
                    "matched_request": shape_req,
                    "click_text": label[:80],
                }
        except Exception:
            pass
        finally:
            page.close()
    return best_exact_hit


def _target_path_id(case: EvidenceCase) -> str | None:
    """The concrete resource id sitting in the target URL path, e.g.
    /api/v1/posts/2/comments -> '2'. That's the parent record (post 2) whose
    detail page must be opened to reach the nested content (its comments)."""
    segs = _segments(_canonical_api_path(_path_of(case.exchange.url)))
    ids = [s for s in segs if s.isdigit()]
    return ids[-1] if ids else None


def _parent_collection_path(case: EvidenceCase) -> str | None:
    """The collection endpoint the target id belongs to: strip the trailing
    /{id}/<sub...> so /api/v1/posts/2/comments -> /api/v1/posts. That list
    response names each record's own text, letting us find which card to click."""
    segs = _segments(_canonical_api_path(_path_of(case.exchange.url)))
    for i in range(len(segs) - 1, -1, -1):
        if segs[i].isdigit():
            return ("/" + "/".join(segs[:i])) if i else None
    return None


def _iter_record_dicts(body: Any):
    """Yield record dicts from a list response of any common envelope shape,
    including *nested* ones (a bare list, {data:[...]}, or a paginated
    {data:{content:[...]}} / {result:{items:[...]}}). App-agnostic: only
    conventional wrapper keys are unwrapped, no record field name assumed."""
    for _ in range(4):  # bounded unwrap for nested envelopes
        if isinstance(body, list):
            break
        if not isinstance(body, dict):
            return
        nxt = None
        for key in ("data", "content", "items", "results", "list", "posts", "rows"):
            val = body.get(key)
            if isinstance(val, (list, dict)):
                nxt = val
                break
        if nxt is None:
            body = [body]
            break
        body = nxt
    if isinstance(body, list):
        for item in body:
            if isinstance(item, dict):
                yield item


def _record_matches_id(rec: dict, target_id: str) -> bool:
    """True if the record's id-ish field equals target_id — the REST
    convention that a primary key lives in a key named ``id`` or ``*Id``
    (a generic naming pattern, not any one app's schema), matched by value."""
    for key, val in rec.items():
        kl = str(key).lower()
        if (kl == "id" or kl.endswith("id")) and str(val) == str(target_id):
            return True
    return False


def _list_text_needles(api_bodies: list[tuple[str, Any]], case: EvidenceCase) -> list[str]:
    """Bridge a nested-resource target to the card that opens it: from the
    parent collection's captured response, find the record whose id matches the
    target's path id, and return its distinctive visible text (title/body/
    author). That text lets ``_click_matching`` reach the right card by
    ``get_by_text`` — the id itself is usually absent from the DOM for
    onClick-navigated SPAs, which is why clicking by id alone fails."""
    target_id = _target_path_id(case)
    parent = _parent_collection_path(case)
    if not target_id or not parent:
        return []
    parent = parent.rstrip("/")
    needles: list[str] = []
    for url, body in api_bodies:
        if _canonical_api_path(_path_of(url)).rstrip("/") != parent:
            continue
        for rec in _iter_record_dicts(body):
            if not _record_matches_id(rec, target_id):
                continue
            for val in rec.values():
                if isinstance(val, str):
                    text = val.strip()
                    # Skip empty/huge, injected payloads and any HTML — those
                    # don't render as clean, matchable visible text.
                    if 4 <= len(text) <= 120 and "ARGUS_" not in text and "<" not in text:
                        needles.append(text)
    # De-dup, longest (most distinctive) first, capped.
    return list(dict.fromkeys(sorted(needles, key=len, reverse=True)))[:3]


def _discover_via_click(context, page_url: str, case: EvidenceCase, resource_ids: list[str]) -> dict[str, Any] | None:
    """Second-pass discovery for content that only appears after navigating
    into a specific list item (e.g. a post's comments) — page-load-only
    request watching can't see this because nothing fires until the click.
    Tries clicking on the URL's resource id first, then on the payload/its
    ARGUS marker, and finally falls back to brute-force clicking every
    plausible element on the page (for targets whose click handle is neither
    an id nor the payload text — a "manage profile" tab, an un-id'd card)."""
    page = context.new_page()
    observed: list[dict[str, str]] = []
    api_bodies: list[tuple[str, Any]] = []

    def on_request(req) -> None:
        observed.append({"method": req.method, "url": req.url})

    def on_response(resp) -> None:
        # Capture parent-list JSON so a nested-resource target can be reached by
        # the record's visible text (see _list_text_needles). Best-effort only.
        try:
            if "/api/" not in resp.url:
                return
            if "json" not in str(resp.headers.get("content-type", "")).lower():
                return
            api_bodies.append((resp.url, resp.json()))
        except Exception:
            pass

    page.on("request", on_request)
    page.on("response", on_response)
    try:
        page.goto(page_url, wait_until="domcontentloaded", timeout=15_000)
        page.wait_for_timeout(1_000)
        # Try, in order: the URL resource id, then the parent record's own text
        # (bridges an un-id'd feed card to the post the payload lives in), then
        # the payload/marker text.
        candidates = (
            [("id", rid) for rid in resource_ids]
            + [("text", needle) for needle in _list_text_needles(api_bodies, case)]
            + [("text", needle) for needle in _content_needles(case)]
        )
        for kind, needle in candidates:
            observed.clear()
            clicked = _click_matching(page, needle)
            if not clicked:
                continue
            page.wait_for_timeout(1_200)
            click_field = {"click_id": needle} if kind == "id" else {"click_text": needle}
            content_match = _page_contains_text(page, _content_needles(case))
            if content_match:
                return {
                    "url": page_url,
                    "route": page_url,
                    "matched_request": {"method": "PAGE_CONTENT", "url": page_url},
                    "content_match": content_match,
                    **click_field,
                }
            for request in observed:
                if _request_matches_target(case, request["url"]):
                    return {
                        "url": page_url,
                        "route": page_url,
                        "matched_request": request,
                        **click_field,
                    }
    except Exception:
        pass
    finally:
        page.remove_listener("request", on_request)
        page.remove_listener("response", on_response)
        page.close()

    # Nothing matched a specific id/text handle — sweep the page's clickable
    # elements and see which click surfaces the target.
    return _brute_force_click_discovery(context, page_url, case)


def _route_priority(case: EvidenceCase, route: str) -> int:
    """Rough heuristic for which undiscovered link to try next: prefer ones
    whose own path segments overlap with the target API's segments (e.g. a
    ``/seller`` link is a good bet for an ``/api/v1/seller/...`` finding).
    ``/`` always wins outright — it's the one entry point guaranteed to be a
    real page (everything else guessed from the API path may 404), and it's
    the only page button-based nav discovery can reliably run against."""
    if route == "/":
        return 1_000_000
    target_parts = set(_segments(_path_of(case.exchange.url)))
    return len(target_parts & set(_segments(route)))


def discover_site_url(context, case: EvidenceCase) -> dict[str, Any]:
    """Find the frontend page tied to the finding's API the way the 1-2
    module does: walk a list of candidate frontend routes and pick the first
    one whose own network traffic hits the finding's *exact* API path (or, for
    Stored XSS, renders the payload). No scoring — a page either calls the
    target endpoint or it doesn't.

    Root ("/") is checked LAST. The homepage frequently calls the same list
    endpoint from a widget (e.g. a "recent posts" strip hitting
    ``/api/v1/posts``), so if it were checked first it would shadow the
    dedicated page (``/feed``) that actually renders the exploited item. It's
    still visited up front, but only to harvest nav links/buttons; its own
    match is deferred until nothing more specific hits."""
    base = frontend_base_url()
    base_netloc = urlsplit(base).netloc
    content_needles = _content_needles(case)
    errors: list[str] = []
    visited_paths: set[str] = set()
    nav_routes: list[str] = []
    # Routes whose page calls a *parent* of the target API path — the
    # listing/summary screen you click through to reach the target content
    # (e.g. /feed calls /api/v1/posts, so it's where you click a post to
    # reach /api/v1/posts/{id}/comments; /mypage calls /api/v1/members/me,
    # where a "manage profile" tab loads /api/v1/members/me/profile). These
    # are the right places to start click-through, in visit order.
    parent_routes: list[str] = []
    # Sibling-scope matches, keyed by API path -> routes that called it. A
    # header widget calling /members/me/mileage on *every* page would flag
    # every page as "related" to a /members/me/profile finding, which is
    # useless — so scope matches are held here and only promoted to
    # parent_routes if they're page-specific (called on a single route),
    # dropping the ones that turn out to be page-independent boilerplate.
    scope_match_routes: dict[str, set[str]] = {}
    # Every real content page we actually rendered (route, request count).
    # When no parent page is found, these are the fallback click-through
    # targets — the content that a finding needs may sit behind a click on a
    # page that never calls the parent API on load (e.g. /mypage only calls
    # /members/me/profile after its "manage profile" tab is clicked), so the
    # page has to be swept even though nothing flagged it during the crawl.
    content_routes: list[tuple[str, int]] = []

    # Candidate routes, same sources as before (root handled explicitly, so
    # it's excluded here): guesses derived from the target API path, ARGUS's
    # own inventory (api-tree.json frontend rows), and the team's per-target
    # examples/*url-list*.txt onboarding file.
    frontier: list[str] = []

    def _add(route: str) -> None:
        # Skip HTTP-status error routes (/401../503) — every app has them and
        # none is ever the page tied to a finding, so they only waste crawl
        # budget that a real page (e.g. /mypage) needs.
        if route and route != "/" and route not in frontier and not _ERROR_PAGE_RE.match(route):
            frontier.append(route)

    for candidate in _derive_candidate_routes(case):
        _add(candidate)
    api_tree_routes = _frontend_routes_from_api_tree(base)
    for candidate in api_tree_routes:
        _add(candidate)
    examples_routes = _frontend_routes_from_examples()
    for candidate in examples_routes:
        _add(candidate)

    _log(
        f"target={case.exchange.method} {_path_of(case.exchange.url)} "
        f"vuln_type={case.vuln_type} base={base} seed_frontier=['/', *{frontier}] "
        f"(api_tree contributed {len(api_tree_routes)}, examples contributed {len(examples_routes)})"
    )

    wait_ms = 600
    try:
        wait_ms = int(os.getenv("ARGUS_SCREENSHOT_ROUTE_WAIT_MS", str(wait_ms)))
    except ValueError:
        pass
    max_pages = 20
    try:
        max_pages = int(os.getenv("ARGUS_SCREENSHOT_CRAWL_MAX_PAGES", str(max_pages)))
    except ValueError:
        pass

    visited = 0

    def probe(route: str) -> dict[str, Any] | None:
        """Visit one route. Return a match dict if this page calls the target
        API or renders the payload, else None. Harvest same-origin links (and,
        on root, nav-button routes) into ``frontier`` as a side effect."""
        nonlocal visited, nav_routes
        if route in visited_paths:
            return None
        visited_paths.add(route)
        visited += 1
        url = urljoin(f"{base}/", route.lstrip("/"))
        page = context.new_page()
        hit: dict[str, Any] | None = None
        seen_requests = 0

        def on_request(req) -> None:
            nonlocal hit, seen_requests
            if seen_requests >= 80:
                return
            request_url = str(req.url or "")
            if _path_of(request_url).lower().endswith(_STATIC_SUFFIXES):
                return
            seen_requests += 1
            if hit is None and _request_matches_target(case, request_url):
                hit = {
                    "url": url,
                    "route": route,
                    "matched_request": {"method": req.method, "url": request_url},
                }
            elif _request_is_ancestor_of_target(case, request_url):
                # A true ancestor path (e.g. /posts for a /posts/{id}/comments
                # finding) — trusted directly as a click-through start even if
                # several pages call it, since it's the genuine parent resource.
                if route not in parent_routes:
                    parent_routes.append(route)
            elif _request_shares_resource_scope(case, request_url):
                # A sibling under the same resource scope (e.g.
                # /members/me/reservations for a /members/me/profile finding).
                # Held for boilerplate filtering — only page-specific ones are
                # promoted to parents later.
                api_path = _canonical_api_path(_path_of(request_url))
                scope_match_routes.setdefault(api_path, set()).add(route)

        page.on("request", on_request)
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=15_000)
            page.wait_for_timeout(max(250, wait_ms))
            content_match = _page_contains_text(page, content_needles) if content_needles else None
            if content_match:
                # Exploited content is directly visible here — the strongest
                # possible signal, overrides a mere request match.
                hit = {
                    "url": url,
                    "route": route,
                    "matched_request": {"method": "PAGE_CONTENT", "url": url},
                    "content_match": content_match,
                }
            new_links = [
                link for link in _extract_internal_links(page, base_netloc)
                if link != "/" and link not in visited_paths and link not in frontier
            ]
            frontier.extend(new_links)
            button_links: list[str] = []
            if route == "/":
                # The main nav is often button onClick + client-side routing
                # rather than real <a href> links, so <a> extraction alone
                # finds nothing to crawl — click the nav buttons to harvest
                # their destinations. Only meaningful on root.
                button_links = [
                    link for link in _discover_button_routes(page, base_netloc, url)
                    if link != "/" and link not in visited_paths and link not in frontier
                ]
                frontier.extend(button_links)
                nav_routes = list(button_links)
            # A route that redirects to an error screen (/404, /403, ...) is
            # not a real page — an ONDE SPA renders its error component but
            # keeps calling nothing useful. Drop it from every candidate list
            # so it can't crowd out a real page (e.g. /mypage) in click-through.
            landed_error = bool(_ERROR_PAGE_RE.match(urlsplit(page.url).path or "/"))
            if landed_error:
                if route in parent_routes:
                    parent_routes.remove(route)
                for routes in scope_match_routes.values():
                    routes.discard(route)
            elif seen_requests >= 3 and not _ERROR_PAGE_RE.match(route):
                content_routes.append((route, seen_requests))
            _log(
                f"visit #{visited} route={route!r} match={'YES' if hit else 'no'}"
                f"{' (content)' if hit and hit.get('content_match') else ''}"
                f"{' (->error)' if landed_error else ''} "
                f"new_links={new_links} button_links={button_links} requests_seen={seen_requests}"
            )
        except Exception as exc:
            errors.append(f"{route}: {exc}")
            _log(f"visit #{visited} route={route!r} -> ERROR: {exc}")
        finally:
            page.remove_listener("request", on_request)
            page.close()
        return hit

    def _finalize(match: dict[str, Any]) -> dict[str, Any]:
        _log(f"FINAL: url={match.get('url')} route={match.get('route')} pages_visited={visited}")
        match.update(
            {
                "source": "crawl",
                "fallback": False,
                "frontend_base_url": base,
                "pages_visited": visited,
            }
        )
        return match

    # When there's payload text to verify (Stored XSS), a page whose network
    # merely *calls* the target API isn't good enough on its own — the payload
    # can live one click deeper (a feed post's full body, only shown in its
    # detail view). Such request-only matches are held here and only used as a
    # fallback if the click-through phase can't surface the payload; a match
    # where the payload is actually visible (content_match) wins immediately.
    def _is_confirmed(match: dict[str, Any] | None) -> bool:
        return bool(match) and (bool(match.get("content_match")) or not content_needles)

    deferred_request_hit: dict[str, Any] | None = None

    # Phase 1 — visit root first, but ONLY to harvest nav routes. Its own
    # match is remembered and deferred so a more specific page can win.
    root_hit = probe("/")

    # Phase 2 — specific routes, most path-segment-overlap first.
    while frontier and visited < max_pages:
        frontier.sort(key=lambda candidate: _route_priority(case, candidate), reverse=True)
        route = frontier.pop(0)
        match = probe(route)
        if _is_confirmed(match):
            return _finalize(match)
        if match and deferred_request_hit is None:
            deferred_request_hit = match

    # Phase 3 — root's own match, if confirmed.
    if _is_confirmed(root_hit):
        return _finalize(root_hit)
    if root_hit and deferred_request_hit is None:
        deferred_request_hit = root_hit

    # Phase 4 — content that only loads after clicking into a specific list
    # item (a post's comments, a detail view, ...). Nothing fires on page
    # load, so the crawl above can't see it. Click into the finding's own
    # resource id (from the URL or recovered from the evidence record), then
    # the payload text, across the real nav destinations (a listing page like
    # /feed renders the clickable per-item cards; root often doesn't).
    resource_ids = [seg for seg in _segments(_path_of(case.exchange.url)) if _DYNAMIC_SEGMENT_RE.match(seg)]
    for rid in _resource_ids_from_evidence(case):
        if rid not in resource_ids:
            resource_ids.append(rid)
    # Promote page-specific sibling-scope matches to parent routes, dropping
    # the page-independent boilerplate ones (an API path called on 2+ routes
    # is a shared header/widget call, not evidence that any one page is the
    # relevant screen).
    for api_path, routes in scope_match_routes.items():
        if len(routes) >= 2:
            continue
        for route in routes:
            if route not in parent_routes:
                parent_routes.append(route)

    if resource_ids or content_needles:
        # Ordered click-through targets:
        #   1. pages calling the target's parent API (the true listing/summary
        #      screen) — the most likely place,
        #   2. then every other real content page, richest first (most network
        #      activity ~ most rendered content, e.g. /mypage), since the
        #      handle can be behind a click on a page that never flagged
        #      itself during the crawl,
        #   3. then root as a last resort.
        ordered_routes: list[str] = list(parent_routes)
        for route, _seen in sorted(content_routes, key=lambda rs: rs[1], reverse=True):
            if route not in ordered_routes:
                ordered_routes.append(route)
        for route in nav_routes:
            if route not in ordered_routes:
                ordered_routes.append(route)

        click_candidates: list[str] = []
        for route in ordered_routes:
            candidate_url = urljoin(f"{base}/", route.lstrip("/"))
            if candidate_url not in click_candidates:
                click_candidates.append(candidate_url)
        root_url = f"{base}/"
        if root_url not in click_candidates:
            click_candidates.append(root_url)

        _log(f"click-through candidates (parent_routes={parent_routes}): {click_candidates[:6]}")
        for click_base_url in click_candidates[:6]:
            _log(f"click-through from {click_base_url} for ids={resource_ids}")
            deep = _discover_via_click(context, click_base_url, case, resource_ids)
            if deep:
                _log(f"click-through succeeded: {deep}")
                return _finalize(deep)
        _log("click-through found nothing on any candidate page")

    # Phase 5 — click-through couldn't surface the payload. Fall back to the
    # best page that at least *calls* the target API (e.g. /feed for a posts
    # finding) — better than root, even if the payload isn't scrolled into
    # view — before giving up entirely.
    if deferred_request_hit:
        _log(f"using deferred request-match page: {deferred_request_hit.get('url')}")
        return _finalize(deferred_request_hit)

    _log(f"FINAL: no match at all, falling back to root. pages_visited={visited} errors={errors[-3:]}")
    return {
        "url": f"{base}/",
        "route": "/",
        "source": "frontend_root_fallback",
        "fallback": True,
        "frontend_base_url": base,
        "pages_visited": visited,
        "errors": errors[-5:],
    }
