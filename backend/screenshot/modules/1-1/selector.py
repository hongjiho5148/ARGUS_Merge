"""Select and deduplicate capturable 1-1 findings.

Scope: only ``Stored XSS`` and ``CSRF`` are handled today. Other vuln_types
produced by the 1-1 scanner (Reflected XSS, Persistent XSS, Cross-Role
Stored XSS, CORS Origin Reflection, DOM XSS Suspect) are intentionally
skipped — extending coverage only requires adding the type name to
``_SUPPORTED_VULN_TYPES`` plus a matching branch in ``renderer.py``/
``engine.py``.
"""

from __future__ import annotations

import re
from hashlib import sha256
from typing import Any
from urllib.parse import urlsplit

_SUPPORTED_VULN_TYPES = ("Stored XSS", "CSRF")


def finding_evidence(finding: dict[str, Any]) -> dict[str, Any]:
    return dict(finding.get("evidence") or {})


def _dedupe_key(finding: dict[str, Any]) -> tuple[str, str, str, str]:
    """(vuln_type, url, param, account_role) — kept per-role on purpose.
    The same endpoint+parameter tripped by different roles is a *different*
    capture, because the evidence page it renders is role-specific: a
    "my-profile" stored XSS shows on each user's own page, so USER's payload
    lives on jiho's profile and SUPER_ADMIN's on admin's — collapsing them
    would drop every role but one (and often keep the admin, whose profile
    UI can't even be shown)."""
    evidence = finding_evidence(finding)
    return (
        str(evidence.get("vuln_type") or "").strip(),
        str(evidence.get("url") or "").rstrip("/") or "/",
        str(evidence.get("param") or "").lower(),
        str(evidence.get("account_role") or "").strip().upper(),
    )


def is_capturable(finding: dict[str, Any]) -> bool:
    evidence = finding_evidence(finding)
    if str(evidence.get("vuln_type") or "").strip() not in _SUPPORTED_VULN_TYPES:
        return False
    status = str(evidence.get("validation_status") or "").strip()
    if status == "True Positive":
        return True
    # A Stored XSS candidate is only API-level evidence; the browser capture is
    # what decides whether it is promoted or stays a candidate.
    return status == "Potential" and str(evidence.get("vuln_type") or "").strip() == "Stored XSS"


def _rank(finding: dict[str, Any]) -> tuple[int, int, int, int, int]:
    evidence = finding_evidence(finding)
    url = str(evidence.get("url") or "").lower()
    return (
        # Prefer findings tied to an authenticated role and a real
        # state-changing endpoint over edge cases like the login endpoint
        # itself, which has no meaningful "victim session" to demonstrate.
        1 if evidence.get("account_role") else 0,
        0 if "/auth/login" in url or "/auth/admin/login" in url else 1,
        1 if str(evidence.get("confidence") or "").upper() == "HIGH" else 0,
        1 if str(evidence.get("risk") or "").upper() == "HIGH" else 0,
        int(evidence.get("occurrence_count") or 0),
    )


def _slug(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9]+", "-", str(value or "").strip())
    return text.strip("-") or "x"


def stable_finding_id(finding: dict[str, Any]) -> str:
    """Human-readable, stable evidence-folder name built from the same
    (vuln_type, method, url path, param) that groups findings, e.g.
    ``1-1_Stored-XSS_GET_api-v1-posts_title``. A short hash suffix guards
    against two different values slugifying to the same text."""
    vuln_type, url, param, role = _dedupe_key(finding)
    method = str(finding_evidence(finding).get("method") or "GET").upper()
    path = urlsplit(url).path.strip("/") or "root"
    # Role goes in the folder name so each account's capture is distinct on
    # disk (e.g. ..._name_USER vs ..._name_SUPER-ADMIN); omitted when blank
    # (anonymous CSRF) to keep those names unchanged.
    slug_parts = [vuln_type, method, path, param] + ([role] if role else [])
    slug = "_".join(_slug(part) for part in slug_parts)
    digest = sha256("|".join((vuln_type, url, param, role)).encode("utf-8")).hexdigest()[:6]
    return f"1-1_{slug}_{digest}"[:150]


def select_representatives(
    findings: list[dict[str, Any]],
    *,
    per_type_limit: int | None = None,
) -> list[dict[str, Any]]:
    """Pick one representative per deduplicated (vuln_type, url, param)
    group. By default every distinct vulnerability gets captured; pass
    ``per_type_limit`` to cap how many are taken per vuln_type instead."""
    grouped: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    for finding in findings:
        if is_capturable(finding):
            grouped.setdefault(_dedupe_key(finding), []).append(finding)

    by_type: dict[str, list[dict[str, Any]]] = {vuln_type: [] for vuln_type in _SUPPORTED_VULN_TYPES}
    for key, rows in grouped.items():
        representative = max(rows, key=_rank)
        by_type.setdefault(key[0], []).append(representative)

    selected: list[dict[str, Any]] = []
    for vuln_type in _SUPPORTED_VULN_TYPES:
        ranked = sorted(by_type.get(vuln_type, []), key=_rank, reverse=True)
        if per_type_limit is not None:
            ranked = ranked[:per_type_limit]
        selected.extend(ranked)
    return selected
