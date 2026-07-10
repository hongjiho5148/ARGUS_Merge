"""httpx probes for guideline 1-5 (redirect, CORS, crossdomain)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx

from diagnosis.result import DiagnosisFinding


def _request(
    client: httpx.Client,
    job: dict[str, Any],
    *,
    timeout: float,
) -> tuple[int | None, dict[str, str], str | None]:
    method = str(job.get("method") or "GET").upper()
    url = str(job["url"])
    headers = dict(job.get("headers") or {})
    body = job.get("body") or ""
    try:
        resp = client.request(
            method,
            url,
            headers=headers,
            content=body if body else None,
            timeout=timeout,
            follow_redirects=False,
        )
        return resp.status_code, dict(resp.headers), None
    except httpx.HTTPError as exc:
        return None, {}, str(exc)[:200]


def _location(headers: dict[str, str]) -> str | None:
    for key, val in headers.items():
        if key.lower() == "location":
            return val
    return None


def run_redirect_jobs(
    jobs: list[dict[str, Any]],
    *,
    sink_base: str,
    is_open_redirect_fn: Any,
    timeout: float = 8.0,
    on_progress: Callable[..., None] | None = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    findings: list[DiagnosisFinding] = []
    stats: dict[str, Any] = {
        "redirect_jobs": len(jobs),
        "probed": 0,
        "errors": 0,
        "open_redirects": 0,
        "phase_a": 0,
        "phase_b": 0,
    }
    seen: set[str] = set()

    with httpx.Client() as client:
        for job in jobs:
            stats["probed"] += 1
            phase = job.get("phase") or "?"
            if on_progress:
                on_progress(
                    endpoints_done=stats["probed"],
                    endpoints_total=len(jobs),
                    endpoint_id=str(job.get("test_url") or "")[:80],
                )
            if phase == "A":
                stats["phase_a"] += 1
            elif phase == "B":
                stats["phase_b"] += 1

            base_status, base_headers, base_err = _request(
                client,
                {
                    "method": job["method"],
                    "url": job["baseline_url"],
                    "headers": job.get("headers"),
                    "body": job.get("baseline_body", job.get("body")),
                },
                timeout=timeout,
            )
            test_status, test_headers, test_err = _request(
                client,
                {"method": job["method"], "url": job["test_url"], "headers": job.get("headers"), "body": job.get("body")},
                timeout=timeout,
            )
            if base_err and test_err:
                stats["errors"] += 1
                continue

            baseline_loc = _location(base_headers)
            test_loc = _location(test_headers)
            if not is_open_redirect_fn(
                test_status,
                test_loc,
                sink_base=sink_base,
                baseline_location=baseline_loc,
            ):
                continue

            dedupe = f"{job.get('test_url')}|{job.get('param_name')}|{test_loc}"
            if dedupe in seen:
                continue
            seen.add(dedupe)
            stats["open_redirects"] += 1

            phase_label = "param fuzz" if phase == "A" else "path sweep"
            findings.append(
                DiagnosisFinding(
                    severity="high",
                    message=(
                        f"Open redirect ({phase_label}): {job.get('param_name')} → "
                        f"Location {test_loc}"
                    ),
                    evidence={
                        "rule_id": "1-5-open-redirect",
                        "trigger": f"open_redirect_phase_{phase.lower()}",
                        "engine": "httpx",
                        "phase": phase,
                        "endpoint_id": job.get("endpoint_id"),
                        "base_url": job.get("base_url"),
                        "path": job.get("path"),
                        "param_name": job.get("param_name"),
                        "param_in": job.get("param_in"),
                        "baseline_url": job.get("baseline_url"),
                        "test_url": job.get("test_url"),
                        "baseline_status": base_status,
                        "test_status": test_status,
                        "baseline_location": baseline_loc,
                        "location": test_loc,
                        "sink_token": job.get("sink_token"),
                        "related_sections": ["1-5"],
                    },
                )
            )

    return findings, stats


def run_cors_probes(
    targets: list[dict[str, str]],
    *,
    probe_origin: str,
    analyze_cors_fn: Any,
    timeout: float = 8.0,
    on_progress: Callable[..., None] | None = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    findings: list[DiagnosisFinding] = []
    stats: dict[str, Any] = {"cors_targets": len(targets), "probed": 0, "issues": 0}

    headers = {
        "Origin": probe_origin,
        "Access-Control-Request-Method": "GET",
        "User-Agent": "ARGUS-1-5/1.0",
    }

    with httpx.Client() as client:
        for target in targets:
            url = target["probe_url"]
            stats["probed"] += 1
            if on_progress:
                on_progress(
                    endpoints_done=stats["probed"],
                    endpoints_total=len(targets),
                    endpoint_id=url[:80],
                )
            try:
                resp = client.get(url, headers=headers, timeout=timeout, follow_redirects=True)
            except httpx.HTTPError:
                continue
            for issue in analyze_cors_fn(dict(resp.headers), probe_origin=probe_origin):
                stats["issues"] += 1
                findings.append(
                    DiagnosisFinding(
                        severity=str(issue.get("severity") or "medium"),
                        message=f"CORS misconfiguration ({issue.get('reason')}): {url}",
                        evidence={
                            "rule_id": "1-5-cors-misconfig",
                            "trigger": str(issue.get("reason")),
                            "engine": "httpx",
                            "url": url,
                            "base_url": target.get("base_url"),
                            "probe_origin": probe_origin,
                            "http_status": resp.status_code,
                            **issue,
                            "related_sections": ["1-5", "7-4"],
                        },
                    )
                )
    return findings, stats


def run_crossdomain_probes(
    targets: list[dict[str, str]],
    *,
    analyze_crossdomain_fn: Any,
    timeout: float = 8.0,
    on_progress: Callable[..., None] | None = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    findings: list[DiagnosisFinding] = []
    stats: dict[str, Any] = {"crossdomain_targets": len(targets), "probed": 0, "issues": 0}

    with httpx.Client() as client:
        for target in targets:
            url = target["probe_url"]
            stats["probed"] += 1
            if on_progress:
                on_progress(
                    endpoints_done=stats["probed"],
                    endpoints_total=len(targets),
                    endpoint_id=url[:80],
                )
            try:
                resp = client.get(
                    url,
                    timeout=timeout,
                    follow_redirects=True,
                    headers={"User-Agent": "ARGUS-1-5/1.0", "Accept": "application/xml,text/xml,*/*"},
                )
            except httpx.HTTPError:
                continue
            if resp.status_code >= 400:
                continue
            body = resp.text or ""
            if "cross-domain-policy" not in body.lower() and "<allow-access-from" not in body.lower():
                continue
            for issue in analyze_crossdomain_fn(body):
                stats["issues"] += 1
                findings.append(
                    DiagnosisFinding(
                        severity=str(issue.get("severity") or "info"),
                        message=f"Permissive crossdomain.xml ({issue.get('domain')}): {url}",
                        evidence={
                            "rule_id": "1-5-crossdomain-permissive",
                            "trigger": str(issue.get("reason")),
                            "engine": "httpx",
                            "url": url,
                            "base_url": target.get("base_url"),
                            "http_status": resp.status_code,
                            **issue,
                            "related_sections": ["1-5"],
                        },
                    )
                )
    return findings, stats
