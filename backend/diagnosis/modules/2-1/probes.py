"""Run malicious/edge-case multipart upload probes for 2-1.

Transport-agnostic: works identically over ``HttpxTransport`` (direct) or
``ZapTransport`` (every request goes through ``zap.core.sendRequest``, so it
lands in ZAP's Sites/History and gets passively scanned like normal proxied
traffic — see ``zap_scan.py`` for the supplemental ZAP-native findings this
enables).
"""

from __future__ import annotations

from typing import Any, Callable

from diagnosis.result import DiagnosisFinding

_MAX_BODY_CAPTURE = 4000


def _decode(body: bytes) -> str:
    return body.decode("utf-8", errors="replace")[:_MAX_BODY_CAPTURE]


def _post_upload(
    transport: Any,
    target: Any,
    payload: Any,
    multipart_mod: Any,
    *,
    timeout: float,
    extra_headers: dict[str, str] | None,
) -> tuple[int | None, str, str, dict[str, str], str | None]:
    body, content_type = multipart_mod.encode_multipart(
        file_field=target.file_field,
        filename=payload.filename,
        file_content=payload.content,
        file_content_type=payload.content_type,
        fields=target.extra_fields,
    )
    headers = {"User-Agent": "ARGUS-2-1/1.0", "Accept": "*/*", "Content-Type": content_type}
    if extra_headers:
        headers.update(extra_headers)

    resp = transport.request(target.method, target.url, headers, body, timeout=timeout)
    if resp.error:
        return None, "", "", {}, resp.error
    return resp.status, _decode(resp.body), resp.headers.get("content-type", ""), resp.headers, None


def run_upload_probes(
    targets: list[Any],
    payloads: list[Any],
    *,
    transport: Any,
    engine: str,
    rules_mod: Any,
    multipart_mod: Any,
    timeout: float = 15.0,
    auth_mode: str = "anonymous",
    request_headers: dict[str, str] | None = None,
    account_email: str | None = None,
    login_label: str | None = None,
    on_progress: Callable[..., None] | None = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    findings: list[DiagnosisFinding] = []
    requested_urls: set[str] = set()
    stats: dict[str, Any] = {
        "engine": engine,
        "auth_mode": auth_mode,
        "targets": len(targets),
        "payloads": len(payloads),
        "requests_sent": 0,
        "send_errors": 0,
        "extension_bypass_issues": 0,
        "path_exposure_issues": 0,
        "by_severity": {"high": 0, "medium": 0, "low": 0, "info": 0},
    }

    total = len(targets) * len(payloads)
    done = 0
    prefix = f"[2-1][{engine}][{auth_mode}]"

    for target in targets:
        for payload in payloads:
            done += 1
            stats["requests_sent"] += 1
            if on_progress:
                on_progress(
                    endpoints_done=done,
                    endpoints_total=total,
                    endpoint_id=f"{target.label} · {payload.payload_id}"[:80],
                )

            requested_urls.add(target.url)
            status, body, content_type, resp_headers, err = _post_upload(
                transport, target, payload, multipart_mod, timeout=timeout, extra_headers=request_headers
            )

            base_evidence: dict[str, Any] = {
                "rule_id": "2-1-malicious-upload",
                "engine": engine,
                "auth_mode": auth_mode,
                "account_email": account_email,
                "login_label": login_label,
                "url": target.url,
                "method": target.method,
                "endpoint_id": target.endpoint_id,
                "file_field": target.file_field,
                "source": target.source,
                "payload_id": payload.payload_id,
                "technique": payload.technique,
                "extension": payload.ext,
                "category": payload.category,
                "filename": payload.filename.replace("\x00", "\\x00"),
                "http_status": status,
            }

            if err:
                stats["send_errors"] += 1
                continue

            ext_issue = rules_mod.classify_extension_bypass(
                technique=payload.technique,
                expect_reject=payload.expect_reject,
                http_status=status,
                body=body,
            )
            if ext_issue is not None:
                stats["extension_bypass_issues"] += 1 if ext_issue.accepted else 0
                sev = ext_issue.severity
                stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1
                ev = dict(base_evidence)
                ev["reason"] = ext_issue.reason
                ev["body_preview"] = body[:500].replace("\n", " ").strip()
                if ext_issue.accepted:
                    msg = (
                        f"{prefix} 허용되지 않은 확장자(.{payload.ext}) 업로드가 차단되지 않음 "
                        f"— {payload.technique} · {target.label}"
                    )
                else:
                    msg = (
                        f"{prefix} 정상 이미지 업로드가 거부됨(baseline) — "
                        f"다른 결과 해석 시 참고: {target.label}"
                    )
                findings.append(DiagnosisFinding(severity=sev, message=msg, evidence=ev))

            exposure = rules_mod.detect_path_exposure(body, content_type, resp_headers)
            if exposure is not None:
                stats["path_exposure_issues"] += 1
                stats["by_severity"][exposure.severity] = (
                    stats["by_severity"].get(exposure.severity, 0) + 1
                )
                findings.append(
                    DiagnosisFinding(
                        severity=exposure.severity,
                        message=(
                            f"{prefix} 업로드 응답에 내부 경로/주소 노출 "
                            f"({exposure.kind} · {exposure.location}) — {target.label}"
                        ),
                        evidence={
                            **base_evidence,
                            "reason": f"path_exposure:{exposure.kind}",
                            "exposure_location": exposure.location,
                            "exposed_sample": exposure.sample,
                            "body_preview": body[:500].replace("\n", " ").strip(),
                        },
                    )
                )

    stats["requested_urls"] = sorted(requested_urls)
    return findings, stats
