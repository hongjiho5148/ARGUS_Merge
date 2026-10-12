"""1-1 Stored XSS / CSRF evidence screenshot adapter.

The directory name intentionally remains ``1-1``. Load this module by file
path or execute it directly instead of importing it with dotted Python
syntax (see ``sys.path`` bootstrap below).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

import yaml

_MODULE_DIR = Path(__file__).resolve().parent
if str(_MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(_MODULE_DIR))

from engine import capture_case  # noqa: E402
from models import EvidenceCase, HttpExchange  # noqa: E402
from redaction import redact_text  # noqa: E402
from selector import finding_evidence, select_representatives, stable_finding_id  # noqa: E402


def display_url(url: str) -> str:
    return str(url or "").replace("host.docker.internal", "localhost")


def case_from_finding(finding: dict[str, Any]) -> EvidenceCase:
    evidence = finding_evidence(finding) or dict(finding)
    finding_id = stable_finding_id(finding)
    url = str(evidence.get("url") or "")
    status_code = evidence.get("status_code")

    exchange = HttpExchange(
        method=str(evidence.get("method") or "GET"),
        url=url,
        display_url=display_url(url),
        status_code=int(status_code) if status_code is not None else None,
        request_text=str(evidence.get("evidence_request") or ""),
        response_text=str(evidence.get("evidence_response") or ""),
    )

    return EvidenceCase(
        finding_id=finding_id,
        section_id="1-1",
        vuln_type=str(evidence.get("vuln_type") or ""),
        title=str(evidence.get("alert") or evidence.get("vuln_type") or "XSS/CSRF finding"),
        parameter=str(evidence.get("param") or "-"),
        payload=str(evidence.get("attack") or "-"),
        validation_status=str(evidence.get("validation_status") or ""),
        confidence=str(evidence.get("confidence") or "unknown"),
        account_role=str(evidence.get("account_role") or ""),
        exchange=exchange,
        metadata={
            "vuln_id": evidence.get("vuln_id"),
            "risk": evidence.get("risk"),
            "occurrence_count": evidence.get("occurrence_count"),
            "vuln_description": evidence.get("vuln_description"),
            "validation_reason": evidence.get("validation_reason"),
            "ui_url": evidence.get("ui_url") or evidence.get("page_url"),
            "csrf_defenses": evidence.get("csrf_defenses"),
        },
    )


def _safe_exchange(exchange: HttpExchange) -> dict[str, Any]:
    return {
        "method": exchange.method,
        "url": exchange.display_url or display_url(exchange.url),
        "status_code": exchange.status_code,
        "request_text": redact_text(exchange.request_text),
        "response_text": redact_text(exchange.response_text),
    }


def _safe_submission(case: EvidenceCase) -> dict[str, Any] | None:
    submission = case.attacker_submission
    if submission is None:
        return None
    return {
        "target_url": display_url(submission.target_url),
        "method": submission.method,
        "request_body": redact_text(submission.request_body),
        "status_code": submission.status_code,
        "response_text": redact_text(submission.response_text),
    }


def capture_finding(
    finding: dict[str, Any],
    output_root: Path,
    *,
    perform_replay: bool = True,
    info: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    """``info``, when given, is filled with facts the capture learned about the
    finding (currently the browser verification of a Stored XSS)."""
    case = case_from_finding(finding)
    output_dir = output_root / case.finding_id
    artifacts = capture_case(case, output_dir, perform_replay=perform_replay)
    if info is not None and case.metadata.get("browser_verification"):
        info["browser_verification"] = case.metadata["browser_verification"]

    manifest = {
        "section_id": case.section_id,
        "finding_id": case.finding_id,
        "vuln_type": case.vuln_type,
        "viewport": {"width": 1280, "height": 720},
        "parameter": case.parameter,
        "payload": case.payload,
        "validation_status": case.validation_status,
        "confidence": case.confidence,
        "account_role": case.account_role,
        "exchange": _safe_exchange(case.exchange),
        "attacker_submission": _safe_submission(case),
        "metadata": case.metadata,
        "artifacts": [{"kind": item.kind, "path": item.path} for item in artifacts],
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return manifest["artifacts"]


def _csrf_occurrence_findings(finding: dict[str, Any]) -> list[dict[str, Any]]:
    evidence = finding_evidence(finding)
    if str(evidence.get("vuln_type") or "").strip() != "CSRF":
        return []
    occurrences = evidence.get("csrf_occurrences")
    if not isinstance(occurrences, list) or len(occurrences) <= 1:
        return []

    expanded: list[dict[str, Any]] = []
    for index, occurrence in enumerate(occurrences, start=1):
        if not isinstance(occurrence, dict):
            continue
        occurrence_evidence = dict(evidence)
        occurrence_evidence.update(
            {
                "method": occurrence.get("method") or evidence.get("method"),
                "url": occurrence.get("url") or evidence.get("url"),
                "param": occurrence.get("param") or evidence.get("param"),
                "attack": occurrence.get("attack") or evidence.get("attack"),
                "status_code": occurrence.get("status_code") if occurrence.get("status_code") is not None else evidence.get("status_code"),
                "account_role": occurrence.get("account_role") or evidence.get("account_role"),
                "csrf_defenses": occurrence.get("csrf_defenses") or evidence.get("csrf_defenses"),
                "evidence_request": occurrence.get("evidence_request") or evidence.get("evidence_request"),
                "evidence_response": occurrence.get("evidence_response") or evidence.get("evidence_response"),
                "validation_status": occurrence.get("validation_status") or evidence.get("validation_status"),
                "validation_reason": occurrence.get("validation_reason") or evidence.get("validation_reason"),
                "confidence": occurrence.get("confidence") or evidence.get("confidence"),
                "risk": occurrence.get("risk") or evidence.get("risk"),
                "occurrence_index": index,
                "occurrence_count": evidence.get("occurrence_count") or len(occurrences),
            }
        )
        expanded.append({**finding, "evidence": occurrence_evidence})
    return expanded


def capture_latest(
    report_path: Path,
    output_root: Path,
    *,
    per_type_limit: int | None = None,
    perform_replay: bool = True,
) -> list[dict[str, Any]]:
    report = yaml.safe_load(report_path.read_text(encoding="utf-8")) or {}
    findings = list(report.get("findings") or [])
    selected = select_representatives(findings, per_type_limit=per_type_limit)
    capture_jobs: list[tuple[dict[str, Any], str | None, int | None]] = []
    for finding in selected:
        parent_id = stable_finding_id(finding)
        occurrence_findings = _csrf_occurrence_findings(finding)
        if occurrence_findings:
            capture_jobs.extend((item, parent_id, index) for index, item in enumerate(occurrence_findings, start=1))
        else:
            capture_jobs.append((finding, None, None))

    selected_ids = {stable_finding_id(finding) for finding, _, _ in capture_jobs}
    if output_root.is_dir():
        for stale_dir in output_root.glob("1-1_*"):
            if stale_dir.is_dir() and stale_dir.name not in selected_ids:
                shutil.rmtree(stale_dir)

    output_root.mkdir(parents=True, exist_ok=True)
    summary_path = output_root / "capture-summary.json"

    def _write_summary(results: list[dict[str, Any]]) -> None:
        # Written after every finding, not just once at the end, so a run that
        # gets killed partway (parent process timeout, crash) still leaves a
        # valid summary covering whatever finished — the report/frontend read
        # this file, not the individual finding folders, so without an
        # incremental write a partial run's already-captured evidence would
        # never be shown anywhere even though the screenshots exist on disk.
        summary = {
            "section_id": "1-1",
            "report": str(report_path),
            "selected": len(capture_jobs),
            "succeeded": sum(1 for row in results if row["ok"]),
            "failed": sum(1 for row in results if not row["ok"]),
            "results": results,
        }
        summary_path.write_text(
            json.dumps(summary, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    results: list[dict[str, Any]] = []
    for finding, parent_id, occurrence_index in capture_jobs:
        finding_id = stable_finding_id(finding)
        try:
            info: dict[str, Any] = {}
            artifacts = capture_finding(finding, output_root, perform_replay=perform_replay, info=info)
            evidence = finding_evidence(finding)
            row = {
                "finding_id": finding_id,
                "ok": True,
                "artifacts": artifacts,
                # lets the diagnosis service find this finding again without
                # importing the selector's id scheme
                "match": {
                    "vuln_type": str(evidence.get("vuln_type") or ""),
                    "url": str(evidence.get("url") or "").rstrip("/"),
                    "param": str(evidence.get("param") or ""),
                    "account_role": str(evidence.get("account_role") or ""),
                },
                **info,
            }
            if parent_id:
                evidence = finding_evidence(finding)
                row.update(
                    {
                        "parent_finding_id": parent_id,
                        "occurrence_index": occurrence_index,
                        "url": display_url(str(evidence.get("url") or "")),
                        "param": evidence.get("param"),
                        "payload": evidence.get("attack"),
                    }
                )
            results.append(row)
        except Exception as exc:
            row = {"finding_id": finding_id, "ok": False, "error": str(exc)}
            if parent_id:
                row.update({"parent_finding_id": parent_id, "occurrence_index": occurrence_index})
            results.append(row)
        _write_summary(results)

    return results


def _default_backend_root() -> Path:
    # /app/screenshot/modules/1-1 -> /app
    return _MODULE_DIR.parents[2]


def main() -> int:
    # xvfb-run only exists (and is only needed) on the headless Linux capture
    # container; on Windows/macOS dev machines Playwright can launch a headed
    # browser directly, so skip the re-exec there entirely.
    if sys.platform.startswith("linux") and not os.environ.get("DISPLAY"):
        try:
            os.execvp(
                "xvfb-run",
                [
                    "xvfb-run",
                    "-a",
                    "-s",
                    "-screen 0 1280x720x24",
                    sys.executable,
                    *sys.argv,
                ],
            )
        except FileNotFoundError:
            pass  # xvfb-run not installed; continue and let Playwright surface a clearer error

    backend_root = _default_backend_root()
    parser = argparse.ArgumentParser(description="Capture 1-1 Stored XSS / CSRF evidence screenshots")
    parser.add_argument(
        "--report",
        type=Path,
        default=backend_root / "data" / "report" / "1-1" / "latest.yaml",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=backend_root / "data" / "report" / "1-1" / "evidence",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Max representatives per vuln_type (default: capture every distinct finding)",
    )
    parser.add_argument(
        "--no-replay",
        action="store_true",
        help="Render saved evidence without live CSRF replay (skips the forged-request capture)",
    )
    args = parser.parse_args()

    results = capture_latest(
        args.report,
        args.output,
        per_type_limit=args.limit if args.limit is None else max(1, args.limit),
        perform_replay=not args.no_replay,
    )
    print(json.dumps(results, ensure_ascii=False, indent=2))
    return 0 if results and all(row["ok"] for row in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
