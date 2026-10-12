"""Orchestrate guideline diagnosis modules (1-1 ??8-1)."""

from __future__ import annotations

import importlib.util
import json
import logging
import re
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

from app.config import BACKEND_ROOT, load_config, config_to_inventory_dict
from diagnosis.catalog import SECTION_BY_ID, SECTIONS
from diagnosis.context import DiagnosisContext
from diagnosis.registry import get_module, get_modules, list_registered_ids
from diagnosis.exceptions import DiagnosisCancelled
from diagnosis.result import DiagnosisFinding, SectionReport

logger = logging.getLogger(__name__)



def _generate_g11_report_document(report_dir: Path) -> Path:
    module_path = BACKEND_ROOT / "report" / "modules" / "1-1" / "document.py"
    spec = importlib.util.spec_from_file_location("argus_g11_report_document", module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Failed to load 1-1 report document engine: {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.generate_report_document(report_dir)


def _inject_gradle_dep_files(raw: dict) -> dict:
    """data/gradle_dep_files.json에 저장된 경로를 diagnosis_7_4.gradle_dep_files에 주입한다.

    - 이미 raw config에 gradle_dep_files 목록이 있으면 그것을 우선한다.
    - JSON 파일이 없으면 raw를 그대로 반환(기존 동작 유지).
    """
    import json as _json

    gradle_json = BACKEND_ROOT / "data" / "gradle_dep_files.json"
    if not gradle_json.is_file():
        return raw

    try:
        stored = _json.loads(gradle_json.read_text(encoding="utf-8"))
        paths: list[str] = [p for p in (stored.get("paths") or []) if p]
    except Exception:
        return raw

    if not paths:
        return raw

    base_g74: dict = dict(raw.get("diagnosis_7_4") or {})
    # 이미 config.yaml에 gradle_dep_files가 명시된 경우 그것을 유지
    if base_g74.get("gradle_dep_files"):
        return raw

    base_g74["gradle_dep_files"] = paths
    return {**raw, "diagnosis_7_4": base_g74}



def _context(raw_overrides: dict | None = None) -> DiagnosisContext:
    cfg = load_config()
    import os
    import yaml

    env_path = os.environ.get("CONFIG_PATH")
    config_path = Path(env_path) if env_path else (BACKEND_ROOT / "config.yaml")
    raw: dict = {}
    if config_path.is_file():
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}

    raw = _inject_gradle_dep_files(raw)

    # Load test-accounts.json if raw doesn't have auth accounts explicitly
    from app.services.test_accounts_service import load_test_accounts
    test_accs = load_test_accounts().get("accounts")
    if test_accs:
        if "auth" not in raw:
            raw["auth"] = {}
        if not raw["auth"].get("accounts"):
            raw["auth"]["accounts"] = test_accs

    if raw_overrides:
        if "diagnosis_2_1" in raw_overrides:
            base_g21 = dict(raw.get("diagnosis_2_1") or {})
            base_g21.update(raw_overrides["diagnosis_2_1"])
            raw = {**raw, "diagnosis_2_1": base_g21}
        elif "diagnosis_2_2" in raw_overrides:
            base_g22 = dict(raw.get("diagnosis_2_2") or {})
            base_g22.update(raw_overrides["diagnosis_2_2"])
            raw = {**raw, "diagnosis_2_2": base_g22}
        elif "diagnosis_7_3" in raw_overrides:
            base_g73 = dict(raw.get("diagnosis_7_3") or {})
            base_g73.update(raw_overrides["diagnosis_7_3"])
            raw = {**raw, "diagnosis_7_3": base_g73}
        elif "diagnosis_7_1" in raw_overrides:
            base_g71 = dict(raw.get("diagnosis_7_1") or {})
            base_g71.update(raw_overrides["diagnosis_7_1"])
            raw = {**raw, "diagnosis_7_1": base_g71}
        elif "diagnosis_7_2" in raw_overrides:
            base_g72 = dict(raw.get("diagnosis_7_2") or {})
            base_g72.update(raw_overrides["diagnosis_7_2"])
            raw = {**raw, "diagnosis_7_2": base_g72}
        elif "diagnosis_7_4" in raw_overrides:
            base_g74 = dict(raw.get("diagnosis_7_4") or {})
            base_g74.update(raw_overrides["diagnosis_7_4"])
            raw = {**raw, "diagnosis_7_4": base_g74}
        elif "diagnosis_5_2" in raw_overrides:
            base_g52 = dict(raw.get("diagnosis_5_2") or {})
            base_g52.update(raw_overrides["diagnosis_5_2"])
            raw = {**raw, "diagnosis_5_2": base_g52}
        elif "diagnosis_6_1" in raw_overrides:
            base_g61 = dict(raw.get("diagnosis_6_1") or {})
            base_g61.update(raw_overrides["diagnosis_6_1"])
            raw = {**raw, "diagnosis_6_1": base_g61}
        elif "diagnosis_6_2" in raw_overrides:
            base_g62 = dict(raw.get("diagnosis_6_2") or {})
            base_g62.update(raw_overrides["diagnosis_6_2"])
            raw = {**raw, "diagnosis_6_2": base_g62}
        elif "diagnosis_3_6" in raw_overrides:
            base_g36 = dict(raw.get("diagnosis_3_6") or {})
            base_g36.update(raw_overrides["diagnosis_3_6"])
            raw = {**raw, "diagnosis_3_6": base_g36}
        elif "diagnosis_3_5" in raw_overrides:
            base_g35 = dict(raw.get("diagnosis_3_5") or {})
            base_g35.update(raw_overrides["diagnosis_3_5"])
            raw = {**raw, "diagnosis_3_5": base_g35}
        elif "diagnosis_3_2" in raw_overrides:
            base_g32 = dict(raw.get("diagnosis_3_2") or {})
            base_g32.update(raw_overrides["diagnosis_3_2"])
            raw = {**raw, "diagnosis_3_2": base_g32}
        elif "diagnosis_3_4" in raw_overrides:
            base_g34 = dict(raw.get("diagnosis_3_4") or {})
            base_g34.update(raw_overrides["diagnosis_3_4"])
            raw = {**raw, "diagnosis_3_4": base_g34}
        elif "diagnosis_4_2" in raw_overrides:
            base_g42 = dict(raw.get("diagnosis_4_2") or {})
            base_g42.update(raw_overrides["diagnosis_4_2"])
            raw = {**raw, "diagnosis_4_2": base_g42}
        elif "diagnosis_4_5" in raw_overrides:
            base_g45 = dict(raw.get("diagnosis_4_5") or {})
            base_g45.update(raw_overrides["diagnosis_4_5"])
            raw = {**raw, "diagnosis_4_5": base_g45}
        elif "diagnosis_1_5" in raw_overrides:
            base_g15 = dict(raw.get("diagnosis_1_5") or {})
            base_g15.update(raw_overrides["diagnosis_1_5"])
            raw = {**raw, "diagnosis_1_5": base_g15}
        elif "diagnosis_1_6" in raw_overrides:
            base_g16 = dict(raw.get("diagnosis_1_6") or {})
            base_g16.update(raw_overrides["diagnosis_1_6"])
            raw = {**raw, "diagnosis_1_6": base_g16}
        elif "diagnosis_1_2" in raw_overrides:
            base_g12 = dict(raw.get("diagnosis_1_2") or {})
            base_g12.update(raw_overrides["diagnosis_1_2"])
            raw = {**raw, "diagnosis_1_2": base_g12}
        elif "diagnosis_4_1" in raw_overrides:
            base_g41 = dict(raw.get("diagnosis_4_1") or {})
            base_g41.update(raw_overrides["diagnosis_4_1"])
            raw = {**raw, "diagnosis_4_1": base_g41}
        elif "diagnosis_2_1" in raw_overrides:
            base_g21 = dict(raw.get("diagnosis_2_1") or {})
            base_g21.update(raw_overrides["diagnosis_2_1"])
            raw = {**raw, "diagnosis_2_1": base_g21}
        else:
            raw = {**raw, **raw_overrides}

    return DiagnosisContext(
        data_dir=BACKEND_ROOT / "data",
        config=config_to_inventory_dict(cfg),
        raw_config=raw,
    )


def catalog() -> list[dict]:
    registered = set(list_registered_ids())
    items: list[dict] = []
    for entry in SECTIONS:
        section_id = entry["id"]
        mod = get_module(section_id)
        items.append(
            {
                "id": section_id,
                "title": entry["title"],
                "chapter": entry["chapter"],
                "registered": section_id in registered,
                "implemented": bool(mod.implemented) if mod else False,
                "diagnosable": bool(getattr(mod, "diagnosable", True)) if mod else True,
                "review_later": bool(getattr(mod, "review_later", False)) if mod else False,
                "status_label": getattr(mod, "status_label", None) if mod else None,
                "engine": mod.engine if mod else "missing",
            }
        )
    return items


def get_report(section_id: str) -> SectionReport | None:
    if section_id not in SECTION_BY_ID:
        return None
    mod = get_module(section_id)
    if mod is None:
        return None
    ctx = _context()
    return mod.load_report(ctx)


def get_report_pdf(section_id: str, *, generate_if_missing: bool = True) -> Path | None:
    """섹션 결과서 PDF 경로를 반환. 없으면(옵션) 최신 진단 결과로 즉석 생성."""
    if section_id not in SECTION_BY_ID:
        return None
    ctx = _context()
    try:
        from report.service import report_pdf_path, generate_report
    except Exception:
        logger.exception("결과서 서비스 로드 실패")
        return None

    pdf_path = report_pdf_path(section_id, ctx.data_dir)
    if pdf_path is None:
        return None
    if pdf_path.is_file():
        return pdf_path
    if not generate_if_missing:
        return None
    try:
        return generate_report(section_id, ctx.data_dir)
    except Exception:
        logger.exception("%s 결과서 즉석 생성 실패", section_id)
        return None


def resolve_evidence_file(section_id: str, rel_path: str) -> Path | None:
    """Resolve a client-supplied relative path to a file under a section's
    evidence dir, rejecting anything that would escape that dir."""
    from diagnosis.paths import section_evidence_dir

    if section_id not in SECTION_BY_ID or not rel_path:
        return None

    ctx = _context()
    evidence_root = section_evidence_dir(ctx.data_dir, section_id).resolve()
    candidate = (evidence_root / rel_path).resolve()
    try:
        candidate.relative_to(evidence_root)
    except ValueError:
        return None
    if not candidate.is_file():
        return None
    return candidate


# Sections with PDF result-export implementations under backend/report/modules/{id}/
PDF_EXPORT_SECTIONS = frozenset({"2-2"})


def supports_pdf_export(section_id: str) -> bool:
    return section_id in PDF_EXPORT_SECTIONS


def build_section_pdf(section_id: str) -> Path:
    """Generate (or refresh) the section PDF under data/report/{id}/result.pdf."""
    if section_id not in PDF_EXPORT_SECTIONS:
        raise ValueError(f"PDF export not supported for section {section_id}")

    import importlib.util

    from diagnosis.paths import section_report_dir, section_report_path

    ctx = _context()
    report_dir = section_report_dir(ctx.data_dir, section_id)
    yaml_path = section_report_path(ctx.data_dir, section_id)
    if not yaml_path.is_file():
        raise FileNotFoundError(f"No report for module {section_id}")

    module_dir = BACKEND_ROOT / "report" / "modules" / section_id
    generate_py = module_dir / "generate.py"
    if not generate_py.is_file():
        raise FileNotFoundError(f"PDF generator missing for section {section_id}")

    # hyphen folder (e.g. 2-2) is not importable; load generate.py by path.
    # generate.py pulls siblings (content/shots) via the same directory on sys.path.
    inserted = str(module_dir)
    path_was_present = inserted in sys.path
    if not path_was_present:
        sys.path.insert(0, inserted)
    try:
        mod_name = f"argus_report_{section_id.replace('-', '_')}_generate"
        spec = importlib.util.spec_from_file_location(mod_name, generate_py)
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot load PDF generator: {generate_py}")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        out = mod.build_pdf(report_dir)
    finally:
        if not path_was_present:
            try:
                sys.path.remove(inserted)
            except ValueError:
                pass

    out_path = Path(out)
    if not out_path.is_file():
        raise RuntimeError(f"PDF was not written for section {section_id}")
    return out_path


def get_g61_report_summary() -> dict[str, Any] | None:
    """Compact 6-1 report for UI (aggregated groups, no raw 70k findings)."""
    import importlib.util

    mod = get_module("6-1")
    if mod is None:
        return None
    ctx = _context()
    report_path = mod.report_path(ctx)
    if not report_path.is_file():
        return None

    spec = importlib.util.spec_from_file_location(
        "diag_g61_report_summary",
        mod.module_dir / "report_summary.py",
    )
    if spec is None or spec.loader is None:
        return None
    rs = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rs)
    summary = rs.load_or_build_summary(report_path)

    raw = report_path.read_text(encoding="utf-8", errors="replace").split("\nfindings:\n", 1)[0]
    meta: dict[str, Any] = {}
    for key in ("section_id", "title", "status", "message", "checked_at"):
        m = re.search(rf"^{key}: (.+)$", raw, re.M)
        if not m:
            continue
        meta[key] = m.group(1).strip().strip("'\"")
    m = re.search(r"^chapter: (\d+)$", raw, re.M)
    if m:
        meta["chapter"] = int(m.group(1))

    stats = summary.get("stats") or {}
    stats_finding = {
        "severity": "info",
        "message": "6-1 scan statistics",
        "evidence": {"stats": stats},
    }
    return {
        "section_id": meta.get("section_id", "6-1"),
        "title": meta.get("title", "오류페이지를 통한 정보 노출 여부"),
        "chapter": meta.get("chapter", 6),
        "status": meta.get("status", "pending"),
        "implemented": True,
        "message": meta.get("message", ""),
        "checked_at": meta.get("checked_at"),
        "findings": [stats_finding],
        "g61_summary": {
            "total_issues": summary.get("total_issues", 0),
            "by_severity": summary.get("by_severity", {}),
            "by_sk": summary.get("by_sk", {}),
            "by_category": summary.get("by_category", {}),
            "by_trigger_family": summary.get("by_trigger_family", {}),
            "by_origin": summary.get("by_origin", []),
            "groups": summary.get("groups", []),
            "endpoints": summary.get("endpoints", []),
            "stats": stats,
        },
    }


def _build_overrides(
    section_id: str,
    *,
    g22_options: dict | None = None,
    g71_options: dict | None = None,
    g73_options: dict | None = None,
    g72_options: dict | None = None,
    g74_options: dict | None = None,
    g52_options: dict | None = None,
    g61_options: dict | None = None,
    g62_options: dict | None = None,
    g36_options: dict | None = None,
    g35_options: dict | None = None,
    g32_options: dict | None = None,
    g34_options: dict | None = None,
    g12_options: dict | None = None,
    g15_options: dict | None = None,
    g16_options: dict | None = None,
    g41_options: dict | None = None,
    g42_options: dict | None = None,
    g21_options: dict | None = None,
    g45_options: dict | None = None,
    **kwargs: Any,
) -> dict | None:
    if g22_options and section_id == "2-2":
        return {"diagnosis_2_2": {k: v for k, v in g22_options.items() if v is not None}}
    if g71_options and section_id == "7-1":
        return {"diagnosis_7_1": {k: v for k, v in g71_options.items() if v is not None}}
    if g73_options and section_id == "7-3":
        return {"diagnosis_7_3": {k: v for k, v in g73_options.items() if v is not None}}
    if g72_options and section_id == "7-2":
        return {"diagnosis_7_2": {k: v for k, v in g72_options.items() if v is not None}}
    if g74_options and section_id == "7-4":
        return {"diagnosis_7_4": {k: v for k, v in g74_options.items() if v is not None}}
    if g52_options and section_id == "5-2":
        return {"diagnosis_5_2": {k: v for k, v in g52_options.items() if v is not None}}
    if g61_options and section_id == "6-1":
        return {"diagnosis_6_1": {k: v for k, v in g61_options.items() if v is not None}}
    if g62_options and section_id == "6-2":
        return {"diagnosis_6_2": {k: v for k, v in g62_options.items() if v is not None}}
    if g36_options and section_id == "3-6":
        return {"diagnosis_3_6": {k: v for k, v in g36_options.items() if v is not None}}
    if g35_options and section_id == "3-5":
        return {"diagnosis_3_5": {k: v for k, v in g35_options.items() if v is not None}}
    if g32_options and section_id == "3-2":
        return {"diagnosis_3_2": {k: v for k, v in g32_options.items() if v is not None}}
    if g34_options and section_id == "3-4":
        return {"diagnosis_3_4": {k: v for k, v in g34_options.items() if v is not None}}
    if g15_options and section_id == "1-5":
        return {"diagnosis_1_5": {k: v for k, v in g15_options.items() if v is not None}}
    if g16_options and section_id == "1-6":
        return {"diagnosis_1_6": {k: v for k, v in g16_options.items() if v is not None}}
    if g12_options and section_id == "1-2":
        return {"diagnosis_1_2": {k: v for k, v in g12_options.items() if v is not None}}
    if g41_options and section_id == "4-1":
        return {"diagnosis_4_1": {k: v for k, v in g41_options.items() if v is not None}}
    if g42_options and section_id == "4-2":
        return {"diagnosis_4_2": {k: v for k, v in g42_options.items() if v is not None}}
    if g21_options and section_id == "2-1":
        return {"diagnosis_2_1": {k: v for k, v in g21_options.items() if v is not None}}
    if g45_options and section_id == "4-5":
        return {"diagnosis_4_5": {k: v for k, v in g45_options.items() if v is not None}}
    return None


def _resolve_module(section_id: str) -> Any:
    if section_id not in SECTION_BY_ID:
        raise KeyError(f"Unknown section: {section_id}")
    mod = get_module(section_id)
    if mod is None:
        raise RuntimeError(f"Module not registered: {section_id}")
    if not getattr(mod, "diagnosable", True):
        raise ValueError(f"Section {section_id} is not diagnosable automatically")
    return mod


def _run_options_kwargs(
    *,
    g22_options: dict | None = None,
    g71_options: dict | None = None,
    g73_options: dict | None = None,
    g72_options: dict | None = None,
    g74_options: dict | None = None,
    g52_options: dict | None = None,
    g61_options: dict | None = None,
    g62_options: dict | None = None,
    g36_options: dict | None = None,
    g35_options: dict | None = None,
    g32_options: dict | None = None,
    g34_options: dict | None = None,
    g12_options: dict | None = None,
    g15_options: dict | None = None,
    g16_options: dict | None = None,
    g41_options: dict | None = None,
    g42_options: dict | None = None,
    g21_options: dict | None = None,
    g45_options: dict | None = None,
    **kwargs: Any,
) -> dict[str, dict | None]:
    return {
        "g22_options": g22_options,
        "g71_options": g71_options,
        "g73_options": g73_options,
        "g72_options": g72_options,
        "g74_options": g74_options,
        "g52_options": g52_options,
        "g61_options": g61_options,
        "g62_options": g62_options,
        "g36_options": g36_options,
        "g35_options": g35_options,
        "g32_options": g32_options,
        "g34_options": g34_options,
        "g12_options": g12_options,
        "g15_options": g15_options,
        "g16_options": g16_options,
        "g41_options": g41_options,
        "g42_options": g42_options,
        "g21_options": g21_options,
        "g45_options": g45_options,
    }


def is_section_run_in_progress() -> bool:
    from app.services import diagnosis_progress as dp

    return bool(dp.snapshot().get("running"))


def request_cancel_run() -> str | None:
    """Request cancellation of the in-flight diagnosis run. Returns section_id if accepted."""
    from app.services import diagnosis_progress as dp

    snap = dp.snapshot()
    if not snap.get("running"):
        return None
    section_id = str(snap.get("section_id") or "").strip()
    if not section_id:
        return None
    dp.request_cancel()
    return section_id


def _finish_progress(section_id: str, report: SectionReport) -> None:
    from app.services import diagnosis_progress as dp

    if report.status == "cancelled" or dp.is_cancel_requested():
        dp.cancel_finish(f"{section_id}: cancelled")
        return
    dp.finish(f"{section_id}: {report.status}")


def apply_g11_browser_verdicts(report: SectionReport, capture_summary: dict[str, Any]) -> int:
    """Fold the capture browser's Stored XSS observations into the findings.

    The scan grades a finding from the HTTP response alone; the capture then
    opens the real page. Executed -> confirmed, shown as inert text -> candidate,
    page not inspected -> the response-based level stands. Returns how many
    findings were updated."""
    from diagnosis import stored_xss_verdict as verdict

    def key(evidence: dict[str, Any]) -> tuple[str, str, str, str]:
        return (
            str(evidence.get("vuln_type") or ""),
            str(evidence.get("url") or "").rstrip("/"),
            str(evidence.get("param") or ""),
            str(evidence.get("account_role") or ""),
        )

    browser_by_key: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for row in capture_summary.get("results") or []:
        if not isinstance(row, dict) or not row.get("ok"):
            continue
        browser = row.get("browser_verification")
        match = row.get("match")
        if isinstance(browser, dict) and isinstance(match, dict):
            browser_by_key[key(match)] = browser

    updated = 0
    for finding in report.findings:
        evidence = finding.evidence
        if str(evidence.get("vuln_type") or "") != "Stored XSS":
            continue
        browser = browser_by_key.get(key(evidence))
        if browser is None:
            continue
        status = str(browser.get("status") or verdict.BROWSER_NOT_CHECKED)
        response_level = str(evidence.get("xss_level") or verdict.CANDIDATE)
        level = verdict.final_level(response_level, status)
        risk, confidence, validation_status = verdict.rating(level)
        evidence.update(
            {
                "xss_level": level,
                "xss_level_by_response": response_level,
                "browser_verification": browser,
                "risk": risk,
                "confidence": confidence,
                "validation_status": validation_status,
                "validation_reason": verdict.reason(level, status),
            }
        )
        updated += 1
    return updated


def _run_g11_screenshot_capture(mod: Any, ctx: DiagnosisContext, report: SectionReport) -> None:
    """Generate 1-1 evidence screenshots after latest.yaml is written.

    Screenshot capture is a post-processing artifact step. It should never turn
    a completed diagnosis into a failed diagnosis; failures are recorded as an
    informational finding and in capture-summary.json.
    """
    if report.section_id != "1-1":
        return

    import os
    from app.services import diagnosis_progress as dp

    if str(os.getenv("ARGUS_SCREENSHOT_AUTO", "true")).strip().lower() in {"0", "false", "no", "off"}:
        return

    screenshot_root = ctx.data_dir.parent / "screenshot"
    capture_script = screenshot_root / "modules" / "1-1" / "capture.py"
    report_path = ctx.data_dir / "report" / "1-1" / "latest.yaml"
    output_dir = ctx.data_dir / "report" / "1-1" / "evidence"
    summary_path = output_dir / "capture-summary.json"

    if not capture_script.is_file():
        report.findings.append(
            DiagnosisFinding(
                severity="info",
                message="1-1 evidence screenshot capture skipped",
                evidence={
                    "screenshot_capture": {
                        "ok": False,
                        "reason": f"capture script not found: {capture_script}",
                    }
                },
            )
        )
        mod.save_report(ctx, report)
        return

    # Force running=True for the capture phase: the scan engine may have already
    # flipped running=False (a benign end-of-scan auth-reverify message routes
    # through dp.fail), and dp.update alone won't undo that. The run isn't done
    # until screenshots exist, so re-assert running here; _finish_progress does
    # the real finish only after capture returns.
    dp.update(phase="screenshot", message="1-1 generating evidence screenshots...", percent=98, running=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        str(capture_script),
        "--report",
        str(report_path),
        "--output",
        str(output_dir),
    ]
    timeout_sec = int(os.getenv("ARGUS_SCREENSHOT_TIMEOUT_SEC", "900") or "900")
    capture_log_path = output_dir / "capture.log"

    result_payload: dict[str, Any] = {
        "command": cmd,
        "report": str(report_path),
        "output": str(output_dir),
        "summary": str(summary_path),
        "log": str(capture_log_path),
    }

    def _tail(text_or_path: Any, limit: int = 4000) -> str:
        try:
            if isinstance(text_or_path, Path):
                return text_or_path.read_text(encoding="utf-8", errors="replace")[-limit:]
            return str(text_or_path or "")[-limit:]
        except Exception:
            return ""

    # Stream capture output to a log FILE, not a pipe. capture.py prints
    # thousands of progress lines and re-execs itself under xvfb-run (spawning
    # scrot/chromium children); with capture_output=True (PIPE) that mix
    # triggered [Errno 32] Broken pipe partway through, killing every remaining
    # finding's capture. A plain file has no such backpressure — this is the
    # same reason a manual run piped to `tee` captured all 32/32 findings.
    try:
        with capture_log_path.open("w", encoding="utf-8", errors="replace") as logf:
            proc = subprocess.run(
                cmd,
                cwd=str(ctx.data_dir.parent),
                text=True,
                stdout=logf,
                stderr=subprocess.STDOUT,
                timeout=timeout_sec,
            )
        result_payload.update(
            {
                "ok": proc.returncode == 0,
                "returncode": proc.returncode,
                "stdout": _tail(capture_log_path),
                "stderr": "",
            }
        )
    except subprocess.TimeoutExpired:
        result_payload.update(
            {
                "ok": False,
                "error": f"screenshot capture timed out after {timeout_sec}s",
                "stdout": _tail(capture_log_path),
                "stderr": "",
            }
        )
    except Exception as exc:
        result_payload.update({"ok": False, "error": str(exc), "stdout": _tail(capture_log_path)})

    if summary_path.is_file():
        try:
            result_payload["capture_summary"] = json.loads(summary_path.read_text(encoding="utf-8"))
        except Exception:
            result_payload["capture_summary"] = {"unreadable": str(summary_path)}

    summary_data = result_payload.get("capture_summary")
    if isinstance(summary_data, dict):
        try:
            result_payload["browser_verdicts_applied"] = apply_g11_browser_verdicts(report, summary_data)
            # the PDF below is built from the saved report, so save the verdicts first
            mod.save_report(ctx, report)
        except Exception as exc:
            result_payload["browser_verdict_error"] = str(exc)

    report.findings.append(
        DiagnosisFinding(
            severity="info",
            message="1-1 evidence screenshot capture completed"
            if result_payload.get("ok")
            else "1-1 evidence screenshot capture failed",
            evidence={"screenshot_capture": result_payload},
        )
    )
    try:
        result_payload["report_document"] = str(_generate_g11_report_document(report_path.parent))
    except Exception as exc:
        result_payload["report_document_error"] = str(exc)
    mod.save_report(ctx, report)


def _run_module(mod: Any, ctx: DiagnosisContext, section_id: str) -> SectionReport:
    from app.services import diagnosis_progress as dp

    try:
        report = mod.run(ctx)
    except DiagnosisCancelled as exc:
        dp.cancel_finish(f"{section_id}: cancelled")
        raise RuntimeError(str(exc) or "Diagnosis cancelled") from exc
    # 1-2 / 2-1 / 2-2 / 7-4: 증거 스크린샷 캡처
    if section_id in {"1-2", "2-1", "2-2", "7-4"} and report.status != "cancelled":
        from app.services.evidence_capture_service import capture_after_diagnosis, supports

        if supports(section_id):
            dp.update(
                phase="evidence",
                message=f"{section_id}: 증거 스크린샷 생성 중…",
                percent=99,
            )
            capture_result = capture_after_diagnosis(section_id, ctx.data_dir)
            if not capture_result.get("ok"):
                dp.update(
                    phase="evidence",
                    message=f"{section_id}: 스크린샷 생성 실패 — 진단 결과는 저장됨",
                    percent=99,
                )
        else:
            from app.services.report_generation_service import (
                generate_after_capture,
                supports as supports_final_report,
            )

            if supports_final_report(section_id):
                dp.update(
                    phase="report",
                    message=f"{section_id}: 최종 보고서 생성 중…",
                    percent=99,
                )
                report_result = generate_after_capture(section_id, ctx.data_dir)
                if not report_result.get("ok"):
                    dp.update(
                        phase="report",
                        message=f"{section_id}: 보고서 생성 실패 — 진단 및 증거는 저장됨",
                        percent=99,
                    )

    # 1-1: XSS/CSRF 증거 스크린샷 캡처
    # 내부에서 section_id != "1-1"이면 즉시 return 하므로 무조건 호출해도 안전
    _run_g11_screenshot_capture(mod, ctx, report)

    # 5-2: 진단 결과서(PDF) 생성 — 진단을 다시 하면 덮어쓴다.
    if section_id == "5-2" and report.status != "cancelled":
        _generate_section_report(section_id, ctx, report)

            # Report generation is sequenced strictly after screenshot capture
            # finishes (whether it succeeded or not) — only sections with
            # auto-capture get an auto-built report; everything else still
            # renders on-demand at download time.
    _build_report_pdf_best_effort(section_id, ctx)

    _finish_progress(section_id, report)
    return report


def _generate_section_report(section_id: str, ctx: DiagnosisContext, report: SectionReport) -> None:
    """섹션 결과서 PDF 생성. 실패해도 진단 결과 자체는 유지한다."""
    from app.services import diagnosis_progress as dp

    dp.update(
        phase="report",
        message=f"{section_id}: 결과서(PDF) 생성 중…",
        percent=99,
    )
    try:
        from report.service import generate_report

        out = generate_report(section_id, ctx.data_dir)
        if out is None:
            dp.update(
                phase="report",
                message=f"{section_id}: 결과서 빌더 없음 — 진단 결과는 저장됨",
                percent=99,
            )
    except Exception as exc:  # 결과서 실패가 진단을 막지 않도록
        logger.exception("%s 결과서 생성 실패", section_id)
        dp.update(
            phase="report",
            message=f"{section_id}: 결과서 생성 실패 — 진단 결과는 저장됨",
            percent=99,
        )


def _build_report_pdf_best_effort(section_id: str, ctx: DiagnosisContext) -> None:
    """Pre-build data/report/{id}/latest.pdf right after screenshot capture
    finishes, so the download button just serves an already-generated file
    instead of rendering on click.

    Only runs for sections with their own report/modules/{id}/renderer.py
    (loaded dynamically since e.g. "6-1" isn't a valid Python import segment).
    Never fails the diagnosis run."""
    import importlib.util

    from app.config import BACKEND_ROOT

    renderer_path = BACKEND_ROOT / "report" / "modules" / section_id / "renderer.py"
    if not renderer_path.is_file():
        return
    try:
        mod_name = f"report_renderer_{section_id.replace('-', '_')}"
        spec = importlib.util.spec_from_file_location(mod_name, renderer_path)
        if spec is None or spec.loader is None:
            return
        renderer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(renderer)
        renderer.render_pdf(ctx=ctx)
    except Exception:
        pass


def start_section_run_background(
    section_id: str,
    *,
    g22_options: dict | None = None,
    g71_options: dict | None = None,
    g73_options: dict | None = None,
    g72_options: dict | None = None,
    g74_options: dict | None = None,
    g52_options: dict | None = None,
    g61_options: dict | None = None,
    g62_options: dict | None = None,
    g36_options: dict | None = None,
    g35_options: dict | None = None,
    g32_options: dict | None = None,
    g34_options: dict | None = None,
    g12_options: dict | None = None,
    g15_options: dict | None = None,
    g16_options: dict | None = None,
    g41_options: dict | None = None,
    g42_options: dict | None = None,
    g21_options: dict | None = None,
    g45_options: dict | None = None,
    **kwargs: Any,
) -> None:
    """Start a diagnosis run on a background thread (for long scans such as 6-1)."""
    from app.services import diagnosis_progress as dp

    if dp.snapshot().get("running"):
        current = dp.snapshot().get("section_id") or "unknown"
        raise RuntimeError(f"Diagnosis already running: {current}")

    mod = _resolve_module(section_id)
    option_kwargs = _run_options_kwargs(
        g22_options=g22_options,
        g71_options=g71_options,
        g73_options=g73_options,
        g72_options=g72_options,
        g74_options=g74_options,
        g52_options=g52_options,
        g61_options=g61_options,
        g62_options=g62_options,
        g36_options=g36_options,
        g35_options=g35_options,
        g32_options=g32_options,
        g34_options=g34_options,
        g12_options=g12_options,
        g15_options=g15_options,
        g16_options=g16_options,
        g41_options=g41_options,
        g42_options=g42_options,
        g21_options=g21_options,
        g45_options=g45_options,
    )
    overrides = _build_overrides(section_id, **option_kwargs)
    ctx = _context(overrides)
    dp.reset(section_id=section_id, message=f"Running {section_id}...")

    def _worker() -> None:
        try:
            _run_module(mod, ctx, section_id)
        except DiagnosisCancelled:
            pass
        except Exception as exc:
            dp.fail(str(exc)[:300])

    thread = threading.Thread(
        target=_worker,
        name=f"diagnosis-{section_id}",
        daemon=True,
    )
    thread.start()


def run_section(
    section_id: str,
    *,
    g21_options: dict | None = None,
    g22_options: dict | None = None,
    g71_options: dict | None = None,
    g73_options: dict | None = None,
    g72_options: dict | None = None,
    g74_options: dict | None = None,
    g52_options: dict | None = None,
    g61_options: dict | None = None,
    g62_options: dict | None = None,
    g36_options: dict | None = None,
    g35_options: dict | None = None,
    g32_options: dict | None = None,
    g34_options: dict | None = None,
    g12_options: dict | None = None,
    g15_options: dict | None = None,
    g16_options: dict | None = None,
    g41_options: dict | None = None,
    g42_options: dict | None = None,
    g45_options: dict | None = None,
    **kwargs: Any,
) -> SectionReport:
    mod = _resolve_module(section_id)
    option_kwargs = _run_options_kwargs(
        g22_options=g22_options,
        g71_options=g71_options,
        g73_options=g73_options,
        g72_options=g72_options,
        g74_options=g74_options,
        g52_options=g52_options,
        g61_options=g61_options,
        g62_options=g62_options,
        g36_options=g36_options,
        g35_options=g35_options,
        g32_options=g32_options,
        g34_options=g34_options,
        g12_options=g12_options,
        g15_options=g15_options,
        g16_options=g16_options,
        g41_options=g41_options,
        g42_options=g42_options,
        g21_options=g21_options,
        g45_options=g45_options,
    )
    overrides = _build_overrides(section_id, **option_kwargs)
    ctx = _context(overrides)
    from app.services import diagnosis_progress as dp

    dp.reset(section_id=section_id, message=f"Running {section_id}...")
    try:
        return _run_module(mod, ctx, section_id)
    except DiagnosisCancelled as exc:
        raise RuntimeError(str(exc) or "Diagnosis cancelled") from exc
    except Exception as exc:
        dp.fail(str(exc)[:300])
        raise


def run_all() -> list[SectionReport]:
    ctx = _context()
    reports: list[SectionReport] = []
    for section_id in sorted(get_modules().keys()):
        mod = get_modules()[section_id]
        if not getattr(mod, "diagnosable", True):
            continue
        reports.append(mod.run(ctx))
    return reports


def list_replay_findings(section_id: str) -> list[dict]:
    from diagnosis.replay.service import list_replayable_findings

    if section_id not in SECTION_BY_ID:
        raise KeyError(f"Unknown section: {section_id}")
    return list_replayable_findings(section_id)


def run_replay(section_id: str, *, finding_id: str | None = None, use_playwright: bool = True) -> list:
    from diagnosis.replay.service import run_section_replay

    if section_id not in SECTION_BY_ID:
        raise KeyError(f"Unknown section: {section_id}")

    import os
    import yaml
    from app.config import BACKEND_ROOT

    env_path = os.environ.get("CONFIG_PATH")
    config_path = Path(env_path) if env_path else (BACKEND_ROOT / "config.yaml")
    raw: dict = {}
    if config_path.is_file():
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}

    return run_section_replay(
        section_id,
        finding_id=finding_id,
        raw_config=raw,
        use_playwright=use_playwright,
    )
