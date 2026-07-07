"""Orchestrate guideline diagnosis modules (1-1 ??8-1)."""

from __future__ import annotations

import re
import threading
from pathlib import Path
from typing import Any

from app.config import BACKEND_ROOT, load_config, config_to_inventory_dict
from diagnosis.catalog import SECTION_BY_ID, SECTIONS
from diagnosis.context import DiagnosisContext
from diagnosis.registry import get_module, get_modules, list_registered_ids
from diagnosis.exceptions import DiagnosisCancelled
from diagnosis.result import SectionReport


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

    # Load test-accounts.json if raw doesn't have auth accounts explicitly
    from app.services.test_accounts_service import load_test_accounts
    test_accs = load_test_accounts().get("accounts")
    if test_accs:
        if "auth" not in raw:
            raw["auth"] = {}
        if not raw["auth"].get("accounts"):
            raw["auth"]["accounts"] = test_accs

    if raw_overrides:
        if "diagnosis_2_2" in raw_overrides:
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
        raw_config=_inject_gradle_dep_files(raw),
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


def _run_module(mod: Any, ctx: DiagnosisContext, section_id: str) -> SectionReport:
    from app.services import diagnosis_progress as dp

    try:
        report = mod.run(ctx)
    except DiagnosisCancelled as exc:
        dp.cancel_finish(f"{section_id}: cancelled")
        raise RuntimeError(str(exc) or "Diagnosis cancelled") from exc
    _finish_progress(section_id, report)
    return report


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
    **kwargs,  # tolerate any future gNN_options the router may add (defensive)
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
    **kwargs,  # tolerate any future gNN_options the router may add (defensive)
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


