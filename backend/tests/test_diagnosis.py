"""Tests for diagnosis module registry and stub run."""

from __future__ import annotations

from pathlib import Path

from app.services import diagnosis_service
from diagnosis.catalog import SECTIONS
from diagnosis.registry import list_registered_ids, module_dir

SHELL_ONLY_SECTIONS = frozenset()

MANUAL_DIAGNOSIS_SECTIONS = frozenset(
    {"1-3", "1-4", "3-1", "3-3", "4-1", "4-2", "4-3", "5-1", "8-1"}
)


def test_all_modules_registered():
    assert len(list_registered_ids()) == len(SECTIONS) - len(SHELL_ONLY_SECTIONS)


def test_catalog_matches_modules():
    catalog = diagnosis_service.catalog()
    assert len(catalog) == len(SECTIONS)
    for row in catalog:
        if row["id"] in SHELL_ONLY_SECTIONS:
            assert row["registered"] is False
            assert row["engine"] == "missing"
        else:
            assert row["registered"] is True


def test_run_module_stub():
    import pytest

    with pytest.raises(ValueError, match="not diagnosable"):
        diagnosis_service.run_section("1-3")


def test_not_diagnosable_sections():
    catalog = diagnosis_service.catalog()
    for section_id in MANUAL_DIAGNOSIS_SECTIONS:
        row = next(r for r in catalog if r["id"] == section_id)
        assert row["diagnosable"] is False
        assert row["implemented"] is False


def test_no_review_later_sections():
    catalog = diagnosis_service.catalog()
    for row in catalog:
        assert row["review_later"] is False


def test_manual_diagnosis_sections():
    catalog = diagnosis_service.catalog()
    for section_id in MANUAL_DIAGNOSIS_SECTIONS:
        row = next(r for r in catalog if r["id"] == section_id)
        assert row["status_label"] == "수동 진단"
        assert row["review_later"] is False
        assert row["diagnosable"] is False
        assert row["implemented"] is False


def test_run_not_diagnosable_raises():
    import pytest

    for section_id in MANUAL_DIAGNOSIS_SECTIONS:
        with pytest.raises(ValueError, match="not diagnosable"):
            diagnosis_service.run_section(section_id)


def test_g22_module_implemented():
    mod = diagnosis_service.catalog()
    row = next(r for r in mod if r["id"] == "2-2")
    assert row["implemented"] is True
    assert row["engine"] == "httpx+zap"


def test_g72_module_implemented():
    mod = diagnosis_service.catalog()
    row = next(r for r in mod if r["id"] == "7-2")
    assert row["implemented"] is True
    assert row["engine"] == "httpx+zap"


def test_g71_module_implemented():
    mod = diagnosis_service.catalog()
    row = next(r for r in mod if r["id"] == "7-1")
    assert row["implemented"] is True
    assert row["engine"] == "httpx+zap"


def test_g73_module_implemented():
    mod = diagnosis_service.catalog()
    row = next(r for r in mod if r["id"] == "7-3")
    assert row["implemented"] is True
    assert row["engine"] == "httpx+zap"


def test_g74_module_implemented():
    mod = diagnosis_service.catalog()
    row = next(r for r in mod if r["id"] == "7-4")
    assert row["implemented"] is True
    assert row["engine"] == "httpx+zap"


def test_g62_module_implemented():
    mod = diagnosis_service.catalog()
    row = next(r for r in mod if r["id"] == "6-2")
    assert row["implemented"] is True
    assert row["engine"] == "httpx+zap"


def test_g61_module_implemented():
    mod = diagnosis_service.catalog()
    row = next(r for r in mod if r["id"] == "6-1")
    assert row["implemented"] is True
    assert row["engine"] == "httpx+zap"


def test_g35_module_implemented():
    mod = diagnosis_service.catalog()
    row = next(r for r in mod if r["id"] == "3-5")
    assert row["implemented"] is True
    assert row["engine"] == "httpx"


def test_g32_module_implemented():
    mod = diagnosis_service.catalog()
    row = next(r for r in mod if r["id"] == "3-2")
    assert row["implemented"] is True
    assert row["engine"] == "httpx"


def test_g36_module_implemented():
    mod = diagnosis_service.catalog()
    row = next(r for r in mod if r["id"] == "3-6")
    assert row["implemented"] is True
    assert row["engine"] == "httpx"


def test_g34_module_implemented():
    mod = diagnosis_service.catalog()
    row = next(r for r in mod if r["id"] == "3-4")
    assert row["implemented"] is True
    assert row["diagnosable"] is True
    assert row["engine"] == "httpx"


def test_g11_module_implemented():
    mod = diagnosis_service.catalog()
    row = next(r for r in mod if r["id"] == "1-1")
    assert row["implemented"] is True
    assert row["registered"] is True
    assert row["engine"] == "httpx+zap"


def test_g15_module_implemented():
    mod = diagnosis_service.catalog()
    row = next(r for r in mod if r["id"] == "1-5")
    assert row["implemented"] is True
    assert row["engine"] == "httpx+zap"


def test_g41_module_manual_diagnosis():
    mod = diagnosis_service.catalog()
    row = next(r for r in mod if r["id"] == "4-1")
    assert row["implemented"] is False
    assert row["status_label"] == "수동 진단"
    assert row["review_later"] is False
    assert row["diagnosable"] is False


def test_g42_module_manual_diagnosis():
    mod = diagnosis_service.catalog()
    row = next(r for r in mod if r["id"] == "4-2")
    assert row["implemented"] is False
    assert row["status_label"] == "수동 진단"
    assert row["review_later"] is False
    assert row["diagnosable"] is False


def test_g44_module_has_start_button_catalog():
    mod = diagnosis_service.catalog()
    row = next(r for r in mod if r["id"] == "4-4")
    assert row["review_later"] is False
    assert row["diagnosable"] is True
    assert row["status_label"] is None


def test_run_g15_with_options(tmp_path, monkeypatch):
    import yaml
    from diagnosis.context import DiagnosisContext
    from diagnosis.registry import get_module

    captured: list[DiagnosisContext] = []

    def fake_run(ctx):
        captured.append(ctx)
        from diagnosis.result import SectionReport, utc_now_iso

        return SectionReport(
            section_id="1-5",
            title="test",
            chapter=1,
            status="pass",
            implemented=True,
            checked_at=utc_now_iso(),
        )

    mod = get_module("1-5")
    monkeypatch.setattr(mod, "run", fake_run)

    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        yaml.safe_dump({"diagnosis_1_5": {"probe_mode": "sample", "zap_enabled": False}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("CONFIG_PATH", str(cfg))
    monkeypatch.setattr(diagnosis_service, "BACKEND_ROOT", tmp_path)

    diagnosis_service.run_section(
        "1-5",
        g15_options={"zap_enabled": True, "probe_mode": "full", "cors_enabled": False},
    )
    assert captured
    g15 = captured[0].raw_config["diagnosis_1_5"]
    assert g15["zap_enabled"] is True
    assert g15["probe_mode"] == "full"
    assert g15["cors_enabled"] is False


def test_run_g41_not_diagnosable():
    import pytest

    with pytest.raises(ValueError, match="not diagnosable"):
        diagnosis_service.run_section(
            "4-1",
            g41_options={"probe_mode": "full", "tamper_enabled": False, "max_endpoints": 100},
        )


def test_run_g22_with_options(tmp_path, monkeypatch):
    import yaml
    from diagnosis.context import DiagnosisContext
    from diagnosis.registry import get_module

    captured: list[DiagnosisContext] = []

    def fake_run(ctx):
        captured.append(ctx)
        from diagnosis.result import SectionReport, utc_now_iso

        return SectionReport(
            section_id="2-2",
            title="test",
            chapter=2,
            status="pass",
            implemented=True,
            checked_at=utc_now_iso(),
        )

    mod = get_module("2-2")
    monkeypatch.setattr(mod, "run", fake_run)

    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        yaml.safe_dump({"diagnosis_2_2": {"max_candidates": 99, "zap_enabled": True}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("CONFIG_PATH", str(cfg))
    monkeypatch.setattr(
        diagnosis_service,
        "BACKEND_ROOT",
        tmp_path,
    )

    diagnosis_service.run_section(
        "2-2",
        g22_options={"zap_enabled": False, "httpx_enabled": False, "max_candidates": 10},
    )
    assert captured
    g22 = captured[0].raw_config["diagnosis_2_2"]
    assert g22["zap_enabled"] is False
    assert g22["httpx_enabled"] is False
    assert g22["max_candidates"] == 10
