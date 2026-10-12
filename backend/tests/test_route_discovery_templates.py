"""Frontend route templates (/posts/{id}) are filled with the finding's own record id."""

import importlib.util
import sys
from pathlib import Path

import pytest

_DIR = Path(__file__).resolve().parents[1] / "screenshot" / "modules" / "1-1"


@pytest.fixture(scope="module")
def rd():
    # Sibling modules are imported by bare name (``from models import ...``) and
    # other screenshot modules use the same names, so load against a clean slate.
    shadowed = {name: sys.modules.pop(name) for name in ("models",) if name in sys.modules}
    sys.path.insert(0, str(_DIR))
    try:
        spec = importlib.util.spec_from_file_location("route_discovery_test", _DIR / "route_discovery.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(_DIR))
        sys.modules.pop("models", None)
        sys.modules.update(shadowed)
    return module


def test_both_placeholder_styles_are_templates(rd):
    assert rd._is_route_template("/posts/{id}")
    assert rd._is_route_template("/posts/:id/edit")
    assert not rd._is_route_template("/mypage")
    assert not rd._is_route_template("/")


def test_template_is_filled_with_the_record_id(rd):
    assert rd._fill_route_template("/posts/{id}", "62") == "/posts/62"
    assert rd._fill_route_template("/posts/:id/edit", 62) == "/posts/62/edit"


def test_record_ids_come_from_the_evidence_record(rd):
    case = type("Case", (), {})()
    case.exchange = type("Ex", (), {"response_text": 'HTTP/1.1 200\n\nBody:\n{"id": 62, "ownerId": 3, "title": "x"}'})()
    assert rd._resource_ids_from_evidence(case) == ["62", "3"]
