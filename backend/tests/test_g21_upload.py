from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace


MODULE_DIR = Path(__file__).resolve().parents[1] / "diagnosis" / "modules" / "2-1"
BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


def load_g21_module(name: str):
    path = MODULE_DIR / f"{name}.py"
    mod_name = f"test_g21_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_path_exposure_detects_upload_url_only_on_success():
    rules = load_g21_module("rules")

    body = '{"imageUrl":"https://cdn.example.test/uploads/post/argus-probe.png"}'
    issue = rules.detect_path_exposure(body, "application/json", {})
    assert issue is not None
    assert issue.kind == "public_file_url"
    assert rules.upload_accepted(201, body) is True
    assert rules.upload_accepted(415, body) is False


def test_probe_marks_disallowed_upload_as_true_positive():
    probes = load_g21_module("probes")
    payloads = load_g21_module("payloads")
    multipart = load_g21_module("multipart")
    rules = load_g21_module("rules")

    class AcceptingTransport:
        def request(self, method, url, headers, body, timeout=15.0):
            return SimpleNamespace(
                status=201,
                body=b'{"fileUrl":"https://cdn.example.test/uploads/post/argus-shell.php"}',
                headers={"content-type": "application/json"},
                error=None,
            )

    target = SimpleNamespace(
        file_field="images",
        extra_fields={},
        method="POST",
        url="https://app.example.test/api/v1/posts",
        label="POST https://app.example.test/api/v1/posts",
        endpoint_id="https://app.example.test:POST:/api/v1/posts",
        source="config",
        path="/api/v1/posts",
        business_role="user",
        feature_key="posts_images",
        feature_label="Posts / images",
    )
    payload = payloads.UploadPayload(
        payload_id="php-direct",
        filename="argus-shell.php",
        content=b"<?php echo 1; ?>",
        content_type="application/x-php",
        technique="direct_extension",
        ext="php",
        category="server_script",
        expect_reject=True,
    )

    findings, stats = probes.run_upload_probes(
        [target],
        [payload],
        transport=AcceptingTransport(),
        engine="httpx",
        rules_mod=rules,
        multipart_mod=multipart,
    )

    assert stats["extension_bypass_issues"] == 1
    assert stats["path_exposure_issues"] == 1
    assert any(f.evidence["finding_type"] == "true_positive" for f in findings)
    assert {f.evidence["business_role"] for f in findings} == {"user"}
