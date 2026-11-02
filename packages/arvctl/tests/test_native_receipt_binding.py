"""The native artifact receipt binds the tracked overlay bytes and the admitted digest.

A reviewer of the first public candidate found the receipt pinning overlay bytes
that were no longer in the tree (a stripped header line), which made the
"reproducible from this repository" claim false. This test fails whenever the
receipt and the tracked overlay disagree, or the receipt and the policy disagree.
"""
import hashlib
import json
from pathlib import Path

from arvyx_control import native_artifact_policy as policy

ROOT = Path(__file__).resolve().parents[3]
RECEIPT = ROOT / "frontends/arvyx/receipts/onboarding-v1-linux-x86_64.json"
OVERLAY = ROOT / "frontends/arvyx"


def _receipt() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def test_receipt_digest_is_the_admitted_onboarding_digest():
    receipt = _receipt()
    assert receipt["binary_sha256"] == policy.NATIVE_ONBOARDING_BINARY_SHA256
    assert receipt["manifest"]["binary_sha256"] == policy.NATIVE_ONBOARDING_BINARY_SHA256
    assert receipt["platform"] == "linux-x86_64"
    assert "onboarding-v1" in policy.admitted_capabilities(policy.NATIVE_ONBOARDING_BINARY_SHA256)


def test_receipt_records_executed_overlay_tests():
    manifest = _receipt()["manifest"]
    assert manifest["native_tests_executed"] is True
    assert manifest["native_test_count"] >= 16, "the overlay carries at least 16 unit tests"
    assert manifest["native_test_filter"] == "client::shell::amc_"


def test_receipt_overlay_inputs_are_the_tracked_overlay_bytes():
    recorded = _receipt()["manifest"]["overlay_input_sha256"]
    tracked = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in OVERLAY.iterdir()
        if path.is_file()
    }
    assert recorded == tracked, "the admitted binary was built from bytes that are not in this tree"
    for name, digest in recorded.items():
        if name.endswith(".rs"):
            assert _receipt()["manifest"]["client_overlay_sha256"][name] == digest
    assert _receipt()["manifest"]["patch_sha256"] == recorded["amc-native-mouse.patch"]
