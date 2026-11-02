from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "packages" / "arvctl" / "src"))

from arvyx_control.mcp_client_evidence import (  # noqa: E402
    ALLOWED_RESULT_KEYS,
    ALLOWED_TOP_LEVEL_KEYS,
    MAX_EVIDENCE_BYTES,
    validate_mcp_client_evidence,
)


def _valid_payload() -> dict:
    return {
        "schema_version": 1,
        "client": "python-mcp-sdk",
        "client_version": "1.29.0",
        "protocol_version": "2024-11-05",
        "checked_at": "2026-09-14T20:00:00Z",
        "git_head": "a" * 40,
        "git_tree": "b" * 40,
        "transport": "stdio",
        "command": "python -m arvyx_control.cli mcp --profile read-only --vault fixtures/x",
        "result": {
            "tools_list_ok": True,
            "recall_ok": True,
            "sources_returned": True,
            "private_paths_leaked": False,
        },
        "scan_scope": ["initialize", "tools/list", "memory.recall"],
        "capture_sha256": "c" * 64,
        "capture_bytes": 1234,
        "marker_set_sha256": "d" * 64,
        "notes": "Recorded by a local run.",
    }


class McpClientEvidenceShapeTests(unittest.TestCase):
    """The signed evidence file must be a closed, bounded shape.

    It is signed by a release principal and then hashed, attested and published, so an
    unknown key is a way to move arbitrary bytes into release assets, and an unbounded
    file is a way to move any amount of them. Both are refused before the file is read
    into memory.
    """

    def _write(self, directory: Path, payload: dict, name: str = "evidence.json") -> Path:
        path = directory / name
        path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        return path

    def test_a_complete_payload_validates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = validate_mcp_client_evidence(self._write(Path(tmp), _valid_payload()))
        self.assertEqual(result["errors"], [])
        self.assertTrue(result["ok"])

    def test_unknown_top_level_key_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload = _valid_payload()
            payload["extra_blob"] = "anything"
            result = validate_mcp_client_evidence(self._write(Path(tmp), payload))
        self.assertIn("unknown top-level key(s): extra_blob", result["errors"])
        self.assertFalse(result["ok"])

    def test_unknown_result_key_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload = _valid_payload()
            payload["result"]["extra"] = True
            result = validate_mcp_client_evidence(self._write(Path(tmp), payload))
        self.assertIn("unknown result key(s): extra", result["errors"])

    def test_oversized_file_is_refused_before_reading(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "huge.json"
            path.write_text(json.dumps(_valid_payload()) + " " * MAX_EVIDENCE_BYTES, encoding="utf-8")
            self.assertGreater(path.stat().st_size, MAX_EVIDENCE_BYTES)
            result = validate_mcp_client_evidence(path)
        self.assertFalse(result["ok"])
        self.assertIn("exceeds", result["errors"][0])

    def test_overlong_text_field_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload = _valid_payload()
            payload["notes"] = "n" * 2000
            result = validate_mcp_client_evidence(self._write(Path(tmp), payload))
        self.assertIn("notes must be at most 1024 characters", result["errors"])

    def test_a_nested_object_in_a_text_field_is_refused(self) -> None:
        # A length test guarded by `isinstance(value, str)` is skipped entirely for
        # an object, so nested keys and text would ride inside a signed artifact.
        for field in (
            "client",
            "client_version",
            "protocol_version",
            "command",
            "notes",
            "git_head",
            "git_tree",
        ):
            with self.subTest(field=field):
                with tempfile.TemporaryDirectory() as tmp:
                    payload = _valid_payload()
                    payload[field] = {"nested": "x" * 20000}
                    result = validate_mcp_client_evidence(self._write(Path(tmp), payload))
                self.assertIn(f"{field} must be a string", result["errors"])
                self.assertFalse(result["ok"])

    def test_a_null_optional_binding_is_treated_as_absent(self) -> None:
        # package-smoke generates self-attested evidence from a non-checkout
        # directory, so git_head/git_tree are null. Nested objects still fail.
        with tempfile.TemporaryDirectory() as tmp:
            payload = _valid_payload()
            payload["git_head"] = None
            payload["git_tree"] = None
            result = validate_mcp_client_evidence(self._write(Path(tmp), payload))
        self.assertEqual(result["errors"], [])
        self.assertTrue(result["ok"])

    def test_an_overlong_timestamp_is_refused(self) -> None:
        # `datetime.fromisoformat` accepts an arbitrary number of fractional digits,
        # so a timestamp alone does not bound the field.
        with tempfile.TemporaryDirectory() as tmp:
            payload = _valid_payload()
            payload["checked_at"] = "2026-09-14T20:00:00." + "0" * 20000 + "Z"
            result = validate_mcp_client_evidence(self._write(Path(tmp), payload))
        self.assertIn("checked_at must be at most 64 characters", result["errors"])
        self.assertFalse(result["ok"])

    def test_malformed_capture_digest_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload = _valid_payload()
            payload["capture_sha256"] = "not-a-digest"
            result = validate_mcp_client_evidence(self._write(Path(tmp), payload))
        self.assertIn("capture_sha256 must be a sha256 hex digest", result["errors"])

    def test_malformed_scan_scope_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload = _valid_payload()
            payload["scan_scope"] = []
            result = validate_mcp_client_evidence(self._write(Path(tmp), payload))
        self.assertIn("scan_scope must be a list of 1 to 8 entries", result["errors"])

    def test_the_public_example_still_validates(self) -> None:
        example = ROOT / "examples" / "mcp-clients" / "real-client-evidence.example.json"
        result = validate_mcp_client_evidence(example)
        for error in result["errors"]:
            self.assertNotIn("unknown", error)
            self.assertNotIn("must be at most", error)

    def test_every_allowed_key_is_named_and_bounded(self) -> None:
        # A guard against silently widening the schema: every allowed key must be either
        # a required field, a documented optional one, or the attestation block.
        self.assertEqual(
            ALLOWED_TOP_LEVEL_KEYS,
            {
                "schema_version",
                "client",
                "client_version",
                "client_provenance",
                "protocol_version",
                "checked_at",
                "git_head",
                "git_tree",
                "transport",
                "command",
                "result",
                "notes",
                "capture_sha256",
                "capture_bytes",
                "scan_scope",
                "marker_set_sha256",
                "attestation",
            },
        )
        self.assertEqual(
            ALLOWED_RESULT_KEYS,
            {"tools_list_ok", "recall_ok", "sources_returned", "private_paths_leaked"},
        )


if __name__ == "__main__":
    unittest.main()
