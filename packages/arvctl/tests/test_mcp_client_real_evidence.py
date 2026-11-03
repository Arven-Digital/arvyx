from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import os
import unittest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "packages" / "arvctl" / "src"))


def _load_producer():
    path = ROOT / "scripts" / "mcp_client_real_evidence.py"
    spec = importlib.util.spec_from_file_location("mcp_client_real_evidence", path)
    assert spec is not None and spec.loader is not None, f"cannot load {path}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class McpClientEvidenceProducerTests(unittest.TestCase):
    """The leak tripwire must be measured, not asserted, and the recorded command
    must describe the argument that really ran.

    An earlier revision wrote ``private_paths_leaked: false`` as a constant, which
    silently disabled the gate's only leak check on the one evidence file that
    carries a release-grade signature. These tests fail if that returns.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.producer = _load_producer()
        cls.vault = ROOT / "fixtures" / "synthetic-vault"

    def setUp(self):
        from unittest.mock import patch
        provenance = {"kind": "third-party-sdk", "distribution": "mcp",
                      "version": "synthetic-unit-version", "implementation_sha256": "a" * 64}
        self.synthetic_provenance = provenance
        patcher = patch.object(self.producer, "_sdk_provenance", return_value=provenance)
        patcher.start()
        self.addCleanup(patcher.stop)

    # ---- the tripwire itself ----

    def test_clean_capture_reports_no_markers(self) -> None:
        self.assertEqual(self.producer.scan_for_private_markers('{"answer": "ok"}'), [])

    def test_operator_path_is_detected(self) -> None:
        found = self.producer.scan_for_private_markers('{"vault": "/home/runner/x"}')
        self.assertIn("/home/", found)

    def test_credential_shapes_are_detected(self) -> None:
        found = self.producer.scan_for_private_markers("password=1 api_key=2")
        self.assertIn("password", found)
        self.assertIn("api_key", found)

    # ---- the tripwire is wired into what gets written and what gets returned ----

    def _fake_client(self, *, leaked: bool):
        async def fake(**_kwargs):
            captured = json.dumps(
                {
                    "initialize": {"protocolVersion": "2024-11-05"},
                    "tools": {"tools": [{"name": "memory.recall"}]},
                    "recall": {"structuredContent": {"answer": "ok", "sources": [{"path": "x"}]}},
                },
                sort_keys=True,
            )
            return {
                "tools_list_ok": True,
                "recall_ok": True,
                "sources_returned": True,
                "private_paths_leaked": leaked,
                "leaked_markers": ["/home/"] if leaked else [],
                "protocol_version": "2024-11-05",
                "captured": captured,
                "client_provenance": self.synthetic_provenance,
            }

        return fake

    def _produce_with(self, *, leaked: bool) -> tuple[int, dict]:
        original = getattr(self.producer, "_run_client")
        setattr(self.producer, "_run_client", self._fake_client(leaked=leaked))
        try:
            with tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp) / "evidence.json"
                code = self.producer._produce(
                    repo=ROOT, vault=self.vault, output=out, json_output=False
                )
                return code, json.loads(out.read_text(encoding="utf-8"))
        finally:
            setattr(self.producer, "_run_client", original)

    def test_a_leaking_run_is_written_as_leaked_and_exits_nonzero(self) -> None:
        code, payload = self._produce_with(leaked=True)
        self.assertEqual(code, 1)
        self.assertIs(payload["result"]["private_paths_leaked"], True)

    def test_a_clean_run_is_written_as_clean_and_exits_zero(self) -> None:
        code, payload = self._produce_with(leaked=False)
        self.assertEqual(code, 0)
        self.assertIs(payload["result"]["private_paths_leaked"], False)

    # ---- the recorded command matches the launched one ----

    def test_launch_plan_executes_and_records_the_same_vault_argument(self) -> None:
        plan = self.producer.launch_plan(repo=ROOT, vault=self.vault)
        argv = list(plan["argv"])
        self.assertEqual(argv[argv.index("--vault") + 1], plan["vault_arg"])
        self.assertFalse(plan["outside_repo"])
        self.assertNotIn(str(ROOT), plan["vault_arg"])
        self.assertTrue(str(plan["display"]).endswith(f"--vault {plan['vault_arg']}"))

    def test_launch_plan_keeps_a_vault_outside_the_repository_absolute(self) -> None:
        outside = Path(tempfile.gettempdir()) / "amc-outside-vault"
        plan = self.producer.launch_plan(repo=ROOT, vault=outside)
        self.assertTrue(plan["outside_repo"])
        self.assertEqual(plan["vault_arg"], outside.as_posix())
        argv = list(plan["argv"])
        self.assertEqual(argv[argv.index("--vault") + 1], outside.as_posix())

    def test_producer_records_measured_provenance_not_label_authority(self) -> None:
        code, payload = self._produce_with(leaked=False)
        self.assertEqual(code, 0)
        self.assertEqual(payload["client_provenance"], self.synthetic_provenance)
        self.assertEqual(payload["client_version"], "synthetic-unit-version")

    # ---- what actually gets launched, and what the scan sees ----

    def _fake_sdk(self, *, init_payload: dict, captured: dict):
        class FakeParams:
            def __init__(self, **kwargs):
                self.command = kwargs.get("command")
                self.args = list(kwargs.get("args") or [])
                self.env = dict(kwargs.get("env") or {})
                self.cwd = kwargs.get("cwd")

        class FakeInit:
            protocol_version = "2024-11-05"

            def model_dump(self, mode="json", *, by_alias=False):
                assert mode == "json" and by_alias is True
                return init_payload

        class FakeTools:
            def __init__(self):
                self.tools = [type("Tool", (), {"name": "memory.recall"})()]

            def model_dump(self, mode="json", *, by_alias=False):
                assert mode == "json" and by_alias is True
                return {"tools": [{"name": "memory.recall"}]}

        class FakeCall:
            is_error = False
            structured_content = {
                "answer": "ok",
                "sources": [{"path": "fixtures/synthetic-vault/notes.md"}],
            }

            def model_dump(self, mode="json", *, by_alias=False):
                assert mode == "json" and by_alias is True
                return {"structuredContent": self.structured_content, "isError": self.is_error}

        class FakeSession:
            def __init__(self, read, write):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def initialize(self):
                return FakeInit()

            async def list_tools(self):
                return FakeTools()

            async def call_tool(self, name, arguments):
                return FakeCall()

        def stdio_client(params):
            captured["params"] = params

            class FakeStdio:
                async def __aenter__(self):
                    return (object(), object())

                async def __aexit__(self, *exc):
                    return False

            return FakeStdio()

        # The producer unpacks this as ClientSession, StdioServerParameters, stdio_client.
        return FakeSession, FakeParams, stdio_client

    def _run_with_fake_sdk(self, *, init_payload: dict):
        captured: dict = {}
        original = getattr(self.producer, "_require_sdk")
        setattr(
            self.producer,
            "_require_sdk",
            lambda: self._fake_sdk(init_payload=init_payload, captured=captured),
        )
        try:
            result = asyncio.run(self.producer._run_client(repo=ROOT, vault=self.vault))
        finally:
            setattr(self.producer, "_require_sdk", original)
        return result, captured["params"]

    def test_run_client_launches_exactly_the_recorded_plan(self) -> None:
        result, params = self._run_with_fake_sdk(init_payload={"protocolVersion": "2024-11-05"})
        plan = self.producer.launch_plan(repo=ROOT, vault=self.vault)
        self.assertEqual(params.args, [str(part) for part in plan["argv"]])
        self.assertEqual(params.cwd, str(plan["cwd"]))
        self.assertEqual(params.command, sys.executable)
        # Read regardless of a missing serverInfo, and the captured traffic is clean.
        self.assertEqual(result["protocol_version"], "2024-11-05")
        self.assertIs(result["private_paths_leaked"], False)

    def test_run_client_fails_the_scan_on_an_absolute_path_in_the_handshake(self) -> None:
        result, _ = self._run_with_fake_sdk(
            init_payload={"serverInfo": {"name": "/home/operator/private"}}
        )
        self.assertIs(result["private_paths_leaked"], True)
        self.assertIn("/home/", result["leaked_markers"])

    @unittest.skipUnless(os.name == 'posix', 'POSIX mode bits and path forms')
    def test_run_client_fails_the_scan_on_an_absolute_repository_path(self) -> None:
        result, _ = self._run_with_fake_sdk(init_payload={"repo": str(ROOT)})
        self.assertIs(result["private_paths_leaked"], True)
        self.assertIn(ROOT.as_posix(), result["leaked_markers"])

    # ---- the measurement can be replayed from a kept capture ----

    def _produce_with_capture(self) -> tuple[int, dict, Path, Path, tempfile.TemporaryDirectory]:
        original = getattr(self.producer, "_run_client")
        setattr(self.producer, "_run_client", self._fake_client(leaked=False))
        tmp = tempfile.TemporaryDirectory()
        try:
            out = Path(tmp.name) / "evidence.json"
            capture = Path(tmp.name) / "capture.json"
            code = self.producer._produce(
                repo=ROOT,
                vault=self.vault,
                output=out,
                json_output=False,
                capture_out=capture,
            )
        finally:
            setattr(self.producer, "_run_client", original)
        return code, json.loads(out.read_text(encoding="utf-8")), out, capture, tmp

    @unittest.skipUnless(os.name == 'posix', 'POSIX mode bits and path forms')
    def test_produce_records_the_measurement_and_keeps_a_private_capture(self) -> None:
        code, payload, out, capture, tmp = self._produce_with_capture()
        try:
            self.assertEqual(code, 0)
            self.assertEqual(payload["scan_scope"], list(self.producer.SCAN_SCOPE))
            digest, size = self.producer.capture_digest(capture.read_text(encoding="utf-8"))
            self.assertEqual(payload["capture_sha256"], digest)
            self.assertEqual(payload["capture_bytes"], size)
            self.assertEqual(oct(capture.stat().st_mode)[-3:], "600")
            # The record binds the measurement without carrying the traffic or the markers.
            recorded = out.read_text(encoding="utf-8")
            for marker in self.producer.PRIVATE_MARKERS:
                self.assertNotIn(marker, recorded)
        finally:
            tmp.cleanup()

    def _replay(
        self,
        out: Path,
        capture: Path,
        *,
        repo: Path | None = None,
        vault: Path | None = None,
    ):
        # Replay needs the producer's local path context; the producer counts an
        # echo of those absolute paths as a leak.
        return self.producer.verify_capture(
            evidence=out,
            capture=capture,
            repo=repo or ROOT,
            vault=vault or self.vault,
        )

    def _rewrite(self, out: Path, payload: dict) -> None:
        out.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")

    def test_verify_capture_replays_clean_and_refuses_a_tampered_capture(self) -> None:
        code, _payload, out, capture, tmp = self._produce_with_capture()
        try:
            replayed, errors, details = self._replay(out, capture)
            self.assertTrue(replayed, errors)
            self.assertEqual(details["leaked_markers"], [])
            capture.write_text(capture.read_text(encoding="utf-8") + "tampered", encoding="utf-8")
            replayed, errors, _ = self._replay(out, capture)
            self.assertFalse(replayed)
            self.assertIn("does not hash to the digest recorded", " ".join(errors))
        finally:
            tmp.cleanup()

    def test_verify_capture_fails_closed_without_a_recorded_digest(self) -> None:
        code, payload, out, capture, tmp = self._produce_with_capture()
        try:
            payload.pop("capture_sha256")
            self._rewrite(out, payload)
            replayed, errors, _ = self._replay(out, capture)
            self.assertFalse(replayed)
            self.assertIn("evidence records no capture_sha256, so nothing can be replayed", errors)
        finally:
            tmp.cleanup()

    def test_verify_capture_requires_the_whole_measurement_record(self) -> None:
        # A digest alone can be "replayed" against a different scan configuration,
        # so every field that names the measurement must be present.
        missing = {
            "capture_bytes": "capture_bytes",
            "marker_set_sha256": "marker_set_sha256",
            "scan_scope": "scan_scope",
        }
        for field, expected in missing.items():
            with self.subTest(field=field):
                code, payload, out, capture, tmp = self._produce_with_capture()
                try:
                    payload.pop(field)
                    self._rewrite(out, payload)
                    replayed, errors, _ = self._replay(out, capture)
                    self.assertFalse(replayed)
                    self.assertTrue(any(expected in error for error in errors), errors)
                finally:
                    tmp.cleanup()

    def test_verify_capture_refuses_a_foreign_marker_set(self) -> None:
        code, payload, out, capture, tmp = self._produce_with_capture()
        try:
            payload["marker_set_sha256"] = "d" * 64
            self._rewrite(out, payload)
            replayed, errors, _ = self._replay(out, capture)
            self.assertFalse(replayed)
            self.assertIn(
                "marker_set_sha256 does not match the marker set this replay scans with", errors
            )
        finally:
            tmp.cleanup()

    def test_verify_capture_refuses_an_unsupported_scope(self) -> None:
        code, payload, out, capture, tmp = self._produce_with_capture()
        try:
            payload["scan_scope"] = ["initialize"]
            self._rewrite(out, payload)
            replayed, errors, _ = self._replay(out, capture)
            self.assertFalse(replayed)
            self.assertIn(
                "scan_scope must record the supported scope "
                f"({', '.join(self.producer.SCAN_SCOPE)}), not ['initialize']",
                errors,
            )
        finally:
            tmp.cleanup()

    def test_verify_capture_applies_the_producers_path_context(self) -> None:
        # The marker set alone misses an absolute path that carries no marker, which
        # is exactly why replay must share the producer's path-context scan.
        # This is lexical scan context, not an on-disk checkout. A temp path can
        # already contain a generic marker (e.g. /home/) on legitimate runners,
        # accidentally making this test unable to isolate the context check.
        fake_repo = Path('/synthetic-capture-context/repository')
        code, payload, out, capture, tmp = self._produce_with_capture()
        try:
            dirty = json.dumps({"echo": fake_repo.as_posix()}, sort_keys=True)
            self.assertEqual(self.producer.scan_for_private_markers(dirty), [])
            digest, size = self.producer.capture_digest(dirty)
            payload["capture_sha256"] = digest
            payload["capture_bytes"] = size
            self._rewrite(out, payload)
            capture.write_text(dirty, encoding="utf-8")
            replayed, errors, details = self._replay(out, capture, repo=fake_repo)
            self.assertFalse(replayed)
            self.assertIn(fake_repo.as_posix(), details["leaked_markers"])
        finally:
            tmp.cleanup()

    @unittest.skipUnless(os.name == 'posix', 'POSIX mode bits and path forms')
    def test_the_capture_is_private_before_any_bytes_are_visible(self) -> None:
        # `write_text` + `chmod` leaves a world-readable window on a 022 umask. The
        # mode must be 0600 on the file that becomes the capture, not after.
        import os as _os
        import shutil
        import stat as _stat

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "nested" / "capture.json"
            seen: dict = {}
            original_replace = _os.replace

            def spy(source, destination):
                seen["mode_at_replace"] = _stat.S_IMODE(_os.stat(source).st_mode)
                seen["destination_existed"] = Path(destination).exists()
                return original_replace(source, destination)

            previous_umask = _os.umask(0o022)
            _os.replace = spy
            try:
                self.producer.write_private_file(target, '{"answer": "ok"}')
            finally:
                _os.replace = original_replace
                _os.umask(previous_umask)

            self.assertEqual(seen.get("mode_at_replace"), 0o600)
            self.assertFalse(seen.get("destination_existed"))
            self.assertEqual(oct(_stat.S_IMODE(target.stat().st_mode))[-3:], "600")
            self.assertEqual(target.read_text(encoding="utf-8"), '{"answer": "ok"}')
            shutil.rmtree(tmp, ignore_errors=True)

    def test_total_budget_exceeds_a_single_call_budget(self) -> None:
        self.assertGreater(
            self.producer.TOTAL_TIMEOUT_SECONDS, self.producer.PER_CALL_TIMEOUT_SECONDS
        )

    def test_notes_name_the_workflow_instead_of_claiming_a_release_run(self) -> None:
        import os

        original_workflow = os.environ.get("GITHUB_WORKFLOW")
        original_ref_type = os.environ.get("GITHUB_REF_TYPE")
        os.environ["GITHUB_WORKFLOW"] = "CI"
        os.environ["GITHUB_REF_TYPE"] = "branch"
        try:
            notes = self.producer._notes()
        finally:
            for key, value in (
                ("GITHUB_WORKFLOW", original_workflow),
                ("GITHUB_REF_TYPE", original_ref_type),
            ):
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        self.assertIn("'CI'", notes)
        self.assertIn("ref_type=branch", notes)
        self.assertNotIn("release pipeline", notes)


if __name__ == "__main__":
    unittest.main()
