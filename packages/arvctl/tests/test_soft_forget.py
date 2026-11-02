from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from arvyx_control.vault import init_vault


class SoftForgetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.vault = Path(self.tmp.name) / "vault"
        init_vault(self.vault)
        self.source_path = "projects/demo-agent/STATUS.md"
        self.source = self.vault / self.source_path
        self.original = self.source.read_bytes()

    def _forget(self, **overrides):
        from arvyx_control.forget import soft_forget

        kwargs = {
            "vault": self.vault,
            "project": "demo-agent",
            "source_path": self.source_path,
            "reason_category": "superseded",
            "batch_id": "batch-2026-09-09-001",
            "actor": "operator",
            "idempotency_key": "forget-operation-0001",
            "dry_run": False,
        }
        kwargs.update(overrides)
        return soft_forget(**kwargs)

    def test_dry_run_has_no_side_effect_and_reports_exact_target(self) -> None:
        result = self._forget(dry_run=True)
        self.assertEqual(result.status, "dry-run")
        self.assertEqual(result.source_path, self.source_path)
        self.assertTrue(self.source.is_file())
        self.assertEqual(list((self.vault / "excluded" / "forgotten").glob("**/*")), [])

    def test_forget_archives_original_and_tombstone_and_excludes_recall(self) -> None:
        from arvyx_control.recall import context_pack, recall

        before = recall("current operational status", self.vault, project="demo-agent")
        self.assertIn(self.source_path, [source.path for source in before.sources])
        result = self._forget()
        self.assertEqual(result.status, "forgotten")
        self.assertFalse(self.source.exists())
        archive = self.vault / result.archive_path
        tombstone = self.vault / result.tombstone_path
        self.assertEqual(archive.read_bytes(), self.original)
        metadata = json.loads(tombstone.read_text(encoding="utf-8"))
        self.assertEqual(metadata["source_path"], self.source_path)
        self.assertEqual(metadata["reason_category"], "superseded")
        self.assertEqual(metadata["batch_id"], "batch-2026-09-09-001")
        self.assertEqual(metadata["actor"], "operator")
        self.assertNotIn(self.source_path, [source.path for source in recall("current operational status", self.vault, project="demo-agent").sources])
        self.assertNotIn(self.source_path, [source.path for source in context_pack("current operational status", self.vault, project="demo-agent").sources])

    def test_idempotent_replay_returns_same_receipt_and_conflict_is_rejected(self) -> None:
        first = self._forget()
        second = self._forget()
        self.assertEqual(second.to_dict(), first.to_dict())
        with self.assertRaisesRegex(ValueError, "idempotency key.*different request"):
            self._forget(reason_category="incorrect")

    def _completion_barrier_failure_and_replay(self, *, restore: bool) -> None:
        # Source-only regression: NOT_EXECUTED under static authorization.
        from unittest.mock import call, patch
        import arvyx_control.forget as forget_module
        import arvyx_control.forget_guard as guard_module

        if restore:
            forgotten = self._forget()
            key = "restore-visible-receipt-0001"
            def invoke():
                return forget_module.restore_forgotten(
                    self.vault, forgotten.tombstone_path, "operator", key,
                )
        else:
            key = "forget-operation-0001"
            invoke = self._forget
        receipt = forget_module._operation_path(self.vault, key)
        actual_sync = forget_module._fsync_dir
        failures = []

        def fail_after_receipt_rename(directory):
            if directory == receipt.parent and receipt.exists():
                failures.append(directory)
                raise OSError("synthetic receipt namespace barrier failure")
            return actual_sync(directory)

        with patch.object(forget_module, "_fsync_dir", side_effect=fail_after_receipt_rename):
            with self.assertRaisesRegex(OSError, "receipt namespace barrier failure"):
                invoke()
        self.assertEqual(failures, [receipt.parent])
        expected = json.loads(receipt.read_text(encoding="utf-8"))["result"]
        self.assertEqual(self.source.exists(), restore)
        # A snapshot or unrelated mutation may not trust visible completion
        # when its namespace barrier is still failing.
        with patch.object(guard_module, "fsync_directory", side_effect=OSError("still failing")) as guard_sync:
            with self.assertRaisesRegex(RuntimeError, "mutation/snapshot refused"):
                guard_module.assert_copyable_forget_operations(self.vault)
            guard_sync.assert_called_once_with(receipt.parent)
        with (
            patch.object(forget_module, "_fsync_dir", wraps=actual_sync) as replay_sync,
            patch.object(forget_module, "_publish_bound_file", side_effect=AssertionError("must not republish")),
        ):
            self.assertEqual(invoke().to_dict(), expected)
            if restore:
                self.assertEqual(replay_sync.call_args_list, [call(receipt.parent), call(self.source.parent)])
                intent=json.loads(receipt.with_suffix('.intent.json').read_text())
                self.assertFalse((self.vault / intent['stage_path']).exists())
                self.assertEqual(self.source.stat().st_nlink, 1)
            else:
                replay_sync.assert_called_once_with(receipt.parent)
        # Even a legacy completed receipt without an intent must repeat the
        # read-side barrier; the guard only enumerates retained intents.
        receipt.with_suffix(".intent.json").unlink()
        with patch.object(forget_module, "_fsync_dir", side_effect=OSError("legacy barrier")):
            with self.assertRaisesRegex(OSError, "legacy barrier"):
                invoke()

    def test_forget_visible_receipt_requires_durable_replay(self) -> None:
        self._completion_barrier_failure_and_replay(restore=False)

    def test_restore_visible_receipt_requires_durable_replay(self) -> None:
        self._completion_barrier_failure_and_replay(restore=True)

    def test_requires_exact_curated_source_path(self) -> None:
        for invalid in ("STATUS.md", "projects/demo-agent/STATUS", "projects/demo-agent/status.md"):
            with self.subTest(invalid=invalid), self.assertRaises((ValueError, FileNotFoundError)):
                self._forget(source_path=invalid, idempotency_key=f"key-{invalid}")
        self.assertTrue(self.source.exists())

    def test_rejects_non_curated_lanes_cross_project_and_traversal(self) -> None:
        invalid = (
            "projects/demo-agent/pending/x.md",
            "projects/other/STATUS.md",
            "projects/demo-agent/../other/STATUS.md",
            "../../etc/passwd",
            "/etc/passwd",
            "projects\\demo-agent\\STATUS.md",
        )
        for index, source_path in enumerate(invalid):
            with self.subTest(source_path=source_path), self.assertRaises((ValueError, FileNotFoundError)):
                self._forget(source_path=source_path, idempotency_key=f"negative-{index}-0000")
        self.assertTrue(self.source.exists())

    def test_reason_batch_actor_and_idempotency_are_required_and_validated(self) -> None:
        cases = (
            ({"reason_category": ""}, "reason category"),
            ({"reason_category": "free text"}, "reason category"),
            ({"batch_id": ""}, "batch_id"),
            ({"actor": ""}, "actor"),
            ({"idempotency_key": "short"}, "idempotency_key"),
        )
        for overrides, message in cases:
            with self.subTest(overrides=overrides), self.assertRaisesRegex(ValueError, message):
                self._forget(**overrides)
        self.assertTrue(self.source.exists())

    def test_restore_is_safe_idempotent_and_refuses_overwrite(self) -> None:
        from arvyx_control.forget import restore_forgotten

        forgotten = self._forget()
        restored = restore_forgotten(
            vault=self.vault,
            tombstone_path=forgotten.tombstone_path,
            actor="operator",
            idempotency_key="restore-operation-0001",
        )
        self.assertEqual(restored.status, "restored")
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertEqual(
            restore_forgotten(self.vault, forgotten.tombstone_path, "operator", "restore-operation-0001").to_dict(),
            restored.to_dict(),
        )
        self.source.write_text("changed", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "refusing unrelated existing publication target"):
            restore_forgotten(self.vault, forgotten.tombstone_path, "operator", "restore-operation-0002")
        self.assertEqual(self.source.read_text(encoding="utf-8"), "changed")

    def test_restore_receipt_failure_recovers_same_key_but_preserves_unrelated_target(self) -> None:
        from unittest.mock import call, patch
        import arvyx_control.forget as forget_module

        forgotten = self._forget()
        key = "restore-receipt-failure-0001"
        receipt = forget_module._operation_path(self.vault, key)
        original_json = forget_module._atomic_json

        def fail_receipt(path, payload):
            if path == receipt:
                raise OSError("completion receipt failure")
            return original_json(path, payload)

        with patch.object(forget_module, "_atomic_json", side_effect=fail_receipt):
            with self.assertRaises(OSError):
                forget_module.restore_forgotten(self.vault, forgotten.tombstone_path, "operator", key)
        self.assertFalse(receipt.exists())
        self.assertTrue(receipt.with_suffix(".intent.json").exists())
        self.assertEqual(self.source.read_bytes(), self.original)
        # Replace the published inode with unrelated, byte-identical content.
        self.source.unlink()
        self.source.write_bytes(self.original)
        unrelated_inode = self.source.stat().st_ino
        with self.assertRaisesRegex(ValueError, "refusing unrelated existing publication target"):
            forget_module.restore_forgotten(self.vault, forgotten.tombstone_path, "operator", key)
        self.assertEqual(self.source.stat().st_ino, unrelated_inode)
        self.assertEqual(self.source.read_bytes(), self.original)
        # Removing only the unrelated target lets the retained witness recover.
        self.source.unlink()
        recovered = forget_module.restore_forgotten(self.vault, forgotten.tombstone_path, "operator", key)
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertEqual(
            forget_module.restore_forgotten(self.vault, forgotten.tombstone_path, "operator", key).to_dict(),
            recovered.to_dict(),
        )

    def test_cli_api_and_mcp_surfaces(self) -> None:
        from arvyx_control.api import handle_api_request
        from arvyx_control.auth import issue_token
        from arvyx_control.cli import main
        from arvyx_control.mcp import handle_request

        dry_run_code = main([
            "memory", "forget", self.source_path, "--project", "demo-agent", "--vault", str(self.vault),
            "--reason-category", "superseded", "--batch-id", "cli-batch-0001", "--by", "operator",
            "--idempotency-key", "cli-forget-operation-0001", "--dry-run", "--json",
        ])
        self.assertEqual(dry_run_code, 0)
        self.assertTrue(self.source.exists())

        state = self.vault / "events.jsonl"
        denied = handle_api_request("POST", "/memory/forget", {
            "project": "demo-agent", "source_path": self.source_path, "reason_category": "superseded",
            "batch_id": "api-batch-0001", "actor": "spoof", "idempotency_key": "api-forget-operation-0001",
        }, vault=self.vault, state=state)
        self.assertEqual(denied.status, 401)

        curator = issue_token(self.vault, "demobot", scopes=["memory.curate"])
        bound = handle_api_request("POST", "/memory/forget", {
            "project": "demo-agent", "source_path": self.source_path, "reason_category": "superseded",
            "batch_id": "api-bound-batch-0001", "actor": "spoof", "idempotency_key": "api-bound-forget-0001",
            "dry_run": True,
        }, vault=self.vault, state=state, authorization=f"Bearer {curator.token}")
        self.assertEqual(bound.status, 200)
        self.assertEqual(bound.body["actor"], "demobot")

        response = handle_api_request("POST", "/memory/forget", {
            "project": "demo-agent", "source_path": self.source_path, "reason_category": "superseded",
            "batch_id": "api-batch-0001", "actor": "operator", "idempotency_key": "api-forget-operation-0001",
            "dry_run": True,
        }, vault=self.vault, state=state, allow_unauthenticated_demo=True)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["status"], "dry-run")

        listed = handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, self.vault, state=state, allowed_tools={"memory.forget"})
        schema = listed["result"]["tools"][0]["inputSchema"]
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["reason_category"]["enum"], ["incorrect", "superseded", "privacy", "retention", "other"])
        called = handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "memory.forget", "arguments": {
            "project": "demo-agent", "source_path": self.source_path, "reason_category": "superseded",
            "batch_id": "mcp-batch-0001", "actor": "spoof", "idempotency_key": "mcp-forget-operation-0001", "dry_run": True,
        }}}, self.vault, state=state, allowed_tools={"memory.forget"}, actor="demobot")
        self.assertEqual(called["result"]["structuredContent"]["actor"], "demobot")


    def test_forget_retains_intent_when_tombstone_write_fails_and_resumes(self) -> None:
        import arvyx_control.forget as forget_module

        original = forget_module._atomic_json
        calls = {"n": 0}

        def failing(path, payload):
            if str(path).endswith(".tombstone.json"):
                calls["n"] += 1
                raise OSError("simulated tombstone write failure")
            return original(path, payload)

        forget_module._atomic_json = failing
        self.addCleanup(setattr, forget_module, "_atomic_json", original)
        with self.assertRaises(OSError):
            self._forget()
        self.assertEqual(calls["n"], 1)
        # Ordinary failure retains the archive, intent and staged inode witness.
        self.assertEqual(self.source.read_bytes(), self.original)
        operation = forget_module._operation_path(self.vault, "forget-operation-0001")
        self.assertFalse(operation.exists())
        intent_path = operation.with_suffix(".intent.json")
        intent = json.loads(intent_path.read_text(encoding="utf-8"))
        archive = self.vault / intent["publication_path"]
        witness = self.vault / intent["stage_path"]
        self.assertEqual(archive.read_bytes(), self.original)
        self.assertTrue(archive.samefile(witness))
        forget_module._atomic_json = original
        resumed = self._forget()
        self.assertFalse(self.source.exists())
        self.assertEqual(resumed.archive_path, intent["publication_path"])
        self.assertTrue(archive.samefile(witness))
        self.assertEqual(self._forget().to_dict(), resumed.to_dict())

    def test_restore_rejects_tampered_archive_hash_mismatch(self) -> None:
        from arvyx_control.forget import restore_forgotten

        forgotten = self._forget()
        archive = self.vault / forgotten.archive_path
        archive.write_bytes(self.original + b"tampered")
        with self.assertRaisesRegex(ValueError, "checksum does not match"):
            restore_forgotten(self.vault, forgotten.tombstone_path, "operator", "restore-tamper-00001")
        self.assertFalse(self.source.exists())

    def test_recall_excludes_forgotten_file_even_when_archive_corrupted(self) -> None:
        from arvyx_control.recall import context_pack, recall

        forgotten = self._forget()
        (self.vault / forgotten.archive_path).write_bytes(b"corrupted")
        for query in (recall, context_pack):
            sources = [source.path for source in query("current operational status", self.vault, project="demo-agent").sources]
            self.assertNotIn(self.source_path, sources)

    def test_forget_receipt_failure_after_source_removal_resumes_cleanly(self) -> None:
        # Archive and tombstone are durable, source removed, receipt absent.
        # A replay of the same key finishes the forget.
        import arvyx_control.forget as forget_module

        original = forget_module._atomic_json

        def failing(path, payload):
            if path == forget_module._operation_path(self.vault, "forget-operation-0001"):
                raise OSError("simulated crash before receipt")
            return original(path, payload)

        forget_module._atomic_json = failing
        try:
            with self.assertRaises(OSError):
                self._forget()
        finally:
            forget_module._atomic_json = original
        # The failure happened after the source was already removed (receipt is
        # last), so state must be: gone source, recoverable archive+tombstone.
        self.assertFalse(self.source.exists())
        archive_dir = self.vault / "excluded" / "forgotten" / "batch-2026-09-09-001"
        archives = sorted(archive_dir.glob("*.original"))
        tombstones = sorted(archive_dir.glob("*.tombstone.json"))
        self.assertEqual(len(archives), 1)
        self.assertEqual(len(tombstones), 1)
        self.assertEqual(archives[0].read_bytes(), self.original)
        # Replay reconstructs the receipt and returns the original result.
        resumed = self._forget()
        self.assertEqual(resumed.status, "forgotten")
        self.assertEqual(resumed.archive_path, archives[0].relative_to(self.vault).as_posix())
        self.assertEqual(resumed.content_sha256, __import__("hashlib").sha256(self.original).hexdigest())
        # And the receipt now replays idempotently.
        self.assertEqual(self._forget().to_dict(), resumed.to_dict())

    def test_forget_crash_after_archive_before_tombstone_resumes_with_intact_source(self) -> None:
        # Crash window: archive durable, tombstone missing, source intact.
        # The next attempt must see the intact source and complete the forget.
        import arvyx_control.forget as forget_module

        original = forget_module._atomic_json
        state = {"fail": True}

        def failing(path, payload):
            if state["fail"] and str(path).endswith(".tombstone.json"):
                state["fail"] = False
                # Simulate a hard crash AFTER the archive copy but BEFORE any
                # tombstone/rollback: leave the copied archive in place.
                raise KeyboardInterrupt("simulated crash")
            return original(path, payload)

        forget_module._atomic_json = failing
        try:
            with self.assertRaises(KeyboardInterrupt):
                self._forget()
        finally:
            forget_module._atomic_json = original
        self.assertTrue(self.source.is_file())
        # Re-run with the archive already present from the interrupted copy:
        # forget refuses to clobber an unrelated pre-existing archive target
        # unless it matches this exact request, so resume must succeed here.
        resumed = self._forget()
        self.assertEqual(resumed.status, "forgotten")
        self.assertFalse(self.source.exists())
        self.assertEqual((self.vault / resumed.archive_path).read_bytes(), self.original)

    def test_restore_request_hash_includes_idempotency_key(self) -> None:
        from arvyx_control.forget import restore_forgotten

        forgotten = self._forget()
        first = restore_forgotten(self.vault, forgotten.tombstone_path, "operator", "restore-key-aaa-0001")
        # Exact replay returns the stored receipt unchanged.
        replay = restore_forgotten(self.vault, forgotten.tombstone_path, "operator", "restore-key-aaa-0001")
        self.assertEqual(replay.to_dict(), first.to_dict())
        # Same actor/tombstone with a DIFFERENT idempotency key must not be
        # treated as a replay of the first request: with the target now
        # present it is refused as an overwrite (old bug: request_hash omitted
        # the key, so a second key could never even be distinguished).
        with self.assertRaisesRegex(ValueError, "refusing unrelated existing publication target"):
            restore_forgotten(self.vault, forgotten.tombstone_path, "operator", "restore-key-bbb-0002")
        # With the target removed, the distinct key executes a fresh restore
        # rather than replaying the first receipt.
        self.source.unlink()
        second = restore_forgotten(self.vault, forgotten.tombstone_path, "operator", "restore-key-bbb-0002")
        self.assertEqual(second.idempotency_key, "restore-key-bbb-0002")
        self.assertEqual(self.source.read_bytes(), self.original)
        # The stored receipt for key A still replays with key A only.
        with self.assertRaisesRegex(ValueError, "different request"):
            restore_forgotten(self.vault, forgotten.tombstone_path, "spoof", "restore-key-aaa-0001")

    def test_symlinked_source_is_rejected_not_followed(self) -> None:
        import os

        outside = Path(self.tmp.name) / "outside-secret.md"
        outside.write_text("host secret outside vault", encoding="utf-8")
        self.source.unlink()
        os.symlink(outside, self.source)
        with self.assertRaises((ValueError, FileNotFoundError)):
            self._forget()
        self.assertEqual(outside.read_text(encoding="utf-8"), "host secret outside vault")
        # Symlink to a regular file INSIDE the vault is also refused: forget
        # only operates on real regular files, never on link targets.
        inside = self.vault / "projects" / "demo-agent" / "REAL.md"
        inside.write_text("real curated file", encoding="utf-8")
        self.source.unlink()
        os.symlink(inside, self.source)
        with self.assertRaises(FileNotFoundError):
            self._forget()
        self.assertEqual(inside.read_text(encoding="utf-8"), "real curated file")
        self.assertEqual(outside.read_text(encoding="utf-8"), "host secret outside vault")

    def test_id_charset_rejects_colon(self) -> None:
        with self.assertRaisesRegex(ValueError, "batch_id"):
            self._forget(batch_id="batch:2026-09-09")
        with self.assertRaisesRegex(ValueError, "actor"):
            self._forget(actor="oper:ator")
        self.assertTrue(self.source.exists())

    def test_api_forget_coerces_none_fields_to_validation_errors(self) -> None:
        from arvyx_control.api import handle_api_request

        state = self.vault / "events.jsonl"
        response = handle_api_request("POST", "/memory/forget", {
            "project": None, "source_path": None, "reason_category": None,
            "batch_id": None, "actor": "operator", "idempotency_key": None,
        }, vault=self.vault, state=state, allow_unauthenticated_demo=True)
        self.assertEqual(response.status, 400)
        self.assertNotIn("None", response.body.get("error", "").replace("NoneType", ""))
        self.assertTrue(self.source.exists())

    def test_concurrent_forget_and_restore_under_vault_lock(self) -> None:
        import threading

        from arvyx_control.forget import restore_forgotten

        forgotten = self._forget()
        results: list[object] = []
        errors: list[BaseException] = []

        def worker(index: int) -> None:
            try:
                results.append(restore_forgotten(
                    self.vault, forgotten.tombstone_path, "operator", f"concurrent-restore-{index:04d}",
                ))
            except BaseException as exc:  # noqa: BLE001 - collected for assertions
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        # Exactly one restore wins; the rest are refused as overwrite attempts
        # or rejected used keys -- never two successful writes of the target.
        successes = [r for r in results if getattr(r, "status", None) == "restored"]
        self.assertEqual(len(successes), 1)
        self.assertEqual(self.source.read_bytes(), self.original)
        for error in errors:
            self.assertIsInstance(error, ValueError)

        # Concurrent forgets of the restored file with distinct keys: exactly
        # one removes it; the others fail (source gone) or replay their own
        # receipts. No duplicated or corrupted archives.
        self.source.write_bytes(self.original)
        outcomes: list[str] = []
        lock = threading.Lock()

        def forgetter(index: int) -> None:
            try:
                result = self._forget(
                    batch_id=f"concurrent-batch-{index:04d}",
                    idempotency_key=f"concurrent-forget-{index:04d}-0001",
                )
                with lock:
                    outcomes.append(result.status)
            except (FileNotFoundError, ValueError):
                with lock:
                    outcomes.append("refused")

        threads = [threading.Thread(target=forgetter, args=(i,)) for i in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(outcomes.count("forgotten"), 1)
        self.assertFalse(self.source.exists())
        archives = [p for p in (self.vault / "excluded" / "forgotten").rglob("*.original")]
        for archive in archives:
            if archive.read_bytes() == self.original:
                continue
            self.fail(f"archive with unexpected bytes: {archive}")


if __name__ == "__main__":
    unittest.main()
