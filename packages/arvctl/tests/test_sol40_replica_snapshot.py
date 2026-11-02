"""Source snapshot ownership and promotion recovery regressions (not executed)."""
from contextlib import contextmanager
import hashlib
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from arvyx_control import promotion_transaction, replica


class ReplicaSnapshotTests(unittest.TestCase):
    def test_control_cut_precedes_reconciliation_and_audit_follows_vault_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            vault.mkdir()
            note = vault / "note.md"
            state = Path(tmp) / "events.jsonl"
            audit = Path(tmp) / "audit.jsonl"
            state.write_bytes(b'{"type":"test"}\n')
            audit.write_bytes(b"audit\n")
            active = False
            events = []
            real_boundary = promotion_transaction.memory_mutation
            real_files = replica._source_files
            real_read = replica._source_bytes
            real_lock = replica.exclusive_lock

            def recover(root, *, deadline=None):
                self.assertEqual(root, vault.resolve())
                events.append("recover")
                note.write_bytes(b"reconciled\n")

            @contextmanager
            def boundary(root):
                nonlocal active
                with real_boundary(root):
                    active = True
                    try:
                        yield
                    finally:
                        active = False
                        events.append("released")

            def enumerate_paths(directory_fd, prefix=""):
                if not prefix:
                    self.assertTrue(active)
                    self.assertEqual(events, ["state-lock", "recover"])
                    events.append("enumerate")
                yield from real_files(directory_fd, prefix)

            def read_bytes(root_fd, relative):
                if relative == "note.md":
                    self.assertTrue(active)
                    events.append("hash")
                return real_read(root_fd, relative)

            @contextmanager
            def state_lock(path):
                self.assertFalse(active, "writer locks must not nest inside the vault lock")
                if path == audit.with_suffix(audit.suffix + ".lock"):
                    self.assertIn("released", events)
                else:
                    self.assertEqual(events, [])
                events.append("state-lock")
                with real_lock(path):
                    yield

            with patch.object(promotion_transaction, "recover", side_effect=recover), \
                    patch.object(replica, "memory_mutation", side_effect=boundary), \
                    patch.object(replica, "_source_files", enumerate_paths), \
                    patch.object(replica, "_source_bytes", read_bytes), \
                    patch.object(replica, "exclusive_lock", side_effect=state_lock):
                manifest = replica.build_manifest(vault, state, audit)
            self.assertEqual(events, ["state-lock", "recover", "enumerate", "hash", "released", "state-lock"])
            self.assertEqual(manifest["files"], {
                "note.md": {"sha256": hashlib.sha256(b"reconciled\n").hexdigest(), "size": len(b"reconciled\n")},
            })
            self.assertEqual(set(manifest["state_files"]), {"control-events.jsonl", "audit-log.jsonl"})

    def test_manifest_recovers_interrupted_promotion_before_enumeration(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            vault.mkdir()
            source = vault / "pending.md"
            parent = vault / "parent.md"
            target = vault / "replacement.md"
            source.write_bytes(b"pending\n")
            parent.write_bytes(b"current\n")
            real_stage = promotion_transaction.stage

            def interrupt_commit(path, data, mode=0o600):
                if path.name == "committed.stage":
                    raise OSError("interrupted after source unlink")
                return real_stage(path, data, mode)

            with promotion_transaction.memory_mutation(vault):
                with patch.object(promotion_transaction, "stage", side_effect=interrupt_commit), \
                        patch.object(promotion_transaction, "rollback", return_value=False):
                    with self.assertRaisesRegex(OSError, "interrupted"):
                        promotion_transaction.publish(
                            vault, source, target, b"replacement\n",
                            {parent: (b"current\n", b"superseded\n")},
                            source_bytes=b"pending\n",
                        )
            self.assertFalse(source.exists())
            self.assertTrue(target.exists())
            manifest = replica.build_manifest(vault)
            self.assertEqual(set(manifest["files"]), {"pending.md", "parent.md"})
            for name, original in (("pending.md", b"pending\n"), ("parent.md", b"current\n")):
                self.assertEqual(manifest["files"][name]["sha256"], hashlib.sha256(original).hexdigest())
            self.assertFalse(target.exists())

    def test_promotion_between_enumeration_and_hashing_waits_for_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            vault.mkdir()
            source = vault / "pending.md"
            parent = vault / "parent.md"
            target = vault / "replacement.md"
            source.write_bytes(b"pending\n")
            parent.write_bytes(b"current\n")
            attempted = threading.Event()
            acquired = threading.Event()
            errors = []
            real_files = replica._source_files
            enumerated = []

            def promote():
                try:
                    attempted.set()
                    with promotion_transaction.memory_mutation(vault):
                        acquired.set()
                        promotion_transaction.publish(
                            vault, source, target, b"replacement\n",
                            {parent: (b"current\n", b"superseded\n")},
                            source_bytes=b"pending\n",
                        )
                except BaseException as exc:
                    errors.append(exc)

            worker = threading.Thread(target=promote, daemon=True)

            def enumerate_paths(directory_fd, prefix=""):
                paths = list(real_files(directory_fd, prefix))
                if not prefix:
                    enumerated.extend(paths)
                    worker.start()
                    self.assertTrue(attempted.wait(5))
                    self.assertFalse(acquired.wait(0.1), "promotion crossed source snapshot lock")
                return iter(paths)

            try:
                with patch.object(replica, "_source_files", enumerate_paths):
                    before = replica.build_manifest(vault)
            finally:
                if worker.ident is not None:
                    worker.join(5)
            self.assertFalse(worker.is_alive())
            self.assertIsNotNone(worker.ident)
            self.assertTrue(attempted.is_set())
            self.assertEqual(set(enumerated), {"pending.md", "parent.md"})
            self.assertEqual(errors, [])
            self.assertTrue(acquired.is_set())
            self.assertEqual(set(before["files"]), {"pending.md", "parent.md"})
            self.assertEqual(before["files"]["parent.md"]["sha256"], hashlib.sha256(b"current\n").hexdigest())
            after = replica.build_manifest(vault)
            self.assertEqual(set(after["files"]), {"parent.md", "replacement.md"})
            self.assertEqual(after["files"]["parent.md"]["sha256"], hashlib.sha256(b"superseded\n").hexdigest())

    def test_recovery_conflict_refuses_manifest_before_enumeration(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            vault.mkdir()
            with patch.object(promotion_transaction, "recover", side_effect=OSError("recovery conflict")), \
                    patch.object(replica, "_source_files") as enumeration:
                with self.assertRaisesRegex(OSError, "recovery conflict"):
                    replica.build_manifest(vault)
                enumeration.assert_not_called()
