from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from arvyx_control.replica_authority import authority_context
from arvyx_control import operation_journal
from arvyx_control.audit_log import append_audit, append_audit_once, verify_chain
from arvyx_control.audit_log import AuditCorruptionError, _last_hash, recent_events, verify_chain_tail


class AuditReceiptTests(unittest.TestCase):
    def test_rebuild_tolerates_non_object_audit_tail_without_extending_it(self) -> None:
        from contextlib import redirect_stderr
        from io import StringIO
        from arvyx_control.checkpoint_jobs import rebuild_index_checkpointed, _audit_path
        from arvyx_control.vault import init_vault

        for value in ([], None, "scalar", 3, True):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as tmp:
                vault = Path(tmp) / "vault"
                init_vault(vault)
                log = _audit_path(vault)
                log.parent.mkdir(parents=True, exist_ok=True)
                log.write_text(json.dumps(value) + "\n", encoding="utf-8")
                before = log.read_bytes()
                errors = StringIO()
                with authority_context(vault), redirect_stderr(errors):
                    result = rebuild_index_checkpointed(vault, owner="audit-tail-regression")
                self.assertEqual(result.status, "completed")
                self.assertIn("audit event was not recorded", errors.getvalue())
                self.assertEqual(log.read_bytes(), before)

    def test_non_object_audit_records_fail_closed_without_attribute_errors(self) -> None:
        for value in ([], None, "scalar", 3, True):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as tmp:
                log = Path(tmp) / "audit.jsonl"
                log.write_text(json.dumps(value) + "\n", encoding="utf-8")
                before = log.read_bytes()
                with self.assertRaises(AuditCorruptionError):
                    _last_hash(log)
                self.assertFalse(verify_chain(log).ok)
                self.assertFalse(verify_chain_tail(log).ok)
                self.assertFalse(recent_events(log).chain.ok)
                self.assertEqual(log.read_bytes(), before)

    def test_repeated_event_id_is_appended_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, authority_context(Path(tmp) / "vault"):
            log = Path(tmp) / "audit.jsonl"
            event = {"event_id": "op-1:outcome", "phase": "outcome", "operation_id": "op-1"}
            append_audit_once(log, event)
            append_audit_once(log, event)
            self.assertEqual(len(log.read_text(encoding="utf-8").splitlines()), 1)
            self.assertTrue(verify_chain(log).ok)

    def test_pending_receipt_recovers_append_without_duplicate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, authority_context(Path(tmp) / "vault"):
            log = Path(tmp) / "audit.jsonl"
            receipt_db = operation_journal.journal_path(log)
            event = {"event_id": "op-2:outcome", "phase": "outcome", "operation_id": "op-2"}
            state = operation_journal.claim_audit_receipt(receipt_db, event["event_id"])
            self.assertEqual(state, "new")
            append_audit(log, event)
            append_audit_once(log, event)
            self.assertEqual(len(log.read_text(encoding="utf-8").splitlines()), 1)
            self.assertEqual(
                operation_journal.claim_audit_receipt(receipt_db, event["event_id"]),
                "written",
            )
            self.assertTrue(verify_chain(log).ok)

    def test_written_receipt_short_circuits_without_rewriting_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, authority_context(Path(tmp) / "vault"):
            log = Path(tmp) / "audit.jsonl"
            event = {"event_id": "op-3:intent", "phase": "intent", "operation_id": "op-3"}
            append_audit_once(log, event)
            before = log.read_bytes()
            append_audit_once(log, event)
            self.assertEqual(log.read_bytes(), before)
            receipt_db = operation_journal.journal_path(log)
            self.assertEqual(
                operation_journal.claim_audit_receipt(receipt_db, event["event_id"]),
                "written",
            )


if __name__ == "__main__":
    unittest.main()
