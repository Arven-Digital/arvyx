from arvyx_control.replica_authority import authority_context
"""Candidate 43 regression sources. NOT_EXECUTED by instruction."""
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from arvyx_control import audit_log, cli, operation_journal


class AuditLifecycleTests(unittest.TestCase):
    def test_cli_rejected_material_never_reaches_audit_or_error(self):
        literal = "ghp_" + "A" * 36
        for ref in (literal, "secret://env/" + literal, "not-a-reference"):
            with self.subTest(ref=ref), tempfile.TemporaryDirectory() as tmp:
                log = Path(tmp) / "audit.jsonl"
                out, err = StringIO(), StringIO()
                with redirect_stdout(out), redirect_stderr(err):
                    code = cli.main(["--authority-vault", str(Path(tmp) / "authority-vault"), "secret", "resolve", ref, "--audit-log", str(log)])
                self.assertEqual(code, 1)
                text = log.read_text()
                self.assertNotIn(ref, text + out.getvalue() + err.getvalue())
                records = [json.loads(line) for line in text.splitlines()]
                self.assertEqual([r["decision"] for r in records], ["pending", "denied"])
                self.assertTrue(all(r["secret_ref"] == "invalid-secret-ref" for r in records))

    def test_cli_validates_once_and_reuses_safe_ref_in_all_phases(self):
        for denied in (False, True):
            with self.subTest(denied=denied), tempfile.TemporaryDirectory() as tmp:
                out, err = StringIO(), StringIO()
                resolved = mock.Mock(value="synthetic-output")
                with mock.patch.object(cli, "is_secret_ref", return_value=True) as valid, \
                     mock.patch.object(cli, "append_audit") as append, \
                     mock.patch.object(cli, "resolve_ref", return_value=resolved,
                                       side_effect=ValueError("synthetic-private-error") if denied else None), \
                     redirect_stdout(out), redirect_stderr(err):
                    code = cli.main(["--authority-vault", str(Path(tmp) / "authority-vault"), "secret", "resolve", "secret://env/DB"])
                valid.assert_called_once_with("secret://env/DB")
                self.assertEqual(code, 1 if denied else 0)
                self.assertEqual([c.args[1]["decision"] for c in append.call_args_list],
                                 ["pending", "denied" if denied else "allowed"])
                self.assertTrue(all(c.args[1]["secret_ref"] == "secret://env/DB"
                                    for c in append.call_args_list))
                self.assertNotIn("synthetic-private-error", err.getvalue())

    def test_barriers_precede_receipt_for_new_pending_and_written_paths(self):
        for state in ("normal", "new", "pending", "written"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as tmp:
                log = Path(tmp) / "nested" / "audit.jsonl"
                event = {"event_id": "synthetic:event"}
                if state in ("pending", "written"):
                    with authority_context(Path(tmp) / "authority-vault"):
                        audit_log.append_audit(log, event)
                steps = []
                real_mkdir = audit_log.durable_mkdir
                def mkdir(path):
                    steps.append("mkdir")
                    real_mkdir(path)
                with mock.patch.object(audit_log, "durable_mkdir", side_effect=mkdir), \
                     mock.patch.object(audit_log.os, "fsync", side_effect=lambda fd: steps.append("file")), \
                     mock.patch.object(audit_log, "fsync_directory", side_effect=lambda p: steps.append("parent")), \
                     mock.patch.object(audit_log, "claim_audit_receipt", return_value=state), \
                     mock.patch.object(audit_log, "mark_audit_receipt_written", side_effect=lambda *a: steps.append("receipt")):
                    if state == "normal":
                        with authority_context(Path(tmp) / "authority-vault"):
                            audit_log.append_audit(log, event)
                    else:
                        with authority_context(Path(tmp) / "authority-vault"):
                            audit_log.append_audit_once(log, event)
                self.assertEqual(steps[-3:] if state in ("new", "pending") else steps[-2:],
                                 ["file", "parent", "receipt"] if state in ("new", "pending") else ["file", "parent"])
                self.assertEqual(len(log.read_text().splitlines()), 1)
                self.assertTrue(audit_log.verify_chain(log).ok)

    def test_failed_parent_barrier_keeps_pending_and_retry_does_not_duplicate(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "audit.jsonl"
            event = {"event_id": "synthetic:retry"}
            with mock.patch.object(audit_log, "fsync_directory", side_effect=OSError("barrier")):
                with self.assertRaises(OSError):
                    with authority_context(Path(tmp) / "authority-vault"):
                        audit_log.append_audit_once(log, event)
            receipt = operation_journal.journal_path(log)
            with authority_context(Path(tmp) / "authority-vault"):
                self.assertEqual(operation_journal.claim_audit_receipt(receipt, event["event_id"]), "pending")
            with mock.patch.object(audit_log, "fsync_directory", side_effect=OSError("recovery barrier")):
                with self.assertRaises(OSError):
                    with authority_context(Path(tmp) / "authority-vault"):
                        audit_log.append_audit_once(log, event)
            with authority_context(Path(tmp) / "authority-vault"):
                self.assertEqual(operation_journal.claim_audit_receipt(receipt, event["event_id"]), "pending")
            with authority_context(Path(tmp) / "authority-vault"):
                audit_log.append_audit_once(log, event)
            self.assertEqual(len(log.read_text().splitlines()), 1)
            with authority_context(Path(tmp) / "authority-vault"):
                self.assertEqual(operation_journal.claim_audit_receipt(receipt, event["event_id"]), "written")

    def test_file_and_ancestor_failures_propagate_without_receipt_ack(self):
        for barrier in ("durable_mkdir", "os.fsync"):
            with self.subTest(barrier=barrier), tempfile.TemporaryDirectory() as tmp:
                log = Path(tmp) / "audit.jsonl"
                with mock.patch("arvyx_control.audit_log." + barrier, side_effect=OSError("barrier")), \
                     mock.patch.object(audit_log, "mark_audit_receipt_written") as mark:
                    with self.assertRaises(OSError):
                        with authority_context(Path(tmp) / "authority-vault"):
                            audit_log.append_audit_once(log, {"event_id": "synthetic:failure"})
                    mark.assert_not_called()

    def test_written_receipt_without_log_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "audit.jsonl"
            with mock.patch.object(audit_log, "claim_audit_receipt", return_value="written"):
                with self.assertRaises(audit_log.AuditCorruptionError):
                    with authority_context(Path(tmp) / "authority-vault"):
                        audit_log.append_audit_once(log, {"event_id": "synthetic:missing"})
            self.assertFalse(log.exists())

    def test_pending_receipt_rejects_torn_or_tampered_retained_record(self):
        for damage in ("torn", "tampered"):
            with self.subTest(damage=damage), tempfile.TemporaryDirectory() as tmp:
                log = Path(tmp) / "audit.jsonl"
                event = {"event_id": "synthetic:damaged", "decision": "allowed"}
                with authority_context(Path(tmp) / "authority-vault"):
                    audit_log.append_audit(log, event)
                text = log.read_text()
                log.write_text(text.rstrip("\n") if damage == "torn"
                               else text.replace("allowed", "denied"))
                with mock.patch.object(audit_log, "claim_audit_receipt", return_value="pending"), \
                     mock.patch.object(audit_log, "mark_audit_receipt_written") as mark:
                    with self.assertRaises(audit_log.AuditCorruptionError):
                        with authority_context(Path(tmp) / "authority-vault"):
                            audit_log.append_audit_once(log, event)
                    mark.assert_not_called()

    def test_cli_completion_barrier_failure_never_releases_secret(self):
        out, err = StringIO(), StringIO()
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(cli, "append_audit", side_effect=[{}, OSError("private-detail")]), \
             mock.patch.object(cli, "resolve_ref", return_value=mock.Mock(value="private-value")), \
             redirect_stdout(out), redirect_stderr(err):
            code = cli.main(["--authority-vault", str(Path(tmp) / "authority-vault"), "secret", "resolve", "secret://env/DB"])
        self.assertEqual(code, 1)
        self.assertEqual(out.getvalue(), "")
        self.assertNotIn("private-detail", err.getvalue())
