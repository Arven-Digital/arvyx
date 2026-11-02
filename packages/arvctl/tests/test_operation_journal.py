from __future__ import annotations

import json
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

from arvyx_control.replica_authority import authority_context
from arvyx_control import api
from arvyx_control.api import handle_api_request
from arvyx_control.cli import main
from arvyx_control.audit_log import pending_operations
from arvyx_control.auth import issue_token
from arvyx_control.brokers import ResolveResult
from arvyx_control.operation_journal import (
    claim_operation,
    journal_path,
    pending_operation_count,
    request_digest,
    set_operation_state,
    transition_operation_state,
    try_begin_dispatch,
)
from arvyx_control.vault import init_vault


class OperationJournalTests(unittest.TestCase):
    def test_operator_can_reconcile_unknown_dispatch_without_redispatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, authority_context(Path(tmp) / "vault", None):
            audit = Path(tmp) / "audit.jsonl"
            store = journal_path(audit)
            claim = claim_operation(
                store,
                vault=Path(tmp) / "vault",
                principal_scope="agent:operator",
                action="POST:/tasks",
                idempotency_key="reconcile-unknown-key-0001",
                request_hash="a" * 64,
            )
            self.assertTrue(
                transition_operation_state(
                    store,
                    claim.operation_id,
                    expected_state="claimed",
                    new_state="intent_durable",
                )
            )
            self.assertTrue(try_begin_dispatch(store, claim.operation_id, "worker-one"))
            blocked_err = StringIO()
            with redirect_stderr(blocked_err):
                blocked = main(
                    [
                        "--authority-vault", str(Path(tmp) / "vault"),
                        "operation", "reconcile", claim.operation_id,
                        "--audit-log", str(audit),
                        "--resolution", "reject-unknown",
                    ]
                )
            self.assertEqual(blocked, 1)
            self.assertIn("confirm-unknown", blocked_err.getvalue())
            output = StringIO()
            with redirect_stdout(output):
                code = main(
                    [
                        "--authority-vault", str(Path(tmp) / "vault"),
                        "operation", "reconcile", claim.operation_id,
                        "--audit-log", str(audit),
                        "--resolution", "reject-unknown",
                        "--confirm-unknown-may-have-dispatched",
                        "--json",
                    ]
                )
            self.assertEqual(code, 0)
            self.assertFalse(json.loads(output.getvalue())["redispatched"])
            self.assertEqual(pending_operation_count(store), 0)
            self.assertIn("rejected-unknown", audit.read_text(encoding="utf-8"))

    def test_concurrent_same_key_grants_one_dispatch_owner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, authority_context(Path(tmp) / "vault", None):
            journal = Path(tmp) / "operations.sqlite3"
            claim = claim_operation(
                journal,
                vault=Path(tmp) / "vault",
                principal_scope="agent:demobot",
                action="POST:/tasks",
                idempotency_key="concurrent-dispatch-0001",
                request_hash=request_digest({"title": "one", "owner": "demobot"}),
            )
            set_operation_state(journal, claim.operation_id, "intent_durable")
            barrier = threading.Barrier(2)
            grants: list[bool] = []

            def contender(owner: str) -> None:
                with authority_context(Path(tmp) / "vault"):
                    barrier.wait()
                    grants.append(try_begin_dispatch(journal, claim.operation_id, owner))

            threads = [threading.Thread(target=contender, args=(f"owner-{index}",)) for index in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=10)
            self.assertTrue(all(not thread.is_alive() for thread in threads))
            self.assertEqual(grants.count(True), 1)
            self.assertEqual(grants.count(False), 1)

    def test_concurrent_same_key_dispatches_domain_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, authority_context(Path(tmp) / "vault", Path(tmp) / "events.jsonl"):
            root = Path(tmp)
            vault = root / "vault"
            state = root / "events.jsonl"
            audit = root / "audit.jsonl"
            init_vault(vault)
            entered = threading.Event()
            release = threading.Event()
            calls = 0
            first_response: list[object] = []
            real_dispatch = api._handle_api_request

            def slow_dispatch(**kwargs):
                nonlocal calls
                calls += 1
                entered.set()
                self.assertTrue(release.wait(timeout=10))
                return real_dispatch(**kwargs)

            common = dict(
                vault=vault,
                state=state,
                audit_log=audit,
                allow_unauthenticated_demo=True,
                idempotency_key="api-concurrent-dispatch-0001",
            )
            with mock.patch.object(api, "_handle_api_request", side_effect=slow_dispatch):
                worker = threading.Thread(
                    target=lambda: first_response.append(
                        handle_api_request("POST", "/tasks", {"title": "one", "owner": "demobot"}, **common)
                    )
                )
                worker.start()
                self.assertTrue(entered.wait(timeout=10))
                second = handle_api_request("POST", "/tasks", {"title": "one", "owner": "demobot"}, **common)
                release.set()
                worker.join(timeout=10)
            self.assertFalse(worker.is_alive())
            self.assertEqual(calls, 1)
            self.assertEqual(second.status, 409)
            self.assertEqual(second.body["error"], "operation_reconciliation_required")
            self.assertEqual(first_response[0].status, 201)

    def test_retry_cannot_repeat_domain_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, authority_context(Path(tmp) / "vault", Path(tmp) / "events.jsonl"):
            root = Path(tmp)
            vault = root / "vault"
            state = root / "events.jsonl"
            audit = root / "audit.jsonl"
            init_vault(vault)
            body = {"title": "exactly once", "owner": "demobot"}
            first = handle_api_request(
                "POST", "/tasks", body, vault=vault, state=state,
                allow_unauthenticated_demo=True, audit_log=audit,
                idempotency_key="task-exactly-once-0001",
            )
            retry = handle_api_request(
                "POST", "/tasks", body, vault=vault, state=state,
                allow_unauthenticated_demo=True, audit_log=audit,
                idempotency_key="task-exactly-once-0001",
            )
            listed = handle_api_request(
                "GET", "/tasks", {}, vault=vault, state=state,
                allow_unauthenticated_demo=True, audit_log=audit,
            )
            self.assertEqual(first.status, 201)
            self.assertEqual(retry.status, 409)
            self.assertEqual(len(listed.body["tasks"]), 1)
            self.assertEqual(pending_operations(audit), 0)

    def test_same_key_with_different_request_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, authority_context(Path(tmp) / "vault", Path(tmp) / "events.jsonl"):
            root = Path(tmp)
            vault = root / "vault"
            state = root / "events.jsonl"
            audit = root / "audit.jsonl"
            init_vault(vault)
            common = dict(
                vault=vault, state=state, allow_unauthenticated_demo=True,
                audit_log=audit, idempotency_key="task-conflict-key-0001",
            )
            self.assertEqual(handle_api_request("POST", "/tasks", {"title": "one", "owner": "demobot"}, **common).status, 201)
            conflict = handle_api_request("POST", "/tasks", {"title": "two"}, **common)
            self.assertEqual(conflict.status, 409)
            self.assertEqual(conflict.body["error"], "idempotency_conflict")

    def test_secret_resolve_refuses_value_when_audit_tail_is_torn(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, authority_context(Path(tmp) / "vault", Path(tmp) / "events.jsonl"):
            root = Path(tmp)
            vault = root / "vault"
            state = root / "events.jsonl"
            audit = root / "audit.jsonl"
            init_vault(vault)
            audit.write_bytes(b'{"event_id":"torn"')
            token = issue_token(vault, "demobot", scopes=["secret.resolve"]).token
            resolution = ResolveResult(
                ref="secret://env/DB", broker="env", provider="env", value="sensitive-marker"
            )
            with mock.patch.object(api, "resolve_ref", return_value=resolution) as broker:
                response = handle_api_request(
                    "POST",
                    "/secret/resolve",
                    {"ref": "secret://env/DB"},
                    vault=vault,
                    state=state,
                    audit_log=audit,
                    authorization=f"Bearer {token}",
                    idempotency_key="secret-torn-audit-0001",
                )
            self.assertEqual(response.status, 503)
            self.assertNotIn("sensitive-marker", json.dumps(response.body))
            broker.assert_not_called()

    def test_secret_value_is_withheld_until_outcome_is_durable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, authority_context(Path(tmp) / "vault", Path(tmp) / "events.jsonl"):
            root = Path(tmp)
            vault = root / "vault"
            state = root / "events.jsonl"
            audit = root / "audit.jsonl"
            init_vault(vault)
            token = issue_token(vault, "demobot", scopes=["secret.resolve"]).token
            real_append = api.append_audit_once
            calls = 0

            def fail_outcome(path, event):
                nonlocal calls
                calls += 1
                if event.get("phase") == "outcome":
                    raise OSError("synthetic audit failure")
                return real_append(path, event)

            resolution = ResolveResult(
                ref="secret://env/DB", broker="env", provider="env", value="sensitive-marker"
            )
            with mock.patch.object(api, "resolve_ref", return_value=resolution), mock.patch.object(
                api, "append_audit_once", side_effect=fail_outcome
            ):
                first = handle_api_request(
                    "POST", "/secret/resolve", {"ref": "secret://env/DB"},
                    vault=vault, state=state, audit_log=audit,
                    authorization=f"Bearer {token}",
                    idempotency_key="secret-resolution-0001",
                )
            self.assertEqual(first.status, 503)
            self.assertNotIn("sensitive-marker", json.dumps(first.body))
            self.assertGreater(calls, 1)
            self.assertEqual(pending_operations(audit), 1)

            with mock.patch.object(api, "resolve_ref", side_effect=AssertionError("broker must not run again")):
                retry = handle_api_request(
                    "POST", "/secret/resolve", {"ref": "secret://env/DB"},
                    vault=vault, state=state, audit_log=audit,
                    authorization=f"Bearer {token}",
                    idempotency_key="secret-resolution-0001",
                )
            self.assertEqual(retry.status, 409)
            self.assertEqual(retry.body["error"], "secret_value_not_replayable")
            self.assertNotIn("sensitive-marker", json.dumps(retry.body))
            self.assertEqual(pending_operations(audit), 0)

    def test_large_legacy_audit_without_sidecar_does_not_fake_pending(self) -> None:
        from arvyx_control.audit_log import _READINESS_TAIL_BYTES, append_audit, pending_operations

        with tempfile.TemporaryDirectory() as tmp, authority_context(Path(tmp) / "vault", None):
            audit = Path(tmp) / "audit.jsonl"
            append_audit(
                audit,
                {
                    "phase": "intent",
                    "operation_id": "legacy-complete-1",
                    "event_id": "legacy-complete-1:intent",
                },
            )
            append_audit(
                audit,
                {
                    "phase": "outcome",
                    "operation_id": "legacy-complete-1",
                    "event_id": "legacy-complete-1:outcome",
                    "decision": "allowed",
                },
            )
            # Inflate beyond the readiness tail bound while keeping the chain intact.
            while audit.stat().st_size <= _READINESS_TAIL_BYTES:
                append_audit(audit, {"action": "noise", "detail": "x" * 4096})
            self.assertGreater(audit.stat().st_size, _READINESS_TAIL_BYTES)
            self.assertFalse(journal_path(audit).exists())
            self.assertEqual(pending_operations(audit), 0)
            self.assertTrue(journal_path(audit).exists())
            self.assertEqual(pending_operations(audit), 0)

    def test_large_legacy_audit_with_real_pending_still_reports_pending(self) -> None:
        from arvyx_control.audit_log import _READINESS_TAIL_BYTES, append_audit, pending_operations

        with tempfile.TemporaryDirectory() as tmp, authority_context(Path(tmp) / "vault", None):
            audit = Path(tmp) / "audit.jsonl"
            append_audit(
                audit,
                {
                    "phase": "intent",
                    "operation_id": "legacy-pending-1",
                    "event_id": "legacy-pending-1:intent",
                },
            )
            while audit.stat().st_size <= _READINESS_TAIL_BYTES:
                append_audit(audit, {"action": "noise", "detail": "y" * 4096})
            self.assertGreater(audit.stat().st_size, _READINESS_TAIL_BYTES)
            self.assertFalse(journal_path(audit).exists())
            self.assertEqual(pending_operations(audit), 1)
            self.assertTrue(journal_path(audit).exists())
            self.assertEqual(pending_operations(audit), 1)

    def test_schema_only_sidecar_does_not_hide_orphan_intent(self) -> None:
        from arvyx_control.audit_log import append_audit, pending_operations
        from arvyx_control.operation_journal import _connect

        with tempfile.TemporaryDirectory() as tmp, authority_context(Path(tmp) / "vault", None):
            audit = Path(tmp) / "audit.jsonl"
            append_audit(
                audit,
                {
                    "phase": "intent",
                    "operation_id": "orphan-after-partial-migrate",
                    "event_id": "orphan-after-partial-migrate:intent",
                },
            )
            sidecar = journal_path(audit)
            connection = _connect(sidecar)
            connection.close()
            self.assertTrue(sidecar.exists())
            self.assertEqual(pending_operations(audit), 1)
            self.assertEqual(pending_operation_count(sidecar), 1)


if __name__ == "__main__":
    unittest.main()
