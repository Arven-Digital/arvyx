from __future__ import annotations
from arvyx_control.replica_authority import authority_context

from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import tempfile
import unittest

from arvyx_control.auth import issue_token, resolve_identity
from arvyx_control.control import (
    approve_request,
    create_task,
    list_approvals,
    read_events,
    request_approval,
)


class ExpiryIdempotencyTests(unittest.TestCase):
    def _expire(self, state: Path) -> None:
        payload = json.loads(state.read_text())
        payload["payload"]["expires_at"] = (
            datetime.now(UTC) - timedelta(seconds=1)
        ).isoformat().replace("+00:00", "Z")
        state.write_text(json.dumps(payload) + "\n")

    def test_expired_approval_is_listed_as_expired_not_requested(self) -> None:
        """A dead approval must not look actionable on any listing surface.

        Expiry is derived rather than written, so the stored status stays
        ``requested`` forever; the listing is where the truth has to appear.
        """
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                result = request_approval(state, "deploy", ttl_seconds=60, requester="demobot")
                self.assertEqual(list_approvals(state).approvals[0].status, "requested")
                self._expire(state)
                listed = list_approvals(state)
                self.assertEqual([approval.status for approval in listed.approvals], ["expired"])
                self.assertEqual(list_approvals(state, status="requested").approvals, [])
                self.assertEqual(
                    [approval.id for approval in list_approvals(state, status="expired").approvals],
                    [result.approval.id],
                )

    def test_create_retry_returns_original_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                first = create_task(state, "ship", idempotency_key="retry-1", owner="demobot")
                second = create_task(state, "ship", idempotency_key="retry-1", owner="demobot")
                with self.assertRaisesRegex(ValueError, "idempotency"):
                    create_task(state, "changed request", idempotency_key="retry-1", owner="demobot")
                self.assertEqual(first.event.id, second.event.id)
                self.assertEqual(first.task.id, second.task.id)
                self.assertEqual(len(read_events(state)), 1)

    def test_expired_approval_cannot_be_approved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                result = request_approval(state, "deploy", ttl_seconds=60, requester="demobot")
                payload = json.loads(state.read_text())
                payload["payload"]["expires_at"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
                state.write_text(json.dumps(payload) + "\n")
                with self.assertRaisesRegex(ValueError, "expired"):
                    approve_request(state, result.approval.id, "operator")

    def test_expired_and_malformed_tokens_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp)
            agents = vault / "registry" / "agents"
            agents.mkdir(parents=True)
            (agents / "demobot.json").write_text(json.dumps({"scopes": ["memory.read"]}))
            issued = issue_token(vault, "demobot", ttl_days=30)
            record_path = vault / "registry" / "tokens" / "demobot.json"
            record = json.loads(record_path.read_text())
            for expiry in ((datetime.now(UTC) - timedelta(days=1)).isoformat(), "not-a-date"):
                record["expires_at"] = expiry
                record_path.write_text(json.dumps(record))
                self.assertIsNone(resolve_identity(vault, f"Bearer {issued.token}"))


if __name__ == "__main__":
    unittest.main()
