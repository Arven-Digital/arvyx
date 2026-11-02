from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import tempfile
import unittest

from arvyx_control.replica_authority import authority_context
from arvyx_control.agent_delivery import AgentDeliveryResult, AgentRoute
from arvyx_control.control import acknowledge_thread, complete_thread, post_thread
from arvyx_control.dispatcher import dispatch_once
from arvyx_control.execution import claim_execution
from arvyx_control.outbox import claim_due, mark_delivered, project_outbox, record_failure, replay
from arvyx_control.session_return import (
    get_session_return,
    list_session_returns,
    request_session_return,
    session_return_dispatch_error,
)


T0 = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)


class SessionReturnTests(unittest.TestCase):
    def _leased(self, state: Path):
        thread = post_thread(
            state, title="return to Elin", actor="esme", target="amir",
            actor_identity_bound=True,
        )
        acknowledge_thread(state, thread.thread.id, actor="amir", actor_identity_bound=True)
        execution = claim_execution(
            state,
            worker="return-worker",
            execution_capable_targets={"amir"},
            now=T0,
            lease_seconds=600,
        )
        self.assertIsNotNone(execution)
        return execution

    def test_target_requests_idempotent_exact_attempt_session_return(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution = self._leased(state)
                message = " ".join(f"kelime{i}" for i in range(100))

                first = request_session_return(
                    state,
                    execution_id=execution.id,
                    attempt_id=execution.attempt_id,
                    actor="amir",
                    message=message,
                    expected_word_count=100,
                    idempotency_key="story-return-0001",
                    now=T0,
                )
                replay = request_session_return(
                    state,
                    execution_id=execution.id,
                    attempt_id=execution.attempt_id,
                    actor="amir",
                    message=message,
                    expected_word_count=100,
                    idempotency_key="story-return-0001",
                    now=T0,
                )

                self.assertEqual(replay.request_id, first.request_id)
                self.assertEqual(first.target, "amir")
                self.assertEqual(first.word_count, 100)
                self.assertEqual(len(first.message_sha256), 64)
                projected = get_session_return(state, request_id=first.request_id, actor="amir")
                self.assertEqual(projected.status, "requested")
                self.assertEqual(projected.execution_id, execution.id)

    def test_request_materializes_fixed_target_session_return_outbox(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution = self._leased(state)
                requested = request_session_return(
                    state,
                    execution_id=execution.id,
                    attempt_id=execution.attempt_id,
                    actor="amir",
                    message="tam yüz kelimelik hikaye",
                    expected_word_count=4,
                    idempotency_key="materialize-return",
                    now=T0,
                )
                claimed = claim_due(
                    state,
                    worker="dispatcher",
                    now=T0,
                    lease_seconds=120,
                    deliver_after="2026-08-20T11:00:00Z",
                    targets={"amir"},
                    limit=10,
                )
                item = next(item for item in claimed if item.subject_id == requested.request_id)
                self.assertEqual(item.target, "amir")
                self.assertEqual(item.payload["delivery_mode"], "session_return")
                self.assertEqual(item.payload["execution_id"], execution.id)
                self.assertEqual(item.payload["attempt_id"], execution.attempt_id)
                self.assertEqual(item.payload["message"], "tam yüz kelimelik hikaye")
                self.assertEqual(item.payload["message_sha256"], requested.message_sha256)
                self.assertNotIn("destination", item.payload)

                mark_delivered(
                    state,
                    outbox_id=item.id,
                    worker="dispatcher", claim_attempts=next(c.attempts for c in claimed if c.id == item.id),
                    now=T0,
                    provider_receipt="telegram-message-42",
                )
                delivered = get_session_return(state, request_id=requested.request_id, actor="amir")
                self.assertEqual(delivered.status, "delivered")
                self.assertEqual(delivered.delivery_id, item.id)
                self.assertEqual(delivered.provider_receipt, "telegram-message-42")

    def test_foreign_identity_cannot_request_or_read_session_return(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution = self._leased(state)
                with self.assertRaisesRegex(ValueError, "identity-bound target"):
                    request_session_return(
                        state,
                        execution_id=execution.id,
                        attempt_id=execution.attempt_id,
                        actor="kiran",
                        message="merhaba",
                        expected_word_count=1,
                        idempotency_key="foreign-return",
                        now=T0,
                    )

    def test_stale_attempt_and_word_count_mismatch_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution = self._leased(state)
                with self.assertRaisesRegex(ValueError, "attempt"):
                    request_session_return(
                        state,
                        execution_id=execution.id,
                        attempt_id="attempt_stale",
                        actor="amir",
                        message="bir iki",
                        expected_word_count=2,
                        idempotency_key="stale-return",
                        now=T0,
                    )
                with self.assertRaisesRegex(ValueError, "word count"):
                    request_session_return(
                        state,
                        execution_id=execution.id,
                        attempt_id=execution.attempt_id,
                        actor="amir",
                        message="bir iki",
                        expected_word_count=100,
                        idempotency_key="count-return",
                        now=T0,
                    )

    def test_secret_shaped_message_and_second_return_for_attempt_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution = self._leased(state)
                shaped = "".join(("sk-", "a" * 40))
                with self.assertRaisesRegex(ValueError, "secret-shaped"):
                    request_session_return(
                        state,
                        execution_id=execution.id,
                        attempt_id=execution.attempt_id,
                        actor="amir",
                        message=shaped,
                        expected_word_count=1,
                        idempotency_key="secret-return-0001",
                        now=T0,
                    )
                first = request_session_return(
                    state,
                    execution_id=execution.id,
                    attempt_id=execution.attempt_id,
                    actor="amir",
                    message="tek güvenli mesaj",
                    expected_word_count=3,
                    idempotency_key="single-return-0001",
                    now=T0,
                )
                replayed = request_session_return(
                    state,
                    execution_id=execution.id,
                    attempt_id=execution.attempt_id,
                    actor="amir",
                    message="tek güvenli mesaj",
                    expected_word_count=3,
                    idempotency_key="single-return-0001",
                    now=T0,
                )
                self.assertEqual(replayed.request_id, first.request_id)
                with self.assertRaisesRegex(ValueError, "already has"):
                    request_session_return(
                        state,
                        execution_id=execution.id,
                        attempt_id=execution.attempt_id,
                        actor="amir",
                        message="ikinci mesaj yasak",
                        expected_word_count=3,
                        idempotency_key="second-return-0001",
                        now=T0,
                    )

    def test_readback_prefers_latest_replay_epoch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution = self._leased(state)
                requested = request_session_return(
                    state,
                    execution_id=execution.id,
                    attempt_id=execution.attempt_id,
                    actor="amir",
                    message="yeniden teslim",
                    expected_word_count=2,
                    idempotency_key="replay-return-0001",
                    now=T0,
                )
                original = next(
                    item for item in claim_due(
                        state, worker="first", now=T0, lease_seconds=120,
                        deliver_after="2026-08-20T11:00:00Z", targets={"amir"}, limit=10,
                    )
                    if item.subject_id == requested.request_id
                )
                record_failure(
                    state,
                    outbox_id=original.id,
                    worker="first", claim_attempts=original.attempts,
                    detail="synthetic permanent failure",
                    transient=False,
                    now=T0,
                )
                replayed = replay(state, outbox_id=original.id, now=T0)
                claimed = next(
                    item for item in claim_due(
                        state, worker="second", now=T0, lease_seconds=120,
                        targets={"amir"}, limit=10,
                    )
                    if item.id == replayed.id
                )
                mark_delivered(
                    state,
                    outbox_id=claimed.id,
                    worker="second", claim_attempts=claimed.attempts,
                    now=T0,
                    provider_receipt="telegram-message-replay",
                )
                result = get_session_return(state, request_id=requested.request_id, actor="amir")
                self.assertEqual(result.delivery_id, replayed.id)
                self.assertEqual(result.status, "delivered")
                self.assertEqual(result.provider_receipt, "telegram-message-replay")

    def test_dispatch_gate_rejects_terminal_or_stale_attempt_before_network(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution = self._leased(state)
                self.assertIsNone(
                    session_return_dispatch_error(
                        state,
                        execution_id=execution.id,
                        attempt_id=execution.attempt_id,
                        target="amir",
                        now=T0,
                    )
                )
                complete_thread(
                    state,
                    execution.subject_id,
                    actor="amir",
                    actor_identity_bound=True,
                )
                self.assertIn(
                    "terminal",
                    session_return_dispatch_error(
                        state,
                        execution_id=execution.id,
                        attempt_id=execution.attempt_id,
                        target="amir",
                        now=T0,
                    ) or "",
                )
                self.assertIn(
                    "no longer live",
                    session_return_dispatch_error(
                        state,
                        execution_id=execution.id,
                        attempt_id="attempt_stale",
                        target="amir",
                        now=T0,
                    ) or "",
                )

    def test_message_is_bounded_and_idempotency_key_cannot_change_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution = self._leased(state)
                with self.assertRaisesRegex(ValueError, "4096 bytes"):
                    request_session_return(
                        state,
                        execution_id=execution.id,
                        attempt_id=execution.attempt_id,
                        actor="amir",
                        message="x" * 4097,
                        expected_word_count=None,
                        idempotency_key="large-return",
                        now=T0,
                    )
                request_session_return(
                    state,
                    execution_id=execution.id,
                    attempt_id=execution.attempt_id,
                    actor="amir",
                    message="ilk mesaj",
                    expected_word_count=2,
                    idempotency_key="same-key-00000001",
                    now=T0,
                )
                with self.assertRaisesRegex(ValueError, "idempotency key"):
                    request_session_return(
                        state,
                        execution_id=execution.id,
                        attempt_id=execution.attempt_id,
                        actor="amir",
                        message="başka mesaj",
                        expected_word_count=2,
                        idempotency_key="same-key-00000001",
                        now=T0,
                    )


class SessionReturnContinuationTests(unittest.TestCase):
    """Receipt-to-completion continuation: once a session return is delivered
    with a durable provider receipt, the same target/execution gets exactly
    one bounded continuation wake so it can read the receipt back and write
    canonical completion - even if its original model session already exited."""

    ENV = {
        "TEST_URL": "http://127.0.0.1:9999/wake",
        "TEST_SECRET": "test-route-secret",
        "RETURN_URL": "http://127.0.0.1:9998/session-return",
        "RETURN_SECRET": "return-route-secret",
    }
    ROUTE = AgentRoute(
        "amir", "hermes-webhook", "TEST_URL", "TEST_SECRET",
        return_url_env="RETURN_URL", return_credential_env="RETURN_SECRET",
    )

    def _requested(self, state: Path, *, receipt: str = "tg-provider-45543"):
        thread = post_thread(
            state, title="return to Elin", actor="esme", target="amir",
            actor_identity_bound=True,
        )
        acknowledge_thread(state, thread.thread.id, actor="amir", actor_identity_bound=True)
        execution = claim_execution(
            state, worker="return-worker", execution_capable_targets={"amir"},
            now=T0, lease_seconds=600,
        )
        requested = request_session_return(
            state,
            execution_id=execution.id,
            attempt_id=execution.attempt_id,
            actor="amir",
            message="tam yüz kelimelik hikaye",
            expected_word_count=4,
            idempotency_key="continuation-return-0001",
            now=T0,
        )
        adapter_log: list[tuple[str, str]] = []

        def deliverer(item, _route, **_kwargs):
            adapter_log.append((str(item.payload.get("delivery_mode", "wake")), item.id))
            if item.payload.get("delivery_mode") == "session_return":
                return AgentDeliveryResult(True, "accepted", 202, "accepted", receipt)
            return AgentDeliveryResult(True, "accepted", 202, "accepted")

        def tick():
            return dispatch_once(
                state,
                routes={"amir": self.ROUTE},
                worker="dispatcher-a",
                deliver_after="2026-08-20T11:00:00Z",
                now=T0,
                clock=lambda: T0,
                environ=self.ENV,
                deliverer=deliverer,
                limit=10,
                lease_seconds=300,
            )

        return thread.thread.id, execution, requested, adapter_log, tick

    def _continuations(self, state: Path):
        return [
            item for item in project_outbox(state).values()
            if item.payload.get("delivery_mode") == "session_return_receipt"
        ]

    def test_missing_unrelated_route_does_not_block_return_or_duplicate_send(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                post_thread(state, title="Unconfigured target", actor="esme", target="vesper")
                _, _, requested, adapter_log, tick = self._requested(state)
                first = tick()
                self.assertFalse(first.ok)
                self.assertEqual(first.skipped_unconfigured_targets, ("vesper",))
                delivered = get_session_return(state, request_id=requested.request_id, actor="amir")
                self.assertEqual(delivered.status, "delivered")
                self.assertEqual(delivered.provider_receipt, "tg-provider-45543")
                tick()
                tick()
                self.assertEqual([mode for mode, _ in adapter_log].count("session_return"), 1)
                self.assertEqual([mode for mode, _ in adapter_log].count("session_return_receipt"), 1)

    def test_delivered_receipt_enqueues_exactly_one_continuation_wake(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                _, execution, requested, adapter_log, tick = self._requested(state)

                tick()
                continuations = self._continuations(state)
                self.assertEqual(len(continuations), 1)
                continuation = continuations[0]
                # Bound to the exact target and execution attempt; content and
                # receipt stay behind the identity-scoped readback surface.
                self.assertEqual(continuation.target, "amir")
                self.assertEqual(continuation.subject_id, requested.request_id)
                self.assertEqual(continuation.payload["execution_id"], execution.id)
                self.assertEqual(continuation.payload["attempt_id"], execution.attempt_id)
                self.assertEqual(
                    continuation.payload["session_return_request_id"], requested.request_id
                )
                self.assertNotIn("message", continuation.payload)
                self.assertNotIn("provider_receipt", continuation.payload)
                # The receipt was durable before the continuation existed.
                self.assertEqual(
                    get_session_return(
                        state, request_id=requested.request_id, actor="amir"
                    ).provider_receipt,
                    "tg-provider-45543",
                )

                # The next tick delivers the continuation over the normal wake
                # route and never re-enters the session-return provider path.
                tick()
                modes = [mode for mode, _ in adapter_log]
                self.assertEqual(modes.count("session_return"), 1)
                self.assertIn("session_return_receipt", modes)
                delivered = self._continuations(state)[0]
                self.assertEqual(
                    project_outbox(state)[delivered.id].status, "delivered"
                )

                # Re-ticking never duplicates the continuation or the human-visible send.
                tick()
                self.assertEqual(len(self._continuations(state)), 1)
                self.assertEqual(
                    [mode for mode, _ in adapter_log].count("session_return"), 1
                )

    def test_provider_acceptance_after_execution_terminal_is_ambiguous(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                thread_id, _, requested, _, _ = self._requested(state)
                sends = []

                def deliverer(item, _route, **_kwargs):
                    if item.payload.get("delivery_mode") == "session_return":
                        sends.append(item.id)
                        complete_thread(state, thread_id, actor="amir", actor_identity_bound=True)
                        return AgentDeliveryResult(True, "accepted", 202, "accepted", "tg-race-receipt")
                    return AgentDeliveryResult(True, "accepted", 202, "accepted")

                result = dispatch_once(
                    state, routes={"amir": self.ROUTE}, worker="dispatcher-a",
                    deliver_after="2026-08-20T11:00:00Z", now=T0, clock=lambda: T0,
                    environ=self.ENV, deliverer=deliverer, limit=10, lease_seconds=300,
                )
                returned = get_session_return(state, request_id=requested.request_id, actor="amir")
                self.assertEqual(len(sends), 1)
                self.assertEqual(returned.status, "ambiguous_delivery")
                self.assertEqual(returned.provider_receipt, "tg-race-receipt")
                self.assertEqual(result.ambiguous, 1)
                self.assertEqual(self._continuations(state), [])

    def test_provider_acceptance_after_lease_or_attempt_change_is_ambiguous(self) -> None:
        for race in ("execution-expiry", "outbox-expiry", "reclaimed-attempt"):
            with self.subTest(race=race), tempfile.TemporaryDirectory() as tmp:
                state = Path(tmp) / "events.jsonl"
                vault = Path(tmp) / "vault"
                vault.mkdir(exist_ok=True)
                with authority_context(vault, state):
                    _, execution, requested, _, _ = self._requested(state)
                    clock = [T0]
                    sends = []

                    def deliverer(item, _route, **_kwargs):
                        if item.payload.get("delivery_mode") == "session_return":
                            sends.append(item.id)
                            clock[0] = T0 + timedelta(seconds=310 if race == "outbox-expiry" else 610)
                            if race == "reclaimed-attempt":
                                replacement = claim_execution(
                                    state, worker="replacement-worker", execution_capable_targets={"amir"},
                                    now=clock[0], lease_seconds=600, retry_backoff_seconds=0,
                                )
                                self.assertIsNotNone(replacement)
                                self.assertNotEqual(replacement.attempt_id, execution.attempt_id)
                            return AgentDeliveryResult(True, "accepted", 202, "accepted", "tg-race-receipt")
                        return AgentDeliveryResult(True, "accepted", 202, "accepted")

                    def tick():
                        return dispatch_once(
                            state, routes={"amir": self.ROUTE}, worker="dispatcher-a",
                            deliver_after="2026-08-20T11:00:00Z", now=clock[0], clock=lambda: clock[0],
                            environ=self.ENV, deliverer=deliverer, limit=10,
                            lease_seconds=300 if race == "outbox-expiry" else 900,
                        )

                    result = tick()
                    returned = get_session_return(state, request_id=requested.request_id, actor="amir")
                    self.assertEqual(len(sends), 1)
                    self.assertEqual(returned.status, "ambiguous_delivery")
                    self.assertEqual(returned.provider_receipt, "tg-race-receipt")
                    self.assertEqual(result.ambiguous, 1)
                    self.assertEqual(self._continuations(state), [])
                    tick()
                    self.assertEqual(len(sends), 1)

    def test_expired_return_lease_is_not_reclaimed_while_provider_is_in_flight(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                _, _, requested, _, _ = self._requested(state)
                clock = [T0]
                reclaimed = []
                original_claims = []

                def deliverer(item, _route, **_kwargs):
                    if item.payload.get("delivery_mode") == "session_return":
                        original_claims.append(item)
                        clock[0] = T0 + timedelta(seconds=310)
                        reclaimed.extend(claim_due(
                            state, worker="other-dispatcher", now=clock[0],
                            lease_seconds=300, limit=10, targets={"amir"},
                        ))
                        return AgentDeliveryResult(True, "accepted", 202, "accepted", "tg-late-receipt")
                    return AgentDeliveryResult(True, "accepted", 202, "accepted")

                result = dispatch_once(
                    state, routes={"amir": self.ROUTE}, worker="dispatcher-a",
                    deliver_after="2026-08-20T11:00:00Z", now=T0, clock=lambda: clock[0],
                    environ=self.ENV, deliverer=deliverer, limit=10, lease_seconds=300,
                )
                self.assertEqual([item for item in reclaimed if item.payload.get("delivery_mode") == "session_return"], [])
                returned = get_session_return(state, request_id=requested.request_id, actor="amir")
                self.assertEqual(returned.status, "ambiguous_delivery")
                self.assertEqual(returned.provider_receipt, "tg-late-receipt")
                self.assertEqual(result.ambiguous, 1)
                self.assertEqual(self._continuations(state), [])
                before = state.read_bytes()
                with self.assertRaisesRegex(ValueError, "original outbox claimant"):
                    mark_delivered(state, outbox_id=returned.delivery_id, claim_attempts=original_claims[0].attempts, worker="foreign-worker",
                                   now=clock[0], provider_receipt="tg-forged")
                with self.assertRaisesRegex(ValueError, "conflicts"):
                    mark_delivered(state, outbox_id=returned.delivery_id, claim_attempts=original_claims[0].attempts, worker="dispatcher-a",
                                   now=clock[0], provider_receipt="tg-conflicting")
                repeated = mark_delivered(state, outbox_id=returned.delivery_id, claim_attempts=original_claims[0].attempts, worker="dispatcher-a",
                                          now=clock[0], provider_receipt="tg-late-receipt")
                self.assertEqual(repeated.status, "ambiguous_delivery")
                self.assertEqual(state.read_bytes(), before)

    def test_receiptless_delivery_does_not_enqueue_continuation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                _, _, requested, _, tick = self._requested(state, receipt="")
                result = tick()
                self.assertEqual(result.ambiguous, 1)
                self.assertEqual(
                    get_session_return(state, request_id=requested.request_id, actor="amir").status,
                    "ambiguous_delivery",
                )
                tick()
                self.assertEqual(self._continuations(state), [])

    def test_terminal_subject_gets_no_continuation_or_provider_send(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                thread_id, _, _, adapter_log, tick = self._requested(state)
                complete_thread(state, thread_id, actor="amir", actor_identity_bound=True)
                tick()
                tick()
                self.assertEqual(
                    [mode for mode, _ in adapter_log].count("session_return"), 0
                )
                self.assertEqual(self._continuations(state), [])


class SessionReturnLineageTests(unittest.TestCase):
    """One human-visible return per execution lineage.

    A lease that expires after the return was requested or delivered is
    reclaimed under a new attempt_id. The fresh attempt must finalize the
    existing return, never send a second message; only a return that failed
    permanently frees the lineage for another request.
    """

    ENV = {
        "TEST_URL": "http://127.0.0.1:9999/wake",
        "TEST_SECRET": "test-route-material",
        "RETURN_URL": "http://127.0.0.1:9998/session-return",
        "RETURN_SECRET": "return-route-material",
    }
    ROUTE = AgentRoute(
        "amir", "hermes-webhook", "TEST_URL", "TEST_SECRET",
        return_url_env="RETURN_URL", return_credential_env="RETURN_SECRET",
    )
    LEASE_SECONDS = 600

    def _leased(self, state: Path, *, now=T0):
        thread = post_thread(
            state, title="return to Elin", actor="esme", target="amir",
            actor_identity_bound=True,
        )
        acknowledge_thread(state, thread.thread.id, actor="amir", actor_identity_bound=True)
        execution = claim_execution(
            state, worker="return-worker", execution_capable_targets={"amir"},
            now=now, lease_seconds=self.LEASE_SECONDS,
        )
        self.assertIsNotNone(execution)
        return execution

    def _request(self, state: Path, execution, *, key: str, now=T0):
        return request_session_return(
            state,
            execution_id=execution.id,
            attempt_id=execution.attempt_id,
            actor="amir",
            message="tam yüz kelimelik hikaye",
            expected_word_count=4,
            idempotency_key=key,
            now=now,
        )

    def _dispatch(self, state: Path, *, result: AgentDeliveryResult):
        def deliverer(item, _route, **_kwargs):
            if item.payload.get("delivery_mode") == "session_return":
                return result
            return AgentDeliveryResult(True, "accepted", 202, "accepted")

        return dispatch_once(
            state,
            routes={"amir": self.ROUTE},
            worker="dispatcher-a",
            deliver_after="2026-08-20T11:00:00Z",
            now=T0,
            clock=lambda: T0,
            environ=self.ENV,
            deliverer=deliverer,
            limit=5,
            lease_seconds=300,
        )

    def _reclaim(self, state: Path, execution):
        later = T0 + timedelta(seconds=self.LEASE_SECONDS + 120)
        reclaimed = claim_execution(
            state, worker="return-worker", execution_capable_targets={"amir"},
            now=later, lease_seconds=self.LEASE_SECONDS,
        )
        self.assertIsNotNone(reclaimed)
        self.assertEqual(reclaimed.id, execution.id)
        self.assertNotEqual(reclaimed.attempt_id, execution.attempt_id)
        return reclaimed, later

    def test_reclaimed_attempt_cannot_request_a_second_return_after_delivery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution = self._leased(state)
                first = self._request(state, execution, key="lineage-return-0001")
                self._dispatch(
                    state, result=AgentDeliveryResult(True, "accepted", 200, "sent", "tg-provider-1"),
                )
                reclaimed, later = self._reclaim(state, execution)

                visible = list_session_returns(state, execution_id=execution.id, actor="amir")
                self.assertEqual(
                    [(item.request_id, item.status, item.provider_receipt) for item in visible],
                    [(first.request_id, "delivered", "tg-provider-1")],
                )
                with self.assertRaisesRegex(ValueError, f"already has a session return {first.request_id}"):
                    self._request(state, reclaimed, key="lineage-return-0002", now=later)
                # The refusal names the readback tool so a fresh session knows how to finish.
                with self.assertRaisesRegex(ValueError, "control.execution_session_return_get"):
                    self._request(state, reclaimed, key="lineage-return-0003", now=later)

    def test_reclaimed_attempt_cannot_request_while_prior_return_is_in_flight(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution = self._leased(state)
                first = self._request(state, execution, key="lineage-return-0001")
                # Never dispatched: still "requested" with no outbox item at all.
                reclaimed, later = self._reclaim(state, execution)
                with self.assertRaisesRegex(ValueError, f"{first.request_id} \\(requested\\)"):
                    self._request(state, reclaimed, key="lineage-return-0002", now=later)

    def test_permanently_failed_return_frees_the_lineage_for_a_new_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution = self._leased(state)
                first = self._request(state, execution, key="lineage-return-0001")
                self._dispatch(
                    state,
                    result=AgentDeliveryResult(False, "permanent", 500, "provider rejected"),
                )
                self.assertEqual(
                    get_session_return(state, request_id=first.request_id, actor="amir").status,
                    "dead_lettered",
                )
                reclaimed, later = self._reclaim(state, execution)
                second = self._request(state, reclaimed, key="lineage-return-0002", now=later)
                self.assertNotEqual(second.request_id, first.request_id)
                self.assertEqual(second.attempt_id, reclaimed.attempt_id)
                statuses = {
                    item.request_id: item.status
                    for item in list_session_returns(state, execution_id=execution.id, actor="amir")
                }
                self.assertEqual(statuses, {first.request_id: "dead_lettered", second.request_id: "requested"})

    def test_ambiguous_return_requires_reconciliation_not_completion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution = self._leased(state)
                first = self._request(state, execution, key="lineage-return-0001")
                self._dispatch(
                    state,
                    result=AgentDeliveryResult(
                        False, "ambiguous", 202, "provider accepted but receipt was lost"
                    ),
                )
                reclaimed, later = self._reclaim(state, execution)

                with self.assertRaisesRegex(ValueError, "reconciliation required") as caught:
                    self._request(state, reclaimed, key="lineage-return-0002", now=later)

                self.assertIn(first.request_id, str(caught.exception))
                self.assertIn("do not complete the subject", str(caught.exception))

    def test_lineage_listing_is_identity_scoped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution = self._leased(state)
                self._request(state, execution, key="lineage-return-0001")
                self.assertEqual(list_session_returns(state, execution_id=execution.id, actor="esme"), [])
                with self.assertRaisesRegex(ValueError, "identity-bound target actor"):
                    list_session_returns(state, execution_id=execution.id, actor="")


class SessionReturnOwnerRoutingTests(unittest.TestCase):
    """L1-1: session-return traffic only ever reaches the execution owner.

    When the owner or its live attempt is gone, the item must land in a
    classified terminal state (or an explicit operator-visible anomaly), never
    in a send to someone else and never in an unclassified, replay-looping
    dead letter (production: five `execution attempt is no longer live` dead
    letters for amir with an empty resolution_category).
    """

    ENV = {
        "AMIR_URL": "http://127.0.0.1:9999/wake",
        "AMIR_SECRET": "amir-route-material",
        "AMIR_RETURN_URL": "http://127.0.0.1:9998/session-return",
        "AMIR_RETURN_SECRET": "amir-return-material",
        "ODIN_URL": "http://127.0.0.1:9997/wake",
        "ODIN_SECRET": "odin-route-material",
        "ODIN_RETURN_URL": "http://127.0.0.1:9996/session-return",
        "ODIN_RETURN_SECRET": "odin-return-material",
    }
    ROUTES = {
        "amir": AgentRoute(
            "amir", "hermes-webhook", "AMIR_URL", "AMIR_SECRET",
            return_url_env="AMIR_RETURN_URL", return_credential_env="AMIR_RETURN_SECRET",
        ),
        "odin": AgentRoute(
            "odin", "openclaw-hook", "ODIN_URL", "ODIN_SECRET",
            return_url_env="ODIN_RETURN_URL", return_credential_env="ODIN_RETURN_SECRET",
        ),
    }
    LEASE_SECONDS = 600

    def _leased(self, state: Path, *, target: str = "odin", now=T0):
        thread = post_thread(
            state, title="AMC session return", actor="elin", target=target,
            actor_identity_bound=True,
        )
        execution = claim_execution(
            state, worker="return-worker", execution_capable_targets={target},
            now=now, lease_seconds=self.LEASE_SECONDS,
        )
        self.assertIsNotNone(execution)
        return thread.thread.id, execution

    def _request(self, state: Path, execution, *, actor: str = "odin", key: str = "owner-return-0001", now=T0):
        return request_session_return(
            state,
            execution_id=execution.id,
            attempt_id=execution.attempt_id,
            actor=actor,
            message="tam yüz kelimelik hikaye",
            expected_word_count=4,
            idempotency_key=key,
            now=now,
        )

    def _dispatch(self, state: Path, *, now, sends: list[tuple[str, str]]):
        def deliverer(item, route, **_kwargs):
            sends.append((str(item.payload.get("delivery_mode", "direct")), route.agent_id))
            if item.payload.get("delivery_mode") == "session_return":
                return AgentDeliveryResult(True, "accepted", 200, "sent", "provider-message-1")
            return AgentDeliveryResult(True, "accepted", 202, "accepted")

        return dispatch_once(
            state,
            routes=self.ROUTES,
            worker="dispatcher-a",
            deliver_after="2026-08-20T11:00:00Z",
            now=now,
            clock=lambda: now,
            environ=self.ENV,
            deliverer=deliverer,
            limit=5,
            lease_seconds=300,
        )

    def _return_item(self, state: Path, request_id: str):
        return next(
            item for item in project_outbox(state).values()
            if item.subject_id == request_id and item.payload.get("delivery_mode") == "session_return"
        )

    def test_return_for_a_reclaimed_attempt_is_classified_superseded_not_left_actionable(self) -> None:
        from arvyx_control.api import _delivery_health

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                _, execution = self._leased(state)
                requested = self._request(state, execution)
                later = T0 + timedelta(seconds=self.LEASE_SECONDS + 120)
                reclaimed = claim_execution(
                    state, worker="return-worker", execution_capable_targets={"odin"},
                    now=later, lease_seconds=self.LEASE_SECONDS,
                )
                self.assertNotEqual(reclaimed.attempt_id, execution.attempt_id)
                sends: list[tuple[str, str]] = []
                self._dispatch(state, now=later, sends=sends)

                item = self._return_item(state, requested.request_id)
                self.assertNotIn(("session_return", "odin"), sends)
                self.assertEqual(item.target, "odin")
                self.assertEqual(item.status, "dead_lettered")
                self.assertIn("no longer live", item.failure_detail)
                self.assertIn(reclaimed.attempt_id, item.failure_detail)
                self.assertEqual(item.resolution_category, "superseded")
                self.assertEqual(item.resolved_by, "dispatcher")
                self.assertEqual(_delivery_health(state)["unresolved_dead_letters"], 0)
                # The lineage is free for the live attempt, and replaying the dead
                # attempt's return would only loop back into the same gate.
                with self.assertRaisesRegex(ValueError, "no longer live"):
                    replay(state, outbox_id=item.id, now=later)
                second = self._request(state, reclaimed, key="owner-return-0002", now=later)
                self.assertEqual(second.attempt_id, reclaimed.attempt_id)

    def test_return_for_a_terminal_subject_is_classified_terminal_elsewhere(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                thread_id, execution = self._leased(state)
                requested = self._request(state, execution)
                complete_thread(state, thread_id, actor="odin", actor_identity_bound=True)
                sends: list[tuple[str, str]] = []
                self._dispatch(state, now=T0, sends=sends)
                item = self._return_item(state, requested.request_id)
                self.assertEqual([send for send in sends if send[0] == "session_return"], [])
                self.assertEqual(item.status, "dead_lettered")
                self.assertEqual(item.resolution_category, "terminal_elsewhere")

    def test_forged_return_naming_a_non_owner_is_never_sent_and_stays_operator_visible(self) -> None:
        from arvyx_control.api import _delivery_health
        from arvyx_control.control import ControlEvent, _append_event

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                _, execution = self._leased(state)
                # A legacy/forged request event that names amir for odin's live attempt.
                _append_event(state, ControlEvent(
                    id="event_forged_return",
                    type="execution.session_return.requested",
                    task_id="session_return_forged",
                    timestamp="2026-08-20T12:00:00Z",
                    payload={
                        "request_id": "session_return_forged",
                        "execution_id": execution.id,
                        "attempt_id": execution.attempt_id,
                        "target": "amir",
                        "message": "başkasının dönüşü",
                        "message_sha256": hashlib.sha256("başkasının dönüşü".encode()).hexdigest(),
                        "word_count": 2,
                        "idempotency_key": "forged-return-0001",
                        "requested_at": "2026-08-20T12:00:00Z",
                        "status": "requested",
                        "delivery_id": "",
                        "provider_receipt": "",
                    },
                ))
                sends: list[tuple[str, str]] = []
                self._dispatch(state, now=T0, sends=sends)
                item = self._return_item(state, "session_return_forged")
                self.assertEqual(
                    [send for send in sends if send[0] == "session_return"], [],
                    "a non-owner session return reached a runtime",
                )
                self.assertEqual(item.status, "dead_lettered")
                self.assertIn("does not own", item.failure_detail)
                self.assertIn("odin", item.failure_detail)
                # Not something the system can classify on its own: keep it actionable.
                self.assertEqual(item.resolution_category, "")
                self.assertEqual(_delivery_health(state)["unresolved_dead_letters"], 1)
                # No continuation or other wake was ever created for the non-owner.
                self.assertEqual(
                    [entry for entry in project_outbox(state).values()
                     if entry.target == "amir" and entry.payload.get("delivery_mode") != "session_return"],
                    [],
                )

    def test_legacy_unclassified_no_longer_live_dead_letter_projects_and_is_operator_classifiable(self) -> None:
        """The production backlog shape: written before classification existed."""
        from arvyx_control.api import _delivery_health
        from arvyx_control.outbox import resolve_dead_letter

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                _, execution = self._leased(state, target="amir")
                requested = self._request(state, execution, actor="amir")
                item = next(
                    entry for entry in claim_due(
                        state, worker="old-dispatcher", now=T0, lease_seconds=120,
                        deliver_after="2026-08-20T11:00:00Z", targets={"amir"}, limit=10,
                    )
                    if entry.subject_id == requested.request_id
                )
                # Old dispatcher: permanent failure, no resolution fields at all.
                record_failure(
                    state, outbox_id=item.id, worker="old-dispatcher", claim_attempts=item.attempts,
                    detail="session return execution attempt is no longer live",
                    transient=False, now=T0,
                )
                later = T0 + timedelta(seconds=self.LEASE_SECONDS + 120)
                claim_execution(
                    state, worker="return-worker", execution_capable_targets={"amir"},
                    now=later, lease_seconds=self.LEASE_SECONDS,
                )
                legacy = project_outbox(state)[item.id]
                self.assertEqual(legacy.status, "dead_lettered")
                self.assertEqual(legacy.resolution_category, "")
                self.assertEqual(_delivery_health(state, now=later)["unresolved_dead_letters"], 1)
                # Replay can only loop into the gate again, so it is refused ...
                with self.assertRaisesRegex(ValueError, "session return replay refused"):
                    replay(state, outbox_id=item.id, now=later)
                # ... and the operator classifies it append-only instead.
                resolved = resolve_dead_letter(
                    state, outbox_id=item.id, resolution_category="superseded",
                    resolved_by="operator", detail="attempt reclaimed; live attempt owns any new return",
                    now=later,
                )
                self.assertEqual(resolved.resolution_category, "superseded")
                self.assertEqual(_delivery_health(state, now=later)["unresolved_dead_letters"], 0)

    def test_continuation_wake_is_bound_to_the_execution_owner(self) -> None:
        from dataclasses import replace as dc_replace

        from arvyx_control.session_return import enqueue_session_return_continuation

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                _, execution = self._leased(state)
                requested = self._request(state, execution)
                sends: list[tuple[str, str]] = []
                self._dispatch(state, now=T0, sends=sends)
                delivered = self._return_item(state, requested.request_id)
                self.assertEqual(delivered.status, "delivered")
                continuations = [
                    item for item in project_outbox(state).values()
                    if item.payload.get("delivery_mode") == "session_return_receipt"
                ]
                self.assertEqual([item.target for item in continuations], ["odin"])

                # A delivered return whose outbox target disagrees with the owner
                # (legacy/forged) must never mint a wake for that other identity.
                enqueue_session_return_continuation(
                    state, dc_replace(delivered, id="outbox_forged", target="amir"), now=T0,
                )
                self.assertEqual(
                    [item.target for item in project_outbox(state).values()
                     if item.payload.get("delivery_mode") == "session_return_receipt"],
                    ["odin"],
                )


if __name__ == "__main__":
    unittest.main()
