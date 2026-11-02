"""Operator decision cards: ask from a live attempt, park, answer through the gateway, resume."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from arvyx_control.replica_authority import authority_context
from arvyx_control.agent_delivery import AgentRoute
from arvyx_control.control import acknowledge_thread, post_thread, read_events
from arvyx_control.decisions import (
    DECISION_CARD_MODE,
    DECISION_HOLD_PREFIX,
    answer_decision,
    classify_decision_card_dispatch,
    decision_nonce,
    project_decisions,
    request_decision,
)
from arvyx_control.execution import claim_execution, project_executions
from arvyx_control.outbox import claim_due, mark_delivered, project_outbox
from arvyx_control.watchdog import run_watchdog

UTC = timezone.utc
T0 = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)
SECRET_ENV = {"ARVYX_V2_CONTROL_SECRET": "unit-test-control-secret-material",
              "ARVYX_DECISION_OPERATOR_USER_IDS": "1111, 2222"}
FIRST_REQUEST = "decision-request-first-attempt"


class DecisionTests(unittest.TestCase):
    def _leased(self, state: Path, target: str = "amir"):
        with patch("arvyx_control.control._now", side_effect=["2026-08-20T11:59:00Z", "2026-08-20T12:00:00Z"]):
            thread = post_thread(state, title="needs a ruling", actor="esme", target=target,
                                 thread_type="ask", actor_identity_bound=True)
            acknowledge_thread(state, thread.thread.id, actor=target, actor_identity_bound=True)
        execution = claim_execution(state, worker="w", execution_capable_targets={target}, now=T0, lease_seconds=600)
        assert execution is not None
        return execution

    def _ask(self, state: Path, execution, **overrides):
        args = dict(execution_id=execution.id, attempt_id=execution.attempt_id, actor=execution.target,
                    question="Deploy X to prod?", allow_text=True, idempotency_key=FIRST_REQUEST,
                    now=T0 + timedelta(seconds=5))
        args.update(overrides)
        return request_decision(state, **args)

    def _deliver_card(self, state: Path, receipt: str = "7001"):
        delivery_claims = claim_due(state, worker="dispatch", now=T0 + timedelta(seconds=10))
        card = next(i for i in project_outbox(state).values() if i.payload.get("delivery_mode") == DECISION_CARD_MODE)
        mark_delivered(state, outbox_id=card.id, worker="dispatch", claim_attempts=next(c.attempts for c in delivery_claims if c.id == card.id), now=T0 + timedelta(seconds=10),
                       provider_receipt=receipt)
        return card

    def _answer(self, state: Path, decision, **overrides):
        args = dict(decision_id=decision.decision_id, actor=decision.target, choice="approve", text="",
                    nonce=decision_nonce(decision.decision_id, environ=SECRET_ENV), operator_user_id="1111",
                    platform="telegram", message_id="7001", now=T0 + timedelta(seconds=20), environ=SECRET_ENV)
        args.update(overrides)
        return answer_decision(state, **args)

    def test_authority_clock_follows_lock_and_projection_reads(self) -> None:
        # NOT_EXECUTED: deterministic lock/projection delays without sleeps.
        from contextlib import contextmanager
        from arvyx_control import decisions, execution as lifecycle

        for operation in ("heartbeat", "session", "steer", "decision"):
            for injected in (False, True):
                with self.subTest(operation=operation, injected=injected), tempfile.TemporaryDirectory() as tmp:
                    state = Path(tmp) / "events.jsonl"
                    vault = Path(tmp) / "vault"
                    vault.mkdir(exist_ok=True)
                    with authority_context(vault, state):
                        leased = self._leased(state)
                        before = read_events(state)
                        moment = [T0 + timedelta(seconds=599)]
                        real_lock = lifecycle._locked_state
                        real_projection = lifecycle.project_executions
                        real_fold = lifecycle._project_executions

                        @contextmanager
                        def delayed_lock(path):
                            with real_lock(path):
                                moment[0] = T0 + timedelta(seconds=600)
                                yield

                        def delayed_projection(*args, **kwargs):
                            result = real_projection(*args, **kwargs)
                            moment[0] = T0 + timedelta(seconds=601)
                            return result

                        def delayed_fold(*args, **kwargs):
                            result = real_fold(*args, **kwargs)
                            moment[0] = T0 + timedelta(seconds=601)
                            return result

                        class Clock(datetime):
                            @classmethod
                            def now(cls, tz=None):
                                return moment[0]

                        clock = T0 + timedelta(seconds=599) if injected else None
                        def invoke():
                            common = dict(execution_id=leased.id, attempt_id=leased.attempt_id, now=clock)
                            if operation == "heartbeat":
                                return lifecycle.heartbeat_execution(state, worker="w", **common)
                            if operation == "session":
                                return lifecycle.execution_session(state, actor=leased.target, **common)
                            if operation == "steer":
                                return lifecycle.request_execution_steer(
                                    state, requested_by="operator", message="pause here",
                                    idempotency_key="lease-authority-steer-key", **common)
                            return self._ask(state, leased, now=clock)

                        with patch.object(lifecycle, "_locked_state", delayed_lock), \
                             patch.object(decisions, "_locked_state", delayed_lock), \
                             patch.object(lifecycle, "datetime", Clock), \
                             patch.object(decisions, "datetime", Clock), \
                             patch.object(lifecycle, "project_executions", side_effect=delayed_projection), \
                             patch.object(decisions, "project_executions", side_effect=delayed_projection), \
                             patch.object(lifecycle, "_project_executions", side_effect=delayed_fold):
                            if injected:
                                self.assertIsNotNone(invoke())
                            else:
                                with self.assertRaisesRegex(ValueError, "lease expired"):
                                    invoke()
                        if not injected:
                            self.assertEqual(read_events(state), before)
                            self.assertEqual(project_executions(state)[leased.id], leased)

    def test_request_parks_the_execution_and_queues_exactly_one_card_without_the_nonce(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution = self._leased(state)
                decision = self._ask(state, execution)
                again = self._ask(state, execution)  # exact retry
                self.assertEqual(decision, again)
                held = project_executions(state)[execution.id]
                self.assertEqual(held.status, "held")
                self.assertEqual(held.hold_reason, DECISION_HOLD_PREFIX + decision.decision_id)
                cards = [i for i in project_outbox(state).values() if i.payload.get("delivery_mode") == DECISION_CARD_MODE]
                self.assertEqual(len(cards), 1)
                nonce = decision_nonce(decision.decision_id, environ=SECRET_ENV)
                self.assertNotIn(nonce, state.read_text())

    def test_one_open_decision_per_execution_and_stale_attempts_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution = self._leased(state)
                self._ask(state, execution)
                with self.assertRaisesRegex(ValueError, "not live|already awaits|stale"):
                    self._ask(state, execution, idempotency_key="decision-request-second-attempt")

    def test_every_forged_or_wrong_answer_is_refused_without_appending(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution = self._leased(state)
                decision = self._ask(state, execution)
                # Before the card is delivered there is no message to answer.
                before = state.read_bytes()
                with self.assertRaisesRegex(ValueError, "delivered card"):
                    self._answer(state, decision)
                self.assertEqual(state.read_bytes(), before)
                self._deliver_card(state)
                cases = [
                    ({"nonce": "0" * 32}, "proof is invalid"),
                    ({"operator_user_id": "9999"}, "allowed operator"),
                    ({"message_id": "7002"}, "delivered card"),
                    ({"actor": "kiran"}, "own gateway"),
                    ({"choice": "maybe"}, "choice"),
                    ({"choice": "text", "text": ""}, "non-empty text"),
                    ({"choice": "approve", "text": "and also"}, "only a text"),
                    ({"environ": {"ARVYX_V2_CONTROL_SECRET": "unit-test-control-secret-material"}}, "allowlist is not configured"),
                ]
                for overrides, message in cases:
                    with self.subTest(case=overrides):
                        before = state.read_bytes()
                        with self.assertRaisesRegex(ValueError, message):
                            self._answer(state, decision, **overrides)
                        self.assertEqual(state.read_bytes(), before)

    def test_answer_records_the_decision_and_resumes_the_same_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution = self._leased(state)
                decision = self._ask(state, execution)
                self._deliver_card(state)
                answered = self._answer(state, decision, choice="text", text="Evet, ama önce yedek al.")
                self.assertEqual((answered.status, answered.choice, answered.answered_by), ("answered", "text", "operator"))
                resumed = project_executions(state)[execution.id]
                self.assertEqual((resumed.status, resumed.attempts, resumed.hold_reason), ("pending", 0, ""))
                # Exact retry is idempotent; a different answer is refused.
                self.assertEqual(self._answer(state, decision, choice="text", text="Evet, ama önce yedek al."), answered)
                with self.assertRaisesRegex(ValueError, "already answered"):
                    self._answer(state, decision, choice="deny")
                self.assertEqual(project_decisions(state)[decision.decision_id].choice, "text")

    def test_text_answer_is_refused_when_the_card_does_not_allow_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution = self._leased(state)
                decision = self._ask(state, execution, allow_text=False)
                self._deliver_card(state)
                with self.assertRaisesRegex(ValueError, "does not accept a text"):
                    self._answer(state, decision, choice="text", text="free text")
                self.assertEqual(self._answer(state, decision, choice="deny").choice, "deny")

    def test_answered_cards_are_not_dispatched_and_parked_executions_are_not_escalated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution = self._leased(state)
                decision = self._ask(state, execution)
                self.assertIsNone(classify_decision_card_dispatch(state, decision_id=decision.decision_id, target="amir"))
                self.assertIn("target", classify_decision_card_dispatch(state, decision_id=decision.decision_id, target="kiran"))
                routes = {"amir": AgentRoute("amir", "hermes-webhook", "WD_URL", "WD_SECRET")}
                env = {"WD_URL": "https://runtime.invalid/hook", "WD_SECRET": "secret-material"}
                report = run_watchdog(state, routes=routes, now=T0 + timedelta(minutes=5), environ=env)
                self.assertEqual(report["escalated"], [])
                self._deliver_card(state)
                self._answer(state, decision)
                self.assertIn("already answered",
                              classify_decision_card_dispatch(state, decision_id=decision.decision_id, target="amir"))

    def test_http_answer_route_needs_the_target_identity_and_resumes_the_execution(self) -> None:
        import os
        from arvyx_control.api import handle_api_request
        from arvyx_control.auth import issue_token
        from arvyx_control.vault import init_vault

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                vault = Path(tmp) / "vault"
                init_vault(vault)
                amir = issue_token(vault, "demobot", scopes=["control.write", "control.read"]).token
                kiran = issue_token(vault, "vesper", scopes=["control.write", "control.read"]).token
                execution = self._leased(state, target="demobot")
                decision = self._ask(state, execution)
                self._deliver_card(state)
                body = {"choice": "approve", "text": "", "platform": "telegram", "chat_id": "42", "message_id": "7001",
                        "operator_user_id": "1111", "nonce": decision_nonce(decision.decision_id, environ=SECRET_ENV)}
                seq = iter(range(100))

                def call(token: str, payload: dict):
                    return handle_api_request(
                        method="POST", path=f"/decisions/{decision.decision_id}/answer", body=payload, vault=vault,
                        state=state, bearer_secret="operator-secret-for-decision-tests",
                        authorization=f"Bearer {token}", idempotency_key=f"decision-answer-test-{next(seq):04d}",
                    )

                with patch.dict(os.environ, SECRET_ENV, clear=False):
                    wrong_gateway = call(kiran, body)
                    forged = call(amir, {**body, "nonce": "f" * 32})
                    unknown_field = call(amir, {**body, "answered_by": "operator"})
                    self.assertNotEqual(project_executions(state)[execution.id].status, "pending")
                    ok = call(amir, body)
                self.assertEqual(wrong_gateway.status, 400)
                self.assertEqual(forged.status, 400)
                self.assertEqual(unknown_field.status, 400)
                self.assertEqual((ok.status, ok.body["ok"], ok.body["choice"]), (200, True, "approve"))
                self.assertEqual(project_executions(state)[execution.id].status, "pending")

    def test_an_expired_card_lease_is_fenced_never_resent_and_a_late_receipt_still_answers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution = self._leased(state)
                decision = self._ask(state, execution)
                leased = claim_due(state, worker="dispatch-a", now=T0 + timedelta(seconds=10), lease_seconds=30)
                card = next(i for i in leased if i.payload.get("delivery_mode") == DECISION_CARD_MODE)
                # The sender is still inside provider I/O when the lease expires; the next tick
                # must fence the card instead of sending the operator a second copy.
                reclaimed = claim_due(state, worker="dispatch-b", now=T0 + timedelta(seconds=100), lease_seconds=30)
                self.assertNotIn(card.id, [i.id for i in reclaimed])
                self.assertEqual(project_outbox(state)[card.id].status, "ambiguous_delivery")
                # The original sender's late receipt is attached to the fenced card.
                mark_delivered(state, outbox_id=card.id, worker="dispatch-a", claim_attempts=next(c.attempts for c in leased if c.id == card.id), now=T0 + timedelta(seconds=101),
                               provider_receipt="7001")
                self.assertEqual(project_outbox(state)[card.id].provider_receipt, "7001")
                self.assertEqual(self._answer(state, decision).status, "answered")

    def test_an_operator_replay_supersedes_an_open_decision(self) -> None:
        from arvyx_control.execution import replay_execution

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution = self._leased(state)
                decision = self._ask(state, execution)
                self._deliver_card(state)
                replay_execution(state, execution_id=execution.id, replayed_by="operator", now=T0 + timedelta(seconds=30))
                self.assertIn("no longer awaited",
                              classify_decision_card_dispatch(state, decision_id=decision.decision_id, target="amir"))
                before = state.read_bytes()
                with self.assertRaisesRegex(ValueError, "no longer awaited"):
                    self._answer(state, decision)
                self.assertEqual(state.read_bytes(), before)
                # The lineage can ask again on its new attempt.
                fresh = claim_execution(state, worker="w", execution_capable_targets={"amir"},
                                        now=T0 + timedelta(seconds=40), lease_seconds=600)
                again = self._ask(state, fresh, idempotency_key="decision-request-after-replay",
                                  now=T0 + timedelta(seconds=45))
                self.assertNotEqual(again.decision_id, decision.decision_id)

    def test_the_watchdog_restores_a_card_lost_between_park_and_enqueue(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution = self._leased(state)
                with patch("arvyx_control.decisions.enqueue", side_effect=RuntimeError("crash after park")):
                    with self.assertRaises(RuntimeError):
                        self._ask(state, execution)
                self.assertEqual(project_executions(state)[execution.id].status, "held")
                self.assertEqual([i for i in project_outbox(state).values()
                                  if i.payload.get("delivery_mode") == DECISION_CARD_MODE], [])
                routes = {"amir": AgentRoute("amir", "hermes-webhook", "WD_URL", "WD_SECRET")}
                env = {"WD_URL": "https://runtime.invalid/hook", "WD_SECRET": "secret-material"}
                first = run_watchdog(state, routes=routes, now=T0 + timedelta(minutes=2), environ=env, escalate=False)
                second = run_watchdog(state, routes=routes, now=T0 + timedelta(minutes=3), environ=env, escalate=False)
                self.assertEqual(first["counts"]["decision_cards_restored"], 1)
                self.assertEqual(second["counts"]["decision_cards_restored"], 0)
                cards = [i for i in project_outbox(state).values() if i.payload.get("delivery_mode") == DECISION_CARD_MODE]
                self.assertEqual(len(cards), 1)

    def test_nonce_requires_the_server_secret(self) -> None:
        with self.assertRaisesRegex(ValueError, "secret is not configured"):
            decision_nonce("decision_" + "0" * 24, environ={})


if __name__ == "__main__":
    unittest.main()


class DecisionCardTargetTests(unittest.TestCase):
    def test_card_capability_is_per_agent_and_defaults_to_everyone(self) -> None:
        from arvyx_control.decisions import decision_cards_enabled_for
        self.assertTrue(decision_cards_enabled_for("harbor", environ={}))
        env = {"ARVYX_DECISION_CARD_TARGETS": "sage, Juniper,keeper"}
        self.assertTrue(decision_cards_enabled_for("juniper", environ=env))
        self.assertFalse(decision_cards_enabled_for("harbor", environ=env))

    def test_an_agent_without_cards_is_told_to_ask_directly(self) -> None:
        from unittest.mock import patch
        import os
        from arvyx_control.agent_delivery import _decision_contract
        from arvyx_control.decisions import request_decision
        # NOT_EXECUTED: the refusal must use only this test's exact owned state.
        with tempfile.TemporaryDirectory() as authority_tmp:
            root = Path(authority_tmp)
            vault = root / "vault"
            vault.mkdir()
            state = root / "private-state" / "events.jsonl"
            with authority_context(vault, state), patch.dict(
                os.environ, {"ARVYX_DECISION_CARD_TARGETS": "sage,juniper,keeper"}
            ):
                direct = _decision_contract("harbor")
                card = _decision_contract("keeper")
                with self.assertRaisesRegex(ValueError, "ask the operator directly"):
                    request_decision(state, execution_id="execution_x", attempt_id="attempt_x",
                                     actor="harbor", question="Deploy?", allow_text=False,
                                     idempotency_key="decision-ask-directly-please")
                self.assertFalse(state.exists())
        self.assertIn("ask the operator directly", direct)
        self.assertNotIn("control.decision_request once", direct)
        self.assertIn("control.decision_request once", card)

