"""Operator decision cards: a blocked agent asks, the operator answers, the work resumes on its own.

Lifecycle (append-only, one open decision per execution lineage):

1. ``request_decision`` - the identity-bound target of a LIVE leased attempt asks one
   question. The decision is recorded, the execution parks in HOLD with the reason
   ``awaiting operator decision <id>`` (not the BLOCKED prefix, so the watchdog does not
   escalate it to the operator dashboard), and one ``decision_card`` outbox item is
   queued to the agent's fixed session-return route (its own bot, the operator's chat).
2. The dispatcher delivers the card with a per-decision nonce derived at send time
   from the server secret. The nonce is never persisted, never in the outbox payload,
   and never on any agent-readable surface; the card's buttons carry it.
3. ``answer_decision`` - the agent's gateway code (not its model) posts the operator's button
   press or text reply. It is accepted only with the right nonce, the card's exact
   provider message id, and an operator user id from the configured allowlist. The
   answer is recorded and the parked execution is replayed, so the worker wakes the
   agent with the decision visible in ``control.execution_session_get``.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import hmac
import os
from pathlib import Path
from typing import Mapping, Sequence

from . import projection_cache
from .control import ControlEvent, _append_event_unlocked, _event, _locked_state, read_events
from .execution import project_executions
from .outbox import enqueue, project_outbox
from .security import contains_literal_secret, redact_secrets

DECISION_REQUESTED_EVENT = "decision.requested"
DECISION_ANSWERED_EVENT = "decision.answered"
DECISION_CARD_MODE = "decision_card"
DECISION_HOLD_PREFIX = "awaiting operator decision "
QUESTION_MAX_BYTES = 1500
ANSWER_TEXT_MAX_BYTES = 2000
NONCE_SECRET_ENV = "ARVYX_V2_CONTROL_SECRET"
OPERATOR_IDS_ENV = "ARVYX_DECISION_OPERATOR_USER_IDS"
#: Agents whose gateway renders decision cards (comma list). Unset = every agent. Harbor's runtime
#: has no card surface: by the operator's call (2026-09-25) it asks the operator directly instead.
CARD_TARGETS_ENV = "ARVYX_DECISION_CARD_TARGETS"
CHOICES = frozenset({"approve", "deny", "text"})
_NONCE_DOMAIN = b"arvyx-decision-card-nonce/v1\0"


@dataclass(frozen=True)
class Decision:
    decision_id: str
    execution_id: str
    attempt_id: str
    target: str
    subject_id: str
    subject_type: str
    question: str
    allow_text: bool
    idempotency_key: str
    requested_at: str
    status: str = "requested"
    choice: str = ""
    text: str = ""
    answered_by: str = ""
    answered_at: str = ""
    answer_platform: str = ""
    answer_message_id: str = ""

    def to_dict(self) -> dict[str, object]:
        return dict(self.__dict__)


def _timestamp(value: datetime | None = None) -> str:
    current = value or datetime.now(timezone.utc)
    return current.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def decision_cards_enabled_for(target: str, *, environ: Mapping[str, str] | None = None) -> bool:
    env = os.environ if environ is None else environ
    raw = env.get(CARD_TARGETS_ENV, "").strip()
    if not raw:
        return True
    return target.strip().casefold() in {part.strip().casefold() for part in raw.split(",") if part.strip()}


def decision_nonce(decision_id: str, *, environ: Mapping[str, str] | None = None) -> str:
    """Per-decision nonce, derived on demand and never stored."""
    env = os.environ if environ is None else environ
    secret = env.get(NONCE_SECRET_ENV, "").strip()
    if not secret:
        raise ValueError(f"decision nonce secret is not configured: {NONCE_SECRET_ENV}")
    return hmac.new(secret.encode(), _NONCE_DOMAIN + decision_id.encode(), hashlib.sha256).hexdigest()[:32]


def _decision_from_payload(payload: Mapping[str, object]) -> Decision:
    return Decision(
        decision_id=str(payload["decision_id"]),
        execution_id=str(payload["execution_id"]),
        attempt_id=str(payload["attempt_id"]),
        target=str(payload["target"]),
        subject_id=str(payload.get("subject_id", "")),
        subject_type=str(payload.get("subject_type", "")),
        question=str(payload.get("question", "")),
        allow_text=payload.get("allow_text") is True,
        idempotency_key=str(payload.get("idempotency_key", "")),
        requested_at=str(payload.get("requested_at", "")),
        status=str(payload.get("status", "requested")),
        choice=str(payload.get("choice", "")),
        text=str(payload.get("text", "")),
        answered_by=str(payload.get("answered_by", "")),
        answered_at=str(payload.get("answered_at", "")),
        answer_platform=str(payload.get("answer_platform", "")),
        answer_message_id=str(payload.get("answer_message_id", "")),
    )


def _fold_decisions(decisions: dict[str, Decision], events: Sequence[ControlEvent]) -> dict[str, Decision]:
    for event in events:
        if event.type in (DECISION_REQUESTED_EVENT, DECISION_ANSWERED_EVENT):
            decision = _decision_from_payload(event.payload)
            decisions[decision.decision_id] = decision
    return decisions


_DECISION_FIELDS = frozenset(Decision.__dataclass_fields__)


def _decisions_seed(events: Sequence[ControlEvent]) -> dict[str, object]:
    # Insertion order is part of the projection: the seed keeps it exactly.
    return {"decisions": [decision.to_dict() for decision in _fold_decisions({}, events).values()]}


def _decisions_seed_state(seed: object) -> dict[str, Decision]:
    if not isinstance(seed, dict) or set(seed) != {"decisions"} or not isinstance(seed["decisions"], list):
        raise ValueError("decisions seed is malformed")
    decisions: dict[str, Decision] = {}
    for value in seed["decisions"]:
        if not isinstance(value, dict) or set(value) != _DECISION_FIELDS:
            raise ValueError("decisions seed entry is malformed")
        for field, field_value in value.items():
            if not isinstance(field_value, bool if field == "allow_text" else str):
                raise ValueError("decisions seed entry is malformed")
        decision = Decision(**value)  # type: ignore[arg-type]
        if not decision.decision_id:
            raise ValueError("decisions seed entry is malformed")
        decisions[decision.decision_id] = decision
    return decisions


def _valid_decisions_seed(seed: object) -> bool:
    try:
        _decisions_seed_state(seed)
    except (TypeError, ValueError):
        return False
    return True


projection_cache.register_seed("decisions", builder=_decisions_seed, validator=_valid_decisions_seed)


def project_decisions(state: Path, events: Sequence[ControlEvent] | None = None) -> dict[str, Decision]:
    """Decisions by id. Reads the projection checkpoint plus the log tail, like executions and
    outbox: a full parse of a 130 MiB log cost ~4.7 s per call, and answering a card pays it
    under the state lock."""
    if events is not None:
        return _fold_decisions({}, events)
    seed, tail, source = projection_cache.projection_source(state, "decisions")
    if source == "checkpoint":
        return _fold_decisions(_decisions_seed_state(seed), tail)
    return _fold_decisions({}, tail)


def decisions_for_execution(state: Path, execution_id: str, *, actor: str) -> list[dict[str, object]]:
    """Decisions on one lineage, for its identity-bound target only."""
    normalized = actor.strip().casefold()
    return [
        decision.to_dict()
        for decision in sorted(project_decisions(state).values(), key=lambda d: (d.requested_at, d.decision_id))
        if decision.execution_id == execution_id and decision.target == normalized
    ]


def _is_awaited(decision: Decision, executions: Mapping[str, object],
                events: Sequence[ControlEvent]) -> bool:
    """Exact request-owned HOLD validation; caller holds the state lock."""
    from .execution import EXECUTION_EVENT_TYPES, _is_authoritative_terminal
    from .operator_archive import archived_ids

    execution = executions.get(decision.execution_id)
    if (decision.status != "requested" or execution is None
            or execution.status != "held"
            or execution.hold_reason != DECISION_HOLD_PREFIX + decision.decision_id
            or execution.held_by != decision.target
            or execution.target.strip().casefold() != decision.target
            or execution.attempt_id != decision.attempt_id
            or execution.subject_id != decision.subject_id
            or execution.subject_type != decision.subject_type
            or execution.subject_id in archived_ids(events)
            or any(_is_authoritative_terminal(event, execution) for event in events)):
        return False
    requests = [i for i, event in enumerate(events)
                if event.type == DECISION_REQUESTED_EVENT
                and event.task_id == decision.decision_id]
    if len(requests) != 1 or _decision_from_payload(events[requests[0]].payload) != decision:
        return False
    writes = [event for event in events[requests[0] + 1:]
              if event.task_id == execution.id and event.type in EXECUTION_EVENT_TYPES]
    return (len(writes) == 1 and writes[0].type == "execution.held"
            and writes[0].payload == execution.to_dict())


def reconcile_decision_transitions(state: Path, *, now: datetime | None = None) -> list[str]:
    """Recover paired writes under the state fence; return repaired execution IDs."""
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    with _locked_state(state):
        return _reconcile_decision_transitions_unlocked(state, now=now)


def _reconcile_decision_transitions_unlocked(
    state: Path, *, now: datetime | None = None, decision_id: str | None = None,
    capable: set[str] | None = None,
) -> list[str]:
    """Caller MUST hold _locked_state. Never acquire it or call a locking API here.

    Log order, not timestamps, fences recovery. Any execution-state write after
    the decision event supersedes its missing pair, even an operator restoring
    exactly the same hold reason. Never infer ownership from a reason alone.
    """
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    from .execution import EXECUTION_EVENT_TYPES, _is_authoritative_terminal
    from .operator_archive import archived_ids

    events = read_events(state)
    decisions = project_decisions(state, events)
    executions = project_executions(state, events=events)
    archived = archived_ids(events)
    latest_execution: dict[str, int] = {}
    latest_decision: dict[str, int] = {}
    terminals: dict[tuple[str, str], list[ControlEvent]] = {}
    for index, event in enumerate(events):
        if event.type in EXECUTION_EVENT_TYPES:
            latest_execution[event.task_id] = index
        elif event.type in (DECISION_REQUESTED_EVENT, DECISION_ANSWERED_EVENT):
            latest_decision[event.task_id] = index
        elif event.type in ("thread.done", "handoff.completed"):
            terminals.setdefault((event.type, event.task_id), []).append(event)
    repaired: list[str] = []
    stamp = _timestamp(now)
    for decision in decisions.values():
        if decision_id is not None and decision.decision_id != decision_id:
            continue
        execution = executions.get(decision.execution_id)
        if execution is not None and capable is not None and execution.target.strip().casefold() not in capable:
            continue
        if (execution is None or execution.subject_id in archived
                or execution.attempt_id != decision.attempt_id
                or execution.target.strip().casefold() != decision.target
                or execution.subject_id != decision.subject_id
                or execution.subject_type != decision.subject_type):
            continue
        boundary = latest_decision.get(decision.decision_id, -1)
        if latest_execution.get(execution.id, -1) >= boundary:
            continue
        terminal_type = "thread.done" if execution.subject_type == "thread" else "handoff.completed"
        if any(_is_authoritative_terminal(event, execution)
               for event in terminals.get((terminal_type, execution.subject_id), ())):
            continue
        if decision.status == "requested" and execution.status == "leased":
            updated = replace(
                execution, status="held", updated_at=stamp, lease_owner="", lease_expires_at="",
                hold_reason=DECISION_HOLD_PREFIX + decision.decision_id, held_by=decision.target,
            )
            event_type = "execution.held"
            payload = updated.to_dict()
        elif (decision.status == "answered" and execution.status == "held"
              and execution.hold_reason == DECISION_HOLD_PREFIX + decision.decision_id
              and execution.held_by == decision.target):
            # The hold itself must belong to this request, not an operator who
            # reused its display reason before the durable answer.
            hold = events[latest_execution[execution.id]]
            request_index = next((i for i, event in enumerate(events)
                                  if event.type == DECISION_REQUESTED_EVENT
                                  and event.task_id == decision.decision_id), -1)
            if (hold.type != "execution.held" or request_index < 0
                    or latest_execution[execution.id] <= request_index
                    or any(event.task_id == execution.id and event.type in EXECUTION_EVENT_TYPES
                           for event in events[request_index + 1:latest_execution[execution.id]])):
                continue
            updated = replace(
                execution, status="pending", attempts=0, updated_at=stamp, lease_owner="",
                lease_expires_at="", attempt_id="", hold_reason="", held_by="",
            )
            event_type = "execution.replayed"
            payload = updated.to_dict()
            payload["replayed_by"] = "decision:" + decision.decision_id
            payload["replayed_from_status"] = "held"
        else:
            continue
        _append_event_unlocked(state, _event(event_type, execution.id, stamp, payload))
        executions[execution.id] = updated
        latest_execution[execution.id] = len(events) + len(repaired)
        repaired.append(execution.id)
    return repaired


def awaited_decisions(state: Path) -> list[Decision]:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    with _locked_state(state):
        _reconcile_decision_transitions_unlocked(state)
        events = read_events(state)
        executions = project_executions(state, events=events)
        return [d for d in project_decisions(state, events).values()
                if _is_awaited(d, executions, events)]


def card_payload(decision: Decision) -> dict[str, object]:
    """Deterministic outbox payload: identical on every call, so enqueue is idempotent."""
    return {
        "delivery_mode": DECISION_CARD_MODE,
        "source_event_type": DECISION_REQUESTED_EVENT,
        "decision_id": decision.decision_id,
        "execution_id": decision.execution_id,
        "subject_id": decision.subject_id,
        "subject_type": decision.subject_type,
        "question": decision.question,
        "allow_text": decision.allow_text,
    }


def request_decision(
    state: Path,
    *,
    execution_id: str,
    attempt_id: str,
    actor: str,
    question: str,
    allow_text: bool,
    idempotency_key: str,
    now: datetime | None = None,
) -> Decision:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    normalized = actor.strip().casefold()
    if not normalized:
        raise ValueError("decision request requires the identity-bound target actor")
    if not decision_cards_enabled_for(normalized):
        raise ValueError(
            f"{normalized} has no decision cards: ask the operator directly through your session return "
            "(one concrete question with the options), then post BLOCKED: waiting for the operator's answer"
        )
    text = question.strip()
    if not text:
        raise ValueError("decision question must not be empty")
    if len(text.encode("utf-8")) > QUESTION_MAX_BYTES:
        raise ValueError(f"decision question must be at most {QUESTION_MAX_BYTES} bytes")
    if contains_literal_secret(text):
        raise ValueError("decision question contains a secret-shaped string; use a secret reference instead")
    key = idempotency_key
    if not isinstance(key, str) or not 16 <= len(key) <= 256 or any(ord(char) < 33 or ord(char) > 126 for char in key):
        raise ValueError("decision idempotency key must be 16-256 printable ASCII characters")
    if contains_literal_secret(key):
        raise ValueError("decision idempotency key contains a secret-shaped string")
    decision_id = "decision_" + hashlib.sha256(f"{execution_id}\0{normalized}\0{key}".encode()).hexdigest()[:24]
    # Exact retries retain their durable paired-write recovery semantics.
    with _locked_state(state):
        existing = project_decisions(state)
        prior = existing.get(decision_id)
        if prior is not None:
            if prior.target != normalized or prior.attempt_id != attempt_id:
                raise ValueError("decision idempotency key belongs to another attempt")
            if prior.question != text or prior.allow_text != bool(allow_text):
                raise ValueError("decision idempotency key was already used with another question")
            decision = prior
        else:
            _reconcile_decision_transitions_unlocked(state, now=now)
            live = project_executions(state).get(execution_id)
            if (live is None or live.status != "leased" or live.attempt_id != attempt_id
                    or live.target.strip().casefold() != normalized):
                raise ValueError("execution attempt is stale")
            executions = project_executions(state)
            open_ = [d for d in existing.values() if d.execution_id == execution_id and _is_awaited(d, executions, read_events(state))]
            if open_:
                raise ValueError(
                    f"execution already awaits decision {open_[0].decision_id}; do not ask again - "
                    "stop and wait for the operator's answer"
                )
            # Final authority: the lock, reconciliation and projections all precede time.
            current = now if now is not None else datetime.now(timezone.utc)
            if datetime.fromisoformat(live.lease_expires_at.replace("Z", "+00:00")) <= current:
                raise ValueError("execution lease expired")
            stamp = _timestamp(current)
            decision = Decision(
                decision_id=decision_id, execution_id=execution_id, attempt_id=attempt_id, target=normalized,
                subject_id=live.subject_id, subject_type=live.subject_type, question=text,
                allow_text=bool(allow_text), idempotency_key=key, requested_at=stamp,
            )
            _append_event_unlocked(state, _event(DECISION_REQUESTED_EVENT, decision_id, stamp, decision.to_dict()))
        _reconcile_decision_transitions_unlocked(state, now=now, decision_id=decision_id)
        queue_card = _is_awaited(decision, project_executions(state), read_events(state))
    # The state lock is not reentrant, so the card is queued after release. The payload is
    # deterministic, so a retry after a crash here re-queues the same single card.
    if queue_card:
        enqueue(state, subject_id=decision.decision_id, target=decision.target, payload=card_payload(decision), now=now)
    return decision


def classify_decision_card_dispatch(state: Path, *, decision_id: str, target: str) -> str | None:
    """Refusal detail when a queued card must not be sent (answered, unknown, or retargeted)."""
    with _locked_state(state):
        return _classify_decision_card_dispatch_unlocked(state, decision_id=decision_id, target=target)


def _classify_decision_card_dispatch_unlocked(state: Path, *, decision_id: str, target: str) -> str | None:
    """Caller MUST hold the state lock (outbox receipt finalization)."""
    events = read_events(state)
    decision = project_decisions(state, events).get(decision_id)
    if decision is None:
        return "decision card refers to an unknown decision"
    if decision.target != target.strip().casefold():
        return "decision card target does not match the decision"
    if decision.status != "requested":
        return "decision is already answered; card not sent"
    if not _is_awaited(decision, project_executions(state, events=events), events):
        return "decision is no longer awaited (execution resumed or closed elsewhere); card not sent"
    return None


def _operator_ids(environ: Mapping[str, str] | None = None) -> set[str]:
    env = os.environ if environ is None else environ
    return {part.strip() for part in env.get(OPERATOR_IDS_ENV, "").split(",") if part.strip()}


def answer_decision(
    state: Path,
    *,
    decision_id: str,
    actor: str,
    choice: str,
    text: str,
    nonce: str,
    operator_user_id: str,
    platform: str,
    message_id: str,
    now: datetime | None = None,
    environ: Mapping[str, str] | None = None,
) -> Decision:
    """Record the operator's answer from the agent's gateway and resume the parked execution.

    Every check fails closed before anything is appended.
    """
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    if (not isinstance(platform, str) or not platform.strip()
            or len(platform.encode('utf-8')) > 32 or contains_literal_secret(platform)
            or any(not (c.isascii() and (c.isalnum() or c in '_-')) for c in platform.strip())):
        raise ValueError('decision platform must be a bounded non-secret identifier')
    normalized = actor.strip().casefold()
    choice = choice.strip().casefold()
    if choice not in CHOICES:
        raise ValueError("decision choice must be approve, deny, or text")
    answer_text = text.strip()
    if choice == "text" and not answer_text:
        raise ValueError("a text decision needs non-empty text")
    if choice != "text" and answer_text:
        raise ValueError("only a text decision may carry text")
    if len(answer_text.encode("utf-8")) > ANSWER_TEXT_MAX_BYTES:
        raise ValueError(f"decision text must be at most {ANSWER_TEXT_MAX_BYTES} bytes")
    if contains_literal_secret(answer_text):
        raise ValueError("decision text contains a secret-shaped string")
    allowed = _operator_ids(environ)
    if not allowed:
        raise ValueError(f"decision operator allowlist is not configured: {OPERATOR_IDS_ENV}")
    if operator_user_id.strip() not in allowed:
        raise ValueError("decision answer is not from an allowed operator")
    expected_nonce = decision_nonce(decision_id, environ=environ)
    if not hmac.compare_digest(nonce.strip().encode(), expected_nonce.encode()):
        raise ValueError("decision answer proof is invalid")
    with _locked_state(state):
        decision = project_decisions(state).get(decision_id)
        if decision is None:
            raise ValueError(f"unknown decision: {decision_id}")
        if decision.target != normalized:
            raise ValueError("decision answer must come through the decision target's own gateway")
        stored_text = redact_secrets(answer_text)
        if decision.status == "answered":
            if (decision.choice, decision.text, decision.answer_message_id) == (choice, stored_text, message_id.strip()):
                _reconcile_decision_transitions_unlocked(state, now=now, decision_id=decision_id)
                return decision  # exact retry of the recorded answer
            raise ValueError(f"decision is already answered: {decision_id}")
        executions = project_executions(state)
        if not _is_awaited(decision, executions, read_events(state)):
            raise ValueError("decision is no longer awaited; its execution was resumed or closed elsewhere")
        if choice == "text" and not decision.allow_text:
            raise ValueError("this decision does not accept a text answer")
        cards = [item for item in project_outbox(state).values()
                 if item.subject_id == decision_id and item.payload.get("delivery_mode") == DECISION_CARD_MODE]
        # An ambiguous card (lease expired mid-send) may still have reached the operator; it counts
        # once its provider receipt is recorded, so his press on it is not refused.
        delivered = [item for item in cards
                     if item.status in {"delivered", "ambiguous_delivery"} and item.provider_receipt]
        if not delivered or all(item.provider_receipt != message_id.strip() for item in delivered):
            raise ValueError("decision answer does not reference the delivered card")
        stamp = _timestamp(now)
        answered = replace(
            decision, status="answered", choice=choice, text=stored_text,
            answered_by="operator", answered_at=stamp, answer_platform=platform.strip(),
            answer_message_id=message_id.strip(),
        )
        _append_event_unlocked(state, _event(DECISION_ANSWERED_EVENT, decision_id, stamp, answered.to_dict()))
        _reconcile_decision_transitions_unlocked(state, now=now, decision_id=decision_id)
    return answered
