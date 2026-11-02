from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
from pathlib import Path

from .control import _append_event_unlocked, _event, _locked_state, read_events
from .execution import _is_authoritative_terminal, execution_session, project_executions
from .outbox import OutboxItem, project_outbox
from .security import contains_literal_secret


SESSION_RETURN_EVENT = "execution.session_return.requested"
MESSAGE_MAX_BYTES = 4096


@dataclass(frozen=True)
class SessionReturn:
    request_id: str
    execution_id: str
    attempt_id: str
    target: str
    message: str
    message_sha256: str
    word_count: int
    idempotency_key: str
    requested_at: str
    status: str = "requested"
    delivery_id: str = ""
    provider_receipt: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "request_id": self.request_id,
            "execution_id": self.execution_id,
            "attempt_id": self.attempt_id,
            "target": self.target,
            "message": self.message,
            "message_sha256": self.message_sha256,
            "word_count": self.word_count,
            "idempotency_key": self.idempotency_key,
            "requested_at": self.requested_at,
            "status": self.status,
            "delivery_id": self.delivery_id,
            "provider_receipt": self.provider_receipt,
        }


def request_session_return(
    state: Path,
    *,
    execution_id: str,
    attempt_id: str,
    actor: str,
    message: str,
    expected_word_count: int | None,
    idempotency_key: str,
    now: datetime | None = None,
) -> SessionReturn:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    current = now or datetime.now(timezone.utc)
    execution_session(
        state,
        execution_id=execution_id,
        attempt_id=attempt_id,
        actor=actor,
        now=current,
    )
    normalized_actor = actor.strip().casefold()
    text = message.strip()
    if not text:
        raise ValueError("session return message must not be empty")
    if len(text.encode("utf-8")) > MESSAGE_MAX_BYTES:
        raise ValueError("session return message must be at most 4096 bytes")
    if contains_literal_secret(text):
        raise ValueError(
            "session return message contains a secret-shaped string; use a secret reference instead"
        )
    word_count = len(text.split())
    if expected_word_count is not None:
        if expected_word_count < 1:
            raise ValueError("expected word count must be positive")
        if word_count != expected_word_count:
            raise ValueError(
                f"session return word count mismatch: expected {expected_word_count}, got {word_count}"
            )
    key = idempotency_key
    if not isinstance(key, str) or not 16 <= len(key) <= 256 or any(ord(char) < 33 or ord(char) > 126 for char in key):
        raise ValueError("session return idempotency key must be 16-256 printable ASCII characters")
    if contains_literal_secret(key):
        raise ValueError("session return idempotency key contains a secret-shaped string")
    message_sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
    request_id = "session_return_" + hashlib.sha256(
        f"{execution_id}\0{attempt_id}\0{normalized_actor}\0{key}".encode()
    ).hexdigest()[:24]
    timestamp = current.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    result = SessionReturn(
        request_id=request_id,
        execution_id=execution_id,
        attempt_id=attempt_id,
        target=normalized_actor,
        message=text,
        message_sha256=message_sha256,
        word_count=word_count,
        idempotency_key=key,
        requested_at=timestamp,
    )
    with _locked_state(state):
        live = project_executions(state).get(execution_id)
        if (
            live is None
            or live.status != "leased"
            or live.attempt_id != attempt_id
            or live.target.strip().casefold() != normalized_actor
        ):
            raise ValueError("execution attempt is stale")
        existing = _project_session_returns_unlocked(state).get(request_id)
        if existing is not None:
            if existing.message_sha256 != message_sha256 or existing.word_count != word_count:
                raise ValueError("session return idempotency key was already used with another payload")
            return existing
        lineage = [
            item for item in _project_session_returns_unlocked(state).values()
            if item.execution_id == execution_id
        ]
        if any(item.attempt_id == attempt_id for item in lineage):
            raise ValueError("execution attempt already has a session return")
        outbox = project_outbox(state)
        # Sample after the final locked projections; explicit clocks stay deterministic.
        terminal = any(_is_authoritative_terminal(event, live) for event in read_events(state))
        try:
            expiry = datetime.fromisoformat(live.lease_expires_at.replace("Z", "+00:00"))
            if expiry.tzinfo is None:
                raise ValueError("execution lease has no timezone")
        except ValueError as error:
            raise ValueError("execution lease is invalid") from error
        current = now or datetime.now(timezone.utc)
        if expiry <= current or terminal:
            raise ValueError("execution attempt is stale or expired")
        timestamp = current.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        result = replace(result, requested_at=timestamp)
        for prior in sorted(lineage, key=lambda item: (item.requested_at, item.request_id)):
            live = _overlay_delivery(prior, outbox)
            if live.status in _RETURN_FAILED_STATUSES:
                continue
            if live.status == "ambiguous_delivery":
                raise ValueError(
                    f"execution already has ambiguous session return {live.request_id}; "
                    "provider reconciliation required before completion; do not resend and do not "
                    "complete the subject without a delivered provider receipt"
                )
            raise ValueError(
                f"execution already has a session return {live.request_id} ({live.status}) from "
                f"attempt {live.attempt_id}; read it back with control.execution_session_return_get "
                "and complete the subject instead of sending another message"
            )
        _append_event_unlocked(
            state,
            _event(SESSION_RETURN_EVENT, request_id, timestamp, result.to_dict()),
        )
    return result


# Outbox statuses after which a session return lineage may request again.
# Anything else (requested but not yet materialized, pending, leased, or
# delivered) is a human-visible send that is still in flight or already
# landed, so a second request on the same execution would duplicate it.
_RETURN_FAILED_STATUSES = frozenset({"dead_lettered", "cancelled"})


def _overlay_delivery(item: SessionReturn, outbox: dict[str, OutboxItem]) -> SessionReturn:
    # Receipt continuations share the subject and have their own replay epochs.
    # Only the exact human-facing send may determine readback or free its fence.
    deliveries = [
        entry for entry in outbox.values()
        if entry.subject_id == item.request_id
        and entry.target == item.target
        and entry.payload.get("delivery_mode") == "session_return"
        and entry.payload.get("execution_id") == item.execution_id
        and entry.payload.get("attempt_id") == item.attempt_id
        and entry.payload.get("message_sha256") == item.message_sha256
        and entry.payload.get("message") == item.message
        and entry.payload.get("word_count") == item.word_count
    ]
    delivery = max(deliveries, key=lambda entry: entry.epoch, default=None)
    if delivery is None:
        return item
    return replace(
        item,
        status=delivery.status,
        delivery_id=delivery.id,
        provider_receipt=delivery.provider_receipt,
    )


def get_session_return(state: Path, *, request_id: str, actor: str) -> SessionReturn:
    normalized_actor = actor.strip().casefold()
    if not normalized_actor:
        raise ValueError("session return lookup requires the identity-bound target actor")
    projected = _project_session_returns_unlocked(state).get(request_id)
    if projected is None or projected.target != normalized_actor:
        raise ValueError(f"unknown session return: {request_id}")
    return _overlay_delivery(projected, project_outbox(state))


def list_session_returns(state: Path, *, execution_id: str, actor: str) -> list[SessionReturn]:
    """Every session return on one execution lineage, visible only to its target.

    A reclaimed attempt (or a fresh runtime session after a restart) needs to
    see that the lineage already produced a human-visible message before it
    decides whether to request one.
    """
    normalized_actor = actor.strip().casefold()
    if not normalized_actor:
        raise ValueError("session return lookup requires the identity-bound target actor")
    outbox = project_outbox(state)
    items = [
        _overlay_delivery(item, outbox)
        for item in _project_session_returns_unlocked(state).values()
        if item.execution_id == execution_id and item.target == normalized_actor
    ]
    return sorted(items, key=lambda item: (item.requested_at, item.request_id))


@dataclass(frozen=True)
class SessionReturnDispatchRefusal:
    """Why a queued session return must not be sent, and how to classify it.

    ``resolution_category`` is one of the append-only dead-letter categories
    when authoritative state proves nothing is left to act on, and empty when
    the refusal is an anomaly an operator has to look at (unknown execution,
    or a return whose target does not own the execution).
    """

    detail: str
    resolution_category: str = ""


def classify_session_return_dispatch(
    state: Path,
    *,
    execution_id: str,
    attempt_id: str,
    target: str,
    now: datetime | None = None,
) -> SessionReturnDispatchRefusal | None:
    """Revalidate owner and exact live attempt immediately before a send.

    A session return is fenced to one attempt of one execution and may only
    ever reach that execution's owner. It is never re-targeted: when the owner
    cannot be determined or does not match, the item stays an unresolved,
    operator-visible dead letter; when the attempt is provably gone, the item
    dead-letters already classified (``terminal_elsewhere`` or
    ``superseded``) because a replay would only hit this gate again.
    """
    current = now or datetime.now(timezone.utc)
    execution = project_executions(state).get(execution_id)
    normalized_target = target.strip().casefold()
    if execution is None:
        return SessionReturnDispatchRefusal(
            f"session return names unknown execution {execution_id or '<missing>'}; "
            "its owner cannot be determined, so it is never delivered to anyone"
        )
    owner = execution.target.strip().casefold()
    if owner != normalized_target:
        return SessionReturnDispatchRefusal(
            f"session return target {normalized_target or '<missing>'} does not own execution "
            f"{execution.id} (owner {owner}); refusing to deliver to a non-owner"
        )
    terminal = execution.status == "completed" or any(
        _is_authoritative_terminal(event, execution) for event in read_events(state)
    )
    gone_category = "terminal_elsewhere" if terminal else "superseded"
    if execution.status != "leased" or execution.attempt_id != attempt_id:
        live = (
            f"live attempt is {execution.attempt_id}"
            if execution.status == "leased" and execution.attempt_id
            else f"execution status is {execution.status}"
        )
        return SessionReturnDispatchRefusal(
            f"session return execution attempt is no longer live: attempt {attempt_id or '<missing>'} "
            f"of execution {execution.id}; {live}",
            gone_category,
        )
    try:
        lease_expires_at = datetime.fromisoformat(execution.lease_expires_at.replace("Z", "+00:00"))
    except ValueError:
        return SessionReturnDispatchRefusal("session return execution lease is invalid")
    if lease_expires_at <= current:
        # An expired lease can never be renewed; the lineage reclaims under a
        # new attempt, which must request its own return.
        return SessionReturnDispatchRefusal(
            "session return execution lease has expired", gone_category,
        )
    if terminal:
        return SessionReturnDispatchRefusal(
            "session return execution subject is already terminal", "terminal_elsewhere",
        )
    return None


def session_return_dispatch_error(
    state: Path,
    *,
    execution_id: str,
    attempt_id: str,
    target: str,
    now: datetime | None = None,
) -> str | None:
    """Return a permanent no-send reason when a queued return lost its exact live authority."""
    refusal = classify_session_return_dispatch(
        state, execution_id=execution_id, attempt_id=attempt_id, target=target, now=now,
    )
    return refusal.detail if refusal is not None else None


def session_return_continuation_skip(state: Path, *, execution_id: str) -> str | None:
    """Return a reason to skip the receipt continuation wake, or ``None``.

    The continuation exists so the target can read its durable provider
    receipt back and write canonical completion. If the subject already
    reached an authoritative target-authored terminal, the loop is closed and
    another wake is pure noise. Lease state deliberately does not matter
    here: the whole point of the continuation is surviving a runtime that
    exited (and whose lease may have expired) before the receipt landed.
    """
    execution = project_executions(state).get(execution_id)
    if execution is None:
        return "session return continuation has no known execution"
    if any(_is_authoritative_terminal(event, execution) for event in read_events(state)):
        return "session return subject is already terminal"
    return None


def enqueue_session_return_continuation(
    state: Path,
    item: OutboxItem,
    *,
    now: datetime,
) -> None:
    """Recover from canonical delivery state, never from a caller's stale lease."""
    from .outbox import recover_session_return_continuations
    recover_session_return_continuations(state, now=now, outbox_id=item.id)


def session_return_continuation_payload(
    state: Path, item: OutboxItem,
) -> dict[str, object] | None:
    """Wake the target once after a provider receipt becomes durable.

    The wake is bound to the execution owner: it is only minted when the
    delivered item's target, the recorded request's target, and the
    execution's owner are the same identity and the request names the same
    fenced attempt. Anything else is never re-targeted to another agent.
    """
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    execution_id = str(item.payload.get("execution_id", ""))
    if (item.status != "delivered" or not item.provider_receipt
            or item.payload.get("delivery_mode") != "session_return"):
        return None
    skip = session_return_continuation_skip(state, execution_id=execution_id)
    if skip is not None:
        return
    execution = project_executions(state).get(execution_id)
    request = _project_session_returns_unlocked(state).get(item.subject_id)
    owner = execution.target.strip().casefold() if execution is not None else ""
    if (
        not owner
        or item.target.strip().casefold() != owner
        or request is None
        or request.target != owner
        or request.execution_id != execution_id
        or request.attempt_id != str(item.payload.get("attempt_id", ""))
        or request.message_sha256 != item.payload.get("message_sha256")
    ):
        return
    payload: dict[str, object] = {
        "schema": "v2.agent-delivery/1",
        "source_event_id": item.id,
        "source_event_type": "outbox.session_return.delivered",
        "delivery_mode": "session_return_receipt",
        "session_return_request_id": item.subject_id,
        "execution_id": execution_id,
        "attempt_id": str(item.payload.get("attempt_id", "")),
        "target": item.target,
    }
    if execution is not None:
        payload["subject_id"] = execution.subject_id
        payload["subject_type"] = execution.subject_type
    return payload


def project_session_returns(state: Path) -> dict[str, SessionReturn]:
    return _project_session_returns_unlocked(state)


def _project_session_returns_unlocked(state: Path) -> dict[str, SessionReturn]:
    items: dict[str, SessionReturn] = {}
    for event in read_events(state):
        if event.type != SESSION_RETURN_EVENT:
            continue
        payload = event.payload
        item = SessionReturn(
            request_id=str(payload["request_id"]),
            execution_id=str(payload["execution_id"]),
            attempt_id=str(payload["attempt_id"]),
            target=str(payload["target"]),
            message=str(payload["message"]),
            message_sha256=str(payload["message_sha256"]),
            word_count=int(payload["word_count"]),
            idempotency_key=str(payload["idempotency_key"]),
            requested_at=str(payload["requested_at"]),
        )
        items[item.request_id] = item
    return items
