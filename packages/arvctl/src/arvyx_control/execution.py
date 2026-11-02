from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
import json
from pathlib import Path
import re
from typing import Iterable, Iterator, Mapping, Sequence

from .agent_delivery import AgentDeliveryResult, AgentRoute, deliver_outbox_item
from .control import (
    ControlEvent,
    _acknowledge_replay_unlocked,
    _append_event_unlocked,
    _event,
    _locked_state,
    _project_threads,
    parse_event_line,
    read_events,
    same_agent_identity,
)
from .outbox import OutboxItem, finalize_execution_wake, record_execution_wake_unlocked
from . import projection_cache
from .security import contains_literal_secret, redact_secrets

EXECUTION_EVENT_TYPES = frozenset({
    "execution.created", "execution.attempt.started", "execution.heartbeat",
    "execution.attempt.failed", "execution.dead_lettered", "execution.completed",
    "execution.replayed", "execution.held", "execution.closed",
    "execution.cancel_requested",
    "execution.resumed", "execution.steer.requested", "execution.steer.acknowledged",
})
EXECUTION_STATE_EVENT_TYPES = EXECUTION_EVENT_TYPES - {
    "execution.steer.requested", "execution.steer.acknowledged",
}

# Statuses a claim never touches. "held" is the canonical operator-attention
# terminal: remediation is exhausted and only an explicit replay (or a real
# authoritative terminal event) moves the execution again. "closed" is the
# operator-resolution terminal for work that will never run again (superseded,
# obsolete, terminal elsewhere, or no longer actionable): unlike "held" it
# leaves the operator queue entirely, so it is never claimable or replayable.
EXECUTION_INERT_STATUSES = frozenset({"completed", "dead_lettered", "held", "paused", "closed"})
# Resolution categories an operator may record when closing a held or
# dead-lettered execution. Every closure must name why the work stopped.
CLOSE_RESOLUTION_CATEGORIES = frozenset({
    "superseded", "obsolete", "terminal_elsewhere", "no_longer_actionable",
})
CONTROL_MESSAGE_MAX_BYTES = 4096
# Event history is an authenticated worker-facing endpoint. Cap the complete
# source snapshot, not merely the returned page, so a corrupt/growing JSONL log
# cannot monopolize a request worker. Operators must compact/archive before the
# source reaches this deliberately conservative ceiling.
EXECUTION_EVENT_SNAPSHOT_MAX_BYTES = 16 * 1024 * 1024


# Bounded, deterministic re-wake backoff. Without it an expired or rejected
# attempt is re-claimed on the very next worker tick, so a stalled or failing
# target burns its whole dead-letter budget in minutes while being hammered
# with duplicate wakes.
RETRY_BACKOFF_BASE_SECONDS = 15
RETRY_BACKOFF_MAX_SECONDS = 300
# Bounded BLOCKED retry. A target that reports BLOCKED (a target-authored
# thread reply whose first word is "BLOCKED") and then receives no new input
# on the subject would only report the same blocker again if re-woken: the
# thing it needs has not changed. After this many consecutive BLOCKED attempts
# with no intervening input the worker parks the execution in the canonical
# operator HOLD instead of spending the rest of its attempt budget on
# duplicate wakes (production: 12 BLOCKED replies on one thread in 72 minutes).
BLOCKED_REWAKE_LIMIT = 2
BLOCKED_HOLD_REASON_PREFIX = "target reported BLOCKED"
# A BLOCKED report is the reply's first word, optionally wrapped in markdown
# emphasis, heading or list markers, followed by punctuation, whitespace or
# the end. Quoted or questioned forms ("BLOCKED" earlier, > BLOCKED?) and
# identifiers (BLOCKED_BY_X, unblocked) are not reports.
_BLOCKED_REPORT = re.compile(r"^[\s*_~`#-]*blocked(?=[*_~`]*(?:[:\s.!,;\u2013\u2014-]|$))", re.IGNORECASE)
_ZERO_WIDTH = re.compile("[\u200b-\u200d\u2060\ufeff]")
_BLOCKED_REASON_MAX_CHARS = 280
# First-heartbeat window (B6). An LLM runtime needs time to start before it can
# heartbeat (production: 71 s to the first heartbeat on a healthy path against
# a 120 s lease), but raising the renewal lease would also delay detecting a
# target that stopped. So the attempt gets two distinct deadlines: after the
# wake is accepted, the lease runs to accepted_at + first_heartbeat_seconds;
# once the first identity-bound target heartbeat is recorded, each target
# heartbeat renews by lease_seconds as before. The window is recorded in the
# worker's heartbeat event, never derived from current config.
DEFAULT_FIRST_HEARTBEAT_SECONDS = 300
MAX_LEASE_SECONDS = 3600
LEASE_EXPIRED_FAILURE = "lease expired before heartbeat or finalization"
FIRST_HEARTBEAT_EXPIRED_PREFIX = "no target heartbeat within first-heartbeat window"
RENEWAL_LAPSED_PREFIX = "target heartbeat lapsed"
ASSIGNMENT_PROVENANCE_CUTOFF = datetime(2026, 9, 2, tzinfo=timezone.utc)
RUNTIME_OUTCOMES = frozenset({
    "progressing", "waiting_human", "provider_error", "runtime_exited", "unobservable",
})


@dataclass(frozen=True)
class Execution:
    id: str
    subject_id: str
    subject_type: str
    target: str
    source_event_id: str
    source_event_type: str
    status: str
    attempts: int
    created_at: str
    updated_at: str
    lease_owner: str = ""
    lease_expires_at: str = ""
    attempt_id: str = ""
    heartbeat_at: str = ""
    last_failure: str = ""
    terminal_event_id: str = ""
    terminal_event_type: str = ""
    hold_reason: str = ""
    held_by: str = ""
    close_reason: str = ""
    closed_by: str = ""
    closed_at: str = ""
    resolution_category: str = ""
    runtime_outcome: str = ""
    cancel_reason: str = ""
    cancelled_by: str = ""
    resume_pending: bool = False
    # First-heartbeat window (B6). Set by the worker's accepted-wake heartbeat
    # to accepted_at + first_heartbeat_seconds; the attempt's lease runs to it
    # until the first identity-bound target heartbeat, recorded once per
    # attempt in first_target_heartbeat_at. Both are empty on events written
    # before the window existed, so old logs project exactly as before.
    first_heartbeat_deadline: str = ""
    first_target_heartbeat_at: str = ""
    operator_archive_json: str = ""

    def to_dict(self) -> dict[str, object]:
        return dict(self.__dict__)


def _timestamp(value: datetime | None = None) -> str:
    current = value or datetime.now(timezone.utc)
    return current.astimezone(timezone.utc).isoformat(timespec="auto").replace("+00:00", "Z")


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _parse_aware(value: str) -> datetime:
    parsed = _parse(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp is offset-naive")
    return parsed


def _is_pre_provenance_event(value: str) -> bool:
    try:
        return _parse(value) < ASSIGNMENT_PROVENANCE_CUTOFF
    except (TypeError, ValueError):
        return False


def _execution_id(subject_type: str, subject_id: str, target: str) -> str:
    lineage = f"{subject_type}\0{subject_id}\0{target}".encode()
    return "execution_" + hashlib.sha256(lineage).hexdigest()[:24]


def _attempt_id(execution_id: str, attempts: int, started_at: str) -> str:
    """Unique per claim, not per attempt number.

    A replay resets ``attempts``, so an id derived from the number alone repeated
    after every replay: the resumed wake reused its predecessor's delivery id and the
    agent gateway dropped it as a duplicate (2026-09-24), and a heartbeat or terminal
    still in flight from the superseded attempt would have fenced as current. The
    claim time plus a random salt keeps every attempt distinct.
    """
    lineage = f"{execution_id}\0{attempts}\0{started_at}\0{secrets.token_hex(8)}".encode()
    return "attempt_" + hashlib.sha256(lineage).hexdigest()[:24]


def _legacy_authorized_assignments(events: Sequence[object]) -> set[tuple[str, str]]:
    """Find pre-provenance assignments authorized by their exact target."""
    assignments: dict[tuple[str, str], str] = {}
    for event in events:
        payload = getattr(event, "payload", {})
        if (
            not isinstance(payload, dict)
            or "actor_identity_bound" in payload
            or not _is_pre_provenance_event(str(getattr(event, "timestamp", "")))
        ):
            continue
        event_type = str(getattr(event, "type", ""))
        task_id = str(getattr(event, "task_id", ""))
        if event_type == "thread.created":
            assignments[("thread", task_id)] = str(payload.get("target", "")).strip().casefold()
        elif event_type == "handoff.created":
            assignments[("handoff", task_id)] = str(payload.get("to_agent", "")).strip().casefold()

    authorized: set[tuple[str, str]] = set()
    for event in events:
        payload = getattr(event, "payload", {})
        if not isinstance(payload, dict) or payload.get("actor_identity_bound") is not True:
            continue
        event_type = str(getattr(event, "type", ""))
        task_id = str(getattr(event, "task_id", ""))
        if event_type == "thread.acknowledged":
            key = ("thread", task_id)
            actor = str(payload.get("acked_by", "")).strip().casefold()
        elif event_type == "handoff.accepted":
            key = ("handoff", task_id)
            actor = str(payload.get("accepted_by", "")).strip().casefold()
        else:
            continue
        if assignments.get(key) and actor == assignments[key]:
            authorized.add(key)
    return authorized


def execution_assignment_sources(events: Sequence[object]) -> dict[str, tuple[str, str]]:
    """Assignment eligibility shared by execution workers and delivery notices.

    Classification precedes materialization, so dispatcher-first scheduling
    cannot mint independent work authority. Legacy target authorization remains
    limited to the existing pre-provenance policy.
    """
    legacy_authorized = _legacy_authorized_assignments(events)
    sources: dict[str, tuple[str, str]] = {}
    for event in events:
        event_type = getattr(event, "type", "")
        payload = getattr(event, "payload", {})
        if event_type == "thread.created":
            if str(payload.get("type", "")).strip().casefold() not in {"ask", "handoff", "blocker"}:
                continue
            kind, target_field = "thread", "target"
        elif event_type == "handoff.created":
            kind, target_field = "handoff", "to_agent"
        else:
            continue
        target = str(payload.get(target_field, "")).strip().casefold()
        if (target and target != "all" and (
                payload.get("actor_identity_bound") is True
                or (kind, getattr(event, "task_id", "")) in legacy_authorized)):
            sources[str(event.id)] = (kind, target)
    return sources


def _project_executions_state(
    projected: dict[str, Execution],
    malformed: set[str],
    events: Sequence[object],
) -> tuple[dict[str, Execution], set[str]]:
    for event in events:
        if getattr(event, "type", "") not in EXECUTION_STATE_EVENT_TYPES:
            continue
        payload = getattr(event, "payload", {})
        event_execution_id = str(getattr(event, "task_id", ""))
        try:
            if not isinstance(payload, dict):
                raise ValueError("payload is not an object")
            attempts = payload.get("attempts", 0)
            if not isinstance(attempts, int) or isinstance(attempts, bool) or attempts < 0:
                raise ValueError("attempts is not a non-negative integer")
            values = {field: payload.get(field, "") for field in Execution.__dataclass_fields__}
            values["attempts"] = attempts
            values["resume_pending"] = payload.get("resume_pending", False)
            for field in Execution.__dataclass_fields__:
                if field in {"attempts", "resume_pending"}:
                    continue
                if not isinstance(values[field], str):
                    raise ValueError(f"{field} is not a string")
            if not isinstance(values["resume_pending"], bool):
                raise ValueError("resume_pending is not a boolean")
            if not values["id"] or values["id"] != event_execution_id:
                raise ValueError("execution id does not match event lineage")
            for field in ("created_at", "updated_at"):
                if not values[field]:
                    raise ValueError(f"{field} is empty")
                _parse_aware(values[field])
            for field in (
                "lease_expires_at", "heartbeat_at",
                "first_heartbeat_deadline", "first_target_heartbeat_at",
            ):
                if values[field]:
                    _parse_aware(values[field])
            if bool(values["lease_owner"]) != bool(values["lease_expires_at"]):
                raise ValueError("lease owner and expiry must be present together")
            if values["status"] == "leased" and (
                not values["lease_owner"].strip()
                or not values["lease_expires_at"]
                or attempts < 1
                or not values["attempt_id"].strip()
            ):
                raise ValueError("leased execution has incoherent attempt state")
            execution = Execution(**values)
        except (TypeError, ValueError):
            malformed.add(event_execution_id)
            projected.pop(event_execution_id, None)
            continue
        if execution.id in malformed:
            continue
        projected[execution.id] = execution
    return projected, malformed


def _project_executions(events: Sequence[object]) -> dict[str, Execution]:
    return _project_executions_state({}, set(), events)[0]


EXECUTION_FIELDS = frozenset(Execution.__dataclass_fields__)
EXECUTION_INTEGER_FIELDS = ("attempts",)
EXECUTION_BOOLEAN_FIELDS = ("resume_pending",)


def _executions_seed(events: Sequence[ControlEvent]) -> dict[str, object]:
    projected, malformed = _project_executions_state({}, set(), events)
    # Insertion order, not sorted order: the resumed projection must reproduce
    # the exact dict the full parse builds, down to iteration order.
    return {
        "executions": [execution.to_dict() for execution in projected.values()],
        "malformed": sorted(malformed),
    }


def _executions_seed_state(seed: object) -> tuple[dict[str, Execution], set[str]]:
    if not isinstance(seed, dict) or set(seed) != {"executions", "malformed"}:
        raise ValueError("executions seed is malformed")
    entries = seed["executions"]
    malformed = seed["malformed"]
    if not isinstance(entries, list) or not isinstance(malformed, list):
        raise ValueError("executions seed is malformed")
    if not all(isinstance(value, str) and value for value in malformed):
        raise ValueError("executions seed is malformed")
    projected: dict[str, Execution] = {}
    for value in entries:
        if not isinstance(value, dict) or set(value) != EXECUTION_FIELDS:
            raise ValueError("executions seed entry is malformed")
        for field, field_value in value.items():
            if field in EXECUTION_INTEGER_FIELDS:
                if isinstance(field_value, bool) or not isinstance(field_value, int) or field_value < 0:
                    raise ValueError("executions seed entry is malformed")
            elif field in EXECUTION_BOOLEAN_FIELDS:
                if not isinstance(field_value, bool):
                    raise ValueError("executions seed entry is malformed")
            elif not isinstance(field_value, str):
                raise ValueError("executions seed entry is malformed")
        execution = Execution(**value)  # type: ignore[arg-type]
        if not execution.id:
            raise ValueError("executions seed entry is malformed")
        projected[execution.id] = execution
    return projected, set(malformed)


def _valid_executions_seed(seed: object) -> bool:
    try:
        _executions_seed_state(seed)
    except (TypeError, ValueError):
        return False
    return True


projection_cache.register_seed(
    "executions", builder=_executions_seed, validator=_valid_executions_seed
)


def assignment_event_types() -> frozenset[str]:
    """Event types that decide an assignment's fate, and nothing else.

    Exactly the events the materialization scan needs: the assignments
    themselves, the legacy-authorization receipts that can authorize a
    pre-provenance one, and the archive/retirement markers that make a subject
    inert. Imported lazily because ``operator_archive`` reads the event log.
    """
    from .operator_archive import ARCHIVE_TYPES

    return frozenset(
        {
            "thread.created",
            "handoff.created",
            "thread.acknowledged",
            "handoff.accepted",
            "thread.retired",
        }
    ) | ARCHIVE_TYPES


CONTROL_EVENT_FIELDS = frozenset(ControlEvent.__dataclass_fields__)


def _assignments_seed(events: Sequence[ControlEvent]) -> dict[str, object]:
    """Keep the assignment-shaped events, drop the 99.5% that are tick noise.

    At 310k events the log is 142 MB but only ~1.6k events are relevant here. The
    seed is stored whole (2.1 MB at that size) rather than reduced, so the
    consumers below are the existing scans, unchanged, run over `seed + tail`.

    The set of types it was built with travels in the seed, and the validator
    requires it to match the current one. Adding a scan type therefore
    invalidates every existing checkpoint instead of leaving a valid-looking seed
    that silently lacks the new events: readers fall back to the full parse and
    the next scheduled tick rebuilds. That costs nothing to remember, which is
    the point — a rule to bump the schema when the set changes would be missed.
    """
    types = assignment_event_types()
    return {
        "types": sorted(types),
        "events": [event.to_dict() for event in events if event.type in types],
    }


def _assignments_seed_state(seed: object) -> list[ControlEvent]:
    types = assignment_event_types()
    if not isinstance(seed, dict) or set(seed) != {"types", "events"}:
        raise ValueError("assignments seed is malformed")
    if seed["types"] != sorted(types):
        raise ValueError("assignments seed was built with a different type set")
    entries = seed["events"]
    if not isinstance(entries, list):
        raise ValueError("assignments seed is malformed")
    events: list[ControlEvent] = []
    for value in entries:
        if not isinstance(value, dict) or set(value) != CONTROL_EVENT_FIELDS:
            raise ValueError("assignments seed entry is malformed")
        for field in ("id", "type", "task_id", "timestamp"):
            if not isinstance(value[field], str) or not value[field]:
                raise ValueError("assignments seed entry is malformed")
        if value["type"] not in types:
            raise ValueError("assignments seed entry is malformed")
        if not isinstance(value["payload"], dict):
            raise ValueError("assignments seed entry is malformed")
        events.append(ControlEvent(**value))  # type: ignore[arg-type]
    return events


def _valid_assignments_seed(seed: object) -> bool:
    try:
        _assignments_seed_state(seed)
    except (TypeError, ValueError):
        return False
    return True


projection_cache.register_seed(
    "assignments", builder=_assignments_seed, validator=_valid_assignments_seed
)


def project_executions(
    state: Path, *, events: Sequence[ControlEvent] | None = None,
) -> dict[str, Execution]:
    return _execution_projection_state(state, events=events)[0]


def _execution_projection_state(
    state: Path, *, events: Sequence[ControlEvent] | None = None,
) -> tuple[dict[str, Execution], set[str]]:
    """Keep permanent quarantine alongside the surviving execution projection."""
    if events is not None:
        return _project_executions_state({}, set(), events)
    seed, tail, source = projection_cache.projection_source(state, "executions")
    if source == "checkpoint":
        projected, malformed = _executions_seed_state(seed)
        return _project_executions_state(projected, malformed, tail)
    return _project_executions_state({}, set(), tail)


def read_execution_event_snapshot(state: Path) -> list[ControlEvent]:
    """Read one size-bounded immutable snapshot for execution event history."""
    if state.exists() and state.stat().st_size > EXECUTION_EVENT_SNAPSHOT_MAX_BYTES:
        raise ValueError(
            f"execution event snapshot exceeds {EXECUTION_EVENT_SNAPSHOT_MAX_BYTES} bytes"
        )
    return read_events(state, max_bytes=EXECUTION_EVENT_SNAPSHOT_MAX_BYTES)


def _control_message(value: str, *, label: str) -> str:
    text = value.strip()
    if not text:
        raise ValueError(f"{label} must not be empty")
    if len(text.encode("utf-8")) > CONTROL_MESSAGE_MAX_BYTES:
        raise ValueError(f"{label} must be at most {CONTROL_MESSAGE_MAX_BYTES} bytes")
    if contains_literal_secret(text):
        raise ValueError(f"{label} contains a secret-shaped string; use a secret reference instead")
    return text


def _control_key(value: str, *, label: str) -> str:
    key = value.strip()
    if not 16 <= len(key) <= 256 or any(ord(char) < 33 or ord(char) > 126 for char in key):
        raise ValueError(f"{label} idempotency key must be 16-256 printable ASCII characters")
    return key


def _safe_execution_event(event: object) -> dict[str, object]:
    payload = getattr(event, "payload", {})
    safe: dict[str, object] = {"id": str(getattr(event, "id", "")), "type": str(getattr(event, "type", "")), "timestamp": str(getattr(event, "timestamp", ""))}
    for key in ("attempt_id", "status", "attempts", "runtime_outcome", "request_id", "ack_id", "message", "message_sha256", "requested_by", "acknowledged_by", "cancel_reason", "cancelled_by", "resumed_by"):
        if isinstance(payload, dict) and key in payload:
            safe[key] = payload[key]
    return safe


def _traverse_execution_events(
    events: Iterable[ControlEvent], *, execution_id: str, after: str, limit: int
) -> tuple[list[ControlEvent], bool]:
    """Cursor traversal over any event source, retaining only ``limit + 1`` matches."""
    cursor_found = not after
    page: list[ControlEvent] = []
    for event in events:
        if event.task_id != execution_id or event.type not in EXECUTION_EVENT_TYPES:
            continue
        if not cursor_found:
            if event.id == after:
                cursor_found = True
            continue
        page.append(event)
        if len(page) > limit:
            break
    if not cursor_found:
        raise ValueError("unknown execution event cursor")
    return page[:limit], len(page) > limit


def _streamed_execution_events(state: Path) -> Iterator[ControlEvent]:
    """Yield control events from a byte-bounded view of the log.

    The boundary is the size the file had when it was opened, so a concurrent
    append is never read half-way, and memory stays flat whatever the log weighs.
    """
    if not state.exists():
        return
    with state.open("rb") as handle:
        boundary = handle.seek(0, 2)
        handle.seek(0)
        consumed = 0
        line_number = 0
        while consumed < boundary:
            chunk = handle.readline()
            if not chunk or consumed + len(chunk) > boundary:
                return
            consumed += len(chunk)
            line_number += 1
            event = parse_event_line(chunk.decode("utf-8"), line_number=line_number)
            if event is not None:
                yield event


def list_execution_events(state: Path, *, execution_id: str, target: str = "", after: str = "", limit: int = 100, events: Sequence[ControlEvent] | None = None) -> dict[str, object]:
    """List one execution's history without materialising the whole log.

    ``read_execution_event_snapshot`` loads every event and refuses outright once
    the log passes ``EXECUTION_EVENT_SNAPSHOT_MAX_BYTES``, which is why this route
    stops working as the log grows. Traversal only ever retains ``limit + 1``
    matches, so it streams the file instead and stays flat in memory; the
    projection that resolves and authorises the execution comes from the
    checkpoint-accelerated ``project_executions``.
    """
    if limit < 1:
        raise ValueError("execution event limit must be positive")
    if limit > 500:
        raise ValueError("execution event limit must be at most 500")
    if events is not None:
        execution = _project_executions(events).get(execution_id)
    else:
        execution = project_executions(state).get(execution_id)
    if execution is None:
        raise ValueError(f"unknown execution: {execution_id}")
    if target and execution.target.strip().casefold() != target.strip().casefold():
        raise ValueError("execution events require the identity-bound target actor")
    source: Iterable[ControlEvent] = events if events is not None else _streamed_execution_events(state)
    page, has_more = _traverse_execution_events(
        source, execution_id=execution_id, after=after, limit=limit
    )
    return {"events": [_safe_execution_event(event) for event in page], "next_cursor": page[-1].id if page else after, "has_more": has_more}


def _acknowledge_execution_replay_unlocked(state: Path, execution: Execution) -> None:
    """A projected stop is visible evidence, not an append durability receipt.

    Under the state lock, resolve the snapshot's latest source event and use
    the shared complete-log validation and file/namespace barriers. This also
    works for stops loaded from a derived checkpoint without source event IDs.
    """
    source = next((event for event in reversed(read_events(state))
                   if event.task_id == execution.id
                   and event.type in EXECUTION_STATE_EVENT_TYPES), None)
    if source is None or _project_executions([source]).get(execution.id) != execution:
        raise ValueError("execution replay source is missing or changed")
    _acknowledge_replay_unlocked(state, source)


def cancel_execution(state: Path, *, execution_id: str, reason: str, cancelled_by: str, now: datetime | None = None) -> Execution:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    reason = _control_message(reason, label="cancel reason")
    actor = cancelled_by.strip()
    if not actor:
        raise ValueError("cancelled_by must not be empty")

    def stamp() -> str:
        # Sample per append, never on entry. This function reads the event log
        # before it writes anything, so a stamp taken on entry can predate the
        # source event that produced this write. With an injected clock the
        # stamp stays pinned exactly as before.
        return _timestamp(now)
    with _locked_state(state):
        execution = project_executions(state).get(execution_id)
        if execution is None:
            raise ValueError(f"unknown execution: {execution_id}")
        if execution.status == "paused":
            _acknowledge_execution_replay_unlocked(state, execution)
            return execution
        if execution.status in {"completed", "dead_lettered", "held", "closed"}:
            raise ValueError(f"terminal execution cannot be cancelled: {execution_id}")
        updated = replace(execution, status="paused", updated_at=stamp(), lease_owner="", lease_expires_at="", cancel_reason=reason, cancelled_by=actor)
        _append_event_unlocked(state, _event("execution.cancel_requested", execution.id, stamp(), updated.to_dict()))
        return updated


def resume_execution(state: Path, *, execution_id: str, resumed_by: str, now: datetime | None = None) -> Execution:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    actor = resumed_by.strip()
    if not actor:
        raise ValueError("resumed_by must not be empty")

    def stamp() -> str:
        # Sample per append, never on entry. This function reads the event log
        # before it writes anything, so a stamp taken on entry can predate the
        # source event that produced this write. With an injected clock the
        # stamp stays pinned exactly as before.
        return _timestamp(now)
    with _locked_state(state):
        execution = project_executions(state).get(execution_id)
        if execution is None:
            raise ValueError(f"unknown execution: {execution_id}")
        if execution.status != "paused":
            raise ValueError(f"execution is not paused: {execution_id}")
        updated = replace(execution, status="pending", updated_at=stamp(), lease_owner="", lease_expires_at="", attempt_id="", cancel_reason="", cancelled_by="", resume_pending=True)
        payload = updated.to_dict(); payload["resumed_by"] = actor
        _append_event_unlocked(state, _event("execution.resumed", execution.id, stamp(), payload))
        return updated


def request_execution_steer(state: Path, *, execution_id: str, attempt_id: str, message: str, requested_by: str, idempotency_key: str, now: datetime | None = None) -> dict[str, object]:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    text = _control_message(message, label="steer message")
    key = _control_key(idempotency_key, label="steer")
    actor = requested_by.strip()
    if not actor:
        raise ValueError("requested_by must not be empty")
    digest = hashlib.sha256(text.encode()).hexdigest()
    request_id = "steer_" + hashlib.sha256(f"{execution_id}\0{attempt_id}\0{key}".encode()).hexdigest()[:24]

    def stamp() -> str:
        # Sample per append, never on entry. This function reads the event log
        # before it writes anything, so a stamp taken on entry can predate the
        # source event that produced this write. With an injected clock the
        # stamp stays pinned exactly as before.
        return _timestamp(now)
    with _locked_state(state):
        events = read_events(state)
        execution = _project_executions(events).get(execution_id)
        if execution is None or execution.status != "leased":
            raise ValueError("execution attempt is not live")
        if not attempt_id or execution.attempt_id != attempt_id:
            raise ValueError("execution attempt is stale")
        current = now if now is not None else datetime.now(timezone.utc)
        if _parse(execution.lease_expires_at) <= current:
            raise ValueError("execution lease expired")
        matches = [e for e in events if e.type == "execution.steer.requested" and e.payload.get("request_id") == request_id]
        if len(matches) > 1:
            raise ValueError("steer replay source is ambiguous")
        existing = matches[0] if matches else None
        if existing:
            if (
                existing.task_id != execution_id
                or existing.payload.get("execution_id") != execution_id
                or existing.payload.get("attempt_id") != attempt_id
                or existing.payload.get("message_sha256") != digest
            ):
                raise ValueError("steer idempotency key was already used with another payload")
            _acknowledge_replay_unlocked(state, existing)
            return dict(existing.payload)
        payload: dict[str, object] = {"request_id": request_id, "execution_id": execution_id, "attempt_id": attempt_id, "message": text, "message_sha256": digest, "requested_by": actor, "requested_at": stamp(), "status": "requested"}
        _append_event_unlocked(state, _event("execution.steer.requested", execution.id, stamp(), payload))
        return payload


def acknowledge_execution_steer(state: Path, *, execution_id: str, attempt_id: str, request_id: str, actor: str, message: str, idempotency_key: str, now: datetime | None = None) -> dict[str, object]:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    text = _control_message(message, label="steer acknowledgement message")
    key = _control_key(idempotency_key, label="steer acknowledgement")
    normalized = actor.strip().casefold()
    digest = hashlib.sha256(text.encode()).hexdigest()
    ack_id = "steer_ack_" + hashlib.sha256(f"{request_id}\0{attempt_id}\0{normalized}\0{key}".encode()).hexdigest()[:24]

    def stamp() -> str:
        # Sample per append, never on entry. This function reads the event log
        # before it writes anything, so a stamp taken on entry can predate the
        # source event that produced this write. With an injected clock the
        # stamp stays pinned exactly as before.
        return _timestamp(now)
    with _locked_state(state):
        events = read_events(state)
        execution = _project_executions(events).get(execution_id)
        if execution is None or execution.status != "leased":
            raise ValueError("execution attempt is not live")
        if execution.attempt_id != attempt_id:
            raise ValueError("execution attempt is stale")
        current = now if now is not None else datetime.now(timezone.utc)
        if _parse(execution.lease_expires_at) <= current:
            raise ValueError("execution lease expired")
        if execution.target.strip().casefold() != normalized:
            raise ValueError("steer acknowledgement requires the identity-bound target actor")
        requests = [e for e in events if (
            e.type == "execution.steer.requested"
            and e.task_id == execution_id
            and e.payload.get("request_id") == request_id
            and e.payload.get("execution_id") == execution_id
            and e.payload.get("attempt_id") == attempt_id
        )]
        if not requests:
            raise ValueError("unknown steer request for execution attempt")
        if len(requests) != 1:
            raise ValueError("steer request source is ambiguous")
        matches = [e for e in events if e.type == "execution.steer.acknowledged" and e.payload.get("ack_id") == ack_id]
        if len(matches) > 1:
            raise ValueError("steer acknowledgement replay source is ambiguous")
        existing = matches[0] if matches else None
        if existing:
            if (
                existing.task_id != execution_id
                or existing.payload.get("execution_id") != execution_id
                or existing.payload.get("attempt_id") != attempt_id
                or existing.payload.get("request_id") != request_id
                or existing.payload.get("message_sha256") != digest
            ):
                raise ValueError("steer acknowledgement idempotency key was already used with another payload")
            _acknowledge_replay_unlocked(state, existing)
            return dict(existing.payload)
        payload: dict[str, object] = {"ack_id": ack_id, "request_id": request_id, "execution_id": execution_id, "attempt_id": attempt_id, "message": text, "message_sha256": digest, "acknowledged_by": normalized, "acknowledged_at": stamp(), "status": "acknowledged"}
        _append_event_unlocked(state, _event("execution.steer.acknowledged", execution.id, stamp(), payload))
        return payload


def materialize_executions(
    state: Path, *, execution_capable_targets: set[str], now: datetime | None = None,
    quarantined: list[str] | None = None,
) -> list[Execution]:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    capable = {target.strip().casefold() for target in execution_capable_targets if target.strip()}
    return _materialize_executions(state, capable=capable, now=now, quarantined_roots=quarantined)


def _materialize_executions(
    state: Path, *, capable: set[str], now: datetime | None = None,
    quarantined_roots: list[str] | None = None,
) -> list[Execution]:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    created: list[Execution] = []
    with _locked_state(state):
        # Resume instead of re-parsing. ``seed`` holds every assignment-shaped
        # event up to the checkpoint offset and ``tail`` holds the rest, so the
        # union is the whole log for the types this scan reads: a ~4.9 s full
        # parse becomes a ~0.2 s resumed read on every worker tick, and the state
        # lock is no longer held across a 142 MB parse.
        # ``existing`` is deliberately read *after* the seed: the checkpoint only
        # ever advances, so executions cannot be older than the seed, and the
        # skip decision is then made against at least as much history as the
        # scan itself can see. In ``full`` mode ``tail`` already is the full log,
        # so this is the old behaviour exactly.
        seed, tail, source = projection_cache.projection_source(state, "assignments")
        existing, quarantined = _execution_projection_state(state)
        if quarantined_roots is not None:
            quarantined_roots.extend(sorted(quarantined))
        if source == "checkpoint":
            events = _assignments_seed_state(seed) + list(tail)
        else:
            events = list(tail)
        # Backward compatibility for assignments written before creation
        # provenance existed: a later identity-bound target ACK/accept may
        # authorize that legacy assignment. New unbound assignments never
        # launch directly.
        assignment_sources = execution_assignment_sources(events)
        from .operator_archive import archived_ids
        archived = archived_ids(events)
        for event in events:
            if event.task_id in archived:
                continue
            # Execution starts when actionable work is assigned, not when an LLM
            # later chooses to ACK it.  The dispatcher is the kernel: assignment
            # materializes one stable execution root and the target runtime is
            # launched from that root.  ACK/accept remain coordination receipts,
            # never execution triggers.
            assignment = assignment_sources.get(event.id)
            if assignment is None:
                continue
            subject_type, target = assignment
            if target not in capable:
                continue
            execution_id = _execution_id(subject_type, event.task_id, target)
            if execution_id in existing or execution_id in quarantined:
                continue
            # Stamp at the append, never on entry. This call waits on the state
            # lock and then re-reads the whole event log, so a stamp sampled on
            # entry can predate the ``thread.created`` it was materialized from.
            # With an injected clock the stamp stays pinned exactly as before.
            stamp = _timestamp(now)
            execution = Execution(
                id=execution_id, subject_id=event.task_id, subject_type=subject_type,
                target=target, source_event_id=event.id, source_event_type=event.type,
                status="pending", attempts=0, created_at=event.timestamp, updated_at=stamp,
            )
            _append_event_unlocked(state, _event("execution.created", execution.id, stamp, execution.to_dict()))
            existing[execution.id] = execution
            created.append(execution)
    return created


def _terminal_actor(event: object) -> str:
    event_type = str(getattr(event, "type", ""))
    payload = getattr(event, "payload", {})
    if not isinstance(payload, dict):
        return ""
    field = "done_by" if event_type == "thread.done" else "completed_by"
    return str(payload.get(field, "")).strip().casefold()


def _is_authoritative_terminal(event: object, execution: Execution) -> bool:
    expected_type = "thread.done" if execution.subject_type == "thread" else "handoff.completed"
    return (
        getattr(event, "type", "") == expected_type
        and getattr(event, "task_id", "") == execution.subject_id
        and _terminal_actor(event) == execution.target.strip().casefold()
        and getattr(event, "payload", {}).get("actor_identity_bound") is True
    )


def _terminal_index(events: Sequence[ControlEvent]) -> dict[tuple[str, str, str], ControlEvent]:
    """Newest identity-bound terminal per subject and actor; not an authority rule."""
    terminals: dict[tuple[str, str, str], ControlEvent] = {}
    for event in reversed(events):
        if (event.type in {"thread.done", "handoff.completed"}
                and event.payload.get("actor_identity_bound") is True):
            terminals.setdefault((event.type, event.task_id, _terminal_actor(event)), event)
    return terminals


def _indexed_terminal(
    terminals: Mapping[tuple[str, str, str], ControlEvent], execution: Execution,
) -> ControlEvent | None:
    expected_type = "thread.done" if execution.subject_type == "thread" else "handoff.completed"
    candidate = terminals.get((expected_type, execution.subject_id, execution.target.strip().casefold()))
    return candidate if candidate is not None and _is_authoritative_terminal(candidate, execution) else None


def reconcile_executions(state: Path, *, now: datetime | None = None) -> list[Execution]:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    return _reconcile_executions(state, now=now)


def _reconcile_executions(
    state: Path, *, now: datetime | None = None, capable: set[str] | None = None,
) -> list[Execution]:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    reconciled: list[Execution] = []
    with _locked_state(state):
        from .decisions import _reconcile_decision_transitions_unlocked
        _reconcile_decision_transitions_unlocked(state, now=now, capable=capable)
        executions = project_executions(state)
        events = read_events(state)
        from .operator_archive import archived_ids
        archived = archived_ids(events)
        explicitly_closed = {e.task_id for e in events
                             if e.type == "execution.closed" and e.payload.get("status") == "closed"
                             and isinstance(e.payload.get("operator_archive"), dict)
                             and e.payload["operator_archive"].get("operation") == "operator_archive"}
        # One pass over the log, newest first, indexes the newest identity-bound terminal
        # per (type, subject, actor). The previous per-execution rescan of the whole log was
        # O(executions x events) and held the state lock for ~30 s per tick at 306k events.
        # Only bound terminals enter the index, so a later unbound or forged terminal can
        # never mask an earlier authoritative one; the full check below still decides.
        newest_terminal = _terminal_index(events)
        for execution in executions.values():
            if capable is not None and execution.target not in capable:
                continue
            if execution.subject_id in archived or execution.id in explicitly_closed:
                continue
            if execution.status == "completed":
                continue
            terminal = _indexed_terminal(newest_terminal, execution)
            if terminal is None:
                continue
            # Same rule as materialize_executions: stamp where the event is
            # appended so a reconciled completion cannot predate its terminal.
            stamp = _timestamp(now)
            updated = replace(
                execution, status="completed", updated_at=stamp, lease_owner="", lease_expires_at="",
                terminal_event_id=terminal.id, terminal_event_type=terminal.type,
            )
            _append_event_unlocked(state, _event("execution.completed", execution.id, stamp, updated.to_dict()))
            reconciled.append(updated)
    return reconciled


def is_blocked_report(text: str) -> bool:
    """A thread reply whose first word is BLOCKED (any case, markup allowed)."""
    return bool(_BLOCKED_REPORT.match(_ZERO_WIDTH.sub("", text)))


def _blocked_streaks(
    events: Sequence[object], executions: Mapping[str, Execution],
) -> dict[str, tuple[int, str]]:
    """Consecutive trailing BLOCKED attempts per thread execution, in one pass.

    An attempt counts when the latest reply its target posted on the subject
    thread during that attempt (between its ``execution.attempt.started`` and
    the next one) is a BLOCKED report. The streak resets on any new input:
    a reply from anyone other than the target, the first identity-bound terminal
    of an exact continuation child owned by a different identity, a steer request, a resume, or a replay (an
    explicit decision to try again), and on any attempt that
    ended without a BLOCKED report. "Same reason" is therefore structural,
    not textual: with no new input the blocker cannot have been resolved
    through the control plane, however the model words it the second time.
    Returns ``{execution_id: (streak, latest BLOCKED text)}``.
    """
    by_subject: dict[str, list[str]] = {}
    targets: dict[str, str] = {}
    for execution in executions.values():
        if execution.subject_type != "thread":
            continue
        by_subject.setdefault(execution.subject_id, []).append(execution.id)
        targets[execution.id] = execution.target.strip().casefold()
    streak: dict[str, list[str]] = {execution_id: [] for execution_id in targets}
    attempt_open: dict[str, bool] = dict.fromkeys(targets, False)
    latest: dict[str, tuple[bool, str] | None] = dict.fromkeys(targets)
    # Bind child completion to the immutable, identity-bound assignment, not
    # continuation fields copied into a terminal notification. The child need
    # not have a materialized execution on this worker's capable-target set.
    dependencies: dict[str, tuple[str, list[str]]] = {}
    completed_dependencies: set[str] = set()

    def close(execution_id: str) -> None:
        if not attempt_open[execution_id]:
            return
        report = latest[execution_id]
        if report is not None and report[0]:
            streak[execution_id].append(report[1])
        elif report is not None:
            # The target reported something other than BLOCKED: progress.
            streak[execution_id] = []
        # An attempt with no target reply at all (silent, or a transport
        # rejection) is neutral: it neither extends nor clears the streak, so
        # BLOCKED / silence / BLOCKED still reaches the bound.
        attempt_open[execution_id] = False
        latest[execution_id] = None

    def reset(execution_id: str) -> None:
        streak[execution_id] = []
        latest[execution_id] = None

    for event in events:
        event_type = str(getattr(event, "type", ""))
        task_id = str(getattr(event, "task_id", ""))
        if event_type == "thread.created":
            payload = getattr(event, "payload", {})
            if not isinstance(payload, dict) or payload.get("actor_identity_bound") is not True:
                continue
            parent_id = str(payload.get("continuation_thread_id", "")).strip()
            actor = str(payload.get("actor", "")).strip().casefold()
            child_target = str(payload.get("target", "")).strip().casefold()
            parents = [key for key in by_subject.get(parent_id, ()) if targets[key] == actor]
            if parents and child_target and child_target != "all" and child_target != actor:
                dependencies.setdefault(task_id, (child_target, parents))
        elif event_type == "thread.done" and task_id in dependencies:
            child_target, parents = dependencies[task_id]
            if (task_id not in completed_dependencies
                    and getattr(event, "payload", {}).get("actor_identity_bound") is True
                    and _terminal_actor(event) == child_target):
                completed_dependencies.add(task_id)
                for execution_id in parents:
                    # A different identity's completion is new input. Closing the
                    # open attempt drops its in-flight report, matching
                    # steer/resume/replay; it can delay HOLD by at most one
                    # attempt. This does not revive HOLD/cancel, grant a lease,
                    # or complete the parent.
                    close(execution_id)
                    reset(execution_id)
        elif event_type == "execution.attempt.started" and task_id in targets:
            close(task_id)
            attempt_open[task_id] = True
        elif event_type in {"execution.steer.requested", "execution.resumed", "execution.replayed"} and task_id in targets:
            close(task_id)
            reset(task_id)
        elif event_type == "thread.message.posted" and task_id in by_subject:
            payload = getattr(event, "payload", {})
            if not isinstance(payload, dict):
                continue
            actor = str(payload.get("posted_by", "")).strip().casefold()
            text = str(payload.get("text", "")).strip()
            for execution_id in by_subject[task_id]:
                if actor and actor == targets[execution_id]:
                    if attempt_open[execution_id]:
                        latest[execution_id] = (is_blocked_report(text), text)
                else:
                    reset(execution_id)
    result: dict[str, tuple[int, str]] = {}
    for execution_id in targets:
        close(execution_id)
        if streak[execution_id]:
            result[execution_id] = (len(streak[execution_id]), streak[execution_id][-1])
    return result


def _blocked_hold_reason(streak: int, report: str) -> str:
    excerpt = " ".join(report.split())
    if len(excerpt) > _BLOCKED_REASON_MAX_CHARS:
        excerpt = excerpt[: _BLOCKED_REASON_MAX_CHARS - 3] + "..."
    return redact_secrets(
        f"{BLOCKED_HOLD_REASON_PREFIX} on {streak} consecutive attempts with no new input; "
        "re-waking cannot resolve it. Operator: supply the missing input or authority on the "
        "subject (or reassign the work to the identity that owns it), then replay the execution. "
        f"Latest report: {excerpt}"
    )[:1024]


def _retry_backoff(attempts: int, *, base_seconds: int, max_seconds: int) -> timedelta:
    if attempts < 1 or base_seconds < 1:
        return timedelta(0)
    return timedelta(seconds=min(max_seconds, base_seconds * 2 ** (attempts - 1)))


def _awaiting_first_heartbeat(execution: Execution) -> bool:
    """The attempt's accepted wake opened a window no target heartbeat closed."""
    return bool(execution.first_heartbeat_deadline) and not execution.first_target_heartbeat_at


def _whole_seconds(start: str, end: str) -> int:
    return int(round((_parse(end) - _parse(start)).total_seconds()))


def _expired_attempt_failure(execution: Execution) -> str:
    """Why a leased attempt expired, so "never started" reads apart from "stopped".

    Derived only from the attempt's projected fields. An attempt without the
    window fields (events written before B6, or a worker that died before
    recording the accepted wake) keeps the historical message.
    """
    if execution.first_target_heartbeat_at and execution.heartbeat_at:
        return (
            f"{RENEWAL_LAPSED_PREFIX}: the renewal lease "
            f"({_whole_seconds(execution.heartbeat_at, execution.lease_expires_at)}s) expired "
            "after the last heartbeat with no further target heartbeat or finalization"
        )
    if _awaiting_first_heartbeat(execution) and execution.heartbeat_at:
        window = _whole_seconds(execution.heartbeat_at, execution.first_heartbeat_deadline)
        return f"{FIRST_HEARTBEAT_EXPIRED_PREFIX} ({window}s) after accepted wake"
    return LEASE_EXPIRED_FAILURE


def _validated_worker(worker: str) -> str:
    """Trim worker boundaries without changing case-sensitive ownership."""
    if not isinstance(worker, str) or not worker.strip():
        raise ValueError("worker must be a non-empty string")
    return worker.strip()


def _claim_exact_execution(
    state: Path, *, worker: str, execution_capable_targets: set[str],
    execution_id: str | None, subject_id: str | None, target: str | None,
    now: datetime | None, lease_seconds: int,
) -> Execution:
    """Fresh one-shot only: never reconcile, retry, replay, or scan-to-claim.

    Resolve and validate under the same state lock as creation and claim. An
    exact selector is an operator safety fence, not new agent authority.
    """
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    worker = _validated_worker(worker)
    if (execution_id is None) == (subject_id is None):
        raise ValueError("exactly one execution_id or subject_id is required")
    selector = execution_id if execution_id is not None else subject_id
    if not selector or selector != selector.strip():
        raise ValueError("exact selector must be non-empty and literal")
    if not target or target != target.strip().casefold() or target not in execution_capable_targets:
        raise ValueError("exact selection requires a canonical configured target")
    with _locked_state(state):
        events = read_events(state)
        existing = _project_executions(events)
        selected = existing.get(execution_id) if execution_id is not None else None
        if execution_id is not None and selected is None:
            raise ValueError("exact execution is unavailable")
        wanted = selected.subject_id if selected is not None else subject_id
        from .operator_archive import require_unarchived
        require_unarchived(state, wanted)
        sources = [event for event in events if event.task_id == wanted
                   and event.type in {"thread.created", "handoff.created"}]
        if len(sources) != 1:
            raise ValueError("exact assignment is unavailable or ambiguous")
        source = sources[0]
        kind = "thread" if source.type == "thread.created" else "handoff"
        owner = source.payload.get("target" if kind == "thread" else "to_agent")
        if (not same_agent_identity(owner, target) or source.payload.get("actor_identity_bound") is not True
                or (kind == "thread" and source.payload.get("type") not in {"ask", "handoff", "blocker"})):
            raise ValueError("exact assignment is not authorized for target")
        root_id = _execution_id(kind, source.task_id, target)
        if execution_id is not None and execution_id != root_id:
            raise ValueError("exact execution does not match assignment")
        from .exact_fences import validate_known_lineage
        validate_known_lineage(events, {root_id, source.task_id})
        selected = existing.get(root_id)
        if selected is None and any(e.task_id == root_id and e.type.startswith("execution.") for e in events):
            raise ValueError("exact execution root exists but is invalid or quarantined")
        if selected is not None and (
            selected.id, selected.subject_id, selected.subject_type, selected.target,
            selected.source_event_id, selected.source_event_type,
        ) != (root_id, source.task_id, kind, target, source.id, source.type):
            raise ValueError("exact execution provenance does not match assignment")
        if selected is not None and (selected.target != target or selected.status != "pending"
                                     or selected.attempts != 0):
            raise ValueError("exact execution is not fresh pending work")
        # Freshness belongs to the append-only lineage, not the resettable
        # attempt budget. HOLD/replay and pause/resume never restore eligibility
        # for an exact canary, even when no attempt has started yet. Ordinary
        # worker claims retain their existing replay/resume behavior.
        nonfresh_events = {
            "execution.attempt.started", "execution.held", "execution.replayed",
            "execution.cancel_requested", "execution.resumed",
        }
        if any(e.task_id == root_id and e.type in nonfresh_events for e in events):
            raise ValueError("exact execution has non-fresh history; replay/resume is not a canary")
        current = now or datetime.now(timezone.utc)
        stamp = _timestamp(current)
        candidate = selected or Execution(
            id=root_id, subject_id=source.task_id, subject_type=kind, target=target,
            source_event_id=source.id, source_event_type=source.type, status="pending",
            attempts=0, created_at=source.timestamp, updated_at=stamp,
        )
        if any(_is_authoritative_terminal(e, candidate) for e in events):
            raise ValueError("exact assignment is already terminal")
        threads = _project_threads(state, events)
        if any(t.continuation_thread_id == wanted and t.pending for t in threads.values()):
            raise ValueError("exact assignment is waiting for a continuation")
        # All refusal checks precede the first append. No unrelated root or
        # completion is materialized as a side effect of this bounded path.
        if selected is None:
            _append_event_unlocked(state, _event("execution.created", root_id, stamp, candidate.to_dict()))
        claimed = replace(candidate, status="leased", attempts=1, updated_at=stamp,
                          lease_owner=worker, lease_expires_at=_timestamp(current + timedelta(seconds=lease_seconds)),
                          attempt_id=_attempt_id(root_id, 1, stamp), resume_pending=False)
        _append_event_unlocked(state, _event("execution.attempt.started", root_id, stamp, claimed.to_dict()))
        return claimed


def claim_execution(
    state: Path, *, worker: str, execution_capable_targets: Iterable[str], now: datetime | None = None,
    lease_seconds: int = 60, max_attempts: int = 3,
    retry_backoff_seconds: int = RETRY_BACKOFF_BASE_SECONDS,
    retry_backoff_max_seconds: int = RETRY_BACKOFF_MAX_SECONDS,
    blocked_rewake_limit: int = BLOCKED_REWAKE_LIMIT,
    execution_id: str | None = None, subject_id: str | None = None, target: str | None = None,
) -> Execution | None:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    worker = _validated_worker(worker)
    if lease_seconds < 1 or max_attempts < 1:
        raise ValueError("lease_seconds and max_attempts must be positive")
    if retry_backoff_seconds < 0 or retry_backoff_max_seconds < retry_backoff_seconds:
        raise ValueError("retry backoff bounds must be non-negative and ordered")
    if blocked_rewake_limit < 1:
        raise ValueError("blocked_rewake_limit must be positive")
    # Consume route iterables once, before any state-changing path. Empty means
    # no authority; None remains invalid rather than becoming unrestricted.
    capable = {value.strip().casefold() for value in execution_capable_targets if value.strip()}
    if execution_id is not None or subject_id is not None or target is not None:
        return _claim_exact_execution(
            state, worker=worker, execution_capable_targets=capable,
            execution_id=execution_id, subject_id=subject_id, target=target,
            now=now, lease_seconds=lease_seconds,
        )
    # ``now`` is forwarded unchanged, never concretised into ``current``: a
    # concrete value would pin every downstream stamp to this pass's start.
    _materialize_executions(state, capable=capable, now=now)
    _reconcile_executions(state, capable=capable, now=now)
    with _locked_state(state):
        events = read_events(state)
        threads = _project_threads(state, events)
        waiting_parent_ids = {
            thread.continuation_thread_id
            for thread in threads.values()
            if thread.continuation_thread_id and thread.pending
        }
        executions = _project_executions(events)
        newest_terminal = _terminal_index(events)
        blocked = _blocked_streaks(events, executions)
        from .operator_archive import archived_ids
        archived = archived_ids(events)
        for execution in sorted(executions.values(), key=lambda item: (item.created_at, item.id)):
            if execution.target not in capable:
                continue
            if execution.subject_id in archived or execution.status in EXECUTION_INERT_STATUSES:
                continue
            # The earlier reconciliation held a different lock acquisition. A
            # terminal appended in that gap must win over every claim mutation.
            terminal = _indexed_terminal(newest_terminal, execution)
            if terminal is not None:
                stamp = _timestamp(now)
                completed = replace(
                    execution, status="completed", updated_at=stamp,
                    lease_owner="", lease_expires_at="",
                    terminal_event_id=terminal.id, terminal_event_type=terminal.type,
                )
                _append_event_unlocked(
                    state, _event("execution.completed", execution.id, stamp, completed.to_dict()),
                )
                continue
            if execution.subject_type == "thread" and execution.subject_id in waiting_parent_ids:
                continue
            current = now if now is not None else datetime.now(timezone.utc)
            if execution.status == "leased" and _parse(execution.lease_expires_at) > current:
                continue
            streak, report = blocked.get(execution.id, (0, ""))
            # Sample authority only after the lock and projections; retain a
            # fresh append stamp and preserve explicitly injected clocks.
            appended = current if now is not None else datetime.now(timezone.utc)
            stamp = _timestamp(appended)
            if streak >= blocked_rewake_limit:
                # Dedupe instead of re-waking: the target already reported
                # the same blocker and nobody changed anything since. Park it
                # in the canonical HOLD; only operator replay (or a real
                # target-authored terminal) moves it again, and the watchdog
                # escalates it to the operator exactly once.
                held = replace(
                    execution, status="held", updated_at=stamp, lease_owner="",
                    lease_expires_at="", hold_reason=_blocked_hold_reason(streak, report),
                    held_by=worker,
                )
                _append_event_unlocked(state, _event("execution.held", execution.id, stamp, held.to_dict()))
                continue
            if execution.attempts > 0 and not execution.resume_pending:
                # Re-wake backoff: an expired lease retries after its expiry
                # plus backoff; a failed attempt retries after its failure
                # plus backoff. Fresh executions claim immediately.
                anchor = execution.lease_expires_at if execution.status == "leased" else execution.updated_at
                backoff = _retry_backoff(
                    execution.attempts,
                    base_seconds=retry_backoff_seconds,
                    max_seconds=retry_backoff_max_seconds,
                )
                if anchor and _parse(anchor) + backoff > current:
                    continue
            attempts = execution.attempts + 1
            last_failure = execution.last_failure
            if execution.status == "leased":
                last_failure = _expired_attempt_failure(execution)
            if attempts > max_attempts:
                updated = replace(execution, status="dead_lettered", updated_at=stamp, lease_owner="",
                                  lease_expires_at="", last_failure=last_failure)
                _append_event_unlocked(state, _event("execution.dead_lettered", execution.id, stamp, updated.to_dict()))
                continue
            # A new attempt starts outside any window: its own accepted wake
            # opens its own first-heartbeat window.
            updated = replace(
                execution, status="leased", attempts=attempts, updated_at=stamp, lease_owner=worker,
                lease_expires_at=_timestamp(appended + timedelta(seconds=lease_seconds)),
                attempt_id=_attempt_id(execution.id, attempts, stamp), last_failure=last_failure,
                runtime_outcome="", resume_pending=False,
                first_heartbeat_deadline="", first_target_heartbeat_at="",
            )
            _append_event_unlocked(state, _event("execution.attempt.started", execution.id, stamp, updated.to_dict()))
            return updated
    return None


def _leased(
    state: Path, execution_id: str, attempt_id: str, worker: str, now: datetime | None,
    *, allow_expired: bool = False,
) -> Execution:
    normalized_worker = _validated_worker(worker)
    execution = project_executions(state).get(execution_id)
    if execution is None:
        raise ValueError(f"unknown execution: {execution_id}")
    # Preserve exact legacy padded owners; newly claimed owners are trimmed.
    # Never casefold: worker leases are not target-identity aliases.
    if execution.status != "leased" or execution.lease_owner not in (worker, normalized_worker):
        raise ValueError("execution is not leased by worker")
    if not attempt_id or execution.attempt_id != attempt_id:
        raise ValueError("execution attempt is stale")
    if not allow_expired and _parse(execution.lease_expires_at) <= (now or datetime.now(timezone.utc)):
        raise ValueError("execution lease expired")
    return execution


def heartbeat_execution(
    state: Path, *, execution_id: str, attempt_id: str, worker: str, now: datetime | None = None,
    lease_seconds: int = 60, detail: str = "", heartbeat_by: str = "",
    actor_identity_bound: bool = False, runtime_outcome: str = "",
    first_heartbeat_seconds: int | None = None,
) -> Execution:
    """Renew a live attempt's lease.

    ``first_heartbeat_seconds`` is only for the worker's accepted-wake
    heartbeat: it opens the attempt's first-heartbeat window, running the lease
    to ``now + first_heartbeat_seconds`` and recording that deadline in the
    event. Only an identity-bound target heartbeat counts as the attempt's
    first heartbeat; from then on every target heartbeat renews by
    ``lease_seconds``, and a later worker heartbeat never reopens a window.
    """
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    if lease_seconds < 1:
        raise ValueError("lease_seconds must be positive")
    if lease_seconds > MAX_LEASE_SECONDS:
        raise ValueError(f"lease_seconds must be at most {MAX_LEASE_SECONDS}")
    if first_heartbeat_seconds is not None:
        if actor_identity_bound:
            raise ValueError(
                "the first-heartbeat window is opened only by the worker's accepted-wake heartbeat"
            )
        if isinstance(first_heartbeat_seconds, bool) or not isinstance(first_heartbeat_seconds, int):
            raise ValueError("first_heartbeat_seconds must be an integer")
        if first_heartbeat_seconds < lease_seconds:
            raise ValueError(
                f"first_heartbeat_seconds must be at least lease_seconds ({lease_seconds})"
            )
        if first_heartbeat_seconds > MAX_LEASE_SECONDS:
            raise ValueError(f"first_heartbeat_seconds must be at most {MAX_LEASE_SECONDS}")
    runtime_outcome = runtime_outcome.strip().casefold()
    if runtime_outcome and runtime_outcome not in RUNTIME_OUTCOMES:
        raise ValueError(
            "runtime outcome must be one of: " + ", ".join(sorted(RUNTIME_OUTCOMES))
        )
    with _locked_state(state):
        execution = _leased(state, execution_id, attempt_id, worker, now, allow_expired=True)
        current = now if now is not None else datetime.now(timezone.utc)
        if _parse(execution.lease_expires_at) <= current:
            raise ValueError("execution lease expired")
        timestamp = _timestamp(current)
        normalized_actor = heartbeat_by.strip().casefold()
        if actor_identity_bound:
            if not normalized_actor or normalized_actor != execution.target.strip().casefold():
                raise ValueError("heartbeat requires the identity-bound target actor")
        elif normalized_actor:
            raise ValueError("heartbeat actor provenance is not identity-bound")
        lease_expires_at = _timestamp(current + timedelta(seconds=lease_seconds))
        first_heartbeat_deadline = execution.first_heartbeat_deadline
        first_target_heartbeat_at = execution.first_target_heartbeat_at
        opens_window = False
        if actor_identity_bound:
            # The first identity-bound target heartbeat ends the window; this
            # and every later one renews by lease_seconds.
            first_target_heartbeat_at = first_target_heartbeat_at or timestamp
        elif first_heartbeat_deadline and not first_target_heartbeat_at:
            # Accepted-wake retries and plain worker renewals cannot slide or
            # erase an already established window within this exact attempt.
            lease_expires_at = execution.lease_expires_at
        elif first_heartbeat_seconds is not None and not first_target_heartbeat_at:
            opens_window = True
            lease_expires_at = _timestamp(current + timedelta(seconds=first_heartbeat_seconds))
            first_heartbeat_deadline = lease_expires_at
        elif not first_target_heartbeat_at:
            # A plain worker renewal is the pre-window lease: it does not keep
            # a window open. After a target heartbeat the renewal lease already
            # applies and the recorded deadline stays as history.
            first_heartbeat_deadline = ""
        # Runtime detail is diagnostic only and deliberately cannot affect terminal state.
        updated = replace(
            execution,
            updated_at=timestamp,
            heartbeat_at=timestamp,
            lease_expires_at=lease_expires_at,
            runtime_outcome=runtime_outcome,
            first_heartbeat_deadline=first_heartbeat_deadline,
            first_target_heartbeat_at=first_target_heartbeat_at,
        )
        payload = updated.to_dict()
        if opens_window:
            payload["first_heartbeat_seconds"] = int(first_heartbeat_seconds)
        if detail:
            payload["runtime_detail"] = redact_secrets(detail)[:4096]
        if actor_identity_bound:
            payload["heartbeat_by"] = normalized_actor
            payload["actor_identity_bound"] = True
        _append_event_unlocked(state, _event("execution.heartbeat", execution.id, timestamp, payload))
        return updated


def execution_session(
    state: Path, *, execution_id: str, attempt_id: str, actor: str,
    now: datetime | None = None,
) -> Execution:
    """Return one live attempt only to its authenticated target identity."""
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    normalized_actor = actor.strip().casefold()
    if not normalized_actor:
        raise ValueError("execution session requires the identity-bound target actor")
    with _locked_state(state):
        execution = project_executions(state).get(execution_id)
        if execution is None:
            raise ValueError(f"unknown execution: {execution_id}")
        if normalized_actor != execution.target.strip().casefold():
            raise ValueError("execution session requires the identity-bound target actor")
        if execution.status != "leased":
            raise ValueError("execution attempt is not live")
        if not attempt_id or execution.attempt_id != attempt_id:
            raise ValueError("execution attempt is stale")
        current = now if now is not None else datetime.now(timezone.utc)
        if _parse(execution.lease_expires_at) <= current:
            raise ValueError("execution lease expired")
        return execution


def heartbeat_execution_as_target(
    state: Path, *, execution_id: str, attempt_id: str, actor: str,
    now: datetime | None = None, lease_seconds: int = 60, detail: str = "",
    runtime_outcome: str = "",
) -> Execution:
    """Extend a live attempt from the authenticated execution target."""
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    execution = execution_session(
        state, execution_id=execution_id, attempt_id=attempt_id, actor=actor, now=now,
    )
    return heartbeat_execution(
        state, execution_id=execution_id, attempt_id=attempt_id,
        worker=execution.lease_owner, now=now, lease_seconds=lease_seconds,
        detail=detail, heartbeat_by=actor, actor_identity_bound=True,
        runtime_outcome=runtime_outcome,
    )


def record_execution_failure(
    state: Path, *, execution_id: str, attempt_id: str, worker: str, detail: str,
    now: datetime | None = None,
) -> Execution:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    current = now or datetime.now(timezone.utc)

    def stamp() -> str:
        # Sample per append, never on entry. This function reads the event log
        # before it writes anything, so a stamp taken on entry can predate the
        # source event that produced this write. With an injected clock the
        # stamp stays pinned exactly as before.
        return _timestamp(now)
    with _locked_state(state):
        execution = _leased(
            state, execution_id, attempt_id, worker, current, allow_expired=True,
        )
        terminal = next(
            (
                event for event in reversed(read_events(state))
                if _is_authoritative_terminal(event, execution)
            ),
            None,
        )
        if terminal is not None:
            updated = replace(
                execution, status="completed", updated_at=stamp(), lease_owner="",
                lease_expires_at="", terminal_event_id=terminal.id,
                terminal_event_type=terminal.type,
            )
            _append_event_unlocked(
                state, _event("execution.completed", execution.id, stamp(), updated.to_dict()),
            )
            return updated
        updated = replace(execution, status="pending", updated_at=stamp(), lease_owner="", lease_expires_at="",
                          last_failure=redact_secrets(detail)[:4096])
        _append_event_unlocked(state, _event("execution.attempt.failed", execution.id, stamp(), updated.to_dict()))
        return updated


def replay_execution(
    state: Path, *, execution_id: str, replayed_by: str = "operator", now: datetime | None = None,
) -> Execution:
    """Give a dead-lettered or held execution a fresh attempt budget.

    Append-only: the original dead-letter/hold evidence stays in the log; the
    replay resets the projection to pending with attempts=0 under the same
    stable execution ID so the retry lineage is preserved.
    """
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    current = now or datetime.now(timezone.utc)

    def stamp() -> str:
        # Sample per append, never on entry. This function reads the event log
        # before it writes anything, so a stamp taken on entry can predate the
        # source event that produced this write. With an injected clock the
        # stamp stays pinned exactly as before.
        return _timestamp(now)
    replayed_by = replayed_by.strip() or "operator"
    with _locked_state(state):
        execution = project_executions(state).get(execution_id)
        if execution is None:
            raise ValueError(f"unknown execution: {execution_id}")
        if execution.status not in {"dead_lettered", "held"}:
            raise ValueError(
                f"execution is not dead-lettered or held: {execution_id} status={execution.status}"
            )
        return _replay_execution_unlocked(state, execution, actor=replayed_by, now=now)


def _replay_execution_unlocked(
    state: Path, execution: Execution, *, actor: str, now: datetime | None,
) -> Execution:
    """Append a validated replay while the caller holds the state lock."""
    stamp = _timestamp(now)
    updated = replace(
        execution, status="pending", attempts=0, updated_at=stamp,
        lease_owner="", lease_expires_at="", attempt_id="",
        hold_reason="", held_by="",
    )
    payload = updated.to_dict()
    payload["replayed_by"] = actor
    payload["replayed_from_status"] = execution.status
    _append_event_unlocked(state, _event("execution.replayed", execution.id, stamp, payload))
    return updated


def hold_execution(
    state: Path, *, execution_id: str, reason: str, held_by: str, now: datetime | None = None,
) -> Execution:
    """Move an execution into the canonical operator-attention HOLD state.

    Idempotent: holding an already-held execution returns it unchanged so an
    overlapping watchdog tick cannot double-escalate. A completed or already
    closed execution cannot be held: a closure is terminal and must not be
    reversible. A later authoritative terminal still reconciles a held
    execution to completed.
    """
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    reason = redact_secrets(reason.strip())[:1024]
    held_by = held_by.strip()
    if not reason:
        raise ValueError("hold reason must not be empty")
    if not held_by:
        raise ValueError("held_by must not be empty")
    current = now or datetime.now(timezone.utc)

    def stamp() -> str:
        # Sample per append, never on entry. This function reads the event log
        # before it writes anything, so a stamp taken on entry can predate the
        # source event that produced this write. With an injected clock the
        # stamp stays pinned exactly as before.
        return _timestamp(now)
    with _locked_state(state):
        execution = project_executions(state).get(execution_id)
        if execution is None:
            raise ValueError(f"unknown execution: {execution_id}")
        if execution.status == "held":
            _acknowledge_execution_replay_unlocked(state, execution)
            return execution
        if execution.status in {"completed", "closed"}:
            raise ValueError(f"{execution.status} execution cannot be held: {execution_id}")
        return _hold_execution_unlocked(state, execution, actor=held_by, reason=reason, now=now)


def _hold_execution_unlocked(
    state: Path, execution: Execution, *, actor: str, reason: str, now: datetime | None,
) -> Execution:
    """Append a validated HOLD while the caller holds the state lock."""
    stamp = _timestamp(now)
    updated = replace(
        execution, status="held", updated_at=stamp,
        lease_owner="", lease_expires_at="", hold_reason=reason, held_by=actor,
    )
    _append_event_unlocked(state, _event("execution.held", execution.id, stamp, updated.to_dict()))
    return updated


def remediate_dead_letter(
    state: Path, execution_id: str, *, expected_event_id: str, actor: str,
    max_replays: int, hold_reason: str, now: datetime | None = None,
) -> tuple[str, Execution | None]:
    """Condition watchdog recovery on one exact authoritative state revision.

    Revision/status/attempt eligibility and the *current* replay budget are
    checked against the same event snapshot under the write lock. An event ID
    identifies the entire state snapshot, including attempt identity. Changed,
    missing or quarantined lineages are benign skips; validation, authority,
    corruption and durability failures propagate rather than becoming skips.
    """
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    actor = actor.strip()
    reason = redact_secrets(hold_reason.strip())[:1024]
    if not execution_id or not expected_event_id or not actor or not reason:
        raise ValueError("execution, expected revision, actor and HOLD reason are required")
    if isinstance(max_replays, bool) or not isinstance(max_replays, int) or max_replays < 0:
        raise ValueError("max_replays must be a non-negative integer")
    with _locked_state(state):
        events = read_events(state)
        execution = _project_executions(events).get(execution_id)
        latest = next((event for event in reversed(events)
                       if event.task_id == execution_id
                       and event.type in EXECUTION_STATE_EVENT_TYPES), None)
        if (execution is None or latest is None or latest.id != expected_event_id
                or execution.status != "dead_lettered"):
            return "changed", execution
        # Subject completion can race the watchdog without changing the
        # execution revision. Consult the same authoritative locked snapshot.
        if _indexed_terminal(_terminal_index(events), execution) is not None:
            return "changed", execution
        # Duplicate revision IDs cannot supply an unambiguous compare token.
        if sum(event.id == expected_event_id for event in events) != 1:
            raise ValueError("execution remediation revision is ambiguous")
        replays = sum(event.type == "execution.replayed" and event.task_id == execution_id
                      for event in events)
        if replays < max_replays:
            return "replayed", _replay_execution_unlocked(state, execution, actor=actor, now=now)
        return "held", _hold_execution_unlocked(state, execution, actor=actor, reason=reason, now=now)


def close_execution(
    state: Path, *, execution_id: str, resolution_category: str, reason: str,
    closed_by: str, now: datetime | None = None,
) -> Execution:
    """Close a held or dead-lettered execution as terminally not-actionable.

    A held execution stays in the operator queue forever unless it is replayed
    or a real authoritative terminal event arrives. Work that will never run
    again (superseded canary, obsolete flow, completed elsewhere) therefore had
    no supported closure, so `held_count` could never return to zero and the
    operator queue could not be told apart from live debt.

    Closing is operator-only, append-only and terminal:

    - only ``held`` or ``dead_lettered`` executions may be closed; live
      (pending/leased) work must be held first, a ``paused`` execution must be
      resumed or held first, and a ``completed`` execution keeps its real
      completion evidence;
    - ``resolution_category`` must name why the work stopped, exactly as one of
      the canonical lowercase categories (the same contract the CLI choices and
      the sibling operator-resolution route enforce), and ``reason`` must be
      non-empty (secret-shaped text is rejected like every other control
      message);
    - idempotent for the same category: closing an already-closed execution
      again returns it unchanged so a retried operator command cannot rewrite
      the recorded resolution. A repeat that names a different category is
      refused instead of silently keeping the original one, which would report
      a resolution the operator never actually recorded;
    - the original hold/dead-letter evidence stays in the append-only log.

    A closed execution is inert (never claimed, never replayable), cannot be
    re-opened by ``hold``/``cancel``, and is excluded from the operator queue
    counts. A later authoritative terminal event still reconciles it to
    ``completed``.
    """
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    category = resolution_category.strip()
    if not category:
        raise ValueError("resolution category must not be empty")
    if category not in CLOSE_RESOLUTION_CATEGORIES:
        raise ValueError(
            f"unknown resolution category: {resolution_category}; expected one of "
            f"{', '.join(sorted(CLOSE_RESOLUTION_CATEGORIES))}"
        )
    reason = _control_message(reason, label="close reason")
    actor = closed_by.strip()
    if not actor:
        raise ValueError("closed_by must not be empty")

    def stamp() -> str:
        # Sample per append, never on entry. This function reads the event log
        # before it writes anything, so a stamp taken on entry can predate the
        # source event that produced this write. With an injected clock the
        # stamp stays pinned exactly as before.
        return _timestamp(now)
    with _locked_state(state):
        execution = project_executions(state).get(execution_id)
        if execution is None:
            raise ValueError(f"unknown execution: {execution_id}")
        if execution.status == "closed":
            if execution.resolution_category == category:
                _acknowledge_execution_replay_unlocked(state, execution)
                return execution
            raise ValueError(
                f"execution is already closed as {execution.resolution_category}: {execution_id}"
            )
        if execution.status == "completed":
            raise ValueError(f"completed execution cannot be closed: {execution_id}")
        if execution.status == "paused":
            raise ValueError(
                f"paused execution cannot be closed: {execution_id}; resume or hold it first"
            )
        if execution.status not in {"held", "dead_lettered"}:
            raise ValueError(
                f"live execution cannot be closed: {execution_id}; hold it first"
            )
        updated = replace(
            execution, status="closed", updated_at=stamp(),
            lease_owner="", lease_expires_at="",
            close_reason=reason, closed_by=actor, closed_at=stamp(),
            resolution_category=category,
        )
        _append_event_unlocked(
            state, _event("execution.closed", execution.id, stamp(), updated.to_dict())
        )
        return updated


def count_execution_replays(state: Path) -> dict[str, int]:
    """Replay lineage per execution ID, for bounded autonomous remediation."""
    counts: dict[str, int] = {}
    for event in read_events(state):
        if event.type == "execution.replayed":
            counts[event.task_id] = counts.get(event.task_id, 0) + 1
    return counts


def queue_health(
    state: Path, *, execution_capable_targets: set[str], now: datetime | None = None,
    heartbeat_stale_seconds: int = 300,
) -> dict[str, object]:
    current = now or datetime.now(timezone.utc)
    executions, quarantined = _execution_projection_state(state)
    live_subjects = {
        item.subject_id for item in executions.values()
        if item.status == "pending" or (item.status == "leased" and _parse(item.lease_expires_at) > current)
    }
    paused = sorted(item.id for item in executions.values() if item.status == "paused")
    paused_subjects = {item.subject_id for item in executions.values() if item.status == "paused"}
    # Closed executions are terminally resolved operator decisions: the subject
    # may still be an open thread or handoff, but no execution work remains.
    closed_subjects = {item.subject_id for item in executions.values() if item.status == "closed"}
    capable = {target.strip().casefold() for target in execution_capable_targets if target.strip()}
    eligible: dict[str, str] = {}
    done: set[str] = set()
    events = read_events(state)
    legacy_authorized = _legacy_authorized_assignments(events)
    for event in events:
        if event.type == "thread.created":
            target = str(event.payload.get("target", "")).strip().casefold()
            thread_type = str(event.payload.get("type", "")).strip().casefold()
            if (
                target and target != "all" and target in capable
                and thread_type in {"ask", "handoff", "blocker"}
                and (
                    event.payload.get("actor_identity_bound") is True
                    or ("thread", event.task_id) in legacy_authorized
                )
            ):
                eligible[event.task_id] = target
        elif event.type == "handoff.created":
            target = str(event.payload.get("to_agent", "")).strip().casefold()
            if (
                target and target in capable
                and (
                    event.payload.get("actor_identity_bound") is True
                    or ("handoff", event.task_id) in legacy_authorized
                )
            ):
                eligible[event.task_id] = target
        elif event.type in {"thread.done", "handoff.completed"}:
            target = eligible.get(event.task_id, "")
            if (
                target and _terminal_actor(event) == target
                and event.payload.get("actor_identity_bound") is True
            ):
                done.add(event.task_id)
    from .operator_archive import archived_ids
    retired_subjects = archived_ids(events)
    missing = sorted(set(eligible) - done - live_subjects - paused_subjects - closed_subjects - retired_subjects)
    # An attempt still inside its first-heartbeat window is starting, not
    # stale: its runtime has until the recorded deadline to heartbeat first.
    stale_heartbeats = sorted(
        item.id for item in executions.values()
        if item.status == "leased"
        and not (
            _awaiting_first_heartbeat(item)
            and _parse(item.first_heartbeat_deadline) > current
        )
        and (
            not item.heartbeat_at
            or (current - _parse(item.heartbeat_at)).total_seconds() >= heartbeat_stale_seconds
        )
    )
    return {
        "quarantined_execution_count": len(quarantined),
        "quarantined_executions": sorted(quarantined),
        "retired_subject_count": len(retired_subjects),
        "retired_subjects": sorted(retired_subjects),
        "assigned_without_live_execution_count": len(missing),
        "assigned_without_live_execution": missing,
        # Compatibility aliases for existing dashboards and operators.  The
        # kernel now starts from assignment, so these no longer imply ACK was
        # the execution trigger.
        "acked_without_live_execution_count": len(missing),
        "acked_without_live_execution": missing,
        "live_execution_count": len(live_subjects),
        "dead_lettered_count": sum(item.status == "dead_lettered" for item in executions.values()),
        "held_count": sum(item.status == "held" for item in executions.values()),
        "closed_count": sum(item.status == "closed" for item in executions.values()),
        "paused_execution_count": len(paused),
        "paused_executions": paused[:20],
        "leased_without_recent_heartbeat_count": len(stale_heartbeats),
        "leased_without_recent_heartbeat": stale_heartbeats[:20],
    }


def deliver_execution_attempt(
    execution: Execution,
    route: AgentRoute,
    *,
    now: datetime | None = None,
    environ: Mapping[str, str] | None = None,
    lease_seconds: int | None = None,
    state: Path | None = None,
    first_heartbeat_seconds: int | None = None,
) -> AgentDeliveryResult:
    """Wake the bound runtime through the existing authenticated transport.

    With ``state`` (the production worker path) the wake's delivery record is
    appended to the outbox projection *before* any network I/O, under the
    execution fence, and finalized after, so the delivery ID the wake names
    always resolves through ``control.delivery_get`` for the target. Without
    ``state`` the call is a pure transport helper.
    """
    from .replica_authority import assert_state_authority, assert_bound_authority
    if state is None:
        assert_bound_authority()
    else:
        assert_state_authority(state)
    if not execution.attempt_id or execution.status != "leased":
        return AgentDeliveryResult(False, "configuration", None, "execution attempt is not live")
    item = execution_wake_item(
        execution, lease_seconds=lease_seconds, first_heartbeat_seconds=first_heartbeat_seconds,
    )
    if state is None:
        return deliver_outbox_item(item, route, now=now, environ=environ)
    with _locked_state(state):
        # Read liveness and validate the canonical owner/attempt/expiry while
        # mutations are fenced. Sample the clock after reads and lock waiting.
        events = read_events(state)
        from .operator_archive import archived_ids
        archived = archived_ids(events)
        terminals = _terminal_index(events)
        try:
            live = _leased(
                state, execution.id, execution.attempt_id, execution.lease_owner, now,
            )
        except ValueError as exc:
            return AgentDeliveryResult(False, "configuration", None, str(exc))
        if (
            live.target != execution.target
            or live.subject_id in archived
            or _indexed_terminal(terminals, live) is not None
        ):
            return AgentDeliveryResult(False, "configuration", None, "execution subject is not live")
        item = execution_wake_item(
            live, lease_seconds=lease_seconds, first_heartbeat_seconds=first_heartbeat_seconds,
        )
        item = record_execution_wake_unlocked(state, item)
    result = deliver_outbox_item(item, route, now=now, environ=environ)
    finalize_execution_wake(
        state, outbox_id=item.id, worker=item.lease_owner, claim_attempts=item.attempts,
        accepted=result.accepted, detail=result.detail, now=now,
    )
    return result


def execution_wake_item(
    execution: Execution, *, lease_seconds: int | None = None,
    first_heartbeat_seconds: int | None = None,
) -> OutboxItem:
    """The deterministic delivery record for one fenced attempt's wake.

    Its target is always the execution owner: an execution wake can never name
    another identity's execution or attempt. ``first_heartbeat_seconds`` names
    the first-heartbeat window the worker opens once the wake is accepted, so
    the runtime is told both deadlines it is held to.
    """
    payload: dict[str, object] = {
        "schema": "v2.agent-delivery/1",
        "source_event_id": execution.source_event_id,
        "source_event_type": "execution.attempt.started",
        "origin_event_type": execution.source_event_type,
        "subject_id": execution.subject_id,
        "subject_type": execution.subject_type,
        "delivery_mode": "execution",
        "execution_id": execution.id,
        "attempt_id": execution.attempt_id,
        "target": execution.target,
    }
    if lease_seconds is not None and lease_seconds >= 1:
        payload["lease_seconds"] = int(lease_seconds)
    if first_heartbeat_seconds is not None and first_heartbeat_seconds >= 1:
        payload["first_heartbeat_seconds"] = int(first_heartbeat_seconds)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    delivery_id = "execution_delivery_" + hashlib.sha256(
        f"{execution.id}\0{execution.attempt_id}".encode()
    ).hexdigest()[:24]
    item = OutboxItem(
        id=delivery_id,
        subject_id=execution.subject_id,
        target=execution.target,
        payload=payload,
        payload_hash=hashlib.sha256(encoded).hexdigest(),
        epoch=execution.attempts,
        status="leased",
        attempts=execution.attempts,
        # The wake belongs to this attempt, so it is as old as the claim.
        created_at=execution.updated_at,
        updated_at=execution.updated_at,
        next_attempt_at=execution.updated_at,
        lease_owner=execution.lease_owner,
        lease_expires_at=execution.lease_expires_at,
    )
    return item
