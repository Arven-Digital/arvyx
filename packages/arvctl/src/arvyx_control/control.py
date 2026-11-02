from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
import hashlib
import json
import os
import time
from pathlib import Path
from secrets import token_hex
import threading
from typing import Iterable, Mapping

from .thread_history import completion_supersedes
from .locks import exclusive_lock, admission_lock, inherited_deadline, check_inherited_deadline
from .filesystem import durable_mkdir, fsync_directory
from .security import contains_literal_secret

# Incremental read cache for the append-only control-event log. See read_events().
_EVENT_CACHE_LOCK = threading.Lock()
_EVENT_CACHE: dict[str, tuple[int, int, int, list[ControlEvent], int, bytes, int, "hashlib._Hash", int]] = {}
# File timestamps come from the kernel's coarse clock: a rewrite inside the same tick
# as the cached read keeps size and mtime. An entry cached within this window of the
# file's mtime is "racy": on an equal-size, equal-mtime hit its committed prefix digest
# is re-verified against the file's bytes before it is served (git's racy-index rule);
# nothing is re-parsed unless the bytes differ.
_EVENT_CACHE_RACY_NS = 2_000_000_000
# How much of the already-parsed prefix is re-hashed to prove a file was appended to
# rather than rewritten in place. An append leaves these bytes untouched; any rewrite
# that touches the previous tail changes them and forces a full parse.
_EVENT_ANCHOR_BYTES = 65536


def _event_anchor(raw: bytes, consumed: int) -> tuple[bytes, int]:
    window = raw[max(0, consumed - _EVENT_ANCHOR_BYTES) : consumed]
    return hashlib.sha256(window).digest(), len(window)


def _prefix_unchanged(state: Path, consumed: int, digest: bytes, length: int) -> bool:
    """True when the bytes preceding ``consumed`` are still the ones we parsed."""
    if length <= 0 or consumed < length:
        return False
    try:
        with state.open("rb") as handle:
            handle.seek(consumed - length)
            window = handle.read(length)
    except OSError:
        return False
    return len(window) == length and hashlib.sha256(window).digest() == digest


@dataclass(frozen=True)
class ControlEvent:
    id: str
    type: str
    task_id: str
    timestamp: str
    payload: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "type": self.type,
            "task_id": self.task_id,
            "timestamp": self.timestamp,
            "payload": self.payload,
        }


@dataclass(frozen=True)
class Task:
    id: str
    title: str
    owner: str
    status: str
    created_at: str
    updated_at: str
    retirement_json: str = ""

    @property
    def retirement(self):
        return json.loads(self.retirement_json) if self.retirement_json else {}

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "title": self.title,
            "owner": self.owner,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "retirement": self.retirement,
        }


@dataclass(frozen=True)
class TaskResult:
    task: Task
    event: ControlEvent

    def to_dict(self) -> dict[str, object]:
        return {"task": self.task.to_dict(), "event": self.event.to_dict()}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass(frozen=True)
class TaskListResult:
    tasks: list[Task]

    def to_dict(self) -> dict[str, object]:
        return {"tasks": [task.to_dict() for task in self.tasks]}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass(frozen=True)
class Approval:
    id: str
    command_hash: str
    requester: str
    approver: str | None
    status: str
    reason: str
    created_at: str
    updated_at: str
    expires_at: str = ""

    def to_dict(self) -> dict[str, str | None]:
        return {
            "id": self.id,
            "command_hash": self.command_hash,
            "requester": self.requester,
            "approver": self.approver,
            "status": self.status,
            "reason": self.reason,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True)
class ApprovalResult:
    approval: Approval
    event: ControlEvent

    def to_dict(self) -> dict[str, object]:
        return {"approval": self.approval.to_dict(), "event": self.event.to_dict()}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass(frozen=True)
class ApprovalListResult:
    approvals: list[Approval]

    def to_dict(self) -> dict[str, object]:
        return {"approvals": [approval.to_dict() for approval in self.approvals]}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass(frozen=True)
class Handoff:
    id: str
    title: str
    from_agent: str
    to_agent: str
    status: str
    summary: str
    created_at: str
    updated_at: str
    reviewer: str = ""
    review_decision: str = ""
    review_notes: str = ""
    retirement_json: str = ""
    accepted_by: str = ""

    @property
    def retirement(self):
        return json.loads(self.retirement_json) if self.retirement_json else {}

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "title": self.title,
            "from_agent": self.from_agent,
            "to_agent": self.to_agent,
            "status": self.status,
            "summary": self.summary,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "reviewer": self.reviewer,
            "review_decision": self.review_decision,
            "review_notes": self.review_notes,
            "accepted_by": self.accepted_by,
            "retirement": self.retirement,
        }


@dataclass(frozen=True)
class HandoffResult:
    handoff: Handoff
    event: ControlEvent

    def to_dict(self) -> dict[str, object]:
        return {"handoff": self.handoff.to_dict(), "event": self.event.to_dict()}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass(frozen=True)
class HandoffListResult:
    handoffs: list[Handoff]

    def to_dict(self) -> dict[str, object]:
        return {"handoffs": [handoff.to_dict() for handoff in self.handoffs]}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass(frozen=True)
class BusMessage:
    id: str
    channel: str
    actor: str
    severity: str
    message: str
    created_at: str

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "channel": self.channel,
            "actor": self.actor,
            "severity": self.severity,
            "message": self.message,
            "created_at": self.created_at,
        }


@dataclass(frozen=True)
class BusMessageResult:
    message: BusMessage
    event: ControlEvent

    def to_dict(self) -> dict[str, object]:
        return {"message": self.message.to_dict(), "event": self.event.to_dict()}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass(frozen=True)
class BusMessageListResult:
    messages: list[BusMessage]

    def to_dict(self) -> dict[str, object]:
        return {"messages": [message.to_dict() for message in self.messages]}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


THREAD_TYPES = ("ask", "handoff", "blocker", "update", "status")
ACTIONABLE_THREAD_TYPES = frozenset({"ask", "handoff", "blocker"})
THREAD_SEVERITIES = ("info", "notice", "warn", "critical")
EVIDENCE_METHODS = ("api-readback", "checksum", "direct-read", "test-output")
THREAD_EVENT_TYPES = frozenset(
    {"thread.created", "thread.message.posted", "thread.acknowledged", "thread.done", "thread.read", "thread.retired", "thread.operator_archived"}
)
# Delivery bookkeeping, not thread state: excluded from THREAD_EVENT_TYPES so
# a notification never changes a thread's unread/pending projection.
THREAD_NOTIFICATION_EVENT = "thread.notification_sent"
THREAD_NOTIFICATION_FAILED_EVENT = "thread.notification_failed"
THREAD_NOTIFICATION_KINDS = ("notification", "escalation")
THREAD_MESSAGE_MAX_CHARS = 4000
THREAD_MESSAGE_MAX_COUNT = 500
THREAD_REPLY_ARTIFACT_PREFIX = "control thread reply authored by "


@dataclass(frozen=True)
class ThreadMessage:
    actor: str
    text: str
    created_at: str

    def to_dict(self) -> dict[str, str]:
        return {"actor": self.actor, "text": self.text, "created_at": self.created_at}


@dataclass(frozen=True)
class Thread:
    id: str
    type: str
    actor: str
    target: str
    channel: str
    severity: str
    title: str
    body: str
    status: str
    created_at: str
    latest_at: str
    acked_at: str = ""
    acked_by: str = ""
    done_at: str = ""
    done_by: str = ""
    read_at: str = ""
    completion_artifact: str = ""
    completion_anchor: str = ""
    evidence_artifact: str = ""
    evidence_anchor: str = ""
    evidence_method: str = ""
    continuation_thread_id: str = ""
    # Authoritative read/unread state, resolved by append order of the event
    # log: activity events set it, read events clear it. It cannot be derived
    # from latest_at/read_at because timestamps are second-resolution, so a
    # read and a reply within the same second compare equal.
    unread: bool = True
    messages: tuple[ThreadMessage, ...] = ()
    # Canonical immutable storage keeps frozen Thread equality/hash meaningful.
    # The property returns a detached object; callers cannot mutate the record.
    retirement_json: str = ""
    actor_identity_bound: bool | None = None

    @property
    def retirement(self) -> dict[str, object]:
        return json.loads(self.retirement_json) if self.retirement_json else {}

    @property
    def pending(self) -> bool:
        """Actionable and not finished; ack alone does not clear pending."""
        return self.type in ACTIONABLE_THREAD_TYPES and self.status not in {"done", "retired"}

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "type": self.type,
            "actor": self.actor,
            "actor_identity_bound": self.actor_identity_bound,
            "target": self.target,
            "channel": self.channel,
            "severity": self.severity,
            "title": self.title,
            "body": self.body,
            "status": self.status,
            "created_at": self.created_at,
            "latest_at": self.latest_at,
            "acked_at": self.acked_at,
            "acked_by": self.acked_by,
            "done_at": self.done_at,
            "done_by": self.done_by,
            "read_at": self.read_at,
            "completion_artifact": self.completion_artifact,
            "completion_anchor": self.completion_anchor,
            "evidence_artifact": self.evidence_artifact,
            "evidence_anchor": self.evidence_anchor,
            "evidence_method": self.evidence_method,
            "continuation_thread_id": self.continuation_thread_id,
            "pending": self.pending,
            "unread": self.unread,
            "messages": [message.to_dict() for message in self.messages],
            "retirement": self.retirement,
        }


def _thread_event_payload(thread: Thread) -> dict[str, object]:
    payload = thread.to_dict()
    payload.pop("messages", None)
    return payload


@dataclass(frozen=True)
class ThreadResult:
    thread: Thread
    event: ControlEvent

    def to_dict(self) -> dict[str, object]:
        return {"thread": self.thread.to_dict(), "event": self.event.to_dict()}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass(frozen=True)
class ThreadListResult:
    threads: list[Thread]

    def to_dict(self) -> dict[str, object]:
        return {"threads": [thread.to_dict() for thread in self.threads]}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def _reject_retired_identity(**fields: str) -> None:
    """Fence new identities, not historical payloads or the open agent namespace.

    Atlas was a fixture/default author, never a live delivery agent. Keep this
    check at producer inputs: completion events legitimately copy old authors.
    """
    for field, value in fields.items():
        if value.strip().casefold() == "atlas":
            raise ValueError(f"{field}: retired identity atlas cannot author or receive new work")


def create_task(
    state: Path,
    title: object,
    owner: str = "",
    idempotency_key: str | None = None,
    created_by: str = "operator",
    principal_scope: str | None = None,
) -> TaskResult:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    if not isinstance(title, str):
        raise ValueError("task title must be a string")
    if not title.strip():
        raise ValueError("task title must not be empty")
    _reject_retired_identity(owner=owner, created_by=created_by)
    owner = owner.strip()
    if not owner:
        raise ValueError("task owner must not be empty")
    if owner.casefold() == "all":
        raise ValueError("tasks require a concrete agent owner; owner=all is pull-only")
    _reject_secret_shaped_text(title=title)
    key = _validate_idempotency_key(idempotency_key)
    with _locked_state(state):
        request = dict(title=title, owner=owner, created_by=created_by)
        previous = _idempotent_event(state, "task.created", key, principal_scope=principal_scope, request=request, acknowledge_replay=True)
        if previous:
            task = _project_tasks(state).get(previous.task_id) or _task_from_payload(previous.payload)
            return TaskResult(task=task, event=previous)
        timestamp = _now()
        task_id = _stable_id("task", title, owner, timestamp)
        task = Task(task_id, title, owner, "open", timestamp, timestamp)
        payload: dict[str, object] = {**task.to_dict(), "created_by": created_by}
        event = _event("task.created", task_id, timestamp, _bind_idempotency(payload, key, principal_scope, request))
        _append_event_unlocked(state, event)
    return TaskResult(task=task, event=event)


def complete_task(state: Path, task_id: str, actor: str | None = None) -> TaskResult:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    with _locked_state(state):
        tasks = _project_tasks(state)
        if task_id not in tasks:
            raise ValueError(f"unknown task: {task_id}")
        previous = tasks[task_id]
        if actor is not None and actor.strip().casefold() != previous.owner.strip().casefold():
            raise ValueError("only the task owner can complete a task")
        if previous.status in {"done", "retired"}:
            raise ValueError(f"task is already terminal: {task_id}")
        timestamp = _now()
        task = Task(
            id=previous.id,
            title=previous.title,
            owner=previous.owner,
            status="done",
            created_at=previous.created_at,
            updated_at=timestamp,
        )
        event = _event("task.completed", task_id, timestamp, task.to_dict())
        _append_event_unlocked(state, event)
    return TaskResult(task=task, event=event)


def list_tasks(state: Path, status: str | None = None, events: list[ControlEvent] | None = None) -> TaskListResult:
    tasks = sorted(_project_tasks(state, events=events).values(), key=lambda task: (task.status, task.created_at, task.id))
    if status:
        tasks = [task for task in tasks if task.status == status]
    return TaskListResult(tasks=tasks)


def request_approval(state: Path, command: str, requester: str = "", reason: str = "", ttl_seconds: int = 3600, idempotency_key: str | None = None, *, principal_scope: str | None = None) -> ApprovalResult:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    _reject_retired_identity(requester=requester)
    requester = requester.strip()
    if not requester:
        raise ValueError("approval requester must not be empty")
    _reject_secret_shaped_text(reason=reason)
    if not 60 <= ttl_seconds <= 604800:
        raise ValueError("approval ttl_seconds must be between 60 and 604800")
    key = _validate_idempotency_key(idempotency_key)
    with _locked_state(state):
        request = dict(command_hash=hash_command(command), requester=requester, reason=reason, ttl_seconds=ttl_seconds)
        previous = _idempotent_event(state, "approval.requested", key, principal_scope=principal_scope, request=request, acknowledge_replay=True)
        if previous:
            return ApprovalResult(approval=_approval_from_payload(previous.payload), event=previous)
        timestamp = _now()
        command_hash = hash_command(command)
        approval_id = _stable_id("approval", requester, command_hash, timestamp)
        expires_at = _format_time(_parse_time(timestamp) + timedelta(seconds=ttl_seconds))
        approval = Approval(approval_id, command_hash, requester, None, "requested", reason, timestamp, timestamp, expires_at)
        event = _event("approval.requested", approval_id, timestamp, _bind_idempotency(approval.to_dict(), key, principal_scope, request))
        _append_event_unlocked(state, event)
    return ApprovalResult(approval=approval, event=event)


def approve_request(state: Path, approval_id: str, approver: str = "operator") -> ApprovalResult:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    with _locked_state(state):
        approvals = _project_approvals(state)
        if approval_id not in approvals:
            raise ValueError(f"unknown approval: {approval_id}")
        previous = approvals[approval_id]
        _require_unexpired(previous)
        if previous.status != "requested":
            raise ValueError(f"approval is not requestable: {approval_id} status={previous.status}")
        if approver.strip().casefold() == previous.requester.strip().casefold():
            raise ValueError("approval requester cannot approve their own request")
        timestamp = _now()
        approval = Approval(
            id=previous.id,
            command_hash=previous.command_hash,
            requester=previous.requester,
            approver=approver,
            status="approved",
            reason=previous.reason,
            created_at=previous.created_at,
            updated_at=timestamp,
            expires_at=previous.expires_at,
        )
        event = _event("approval.approved", approval_id, timestamp, approval.to_dict())
        _append_event_unlocked(state, event)
    return ApprovalResult(approval=approval, event=event)


def consume_approval(
    state: Path,
    approval_id: str,
    command: str,
    actor: str | None = None,
) -> ApprovalResult:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    with _locked_state(state):
        approvals = _project_approvals(state)
        if approval_id not in approvals:
            raise ValueError(f"unknown approval: {approval_id}")
        previous = approvals[approval_id]
        if actor is not None and actor.strip().casefold() != previous.requester.strip().casefold():
            raise ValueError("only the approval requester can consume an approval")
        _require_unexpired(previous)
        if previous.status != "approved":
            raise ValueError(f"approval is not consumable: {approval_id} status={previous.status}")
        command_hash = hash_command(command)
        if command_hash != previous.command_hash:
            raise ValueError("command hash does not match approval")
        timestamp = _now()
        approval = Approval(
            id=previous.id,
            command_hash=previous.command_hash,
            requester=previous.requester,
            approver=previous.approver,
            status="consumed",
            reason=previous.reason,
            created_at=previous.created_at,
            updated_at=timestamp,
            expires_at=previous.expires_at,
        )
        event = _event("approval.consumed", approval_id, timestamp, approval.to_dict())
        _append_event_unlocked(state, event)
    return ApprovalResult(approval=approval, event=event)


def approval_effective_status(approval: Approval, now: datetime | None = None) -> str:
    """The status an approval actually has right now.

    Expiry is derived, never written: the control log is append-only, so a
    unconsumed approval whose TTL has passed retains its stored status and is
    *reported* as ``expired``. ``approve_request`` and ``consume_approval`` already
    refuse it through ``_require_unexpired``; deriving the status here keeps every
    listing surface in agreement with that instead of showing callers
    actionable-looking rows that can never be acted on.
    """
    if approval.status not in {"requested", "approved"} or not approval.expires_at:
        return approval.status
    try:
        expiry = datetime.fromisoformat(approval.expires_at.replace("Z", "+00:00"))
    except ValueError:
        return approval.status
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    reference = now or datetime.now(timezone.utc)
    return "expired" if expiry.astimezone(timezone.utc) <= reference.astimezone(timezone.utc) else approval.status


def list_approvals(
    state: Path, status: str | None = None, *, now: datetime | None = None
) -> ApprovalListResult:
    reference = now or datetime.now(timezone.utc)
    projected = [
        replace(approval, status=approval_effective_status(approval, reference))
        for approval in _project_approvals(state).values()
    ]
    approvals = sorted(
        projected, key=lambda approval: (approval.status, approval.created_at, approval.id)
    )
    if status:
        approvals = [approval for approval in approvals if approval.status == status]
    return ApprovalListResult(approvals=approvals)


def create_handoff(
    state: Path,
    title: str,
    from_agent: str = "",
    to_agent: str = "operator",
    summary: str = "",
    idempotency_key: str | None = None,
    actor_identity_bound: bool | None = None,
    principal_scope: str | None = None,
) -> HandoffResult:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    _reject_retired_identity(from_agent=from_agent, to_agent=to_agent)
    from_agent = from_agent.strip()
    to_agent = to_agent.strip()
    if not from_agent:
        raise ValueError("handoff source must not be empty")
    if from_agent.casefold() == "all":
        raise ValueError("handoffs require a concrete source agent; from_agent=all is pull-only")
    if not to_agent:
        raise ValueError("handoff target must not be empty")
    if to_agent.casefold() == "all":
        raise ValueError("handoffs require a concrete target agent; to_agent=all is pull-only")
    _reject_secret_shaped_text(title=title, summary=summary)
    key = _validate_idempotency_key(idempotency_key)
    with _locked_state(state):
        request = dict(title=title, from_agent=from_agent, to_agent=to_agent, summary=summary, actor_identity_bound=actor_identity_bound)
        previous = _idempotent_event(state, "handoff.created", key, principal_scope=principal_scope, request=request, acknowledge_replay=True)
        if previous:
            current = _project_handoffs(state).get(previous.task_id) or _handoff_from_payload(previous.payload)
            return HandoffResult(handoff=current, event=previous)
        timestamp = _now()
        handoff_id = _stable_id("handoff", title, from_agent, to_agent, timestamp)
        handoff = Handoff(
            id=handoff_id,
            title=title,
            from_agent=from_agent,
            to_agent=to_agent,
            status="open",
            summary=summary,
            created_at=timestamp,
            updated_at=timestamp,
        )
        payload: dict[str, object] = _with_key(dict(handoff.to_dict()), key)
        if actor_identity_bound is not None:
            payload["actor_identity_bound"] = bool(actor_identity_bound)
        event = _event("handoff.created", handoff_id, timestamp, _bind_idempotency(payload, key, principal_scope, request))
        _append_event_unlocked(state, event)
    return HandoffResult(handoff=handoff, event=event)


def accept_handoff(
    state: Path, handoff_id: str, actor: str | None = None, *,
    actor_identity_bound: bool = False,
) -> HandoffResult:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    with _locked_state(state):
        handoffs = _project_handoffs(state)
        if handoff_id not in handoffs:
            raise ValueError(f"unknown handoff: {handoff_id}")
        previous = handoffs[handoff_id]
        if previous.status != "open":
            raise ValueError(f"handoff is not open: {handoff_id} status={previous.status}")
        if actor is not None and actor.strip().casefold() != previous.to_agent.strip().casefold():
            raise ValueError("only the target agent can accept a handoff")
        timestamp = _now()
        handoff = Handoff(
            id=previous.id,
            title=previous.title,
            from_agent=previous.from_agent,
            to_agent=previous.to_agent,
            status="accepted",
            accepted_by=actor.strip().casefold() if actor is not None else "",
            summary=previous.summary,
            created_at=previous.created_at,
            updated_at=timestamp,
            reviewer=previous.reviewer,
            review_decision=previous.review_decision,
            review_notes=previous.review_notes,
        )
        event = _event(
            "handoff.accepted", handoff_id, timestamp,
            {
                **handoff.to_dict(),
                "accepted_by": handoff.accepted_by,
                "actor_identity_bound": bool(actor_identity_bound),
            },
        )
        _append_event_unlocked(state, event)
    return HandoffResult(handoff=handoff, event=event)


def review_handoff(
    state: Path,
    handoff_id: str,
    reviewer: str = "operator",
    decision: str = "approved",
    notes: str = "",
) -> HandoffResult:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    decision = decision.strip().lower().replace("-", "_")
    if decision not in {"approved", "changes_requested", "blocked"}:
        raise ValueError("handoff review decision must be approved, changes_requested, or blocked")
    _reject_secret_shaped_text(notes=notes)
    with _locked_state(state):
        handoffs = _project_handoffs(state)
        if handoff_id not in handoffs:
            raise ValueError(f"unknown handoff: {handoff_id}")
        previous = handoffs[handoff_id]
        if previous.status != "accepted":
            raise ValueError(f"handoff is not accepted: {handoff_id} status={previous.status}")
        if reviewer.strip().casefold() == previous.from_agent.strip().casefold():
            raise ValueError("handoff author cannot review their own handoff")
        timestamp = _now()
        handoff = Handoff(
            id=previous.id,
            title=previous.title,
            from_agent=previous.from_agent,
            to_agent=previous.to_agent,
            status="reviewed",
            accepted_by=previous.accepted_by,
            summary=previous.summary,
            created_at=previous.created_at,
            updated_at=timestamp,
            reviewer=reviewer,
            review_decision=decision,
            review_notes=notes,
        )
        event = _event("handoff.reviewed", handoff_id, timestamp, handoff.to_dict())
        _append_event_unlocked(state, event)
    return HandoffResult(handoff=handoff, event=event)


def complete_handoff(
    state: Path, handoff_id: str, actor: str = "operator", *,
    actor_identity_bound: bool = False,
) -> HandoffResult:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    with _locked_state(state):
        handoffs = _project_handoffs(state)
        if handoff_id not in handoffs:
            raise ValueError(f"unknown handoff: {handoff_id}")
        previous = handoffs[handoff_id]
        participants = {previous.from_agent.strip().casefold(), previous.to_agent.strip().casefold()}
        # Bound agent identities never acquire operator authority by name.
        operator_override = not actor_identity_bound and actor.strip().casefold() == "operator"
        if not operator_override and actor.strip().casefold() not in participants:
            raise ValueError("only a handoff participant can complete a handoff")
        prior_terminal = next(
            (
                event
                for event in reversed(read_events(state))
                if event.type == "handoff.completed" and event.task_id == handoff_id
            ),
            None,
        )
        identity_bound_supersession = (
            previous.status == "completed"
            and actor_identity_bound
            and actor.strip().casefold() == previous.to_agent.strip().casefold()
            and prior_terminal is not None
            and not (
                prior_terminal.payload.get("actor_identity_bound") is True
                and str(prior_terminal.payload.get("completed_by", "")).strip().casefold()
                == previous.to_agent.strip().casefold()
            )
        )
        if previous.status not in {"accepted", "reviewed"} and not identity_bound_supersession:
            raise ValueError(f"handoff is not accepted or reviewed: {handoff_id} status={previous.status}")
        timestamp = _now()
        handoff = Handoff(
            id=previous.id,
            title=previous.title,
            from_agent=previous.from_agent,
            to_agent=previous.to_agent,
            status="completed",
            accepted_by=previous.accepted_by,
            summary=previous.summary,
            created_at=previous.created_at,
            updated_at=timestamp,
            reviewer=previous.reviewer,
            review_decision=previous.review_decision,
            review_notes=previous.review_notes,
        )
        payload: dict[str, object] = {
            **handoff.to_dict(), "completed_by": actor,
            "actor_identity_bound": bool(actor_identity_bound),
        }
        event = _event("handoff.completed", handoff_id, timestamp, payload)
        _append_event_unlocked(state, event)
    return HandoffResult(handoff=handoff, event=event)


def list_handoffs(state: Path, status: str | None = None, events: list[ControlEvent] | None = None) -> HandoffListResult:
    handoffs = sorted(
        _project_handoffs(state, events=events).values(),
        key=lambda handoff: (handoff.status, handoff.created_at, handoff.id),
    )
    if status:
        handoffs = [handoff for handoff in handoffs if handoff.status == status]
    return HandoffListResult(handoffs=handoffs)


def post_bus_message(
    state: Path,
    message: str,
    channel: str = "ops",
    actor: str = "",
    severity: str = "notice",
    idempotency_key: str | None = None,
    principal_scope: str | None = None,
) -> BusMessageResult:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    _reject_retired_identity(actor=actor)
    actor = actor.strip()
    if not actor:
        raise ValueError("bus actor must not be empty")
    _reject_secret_shaped_text(message=message)
    key = _validate_idempotency_key(idempotency_key)
    with _locked_state(state):
        request = dict(message=message, channel=channel, actor=actor, severity=severity)
        previous = _idempotent_event(state, "bus.message", key, principal_scope=principal_scope, request=request, acknowledge_replay=True)
        if previous:
            return BusMessageResult(message=_bus_from_payload(previous.payload), event=previous)
        timestamp = _now()
        message_id = _stable_id("bus", channel, actor, severity, message, timestamp)
        bus_message = BusMessage(
            id=message_id,
            channel=channel,
            actor=actor,
            severity=severity,
            message=message,
            created_at=timestamp,
        )
        event = _event("bus.message", message_id, timestamp, _bind_idempotency(bus_message.to_dict(), key, principal_scope, request))
        _append_event_unlocked(state, event)
    return BusMessageResult(message=bus_message, event=event)


def list_bus_messages(state: Path, channel: str | None = None) -> BusMessageListResult:
    messages = sorted(_project_bus_messages(state).values(), key=lambda message: (message.created_at, message.id))
    if channel:
        messages = [message for message in messages if message.channel == channel]
    return BusMessageListResult(messages=messages)


@contextmanager
def thread_state_lock(state: Path):
    """Hold the control-state lock across a multi-step read/decide/append
    sequence. Composite operations (daily handoffs, notify sweeps) take this
    once so two overlapping runs cannot both project stale history and then
    append duplicate events. Inside the block use only the *_unlocked write
    helpers — the plain ones re-acquire this non-reentrant lock."""
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    with _locked_state(state):
        yield


def post_thread(
    state: Path,
    title: str,
    body: str = "",
    thread_type: str = "ask",
    actor: str = "",
    target: str = "operator",
    channel: str = "ops",
    severity: str = "notice",
    completion_artifact: str = "",
    completion_anchor: str = "",
    continuation_thread_id: str = "",
    actor_identity_bound: bool | None = None,
) -> ThreadResult:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    with _locked_state(state):
        return post_thread_unlocked(
            state,
            title=title,
            body=body,
            thread_type=thread_type,
            actor=actor,
            target=target,
            channel=channel,
            severity=severity,
            completion_artifact=completion_artifact,
            completion_anchor=completion_anchor,
            continuation_thread_id=continuation_thread_id,
            actor_identity_bound=actor_identity_bound,
        )


def post_thread_unlocked(
    state: Path,
    title: str,
    body: str = "",
    thread_type: str = "ask",
    actor: str = "",
    target: str = "operator",
    channel: str = "ops",
    severity: str = "notice",
    completion_artifact: str = "",
    completion_anchor: str = "",
    continuation_thread_id: str = "",
    actor_identity_bound: bool | None = None,
) -> ThreadResult:
    """post_thread for callers already holding thread_state_lock."""
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    title = title.strip()
    body = body.strip()
    thread_type = thread_type.strip().lower()
    _reject_retired_identity(actor=actor)
    actor = actor.strip()
    _reject_retired_identity(target=target)
    target = target.strip()
    severity = severity.strip().lower()
    completion_artifact = completion_artifact.strip()
    completion_anchor = completion_anchor.strip()
    continuation_thread_id = continuation_thread_id.strip()
    if not title:
        raise ValueError("thread title must not be empty")
    if not actor:
        raise ValueError("thread actor must not be empty")
    if actor.casefold() == "all":
        raise ValueError("threads require a concrete actor; actor=all is pull-only")
    if not target:
        raise ValueError("thread target must not be empty")
    if thread_type not in THREAD_TYPES:
        raise ValueError("thread type must be one of: " + ", ".join(THREAD_TYPES))
    if target.casefold() == "all":
        target = "all"
        if thread_type not in {"status", "update"}:
            raise ValueError("actionable threads require a concrete agent target; target=all is pull-only")
    if severity not in THREAD_SEVERITIES:
        raise ValueError("thread severity must be one of: " + ", ".join(THREAD_SEVERITIES))
    _reject_secret_shaped_text(title=title, body=body)
    _validate_completion_contract(thread_type, target, completion_artifact, completion_anchor)
    if continuation_thread_id:
        if actor_identity_bound is not True:
            raise ValueError("continuation threads require an identity-bound actor")
        parents = _project_threads(state)
        parent = parents.get(continuation_thread_id)
        if parent is None:
            raise ValueError("unknown continuation thread")
        if parent.target.casefold() != actor.casefold():
            raise ValueError("continuation thread must target the child actor")
        if parent.status != "acked" or parent.acked_by.casefold() != actor.casefold():
            raise ValueError("continuation thread must be acked by the child actor")
        parent_ack = next(
            (
                event
                for event in reversed(read_events(state))
                if event.type == "thread.acknowledged" and event.task_id == continuation_thread_id
            ),
            None,
        )
        if parent_ack is None or parent_ack.payload.get("actor_identity_bound") is not True:
            raise ValueError("continuation parent acknowledgement must be identity-bound")
        if any(
            thread.continuation_thread_id == continuation_thread_id and thread.pending
            for thread in parents.values()
        ):
            raise ValueError("continuation thread already has a pending child")
    timestamp = _now()
    thread_id = _stable_id("thread", title, actor, target, timestamp)
    thread = Thread(
        id=thread_id,
        type=thread_type,
        actor=actor,
        target=target,
        channel=channel,
        severity=severity,
        title=title,
        body=body,
        status="open",
        created_at=timestamp,
        latest_at=timestamp,
        unread=target != "all",
        completion_artifact=completion_artifact,
        completion_anchor=completion_anchor,
        continuation_thread_id=continuation_thread_id,
        actor_identity_bound=actor_identity_bound,
    )
    payload = _thread_event_payload(thread)
    if actor_identity_bound is not None:
        payload["actor_identity_bound"] = bool(actor_identity_bound)
    event = _event("thread.created", thread_id, timestamp, payload)
    _append_event_unlocked(state, event)
    return ThreadResult(thread=thread, event=event)


def _require_live_recipient(state: Path, thread: "Thread", actor: str) -> None:
    """Refuse an agent's reply that can never reach the thread's owner.

    A reply is new input for the owner's live execution; it never wakes anyone by itself.
    When the owner acknowledged the thread but every execution for it is terminal, the
    reply would sit unread forever (one agent's reply to another's finished thread did
    exactly that in production on 2026-09-25).
    Say so, so the caller opens a fresh thread instead. The owner's own notes, finished
    threads and threads with live or not-yet-created work are unaffected.
    """
    target = str(thread.target or "").strip().casefold()
    if (not target or target == "all" or actor.strip().casefold() == target
            or thread.status not in {"open", "acked", "acknowledged"}):
        return
    from .execution import project_executions

    lineage = [e for e in project_executions(state).values()
               if e.subject_id == thread.id and e.target.strip().casefold() == target]
    if lineage and all(e.status in {"closed", "completed", "cancelled"} for e in lineage):
        raise ValueError(
            f"{thread.id}: {thread.target}'s work on this thread is already closed, so this reply would never "
            "reach them. Post a new thread to them instead."
        )


def post_thread_message(
    state: Path,
    thread_id: str,
    text: str,
    actor: str = "",
    idempotency_key: str | None = None,
    require_live_recipient: bool = False,
    principal_scope: str | None = None,
) -> ThreadResult:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    text = text.strip()
    _reject_retired_identity(actor=actor)
    actor = actor.strip()
    if not text:
        raise ValueError("thread message text must not be empty")
    if len(text) > THREAD_MESSAGE_MAX_CHARS:
        raise ValueError(f"thread message text must not exceed {THREAD_MESSAGE_MAX_CHARS} characters")
    if not actor or actor.casefold() == "all":
        raise ValueError("thread replies require a concrete actor")
    _reject_secret_shaped_text(text=text)
    key = _validate_idempotency_key(idempotency_key)
    with _locked_state(state):
        threads = _project_threads(state)
        if thread_id not in threads:
            raise ValueError(f"unknown thread: {thread_id}")
        request = dict(thread_id=thread_id, text=text, posted_by=actor)
        previous_event = _idempotent_event(state, "thread.message.posted", key, principal_scope=principal_scope, request=request, acknowledge_replay=True)
        if previous_event is not None:
            if previous_event.task_id != thread_id:
                raise ValueError("idempotency key is already bound to another thread reply")
            if previous_event.payload.get("posted_by") != actor or previous_event.payload.get("text") != text:
                raise ValueError("idempotency key is already bound to a different thread reply")
            return ThreadResult(thread=threads[thread_id], event=previous_event)
        if threads[thread_id].status == "retired":
            raise ValueError("retired thread cannot receive replies")
        if require_live_recipient:
            _require_live_recipient(state, threads[thread_id], actor)
        if len(threads[thread_id].messages) >= THREAD_MESSAGE_MAX_COUNT:
            raise ValueError(f"thread message count must not exceed {THREAD_MESSAGE_MAX_COUNT}")
        timestamp = _now()
        message = ThreadMessage(actor=actor, text=text, created_at=timestamp)
        thread = replace(
            threads[thread_id],
            latest_at=timestamp,
            unread=threads[thread_id].target != "all",
            messages=threads[thread_id].messages + (message,),
        )
        payload = _with_key(
            {**_thread_event_payload(thread), "text": text, "posted_by": actor},
            key,
        )
        event = _event("thread.message.posted", thread_id, timestamp, _bind_idempotency(payload, key, principal_scope, request))
        _append_event_unlocked(state, event)
    return ThreadResult(thread=thread, event=event)


def acknowledge_thread(
    state: Path, thread_id: str, actor: str = "operator", text: str = "", *,
    actor_identity_bound: bool = False,
) -> ThreadResult:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    text = text.strip()
    _reject_secret_shaped_text(text=text)
    with _locked_state(state):
        threads = _project_threads(state)
        if thread_id not in threads:
            raise ValueError(f"unknown thread: {thread_id}")
        previous = threads[thread_id]
        if previous.type not in ACTIONABLE_THREAD_TYPES:
            raise ValueError(f"non-actionable thread cannot be acknowledged: {thread_id}")
        if previous.status != "open":
            raise ValueError(f"thread is not open: {thread_id} status={previous.status}")
        timestamp = _now()
        thread = replace(
            previous, status="acked", acked_at=timestamp, acked_by=actor, latest_at=timestamp, unread=True
        )
        payload = {
            **_thread_event_payload(thread),
            **({"text": text, "posted_by": actor} if text else {}),
            "actor_identity_bound": bool(actor_identity_bound),
        }
        event = _event("thread.acknowledged", thread_id, timestamp, payload)
        _append_event_unlocked(state, event)
    return ThreadResult(thread=thread, event=event)


def complete_thread(
    state: Path,
    thread_id: str,
    actor: str = "operator",
    text: str = "",
    evidence_artifact: str = "",
    evidence_anchor: str = "",
    evidence_method: str = "",
    *,
    actor_identity_bound: bool = False,
) -> ThreadResult:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    text = text.strip()
    evidence_artifact = evidence_artifact.strip()
    evidence_anchor = evidence_anchor.strip()
    evidence_method = evidence_method.strip()
    _reject_secret_shaped_text(
        text=text,
        evidence_artifact=evidence_artifact,
        evidence_anchor=evidence_anchor,
        evidence_method=evidence_method,
    )
    if len(evidence_artifact) > 1024:
        raise ValueError("evidence_artifact must not exceed 1024 characters")
    if len(evidence_anchor) > 512:
        raise ValueError("evidence_anchor must not exceed 512 characters")
    if len(evidence_method) > 64:
        raise ValueError("evidence_method must not exceed 64 characters")
    evidence_method = evidence_method.casefold()
    if evidence_method and evidence_method not in EVIDENCE_METHODS:
        raise ValueError("evidence_method must be one of: " + ", ".join(EVIDENCE_METHODS))
    with _locked_state(state):
        threads = _project_threads(state)
        if thread_id not in threads:
            raise ValueError(f"unknown thread: {thread_id}")
        previous = threads[thread_id]
        if previous.type not in ACTIONABLE_THREAD_TYPES:
            raise ValueError(f"non-actionable thread cannot be completed: {thread_id}")
        if previous.status == "retired":
            raise ValueError("retired thread cannot be completed")
        prior_terminal = next(
            (
                event
                for event in reversed(read_events(state))
                if event.type == "thread.done" and event.task_id == thread_id
            ),
            None,
        )
        identity_bound_supersession = completion_supersedes(
            status=previous.status, target=previous.target, actor=actor,
            actor_identity_bound=actor_identity_bound,
            prior_terminal=prior_terminal.payload if prior_terminal is not None else None,
        )
        if previous.status not in {"open", "acked"} and not identity_bound_supersession:
            raise ValueError(f"thread is not open or acked: {thread_id} status={previous.status}")
        has_evidence = bool(evidence_artifact or evidence_anchor or evidence_method)
        if previous.completion_artifact:
            if not evidence_artifact or not evidence_anchor or not evidence_method:
                raise ValueError("completion evidence is required by this thread")
            for field, evidence, expected in (
                ("artifact", evidence_artifact, previous.completion_artifact),
                ("anchor", evidence_anchor, previous.completion_anchor),
            ):
                if evidence != expected:
                    raise ValueError(
                        f"completion evidence {field} does not match the thread contract; "
                        f"evidence_{field} must exactly equal completion_{field}. "
                        "Completion fields are literal expected values, not evidence kinds or placeholders. "
                        "Read control.thread_get for this thread's stored contract. If it describes a kind "
                        "instead of the actual expected value, report the contract blocker to the requester. "
                        "Do not copy an unverified value merely to satisfy equality. "
                        "This rejected completion does not establish delivery or record thread.done."
                    )
            if previous.completion_artifact.startswith(THREAD_REPLY_ARTIFACT_PREFIX):
                expected_actor = previous.completion_artifact.removeprefix(THREAD_REPLY_ARTIFACT_PREFIX)
                has_exact_reply = bool(expected_actor) and expected_actor == previous.target and any(
                    same_agent_identity(message.actor, expected_actor) and message.text.strip() == previous.completion_anchor
                    for message in previous.messages
                )
                if not has_exact_reply:
                    raise ValueError(
                        "completion requires a target-authored exact anchor reply recorded on the thread"
                    )
        elif has_evidence:
            raise ValueError("completion evidence is not accepted for an uncontracted thread")

        timestamp = _now()
        thread = replace(
            previous,
            status="done",
            done_at=timestamp,
            done_by=actor,
            latest_at=timestamp,
            unread=True,
            evidence_artifact=evidence_artifact,
            evidence_anchor=evidence_anchor,
            evidence_method=evidence_method,
        )
        payload = {
            **_thread_event_payload(thread),
            **({"text": text, "posted_by": actor} if text else {}),
            "actor_identity_bound": bool(actor_identity_bound),
        }
        event = _event("thread.done", thread_id, timestamp, payload)
        _append_event_unlocked(state, event)
    return ThreadResult(thread=thread, event=event)


def read_thread(state: Path, thread_id: str) -> ThreadResult:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    with _locked_state(state):
        threads = _project_threads(state)
        if thread_id not in threads:
            raise ValueError(f"unknown thread: {thread_id}")
        timestamp = _now()
        thread = replace(threads[thread_id], read_at=timestamp, unread=False)
        event = _event("thread.read", thread_id, timestamp, _thread_event_payload(thread))
        _append_event_unlocked(state, event)
    return ThreadResult(thread=thread, event=event)


def same_agent_identity(left: object, right: object) -> bool:
    """Compare concrete agent names, never IDs, artifacts, or worker tokens.

    Match the dispatcher's trimmed/casefolded identity policy without rewriting
    stored spelling. Empty names and the broadcast sentinel grant no ownership.
    """
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    canonical = left.strip().casefold()
    return bool(canonical) and canonical != "all" and canonical == right.strip().casefold()


def read_all_threads(state: Path, target: str, include_pending: bool = False) -> ThreadListResult:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    marked: list[Thread] = []
    with _locked_state(state):
        threads = sorted(_project_threads(state).values(), key=lambda thread: (thread.latest_at, thread.id))
        timestamp = _now()
        for previous in threads:
            # Preserve explicit operator-local broadcast read-all without
            # treating the sentinel as a concrete identity at auth boundaries.
            if not (same_agent_identity(previous.target, target) or previous.target == target == "all") or not previous.unread:
                continue
            if previous.pending and not include_pending:
                continue
            thread = replace(previous, read_at=timestamp, unread=False)
            event = _event("thread.read", thread.id, timestamp, _thread_event_payload(thread))
            _append_event_unlocked(state, event)
            marked.append(thread)
    return ThreadListResult(threads=marked)


def list_thread_inbox(state: Path, target: str | None = None, events: list[ControlEvent] | None = None) -> ThreadListResult:
    threads = [
        thread
        for thread in _project_threads(state, events=events).values()
        if target is None or thread.target == "all" or same_agent_identity(thread.target, target)
    ]
    return ThreadListResult(threads=sorted(threads, key=lambda thread: (thread.latest_at, thread.id)))


def list_pending_threads(state: Path, target: str | None = None) -> ThreadListResult:
    threads = [
        thread
        for thread in _project_threads(state).values()
        if thread.pending and (target is None or thread.target == "all" or same_agent_identity(thread.target, target))
    ]
    return ThreadListResult(threads=sorted(threads, key=lambda thread: (thread.latest_at, thread.id)))


def record_thread_notification(state: Path, thread: Thread, kind: str, text: str) -> ControlEvent:
    """Append a thread.notification_sent event; dedupe state lives in the log."""
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    with _locked_state(state):
        return record_thread_notification_unlocked(state, thread=thread, kind=kind, text=text)


def record_thread_notification_unlocked(state: Path, thread: Thread, kind: str, text: str) -> ControlEvent:
    """record_thread_notification for callers already holding thread_state_lock."""
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    if kind not in THREAD_NOTIFICATION_KINDS:
        raise ValueError("notification kind must be one of: " + ", ".join(THREAD_NOTIFICATION_KINDS))
    timestamp = _now()
    payload = {
        "thread_id": thread.id,
        "kind": kind,
        "title": thread.title,
        "target": thread.target,
        "channel": thread.channel,
        "severity": thread.severity,
        "text": text,
        "notified_at": timestamp,
    }
    event = _event(THREAD_NOTIFICATION_EVENT, thread.id, timestamp, payload)
    _append_event_unlocked(state, event)
    return event


def record_thread_notification_failure(
    state: Path, thread_id: str, kind: str, detail: str, *, claim_event_id: str,
) -> bool:
    """Release only the exact current generation, atomically with its check."""
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    if kind not in THREAD_NOTIFICATION_KINDS:
        raise ValueError("notification kind must be one of: " + ", ".join(THREAD_NOTIFICATION_KINDS))
    if not isinstance(claim_event_id, str) or not claim_event_id:
        raise ValueError("notification failure requires an exact claim event ID")
    with thread_state_lock(state):
        current = None
        for prior in read_events(state):
            if prior.task_id != thread_id or prior.payload.get("kind") != kind:
                continue
            if prior.type == THREAD_NOTIFICATION_EVENT:
                current = prior.id
            elif (prior.type == THREAD_NOTIFICATION_FAILED_EVENT and current is not None
                  and prior.payload.get("claim_event_id") == current):
                current = None
        if current != claim_event_id:
            return False
        timestamp = _now()
        event = _event(THREAD_NOTIFICATION_FAILED_EVENT, thread_id, timestamp, {
            "thread_id": thread_id, "kind": kind, "detail": detail,
            "failed_at": timestamp, "claim_event_id": claim_event_id,
        })
        _append_event_unlocked(state, event)
        return True


def project_thread_notifications(state: Path) -> dict[str, dict[str, str]]:
    """thread_id -> {kind: latest successfully notified_at}, projected from the log."""
    notifications: dict[str, dict[str, str]] = {}
    generations: dict[tuple[str, str], str] = {}
    for event in read_events(state):
        if event.type not in {THREAD_NOTIFICATION_EVENT, THREAD_NOTIFICATION_FAILED_EVENT}:
            continue
        by_kind = notifications.setdefault(event.task_id, {})
        kind = str(event.payload.get("kind", "notification"))
        key = (event.task_id, kind)
        if event.type == THREAD_NOTIFICATION_FAILED_EVENT:
            # Generationless historical failures cannot authorize a resend.
            claim = event.payload.get("claim_event_id")
            if isinstance(claim, str) and claim and generations.get(key) == claim:
                by_kind.pop(kind, None)
                generations.pop(key, None)
        else:
            generations[key] = event.id
            by_kind[kind] = str(event.payload.get("notified_at", event.timestamp))
    return notifications


def hash_command(command: str) -> str:
    return hashlib.sha256(command.encode("utf-8")).hexdigest()


def _complete_prefix_events(
    raw: bytes, *, existing: list[ControlEvent], first_line: int
) -> tuple[list[ControlEvent], int, int]:
    """Parse the complete lines in ``raw``, which must start at a line boundary.

    Returns ``(events, consumed_bytes, consumed_lines)``. A trailing line without its
    newline is deliberately left unconsumed, so an incremental reader resumes at a line
    boundary and can never re-parse or duplicate an event.
    """
    cut = raw.rfind(b"\n")
    if cut == -1:
        return list(existing), 0, 0
    prefix = raw[: cut + 1]
    text = prefix.decode("utf-8")
    return [*existing, *parse_event_lines(text, first_line=first_line)], cut + 1, text.count("\n")


def _racy(mtime_ns: int, cached_at_ns: int) -> bool:
    """True when the entry was cached too close to the file's mtime to trust equality."""
    return cached_at_ns - mtime_ns < _EVENT_CACHE_RACY_NS


def _prefix_bytes_match(state: Path, size: int, prefix_hash: "hashlib._Hash") -> bool:
    """Compare the file's bytes with the digest of the cached committed prefix."""
    with state.open("rb") as handle:
        raw = handle.read(size + 1)
    return len(raw) == size and hashlib.sha256(raw).digest() == prefix_hash.digest()


def read_events(state: Path, *, max_bytes: int | None = None) -> list[ControlEvent]:
    check_inherited_deadline()
    if not state.exists():
        return []
    if max_bytes is not None:
        if max_bytes < 1:
            raise ValueError("event snapshot byte limit must be positive")
        with state.open("rb") as handle:
            raw = handle.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise ValueError(f"event snapshot exceeds {max_bytes} bytes")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("event snapshot is not valid UTF-8") from exc
        return parse_event_lines(text)

    # Parsing this log is the hot path of every read surface: at 103 MB / 242k events a
    # full parse costs ~3 s, and /summary and /control-plane call several projections per
    # request (22 s and 13 s measured on production). The log is append-only, so a process
    # keeps what it has already parsed and reads only the bytes appended since. The cache
    # is validated by inode, size and mtime, so a replaced, truncated or rewritten file
    # always falls back to a full parse; an entry cached inside the timestamp tick of
    # the file's last write is marked racy and re-parsed on its next equal-size hit.
    try:
        stat = state.stat()
    except OSError as exc:
        raise ValueError(f"cannot stat control events: {exc}") from exc
    key = str(state.resolve())
    with admission_lock(_EVENT_CACHE_LOCK):
        cached = _EVENT_CACHE.get(key)
        appended = False
        if cached is not None and cached[0] == stat.st_ino and stat.st_mtime_ns >= cached[4]:
            if stat.st_size == cached[1]:
                if stat.st_mtime_ns == cached[4]:
                    if not _racy(cached[4], cached[8]):
                        return list(cached[3])
                    if _prefix_bytes_match(state, cached[1], cached[7]):
                        # The bytes still match: refresh the caching time so the entry
                        # stops being racy once the window has passed, instead of being
                        # re-hashed on every later read of an idle log.
                        _EVENT_CACHE[key] = (*cached[:8], time.time_ns())
                        return list(cached[3])
            elif stat.st_size > cached[1] and _prefix_unchanged(state, cached[1], cached[5], cached[6]):
                appended = True
        if not appended:
            raw = state.read_bytes()
            events, consumed, lines = _complete_prefix_events(raw, existing=[], first_line=1)
            digest, anchor = _event_anchor(raw, consumed)
            result = list(events)
            trailing = raw[consumed:]
            if trailing.strip():
                result.extend(parse_event_lines(trailing.decode("utf-8"), first_line=lines + 1))
            _EVENT_CACHE[key] = (stat.st_ino, consumed, lines, events, stat.st_mtime_ns, digest, anchor,
                                 hashlib.sha256(raw[:consumed]), time.time_ns())
            return result
        assert cached is not None  # implied by `appended`
        with state.open("rb") as handle:
            handle.seek(cached[1])
            raw = handle.read()
        events, added, lines = _complete_prefix_events(
            raw, existing=cached[3], first_line=cached[2] + 1
        )
        # raw is suffix-relative; retain a full committed tail window from the
        # file, including bytes preceding this append. Absolute offsets cannot
        # index raw, and a suffix-only anchor would lose rewrite detection.
        committed = cached[1] + added
        prefix_hash = cached[7].copy()
        prefix_hash.update(raw[:added])
        with state.open("rb") as handle:
            handle.seek(max(0, committed - _EVENT_ANCHOR_BYTES))
            window = handle.read(min(committed, _EVENT_ANCHOR_BYTES))
        digest, anchor = _event_anchor(window, len(window))
        result = list(events)
        trailing = raw[added:]
        if trailing.strip():
            result.extend(
                parse_event_lines(trailing.decode("utf-8"), first_line=cached[2] + lines + 1)
            )
        _EVENT_CACHE[key] = (
            stat.st_ino,
            cached[1] + added,
            cached[2] + lines,
            events,
            stat.st_mtime_ns,
            digest,
            anchor,
            prefix_hash,
            time.time_ns(),
        )
        return result


def parse_event_line(line: str, *, line_number: int) -> ControlEvent | None:
    """Parse one JSONL control event, or ``None`` for a blank line.

    Split out of ``parse_event_lines`` so a streaming reader can bound its memory
    while still reporting the absolute line number of anything it rejects.
    """
    if not line.strip():
        return None
    try:
        payload = json.loads(line)
    except (ValueError, RecursionError) as exc:
        # A torn final transition can resurrect consumed approvals or
        # completed work. Fail closed and require explicit repair instead
        # of silently projecting stale state.
        raise ValueError(f"invalid event JSON on line {line_number}") from exc
    required = {'id', 'type', 'task_id', 'timestamp', 'payload'}
    if (not isinstance(payload, dict) or not required <= payload.keys()
            or any(not isinstance(payload[key], str) or not payload[key].strip()
                   for key in required - {'payload'})
            or not isinstance(payload['payload'], dict)):
        raise ValueError(f"invalid event schema on line {line_number}")
    return ControlEvent(
        id=payload["id"],
        type=payload["type"],
        task_id=payload["task_id"],
        timestamp=payload["timestamp"],
        payload=payload["payload"],
    )


def parse_event_lines(text: str, *, first_line: int = 1) -> list[ControlEvent]:
    """Parse JSONL control events, keeping absolute line numbers for a suffix.

    ``first_line`` lets a reader that starts mid-log (from a derived checkpoint
    offset) report the same line numbers a full-log read would report.
    """
    if first_line < 1:
        raise ValueError("first_line must be positive")
    events: list[ControlEvent] = []
    for index, line in enumerate(text.splitlines()):
        if index % 128 == 0:
            check_inherited_deadline()
        event = parse_event_line(line, line_number=first_line + index)
        if event is not None:
            events.append(event)
    return events


def _project_tasks(state: Path, events: list[ControlEvent] | None = None) -> dict[str, Task]:
    tasks: dict[str, Task] = {}
    for event in events if events is not None else read_events(state):
        check_inherited_deadline()
        if event.type not in {"task.created", "task.completed", "task.operator_archived"}:
            continue
        payload = event.payload
        tasks[event.task_id] = Task(
            id=str(payload["id"]),
            title=str(payload["title"]),
            owner=str(payload["owner"]),
            status=str(payload["status"]),
            created_at=str(payload["created_at"]),
            updated_at=str(payload["updated_at"]),
            retirement_json=json.dumps(payload["retirement"], sort_keys=True) if payload.get("retirement") else "",
        )
    return tasks


def _project_approvals(state: Path) -> dict[str, Approval]:
    approvals: dict[str, Approval] = {}
    for event in read_events(state):
        check_inherited_deadline()
        if event.type not in {"approval.requested", "approval.approved", "approval.consumed"}:
            continue
        payload = event.payload
        approvals[event.task_id] = Approval(
            id=str(payload["id"]),
            command_hash=str(payload["command_hash"]),
            requester=str(payload["requester"]),
            approver=str(payload["approver"]) if payload.get("approver") is not None else None,
            status=str(payload["status"]),
            reason=str(payload["reason"]),
            created_at=str(payload["created_at"]),
            updated_at=str(payload["updated_at"]),
            expires_at=str(payload.get("expires_at", "")),
        )
    return approvals


def _project_handoffs(state: Path, events: list[ControlEvent] | None = None) -> dict[str, Handoff]:
    handoffs: dict[str, Handoff] = {}
    for event in events if events is not None else read_events(state):
        check_inherited_deadline()
        if event.type not in {"handoff.created", "handoff.accepted", "handoff.reviewed", "handoff.completed", "handoff.operator_archived"}:
            continue
        payload = event.payload
        handoffs[event.task_id] = Handoff(
            id=str(payload["id"]),
            title=str(payload["title"]),
            from_agent=str(payload["from_agent"]),
            to_agent=str(payload["to_agent"]),
            status=str(payload["status"]),
            summary=str(payload["summary"]),
            created_at=str(payload["created_at"]),
            updated_at=str(payload["updated_at"]),
            reviewer=str(payload.get("reviewer", "")),
            review_decision=str(payload.get("review_decision", "")),
            review_notes=str(payload.get("review_notes", "")),
            retirement_json=json.dumps(payload["retirement"], sort_keys=True) if payload.get("retirement") else "",
            accepted_by=str(payload.get("accepted_by", handoffs[event.task_id].accepted_by if event.task_id in handoffs else "")),
        )
    return handoffs


def _project_bus_messages(state: Path) -> dict[str, BusMessage]:
    messages: dict[str, BusMessage] = {}
    for event in read_events(state):
        if event.type != "bus.message":
            continue
        payload = event.payload
        messages[event.task_id] = BusMessage(
            id=str(payload["id"]),
            channel=str(payload["channel"]),
            actor=str(payload["actor"]),
            severity=str(payload["severity"]),
            message=str(payload["message"]),
            created_at=str(payload["created_at"]),
        )
    return messages


def _project_threads(state: Path, events: list[ControlEvent] | None = None) -> dict[str, Thread]:
    threads: dict[str, Thread] = {}
    for event in events if events is not None else read_events(state):
        check_inherited_deadline()
        if event.type not in THREAD_EVENT_TYPES:
            continue
        payload = event.payload
        previous = threads.get(event.task_id)
        raw_messages = payload.get("messages")
        if isinstance(raw_messages, list):
            messages = tuple(
                ThreadMessage(
                    actor=str(message.get("actor", "")),
                    text=str(message.get("text", "")),
                    created_at=str(message.get("created_at", "")),
                )
                for message in raw_messages
                if isinstance(message, dict)
            )
        elif event.type == "thread.message.posted":
            historical = previous.messages if previous is not None else ()
            messages = historical + (
                ThreadMessage(
                    actor=str(payload.get("posted_by", "")),
                    text=str(payload.get("text", "")),
                    created_at=str(payload.get("latest_at", "")),
                ),
            )
        else:
            messages = previous.messages if previous is not None else ()
        threads[event.task_id] = Thread(
            id=str(payload["id"]),
            type=str(payload["type"]),
            actor=str(payload["actor"]),
            target=str(payload["target"]),
            channel=str(payload["channel"]),
            severity=str(payload["severity"]),
            title=str(payload["title"]),
            body=str(payload["body"]),
            status=str(payload["status"]),
            created_at=str(payload["created_at"]),
            latest_at=str(payload["latest_at"]),
            acked_at=str(payload.get("acked_at", "")),
            acked_by=str(payload.get("acked_by", "")),
            done_at=str(payload.get("done_at", "")),
            done_by=str(payload.get("done_by", "")),
            read_at=str(payload.get("read_at", "")),
            completion_artifact=str(payload.get("completion_artifact", "")),
            completion_anchor=str(payload.get("completion_anchor", "")),
            evidence_artifact=str(payload.get("evidence_artifact", "")),
            evidence_anchor=str(payload.get("evidence_anchor", "")),
            evidence_method=str(payload.get("evidence_method", "")),
            continuation_thread_id=str(payload.get("continuation_thread_id", "")),
            unread=bool(payload.get("unread", True)),
            messages=messages,
            actor_identity_bound=(
                bool(payload["actor_identity_bound"]) if event.type == "thread.created"
                and isinstance(payload.get("actor_identity_bound"), bool)
                else previous.actor_identity_bound if previous is not None else None
            ),
            retirement_json=json.dumps(payload["retirement"], sort_keys=True) if payload.get("retirement") else "",
        )
    return threads


def _reject_secret_shaped_text(**fields: str) -> None:
    for name, value in fields.items():
        if value and contains_literal_secret(value):
            raise ValueError(
                f"{name} contains a secret-shaped string; store a "
                "secret://broker/path reference instead of the literal value"
            )


def _validate_completion_contract(thread_type: str, target: str, artifact: str, anchor: str) -> None:
    if bool(artifact) != bool(anchor):
        raise ValueError("completion_artifact and completion_anchor must be provided together")
    if not artifact:
        return
    if thread_type not in ACTIONABLE_THREAD_TYPES:
        raise ValueError("completion contracts are supported only for actionable threads")
    if len(artifact) > 1024:
        raise ValueError("completion_artifact must not exceed 1024 characters")
    if len(anchor) > 512:
        raise ValueError("completion_anchor must not exceed 512 characters")
    if artifact.startswith(THREAD_REPLY_ARTIFACT_PREFIX):
        expected = THREAD_REPLY_ARTIFACT_PREFIX + target
        if target == "all" or artifact != expected:
            raise ValueError(
                "reply completion artifact must exactly name the concrete thread target"
            )
        if anchor != anchor.strip() or not anchor:
            raise ValueError("reply completion anchor must be non-empty and trimmed")
    _reject_secret_shaped_text(completion_artifact=artifact, completion_anchor=anchor)


def _validate_idempotency_key(value: str | None) -> str | None:
    if value is None:
        return None
    key = value.strip()
    if not key or len(key) > 128:
        raise ValueError("idempotency key must be between 1 and 128 characters")
    _reject_secret_shaped_text(idempotency_key=key)
    return key


def _with_key(payload: dict[str, object], key: str | None) -> dict[str, object]:
    return {**payload, "idempotency_key": key} if key else payload


def _idempotent_event(
    state: Path, event_type: str, key: str | None, *,
    principal_scope: str | None = None, request: Mapping[str, object] | None = None,
    acknowledge_replay: bool = False,
) -> ControlEvent | None:
    if not key:
        return None
    previous = next((event for event in read_events(state)
                     if event.type == event_type
                     and event.payload.get("idempotency_key") == key
                     and event.payload.get("idempotency_principal") == principal_scope), None)
    if previous is not None and request is not None:
        stored = previous.payload.get("idempotency_request")
        if stored is None:
            # Legacy internal events have no envelope. Compare original input
            # fields rather than generated IDs/status/timestamps.
            stored = {name: previous.payload.get(name) for name in request}
            if "ttl_seconds" in request:
                stored["ttl_seconds"] = int((
                    _parse_time(str(previous.payload["expires_at"]))
                    - _parse_time(str(previous.payload["created_at"]))
                ).total_seconds())
            if "thread_id" in request:
                stored["thread_id"] = previous.task_id
        if stored != request:
            raise ValueError("idempotency key is already bound to a different request")
    if previous is not None and acknowledge_replay:
        _acknowledge_replay_unlocked(state, previous)
    return previous


def _acknowledge_replay_unlocked(state: Path, event: ControlEvent) -> None:
    """Repair uncertain append durability before acknowledging a keyed replay.

    Callers hold the state lock. Validate the complete log, including its final
    delimiter, and retain the original event rather than appending a duplicate.
    """
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    fd = os.open(state, os.O_RDWR)
    try:
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read()
        if not data or not data.endswith(b"\n"):
            raise ValueError("control log has a torn final event; refusing replay acknowledgement")
        records = parse_event_lines(data.decode("utf-8"))
        matches = [record.to_dict() for record in records if record.id == event.id]
        if matches != [event.to_dict()]:
            raise ValueError("control replay event is missing, changed, or ambiguous")
        os.fsync(fd)
        fsync_directory(state.parent)
    finally:
        os.close(fd)


def _bind_idempotency(payload: Mapping[str, object], key: str | None,
                      principal_scope: str | None, request: Mapping[str, object]) -> dict[str, object]:
    if not key:
        return dict(payload)
    return {**_with_key(dict(payload), key), "idempotency_principal": principal_scope,
            "idempotency_request": dict(request)}


def _task_from_payload(payload: dict[str, object]) -> Task:
    return Task(*(str(payload[name]) for name in ("id", "title", "owner", "status", "created_at", "updated_at")))


def _approval_from_payload(payload: dict[str, object]) -> Approval:
    return Approval(str(payload["id"]), str(payload["command_hash"]), str(payload["requester"]), str(payload["approver"]) if payload.get("approver") is not None else None, str(payload["status"]), str(payload["reason"]), str(payload["created_at"]), str(payload["updated_at"]), str(payload.get("expires_at", "")))


def _handoff_from_payload(payload: dict[str, object]) -> Handoff:
    return Handoff(str(payload["id"]), str(payload["title"]), str(payload["from_agent"]), str(payload["to_agent"]), str(payload["status"]), str(payload["summary"]), str(payload["created_at"]), str(payload["updated_at"]), str(payload.get("reviewer", "")), str(payload.get("review_decision", "")), str(payload.get("review_notes", "")), accepted_by=str(payload.get("accepted_by", "")))


def _bus_from_payload(payload: dict[str, object]) -> BusMessage:
    return BusMessage(*(str(payload[name]) for name in ("id", "channel", "actor", "severity", "message", "created_at")))


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _require_unexpired(approval: Approval) -> None:
    if approval.expires_at and _parse_time(approval.expires_at) <= datetime.now(timezone.utc):
        raise ValueError(f"approval is expired: {approval.id}")


def _append_event(state: Path, event: ControlEvent) -> None:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    with _locked_state(state):
        _append_event_unlocked(state, event)


def _append_event_unlocked(state: Path, event: ControlEvent) -> None:
    """Append one JSONL record with one durable write."""
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    record = (json.dumps(event.to_dict(), sort_keys=True) + "\n").encode("utf-8")
    durable_mkdir(state.parent)
    fd = os.open(state, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        size = os.fstat(fd).st_size
        if size:
            os.lseek(fd, size - 1, os.SEEK_SET)
            if os.read(fd, 1) != b"\n":
                raise ValueError(
                    "control log has a torn final event; refusing append; "
                    "run `arvyx control-log recover-torn-final --state <path>`"
                )
        written = os.write(fd, record)
        if written != len(record):
            os.fsync(fd)
            raise OSError(f"short event append: wrote {written} of {len(record)} bytes")
        os.fsync(fd)
        # Always retry the namespace barrier, including after an earlier fsync
        # failure left a visible but not durably acknowledged first append.
        fsync_directory(state.parent)
    finally:
        os.close(fd)


def _append_events_unlocked(state: Path, events: Iterable[ControlEvent]) -> None:
    """Durably append events one bounded record at a time.

    A crash can therefore damage only the final record, while every completed
    record has already crossed an fsync boundary. The caller's state lock keeps
    the sequence contiguous without turning the sequence into one large write.
    """
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    for event in events:
        _append_event_unlocked(state, event)


def recover_torn_final_event(state: Path) -> dict[str, object]:
    """Explicitly quarantine and remove only an invalid, unterminated final record.

    Complete records, including a valid final JSON record without a newline, are
    never removed. Any invalid record before the final suffix fails closed.
    """
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    with _locked_state(state):
        if not state.exists():
            raise ValueError("no torn final event: event log does not exist")
        data = state.read_bytes()
        if not data or data.endswith(b"\n"):
            # Validate before reporting that there is nothing to recover.
            read_events(state)
            raise ValueError("no torn final event")
        complete, separator, final = data.rpartition(b"\n")
        prefix = complete + separator
        for line_number, line in enumerate(complete.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                parse_event_line(line.decode('utf-8'), line_number=line_number)
            except (ValueError, UnicodeDecodeError) as exc:
                raise ValueError(f"mid-file corruption on line {line_number}; refusing final-record recovery") from exc
        try:
            json.loads(final)
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
        else:
            # A complete but schema-invalid final record is corruption, not a
            # removable torn write and not eligible for newline-only repair.
            parse_event_line(final.decode('utf-8'), line_number=prefix.count(b'\n') + 1)
            fd = os.open(state, os.O_WRONLY | os.O_APPEND)
            try:
                if os.fstat(fd).st_size != len(data):
                    raise OSError("event log changed during torn-record recovery; refusing repair")
                if os.write(fd, b"\n") != 1:
                    raise OSError("short write while repairing missing final newline")
                os.fsync(fd)
            finally:
                os.close(fd)
            from .filesystem import fsync_directory
            fsync_directory(state.parent)
            return {
                "repair": "missing_final_newline",
                "removed_bytes": 0,
                "quarantine_path": "",
                "quarantine_sha256": "",
            }

        digest = hashlib.sha256(final).hexdigest()[:16]
        quarantine = state.with_name(f"{state.name}.torn-{digest}.bin")
        try:
            qfd = os.open(quarantine, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            import stat as stat_module

            # Never follow a replacement symlink or block on a special file.
            before = os.lstat(quarantine)
            if not stat_module.S_ISREG(before.st_mode):
                raise ValueError("nonregular torn-record quarantine; refusing recovery")
            qfd = os.open(quarantine, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
                          | getattr(os, 'O_NONBLOCK', 0))
            try:
                metadata = os.fstat(qfd)
                if (not os.path.samestat(before, metadata)
                        or not stat_module.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                        or metadata.st_size != len(final)):
                    raise ValueError("conflicting or partial torn-record quarantine; refusing recovery")
                with os.fdopen(qfd, 'rb', closefd=False) as saved:
                    if saved.read(len(final) + 1) != final:
                        raise ValueError("conflicting or partial torn-record quarantine; refusing recovery")
                os.fsync(qfd)
            finally:
                os.close(qfd)
        else:
            try:
                written = os.write(qfd, final)
                if written != len(final):
                    raise OSError(f"short quarantine write: wrote {written} of {len(final)} bytes")
                os.fsync(qfd)
            finally:
                os.close(qfd)
        # Publish durable quarantine evidence before destroying the suffix.
        if os.name != "nt":
            directory_fd = os.open(state.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        fd = os.open(state, os.O_RDWR)
        try:
            with os.fdopen(fd, 'rb', closefd=False) as current:
                if current.read(len(data) + 1) != data:
                    raise OSError("event log changed during torn-record recovery; refusing truncate")
            os.ftruncate(fd, len(prefix))
            os.fsync(fd)
        finally:
            os.close(fd)
        if os.name != "nt":
            directory_fd = os.open(state.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        return {
            "removed_bytes": len(final),
            "quarantine_path": str(quarantine),
            "quarantine_sha256": hashlib.sha256(final).hexdigest(),
        }


@contextmanager
def _locked_state(state: Path):
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    check_inherited_deadline()
    state.parent.mkdir(parents=True, exist_ok=True)
    with exclusive_lock(state.with_suffix(state.suffix + ".lock"), deadline=inherited_deadline()):
        check_inherited_deadline()
        assert_state_authority(state)
        yield


def _event(event_type: str, task_id: str, timestamp: str, payload: dict[str, object]) -> ControlEvent:
    event_id = f"event_{token_hex(12)}"
    return ControlEvent(id=event_id, type=event_type, task_id=task_id, timestamp=timestamp, payload=payload)


def _stable_id(prefix: str, *parts: object) -> str:
    digest = hashlib.sha256("\0".join(str(part) for part in parts).encode("utf-8")).hexdigest()[:12]
    return f"{prefix}_{digest}_{token_hex(3)}"


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
