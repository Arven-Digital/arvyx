"""Exact operator retirement; never completion, dispatch or reconciliation.

Only the two documented categories are supported. Read/validate/append uses
one control-state lock, including dry runs. Raw history is deliberately read
rather than trusting a latest snapshot to prove no prior send occurred.
"""
from dataclasses import replace
from pathlib import Path
import json
import re

from .auth import Identity, SCOPE_CONTROL_WRITE, SCOPE_CONTROL_DELIVERY
from .control import (
    _append_event_unlocked, _acknowledge_replay_unlocked, _event, _locked_state, _now, _project_threads,
    _reject_secret_shaped_text, _thread_event_payload, read_events,
)
from .thread_history import validate_thread_history as _validate_thread_history
from .exact_fences import validate_known_lineage, validate_raw_outbox
from .execution import EXECUTION_EVENT_TYPES, project_executions
from .outbox import _payload_hash, _identity, _project_outbox_state
from .watchdog import _escalation_title, _is_watchdog_escalation
from .watchdog_alerts import operator_hold_alert_bodies as _operator_hold_alert_bodies

COMMON = frozenset({"expected_event_id", "source_event_id", "target", "terminal_event_id", "category", "reason"})
THREAD_FIELDS = COMMON | {"execution_id", "execution_subject_id", "execution_target"}
DELIVERY_FIELDS = COMMON | {"subject_id", "payload_hash", "epoch"}


def _request(request, fields, category, identity, dry_run):
    if identity is None or identity.kind != "operator" or identity.agent_id != "operator":
        raise ValueError("operator identity required for retirement")
    scope = SCOPE_CONTROL_WRITE if fields == THREAD_FIELDS else SCOPE_CONTROL_DELIVERY
    if scope not in identity.scopes:
        raise ValueError("operator lacks retirement scope")
    if type(dry_run) is not bool or not isinstance(request, dict) or set(request) != fields:
        raise ValueError("retirement requires the exact request fields")
    for key, value in request.items():
        if key == "epoch":
            if type(value) is not int or value != 0:
                raise ValueError("only original legacy epoch zero is eligible")
        elif not isinstance(value, str) or not value.strip() or value != value.strip():
            raise ValueError(f"{key} must be a nonempty exact string")
    if request["category"] != category:
        raise ValueError("unsupported retirement category")
    if len(request["reason"]) > 1024:
        raise ValueError("retirement reason exceeds 1024 characters")
    _reject_secret_shaped_text(reason=request["reason"])
    return dict(request)


def _one(events, event_id):
    matches = [e for e in events if e.id == event_id]
    if len(matches) != 1:
        raise ValueError("exact evidence event is missing or ambiguous")
    return matches[0]


def _latest(events, identifier):
    matches = [e for e in events if e.task_id == identifier]
    if not matches:
        raise ValueError("unknown exact record")
    return matches[-1]


def _revision(events, identifier, request, operation, record):
    latest = _latest(events, identifier)
    metadata = record.retirement
    if metadata:
        event_type = "thread.retired" if operation == "retire_thread" else "outbox.cancelled"
        recorded = [e for e in events if e.task_id == identifier and e.type == event_type
                    and e.payload.get("retirement") == metadata]
        if (metadata.get("request") != request or metadata.get("operation") != operation
                or metadata.get("operator") != "operator" or len(recorded) != 1):
            raise ValueError("retirement retry conflicts with recorded action")
        # Thread GET/readback appends thread.read. It must not break an exact
        # retry, but no other post-retirement lifecycle change is admissible.
        for event in events[events.index(recorded[0]) + 1:]:
            if event.task_id == identifier and not (
                    operation == "retire_thread" and event.type == "thread.read"
                    and event.payload.get("status") == "retired"
                    and event.payload.get("retirement") == metadata):
                raise ValueError("retired record changed after the action")
        return recorded[0]
    if latest.id != request["expected_event_id"]:
        raise ValueError("stale expected_event_id")
    return False


def _known_lineage(events, identifiers):
    # Also inspect raw roots that projections ignore/quarantine. A future event
    # attached to this exact subject cannot disappear behind a latest snapshot.
    linked = set(identifiers)
    for event in events:
        if any(event.payload.get(key) in identifiers for key in ("subject_id", "execution_id")):
            linked.add(event.task_id)
    validate_known_lineage(events, linked)


def _no_continuation(events, threads, identifiers):
    if any(t.continuation_thread_id and (t.id in identifiers or t.continuation_thread_id in identifiers)
           for t in threads.values()):
        raise ValueError("continuation-linked records are not eligible")
    for e in events:
        if (e.task_id in identifiers or e.payload.get("subject_id") in identifiers
                or e.payload.get("execution_id") in identifiers):
            if (e.payload.get("continuation_thread_id") or e.payload.get("continuation_of")
                    or e.type == "execution.session_return.requested"
                    or e.payload.get("source_event_type") == "outbox.session_return.delivered"):
                raise ValueError("continuation/return lineage is not eligible")


def _metadata(request, operation, terminal, timestamp):
    return {"operation": operation, "operator": "operator", "retired_at": timestamp,
            "request": request, "terminal_evidence": {
                "event_id": terminal.id, "event_type": terminal.type,
                "timestamp": terminal.timestamp, "record_id": terminal.task_id,
                "status": terminal.payload.get("status"),
            }}


def _result(record, event, *, changed, dry_run):
    return {"record": record.to_dict(), "event_id": event.id if event else None,
            "changed": changed, "dry_run": dry_run}


def retire_thread(state: Path, *, thread_id: str, request: dict, identity: Identity | None,
                  dry_run: bool = False) -> dict:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    request = _request(request, THREAD_FIELDS, "obsolete_watchdog_alert", identity, dry_run)
    with _locked_state(state):
        events = read_events(state)
        _validate_thread_history(events, thread_id)
        threads = _project_threads(state, events)
        thread = threads.get(thread_id)
        if thread is None:
            raise ValueError("unknown exact thread")
        identifiers = {thread_id, request["execution_id"], request["execution_subject_id"]}
        _known_lineage(events, identifiers)
        _no_continuation(events, threads, identifiers)
        retry = _revision(events, thread_id, request, "retire_thread", thread)
        source = _one(events, request["source_event_id"])
        execution = project_executions(state).get(request["execution_id"])
        if execution is None or (execution.subject_id, execution.target) != (
                request["execution_subject_id"], request["execution_target"]):
            raise ValueError("exact execution binding mismatch")
        if execution.status not in {"closed", "completed"}:
            raise ValueError("referenced execution is not terminal")
        terminal = _one(events, request["terminal_event_id"])
        if (terminal.task_id != execution.id or terminal.type != f"execution.{execution.status}"
                or _latest(events, execution.id).id != terminal.id
                or terminal.payload.get("subject_id") != execution.subject_id
                or terminal.payload.get("target") != execution.target
                or terminal.payload.get("status") != execution.status):
            raise ValueError("exact execution terminal evidence mismatch")
        if (source.type != "thread.created" or source.task_id != thread_id
                or len([e for e in events if e.task_id == thread_id and e.type == "thread.created"]) != 1
                or request["target"] != "operator" or thread.target != "operator"
                or thread.type != "blocker" or thread.status != ("retired" if retry else "open")
                or source.payload.get("type") != "blocker"
                # post_thread historically omits this field for None (including
                # watchdog callers). Absence is unproven, NOT explicit False.
                # Do not loosen the separate watchdog deduplication contract.
                or source.payload.get("actor_identity_bound") is not False
                or thread.actor != source.payload.get("actor")
                or not _is_watchdog_escalation(actor=source.payload.get("actor"),
                    target=source.payload.get("target"), identity_bound=source.payload.get("actor_identity_bound"),
                    worker="arvyx-watchdog")
                or source.payload.get("title") != _escalation_title(execution.id)
                or thread.title != source.payload.get("title")):
            raise ValueError("not an open proven operator watchdog alert")
        # Exact finite body spellings and a preceding HOLD prove the title's join.
        prior = events[:events.index(source)]
        hold = next((e for e in reversed(prior) if e.task_id == execution.id and e.type == "execution.held"), None)
        if (hold is None or (hold.payload.get("subject_id"), hold.payload.get("subject_type"),
                             hold.payload.get("target"), hold.payload.get("status")) !=
                            (execution.subject_id, execution.subject_type, execution.target, "held")
                or source.payload.get("body") not in _operator_hold_alert_bodies(
                    target=execution.target, subject_type=execution.subject_type,
                    subject_id=execution.subject_id, hold_reason=str(hold.payload.get("hold_reason", "")))
                or thread.body != source.payload.get("body")):
            raise ValueError("watchdog HOLD provenance is not proven")
        if any(e.type.startswith("execution.") and e.payload.get("subject_id") == thread_id for e in events):
            raise ValueError("alert has its own execution lineage")
        if retry:
            if not dry_run:
                _acknowledge_replay_unlocked(state, retry)
            return _result(thread, retry, changed=False, dry_run=dry_run)
        timestamp = _now()
        updated = replace(thread, status="retired", latest_at=timestamp, unread=False,
                          retirement_json=json.dumps(_metadata(request, "retire_thread", terminal, timestamp), sort_keys=True))
        if dry_run:
            return _result(updated, None, changed=False, dry_run=True)
        event = _event("thread.retired", thread_id, timestamp, _thread_event_payload(updated))
        _append_event_unlocked(state, event)
        return _result(updated, event, changed=True, dry_run=False)


# These messages originate before adapter I/O, not a generic timeout / HTTP
# error allowlist. Unknown historical errors always need separate adjudication.
_PRE_DISPATCH = re.compile(r"delivery (?:URL|credential) environment reference is not configured: [A-Za-z_][A-Za-z0-9_]*")


def _unsent_history(events, item):
    history = [e for e in events if e.task_id == item.id]
    previous = None
    claimed = False
    attempts = 0
    failures = 0
    for event in history:
        p = event.payload
        if event.type not in {"outbox.enqueued", "outbox.attempt.started", "outbox.attempt.failed", "outbox.deferred"}:
            raise ValueError("prior send evidence or unsupported delivery history")
        if (p.get("payload") != item.payload or p.get("payload_hash") != item.payload_hash
                or p.get("subject_id") != item.subject_id or p.get("target") != item.target
                or p.get("epoch") != item.epoch
                or any(p.get(k) for k in ("delivered_at", "provider_receipt", "ambiguous_at", "ambiguity_detail",
                                          "receipt_status", "receipt_by", "receipt_at", "receipt_detail",
                                          "resolution_category", "cancelled_at"))):
            raise ValueError("delivery history binding or prior-send evidence mismatch")
        if event.type == "outbox.enqueued":
            if p.get("failure_detail"):
                raise ValueError("enqueue has unexplained failure history")
            if previous is not None:
                raise ValueError("duplicate enqueue history")
        elif previous is None:
            raise ValueError("missing original enqueue")
        elif event.type == "outbox.attempt.started":
            if claimed or p.get("status") != "leased" or not p.get("lease_owner") or not p.get("lease_expires_at"):
                raise ValueError("ambiguous prior lease history")
            attempts += 1
            claimed = True
        elif event.type == "outbox.attempt.failed":
            if not claimed or not _PRE_DISPATCH.fullmatch(str(p.get("failure_detail", ""))):
                raise ValueError("failure is not proven pre-dispatch")
            failures += 1
            claimed = False
        elif event.type == "outbox.deferred" and claimed:
            # defer_lease is the dispatcher's pre-I/O deadline path. A pending
            # deferral alone cannot erase a started send or a failed attempt.
            claimed = False
        if (previous is not None and event.type != "outbox.attempt.failed"
                and p.get("failure_detail", "") != previous.payload.get("failure_detail", "")):
            raise ValueError("unexplained change in prior failure evidence")
        if (p.get("attempts") != attempts or p.get("failures", failures) != failures
                or (not claimed and (p.get("status") != "pending" or p.get("lease_owner") or p.get("lease_expires_at")))):
            raise ValueError("incomplete or ambiguous attempt history")
        previous = event
    if previous is None or claimed or item.attempts != attempts or item.failures != failures:
        raise ValueError("unsettled prior delivery history")


def retire_pending_delivery(state: Path, *, outbox_id: str, request: dict,
                            identity: Identity | None, dry_run: bool = False) -> dict:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    request = _request(request, DELIVERY_FIELDS, "obsolete_subject", identity, dry_run)
    with _locked_state(state):
        events = read_events(state)
        item = _project_outbox_state({}, events).get(outbox_id)
        if item is None:
            raise ValueError("unknown exact outbox")
        identifiers = {outbox_id, request["subject_id"]}
        executions = project_executions(state)
        if any(e.type in EXECUTION_EVENT_TYPES and e.payload.get("subject_id") == request["subject_id"]
               and e.task_id not in executions for e in events):
            raise ValueError("source has unknown or quarantined execution lineage")
        related = [e for e in executions.values() if e.subject_id == request["subject_id"]]
        identifiers.update(e.id for e in related)
        _known_lineage(events, identifiers)
        validate_raw_outbox(events, outbox_id)
        _validate_thread_history(events, request["subject_id"])
        threads = _project_threads(state, events)
        _no_continuation(events, threads, identifiers)
        if any(e.status not in {"closed", "completed", "cancelled"} for e in related):
            raise ValueError("source has an active execution lineage")
        retry = _revision(events, outbox_id, request, "retire_pending_delivery", item)
        if (item.status != ("cancelled" if retry else "pending") or item.lease_owner or item.lease_expires_at
                or (item.subject_id, item.target, item.payload_hash, item.epoch) != (
                    request["subject_id"], request["target"], request["payload_hash"], request["epoch"])
                or item.payload_hash != _payload_hash(item.payload)
                or item.id != "outbox_" + _identity(item.subject_id, item.target, item.payload_hash, item.epoch)[:24]):
            raise ValueError("delivery is not exact pending unleased legacy work")
        source = _one(events, request["source_event_id"])
        subject = threads.get(item.subject_id)
        expected_payload: dict[str, object] = {"schema": "v2.agent-delivery/1", "source_event_id": source.id,
                            "source_event_type": "thread.created", "subject_id": item.subject_id}
        if source.payload.get("completion_artifact") and source.payload.get("completion_anchor"):
            expected_payload.update(completion_artifact=source.payload["completion_artifact"],
                                    completion_anchor=source.payload["completion_anchor"])
        if (len([e for e in events if e.task_id == item.subject_id and e.type == "thread.created"]) != 1
                or source.type != "thread.created" or source.task_id != item.subject_id
                or source.payload.get("target") != item.target or source.payload.get("type") not in {"ask", "handoff", "blocker"}
                or item.payload != expected_payload or subject is None or subject.status != "done"
                or subject.target != item.target):
            raise ValueError("source is not an exact terminal legacy actionable thread")
        terminal = _one(events, request["terminal_event_id"])
        done_events = [e for e in events if e.task_id == item.subject_id and e.type == "thread.done"]
        if (not done_events or done_events[-1].id != terminal.id or terminal.type != "thread.done"
                or terminal.task_id != item.subject_id or terminal.payload.get("done_by") != item.target
                or terminal.payload.get("target") != item.target or terminal.payload.get("status") != "done"):
            raise ValueError("exact source terminal evidence mismatch")
        original_events = events[:events.index(_latest(events, outbox_id))] if retry else events
        _unsent_history(original_events, item)
        if retry:
            if not dry_run:
                _acknowledge_replay_unlocked(state, retry)
            return _result(item, retry, changed=False, dry_run=dry_run)
        timestamp = _now()
        updated = replace(item, status="cancelled", updated_at=timestamp, cancelled_at=timestamp,
                          cancellation_reason_category="obsolete_subject", resolution_category="obsolete_subject",
                          resolved_by="operator", resolved_at=timestamp, resolution_detail=request["reason"],
                          retirement=_metadata(request, "retire_pending_delivery", terminal, timestamp))
        if dry_run:
            return _result(updated, None, changed=False, dry_run=True)
        event = _event("outbox.cancelled", item.id, timestamp, updated.to_dict())
        _append_event_unlocked(state, event)
        return _result(updated, event, changed=True, dry_run=False)


ABANDON_CATEGORY = "stale_no_longer_needed"
_LIVE_EXECUTION = frozenset({"pending", "leased", "held", "dead_lettered", "paused"})


def abandon_stale_thread(state: Path, *, thread_id: str, reason: str, approval_reference: str,
                         operator: str = "operator", dry_run: bool = True) -> dict:
    """Retire an open/acknowledged thread that will never be finished, without claiming it was.

    For work debt: a thread its owner acknowledged and abandoned, whose contract may even demand
    completion evidence that will never exist. DONE would be a lie and the strict retirement paths
    only cover watchdog alerts, so the operator records an explicit, reasoned abandonment in the
    existing retired lane. Refused while any execution for the thread is still live, or while a
    pending continuation child depends on it: those must be resolved first, never silently dropped.
    Dry run by default; one thread per call.
    """
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    reason = reason.strip()
    if operator != "operator" or type(dry_run) is not bool:
        raise ValueError("abandonment requires the operator disposition and boolean dry_run")
    approval_reference = approval_reference.strip()
    if not reason or len(reason) > 1024:
        raise ValueError("abandonment needs a reason of at most 1024 characters")
    if not approval_reference or len(approval_reference) > 1024:
        raise ValueError("abandonment needs the operator approval reference")
    _reject_secret_shaped_text(reason=reason, approval_reference=approval_reference)
    with _locked_state(state):
        events = read_events(state)
        threads = _project_threads(state, events)
        thread = threads.get(thread_id)
        if thread is None:
            raise ValueError("unknown exact thread")
        _validate_thread_history(events, thread_id)
        if thread.status not in {"open", "acked"}:
            raise ValueError(f"thread is {thread.status}; only open or acknowledged threads can be abandoned")
        executions = project_executions(state)
        related_ids = {e.task_id for e in events
                       if e.type.startswith('execution.') and e.payload.get('subject_id') == thread_id}
        _known_lineage(events, {thread_id, *related_ids})
        if any(identifier not in executions for identifier in related_ids):
            raise ValueError('thread has unknown or quarantined execution lineage')
        live = sorted(e.id for e in executions.values()
                      if e.subject_id == thread_id and e.status in _LIVE_EXECUTION)
        if live:
            raise ValueError("thread still has live execution work (close or resolve it first): " + ", ".join(live))
        children = sorted(t.id for t in threads.values()
                          if t.continuation_thread_id == thread_id and t.status not in {"done", "retired"})
        if children:
            raise ValueError("a pending continuation child depends on this thread: " + ", ".join(children))
        timestamp = _now()
        metadata = {"operation": "abandon", "category": ABANDON_CATEGORY, "operator": operator,
                    "retired_at": timestamp, "reason": reason, "approval_reference": approval_reference,
                    "prior_status": thread.status}
        updated = replace(thread, status="retired", latest_at=timestamp, unread=False,
                          retirement_json=json.dumps(metadata, sort_keys=True))
        event = _event("thread.retired", thread_id, timestamp, _thread_event_payload(updated))
        _validate_thread_history([*events, event], thread_id)
        if dry_run:
            return _result(updated, None, changed=False, dry_run=True)
        _append_event_unlocked(state, event)
        return _result(updated, event, changed=True, dry_run=False)
