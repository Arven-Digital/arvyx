from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Callable, Mapping, Sequence

from .control import (
    ControlEvent,
    _append_event_unlocked,
    _append_events_unlocked,
    _event,
    _locked_state,
    read_events,
)
from . import projection_cache
from .security import contains_literal_secret, redact_secrets


RECEIPT_DETAIL_MAX_LENGTH = 4096
SESSION_RETURN_EXPIRED_LEASE = "session return dispatch lease expired before finalization; provider reconciliation required"


OUTBOX_EVENT_TYPES = frozenset({
    "outbox.enqueued",
    "outbox.attempt.started",
    "outbox.attempt.failed",
    "outbox.delivered",
    "outbox.deferred",
    "outbox.dead_lettered",
    "outbox.replayed",
    "outbox.receipt",
    "outbox.cancelled",
    "outbox.resolved",
})

# Append-only dead-letter resolution taxonomy. A dead letter can never be
# cancelled (its evidence is history), but it can be classified so the health
# surface stops demanding action for work that no longer needs any:
#   obsolete           - the subject no longer matters (stale canary, retired flow)
#   superseded         - a newer delivery or subject replaced this one
#   terminal_elsewhere - the underlying subject reached an authoritative
#                        terminal state through another route
RESOLUTION_CATEGORIES = frozenset({"obsolete", "superseded", "terminal_elsewhere"})
# A recorded ambiguity is the only classification that may be replaced: the
# transport outcome was never verifiable, and when the originating attempt has
# ended the replay gate refuses the item, so without this transition the dead
# letter would stay unresolved forever. Every other classification stays
# immutable and a re-classification keeps the replaced category on the record.
RECLASSIFIABLE_RESOLUTION_CATEGORIES = frozenset({"ambiguous_not_delivered"})
RESOLUTION_DETAIL_MAX_LENGTH = 1024
# Execution wakes are sent by the execution worker, not the outbox dispatcher.
# Their delivery records live in the outbox projection so the delivery ID a
# wake names always resolves, but the execution lineage (fenced attempts,
# lease, retry, HOLD) owns their redelivery: the dispatcher never claims or
# replays them.
EXECUTION_WAKE_MODE = "execution"
# Sends that land in a human's chat through the agent's own bot. A second send
# is visible to the human, so an expired lease or a lost finalization fences to
# ambiguous_delivery instead of retrying, and the provider receipt is kept.
HUMAN_FACING_MODES = frozenset({"session_return", "decision_card"})
EXECUTION_WAKE_RESOLVER = "execution-worker"
MATERIALIZATION_CHECKPOINT_EVENT = "outbox.materialization.checkpoint"
MATERIALIZATION_SKIPPED_EVENT = "outbox.materialization.skipped"
DISPATCHER_TICK_EVENT = "outbox.dispatcher.tick"
BUILTIN_NON_AGENT_TARGETS = frozenset({"all"})
# ``all`` is the canonical global broadcast target for status/update threads.
# The dispatcher expands it to registered concrete routes; a literal route
# named ``all`` is invalid. Legacy actionable ``all`` records remain pull-only
# and observable so they neither fan out nor poison the checkpoint.


@dataclass(frozen=True)
class OutboxItem:
    id: str
    subject_id: str
    target: str
    payload: dict[str, object]
    payload_hash: str
    epoch: int
    status: str
    attempts: int
    created_at: str
    updated_at: str
    next_attempt_at: str
    lease_owner: str = ""
    lease_expires_at: str = ""
    failures: int = 0
    failure_detail: str = ""
    delivered_at: str = ""
    provider_receipt: str = ""
    ambiguous_at: str = ""
    ambiguity_detail: str = ""
    receipt_status: str = ""
    receipt_by: str = ""
    receipt_at: str = ""
    receipt_detail: str = ""
    cancellation_reason_category: str = ""
    cancelled_at: str = ""
    resolution_category: str = ""
    resolved_by: str = ""
    resolved_at: str = ""
    resolution_detail: str = ""
    prior_resolution_category: str = ""
    retirement: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "subject_id": self.subject_id,
            "target": self.target,
            "payload": self.payload,
            "payload_hash": self.payload_hash,
            "epoch": self.epoch,
            "status": self.status,
            "attempts": self.attempts,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "next_attempt_at": self.next_attempt_at,
            "lease_owner": self.lease_owner,
            "lease_expires_at": self.lease_expires_at,
            "failures": self.failures,
            "failure_detail": self.failure_detail,
            "delivered_at": self.delivered_at,
            "provider_receipt": self.provider_receipt,
            "ambiguous_at": self.ambiguous_at,
            "ambiguity_detail": self.ambiguity_detail,
            "receipt_status": self.receipt_status,
            "receipt_by": self.receipt_by,
            "receipt_at": self.receipt_at,
            "receipt_detail": self.receipt_detail,
            "cancellation_reason_category": self.cancellation_reason_category,
            "cancelled_at": self.cancelled_at,
            "resolution_category": self.resolution_category,
            "resolved_by": self.resolved_by,
            "resolved_at": self.resolved_at,
            "resolution_detail": self.resolution_detail,
            "prior_resolution_category": self.prior_resolution_category,
            "retirement": self.retirement,
        }


def enqueue(
    state: Path,
    *,
    subject_id: str,
    target: str,
    payload: Mapping[str, object],
    epoch: int = 0,
    now: datetime | None = None,
) -> OutboxItem:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    canonical_payload = dict(payload)
    payload_hash = _payload_hash(canonical_payload)
    identity = _identity(subject_id, target, payload_hash, epoch)
    with _locked_state(state):
        from .operator_archive import require_unarchived
        require_unarchived(state, subject_id)
        items = project_outbox(state)
        for item in items.values():
            if _identity(item.subject_id, item.target, item.payload_hash, item.epoch) == identity:
                return item
        timestamp = _timestamp(now)
        item = OutboxItem(
            id=f"outbox_{identity[:24]}",
            subject_id=subject_id,
            target=target,
            payload=canonical_payload,
            payload_hash=payload_hash,
            epoch=epoch,
            status="pending",
            attempts=0,
            created_at=timestamp,
            updated_at=timestamp,
            next_attempt_at=timestamp,
        )
        _append_event_unlocked(state, _event("outbox.enqueued", item.id, timestamp, item.to_dict()))
        return item


def _recover_session_return_continuations_unlocked(
    state: Path, items: dict[str, OutboxItem], *, now: datetime | None,
    limit: int, outbox_id: str | None = None,
) -> int:
    """Delivered originals are durable intent; only missing wakes consume budget.

    No provider I/O, no reopening originals. The claim lock serializes the
    receipt/terminal check and append. Deterministic identity repairs a crash
    before or after any wake append without requiring another provider send.
    """
    from .session_return import session_return_continuation_payload
    from .operator_archive import archived_ids
    from .execution import project_executions
    events = read_events(state)
    archived = archived_ids(events)
    executions = project_executions(state)
    recovered = 0
    for original in list(items.values()):
        if recovered >= limit:
            break
        if outbox_id is not None and original.id != outbox_id:
            continue
        if original.subject_id in archived:
            continue
        if original.status != "delivered" or original.payload.get("delivery_mode") != "session_return":
            continue
        execution_id = original.payload.get("execution_id")
        execution = executions.get(execution_id) if isinstance(execution_id, str) else None
        # The durable provider receipt is not authority to wake a replacement
        # execution incarnation or an archived canonical subject. Expiry alone
        # is deliberately not a refusal: receipt recovery survives runtime exit.
        if (execution is None or execution.subject_id in archived
                or execution.id in archived
                or execution.attempt_id != original.payload.get("attempt_id")
                or execution.target.strip().casefold() != original.target.strip().casefold()
                or original.payload_hash != _payload_hash(original.payload)):
            continue
        payload = session_return_continuation_payload(state, original)
        if payload is None:
            continue
        payload_hash = _payload_hash(payload)
        identity = _identity(original.subject_id, original.target, payload_hash, 0)
        item_id = f"outbox_{identity[:24]}"
        if item_id in items:
            continue
        timestamp = _timestamp(now)
        continuation = OutboxItem(
            id=item_id, subject_id=original.subject_id, target=original.target,
            payload=payload, payload_hash=payload_hash, epoch=0,
            status="pending", attempts=0, created_at=timestamp,
            updated_at=timestamp, next_attempt_at=timestamp,
        )
        _append_event_unlocked(
            state, _event("outbox.enqueued", item_id, timestamp, continuation.to_dict()),
        )
        items[item_id] = continuation
        recovered += 1
    return recovered


def recover_session_return_continuations(
    state: Path, *, now: datetime | None = None, limit: int = 100,
    outbox_id: str | None = None,
) -> int:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    if limit < 1:
        raise ValueError("continuation recovery limit must be positive")
    with _locked_state(state):
        return _recover_session_return_continuations_unlocked(
            state, project_outbox(state), now=now, limit=limit, outbox_id=outbox_id,
        )


EXACT_OUTBOX_FIELDS = frozenset({
    "outbox_id", "subject_id", "target", "source_event_id", "source_event_type",
    "execution_id", "attempt_id", "payload_hash",
})


def _claim_exact_outboxes_unlocked(
    state: Path, allowlist: list[dict[str, str]], *,
    worker: str, targets: set[str] | None, current: datetime, lease_seconds: int,
    limit: int, dry_run: bool, intentional_human_targets: set[str] | None = None,
) -> list[OutboxItem]:
    """Existing, fresh items only; validate the entire manifest before any append.

    No materialization, cursor advance, orphan settlement, retry or continuation
    creation is permitted here. None selects the independent normal path; an
    empty or malformed explicit manifest never falls back to that path.
    """
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    if not isinstance(allowlist, list) or not allowlist or len(allowlist) > limit:
        raise ValueError("exact outbox allowlist must be non-empty and fit limit")
    events = read_events(state)
    selected: list[OutboxItem] = []
    seen: set[str] = set()
    for fence in allowlist:
        if not isinstance(fence, dict) or set(fence) != EXACT_OUTBOX_FIELDS:
            raise ValueError("exact outbox allowlist fields are invalid")
        if any(not isinstance(v, str) or v != v.strip() for v in fence.values()):
            raise ValueError("exact outbox values must be literal strings")
        if any(not fence[k] for k in EXACT_OUTBOX_FIELDS - {"execution_id", "attempt_id"}):
            raise ValueError("exact outbox tuple is incomplete")
        from .exact_fences import validate_known_lineage, validate_raw_outbox
        validate_known_lineage(events, {v for k, v in fence.items()
                                       if k in {"outbox_id", "subject_id", "execution_id"} and v})
        validate_raw_outbox(events, fence["outbox_id"])
        item = project_outbox(state).get(fence["outbox_id"])
        if item is None or item.id in seen:
            raise ValueError("exact outbox is missing or duplicated")
        from .operator_archive import require_unarchived
        require_unarchived(state, item.subject_id)
        seen.add(item.id)
        actual = dict(outbox_id=item.id, subject_id=item.subject_id, target=item.target,
                      payload_hash=item.payload_hash, **{k: item.payload.get(k, "") for k in
                      ("source_event_id", "source_event_type", "execution_id", "attempt_id")})
        # The configured agent routes are the authority; no deployment's agent
        # names live in code. Human targets never use this exact agent path.
        if (actual != fence or targets is None or item.target not in targets
                or item.target in (intentional_human_targets or set())):
            raise ValueError("exact outbox provenance tuple mismatch")
        if (item.payload_hash != _payload_hash(item.payload) or item.epoch != 0
                or item.id != f"outbox_{_identity(item.subject_id, item.target, item.payload_hash, 0)[:24]}"):
            raise ValueError("exact outbox identity mismatch")
        if (item.status != "pending" or item.attempts != 0 or item.failures != 0
                or any(e.task_id == item.id and e.type == "outbox.attempt.started" for e in events)
                or _parse_rfc3339(item.next_attempt_at, label="next_attempt_at") > current):
            raise ValueError("exact outbox must be fresh pending and due")
        mode = item.payload.get("delivery_mode", "direct")
        # Receipt continuations require a separate supported creation gate. This
        # narrow path refuses them rather than minting or sending an implicit wake.
        if mode not in {"direct", "session_return"}:
            raise ValueError("exact outbox delivery mode is not supported")
        sources = [e for e in events if e.id == fence["source_event_id"]]
        if len(sources) != 1 or sources[0].type != fence["source_event_type"] or sources[0].task_id != item.subject_id:
            raise ValueError("exact outbox source mismatch")
        source = sources[0]
        if mode == "session_return":
            from .session_return import classify_session_return_dispatch
            if (source.type != "execution.session_return.requested"
                    or any(source.payload.get(k) != fence[k] for k in ("target", "execution_id", "attempt_id"))
                    or any(source.payload.get(k) != item.payload.get(k) for k in ("message", "message_sha256", "word_count"))
                    or not fence["execution_id"] or not fence["attempt_id"]
                    or classify_session_return_dispatch(state, execution_id=fence["execution_id"],
                        attempt_id=fence["attempt_id"], target=item.target, now=current) is not None):
                raise ValueError("exact session return source or live attempt mismatch")
        elif (source.type not in {"thread.created", "handoff.created"}
              or source.payload.get("target" if source.type == "thread.created" else "to_agent") != item.target
              or source.payload.get("actor_identity_bound") is not True
              or fence["execution_id"] or fence["attempt_id"]):
            raise ValueError("exact direct source mismatch")
        selected.append(item)
    if dry_run:
        return []
    claimed = []
    for item in selected:
        stamp = _timestamp(current)
        updated = replace(item, status="leased", attempts=1, updated_at=stamp,
                          lease_owner=worker, lease_expires_at=_timestamp(current + timedelta(seconds=lease_seconds)))
        _append_event_unlocked(state, _event("outbox.attempt.started", item.id, stamp, updated.to_dict()))
        claimed.append(updated)
    return claimed


def claim_due(
    state: Path,
    *,
    worker: str,
    now: datetime | None = None,
    lease_seconds: int = 60,
    limit: int = 1,
    deliver_after: str | None = None,
    targets: set[str] | None = None,
    intentional_human_targets: set[str] | None = None,
    per_target_limit: int | None = None,
    max_attempts: int = 8,
    deferred_by_target_cap: dict[str, int] | None = None,
    quarantined: list[str] | None = None,
    dead_lettered_on_reclaim: list[str] | None = None,
    ambiguous_on_reclaim: list[str] | None = None,
    materialization_limit: int = 100,
    materialization_report: dict[str, object] | None = None,
    dry_run: bool = False,
    max_watermark_age_seconds: int | None = None,
    exact_allowlist: list[dict[str, str]] | None = None,
) -> list[OutboxItem]:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    if lease_seconds < 1:
        raise ValueError("lease_seconds must be positive")
    if limit < 1:
        raise ValueError("limit must be positive")
    if per_target_limit is not None and per_target_limit < 1:
        raise ValueError("per_target_limit must be positive")
    if max_attempts < 1:
        raise ValueError("max_attempts must be positive")
    if materialization_limit < 1:
        raise ValueError("materialization_limit must be positive")
    if max_watermark_age_seconds is not None and max_watermark_age_seconds < 1:
        raise ValueError("max_watermark_age_seconds must be positive")
    current = now or datetime.now(timezone.utc)
    watermark = _parse_rfc3339(deliver_after, label="deliver_after") if deliver_after is not None else None
    normalized_targets = (
        None if targets is None else {_normalize_materialization_target(target) for target in targets}
    )
    effective_non_agent_targets = set(BUILTIN_NON_AGENT_TARGETS)
    effective_non_agent_targets.update(
        _normalize_materialization_target(target) for target in (intentional_human_targets or ())
    )
    if normalized_targets is not None:
        effective_non_agent_targets.difference_update(normalized_targets)
    def stamp() -> str:
        # Sample per append. This pass waits on the state lock and materializes
        # from a full log read before it writes anything, so a stamp taken on
        # entry can predate the source event that produced the item. With an
        # injected clock the stamp stays pinned exactly as before.
        return _timestamp(now)

    claimed: list[OutboxItem] = []
    claimed_by_target: dict[str, int] = {}
    with _locked_state(state):
        if exact_allowlist is not None:
            return _claim_exact_outboxes_unlocked(
                state, exact_allowlist, worker=worker, targets=targets,
                current=current, lease_seconds=lease_seconds, limit=limit, dry_run=dry_run,
                intentional_human_targets=intentional_human_targets,
            )
        projected = project_outbox(state)
        if not dry_run:
            _recover_session_return_continuations_unlocked(
                state, projected, now=now, limit=materialization_limit,
            )
        if watermark is not None:
            checkpoint = _materialization_checkpoint(state)
            bootstrap_expired = (
                checkpoint is None
                and max_watermark_age_seconds is not None
                and current - watermark > timedelta(seconds=max_watermark_age_seconds)
            )
            if bootstrap_expired:
                materialized, remaining = 0, False
            else:
                materialized, remaining = _materialize_source_events_unlocked(
                    state,
                    projected,
                    deliver_after=watermark,
                    checkpoint=checkpoint,
                    now=now,
                    quarantined=quarantined,
                    limit=materialization_limit,
                    dry_run=dry_run,
                    target_allowlist=normalized_targets,
                    intentional_human_targets=effective_non_agent_targets,
                    skip_report=materialization_report,
                )
            if materialization_report is not None:
                materialization_report.update(materialized=materialized, remaining=remaining)
                if bootstrap_expired:
                    materialization_report["bootstrap_expired"] = True
        if dry_run:
            return []
        scheduled: list[tuple[datetime, datetime, OutboxItem]] = []
        orphan_cache: dict[str, object] = {}
        from .operator_archive import archived_ids
        archived = archived_ids(read_events(state))
        for item in projected.values():
            if item.subject_id in archived:
                continue
            if item.payload.get("delivery_mode") == EXECUTION_WAKE_MODE:
                # Never claimed here: the execution worker sent it. A record
                # the worker left leased (worker crash between send and
                # finalization) is settled from the execution lineage, never
                # redelivered: a target heartbeat on the fenced attempt proves
                # receipt; a still-live attempt is left alone; only a record
                # whose attempt is gone is classified superseded.
                if item.status == "leased":
                    verdict = _orphan_wake_verdict(state, item, current=current, cache=orphan_cache)
                    if verdict == "delivered":
                        _append_event_unlocked(
                            state,
                            _event(
                                "outbox.delivered",
                                item.id,
                                stamp(),
                                replace(
                                    item,
                                    status="delivered",
                                    updated_at=stamp(),
                                    lease_owner="",
                                    lease_expires_at="",
                                    failure_detail="",
                                    delivered_at=stamp(),
                                ).to_dict(),
                            ),
                        )
                    elif verdict == "superseded":
                        _append_event_unlocked(
                            state,
                            _event(
                                "outbox.dead_lettered",
                                item.id,
                                stamp(),
                                _classified_execution_wake_failure(
                                    item,
                                    timestamp=stamp(),
                                    detail="execution worker did not finalize this wake before its lease expired",
                                ).to_dict(),
                            ),
                        )
                continue
            due = _try_parse_rfc3339(item.next_attempt_at)
            created = _try_parse_rfc3339(item.created_at)
            if (
                due is None
                or created is None
                or (item.status == "leased" and _try_parse_rfc3339(item.lease_expires_at) is None)
            ):
                if quarantined is not None:
                    quarantined.append(item.id)
                continue
            scheduled.append((due, created, item))
        items = [entry[2] for entry in sorted(scheduled, key=lambda entry: (entry[0], entry[1], entry[2].id))]
        for item in items:
            if len(claimed) >= limit:
                break
            if (
                item.status not in {"pending", "leased"}
                or _parse_rfc3339(item.next_attempt_at, label="next_attempt_at") > current
            ):
                continue
            if normalized_targets is not None and item.target not in normalized_targets:
                continue
            if (
                item.status == "leased"
                and _parse_rfc3339(item.lease_expires_at, label="lease_expires_at") > current
            ):
                continue
            if per_target_limit is not None and claimed_by_target.get(item.target, 0) >= per_target_limit:
                if deferred_by_target_cap is not None:
                    deferred_by_target_cap[item.target] = deferred_by_target_cap.get(item.target, 0) + 1
                continue
            failures = item.failures
            if item.status == "leased":
                if item.payload.get("delivery_mode") in HUMAN_FACING_MODES:
                    # A timed-out sender may still be inside provider I/O, or
                    # may have crashed after acceptance. Never send it twice.
                    timestamp = stamp()
                    ambiguous = replace(
                        item, status="ambiguous_delivery", updated_at=timestamp,
                        lease_owner="", lease_expires_at="", failure_detail="",
                        ambiguous_at=timestamp, ambiguity_detail=SESSION_RETURN_EXPIRED_LEASE,
                    )
                    _append_event_unlocked(
                        state, _event("outbox.dead_lettered", item.id, timestamp, ambiguous.to_dict())
                    )
                    if ambiguous_on_reclaim is not None:
                        ambiguous_on_reclaim.append(item.id)
                    continue
                failures += 1
                if failures >= max_attempts:
                    dead = replace(
                        item,
                        status="dead_lettered",
                        failures=failures,
                        updated_at=stamp(),
                        lease_owner="",
                        lease_expires_at="",
                        failure_detail="lease expired before finalization",
                    )
                    _append_event_unlocked(state, _event("outbox.dead_lettered", item.id, stamp(), dead.to_dict()))
                    if dead_lettered_on_reclaim is not None:
                        dead_lettered_on_reclaim.append(item.id)
                    continue
            # The lease is anchored where it is taken: a deadline computed from
            # the pass start would silently shorten every lease by the length of
            # the pass itself.
            claimed_at = current if now is not None else datetime.now(timezone.utc)
            updated = replace(
                item,
                status="leased",
                attempts=item.attempts + 1,
                failures=failures,
                updated_at=stamp(),
                lease_owner=worker,
                lease_expires_at=_timestamp(claimed_at + timedelta(seconds=lease_seconds)),
            )
            _append_event_unlocked(state, _event("outbox.attempt.started", item.id, stamp(), updated.to_dict()))
            claimed.append(updated)
            claimed_by_target[item.target] = claimed_by_target.get(item.target, 0) + 1
    return claimed


def record_failure(
    state: Path,
    *,
    outbox_id: str,
    worker: str,
    claim_attempts: int,
    detail: str,
    transient: bool,
    now: datetime | None = None,
    base_backoff_seconds: int = 5,
    max_backoff_seconds: int = 300,
    max_attempts: int = 8,
    jitter: Callable[[int], int] | None = None,
    resolution_category: str = "",
    resolved_by: str = "",
    resolution_detail: str = "",
) -> OutboxItem:
    """Record one failed attempt; retry transient failures, dead-letter the rest.

    ``resolution_category`` classifies a permanent failure in the same
    append-only dead-letter event when the caller can prove from
    authoritative state that nothing is left to act on (for example a session
    return whose fenced attempt was superseded). It is ignored for a failure
    that is retried.
    """
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    if base_backoff_seconds < 1 or max_backoff_seconds < base_backoff_seconds:
        raise ValueError("invalid backoff bounds")
    if max_attempts < 1:
        raise ValueError("max_attempts must be positive")
    if resolution_category and resolution_category not in RESOLUTION_CATEGORIES:
        raise ValueError(
            "resolution_category must be one of: " + ", ".join(sorted(RESOLUTION_CATEGORIES))
        )
    if resolution_category and not resolved_by.strip():
        raise ValueError("a classified dead letter requires resolved_by")
    current = now or datetime.now(timezone.utc)
    timestamp = _timestamp(current)
    with _locked_state(state):
        item = _leased_item(state, outbox_id, worker, current, claim_attempts=claim_attempts)
        failures = item.failures + 1
        if not transient or failures >= max_attempts:
            updated = replace(
                item,
                status="dead_lettered",
                failures=failures,
                updated_at=timestamp,
                lease_owner="",
                lease_expires_at="",
                failure_detail=redact_secrets(detail),
            )
            if resolution_category:
                updated = replace(
                    updated,
                    resolution_category=resolution_category,
                    resolved_by=resolved_by.strip(),
                    resolved_at=timestamp,
                    resolution_detail=redact_secrets(resolution_detail.strip())[:RESOLUTION_DETAIL_MAX_LENGTH],
                )
            _append_event_unlocked(state, _event("outbox.dead_lettered", item.id, timestamp, updated.to_dict()))
            return updated
        delay = min(max_backoff_seconds, base_backoff_seconds * (2 ** (failures - 1)))
        jitter_bound = max(1, delay // 10)
        if jitter is None:
            seed = hashlib.sha256(f"{item.id}:{failures}".encode()).digest()
            jitter_seconds = int.from_bytes(seed[:4], "big") % (jitter_bound + 1)
        else:
            jitter_seconds = jitter(jitter_bound)
        jitter_seconds = max(0, min(jitter_bound, int(jitter_seconds)))
        updated = replace(
            item,
            status="pending",
            failures=failures,
            updated_at=timestamp,
            next_attempt_at=_timestamp(current + timedelta(seconds=delay + jitter_seconds)),
            lease_owner="",
            lease_expires_at="",
            failure_detail=redact_secrets(detail),
        )
        _append_event_unlocked(state, _event("outbox.attempt.failed", item.id, timestamp, updated.to_dict()))
        return updated


def defer_lease(
    state: Path,
    *,
    outbox_id: str,
    worker: str,
    claim_attempts: int,
    now: datetime | None = None,
    delay_seconds: int = 1,
) -> OutboxItem:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    if delay_seconds < 1:
        raise ValueError("delay_seconds must be positive")
    current = now or datetime.now(timezone.utc)
    timestamp = _timestamp(current)
    with _locked_state(state):
        item = _leased_item(state, outbox_id, worker, current, claim_attempts=claim_attempts)
        updated = replace(
            item,
            status="pending",
            updated_at=timestamp,
            next_attempt_at=_timestamp(current + timedelta(seconds=delay_seconds)),
            lease_owner="",
            lease_expires_at="",
        )
        _append_event_unlocked(state, _event("outbox.deferred", item.id, timestamp, updated.to_dict()))
    return updated


def mark_delivered(
    state: Path,
    *,
    outbox_id: str,
    worker: str,
    claim_attempts: int,
    now: datetime | None = None,
    provider_receipt: str = "",
) -> OutboxItem:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    with _locked_state(state):
        current = now or datetime.now(timezone.utc)
        timestamp = _timestamp(current)
        receipt = redact_secrets(provider_receipt.strip())[:256]
        try:
            item = _leased_item(
                state, outbox_id, worker, current,
                claim_attempts=claim_attempts, allow_expired=True,
            )
        except ValueError:
            item = project_outbox(state).get(outbox_id)
            if (item is None or item.status != "ambiguous_delivery"
                    or item.payload.get("delivery_mode") not in HUMAN_FACING_MODES
                    or item.ambiguity_detail != SESSION_RETURN_EXPIRED_LEASE):
                raise
            _require_claim_attempt(item, claim_attempts)
            # A competing tick may have fenced the expired lease during I/O.
            # Only its original claimant may attach the late provider receipt;
            # this never clears ambiguity or authorizes another send.
            claim = next((event for event in reversed(read_events(state))
                          if event.type == "outbox.attempt.started" and event.task_id == item.id), None)
            if (claim is None or claim.payload.get("lease_owner") != worker
                    or claim.payload.get("attempts") != item.attempts):
                raise ValueError("late provider receipt is not from the original outbox claimant")
            if item.provider_receipt and receipt and item.provider_receipt != receipt:
                raise ValueError("late provider receipt conflicts with the recorded receipt")
            if receipt and not item.provider_receipt:
                item = replace(item, provider_receipt=receipt, updated_at=timestamp)
                _append_event_unlocked(
                    state, _event("outbox.dead_lettered", item.id, timestamp, item.to_dict())
                )
            return item
        if item.payload.get("delivery_mode") in HUMAN_FACING_MODES:
            # The provider call happened outside the state lock. Revalidate
            # authority here, atomically with finalization; an outbox lease alone
            # does not fence a terminal/reclaimed execution or a retargeted card.
            if item.payload.get("delivery_mode") == "session_return":
                from .session_return import classify_session_return_dispatch

                session_refusal = classify_session_return_dispatch(
                    state, execution_id=str(item.payload.get("execution_id", "")),
                    attempt_id=str(item.payload.get("attempt_id", "")),
                    target=item.target, now=current,
                )
                refusal_detail = session_refusal.detail if session_refusal else ""
            else:
                from .decisions import _classify_decision_card_dispatch_unlocked

                refusal_detail = _classify_decision_card_dispatch_unlocked(
                    state, decision_id=str(item.payload.get("decision_id", "")), target=item.target,
                ) or ""
            detail = (
                refusal_detail if refusal_detail else
                "provider accepted without a durable receipt" if not receipt else
                "outbox lease expired during provider acceptance"
                if _parse_rfc3339(item.lease_expires_at, label="lease_expires_at") <= current else ""
            )
            if detail:
                updated = replace(
                    item, status="ambiguous_delivery", updated_at=timestamp,
                    lease_owner="", lease_expires_at="", failure_detail="",
                    ambiguous_at=timestamp,
                    ambiguity_detail=redact_secrets(detail)[:RECEIPT_DETAIL_MAX_LENGTH],
                    provider_receipt=receipt,
                )
                # Backward-compatible event: old readers also keep this inert.
                _append_event_unlocked(
                    state, _event("outbox.dead_lettered", item.id, timestamp, updated.to_dict())
                )
                return updated
        elif _parse_rfc3339(item.lease_expires_at, label="lease_expires_at") <= current:
            raise ValueError(f"outbox item lease expired for {worker}: {outbox_id}")
        updated = replace(
            item,
            status="delivered",
            updated_at=timestamp,
            lease_owner="",
            lease_expires_at="",
            failure_detail="",
            delivered_at=timestamp,
            provider_receipt=redact_secrets(provider_receipt)[:256],
        )
        _append_event_unlocked(state, _event("outbox.delivered", item.id, timestamp, updated.to_dict()))
        return updated


def mark_delivery_ambiguous(
    state: Path,
    *,
    outbox_id: str,
    worker: str,
    claim_attempts: int,
    detail: str,
    now: datetime | None = None,
) -> OutboxItem:
    """Fence an external effect that cannot be proven either way.

    Automatic retry is forbidden because the provider may already have applied
    the effect. A later transition requires explicit reconciliation.
    """
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    current = now or datetime.now(timezone.utc)
    timestamp = _timestamp(current)
    safe_detail = redact_secrets(detail.strip())[:RECEIPT_DETAIL_MAX_LENGTH]
    if not safe_detail:
        raise ValueError("ambiguous delivery detail must not be empty")
    with _locked_state(state):
        item = _leased_item(
            state, outbox_id, worker, current,
            claim_attempts=claim_attempts, allow_expired=True,
        )
        updated = replace(
            item,
            status="ambiguous_delivery",
            updated_at=timestamp,
            lease_owner="",
            lease_expires_at="",
            failure_detail="",
            ambiguous_at=timestamp,
            ambiguity_detail=safe_detail,
        )
        _append_event_unlocked(
            state,
            # Use an event type understood by the previous reader. Its payload
            # status remains `ambiguous_delivery`, so rollback readers keep it
            # inert instead of reclaiming the last leased attempt.
            _event("outbox.dead_lettered", item.id, timestamp, updated.to_dict()),
        )
        return updated


def reconcile_ambiguous_delivery(
    state: Path,
    *,
    outbox_id: str,
    resolved_by: str,
    outcome: str,
    provider_receipt: str,
    detail: str = "",
    now: datetime | None = None,
) -> OutboxItem:
    """Resolve one ambiguous send from authoritative provider readback.

    ``unverifiable`` is for sends that predate provider receipts: the gateway accepted them but
    recorded no message id, so neither readback outcome can be proven. It is allowed only when
    the delivery's execution is already terminal (nothing downstream still waits on it) and a
    reason is given. It never claims delivery and never triggers a return continuation.
    """
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    resolved_by = resolved_by.strip()
    outcome = outcome.strip().casefold()
    receipt = redact_secrets(provider_receipt.strip())[:256]
    resolution_detail = redact_secrets(detail.strip())[:RESOLUTION_DETAIL_MAX_LENGTH]
    if not resolved_by:
        raise ValueError("ambiguous delivery reconciliation requires resolved_by")
    if outcome not in {"delivered", "not_delivered", "unverifiable"}:
        raise ValueError("ambiguous delivery outcome must be: delivered, not_delivered or unverifiable")
    if outcome == "unverifiable" and (receipt or not resolution_detail):
        raise ValueError("unverifiable reconciliation needs a reason and must not include a provider receipt")
    if outcome == "delivered" and not receipt:
        raise ValueError("delivered reconciliation requires a provider receipt")
    if outcome == "not_delivered" and receipt:
        raise ValueError("not-delivered reconciliation must not include a provider receipt")

    def stamp() -> str:
        # Sample per append, never on entry. This function reads the event log
        # before it writes anything, so a stamp taken on entry can predate the
        # source event that produced this write. With an injected clock the
        # stamp stays pinned exactly as before.
        return _timestamp(now)
    with _locked_state(state):
        item = project_outbox(state).get(outbox_id)
        if item is None:
            raise ValueError(f"unknown outbox item: {outbox_id}")
        expected_status = "delivered" if outcome == "delivered" else "dead_lettered"
        expected_category = f"ambiguous_{outcome}"
        if outcome == "unverifiable" and item.status == "ambiguous_delivery":
            execution_id = str(item.payload.get("execution_id", "")).strip()
            from .execution import project_executions

            execution = project_executions(state).get(execution_id) if execution_id else None
            if execution is None or execution.status not in {"completed", "closed", "cancelled"}:
                raise ValueError("unverifiable reconciliation requires the delivery's execution to be terminal")
        if item.status == expected_status and item.resolution_category == expected_category:
            if item.provider_receipt != receipt:
                raise ValueError("ambiguous delivery was reconciled with another provider receipt")
            updated = item
        elif item.status != "ambiguous_delivery":
            raise ValueError(f"outbox item is not ambiguous: {outbox_id}")
        else:
            if item.provider_receipt and (outcome != "delivered" or receipt != item.provider_receipt):
                raise ValueError("reconciliation must preserve the retained provider receipt")
            updated = replace(
                item,
                status=expected_status,
                updated_at=stamp(),
                delivered_at=stamp() if outcome == "delivered" else "",
                provider_receipt=receipt,
                resolution_category=expected_category,
                resolved_by=resolved_by,
                resolved_at=stamp(),
                resolution_detail=resolution_detail,
            )
            _append_event_unlocked(
                state,
                _event(
                    "outbox.delivered" if outcome == "delivered" else "outbox.dead_lettered",
                    item.id,
                    stamp(),
                    updated.to_dict(),
                ),
            )
    if outcome == "delivered" and updated.payload.get("delivery_mode") == "session_return":
        from .session_return import enqueue_session_return_continuation

        enqueue_session_return_continuation(state, updated, now=now or datetime.now(timezone.utc))
    return updated


def record_receipt(
    state: Path,
    *,
    outbox_id: str,
    actor: str,
    status: str,
    detail: str = "",
    now: datetime | None = None,
) -> OutboxItem:
    """Append an idempotent target-authored business lifecycle receipt."""
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    ranks = {"seen": 1, "accepted": 2, "completed": 3, "failed": 3}
    status = status.strip().lower()
    if status not in ranks:
        raise ValueError("receipt status must be one of: seen, accepted, completed, failed")
    if len(detail) > RECEIPT_DETAIL_MAX_LENGTH:
        raise ValueError(f"detail must not exceed {RECEIPT_DETAIL_MAX_LENGTH} characters")
    if detail and contains_literal_secret(detail):
        raise ValueError(
            "detail contains a secret-shaped string; store a "
            "secret://broker/path reference instead of the literal value"
        )

    def stamp() -> str:
        # Sample per append, never on entry. This function reads the event log
        # before it writes anything, so a stamp taken on entry can predate the
        # source event that produced this write. With an injected clock the
        # stamp stays pinned exactly as before.
        return _timestamp(now)
    with _locked_state(state):
        item = project_outbox(state).get(outbox_id)
        if item is None:
            raise ValueError(f"unknown outbox item: {outbox_id}")
        from .operator_archive import require_unarchived
        require_unarchived(state, item.subject_id)
        if item.status != "delivered":
            raise ValueError(f"outbox item is not delivered: {outbox_id}")
        from .control import same_agent_identity
        if not same_agent_identity(actor, item.target):
            raise ValueError(f"receipt actor does not match target: {actor}")
        if item.receipt_status == status:
            return item
        if item.receipt_status in {"completed", "failed"}:
            raise ValueError(f"receipt is already terminal: {outbox_id}")
        if item.receipt_status and ranks[status] < ranks[item.receipt_status]:
            raise ValueError(f"receipt status cannot regress: {item.receipt_status} -> {status}")
        updated = replace(
            item,
            updated_at=stamp(),
            receipt_status=status,
            receipt_by=actor,
            receipt_at=stamp(),
            receipt_detail=redact_secrets(detail),
        )
        _append_event_unlocked(state, _event("outbox.receipt", item.id, stamp(), updated.to_dict()))
        return updated


def cancel_unroutable(
    state: Path,
    *,
    outbox_id: str,
    configured_targets: set[str],
    reason_category: str,
    now: datetime | None = None,
) -> OutboxItem:
    """Cancel active legacy work that cannot be routed by current configuration."""
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    if reason_category != "unroutable_target":
        raise ValueError("reason_category must be: unroutable_target")

    def stamp() -> str:
        # Sample per append, never on entry. This function reads the event log
        # before it writes anything, so a stamp taken on entry can predate the
        # source event that produced this write. With an injected clock the
        # stamp stays pinned exactly as before.
        return _timestamp(now)
    with _locked_state(state):
        item = project_outbox(state).get(outbox_id)
        if item is None:
            raise ValueError(f"unknown outbox item: {outbox_id}")
        if item.status == "cancelled":
            if item.cancellation_reason_category != reason_category:
                raise ValueError(f"outbox item is already cancelled: {outbox_id}")
            return item
        if item.status not in {"pending", "leased"}:
            raise ValueError(f"outbox item cannot be cancelled from status {item.status}: {outbox_id}")
        if item.target in configured_targets:
            raise ValueError(f"outbox item target is currently routable: {outbox_id}")
        updated = replace(
            item,
            status="cancelled",
            updated_at=stamp(),
            lease_owner="",
            lease_expires_at="",
            failure_detail="",
            cancellation_reason_category=reason_category,
            cancelled_at=stamp(),
        )
        _append_event_unlocked(state, _event("outbox.cancelled", item.id, stamp(), updated.to_dict()))
        return updated


def resolve_dead_letter(
    state: Path,
    *,
    outbox_id: str,
    resolution_category: str,
    resolved_by: str,
    detail: str = "",
    now: datetime | None = None,
) -> OutboxItem:
    """Classify a dead letter append-only instead of leaving it unresolvable.

    The record keeps its dead_lettered status and full failure evidence; the
    resolution marks it as classified so delivery health stops counting it as
    actionable. Idempotent for the same category; a different category is
    refused rather than silently rewritten - reclassification is a new
    operator decision that should be visible as an explicit conflict.
    """
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    resolution_category = resolution_category.strip()
    resolved_by = resolved_by.strip() or "operator"
    detail = redact_secrets(detail.strip())[:RESOLUTION_DETAIL_MAX_LENGTH]
    if resolution_category not in RESOLUTION_CATEGORIES:
        raise ValueError(
            "resolution_category must be one of: " + ", ".join(sorted(RESOLUTION_CATEGORIES))
        )

    def stamp() -> str:
        # Sample per append, never on entry. This function reads the event log
        # before it writes anything, so a stamp taken on entry can predate the
        # source event that produced this write. With an injected clock the
        # stamp stays pinned exactly as before.
        return _timestamp(now)
    with _locked_state(state):
        item = project_outbox(state).get(outbox_id)
        if item is None:
            raise ValueError(f"unknown outbox item: {outbox_id}")
        if item.status != "dead_lettered":
            raise ValueError(f"outbox item is not dead-lettered: {outbox_id}")
        prior_resolution_category = ""
        preserved_detail = detail
        if item.resolution_category:
            if item.resolution_category == resolution_category:
                return item
            if item.resolution_category not in RECLASSIFIABLE_RESOLUTION_CATEGORIES:
                raise ValueError(
                    f"outbox item is already resolved as {item.resolution_category}: {outbox_id}"
                )
            # A recorded ambiguity is replaced by the operator's terminal
            # decision; the replaced category stays on the record so the
            # append-only history shows both.
            prior_resolution_category = item.resolution_category
            if not detail:
                # An empty note must not erase the classification that produced
                # the ambiguity; the earlier detail stays on the record.
                preserved_detail = item.resolution_detail
        updated = replace(
            item,
            updated_at=stamp(),
            resolution_category=resolution_category,
            resolved_by=resolved_by,
            resolved_at=stamp(),
            resolution_detail=preserved_detail,
            prior_resolution_category=prior_resolution_category,
        )
        _append_event_unlocked(state, _event("outbox.resolved", item.id, stamp(), updated.to_dict()))
        return updated


def _orphan_wake_verdict(
    state: Path, item: OutboxItem, *, current: datetime, cache: dict[str, object]
) -> str:
    """Settle a leased execution-wake record the worker never finalized.

    Returns ``delivered`` when the target posted an identity-bound heartbeat
    on the record's exact fenced attempt (the wake evidently arrived),
    ``live`` while that attempt is still the execution's live leased attempt
    (e.g. inside its first-heartbeat window), and ``superseded`` once the
    record's lease has expired and its attempt is no longer live. The event
    log is read at most once per dispatcher pass and only when such a record
    exists.
    """
    execution_id = str(item.payload.get("execution_id", ""))
    attempt_id = str(item.payload.get("attempt_id", ""))
    if "events" not in cache:
        from .execution import project_executions

        events = read_events(state)
        heartbeats: set[tuple[str, str]] = set()
        for event in events:
            if event.type != "execution.heartbeat":
                continue
            payload = event.payload if isinstance(event.payload, dict) else {}
            if payload.get("actor_identity_bound") is True and payload.get("heartbeat_by"):
                heartbeats.add((event.task_id, str(payload.get("attempt_id", ""))))
        cache["events"] = True
        cache["heartbeats"] = heartbeats
        cache["executions"] = project_executions(state, events=events)
    heartbeats = cache["heartbeats"]
    executions = cache["executions"]
    if execution_id and attempt_id and (execution_id, attempt_id) in heartbeats:  # type: ignore[operator]
        return "delivered"
    expires = _try_parse_rfc3339(item.lease_expires_at)
    if expires is not None and expires > current:
        return "live"
    execution = executions.get(execution_id)  # type: ignore[union-attr]
    if execution is not None and execution.status == "leased" and execution.attempt_id == attempt_id:
        execution_expires = _try_parse_rfc3339(execution.lease_expires_at)
        if execution_expires is not None and execution_expires > current:
            return "live"
    return "superseded"


def _classified_execution_wake_failure(item: OutboxItem, *, timestamp: str, detail: str) -> OutboxItem:
    """A failed execution wake is superseded by its execution lineage.

    The execution (not the wake record) is the operator-visible unit: a
    rejected or unfinalized wake requeues the execution under a new fenced
    attempt with its own wake record, or ends in the execution's own
    dead-letter/HOLD. The record therefore dead-letters already classified so
    delivery health never demands a replay that could only re-wake a stale
    attempt.
    """
    return replace(
        item,
        status="dead_lettered",
        failures=item.failures + 1,
        updated_at=timestamp,
        lease_owner="",
        lease_expires_at="",
        failure_detail=redact_secrets(detail)[:RECEIPT_DETAIL_MAX_LENGTH],
        resolution_category="superseded",
        resolved_by=EXECUTION_WAKE_RESOLVER,
        resolved_at=timestamp,
        resolution_detail=(
            "execution wakes are redelivered only by the execution lineage under a new fenced attempt; "
            f"see execution {item.payload.get('execution_id', '')}"
        ),
    )


def record_execution_wake_unlocked(state: Path, item: OutboxItem) -> OutboxItem:
    """Persist an execution wake's delivery record before the wake is sent.

    The caller holds the state lock and has already verified the fenced
    attempt is live. Idempotent per delivery ID: a duplicate wake for the same
    attempt reuses the existing record.
    """
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    if item.payload.get("delivery_mode") != EXECUTION_WAKE_MODE or item.status != "leased":
        raise ValueError("execution wake records must be leased execution-mode deliveries")
    existing = project_outbox(state).get(item.id)
    if existing is not None:
        return existing
    _append_event_unlocked(state, _event("outbox.enqueued", item.id, item.updated_at, item.to_dict()))
    return item


def finalize_execution_wake(
    state: Path,
    *,
    outbox_id: str,
    worker: str,
    claim_attempts: int,
    accepted: bool,
    detail: str,
    now: datetime | None = None,
) -> OutboxItem | None:
    """Record the transport outcome of an execution wake the worker just sent.

    Only a record still leased by its worker moves; a duplicate wake for an
    already finalized attempt never regresses the record.
    """

    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    def stamp() -> str:
        # Sample per append, never on entry. This function reads the event log
        # before it writes anything, so a stamp taken on entry can predate the
        # source event that produced this write. With an injected clock the
        # stamp stays pinned exactly as before.
        return _timestamp(now)
    with _locked_state(state):
        item = project_outbox(state).get(outbox_id)
        if item is None or item.status != "leased" or item.payload.get("delivery_mode") != EXECUTION_WAKE_MODE:
            return item
        _require_claim_attempt(item, claim_attempts)
        if item.lease_owner != worker:
            raise ValueError(f"outbox item is not leased by {worker}: {outbox_id}")
        if accepted:
            updated = replace(
                item,
                status="delivered",
                updated_at=stamp(),
                lease_owner="",
                lease_expires_at="",
                failure_detail="",
                delivered_at=stamp(),
            )
            _append_event_unlocked(state, _event("outbox.delivered", item.id, stamp(), updated.to_dict()))
            return updated
        updated = _classified_execution_wake_failure(item, timestamp=stamp(), detail=detail)
        _append_event_unlocked(state, _event("outbox.dead_lettered", item.id, stamp(), updated.to_dict()))
        return updated


def replay(state: Path, *, outbox_id: str, now: datetime | None = None) -> OutboxItem:

    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    def stamp() -> str:
        # Sample per append, never on entry. This function reads the event log
        # before it writes anything, so a stamp taken on entry can predate the
        # source event that produced this write. With an injected clock the
        # stamp stays pinned exactly as before.
        return _timestamp(now)
    with _locked_state(state):
        original = project_outbox(state).get(outbox_id)
        if original is None:
            raise ValueError(f"unknown outbox item: {outbox_id}")
        from .operator_archive import require_unarchived
        require_unarchived(state, original.subject_id)
        if original.status != "dead_lettered":
            raise ValueError(f"outbox item is not dead-lettered: {outbox_id}")
        if original.payload.get("delivery_mode") == EXECUTION_WAKE_MODE:
            raise ValueError(
                "execution wakes are redelivered only by the execution lineage; "
                f"replay the execution instead: {original.payload.get('execution_id', '')}"
            )
        if original.payload.get("delivery_mode") == "session_return":
            from .session_return import session_return_dispatch_error

            stale = session_return_dispatch_error(
                state,
                execution_id=str(original.payload.get("execution_id", "")),
                attempt_id=str(original.payload.get("attempt_id", "")),
                target=original.target,
                now=now,
            )
            if stale:
                raise ValueError(
                    f"session return replay refused: {stale}; a replay would dead-letter at the same "
                    "dispatch gate - the live attempt of the owning execution must request its own return"
                )
        epoch = original.epoch + 1
        identity = _identity(original.subject_id, original.target, original.payload_hash, epoch)
        for item in project_outbox(state).values():
            if _identity(item.subject_id, item.target, item.payload_hash, item.epoch) == identity:
                return item
        replayed = OutboxItem(
            id=f"outbox_{identity[:24]}",
            subject_id=original.subject_id,
            target=original.target,
            payload=original.payload,
            payload_hash=original.payload_hash,
            epoch=epoch,
            status="pending",
            attempts=0,
            created_at=stamp(),
            updated_at=stamp(),
            next_attempt_at=stamp(),
        )
        _append_event_unlocked(state, _event("outbox.replayed", replayed.id, stamp(), replayed.to_dict()))
        return replayed


TICK_HEARTBEAT_SECONDS = 180
_TICK_TAIL_BYTES = 262144


def _tick_comparison_fields(payload: Mapping[str, object]) -> tuple[object, ...]:
    """The parts of a tick record that must never lag behind reality.

    The record is a snapshot, not a delta, so a coalesced quiet cycle keeps the
    values it did not restate. Anything a consumer reads to decide freshness —
    the route attestation the cancel gate compares, the configured target set,
    the health flag, the skip and materialization state — therefore counts as a
    change worth writing, independently of the heartbeat.
    """
    targets = payload.get("configured_targets")
    skipped_unconfigured = payload.get("skipped_unconfigured_targets")
    skipped_human = payload.get("skipped_intentional_human_targets")
    return (
        bool(payload.get("healthy")),
        tuple(sorted(str(target) for target in targets)) if isinstance(targets, (list, tuple)) else (),
        str(payload.get("route_revision", "")),
        str(payload.get("route_sha256", "")),
        bool(payload.get("materialization_remaining")),
        tuple(sorted(str(t) for t in skipped_unconfigured)) if isinstance(skipped_unconfigured, (list, tuple)) else (),
        tuple(sorted(str(t) for t in skipped_human)) if isinstance(skipped_human, (list, tuple)) else (),
    )


def last_dispatcher_tick_record(state: Path, *, tail_bytes: int = _TICK_TAIL_BYTES) -> dict[str, object]:
    """The newest dispatcher tick (timestamp + payload), read from the log tail first.

    Deciding whether to append a 358-byte tick would otherwise cost a full scan of
    an append-only log that grows by megabytes a day. The newest tick is always
    inside the tail in practice; when it is not, fall back to the projection.
    """
    try:
        with open(state, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            start = max(0, size - tail_bytes)
            handle.seek(start)
            chunk = handle.read()
    except OSError:
        return {}
    lines = chunk.decode("utf-8", "ignore").splitlines()
    if start:
        # The first line of the window can be a partial record.
        lines = lines[1:]
    for line in reversed(lines):
        if DISPATCHER_TICK_EVENT not in line:
            continue
        try:
            event = json.loads(line)
        except (ValueError, TypeError):
            continue
        # The substring above is only a cheap prefilter; the event type must match
        # exactly or another event that merely mentions the name would be read as
        # a tick and hand back its own timestamp.
        if str(event.get("type", "")) != DISPATCHER_TICK_EVENT:
            continue
        payload = event.get("payload")
        return {
            "timestamp": str(event.get("timestamp", "")),
            "payload": dict(payload) if isinstance(payload, dict) else {},
        }
    if start:
        projected = project_dispatcher_tick(state)
        return {"timestamp": str(projected.get("last_tick_at", "")), "payload": projected}
    return {}


def last_dispatcher_tick_timestamp(state: Path, *, tail_bytes: int = _TICK_TAIL_BYTES) -> str:
    return str(last_dispatcher_tick_record(state, tail_bytes=tail_bytes).get("timestamp", ""))


def _timestamp_age_seconds(now: datetime, stamp: str) -> float | None:
    if not stamp:
        return None
    try:
        parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return (now.astimezone(timezone.utc) - parsed.astimezone(timezone.utc)).total_seconds()


def should_record_dispatcher_tick(
    state: Path,
    *,
    has_work: bool,
    now: datetime,
    snapshot: Mapping[str, object] | None = None,
    heartbeat_seconds: int = TICK_HEARTBEAT_SECONDS,
) -> bool:
    """A tick that did something is always recorded; a no-op tick only on the heartbeat.

    The tick record is the dispatcher's liveness authority: `/deliveries/health`
    marks the dispatcher stale past its own window (300 seconds by default) and the
    delivery-cancel gate refuses a tick older than 300 seconds, so the heartbeat is
    bounded well below both. Coalescing removes liveness noise, never a state
    change: every result that differs from "nothing happened" is written.

    `snapshot` is the record this cycle would write. When it differs from the last
    written record in anything a consumer reads, it is written immediately: a
    coalesced cycle must not leave a stale route attestation, target set, or health
    flag standing for up to the heartbeat.
    """
    if has_work:
        return True
    previous = last_dispatcher_tick_record(state)
    age = _timestamp_age_seconds(now, str(previous.get("timestamp", "")))
    if age is None:
        return True
    if snapshot is not None:
        recorded = previous.get("payload")
        if _tick_comparison_fields(snapshot) != _tick_comparison_fields(
            recorded if isinstance(recorded, Mapping) else {}
        ):
            return True
    return age >= heartbeat_seconds


def record_dispatcher_tick(
    state: Path,
    *,
    configured_targets: set[str],
    healthy: bool = True,
    materialization_remaining: bool = False,
    skipped_unconfigured_targets: tuple[str, ...] = (),
    skipped_intentional_human_targets: tuple[str, ...] = (),
    route_revision: str = "",
    route_sha256: str = "",
    now: datetime | None = None,
) -> dict[str, object]:
    """Persist a secret-safe dispatcher heartbeat, routable target names, and
    the loaded route-document attestation (empty when the document is
    unversioned)."""
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    timestamp = _timestamp(now)
    payload: dict[str, object] = {
        "configured_targets": sorted(configured_targets),
        "healthy": healthy,
        "materialization_remaining": materialization_remaining,
        "skipped_unconfigured_targets": sorted(set(skipped_unconfigured_targets)),
        "skipped_intentional_human_targets": sorted(set(skipped_intentional_human_targets)),
        "route_revision": route_revision,
        "route_sha256": route_sha256,
    }
    with _locked_state(state):
        _append_event_unlocked(state, _event(DISPATCHER_TICK_EVENT, "outbox_dispatcher", timestamp, payload))
    return {"initialized": True, "last_tick_at": timestamp, **payload}


def _empty_dispatcher_tick() -> dict[str, object]:
    return {
        "initialized": False,
        "last_tick_at": "",
        "configured_targets": [],
        "healthy": False,
        "materialization_remaining": False,
        "skipped_unconfigured_targets": [],
        "skipped_intentional_human_targets": [],
        "route_revision": "",
        "route_sha256": "",
    }


DISPATCHER_TICK_FIELDS = frozenset(_empty_dispatcher_tick())


def _project_dispatcher_tick_state(
    tick: dict[str, object], events: Sequence[ControlEvent]
) -> dict[str, object]:
    for event in events:
        if event.type != DISPATCHER_TICK_EVENT:
            continue
        payload = event.payload
        targets = payload.get("configured_targets")
        if not isinstance(targets, list) or not all(isinstance(target, str) and target for target in targets):
            raise ValueError("dispatcher tick is malformed")
        healthy = payload.get("healthy")
        remaining = payload.get("materialization_remaining")
        skipped_unconfigured = payload.get("skipped_unconfigured_targets", [])
        skipped_human = payload.get("skipped_intentional_human_targets", [])
        if not isinstance(healthy, bool) or not isinstance(remaining, bool):
            raise ValueError("dispatcher tick health is malformed")
        if not all(
            isinstance(values, list) and all(isinstance(target, str) and target for target in values)
            for values in (skipped_unconfigured, skipped_human)
        ):
            raise ValueError("dispatcher tick skip attention is malformed")
        # Pre-versioning ticks legitimately omit the attestation fields.
        route_revision = payload.get("route_revision", "")
        route_sha256 = payload.get("route_sha256", "")
        if not isinstance(route_revision, str) or not isinstance(route_sha256, str):
            raise ValueError("dispatcher tick route attestation is malformed")
        if route_sha256 and (
            len(route_sha256) != 64 or any(char not in "0123456789abcdef" for char in route_sha256)
        ):
            raise ValueError("dispatcher tick route attestation is malformed")
        tick = {
            "initialized": True,
            "last_tick_at": event.timestamp,
            "configured_targets": sorted(set(targets)),
            "healthy": healthy,
            "materialization_remaining": remaining,
            "skipped_unconfigured_targets": sorted(set(skipped_unconfigured)),
            "skipped_intentional_human_targets": sorted(set(skipped_human)),
            "route_revision": route_revision,
            "route_sha256": route_sha256,
        }
    return tick


def _dispatcher_tick_seed(events: Sequence[ControlEvent]) -> dict[str, object]:
    return {"tick": _project_dispatcher_tick_state(_empty_dispatcher_tick(), events)}


def _dispatcher_tick_seed_state(seed: object) -> dict[str, object]:
    if not isinstance(seed, dict) or set(seed) != {"tick"}:
        raise ValueError("dispatcher tick seed is malformed")
    tick = seed["tick"]
    if not isinstance(tick, dict) or set(tick) != DISPATCHER_TICK_FIELDS:
        raise ValueError("dispatcher tick seed is malformed")
    if not isinstance(tick["initialized"], bool) or not isinstance(tick["healthy"], bool):
        raise ValueError("dispatcher tick seed is malformed")
    if not isinstance(tick["materialization_remaining"], bool):
        raise ValueError("dispatcher tick seed is malformed")
    for field in ("last_tick_at", "route_revision", "route_sha256"):
        if not isinstance(tick[field], str):
            raise ValueError("dispatcher tick seed is malformed")
    for field in ("configured_targets", "skipped_unconfigured_targets", "skipped_intentional_human_targets"):
        values = tick[field]
        if not isinstance(values, list) or not all(isinstance(value, str) and value for value in values):
            raise ValueError("dispatcher tick seed is malformed")
    return dict(tick)


def project_dispatcher_tick(state: Path) -> dict[str, object]:
    seed, events, source = projection_cache.projection_source(state, "dispatcher_tick")
    tick = (
        _dispatcher_tick_seed_state(seed)
        if source == "checkpoint"
        else _empty_dispatcher_tick()
    )
    return _project_dispatcher_tick_state(tick, events)


def _normalize_materialization_target(value: object) -> str:
    return str(value).strip().casefold()


def assignment_notice_for_delivery(state: Path, item: OutboxItem) -> OutboxItem:
    """Restrict previously queued assignment wakes at the transport boundary.

    The immutable historical outbox identity and audit payload stay intact.
    Only the transport's instructions become informational; this cannot grant
    an execution lease or authorize starting work.
    """
    if (item.payload.get("delivery_mode", "direct") != "direct"
            or item.payload.get("source_event_type") not in {"thread.created", "handoff.created"}):
        return item
    from .execution import execution_assignment_sources
    assignment = execution_assignment_sources(read_events(state)).get(str(item.payload.get("source_event_id", "")))
    if assignment is None or assignment[1] != item.target.strip().casefold():
        return item
    return replace(item, payload={**item.payload, "delivery_mode": "notification", "execution_managed": True})


def _materialize_source_events_unlocked(
    state: Path,
    items: dict[str, OutboxItem],
    *,
    deliver_after: datetime,
    checkpoint: str | None,
    now: datetime,
    quarantined: list[str] | None = None,
    limit: int,
    dry_run: bool,
    target_allowlist: set[str] | None,
    intentional_human_targets: set[str],
    skip_report: dict[str, object] | None = None,
) -> tuple[int, bool]:
    """Derive a bounded batch and advance an append-only source cursor."""

    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    def stamp() -> str:
        # Sample per append, not on entry: this function reads the whole event log
        # before it writes anything, so an entry-time stamp can predate the source
        # event that produced the item. With an injected clock it stays pinned.
        return _timestamp(now)

    target_fields = {
        "task.created": ("owner",),
        "handoff.created": ("to_agent",),
        "handoff.reviewed": ("from_agent",),
        "handoff.completed": ("from_agent",),
        "thread.created": ("target",),
        "thread.done": ("actor",),
        "execution.session_return.requested": ("target",),
    }
    causing_actor_fields = {
        "task.created": "created_by",
        "handoff.created": "from_agent",
        "handoff.reviewed": "reviewer",
        "handoff.completed": "completed_by",
        "thread.created": "actor",
        "thread.done": "done_by",
        "execution.session_return.requested": "",
    }
    assert set(target_fields) == set(causing_actor_fields)
    events = read_events(state)
    from .execution import execution_assignment_sources
    assignment_sources = execution_assignment_sources(events)
    start = 0
    if checkpoint is not None:
        positions = [index for index, event in enumerate(events) if event.id == checkpoint]
        if not positions:
            raise ValueError("materialization checkpoint source event is missing")
        start = positions[-1] + 1
    candidates: list[OutboxItem] = []
    # Source events are immutable. Index original materializations once so
    # revisiting the suffix behind a missing route does not rebuild/hash every
    # already-queued payload (including large session-return messages).
    materialized_sources = {
        (str(item.payload.get("source_event_id", "")), item.target)
        for item in items.values()
        if item.epoch == 0 and item.payload.get("schema") == "v2.agent-delivery/1"
    }
    skipped: dict[str, dict[str, int]] = {
        "intentional_human": {},
        "unconfigured_route": {},
        "obsolete_author": {},
    }
    blocked_unconfigured: set[str] = set()
    obsolete_author_source_ids: list[str] = []
    last_processed_id: str | None = None
    remaining = False
    from .operator_archive import archived_ids
    archived = archived_ids(events)
    for event in events[start:]:
        if event.task_id in archived:
            if not blocked_unconfigured:
                last_processed_id = event.id
            continue
        fields = target_fields.get(event.type)
        if fields is None:
            if not blocked_unconfigured and not event.type.startswith("outbox."):
                last_processed_id = event.id
            continue
        event_time = _try_parse_rfc3339(event.timestamp)
        if event_time is None:
            if quarantined is not None:
                quarantined.append(f"source:{event.id}")
            if not blocked_unconfigured:
                last_processed_id = event.id
            continue
        if checkpoint is None and event_time <= deliver_after:
            if not blocked_unconfigured:
                last_processed_id = event.id
            continue
        targets = {_normalize_materialization_target(event.payload.get(field, "")) for field in fields}
        is_broadcast = (
            "all" in targets
            and event.type == "thread.created"
            and str(event.payload.get("type", "")).strip().lower() in {"status", "update"}
        )
        if event.type == "execution.session_return.requested":
            delivery_mode = "session_return"
        elif event.id in assignment_sources:
            delivery_mode = "notification"
        elif event.type in {"handoff.reviewed", "handoff.completed", "thread.done"}:
            delivery_mode = "notification"
        elif is_broadcast:
            delivery_mode = "broadcast"
        else:
            delivery_mode = "direct"
        if is_broadcast and target_allowlist is not None:
            targets = (targets - {"all"}) | target_allowlist
        causing_actor = _normalize_materialization_target(event.payload.get(causing_actor_fields[event.type], ""))
        eligible_targets = {target for target in targets if target and target != causing_actor}
        event_skipped: dict[str, list[str]] = {
            "intentional_human": [],
            "unconfigured_route": [],
            "obsolete_author": [],
        }
        for target in eligible_targets:
            # Atlas was a historical default author, not a deployed agent.
            # Only retire the inferred completion notification: explicit
            # assignments and every other unknown identity still fail closed.
            if event.type == "thread.done" and target == "atlas":
                event_skipped["obsolete_author"].append(target)
            elif target in intentional_human_targets and (
                target_allowlist is None or target not in target_allowlist
            ):
                event_skipped["intentional_human"].append(target)
            elif target_allowlist is not None and target not in target_allowlist:
                event_skipped["unconfigured_route"].append(target)
        if event_skipped["unconfigured_route"]:
            blocked_unconfigured.update(event_skipped["unconfigured_route"])
            remaining = True
            # Keep the cursor before the missing route so restoration can
            # recover its source event, but do not starve unrelated targets.
            # Existing deterministic outbox IDs deduplicate look-ahead work.
            continue
        event_candidates: list[OutboxItem] = []
        skipped_targets = {
            target for event_targets in event_skipped.values() for target in event_targets
        }
        for target in sorted(
            target
            for target in targets
            if target
            and target != causing_actor
            and target not in skipped_targets
            and (target_allowlist is None or target in target_allowlist)
        ):
            if (event.id, target) in materialized_sources:
                continue
            payload: dict[str, object] = {
                "schema": "v2.agent-delivery/1",
                "source_event_id": event.id,
                "source_event_type": event.type,
                "subject_id": event.task_id,
            }
            if event.type == "thread.created":
                completion_artifact = str(event.payload.get("completion_artifact", ""))
                completion_anchor = str(event.payload.get("completion_anchor", ""))
                if completion_artifact and completion_anchor:
                    payload["completion_artifact"] = completion_artifact
                    payload["completion_anchor"] = completion_anchor
            elif event.type == "thread.done":
                continuation_thread_id = str(event.payload.get("continuation_thread_id", "")).strip()
                if continuation_thread_id:
                    payload["continuation_thread_id"] = continuation_thread_id
            elif event.type == "execution.session_return.requested":
                for field in (
                    "execution_id", "attempt_id", "message", "message_sha256", "word_count",
                ):
                    payload[field] = event.payload[field]
            if delivery_mode != "direct":
                payload["delivery_mode"] = delivery_mode
            if event.id in assignment_sources:
                payload["execution_managed"] = True
            payload_hash = _payload_hash(payload)
            identity = _identity(event.task_id, target, payload_hash, 0)
            item_id = f"outbox_{identity[:24]}"
            if item_id in items:
                continue
            event_candidates.append(OutboxItem(
                id=item_id,
                subject_id=event.task_id,
                target=target,
                payload=payload,
                payload_hash=payload_hash,
                epoch=0,
                status="pending",
                attempts=0,
                created_at=event.timestamp,
                updated_at=stamp(),
                next_attempt_at=stamp(),
            ))
        if len(candidates) + len(event_candidates) > limit:
            # Persist a deterministic prefix, but leave the cursor before this
            # event. Existing IDs shrink its remaining fanout on the next tick.
            candidates.extend(event_candidates[:limit - len(candidates)])
            remaining = True
            break
        candidates.extend(event_candidates)
        if not blocked_unconfigured:
            # Only count skips covered by cursor advancement. Look-ahead will
            # revisit these events until the missing route is restored.
            if event_skipped["obsolete_author"]:
                obsolete_author_source_ids.append(event.id)
            for category, event_targets in event_skipped.items():
                for target in event_targets:
                    skipped[category][target] = skipped[category].get(target, 0) + 1
            last_processed_id = event.id
    if not dry_run:
        _append_events_unlocked(
            state,
            (_event("outbox.enqueued", item.id, stamp(), item.to_dict()) for item in candidates),
        )
        items.update((item.id, item) for item in candidates)
        for category, counts_by_target in skipped.items():
            if counts_by_target:
                _append_event_unlocked(
                    state,
                    _event(
                        MATERIALIZATION_SKIPPED_EVENT,
                        "outbox_materialization",
                        stamp(),
                        {
                            # Wire-compatible with strict pre-retirement readers:
                            # this identity has no supported route, not a human.
                            # Reason + exact IDs explain why this subset advances
                            # the cursor rather than pinning on route recovery.
                            "category": "unconfigured_route" if category == "obsolete_author" else category,
                            "counts_by_target": dict(sorted(counts_by_target.items())),
                            **({"reason": "obsolete_author", "source_event_ids": obsolete_author_source_ids} if category == "obsolete_author" else {}),
                        },
                    ),
                )
        if last_processed_id is not None and last_processed_id != checkpoint:
            _append_event_unlocked(
                state,
                _event(
                    MATERIALIZATION_CHECKPOINT_EVENT,
                    "outbox_materialization",
                    stamp(),
                    {"source_event_id": last_processed_id},
                ),
            )
    if skip_report is not None:
        intentional = tuple(sorted(skipped["intentional_human"]))
        unconfigured = tuple(sorted(set(skipped["unconfigured_route"]) | blocked_unconfigured))
        # These are current-pass results, not historical accumulators.
        for key, values in (
            ("skipped_intentional_human_targets", intentional),
            ("skipped_unconfigured_targets", unconfigured),
        ):
            skip_report.pop(key, None)
            if values:
                skip_report[key] = values
    return len(candidates), remaining


def project_materialization_skips(state: Path) -> dict[str, object]:
    """Project privacy-minimal append-only skip counts and target names."""
    counts: dict[str, int] = {}
    targets: dict[str, set[str]] = {}
    for event in read_events(state):
        if event.type != MATERIALIZATION_SKIPPED_EVENT:
            continue
        category = event.payload.get("category")
        by_target = event.payload.get("counts_by_target")
        if category not in {"intentional_human", "unconfigured_route"} or not isinstance(by_target, dict):
            raise ValueError("materialization skip event is malformed")
        for target, value in by_target.items():
            if not isinstance(target, str) or not target or not isinstance(value, int) or value < 1:
                raise ValueError("materialization skip event is malformed")
            counts[category] = counts.get(category, 0) + value
            targets.setdefault(category, set()).add(target)
    return {
        "counts": counts,
        "targets": {category: sorted(values) for category, values in targets.items()},
    }


def _empty_materialization_checkpoint() -> dict[str, object]:
    return {"initialized": False, "source_event_id": "", "advanced_at": ""}


MATERIALIZATION_CHECKPOINT_FIELDS = frozenset(_empty_materialization_checkpoint())


def _project_materialization_checkpoint_state(
    checkpoint: dict[str, object], events: Sequence[ControlEvent]
) -> dict[str, object]:
    for event in events:
        if event.type == MATERIALIZATION_CHECKPOINT_EVENT:
            source_event_id = event.payload.get("source_event_id")
            if not isinstance(source_event_id, str) or not source_event_id:
                raise ValueError("materialization checkpoint is malformed")
            checkpoint = {
                "initialized": True,
                "source_event_id": source_event_id,
                "advanced_at": event.timestamp,
            }
    return checkpoint


def _materialization_checkpoint_seed(events: Sequence[ControlEvent]) -> dict[str, object]:
    return {
        "checkpoint": _project_materialization_checkpoint_state(
            _empty_materialization_checkpoint(), events
        )
    }


def _materialization_checkpoint_seed_state(seed: object) -> dict[str, object]:
    if not isinstance(seed, dict) or set(seed) != {"checkpoint"}:
        raise ValueError("materialization checkpoint seed is malformed")
    checkpoint = seed["checkpoint"]
    if not isinstance(checkpoint, dict) or set(checkpoint) != MATERIALIZATION_CHECKPOINT_FIELDS:
        raise ValueError("materialization checkpoint seed is malformed")
    if not isinstance(checkpoint["initialized"], bool):
        raise ValueError("materialization checkpoint seed is malformed")
    for field in ("source_event_id", "advanced_at"):
        if not isinstance(checkpoint[field], str):
            raise ValueError("materialization checkpoint seed is malformed")
    if checkpoint["initialized"] and not checkpoint["source_event_id"]:
        raise ValueError("materialization checkpoint seed is malformed")
    return dict(checkpoint)


def project_materialization_checkpoint(state: Path) -> dict[str, object]:
    seed, events, source = projection_cache.projection_source(
        state, "materialization_checkpoint"
    )
    checkpoint = (
        _materialization_checkpoint_seed_state(seed)
        if source == "checkpoint"
        else _empty_materialization_checkpoint()
    )
    return _project_materialization_checkpoint_state(checkpoint, events)


def _materialization_checkpoint(state: Path) -> str | None:
    checkpoint = project_materialization_checkpoint(state)
    return str(checkpoint["source_event_id"]) if checkpoint["initialized"] else None


def _require_claim_attempt(item: OutboxItem, claim_attempts: int) -> None:
    # Pass the attempts value returned by claim_due, never a fresh projection.
    # Labels can be reused by another process; generations cannot be reused for
    # the same outbox ID, including across defer, failure, and expired leases.
    if (type(claim_attempts) is not int or claim_attempts < 1
            or item.attempts != claim_attempts):
        raise ValueError(f"outbox claim attempt does not match: {item.id}")


def _leased_item(
    state: Path,
    outbox_id: str,
    worker: str,
    now: datetime,
    *,
    claim_attempts: int,
    allow_expired: bool = False,
) -> OutboxItem:
    item = project_outbox(state).get(outbox_id)
    if item is None:
        raise ValueError(f"unknown outbox item: {outbox_id}")
    _require_claim_attempt(item, claim_attempts)
    if item.status != "leased" or item.lease_owner != worker:
        raise ValueError(f"outbox item is not leased by {worker}: {outbox_id}")
    if not allow_expired and _parse_rfc3339(item.lease_expires_at, label="lease_expires_at") <= now:
        raise ValueError(f"outbox item lease expired for {worker}: {outbox_id}")
    return item


def _project_outbox_state(
    items: dict[str, OutboxItem], events: Sequence[ControlEvent]
) -> dict[str, OutboxItem]:
    for event in events:
        if event.type not in OUTBOX_EVENT_TYPES:
            continue
        payload = event.payload
        previous = items.get(event.task_id)
        if "failures" in payload:
            failures = _coerce_nonnegative_int(payload.get("failures"))
        elif event.type in {"outbox.attempt.failed", "outbox.dead_lettered"}:
            failures = (previous.failures if previous else 0) + 1
        else:
            failures = previous.failures if previous else 0
        items[event.task_id] = OutboxItem(
            id=str(payload["id"]),
            subject_id=str(payload["subject_id"]),
            target=str(payload["target"]),
            payload=dict(payload["payload"]),
            payload_hash=str(payload["payload_hash"]),
            epoch=int(payload["epoch"]),
            status=str(payload["status"]),
            attempts=int(payload["attempts"]),
            created_at=str(payload["created_at"]),
            updated_at=str(payload["updated_at"]),
            next_attempt_at=str(payload["next_attempt_at"]),
            lease_owner=str(payload.get("lease_owner", "")),
            lease_expires_at=str(payload.get("lease_expires_at", "")),
            failures=failures,
            failure_detail=str(payload.get("failure_detail", "")),
            delivered_at=str(payload.get("delivered_at", "")),
            provider_receipt=str(payload.get("provider_receipt", "")),
            ambiguous_at=str(payload.get("ambiguous_at", "")),
            ambiguity_detail=str(payload.get("ambiguity_detail", "")),
            receipt_status=str(payload.get("receipt_status", "")),
            receipt_by=str(payload.get("receipt_by", "")),
            receipt_at=str(payload.get("receipt_at", "")),
            receipt_detail=str(payload.get("receipt_detail", "")),
            cancellation_reason_category=str(payload.get("cancellation_reason_category", "")),
            cancelled_at=str(payload.get("cancelled_at", "")),
            resolution_category=str(payload.get("resolution_category", "")),
            resolved_by=str(payload.get("resolved_by", "")),
            resolved_at=str(payload.get("resolved_at", "")),
            resolution_detail=str(payload.get("resolution_detail", "")),
            prior_resolution_category=str(payload.get("prior_resolution_category", "")),
            retirement=dict(payload.get("retirement", {})),
        )
    return items


OUTBOX_ITEM_FIELDS = frozenset(OutboxItem.__dataclass_fields__)
OUTBOX_SEED_INTEGER_FIELDS = ("epoch", "attempts", "failures")


def _outbox_seed(events: Sequence[ControlEvent]) -> dict[str, object]:
    items = _project_outbox_state({}, events)
    # Insertion order, not sorted order: the resumed projection must reproduce
    # the exact dict the full parse builds, because a few consumers break epoch
    # ties or take the first match in iteration order.
    return {"items": [item.to_dict() for item in items.values()]}


def _outbox_seed_items(seed: object) -> dict[str, OutboxItem]:
    if not isinstance(seed, dict) or set(seed) != {"items"}:
        raise ValueError("outbox seed is malformed")
    raw = seed["items"]
    if not isinstance(raw, list):
        raise ValueError("outbox seed is malformed")
    items: dict[str, OutboxItem] = {}
    for value in raw:
        if not isinstance(value, dict) or set(value) != OUTBOX_ITEM_FIELDS:
            raise ValueError("outbox seed entry is malformed")
        if not isinstance(value.get("payload"), dict) or not isinstance(value.get("retirement"), dict):
            raise ValueError("outbox seed entry is malformed")
        for field, field_value in value.items():
            if field in {"payload", "retirement"}:
                continue
            if field in OUTBOX_SEED_INTEGER_FIELDS:
                if isinstance(field_value, bool) or not isinstance(field_value, int) or field_value < 0:
                    raise ValueError("outbox seed entry is malformed")
            elif not isinstance(field_value, str):
                raise ValueError("outbox seed entry is malformed")
        item = OutboxItem(**value)  # type: ignore[arg-type]
        if not item.id or item.id != str(item.id):
            raise ValueError("outbox seed entry is malformed")
        items[item.id] = item
    return items


def _valid_outbox_seed(seed: object) -> bool:
    try:
        _outbox_seed_items(seed)
    except (TypeError, ValueError):
        return False
    return True


def project_outbox(state: Path) -> dict[str, OutboxItem]:
    seed, events, source = projection_cache.projection_source(state, "outbox")
    items = _outbox_seed_items(seed) if source == "checkpoint" else {}
    return _project_outbox_state(items, events)


def _coerce_nonnegative_int(value: object) -> int:
    try:
        parsed = int(str(value))
    except (TypeError, ValueError):
        return 0
    return max(0, parsed)


def _identity(subject_id: str, target: str, payload_hash: str, epoch: int) -> str:
    return hashlib.sha256(f"{subject_id}\0{target}\0{payload_hash}\0{epoch}".encode()).hexdigest()


def _payload_hash(payload: Mapping[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()


_RFC3339_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")


def _parse_rfc3339(value: str | None, *, label: str) -> datetime:
    text = value.strip() if isinstance(value, str) else ""
    if not _RFC3339_RE.fullmatch(text):
        raise ValueError(f"{label} must be a timezone-aware RFC3339 instant")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
    except ValueError as exc:
        raise ValueError(f"{label} must be a timezone-aware RFC3339 instant") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must be a timezone-aware RFC3339 instant")
    return parsed.astimezone(timezone.utc)


def _try_parse_rfc3339(value: str | None) -> datetime | None:
    try:
        return _parse_rfc3339(value, label="projected timestamp")
    except ValueError:
        return None


def _timestamp(value: datetime | None = None) -> str:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("outbox timestamps must be timezone-aware")
    return current.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _valid_dispatcher_tick_seed(seed: object) -> bool:
    try:
        _dispatcher_tick_seed_state(seed)
    except (TypeError, ValueError):
        return False
    return True


def _valid_materialization_checkpoint_seed(seed: object) -> bool:
    try:
        _materialization_checkpoint_seed_state(seed)
    except (TypeError, ValueError):
        return False
    return True


projection_cache.register_seed(
    "outbox", builder=_outbox_seed, validator=_valid_outbox_seed
)
projection_cache.register_seed(
    "dispatcher_tick",
    builder=_dispatcher_tick_seed,
    validator=_valid_dispatcher_tick_seed,
)
projection_cache.register_seed(
    "materialization_checkpoint",
    builder=_materialization_checkpoint_seed,
    validator=_valid_materialization_checkpoint_seed,
)
