"""Autonomous lifecycle watchdog.

Detects the four durable-autonomy gap classes and applies at most one bounded
remediation per subject per tick, with an explicit terminal HOLD when the
autonomous budget is exhausted:

1. target endpoint unavailable      -> observe, defer remediation (backoff)
2. wake accepted but no receipt     -> observe, surface for the operator
3. assignment without an execution -> materialize (idempotent) or replay a
                                       dead letter once, then HOLD; a HOLD the
                                       worker applied for repeated BLOCKED
                                       reports is escalated once as well
4. leased without a recent heartbeat-> observe; the worker's lease reclaim
                                       plus re-wake backoff is the remediation
                                       (an attempt inside its first-heartbeat
                                       window is starting, not stale)

The watchdog never posts a wake itself. Execution remediation uses the canonical
event formats under the state lock, conditional on the inspected revision.
A dedicated overlap lock serializes whole ticks on top of that.
"""

from __future__ import annotations

from .diagnostics import boundary, capture

from datetime import datetime, timezone
import json
import os
import socket
from pathlib import Path
from typing import Callable, Mapping
from urllib.parse import urlsplit

from .agent_delivery import AgentRoute, validate_agent_route
from .control import (
    _append_event_unlocked,
    _event,
    _locked_state,
    list_thread_inbox,
    post_thread,
    read_events,
)
from .execution import (
    BLOCKED_HOLD_REASON_PREFIX,
    EXECUTION_STATE_EVENT_TYPES,
    remediate_dead_letter,
    materialize_executions,
    project_executions,
    queue_health,
    reconcile_executions,
)
from .watchdog_alerts import hold_alert_body as _hold_alert_body
from .locks import exclusive_lock
from .decisions import DECISION_CARD_MODE, awaited_decisions, card_payload
from .auth import TOKEN_EXPIRY_WARN_DAYS, expiring_tokens
from .outbox import EXECUTION_WAKE_MODE, enqueue, project_outbox

WATCHDOG_TICK_EVENT = "execution.watchdog.tick"
# One autonomous replay per execution lineage. A second dead letter for the
# same execution is a systemic failure, not a transient: it holds for the
# operator instead of retrying forever.
MAX_AUTONOMOUS_REPLAYS = 1
DEFAULT_RECEIPT_STALE_SECONDS = 900
DEFAULT_HEARTBEAT_STALE_SECONDS = 300
DEFAULT_PROBE_TIMEOUT_SECONDS = 3.0
BOUNDED_LIST_LIMIT = 20
SESSION_RETURN_MODE = "session_return"
# Human-facing sends proven by the provider's native message id (the operator's chat).
_PROVIDER_RECEIPTED_MODES = frozenset({SESSION_RETURN_MODE, "decision_card"})
_RECEIPT_EXEMPT_WAKE_MODES = frozenset({EXECUTION_WAKE_MODE, "session_return_receipt"})
RECEIPT_WAIVER_EVENT = "outbox.receipt_waived"
#: An unchanged tick is not re-recorded more often than this. Watchdog ticks were
#: 40% of the control log's growth (one ~800 B event a minute, almost all identical);
#: a changed tick is always written at once, and this bounds the liveness signal.
WATCHDOG_TICK_HEARTBEAT_SECONDS = 600
#: The operator's rule (2026-09-25): nothing stays stale in AMC. Anything stuck this long is paged.
DEFAULT_STALE_ESCALATION_SECONDS = 2 * 3600
#: Health surfaces call the watchdog stale past three missed heartbeats.
WATCHDOG_TICK_STALE_SECONDS = 3 * WATCHDOG_TICK_HEARTBEAT_SECONDS


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="auto").replace("+00:00", "Z")


def _parse(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be text")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def _parse_aware(value: str) -> datetime:
    parsed = _parse(value)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def probe_route(
    route: AgentRoute,
    *,
    environ: Mapping[str, str] | None = None,
    timeout: float = DEFAULT_PROBE_TIMEOUT_SECONDS,
) -> tuple[bool, str]:
    """Secret-safe reachability check: config validation plus a bounded TCP
    connect. Never returns the URL or any resolved value."""
    config_error = validate_agent_route(route, environ=environ)
    if config_error is not None:
        return False, f"configuration: {config_error}"
    env = os.environ if environ is None else environ
    parsed = urlsplit(env[route.url_env].strip())
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    try:
        from .http_bounds import bounded_tcp_connection
        with bounded_tcp_connection((parsed.hostname, port), timeout=timeout):
            return True, "tcp-connect ok"
    except OSError as exc:
        capture(exc, component="watchdog", code="probe")
        return False, f"tcp-connect failed: {type(exc).__name__}"


def _escalation_title(execution_id: str) -> str:
    return f"[watchdog] execution {execution_id} held for operator"


def _is_watchdog_escalation(
    *, actor: object, target: object, identity_bound: object, worker: str,
    targets: frozenset[str] = frozenset({"operator"}),
) -> bool:
    """A thread counts as this watchdog's escalation only by provenance, never
    by title alone: posted by the watchdog worker identity, to an escalation
    target, and not through an identity-bound agent surface. Otherwise any agent
    could pre-post a same-title thread and silence the page for a HOLD that only
    the operator can clear."""
    return (
        str(actor or "").strip().casefold() == worker.strip().casefold()
        and str(target or "").strip().casefold() in targets
        and identity_bound is not True
    )


def _escalation_targets(escalation_target: str) -> frozenset[str]:
    # "operator" always counts, so escalations posted before a target change still dedupe.
    return frozenset({"operator", escalation_target.strip().casefold() or "operator"})


def _token_expiry_title(token: Mapping[str, object]) -> str:
    # ``post_thread`` stores the stripped title, so the dedupe key must be built the
    # same way: a value with stray whitespace would otherwise never match the stored
    # title and re-post the warning on every tick.
    return f"watchdog token expiry: {token['agent_id']}/{token['slot']} {str(token['expires_at']).strip()}".strip()


def _escalated_since_latest_hold(
    state: Path, execution_ids: set[str], *, worker: str, targets: frozenset[str] = frozenset({"operator"}),
) -> set[str]:
    """Executions whose latest ``execution.held`` already has an escalation
    thread appended after it. Log order, not wall-clock timestamps, decides,
    so an operator closing the escalation thread never triggers a re-post
    while the same HOLD stands, and a fresh HOLD after a replay escalates.
    Only threads with watchdog provenance count (see _is_watchdog_escalation)."""
    titles = {_escalation_title(execution_id): execution_id for execution_id in execution_ids}
    latest_hold: dict[str, int] = {}
    latest_escalation: dict[str, int] = {}
    for index, event in enumerate(read_events(state)):
        if event.type == "execution.held" and event.task_id in execution_ids:
            latest_hold[event.task_id] = index
        elif event.type == "thread.created":
            execution_id = titles.get(str(event.payload.get("title", "")))
            if execution_id is not None and _is_watchdog_escalation(
                actor=event.payload.get("actor"),
                target=event.payload.get("target"),
                identity_bound=event.payload.get("actor_identity_bound"),
                worker=worker,
                targets=targets,
            ):
                latest_escalation[execution_id] = index
    return {
        execution_id
        for execution_id, index in latest_escalation.items()
        if index > latest_hold.get(execution_id, -1)
    }


def _receiptless_delivered(items: object) -> list[object]:
    """Delivered items still owing the receipt their wake asked for (gap class 2)."""
    return [
        item
        for item in items  # type: ignore[attr-defined]
        if item.status == "delivered"
        and not item.receipt_status
        and item.payload.get("delivery_mode") not in _RECEIPT_EXEMPT_WAKE_MODES
        and not (
            item.payload.get("delivery_mode") in _PROVIDER_RECEIPTED_MODES
            and str(item.provider_receipt or "").strip()
        )
    ]


def project_watchdog_tick(state: Path) -> dict[str, object]:
    """Latest watchdog tick summary, for health surfaces."""
    latest, _waived = _scan_watchdog_state(state)
    latest.pop("signature", None)  # internal coalescing key, not a health field
    return latest


def _tick_signature(payload: Mapping[str, object]) -> str:
    """What makes a tick worth recording: attention, counts, per-target reachability
    (ok only — probe detail wording varies) and the receipt boundary."""
    reachability = payload.get("reachability")
    reach = (
        {str(target): bool(value.get("ok")) for target, value in reachability.items() if isinstance(value, dict)}
        if isinstance(reachability, dict) else {}
    )
    return json.dumps({
        "attention": payload.get("attention"), "counts": payload.get("counts"), "reachability": reach,
        "receipt_enforcement_since": payload.get("receipt_enforcement_since"),
    }, sort_keys=True, default=str)


def _scan_watchdog_state(state: Path) -> tuple[dict[str, object], set[str]]:
    """One pass: the latest tick summary plus every operator receipt waiver."""
    latest: dict[str, object] = {"initialized": False}
    receipt_enforcement_since = ""
    receipt_enforcement_boundary_invalid = False
    waived: set[str] = set()
    for event in read_events(state):
        if event.type == RECEIPT_WAIVER_EVENT:
            ids = event.payload.get("outbox_ids") if isinstance(event.payload, dict) else None
            if isinstance(ids, list):
                waived.update(str(value) for value in ids if isinstance(value, str) and value)
            continue
        if event.type != WATCHDOG_TICK_EVENT:
            continue
        payload = event.payload if isinstance(event.payload, dict) else {}
        raw_boundary = payload.get("receipt_enforcement_since")
        if not receipt_enforcement_since and isinstance(raw_boundary, str) and raw_boundary.strip():
            try:
                _parse_aware(raw_boundary)
            except ValueError:
                receipt_enforcement_boundary_invalid = True
            else:
                receipt_enforcement_since = raw_boundary
                receipt_enforcement_boundary_invalid = False
        latest = {
            "initialized": True,
            "last_tick_at": event.timestamp,
            "worker": str(payload.get("worker", "")),
            "attention": list(payload.get("attention", [])),
            "counts": dict(payload.get("counts", {})),
            "receipt_enforcement_since": receipt_enforcement_since,
            "receipt_enforcement_boundary_invalid": receipt_enforcement_boundary_invalid,
            "signature": _tick_signature(payload),
        }
    if latest.get("initialized"):
        latest["receipt_waived_count"] = len(waived)
    return latest, waived


def receipt_waiver_candidates(state: Path, *, before: datetime) -> list[dict[str, str]]:
    """Receiptless deliveries in the alarm set (the gap-class-2 set) delivered before ``before``.

    Items before the receipt-enforcement boundary are already baselined and never alarm, so
    they are not candidates: a waiver names only what the watchdog actually reports.
    """
    latest, waived = _scan_watchdog_state(state)
    boundary_raw = str(latest.get("receipt_enforcement_since") or "")
    boundary = _parse(boundary_raw) if boundary_raw else None
    rows = []
    for item in _receiptless_delivered(project_outbox(state).values()):
        delivered = _parse(item.delivered_at or item.updated_at)
        if item.id in waived or delivered >= before or (boundary is not None and delivered < boundary):
            continue
        rows.append({
            "outbox_id": item.id, "target": item.target,
            "delivery_mode": str(item.payload.get("delivery_mode") or "direct"),
            "delivered_at": item.delivered_at or item.updated_at,
        })
    return sorted(rows, key=lambda row: (row["delivered_at"], row["outbox_id"]))


def waive_receipts(state: Path, *, outbox_ids: list[str], reason: str, waived_by: str = "operator") -> dict[str, object]:
    """Operator acknowledgement that these deliveries will never get their receipt.

    Their receivers already missed the receipt the wake asked for (historical agent
    behaviour, not a live gap). A waiver moves them into the baselined count so the
    watchdog's attention reflects new gaps only; nothing about the deliveries changes
    and they stay counted. Every id must currently be in the gap set — waiving a
    receipted, pending or unknown delivery is refused, and nothing is appended.
    """
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    reason = reason.strip()
    if not reason:
        raise ValueError("a receipt waiver needs a reason")
    wanted = list(dict.fromkeys(value.strip() for value in outbox_ids if value.strip()))
    if not wanted:
        raise ValueError("a receipt waiver needs at least one outbox id")
    with _locked_state(state):
        _latest, waived = _scan_watchdog_state(state)
        gap = {item.id for item in _receiptless_delivered(project_outbox(state).values())}
        refused = [value for value in wanted if value not in gap or value in waived]
        if refused:
            raise ValueError(f"not a current receipt gap (or already waived): {', '.join(refused[:10])}")
        stamp = _timestamp(datetime.now(timezone.utc))
        payload = {"outbox_ids": wanted, "reason": reason, "waived_by": waived_by, "waived_at": stamp}
        _append_event_unlocked(state, _event(RECEIPT_WAIVER_EVENT, "watchdog", stamp, payload))
    return {"waived": len(wanted), "outbox_ids": wanted, "reason": reason}


@boundary("watchdog")
def run_watchdog(
    state: Path,
    *,
    routes: dict[str, AgentRoute],
    worker: str = "arvyx-watchdog",
    now: datetime | None = None,
    environ: Mapping[str, str] | None = None,
    probe: bool = False,
    receipt_stale_seconds: int = DEFAULT_RECEIPT_STALE_SECONDS,
    heartbeat_stale_seconds: int = DEFAULT_HEARTBEAT_STALE_SECONDS,
    escalate: bool = True,
    clock: Callable[[], datetime] | None = None,
    vault: Path | None = None,
    token_expiry_days: int = TOKEN_EXPIRY_WARN_DAYS,
    token_expiry_target: str = "operator",
    escalation_target: str = "operator",
    stale_escalation_seconds: int = DEFAULT_STALE_ESCALATION_SECONDS,
) -> dict[str, object]:
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    if not routes:
        raise ValueError("watchdog requires a non-empty validated route map")
    worker = worker.strip()
    if not worker:
        raise ValueError("watchdog worker identity must not be empty")
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError('watchdog clock must include a timezone')

    # A tick can run for a minute or more (probes, remediation). Events must be
    # stamped when they are appended, not when the tick started, or an event this
    # tick writes late can appear older than a cause another actor appended in
    # between — and the log's apparent order stops matching its real order. An
    # injected `now` (tests, drills) still pins every stamp for determinism.
    tick_clock = clock or (lambda: datetime.now(timezone.utc))

    def stamp() -> datetime:
        return now if now is not None else tick_clock()

    # Deliberate exception: the tick record itself (`timestamp`, below) keeps the
    # tick's reference time rather than the append time. The next tick derives its
    # receipt-enforcement boundary from that value, and an end-stamped record would
    # baseline deliveries that arrived *during* this tick, silently suppressing
    # gap-class-2 detection. The class is therefore eliminated for domain writes,
    # not for the tick record. Related known limitation: the escalation thread's
    # `thread.created` is stamped by `control.post_thread`, which takes no clock.

    timestamp = _timestamp(current)
    capable = set(routes)
    lock_path = state.parent / (state.name + ".watchdog.lock")

    with exclusive_lock(lock_path):
        previous_tick, receipt_waived = _scan_watchdog_state(state)
        boundary_invalid = bool(previous_tick.get("receipt_enforcement_boundary_invalid"))
        boundary_candidate = str(
            previous_tick.get("receipt_enforcement_since")
            or previous_tick.get("last_tick_at")
            or timestamp
        )
        try:
            receipt_enforcement_at = _parse_aware(boundary_candidate)
        except ValueError:
            boundary_invalid = True
            receipt_enforcement_since = "1970-01-01T00:00:00Z"
            receipt_enforcement_at = _parse_aware(receipt_enforcement_since)
        else:
            receipt_enforcement_since = boundary_candidate

        # Gap class 1: endpoint availability, secret-safe. Config validation is
        # always checked; TCP probing is opt-in because the watchdog must stay
        # useful in offline test and drill environments.
        reachability: dict[str, dict[str, object]] = {}
        for target, route in sorted(routes.items()):
            if probe:
                ok, detail = probe_route(route, environ=environ)
            else:
                config_error = validate_agent_route(route, environ=environ)
                ok = config_error is None
                detail = "configuration ok" if ok else f"configuration: {config_error}"
            reachability[target] = {"ok": ok, "detail": detail}

        # Gap class 3 remediation, part one: materialize any assignment that never
        # produced an execution and reconcile authoritative terminals. Both are
        # idempotent domain operations.
        materialized = materialize_executions(
            state, execution_capable_targets=capable, now=stamp()
        )
        reconciled = reconcile_executions(state, now=stamp())

        # Gap class 3 remediation, part two: bounded dead-letter replay.
        with _locked_state(state):
            snapshot_events = read_events(state)
            executions_before = project_executions(state, events=snapshot_events)
            revisions = {event.task_id: event.id for event in snapshot_events
                         if event.type in EXECUTION_STATE_EVENT_TYPES}
            replay_counts: dict[str, int] = {}
            for event in snapshot_events:
                if event.type == "execution.replayed":
                    replay_counts[event.task_id] = replay_counts.get(event.task_id, 0) + 1
        replayed: list[str] = []
        held: list[str] = []
        deferred_unreachable: list[str] = []
        for execution in sorted(
            executions_before.values(), key=lambda item: (item.created_at, item.id)
        ):
            if execution.status != "dead_lettered":
                continue
            reachable = bool(reachability.get(execution.target, {}).get("ok"))
            if not reachable and replay_counts.get(execution.id, 0) < MAX_AUTONOMOUS_REPLAYS:
                # Counts only grow: defer without a write. Exhausted snapshots
                # still use the atomic helper to HOLD while offline.
                deferred_unreachable.append(execution.id)
                continue
            outcome, _updated = remediate_dead_letter(
                state, execution.id, expected_event_id=revisions[execution.id],
                actor=worker, max_replays=MAX_AUTONOMOUS_REPLAYS,
                hold_reason=("autonomous replay budget exhausted after repeated dead letter; "
                             f"last failure: {execution.last_failure or 'unknown'}"),
                now=stamp(),
            )
            if outcome == "changed":
                # Recovery or terminal reconciliation won; skip only this subject.
                continue
            if outcome == "held":
                held.append(execution.id)
            elif outcome == "replayed":
                replayed.append(execution.id)

        # Decision cards: a parked execution whose card never got queued (a crash in
        # the window after the park and before the enqueue) would wait silently, since
        # the decision hold is deliberately not escalated. Re-queue it; the payload is
        # deterministic, so enqueue is idempotent. Flag decisions the operator left open > 24 h.
        decision_cards_restored: list[str] = []
        decisions_awaiting_long: list[str] = []
        outbox_snapshot = project_outbox(state)
        for decision in awaited_decisions(state):
            has_card = any(
                item.subject_id == decision.decision_id
                and item.payload.get("delivery_mode") == DECISION_CARD_MODE
                for item in outbox_snapshot.values()
            )
            if not has_card:
                enqueue(state, subject_id=decision.decision_id, target=decision.target,
                        payload=card_payload(decision), now=stamp())
                decision_cards_restored.append(decision.decision_id)
            elif decision.requested_at:
                try:
                    overdue = (current - _parse(decision.requested_at)).total_seconds() > 86400
                except ValueError:
                    overdue = True  # Invalid timing is attention, never health.
                if overdue:
                    decisions_awaiting_long.append(decision.decision_id)

        # Token expiry: every agent token carries a 30-day default, so a missed renewal
        # silently cuts an agent off AMC (Keeper's provider slot: 401 for six days).
        # Warn once per (agent, slot, expiry) — a renewal changes the expiry, so the next
        # cycle warns again. Only with a vault; metadata only, never a hash or value.
        tokens_expiring: list[dict[str, object]] = []
        token_expiry_error = ""
        if vault is not None:
            # The vault check is opt-in and secondary. A registry problem must surface
            # as attention on this tick, never abort it: losing the whole autonomy
            # watchdog (escalations, dead-letter replay, stale-work sweep) to one bad
            # token record is the strictly worse failure. The exception class is
            # reported by name so the fault stays diagnosable.
            try:
                tokens_expiring = expiring_tokens(vault, now=current, within_days=token_expiry_days)
            except Exception as exc:  # noqa: BLE001 — deliberate: the tick must survive
                capture(exc, component="watchdog", code="token_expiry")
                token_expiry_error = type(exc).__name__
        tokens_warned: list[str] = []
        if escalate and tokens_expiring:
            notify = token_expiry_target.strip() or "operator"
            # Any status counts: closing the warning thread must not re-post it for the
            # same expiry. Only this watchdog's own threads count.
            already = {
                thread.title
                for thread in list_thread_inbox(state=state, target=notify).threads
                if _is_watchdog_escalation(
                    actor=thread.actor, target=thread.target, identity_bound=thread.actor_identity_bound, worker=worker,
                    targets=frozenset({notify.casefold()}),
                )
            }
            for token in tokens_expiring:
                title = _token_expiry_title(token)
                if title in already:
                    continue
                state_word = "EXPIRED" if token["expired"] else "expires"
                post_thread(
                    state,
                    title=title,
                    body=(
                        f"AMC token {token['agent_id']}/{token['slot']} {state_word} at {token['expires_at']}. "
                        f"When it lapses that agent's calls to AMC fail with 401. Renew it with "
                        f"`arvyx auth renew {token['agent_id']} --slot {token['slot']}` (runbook: "
                        f"docs/runbooks/token-renewal.md) and tell the operator; revoke it instead if the slot is unused."
                    ),
                    thread_type="blocker" if token["expired"] else "ask",
                    actor=worker,
                    actor_identity_bound=False,
                    target=notify,
                    severity="warn",
                )
                tokens_warned.append(f"{token['agent_id']}/{token['slot']}")

        # Gap class 2: transport-accepted deliveries whose receiver never wrote
        # any receipt. Detection only; forging receipts or re-waking here would
        # re-enter the same broken path the report warns about.
        # Execution wakes are excluded: their receipt is the identity-bound
        # heartbeat and terminal on the execution itself, which gap class 4
        # and the HOLD path already cover. A session-return receipt wake is the
        # same kind of continuation wake: its evidence is the agent's terminal on
        # the subject, and a silent agent surfaces through the HOLD/assigned
        # classes. A human-facing session return carries its receipt as the
        # provider's native message id (finalization refuses `delivered` without
        # one), so a provider receipt satisfies it; one without a provider
        # receipt still alerts.
        receiptless_delivered = _receiptless_delivered(project_outbox(state).values())
        # An operator waiver (outbox.receipt_waived) baselines exactly the listed
        # deliveries: still counted, no longer attention.
        delivered_without_receipt_baselined = 0
        delivered_without_receipt = []
        for item in receiptless_delivered:
            if item.id in receipt_waived:
                delivered_without_receipt_baselined += 1
                continue
            try:
                delivered_at = _parse(item.delivered_at or item.updated_at)
            except ValueError:
                delivered_without_receipt.append(item.id)
                continue
            if delivered_at < receipt_enforcement_at:
                delivered_without_receipt_baselined += 1
            elif (current - delivered_at).total_seconds() >= receipt_stale_seconds:
                delivered_without_receipt.append(item.id)
        delivered_without_receipt.sort()

        # Gap class 4 plus queue posture after remediation.
        health = queue_health(
            state,
            execution_capable_targets=capable,
            now=stamp(),
            heartbeat_stale_seconds=heartbeat_stale_seconds,
        )

        # Escalate each hold performed on this tick, and each repeated-BLOCKED
        # hold the execution worker performed, exactly once: an already open
        # watchdog thread for the same execution, or any escalation thread
        # appended after that execution's latest hold, suppresses a duplicate.
        escalated: list[str] = []
        blocked_holds = [
            execution.id
            for execution in sorted(
                project_executions(state).values(), key=lambda item: (item.created_at, item.id)
            )
            if execution.status == "held"
            and execution.hold_reason.startswith((
                BLOCKED_HOLD_REASON_PREFIX,
                "autonomous replay budget exhausted after repeated dead letter; ",
            ))
            and execution.id not in held
        ]
        candidates = held + blocked_holds
        if escalate and candidates:
            targets = _escalation_targets(escalation_target)
            all_threads = list_thread_inbox(state=state).threads
            open_titles = {
                thread.title
                for thread in all_threads
                if thread.status not in {"done", "retired"}
                and _is_watchdog_escalation(
                    actor=thread.actor, target=thread.target, identity_bound=thread.actor_identity_bound, worker=worker, targets=targets,
                )
            }
            # Loop guard: an escalation thread sent to an agent wakes an execution for it;
            # if THAT execution is held, paging the same agent again would loop forever.
            # Escalations about the watchdog's own threads stay on the dashboard lane.
            watchdog_threads = {
                thread.id for thread in all_threads
                if str(thread.actor or "").strip().casefold() == worker.strip().casefold()
            }
            escalated_since_hold = _escalated_since_latest_hold(
                state, set(candidates), worker=worker, targets=targets,
            )
            for execution_id in candidates:
                title = _escalation_title(execution_id)
                if title in open_titles or execution_id in escalated_since_hold:
                    continue
                execution = project_executions(state)[execution_id]
                page_target = "operator" if execution.subject_id in watchdog_threads else (
                    escalation_target.strip() or "operator"
                )
                guidance = "" if page_target == "operator" else (
                    " Investigate with control.execution_list / control.thread_get, fix what is within your "
                    "authority, and tell the operator what is stuck and what it needs; only the operator can replay "
                    "or close another agent's execution."
                )
                post_thread(
                    state,
                    title=title,
                    body=_hold_alert_body(
                        target=execution.target, subject_type=execution.subject_type,
                        subject_id=execution.subject_id, hold_reason=execution.hold_reason,
                    ) + guidance,
                    thread_type="blocker",
                    actor=worker,
                    actor_identity_bound=False,
                    target=page_target,
                    severity="warn",
                )
                escalated.append(execution_id)

        # Stale sweep. Nothing may sit stale in AMC: every stuck item is paged once to the
        # escalation target, keyed by its current state so a fresh stall pages again. Pages about
        # the watchdog's own threads go to operator only, so a page can never page itself.
        stale_work: list[tuple[str, str, str]] = []  # (title, body, subject thread id or "")
        worker_key = worker.strip().casefold()
        all_threads = list_thread_inbox(state=state).threads
        own_threads = {t.id for t in all_threads if str(t.actor or "").strip().casefold() == worker_key}
        for thread in all_threads:
            if not thread.pending or thread.status not in {"acked", "acknowledged"}:
                continue
            progress = str(thread.latest_at or thread.acked_at or "")
            try:
                age = (current - _parse(progress)).total_seconds()
            except ValueError:
                age = float("inf")
            if age >= stale_escalation_seconds:
                stale_work.append((
                    f"watchdog stale thread: {thread.id} since {progress}",
                    f"{thread.target} acknowledged \"{thread.title[:120]}\" and has made no progress since {progress}. "
                    "Get it finished, released or abandoned (arvyx thread-abandon, with the operator's approval).",
                    thread.id,
                ))
        for item in outbox_snapshot.values():
            mode = str(item.payload.get("delivery_mode") or "direct")
            if item.status == "ambiguous_delivery":
                stale_work.append((
                    f"watchdog ambiguous delivery: {item.id}",
                    f"{mode} to {item.target} may or may not have reached its receiver. Read it back from the "
                    "provider and reconcile it (arvyx execution reconcile-delivery).",
                    item.subject_id if item.subject_id in own_threads else "",
                ))
            elif item.status == "dead_lettered" and not item.resolution_category and mode != "execution":
                stale_work.append((
                    f"watchdog dead letter: {item.id}",
                    f"{mode} to {item.target} for {item.subject_id} dead-lettered. Replay it if the work is still "
                    "wanted, or resolve it with a category (docs/runbooks/dead-letter-recovery.md).",
                    item.subject_id if item.subject_id in own_threads else "",
                ))
        for decision_id in decisions_awaiting_long:
            stale_work.append((
                f"watchdog decision waiting: {decision_id}",
                f"The operator has not answered decision {decision_id} for over 24 hours. Remind them, or ask whether "
                "the question still stands.",
                "",
            ))
        stale_paged: list[str] = []
        if escalate and stale_work:
            targets = _escalation_targets(escalation_target)
            already = {
                t.title for t in all_threads
                if _is_watchdog_escalation(actor=t.actor, target=t.target, identity_bound=t.actor_identity_bound, worker=worker,
                                           targets=targets)
            }
            for title, body, subject in stale_work:
                if title in already:
                    continue
                post_thread(
                    state, title=title, body=body, thread_type="blocker", actor=worker,
                    actor_identity_bound=False,
                    target="operator" if subject in own_threads else (escalation_target.strip() or "operator"),
                    severity="warn",
                )
                stale_paged.append(title)

        attention: list[str] = []
        if boundary_invalid:
            attention.append("invalid_receipt_enforcement_boundary")
        if any(not bool(item["ok"]) for item in reachability.values()):
            attention.append("unreachable_targets")
        if delivered_without_receipt:
            attention.append("delivered_without_receipt")
        if health["assigned_without_live_execution_count"]:
            # Stable token for existing alert consumers; the underlying health
            # object also exposes the assignment-driven name.
            attention.append("acked_without_live_execution")
        if health["leased_without_recent_heartbeat_count"]:
            attention.append("leased_without_recent_heartbeat")
        if health["dead_lettered_count"]:
            attention.append("dead_lettered_executions")
        if health["held_count"]:
            attention.append("held_executions")
        if decisions_awaiting_long:
            attention.append("decisions_awaiting_operator")
        if tokens_expiring:
            attention.append("tokens_expiring")
        if token_expiry_error:
            # Distinct from "nothing expiring": the watch could not read the registry
            # at all, so an operator must not read the empty list as "all healthy".
            attention.append("token_expiry_check_failed")
        if stale_work:
            attention.append("stale_work")

        counts = {
            "materialized": len(materialized),
            "reconciled": len(reconciled),
            "replayed": len(replayed),
            "held": len(held),
            "deferred_unreachable": len(deferred_unreachable),
            "delivered_without_receipt": len(delivered_without_receipt),
            "delivered_without_receipt_baselined": delivered_without_receipt_baselined,
            "escalated": len(escalated),
            "decision_cards_restored": len(decision_cards_restored),
            "decisions_awaiting_over_24h": len(decisions_awaiting_long),
            "tokens_expiring": len(tokens_expiring),
            "tokens_warned": len(tokens_warned),
            "stale_work": len(stale_work),
            "stale_paged": len(stale_paged),
        }
        tick_payload = {
            "worker": worker,
            "attention": attention,
            "counts": counts,
            "reachability": reachability,
            "receipt_enforcement_since": receipt_enforcement_since,
            "token_expiry_error": token_expiry_error,
        }
        # Coalesce: an unchanged tick inside the heartbeat window is not re-recorded
        # (the tick report still returns to the timer's journal every run).
        previous_at = previous_tick.get("last_tick_at")
        try:
            previous_age = (current - _parse(previous_at)).total_seconds()
        except ValueError:
            previous_age = float('inf')
        unchanged = (
            bool(previous_tick.get("initialized"))
            and previous_tick.get("signature") == _tick_signature(tick_payload)
            and isinstance(previous_at, str)
            and 0 <= previous_age < WATCHDOG_TICK_HEARTBEAT_SECONDS
        )
        if not unchanged:
            with _locked_state(state):
                _append_event_unlocked(
                    state, _event(WATCHDOG_TICK_EVENT, "watchdog", timestamp, tick_payload)
                )

    return {
        "ok": not attention,
        "tick_recorded": not unchanged,
        "attention": attention,
        "counts": counts,
        "reachability": reachability,
        "token_expiry_error": token_expiry_error,
        "materialized": [item.id for item in materialized][:BOUNDED_LIST_LIMIT],
        "reconciled": [item.id for item in reconciled][:BOUNDED_LIST_LIMIT],
        "replayed": replayed[:BOUNDED_LIST_LIMIT],
        "held": held[:BOUNDED_LIST_LIMIT],
        "deferred_unreachable": deferred_unreachable[:BOUNDED_LIST_LIMIT],
        "delivered_without_receipt": delivered_without_receipt[:BOUNDED_LIST_LIMIT],
        "escalated": escalated[:BOUNDED_LIST_LIMIT],
        "decision_cards_restored": decision_cards_restored[:BOUNDED_LIST_LIMIT],
        "decisions_awaiting_over_24h": decisions_awaiting_long[:BOUNDED_LIST_LIMIT],
        "tokens_expiring": tokens_expiring[:BOUNDED_LIST_LIMIT],
        "health": health,
    }
