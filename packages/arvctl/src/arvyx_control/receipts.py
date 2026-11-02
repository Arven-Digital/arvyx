from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .control import read_events
from .execution import _is_authoritative_terminal, project_executions
from .outbox import OutboxItem, project_outbox
from .session_return import SESSION_RETURN_EVENT, _overlay_delivery, project_session_returns


LEGS = ("capture", "dispatch", "accept", "work", "deliver")
_STATES = frozenset({"pending", "succeeded", "failed"})
_PROVENANCE = frozenset({"control_plane", "runtime", "provider", "ui", "user_report", "inferred"})


@dataclass(frozen=True)
class EvidenceEvent:
    leg: str
    state: str
    provenance: str
    evidence_ref: str = ""
    reason: str = ""

    def __post_init__(self) -> None:
        if self.leg not in LEGS:
            raise ValueError(f"unknown evidence leg: {self.leg}")
        if self.state not in _STATES:
            raise ValueError(f"unknown evidence state: {self.state}")
        if self.provenance not in _PROVENANCE:
            raise ValueError(f"unknown evidence provenance: {self.provenance}")
        if self.state == "succeeded" and self.provenance == "inferred":
            raise ValueError("inferred evidence cannot prove success")

    def to_dict(self) -> dict[str, str]:
        return {
            "leg": self.leg,
            "state": self.state,
            "provenance": self.provenance,
            "evidence_ref": self.evidence_ref,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class SubjectReceipt:
    subject_id: str
    status: str
    legs: dict[str, EvidenceEvent]

    def to_dict(self) -> dict[str, object]:
        return {
            "subject_id": self.subject_id,
            "status": self.status,
            "legs": {name: leg.to_dict() for name, leg in self.legs.items()},
        }


def _pending(leg: str, reason: str = "evidence not observed") -> EvidenceEvent:
    return EvidenceEvent(leg, "pending", "inferred", reason=reason)


def _latest_delivery_epochs(items: Iterable[OutboxItem]) -> list[OutboxItem]:
    latest: dict[tuple[str, str, str], OutboxItem] = {}
    for item in items:
        key = (item.subject_id, item.target, item.payload_hash)
        previous = latest.get(key)
        if previous is None or item.epoch > previous.epoch:
            latest[key] = item
    return list(latest.values())


def project_subject_receipt(state: Path, *, subject_id: str) -> SubjectReceipt:
    """Derive a conservative five-leg receipt from canonical control events.

    This is a read-only projection. It does not replace domain lifecycle state;
    it answers only how much of capture → dispatch → accept → work → deliver is
    proven for one exact subject.
    """
    events = read_events(state)
    outbox = project_outbox(state)
    current_outbox = _latest_delivery_epochs(outbox.values())
    executions = project_executions(state)
    returns = project_session_returns(state)
    legs = {leg: _pending(leg) for leg in LEGS}

    created = next(
        (
            event
            for event in events
            if event.task_id == subject_id and event.type in {"thread.created", "handoff.created", "task.created"}
        ),
        None,
    )
    if created is not None:
        legs["capture"] = EvidenceEvent(
            "capture", "succeeded", "control_plane", created.id
        )

    subject_deliveries = [
        item
        for item in current_outbox
        if item.subject_id == subject_id
        and str(item.payload.get("source_event_type", ""))
        in {"thread.created", "handoff.created", "task.created"}
    ]
    delivered = next((item for item in subject_deliveries if item.status == "delivered"), None)
    ambiguous = next(
        (item for item in subject_deliveries if item.status == "ambiguous_delivery"),
        None,
    )
    failed_delivery = next(
        (
            item
            for item in subject_deliveries
            if item.status == "dead_lettered"
            and item.resolution_category in {"", "ambiguous_not_delivered"}
        ),
        None,
    )
    if failed_delivery is not None:
        legs["dispatch"] = EvidenceEvent(
            "dispatch", "failed", "provider", failed_delivery.id, failed_delivery.failure_detail
        )
    elif ambiguous is not None:
        legs["dispatch"] = EvidenceEvent(
            "dispatch",
            "pending",
            "provider",
            ambiguous.id,
            ambiguous.ambiguity_detail or "provider acceptance is ambiguous",
        )
    elif subject_deliveries and all(item.status == "delivered" for item in subject_deliveries):
        assert delivered is not None
        provenance = (
            "user_report"
            if any(item.resolution_category == "ambiguous_delivered" for item in subject_deliveries)
            else "provider"
        )
        legs["dispatch"] = EvidenceEvent(
            "dispatch", "succeeded", provenance, delivered.id
        )

    accepted_event = next(
        (
            event
            for event in events
            if event.task_id == subject_id
            and event.type in {"thread.acknowledged", "handoff.accepted"}
            and event.payload.get("actor_identity_bound") is True
        ),
        None,
    )
    accepted_receipt = next(
        (
            item
            for item in subject_deliveries
            if item.receipt_status in {"accepted", "completed"} and item.receipt_by == item.target
        ),
        None,
    )
    if accepted_event is not None:
        legs["accept"] = EvidenceEvent(
            "accept", "succeeded", "control_plane", accepted_event.id
        )
    elif accepted_receipt is not None:
        legs["accept"] = EvidenceEvent(
            "accept", "succeeded", "runtime", accepted_receipt.id
        )

    subject_executions = [item for item in executions.values() if item.subject_id == subject_id]
    current_attempts = {item.id: item.attempt_id for item in subject_executions}
    heartbeat = next(
        (
            event
            for event in reversed(events)
            if event.type == "execution.heartbeat"
            and event.task_id in current_attempts
            and str(event.payload.get("attempt_id", "")) == current_attempts[event.task_id]
            and event.payload.get("actor_identity_bound") is True
        ),
        None,
    )
    terminal = next(
        (
            event
            for event in reversed(events)
            if any(
                _is_authoritative_terminal(event, execution)
                for execution in subject_executions
            )
        ),
        None,
    )
    dead_execution = next(
        (item for item in subject_executions if item.status == "dead_lettered"),
        None,
    )
    if terminal is not None:
        legs["work"] = EvidenceEvent("work", "succeeded", "control_plane", terminal.id)
    elif dead_execution is not None:
        legs["work"] = EvidenceEvent(
            "work", "failed", "runtime", dead_execution.id, dead_execution.last_failure
        )
    elif heartbeat is not None:
        outcome = str(heartbeat.payload.get("runtime_outcome", "")).strip().casefold()
        if outcome in {"provider_error", "runtime_exited"}:
            legs["work"] = EvidenceEvent(
                "work", "failed", "runtime", heartbeat.id, outcome
            )
        elif outcome in {"unobservable", "waiting_human"}:
            legs["work"] = EvidenceEvent(
                "work", "pending", "runtime", heartbeat.id, outcome
            )
        else:
            legs["work"] = EvidenceEvent(
                "work", "pending", "runtime", heartbeat.id, outcome or "heartbeat_only"
            )

    execution_ids = {item.id for item in subject_executions}
    subject_returns = [item for item in returns.values() if item.execution_id in execution_ids]
    return_ids = {item.request_id for item in subject_returns}
    verified_returns = {item.request_id: _overlay_delivery(item, outbox) for item in subject_returns}
    # Append order binds a successful replacement to its own execution/target.
    # Historical dead letters stay visible in the canonical projections.
    positions = {event.task_id: index for index, event in enumerate(events) if event.type == SESSION_RETURN_EVENT}
    superseded_failures = set()
    for execution in subject_executions:
        completed_at = max((index for index, event in enumerate(events)
                            if _is_authoritative_terminal(event, execution)), default=-1)
        lineage = [item for item in subject_returns if item.execution_id == execution.id
                   and item.target == execution.target.strip().casefold()]
        for replacement in lineage:
            delivered_return = verified_returns[replacement.request_id]
            replacement_at = positions.get(replacement.request_id, -1)
            if (delivered_return.status != 'delivered' or not delivered_return.provider_receipt
                    or replacement_at < 0 or completed_at <= replacement_at):
                continue
            superseded_failures.update(prior.request_id for prior in lineage
                if 0 <= positions.get(prior.request_id, -1) < replacement_at
                and verified_returns[prior.request_id].status in {'dead_lettered', 'cancelled'})
    verified_delivery_ids = {item.delivery_id for item in verified_returns.values() if item.delivery_id}
    returned = next(
        (
            item
            for item in current_outbox
            if item.subject_id in return_ids
            and item.payload.get("source_event_type") == "execution.session_return.requested"
            and item.status == "delivered"
            and item.id in verified_delivery_ids
            and bool(item.provider_receipt)
        ),
        None,
    )
    ambiguous_return = next(
        (
            item
            for item in current_outbox
            if item.subject_id in return_ids
            and item.payload.get("source_event_type") == "execution.session_return.requested"
            and item.status == "ambiguous_delivery"
            and item.id in verified_delivery_ids
        ),
        None,
    )
    failed_return = next(
        (
            item
            for item in current_outbox
            if item.subject_id in return_ids
            and item.payload.get("source_event_type") == "execution.session_return.requested"
            and item.status == "dead_lettered"
            and item.subject_id not in superseded_failures
            and item.id in verified_delivery_ids
            and item.resolution_category in {"", "ambiguous_not_delivered"}
        ),
        None,
    )
    if failed_return is not None:
        legs["deliver"] = EvidenceEvent(
            "deliver", "failed", "provider", failed_return.id, failed_return.failure_detail
        )
    elif ambiguous_return is not None:
        legs["deliver"] = EvidenceEvent(
            "deliver",
            "pending",
            "provider",
            ambiguous_return.id,
            ambiguous_return.ambiguity_detail or "human delivery is ambiguous",
        )
    elif returned is not None:
        provenance = "user_report" if returned.resolution_category == "ambiguous_delivered" else "provider"
        legs["deliver"] = EvidenceEvent(
            "deliver", "succeeded", provenance, returned.id
        )

    if any(leg.state == "failed" for leg in legs.values()):
        status = "RED"
    elif all(leg.state == "succeeded" for leg in legs.values()) and not any(
        leg.provenance == "user_report" for leg in legs.values()
    ):
        status = "GREEN"
    else:
        status = "YELLOW"
    return SubjectReceipt(subject_id=subject_id, status=status, legs=legs)
