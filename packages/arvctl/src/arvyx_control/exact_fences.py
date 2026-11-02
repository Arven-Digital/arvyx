"""Fail-closed raw lineage checks used only by bounded operator selectors."""
from .control import THREAD_EVENT_TYPES


def validate_known_lineage(events, identifiers: set[str]) -> None:
    # Lazy imports avoid coupling the ordinary projection paths to this gate.
    from .execution import EXECUTION_EVENT_TYPES
    from .outbox import OUTBOX_EVENT_TYPES
    known = (EXECUTION_EVENT_TYPES | OUTBOX_EVENT_TYPES | THREAD_EVENT_TYPES | {
        "thread.notification_sent", "thread.notification_failed",
        "handoff.created", "handoff.accepted", "handoff.completed", "handoff.reviewed",
        "execution.session_return.requested",
    })
    for event in events:
        if event.task_id in identifiers and event.type not in known:
            raise ValueError("exact selection has an unknown lineage event")


def validate_raw_outbox(events, outbox_id: str) -> None:
    from .outbox import OUTBOX_EVENT_TYPES
    for event in events:
        if event.task_id != outbox_id or event.type not in OUTBOX_EVENT_TYPES:
            continue
        if event.type == "outbox.receipt":
            continue  # Receipt metadata is not an item snapshot.
        payload = event.payload
        if payload.get("status") not in {
            "pending", "leased", "delivered", "dead_lettered", "cancelled", "ambiguous_delivery",
        }:
            raise ValueError("exact outbox has an invalid raw lifecycle")
        for field in ("attempts", "epoch", "failures"):
            value = payload.get(field, 0)
            if type(value) is not int or value < 0:
                raise ValueError("exact outbox has an invalid raw counter")
