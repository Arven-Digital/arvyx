from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import json
from pathlib import Path
from typing import Any

from .control import list_approvals, list_bus_messages, list_handoffs, list_tasks
from .session import get_session


# A start-of-session / weekly brief: the agent-team analog of a "morning
# brief". It composes existing read surfaces (control event log + hot session
# state) into one synthesis so an agent — or the operator — can answer "where
# do I start?" without scanning every list. Read-only; writes nothing.
ALERT_SEVERITIES = {"alert", "warning"}
_LIST_CAP = 8


@dataclass(frozen=True)
class DigestResult:
    agent: str
    generated_at: str
    window_hours: int
    session: dict[str, Any] | None
    open_tasks: list[dict[str, Any]]
    overdue_tasks: list[dict[str, Any]]
    awaiting_approvals: list[dict[str, Any]]
    assigned_handoffs: list[dict[str, Any]]
    review_handoffs: list[dict[str, Any]]
    recent_alerts: list[dict[str, Any]]
    completed: dict[str, int]
    focus: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "generated_at": self.generated_at,
            "window_hours": self.window_hours,
            "session": self.session,
            "open_tasks": self.open_tasks,
            "overdue_tasks": self.overdue_tasks,
            "awaiting_approvals": self.awaiting_approvals,
            "assigned_handoffs": self.assigned_handoffs,
            "review_handoffs": self.review_handoffs,
            "recent_alerts": self.recent_alerts,
            "completed": self.completed,
            "focus": self.focus,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def build_digest(
    state: Path,
    vault: Path | None = None,
    agent: str | None = None,
    window_hours: int = 24,
    task_sla_hours: int = 48,
    now: datetime | None = None,
    include_session: bool = True,
) -> DigestResult:
    """Synthesize a brief. With `agent`, scope every section to that agent's
    involvement (its own session, tasks it owns, handoffs and approvals it is
    party to, and its completed work); without, give the operator-wide view.
    `window_hours` bounds what counts as recent/completed. `include_session`
    is set False by callers whose scope does not include memory.read, so the
    control-plane brief never leaks an agent's working-memory prose."""
    now = now or datetime.now(UTC)
    window_hours = max(1, window_hours)
    task_sla_hours = max(0, task_sla_hours)
    tasks = list_tasks(state).tasks
    approvals = list_approvals(state).approvals
    handoffs = list_handoffs(state).handoffs
    messages = list_bus_messages(state).messages

    session = _session(vault, agent) if include_session else None

    def task_mine(task: Any) -> bool:
        return agent is None or task.owner == agent

    def handoff_mine(handoff: Any) -> bool:
        return agent is None or agent in (handoff.to_agent, handoff.from_agent)

    def approval_mine(approval: Any) -> bool:
        return agent is None or approval.requester == agent

    open_tasks = [t for t in tasks if t.status == "open" and task_mine(t)]
    overdue_tasks = [t for t in open_tasks if _age_hours(t.created_at, now) >= task_sla_hours]
    awaiting_approvals = [a for a in approvals if a.status == "requested" and approval_mine(a)]
    assigned_handoffs = [
        h for h in handoffs if h.status in {"open", "accepted"} and (agent is None or h.to_agent == agent)
    ]
    review_handoffs = [h for h in handoffs if h.status == "accepted" and handoff_mine(h)]
    # list_bus_messages is ascending by (created_at, id); reverse so the digest
    # shows the newest alerts first and the cap keeps the newest, not the oldest.
    # (created_at is second-precision, so id is the within-second tiebreaker.)
    recent_alerts = list(
        reversed([m for m in messages if m.severity in ALERT_SEVERITIES and _within(m.created_at, now, window_hours)])
    )

    completed = {
        "tasks": sum(
            1 for t in tasks if t.status == "done" and task_mine(t) and _within(t.updated_at, now, window_hours)
        ),
        "handoffs": sum(
            1
            for h in handoffs
            if h.status == "completed" and handoff_mine(h) and _within(h.updated_at, now, window_hours)
        ),
    }

    focus = _focus(
        agent=agent,
        overdue_tasks=overdue_tasks,
        open_tasks=open_tasks,
        assigned_handoffs=assigned_handoffs,
        awaiting_approvals=awaiting_approvals,
        recent_alerts=recent_alerts,
    )

    return DigestResult(
        agent=agent or "all",
        generated_at=_iso(now),
        window_hours=window_hours,
        session=session,
        open_tasks=[_task(t, now) for t in open_tasks[:_LIST_CAP]],
        overdue_tasks=[_task(t, now) for t in overdue_tasks[:_LIST_CAP]],
        awaiting_approvals=[_approval(a) for a in awaiting_approvals[:_LIST_CAP]],
        assigned_handoffs=[_handoff(h) for h in assigned_handoffs[:_LIST_CAP]],
        review_handoffs=[_handoff(h) for h in review_handoffs[:_LIST_CAP]],
        recent_alerts=[_message(m) for m in recent_alerts[:_LIST_CAP]],
        completed=completed,
        focus=focus,
    )


def _session(vault: Path | None, agent: str | None) -> dict[str, Any] | None:
    if vault is None or not agent:
        return None
    try:
        result = get_session(vault=vault, agent=agent)
    except (FileNotFoundError, ValueError):
        return None
    return {"updated_at": result.updated_at, "content": result.content}


def _focus(
    agent: str | None,
    overdue_tasks: list[Any],
    open_tasks: list[Any],
    assigned_handoffs: list[Any],
    awaiting_approvals: list[Any],
    recent_alerts: list[Any],
) -> list[str]:
    who = agent or "the team"
    focus: list[str] = []
    if assigned_handoffs:
        handoff = assigned_handoffs[0]
        focus.append(f"Handoff '{handoff.title}' is waiting on {who} ({handoff.status}).")
    if overdue_tasks:
        focus.append(f"Task '{overdue_tasks[0].title}' is overdue — start here.")
    elif open_tasks:
        focus.append(f"Next open task: '{open_tasks[0].title}'.")
    if recent_alerts:
        focus.append(f"{len(recent_alerts)} unresolved ops-bus alert(s) in the window.")
    if agent is None and awaiting_approvals:
        focus.append(f"{len(awaiting_approvals)} approval(s) awaiting review.")
    if not focus:
        focus.append("Nothing pending — inbox zero.")
    return focus[:3]


def _task(task: Any, now: datetime) -> dict[str, Any]:
    return {
        "id": task.id,
        "title": task.title,
        "owner": task.owner,
        "status": task.status,
        "age_hours": round(_age_hours(task.created_at, now), 1),
    }


def _handoff(handoff: Any) -> dict[str, Any]:
    return {
        "id": handoff.id,
        "title": handoff.title,
        "from_agent": handoff.from_agent,
        "to_agent": handoff.to_agent,
        "status": handoff.status,
    }


def _approval(approval: Any) -> dict[str, Any]:
    return {
        "id": approval.id,
        "requester": approval.requester,
        "command_hash": approval.command_hash,
        "status": approval.status,
    }


def _message(message: Any) -> dict[str, Any]:
    return {
        "channel": message.channel,
        "severity": message.severity,
        "actor": message.actor,
        "message": message.message,
        "created_at": message.created_at,
    }


def _parse(timestamp: str) -> datetime | None:
    if not timestamp:
        return None
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _age_hours(timestamp: str, now: datetime) -> float:
    parsed = _parse(timestamp)
    if parsed is None:
        return 0.0
    return max(0.0, (now - parsed).total_seconds() / 3600)


def _within(timestamp: str, now: datetime, window_hours: int) -> bool:
    # An unknown/malformed time is treated as out-of-window (fail-safe): a
    # brief must not claim an unparseable event happened "recently".
    parsed = _parse(timestamp)
    if parsed is None:
        return False
    return max(0.0, (now - parsed).total_seconds() / 3600) <= window_hours


def _iso(moment: datetime) -> str:
    return moment.replace(microsecond=0).isoformat().replace("+00:00", "Z")
