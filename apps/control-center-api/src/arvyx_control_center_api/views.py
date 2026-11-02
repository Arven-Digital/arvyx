"""Bounded read-model views over existing ``arvyx_control`` projections.

This module is the single seam between the Control Center API and
``arvyx_control``. It never re-implements lifecycle logic: Kanban cards and
lanes, agent workload, blocker and continuation state, safe event metadata,
activity buckets, delivery health, and the fleet verdict all come from the
projection the operator API serves at ``GET /control-plane``. Approvals,
retention, replica, memory-queue, and audit-chain posture come from the same
helpers ``GET /summary`` and ``GET /audit/events`` use. Views only select,
filter, and bound that output.

Nothing in this module writes to the vault, the event log, or the audit log.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any, Mapping
from urllib.parse import parse_qsl

# These projection helpers are module-private in arvyx_control.api. Importing
# them here, in one place, keeps this read model on exactly the code path the
# operator API uses; a rename there fails this import and the test suite
# loudly instead of letting the two surfaces drift apart.
from arvyx_control.api import (
    _approval_effective_status,
    _control_plane,
    _count_by_status,
    _health_age,
    _memory_queue,
    _thread_counts,
)
from arvyx_control.audit_log import default_audit_log, verify_chain
from arvyx_control.control import (
    list_approvals,
    list_handoffs,
    list_tasks,
    list_thread_inbox,
    read_events,
)
from arvyx_control.replica import replica_status
from arvyx_control.security import redact_secrets
from arvyx_control.store import manifest_state

from . import SCHEMA

LANES = ("queued", "active", "review", "done", "retired")
CARD_KINDS = ("task", "handoff", "thread")
_RETIRED_CARD_FIELDS = frozenset({
    'id', 'kind', 'thread_type', 'title', 'owner', 'actor', 'source_status',
    'status', 'lane', 'pending', 'unread', 'severity', 'created_at', 'updated_at',
})
# Every string in every response is secret-redacted and then capped.
MAX_STRING_CHARS = 512
TRUNCATION_MARKER = "..."
# Caps for lists the upstream projection does not bound itself.
MAX_NESTED_LIST_ITEMS = 50
MAX_QUERY_FIELDS = 8
ID_PATTERN = re.compile(r"[a-z0-9_-]{1,100}")


@dataclass(frozen=True)
class Sources:
    """Read-only inputs shared by every view."""

    vault: Path
    state: Path
    delivery_routes: Path | None = None
    audit_log: Path | None = None

    @property
    def audit_log_path(self) -> Path:
        return self.audit_log or default_audit_log(self.state)


class QueryError(ValueError):
    """A query parameter is unknown, repeated, malformed, or out of bounds."""


@dataclass(frozen=True)
class Param:
    """One declared query parameter of a route."""

    name: str
    kind: str  # "integer", "enum", or "id"
    description: str
    default: int | None = None
    maximum: int | None = None
    choices: tuple[str, ...] = ()

    def describe(self) -> dict[str, Any]:
        spec: dict[str, Any] = {"name": self.name, "description": self.description}
        if self.kind == "integer":
            spec.update(type="integer", minimum=1, maximum=self.maximum, default=self.default)
        elif self.kind == "enum":
            spec.update(type="string", enum=list(self.choices))
        else:
            spec.update(type="string", pattern=ID_PATTERN.pattern)
        return spec

    def parse(self, value: str) -> int | str:
        if self.kind == "integer":
            maximum = int(self.maximum or 1)
            if not re.fullmatch(r"[0-9]{1,7}", value) or not 1 <= int(value) <= maximum:
                raise QueryError(f"{self.name} must be an integer from 1 to {maximum}")
            return int(value)
        if self.kind == "enum":
            if value not in self.choices:
                raise QueryError(f"{self.name} must be one of: {', '.join(self.choices)}")
            return value
        if not ID_PATTERN.fullmatch(value):
            raise QueryError(f"{self.name} must match {ID_PATTERN.pattern}")
        return value


def parse_query(params: tuple[Param, ...], raw_query: str) -> dict[str, Any]:
    """Validate a query string against a route's declared parameters.

    Unknown and repeated parameters are rejected rather than ignored so a
    client typo cannot silently widen or narrow a view.
    """
    try:
        pairs = parse_qsl(raw_query, keep_blank_values=True, max_num_fields=MAX_QUERY_FIELDS)
    except ValueError as exc:
        raise QueryError("query string has too many fields") from exc
    specs = {param.name: param for param in params}
    parsed: dict[str, Any] = {}
    for name, value in pairs:
        spec = specs.get(name)
        if spec is None:
            allowed = ", ".join(sorted(specs)) or "none"
            raise QueryError(f"unsupported query parameter; allowed: {allowed}")
        if name in parsed:
            raise QueryError(f"{name} may appear at most once")
        parsed[name] = spec.parse(value)
    for spec in params:
        if spec.name not in parsed and spec.default is not None:
            parsed[spec.name] = spec.default
    return parsed


def sanitize(value: Any) -> Any:
    """Secret-redact and length-cap every string, recursively.

    The upstream projection already withholds bodies, messages, notes, and
    memory content; this is defense in depth for free-text fields that are
    legitimately exposed (titles, labels) and for mapping keys.
    """
    if isinstance(value, str):
        return _safe_text(value)
    if isinstance(value, Mapping):
        return {_safe_text(str(key)): sanitize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize(item) for item in value]
    return value


def _safe_text(text: str) -> str:
    # Redact before truncating so a cut can never split a secret past the
    # pattern that would have caught it.
    redacted = redact_secrets(text)
    if len(redacted) > MAX_STRING_CHARS:
        return redacted[: MAX_STRING_CHARS - len(TRUNCATION_MARKER)] + TRUNCATION_MARKER
    return redacted


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def stamp(instant: datetime) -> str:
    return instant.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _bound(items: list[Any], limit: int) -> tuple[list[Any], dict[str, Any]]:
    returned = items[:limit]
    return returned, {
        "total": len(items),
        "returned": len(returned),
        "limit": limit,
        "truncated": len(items) > len(returned),
    }


def _bound_nested_lists(value: Any, bounds: dict[str, Any], path: str = "") -> Any:
    """Cap every list inside ``value``, recording each truncation by path."""
    if isinstance(value, Mapping):
        return {
            key: _bound_nested_lists(item, bounds, f"{path}.{key}" if path else str(key))
            for key, item in value.items()
        }
    if isinstance(value, list):
        items = [_bound_nested_lists(item, bounds, f"{path}[]") for item in value]
        returned, info = _bound(items, MAX_NESTED_LIST_ITEMS)
        if info["truncated"]:
            bounds[path] = info
        return returned
    return value


def _envelope(
    view: str,
    *,
    generated_at: str,
    source: dict[str, Any],
    data: dict[str, Any],
    bounds: dict[str, Any],
) -> dict[str, Any]:
    return {
        "ok": True,
        "schema": SCHEMA,
        "view": view,
        "generated_at": generated_at,
        "source": source,
        "bounds": bounds,
        "data": data,
    }


def _projection(sources: Sources) -> dict[str, Any]:
    return _control_plane(
        vault=sources.vault, state=sources.state, delivery_routes=sources.delivery_routes
    )


def _projection_source(projection: Mapping[str, Any]) -> dict[str, Any]:
    source = projection["source"]
    return {
        key: source.get(key)
        for key in ("event_count", "first_timestamp", "last_timestamp", "freshness_seconds", "retention")
    }


def command_deck(sources: Sources, params: Mapping[str, Any]) -> dict[str, Any]:
    """Headline health and posture: fleet verdict, pressure, and counts."""
    projection = _projection(sources)
    events = read_events(sources.state)
    tasks = list_tasks(state=sources.state, events=events).tasks
    handoffs = list_handoffs(state=sources.state, events=events).handoffs
    threads = list_thread_inbox(state=sources.state, events=events).threads
    approvals = list_approvals(state=sources.state).approvals
    now = utc_now()
    fleet = projection["fleet"]
    delivery_health = projection["delivery"]
    agents = projection["agents"]
    buckets = projection["activity"]["buckets"]
    queue = _memory_queue(sources.vault)
    card_bounds = projection["source"]["bounds"]
    data = {
        "fleet": {"verdict": fleet["verdict"], "red": fleet["red"], "amber": fleet["amber"]},
        "delivery": {
            "ok": delivery_health["ok"],
            "attention": delivery_health["attention"],
            "backlog_count": delivery_health["work"]["backlog_count"],
            "unresolved_dead_letters": delivery_health["unresolved_dead_letters"],
        },
        "work": {"lanes": {lane: len(projection["kanban"][lane]) for lane in LANES}},
        "counts": {
            "tasks": _count_by_status(task.status for task in tasks),
            "handoffs": _count_by_status(handoff.status for handoff in handoffs),
            "threads": _thread_counts(threads),
            "approvals": _count_by_status(
                _approval_effective_status(approval, now) for approval in approvals
            ),
        },
        "squad": {
            "registered": len(agents),
            "by_status": _count_by_status(agent["status"] for agent in agents),
            "stale_continuations": projection["continuation"]["stale_count"],
        },
        "memory_queue": {"pending": queue["pending"], "refining": queue["refining"]},
        "signal": {
            "window_buckets": len(buckets),
            "events_in_window": sum(int(bucket["count"]) for bucket in buckets),
            "last_event_at": projection["source"]["last_timestamp"] or None,
        },
    }
    bounds = {
        # Lane counts are taken over the bounded card projection, which keeps
        # current work ahead of done history; "truncated" says when the done
        # lane count is therefore a floor rather than a total.
        "lane_counts": {
            "cards_total": card_bounds["cards_total"],
            "cards_counted": card_bounds["cards_returned"],
            "truncated": card_bounds["cards_truncated"],
        },
    }
    return _envelope(
        "command-deck",
        generated_at=projection["generated_at"],
        source=_projection_source(projection),
        data=data,
        bounds=bounds,
    )


def work_board(sources: Sources, params: Mapping[str, Any]) -> dict[str, Any]:
    """Kanban lanes of tasks, handoffs, and actionable threads."""
    projection = _projection(sources)
    lane_filter = params.get("lane")
    owner = params.get("owner")
    kind = params.get("kind")
    limit = int(params["limit"])
    cards = [
        ({key: value for key, value in card.items() if key in _RETIRED_CARD_FIELDS}
         if card.get('lane') == 'retired' else card)
        for card in projection["cards"]
        if (owner is None or card.get("owner") == owner) and (kind is None or card.get("kind") == kind)
    ]
    lanes: dict[str, list[Any]] = {}
    lane_bounds: dict[str, Any] = {}
    for lane in (lane_filter,) if lane_filter else LANES:
        lanes[lane], lane_bounds[lane] = _bound([card for card in cards if card["lane"] == lane], limit)
    card_bounds = projection["source"]["bounds"]
    return _envelope(
        "work-board",
        generated_at=projection["generated_at"],
        source=_projection_source(projection),
        data={"filters": {"lane": lane_filter, "owner": owner, "kind": kind}, "lanes": lanes},
        bounds={
            "lanes": lane_bounds,
            "projection": {
                "cards_total": card_bounds["cards_total"],
                "cards_projected": card_bounds["cards_returned"],
                "truncated": card_bounds["cards_truncated"],
            },
        },
    )


def squad(sources: Sources, params: Mapping[str, Any]) -> dict[str, Any]:
    """Registry agents with workload, blockers, continuation, skills, memory counts."""
    projection = _projection(sources)
    agent_filter = params.get("agent")
    agents = [agent for agent in projection["agents"] if agent_filter is None or agent["id"] == agent_filter]
    returned, agent_bounds = _bound(agents, int(params["limit"]))
    registry = projection["source"]["bounds"]
    agent_bounds.update(
        registry_discovered=registry["agents_discovered"],
        registry_invalid=registry["agents_invalid"],
        registry_truncated=registry["agents_truncated"],
    )
    return _envelope(
        "squad",
        generated_at=projection["generated_at"],
        source=_projection_source(projection),
        data={
            "filters": {"agent": agent_filter},
            "agents": returned,
            "continuation": projection["continuation"],
        },
        bounds={"agents": agent_bounds},
    )


def signal(sources: Sources, params: Mapping[str, Any]) -> dict[str, Any]:
    """Newest-first safe event metadata plus hourly activity buckets."""
    projection = _projection(sources)
    limit = int(params["limit"])
    events = projection["events"][:limit]
    total = int(projection["source"]["event_count"])
    return _envelope(
        "signal",
        generated_at=projection["generated_at"],
        source=_projection_source(projection),
        data={"events": events, "activity": projection["activity"]},
        bounds={
            "events": {
                "total": total,
                "returned": len(events),
                "limit": limit,
                "truncated": total > len(events),
            }
        },
    )


def governance(sources: Sources, params: Mapping[str, Any]) -> dict[str, Any]:
    """Approvals, audit-chain integrity, retention, replica, and memory-queue posture."""
    now = utc_now()
    limit = int(params["limit"])
    approvals = sorted(
        list_approvals(state=sources.state).approvals,
        key=lambda approval: (approval.updated_at, approval.id),
        reverse=True,
    )
    # Commands are stored only as hashes upstream; the free-text reason is
    # withheld here like every other body/notes field.
    rows = [
        {
            "id": approval.id,
            "requester": approval.requester,
            "approver": approval.approver,
            "status": approval.status,
            "effective_status": _approval_effective_status(approval, now),
            "created_at": approval.created_at,
            "updated_at": approval.updated_at,
            "expires_at": approval.expires_at,
        }
        for approval in approvals
    ]
    returned, approval_bounds = _bound(rows, limit)
    manifest = manifest_state(sources.state)
    replica = replica_status(sources.vault)
    queue = _memory_queue(sources.vault)
    projects = [{"project": name, **counts} for name, counts in sorted(queue["by_project"].items())]
    projects_returned, project_bounds = _bound(projects, MAX_NESTED_LIST_ITEMS)
    data = {
        "approvals": {
            "counts": _count_by_status(row["effective_status"] for row in rows),
            "items": returned,
        },
        "audit": _audit_posture(sources.audit_log_path),
        "retention": {
            "retention": manifest.retention,
            "events": manifest.events,
            "first_timestamp": manifest.first_timestamp,
            "last_timestamp": manifest.last_timestamp,
            "sha256": manifest.sha256,
        },
        # The replica status carries the vault path and sync source; neither
        # is exposed, only the posture.
        "replica": {
            "role": "replica" if replica.is_replica else "primary",
            "is_replica": replica.is_replica,
            "last_synced_at": replica.last_synced_at,
            "age_seconds": replica.age_seconds,
            "files": replica.files,
        },
        "memory_queue": {
            "pending": queue["pending"],
            "refining": queue["refining"],
            "projects": projects_returned,
        },
    }
    return _envelope(
        "governance",
        generated_at=stamp(now),
        source={
            "event_count": manifest.events,
            "first_timestamp": manifest.first_timestamp,
            "last_timestamp": manifest.last_timestamp,
            "freshness_seconds": _health_age(now, manifest.last_timestamp or ""),
            "retention": manifest.retention,
        },
        data=data,
        bounds={"approvals": approval_bounds, "memory_queue_projects": project_bounds},
    )


def _audit_posture(path: Path) -> dict[str, Any]:
    """Four-state audit-chain posture without exposing any audit record."""
    if not path.exists():
        return {"status": "absent", "events": 0, "first_break_line": None}
    try:
        result = verify_chain(path)
    except (OSError, UnicodeError):
        return {"status": "unavailable", "events": None, "first_break_line": None}
    return {
        "status": "ok" if result.ok else "broken",
        "events": result.events,
        "first_break_line": result.first_break_line,
    }


def delivery(sources: Sources, params: Mapping[str, Any]) -> dict[str, Any]:
    """Outbox delivery health and the fail-closed fleet verdict."""
    projection = _projection(sources)
    nested_bounds: dict[str, Any] = {}
    fleet = _bound_nested_lists(projection["fleet"], nested_bounds, "fleet")
    delivery_health = _bound_nested_lists(projection["delivery"], nested_bounds, "delivery")
    return _envelope(
        "delivery",
        generated_at=projection["generated_at"],
        source=_projection_source(projection),
        data={
            "verdict": fleet["verdict"],
            "route_configuration": "configured" if sources.delivery_routes is not None else "not_configured",
            "fleet": fleet,
            "delivery": delivery_health,
        },
        bounds={"list_limit": MAX_NESTED_LIST_ITEMS, "truncated_lists": nested_bounds},
    )
