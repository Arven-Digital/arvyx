from __future__ import annotations

from dataclasses import dataclass
from datetime import date as date_type
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request
from .http_bounds import BoundedOpener

from .control import (
    Thread,
    list_pending_threads,
    list_thread_inbox,
    post_thread_unlocked,
    project_thread_notifications,
    record_thread_notification_unlocked,
    thread_state_lock,
)
from .security import is_http_url

DAILY_HANDOFF_CHANNEL = "daily-handoff"

# Generic role defaults only: fixture agents, never live topology.
DEFAULT_DAILY_ROLES = (
    {
        "role": "ops",
        "target": "demobot",
        "title": "ops check",
        "body": "Run the daily ops synthetic checks and close this thread with receipts.",
    },
    {
        "role": "build",
        "target": "vesper",
        "title": "build and system check",
        "body": "Verify build targets and system health, then close this thread with receipts.",
    },
    {
        "role": "memory",
        "target": "operator",
        "title": "memory quality check",
        "body": "Review recall quality and the pending memory lanes, then close this thread.",
    },
    {
        "role": "research",
        "target": "nova",
        "title": "research runtime check",
        "body": "Verify browser/research runtime readiness, then close this thread.",
    },
)

MATRIX_STATUS_ORDER = ("FAIL", "WARN", "OK", "SKIP")


@dataclass(frozen=True)
class EndpointProbe:
    name: str
    url: str
    status: str
    note: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "url": self.url, "status": self.status, "note": self.note}


@dataclass(frozen=True)
class AgentReadiness:
    id: str
    runtime: str
    status: str
    endpoints: list[EndpointProbe]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "runtime": self.runtime,
            "status": self.status,
            "endpoints": [probe.to_dict() for probe in self.endpoints],
        }


@dataclass(frozen=True)
class AgentMatrixResult:
    ok: bool
    agents: list[AgentReadiness]
    counts: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "agents": [agent.to_dict() for agent in self.agents],
            "counts": self.counts,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass(frozen=True)
class DailyHandoffResult:
    date: str
    created: list[Thread]
    skipped: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "date": self.date,
            "created": [thread.to_dict() for thread in self.created],
            "skipped": self.skipped,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass(frozen=True)
class NotifyCheckResult:
    candidates: list[dict[str, str]]
    suppressed: list[str]
    dry_run: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidates": self.candidates,
            "suppressed": self.suppressed,
            "dry_run": self.dry_run,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def agent_matrix(config: Path, timeout: float = 5.0) -> AgentMatrixResult:
    """Probe configured agent endpoints into an OK/WARN/FAIL/SKIP matrix.

    The topology comes entirely from the config file; nothing about live
    machines is built in. ok means every endpoint is OK or SKIP.
    """
    spec = _load_json_object(config)
    agents_spec = spec.get("agents")
    if not isinstance(agents_spec, list) or not agents_spec:
        raise ValueError("agent matrix config must contain a non-empty 'agents' list")
    agents: list[AgentReadiness] = []
    counts = {status: 0 for status in MATRIX_STATUS_ORDER}
    for entry in agents_spec:
        if not isinstance(entry, dict) or not str(entry.get("id", "")).strip():
            raise ValueError("each agent entry must be an object with an 'id'")
        agent_id = str(entry["id"]).strip()
        endpoints_spec = entry.get("endpoints")
        if not isinstance(endpoints_spec, list):
            raise ValueError(f"agent {agent_id} must declare an 'endpoints' list")
        probes = [_probe_endpoint(endpoint, agent_id=agent_id, timeout=timeout) for endpoint in endpoints_spec]
        for probe in probes:
            counts[probe.status] += 1
        agents.append(
            AgentReadiness(
                id=agent_id,
                runtime=str(entry.get("runtime", "")),
                status=_worst_status(probes),
                endpoints=probes,
            )
        )
    ok = counts["FAIL"] == 0 and counts["WARN"] == 0
    return AgentMatrixResult(ok=ok, agents=agents, counts=counts)


def daily_handoff(
    state: Path,
    date: str | None = None,
    actor: str = "operator",
    config: Path | None = None,
) -> DailyHandoffResult:
    """Create the day's health handoff threads, at most once per (date, role).

    One state lock spans reading the existing titles and creating the new
    threads, so an overlapping run projects a complete picture and skips
    instead of duplicating.
    """
    handoff_date = _validate_date(date)
    roles = _load_roles(config)
    created: list[Thread] = []
    skipped: list[str] = []
    with thread_state_lock(state):
        existing_titles = {
            thread.title
            for thread in list_thread_inbox(state=state).threads
            if thread.channel == DAILY_HANDOFF_CHANNEL
        }
        for role in roles:
            title = f"[{handoff_date}] daily {role['role']} check: {role['title']}"
            if title in existing_titles:
                skipped.append(title)
                continue
            result = post_thread_unlocked(
                state,
                title=title,
                body=str(role.get("body", "")),
                thread_type="ask",
                actor=actor,
                target=str(role["target"]),
                channel=DAILY_HANDOFF_CHANNEL,
                severity=str(role.get("severity", "notice")),
            )
            created.append(result.thread)
            # duplicate role entries in the same config skip, not duplicate
            existing_titles.add(title)
    return DailyHandoffResult(date=handoff_date, created=created, skipped=skipped)


def notify_check(
    state: Path,
    dedupe_window_minutes: int = 240,
    escalate_after_minutes: int = 60,
    dry_run: bool = False,
    dashboard_url: str | None = None,
) -> NotifyCheckResult:
    """Compute notification/escalation candidates for pending threads.

    Dedupe and escalation state is projected from thread.notification_sent
    events in the same append-only log, so a dry run (which appends nothing)
    can never change future behavior. One state lock spans projecting the
    history, listing pending threads, deciding candidates, and appending the
    events — two overlapping runs serialize, and the later one suppresses
    instead of duplicating. Notification text carries no dashboard link
    unless one is explicitly configured.
    """
    if dedupe_window_minutes < 1:
        raise ValueError("--dedupe-window-minutes must be greater than zero")
    if escalate_after_minutes < 1:
        raise ValueError("--escalate-after-minutes must be greater than zero")
    candidates: list[dict[str, str]] = []
    suppressed: list[str] = []
    to_record: list[tuple[Thread, str, str]] = []
    with thread_state_lock(state):
        now = _utcnow()
        notified = project_thread_notifications(state)
        for thread in list_pending_threads(state=state).threads:
            history = notified.get(thread.id, {})
            last_notified = _parse_timestamp(history.get("notification"))
            if last_notified is None or _age_minutes(last_notified, now) >= dedupe_window_minutes:
                text = _notification_text(thread, dashboard_url)
                candidates.append(_candidate(thread, kind="notification", text=text))
                to_record.append((thread, "notification", text))
            else:
                suppressed.append(thread.id)
            created_at = _parse_timestamp(thread.created_at)
            unacked = thread.status == "open"
            overdue = created_at is not None and _age_minutes(created_at, now) >= escalate_after_minutes
            if unacked and overdue and "escalation" not in history:
                age = _age_minutes(created_at, now)
                text = _notification_text(thread, dashboard_url, prefix=f"ESCALATION unacked {age}m: ")
                candidates.append(_candidate(thread, kind="escalation", text=text))
                to_record.append((thread, "escalation", text))
        if not dry_run:
            for candidate, (thread, kind, text) in zip(candidates, to_record):
                claim = record_thread_notification_unlocked(state, thread=thread, kind=kind, text=text)
                candidate["claim_event_id"] = claim.id
    return NotifyCheckResult(candidates=candidates, suppressed=suppressed, dry_run=dry_run)


def _candidate(thread: Thread, kind: str, text: str) -> dict[str, str]:
    return {
        "kind": kind,
        "thread_id": thread.id,
        "type": thread.type,
        "severity": thread.severity,
        "target": thread.target,
        "channel": thread.channel,
        "title": thread.title,
        "text": text,
    }


def _notification_text(thread: Thread, dashboard_url: str | None, prefix: str = "") -> str:
    text = f"{prefix}[{thread.severity}] {thread.type} for {thread.target}: {thread.title}"
    if dashboard_url:
        text = f"{text} | {dashboard_url}"
    return text


def _probe_endpoint(endpoint: object, agent_id: str, timeout: float) -> EndpointProbe:
    if not isinstance(endpoint, dict) or not str(endpoint.get("name", "")).strip():
        raise ValueError(f"agent {agent_id} has an endpoint without a 'name'")
    name = str(endpoint["name"]).strip()
    url = str(endpoint.get("url", "")).strip()
    if endpoint.get("enabled") is False or not url:
        return EndpointProbe(name=name, url=url, status="SKIP", note="disabled")
    if not is_http_url(url):
        return EndpointProbe(name=name, url=url, status="FAIL", note="refusing non-http(s) url")
    try:
        with BoundedOpener().open(Request(url, method="GET"), timeout=timeout) as response:
            status_code = int(response.status)
            if len(response.read(1024 * 1024 + 1)) > 1024 * 1024:
                raise ValueError('health probe response exceeds limit')
    except HTTPError as exc:
        exc.close()
        return EndpointProbe(name=name, url=url, status="WARN", note=f"HTTP {exc.code}")
    except (URLError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        return EndpointProbe(name=name, url=url, status="FAIL", note=f"unreachable: {reason}")
    if 200 <= status_code < 300:
        return EndpointProbe(name=name, url=url, status="OK", note=f"HTTP {status_code}")
    return EndpointProbe(name=name, url=url, status="WARN", note=f"HTTP {status_code}")


def _worst_status(probes: list[EndpointProbe]) -> str:
    statuses = {probe.status for probe in probes}
    for status in MATRIX_STATUS_ORDER:
        if status in statuses:
            return status
    return "SKIP"


def _load_roles(config: Path | None) -> list[dict[str, str]]:
    if config is None:
        raise ValueError("daily handoff requires an explicit roles config; fixture agents are not a live roster")
    spec = _load_json_object(config)
    roles = spec.get("roles")
    if not isinstance(roles, list) or not roles:
        raise ValueError("daily handoff config must contain a non-empty 'roles' list")
    validated: list[dict[str, str]] = []
    for role in roles:
        if not isinstance(role, dict):
            raise ValueError("each role must be an object")
        for key in ("role", "target", "title"):
            if not str(role.get(key, "")).strip():
                raise ValueError(f"each role must declare a non-empty '{key}'")
        validated.append({key: str(value) for key, value in role.items()})
    return validated


def _load_json_object(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"config file not found: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in {path}: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"config must be a JSON object: {path}")
    return payload


def _validate_date(date: str | None) -> str:
    if date is None:
        return _utcnow().date().isoformat()
    try:
        return date_type.fromisoformat(date.strip()).isoformat()
    except ValueError as exc:
        raise ValueError(f"invalid --date (expected YYYY-MM-DD): {date}") from exc


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _age_minutes(then: datetime, now: datetime) -> int:
    return max(0, int((now - then).total_seconds() // 60))


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)
