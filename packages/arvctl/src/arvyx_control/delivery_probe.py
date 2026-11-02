"""Read-only delivery liveness probe.

``arvyx delivery probe`` answers "is agent delivery actually working right
now?" from four independent angles, none of which wakes an agent or appends to
the control log:

(a) transport  - a bounded TCP connect to every route endpoint (the same
                 probe ``arvyx routes doctor --probe`` runs);
(b) ticks      - the dispatcher and execution-worker liveness records are
                 present, recent, and not reporting errors;
(c) delivery   - per target, over a sliding window of the event log: enqueued,
                 delivered, failed and dead-lettered counts, the oldest
                 undelivered item, and the most common failure details;
(d) execution  - per target: executions created and completed in the window,
                 lease expiries, and the live count.

The event log is streamed line by line with a byte budget and a per-line cap;
only outbox and execution events are decoded, and only events inside the
window are aggregated. Per-item projection state is a few strings per record,
so memory grows with the number of deliveries and executions, never with the
size of their payloads.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sys
import time
from typing import Any, Callable, Iterator, Mapping

from .agent_delivery import AgentRoute, probe_route_endpoint
from .dispatcher import load_route_document, validate_routes
from .liveness import (
    DISPATCHER_COMPONENT,
    TICK_COMPONENTS,
    WORKER_COMPONENT,
    liveness_dir,
    load_deadman_url,
    parse_timestamp,
    ping_deadman,
    read_tick_record,
    run_alerting,
    worst_verdict,
)
from .notifiers import build_notifier_from_config
from .outbox import EXECUTION_WAKE_MODE
from .security import redact_secrets

PROBE_SCHEMA = "v2.delivery-probe/1"
PROBE_ALERT_STATE_NAME = "delivery-probe-alert.json"
EXIT_OK = 0
EXIT_ALERT = 1
EXIT_USAGE = 2

# Fixed, bounded allowance for wall-clock jitter; never scale with stale intervals.
TICK_FUTURE_SKEW_TOLERANCE_SECONDS = 5
DEFAULT_EXPECTED_INTERVALS = {DISPATCHER_COMPONENT: 10, WORKER_COMPONENT: 5}
UNDELIVERED_STATUSES = frozenset({"pending", "leased"})
# claim_execution only re-claims (attempt.started) or exhausts (dead_lettered)
# a leased execution after its lease expired, so a transition out of
# ``leased`` into one of these is a lease expiry.
_LEASE_EXPIRY_TRANSITIONS = frozenset({"execution.attempt.started", "execution.dead_lettered"})
_EXECUTION_STATE_EVENTS = frozenset({
    "execution.created", "execution.attempt.started", "execution.heartbeat",
    "execution.attempt.failed", "execution.dead_lettered", "execution.completed",
    "execution.replayed", "execution.held", "execution.closed",
    "execution.cancel_requested", "execution.resumed",
})
_OUTBOX_ITEM_EVENTS = frozenset({
    "outbox.enqueued", "outbox.attempt.started", "outbox.attempt.failed",
    "outbox.delivered", "outbox.deferred", "outbox.dead_lettered",
    "outbox.replayed", "outbox.receipt", "outbox.cancelled", "outbox.resolved",
})
_FILTER_TOKENS = (b"outbox.", b"execution.")
_READ_CHUNK = 1024 * 1024


@dataclass(frozen=True)
class ProbeConfig:
    window_seconds: int = 3600
    dispatcher_interval_seconds: int = DEFAULT_EXPECTED_INTERVALS[DISPATCHER_COMPONENT]
    worker_interval_seconds: int = DEFAULT_EXPECTED_INTERVALS[WORKER_COMPONENT]
    stale_multiplier: float = 3.0
    tick_components: tuple[str, ...] = TICK_COMPONENTS
    max_dead_letter_ratio: float = 0.2
    max_failure_ratio: float = 0.5
    min_outcomes_for_ratio: int = 4
    max_undelivered_age_seconds: int = 1800
    delivery_grace_seconds: int = 300
    max_scan_bytes: int = 512 * 1024 * 1024
    max_line_bytes: int = 1024 * 1024
    top_failures: int = 3
    transport: bool = True

    def validate(self) -> None:
        if self.window_seconds < 60:
            raise ValueError("window must be at least 1 minute")
        if self.dispatcher_interval_seconds < 1 or self.worker_interval_seconds < 1:
            raise ValueError("expected tick intervals must be positive")
        if self.stale_multiplier < 1:
            raise ValueError("stale multiplier must be at least 1")
        for ratio in (self.max_dead_letter_ratio, self.max_failure_ratio):
            if not 0 < ratio <= 1:
                raise ValueError("ratio thresholds must be in (0, 1]")
        if self.min_outcomes_for_ratio < 1:
            raise ValueError("min outcomes for ratio checks must be positive")
        if self.max_undelivered_age_seconds < 60:
            raise ValueError("max undelivered age must be at least 1 minute")
        if not 0 <= self.delivery_grace_seconds < self.window_seconds:
            raise ValueError("delivery grace must be non-negative and shorter than the window")
        if self.max_scan_bytes < 1024 or self.max_line_bytes < 1024:
            raise ValueError("scan bounds must be at least 1 KiB")
        unknown = set(self.tick_components) - set(TICK_COMPONENTS)
        if unknown:
            raise ValueError("unknown tick component: " + ", ".join(sorted(unknown)))

    def stale_after(self, component: str) -> int:
        interval = (
            self.dispatcher_interval_seconds
            if component == DISPATCHER_COMPONENT
            else self.worker_interval_seconds
        )
        return int(round(interval * self.stale_multiplier))


@dataclass(frozen=True)
class Finding:
    check: str
    severity: str  # degraded | failed
    code: str
    detail: str
    target: str = ""

    def to_dict(self) -> dict[str, str]:
        payload = {"check": self.check, "severity": self.severity, "code": self.code, "detail": self.detail}
        if self.target:
            payload["target"] = self.target
        return payload


@dataclass
class _Flow:
    enqueued: int = 0
    enqueued_settled: int = 0
    delivered: int = 0
    attempt_failed: int = 0
    dead_lettered: int = 0
    dead_lettered_refused: int = 0
    failures: Counter = field(default_factory=Counter)
    executions_created: int = 0
    executions_completed: int = 0
    lease_expired: int = 0
    executions_dead_lettered: int = 0
    executions_held: int = 0


@dataclass
class _Scan:
    flows: dict[str, _Flow] = field(default_factory=dict)
    # outbox id -> (target, created_at, status, delivery_mode)
    items: dict[str, tuple[str, str, str, str]] = field(default_factory=dict)
    # execution id -> (target, status, lease_expires_at)
    executions: dict[str, tuple[str, str, str]] = field(default_factory=dict)
    bytes_scanned: int = 0
    truncated: bool = False
    lines: int = 0
    decoded: int = 0
    in_window: int = 0
    malformed_lines: int = 0
    overlong_lines: int = 0

    def flow(self, target: str) -> _Flow:
        entry = self.flows.get(target)
        if entry is None:
            entry = self.flows[target] = _Flow()
        return entry


def iter_log_lines(
    state: Path, *, max_scan_bytes: int, max_line_bytes: int, scan: _Scan | None = None,
    start_offset: int = 0,
) -> Iterator[tuple[int, bytes]]:
    """Yield ``(end_offset, line)`` for complete lines, within a byte budget.

    Reads at most ``max_scan_bytes`` from the tail of the file (skipping the
    first partial line when it has to start mid-file), never holds more than
    ``max_line_bytes`` of one line in memory (longer lines are skipped and
    counted), and stops at the size observed when it started so a busy writer
    cannot keep it reading forever. A final line without its newline (a write
    in progress or a torn tail) is not yielded.
    """
    size = state.stat().st_size
    begin = max(start_offset, size - max_scan_bytes, 0)
    with state.open("rb") as handle:
        handle.seek(begin)
        position = begin
        if begin > start_offset and begin > 0:
            if scan is not None:
                scan.truncated = True
            # Resynchronize on a line boundary: the byte before ``begin`` tells
            # us whether we already are at one.
            handle.seek(begin - 1)
            if handle.read(1) != b"\n":
                skipped = _skip_to_newline(handle, size - begin)
                position = begin + skipped
            else:
                position = begin
        while position < size:
            line = handle.readline(min(max_line_bytes + 1, size - position))
            if not line:
                break
            if not line.endswith(b"\n"):
                if position + len(line) >= size:
                    break  # incomplete final line
                # overlong line: drop the rest of it without buffering it
                rest = _skip_to_newline(handle, size - position - len(line))
                position += len(line) + rest
                if scan is not None:
                    scan.overlong_lines += 1
                continue
            position += len(line)
            if scan is not None:
                scan.lines += 1
            if len(line) > max_line_bytes:
                if scan is not None:
                    scan.overlong_lines += 1
                continue
            yield position, line
        if scan is not None:
            scan.bytes_scanned = position - begin


def _skip_to_newline(handle: Any, budget: int) -> int:
    consumed = 0
    while consumed < budget:
        chunk = handle.read(min(_READ_CHUNK, budget - consumed))
        if not chunk:
            break
        index = chunk.find(b"\n")
        if index >= 0:
            consumed += index + 1
            handle.seek(handle.tell() - (len(chunk) - index - 1))
            return consumed
        consumed += len(chunk)
    return consumed


def _decode(line: bytes, scan: _Scan) -> dict[str, Any] | None:
    if not any(token in line for token in _FILTER_TOKENS):
        return None
    try:
        event = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError):
        scan.malformed_lines += 1
        return None
    if not isinstance(event, dict) or not isinstance(event.get("payload"), dict):
        return None
    scan.decoded += 1
    return event


def scan_event_log(
    state: Path, *, now: datetime, config: ProbeConfig
) -> _Scan:
    scan = _Scan()
    if not state.exists():
        raise FileNotFoundError(f"event log not found: {state}")
    window_start = now - timedelta(seconds=config.window_seconds)
    settled_before = now - timedelta(seconds=config.delivery_grace_seconds)
    for _, line in iter_log_lines(
        state, max_scan_bytes=config.max_scan_bytes, max_line_bytes=config.max_line_bytes, scan=scan,
    ):
        event = _decode(line, scan)
        if event is None:
            continue
        event_type = str(event.get("type", ""))
        task_id = str(event.get("task_id", ""))
        payload = event["payload"]
        if event_type in _OUTBOX_ITEM_EVENTS:
            _apply_outbox(scan, event_type, task_id, payload, event, window_start, settled_before, now)
        elif event_type in _EXECUTION_STATE_EVENTS:
            _apply_execution(scan, event_type, task_id, payload, event, window_start, now)
    return scan


def _in_window(event: Mapping[str, Any], window_start: datetime, now: datetime) -> datetime | None:
    stamp = parse_timestamp(event.get("timestamp"))
    if stamp is None or stamp < window_start or stamp > now + timedelta(minutes=5):
        return None
    return stamp


def _apply_outbox(
    scan: _Scan, event_type: str, task_id: str, payload: Mapping[str, Any], event: Mapping[str, Any],
    window_start: datetime, settled_before: datetime, now: datetime,
) -> None:
    target = str(payload.get("target", ""))
    inner = payload.get("payload")
    mode = str(inner.get("delivery_mode", "")) if isinstance(inner, dict) else ""
    status = str(payload.get("status", ""))
    previous = scan.items.get(task_id)
    created_at = str(payload.get("created_at", "")) or (previous[1] if previous else "")
    if target and status:
        scan.items[task_id] = (target, created_at, status, mode)
    stamp = _in_window(event, window_start, now)
    if stamp is None or not target:
        return
    scan.in_window += 1
    flow = scan.flow(target)
    if event_type == "outbox.enqueued":
        flow.enqueued += 1
        if stamp <= settled_before:
            flow.enqueued_settled += 1
    elif event_type == "outbox.delivered":
        flow.delivered += 1
    elif event_type == "outbox.attempt.failed":
        flow.attempt_failed += 1
        _count_failure(flow, payload)
    elif event_type == "outbox.dead_lettered":
        flow.dead_lettered += 1
        # A dispatcher gate refusal (a session return whose attempt is gone)
        # is a classified non-delivery, not a transport failure.
        if str(payload.get("resolved_by", "")) == "dispatcher":
            flow.dead_lettered_refused += 1
        else:
            _count_failure(flow, payload)


def _count_failure(flow: _Flow, payload: Mapping[str, Any]) -> None:
    detail = " ".join(str(payload.get("failure_detail", "") or "unspecified").split())
    flow.failures[redact_secrets(detail)[:120]] += 1


def _apply_execution(
    scan: _Scan, event_type: str, task_id: str, payload: Mapping[str, Any], event: Mapping[str, Any],
    window_start: datetime, now: datetime,
) -> None:
    previous = scan.executions.get(task_id)
    target = str(payload.get("target", "")) or (previous[0] if previous else "")
    status = payload.get("status")
    if isinstance(status, str) and status and target:
        scan.executions[task_id] = (target, status, str(payload.get("lease_expires_at", "")))
    stamp = _in_window(event, window_start, now)
    if stamp is None or not target:
        return
    scan.in_window += 1
    flow = scan.flow(target)
    if event_type == "execution.created":
        flow.executions_created += 1
    elif event_type == "execution.completed":
        flow.executions_completed += 1
    elif event_type == "execution.held":
        flow.executions_held += 1
    if event_type == "execution.dead_lettered":
        flow.executions_dead_lettered += 1
    if event_type in _LEASE_EXPIRY_TRANSITIONS and previous is not None and previous[1] == "leased":
        flow.lease_expired += 1


# --- checks -----------------------------------------------------------------


def check_transport(
    routes: Mapping[str, AgentRoute],
    *,
    environ: Mapping[str, str],
    prober: Callable[[str, int], dict[str, object]] = probe_route_endpoint,
) -> tuple[dict[str, dict[str, object]], list[Finding]]:
    findings: list[Finding] = []
    report: dict[str, dict[str, object]] = {}
    for error in validate_routes(routes, environ=environ):
        findings.append(Finding("transport", "failed", "route_config_invalid", error))
    for target, route in sorted(routes.items()):
        result = prober(str(environ.get(route.url_env, "")).strip(), route.timeout_seconds)
        entry = {
            "endpoint": str(result.get("endpoint", "")),
            "ok": bool(result.get("ok")),
            "detail": str(result.get("detail", "")),
        }
        report[target] = entry
        if not entry["ok"]:
            findings.append(Finding(
                "transport", "failed", "transport_unreachable",
                f"connect to {entry['endpoint'] or 'unresolved endpoint'} failed: {entry['detail'] or 'unknown'}",
                target,
            ))
    return report, findings


def check_ticks(state: Path, *, now: datetime, config: ProbeConfig) -> tuple[dict[str, dict[str, object]], list[Finding]]:
    findings: list[Finding] = []
    report: dict[str, dict[str, object]] = {}
    for component in config.tick_components:
        stale_after = config.stale_after(component)
        entry: dict[str, object] = {"stale_after_seconds": stale_after}
        try:
            record = read_tick_record(state, component)
        except (OSError, ValueError) as exc:
            entry.update(status="unreadable", detail=str(exc))
            findings.append(Finding("ticks", "failed", "tick_unreadable", f"{component}: {exc}"))
            report[component] = entry
            continue
        if record is None:
            entry["status"] = "missing"
            findings.append(Finding(
                "ticks", "failed", "tick_missing",
                f"{component}: no liveness record in {liveness_dir(state)}; the tick has not finished "
                "on this build or cannot write",
            ))
            report[component] = entry
            continue
        finished = parse_timestamp(record.get("finished_at"))
        assert finished is not None  # read_tick_record validated it
        signed_age = (now - finished).total_seconds()
        if signed_age < -TICK_FUTURE_SKEW_TOLERANCE_SECONDS:
            entry.update(
                status="clock_skew", finished_at=str(record.get("finished_at")),
                future_seconds=-signed_age,
                clock_skew_tolerance_seconds=TICK_FUTURE_SKEW_TOLERANCE_SECONDS,
                result=str(record.get("result", "")),
            )
            findings.append(Finding(
                "ticks", "failed", "tick_clock_skew",
                f"{component}: last tick is {-signed_age:g}s in the future "
                f"(tolerance {TICK_FUTURE_SKEW_TOLERANCE_SECONDS}s)",
            ))
            report[component] = entry
            continue
        age = max(0, int(signed_age))
        entry.update(
            status="fresh" if age <= stale_after else "stale",
            finished_at=str(record.get("finished_at")),
            age_seconds=age,
            result=str(record.get("result", "")),
            detail=str(record.get("detail", "")),
            route_revision=str(record.get("route_revision", "")),
            route_sha256=str(record.get("route_sha256", "")),
            code_version=str(record.get("code_version", "")),
        )
        if record.get("build_id"):
            entry["build_id"] = str(record["build_id"])
        if age > stale_after:
            findings.append(Finding(
                "ticks", "failed", "tick_stale",
                f"{component}: last tick finished {age}s ago (threshold {stale_after}s)",
            ))
        elif record.get("result") == "error":
            findings.append(Finding(
                "ticks", "degraded", "tick_error",
                f"{component}: last tick reported an error: {entry['detail'] or 'no detail'}",
            ))
        report[component] = entry
    return report, findings


def evaluate_flows(
    scan: _Scan, *, routes: Mapping[str, AgentRoute], now: datetime, config: ProbeConfig
) -> tuple[dict[str, dict[str, object]], list[Finding]]:
    findings: list[Finding] = []
    targets: dict[str, dict[str, object]] = {}
    oldest: dict[str, tuple[int, str, int]] = {}  # target -> (age, id, count)
    ambiguous: Counter = Counter()
    dangling_wakes: Counter = Counter()
    for item_id, (target, created_at, status, mode) in scan.items.items():
        if status == "ambiguous_delivery":
            ambiguous[target] += 1
            continue
        if status not in UNDELIVERED_STATUSES:
            continue
        if mode == EXECUTION_WAKE_MODE:
            # Execution lineage owns redelivery; an unfinalized wake record is
            # reported, never judged as a stuck delivery.
            dangling_wakes[target] += 1
            continue
        created = parse_timestamp(created_at)
        age = max(0, int((now - created).total_seconds())) if created else 0
        age_value, oldest_id, count = oldest.get(target, (-1, "", 0))
        if age > age_value:
            age_value, oldest_id = age, item_id
        oldest[target] = (age_value, oldest_id, count + 1)
    live: Counter = Counter()
    for target, status, lease_expires_at in scan.executions.values():
        if status == "pending":
            live[target] += 1
        elif status == "leased":
            expires = parse_timestamp(lease_expires_at)
            if expires is not None and expires > now:
                live[target] += 1
    names = set(routes) | set(scan.flows) | set(oldest)
    window_minutes = config.window_seconds // 60
    for target in sorted(names):
        flow = scan.flows.get(target, _Flow())
        routed = target in routes
        outcomes = flow.delivered + flow.attempt_failed + flow.dead_lettered - flow.dead_lettered_refused
        failed_outcomes = flow.attempt_failed + flow.dead_lettered - flow.dead_lettered_refused
        dead_unclassified = flow.dead_lettered - flow.dead_lettered_refused
        age, oldest_id, undelivered = oldest.get(target, (0, "", 0))
        delivery: dict[str, object] = {
            "enqueued": flow.enqueued,
            "enqueued_settled": flow.enqueued_settled,
            "delivered": flow.delivered,
            "attempt_failed": flow.attempt_failed,
            "dead_lettered": flow.dead_lettered,
            "dead_lettered_refused": flow.dead_lettered_refused,
            "failure_ratio": round(failed_outcomes / outcomes, 3) if outcomes else 0.0,
            "dead_letter_ratio": round(dead_unclassified / outcomes, 3) if outcomes else 0.0,
            "undelivered": undelivered,
            "oldest_undelivered_age_seconds": age if undelivered else None,
            "oldest_undelivered_id": oldest_id if undelivered else "",
            "ambiguous": ambiguous.get(target, 0),
            "unfinalized_execution_wakes": dangling_wakes.get(target, 0),
            "top_failures": [
                {"detail": detail, "count": count}
                for detail, count in flow.failures.most_common(config.top_failures)
            ],
        }
        execution: dict[str, object] = {
            "created": flow.executions_created,
            "completed": flow.executions_completed,
            "lease_expired": flow.lease_expired,
            "dead_lettered": flow.executions_dead_lettered,
            "held": flow.executions_held,
            "live": live.get(target, 0),
        }
        entry: dict[str, object] = {"routed": routed, "delivery": delivery, "execution": execution}
        target_findings: list[Finding] = []
        if routed:
            if flow.enqueued_settled > 0 and flow.delivered == 0:
                target_findings.append(Finding(
                    "delivery", "failed", "no_delivery_in_window",
                    f"{flow.enqueued} enqueued, 0 delivered in the last {window_minutes}m",
                    target,
                ))
            if outcomes >= config.min_outcomes_for_ratio:
                if dead_unclassified / outcomes >= config.max_dead_letter_ratio:
                    target_findings.append(Finding(
                        "delivery", "failed", "dead_letter_ratio",
                        f"{dead_unclassified}/{outcomes} outcomes dead-lettered in {window_minutes}m "
                        f"(threshold {config.max_dead_letter_ratio:.0%})",
                        target,
                    ))
                elif failed_outcomes / outcomes >= config.max_failure_ratio:
                    target_findings.append(Finding(
                        "delivery", "degraded", "failure_ratio",
                        f"{failed_outcomes}/{outcomes} attempts failed in {window_minutes}m "
                        f"(threshold {config.max_failure_ratio:.0%})",
                        target,
                    ))
            if undelivered and age > config.max_undelivered_age_seconds:
                target_findings.append(Finding(
                    "delivery", "failed", "undelivered_too_old",
                    f"{undelivered} undelivered; oldest {oldest_id} is {age}s old "
                    f"(threshold {config.max_undelivered_age_seconds}s)",
                    target,
                ))
            if flow.lease_expired > 0 and flow.executions_completed == 0:
                target_findings.append(Finding(
                    "execution", "degraded", "lease_expiries_without_completion",
                    f"{flow.lease_expired} lease expiries and 0 completions in {window_minutes}m",
                    target,
                ))
            if target_findings and delivery["top_failures"]:
                top = delivery["top_failures"][0]
                assert isinstance(top, dict)
                target_findings[0] = Finding(
                    target_findings[0].check, target_findings[0].severity, target_findings[0].code,
                    f"{target_findings[0].detail}; top failure: {top['detail']} x{top['count']}",
                    target,
                )
        findings.extend(target_findings)
        targets[target] = entry
    return targets, findings


@dataclass(frozen=True)
class ProbeReport:
    payload: dict[str, object]

    @property
    def verdict(self) -> str:
        return str(self.payload["verdict"])

    def findings(self) -> list[dict[str, str]]:
        raw = self.payload.get("findings", [])
        return list(raw) if isinstance(raw, list) else []


def run_probe(
    state: Path,
    *,
    routes: Mapping[str, AgentRoute],
    route_revision: str = "",
    route_sha256: str = "",
    now: datetime | None = None,
    config: ProbeConfig | None = None,
    environ: Mapping[str, str] | None = None,
    prober: Callable[[str, int], dict[str, object]] = probe_route_endpoint,
) -> ProbeReport:
    """Run every check and fold the findings into one verdict. Read-only."""
    config = config or ProbeConfig()
    config.validate()
    current = now or datetime.now(timezone.utc)
    env = os.environ if environ is None else environ
    findings: list[Finding] = []
    payload: dict[str, object] = {
        "schema": PROBE_SCHEMA,
        "checked_at": current.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "window_seconds": config.window_seconds,
        "route_document": {"revision": route_revision or "unversioned", "sha256": route_sha256},
    }
    if config.transport:
        transport, transport_findings = check_transport(routes, environ=env, prober=prober)
        findings.extend(transport_findings)
    else:
        transport = {}
    ticks, tick_findings = check_ticks(state, now=current, config=config)
    findings.extend(tick_findings)
    payload["ticks"] = ticks
    started = time.monotonic()
    try:
        scan = scan_event_log(state, now=current, config=config)
    except OSError as exc:
        findings.append(Finding("delivery", "failed", "event_log_unreadable", f"{type(exc).__name__}: {exc}"))
        scan = None
    duration_ms = int((time.monotonic() - started) * 1000)
    if scan is not None:
        targets, flow_findings = evaluate_flows(scan, routes=routes, now=current, config=config)
        findings.extend(flow_findings)
        payload["scan"] = {
            "bytes_scanned": scan.bytes_scanned,
            "truncated": scan.truncated,
            "lines": scan.lines,
            "decoded_events": scan.decoded,
            "window_events": scan.in_window,
            "malformed_lines": scan.malformed_lines,
            "overlong_lines": scan.overlong_lines,
            "duration_ms": duration_ms,
        }
    else:
        targets = {target: {"routed": True} for target in sorted(routes)}
    for target, entry in transport.items():
        targets.setdefault(target, {"routed": True})["transport"] = entry
    for target, entry in targets.items():
        mine = [finding for finding in findings if finding.target == target]
        entry["verdict"] = worst_verdict([finding.severity for finding in mine])
        entry["findings"] = [finding.to_dict() for finding in mine]
    payload["targets"] = targets
    payload["findings"] = [finding.to_dict() for finding in findings]
    payload["verdict"] = worst_verdict([finding.severity for finding in findings])
    return ProbeReport(payload)


def summarize(report: Mapping[str, object], *, label: str = "", max_findings: int = 5) -> tuple[str, str]:
    """Concise ``(title, text)`` for an alert or a dead-man ping body."""
    verdict = str(report.get("verdict", "failed"))
    prefix = f"[arvyx delivery probe{' ' + label if label else ''}]"
    title = f"{prefix} {verdict.upper()}"
    findings = report.get("findings", [])
    lines = []
    if isinstance(findings, list):
        for finding in findings[:max_findings]:
            if isinstance(finding, dict):
                target = f"{finding.get('target')}: " if finding.get("target") else ""
                lines.append(f"- {target}{finding.get('code')}: {finding.get('detail')}")
        if len(findings) > max_findings:
            lines.append(f"- ... {len(findings) - max_findings} more finding(s)")
    body = "\n".join(lines) if lines else "- all checks passed"
    text = f"{title} at {report.get('checked_at', '')}\n{body}"
    return title, redact_secrets(text)


# --- command ----------------------------------------------------------------


def probe_config_from_args(args: Any) -> ProbeConfig:
    components = tuple(args.tick_component) if getattr(args, "tick_component", None) else TICK_COMPONENTS
    return ProbeConfig(
        window_seconds=int(args.window_minutes * 60),
        dispatcher_interval_seconds=args.dispatcher_interval_seconds,
        worker_interval_seconds=args.worker_interval_seconds,
        stale_multiplier=args.stale_multiplier,
        tick_components=components,
        max_dead_letter_ratio=args.max_dead_letter_ratio,
        max_failure_ratio=args.max_failure_ratio,
        min_outcomes_for_ratio=args.min_outcomes,
        max_undelivered_age_seconds=int(args.max_undelivered_age_minutes * 60),
        delivery_grace_seconds=args.delivery_grace_seconds,
        max_scan_bytes=int(args.max_scan_mib * 1024 * 1024),
        transport=not args.no_transport,
    )


def run_probe_command(
    args: Any,
    *,
    stdout: Any = None,
    stderr: Any = None,
    environ: Mapping[str, str] | None = None,
    prober: Callable[[str, int], dict[str, object]] = probe_route_endpoint,
    deadman_opener: Callable[..., Any] | None = None,
) -> int:
    """``arvyx delivery probe``. Exit 0 ok, 1 degraded or failed, 2 usage/config."""
    out = stdout or sys.stdout
    err = stderr or sys.stderr
    env = os.environ if environ is None else environ
    try:
        deadman_url = load_deadman_url(
            env_name=args.deadman_url_env, file=args.deadman_url_file, environ=env,
        )
    except ValueError as exc:
        return _usage(args, f"dead-man: {exc}", out, err)

    def refuse(message: str) -> int:
        # A probe that cannot run is itself an outage of the monitor: flip the
        # external check right away instead of waiting for its grace period.
        deadman = (
            ping_deadman(deadman_url, fail=True, body=f"delivery probe refused to run: {message}",
                         timeout=args.deadman_timeout_seconds, opener=deadman_opener)
            if deadman_url else None
        )
        return _usage(args, message, out, err, deadman=deadman)

    notifier = None
    if args.notify_config is not None:
        try:
            notifier = build_notifier_from_config(args.notify_config, stdout_stream=err)
        except (OSError, ValueError) as exc:
            return refuse(f"notifier: {exc}")
    try:
        config = probe_config_from_args(args)
        config.validate()
        if args.realert_hours <= 0:
            raise ValueError("re-alert interval must be positive")
        now = parse_timestamp(args.now) if args.now else datetime.now(timezone.utc)
        if now is None:
            raise ValueError("--now must be a timezone-aware RFC3339 instant")
    except ValueError as exc:
        return refuse(str(exc))
    try:
        document = load_route_document(args.routes)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return refuse(f"invalid routes: {exc}")
    if not document.routes:
        return refuse("no delivery routes configured")

    report = run_probe(
        args.state,
        routes=document.routes,
        route_revision=document.revision,
        route_sha256=document.attested_sha256,
        now=now,
        config=config,
        environ=env,
        prober=prober,
    )
    payload = dict(report.payload)
    title, text = summarize(payload, label=args.label)
    if notifier is not None:
        payload["alert"] = run_alerting(
            state_path=liveness_dir(args.state) / PROBE_ALERT_STATE_NAME,
            verdict=report.verdict,
            title=title,
            text=text,
            notifier=notifier,
            now=now,
            realert_seconds=int(args.realert_hours * 3600),
            kind="delivery_probe",
        )
    if deadman_url:
        payload["deadman"] = ping_deadman(
            deadman_url, fail=report.verdict == "failed", body=text,
            timeout=args.deadman_timeout_seconds, opener=deadman_opener,
        )
    if args.json_output:
        print(json.dumps(payload, sort_keys=True), file=out)
    else:
        _print_human(payload, out)
    return EXIT_OK if report.verdict == "ok" else EXIT_ALERT


def _usage(args: Any, message: str, out: Any, err: Any, *, deadman: Mapping[str, object] | None = None) -> int:
    if getattr(args, "json_output", False):
        payload: dict[str, object] = {"schema": PROBE_SCHEMA, "ok": False, "verdict": "error", "error": message}
        if deadman is not None:
            payload["deadman"] = dict(deadman)
        print(json.dumps(payload, sort_keys=True), file=out)
    else:
        print(f"error: {message}", file=err)
    return EXIT_USAGE


def _print_human(payload: Mapping[str, object], out: Any) -> None:
    verdict = str(payload.get("verdict", "failed")).upper()
    window = int(str(payload.get("window_seconds", 0))) // 60
    print(f"DELIVERY PROBE {verdict} checked_at={payload.get('checked_at')} window={window}m", file=out)
    findings = payload.get("findings", [])
    for finding in findings if isinstance(findings, list) else []:
        target = f" {finding.get('target')}" if finding.get("target") else ""
        print(f"- [{finding.get('severity')}] {finding.get('check')}{target} {finding.get('code')}: "
              f"{finding.get('detail')}", file=out)
    ticks = payload.get("ticks", {})
    for component, entry in (ticks.items() if isinstance(ticks, dict) else []):
        print(f"tick {component}: {entry.get('status')} age={entry.get('age_seconds', '-')}s "
              f"result={entry.get('result', '-')}", file=out)
    targets = payload.get("targets", {})
    for target, entry in (targets.items() if isinstance(targets, dict) else []):
        delivery = entry.get("delivery", {}) if isinstance(entry, dict) else {}
        execution = entry.get("execution", {}) if isinstance(entry, dict) else {}
        transport = entry.get("transport", {}) if isinstance(entry, dict) else {}
        print(
            f"target {target}: {entry.get('verdict')} routed={entry.get('routed')} "
            f"transport={'ok' if transport.get('ok') else transport.get('detail', '-') if transport else '-'} "
            f"enqueued={delivery.get('enqueued', 0)} delivered={delivery.get('delivered', 0)} "
            f"failed={delivery.get('attempt_failed', 0)} dead={delivery.get('dead_lettered', 0)} "
            f"undelivered={delivery.get('undelivered', 0)} "
            f"exec_created={execution.get('created', 0)} exec_completed={execution.get('completed', 0)} "
            f"lease_expired={execution.get('lease_expired', 0)} live={execution.get('live', 0)}",
            file=out,
        )
    alert = payload.get("alert")
    if isinstance(alert, dict):
        print(f"alert: {alert.get('reason')} {alert.get('status', '')}".rstrip(), file=out)
    deadman = payload.get("deadman")
    if isinstance(deadman, dict):
        print(f"deadman: {deadman.get('endpoint')} {deadman.get('status')}", file=out)
