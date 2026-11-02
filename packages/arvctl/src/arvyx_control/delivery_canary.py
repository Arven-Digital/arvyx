"""Identity-bound end-to-end delivery canary.

``arvyx delivery canary`` is the explicit, daily "does the whole chain work"
check. It is not part of the read-only probe because it deliberately wakes a
real agent:

1. ``thread_created``      - an identity-bound agent token posts one ``ask``
                             thread (clearly marked as a canary) to the target
                             through the HTTP API, with an idempotency key;
2. ``execution_created``   - the assignment materialized an execution;
3. ``wake_delivered``      - the execution worker's wake has a resolvable
                             delivery record that reached ``delivered``;
4. ``target_heartbeat``    - the target heartbeated the live attempt under
                             its own identity;
5. ``execution_completed`` - the execution completed from an identity-bound
                             ``thread.done`` written by the target;
6. ``thread_done_readback``- the canary author reads the thread back through
                             the API (``control.thread_get``) as done by the
                             target.

Why the middle legs are read from the event log: the canary author's agent
token can, by design, only read threads it authored. Execution, delivery and
heartbeat records belong to the target and fail closed for any other identity,
and the operator-facing execution event history is size-capped. The canary
therefore never borrows another credential: it observes legs 2-5 read-only
from the authoritative control log on the host (streamed from the byte offset
the log had before the canary thread existed), and proves the API path at both
ends with its own identity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.client import HTTPException
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import sys
import time
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request

from .delivery_probe import iter_log_lines
from .execution import _execution_id
from .liveness import (
    liveness_dir,
    load_deadman_url,
    ping_deadman,
    run_alerting,
)
from .notifiers import build_notifier_from_config
from .outbox import EXECUTION_WAKE_MODE
from .security import redact_secrets

CANARY_SCHEMA = "v2.delivery-canary/1"
CANARY_MARKER = "[arvyx-canary]"
CANARY_ALERT_STATE_NAME = "delivery-canary-alert.json"
LEGS = (
    "thread_created",
    "execution_created",
    "wake_delivered",
    "target_heartbeat",
    "execution_completed",
    "thread_done_readback",
)
EXIT_OK = 0
EXIT_ALERT = 1
EXIT_USAGE = 2
_NEGATIVE_EXECUTION_STATUSES = frozenset({"dead_lettered", "held", "closed", "paused"})
_RESPONSE_MAX_BYTES = 1024 * 1024
_TOKEN_RE = re.compile(r"[!-~]{32,4096}")
_TARGET_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_LOG_SCAN_BUDGET = 1024 * 1024 * 1024

HttpCall = Callable[[str, str, "dict[str, Any] | None", Mapping[str, str], float], "tuple[int, Any]"]



# No redirects (the bearer token must never follow one) and no proxy: the
# control API is loopback/tailnet-local and an agent token must not transit an
# egress proxy.
from .http_bounds import BoundedOpener
_API_OPENER = BoundedOpener()


def http_json(
    method: str, url: str, body: dict[str, Any] | None, headers: Mapping[str, str], timeout: float
) -> tuple[int, Any]:
    """One bounded JSON request; returns ``(status, parsed body or None)``."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = Request(url, data=data, headers=dict(headers), method=method)
    try:
        with _API_OPENER.open(request, timeout=timeout) as response:
            status = int(response.status)
            raw = response.read(_RESPONSE_MAX_BYTES + 1)
    except HTTPError as exc:
        status = int(exc.code)
        try:
            raw = exc.read(_RESPONSE_MAX_BYTES + 1)
        except (OSError, HTTPException):
            raw = b""
        finally:
            exc.close()
    except HTTPException as exc:
        # a torn or malformed response is an unreachable API, not a crash
        raise OSError(type(exc).__name__) from exc
    if len(raw) > _RESPONSE_MAX_BYTES:
        return status, None
    try:
        return status, json.loads(raw.decode("utf-8")) if raw else None
    except (UnicodeDecodeError, json.JSONDecodeError):
        return status, None


def validate_api_url(url: str) -> str:
    url = url.strip().rstrip("/")
    parts = urlsplit(url)
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise ValueError("--api must be an http(s) URL")
    if parts.username or parts.password:
        raise ValueError("--api must not embed credentials")
    if parts.query or parts.fragment:
        raise ValueError("--api must not carry a query or fragment")
    if parts.scheme.lower() != "https" and not _is_loopback(parts.hostname):
        raise ValueError("--api must use https unless it is a loopback address (the agent token rides along)")
    return url


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass
class _Leg:
    ok: bool = False
    at: str = ""
    detail: str = ""

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {"ok": self.ok}
        if self.at:
            payload["at"] = self.at
        if self.detail:
            payload["detail"] = self.detail
        return payload


@dataclass
class ChainObserver:
    """Incremental, read-only reader of the control log for one canary subject."""

    state: Path
    thread_id: str
    target: str
    offset: int
    execution_id: str = ""
    legs: dict[str, _Leg] = field(default_factory=lambda: {leg: _Leg() for leg in LEGS})
    execution_status: str = ""
    attempts: int = 0
    terminal_detail: str = ""
    wake_failures: list[str] = field(default_factory=list)
    malformed_lines: int = 0
    bound_done_event_id: str = ""

    def __post_init__(self) -> None:
        if not self.execution_id:
            self.execution_id = _execution_id("thread", self.thread_id, self.target)

    @property
    def negative_terminal(self) -> bool:
        return self.execution_status in _NEGATIVE_EXECUTION_STATUSES

    @property
    def log_legs_done(self) -> bool:
        return all(self.legs[leg].ok for leg in LEGS[1:5])

    def poll(self) -> None:
        try:
            size = self.state.stat().st_size
        except OSError as exc:
            self.terminal_detail = f"event log unreadable: {type(exc).__name__}"
            return
        if size < self.offset:
            # compaction/rotation under our feet: rescan from the start; the
            # filters below are exact, so earlier unrelated lines are ignored
            self.offset = 0
        needles = (self.thread_id.encode(), self.execution_id.encode())
        for end, line in iter_log_lines(
            self.state, max_scan_bytes=_LOG_SCAN_BUDGET, max_line_bytes=4 * 1024 * 1024,
            start_offset=self.offset,
        ):
            self.offset = end
            if not any(needle in line for needle in needles):
                continue
            try:
                event = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError):
                self.malformed_lines += 1
                continue
            if isinstance(event, dict) and isinstance(event.get("payload"), dict):
                self._apply(event)

    def _mark(self, leg: str, event: Mapping[str, Any], detail: str = "") -> None:
        entry = self.legs[leg]
        if not entry.ok:
            entry.ok = True
            entry.at = str(event.get("timestamp", ""))
            entry.detail = detail

    def _apply(self, event: Mapping[str, Any]) -> None:
        event_type = str(event.get("type", ""))
        task_id = str(event.get("task_id", ""))
        payload: Mapping[str, Any] = event["payload"]
        if task_id == self.thread_id and event_type == "thread.done":
            self.bound_done_event_id = (
                str(event.get("id", ""))
                if payload.get("actor_identity_bound") is True
                and str(payload.get("done_by", "")).strip().casefold() == self.target
                and str(payload.get("id", "")) == self.thread_id
                else ""
            )
            return
        if task_id == self.execution_id and event_type.startswith("execution."):
            status = payload.get("status")
            if isinstance(status, str) and status:
                self.execution_status = status
            attempts = payload.get("attempts")
            if isinstance(attempts, int) and not isinstance(attempts, bool):
                self.attempts = max(self.attempts, attempts)
            if event_type == "execution.created":
                if str(payload.get("subject_id", "")) == self.thread_id and str(payload.get("target", "")) == self.target:
                    self._mark("execution_created", event)
            elif event_type == "execution.heartbeat":
                if (
                    payload.get("actor_identity_bound") is True
                    and str(payload.get("heartbeat_by", "")).strip().casefold() == self.target
                ):
                    self._mark("target_heartbeat", event, f"attempt {payload.get('attempt_id', '')}")
            elif event_type == "execution.completed":
                if (
                    payload.get("terminal_event_type") == "thread.done"
                    and self.bound_done_event_id
                    and payload.get("terminal_event_id") == self.bound_done_event_id
                    and payload.get("subject_type") == "thread"
                    and payload.get("subject_id") == self.thread_id
                    and payload.get("target") == self.target
                ):
                    self._mark("execution_completed", event, f"terminal {payload.get('terminal_event_id', '')}")
            if self.execution_status in _NEGATIVE_EXECUTION_STATUSES:
                reason = payload.get("hold_reason") or payload.get("last_failure") or payload.get("close_reason") or ""
                self.terminal_detail = redact_secrets(
                    f"execution {self.execution_status}: {' '.join(str(reason).split())}"
                )[:300]
            return
        if event_type.startswith("outbox.") and event_type != "outbox.dispatcher.tick":
            inner = payload.get("payload")
            if (
                isinstance(inner, dict)
                and inner.get("delivery_mode") == EXECUTION_WAKE_MODE
                and inner.get("execution_id") == self.execution_id
            ):
                status = str(payload.get("status", ""))
                if status == "delivered":
                    self._mark("wake_delivered", event, f"delivery {payload.get('id', '')}")
                elif status == "dead_lettered":
                    detail = " ".join(str(payload.get("failure_detail", "") or "wake rejected").split())
                    self.wake_failures.append(redact_secrets(detail)[:200])


@dataclass(frozen=True)
class CanaryOptions:
    api: str
    bearer: str
    target: str
    state: Path
    timeout_seconds: int = 900
    poll_seconds: float = 15.0
    http_timeout_seconds: float = 10.0
    label: str = ""


def run_canary(
    options: CanaryOptions,
    *,
    http: HttpCall = http_json,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, object]:
    """Create one canary thread and classify how far the chain got."""
    started = clock()
    deadline = started + options.timeout_seconds
    stamp = now().astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"canary-{stamp}-{secrets.token_hex(4)}"
    report: dict[str, object] = {
        "schema": CANARY_SCHEMA,
        "run_id": run_id,
        "target": options.target,
        "started_at": now().astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    legs = {leg: _Leg() for leg in LEGS}
    headers = {
        "Authorization": f"Bearer {options.bearer}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    # The offset is taken before the thread exists, so every event of this run
    # lies after it and the observer never rereads the history.
    try:
        offset = options.state.stat().st_size
    except OSError as exc:
        return _finish(report, legs, None, started, clock, f"event log unreadable: {type(exc).__name__}")

    idempotency_key = f"delivery-{run_id}"
    body = {
        "title": f"{CANARY_MARKER} delivery chain check {run_id}",
        "body": (
            f"{CANARY_MARKER} Automated end-to-end delivery canary (run {run_id}). No work is requested. "
            "Heartbeat your live execution attempt, then complete this thread with control.thread_done "
            "under your own identity (text: canary ok). Do not reply elsewhere."
        ),
        "type": "ask",
        "target": options.target,
        "channel": "ops",
        "severity": "info",
        "idempotency_key": idempotency_key,
    }
    try:
        status, response = http(
            "POST", f"{options.api}/threads", body, {**headers, "Idempotency-Key": idempotency_key},
            options.http_timeout_seconds,
        )
    except (URLError, OSError, ValueError) as exc:
        legs["thread_created"].detail = f"API unreachable: {type(exc).__name__}"
        return _finish(report, legs, None, started, clock, "")
    # REST dictionaries are serialized as {status, body} by ArvyxApiHandler.
    # Keep raw bodies usable by explicitly injected in-process transports, but
    # never bypass a malformed body in a transport that supplied an envelope.
    if isinstance(response, dict) and 'body' in response:
        response = response['body']
    thread = response.get("thread") if isinstance(response, dict) else None
    if status != 201 or not isinstance(thread, dict) or not thread.get("id"):
        error = response.get("error") if isinstance(response, dict) else ""
        legs["thread_created"].detail = redact_secrets(f"HTTP {status}: {error or 'unexpected response'}")[:300]
        return _finish(report, legs, None, started, clock, "")
    thread_id = str(thread["id"])
    report["thread_id"] = thread_id
    event_payload = (response.get("event") or {}).get("payload") if isinstance(response.get("event"), dict) else {}
    if (
        not isinstance(event_payload, dict)
        or event_payload.get("actor_identity_bound") is not True
        or event_payload.get("id") != thread_id
        or event_payload.get("target") != options.target
        or thread.get("target") != options.target
        or not isinstance(thread.get("actor"), str)
        or not thread["actor"].strip()
        or event_payload.get("actor") != thread["actor"]
    ):
        legs["thread_created"].detail = (
            "thread was created but is not identity-bound, so no execution can materialize: "
            "--auth-env must hold the canary agent's own token, not the operator secret"
        )
        return _finish(report, legs, None, started, clock, "")
    legs["thread_created"] = _Leg(True, str(thread.get("created_at", "")), f"author {thread.get('actor', '')}")

    observer = ChainObserver(options.state, thread_id, options.target, offset)
    observer.legs["thread_created"] = legs["thread_created"]
    report["execution_id"] = observer.execution_id
    while True:
        observer.poll()
        if observer.log_legs_done or observer.negative_terminal or observer.terminal_detail.startswith("event log"):
            break
        if clock() >= deadline:
            break
        sleep(min(options.poll_seconds, max(0.0, deadline - clock())))

    readback = observer.legs["thread_done_readback"]
    thread_status = _read_thread(options, http, headers, thread_id)
    report["thread"] = thread_status
    if (
        thread_status.get("status") == "done"
        and str(thread_status.get("done_by", "")).strip().casefold() == options.target
        and thread_status.get("id") == thread_id
        and observer.bound_done_event_id
    ):
        readback.ok = True
        readback.at = str(thread_status.get("done_at", ""))
    else:
        readback.detail = str(thread_status.get("error") or f"thread status {thread_status.get('status', 'unknown')}")
    if observer.wake_failures and not observer.legs["wake_delivered"].ok:
        observer.legs["wake_delivered"].detail = f"last wake failure: {observer.wake_failures[-1]}"
    report["execution_status"] = observer.execution_status
    report["attempts"] = observer.attempts
    return _finish(report, observer.legs, observer, started, clock, observer.terminal_detail)


def _read_thread(
    options: CanaryOptions, http: HttpCall, headers: Mapping[str, str], thread_id: str
) -> dict[str, object]:
    """Read the canary thread back as its author (read tool: no idempotency key)."""
    rpc = {
        "jsonrpc": "2.0",
        "id": "delivery-canary-readback",
        "method": "tools/call",
        "params": {"name": "control.thread_get", "arguments": {"thread_id": thread_id}},
    }
    try:
        status, response = http("POST", f"{options.api}/mcp", rpc, headers, options.http_timeout_seconds)
    except (URLError, OSError, ValueError) as exc:
        return {"error": f"API unreachable: {type(exc).__name__}"}
    if status != 200 or not isinstance(response, dict):
        return {"error": f"HTTP {status}"}
    if isinstance(response.get("error"), dict):
        return {"error": redact_secrets(str(response["error"].get("message", "tool error")))[:300]}
    result = response.get("result")
    structured = result.get("structuredContent") if isinstance(result, dict) else None
    thread = structured.get("thread") if isinstance(structured, dict) else None
    if not isinstance(thread, dict):
        return {"error": "thread readback returned no thread"}
    return {
        "id": str(thread.get("id", "")),
        "status": str(thread.get("status", "")),
        "acked_by": str(thread.get("acked_by", "")),
        "done_by": str(thread.get("done_by", "")),
        "done_at": str(thread.get("done_at", "")),
    }


def _finish(
    report: dict[str, object],
    legs: Mapping[str, _Leg],
    observer: ChainObserver | None,
    started: float,
    clock: Callable[[], float],
    terminal_detail: str,
) -> dict[str, object]:
    missing = [leg for leg in LEGS if not legs[leg].ok]
    stopped_at = missing[0] if missing else None
    if not missing:
        verdict = "ok"
    elif missing == ["target_heartbeat"]:
        # Completed and read back, but the target never heartbeated its attempt.
        verdict = "degraded"
    else:
        verdict = "failed"
    if stopped_at and terminal_detail and not legs[stopped_at].detail:
        legs[stopped_at].detail = terminal_detail
    report["legs"] = {leg: legs[leg].to_dict() for leg in LEGS}
    report["stopped_at"] = stopped_at
    report["verdict"] = verdict
    report["elapsed_seconds"] = round(clock() - started, 1)
    if observer is not None and observer.malformed_lines:
        report["malformed_lines"] = observer.malformed_lines
    return report


def summarize_canary(report: Mapping[str, object], *, label: str = "") -> tuple[str, str]:
    verdict = str(report.get("verdict", "failed"))
    prefix = f"[arvyx delivery canary{' ' + label if label else ''}]"
    stopped = report.get("stopped_at")
    title = f"{prefix} {verdict.upper()}" + (f": stopped at {stopped}" if stopped else "")
    legs = report.get("legs", {})
    lines = []
    for leg in LEGS:
        entry = legs.get(leg, {}) if isinstance(legs, dict) else {}
        mark = "ok" if isinstance(entry, dict) and entry.get("ok") else "--"
        detail = f" ({entry.get('detail')})" if isinstance(entry, dict) and entry.get("detail") else ""
        lines.append(f"{mark} {leg}{detail}")
    text = (
        f"{title}\ntarget={report.get('target')} run={report.get('run_id')} "
        f"elapsed={report.get('elapsed_seconds')}s\n" + "\n".join(lines)
    )
    return title, redact_secrets(text)


# --- command ----------------------------------------------------------------


def _token(auth_env: str | None, auth_file: Path | None, environ: Mapping[str, str]) -> str:
    if bool(auth_env) == (auth_file is not None):
        raise ValueError("exactly one of --auth-env or --auth-file is required")
    if auth_env:
        value = str(environ.get(auth_env, ""))
        source = f"environment variable {auth_env}"
    else:
        assert auth_file is not None
        if auth_file.is_symlink() or not auth_file.is_file():
            raise ValueError("auth file must be a regular non-symlink file")
        raw = auth_file.read_bytes()[:4097]
        value = raw.decode("utf-8", errors="replace").strip()
        if len(raw) > 4096 or "\n" in value:
            raise ValueError("auth file must contain exactly one token line")
        source = "auth file"
    if not _TOKEN_RE.fullmatch(value):
        raise ValueError(f"{source} must hold one 32-4096 character printable ASCII agent token")
    return value


def run_canary_command(
    args: Any,
    *,
    stdout: Any = None,
    stderr: Any = None,
    environ: Mapping[str, str] | None = None,
    http: HttpCall = http_json,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    deadman_opener: Callable[..., Any] | None = None,
) -> int:
    """``arvyx delivery canary``. Exit 0 ok, 1 degraded or failed, 2 usage/config."""
    out = stdout or sys.stdout
    err = stderr or sys.stderr
    env = os.environ if environ is None else environ
    try:
        deadman_url = load_deadman_url(env_name=args.deadman_url_env, file=args.deadman_url_file, environ=env)
    except ValueError as exc:
        return _usage(args, f"dead-man: {exc}", out, err)

    def refuse(message: str) -> int:
        deadman = (
            ping_deadman(deadman_url, fail=True, body=f"delivery canary refused to run: {message}",
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
        api = validate_api_url(args.api)
        token = _token(args.auth_env, args.auth_file, env)
        target = args.target.strip().casefold()
        if not _TARGET_RE.fullmatch(target) or target == "all":
            raise ValueError("--target must be one concrete canonical agent id")
        if not 30 <= args.timeout_seconds <= 3600:
            raise ValueError("--timeout-seconds must be between 30 and 3600")
        if not 1 <= args.poll_seconds <= 300:
            raise ValueError("--poll-seconds must be between 1 and 300")
        if args.realert_hours <= 0:
            raise ValueError("re-alert interval must be positive")
        if not args.state.is_file():
            raise ValueError(f"event log not found: {args.state}")
        with args.state.open("rb") as handle:
            handle.read(1)
    except (OSError, ValueError) as exc:
        return refuse(str(exc))

    options = CanaryOptions(
        api=api, bearer=token, target=target, state=args.state,
        timeout_seconds=args.timeout_seconds, poll_seconds=float(args.poll_seconds),
        http_timeout_seconds=float(args.http_timeout_seconds), label=args.label,
    )
    report = run_canary(options, http=http, sleep=sleep, clock=clock)
    title, text = summarize_canary(report, label=args.label)
    current = datetime.now(timezone.utc)
    verdict = str(report["verdict"])
    if notifier is not None:
        report["alert"] = run_alerting(
            state_path=liveness_dir(args.state) / CANARY_ALERT_STATE_NAME,
            verdict=verdict,
            title=title,
            text=text,
            notifier=notifier,
            now=current,
            realert_seconds=int(args.realert_hours * 3600),
            kind="delivery_canary",
        )
    if deadman_url:
        report["deadman"] = ping_deadman(
            deadman_url, fail=verdict == "failed", body=text,
            timeout=args.deadman_timeout_seconds, opener=deadman_opener,
        )
    if args.json_output:
        print(json.dumps(report, sort_keys=True), file=out)
    else:
        print(text, file=out)
        alert = report.get("alert")
        if isinstance(alert, dict):
            print(f"alert: {alert.get('reason')} {alert.get('status', '')}".rstrip(), file=out)
        deadman = report.get("deadman")
        if isinstance(deadman, dict):
            print(f"deadman: {deadman.get('endpoint')} {deadman.get('status')}", file=out)
    return EXIT_OK if verdict == "ok" else EXIT_ALERT


def _usage(args: Any, message: str, out: Any, err: Any, *, deadman: Mapping[str, object] | None = None) -> int:
    if getattr(args, "json_output", False):
        payload: dict[str, object] = {"schema": CANARY_SCHEMA, "ok": False, "verdict": "error", "error": message}
        if deadman is not None:
            payload["deadman"] = dict(deadman)
        print(json.dumps(payload, sort_keys=True), file=out)
    else:
        print(f"error: {message}", file=err)
    return EXIT_USAGE

