"""Operational liveness telemetry and out-of-band alert plumbing.

Tick records answer one question the append-only control log cannot answer
cheaply: *did the periodic tick actually finish, and when?* A dispatcher or
execution-worker tick that never starts (a dead timer, a ``docker exec`` into a
recreated container) leaves no trace in the event log, so a probe that only
reads domain events cannot tell "idle" from "dead".

Each tick therefore overwrites one small JSON record in a per-state namespace
beneath the sibling ``liveness/`` directory. The records are operational telemetry, not
domain events: they never enter the event log, they are replaced (not
appended), and a failure to write one is swallowed with a one-line stderr note
so telemetry can never break or slow the tick it describes.

The same directory holds the delivery probe's alert-dedupe state. Alerts and
dead-man pings leave through channels that do not depend on the thread/outbox
path under observation (see ``docs/runbooks/delivery-liveness.md``).
"""

from __future__ import annotations

from . import safe_open
from .diagnostics import capture

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import hashlib
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any, Callable, Mapping, TextIO
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request

from . import __version__
from .locks import exclusive_lock
from .security import contains_literal_secret, redact_secrets

LIVENESS_DIRNAME = "liveness"
TICK_RECORD_SCHEMA = "v2.tick-liveness/1"
TICK_RESULTS = ("ok", "idle", "error")
DISPATCHER_COMPONENT = "dispatcher"
WORKER_COMPONENT = "execution-worker"
TICK_COMPONENTS = (DISPATCHER_COMPONENT, WORKER_COMPONENT)
TICK_DETAIL_MAX_CHARS = 240
TICK_RECORD_MAX_BYTES = 16 * 1024
BUILD_ID_ENV = "ARVYX_RELEASE_BUILD_ID"
_COMPONENT_RE = re.compile(r"[a-z][a-z0-9-]{0,47}")
_BUILD_ID_RE = re.compile(r"[A-Za-z0-9._:+-]{1,64}")

ALERT_STATE_SCHEMA = "v2.liveness-alert-state/1"
DEFAULT_REALERT_SECONDS = 6 * 3600
VERDICTS = ("ok", "degraded", "failed")
_VERDICT_RANK = {"ok": 0, "degraded": 1, "failed": 2}
ALERT_TEXT_MAX_CHARS = 1200

DEADMAN_TIMEOUT_SECONDS = 10.0
DEADMAN_BODY_MAX_BYTES = 2048


def state_identity(state: Path) -> str:
    """Identify a state within its mounted directory, independent of mount prefix.

    Host and container paths mount the same directory under different absolute
    prefixes. The filename distinguishes sibling authorities within that
    directory; neither the absolute path nor the replaceable log inode does.
    """
    return hashlib.sha256(os.fsencode(state.resolve().name)).hexdigest()


def liveness_dir(state: Path) -> Path:
    """A per-state namespace beneath the shared telemetry directory."""
    resolved = state.resolve()
    return resolved.parent / LIVENESS_DIRNAME / ("state-" + state_identity(resolved))


def tick_record_path(state: Path, component: str) -> Path:
    if not _COMPONENT_RE.fullmatch(component):
        raise ValueError(f"invalid liveness component name: {component!r}")
    return liveness_dir(state) / f"{component}.json"


def _timestamp(value: datetime | None = None) -> str:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("liveness timestamps must be timezone-aware")
    return current.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_timestamp(value: object) -> datetime | None:
    """Parse an RFC3339 instant; ``None`` for anything malformed or naive."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def _code_version(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    env = os.environ if environ is None else environ
    version = {"code_version": __version__}
    build_id = str(env.get(BUILD_ID_ENV, "")).strip()
    if build_id and _BUILD_ID_RE.fullmatch(build_id):
        version["build_id"] = build_id
    return version


def _atomic_write_json(path: Path, payload: Mapping[str, object]) -> None:
    """Write-temp-then-rename in the destination directory.

    Readers see either the previous complete record or the new one, never a
    torn write. No fsync: this is telemetry, and a lost record after a power
    cut is indistinguishable from a tick that did not run, which the probe
    already treats as stale.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        safe_open.replace_path(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def write_tick_record(
    state: Path,
    *,
    component: str,
    result: str,
    detail: str = "",
    route_revision: str = "",
    route_sha256: str = "",
    now: datetime | None = None,
    environ: Mapping[str, str] | None = None,
    stderr: TextIO | None = None,
) -> bool:
    """Record that one tick finished. Never raises; returns whether it wrote.

    ``result`` is ``ok`` (did work), ``idle`` (nothing to do) or ``error``
    (the tick ran and reported a failure). Any other value is recorded as
    ``error`` so a caller bug cannot masquerade as health.
    """
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    try:
        path = tick_record_path(state, component)
        record: dict[str, object] = {
            "schema": TICK_RECORD_SCHEMA,
            "state_id": state_identity(state),
            "component": component,
            "finished_at": _timestamp(now),
            "result": result if result in TICK_RESULTS else "error",
            "detail": redact_secrets(" ".join(str(detail).split()))[:TICK_DETAIL_MAX_CHARS],
            "route_revision": str(route_revision or "")[:128],
            "route_sha256": str(route_sha256 or "")[:64],
            "pid": os.getpid(),
            **_code_version(environ),
        }
        _atomic_write_json(path, record)
        return True
    except Exception as exc:  # telemetry must never break the tick
        capture(exc, component="liveness", code="tick_record")
        try:
            print(
                f"warning: liveness record for {component!r} not written: {type(exc).__name__}",
                file=stderr or sys.stderr,
            )
        except Exception:
            pass
        return False


def read_tick_record(state: Path, component: str) -> dict[str, object] | None:
    """Load one tick record; ``None`` when absent. Raises ``ValueError`` when corrupt."""
    path = tick_record_path(state, component)
    try:
        with path.open("rb") as handle:
            raw = handle.read(TICK_RECORD_MAX_BYTES + 1)
    except FileNotFoundError:
        return None
    if len(raw) > TICK_RECORD_MAX_BYTES:
        raise ValueError("liveness record is too large")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("liveness record is not valid JSON") from exc
    if not isinstance(payload, dict) or payload.get("component") != component:
        raise ValueError("liveness record does not describe this component")
    if payload.get("schema") != TICK_RECORD_SCHEMA or payload.get("state_id") != state_identity(state):
        raise ValueError("liveness record does not describe this state")
    if parse_timestamp(payload.get("finished_at")) is None:
        raise ValueError("liveness record has no valid finished_at")
    return payload


# --- alert dedupe -----------------------------------------------------------


@dataclass(frozen=True)
class AlertDecision:
    send: bool
    reason: str  # transition | recovery | realert | suppressed | steady_ok
    alerted_verdict: str


def worst_verdict(verdicts: list[str]) -> str:
    worst = "ok"
    for verdict in verdicts:
        if _VERDICT_RANK.get(verdict, 2) > _VERDICT_RANK[worst]:
            worst = verdict if verdict in _VERDICT_RANK else "failed"
    return worst


def load_alert_state(path: Path) -> tuple[dict[str, object], str]:
    """Return ``(state, note)``. A missing or corrupt file starts from ok."""
    default: dict[str, object] = {"schema": ALERT_STATE_SCHEMA, "alerted_verdict": "ok", "last_alert_at": ""}
    namespace = path.parent.name
    if re.fullmatch(r"state-[0-9a-f]{64}", namespace):
        default["state_id"] = namespace.removeprefix("state-")
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return default, ""
    except OSError as exc:
        return default, f"alert state unreadable: {type(exc).__name__}"
    try:
        payload = json.loads(raw[:TICK_RECORD_MAX_BYTES].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return default, "alert state was corrupt and has been reset"
    if not isinstance(payload, dict) or payload.get("alerted_verdict") not in _VERDICT_RANK:
        return default, "alert state was corrupt and has been reset"
    if "state_id" in default and payload.get("state_id") != default["state_id"]:
        return default, "alert state binding did not match and has been reset"
    return {**default, **payload}, ""


def decide_alert(
    state: Mapping[str, object], verdict: str, *, now: datetime, realert_seconds: int
) -> AlertDecision:
    """Alert on a verdict change, and re-alert while still failing.

    The state remembers the verdict the last *successful* alert announced, not
    merely the last verdict observed, so a notifier outage delays an alert
    instead of losing it: the next run sees the same unannounced change.
    """
    alerted = str(state.get("alerted_verdict", "ok"))
    uncertain = state.get("uncertain_verdict")
    if isinstance(uncertain, str) and uncertain in _VERDICT_RANK:
        last_uncertain = parse_timestamp(state.get("last_uncertain_at"))
        if verdict == uncertain and last_uncertain is not None:
            if (now - last_uncertain).total_seconds() < realert_seconds:
                return AlertDecision(False, "uncertain_suppressed", alerted)
            return AlertDecision(True, "uncertain_realert", alerted)
        # A changed observation still needs announcing, including recovery
        # after an alert that may have reached the operator.
        return AlertDecision(True, "recovery" if verdict == "ok" else "transition", alerted)
    if alerted not in _VERDICT_RANK:
        alerted = "ok"
    if verdict != alerted:
        return AlertDecision(True, "recovery" if verdict == "ok" else "transition", alerted)
    if verdict == "ok":
        return AlertDecision(False, "steady_ok", alerted)
    last = parse_timestamp(state.get("last_alert_at"))
    if last is None or (now - last).total_seconds() >= realert_seconds:
        return AlertDecision(True, "realert", alerted)
    return AlertDecision(False, "suppressed", alerted)


def run_alerting(
    *,
    state_path: Path,
    verdict: str,
    title: str,
    text: str,
    notifier: Any,
    now: datetime,
    realert_seconds: int = DEFAULT_REALERT_SECONDS,
    kind: str = "delivery_liveness",
) -> dict[str, object]:
    """Decide, send at most one alert, and persist the dedupe state.

    Never raises and never changes the caller's verdict: a notifier or state
    failure is reported in the returned dict.
    """
    report: dict[str, object] = {"configured": notifier is not None}
    if notifier is None:
        report["reason"] = "not_configured"
        return report
    try:
        with exclusive_lock(state_path.with_name(state_path.name + ".lock")):
            state, note = load_alert_state(state_path)
            if note:
                report["state_note"] = note
            decision = decide_alert(state, verdict, now=now, realert_seconds=realert_seconds)
            report["reason"] = decision.reason
            report["previous_alerted_verdict"] = decision.alerted_verdict
            observed_since = str(state.get("observed_since", ""))
            if state.get("observed_verdict") != verdict or not observed_since:
                observed_since = _timestamp(now)
            state = {
                **state,
                "schema": ALERT_STATE_SCHEMA,
                "observed_verdict": verdict,
                "observed_since": observed_since,
                "last_run_at": _timestamp(now),
            }
            if decision.send:
                severity = {"ok": "info", "degraded": "warn", "failed": "critical"}.get(verdict, "critical")
                candidate = {
                    "kind": kind,
                    "thread_id": "",
                    "target": "operator",
                    "channel": "ops",
                    "severity": severity,
                    "title": redact_secrets(title)[:200],
                    "text": redact_secrets(text)[:ALERT_TEXT_MAX_CHARS],
                }
                report["attempted"] = True
                try:
                    delivery = notifier.deliver(candidate, dry_run=False)
                    status = str(getattr(delivery, "status", "failed"))
                    detail = str(getattr(delivery, "detail", ""))
                except Exception as exc:  # notifier failure must not change the verdict
                    status, detail = "failed", f"notifier raised {type(exc).__name__}"
                report["status"] = status
                if detail:
                    report["detail"] = redact_secrets(detail)[:240]
                if status in {"sent", "printed", "recorded"}:
                    state["alerted_verdict"] = verdict
                    state["last_alert_at"] = _timestamp(now)
                    state.pop("uncertain_verdict", None)
                    state.pop("last_uncertain_at", None)
                elif status == "ambiguous":
                    state["uncertain_verdict"] = verdict
                    state["last_uncertain_at"] = _timestamp(now)
                else:
                    state["last_alert_failure_at"] = _timestamp(now)
            else:
                report["attempted"] = False
            try:
                _atomic_write_json(state_path, state)
            except OSError as exc:
                report["state_error"] = f"alert state not saved: {type(exc).__name__}"
    except Exception as exc:
        report["error"] = f"alerting failed: {type(exc).__name__}"
    return report


# --- dead-man switch --------------------------------------------------------



from .http_bounds import BoundedOpener
_DEADMAN_OPENER = BoundedOpener()


def validate_deadman_url(url: str) -> str:
    """HTTPS only, no credentials, no whitespace: the URL is itself a secret."""
    url = url.strip()
    if not url:
        raise ValueError("dead-man url is empty")
    if any(char.isspace() or ord(char) < 0x20 for char in url):
        raise ValueError("dead-man url must not contain whitespace or control characters")
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise ValueError("dead-man url is not parseable") from exc
    if parts.scheme.lower() != "https" or not parts.hostname:
        raise ValueError("dead-man url must be an https URL")
    if parts.username or parts.password:
        raise ValueError("dead-man url must not embed credentials")
    if contains_literal_secret(url):
        raise ValueError("dead-man url contains a secret-shaped string")
    return url


def load_deadman_url(
    *,
    env_name: str | None,
    file: Path | None,
    environ: Mapping[str, str] | None = None,
) -> str | None:
    """Resolve the dead-man URL from an env var or a one-line file.

    Taking the URL by reference keeps it out of process listings and unit
    files. Returns ``None`` when neither source is configured.
    """
    if env_name and file is not None:
        raise ValueError("--deadman-url-env and --deadman-url-file are mutually exclusive")
    if env_name:
        env = os.environ if environ is None else environ
        value = str(env.get(env_name, "")).strip()
        if not value:
            raise ValueError(f"dead-man url environment variable {env_name} is not set")
        return validate_deadman_url(value)
    if file is not None:
        if file.is_symlink() or not file.is_file():
            raise ValueError("dead-man url file must be a regular non-symlink file")
        try:
            raw = file.read_bytes()[:4097]
            text = raw.decode("utf-8")
        except (OSError, UnicodeError) as exc:
            raise ValueError("dead-man url file is unreadable") from exc
        if len(raw) > 4096:
            raise ValueError("dead-man url file is too large")
        lines = [line for line in text.splitlines() if line.strip()]
        if len(lines) != 1:
            raise ValueError("dead-man url file must contain exactly one URL line")
        return validate_deadman_url(lines[0])
    return None


def _fail_url(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path.rstrip("/") + "/fail", parts.query, ""))


def ping_deadman(
    url: str,
    *,
    fail: bool,
    body: str = "",
    timeout: float = DEADMAN_TIMEOUT_SECONDS,
    opener: Callable[..., Any] | None = None,
) -> dict[str, object]:
    """POST one healthchecks-style ping: ``<url>`` on success, ``<url>/fail`` on failure.

    Bounded by ``timeout``, never follows redirects, and never reports the URL
    (the URL is the credential for the external check).
    """
    target = _fail_url(url) if fail else url
    report: dict[str, object] = {"configured": True, "endpoint": "fail" if fail else "success"}
    data = redact_secrets(body).encode("utf-8")[:DEADMAN_BODY_MAX_BYTES]
    request = Request(target, data=data, headers={"Content-Type": "text/plain; charset=utf-8"}, method="POST")
    send = opener or _DEADMAN_OPENER.open
    try:
        with send(request, timeout=timeout) as response:
            status = int(getattr(response, "status", 200))
            if opener is None and len(response.read(65536 + 1)) > 65536:
                raise ValueError("deadman response exceeds limit")
    except HTTPError as exc:
        exc.close()
        report.update(status="failed", detail=f"HTTP {exc.code}")
        return report
    except (URLError, OSError, ValueError) as exc:
        reason = str(getattr(exc, "reason", "") or type(exc).__name__)
        reason = reason.replace(target, "[deadman-url]").replace(url, "[deadman-url]")
        report.update(status="failed", detail=redact_secrets(f"unreachable: {reason}")[:200])
        return report
    if 200 <= status < 300:
        report["status"] = "sent"
    else:
        report.update(status="failed", detail=f"HTTP {status}")
    return report
