"""Derived projection checkpoint for the control event log.

Every operator route re-projects the whole append-only control log, so a 95 MiB
log makes one `close`/`resolve`/`cancel`/`reconcile` call cost 10-30 s. This
module keeps a *derived* checkpoint beside the log: the projected prefix state
plus the log byte offset it was built at, with a fingerprint of the bytes at
that offset and a content fingerprint of the state itself.

The log stays the authority. A checkpoint is only ever an optimisation:

* readers load it, validate it, and parse only the tail after the offset;
* on any doubt they fall back to the full parse, and deleting the checkpoint is
  a supported recovery action;
* it is written off the hot path (atomic replace of a temp file in the same
  directory), never by an append;
* a checkpoint that lags behind the log is a cost, not a correctness problem.

In-place mutation of an already sealed prefix is outside the append-only
contract: the fingerprint covers only the bytes around the offset, so
``arvyx control-log projection-verify`` exists to re-derive the projections from
the whole log and compare them with the stored checkpoint when an operator wants
a deep check.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from . import safe_open
from . import private_paths
from .security import bounded_json_loads
import os
from pathlib import Path
import stat
import tempfile
import time
from typing import Callable, Sequence

from .control import ControlEvent, parse_event_lines, read_events

#: 3: adds the ``decisions`` projection. A schema-2 checkpoint is rejected and
#: rebuilt on the next dispatcher tick (a full parse in the meantime).
#: 4: adds the ``assignments`` projection. ``materialize_executions`` ran a full
#: parse on every worker tick to find assignment-shaped events — 4.9 s at 310k
#: events, and it holds the state lock while it does. The seed carries just those
#: events, so the tick resumes instead.
SCHEMA_VERSION = 4
CHECKPOINT_SUFFIX = ".projections.json"
#: Rebuild the checkpoint once this many uncovered bytes have accumulated. At
#: the post-coalescing tick rate (~0.4 MiB/day) this is a rare write, and the
#: tail parse it bounds stays far below the full-log cost.
DEFAULT_MIN_TAIL_BYTES = 4 * 1024 * 1024
#: Ceiling for the write path. The build costs roughly one pass over the log, so
#: it is refused above this size instead of risking a scheduled tick's timeout;
#: phase 3 (rotation) is the answer beyond it.
DEFAULT_MAX_LOG_BYTES = 512 * 1024 * 1024
#: Bytes around the checkpoint offset that bind the checkpoint to this exact log.
PREFIX_FINGERPRINT_BYTES = 64
#: Operability switch: ``auto`` (default), ``off``, or ``require`` (fail closed
#: unless a valid checkpoint is used — verification and tests only).
CACHE_MODE_ENV = "ARVYX_PROJECTION_CACHE"
CACHE_MODES = ("auto", "off", "require")

PROJECTION_NAMES: tuple[str, ...] = (
    "executions",
    "outbox",
    "dispatcher_tick",
    "materialization_checkpoint",
    "decisions",
    "assignments",
)
PROJECTIONS = PROJECTION_NAMES

SeedBuilder = Callable[[Sequence[ControlEvent]], dict[str, object]]
SeedValidator = Callable[[object], bool]
_SEED_BUILDERS: dict[str, SeedBuilder] = {}
_SEED_VALIDATORS: dict[str, SeedValidator] = {}


class ProjectionCacheUnavailable(RuntimeError):
    """Raised only when the caller demanded a checkpoint read path."""


#: Validation reasons that mean "the log contradicts this checkpoint" rather than
#: "this checkpoint file is malformed". ``projection-verify`` reports the latter
#: without an alarm and the former as a disagreement.
LOG_CONTRADICTION_REASONS = frozenset(
    {
        "prefix_fingerprint_mismatch",
        "offset_not_at_record_boundary",
        "log_shorter_than_offset",
        "log_size_shorter_than_offset",
    }
)


def register_seed(
    name: str, *, builder: SeedBuilder, validator: SeedValidator
) -> None:
    """Register how one projection serializes and validates its prefix state."""
    if name not in PROJECTION_NAMES:
        raise ValueError(f"unknown projection: {name}")
    _SEED_BUILDERS[name] = builder
    _SEED_VALIDATORS[name] = validator


def cache_mode() -> str:
    value = os.environ.get(CACHE_MODE_ENV, "").strip().casefold()
    return value if value in CACHE_MODES else "auto"


def checkpoint_path(state: Path) -> Path:
    return state.with_name(state.name + CHECKPOINT_SUFFIX)


def prefix_fingerprint(state: Path, offset: int) -> str:
    """SHA-256 of the bounded byte window that precedes ``offset``."""
    if offset < 0:
        raise ValueError("log offset must not be negative")
    length = min(PREFIX_FINGERPRINT_BYTES, offset)
    with state.open("rb") as handle:
        if length:
            handle.seek(offset - length)
        return hashlib.sha256(handle.read(length)).hexdigest()


#: Checkpoint fields the content fingerprint binds. They must be covered: a
#: checkpoint with a correct offset but a wrong ``prefix_lines`` would otherwise
#: pass every check and then report wrong absolute line numbers, and a wrong
#: ``event_count`` would misdescribe what the seed covers.
FINGERPRINT_FIELDS = ("log_offset", "log_size", "prefix_lines", "event_count")


def state_fingerprint(payload: object) -> str:
    """Content fingerprint over the bound metadata and the projected state."""
    if isinstance(payload, dict):
        bound: dict[str, object] = {
            field: payload.get(field) for field in FINGERPRINT_FIELDS
        }
        bound["projections"] = payload.get("projections")
    else:
        bound = {"projections": None}
    canonical = json.dumps(bound, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def read_tail_events(state: Path, offset: int, first_line: int) -> list[ControlEvent]:
    """Parse the log suffix at ``offset``, numbered from ``first_line``.

    ``first_line`` is the absolute line number of the first line in the suffix,
    so a reader resuming mid-log reports the same line numbers a full read would
    report.

    Fail-closed semantics match :func:`arvyx_control.control.read_events`: an
    invalid record is an error, never silently skipped.
    """
    if offset < 0:
        raise ValueError("log offset must not be negative")
    with state.open("rb") as handle:
        handle.seek(offset)
        raw = handle.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("event snapshot is not valid UTF-8") from exc
    return parse_event_lines(text, first_line=first_line)


def _read_log(state: Path) -> tuple[list[ControlEvent], int, int]:
    """Read the log once and report the events, the byte offset, and the lines."""
    if not state.exists():
        return [], 0, 0
    raw = state.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("event snapshot is not valid UTF-8") from exc
    events = parse_event_lines(text)
    return events, len(raw), len(text.splitlines())


def _ensure_seed_modules() -> None:
    """Import every module that registers a seed. A checkpoint is built for all projections at
    once, so a process that never imported one of them (a CLI path, a test) must not fail the
    build or silently leave every reader on the full parse."""
    from . import decisions, execution, outbox  # noqa: F401  (import registers the seeds)


def build_seed(name: str, events: Sequence[ControlEvent]) -> dict[str, object]:
    if name not in _SEED_BUILDERS:
        _ensure_seed_modules()
    builder = _SEED_BUILDERS.get(name)
    if builder is None:
        raise ValueError(f"projection seed builder is not registered: {name}")
    return builder(events)


def _validate(state: Path, raw: object) -> tuple[dict[str, object] | None, str]:
    if not isinstance(raw, dict):
        return None, "not_an_object"
    schema = raw.get("schema")
    if isinstance(schema, bool) or not isinstance(schema, int):
        return None, "schema_not_an_integer"
    if schema != SCHEMA_VERSION:
        return None, "schema_mismatch"
    offset = raw.get("log_offset")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        return None, "log_offset_invalid"
    for field in ("prefix_lines", "event_count", "log_size"):
        value = raw.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            return None, f"{field}_invalid"
    if raw["log_size"] < offset:
        return None, "log_size_shorter_than_offset"
    fingerprint = raw.get("prefix_fingerprint")
    if not _is_sha256(fingerprint):
        return None, "prefix_fingerprint_invalid"
    state_sha256 = raw.get("state_sha256")
    if not _is_sha256(state_sha256):
        return None, "state_sha256_invalid"
    projections = raw.get("projections")
    if not isinstance(projections, dict):
        return None, "projections_not_an_object"
    if set(projections) != set(PROJECTION_NAMES):
        return None, "projections_incomplete"
    if state_fingerprint(raw) != state_sha256:
        return None, "state_fingerprint_mismatch"
    if not state.exists():
        return None, "log_missing"
    size = state.stat().st_size
    if size < offset:
        return None, "log_shorter_than_offset"
    if offset:
        with state.open("rb") as handle:
            handle.seek(offset - 1)
            if handle.read(1) != b"\n":
                # A checkpoint must start at a record boundary; anything else
                # would silently project a truncated first event.
                return None, "offset_not_at_record_boundary"
    if prefix_fingerprint(state, offset) != fingerprint:
        return None, "prefix_fingerprint_mismatch"
    for name in PROJECTION_NAMES:
        validator = _SEED_VALIDATORS.get(name)
        if validator is None:
            continue
        if not validator(projections[name]):
            return None, f"{name}_seed_invalid"
    return dict(raw), "ok"


def _as_int(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} is malformed")
    return value


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _load(state: Path) -> tuple[dict[str, object] | None, str]:
    path = checkpoint_path(state)
    try:
        raw = bounded_json_loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, "missing"
    except (OSError, ValueError, UnicodeDecodeError, RecursionError):
        # JSONNestingError is a ValueError: over-deep checkpoints are unreadable.
        return None, "unreadable"
    return _validate(state, raw)


def inspect_checkpoint(state: Path) -> dict[str, object]:
    """Operator-facing status of the derived checkpoint."""
    raw, reason = _load(state)
    size = state.stat().st_size if state.exists() else 0
    report: dict[str, object] = {
        "checkpoint_path": str(checkpoint_path(state)),
        "present": checkpoint_path(state).exists(),
        "valid": raw is not None,
        "reason": reason,
        "schema": SCHEMA_VERSION,
        "built_at": "",
        "log_offset": 0,
        "log_size": size,
        "tail_bytes": size,
        "event_count": 0,
        "prefix_lines": 0,
    }
    if raw is not None:
        # Safe because ``_validate`` only returns a checkpoint whose metadata it
        # has already proven to be a non-negative integer: a status command must
        # report corruption, not raise on it.
        offset = int(str(raw.get("log_offset", 0)))
        report.update(
            {
                "built_at": str(raw.get("built_at", "")),
                "log_offset": offset,
                "log_size": int(str(raw.get("log_size", size))),
                "tail_bytes": size - offset,
                "event_count": int(str(raw.get("event_count", 0))),
                "prefix_lines": int(str(raw.get("prefix_lines", 0))),
            }
        )
    return report


def projection_status(state: Path) -> dict[str, object]:
    return inspect_checkpoint(state)


def projection_source(
    state: Path, name: str
) -> tuple[object | None, list[ControlEvent], str]:
    """Return ``(seed, events, source)`` for one projection.

    ``source`` is ``"checkpoint"`` when the seed is prefix state and ``events``
    is the tail, or ``"full"`` when the caller must project the whole log.
    """
    if name not in PROJECTION_NAMES:
        raise ValueError(f"unknown projection: {name}")
    mode = cache_mode()
    if mode == "off":
        return None, read_events(state), "full"
    validator = _SEED_VALIDATORS.get(name)
    if validator is None:
        if mode == "require":
            raise ProjectionCacheUnavailable(
                f"projection seed validator is not registered: {name}"
            )
        return None, read_events(state), "full"

    raw, reason = _load(state)
    if raw is not None and validator(raw["projections"][name]):  # type: ignore[index]
        try:
            prefix_lines = _as_int(raw.get("prefix_lines"), label="prefix_lines")
            events = read_tail_events(
                state,
                _as_int(raw.get("log_offset"), label="log_offset"),
                prefix_lines + 1,
            )
        except ValueError:
            # The log itself is unreadable (torn record, bad encoding). Surface
            # the same fail-closed error a full read would raise.
            raise
        except OSError as exc:
            if mode == "require":
                raise ProjectionCacheUnavailable(f"log tail unreadable: {exc}") from exc
        else:
            return raw["projections"][name], events, "checkpoint"  # type: ignore[index]
    elif mode == "require":
        # ``require`` exists so a resumed measurement cannot silently be a full
        # parse: an absent checkpoint is as disqualifying as an invalid one.
        raise ProjectionCacheUnavailable(f"checkpoint is unusable: {reason}")

    return None, read_events(state), "full"


def build_projection_checkpoint(
    state: Path,
    *,
    force: bool = False,
    min_tail_bytes: int = DEFAULT_MIN_TAIL_BYTES,
    max_log_bytes: int = DEFAULT_MAX_LOG_BYTES,
    now: datetime | None = None,
) -> dict[str, object]:
    """Derive a checkpoint from the whole log and replace it atomically.

    Raises ``ValueError`` when the log cannot be projected: a checkpoint is
    never written from a partial read.
    """
    if min_tail_bytes < 0:
        raise ValueError("min_tail_bytes must not be negative")
    if max_log_bytes < 0:
        raise ValueError("max_log_bytes must not be negative")
    report: dict[str, object] = {
        "built": False,
        "reason": "",
        "checkpoint_path": str(checkpoint_path(state)),
        "log_offset": 0,
        "log_size": 0,
        "tail_bytes": 0,
        "event_count": 0,
        "prefix_lines": 0,
        "projections": {},
        "build_seconds": 0.0,
    }
    if not state.exists():
        report["reason"] = "no_log"
        return report
    size = state.stat().st_size
    if max_log_bytes and size > max_log_bytes:
        report["reason"] = "log_above_ceiling"
        report["log_size"] = size
        report["tail_bytes"] = size
        return report
    if not size:
        report["reason"] = "empty_log"
        return report

    # Every no-op decision is taken from the file size and the stored offset, so
    # the common tick pays one stat plus reading and validating the checkpoint
    # itself (measured 0.158 s against a 100 MiB log, versus ~2 s for the full-log
    # parse this checkpoint exists to avoid) — never the log.
    current, _reason = _load(state)
    current_offset = (
        _as_int(current.get("log_offset"), label="log_offset") if current is not None else 0
    )
    report.update({"tail_bytes": size - current_offset, "log_offset": current_offset, "log_size": size})
    if current is not None and current_offset == size:
        report["reason"] = "nothing_new"
        return report
    if not force and current is not None and size - current_offset < min_tail_bytes:
        # A valid checkpoint that lags is a cost, not a correctness problem: the
        # write path stays rare. The first checkpoint is built regardless, so a
        # fresh or repaired state directory bootstraps on the next tick.
        report["reason"] = "tail_below_threshold"
        return report

    started = time.perf_counter()
    events, offset, prefix_lines = _read_log(state)
    report.update(
        {
            "tail_bytes": offset - current_offset,
            "log_offset": offset,
            "log_size": offset,
            "event_count": len(events),
            "prefix_lines": prefix_lines,
        }
    )

    projections: dict[str, object] = {}
    for name in PROJECTION_NAMES:
        projections[name] = build_seed(name, events)
    built_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    payload: dict[str, object] = {
        "schema": SCHEMA_VERSION,
        "log_offset": offset,
        "log_size": offset,
        "prefix_lines": prefix_lines,
        "event_count": len(events),
        "prefix_fingerprint": prefix_fingerprint(state, offset),
        "built_at": built_at.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "projections": projections,
    }
    payload["state_sha256"] = state_fingerprint(payload)
    _write_checkpoint(state, payload)
    report["build_seconds"] = round(time.perf_counter() - started, 4)
    report.update(
        {
            "built": True,
            "reason": "built" if current is not None else "bootstrap",
            "event_count": len(events),
            "prefix_lines": prefix_lines,
            "projections": {
                name: len(value) if isinstance(value, (list, dict)) else 0
                for name, value in projections.items()
            },
        }
    )
    return report


def maybe_refresh_projection_checkpoint(
    state: Path,
    *,
    min_tail_bytes: int = DEFAULT_MIN_TAIL_BYTES,
    max_log_bytes: int = DEFAULT_MAX_LOG_BYTES,
) -> dict[str, object]:
    """Write path for a scheduled tick: cheap no-op unless the tail grew."""
    try:
        return build_projection_checkpoint(
            state, min_tail_bytes=min_tail_bytes, max_log_bytes=max_log_bytes
        )
    except (OSError, ValueError, KeyError) as exc:
        # KeyError: a source event whose payload is missing a mandatory field (a
        # decision record without ``decision_id``) fails the build rather than the
        # reader, and a scheduled tick must report that, not die on it.
        return {
            "built": False,
            "reason": f"unavailable: {exc}",
            "checkpoint_path": str(checkpoint_path(state)),
            "log_offset": 0,
            "log_size": 0,
            "tail_bytes": 0,
            "event_count": 0,
            "prefix_lines": 0,
            "projections": {},
            "build_seconds": 0.0,
        }


def verify_projection_checkpoint(state: Path) -> dict[str, object]:
    """Re-derive the *prefix* state from the whole log and compare it.

    This is the deep operator check behind the append-only assumption: the
    stored seed must equal the projection of exactly the log prefix it claims
    to cover. It costs a full parse, so it is not on any hot path.
    """
    report: dict[str, object] = {
        "ok": False,
        "reason": "",
        "mismatched": [],
        "log_offset": 0,
        "log_size": 0,
        "tail_bytes": 0,
        # An invalid checkpoint is auto-rejected on the read path and must not
        # page an operator the way a real disagreement with the log does.
        "disagrees_with_log": False,
    }
    raw, reason = _load(state)
    if raw is None:
        report["reason"] = f"invalid:{reason}"
        # A structurally invalid checkpoint is auto-rejected on the read path;
        # report it, but do not raise the alarm an append-only violation deserves.
        # The remaining reasons mean the log *contradicts* a checkpoint that is
        # otherwise well formed: the bytes it was built against are gone, moved,
        # or replaced. That is the signal this command exists to produce, so those
        # do exit non-zero (a restore can legitimately produce the shorter-log
        # case, and re-deriving the checkpoint is the documented answer).
        report["disagrees_with_log"] = reason in LOG_CONTRADICTION_REASONS
        return report
    data = state.read_bytes()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        report["reason"] = "log_not_utf8"
        return report
    events = parse_event_lines(text)
    log_offset = _as_int(raw.get("log_offset"), label="log_offset")
    prefix_lines = _as_int(raw.get("prefix_lines"), label="prefix_lines")
    event_count = _as_int(raw.get("event_count"), label="event_count")
    prefix_bytes = len("".join(text.splitlines(keepends=True)[:prefix_lines]).encode("utf-8"))

    mismatched: list[str] = []
    if prefix_bytes != log_offset:
        mismatched.append("log_offset")
    if event_count > len(events):
        mismatched.append("event_count")
        prefix_events: list[ControlEvent] = []
    else:
        prefix_events = events[:event_count]
    for name in PROJECTION_NAMES:
        if _SEED_BUILDERS.get(name) is None:
            mismatched.append(f"{name}:unregistered")
            continue
        if build_seed(name, prefix_events) != raw["projections"][name]:  # type: ignore[index]
            mismatched.append(name)

    report.update(
        {
            "ok": not mismatched,
            "reason": "ok" if not mismatched else "projection_mismatch",
            "disagrees_with_log": bool(mismatched),
            "mismatched": sorted(set(mismatched)),
            "log_offset": log_offset,
            "log_size": len(data),
            "tail_bytes": len(data) - log_offset,
        }
    )
    return report


def _write_checkpoint(state: Path, payload: dict[str, object]) -> None:
    directory = checkpoint_path(state).parent
    directory.mkdir(parents=True, exist_ok=True)
    body = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{checkpoint_path(state).name}.", dir=str(directory)
    )
    try:
        private_paths.apply_mode(fd=descriptor, mode=stat.S_IRUSR | stat.S_IWUSR)
        handle = os.fdopen(descriptor, "wb")
        descriptor = -1
        with handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        safe_open.replace_path(temporary, checkpoint_path(state))
        _fsync_directory(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if os.path.exists(temporary):
            os.unlink(temporary)


def _fsync_directory(directory: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
