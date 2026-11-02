#!/usr/bin/env python3
"""Measure the control-log read path with and without the derived checkpoint.

The point of phase 2 is a number: the operator routes re-project the whole
append-only log per call, so a 95 MiB log costs 10-30 s per ``close`` /
``resolve`` / ``cancel`` / ``reconcile``. This benchmark reports the same
projections before and after a derived checkpoint, over a synthetic log of a
requested size (deterministic, no private data) or over an existing log that an
operator has copied out of production.

Safety: against an existing ``--state`` the benchmark never writes a checkpoint
unless ``--allow-checkpoint-write`` is passed, because the checkpoint belongs
next to the log it describes.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import random
import sys
import tempfile
import time
from typing import Mapping

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packages" / "arvctl" / "src"))

from arvyx_control import projection_cache  # noqa: E402
from arvyx_control.api import _delivery_health  # noqa: E402
from arvyx_control.control import read_events  # noqa: E402
from arvyx_control.execution import project_executions  # noqa: E402
from arvyx_control.outbox import (  # noqa: E402
    project_dispatcher_tick,
    project_materialization_checkpoint,
    project_outbox,
)

UTC = timezone.utc
T0 = datetime(2026, 9, 1, tzinfo=UTC)
TARGETS = ("alpha", "bravo", "charlie", "delta")


def _ts(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _tick(index: int, at: datetime) -> dict[str, object]:
    return {
        "id": f"event_{index:08d}",
        "type": "outbox.dispatcher.tick",
        "task_id": "outbox_dispatcher",
        "timestamp": _ts(at),
        "payload": {
            "configured_targets": list(TARGETS),
            "healthy": True,
            "materialization_remaining": False,
            "skipped_unconfigured_targets": [],
            "skipped_intentional_human_targets": [],
            "route_revision": "rev-1",
            "route_sha256": "a" * 64,
        },
    }


def _outbox(index: int, at: datetime, rng: random.Random) -> dict[str, object]:
    item = f"outbox_{rng.randrange(4000)}"
    status = rng.choice(("pending", "leased", "delivered", "dead_lettered", "ambiguous_delivery"))
    return {
        "id": f"event_{index:08d}",
        "type": {"pending": "outbox.enqueued"}.get(status, f"outbox.{status}"),
        "task_id": item,
        "timestamp": _ts(at),
        "payload": {
            "id": item,
            "subject_id": f"thread_{item}",
            "target": rng.choice(TARGETS),
            "payload": {"delivery_mode": "direct", "source_event_type": "thread.created"},
            "payload_hash": "0" * 64,
            "epoch": rng.randrange(3),
            "status": status,
            "attempts": rng.randrange(4),
            "created_at": _ts(at - timedelta(seconds=30)),
            "updated_at": _ts(at),
            "next_attempt_at": _ts(at),
            "failures": rng.randrange(4),
            "resolution_category": "ambiguous_not_delivered" if rng.random() < 0.05 else "",
            "resolved_by": "operator" if rng.random() < 0.05 else "",
        },
    }


def _execution(index: int, at: datetime, rng: random.Random) -> dict[str, object]:
    execution = f"execution_{rng.randrange(3000)}"
    status = rng.choice(("pending", "leased", "completed", "held"))
    lease = status == "leased"
    return {
        "id": f"event_{index:08d}",
        "type": {"pending": "execution.created"}.get(status, f"execution.{status}"),
        "task_id": execution,
        "timestamp": _ts(at),
        "payload": {
            "id": execution,
            "subject_id": f"thread_{execution}",
            "subject_type": "thread",
            "target": rng.choice(TARGETS),
            "status": status,
            "attempts": 1 if lease else rng.randrange(3),
            "created_at": _ts(at - timedelta(seconds=45)),
            "updated_at": _ts(at),
            "lease_owner": "worker-1" if lease else "",
            "lease_expires_at": _ts(at + timedelta(minutes=2)) if lease else "",
            "attempt_id": "attempt_1" if lease else "",
            "heartbeat_at": _ts(at) if lease else "",
        },
    }


def generate(path: Path, target_bytes: int, *, seed: int = 20260911) -> dict[str, object]:
    """Write a deterministic log of roughly ``target_bytes`` bytes."""
    rng = random.Random(seed)
    written = 0
    index = 0
    at = T0
    with path.open("w", encoding="utf-8") as handle:
        while written < target_bytes:
            index += 1
            at += timedelta(seconds=10)
            roll = rng.random()
            if roll < 0.78:
                record = _tick(index, at)
            elif roll < 0.96:
                record = _outbox(index, at, rng)
            else:
                record = _execution(index, at, rng)
            line = json.dumps(record, sort_keys=True) + "\n"
            handle.write(line)
            written += len(line.encode("utf-8"))
    return {"events": index, "bytes": path.stat().st_size}


def _time(operation) -> float:
    start = time.perf_counter()
    operation()
    return time.perf_counter() - start


def snapshot(state: Path) -> dict[str, object]:
    """Canonical hash of every checkpointed projection."""
    return {
        "executions": {
            key: value.to_dict() for key, value in project_executions(state).items()
        },
        "outbox": {key: value.to_dict() for key, value in project_outbox(state).items()},
        "dispatcher_tick": project_dispatcher_tick(state),
        "materialization_checkpoint": project_materialization_checkpoint(state),
    }


def equivalence(state: Path) -> dict[str, object]:
    """Prove the resumed read path equals the full parse on this exact log."""
    previous = os.environ.get(projection_cache.CACHE_MODE_ENV)
    try:
        os.environ[projection_cache.CACHE_MODE_ENV] = "off"
        full = snapshot(state)
        os.environ[projection_cache.CACHE_MODE_ENV] = "require"
        resumed = snapshot(state)
    finally:
        if previous is None:
            os.environ.pop(projection_cache.CACHE_MODE_ENV, None)
        else:
            os.environ[projection_cache.CACHE_MODE_ENV] = previous
    mismatched = sorted(name for name in full if full[name] != resumed[name])
    return {
        "ok": not mismatched,
        "mismatched": mismatched,
        "projections": {
            name: {
                "records": len(full[name]) if isinstance(full[name], dict) else 1,
                "sha256": hashlib.sha256(
                    json.dumps(full[name], sort_keys=True, default=str).encode("utf-8")
                ).hexdigest(),
            }
            for name in full
        },
    }


def nearest_rank(values: list[float], percentile: int) -> float:
    """Nearest rank: sorted samples[ceil(n * percentile / 100) - 1]."""
    if not values or not 1 <= percentile <= 100:
        raise ValueError("nonempty samples and percentile in 1..100 required")
    return sorted(values)[(len(values) * percentile + 99) // 100 - 1]


@contextmanager
def cache_mode(mode: str):
    previous = os.environ.get(projection_cache.CACHE_MODE_ENV)
    os.environ[projection_cache.CACHE_MODE_ENV] = mode
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(projection_cache.CACHE_MODE_ENV, None)
        else:
            os.environ[projection_cache.CACHE_MODE_ENV] = previous


def budget_verdict(after: dict[str, float], verification: Mapping[str, object],
                   equivalences: Mapping[str, object], *, budget: float,
                   noop_seconds: float | None) -> dict[str, object]:
    """Qualify resumed reads, not the intentionally slow baseline/build cost."""
    expected = {f"{name}_p95" for name in (
        "read_events", "project_executions", "project_outbox", "project_dispatcher_tick",
        "project_materialization_checkpoint", "deliveries_health",
    )}
    measured = {name: after[name] for name in sorted(expected) if name in after}
    if noop_seconds is not None:
        measured["refresh_noop_seconds"] = noop_seconds
    checks = {name: math.isfinite(value) and 0 <= value <= budget
              for name, value in measured.items()}
    complete = expected.issubset(after)
    correctness = verification.get("ok") is True and equivalences.get("ok") is True
    return {"ok": complete and correctness and all(checks.values()),
            "qualification_complete": complete and correctness,
            "latency_budget_inputs": measured, "latency_within_budget": checks,
            "deliveries_health_p95_within_budget": checks.get("deliveries_health_p95", False)}


def measure(state: Path, *, repeats: int) -> dict[str, float]:
    if repeats < 1:
        raise ValueError("repeats must be positive")
    samples: dict[str, list[float]] = {
        "read_events": [],
        "project_executions": [],
        "project_outbox": [],
        "project_dispatcher_tick": [],
        "project_materialization_checkpoint": [],
        "deliveries_health": [],
    }
    for _ in range(repeats):
        samples["read_events"].append(_time(lambda: read_events(state)))
        samples["project_executions"].append(_time(lambda: project_executions(state)))
        samples["project_outbox"].append(_time(lambda: project_outbox(state)))
        samples["project_dispatcher_tick"].append(_time(lambda: project_dispatcher_tick(state)))
        samples["project_materialization_checkpoint"].append(
            _time(lambda: project_materialization_checkpoint(state))
        )
        # The real operator surface reads outbox + materialization + tick.
        samples["deliveries_health"].append(_time(lambda: _delivery_health(state)))
    report: dict[str, float] = {}
    for name, values in samples.items():
        # Keep full precision for the verdict; rounding can hide a budget miss.
        report[f"{name}_p50"] = nearest_rank(values, 50)
        report[f"{name}_p95"] = nearest_rank(values, 95)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="projection_checkpoint_benchmark")
    parser.add_argument("--state", type=Path, help="existing log to measure (read-only by default)")
    parser.add_argument("--size-mib", type=float, default=100.0)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--p95-budget-seconds", type=float, default=2.0)
    parser.add_argument("--allow-checkpoint-write", action="store_true")
    parser.add_argument("--keep", action="store_true", help="keep the generated synthetic log")
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args(argv)
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    if not math.isfinite(args.p95_budget_seconds) or args.p95_budget_seconds <= 0:
        parser.error("--p95-budget-seconds must be finite and positive")
    if not math.isfinite(args.size_mib) or args.size_mib <= 0:
        parser.error("--size-mib must be finite and positive")

    temporary: tempfile.TemporaryDirectory[str] | None = None
    if args.state is None:
        temporary = tempfile.TemporaryDirectory()
        state = Path(temporary.name) / "control-events.jsonl"
        generation = generate(state, int(args.size_mib * 1024 * 1024))
    else:
        state = args.state
        if not state.exists():
            print(f"error: no such log: {state}", file=sys.stderr)
            return 2
        generation = {"events": None, "bytes": state.stat().st_size}

    try:
        with cache_mode("off"):
            before = measure(state, repeats=args.repeats)
        checkpoint_present = projection_cache.checkpoint_path(state).exists()
        write_allowed = args.state is None or args.allow_checkpoint_write
        build: dict[str, object] = {"built": False, "reason": "write_not_allowed"}
        if write_allowed:
            build = projection_cache.build_projection_checkpoint(
                state, force=True, min_tail_bytes=0
            )
        checkpoint_ready = (build.get("built") is True or build.get("reason") == "nothing_new"
                            or (not write_allowed and checkpoint_present))
        with cache_mode("require"):
            after = measure(state, repeats=args.repeats) if checkpoint_ready else {}
        verification = (
            projection_cache.verify_projection_checkpoint(state)
            if checkpoint_ready
            else {"ok": None}
        )
        equivalences = equivalence(state) if checkpoint_ready else {"ok": None}
        # Every checkpoint write is gated: against an operator's log this script
        # must not create or refresh a file unless the operator asked for it.
        noop_seconds = None
        noop: dict[str, object] = {"reason": ""}
        if write_allowed:
            # The scheduled tick's common case: the guards must decide from the
            # file size and the stored offset, without re-reading the log.
            noop_started = time.perf_counter()
            noop = projection_cache.maybe_refresh_projection_checkpoint(
                state, min_tail_bytes=projection_cache.DEFAULT_MIN_TAIL_BYTES
            )
            noop_seconds = time.perf_counter() - noop_started
        checkpoint_bytes = (
            projection_cache.checkpoint_path(state).stat().st_size
            if checkpoint_ready
            else 0
        )
    finally:
        if temporary is not None and not args.keep:
            temporary.cleanup()

    report = {
        "log_bytes": generation["bytes"],
        "log_mib": round(generation["bytes"] / (1024 * 1024), 2),
        "events": generation["events"],
        "repeats": args.repeats,
        "checkpoint_present_before": checkpoint_present,
        "build": build,
        "before": before,
        "after": after,
        "p95_budget_seconds": args.p95_budget_seconds,
        "verify": verification,
        "equivalence": equivalences,
        "checkpoint_bytes": checkpoint_bytes,
        "refresh_noop_seconds": noop_seconds,
        "refresh_noop_reason": noop.get("reason", ""),
        "checkpoint_write_allowed": write_allowed,
    }
    if after:
        report["speedup"] = {
            name: round(before[f"{name}_p95"] / after[f"{name}_p95"], 1)
            for name in (
                "read_events",
                "project_executions",
                "project_outbox",
                "deliveries_health",
            )
            if after[f"{name}_p95"] > 0
        }
    report.update(budget_verdict(after, verification, equivalences,
                                budget=args.p95_budget_seconds, noop_seconds=noop_seconds))
    report["percentile_convention"] = "nearest-rank ceil(n*p/100), unrounded seconds"
    report["budget_scope"] = "all resumed read p95s and measured scheduled refresh; baseline and checkpoint build are diagnostic costs"
    ok = report["ok"]

    if args.json_output:
        print(json.dumps(report, sort_keys=True))
    else:
        print(f"log: {report['log_mib']} MiB, {report['events']} events")
        for label, timings in (("before", before), ("after", after)):
            if not timings:
                continue
            print(f"{label}:")
            for name, value in sorted(timings.items()):
                print(f"  {name}: {value}s")
        if after:
            print(f"speedup: {report['speedup']}")
        print(f"verify: {verification}")
        print(f"equivalence: {equivalences}")
        print("OK" if ok else "FAILED OR INCOMPLETE QUALIFICATION")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
