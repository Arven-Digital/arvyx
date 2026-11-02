from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from arvyx_control.replica_authority import authority_context
from arvyx_control import execution as execution_module
from arvyx_control import projection_cache
from arvyx_control.cli import main as cli_main
from arvyx_control.control import parse_event_lines, read_events
from arvyx_control.decisions import project_decisions
from arvyx_control.execution import materialize_executions, project_executions
from arvyx_control.outbox import (
    project_dispatcher_tick,
    project_materialization_checkpoint,
    project_outbox,
)

UTC = timezone.utc
T0 = datetime(2026, 9, 11, 12, 0, tzinfo=UTC)


def _ts(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


class Log:
    """Synthetic control log that carries the production event shapes."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch()
        self.counter = 0

    def event(self, event_type: str, task_id: str, at: datetime, payload: dict[str, object]) -> None:
        self.counter += 1
        record = {
            "id": f"event_{self.counter:06d}",
            "type": event_type,
            "task_id": task_id,
            "timestamp": _ts(at),
            "payload": payload,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")

    def raw(self, text: str) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(text)

    def item(
        self,
        event_type: str,
        item_id: str,
        target: str,
        at: datetime,
        *,
        status: str,
        failures: int | None = None,
        resolved_by: str = "",
    ) -> None:
        payload: dict[str, object] = {
            "id": item_id,
            "subject_id": f"thread_{item_id}",
            "target": target,
            "payload": {"delivery_mode": "direct", "source_event_type": "thread.created"},
            "payload_hash": "0" * 64,
            "epoch": 0,
            "status": status,
            "attempts": 1,
            "created_at": _ts(at),
            "updated_at": _ts(at),
            "next_attempt_at": _ts(at),
            "resolved_by": resolved_by,
        }
        if failures is not None:
            payload["failures"] = failures
        self.event(event_type, item_id, at, payload)

    def execution(
        self,
        event_type: str,
        execution_id: str,
        target: str,
        at: datetime,
        *,
        status: str,
        attempts: int = 1,
        lease_expires_at: str = "",
    ) -> None:
        # A leased execution must carry a coherent attempt: owner, expiry, and
        # attempt id together, or the projection disqualifies the lineage.
        leased = status == "leased"
        self.event(
            event_type,
            execution_id,
            at,
            {
                "id": execution_id,
                "target": target,
                "status": status,
                "attempts": attempts,
                "subject_id": f"thread_{execution_id}",
                "subject_type": "thread",
                "created_at": _ts(at),
                "updated_at": _ts(at),
                "lease_owner": "worker-1" if leased else "",
                "lease_expires_at": (
                    lease_expires_at or _ts(at + timedelta(minutes=5)) if leased else ""
                ),
                "attempt_id": "attempt_1" if leased else "",
            },
        )

    def tick(
        self,
        at: datetime,
        *,
        targets: tuple[str, ...] = ("alpha",),
        healthy: bool = True,
        route_revision: str = "rev-1",
        route_sha256: str = "a" * 64,
    ) -> None:
        self.event(
            "outbox.dispatcher.tick",
            "outbox_dispatcher",
            at,
            {
                "configured_targets": list(targets),
                "healthy": healthy,
                "materialization_remaining": False,
                "skipped_unconfigured_targets": [],
                "skipped_intentional_human_targets": [],
                "route_revision": route_revision,
                "route_sha256": route_sha256,
            },
        )

    def decision(self, event_type: str, decision_id: str, at: datetime, *, status: str = "requested",
                 choice: str = "", allow_text: bool = False) -> None:
        payload: dict[str, object] = {
            "decision_id": decision_id, "execution_id": "execution_1", "attempt_id": "attempt_1",
            "target": "alpha", "subject_id": "handoff_1", "subject_type": "handoff", "question": "Deploy?",
            "allow_text": allow_text, "idempotency_key": "decision-" + decision_id, "requested_at": _ts(T0),
            "status": status,
        }
        if status == "answered":
            payload.update({"choice": choice, "answered_by": "operator", "answered_at": _ts(at),
                            "answer_platform": "telegram", "answer_message_id": "6169"})
        self.event(event_type, decision_id, at, payload)

    def materialization(self, source_event_id: str, at: datetime) -> None:
        self.event(
            "outbox.materialization.checkpoint",
            "outbox_materialization",
            at,
            {"source_event_id": source_event_id},
        )


class ProjectionCacheHarness(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.state = self.root / "state" / "control-events.jsonl"
        self.vault = Path(self._tmp.name) / "vault"
        self.vault.mkdir(exist_ok=True)
        self.enterContext(authority_context(self.vault, self.state))
        self.log = Log(self.state)

    def populate(self) -> None:
        """A mixed log that exercises every projection's state machine."""
        self.log.event("task.created", "task_1", T0, {"id": "task_1", "title": "T", "owner": "alpha"})
        self.log.item("outbox.enqueued", "outbox_1", "alpha", T0 + timedelta(seconds=1), status="pending")
        self.log.item(
            "outbox.attempt.failed", "outbox_1", "alpha", T0 + timedelta(seconds=2),
            status="pending", failures=1,
        )
        self.log.item("outbox.leased", "outbox_1", "alpha", T0 + timedelta(seconds=3), status="leased")
        self.log.item("outbox.delivered", "outbox_1", "alpha", T0 + timedelta(seconds=4), status="delivered")
        self.log.item("outbox.enqueued", "outbox_2", "bravo", T0 + timedelta(seconds=5), status="pending")
        self.log.item("outbox.dead_lettered", "outbox_2", "bravo", T0 + timedelta(seconds=6), status="dead_lettered")
        self.log.item(
            "outbox.resolved", "outbox_2", "bravo", T0 + timedelta(seconds=7),
            status="dead_lettered", resolved_by="operator",
        )
        self.log.execution("execution.created", "execution_1", "alpha", T0 + timedelta(seconds=8), status="pending")
        self.log.execution(
            "execution.leased", "execution_1", "alpha", T0 + timedelta(seconds=9),
            status="leased", lease_expires_at=_ts(T0 + timedelta(minutes=5)),
        )
        self.log.execution(
            "execution.heartbeat", "execution_1", "alpha", T0 + timedelta(seconds=10), status="leased",
        )
        self.log.execution("execution.completed", "execution_1", "alpha", T0 + timedelta(seconds=11), status="completed")
        # A malformed state event permanently disqualifies its execution id.
        self.log.execution(
            "execution.created", "execution_2", "bravo", T0 + timedelta(seconds=12),
            status="pending", attempts=-1,
        )
        self.log.execution("execution.created", "execution_3", "bravo", T0 + timedelta(seconds=13), status="pending")
        self.log.materialization("event_000002", T0 + timedelta(seconds=14))
        self.log.tick(T0 + timedelta(seconds=15))
        self.log.event("thread.created", "thread_1", T0 + timedelta(seconds=16), {"target": "alpha", "type": "ask"})
        self.log.tick(T0 + timedelta(seconds=17), targets=("alpha", "bravo"), route_revision="rev-2")
        self.log.decision("decision.requested", "decision_1", T0 + timedelta(seconds=17), allow_text=True)
        self.log.decision("decision.requested", "decision_2", T0 + timedelta(seconds=17))
        self.log.decision("decision.answered", "decision_1", T0 + timedelta(seconds=17), status="answered",
                          choice="approve")

    def random_log(self, events: int = 360, seed: int = 20260911) -> None:
        import random

        rng = random.Random(seed)
        targets = ("alpha", "bravo", "charlie")
        for index in range(events):
            at = T0 + timedelta(seconds=index)
            kind = rng.choice(
                ("outbox", "execution", "tick", "materialization", "task", "thread", "decision")
            )
            if kind == "outbox":
                item = f"outbox_{rng.randrange(6)}"
                status = rng.choice(("pending", "leased", "delivered", "dead_lettered"))
                self.log.item(
                    f"outbox.{status}" if status != "pending" else "outbox.enqueued",
                    item,
                    rng.choice(targets),
                    at,
                    status=status,
                    resolved_by="operator" if rng.random() < 0.2 else "",
                )
            elif kind == "execution":
                execution = f"execution_{rng.randrange(4)}"
                status = rng.choice(("pending", "leased", "completed", "held"))
                self.log.execution(
                    f"execution.{status}" if status != "pending" else "execution.created",
                    execution,
                    rng.choice(targets),
                    at,
                    status=status,
                )
            elif kind == "tick":
                self.log.tick(at, targets=rng.sample(targets, rng.randrange(1, 4)))
            elif kind == "materialization":
                self.log.materialization(f"event_{rng.randrange(100):06d}", at)
            elif kind == "decision":
                answered = rng.random() < 0.4
                self.log.decision(
                    "decision.answered" if answered else "decision.requested",
                    f"decision_{rng.randrange(4)}",
                    at,
                    status="answered" if answered else "requested",
                    choice=rng.choice(("approve", "deny")) if answered else "",
                    allow_text=rng.random() < 0.5,
                )
            elif kind == "task":
                self.log.event(
                    "task.created",
                    f"task_{rng.randrange(5)}",
                    at,
                    {"id": f"task_{rng.randrange(5)}", "title": "t", "owner": rng.choice(targets)},
                )
            else:
                target = rng.choice(targets)
                # Bound provenance, or the materialization scan skips every one
                # of these and the resumed-vs-full comparison below is vacuous
                # (it would compare two empty lists while the seed goes unread).
                if rng.random() < 0.25:
                    self.log.event(
                        "handoff.created",
                        f"handoff_{rng.randrange(5)}",
                        at,
                        {"to_agent": target, "actor_identity_bound": True},
                    )
                else:
                    self.log.event(
                        "thread.created",
                        f"thread_{rng.randrange(5)}",
                        at,
                        {"target": target, "type": "ask", "actor_identity_bound": True},
                    )

    def snapshot(self) -> dict[str, object]:
        """Every exported projection, canonically serialized."""
        return {
            "executions": {key: value.to_dict() for key, value in project_executions(self.state).items()},
            "outbox": {key: value.to_dict() for key, value in project_outbox(self.state).items()},
            "dispatcher_tick": project_dispatcher_tick(self.state),
            "materialization_checkpoint": project_materialization_checkpoint(self.state),
            # dict order is part of the projection, so compare it as an ordered list.
            "decisions": [(key, value.to_dict()) for key, value in project_decisions(self.state).items()],
            # The assignment scan is an input to materialization rather than an
            # exported projection, but it is compared here too so the resumed and
            # full-parse paths are held to agreeing on which executions a tick
            # creates, at every checkpoint offset the suites sweep.
            "materialized": self.materialize_resumed(),
        }

    def materialize_resumed(self) -> list[dict[str, object]]:
        """Run the assignment scan against a throwaway copy of the log.

        ``materialize_executions`` appends ``execution.created`` events, so it
        runs on a copy: the caller's log and its checkpoint must keep the exact
        prefix it built. The checkpoint travels with the copy, which is what
        makes the resumed path reachable here. The clock is pinned because the
        created execution is stamped at the append — comparing a resumed run
        against a full-parsed one otherwise fails on the wall clock, which is
        how this comparison silently passed while it was comparing two empties.
        """
        self._materialize_calls = getattr(self, "_materialize_calls", 0) + 1
        copy = self.root / f"materialize-copy-{self._materialize_calls}.jsonl"
        shutil.copyfile(self.state, copy)
        checkpoint = projection_cache.checkpoint_path(self.state)
        if checkpoint.exists():
            shutil.copyfile(checkpoint, projection_cache.checkpoint_path(copy))
        # A copied log is a different configured state, not an alias of the
        # live harness binding. Model its independent caller context explicitly.
        from contextvars import Context
        def materialize_copy():
            with authority_context(self.vault, copy):
                return materialize_executions(
                    copy,
                    execution_capable_targets={"alpha", "bravo", "charlie"},
                    now=T0 + timedelta(hours=1),
                )
        created = Context().run(materialize_copy)
        return [execution.to_dict() for execution in created]

    def full_parse_snapshot(self) -> dict[str, object]:
        """The same snapshot with the checkpoint read path disabled."""
        with mock.patch.dict(os.environ, {projection_cache.CACHE_MODE_ENV: "off"}):
            return self.snapshot()

    def checkpoint_only_snapshot(self) -> dict[str, object]:
        with mock.patch.dict(os.environ, {projection_cache.CACHE_MODE_ENV: "require"}):
            return self.snapshot()

    def write_checkpoint(self, payload: dict[str, object]) -> None:
        projection_cache.checkpoint_path(self.state).write_text(
            json.dumps(payload, sort_keys=True), encoding="utf-8"
        )

    def read_checkpoint(self) -> dict[str, object]:
        return json.loads(projection_cache.checkpoint_path(self.state).read_text(encoding="utf-8"))

    def retag(self, payload: dict[str, object]) -> dict[str, object]:
        """Re-seal a tampered checkpoint so only the tampering is under test."""
        body = dict(payload)
        body["state_sha256"] = projection_cache.state_fingerprint(body)
        return body


class CheckpointEquivalenceTests(ProjectionCacheHarness):
    def test_overdepth_json_falls_back_and_can_be_rebuilt(self) -> None:
        self.populate()
        baseline = self.full_parse_snapshot()
        for force in (False, True):
            with self.subTest(force=force):
                projection_cache.checkpoint_path(self.state).write_text(
                    '[' * 2000 + '0' + ']' * 2000, encoding='utf-8')
                status = projection_cache.projection_status(self.state)
                self.assertFalse(status['valid'])
                self.assertEqual(status['reason'], 'unreadable')
                self.assertEqual(self.snapshot(), baseline)
                report = projection_cache.build_projection_checkpoint(self.state, force=force)
                self.assertTrue(report['built'], report)
                self.assertEqual(self.checkpoint_only_snapshot(), baseline)

    def test_decisions_read_the_checkpoint_and_the_tail(self) -> None:
        self.populate()
        projection_cache.build_projection_checkpoint(self.state, force=True)
        self.log.decision("decision.answered", "decision_2", T0 + timedelta(seconds=30), status="answered",
                          choice="deny")
        seed, tail, source = projection_cache.projection_source(self.state, "decisions")
        self.assertEqual(source, "checkpoint")
        self.assertEqual([event.type for event in tail], ["decision.answered"])
        with mock.patch.dict(os.environ, {projection_cache.CACHE_MODE_ENV: "require"}):
            decisions = project_decisions(self.state)
        self.assertEqual(decisions["decision_1"].choice, "approve")
        self.assertEqual((decisions["decision_2"].status, decisions["decision_2"].choice), ("answered", "deny"))

    def test_a_schema_2_checkpoint_without_decisions_is_rebuilt_not_trusted(self) -> None:
        self.populate()
        projection_cache.build_projection_checkpoint(self.state, force=True)
        old = self.read_checkpoint()
        old["schema"] = 2
        del old["projections"]["decisions"]
        self.write_checkpoint(self.retag(old))
        self.assertFalse(projection_cache.projection_status(self.state)["valid"])
        self.assertEqual(self.snapshot(), self.full_parse_snapshot())
        report = projection_cache.build_projection_checkpoint(self.state)  # not forced: repair path
        self.assertTrue(report["built"], report)
        self.assertEqual(self.checkpoint_only_snapshot(), self.full_parse_snapshot())

    def test_malformed_decisions_seed_falls_back_to_the_full_parse(self) -> None:
        self.populate()
        projection_cache.build_projection_checkpoint(self.state, force=True)
        bad = self.read_checkpoint()
        bad["projections"]["decisions"]["decisions"][0]["allow_text"] = "yes"
        self.write_checkpoint(self.retag(bad))
        _seed, _events, source = projection_cache.projection_source(self.state, "decisions")
        self.assertEqual(source, "full")
        self.assertEqual(self.snapshot(), self.full_parse_snapshot())

    def test_checkpoint_tail_equals_full_projection_for_every_projection(self) -> None:
        self.populate()
        baseline = self.full_parse_snapshot()

        report = projection_cache.build_projection_checkpoint(self.state, force=True)
        self.assertTrue(report["built"], report)
        status = projection_cache.projection_status(self.state)
        self.assertTrue(status["present"])
        self.assertTrue(status["valid"], status)
        self.assertEqual(status["tail_bytes"], 0)
        self.assertEqual(status["log_size"], self.state.stat().st_size)
        self.assertGreater(status["event_count"], 0)

        # Nothing new: the checkpoint path must reproduce the full projection.
        self.assertEqual(self.checkpoint_only_snapshot(), baseline)

        # One more event per projection family, then the tail must be applied.
        self.log.item("outbox.enqueued", "outbox_3", "alpha", T0 + timedelta(seconds=18), status="pending")
        self.log.execution("execution.created", "execution_4", "alpha", T0 + timedelta(seconds=19), status="pending")
        self.log.tick(T0 + timedelta(seconds=20), targets=("alpha",), route_revision="rev-3")
        self.log.materialization("event_000017", T0 + timedelta(seconds=21))
        self.log.decision("decision.answered", "decision_2", T0 + timedelta(seconds=22), status="answered",
                          choice="deny")

        for name in projection_cache.PROJECTIONS:
            _seed, events, source = projection_cache.projection_source(self.state, name)
            self.assertEqual(source, "checkpoint", name)
            self.assertGreater(len(events), 0, name)

        self.assertEqual(self.checkpoint_only_snapshot(), self.full_parse_snapshot())
        self.assertGreater(projection_cache.projection_status(self.state)["tail_bytes"], 0)

    def test_projection_is_unchanged_when_the_checkpoint_is_deleted(self) -> None:
        self.populate()
        baseline = self.full_parse_snapshot()
        projection_cache.build_projection_checkpoint(self.state, force=True)
        self.assertEqual(self.checkpoint_only_snapshot(), baseline)

        projection_cache.checkpoint_path(self.state).unlink()
        self.assertFalse(projection_cache.projection_status(self.state)["present"])
        self.assertEqual(self.full_parse_snapshot(), baseline)
        self.assertEqual(self.snapshot(), baseline)

    def test_stale_checkpoint_by_one_event_stays_correct_and_is_used(self) -> None:
        self.populate()
        projection_cache.build_projection_checkpoint(self.state, force=True)
        prefix_offset = self.read_checkpoint()["log_offset"]

        self.log.item("outbox.enqueued", "outbox_4", "alpha", T0 + timedelta(seconds=22), status="pending")
        expected_tail = self.state.stat().st_size - prefix_offset
        self.assertEqual(projection_cache.projection_status(self.state)["tail_bytes"], expected_tail)

        self.assertEqual(self.checkpoint_only_snapshot(), self.full_parse_snapshot())
        _seed, events, source = projection_cache.projection_source(self.state, "outbox")
        self.assertEqual(source, "checkpoint")
        self.assertEqual(len(events), 1)

    def test_the_equality_assertion_can_discriminate_seed_and_tail_use(self) -> None:
        """The comparison above has teeth: both halves of the resume must matter."""
        self.populate()
        projection_cache.build_projection_checkpoint(self.state, force=True)
        baseline = self.full_parse_snapshot()

        # A checkpoint whose seed lost one execution still passes every structural
        # check, so only a *different* result can prove the seed was consulted.
        tampered = self.read_checkpoint()
        executions = list(tampered["projections"]["executions"]["executions"])
        self.assertTrue(executions)
        executions.pop(0)
        tampered["projections"]["executions"]["executions"] = executions
        self.write_checkpoint(self.retag(tampered))
        self.assertNotEqual(self.checkpoint_only_snapshot(), baseline)

        # And the tail is applied, not skipped: the id only exists after the
        # checkpoint offset, so it can only come from the resumed events.
        self.log.execution("execution.created", "execution_9", "alpha", T0 + timedelta(seconds=23), status="pending")
        seed, events, source = projection_cache.projection_source(self.state, "executions")
        self.assertEqual(source, "checkpoint")
        self.assertNotIn("execution_9", {entry["id"] for entry in seed["executions"]})
        self.assertIn("execution_9", self.checkpoint_only_snapshot()["executions"])

    def test_a_malformed_prefix_execution_stays_disqualified_across_the_boundary(self) -> None:
        self.populate()
        projection_cache.build_projection_checkpoint(self.state, force=True)
        # The malformed event lives in the prefix; a valid event for the same id
        # arrives in the tail and must still be ignored.
        self.log.execution("execution.created", "execution_2", "bravo", T0 + timedelta(seconds=24), status="pending")
        resumed = self.checkpoint_only_snapshot()
        self.assertEqual(resumed, self.full_parse_snapshot())
        self.assertNotIn("execution_2", resumed["executions"])

    def test_tick_seed_ordering_survives_the_boundary(self) -> None:
        self.populate()
        projection_cache.build_projection_checkpoint(self.state, force=True)
        self.log.tick(T0 + timedelta(seconds=25), targets=("bravo",), route_sha256="b" * 64)
        resumed = self.checkpoint_only_snapshot()
        self.assertEqual(resumed, self.full_parse_snapshot())
        self.assertEqual(resumed["dispatcher_tick"]["route_sha256"], "b" * 64)


class RandomizedEquivalenceTests(ProjectionCacheHarness):
    """Property test: resume state plus tail equals the full-log projection."""

    def test_randomized_resume_equals_full_projection_at_every_checkpoint(self) -> None:
        self.random_log()
        lines = self.state.read_text(encoding="utf-8").splitlines(keepends=True)
        chunk = len(lines) // 4
        self.assertTrue(chunk > 0)
        for covered, keep in ((chunk, chunk * 2), (chunk * 2, chunk * 3), (chunk * 3, len(lines))):
            self.state.write_text("".join(lines[:covered]), encoding="utf-8")
            report = projection_cache.build_projection_checkpoint(self.state, force=True)
            self.assertTrue(report["built"], report)
            self.state.write_text("".join(lines[:keep]), encoding="utf-8")
            with mock.patch.dict(os.environ, {projection_cache.CACHE_MODE_ENV: "off"}):
                expected = self.snapshot()
            # Without this the comparison silently degrades to comparing two
            # empty lists, which is exactly how it passed while the seed went
            # unread. A fixture change must fail here, not go quiet.
            self.assertTrue(expected["materialized"], "materialization comparison is vacuous")
            self.assertEqual(self.checkpoint_only_snapshot(), expected)
            status = projection_cache.projection_status(self.state)
            self.assertTrue(status["valid"], status)
            self.assertGreater(status["tail_bytes"], 0)

    def test_randomized_stale_checkpoint_at_every_tail_length(self) -> None:
        """Rebuild at each step, so the tail's *first* event keeps changing."""
        self.random_log(160, seed=99)
        lines = self.state.read_text(encoding="utf-8").splitlines(keepends=True)
        covered = 60
        tails = 0
        for target in range(67, len(lines) + 1, 7):
            self.state.write_text("".join(lines[:covered]), encoding="utf-8")
            report = projection_cache.build_projection_checkpoint(self.state, force=True)
            self.assertTrue(report["built"], report)
            self.state.write_text("".join(lines[:target]), encoding="utf-8")
            self.assertEqual(
                projection_cache.projection_status(self.state)["tail_bytes"],
                sum(len(line.encode("utf-8")) for line in lines[covered:target]),
            )
            with mock.patch.dict(os.environ, {projection_cache.CACHE_MODE_ENV: "off"}):
                expected = self.snapshot()
            self.assertTrue(expected["materialized"], "materialization comparison is vacuous")
            self.assertEqual(self.checkpoint_only_snapshot(), expected, target)
            covered = target
            tails += 1
        self.assertGreater(tails, 8)


class CheckpointInvalidationTests(ProjectionCacheHarness):
    def invalid_cases(self) -> list[tuple[str, dict[str, object]]]:
        projection_cache.build_projection_checkpoint(self.state, force=True)
        good = self.read_checkpoint()
        offset = int(good["log_offset"])
        size = self.state.stat().st_size
        mid = offset - 5
        self.assertGreater(mid, 0)

        missing_projection = json.loads(json.dumps(good))
        missing_projection["projections"].pop("outbox")
        missing_projection = self.retag(missing_projection)

        wrong_types = json.loads(json.dumps(good))
        wrong_types["projections"]["dispatcher_tick"] = ["not", "a", "mapping"]
        wrong_types = self.retag(wrong_types)

        # Unsealed metadata tamper: the content fingerprint must cover the fields
        # that decide the tail's numbering, not just the projected state. (A
        # re-sealed file is internally consistent by construction, like any other
        # coherent rewrite of the file.)
        wrong_prefix_lines = {**good, "prefix_lines": int(good["prefix_lines"]) + 3}

        mid_record = json.loads(json.dumps(good))
        mid_record["log_offset"] = mid
        # The fingerprints are correct for the tampered offset, so only the
        # record-boundary guard can reject this checkpoint.
        mid_record["prefix_fingerprint"] = projection_cache.prefix_fingerprint(self.state, mid)
        mid_record = self.retag(mid_record)

        return [
            ("unknown schema", {**good, "schema": projection_cache.SCHEMA_VERSION + 1}),
            ("schema is not an integer", {**good, "schema": str(projection_cache.SCHEMA_VERSION)}),
            ("offset beyond the log", {**good, "log_offset": size + 1}),
            ("offset is not a record boundary", mid_record),
            ("prefix fingerprint mismatch", {**good, "prefix_fingerprint": "f" * 64}),
            ("content fingerprint mismatch", {**good, "state_sha256": "0" * 64}),
            ("projection missing", missing_projection),
            ("projection shape is wrong", wrong_types),
            ("prefix line count is unsealed", wrong_prefix_lines),
            ("not an object", ["nope"]),  # type: ignore[list-item]
        ]

    def test_invalid_checkpoints_fall_back_and_never_change_the_projection(self) -> None:
        self.populate()
        baseline = self.full_parse_snapshot()
        for label, payload in self.invalid_cases():
            with self.subTest(label):
                self.write_checkpoint(payload)
                status = projection_cache.projection_status(self.state)
                self.assertFalse(status["valid"], status)
                self.assertEqual(self.snapshot(), baseline)
                with mock.patch.dict(os.environ, {projection_cache.CACHE_MODE_ENV: "require"}):
                    with self.assertRaises(projection_cache.ProjectionCacheUnavailable):
                        self.snapshot()
        # Removing the checkpoint restores the healthy state.
        projection_cache.checkpoint_path(self.state).unlink()
        self.assertTrue(projection_cache.build_projection_checkpoint(self.state, force=True)["built"])

    def test_corrupt_checkpoint_json_falls_back(self) -> None:
        self.populate()
        baseline = self.full_parse_snapshot()
        projection_cache.checkpoint_path(self.state).write_text("{ not json", encoding="utf-8")
        self.assertEqual(self.snapshot(), baseline)
        self.assertFalse(projection_cache.projection_status(self.state)["valid"])

    def test_truncated_log_invalidates_the_checkpoint(self) -> None:
        self.populate()
        projection_cache.build_projection_checkpoint(self.state, force=True)
        lines = self.state.read_text(encoding="utf-8").splitlines(keepends=True)
        # Truncate at a record boundary, so the log itself stays readable and
        # only the checkpoint is stale beyond recovery.
        self.state.write_text("".join(lines[: len(lines) // 3]), encoding="utf-8")
        status = projection_cache.projection_status(self.state)
        self.assertFalse(status["valid"], status)
        with mock.patch.dict(os.environ, {projection_cache.CACHE_MODE_ENV: "off"}):
            expected = self.snapshot()
        self.assertEqual(self.snapshot(), expected)

    def test_a_rewritten_boundary_window_is_detected_by_the_fingerprint(self) -> None:
        self.populate()
        projection_cache.build_projection_checkpoint(self.state, force=True)
        data = self.state.read_bytes()
        # Same length, different bytes inside the fingerprinted window: size and
        # record boundary still line up, so only the fingerprint can catch it.
        window = projection_cache.PREFIX_FINGERPRINT_BYTES
        self.state.write_bytes(data[:-window] + data[-window:].replace(b"a", b"b"))
        self.assertFalse(projection_cache.projection_status(self.state)["valid"])
        with mock.patch.dict(os.environ, {projection_cache.CACHE_MODE_ENV: "require"}):
            with self.assertRaises(projection_cache.ProjectionCacheUnavailable):
                self.snapshot()

    def test_in_place_prefix_mutation_is_caught_by_the_deep_verify(self) -> None:
        """The bounded fingerprint binds the boundary, not the whole prefix."""
        self.populate()
        projection_cache.build_projection_checkpoint(self.state, force=True)
        lines = self.state.read_text(encoding="utf-8").splitlines(keepends=True)
        target = next(
            index
            for index, line in enumerate(lines)
            if '"type": "execution.completed"' in line
        )
        lines[target] = lines[target].replace('"status": "completed"', '"status": "cancelled"')
        mutated = "".join(lines)
        self.assertNotEqual(mutated, "".join(lines[:target] + lines[target + 1 :]))
        self.state.write_text(mutated, encoding="utf-8")
        # The change is far from the boundary, so the cheap status still looks
        # valid...
        self.assertTrue(projection_cache.projection_status(self.state)["valid"])
        # ...and the explicit deep check is what catches it.
        verification = projection_cache.verify_projection_checkpoint(self.state)
        self.assertFalse(verification["ok"], verification)
        self.assertIn("executions", verification["mismatched"])


class CheckpointErrorSurfaceTests(ProjectionCacheHarness):
    def test_torn_final_record_reports_the_absolute_line_number(self) -> None:
        self.populate()
        projection_cache.build_projection_checkpoint(self.state, force=True)
        self.log.raw('{"id": "event_broken", "type": "task.created"')
        with mock.patch.dict(os.environ, {projection_cache.CACHE_MODE_ENV: "off"}):
            with self.assertRaises(ValueError) as full:
                self.snapshot()
        with mock.patch.dict(os.environ, {projection_cache.CACHE_MODE_ENV: "require"}):
            with self.assertRaises(ValueError) as resumed:
                self.snapshot()
        self.assertEqual(str(resumed.exception), str(full.exception))
        self.assertIn("line", str(resumed.exception))

    def test_malformed_tick_in_the_tail_fails_like_the_full_parse(self) -> None:
        self.populate()
        projection_cache.build_projection_checkpoint(self.state, force=True)
        self.log.event(
            "outbox.dispatcher.tick", "outbox_dispatcher", T0 + timedelta(seconds=26),
            {"configured_targets": "alpha", "healthy": True, "materialization_remaining": False},
        )
        with mock.patch.dict(os.environ, {projection_cache.CACHE_MODE_ENV: "off"}):
            with self.assertRaises(ValueError) as full:
                project_dispatcher_tick(self.state)
        with mock.patch.dict(os.environ, {projection_cache.CACHE_MODE_ENV: "require"}):
            with self.assertRaises(ValueError) as resumed:
                project_dispatcher_tick(self.state)
        self.assertEqual(str(resumed.exception), str(full.exception))

    def test_prefix_line_numbering_matches_the_full_parse(self) -> None:
        self.populate()
        projection_cache.build_projection_checkpoint(self.state, force=True)
        checkpoint = self.read_checkpoint()
        offset = int(checkpoint["log_offset"])
        self.log.execution("execution.created", "execution_5", "alpha", T0 + timedelta(seconds=27), status="pending")
        events = read_events(self.state)
        prefix_events = int(checkpoint["event_count"])
        self.assertEqual(prefix_events, len(events) - 1)
        tail = projection_cache.read_tail_events(
            self.state, offset, int(checkpoint["prefix_lines"]) + 1
        )
        self.assertEqual(
            [(event.id, event.type, event.timestamp, event.payload) for event in tail],
            [(event.id, event.type, event.timestamp, event.payload) for event in events[prefix_events:]],
        )


class CheckpointWritePathTests(ProjectionCacheHarness):
    def test_threshold_guards_the_write_path(self) -> None:
        self.log.tick(T0)
        # The first checkpoint bootstraps regardless of the threshold, so a
        # fresh state directory is never left without a read path.
        report = projection_cache.maybe_refresh_projection_checkpoint(self.state, min_tail_bytes=1024)
        self.assertTrue(report["built"], report)
        self.assertEqual(report["reason"], "bootstrap")
        offset = int(report["log_offset"])
        self.assertEqual(offset, self.state.stat().st_size)

        self.log.item("outbox.enqueued", "outbox_5", "alpha", T0 + timedelta(seconds=1), status="pending")
        skipped = projection_cache.maybe_refresh_projection_checkpoint(self.state, min_tail_bytes=1024)
        self.assertFalse(skipped["built"])
        self.assertEqual(skipped["reason"], "tail_below_threshold")
        self.assertEqual(
            int(projection_cache.inspect_checkpoint(self.state)["log_offset"]), offset
        )

        forced = projection_cache.build_projection_checkpoint(self.state, force=True)
        self.assertTrue(forced["built"], forced)
        self.assertEqual(int(forced["log_offset"]), self.state.stat().st_size)

    def test_refresh_is_a_no_op_when_the_checkpoint_already_covers_the_log(self) -> None:
        self.populate()
        first = projection_cache.build_projection_checkpoint(self.state, force=True)
        self.assertTrue(first["built"])
        second = projection_cache.maybe_refresh_projection_checkpoint(self.state, min_tail_bytes=1)
        self.assertFalse(second["built"])
        self.assertEqual(second["reason"], "nothing_new")

    def test_a_decision_record_missing_its_id_is_reported_not_raised(self) -> None:
        """A scheduled tick must report an unprojectable record, not die on it."""
        self.populate()
        self.log.event("decision.requested", "decision_bad", T0, {"execution_id": "execution_1"})
        report = projection_cache.maybe_refresh_projection_checkpoint(self.state, min_tail_bytes=1)
        self.assertFalse(report["built"])
        self.assertIn("unavailable:", report["reason"])
        # Nothing half-written: the log stays the authority and readers keep the
        # full parse, which is the documented degradation for an unusable checkpoint.
        self.assertFalse(projection_cache.checkpoint_path(self.state).exists())
        # The read path stays fail-closed; only the scheduled write path is tolerant.
        with self.assertRaises(KeyError):
            project_decisions(self.state)

    def test_the_write_path_refuses_a_log_above_the_ceiling(self) -> None:
        self.populate()
        report = projection_cache.build_projection_checkpoint(
            self.state, force=True, max_log_bytes=1
        )
        self.assertFalse(report["built"], report)
        self.assertEqual(report["reason"], "log_above_ceiling")
        self.assertFalse(projection_cache.checkpoint_path(self.state).exists())
        self.assertEqual(report["log_size"], self.state.stat().st_size)

    def test_a_built_checkpoint_reports_its_own_cost(self) -> None:
        self.populate()
        report = projection_cache.build_projection_checkpoint(self.state, force=True)
        self.assertTrue(report["built"], report)
        self.assertGreater(report["build_seconds"], 0)
        self.assertEqual(report["event_count"], len(read_events(self.state)))

    def test_building_over_an_invalid_checkpoint_repairs_it(self) -> None:
        self.populate()
        self.write_checkpoint({"schema": 99, "log_offset": 5})
        self.assertFalse(projection_cache.projection_status(self.state)["valid"])
        self.assertTrue(projection_cache.build_projection_checkpoint(self.state, force=True)["built"])
        self.assertTrue(projection_cache.projection_status(self.state)["valid"])

    def test_missing_and_empty_logs_are_safe(self) -> None:
        self.assertFalse(projection_cache.projection_status(self.state)["present"])
        seed, events, source = projection_cache.projection_source(self.state, "outbox")
        self.assertIsNone(seed)
        self.assertEqual(events, [])
        self.assertEqual(source, "full")
        self.state.unlink()
        report = projection_cache.maybe_refresh_projection_checkpoint(self.state, min_tail_bytes=1)
        self.assertFalse(report["built"])
        self.assertEqual(report["reason"], "no_log")

        self.state.parent.mkdir(parents=True, exist_ok=True)
        self.state.write_text("", encoding="utf-8")
        report = projection_cache.build_projection_checkpoint(self.state, force=True)
        self.assertFalse(report["built"])
        self.assertEqual(report["reason"], "empty_log")

    def test_checkpoint_file_is_owner_only(self) -> None:
        if os.name == "nt":
            self.skipTest("POSIX mode bits")
        self.populate()
        projection_cache.build_projection_checkpoint(self.state, force=True)
        mode = os.stat(projection_cache.checkpoint_path(self.state)).st_mode & 0o777
        self.assertEqual(mode, 0o600)


class ResumeCostAndOrderTests(ProjectionCacheHarness):
    def test_a_no_op_refresh_never_reads_the_log(self) -> None:
        """The tick's common case must not pay the full parse again."""
        self.populate()
        self.assertTrue(projection_cache.build_projection_checkpoint(self.state, force=True)["built"])

        def explode(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("the no-op refresh read the whole log")

        with mock.patch.object(projection_cache, "_read_log", explode):
            report = projection_cache.maybe_refresh_projection_checkpoint(
                self.state, min_tail_bytes=1024
            )
        self.assertFalse(report["built"])
        self.assertEqual(report["reason"], "nothing_new")
        self.assertEqual(report["build_seconds"], 0.0)

        self.log.item("outbox.enqueued", "outbox_6", "alpha", T0 + timedelta(seconds=30), status="pending")
        with mock.patch.object(projection_cache, "_read_log", explode):
            report = projection_cache.maybe_refresh_projection_checkpoint(
                self.state, min_tail_bytes=1024
            )
        self.assertFalse(report["built"])
        self.assertEqual(report["reason"], "tail_below_threshold")

    def test_resumed_projection_preserves_iteration_order(self) -> None:
        """Order matters: some consumers break ties by first-seen order."""
        self.random_log(120, seed=7)
        with mock.patch.dict(os.environ, {projection_cache.CACHE_MODE_ENV: "off"}):
            expected_executions = list(project_executions(self.state).items())
            expected_outbox = list(project_outbox(self.state).items())
        self.assertTrue(projection_cache.build_projection_checkpoint(self.state, force=True)["built"])
        self.log.item("outbox.enqueued", "outbox_zz", "alpha", T0 + timedelta(seconds=200), status="pending")
        resumed_executions = list(project_executions(self.state).items())
        resumed_outbox = list(project_outbox(self.state).items())
        self.assertEqual(
            [key for key, _ in expected_executions],
            [key for key, _ in resumed_executions][: len(expected_executions)],
        )
        self.assertEqual(
            [key for key, _ in expected_outbox],
            [key for key, _ in resumed_outbox][: len(expected_outbox)],
        )
        self.assertEqual(resumed_outbox[-1][0], "outbox_zz")


class ProjectionCacheModeTests(ProjectionCacheHarness):
    def test_require_fails_closed_without_a_checkpoint(self) -> None:
        self.populate()
        with mock.patch.dict(os.environ, {projection_cache.CACHE_MODE_ENV: "require"}):
            with self.assertRaises(projection_cache.ProjectionCacheUnavailable):
                self.snapshot()

    def test_auto_falls_back_without_a_checkpoint(self) -> None:
        self.populate()
        _seed, events, source = projection_cache.projection_source(self.state, "executions")
        self.assertIsNone(_seed)
        self.assertEqual(source, "full")
        self.assertEqual(len(events), len(read_events(self.state)))

    def test_off_disables_the_read_path_even_with_a_valid_checkpoint(self) -> None:
        self.populate()
        self.assertTrue(projection_cache.build_projection_checkpoint(self.state, force=True)["built"])
        with mock.patch.dict(os.environ, {projection_cache.CACHE_MODE_ENV: "off"}):
            _seed, _events, source = projection_cache.projection_source(self.state, "outbox")
        self.assertEqual(source, "full")


class ProjectionCacheSurfaceTests(ProjectionCacheHarness):
    def test_cli_verify_confirms_a_matching_checkpoint(self) -> None:
        import io
        from contextlib import redirect_stdout

        self.populate()
        cli_main(["--authority-vault", str(self.vault), *["control-log", "projection-checkpoint", "--state", str(self.state)]])
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli_main(["--authority-vault", str(self.vault), *["control-log", "projection-verify", "--state", str(self.state), "--json"]])
        self.assertEqual(code, 0, out.getvalue())
        self.assertTrue(json.loads(out.getvalue().strip())["ok"])

    def test_dispatcher_refreshes_the_checkpoint_off_the_request_path(self) -> None:
        from arvyx_control import dispatcher

        self.populate()
        # A dry run must not write anything.
        self.assertIsNone(
            dispatcher._refresh_projection_checkpoint(self.state, min_tail_bytes=1, dry_run=True)
        )
        self.assertFalse(projection_cache.checkpoint_path(self.state).exists())

        report = dispatcher._refresh_projection_checkpoint(
            self.state, min_tail_bytes=1, dry_run=False
        )
        self.assertIsNotNone(report)
        self.assertTrue(report["built"], report)
        self.assertTrue(projection_cache.projection_status(self.state)["valid"])

        # A negative threshold disables the refresh entirely.
        projection_cache.checkpoint_path(self.state).unlink()
        self.assertIsNone(
            dispatcher._refresh_projection_checkpoint(self.state, min_tail_bytes=-1, dry_run=False)
        )
        self.assertFalse(projection_cache.checkpoint_path(self.state).exists())

    def test_cli_builds_reports_and_statuses_a_checkpoint(self) -> None:
        self.populate()
        import io
        from contextlib import redirect_stdout

        out = io.StringIO()
        with redirect_stdout(out):
            code = cli_main(
                ["--authority-vault", str(self.vault), *["control-log", "projection-checkpoint", "--state", str(self.state), "--json"]]
            )
        self.assertEqual(code, 0, out.getvalue())
        body = json.loads(out.getvalue().strip().splitlines()[-1])
        self.assertTrue(body["built"], body)

        out = io.StringIO()
        with redirect_stdout(out):
            code = cli_main(["--authority-vault", str(self.vault), *["control-log", "projection-status", "--state", str(self.state), "--json"]])
        self.assertEqual(code, 0, out.getvalue())
        status = json.loads(out.getvalue().strip().splitlines()[-1])
        self.assertTrue(status["present"])
        self.assertTrue(status["valid"])

    def test_verify_separates_a_log_contradiction_from_a_benign_invalidity(self) -> None:
        import io
        from contextlib import redirect_stdout

        self.populate()
        projection_cache.build_projection_checkpoint(self.state, force=True)

        # The bytes the checkpoint was built against are gone: a contradiction,
        # even though the checkpoint file itself is well formed.
        data = self.state.read_bytes()
        window = projection_cache.PREFIX_FINGERPRINT_BYTES
        self.state.write_bytes(data[:-window] + data[-window:].replace(b"a", b"b"))
        contradiction = projection_cache.verify_projection_checkpoint(self.state)
        self.assertFalse(contradiction["ok"], contradiction)
        self.assertTrue(contradiction["disagrees_with_log"])
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli_main(["--authority-vault", str(self.vault), *["control-log", "projection-verify", "--state", str(self.state), "--json"]])
        self.assertEqual(code, 1, out.getvalue())

        # A corrupt checkpoint is rejected by the read path and is not an incident.
        projection_cache.checkpoint_path(self.state).write_text("{ not json", encoding="utf-8")
        benign = projection_cache.verify_projection_checkpoint(self.state)
        self.assertFalse(benign["ok"], benign)
        self.assertFalse(benign["disagrees_with_log"])
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli_main(["--authority-vault", str(self.vault), *["control-log", "projection-verify", "--state", str(self.state), "--json"]])
        self.assertEqual(code, 0, out.getvalue())

    def test_the_benchmark_never_writes_against_an_external_log_by_default(self) -> None:
        import importlib.util
        import io
        from contextlib import redirect_stdout

        repo = Path(__file__).resolve().parents[3]
        spec = importlib.util.spec_from_file_location(
            "projection_checkpoint_benchmark",
            repo / "scripts" / "projection_checkpoint_benchmark.py",
        )
        assert spec is not None and spec.loader is not None
        benchmark = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(benchmark)

        self.populate()
        out = io.StringIO()
        with redirect_stdout(out):
            code = benchmark.main(["--state", str(self.state), "--repeats", "1", "--json"])
        # Measuring a baseline without a checkpoint is not a successful resumed
        # qualification, even though the read-only observation itself completed.
        self.assertEqual(code, 1, out.getvalue())
        payload = json.loads(out.getvalue().strip().splitlines()[-1])
        self.assertFalse(payload["ok"])
        self.assertFalse(payload["qualification_complete"])
        self.assertFalse(payload["checkpoint_write_allowed"], payload)
        self.assertEqual(payload["build"]["reason"], "write_not_allowed")
        self.assertFalse(projection_cache.checkpoint_path(self.state).exists())
        self.assertEqual(payload["refresh_noop_reason"], "")

    def _benchmark_module(self):
        import importlib.util

        repo = Path(__file__).resolve().parents[3]
        spec = importlib.util.spec_from_file_location(
            "projection_checkpoint_benchmark", repo / "scripts" / "projection_checkpoint_benchmark.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_benchmark_nearest_rank_keeps_the_small_sample_tail(self) -> None:
        benchmark = self._benchmark_module()
        for population in (1, 2, 5, 19):
            with self.subTest(population=population):
                self.assertEqual(benchmark.nearest_rank([0.1] * (population - 1) + [20.0], 95), 20.0)
        self.assertEqual(benchmark.nearest_rank([0.1] * 19 + [20.0], 95), 0.1)
        self.assertEqual(benchmark.nearest_rank([1.0, 2.0], 50), 1.0)
        with self.assertRaises(ValueError):
            benchmark.nearest_rank([], 95)

    def test_benchmark_verdict_requires_every_budget_and_correctness_input(self) -> None:
        benchmark = self._benchmark_module()
        timings = {name + "_p95": 0.1 for name in (
            "read_events", "project_executions", "project_outbox", "project_dispatcher_tick",
            "project_materialization_checkpoint", "deliveries_health")}

        def verdict(values=timings, verify=True, equivalent=True, noop=0.1):
            return benchmark.budget_verdict(values, {"ok": verify}, {"ok": equivalent},
                                            budget=2.0, noop_seconds=noop)

        self.assertTrue(verdict()["ok"])
        self.assertFalse(verdict({})["ok"])
        for name in timings:
            with self.subTest(name=name):
                for slow in (2.00001, float("nan"), float("inf"), -1.0):
                    self.assertFalse(verdict({**timings, name: slow})["ok"])
                self.assertFalse(verdict({key: value for key, value in timings.items() if key != name})["ok"])
        self.assertFalse(verdict(verify=False)["ok"])
        self.assertFalse(verdict(equivalent=False)["ok"])
        self.assertFalse(verdict(noop=2.00001)["ok"])

    def test_benchmark_nothing_new_still_measures_and_verifies_checkpoint(self) -> None:
        import io
        from contextlib import redirect_stdout

        benchmark = self._benchmark_module()
        self.populate()
        self.assertTrue(projection_cache.build_projection_checkpoint(self.state, force=True)["built"])
        for correctness in (True, False):
            with self.subTest(correctness=correctness), mock.patch.object(
                benchmark, "_time", return_value=0.1
            ), mock.patch.object(
                benchmark, "equivalence", return_value={"ok": correctness}
            ) as equivalent, mock.patch.object(
                projection_cache, "verify_projection_checkpoint", wraps=projection_cache.verify_projection_checkpoint
            ) as verify:
                out = io.StringIO()
                with redirect_stdout(out):
                    code = benchmark.main(["--state", str(self.state), "--allow-checkpoint-write",
                                           "--repeats", "1", "--p95-budget-seconds", "60", "--json"])
                payload = json.loads(out.getvalue())
                self.assertEqual(payload["build"]["reason"], "nothing_new")
                self.assertEqual(len(payload["after"]), 12)
                self.assertEqual(len(payload["latency_budget_inputs"]), 7)
                verify.assert_called_once_with(self.state)
                equivalent.assert_called_once_with(self.state)
                self.assertEqual(payload["ok"], correctness)
                self.assertEqual(code, 0 if correctness else 1)

    def test_checkpoint_filename_is_derived_from_the_state_path(self) -> None:
        self.assertEqual(
            projection_cache.checkpoint_path(Path("/srv/arvyx-v2/data/state/control-events.jsonl")),
            Path("/srv/arvyx-v2/data/state/control-events.jsonl.projections.json"),
        )

    def test_state_fingerprint_is_stable_across_key_order(self) -> None:
        payload = {
            "log_offset": 7,
            "log_size": 7,
            "prefix_lines": 2,
            "event_count": 2,
            "projections": {"a": 1, "b": [1, 2]},
        }
        self.assertEqual(
            projection_cache.state_fingerprint(payload),
            projection_cache.state_fingerprint({**payload, "projections": {"b": [1, 2], "a": 1}}),
        )
        # Every bound field is covered: changing one changes the fingerprint.
        for field in projection_cache.FINGERPRINT_FIELDS:
            mutated = {**payload, field: payload[field] + 1}
            self.assertNotEqual(
                projection_cache.state_fingerprint(payload),
                projection_cache.state_fingerprint(mutated),
                field,
            )


class AssignmentSeedTests(ProjectionCacheHarness):
    """The worker's assignment scan resumes from the checkpoint, not the whole log.

    ``materialize_executions`` used to full-parse the log on every worker tick to
    find the handful of assignment-shaped events in it — 4.9 s at 310k events,
    under the state lock. These tests hold the resumed path to the full-parse
    result and pin the property that makes the resume safe: the seed carries the
    events up to the checkpoint offset, the tail carries the rest, and every scan
    input is a set or a scan over exactly those events.
    """

    def setUp(self) -> None:
        super().setUp()
        # A real assignment carries provenance; an unbound post-provenance one
        # never launches, so the fixtures must be bound to be materializable.
        self.assignment = {"target": "alpha", "type": "ask", "actor_identity_bound": True}

    def build(self) -> None:
        projection_cache.build_projection_checkpoint(self.state, force=True)

    def materialize_copy(self, state, **kwargs):
        from contextvars import Context
        def run():
            with authority_context(self.vault, state):
                return materialize_executions(state, **kwargs)
        return Context().run(run)

    def copy_state(self, name: str) -> Path:
        copy = self.root / f"{name}.jsonl"
        shutil.copyfile(self.state, copy)
        checkpoint = projection_cache.checkpoint_path(self.state)
        if checkpoint.exists():
            shutil.copyfile(checkpoint, projection_cache.checkpoint_path(copy))
        return copy

    def subjects(self, created: list) -> set[str]:
        return {str(entry.subject_id) for entry in created}

    def test_the_checkpoint_carries_the_assignments_seed(self) -> None:
        self.log.event("thread.created", "thread_1", T0, self.assignment)
        self.log.tick(T0 + timedelta(seconds=1))
        self.build()
        seed = self.read_checkpoint()["projections"]["assignments"]
        # Only the assignment-shaped event is kept: the tick is 99.5% of the log
        # in production and is exactly what the resume exists to avoid reading.
        self.assertEqual([entry["task_id"] for entry in seed["events"]], ["thread_1"])

    def test_a_prefix_assignment_and_a_tail_assignment_both_materialize(self) -> None:
        self.log.event("thread.created", "thread_prefix", T0, self.assignment)
        self.build()
        self.log.event(
            "thread.created", "thread_tail", T0 + timedelta(seconds=30), self.assignment,
        )
        created = self.materialize_copy(
            self.copy_state("both"), execution_capable_targets={"alpha", "bravo", "charlie"},
        )
        # Dropping either half of the union loses one of these.
        self.assertEqual(self.subjects(created), {"thread_prefix", "thread_tail"})

    def test_the_resumed_scan_never_reads_the_whole_log(self) -> None:
        self.log.event("thread.created", "thread_prefix", T0, self.assignment)
        self.build()
        self.log.event(
            "thread.created", "thread_tail", T0 + timedelta(seconds=30), self.assignment,
        )
        with mock.patch.object(
            execution_module, "read_events", side_effect=AssertionError("full parse")
        ), mock.patch.object(
            projection_cache, "read_events", side_effect=AssertionError("full parse")
        ):
            created = self.materialize_copy(
                self.copy_state("noread"), execution_capable_targets={"alpha", "bravo", "charlie"},
            )
        self.assertEqual(self.subjects(created), {"thread_prefix", "thread_tail"})

    def test_a_legacy_authorization_across_the_boundary_still_launches(self) -> None:
        """A pre-provenance assignment authorized by a later bound ACK.

        The assignment lands in the seed and its authorizing ACK in the tail, so
        this only passes if the scan genuinely unions the two — the reason a
        tail-only read would not have been a valid fix.
        """
        pre_provenance = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)
        self.log.event(
            "thread.created", "thread_legacy", pre_provenance, {"target": "alpha", "type": "ask"},
        )
        self.build()
        self.log.event(
            "thread.acknowledged", "thread_legacy", T0 + timedelta(seconds=5),
            {"acked_by": "alpha", "actor_identity_bound": True},
        )
        created = self.materialize_copy(
            self.copy_state("legacy"), execution_capable_targets={"alpha"},
        )
        self.assertEqual(self.subjects(created), {"thread_legacy"})

    def test_a_retirement_in_the_tail_keeps_a_seeded_subject_inert(self) -> None:
        self.log.event("thread.created", "thread_retired", T0, self.assignment)
        self.build()
        self.log.event("thread.retired", "thread_retired", T0 + timedelta(seconds=1), {})
        created = self.materialize_copy(
            self.copy_state("retired"), execution_capable_targets={"alpha"},
        )
        self.assertEqual(self.subjects(created), set())

    def test_require_mode_without_a_checkpoint_fails_closed(self) -> None:
        self.log.event("thread.created", "thread_1", T0, self.assignment)
        with mock.patch.dict(os.environ, {projection_cache.CACHE_MODE_ENV: "require"}):
            with self.assertRaises(projection_cache.ProjectionCacheUnavailable):
                self.materialize_copy(
                    self.copy_state("nocache"), execution_capable_targets={"alpha"},
                )

    def test_a_checkpoint_built_with_a_different_type_set_is_not_resumed(self) -> None:
        """Changing the seeded types must invalidate an existing checkpoint.

        If it did not, adding a scan type would leave a live checkpoint that
        still validates but whose seed silently lacks the new events, and a
        resumed tick would materialize from an incomplete seed — for hours, until
        the tail threshold happened to force a rebuild. The seed carries the type
        set it was built with, so the change fails validation instead: readers
        full-parse until the next rebuild. Fail-closed with nothing to remember.
        """
        self.log.event("thread.created", "thread_prefix", T0, self.assignment)
        self.build()
        self.log.event(
            "thread.created", "thread_tail", T0 + timedelta(seconds=30), self.assignment,
        )
        payload = self.read_checkpoint()
        payload["projections"]["assignments"]["types"] = ["handoff.created"]  # an older set
        self.write_checkpoint(self.retag(payload))
        self.assertFalse(projection_cache.projection_status(self.state)["valid"])
        created = self.materialize_copy(
            self.copy_state("oldtypes"), execution_capable_targets={"alpha"},
        )
        # Still correct, because the rejected checkpoint means a full parse.
        self.assertEqual(self.subjects(created), {"thread_prefix", "thread_tail"})

    def test_a_schema_3_checkpoint_is_not_trusted_without_assignments(self) -> None:
        """The live production checkpoint is schema 3 today.

        The upgrade must fail its validation and full-parse rather than resume
        with a missing assignments projection — an absent key must never be
        mistaken for "nothing to materialize".
        """
        self.log.event("thread.created", "thread_1", T0, self.assignment)
        self.build()
        self.log.event(
            "thread.created", "thread_2", T0 + timedelta(seconds=1), self.assignment,
        )
        payload = self.read_checkpoint()
        payload["schema"] = 3
        payload["projections"].pop("assignments")
        self.write_checkpoint(self.retag(payload))
        self.assertFalse(projection_cache.projection_status(self.state)["valid"])
        created = self.materialize_copy(
            self.copy_state("schema3"), execution_capable_targets={"alpha"},
        )
        self.assertEqual(self.subjects(created), {"thread_1", "thread_2"})

    def test_resumed_and_full_parse_agree_on_a_mixed_log(self) -> None:
        self.populate()
        self.build()
        self.assertEqual(self.checkpoint_only_snapshot(), self.full_parse_snapshot())


if __name__ == "__main__":
    unittest.main()
