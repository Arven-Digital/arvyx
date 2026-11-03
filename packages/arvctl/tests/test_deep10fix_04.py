"""Lane 04 regressions: disposable authority, no runtime/provider dispatch."""
from contextlib import contextmanager, redirect_stdout
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from arvyx_control import control, execution, projection_cache, store
from arvyx_control.replica_authority import authority_context

NOW = datetime(2026, 10, 28, tzinfo=timezone.utc)
STAMP = "2026-10-28T00:00:00Z"


class Deep10Fix04Tests(unittest.TestCase):
    @contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory(prefix="deep10fix04-") as directory:
            root = Path(directory)
            vault = root / "vault"
            vault.mkdir()
            state = root / "events.jsonl"
            with authority_context(vault, state), patch.dict(
                os.environ, {projection_cache.CACHE_MODE_ENV: "off"}
            ):
                yield state, vault

    def assignment(self, state):
        with patch.object(control, "_now", return_value=STAMP):
            return control.post_thread(
                state, title="disposable assignment", actor="fixture-sender",
                target="fixture-target", thread_type="ask", actor_identity_bound=True,
            ).thread.id

    def prepare_operation(self, state, name):
        self.assignment(state)
        item = execution.materialize_executions(
            state, execution_capable_targets={"fixture-target"}, now=NOW,
        )[0]
        common = dict(execution_id=item.id, now=NOW)
        if name == "cancel":
            return lambda: execution.cancel_execution(
                state, **common, reason="stop", cancelled_by="fixture-operator",
            ), "execution.cancel_requested"
        if name == "hold":
            return lambda: execution.hold_execution(
                state, **common, reason="attention", held_by="fixture-operator",
            ), "execution.held"
        if name == "close":
            execution.hold_execution(state, **common, reason="attention", held_by="fixture-operator")
            return lambda: execution.close_execution(
                state, **common, reason="obsolete fixture", closed_by="fixture-operator",
                resolution_category="obsolete",
            ), "execution.closed"
        claimed = execution.claim_execution(
            state, worker="fixture-worker", execution_capable_targets={"fixture-target"}, now=NOW,
        )
        steer = lambda: execution.request_execution_steer(
            state, **common, attempt_id=claimed.attempt_id, message="inspect fixture",
            requested_by="fixture-operator", idempotency_key="fixture-steer-key-04",
        )
        if name == "steer":
            return steer, "execution.steer.requested"
        request = steer()
        return lambda: execution.acknowledge_execution_steer(
            state, **common, attempt_id=claimed.attempt_id, request_id=request["request_id"],
            actor="fixture-target", message="fixture observed", idempotency_key="test-test-test-04",
        ), "execution.steer.acknowledged"

    @unittest.skipUnless(os.name == 'posix', 'directory fsync barriers are not performed on Windows and file flushes bypass os.fsync (docs/limitations.md, Windows durability)')
    def test_01_uncertain_stop_and_steer_retries_repeat_both_barriers(self):
        for name in ("cancel", "hold", "close", "steer", "ack"):
            for barrier in ("file", "directory"):
                for mode in ("off", "require"):
                    with self.subTest(operation=name, barrier=barrier, mode=mode), self.fixture() as (state, _):
                        operation, event_type = self.prepare_operation(state, name)
                        if mode == "require":
                            projection_cache.build_projection_checkpoint(state, force=True)
                        calls = []
                        real_fsync = os.fsync
                        failing = True

                        def sync(fd):
                            nonlocal failing
                            kind = "directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file"
                            calls.append(kind)
                            if kind == barrier and failing:
                                # Ancestor mkdir barriers happen before the write. Fail
                                # only once the operation's full event is visible.
                                if any(e.type == event_type for e in control.read_events(state)):
                                    raise OSError("injected uncertain barrier")
                            real_fsync(fd)

                        with patch.dict(os.environ, {projection_cache.CACHE_MODE_ENV: mode}), patch.object(os, "fsync", side_effect=sync):
                            with self.assertRaisesRegex(OSError, "uncertain barrier"):
                                operation()
                            uncertain = state.read_bytes()
                            self.assertTrue(uncertain.endswith(b"\n"))
                            self.assertEqual(sum(e.type == event_type for e in control.read_events(state)), 1)
                            calls.clear()
                            with self.assertRaisesRegex(OSError, "uncertain barrier"):
                                operation()
                            self.assertIn(barrier, calls)
                            self.assertEqual(state.read_bytes(), uncertain)
                            failing = False
                            calls.clear()
                            operation()
                            self.assertEqual(calls, ["file", "directory"])
                            self.assertEqual(state.read_bytes(), uncertain)

    def test_01_replay_rejects_missing_delimiter_and_duplicate_source_id(self):
        for name in ("cancel", "hold", "close", "steer", "ack"):
            for damage in ("delimiter", "duplicate"):
                with self.subTest(operation=name, damage=damage), self.fixture() as (state, _):
                    operation, event_type = self.prepare_operation(state, name)
                    operation()
                    source = next(e for e in control.read_events(state) if e.type == event_type)
                    if damage == "delimiter":
                        state.write_bytes(state.read_bytes().rstrip(b"\n"))
                    else:
                        control._append_event(state, source)
                    before = state.read_bytes()
                    with self.assertRaises(ValueError):
                        operation()
                    self.assertEqual(state.read_bytes(), before)

    def test_01_steer_replay_rejects_ambiguous_domain_key(self):
        for name in ("steer", "ack"):
            with self.subTest(operation=name), self.fixture() as (state, _):
                operation, event_type = self.prepare_operation(state, name)
                operation()
                original = next(e for e in control.read_events(state) if e.type == event_type)
                control._append_event(state, replace(original, id="different-source-id"))
                with self.assertRaisesRegex(ValueError, "ambiguous"):
                    operation()

    def test_02_quarantined_roots_stay_inert_without_recreation(self):
        for mode in ("off", "require"):
            for checkpoint_position in ("before", "after"):
                for corrupt in ({"attempts": True}, {"updated_at": "bad-time"}, {"lease_owner": "orphan"}):
                    with self.subTest(mode=mode, checkpoint=checkpoint_position, corrupt=corrupt), self.fixture() as (state, _):
                        subject = self.assignment(state)
                        root_id = execution._execution_id("thread", subject, "fixture-target")
                        valid = execution.Execution(
                            id=root_id, subject_id=subject, subject_type="thread", target="fixture-target",
                            source_event_id=control.read_events(state)[0].id, source_event_type="thread.created",
                            status="pending", attempts=0, created_at=STAMP, updated_at=STAMP,
                        )
                        if mode == "require" and checkpoint_position == "before":
                            projection_cache.build_projection_checkpoint(state, force=True)
                        control._append_event(state, control._event(
                            "execution.created", root_id, STAMP, {**valid.to_dict(), **corrupt},
                        ))
                        # A syntactically valid replacement must never undo quarantine.
                        control._append_event(state, control._event("execution.created", root_id, STAMP, valid.to_dict()))
                        if mode == "require" and checkpoint_position == "after":
                            projection_cache.build_projection_checkpoint(state, force=True)
                        before = state.read_bytes()
                        with patch.dict(os.environ, {projection_cache.CACHE_MODE_ENV: mode}):
                            for _ in range(3):
                                self.assertEqual(execution.materialize_executions(
                                    state, execution_capable_targets={"fixture-target"}, now=NOW,
                                ), [])
                                self.assertIsNone(execution.claim_execution(
                                    state, worker="fixture-worker", execution_capable_targets={"fixture-target"}, now=NOW,
                                ))
                            self.assertNotIn(root_id, execution.project_executions(state))
                            health = execution.queue_health(state, execution_capable_targets={"fixture-target"}, now=NOW)
                            self.assertEqual(health["quarantined_execution_count"], 1)
                            self.assertEqual(health["quarantined_executions"], [root_id])
                            with self.assertRaisesRegex(ValueError, "invalid or quarantined"):
                                execution.claim_execution(
                                    state, worker="fixture-worker", execution_capable_targets={"fixture-target"},
                                    subject_id=subject, target="fixture-target", now=NOW,
                                )
                        self.assertEqual(state.read_bytes(), before)

    def test_03_manifest_fields_and_callers_use_one_byte_snapshot(self):
        from arvyx_control import api, cli

        for surface in ("domain", "cli", "summary"):
            with self.subTest(surface=surface), self.fixture() as (state, vault):
                first = control._event("fixture.first", "fixture", STAMP, {})
                control._append_event(state, first)
                captured = state.read_bytes()
                later = control._event("fixture.later", "fixture", "2026-10-29T00:00:00Z", {})
                original_read = Path.read_bytes
                appended = False

                def racing_read(path):
                    nonlocal appended
                    raw = original_read(path)
                    if path == state and not appended:
                        appended = True
                        control._append_event(state, later)
                    return raw

                # Prime other summary readers so the race occurs at manifest capture.
                control.read_events(state)
                with patch.object(Path, "read_bytes", racing_read):
                    if surface == "domain":
                        result = store.manifest_state(state).to_dict()
                    elif surface == "cli":
                        output = io.StringIO()
                        with redirect_stdout(output):
                            self.assertEqual(cli.main([
                                "--authority-vault", str(vault), "store", "manifest", "--state", str(state), "--json",
                            ]), 0)
                        result = json.loads(output.getvalue())
                    else:
                        result = api._operator_summary(state, "operator", vault)["store"]["source"]
                self.assertTrue(appended)
                self.assertEqual(result["sha256"], hashlib.sha256(captured).hexdigest())
                self.assertEqual(result["events"], 1)
                self.assertEqual(result["first_timestamp"], STAMP)
                self.assertEqual(result["last_timestamp"], STAMP)
                if surface != "summary":
                    self.assertEqual(result["event_types"], {"fixture.first": 1})
                self.assertEqual(len(control.read_events(state)), 2)

    def test_03_manifest_preserves_parser_failure_and_empty_semantics(self):
        with self.fixture() as (state, _):
            result = store.manifest_state(state)
            self.assertEqual(result.events, 0)
            self.assertEqual(result.sha256, hashlib.sha256(b"").hexdigest())
            self.assertIsNone(result.first_timestamp)
            for raw in (b'{"id":', b'\xff\n'):
                state.write_bytes(raw)
                with self.assertRaises(ValueError):
                    store.manifest_state(state)


if __name__ == "__main__":
    unittest.main()
