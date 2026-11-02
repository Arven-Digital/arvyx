from __future__ import annotations
from arvyx_control.replica_authority import authority_context

from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from arvyx_control.vault import init_vault


class CheckpointedIndexRebuildTests(unittest.TestCase):
    def test_heartbeat_samples_clock_after_connection_lock_and_row(self) -> None:
        # NOT_EXECUTED: acquisition and row fetch advance a controlled wall clock.
        from unittest.mock import MagicMock
        from arvyx_control import checkpoint_jobs as jobs

        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        moment = [start]
        class Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                return moment[0]

        connection = MagicMock()
        def execute(sql, *args):
            if sql == "BEGIN IMMEDIATE":
                moment[0] = start + timedelta(seconds=29)
            cursor = MagicMock()
            def fetchone():
                moment[0] = start + timedelta(seconds=31)
                return ("worker", 1, "running", "2026-01-01T00:00:30Z", "generation")
            cursor.fetchone.side_effect = fetchone
            return cursor
        connection.execute.side_effect = execute
        stop = MagicMock()
        stop.wait.side_effect = [False, True]
        lost = MagicMock()
        with patch.object(jobs, "datetime", Clock), patch.object(jobs, "_connect", return_value=connection):
            jobs._renew_heartbeat(Path("unused"), "worker", 1, "generation", 30, stop, lost)
        lost.set.assert_called_once_with()
        self.assertFalse(any("UPDATE jobs" in call.args[0] for call in connection.execute.call_args_list))
        connection.close.assert_called_once_with()

    def test_file_claim_and_checkpoint_reject_time_crossed_during_row_read(self) -> None:
        from unittest.mock import MagicMock
        from arvyx_control import checkpoint_jobs as jobs
        import threading

        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for expire_at in (1, 2):
            with self.subTest(transaction=expire_at):
                moment = [start]
                reads = [0]
                class Clock(datetime):
                    @classmethod
                    def now(cls, tz=None):
                        return moment[0]
                connection = MagicMock()
                def execute(sql, *args):
                    cursor = MagicMock()
                    def fetchone():
                        if "SELECT owner" in sql:
                            reads[0] += 1
                            if reads[0] == expire_at:
                                moment[0] = start + timedelta(seconds=31)
                            return ("worker", 1, "running", "2026-01-01T00:00:30Z", "generation")
                        return None
                    cursor.fetchone.side_effect = fetchone
                    return cursor
                connection.execute.side_effect = execute
                with patch.object(jobs, "datetime", Clock), \
                     patch.object(jobs, "_index_file", return_value=[]), \
                     patch.object(jobs, "_source_snapshot", return_value=((1, 2, "digest"), "")), \
                     patch.object(jobs, "_current_file_stat", return_value=(1, 2, "digest")):
                    with self.assertRaisesRegex(RuntimeError, "lease was lost"):
                        jobs._process_files(
                            connection, root=Path("unused"), stats={"note.md": (1, 2, "digest")},
                            owner="worker", attempt=1, generation="generation", lease_seconds=30,
                            now=None, lease_lost=threading.Event(), after_checkpoint=None)
                self.assertFalse(any("INSERT OR REPLACE INTO checkpoints" in call.args[0]
                                     for call in connection.execute.call_args_list))

    def test_drift_failure_uses_the_injected_clock(self) -> None:
        import sqlite3

        from arvyx_control.checkpoint_jobs import _connect, _journal_path, _mark_failed

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            now = datetime(2026, 1, 1, tzinfo=timezone.utc)
            connection = _connect(_journal_path(vault))
            try:
                connection.execute(
                    "INSERT INTO jobs "
                    "(name,status,attempt,manifest_hash,owner,generation,lease_expires_at,updated_at) "
                    "VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        "index-rebuild", "running", 1, "manifest", "clock-worker",
                        "clock-generation",
                        "2026-01-01T00:00:30Z", "2026-01-01T00:00:00Z",
                    ),
                )
                _mark_failed(
                    connection, owner="clock-worker", attempt=1,
                    generation="clock-generation", reason="injected drift", current=now,
                )
            finally:
                connection.close()

            connection = sqlite3.connect(_journal_path(vault))
            try:
                row = connection.execute(
                    "SELECT status, lease_expires_at, updated_at FROM jobs WHERE name='index-rebuild'"
                ).fetchone()
            finally:
                connection.close()
            self.assertEqual(row, ("failed", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"))

    def test_expired_lease_cannot_commit_a_file_checkpoint(self) -> None:
        import sqlite3

        from arvyx_control.checkpoint_jobs import _journal_path, rebuild_index_checkpointed
        from arvyx_control.index import _index_file as real_index_file

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            now = datetime(2026, 1, 1, tzinfo=timezone.utc)

            def expire_lease(vault_path: Path, relative: str, mtime_ns: int, *, text: str | None = None):
                chunks = list(real_index_file(vault_path, relative, mtime_ns, text=text))
                connection = sqlite3.connect(_journal_path(vault))
                try:
                    connection.execute(
                        "UPDATE jobs SET lease_expires_at=? WHERE name='index-rebuild'",
                        ("2025-12-31T23:59:59Z",),
                    )
                    connection.commit()
                finally:
                    connection.close()
                return chunks

            with patch("arvyx_control.checkpoint_jobs._index_file", side_effect=expire_lease):
                with self.assertRaisesRegex(RuntimeError, "lease was lost"):
                    with authority_context(vault):
                        rebuild_index_checkpointed(
                            vault, owner="expired-worker", now=now, lease_seconds=30,
                        )

    def test_mutation_after_persistence_validation_removes_cache_and_fails_lease(self) -> None:
        from arvyx_control.checkpoint_jobs import index_rebuild_status, rebuild_index_checkpointed
        from arvyx_control.index import INDEX_RELATIVE, _read_cache as real_read_cache

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            now = datetime(2026, 1, 1, tzinfo=timezone.utc)
            target = vault / "projects" / "publish-race.md"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("before\n", encoding="utf-8")

            def read_then_mutate(vault_path: Path):
                # Preserve real persistence validation; inject after its readback.
                files = real_read_cache(vault_path)
                self.assertTrue(files)
                target.write_text("after\n", encoding="utf-8")
                return files

            with patch("arvyx_control.checkpoint_jobs._read_cache", side_effect=read_then_mutate) as readback:
                with self.assertRaisesRegex(RuntimeError, "indexed sources changed during cache publication"):
                    with authority_context(vault):
                        rebuild_index_checkpointed(
                            vault, owner="publish-worker", now=now, lease_seconds=30,
                        )
            self.assertFalse((vault / INDEX_RELATIVE).exists())
            readback.assert_called_once_with(vault.resolve())
            failed = index_rebuild_status(vault)
            self.assertEqual(failed.status, "failed")
            self.assertEqual(failed.lease_expires_at, "2026-01-01T00:00:00Z")
            self.assertEqual(failed.checkpoint, failed.total)

    def test_audit_write_failure_is_visible_without_corrupting_job_state(self) -> None:
        from arvyx_control.checkpoint_jobs import rebuild_index_checkpointed

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            stderr = StringIO()
            with patch("arvyx_control.checkpoint_jobs.append_audit", side_effect=OSError("read-only audit")):
                with redirect_stderr(stderr):
                    with authority_context(vault):
                        result = rebuild_index_checkpointed(
                            vault, owner="audit-failure-worker", lease_seconds=30,
                        )
            self.assertEqual(result.status, "completed")
            self.assertIn("warning: index rebuild audit event was not recorded", stderr.getvalue())
            self.assertNotIn("read-only audit", stderr.getvalue())

    def test_crash_resume_continues_after_durable_checkpoint(self) -> None:
        from arvyx_control.checkpoint_jobs import index_rebuild_status, rebuild_index_checkpointed
        from arvyx_control.index import INDEX_RELATIVE, _index_file as real_index_file

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            now = datetime(2026, 1, 1, tzinfo=timezone.utc)
            visited: list[str] = []

            def recording_index_file(vault_path: Path, relative: str, mtime_ns: int, *, text: str | None = None):
                visited.append(relative)
                return real_index_file(vault_path, relative, mtime_ns, text=text)

            def crash_after_first(relative: str, completed: int) -> None:
                if completed == 1:
                    raise RuntimeError("injected crash")

            with patch("arvyx_control.checkpoint_jobs._index_file", side_effect=recording_index_file):
                with self.assertRaisesRegex(RuntimeError, "injected crash"):
                    with authority_context(vault):
                        rebuild_index_checkpointed(
                            vault,
                            owner="worker-a",
                            now=now,
                            lease_seconds=30,
                            after_checkpoint=crash_after_first,
                        )
                first_file = visited[0]
                crashed = index_rebuild_status(vault)
                self.assertEqual(crashed.status, "running")
                self.assertEqual(crashed.attempt, 1)
                self.assertEqual(crashed.checkpoint, 1)

                with authority_context(vault):
                    resumed = rebuild_index_checkpointed(
                        vault,
                        owner="worker-b",
                        now=now + timedelta(seconds=31),
                        lease_seconds=30,
                    )

            self.assertEqual(resumed.status, "completed")
            self.assertEqual(resumed.attempt, 2)
            self.assertNotIn(first_file, visited[1:])
            self.assertTrue((vault / INDEX_RELATIVE).exists())

    def test_live_lease_blocks_overlap_and_stale_recovery_is_bounded(self) -> None:
        from arvyx_control.checkpoint_jobs import index_rebuild_status, rebuild_index_checkpointed

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            now = datetime(2026, 1, 1, tzinfo=timezone.utc)

            def crash(relative: str, completed: int) -> None:
                raise RuntimeError("injected crash")

            with self.assertRaises(RuntimeError):
                with authority_context(vault):
                    rebuild_index_checkpointed(
                        vault, owner="worker-a", now=now, lease_seconds=30,
                        max_attempts=2, after_checkpoint=crash,
                    )
            with self.assertRaisesRegex(RuntimeError, "already running"):
                with authority_context(vault):
                    rebuild_index_checkpointed(
                        vault, owner="worker-b", now=now + timedelta(seconds=29),
                        lease_seconds=30, max_attempts=2,
                    )
            with self.assertRaises(RuntimeError):
                with authority_context(vault):
                    rebuild_index_checkpointed(
                        vault, owner="worker-b", now=now + timedelta(seconds=31),
                        lease_seconds=30, max_attempts=2, after_checkpoint=crash,
                    )
            with self.assertRaisesRegex(RuntimeError, "attempt budget exhausted"):
                with authority_context(vault):
                    rebuild_index_checkpointed(
                        vault, owner="worker-c", now=now + timedelta(seconds=62),
                        lease_seconds=30, max_attempts=2,
                    )

            failed = index_rebuild_status(vault)
            self.assertEqual(failed.status, "failed")
            self.assertEqual(failed.attempt, 2)
            self.assertGreaterEqual(failed.checkpoint, 1)

    def test_cli_rebuild_and_status_expose_job_receipts(self) -> None:
        from arvyx_control.cli import main

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            rebuilt_out = StringIO()
            with redirect_stdout(rebuilt_out):
                code = main(["index", "rebuild", "--vault", str(vault), "--owner", "cli-worker", "--json"])
            self.assertEqual(code, 0)
            rebuilt = json.loads(rebuilt_out.getvalue())
            self.assertEqual(rebuilt["status"], "completed")
            self.assertEqual(rebuilt["attempt"], 1)
            self.assertEqual(rebuilt["checkpoint"], rebuilt["total"])

            status_out = StringIO()
            with redirect_stdout(status_out):
                code = main(["index", "status", "--vault", str(vault), "--json"])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(status_out.getvalue()), rebuilt)


    # Real-clock lease tests. The heartbeat renews every lease/3 and, correctly,
    # treats a lease it finds already expired as lost, so one stall of the
    # whole process (CPU steal on a shared CI runner, fsync latency on the
    # synchronous=FULL renewal commit, `coverage run --branch` tracing) longer
    # than 2/3 of the lease loses it to the next claimant. A 1 s lease left a
    # 0.67 s stall budget and flaked in CI; 4 s leaves 2.67 s. Each test still
    # waits past the lease it observed before stalling on the slow file, so a
    # live lease at that point can only come from heartbeat renewal.
    REAL_CLOCK_LEASE_SECONDS = 4

    def _wait_past_unrenewed_lease(self, vault: Path) -> datetime:
        """Sleep until the lease observed now would have expired without renewal."""
        import time

        from arvyx_control.checkpoint_jobs import index_rebuild_status

        observed = datetime.fromisoformat(
            index_rebuild_status(vault).lease_expires_at.replace("Z", "+00:00")
        )
        remaining = (observed - datetime.now(timezone.utc)).total_seconds()
        time.sleep(max(0.0, remaining) + 0.5)
        self.assertGreater(datetime.now(timezone.utc), observed)
        return observed

    def test_slow_file_processing_keeps_lease_live_against_second_worker(self) -> None:
        """A long _index_file must not let the lease lapse and be stolen."""
        import threading

        from arvyx_control.checkpoint_jobs import index_rebuild_status, rebuild_index_checkpointed
        from arvyx_control.index import _index_file as real_index_file

        lease_seconds = self.REAL_CLOCK_LEASE_SECONDS
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            started = threading.Event()
            release = threading.Event()

            def slow_index_file(vault_path: Path, relative: str, mtime_ns: int, *, text: str | None = None):
                started.set()
                release.wait(timeout=20)
                return real_index_file(vault_path, relative, mtime_ns, text=text)

            errors: list[BaseException] = []
            results: list["CheckpointJobStatus"] = []

            from arvyx_control.checkpoint_jobs import CheckpointJobStatus  # noqa: F401

            def slow_worker() -> None:
                try:
                    with authority_context(vault):
                        results.append(
                            rebuild_index_checkpointed(
                                vault, owner="worker-slow", lease_seconds=lease_seconds,
                            )
                        )
                except BaseException as exc:  # pragma: no cover - failure path
                    errors.append(exc)

            def stealing_worker() -> None:
                try:
                    with authority_context(vault):
                        results.append(
                            rebuild_index_checkpointed(
                                vault, owner="worker-steal", lease_seconds=lease_seconds,
                            )
                        )
                except BaseException as exc:
                    errors.append(exc)

            with patch("arvyx_control.checkpoint_jobs._index_file", side_effect=slow_index_file):
                first = threading.Thread(target=slow_worker)
                first.start()
                self.assertTrue(started.wait(timeout=10))
                # Wait past the lease as it stood when the slow file started:
                # without heartbeat renewal it would be expired and stealable.
                unrenewed = self._wait_past_unrenewed_lease(vault)
                renewed = index_rebuild_status(vault)
                self.assertEqual(renewed.owner, "worker-slow")
                self.assertGreater(
                    datetime.fromisoformat(renewed.lease_expires_at.replace("Z", "+00:00")),
                    unrenewed,
                    "the heartbeat did not renew the lease during slow processing",
                )
                second = threading.Thread(target=stealing_worker)
                second.start()
                second.join(timeout=10)
                release.set()
                first.join(timeout=30)

            # The second worker must be rejected by the still-live lease,
            # proving the heartbeat kept it unstealable during slow processing.
            self.assertEqual(len(errors), 1, [str(error) for error in errors])
            self.assertRegex(str(errors[0]), "already running")
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].status, "completed")
            final = index_rebuild_status(vault)
            self.assertEqual(final.status, "completed")

    def test_heartbeat_renews_after_bounded_sqlite_busy_contention(self) -> None:
        import sqlite3
        import threading
        import time

        from arvyx_control.checkpoint_jobs import (
            _journal_path, index_rebuild_status, rebuild_index_checkpointed,
        )
        from arvyx_control.index import _index_file as real_index_file

        lease_seconds = self.REAL_CLOCK_LEASE_SECONDS
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            started = threading.Event()
            release_file = threading.Event()
            errors: list[BaseException] = []

            def slow_index_file(vault_path: Path, relative: str, mtime_ns: int, *, text: str | None = None):
                started.set()
                release_file.wait(timeout=20)
                return real_index_file(vault_path, relative, mtime_ns, text=text)

            def worker() -> None:
                try:
                    with authority_context(vault):
                        rebuild_index_checkpointed(vault, owner="busy-worker", lease_seconds=lease_seconds)
                except BaseException as exc:
                    errors.append(exc)

            with patch("arvyx_control.checkpoint_jobs._index_file", side_effect=slow_index_file):
                thread = threading.Thread(target=worker)
                thread.start()
                self.assertTrue(started.wait(timeout=10))
                unrenewed = datetime.fromisoformat(
                    index_rebuild_status(vault).lease_expires_at.replace("Z", "+00:00")
                )
                # Hold the write lock for longer than one renewal interval
                # (lease/3), so at least one renewal must wait on SQLITE_BUSY.
                blocker = sqlite3.connect(_journal_path(vault), isolation_level=None)
                blocker.execute("BEGIN IMMEDIATE")
                try:
                    time.sleep(lease_seconds / 3 + 0.2)
                finally:
                    blocker.execute("ROLLBACK")
                    blocker.close()
                # Then wait past the lease observed before the contention.
                remaining = (unrenewed - datetime.now(timezone.utc)).total_seconds()
                time.sleep(max(0.0, remaining) + 0.5)
                self.assertGreater(
                    datetime.fromisoformat(
                        index_rebuild_status(vault).lease_expires_at.replace("Z", "+00:00")
                    ),
                    unrenewed,
                    "the heartbeat did not renew the lease after SQLite busy contention",
                )
                with self.assertRaisesRegex(RuntimeError, "already running"):
                    with authority_context(vault):
                        rebuild_index_checkpointed(
                            vault, owner="would-be-thief", lease_seconds=lease_seconds,
                        )
                release_file.set()
                thread.join(timeout=30)

            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])

    def test_heartbeat_thread_is_cleaned_up_after_worker_failure(self) -> None:
        import threading

        from arvyx_control.checkpoint_jobs import _renew_heartbeat, rebuild_index_checkpointed

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            with patch(
                "arvyx_control.checkpoint_jobs._index_file",
                side_effect=RuntimeError("injected indexing failure"),
            ):
                with self.assertRaisesRegex(RuntimeError, "injected indexing failure"):
                    with authority_context(vault):
                        rebuild_index_checkpointed(vault, owner="cleanup-worker", lease_seconds=1)

            heartbeat_threads = [
                thread for thread in threading.enumerate()
                if getattr(thread, "_target", None) is _renew_heartbeat
            ]
            self.assertEqual(heartbeat_threads, [])

    def test_cli_default_owner_is_process_unique(self) -> None:
        import os
        import socket

        from arvyx_control.checkpoint_jobs import CheckpointJobStatus
        from arvyx_control.cli import main

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            with patch(
                "arvyx_control.cli.rebuild_index_checkpointed",
                return_value=CheckpointJobStatus("completed", 1, 0, 0, "", ""),
            ) as rebuild:
                with redirect_stdout(StringIO()):
                    code = main(["index", "rebuild", "--vault", str(vault), "--json"])
            self.assertEqual(code, 0)
            owner = rebuild.call_args.kwargs["owner"]
            self.assertEqual(owner, f"arvyx-index-worker@{socket.gethostname()}:{os.getpid()}")

    def test_write_cache_failure_after_checkpoints_resumes_without_reprocessing(self) -> None:
        from arvyx_control.checkpoint_jobs import index_rebuild_status, rebuild_index_checkpointed
        from arvyx_control.index import INDEX_RELATIVE, _index_file as real_index_file

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            now = datetime(2026, 1, 1, tzinfo=timezone.utc)
            visited: list[str] = []

            def recording_index_file(vault_path: Path, relative: str, mtime_ns: int, *, text: str | None = None):
                visited.append(relative)
                return real_index_file(vault_path, relative, mtime_ns, text=text)

            with patch("arvyx_control.checkpoint_jobs._index_file", side_effect=recording_index_file):
                with patch(
                    "arvyx_control.checkpoint_jobs._write_cache",
                    side_effect=RuntimeError("injected cache failure"),
                ):
                    with self.assertRaisesRegex(RuntimeError, "injected cache failure"):
                        with authority_context(vault):
                            rebuild_index_checkpointed(vault, owner="worker-a", now=now, lease_seconds=30)
                crashed = index_rebuild_status(vault)
                self.assertEqual(crashed.status, "running")
                self.assertEqual(crashed.checkpoint, crashed.total)
                self.assertFalse((vault / INDEX_RELATIVE).exists())

                with authority_context(vault):
                    resumed = rebuild_index_checkpointed(
                        vault, owner="worker-a", now=now + timedelta(seconds=31), lease_seconds=30,
                    )

            self.assertEqual(resumed.status, "completed")
            self.assertEqual(resumed.attempt, 2)
            # All checkpoints survived: the resume republished the cache
            # without re-tokenizing any file.
            self.assertEqual(visited, visited[: crashed.total])
            self.assertTrue((vault / INDEX_RELATIVE).exists())

    def test_max_attempts_resets_when_manifest_changes(self) -> None:
        from arvyx_control.checkpoint_jobs import index_rebuild_status, rebuild_index_checkpointed

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            now = datetime(2026, 1, 1, tzinfo=timezone.utc)
            target = vault / "projects" / "drift.md"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("# drift v1\n", encoding="utf-8")

            def crash(relative: str, completed: int) -> None:
                raise RuntimeError("injected crash")

            # Exhaust the budget for the first manifest.
            with self.assertRaises(RuntimeError):
                with authority_context(vault):
                    rebuild_index_checkpointed(
                        vault, owner="worker-a", now=now, lease_seconds=30,
                        max_attempts=1, after_checkpoint=crash,
                    )
            with self.assertRaisesRegex(RuntimeError, "attempt budget exhausted"):
                with authority_context(vault):
                    rebuild_index_checkpointed(
                        vault, owner="worker-b", now=now + timedelta(seconds=31),
                        lease_seconds=30, max_attempts=1,
                    )
            self.assertEqual(index_rebuild_status(vault).status, "failed")

            # A manifest change starts a fresh budget at attempt 1.
            target.write_text("# drift v2\n", encoding="utf-8")
            with authority_context(vault):
                resumed = rebuild_index_checkpointed(
                    vault, owner="worker-c", now=now + timedelta(seconds=62),
                    lease_seconds=30, max_attempts=1,
                )
            self.assertEqual(resumed.status, "completed")
            self.assertEqual(resumed.attempt, 1)

    def test_drift_marks_attempt_failed_but_checkpoints_resume(self) -> None:
        from arvyx_control.checkpoint_jobs import index_rebuild_status, rebuild_index_checkpointed
        from arvyx_control.index import _index_file as real_index_file

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            now = datetime(2026, 1, 1, tzinfo=timezone.utc)
            visited: list[str] = []
            stats = None
            from arvyx_control.index import _current_file_stats

            stats = _current_file_stats(vault.resolve())
            first_file = sorted(stats)[0]
            last_file = sorted(stats)[-1]
            self.assertNotEqual(first_file, last_file)

            def recording_index_file(vault_path: Path, relative: str, mtime_ns: int, *, text: str | None = None):
                visited.append(relative)
                return real_index_file(vault_path, relative, mtime_ns, text=text)

            def mutate_first_on_last(relative: str, completed: int) -> None:
                if relative == last_file:
                    (vault / first_file).write_text(
                        (vault / first_file).read_text(encoding="utf-8") + "\nmutated\n",
                        encoding="utf-8",
                    )

            with patch("arvyx_control.checkpoint_jobs._index_file", side_effect=recording_index_file):
                with self.assertRaisesRegex(RuntimeError, "indexed sources changed during rebuild"):
                    with authority_context(vault):
                        rebuild_index_checkpointed(
                            vault, owner="worker-a", now=now, lease_seconds=30,
                            after_checkpoint=mutate_first_on_last,
                        )
                drifted = index_rebuild_status(vault)
                self.assertEqual(drifted.status, "failed")
                # Checkpoints for every processed file survived the drift.
                self.assertEqual(drifted.checkpoint, drifted.total)
                before = list(visited)

                with authority_context(vault):
                    resumed = rebuild_index_checkpointed(
                        vault, owner="worker-b", now=now + timedelta(seconds=31), lease_seconds=30,
                    )

            self.assertEqual(resumed.status, "completed")
            self.assertEqual(resumed.attempt, 1)  # new manifest resets the budget
            # Only the mutated file was reprocessed on resume.
            self.assertEqual(visited[len(before):], [first_file])

    def test_two_threads_concurrent_rebuild_is_safe(self) -> None:
        import threading

        from arvyx_control.checkpoint_jobs import index_rebuild_status, rebuild_index_checkpointed
        from arvyx_control.index import INDEX_RELATIVE, _read_cache

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            barrier = threading.Barrier(2, timeout=10)
            outcomes: list[tuple[str, object]] = []
            lock = threading.Lock()

            def worker(name: str) -> None:
                barrier.wait()
                try:
                    with authority_context(vault):
                        result = rebuild_index_checkpointed(vault, owner=name, lease_seconds=30)
                    with lock:
                        outcomes.append(("completed", result))
                except RuntimeError as exc:
                    with lock:
                        outcomes.append(("error", str(exc)))

            threads = [threading.Thread(target=worker, args=(f"worker-{i}",)) for i in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=60)

            self.assertEqual(len(outcomes), 2)
            kinds = sorted(kind for kind, _ in outcomes)
            # Either one wins and one is blocked by the live lease, or (when
            # the first finished before the second claimed) both complete
            # idempotently. Never an unexpected error.
            for kind, payload in outcomes:
                if kind == "error":
                    self.assertIn("already running", str(payload))
            self.assertIn("completed", kinds)
            final = index_rebuild_status(vault)
            self.assertEqual(final.status, "completed")
            self.assertEqual(final.checkpoint, final.total)
            self.assertTrue((vault / INDEX_RELATIVE).exists())
            self.assertTrue(_read_cache(vault.resolve()))

    def test_job_state_transitions_are_audit_logged(self) -> None:
        from arvyx_control.checkpoint_jobs import _audit_path, rebuild_index_checkpointed
        from arvyx_control.audit_log import verify_chain

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            with authority_context(vault):
                rebuild_index_checkpointed(vault, owner="audit-worker", lease_seconds=30)
            audit_path = _audit_path(vault)
            self.assertTrue(audit_path.exists())
            events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            names = [event["event"] for event in events]
            self.assertEqual(names, ["index_rebuild_started", "index_rebuild_completed"])
            self.assertTrue(all(event["job"] == "index-rebuild" for event in events))
            self.assertTrue(verify_chain(audit_path).ok)

    def test_rebuild_source_byte_reads_scale_linearly(self) -> None:
        from collections import Counter

        from arvyx_control.checkpoint_jobs import rebuild_index_checkpointed
        from arvyx_control.index import _current_file_stats

        # Count source reads, not wall-clock time; retain every publication scan.
        for added_files in (4, 12):
            with self.subTest(added_files=added_files), tempfile.TemporaryDirectory() as tmp:
                vault = Path(tmp) / "vault"
                init_vault(vault)
                for number in range(added_files):
                    (vault / "projects" / f"linear-{number}.md").write_text(
                        f"# Source {number}\n", encoding="utf-8",
                    )
                sources = {vault.resolve() / relative for relative in _current_file_stats(vault)}
                reads = Counter()
                # Indexed sources are read through the descriptor-relative,
                # no-follow external_workspace._read (index._source_snapshot), not
                # Path.read_bytes. Count reads at that real production boundary.
                from arvyx_control import external_workspace
                real_read = external_workspace._read

                def recording_read(root, parts, limit, *args, **kwargs):
                    path = Path(root).joinpath(*parts)
                    if path in sources:
                        reads[path] += 1
                    return real_read(root, parts, limit, *args, **kwargs)

                with patch.object(external_workspace, "_read", recording_read):
                    with authority_context(vault):
                        result = rebuild_index_checkpointed(
                            vault, owner="linear-worker",
                            now=datetime(2026, 1, 1, tzinfo=timezone.utc), lease_seconds=30,
                        )
                self.assertEqual(result.status, "completed")
                # Bound reads per source independently of vault size. Include
                # checkpoint and artifact byte validation, without freezing an
                # obsolete exact count or weakening generation checks.
                self.assertEqual(set(reads), sources)
                self.assertTrue(all(1 <= count <= 10 for count in reads.values()), dict(reads))
                self.assertLessEqual(sum(reads.values()), 10 * len(sources))

    def test_single_file_stats_share_scanner_eligibility_and_metadata(self) -> None:
        from arvyx_control.index import _current_file_stat, _current_file_stats

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            projects = vault / "projects"
            projects.mkdir(parents=True)
            (projects / "current.md").write_text("# Current\n", encoding="utf-8")
            (projects / "old.md").write_text(
                "---\nstatus: superseded\n---\n# Old\n", encoding="utf-8",
            )
            (projects / "SESSION-STATE.md").write_text("session\n", encoding="utf-8")
            (projects / "archive").mkdir()
            (projects / "archive" / "hidden.md").write_text("hidden\n", encoding="utf-8")
            (projects / "link.md").symlink_to(projects / "current.md")
            outside = Path(tmp) / "outside"
            outside.mkdir()
            (outside / "escaped.md").write_text("outside\n", encoding="utf-8")
            (projects / "escape").symlink_to(outside, target_is_directory=True)
            current = _current_file_stat(vault, "projects/current.md")
            self.assertIsNotNone(current)
            self.assertEqual(_current_file_stats(vault), {"projects/current.md": current})
            stat = (projects / "current.md").stat()
            self.assertEqual(current[:2], (stat.st_mtime_ns, stat.st_size))
            for relative in (
                "projects/old.md", "projects/SESSION-STATE.md",
                "projects/archive/hidden.md", "projects/link.md",
                "projects/escape/escaped.md", "projects/missing.md",
                "../outside/escaped.md", "other/current.md",
            ):
                with self.subTest(relative=relative):
                    self.assertIsNone(_current_file_stat(vault, relative))

    def test_index_root_and_resolved_lane_are_checked_before_reads(self) -> None:
        from arvyx_control.index import _current_file_stat, _current_file_stats, _resolve_indexed_path

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            raw = vault / "projects" / "p" / "raw"
            raw.mkdir(parents=True)
            (raw / "private.md").write_text("excluded\n", encoding="utf-8")
            (vault / "agents").symlink_to(raw, target_is_directory=True)
            (vault / "projects" / "alias").symlink_to(raw, target_is_directory=True)
            with patch.object(Path, "read_bytes", side_effect=AssertionError("contents read")):
                self.assertEqual(_current_file_stats(vault), {})
                for relative in ("agents/private.md", "projects/alias/private.md"):
                    self.assertIsNone(_current_file_stat(vault, relative))
                    with self.assertRaises(ValueError):
                        _resolve_indexed_path(vault, relative)

    def test_touch_refreshes_cache_and_completed_checkpoint_recency(self) -> None:
        import os
        from arvyx_control.index import load_index, _parse_timestamp
        from arvyx_control.checkpoint_jobs import rebuild_index_checkpointed

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            projects = vault / "projects"
            projects.mkdir(parents=True)
            plain = projects / "plain.md"
            dated = projects / "dated.md"
            plain.write_text("# Plain\n", encoding="utf-8")
            dated.write_text("---\ndate: 2025-01-01\n---\n# Dated\n", encoding="utf-8")
            for path in (plain, dated):
                os.utime(path, ns=(1_000_000_000, 1_000_000_000))
            load_index(vault)
            for path in (plain, dated):
                os.utime(path, ns=(2_000_000_000, 2_000_000_000))
            chunks = {chunk.relative_path: chunk for chunk in load_index(vault)}
            self.assertEqual(chunks["projects/plain.md"].timestamp, 2.0)
            self.assertEqual(chunks["projects/dated.md"].timestamp, _parse_timestamp("2025-01-01"))
            moment = datetime(2026, 1, 1, tzinfo=timezone.utc)
            with authority_context(vault):
                rebuild_index_checkpointed(vault, owner="touch-worker", now=moment)
            os.utime(plain, ns=(3_000_000_000, 3_000_000_000))
            from arvyx_control import checkpoint_jobs
            real_index_file = checkpoint_jobs._index_file
            with patch.object(checkpoint_jobs, "_index_file", wraps=real_index_file) as index_file:
                with authority_context(vault):
                    rebuild_index_checkpointed(vault, owner="touch-worker", now=moment)
            self.assertEqual([call.args[1] for call in index_file.call_args_list], ["projects/plain.md"])
            chunks = {chunk.relative_path: chunk for chunk in load_index(vault)}
            self.assertEqual(chunks["projects/plain.md"].timestamp, 3.0)

    def test_content_hash_is_sha256_of_file_bytes(self) -> None:
        import hashlib

        from arvyx_control.index import _current_file_stats

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            vault.mkdir()
            target = vault / "projects" / "hash-check.md"
            target.parent.mkdir(parents=True)
            payload = "# hash check\n\nexact bytes matter\n".encode("utf-8")
            target.write_bytes(payload)
            stats = _current_file_stats(vault)
            self.assertEqual(
                stats["projects/hash-check.md"][2], hashlib.sha256(payload).hexdigest()
            )


if __name__ == "__main__":
    unittest.main()
