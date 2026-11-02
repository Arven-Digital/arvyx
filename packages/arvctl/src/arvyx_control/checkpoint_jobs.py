from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import threading
from uuid import uuid4

from .audit_log import append_audit
from .filesystem import fsync_directory


class SourceDriftError(RuntimeError):
    """An observed source generation changed; release this worker's lease."""

from .index import INDEX_FORMAT, INDEX_RELATIVE, _current_file_stat, _current_file_stats, _source_snapshot, _index_file, _publication_lock, _read_cache, _valid_cached_entry, _write_cache


_JOB_NAME = "index-rebuild"
_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    name TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK(status IN ('running', 'completed', 'failed')),
    attempt INTEGER NOT NULL,
    manifest_hash TEXT NOT NULL,
    owner TEXT NOT NULL,
    generation TEXT NOT NULL DEFAULT '',
    lease_expires_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS checkpoints (
    job_name TEXT NOT NULL,
    relative_path TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    entry_json TEXT NOT NULL,
    PRIMARY KEY(job_name, relative_path)
);
"""


@dataclass(frozen=True)
class CheckpointJobStatus:
    status: str
    attempt: int
    checkpoint: int
    total: int
    owner: str
    lease_expires_at: str


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("job time must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _journal_path(vault: Path) -> Path:
    return vault.resolve() / ".arvyx" / "jobs.sqlite3"


def _audit_path(vault: Path) -> Path:
    return vault.resolve() / ".arvyx" / "jobs-audit.jsonl"


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=30)
    # Manual transaction control: every write path issues its own
    # BEGIN IMMEDIATE / COMMIT so lease renewals and checkpoints are atomic.
    connection.isolation_level = None
    connection.execute("PRAGMA synchronous=FULL")
    connection.executescript(_SCHEMA)
    connection.execute("BEGIN IMMEDIATE")
    try:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(jobs)")}
        if "generation" not in columns:
            connection.execute("ALTER TABLE jobs ADD COLUMN generation TEXT NOT NULL DEFAULT ''")
        connection.execute("COMMIT")
    except BaseException:
        connection.execute("ROLLBACK")
        connection.close()
        raise
    return connection


def _manifest_hash(stats: dict[str, tuple[int, int, str]]) -> str:
    snapshot = [(relative, *values) for relative, values in sorted(stats.items())]
    return hashlib.sha256(json.dumps(snapshot, separators=(",", ":")).encode()).hexdigest()


def _valid_source_entry(root: Path, relative: str, entry: object,
                        mtime_ns: int, size: int, digest: str) -> bool:
    """Bind checkpoint and artifact validation to the same source generation."""
    snapshot = _source_snapshot(root, relative)
    return (snapshot is not None
            and snapshot[0] == (mtime_ns, size, digest)
            and _valid_cached_entry(relative, entry, digest, mtime_ns, size,
                                    text=snapshot[1]))


def _cache_matches_manifest(root: Path, stats: dict[str, tuple[int, int, str]]) -> bool:
    """Require an actual, current-format artifact, even for an empty vault."""
    try:
        payload = json.loads((root / INDEX_RELATIVE).read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError, RecursionError):
        return False
    if not isinstance(payload, dict) or payload.get("format") != INDEX_FORMAT:
        return False
    files = payload.get("files")
    if not isinstance(files, dict) or set(files) != set(stats):
        return False
    return all(
        _valid_source_entry(root, relative, files[relative], mtime_ns, size, digest)
        for relative, (mtime_ns, size, digest) in stats.items()
    )


def _audit_event(path: Path, event: str, **fields: object) -> None:
    """Append an audit event; report audit loss without breaking the rebuild."""
    try:
        append_audit(path, {"event": event, "job": _JOB_NAME, **fields})
    except OSError:
        print(
            f"warning: index rebuild audit event was not recorded: {event}",
            file=sys.stderr,
        )


def index_rebuild_status(vault: Path) -> CheckpointJobStatus:
    stats = _current_file_stats(vault.resolve())
    path = _journal_path(vault)
    if not path.exists():
        return CheckpointJobStatus("completed", 0, 0, len(stats), "", "")
    connection = _connect(path)
    try:
        row = connection.execute(
            "SELECT status, attempt, owner, lease_expires_at FROM jobs WHERE name=?", (_JOB_NAME,)
        ).fetchone()
        checkpoint = connection.execute(
            "SELECT COUNT(*) FROM checkpoints WHERE job_name=?", (_JOB_NAME,)
        ).fetchone()[0]
    finally:
        connection.close()
    if row is None:
        return CheckpointJobStatus("completed", 0, 0, len(stats), "", "")
    return CheckpointJobStatus(str(row[0]), int(row[1]), int(checkpoint), len(stats), str(row[2]), str(row[3]))


def rebuild_index_checkpointed(
    vault: Path,
    *,
    owner: str,
    now: datetime | None = None,
    lease_seconds: int = 60,
    max_attempts: int = 3,
    after_checkpoint: Callable[[str, int], None] | None = None,
) -> CheckpointJobStatus:
    """Rebuild the lexical index with per-file durable checkpoints.

    This is a resumable worker primitive, not a scheduler. A live lease prevents
    overlap; only an expired lease may start another bounded attempt.

    Lease safety: the lease is renewed inside the same SQLite transaction that
    claims each file, and — on real-clock runs (``now`` is None) — a background
    heartbeat renews it every ``lease_seconds / 3`` while a single file is being
    processed, so a slow ``_index_file`` call cannot let the lease lapse and be
    stolen. When a deterministic ``now`` is injected (tests), the heartbeat is
    disabled and ``lease_seconds`` must exceed the longest single-file
    processing time for the injected timeline to be meaningful.

    Drift semantics: a source change during the rebuild fails the attempt, but
    durable checkpoints always survive. The next attempt reprocesses only
    changed or new files and reuses checkpoints whose content hash, mtime and
    size still match; rows for files that no longer exist are pruned. If the manifest
    changed, ``max_attempts`` restarts at attempt 1 for the new manifest.

    Job state transitions (start/complete/fail) are appended to a hash-chained
    audit log at ``.arvyx/jobs-audit.jsonl`` via the existing ``audit_log``
    module; audit write failures are reported to stderr without failing a rebuild.
    """
    if not owner or len(owner) > 128:
        raise ValueError("job owner must be 1-128 characters")
    if lease_seconds < 1 or lease_seconds > 3600:
        raise ValueError("lease seconds must be 1-3600")
    if max_attempts < 1 or max_attempts > 100:
        raise ValueError("max attempts must be 1-100")
    root = vault.resolve()
    path = _journal_path(root)
    audit = _audit_path(root)

    def _now() -> datetime:
        return now if now is not None else datetime.now(timezone.utc)

    stats = _current_file_stats(root)
    manifest_hash = _manifest_hash(stats)

    # One connection for the whole run: no reconnect/DDL overhead per file.
    connection = _connect(path)
    try:
        generation = uuid4().hex
        # Completed-artifact acceptance participates in the publication protocol
        # too. Never acquire this flock while already holding a jobs transaction.
        with _publication_lock(root):
            attempt = _start_attempt(
                connection,
                root=root,
                owner=owner,
                generation=generation,
                current=now,
                lease_seconds=lease_seconds,
                max_attempts=max_attempts,
                manifest_hash=manifest_hash,
                stats=stats,
                audit=audit,
            )
        if attempt is None:
            return index_rebuild_status(root)

        stop_heartbeat = threading.Event()
        lease_lost = threading.Event()
        heartbeat: threading.Thread | None = None
        if now is None:
            heartbeat = threading.Thread(
                target=_renew_heartbeat,
                args=(path, owner, attempt, generation, lease_seconds, stop_heartbeat, lease_lost),
                daemon=True,
            )
            heartbeat.start()
        try:
            try:
                _process_files(
                    connection,
                    root=root,
                    stats=stats,
                    owner=owner,
                    attempt=attempt,
                    generation=generation,
                    lease_seconds=lease_seconds,
                    now=now,
                    lease_lost=lease_lost,
                    after_checkpoint=after_checkpoint,
                )

                final_stats = _current_file_stats(root)
                if _manifest_hash(final_stats) != manifest_hash:
                    # Drift after the last checkpoint: mark the attempt failed
                    # but preserve every durable checkpoint; the next attempt
                    # (new manifest, budget reset) resumes the remaining files.
                    raise SourceDriftError("indexed sources changed during rebuild")

            except BaseException as exc:
                # Single-file drift must release the generation too, not only
                # drift observed by the final full scan. Keep checkpoints.
                if isinstance(exc, SourceDriftError):
                    _mark_failed(
                        connection, owner=owner, attempt=attempt, generation=generation,
                        reason=str(exc), current=now,
                    )
                _audit_event(
                    audit, "index_rebuild_failed", owner=owner, attempt=attempt,
                    manifest_hash=manifest_hash, reason=str(exc),
                )
                raise

            with _publication_lock(root):
                # Lock order is cache publication flock, then SQLite. Keep both
                # through readback and completion; no provider I/O runs here.
                # Source hashes are checked both before and after the atomic cache
                # replace, so a mutation in the publication window cannot leave a
                # stale cache advertised by a completed job.
                connection.execute("BEGIN IMMEDIATE")
                transaction_open = True
                try:
                    row = connection.execute(
                        "SELECT owner, attempt, status, lease_expires_at, generation FROM jobs WHERE name=?", (_JOB_NAME,)
                    ).fetchone()
                    complete_now = _now()
                    if (
                        row is None
                        or str(row[0]) != owner
                        or int(row[1]) != attempt
                        or str(row[4]) != generation
                        or str(row[2]) != "running"
                        or _parse_timestamp(str(row[3])) <= complete_now
                    ):
                        connection.execute("ROLLBACK")
                        transaction_open = False
                        raise RuntimeError("index rebuild lease was lost before completion")
                    publish_stats = _current_file_stats(root)
                    if _manifest_hash(publish_stats) != manifest_hash:
                        connection.execute(
                            "UPDATE jobs SET status='failed', lease_expires_at=?, updated_at=? WHERE name=?",
                            (_timestamp(complete_now), _timestamp(complete_now), _JOB_NAME),
                        )
                        connection.execute("COMMIT")
                        transaction_open = False
                        raise RuntimeError("indexed sources changed during cache publication")
                    rows = connection.execute(
                        "SELECT relative_path, content_hash, entry_json FROM checkpoints WHERE job_name=?",
                        (_JOB_NAME,),
                    ).fetchall()
                    files = {}
                    for relative, content_hash, entry_json in rows:
                        relative = str(relative)
                        if relative not in publish_stats:
                            continue
                        mtime_ns, size, digest = publish_stats[relative]
                        try:
                            entry = json.loads(str(entry_json))
                        except (ValueError, UnicodeError, RecursionError):
                            entry = None
                        if str(content_hash) != digest or not _valid_source_entry(
                            root, relative, entry, mtime_ns, size, digest
                        ):
                            raise RuntimeError(f"stale checkpoint during publication: {relative}")
                        files[relative] = entry
                    if set(files) != set(publish_stats):
                        raise RuntimeError("index rebuild checkpoints are incomplete")
                    try:
                        _write_cache(root, files)
                    except OSError:
                        # Persist failure while this generation still owns the
                        # publication transaction. Replacement may already have
                        # made readable bytes visible without a durable barrier.
                        failed_now = _now()
                        connection.execute(
                            "UPDATE jobs SET status='failed', lease_expires_at=?, updated_at=? "
                            "WHERE name=? AND owner=? AND attempt=? AND generation=? AND status='running'",
                            (_timestamp(failed_now), _timestamp(failed_now), _JOB_NAME, owner, attempt, generation),
                        )
                        connection.execute("COMMIT")
                        transaction_open = False
                        raise
                    # The tolerant reader returns {} for invalid/missing artifacts;
                    # equality alone cannot prove publication of an empty index.
                    if not _cache_matches_manifest(root, publish_stats) or _read_cache(root) != files:
                        connection.execute(
                            "UPDATE jobs SET status='failed', lease_expires_at=?, updated_at=? WHERE name=?",
                            (_timestamp(complete_now), _timestamp(complete_now), _JOB_NAME),
                        )
                        connection.execute("COMMIT")
                        transaction_open = False
                        raise RuntimeError("index cache could not be persisted")
                    if _manifest_hash(_current_file_stats(root)) != manifest_hash:
                        (root / INDEX_RELATIVE).unlink(missing_ok=True)
                        connection.execute(
                            "UPDATE jobs SET status='failed', lease_expires_at=?, updated_at=? WHERE name=?",
                            (_timestamp(complete_now), _timestamp(complete_now), _JOB_NAME),
                        )
                        connection.execute("COMMIT")
                        transaction_open = False
                        raise RuntimeError("indexed sources changed during cache publication")
                    connection.execute(
                        "UPDATE jobs SET status='completed', lease_expires_at=?, updated_at=? WHERE name=?",
                        (_timestamp(complete_now), _timestamp(complete_now), _JOB_NAME),
                    )
                    connection.execute("COMMIT")
                    transaction_open = False
                except BaseException:
                    if transaction_open:
                        try:
                            connection.execute("ROLLBACK")
                        except sqlite3.Error:
                            pass
                    _audit_event(
                        audit, "index_rebuild_failed", owner=owner, attempt=attempt,
                        manifest_hash=manifest_hash, reason="cache publication or completion failed",
                    )
                    raise
            _audit_event(
                audit, "index_rebuild_completed", owner=owner, attempt=attempt,
                manifest_hash=manifest_hash, files=len(files),
            )
            return index_rebuild_status(root)
        finally:
            stop_heartbeat.set()
            if heartbeat is not None:
                heartbeat.join()
    finally:
        connection.close()


def _start_attempt(
    connection: sqlite3.Connection,
    *,
    root: Path,
    owner: str,
    generation: str,
    current: datetime | None,
    lease_seconds: int,
    max_attempts: int,
    manifest_hash: str,
    stats: dict[str, tuple[int, int, str]],
    audit: Path,
) -> int | None:
    """Claim the job inside one transaction. Returns the attempt number.

    Returns None only when the job is completed with this manifest and its
    actual cache artifact is valid. Otherwise a completed job starts a fresh
    publication cycle using its durable checkpoints. Raises RuntimeError when
    a live lease blocks the start or the attempt budget is exhausted.
    """
    connection.execute("BEGIN IMMEDIATE")
    try:
        row = connection.execute(
            "SELECT status, attempt, manifest_hash, lease_expires_at FROM jobs WHERE name=?", (_JOB_NAME,)
        ).fetchone()
        current = current if current is not None else datetime.now(timezone.utc)
        current_text = _timestamp(current)
        lease_text = _timestamp(current + timedelta(seconds=lease_seconds))
        if row is not None and _parse_timestamp(str(row[3])) > current:
            raise RuntimeError("index rebuild is already running with a live lease")
        if row is None or str(row[2]) != manifest_hash:
            # New job or changed manifest: the attempt budget resets to 1 and
            # durable checkpoints survive. Rows whose content hash still
            # matches are reused by the processing loop; rows for files that
            # no longer exist are pruned here.
            if row is not None:
                stale = [
                    str(relative)
                    for (relative,) in connection.execute(
                        "SELECT relative_path FROM checkpoints WHERE job_name=?", (_JOB_NAME,)
                    ).fetchall()
                    if str(relative) not in stats
                ]
                connection.executemany(
                    "DELETE FROM checkpoints WHERE job_name=? AND relative_path=?",
                    [(_JOB_NAME, relative) for relative in stale],
                )
            connection.execute(
                "INSERT OR REPLACE INTO jobs(name,status,attempt,manifest_hash,owner,lease_expires_at,updated_at,generation) "
                "VALUES(?, 'running', 1, ?, ?, ?, ?, ?)",
                (_JOB_NAME, manifest_hash, owner, lease_text, current_text, generation),
            )
            attempt = 1
        elif str(row[0]) == "completed":
            if _manifest_hash(_current_file_stats(root)) != manifest_hash:
                raise SourceDriftError("indexed sources changed before completed artifact acceptance")
            if _cache_matches_manifest(root, stats):
                # A visible artifact may follow a failed replacement barrier.
                # Completed replay must re-establish that barrier under the
                # publication lock before acknowledging its old completion.
                fsync_directory((root / INDEX_RELATIVE).parent)
                if _manifest_hash(_current_file_stats(root)) != manifest_hash:
                    raise SourceDriftError("indexed sources changed during completed artifact acceptance")
                connection.execute("COMMIT")
                return None
            # Artifact repair is a new bounded publication cycle, not another
            # failed attempt of the completed cycle. Keep validated checkpoints
            # and acquire a fresh generation before using the normal worker and
            # manifest-fenced publication path.
            attempt = 1
            connection.execute(
                "UPDATE jobs SET status='running', attempt=?, owner=?, lease_expires_at=?, updated_at=?, generation=? WHERE name=?",
                (attempt, owner, lease_text, current_text, generation, _JOB_NAME),
            )
        else:
            attempt = int(row[1]) + 1
            if attempt > max_attempts:
                connection.execute(
                    "UPDATE jobs SET status='failed', owner=?, lease_expires_at=?, updated_at=? WHERE name=?",
                    (owner, current_text, current_text, _JOB_NAME),
                )
                connection.execute("COMMIT")
                _audit_event(
                    audit, "index_rebuild_failed", owner=owner, attempt=attempt,
                    manifest_hash=manifest_hash, reason="attempt budget exhausted",
                )
                raise RuntimeError("index rebuild attempt budget exhausted")
            connection.execute(
                "UPDATE jobs SET status='running', attempt=?, owner=?, lease_expires_at=?, updated_at=?, generation=? WHERE name=?",
                (attempt, owner, lease_text, current_text, generation, _JOB_NAME),
            )
        connection.execute("COMMIT")
    except BaseException:
        try:
            connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    _audit_event(
        audit, "index_rebuild_started", owner=owner, attempt=attempt, manifest_hash=manifest_hash,
    )
    return attempt


def _mark_failed(
    connection: sqlite3.Connection, *, owner: str, attempt: int, generation: str, reason: str,
    current: datetime | None,
) -> None:
    """Mark the attempt failed and drop the lease, preserving checkpoints."""
    try:
        connection.execute("BEGIN IMMEDIATE")
        now_text = _timestamp(current if current is not None else datetime.now(timezone.utc))
        connection.execute(
            "UPDATE jobs SET status='failed', lease_expires_at=?, updated_at=? "
            "WHERE name=? AND owner=? AND attempt=? AND generation=? AND status='running'",
            (now_text, now_text, _JOB_NAME, owner, attempt, generation),
        )
        connection.execute("COMMIT")
    except sqlite3.Error:
        try:
            connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass


def _renew_heartbeat(
    path: Path,
    owner: str,
    attempt: int,
    generation: str,
    lease_seconds: int,
    stop: threading.Event,
    lease_lost: threading.Event,
) -> None:
    """Renew the lease every lease_seconds/3 so one slow file cannot lapse it.

    Uses its own connection (SQLite connections are not shareable across
    threads). If a renewal finds the lease lost or already expired, the
    processing loop is signalled through ``lease_lost`` and the heartbeat ends.
    """
    interval = max(0.2, lease_seconds / 3.0)
    connection: sqlite3.Connection | None = None
    try:
        while not stop.wait(interval):
            if connection is None:
                connection = _connect(path)
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT owner, attempt, status, lease_expires_at, generation FROM jobs WHERE name=?", (_JOB_NAME,)
                ).fetchone()
                moment = datetime.now(timezone.utc)
                if (
                    row is None
                    or str(row[0]) != owner
                    or int(row[1]) != attempt
                    or str(row[4]) != generation
                    or str(row[2]) != "running"
                    or _parse_timestamp(str(row[3])) <= moment
                ):
                    connection.execute("ROLLBACK")
                    lease_lost.set()
                    return
                connection.execute(
                    "UPDATE jobs SET lease_expires_at=?, updated_at=? WHERE name=?",
                    (
                        _timestamp(moment + timedelta(seconds=lease_seconds)),
                        _timestamp(moment),
                        _JOB_NAME,
                    ),
                )
                connection.execute("COMMIT")
            except BaseException:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
    except sqlite3.Error:
        lease_lost.set()
    finally:
        if connection is not None:
            connection.close()


def _process_files(
    connection: sqlite3.Connection,
    *,
    root: Path,
    stats: dict[str, tuple[int, int, str]],
    owner: str,
    attempt: int,
    generation: str,
    lease_seconds: int,
    now: datetime | None,
    lease_lost: threading.Event,
    after_checkpoint: Callable[[str, int], None] | None,
) -> int:
    completed = 0
    for relative, (mtime_ns, size, content_hash) in sorted(stats.items()):
        if lease_lost.is_set():
            raise RuntimeError("index rebuild lease was lost")
        # Claim the file and renew the lease in one transaction: ownership and
        # unexpired lease are verified before any potentially slow _index_file
        # work starts, so the lease window always covers the file being read.
        connection.execute("BEGIN IMMEDIATE")
        try:
            lease = connection.execute(
                "SELECT owner, attempt, status, lease_expires_at, generation FROM jobs WHERE name=?", (_JOB_NAME,)
            ).fetchone()
            claim_now = now if now is not None else datetime.now(timezone.utc)
            if (
                lease is None
                or (str(lease[0]), int(lease[1]), str(lease[2]), str(lease[4])) != (owner, attempt, "running", generation)
                or _parse_timestamp(str(lease[3])) <= claim_now
            ):
                connection.execute("ROLLBACK")
                raise RuntimeError("index rebuild lease was lost")
            row = connection.execute(
                "SELECT content_hash, entry_json FROM checkpoints WHERE job_name=? AND relative_path=?",
                (_JOB_NAME, relative),
            ).fetchone()
            try:
                entry = json.loads(str(row[1])) if row is not None else None
            except (ValueError, UnicodeError, RecursionError):
                entry = None
            # The shared entry validator invokes the same complete chunk
            # decoder as recall. Malformed checkpoint fields must recompute,
            # not survive artifact repair merely because their hash matches.
            already = (
                row is not None
                and str(row[0]) == content_hash
                and _valid_source_entry(root, relative, entry, mtime_ns, size, content_hash)
            )
            connection.execute(
                "UPDATE jobs SET lease_expires_at=?, updated_at=? WHERE name=?",
                (
                    _timestamp(claim_now + timedelta(seconds=lease_seconds)),
                    _timestamp(claim_now),
                    _JOB_NAME,
                ),
            )
            connection.execute("COMMIT")
        except BaseException:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        if already:
            completed += 1
            continue

        snapshot = _source_snapshot(root, relative)
        if snapshot is None or snapshot[0] != (mtime_ns, size, content_hash):
            raise SourceDriftError(f"indexed source changed before rebuild: {relative}")
        chunks = [chunk.to_dict() for chunk in _index_file(
            root, relative, mtime_ns, text=snapshot[1])]
        latest = _current_file_stat(root, relative)
        if latest != (mtime_ns, size, content_hash):
            raise SourceDriftError(f"indexed source changed during rebuild: {relative}")
        entry = {"mtime_ns": mtime_ns, "size": size, "content_hash": content_hash, "chunks": chunks}
        connection.execute("BEGIN IMMEDIATE")
        try:
            lease = connection.execute(
                "SELECT owner, attempt, status, lease_expires_at, generation FROM jobs WHERE name=?", (_JOB_NAME,)
            ).fetchone()
            commit_now = now if now is not None else datetime.now(timezone.utc)
            if (
                lease is None
                or (str(lease[0]), int(lease[1]), str(lease[2]), str(lease[4])) != (owner, attempt, "running", generation)
                or _parse_timestamp(str(lease[3])) <= commit_now
            ):
                connection.execute("ROLLBACK")
                raise RuntimeError("index rebuild lease was lost")
            connection.execute(
                "INSERT OR REPLACE INTO checkpoints(job_name,relative_path,content_hash,entry_json) VALUES(?,?,?,?)",
                (_JOB_NAME, relative, content_hash, json.dumps(entry, sort_keys=True)),
            )
            connection.execute(
                "UPDATE jobs SET lease_expires_at=?, updated_at=? WHERE name=?",
                (
                    _timestamp(commit_now + timedelta(seconds=lease_seconds)),
                    _timestamp(commit_now),
                    _JOB_NAME,
                ),
            )
            connection.execute("COMMIT")
        except BaseException:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        completed += 1
        if after_checkpoint is not None:
            after_checkpoint(relative, completed)
    return completed
