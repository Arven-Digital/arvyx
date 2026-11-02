"""Bounded, metadata-only enumeration of file-per-session harness stores.

Claude Code and Codex keep one JSONL file per session beneath their state root.
Listing uses directory names, file names and stat() only: no session file is
opened while enumerating, so transcripts are never read eagerly. An explicit,
reviewed exact selection opens one file and reads a bounded prefix for routing
fields only (session identity, working directory, version); message content,
summaries and instructions never cross this boundary. Nothing here launches,
resumes or attaches a harness.

Every enumeration is budgeted (directory entries, sessions, wall clock). A store
that exceeds its budget is refused as incomplete, never presented as All.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import time

from .agent_sessions import (MAX_METADATA_BYTES, MAX_METADATA_FIELD_BYTES, RoutingError,
                             SessionMetadata, SessionRoute, SessionTarget, metadata_bytes)

PREFIX_BYTES = 256 * 1024
PREFIX_LINES = 64


def inode(path):
    info = path.stat()
    return info.st_dev, info.st_ino


def _reparse(info):
    # Reject POSIX symlinks and Windows junctions/reparse points alike.
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, 'st_file_attributes', 0) & 0x400)


def bounded_text(value):
    """A text routing field within the metadata field budget, or None when absent."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise RoutingError('session routing field has an unexpected type')
    cap = MAX_METADATA_FIELD_BYTES
    if len(value) > cap or len(value.encode('utf-8')) > cap:
        raise RoutingError('selection metadata field byte budget exceeded')
    return value


def prefix_records(prefix, complete, *, max_lines=PREFIX_LINES):
    """JSON object lines fully contained in the prefix; a trailing partial line is dropped."""
    lines = prefix.split(b'\n')
    if not complete or prefix.endswith(b'\n'):
        lines = lines[:-1]
    records = []
    for raw in lines[:max_lines]:
        raw = raw.strip()
        if not raw:
            continue
        try:
            value = json.loads(raw)
        except ValueError:
            continue
        if isinstance(value, dict):
            records.append(value)
    return records


class StoreProfile:
    """Pin the state root and its session container by identity, like HermesProfile."""

    def __init__(self, home, sessions_relative):
        original = Path(home)
        if original.is_symlink():
            raise RoutingError('explicit profile must not be a symlink')
        self.home = original.resolve(strict=True)
        if not self.home.is_dir():
            raise RoutingError('existing state root directory required')
        self.root = self.home / sessions_relative
        if self.root.is_symlink():
            raise RoutingError('session store must not be a symlink')
        self.home_identity = inode(self.home)
        self.identity = inode(self.root) if self.root.is_dir() else None

    def validate(self):
        if (self.home.is_symlink() or self.root.is_symlink() or inode(self.home) != self.home_identity
                or (inode(self.root) if self.root.is_dir() else None) != self.identity):
            raise RoutingError('state root or session store replaced; reconnect explicitly')


class _Budget:
    def __init__(self, *, seconds, entries):
        self.deadline = time.monotonic() + seconds
        self.remaining = entries
        self.probes = 0

    def tick(self):
        self.probes += 1
        self.remaining -= 1
        if self.remaining < 0 or time.monotonic() >= self.deadline:
            raise RoutingError('metadata collection work/time budget exceeded; enumeration incomplete')


class _Walker:
    """Descend from the pinned store root without following links.

    POSIX uses descriptor-relative opens with O_NOFOLLOW and scandir(fd). Windows
    lacks dir_fd/O_NOFOLLOW, so it uses lstat-based checks and rejects reparse
    points, as harness discovery does.
    """
    posix = os.name == 'posix' and hasattr(os, 'O_NOFOLLOW') and os.open in os.supports_dir_fd

    def __init__(self, root, budget):
        self.root, self.budget = root, budget

    @contextmanager
    def open_root(self):
        if self.posix:
            fd = os.open(self.root.anchor, os.O_RDONLY | os.O_DIRECTORY)
            try:
                for part in self.root.parts[1:]:
                    self.budget.tick()
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    os.close(fd)
                    fd = child
                yield fd
            finally:
                os.close(fd)
            return
        path = Path(self.root.anchor)
        for part in self.root.parts[1:]:
            path /= part
            self.budget.tick()
            info = path.lstat()
            if _reparse(info) or not stat.S_ISDIR(info.st_mode):
                raise RoutingError('session store path is not a plain directory')
        yield path

    @contextmanager
    def child_dir(self, parent, name):
        self.budget.tick()
        if self.posix:
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                yield fd
            finally:
                os.close(fd)
            return
        path = parent / name
        info = path.lstat()
        if _reparse(info) or not stat.S_ISDIR(info.st_mode):
            raise RoutingError('session store path is not a plain directory')
        yield path

    def entries(self, handle):
        """Yield (name, kind, mtime, size) for plain files and directories only."""
        with os.scandir(handle) as iterator:
            for entry in iterator:
                self.budget.tick()
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    if exc.errno == errno.ENOENT:
                        continue
                    raise
                if _reparse(info):
                    continue
                if stat.S_ISDIR(info.st_mode):
                    yield entry.name, 'dir', info.st_mtime, 0
                elif stat.S_ISREG(info.st_mode):
                    yield entry.name, 'file', info.st_mtime, info.st_size

    @contextmanager
    def open_file(self, parent, name):
        self.budget.tick()
        if self.posix:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        else:
            path = parent / name
            info = path.lstat()
            if _reparse(info) or not stat.S_ISREG(info.st_mode):
                raise RoutingError('exact session file unavailable')
            fd = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOINHERIT', 0))
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise RoutingError('exact session file is not a regular file')
            yield fd, info
        finally:
            os.close(fd)


def _read_prefix(fd, limit):
    chunks, size = [], 0
    while size < limit:
        chunk = os.read(fd, min(65536, limit - size))
        if not chunk:
            return b''.join(chunks), True
        chunks.append(chunk)
        size += len(chunk)
    return b''.join(chunks), False


class FileSessionStore:
    """Shared read-only SessionAdapter over a file-per-session store.

    Subclasses define the harness family, the container below the state root,
    how recognized session files map to exact IDs, and which routing fields a
    bounded prefix may yield. All other behaviour, including budgets, review
    pinning and link refusal, is shared.
    """
    connected = True
    harness = ''
    label = ''
    sessions_relative = ''
    time_budget_seconds = 2
    max_sessions = 20_000
    max_entries = 200_000

    def __init__(self, home, *, review_snapshot=None):
        self.profile = StoreProfile(home, self.sessions_relative)
        self.home = self.profile.home
        self.identity = self.profile.identity
        self.review_snapshot = review_snapshot
        self.last_scan = None
        self.validate_review()
        incarnation = hashlib.sha256(repr((self.harness, self.identity)).encode()).hexdigest()
        self.target = SessionTarget('local', self.harness + ':' + str(self.home), str(self.home), incarnation)

    def validate_review(self):
        self.profile.validate()
        expected = self.review_snapshot
        if expected is not None:
            if (not isinstance(expected, dict) or expected.get('profile') != str(self.home)
                    or expected.get('identity') != list(self.identity or ())
                    or expected.get('home_identity') != list(self.profile.home_identity)
                    or expected.get('harness', self.harness) != self.harness):
                raise RoutingError(f'reviewed {self.label} state root or session store identity changed')

    # -- enumeration (names and stat only) -----------------------------------
    def metadata(self, target):
        if target != self.target:
            raise RoutingError('wrong exact store target')
        self.validate_review()
        if self.identity is None:
            return ()
        budget = _Budget(seconds=self.time_budget_seconds, entries=self.max_entries)
        walker = _Walker(self.profile.root, budget)
        items, size, skipped = [], 0, 0
        with walker.open_root() as root:
            for session_id, title, updated_at in self._sessions(walker, root):
                if session_id is None:
                    skipped += 1
                    continue
                if len(items) >= self.max_sessions:
                    raise RoutingError('metadata collection session budget exceeded; enumeration incomplete')
                item = SessionMetadata(SessionRoute(target, session_id), title, float(updated_at))
                size += metadata_bytes(item)
                if size > MAX_METADATA_BYTES:
                    raise RoutingError('metadata collection byte budget exceeded; enumeration incomplete')
                items.append(item)
        self.validate_review()
        self.last_scan = dict(sessions=len(items), skipped=skipped, probes=budget.probes)
        return tuple(items)

    def _sessions(self, walker, root):
        """Yield (session_id, title, mtime) per recognized file, or (None, name, 0) when skipped."""
        raise NotImplementedError

    # -- exact selection (bounded prefix, routing fields only) ----------------
    def perform(self, target, action, session_id=None, *, publication_guard=None):
        if target != self.target or action != 'select':
            raise RoutingError('launch requires separate explicit authorization')
        result = self.exact(session_id)
        if publication_guard is not None:
            publication_guard()
        return result

    def exact(self, session_id):
        cap = MAX_METADATA_FIELD_BYTES
        if (not isinstance(session_id, str) or not session_id or len(session_id) > cap
                or len(session_id.encode('utf-8')) > cap):
            raise RoutingError('selection identifier byte/type budget exceeded')
        parts = self._locate(session_id)
        self.validate_review()
        if self.identity is None:
            raise RoutingError('exact existing session ID unavailable; no fallback')
        budget = _Budget(seconds=self.time_budget_seconds, entries=self.max_entries)
        walker = _Walker(self.profile.root, budget)
        try:
            with ExitStack() as stack:
                parent = stack.enter_context(walker.open_root())
                for part in parts[:-1]:
                    parent = stack.enter_context(walker.child_dir(parent, part))
                fd, info = stack.enter_context(walker.open_file(parent, parts[-1]))
                prefix, complete = _read_prefix(fd, PREFIX_BYTES)
                after = os.fstat(fd)
        except OSError:
            # Missing, replaced by a link (ELOOP under O_NOFOLLOW), not a directory,
            # or unreadable: the exact destination is unavailable; never fall back.
            raise RoutingError('exact existing session ID unavailable; no fallback') from None
        if (after.st_dev, after.st_ino, after.st_size) != (info.st_dev, info.st_ino, info.st_size):
            raise RoutingError('session file changed during read; select again')
        result = dict(id=session_id, path='/'.join(parts), size_bytes=info.st_size, modified_at=info.st_mtime)
        result.update(self._routing_fields(parts, prefix, complete))
        for value in result.values():
            if isinstance(value, str):
                bounded_text(value)
        self.validate_review()
        return result

    def _locate(self, session_id):
        """Literal path parts below the store root for an exact ID, or RoutingError."""
        raise NotImplementedError

    def _routing_fields(self, parts, prefix, complete):
        """Allowlisted routing fields from a bounded prefix; never message content."""
        raise NotImplementedError

    # -- no native launch -----------------------------------------------------
    def launch_plan(self, *args, **kwargs):
        raise RoutingError(f'no verified native launch adapter for {self.label}; metadata only')

    launch = launch_plan
