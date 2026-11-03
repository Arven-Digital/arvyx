"""Bounded, discovered or selected-file workspace manifests; NOT an authorization boundary.

Callers MUST enforce authenticated resource/export grants, expiry, revocation and
access auditing before both snapshot creation and every read/export. No directory
is implicitly authorized. UTF-8 text is checked with the existing heuristic secret
scanner; binary/undecodable content is excluded. This is NOT complete secret
detection or content DLP. Callers must supply private exclusions and review content.

POSIX descriptor-relative, no-follow opens fail closed on unsupported platforms.
Reads detect replacement and mutation but cannot promise atomic multi-file views
against a hostile writer or recall previously disclosed bytes. No filesystem writes,
archives, network calls, execution, or grant creation are performed here.
"""
from contextlib import closing, contextmanager
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
import time

from . import safe_open
from .security import contains_literal_secret


class WorkspaceError(ValueError):
    """Invalid, unsafe, changed, or over-budget workspace selection."""


@dataclass(frozen=True)
class WorkspaceLimits:
    max_files: int = 1000
    max_file_bytes: int = 1024 * 1024
    max_total_bytes: int = 16 * 1024 * 1024
    max_path_bytes: int = 4096
    max_entries: int = 10000
    max_depth: int = 32


@dataclass(frozen=True)
class WorkspaceFile:
    path: str
    size: int
    sha256: str
    identity: tuple[int, ...]


@dataclass(frozen=True)
class WorkspaceExclusion:
    path: str
    reason: str


@dataclass(frozen=True)
class WorkspaceSnapshot:
    root: str
    root_identity: tuple[int, int]
    files: tuple[WorkspaceFile, ...]
    excluded: tuple[WorkspaceExclusion, ...]
    limits: WorkspaceLimits
    coverage: str = "selection"
    inventory: tuple = ()
    exclude_paths: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        """No omissions within coverage (selection or workspace), not a DLP guarantee."""
        return not self.excluded


def manifest_fingerprint(snapshot):
    """Stable approved selection identity across reopening, independent of mtimes.

    File content hashes bind bytes; canonical root and directory identity bind
    their source. File inode/ctime are still checked by each live export but do
    not make an unchanged reviewed selection depend on process-local metadata.
    """
    import json
    value = dict(version=1, root=snapshot.root, root_identity=snapshot.root_identity,
        coverage=snapshot.coverage, complete=snapshot.complete,
        files=sorted((f.path, f.size, f.sha256) for f in snapshot.files),
        excluded=sorted((f.path, f.reason) for f in snapshot.excluded),
        exclude_paths=sorted(snapshot.exclude_paths))
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _path(value: str, limit: int) -> tuple[str, ...]:
    if (not isinstance(value, str) or not value or "\\" in value or "\x00" in value
            or (os.name == "nt" and ":" in value)):
        raise WorkspaceError("invalid relative path")
    parts = tuple(value.split("/"))
    if any(p in ("", ".", "..") for p in parts):
        raise WorkspaceError("non-canonical relative path")
    try:
        length = len(value.encode("utf-8"))
    except UnicodeError as exc:
        raise WorkspaceError("invalid path encoding") from exc
    if length > limit:
        raise WorkspaceError("path budget exceeded")
    return parts


def _secret(parts: tuple[str, ...]) -> bool:
    for name in parts:
        name = name.lower()
        if (name in {".git", ".ssh", ".aws", ".azure", ".gnupg", ".kube",
                     ".netrc", ".npmrc", ".pypirc", "secrets", "private-family",
                     "credentials", "credentials.json", "id_rsa", "id_ed25519"}
                or name.startswith((".env", "secrets.", "credentials."))
                or name.endswith((".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"))):
            return True
    return False


# File timestamps come from the kernel's coarse clock. A file unlinked and recreated
# with the same bytes inside the tick that pinned it can keep every identity field
# (inode number reused), so a pin taken in the same tick as the file's last change
# could never detect that replacement. Pins that fresh are settled: the snapshot waits
# out the tick and re-reads the file, after which any later change necessarily moves
# mtime or ctime. The window covers coarse-clock ticks on nanosecond-resolution
# filesystems; one-second-resolution filesystems stay as (un)safe as before.
_RACY_TIMESTAMP_NS = 50_000_000


def _settle_racy_files(root, root_id, files, parts_by_path, limits):
    """Re-read files pinned inside the current timestamp tick once it has passed."""
    def latest(entry):
        # ctime alone: it is set by the kernel on every change and cannot be chosen
        # by a writer, whereas mtime may be arbitrary (utime, a future clock).
        return entry.identity[6]
    fresh = [entry for entry in files if latest(entry) + _RACY_TIMESTAMP_NS > time.time_ns()]
    if not fresh:
        return
    wait = max(latest(entry) for entry in fresh) + _RACY_TIMESTAMP_NS - time.time_ns()
    if wait > 0:
        time.sleep(min(wait, _RACY_TIMESTAMP_NS) / 1_000_000_000)
    for entry in fresh:
        data, identity, _ = _read(root, parts_by_path[entry.path], limits.max_file_bytes, root_id)
        if identity != entry.identity or hashlib.sha256(data).hexdigest() != entry.sha256:
            raise WorkspaceError("entry changed during discovery")


def _identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_size,
            st.st_mtime_ns, st.st_ctime_ns)


@contextmanager
def _open_root(root):
    if not safe_open.available():
        raise WorkspaceError("secure descriptor-relative opens unavailable")
    path = Path(root)
    if not path.is_absolute() or any(p in (".", "..") for p in os.fspath(root).replace("\\", "/").split("/")):
        raise WorkspaceError("root must be an absolute canonical directory")
    try:
        fd = safe_open.open_root(path)
    except OSError as exc:
        raise WorkspaceError("workspace root unavailable or unsafe") from exc
    try:
        yield fd
    finally:
        os.close(fd)


@contextmanager
def _open_file(root_fd, parts):
    parent = os.dup(root_fd)
    fd = None
    try:
        for part in parts[:-1]:
            next_fd = safe_open.open_directory_at(parent, part)
            os.close(parent)
            parent = next_fd
        fd = safe_open.open_file_at(parent, parts[-1])
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise WorkspaceError("only singly-linked regular files may be exported")
        yield fd
    except OSError as exc:
        raise WorkspaceError("selected file unavailable or unsafe") from exc
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def _read(root, parts, limit, expected_root=None, expected_file=None):
    with _open_root(root) as root_fd:
        root_st = os.fstat(root_fd)
        root_id = (safe_open.stable_identity(root_st.st_dev), safe_open.stable_identity(root_st.st_ino))
        if expected_root is not None and root_id != tuple(safe_open.stable_identity(v) for v in expected_root):
            raise WorkspaceError("workspace root replaced")
        with _open_file(root_fd, parts) as fd:
            before = _identity(os.fstat(fd))
            if expected_file is not None and before != expected_file:
                raise WorkspaceError("snapshot file changed")
            if before[4] > limit:
                raise WorkspaceError("file byte budget exceeded")
            chunks = []
            size = 0
            while True:
                chunk = os.read(fd, min(65536, limit - size + 1))
                if not chunk:
                    break
                size += len(chunk)
                if size > limit:
                    raise WorkspaceError("file byte budget exceeded")
                chunks.append(chunk)
            if _identity(os.fstat(fd)) != before or size != before[4]:
                raise WorkspaceError("file changed during read")
        # Rewalk from the absolute root, not a possibly detached directory fd.
        with _open_root(root) as check_root:
            st = os.fstat(check_root)
            if (safe_open.stable_identity(st.st_dev), safe_open.stable_identity(st.st_ino)) != root_id:
                raise WorkspaceError("workspace root replaced during read")
            with _open_file(check_root, parts) as check_fd:
                if _identity(os.fstat(check_fd)) != before:
                    raise WorkspaceError("file replaced during read")
        return b"".join(chunks), before, root_id


def _content_exclusion(data):
    try:
        text = data.decode("utf-8")
    except UnicodeError:
        return "unsupported-content"
    if any(ord(c) < 32 and c not in "\n\r\t" for c in text):
        return "unsupported-content"
    return "secret-content" if contains_literal_secret(text) else None


def _discover(root, limits, exclusions):
    """Bounded no-follow walk; excluded directories are opaque omissions.

    Metadata inventories detect observed changes, not an atomic filesystem view.
    No gitignore rules or executable repository configuration are evaluated.
    """
    files, omitted, inventory = [], [], []
    count = 0

    def walk(fd, prefix, depth):
        nonlocal count
        before = _identity(os.fstat(fd))
        inventory.append(("/".join(prefix), before))
        with closing(safe_open.scandir_names(fd)) as names_iter:
            for name in names_iter:
                count += 1
                if count > limits.max_entries:
                    raise WorkspaceError("traversal entry budget exceeded")
                parts = _path("/".join((*prefix, name)), limits.max_path_bytes)
                value = "/".join(parts)
                st = safe_open.stat_at(fd, name)
                identity = _identity(st)
                directory = stat.S_ISDIR(st.st_mode)
                if not directory and (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1):
                    raise WorkspaceError("unsafe workspace entry")
                if st.st_dev != before[0]:
                    raise WorkspaceError("cross-device workspace entry")
                private = _secret(parts)
                if private or any(parts[:len(p)] == p for p in exclusions):
                    inventory.append((value, identity))
                    omitted.append(WorkspaceExclusion(value, "secret-or-private" if private else "caller-excluded"))
                elif directory:
                    if depth >= limits.max_depth:
                        raise WorkspaceError("traversal depth budget exceeded")
                    child = safe_open.open_directory_at(fd, name)
                    try:
                        if _identity(os.fstat(child)) != identity:
                            raise WorkspaceError("directory replaced during discovery")
                        walk(child, parts, depth + 1)
                    finally:
                        os.close(child)
                else:
                    inventory.append((value, identity))
                    files.append(value)
                if len(files) + len(omitted) > limits.max_files:
                    raise WorkspaceError("manifest budget exceeded")
                if _identity(safe_open.stat_at(fd, name)) != identity:
                    raise WorkspaceError("entry changed during discovery")
        if _identity(os.fstat(fd)) != before:
            raise WorkspaceError("directory changed during discovery")

    try:
        with _open_root(root) as fd:
            walk(fd, (), 0)
    except OSError as exc:
        raise WorkspaceError("workspace discovery unavailable or unsafe") from exc
    return sorted(files), omitted, tuple(sorted(inventory))


def _verify_inventory(snapshot):
    if snapshot.coverage == "workspace":
        exclusions = [_path(p, snapshot.limits.max_path_bytes) for p in snapshot.exclude_paths]
        _, _, current = _discover(snapshot.root, snapshot.limits, exclusions)
        if current != snapshot.inventory:
            raise WorkspaceError("workspace inventory changed; create a new manifest")


def snapshot_workspace(root, paths=None, *, limits=WorkspaceLimits(), exclude_paths=()):
    """Discover a workspace when paths is None, otherwise hash selected files.

    Enforce live grants (including 24-hour expiry) before creation and reads.

    Excluded paths need not exist in selected mode and are never opened. In
    discovery mode excluded directories are opaque subtree omissions (one record,
    not an enumeration of private descendants). No gitignore is consulted.
    Coverage is explicitly 'workspace' or 'selection'; complete only means no
    recorded omissions in that scope, never complete secret detection. Binary,
    non-UTF-8 and secret-shaped content is omitted, not redacted or returned.
    Selection/omission count, traversal entries/depth, path length and bytes are
    bounded; over-budget selections fail, never silently truncate. Scanned but
    omitted content still consumes the aggregate byte budget. Discovery stores a
    metadata inventory rechecked before/after reads; changed workspaces require
    a new manifest. This is not an atomic snapshot or a 24-hour content freeze.
    Files changed within the last few milliseconds are pinned only after their
    timestamp tick has passed (a bounded wait); one that changes meanwhile fails
    with "entry changed during discovery", which a caller may simply retry.
    """
    if not isinstance(limits, WorkspaceLimits) or any(
        type(n) is not int or n < 0 for n in
        (limits.max_files, limits.max_file_bytes, limits.max_total_bytes, limits.max_path_bytes,
         limits.max_entries, limits.max_depth)
    ):
        raise WorkspaceError("invalid workspace limits")
    exclusions = []
    for value in exclude_paths:
        if len(exclusions) >= limits.max_files:
            raise WorkspaceError("exclusion budget exceeded")
        exclusions.append(_path(value, limits.max_path_bytes))
    discovery = paths is None
    inventory = ()
    discovered_omissions = []
    if discovery:
        paths, discovered_omissions, inventory = _discover(root, limits, exclusions)
    files, omitted, seen = [], list(discovered_omissions), set()
    parts_by_path = {}
    total = 0
    with _open_root(root) as fd:
        st = os.fstat(fd)
        root_id = (st.st_dev, st.st_ino)
    for value in paths:
        if len(seen) >= limits.max_files:
            raise WorkspaceError("selection budget exceeded")
        parts = _path(value, limits.max_path_bytes)
        if value in seen:
            raise WorkspaceError("duplicate selection")
        seen.add(value)
        parts_by_path[value] = parts
        private = _secret(parts)
        if private or any(parts[:len(prefix)] == prefix for prefix in exclusions):
            omitted.append(WorkspaceExclusion(value, "secret-or-private" if private else "caller-excluded"))
            continue
        data, identity, _ = _read(root, parts, min(limits.max_file_bytes, limits.max_total_bytes - total), root_id)
        total += len(data)
        reason = _content_exclusion(data)
        if reason:
            omitted.append(WorkspaceExclusion(value, reason))
            continue
        files.append(WorkspaceFile(value, len(data), hashlib.sha256(data).hexdigest(), identity))
    _settle_racy_files(root, root_id, files, parts_by_path, limits)
    snapshot = WorkspaceSnapshot(os.fspath(root), root_id, tuple(sorted(files, key=lambda f: f.path)),
                                 tuple(sorted(omitted, key=lambda f: f.path)), limits,
                                 "workspace" if discovery else "selection", inventory,
                                 tuple("/".join(p) for p in exclusions))
    _verify_inventory(snapshot)
    return snapshot


def read_snapshot_file(snapshot, path):
    """Revalidate membership, identity and hash; caller must check live grants."""
    _verify_inventory(snapshot)
    parts = _path(path, snapshot.limits.max_path_bytes)
    entry = next((entry for entry in snapshot.files if entry.path == path), None)
    if entry is None or _secret(parts):
        raise WorkspaceError("file is not in the permitted manifest")
    data, _, _ = _read(snapshot.root, parts, min(entry.size, snapshot.limits.max_file_bytes),
                       snapshot.root_identity, entry.identity)
    if len(data) != entry.size or hashlib.sha256(data).hexdigest() != entry.sha256:
        raise WorkspaceError("snapshot hash mismatch")
    if _content_exclusion(data):
        raise WorkspaceError("snapshot content is not permitted")
    _verify_inventory(snapshot)
    return data


def export_snapshot(snapshot):
    """Return bounded verified bytes, or fail without returning a partial export.

    Snapshot objects are local trusted records, not bearer tokens or serialized
    authorization proofs. Enforce export authority before calling this primitive.
    """
    if len(snapshot.files) + len(snapshot.excluded) > snapshot.limits.max_files:
        raise WorkspaceError("manifest budget exceeded")
    result = {}
    total = 0
    for entry in snapshot.files:
        if entry.path in result or entry.size > snapshot.limits.max_total_bytes - total:
            raise WorkspaceError("export budget exceeded or duplicate entry")
        data = read_snapshot_file(snapshot, entry.path)
        total += len(data)
        result[entry.path] = data
    _verify_inventory(snapshot)
    return result
