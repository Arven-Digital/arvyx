from __future__ import annotations

import base64
from collections.abc import Callable
from contextlib import ExitStack, contextmanager
import stat
from dataclasses import dataclass
from datetime import UTC
from datetime import datetime
import hashlib
import ipaddress
import json
import os

from pathlib import Path
import re
from typing import Any, NoReturn
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit, urlunsplit
from urllib.request import Request
from .http_bounds import BoundedOpener

from .locks import exclusive_lock, vault_lock
from .promotion_transaction import memory_mutation
from .security import is_http_url


_OPENER = BoundedOpener()
urlopen = _OPENER.open


REPLICA_MARKER = ".arvyx-replica"
REPLICA_STATUS = Path(".arvyx") / "replica-status.json"
REPLICA_FAILOVER = Path(".arvyx") / "failover.json"
# The vault-local cache/status directory and the primary/replica marker
# files are host-specific state; they must never replicate. Shipping the
# primary's `.arvyx-vault` into a replica would leave it carrying both
# markers, so losing `.arvyx-replica` would misclassify it as a primary and
# make re-sync refuse it. (VAULT_MARKER = ".arvyx-vault", kept as a literal
# here to avoid importing vault.py at module load.)
SKIP_SEGMENTS = {".arvyx", ".arvyx-vault", ".arvyx-replica"}
# What a replica keeps locally and the sync deletion loop must never reap:
# its own cache dir and replica marker. Notably NOT .arvyx-vault — a stray
# primary marker on a replica (e.g. left by a pre-fix sync) should be deleted
# so the replica self-heals to a clean replica-only state.
REPLICA_PRESERVE = {".arvyx", ".arvyx-replica"}
STATE_FILE_NAMES = ("control-events.jsonl", "audit-log.jsonl")
DEFAULT_MAX_STALENESS_SECONDS = 3600
MAX_REPLICA_FILE_BYTES = 8 * 1024 * 1024
SHA256_HEX = re.compile(r"^[a-f0-9]{64}$")


@dataclass(frozen=True)
class ReplicaSyncResult:
    source: str
    vault: str
    fetched: list[str]
    deleted: list[str]
    unchanged: int
    state_fetched: list[str]
    state_deleted: list[str]
    synced_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "vault": self.vault,
            "fetched": self.fetched,
            "deleted": self.deleted,
            "unchanged": self.unchanged,
            "state_fetched": self.state_fetched,
            "state_deleted": self.state_deleted,
            "synced_at": self.synced_at,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass(frozen=True)
class ReplicaStatusResult:
    vault: str
    is_replica: bool
    source: str | None
    last_synced_at: str | None
    age_seconds: int | None
    files: int | None
    sync_complete: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "vault": self.vault,
            "is_replica": self.is_replica,
            "source": self.source,
            "last_synced_at": self.last_synced_at,
            "age_seconds": self.age_seconds,
            "files": self.files,
            "sync_complete": self.sync_complete,
            # Completion describes the file mirror only, not write admission.
            "writable_failover_ready": False,
            "mutation_authority": "not-replicated",
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def build_manifest(vault: Path, state: Path | None = None, audit_log: Path | None = None) -> dict[str, Any]:
    """Describe every replicable file with its sha256, for pull sync."""
    vault_root = vault.absolute()
    # Capture the bounded control prefix BEFORE enumerating transcript blobs.
    # Transcript writers publish the immutable blob before appending its event
    # under this same sidecar lock. Release it before taking memory_mutation:
    # the independent authority locks must never nest.
    state_files: dict[str, dict[str, Any]] = {}
    control_prefix = b""
    if state is not None:
        with exclusive_lock(state.with_suffix(state.suffix + ".lock")):
            if state.is_file():
                with state.open("rb") as handle:
                    control_prefix = handle.read(MAX_REPLICA_FILE_BYTES + 1)
                if len(control_prefix) > MAX_REPLICA_FILE_BYTES:
                    raise ValueError("state file exceeds replication size cap: control-events.jsonl")
                state_files["control-events.jsonl"] = {
                    "sha256": hashlib.sha256(control_prefix).hexdigest(), "size": len(control_prefix),
                }
    transcript_refs = _transcript_references(control_prefix)
    files: dict[str, dict[str, Any]] = {}
    # Reconcile interrupted promotions before observing names, then keep the
    # source vault locked through hashing so no multi-file publication can
    # produce a manifest with a superseded parent but no replacement.
    with _source_root(vault_root) as root_fd, memory_mutation(vault_root):
        for relative in _source_files(root_fd):
            data = _source_bytes(root_fd, relative)
            files[relative] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        # Check EVERY reference from the exact bytes advertised above, not a
        # later control read (which could introduce a second inconsistent cut).
        for relative, digest in transcript_refs:
            if relative not in files or files[relative]["sha256"] != digest:
                raise ValueError(f"replica transcript blob missing or digest mismatch: {relative}")
    # Audit keeps its own bounded writer-locked prefix, outside the vault lock.
    for name, candidate in (("audit-log.jsonl", audit_log),):
        if candidate is not None:
            # Use the same sidecar lock as both state and audit writers. Hash
            # only bounded bytes captured while appenders are excluded.
            with exclusive_lock(candidate.with_suffix(candidate.suffix + ".lock")):
                if not candidate.is_file():
                    continue
                with candidate.open("rb") as handle:
                    data = handle.read(MAX_REPLICA_FILE_BYTES + 1)
                if len(data) > MAX_REPLICA_FILE_BYTES:
                    raise ValueError(f"state file exceeds replication size cap: {name}")
                state_files[name] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
    return {
        "schema_version": 1,
        "generated_at": _now(),
        "files": files,
        "state_files": state_files,
    }


def _transcript_references(prefix: bytes) -> list[tuple[str, str]]:
    """Validate archive receipts using only the captured control authority."""
    references: list[tuple[str, str]] = []
    for line in prefix.splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("invalid replica control prefix") from exc
        if not isinstance(event, dict):
            raise ValueError("invalid replica control event")
        if event.get("type") != "work.transcript":
            continue
        payload = event.get("payload")
        if not isinstance(payload, dict):
            raise ValueError("invalid replica transcript reference")
        event_id = payload.get("event_id")
        digest = payload.get("sha256")
        if (not isinstance(event_id, str)
                or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", event_id) is None
                or not isinstance(digest, str) or SHA256_HEX.fullmatch(digest) is None):
            raise ValueError("invalid replica transcript reference")
        relative = f"conversations/cockpit-archive/{event_id}.json"
        if payload.get("storage_ref") != relative:
            raise ValueError("invalid replica transcript storage reference")
        references.append((relative, digest))
    return references


def _source_parts(relative: str) -> list[str]:
    # Do not resolve or normalize away an excluded/traversal component.
    parts = relative.split("/")
    if (not relative or "\\" in relative or "\x00" in relative
            or any(part in {"", ".", ".."} or part in SKIP_SEGMENTS for part in parts)):
        raise ValueError(f"path is not replicable: {relative}")
    return parts


@contextmanager
def _source_root(vault: Path):
    # Fail closed on platforms without descriptor-relative no-follow support.
    if (not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY")
            or os.open not in os.supports_dir_fd):
        raise ValueError("replica source requires descriptor-relative no-follow support")
    absolute = vault.absolute()
    if ".." in absolute.parts:
        raise ValueError("replica source root must not contain traversal")
    with ExitStack() as stack:
        fd = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stack.callback(os.close, fd)
        for part in absolute.parts[1:]:
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            stack.callback(os.close, fd)
        yield fd


def _source_files(directory_fd: int, prefix: str = ""):
    for name in sorted(os.listdir(directory_fd)):
        relative = prefix + name
        if name in SKIP_SEGMENTS:
            continue
        _source_parts(relative)
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
            try:
                yield from _source_files(fd, relative + "/")
            finally:
                os.close(fd)
        elif stat.S_ISREG(info.st_mode):
            yield relative


def _source_bytes(root_fd: int, relative: str) -> bytes:
    parts = _source_parts(relative)
    with ExitStack() as stack:
        parent_fd = root_fd
        for part in parts[:-1]:
            parent_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            stack.callback(os.close, parent_fd)
        # NONBLOCK prevents a replaced FIFO from hanging before fstat rejects it.
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
        stack.callback(os.close, fd)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError(f"replica source must be a regular file: {relative}")
        with os.fdopen(os.dup(fd), "rb") as handle:
            data = handle.read(MAX_REPLICA_FILE_BYTES + 1)
        if len(data) > MAX_REPLICA_FILE_BYTES:
            raise ValueError(f"file exceeds replication size cap: {relative}")
        return data


def read_vault_file(vault: Path, relative: str) -> dict[str, Any]:
    _source_parts(relative)
    with _source_root(vault) as root_fd:
        data = _source_bytes(root_fd, relative)
    return {"path": relative, "content_b64": base64.b64encode(data).decode("ascii"), "size": len(data)}


def read_state_file(
    name: str, state: Path | None, audit_log: Path | None, *, size: int, sha256: str,
) -> dict[str, Any]:
    """Serve a manifest-bound prefix; rotation/rewrite fails closed."""
    sources = {"control-events.jsonl": state, "audit-log.jsonl": audit_log}
    if name not in sources:
        raise ValueError(f"unknown state file: {name}")
    _manifest_state_size({"size": size}, label=name)
    _manifest_sha256({"sha256": sha256}, label=name)
    path = sources[name]
    if path is None:
        raise FileNotFoundError(name)
    with exclusive_lock(path.with_suffix(path.suffix + ".lock")):
        with path.open("rb") as handle:
            data = handle.read(size)
        if len(data) != size or hashlib.sha256(data).hexdigest() != sha256:
            raise ValueError(f"replica state snapshot changed; fetch a fresh manifest: {name}")
    return {"path": name, "content_b64": base64.b64encode(data).decode("ascii"), "size": len(data)}


def sync_replica(
    source_url: str,
    vault: Path,
    token: str | None = None,
    state_dir: Path | None = None,
    timeout: float = 30.0,
) -> ReplicaSyncResult:
    """Pull the primary's vault (and state files) into a replica vault.

    The target must be empty/new or carry the replica marker; a primary
    vault (marker without replica marker) is refused so a mistyped path
    cannot overwrite the source of truth.
    """
    source_url = source_url.rstrip("/")
    vault_root = vault.absolute()
    # Hold the vault lock across the whole sync so the marker check, the file
    # writes, and the deletion loop are atomic against a concurrent failover
    # (which flips the same markers) — otherwise a race could delete a
    # freshly-promoted .arvyx-vault and leave a marker-less, bricked vault.
    # Reject unrelated authority before even vault_lock can create a directory.
    if state_dir is not None:
        state_dir = state_dir.resolve()
        _validate_replica_state_owner(state_dir, vault_root, source_url)
    # Validate before lock setup can follow an alias into excluded authority,
    # but after rejecting an unrelated external authority without writes.
    with _destination_parent(vault_root / '.destination-check', create=True):
        pass
    _destination_inventory(vault_root)
    with ExitStack() as stack:
        if state_dir is not None:
            stack.enter_context(exclusive_lock(
                state_dir.parent / ('.' + state_dir.name + '.replica-owner.lock')
            ))
            # A competing first adopter may have published while we waited.
            _validate_replica_state_owner(state_dir, vault_root, source_url)
            _durable_mkdir(state_dir)
            _durable_write(state_dir / '.arvyx-replica-state.json', (
                json.dumps(_replica_state_owner(vault_root, source_url), sort_keys=True) + '\n'
            ).encode())
            for name in STATE_FILE_NAMES:
                stack.enter_context(exclusive_lock(state_dir / (name + '.lock')))
        stack.enter_context(vault_lock(vault_root))
        from .forget_guard import assert_copyable_forget_operations
        assert_copyable_forget_operations(vault_root)
        return _sync_replica_locked(source_url, vault_root, token, state_dir, timeout)


def _replica_state_owner(vault_root: Path, source_url: str) -> dict[str, str]:
    return {'schema': 'arvyx-replica-state/v1', 'vault': str(vault_root), 'source': source_url}


def _validate_replica_state_owner(state_dir: Path, vault_root: Path, source_url: str) -> None:
    # External authority cannot be inside (or contain) the replicated tree.
    if state_dir == vault_root or state_dir in vault_root.parents or vault_root in state_dir.parents:
        raise ValueError('replica state directory must be separate from replica vault')
    marker = state_dir / '.arvyx-replica-state.json'
    if marker.is_symlink():
        raise ValueError('replica state ownership marker must not be a symlink')
    if marker.exists():
        if not marker.is_file() or json.loads(marker.read_text()) != _replica_state_owner(vault_root, source_url):
            raise ValueError('replica state directory belongs to another replica or source')
        for name in STATE_FILE_NAMES:
            for path in (state_dir / name, state_dir / (name + '.lock')):
                if path.is_symlink() or (path.exists() and not path.is_file()):
                    raise ValueError('replica state files and locks must be regular files')
        return
    if state_dir.exists() and (not state_dir.is_dir() or any(state_dir.iterdir())):
        raise ValueError('refusing unowned nonempty replica state directory')


def _sync_replica_locked(
    source_url: str,
    vault_root: Path,
    token: str | None,
    state_dir: Path | None,
    timeout: float,
) -> ReplicaSyncResult:
    _destination_inventory(vault_root)
    if _promotion_lineage(vault_root) is not None:
        raise ValueError("failover transaction exists; reconcile promotion before syncing")
    _ensure_replica_target(vault_root, source_url)

    manifest = _get_json(f"{source_url}/replica/manifest", token=token, timeout=timeout)
    remote_files = manifest.get("files")
    if not isinstance(remote_files, dict):
        raise ValueError("replica manifest is missing files")

    fetched: list[str] = []
    unchanged = 0
    for relative, meta in sorted(remote_files.items()):
        target = _replica_target_path(vault_root, relative)
        expected = _manifest_sha256(meta, label=str(relative))
        if _destination_matches(target, expected):
            unchanged += 1
            continue
        payload = _get_json(
            f"{source_url}/replica/file?path={quote(relative)}",
            token=token,
            timeout=timeout,
        )
        data = base64.b64decode(str(payload.get("content_b64", "")))
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f"replica file hash mismatch: {relative}")
        _durable_write(target, data)
        fetched.append(relative)

    deleted: list[str] = []
    for relative in _destination_inventory(vault_root):
        if any(part in REPLICA_PRESERVE for part in relative.split("/")):
            continue
        if relative not in remote_files:
            path = vault_root / relative
            with _destination_parent(path) as parent_fd:
                _destination_leaf(parent_fd, path.name)
                os.unlink(path.name, dir_fd=parent_fd)
                os.fsync(parent_fd)
            deleted.append(relative)

    state_fetched: list[str] = []
    state_deleted: list[str] = []
    remote_state = manifest.get("state_files")
    if state_dir is not None and not isinstance(remote_state, dict):
        raise ValueError("replica manifest is missing state_files")
    if state_dir is not None and isinstance(remote_state, dict):
        state_dir = state_dir.resolve()
        _durable_mkdir(state_dir)
        remote_state_names = set(remote_state).intersection(STATE_FILE_NAMES)
        for name in STATE_FILE_NAMES:
            if name not in remote_state:
                continue
            meta = remote_state.get(name)
            expected = _manifest_sha256(meta, label=f"state_files.{name}")
            size = _manifest_state_size(meta, label=f"state_files.{name}")
            payload = _get_json(
                f"{source_url}/replica/state?name={quote(name)}&size={size}&sha256={expected}",
                token=token, timeout=timeout,
            )
            data = base64.b64decode(str(payload.get("content_b64", "")), validate=True)
            if len(data) != size or hashlib.sha256(data).hexdigest() != expected:
                raise ValueError(f"replica state file hash mismatch: {name}")
            _durable_write(state_dir / name, data)
            state_fetched.append(name)
        for name in STATE_FILE_NAMES:
            if name in remote_state_names:
                continue
            target = state_dir / name
            if target.exists():
                target.unlink()
                _fsync_directory(target.parent)
                state_deleted.append(name)

    synced_at = _now()
    status_path = vault_root / REPLICA_STATUS
    _durable_write(status_path, (
        json.dumps(
            {
                "source": source_url,
                "sync_complete": True,
                "last_synced_at": synced_at,
                "files": len(remote_files),
                "state_files": state_fetched,
                "state_deleted": state_deleted,
            },
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8"))
    return ReplicaSyncResult(
        source=source_url,
        vault=str(vault_root),
        fetched=fetched,
        deleted=deleted,
        unchanged=unchanged,
        state_fetched=state_fetched,
        state_deleted=state_deleted,
        synced_at=synced_at,
    )


def replica_status(vault: Path) -> ReplicaStatusResult:
    vault_root = vault.resolve()
    marker = vault_root / REPLICA_MARKER
    status_path = vault_root / REPLICA_STATUS
    from .replica_authority import LEGACY_REPLICA_MARKER
    legacy = vault_root / LEGACY_REPLICA_MARKER
    if not marker.is_file() and (legacy.exists() or legacy.is_symlink()):
        # Pre-rename replica: mutation is quarantined; never report it as primary.
        return ReplicaStatusResult(
            vault=str(vault_root), is_replica=True, source=None, last_synced_at=None, age_seconds=None, files=None
        )
    if not marker.is_file():
        return ReplicaStatusResult(
            vault=str(vault_root), is_replica=False, source=None, last_synced_at=None, age_seconds=None, files=None
        )
    source = None
    last_synced_at = None
    files = None
    sync_complete = False
    if status_path.is_file():
        try:
            payload = json.loads(status_path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("replica status must be an object")
            sync_complete = payload.get("sync_complete") is True
            source = str(payload.get("source")) if payload.get("source") else None
            last_synced_at = str(payload.get("last_synced_at")) if payload.get("last_synced_at") else None
            files = int(payload["files"]) if payload.get("files") is not None else None
        except (OSError, TypeError, ValueError):
            pass
    age_seconds = None
    if last_synced_at:
        try:
            synced = datetime.fromisoformat(last_synced_at.replace("Z", "+00:00"))
            elapsed = (datetime.now(UTC) - synced).total_seconds()
            if elapsed >= 0:
                age_seconds = int(elapsed)
        except (TypeError, ValueError):
            pass
    return ReplicaStatusResult(
        vault=str(vault_root),
        is_replica=True,
        source=source,
        last_synced_at=last_synced_at,
        age_seconds=age_seconds,
        files=files,
        sync_complete=sync_complete,
    )


@dataclass(frozen=True)
class FailoverResult:
    vault: str
    promoted: bool
    reason: str
    prior_source: str | None
    primary_reachable: bool
    quorum_reachable: int
    quorum_required: int
    promoted_at: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "vault": self.vault,
            "promoted": self.promoted,
            "reason": self.reason,
            "prior_source": self.prior_source,
            "primary_reachable": self.primary_reachable,
            "quorum_reachable": self.quorum_reachable,
            "quorum_required": self.quorum_required,
            "promoted_at": self.promoted_at,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def probe_reachable(url: str, timeout: float = 5.0, token: str | None = None) -> bool:
    """True if the host answers /health as an Arvyx control API.

    Any transport, HTTP, or scheme error counts as unreachable — a probe is
    a liveness check, not a place to surface exceptions.
    """
    base = url.rstrip("/")
    try:
        payload = _get_json(f"{base}/health", token=token, timeout=timeout)
    except (ValueError, OSError):
        return False
    return payload.get("ok") is True or bool(payload.get("service"))


def promote_replica(vault: Path, reason: str = "manual", prior_source: str | None = None) -> NoReturn:
    """Request promotion; refuse until journal/effect authority is replicated.

    Role validation and existing intent guards are retained, but no current
    replica generation is eligible for writable promotion.
    reason and prior_source remain accepted for caller compatibility only.
    """
    vault_root = vault.resolve()
    with vault_lock(vault_root):
        from .forget_guard import assert_copyable_forget_operations
        assert_copyable_forget_operations(vault_root)
        _promote_replica_locked(vault_root)


def _promote_replica_locked(vault_root: Path) -> NoReturn:
    from .vault import VAULT_MARKER

    lineage = _promotion_lineage(vault_root)
    marker = vault_root / REPLICA_MARKER
    if lineage is None:
        if not marker.is_file():
            if (vault_root / VAULT_MARKER).is_file():
                raise ValueError(f"{vault_root} is already a primary vault; nothing to promote")
            raise ValueError(f"not a replica vault (no {REPLICA_MARKER}): {vault_root}")
    elif lineage["phase"] == "complete":
        if marker.exists() or not (vault_root / VAULT_MARKER).is_file():
            raise ValueError("completed failover has inconsistent role markers")

    # JSONL/vault sync does not carry matching journal/effect authority. Refuse
    # before any role or lineage publication, including forced and retry paths.
    # Do not infer authority from a locally existing (possibly stale) journal.
    from .replica_authority import assert_promotion_authority
    assert_promotion_authority(vault_root)


def _promotion_lineage(vault_root: Path) -> dict[str, Any] | None:
    path = vault_root / REPLICA_FAILOVER
    if not path.exists():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    # Historical lineage is not a prepared transaction and cannot authorize replay.
    if isinstance(payload, dict) and "phase" not in payload:
        return None
    if (
        not isinstance(payload, dict) or payload.get("schema_version") != 1
        or payload.get("phase") not in {"prepared", "complete"}
        or not isinstance(payload.get("reason"), str)
        or not isinstance(payload.get("promoted_at"), str)
        or "prior_source" not in payload
        or (payload["prior_source"] is not None and not isinstance(payload["prior_source"], str))
    ):
        raise ValueError("invalid failover transaction lineage")
    return payload


def _canonical_peer(url: str) -> str:
    """Canonical endpoint identity; DNS aliases still require operator discipline."""
    if not isinstance(url, str) or any(c.isspace() for c in url):
        raise ValueError("peer must be an HTTP(S) endpoint")
    parts = urlsplit(url)
    if (parts.scheme.lower() not in {"http", "https"} or not parts.hostname
            or parts.username is not None or parts.password is not None
            or parts.query or parts.fragment):
        raise ValueError("peer must be an HTTP(S) endpoint without credentials, query or fragment")
    scheme = parts.scheme.lower()
    host = parts.hostname.lower().rstrip(".")
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        host = host.encode("idna").decode("ascii")
    if not host:
        raise ValueError("peer endpoint requires a hostname")
    if ":" in host:
        host = f"[{host}]"
    port = parts.port
    authority = host if port is None or port == (443 if scheme == "https" else 80) else f"{host}:{port}"
    path = parts.path.rstrip("/")
    if any(part in {".", ".."} for part in path.split("/")) or "%" in path or "\\" in path or "//" in path:
        raise ValueError("peer endpoint path must be canonical")
    return urlunsplit((scheme, authority, path, "", ""))


def auto_failover(
    vault: Path,
    source_url: str,
    peers: tuple[str, ...] = (),
    timeout: float = 5.0,
    token: str | None = None,
    probe: Callable[[str, float, str | None], bool] = probe_reachable,
    max_staleness_seconds: int | None = DEFAULT_MAX_STALENESS_SECONDS,
    force: bool = False,
) -> FailoverResult:
    """Promote a replica only when it is safe to: the primary is unreachable,
    the replica is fresh enough, and a majority of the replica set is
    reachable from this node.

    Quorum needs peers to mean anything: with no `--peer`, a majority of one
    is trivially satisfied, so `--auto` would promote on any primary blip —
    exactly the split-brain it is meant to stop. So auto-failover refuses
    unless at least one peer is configured; a genuine single-replica warm
    standby should use the manual `failover` path (no `--auto`) once the
    operator has confirmed the primary is down out of band.

    The quorum signal is peer *reachability*, not distributed agreement: it
    rules out a minority-partition replica promoting itself, but a one-way
    partition (this node cannot reach the primary while its peers still can)
    is a residual risk that only external DNS/proxy repointing resolves.
    Freshness fails closed: an unknown replica age is treated as too stale.
    Omitted or None freshness limits use the bounded one-hour default.
    Legacy status without explicit completion requires a successful resync.
    `force` bypasses availability gates, never the journal/effect authority
    fence in the shared promotion primitive. Writable promotion is unavailable.
    """
    vault_root = vault.resolve()
    freshness_limit = DEFAULT_MAX_STALENESS_SECONDS if max_staleness_seconds is None else max_staleness_seconds
    if not force and freshness_limit <= 0:
        raise ValueError("automatic failover requires a positive staleness limit")
    peers = tuple(_canonical_peer(peer) for peer in peers)
    if len(set(peers)) != len(peers):
        raise ValueError("duplicate failover peer endpoints")
    asserted_source = _canonical_peer(source_url)
    if asserted_source in peers:
        raise ValueError("primary endpoint cannot be a failover peer")

    def source_identity(source: str | None) -> str | None:
        try:
            return _canonical_peer(source) if source else None
        except (ValueError, TypeError, UnicodeError):
            return None

    with vault_lock(vault_root):
        from .forget_guard import assert_copyable_forget_operations
        assert_copyable_forget_operations(vault_root)
        if _promotion_lineage(vault_root) is not None:
            _promote_replica_locked(vault_root)
        probed_source = source_identity(replica_status(vault_root).source)
    # --from is an assertion, not authority to probe an unrelated primary.
    # Force retains its existing operator-supplied probe and gate bypass.
    bound_source = probed_source is not None and probed_source == asserted_source
    primary_reachable = False
    reachable = 1
    if force or bound_source:
        probe_url = source_url if force else probed_source
        assert probe_url is not None
        primary_reachable = probe(probe_url, timeout, token)
        reachable += sum(1 for peer in peers if probe(peer, timeout, token))
    total = 1 + len(peers)
    required = total // 2 + 1

    with vault_lock(vault_root):
        from .forget_guard import assert_copyable_forget_operations
        assert_copyable_forget_operations(vault_root)
        if _promotion_lineage(vault_root) is not None:
            _promote_replica_locked(vault_root)
        status = replica_status(vault_root)
        if not status.is_replica:
            raise ValueError(f"not a replica vault: {vault_root}")

        def refuse(reason: str) -> FailoverResult:
            return FailoverResult(
                vault=str(vault_root),
                promoted=False,
                reason=reason,
                prior_source=status.source,
                primary_reachable=primary_reachable,
                quorum_reachable=reachable,
                quorum_required=required,
                promoted_at=None,
            )

        if not force:
            if not status.sync_complete:
                return refuse("replica-incomplete")
            current_source = source_identity(status.source)
            if probed_source is None or current_source is None:
                return refuse("replica-source-missing-or-invalid")
            if current_source != probed_source:
                return refuse("replica-source-changed")
            if asserted_source != current_source:
                return refuse("replica-source-mismatch")
            if primary_reachable:
                return refuse("primary-reachable")
            if status.age_seconds is None or status.age_seconds > freshness_limit:
                return refuse("replica-stale")
            if not peers:
                return refuse("quorum-requires-peers")
            if reachable < required:
                return refuse("no-quorum")

        _promote_replica_locked(vault_root)


def _ensure_replica_target(vault_root: Path, source_url: str) -> None:
    # Imported lazily: vault.py imports api.py which imports this module.
    from .vault import VAULT_MARKER

    marker = vault_root / REPLICA_MARKER
    if marker.is_file():
        _mark_sync_incomplete(vault_root, source_url)
        return
    # The vault lock creates a lone .arvyx/ before we get here; ignore it so a
    # genuinely fresh target still counts as empty.
    contents = [p for p in vault_root.iterdir() if p.name != ".arvyx"] if vault_root.exists() else []
    if contents:
        if (vault_root / VAULT_MARKER).is_file():
            raise ValueError(
                f"refusing to sync into {vault_root}: it looks like a primary vault "
                f"(has {VAULT_MARKER} but no {REPLICA_MARKER})"
            )
        raise ValueError(f"refusing to sync into non-empty directory without {REPLICA_MARKER}: {vault_root}")
    _mark_sync_incomplete(vault_root, source_url)
    _durable_write(marker, f"replica-of: {source_url}\n".encode("utf-8"))


def _replica_target_path(vault_root: Path, relative: str) -> Path:
    _source_parts(relative)
    target = vault_root / relative
    # Do not resolve aliases, even if they stay within the vault. An internal
    # alias can target the local lock/status/journal authority excluded on wire.
    try:
        with _destination_parent(target) as parent_fd:
            _destination_leaf(parent_fd, target.name)
    except FileNotFoundError:
        pass
    return target


def _manifest_state_size(meta: Any, *, label: str) -> int:
    size = meta.get("size") if isinstance(meta, dict) else None
    if type(size) is not int or not 0 <= size <= MAX_REPLICA_FILE_BYTES:
        raise ValueError(f"replica manifest entry has invalid bounded size: {label}")
    return size


def _manifest_sha256(meta: Any, *, label: str) -> str:
    if not isinstance(meta, dict):
        raise ValueError(f"replica manifest entry missing metadata: {label}")
    expected = meta.get("sha256")
    if not isinstance(expected, str) or SHA256_HEX.fullmatch(expected) is None:
        raise ValueError(f"replica manifest entry missing sha256: {label}")
    return expected


def _get_json(url: str, token: str | None, timeout: float) -> dict[str, Any]:
    if not is_http_url(url):
        raise ValueError(f"refusing non-http(s) replica source: {url}")
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, headers=headers, method="GET")
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310 - operator-configured source
            limit = 12 * 1024 * 1024  # accommodates an 8-MiB base64 file plus bounded JSON metadata
            data = response.read(limit + 1)
            if len(data) > limit:
                raise ValueError("replica response exceeds limit")
            payload = json.loads(data.decode("utf-8"))
    except HTTPError as exc:
        # The status is sufficient; upstream error bodies are untrusted and
        # unnecessary (and may stream indefinitely or echo credentials).
        exc.close()
        raise ValueError(f"replica source returned HTTP {exc.code}") from None
    except URLError as exc:
        raise ValueError(f"replica source unreachable: {exc.reason}") from exc
    if not isinstance(payload, dict):
        raise ValueError("replica source returned non-object JSON")
    body = payload.get("body")
    return body if isinstance(body, dict) else payload


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _durable_mkdir(path: Path) -> None:
    if not path.exists():
        _durable_mkdir(path.parent)
        path.mkdir(exist_ok=True)
    # Also persist directories created by the lock setup before this helper.
    _fsync_directory(path)
    _fsync_directory(path.parent)


def _durable_write(path: Path, data: bytes) -> None:
    with _destination_parent(path, create=True) as parent_fd:
        _destination_leaf(parent_fd, path.name)
        name = '.replica-' + os.urandom(16).hex()
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
        try:
            with os.fdopen(fd, 'wb') as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            _destination_leaf(parent_fd, path.name)
            os.replace(name, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            try:
                os.unlink(name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass


@contextmanager
def _destination_parent(path: Path, *, create=False):
    absolute = path.absolute()
    if '..' in absolute.parts:
        raise ValueError('replica destination traversal refused')
    with ExitStack() as stack:
        fd = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stack.callback(os.close, fd)
        for part in absolute.parts[1:-1]:
            if create:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                os.fsync(fd)
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            stack.callback(os.close, fd)
        yield fd


def _destination_leaf(parent_fd, name):
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('replica destination must be an unaliased regular file')
    return info


def _destination_matches(path, expected):
    try:
        with _destination_parent(path) as parent_fd:
            before = _destination_leaf(parent_fd, path.name)
            if before is None:
                return False
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
            with os.fdopen(fd, 'rb') as handle:
                info = os.fstat(handle.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not os.path.samestat(before, info):
                    raise ValueError('replica destination identity changed')
                data = handle.read(MAX_REPLICA_FILE_BYTES + 1)
                if len(data) > MAX_REPLICA_FILE_BYTES or hashlib.sha256(data).hexdigest() != expected:
                    return False
                os.fsync(handle.fileno())
            os.fsync(parent_fd)
            return True
    except FileNotFoundError:
        return False


def _destination_inventory(root):
    """Refuse aliases also on unchanged/deletion-only paths, before metadata writes."""
    files = []
    def walk(fd, prefix=''):
        for name in sorted(os.listdir(fd)):
            relative = prefix + name
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    walk(child, relative + '/')
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                files.append(relative)
            else:
                raise ValueError('replica destination alias or special file refused')
    with _source_root(root) as root_fd:
        walk(root_fd)
    return files


def _mark_sync_incomplete(vault_root: Path, source_url: str) -> None:
    _durable_mkdir(vault_root)
    _durable_write(vault_root / REPLICA_STATUS, (
        json.dumps({"source": source_url, "sync_complete": False}, sort_keys=True) + "\n"
    ).encode("utf-8"))
