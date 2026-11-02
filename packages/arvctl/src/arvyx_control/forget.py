"""Governed soft forget / restore for exact curated memory sources.

Crash-safety contract: a fsynced staged inode and request-bound intent precede
archive/restore-target publication. Exclusive hard-link publication retains the
staged inode as an identity witness so replay can reconcile an exact published
file, but never adopt an unrelated existing file (even identical bytes).
Forget publishes archive, tombstone, removes the source, then writes its receipt.
Restore publishes its target, then writes its receipt. Interrupted operations
resume under the existing vault lock; ordinary failures retain recovery state.
The receipt denotes completion, not merely intent. Restore witnesses are retired
only after durable completion; completed replay repeats the cleanup barrier.

Accepted risk (archive authenticity): the forgotten archive and its tombstone
live in the vault's excluded lane (``excluded/forgotten/``). Their integrity is
protected by the sha256 recorded in the tombstone and receipt, and their
authenticity relies on vault-level access control (filesystem permissions on
the vault root plus the governed API/MCP scope ``memory.curate``). An attacker
who can write arbitrary bytes inside the vault could forge a matching archive
and tombstone. We deliberately accept this risk instead of introducing an
HMAC key authority: the vault has no existing on-disk secret lane usable
without new key-management infrastructure, and anyone able to rewrite vault
files can equally rewrite curated memory itself, so an archive HMAC would add
a key-management surface without raising the effective trust boundary.
Restore still refuses any archive whose sha256 does not match the tombstone,
so accidental corruption is always caught.

Symlink TOCTOU: every read or removal of a vault file in this module opens
with ``O_NOFOLLOW``, verifies via ``fstat``/``lstat`` that the target is a
regular file, and verifies the path stays inside the vault root.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat as stat_module
import uuid

from .promotion_transaction import memory_mutation
from .forget_guard import assert_copyable_forget_operations, _read_regular_nofollow
from .filesystem import fsync_directory
from .paths import resolve_under, validate_project_id
from .security import contains_literal_secret

REASON_CATEGORIES = ("incorrect", "superseded", "privacy", "retention", "other")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{15,255}$")


@dataclass(frozen=True)
class ForgetResult:
    source_path: str
    archive_path: str
    tombstone_path: str
    reason_category: str
    batch_id: str
    actor: str
    idempotency_key: str
    status: str
    content_sha256: str

    def to_dict(self) -> dict[str, str]:
        return dict(self.__dict__)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass(frozen=True)
class RestoreResult:
    source_path: str
    archive_path: str
    tombstone_path: str
    actor: str
    idempotency_key: str
    status: str
    content_sha256: str

    def to_dict(self) -> dict[str, str]:
        return dict(self.__dict__)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def soft_forget(
    vault: Path,
    project: str,
    source_path: str,
    reason_category: str,
    batch_id: str,
    actor: str,
    idempotency_key: str,
    dry_run: bool = False,
) -> ForgetResult:
    root = vault.resolve()
    project = validate_project_id(project)
    _curated_candidate(root, project, source_path)
    reason_category = reason_category.strip()
    if reason_category not in REASON_CATEGORIES:
        raise ValueError(f"reason category must be one of: {', '.join(REASON_CATEGORIES)}")
    batch_id = _validate_id("batch_id", batch_id)
    actor = _validate_id("actor", actor)
    idempotency_key = _validate_key(idempotency_key)
    request = {
        "operation": "forget",
        "source_path": source_path,
        "reason_category": reason_category,
        "batch_id": batch_id,
        "actor": actor,
        "idempotency_key": idempotency_key,
        "dry_run": dry_run,
    }
    request_hash = _digest_json(request)
    with memory_mutation(root, forget_recovery=(idempotency_key, request_hash)):
        existing = _read_operation(root, idempotency_key, request_hash)
        if existing is not None:
            if existing["request_hash"] != request_hash:
                raise ValueError("idempotency key was already used for a different request")
            return ForgetResult(**existing["result"])

        source = _curated_candidate(root, project, source_path)
        if source.suffix.lower() != ".md":
            raise FileNotFoundError(source_path)
        token = hashlib.sha256(f"{batch_id}\0{source_path}".encode()).hexdigest()[:24]
        archive_rel = f"excluded/forgotten/{batch_id}/{token}.original"
        tombstone_rel = f"excluded/forgotten/{batch_id}/{token}.tombstone.json"
        status = "dry-run" if dry_run else "forgotten"
        tombstone = resolve_under(root, *tombstone_rel.split("/")[:-1]) / tombstone_rel.split("/")[-1]
        if _lexists_regular(source):
            digest = hashlib.sha256(_read_regular_nofollow(source, root)).hexdigest()
        elif not dry_run and _lexists_regular(tombstone):
            # Crash-window resume: the source is already gone but a tombstone for
            # this exact target exists; take the recorded digest and let the
            # following resume checks verify archive integrity before replaying.
            recorded = json.loads(_read_regular_nofollow(tombstone, root).decode("utf-8"))
            digest = str(recorded.get("content_sha256", ""))
        else:
            raise FileNotFoundError(source_path)
        result = ForgetResult(source_path, archive_rel, tombstone_rel, reason_category, batch_id, actor, idempotency_key, status, digest)
        if dry_run:
            return result

        archive = resolve_under(root, *archive_rel.split("/")[:-1]) / archive_rel.split("/")[-1]
        operation = _operation_path(root, idempotency_key)
        metadata = {
            **result.to_dict(),
            "operation": "memory.forget",
            "excluded_from_recall": True,
            "original_retained": True,
        }

        source_exists = _lexists_regular(source)
        tombstone_exists = _lexists_regular(tombstone)
        if (os.path.lexists(source) and not source_exists) or (os.path.lexists(tombstone) and not tombstone_exists):
            raise ValueError("refusing non-regular forget source or tombstone")

        if not source_exists:
            # Crash-window resume: source already removed by an earlier
            # interrupted attempt. Require a matching tombstone + archive,
            # persist the (possibly missing) receipt, and replay.
            if not tombstone_exists:
                raise FileNotFoundError(source_path)
            _verify_resume_state(root, tombstone, archive, metadata)
            metadata["forgotten_at"] = _read_forgotten_at(root, tombstone)
            _fsync_dir(source.parent)
            _atomic_json(operation, {"request_hash": request_hash, "result": result.to_dict()})
            return result

        digest_now = hashlib.sha256(_read_regular_nofollow(source, root)).hexdigest()
        if digest_now != digest:
            # Content changed since the earlier locked read; keep the
            # receipt bound to the bytes we actually archive.
            digest = digest_now
            result = ForgetResult(source_path, archive_rel, tombstone_rel, reason_category, batch_id, actor, idempotency_key, status, digest)
            metadata = {
                **result.to_dict(),
                "operation": "memory.forget",
                "excluded_from_recall": True,
                "original_retained": True,
            }
        metadata["forgotten_at"] = _now()

        if tombstone_exists:
            # Half-completed earlier attempt (archive/tombstone durable, source
            # still present): verify it matches this exact request, then finish.
            _verify_resume_state(root, tombstone, archive, metadata)
            source.unlink()
            _fsync_dir(source.parent)
            _atomic_json(operation, {"request_hash": request_hash, "result": result.to_dict()})
            return result

        # Keep a durable staged inode and request binding BEFORE publishing
        # the archive. A hard crash cannot run exception rollback.
        _publish_bound_file(root, idempotency_key, request_hash, result.to_dict(),
                            archive, _read_regular_nofollow(source, root))
        _atomic_json(tombstone, metadata)
        # Archive + tombstone are durable; only now remove the source, and
        # write the receipt last so a stored receipt implies removal happened.
        if not _lexists_regular(source):
            raise ValueError(f"source changed underneath forget: {source_path}")
        source.unlink()
        _fsync_dir(source.parent)
        _atomic_json(operation, {"request_hash": request_hash, "result": result.to_dict()})
        return result


def restore_forgotten(
    vault: Path,
    tombstone_path: str,
    actor: str,
    idempotency_key: str,
) -> RestoreResult:
    root = vault.resolve()
    actor = _validate_id("actor", actor)
    idempotency_key = _validate_key(idempotency_key)
    request_hash = _digest_json({
        "operation": "restore",
        "tombstone_path": tombstone_path,
        "actor": actor,
        "idempotency_key": idempotency_key,
    })
    with memory_mutation(root, forget_recovery=(idempotency_key, request_hash)):
        tombstone = _resolve_tombstone(root, tombstone_path)
        metadata = json.loads(_read_regular_nofollow(tombstone, root).decode("utf-8"))
        source_path = str(metadata.get("source_path", ""))
        project_parts = PurePosixPath(source_path).parts
        if len(project_parts) < 3 or project_parts[0] != "projects":
            raise ValueError("tombstone has invalid curated source path")
        project = validate_project_id(project_parts[1])
        target = _curated_candidate(root, project, source_path)
        archive_path = str(metadata.get("archive_path", ""))
        archive_parts = PurePosixPath(archive_path).parts
        if not archive_parts:
            raise ValueError("tombstone has invalid archive path")
        archive = resolve_under(root, *archive_parts[:-1]) / archive_parts[-1]
        digest = str(metadata.get("content_sha256", ""))
        try:
            archive_bytes = _read_regular_nofollow(archive, root)
        except FileNotFoundError as exc:
            raise ValueError("forgotten archive is missing or its checksum does not match") from exc
        if hashlib.sha256(archive_bytes).hexdigest() != digest:
            raise ValueError("forgotten archive is missing or its checksum does not match")
        existing = _read_operation(root, idempotency_key, request_hash)
        if existing is not None:
            if existing["request_hash"] != request_hash:
                raise ValueError("idempotency key was already used for a different request")
            _retire_restore_witness(root, idempotency_key, existing)
            return RestoreResult(**existing["result"])
        result = RestoreResult(source_path, archive_path, tombstone_path, actor, idempotency_key, "restored", digest)
        # Re-verify the archive before publication, still under the same lock.
        try:
            archive_bytes = _read_regular_nofollow(archive, root)
        except FileNotFoundError as exc:
            raise ValueError("forgotten archive is missing or its checksum does not match") from exc
        if hashlib.sha256(archive_bytes).hexdigest() != digest:
            raise ValueError("forgotten archive is missing or its checksum does not match")
        _publish_bound_file(root, idempotency_key, request_hash, result.to_dict(),
                            target, archive_bytes)
        _atomic_json(
            _operation_path(root, idempotency_key),
            {"request_hash": request_hash, "result": result.to_dict()},
        )
        _retire_restore_witness(root, idempotency_key,
                                {"request_hash": request_hash, "result": result.to_dict()})
        return result


def _retire_restore_witness(root: Path, key: str, receipt: dict[str, object]) -> None:
    """Caller holds the vault lock and has synchronized the completion receipt.

    Keep the intent as a cleanup journal. Missing witnesses still require their
    parent barrier on replay, covering death after unlink but before fsync.
    Never touch the final target: it may have changed since completed restore.
    Completed copies retain receipt authority, never the old inode authority.
    """
    intent_path = _operation_path(root, key).with_suffix(".intent.json")
    if not os.path.lexists(intent_path):
        return  # Legacy receipts need no inode witness to replay.
    intent = json.loads(_read_regular_nofollow(intent_path, root))
    if receipt != {"request_hash": intent.get("request_hash"), "result": intent.get("result")}:
        raise ValueError("restore completion receipt does not match intent")
    result = receipt["result"]
    source_path = result["source_path"]
    parts = PurePosixPath(source_path).parts
    if result.get("status") != "restored" or len(parts) < 3:
        raise ValueError("invalid restore cleanup receipt")
    final = _curated_candidate(root, validate_project_id(parts[1]), source_path)
    stage = _intent_stage(root, final, intent)
    if os.path.lexists(stage):
        info = os.lstat(stage)
        if (stat_module.S_ISREG(info.st_mode)
                and (info.st_dev, info.st_ino) == (intent["device"], intent["inode"])):
            if hashlib.sha256(_read_regular_nofollow(stage, root)).hexdigest() != result["content_sha256"]:
                raise ValueError("restore cleanup staging checksum does not match")
            stage.unlink()
        # A copy or unrelated replacement is not ours to remove. The durable
        # receipt already completed this operation; do not adopt/re-publish it.
    _fsync_dir(stage.parent)


def _intent_stage(root: Path, final: Path, intent: dict[str, object]) -> Path:
    """Accept bounded new stages and exact legacy UUID witnesses on replay."""
    relative = intent.get("stage_path")
    if (not isinstance(relative, str) or "\\" in relative
            or PurePosixPath(relative).is_absolute()
            or relative != PurePosixPath(relative).as_posix()
            or ".." in PurePosixPath(relative).parts):
        raise ValueError("operation intent has an invalid staging path")
    stage = root / relative
    legacy = re.escape(f".{final.name}.") + r"[0-9a-f]{32}\.stage"
    if (intent.get("publication_path") != final.relative_to(root).as_posix()
            or stage.parent != final.parent
            or re.fullmatch(r"\.forget-[0-9a-f]{32}\.stage|" + legacy, stage.name) is None):
        raise ValueError("operation intent has an invalid staging path")
    resolve_under(root, *stage.relative_to(root).parts)
    return stage


def _publish_bound_file(
    root: Path, key: str, request_hash: str, result: dict[str, str],
    final: Path, payload: bytes,
) -> None:
    """Under vault_lock, publish/reconcile only the inode owned by this intent.

    Retain the staging hard link as an identity witness (not just a checksum).
    Even an unrelated existing file with identical bytes must be refused.
    Restore retires its witness only after the completion receipt is durable.
    Forget witnesses and all intents remain for recovery bookkeeping.
    """
    relative = final.relative_to(root)
    resolve_under(root, *relative.parts)  # containment before any write
    intent_path = _operation_path(root, key).with_suffix(".intent.json")
    if os.path.lexists(intent_path):
        intent = json.loads(_read_regular_nofollow(intent_path, root))
        if intent.get("request_hash") != request_hash or intent.get("result") != result:
            raise ValueError("idempotency key was already used for a different request or content")
        if intent.get("publication_path") != final.relative_to(root).as_posix():
            raise ValueError("operation intent has a conflicting publication path")
        stage = _intent_stage(root, final, intent)
    else:
        if os.path.lexists(final):
            raise ValueError(f"refusing unrelated existing publication target: {final}")
        final.parent.mkdir(parents=True, exist_ok=True)
        intent_path.parent.mkdir(parents=True, exist_ok=True)
        # Persist newly created directory entries all the way to the vault.
        for directory in (final.parent, intent_path.parent):
            while directory != root:
                _fsync_dir(directory)
                directory = directory.parent
            _fsync_dir(root)
        stage = final.with_name(f".forget-{uuid.uuid4().hex}.stage")
        fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
            info = os.fstat(handle.fileno())
        _fsync_dir(stage.parent)
        intent = {
            "request_hash": request_hash, "result": result,
            "publication_path": final.relative_to(root).as_posix(),
            "stage_path": stage.relative_to(root).as_posix(),
            "device": info.st_dev, "inode": info.st_ino,
        }
        _atomic_json(intent_path, intent)

    staged_bytes = _read_regular_nofollow(stage, root)
    info = os.lstat(stage)
    if (not stat_module.S_ISREG(info.st_mode)
            or (info.st_dev, info.st_ino) != (intent["device"], intent["inode"])
            or staged_bytes != payload
            or hashlib.sha256(staged_bytes).hexdigest() != result["content_sha256"]):
        raise ValueError("operation staging identity or checksum does not match")
    _fsync_dir(intent_path.parent)
    if not os.path.lexists(final):
        # Exclusive publication: never replace a file which appeared meanwhile.
        os.link(stage, final, follow_symlinks=False)
    published = os.lstat(final)
    if (not stat_module.S_ISREG(published.st_mode)
            or (published.st_dev, published.st_ino) != (info.st_dev, info.st_ino)
            or _read_regular_nofollow(final, root) != staged_bytes):
        raise ValueError("refusing unrelated existing publication target")
    # Also covers death after link() but before directory fsync/receipt.
    _fsync_dir(final.parent)


def _curated_candidate(root: Path, project: str, source_path: str) -> Path:
    if not isinstance(source_path, str) or "\\" in source_path or source_path.startswith("/"):
        raise ValueError("source_path must be an exact vault-relative POSIX path")
    parts = PurePosixPath(source_path).parts
    # PurePosixPath collapses dot and empty components. Validate the literal
    # spelling first so request hashes, tombstones and actual targets agree.
    if source_path != PurePosixPath(source_path).as_posix():
        raise ValueError("source_path must be an exact canonical vault-relative POSIX path")
    if any(part in {"", ".", ".."} for part in source_path.split("/")):
        raise ValueError("source_path traversal is not allowed")
    if len(parts) < 3 or parts[:2] != ("projects", project):
        raise ValueError(f"source_path must be an exact curated path for project {project}")
    relative = parts[2:]
    if relative[0] in {"pending", "refining", "raw", "archive", "imported"}:
        raise ValueError("source_path must identify curated memory, not an excluded or imported lane")
    # Join lexically (parts are already traversal-free) instead of resolve():
    # resolve() would silently rewrite a symlinked final component to its
    # target, letting a symlink masquerade as a curated source. Symlink and
    # regular-file status is then checked with lstat by the caller.
    return root.joinpath(*parts)


def _resolve_tombstone(root: Path, source_path: str) -> Path:
    if (not isinstance(source_path, str) or "\\" in source_path
            or source_path.startswith("/")
            or source_path != PurePosixPath(source_path).as_posix()
            or any(part in {"", ".", ".."} for part in source_path.split("/"))):
        raise ValueError("tombstone_path must be an exact vault-relative POSIX path")
    parts = PurePosixPath(source_path).parts
    if len(parts) != 4 or parts[:2] != ("excluded", "forgotten") or not parts[-1].endswith(".tombstone.json"):
        raise ValueError("tombstone_path must be an exact excluded/forgotten tombstone path")
    path = resolve_under(root, *parts[:-1]) / parts[-1]
    if not _lexists_regular(path):
        raise FileNotFoundError(source_path)
    return path


def _validate_id(label: str, value: str) -> str:
    normalized = value.strip()
    if not _ID_RE.fullmatch(normalized):
        raise ValueError(f"{label} must be 3-128 safe identifier characters")
    return normalized


def _validate_key(value: str) -> str:
    normalized = value.strip()
    if contains_literal_secret(normalized):
        raise ValueError("idempotency_key contains a secret-shaped string")
    if not _KEY_RE.fullmatch(normalized):
        raise ValueError("idempotency_key must be 16-256 safe identifier characters")
    return normalized


def _operation_path(root: Path, key: str) -> Path:
    name = hashlib.sha256(key.encode()).hexdigest() + ".json"
    parent = resolve_under(root, ".arvyx", "forget-operations")
    return parent / name


def _read_operation(root: Path, key: str, request_hash: str | None = None) -> dict[str, object] | None:
    path = _operation_path(root, key)
    intent_path = path.with_suffix(".intent.json")
    if request_hash is not None and os.path.lexists(intent_path):
        intent = json.loads(_read_regular_nofollow(intent_path, root))
        if intent.get("request_hash") != request_hash:
            raise ValueError("idempotency key was already used for a different request")
    if not os.path.lexists(path):
        return None
    receipt = json.loads(_read_regular_nofollow(path, root))
    # A visible rename is not proof its directory barrier succeeded. Repeat
    # that barrier on every completed replay before acknowledging success,
    # including legacy receipts without a retained publication intent.
    _fsync_dir(path.parent)
    return receipt



def _lexists_regular(path: Path) -> bool:
    """True only for an existing regular file (never a symlink or directory)."""
    try:
        return stat_module.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False



def _unlink_if_hash_matches(root: Path, path: Path, digest: str) -> None:
    """Remove a rollback target only while its content still matches digest."""
    try:
        if hashlib.sha256(_read_regular_nofollow(path, root)).hexdigest() == digest:
            path.unlink(missing_ok=True)
    except (OSError, ValueError):
        pass


def _unlink_temp_siblings(directory: Path) -> None:
    try:
        entries = list(directory.iterdir())
    except OSError:
        return
    for entry in entries:
        if entry.name.startswith(".") and entry.name.endswith(".tmp"):
            entry.unlink(missing_ok=True)


def _fsync_dir(path: Path) -> None:
    fsync_directory(path)


def _atomic_write_bytes_via(temporary: Path, final: Path, payload: bytes) -> None:
    final.parent.mkdir(parents=True, exist_ok=True)
    with open(temporary, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, final)
    _fsync_dir(final.parent)


def _atomic_write_bytes(final: Path, payload: bytes) -> None:
    temporary = final.with_name(f".{final.name}.{uuid.uuid4().hex}.tmp")
    try:
        _atomic_write_bytes_via(temporary, final, payload)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_json(path: Path, payload: dict[str, object]) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        _atomic_write_bytes_via(temporary, path, (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    finally:
        temporary.unlink(missing_ok=True)


def _verify_resume_state(root: Path, tombstone: Path, archive: Path, metadata: dict[str, object]) -> None:
    """Verify a half-completed forget matches this exact request before
    resuming: tombstone fields equal and archive sha256 equals the recorded
    digest. Anything else is a conflicting prior operation."""
    recorded = json.loads(_read_regular_nofollow(tombstone, root).decode("utf-8"))
    for key, value in metadata.items():
        if key == "forgotten_at":
            continue
        if recorded.get(key) != value:
            raise ValueError("forget archive target already exists for a different request")
    if not _lexists_regular(archive):
        raise ValueError("forget tombstone exists but its archive is missing")
    if hashlib.sha256(_read_regular_nofollow(archive, root)).hexdigest() != metadata["content_sha256"]:
        raise ValueError("forget archive checksum does not match its tombstone")
    _fsync_dir(archive.parent)
    _fsync_dir(tombstone.parent)


def _read_forgotten_at(root: Path, tombstone: Path) -> str:
    recorded = json.loads(_read_regular_nofollow(tombstone, root).decode("utf-8"))
    return str(recorded.get("forgotten_at", ""))


def _digest_json(payload: dict[str, object]) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
