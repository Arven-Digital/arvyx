from __future__ import annotations

import argparse
import copy
from functools import wraps
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "arvctl" / "src"))

from arvyx_control.audit_log import verify_chain  # noqa: E402
from arvyx_control.control import read_events  # noqa: E402


MARKER_TEXT = "arvyx-vault-format: 1"
STAGED_SECRET_BASENAME = ".arvyx-control-secret"
RESTORE_BINDING_SCHEMA = "arvyx-restore-binding/v1"
RESTORE_BINDING_PURPOSE = b"arvyx:restore-binding:v1\0"


class RestoreCleanupRequired(RuntimeError):
    """A failed restore retained candidate resources that require operator cleanup."""


class VolumePointerPublicationDurabilityError(RuntimeError):
    """The pointer was replaced, but parent-directory durability was not proven."""


class VolumePointerReconciliationRequired(RuntimeError):
    """Durable volume pointer needs reconciliation; both volumes must be retained."""

    candidate_volume: str
    previous_volume: str
    cleanup_failures: tuple[str, ...]
    restart_failed: bool
    restart_blocked: bool


_STAGE_SPEC = importlib.util.spec_from_file_location(
    "stage_control_secret", ROOT / "scripts" / "stage_control_secret.py"
)
assert _STAGE_SPEC is not None and _STAGE_SPEC.loader is not None
_stage_control_secret_module = importlib.util.module_from_spec(_STAGE_SPEC)
_STAGE_SPEC.loader.exec_module(_stage_control_secret_module)


def _stage_current_control_secret(
    *, secret_file: Path, volume: str, image: str, env: dict[str, str]
) -> None:
    _stage_control_secret_module.stage_control_secret(
        secret_file=secret_file,
        volume=volume,
        image=image,
        env=env,
    )


def _run(command: list[str], *, env: dict[str, str], check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, check=check)


def _attempt_cleanup(
    command: list[str], *, env: dict[str, str], label: str
) -> str | None:
    try:
        completed = _run(command, env=env, check=False)
    except Exception as exc:
        return f"{label} raised {type(exc).__name__}"
    returncode = getattr(completed, "returncode", 0)
    if isinstance(returncode, int) and returncode != 0:
        return f"{label} exited {returncode}"
    return None


def _compose(project: str, *, override: Path | None = None) -> list[str]:
    command = ["docker", "compose", "-p", project]
    if override is not None:
        command.extend(["-f", str(ROOT / "docker-compose.yml"), "-f", str(override)])
    return command


def _read_active_volume_pointer(env_file: Path) -> str:
    try:
        if not env_file.is_file() or env_file.is_symlink():
            raise VolumePointerReconciliationRequired(
                "volume pointer reconciliation required: .env is not a regular file; retain both volumes"
            )
        lines = env_file.read_text(encoding="utf-8").splitlines()
    except VolumePointerReconciliationRequired:
        raise
    except (OSError, UnicodeError) as exc:
        raise VolumePointerReconciliationRequired(
            "volume pointer reconciliation required: .env could not be read; retain both volumes"
        ) from exc
    values = [
        line.removeprefix("ARVYX_DATA_VOLUME=")
        for line in lines
        if line.startswith("ARVYX_DATA_VOLUME=")
    ]
    if len(values) != 1 or not values[0]:
        raise VolumePointerReconciliationRequired(
            "volume pointer reconciliation required: ARVYX_DATA_VOLUME is ambiguous; retain both volumes"
        )
    return values[0]


def _fsync_parent_directory(path: Path) -> None:
    if os.name == "nt" or not hasattr(os, "O_DIRECTORY"):
        return
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _atomic_update_active_volume(env_file: Path, *, previous: str, candidate: str) -> None:
    if not env_file.is_file() or env_file.is_symlink():
        raise RuntimeError("restore requires a regular existing .env file for atomic cutover")
    text = env_file.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    matches = [index for index, line in enumerate(lines) if line.startswith("ARVYX_DATA_VOLUME=")]
    if len(matches) != 1 or lines[matches[0]].strip() != f"ARVYX_DATA_VOLUME={previous}":
        raise RuntimeError(".env ARVYX_DATA_VOLUME does not match the inspected production volume")
    newline = "\r\n" if lines[matches[0]].endswith("\r\n") else "\n"
    lines[matches[0]] = f"ARVYX_DATA_VOLUME={candidate}{newline}"
    temporary = env_file.with_name(f".{env_file.name}.restore-{secrets.token_hex(8)}")
    mode = env_file.stat().st_mode & 0o777
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        descriptor = os.open(temporary, flags, mode or 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write("".join(lines))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, env_file)
        try:
            _fsync_parent_directory(env_file)
        except OSError as exc:
            raise VolumePointerPublicationDurabilityError(
                f"volume pointer publication durability failed after replace: {exc}"
            ) from exc
    finally:
        temporary.unlink(missing_ok=True)


def _rollback_active_volume_pointer(
    env_file: Path, *, previous_volume: str, candidate_volume: str
) -> None:
    current = _read_active_volume_pointer(env_file)
    if current not in {previous_volume, candidate_volume}:
        raise VolumePointerReconciliationRequired(
            "volume pointer reconciliation required: .env names neither retained volume; retain both volumes"
        )
    try:
        _atomic_update_active_volume(
            env_file,
            # Even an already restored value may be the visible result of an
            # earlier failed directory barrier. Re-publish it durably before up.
            previous=current,
            candidate=previous_volume,
        )
    except Exception as exc:
        raise VolumePointerReconciliationRequired(
            "volume pointer reconciliation required: rollback durability is ambiguous; retain both volumes"
        ) from exc
    if _read_active_volume_pointer(env_file) != previous_volume:
        raise VolumePointerReconciliationRequired(
            "volume pointer reconciliation required: rollback verification failed; retain both volumes"
        )


def _acceptance_probe(compose: list[str], env: dict[str, str], *, operation_key: str) -> None:
    if re.fullmatch(r"[A-Za-z0-9._:-]{16,256}", operation_key) is None:
        raise RuntimeError("restore acceptance operation key is invalid")
    probe = ROOT / "scripts" / "restore_acceptance_probe.py"
    completed = subprocess.run(
        [
            *compose,
            "exec",
            "-T",
            "arvyx-server",
            "env",
            f"ARVYX_RESTORE_OPERATION_KEY={operation_key}",
            "python",
            "-",
        ],
        cwd=ROOT,
        env=env,
        input=probe.read_text(encoding="utf-8"),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    if completed.stdout.strip() != "restore-acceptance-ok":
        raise RuntimeError("restore acceptance probe did not complete")


def _expected_data_volume(env: dict[str, str], project: str) -> str:
    value = env.get("ARVYX_DATA_VOLUME", "").strip()
    deployment_id = env.get("ARVYX_DEPLOYMENT_ID", "").strip()
    if (
        re.fullmatch(r"[a-z0-9][a-z0-9-]{7,31}", deployment_id) is None
        or deployment_id.startswith("change-me")
    ):
        raise RuntimeError("ARVYX_DEPLOYMENT_ID must be a unique 8-32 character deployment identifier")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value):
        raise RuntimeError("ARVYX_DATA_VOLUME must be explicitly configured with a safe name")
    if not value.startswith(f"{project}_{deployment_id}_"):
        raise RuntimeError("ARVYX_DATA_VOLUME must be scoped to COMPOSE_PROJECT_NAME and ARVYX_DEPLOYMENT_ID")
    return value


def _assert_data_volume(container_id: str, expected: str, project: str, env: dict[str, str]) -> None:
    inspection = json.loads(_run(["docker", "inspect", container_id], env=env).stdout)
    if len(inspection) != 1:
        raise RuntimeError("container inspection did not return one object")
    mounts = inspection[0].get("Mounts") or []
    matching = [
        mount
        for mount in mounts
        if mount.get("Destination") == "/data" and mount.get("Type") == "volume"
    ]
    if len(matching) != 1 or matching[0].get("Name") != expected:
        raise RuntimeError("container /data mount does not match ARVYX_DATA_VOLUME")
    volume = json.loads(_run(["docker", "volume", "inspect", expected], env=env).stdout)
    if len(volume) != 1:
        raise RuntimeError("volume inspection did not return one object")
    labels = volume[0].get("Labels") or {}
    if labels.get("com.docker.compose.project") != project:
        raise RuntimeError("data volume Compose project label does not match")
    if labels.get("com.docker.compose.volume") != "arvyx-data":
        raise RuntimeError("data volume logical label does not match")


def _verify_data(data: Path) -> None:
    if not data.is_dir() or data.is_symlink():
        raise RuntimeError("backup data root is not a regular directory")
    for path in data.rglob("*"):
        if path.is_symlink():
            raise RuntimeError("backup contains a symbolic link")
    marker = data / "vault" / ".arvyx-vault"
    if not marker.is_file() or marker.read_text(encoding="utf-8").strip() != MARKER_TEXT:
        raise RuntimeError("backup vault marker is missing or invalid")
    state = data / "control-events.jsonl"
    audit = data / "audit-log.jsonl"
    if state.exists():
        if not state.is_file():
            raise RuntimeError("backup state path is not a regular file")
        read_events(state)
    if audit.exists():
        if not audit.is_file() or not verify_chain(audit).ok:
            raise RuntimeError("backup audit chain is invalid")
    operation_store = data / "audit-log.jsonl.operations.sqlite3"
    if operation_store.exists():
        if not operation_store.is_file() or operation_store.is_symlink():
            raise RuntimeError("backup operation journal is not a regular file")
        try:
            connection = sqlite3.connect(f"file:{operation_store.as_posix()}?mode=ro", uri=True)
            try:
                integrity = connection.execute("PRAGMA integrity_check").fetchone()
                if integrity != ("ok",):
                    raise RuntimeError("backup operation journal integrity check failed")
                tables = {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
                if not {"operations", "audit_receipts"}.issubset(tables):
                    raise RuntimeError("backup operation journal schema is incomplete")
                invalid_operations = connection.execute(
                    "SELECT COUNT(*) FROM operations WHERE state NOT IN "
                    "('claimed','intent_durable','dispatching','outcome_pending','completed','rejected')"
                ).fetchone()[0]
                invalid_receipts = connection.execute(
                    "SELECT COUNT(*) FROM audit_receipts WHERE state NOT IN ('pending','written')"
                ).fetchone()[0]
                if invalid_operations or invalid_receipts:
                    raise RuntimeError("backup operation journal contains invalid states")
            finally:
                connection.close()
        except sqlite3.DatabaseError as exc:
            raise RuntimeError("backup operation journal is corrupt") from exc


def _validated_members(bundle: tarfile.TarFile) -> list[tarfile.TarInfo]:
    members = bundle.getmembers()
    if not members:
        raise RuntimeError("backup archive is empty")
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != "data":
            raise RuntimeError("backup archive contains an unsafe path")
        if not (member.isdir() or member.isfile()):
            raise RuntimeError("backup archive contains an unsafe entry type")
    return members


def _safe_extract(archive: Path, destination: Path) -> Path:
    with tarfile.open(archive, "r:gz") as bundle:
        for member in _validated_members(bundle):
            parts = PurePosixPath(member.name).parts
            target = destination.joinpath(*parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = bundle.extractfile(member)
            if source is None:
                raise RuntimeError("backup regular file has no payload")
            with source, target.open("xb") as output:
                shutil.copyfileobj(source, output)
            os.chmod(target, member.mode & 0o777)
    data = destination / "data"
    _verify_data(data)
    return data


def _container_tar(archive: Path, destination: Path) -> None:
    with tarfile.open(archive, "r:gz") as source, tarfile.open(destination, "w") as output:
        for member in _validated_members(source):
            parts = PurePosixPath(member.name).parts[1:]
            if not parts:
                continue
            copied = copy.copy(member)
            copied.name = PurePosixPath(*parts).as_posix()
            copied.pax_headers = {
                key: value for key, value in copied.pax_headers.items() if key not in {"path", "linkpath"}
            }
            payload = source.extractfile(member) if member.isfile() else None
            output.addfile(copied, payload)


def _normalize_container_archive(source: tarfile.TarFile, output: tarfile.TarFile) -> None:
    """Materialize only direct, validated in-archive regular hardlink targets."""
    def parts_for(name: str) -> tuple[str, ...]:
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or "\\" in name or "\0" in name:
            raise RuntimeError("container data stream contains an unsafe path")
        return path.parts

    members = source.getmembers()
    if not members:
        raise RuntimeError("container data stream is empty")
    indexed: dict[tuple[str, ...], tarfile.TarInfo] = {}
    for member in members:
        parts = parts_for(member.name)
        if parts in indexed or not (member.isdir() or member.isfile() or member.islnk()):
            raise RuntimeError("container data stream contains an unsafe or duplicate entry")
        if not parts and not member.isdir():
            raise RuntimeError("container data stream root is not a directory")
        indexed[parts] = member
    excluded_entry = (STAGED_SECRET_BASENAME,)
    for parts, member in indexed.items():
        for length in range(1, len(parts)):
            ancestor = indexed.get(parts[:length])
            if ancestor is not None and not ancestor.isdir():
                raise RuntimeError("container data stream traverses a non-directory")
        if parts == excluded_entry and not member.isfile():
            raise RuntimeError("excluded secret must be a regular archive entry")
        if parts[:1] == excluded_entry and parts != excluded_entry:
            raise RuntimeError("container data stream traverses the excluded secret")
        if member.islnk():
            target_parts = parts_for(member.linkname)
            target = indexed.get(target_parts)
            # No recursive resolution: chains, cycles, symlinks, absent and
            # excluded targets are invalid, irrespective of archive ordering.
            if (not target_parts or target_parts[:1] == excluded_entry
                    or target is None or not target.isfile()):
                raise RuntimeError("container data stream has an invalid hardlink target")
            for length in range(1, len(target_parts)):
                ancestor = indexed.get(target_parts[:length])
                if ancestor is not None and not ancestor.isdir():
                    raise RuntimeError("hardlink target traverses a non-directory")
    for parts, member in indexed.items():
        if not parts or parts == excluded_entry:
            continue
        copied = copy.copy(member)
        copied.name = (PurePosixPath("data") / PurePosixPath(*parts)).as_posix()
        copied.pax_headers = {
            key: value for key, value in copied.pax_headers.items()
            if key not in {"path", "linkpath", "size"}
        }
        payload_member = indexed[parts_for(member.linkname)] if member.islnk() else member
        if member.islnk():
            copied.type = tarfile.REGTYPE
            copied.linkname = ""
            copied.size = payload_member.size
        payload = source.extractfile(payload_member) if payload_member.isfile() else None
        if payload_member.isfile() and payload is None:
            raise RuntimeError("container regular file has no payload")
        try:
            output.addfile(copied, payload)
        finally:
            if payload is not None:
                payload.close()


def _capture_container_data(container_id: str, destination: Path, env: dict[str, str]) -> None:
    raw_archive = destination.with_suffix(".tar")
    # The service is stopped by backup(), but its volume must remain writable
    # for original-inode recovery. A one-shot, networkless helper owns the same
    # vault lock throughout recovery AND archive streaming. Never recover a copy.
    image = _run(
        ["docker", "inspect", "--format", "{{.Image}}", container_id], env=env
    ).stdout.strip()
    if re.fullmatch(r"sha256:[0-9a-f]{64}", image) is None:
        raise RuntimeError("backup source image identity is invalid")
    capture = (
        "from pathlib import Path\n"
        "import sys, tarfile\n"
        "from arvyx_control.snapshot_guard import snapshot_preparation\n"
        "with snapshot_preparation(Path('/data/vault')):\n"
        "    with tarfile.open(fileobj=sys.stdout.buffer, mode='w|') as archive:\n"
        "        archive.add('/data', arcname='.', recursive=True)\n"
    )
    try:
        with raw_archive.open("wb") as output:
            subprocess.run(
                ["docker", "run", "--rm", "--network", "none", "--read-only",
                 "--volumes-from", container_id, "--entrypoint", "python", image,
                 "-c", capture],
                cwd=ROOT,
                env=env,
                stdout=output,
                stderr=subprocess.PIPE,
                check=True,
            )
        with tarfile.open(raw_archive, "r:") as source, tarfile.open(destination, "w:gz") as output:
            _normalize_container_archive(source, output)
    finally:
        raw_archive.unlink(missing_ok=True)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _restore_binding_key(key_file: Path) -> bytes:
    """Read the binding key without following symlinks and without TOCTOU races.

    Symlinked secret mounts are intentionally rejected: secret managers must
    materialize a real regular file (see docs/vps-deployment.md). The file is
    opened with O_NOFOLLOW and validated via fstat on the descriptor, so the
    permission and regular-file checks cannot race with a path swap.
    """
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        descriptor = os.open(key_file, flags)
    except OSError as exc:
        raise RuntimeError("restore binding key must be a regular file") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError("restore binding key must be a regular file")
        if os.name != "nt" and info.st_mode & 0o077:
            raise RuntimeError("restore binding key permissions must be 0600 or stricter")
        chunks = []
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        key = b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(key) < 32:
        raise RuntimeError("restore binding key must contain at least 32 bytes")
    return key


_BINDING_IDENTITY_RE = re.compile(r"[a-z0-9][a-z0-9-]{7,63}")


def _binding_payload(*, archive: Path, authority_id: str, deployment_id: str) -> dict[str, str]:
    identity = _BINDING_IDENTITY_RE
    if identity.fullmatch(authority_id) is None:
        raise RuntimeError("restore binding authority ID is invalid")
    if identity.fullmatch(deployment_id) is None:
        raise RuntimeError("restore binding source deployment ID is invalid")
    return {
        "schema": RESTORE_BINDING_SCHEMA,
        "authority_id": authority_id,
        "source_deployment_id": deployment_id,
        "archive_name": archive.name,
        "archive_sha256": _sha256(archive),
    }


def _binding_mac(payload: dict[str, str], key: bytes) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(key, RESTORE_BINDING_PURPOSE + canonical, hashlib.sha256).hexdigest()


def _write_restore_binding(
    *, archive: Path, manifest: Path, authority_id: str, deployment_id: str, key_file: Path
) -> dict[str, str]:
    payload = _binding_payload(
        archive=archive, authority_id=authority_id, deployment_id=deployment_id
    )
    document = {**payload, "mac": _binding_mac(payload, _restore_binding_key(key_file))}
    manifest.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    os.chmod(manifest, 0o600)
    return document


def _verify_restore_binding(
    *, archive: Path, manifest: Path, authority_id: str, key_file: Path
) -> dict[str, str]:
    if not manifest.is_file() or manifest.is_symlink():
        raise RuntimeError("restore binding manifest is missing")
    try:
        document = json.loads(manifest.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise RuntimeError("restore binding manifest is invalid") from exc
    fields = {
        name: document.get(name)
        for name in ("schema", "authority_id", "source_deployment_id", "archive_name", "archive_sha256")
    }
    if not all(isinstance(value, str) for value in fields.values()):
        raise RuntimeError("restore binding manifest is incomplete")
    if fields["schema"] != RESTORE_BINDING_SCHEMA:
        raise RuntimeError("restore binding manifest version is unsupported")
    if fields["authority_id"] != authority_id:
        raise RuntimeError("restore binding target mismatch: archive belongs to a different authority")
    expected = _binding_mac(fields, _restore_binding_key(key_file))
    if not isinstance(document.get("mac"), str) or not secrets.compare_digest(document["mac"], expected):
        raise RuntimeError("restore binding manifest authentication failed")
    expected_payload = _binding_payload(
        archive=archive,
        authority_id=authority_id,
        deployment_id=fields["source_deployment_id"],
    )
    # Compare known fields explicitly so future optional payload fields do not
    # silently break verification of older manifests. The MAC above already
    # authenticates schema, authority_id, and source_deployment_id, which were
    # checked individually; archive_name and archive_sha256 tie the manifest to
    # this exact archive bytes-for-bytes.
    if (
        fields["archive_name"] != expected_payload["archive_name"]
        or fields["archive_sha256"] != expected_payload["archive_sha256"]
    ):
        raise RuntimeError("restore binding archive identity mismatch")
    return fields


def _restore_binding_config(env: dict[str, str]) -> tuple[str, Path]:
    authority_id = env.get("ARVYX_BACKUP_AUTHORITY_ID", "").strip()
    key_path = env.get("ARVYX_BACKUP_BINDING_KEY_FILE", "").strip()
    if not authority_id or not key_path:
        raise RuntimeError(
            "restore binding requires ARVYX_BACKUP_AUTHORITY_ID and ARVYX_BACKUP_BINDING_KEY_FILE"
        )
    return authority_id, Path(key_path)


def _write_checksum(archive: Path, checksum: Path) -> str:
    digest = _sha256(archive)
    checksum.write_text(f"{digest}  {archive.name}\n", encoding="ascii")
    os.chmod(checksum, 0o600)
    return digest


def _verify_checksum(archive: Path, checksum: Path) -> str:
    if not checksum.is_file():
        raise RuntimeError("backup checksum is missing")
    parts = checksum.read_text(encoding="ascii").strip().split()
    if len(parts) != 2 or parts[1] != archive.name or len(parts[0]) != 64:
        raise RuntimeError("backup checksum format is invalid")
    actual = _sha256(archive)
    if not secrets.compare_digest(parts[0].lower(), actual):
        raise RuntimeError("backup checksum mismatch")
    return actual


def _publish_off_host_atomic(archive: Path, checksum: Path, binding: Path | None, destination: Path) -> None:
    """Publish archive and sidecars in a crash-durable, archive-last sequence.

    Staged files are verified and fsynced before publication. Binding/checksum
    entries are published and the destination directory is fsynced before the
    archive is replaced; a second directory barrier persists the archive entry.
    This is ordered publication, not an atomic transaction across all entries:
    failures can leave sidecars, or an archive whose final durability is unknown.
    """
    # Persist each newly created directory entry separately, including any
    # missing ancestors. Syncing the destination itself cannot persist its name
    # in its parent directory.
    missing_directories: list[Path] = []
    current = destination
    while not current.exists():
        missing_directories.append(current)
        current = current.parent
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    if destination.is_symlink():
        raise RuntimeError("off-host destination must not be a symbolic link")
    for directory in reversed(missing_directories):
        _fsync_parent_directory(directory)
    suffix = secrets.token_hex(4)
    sources: list[Path] = [checksum, archive]
    if binding is not None:
        # Stage binding first so the manifest is never the file left uncommitted
        # while a visible archive already exists.
        sources.insert(0, binding)
    staged: list[tuple[Path, Path]] = []
    try:
        for source in sources:
            # Exclusively reserve a regular staging file; never follow a
            # pre-existing staging symlink, and own cleanup before copying.
            descriptor, temporary = tempfile.mkstemp(
                prefix=f".{source.name}.{suffix}.", suffix=".tmp", dir=destination
            )
            target = Path(temporary)
            staged.append((target, destination / source.name))
            try:
                if source.is_symlink():
                    raise RuntimeError("off-host backup source must not be a symbolic link")
                shutil.copy2(source, target, follow_symlinks=False)
                os.chmod(target, 0o600)
                if _sha256(target) != _sha256(source):
                    raise RuntimeError(f"off-host backup copy verification failed for {source.name}")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        # Persist sidecar entries in the ACTUAL destination directory before
        # making the archive visible. Passing destination itself would instead
        # sync destination.parent and would not order these renamed entries.
        for target, final in staged[:-1]:
            os.replace(target, final)
        _fsync_parent_directory(destination / archive.name)
        target, final = staged[-1]
        os.replace(target, final)
        _fsync_parent_directory(destination / archive.name)
    finally:
        for target, _ in staged:
            target.unlink(missing_ok=True)


def _enforce_retention(directory: Path, keep: int) -> None:
    if keep < 1:
        raise RuntimeError("retention must keep at least one backup")
    complete: list[Path] = []
    orphans: list[Path] = []
    archives = list(directory.glob("arvyx-backup-*.tar.gz"))
    for archive in archives:
        checksum = archive.with_name(f"{archive.name}.sha256")
        try:
            _verify_checksum(archive, checksum)
        except (OSError, RuntimeError, UnicodeError):
            orphans.append(archive)
        else:
            complete.append(archive)
    complete.sort(key=lambda path: path.stat().st_mtime, reverse=True)
    for archive in complete[keep:]:
        archive.unlink()
        archive.with_name(f"{archive.name}.sha256").unlink(missing_ok=True)
        archive.with_name(f"{archive.name}.binding.json").unlink(missing_ok=True)
    for archive in orphans:
        archive.unlink(missing_ok=True)
        archive.with_name(f"{archive.name}.sha256").unlink(missing_ok=True)
        archive.with_name(f"{archive.name}.binding.json").unlink(missing_ok=True)
    archive_names = {archive.name for archive in archives}
    for checksum in directory.glob("arvyx-backup-*.tar.gz.sha256"):
        if checksum.name.removesuffix(".sha256") not in archive_names:
            checksum.unlink(missing_ok=True)


def _deployment_serialized(operation: Callable[..., Any]) -> Callable[..., Any]:
    """Own the whole lifecycle on one stable inode, independent of volume/path.

    All public entrypoints acquire here, not in main or the shared helpers.
    Never unlink this file: waiters must continue locking the same inode.
    The fixed checkout lock deliberately serializes even different project names.
    """
    @wraps(operation)
    def locked(*args: Any, **kwargs: Any) -> Any:
        # Docker deployment operations require POSIX flock; fail closed elsewhere.
        import fcntl

        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
        descriptor = os.open(ROOT / ".backup-restore.deployment.lock", flags, 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise RuntimeError("deployment lock must be a single-link regular file")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            try:
                return operation(*args, **kwargs)
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    return locked


@_deployment_serialized
def backup(*, project: str, backup_dir: Path, off_host_dir: Path | None, local_only: bool, retention: int, enforce_binding: bool = False) -> dict[str, Any]:
    if off_host_dir is None and not local_only:
        raise RuntimeError("backup requires --off-host-dir or explicit --local-only")
    env = os.environ.copy()
    binding_config = _restore_binding_config(env) if enforce_binding else None
    compose = _compose(project)
    _run(["docker", "compose", "version"], env=env)
    container_id = _run([*compose, "ps", "-aq", "arvyx-server"], env=env).stdout.strip()
    if not container_id:
        raise RuntimeError("arvyx-server container does not exist")
    _assert_data_volume(container_id, _expected_data_volume(env, project), project, env)
    if backup_dir.is_symlink():
        raise RuntimeError("backup directory must not be a symbolic link")
    timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    final_archive = backup_dir / f"arvyx-backup-{timestamp}.tar.gz"
    final_checksum = backup_dir / f"{final_archive.name}.sha256"
    if final_archive.exists() or final_checksum.exists():
        raise RuntimeError("backup destination already exists")

    initial_running = _run(
        ['docker', 'inspect', '--format', '{{.State.Running}}', container_id], env=env
    ).stdout.strip()
    if initial_running not in {'true', 'false'}:
        raise RuntimeError('cannot establish original backup container running state')
    stop_attempted = False
    backup_error: BaseException | None = None
    # Let the durable publisher create/persist destination directory entries.
    with tempfile.TemporaryDirectory(prefix=".arvyx-backup-") as temporary:
        stage = Path(temporary)
        temp_archive = stage / final_archive.name
        temp_checksum = stage / final_checksum.name
        temp_binding = stage / f"{final_archive.name}.binding.json"
        try:
            stop_attempted = True
            _run([*compose, "stop", "arvyx-server"], env=env)
            _capture_container_data(container_id, temp_archive, env)
            with tempfile.TemporaryDirectory(prefix="verify-", dir=stage) as verify_tmp:
                _safe_extract(temp_archive, Path(verify_tmp))
            digest = _write_checksum(temp_archive, temp_checksum)
            if binding_config is not None:
                authority_id, key_file = binding_config
                _write_restore_binding(
                    archive=temp_archive,
                    manifest=temp_binding,
                    authority_id=authority_id,
                    deployment_id=env["ARVYX_DEPLOYMENT_ID"].strip(),
                    key_file=key_file,
                )
            os.chmod(temp_archive, 0o600)
            if off_host_dir is not None:
                _publish_off_host_atomic(
                    temp_archive,
                    temp_checksum,
                    temp_binding if binding_config is not None else None,
                    off_host_dir,
                )
            _publish_off_host_atomic(
                temp_archive,
                temp_checksum,
                temp_binding if binding_config is not None else None,
                backup_dir,
            )
        except BaseException as exc:
            backup_error = exc
            raise
        finally:
            if stop_attempted and initial_running == 'true':
                try:
                    # Reconcile the pinned original, never a replacement selected
                    # by Compose. A failed stop client may already have stopped it.
                    running = _run(
                        ['docker', 'inspect', '--format', '{{.State.Running}}', container_id], env=env
                    ).stdout.strip()
                    if running not in {'true', 'false'}:
                        raise RuntimeError('original backup container state is unknown')
                    if running == 'false':
                        _run(['docker', 'start', container_id], env=env)
                    healthy_id = _wait_healthy(compose, env, phase='backup restart')
                    if healthy_id != container_id:
                        raise RuntimeError('backup restart selected a different container')
                except BaseException as restart_error:
                    if backup_error is not None:
                        backup_error.add_note('Original service restart/reconciliation failed: ' + repr(restart_error))
                        setattr(backup_error, 'restart_failed', True)
                        setattr(backup_error, 'reconciliation_error', restart_error)
                    else:
                        raise

    _verify_checksum(final_archive, final_checksum)
    _enforce_retention(backup_dir, retention)
    if off_host_dir is not None:
        _enforce_retention(off_host_dir, retention)
    return {
        "ok": True,
        "archive": str(final_archive),
        "checksum": str(final_checksum),
        "sha256": digest,
        "off_host_copy": off_host_dir is not None,
        "retention": retention,
        "service_restarted": initial_running == 'true',
        "restore_binding": RESTORE_BINDING_SCHEMA if binding_config is not None else None,
    }


def _verify_candidate_volume_ownership(
    *,
    candidate_volume: str,
    project: str,
    ownership_token: str,
    production_env: dict[str, str],
) -> None:
    inspected = _run(
        ["docker", "volume", "inspect", candidate_volume],
        env=production_env,
    )
    try:
        payload = json.loads(inspected.stdout)
        labels = payload[0].get("Labels") if len(payload) == 1 else None
    except (json.JSONDecodeError, IndexError, AttributeError, TypeError) as exc:
        raise RuntimeError("candidate volume ownership inspection was invalid") from exc
    expected = {
        "com.docker.compose.project": project,
        "com.docker.compose.volume": "arvyx-data",
        "com.arvyx.restore.operation": ownership_token,
    }
    if not isinstance(labels, dict) or any(
        labels.get(key) != value for key, value in expected.items()
    ):
        raise RuntimeError(
            "candidate volume ownership labels do not match this restore operation"
        )


def _create_candidate_volume(
    *,
    candidate_volume: str,
    project: str,
    ownership_token: str,
    production_env: dict[str, str],
) -> None:
    _run(
        [
            "docker",
            "volume",
            "create",
            "--label",
            f"com.docker.compose.project={project}",
            "--label",
            "com.docker.compose.volume=arvyx-data",
            "--label",
            f"com.arvyx.restore.operation={ownership_token}",
            candidate_volume,
        ],
        env=production_env,
    )
    _verify_candidate_volume_ownership(
        candidate_volume=candidate_volume,
        project=project,
        ownership_token=ownership_token,
        production_env=production_env,
    )


# Executed only by the explicit restore operation, on the Docker daemon's
# candidate filesystem, not a guessed host Mountpoint. No application starts.
_CANDIDATE_FSYNC_PROGRAM = r'''
import os
import stat

def flush_directory(fd):
    for name in os.listdir(fd):
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                actual = os.fstat(child)
                if (actual.st_dev, actual.st_ino) != (info.st_dev, info.st_ino):
                    raise RuntimeError('candidate directory changed during durability barrier')
                flush_directory(child)
            finally:
                os.close(child)
        elif stat.S_ISREG(info.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                actual = os.fstat(child)
                if not stat.S_ISREG(actual.st_mode) or (actual.st_dev, actual.st_ino) != (info.st_dev, info.st_ino):
                    raise RuntimeError('candidate file changed during durability barrier')
                os.fsync(child)
            finally:
                os.close(child)
        else:
            raise RuntimeError('candidate durability requires regular files/directories')
    os.fsync(fd)

root = os.open('/candidate', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    flush_directory(root)
finally:
    os.close(root)
'''


def _persist_candidate_volume(*, candidate_volume: str, project: str,
                              ownership_token: str, production_env: dict[str, str]) -> None:
    _verify_candidate_volume_ownership(
        candidate_volume=candidate_volume, project=project,
        ownership_token=ownership_token, production_env=production_env,
    )
    _run([
        'docker', 'run', '--rm', '--network', 'none', '--read-only',
        '--cap-drop', 'ALL', '--cap-add', 'DAC_OVERRIDE',
        '--security-opt', 'no-new-privileges', '--user', '0:0',
        '--mount', f'type=volume,src={candidate_volume},dst=/candidate',
        '--entrypoint', 'python3',
        production_env.get('ARVYX_IMAGE', 'arvyx:local'),
        '-c', _CANDIDATE_FSYNC_PROGRAM,
    ], env=production_env)
    _verify_candidate_volume_ownership(
        candidate_volume=candidate_volume, project=project,
        ownership_token=ownership_token, production_env=production_env,
    )


def _materialize_candidate_volume(
    *,
    staging_compose: list[str],
    staging_env: dict[str, str],
    production_env: dict[str, str],
    project: str,
    candidate_volume: str,
    container_archive: Path,
) -> None:
    _run([*staging_compose, "create", "arvyx-server"], env=staging_env)
    staging_container = _run([*staging_compose, "ps", "-aq", "arvyx-server"], env=staging_env).stdout.strip()
    if not staging_container:
        raise RuntimeError("staging restore container was not created")
    _assert_data_volume(staging_container, candidate_volume, project, staging_env)
    with container_archive.open("rb") as source:
        subprocess.run(
            ["docker", "cp", "--archive", "--quiet", "-", f"{staging_container}:/data"],
            cwd=ROOT,
            env=staging_env,
            stdin=source,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
    _stage_current_control_secret(
        secret_file=Path(production_env["ARVYX_CONTROL_SECRET_FILE"]),
        volume=candidate_volume,
        image=production_env.get("ARVYX_IMAGE", "arvyx:local"),
        env=production_env,
    )


def _reseed_pristine_candidate_volume(
    *,
    staging_compose: list[str],
    staging_env: dict[str, str],
    production_env: dict[str, str],
    project: str,
    candidate_volume: str,
    ownership_token: str,
    container_archive: Path,
    on_candidate_removal_started: Callable[[], None],
    on_candidate_removed: Callable[[], None],
    on_candidate_created: Callable[[], None],
) -> None:
    """Rebuild the promote candidate from the verified archive after mutating probe."""
    staging_failure = _attempt_cleanup(
        [*staging_compose, "down", "--remove-orphans"],
        env=staging_env,
        label="reseed staging cleanup",
    )
    if staging_failure is not None:
        raise RuntimeError(staging_failure)
    on_candidate_removal_started()
    _verify_candidate_volume_ownership(
        candidate_volume=candidate_volume,
        project=project,
        ownership_token=ownership_token,
        production_env=production_env,
    )
    _run(["docker", "volume", "rm", candidate_volume], env=production_env)
    on_candidate_removed()
    _create_candidate_volume(
        candidate_volume=candidate_volume,
        project=project,
        ownership_token=ownership_token,
        production_env=production_env,
    )
    on_candidate_created()
    _materialize_candidate_volume(
        staging_compose=staging_compose,
        staging_env=staging_env,
        production_env=production_env,
        project=project,
        candidate_volume=candidate_volume,
        container_archive=container_archive,
    )


def _wait_healthy(
    compose: list[str],
    env: dict[str, str],
    timeout: int = 120,
    *,
    phase: str = "restored server",
) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        container_id = _run([*compose, "ps", "-q", "arvyx-server"], env=env).stdout.strip()
        if container_id:
            status = _run(["docker", "inspect", "--format", "{{.State.Health.Status}}", container_id], env=env, check=False).stdout.strip()
            if status == "healthy":
                return container_id
            if status == "unhealthy":
                raise RuntimeError(f"{phase} is unhealthy")
        time.sleep(1)
    raise RuntimeError(f"{phase} did not become healthy")


# Bound untrusted input copying before any archive parsing or Docker work.
RESTORE_ARCHIVE_MAX_BYTES = 64 * 1024 * 1024 * 1024
RESTORE_SIDECAR_MAX_BYTES = 64 * 1024


def _copy_restore_input(source: Path, destination: Path, *, limit: int) -> None:
    """Copy one descriptor-pinned regular input into exclusively owned storage."""
    # Restore is POSIX-only (the deployment lock already requires flock).
    # O_NONBLOCK ensures FIFOs cannot hang before the descriptor type check.
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(source, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RuntimeError("restore input must be a single-link regular file")
        if before.st_size > limit:
            raise RuntimeError("restore input exceeds copy limit")
        with destination.open("xb") as output:
            os.chmod(destination, 0o600)
            remaining = before.st_size
            while remaining:
                chunk = os.read(descriptor, min(remaining, 1024 * 1024))
                if not chunk:
                    raise RuntimeError("restore input changed during copy")
                output.write(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise RuntimeError("restore input changed during copy")
        after = os.fstat(descriptor)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ) or after.st_nlink != 1:
            raise RuntimeError("restore input changed during copy")
    finally:
        os.close(descriptor)


@_deployment_serialized
def restore(
    *,
    project: str,
    archive: Path,
    checksum: Path,
    confirm_destroy_volume: bool,
    env_file: Path = ROOT / ".env",
    enforce_binding: bool = False,
) -> dict[str, Any]:
    if not confirm_destroy_volume:
        raise RuntimeError("restore requires explicit cutover confirmation")
    # Do not resolve inputs: that would turn a rejected final symlink into a
    # followed regular path. Preserve the basename authenticated by both sidecars.
    if archive.name in {"", ".", ".."}:
        raise RuntimeError("restore archive basename is invalid")
    with tempfile.TemporaryDirectory(prefix="arvyx-restore-inputs-") as temporary:
        stage = Path(temporary)
        os.chmod(stage, 0o700)
        staged_archive = stage / archive.name
        staged_checksum = stage / f"{archive.name}.sha256"
        _copy_restore_input(archive, staged_archive, limit=RESTORE_ARCHIVE_MAX_BYTES)
        _copy_restore_input(checksum, staged_checksum, limit=RESTORE_SIDECAR_MAX_BYTES)
        if enforce_binding:
            _copy_restore_input(
                archive.with_name(f"{archive.name}.binding.json"),
                stage / f"{archive.name}.binding.json",
                limit=RESTORE_SIDECAR_MAX_BYTES,
            )
        # This context owns the private bytes until cleanup/rollback has finished.
        # Nothing below this boundary receives an external archive pathname.
        return _restore_private(
            project=project, archive=staged_archive, checksum=staged_checksum,
            env_file=env_file, enforce_binding=enforce_binding,
        )


def _restore_private(
    *, project: str, archive: Path, checksum: Path, env_file: Path,
    enforce_binding: bool,
) -> dict[str, Any]:
    """Authenticate and consume only the private snapshot owned by restore()."""
    production_env = os.environ.copy()
    binding = None
    if enforce_binding:
        authority_id, key_file = _restore_binding_config(production_env)
        binding = _verify_restore_binding(
            archive=archive,
            manifest=archive.with_name(f"{archive.name}.binding.json"),
            authority_id=authority_id,
            key_file=key_file,
        )
    digest = _verify_checksum(archive, checksum)
    if not production_env.get("ARVYX_CONTROL_SECRET_FILE", "").strip():
        raise RuntimeError("ARVYX_CONTROL_SECRET_FILE must be configured for restore verification")
    # Bind restore to the maintained production definition and the same pointer
    # file we commit; never inherit COMPOSE_FILE or an automatic override file.
    production_compose = [
        "docker", "compose", "-p", project, "--env-file", str(env_file),
        "-f", str(ROOT / "docker-compose.yml"),
    ]
    previous_volume = _expected_data_volume(production_env, project)
    if _read_active_volume_pointer(env_file) != previous_volume:
        raise VolumePointerReconciliationRequired(
            "restore environment and durable volume pointer disagree; no services changed"
        )
    _run(["docker", "volume", "inspect", previous_volume], env=production_env)
    existing_container = _run([*production_compose, "ps", "-aq", "arvyx-server"], env=production_env).stdout.strip()
    if existing_container:
        _assert_data_volume(existing_container, previous_volume, project, production_env)

    suffix = secrets.token_hex(6)
    ownership_token = secrets.token_hex(16)
    deployment_id = production_env["ARVYX_DEPLOYMENT_ID"].strip()
    candidate_volume = f"{project}_{deployment_id}_arvyx-data-restore-{suffix}"
    staging_project = f"{project}-restore-{suffix}"
    candidate_env = production_env.copy()
    candidate_env["ARVYX_DATA_VOLUME"] = candidate_volume
    candidate_env["COMPOSE_PROJECT_NAME"] = project
    staging_env = candidate_env.copy()
    staging_env["COMPOSE_PROJECT_NAME"] = staging_project
    staging_env["ARVYX_PORT"] = "0"
    candidate_created = False
    candidate_identity_uncertain = False
    staging_cleanup_owned = False
    staging_started = False
    cutover_started = False
    pointer_committed = False
    admission_started = False

    def mark_candidate_removal_started() -> None:
        nonlocal candidate_created, candidate_identity_uncertain
        candidate_created = False
        candidate_identity_uncertain = True

    def mark_candidate_removed() -> None:
        nonlocal candidate_created, candidate_identity_uncertain
        candidate_created = False
        candidate_identity_uncertain = False

    def mark_candidate_created() -> None:
        nonlocal candidate_created, candidate_identity_uncertain
        candidate_created = True
        candidate_identity_uncertain = False

    with tempfile.TemporaryDirectory(prefix="arvyx-restore-") as temporary:
        temporary_path = Path(temporary)
        _safe_extract(archive, temporary_path / "verify")
        container_archive = temporary_path / "container-data.tar"
        _container_tar(archive, container_archive)
        override = temporary_path / "staging-compose.yml"
        override.write_text(
            "volumes:\n"
            "  arvyx-data:\n"
            "    external: true\n"
            f"    name: {candidate_volume}\n",
            encoding="utf-8",
        )
        # A standalone definition is essential: merging the production service
        # would inherit its published port and client-reachable network.
        staging_compose = [
            "docker", "compose", "-p", staging_project,
            "-f", str(ROOT / "scripts" / "restore-candidate.private.yml"),
            "-f", str(override),
        ]
        try:
            _create_candidate_volume(
                candidate_volume=candidate_volume,
                project=project,
                ownership_token=ownership_token,
                production_env=production_env,
            )
            mark_candidate_created()
            # Own namespace cleanup before Compose container creation is attempted;
            # a failed create can still leave a partial container behind.
            staging_cleanup_owned = True
            _materialize_candidate_volume(
                staging_compose=staging_compose,
                staging_env=staging_env,
                production_env=production_env,
                project=project,
                candidate_volume=candidate_volume,
                container_archive=container_archive,
            )
            _run([*staging_compose, "up", "-d", "--no-build", "arvyx-server"], env=staging_env)
            staging_started = True
            _wait_healthy(staging_compose, staging_env, phase="staging restore")
            _acceptance_probe(
                staging_compose,
                staging_env,
                operation_key=f"restore-acceptance-{suffix}",
            )
            # Mutating acceptance must not pollute the promote candidate.
            _reseed_pristine_candidate_volume(
                staging_compose=staging_compose,
                staging_env=staging_env,
                production_env=production_env,
                project=project,
                candidate_volume=candidate_volume,
                ownership_token=ownership_token,
                container_archive=container_archive,
                on_candidate_removal_started=mark_candidate_removal_started,
                on_candidate_removed=mark_candidate_removed,
                on_candidate_created=mark_candidate_created,
            )
            staging_started = False
            _run([*staging_compose, "up", "-d", "--no-build", "arvyx-server"], env=staging_env)
            staging_started = True
            candidate_container = _wait_healthy(staging_compose, staging_env, phase="pristine candidate")
            _assert_data_volume(candidate_container, candidate_volume, project, staging_env)
            _run([*staging_compose, "down", "--remove-orphans"], env=staging_env)
            staging_started = False
            staging_cleanup_owned = False

            # Include final reseed, current secret and readiness writes. Barrier
            # failure precedes production teardown and leaves the old pointer.
            _persist_candidate_volume(
                candidate_volume=candidate_volume, project=project,
                ownership_token=ownership_token, production_env=production_env,
            )
            cutover_started = True
            _run([*production_compose, "down", "--remove-orphans"], env=production_env)
            # All health verification above is isolated. No client-reachable
            # candidate exists until the pointer's file AND directory barriers.
            _atomic_update_active_volume(env_file, previous=previous_volume, candidate=candidate_volume)
            pointer_committed = True
            # Set BEFORE invoking Docker: failed/ interrupted up can still have
            # published a port and acknowledged writes. Never infer no admission
            # from a subprocess error or from a failed later health check.
            admission_started = True
            _run([*production_compose, "up", "-d", "--no-build", "arvyx-server"], env=candidate_env)
            candidate_container = _wait_healthy(
                production_compose, candidate_env, phase="candidate cutover"
            )
            _assert_data_volume(candidate_container, candidate_volume, project, candidate_env)
        except BaseException as restore_error:
            if pointer_committed or admission_started:
                # The committed candidate is now authoritative. Stop, but do not
                # remove its container/volume, repoint .env, or restart old data.
                # A stop failure is an explicit unresolved admission fence.
                failure = _attempt_cleanup(
                    [*production_compose, "stop", "arvyx-server"],
                    env=candidate_env,
                    label="post-commit admission fence",
                )
                if failure is None:
                    try:
                        retained_container = _run(
                            [*production_compose, "ps", "-aq", "arvyx-server"], env=candidate_env
                        ).stdout.strip()
                        if retained_container:
                            running = _run(
                                ["docker", "inspect", "--format", "{{.State.Running}}", retained_container],
                                env=candidate_env,
                            ).stdout.strip()
                            if running != "false":
                                raise RuntimeError("candidate still running")
                    except Exception:
                        failure = "post-commit admission fence could not be verified"
                error = VolumePointerReconciliationRequired(
                    "restore committed candidate requires reconciliation; automatic rollback forbidden"
                )
                error.candidate_volume = candidate_volume
                error.previous_volume = previous_volume
                error.cleanup_failures = (failure,) if failure is not None else ()
                error.restart_failed = False
                error.restart_blocked = True
                error.add_note(f"retain candidate {candidate_volume} and previous volume {previous_volume}")
                if failure is not None:
                    error.add_note("admission fence unproven; operator must isolate the service immediately")
                raise error from restore_error
            reconciliation_error: VolumePointerReconciliationRequired | None = None
            rollback_restart_error: Exception | None = None
            cleanup_failures: list[str] = []
            if candidate_identity_uncertain:
                cleanup_failures.append(
                    "candidate volume ownership is uncertain after reseed removal failure"
                )
            if staging_started or staging_cleanup_owned:
                failure = _attempt_cleanup(
                    [*staging_compose, "down", "--remove-orphans"],
                    env=staging_env,
                    label="staging namespace cleanup",
                )
                if failure is not None:
                    cleanup_failures.append(failure)
            if cutover_started:
                failure = _attempt_cleanup(
                    [*production_compose, "down", "--remove-orphans"],
                    env=candidate_env,
                    label="candidate service cleanup",
                )
                if failure is not None:
                    cleanup_failures.append(failure)
            rollback_confirmed = False
            if candidate_created or cutover_started:
                try:
                    _rollback_active_volume_pointer(
                        env_file,
                        previous_volume=previous_volume,
                        candidate_volume=candidate_volume,
                    )
                    rollback_confirmed = True
                except VolumePointerReconciliationRequired as exc:
                    reconciliation_error = exc
            restart_blocked = cutover_started and (
                not rollback_confirmed or reconciliation_error is not None or bool(cleanup_failures)
            )
            if cutover_started and not restart_blocked:
                try:
                    # Recheck at admission, not only inside rollback. A changed
                    # pointer must never be hidden by the old environment override.
                    if _read_active_volume_pointer(env_file) != previous_volume:
                        raise VolumePointerReconciliationRequired(
                            "volume pointer changed before rollback restart; retain both volumes"
                        )
                    _run(
                        [*production_compose, "up", "-d", "--no-build", "arvyx-server"],
                        env=production_env,
                    )
                    rollback_container = _wait_healthy(
                        production_compose, production_env, phase="rollback restart"
                    )
                    _assert_data_volume(
                        rollback_container, previous_volume, project, production_env
                    )
                except VolumePointerReconciliationRequired as exc:
                    reconciliation_error = exc
                    restart_blocked = True
                except Exception as exc:
                    rollback_restart_error = exc
            if (
                candidate_created
                and reconciliation_error is None
                and rollback_restart_error is None
                and not cleanup_failures
            ):
                try:
                    _verify_candidate_volume_ownership(
                        candidate_volume=candidate_volume,
                        project=project,
                        ownership_token=ownership_token,
                        production_env=production_env,
                    )
                except Exception:
                    cleanup_failures.append(
                        "candidate volume ownership verification failed before cleanup; volume retained"
                    )
                else:
                    failure = _attempt_cleanup(
                        ["docker", "volume", "rm", candidate_volume],
                        env=production_env,
                        label="candidate volume cleanup",
                    )
                    if failure is not None:
                        cleanup_failures.append(failure)
            elif (
                candidate_created
                and reconciliation_error is None
                and rollback_restart_error is None
                and cleanup_failures
            ):
                cleanup_failures.append(
                    "candidate volume retained because prior teardown or cleanup was unproven"
                )
            elif (
                candidate_created
                and reconciliation_error is None
                and rollback_restart_error is not None
            ):
                cleanup_failures.append(
                    "candidate volume retained because previous volume restart verification failed"
                )
            if reconciliation_error is not None:
                reconciliation_error.candidate_volume = candidate_volume
                reconciliation_error.previous_volume = previous_volume
                reconciliation_error.cleanup_failures = tuple(cleanup_failures)
                reconciliation_error.restart_failed = rollback_restart_error is not None
                reconciliation_error.restart_blocked = restart_blocked
                reconciliation_error.add_note(
                    f"candidate volume retained for reconciliation: {candidate_volume}"
                )
                if restart_blocked:
                    reconciliation_error.add_note("previous volume restart withheld until pointer and teardown are reconciled")
                if rollback_restart_error is not None:
                    reconciliation_error.add_note("previous volume restart also failed")
                if cleanup_failures:
                    reconciliation_error.add_note(
                        f"cleanup required for candidate volume {candidate_volume}: "
                        + "; ".join(cleanup_failures)
                    )
                raise reconciliation_error from restore_error
            if cleanup_failures:
                cleanup_error = RestoreCleanupRequired(
                    f"restore cleanup required for candidate volume {candidate_volume}: "
                    + "; ".join(cleanup_failures)
                )
                cleanup_error.candidate_volume = candidate_volume
                cleanup_error.previous_volume = previous_volume
                cleanup_error.cleanup_failures = tuple(cleanup_failures)
                cleanup_error.restart_failed = rollback_restart_error is not None
                cleanup_error.restart_blocked = restart_blocked
                if rollback_restart_error is not None:
                    cleanup_error.add_note("previous volume restart also failed")
                raise cleanup_error from restore_error
            if rollback_restart_error is not None:
                raise rollback_restart_error from restore_error
            raise

    return {
        "ok": True,
        "sha256": digest,
        "health": True,
        "acceptance_probe": True,
        "pristine_candidate": True,
        "active_volume": candidate_volume,
        "rollback_volume": previous_volume,
        "rollback_volume_retained": True,
        "restore_binding": binding["schema"] if binding is not None else None,
        "source_deployment_id": binding["source_deployment_id"] if binding is not None else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Fail-closed Docker volume backup and restore utility.")
    parser.add_argument("--project", default=os.environ.get("COMPOSE_PROJECT_NAME", "arvyx"))
    subparsers = parser.add_subparsers(dest="command", required=True)
    backup_parser = subparsers.add_parser("backup")
    backup_parser.add_argument("--backup-dir", type=Path, required=True)
    backup_parser.add_argument("--off-host-dir", type=Path)
    backup_parser.add_argument("--local-only", action="store_true")
    backup_parser.add_argument("--retention", type=int, default=7)
    restore_parser = subparsers.add_parser("restore")
    restore_parser.add_argument("archive", type=Path)
    restore_parser.add_argument("--checksum", type=Path)
    restore_parser.add_argument("--env-file", type=Path, default=ROOT / ".env")
    restore_parser.add_argument(
        "--confirm-cutover",
        "--confirm-destroy-volume",
        dest="confirm_cutover",
        action="store_true",
        help="Confirm staged validation and atomic volume-pointer cutover; the previous volume is retained.",
    )
    args = parser.parse_args()
    try:
        if args.command == "backup":
            result = backup(
                project=args.project,
                backup_dir=args.backup_dir,
                off_host_dir=args.off_host_dir,
                local_only=args.local_only,
                retention=args.retention,
                enforce_binding=True,
            )
        else:
            checksum = args.checksum or args.archive.with_name(f"{args.archive.name}.sha256")
            result = restore(
                project=args.project,
                archive=args.archive,
                checksum=checksum,
                confirm_destroy_volume=args.confirm_cutover,
                env_file=args.env_file,
                enforce_binding=True,
            )
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.CalledProcessError, tarfile.TarError, UnicodeError) as exc:
        payload: dict[str, object] = {
            "ok": False,
            "error": type(exc).__name__,
            "message": (f"external command failed with exit status {exc.returncode}"
                        if isinstance(exc, subprocess.CalledProcessError) else str(exc)),
        }
        if isinstance(
            exc,
            (RestoreCleanupRequired, VolumePointerReconciliationRequired),
        ):
            candidate_volume = getattr(exc, "candidate_volume", None)
            cleanup_failures = getattr(exc, "cleanup_failures", ())
            restart_failed = getattr(exc, "restart_failed", False)
            if isinstance(candidate_volume, str):
                payload["candidate_volume"] = candidate_volume
            if isinstance(cleanup_failures, (tuple, list)) and all(
                isinstance(item, str) for item in cleanup_failures
            ):
                payload["cleanup_failures"] = list(cleanup_failures)
            payload["restart_failed"] = bool(restart_failed)
            payload["restart_blocked"] = bool(getattr(exc, "restart_blocked", False))
            previous_volume = getattr(exc, "previous_volume", None)
            if isinstance(previous_volume, str):
                payload["previous_volume"] = previous_volume
        # Backup reconciliation annotates the original exception rather than
        # replacing it with a restore-only exception class. Preserve that signal
        # at the CLI boundary without serializing subprocess argv or stderr.
        if getattr(exc, "restart_failed", False):
            payload["restart_failed"] = True
            payload["reconciliation_required"] = True
        print(json.dumps(payload, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
