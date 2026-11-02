#!/usr/bin/env python3
"""Executable, local-only backup/loss/restore/restart acceptance drill."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

SCHEMA = "arvyx-synthetic-restore-drill/v1"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): sha256(path)
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }


def _extract(archive: Path, destination: Path) -> None:
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        if not members:
            raise RuntimeError("backup archive is empty")
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not (member.isdir() or member.isfile()):
                raise RuntimeError("backup archive contains an unsafe entry")
        resolved_destination = destination.resolve()
        for member in members:
            target = destination.joinpath(*PurePosixPath(member.name).parts)
            if not target.resolve().is_relative_to(resolved_destination):
                raise RuntimeError("backup archive contains an unsafe entry")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = bundle.extractfile(member)
            if source is None:
                raise RuntimeError("backup file has no payload")
            with source, target.open("xb") as output:
                shutil.copyfileobj(source, output)


def run(*, workspace: Path | None = None, corrupt_backup: bool = False, probe_timeout: float = 10.0) -> dict[str, object]:
    temporary = None if workspace else tempfile.TemporaryDirectory(prefix="arvyx-synthetic-drill-")
    try:
        return _run(workspace=workspace, corrupt_backup=corrupt_backup, temporary=temporary, probe_timeout=probe_timeout)
    finally:
        if temporary is not None:
            temporary.cleanup()


def _run(*, workspace: Path | None, corrupt_backup: bool, temporary, probe_timeout: float = 10.0) -> dict[str, object]:
    started = time.monotonic()
    root = workspace if workspace is not None else Path(temporary.name)  # type: ignore[union-attr]
    root.mkdir(parents=True, exist_ok=True)
    source = root / "synthetic-primary"
    backup_dir = root / "offline-backup"
    restore = root / "offline-restore"
    source.mkdir()
    backup_dir.mkdir()
    (source / "vault").mkdir()
    (source / "state").mkdir()
    mutation_wall = time.time()
    (source / "vault" / "current.md").write_text("synthetic governed truth\n", encoding="utf-8")
    (source / "state" / "events.jsonl").write_text('{"kind":"synthetic"}\n', encoding="utf-8")
    expected = _manifest(source)

    archive = backup_dir / "snapshot.tar.gz"
    manifest_path = backup_dir / "manifest.json"
    with tarfile.open(archive, "w:gz", dereference=False) as bundle:
        bundle.add(source, arcname="data")
    manifest_path.write_text(json.dumps({"schema": SCHEMA, "files": expected}, sort_keys=True) + "\n", encoding="utf-8")
    backup_completed_wall = time.time()
    archive_digest = sha256(archive)
    if corrupt_backup:
        with archive.open("ab") as handle:
            handle.write(b"synthetic-corruption")

    if sha256(archive) != archive_digest:
        raise RuntimeError("backup checksum mismatch")
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    if document.get("schema") != SCHEMA or document.get("files") != expected:
        raise RuntimeError("backup manifest mismatch")
    # Declare total primary loss only after the offline backup is complete AND verified.
    shutil.rmtree(source)
    failure_declared = time.monotonic()
    restore.mkdir()
    _extract(archive, restore)
    restored_data = restore / "data"
    actual = _manifest(restored_data)
    if actual != expected:
        raise RuntimeError("restored integrity mismatch")

    # A fresh process stands in for restart: it must read restored state and
    # return an exact acceptance value. It has no access to the deleted source.
    probe = subprocess.run(
        [sys.executable, "-c", "from pathlib import Path; print((Path(__import__('sys').argv[1])/'vault/current.md').read_text().strip())", str(restored_data)],
        text=True,
        capture_output=True,
        timeout=probe_timeout,
        check=True,
    )
    if probe.stdout.strip() != "synthetic governed truth":
        raise RuntimeError("restarted synthetic service rejected restored state")
    accepted = time.monotonic()
    result: dict[str, object] = {
        "ok": True,
        "schema": SCHEMA,
        "backup_created": True,
        "primary_loss_simulated": True,
        "offline_restore_verified": True,
        # Legacy field refers only to the fresh synthetic file-reader process.
        "restart_acceptance_verified": True,
        "acceptance_scope": "two-file synthetic archive and fresh file-reader process only",
        "product_composition_restore_verified": False,
        "product_restart_acceptance_verified": False,
        "authority_reprovisioning_verified": False,
        "manifest_entries": len(expected),
        "rpo_like_seconds": round(max(0.0, backup_completed_wall - mutation_wall), 6),
        "rto_like_seconds": round(accepted - failure_declared, 6),
        "elapsed_seconds": round(accepted - started, 6),
        "metric_scope": "local synthetic drill; not a production RPO/RTO claim",
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, help="new or empty synthetic workspace to retain")
    parser.add_argument("--corrupt-backup", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        if args.workspace and args.workspace.exists() and any(args.workspace.iterdir()):
            raise RuntimeError("workspace must be new or empty")
        result = run(workspace=args.workspace, corrupt_backup=args.corrupt_backup)
    except Exception as exc:
        print(json.dumps({"ok": False, "error": type(exc).__name__, "message": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True) if args.json else "synthetic restore drill PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
