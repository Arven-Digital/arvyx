#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tarfile
import tempfile
import time

ALLOWED_SCHEMAS = {"arvyx-v2-snapshot-manifest/v1", "arvyx-v2-snapshot-manifest/v2"}
PRODUCTION_ROOT = Path("/srv/arvyx-v2").resolve()


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_bundle(snapshot: Path) -> tuple[dict, Path, Path | None]:
    if snapshot.is_symlink() or not snapshot.is_dir():
        raise RuntimeError("snapshot must be a regular directory")
    manifest_path = snapshot / "manifest.json"
    archive_path = snapshot / "archive.tar.gz"
    authority_path = snapshot / "authority-evidence.tar.gz"
    expected: dict[str, str] = {}
    for line in (snapshot / "bundle.sha256").read_text(encoding="utf-8").splitlines():
        checksum, name = line.split(None, 1)
        expected[name.strip()] = checksum
    possible = {"archive.tar.gz": archive_path, "manifest.json": manifest_path, "authority-evidence.tar.gz": authority_path}
    if set(expected) not in ({"archive.tar.gz", "manifest.json"}, set(possible)):
        raise RuntimeError("snapshot bundle member set is unsupported")
    actual = {name: digest(possible[name]) for name in expected}
    if expected != actual:
        raise RuntimeError("snapshot bundle checksum mismatch")
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    schema = document.get("schema")
    if schema not in ALLOWED_SCHEMAS or not document.get("files"):
        raise RuntimeError("unsupported or empty snapshot manifest")
    allowed = {"archive.tar.gz", "manifest.json"}
    if schema.endswith("/v2"):
        allowed.add("authority-evidence.tar.gz")
    if set(expected) != allowed:
        raise RuntimeError("snapshot bundle member set does not match schema")
    authority: Path | None = authority_path if schema.endswith("/v2") else None
    if authority is not None and document.get("authority_policy") != "separate-evidence-never-auto-activate":
        raise RuntimeError("snapshot authority policy is missing or unsafe")
    return document, archive_path, authority


def safe_extract(archive: Path, destination: Path) -> None:
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        if not members:
            raise RuntimeError("snapshot archive is empty")
        for member in members:
            rel = PurePosixPath(member.name)
            if rel.is_absolute() or ".." in rel.parts or not rel.parts:
                raise RuntimeError("snapshot archive contains unsafe path")
            if not (member.isdir() or member.isfile()):
                raise RuntimeError("snapshot archive contains unsafe entry type")
        for member in members:
            target = destination.joinpath(*PurePosixPath(member.name).parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=False)
                os.chown(target, member.uid, member.gid)
                os.chmod(target, member.mode & 0o7777)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = bundle.extractfile(member)
            if source is None:
                raise RuntimeError("snapshot file has no payload")
            with source, target.open("xb") as output:
                shutil.copyfileobj(source, output)
            os.chown(target, member.uid, member.gid)
            os.chmod(target, member.mode & 0o7777)


def verify_restored(root: Path, expected: dict[str, dict]) -> None:
    actual_paths: set[str] = set()
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        actual_paths.add(rel)
        meta = expected.get(rel)
        if meta is None:
            raise RuntimeError("restored tree contains an unmanifested path")
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise RuntimeError("restored tree contains a symlink")
        kind = "dir" if stat.S_ISDIR(info.st_mode) else "file" if stat.S_ISREG(info.st_mode) else "other"
        if kind != meta["type"] or stat.S_IMODE(info.st_mode) != meta["mode"]:
            raise RuntimeError("restored type/mode mismatch")
        if info.st_uid != meta["uid"] or info.st_gid != meta["gid"]:
            raise RuntimeError("restored ownership mismatch")
        if kind == "file" and (info.st_size != meta["size"] or digest(path) != meta["sha256"]):
            raise RuntimeError("restored file integrity mismatch")
    if actual_paths != set(expected):
        raise RuntimeError("restored tree is incomplete")


def validate_destination(path: Path) -> Path:
    resolved = path.resolve(strict=False)
    if resolved == PRODUCTION_ROOT or PRODUCTION_ROOT in resolved.parents or resolved in PRODUCTION_ROOT.parents:
        raise RuntimeError("restore drill destination must be outside the production root")
    if resolved.exists():
        raise RuntimeError("restore drill destination must not already exist")
    return resolved


def run(snapshot: Path, *, keep: Path | None = None) -> dict:
    if os.geteuid() != 0:
        raise PermissionError("restore drill requires root for mandatory uid/gid verification")
    started = time.monotonic()
    document, archive, authority_archive = load_bundle(snapshot)
    if keep is None:
        temporary = tempfile.TemporaryDirectory(prefix="arvyx-v2-restore-drill-")
        destination = Path(temporary.name)
    else:
        temporary = None
        destination = validate_destination(keep)
    data_root = destination / "restored-data"
    evidence_root = destination / "evidence-only"
    data_root.mkdir(parents=True)
    try:
        files: dict[str, dict] = document["files"]
        data_expected = {path: meta for path, meta in files.items() if not (path == "authority" or path.startswith("authority/"))}
        authority_expected = {path: meta for path, meta in files.items() if path == "authority" or path.startswith("authority/")}
        safe_extract(archive, data_root)
        verify_restored(data_root, data_expected)
        authority_verified = False
        if authority_archive is not None:
            evidence_root.mkdir()
            safe_extract(authority_archive, evidence_root)
            verify_restored(evidence_root, authority_expected)
            authority_state_path = evidence_root / "authority" / "state.json"
            if authority_state_path.exists():
                authority_state = json.loads(authority_state_path.read_text(encoding="utf-8"))
                if not isinstance(authority_state, dict):
                    raise RuntimeError("authority evidence is invalid")
            if (data_root / "authority").exists():
                raise RuntimeError("authority evidence leaked into restorable data")
            authority_verified = True
        return {
            "ok": True,
            "restore_proven": True,
            "ownership_verified": True,
            "snapshot": snapshot.name,
            "schema": document["schema"],
            "manifest_entries": len(files),
            "authority_evidence_verified": authority_verified,
            "authority_present_in_restorable_data": False,
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
    finally:
        if temporary is not None:
            temporary.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline, non-promoting Arvyx V2 snapshot restore drill")
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--keep", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = run(args.snapshot.resolve(strict=True), keep=args.keep)
    except Exception as exc:
        result = {"ok": False, "restore_proven": False, "error": type(exc).__name__, "message": str(exc)}
        print(json.dumps(result, sort_keys=True) if args.json else f"restore drill failed: {exc}")
        return 1
    print(json.dumps(result, sort_keys=True) if args.json else "restore drill PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
