from __future__ import annotations

import argparse
import os
from pathlib import Path
import secrets
import sys


def create_secret_file(path: Path, *, token_bytes: int = 48) -> Path:
    if token_bytes < 32:
        raise ValueError("secret entropy must be at least 32 bytes")
    # Preserve the requested leaf until exclusive publication. Resolving it
    # first follows even a dangling symlink and can chmod an unrelated parent.
    # Provisioning assumes ancestors cannot be concurrently replaced by an
    # untrusted writer; these checks do not create a filesystem sandbox.
    path = Path(os.path.abspath(path))
    if os.path.lexists(path):
        raise RuntimeError("secret path already exists; refuse overwrite")
    parent = path.parent
    for ancestor in (parent, *parent.parents):
        from arvyx_control.posix_support import system_directory_symlink
        if ancestor.is_symlink() and not system_directory_symlink(ancestor):
            raise RuntimeError("secret directory must not be a symlink")
    parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    if not parent.is_dir() or parent.is_symlink():
        raise RuntimeError("secret directory is not a real directory")
    if os.name != "nt":
        os.chmod(parent, 0o700)
    if os.path.lexists(path):
        raise RuntimeError("secret path already exists; refuse overwrite")

    temp_path = parent / f".{path.name}.{secrets.token_hex(16)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd: int | None = None
    published = False
    try:
        fd = os.open(temp_path, flags, 0o600)
        payload = (secrets.token_urlsafe(token_bytes) + "\n").encode("ascii")
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write while creating secret")
            view = view[written:]
        if os.name != "nt":
            os.fchmod(fd, 0o600)
        os.fsync(fd)
        os.close(fd)
        fd = None

        # Hard-link publication is atomic and refuses to replace an existing
        # destination. The temporary inode is never visible at the final path
        # until its complete bytes are durable.
        os.link(temp_path, path)
        published = True
        temp_path.unlink()
        if os.name != "nt" and hasattr(os, "O_DIRECTORY"):
            directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except FileExistsError as exc:
        raise RuntimeError("secret path already exists; refuse overwrite") from exc
    except Exception:
        if fd is not None:
            os.close(fd)
        if published:
            path.unlink(missing_ok=True)
        raise
    finally:
        temp_path.unlink(missing_ok=True)
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a new file-backed bearer secret without overwriting existing paths.")
    parser.add_argument("path", type=Path, nargs="?", default=Path("secrets/arvyx-control-secret"))
    args = parser.parse_args()
    try:
        created = create_secret_file(args.path)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"secret creation failed: {exc}", file=sys.stderr)
        return 1
    print(f"created secret file: {created}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
