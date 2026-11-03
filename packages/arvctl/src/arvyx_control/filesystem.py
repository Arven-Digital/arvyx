"""Filesystem namespace durability barriers shared by authoritative writers."""
from __future__ import annotations

import os
from pathlib import Path


MAX_MEMORY_DOCUMENT_BYTES = 1024 * 1024


def memory_document_bytes(text: str) -> bytes:
    """Encode a fully rendered memory within the lifecycle reader's bound."""
    payload = text.encode("utf-8")
    if len(payload) > MAX_MEMORY_DOCUMENT_BYTES:
        raise ValueError("rendered memory document byte limit exceeded")
    return payload


def fsync_directory(path: Path) -> None:
    # Never suppress a POSIX failure (including unsupported filesystem barriers).
    if os.name == "nt":
        # Windows: no directory flush. FlushFileBuffers on a directory handle flushes
        # the whole NTFS volume (seconds per call under load); NTFS journals the
        # directory metadata itself. Conditional Windows support guarantees file
        # fsync only, not fsynced namespaces (see safe_open.fsync_directory).
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def durable_mkdir(path: Path, *, mode: int = 0o777) -> None:
    """Create a directory and persist its entire ancestor chain.

    Existing ancestors also require barriers: callers or lock setup may have
    just created them without syncing their names. Do not infer durability
    from existence. Errors propagate before any destructive publication.
    """
    path = Path(os.path.abspath(path))
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    chain = [path, *path.parents]
    for directory in reversed(chain):
        fsync_directory(directory)
