from __future__ import annotations

import os

from contextlib import contextmanager
from pathlib import Path
import errno
import math
import sys
import time
from typing import IO, Iterator

try:  # POSIX
    import fcntl

    def _lock(handle: IO[str], deadline: float | None = None) -> None:
        if deadline is None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            return
        while True:
            check_deadline(deadline)
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN):
                    raise
            time.sleep(min(.01, check_deadline(deadline) or .01))

    def _unlock(handle: IO[str]) -> None:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

except ImportError:  # Windows
    import msvcrt

    def _lock(handle: IO[str], deadline: float | None = None) -> None:
        # msvcrt locks a byte range, not the whole file; one byte is enough
        # because every locker targets the same offset of the same lock file.
        # Windows permits locking beyond EOF. Do not write a sentinel byte
        # before acquiring the lock: simultaneous first-openers can race that
        # write against an already-held byte-range lock and raise PermissionError.
        # LK_LOCK gives up after ~10s, so keep retrying until acquired.
        handle.seek(0)
        while True:
            try:
                check_deadline(deadline)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK if deadline is not None else msvcrt.LK_LOCK, 1)
                return
            except TimeoutError:
                raise
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                    raise
                time.sleep(min(.01, check_deadline(deadline) or .01))

    def _unlock(handle: IO[str]) -> None:
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)


def check_deadline(deadline: float | None) -> float | None:
    """Check an optional absolute monotonic budget without resetting it."""
    if deadline is None:
        return None
    if not math.isfinite(deadline):
        raise ValueError("deadline must be finite")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("vault admission/recovery deadline exceeded")
    return remaining


def inherited_deadline() -> float | None:
    """Read an active cockpit budget without importing the cockpit into core.

    The transport owns this ContextVar. A core-only CLI has no exchange budget;
    importing cockpit_client here would introduce control/client import cycles.
    """
    client = sys.modules.get(f"{__package__}.cockpit_client")
    budget = getattr(client, "_deadline", None)
    return None if budget is None else budget.get()


def check_inherited_deadline() -> float | None:
    return check_deadline(inherited_deadline())


@contextmanager
def admission_lock(lock):
    """Bound read-cache mutex admission only when an exchange budget exists."""
    remaining = check_inherited_deadline()
    acquired = lock.acquire() if remaining is None else lock.acquire(timeout=remaining)
    if not acquired:
        raise TimeoutError("control read-cache admission deadline exceeded")
    try:
        check_inherited_deadline()
        yield
    finally:
        lock.release()


@contextmanager
def exclusive_lock(lock_path: Path, *, deadline: float | None = None) -> Iterator[None]:
    check_deadline(deadline)
    # Never grant group/other write to a lock directory, whatever the ambient umask;
    # deployed units already run with UMask=0077.
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    # Same semantics as open("a+"), but the lock file is created 0644, not 0666 minus umask.
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o644)
    with os.fdopen(descriptor, "a+", encoding="utf-8") as handle:
        _lock(handle, deadline)
        try:
            check_deadline(deadline)
            yield
        finally:
            _unlock(handle)


@contextmanager
def vault_lock(vault_root: Path, *, deadline: float | None = None) -> Iterator[None]:
    """Serialize mutations to a single vault: the governed write lane
    (suggest/refine/promote/reject) and replica sync/promote all take this so
    concurrent moves cannot leave a suggestion in two lanes, and a sync cannot
    race a failover into a marker-less (bricked) vault. The lock file lives in
    .arvyx/, which never replicates."""
    with exclusive_lock(vault_root / ".arvyx" / "vault.lock", deadline=deadline):
        yield
