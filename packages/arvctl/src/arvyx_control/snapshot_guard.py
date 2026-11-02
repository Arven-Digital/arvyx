"""Canonical preparation as the trusted vault owner, lock held across copying."""
from contextlib import contextmanager
import math
import os
from pathlib import Path
import select
import signal
import stat
import time
from typing import Iterator

from .promotion_transaction import memory_mutation


def _remaining(deadline: float | None) -> float | None:
    if deadline is None:
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('snapshot preparation/capture budget exceeded')
    return remaining


def _read_until(descriptor: int, deadline: float | None) -> bytes:
    if deadline is not None:
        ready, _, _ = select.select([descriptor], [], [], _remaining(deadline))
        if not ready:
            raise TimeoutError('snapshot preparation/capture budget exceeded')
        _remaining(deadline)
    return os.read(descriptor, 1)


def _reap(pid: int, deadline: float | None, *, cancel: bool) -> tuple[int, bool]:
    """Bound normal shutdown by the attempt, then allow one second to reap.

    SIGKILL targets only our unreaped child. A kernel-uninterruptible child may
    outlive this grace; report that failure rather than block the caller forever.
    Durable recovery authority belongs to the original filesystem, not cleanup.
    """
    expired = False
    killing = cancel
    if cancel:
        os.kill(pid, signal.SIGKILL)
        deadline = time.monotonic() + 1
    if deadline is None:
        return os.waitpid(pid, 0)[1], False
    while True:
        found, status = os.waitpid(pid, os.WNOHANG)
        if found:
            return status, expired
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            if killing:
                raise TimeoutError('snapshot helper did not reap within cancellation grace')
            os.kill(pid, signal.SIGKILL)
            killing = expired = True
            deadline = time.monotonic() + 1
        else:
            time.sleep(min(.01, remaining))


@contextmanager
def snapshot_preparation(vault: Path, *, owner: tuple[int, int] | None = None,
                         deadline: float | None = None) -> Iterator[None]:
    """Use a credential-isolated lock holder, not process-wide temporary setuid.

    The vault directory is trusted operator-provisioned authority, not a state
    path inferred from a generic lock name. Privileged deployments may bind an
    explicit expected owner. No live lock inode is replaced or chowned.

    An absolute monotonic deadline covers lock admission, recovery, readiness,
    and lock-holder shutdown. Deadline-bearing calls isolate even same-owner
    recovery so cancellation never interrupts the parent's thread or changes
    process-wide credentials. Copying must observe the same deadline; an expired
    body cannot exit successfully. Omitted deadlines retain legacy behavior.
    """
    if deadline is not None:
        if not math.isfinite(deadline):
            raise ValueError('snapshot deadline must be finite')
        _remaining(deadline)
        if not hasattr(os, 'fork'):
            raise OSError('bounded snapshot preparation requires process isolation')
    vault = Path(vault).resolve(strict=True)
    info = vault.stat()
    if not stat.S_ISDIR(info.st_mode):
        raise OSError('snapshot vault is not a directory')
    authority = (info.st_uid, info.st_gid)
    if owner is not None and owner != authority:
        raise OSError('snapshot vault ownership differs from configured authority')
    drop_identity = (hasattr(os, 'geteuid') and os.geteuid() == 0
                     and authority != (os.geteuid(), os.getegid()))
    if deadline is None and not drop_identity:
        with memory_mutation(vault):
            yield
        return
    # Only the child drops identity. The privileged parent can still read/copy
    # the other snapshot stores; the child owns recovery and all its artifacts.
    ready_read, ready_write = os.pipe()
    try:
        release_read, release_write = os.pipe()
    except BaseException:
        os.close(ready_read)
        os.close(ready_write)
        raise
    try:
        pid = os.fork()
    except BaseException:
        for fd in (ready_read, ready_write, release_read, release_write):
            os.close(fd)
        raise
    if pid == 0:
        os.close(ready_read)
        os.close(release_write)
        code = 1
        try:
            # Do not run the snapshot parent's stage-cleanup signal handlers.
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            signal.signal(signal.SIGINT, signal.SIG_DFL)
            if drop_identity:
                os.setgroups([])
                os.setgid(authority[1])
                os.setuid(authority[0])
            _remaining(deadline)
            # Parent readiness waiting supervises the entire blocking context,
            # including flock, forget admission, and each recovery filesystem
            # operation. Cancellation leaves existing crash-recovery journals.
            with memory_mutation(vault, deadline=deadline):
                _remaining(deadline)
                os.write(ready_write, b'R')
                # EOF on parent death also releases the canonical lock.
                if _read_until(release_read, deadline) == b'D':
                    code = 0
        except BaseException:
            code = 1
        finally:
            os.close(ready_write)
            os.close(release_read)
            os._exit(code)
    os.close(ready_write)
    os.close(release_read)
    body_failed = False
    try:
        if _read_until(ready_read, deadline) != b'R':
            _remaining(deadline)
            raise OSError('vault-owner snapshot preparation failed')
        yield
        _remaining(deadline)
    except BaseException:
        body_failed = True
        raise
    finally:
        os.close(ready_read)
        try:
            os.write(release_write, b'D')
        except BrokenPipeError:
            pass
        finally:
            os.close(release_write)
            status, expired = _reap(pid, deadline, cancel=body_failed)
        if expired and not body_failed:
            raise TimeoutError('snapshot lock holder shutdown budget exceeded')
        if not body_failed:
            _remaining(deadline)
        if status != 0 and not body_failed:
            raise OSError('vault-owner snapshot lock holder failed during capture')
