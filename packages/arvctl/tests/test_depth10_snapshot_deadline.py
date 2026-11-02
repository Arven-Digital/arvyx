"""Deadline regressions authored for D10-01-001. NOT_EXECUTED."""
from contextlib import contextmanager
import os
from pathlib import Path
import select
import signal
import time

import pytest

from arvyx_control import locks, snapshot_guard as guard
from arvyx_control import promotion_transaction as tx

pytestmark = pytest.mark.skipif(not hasattr(os, 'fork'), reason='POSIX helper contract')


def _identity(path):
    st = path.stat()
    return st.st_dev, st.st_ino, st.st_uid, st.st_gid


def test_real_lock_contention_expires_without_inode_replacement(tmp_path):
    vault = tmp_path / 'vault'
    vault.mkdir()
    ready_r, ready_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(ready_r)
        try:
            with locks.vault_lock(vault):
                os.write(ready_w, b'R')
                time.sleep(10)
        finally:
            os._exit(0)
    os.close(ready_w)
    try:
        assert select.select([ready_r], [], [], 2)[0]
        assert os.read(ready_r, 1) == b'R'
        lock = vault / '.arvyx/vault.lock'
        before = _identity(lock)
        started = time.monotonic()
        with pytest.raises(TimeoutError):
            with locks.vault_lock(vault, deadline=started + .1):
                pytest.fail('contended lock admitted')
        assert time.monotonic() - started < 2
        assert _identity(lock) == before
    finally:
        os.close(ready_r)
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)


@pytest.mark.parametrize('drop_owner', [False, True])
def test_helper_recovery_timeout_reaped_and_prior_pointer_unchanged(tmp_path, monkeypatch, drop_owner):
    if drop_owner and os.geteuid() != 0:
        pytest.skip('root-to-owner boundary requires root')
    # Never change shared ancestor permissions for a regression fixture.
    if drop_owner:
        if any(not (directory.stat().st_mode & 0o001) for directory in tmp_path.parents):
            pytest.skip('owner boundary requires traversable test ancestors')
        tmp_path.chmod(0o755)
    vault = tmp_path / 'vault'
    vault.mkdir()
    (vault / '.arvyx').mkdir()
    lock = vault / '.arvyx/vault.lock'
    lock.touch()
    if drop_owner:
        for path in (vault, vault / '.arvyx', lock):
            os.chown(path, 10001, 10001)
    prior = tmp_path / 'current'
    prior.symlink_to('previous-snapshot')
    witness = vault / '.arvyx/journal-witness'
    witness.write_bytes(b'recovery authority retained')
    before = _identity(lock)
    pids = []
    real_fork = os.fork

    def recording_fork():
        pid = real_fork()
        if pid:
            pids.append(pid)
        return pid

    @contextmanager
    def blocked_recovery(root, *, deadline=None):
        assert deadline is not None
        with locks.vault_lock(root, deadline=deadline):
            time.sleep(10)  # emulate blocked recovery I/O before readiness
            yield

    monkeypatch.setattr(guard, 'memory_mutation', blocked_recovery)
    monkeypatch.setattr(guard.os, 'fork', recording_fork)
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        with guard.snapshot_preparation(vault, owner=(vault.stat().st_uid, vault.stat().st_gid),
                                        deadline=started + .15):
            pytest.fail('copy entered before preparation')
    assert time.monotonic() - started < 2
    assert len(pids) == 1
    with pytest.raises(ChildProcessError):
        os.waitpid(pids[0], os.WNOHANG)
    assert _identity(lock) == before
    assert witness.read_bytes() == b'recovery authority retained'
    assert os.readlink(prior) == 'previous-snapshot'


def test_expired_recovery_does_not_retire_journal(tmp_path):
    journal = tmp_path / '.arvyx/promotions/prepared'
    journal.mkdir(parents=True)
    manifest = journal / 'manifest.json'
    manifest.write_text('{"schema": 1, "files": []}')
    with pytest.raises(TimeoutError):
        tx.recover(tmp_path, deadline=time.monotonic() - 1)
    assert manifest.exists()


def test_legacy_no_deadline_same_owner_remains_in_process(tmp_path, monkeypatch):
    events = []

    @contextmanager
    def legacy(root):
        events.append('enter')
        yield
        events.append('exit')

    monkeypatch.setattr(guard, 'memory_mutation', legacy)
    with guard.snapshot_preparation(tmp_path):
        events.append('copy')
    assert events == ['enter', 'copy', 'exit']
