"""Lane 01 deadline regressions: disposable vaults, no native/service starts."""
from contextlib import contextmanager
import fcntl
import importlib.util
import inspect
import json
import os
from pathlib import Path
import signal
import time
from unittest.mock import patch

import pytest

from arvyx_control import promotion_transaction as tx
from arvyx_control import snapshot_guard as guard
from arvyx_control.locks import vault_lock

_fixture_fork = os.fork


@pytest.fixture
def children(monkeypatch):
    """Record only this guard's fixture children; never reap unrelated workers."""
    fork = os.fork
    pids = []

    def tracked_fork():
        pid = fork()
        if pid:
            pids.append(pid)
        return pid

    monkeypatch.setattr(guard.os, 'fork', tracked_fork)
    yield pids
    for pid in pids:
        try:
            if os.waitpid(pid, os.WNOHANG)[0] == 0:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
        except ProcessLookupError:
            pass
        except ChildProcessError:
            pass


def assert_reaped(pids):
    assert pids
    for pid in pids:
        with pytest.raises(ChildProcessError):
            os.waitpid(pid, os.WNOHANG)


def lock_identity(vault):
    info = (vault / '.arvyx/vault.lock').stat()
    return info.st_dev, info.st_ino, info.st_uid, info.st_gid


@contextmanager
def held_lock(vault):
    """A separate fixture process holds the real canonical lock until released."""
    ready_r, ready_w = os.pipe()
    done_r, done_w = os.pipe()
    pid = _fixture_fork()
    if pid == 0:
        os.close(ready_r)
        os.close(done_w)
        try:
            with vault_lock(vault):
                os.write(ready_w, b'R')
                os.read(done_r, 1)
        finally:
            os._exit(0)
    os.close(ready_w)
    os.close(done_r)
    try:
        assert os.read(ready_r, 1) == b'R'
        yield
    finally:
        os.close(done_w)
        os.close(ready_r)
        os.waitpid(pid, 0)


@pytest.mark.parametrize('owner_helper', [False, True])
def test_lock_wait_deadline_reaps_helper_without_touching_lock(tmp_path, children, owner_helper):
    with held_lock(tmp_path):
        before = lock_identity(tmp_path)
        # Exercise root-to-owner control flow without any actual setuid/chown.
        with patch.object(guard.os, 'geteuid', return_value=0 if owner_helper else os.getuid()), \
                patch.object(guard.os, 'setgroups', create=True), \
                patch.object(guard.os, 'setgid'), patch.object(guard.os, 'setuid'):
            started = time.monotonic()
            with pytest.raises(TimeoutError):
                with guard.snapshot_preparation(tmp_path, deadline=started + .15):
                    pytest.fail('copy admitted while another process holds the lock')
            assert time.monotonic() - started < 1.5
        assert lock_identity(tmp_path) == before
        assert_reaped(children)


def test_slow_recovery_is_bounded_before_readiness(tmp_path, children):
    original = tx.recover

    def delayed(vault, *, deadline=None):
        time.sleep(.6)
        original(vault, deadline=deadline)

    # The fallback makes the historical missing-budget behavior executable,
    # instead of RED being only an unexpected-keyword error.
    kwargs = {'deadline': time.monotonic() + .12} if 'deadline' in inspect.signature(guard.snapshot_preparation).parameters else {}
    with patch.object(tx, 'recover', delayed):
        started = time.monotonic()
        with pytest.raises(TimeoutError):
            with guard.snapshot_preparation(tmp_path, **kwargs):
                pass
        assert time.monotonic() - started < .5
    assert_reaped(children)


def test_interrupted_recovery_retains_journal_for_original_filesystem_retry(tmp_path, children):
    target = tmp_path / 'note.md'
    target.write_bytes(b'published')
    journal = tmp_path / '.arvyx/promotions/prepared'
    journal.mkdir(parents=True)
    (journal / 'original').write_bytes(b'original')
    info = target.stat()
    row = dict(path='note.md', backup='original', original=[info.st_dev, 0, tx.identity(journal / 'original')[2]],
               published=tx.identity(target), source=False, stage=str(tmp_path / '.stage'),
               uid=info.st_uid, gid=info.st_gid, mode=0o600)
    (journal / 'manifest.json').write_text(json.dumps(dict(files=[row])))
    restore = tx.restoration

    def delayed(*args):
        (journal / 'entered').write_bytes(b'yes')
        time.sleep(2)
        return restore(*args)

    with patch.object(tx, 'restoration', delayed):
        with pytest.raises(TimeoutError):
            with guard.snapshot_preparation(tmp_path, deadline=time.monotonic() + .25):
                pytest.fail('unfinished recovery admitted')
    assert (journal / 'entered').exists()
    assert (journal / 'manifest.json').exists()
    assert (journal / 'original').read_bytes() == b'original'
    before = lock_identity(tmp_path)
    with guard.snapshot_preparation(tmp_path, deadline=time.monotonic() + 2):
        assert target.read_bytes() == b'original'
    assert not journal.exists()
    assert lock_identity(tmp_path) == before
    assert_reaped(children)


def test_copy_keeps_lock_and_original_body_error(tmp_path, children):
    class CopyFailure(Exception):
        pass

    with pytest.raises(CopyFailure):
        with guard.snapshot_preparation(tmp_path, deadline=time.monotonic() + 2):
            with (tmp_path / '.arvyx/vault.lock').open('a+') as handle:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            raise CopyFailure('fixture copy failed')
    with (tmp_path / '.arvyx/vault.lock').open('a+') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    assert_reaped(children)


def test_stopped_ready_helper_is_killed_and_reaped_on_deadline(tmp_path, children):
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        with guard.snapshot_preparation(tmp_path, deadline=started + .2):
            os.kill(children[-1], signal.SIGSTOP)
    assert time.monotonic() - started < 1.5
    assert_reaped(children)


def test_expired_capture_body_is_not_accepted(tmp_path, children):
    with pytest.raises(TimeoutError):
        with guard.snapshot_preparation(tmp_path, deadline=time.monotonic() + .1):
            time.sleep(.2)
    assert_reaped(children)


def test_expiry_during_reaping_cannot_return_success(tmp_path, children, monkeypatch):
    parent = os.getpid()
    sleep = time.sleep
    mutation = guard.memory_mutation

    @contextmanager
    def delayed_shutdown(vault, *, deadline=None):
        with mutation(vault, deadline=deadline):
            yield
            sleep(.03)

    def descheduled_poll(delay):
        # Model the parent being descheduled while the real helper exits.
        sleep(.15 if os.getpid() == parent else delay)

    monkeypatch.setattr(guard, 'memory_mutation', delayed_shutdown)
    monkeypatch.setattr(guard.time, 'sleep', descheduled_poll)
    with pytest.raises(TimeoutError):
        with guard.snapshot_preparation(tmp_path, deadline=time.monotonic() + .1):
            pass
    assert_reaped(children)


@pytest.mark.parametrize('deadline', [float('nan'), float('inf'), -float('inf')])
def test_invalid_deadline_creates_no_lock(tmp_path, deadline):
    with pytest.raises(ValueError):
        with guard.snapshot_preparation(tmp_path, deadline=deadline):
            pytest.fail('invalid deadline admitted')
    assert not (tmp_path / '.arvyx').exists()


def test_existing_owner_and_forget_fences_remain(tmp_path, children):
    info = tmp_path.stat()
    with pytest.raises(OSError, match='configured authority'):
        with guard.snapshot_preparation(tmp_path, owner=(info.st_uid + 1, info.st_gid), deadline=time.monotonic() + 1):
            pytest.fail('wrong owner admitted')
    lane = tmp_path / '.arvyx/forget-operations'
    lane.mkdir(parents=True)
    (lane / ('a' * 64 + '.intent.json')).write_text('{}')
    with pytest.raises(OSError, match='preparation failed'):
        with guard.snapshot_preparation(tmp_path, deadline=time.monotonic() + 1):
            pytest.fail('invalid forget intent admitted')
    assert_reaped(children)


def test_legacy_same_owner_call_remains_synchronous(tmp_path):
    with patch.object(guard.os, 'fork', side_effect=AssertionError('unexpected fork')):
        with guard.snapshot_preparation(tmp_path):
            assert (tmp_path / '.arvyx/vault.lock').is_file()


def test_capture_retry_cleanup_with_real_deadline_wiring(tmp_path, children, monkeypatch):
    """Actual production capture loop forwards its deadline to the real guard."""
    source = Path(__file__).resolve().parents[3] / 'deploy/systemd/arvyx-v2-snapshot.py'
    if not source.is_file():
        pytest.skip('deployment snapshot script is not part of this checkout (public candidate)')
    spec = importlib.util.spec_from_file_location('deep10fix01_capture', source)
    capture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(capture)
    vault = tmp_path / 'vault'
    vault.mkdir()
    work = tmp_path / 'work'
    work.mkdir()
    current = tmp_path / 'current'
    current.symlink_to('prior-snapshot')
    monkeypatch.setattr(capture, 'DATA', tmp_path)
    monkeypatch.setattr(capture, 'LOCK_HOLD', .1)
    monkeypatch.setenv('ARVYX_V2_VAULT_UID', str(vault.stat().st_uid))
    monkeypatch.setenv('ARVYX_V2_VAULT_GID', str(vault.stat().st_gid))
    with held_lock(vault):
        before = lock_identity(vault)
        with patch.object(capture, 'manifest', side_effect=AssertionError('copy before readiness')):
            with pytest.raises(RuntimeError, match='after 2 attempts'):
                capture.capture_stable(work, max_attempts=2, retry_sleep=lambda _: None)
        assert lock_identity(vault) == before
    assert not (work / 'data').exists()
    assert os.readlink(current) == 'prior-snapshot'
    assert_reaped(children)
