from arvyx_control.local_executor import ExecutionPolicy
"""Offline regressions; every fork/launch boundary is replaced. Not yet run."""
import os
from pathlib import Path
import sqlite3
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from arvyx_control.agent_sessions import RoutingError
from arvyx_control.cockpit import LocalCockpit
from arvyx_control.cockpit_client import initialize
from arvyx_control.cockpit_native_runtime import NativeRuntime
from arvyx_control.hermes_history import HermesHistory
from arvyx_control.hermes_profile import HermesProfile
from arvyx_control.replica_authority import authority_context
from arvyx_control.control import create_task


@pytest.fixture
def profile(tmp_path, monkeypatch):
    home = tmp_path/'profile'
    home.mkdir(mode=0o700)
    workspace = tmp_path/'workspace'
    workspace.mkdir()
    with sqlite3.connect(home/'state.db') as db:
        db.execute('CREATE TABLE sessions(id TEXT,cwd TEXT,end_reason TEXT)')
        db.executemany('INSERT INTO sessions VALUES(?,?,NULL)', [('one', str(workspace)), ('two', str(workspace))])
    # Only admission tests explicitly supply synthetic proc data below.
    monkeypatch.setattr(HermesProfile, 'assert_idle', lambda *a, **k: None)
    return HermesProfile(home), workspace


@pytest.mark.parametrize('other', ['one', 'two'])
def test_profile_wide_reservation_shared_between_history_and_configured(profile, other):
    selected, workspace = profile
    runtime = NativeRuntime(tool='hermes', executable='/usr/bin/python3', home=selected.home, store=selected.store)
    history = HermesHistory(selected.home, executable='/usr/bin/python3')
    reservation = history.profile.reserve('one')
    try:
        assert reservation.conversation == 'one'
        with pytest.raises(RoutingError, match='reserved'):
            runtime.reserve(other)
        # Read-only planning/metadata remains possible; no provider is launched.
        runtime.plan(other, workspace)
    finally:
        reservation.release()
    replacement = runtime.reserve(other)
    replacement.release()


@pytest.mark.parametrize('unreadable', [False, True])
def test_external_profile_writer_or_unknown_liveness_refuses(tmp_path, monkeypatch, unreadable):
    import arvyx_control.hermes_profile as module
    home = tmp_path/'profile'
    home.mkdir(mode=0o700)
    selected = HermesProfile(home)
    proc = tmp_path/'proc'
    proc.mkdir()
    entry = proc/str(os.getpid()+100000)
    entry.mkdir()
    (entry/'environ').write_bytes(b'HERMES_HOME='+os.fsencode(home)+b'\0')
    original_read = Path.read_bytes
    if unreadable:
        def read(path):
            if path == entry/'environ':
                raise PermissionError('synthetic inaccessible writer')
            return original_read(path)
        monkeypatch.setattr(Path, 'read_bytes', read)
    monkeypatch.setattr(module, 'Path', lambda p: proc if p == '/proc' else Path(p))
    with pytest.raises(RoutingError, match='live process|cannot verify'):
        selected.reserve('one', default_home=home)


@pytest.fixture
def owner(profile, tmp_path):
    selected, workspace = profile
    root = tmp_path/'owner'
    initialize(root)
    runtime = NativeRuntime(tool='hermes', executable='/usr/bin/python3', home=selected.home, store=selected.store)
    service = LocalCockpit(root/'runtime', root/'vault', root/'events.jsonl', 'fixture', native_runtimes={'hermes': runtime}, execution_policy=ExecutionPolicy(host_uid=__import__("os").geteuid(), allow_host=True))
    ids = []
    for name in ('one', 'two'):
        with authority_context(service.vault, service.state):
            task = create_task(service.state, name, owner='demobot').task
        row = service.open(project='demo-agent', task=task.id, name=name, workspace=workspace, actor='operator')
        service.bind_native(row['id'], tool='hermes', conversation='one', actor='operator')
        ids.append(row['id'])
    yield service, ids, runtime
    service.close()


@pytest.fixture
def inert_process(owner, monkeypatch):
    """No process proof is manufactured in production; these are test doubles."""
    service, ids, runtime = owner
    import pty
    real_pipe2 = os.pipe2
    handshake = {}
    def pipe2(flags):
        pair = real_pipe2(flags)
        handshake['write'] = pair[1]
        return pair
    def forked():
        os.write(handshake['write'], b'X')
        return 43210, 123456
    monkeypatch.setattr(os, 'pipe2', pipe2)
    monkeypatch.setattr(os, 'waitid', lambda *args: None)
    fork = Mock(side_effect=forked)
    monkeypatch.setattr(pty, 'fork', fork)
    monkeypatch.setattr(os, 'set_blocking', lambda *a: None)
    original_close = os.close
    monkeypatch.setattr(os, 'close', lambda fd: None if fd == 123456 else original_close(fd))
    def terminate(live):
        live['stop'].set()
        live['terminated'] = True
    monkeypatch.setattr(service, '_terminate', terminate)
    class Pump:
        ident = None
        def __init__(self, **kwargs):
            self.alive = False
        def start(self):
            self.ident = 1
            self.alive = True
        def join(self, timeout=None):
            assert not service.lock._is_owned(), 'join under owner lock deadlocks the real pump'
            self.alive = False
        def is_alive(self):
            return self.alive
    monkeypatch.setattr(threading, 'Thread', Pump)
    return fork


def test_two_configured_sessions_only_first_reaches_fork(owner, inert_process):
    service, (one, two), runtime = owner
    service.start_native(one, actor='operator', allow_provider=True, environment='host')
    with pytest.raises(RoutingError, match='reserved'):
        service.start_native(two, actor='operator', allow_provider=True, environment='host')
    assert inert_process.call_count == 1
    service.end(one, actor='operator')
    service.start_native(two, actor='operator', allow_provider=True, environment='host')
    assert inert_process.call_count == 2


def test_failed_publication_joins_outside_lock_before_retry(owner, inert_process):
    service, (sid, _), runtime = owner
    service.db.execute("CREATE TRIGGER fail_publish BEFORE INSERT ON cleanup_ownership WHEN NEW.pid>0 BEGIN SELECT RAISE(ABORT,'injected publication'); END")
    with pytest.raises(sqlite3.IntegrityError):
        service.start_native(sid, actor='operator', allow_provider=True, environment='host')
    old = service.live[sid]
    assert old['retired'] and old['terminated']
    assert not old['thread'].is_alive()
    assert old['reservation'] is None
    assert not service.starting
    service.db.execute('DROP TRIGGER fail_publish')
    service.db.commit()
    service.start_native(sid, actor='operator', allow_provider=True, environment='host')
    assert service.live[sid] is not old
    assert service._get(sid)['status'] == 'running'


def test_stale_finalizer_cannot_update_replacement(owner, monkeypatch):
    service, (sid, _), runtime = owner
    import arvyx_control.cockpit as module
    stale = dict(fd=123456, input=bytearray(), input_lock=threading.Lock(),
                 input_error=None, discarded_bytes=0, capture_error=None,
                 recorder=SimpleNamespace(finish=Mock()))
    current = dict(pid=98765, fd=None)
    service.live[sid] = current
    service.db.execute("UPDATE sessions SET status='running',pid=98765 WHERE id=?", (sid,))
    service.db.execute("INSERT INTO delegations VALUES(?, 'rowan', 'goal', 'limits', 9, 0, 'active', NULL)", (sid,))
    service.db.commit()
    monkeypatch.setattr(module.select, 'select', lambda *a: ([123456], [], []))
    monkeypatch.setattr(os, 'read', lambda *a: b'')
    original_close = os.close
    monkeypatch.setattr(os, 'close', lambda fd: None if fd == 123456 else original_close(fd))
    service._pump(sid, stale)
    assert service._get(sid)['status'] == 'running'
    assert service._get(sid)['pid'] == 98765
    delegation = service.delegation(sid, actor='operator')
    assert delegation['generation'] == 9 and delegation['status'] == 'active'
    assert service.live.pop(sid) is current


def test_retry_is_refused_while_failed_start_is_joining(owner, monkeypatch):
    service, (sid, _), runtime = owner
    joined = Mock()
    def failed_start(*a, **k):
        service.live[sid] = dict(terminated=True, thread=SimpleNamespace(ident=1))
        raise RuntimeError('publication failed')
    def retire(sid, live):
        assert not service.lock._is_owned()
        with pytest.raises(ValueError, match='in progress'):
            service.start_native(sid, actor='operator', allow_provider=True, environment='host')
        joined()
        service.live.pop(sid)
    monkeypatch.setattr(service, '_start_locked', failed_start)
    monkeypatch.setattr(service, '_terminate', lambda live: None)
    monkeypatch.setattr(service, '_retire_live', retire)
    with pytest.raises(RuntimeError, match='publication failed'):
        service.start_native(sid, actor='operator', allow_provider=True, environment='host')
    joined.assert_called_once()
