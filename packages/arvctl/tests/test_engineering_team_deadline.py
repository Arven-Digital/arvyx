"""Exercise the real team handler and fleet/client consumers without listeners."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from arvyx_control import cockpit_web as web, control
from arvyx_control.cockpit_client import exchange_deadline
from arvyx_control.locks import exclusive_lock
from arvyx_control.replica_authority import authority_context
import os

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='fork-based fixtures are POSIX-only')


def handler(snapshot, monkeypatch):
    replies = []
    team = SimpleNamespace(read=lambda: {'availability': {'control': True}})
    request = SimpleNamespace(path='/api/team', server=SimpleNamespace(root=Path('/synthetic'), team=team),
        authorized=lambda: True, reply=lambda *a, **kw: replies.append((a, kw)))
    monkeypatch.setattr(web, 'snapshot', lambda root: snapshot)
    return request, replies


def test_offline_cached_sessions_never_trigger_delegation_probes(monkeypatch):
    request, replies = handler({'sessions': [
        {'id': 'a', 'online': False, 'status': 'running'},
        {'id': 'b', 'status': 'offline; last known running'}], 'host': 'synthetic'}, monkeypatch)
    probe = Mock(side_effect=AssertionError('offline sessions must not be probed'))
    monkeypatch.setattr(web, 'request', probe)
    web.DashboardHandler.do_GET(request)
    assert replies[0][0][0] == 200
    assert 'AMC control: available' in replies[0][0][1]['html']
    probe.assert_not_called()


def test_snapshot_delegation_none_is_authoritative_and_not_reprobed(monkeypatch):
    request, replies = handler({'sessions': [
        {'id': 'a', 'delegation': None, 'status': 'running'}], 'host': 'synthetic'}, monkeypatch)
    probe = Mock(side_effect=AssertionError('snapshot already contains delegation'))
    monkeypatch.setattr(web, 'request', probe)
    web.DashboardHandler.do_GET(request)
    assert replies[0][0][0] == 200
    probe.assert_not_called()


def test_remaining_delegation_reads_share_one_deadline(monkeypatch):
    from arvyx_control import cockpit_client as client
    clock = [100.0]
    request, replies = handler({'sessions': [{'id': 'a'}, {'id': 'b'}], 'host': 'synthetic'}, monkeypatch)
    calls = []
    def probe(*args, **kwargs):
        calls.append(kwargs['sid'])
        clock[0] += 3
        raise TimeoutError('synthetic endpoint exceeded remaining allowance')
    monkeypatch.setattr(client.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(web, 'request', probe)
    web.DashboardHandler.do_GET(request)
    assert calls == ['a']
    assert replies[0][0][0] == 503


def test_control_writer_lock_honors_inherited_dashboard_deadline(tmp_path):
    import os
    import select
    import signal
    import time
    state = tmp_path / 'events.jsonl'
    ready_r, ready_w = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(ready_r)
        try:
            with exclusive_lock(state.with_suffix('.jsonl.lock')):
                os.write(ready_w, b'R')
                time.sleep(10)
        finally:
            os._exit(0)
    os.close(ready_w)
    try:
        assert select.select([ready_r], [], [], 2)[0]
        assert os.read(ready_r, 1) == b'R'
        start = time.monotonic()
        with authority_context(tmp_path / 'vault', state), exchange_deadline(.1), pytest.raises(TimeoutError):
            with control._locked_state(state):
                pytest.fail('contended control lock must not admit late')
        assert time.monotonic() - start < 1
    finally:
        os.close(ready_r)
        os.kill(child, signal.SIGKILL)
        os.waitpid(child, 0)
