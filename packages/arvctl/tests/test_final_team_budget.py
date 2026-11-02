"""REV-0452 regression candidates. Not executed in the source-only fix lane."""
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from arvyx_control import cockpit, cockpit_client as client
from arvyx_control.cockpit_team import TeamAuthority
from arvyx_control.cockpit_transport import Endpoint


@pytest.mark.parametrize('budget', [None, True, False, 0, -1, 6, float('inf'), float('nan'), '1', 10**500])
def test_invalid_wire_budget_never_dispatches(budget):
    dispatch = SimpleNamespace(snapshot=MagicMock())
    service = SimpleNamespace(host='local', state=Path('/state'))
    raw = json.dumps({'operation': 'snapshot', 'actor': 'operator', '_budget_seconds': budget}).encode()
    with patch.object(client, 'receive_frame', return_value=raw), patch.object(client, 'send_frame'):
        cockpit.handle_connection(object(), service, dispatch)
    dispatch.snapshot.assert_not_called()


def test_owner_charges_receipt_and_strips_budget_before_strict_dispatch():
    clock = [100.0]
    observed = []
    def receive(*args):
        clock[0] += .2
        return b'{"operation":"snapshot","actor":"operator","_budget_seconds":0.7}'
    def snapshot(*, actor):
        observed.append((actor, client.checkpoint()))
        return {}
    service = SimpleNamespace(host='local', state=Path('/state'))
    with patch.object(client.time, 'monotonic', side_effect=lambda: clock[0]), \
         patch.object(client, 'receive_frame', side_effect=receive), patch.object(client, 'send_frame'):
        cockpit.handle_connection(object(), service, SimpleNamespace(snapshot=snapshot))
    assert observed[0][0] == 'operator'
    assert observed[0][1] == pytest.approx(.5)


def test_old_client_without_metadata_keeps_owner_default():
    observed = []
    def snapshot(*, actor):
        observed.append(client.checkpoint())
        return {}
    with patch.object(client.time, 'monotonic', return_value=100.0), \
         patch.object(client, 'receive_frame', return_value=b'{"operation":"snapshot","actor":"operator"}'), \
         patch.object(client, 'send_frame'):
        cockpit.handle_connection(object(), SimpleNamespace(host='local', state=Path('/state')),
                                  SimpleNamespace(snapshot=snapshot))
    assert observed == [cockpit.OWNER_TIMEOUT]


def test_real_exchange_writes_shrinking_budget_after_connect():
    clock = [100.0]
    sock = MagicMock()
    sock.__enter__.return_value = sock
    sock.connect.side_effect = lambda endpoint: clock.__setitem__(0, clock[0] + .2)
    sock.recv.return_value = b'{"ok":true,"result":{}}\n'
    with patch.object(client.time, 'monotonic', side_effect=lambda: clock[0]), \
         patch.object(client.socket, 'socket', return_value=sock):
        with client.exchange_deadline(.8):
            client.request(Path('/private'), 'snapshot', actor='operator')
    envelope = json.loads(sock.sendall.call_args.args[0])
    assert envelope['_budget_seconds'] == pytest.approx(.6)
    assert envelope['operation'] == 'snapshot'


def test_endpoint_preflight_does_not_renew_operation_budget():
    clock = [100.0]
    observed = []
    def request(root, operation, **fields):
        observed.append(client.checkpoint())
        clock[0] += .2
        return {'host': 'remote', 'state': '/state'}
    with patch.object(client.time, 'monotonic', side_effect=lambda: clock[0]), \
         patch('arvyx_control.cockpit_transport.request', side_effect=request):
        with client.exchange_deadline(.8):
            Endpoint(Path('/private'), 'remote', '/state').call('delegation', sid='x', actor='operator')
    assert observed == pytest.approx([.8, .6])


def test_team_expiry_prevents_next_local_api_dispatch():
    clock = [100.0]
    calls = []
    def api(method, path, body, **fields):
        calls.append(path)
        clock[0] += .6
        return SimpleNamespace(status=200, body={})
    with patch.object(client.time, 'monotonic', side_effect=lambda: clock[0]), \
         patch('arvyx_control.cockpit_team.handle_api_request', side_effect=api):
        with client.exchange_deadline(.5), pytest.raises(TimeoutError):
            TeamAuthority(Path('/vault'), Path('/state')).read()
    assert calls == ['/control-plane']


def test_fleet_exhausted_fanout_uses_cache_without_later_endpoint_calls():
    import threading
    from arvyx_control.cockpit_fleet import FleetCockpit
    clock = [100.0]
    db = MagicMock()
    db.execute.return_value.fetchone.return_value = {'snapshot': json.dumps({'sessions': []})}
    owner = SimpleNamespace(host='local', lock=threading.RLock(), db=db, _human=MagicMock(),
                            snapshot=lambda **kw: {'host': 'local', 'sessions': [],
                                                  'operator_status': {'delegations': {}}})
    first, later = MagicMock(), MagicMock()
    def stall(*args, **fields):
        clock[0] += 1.1
        raise TimeoutError('endpoint expired')
    first.call.side_effect = stall
    fleet = object.__new__(FleetCockpit)
    fleet.owner, fleet.endpoints = owner, {'a': first, 'b': later}
    fleet.view = lambda: {}
    with patch.object(client.time, 'monotonic', side_effect=lambda: clock[0]):
        with client.exchange_deadline(2):
            result = fleet.snapshot(actor='operator')
    first.call.assert_called_once()
    later.call.assert_not_called()
    assert result['hosts'][1]['online'] is False
    assert result['hosts'][2]['online'] is False
