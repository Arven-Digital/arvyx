"""R10 regression source. NOT_EXECUTED: only AST syntax inspected."""
import io
import json
from unittest.mock import patch

import pytest
from safe_mcp_bridge import cli

CONFIG = {'policy': {'allow_tools': ['memory.promote']}}
BAD = [None, [], {}, {'jsonrpc': '1.0', 'id': 1, 'result': {}},
       {'jsonrpc': '2.0', 'result': {}},
       {'jsonrpc': '2.0', 'id': '1', 'result': {}},
       {'jsonrpc': '2.0', 'id': True, 'result': {}},
       {'jsonrpc': '2.0', 'id': 1.0, 'result': {}},
       {'jsonrpc': '2.0', 'id': 1},
       {'jsonrpc': '2.0', 'id': 1, 'result': {}, 'error': {}},
       {'jsonrpc': '2.0', 'id': 1, 'method': 'ping', 'result': {}},
       *[{'jsonrpc': '2.0', 'id': 1, 'error': e} for e in
         (None, [], {}, {'code': True, 'message': 'bad'}, {'code': -1})]]


@pytest.mark.parametrize('bad', BAD)
def test_bad_envelope_is_correlated_and_not_replayed(bad, monkeypatch, capsys):
    frames = [{'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
               'params': {'name': 'memory.promote', 'arguments': {'idempotency_key': 'original'}}},
              {'jsonrpc': '2.0', 'id': 2, 'method': 'ping'}]
    monkeypatch.setattr(cli.sys, 'stdin', io.StringIO('\n'.join(map(json.dumps, frames)) + '\n'))
    with patch.object(cli, '_post_json', side_effect=[bad, {'jsonrpc': '2.0', 'id': 2, 'result': {}}]) as post:
        assert cli._run(CONFIG) == 0
    replies = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert replies[0]['id'] == 1
    assert replies[0]['error']['code'] == -32000
    assert 'outcome uncertain; nothing retried' in replies[0]['error']['message']
    assert replies[1] == {'jsonrpc': '2.0', 'id': 2, 'result': {}}
    assert post.call_count == 2
    assert post.call_args_list[0].args[1] == frames[0]


@pytest.mark.parametrize('bad', BAD)
def test_notification_silence(bad):
    with patch.object(cli, '_post_json', return_value=bad) as post:
        assert cli._handle_line(CONFIG, '{"jsonrpc":"2.0","method":"ping"}') is None
    post.assert_called_once()


@pytest.mark.parametrize('result', [None, [], 'bad', {}, {'tools': None}, {'tools': {}}, {'tools': 'bad'}])
def test_doctor_malformed_containers_are_controlled(result):
    response = {'jsonrpc': '2.0', 'id': 'doctor-tools', 'result': result}
    with patch.object(cli, '_post_json', return_value=response) as post:
        with pytest.raises(cli.BridgeError, match='invalid upstream tools/list result'):
            cli._doctor(CONFIG)
    post.assert_called_once()


@pytest.mark.parametrize('request_id', [None, 'client', 1, 1.5])
@pytest.mark.parametrize('body', [{'result': None}, {'error': {'code': -1, 'message': 'rejected', 'data': {}}}])
def test_valid_correlated_success_and_error(request_id, body):
    response = {'jsonrpc': '2.0', 'id': request_id, **body}
    with patch.object(cli, '_post_json', return_value=response):
        assert cli._handle_line(CONFIG, json.dumps({'jsonrpc': '2.0', 'id': request_id, 'method': 'ping'})) == response


def test_post_json_validates_real_decoded_envelope_without_network():
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, limit): return b'{"jsonrpc":"2.0","id":"wrong","result":{}}'
    with patch.object(cli._OPENER, 'open', return_value=Response()) as post:
        with pytest.raises(cli.BridgeError, match='uncorrelated'):
            cli._post_json({'target': {'url': 'http://example.invalid/mcp'}},
                           {'jsonrpc': '2.0', 'id': 1, 'method': 'ping'})
    post.assert_called_once()
