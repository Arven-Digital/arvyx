"""Private candidate-12 bridge regressions; synthetic data only."""
import io
import json
import time
from statistics import median

import pytest
from safe_mcp_bridge import cli


@pytest.mark.parametrize('detector', [cli._FALLBACK_SECRET_RE, cli._secret_re()])
def test_postgres_failed_prefix_scaling(detector):
    def elapsed(n):
        text = 'postgres://u:' * n
        samples = []
        for _ in range(3):
            start = time.process_time()
            assert cli.bounded_secret_subn(text, detector) == (text, 0)
            samples.append(time.process_time() - start)
        return median(samples)
    small = elapsed(1000)
    large = elapsed(4000)
    assert large < max(small * 8, 0.08), (small, large)


@pytest.mark.parametrize('url', [
    'postgres://u:p@host/db',
    'POSTGRESQL://u:p:with:colons@host/db',
    'postgres://u:postgres://nested:password@host/db',
])
def test_postgres_positive_matches_preserved(url):
    assert cli.bounded_secret_subn(url, cli._FALLBACK_SECRET_RE) == ('[REDACTED-SECRET]', 1)


@pytest.mark.parametrize('secret', ['quoted"back\\slash', 'line\nbreak\tvalue', 'unicode-\u00e9-value'])
def test_configured_escaped_secret_blocked_request_audit(tmp_path, monkeypatch, secret):
    monkeypatch.setenv('SOL13_SYNTHETIC_AUTH', secret)
    path = tmp_path / 'audit.jsonl'
    config = {'policy': {'allow_tools': []}, 'auth': {'env': 'SOL13_SYNTHETIC_AUTH'},
              'audit': {'path': str(path), 'redact': True}}
    response = cli._handle_line(config, json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'blocked/' + secret}))
    assert response['error']['code'] == cli.BLOCKED_METHOD_CODE
    event = json.loads(path.read_text())
    assert event['method'] == 'blocked/[redacted]'
    nested = cli._redact(config, {secret: [{'value': secret}], 'count': 2})
    assert nested == {'[redacted]': [{'value': '[redacted]'}], 'count': 2}


def test_missing_jsonrpc_rejected_before_policy_audit(tmp_path):
    path = tmp_path / 'audit.jsonl'
    config = {'policy': {'allow_tools': []}, 'audit': {'path': str(path), 'redact': True}}
    response = cli._handle_line(config, json.dumps({'id': 1, 'method': 'blocked/synthetic'}))
    assert response['error']['code'] == -32600
    assert not path.exists()


@pytest.mark.parametrize('name', [[], {}, None, 1, True])
def test_malformed_catalog_does_not_terminate_stdio(monkeypatch, capsys, name):
    config = {'policy': {'allow_tools': ['safe']}}
    def upstream(config, payload):
        if payload['method'] == 'tools/list':
            return {'jsonrpc': '2.0', 'id': payload['id'], 'result': {'tools': [
                {'name': name}, {'name': 'safe'}, {'name': 'blocked'}, None]}}
        return {'jsonrpc': '2.0', 'id': payload['id'], 'result': {}}
    monkeypatch.setattr(cli, '_post_json', upstream)
    monkeypatch.setattr(cli.sys, 'stdin', io.StringIO(
        json.dumps({"jsonrpc": "2.0", 'id': 1, 'method': 'tools/list'}) + '\n' +
        json.dumps({"jsonrpc": "2.0", 'id': 2, 'method': 'ping'}) + '\n'))
    assert cli._run(config) == 0
    responses = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert responses == [{'jsonrpc': '2.0', 'id': 1, 'result': {'tools': [{'name': 'safe'}]}},
                         {'jsonrpc': '2.0', 'id': 2, 'result': {}}]
