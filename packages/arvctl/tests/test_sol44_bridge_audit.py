"""Scoped audit-sink regressions. Synthetic strings only; NOT_EXECUTED."""
import json

import pytest
from safe_mcp_bridge import cli


@pytest.mark.parametrize('detector', [cli._FALLBACK_SECRET_RE, cli._secret_re()])
@pytest.mark.parametrize('kind', ['method', 'tool'])
@pytest.mark.parametrize('redact', [True, False, None])
def test_rejected_metadata_audit_redaction(tmp_path, monkeypatch, detector, kind, redact):
    monkeypatch.setattr(cli, '_secret_re', lambda: detector)
    bearer = 'fixture"with\\escapes\nand-unicode-\u00e9'
    shaped = 'sk-' + 'syntheticfixtureonly' * 2
    monkeypatch.setenv('SOL44_FIXTURE_AUTH', bearer)
    path = tmp_path / 'audit.jsonl'
    audit = {'path': str(path)}
    if redact is not None:
        audit['redact'] = redact
    config = {'policy': {'allow_tools': []},
              'auth': {'env': 'SOL44_FIXTURE_AUTH'}, 'audit': audit}
    metadata = 'blocked/' + bearer + '/' + shaped
    request = {'jsonrpc': '2.0', 'id': 1, 'method': metadata}
    expected_code = cli.BLOCKED_METHOD_CODE
    if kind == 'tool':
        request.update(method='tools/call', params={'name': metadata})
        expected_code = cli.BLOCKED_TOOL_CODE

    def no_upstream(*args, **kwargs):
        pytest.fail('rejected request must not contact upstream')

    monkeypatch.setattr(cli, '_post_json', no_upstream)
    response = cli._handle_line(config, json.dumps(request))
    assert response['error']['code'] == expected_code
    raw = path.read_text(encoding='utf-8')
    event = json.loads(raw)
    assert event == {'event': kind + '_blocked', 'code': expected_code,
                     kind: metadata if redact is False else
                     'blocked/[redacted]/[REDACTED-SECRET]'}
    if redact is not False:
        assert shaped not in raw
        assert json.dumps(bearer)[1:-1] not in raw


def test_audit_sink_scrubs_nested_metadata_without_mutating_event(tmp_path, monkeypatch):
    shaped = 'ghp_' + 'syntheticfixtureonly' * 2
    monkeypatch.setenv('SOL44_FIXTURE_AUTH', shaped)
    path = tmp_path / 'audit.jsonl'
    config = {'auth': {'env': 'SOL44_FIXTURE_AUTH'},
              'audit': {'path': str(path), 'redact': True}}
    other = 'sk-' + 'syntheticfixtureonly' * 2
    event = {'event': 'fixture', 'metadata': {shaped: [other]}, 'count': 2}
    cli._audit(config, event)
    # Configured-value replacement must happen before shape scrubbing.
    assert json.loads(path.read_text(encoding='utf-8')) == {
        'event': 'fixture', 'metadata': {'[redacted]': ['[REDACTED-SECRET]']}, 'count': 2}
    assert event == {'event': 'fixture', 'metadata': {shaped: [other]}, 'count': 2}


def test_output_redaction_refusal_does_not_kill_next_stdio_request(monkeypatch, capsys):
    import io
    config = {'redaction': {'fail_on_secret_output': True}}
    monkeypatch.setattr(cli.sys, 'stdin', io.StringIO('first\nsecond\n'))
    monkeypatch.setattr(cli, '_secret_values', lambda _: ['fixture-private-value'])
    responses = iter([{'jsonrpc': '2.0', 'id': 1, 'result': 'fixture-private-value'},
                      {'jsonrpc': '2.0', 'id': 2, 'result': 'safe'}])
    monkeypatch.setattr(cli, '_handle_line', lambda *_: next(responses))
    assert cli._run(config) == 0
    raw = capsys.readouterr().out
    records = [json.loads(line) for line in raw.splitlines()]
    assert len(records) == 2
    assert records[0]['id'] is None and records[0]['error']['code'] == -32003
    assert records[1]['id'] == 2 and records[1]['result'] == 'safe'
    assert 'fixture-private-value' not in raw


@pytest.mark.parametrize('timeout', [None, True, False, [], {}, 'invalid', 'nan', 'inf', 0, -1, 10 ** 1000])
def test_invalid_timeout_is_typed_before_upstream_dispatch(monkeypatch, timeout):
    config = {'target': {'url': 'http://127.0.0.1:8766/mcp', 'timeout_seconds': timeout}}

    def no_upstream(*args, **kwargs):
        pytest.fail('invalid timeout must not dispatch')

    monkeypatch.setattr(cli._OPENER, 'open', no_upstream)
    with pytest.raises(cli.BridgeError, match='finite positive number; nothing dispatched'):
        cli._post_json(config, {'jsonrpc': '2.0', 'id': 1, 'method': 'ping'})
