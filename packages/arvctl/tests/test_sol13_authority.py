from arvyx_control.replica_authority import authority_context
"""Private synthetic regressions for candidate-12 findings 1, 6, and 7."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest

from arvyx_control.api import handle_api_request
from arvyx_control.auth import ALL_SCOPES, Identity, OPERATOR_IDENTITY, resolve_identity
from arvyx_control.control import accept_handoff, create_handoff
from arvyx_control.mcp import AGENT_CONTROL_TOOL_NAMES, handle_json_line


@pytest.mark.parametrize('scopes', [frozenset({'control.write'}), ALL_SCOPES])
@pytest.mark.parametrize('demo', [False, True])
def test_agent_cannot_review_handoff(tmp_path, scopes, demo):
    with authority_context(tmp_path / 'vault', tmp_path / 'events.jsonl'):
        state = tmp_path / 'events.jsonl'
        handoff = create_handoff(state, 'Synthetic handoff', from_agent='sender', to_agent='recipient').handoff
        accept_handoff(state, handoff.id, actor='recipient')
        before = state.read_bytes()
        with patch('arvyx_control.api.resolve_identity', return_value=Identity('recipient', scopes, 'agent')):
            response = handle_api_request('POST', f'/handoffs/{handoff.id}/review',
                {'reviewer': 'operator', 'decision': 'approved'}, tmp_path / 'vault', state,
                authorization='Bearer synthetic', idempotency_key='synthetic-review',
                allow_unauthenticated_demo=demo)
        assert response.status == 403, response
        assert state.read_bytes() == before
        assert 'control.handoff_review' not in AGENT_CONTROL_TOOL_NAMES


def test_operator_can_review_handoff(tmp_path):
    with authority_context(tmp_path / 'vault', tmp_path / 'events.jsonl'):
        state = tmp_path / 'events.jsonl'
        handoff = create_handoff(state, 'Synthetic handoff', from_agent='sender', to_agent='recipient').handoff
        accept_handoff(state, handoff.id, actor='recipient')
        with patch('arvyx_control.api.resolve_identity', return_value=OPERATOR_IDENTITY):
            response = handle_api_request('POST', f'/handoffs/{handoff.id}/review', {}, tmp_path / 'vault', state,
                authorization='Bearer synthetic', idempotency_key='synthetic-operator-review')
        assert response.status == 200, response
        assert json.loads(state.read_text().splitlines()[-1])['type'] == 'handoff.reviewed'


@pytest.mark.parametrize('record', [[], None, 'invalid', 42, False])
def test_nonobject_token_record_does_not_block_valid_token(tmp_path, record):
    tokens = tmp_path / 'registry' / 'tokens'
    tokens.mkdir(parents=True)
    (tokens / 'aaa.json').write_text(json.dumps(record))
    (tokens / 'zzz.json').write_text(json.dumps({'agent_id': 'recipient',
        'token_sha256': hashlib.sha256(b'synthetic-token').hexdigest(), 'scopes': ['control.write']}))
    identity = resolve_identity(tmp_path, 'Bearer synthetic-token')
    assert identity == Identity('recipient', frozenset({'control.write'}), 'agent')
    assert resolve_identity(tmp_path, 'Bearer incorrect') is None


def test_nested_json_returns_parse_error(tmp_path):
    response = json.loads(handle_json_line('[' * 1100 + '0' + ']' * 1100, tmp_path))
    assert response['error']['code'] == -32700
    assert json.loads(handle_json_line('{"jsonrpc":"2.0","id":2,"method":"ping"}', tmp_path))['id'] == 2


def test_stdio_survives_nested_json(tmp_path):
    result = subprocess.run([sys.executable, '-m', 'arvyx_control.cli', 'mcp', '--vault', str(tmp_path)],
        input='[' * 1100 + '0' + ']' * 1100 + '\n{"jsonrpc":"2.0","id":2,"method":"ping"}\n',
        text=True, capture_output=True, timeout=15, env=os.environ.copy())
    assert result.returncode == 0, result.stderr
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    assert responses[0]['error']['code'] == -32700
    assert responses[1]['id'] == 2
