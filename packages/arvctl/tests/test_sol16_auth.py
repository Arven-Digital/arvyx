from arvyx_control.replica_authority import authority_context
"""Synthetic candidate-15 regressions for findings 1, 2 and 9."""
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from arvyx_control.api import handle_api_request
from arvyx_control.auth import Identity, OPERATOR_IDENTITY
from arvyx_control.control import accept_handoff, complete_handoff, create_handoff
from arvyx_control.mcp import handle_request
from arvyx_control.security import contains_literal_secret, redact_secrets, SECRET_RE
from safe_mcp_bridge import cli as bridge


def accepted(state, target='recipient'):
    handoff = create_handoff(state, 'Synthetic handoff', from_agent='sender', to_agent=target).handoff
    accept_handoff(state, handoff.id, actor=target)
    return handoff.id


@pytest.mark.parametrize('actor', ['operator', ' Operator ', 'intruder'])
def test_identity_bound_nonparticipant_cannot_complete(tmp_path, actor):
    with authority_context(tmp_path / 'vault', tmp_path / 'events.jsonl'):
        state = tmp_path / 'events.jsonl'
        hid = accepted(state)
        before = state.read_bytes()
        with pytest.raises(ValueError, match='participant'):
            complete_handoff(state, hid, actor=actor, actor_identity_bound=True)
        assert state.read_bytes() == before


@pytest.mark.parametrize('identity,expected', [(Identity('operator', frozenset({'control.write'}), 'agent'), 400), (OPERATOR_IDENTITY, 200)])
def test_rest_operator_authority_not_agent_name(tmp_path, identity, expected):
    with authority_context(tmp_path / 'vault', tmp_path / 'events.jsonl'):
        state = tmp_path / 'events.jsonl'
        hid = accepted(state)
        before = state.read_bytes()
        with patch('arvyx_control.api.resolve_identity', return_value=identity):
            response = handle_api_request('POST', f'/handoffs/{hid}/complete', {'actor': 'operator'}, tmp_path / 'vault', state,
                authorization='Bearer synthetic', idempotency_key='synthetic-complete')
        assert response.status == expected, response
        if expected != 200:
            assert state.read_bytes() == before
        else:
            assert json.loads(state.read_text().splitlines()[-1])['type'] == 'handoff.completed'


def test_mcp_bound_operator_name_cannot_complete(tmp_path):
    with authority_context(tmp_path, tmp_path / 'events.jsonl'):
        state = tmp_path / 'events.jsonl'
        hid = accepted(state)
        before = state.read_bytes()
        response = handle_request({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {
            'name': 'control.handoff_complete', 'arguments': {'handoff_id': hid}}}, tmp_path, state,
            actor='operator', allowed_tools={'control.handoff_complete'})
        assert 'error' in response or response.get('result', {}).get('isError') is True
        assert state.read_bytes() == before


@pytest.mark.parametrize('target,actor,bound', [('recipient', 'operator', False), ('operator', 'operator', True), ('recipient', 'recipient', True), ('recipient', 'sender', True)])
def test_legitimate_completions_preserved(tmp_path, target, actor, bound):
    with authority_context(tmp_path / 'vault', tmp_path / 'events.jsonl'):
        state = tmp_path / 'events.jsonl'
        hid = accepted(state, target)
        assert complete_handoff(state, hid, actor=actor, actor_identity_bound=bound).handoff.status == 'completed'


@pytest.mark.parametrize('agent', ['a', 'agent_one-two', 'a' * 64, 'operator'])
def test_issued_token_detected_rejected_and_redacted(tmp_path, agent):
    with authority_context(tmp_path / 'vault', tmp_path / 'events.jsonl'):
        value = 'arv_' + agent + '_' + 'ab09' * 10
        prose = 'Synthetic prose (' + value + ') end.'
        assert contains_literal_secret(prose)
        assert value not in redact_secrets(prose)
        with pytest.raises(ValueError, match='secret'):
            create_handoff(tmp_path / 'events.jsonl', prose, from_agent='sender', to_agent='recipient')
        assert bridge._FALLBACK_SECRET_RE.pattern == SECRET_RE.pattern
        with patch.object(bridge, '_secret_re', return_value=bridge._FALLBACK_SECRET_RE):
            redacted, count = bridge._redact_secret_shapes({'text': prose, value: [prose]})
        assert value not in json.dumps(redacted)
        assert count == 3


@pytest.mark.parametrize('value', ['arv_a_' + 'a' * 39, 'arv_a_' + 'a' * 41, 'arv__' + 'a' * 40, 'arv_' + 'a' * 65 + '_' + 'a' * 40, 'arv_a_' + 'g' * 40])
def test_nonissued_shapes_not_matched(value):
    assert not contains_literal_secret(value)


def test_auth_documentation_describes_rest_scope():
    text = (Path(__file__).resolve().parents[3] / 'docs/auth.md').read_text()
    assert 'operator-only secret resolution' not in text
    assert 'REST' in text and 'explicitly granted `secret.resolve`' in text
