from arvyx_control.replica_authority import authority_context
"""SOL22 private regression: principal/request bound domain retries."""
import tempfile
from pathlib import Path
import pytest
from arvyx_control import control as c

def test_rest_principals_do_not_share_tasks(tmp_path):
    from unittest.mock import patch
    from arvyx_control.api import handle_api_request
    from arvyx_control.auth import Identity
    state = tmp_path / 'events.jsonl'
    results = []
    for agent in ['alpha', 'beta']:
        with patch('arvyx_control.api.resolve_identity', return_value=Identity(agent, frozenset({'control.write'}), 'agent')):
            response = handle_api_request('POST', '/tasks', {'title': agent, 'owner': agent, 'idempotency_key': 'shared-domain-key'}, tmp_path / 'vault', state, authorization='Bearer synthetic')
        assert response.status == 201, response
        results.append(response.body['task']['id'])
    assert results[0] != results[1]
    assert len(c.list_tasks(state).tasks) == 2

@pytest.mark.parametrize('operation', ['task', 'approval', 'handoff', 'bus', 'reply'])
def test_principal_request_binding(operation):
    with tempfile.TemporaryDirectory() as directory:
        state = Path(directory) / 'events.jsonl'
        vault = Path(directory) / "authority-vault"
        vault.mkdir(exist_ok=True)
        with authority_context(vault, state):
            thread = c.post_thread(state, title='Thread', body='Body', actor='alpha', target='beta').thread.id
            def call(principal, changed=False):
                shared = dict(idempotency_key='same-key', principal_scope=principal)
                if operation == 'task':
                    return c.create_task(state, title='changed' if changed else 'Task', owner='worker', **shared)
                if operation == 'approval':
                    return c.request_approval(state, command='pwd', requester='worker', ttl_seconds=120 if changed else 60, **shared)
                if operation == 'handoff':
                    return c.create_handoff(state, title='Handoff', from_agent='worker', summary='changed' if changed else 'Summary', **shared)
                if operation == 'bus':
                    return c.post_bus_message(state, message='Message', actor='worker', channel='other' if changed else 'ops', **shared)
                return c.post_thread_message(state, thread, 'changed' if changed else 'Reply', actor='worker', **shared)
            first = call('agent:alpha')
            assert call('agent:alpha').event.id == first.event.id
            second = call('agent:beta')
            assert second.event.id != first.event.id
            with pytest.raises(ValueError, match='idempotency'):
                call('agent:alpha', True)
            assert call('agent:alpha').event.id == first.event.id

@pytest.mark.parametrize('operation', ['task', 'approval', 'handoff', 'bus', 'reply'])
def test_internal_compatibility(operation):
    with tempfile.TemporaryDirectory() as directory:
        state = Path(directory) / 'events.jsonl'
        vault = Path(directory) / "authority-vault"
        vault.mkdir(exist_ok=True)
        with authority_context(vault, state):
            thread = c.post_thread(state, title='Thread', body='Body', actor='alpha', target='beta').thread.id
            calls = {
                'task': lambda: c.create_task(state, 'Task', owner='worker', idempotency_key='retry'),
                'approval': lambda: c.request_approval(state, 'pwd', requester='worker', idempotency_key='retry'),
                'handoff': lambda: c.create_handoff(state, 'Handoff', from_agent='worker', idempotency_key='retry'),
                'bus': lambda: c.post_bus_message(state, 'Message', actor='worker', idempotency_key='retry'),
                'reply': lambda: c.post_thread_message(state, thread, 'Reply', actor='worker', idempotency_key='retry'),
            }
            assert calls[operation]().event.id == calls[operation]().event.id

@pytest.mark.parametrize('tool,args', [
    ('control.task_create', {'title': 'Task', 'owner': 'worker'}),
    ('control.approval_request', {'command': 'pwd', 'requester': 'worker'}),
    ('control.handoff_create', {'title': 'Handoff', 'from_agent': 'worker'}),
    ('control.bus_post', {'message': 'Message', 'actor': 'worker'}),
    ('control.thread_reply', {'text': 'Reply', 'actor': 'worker'}),
])
def test_mcp_all_callers(tmp_path, tool, args):
    with authority_context(tmp_path, tmp_path / 'events.jsonl'):
        from arvyx_control.mcp import _call_tool
        state = tmp_path / 'events.jsonl'
        args = dict(args, idempotency_key='same-key')
        if tool == 'control.thread_reply':
            args['thread_id'] = c.post_thread(state, title='Thread', body='Body', actor='worker', target='all', thread_type='status').thread.id
        def call(principal):
            return _call_tool({'name': tool, 'arguments': args}, tmp_path, state, {tool}, principal_scope=principal)['structuredContent']
        first = call('operator:alpha')
        assert call('operator:alpha')['event']['id'] == first['event']['id']
        assert call('operator:beta')['event']['id'] != first['event']['id']

@pytest.mark.parametrize('route,args', [
    ('/tasks', {'title': 'Task', 'owner': 'worker'}),
    ('/approvals/request', {'command': 'pwd', 'requester': 'worker'}),
    ('/handoffs', {'title': 'Handoff', 'from_agent': 'worker'}),
    ('/bus', {'message': 'Message', 'actor': 'worker'}),
])
def test_rest_all_callers_operator_principal_not_payload(tmp_path, route, args):
    from unittest.mock import patch
    from arvyx_control.api import handle_api_request
    from arvyx_control.auth import Identity
    state = tmp_path / 'events.jsonl'
    results = []
    for agent in ['alpha', 'beta']:
        with patch('arvyx_control.api.resolve_identity', return_value=Identity(agent, frozenset({'control.write'}), 'operator')):
            response = handle_api_request('POST', route, dict(args, idempotency_key='shared-domain-key', principal_scope='spoofed'), tmp_path / 'vault', state, authorization='Bearer synthetic')
        assert response.status == 201, response
        results.append(response.body['event']['id'])
    assert results[0] != results[1]


def test_transcript_global_blob_conflicts_across_actors(tmp_path):
    with authority_context(tmp_path, tmp_path / 'events.jsonl'):
        import json
        from arvyx_control.cockpit_archive_authority import append_transcript
        state = tmp_path / 'events.jsonl'
        projects = tmp_path / 'registry/projects'
        projects.mkdir(parents=True)
        project = projects / 'demo.json'
        project.write_text(json.dumps({'owner_agent_id': 'alpha'}))
        task = c.create_task(state, 'Task', owner='alpha').task.id
        payload = dict(event_id='transcript-key', session='session', run='run', text='Text', project='demo', task=task, host='host')
        first = append_transcript(tmp_path, state, payload, actor='alpha')
        assert append_transcript(tmp_path, state, payload, actor='alpha') == first
        # Simulate a later project/task owner change; the old event ID still may
        # not be claimed by the new owner, even with byte-identical content.
        project.write_text(json.dumps({'owner_agent_id': 'beta'}))
        original = c.read_events(state)[0]
        changed = {**original.payload, 'owner': 'beta'}
        with c._locked_state(state):
            c._append_event_unlocked(state, c._event('task.created', task, c._now(), changed))
        before = state.read_bytes()
        with pytest.raises(ValueError, match='conflict'):
            append_transcript(tmp_path, state, payload, actor='beta')
        assert state.read_bytes() == before


def test_legacy_internal_retry_and_authenticated_isolation(tmp_path):
    with authority_context(tmp_path, tmp_path / 'events.jsonl'):
        import json
        state = tmp_path / 'events.jsonl'
        first = c.create_task(state, 'Task', owner='worker', idempotency_key='legacy')
        row = json.loads(state.read_text())
        row['payload'].pop('idempotency_principal')
        row['payload'].pop('idempotency_request')
        state.write_text(json.dumps(row) + '\n')
        assert c.create_task(state, 'Task', owner='worker', idempotency_key='legacy').event.id == first.event.id
        with pytest.raises(ValueError, match='idempotency'):
            c.create_task(state, 'Different', owner='worker', idempotency_key='legacy')
        assert c.create_task(state, 'Task', owner='worker', idempotency_key='legacy', principal_scope='agent:alpha').event.id != first.event.id


def test_http_mcp_preserves_operator_principal(tmp_path):
    import json
    from unittest.mock import patch
    from arvyx_control.api import handle_api_request
    from arvyx_control.auth import Identity
    state = tmp_path / 'events.jsonl'
    events = []
    for agent in ['alpha', 'beta']:
        with patch('arvyx_control.api.resolve_identity', return_value=Identity(agent, frozenset({'control.write'}), 'operator')):
            response = handle_api_request('POST', '/mcp', {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': 'control.task_create', 'arguments': {'title': 'Task', 'owner': 'worker', 'idempotency_key': 'shared-mcp-domain-key'}}}, tmp_path / 'vault', state, authorization='Bearer synthetic', mcp_profile='operator')
        assert response.status == 200, response
        result = json.loads(response.body) if isinstance(response.body, str) else response.body
        assert 'error' not in result, result
        events.append(result['result']['structuredContent']['event']['id'])
    assert events[0] != events[1]
