"""Lane B: disposable authorities and harmless transport recorders only."""
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import sqlite3
import os
import subprocess
import sys

import pytest

from arvyx_control import api, audit_log, control, mcp, operation_journal as journal
from arvyx_control.auth import ALL_SCOPES, Identity, OPERATOR_IDENTITY
from arvyx_control.replica_authority import authority_context


@pytest.fixture
def authority(tmp_path):
    vault, state = tmp_path / 'vault', tmp_path / 'events.jsonl'
    vault.mkdir()
    with authority_context(vault, state):
        yield vault, state


@pytest.mark.parametrize('phase', ['completed', 'claimed', 'intent_durable'])
@pytest.mark.parametrize('different', ['state', 'vault'])
@pytest.mark.parametrize('transport', ['http', 'stdio'])
def test_journal_refuses_authority_rebinding(tmp_path, monkeypatch, phase, different, transport):
    monkeypatch.setattr(api, 'resolve_identity', lambda *a, **k: OPERATOR_IDENTITY)
    vault, state = tmp_path / 'vault', tmp_path / 'first.jsonl'
    audit = tmp_path / 'shared-audit.jsonl' if different == 'vault' else None
    key = 'namespace-retry-key'
    body = {'title': 'Synthetic namespace task', 'owner': 'worker', 'idempotency_key': key}

    def invoke(v, s):
        if transport == 'http':
            return api.handle_api_request('POST', '/tasks', body, v, s, audit_log=audit)
        return mcp.handle_request({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
            'params': {'name': 'control.task_create', 'arguments': body}}, v, state=s,
            allowed_tools={'control.task_create'}, secret_audit_log=audit)

    first = invoke(vault, state)
    assert first.status == 201 if transport == 'http' else 'error' not in first
    store = journal.journal_path(audit or audit_log.default_audit_log(state))
    with sqlite3.connect(store) as conn:
        op = conn.execute('SELECT operation_id FROM operations').fetchone()[0]
    with authority_context(vault, state):
        journal.set_operation_state(store, op, phase)
    if phase != 'completed':
        with sqlite3.connect(store) as conn:
            conn.execute('UPDATE operations SET dispatch_owner=NULL,safe_outcome_json=NULL,http_status=NULL')
    other_vault = tmp_path / 'other-vault' if different == 'vault' else vault
    other_state = tmp_path / 'second.jsonl' if different == 'state' else state
    before = state.read_bytes()
    second = invoke(other_vault, other_state)
    if transport == 'http':
        assert second.status == 503, second
        assert 'namespace' in second.body['error'] and second.body['retry_safe'] is False
    else:
        assert 'namespace' in json.dumps(second).lower(), second
    assert state.read_bytes() == before
    if other_state != state:
        assert not other_state.exists()
    with sqlite3.connect(store) as conn:
        assert conn.execute('SELECT state FROM operations').fetchone()[0] == phase


def test_populated_legacy_journal_is_not_silently_adopted(authority, tmp_path, monkeypatch):
    vault, state = authority
    monkeypatch.setattr(api, 'resolve_identity', lambda *a, **k: OPERATOR_IDENTITY)
    store = journal.journal_path(audit_log.default_audit_log(state))
    with sqlite3.connect(store) as conn:
        conn.executescript(journal._SCHEMA)
        conn.execute("INSERT INTO operations(operation_id,principal_scope,action,key_hash,request_hash,state) "
                     "VALUES('legacy','operator:operator','POST:/tasks',?,?,'intent_durable')",
                     (hashlib.sha256(b'legacy-namespace-key').hexdigest(), 'old-hash'))
    before = store.read_bytes()
    result = api.handle_api_request('POST', '/tasks', {'title': 'Synthetic', 'owner': 'worker',
        'idempotency_key': 'new-namespace-key'}, vault, state)
    assert result.status == 503
    assert not state.exists()
    assert store.read_bytes() == before
    assert journal.operation_record(store, 'legacy').state == 'intent_durable'


def test_bound_journal_legacy_migration_keeps_unknown_and_normal_intents(authority, tmp_path, monkeypatch):
    vault, state = authority
    audit = tmp_path / 'migration-audit.jsonl'
    store = journal.journal_path(audit)
    normal = journal.claim_operation(store, vault=vault, principal_scope='operator',
        action='MCP:control.thread_post', idempotency_key='normal-intent-preserved-key', request_hash='a'*64)
    journal.set_operation_state(store, normal.operation_id, 'intent_durable')
    audit_log.append_audit(audit, {'operation_id': 'orphan-v1', 'phase': 'intent'})
    journal.migrate_legacy_audit_operations(audit)
    with sqlite3.connect(store) as db:
        db.execute("UPDATE operations SET state='intent_durable',dispatch_owner=NULL WHERE operation_id='orphan-v1'")
        db.execute("UPDATE journal_meta SET value='v1' WHERE key=?", (journal.LEGACY_MIGRATION_KEY,))
    class Interrupted(sqlite3.Connection):
        def commit(self):
            raise sqlite3.OperationalError('synthetic migration interruption')
    def interrupted(path):
        return sqlite3.connect(path, factory=Interrupted)
    with monkeypatch.context() as patch:
        patch.setattr(journal, '_connect', interrupted)
        with pytest.raises(sqlite3.OperationalError, match='synthetic migration interruption'):
            journal.migrate_legacy_audit_operations(audit)
    assert journal.operation_record(store, 'orphan-v1').state == 'intent_durable'
    journal.migrate_legacy_audit_operations(audit)
    assert journal.operation_record(store, 'orphan-v1').state == 'dispatching'
    assert journal.operation_record(store, normal.operation_id).state == 'intent_durable'
    assert not journal.try_begin_dispatch(store, 'orphan-v1', 'cannot-replay')
    assert journal.reject_unknown_dispatch(store, 'orphan-v1')
    assert not journal.reject_unknown_dispatch(store, 'orphan-v1')


def test_fleet_health_retains_operator_scope(authority, monkeypatch):
    from arvyx_control.execution import materialize_executions, hold_execution
    vault, state = authority
    for target in ('alpha', 'beta'):
        control.post_thread(state, title='Synthetic work', actor='operator', target=target,
                            actor_identity_bound=True)
    executions = materialize_executions(state, execution_capable_targets={'alpha', 'beta'})
    foreign = next(e for e in executions if e.target == 'beta')
    hold_execution(state, execution_id=foreign.id, reason='Synthetic hold', held_by='operator')
    monkeypatch.setattr(api, 'resolve_identity', lambda *a, **k: Identity('alpha', ALL_SCOPES, 'agent'))
    for path in ('/fleet/health', '/executions/health', '/executions/' + foreign.id):
        response = api.handle_api_request('GET', path, {}, vault, state)
        assert response.status == 403, response
        if path.endswith('/health'):
            assert foreign.id not in response.to_json()
    monkeypatch.setattr(api, 'resolve_identity', lambda *a, **k: OPERATOR_IDENTITY)
    assert api.handle_api_request('GET', '/fleet/health', {}, vault, state).status == 200


@pytest.mark.parametrize('failure_at,notification', [
    ('before', False), ('before', True), ('after', False), ('after', True),
    ('upstream_error', False), ('upstream_error', True), ('emit', False)])
def test_bridge_audit_failure_keeps_framing_and_fences_dispatch(monkeypatch, capsys, notification, failure_at):
    from safe_mcp_bridge import cli
    config = {'policy': {'allow_tools': ['control.task_create']},
              'audit': {'path': '/synthetic/recorded-only'}}
    first = {'jsonrpc': '2.0', 'method': 'tools/call', 'params': {'name': 'control.task_create'}}
    if not notification:
        first['id'] = 'original-request'
    frames = [first, {'jsonrpc': '2.0', 'id': 2, 'method': 'ping'},
              {'jsonrpc': '2.0', 'id': 3, 'method': 'ping'}]
    monkeypatch.setattr(cli.sys, 'stdin', io.StringIO('\n'.join(map(json.dumps, frames)) + '\n'))
    effects = []
    def upstream(config, payload):
        effects.append(payload)
        if failure_at == 'upstream_error':
            raise cli.BridgeError('synthetic transport uncertain')
        result = 'sk-' + 'syntheticfixtureonly' * 2 if failure_at == 'emit' else 'safe'
        return {'jsonrpc': '2.0', 'id': payload.get('id'), 'result': result}
    def audit(config, event):
        event_name = event['event']
        should_fail = (failure_at == 'before' or
            failure_at == 'after' and event_name == 'request_forwarded' or
            failure_at == 'upstream_error' and event_name == 'upstream_error' or
            failure_at == 'emit' and event_name == 'secret_shape_redacted')
        if should_fail:
            raise OSError('synthetic-private-detail')
    monkeypatch.setattr(cli, '_post_json', upstream)
    monkeypatch.setattr(cli, '_audit', audit)
    assert cli._run(config) == 0
    raw = capsys.readouterr().out
    replies = [json.loads(line) for line in raw.splitlines()]
    assert [r['id'] for r in replies] == ([2, 3] if notification else ['original-request', 2, 3])
    assert len(effects) == (0 if failure_at == 'before' else 1)
    assert all('error' in r for r in replies)
    if not notification and failure_at != 'before':
        assert 'uncertain' in replies[0]['error']['message']
    assert 'synthetic-private-detail' not in raw


@pytest.mark.parametrize('surface', ['http', 'mcp'])
def test_mixed_case_target_reply_keeps_literal_evidence(authority, monkeypatch, surface):
    vault, state = authority
    artifact = 'control thread reply authored by Nova'
    thread = control.post_thread(state, title='Synthetic contracted reply', actor='operator',
        target='Nova', completion_artifact=artifact, completion_anchor='Exact Anchor',
        actor_identity_bound=True).thread
    identity = Identity('nova', ALL_SCOPES, 'agent')
    monkeypatch.setattr(api, 'resolve_identity', lambda *a, **k: identity)
    def call(action, args, key):
        if surface == 'http' and action == 'done':
            route = '/threads/' + thread.id + '/done'
            return api.handle_api_request('POST', route, dict(args, idempotency_key=key), vault, state)
        payload = {'jsonrpc': '2.0', 'id': key, 'method': 'tools/call', 'params': {
            'name': 'control.thread_' + action, 'arguments': dict(args, thread_id=thread.id,
                idempotency_key=key)}}
        return api.handle_api_request('POST', '/mcp', payload, vault, state, mcp_profile='operator')
    def success(response):
        if surface == 'http' and not isinstance(response.body, str):
            return response.status == 200
        result = json.loads(response.body)
        return 'error' not in result and not result.get('result', {}).get('isError')
    assert success(call('reply', {'text': 'Exact Anchor'}, 'mixed-case-reply-key'))
    evidence = dict(evidence_artifact=artifact, evidence_anchor='Exact Anchor', evidence_method='api-readback')
    for field, value in [('evidence_artifact', artifact.lower()), ('evidence_anchor', 'exact anchor')]:
        assert not success(call('done', dict(evidence, **{field: value}), 'bad-evidence-key-' + field))
    identity = Identity('foreign', ALL_SCOPES, 'agent')
    assert not success(call('done', evidence, 'foreign-author-key'))
    identity = Identity('nova', ALL_SCOPES, 'agent')
    result = call('done', evidence, 'mixed-case-done-key')
    assert success(result), result
    assert control.list_thread_inbox(state).threads[0].status == 'done'


def leased(state):
    from arvyx_control.execution import claim_execution
    now = datetime.now(timezone.utc)
    control.post_thread(state, title='Synthetic live attempt', actor='operator', target='worker',
                        actor_identity_bound=True)
    result = claim_execution(state, worker='synthetic', execution_capable_targets={'worker'},
                             now=now, lease_seconds=600)
    assert result is not None
    return result


@pytest.mark.parametrize('domain', ['decision', 'session_return', 'control'])
def test_direct_secret_keys_never_enter_domain_records(authority, domain):
    from arvyx_control.decisions import request_decision
    from arvyx_control.session_return import request_session_return
    vault, state = authority
    execution = leased(state)
    secret_key = 'arv_synthetic_' + 'a' * 40
    before = state.read_bytes()
    def call(key):
        common = dict(execution_id=execution.id, attempt_id=execution.attempt_id,
                      actor='worker', idempotency_key=key)
        if domain == 'decision':
            return request_decision(state, question='Synthetic choice?', allow_text=True, **common)
        if domain == 'session_return':
            return request_session_return(state, message='Synthetic result', expected_word_count=2, **common)
        return control.create_task(state, title='Synthetic task', owner='worker', idempotency_key=key)
    with pytest.raises(ValueError, match='secret-shaped'):
        call(secret_key)
    assert state.read_bytes() == before
    assert secret_key.encode() not in state.read_bytes()
    first = call('ordinary-retry-key')
    after = state.read_bytes()
    assert call('ordinary-retry-key') == first
    assert state.read_bytes() == after


@pytest.mark.parametrize('surface', ['http', 'mcp', 'stdio', 'journal'])
def test_shared_secret_keys_refused_before_claim(authority, surface, monkeypatch):
    vault, state = authority
    secret_key = 'arv_synthetic_' + 'a' * 40
    monkeypatch.setattr(api, 'resolve_identity', lambda *a, **k: OPERATOR_IDENTITY)
    arguments = {'execution_id': 'execution_synthetic', 'attempt_id': 'synthetic',
                 'question': 'Synthetic choice?', 'idempotency_key': secret_key}
    payload = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
               'params': {'name': 'control.decision_request', 'arguments': arguments}}
    if surface == 'journal':
        with pytest.raises(ValueError, match='secret-shaped'):
            journal.claim_operation(vault / 'journal.sqlite', vault=vault, principal_scope='synthetic',
                action='synthetic', idempotency_key=secret_key, request_hash='x')
    elif surface == 'stdio':
        response = mcp.handle_request(payload, vault, state=state, allowed_tools={'control.decision_request'})
        assert 'secret-shaped' in json.dumps(response)
    else:
        path = '/mcp' if surface == 'mcp' else '/tasks'
        body = payload if surface == 'mcp' else {'title': 'Synthetic', 'idempotency_key': secret_key}
        response = api.handle_api_request('POST', path, body, vault, state, mcp_profile='operator')
        assert response.status == 400
    assert not state.exists()
    assert not journal.journal_path(audit_log.default_audit_log(state)).exists()
    assert not (vault / 'journal.sqlite').exists()


def test_audit_browse_retains_torn_byte_evidence(authority, tmp_path):
    path = tmp_path / 'audit.jsonl'
    audit_log.append_audit(path, {'event_id': 'synthetic', 'decision': 'allowed'})
    assert audit_log.recent_events(path).chain.ok
    path.write_bytes(path.read_bytes()[:-1])
    assert not audit_log.recent_events(path).chain.ok
    assert not audit_log.verify_chain(path).ok
    assert not audit_log.verify_chain_tail(path).ok
    with pytest.raises(audit_log.AuditCorruptionError):
        audit_log.append_audit(path, {'event_id': 'second'})


def dispatch_notification(state, *, settled=True):
    from arvyx_control.agent_delivery import AgentDeliveryResult, AgentRoute
    from arvyx_control.dispatcher import dispatch_once
    from arvyx_control.outbox import project_outbox
    recorded = []
    def deliverer(*args, **kwargs):
        recorded.append((args, kwargs))
        if not settled:
            return AgentDeliveryResult(False, 'transient', 503, 'synthetic unavailable')
        return AgentDeliveryResult(True, 'accepted', 202, 'synthetic accepted', 'synthetic receipt')
    now = datetime.now(timezone.utc)
    result = dispatch_once(state, routes={'worker': AgentRoute('worker', 'hermes-webhook', 'B_URL', 'B_SECRET')},
        worker='synthetic-dispatch', deliver_after=(now - timedelta(minutes=5)).isoformat(), now=now, clock=lambda: now,
        environ={'B_URL': 'http://127.0.0.1:9999/synthetic', 'B_SECRET': 'synthetic-route-secret'},
        deliverer=deliverer)
    assert result.delivered == int(settled), result
    item = next(iter(project_outbox(state).values()))
    assert item.payload['delivery_mode'] == 'notification'
    assert item.payload['execution_managed'] is True
    assert item.status == ('delivered' if settled else 'pending') and len(recorded) == 1
    return item


def archive_request(state, execution):
    from arvyx_control.operator_archive import history_digest, related_records
    events = control.read_events(state)
    history = [e for e in events if e.task_id == execution.id]
    quote = 'Cancel this exact synthetic execution without claiming success.'
    return dict(schema='operator-archive/v1', operation='archive', record_type='execution',
        record_id=execution.id, expected_event_id=history[-1].id, source_event_id=history[0].id,
        target=execution.target, history_sha256=history_digest(state, execution.id),
        related_revisions={i: dict(expected_event_id=next(e.id for e in reversed(events) if e.task_id == i),
            history_sha256=history_digest(state, i)) for i in related_records(events, execution.id)},
        category='operator_cancelled_no_longer_needed', reason='Synthetic obsolete execution.',
        approval_reference='synthetic:operator', approval_quote=quote,
        approval_sha256=hashlib.sha256(quote.encode()).hexdigest(),
        evidence_references=['synthetic:history'], terminal_event_id='')


@pytest.mark.parametrize('disposition', ['archive', 'dismiss'])
@pytest.mark.parametrize('kind', ['thread', 'handoff'])
@pytest.mark.parametrize('settled', [True, False])
def test_current_producer_notification_allows_governed_disposition(authority, monkeypatch, disposition, kind, settled):
    from arvyx_control.execution import materialize_executions, hold_execution, close_execution
    from arvyx_control.operator_archive import archive_record
    from arvyx_control.operator_alert_dismissal import prepare_alert_dismissal, dismiss_alert
    from arvyx_control.watchdog import _escalation_title
    from arvyx_control.watchdog_alerts import operator_hold_alert_bodies
    vault, state = authority
    if kind == 'thread':
        subject = control.post_thread(state, title='Synthetic actionable assignment', actor='operator',
            target='worker', actor_identity_bound=True).thread
    else:
        subject = control.create_handoff(state, title='Synthetic actionable handoff', from_agent='operator',
            to_agent='worker', actor_identity_bound=True).handoff
    dispatch_notification(state, settled=settled)
    execution = materialize_executions(state, execution_capable_targets={'worker'})[0]
    reason = 'Synthetic obsolete hold'
    hold_execution(state, execution_id=execution.id, reason=reason, held_by='operator')
    if disposition == 'archive':
        monkeypatch.setenv('ARVYX_ENABLE_OPERATOR_ARCHIVE', '1')
        request = archive_request(state, execution)
        if not settled:
            before = state.read_bytes()
            with pytest.raises(ValueError, match='active or unknown related work'):
                archive_record(state, record_id=execution.id, request=request, identity=OPERATOR_IDENTITY)
            assert state.read_bytes() == before
            return
        assert archive_record(state, record_id=execution.id, request=request,
                              identity=OPERATOR_IDENTITY)['dry_run']
        result = archive_record(state, record_id=execution.id, request=request,
                                identity=OPERATOR_IDENTITY, dry_run=False)
        assert result['record']['status'] == 'closed'
    else:
        alert = control.post_thread(state, title=_escalation_title(execution.id), actor='arvyx-watchdog',
            target='operator', thread_type='blocker', body=operator_hold_alert_bodies(target='worker',
            subject_type=kind, subject_id=subject.id, hold_reason=reason)[0]).thread
        close_execution(state, execution_id=execution.id, reason='Synthetic closure', closed_by='operator',
                        resolution_category='no_longer_actionable')
        def prepare():
            return prepare_alert_dismissal(state, record_id=alert.id, identity=OPERATOR_IDENTITY,
                reason='Dismiss only the synthetic alert.', approval_reference='synthetic:operator',
                approval_quote='Dismiss this exact synthetic alert.', evidence_references=['synthetic:history'])
        if not settled:
            before = state.read_bytes()
            with pytest.raises(ValueError, match='live or ambiguous transport'):
                prepare()
            assert state.read_bytes() == before
            return
        request = prepare()
        result = dismiss_alert(state, record_id=alert.id, request=request, identity=OPERATOR_IDENTITY, dry_run=False)
        assert result['record']['status'] == 'retired'


@pytest.mark.parametrize('fault', ['flag_false', 'flag_integer', 'ineligible', 'target', 'extra', 'anchor'])
def test_forged_notification_never_passes_shared_validator(authority, fault):
    from arvyx_control.operator_archive import _validate_history
    from arvyx_control.outbox import enqueue
    vault, state = authority
    created = control.post_thread(state, title='Synthetic notification', actor='operator', target='worker',
        actor_identity_bound=fault != 'ineligible', completion_artifact='synthetic:artifact',
        completion_anchor='Exact synthetic anchor')
    payload = dict(schema='v2.agent-delivery/1', source_event_id=created.event.id,
        source_event_type='thread.created', subject_id=created.thread.id, delivery_mode='notification',
        execution_managed=True, completion_artifact='synthetic:artifact', completion_anchor='Exact synthetic anchor')
    if fault == 'flag_false': payload['execution_managed'] = False
    if fault == 'flag_integer': payload['execution_managed'] = 1
    if fault == 'extra': payload['forged'] = True
    if fault == 'anchor': payload['completion_anchor'] = 'Changed anchor'
    item = enqueue(state, subject_id=created.thread.id, target='foreign' if fault == 'target' else 'worker', payload=payload)
    with pytest.raises(ValueError):
        _validate_history(control.read_events(state), item.id)


def test_actual_core_stdio_reopen_preserves_namespace(tmp_path):
    vault, state, audit = tmp_path / 'vault', tmp_path / 'first.jsonl', tmp_path / 'audit.jsonl'
    payload = {'jsonrpc': '2.0', 'id': 'correlation', 'method': 'tools/call', 'params': {
        'name': 'control.task_create', 'arguments': {'title': 'Synthetic CLI task', 'owner': 'worker',
                                                   'idempotency_key': 'actual-stdio-retry-key'}}}
    def invoke(selected):
        cmd = [sys.executable, '-m', 'arvyx_control.cli', 'mcp', '--vault', str(vault),
               '--state', str(selected), '--audit-log', str(audit), '--profile', 'operator']
        process = subprocess.run(cmd, input=json.dumps(payload) + '\n', text=True,
                                 capture_output=True, timeout=10, env=os.environ.copy())
        assert process.returncode == 0, process.stderr
        return json.loads(process.stdout)
    assert 'error' not in invoke(state)
    before = state.read_bytes()
    assert 'operation_completed_no_replay' in json.dumps(invoke(state))
    assert 'namespace' in json.dumps(invoke(tmp_path / 'second.jsonl'))
    assert state.read_bytes() == before and not (tmp_path / 'second.jsonl').exists()


@pytest.mark.parametrize('notification', [False, True])
def test_actual_bridge_stdio_audit_fault_is_correlated_and_not_replayed(tmp_path, notification):
    config = tmp_path / 'config.json'
    effects = tmp_path / 'effects.jsonl'
    config.write_text(json.dumps({'policy': {'allow_tools': ['control.task_create']},
        'target': {'url': 'http://127.0.0.1:9999/synthetic'},
        'audit': {'path': str(tmp_path / 'bridge-audit.jsonl')}}))
    script = '''
import json, sys
from pathlib import Path
from safe_mcp_bridge import cli
original_audit = cli._audit
def audit(config, event):
    if event['event'] == 'request_forwarded':
        raise OSError('synthetic-private-detail')
    original_audit(config, event)
def upstream(config, payload):
    with Path(sys.argv[2]).open('a') as handle:
        handle.write(json.dumps(payload) + '\\n')
    return {'jsonrpc': '2.0', 'id': payload.get('id'), 'result': 'safe'}
cli._audit, cli._post_json = audit, upstream
raise SystemExit(cli.main(['run', sys.argv[1]]))
'''
    first = {'jsonrpc': '2.0', 'method': 'tools/call', 'params': {'name': 'control.task_create'}}
    if not notification: first['id'] = 'original'
    frames = [first, {'jsonrpc': '2.0', 'id': 'next', 'method': 'ping'}]
    cmd = [sys.executable, '-c', script, str(config), str(effects)]
    process = subprocess.run(cmd, input='\n'.join(map(json.dumps, frames)) + '\n',
                             text=True, capture_output=True, timeout=10, env=os.environ.copy())
    assert process.returncode == 0, process.stderr
    replies = [json.loads(line) for line in process.stdout.splitlines()]
    assert [r['id'] for r in replies] == (['next'] if notification else ['original', 'next'])
    assert all('error' in r for r in replies)
    if not notification: assert 'uncertain' in replies[0]['error']['message']
    assert len(effects.read_text().splitlines()) == 1
    assert 'synthetic-private-detail' not in process.stdout + process.stderr
