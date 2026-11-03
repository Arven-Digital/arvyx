"""Lane B regression boundaries. Disposable authority; no providers or network."""
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from io import StringIO
import json
from pathlib import Path
import sqlite3
from contextlib import closing
import threading
from unittest.mock import patch

import os
import pytest

from arvyx_control import api, cli, control, mcp, mutation_dispatch, operation_journal as journal
from arvyx_control.audit_log import append_audit, pending_operations, verify_chain
from arvyx_control.auth import issue_token
from arvyx_control.health_ops import notify_check
from arvyx_control.replica_authority import authority_context
from arvyx_control.retirement import abandon_stale_thread
from arvyx_control.thread_history import validate_thread_history
from arvyx_control.vault import init_vault

NOW = datetime(2099, 1, 1, tzinfo=timezone.utc)


@pytest.fixture
def lane(tmp_path):
    vault, state, audit = tmp_path / 'vault', tmp_path / 'events.jsonl', tmp_path / 'audit.jsonl'
    with authority_context(vault, state):
        init_vault(vault)
        yield vault, state, audit


def rpc(arguments, *, request_id=1, tool='control.thread_read_all'):
    return {'jsonrpc': '2.0', 'id': request_id, 'method': 'tools/call',
            'params': {'name': tool, 'arguments': arguments}}


def stdio(lane, frames):
    vault, state, audit = lane
    out = StringIO()
    with patch('sys.stdin', StringIO(''.join(json.dumps(f) + '\n' for f in frames))), redirect_stdout(out):
        assert cli.main(['mcp', '--vault', str(vault), '--state', str(state),
                         '--audit-log', str(audit), '--profile', 'operator']) == 0
    return [json.loads(line) for line in out.getvalue().splitlines()]


def unread(lane):
    return control.post_thread(lane[1], title='Unread update', thread_type='update',
                               actor='uma', target='demobot').thread.id


@pytest.mark.parametrize('bad', [[], None, True, 'arguments'])
@pytest.mark.parametrize('notification', [False, True])
def test_malformed_arguments_http_never_claim_or_mark_read(lane, bad, notification):
    vault, state, audit = lane
    identifier = unread(lane)
    token = issue_token(vault, 'demobot', scopes=['control.write']).token
    body = rpc(bad)
    if notification:
        body.pop('id')
    with patch.object(api, 'claim_mutation', wraps=api.claim_mutation) as claim:
        response = api.handle_api_request('POST', '/mcp', body, vault=vault, state=state,
            audit_log=audit, mcp_profile='agent', authorization=f'Bearer {token}',
            idempotency_key='malformed-http-arguments-0001')
    if notification:
        assert response.status == 202
    else:
        payload = json.loads(response.body) if isinstance(response.body, str) else response.body
        assert payload['error']['code'] == -32602
    claim.assert_not_called()
    assert not any(e.type == 'thread.read' for e in control.read_events(state))
    assert next(t for t in control.list_thread_inbox(state).threads if t.id == identifier).unread
    assert not journal.journal_path(audit).exists()
    ping = api.handle_api_request('POST', '/mcp', {'jsonrpc': '2.0', 'id': 2, 'method': 'ping'},
        vault=vault, state=state, authorization=f'Bearer {token}', audit_log=audit)
    assert (json.loads(ping.body) if isinstance(ping.body, str) else ping.body)['result'] == {}


@pytest.mark.parametrize('bad', [[], None, True, 'arguments'])
@pytest.mark.parametrize('notification', [False, True])
def test_malformed_arguments_stdio_keeps_next_frame(lane, bad, notification):
    identifier = unread(lane)
    body = rpc(bad)
    body['idempotency_key'] = 'malformed-stdio-arguments-0001'
    if notification:
        body.pop('id')
    responses = stdio(lane, [body, {'jsonrpc': '2.0', 'id': 2, 'method': 'ping'}])
    assert [r['id'] for r in responses] == ([2] if notification else [1, 2])
    if not notification:
        assert responses[0]['error']['code'] == -32602
    assert responses[-1]['result'] == {}
    assert not journal.journal_path(lane[2]).exists()
    assert next(t for t in control.list_thread_inbox(lane[1]).threads if t.id == identifier).unread


@pytest.mark.parametrize('phase', ['claim', 'intent', 'dispatch_fence', 'outcome', 'audit_outcome', 'completed'])
@pytest.mark.parametrize('notification', [False, True])
def test_sqlite_failure_stdio_preserves_fence_and_session(lane, phase, notification):
    vault, state, audit = lane
    unread(lane)
    body = rpc({'target': 'demobot', 'idempotency_key': 'sqlite-frame-failure-0001'})
    if notification:
        body.pop('id')
    failed = False
    def fail_once(original, predicate=lambda *a, **kw: True):
        def invoke(*args, **kwargs):
            nonlocal failed
            if not failed and predicate(*args, **kwargs):
                failed = True
                raise sqlite3.OperationalError('PRIVATE_STORAGE_ERROR')
            return original(*args, **kwargs)
        return invoke
    if phase == 'claim':
        target, attribute = mutation_dispatch, 'claim_operation'
        replacement = fail_once(mutation_dispatch.claim_operation)
    elif phase == 'intent':
        target, attribute = mcp, 'append_audit_once'
        replacement = fail_once(mcp.append_audit_once, lambda p, e: e['phase'] == 'intent')
    elif phase == 'dispatch_fence':
        target, attribute = mcp, 'try_begin_dispatch'
        replacement = fail_once(mcp.try_begin_dispatch)
    elif phase == 'audit_outcome':
        target, attribute = mcp, 'append_audit_once'
        replacement = fail_once(mcp.append_audit_once, lambda p, e: e['phase'] == 'outcome')
    else:
        target, attribute = mcp, 'set_operation_state'
        expected = 'outcome_pending' if phase == 'outcome' else 'completed'
        replacement = fail_once(mcp.set_operation_state, lambda p, o, s, **kw: s == expected)
    with patch.object(target, attribute, side_effect=replacement):
        responses = stdio(lane, [body, {'jsonrpc': '2.0', 'id': 2, 'method': 'ping'}])
    assert failed
    assert responses[-1] == {'jsonrpc': '2.0', 'id': 2, 'result': {}}
    assert 'PRIVATE_STORAGE_ERROR' not in json.dumps(responses)
    if not notification:
        assert 'error' in responses[0]
        assert ('outcome uncertain' in responses[0]['error']['message']) == (phase in {'outcome', 'audit_outcome', 'completed'})
    records = journal.pending_operation_records(journal.journal_path(audit))
    if phase != 'claim':
        assert len(records) == 1
        assert records[0].state == {'intent': 'claimed', 'dispatch_fence': 'intent_durable',
            'outcome': 'dispatching', 'audit_outcome': 'outcome_pending', 'completed': 'outcome_pending'}[phase]
    # Retry/reopen may complete an audit or resume pre-effect admission, never repeat an uncertain effect.
    stdio(lane, [body, {'jsonrpc': '2.0', 'id': 3, 'method': 'ping'}])
    assert len([e for e in control.read_events(state) if e.type == 'thread.read']) == 1


def test_legacy_orphan_reopens_and_reconciles_via_confirmed_cli(lane):
    vault, state, audit = lane
    append_audit(audit, {'event_id': 'legacy-op:intent', 'operation_id': 'legacy-op', 'phase': 'intent'})
    original = audit.read_bytes()
    assert pending_operations(audit) == 1
    assert pending_operations(audit) == 1
    args = ['--authority-vault', str(vault), 'operation', 'reconcile', 'legacy-op',
            '--audit-log', str(audit), '--resolution', 'reject-unknown', '--json']
    with redirect_stderr(StringIO()):
        assert cli.main(args) == 1
    assert audit.read_bytes() == original
    out = StringIO()
    with redirect_stdout(out):
        assert cli.main([*args, '--confirm-unknown-may-have-dispatched']) == 0
    assert json.loads(out.getvalue())['redispatched'] is False
    assert audit.read_bytes().startswith(original)
    assert verify_chain(audit).ok
    assert pending_operations(audit) == 0
    assert not state.exists()
    with redirect_stderr(StringIO()):
        assert cli.main([*args, '--confirm-unknown-may-have-dispatched']) == 1


def notification_failure(lane):
    identifier = control.post_thread(lane[1], title='Stale ask', thread_type='ask',
        actor='uma', target='nova').thread.id
    candidate = next(c for c in notify_check(lane[1]).candidates if c['kind'] == 'notification')
    assert control.record_thread_notification_failure(lane[1], identifier, 'notification', 'definite refusal',
        claim_event_id=candidate['claim_event_id'])
    return identifier


def test_canonical_notification_failure_allows_operator_abandonment(lane):
    identifier = notification_failure(lane)
    validate_thread_history(control.read_events(lane[1]), identifier)
    assert abandon_stale_thread(lane[1], thread_id=identifier, reason='Synthetic stale work',
        approval_reference='fixture-only', dry_run=False)['changed']
    validate_thread_history(control.read_events(lane[1]), identifier)


@pytest.mark.parametrize('mutation', ['empty', 'foreign', 'wrong_kind', 'duplicate', 'superseded', 'unknown_field'])
def test_notification_failure_rejects_invalid_generation(lane, mutation):
    identifier = notification_failure(lane)
    events = control.read_events(lane[1])
    failed = events[-1]
    payload = dict(failed.payload)
    if mutation == 'empty': payload['claim_event_id'] = ''
    elif mutation == 'foreign': payload['claim_event_id'] = 'foreign-event'
    elif mutation == 'wrong_kind': payload['kind'] = 'escalation'
    elif mutation == 'unknown_field': payload['surprise'] = 'field'
    elif mutation == 'duplicate':
        events.append(replace(failed, id='second-failure'))
    elif mutation == 'superseded':
        claim = next(e for e in events if e.type == 'thread.notification_sent')
        events.insert(-1, replace(claim, id='replacement-generation'))
    if mutation not in {'duplicate', 'superseded'}: events[-1] = replace(failed, payload=payload)
    with pytest.raises(ValueError): validate_thread_history(events, identifier)


def test_generationless_historical_failure_does_not_release_current_claim(lane):
    identifier = notification_failure(lane)
    events = control.read_events(lane[1])
    failed = events[-1]
    historical = dict(failed.payload)
    historical.pop('claim_event_id')
    # Historical failures are accepted as evidence but cannot clear a current generation.
    events.insert(-1, replace(failed, id='historical-failure', payload=historical))
    validate_thread_history(events, identifier)


def test_journal_missing_row_after_effect_is_sanitized_in_stdio(lane):
    unread(lane)
    original = mcp.set_operation_state
    def missing(path, operation, state, **kwargs):
        if state == 'outcome_pending':
            # Disposable journal only: reproduce its maintained missing-row check.
            with closing(sqlite3.connect(path)) as db, db:
                db.execute('DELETE FROM operations WHERE operation_id=?', (operation,))
        return original(path, operation, state, **kwargs)
    with patch.object(mcp, 'set_operation_state', side_effect=missing):
        responses = stdio(lane, [rpc({'target': 'demobot', 'idempotency_key': 'test-test-test-41'}),
                                 {'jsonrpc': '2.0', 'id': 2, 'method': 'ping'}])
    assert responses[-1]['result'] == {}
    assert 'outcome uncertain' in responses[0]['error']['message']
    assert 'row is missing' not in json.dumps(responses)


def test_legacy_v1_upgrade_is_narrow_and_transactional(lane):
    vault, state, audit = lane
    # Bind current authority while empty; do not adopt populated unbound history.
    store = journal.journal_path(audit)
    normal = journal.claim_operation(store, vault=vault, state=state, principal_scope='operator', action='MCP:control.thread_post',
        idempotency_key='test-test-test-42', request_hash='a' * 64)
    journal.set_operation_state(store, normal.operation_id, 'intent_durable')
    append_audit(audit, {'operation_id': 'orphan-v1', 'phase': 'intent'})
    journal.migrate_legacy_audit_operations(audit)
    with closing(sqlite3.connect(store)) as db, db:
        db.execute("UPDATE operations SET state='intent_durable', dispatch_owner=NULL WHERE operation_id='orphan-v1'")
        db.execute("UPDATE journal_meta SET value='v1' WHERE key=?", (journal.LEGACY_MIGRATION_KEY,))
    class Interrupt(sqlite3.Connection):
        def commit(self): raise sqlite3.OperationalError('migration interrupted before commit')
    def interrupted(path):
        db = sqlite3.connect(path, factory=Interrupt)
        db.execute('PRAGMA synchronous=FULL')
        return db
    with patch.object(journal, '_connect', side_effect=interrupted):
        with pytest.raises(sqlite3.OperationalError): journal.migrate_legacy_audit_operations(audit)
    assert journal.operation_record(store, 'orphan-v1').state == 'intent_durable'
    journal.migrate_legacy_audit_operations(audit)
    assert journal.operation_record(store, 'orphan-v1').state == 'dispatching'
    assert journal.operation_record(store, normal.operation_id).state == 'intent_durable'
    assert not journal.try_begin_dispatch(store, 'orphan-v1', 'cannot-redispatch')
    assert journal.reject_unknown_dispatch(store, 'orphan-v1')
    assert not journal.reject_unknown_dispatch(store, 'orphan-v1')
    journal.migrate_legacy_audit_operations(audit)
    assert journal.operation_record(store, 'orphan-v1').state == 'rejected'


from arvyx_control import agent_delivery, dispatcher, execution, liveness, delivery_probe, outbox

ROUTE_ENV = {'B_ROUTE_URL': 'http://127.0.0.1:9/wake', 'B_ROUTE_CREDENTIAL': 'synthetic-B-route'}
ROUTES = {'nova': agent_delivery.AgentRoute('nova', 'hermes-webhook', 'B_ROUTE_URL', 'B_ROUTE_CREDENTIAL')}


class Accepted:
    status, length = 202, 0
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def read(self, limit): return b'{}'


def dispatch(lane):
    return dispatcher.dispatch_once(lane[1], routes=ROUTES, worker='dispatcher-B',
        deliver_after='2020-01-01T00:00:00Z', max_watermark_age_seconds=10**12,
        now=NOW, clock=lambda: NOW, environ=ROUTE_ENV)


@pytest.mark.parametrize('kind', ['status', 'update'])
def test_mixed_case_api_recipient_routes_without_rewriting_source(lane, kind):
    token = issue_token(lane[0], 'demobot', scopes=['control.write']).token
    response = api.handle_api_request('POST', '/threads',
        {'title': 'Mixed case route', 'type': kind, 'target': ' NoVa '},
        vault=lane[0], state=lane[1], audit_log=lane[2], authorization=f'Bearer {token}',
        idempotency_key='mixed-case-recipient-0001')
    assert response.status == 201, response.body
    captured = []
    def record(request, **kwargs):
        captured.append(json.loads(request.data)); return Accepted()
    with patch.object(agent_delivery._OPENER, 'open', side_effect=record):
        result = dispatch(lane)
        again = dispatch(lane)
    assert result.delivered == 1
    assert again.delivered == 0
    assert not result.skipped_unconfigured_targets
    assert len(captured) == 1 and captured[0]['target_agent'] == 'nova'
    event = next(e for e in control.read_events(lane[1]) if e.type == 'thread.created')
    assert event.payload['target'] == 'NoVa'
    checkpoint = outbox.project_materialization_checkpoint(lane[1])
    assert checkpoint['source_event_id']


def test_case_variant_causing_actor_is_not_self_delivered(lane):
    control.post_thread(lane[1], title='Own update', thread_type='update', actor='NOVA', target='nova')
    control.post_thread(lane[1], title='Own broadcast', thread_type='status', actor=' NoVa ', target='ALL')
    captured = []
    with patch.object(agent_delivery._OPENER, 'open', side_effect=lambda req, **kw: captured.append(req) or Accepted()):
        result = dispatch(lane)
    assert result.claimed == 0
    assert captured == []


@pytest.mark.parametrize('kind', ['thread', 'handoff'])
@pytest.mark.parametrize('order', ['dispatcher-first', 'worker-first', 'overlap'])
def test_assignment_has_one_actionable_execution_wake(lane, kind, order):
    if kind == 'thread':
        subject = control.post_thread(lane[1], title='Bound work', thread_type='ask',
            actor='demobot', target='nova', actor_identity_bound=True).thread.id
    else:
        subject = control.create_handoff(lane[1], title='Bound handoff', from_agent='demobot',
            to_agent='nova', actor_identity_bound=True).handoff.id
    captured, errors = [], []
    barrier = threading.Barrier(2) if order == 'overlap' else None
    def record(request, **kwargs):
        captured.append(json.loads(request.data)); return Accepted()
    def worker():
        with authority_context(lane[0], lane[1]):
            if barrier: barrier.wait(timeout=5)
            claimed = execution.claim_execution(lane[1], worker='execution-B', execution_capable_targets={'nova'}, now=NOW)
            assert claimed and claimed.subject_id == subject
            assert execution.deliver_execution_attempt(claimed, ROUTES['nova'], state=lane[1], now=NOW,
                environ=ROUTE_ENV).accepted
    def dispatcher_tick():
        with authority_context(lane[0], lane[1]):
            if barrier: barrier.wait(timeout=5)
            assert dispatch(lane).ok
    def guarded(fn):
        try: fn()
        except BaseException as exc: errors.append(exc)
    with patch.object(agent_delivery._OPENER, 'open', side_effect=record):
        if barrier:
            threads = [threading.Thread(target=guarded, args=(fn,)) for fn in [worker, dispatcher_tick]]
            for t in threads: t.start()
            for t in threads: t.join(timeout=10)
            assert all(not t.is_alive() for t in threads)
        else:
            for fn in ([dispatcher_tick, worker] if order == 'dispatcher-first' else [worker, dispatcher_tick]): fn()
    assert errors == []
    actionable = [p for p in captured if not p['response_contract'].startswith('execution notice:')]
    assert len(actionable) == 1, captured
    assert actionable[0]['payload']['delivery_mode'] == 'execution'
    assert actionable[0]['payload']['attempt_id']
    notices = [p for p in captured if p not in actionable]
    for notice in notices:
        assert 'do not start work' in notice['response_contract']
        assert 'canonical execution wake' in notice['response_contract']
    assert len(execution.project_executions(lane[1])) == 1


def test_liveness_sibling_states_do_not_share_ticks(tmp_path):
    a, b = tmp_path / 'a.jsonl', tmp_path / 'b.jsonl'
    for state in [a, b]: state.write_text('')
    with authority_context(tmp_path / 'vault', a):
        for component in liveness.TICK_COMPONENTS:
            assert liveness.write_tick_record(a, component=component, result='idle', now=NOW)
    ticks, findings = delivery_probe.check_ticks(b, now=NOW, config=delivery_probe.ProbeConfig())
    assert {v['status'] for v in ticks.values()} == {'missing'}
    assert len(findings) == 2
    assert liveness.liveness_dir(a) != liveness.liveness_dir(b)


def test_liveness_alias_and_copied_record_binding(tmp_path):
    host = tmp_path / 'host'
    host.mkdir()
    container = tmp_path / 'container'
    container.symlink_to(host, target_is_directory=True)
    a, alias = host / 'control-events.jsonl', container / 'control-events.jsonl'
    a.write_text('')
    with authority_context(tmp_path / 'vault', a):
        assert liveness.write_tick_record(a, component='dispatcher', result='ok', now=NOW)
    assert liveness.read_tick_record(alias, 'dispatcher') == liveness.read_tick_record(a, 'dispatcher')
    b = host / 'other.jsonl'
    b.write_text('')
    destination = liveness.tick_record_path(b, 'dispatcher')
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(liveness.tick_record_path(a, 'dispatcher').read_bytes())
    with pytest.raises(ValueError, match='state'):
        liveness.read_tick_record(b, 'dispatcher')


def test_probe_alert_histories_are_independent(tmp_path):
    a, b = tmp_path / 'a.jsonl', tmp_path / 'b.jsonl'
    captured = []
    class Notifier:
        def deliver(self, candidate, dry_run=False):
            captured.append(candidate)
            return type('Delivery', (), {'status': 'recorded', 'detail': ''})()
    def alert(state, verdict):
        return liveness.run_alerting(state_path=liveness.liveness_dir(state) / delivery_probe.PROBE_ALERT_STATE_NAME,
            verdict=verdict, title='Synthetic health', text='Synthetic state', notifier=Notifier(), now=NOW)
    assert alert(a, 'failed')['attempted']
    assert alert(b, 'failed')['attempted']
    assert not alert(a, 'failed')['attempted']
    assert alert(a, 'ok')['reason'] == 'recovery'
    assert not alert(b, 'failed')['attempted']
    assert len(captured) == 3


def test_old_queued_direct_assignment_is_restricted_on_reopen(lane):
    subject = control.post_thread(lane[1], title='Historical queued work', thread_type='ask',
        actor='demobot', target='nova', actor_identity_bound=True).thread.id
    source = next(e for e in control.read_events(lane[1]) if e.task_id == subject)
    old = outbox.enqueue(lane[1], subject_id=subject, target='nova', payload={
        'schema': 'v2.agent-delivery/1', 'source_event_id': source.id,
        'source_event_type': source.type, 'subject_id': subject}, now=NOW)
    captured = []
    with patch.object(agent_delivery._OPENER, 'open', side_effect=lambda req, **kw: captured.append(json.loads(req.data)) or Accepted()):
        assert dispatch(lane).delivered == 1
    assert captured[0]['delivery_id'] == old.id
    assert captured[0]['response_contract'].startswith('execution notice:')
    # Transport restrictions never rewrite the immutable historical payload/ID.
    reopened = outbox.project_outbox(lane[1])[old.id]
    assert reopened.payload == old.payload
    assert reopened.payload_hash == old.payload_hash


@pytest.mark.parametrize('kind', ['thread', 'handoff'])
def test_unbound_new_assignment_does_not_gain_execution_authority(lane, kind):
    if kind == 'thread':
        control.post_thread(lane[1], title='Unbound work', thread_type='ask', actor='demobot', target='nova',
            actor_identity_bound=False)
    else:
        control.create_handoff(lane[1], title='Unbound handoff', from_agent='demobot', to_agent='nova',
            actor_identity_bound=False)
    captured = []
    with patch.object(agent_delivery._OPENER, 'open', side_effect=lambda req, **kw: captured.append(json.loads(req.data)) or Accepted()):
        assert dispatch(lane).delivered == 1
    assert not captured[0]['response_contract'].startswith('execution notice:')
    assert execution.claim_execution(lane[1], worker='worker', execution_capable_targets={'nova'}, now=NOW) is None


@pytest.mark.parametrize('kind', ['thread', 'handoff'])
def test_legacy_target_authorization_converts_pending_notice_without_widening(lane, kind):
    if kind == 'thread':
        identifier = control.post_thread(lane[1], title='Pre-provenance work', thread_type='ask',
            actor='demobot', target='nova').thread.id
    else:
        identifier = control.create_handoff(lane[1], title='Pre-provenance handoff',
            from_agent='demobot', to_agent='nova').handoff.id
    events = control.read_events(lane[1])
    source = events[-1]
    payload = dict(source.payload)
    payload.pop('actor_identity_bound', None)
    source = replace(source, timestamp='2020-01-01T00:00:00Z', payload=payload)
    # Reconstruct the old-generation source in this disposable fixture only.
    lane[1].write_text(json.dumps(source.to_dict()) + '\n')
    if kind == 'thread':
        control.acknowledge_thread(lane[1], identifier, actor='nova', actor_identity_bound=True)
    else:
        control.accept_handoff(lane[1], identifier, actor='nova', actor_identity_bound=True)
    sources = execution.execution_assignment_sources(control.read_events(lane[1]))
    assert sources[source.id] == (kind, 'nova')
    old = outbox.enqueue(lane[1], subject_id=identifier, target='nova', payload={
        'schema': 'v2.agent-delivery/1', 'source_event_id': source.id,
        'source_event_type': source.type, 'subject_id': identifier}, now=NOW)
    captured = []
    with patch.object(agent_delivery._OPENER, 'open', side_effect=lambda req, **kw: captured.append(json.loads(req.data)) or Accepted()):
        assert dispatch(lane).delivered == 1
    assert captured[0]['delivery_id'] == old.id
    assert captured[0]['response_contract'].startswith('execution notice:')
    assert execution.claim_execution(lane[1], worker='worker', execution_capable_targets={'nova'}, now=NOW)


@pytest.mark.parametrize('runtime', ['hermes-webhook', 'openclaw-hook'])
def test_assignment_notice_transport_never_instructs_independent_work(lane, runtime):
    subject = control.post_thread(lane[1], title='No duplicate work', thread_type='ask',
        actor='demobot', target='nova', actor_identity_bound=True).thread.id
    claimed = outbox.claim_due(lane[1], worker='dispatcher', targets={'nova'}, now=NOW,
        deliver_after='2020-01-01T00:00:00Z')
    assert len(claimed) == 1
    captured = []
    route = replace(ROUTES['nova'], runtime=runtime)
    with patch.object(agent_delivery._OPENER, 'open', side_effect=lambda req, **kw: captured.append(json.loads(req.data)) or Accepted()):
        assert agent_delivery.deliver_outbox_item(claimed[0], route, now=NOW, environ=ROUTE_ENV).accepted
    contract = captured[0].get('response_contract') or captured[0]['message']
    assert 'do not start work' in contract and 'canonical execution wake' in contract
    assert 'control.execution_session_get' in contract
    assert not execution.project_executions(lane[1])


def test_liveness_copied_alert_state_cannot_suppress_another_authority(tmp_path):
    a, b = tmp_path / 'a.jsonl', tmp_path / 'b.jsonl'
    a_path = liveness.liveness_dir(a) / delivery_probe.PROBE_ALERT_STATE_NAME
    b_path = liveness.liveness_dir(b) / delivery_probe.PROBE_ALERT_STATE_NAME
    class Notifier:
        def deliver(self, *args, **kwargs):
            return type('Delivery', (), {'status': 'recorded', 'detail': ''})()
    common = dict(verdict='failed', title='Synthetic state', text='Synthetic failure', notifier=Notifier(), now=NOW)
    assert liveness.run_alerting(state_path=a_path, **common)['attempted']
    b_path.parent.mkdir(parents=True, exist_ok=True)
    b_path.write_bytes(a_path.read_bytes())
    result = liveness.run_alerting(state_path=b_path, **common)
    assert result['attempted']
    assert 'binding' in result['state_note']


def test_actual_sqlite_writer_lock_returns_error_then_ping_and_retry(lane):
    unread(lane)
    store = journal.journal_path(lane[2])
    with journal._connection(store): pass
    body = rpc({'target': 'demobot', 'idempotency_key': 'real-writer-lock-0001'})
    with closing(sqlite3.connect(store)) as lock, lock:
        lock.execute('BEGIN IMMEDIATE')
        responses = stdio(lane, [body, {'jsonrpc': '2.0', 'id': 2, 'method': 'ping'}])
    assert responses[0]['error']['message'].startswith('mutation durability unavailable')
    assert responses[-1]['result'] == {}
    stdio(lane, [body])
    assert len([e for e in control.read_events(lane[1]) if e.type == 'thread.read']) == 1


def test_namespaced_liveness_write_failure_is_swallowed(tmp_path):
    state = tmp_path / 'events.jsonl'
    state.write_text('')
    directory = liveness.liveness_dir(state)
    directory.parent.mkdir(parents=True, exist_ok=True)
    directory.write_text('not a directory')
    err = StringIO()
    with authority_context(tmp_path / 'vault', state):
        assert not liveness.write_tick_record(state, component='dispatcher', result='ok', now=NOW, stderr=err)
    assert err.getvalue().startswith('warning: liveness record')
    assert state.read_text() == ''


def test_valid_mutation_can_reuse_key_refused_before_admission(lane):
    unread(lane)
    bad = rpc([])
    bad['idempotency_key'] = 'invalid-then-valid-0001'
    good = rpc({'target': 'demobot'})
    good['idempotency_key'] = bad['idempotency_key']
    responses = stdio(lane, [bad, good, {'jsonrpc': '2.0', 'id': 3, 'method': 'ping'}])
    assert responses[0]['error']['code'] == -32602
    assert 'result' in responses[1]
    assert responses[2]['result'] == {}
    assert len([e for e in control.read_events(lane[1]) if e.type == 'thread.read']) == 1


def test_custom_human_route_uses_canonical_identity(lane):
    control.post_thread(lane[1], title='Human update', thread_type='update', actor='demobot', target=' OWNER ')
    result = dispatcher.dispatch_once(lane[1], routes=ROUTES, worker='dispatcher', now=NOW, clock=lambda: NOW,
        deliver_after='2020-01-01T00:00:00Z', max_watermark_age_seconds=10**12,
        intentional_human_targets={'Owner'}, environ=ROUTE_ENV)
    assert result.ok
    assert result.claimed == 0
    assert result.skipped_intentional_human_targets == ('owner',)


def test_state_file_symlink_alias_uses_same_telemetry(tmp_path):
    root = tmp_path / 'real'
    root.mkdir()
    state = root / 'control-events.jsonl'
    state.write_text('')
    alias = tmp_path / 'renamed-state.jsonl'
    alias.symlink_to(state)
    with authority_context(tmp_path / 'vault', state):
        assert liveness.write_tick_record(state, component='dispatcher', result='idle', now=NOW)
    assert liveness.read_tick_record(alias, 'dispatcher') == liveness.read_tick_record(state, 'dispatcher')


def test_execution_notice_receipt_closes_delivery_without_subject_work(lane):
    subject = control.post_thread(lane[1], title='Informational assignment', thread_type='ask',
        actor='demobot', target='nova', actor_identity_bound=True).thread.id
    captured = []
    with patch.object(agent_delivery._OPENER, 'open', side_effect=lambda req, **kw: captured.append(json.loads(req.data)) or Accepted()):
        assert dispatch(lane).delivered == 1
    wake = captured[0]
    contract = wake['response_contract']
    assert 'control.delivery_receipt' in contract
    assert f"delivery_id={wake['delivery_id']}" in contract
    assert 'status=completed' in contract
    response = mcp.handle_request(rpc({'delivery_id': wake['delivery_id'], 'status': 'completed',
        'idempotency_key': 'notice-receipt-only-0001'}, tool='control.delivery_receipt'),
        vault=lane[0], state=lane[1], secret_audit_log=lane[2], actor='nova',
        allowed_tools={'control.delivery_receipt'})
    assert 'result' in response
    item = outbox.project_outbox(lane[1])[wake['delivery_id']]
    assert item.receipt_status == 'completed' and item.receipt_by == 'nova'
    assert next(t for t in control.list_thread_inbox(lane[1]).threads if t.id == subject).status == 'open'
    assert not execution.project_executions(lane[1])
    assert not any(e.type in {'thread.acknowledged', 'thread.done'} for e in control.read_events(lane[1]))



@pytest.mark.skipif(os.name != 'posix', reason='the deployment tree and its POSIX paths')
def test_deployment_units_scope_exact_telemetry_namespace(tmp_path):
    from pathlib import Path
    root=Path(__file__).resolve().parents[3]
    if not (root/'deploy').is_dir():
        pytest.skip('deployment tree is not part of this checkout (public candidate)')
    state=Path('/srv/arvyx-v2/data/state/control-events.jsonl')
    expected=str(liveness.liveness_dir(state))
    # Host/container bind-mount prefixes deliberately share this basename.
    assert expected.rsplit('/',1)[1]==liveness.liveness_dir(Path('/data/state/control-events.jsonl')).name
    assert liveness.liveness_dir(state.with_name('sibling.jsonl')).name!=Path(expected).name
    for name in ['arvyx-delivery-probe.service','arvyx-delivery-canary.service']:
        source=(root/'deploy/systemd'/name).read_text()
        assert 'ExecStartPre=+/usr/bin/install -d -m 0700 -o 10001 -g 10001 '+expected in source
        assert 'ReadWritePaths=-'+expected+'\n' in source
        assert 'ReadWritePaths=-'+str(state.parent/'liveness')+'\n' not in source
        assert 'User=10001\n' in source and 'ProtectSystem=strict\n' in source
