"""Bounded cross-lane regressions. Every authority, transport and process is disposable or mocked."""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import os
import pytest
from arvyx_control import api, audit_log, dispatcher, terminal_sessions, watchdog
from arvyx_control.auth import OPERATOR_IDENTITY
from arvyx_control.control import post_thread, read_events, read_thread, _project_threads, complete_thread
from arvyx_control.execution import claim_execution, hold_execution, close_execution
from arvyx_control.replica_authority import authority_context
from arvyx_control.retirement import retire_thread
from arvyx_control.operator_archive import archive_record, history_digest, related_records
from arvyx_control.agent_delivery import AgentRoute, AgentDeliveryResult

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='fork and flock based snapshot fixtures are POSIX-only')

ROOT = Path(__file__).resolve().parents[3]


def load_script(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def authority(tmp_path):
    vault = tmp_path / 'vault'
    vault.mkdir()
    state = tmp_path / 'events.jsonl'
    with authority_context(vault, state):
        yield vault, state


def test_snapshot_forwards_one_absolute_attempt_deadline(tmp_path, monkeypatch):
    if not (ROOT / 'deploy/systemd/arvyx-v2-snapshot.py').is_file():
        pytest.skip('deployment snapshot script is not part of this checkout (public candidate)')
    capture = load_script('deep10integration_capture', 'deploy/systemd/arvyx-v2-snapshot.py')
    monkeypatch.setattr(capture, 'DATA', tmp_path)
    monkeypatch.setattr(capture, 'LOCK_HOLD', 60)
    seen = []
    @contextmanager
    def prepare(path, *, owner, deadline=None):
        assert deadline is not None, 'production caller omitted its existing deadline'
        seen.append(deadline)
        yield
    monkeypatch.setattr(capture, 'snapshot_preparation', prepare)
    def manifest(path, deadline):
        seen.append(deadline)
        return {}
    monkeypatch.setattr(capture, 'manifest', manifest)
    monkeypatch.setattr(capture, 'copy_tree', lambda stage, a, deadline: seen.append(deadline))
    monkeypatch.setattr(capture, 'stable_cut', lambda a, b, c, deadline: seen.append(deadline) or True)
    work = tmp_path / 'work'
    work.mkdir()
    assert capture.capture_stable(work, max_attempts=1)[2] == 1
    assert len(seen) == 6 and all(value is seen[0] for value in seen)


@pytest.mark.parametrize('body,correlation', [
    ({'id': 7, 'method': 'ping'}, 7),
    ({'jsonrpc': '1.0', 'id': 'x', 'method': 'tools/list'}, 'x'),
    ({'jsonrpc': '2.0', 'id': True, 'method': 'tools/call'}, None),
    ({'jsonrpc': '2.0', 'id': 8, 'method': 'tools/call', 'params': []}, 8),
    ({'jsonrpc': '2.0', 'method': 3}, None),
    ([], None), (False, None), (None, None),
])
def test_http_invalid_envelopes_precede_classification_and_dispatch(authority, tmp_path, body, correlation):
    vault, state = authority
    audit = tmp_path / 'audit.jsonl'
    with patch.object(api, '_requires_audit_success') as classify, patch.object(api, '_handle_api_request') as dispatch:
        response = api.handle_api_request('POST', '/mcp', body, vault, state,
            bearer_secret='fixture', authorization='Bearer fixture', audit_log=audit)
    classify.assert_not_called()
    dispatch.assert_not_called()
    rpc = json.loads(response.body) if isinstance(response.body, str) else response.body
    assert response.status == 400
    assert rpc == {'jsonrpc': '2.0', 'id': correlation,
                   'error': {'code': -32600, 'message': 'invalid JSON-RPC request'}}
    assert not state.exists() and not audit.exists() and not audit_log.journal_path(audit).exists()


@pytest.mark.parametrize('outcome,finalizer', [('sent', 'mark_delivered'), ('ambiguous', 'mark_delivery_ambiguous'),
                                             ('failed', 'record_failure'), ('deferred', 'defer_lease')])
def test_dispatcher_forwards_original_claim_for_every_exit(authority, outcome, finalizer):
    _, state = authority
    now = datetime.now(timezone.utc)
    item = SimpleNamespace(id='outbox_fixture', target='fixturebot', attempts=7, payload={})
    route = AgentRoute('fixturebot', 'hermes-webhook', 'FIXTURE_URL', 'FIXTURE_SECRET')
    result = AgentDeliveryResult(outcome == 'sent', 'ambiguous' if outcome == 'ambiguous' else 'permanent', None, 'fixture')
    clock = Mock(side_effect=[now, now + timedelta(seconds=121), now + timedelta(seconds=121)]) if outcome == 'deferred' else lambda: now
    with patch.object(dispatcher, 'claim_due', return_value=[item]), patch.object(dispatcher, finalizer) as finish:
        finish.return_value = SimpleNamespace(status='dead_lettered', payload={})
        report = dispatcher.dispatch_once(state, routes={'fixturebot': route}, worker='fixture-worker',
            deliver_after=now.isoformat(), limit=1, clock=clock,
            environ={'FIXTURE_URL': 'https://fixture.invalid', 'FIXTURE_SECRET': 'synthetic'},
            deliverer=lambda *a, **kw: result)
    assert not report.processing_errors
    finish.assert_called_once()
    assert finish.call_args.kwargs['claim_attempts'] == 7


def test_runbook_checker_validates_each_configured_project_example():
    checker = load_script('deep10integration_compose', 'scripts/docker_compose_check.py')
    text = (ROOT / 'docs/vps-deployment.md').read_text()
    # Isolate only documentation input validation; never call the full checker.
    errors = []
    checker._check_backup_restore_examples(text, errors)
    assert errors == []
    for bad in (text.replace('--project "$COMPOSE_PROJECT_NAME" backup', '--project arvyx backup'),
                text.replace('--project "$COMPOSE_PROJECT_NAME" restore', '--project arvyx restore'),
                text.replace('set -a; . ./.env; set +a\nbackup_root=', '. ./.env\nbackup_root='),
                text.replace('set -a; . ./.env; set +a\npython3 scripts/backup_restore.py',
                             '. ./.env\npython3 scripts/backup_restore.py')):
        errors = []
        checker._check_backup_restore_examples(bad, errors)
        assert errors, 'wrong project or unexported example must fail closed'


@pytest.fixture
def attach_fixture(tmp_path, monkeypatch):
    binding = {'authority_home': str(tmp_path), 'bindings': [{'sid': 's', 'pane': 'p'}]}
    (tmp_path / 'bindings.json').write_text(json.dumps(binding))
    active = {'conversation': 'c', 'status': 'running'}
    def request(home, op, **kw):
        return [{'id': 's', 'name': 'fixture', 'status': active['status']}] if op == 'list' else {'tool': 'hermes', 'conversation': active['conversation']}
    adapter = terminal_sessions.ExistingArvyxAdapter(tmp_path, tmp_path, '/unused', request_fn=request)
    route = adapter.metadata(adapter.target)[0].route
    monkeypatch.setattr(terminal_sessions.sys.stdin, 'isatty', lambda: True)
    monkeypatch.setattr(terminal_sessions.sys.stdout, 'isatty', lambda: True)
    monkeypatch.setattr(terminal_sessions, 'frontend_environment', lambda _: {})
    native = Mock()
    monkeypatch.setattr(terminal_sessions, 'VerifiedNative', Mock(return_value=Mock(__enter__=Mock(return_value=native), __exit__=Mock(return_value=False))))
    return adapter, route, native, active


def test_direct_attach_exact_focus_ack_then_observation(attach_fixture):
    adapter, route, native, _ = attach_fixture
    edges = []
    snapshots = iter([False, True])
    def invoke(operation, args, **kwargs):
        edges.append(tuple(args))
        if args[-2:] == ['api', 'snapshot']:
            focused = next(snapshots)
            return json.dumps({'result': {'snapshot': {'panes': [
                {'pane_id': 'p', 'workspace_id': 'w', 'tab_id': 't', 'focused': focused},
                {'pane_id': 'sibling', 'workspace_id': 'w', 'tab_id': 't', 'focused': not focused}]}}})
        if args == ['session', 'attach', 'amc']:
            assert edges[-2][-2:] == ('api', 'snapshot')
            return 0
        return '{}'
    native.invoke.side_effect = invoke
    def exchange(endpoint, payload, **options):
        # Foreign frontend API: exact request, no AMC owner budget metadata.
        assert options == {'owner_budget': False}
        request = json.loads(payload)
        assert request['method'] == 'pane.focus' and request['params'] == {'pane_id': 'p'}
        edges.append(('pane.focus',))
        return json.dumps({'id': request['id'], 'result': {'pane': {'pane_id': 'p'}}}).encode()
    with patch('arvyx_control.cockpit_client.exchange', side_effect=exchange) as rpc:
        assert adapter.attach(route) == 0
    rpc.assert_called_once()
    assert edges.index(('pane.focus',)) < len(edges) - 2


@pytest.mark.parametrize('failure', ['wrong_ack', 'error', 'malformed', 'timeout', 'unobserved', 'route_changed', 'binding_changed'])
def test_direct_attach_refuses_uncertain_focus_without_retry(attach_fixture, failure):
    adapter, route, native, active = attach_fixture
    attached = []
    snapshots = []
    def invoke(operation, args, **kwargs):
        if args[-2:] == ['api', 'snapshot']:
            focused = bool(snapshots) and failure in {'route_changed', 'binding_changed'}
            snapshots.append(True)
            return json.dumps({'result': {'snapshot': {'panes': [
                {'pane_id': 'p', 'workspace_id': 'w', 'tab_id': 't', 'focused': focused}]}}})
        if args == ['session', 'attach', 'amc']:
            attached.append(True)
        return '{}'
    native.invoke.side_effect = invoke
    def exchange(endpoint, payload, **options):
        assert options == {'owner_budget': False}
        req = json.loads(payload)
        if failure == 'timeout':
            raise TimeoutError('synthetic consumed focus')
        if failure == 'route_changed':
            active['conversation'] = 'replacement'
        if failure == 'binding_changed':
            (adapter.frontend / 'bindings.json').write_text('{}')
        if failure == 'malformed':
            return b'[]'
        if failure == 'error':
            return json.dumps({'id': req['id'], 'error': {}}).encode()
        return json.dumps({'id': req['id'], 'result': {'pane': {'pane_id': 'wrong' if failure == 'wrong_ack' else 'p'}}}).encode()
    with patch('arvyx_control.cockpit_client.exchange', side_effect=exchange) as rpc:
        with pytest.raises((ValueError, TimeoutError, terminal_sessions.RoutingError)):
            adapter.attach(route)
    assert not attached
    rpc.assert_called_once()


def historical_alert(state, *, ending='.', explicit=False, closed=True, source_actor='arvyx-watchdog'):
    subject = post_thread(state, title='Synthetic task', actor='operator', target='fixturebot',
                          thread_type='ask', actor_identity_bound=True).thread
    execution = claim_execution(state, worker='fixture-worker', execution_capable_targets={'fixturebot'})
    hold_execution(state, execution_id=execution.id, reason='Synthetic reason.', held_by='operator')
    alert = post_thread(state, title=watchdog._escalation_title(execution.id),
        actor=source_actor, target='operator', thread_type='blocker', actor_identity_bound=explicit,
        body=f'target=fixturebot subject=thread {subject.id}; Synthetic reason.{ending}')
    if closed:
        close_execution(state, execution_id=execution.id, reason='Synthetic closure', closed_by='operator', resolution_category='obsolete')
    terminal = read_events(state)[-1]
    strict = dict(expected_event_id=alert.event.id, source_event_id=alert.event.id, target='operator',
        execution_id=execution.id, execution_subject_id=subject.id, execution_target='fixturebot',
        terminal_event_id=terminal.id, category='obsolete_watchdog_alert', reason='Retire only the fixture notification')
    return subject, alert, strict


def archive_request(state, alert, strict):
    events = read_events(state)
    identifier = alert.thread.id
    quote = 'Archive this synthetic alert only.'
    return dict(schema='operator-archive/v1', operation='archive', record_type='thread', record_id=identifier,
        expected_event_id=alert.event.id, source_event_id=alert.event.id, target='operator',
        history_sha256=history_digest(state, identifier),
        related_revisions={i: dict(expected_event_id=next(e.id for e in reversed(events) if e.task_id == i),
            history_sha256=history_digest(state, i)) for i in related_records(events, identifier)},
        category='historical_alert_obsolete', reason='Synthetic obsolete notification.',
        approval_reference='synthetic:integration', approval_quote=quote,
        approval_sha256=hashlib.sha256(quote.encode()).hexdigest(), evidence_references=['synthetic:history'],
        terminal_event_id=strict['terminal_event_id'])


@pytest.mark.parametrize('consumer', ['retirement', 'archive'])
@pytest.mark.parametrize('ending', ['', '.'])
def test_historical_alert_actual_prepare_execute_readback(authority, monkeypatch, consumer, ending):
    _, state = authority
    subject, alert, strict = historical_alert(state, ending=ending)
    identifier = alert.thread.id
    if consumer == 'retirement':
        request = strict  # Strict retirement has no preparation API; bind exact raw event evidence.
        apply = lambda dry: retire_thread(state, thread_id=identifier, request=request, identity=OPERATOR_IDENTITY, dry_run=dry)
    else:
        complete_thread(state, subject.id, actor='fixturebot', actor_identity_bound=True)
        request = archive_request(state, alert, strict)
        with pytest.raises(ValueError, match='disabled'):
            archive_record(state, record_id=identifier, request=request, identity=OPERATOR_IDENTITY)
        monkeypatch.setenv('ARVYX_ENABLE_OPERATOR_ARCHIVE', '1')
        apply = lambda dry: archive_record(state, record_id=identifier, request=request, identity=OPERATOR_IDENTITY, dry_run=dry)
    before = state.read_bytes()
    assert not apply(True)['changed'] and state.read_bytes() == before
    assert apply(False)['changed']
    read_thread(state, identifier)
    assert not apply(False)['changed']
    record = _project_threads(state)[identifier]
    assert record.status == 'retired' and not record.done_at and not record.pending
    assert len([e for e in read_events(state) if e.task_id == identifier and e.type in {'thread.retired', 'thread.operator_archived'}]) == 1


@pytest.mark.parametrize('consumer', ['retirement', 'archive'])
@pytest.mark.parametrize('ending', ['..', '. guidance', ' altered'])
def test_historical_alert_rejects_nonfinite_format_policy(authority, monkeypatch, consumer, ending):
    _, state = authority
    subject, alert, strict = historical_alert(state, ending=ending)
    if consumer == 'archive':
        complete_thread(state, subject.id, actor='fixturebot', actor_identity_bound=True)
        request = archive_request(state, alert, strict)
        monkeypatch.setenv('ARVYX_ENABLE_OPERATOR_ARCHIVE', '1')
        apply = lambda: archive_record(state, record_id=alert.thread.id, request=request, identity=OPERATOR_IDENTITY, dry_run=False)
    else:
        apply = lambda: retire_thread(state, thread_id=alert.thread.id, request=strict, identity=OPERATOR_IDENTITY, dry_run=False)
    before = state.read_bytes()
    with pytest.raises(ValueError, match='HOLD'):
        apply()
    assert state.read_bytes() == before


@pytest.mark.parametrize('explicit', [None, True])
def test_strict_retirement_keeps_explicit_false_provenance(authority, explicit):
    _, state = authority
    _, alert, request = historical_alert(state, explicit=explicit)
    before = state.read_bytes()
    with pytest.raises(ValueError, match='proven operator watchdog'):
        retire_thread(state, thread_id=alert.thread.id, request=request, identity=OPERATOR_IDENTITY)
    assert state.read_bytes() == before


@pytest.mark.parametrize('consumer', ['retirement', 'archive'])
@pytest.mark.parametrize('fault', ['stale', 'live', 'provenance'])
def test_historical_alert_keeps_revision_terminal_and_provenance_fences(authority, monkeypatch, consumer, fault):
    _, state = authority
    subject, alert, strict = historical_alert(state, closed=fault != 'live',
        source_actor='operator' if fault == 'provenance' else 'arvyx-watchdog')
    if consumer == 'archive':
        complete_thread(state, subject.id, actor='fixturebot', actor_identity_bound=True)
        request = archive_request(state, alert, strict)
        monkeypatch.setenv('ARVYX_ENABLE_OPERATOR_ARCHIVE', '1')
        apply = lambda: archive_record(state, record_id=alert.thread.id, request=request, identity=OPERATOR_IDENTITY, dry_run=False)
    else:
        apply = lambda: retire_thread(state, thread_id=alert.thread.id, request=strict, identity=OPERATOR_IDENTITY, dry_run=False)
    if fault == 'stale':
        read_thread(state, alert.thread.id)
    before = state.read_bytes()
    with pytest.raises(ValueError):
        apply()
    assert state.read_bytes() == before


def test_new_private_lane_and_integration_paths_are_classified():
    # Every lane path must be classified explicitly. Since the 2026-11-02 public
    # candidate export, regression tests are public-approved and the private
    # implementation records stay private-only; neither may be unclassified.
    policy = json.loads((ROOT / 'config/public-release-paths.json').read_text())['paths']
    tests = [f'packages/arvctl/tests/test_deep10fix_{i:02}.py' for i in range(1, 11)]
    tests += ['packages/arvctl/tests/test_deep10fix_integration.py']
    records = [f'docs/deep10fix-{i:02}.md' for i in range(1, 11)] + ['docs/deep10fix-integration.md']
    assert {p: policy.get(p) for p in tests} == {p: 'public-approved' for p in tests}
    if not any((ROOT / record).exists() for record in records):
        pytest.skip('private implementation records are not part of this checkout (public candidate)')
    assert {p: policy.get(p) for p in records} == {p: 'private-only' for p in records}


@pytest.mark.parametrize('body', [[], None, False, {'id': 7, 'method': 'ping'}])
def test_http_handler_emits_top_level_jsonrpc_invalid_request(authority, body):
    from email.message import Message
    from io import BytesIO
    vault, state = authority
    payload = json.dumps(body).encode()
    handler = object.__new__(api.make_handler(vault, state, bearer_secret='fixture'))
    handler.path, handler.command = '/mcp', 'POST'
    handler.headers = Message()
    handler.headers['Content-Length'] = str(len(payload))
    handler.headers['Authorization'] = 'Bearer fixture'
    handler.rfile, handler.wfile = BytesIO(payload), BytesIO()
    handler.connection = Mock()
    handler.connection.gettimeout.return_value = None
    handler.send_response, handler.send_header, handler.end_headers = Mock(), Mock(), Mock()
    with patch.object(api, '_requires_audit_success') as classification, patch.object(api, '_handle_api_request') as dispatch:
        handler.do_POST()
    classification.assert_not_called()
    dispatch.assert_not_called()
    handler.send_response.assert_called_once_with(400)
    assert json.loads(handler.wfile.getvalue()) == {'jsonrpc': '2.0', 'id': 7 if isinstance(body, dict) else None,
        'error': {'code': -32600, 'message': 'invalid JSON-RPC request'}}
    assert not state.exists()
    assert handler.connection.settimeout.call_args.args == (None,)
