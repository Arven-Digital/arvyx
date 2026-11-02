"""Synthetic exact operator archival contract tests."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from arvyx_control.replica_authority import authority_context
from arvyx_control.auth import OPERATOR_IDENTITY
from arvyx_control.control import post_thread, acknowledge_thread, read_events, complete_task, create_task
from arvyx_control.operator_archive import archive_record, history_digest, related_records


class OperatorArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / 'events.jsonl'
        self.vault = Path(self.tmp.name) / "vault"
        self.vault.mkdir(exist_ok=True)
        self.enterContext(authority_context(self.vault, self.state))
        from unittest.mock import patch
        self.feature_gate = patch.dict('os.environ', {'ARVYX_ENABLE_OPERATOR_ARCHIVE': '1'})
        self.feature_gate.start()
        self.addCleanup(self.feature_gate.stop)

    def cold_call(self, state, function, *args, **kwargs):
        # Simulate a separate configured entrypoint; nested rebinding is refused.
        from contextvars import Context
        def invoke():
            with authority_context(self.vault, state):
                return function(state, *args, **kwargs)
        return Context().run(invoke)

    def thread(self):
        return post_thread(self.state, title='Synthetic obsolete assignment', actor='operator', target='demobot', thread_type='ask').thread

    def request(self, identifier, kind='thread', target='demobot'):
        events = read_events(self.state)
        selected = [e for e in events if e.task_id == identifier]
        quote = 'Cancel this exact synthetic obligation without claiming success.'
        return dict(schema='operator-archive/v1', operation='archive', record_type=kind,
                    record_id=identifier, expected_event_id=selected[-1].id,
                    source_event_id=selected[0].id, target=target,
                    history_sha256=history_digest(self.state, identifier),
                    related_revisions={i: dict(expected_event_id=next(e.id for e in reversed(events) if e.task_id == i), history_sha256=history_digest(self.state, i)) for i in related_records(events, identifier)},
                    category='operator_cancelled_no_longer_needed', reason='Synthetic obligation explicitly abandoned.',
                    approval_reference='synthetic:test-request', approval_quote=quote,
                    approval_sha256=hashlib.sha256(quote.encode()).hexdigest(), evidence_references=['synthetic:decision'],
                    terminal_event_id='')

    def apply(self, r, **kwargs):
        with authority_context(self.vault, self.state):
            return archive_record(self.state, record_id=r['record_id'], request=r, identity=OPERATOR_IDENTITY, **kwargs)

    def test_archive_reason_already_satisfies_control_message_contract(self):
        from arvyx_control.operator_archive import _request
        from arvyx_control.execution import _control_message
        t = self.thread()
        request = self.request(t.id)
        for reason in ("Synthetic reason", "\U0001f600" * 1024):
            request["reason"] = reason
            validated = _request(request, OPERATOR_IDENTITY, t.id, True)
            self.assertEqual(reason, _control_message(validated["reason"], label="close reason"))

    def test_storage_archive_evidence_secret_refused_without_append(self):
        subject = self.thread()
        request = self.request(subject.id)
        request['evidence_references'] = ['ghp_' + 'A' * 36]
        before = self.state.read_bytes()
        with self.assertRaises(ValueError):
            self.apply(request, dry_run=False)
        self.assertEqual(self.state.read_bytes(), before)

    def test_storage_task_creator_survives_archive_and_exact_retry(self):
        # NOT_EXECUTED: archival stays opt-in in this fixture only.
        task = create_task(self.state, title='Synthetic provenance', owner='demobot', created_by='operator').task
        request = self.request(task.id, kind='task')
        first = self.apply(request, dry_run=False)
        after = self.state.read_bytes()
        second = self.apply(request, dry_run=False)
        self.assertEqual(first['record']['created_by'], 'operator')
        self.assertEqual(first['event_id'], second['event_id'])
        self.assertFalse(second['changed'])
        self.assertEqual(self.state.read_bytes(), after)

    def test_dismissal_uses_retirement_auth_fence(self):
        from arvyx_control.api import _is_retirement_route, handle_api_request
        route = '/operator-alert-dismissal/thread_synthetic'
        self.assertTrue(_is_retirement_route(route))
        before = set(Path(self.tmp.name).rglob('*'))
        response = handle_api_request('POST', route, {}, Path(self.tmp.name)/'vault',
                                      self.state, allow_unauthenticated_demo=True)
        self.assertEqual(403, response.status)
        self.assertEqual(before, set(Path(self.tmp.name).rglob('*')))

    def test_generic_archive_disabled_function_api_cli_no_writes(self):
        from unittest.mock import patch
        from contextlib import redirect_stderr, redirect_stdout
        from io import StringIO
        from arvyx_control.api import handle_api_request, _handle_api_request
        from arvyx_control.cli import main
        t = self.thread()
        request = self.request(t.id)
        manifest = Path(self.tmp.name)/'request.json'
        manifest.write_text(json.dumps(request))
        def snapshot():
            return {str(p): p.read_bytes() for p in Path(self.tmp.name).rglob('*') if p.is_file()}
        before = snapshot()
        for flag in (None, '', '0', 'true'):
            with self.subTest(flag=flag), patch.dict('os.environ', {} if flag is None else {'ARVYX_ENABLE_OPERATOR_ARCHIVE': flag}):
                if flag is None:
                    import os
                    os.environ.pop('ARVYX_ENABLE_OPERATOR_ARCHIVE', None)
                for dry_run in (True, False):
                    with self.assertRaisesRegex(ValueError, 'disabled'):
                        self.apply(request, dry_run=dry_run)
                    for handler in (handle_api_request, _handle_api_request):
                        for auth in ({'allow_unauthenticated_demo': True},
                                     {'bearer_secret': 'synthetic-value', 'authorization': 'Bearer synthetic-value'}):
                            response = handler('POST', '/operator-archive/'+t.id,
                                dict(request, dry_run=dry_run), Path(self.tmp.name)/'vault', self.state, **auth)
                            self.assertEqual(503, response.status, response.body)
                with redirect_stderr(StringIO()) as err, redirect_stdout(StringIO()):
                    status = main(["--authority-vault", str(self.vault), *['operator-archive', t.id, '--state', str(self.state),
                                   '--manifest', str(manifest), '--apply']])
                self.assertEqual(1, status)
                self.assertIn('disabled', err.getvalue())
                self.assertEqual(before, snapshot())

    def test_unrelated_archive_metadata_does_not_suppress_reconciliation(self):
        from arvyx_control.control import _append_event, _event, _now, complete_thread
        from arvyx_control.execution import materialize_executions, reconcile_executions
        for event_type in ('bus.message', 'execution.note'):
            with self.subTest(event_type=event_type):
                t = post_thread(self.state, title=event_type, actor='operator', target='demobot', actor_identity_bound=True).thread
                execution = next(e for e in materialize_executions(self.state, execution_capable_targets={'demobot'}) if e.subject_id == t.id)
                _append_event(self.state, _event(event_type, execution.id, _now(), {'operator_archive': {'operation': 'operator_archive'}}))
                complete_thread(self.state, t.id, actor='demobot', actor_identity_bound=True)
                self.assertIn(execution.id, {e.id for e in reconcile_executions(self.state)})

    def test_sqlite_handoff_actor_absent_carries_forward_empty_clears(self):
        import sqlite3
        from arvyx_control.control import create_handoff, accept_handoff, _append_event, _event, _now, _project_handoffs
        from arvyx_control.store import sync_sqlite
        h = create_handoff(self.state, 'Synthetic handoff', from_agent='operator', to_agent='demobot').handoff
        accept_handoff(self.state, h.id, actor='demobot', actor_identity_bound=True)
        p = dict(read_events(self.state)[-1].payload)
        p.pop('accepted_by')
        for event_type, explicit, expected in (('handoff.reviewed', False, 'demobot'),
                                               ('handoff.completed', True, ''),
                                               ('handoff.created', False, '')):
            if explicit:
                p['accepted_by'] = ''
            else:
                p.pop('accepted_by', None)
            _append_event(self.state, _event(event_type, h.id, _now(), dict(p)))
            db = Path(self.tmp.name)/'store.sqlite'
            sync_sqlite(self.state, db)
            with sqlite3.connect(db) as conn:
                actual = conn.execute('SELECT accepted_by FROM handoffs WHERE id=?', (h.id,)).fetchone()[0]
            self.assertEqual(expected, _project_handoffs(self.state)[h.id].accepted_by)
            self.assertEqual(expected, actual)

    def test_materialization_cursor_is_not_business_dependency(self):
        from arvyx_control.control import _append_event, _event, _now
        first = self.thread()
        second = self.thread()
        sources = [e for e in read_events(self.state) if e.type == 'thread.created']
        for source in sources:
            _append_event(self.state, _event('outbox.materialization.checkpoint',
                'outbox_materialization', _now(), {'source_event_id': source.id}))
        self.assertEqual(set(), related_records(read_events(self.state), first.id))
        request = self.request(first.id)
        self.assertEqual('retired', self.apply(request, dry_run=False)['record']['status'])
        self.assertNotIn(second.id, request['related_revisions'])

    def test_reference_symbols_do_not_join_unrelated_histories(self):
        first = post_thread(self.state, title='Synthetic alert', actor='operator', target='demobot',
                            thread_type='ask', body='Inspect control.thread_pending; execution_count=0.').thread
        second = post_thread(self.state, title='Synthetic other', actor='operator', target='demobot',
                             thread_type='ask', body='Inspect control.thread_pending; execution_count=1.').thread
        self.assertEqual(set(), related_records(read_events(self.state), first.id))
        request = self.request(first.id)
        self.assertNotIn(second.id, request['related_revisions'])
        self.assertEqual('retired', self.apply(request, dry_run=False)['record']['status'])

    def test_embedded_and_unicode_adjacent_unknown_links_remain_fenced(self):
        from arvyx_control.operator_archive import _references
        for value, expected in (
            ('parent_thread_unknown', 'thread_unknown'),
            ('source_execution_unknown', 'execution_unknown'),
            ('thread_unknowné', 'thread_unknown'),
            ('prefix_session_return_' + 'a' * 24, 'session_return_' + 'a' * 24),
        ):
            with self.subTest(value=value):
                self.assertEqual({expected}, _references({'future_link': value}))
                self.assertEqual({expected}, _references({'body': value}))

    def test_documented_api_symbols_are_not_prose_dependencies(self):
        from arvyx_control.operator_archive import _references
        symbols = ('thread_pending thread_inbox thread_ack thread_post thread_reply thread_done '
                   'thread_get task_create handoff_create handoff_complete handoff_list '
                   'execution_session_get execution_heartbeat execution_session_return_request '
                   'execution_session_return_get execution_list execution_count task_id thread_id execution_id')
        self.assertEqual(set(), _references({'body': symbols}))
        self.assertEqual(set(symbols.split()), _references({'future_link': symbols}))

    def test_session_return_reference_preserves_whole_identifier(self):
        from arvyx_control.operator_archive import _references
        identifier = 'session_return_' + 'a' * 24
        self.assertEqual({identifier}, _references({'body': f'Inspect `{identifier}`.'}))
        self.assertEqual({identifier}, _references({'session_return_request_id': identifier}))

    def test_reference_scanner_retains_unknown_and_short_lineage(self):
        from arvyx_control.operator_archive import _references
        identifiers = {'thread_' + 'a' * 12, 'execution_unknown', 'return_unknown',
                       'execution_delivery_' + 'b' * 24, 'outbox_' + 'c' * 24,
                       'thread_' + 'd' * 12 + '_' + 'e' * 6}
        self.assertEqual(identifiers, _references({'body': ', '.join(sorted(identifiers))}))
        # Symbols in explicit lineage slots must never be excused as prose.
        for key in ('subject_id', 'continuation_thread_id', 'execution_id', 'future_link'):
            self.assertEqual({'thread_pending'}, _references({key: 'thread_pending'}))

    def test_unknown_reference_still_blocks_apply_without_writes(self):
        from arvyx_control.control import post_thread_message
        thread = self.thread()
        request = self.request(thread.id)
        post_thread_message(self.state, thread.id, actor='operator', text='Unknown thread_deadbeef0000 must remain fenced.')
        events = read_events(self.state)
        request.update(expected_event_id=events[-1].id, history_sha256=history_digest(self.state, thread.id))
        self.assertIn('thread_deadbeef0000', related_records(events, thread.id))
        before = self.state.read_bytes()
        with self.assertRaisesRegex(ValueError, 'complete exact closure'):
            self.apply(request, dry_run=False)
        self.assertEqual(before, self.state.read_bytes())

    def test_existing_symbol_shaped_record_is_never_filtered(self):
        from arvyx_control.control import _append_event, _event, _now
        first = post_thread(self.state, title='Synthetic alert', actor='operator', target='demobot',
                            thread_type='ask', body='Inspect thread_pending.').thread
        _append_event(self.state, _event('thread.future', 'thread_pending', _now(), {}))
        self.assertIn('thread_pending', related_records(read_events(self.state), first.id))

    def test_session_return_unknown_history_blocks_apply(self):
        from arvyx_control.control import _append_event, _event, _now
        identifier = 'session_return_' + 'a' * 24
        first = post_thread(self.state, title='Synthetic alert', actor='operator', target='demobot',
                            thread_type='ask', body=f'Inspect {identifier}.').thread
        _append_event(self.state, _event('session_return.future', identifier, _now(), {}))
        self.assertEqual({identifier}, related_records(read_events(self.state), first.id))
        request = self.request(first.id)
        before = self.state.read_bytes()
        with self.assertRaisesRegex(ValueError, 'unsupported related record kind'):
            self.apply(request, dry_run=False)
        self.assertEqual(before, self.state.read_bytes())

    def test_missing_provenance_dryrun_apply_retry(self):
        thread = self.thread()
        r = self.request(thread.id)
        before = self.state.read_bytes()
        self.assertFalse(self.apply(r)['changed'])
        self.assertEqual(before, self.state.read_bytes())
        result = self.apply(r, dry_run=False)
        self.assertTrue(result['changed'])
        self.assertEqual('retired', result['record']['status'])
        self.assertEqual('missing', result['record']['retirement']['source_actor_identity_bound'])
        self.assertTrue(self.state.read_bytes().startswith(before))
        self.assertEqual(len(read_events(self.state)), 2)
        self.assertFalse(self.apply(r, dry_run=False)['changed'])

    def test_acked_preserved_and_no_materialization(self):
        thread = self.thread()
        acknowledge_thread(self.state, thread.id, actor='demobot', actor_identity_bound=True)
        r = self.request(thread.id)
        result = self.apply(r, dry_run=False)
        self.assertEqual('demobot', result['record']['acked_by'])
        from arvyx_control.execution import materialize_executions
        self.assertEqual([], materialize_executions(self.state, execution_capable_targets={'demobot'}))

    def test_handoff_accept_preserved(self):
        from arvyx_control.control import create_handoff, accept_handoff, complete_handoff, review_handoff, _project_handoffs
        h = create_handoff(self.state, title='Synthetic handoff', from_agent='operator', to_agent='demobot').handoff
        accept_handoff(self.state, h.id, actor='demobot', actor_identity_bound=True)
        r = self.request(h.id, 'handoff')
        self.apply(r, dry_run=False)
        projected = _project_handoffs(self.state)[h.id]
        self.assertEqual('retired', projected.status)
        self.assertEqual('demobot', projected.accepted_by)
        self.assertTrue(projected.retirement)
        for action in (accept_handoff, complete_handoff, review_handoff):
            with self.assertRaises(ValueError):
                action(self.state, h.id)
        from arvyx_control.execution import materialize_executions
        self.assertEqual([], materialize_executions(self.state, execution_capable_targets={'demobot'}))
        self.assertFalse(self.apply(r, dry_run=False)['changed'])

    def test_auth_rejects_quote_as_authority(self):
        from arvyx_control.auth import Identity, SCOPE_CONTROL_WRITE
        t = self.thread()
        r = self.request(t.id)
        before = self.state.read_bytes()
        for identity in (None, Identity(agent_id='operator', kind='agent', scopes=frozenset({SCOPE_CONTROL_WRITE})), Identity(agent_id='operator', kind='operator', scopes=frozenset())):
            with self.assertRaises(ValueError):
                archive_record(self.state, record_id=t.id, request=r, identity=identity, dry_run=False)
            self.assertEqual(before, self.state.read_bytes())

    def test_bad_schema_no_writes(self):
        t = self.thread()
        r = self.request(t.id)
        before = self.state.read_bytes()
        for patch in ({'extra': True}, {'schema': 'operator-archive/v2'}, {'expected_event_id': 'bad'}, {'target': 'other'}, {'approval_sha256': '0'*64}, {'history_sha256': '0'*64}, {'reason': ''}, {'record_type': 'outbox'}, {'terminal_event_id': True}, {'related_revisions': []}):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                self.apply(dict(r, **patch), dry_run=False)
            self.assertEqual(before, self.state.read_bytes())

    def test_unknown_duplicate_and_malformed_raw_history(self):
        from arvyx_control.control import _append_event, _event, _now
        t = self.thread()
        initial = self.state.read_bytes()
        for kind in ('unknown', 'duplicate', 'bad_boolean', 'missing_root'):
            self.state.write_bytes(initial)
            source = read_events(self.state)[0]
            if kind == 'unknown':
                _append_event(self.state, _event('thread.future', t.id, _now(), source.payload))
            elif kind == 'duplicate':
                self.state.write_bytes(initial + initial)
            else:
                p = dict(source.payload)
                p['pending'] = 'true' if kind == 'bad_boolean' else True
                event = source.to_dict()
                event['payload'] = p
                if kind == 'missing_root':
                    event['type'] = 'thread.read'
                self.state.write_text(json.dumps(event) + '\n')
            r = self.request(t.id)
            before = self.state.read_bytes()
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.apply(r, dry_run=False)
            self.assertEqual(before, self.state.read_bytes())

    def test_stale_revision_and_rewritten_bytes(self):
        from arvyx_control.control import post_thread_message
        t = self.thread()
        r = self.request(t.id)
        post_thread_message(self.state, t.id, text='Synthetic later decision', actor='demobot')
        with self.assertRaises(ValueError):
            self.apply(r, dry_run=False)
        r = self.request(t.id)
        raw = self.state.read_bytes()
        self.state.write_bytes(raw.replace(b'Synthetic later decision', b'Synthetic other decision'))
        with self.assertRaises(ValueError):
            self.apply(r, dry_run=False)

    def test_read_retry_and_all_thread_mutations_blocked(self):
        from arvyx_control.control import read_thread, post_thread_message, complete_thread
        t = self.thread()
        r = self.request(t.id)
        self.apply(r, dry_run=False)
        read_thread(self.state, t.id)
        self.assertFalse(self.apply(r, dry_run=False)['changed'])
        for action in (lambda: acknowledge_thread(self.state, t.id, actor='demobot'),
                       lambda: complete_thread(self.state, t.id, actor='demobot'),
                       lambda: post_thread_message(self.state, t.id, actor='demobot', text='No resurrection')):
            with self.assertRaises(ValueError):
                action()
        with self.assertRaises(ValueError):
            self.apply(dict(r, reason='Changed decision'), dry_run=False)

    def test_no_existing_root_exact_claim_route_restore_and_rewind(self):
        from arvyx_control.execution import claim_execution, materialize_executions, reconcile_executions
        from arvyx_control.outbox import claim_due, project_outbox, enqueue
        t = post_thread(self.state, title='Synthetic identity bound root', actor='operator', target='demobot', actor_identity_bound=True).thread
        # Missing route leaves historical source unmaterialized.
        claim_due(self.state, worker='test', targets=set(), deliver_after='2000-01-01T00:00:00Z')
        r = self.request(t.id)
        self.apply(r, dry_run=False)
        for _ in range(2):
            self.assertEqual([], materialize_executions(self.state, execution_capable_targets={'demobot'}))
            self.assertEqual([], reconcile_executions(self.state))
            self.assertIsNone(claim_execution(self.state, worker='test', execution_capable_targets={'demobot'}))
            with self.assertRaises(ValueError):
                claim_execution(self.state, worker='test', execution_capable_targets={'demobot'}, subject_id=t.id, target='demobot')
            self.assertEqual([], claim_due(self.state, worker='test', targets={'demobot'}, deliver_after='2000-01-01T00:00:00Z'))
            self.assertEqual({}, project_outbox(self.state))
            from arvyx_control.execution import queue_health
            health = queue_health(self.state, execution_capable_targets={'demobot'})
            self.assertEqual(0, health['assigned_without_live_execution_count'])
            self.assertIn(t.id, health['retired_subjects'])
        with self.assertRaises(ValueError):
            enqueue(self.state, subject_id=t.id, target='demobot', payload={'synthetic': True})
        # A cold authority copy without materialization cursor cannot revive it.
        copy = Path(self.tmp.name) / 'cold.jsonl'
        copy.write_text(''.join(json.dumps(e.to_dict())+'\n' for e in read_events(self.state) if not e.type.startswith('outbox.materialization.')))
        self.assertEqual([], self.cold_call(copy, claim_due, worker='test', targets={'demobot'}, deliver_after='2000-01-01T00:00:00Z'))
        self.assertEqual({}, project_outbox(copy))

    def test_execution_exact_disposition_then_subject_archive(self):
        from arvyx_control.execution import materialize_executions, project_executions, replay_execution, reconcile_executions
        t = post_thread(self.state, title='Synthetic cancellation', actor='operator', target='demobot', actor_identity_bound=True).thread
        e = materialize_executions(self.state, execution_capable_targets={'demobot'})[0]
        r = self.request(t.id)
        with self.assertRaises(ValueError):
            self.apply(r, dry_run=False)
        er = self.request(e.id, 'execution')
        result = self.apply(er, dry_run=False)
        self.assertEqual('closed', result['record']['status'])
        self.assertFalse(self.apply(er, dry_run=False)['changed'])
        self.assertEqual('closed', project_executions(self.state)[e.id].status)
        self.assertTrue(project_executions(self.state)[e.id].operator_archive_json)
        with self.assertRaises(ValueError):
            replay_execution(self.state, execution_id=e.id, replayed_by='operator')
        self.apply(self.request(t.id), dry_run=False)
        self.assertEqual([], reconcile_executions(self.state))
        self.assertEqual('closed', project_executions(self.state)[e.id].status)

    def test_linked_set_stale_and_new_record(self):
        from arvyx_control.execution import materialize_executions, hold_execution
        t = post_thread(self.state, title='Synthetic linked closure', actor='operator', target='demobot', actor_identity_bound=True).thread
        r = self.request(t.id)
        e = materialize_executions(self.state, execution_capable_targets={'demobot'})[0]
        with self.assertRaises(ValueError):
            self.apply(r, dry_run=False)
        er = self.request(e.id, 'execution')
        acknowledge_thread(self.state, t.id, actor='demobot', actor_identity_bound=True)
        with self.assertRaises(ValueError):
            self.apply(er, dry_run=False)
        er = self.request(e.id, 'execution')
        hold_execution(self.state, execution_id=e.id, reason='Synthetic hold', held_by='operator')
        with self.assertRaises(ValueError):
            self.apply(er, dry_run=False)

    def test_delivered_preserved_and_ambiguous_guard(self):
        from arvyx_control.outbox import enqueue, claim_due, mark_delivered, mark_delivery_ambiguous, project_outbox
        t = self.thread()
        source = read_events(self.state)[0]
        item = enqueue(self.state, subject_id=t.id, target='demobot', payload={'schema':'v2.agent-delivery/1','source_event_id':source.id,'source_event_type':'thread.created','subject_id':t.id})
        with self.assertRaises(ValueError):
            self.apply(self.request(t.id), dry_run=False)
        delivery_claims = claim_due(self.state, worker='test', targets={'demobot'})
        with self.assertRaises(ValueError):
            self.apply(self.request(t.id), dry_run=False)
        mark_delivered(self.state, outbox_id=item.id, worker='test', claim_attempts=next(c.attempts for c in delivery_claims if c.id == item.id))
        old = project_outbox(self.state)[item.id].to_dict()
        r = self.request(t.id)
        self.apply(r, dry_run=False)
        self.assertEqual(old, project_outbox(self.state)[item.id].to_dict())

    def test_sqlite_api_projection_and_unselected_unchanged(self):
        import sqlite3
        from arvyx_control.control import _project_threads, _project_tasks
        from arvyx_control.store import sync_sqlite
        t = self.thread()
        other = self.thread()
        original = [e.to_dict() for e in read_events(self.state) if e.task_id == other.id]
        self.apply(self.request(t.id), dry_run=False)
        self.assertEqual('retired', _project_threads(self.state)[t.id].status)
        self.assertFalse(_project_threads(self.state)[t.id].pending)
        self.assertEqual(original, [e.to_dict() for e in read_events(self.state) if e.task_id == other.id])
        task = create_task(self.state, title='Synthetic sqlite task', owner='demobot').task
        self.apply(self.request(task.id, 'task'), dry_run=False)
        db = Path(self.tmp.name)/'projection.db'
        sync_sqlite(self.state, db)
        with sqlite3.connect(db) as conn:
            for table, identifier in [('threads',t.id), ('tasks',task.id)]:
                row = conn.execute(f'SELECT status, retirement_json FROM {table} WHERE id=?',(identifier,)).fetchone()
                self.assertEqual('retired', row[0])
                self.assertEqual('operator',json.loads(row[1])['operator'])

    def test_duplicate_apply_and_ack_races(self):
        from concurrent.futures import ThreadPoolExecutor
        for race in ('duplicate','ack'):
            t = self.thread()
            r = self.request(t.id)
            def first():
                with authority_context(self.vault, self.state):
                    try:
                        return self.apply(r, dry_run=False)['changed']
                    except ValueError:
                        return 'rejected'
            def second():
                with authority_context(self.vault, self.state):
                    if race == 'duplicate':
                        return first()
                    try:
                        acknowledge_thread(self.state, t.id, actor='demobot', actor_identity_bound=True)
                        return 'acked'
                    except ValueError:
                        return 'rejected'
            with ThreadPoolExecutor(2) as pool:
                a = pool.submit(first)
                b = pool.submit(second)
                results = [a.result(), b.result()]
            if race == 'duplicate':
                self.assertEqual(1, results.count(True))
            else:
                self.assertIn('rejected', results)

    def test_historical_missing_flag_and_old_retirement_still_rejects(self):
        from test_watchdog import ExactRetirementTests
        from arvyx_control.control import complete_thread
        from arvyx_control.retirement import retire_thread
        fixture = ExactRetirementTests()
        fixture.state = self.state
        identifier, old = fixture.alert()
        fixture.rewrite_alert_event(old['source_event_id'], {}, drop=('actor_identity_bound',))
        complete_thread(self.state, old['execution_subject_id'], actor='amir', actor_identity_bound=True)
        with self.assertRaises(ValueError):
            retire_thread(self.state, thread_id=identifier, request=old, identity=OPERATOR_IDENTITY, dry_run=True)
        r = self.request(identifier, target='operator')
        r.update(category='historical_alert_obsolete', terminal_event_id=old['terminal_event_id'])
        raw = self.state.read_bytes()
        result = self.apply(r, dry_run=False)
        self.assertEqual('missing', result['record']['retirement']['source_actor_identity_bound'])
        self.assertTrue(self.state.read_bytes().startswith(raw))
        self.assertFalse(self.apply(r, dry_run=False)['changed'])

    def test_http_operator_default_dryrun_explicit_apply(self):
        from arvyx_control.api import handle_api_request
        t = self.thread()
        r = self.request(t.id)
        vault = Path(self.tmp.name)/'vault'
        before = self.state.read_bytes()
        route = '/operator-archive/' + t.id
        response = handle_api_request('POST', route, r, vault, self.state, allow_unauthenticated_demo=True)
        self.assertIn(response.status, {401,403})
        self.assertEqual(before,self.state.read_bytes())
        operator_value = 'synthetic-operator-value'
        auth = dict(bearer_secret=operator_value, authorization=f'Bearer {operator_value}')
        response = handle_api_request('POST', route, r, vault, self.state, idempotency_key='synthetic-dry-run', **auth)
        self.assertEqual(200, response.status, response.body)
        self.assertTrue(response.body['dry_run'])
        self.assertEqual(before,self.state.read_bytes())
        response = handle_api_request('POST', route, dict(r,dry_run=False), vault, self.state, idempotency_key='synthetic-apply-request', **auth)
        self.assertEqual(200,response.status,response.body)
        self.assertTrue(response.body['changed'])
        response = handle_api_request('GET','/control-plane',None,vault,self.state,**auth)
        self.assertEqual(200,response.status,response.body)
        self.assertIn(t.id, json.dumps(response.body['kanban']['retired']))
        self.assertNotIn(t.id, json.dumps(response.body['kanban']['done']))

    def test_ambiguous_transport_never_hidden(self):
        from arvyx_control.outbox import enqueue, claim_due, mark_delivery_ambiguous, project_outbox
        t = self.thread()
        source = read_events(self.state)[0]
        item = enqueue(self.state, subject_id=t.id, target='demobot', payload={'schema':'v2.agent-delivery/1','source_event_id':source.id,'source_event_type':'thread.created','subject_id':t.id})
        delivery_claims = claim_due(self.state,worker='test',targets={'demobot'})
        mark_delivery_ambiguous(self.state,outbox_id=item.id,worker='test', claim_attempts=next(c.attempts for c in delivery_claims if c.id == item.id),detail='Synthetic unknown provider outcome')
        before = self.state.read_bytes()
        with self.assertRaises(ValueError):
            self.apply(self.request(t.id), dry_run=False)
        self.assertEqual(before, self.state.read_bytes())
        self.assertEqual('ambiguous_delivery',project_outbox(self.state)[item.id].status)

    def test_execution_claim_vs_close_race_and_late_success(self):
        from concurrent.futures import ThreadPoolExecutor
        from arvyx_control.execution import materialize_executions, claim_execution, project_executions, hold_execution, reconcile_executions
        from arvyx_control.control import complete_thread
        t = post_thread(self.state, title='Synthetic race work', actor='operator', target='demobot', actor_identity_bound=True).thread
        e = materialize_executions(self.state, execution_capable_targets={'demobot'})[0]
        r = self.request(e.id, 'execution')
        def close():
            with authority_context(self.vault, self.state):
                try:
                    self.apply(r, dry_run=False)
                    return 'closed'
                except ValueError:
                    return 'rejected'
        def claim():
            with authority_context(self.vault, self.state):
                try:
                    claim_execution(self.state, worker='test', execution_capable_targets={'demobot'}, execution_id=e.id, target='demobot')
                    return 'claimed'
                except ValueError:
                    return 'rejected'
        with ThreadPoolExecutor(2) as pool:
            a,b = pool.submit(close), pool.submit(claim)
            results = [a.result(),b.result()]
        self.assertEqual(1,results.count('rejected'))
        if project_executions(self.state)[e.id].status == 'leased':
            hold_execution(self.state,execution_id=e.id,reason='Synthetic obsolete held work',held_by='operator')
            self.apply(self.request(e.id,'execution'),dry_run=False)
        # Legitimate late subject terminal evidence is retained, not reclassified
        # as success of the explicitly abandoned execution.
        complete_thread(self.state,t.id,actor='demobot',actor_identity_bound=True)
        self.assertEqual([],reconcile_executions(self.state))
        self.assertEqual('closed',project_executions(self.state)[e.id].status)

    def test_exact_claim_races_archive_without_existing_root(self):
        from concurrent.futures import ThreadPoolExecutor
        from arvyx_control.execution import claim_execution, project_executions
        for _ in range(4):
            t = post_thread(self.state, title='Synthetic claim race', actor='operator', target='demobot', actor_identity_bound=True).thread
            r = self.request(t.id)
            def archive():
                with authority_context(self.vault, self.state):
                    try:
                        self.apply(r, dry_run=False)
                        return 'retired'
                    except ValueError:
                        return 'rejected'
            def claim():
                with authority_context(self.vault, self.state):
                    try:
                        claim_execution(self.state, worker='synthetic', execution_capable_targets={'demobot'}, subject_id=t.id, target='demobot')
                        return 'claimed'
                    except ValueError:
                        return 'rejected'
            with ThreadPoolExecutor(2) as pool:
                a, b = pool.submit(archive), pool.submit(claim)
                results = [a.result(), b.result()]
            self.assertEqual(1, results.count('rejected'))
            if 'retired' in results:
                self.assertFalse(any(e.subject_id == t.id for e in project_executions(self.state).values()))

    def test_legacy_notifier_unsettled_fence_rejects(self):
        from arvyx_control.health_ops import notify_check
        t = self.thread()
        notify_check(self.state)
        r = self.request(t.id)
        before = self.state.read_bytes()
        with self.assertRaises(ValueError):
            self.apply(r, dry_run=False)
        self.assertEqual(before, self.state.read_bytes())

    def legacy_root(self, kind='thread', flag='missing', root=True):
        """Synthetic ACK-era schema from 09cd0d5/00f75c5, not live evidence."""
        from arvyx_control.control import create_handoff, accept_handoff, _append_event, _event
        from arvyx_control.execution import Execution, _execution_id
        if kind == 'thread':
            subject = self.thread()
            acknowledge_thread(self.state, subject.id, actor='demobot', actor_identity_bound=True)
        else:
            subject = create_handoff(self.state, title='Synthetic legacy handoff', from_agent='operator', to_agent='demobot').handoff
            accept_handoff(self.state, subject.id, actor='demobot', actor_identity_bound=True)
        raw = [e.to_dict() for e in read_events(self.state)]
        for e in raw:
            if e['task_id'] == subject.id:
                e['payload'].pop('actor_identity_bound', None)
                if e['type'] in {'thread.acknowledged', 'handoff.accepted'} and flag != 'missing':
                    e['payload']['actor_identity_bound'] = flag
        self.state.write_text(''.join(json.dumps(e) + '\n' for e in raw))
        source = read_events(self.state)[-1]
        execution = Execution(id=_execution_id(kind, subject.id, 'demobot'), subject_id=subject.id,
                              subject_type=kind, target='demobot', source_event_id=source.id,
                              source_event_type=source.type, status='pending', attempts=0,
                              created_at=source.timestamp, updated_at=source.timestamp)
        if root:
            _append_event(self.state, _event('execution.created', execution.id, source.timestamp, execution.to_dict()))
        return subject, execution

    def test_legacy_ack_accept_close_then_archive_preserves_unknown(self):
        from arvyx_control.execution import materialize_executions, reconcile_executions, project_executions, claim_execution
        for kind in ('thread', 'handoff'):
            for flag in ('missing', True):
                with self.subTest(kind=kind, flag=flag):
                    subject, execution = self.legacy_root(kind, flag)
                    before = self.state.read_bytes()
                    request = self.request(execution.id, 'execution')
                    self.assertFalse(self.apply(request)['changed'])
                    self.assertEqual(before, self.state.read_bytes())
                    self.apply(request, dry_run=False)
                    self.assertFalse(self.apply(request, dry_run=False)['changed'])
                    sr = self.request(subject.id, kind)
                    result = self.apply(sr, dry_run=False)
                    self.assertEqual('demobot', result['record']['acked_by' if kind == 'thread' else 'accepted_by'])
                    self.assertEqual('missing', result['record']['retirement']['source_actor_identity_bound'])
                    self.assertTrue(self.state.read_bytes().startswith(before))
                    self.assertFalse(self.apply(sr, dry_run=False)['changed'])
                    self.assertEqual([], materialize_executions(self.state, execution_capable_targets={'demobot'}))
                    self.assertEqual([], reconcile_executions(self.state))
                    self.assertEqual('closed', project_executions(self.state)[execution.id].status)
                    with self.assertRaises(ValueError):
                        claim_execution(self.state, worker='synthetic', execution_capable_targets={'demobot'}, execution_id=execution.id, target='demobot')

    def test_legacy_no_root_cold_materialization_inert(self):
        from arvyx_control.execution import materialize_executions, claim_execution
        from arvyx_control.outbox import claim_due, project_outbox
        for kind in ('thread', 'handoff'):
            subject, _ = self.legacy_root(kind, root=False)
            self.apply(self.request(subject.id, kind), dry_run=False)
        cold = Path(self.tmp.name) / 'legacy-cold.jsonl'
        cold.write_bytes(self.state.read_bytes())
        for state in (self.state, cold):
            self.assertEqual([], self.cold_call(state, materialize_executions, execution_capable_targets={'demobot'}))
            self.assertIsNone(self.cold_call(state, claim_execution, worker='synthetic', execution_capable_targets={'demobot'}))
            self.assertEqual([], self.cold_call(state, claim_due, worker='synthetic', targets={'demobot'}, deliver_after='2000-01-01T00:00:00Z'))
            self.assertEqual({}, project_outbox(state))

    def test_legacy_source_owner_actor_and_raw_lineage_reject(self):
        for kind in ('thread', 'handoff'):
            for defect in ('actor', 'owner', 'source_type', 'root_id', 'duplicate', 'future', 'null_flag', 'false_flag', 'source_after_root', 'root_timestamp'):
                with self.subTest(kind=kind, defect=defect):
                    self.state.write_text('')
                    subject, execution = self.legacy_root(kind)
                    raw = [e.to_dict() for e in read_events(self.state)]
                    source = raw[1]
                    if defect == 'actor':
                        source['payload']['acked_by' if kind == 'thread' else 'accepted_by'] = 'other'
                    elif defect == 'owner':
                        source['payload']['target' if kind == 'thread' else 'to_agent'] = 'other'
                    elif defect == 'source_type':
                        raw[-1]['payload']['source_event_type'] = kind + '.created'
                    elif defect == 'root_id':
                        raw[-1]['task_id'] = raw[-1]['payload']['id'] = 'execution_invalid'
                        execution = __import__('dataclasses').replace(execution, id='execution_invalid')
                    elif defect == 'duplicate':
                        raw.insert(2, dict(source))
                    elif defect == 'future':
                        extra = json.loads(json.dumps(source))
                        extra.update(id='event_' + 'f'*24, type=kind + '.future')
                        raw.append(extra)
                    elif defect in {'null_flag', 'false_flag'}:
                        source['payload']['actor_identity_bound'] = None if defect == 'null_flag' else False
                    elif defect == 'root_timestamp':
                        raw[-1]['payload']['created_at'] = '2000-01-01T00:00:00Z'
                    elif defect == 'source_after_root':
                        raw[1], raw[2] = raw[2], raw[1]
                    self.state.write_text(''.join(json.dumps(e)+'\n' for e in raw))
                    request = self.request(execution.id, 'execution')
                    before = self.state.read_bytes()
                    with self.assertRaises(ValueError):
                        self.apply(request, dry_run=False)
                    self.assertEqual(before, self.state.read_bytes())

    def test_legacy_handoff_without_root_requires_recorded_owner_acceptance(self):
        subject, _ = self.legacy_root('handoff', root=False)
        raw = [e.to_dict() for e in read_events(self.state)]
        for actor in ('other', ''):
            raw[-1]['payload']['accepted_by'] = actor
            self.state.write_text(''.join(json.dumps(e)+'\n' for e in raw))
            before = self.state.read_bytes()
            with self.assertRaises(ValueError):
                self.apply(self.request(subject.id, 'handoff'), dry_run=False)
            self.assertEqual(before, self.state.read_bytes())

    def test_legacy_terminal_alert_and_archived_owner_dependency(self):
        from arvyx_control.control import complete_thread, complete_handoff
        from arvyx_control.execution import hold_execution, close_execution, project_executions
        from arvyx_control.watchdog import _escalation_title
        for kind in ('thread', 'handoff'):
            for owner_state in ('active', 'completed', 'archived'):
                with self.subTest(kind=kind, owner_state=owner_state):
                    self.state.write_text('')
                    subject, execution = self.legacy_root(kind)
                    hold_execution(self.state, execution_id=execution.id, reason='Synthetic obsolete hold', held_by='operator')
                    close_execution(self.state, execution_id=execution.id, resolution_category='no_longer_actionable', reason='Synthetic explicit close', closed_by='operator')
                    if owner_state == 'completed':
                        (complete_thread if kind == 'thread' else complete_handoff)(self.state, subject.id, actor='demobot', actor_identity_bound=True)
                    elif owner_state == 'archived':
                        self.apply(self.request(subject.id, kind), dry_run=False)
                    alert = post_thread(self.state, title=_escalation_title(execution.id), actor='arvyx-watchdog', target='operator', thread_type='blocker',
                                        body=f'target=demobot subject={kind} {subject.id}; Synthetic obsolete hold').thread
                    request = self.request(alert.id, target='operator')
                    request.update(category='historical_alert_obsolete', terminal_event_id=next(e.id for e in reversed(read_events(self.state)) if e.task_id == execution.id))
                    before = self.state.read_bytes()
                    if owner_state == 'active':
                        with self.assertRaises(ValueError):
                            self.apply(request, dry_run=False)
                        # Do not resolve the owner/alert cycle by broadening active links.
                        with self.assertRaises(ValueError):
                            self.apply(self.request(subject.id, kind), dry_run=False)
                        self.assertEqual(before, self.state.read_bytes())
                    else:
                        self.assertFalse(self.apply(request)['changed'])
                        self.assertEqual(before, self.state.read_bytes())
                        self.apply(request, dry_run=False)
                        self.assertTrue(self.state.read_bytes().startswith(before))
                        self.assertFalse(self.apply(request, dry_run=False)['changed'])
                        self.assertEqual('closed', project_executions(self.state)[execution.id].status)

    def test_legacy_related_stale_and_active_guards(self):
        from arvyx_control.control import post_thread_message
        subject, execution = self.legacy_root()
        with self.assertRaises(ValueError):
            self.apply(self.request(subject.id), dry_run=False)
        er = self.request(execution.id, 'execution')
        post_thread_message(self.state, subject.id, actor='demobot', text='Synthetic changed decision')
        before = self.state.read_bytes()
        with self.assertRaises(ValueError):
            self.apply(er, dry_run=False)
        self.assertEqual(before, self.state.read_bytes())

    def test_task_non_success(self):
        task = create_task(self.state, title='Synthetic obsolete task', owner='demobot').task
        result = self.apply(self.request(task.id, 'task'), dry_run=False)
        self.assertEqual('retired', result['record']['status'])
        with self.assertRaises(ValueError):
            complete_task(self.state, task.id, actor='demobot')
