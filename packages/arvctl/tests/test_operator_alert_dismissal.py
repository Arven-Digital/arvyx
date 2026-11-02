"""Synthetic alert-only cancellation; never embeds production histories."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

from arvyx_control.replica_authority import authority_context
from arvyx_control.auth import OPERATOR_IDENTITY
from arvyx_control.control import (post_thread, read_events, _append_event, _event, _now,
    _project_threads, read_thread, complete_thread, post_thread_message)
from arvyx_control.execution import materialize_executions, hold_execution, close_execution
from arvyx_control.operator_alert_dismissal import prepare_alert_dismissal, dismiss_alert


class AlertDismissalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / 'events.jsonl'
        self.vault = Path(self.tmp.name) / "vault"
        self.vault.mkdir()
        self.enterContext(authority_context(self.vault, self.state))
        self.subject = post_thread(self.state, title='Synthetic work', actor='operator',
            target='demobot', thread_type='ask', body='Unresolved prose thread_unknown remains audit.',
            actor_identity_bound=True).thread
        self.execution = materialize_executions(self.state, execution_capable_targets={'demobot'})[0]
        hold_execution(self.state, execution_id=self.execution.id, reason='Synthetic obsolete hold', held_by='operator')
        self.alert = post_thread(self.state, title=f'[watchdog] execution {self.execution.id} held for operator',
            actor='arvyx-watchdog', target='operator', thread_type='blocker',
            body=f'target=demobot subject=thread {self.subject.id}; Synthetic obsolete hold').thread
        close_execution(self.state, execution_id=self.execution.id, reason='Synthetic explicit closure',
            closed_by='operator', resolution_category='no_longer_actionable')

    def request(self):
        return prepare_alert_dismissal(self.state, record_id=self.alert.id, identity=OPERATOR_IDENTITY,
            reason='Abandon only this obsolete watchdog notification, not its work.',
            approval_reference='synthetic:operator', approval_quote='Dismiss this exact alert only.',
            evidence_references=['synthetic:history'])

    def apply(self, request=None, **kwargs):
        with authority_context(self.vault, self.state):
            return dismiss_alert(self.state, record_id=self.alert.id, request=request or self.request(),
                identity=OPERATOR_IDENTITY, **kwargs)

    def test_diagnostic_reporting_does_not_stale_alert_authority(self):
        import secrets
        from unittest.mock import patch
        from arvyx_control.api import handle_api_request
        from arvyx_control.diagnostics import Reporter
        request = self.request()
        before = self.state.read_bytes()
        reporter = Reporter(Path(self.tmp.name) / 'diagnostics.sqlite')
        self.addCleanup(reporter.close)
        operator_secret = secrets.token_urlsafe(32)
        audit = Path(self.tmp.name) / 'business-audit.jsonl'
        with patch('arvyx_control.api.get_reporter', return_value=reporter):
            result = handle_api_request(method='POST', path='/diagnostics/client',
                body={'kind': 'error'}, vault=Path(self.tmp.name) / 'vault',
                state=self.state, bearer_secret=operator_secret,
                authorization='Bearer ' + operator_secret, audit_log=audit)
        self.assertEqual(202, result.status)
        self.assertTrue(reporter.flush(3))
        self.assertEqual(1, len(reporter.read()['groups']))
        self.assertFalse(audit.exists())
        self.assertEqual(before, self.state.read_bytes())
        self.assertEqual('retired', self.apply(request, dry_run=False)['record']['status'])

    def test_explicit_abandonment_not_completion_or_generic_archive(self):
        from arvyx_control.operator_archive import archive_record, related_records
        request = self.request()
        self.assertIn('thread_unknown', request['audit_references'])
        self.assertIn('thread_unknown', related_records(read_events(self.state), self.alert.id))
        before = self.state.read_bytes()
        self.assertFalse(self.apply(request)['changed'])
        self.assertEqual(before, self.state.read_bytes())
        result = self.apply(request, dry_run=False)
        self.assertEqual('retired', result['record']['status'])
        self.assertFalse(result['record']['pending'])
        self.assertFalse(result['record']['done_at'])
        self.assertEqual('operator_alert_dismissal', result['record']['retirement']['operation'])
        self.assertEqual('notification_only_not_lineage_completion', request['disposition'])
        self.assertTrue(self.state.read_bytes().startswith(before))
        self.assertEqual('open', _project_threads(self.state)[self.subject.id].status)
        with self.assertRaises(ValueError):
            archive_record(self.state, record_id=self.alert.id, request=request, identity=OPERATOR_IDENTITY, dry_run=False)

    def test_exact_retry_and_readback(self):
        r = self.request()
        first = self.apply(r, dry_run=False)
        read_thread(self.state, self.alert.id)
        second = self.apply(r, dry_run=False)
        self.assertFalse(second['changed'])
        self.assertEqual(first['event_id'], second['event_id'])
        r['reason'] = 'Different decision'
        with self.assertRaises(ValueError): self.apply(r, dry_run=False)

    def test_auth_and_no_implicit_apply(self):
        r = self.request()
        before = self.state.read_bytes()
        with self.assertRaisesRegex(ValueError, 'operator'):
            dismiss_alert(self.state, record_id=self.alert.id, request=r, identity=None, dry_run=False)
        for flag in (0, 1, 'false', None):
            with self.assertRaises(ValueError): self.apply(r, dry_run=flag)
        self.assertEqual(before, self.state.read_bytes())

    def test_revision_and_global_raw_digest_fence(self):
        r = self.request()
        post_thread(self.state, title='Unrelated new event', actor='operator', target='demobot')
        before = self.state.read_bytes()
        with self.assertRaisesRegex(ValueError, 'snapshot'): self.apply(r, dry_run=False)
        self.assertEqual(before, self.state.read_bytes())
        r = self.request()
        self.state.write_bytes(self.state.read_bytes().replace(b'Unrelated new event', b'Unrelated old event'))
        with self.assertRaisesRegex(ValueError, 'snapshot'): self.apply(r, dry_run=False)

    def test_future_structural_unknown_blocks_not_filtered(self):
        events = [e.to_dict() for e in read_events(self.state)]
        events[0]['payload']['future_dependency'] = 'thread_unknown'
        self.state.write_text(''.join(json.dumps(e)+'\n' for e in events))
        with self.assertRaisesRegex(ValueError, 'unresolved structural'): self.request()

    def test_live_execution_and_transport_block(self):
        from arvyx_control.outbox import enqueue
        source = next(e for e in read_events(self.state) if e.task_id == self.subject.id)
        enqueue(self.state, subject_id=self.subject.id, target='demobot', payload={
            'schema':'v2.agent-delivery/1', 'source_event_id':source.id,
            'source_event_type':source.type, 'subject_id':self.subject.id})
        with self.assertRaises(ValueError): self.request()

    def test_reverse_unknown_and_continuation_block(self):
        _append_event(self.state, _event('future.authority', 'thread_future', _now(),
            {'continuation_of': self.subject.id}))
        with self.assertRaises(ValueError): self.request()

    def test_selected_legacy_notification_blocks(self):
        _append_event(self.state, _event('thread.notification_failed', self.alert.id, _now(),
            {'thread_id':self.alert.id,'kind':'notification','detail':'Synthetic','failed_at':_now()}))
        with self.assertRaises(ValueError): self.request()

    def test_protected_publisher_in_narrative_blocks(self):
        post_thread_message(self.state, self.subject.id, actor='operator',
            text='Do not waive thread_54db3ef9e6e5_26efde approval.')
        with self.assertRaisesRegex(ValueError, 'publisher'): self.request()

    def test_no_success_resurrection_materialization_and_watchdog(self):
        from arvyx_control.execution import project_executions, reconcile_executions, queue_health
        from arvyx_control.outbox import claim_due, project_outbox
        from arvyx_control.watchdog import _escalated_since_latest_hold
        self.apply(dry_run=False)
        for action in (lambda: complete_thread(self.state, self.alert.id, actor='operator'),
                       lambda: post_thread_message(self.state, self.alert.id, actor='operator', text='Reopen')):
            with self.assertRaises(ValueError): action()
        materialize_executions(self.state, execution_capable_targets={'demobot','operator'})
        claim_due(self.state, worker='synthetic', targets={'demobot','operator'}, deliver_after='2000-01-01T00:00:00Z')
        reconcile_executions(self.state)
        self.assertFalse(any(e.subject_id == self.alert.id for e in project_executions(self.state).values()))
        self.assertFalse(any(e.subject_id == self.alert.id for e in project_outbox(self.state).values()))
        self.assertIn(self.execution.id, _escalated_since_latest_hold(self.state, {self.execution.id}, worker='arvyx-watchdog'))
        health = queue_health(self.state, execution_capable_targets={'operator'})
        self.assertIn(self.alert.id, health['retired_subjects'])
        self.assertEqual(0, health['assigned_without_live_execution_count'])

    def test_racing_duplicate_dismissal_is_one_append(self):
        r = self.request()
        with ThreadPoolExecutor(2) as pool:
            results = list(pool.map(lambda _: self.apply(r, dry_run=False), range(2)))
        self.assertEqual(1, sum(x['changed'] for x in results))
        self.assertEqual(1, sum(e.type == 'thread.operator_archived' for e in read_events(self.state)))

    def test_cold_projection_cache(self):
        self.apply(dry_run=False)
        for suffix in ('.copy1', '.copy2'):
            copy = self.state.with_suffix(suffix)
            copy.write_bytes(self.state.read_bytes())
            projected = _project_threads(copy)[self.alert.id]
            self.assertEqual('retired', projected.status)
            self.assertFalse(projected.pending)
            self.assertFalse(projected.done_at)

    def test_raw_snapshot_not_stale_event_cache(self):
        import os
        read_events(self.state)
        stat = self.state.stat()
        raw = self.state.read_bytes().replace(b'arvyx-watchdog', b'other-watchdog')
        self.state.write_bytes(raw)
        os.utime(self.state, ns=(stat.st_atime_ns, stat.st_mtime_ns))
        with self.assertRaises(ValueError): self.request()

    def test_partial_final_authority_line_blocks(self):
        self.state.write_bytes(self.state.read_bytes().rstrip(b'\n'))
        with self.assertRaisesRegex(ValueError, 'complete'): self.request()

    def test_unknown_owner_cannot_hide_reverse_authority(self):
        _append_event(self.state, _event('future.authority', 'future_owner', _now(),
            {'subject_id': self.alert.id}))
        with self.assertRaises(ValueError): self.request()

    def test_nested_unknown_authority_in_narrative_slot_not_ignored(self):
        from arvyx_control.operator_alert_dismissal import _structural
        self.assertEqual({'execution_unknown'}, _structural({'detail': {'future_link': 'execution_unknown'}}, {}))

    def test_live_origin_after_new_hold_is_blocked(self):
        from dataclasses import replace
        from arvyx_control.execution import project_executions
        record = project_executions(self.state)[self.execution.id]
        _append_event(self.state, _event('execution.future', record.id, _now(),
            replace(record, status='leased', lease_owner='synthetic').to_dict()))
        before = self.state.read_bytes()
        with self.assertRaises(ValueError): self.request()
        self.assertEqual(before, self.state.read_bytes())

    def test_ambiguous_transport_is_not_terminal(self):
        from arvyx_control.outbox import enqueue, claim_due, mark_delivery_ambiguous
        source = next(e for e in read_events(self.state) if e.task_id == self.subject.id)
        item = enqueue(self.state, subject_id=self.subject.id, target='demobot', payload={
            'schema':'v2.agent-delivery/1', 'source_event_id':source.id,
            'source_event_type':source.type, 'subject_id':self.subject.id})
        delivery_claims = claim_due(self.state, worker='synthetic', targets={'demobot'})
        mark_delivery_ambiguous(self.state, outbox_id=item.id, worker='synthetic', claim_attempts=next(c.attempts for c in delivery_claims if c.id == item.id), detail='Synthetic uncertain send')
        with self.assertRaises(ValueError): self.request()

    def test_raw_duplicate_key_and_event_id_rejected(self):
        raw = self.state.read_bytes()
        self.state.write_bytes(raw + raw.splitlines(keepends=True)[0])
        with self.assertRaisesRegex(ValueError, 'duplicate'): self.request()
        self.state.write_bytes(raw.replace(b'"payload":', b'"payload": {}, "payload":', 1))
        with self.assertRaisesRegex(ValueError, 'duplicate'): self.request()

    def test_selected_revision_and_hash_cannot_be_forged(self):
        from copy import deepcopy
        original = self.request()
        for field, value in [('expected_event_id', 'event_'+'f'*24), ('source_event_id','event_'+'e'*24),
                             ('history_sha256','0'*64), ('related_revisions', {}), ('audit_references', [])]:
            with self.subTest(field=field):
                r = deepcopy(original); r[field] = value
                with self.assertRaises(ValueError): self.apply(r, dry_run=False)

    def test_current_agent_or_readonly_operator_cannot_cancel(self):
        from dataclasses import replace
        request = self.request()
        for identity in (replace(OPERATOR_IDENTITY, agent_id='demobot', kind='agent'),
                         replace(OPERATOR_IDENTITY, scopes=frozenset())):
            with self.assertRaises(ValueError):
                dismiss_alert(self.state, record_id=self.alert.id, request=request, identity=identity, dry_run=False)

    def test_race_new_dependency_vs_apply_is_fenced(self):
        from arvyx_control.control import _locked_state, _append_event_unlocked
        r = self.request()
        def add():
            with authority_context(self.vault, self.state):
                with _locked_state(self.state):
                    _append_event_unlocked(self.state, _event('execution.future', 'execution_unknown', _now(),
                        {'subject_id':self.alert.id}))
        def apply():
            with authority_context(self.vault, self.state):
                try: return self.apply(r, dry_run=False)['changed']
                except ValueError: return False
        with ThreadPoolExecutor(2) as pool:
            a, b = pool.submit(add), pool.submit(apply)
            a.result(); applied = b.result()
        # If insertion wins, cancellation fails. If cancellation wins, normal
        # runtime writers (tested separately) cannot create such a dependency.
        events = read_events(self.state)
        if applied:
            self.assertLess(next(i for i,e in enumerate(events) if e.type=='thread.operator_archived'),
                            next(i for i,e in enumerate(events) if e.type=='execution.future'))
        else:
            self.assertFalse(any(e.type=='thread.operator_archived' for e in events))

    def test_receipt_detail_is_audit_but_future_fields_remain_authority(self):
        from arvyx_control.operator_alert_dismissal import _structural
        self.assertEqual(set(), _structural({'receipt_detail':'Inspect thread_missing'}, {}))
        self.assertEqual({'thread_missing'}, _structural({'future_link':'thread_missing'}, {}))

    def test_cold_sqlite_readback(self):
        from arvyx_control.store import sync_sqlite
        import sqlite3
        self.apply(dry_run=False)
        database = Path(self.tmp.name)/'cold.sqlite'
        sync_sqlite(self.state, database)
        with sqlite3.connect(database) as connection:
            row = connection.execute('SELECT status,pending,done_at FROM threads WHERE id=?', (self.alert.id,)).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(('retired', 0, ''), row)

    def test_real_watchdog_and_checkpoint_no_resurrection(self):
        from arvyx_control.agent_delivery import AgentRoute
        from arvyx_control.watchdog import run_watchdog
        from arvyx_control.projection_cache import build_projection_checkpoint, verify_projection_checkpoint
        from arvyx_control.api import handle_api_request
        self.apply(dry_run=False)
        routes = {'demobot': AgentRoute('demobot', 'hermes-webhook', 'SYNTHETIC_URL', 'SYNTHETIC_SECRET')}
        tick = run_watchdog(self.state, routes=routes, environ={}, probe=False)
        self.assertEqual([], tick['escalated'])
        self.assertEqual([], tick['materialized'])
        self.assertEqual('retired', _project_threads(self.state)[self.alert.id].status)
        built = build_projection_checkpoint(self.state, force=True)
        self.assertTrue(built['built'])
        verified = verify_projection_checkpoint(self.state)
        self.assertTrue(verified['ok'], verified)
        operator_value = 'synthetic-operator-value'
        response = handle_api_request('GET', '/control-plane', None, Path(self.tmp.name)/'vault', self.state,
            bearer_secret=operator_value, authorization=f'Bearer {operator_value}')
        self.assertEqual(200, response.status, response.body)
        self.assertIn(self.alert.id, json.dumps(response.body['kanban']['retired']))
        self.assertNotIn(self.alert.id, json.dumps(response.body['kanban']['done']))

    def test_exact_claim_and_transport_enqueue_vs_dismissal(self):
        from arvyx_control.execution import claim_execution, project_executions
        from arvyx_control.outbox import enqueue, project_outbox
        # Missing historical identity is not permission to launch, even if an
        # operator route is configured after dismissal.
        r = self.request()
        def claim_owned():
            with authority_context(self.vault, self.state):
                return claim_execution(self.state, worker='synthetic',
                    execution_capable_targets={'operator'}, subject_id=self.alert.id, target='operator')
        with ThreadPoolExecutor(2) as pool:
            cancelled = pool.submit(self.apply, r, dry_run=False)
            claim = pool.submit(claim_owned)
            self.assertTrue(cancelled.result()['changed'])
            try: self.assertIsNone(claim.result())
            except ValueError: pass
        self.assertFalse(any(e.subject_id==self.alert.id for e in project_executions(self.state).values()))
        with self.assertRaises(ValueError):
            enqueue(self.state, subject_id=self.alert.id, target='operator', payload={'synthetic':True})
        self.assertFalse(any(e.subject_id==self.alert.id for e in project_outbox(self.state).values()))

    def test_conflicting_retry_after_raw_rewrite_and_late_done(self):
        r = self.request()
        self.apply(r, dry_run=False)
        _append_event(self.state, _event('thread.done', self.alert.id, _now(), {'status':'done'}))
        with self.assertRaises(ValueError): self.apply(r, dry_run=False)
        self.assertEqual(1, sum(e.type=='thread.operator_archived' for e in read_events(self.state)))

    def test_retry_rejects_rewritten_abandonment_assertions(self):
        r = self.request()
        self.apply(r, dry_run=False)
        lines = self.state.read_bytes().splitlines(keepends=True)
        event = json.loads(lines[-1])
        event['payload']['retirement']['lineage_completion_asserted'] = True
        self.state.write_bytes(b''.join(lines[:-1]) + json.dumps(event).encode() + b'\n')
        with self.assertRaises(ValueError): self.apply(r, dry_run=False)

    def test_cli_default_dryrun_and_explicit_apply(self):
        import contextlib
        import io
        from arvyx_control.cli import main
        manifest = Path(self.tmp.name)/'request.json'
        manifest.write_text(json.dumps(self.request()))
        args = ['operator-alert-dismissal', self.alert.id, '--state', str(self.state), '--manifest', str(manifest), '--json']
        before = self.state.read_bytes()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, main(["--authority-vault", str(self.vault), *args]))
            self.assertEqual(before, self.state.read_bytes())
            self.assertEqual(0, main(["--authority-vault", str(self.vault), *args + ['--apply']]))
        self.assertEqual('retired', _project_threads(self.state)[self.alert.id].status)

    def test_http_operator_only_dryrun_and_apply(self):
        from arvyx_control.api import handle_api_request
        r = self.request()
        vault = Path(self.tmp.name)/'vault'
        route = '/operator-alert-dismissal/' + self.alert.id
        before = self.state.read_bytes()
        denied = handle_api_request('POST', route, r, vault, self.state, allow_unauthenticated_demo=True)
        self.assertIn(denied.status, {401,403})
        operator_value = 'synthetic-operator-value'
        auth = dict(bearer_secret=operator_value, authorization=f'Bearer {operator_value}')
        response = handle_api_request('POST', route, r, vault, self.state, idempotency_key='synthetic-dryrun', **auth)
        self.assertEqual(200, response.status, response.body)
        self.assertEqual(before, self.state.read_bytes())
        response = handle_api_request('POST', route, dict(r,dry_run=False), vault, self.state,
            idempotency_key='synthetic-apply-dismissal', **auth)
        self.assertEqual(200, response.status, response.body)
        self.assertTrue(response.body['changed'])
