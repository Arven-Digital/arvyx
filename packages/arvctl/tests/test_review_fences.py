from unittest.mock import Mock, patch

from test_execution_bounded import BoundedExecutionTests, NOW
from arvyx_control.control import _append_event_unlocked, _event, read_events
from arvyx_control.execution import materialize_executions
from arvyx_control.outbox import enqueue, project_outbox
from arvyx_control.dispatcher import dispatch_once
from arvyx_control.agent_delivery import AgentRoute, AgentDeliveryResult


class ReviewFences(BoundedExecutionTests):
    def test_invalid_root_never_recreated(self):
        for mode in ('subject_id', 'execution_id'):
            subject = self.post()
            root = next(e for e in materialize_executions(self.state, execution_capable_targets={'sage'}, now=NOW) if e.subject_id == subject)
            payload = root.to_dict()
            payload.update(status='held', attempts='bad')
            _append_event_unlocked(self.state, _event('execution.held', root.id, NOW.isoformat(), payload))
            before = self.state.read_bytes()
            with self.assertRaises(ValueError):
                self.claim(**{mode: subject if mode == 'subject_id' else root.id})
            self.assertEqual(before, self.state.read_bytes())

    def test_full_root_provenance(self):
        for mode in ('subject_id', 'execution_id'):
            for field, value in (('subject_id', 'thread_unrelated'), ('subject_type', 'handoff'),
                                 ('source_event_id', 'event_unrelated'), ('source_event_type', 'handoff.created')):
                subject = self.post()
                root = next(e for e in materialize_executions(self.state, execution_capable_targets={'sage'}, now=NOW) if e.subject_id == subject)
                payload = root.to_dict()
                payload[field] = value
                _append_event_unlocked(self.state, _event('execution.created', root.id, NOW.isoformat(), payload))
                before = self.state.read_bytes()
                with self.assertRaises(ValueError, msg=(mode, field)):
                    self.claim(**{mode: subject if mode == 'subject_id' else root.id})
                self.assertEqual(before, self.state.read_bytes())

    def fixture(self):
        subject = self.post()
        source = next(e for e in read_events(self.state) if e.task_id == subject)
        item = enqueue(self.state, subject_id=subject, target='sage', now=NOW,
                       payload={'source_event_id': source.id, 'source_event_type': source.type,
                                'subject_id': subject, 'schema': 'v2.agent-delivery/1'})
        fence = dict(outbox_id=item.id, subject_id=subject, target='sage', source_event_id=source.id,
                     source_event_type=source.type, execution_id='', attempt_id='', payload_hash=item.payload_hash)
        return item, fence

    def dispatch(self, fences):
        deliver = Mock(return_value=AgentDeliveryResult(True, 'accepted', 202, 'test'))
        result = dispatch_once(self.state, routes={'sage': AgentRoute('sage', 'hermes-webhook', 'URL', 'SECRET', timeout_seconds=1)},
                               worker='bounded', deliver_after='2026-09-21T00:00:00Z', now=NOW, clock=lambda: NOW,
                               environ={'URL': 'http://127.0.0.1/hook', 'SECRET': 'synthetic'},
                               deliverer=deliver, exact_allowlist=fences)
        return result, deliver

    def test_dispatch_preserves_unrelated_and_does_not_materialize(self):
        old, _ = self.fixture()
        chosen, fence = self.fixture()
        self.post()
        before = read_events(self.state)
        result, deliver = self.dispatch([fence])
        self.assertEqual(result.delivered, 1)
        self.assertEqual(deliver.call_args.args[0].id, chosen.id)
        self.assertEqual(project_outbox(self.state)[old.id], old)
        self.assertTrue(all(e.task_id == chosen.id for e in read_events(self.state)[len(before):]))

    def test_return_is_fenced_and_never_implicitly_enqueues_continuation(self):
        from arvyx_control.session_return import request_session_return
        subject = self.post()
        root = self.claim(subject_id=subject)
        request = request_session_return(self.state, execution_id=root.id, attempt_id=root.attempt_id,
                                         actor='sage', message='Local fixture result',
                                         idempotency_key='local-fixture-key-001', expected_word_count=3, now=NOW)
        source = next(e for e in read_events(self.state) if e.task_id == request.request_id)
        payload = dict(schema='v2.agent-delivery/1', source_event_id=source.id,
                       source_event_type=source.type, subject_id=request.request_id, delivery_mode='session_return',
                       **{k: source.payload[k] for k in ('execution_id', 'attempt_id', 'message', 'message_sha256', 'word_count')})
        item = enqueue(self.state, subject_id=request.request_id, target='sage', payload=payload, now=NOW)
        fence = dict(outbox_id=item.id, subject_id=item.subject_id, target=item.target, payload_hash=item.payload_hash,
                     **{k: payload[k] for k in ('source_event_id', 'source_event_type', 'execution_id', 'attempt_id')})
        for key in ('source_event_id', 'attempt_id', 'execution_id'):
            before = self.state.read_bytes()
            result, deliver = self.dispatch([dict(fence, **{key: 'wrong'})])
            self.assertTrue(result.configuration_errors)
            deliver.assert_not_called()
            self.assertEqual(before, self.state.read_bytes())
        before = read_events(self.state)
        with patch('arvyx_control.dispatcher.enqueue_session_return_continuation') as continuation:
            # A receipt-bearing accepted return must not mint an unallowlisted wake.
            with patch('test_review_fences.AgentDeliveryResult',
                    return_value=AgentDeliveryResult(True, 'accepted', 200, 'test', provider_receipt='fixture-receipt')):
                result, deliver = self.dispatch([fence])
            self.assertEqual(result.delivered, 1)
            continuation.assert_not_called()
        self.assertTrue(all(e.task_id == item.id for e in read_events(self.state)[len(before):]))

    def test_continuation_and_wake_modes_refuse_without_writes(self):
        for mode in ('session_return_receipt', 'execution_wake'):
            item, fence = self.fixture()
            payload = dict(item.payload, delivery_mode=mode)
            other = enqueue(self.state, subject_id=item.subject_id, target='sage', payload=payload, now=NOW)
            fence.update(outbox_id=other.id, payload_hash=other.payload_hash)
            before = self.state.read_bytes()
            result, deliver = self.dispatch([fence])
            self.assertTrue(result.configuration_errors)
            deliver.assert_not_called()
            self.assertEqual(before, self.state.read_bytes())

    def test_manifest_validation_is_atomic_and_dry_run_is_read_only(self):
        from arvyx_control.outbox import claim_due
        item, fence = self.fixture()
        for manifest in ([fence, dict(fence, outbox_id='missing')], [fence, fence], {}, []):
            before = self.state.read_bytes()
            with self.assertRaises(ValueError):
                claim_due(self.state, worker='test', targets={'sage'}, now=NOW, limit=5, exact_allowlist=manifest)
            self.assertEqual(before, self.state.read_bytes())
        before = self.state.read_bytes()
        self.assertEqual(claim_due(self.state, worker='test', targets={'sage'}, now=NOW,
                                  dry_run=True, exact_allowlist=[fence]), [])
        self.assertEqual(before, self.state.read_bytes())

    def test_exact_targets_come_from_configured_routes_never_human_targets(self):
        # No agent names live in the exact path: the configured route set is the
        # authority, and an intentional human target is refused even if routed.
        from arvyx_control.outbox import claim_due
        item, fence = self.fixture()
        for kwargs in (dict(targets={'someone-else'}), dict(targets=None),
                       dict(targets={'sage'}, intentional_human_targets={'sage'})):
            with self.subTest(**{k: str(v) for k, v in kwargs.items()}):
                before = self.state.read_bytes()
                with self.assertRaisesRegex(ValueError, 'exact outbox provenance tuple mismatch'):
                    claim_due(self.state, worker='test', now=NOW, limit=5, exact_allowlist=[fence], **kwargs)
                self.assertEqual(before, self.state.read_bytes())
        before = self.state.read_bytes()
        self.assertEqual(claim_due(self.state, worker='test', targets={'sage'}, now=NOW, dry_run=True,
                                   exact_allowlist=[fence], intentional_human_targets={'operator'}), [])
        self.assertEqual(before, self.state.read_bytes())

    def test_cli_explicit_invalid_manifest_never_falls_back(self):
        import io
        import json
        from contextlib import redirect_stdout
        from arvyx_control.dispatcher import main
        self.fixture()
        manifest = self.state.parent / 'allowlist.json'
        routes = self.state.parent / 'routes.json'
        routes.write_text(json.dumps({'routes': {'sage': {'runtime': 'hermes-webhook',
            'url_env': 'URL', 'credential_env': 'SECRET', 'timeout_seconds': 1}}}))
        args = ['--vault', str(self.vault), '--state', str(self.state), '--routes', str(routes),
                '--deliver-after', '2026-09-21T00:00:00Z', '--exact-allowlist', str(manifest)]
        for value in ('null', '[]', '{}', 'not json'):
            manifest.write_text(value)
            before = self.state.read_bytes()
            with patch('arvyx_control.dispatcher.dispatch_once') as dispatch, \
                 patch('arvyx_control.dispatcher.write_tick_record') as tick, \
                 redirect_stdout(io.StringIO()):
                self.assertEqual(main(args), 2)
                dispatch.assert_not_called()
                tick.assert_not_called()
            self.assertEqual(before, self.state.read_bytes())

    def test_dispatch_tuple_mismatches_and_empty_refuse_without_writes(self):
        item, fence = self.fixture()
        for bad in [[], *[[dict(fence, **{key: 'wrong'})] for key in fence]]:
            before = self.state.read_bytes()
            result, deliver = self.dispatch(bad)
            self.assertTrue(result.configuration_errors)
            deliver.assert_not_called()
            self.assertEqual(before, self.state.read_bytes())


def load_tests(loader, tests, pattern):
    import unittest
    # Reuse fixture helpers without rerunning its inherited tests.
    return unittest.TestSuite(ReviewFences(name) for name in ReviewFences.__dict__ if name.startswith('test_'))
