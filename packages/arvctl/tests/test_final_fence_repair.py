import http.client
import unittest
from dataclasses import replace
from unittest.mock import Mock, patch
from test_review_fences import ReviewFences
from test_execution_bounded import NOW
from arvyx_control.control import _append_event_unlocked, _event
from arvyx_control.execution import materialize_executions
from arvyx_control.outbox import project_outbox
from arvyx_control.agent_delivery import deliver_outbox_item, AgentRoute, AgentDeliveryResult


class FinalFenceRepair(ReviewFences):
    def test_unknown_execution_and_source_lineage(self):
        for mode in ('subject_id', 'execution_id'):
            for source_event in (False, True):
                subject = self.post()
                root = next(e for e in materialize_executions(self.state, execution_capable_targets={'sage'}, now=NOW) if e.subject_id == subject)
                _append_event_unlocked(self.state, _event('thread.future_hold' if source_event else 'execution.future_hold', subject if source_event else root.id, NOW.isoformat(), {}))
                before = self.state.read_bytes()
                with self.assertRaises(ValueError):
                    self.claim(**{mode: subject if mode == 'subject_id' else root.id})
                self.assertEqual(before, self.state.read_bytes())

    def test_unknown_outbox_and_source_lineage(self):
        for source_event in (False, True):
            item, fence = self.fixture()
            _append_event_unlocked(self.state, _event('thread.future_hold' if source_event else 'outbox.future_cancelled', item.subject_id if source_event else item.id, NOW.isoformat(), {}))
            before = self.state.read_bytes()
            result, deliver = self.dispatch([fence])
            self.assertTrue(result.configuration_errors)
            deliver.assert_not_called()
            self.assertEqual(before, self.state.read_bytes())

    def test_raw_outbox_counters(self):
        for field in ('attempts', 'epoch', 'failures'):
            for value in (False, '0', -1, 1.0):
                item, fence = self.fixture()
                payload = item.to_dict()
                payload[field] = value
                _append_event_unlocked(self.state, _event('outbox.enqueued', item.id, NOW.isoformat(), payload))
                before = self.state.read_bytes()
                result, deliver = self.dispatch([fence])
                self.assertTrue(result.configuration_errors, (field, value))
                deliver.assert_not_called()
                self.assertEqual(before, self.state.read_bytes())

    def test_raw_lifecycle_and_legacy_normal_dispatch(self):
        item, fence = self.fixture()
        payload = item.to_dict()
        payload['status'] = 'future_pending'
        _append_event_unlocked(self.state, _event('outbox.enqueued', item.id, NOW.isoformat(), payload))
        before = self.state.read_bytes()
        result, sender = self.dispatch([fence])
        self.assertTrue(result.configuration_errors)
        sender.assert_not_called()
        self.assertEqual(before, self.state.read_bytes())
        # Ordinary projection deliberately retains its historical coercions.
        other, _ = self.fixture()
        payload = other.to_dict()
        payload.update(attempts=False, epoch='0', failures='0')
        _append_event_unlocked(self.state, _event('outbox.enqueued', other.id, NOW.isoformat(), payload))
        from arvyx_control.outbox import claim_due
        claimed = claim_due(self.state, worker='legacy', targets={'sage'}, now=NOW, limit=20)
        self.assertIn(other.id, [entry.id for entry in claimed])

    def test_unrelated_unknowns_do_not_block(self):
        for typ in ('execution.future_hold', 'outbox.future_cancelled', 'thread.future_hold'):
            _append_event_unlocked(self.state, _event(typ, 'unrelated', NOW.isoformat(), {}))
        self.assertIsNotNone(self.claim(subject_id=self.post()))
        item, fence = self.fixture()
        result, deliver = self.dispatch([fence])
        self.assertEqual(result.delivered, 1)

    def test_actual_adapter_interrupted_response(self):
        item, _ = self.fixture()
        response = Mock(status=200)
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.side_effect = http.client.IncompleteRead(b'{', 100)
        with patch('arvyx_control.agent_delivery._OPENER.open', return_value=response):
            result = deliver_outbox_item(item, AgentRoute('sage', 'hermes-webhook', 'URL', 'SECRET'), now=NOW, environ={'URL': 'http://127.0.0.1/hook', 'SECRET': 'synthetic'})
        self.assertEqual(result.classification, 'ambiguous')

    def test_dispatch_exception_never_retried(self):
        item, fence = self.fixture()
        with patch('test_review_fences.Mock', return_value=Mock(side_effect=http.client.IncompleteRead(b'{', 100))):
            result, deliver = self.dispatch([fence])
        self.assertEqual(result.ambiguous, 1)
        self.assertEqual(result.retrying, 0)
        self.assertEqual(project_outbox(self.state)[item.id].status, 'ambiguous_delivery')
        from arvyx_control.dispatcher import dispatch_once
        deliver = Mock()
        dispatch_once(self.state, routes={'sage': AgentRoute('sage', 'hermes-webhook', 'URL', 'SECRET')}, worker='normal', deliver_after='2026-09-21T00:00:00Z', now=NOW, clock=lambda: NOW, environ={'URL': 'http://127.0.0.1/hook', 'SECRET': 'synthetic'}, deliverer=deliver)
        deliver.assert_not_called()

    def _interrupted_session_return(self, real):
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer
        from arvyx_control.control import read_events
        from arvyx_control.outbox import enqueue
        from arvyx_control.session_return import request_session_return
        from arvyx_control.dispatcher import dispatch_once

        class Handler(BaseHTTPRequestHandler):
            calls = 0
            def log_message(self, *args):
                pass
            def do_POST(self):
                self.rfile.read(int(self.headers['Content-Length']))
                Handler.calls += 1
                self.send_response(200)
                self.send_header('Transfer-Encoding', 'chunked')
                self.end_headers()
                self.wfile.write(b'64\r\n{')  # accepted request, interrupted chunk
                self.wfile.flush()
                self.close_connection = True

        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join)
        self.addCleanup(server.shutdown)
        route = AgentRoute('sage', 'hermes-webhook', 'URL', 'SECRET', timeout_seconds=1,
                           return_url_env='RETURN_URL', return_credential_env='RETURN_SECRET')
        env = {'URL': 'http://127.0.0.1/wake', 'SECRET': 'synthetic',
               'RETURN_URL': f'http://127.0.0.1:{server.server_port}/hook', 'RETURN_SECRET': 'synthetic-return'}
        for real in (real,):
            subject = self.post()
            root = self.claim(subject_id=subject)
            request = request_session_return(self.state, execution_id=root.id, attempt_id=root.attempt_id,
                actor='sage', message='Local fixture result', idempotency_key=f'local-fixture-key-{real}',
                expected_word_count=3, now=NOW)
            source = next(e for e in read_events(self.state) if e.task_id == request.request_id)
            payload = dict(schema='v2.agent-delivery/1', source_event_id=source.id, source_event_type=source.type,
                subject_id=request.request_id, delivery_mode='session_return',
                **{k: source.payload[k] for k in ('execution_id', 'attempt_id', 'message', 'message_sha256', 'word_count')})
            item = enqueue(self.state, subject_id=request.request_id, target='sage', payload=payload, now=NOW)
            fence = dict(outbox_id=item.id, subject_id=item.subject_id, target=item.target, payload_hash=item.payload_hash,
                **{k: payload[k] for k in ('source_event_id', 'source_event_type', 'execution_id', 'attempt_id')})
            args = dict(routes={'sage': route}, worker='test', deliver_after='2026-09-21T00:00:00Z',
                        now=NOW, clock=lambda: NOW, environ=env)
            if real:
                result = dispatch_once(self.state, exact_allowlist=[fence], **args)
            else:
                response = Mock(status=200)
                response.__enter__ = Mock(return_value=response)
                response.__exit__ = Mock(return_value=False)
                response.read.side_effect = http.client.IncompleteRead(b'{', 100)
                with patch('arvyx_control.agent_delivery._OPENER.open', return_value=response):
                    result = dispatch_once(self.state, exact_allowlist=[fence], **args)
            self.assertEqual((result.ambiguous, result.retrying, result.delivered), (1, 0, 0), result)
            self.assertEqual(project_outbox(self.state)[item.id].status, 'ambiguous_delivery')
            sender = Mock(return_value=AgentDeliveryResult(True, 'accepted', 202, 'test'))
            dispatch_once(self.state, deliverer=sender, **args)
            self.assertNotIn(item.id, [call.args[0].id for call in sender.call_args_list])
        self.assertEqual(Handler.calls, int(real))

    def test_session_return_real_interrupted_http(self):
        self._interrupted_session_return(True)

    def test_session_return_mock_interrupted_http(self):
        self._interrupted_session_return(False)

    def test_proven_unsent_is_retryable(self):
        from urllib.error import URLError
        item, _ = self.fixture()
        with patch('arvyx_control.agent_delivery._OPENER.open', side_effect=URLError(ConnectionRefusedError())):
            result = deliver_outbox_item(item, AgentRoute('sage', 'hermes-webhook', 'URL', 'SECRET'),
                now=NOW, environ={'URL': 'http://127.0.0.1/hook', 'SECRET': 'synthetic'})
        self.assertEqual(result.classification, 'transient')


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(FinalFenceRepair(name) for name in FinalFenceRepair.__dict__ if name.startswith('test_'))
