"""Lane 10 regressions: disposable state, mocked provider/process/transport I/O."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from http.client import parse_headers
from io import BytesIO, StringIO
import json
from pathlib import Path
import re
import tempfile
import os
import unittest
from unittest.mock import Mock, patch
from contextlib import redirect_stdout

from arvyx_control import cockpit_client
from arvyx_control.api import handle_api_request
from arvyx_control.cockpit import LocalCockpit, handle_connection
from arvyx_control.cockpit_fleet import FleetCockpit
from arvyx_control.control import acknowledge_thread, create_task, list_tasks, post_thread
from arvyx_control.execution import claim_execution
from arvyx_control.outbox import claim_due, mark_delivered, project_outbox, record_failure, replay
from arvyx_control.public_onboarding_api import handler_for
from arvyx_control.replica_authority import authority_context
from arvyx_control.session_return import (
    _overlay_delivery, enqueue_session_return_continuation, get_session_return,
    list_session_returns, request_session_return, session_return_dispatch_error,
)

ROOT = Path(__file__).resolve().parents[3]
T0 = datetime(2026, 8, 20, 12, tzinfo=timezone.utc)


@unittest.skipUnless(os.name == 'posix', 'host-shell execution policy (host_uid) and the PTY owner are POSIX-only')
class ReturnReplayTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        cockpit_client.initialize(self.root)
        self.vault, self.state = self.root / 'vault', self.root / 'events.jsonl'
        self.enterContext(authority_context(self.vault, self.state))
        thread = post_thread(self.state, title='Synthetic return', actor='esme', target='amir',
                             actor_identity_bound=True)
        acknowledge_thread(self.state, thread.thread.id, actor='amir', actor_identity_bound=True)
        self.execution = claim_execution(self.state, worker='fixture-worker', now=T0,
                                         lease_seconds=600, execution_capable_targets={'amir'})
        self.request = self.request_return(self.execution, 'deep10-return-original', T0)
        self.sent = []

    def request_return(self, execution, key, now):
        return request_session_return(self.state, execution_id=execution.id,
            attempt_id=execution.attempt_id, actor='amir', message='Synthetic return message',
            expected_word_count=3, idempotency_key=key, now=now)

    def tick(self, *, fail_wake=False):
        # Real journal/recovery/lease primitives; provider I/O is only counted.
        # This deliberately does not hide concurrent dispatcher signature drift.
        for item in claim_due(self.state, worker='fixture-dispatcher', now=T0,
                              targets={'amir'}, limit=10, lease_seconds=300,
                              deliver_after='2026-08-20T11:00:00Z'):
            mode = item.payload.get('delivery_mode')
            self.sent.append(mode)
            if mode == 'session_return':
                self.assertIsNone(session_return_dispatch_error(self.state,
                    execution_id=str(item.payload['execution_id']),
                    attempt_id=str(item.payload['attempt_id']), target=item.target, now=T0))
            if mode == 'session_return_receipt' and fail_wake:
                record_failure(self.state, outbox_id=item.id, worker='fixture-dispatcher',
                    claim_attempts=item.attempts, detail='fixture wake rejected', transient=False, now=T0)
                continue
            finalized = mark_delivered(self.state, outbox_id=item.id, worker='fixture-dispatcher',
                claim_attempts=item.attempts, now=T0,
                provider_receipt='fixture-receipt' if mode == 'session_return' else '')
            if mode == 'session_return':
                enqueue_session_return_continuation(self.state, finalized, now=T0)

    def replay_failed_wake(self):
        self.tick()
        self.original = next(i for i in project_outbox(self.state).values()
                             if i.payload.get('delivery_mode') == 'session_return')
        self.tick(fail_wake=True)
        wake = next(i for i in project_outbox(self.state).values()
                    if i.payload.get('delivery_mode') == 'session_return_receipt')
        self.assertEqual(wake.status, 'dead_lettered')
        routes = self.root / 'routes.json'
        routes.write_text(json.dumps({'routes': {'amir': {'runtime': 'hermes-webhook',
            'url_env': 'FIXTURE_URL', 'credential_env': 'FIXTURE_SECRET'}}}))
        # Pin time only; authentication, operator route, replay and journal are real.
        with patch('arvyx_control.api.replay',
                   side_effect=lambda state, **kw: replay(state, now=T0, **kw)):
            response = handle_api_request('POST', f'/deliveries/{wake.id}/replay', {},
                self.vault, self.state, bearer_secret='synthetic-operator-marker',
                authorization='Bearer synthetic-operator-marker', delivery_routes=routes,
                idempotency_key='deep10-wake-replay')
        self.assertEqual(response.status, 201, response.body)
        replayed = project_outbox(self.state)[response.body['id']]
        self.assertEqual(replayed.epoch, 1)
        return replayed

    def assert_original_readback(self):
        result = get_session_return(self.state, request_id=self.request.request_id, actor='amir')
        self.assertEqual((result.status, result.delivery_id, result.provider_receipt),
                         ('delivered', self.original.id, 'fixture-receipt'))
        self.assertEqual(list_session_returns(self.state, execution_id=self.execution.id,
                                             actor='amir'), [result])
        self.assertEqual(self.sent.count('session_return'), 1)

    def test_r10_01_pending_wake_replay_preserves_get_and_list(self):
        self.replay_failed_wake()
        self.assert_original_readback()

    def test_r10_01_delivered_wake_replay_preserves_get_and_list(self):
        wake = self.replay_failed_wake()
        self.tick()
        self.assertEqual(project_outbox(self.state)[wake.id].status, 'delivered')
        self.assert_original_readback()

    def test_r10_01_dead_wake_replay_preserves_get_and_list(self):
        wake = self.replay_failed_wake()
        self.tick(fail_wake=True)
        self.assertEqual(project_outbox(self.state)[wake.id].status, 'dead_lettered')
        self.assert_original_readback()

    def test_r10_01_failed_wake_does_not_free_reclaimed_lineage(self):
        self.replay_failed_wake()
        self.tick(fail_wake=True)
        later = T0 + timedelta(seconds=720)
        reclaimed = claim_execution(self.state, worker='fixture-worker', now=later,
                                    lease_seconds=600, execution_capable_targets={'amir'})
        self.assertEqual(reclaimed.id, self.execution.id)
        self.assertNotEqual(reclaimed.attempt_id, self.execution.attempt_id)
        with self.assertRaisesRegex(ValueError, 'already has a session return'):
            self.request_return(reclaimed, 'deep10-return-duplicate', later)
        self.assertEqual(self.sent.count('session_return'), 1)

    def test_r10_01_projection_requires_exact_send_identity(self):
        self.tick()
        original = next(i for i in project_outbox(self.state).values()
                        if i.payload.get('delivery_mode') == 'session_return')
        mutations = [dict(target='vesper')]
        for key, value in [('delivery_mode', 'session_return_receipt'),
                           ('execution_id', 'other'), ('attempt_id', 'other'),
                           ('message_sha256', '0' * 64)]:
            mutations.append(dict(payload=dict(original.payload, **{key: value})))
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                unrelated = replace(original, id='unrelated', epoch=99, status='dead_lettered',
                                    provider_receipt='', **mutation)
                result = _overlay_delivery(self.request, {original.id: original, 'unrelated': unrelated})
                self.assertEqual(result.delivery_id, original.id)

    def test_r10_01_actual_send_replay_still_uses_highest_epoch(self):
        original = next(i for i in claim_due(self.state, worker='first', now=T0,
                        targets={'amir'}, limit=10, deliver_after='2026-08-20T11:00:00Z')
                        if i.subject_id == self.request.request_id)
        record_failure(self.state, outbox_id=original.id, worker='first', claim_attempts=original.attempts,
                       detail='fixture rejection', transient=False, now=T0)
        newer = replay(self.state, outbox_id=original.id, now=T0)
        claim_due(self.state, worker='second', now=T0, targets={'amir'}, limit=10)
        mark_delivered(self.state, outbox_id=newer.id, worker='second', claim_attempts=1, now=T0,
                       provider_receipt='fixture-replay-receipt')
        result = get_session_return(self.state, request_id=self.request.request_id, actor='amir')
        self.assertEqual((result.status, result.delivery_id, result.provider_receipt),
                         ('delivered', newer.id, 'fixture-replay-receipt'))


class MemorySocket:
    """Byte framing without binding a socket or starting a service."""
    def __init__(self, payload):
        self.input = BytesIO(payload)
        self.output = BytesIO()

    def settimeout(self, seconds):
        pass

    def recv(self, size):
        return self.input.read(size)

    def sendall(self, data):
        self.output.write(data)


@unittest.skipUnless(os.name == 'posix', 'host-shell execution policy (host_uid) and the PTY owner are POSIX-only')
class FleetIdentityTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        cockpit_client.initialize(self.root)
        # Explicit test-owned host policy bound to the (non-root) test UID; launches
        # still require an explicit execution mode per request.
        from arvyx_control.local_executor import ExecutionPolicy
        import os
        self.owner = LocalCockpit(self.root / 'runtime', self.root / 'vault',
                                   self.root / 'events.jsonl', 'laptop-a',
                                   execution_policy=ExecutionPolicy(host_uid=os.geteuid(), allow_host=True))
        self.addCleanup(self.owner.close)
        self.fleet = FleetCockpit(self.owner, {})

    def exchange(self, endpoint, payload):
        transport = MemorySocket(payload)
        handle_connection(transport, self.owner, self.fleet)
        return transport.output.getvalue()

    def request(self, operation, **fields):
        return cockpit_client.request(self.root, operation, **fields)

    def test_r10_03_open_identity_survives_socket_lifecycle(self):
        with authority_context(self.owner.vault, self.owner.state):
            task = create_task(self.owner.state, 'Synthetic fleet task', owner='demobot').task
        with patch.object(cockpit_client, 'exchange', side_effect=self.exchange):
            opened = self.request('open', project='demo-agent', task=task.id,
                                  name='lane-ten', actor='operator')
            expected = 'laptop-a:' + self.owner.list()[0]['id']
            self.assertEqual(opened['id'], expected)
            self.assertEqual(opened['host'], 'laptop-a')
            self.assertEqual(self.request('list')[0]['id'], expected)
            self.assertEqual(self.request('snapshot', actor='operator')['sessions'][0]['id'], expected)
            selected = self.request('select', sid=expected, revision=0, actor='operator')
            self.assertEqual(selected['selected'], expected)
            # Only the process boundary is mocked; start's authority/native checks run.
            with patch.object(self.owner, '_start',
                              side_effect=lambda sid, **kw: self.owner._get(sid)) as start:
                # Missing mode and a mode the policy denies never reach the process boundary.
                with self.assertRaisesRegex(ValueError, 'explicit execution mode required'):
                    self.request('start', sid=expected, actor='operator')
                with self.assertRaisesRegex(ValueError, 'independent root policy'):
                    self.request('start', sid=expected, actor='operator', environment='root',
                                 root_acknowledged=True)
                start.assert_not_called()
                started = self.request('start', sid=expected, actor='operator', environment='host')
            start.assert_called_once()
            self.assertEqual(start.call_args.args[0], expected.split(':')[1])
            self.assertEqual(started['id'], expected)
            leaf = expected.split(':')[1]
            self.owner.live[leaf] = dict(fd=123, attached=False)
            try:
                attached = self.request('attach', sid=expected, actor='operator')
                self.assertEqual(attached['id'], expected)
                detached = self.request('detach', sid=expected, actor='operator',
                                        attachment=attached['attachment'])
                self.assertEqual(detached['id'], expected)
            finally:
                self.owner.live.clear()  # Synthetic fd must never reach OS cleanup.
            self.assertEqual(self.request('end', sid=expected, actor='operator')['id'], expected)

    def test_r10_03_cli_new_creates_one_task_and_one_session(self):
        with patch.object(cockpit_client, 'exchange', side_effect=self.exchange), \
                patch.object(self.owner, '_start', side_effect=lambda sid, **kw: self.owner._get(sid)) as start, \
                patch('sys.argv', ['cockpit', '--home', str(self.root), 'new', 'lane-ten',
                                   '--title', 'Synthetic CLI task', '--environment', 'host']), redirect_stdout(StringIO()) as out:
            cockpit_client.main()
        result = json.loads(out.getvalue())
        self.assertEqual(result['id'], 'laptop-a:' + self.owner.list()[0]['id'])
        self.assertEqual(len(self.owner.list()), 1)
        self.assertEqual(len(list_tasks(self.owner.state).tasks), 1)
        self.assertEqual(start.call_count, 1)


@unittest.skipUnless(os.name == 'posix', 'host-shell execution policy (host_uid) and the PTY owner are POSIX-only')
class NativeHeaderSourceTests(unittest.TestCase):
    def test_r10_02_source_request_header_reaches_real_handler(self):
        # No native compilation/execution is authorized. Decode the exact wire
        # literal, then exercise Python's actual HTTP header/body gate in memory.
        source = (ROOT / 'frontends/arvyx/amc_session_rpc.rs').read_text()
        # The format string is either one literal or a compile-time concat! of
        # literals only; decode exactly what rustc concatenates.
        string = r'"(?:[^"\\]|\\.)*"'
        match = re.search(r'let request = format!\(\s*(?:(' + string + r')|concat!\(\s*(' + string +
                          r'(?:\s*,\s*' + string + r')*)\s*,?\s*\))\s*,', source)
        self.assertIsNotNone(match, 'native request format literal not found')
        literals = [match.group(1)] if match.group(1) else re.findall(string, match.group(2))
        template = ''.join(json.loads(literal) for literal in literals)
        payload = json.dumps({'target': {'machine_id': 'fixture-machine'}})
        headers = template.split('\r\n')
        self.assertEqual(headers.count('Content-Type: application/json'), 1)
        for operation in ['sessions/recent', 'sessions/all', 'sessions/select',
                          'sessions/workspaces', 'sessions/prepare', 'sessions/commit']:
            with self.subTest(operation=operation):
                head = template.split('\r\n\r\n')[0].replace('{method}', 'POST').replace('{operation}', operation)
                for value in ['127.0.0.1:8080', 'http://127.0.0.1:8080', 'fixture-marker', str(len(payload))]:
                    head = head.replace('{}', value, 1)
                api = Mock()
                api.remote_pairing = None
                api.dispatch.return_value = (200, {'accepted': True})
                handler = object.__new__(handler_for(api))
                handler.command, handler.path = 'POST', '/api/public-onboarding/' + operation
                handler.server = Mock(server_address=('127.0.0.1', 8080), server_port=8080)
                handler.headers = parse_headers(BytesIO(head.split('\r\n', 1)[1].encode() + b'\r\n\r\n'))
                handler.rfile, handler.wfile = BytesIO(payload.encode()), BytesIO()
                handler.send_response, handler.send_header, handler.end_headers = Mock(), Mock(), Mock()
                handler.do_POST()
                handler.send_response.assert_called_once_with(200)
                api.dispatch.assert_called_once_with('POST', handler.path, 'Bearer fixture-marker', json.loads(payload))
                api.dispatch.reset_mock()
                handler.headers.replace_header('Content-Type', 'text/plain')
                handler.send_response.reset_mock()
                handler.rfile = BytesIO(payload.encode())
                handler.do_POST()
                handler.send_response.assert_called_once_with(400)
                api.dispatch.assert_not_called()
