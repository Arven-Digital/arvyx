"""Wave-1 lane-2 acceptance: delegation policy-guard isolation, deadlines, root ack.

Production DelegationService / ExecutorEndpoint / RemoteDelegationEndpoint /
OrganizerAuthority and the durable final-owner fence are exercised directly.
Only the network peer is substituted: either an in-process transport recorder
with real threading barriers, or a disposable loopback socket server. No
process, provider, native binary or credential is used.
"""
import json
import socket
import socketserver
import threading
import time
from unittest.mock import patch

import pytest

from arvyx_control.executor_endpoint import ExecutorEndpoint
from arvyx_control.organizer_authority import OrganizerAuthority
from arvyx_control.organizer_delegation import DelegationService
from arvyx_control.replica_authority import authority_context
from test_durable_organizer_journey import seed, body, consent
from delegation_fixture_helpers import capabilities, issue, admitted

KEY = ('machine-a', 'worker', 'session-exact')


def _in_thread(vault, function):
    """Run function in its own thread under its own authority context."""
    out = {}
    def run():
        try:
            with authority_context(vault):
                out['value'] = function()
        except BaseException as error:  # recorded for the asserting thread
            out['error'] = error
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, out


def _revoke_from_other_instance(policy_path):
    # A separate OrganizerAuthority instance shares only the durable policy file
    # and its portable lock, exactly like an independent revocation process.
    other = OrganizerAuthority(database=policy_path)
    try:
        other.set_organizer(other.identity_handle('organizer'), False)
    finally:
        other.close()


@pytest.fixture
def local(tmp_path):
    vault = tmp_path / 'vault'
    with authority_context(vault):
        policy = OrganizerAuthority(database=tmp_path / 'policy.sqlite')
        actor, worker = seed(policy)
        endpoint = ExecutorEndpoint('http://127.0.0.1:12345', 'synthetic', machine='machine-a',
                                    agent='worker', session='session-exact', environments=('root', 'host'))
        service = DelegationService(tmp_path / 'requests.sqlite', policy, actor, {KEY: endpoint})
        try:
            yield dict(vault=vault, policy=policy, actor=actor, worker=worker, endpoint=endpoint,
                       service=service, path=tmp_path / 'policy.sqlite')
        finally:
            service.close()
            policy.close()


def _transport(state, *, block_on):
    """Recorder peer: exact capabilities and a leaf that honours the final fence."""
    policy = state['policy']
    state.update(entered=threading.Event(), release=threading.Event(), effects=[], calls=[],
                 phase='prepare')
    def call(path, data=None, *, deadline=None):
        state['calls'].append(path)
        # Structural property under test: no transport while the sender holds the guard.
        assert policy._backend.depth == 0, 'endpoint I/O under the sender policy guard'
        if state['phase'] == block_on[0] and path == block_on[1]:
            state['entered'].set()
            assert state['release'].wait(10)
        if path == 'capabilities':
            return capabilities(policy, machine='machine-a', agent='worker', session='session-exact',
                                environments=['root', 'host'])
        with authority_context(state['vault']), admitted(policy, data):
            state['effects'].append(data)
        return dict(request_id=data['request_id'], status='completed', reference='synthetic')
    return call


def _status(service, identifier):
    row = service.db.execute('SELECT status FROM organizer_requests WHERE id=?', (identifier,)).fetchone()
    return row and row[0]


# REV-0118 / REV-0099: commit binding discovery stalls; revocation must not wait.
def test_commit_binding_discovery_stall_never_blocks_revocation(local):
    local['endpoint']._call = _transport(local, block_on=('commit', 'capabilities'))
    review = local['service'].route('delegations/prepare', 'POST', body())[1]
    local['phase'] = 'commit'
    committer, result = _in_thread(local['vault'], lambda: local['service'].route(
        'delegations/commit', 'POST', consent(review)))
    try:
        assert local['entered'].wait(5)
        start = time.monotonic()
        revoker, revoked = _in_thread(local['vault'], lambda: _revoke_from_other_instance(local['path']))
        revoker.join(2)
        # Revocation finished while discovery is still blocked in the peer.
        assert not revoker.is_alive() and 'error' not in revoked, revoked
        assert not local['release'].is_set() and committer.is_alive()
        assert time.monotonic() - start < 2
    finally:
        local['release'].set()
        committer.join(5)
    assert isinstance(result.get('error'), PermissionError), result
    assert local['effects'] == []
    assert _status(local['service'], review['consent_id']) == 'prepared'  # rolled back, never attempted
    assert local['calls'].count('executor/execute') == 0


# REV-0118 / REV-0099 / REV-0519: endpoint execute stalls after the attempt is durable.
def test_execute_stall_never_blocks_revocation_and_late_leaf_is_fenced(local):
    local['endpoint']._call = _transport(local, block_on=('commit', 'executor/execute'))
    review = local['service'].route('delegations/prepare', 'POST', body())[1]
    local['phase'] = 'commit'
    committer, result = _in_thread(local['vault'], lambda: local['service'].route(
        'delegations/commit', 'POST', consent(review)))
    try:
        assert local['entered'].wait(5)
        # The attempt was made durable and ambiguous before any effect transport.
        assert _status(local['service'], review['consent_id']) == 'ambiguous'
        revoker, revoked = _in_thread(local['vault'], lambda: _revoke_from_other_instance(local['path']))
        revoker.join(2)
        assert not revoker.is_alive() and 'error' not in revoked, revoked
        assert not local['release'].is_set() and committer.is_alive()
    finally:
        local['release'].set()
        committer.join(5)
    # The leaf continued after revocation; its final admission refuses the effect.
    assert result['value'][0] == 503 and result['value'][1]['reconcile_required'] is True
    assert local['effects'] == []
    assert _status(local['service'], review['consent_id']) == 'ambiguous'
    with pytest.raises(ValueError):
        local['service'].route('delegations/commit', 'POST', consent(review))  # no replay


# REV-0118: the forwarded (fenced-execute) binding discovery is outside the guard too.
def test_forwarded_binding_stall_never_blocks_revocation(local):
    policy = local['policy']
    policy.bind_executor(local['worker'], machine='machine-a', environments=('host',))
    plan = dict(machine='machine-a', executing_agent='worker', session='session-exact',
                operation='invoke_host', environment='host', goal='synthetic fixture only')
    effect = issue(policy, local['actor'], local['worker'], plan)
    local['endpoint']._call = _transport(local, block_on=('forward', 'capabilities'))
    local['phase'] = 'forward'
    forwarder, result = _in_thread(local['vault'], lambda: local['service'].route(
        'delegations/fenced-execute', 'POST', effect))
    try:
        assert local['entered'].wait(5)
        revoker, revoked = _in_thread(local['vault'], lambda: _revoke_from_other_instance(local['path']))
        revoker.join(2)
        assert not revoker.is_alive() and 'error' not in revoked, revoked
        assert not local['release'].is_set() and forwarder.is_alive()
    finally:
        local['release'].set()
        forwarder.join(5)
    assert isinstance(result.get('error'), PermissionError), result
    assert local['effects'] == [] and 'executor/execute' not in local['calls']
    assert local['service'].db.execute('SELECT count(*) FROM organizer_requests').fetchone()[0] == 0


# REV-0119: the human's actual acknowledgement travels unchanged, never derived.
@pytest.mark.parametrize('ack', [True, False])
def test_host_delegation_forwards_the_humans_exact_acknowledgement(local, ack):
    local['policy'].bind_executor(local['worker'], machine='machine-a', environments=('host',))
    local['endpoint']._call = _transport(local, block_on=('never', 'never'))
    request = dict(body(), operation='invoke_host', environment='host')
    review = local['service'].route('delegations/prepare', 'POST', request)[1]
    status, value = local['service'].route('delegations/commit', 'POST', consent(review, ack))
    assert status == 200, value
    assert [effect['root_acknowledged'] for effect in local['effects']] == [ack]
    recorded = local['service'].db.execute('SELECT consent FROM organizer_requests WHERE id=?',
                                           (review['consent_id'],)).fetchone()[0]
    assert json.loads(recorded) == dict(principal='organizer', confirmed=True, root_acknowledged=ack)


@pytest.mark.parametrize('ack', [False, None, 'true', 1])
def test_root_without_the_humans_boolean_acknowledgement_never_dispatches(local, ack):
    local['endpoint']._call = _transport(local, block_on=('never', 'never'))
    review = local['service'].route('delegations/prepare', 'POST', body())[1]
    with pytest.raises(ValueError, match='root risk acknowledgement'):
        local['service'].route('delegations/commit', 'POST', dict(consent(review), root_acknowledged=ack))
    assert local['effects'] == [] and 'executor/execute' not in local['calls']
    assert _status(local['service'], review['consent_id']) == 'prepared'


def test_remote_root_without_receiver_provisioning_is_refused_before_transport(local, tmp_path):
    from arvyx_control.remote_delegation import RemoteDelegationEndpoint
    calls = []
    with patch('arvyx_control.shared_onboarding_cli.client',
               return_value=lambda *a, **k: calls.append(a) or pytest.fail('no transport')):
        remote = RemoteDelegationEndpoint(tmp_path / 'links.sqlite', 'http://127.0.0.1:12345',
                                          'synthetic', machine='machine-a')
    service = DelegationService(tmp_path / 'remote-requests.sqlite', local['policy'], local['actor'],
                                {KEY: remote})
    try:
        with pytest.raises(PermissionError, match='approval transfer'):
            service.route('delegations/prepare', 'POST', body())
        assert calls == []
        assert service.db.execute('SELECT count(*) FROM organizer_requests').fetchone()[0] == 0
    finally:
        service.close()
        remote.close()


# REV-0099: real sockets; a peer that renews socket timeouts forever is still cut
# off by the non-renewable total deadline, and no policy guard is held meanwhile.
class _Trickle(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        try:
            self.request.recv(65536)
            self.request.sendall(b'HTTP/1.1 200 OK\r\nX-Slow: ')
            for _ in range(400):
                self.request.sendall(b'a')
                time.sleep(.02)
        except OSError:
            pass


@pytest.fixture
def trickle():
    server = socketserver.ThreadingTCPServer(('127.0.0.1', 0), _Trickle)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_address[1]}'
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_trickling_binding_discovery_is_bounded_and_records_nothing(local, trickle):
    endpoint = ExecutorEndpoint(trickle, 'synthetic', machine='machine-a', agent='worker',
                                session='session-exact', environments=('root',), timeout=.3)
    service = DelegationService(local['path'].with_name('trickle.sqlite'), local['policy'], local['actor'],
                                {KEY: endpoint})
    try:
        start = time.monotonic()
        with pytest.raises(OSError):
            service.route('delegations/prepare', 'POST', body())
        assert time.monotonic() - start < 1.5
        assert service.db.execute('SELECT count(*) FROM organizer_requests').fetchone()[0] == 0
        # Policy stays immediately available after the bounded failure.
        start = time.monotonic()
        _revoke_from_other_instance(local['path'])
        assert time.monotonic() - start < 1
    finally:
        service.close()


def test_trickling_remote_peer_is_bounded_and_never_replayed(tmp_path, trickle):
    from arvyx_control.remote_delegation import RemoteDelegationEndpoint
    remote = RemoteDelegationEndpoint(tmp_path / 'links.sqlite', trickle, 'synthetic',
                                      machine='machine-a', timeout=.3)
    plan = dict(machine='machine-a', executing_agent='worker', session='session-exact',
                operation='invoke_host', environment='host', goal='synthetic', request_id='c' * 32,
                root_acknowledged=False)
    try:
        start = time.monotonic()
        with pytest.raises(OSError):
            remote.execution_binding(plan)
        assert time.monotonic() - start < 1.5
        start = time.monotonic()
        with pytest.raises(OSError):
            remote.execute(plan)
        assert time.monotonic() - start < 1.5
        # The attempt was recorded before transport; it reconciles, never replays.
        assert remote.db.execute('SELECT status FROM remote_delegation_links WHERE local_id=?',
                                 ('c' * 32,)).fetchone()[0] == 'ambiguous'
        with pytest.raises(ValueError, match='reconcile'):
            remote.execute(plan)
    finally:
        remote.close()



# REV-0045: a human-bound primary is a presentation selection. Without explicit
# owner organizer configuration it fails closed with an actionable refusal and
# never populates organizer configuration; with exact explicit configuration the
# default organizer path resolves exactly that agent and starts no process.
import unittest
import test_cockpit_local as _local_harness
import test_cockpit_human_binding as _binding_harness


class HumanBoundPrimaryOrganizerTests(unittest.TestCase):
    # Reuse the harmless real-owner harness without re-collecting its tests.
    setUp = _local_harness.HarmlessOwnerConnectionTests.setUp
    http = _local_harness.HarmlessOwnerConnectionTests.http
    prepare = _binding_harness.HumanBindingTests.prepare

    def test_rev0045_human_primary_requires_explicit_owner_organizer_binding(self):
        payload = self.prepare()
        # Disposable harness state only: the harness's earlier organizer sessions
        # keep running under other names; their organizer metadata was removed.
        self.owner.db.execute("UPDATE sessions SET name=name||'-harness' WHERE name LIKE 'organizer-%'")
        self.owner.db.commit()
        configured = self.owner.organizer_bindings.pop('alpha')  # owner config omits alpha
        self.assertEqual(self.http('/api/local-bindings', payload)[0], 200)
        state = self.http('/api/primary-agent')[1]
        self.assertEqual(state['primary_agent_id'], 'alpha')
        self.assertEqual(self.server.primary.election_sources.get('alpha'), 'human-binding')
        before = self.owner.snapshot(actor='operator')['sessions']
        with self.assertRaisesRegex(ValueError, 'no configured native organizer binding'):
            self.owner.open_organizer(actor='operator')
        self.assertNotIn('alpha', self.owner.organizer_bindings)
        self.assertEqual(self.owner.db.execute(
            "SELECT count(*) FROM native_organizers WHERE agent='alpha'").fetchone()[0], 0)
        self.assertEqual(self.owner.snapshot(actor='operator')['sessions'], before)
        # Explicit owner configuration (runtime-config `organizers`) is the only route.
        self.owner.organizer_bindings['alpha'] = dict(configured, conversation='explicit-alpha')
        session = self.owner.open_organizer(actor='operator')
        self.assertEqual((session['name'], session['status'], session['task']), ('organizer-alpha', 'stopped', None))
        self.assertEqual({k: v for k, v in self.owner.native(session['id'], actor='operator').items() if k != 'session'},
                         dict(tool='gemini', conversation='explicit-alpha'))
        self.assertNotIn(session['id'], self.owner.live)
        self.assertEqual(self.owner.open_organizer(actor='operator')['id'], session['id'])
        # Selecting the primary did not change the human binding or election source.
        self.assertEqual(self.server.bindings.read()['bindings'][0]['agent_id'], 'alpha')
