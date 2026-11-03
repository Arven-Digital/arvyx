"""Review50 regressions. NOT_EXECUTED: execution expressly prohibited."""
import json
import unittest
from contextlib import closing
from types import SimpleNamespace
from unittest import mock

from arvyx_control.external_api import ExternalAPI, Principal
from arvyx_control.external_gateway import AccessDenied
from arvyx_control import machine_pairing_cli


class ExportExpiryTests(unittest.TestCase):
    def test_each_discovery_export_has_fresh_admission(self):
        for operation in ('list', 'search'):
            with self.subTest(operation=operation):
                api = object.__new__(ExternalAPI)
                grant = SimpleNamespace(id='grant', resources={'artifact:a', 'artifact:b'},
                                        operations={operation, 'read'})
                api.store = SimpleNamespace(get=lambda _: grant,
                    decide=lambda *a, **k: SimpleNamespace(allowed=True))
                api._require_manifest_bindings = lambda: None
                exported = []
                api.allows = lambda **kw: not exported
                api._read_plan = lambda resource: ({}, 10)
                def read(*, resource, actor):
                    exported.append(resource.identifier)
                    return {'id': resource.identifier}
                api.read = read
                body = dict(jsonrpc='2.0', id=1, method='tools/call', params=dict(
                    name='external.' + operation,
                    arguments={'query': ''} if operation == 'search' else {}))
                with self.assertRaises(AccessDenied):
                    api._mcp(Principal('remote', 'external'), body, grant_id='grant')
                self.assertEqual(exported, ['a'])


class PairingClaimTests(unittest.TestCase):
    def test_same_key_replacement_cannot_consume_reviewed_claim(self):
        import base64
        import tempfile
        from pathlib import Path
        from arvyx_control.machine_pairing import PairingStore, MachineIdentity
        now = [1000.0]
        with tempfile.TemporaryDirectory() as tmp, closing(PairingStore(Path(tmp) / 'pairing.db', clock=lambda: now[0])) as store:
            identity = MachineIdentity('remote', base64.b64encode(b'x' * 32).decode())
            ticket = store.issue(actor='owner', ttl=10)
            self.assertTrue(store.claim(ticket.code, identity).allowed)
            snapshot = store.claim_snapshot(identity.fingerprint)
            now[0] += 11
            replacement = store.issue(actor='owner', ttl=100)
            self.assertTrue(store.claim(replacement.code, identity).allowed)
            transport = SimpleNamespace(store=store, close=lambda: None)
            with mock.patch.object(machine_pairing_cli, 'PairingTransport', return_value=transport):
                result = machine_pairing_cli.main(['approve', identity.fingerprint,
                    '--state-dir', tmp, '--actor', 'owner', '--approve',
                    '--review-snapshot', json.dumps(snapshot)])
            self.assertEqual(result, 1)
            self.assertFalse(store.check(identity).allowed)
            self.assertNotEqual(store.claim_snapshot(identity.fingerprint)['claim_id'], snapshot['claim_id'])

    def test_decision_forwards_reviewed_identity_without_refresh(self):
        snapshot = dict(claim_id='old-claim', fingerprint='key', name='old-name',
                        public_key='public', expires=123, state='claimed')
        for command in ('approve', 'deny'):
            store = mock.Mock()
            store.decide.return_value = SimpleNamespace(allowed=False, reason='no_pending_claim')
            transport = mock.Mock(store=store)
            argv = [command, 'key', '--state-dir', 'unused', '--actor', 'owner',
                    '--review-snapshot', json.dumps(snapshot)]
            if command == 'approve':
                argv.append('--approve')
            with mock.patch.object(machine_pairing_cli, 'PairingTransport', return_value=transport):
                self.assertEqual(machine_pairing_cli.main(argv), 1)
            self.assertEqual(store.decide.call_args.kwargs['claim_id'], 'old-claim')
            self.assertEqual(store.decide.call_args.kwargs['review_snapshot'], snapshot)
            store.claim_snapshot.assert_not_called()

    def test_fingerprint_only_decision_is_rejected_before_open(self):
        with mock.patch.object(machine_pairing_cli, 'PairingTransport') as transport:
            with self.assertRaises(SystemExit):
                machine_pairing_cli.main(['deny', 'key', '--state-dir', 'unused', '--actor', 'owner'])
            transport.assert_not_called()
