from arvyx_control.replica_authority import authority_context
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from arvyx_control import cockpit_client, control
from arvyx_control.cockpit import LocalCockpit
from arvyx_control.cockpit_fleet import FleetCockpit


class OwnerEndpoint:
    def __init__(self, owner):
        self.owner = owner
        self.online = True
        self.writes = 0

    def call(self, operation, **fields):
        if not self.online:
            raise OSError('disconnected')
        if operation == 'write':
            self.writes += 1
        return getattr(self.owner, operation)(**fields)


class FleetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.owners = []
        for host in ('host-a', 'host-b'):
            root = Path(self.temp.name) / host
            cockpit_client.initialize(root)
            owner = LocalCockpit(root / 'runtime', root / 'vault', root / 'events.jsonl', host)
            self.addCleanup(owner.close)
            with authority_context(owner.vault, owner.state):
                task = control.create_task(owner.state, 'fleet task', owner='demobot').task
            session = owner.open(project='demo-agent', task=task.id, name='same-name', actor='operator')
            self.owners.append((owner, session))
        self.endpoint = OwnerEndpoint(self.owners[1][0])
        self.fleet = FleetCockpit(self.owners[0][0], {'host-b': self.endpoint})

    def test_reconcile_input_preserves_exact_remote_lease_and_human_confirmation(self):
        owner, session = self.owners[1]
        reference = self.fleet.reference(owner.host, session['id'])
        with patch.object(self.endpoint, 'call', return_value={'reconciled': True}) as call:
            self.assertEqual(self.fleet.reconcile_input(reference, actor='operator', attachment='exact-lease', confirmed_clean=True), {'reconciled': True})
            call.assert_called_once_with('reconcile_input', sid=session['id'], actor='operator', attachment='exact-lease', confirmed_clean=True)
        with patch.object(self.endpoint, 'call', side_effect=OSError('disconnected')) as call:
            with self.assertRaises(OSError):
                self.fleet.reconcile_input(reference, actor='operator', attachment='exact-lease', confirmed_clean=True)
            self.assertEqual(call.call_count, 1)

    def test_two_clients_share_revision_layout_and_distinct_host_names(self):
        snapshot = self.fleet.snapshot(actor='operator')
        ids = [session['id'] for session in snapshot['sessions']]
        self.assertEqual(len(set(ids)), 2)
        self.assertEqual({session['name'] for session in snapshot['sessions']}, {'same-name'})
        second_client = FleetCockpit(self.owners[0][0], {'host-b': self.endpoint})
        view = self.fleet.select(ids[1], revision=0, actor='operator')
        self.assertEqual(second_client.view(), view)
        with self.assertRaisesRegex(ValueError, 'stale'):
            second_client.select(ids[0], revision=0, actor='operator')
        restarted = FleetCockpit(self.owners[0][0], {'host-b': self.endpoint})
        self.assertEqual(restarted.view(), view)

    def test_disconnect_keeps_cached_sessions_and_never_retries_input(self):
        snapshot = self.fleet.snapshot(actor='operator')
        target = snapshot['sessions'][1]['id']
        self.endpoint.online = False
        offline = self.fleet.snapshot(actor='operator')
        self.assertFalse(offline['sessions'][1]['online'])
        with self.assertRaises(OSError):
            self.fleet.write(target, actor='operator', text='unsent', attachment='none')
        self.endpoint.online = True
        self.fleet.snapshot(actor='operator')
        self.assertEqual(self.endpoint.writes, 0)

    def test_stop_recorded_is_not_acknowledged_until_host_readback(self):
        owner, session = self.owners[1]
        owner.delegate(session['id'], operator='rowan', goal='inspect', limits='local only', actor='operator')
        reference = self.fleet.reference(owner.host, session['id'])
        self.endpoint.online = False
        unconfirmed = self.fleet.take_control(reference, actor='operator')
        self.assertFalse(unconfirmed['acknowledged'])
        self.assertEqual(owner.delegation(session['id'], actor='operator')['status'], 'active')
        self.endpoint.online = True
        self.assertTrue(self.fleet.take_control(reference, actor='operator')['acknowledged'])
        rows = list(self.owners[0][0].db.execute('SELECT status FROM fleet_cancellations ORDER BY rowid'))
        self.assertEqual([row[0] for row in rows], ['recorded; not acknowledged', 'acknowledged'])

    def test_bad_endpoint_does_not_prevent_local_fleet_stop(self):
        owner, session = self.owners[0]
        owner.delegate(session['id'], operator='rowan', goal='inspect', limits='local only', actor='operator')
        self.fleet.snapshot(actor='operator')
        with patch.object(self.endpoint, 'call', side_effect=ValueError('identity mismatch')):
            result = self.fleet.take_control_scope('fleet', actor='operator')
        self.assertFalse(result['acknowledged'])
        self.assertEqual(result['unreachable_hosts'], ['host-b'])
        self.assertEqual(owner.delegation(session['id'], actor='operator')['status'], 'revoked')
        self.assertTrue(any(row['acknowledged'] and row['target'].startswith('host-a:') for row in result['results']))

    def test_unconfigured_host_and_nonhuman_are_refused(self):
        with self.assertRaises(ValueError):
            self.fleet.select('unknown:' + 'a' * 32, revision=0, actor='operator')
        with self.assertRaises(PermissionError):
            self.fleet.take_control('host-b:' + self.owners[1][1]['id'], actor='rowan')

    def test_draft_send_exact_session_local_and_remote_without_retry(self):
        for owner, session in self.owners:
            reference = self.fleet.reference(owner.host, session['id'])
            draft = self.fleet.stage_draft(reference, text='fixture prompt', actor='operator')
            fields = dict(identifier=draft['id'], consent=draft['sha256'], attachment='fixture', actor='operator')
            with authority_context(owner.vault, owner.state):
                task = control.create_task(owner.state, 'other fleet task', owner='demobot').task
            other = owner.open(project='demo-agent', task=task.id, name='other', actor='operator')
            with self.assertRaisesRegex(ValueError, 'session'):
                self.fleet.send_draft(self.fleet.reference(owner.host, other['id']), **fields)
            with patch.object(owner, 'write', return_value={'accepted': True}) as write:
                result = self.fleet.send_draft(reference, **fields)
                self.assertEqual(result['draft_status'], 'accepted-not-delivered')
                self.assertEqual(write.call_args.args[0], session['id'])
                with self.assertRaisesRegex(ValueError, 'already attempted'):
                    self.fleet.send_draft(reference, **fields)
                self.assertEqual(write.call_count, 1)
            draft = self.fleet.stage_draft(reference, text='ambiguous fixture', actor='operator')
            fields.update(identifier=draft['id'], consent=draft['sha256'])
            with patch.object(owner, 'write', side_effect=OSError('lost acknowledgment')) as write:
                with self.assertRaises(OSError):
                    self.fleet.send_draft(reference, **fields)
                with self.assertRaisesRegex(ValueError, 'ambiguous'):
                    self.fleet.send_draft(reference, **fields)
                self.assertEqual(write.call_count, 1)
