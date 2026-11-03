from arvyx_control.local_executor import ExecutionPolicy
from arvyx_control.replica_authority import authority_context
import tempfile
import json
import time
import os
import unittest
import sqlite3
from unittest.mock import patch
from pathlib import Path

from arvyx_control import cockpit_archive, cockpit_client, control
from arvyx_control.cockpit import LocalCockpit
from arvyx_control.cockpit_team import TeamAuthority
from arvyx_control.cockpit_archive_authority import governed_sink


@unittest.skipUnless(os.name == 'posix', 'PTY owner, curses surface, fork or pidfd semantics are POSIX-only')
class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'pilot'
        cockpit_client.initialize(self.root)
        self.enterContext(authority_context(self.root / 'vault', self.root / 'events.jsonl'))
        self.owner = self.connect()
        self.addCleanup(lambda: self.owner.close())
        task = control.create_task(self.root / 'events.jsonl', 'capture', owner='demobot').task
        self.sid = self.owner.open(project='demo-agent', task=task.id, name='capture', actor='operator')['id']

    def connect(self):
        return LocalCockpit(self.root / 'runtime', self.root / 'vault', self.root / 'events.jsonl', 'capture-host', execution_policy=ExecutionPolicy(host_uid=__import__("os").geteuid(), allow_host=True))

    def test_capture_outlives_ring_restart_and_deduplicates_delivery(self):
        capture = cockpit_archive.WorkCapture(self.owner, self.sid, 'run-one')
        capture.feed(b'hello\n' * 12000)
        capture.finish()
        before = cockpit_archive.pending_capture(self.owner)
        self.assertGreater(sum(len(row['text']) for row in before), 65536)
        self.owner.close()
        self.owner = self.connect()
        self.assertEqual(cockpit_archive.pending_capture(self.owner), before)
        seen = {}
        def sink(row):
            seen.setdefault(row['event_id'], row['text'])
            return row['event_id']
        count = 0
        while cockpit_archive.pending_capture(self.owner):
            count += cockpit_archive.sync_capture(self.owner, sink)
        self.assertEqual(count, len(before))
        self.assertEqual(cockpit_archive.sync_capture(self.owner, sink), 0)
        self.assertEqual(len(seen), len(before))

    def test_outage_and_wrong_ack_preserve_pending(self):
        capture = cockpit_archive.WorkCapture(self.owner, self.sid, 'run-two')
        capture.feed(b'recorded\n')
        capture.finish()
        before = cockpit_archive.pending_capture(self.owner)
        def outage(row):
            raise OSError('offline')
        self.assertEqual(cockpit_archive.sync_capture(self.owner, outage), 0)
        self.assertEqual(cockpit_archive.sync_capture(self.owner, lambda row: 'wrong-id'), 0)
        self.assertEqual(cockpit_archive.pending_capture(self.owner), before)

    def test_storage_pem_context_survives_recorder_and_owner_restart(self):
        # NOT_EXECUTED in the static source round.
        first = cockpit_archive.WorkCapture(self.owner, self.sid, 'storage-before')
        first.feed(b'-----BEGIN PRIVATE KEY-----\n')
        self.owner.close()
        self.owner = self.connect()
        resumed = cockpit_archive.WorkCapture(self.owner, self.sid, 'storage-after')
        resumed.feed(b'c3ludGhldGljLWJvZHk=\n-----END PRIVATE KEY-----\nordinary\n')
        resumed.finish()
        text = ''.join(row['text'] for row in cockpit_archive.pending_capture(self.owner))
        self.assertNotIn('c3ludGhldGljLWJvZHk=', text)
        self.assertIn('ordinary', text)

    def test_storage_failed_feed_rolls_back_rows_and_screen_context(self):
        capture = cockpit_archive.WorkCapture(self.owner, self.sid, 'storage-rollback')
        before = self.owner.db.execute('SELECT pem FROM capture_screen_context WHERE session=?', (self.sid,)).fetchone()[0]
        with patch.object(capture, '_save_screen', side_effect=OSError('synthetic barrier')):
            with self.assertRaises(OSError):
                capture.feed(b'-----BEGIN PRIVATE KEY-----\n')
        self.assertEqual(cockpit_archive.pending_capture(self.owner), [])
        self.assertEqual(self.owner.db.execute('SELECT pem FROM capture_screen_context WHERE session=?', (self.sid,)).fetchone()[0], before)
        self.assertFalse(capture.private_block)

    def test_actual_work_pty_is_automatically_recorded_without_archive_action(self):
        self.owner.start(self.sid, actor='operator', environment='host')
        lease = self.owner.attach(self.sid, actor='operator')
        self.owner.write(self.sid, actor='operator', text="printf 'automatic-capture-marker\\n'\n", attachment=lease['attachment'])
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if any('automatic-capture-marker' in row['text'] for row in cockpit_archive.pending_capture(self.owner)):
                break
            time.sleep(.02)
        self.owner.end(self.sid, actor='operator')
        self.assertTrue(any('automatic-capture-marker' in row['text'] for row in cockpit_archive.pending_capture(self.owner)))

    def test_governed_archive_uses_existing_identity_and_deduplicates_lost_ack(self):
        capture = cockpit_archive.WorkCapture(self.owner, self.sid, 'governed-run')
        capture.feed(b'governed record\n')
        capture.finish()
        with self.assertRaises(ValueError):
            governed_sink(self.owner)
        self.owner.team = TeamAuthority(self.owner.vault, self.owner.state,
                                       bearer_secret='fixture-only', authorization='Bearer fixture-only')
        sink = governed_sink(self.owner)
        row = cockpit_archive.pending_capture(self.owner)[0]
        self.assertEqual(sink(row), row['event_id'])
        self.assertEqual(sink(row), row['event_id'])
        recorded = [event for event in control.read_events(self.owner.state) if event.type == 'work.transcript']
        self.assertEqual(len(recorded), 1)
        self.assertNotIn('text', recorded[0].payload)
        blob = self.owner.vault / recorded[0].payload['storage_ref']
        self.assertEqual(json.loads(blob.read_text())['text'], 'governed record\n')
        self.assertEqual(blob.stat().st_mode & 0o777, 0o600)
        self.assertEqual(cockpit_archive.sync_capture(self.owner, sink), 1)
        self.owner.team = TeamAuthority(self.owner.vault, self.owner.state)
        with self.assertRaises(ValueError):
            governed_sink(self.owner)(row)

    def test_capacity_backpressures_without_deleting_or_advancing(self):
        capture = cockpit_archive.WorkCapture(self.owner, self.sid, 'capacity-run')
        capture.feed(b'first\n')
        before = cockpit_archive.pending_capture(self.owner)
        with patch.object(cockpit_archive, 'CAPTURE_CAPACITY', 1):
            with self.assertRaises(BufferError):
                capture.feed(b'second\n')
        self.assertEqual(cockpit_archive.pending_capture(self.owner), before)
        capture.feed(b'second\n')
        self.assertEqual(len(cockpit_archive.pending_capture(self.owner)), 2)

    def test_multiline_private_key_body_is_redacted(self):
        capture = cockpit_archive.WorkCapture(self.owner, self.sid, 'private-block-run')
        key_kind = 'PRIVATE' + ' KEY'
        begin = '-----' + 'BEGIN ' + key_kind + '-----\n'
        end = '-----' + 'END ' + key_kind + '-----\n'
        capture.feed(begin.encode())
        capture.feed(b'not-a-real-key-body\n')
        capture.feed(end.encode())
        capture.feed(b'ordinary output\n')
        capture.finish()
        text = ''.join(row['text'] for row in cockpit_archive.pending_capture(self.owner))
        self.assertNotIn('not-a-real-key-body', text)
        self.assertIn('ordinary output', text)

    def test_overlong_stream_delimiters_are_screened_independent_of_storage(self):
        # Canonical delimiter grammar with synthetic body, not patched internals.
        capture = cockpit_archive.WorkCapture(self.owner, self.sid, 'oversize-block')
        capture.feed(b'x' * 20000 + b'-----beg')
        capture.feed(b'in ' + b' ' * 25000 + b'RSA PRIVATE KE')
        capture.feed(b'Y-----\nharmless protected fixture body\n')
        capture.feed(b'y' * 20000 + b'-----END RSA PRIVATE KEY-----\nordinary after block\n')
        capture.finish()
        text = ''.join(row['text'] for row in cockpit_archive.pending_capture(self.owner))
        self.assertNotIn('harmless protected fixture body', text)
        self.assertIn('ordinary after block', text)
        self.assertLessEqual(len(capture.screen_tail), 64)

    def test_finish_failure_preserves_tail_and_open_status_until_exact_retry(self):
        for operation, table in [('INSERT', 'work_capture'), ('UPDATE', 'capture_runs')]:
            capture = cockpit_archive.WorkCapture(self.owner, self.sid)
            capture.feed(b'harmless final tail')
            before = (bytes(capture.buffer), capture.overlong, capture.private_block,
                      capture.screen_tail, capture.screen_candidate, capture.screen_escape, capture.line_private)
            self.owner.db.execute('CREATE TEMP TRIGGER fail_finish BEFORE ' + operation + ' ON ' + table +
                                  " BEGIN SELECT RAISE(ABORT, 'fixture write failure'); END")
            self.owner.db.commit()
            with self.assertRaises(sqlite3.IntegrityError):
                capture.finish()
            self.assertEqual((bytes(capture.buffer), capture.overlong, capture.private_block,
                              capture.screen_tail, capture.screen_candidate, capture.screen_escape,
                              capture.line_private), before)
            self.assertEqual(self.owner.db.execute('SELECT status FROM capture_runs WHERE run=?',
                                                  (capture.run,)).fetchone()[0], 'open')
            self.assertEqual(self.owner.db.execute('SELECT COUNT(*) FROM work_capture WHERE run=?',
                                                  (capture.run,)).fetchone()[0], 0)
            self.owner.db.execute('DROP TRIGGER fail_finish')
            self.owner.db.commit()
            capture.finish()
            capture.finish()
            rows = self.owner.db.execute('SELECT text FROM work_capture WHERE run=?', (capture.run,)).fetchall()
            self.assertEqual([row[0] for row in rows], ['harmless final tail'])
            self.assertEqual(self.owner.db.execute('SELECT status FROM capture_runs WHERE run=?',
                                                  (capture.run,)).fetchone()[0], 'complete')

    def test_finish_commit_failure_rolls_back_tail_and_completion(self):
        capture = cockpit_archive.WorkCapture(self.owner, self.sid)
        capture.feed(b'harmless commit tail')
        connection = self.owner.db
        class FailedCommit:
            def __getattr__(self, name):
                return getattr(connection, name)
            def commit(self):
                raise sqlite3.OperationalError('fixture commit failure')
        with patch.object(self.owner, 'db', FailedCommit()):
            with self.assertRaises(sqlite3.OperationalError):
                capture.finish()
        self.assertEqual(bytes(capture.buffer), b'harmless commit tail')
        self.assertEqual(connection.execute('SELECT status FROM capture_runs WHERE run=?',
                                            (capture.run,)).fetchone()[0], 'open')
        self.assertEqual(connection.execute('SELECT COUNT(*) FROM work_capture WHERE run=?',
                                            (capture.run,)).fetchone()[0], 0)
        capture.finish()
        self.assertEqual([row[0] for row in connection.execute('SELECT text FROM work_capture WHERE run=?',
                                                              (capture.run,))], ['harmless commit tail'])

    def test_interrupted_run_remains_visible_after_reconnect(self):
        capture = cockpit_archive.WorkCapture(self.owner, self.sid, 'interrupted-run')
        capture.feed(b'committed line\nprivate incomplete tail')
        self.owner.close()
        self.owner = self.connect()
        self.assertEqual(cockpit_archive.capture_status(self.owner)['interrupted_runs'], 1)
        self.assertEqual([row['text'] for row in cockpit_archive.pending_capture(self.owner)], ['committed line\n'])

    def test_secret_across_reads_and_overlong_line_never_persist_raw(self):
        capture = cockpit_archive.WorkCapture(self.owner, self.sid, 'run-three')
        secret = 'ghp_' + 'A' * 36
        capture.feed(('token=' + secret[:15]).encode())
        capture.feed((secret[15:] + '\n').encode())
        capture.feed(b'x' * 20000)
        capture.feed(b'\nvisible\n')
        capture.finish()
        text = ''.join(row['text'] for row in cockpit_archive.pending_capture(self.owner))
        self.assertNotIn(secret, text)
        self.assertIn('[redacted', text)
        self.assertIn('[overlong', text)
        self.assertIn('visible', text)
