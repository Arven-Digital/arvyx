from arvyx_control.replica_authority import authority_context
import json
import os
from pathlib import Path
import sqlite3
from contextlib import closing
import sys
import tempfile
import time
import unittest

from arvyx_control import cockpit_client, control
from arvyx_control.cockpit import LocalCockpit
from arvyx_control.cockpit_adapters import resume_plan
from arvyx_control.cockpit_native_runtime import NativeRuntime
from arvyx_control.cockpit_terminal_runner import JsonOperator
from arvyx_control.cockpit_archive import import_native, pending_capture


@unittest.skipUnless(os.name == 'posix', 'the native runtime (Linux x86_64 artifact, host-shell policies) is POSIX-only')
class NativeRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'pilot'
        cockpit_client.initialize(self.root)
        self.home = self.root / 'approved-home'
        self.home.mkdir()
        self.workspace = self.root / 'workspace'
        self.workspace.mkdir()

    def test_documented_exact_hermes_gemini_plans_no_latest(self):
        for tool in ('hermes', 'gemini'):
            self.assertEqual(resume_plan(tool, 'exact-id'), [tool, '--resume', 'exact-id'])
            with self.assertRaises(ValueError):
                resume_plan(tool, 'latest')

    def test_native_metadata_identity_and_home_are_verified_without_execution(self):
        for tool in ('hermes', 'gemini', 'claude', 'codex'):
            with self.subTest(tool=tool):
                store = self.home / ('state.db' if tool == 'hermes' else tool + '.metadata')
                if tool == 'hermes':
                    with closing(sqlite3.connect(store)) as db, db:
                        db.execute('CREATE TABLE sessions(id TEXT PRIMARY KEY,cwd TEXT,end_reason TEXT)')
                        db.execute("INSERT INTO sessions VALUES(?,?,NULL)", ('exact-id',str(self.workspace)))
                else:
                    data = {'sessionId': 'exact-id', 'cwd': str(self.workspace)}
                    if tool == 'codex':
                        data = {'type': 'session_meta', 'payload': {'id': 'exact-id', 'cwd': str(self.workspace)}}
                    store.write_text(json.dumps(data) + '\n')
                runtime = NativeRuntime(tool=tool, executable='/usr/bin/python3', home=self.home, store=store)
                argv, env = runtime.plan('exact-id', self.workspace)
                self.assertEqual(argv[-1], 'exact-id')
                self.assertEqual(env['HOME'], str(self.home))
                self.assertEqual(set(env), {'PATH', 'HOME', 'TERM', 'ENV'} | ({'HERMES_HOME'} if tool == 'hermes' else set()))
                with self.assertRaises(ValueError):
                    runtime.plan('wrong-id', self.workspace)

    def test_native_organizer_persists_without_fabricating_a_work_task(self):
        configuration = {'demobot': {'tool': 'fixture', 'conversation': 'persistent-organizer', 'workspace': str(self.workspace)}}
        owner = LocalCockpit(self.root / 'runtime', self.root / 'vault', self.root / 'events.jsonl', 'runtime-host',
                             organizers=configuration)
        try:
            first = owner.open_organizer('demobot', actor='operator')
            self.assertEqual(first['kind'], 'organizer')
            self.assertIsNone(first['task'])
            self.assertEqual(control.list_tasks(owner.state).tasks, [])
            owner.start_native(first['id'], fixture=True, actor='operator')
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and 'persistent-organizer' not in owner.read(first['id'], actor='operator')['output']:
                time.sleep(.02)
            self.assertIn('persistent-organizer', owner.read(first['id'], actor='operator')['output'])
            owner.end(first['id'], actor='operator')
        finally:
            owner.close()
        reopened = LocalCockpit(self.root / 'runtime', self.root / 'vault', self.root / 'events.jsonl', 'runtime-host',
                                organizers=configuration)
        try:
            self.assertEqual(reopened.open_organizer('demobot', actor='operator')['id'], first['id'])
            self.assertEqual(reopened.native(first['id'], actor='operator')['conversation'], 'persistent-organizer')
        finally:
            reopened.close()

    def test_hermes_transcript_import_is_exact_session_only_and_durable(self):
        store = self.home / 'state.db'
        with closing(sqlite3.connect(store)) as db, db:
            db.execute('CREATE TABLE sessions(id TEXT PRIMARY KEY,cwd TEXT,end_reason TEXT)')
            db.execute("INSERT INTO sessions VALUES(?,?,NULL)", ('exact-id',str(self.workspace)))
            db.execute('CREATE TABLE messages(id INTEGER PRIMARY KEY,session_id TEXT,role TEXT,content TEXT)')
            db.executemany('INSERT INTO messages VALUES(?,?,?,?)',
                           [(1, 'other-private-chat', 'user', 'must not import'),
                            (2, 'exact-id', 'assistant', 'work result')])
        runtime = NativeRuntime(tool='hermes', executable='/usr/bin/python3', home=self.home, store=store)
        owner = LocalCockpit(self.root / 'runtime', self.root / 'vault', self.root / 'events.jsonl', 'runtime-host',
                             native_runtimes={'hermes': runtime})
        self.addCleanup(owner.close)
        with authority_context(owner.vault, owner.state):
            task = control.create_task(owner.state, 'native records', owner='demobot').task
        session = owner.open(project='demo-agent', task=task.id, name='native-records', workspace=self.workspace, actor='operator')
        owner.bind_native(session['id'], tool='hermes', conversation='exact-id', actor='operator')
        self.assertEqual(import_native(owner, session['id'], actor='operator')['imported'], 1)
        self.assertEqual(import_native(owner, session['id'], actor='operator')['imported'], 0)
        self.assertEqual([row['text'] for row in pending_capture(owner)], ['assistant: work result'])

    def test_configured_local_driver_runs_explicit_goal_to_review_without_provider(self):
        driver = JsonOperator(['/usr/bin/python3', '-c',
                               'import json,sys; c=json.load(sys.stdin); print(json.dumps({"action":"review","evidence":"fixture checked: "+c["goal"]}))'],
                              cwd=self.root)
        owner = LocalCockpit(self.root / 'runtime', self.root / 'vault', self.root / 'events.jsonl', 'runtime-host',
                             driver={'rowan': driver})
        self.addCleanup(owner.close)
        with authority_context(owner.vault, owner.state):
            task = control.create_task(owner.state, 'operator loop', owner='demobot').task
        session = owner.open(project='demo-agent', task=task.id, name='operator-loop', actor='operator')
        owner.bind_native(session['id'], tool='fixture', conversation='fixture-existing', actor='operator')
        owner.start_native(session['id'], fixture=True, actor='operator')
        owner.delegate(session['id'], operator='rowan', goal='read fixture', limits='provider-free', actor='operator')
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and owner.delegation(session['id'], actor='operator')['status'] == 'active':
            time.sleep(.05)
        self.assertEqual(owner.delegation(session['id'], actor='operator')['status'], 'review')
        self.assertEqual(owner._get(session['id'])['status'], 'running')
        self.assertEqual(owner.snapshot(actor='operator')['operator_status']['runner'], 'configured: rowan')
        owner.take_control(session['id'], actor='operator')
        self.assertEqual(owner._get(session['id'])['status'], 'running')
        owner.end(session['id'], actor='operator')
