import contextlib
from arvyx_control.replica_authority import authority_context
"""Synthetic-only diagnostics contracts; never read a live state store."""
import json
from pathlib import Path
import tempfile
import unittest


class DiagnosticsTests(unittest.TestCase):
    def test_readers_tolerate_short_external_writer_commit(self):
        import subprocess
        import sys
        from unittest.mock import patch
        from arvyx_control.diagnostics import Reporter
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'errors.sqlite'
            writer = Reporter(path)
            writer.capture(RuntimeError(), component='api', code='reader_contention')
            writer.close()
            reader = Reporter(path, observer=True)
            original_check = reader._check_path
            processes = []
            def check_then_lock():
                original_check()
                # Real separate-process EXCLUSIVE commit window AFTER validation.
                child = subprocess.Popen([sys.executable, '-c',
                    'import sqlite3,sys,time; c=sqlite3.connect(sys.argv[1]); '
                    'c.execute("BEGIN EXCLUSIVE"); print("locked",flush=True); '
                    'time.sleep(.08); c.rollback(); c.close()', str(path)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                processes.append(child)
                self.assertEqual('locked', child.stdout.readline().strip())
            try:
                with patch.object(reader, '_check_path', side_effect=check_then_lock):
                    data = reader.read()
                    self.assertFalse(data['status'].get('read_failed', False))
                    self.assertEqual(1, len(data['groups']))
                    feed = reader.feed()
                    self.assertFalse(feed['status'].get('read_failed', False))
                    self.assertEqual(1, len(feed['events']))
            finally:
                for child in processes:
                    child.communicate(timeout=5)
                    self.assertEqual(0, child.returncode)
                reader.close()

    def test_cli_observer_never_creates_or_refreshes_sink(self):
        import os
        import contextlib
        import io
        from unittest.mock import patch
        from arvyx_control import diagnostics
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'errors.sqlite'
            def poll():
                with patch.dict(os.environ, {'ARVYX_DIAGNOSTICS_DB': str(path)}), patch.object(diagnostics, 'get_reporter', side_effect=AssertionError('writer factory forbidden')):
                    for command in ('status', 'list', 'feed'):
                        with contextlib.redirect_stdout(io.StringIO()):
                            diagnostics.main([command])
            poll()
            self.assertEqual(list(Path(tmp).iterdir()), [])
            reporter = diagnostics.Reporter(path)
            reporter.capture(RuntimeError(), component='worker', code='producer')
            reporter.close()
            before = path.read_bytes()
            poll()
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual({p.name for p in Path(tmp).iterdir()}, {'errors.sqlite'})

    def test_foreign_stores_are_unchanged_and_visibly_rejected(self):
        import sqlite3
        from arvyx_control.diagnostics import Reporter
        for kind in ('projection', 'empty-sqlite', 'empty-file', 'text', 'lookalike'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp)/'foreign.sqlite'
                if kind in ('projection', 'empty-sqlite', 'lookalike'):
                    with contextlib.closing(sqlite3.connect(path)) as db, db:
                        db.execute('PRAGMA user_version=17')
                        if kind != 'empty-sqlite':
                            db.execute('CREATE TABLE control_events (payload TEXT)')
                            db.execute("INSERT INTO control_events VALUES ('synthetic business data')")
                        if kind == 'lookalike':
                            db.execute('CREATE TABLE groups (payload TEXT)')
                else:
                    path.write_bytes(b'' if kind == 'empty-file' else b'synthetic non database')
                path.chmod(0o600)
                before = {p.name: p.read_bytes() for p in Path(tmp).iterdir()}
                reporter = Reporter(path)
                try:
                    reporter.capture(RuntimeError(), component='api', code='foreign')
                    self.assertTrue(reporter.flush(10))
                    view = reporter.read()
                    self.assertGreater(view['status']['sink_failures'], 0)
                    self.assertFalse(view['status']['available'])
                    self.assertEqual(view['groups'], [])
                    self.assertEqual(reporter.feed()['events'], [])
                finally:
                    reporter.close()
                self.assertEqual({p.name: p.read_bytes() for p in Path(tmp).iterdir()}, before)

    def test_dedicated_identity_and_concurrent_first_create(self):
        import sqlite3
        from concurrent.futures import ThreadPoolExecutor
        from arvyx_control.diagnostics import Reporter
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'errors.sqlite'
            def writer(_):
                reporter = Reporter(path)
                try:
                    for _ in range(10):
                        reporter.capture(RuntimeError(), component='api', code='concurrent')
                    self.assertTrue(reporter.flush(10))
                    self.assertEqual(reporter.counts['sink_failures'], 0)
                finally:
                    reporter.close()
            with ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(writer, range(4)))
            with contextlib.closing(sqlite3.connect(path)) as db, db:
                self.assertEqual(db.execute('PRAGMA application_id').fetchone()[0], 0x414D4344)
                self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 1)
                self.assertEqual(db.execute('SELECT sum(count) FROM groups').fetchone()[0], 40)
                self.assertEqual(db.execute('SELECT count(*) FROM feed').fetchone()[0], 1)
            self.assertEqual({p.name for p in Path(tmp).iterdir()}, {'errors.sqlite'})

    def test_release_build_id_is_validated_and_frozen_per_reporter(self):
        import os
        from unittest.mock import patch
        from arvyx_control import __version__
        from arvyx_control.diagnostics import Reporter
        for value in (None, 'build-8ca23fa.20260922', '', 'x'*65, 'private/path', 'bad\nvalue', 'é'):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as tmp:
                with patch.dict(os.environ, {}, clear=True):
                    if value is not None:
                        os.environ['ARVYX_RELEASE_BUILD_ID'] = value
                    reporter = Reporter(Path(tmp)/'errors.sqlite')
                    os.environ['ARVYX_RELEASE_BUILD_ID'] = 'changed-after-initialization'
                    try:
                        reporter.capture(RuntimeError(), component='api', code='release')
                        self.assertTrue(reporter.flush())
                        expected = __version__ if value is None else (value if value == 'build-8ca23fa.20260922' else 'invalid-build-id')
                        view = reporter.read()
                        self.assertEqual(view['groups'][0]['release'], expected)
                        self.assertEqual(reporter.feed()['events'][0]['release'], expected)
                        self.assertNotIn('changed-after-initialization', json.dumps(view))
                    finally:
                        reporter.close()

    def test_capture_groups_redacts_and_feed_is_monotonic(self):
        from arvyx_control.diagnostics import Reporter
        with tempfile.TemporaryDirectory() as tmp:
            reporter = Reporter(Path(tmp) / 'errors.sqlite')
            for _ in range(3):
                try:
                    raise RuntimeError('SECRET message body /home/private token=abc')
                except RuntimeError as exc:
                    trace = reporter.capture(exc, component='api', code='boundary')
            self.assertTrue(reporter.flush())
            view = reporter.read()
            self.assertEqual(view['groups'][0]['count'], 3)
            self.assertEqual(view['groups'][0]['trace_id'], trace)
            self.assertNotIn('SECRET', json.dumps(view))
            self.assertNotIn('/home/', json.dumps(view))
            self.assertEqual(view['groups'][0]['exception'], 'RuntimeError')
            self.assertTrue(view['groups'][0]['frames'])
            feed = reporter.feed(0)
            self.assertEqual(len(feed['events']), 1)
            self.assertEqual(feed['events'][0]['kind'], 'NEW')
            self.assertEqual(reporter.feed(feed['cursor'])['events'], [])
            reporter.close()

    def test_http_boundary_browser_and_operator_retrieval(self):
        import threading
        from http.server import ThreadingHTTPServer
        from urllib.request import Request, urlopen
        from urllib.error import HTTPError
        from unittest.mock import patch
        from arvyx_control import api, diagnostics
        from arvyx_control.diagnostics import Reporter
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reporter = Reporter(root / 'errors.sqlite')
            handler = api.make_handler(vault=root, state=root / 'state.jsonl', bearer_secret='synthetic-only')
            server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            def request(path, body=None, auth=True):
                headers = {'Authorization': 'Bearer synthetic-only'} if auth else {}
                data = json.dumps(body).encode() if body is not None else None
                try:
                    response = urlopen(Request(f'http://127.0.0.1:{server.server_port}'+path, data=data, headers=headers))
                except HTTPError as exc:
                    response = exc
                with response:
                    return response.status, json.loads(response.read()), response.headers
            try:
                with patch.object(diagnostics, '_reporter', reporter):
                    self.assertIn(request('/diagnostics', auth=False)[0], (401, 403))
                    with patch.object(api, '_operator_summary', side_effect=RuntimeError('SECRET')):
                        status, body, headers = request('/summary')
                    self.assertEqual(status, 500)
                    self.assertTrue(headers.get('X-AMC-Trace-ID'))
                    status, body, _ = request('/diagnostics/client', {'kind': 'error', 'message': 'SECRET', 'trace_id': 'spoofed'})
                    self.assertEqual(status, 202)
                    reporter.flush()
                    status, body, _ = request('/diagnostics')
                    self.assertEqual(status, 200)
                    self.assertEqual({g['component'] for g in body['body']['groups']}, {'api', 'browser'})
                    self.assertNotIn('SECRET', json.dumps(body))
                    fp = body['body']['groups'][0]['fingerprint']
                    self.assertEqual(len(request('/diagnostics/groups/'+fp)[1]['body']['groups']), 1)
                    with patch.object(api, 'resolve_identity', side_effect=OSError('SECRET')):
                        status, _, auth_headers = request('/summary')
                    self.assertEqual(status, 500)
                    reporter.flush()
                    auth_fault = next(g for g in reporter.read()['groups'] if g['code']=='auth_store')
                    self.assertEqual(auth_fault['trace_id'], auth_headers.get('X-AMC-Trace-ID'))
            finally:
                server.shutdown()
                server.server_close()
                reporter.close()

    def test_explicit_background_and_mcp_boundaries(self):
        from unittest.mock import patch
        from arvyx_control import diagnostics, cli, mcp
        from arvyx_control.diagnostics import Reporter
        import argparse
        with tempfile.TemporaryDirectory() as tmp:
            reporter = Reporter(Path(tmp) / 'errors.sqlite')
            with patch.object(diagnostics, '_reporter', reporter):
                with patch.object(cli, '_execution_worker_tick', side_effect=RuntimeError('SECRET')), patch.object(cli, 'write_tick_record'):
                    with self.assertRaises(RuntimeError):
                        with authority_context(Path(tmp), Path(tmp) / "state"):
                            cli._run_execution_worker(argparse.Namespace(state=Path(tmp)/'state'))
                with patch.object(mcp, '_call_tool', side_effect=RuntimeError('SECRET')):
                    with self.assertRaises(RuntimeError):
                        mcp.handle_request({"jsonrpc": "2.0", 'id': 1, 'method': 'tools/call', 'params': {'name': 'memory.recall'}}, Path(tmp))
                reporter.flush()
                self.assertEqual({g['component'] for g in reporter.read()['groups']}, {'worker', 'mcp'})
            reporter.close()

    def test_swallowed_dispatch_watchdog_and_audit_failures(self):
        from unittest.mock import patch
        from arvyx_control import diagnostics, api, watchdog
        from arvyx_control.diagnostics import Reporter
        from arvyx_control.dispatcher import dispatch_once
        from arvyx_control.agent_delivery import AgentRoute
        from arvyx_control.outbox import enqueue
        from datetime import datetime, timezone
        now = datetime(2026, 8, 10, tzinfo=timezone.utc)
        route = AgentRoute('amir', 'hermes-webhook', 'TEST_URL', 'TEST_SECRET')
        env = {'TEST_URL': 'http://127.0.0.1:9999/wake', 'TEST_SECRET': 'synthetic'}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reporter = Reporter(root/'diagnostics.sqlite')
            state = root/'state.jsonl'
            vault = root
            with authority_context(vault, state):
                enqueue(state, subject_id='synthetic', target='amir', payload={}, now=now)
                def broken(*args, **kwargs):
                    raise RuntimeError('SECRET')
                with patch.object(diagnostics, '_reporter', reporter):
                    result = dispatch_once(state, routes={'amir': route}, deliverer=broken, worker='test', deliver_after='2026-08-10T00:00:00Z', now=now, clock=lambda: now, environ=env)
                    self.assertEqual(result.ambiguous, 1)
                    with patch('arvyx_control.http_bounds.bounded_tcp_connection', side_effect=OSError('SECRET')):
                        self.assertFalse(watchdog.probe_route(route, environ=env)[0])
                    with patch.object(api, 'append_audit', side_effect=OSError('SECRET')):
                        api.handle_api_request('GET', '/summary', {}, root, state, bearer_secret='synthetic', authorization='Bearer synthetic')
                    reporter.flush()
                    self.assertEqual({g['component'] for g in reporter.read()['groups']}, {'dispatcher', 'watchdog', 'api'})
                reporter.close()

    def test_canary_and_feed_cli(self):
        from arvyx_control import diagnostics
        import contextlib
        import io
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(diagnostics.main(['canary']), 0)
        result = json.loads(output.getvalue())
        self.assertTrue(result['synthetic_only'])
        self.assertTrue(result['ok'])
        self.assertEqual(set(result['components']), {'api', 'worker', 'browser'})

    def test_concurrency_backpressure_and_durable_health(self):
        import sqlite3
        import threading
        import time
        from unittest.mock import patch
        from arvyx_control.diagnostics import Reporter
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'errors.sqlite'
            reporter = Reporter(path)
            reporter.capture(RuntimeError(), component='api', code='boundary')
            reporter.flush()
            with contextlib.closing(sqlite3.connect(path)) as db, db:
                db.execute('BEGIN EXCLUSIVE')
                started = time.monotonic()
                for _ in range(400):
                    reporter.capture(RuntimeError(), component='api', code='boundary')
                self.assertLess(time.monotonic()-started, .5)
                self.assertGreater(reporter.counts['queue_dropped'], 0)
            self.assertTrue(reporter.flush(timeout=30))
            reporter.close()
            reader = Reporter(path)
            self.assertGreater(reader.read()['status']['persisted_counters']['queue_dropped'], 0)
            self.assertIsNotNone(reader.read()['status']['last_sink_heartbeat'])
            reader.close()

    def test_browser_script_reports_fixed_metadata_and_renders(self):
        import subprocess
        html = (Path(__file__).parents[1]/'src/arvyx_control/static/index.html').read_text(encoding='utf-8')
        self.assertIn('AMC_DIAGNOSTICS_BEGIN', html)
        script = html.split('// AMC_DIAGNOSTICS_BEGIN')[1].split('// AMC_DIAGNOSTICS_END')[0]
        harness = '''const assert = require('node:assert/strict');
const handlers = {}, requests = [], nodes = {};
const window = {addEventListener: (name, fn) => handlers[name] = fn};
const document = {getElementById: id => nodes[id] ||= {textContent:''}};
const headers = () => ({Authorization: 'synthetic-only'});
const fetch = async (path, opts) => {requests.push([path, opts]); return {ok:true, json:async()=>({body:{status:{enabled:true,available:true},groups:[]}})}};
'''
        check = '''\n(async()=>{ handlers.error({message:'SECRET', filename:'SECRET', error:new Error('SECRET')});
await new Promise(resolve=>setTimeout(resolve, 0));
assert.equal(requests.length,1); assert.equal(requests[0][0],'/diagnostics/client');
assert.deepEqual(JSON.parse(requests[0][1].body),{kind:'error'});
await refreshDiagnostics(); assert.match(nodes['diagnostics-status'].textContent,/enabled/);
console.log('browser metadata and rendering verified'); })();'''
        result = subprocess.run(['node', '-e', harness+script+check], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_feed_carries_trust_and_retention_is_bounded(self):
        from arvyx_control.diagnostics import Reporter
        import sqlite3
        with tempfile.TemporaryDirectory() as tmp:
            reporter = Reporter(Path(tmp)/'errors.sqlite', max_groups=2)
            for code in ('first', 'second', 'third'):
                reporter.capture(RuntimeError(), component='api', code=code)
            reporter.client({'kind':'error'})
            self.assertTrue(reporter.flush(timeout=10))
            view = reporter.read()
            self.assertEqual(len(view['groups']), 2)
            feed = reporter.feed(0)
            self.assertEqual(feed['events'][-1]['trust'], 'untrusted-client')
            self.assertEqual(feed['events'][-1]['component'], 'browser')
            self.assertEqual(feed['checkpoint'], feed['cursor'])
            with contextlib.closing(sqlite3.connect(reporter.path)) as db, db:
                db.execute('DELETE FROM feed WHERE id < 4')
            self.assertTrue(reporter.feed(1)['gap'])
            reporter.close()

    def test_empty_feed_preserves_retention_gap_and_restart_checkpoint(self):
        import sqlite3
        from arvyx_control.diagnostics import Reporter
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'empty-feed.sqlite'
            reporter = Reporter(path)
            reporter.capture(RuntimeError(), component='api', code='lost-history')
            self.assertTrue(reporter.flush())
            cursor = reporter.feed()['cursor']
            reporter.close()
            with contextlib.closing(sqlite3.connect(path)) as db, db:
                db.execute('UPDATE retention SET floor=? WHERE singleton=1', (cursor,))
                db.execute('DELETE FROM feed')
            observer = Reporter(path, observer=True)
            gap = observer.feed(0)
            self.assertTrue(gap['gap'])
            self.assertEqual(gap['events'], [])
            self.assertEqual(gap['checkpoint'], cursor)
            self.assertFalse(observer.feed(cursor)['gap'])
            observer.close()

    def test_secret_audit_fault_is_an_incident_not_only_refusal(self):
        from arvyx_control import diagnostics, mcp
        from unittest.mock import patch
        from arvyx_control.diagnostics import Reporter
        with tempfile.TemporaryDirectory() as tmp:
            reporter = Reporter(Path(tmp)/'errors.sqlite')
            with patch.object(diagnostics, '_reporter', reporter), patch.object(mcp, 'append_audit', side_effect=OSError('SECRET')):
                result = mcp._audit_secret_resolve(params={'name':'secret.resolve','arguments':{'ref':'synthetic'}}, audit_log=Path(tmp)/'audit', require_audit=True, surface='mcp', actor=None, allowed_tools={'secret.resolve'})
                self.assertIn('refusing', result)
                reporter.flush()
                self.assertEqual(reporter.read()['groups'][0]['code'], 'secret_audit')
            reporter.close()

    def test_nested_boundaries_count_one_propagating_fault(self):
        from arvyx_control import diagnostics
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            reporter = diagnostics.Reporter(Path(tmp)/'errors.sqlite')
            @diagnostics.boundary('mcp')
            def inner():
                raise RuntimeError('SECRET')
            @diagnostics.boundary('cli')
            def outer():
                inner()
            with patch.object(diagnostics, '_reporter', reporter):
                with self.assertRaises(RuntimeError):
                    outer()
                reporter.flush()
                self.assertEqual(len(reporter.read()['groups']), 1)
                self.assertEqual(reporter.read()['groups'][0]['component'], 'mcp')
            reporter.close()

    def test_dispatcher_setup_and_liveness_handled_faults(self):
        from arvyx_control import diagnostics, dispatcher, liveness
        from unittest.mock import patch
        import contextlib
        import io
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reporter = diagnostics.Reporter(root/'errors.sqlite')
            with patch.object(diagnostics, '_reporter', reporter), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(dispatcher.main(['--vault', str(root / 'vault'), '--state', str(root/'state'), '--routes', str(root/'missing'), '--deliver-after','2026-08-10T00:00:00Z']), 2)
                with patch.object(liveness, '_atomic_write_json', side_effect=OSError('SECRET')):
                    with authority_context(Path(tmp), Path(tmp) / "state"):
                        self.assertFalse(liveness.write_tick_record(root/'state', component=liveness.WORKER_COMPONENT, result='error', detail='synthetic', stderr=io.StringIO()))
                reporter.flush()
                self.assertEqual({g['code'] for g in reporter.read()['groups']}, {'setup', 'tick_record'})
            reporter.close()

    def test_unhandled_filesystem_faults_are_not_auth_refusals(self):
        from arvyx_control import diagnostics
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            reporter = diagnostics.Reporter(Path(tmp)/'errors.sqlite')
            @diagnostics.boundary('worker')
            def operation(exc):
                raise exc
            with patch.object(diagnostics, '_reporter', reporter):
                for kind in (PermissionError, FileNotFoundError):
                    with self.assertRaises(kind):
                        operation(kind('SECRET'))
                reporter.flush()
                self.assertEqual({g['exception'] for g in reporter.read()['groups']}, {'PermissionError', 'FileNotFoundError'})
            reporter.close()

    def test_read_model_api_projection_fault_is_captured_without_repr(self):
        from arvyx_control import diagnostics
        from arvyx_control_center_api import app
        from arvyx_control_center_api.views import Sources
        from unittest.mock import patch
        from dataclasses import replace
        import contextlib
        import io
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reporter = diagnostics.Reporter(root/'errors.sqlite')
            def broken(*args):
                raise OSError('SECRET-PATH-AND-BODY')
            route = replace(app.ROUTE_TABLE['/v1/health'], build=broken)
            output = io.StringIO()
            with patch.object(diagnostics, '_reporter', reporter), patch.dict(app.ROUTE_TABLE, {'/v1/health':route}), contextlib.redirect_stderr(output):
                response = app.handle_request('GET', '/v1/health', None, app.AppConfig(Sources(root,root/'state')))
                self.assertEqual(response.status, 503)
                reporter.flush()
                self.assertNotIn('SECRET', output.getvalue())
                groups = reporter.read()['groups']
                self.assertEqual(groups[0]['code'], 'read_model_projection')
                self.assertTrue(any(f['module']=='arvyx_control_center_api.app' for f in groups[0]['frames']))
            reporter.close()

    def test_read_model_transport_fault_has_server_trace(self):
        from arvyx_control import diagnostics
        from arvyx_control_center_api import app, server
        from arvyx_control_center_api.views import Sources
        from unittest.mock import patch
        import contextlib
        import io
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reporter = diagnostics.Reporter(root/'errors.sqlite')
            handler_type = server.make_handler(app.AppConfig(Sources(root,root/'state')))
            handler = handler_type.__new__(handler_type)
            handler.command, handler.path, handler.headers = 'GET', '/v1/health', {}
            responses = []
            handler._write = lambda response, **kwargs: responses.append(response)
            output = io.StringIO()
            with patch.object(diagnostics, '_reporter', reporter), patch.object(server, 'handle_request', side_effect=RuntimeError('SECRET')), contextlib.redirect_stderr(output):
                handler._dispatch(send_body=True)
                reporter.flush()
                self.assertEqual(responses[0].status, 500)
                self.assertNotIn('SECRET', output.getvalue())
                self.assertEqual(reporter.read()['groups'][0]['trace_id'], handler.diagnostic_trace)
            reporter.close()

    def test_transient_sqlite_contention_retries_without_losing_count(self):
        import sqlite3
        import time
        from arvyx_control.diagnostics import Reporter
        with tempfile.TemporaryDirectory() as tmp:
            reporter = Reporter(Path(tmp)/'errors.sqlite')
            reporter.flush()
            with contextlib.closing(sqlite3.connect(reporter.path)) as db, db:
                db.execute('BEGIN EXCLUSIVE')
                reporter.capture(RuntimeError(), component='worker', code='contention')
                time.sleep(.35)
            self.assertTrue(reporter.flush(10))
            result = reporter.read()
            self.assertEqual(result['groups'][0]['count'], 1)
            self.assertEqual(result['status']['sink_failures'], 0)
            reporter.close()

    def test_out_of_order_writer_timestamps_keep_first_and_last(self):
        from arvyx_control import diagnostics
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            reporter = diagnostics.Reporter(Path(tmp)/'errors.sqlite')
            with patch.object(diagnostics.time, 'time', return_value=20000):
                newest = reporter.capture(RuntimeError(), component='worker', code='clock')
                reporter.flush()
            with patch.object(diagnostics.time, 'time', return_value=10000):
                reporter.capture(RuntimeError(), component='worker', code='clock')
                reporter.flush()
                result = reporter.read()['groups'][0]
                self.assertEqual(result['first_seen'], 10000)
                self.assertEqual(result['last_seen'], 20000)
                self.assertEqual(result['trace_id'], newest)
            reporter.close()

    def test_disabled_failed_and_expected_are_visible(self):
        from arvyx_control.diagnostics import Reporter
        disabled = Reporter(None)
        disabled.capture(RuntimeError('secret'), component='api', code='boundary')
        self.assertEqual(disabled.read()['status']['disabled'], 1)
        with tempfile.TemporaryDirectory() as tmp:
            reporter = Reporter(Path(tmp))
            reporter.capture(RuntimeError('secret'), component='api', code='boundary')
            self.assertTrue(reporter.flush())
            self.assertGreater(reporter.read()['status']['sink_failures'], 0)
            reporter.capture(ValueError('secret'), component='api', code='validation', expected=True)
            self.assertEqual(reporter.read()['status']['expected'], 1)
            reporter.close()

    def test_retention_regression_and_client_allowlist(self):
        from arvyx_control.diagnostics import Reporter
        with tempfile.TemporaryDirectory() as tmp:
            reporter = Reporter(Path(tmp) / 'errors.sqlite', max_groups=2, regression_seconds=0)
            reporter.capture(RuntimeError(), component='worker', code='boundary')
            reporter.flush()
            reporter.capture(RuntimeError(), component='worker', code='boundary')
            reporter.flush()
            self.assertEqual([x['kind'] for x in reporter.feed(0)['events']], ['NEW', 'REGRESSED'])
            for _ in range(30):
                reporter.client({'kind': 'error', 'message': 'SECRET', 'trace_id': 'spoofed', 'stack': 'SECRET'})
            reporter.flush()
            view = reporter.read()
            self.assertLessEqual(len(view['groups']), 2)
            client = next(g for g in view['groups'] if g['component'] == 'browser')
            self.assertEqual(client['trust'], 'untrusted-client')
            self.assertNotEqual(client['trace_id'], 'spoofed')
            self.assertNotIn('SECRET', json.dumps(view))
            self.assertGreater(view['status']['rate_limited'], 0)
            reporter.close()
