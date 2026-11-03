"""Capability, routing, CSP and read-only adapter regression tests."""
import os
import http.client
import json
from pathlib import Path
import tempfile
from threading import Thread
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from arvyx_control.cockpit_paperclip import PaperclipServer
import arvyx_control.cockpit_paperclip as module


class PaperclipServerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.dist = self.root / 'dist'
        self.dist.mkdir()
        (self.dist / 'index.html').write_text('<div id="root"></div>')
        self.snapshot = patch.object(module, 'snapshot', return_value={'sessions': [], 'tasks': [], 'view': {'revision': 0}})
        self.snapshot.start()
        self.addCleanup(self.snapshot.stop)
        self.server = PaperclipServer(self.root, self.dist, capability='x' * 40)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def get(self, path, headers=None, method='GET'):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_address[1], timeout=5)
        try:
            connection.request(method, path, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_snapshot_requires_exact_capability_and_host(self):
        self.assertEqual(self.get('/api/snapshot')[0], 403)
        self.assertEqual(self.get('/api/snapshot', {'Authorization': 'Bearer ' + 'x' * 40, 'Host': 'evil.invalid'})[0], 403)
        status, _, body = self.get('/api/snapshot', {'Authorization': 'Bearer ' + 'x' * 40})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['team'], {'availability': {}})

    def test_no_mutations_or_path_fallback(self):
        for path in ('/api/select', '/api/end'):
            with self.subTest(path=path):
                self.assertEqual(self.get(path, method='POST')[0], 405)
        for path in ('/../cockpit_paperclip.py', '/api/dashboard', '/not-found'):
            with self.subTest(path=path):
                self.assertEqual(self.get(path)[0], 404)

    def post_action(self, payload, *, origin=True):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_address[1], timeout=5)
        headers = {'Authorization': 'Bearer ' + 'x' * 40, 'Content-Type': 'application/json'}
        if origin:
            headers['Origin'] = self.server.origin
        try:
            connection.request('POST', '/api/team/action', body=json.dumps(payload), headers=headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def test_governed_action_requires_origin_and_configured_identity(self):
        payload = {'action': 'task-create', 'payload': {'title': 'Fixture', 'owner': 'fixture', 'idempotency_key': 'fixture-only'}}
        self.assertEqual(self.post_action(payload, origin=False)[0], 403)
        self.assertEqual(self.post_action(payload)[0], 503)

    def test_governed_action_uses_existing_authority_and_redacts_denial(self):
        from unittest.mock import Mock
        self.server.team = Mock()
        payload = {'action': 'task-create', 'payload': {'title': 'Fixture', 'owner': 'fixture', 'idempotency_key': 'fixture-only'}}
        self.server.team.action.return_value = SimpleNamespace(status=201, body={'id': 'fixture-task'})
        self.assertEqual(self.post_action(payload), (201, {'id': 'fixture-task'}))
        self.server.team.action.assert_called_once_with(payload['action'], payload['payload'])
        self.server.team.action.return_value = SimpleNamespace(status=403, body={'error': '/private/do-not-reflect'})
        status, body = self.post_action(payload)
        self.assertEqual(status, 403)
        self.assertNotIn('/private', json.dumps(body))

    def test_react_script_csp_and_private_headers(self):
        status, headers, body = self.get('/')
        self.assertEqual(status, 200)
        self.assertIn(b'root', body)
        self.assertIn("script-src 'self'", headers['Content-Security-Policy'])
        self.assertIn("connect-src 'self'", headers['Content-Security-Policy'])
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertEqual(headers['X-Frame-Options'], 'DENY')

    def test_distribution_rejects_symlink_entrypoint(self):
        other = self.root / 'symlink-dist'
        other.mkdir()
        outside = self.root / 'private.txt'
        outside.write_text('never serve this')
        (other / 'index.html').symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'Build'):
            instance = PaperclipServer(self.root, other, capability='x' * 40)
            instance.server_close()

    def test_rebuilt_manifest_is_promoted_as_one_stable_build(self):
        assets = self.dist / 'assets'
        assets.mkdir()
        (assets / 'old.js').write_bytes(b'old script')
        (assets / 'old.css').write_bytes(b'old style')
        old = b'<script src="/assets/old.js"></script><link rel="stylesheet" href="/assets/old.css">'
        (self.dist / 'index.html').write_bytes(old)
        self.assertEqual(self.get('/')[2], old)
        (assets / 'old.js').unlink()
        (assets / 'old.css').unlink()
        new = b'<script src="/assets/new.js"></script><link rel="stylesheet" href="/assets/new.css">'
        (self.dist / 'index.html').write_bytes(new)
        # A partially written build cannot replace the captured working build.
        self.assertEqual(self.get('/')[2], old)
        (assets / 'new.js').write_bytes(b'new script')
        (assets / 'new.css').write_bytes(b'new style')
        self.assertEqual(self.get('/')[2], new)
        for path, body in [('/assets/new.js', b'new script'), ('/assets/new.css', b'new style'),
                           ('/assets/old.js', b'old script'), ('/assets/old.css', b'old style')]:
            with self.subTest(path=path):
                status, headers, actual = self.get(path)
                self.assertEqual((status, actual), (200, body))
                if path.endswith('.css'):
                    self.assertEqual(headers['Content-Type'], 'text/css')
                else:
                    self.assertIn(headers['Content-Type'], ('text/javascript', 'application/javascript'))
        # Reads use captured bytes, never mutable paths from an old allowlist.
        (assets / 'new.js').unlink()
        (assets / 'new.js').symlink_to(self.root / 'private.txt')
        (self.root / 'private.txt').write_bytes(b'secret')
        self.assertEqual(self.get('/assets/new.js')[2], b'new script')

    def test_capture_changed_mid_read_keeps_last_good_generation(self):
        original = self.get('/')[2]
        (self.dist / 'index.html').write_bytes(b'<div>candidate</div>')
        capture = module._capture_build

        def racing_capture(directory, prefix=''):
            files = capture(directory, prefix)
            (self.dist / 'index.html').write_bytes(b'<div>changed during capture</div>')
            return files

        with patch.object(module, '_capture_build', side_effect=racing_capture):
            self.assertEqual(self.get('/')[2], original)
        self.assertEqual(self.get('/')[2], b'<div>changed during capture</div>')

    def test_access_time_update_during_read_is_not_a_build_change(self):
        # Regression: relatime updates st_atime on the first read after a write.
        # The whole-stat comparison refused a freshly built, unchanged frontend.
        real_fstat = os.fstat
        calls = {"n": 0}

        def fstat_with_atime_tick(fd):
            info = real_fstat(fd)
            calls["n"] += 1
            if calls["n"] % 2 == 0:  # the post-read fstat sees a newer access time
                values = list(info)
                values[7] = info.st_atime + 1  # st_atime (integer field)
                extra = {"st_atime_ns": info.st_atime_ns + 10**9,
                         "st_mtime_ns": info.st_mtime_ns, "st_ctime_ns": info.st_ctime_ns}
                if hasattr(info, "st_file_attributes"):  # Windows readers check the reparse bit
                    extra["st_file_attributes"] = info.st_file_attributes
                return os.stat_result(values, extra)
            return info

        (self.dist / 'index.html').write_bytes(b'<div>fresh build</div>')
        with patch.object(module.os, 'fstat', side_effect=fstat_with_atime_tick):
            self.assertEqual(self.get('/')[2], b'<div>fresh build</div>')
        self.assertGreater(calls["n"], 1)

    def test_content_change_during_read_is_still_refused(self):
        real_fstat = os.fstat
        calls = {"n": 0}

        def fstat_with_size_change(fd):
            info = real_fstat(fd)
            calls["n"] += 1
            if calls["n"] % 2 == 0:
                values = list(info)
                values[6] = info.st_size + 1  # st_size
                extra = {"st_atime_ns": info.st_atime_ns, "st_mtime_ns": info.st_mtime_ns, "st_ctime_ns": info.st_ctime_ns}
                if hasattr(info, "st_file_attributes"):  # Windows readers check the reparse bit
                    extra["st_file_attributes"] = info.st_file_attributes
                return os.stat_result(values, extra)
            return info

        original = self.get('/')[2]
        (self.dist / 'index.html').write_bytes(b'<div>racing build</div>')
        with patch.object(module.os, 'fstat', side_effect=fstat_with_size_change):
            self.assertEqual(self.get('/')[2], original)

    def test_missing_startup_dependency_is_rejected(self):
        other = self.root / 'incomplete-dist'
        other.mkdir()
        (other / 'index.html').write_text('<script src="/assets/missing.js"></script>')
        with self.assertRaisesRegex(ValueError, 'Build'):
            PaperclipServer(self.root, other, capability='x' * 40)

    def test_no_symlink_directory_or_encoded_traversal_exposure(self):
        outside = self.root / 'private'
        outside.mkdir()
        (outside / 'secret.js').write_bytes(b'secret')
        (self.dist / 'leak').symlink_to(outside, target_is_directory=True)
        (self.dist / 'secret.js').symlink_to(outside / 'secret.js')
        (self.dist / 'index.html').write_bytes(b'<div>next build</div>')
        self.assertEqual(self.get('/')[0], 200)
        for path in ('/leak/secret.js', '/secret.js', '/../private/secret.js',
                     '/%2e%2e/private/secret.js', '/assets/../secret.js',
                     '/assets/%2e%2e/secret.js', '//private/secret.js'):
            with self.subTest(path=path):
                status, _, body = self.get(path)
                self.assertEqual(status, 404)
                self.assertNotIn(b'secret', body)

    def test_failure_does_not_serialize_private_exception(self):
        with patch.object(module, 'snapshot', side_effect=ValueError('/private/secret')):
            status, _, body = self.get('/api/snapshot', {'Authorization': 'Bearer ' + 'x' * 40})
        self.assertEqual(status, 503)
        self.assertNotIn(b'secret', body)
