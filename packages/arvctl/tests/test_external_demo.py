"""Actual same-origin fixture composition with browser cookie, no printed secrets."""
from pathlib import Path
import http.cookiejar
import json
import tempfile
import threading
import unittest
from urllib.request import build_opener, HTTPCookieProcessor, Request
from urllib.error import HTTPError
from arvyx_control.external_demo import build_fixture_server


class IntegratedExternalDemoTests(unittest.TestCase):
    def test_same_origin_ui_create_read_revoke_with_private_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            frontend = root/'dist'
            frontend.mkdir()
            (frontend/'index.html').write_text('<html>fixture UI</html>')
            server = build_fixture_server(root/'owner', frontend, root/'private', fixture_only=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = server.origin
                browser = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
                def call(path, body=None, origin=None, opener=browser):
                    headers = {'Origin':origin or base}
                    data = json.dumps(body).encode() if body is not None else None
                    try:
                        with opener.open(Request(base+path,data=data,headers=headers),timeout=3) as response:
                            return response.status, json.load(response)
                    except HTTPError as exc:
                        return exc.code, json.load(exc)
                self.assertEqual(call('/external/config',opener=build_opener())[0],403)
                with browser.open(base+'/') as response:
                    self.assertIn(b'fixture UI',response.read())
                    self.assertIn('HttpOnly',response.headers['Set-Cookie'])
                status, config = call('/external/config')
                self.assertEqual(status,200)
                self.assertEqual(config['issuer'],'fixture-issuer')
                self.assertIs(config['fixture_only'], True)
                self.assertEqual(config['ttl_hours'], 24)
                # The browser's private cookie must also connect the main workspace.
                self.assertEqual(call('/api/snapshot',opener=build_opener())[0],403)
                from unittest.mock import patch
                with patch('arvyx_control.cockpit_paperclip.snapshot', return_value={'sessions': [], 'tasks': []}):
                    status, workspace = call('/api/snapshot')
                self.assertEqual(status,200)
                self.assertEqual(set(workspace), {'local', 'team'})
                self.assertEqual(call('/api/snapshot',origin='http://evil.invalid')[0],403)
                self.assertEqual(call('/api/team/action', {}, origin='http://evil.invalid')[0],403)
                self.assertEqual(call('/api/team/action', {}, opener=build_opener())[0],403)
                self.assertNotIn('credential', config)
                self.assertNotIn('session', config)
                body = dict(recipient=config['recipients'][0]['id'],resources=['workspace:fixture-review'],
                            operations=['read'],provenance='explicit fixture UI')
                self.assertEqual(call('/external/grants',body,origin='http://evil.invalid')[0],403)
                status, grant = call('/external/grants',body)
                self.assertEqual(status,201)
                path = '/external/grants/'+grant['id']
                self.assertEqual(call(path)[1]['state'],'active')
                self.assertEqual(call('/external/grants')[1][0]['id'],grant['id'])
                # Browser is issuer, never silently acts as recipient for content.
                self.assertEqual(call(path+'/resources/workspace/fixture-review')[0],403)
                self.assertEqual(call('/mcp')[0],404)
                self.assertEqual(call(path+'/revoke',{})[0],200)
                self.assertEqual(call(path)[1]['state'],'revoked')
                text = json.dumps(config)
                self.assertNotIn('Bearer',text)
                self.assertNotIn(str(root),text)
                self.assertEqual(list((root/'private').glob('*token*')),[])
            finally:
                server.shutdown()
                server.server_close()
                thread.join()
