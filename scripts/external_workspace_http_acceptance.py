"""Read an existing fixture owner; test a separate ephemeral presentation only."""
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import tempfile
import threading
from urllib.error import HTTPError
from urllib.request import Request, build_opener, HTTPCookieProcessor
from arvyx_control.external_demo import build_fixture_server
from arvyx_control.cockpit_client import request
from arvyx_control.cockpit_team import TeamAuthority


def main():
    root = Path(__file__).resolve().parents[1]
    connection = json.loads((root/'receipts/live-demo/connection.json').read_text())
    assert connection.get('fixture_only') is True
    home = Path(connection['home'])
    before = request(home, 'list')
    secret = secrets.token_urlsafe(32)
    team = TeamAuthority(home/'vault', home/'events.jsonl', bearer_secret=secret, authorization='Bearer '+secret)
    with tempfile.TemporaryDirectory(prefix='external-workspace-proof-', dir=os.environ.get('TMPDIR')) as private:
        server = build_fixture_server(home, root/'frontends/paperclip/dist', private, fixture_only=True, capability=secret, team=team)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            browser = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
            def call(path, body=None, opener=browser, headers=None):
                h = {'Origin': server.origin, 'Content-Type': 'application/json'}
                h.update(headers or {})
                try:
                    with opener.open(Request(server.origin+path, data=None if body is None else json.dumps(body).encode(), headers=h), timeout=5) as response:
                        return response.status, json.load(response)
                except HTTPError as exc:
                    return exc.code, json.load(exc)
            assert call('/api/snapshot', opener=build_opener())[0] == 403
            browser.open(server.origin+'/').close()
            status, config = call('/external/config')
            assert status == 200 and config['fixture_only'] is True
            status, snapshot = call('/api/snapshot')
            assert status == 200 and set(snapshot) == {'local', 'team'}
            assert snapshot['team']['availability']['tasks'] is True
            assert call('/api/snapshot', headers={'Authorization':'Bearer rejected-browser-value'})[0] == 403
            assert call('/api/snapshot', headers={'Host':'evil.invalid'})[0] == 403
            assert call('/api/snapshot', headers={'Origin':'http://evil.invalid'})[0] == 403
            assert call('/api/team/action', {}, headers={'Origin':'http://evil.invalid'})[0] == 403
            assert call('/api/team/action', {}, opener=build_opener())[0] == 403
            assert call('/api/team/action', {})[0] == 400  # Reaches bounded schema gate, no write.
            body = dict(recipient=config['recipients'][0]['id'], resources=['workspace:fixture-review'], operations=['read'], provenance='private fixture HTTP acceptance')
            status, grant = call('/external/grants', body)
            assert status == 201
            path = '/external/grants/'+grant['id']
            assert call(path)[1]['state'] == 'active'
            assert call(path+'/revoke', {})[0] == 200
            assert call(path)[1]['state'] == 'revoked'
            assert call(path, opener=build_opener())[0] == 403
            assert request(home, 'list') == before
            print(json.dumps({'result':'PASS','workspace_http':200,'team_tasks_available':True,'grant_create':201,'grant_readback':'active','grant_revoke_readback':'revoked','unauthenticated':403,'foreign_host_origin_and_browser_bearer':403,'owner_session_list_unchanged':True,'presentation':'separate ephemeral listener, now closed'}))
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == '__main__':
    main()
