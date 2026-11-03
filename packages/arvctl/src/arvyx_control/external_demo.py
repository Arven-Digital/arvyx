"""Fixture-only Paperclip + delegation composition; never an owner launcher.

Random credentials exist only in this process. The browser receives an HttpOnly
issuer session cookie, not recipient credentials. No provider integration exists.
"""
import argparse
import hashlib
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
import secrets
import tempfile

from . import private_paths
from .cockpit_paperclip import PaperclipHandler, PaperclipServer
from .external_api import ExternalAPI, Principal
from .external_grants import ExternalGrantStore
from .external_workspace import snapshot_workspace


class FixtureHandler(PaperclipHandler):
    def send_header(self, keyword, value):
        if (keyword.lower() == 'content-type' and self.path == '/'
                and self.headers.get_all('Host', []) == [self.server.origin.removeprefix('http://')]):
            super().send_header('Set-Cookie', 'external_fixture=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/external')
            super().send_header('Set-Cookie', 'external_fixture=' + self.server.fixture_session +
                                '; HttpOnly; SameSite=Strict; Path=/')
        super().send_header(keyword, value)

    def _fixture_authorized(self, *, mutation=False):
        server = self.server
        if self.headers.get_all('Host', []) != [server.origin.removeprefix('http://')]:
            return False
        origins = self.headers.get_all('Origin', [])
        if origins not in ([], [server.origin]) or (mutation and origins != [server.origin]):
            return False
        # Fixture sessions never accept or forward browser credentials.
        if self.headers.get_all('Authorization', []):
            return False
        cookies = self.headers.get_all('Cookie', [])
        if len(cookies) != 1 or cookies[0].count('external_fixture=') != 1:
            return False
        cookie = SimpleCookie()
        try:
            cookie.load(cookies[0])
            value = cookie.get('external_fixture')
            return value is not None and secrets.compare_digest(value.value, server.fixture_session)
        except (ValueError, UnicodeError):
            return False

    def authorized(self, *, mutation=False):
        return self.path in {'/api/snapshot', '/api/team/action', '/api/primary-agent'} and self._fixture_authorized(mutation=mutation)

    def _external(self):
        server = self.server
        if not self._fixture_authorized(mutation=self.command == 'POST'):
            return self.reply(403, {'error':'access denied'})
        try:
            if self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length',[])) > 1:
                raise ValueError('ambiguous framing')
            size = int(self.headers.get('Content-Length','0'))
            if not 0 <= size <= 32768:
                raise ValueError('body bound')
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise ValueError('short body')
            def pairs(items):
                result = {}
                for key, val in items:
                    if key in result:
                        raise ValueError('duplicate key')
                    result[key] = val
                return result
            body = json.loads(raw, object_pairs_hook=pairs) if raw else {}
            status, result = server.external.dispatch(self.command, self.path,
                'Bearer ' + server.fixture_issuer, body)
        except (ValueError, UnicodeError):
            status, result = 400, {'error':'invalid request'}
        if self.path == '/external/config' and status == 200:
            result = dict(result, fixture_only=True)
        self.reply(status, result)

    def do_GET(self):
        if self.path.startswith('/external/'):
            return self._external()
        # Prevent DNS rebinding/bootstrap against a foreign hostname.
        if self.headers.get_all('Host', []) != [self.server.origin.removeprefix('http://')]:
            return self.reply(403, {'error':'access denied'})
        return super().do_GET()

    def do_POST(self):
        if self.path.startswith('/external/'):
            return self._external()
        return super().do_POST()


class FixtureServer(PaperclipServer):
    def server_close(self):
        super().server_close()
        self.external.close()
        self.external.store.close()


def build_fixture_server(home, frontend, private, *, fixture_only=False, port=0, capability=None, team=None):
    if fixture_only is not True:
        raise ValueError('explicit fixture-only composition required')
    home = Path(home).resolve()
    vault, state = home / 'vault', home / 'events.jsonl'
    from .replica_authority import authority_context, assert_mutation_authority
    assert_mutation_authority(vault)
    private = Path(private)
    private.mkdir(mode=0o700, parents=True, exist_ok=True)
    private_paths.apply_mode(path=private, mode=0o700)
    selected = private/'selected'
    selected.mkdir(mode=0o700)
    (selected/'review.txt').write_text('Synthetic selected workspace for local delegation UI review.\n', newline="\n")
    snapshot = snapshot_workspace(selected, ['review.txt','.env'])
    store = ExternalGrantStore(private/'grants.db')
    ops = ['read','lookup','list','search','submit']
    try:
        with authority_context(vault, state):
            store.set_authority('fixture-issuer',resources=['task:fixture-task','workspace:fixture-review'],
                                operations=ops,can_issue=True,can_export=True)
    except BaseException:
        store.close()
        raise
    issuer = secrets.token_urlsafe(32)
    credentials = {hashlib.sha256(issuer.encode()).hexdigest(): Principal('fixture-issuer','issuer')}
    recipients = {}
    for location in ('cloud','local'):
        name = 'fixture-'+location
        credentials[hashlib.sha256(secrets.token_bytes(32)).hexdigest()] = Principal(name,'external')
        recipients[name] = dict(label='Synthetic '+location+' recipient',location=location)
    try:
        api = ExternalAPI(store,private/'work.db',credentials=credentials,
            workspaces={'fixture-review':snapshot},tasks={'fixture-task'},recipients=recipients,
            vault=vault, state=state)
    except BaseException:
        store.close()
        raise
    try:
        server = FixtureServer(Path(home),frontend,port,capability=capability,team=team)
    except BaseException:
        api.close()
        store.close()
        raise
    server.external = api
    server.fixture_issuer = issuer
    server.fixture_session = secrets.token_urlsafe(32)
    server.RequestHandlerClass = FixtureHandler
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--connection', type=Path, required=True,
                        help='Existing explicitly fixture_only connection.json; never creates an owner')
    parser.add_argument('--frontend', type=Path, required=True)
    parser.add_argument('--port',type=int,default=0)
    args = parser.parse_args()
    connection = json.loads(args.connection.read_text())
    if connection.get('fixture_only') is not True:
        raise SystemExit('Only an explicitly synthetic existing owner may be composed')
    from .cockpit_client import request
    from .cockpit_team import TeamAuthority
    home = Path(connection['home'])
    request(home,'list')  # Read only, fail rather than start/replace native owner.
    capability = secrets.token_urlsafe(32)  # Private synthetic authority, never a browser credential.
    team = TeamAuthority(home/'vault',home/'events.jsonl',bearer_secret=capability,
                         authorization='Bearer '+capability)
    with tempfile.TemporaryDirectory(prefix='amc-external-fixture-',dir=os.environ.get('TMPDIR')) as private:
        server = build_fixture_server(home,args.frontend,private,fixture_only=True,
                                      port=args.port,capability=capability,team=team)
        print(json.dumps({'origin':server.origin,'fixture_only':True,'owner':'existing, unchanged'}),flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()


if __name__ == '__main__':
    main()
