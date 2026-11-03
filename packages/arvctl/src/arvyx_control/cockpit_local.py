"""Explicit real-local Paperclip presentation and metadata setup, separate from demos.

Optional native lifecycle and independently provisioned export authority are explicit composition choices; neither is inferred from connection metadata.
The operator credential remains server-side; the browser capability is separate.
"""
from __future__ import annotations

import argparse
import getpass
import json
from . import safe_open
from . import private_paths
from .security import bounded_json_loads
import os
from pathlib import Path
import secrets
import sqlite3
import webbrowser

from .cockpit_client import request
from .cockpit_paperclip import PaperclipHandler, PaperclipServer
from .cockpit_team import TeamAuthority


def inspect_existing_owner(connection):
    """Read-only owner canary. Does not instantiate a registry or elect primary."""
    document = json.loads(Path(connection).read_text())
    if not isinstance(document, dict):
        raise ValueError('connection object required')
    if document.get('fixture_only') not in (None, False):
        raise ValueError('synthetic owner requires the separate demo mode')
    value = document.get('home')
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise ValueError('explicit absolute owner home required')
    home = Path(value).resolve(strict=True)
    current = request(home, 'snapshot', actor='operator')
    from .machine_enrollment import verify
    verify(home,current.get('host'))
    state, vault = home / 'events.jsonl', home / 'vault'
    db = sqlite3.connect((home / 'runtime' / 'sessions.sqlite').as_uri() + '?mode=ro', uri=True)
    try:
        identity = db.execute('SELECT state,vault FROM identity').fetchall()
        if identity != [(str(state.resolve()), str(vault.resolve()))]:
            raise ValueError('native owner authority binding mismatch')
        if Path(current['state']).resolve() != state.resolve():
            raise ValueError('owner snapshot authority binding mismatch')
        bindings = db.execute('''SELECT o.agent,o.session,b.tool FROM native_organizers o
            JOIN native_bindings b ON b.session=o.session ORDER BY o.rowid''').fetchall()
    finally:
        db.close()
    sessions = {row['id']: row for row in current['sessions']}
    eligible = []
    from .auth import AGENT_ID_RE
    for agent, sid, tool in bindings:
        if not isinstance(agent, str) or not AGENT_ID_RE.fullmatch(agent):
            continue
        row = sessions.get(sid, {})
        if tool == 'fixture' or row.get('status') != 'running' or not row.get('pid'):
            continue
        native = request(home, 'native', sid=sid, actor='operator')
        if native and native.get('tool') == tool:
            from .cockpit_primary import compatible_native_identity
            if compatible_native_identity(vault, agent, current.get('host'), tool):
                eligible.append(agent)
    return dict(home=home, state=state, vault=vault, eligible_agents=eligible)


class LocalHandler(PaperclipHandler):
    def do_POST(self):
        if self.path.startswith('/external/'):
            from .external_presentation import handle_external
            return handle_external(self)
        if self.path not in ('/api/local-bindings', '/api/local-enrollments'):
            return super().do_POST()
        if not self.authorized(mutation=True):
            return self.reply(403, {'error': 'Authenticated local human session required'})
        try:
            if self.headers.get_all('Content-Type', []) != ['application/json'] or self.headers.get('Transfer-Encoding'):
                raise ValueError('JSON framing required')
            lengths = self.headers.get_all('Content-Length', [])
            if len(lengths) != 1 or not 0 < int(lengths[0]) <= 4096:
                raise ValueError('bounded JSON required')
            raw = self.rfile.read(int(lengths[0]))
            if len(raw) != int(lengths[0]):
                raise ValueError('incomplete JSON')
            def unique(pairs):
                result = dict(pairs)
                if len(result) != len(pairs):
                    raise ValueError('duplicate fields')
                return result
            payload = bounded_json_loads(raw, object_pairs_hook=unique)
            if self.path == '/api/local-enrollments':
                return self.reply(201, self.server.bindings.enroll(payload))
            return self.reply(200, self.server.bindings.bind(payload))
        except PermissionError:
            return self.reply(403, {'error': 'Human operator required'})
        except (ValueError, KeyError, TypeError) as exc:
            if self.path == '/api/local-enrollments':
                return self.reply(409, {'error': 'Registration rejected: ' + str(exc)})
            return self.reply(409, {'error': 'Binding rejected: refresh exact session and compatible registry identity; stale or rebind conflict'})
        except (OSError, RuntimeError, sqlite3.Error):
            return self.reply(503, {'error': 'Owner unavailable'})

    def do_GET(self):
        if self.path.startswith('/external/'):
            from .external_presentation import handle_external
            return handle_external(self)
        if self.path == '/api/presentation-mode':
            if self.headers.get_all('Host', []) != [self.server.origin.removeprefix('http://')]:
                return self.reply(403, {'error': 'Access denied'})
            return self.reply(200, {'mode': 'real-local'})
        if self.path == '/api/local-bindings':
            if not self.authorized() or self.headers.get_all('Origin', []) not in ([], [self.server.origin]):
                return self.reply(403, {'error': 'Authenticated local human session required'})
            try:
                return self.reply(200, self.server.bindings.read())
            except (OSError, ValueError, RuntimeError, sqlite3.Error):
                return self.reply(503, {'error': 'Owner unavailable'})
        if self.path == '/api/local-connection':
            if not self.authorized() or self.headers.get_all('Origin', []) not in ([], [self.server.origin]):
                return self.reply(403, {'error': 'Authenticated local human session required'})
            try:
                # Revalidate the exact attachment; lost owner is not synthetic fallback.
                owner = inspect_existing_owner(self.server.connection)
                if owner['home'] != self.server.root.resolve():
                    raise ValueError('connection target changed; explicit reconfiguration required')
            except (OSError, ValueError, RuntimeError, sqlite3.Error, KeyError):
                return self.reply(503, {'error': 'Existing owner unavailable'})
            return self.reply(200, dict(mode='real-local', owner_connected=True,
                                       native_session_control=bool(getattr(self.server,'native_enabled',False)), external_delegation=getattr(self.server,'external',None) is not None))
        # Static bootstrap is also host-bound, preventing DNS rebinding.
        if self.headers.get_all('Host', []) != [self.server.origin.removeprefix('http://')]:
            return self.reply(403, {'error': 'Access denied'})
        return super().do_GET()


from .public_onboarding_api import BoundedWorkers


class LocalServer(PaperclipServer):
    def server_close(self):
        super().server_close()
        if getattr(self, 'onboarding', None) is not None:
            self.onboarding.close()
            self.onboarding = None
        if self.primary is not None:
            self.primary.registry.close()
        external=getattr(self,'external',None)
        if external is not None and getattr(external,'owns_api',False):
            external.api.close();external.api.store.close();self.external=None


def build_local_server(connection, frontend, *, operator_secret, port=0, capability=None, discovery_home=None, enable_pairing=False, workspace_roots=None, enable_native=False, external=None, external_config=None,native_frontend=None,native_binary=None):
    """Explicit operator configuration; never imports ambient credentials.

    Uses AMC's existing operator shared-secret trust model. A same-UID operator
    explicitly supplies its existing credential. It is not a new agent token,
    provider login, or browser credential. Construction can create the existing
    primary sidecar, and validated connection events durably elect the first identity.
    """
    # Reject ignored/mismatched presentation options before constructing a
    # listener, sidecar, pairing transport or onboarding database.
    if bool(native_frontend) != bool(native_binary):
        raise ValueError('native frontend/binary pair required')
    if native_frontend is not None and not enable_native:
        raise ValueError('native presentation requires explicit enable_native')
    if external is not None and external_config is not None:
        raise ValueError('choose one explicit export composition')
    if not isinstance(operator_secret, str) or not operator_secret.strip():
        raise ValueError('existing AMC operator credential required')
    owner = inspect_existing_owner(connection)
    team = TeamAuthority(owner['vault'], owner['state'], bearer_secret=operator_secret,
                         authorization='Bearer ' + operator_secret)
    server = LocalServer(owner['home'], frontend, port, capability=capability, team=team)
    if server.primary is None or not server.primary.can_select():
        server.server_close()
        raise ValueError('existing human operator authority required')
    from .cockpit_human_binding import HumanBindings
    server.bindings = HumanBindings(owner['home'], server.primary)
    original_source = server.primary.source
    def source():
        native = original_source()
        human = server.bindings.connected()
        server.primary.election_sources = {agent: 'human-binding' for agent in human if agent not in native}
        return native + human
    server.primary.source = source
    server.connection = Path(connection).resolve()
    if external_config is not None:
        from .external_presentation import load_presentation
        try:external=load_presentation(external_config,vault=owner['vault'],state=owner['state'])
        except BaseException:
            server.server_close();raise
    server.external=external
    server.native_enabled=enable_native
    if external is not None and (external.api.vault!=owner['vault'].resolve() or external.api.state!=owner['state'].resolve()):
        server.server_close()
        raise PermissionError('external issuer must bind the exact existing owner authority')
    from .local_onboarding import local_composition
    from .machine_pairing_transport import private_directory, PairingTransport
    from .public_onboarding_api import handler_for
    directory = private_directory(owner['home'] / 'runtime' / 'onboarding')
    pairing = PairingTransport(directory / 'pairing') if enable_pairing else None
    try:
        server.onboarding = local_composition(directory, vault=owner['vault'],
            machine_id=request(owner['home'], 'snapshot', actor='operator')['host'],
            capability=server.capability, discovery_home=discovery_home,
            authorize=lambda: server.primary.registry._identity(server.primary.authorization, human=True),
            pairing=pairing, workspace_roots=workspace_roots)
        server.onboarding.remote_pairing = pairing
        if enable_native:
            from .native_lifecycle import NativeLifecycle,SocketOwnerProducer
            extension=server.onboarding.owners['local-owner'].extension
            extension.native=NativeLifecycle(extension,SocketOwnerProducer(owner['home'],vault=owner['vault'],state=owner['state'],machine=extension.machine))
            if native_frontend is not None:
                from .native_presentation import NativePresentation
                extension.native.frontend=NativePresentation(owner['home'],native_frontend,native_binary,extension.owner.creation.db)
        server.RequestHandlerClass = handler_for(server.onboarding, LocalHandler)
    except BaseException:
        if pairing:
            pairing.close()
        server.server_close()
        raise
    return server


def write_browser_connection(path, origin, capability):
    """Explicit local handoff only, never overwrite an existing file or symlink."""
    fd = safe_open.open_file(path, write=True, create=True, exclusive=True, mode=0o600)
    with os.fdopen(fd, 'w', newline="\n") as stream:
        json.dump(dict(origin=origin, capability=capability, mode='real-local'), stream)
        stream.write('\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--operator-credential-file',type=Path,help='Explicit private local bootstrap operator credential; never sent to the browser')
    parser.add_argument('--connection', type=Path, required=True, help='Explicit existing non-fixture owner connection JSON')
    parser.add_argument('--frontend', type=Path, required=True)
    parser.add_argument('--discovery-home', type=Path, help='Explicit metadata-only known-location discovery root; no ambient home scan')
    parser.add_argument('--workspace-root', action='append', type=Path, default=[], help='Authorize a workspace directory for reviewed New preparation; no execution')
    parser.add_argument('--enable-pairing', action='store_true', help='Enable Ed25519 proof transport and separate human MAIN approval; requires approved cryptography extra')
    parser.add_argument('--native-frontend',type=Path,help='Explicit existing native frontend binding for reviewed exact pane presentation')
    parser.add_argument('--native-binary',type=Path,help='Independently admitted onboarding-v1 native artifact; never enrolled by this command')
    parser.add_argument('--external-config',type=Path,help='Private independent issuer, reviewed manifests and existing export authority configuration')
    parser.add_argument('--enable-native',action='store_true',help='Enable reviewed lifecycle through the existing owner and its separately configured execution policy')
    parser.add_argument('--port', type=int, default=0)
    parser.add_argument('--open', action='store_true', help='Open capability fragment in the local browser, never print it')
    parser.add_argument('--browser-connection-out', type=Path, help='Create new mode-0600 browser handoff JSON; contains a local secret')
    parser.add_argument('--canary', action='store_true', help='Read-only owner validation; no election, credential, or listener')
    args = parser.parse_args()
    if args.canary:
        owner = inspect_existing_owner(args.connection)
        print(json.dumps(dict(mode='real-local', owner_connected=True,
                              eligible_agents=owner['eligible_agents'], read_only=True)), flush=True)
        return
    if not args.open and args.browser_connection_out is None:
        parser.error('choose --open or --browser-connection-out for private local capability delivery')
    credential=None
    if args.operator_credential_file:
        from .external_workspace import _read
        p=args.operator_credential_file
        raw,identity,_=_read(p.parent,(p.name,),4096)
        if not private_paths.is_private_mode(identity[2],path=p):raise ValueError('operator credential must be private')
        credential=raw.decode().strip()
    server = build_local_server(args.connection, args.frontend,
                                operator_secret=credential or getpass.getpass('Existing AMC operator shared secret (server only): '), port=args.port,
                                discovery_home=args.discovery_home, enable_pairing=args.enable_pairing,enable_native=args.enable_native,external_config=args.external_config,native_frontend=args.native_frontend,native_binary=args.native_binary,
                                workspace_roots={f'root-{i+1}':p for i,p in enumerate(args.workspace_root)})
    try:
        if args.browser_connection_out:
            write_browser_connection(args.browser_connection_out, server.origin, server.capability)
        if args.open:
            webbrowser.open(server.origin + '/#' + server.capability)
        print(json.dumps(dict(origin=server.origin, mode='real-local', owner='existing, unchanged')), flush=True)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
