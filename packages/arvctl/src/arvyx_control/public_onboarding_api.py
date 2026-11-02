"""Trusted local onboarding composition; no installation, root or remote executor.

Embedding code supplies owner-scoped adapters and token digests, not request data.
The fixture factory is explicitly synthetic and never reads the current user's home.
A trusted local extension may compose proof-backed pairing and reviewed profile
creation under the same human capability; fixtures do not gain these services.
"""
from dataclasses import asdict, dataclass, field
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from .security import bounded_json_loads
from pathlib import Path
import secrets
import sqlite3
import socket
import threading
import time
from urllib.parse import urlsplit

_request_deadline = threading.local()


def assert_request_active():
    """Refuse effects after the listener's non-renewable request lifetime.

    Direct trusted calls have no listener deadline. This admission check cannot
    cancel an effect already executing; that operation's durable attempt owns
    ambiguity and reconciliation instead.
    """
    from .reviewed_actions import assert_consent_active
    assert_consent_active()
    expires = getattr(_request_deadline, 'expires', None)
    if expires is not None and time.monotonic() >= expires:
        raise TimeoutError('request deadline expired before effect admission')

from .agent_creation import AgentCreation, CreationRequest
from .agent_sessions import (AgentSessions, SessionTarget, SessionRoute,
                             SessionMetadata, RoutingError, DisconnectedError)
from .harness_discovery import discover_harnesses

PREFIX = '/api/public-onboarding/'


@dataclass
class OwnerAdapters:
    """One authenticated owner's trusted services; never construct from HTTP.

    connect callbacks must attest exact local adapter target/liveness and must not
    import workspaces or start providers. Supply only adapters authorized to this
    owner. Session adapters retain their atomic dispatch/revocation obligation.
    creation must use a dedicated check_same_thread=False SQLite connection;
    all access through this composition is serialized. Do not share it elsewhere.
    """
    discovery: object
    creation: AgentCreation
    sessions: AgentSessions
    connectors: dict = field(default_factory=dict)
    targets: frozenset = frozenset()
    mode: str = 'injected_local_owner'
    extension: object = None
    vault: Path | None = None
    state: Path | None = None


class PublicOnboardingAPI:
    def __init__(self, *, credentials, owners):
        # Credentials map SHA256 token digests to opaque process-local owner keys.
        self.credentials = dict(credentials)
        self.owners = dict(owners)
        if not all(key in self.owners for key in self.credentials.values()):
            raise ValueError('credential owner missing')
        self.lock = threading.RLock()
        self._candidates = {}
        self._connector_ids = {}

    def _connector_incarnation(self,connector):
        # Retain the object as well as the random ID; Python id reuse is harmless.
        identifier=id(connector)
        previous=self._connector_ids.get(identifier)
        if previous is None or previous[0] is not connector:
            previous=(connector,secrets.token_hex(32));self._connector_ids[identifier]=previous
        return previous[1]

    def _profile_request(self,key,body):
        self._fields(body,('candidate_id','agent_id','confirmed'));self._confirm(body)
        candidate=self._candidates.get(key,{}).get(body['candidate_id'])
        from .metadata_adapters import candidate_root
        # Refuses unknown candidates, families without an adapter and foreign markers.
        root=candidate_root(candidate)
        return dict(family=candidate['family'],path=str(root),agent_id=body['agent_id'],confirmed=True)

    def dispatch(self, method, path, authorization, body):
        digest = hashlib.sha256(authorization.removeprefix('Bearer ').encode()).hexdigest()
        owner_key = self.credentials.get(digest) if authorization.startswith('Bearer ') else None
        if owner_key not in self.owners:
            return 401, {'error': 'authentication_required'}
        with self.lock:
            try:
                parts = urlsplit(path)
                if parts.query or parts.fragment or '%' in parts.path or not parts.path.startswith(PREFIX):
                    raise ValueError('canonical path required')
                if type(body) is not dict:
                    raise ValueError('object required')
                owner = self.owners[owner_key]
                from contextlib import nullcontext
                from .replica_authority import (
                    authority_context, assert_mutation_authority, assert_bound_authority,
                )
                # Only embedding-owned configuration may bind authority. Never use
                # body/path fields or infer a vault from an external state path.
                extension = owner.extension
                vault = getattr(extension, 'vault', None) if extension else owner.vault
                state = getattr(extension, 'state', None) if extension else owner.state
                binding = (authority_context(vault, state)
                           if vault is not None else nullcontext())
                with binding:
                    if vault is not None:
                        assert_mutation_authority(vault)
                    elif method != 'GET':
                        assert_bound_authority()
                    if extension and extension.authorize:
                        extension.authorize()
                    assert_request_active()
                    return self._route(owner_key, owner, method, parts.path[len(PREFIX):], body)
            except PermissionError:
                return 403, {'error': 'destination_not_authorized'}
            except DisconnectedError:
                return 409, {'error': 'destination_disconnected', 'queued': False}
            except RoutingError:
                return 409, {'error': 'exact_route_unavailable', 'queued': False}
            except (ValueError, TypeError, KeyError):
                return 400, {'error': 'invalid_request'}
            except (OSError, sqlite3.Error):
                return 503, {'error': 'local_service_unavailable', 'queued': False}

    def dispatch_pairing(self, pairing, path, body):
        """Remote key proof uses owning vault admission, not human approval.

        Transport identity must match exactly one trusted extension. No request
        field or SQLite directory can nominate the authority being checked.
        """
        from .replica_authority import authority_context, assert_mutation_authority
        with self.lock:
            owners = [owner.extension for owner in self.owners.values()
                      if owner.extension is not None
                      and getattr(owner.extension, 'pairing', None) is pairing]
            if len(owners) != 1 or getattr(owners[0], 'vault', None) is None:
                raise ValueError('pairing owner authority unavailable')
            extension = owners[0]
            with authority_context(extension.vault, getattr(extension, 'state', None)):
                assert_mutation_authority(extension.vault)
                if path == '/challenge':
                    return pairing.challenge(body)
                if path == '/prove':
                    return pairing.prove(body)
                raise ValueError('unsupported proof endpoint')

    @staticmethod
    def _fields(body, required=(), optional=()):
        if type(body) is not dict or not set(required) <= body.keys() or body.keys() - set(required) - set(optional):
            raise ValueError('unexpected or missing fields')

    @staticmethod
    def _confirm(body):
        if body.get('confirmed') is not True:
            raise ValueError('per-action confirmation required')

    @staticmethod
    def _target(owner, data):
        if type(data) is not dict or set(data) != {'machine_id', 'agent_id', 'workspace_id', 'connection_id'}:
            raise ValueError('exact target required')
        target = SessionTarget(**data)
        if target not in owner.targets:
            raise PermissionError
        return target

    def _route(self, key, owner, method, path, body, *, reviewed=False,review_snapshot=None):
        if owner.extension is not None and hasattr(owner.extension,'reviewed_actions'):
            from .reviewed_actions import ACTIONS
            reviews=owner.extension.reviewed_actions
            if path.startswith('actions/'):
                return reviews.route(self,key,path,method,body) or (404,dict(error='route_not_found'))
            if method=='POST' and path in ACTIONS and not reviewed:
                # Validate the shape/confirmation before returning the new contract.
                self._confirm(body)
                return 409,dict(error='reviewed_action_consent_required',queued=False)
        if path == 'capabilities' and method == 'GET':
            self._fields(body)
            return 200, dict(**dict(dict(mode=owner.mode, native_installation=False, root_execution=False,
                             remote_transport=False, pairing=False, organizer_provisioning=False,
                             creation_available=True, creation_mode='clean_metadata_only',
                             harnesses=[{'id': h, 'label': h + ' (metadata only)', 'available': True}
                                        for h in sorted(owner.creation.isolated_harnesses)],
                             owner_host=owner.creation.local_host),
                             **(owner.extension.capabilities() if owner.extension else {})))
        if owner.extension:
            if path=='profiles/register' and method=='POST':
                self._fields(body,('candidate_id','display_name','confirmed'));self._confirm(body)
                candidate=self._candidates.get(key,{}).get(body['candidate_id'])
                from .metadata_adapters import METADATA_HARNESSES
                if candidate is None or candidate.get('family') not in METADATA_HARNESSES:raise ValueError('compatible discovered profile unavailable')
                if not isinstance(review_snapshot,dict) or review_snapshot.get('candidate')!=candidate:raise ValueError('reviewed exact registration required')
                from .registry_enrollment import register_profile_identity
                from .reviewed_actions import call_with_publication_guard, record_attempt_plan
                ext=owner.extension
                def effect(*,publication_guard):
                    return register_profile_identity(ext.vault,ext.machine,body['display_name'],candidate['family'],
                                                     publication_guard=publication_guard,plan_recorder=record_attempt_plan)
                return 201,call_with_publication_guard(effect)
            if path=='profiles/connect' and method=='POST':
                profile_snapshot = review_snapshot.get('profile') if isinstance(review_snapshot, dict) else None
                return self._route(key,owner,method,'manual/connect',self._profile_request(key,body),
                                   reviewed=True,review_snapshot=profile_snapshot)
            response = (owner.extension.route(path,method,body,review_snapshot=review_snapshot)
                        if path.startswith('native/') or path in ('manual/connect','pairing/decide') else owner.extension.route(path, method, body))
            if response is not None:
                return response
        if path == 'targets' and method == 'GET':
            self._fields(body)
            return 200, {'items': [asdict(t) for t in sorted(owner.targets, key=repr)]}
        if path == 'discover' and method == 'POST':
            self._fields(body)
            result = owner.discovery()
            from .metadata_adapters import ADAPTERS
            # Only home-relative labels generated by bounded discovery cross HTTP.
            safe = []
            for candidate in result['candidates']:
                item = {k: candidate[k] for k in ('id', 'family', 'label', 'kind', 'local_id') if k in candidate}
                location = candidate.get('location', '')
                item['location'] = (location if isinstance(location, str) and location.startswith('~/')
                    and '..' not in Path(location[2:]).parts and not any(ord(c) < 32 for c in location)
                    else 'Known local location (label unavailable)')
                family=candidate.get('family')
                local_profile=(owner.mode=='real-local' and owner.extension is not None and family in ADAPTERS)
                item['available'] = callable(owner.connectors.get(candidate['id'])) or local_profile
                item['requires_agent_id']=local_profile
                item['reason'] = ('Compatible local connector configured; liveness is checked on explicit connection.'
                    if item['available'] else 'No compatible local connection adapter is configured.')
                if local_profile:item['reason']=ADAPTERS[family].reason()
                safe.append(item)
            self._candidates[key] = {c['id']: c for c in result['candidates']}
            return 200, dict(candidates=safe, truncated=result['truncated'],
                             incomplete=result.get('incomplete', False), incomplete_reasons=result.get('incomplete_reasons', []),
                             requires_explicit_connect=True, auto_import=False, mode=owner.mode)
        if path == 'connect' and method == 'POST':
            self._fields(body, ('candidate_id', 'confirmed'))
            self._confirm(body)
            candidate_id = body['candidate_id']
            if not isinstance(candidate_id, str):
                raise ValueError
            candidate = self._candidates.get(key, {}).get(candidate_id)
            if candidate is None:
                return 404, {'error': 'candidate_not_discovered'}
            connector = owner.connectors.get(candidate_id)
            if connector is None:
                return 501, {'error': 'compatible_local_adapter_unavailable'}
            assert_request_active()
            from .reviewed_actions import call_with_publication_guard
            target = call_with_publication_guard(connector, dict(candidate))
            if target not in owner.targets:
                raise PermissionError
            # Read back exact live adapter metadata before reporting connected.
            owner.sessions.recent(target)
            assert_request_active()
            return 200, dict(target=asdict(target), connected=True, mode=owner.mode)
        if path == 'agents/name-check' and method == 'POST':
            self._fields(body, ('name',))
            import unicodedata
            name = body['name']
            if (not isinstance(name,str) or not name or name != name.strip() or len(name)>128
                    or any(unicodedata.category(c).startswith('C') for c in name)):
                return 400,dict(error='invalid_agent_name')
            canonical = unicodedata.normalize('NFKC',name).casefold()
            duplicate = any(unicodedata.normalize('NFKC',agent.name).casefold()==canonical
                            for agent in owner.creation.list_agents())
            return (409,dict(error='duplicate_agent_name',field='name')) if duplicate else (200,dict(available=True))
        if path == 'agents' and method == 'GET':
            self._fields(body)
            return 200, {'items': [asdict(x) for x in owner.creation.list_agents()]}
        if path == 'agents/create' and method == 'POST':
            if owner.mode == 'real-local':
                return 409, {'error': 'reviewed_creation_consent_required', 'queued': False}
            self._fields(body, ('name', 'harness', 'confirmed'))
            self._confirm(body)
            created = owner.creation.create(CreationRequest(body['name'], body['harness'], owner.creation.local_host))
            if created not in owner.creation.list_agents():
                raise OSError('creation readback failed')
            return 201, asdict(created)
        if path in ('sessions/recent', 'sessions/all', 'sessions/search') and method == 'POST':
            self._fields(body, ('target',), () if path.endswith('recent') else ('query', 'limit', 'cursor'))
            target = self._target(owner, body['target'])
            if path.endswith('recent'):
                return 200, {'items': [asdict(x) for x in owner.sessions.recent(target)]}
            return 200, owner.sessions.all(target, query=body.get('query', ''),
                        limit=body.get('limit', 100), cursor=body.get('cursor')).to_dict()
        if path == 'sessions/select' and method == 'POST':
            self._fields(body, ('route', 'confirmed'))
            self._confirm(body)
            route = body['route']
            self._fields(route, ('target', 'session_id'))
            exact = SessionRoute(self._target(owner, route['target']), route['session_id'])
            assert_request_active()
            result = owner.sessions.select(exact)
            assert_request_active()
            return 200, {'route': asdict(exact), 'result': result, 'queued': False}
        if path in ('native/install', 'root/execute', 'remote/connect', 'pairing/confirm',
                    'organizer/provision', 'sessions/new'):
            return 501, {'error': 'capability_unavailable', 'queued': False}
        return 404, {'error': 'route_not_found'}

    def close(self):
        with self.lock:
            for owner in self.owners.values():
                owner.creation.db.close()
                if owner.extension and owner.extension.pairing:
                    owner.extension.pairing.close()
                if owner.extension and owner.extension.delegations and getattr(owner.extension.delegations,'_runtime_resources',None) is not None:
                    owner.extension.delegations.close()


def handler_for(api, fallback=None):
    """Compose with a trusted same-origin static handler without editing routers.

    Fallback is a BaseHTTPRequestHandler class for non-API paths only. Never
    pass a handler exposing a home directory or private source tree.
    """
    class Handler(fallback or BaseHTTPRequestHandler):
        def _onboarding(self):
            pairing = getattr(api, 'remote_pairing', None)
            proof = pairing is not None and self.path in ('/challenge', '/prove')
            if not self.path.startswith(PREFIX) and not proof:
                inherited = getattr(super(), 'do_' + self.command, None)
                if inherited:
                    return inherited()
                self.send_error(404)
                return
            expected = f'http://{self.server.server_address[0]}:{self.server.server_port}'
            if self.headers.get_all('Host', []) != [expected[7:]] or self.headers.get_all('Origin', []) not in ([], [expected]) or (self.command == 'POST' and not proof and self.headers.get_all('Origin', []) != [expected]):
                status, value = 403, {'error': 'same_origin_required'}
            else:
                try:
                    if self.headers.get('Transfer-Encoding'):
                        raise ValueError
                    lengths = self.headers.get_all('Content-Length', [])
                    if len(lengths) > 1 or len(self.headers.get_all('Authorization', [])) > 1:
                        raise ValueError
                    size = int(lengths[0]) if lengths else 0
                    if not 0 <= size <= 16384:
                        raise ValueError
                    if size and self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
                        raise ValueError
                    raw = self.rfile.read(size)
                    if len(raw) != size:
                        raise ValueError
                    def unique(pairs):
                        value = dict(pairs)
                        if len(value) != len(pairs):
                            raise ValueError('duplicate fields')
                        return value
                    body = bounded_json_loads(raw, object_pairs_hook=unique) if size else {}
                    if proof:
                        if self.command != 'POST' or type(body) is not dict:
                            raise ValueError
                        value = api.dispatch_pairing(pairing, self.path, body)
                        status = 200
                    else:
                        status, value = api.dispatch(self.command, self.path, self.headers.get('Authorization', ''), body)
                except (ValueError, UnicodeError):
                    status, value = 400, {'error': 'invalid_request'}
            data = json.dumps(value).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            self.wfile.write(data)
        do_GET = _onboarding
        do_POST = _onboarding

        def log_message(self, *args):
            pass  # Do not log bearer headers or sensitive request bodies.
    return Handler


class BoundedWorkers:
    """Bound workers, idle reads and non-renewable preheader/body lifetime."""
    request_lifetime_seconds = 3
    daemon_threads = True
    block_on_close = True
    def __init__(self, *args, max_workers=16, socket_timeout=3, **kwargs):
        self._workers = threading.BoundedSemaphore(max_workers)
        self.socket_timeout = socket_timeout
        super().__init__(*args, **kwargs)

    def get_request(self):
        sock, address = super().get_request()
        sock.settimeout(self.socket_timeout)
        return sock, address

    def process_request(self, request, client_address):
        if not self._workers.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._workers.release()
            raise

    def process_request_thread(self, request, client_address):
        # Run before BaseHTTPRequestHandler parses any bytes. An idle timeout
        # alone can be renewed forever by an incomplete, trickling header.
        def expire():
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # Normal completion may already have closed the socket.
        _request_deadline.expires = time.monotonic() + self.request_lifetime_seconds
        deadline = threading.Timer(self.request_lifetime_seconds, expire)
        deadline.daemon = True
        deadline.start()
        try:
            super().process_request_thread(request, client_address)
        finally:
            deadline.cancel()
            deadline.join()
            del _request_deadline.expires
            self._workers.release()


class BoundedOnboardingServer(BoundedWorkers, ThreadingHTTPServer):
    pass


def make_server(api, *, host='127.0.0.1', port=0, fallback=None):
    if host != '127.0.0.1':
        raise ValueError('IPv4 loopback binding required')
    return BoundedOnboardingServer((host, port), handler_for(api, fallback))


class FixtureSessionAdapter:
    """Synthetic in-memory metadata, with exact destination revalidation."""
    def __init__(self, target, count):
        self.target, self.connected = target, False
        self.actions = []
        self.items = tuple(SessionMetadata(SessionRoute(target, f'session-{i}'),
                           f'Fixture session-{i}', i) for i in range(count))

    def metadata(self, target):
        if target != self.target or not self.connected:
            raise DisconnectedError
        return self.items

    def perform(self, target, action, session_id=None, *, publication_guard=None):
        if (target != self.target or not self.connected or action != 'select'
                or not any(x.route.session_id == session_id for x in self.items)):
            raise DisconnectedError
        if publication_guard is not None:publication_guard()
        self.actions.append((target, action, session_id))
        return {'fixture': True, 'session_id': session_id}


def fixture_composition(root, *, session_count=1205):
    """Create isolated fixture files only below an explicit trusted local root.

    No automatic server start, host-home scan, native execution or provisioning.
    Caller protects root and retains returned token privately; never put it in URLs.
    """
    root = Path(root).resolve()
    # Explicit synthetic composition authority, never a production DB inference.
    vault = root / 'fixture-vault'
    vault.mkdir(mode=0o700, parents=True, exist_ok=True)
    state = root / 'fixture-events.jsonl'
    from .replica_authority import assert_mutation_authority
    assert_mutation_authority(vault)
    home = root / 'fixture-home'
    (home / '.hermes').mkdir(parents=True, exist_ok=True)
    (home / '.hermes/config.yaml').write_text('# synthetic discovery marker\n')
    profiles = root / 'profiles'
    profiles.mkdir(mode=0o700, exist_ok=True)
    creation = AgentCreation(sqlite3.connect(root / 'agents.sqlite', check_same_thread=False),
        profiles, workspace_id='fixture-workspace', local_host='fixture-machine',
        isolated_harnesses={'fixture'})
    target = SessionTarget('fixture-machine', 'fixture-agent', 'fixture-workspace', 'fixture-connection')
    adapter = FixtureSessionAdapter(target, session_count)
    def connect(candidate, *, publication_guard=None):
        if publication_guard is not None:publication_guard()
        adapter.connected = True
        return target
    owner = OwnerAdapters(lambda: discover_harnesses(home), creation,
        AgentSessions({target: adapter}), {'hermes:agent:default': connect},
        frozenset({target}), 'fixture_only', vault=vault, state=state)
    token = secrets.token_urlsafe(32)
    api = PublicOnboardingAPI(credentials={hashlib.sha256(token.encode()).hexdigest(): 'fixture-owner'},
                              owners={'fixture-owner': owner})
    api.owner, api.fixture_target = owner, asdict(target)
    return api, token, adapter
