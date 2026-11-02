"""Persistent fleet-global main-agent selection, independent of pane selection.

Integration:
* PaperclipServer attaches NativePrimaryAuthority to the already running owner.
  Its source validates the owner's immutable state/vault binding and native
  organizer sessions via read-only SQLite plus authenticated local socket reads.
  Synthetic fixture tools never establish real native connection evidence.
  GET/POST /api/primary-agent use the existing human presentation boundary plus
  re-resolved underlying AMC identity; agent principals cannot change selection.
* Construct PrimaryAgentRegistry(owner, coordinator_database, shared_secret=...)
  ONCE at the trusted coordinator; every host/client must use this same store,
  not a per-host replica. Existing LocalCockpit supplies vault/state/_human.
* After an actual authenticated transport connection, call
  connect(authorization=server_received_header). Its returned connection_id
  belongs to that exact authenticated agent. Never enroll on registry listing,
  browser page load, agent-supplied name/role, or unauthenticated discovery.
* On that transport's detach call disconnect(connection_id, authorization=...).
  snapshot() returns agent_id/revision/connected; connected means recorded open
  connections, NOT heartbeat/liveness proof. After coordinator restart reconcile
  stale connection IDs with disconnect before advertising live reachability.
* Human selection: select(exact_agent_id, revision=snapshot_revision,
  authorization=human_header). Resolve credentials on EVERY call; never pass
  shared_secret from request data. It uses existing auth.resolve_identity and
  owner._human, not an agent-supplied actor label. Human shared-secret access is
  the existing AMC operator trust model, not a new human identity mechanism.
* Keep selection endpoint off agent HTTP/MCP tools. Browser/Arvyx actions must
  use an authenticated human control boundary. A same-UID process with operator
  credentials or direct database access is outside this model's isolation.

First valid enrollment and subsequent human changes serialize with SQLite
BEGIN IMMEDIATE across processes. No process/tool/session is started or moved.
Names never participate in selection; agent IDs remain exact and immutable.
Disconnect never clears primary or elects a replacement. The only selection
writes after first enrollment are authenticated human compare-and-set actions.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3
import threading
import uuid

from .auth import AGENT_ID_RE, resolve_identity


class PrimaryAgentRegistry:
    """One explicit shared SQLite authority per fleet, not per machine."""

    def __init__(self, owner, database: Path, *, shared_secret=None):
        from .replica_authority import assert_mutation_authority
        assert_mutation_authority(owner.vault)
        self.owner = owner
        self._secret = shared_secret
        self._lock = threading.RLock()
        self._observation_lock = threading.RLock()
        self._observation_path = Path(str(database) + '.observation.lock')
        self.db = sqlite3.connect(database, timeout=30, check_same_thread=False,
                                  isolation_level=None)
        self.db.row_factory = sqlite3.Row
        try:
            with self._transaction():
                self.db.execute('''CREATE TABLE IF NOT EXISTS primary_authority (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    state TEXT NOT NULL, vault TEXT NOT NULL)''')
                binding = (str(owner.state.resolve()), str(owner.vault.resolve()))
                self.db.execute('INSERT OR IGNORE INTO primary_authority VALUES(1,?,?)', binding)
                found = self.db.execute('SELECT state,vault FROM primary_authority').fetchone()
                if tuple(found) != binding:
                    raise ValueError('primary store authority binding mismatch')
                self.db.execute('''CREATE TABLE IF NOT EXISTS primary_agent (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    agent_id TEXT, revision INTEGER NOT NULL)''')
                self.db.execute('INSERT OR IGNORE INTO primary_agent VALUES(1,NULL,0)')
                self.db.execute('''CREATE TABLE IF NOT EXISTS primary_connections (
                    connection_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL,
                    connected INTEGER NOT NULL CHECK(connected IN (0,1)))''')
                self.db.execute('''CREATE TABLE IF NOT EXISTS primary_events (
                    sequence INTEGER PRIMARY KEY, actor TEXT NOT NULL,
                    agent_id TEXT NOT NULL, revision INTEGER NOT NULL, reason TEXT NOT NULL)''')
        except BaseException:
            self.db.close()
            raise

    @contextmanager
    def _transaction(self):
        from .replica_authority import assert_mutation_authority
        with self._lock:
            assert_mutation_authority(self.owner.vault)
            self.db.execute('BEGIN IMMEDIATE')
            try:
                yield
                self.db.execute('COMMIT')
            except BaseException:
                self.db.execute('ROLLBACK')
                raise

    def close(self):
        with self._lock:
            self.db.close()

    def _identity(self, authorization, *, human=False):
        if not isinstance(authorization, str):
            raise PermissionError('authenticated credentials required')
        identity = resolve_identity(self.owner.vault, authorization, self._secret)
        if identity is None or identity.kind != ('operator' if human else 'agent'):
            raise PermissionError('authenticated human operator required' if human
                                  else 'authenticated registered agent required')
        if human:
            self.owner._human(identity.agent_id)
        return identity

    def _registered(self, agent_id):
        if not isinstance(agent_id, str) or not AGENT_ID_RE.fullmatch(agent_id):
            raise ValueError('exact agent ID required')
        try:
            record = json.loads((self.owner.vault / 'registry' / 'agents' /
                                 (agent_id + '.json')).read_text())
        except (OSError, ValueError) as exc:
            raise ValueError('registered agent required') from exc
        if not isinstance(record, dict) or record.get('id') != agent_id:
            raise ValueError('registry ID binding mismatch')

    def _snapshot(self):
        row = dict(self.db.execute('SELECT agent_id,revision FROM primary_agent WHERE singleton=1').fetchone())
        row['connected'] = bool(self.db.execute('''SELECT 1 FROM primary_connections
            WHERE agent_id=? AND connected=1 LIMIT 1''', (row['agent_id'],)).fetchone())
        return row

    def snapshot(self):
        # A read transaction keeps the selection and presence observations coherent.
        with self._transaction():
            return self._snapshot()

    def connect(self, *, authorization):
        with self._transaction():
            identity = self._identity(authorization)
            self._registered(identity.agent_id)
            connection_id = uuid.uuid4().hex
            self.db.execute('INSERT INTO primary_connections VALUES(?,?,1)',
                            (connection_id, identity.agent_id))
            self._elect_locked(identity.agent_id, actor=identity.agent_id, reason='first authenticated connection')
            return dict(self._snapshot(), connection_id=connection_id)

    def _elect_locked(self, agent_id, *, actor, reason):
        """Called only inside a validated connection transaction, never a read."""
        self._registered(agent_id)
        changed = self.db.execute('''UPDATE primary_agent SET agent_id=?,revision=revision+1
            WHERE singleton=1 AND agent_id IS NULL''', (agent_id,)).rowcount
        if changed:
            self.db.execute('INSERT INTO primary_events(actor,agent_id,revision,reason) VALUES(?,?,?,?)',
                            (actor, agent_id, self._snapshot()['revision'], reason))

    def attach_store(self, path, alias):
        """One rollback-journal transaction can commit connection and election.

        SQLite's super-journal recovers both files after a process/power failure.
        WAL and in-memory stores cannot provide this cross-file guarantee.
        """
        with self._lock:
            stores = {row[1]: row[2] for row in self.db.execute('PRAGMA database_list')}
            if alias in stores:
                if Path(stores[alias]).resolve() != Path(path).resolve():
                    raise ValueError('attached authority store mismatch')
            else:
                if alias not in ('human_bindings', 'native_owner'):
                    raise ValueError('unknown authority store')
                self.db.execute('ATTACH DATABASE ? AS ' + alias, (str(Path(path).resolve()),))
            for schema in ('main', alias):
                mode = self.db.execute('PRAGMA ' + schema + '.journal_mode').fetchone()[0]
                if mode != 'delete':
                    raise ValueError('durable multi-store election requires delete journals')
                self.db.execute('PRAGMA ' + schema + '.synchronous=FULL')

    def disconnect(self, connection_id, *, authorization):
        with self._transaction():
            identity = self._identity(authorization)
            if not isinstance(connection_id, str):
                raise ValueError('exact connection ID required')
            found = self.db.execute('SELECT agent_id FROM primary_connections WHERE connection_id=?',
                                    (connection_id,)).fetchone()
            if found is None or found['agent_id'] != identity.agent_id:
                raise PermissionError('connection belongs to another identity or is unknown')
            self.db.execute('UPDATE primary_connections SET connected=0 WHERE connection_id=?',
                            (connection_id,))
            return self._snapshot()

    def select(self, agent_id, *, revision, authorization):
        with self._transaction():
            return self._select_locked(agent_id, revision=revision, authorization=authorization)

    def _select_locked(self, agent_id, *, revision, authorization):
        self._identity(authorization, human=True)
        self._registered(agent_id)
        if type(revision) is not int or revision < 0:
            raise ValueError('exact nonnegative selection revision required')
        current = self._snapshot()
        if current['revision'] != revision:
            raise ValueError('stale primary selection revision')
        if not self.db.execute('''SELECT 1 FROM primary_connections
            WHERE agent_id=? AND connected=1 LIMIT 1''', (agent_id,)).fetchone():
            raise ValueError('selection requires a connected agent')
        if current['agent_id'] != agent_id:
            self.db.execute('UPDATE primary_agent SET agent_id=?,revision=revision+1 WHERE singleton=1',
                            (agent_id,))
            self.db.execute('INSERT INTO primary_events(actor,agent_id,revision,reason) VALUES(?,?,?,?)',
                            ('operator', agent_id, revision + 1, 'explicit human selection'))
        return self._snapshot()


class NativePrimaryAuthority:
    """Server-only adapter: native owner evidence, never browser/agent role claims.

    The supplied source is a trusted coordinator callback, not request data.
    Every read/write reconciles presence before observing or changing authority.
    No native process is started, resumed, interrupted or selected by this adapter.
    """

    def __init__(self, registry, source, *, authorization=None):
        self.registry, self.source, self.authorization = registry, source, authorization

    @contextmanager
    def _observation(self):
        # Serialize observations across workers/processes without holding SQLite
        # while asking the owner for facts. Owner connection writes take primary
        # after owner.lock, so primary -> owner I/O would invert that lock order.
        from .locks import exclusive_lock
        with self.registry._observation_lock, exclusive_lock(self.registry._observation_path):
            yield

    def _reconcile(self):
        with self._observation():
            agents = self._sample()
            with self.registry._transaction():
                return self._publish_locked(agents)

    def _sample(self):
        registry = self.registry
        try:
            agents = list(dict.fromkeys(self.source()))
        except (OSError, ValueError, sqlite3.Error) as exc:
            raise RuntimeError('native connection authority unavailable') from exc
        validated = []
        for agent in agents:
            try:
                registry._registered(agent)
            except ValueError:
                continue  # An unregistered native binding is not an eligible AMC identity.
            validated.append(agent)
        return validated

    def _publish_locked(self, agents):
        registry = self.registry
        registry.db.execute("UPDATE primary_connections SET connected=0 WHERE connection_id LIKE 'native:%'")
        for agent in agents:
            registry.db.execute('INSERT OR REPLACE INTO primary_connections VALUES(?,?,1)',
                                ('native:' + agent, agent))
        return registry._snapshot()
    def can_select(self):
        try:
            self.registry._identity(self.authorization, human=True)
            return True
        except PermissionError:
            return False

    def read(self):
        self._reconcile()
        registry = self.registry
        with registry._transaction():
            state = registry._snapshot()
            agents = [dict(id=row['agent_id'], connected=bool(row['connected'])) for row in
                      registry.db.execute('SELECT agent_id,MAX(connected) AS connected FROM primary_connections GROUP BY agent_id ORDER BY MIN(rowid)')]
            return dict(primary_agent_id=state['agent_id'], primary_connected=state['connected'],
                        revision=state['revision'], can_set_primary=self.can_select(), agents=agents)

    def select(self, agent_id, *, revision):
        # Identity checked before source I/O or any election/selection write.
        self.registry._identity(self.authorization, human=True)
        with self._observation():
            agents = self._sample()
            with self.registry._transaction():
                self._publish_locked(agents)
                return self.registry._select_locked(agent_id, revision=revision, authorization=self.authorization)


def read_native_registry(vault,kind,identifier):
    from .external_workspace import _read
    if kind not in {'agents','runtimes','machines'} or not isinstance(identifier,str) or not AGENT_ID_RE.fullmatch(identifier):
        raise ValueError('exact registry identity required')
    data,_,_=_read(Path(vault),('registry',kind,identifier+'.json'),256*1024)
    return json.loads(data)


def compatible_native_identity(vault, agent, host, tool):
    """Registration is not evidence unless its exact machine/runtime agree."""
    try:
        def record_at(kind,identifier):
            return read_native_registry(vault,kind,identifier)
        if not isinstance(agent, str) or not AGENT_ID_RE.fullmatch(agent):
            return False
        record = record_at('agents',agent)
        if not isinstance(record, dict) or record.get('id') != agent or record.get('machine_id') != host:
            return False
        runtime = record.get('runtime_id')
        if not all(isinstance(v, str) and AGENT_ID_RE.fullmatch(v) for v in (runtime, host)):
            return False
        machine = record_at('machines',host)
        execution = record_at('runtimes',runtime)
        return (isinstance(machine, dict) and machine.get('id') == host
                and isinstance(execution, dict) and execution.get('id') == runtime
                and execution.get('harness') == tool)
    except (OSError, ValueError, TypeError,RecursionError):
        return False


def existing_native_primary(home, team):
    """Attach read-only to the same existing owner; never replace its session.

    Only native organizer bindings explicitly recorded by that owner count.
    Registry names, task owners and synthetic fixture tools do not establish
    a native connection. An unreachable owner yields unavailable, not empty live.
    """
    from types import SimpleNamespace
    from .cockpit_client import request
    home = Path(home)
    initial = request(home, 'snapshot', actor='operator')
    from .cockpit import LocalCockpit
    owner = SimpleNamespace(vault=Path(team.vault), state=Path(team.state),
                            _human=LocalCockpit._human)
    if Path(initial['state']).resolve() != owner.state.resolve():
        raise ValueError('primary owner state binding mismatch')
    database = owner.state.with_name(owner.state.name + '.primary.sqlite')
    registry = PrimaryAgentRegistry(owner, database, shared_secret=team._bearer_secret)
    def source():
        current = request(home, 'snapshot', actor='operator')
        sessions = {row['id']: row for row in current['sessions']}
        db = sqlite3.connect((home / 'runtime' / 'sessions.sqlite').resolve().as_uri() + '?mode=ro', uri=True)
        try:
            identity = db.execute('SELECT state,vault FROM identity').fetchone()
            if identity != (str(owner.state.resolve()), str(owner.vault.resolve())):
                raise ValueError('native owner authority binding mismatch')
            bindings = db.execute('''SELECT o.agent,o.session,b.tool FROM native_organizers o
                                    JOIN native_bindings b ON b.session=o.session ORDER BY o.rowid''').fetchall()
        finally:
            db.close()
        result = []
        for agent, sid, tool in bindings:
            session = sessions.get(sid, {})
            if tool != 'fixture' and session.get('status') == 'running' and session.get('pid'):
                native = request(home, 'native', sid=sid, actor='operator')
                if (native and native['tool'] == tool
                        and compatible_native_identity(owner.vault, agent, current.get('host'), tool)):
                    result.append(agent)
        return result
    return NativePrimaryAuthority(registry, source, authorization=team._authorization)
