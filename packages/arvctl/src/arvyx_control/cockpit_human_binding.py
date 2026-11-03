"""Human-asserted associations in a separate audited authority; never native DB writes."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import time
import unicodedata
from contextlib import closing
from . import private_paths
from . import safe_open
from .locks import check_deadline, exclusive_lock, vault_lock
from .cockpit_client import request
from .auth import AGENT_ID_RE


class HumanBindings:
    def __init__(self, home, primary):
        from .replica_authority import assert_mutation_authority
        assert_mutation_authority(primary.registry.owner.vault)
        self.home, self.primary = Path(home), primary
        self.path = self.home / 'runtime' / 'human-bindings.sqlite'
        self.keypath = self.home / 'runtime' / 'human-bindings.key'
        with exclusive_lock(self.keypath.with_suffix('.lock')):
            try:
                fd = safe_open.open_file(self.keypath, write=True, create=True, exclusive=True, mode=0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(fd, 'wb') as f:
                    f.write(os.urandom(32))
                    f.flush()
                    os.fsync(f.fileno())
            fd = safe_open.open_file(self.keypath)
            with os.fdopen(fd, 'rb') as f:
                self.key = f.read()
            if len(self.key) != 32:
                raise ValueError('invalid binding signing key')
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('CREATE TABLE IF NOT EXISTS bindings(session TEXT PRIMARY KEY, revision INTEGER, document TEXT, signature TEXT)')
            db.execute('CREATE TABLE IF NOT EXISTS audit(sequence INTEGER PRIMARY KEY, actor TEXT, document TEXT, signature TEXT)')
            db.execute('CREATE TABLE IF NOT EXISTS enrollment_journal(agent_id TEXT PRIMARY KEY, document TEXT, signature TEXT, status TEXT)')
        private_paths.apply_mode(path=self.path, mode=0o600)
        self._recover_enrollments()
        self.primary.registry.attach_store(self.path, 'human_bindings')

    @staticmethod
    def _sync_directory(path):
        fd = safe_open.open_directory(path)
        try:
            safe_open.fsync_directory(fd)
        finally:
            os.close(fd)

    def _recover_enrollments(self):
        # Roll back incomplete publication only when the signed intent and exact
        # bytes agree. A replacement or symlink is a conflict, never ours to erase.
        deadline = time.monotonic() + 5
        with vault_lock(self.home/'vault', deadline=deadline), closing(sqlite3.connect(self.path, timeout=check_deadline(deadline) or 0)) as db, db:
            from .replica_authority import assert_mutation_authority
            assert_mutation_authority(self.primary.registry.owner.vault)
            db.execute('PRAGMA busy_timeout=' + str(int((check_deadline(deadline) or 0) * 1000)))
            db.execute('BEGIN IMMEDIATE')
            for agent_id, raw, sig in db.execute("SELECT agent_id,document,signature FROM enrollment_journal WHERE status='prepared'").fetchall():
                if not hmac.compare_digest(sig, self.signature(raw)):
                    raise ValueError('enrollment recovery journal signature mismatch')
                document = json.loads(raw)
                if document['agent']['id'] != agent_id:
                    raise ValueError('enrollment journal identity mismatch')
                for kind, record in (('agents', document['agent']), ('runtimes', document['runtime'])):
                    path = self.home/'vault/registry'/kind/(record['id']+'.json')
                    if path.is_symlink():
                        raise ValueError('enrollment recovery file replaced')
                    try:
                        data = path.read_bytes()
                    except FileNotFoundError:
                        continue
                    if data != json.dumps(record, sort_keys=True).encode():
                        raise ValueError('enrollment recovery bytes changed; human reconciliation required')
                    path.unlink()
                    self._sync_directory(path.parent)
                db.execute("UPDATE enrollment_journal SET status='rolled-back' WHERE agent_id=?", (agent_id,))

    def facts(self):
        current = request(self.home, 'snapshot', actor='operator')
        from .cockpit_primary import read_native_registry
        if (not isinstance(current,dict) or not isinstance(current.get('host'),str)
                or not isinstance(current.get('state'),str) or not isinstance(current.get('sessions'),list)
                or any(not isinstance(r,dict) or not isinstance(r.get('id'),str) for r in current['sessions'])):
            raise ValueError('owner identity unavailable')
        db = sqlite3.connect((self.home / 'runtime/sessions.sqlite').as_uri() + '?mode=ro', uri=True)
        try:
            identity = db.execute('SELECT host,state,vault FROM identity').fetchall()
            expected = (current['host'], str((self.home/'events.jsonl').resolve()), str((self.home/'vault').resolve()))
            if identity != [expected] or current['state'] != expected[1]:
                raise ValueError('owner identity changed')
            native = db.execute('SELECT session,tool,conversation FROM native_bindings').fetchall()
        finally:
            db.close()
        rows = {r['id']: r for r in current['sessions']}
        sessions = []
        for sid, tool, conversation in native:
            row = rows.get(sid, {})
            observed = request(self.home, 'native', sid=sid, actor='operator')
            if tool != 'fixture' and row.get('status') == 'running' and row.get('pid') and observed == dict(session=sid, tool=tool, conversation=conversation):
                sessions.append(dict(session=sid, tool=tool, conversation=conversation, pid=row['pid'], host=current['host']))
        agents = []
        with closing(sqlite3.connect(self.path)) as pending_db:
            pending = {row[0] for row in pending_db.execute("SELECT agent_id FROM enrollment_journal WHERE status='prepared'")}
        for path in sorted((self.home/'vault/registry/agents').glob('*.json')):
            try:
                record = read_native_registry(self.home/'vault','agents',path.stem)
            except (OSError, ValueError,RecursionError):
                continue
            if not isinstance(record, dict):
                continue
            agent = record.get('id')
            if isinstance(agent, str) and agent in pending:
                continue  # Publication is not bindable until the signed audit commits.
            if not isinstance(agent, str) or not AGENT_ID_RE.fullmatch(agent) or path.stem != agent:
                continue
            runtime = record.get('runtime_id', '')
            machine = record.get('machine_id', '')
            harness = None
            if isinstance(runtime, str) and AGENT_ID_RE.fullmatch(runtime):
                try:
                    r = read_native_registry(self.home/'vault','runtimes',runtime)
                    if isinstance(r, dict) and r.get('id') == runtime:
                        harness = r.get('harness')
                except (OSError, ValueError,RecursionError):
                    pass
            machine_valid = False
            if isinstance(machine, str) and AGENT_ID_RE.fullmatch(machine):
                try:
                    machine_record = read_native_registry(self.home/'vault','machines',machine)
                    machine_valid = isinstance(machine_record, dict) and machine_record.get('id') == machine
                except (OSError, ValueError,RecursionError):
                    pass
            agents.append(dict(id=agent, display_name=record.get('display_name', agent), machine_id=machine, runtime_id=runtime, harness=harness,
                               machine_valid=machine_valid))
        return sessions, agents

    def signature(self, document, session='', revision=0):
        envelope = json.dumps([str(self.home.resolve()), session, revision, document])
        return hmac.new(self.key, envelope.encode(), hashlib.sha256).hexdigest()

    def read(self):
        sessions, agents = self.facts()
        with closing(sqlite3.connect(self.path)) as db, db:
            bindings = [dict(session=s, revision=r, **json.loads(d)) for s,r,d,sig in db.execute('SELECT * FROM bindings') if hmac.compare_digest(sig,self.signature(d,s,r))]
        return dict(sessions=sessions, agents=agents, bindings=bindings)

    def enroll(self, payload):
        """Explicit local human registration, not discovery, launch or authentication.

        Create fresh registry identities with no permissions. The separate binding
        confirmation is still required. Existing agent/runtime records never change.
        """
        import uuid
        from .locks import vault_lock
        self.primary.registry._identity(self.primary.authorization, human=True)
        required = {'session', 'host', 'tool', 'conversation', 'pid', 'display_name'}
        if not isinstance(payload, dict) or set(payload) != required:
            raise ValueError('exact observed facts and explicit display name required')
        name = payload['display_name']
        if (not isinstance(name, str) or not name.strip() or name != name.strip()
                or len(name) > 128 or any(unicodedata.category(c).startswith('C') for c in name)):
            raise ValueError('canonical nonempty display name required')
        facts = {k: payload[k] for k in required - {'display_name'}}
        if type(facts['pid']) is not int:
            raise ValueError('integer PID required')
        vault = self.home / 'vault'
        made = []
        deadline = time.monotonic() + 5
        with vault_lock(vault, deadline=deadline), closing(sqlite3.connect(self.path, timeout=check_deadline(deadline) or 0)) as db, db:
            from .replica_authority import assert_mutation_authority
            assert_mutation_authority(self.primary.registry.owner.vault)
            db.execute('PRAGMA busy_timeout=' + str(int((check_deadline(deadline) or 0) * 1000)))
            db.execute('BEGIN IMMEDIATE')
            sessions, _ = self.facts()
            if facts not in sessions:
                raise ValueError('native facts changed')
            if db.execute('SELECT 1 FROM bindings WHERE session=?', (facts['session'],)).fetchone():
                raise ValueError('session already bound')
            for raw, in db.execute('SELECT document FROM audit'):
                prior = json.loads(raw)
                if prior.get('operation') == 'enroll' and prior.get('facts', {}).get('session') == facts['session']:
                    raise ValueError('session already enrolled; select its existing identity')
            with closing(sqlite3.connect((self.home/'runtime/sessions.sqlite').as_uri()+'?mode=ro', uri=True)) as native:
                if native.execute('SELECT 1 FROM native_organizers WHERE session=?', (facts['session'],)).fetchone():
                    raise ValueError('session already has owner identity')
            machine = facts['host']
            if not isinstance(machine, str) or not AGENT_ID_RE.fullmatch(machine):
                raise ValueError('invalid owner machine identity')
            machine_record = json.loads((vault/'registry/machines'/(machine+'.json')).read_text())
            if not isinstance(machine_record, dict) or machine_record.get('id') != machine:
                raise ValueError('existing registered machine required')
            for path in (vault/'registry/agents').glob('*.json'):
                record = json.loads(path.read_text())
                if isinstance(record, dict) and str(record.get('display_name', '')).casefold() == name.casefold():
                    raise ValueError('display name already registered')
            agent_id, runtime_id = 'local-' + uuid.uuid4().hex, 'local-' + uuid.uuid4().hex
            agent = dict(id=agent_id, display_name=name, machine_id=machine,
                         runtime_id=runtime_id, scopes=[], registration='explicit-local-human')
            runtime = dict(id=runtime_id, display_name=name + ' runtime', harness=facts['tool'])
            document = json.dumps(dict(operation='enroll', agent=agent, runtime=runtime, facts=facts), sort_keys=True)
            db.execute('INSERT INTO enrollment_journal VALUES(?,?,?,?)',
                (agent_id, document, self.signature(document), 'prepared'))
            db.commit()  # Durable recovery intent precedes every registry write.
            from .replica_authority import assert_mutation_authority
            assert_mutation_authority(self.primary.registry.owner.vault)
            db.execute('PRAGMA busy_timeout=' + str(int((check_deadline(deadline) or 0) * 1000)))
            db.execute('BEGIN IMMEDIATE')
            try:
                for kind, record in (('runtimes', runtime), ('agents', agent)):
                    path = vault/'registry'/kind/(record['id']+'.json')
                    fd = safe_open.open_file(path, write=True, create=True, exclusive=True, mode=0o600)
                    made.append(path)
                    with os.fdopen(fd, 'w', newline="\n") as stream:
                        json.dump(record, stream, sort_keys=True)
                        stream.flush()
                        os.fsync(stream.fileno())
                    self._sync_directory(path.parent)
                db.execute('INSERT INTO audit(actor,document,signature) VALUES(?,?,?)',
                           ('operator', document, self.signature(document)))
                db.execute("UPDATE enrollment_journal SET status='completed' WHERE agent_id=?", (agent_id,))
                db.commit()
            except BaseException:
                db.rollback()
                for path in reversed(made):
                    path.unlink()
                    self._sync_directory(path.parent)
                db.execute("UPDATE enrollment_journal SET status='rolled-back' WHERE agent_id=?", (agent_id,))
                db.commit()
                raise
        return dict(agent=agent, binding_required=True)

    def bind(self, payload):
        # Never hold primary's write lock during owner socket I/O. Election and
        # binding still commit atomically after the exact facts are validated.
        self.primary.registry._identity(self.primary.authorization, human=True)
        deadline = time.monotonic() + 5
        with vault_lock(self.home/'vault', deadline=deadline):
            from .replica_authority import assert_mutation_authority
            assert_mutation_authority(self.primary.registry.owner.vault)
            observed = self.facts()
            with self.primary.registry._transaction():
                self._bind(payload, observed=observed)
        return self.read()

    def _bind(self, payload, *, observed):
        self.primary.registry._identity(self.primary.authorization, human=True)
        if (not isinstance(payload, dict) or set(payload) != {'session','agent_id','host','tool','conversation','pid','revision'}
                or type(payload['revision']) is not int or not 0 <= payload['revision'] <= 9007199254740991
                or type(payload['pid']) is not int):
            raise ValueError('exact binding facts and revision required')
        sessions, agents = observed
        facts = {k:payload[k] for k in ('session','host','tool','conversation','pid')}
        if facts not in sessions:
            raise ValueError('native session facts changed')
        agent = next((a for a in agents if a['id'] == payload['agent_id']), None)
        if not agent or not agent['machine_valid'] or agent['machine_id'] != facts['host'] or agent['harness'] != facts['tool']:
            raise ValueError('registry host/runtime identity mismatch')
        db = sqlite3.connect((self.home/'runtime/sessions.sqlite').as_uri()+'?mode=ro',uri=True)
        try:
            conflicts = db.execute('SELECT agent,session FROM native_organizers WHERE agent=? OR session=?',
                                   (payload['agent_id'],payload['session'])).fetchall()
            if any(row != (payload['agent_id'],payload['session']) for row in conflicts):
                raise ValueError('existing owner identity conflict')
        finally:
            db.close()
        document = json.dumps({k:v for k,v in payload.items() if k not in ('session','revision')}, sort_keys=True)
        db = self.primary.registry.db
        for sid, raw in db.execute('SELECT session,document FROM human_bindings.bindings WHERE session != ?', (payload['session'],)):
            if json.loads(raw)['agent_id'] == payload['agent_id']:
                raise ValueError('agent already bound to another conversation')
        row = db.execute('SELECT revision,document FROM human_bindings.bindings WHERE session=?',(payload['session'],)).fetchone()
        if payload['revision'] != (row[0] if row else 0):
            raise ValueError('stale binding revision')
        if row and json.loads(row[1])['agent_id'] != payload['agent_id']:
            raise ValueError('session already bound; rebind forbidden')
        revision = payload['revision'] + 1
        db.execute('INSERT OR REPLACE INTO human_bindings.bindings VALUES(?,?,?,?)',(payload['session'], revision, document,self.signature(document,payload['session'],revision)))
        audit = json.dumps(dict(payload, revision=revision),sort_keys=True)
        db.execute('INSERT INTO human_bindings.audit(actor,document,signature) VALUES(?,?,?)',('operator',audit,self.signature(audit)))
        self.primary.registry._elect_locked(payload['agent_id'], actor='human-binding',
            reason='first validated human binding')

    def connected(self):
        state = self.read()
        result=[]
        for binding in state['bindings']:
            facts={k:binding[k] for k in ('session','host','tool','conversation','pid')}
            agent=next((a for a in state['agents'] if a['id']==binding['agent_id']),None)
            if facts in state['sessions'] and agent and agent['machine_valid'] and agent['machine_id']==facts['host'] and agent['harness']==facts['tool']:
                result.append(agent['id'])
        return result
