"""Optional SQLite persistence for the existing organizer policy, not new roles.

Every policy operation reloads provisioned state under BEGIN IMMEDIATE. Identity
objects remain instance-local authenticated handles; serialized principal claims
never become handles. Durable decisions are ordered without loading audit history
on every authorization. No endpoint or OS/root privilege is provisioned here.
"""
from dataclasses import asdict
from contextlib import contextmanager
import hashlib,json,math,os,secrets,sqlite3,threading,time
from pathlib import Path


def private_database(path):
    from .machine_pairing_transport import private_directory
    path=Path(path);private_directory(path.parent)
    fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        info=os.fstat(fd)
        import stat
        if info.st_uid!=os.getuid() or info.st_mode&0o077 or not stat.S_ISREG(info.st_mode):raise ValueError('private owned regular database required')
    finally:os.close(fd)
    db=sqlite3.connect(path,check_same_thread=False)
    db.execute('PRAGMA journal_mode=DELETE');db.execute('PRAGMA synchronous=FULL')
    return db


class Audit:
    def __init__(self,db):self.db=db
    def __len__(self):return self.db.execute('SELECT COALESCE(MAX(sequence),0) FROM organizer_decisions').fetchone()[0]
    def append(self,decision):self.db.execute('INSERT INTO organizer_decisions VALUES(?,?)',(decision.sequence,json.dumps(asdict(decision))))
    def __iter__(self):
        from .organizer_authority import AuthorityDecision
        for row in self.db.execute('SELECT record FROM organizer_decisions ORDER BY sequence'):
            record=json.loads(row[0]);record['authority_chain']=tuple(record['authority_chain']);yield AuthorityDecision(**record)


class PolicyStorage:
    def __init__(self,policy,path):
        self.policy=policy;self.path=Path(path).resolve();self.db=private_database(self.path);self.thread=threading.RLock();self.depth=0
        self.lock_path=Path(str(self.path)+'.policy.lock');self.file_lock=None
        self.db.executescript('''CREATE TABLE IF NOT EXISTS organizer_state (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1), record TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS organizer_decisions(sequence INTEGER PRIMARY KEY,record TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS organizer_fence_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1),authority_id TEXT NOT NULL,generation INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS organizer_effect_tickets(token_hash TEXT PRIMARY KEY,record TEXT NOT NULL,expires REAL NOT NULL,generation INTEGER NOT NULL,status TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS organizer_effect_destinations(token_hash TEXT PRIMARY KEY,receiver TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS organizer_remote_permits(permit_id TEXT PRIMARY KEY,receiver TEXT NOT NULL,record TEXT NOT NULL,status TEXT NOT NULL);''')
        self.db.execute("INSERT OR IGNORE INTO organizer_state VALUES(1,?)",(json.dumps(dict(identities={},organizers=[],machines={},agents={})),));self.db.commit()
        self.db.execute('INSERT OR IGNORE INTO organizer_fence_state VALUES(1,?,0)',(secrets.token_hex(32),));self.db.commit()
        policy._audit=Audit(self.db)

    def __enter__(self):
        from .replica_authority import assert_bound_authority
        assert_bound_authority()
        self.thread.acquire()
        try:
            if not self.depth:
                from .locks import exclusive_lock
                self.file_lock=exclusive_lock(self.lock_path);self.file_lock.__enter__()
                self.db.execute('BEGIN IMMEDIATE');self.load()
            self.depth+=1
            return self
        except BaseException:
            self.db.rollback()
            if self.file_lock is not None and not self.depth:
                self.file_lock.__exit__(None,None,None);self.file_lock=None
            self.thread.release();raise

    def __exit__(self,kind,value,tb):
        self.depth-=1
        try:
            if not self.depth:
                if kind:self.db.rollback()
                else:
                    try:self.save();self.db.commit()
                    except BaseException:self.db.rollback();raise
        finally:
            if not self.depth and self.file_lock is not None:
                self.file_lock.__exit__(None,None,None);self.file_lock=None
            self.thread.release()

    def checkpoint(self):
        """Durable decision before effects while retaining the process-shared lock.

        Every governed policy operation takes that lock. Releasing/reopening the
        SQLite transaction cannot let another governed instance revoke/reassign
        authority in the middle of the bounded dispatch.
        """
        if not self.depth or self.file_lock is None:raise RuntimeError('policy guard required')
        self.save();self.db.commit()
        self.db.execute('BEGIN IMMEDIATE');self.load()

    def load(self):
        from .organizer_authority import Identity
        value=json.loads(self.db.execute('SELECT record FROM organizer_state WHERE singleton=1').fetchone()[0]);p=self.policy
        p._identities={key:(p._identities[key] if key in p._identities and p._identities[key].kind==kind else Identity(key,kind)) for key,kind in value['identities'].items()}
        p._organizers=set(value['organizers']);p._machines=value['machines'];p._agents={k:tuple(v) for k,v in value['agents'].items()}
        p._execution_modes=value.get('execution_modes',{})

    def save(self):
        p=self.policy
        value=dict(identities={key:i.kind for key,i in p._identities.items()},organizers=sorted(p._organizers),machines=p._machines,agents=p._agents,execution_modes=p._execution_modes)
        self.db.execute('UPDATE organizer_state SET record=? WHERE singleton=1',(json.dumps(value,sort_keys=True),))

    def issue_effect_ticket(self,plan,expires,receiver=None):
        """Trusted dispatch only; persist an exact, expiring, single-use effect."""
        if not self.depth:raise RuntimeError('policy guard required')
        if type(expires) not in (int,float) or not math.isfinite(expires) or expires<=time.time():
            raise PermissionError('original delegation consent expired')
        decision=plan['decision'];actor=self.policy.identity_handle(decision['initiating_organizer'])
        executor=self.policy.identity_handle(plan['executing_agent']) if plan['executing_agent'] is not None else None
        if not self.policy.authorize(actor,operation=plan['operation'],machine=plan['machine'],executing_agent=executor).allowed:
            raise PermissionError('delegation authority changed')
        self.save()
        generation=self.db.execute('SELECT generation FROM organizer_fence_state WHERE singleton=1').fetchone()[0]
        authority=self.fence_identity()
        token=secrets.token_hex(32)
        self.db.execute("INSERT INTO organizer_effect_tickets VALUES(?,?,?,?,'issued')",
                        (hashlib.sha256(token.encode()).hexdigest(),_canonical(plan),expires,generation))
        if receiver is not None:
            from .remote_effect_fence import validate_binding
            self.db.execute('INSERT INTO organizer_effect_destinations VALUES(?,?)',(hashlib.sha256(token.encode()).hexdigest(),_canonical(validate_binding(receiver))))
        self.checkpoint()
        return dict(authority_id=authority,token=token)

    def fence_identity(self):
        # A copied database retains its UUID and tickets but does not share the
        # revocation lock. Bind the advertised fence to this host boot and exact
        # canonical database incarnation; copies/restore/reboot need reprovision.
        from .cockpit_restart import boot_id
        info=self.path.stat()
        identifier=self.db.execute('SELECT authority_id FROM organizer_fence_state WHERE singleton=1').fetchone()[0]
        return hashlib.sha256(_canonical([identifier,boot_id(),str(self.path),info.st_dev,info.st_ino]).encode()).hexdigest()

    def close(self):
        with self.thread:
            if self.depth:raise RuntimeError('policy operation active')
            self.db.close()


def _canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'))


def _existing_authority(database):
    # Never bootstrap policy from a request or accept a request-provided path.
    if database is None or not Path(database).is_absolute() or not Path(database).is_file() or Path(database).is_symlink():
        raise PermissionError('explicit existing trusted organizer fence database required')
    from .organizer_authority import OrganizerAuthority
    return OrganizerAuthority(database=database)


def authority_fence_identity(database):
    policy=_existing_authority(database)
    try:
        with policy._lock:
            return policy._backend.fence_identity()
    finally:policy.close()


def _ticket_record(policy,ticket):
    import re
    if (type(ticket) is not dict or set(ticket)!={'authority_id','token'}
            or any(not isinstance(v,str) or not re.fullmatch('[a-f0-9]{64}',v) for v in ticket.values())):
        raise PermissionError('closed authenticated effect ticket required')
    db=policy._backend.db
    generation=db.execute('SELECT generation FROM organizer_fence_state WHERE singleton=1').fetchone()[0]
    if ticket['authority_id']!=policy._backend.fence_identity():raise PermissionError('foreign organizer fence')
    token_hash=hashlib.sha256(ticket['token'].encode()).hexdigest()
    row=db.execute('SELECT record,expires,generation,status FROM organizer_effect_tickets WHERE token_hash=?',(token_hash,)).fetchone()
    if row is None or row[2]!=generation or row[3]!='issued' or row[1]<=time.time():
        raise PermissionError('unknown, revoked, expired or attempted organizer effect')
    return json.loads(row[0]),row[1],token_hash


def validate_delegated_effect(database,ticket,plan):
    """Leaf preflight only. The owner must still hold the final effect guard."""
    policy=_existing_authority(database)
    try:
        with policy._lock:
            stored,expires,_=_ticket_record(policy,ticket)
            if _canonical(stored)!=_canonical(plan):raise PermissionError('exact organizer attempt mismatch')
            return expires
    finally:policy.close()


@contextmanager
def delegated_effect_guard(authority_database,ticket,*,attempt,machine,agent,environment,root_acknowledged):
    """Owner-only fence spanning final admission/fork, including RPC timeouts.

    The database is trusted owner configuration, never serialized input. The
    portable policy lock is also held by every revocation. Consuming the ticket
    precedes effects; an exception remains uncertain and cannot replay.

    Revocation linearizes at its generation update under this same lock. If it
    wins first, _ticket_record rejects the old generation. Otherwise this guard
    consumes admission and excludes revocation through the owner's final
    check/fork/exec acknowledgement/publication, not through process lifetime.
    Sender timeout is neither cancellation nor a successful revocation. Kernel
    or storage stalls inside this guard are not hard-cancellable by transport.
    """
    policy=_existing_authority(authority_database)
    try:
        with policy._lock:
            plan,expires,token_hash=_ticket_record(policy,ticket)
            if (plan['request_id'],plan['machine'],plan['executing_agent'],plan['environment'],plan['root_acknowledged'])!=(attempt,machine,agent,environment,root_acknowledged):
                raise PermissionError('owner effect differs from exact organizer ticket')
            if type(root_acknowledged) is not bool or plan['operation']!='invoke_'+environment or environment=='root' and root_acknowledged is not True:
                raise PermissionError('independent explicit execution authority required')
            policy._backend.db.execute("UPDATE organizer_effect_tickets SET status='admitted' WHERE token_hash=?",(token_hash,))
            policy._backend.checkpoint()
            def check():
                from .public_onboarding_api import assert_request_active
                from .reviewed_actions import assert_consent_active
                assert_request_active();assert_consent_active(expires)
                if expires<=time.time():raise PermissionError('original delegation consent expired')
            check()
            yield check
    finally:policy.close()
