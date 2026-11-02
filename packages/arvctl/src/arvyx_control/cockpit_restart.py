"""Single-use pre-authorized Hermes restart across a verified kernel reboot.

Same-boot owner crashes stay ambiguous. A restart lease never renews consent,
changes conversation, replays staged input or clears uncertain native cleanup on
the same kernel boot. The existing JsonOperator grammar and process reservations
remain authoritative. Runtime starts only when this explicit consumer is invoked.
"""
import hashlib,json,re,time,uuid,os
from pathlib import Path
from .cockpit_terminal_runner import JsonOperator

def boot_id():
    value=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if not re.fullmatch('[a-f0-9-]{36}',value):raise ValueError('kernel reboot proof unavailable')
    return value

def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'))
def schema(owner):
    owner.db.execute('''CREATE TABLE IF NOT EXISTS native_restart_leases (
        id TEXT PRIMARY KEY,payload TEXT NOT NULL,issued REAL NOT NULL,expires REAL NOT NULL,
        status TEXT NOT NULL,result TEXT)''')
    owner.db.execute('CREATE TABLE IF NOT EXISTS delegation_expiries(session TEXT PRIMARY KEY,expires REAL NOT NULL,incarnation TEXT NOT NULL)')

def snapshot(owner,sid):
    if os.geteuid()==0:raise PermissionError('Hermes reboot continuation currently requires the same unprivileged host account')
    binding=owner.native(sid,actor='operator');row=owner._get(sid)
    delegation=owner.delegation(sid,actor='operator')
    if not binding or binding['tool']!='hermes' or not delegation or delegation['pending'] is not None:
        raise PermissionError('exact idle-input Hermes delegation required')
    if owner.db.execute('SELECT 1 FROM staged_input WHERE session=?',(sid,)).fetchone():raise PermissionError('unsettled native input requires human reconciliation')
    runtime=owner.native_runtimes.get('hermes');driver=owner.operator_drivers.get(delegation['operator'])
    if runtime is None or type(driver) is not JsonOperator:raise PermissionError('exact configured Hermes runtime and JsonOperator grammar required')
    runtime.plan(binding['conversation'],row['workspace'])
    return dict(session=sid,binding=binding,workspace=row['workspace'],profile=str(runtime.home),profile_identity=list(runtime.profile.identity),profile_home_identity=list(runtime.profile.home_identity),
        native_executable_sha256=hashlib.sha256(runtime.executable.read_bytes()).hexdigest(),
        driver_argv=driver.argv,driver_cwd=str(driver.cwd),driver_sha256=hashlib.sha256(Path(driver.argv[0]).read_bytes()).hexdigest(),
        effective_uid=os.geteuid(),operator=delegation['operator'],goal=delegation['goal'],limits=delegation['limits'],generation=delegation['generation'],
        epoch=owner.db.execute('SELECT epoch FROM lifecycle_policy WHERE singleton=1').fetchone()[0],grammar='json-operator-v1')

def grant(owner,sid,*,actor,confirmed=False,allow_provider_restart=False,ttl=300):
    owner._human(actor)
    if confirmed is not True or allow_provider_restart is not True or type(ttl) is not int or not 1<=ttl<=3600:
        raise PermissionError('explicit bounded reboot/provider restart consent required')
    with owner.lock:
        schema(owner);saved=snapshot(owner,sid)
        if owner._get(sid)['status']!='running' or owner.delegation(sid,actor='operator')['status']!='active':raise PermissionError('active exact native delegation required')
        saved.update(boot=boot_id(),machine=owner.host);identifier=uuid.uuid4().hex;now=time.time()
        owner.db.execute("INSERT INTO native_restart_leases VALUES(?,?,?,?,'prepared',NULL)",(identifier,encoded(saved),now,now+ttl));owner.db.commit()
        return dict(id=identifier,expires_at=now+ttl,session=sid,grammar='json-operator-v1',consent_renews=False)

class RestartAdmission:
    """In-process guard carrying the original single-use reboot authority."""
    def __init__(self,owner,identifier,saved,issued,expires):
        self.owner=owner;self.identifier=identifier;self.saved=saved;self.sid=saved['session']
        self.issued=issued;self.expires=expires;self.incarnation=owner.incarnation;self.launch_prepared=False

    def validate_identity(self):
        owner=self.owner
        row=owner.db.execute('SELECT payload,issued,expires,status FROM native_restart_leases WHERE id=?',(self.identifier,)).fetchone()
        if (not row or row[3]!='ambiguous' or row[1]!=self.issued or row[2]!=self.expires or json.loads(row[0])!=self.saved
                or owner.incarnation!=self.incarnation or boot_id()==self.saved['boot'] or owner.host!=self.saved['machine']):
            raise PermissionError('exact reboot restart authority changed')
        current=snapshot(owner,self.sid)
        expected={k:v for k,v in self.saved.items() if k not in ('boot','machine')}
        if self.launch_prepared:expected['generation']+=1
        if current!=expected:
            raise PermissionError('native/profile/driver/delegation/revocation identity changed')
        if owner.delegation(self.sid,actor='operator')['status']!='paused':raise PermissionError('restart delegation changed')

    def __call__(self):
        if not self.issued<=time.time()<self.expires:raise PermissionError('restart lease expired before process admission')
        self.validate_identity()
        if not self.issued<=time.time()<self.expires:raise PermissionError('restart lease expired during validation')


def resume(owner,identifier,*,actor):
    owner._human(actor)
    with owner.lock:
        schema(owner)
        found=owner.db.execute('SELECT payload,issued,expires,status FROM native_restart_leases WHERE id=?',(identifier,)).fetchone()
        now=time.time()
        if not found or found[3]!='prepared' or not found[1]<=now<found[2]:raise PermissionError('expired, unknown or consumed restart lease')
        saved=json.loads(found[0]);sid=saved['session']
        if 'profile_home_identity' not in saved:raise PermissionError('restart lease lacks original profile directory binding; review again')
        if boot_id()==saved['boot'] or saved['machine']!=owner.host:raise PermissionError('same-boot cleanup is uncertain; verified kernel reboot required')
        if owner._get(sid)['status']!='stopped':raise PermissionError('restart requires the exact stopped native session')
        current=snapshot(owner,sid)
        if current!={k:v for k,v in saved.items() if k not in ('boot','machine')}:
            raise PermissionError('native/profile/driver/delegation/revocation identity changed')
        if owner.delegation(sid,actor='operator')['status']!='paused':raise PermissionError('ambiguous or revoked delegation cannot restart')
        if not found[1]<=time.time()<found[2]:raise PermissionError('restart lease expired during validation')
        owner.db.execute("UPDATE native_restart_leases SET status='ambiguous' WHERE id=?",(identifier,));owner.db.commit()
        admission=RestartAdmission(owner,identifier,saved,found[1],found[2])
    # No outer owner lock crosses startup or pump retirement. Cleanup ownership
    # is replaced only at final, still-unexpired reboot admission in _start_locked.
    try:
        owner.start_native(sid,actor='operator',allow_provider=True,environment='host',_restart_admission=admission)
        with owner.lock:
            admission.validate_identity()
            if owner.native(sid,actor='operator')!=saved['binding']:raise PermissionError('native binding changed during restart')
            active=time.time()<found[2]
            owner.db.execute('INSERT OR REPLACE INTO delegation_expiries VALUES(?,?,?)',(sid,found[2],owner.incarnation))
            owner.db.execute('UPDATE delegations SET status=? WHERE session=?',('active' if active else 'paused',sid))
            outcome=dict(session=sid,conversation=saved['binding']['conversation'],owner_incarnation=owner.incarnation,
                         expires_at=found[2],status='active' if active else 'paused',input_replayed=False)
            owner.db.execute("UPDATE native_restart_leases SET status='completed',result=? WHERE id=?",(encoded(outcome),identifier));owner.db.commit()
            return outcome
    except BaseException:
        with owner.lock:owner.db.rollback()
        raise # The pre-effect ambiguous marker survives; it never replays.
