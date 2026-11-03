"""Deterministic human-invoked bootstrap export and exact signed install receipts.

No SSH, package installation, provider, runtime, root escalation or network is
executed here. Remote confirmation proves the enrolled key signed the exact plan;
a MAIN approval is a separate trusted integrator decision, never a request field.
A receipt establishes attested installed hashes, not runtime health or permission.
"""
import argparse,base64,hashlib,json,re,time
from pathlib import Path
from .machine_pairing import MachineIdentity
from .organizer_durable import private_database

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def sha(value):return hashlib.sha256(canonical(value)).hexdigest()
def make_plan(*,machine,identity,platform,package_sha256,native_sha256,capabilities,nonce,expires):
    if not isinstance(identity,MachineIdentity) or not isinstance(machine,str) or not re.fullmatch('[a-z0-9-]{1,64}',machine):raise ValueError('exact machine identity required')
    if platform not in ('linux-x86_64','darwin-arm64'):raise ValueError('no approved platform artifact/descriptor execution support')
    if any(not isinstance(v,str) or not re.fullmatch('[a-f0-9]{64}',v) for v in (package_sha256,native_sha256)) or not re.fullmatch('[a-f0-9]{32}',nonce):raise ValueError('exact digests and one-time challenge required')
    if not capabilities or set(capabilities)-{'mouse-existing','onboarding-v1'} or len(set(capabilities))!=len(capabilities):raise ValueError('closed artifact capability selection required')
    if type(expires) not in (int,float) or not time.time()<expires<=time.time()+3600:raise ValueError('bounded future plan expiry required')
    return dict(schema=1,machine=machine,fingerprint=identity.fingerprint,public_key=identity.public_key,
        platform=platform,package_sha256=package_sha256,native_sha256=native_sha256,capabilities=sorted(capabilities),nonce=nonce,expires=expires,
        commands=[['python3','-m','arvyx_control.native_install','--binary','./arvyx','--receipt','./native-provenance.json','--destination','./arvyx-install','--require-capability',('onboarding-v1' if 'onboarding-v1' in capabilities else 'mouse-existing')]],
        prerequisites=['Explicit remote human invocation','Independently approved exact native bytes and capabilities','Existing verified Python package matching package_sha256','Separate MAIN approval and authenticated runtime registration'],
        starts_runtime=False)

def sign_receipt(plan,key,*,remote_confirmed,installed_package_sha256,installed_native_sha256):
    if remote_confirmed is not True:raise PermissionError('fresh explicit remote human confirmation required')
    receipt=dict(schema=1,plan_sha256=sha(plan),nonce=plan['nonce'],machine=plan['machine'],fingerprint=plan['fingerprint'],
        remote_confirmed=True,installed_package_sha256=installed_package_sha256,installed_native_sha256=installed_native_sha256,
        platform=plan['platform'],capabilities=plan['capabilities'])
    return dict(receipt,signature=base64.b64encode(key.sign(canonical(receipt))).decode())

class BootstrapStore:
    def __init__(self,path):
        self.db=private_database(path);self.db.execute('CREATE TABLE IF NOT EXISTS bootstrap_plans(digest TEXT PRIMARY KEY,nonce TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,status TEXT NOT NULL,receipt TEXT)');self.db.commit()
        from .authority_attempts import migrate_attempts
        import secrets
        migrate_attempts(self.db,secrets.token_hex(16))
    def close(self):self.db.close()
    def register(self,plan):
        if plan['expires']<=time.time():raise ValueError('expired bootstrap plan')
        with self.db:self.db.execute('INSERT INTO bootstrap_plans VALUES(?,?,?,?,NULL)',(sha(plan),plan['nonce'],canonical(plan).decode(),'prepared'))
        return sha(plan)
    def accept(self,plan,receipt,*,main_approved):
        if main_approved is not True:raise PermissionError('independent MAIN decision required')
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        expected=dict(schema=1,plan_sha256=sha(plan),nonce=plan['nonce'],machine=plan['machine'],fingerprint=plan['fingerprint'],remote_confirmed=True,
            installed_package_sha256=plan['package_sha256'],installed_native_sha256=plan['native_sha256'],platform=plan['platform'],capabilities=plan['capabilities'])
        if set(receipt)!=(set(expected)|{'signature'}) or {k:v for k,v in receipt.items() if k!='signature'}!=expected:raise PermissionError('receipt plan/identity/artifact mismatch')
        try:Ed25519PublicKey.from_public_bytes(base64.b64decode(plan['public_key'],validate=True)).verify(base64.b64decode(receipt['signature'],validate=True),canonical(expected))
        except (InvalidSignature,ValueError,TypeError):raise PermissionError('remote receipt signature invalid') from None
        self.db.execute('BEGIN IMMEDIATE')
        try:
            row=self.db.execute('SELECT payload,status FROM bootstrap_plans WHERE digest=?',(sha(plan),)).fetchone()
            if not row or row[0]!=canonical(plan).decode() or row[1]!='prepared' or plan['expires']<=time.time():raise ValueError('unknown, expired or consumed bootstrap plan')
            self.db.execute("UPDATE bootstrap_plans SET status='completed',receipt=? WHERE digest=?",(canonical(receipt).decode(),sha(plan)));self.db.commit()
        except BaseException:self.db.rollback();raise
        return dict(verified_installation_receipt=True,runtime_authorized=False,machine=plan['machine'],fingerprint=plan['fingerprint'])

def export_plan(plan,destination):
    from .native_install import write
    destination=Path(destination)
    write(destination,canonical(plan)+b'\n',0o600)
    return dict(plan_sha256=sha(plan),human_invocation_required=True,commands=plan['commands'])

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--plan',type=Path,required=True);parser.add_argument('--export',type=Path,required=True)
    args=parser.parse_args(argv);value=json.loads(args.plan.read_text())
    identity=MachineIdentity(value.pop('name'),value.pop('public_key'))
    print(json.dumps(export_plan(make_plan(identity=identity,**value),args.export)))

if __name__=='__main__':main()
