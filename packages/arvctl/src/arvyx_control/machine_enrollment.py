"""Explicit local enrollment provenance, separate from pilot registry records.

Same-UID human enrollment attests local ownership and records the exact public
machine record. It is not hardware attestation, provider auth or an organizer role.
A restored record or pilot name alone can never satisfy this provenance check.
"""
import argparse,hashlib,json,os,re,secrets,time
from pathlib import Path
from . import private_paths
from . import safe_open
from .native_install import write,sync
from .external_workspace import _read

def enroll(root,machine,*,confirmed=False):
    root=Path(root)
    if confirmed is not True or not re.fullmatch('[a-z0-9-]{1,64}',machine):raise ValueError('explicit machine identity and human confirmation required')
    if root.exists() or root.is_symlink():raise ValueError('new empty enrollment home required; pilot adoption is separate')
    from .external_workspace import _open_root
    with _open_root(root.parent) as parent:
        safe_open.mkdir_at(parent,root.name,0o700);safe_open.fsync_directory(parent)
    vault=root/'vault';private_paths.ensure_private_directory(vault,mode=0o700)
    machine_dir=vault/'registry'/'machines';machine_dir.mkdir(mode=0o700,parents=True)
    record=dict(id=machine,enrollment_kind='explicit-local-human',enrollment_id=secrets.token_hex(16))
    data=json.dumps(record,sort_keys=True).encode()
    write(machine_dir/(machine+'.json'),data,0o600)
    write(vault/'.arvyx-vault',b'arvyx-vault-format: 1\n',0o600)
    write(root/'events.jsonl',b'',0o600)
    runtime=root/'runtime';private_paths.ensure_private_directory(runtime,mode=0o700)
    provenance=dict(schema=1,machine=machine,record_sha256=hashlib.sha256(data).hexdigest(),uid=private_paths.current_user(),enrollment_id=record['enrollment_id'],kind='explicit-local-human',confirmed_at=time.time(),organizer=None)
    write(runtime/'operator.secret',(secrets.token_urlsafe(48)+'\n').encode(),0o600)
    write(runtime/'machine-enrollment.json',json.dumps(provenance,sort_keys=True).encode(),0o600)
    sync(machine_dir);sync(vault);sync(runtime);sync(root)
    return dict(machine=machine,enrolled=True,owner_started=False,organizer=None)

def verify(home,machine):
    home=Path(home)
    if not isinstance(machine,str) or not re.fullmatch('[a-z0-9-]{1,64}',machine):raise PermissionError('exact enrolled machine ID required')
    if (home/'pilot.json').exists():raise PermissionError('pilot identity requires separately reviewed explicit adoption')
    raw,_,_=_read(home,('runtime','machine-enrollment.json'),65536)
    record,_,_=_read(home,('vault','registry','machines',machine+'.json'),65536)
    provenance=json.loads(raw);identity=json.loads(record)
    if (provenance.get('schema')!=1 or provenance.get('kind')!='explicit-local-human' or provenance.get('machine')!=machine
            or provenance.get('uid')!=private_paths.current_user() or provenance.get('record_sha256')!=hashlib.sha256(record).hexdigest()
            or provenance.get('enrollment_id')!=identity.get('enrollment_id')):raise PermissionError('explicit local machine provenance mismatch')
    return provenance

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--home',type=Path,required=True);p.add_argument('--machine',required=True);p.add_argument('--confirm-local-enrollment',action='store_true')
    args=p.parse_args(argv);print(json.dumps(enroll(args.home,args.machine,confirmed=args.confirm_local_enrollment)))
if __name__=='__main__':main()
