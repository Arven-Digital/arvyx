"""Offline coordinated capture, preserving migration and quarantined restoration.

Topology is explicit operator configuration, never request input or discovery of
live databases. All owner/state locks must be held; every SQLite writer is fenced
for the cut. Filesystem producers must be offline; before/after inventories detect
observed changes but do not claim an atomic snapshot of hostile external writers.
Restoration is an inert candidate. Bearers are never copied or recreated, and no
native incarnation or pending consent can authorize effects after restoration.
"""
from contextlib import ExitStack
from dataclasses import dataclass
import argparse,fcntl,hashlib,json,os,sqlite3,stat
from pathlib import Path

ROLES=frozenset(('vault','journal','owner','primary','human_signatures','enrollment','profile_mappings','profile_tree','consents','pairing_identity','pairing_challenges','pairing_enrollment','organizer_policy','organizer_requests','remote_links','external_grants','external_work','bearer_authority'))
MAX_FILE=64*1024*1024
MAX_TOTAL=1024*1024*1024
FENCE='.arvyx-restored-candidate.json'

def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def digest(data):return hashlib.sha256(data).hexdigest()
def relative(value):
    if not isinstance(value,str) or not value or len(value)>4096 or '\\' in value or any(ord(c)<32 for c in value) or any(p in ('','.','..') for p in value.split('/')) or value.startswith('/'):
        raise ValueError('canonical relative topology path required')
    return value

def write(path,data):
    mkdir_durable(path.parent)
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
    sync(path.parent)

def sync(path):
    from .external_workspace import _open_root
    with _open_root(Path(path).absolute()) as fd:os.fsync(fd)

def mkdir_durable(path,*,exist_ok=True):
    """Publish each new ancestor name before publishing files below it."""
    from .external_workspace import _open_root
    path=Path(path).absolute();missing=[];ancestor=path
    while not ancestor.exists():
        if ancestor.is_symlink():raise ValueError('symlink destination refused')
        missing.append(ancestor);ancestor=ancestor.parent
    with _open_root(ancestor):pass
    if not missing and not exist_ok:raise FileExistsError(path)
    for directory in reversed(missing):
        directory.mkdir(mode=0o700)
        sync(directory);sync(directory.parent)
    # Existence cannot prove a previous attempt's namespace barrier succeeded.
    for directory in reversed([path,*path.parents]):sync(directory)

def sync_tree(root):
    # Includes empty directories and SQLite backup output before the completion
    # marker can become visible. Never traverse a symlink destination.
    for parent,_,_ in os.walk(root,topdown=False,followlinks=False):sync(Path(parent))

@dataclass
class Topology:
    root: Path
    vault: str
    roles: dict
    locks: list
    def validate(self):
        from .external_workspace import _open_root
        self.root=Path(self.root)
        with _open_root(self.root):pass
        if set(self.roles)!=ROLES or not self.locks:raise ValueError('every composition role and all owner/state locks must be explicitly classified')
        relative(self.vault)
        for paths in self.roles.values():
            if not isinstance(paths,list):raise ValueError('explicit role paths required; [] means absent')
            for p in paths:relative(p)
        for p in self.locks:relative(p)
        all_paths=[p for role,paths in self.roles.items() if role!='bearer_authority' for p in paths]
        for secret in self.roles['bearer_authority']:
            if any(secret==p or secret.startswith(p+'/') or p.startswith(secret+'/') for p in all_paths):
                raise ValueError('bearer authority must be separately classified outside captured trees')
        mandatory={self.vault+'/.arvyx/vault.lock'}
        for owner_path in self.roles['owner']:
            with sqlite3.connect((self.root/owner_path).as_uri()+'?mode=ro',uri=True) as db:
                try:identity=db.execute('SELECT state,vault FROM identity').fetchall()
                except sqlite3.Error:raise ValueError('exact native owner identity schema required') from None
            if len(identity)!=1:raise ValueError('one exact owner authority binding required')
            state,vault=map(Path,identity[0])
            if vault!=self.root/self.vault or not state.is_relative_to(self.root):raise ValueError('owner authority outside configured composition')
            state_name=state.relative_to(self.root).as_posix()
            if not any(state_name==p or state_name.startswith(p+'/') for p in self.roles['journal']):
                raise ValueError('exact owner control state must be included in the journal role')
            mandatory.update((state_name+'.lock',state_name+'.cockpit-owner.lock'))
        if not mandatory<=set(self.locks):raise ValueError('mandatory owner/state/vault quiescence locks missing')


def completed_forget_links(t):
    """Exact completed witnesses only; never relax the external export reader."""
    from .forget_guard import assert_copyable_forget_operations,_read_regular_nofollow
    from .forget import _intent_stage
    from .paths import resolve_under
    vault=t.root/t.vault;assert_copyable_forget_operations(vault);result={}
    paths=list((vault/'.arvyx/forget-operations').glob('*.intent.json'))
    if len(paths)>10000:raise ValueError('forget witness inventory budget exceeded')
    for path in paths:
        record=json.loads(_read_regular_nofollow(path,vault));receipt=path.with_name(path.name.removesuffix('.intent.json')+'.json')
        if not receipt.exists():raise ValueError('unfinished forget witness')
        outcome=record['result']
        if outcome['status']!='forgotten':continue
        final=resolve_under(vault,*outcome['archive_path'].split('/'));stage=_intent_stage(vault,final,record)
        if not stage.exists():continue # no hard-link exception required
        a=final.lstat();b=stage.lstat()
        if stat.S_ISREG(a.st_mode) and stat.S_ISREG(b.st_mode) and a.st_nlink==b.st_nlink==1:
            # Completed receipt validation above makes the old inode witness
            # inert. Restores intentionally materialize independent files;
            # accept only the exact archived bytes, through the strict reader.
            from .external_workspace import _read
            for entry in (stage,final):
                data,_,_=_read(t.root,tuple(entry.relative_to(t.root).parts),MAX_FILE)
                if digest(data)!=outcome['content_sha256']:
                    raise ValueError('completed forget materialization content conflict')
            continue
        if (not stat.S_ISREG(a.st_mode) or not stat.S_ISREG(b.st_mode) or a.st_nlink!=2 or b.st_nlink!=2
                or (a.st_dev,a.st_ino)!=(b.st_dev,b.st_ino) or (a.st_dev,a.st_ino)!=(record['device'],record['inode'])):
            raise ValueError('completed forget witness inode conflict')
        for entry in (stage,final):
            result[entry.relative_to(t.root).as_posix()]=(a.st_dev,a.st_ino,outcome['content_sha256'])
    return result


def composition_read(t,name,proofs):
    from .external_workspace import _read,_open_root,_identity
    proof=proofs.get(name)
    if proof is None:return _read(t.root,tuple(name.split('/')),MAX_FILE)
    # Materialize a known completed archive/witness pair into independent files.
    # Pending intents and unrelated extra links remain uncopyable.
    path=t.root/name
    with _open_root(path.parent) as parent:
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        try:
            info=os.fstat(fd);identity=_identity(info)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=2 or (info.st_dev,info.st_ino)!=proof[:2] or info.st_size>MAX_FILE:
                raise ValueError('completed forget witness replaced')
            chunks=[];size=0
            while True:
                chunk=os.read(fd,min(65536,MAX_FILE-size+1))
                if not chunk:break
                chunks.append(chunk);size+=len(chunk)
                if size>MAX_FILE:raise ValueError('forget witness byte budget exceeded')
            data=b''.join(chunks)
            if (digest(data)!=proof[2] or size!=info.st_size or _identity(os.fstat(fd))!=identity
                    or _identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False))!=identity):
                raise ValueError('completed forget witness changed')
        finally:os.close(fd)
    return data,identity,None


def inventory(t):
    from .external_workspace import _read,_open_root,_open_file
    files={};total=0;candidates=set();explicit=set();proofs=completed_forget_links(t)
    for role,paths in sorted(t.roles.items()):
        if role=='bearer_authority':continue
        for value in paths:
            path=t.root/value
            # Reject symlinks even when their target is absent.
            if path.is_symlink():raise ValueError('symlink topology refused')
            if not path.exists():raise ValueError('declared topology entry absent: '+value)
            entries=[path]
            if path.is_dir():
                entries=[]
                for parent,dirs,names in os.walk(path,followlinks=False):
                    if any((Path(parent)/d).is_symlink() for d in dirs):raise ValueError('symlink tree refused')
                    entries.extend(Path(parent)/n for n in names)
                    if len(entries)>10000:raise ValueError('file inventory budget exceeded')
            else:explicit.add(value)
            for entry in entries:
                name=entry.relative_to(t.root).as_posix();relative(name)
                if name not in t.locks:candidates.add(name)
                if len(candidates)>10000:raise ValueError('file inventory budget exceeded')
    # Classify a base before any reserved companion. Suffixes alone do not
    # identify sidecars: stores and ordinary profile files may use these names.
    for name in sorted(candidates,key=lambda name:(len(name),name)):
        base=next((name[:-len(suffix)] for suffix in ('-wal','-shm','-journal') if name.endswith(suffix)),None)
        if base in files and files[base]['sqlite']:
            if name in explicit:raise ValueError('explicit SQLite sidecar authority is ambiguous: '+name)
            with _open_root(t.root) as root_fd:
                with _open_file(root_fd,tuple(name.split('/'))):pass
            continue
        data,identity,_=composition_read(t,name,proofs)
        total+=len(data)
        if total>MAX_TOTAL:raise ValueError('composition budget exceeded')
        files[name]=dict(sha256=digest(data),size=len(data),sqlite=data.startswith(b'SQLite format 3\x00'),identity=list(identity))
    return files


def verify_offload_inventory(topology,files):
    """A complete composition may not omit already released capture history.

    Offload storage must be explicitly classified inside the offline topology.
    Never discover/copy an external root or rewrite its authority binding.
    """
    from .capture_offload import chain,storage_identity
    for owner_path in topology.roles['owner']:
        with sqlite3.connect((topology.root/owner_path).as_uri()+'?mode=ro',uri=True) as db:
            tables={row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if 'capture_offload_head' not in tables:continue
            heads=db.execute('SELECT sha256,through FROM capture_offload_head WHERE singleton=1').fetchall()
            if not heads:continue
            if len(heads)!=1 or 'capture_offload_storage' not in tables:
                raise ValueError('offload chain must be explicitly bound before composition capture')
            roots=db.execute('SELECT directory,device,inode FROM capture_offload_storage WHERE singleton=1').fetchall()
            if len(roots)!=1:raise ValueError('offload chain storage binding missing')
            directory,device,inode=roots[0]
            storage=dict(directory=directory,device=device,inode=inode)
            if storage_identity(directory)!=storage:raise ValueError('offload composition storage changed')
            root=Path(directory)
            if not root.is_relative_to(topology.root):raise ValueError('offload storage must be explicitly included inside composition topology')
            latest,through=heads[0];next_hash=latest
            for bundle in chain(root,latest,through=through,expected_root=(device,inode)):
                name=(root/(next_hash+'.json')).relative_to(topology.root).as_posix()
                if name not in files or files[name]['sha256']!=next_hash:
                    raise ValueError('complete offload history missing from classified composition inventory')
                next_hash=bundle['previous']
            if storage_identity(directory)!=storage:raise ValueError('offload composition storage changed')


def capture(topology,destination,*,checkpoint=lambda stage:None):
    t=topology;t.validate();destination=Path(destination)
    from .replica_authority import assert_mutation_authority
    assert_mutation_authority(t.root/t.vault)
    if destination.exists():raise ValueError('new capture destination required')
    if destination.resolve().is_relative_to(t.root.resolve()):raise ValueError('capture must be outside source topology')
    with ExitStack() as stack:
        for name in sorted(set(t.locks)):
            p=t.root/name
            from .external_workspace import _open_root
            # Lock directories are metadata, created before the cut. Walk them
            # descriptor-relative so a missing .arvyx never weakens admission.
            with _open_root(t.root) as root_fd:
                parent_fd=os.dup(root_fd)
                try:
                    for part in Path(name).parts[:-1]:
                        try:os.mkdir(part,0o700,dir_fd=parent_fd)
                        except FileExistsError:pass
                        child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent_fd)
                        os.close(parent_fd);parent_fd=child
                finally:os.close(parent_fd)
            with _open_root(p.parent) as parent:
                fd=os.open(p.name,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600,dir_fd=parent)
            stack.callback(os.close,fd)
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise ValueError('unsafe quiescence lock')
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise ValueError('offline quiescent owner/state locks required') from None
        # These lock-free recovery internals run only after all declared
        # canonical owner/state/vault quiescence locks have been acquired.
        from .promotion_transaction import recover as recover_promotions
        from .import_publication import recover as recover_imports
        recover_imports(t.root/t.vault);recover_promotions(t.root/t.vault)
        before=inventory(t);proofs=completed_forget_links(t)
        directories=set()
        for role,paths in t.roles.items():
            if role=='bearer_authority':continue
            for value in paths:
                path=t.root/value
                if path.is_dir():
                    for parent,children,_ in os.walk(path,followlinks=False):
                        directories.add(Path(parent).relative_to(t.root).as_posix())
        databases={}
        for name,info in sorted(before.items()):
            if info['sqlite']:
                db=sqlite3.connect((t.root/name).as_uri()+'?mode=rw',uri=True,timeout=0)
                stack.callback(db.close)
                try:db.execute('BEGIN IMMEDIATE')
                except sqlite3.OperationalError:raise ValueError('quiescent SQLite writers required') from None
                databases[name]=db
        verify_offload_inventory(t,before)
        mkdir_durable(destination,exist_ok=False)
        manifest={}
        for name,info in sorted(before.items()):
            target=destination/'files'/name
            if info['sqlite']:
                mkdir_durable(target.parent)
                # Read through SQLite while the independent writer fence is held;
                # captures committed WAL state without copying a live WAL prefix.
                with sqlite3.connect((t.root/name).as_uri()+'?mode=ro',uri=True) as source,sqlite3.connect(target) as output:
                    source.backup(output)
                    if output.execute('PRAGMA quick_check').fetchall()!=[('ok',)]:raise ValueError('invalid captured database')
                os.chmod(target,0o600)
                with target.open('rb') as f:os.fsync(f.fileno())
                data=target.read_bytes()
            else:
                from .external_workspace import _read
                data,_,_=composition_read(t,name,proofs);write(target,data)
            manifest[name]=dict(sha256=digest(data),size=len(data),sqlite=info['sqlite'])
        if inventory(t)!=before:raise ValueError('source changed during coordinated cut')
        sync_tree(destination)
        checkpoint('before-manifest')
        record=dict(schema=1,complete=True,roles=t.roles,vault=t.vault,files=manifest,directories=sorted(directories),bearers_captured=False,
                    reopen_policy='quarantined; explicit independent authority reprovision required')
        write(destination/'manifest.json',canonical(record));sync(destination)
        return record


def load_bundle(bundle):
    bundle=Path(bundle)
    try:
        from .external_workspace import _read
        raw,_,_=_read(bundle,('manifest.json',),4*1024*1024);record=json.loads(raw)
    except (OSError,ValueError):raise ValueError('complete capture manifest required') from None
    if record.get('schema')!=1 or record.get('complete') is not True or set(record.get('roles',{}))!=ROLES or record.get('bearers_captured') is not False:
        raise ValueError('complete classified capture required')
    relative(record['vault']);total=0
    if type(record.get('files')) is not dict or len(record['files'])>10000:raise ValueError('manifest budget')
    for name,entry in record['files'].items():
        relative(name);data,_,_=_read(bundle,('files',*name.split('/')),MAX_FILE);total+=len(data)
        if total>MAX_TOTAL or len(data)!=entry['size'] or digest(data)!=entry['sha256']:raise ValueError('capture hash mismatch')
    return record,digest(raw)


def restore(bundle,destination):
    record,manifest_hash=load_bundle(bundle);destination=Path(destination)
    if destination.exists():raise ValueError('new offline candidate required')
    mkdir_durable(destination,exist_ok=False)
    # Fence is published before any state. Partial restores stay inert.
    fence=dict(schema=1,manifest_sha256=manifest_hash,quarantined=True,bearer_authority_restored=False)
    write(destination/record['vault']/FENCE,canonical(fence))
    for name in record.get('directories',[]):
        relative(name);mkdir_durable(destination/name)
    from .external_workspace import _read
    for name,entry in sorted(record['files'].items()):
        data,_,_=_read(Path(bundle),('files',*name.split('/')),MAX_FILE)
        if digest(data)!=entry['sha256']:raise ValueError('capture changed during restore')
        write(destination/name,data)
    sync_tree(destination)
    write(destination/'restore-receipt.json',canonical(dict(fence,files=record['files'],vault=record['vault'])));sync(destination)
    return fence


def inspect_candidate(directory):
    from .external_workspace import _read
    root=Path(directory);raw,_,_=_read(root,('restore-receipt.json',),4*1024*1024);receipt=json.loads(raw)
    checked=0
    for name,entry in receipt['files'].items():
        data,_,_=_read(root,tuple(relative(name).split('/')),MAX_FILE)
        if digest(data)!=entry['sha256']:raise ValueError('candidate hash changed')
        if entry['sqlite']:
            with sqlite3.connect((root/name).as_uri()+'?mode=ro',uri=True) as db:
                if db.execute('PRAGMA quick_check').fetchall()!=[('ok',)]:raise ValueError('candidate database invalid')
            checked+=1
    raw,_,_=_read(root,(*relative(receipt['vault']).split('/'),FENCE),65536)
    if json.loads(raw).get('quarantined') is not True:raise ValueError('quarantine missing')
    return dict(checked_databases=checked,mutable=False,bearer_authority_restored=False)


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['capture','restore','inspect']);p.add_argument('source',type=Path);p.add_argument('--destination',type=Path)
    args=p.parse_args(argv)
    if args.action=='capture':
        config=json.loads(args.source.read_text());result=capture(Topology(Path(config['root']),config['vault'],config['roles'],config['locks']),args.destination)
    elif args.action=='restore':result=restore(args.source,args.destination)
    else:result=inspect_candidate(args.source)
    print(json.dumps(result))

if __name__=='__main__':main()
