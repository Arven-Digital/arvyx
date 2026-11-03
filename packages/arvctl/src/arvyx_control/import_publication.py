"""Exact import link witnesses, reconciled only under the canonical vault lock."""
from contextlib import closing
import hashlib, json, os, re, stat, uuid
from pathlib import Path
from . import private_paths
from .filesystem import durable_mkdir, fsync_directory, MAX_MEMORY_DOCUMENT_BYTES
from .external_workspace import _read, _open_root
from . import safe_open
from .paths import resolve_under


def _path(root, value):
    if (not isinstance(value,str) or '\\' in value or value.startswith('/')
            or any(p in ('','.','..') for p in value.split('/'))):
        raise ValueError('canonical import witness path required')
    return resolve_under(root,*value.split('/'))


def _identity(root,path):
    try:
        with _open_root(path.parent) as parent:
            fd=safe_open.open_file_at(parent,path.name)
            try:
                info=os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink not in (1,2) or info.st_size>MAX_MEMORY_DOCUMENT_BYTES:
                    raise ValueError('unsafe import publication inode')
                data=os.read(fd,MAX_MEMORY_DOCUMENT_BYTES+1)
                after=os.fstat(fd)
                if (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) or len(data)!=info.st_size:
                    raise ValueError('import publication changed during read')
                return [info.st_dev,info.st_ino,hashlib.sha256(data).hexdigest()]
            finally:os.close(fd)
    except FileNotFoundError:return None


def _finish(root,marker,record,*,retired=False):
    if set(record)!={'schema','target','stage','identity'} or record['schema']!=1:
        raise ValueError('invalid import publication witness')
    target=_path(root,record['target']);stage=_path(root,record['stage']);identity=record['identity']
    if (stage.parent!=target.parent or not re.fullmatch(r'\.import-[a-f0-9]{32}\.stage',stage.name)
            or not isinstance(identity,list) or len(identity)!=3 or any(type(i) is not int for i in identity[:2])
            or not isinstance(identity[2],str) or not re.fullmatch('[a-f0-9]{64}',identity[2])):
        raise ValueError('invalid import publication identity')
    staged=_identity(root,stage);published=_identity(root,target)
    if staged not in (None,identity) or published not in (None,identity) or (staged is None and published is None and not retired):
        raise ValueError('import publication conflict; retain exact witness for reconciliation')
    if published is not None:
        # Re-prove publication durability before retiring the only link witness.
        with _open_root(target.parent) as parent:
            fd=safe_open.open_file_at(parent,target.name)
            try:
                if [os.fstat(fd).st_dev,os.fstat(fd).st_ino]!=identity[:2]:raise ValueError('import publication replaced')
                safe_open.fsync_file(fd);safe_open.fsync_directory(parent)
            finally:os.close(fd)
    if not retired:
        # Retire authority durably BEFORE collecting its sole owned stage.
        # Recovery may accept both absent only in this terminal namespace.
        terminal=marker.with_suffix('.retired')
        os.rename(marker,terminal);fsync_directory(marker.parent)
        marker=terminal
    else:
        # A previous rename may have returned before its directory barrier.
        fsync_directory(marker.parent)
    if staged is not None:
        if _identity(root,stage)!=identity:raise ValueError('import stage replaced')
        stage.unlink()
    # Repeat the collection barrier even if an earlier unlink returned before
    # its fsync. Never retire the terminal witness ahead of this durability.
    fsync_directory(stage.parent)
    marker.unlink();fsync_directory(marker.parent)


def recover(root):
    root=Path(root);directory=root/'.arvyx/import-publications'
    if not directory.exists():return
    entries=[]
    # Pending names carry no publication authority. Collect only their own
    # directory entries, never parse their bytes or infer ownership of a stage.
    # Bound each pass; a retry makes progress even after a large fault backlog.
    exhausted=False
    with _open_root(directory) as root_fd:
        with closing(safe_open.scandir_names(root_fd)) as names_iter:
            for count,name in enumerate(names_iter):
                if count >= 2000:
                    exhausted=True
                    break
                if re.fullmatch(r'[a-f0-9]{32}\.pending',name):
                    info=safe_open.stat_at(root_fd,name)
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:
                        raise ValueError('unsafe pending import artifact')
                    safe_open.unlink_at(root_fd,name)
                else:
                    entries.append(directory/name)
    fsync_directory(directory)
    if exhausted:raise ValueError('import recovery pass budget exceeded; retry to drain pending debris')
    if len(entries)>1000:raise ValueError('import recovery journal budget exceeded')
    for marker in sorted(entries):
        if not re.fullmatch(r'[a-f0-9]{32}\.(json|retired)',marker.name):raise ValueError('unknown import recovery artifact')
        raw,_,_=_read(directory,(marker.name,),16384)
        _finish(root,marker,json.loads(raw),retired=marker.suffix=='.retired')


def publish(root,target,payload):
    root=Path(root);target=Path(target);directory=root/'.arvyx/import-publications'
    durable_mkdir(directory,mode=0o700)
    identifier=uuid.uuid4().hex;stage=target.with_name('.import-'+identifier+'.stage');marker=directory/(identifier+'.json')
    with stage.open('xb') as stream:
        private_paths.apply_mode(fd=stream.fileno(),mode=0o600);stream.write(payload);stream.flush();os.fsync(stream.fileno())
    fsync_directory(stage.parent)
    record=dict(schema=1,target=target.relative_to(root).as_posix(),stage=stage.relative_to(root).as_posix(),identity=_identity(root,stage))
    pending=marker.with_suffix('.pending')
    with pending.open('xb') as stream:
        private_paths.apply_mode(fd=stream.fileno(),mode=0o600);stream.write(json.dumps(record,sort_keys=True).encode());stream.flush();os.fsync(stream.fileno())
    os.rename(pending,marker)
    fsync_directory(directory)
    # Windows os.link cannot take follow_symlinks; the stage was created here and
    # verified above with a no-follow open, so the link source is that regular file.
    os.link(stage,target,**({'follow_symlinks':False} if os.link in os.supports_follow_symlinks else {}))
    fsync_directory(target.parent)
    _finish(root,marker,record)
