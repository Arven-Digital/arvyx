"""Recoverable multi-file promotion under the caller's vault lock.

Originals are never opened for writing. Durable byte backups and staged inode
identities precede publication. Rollback only replaces the exact inode/content
we published, preserving unrelated replacements and retaining conflicted journals.
"""
from contextlib import contextmanager
from typing import Iterator
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import uuid
from . import private_paths, safe_open
from .locks import vault_lock, check_deadline
from .filesystem import durable_mkdir, fsync_directory
from .paths import resolve_under
from .forget_guard import assert_copyable_forget_operations


@contextmanager
def memory_mutation(vault: Path, *, forget_recovery: tuple[str, str] | None = None,
                    deadline: float | None = None) -> Iterator[None]:
    """Lock and reconcile promotions before any governed mutation reads state.

    Public mutation entry points own this context; callers must not already
    hold vault_lock. Recovery/publish remain lock-free internals so the same
    lock spans reconciliation, validation, publication, and receipt writes.
    A recovery conflict fails closed before yielding to the requested mutation.
    """
    with vault_lock(vault, deadline=deadline):
        check_deadline(deadline)
        from .replica_authority import assert_mutation_authority
        assert_mutation_authority(vault)
        check_deadline(deadline)
        assert_copyable_forget_operations(vault, recovery=forget_recovery)
        check_deadline(deadline)
        from .import_publication import recover as recover_imports
        recover_imports(vault)
        recover(vault, deadline=deadline)
        check_deadline(deadline)
        yield


def identity(path):
    try:
        with Path(path).open('rb') as stream:
            info=os.fstat(stream.fileno());data=stream.read()
        return [info.st_dev,info.st_ino,hashlib.sha256(data).hexdigest()]
    except FileNotFoundError:
        return None


def sync(directory):
    fsync_directory(directory)


def stage(path,data,mode=0o600):
    with path.open('xb') as stream:
        private_paths.apply_mode(fd=stream.fileno(),mode=mode)
        view=memoryview(data)
        while view:
            written=stream.write(view)
            if not written:raise OSError('short promotion write')
            view=view[written:]
        stream.flush();os.fsync(stream.fileno())
    sync(path.parent)


def apply_original_metadata(path, row):
    """Restore ownership before mode; chown may clear set-id mode bits.

    Legacy manifests lack ownership authority and cannot safely recreate an
    original inode. Retain those journals for explicit operator reconciliation.
    """
    uid, gid = row.get('uid'), row.get('gid')
    if type(uid) is not int or type(gid) is not int or uid < 0 or gid < 0:
        raise OSError('promotion original ownership missing or invalid')
    with path.open('rb') as stream:
        fd = stream.fileno()
        info = os.fstat(fd)
        if (info.st_uid, info.st_gid) != (uid, gid):
            if not hasattr(os, 'fchown'):
                raise OSError('promotion ownership restoration unsupported')
            os.fchown(fd, uid, gid)
        info = os.fstat(fd)
        if (info.st_uid, info.st_gid) != (uid, gid):
            raise OSError('promotion ownership restoration failed')
        private_paths.apply_mode(fd=fd, mode=row['mode'])
        safe_open.fsync_file(fd)


def clean(journal,document):
    # Retire recovery authority before collecting any witnesses or backups.
    retired = journal.with_name('.gc-' + journal.name)
    journal.replace(retired)
    sync(retired.parent)
    for row in document['files']:
        path = Path(row['stage'])
        path.unlink(missing_ok=True)
        sync(path.parent)
    shutil.rmtree(retired)
    sync(retired.parent)


def restoration(journal,row):
    """Record the replacement identity durably before restoring any original.

    A later recovery must recognize originals already restored by an interrupted
    rollback, even though atomic replacement necessarily gives them new inodes.
    The durable backup remains separate from the published restoration inode.
    """
    replacement=journal/(row['backup']+'.'+uuid.uuid4().hex+'.restore')
    stage(replacement,(journal/row['backup']).read_bytes())
    apply_original_metadata(replacement,row)
    restored=identity(replacement)
    if restored is None or restored[2]!=row['original'][2]:
        raise OSError('promotion restoration bytes changed')
    marker=journal/(row['backup']+'.restored.json')
    temporary=journal/(marker.name+'.'+uuid.uuid4().hex)
    stage(temporary,json.dumps(restored).encode())
    authority = journal.stat()
    apply_original_metadata(temporary, dict(uid=authority.st_uid, gid=authority.st_gid, mode=0o600))
    temporary.replace(marker);sync(journal)
    return replacement


def rollback(vault,journal,document,*,deadline=None):
    complete=True
    for row in reversed(document['files']):
        check_deadline(deadline)
        path=resolve_under(vault,*row['path'].split('/'))
        try:
            found=identity(path)
            marker=journal/(row['backup']+'.restored.json')
            restored=json.loads(marker.read_text()) if marker.exists() else None
            if found is not None and found==restored:
                info=path.stat()
                if (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)) != (row.get('uid'),row.get('gid'),row['mode']):
                    complete=False
                sync(path.parent)
                continue
            if row['original'] is None:
                if found==row['published']:
                    path.unlink();sync(path.parent)
                elif found is not None:complete=False
                else:sync(path.parent)
            elif found==row['original']:
                sync(path.parent)
            elif found==row['published'] or (row['source'] and found is None):
                replacement=restoration(journal,row)
                # Compare again after staging; no unrelated inode may be restored over.
                if identity(path)!=found:
                    complete=False;continue
                if found is None:
                    os.link(replacement,path) # exclusive publication of missing pending source
                    replacement.unlink()
                else:replacement.replace(path)
                sync(path.parent)
            else:complete=False
        except TimeoutError:
            raise
        except OSError:
            complete=False # Exact originals remain durable for the next recovery attempt.
    return complete


def recover(vault,*,deadline=None):
    check_deadline(deadline)
    root=vault/'.arvyx/promotions'
    if not root.exists():return
    for journal in sorted(root.iterdir()):
        check_deadline(deadline)
        if journal.name.startswith('.gc-'):
            # The retirement rename may have survived without its parent barrier.
            # Repeat it before deleting even an apparently retired namespace.
            sync(root)
            shutil.rmtree(journal)
            sync(root)
            continue
        manifest=journal/'manifest.json'
        if not manifest.exists():
            # No publication can precede the durable prepared manifest.
            continue
        document=json.loads(manifest.read_text())
        if not (journal/'committed').exists() and not rollback(vault,journal,document,deadline=deadline):
            raise OSError('promotion recovery conflict or I/O failure; originals retained in '+str(journal))
        check_deadline(deadline)
        clean(journal,document)
        check_deadline(deadline)


def publish(vault,source,target,target_bytes,parents,*,source_bytes):
    """parents maps exact paths to (original bytes, replacement bytes)."""
    # Establish every destination namespace before staging or deleting source.
    for path in (target, *parents, source):
        durable_mkdir(path.parent)
    root=vault/'.arvyx/promotions';durable_mkdir(root,mode=0o700)
    journal=root/uuid.uuid4().hex;journal.mkdir(mode=0o700);sync(root)
    files=[];prepared=False
    paths=[(target,None,target_bytes,False),
           *[(path,original,replacement,False) for path,(original,replacement) in parents.items()],
           (source,source_bytes,None,True)]
    try:
        for index,(path,original,replacement,is_source) in enumerate(paths):
            original_info=path.stat() if original is not None else None
            mode=stat.S_IMODE(original_info.st_mode) if original_info is not None else 0o600
            backup='source.original' if is_source else f'parent-{index-1}.original'
            row=dict(path=path.relative_to(vault).as_posix(),original=identity(path),published=None,
                     backup=backup,mode=mode,uid=original_info.st_uid if original_info else None,
                     gid=original_info.st_gid if original_info else None,source=is_source,stage=str(path.with_name('.promotion-'+uuid.uuid4().hex+'.stage')))
            files.append(row)
            if original is None and row['original'] is not None:
                raise OSError('new promotion target is no longer absent')
            if original is not None:
                if row['original'] is None or row['original'][2]!=hashlib.sha256(original).hexdigest():
                    raise OSError('promotion original changed before staging')
                stage(journal/backup,original)
            if replacement is not None:
                stage(Path(row['stage']),replacement)
                if original is not None:apply_original_metadata(Path(row['stage']),row)
                row['published']=identity(row['stage'])
        document=dict(schema=1,files=files)
        # Only a complete, fsynced manifest may become recovery authority.
        # Interrupted preparation leaves manifest.stage, never partial JSON at
        # the authoritative name; no destination is published until its rename
        # is durable in the journal directory.
        stage(journal/'manifest.stage',json.dumps(document,sort_keys=True).encode())
        (journal/'manifest.stage').replace(journal/'manifest.json')
        sync(journal);prepared=True
        for row in files:
            if row['source']:continue
            path=resolve_under(vault,*row['path'].split('/'))
            if identity(path)!=row['original']:
                raise OSError('promotion destination changed before publication')
            if row['original'] is None:
                os.link(row['stage'],path) # exclusive creation, including final-check races
                Path(row['stage']).unlink()
            else:Path(row['stage']).replace(path)
            sync(path.parent)
        if identity(source)!=files[-1]['original']:
            raise OSError('pending source changed before completion')
        source.unlink();sync(source.parent)
        stage(journal/'committed.stage',b'committed\n')
        (journal/'committed.stage').replace(journal/'committed');sync(journal)
    except BaseException:
        if prepared:
            # A failed commit acknowledgement must never leave a success marker
            # over a partially rolled-back transaction. If revocation itself fails,
            # retain the complete journal and do not start a mixed rollback.
            (journal/'committed').unlink(missing_ok=True);sync(journal)
            if rollback(vault,journal,document):clean(journal,document)
        else:
            for row in files:Path(row['stage']).unlink(missing_ok=True)
            shutil.rmtree(journal)
        raise
    else:
        try:clean(journal,document)
        except OSError:pass # Committed marker supports cleanup without replay on reopening.
