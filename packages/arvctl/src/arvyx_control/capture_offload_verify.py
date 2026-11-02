"""Bounded, resumable verification of immutable offload hash-chain segments.

Progress is readback evidence, never a release permit. A ready job is usable only
in the call that completed it; reopening/retrying a ready job starts a fresh walk.
Pending jobs bind the original head, operation, storage and exact owner DB inode.
Ack/relocate jobs also bind authenticated immutable generation commitment facts;
every call revalidates current issuer trust and admission expiry. A directory is
not retention authority. Authenticated time renewal alone can preserve progress.
"""
import hashlib,json,os


class OffloadContinuationRequired(ValueError):
    """No capture rows released: repeat the exact operation to verify next segment."""


def schema(owner):
    owner.db.execute('''CREATE TABLE IF NOT EXISTS capture_offload_verification(
        id TEXT PRIMARY KEY,next_hash TEXT NOT NULL,next_through INTEGER NOT NULL,
        ready INTEGER NOT NULL CHECK(ready IN (0,1)),kind TEXT NOT NULL)''')
    # At most one bounded digest mark per existing local run. No body, context,
    # run name or growing historical receipt is copied. Marks share the existing
    # conservative 512-byte per-run metadata allocation and are retired with it.
    owner.db.execute('''CREATE TABLE IF NOT EXISTS capture_offload_verified_runs(
        run_hash TEXT PRIMARY KEY,job TEXT NOT NULL)''')


def clear(owner,job=None):
    if job is None:
        owner.db.execute('DELETE FROM capture_offload_verified_runs')
        owner.db.execute('DELETE FROM capture_offload_verification')
    else:
        owner.db.execute('DELETE FROM capture_offload_verified_runs WHERE job=?',(job,))
        owner.db.execute('DELETE FROM capture_offload_verification WHERE id=?',(job,))


def verify(owner,directory,latest,through,storage,*,kind,limit,visit=None,keep_ready=False,retention_receipt=None):
    from .capture_offload import bundle_read,storage_identity
    from .public_onboarding_api import assert_request_active
    schema(owner);owner.db.commit()
    database=owner.db.execute('PRAGMA database_list').fetchone()[2]
    if not database:raise ValueError('durable exact owner database required for offload continuation')
    info=os.stat(database)
    retention=''
    if kind in ('ack','relocate'):
        from .capture_retention import verify as verify_retention
        retention=verify_retention(owner,retention_receipt,storage,latest,through,kind)
    key=hashlib.sha256(json.dumps([latest,through,storage,kind,info.st_dev,info.st_ino,retention],sort_keys=True).encode()).hexdigest()
    if type(limit) is not int or not 1<=limit<=64:raise ValueError('bounded verification segment required')
    row=owner.db.execute('SELECT next_hash,next_through,ready FROM capture_offload_verification WHERE id=?',(key,)).fetchone()
    if row and row[2] and keep_ready:return key
    if row and row[2]:
        clear(owner,key);row=None
    if row is None:
        # Only eight fixed-size infrastructure progress rows may coexist. They
        # do not mint archive authority or evict uncertainty/retained history.
        if owner.db.execute('SELECT count(*) FROM capture_offload_verification').fetchone()[0]>=8:
            raise ValueError('offload verification capacity reached; confirmed exact-head progress reset required')
        owner.db.execute('INSERT INTO capture_offload_verification VALUES(?,?,?,0,?)',(key,latest,through,kind))
        row=(latest,through,0)
    next_hash,expected=row[:2]
    owner.db.commit();owner.db.execute('BEGIN IMMEDIATE')
    try:
        for _ in range(limit):
            if not next_hash:break
            assert_request_active()
            bundle=bundle_read(directory,next_hash,durable=True,expected_root=(storage['device'],storage['inode']))
            if bundle['through']!=expected:raise ValueError('offload chain discontinuity')
            if visit is not None:visit(bundle,next_hash)
            if kind=='ack':
                for record in bundle['records']:
                    run=record.get('run')
                    if isinstance(run,str) and owner.db.execute("SELECT 1 FROM capture_runs WHERE run=? AND status='complete'",(run,)).fetchone():
                        owner.db.execute('INSERT OR REPLACE INTO capture_offload_verified_runs VALUES(?,?)',(hashlib.sha256(run.encode()).hexdigest(),key))
            next_hash=bundle['previous'];expected=bundle['after']
        if not next_hash and expected!=0:raise ValueError('offload chain genesis missing')
        if storage_identity(directory)!=storage:raise ValueError('offload storage changed')
        assert_request_active()
        owner.db.execute('UPDATE capture_offload_verification SET next_hash=?,next_through=?,ready=? WHERE id=?',(next_hash,expected,int(not next_hash),key))
        owner.db.commit()
    except BaseException:owner.db.rollback();raise
    if next_hash:
        raise OffloadContinuationRequired('offload verification continuation required; repeat this exact operation; no capture released; checkpoint '+key)
    return key
