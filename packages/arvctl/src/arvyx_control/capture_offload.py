"""Explicit two-phase verified offload of acknowledged sanitized capture rows.

The local spool remains bounded; content-addressed bundles on a mutable directory
are only a read cache. Pruning/rebinding additionally requires a qualified store
issuer's exact complete-generation retention commitment; readback hashes alone
never establish retention. Local-only rows require explicit local-archive acknowledgement; sink delivery is never invented. One durable
head links the history without a growing receipt table. No automatic offload,
network, archive deletion or authority provisioning occurs.
"""
import hashlib,json,re,os
from pathlib import Path
from . import safe_open
from .cockpit_archive import _capture_schema
from .external_workspace import _read,_open_root,_open_file,_identity
from .native_install import write

MAX_BUNDLE=900*1024
MAX_CHAIN=1000 # historical single-call budget, no longer a lifetime limit
MAX_VERIFY_BUNDLES=64

def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def schema(owner):
    _capture_schema(owner)
    owner.db.execute('CREATE TABLE IF NOT EXISTS capture_offload_head(singleton INTEGER PRIMARY KEY CHECK(singleton=1),sha256 TEXT NOT NULL,through INTEGER NOT NULL)')
    owner.db.execute('''CREATE TABLE IF NOT EXISTS capture_offload_storage(
        singleton INTEGER PRIMARY KEY CHECK(singleton=1),directory TEXT NOT NULL,
        device INTEGER NOT NULL,inode INTEGER NOT NULL)''')
    from .capture_offload_verify import schema as verification_schema
    verification_schema(owner)
    from .capture_retention import schema as retention_schema
    retention_schema(owner)
    # Existing accounting charges context insertions. Match releases exactly.
    owner.db.execute('''CREATE TRIGGER IF NOT EXISTS capture_context_delete AFTER DELETE ON capture_delivery_context BEGIN
        UPDATE capture_accounting SET metadata_bytes=metadata_bytes-512-LENGTH(CAST(old.context AS BLOB))-LENGTH(CAST(old.event_id AS BLOB)) WHERE id=1; END''')

def head(owner):
    row=owner.db.execute('SELECT sha256,through FROM capture_offload_head WHERE singleton=1').fetchone()
    return (row[0],row[1]) if row else ('',0)

def storage_identity(directory):
    directory=Path(directory)
    if not directory.is_absolute():raise ValueError('absolute offload storage directory required')
    with _open_root(directory) as fd:
        info=os.fstat(fd)
        return dict(directory=str(directory),device=safe_open.stable_identity(info.st_dev),inode=safe_open.stable_identity(info.st_ino))

def require_storage(owner,storage):
    row=owner.db.execute('SELECT directory,device,inode FROM capture_offload_storage WHERE singleton=1').fetchone()
    if row is None:
        if head(owner)!=('',0):raise ValueError('offload storage unbound; explicit confirmed complete-chain adoption required')
    elif tuple(row)!=(storage['directory'],storage['device'],storage['inode']):
        raise ValueError('offload storage changed; explicit confirmed complete-chain relocation required')

def store_storage(owner,storage):
    owner.db.execute('INSERT OR REPLACE INTO capture_offload_storage VALUES(1,?,?,?)',
                     (storage['directory'],storage['device'],storage['inode']))

def local_only(owner,row):
    """Exactly the rows capture_delivery_payload permanently refuses to export.

    A row with frozen wire context, an unknown session or a non-local session
    still owes shared delivery, so local-archive never abandons it.
    """
    if owner.db.execute('SELECT 1 FROM capture_delivery_context WHERE event_id=?',(row['event_id'],)).fetchone():return False
    try:session=owner._get(row['session'])
    except ValueError:return False
    return type(session) is dict and session.get('kind')=='local'

def current_rows(owner,through=None,*,acknowledgement='delivery'):
    if acknowledgement not in ('delivery','local-archive'):raise ValueError('explicit delivery or local-archive acknowledgement required')
    previous,after=head(owner);rows=[];used=256
    query='SELECT * FROM work_capture WHERE sequence>?'+(' AND sequence<=?' if through is not None else '')+' ORDER BY sequence LIMIT 100'
    values=(after,through) if through is not None else (after,)
    for row in owner.db.execute(query,values).fetchall():
        # Never cross an unacknowledged prefix. Local-archive crosses only rows
        # whose shared export is permanently refused; pending work delivery stays.
        if row['delivered']!=1 and (acknowledgement=='delivery' or not local_only(owner,row)):break
        item=dict(row)
        context=owner.db.execute('SELECT context FROM capture_delivery_context WHERE event_id=?',(row['event_id'],)).fetchone()
        item['delivery_context']=context[0] if context else None
        size=len(encoded(item))+2
        if used+size>MAX_BUNDLE:break
        rows.append(item);used+=size
    return rows

def durable_bundle(directory,digest,*,expected_root=None):
    """Synchronize the exact verified inode, including an uncertain prior write."""
    directory=Path(directory);parts=(digest+'.json',)
    data,identity,root_identity=_read(directory,parts,MAX_BUNDLE,expected_root=expected_root)
    if hashlib.sha256(data).hexdigest()!=digest:raise ValueError('offload hash mismatch')
    with _open_root(directory) as root_fd:
        st=os.fstat(root_fd)
        if (safe_open.stable_identity(st.st_dev),safe_open.stable_identity(st.st_ino))!=root_identity:raise ValueError('offload directory changed')
        with _open_file(root_fd,parts) as fd:
            if _identity(os.fstat(fd))!=identity:raise ValueError('offload bundle changed')
            safe_open.fsync_file(fd)
            if _identity(os.fstat(fd))!=identity:raise ValueError('offload bundle changed during sync')
        safe_open.fsync_directory(root_fd)
    # Reject replacement of either path during the barriers, even with equal bytes.
    verified,_,_=_read(directory,parts,MAX_BUNDLE,expected_root=root_identity,expected_file=identity)
    if verified!=data:raise ValueError('offload readback mismatch')
    return data

def prepare_offload(owner,directory,*,actor,acknowledgement='delivery',verification_limit=None):
    owner._human(actor);directory=Path(directory)
    with owner.lock:
        schema(owner);storage=storage_identity(directory);require_storage(owner,storage)
        previous,after=head(owner)
        from .capture_offload_verify import verify,clear
        job=verify(owner,directory,previous,after,storage,kind='prepare',limit=MAX_VERIFY_BUNDLES if verification_limit is None else verification_limit)
        clear(owner,job);owner.db.commit()
        rows=current_rows(owner,acknowledgement=acknowledgement)
        if not rows:raise ValueError('no contiguous acknowledged capture prefix to offload')
        while rows:
            bundle=dict(schema=3,acknowledgement=acknowledgement,previous=previous,after=after,through=rows[-1]['sequence'],records=rows,storage=storage)
            data=encoded(bundle)
            if len(data)<=MAX_BUNDLE:break
            rows.pop()
        if not rows:raise ValueError('bounded offload bundle required')
        digest=hashlib.sha256(data).hexdigest()
        with _open_root(directory) as fd:
            if (safe_open.stable_identity(os.fstat(fd).st_dev),safe_open.stable_identity(os.fstat(fd).st_ino))!=(storage['device'],storage['inode']):raise ValueError('offload storage changed')
            try:write(digest+'.json',data,0o600,dir_fd=fd)
            except FileExistsError:pass
        verified=durable_bundle(directory,digest,expected_root=(storage['device'],storage['inode']))
        if verified!=data:raise ValueError('offload readback mismatch')
        owner.db.commit()
        return dict(sha256=digest,through=bundle['through'],records=len(rows),released=0)

def bundle_read(directory,digest,*,durable=False,expected_root=None):
    if not isinstance(digest,str) or not re.fullmatch('[a-f0-9]{64}',digest):raise ValueError('exact offload digest required')
    try:
        if durable:data=durable_bundle(directory,digest,expected_root=expected_root)
        else:data,_,_=_read(Path(directory),(digest+'.json',),MAX_BUNDLE,expected_root=expected_root)
    except (OSError,ValueError):raise ValueError('verified offload bundle unavailable') from None
    if hashlib.sha256(data).hexdigest()!=digest:raise ValueError('offload hash mismatch')
    value=json.loads(data)
    if type(value) is not dict or type(value.get('schema')) is not int or value['schema'] not in (1,2,3) or type(value.get('records')) is not list or not 1<=len(value['records'])<=100:raise ValueError('bounded offload bundle required')
    if not isinstance(value.get('previous'),str) or (value['previous'] and not re.fullmatch('[a-f0-9]{64}',value['previous'])):raise ValueError('offload predecessor required')
    if type(value.get('after')) is not int or type(value.get('through')) is not int or not 0<=value['after']<value['through']:raise ValueError('offload sequence bounds required')
    sequence=value['after'];events=set()
    for row in value['records']:
        if type(row) is not dict or type(row.get('sequence')) is not int or not sequence<row['sequence']<=value['through'] or (type(row.get('delivered')) is not int or row['delivered'] not in ((0,1) if value.get('acknowledgement')=='local-archive' and value['schema']==3 else (1,))) or not isinstance(row.get('event_id'),str) or not row['event_id'] or row['event_id'] in events:
            raise ValueError('exact acknowledged offload sequence required')
        sequence=row['sequence'];events.add(row['event_id'])
    if sequence!=value['through']:raise ValueError('offload sequence bounds required')
    if value['schema']==3 and value.get('acknowledgement') not in ('delivery','local-archive'):raise ValueError('explicit offload acknowledgement required')
    if value['schema'] in (2,3):
        storage=value.get('storage')
        if type(storage) is not dict or set(storage)!= {'directory','device','inode'} or not isinstance(storage['directory'],str) or not Path(storage['directory']).is_absolute() or type(storage['device']) is not int or type(storage['inode']) is not int:
            raise ValueError('exact prepared offload storage required')
    return value

def chain(directory,latest,*,through=None,durable=False,expected_root=None):
    next_hash=latest;expected=through
    while next_hash:
        from .public_onboarding_api import assert_request_active
        assert_request_active()
        bundle=bundle_read(directory,next_hash,durable=durable,expected_root=expected_root)
        if expected is not None and bundle['through']!=expected:raise ValueError('offload chain discontinuity')
        yield bundle
        expected=bundle['after'];next_hash=bundle['previous']
    if expected not in (None,0):raise ValueError('offload chain genesis missing')

def verify_chain(directory,latest,through,storage,*,durable=False,reserve=0,runs=None):
    represented=set()
    for count,bundle in enumerate(chain(directory,latest,through=through,durable=durable,expected_root=(storage['device'],storage['inode'])),1):
        if runs is not None:represented.update(row['run'] for row in bundle['records'] if row.get('run') in runs)
    if storage_identity(directory)!=storage:raise ValueError('offload storage changed')
    return represented

def _transfer_bound_chain(owner,directory,latest,through,storage,verification_limit=None):
    """Copy exact immutable bytes; leave the source and local rows untouched."""
    row=owner.db.execute('SELECT directory,device,inode FROM capture_offload_storage WHERE singleton=1').fetchone()
    if row is None:raise ValueError('unbound legacy chain requires complete-chain adoption, not inferred transfer')
    source=dict(directory=row[0],device=row[1],inode=row[2])
    if storage_identity(source['directory'])!=source:raise ValueError('original offload storage unavailable or replaced')
    from .capture_offload_verify import verify
    def copy(bundle,item):
        data=durable_bundle(source['directory'],item,expected_root=(source['device'],source['inode']))
        with _open_root(Path(directory)) as fd:
            info=os.fstat(fd)
            if (safe_open.stable_identity(info.st_dev),safe_open.stable_identity(info.st_ino))!=(storage['device'],storage['inode']):raise ValueError('offload destination changed')
            try:write(item+'.json',data,0o600,dir_fd=fd)
            except FileExistsError:pass
        if durable_bundle(directory,item,expected_root=(storage['device'],storage['inode']))!=data:
            raise ValueError('offload transfer readback mismatch')
    operation='transfer:'+hashlib.sha256(encoded(storage)).hexdigest()
    verify(owner,source['directory'],latest,through,source,kind=operation,limit=MAX_VERIFY_BUNDLES if verification_limit is None else verification_limit,visit=copy,keep_ready=True)
    if storage_identity(source['directory'])!=source:raise ValueError('original offload storage changed')


def relocate_offload_storage(owner,directory,*,actor,expected_head,confirmed=False,copy_from_bound=False,verification_limit=None,retention_receipt=None):
    """Confirm exact-head complete-chain adoption, or explicit verified transfer.

    Default adoption requires a complete independently supplied destination.
    copy_from_bound=True copies the bound chain without deleting its source;
    only complete durable destination verification AND authenticated qualified
    target retention commitment permit the SQLite rebind.
    Legacy unbound heads can be adopted, never implicitly located or copied.
    """
    owner._human(actor)
    if confirmed is not True:raise ValueError('separate explicit offload storage confirmation required')
    if type(copy_from_bound) is not bool:raise ValueError('explicit boolean transfer mode required')
    with owner.lock:
        schema(owner);owner.db.commit()
        latest,through=head(owner)
        if not latest or latest!=expected_head:raise ValueError('exact current offload head required for storage relocation')
        original=owner.db.execute('SELECT directory,device,inode FROM capture_offload_storage WHERE singleton=1').fetchone()
        original=tuple(original) if original else None
        storage=storage_identity(directory)
        from .capture_retention import verify as verify_retention,accept as accept_retention,snapshot
        retention_receipt=snapshot(retention_receipt)
        verify_retention(owner,retention_receipt,storage,latest,through,'relocate')
        if copy_from_bound:_transfer_bound_chain(owner,directory,latest,through,storage,verification_limit)
        from .capture_offload_verify import verify,clear
        verify(owner,directory,latest,through,storage,kind='relocate',limit=MAX_VERIFY_BUNDLES if verification_limit is None else verification_limit,retention_receipt=retention_receipt)
        owner.db.execute('BEGIN IMMEDIATE')
        try:
            current=owner.db.execute('SELECT directory,device,inode FROM capture_offload_storage WHERE singleton=1').fetchone()
            current=tuple(current) if current else None
            if head(owner)!=(latest,through) or current!=original or storage_identity(directory)!=storage:
                raise ValueError('offload authority changed during relocation verification')
            verify_retention(owner,retention_receipt,storage,latest,through,'relocate')
            accept_retention(owner,retention_receipt)
            store_storage(owner,storage);clear(owner);owner.db.commit()
        except BaseException:owner.db.rollback();raise
    return dict(sha256=latest,through=through,storage=storage,released=0)

def acknowledge_offload(owner,directory,digest,*,actor,confirmed=False,verification_limit=None,retention_receipt=None):
    owner._human(actor)
    if confirmed is not True:raise ValueError('separate explicit offload confirmation required')
    with owner.lock:
        schema(owner);owner.db.commit()
        storage=storage_identity(directory);require_storage(owner,storage)
        bundle=bundle_read(directory,digest,durable=True,expected_root=(storage['device'],storage['inode']))
        def exact_prefix():
            require_storage(owner,storage)
            if bundle.get('storage')!=storage:raise ValueError('offload storage differs from prepared bundle; prepare again')
            if head(owner)!=(bundle['previous'],bundle['after']) or current_rows(owner,bundle['through'],acknowledgement=bundle.get('acknowledgement','delivery'))!=bundle['records']:
                raise ValueError('offload prefix or acknowledgement changed; no release')
        exact_prefix()
        from .capture_retention import snapshot
        retention_receipt=snapshot(retention_receipt)
        from .capture_offload_verify import verify,clear
        job=verify(owner,directory,digest,bundle['through'],storage,kind='ack',limit=MAX_VERIFY_BUNDLES if verification_limit is None else verification_limit,retention_receipt=retention_receipt)
        owner.db.execute('BEGIN IMMEDIATE')
        try:
            exact_prefix()
            from .capture_retention import verify as verify_retention,accept as accept_retention
            verify_retention(owner,retention_receipt,storage,digest,bundle['through'],'ack')
            accept_retention(owner,retention_receipt)
            events=[(row['event_id'],) for row in bundle['records']]
            owner.db.executemany('DELETE FROM capture_delivery_context WHERE event_id=?',events)
            owner.db.executemany('DELETE FROM work_capture WHERE event_id=?',events)
            owner.db.create_function('capture_run_digest',1,lambda value:hashlib.sha256(value.encode()).hexdigest(),deterministic=True)
            owner.db.execute("""DELETE FROM capture_runs WHERE status='complete'
                AND EXISTS(SELECT 1 FROM capture_offload_verified_runs WHERE run_hash=capture_run_digest(capture_runs.run) AND job=?)
                AND NOT EXISTS(SELECT 1 FROM work_capture WHERE work_capture.run=capture_runs.run)""",(job,))
            owner.db.execute('INSERT OR REPLACE INTO capture_offload_head VALUES(1,?,?)',(digest,bundle['through']))
            store_storage(owner,storage);clear(owner);owner.db.commit()
        except BaseException:owner.db.rollback();raise
    return dict(released=len(events),sha256=digest,through=bundle['through'],history_retained_in_offload=True)

def read_offload_chain(directory,latest,*,limit=100):
    if type(limit) is not int or not 1<=limit<=10000:raise ValueError('bounded offload read required')
    result=[];storage=storage_identity(directory)
    for bundle in chain(directory,latest,expected_root=(storage['device'],storage['inode'])):
        result=bundle['records']+result
        if len(result)>limit:raise ValueError('offload read page budget exceeded')
    return result


def read_offload_page(directory,latest,*,through=None,limit=16):
    """Bounded newest-first segment with content-hash/sequence continuation.

    The caller retains the authenticated head. Each next digest is committed by
    the preceding immutable bundle; no reset, deletion or fresh genesis occurs.
    Full retention verification still walks to genesis before any release.
    """
    if type(limit) is not int or not 1<=limit<=64:raise ValueError('bounded offload segment required')
    storage=storage_identity(directory);bundles=[];next_hash=latest;expected=through
    for bundle in chain(directory,latest,through=through,expected_root=(storage['device'],storage['inode'])):
        bundles.append(bundle);next_hash=bundle['previous'];expected=bundle['after']
        if len(bundles)==limit:break
    return dict(anchor=latest,bundles=bundles,next_sha256=next_hash or None,next_through=expected if next_hash else None)
