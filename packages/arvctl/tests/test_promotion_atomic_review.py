"""Public HTTP dispatch -> promotion; actual partial I/O and recovery faults."""
from pathlib import Path
from unittest.mock import patch
import pytest
from arvyx_control.api import handle_api_request
from arvyx_control.vault import init_vault
from arvyx_control.writes import suggest_memory_batch

@pytest.fixture
def promotion(tmp_path):
    vault=tmp_path/'vault';init_vault(vault)
    parents=[vault/'projects/demo-agent/notes'/f'parent-{i}.md' for i in range(2)]
    parents[0].parent.mkdir(parents=True,exist_ok=True)
    for i,path in enumerate(parents):
        path.write_bytes(f'---\nid: p{i}\nstatus: promoted\n---\n\n# Parent\n\nExact café bytes {i}.\r\n'.encode())
    suggestion=suggest_memory_batch(vault,'demo-agent','demobot',{'memories':[dict(title='Review atomic',content='Replaces both current parents.',content_class='durable_fact',memory_class='dynamic',future_job='Keep exact curated truth.',assistant_suggestion_accepted=False,relations=[dict(type='updates',parent_source_path=str(p.relative_to(vault))) for p in parents])]}).suggestions[0]
    source=vault/suggestion.path
    def promote():
        return handle_api_request('POST','/memory/promote',dict(project='demo-agent',source_path=suggestion.path,promoted_by='operator'),vault=vault,state=tmp_path/'events.jsonl',allow_unauthenticated_demo=True)
    return vault,parents,source,promote


def test_partial_parent_write_cannot_destroy_curated_bytes(promotion):
    vault,parents,source,promote=promotion
    originals=[p.read_bytes() for p in parents];pending=source.read_bytes();real_open=Path.open
    touched=[];stages=[]
    class Partial:
        def __init__(self,stream):self.stream=stream
        def __enter__(self):self.stream.__enter__();return self
        def __exit__(self,*args):return self.stream.__exit__(*args)
        def __getattr__(self,name):return getattr(self.stream,name)
        def write(self,data):
            self.stream.write(data[:13]);self.stream.flush();touched.append(True)
            raise OSError('injected partial write after truncation')
    def opening(path,mode='r',*args,**kwargs):
        stream=real_open(path,mode,*args,**kwargs)
        if 'x' in mode and path.parent==parents[1].parent and path.name.startswith('.promotion-') and path.suffix=='.stage':
            stages.append(path)
            if len(stages)==3:return Partial(stream)
        return stream
    with patch.object(Path,'open',opening):
        assert promote().status==503
    assert touched,'must inject actual partial bytes, not fail before opening'
    assert [p.read_bytes() for p in parents]==originals
    assert source.read_bytes()==pending
    assert not (parents[0].parent/'review-atomic.md').exists()


def test_replace_and_rollback_failure_retains_recoverable_originals(promotion):
    vault,parents,source,promote=promotion
    originals=[p.read_bytes() for p in parents];real_replace=Path.replace
    def replacing(path,target):
        if Path(target)==parents[1] or (Path(target)==parents[0] and path.suffix=='.restore'):
            raise OSError('injected publication/rollback failure')
        return real_replace(path,target)
    with patch.object(Path,'replace',replacing):
        assert promote().status==503
    assert source.exists()
    backups=list((vault/'.arvyx/promotions').glob('*/parent-0.original'))
    assert backups and backups[0].read_bytes()==originals[0]
    result=promote() # recovery must run before validating superseded parents
    assert result.status==200
    for path in parents:
        assert b'status: superseded' in path.read_bytes()
        assert result.body['target'].encode() in path.read_bytes()
    assert not source.exists()


def test_rollback_never_overwrites_concurrently_replaced_parent(promotion):
    vault,parents,source,promote=promotion
    real_replace=Path.replace
    def replacing(path,target):
        if Path(target)==parents[1]:
            other=parents[0].with_name('external.tmp');other.write_bytes(b'Independent replacement\n');real_replace(other,parents[0])
            raise OSError('injected failure after external replacement')
        return real_replace(path,target)
    with patch.object(Path,'replace',replacing):
        assert promote().status==503
    assert parents[0].read_bytes()==b'Independent replacement\n'
    assert source.exists()


def test_failure_after_pending_unlink_recovers_exact_pending_and_parents(promotion):
    import arvyx_control.promotion_transaction as tx
    vault,parents,source,promote=promotion
    originals=[p.read_bytes() for p in parents];pending=source.read_bytes();real_stage=tx.stage
    def fail_commit(path,*args,**kwargs):
        if path.name in {'committed','committed.stage'}:raise OSError('commit marker disk failure after pending unlink')
        return real_stage(path,*args,**kwargs)
    with patch.object(tx,'stage',fail_commit):
        assert promote().status==503
    assert source.read_bytes()==pending
    assert [p.read_bytes() for p in parents]==originals


def test_process_crash_reopens_journal_before_public_promotion(promotion):
    import os,subprocess,sys
    vault,parents,source,promote=promotion
    code='''import os,sys
from pathlib import Path
from arvyx_control.writes import promote_memory
original=Path.replace
def crash(path,target):
 result=original(path,target)
 if Path(target).name=='parent-0.md':os._exit(71)
 return result
Path.replace=crash
promote_memory(Path(sys.argv[1]),'demo-agent',sys.argv[2],'operator')
'''
    child=subprocess.run([sys.executable,'-c',code,str(vault),str(source.relative_to(vault))])
    assert child.returncode==71 and source.exists()
    assert b'status: superseded' in parents[0].read_bytes()
    result=promote();assert result.status==200
    assert not source.exists()
    assert not list((vault/'.arvyx/promotions').iterdir())


def test_original_snapshot_must_match_inode_before_publication(promotion):
    import arvyx_control.promotion_transaction as tx
    vault,parents,source,promote=promotion
    real_identity=tx.identity;changed=[]
    def identity(path):
        if Path(path)==parents[0] and not changed:
            parents[0].write_bytes(b'Independent edit before staging\n');changed.append(True)
        return real_identity(path)
    with patch.object(tx,'identity',identity):
        assert promote().status==503
    assert parents[0].read_bytes()==b'Independent edit before staging\n'
    assert source.exists()


def test_partial_rollback_is_idempotent_after_pending_and_parent_restore(promotion):
    import arvyx_control.promotion_transaction as tx
    vault,parents,source,promote=promotion
    originals=[p.read_bytes() for p in parents];pending=source.read_bytes()
    real_stage=tx.stage;real_replace=Path.replace
    def fail_commit(path,*args,**kwargs):
        if path.name in {'committed','committed.stage'}:raise OSError('commit marker failure after pending removal')
        return real_stage(path,*args,**kwargs)
    def fail_one_restore(path,target):
        if Path(target)==parents[0] and path.name.endswith('.restore'):
            raise OSError('only earlier parent rollback fails')
        return real_replace(path,target)
    with patch.object(tx,'stage',fail_commit),patch.object(Path,'replace',fail_one_restore):
        assert promote().status==503
    assert source.read_bytes()==pending
    assert parents[1].read_bytes()==originals[1]
    assert b'status: superseded' in parents[0].read_bytes()
    result=promote() # Already restored inodes must be recognized by recovery.
    assert result.status==200
    assert not source.exists()
    assert not list((vault/'.arvyx/promotions').iterdir())


def test_partial_restore_staging_write_can_recover_on_retry(promotion):
    import arvyx_control.promotion_transaction as tx
    vault,parents,source,promote=promotion
    real_stage=tx.stage;real_open=Path.open;touched=[]
    def fail_commit(path,*args,**kwargs):
        if path.name in {'committed','committed.stage'}:raise OSError('commit marker failure')
        return real_stage(path,*args,**kwargs)
    class Partial:
        def __init__(self,stream):self.stream=stream
        def __enter__(self):self.stream.__enter__();return self
        def __exit__(self,*args):return self.stream.__exit__(*args)
        def __getattr__(self,name):return getattr(self.stream,name)
        def write(self,data):
            self.stream.write(data[:13]);self.stream.flush();touched.append(True)
            raise OSError('partial write staging an original restoration')
    def opening(path,mode='r',*args,**kwargs):
        stream=real_open(path,mode,*args,**kwargs)
        if 'x' in mode and path.name.startswith('parent-1.original') and path.suffix=='.restore':
            return Partial(stream)
        return stream
    with patch.object(tx,'stage',fail_commit),patch.object(Path,'open',opening):
        assert promote().status==503
    assert touched and source.exists()
    result=promote();assert result.status==200
    assert not source.exists()


def test_partial_commit_marker_never_discards_incomplete_rollback(promotion):
    vault,parents,source,promote=promotion
    real_open=Path.open;real_replace=Path.replace;touched=[]
    class Partial:
        def __init__(self,stream):self.stream=stream
        def __enter__(self):self.stream.__enter__();return self
        def __exit__(self,*args):return self.stream.__exit__(*args)
        def __getattr__(self,name):return getattr(self.stream,name)
        def write(self,data):
            self.stream.write(data[:3]);self.stream.flush();touched.append(True)
            raise OSError('partial commit marker write')
    def opening(path,mode='r',*args,**kwargs):
        stream=real_open(path,mode,*args,**kwargs)
        if 'x' in mode and path.name in {'committed','committed.stage'}:return Partial(stream)
        return stream
    def fail_restore(path,target):
        if Path(target)==parents[0] and path.suffix=='.restore':raise OSError('rollback replacement failure')
        return real_replace(path,target)
    with patch.object(Path,'open',opening),patch.object(Path,'replace',fail_restore):
        assert promote().status==503
    assert touched and source.exists()
    result=promote();assert result.status==200
    assert not source.exists()


def test_new_target_created_before_identity_capture_is_not_overwritten(promotion):
    import arvyx_control.promotion_transaction as tx
    vault,parents,source,promote=promotion
    real_identity=tx.identity;target=parents[0].parent/'review-atomic.md';changed=[]
    def identity(path):
        if Path(path)==target and not changed:
            target.write_bytes(b'Independent target created after name selection\n');changed.append(True)
        return real_identity(path)
    with patch.object(tx,'identity',identity):
        assert promote().status==503
    assert target.read_bytes()==b'Independent target created after name selection\n'
    assert source.exists()


def test_pending_snapshot_changed_after_rendering_survives_unpublished(promotion):
    from arvyx_control import writes
    vault,parents,source,promote=promotion
    real_render=writes._set_frontmatter_status;external=[]
    def rendering(text,**kwargs):
        result=real_render(text,**kwargs)
        if kwargs.get('status')=='promoted':
            updated=source.read_bytes()+b'\nIndependent pending edit after rendering\n'
            source.write_bytes(updated);external.append(updated)
        return result
    with patch.object(writes,'_set_frontmatter_status',rendering):
        assert promote().status==503
    assert source.read_bytes()==external[0]
    assert not (parents[0].parent/'review-atomic.md').exists()


def test_parent_status_is_validated_from_the_same_staged_byte_snapshot(promotion):
    from arvyx_control import writes
    vault,parents,source,promote=promotion
    real_render=writes._set_frontmatter_status;external=[]
    def rendering(text,**kwargs):
        result=real_render(text,**kwargs)
        if kwargs.get('status')=='promoted':
            updated=real_render(parents[0].read_bytes().decode(),status='superseded',extra={'superseded_by':'independent.md'}).encode()
            parents[0].write_bytes(updated);external.append(updated)
        return result
    with patch.object(writes,'_set_frontmatter_status',rendering):result=promote()
    assert result.status==400
    assert parents[0].read_bytes()==external[0]
    assert source.exists()
