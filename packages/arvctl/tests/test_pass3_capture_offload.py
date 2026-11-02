import sqlite3,threading
from types import SimpleNamespace
from unittest.mock import patch
import pytest
from arvyx_control.cockpit_archive import WorkCapture,sync_capture,capture_status
from retention_fixture_helpers import retention_receipt

def owner(tmp_path):
    db=sqlite3.connect(tmp_path/'capture.db');db.row_factory=sqlite3.Row
    return SimpleNamespace(db=db,lock=threading.RLock(),_human=lambda actor:None,_get=lambda sid:{'id':sid},archive_sync='test',live={})

def test_sustained_capture_offload_eof_reopen_preserves_every_row(tmp_path):
    from arvyx_control.capture_offload import prepare_offload,acknowledge_offload,read_offload_chain
    o=owner(tmp_path);directory=tmp_path/'offload';directory.mkdir(mode=0o700)
    expected=[]
    with patch('arvyx_control.cockpit_archive.CAPTURE_CAPACITY',32768):
        stream=WorkCapture(o,'sid')
        for cycle in range(12):
            text='bounded line '+str(cycle)+'\n';stream.feed(text.encode());expected.append(text)
            sync_capture(o,lambda row:row['event_id'])
            review=prepare_offload(o,directory,actor='operator')
            assert acknowledge_offload(o,directory,review['sha256'],actor='operator',confirmed=True,retention_receipt=retention_receipt(o,directory,review['sha256']))['released']>=1
            assert capture_status(o)['used_bytes']<32768
        stream.feed(b'EOF tail');stream.finish()
        sync_capture(o,lambda row:row['event_id'])
        review=prepare_offload(o,directory,actor='operator');acknowledge_offload(o,directory,review['sha256'],actor='operator',confirmed=True,retention_receipt=retention_receipt(o,directory,review['sha256']))
    latest=o.db.execute('SELECT sha256 FROM capture_offload_head').fetchone()[0];o.db.close()
    reopened=owner(tmp_path);rows=read_offload_chain(directory,latest,limit=100)
    assert [row['text'] for row in rows]==expected+['EOF tail']
    assert reopened.db.execute('SELECT count(*) FROM work_capture').fetchone()[0]==0
    reopened.db.close()


def test_no_release_without_delivery_exact_hash_and_confirmation(tmp_path):
    from arvyx_control.capture_offload import prepare_offload,acknowledge_offload
    o=owner(tmp_path);directory=tmp_path/'offload';directory.mkdir(mode=0o700)
    stream=WorkCapture(o,'sid');stream.feed(b'not delivered\n')
    with pytest.raises(ValueError):prepare_offload(o,directory,actor='operator')
    sync_capture(o,lambda row:row['event_id']);review=prepare_offload(o,directory,actor='operator')
    with pytest.raises(ValueError):acknowledge_offload(o,directory,review['sha256'],actor='operator',confirmed=False)
    with pytest.raises(ValueError):acknowledge_offload(o,directory,'0'*64,actor='operator',confirmed=True)
    assert o.db.execute('SELECT count(*) FROM work_capture').fetchone()[0]==1
    (directory/(review['sha256']+'.json')).write_text('{}')
    with pytest.raises(ValueError):acknowledge_offload(o,directory,review['sha256'],actor='operator',confirmed=True)
    assert o.db.execute('SELECT count(*) FROM work_capture').fetchone()[0]==1
    o.db.close()


def test_saturation_recovery_does_not_lose_refused_bytes(tmp_path):
    from arvyx_control.capture_offload import prepare_offload,acknowledge_offload
    o=owner(tmp_path);directory=tmp_path/'offload';directory.mkdir(mode=0o700)
    with patch('arvyx_control.cockpit_archive.CAPTURE_CAPACITY',32768):
        stream=WorkCapture(o,'sid');chunk=b'bounded '+b'x'*390+b'\n'
        count=0
        while count<100:
            try:stream.feed(chunk);count+=1
            except BufferError:break
        assert 0<count<100
        before=o.db.execute('SELECT count(*) FROM work_capture').fetchone()[0]
        sync_capture(o,lambda row:row['event_id'])
        review=prepare_offload(o,directory,actor='operator')
        acknowledge_offload(o,directory,review['sha256'],actor='operator',confirmed=True,retention_receipt=retention_receipt(o,directory,review['sha256']))
        stream.feed(chunk)
        assert o.db.execute('SELECT count(*) FROM work_capture').fetchone()[0]==1
        assert before==count
    o.db.close()
