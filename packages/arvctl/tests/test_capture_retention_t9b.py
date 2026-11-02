import copy

from unittest.mock import patch

import pytest

from arvyx_control.capture_offload import (
    acknowledge_offload, head, prepare_offload, relocate_offload_storage,
    storage_identity,
)
from arvyx_control.capture_retention import revoke, verify
from arvyx_control.cockpit_archive import WorkCapture, sync_capture
from retention_fixture_helpers import retention_receipt
from test_pass3_capture_offload import owner


def prepared(tmp_path):
    o = owner(tmp_path)
    directory = tmp_path/'offload'
    directory.mkdir(mode=0o700)
    stream = WorkCapture(o, 'sid')
    stream.feed(b'retained history\n')
    sync_capture(o, lambda row: row['event_id'])
    review = prepare_offload(o, directory, actor='operator')
    return o, directory, review


def ack(o, directory, review, receipt):
    return acknowledge_offload(o, directory, review['sha256'], actor='operator',
                               confirmed=True, retention_receipt=receipt)


def unchanged(o):
    assert head(o) == ('', 0)
    assert o.db.execute('SELECT count(*) FROM work_capture').fetchone()[0] == 1
    assert o.db.execute('SELECT count(*) FROM capture_retention_accepted').fetchone()[0] == 0


def test_ordinary_directory_is_not_retention_authority(tmp_path):
    o, directory, review = prepared(tmp_path)
    with pytest.raises(ValueError, match='retention receipt'):
        ack(o, directory, review, None)
    unchanged(o)
    o.db.close()


def test_signed_qualified_fixture_admission_and_replay(tmp_path):
    o, directory, review = prepared(tmp_path)
    receipt = retention_receipt(o, directory, review['sha256'])
    assert ack(o, directory, review, receipt)['released'] == 1
    assert o.db.execute('SELECT count(*) FROM capture_retention_accepted').fetchone()[0] == 1
    with pytest.raises(ValueError, match='prefix'):
        ack(o, directory, review, receipt)
    assert head(o)[0] == review['sha256']
    o.db.close()


@pytest.mark.parametrize('field,value', [
    ('head', '0'*64), ('operation', 'relocate'), ('through', True),
    ('owner_database', {'device': 0, 'inode': 0}), ('qualification', '0'*64),
])
def test_wrong_bound_scope_preserves_local_rows(tmp_path, field, value):
    o, directory, review = prepared(tmp_path)
    receipt = retention_receipt(o, directory, review['sha256'])
    receipt['payload'][field] = value
    with pytest.raises(ValueError):
        ack(o, directory, review, receipt)
    unchanged(o)
    o.db.close()


def test_tampered_signature_preserves_local_rows(tmp_path):
    o, directory, review = prepared(tmp_path)
    receipt = retention_receipt(o, directory, review['sha256'])
    receipt['signature'] = '0'*128
    with pytest.raises(ValueError, match='signature invalid'):
        ack(o, directory, review, receipt)
    unchanged(o)
    o.db.close()


def test_expired_receipt_does_not_release(tmp_path):
    o, directory, review = prepared(tmp_path)
    receipt = retention_receipt(o, directory, review['sha256'])
    with patch('arvyx_control.capture_retention.time.time', return_value=receipt['payload']['admit_before']):
        with pytest.raises(ValueError, match='expired'):
            ack(o, directory, review, receipt)
    unchanged(o)
    o.db.close()


def test_final_writer_reservation_rechecks_expiry(tmp_path):
    o, directory, review = prepared(tmp_path)
    receipt = retention_receipt(o, directory, review['sha256'])
    now = receipt['payload']['issued_at']
    # First continuation admission is valid; final admission after writer wait
    # expires. No SQL delete/head rebind may have happened.
    with patch('arvyx_control.capture_retention.time.time', side_effect=[now, now+3600]):
        with pytest.raises(ValueError, match='expired'):
            ack(o, directory, review, receipt)
    unchanged(o)
    o.db.close()


def test_revoked_pin_cannot_admit_or_reenroll(tmp_path):
    from arvyx_control.capture_retention import trust
    o, directory, review = prepared(tmp_path)
    receipt = retention_receipt(o, directory, review['sha256'])
    public = o.db.execute('SELECT public_key FROM capture_retention_trust').fetchone()[0]
    revoke(o, receipt['payload']['key_id'], actor='operator', confirmed=True)
    with pytest.raises(ValueError, match='revoked'):
        ack(o, directory, review, receipt)
    with pytest.raises(ValueError, match='immutable'):
        trust(o, storage_identity(directory), public, receipt['payload']['qualification'], actor='operator', confirmed=True)
    unchanged(o)
    o.db.close()


def test_relocation_requires_distinct_target_complete_commitment(tmp_path):
    o, directory, review = prepared(tmp_path)
    receipt = retention_receipt(o, directory, review['sha256'])
    ack(o, directory, review, receipt)
    target = tmp_path/'target'
    target.mkdir(mode=0o700)
    # Copying mutable bytes is not authority; no receipt must keep old binding.
    (target/(review['sha256']+'.json')).write_bytes((directory/(review['sha256']+'.json')).read_bytes())
    old = tuple(o.db.execute('SELECT directory,device,inode FROM capture_offload_storage').fetchone())
    with pytest.raises(ValueError):
        relocate_offload_storage(o, target, actor='operator', expected_head=review['sha256'], confirmed=True)
    assert tuple(o.db.execute('SELECT directory,device,inode FROM capture_offload_storage').fetchone()) == old
    target_receipt = retention_receipt(o, target, review['sha256'], kind='relocate')
    result = relocate_offload_storage(o, target, actor='operator', expected_head=review['sha256'], confirmed=True, retention_receipt=target_receipt)
    assert result['released'] == 0
    assert result['storage'] == storage_identity(target)
    assert (directory/(review['sha256']+'.json')).exists()
    o.db.close()


def test_continuation_revalidates_trust_not_saved_cursor(tmp_path):
    from arvyx_control.capture_offload_verify import OffloadContinuationRequired
    o, directory, review = prepared(tmp_path)
    receipt = retention_receipt(o, directory, review['sha256'])
    ack(o, directory, review, receipt)
    stream = WorkCapture(o, 'sid')
    stream.feed(b'second retained generation\n')
    sync_capture(o, lambda row: row['event_id'])
    second = prepare_offload(o, directory, actor='operator')
    receipt = retention_receipt(o, directory, second['sha256'])
    with pytest.raises(OffloadContinuationRequired):
        acknowledge_offload(o, directory, second['sha256'], actor='operator', confirmed=True, retention_receipt=receipt, verification_limit=1)
    before = head(o)
    revoke(o, receipt['payload']['key_id'], actor='operator', confirmed=True)
    with pytest.raises(ValueError, match='revoked'):
        acknowledge_offload(o, directory, second['sha256'], actor='operator', confirmed=True, retention_receipt=receipt, verification_limit=1)
    assert head(o) == before
    assert o.db.execute('SELECT count(*) FROM work_capture').fetchone()[0] == 1
    o.db.close()


def test_no_receipt_issuer_or_unbounded_walk_fallback_in_product():
    # Source-only invariant test, still NOT_EXECUTED with this task's bans.
    import ast
    from pathlib import Path
    root = Path(__file__).parents[1]/'src/arvyx_control'
    tree = ast.parse((root/'capture_retention.py').read_text())
    assert not any(isinstance(n, ast.Attribute) and n.attr in {'sign', 'generate'} for n in ast.walk(tree))
    offload = ast.parse((root/'capture_offload_verify.py').read_text())
    assert any(isinstance(n, ast.For) and isinstance(n.iter, ast.Call) and isinstance(n.iter.func, ast.Name) and n.iter.func.id == 'range' for n in ast.walk(offload))


def test_authenticated_same_commitment_renewal_keeps_bounded_progress_identity(tmp_path):
    from arvyx_control.capture_retention import encoded
    o, directory, review = prepared(tmp_path)
    original = retention_receipt(o,directory,review['sha256'])
    now = original['payload']['issued_at']
    renewed = copy.deepcopy(original)
    renewed['payload']['issued_at'] = now+3600
    renewed['payload']['admit_before'] = now+7200
    fixture = next(iter(o._synthetic_retention_stores.values()))
    renewed['signature'] = fixture['signer'].sign(encoded(renewed['payload'])).hex()
    with patch('arvyx_control.capture_retention.time.time', return_value=now):
        first = verify(o,original,storage_identity(directory),review['sha256'],review['through'],'ack')
    with patch('arvyx_control.capture_retention.time.time', return_value=now+3600):
        second = verify(o,renewed,storage_identity(directory),review['sha256'],review['through'],'ack')
        with pytest.raises(ValueError,match='expired'):
            verify(o,original,storage_identity(directory),review['sha256'],review['through'],'ack')
    assert first == second
    changed = copy.deepcopy(renewed)
    changed['payload']['generation'] = 'f'*64
    changed['signature'] = fixture['signer'].sign(encoded(changed['payload'])).hex()
    with patch('arvyx_control.capture_retention.time.time', return_value=now+3600):
        assert verify(o,changed,storage_identity(directory),review['sha256'],review['through'],'ack') != first
    unchanged(o)
    o.db.close()


def test_removed_visited_cache_segment_has_independent_retained_version(tmp_path):
    import hashlib
    from arvyx_control.capture_offload_verify import OffloadContinuationRequired
    o, directory, first = prepared(tmp_path)
    ack(o,directory,first,retention_receipt(o,directory,first['sha256']))
    reviews=[]
    for text in (b'second segment\n', b'third segment\n'):
        stream=WorkCapture(o,'sid')
        stream.feed(text)
        sync_capture(o,lambda row:row['event_id'])
        review=prepare_offload(o,directory,actor='operator')
        reviews.append(review)
        if len(reviews)==1:
            ack(o,directory,review,retention_receipt(o,directory,review['sha256']))
    latest=reviews[-1]
    receipt=retention_receipt(o,directory,latest['sha256'])
    for _ in range(2):
        with pytest.raises(OffloadContinuationRequired):
            acknowledge_offload(o,directory,latest['sha256'],actor='operator',confirmed=True,retention_receipt=receipt,verification_limit=1)
    visited=reviews[0]['sha256']
    (directory/(visited+'.json')).unlink()
    # Safe ONLY with the independently retained synthetic version. The directory
    # identity and old read observations are not the pruning permit.
    retained=next(iter(o._synthetic_retention_stores.values()))['objects'][visited]
    assert hashlib.sha256(retained).hexdigest()==visited
    result=acknowledge_offload(o,directory,latest['sha256'],actor='operator',confirmed=True,retention_receipt=receipt,verification_limit=1)
    assert result['released']==1
    assert o.db.execute('SELECT count(*) FROM work_capture').fetchone()[0]==0
    assert hashlib.sha256(retained).hexdigest()==visited
    o.db.close()
