"""Capture offload liveness: REV-0529, REV-0544, REV-0549 and the REV-0512 storage fence.

Production paths run unchanged. Substituted boundaries: the shared archive
team transport (an in-memory recorder) and the external retention issuer (a
synthetic Ed25519 fixture store from retention_fixture_helpers, which proves
the source admission protocol only, never physical retention).
"""
import hashlib
import json
from types import SimpleNamespace
from unittest.mock import patch

import os
import pytest

from retention_fixture_helpers import retention_receipt
from test_local_onboarding_services import services  # noqa: F401  (fixture)
from test_session_workspace_journey import journey  # noqa: F401  (fixture)
from test_completion_fix4_C import native_owner, saved_session  # noqa: F401  (fixture)

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='host-shell execution policy (host_uid) and the PTY owner are POSIX-only')


def _until_complete(effect, attempts=64):
    from arvyx_control.capture_offload_verify import OffloadContinuationRequired
    for _ in range(attempts):
        try:
            return effect()
        except OffloadContinuationRequired:
            pass
    pytest.fail('bounded continuation never completed')


def _rows(owner):
    return [dict(row) for row in owner.db.execute('SELECT session,text,delivered FROM work_capture ORDER BY sequence')]


def _mixed_cockpit(native_owner):
    owner, _, ext, _, target, root, _ = native_owner
    local = saved_session(owner, ext.owner.creation.db, target, root, 0)['owner_session']
    owner.db.execute("INSERT INTO sessions VALUES('work','project','task','work',?,'stopped',NULL,'work')", (str(root/'existing'),))
    owner.db.commit()
    projects = owner.vault/'registry/projects'; projects.mkdir(exist_ok=True)
    (projects/'project.json').write_text(json.dumps(dict(owner_agent_id='agent-a')))
    receipts = {}; sent = []

    def team_call(method, path, payload=None):
        if method == 'POST':
            sent.append(payload)
            canonical = {k: v for k, v in payload.items() if k not in {'actor', 'idempotency_key'}}
            receipt = dict(event_id=payload['event_id'], sha256=hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest(), recorded=True)
            receipts[payload['event_id']] = receipt
            return SimpleNamespace(status=201, body=receipt)
        return SimpleNamespace(status=200, body=receipts[path.rsplit('/', 1)[1]])
    owner.team = SimpleNamespace(_call=team_call)

    def sync():
        with patch.object(owner.archive_stop, 'wait', side_effect=[False, False, True]):
            owner._sync_archive()
    return owner, local, sync, sent


def test_rev0549_rev0529_refused_local_row_does_not_block_mixed_capacity_recovery(native_owner, tmp_path):
    from arvyx_control.capture_offload import read_offload_chain
    from arvyx_control.cockpit_archive import WorkCapture, capture_status
    owner, local, sync, sent = _mixed_cockpit(native_owner)
    directory = tmp_path/'offload'; directory.mkdir(mode=0o700)
    # Local capture reaches the global head before ordinary work capture.
    WorkCapture(owner, local).feed(b'synthetic local first\n')
    WorkCapture(owner, 'work').feed(b'synthetic work delivered\n')
    sync()
    assert [p['session'] for p in sent] == ['work']
    assert _rows(owner) == [dict(session=local, text='synthetic local first\n', delivered=0),
                            dict(session='work', text='synthetic work delivered\n', delivered=1)]
    # The delivery acknowledgement never crosses the refused local row.
    with pytest.raises(ValueError, match='no contiguous'):
        owner.prepare_capture_offload(directory, actor='operator')
    # Later ordinary work output that is still pending shared delivery.
    WorkCapture(owner, 'work').feed(b'synthetic work pending\n')
    review = _until_complete(lambda: owner.prepare_capture_offload(directory, actor='operator', acknowledgement='local-archive'))
    # Explicit local-archive crosses the refused local row and delivered work,
    # but never abandons the pending ordinary row's shared delivery.
    assert review['records'] == 2
    before = _rows(owner)
    # Pruning still requires qualified retention admission.
    with pytest.raises(ValueError):
        owner.acknowledge_capture_offload(directory, review['sha256'], actor='operator', confirmed=True)
    assert _rows(owner) == before
    receipt = retention_receipt(owner, directory, review['sha256'])
    result = _until_complete(lambda: owner.acknowledge_capture_offload(directory, review['sha256'], actor='operator', confirmed=True, retention_receipt=receipt))
    assert result['released'] == 2
    assert _rows(owner) == [dict(session='work', text='synthetic work pending\n', delivered=0)]
    # The pending work row is still delivered by the ordinary governed pump.
    sync()
    assert [p['session'] for p in sent] == ['work', 'work'] and _rows(owner)[0]['delivered'] == 1
    review = _until_complete(lambda: owner.prepare_capture_offload(directory, actor='operator'))
    receipt = retention_receipt(owner, directory, review['sha256'])
    _until_complete(lambda: owner.acknowledge_capture_offload(directory, review['sha256'], actor='operator', confirmed=True, retention_receipt=receipt))
    history = read_offload_chain(directory, review['sha256'])
    # Every row retained once, with its original flags: no fabricated delivery.
    assert [(r['session'], r['text'], r['delivered']) for r in history] == [
        (local, 'synthetic local first\n', 0), ('work', 'synthetic work delivered\n', 1), ('work', 'synthetic work pending\n', 1)]
    assert all(p['session'] != local for p in sent)
    attention = owner.db.execute('SELECT kind FROM session_attention WHERE session=?', (local,)).fetchone()
    assert attention and attention['kind'] == 'archive-refused'
    assert capture_status(owner)['used_bytes'] >= 0


def test_rev0549_local_capture_saturation_recovers_and_capture_continues(native_owner, tmp_path):
    from arvyx_control.capture_offload import read_offload_chain
    from arvyx_control.cockpit_archive import WorkCapture
    owner, local, sync, sent = _mixed_cockpit(native_owner)
    directory = tmp_path/'offload'; directory.mkdir(mode=0o700)
    chunk = b'synthetic local '+b'x'*390+b'\n'
    with patch('arvyx_control.cockpit_archive.CAPTURE_CAPACITY', 32768):
        stream = WorkCapture(owner, local); written = 0
        while written < 200:
            try:
                stream.feed(chunk); written += 1
            except BufferError:
                break
        assert 0 < written < 200  # the shared quota backpressured local output
        sync()
        assert sent == [] and all(r['delivered'] == 0 for r in _rows(owner))
        with pytest.raises(BufferError):
            stream.feed(chunk)
        heads = []
        while owner.db.execute('SELECT count(*) FROM work_capture').fetchone()[0]:
            review = _until_complete(lambda: owner.prepare_capture_offload(directory, actor='operator', acknowledgement='local-archive'))
            receipt = retention_receipt(owner, directory, review['sha256'])
            _until_complete(lambda: owner.acknowledge_capture_offload(directory, review['sha256'], actor='operator', confirmed=True, retention_receipt=receipt))
            heads.append(review['sha256'])
        stream.feed(chunk)  # capacity recovered: capture progresses again
        assert len(_rows(owner)) == 1
    retained = read_offload_chain(directory, heads[-1], limit=1000)
    assert len(retained) == written and all(r['delivered'] == 0 and r['session'] == local for r in retained)
    assert sent == []


def test_rev0544_bounded_traversal_progresses_per_call_and_resumes_after_reopen(tmp_path):
    from test_pass3_capture_offload import owner as fake_owner
    from arvyx_control import capture_offload as offload
    from arvyx_control.capture_offload_verify import OffloadContinuationRequired
    from arvyx_control.cockpit_archive import WorkCapture, sync_capture
    o = fake_owner(tmp_path); directory = tmp_path/'offload'; directory.mkdir()
    expected = []
    limit = 2
    try:
        with patch.object(offload, 'MAX_CHAIN', 2), patch.object(offload, 'MAX_VERIFY_BUNDLES', limit):
            # Build a history several times longer than both budgets.
            for i in range(9):
                text = 'synthetic '+str(i)+'\n'; expected.append(text)
                WorkCapture(o, 'sid').feed(text.encode()); sync_capture(o, lambda row: row['event_id'])
                review = _until_complete(lambda: offload.prepare_offload(o, directory, actor='operator'))
                receipt = retention_receipt(o, directory, review['sha256'])
                _until_complete(lambda: offload.acknowledge_offload(o, directory, review['sha256'], actor='operator', confirmed=True, retention_receipt=receipt))
            WorkCapture(o, 'sid').feed(b'synthetic tail\n'); sync_capture(o, lambda row: row['event_id']); expected.append('synthetic tail\n')
            # Each call reads at most `limit` bundles and durably advances the cursor.
            reads = []
            real = offload.bundle_read
            def counting(*a, **k):
                reads.append(a[1]); return real(*a, **k)
            cursors = []
            with patch.object(offload, 'bundle_read', counting):
                for _ in range(2):
                    reads.clear()
                    with pytest.raises(OffloadContinuationRequired):
                        offload.prepare_offload(o, directory, actor='operator')
                    assert len(reads) == limit
                    cursors.append(o.db.execute('SELECT next_through FROM capture_offload_verification').fetchone()[0])
            assert cursors[0] > cursors[1] > 0
            # Reopen mid-walk: the persisted cursor resumes rather than restarting.
            retained = o._synthetic_retention_stores; o.db.close(); o = fake_owner(tmp_path); o._synthetic_retention_stores = retained
            calls = 0
            def attempt():
                nonlocal calls
                calls += 1
                return offload.prepare_offload(o, directory, actor='operator')
            review = _until_complete(attempt)
            remaining = cursors[1]  # one bundle per offload in this history
            assert calls == -(-remaining // limit)
            receipt = retention_receipt(o, directory, review['sha256'])
            result = _until_complete(lambda: offload.acknowledge_offload(o, directory, review['sha256'], actor='operator', confirmed=True, retention_receipt=receipt))
            assert result['released'] == 1
            assert [r['text'] for r in offload.read_offload_chain(directory, result['sha256'])] == expected
            # Bounded pages reach genesis without any reset.
            page = offload.read_offload_page(directory, result['sha256'], limit=3); seen = len(page['bundles'])
            while page['next_sha256']:
                page = offload.read_offload_page(directory, page['next_sha256'], through=page['next_through'], limit=3); seen += len(page['bundles'])
            assert seen == 10
    finally:
        o.db.close()


def test_rev0512_destination_change_is_refused_until_verified_complete_relocation(tmp_path):
    from test_pass3_capture_offload import owner as fake_owner
    from arvyx_control import capture_offload as offload
    from arvyx_control.cockpit_archive import WorkCapture, sync_capture
    o = fake_owner(tmp_path); a = tmp_path/'A'; b = tmp_path/'B'; a.mkdir(); b.mkdir()
    try:
        WorkCapture(o, 'sid').feed(b'synthetic one\n'); sync_capture(o, lambda row: row['event_id'])
        first = offload.prepare_offload(o, a, actor='operator')
        offload.acknowledge_offload(o, a, first['sha256'], actor='operator', confirmed=True, retention_receipt=retention_receipt(o, a, first['sha256']))
        WorkCapture(o, 'sid').feed(b'synthetic two\n'); sync_capture(o, lambda row: row['event_id'])
        before = (_rows(o), offload.head(o))
        # Original trigger: prepare/acknowledge into empty B.
        with pytest.raises(ValueError, match='storage changed'):
            offload.prepare_offload(o, b, actor='operator')
        assert list(b.iterdir()) == [] and (_rows(o), offload.head(o)) == before
        # Relocation without an exact qualified complete-chain commitment is refused.
        with pytest.raises(ValueError):
            offload.relocate_offload_storage(o, b, actor='operator', expected_head=first['sha256'], confirmed=True, copy_from_bound=True)
        # A receipt signed for A does not authorize rebinding to B.
        with pytest.raises(ValueError):
            offload.relocate_offload_storage(o, b, actor='operator', expected_head=first['sha256'], confirmed=True, copy_from_bound=True,
                                             retention_receipt=retention_receipt(o, a, first['sha256'], kind='relocate'))
        assert (_rows(o), offload.head(o)) == before
        assert o.db.execute('SELECT directory FROM capture_offload_storage').fetchone()[0] == str(a)
        # Explicit verified complete relocation, then continued release into B.
        receipt = retention_receipt(o, b, first['sha256'], kind='relocate', retained_source=a)
        offload.relocate_offload_storage(o, b, actor='operator', expected_head=first['sha256'], confirmed=True, copy_from_bound=True, retention_receipt=receipt)
        second = offload.prepare_offload(o, b, actor='operator')
        offload.acknowledge_offload(o, b, second['sha256'], actor='operator', confirmed=True, retention_receipt=retention_receipt(o, b, second['sha256']))
        assert [r['text'] for r in offload.read_offload_chain(b, second['sha256'])] == ['synthetic one\n', 'synthetic two\n']
        with pytest.raises(ValueError, match='storage changed'):
            offload.prepare_offload(o, a, actor='operator')
    finally:
        o.db.close()
