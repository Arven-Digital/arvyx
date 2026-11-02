"""REV-0533: legacy scanner context follows the explicit provenance-recovery contract.

Maintained, executed successor of the authored-only
``private/rescue10_C_regressions_NOT_EXECUTED.py`` and
``private/focus75_agent14_regressions_NOT_EXECUTED.py`` legacy cases (those
copies still import the pre-rename package and carry a stale NativeRuntime
fixture without ``home``). Every case drives a real ``LocalCockpit`` owner,
its SQLite archive and the production ``WorkCapture`` / ``import_native`` /
``inspect_capture_context`` / ``reconcile_capture_context`` chain, reopening
the owner between phases. The native Hermes store is a synthetic SQLite file;
no native process is planned or started.

Contract under test: an unversioned (legacy) context is refused with
``ContextProvenanceRequired`` and nothing is imported or rewritten; recovery
needs an exact current proof, explicit confirmation and, for capture, a clean
boundary attestation; a failed reconciliation changes nothing; a successful one
quarantines the legacy context, retains all prior history and continues safely.
"""
from contextlib import contextmanager
import json
import sqlite3

import pytest

from arvyx_control import cockpit_archive as archive

# Synthetic delimiter words assembled at runtime; no key material anywhere.
OPEN = ' '.join(('BEGIN', 'RSA', 'PRIVATE', 'KEY'))
CLOSE = ' '.join(('END', 'RSA', 'PRIVATE', 'KEY'))
LEGACY_STATES = [
    ['RSA PRIVATE KEY', 'END R', None, ''],    # active block, partial ASCII ending
    ['RSA PRIVATE KEY', 'END R', None, 'c3'],  # active block, dangling UTF-8 lead byte
    [False, '', None, ''],                     # legacy "clear"
    [True, '', None, ''],                      # legacy active boolean
]


@contextmanager
def real_owner(root):
    from arvyx_control.cockpit import LocalCockpit
    from arvyx_control import cockpit_client, control
    from arvyx_control.replica_authority import authority_context
    vault = root / 'vault'
    state = root / 'events.jsonl'
    with authority_context(vault, state):
        if not vault.exists():
            cockpit_client.initialize(root)
        owner = LocalCockpit(root / 'runtime', vault, state, 'synthetic-privacy-host')
        if not owner.list():
            task = control.create_task(state, 'synthetic retained capture', owner='demobot').task
            sid = owner.open(project='demo-agent', task=task.id, name='synthetic', actor='operator')['id']
        else:
            sid = owner.list()[0]['id']
        try:
            yield owner, sid
        finally:
            owner.close()


def _capture_pem(owner, sid):
    return owner.db.execute('SELECT pem FROM capture_screen_context WHERE session=?', (sid,)).fetchone()[0]


def _quarantined(owner, table):
    column = 'session' if table == 'capture_screen_context' else 'run'
    return [json.loads(r[0]) for r in owner.db.execute(
        f"SELECT pem FROM {table} WHERE {column} LIKE 'quarantine-%'")]


def _feed(recorder, data, bytewise):
    for part in ([bytes([b]) for b in data] if bytewise else [data]):
        recorder.feed(part)


def _install_legacy_capture(root, legacy):
    with real_owner(root) as (owner, sid):
        recorder = archive.WorkCapture(owner, sid)
        recorder.feed('ordinary retained history 界\n'.encode())
        recorder.finish()
        with owner.db:
            owner.db.execute('UPDATE capture_screen_context SET pem=? WHERE session=?', (json.dumps(legacy), sid))
        return archive.pending_capture(owner)


@pytest.mark.parametrize('legacy', LEGACY_STATES)
@pytest.mark.parametrize('bytewise', [False, True])
def test_rev0533_legacy_capture_refused_then_explicitly_recovered(tmp_path, legacy, bytewise):
    before = _install_legacy_capture(tmp_path, legacy)
    with real_owner(tmp_path) as (owner, sid):
        # Refusal: nothing imported, legacy context byte-identical.
        with pytest.raises(archive.ContextProvenanceRequired):
            archive.WorkCapture(owner, sid)
        assert archive.pending_capture(owner) == before
        assert json.loads(_capture_pem(owner, sid)) == legacy
        proof = owner.inspect_capture_context(sid, actor='operator', kind='capture')
        # Failed reconciliations: unconfirmed, missing clean-boundary attestation,
        # forged proof, wrong kind. Each leaves context and history untouched.
        failures = [
            dict(kind='capture', expected=proof, confirmed=False, clean_boundary_confirmed=True),
            dict(kind='capture', expected=proof, confirmed=True),
            dict(kind='capture', expected=dict(proof, sha256='0' * 64), confirmed=True, clean_boundary_confirmed=True),
            dict(kind='bogus', expected=proof, confirmed=True, clean_boundary_confirmed=True),
        ]
        for failure in failures:
            with pytest.raises(ValueError):
                owner.reconcile_capture_context(sid, actor='operator', **failure)
            assert json.loads(_capture_pem(owner, sid)) == legacy
            assert archive.pending_capture(owner) == before
            assert _quarantined(owner, 'capture_screen_context') == []
        with pytest.raises(archive.ContextProvenanceRequired):
            archive.WorkCapture(owner, sid)
        result = owner.reconcile_capture_context(sid, actor='operator', kind='capture', expected=proof,
                                                 confirmed=True, clean_boundary_confirmed=True)
        assert result['reconciled'] is True and result['history_retained'] is True
        # A consumed proof cannot be replayed against the new state.
        with pytest.raises(ValueError):
            owner.reconcile_capture_context(sid, actor='operator', kind='capture', expected=proof,
                                            confirmed=True, clean_boundary_confirmed=True)
    with real_owner(tmp_path) as (owner, sid):
        recorder = archive.WorkCapture(owner, sid)
        # Fresh stream with multi-byte UTF-8 endings split across feeds, plus a
        # complete synthetic delimiter block whose body must never be captured.
        data = ('new safe capture café 界\n' + OPEN + '\nSYNTHETIC_BODY_0533\n' + CLOSE
                + '\nafter block é\n').encode()
        _feed(recorder, data, bytewise)
        recorder.finish()
        after = archive.pending_capture(owner)
        assert after[:len(before)] == before  # prior history retained exactly
        text = str(after[len(before):])
        assert 'new safe capture café 界' in text and 'after block é' in text
        assert 'SYNTHETIC_BODY_0533' not in text
        state = json.loads(_capture_pem(owner, sid))
        assert state['version'] == 2 and state['state'][0] is False
        assert _quarantined(owner, 'capture_screen_context') == [legacy]


def test_rev0533_stale_proof_preserves_exact_legacy_context(tmp_path):
    with real_owner(tmp_path) as (owner, sid):
        recorder = archive.WorkCapture(owner, sid)
        recorder.finish()
        raw = json.dumps(LEGACY_STATES[2])
        with owner.db:
            owner.db.execute('UPDATE capture_screen_context SET pem=? WHERE session=?', (raw, sid))
        proof = owner.inspect_capture_context(sid, actor='operator', kind='capture')
        changed = json.dumps(LEGACY_STATES[0])
        with owner.db:
            owner.db.execute('UPDATE capture_screen_context SET pem=? WHERE session=?', (changed, sid))
        before = archive.pending_capture(owner)
        with pytest.raises(ValueError, match='exact current'):
            owner.reconcile_capture_context(sid, actor='operator', kind='capture', expected=proof,
                                            confirmed=True, clean_boundary_confirmed=True)
        assert _capture_pem(owner, sid) == changed
        assert archive.pending_capture(owner) == before
        with pytest.raises(archive.ContextProvenanceRequired):
            archive.WorkCapture(owner, sid)


def _hermes(tmp_path, rows):
    from arvyx_control.cockpit_native_runtime import NativeRuntime
    from arvyx_control.hermes_profile import HermesProfile
    store = tmp_path / 'state.db'
    with sqlite3.connect(store) as db:
        db.execute('CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY,session_id TEXT,role TEXT,content TEXT)')
        db.executemany('INSERT INTO messages VALUES(?,?,?,?)', [(i, 'conversation', 'assistant', c) for i, c in rows])
    runtime = NativeRuntime.__new__(NativeRuntime)
    runtime.tool, runtime.store, runtime.home = 'hermes', store, tmp_path
    runtime.profile = HermesProfile(tmp_path, store)
    runtime.plan = lambda *a: None  # metadata fixture only; never starts a native process
    return runtime


def _native_cursor(owner):
    return owner.db.execute("SELECT cursor FROM native_archive_context WHERE run NOT LIKE 'quarantine-%'").fetchone()[0]


@pytest.mark.parametrize('legacy', LEGACY_STATES)
def test_rev0533_native_legacy_context_retains_cursor_then_reimports_exact_source(tmp_path, legacy):
    runtime = _hermes(tmp_path, [(1, 'ordinary history'), (6, OPEN), (7, 'END Ré')])
    with real_owner(tmp_path) as (owner, sid):
        owner.native_runtimes['hermes'] = runtime
        owner.bind_native(sid, tool='hermes', conversation='conversation', actor='operator')
        assert owner.native_archive(sid, actor='operator')['cursor'] == 7
        with owner.db:
            owner.db.execute('UPDATE native_archive_context SET pem=?', (json.dumps(legacy),))
        before = archive.pending_capture(owner)
    _hermes(tmp_path, [(8, 'SA PRIVATE KEY'), (9, 'SYNTHETIC_PRIVATE_SUFFIX')])
    with real_owner(tmp_path) as (owner, sid):
        owner.native_runtimes['hermes'] = runtime
        with pytest.raises(archive.ContextProvenanceRequired):
            owner.native_archive(sid, actor='operator')
        assert _native_cursor(owner) == 7 and archive.pending_capture(owner) == before
        proof = owner.inspect_capture_context(sid, actor='operator', kind='native')
        for failure in (dict(expected=proof, confirmed=False), dict(expected=dict(proof, sha256='0' * 64), confirmed=True)):
            with pytest.raises(ValueError):
                owner.reconcile_capture_context(sid, actor='operator', kind='native', **failure)
            assert _native_cursor(owner) == 7 and archive.pending_capture(owner) == before
            assert json.loads(owner.db.execute('SELECT pem FROM native_archive_context').fetchone()[0]) == legacy
        owner.reconcile_capture_context(sid, actor='operator', kind='native', expected=proof, confirmed=True)
        result = owner.native_archive(sid, actor='operator')
        assert result['cursor'] == 9 and result['imported'] == 5  # reimport from zero
        assert archive.pending_capture(owner)[:len(before)] == before
        assert 'SYNTHETIC_PRIVATE_SUFFIX' not in str(archive.pending_capture(owner)[len(before):])
        assert _quarantined(owner, 'native_archive_context') == [legacy]
    with real_owner(tmp_path) as (owner, sid):
        owner.native_runtimes['hermes'] = runtime
        assert owner.native_archive(sid, actor='operator')['imported'] == 0


def test_rev0533_native_recovery_carries_scanner_state_across_page_boundary(tmp_path):
    # 150 messages: the delimiter opens on the last row of page one (id 100), the
    # body is the first row of page two, and the block closes on id 102.
    rows = [(i, f'ordinary {i} 界') for i in range(1, 151)]
    rows[99] = (100, OPEN)
    rows[100] = (101, 'SYNTHETIC_PAGE_BODY_0533')
    rows[101] = (102, CLOSE)
    runtime = _hermes(tmp_path, rows)
    with real_owner(tmp_path) as (owner, sid):
        owner.native_runtimes['hermes'] = runtime
        owner.bind_native(sid, tool='hermes', conversation='conversation', actor='operator')
        first = owner.native_archive(sid, actor='operator')
        assert first['cursor'] == 100 and first['has_more']
        with owner.db:
            owner.db.execute('UPDATE native_archive_context SET pem=?', (json.dumps(LEGACY_STATES[2]),))
        before = archive.pending_capture(owner)
    with real_owner(tmp_path) as (owner, sid):
        owner.native_runtimes['hermes'] = runtime
        with pytest.raises(archive.ContextProvenanceRequired):
            owner.native_archive(sid, actor='operator')
        proof = owner.inspect_capture_context(sid, actor='operator', kind='native')
        owner.reconcile_capture_context(sid, actor='operator', kind='native', expected=proof, confirmed=True)
        page = owner.native_archive(sid, actor='operator')
        assert page['cursor'] == 100 and page['imported'] == 100 and page['has_more']
    with real_owner(tmp_path) as (owner, sid):  # restart between pages
        owner.native_runtimes['hermes'] = runtime
        page = owner.native_archive(sid, actor='operator')
        assert page['cursor'] == 150 and page['imported'] == 50
        after = archive.pending_capture(owner)
        assert after[:len(before)] == before
        added = str(after[len(before):])
        assert 'SYNTHETIC_PAGE_BODY_0533' not in added
        assert 'ordinary 103 界' in added and 'ordinary 150 界' in added
        assert owner.native_archive(sid, actor='operator')['imported'] == 0
