"""Lane A regressions: disposable vaults, no services or provider I/O."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from arvyx_control import checkpoint_jobs as jobs, forget, importers, index
from arvyx_control.external_memory import reviewed_memory_snapshot
from arvyx_control.memory_frontmatter import frontmatter_values
from arvyx_control.recall import excerpt, recall
from arvyx_control.replica_authority import authority_context
from arvyx_control.security import redact_secrets
from arvyx_control.writes import promote_memory

NOW = datetime(2026, 10, 29, tzinfo=timezone.utc)
SEPARATORS = ('\n', '\r\n', '\r', '\v', '\f', '\x1c', '\x1d', '\x1e', '\x85', '\u2028', '\u2029')
IMPORTERS = (importers.import_markdown, importers.import_obsidian, importers.import_basic_memory)


def note(root, relative='projects/demo/notes/note.md', text='# Evidence\nPublic recallable evidence.\n'):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode())
    return path


def forgotten(root):
    path = note(root)
    with authority_context(root):
        result = forget.soft_forget(root, 'demo', path.relative_to(root).as_posix(),
                                    'superseded', 'batch-demo', 'operator', 'forget-lane-A-0001')
    return path, result


def restore(root, result, key='restore-lane-A-0001'):
    with authority_context(root):
        return forget.restore_forgotten(root, result.tombstone_path, 'operator', key)


def witness(root, key='restore-lane-A-0001'):
    receipt = forget._operation_path(root, key)
    intent = json.loads(receipt.with_suffix('.intent.json').read_text())
    return receipt, root / intent['stage_path']


def assert_export(root, path):
    selection = {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()}
    with authority_context(root):
        snapshot = reviewed_memory_snapshot(root, selection)
        from arvyx_control.external_api import ExternalAPI
        from arvyx_control.external_grants import ExternalGrantStore
        store = ExternalGrantStore(root / 'grants.sqlite3', clock=lambda: NOW)
        try:
            api = ExternalAPI(store, root / 'work.sqlite3', credentials={}, workspaces={}, tasks=(),
                              vault=root, memory_selections={'artifact:restored': selection})
            api.close()
        finally:
            store.close()
    assert [f.path for f in snapshot.files] == list(selection)


def test_restored_file_can_be_reviewed_and_external_api_can_reopen(tmp_path):
    path, result = forgotten(tmp_path)
    restored = restore(tmp_path, result)
    assert_export(tmp_path, path)
    assert path.stat().st_nlink == 1
    assert restore(tmp_path, result) == restored
    assert_export(tmp_path, path)
    # Arbitrary hard links remain forbidden by the export reader.
    os.link(path, path.with_suffix('.alias'))
    with authority_context(tmp_path), pytest.raises(ValueError, match='singly-linked'):
        reviewed_memory_snapshot(tmp_path, {path.relative_to(tmp_path).as_posix():
                                           hashlib.sha256(path.read_bytes()).hexdigest()})


@pytest.mark.parametrize('phase', ['before-receipt', 'receipt-barrier', 'unlink', 'cleanup-barrier'])
def test_restore_interruption_preserves_witness_until_durable_completion(tmp_path, phase):
    path, result = forgotten(tmp_path)
    receipt = forget._operation_path(tmp_path, 'restore-lane-A-0001')
    real_json, real_sync, real_unlink = forget._atomic_json, forget._fsync_dir, Path.unlink

    def write_json(target, payload):
        if phase == 'before-receipt' and target == receipt:
            raise OSError('receipt interrupted')
        return real_json(target, payload)

    def sync(directory):
        if receipt.exists():
            stage = witness(tmp_path)[1]
            if phase == 'receipt-barrier' and directory == receipt.parent:
                raise OSError('receipt barrier interrupted')
            if phase == 'cleanup-barrier' and directory == path.parent and not stage.exists():
                raise OSError('cleanup barrier interrupted')
        return real_sync(directory)

    def unlink(target, *args, **kwargs):
        if phase == 'unlink' and str(target).endswith('.stage') and target.parent == path.parent:
            assert receipt.exists(), 'witness cleanup preceded completion'
            raise OSError('unlink interrupted')
        return real_unlink(target, *args, **kwargs)

    with patch.object(forget, '_atomic_json', side_effect=write_json), \
            patch.object(forget, '_fsync_dir', side_effect=sync), patch.object(Path, 'unlink', unlink):
        with pytest.raises(OSError, match='interrupted'):
            restore(tmp_path, result)
    _, stage = witness(tmp_path)
    if phase in ('before-receipt', 'receipt-barrier', 'unlink'):
        assert stage.exists()
        assert path.stat().st_ino == stage.stat().st_ino
    else:
        assert not stage.exists()
    with patch.object(forget, '_fsync_dir', wraps=real_sync) as barriers:
        restore(tmp_path, result)
    assert path.parent in [c.args[0] for c in barriers.call_args_list]
    assert not stage.exists()
    assert_export(tmp_path, path)


@pytest.mark.parametrize('importer', IMPORTERS)
@pytest.mark.parametrize('newline', ['\n', '\r\n', '\r'])
def test_import_preserves_relations_through_promotion(tmp_path, importer, newline):
    root = tmp_path / 'vault'
    parent = note(root, 'projects/demo/notes/parent.md', '---\nstatus: promoted\n---\n# Parent\nOriginal truth\n')
    relations = [{'type': 'updates', 'parent_source_path': parent.relative_to(root).as_posix()}]
    original = ('---\nid: replacement\nproject: demo\ntags: [original]\nrelations: '
                + json.dumps(relations) + '\n---\n# Child\nReplacement truth\n')
    source = tmp_path / 'child.md'
    source.write_bytes(original.replace('\n', newline).encode())
    with authority_context(root):
        result = importer(source, root, 'demo')
        imported = root / result.imported[0]
        assert frontmatter_values(imported.read_text())['id'] == 'replacement'
        promoted = promote_memory(root, 'demo', result.imported[0], 'operator')
    assert json.loads(frontmatter_values((root / promoted.target).read_text())['relations']) == relations
    assert frontmatter_values(parent.read_text())['status'] == 'superseded'


@pytest.mark.parametrize('importer', IMPORTERS)
@pytest.mark.parametrize('newline', ['\n', '\r\n', '\r'])
def test_import_keeps_invalid_relations_operative_for_refusal(tmp_path, importer, newline):
    root = tmp_path / 'vault'
    root.mkdir()
    source = tmp_path / 'child.md'
    source.write_bytes(('---\nid: replacement\nrelations: invalid\n---\n# Child\nBody\n').replace('\n', newline).encode())
    with authority_context(root):
        result = importer(source, root, 'demo')
        with pytest.raises(ValueError, match='invalid persisted relation'):
            promote_memory(root, 'demo', result.imported[0], 'operator')
    assert (root / result.imported[0]).exists()
    assert not list((root / 'projects/demo/notes').glob('*.md'))


@pytest.mark.parametrize('when', ['admission', 'artifact-validation'])
@pytest.mark.parametrize('change', ['add', 'remove', 'edit'])
def test_completed_rebuild_rejects_manifest_drift_and_next_call_recovers(tmp_path, when, change):
    path = note(tmp_path) if change != 'add' else tmp_path / 'projects/demo/notes/note.md'
    with authority_context(tmp_path):
        jobs.rebuild_index_checkpointed(tmp_path, owner='worker', now=NOW)
    real = jobs._start_attempt if when == 'admission' else jobs._cache_matches_manifest

    def raced(*args, **kwargs):
        if change == 'add':
            note(tmp_path)
        elif change == 'remove':
            path.unlink()
        else:
            path.write_text('# Changed\nDifferent evidence\n')
        return real(*args, **kwargs)

    name = '_start_attempt' if when == 'admission' else '_cache_matches_manifest'
    with authority_context(tmp_path), patch.object(jobs, name, side_effect=raced):
        with pytest.raises(jobs.SourceDriftError):
            jobs.rebuild_index_checkpointed(tmp_path, owner='worker', now=NOW)
    with authority_context(tmp_path):
        status = jobs.rebuild_index_checkpointed(tmp_path, owner='worker', now=NOW)
    assert status.status == 'completed'
    assert status.checkpoint == status.total
    assert set(index._read_cache(tmp_path)) == set(index._current_file_stats(tmp_path))


@pytest.mark.parametrize('damage', [0.0, 1.0, 999999999999.0, None])
@pytest.mark.parametrize('route', ['recall', 'completed', 'checkpoint'])
def test_cached_timestamp_damage_does_not_change_recency(tmp_path, damage, route):
    for name, date in [('old', '2020-01-01'), ('recent', '2026-10-28')]:
        note(tmp_path, f'projects/demo/notes/{name}.md',
             f'---\ndate: {date}\n---\n# Evidence\nCobalt recall evidence.\n')
    with authority_context(tmp_path):
        jobs.rebuild_index_checkpointed(tmp_path, owner='worker', now=NOW)
    expected = index._read_cache(tmp_path)
    relative = 'projects/demo/notes/old.md'
    entry = json.loads(json.dumps(expected[relative]))
    for chunk in entry['chunks']:
        if damage is None:
            del chunk['timestamp']
        else:
            chunk['timestamp'] = damage
    if route == 'checkpoint':
        with sqlite3.connect(jobs._journal_path(tmp_path)) as db:
            db.execute('UPDATE checkpoints SET entry_json=? WHERE relative_path=?', (json.dumps(entry), relative))
        (tmp_path / index.INDEX_RELATIVE).unlink()
    else:
        payload = json.loads((tmp_path / index.INDEX_RELATIVE).read_text())
        payload['files'][relative] = entry
        (tmp_path / index.INDEX_RELATIVE).write_text(json.dumps(payload))
    if route != 'recall':
        with authority_context(tmp_path):
            jobs.rebuild_index_checkpointed(tmp_path, owner='worker', now=NOW)
        assert index._read_cache(tmp_path) == expected
    result = recall('Cobalt recall evidence', tmp_path, project='demo', recency_half_life_days=365)
    assert result.sources[0].path == 'projects/demo/notes/recent.md'
    chunks = index.load_index(tmp_path)
    assert [c.timestamp for c in chunks if c.relative_path == relative] == [c['timestamp'] for c in expected[relative]['chunks']]


@pytest.mark.parametrize('separator', SEPARATORS)
def test_private_key_suppression_preserves_recall_and_excerpt_lines(tmp_path, separator):
    text = ('# Intro\nPublic introduction.\n-----BEGIN PRIVATE KEY-----' + separator
            + 'SYNTHETIC-KEY-PAYLOAD' + separator + '-----END PRIVATE KEY-----\n'
            + '# Cobalt\nCobalt public evidence.\n')
    path = note(tmp_path, text=text)
    redacted = redact_secrets(text)
    assert 'SYNTHETIC-KEY-PAYLOAD' not in redacted
    assert len(redacted.splitlines()) == len(text.splitlines())
    line = text.splitlines().index('Cobalt public evidence.') + 1
    relative = path.relative_to(tmp_path).as_posix()
    assert excerpt(tmp_path, relative, f'{line}-{line}').text == 'Cobalt public evidence.'
    result = recall('Cobalt', tmp_path, project='demo')
    assert result.sources[0].lines == f'{line - 1}-{line}'


def test_restore_cleanup_preserves_unowned_witness_and_new_target(tmp_path):
    path, result = forgotten(tmp_path)
    real_unlink = Path.unlink

    def fail_witness(target, *args, **kwargs):
        if target.name.endswith('.stage') and target.parent == path.parent:
            raise OSError('cleanup interrupted')
        return real_unlink(target, *args, **kwargs)

    with patch.object(Path, 'unlink', fail_witness), pytest.raises(OSError, match='cleanup interrupted'):
        restore(tmp_path, result)
    _, stage = witness(tmp_path)
    # Keep the owned inode alive while replacing its name with an unrelated
    # byte-identical inode; inode reuse cannot make this negative ambiguous.
    held = stage.with_suffix('.held')
    stage.rename(held)
    stage.write_bytes(held.read_bytes())
    unrelated = stage.stat().st_ino
    assert restore(tmp_path, result).status == 'restored'
    assert stage.stat().st_ino == unrelated
    # An additional hard link remains outside the owned stage name; completion
    # replay must not turn that arbitrary link into export authority.
    with authority_context(tmp_path), pytest.raises(ValueError, match='singly-linked'):
        reviewed_memory_snapshot(tmp_path, {path.relative_to(tmp_path).as_posix():
                                           hashlib.sha256(path.read_bytes()).hexdigest()})
    stage.unlink()
    held.rename(stage)
    path.unlink()
    path.write_text('# New truth\nNew public truth.\n')
    newer = path.stat().st_ino
    with patch.object(forget, '_publish_bound_file', side_effect=AssertionError('completed restore republished')):
        restore(tmp_path, result)
    assert path.stat().st_ino == newer
    assert 'New public truth.' in path.read_text()
    assert not stage.exists()
    assert_export(tmp_path, path)


def test_concurrent_completed_restore_replay_leaves_one_exportable_inode(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    path, result = forgotten(tmp_path)
    gate = Barrier(2)

    def run():
        gate.wait(timeout=5)
        return restore(tmp_path, result)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second = list(pool.map(lambda _: run(), range(2)))
    assert first == second
    assert path.stat().st_nlink == 1
    assert not witness(tmp_path)[1].exists()
    assert_export(tmp_path, path)


@pytest.mark.parametrize('newline', ['\n', '\r\n', '\r'])
def test_import_replay_and_dry_run_preserve_metadata_without_overwrite(tmp_path, newline):
    root = tmp_path / 'vault'
    root.mkdir()
    source = tmp_path / 'input.md'
    source.write_bytes(('---\nid: original\nrelations: []\n---\n# Body\nEvidence.\n').replace('\n', newline).encode())
    with authority_context(root):
        dry = importers.import_markdown(source, root, 'demo', dry_run=True)
        assert dry.dry_run
        assert not (root / 'projects').exists()
        first = importers.import_markdown(source, root, 'demo')
        first_bytes = (root / first.imported[0]).read_bytes()
        second = importers.import_markdown(source, root, 'demo')
    assert first.imported != second.imported
    assert (root / first.imported[0]).read_bytes() == first_bytes
    assert (root / second.imported[0]).read_bytes() == first_bytes
    assert frontmatter_values(first_bytes.decode())['id'] == 'original'
    assert first_bytes.count(b'---') == 2


@pytest.mark.parametrize('phase', ['before-receipt', 'after-receipt', 'after-unlink'])
def test_restore_process_death_recovers_on_fresh_interpreter(tmp_path, phase):
    import subprocess
    import sys
    path, result = forgotten(tmp_path)
    crash = r'''
import os, sys
from pathlib import Path
from arvyx_control import forget
from arvyx_control.replica_authority import authority_context
root, tombstone, phase = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
receipt = forget._operation_path(root, 'restore-lane-A-0001')
real_json, real_unlink = forget._atomic_json, Path.unlink
def write_json(target, payload):
    if target == receipt and phase == 'before-receipt':
        os._exit(17)
    real_json(target, payload)
    if target == receipt and phase == 'after-receipt':
        os._exit(17)
def unlink(target, *args, **kwargs):
    real_unlink(target, *args, **kwargs)
    if phase == 'after-unlink' and target.name.endswith('.stage'):
        assert receipt.exists()
        os._exit(17)
forget._atomic_json, Path.unlink = write_json, unlink
with authority_context(root):
    forget.restore_forgotten(root, tombstone, 'operator', 'restore-lane-A-0001')
'''
    child = subprocess.run([sys.executable, '-c', crash, str(tmp_path), result.tombstone_path, phase],
                           capture_output=True, text=True, timeout=10)
    assert child.returncode == 17, child.stderr
    receipt, stage = witness(tmp_path)
    assert receipt.exists() == (phase != 'before-receipt')
    assert stage.exists() == (phase != 'after-unlink')
    if stage.exists():
        assert stage.stat().st_ino == path.stat().st_ino
    replay = r'''
import sys
from pathlib import Path
from arvyx_control.forget import restore_forgotten
from arvyx_control.replica_authority import authority_context
root = Path(sys.argv[1])
with authority_context(root):
    result = restore_forgotten(root, sys.argv[2], 'operator', 'restore-lane-A-0001')
assert result.status == 'restored'
'''
    reopened = subprocess.run([sys.executable, '-c', replay, str(tmp_path), result.tombstone_path],
                              capture_output=True, text=True, timeout=10)
    assert reopened.returncode == 0, reopened.stderr
    assert not stage.exists()
    assert_export(tmp_path, path)


def test_completed_restore_copy_replays_without_adopting_copied_inode(tmp_path):
    import shutil
    root = tmp_path / 'original'
    path, result = forgotten(root)
    real_unlink = Path.unlink

    def interrupted(target, *args, **kwargs):
        if target.name.endswith('.stage') and target.parent == path.parent:
            raise OSError('cleanup interrupted')
        return real_unlink(target, *args, **kwargs)

    with patch.object(Path, 'unlink', interrupted), pytest.raises(OSError, match='cleanup interrupted'):
        restore(root, result)
    # The existing snapshot contract permits copying completed operations and
    # says old witness inode numbers must not become replay authority on a copy.
    copied = tmp_path / 'copy'
    shutil.copytree(root, copied)
    _, copied_stage = witness(copied)
    copied_inode = copied_stage.stat().st_ino
    from arvyx_control.forget_guard import assert_copyable_forget_operations
    assert_copyable_forget_operations(copied)
    replayed = restore(copied, result)
    assert replayed.status == 'restored'
    assert copied_stage.stat().st_ino == copied_inode
    assert_export(copied, copied / path.relative_to(root))


def test_known_backup_comparison_is_not_a_literal_secret():
    from pathlib import Path
    from arvyx_control.security import canonical_secret_line_spans,python_constant_secret_spans
    source=(Path(__file__).resolve().parents[3]/'scripts/backup_restore.py').read_text()
    assert not list(canonical_secret_line_spans(source))
    assert not python_constant_secret_spans(source)


def test_known_synthetic_fingerprints_are_exact_and_path_bound():
    from pathlib import Path
    from arvyx_control.security import load_secret_scan_allowlist,secret_line_fingerprint
    root=Path(__file__).resolve().parents[3]
    source=Path('packages/arvctl/tests/test_recall.py')
    line=next(l for l in (root/source).read_text().splitlines() if 'authorization="Bearer synthetic-control-plane-operator"' in l)
    allowed=load_secret_scan_allowlist(root)
    assert secret_line_fingerprint(source,line) in allowed
    assert secret_line_fingerprint(Path('unreviewed.py'),line) not in allowed
    assert secret_line_fingerprint(source,line.replace('synthetic-control-plane-operator','a-new-unreviewed-marker')) not in allowed
