"""Focus75 agent13 boundary regressions plus wave1 executed real-path acceptance (REV-0523/0524/0525/0543)."""
import os
import pytest


def test_import_replacement_stage_is_preserved_at_real_mutation_boundary(tmp_path, monkeypatch):
    from arvyx_control import import_publication as publication
    from arvyx_control.promotion_transaction import memory_mutation
    from arvyx_control.replica_authority import authority_context
    target = tmp_path / 'note.md'
    payload = b'original complete import'
    real_link = os.link
    replacement = b'unrelated replacement stage'
    stages = []
    def interrupted_link(source, destination, **kwargs):
        real_link(source, destination, **kwargs)
        stages.append(source)
        os.unlink(source)
        source.write_bytes(replacement)
        raise OSError('interrupted after publication and replacement')
    with authority_context(tmp_path):
        with monkeypatch.context() as scoped:
            scoped.setattr(publication.os, 'link', interrupted_link)
            with pytest.raises(OSError, match='interrupted'):
                publication.publish(tmp_path, target, payload)
        with pytest.raises(ValueError, match='conflict'):
            with memory_mutation(tmp_path):
                pytest.fail('conflicting recovery must not yield')
    assert target.read_bytes() == payload
    assert stages[0].read_bytes() == replacement
    assert list((tmp_path / '.arvyx/import-publications').glob('*.json'))


@pytest.mark.parametrize('component', ['import_publication', 'promotion_transaction'])
def test_capture_recovery_failure_precedes_inventory_and_completion(tmp_path, monkeypatch, component):
    from test_pass3_composition_recovery import topology
    from arvyx_control import composition_recovery as composition
    from arvyx_control import import_publication, promotion_transaction
    from arvyx_control.replica_authority import authority_context
    t = topology(tmp_path)
    module = {'import_publication': import_publication,
              'promotion_transaction': promotion_transaction}[component]
    def refuse(*args, **kwargs):
        raise OSError('exact recovery conflict')
    def forbidden(*args, **kwargs):
        pytest.fail('inventory must not run after recovery failure')
    monkeypatch.setattr(module, 'recover', refuse)
    monkeypatch.setattr(composition, 'inventory', forbidden)
    destination = tmp_path / 'bundle'
    with authority_context(t.root / t.vault):
        with pytest.raises(OSError, match='exact recovery conflict'):
            composition.capture(t, destination)
    assert not destination.exists()


def test_unrelated_hardlinks_still_fail_complete_capture(tmp_path):
    from test_pass3_composition_recovery import topology
    from arvyx_control.composition_recovery import capture
    from arvyx_control.replica_authority import authority_context
    t = topology(tmp_path)
    source = t.root / t.vault / 'unrelated.md'
    source.write_bytes(b'unowned hardlink')
    alias = source.with_name('alias.md')
    os.link(source, alias)
    with authority_context(t.root / t.vault):
        with pytest.raises((OSError, ValueError)):
            capture(t, tmp_path / 'bundle')
    assert source.read_bytes() == alias.read_bytes() == b'unowned hardlink'
    assert source.stat().st_nlink == 2
    assert not (tmp_path / 'bundle/manifest.json').exists()


# ---------------------------------------------------------------------------
# Wave1 lane 1: executed real-path acceptance for REV-0523/0524/0525/0543.
# Interruptions are real hard exits (os._exit) of a child process at the exact
# syscall boundary, so no finally/except cleanup runs. All bytes are synthetic.
# ---------------------------------------------------------------------------
import hashlib
import json
import subprocess
import sys
import textwrap
import uuid
from pathlib import Path

_HARD_EXIT = 86

_CHILD_PRELUDE = textwrap.dedent('''
    import os, sys
    from pathlib import Path
    stage = sys.argv[1]
    def die():
        os._exit(%d)
    real_link, real_rename, real_unlink = os.link, os.rename, os.unlink
''' % _HARD_EXIT)


def _run_child(body, *args):
    script = _CHILD_PRELUDE + textwrap.dedent(body)
    completed = subprocess.run([sys.executable, '-c', script, *map(str, args)],
                               capture_output=True, text=True, timeout=60)
    assert completed.returncode == _HARD_EXIT, (completed.returncode, completed.stdout, completed.stderr)


_IMPORT_CHILD = '''
    vault, source = Path(sys.argv[2]), Path(sys.argv[3])
    def link(src, dst, *a, **k):
        real_link(src, dst, *a, **k)
        if stage == 'after-link':
            die()
    def rename(src, dst, *a, **k):
        real_rename(src, dst, *a, **k)
        if stage == 'after-witness' and str(dst).endswith('.json'):
            die()
        if stage == 'after-retire' and str(dst).endswith('.retired'):
            die()
    def unlink(path, *a, **k):
        real_unlink(path, *a, **k)
        if stage == 'after-stage-unlink' and str(path).endswith('.stage'):
            die()
    os.link, os.rename, os.unlink = link, rename, unlink
    from arvyx_control.importers import import_markdown
    import_markdown(source, vault, 'proj')
    sys.exit(0)
'''


@pytest.mark.parametrize('operation', ['refine', 'promote'])
@pytest.mark.parametrize('stage', ['after-witness', 'after-link', 'after-retire', 'after-stage-unlink'])
def test_rev0523_hard_exit_import_reopens_into_governed_lifecycle(tmp_path, stage, operation):
    from arvyx_control.importers import import_markdown
    from arvyx_control.writes import promote_memory, refine_memory
    vault = tmp_path / 'vault'
    vault.mkdir()
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'note.md').write_text('# Imported\nsynthetic imported body\n')
    lane = vault / 'projects/proj/imported'
    lane.mkdir(parents=True)
    # Unrelated neighbours: an ordinary note and an unowned import-like stage.
    unrelated = lane / 'unrelated.md'
    unrelated.write_bytes(b'unrelated curated bytes')
    foreign_stage = lane / ('.import-' + uuid.uuid4().hex + '.stage')
    foreign_stage.write_bytes(b'unowned replacement stage')
    _run_child(_IMPORT_CHILD, stage, vault, source)
    target = lane / 'note.md'
    witnesses = vault / '.arvyx/import-publications'
    assert list(witnesses.iterdir()), 'hard exit must leave a durable publication witness'
    published = target.exists()
    if stage == 'after-link':
        assert target.stat().st_nlink == 2  # the originally reported stranded alias
    if not published:
        # Interrupted before publication: reimport through the real entry point.
        assert stage == 'after-witness'
        import_markdown(source, vault, 'proj')
    payload = target.read_bytes()
    assert b'synthetic imported body' in payload
    if operation == 'refine':
        result = refine_memory(vault, 'proj', 'imported/note.md', 'refiner')
    else:
        result = promote_memory(vault, 'proj', 'imported/note.md', 'operator')
    assert not target.exists()
    produced = vault / result.target
    assert produced.stat().st_nlink == 1
    assert b'synthetic imported body' in produced.read_bytes()
    assert list(witnesses.iterdir()) == []
    assert not [p for p in lane.glob('.import-*.stage') if p != foreign_stage]
    assert unrelated.read_bytes() == b'unrelated curated bytes'
    assert foreign_stage.read_bytes() == b'unowned replacement stage'


def _composition(tmp_path):
    """Minimal explicit topology: vault plus one journal file, no bearer copy."""
    from arvyx_control.composition_recovery import Topology, ROLES
    root = tmp_path / 'source'
    (root / 'vault').mkdir(parents=True, mode=0o700)
    (root / 'events.jsonl').write_text('')
    roles = {k: [] for k in ROLES}
    roles.update(vault=['vault'], journal=['events.jsonl'])
    return Topology(root, 'vault', roles, ['vault/.arvyx/vault.lock'])


_PROMOTE_CHILD = '''
    vault, operation, source_rel = Path(sys.argv[2]), sys.argv[3], sys.argv[4]
    source = (vault / 'projects/proj' / source_rel).absolute()
    def link(src, dst, *a, **k):
        real_link(src, dst, *a, **k)
        if stage == 'after-target-link' and '.promotion-' in str(src):
            die()
    def unlink(path, *a, **k):
        real_unlink(path, *a, **k)
        if stage == 'after-source-unlink' and Path(path).absolute() == source:
            die()
    os.link, os.unlink = link, unlink
    from arvyx_control import writes
    if operation == 'promote':
        writes.promote_memory(vault, 'proj', source_rel, 'operator')
    elif operation == 'refine':
        writes.refine_memory(vault, 'proj', source_rel, 'refiner')
    else:
        writes.reject_memory(vault, 'proj', source_rel, 'operator', 'synthetic')
    sys.exit(0)
'''


def _interrupted_promotion(tmp_path, operation, stage):
    from arvyx_control.writes import suggest_memory
    t = _composition(tmp_path)
    vault = t.root / t.vault
    suggested = suggest_memory(vault, 'proj', 'Synthetic', 'synthetic pending body', 'agent')
    source_rel = suggested.path.split('projects/proj/', 1)[1]
    source = vault / 'projects/proj' / source_rel
    original = source.read_bytes()
    _run_child(_PROMOTE_CHILD, stage, vault, operation, source_rel)
    journals = list((vault / '.arvyx/promotions').iterdir())
    assert len(journals) == 1 and (journals[0] / 'manifest.json').exists()
    assert not (journals[0] / 'committed').exists()
    return t, vault, source, original, journals[0]


@pytest.mark.parametrize('operation', ['promote', 'refine', 'reject'])
@pytest.mark.parametrize('stage', ['after-target-link', 'after-source-unlink'])
def test_rev0524_capture_reconciles_hard_interrupted_promotion_before_inventory(tmp_path, operation, stage):
    from arvyx_control.composition_recovery import capture, restore, inspect_candidate
    from arvyx_control.writes import promote_memory
    t, vault, source, original, journal = _interrupted_promotion(tmp_path, operation, stage)
    if stage == 'after-source-unlink':
        assert not source.exists()
    record = capture(t, tmp_path / 'bundle')
    assert record['complete'] is True
    # Recovery ran on the original filesystem under the held vault lock.
    assert not journal.exists()
    assert source.read_bytes() == original and source.stat().st_nlink == 1
    assert not any('/.arvyx/promotions/' in name for name in record['files'])
    assert record['files']['vault/' + source.relative_to(vault).as_posix()]['sha256'] == hashlib.sha256(original).hexdigest()
    lanes = {'promote': 'notes', 'refine': 'refining', 'reject': 'archive'}
    published = vault / 'projects/proj' / lanes[operation]
    assert not published.exists() or not list(published.glob('*.md'))
    restore(tmp_path / 'bundle', tmp_path / 'candidate')
    assert inspect_candidate(tmp_path / 'candidate')['mutable'] is False
    candidate = tmp_path / 'candidate' / 'vault'
    assert (candidate / source.relative_to(vault)).read_bytes() == original
    assert not (candidate / '.arvyx/promotions').exists() or not list((candidate / '.arvyx/promotions').iterdir())
    # The reconciled original remains usable by its ordinary lifecycle.
    promote_memory(vault, 'proj', source.relative_to(vault / 'projects/proj').as_posix(), 'operator')


def test_rev0524_conflicted_interrupted_journal_refuses_capture(tmp_path):
    from arvyx_control.composition_recovery import capture
    t, vault, source, original, journal = _interrupted_promotion(tmp_path, 'promote', 'after-target-link')
    target = next((vault / 'projects/proj/notes').glob('*.md'))
    replacement = target.with_name('.unrelated.tmp')
    replacement.write_bytes(b'unrelated operator edit')
    os.replace(replacement, target)  # new inode: not the journal's published identity
    with pytest.raises(OSError, match='promotion recovery conflict'):
        capture(t, tmp_path / 'bundle')
    assert not (tmp_path / 'bundle').exists()
    assert (journal / 'manifest.json').exists()
    assert target.read_bytes() == b'unrelated operator edit'
    assert source.read_bytes() == original


def test_rev0525_completed_forget_and_restore_capture_restore_recapture(tmp_path):
    from arvyx_control.composition_recovery import capture, restore, FENCE
    from arvyx_control.forget import soft_forget, restore_forgotten
    t = _composition(tmp_path)
    vault = t.root / t.vault
    note = vault / 'projects/proj/notes/keep.md'
    note.parent.mkdir(parents=True)
    note.write_bytes(b'# Keep\nsynthetic curated body\n')
    original = note.read_bytes()
    key = 'forget-' + uuid.uuid4().hex
    forgotten = soft_forget(vault, 'proj', 'projects/proj/notes/keep.md', 'other', 'batch-1', 'operator', key)
    archive = vault / forgotten.archive_path
    assert archive.stat().st_nlink == 2  # retained archive/witness pair
    first = capture(t, tmp_path / 'bundle-forgotten')
    archive_name = 'vault/' + forgotten.archive_path
    assert first['files'][archive_name]['sha256'] == hashlib.sha256(original).hexdigest()
    restore(tmp_path / 'bundle-forgotten', tmp_path / 'candidate')
    copied = tmp_path / 'candidate' / archive_name
    assert copied.read_bytes() == original and copied.stat().st_nlink == 1
    witnesses = list(copied.parent.glob('.forget-*.stage'))
    assert len(witnesses) == 1 and witnesses[0].stat().st_nlink == 1 and witnesses[0].read_bytes() == original
    # Completed receipt replay on the original is exact and effect-free.
    replay = soft_forget(vault, 'proj', 'projects/proj/notes/keep.md', 'other', 'batch-1', 'operator', key)
    assert replay == forgotten and not note.exists()
    # Forget then restore, then complete capture again.
    restore_key = 'restore-' + uuid.uuid4().hex
    restored = restore_forgotten(vault, forgotten.tombstone_path, 'operator', restore_key)
    assert note.read_bytes() == original and note.stat().st_nlink == 1
    second = capture(t, tmp_path / 'bundle-restored')
    assert second['files']['vault/projects/proj/notes/keep.md']['sha256'] == hashlib.sha256(original).hexdigest()
    assert restore_forgotten(vault, forgotten.tombstone_path, 'operator', restore_key) == restored
    # Recapture of the restored candidate after explicit independent
    # reprovisioning (fence removal): the materialized pair is accepted.
    candidate_root = tmp_path / 'candidate'
    (candidate_root / 'vault' / FENCE).unlink()
    (candidate_root / 'restore-receipt.json').unlink()
    from arvyx_control.composition_recovery import Topology
    recaptured = capture(Topology(candidate_root, 'vault', t.roles, t.locks), tmp_path / 'bundle-recaptured')
    assert recaptured['files'][archive_name]['sha256'] == hashlib.sha256(original).hexdigest()
    # An unrelated extra alias of the retained archive inode is still refused.
    os.link(archive, archive.with_name('alias.original'))
    with pytest.raises((OSError, ValueError, RuntimeError)):
        capture(t, tmp_path / 'bundle-alias')
    assert not (tmp_path / 'bundle-alias/manifest.json').exists()


def _ancestor_barrier(monkeypatch, failing):
    from arvyx_control import composition_recovery as recovery
    original = recovery.sync
    state = dict(fail=True, calls=[], marker=None, before_marker=[])
    def barrier(path):
        path = Path(path).absolute()
        state['calls'].append(path)
        if path == failing and state['marker'] is not None:
            state['before_marker'].append(not state['marker'].exists())
        if path == failing and state['fail']:
            raise OSError('synthetic ancestor-parent barrier failure')
        return original(path)
    monkeypatch.setattr(recovery, 'sync', barrier)
    return state


@pytest.mark.parametrize('operation', ['capture', 'restore'])
def test_rev0543_retry_repeats_failed_ancestor_barrier_before_completion(tmp_path, monkeypatch, operation):
    from arvyx_control import composition_recovery as recovery
    t = _composition(tmp_path)
    (t.root / 'vault/note.md').write_bytes(b'synthetic')
    holder = tmp_path / 'holder'
    holder.mkdir()
    ancestor = holder / 'P'
    bundle = None
    if operation == 'restore':
        bundle = tmp_path / 'bundle'
        recovery.capture(t, bundle)
    def run(child):
        if operation == 'capture':
            return recovery.capture(t, child)
        return recovery.restore(bundle, child)
    completion = 'manifest.json' if operation == 'capture' else 'restore-receipt.json'
    state = _ancestor_barrier(monkeypatch, holder.absolute())
    with pytest.raises(OSError, match='ancestor-parent'):
        run(ancestor / 'first')
    assert ancestor.is_dir()  # P created; its name in holder never proven durable
    assert not (ancestor / 'first' / completion).exists()
    # Continued failure: the retry beneath visible P must still withhold completion.
    with pytest.raises(OSError, match='ancestor-parent'):
        run(ancestor / 'second')
    assert not (ancestor / 'second' / completion).exists()
    # Recovered barrier: retry repeats the holder barrier and only then completes.
    state['fail'] = False
    state['calls'].clear()
    state['marker'] = ancestor / 'third' / completion
    run(ancestor / 'third')
    assert (ancestor / 'third' / completion).exists()
    assert holder.absolute() in state['calls']
    # The repeated ancestor-parent barrier precedes the completion record.
    assert state['before_marker'] and state['before_marker'][0] is True
