"""Real deterministic subprocess evidence, never provider output."""
import json
import sys
from dataclasses import replace

import os
import pytest

from arvyx_control.agent_sessions import AgentSessions, SessionTarget
from arvyx_control.organizer_authority import OrganizerAuthority
from arvyx_control.harness_improvement import HarnessImprovement, ProbeSpec

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='the owned-command broker supervises with POSIX process groups and is POSIX-only')


@pytest.fixture
def rig(tmp_path):
    authority = OrganizerAuthority()
    actor = authority.provision_identity('main', kind='internal', organizer=True)
    authority.enroll_machine('local')
    target = SessionTarget('local', 'main', 'workspace', 'connection')
    script = tmp_path / 'check.py'
    script.write_text('import json,pathlib,sys\nh=json.loads(pathlib.Path("harness.json").read_text())\nprint("observed:"+h["procedure"])\nsys.exit(0 if h["procedure"] == "verify" else 1)\n')
    spec = ProbeSpec.from_script(script, timeout=2)
    def service():
        return HarnessImprovement(tmp_path / 'state.db', authority, actor, target, spec)
    return service, authority, actor, target, spec


def task(service, name='task', **kwargs):
    return service.start_task(name, {'procedure': 'omit'}, {'input.txt': 'fixed source'}, **kwargs)


def test_persistence_dedup_and_one_main_namespace(rig):
    factory, _, _, target, _ = rig
    a = factory()
    identity = a.session()
    assert identity == factory().session()
    assert identity['target']['agent_id'] == target.agent_id
    assert identity['native_status'] == 'not_opened'
    task(a)
    cid = a.propose('task', 'invariant', {'procedure': 'verify'}, 'reopen outputs')
    assert cid == factory().propose('task', 'invariant', {'procedure': 'verify'}, 'reopen outputs')
    assert len(a.snapshot()['tasks']['task']['candidates']) == 1
    with pytest.raises(ValueError):
        task(a)


def test_real_probe_compose_and_cross_task_proposal(rig):
    a = rig[0]()
    task(a)
    cid = a.propose('task', 'invariant', {'procedure': 'verify'}, 'reopen outputs')
    receipt = a.probe('task', cid)
    assert receipt['baseline']['returncode'] == 1
    assert receipt['candidate']['returncode'] == 0
    assert receipt['candidate']['stdout'] == 'observed:verify\n'
    assert receipt['baseline']['input_digest'] == receipt['candidate']['input_digest']
    assert receipt['candidate']['script_digest']
    result = a.compose('task', [cid], 'candidate process delivered; baseline failed')
    assert result['status'] == 'composed'
    assert result['successor']['returncode'] == 0
    proposal = a.reflect('task', 'missing artifact verification', 'Use procedure verification on artifact tasks')
    assert proposal['status'] == 'proposed_not_applied'
    assert not proposal['transfer_verified']
    task(a, 'next')
    assert a.snapshot()['tasks']['next']['baseline'] == {'procedure': 'omit'}
    assert proposal['id'] in a.snapshot()['tasks']['next']['library_snapshot']


def test_no_evidence_bad_candidate_and_regression(rig):
    a = rig[0]()
    task(a)
    cid = a.propose('task', 'domain', {'procedure': 'bad'}, 'hypothesis')
    with pytest.raises(ValueError, match='evidence'):
        a.compose('task', [cid], 'trust me')
    a.probe('task', cid)
    with pytest.raises(ValueError, match='unsupported'):
        a.compose('task', [cid], 'quality=100')
    assert a.compose('task', [], 'keep baseline: no supported change')['status'] == 'kept_baseline'
    with pytest.raises(ValueError):
        a.reflect('task', 'cue', 'lesson')
    a.start_task('regression', {'procedure': 'verify'}, {})
    c = a.propose('regression', 'domain', {'procedure': 'bad'}, 'hypothesis')
    assert a.probe('regression', c)['contrast'] == 'regression'
    with pytest.raises(ValueError, match='unsupported'):
        a.compose('regression', [c], 'ignore regression')


@pytest.mark.parametrize('patch', [{'soul': 'x'}, {'provider': 'x'}, {'security': 'x'}, {'../procedure': 'x'}, {'user': 'x'}])
def test_scope_is_closed(rig, patch):
    a = rig[0]()
    task(a)
    with pytest.raises(ValueError):
        a.propose('task', 'invariant', patch, 'not allowed')


def test_authority_scope_and_revocation(rig):
    factory, auth, actor, target, spec = rig
    a = factory()
    auth.set_organizer(actor, False)
    with pytest.raises(PermissionError):
        a.session()
    auth.set_organizer(actor, True)
    with pytest.raises(PermissionError):
        HarnessImprovement(a.path, auth, actor, replace(target, agent_id='other'), spec)
    with pytest.raises(ValueError, match='scope'):
        HarnessImprovement(a.path, auth, actor, replace(target, workspace_id='other'), spec)


def test_budget_stop_and_rollback(rig):
    a = rig[0]()
    task(a, max_runs=2, max_candidates=1)
    c = a.propose('task', 'invariant', {'procedure': 'verify'}, 'verify')
    with pytest.raises(ValueError, match='budget'):
        a.propose('task', 'domain', {'procedure': 'bad'}, 'bad')
    a.probe('task', c)
    with pytest.raises(ValueError, match='budget'):
        a.compose('task', [c], 'supported')
    a.stop('task', 'budget exhausted')
    with pytest.raises(ValueError):
        a.probe('task', c)
    assert a.rollback('task', 'restore original')['active'] == {'procedure': 'omit'}


def test_native_missing_adapter_is_honest_and_no_retry(rig):
    a = rig[0]()
    receipt = a.open_native(AgentSessions({}))
    assert receipt['native_status'] == 'handoff_required'
    assert receipt['target']['agent_id'] == 'main'
    assert 'AgentSessions.new' in receipt['handoff']
    assert a.open_native(AgentSessions({})) == receipt


def test_probe_source_drift_and_conflicting_composition(rig):
    a = rig[0]()
    task(a)
    c = a.propose('task', 'invariant', {'procedure': 'verify'}, 'verify')
    rig[4].script.write_text('print("changed")')
    with pytest.raises(ValueError, match='drift'):
        a.probe('task', c)


def test_invalid_inputs_and_forged_receipts_not_accepted(rig):
    a = rig[0]()
    with pytest.raises(ValueError):
        a.start_task('escape', {'procedure': 'omit'}, {'../escape': 'no'})
    with pytest.raises(ValueError):
        task(a, max_runs=-1)
    task(a)
    c = a.propose('task', 'invariant', {'procedure': 'verify'}, 'verify')
    view = a.snapshot()
    view['tasks']['task']['candidates'][c]['receipt'] = {'quality': 100}
    with pytest.raises(ValueError, match='evidence'):
        a.compose('task', [c], 'forged snapshot')


def test_input_aliases_are_canonical_before_persistence(rig):
    a = rig[0]()
    a.start_task('canonical', {'procedure': 'omit'},
                 {'inputs//tmp/amc-victim': 'fixed source'})
    assert a.snapshot()['tasks']['canonical']['inputs'] == {
        'inputs/tmp/amc-victim': 'fixed source'}


@pytest.mark.parametrize('name', [None, 7, '/tmp/escape', 'inputs/../escape',
                                  'inputs', 'inputs/', 'inputs/./', 'a/b', 'a\\b',
                                  'C:escape', 'inputs/C:/escape', 'bad\x00name'])
def test_input_paths_reject_invalid_names_with_value_error(rig, name):
    a = rig[0]()
    with pytest.raises(ValueError, match='unsafe input path'):
        a.start_task('invalid', {'procedure': 'omit'}, {name: 'source'})
    assert 'invalid' not in a.snapshot()['tasks']


def test_colliding_input_aliases_are_rejected(rig):
    a = rig[0]()
    with pytest.raises(ValueError, match='duplicate input path'):
        a.start_task('collision', {'procedure': 'omit'}, {
            'input.txt': 'first', 'inputs/input.txt': 'second'})


def test_legacy_input_alias_never_writes_outside_probe_root(rig, tmp_path):
    a = rig[0]()
    victim = tmp_path / 'victim'
    victim.write_text('unchanged')
    task(a)
    with a._transaction() as state:
        t = state['tasks']['task']
        # Model an already-persisted spelling admitted by the former validator.
        t['inputs'] = {'inputs/' + str(victim): 'must remain isolated'}
    c = a.propose('task', 'invariant', {'procedure': 'verify'}, 'verify')
    a.probe('task', c)
    assert victim.read_text() == 'unchanged'


def test_deadline_receipt_has_identity_without_starting_process(rig, monkeypatch):
    a = rig[0]()
    task(a)
    t = a.snapshot()['tasks']['task']
    monkeypatch.setattr('arvyx_control.harness_improvement.time.time',
                        lambda: t['deadline'] + 1)
    def forbidden(*args, **kwargs):
        raise AssertionError('expired probe must not start a process')
    monkeypatch.setattr('arvyx_control.harness_improvement.subprocess.Popen', forbidden)
    receipt = a._run(t, t['baseline'])
    assert receipt['id']
    assert receipt['failure'] == 'deadline'
    assert receipt['returncode'] is None
    assert receipt['input_digest'] == t['input_digest']
    assert receipt['harness_digest']
    assert receipt['script_digest'] == rig[4].script_digest
    assert receipt['process_started'] is False
    assert not a._ok(receipt)


def test_composition_deadline_after_reservation_records_terminal_receipt(rig, monkeypatch):
    a = rig[0]()
    task(a)
    c = a.propose('task', 'invariant', {'procedure': 'verify'}, 'verify')
    assert a.probe('task', c)['contrast'] == 'process_recovery'
    reserve = a._reserve
    def expire_after_reservation(t, count):
        reserve(t, count)
        monkeypatch.setattr('arvyx_control.harness_improvement.time.time',
                            lambda: t['deadline'] + 1)
    monkeypatch.setattr(a, '_reserve', expire_after_reservation)
    result = a.compose('task', [c], 'expiry before successor process admission')
    assert result['status'] == 'kept_baseline'
    assert result['active'] == {'procedure': 'omit'}
    assert result['successor']['failure'] == 'deadline'
    state = a.snapshot()['tasks']['task']
    assert state['decisions'][-1]['successor_receipt'] == result['successor']['id']
    assert state['decisions'][-1]['rollback_required']


def test_interrupted_probe_resolves_from_durable_effects_without_retry(rig, monkeypatch):
    from arvyx_control.harness_improvement import digest
    a = rig[0]()
    task(a)
    cid = a.propose('task', 'invariant', {'procedure': 'verify'}, 'verify')
    # The side effect completed, but the enclosing lifecycle transaction failed.
    # Exercise the real separate durable evidence path with an inert checker.
    def observed(t, configuration):
        return dict(id='observation', script_digest=a.spec.script_digest,
            input_digest=t['input_digest'], harness_digest=digest(configuration),
            returncode=0, failure=None, truncated=False, process_started=True)
    monkeypatch.setattr(a, '_run', observed)
    recorded = a._run_recorded
    def interrupted(t, configuration, slot):
        result = recorded(t, configuration, slot)
        if slot == 'candidate':
            raise RuntimeError('lifecycle commit unavailable')
        return result
    monkeypatch.setattr(a, '_run_recorded', interrupted)
    with pytest.raises(RuntimeError):
        a.probe('task', cid)
    pending = a.snapshot()['tasks']['task']
    operation_id = pending['pending_operation']['id']
    with pytest.raises(ValueError):
        a.reconcile_interrupted('task', operation_id='foreign')
    resolution = a.reconcile_interrupted('task', operation_id=operation_id)
    assert [item['status'] for item in resolution['evidence']] == ['observed', 'observed']
    assert not resolution['automatic_retry'] and not resolution['adoption_authorized']
    resolved = a.snapshot()['tasks']['task']
    assert resolved['runs'] == pending['runs'] == 2
    assert resolved['active'] == resolved['baseline']
    with pytest.raises(ValueError):
        a.probe('task', cid)


def test_interrupted_dispatch_without_receipt_stays_uncertain(rig, monkeypatch):
    a = rig[0]()
    task(a)
    cid = a.propose('task', 'invariant', {'procedure': 'verify'}, 'verify')
    def crash(*args):
        raise RuntimeError('effect result lost')
    monkeypatch.setattr(a, '_run', crash)
    with pytest.raises(RuntimeError):
        a.probe('task', cid)
    pending = a.snapshot()['tasks']['task']
    result = a.reconcile_interrupted('task', operation_id=pending['pending_operation']['id'])
    assert [item['status'] for item in result['evidence']] == ['uncertain', 'not_dispatched']
    assert a.snapshot()['tasks']['task']['runs'] == 2
