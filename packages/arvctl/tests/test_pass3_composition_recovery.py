"""Offline whole-composition drill on disposable state, including WAL and fences."""
import json,sqlite3,fcntl
from pathlib import Path
import pytest


def topology(tmp_path):
    from arvyx_control.composition_recovery import Topology,ROLES
    root=tmp_path/'source';root.mkdir(mode=0o700);(root/'vault').mkdir()
    roles={k:[] for k in ROLES}
    for role in ROLES:
        file=root/(role+'.sqlite')
        with sqlite3.connect(file) as db:
            db.execute('CREATE TABLE proof(id TEXT PRIMARY KEY,status TEXT,result TEXT)')
            db.execute('INSERT INTO proof VALUES(?,?,?)',('original-'+role,'ambiguous','{"preserved":true}'))
        roles[role]=[file.name]
    with sqlite3.connect(root/'owner.sqlite') as db:
        db.execute('CREATE TABLE identity(host TEXT,state TEXT,vault TEXT)')
        db.execute('INSERT INTO identity VALUES(?,?,?)',('machine-a',str(root/'events.jsonl'),str(root/'vault')))
    (root/'events.jsonl').write_text('')
    roles['journal'].append('events.jsonl');roles['vault'].append('vault')
    (root/'profiles').mkdir();(root/'profiles'/'SOUL.md').write_text('Selected instructions')
    roles['profile_tree']=['profiles']
    (root/'bearer.secret').write_text('disposable credential');roles['bearer_authority']=['bearer.secret']
    return Topology(root,'vault',roles,['events.jsonl.cockpit-owner.lock','events.jsonl.lock','vault/.arvyx/vault.lock'])


def test_full_capture_restore_quarantine_and_preserving_reopen(tmp_path):
    from arvyx_control.composition_recovery import capture,restore,inspect_candidate
    from arvyx_control.replica_authority import assert_mutation_authority,ReplicaAuthorityUnavailable
    t=topology(tmp_path);bundle=tmp_path/'bundle';capture(t,bundle)
    assert not (bundle/'files'/'bearer.secret').exists()
    result=restore(bundle,tmp_path/'candidate')
    assert result['quarantined'] and not result['bearer_authority_restored']
    info=inspect_candidate(tmp_path/'candidate')
    assert info['checked_databases']>=10 and info['mutable'] is False
    with sqlite3.connect(tmp_path/'candidate'/'owner.sqlite') as db:
        assert db.execute('SELECT * FROM proof').fetchone()==('original-owner','ambiguous','{"preserved":true}')
    with pytest.raises(ReplicaAuthorityUnavailable):assert_mutation_authority(tmp_path/'candidate'/'vault')


def test_lock_crash_and_hash_failures_never_publish_candidate(tmp_path):
    from arvyx_control.composition_recovery import capture,restore
    t=topology(tmp_path)
    with (t.root/'events.jsonl.cockpit-owner.lock').open('a+') as held:
        fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with pytest.raises(ValueError,match='quiescent'):capture(t,tmp_path/'busy')
    assert not (tmp_path/'busy').exists()
    def crash(stage):
        if stage=='before-manifest':raise RuntimeError('crash')
    with pytest.raises(RuntimeError):capture(t,tmp_path/'interrupted',checkpoint=crash)
    with pytest.raises(ValueError,match='complete'):restore(tmp_path/'interrupted',tmp_path/'bad')
    capture(t,tmp_path/'bundle')
    (tmp_path/'bundle'/'files'/'owner.sqlite').write_bytes(b'changed')
    with pytest.raises(ValueError,match='hash'):restore(tmp_path/'bundle',tmp_path/'bad')
    assert not (tmp_path/'bad').exists()


def test_actual_current_owner_onboarding_and_attempts_restore_inert(tmp_path):
    from arvyx_control.machine_enrollment import enroll
    from arvyx_control.cockpit import LocalCockpit
    from arvyx_control.local_onboarding import local_composition
    from arvyx_control.composition_recovery import Topology,ROLES,capture,restore,inspect_candidate
    from arvyx_control.replica_authority import ReplicaAuthorityUnavailable
    root=tmp_path/'actual';enroll(root,'machine-a',confirmed=True)
    owner=LocalCockpit(root/'runtime',root/'vault',root/'events.jsonl','machine-a');owner.close()
    directory=root/'runtime'/'onboarding';directory.mkdir()
    api=local_composition(directory,vault=root/'vault',machine_id='machine-a',capability='disposable')
    prepared=api.dispatch('POST','/api/public-onboarding/agents/prepare','Bearer disposable',dict(name='Retained',harness='hermes',environment='metadata',identity_mode='clean'))[1]
    assert prepared['consent_id']
    db=api.owners['local-owner'].creation.db
    with db:db.execute("UPDATE onboarding_consents SET status='ambiguous' WHERE id=?",(prepared['consent_id'],))
    api.close()
    roles={k:[] for k in ROLES}
    roles.update(vault=['vault'],journal=['events.jsonl'],owner=['runtime/sessions.sqlite'],
        enrollment=['runtime/machine-enrollment.json'],profile_mappings=['runtime/onboarding/agents.sqlite'],
        profile_tree=['runtime/onboarding/profiles'],consents=['runtime/onboarding/agents.sqlite'],bearer_authority=['runtime/operator.secret'])
    t=Topology(root,'vault',roles,['events.jsonl.cockpit-owner.lock','events.jsonl.lock','vault/.arvyx/vault.lock'])
    (root/'vault'/'.arvyx').mkdir(exist_ok=True)
    capture(t,tmp_path/'actual-bundle');restore(tmp_path/'actual-bundle',tmp_path/'restored')
    restored=tmp_path/'restored'
    assert inspect_candidate(restored)['mutable'] is False
    assert (restored/'runtime/onboarding/profiles').is_dir()
    with sqlite3.connect(restored/'runtime/onboarding/agents.sqlite') as db:
        assert db.execute('SELECT id,status FROM onboarding_consents').fetchone()==(prepared['consent_id'],'ambiguous')
        assert db.execute('SELECT count(*) FROM created_agents').fetchone()[0]==0
    with pytest.raises(ReplicaAuthorityUnavailable):LocalCockpit(restored/'runtime',restored/'vault',restored/'events.jsonl','machine-a')
    with pytest.raises(ReplicaAuthorityUnavailable):local_composition(restored/'runtime/onboarding',vault=restored/'vault',machine_id='machine-a',capability='new-bearer')
