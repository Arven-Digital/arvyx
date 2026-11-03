"""Focus75 agent12 regression specifications. All NOT_EXECUTED.

Synthetic keys, bytes and authority only; no artifact or store qualification,
remote-host acceptance, provider launch or running-effect cancellation proof.
"""
import copy
from pathlib import Path
from unittest.mock import patch

import pytest


def test_unapproved_onboarding_remains_refused_for_matching_fixture_digest():
    from arvyx_control import native_artifact_policy as native
    from arvyx_control.agent_sessions import RoutingError
    import hashlib
    data = b'synthetic fixture, never an accepted executable'
    digest = hashlib.sha256(data).hexdigest()
    policy = dict(available=True, capabilities=['mouse-existing'])
    # The platform table must not be the thing under test. A mouse-only
    # admission, and nothing else, is what the capability fence has to refuse.
    artifacts = {digest: frozenset({'mouse-existing'})}
    with patch.object(native, 'admitted_native_artifacts', return_value=artifacts), patch.object(
        native, 'native_platform_policy', return_value=policy
    ):
        assert native.verify_native_bytes(data, required_capability='mouse-existing') == digest
        with pytest.raises(RoutingError, match='lacks the requested capability'):
            native.verify_native_bytes(data, required_capability='onboarding-v1')


def test_signed_old_storage_scope_cannot_rebind_new_directory(tmp_path):
    from arvyx_control.capture_offload import relocate_offload_storage
    from test_capture_retention_t9b import prepared, ack
    from retention_fixture_helpers import retention_receipt
    o, directory, review = prepared(tmp_path)
    try:
        receipt = retention_receipt(o, directory, review['sha256'])
        ack(o, directory, review, receipt)
        receipt = retention_receipt(o, directory, review['sha256'], kind='relocate')
        target = tmp_path / 'new-storage'
        target.mkdir(mode=0o700)
        name = review['sha256'] + '.json'
        (target / name).write_bytes((directory / name).read_bytes())
        before = tuple(o.db.execute('SELECT directory,device,inode FROM capture_offload_storage').fetchone())
        # A valid signature from the old store cannot attest the new incarnation.
        with pytest.raises(ValueError):
            relocate_offload_storage(o, target, actor='operator', confirmed=True,
                expected_head=review['sha256'], retention_receipt=copy.deepcopy(receipt))
        assert tuple(o.db.execute('SELECT directory,device,inode FROM capture_offload_storage').fetchone()) == before
        assert (directory / name).exists()
    finally:
        o.db.close()


def test_revocation_and_reenable_cannot_revive_unadmitted_ticket(tmp_path):
    from arvyx_control.organizer_authority import OrganizerAuthority
    from arvyx_control.replica_authority import authority_context
    from delegation_fixture_helpers import issue, admitted
    vault = tmp_path / 'owned-vault'
    vault.mkdir()
    with authority_context(vault):
        policy = OrganizerAuthority(database=tmp_path / 'policy.sqlite')
        try:
            actor = policy.provision_identity('organizer', kind='internal', organizer=True)
            worker = policy.provision_identity('worker', kind='internal')
            policy.enroll_machine('machine-a')
            policy.bind_agent(worker, machine='machine-a', root=True)
            plan = dict(machine='machine-a', executing_agent='worker', session='exact',
                        operation='invoke_root', environment='root', goal='fixture effect only')
            effect = issue(policy, actor, worker, plan)
            policy.set_organizer(actor, False)
            policy.set_organizer(actor, True)
            effects = []
            with pytest.raises(PermissionError, match='revoked'):
                with admitted(policy, effect):
                    effects.append('must never be admitted')
            assert effects == []
        finally:
            policy.close()
