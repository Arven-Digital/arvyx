"""Unexecuted synthetic regressions. No live/provider/native qualification."""
import json
from unittest.mock import patch
import pytest
from arvyx_control.executor_endpoint import ExecutorEndpoint
from arvyx_control.organizer_authority import OrganizerAuthority
from arvyx_control.organizer_delegation import DelegationService
from arvyx_control.replica_authority import authority_context
from arvyx_control.harness_discovery import discovery_catalog
from test_durable_organizer_journey import seed, body, consent
from delegation_fixture_helpers import capabilities, admitted


@pytest.mark.parametrize('change', ['unchanged', 'leaf', 'revoke', 'expired'])
def test_binding_preflight_is_outside_guard_and_revalidated(tmp_path, change):
    with authority_context(tmp_path/'vault'):
        policy = OrganizerAuthority(database=tmp_path/'policy.sqlite')
        actor, _ = seed(policy)
        endpoint = ExecutorEndpoint('http://127.0.0.1:12345', 'fixture',
            machine='machine-a', agent='worker', session='session-exact',
            environments=('root',))
        service = DelegationService(tmp_path/'requests.sqlite', policy, actor,
            {('machine-a', 'worker', 'session-exact'): endpoint})
        phase = ['prepare']
        effects = []
        def call(path, data=None, *, deadline=None):
            assert policy._backend.depth == 0, 'transport under sender policy guard'
            if path == 'capabilities':
                if phase[0] == 'commit':
                    if change == 'revoke':
                        policy.set_organizer(actor, False)
                    if change == 'expired':
                        service.db.execute('UPDATE organizer_requests SET expires=0')
                        service.db.commit()
                return capabilities(policy, machine='machine-a', agent='worker',
                    session='session-exact', environments=['root'],
                    receiving_leaf=('b' if phase[0]=='commit' and change=='leaf' else 'a')*64)
            with admitted(policy, data):
                effects.append(data)
            return dict(request_id=data['request_id'], status='completed', reference='fixture')
        endpoint._call = call
        try:
            review = service.route('delegations/prepare', 'POST', body())[1]
            phase[0] = 'commit'
            if change == 'unchanged':
                assert service.route('delegations/commit', 'POST', consent(review))[0] == 200
                assert len(effects) == 1
                assert effects[0]['root_acknowledged'] is True
            else:
                with pytest.raises((ValueError, PermissionError)):
                    service.route('delegations/commit', 'POST', consent(review))
                assert effects == []
        finally:
            service.close()
            policy.close()


def test_native_doctor_preserves_requested_capability():
    from arvyx_control import native_install
    # No filesystem/native bytes needed: exercise the CLI-to-check contract.
    with patch.object(native_install, 'check', return_value={}) as check:
        assert native_install.main(['--check', '/fixture', '--require-capability', 'onboarding-v1']) == 0
        from pathlib import Path
        check.assert_called_once_with(Path('/fixture'), required_capability='onboarding-v1')


def test_descriptors_do_not_claim_verified_runtime_adapters():
    catalog = discovery_catalog('linux')
    assert all(row['metadata_discovery_supported'] == row['supported'] for row in catalog)
    assert all(row['runtime_adapter_verified'] is False for row in catalog)
    assert [row['family'] for row in catalog if row['manual_metadata_connection_supported']] == ['hermes', 'claude', 'codex']


def test_remote_root_attestation_not_synthesized(tmp_path):
    from arvyx_control.remote_delegation import RemoteDelegationEndpoint
    with patch('arvyx_control.shared_onboarding_cli.client', return_value=lambda *a, **k: pytest.fail('no transport before acknowledgement validation')):
        endpoint = RemoteDelegationEndpoint(tmp_path/'links.sqlite',
            'http://127.0.0.1:12345', 'fixture', machine='machine-a')
    try:
        # The acknowledgement is checked even on non-root transports; root itself
        # still requires independently provisioned receiver capability.
        for value in (None, 'true', 1):
            with pytest.raises(PermissionError, match='acknowledgement'):
                endpoint.execute(dict(environment='host', operation='invoke_host', root_acknowledged=value))
        assert endpoint.db.execute('SELECT count(*) FROM remote_delegation_links').fetchone()[0] == 0
    finally:
        endpoint.close()
