"""Integration regression specifications. AST-only inspection; NOT_EXECUTED.

Synthetic process/transport boundaries confer no artifact or receiver approval.
"""
from pathlib import Path
from unittest.mock import patch
import pytest


@pytest.mark.parametrize('mode,ack', [('host', False), ('root', True), ('sandbox', False)])
def test_history_cli_forwards_exact_execution_policy_and_original_ack(tmp_path, mode, ack):
    from arvyx_control.onboarding_cli import main
    from arvyx_control.local_executor import ExecutionPolicy
    config = dict(host_uid=1001, allow_host=True, allow_root=True)
    policy_path = tmp_path/'operator-policy.json'
    home = tmp_path/'owned-home'
    workspace = tmp_path/'workspace'
    argv = ['history', '--hermes-home', str(home), '--workspace', str(workspace),
            '--execution-policy', str(policy_path), '--execution-mode', mode,
            '--authorize-native-launch', '--authorize-default-resume',
            '--new-hermes-profile', 'fixture-named']
    if ack:
        argv.append('--root-risk-acknowledged')
    with patch('arvyx_control.remote_effect_fence.private_config', return_value=config) as read, patch(
        'arvyx_control.terminal_sessions.history_menu', return_value=0
    ) as menu:
        assert main(argv) == 0
    read.assert_called_once_with(policy_path)
    args, options = menu.call_args
    assert args == (home,)
    assert isinstance(options['execution_policy'], ExecutionPolicy)
    assert options['execution_policy'].allow_host is True
    assert options['environment'] == mode
    assert options['root_acknowledged'] is ack
    assert options['workspace'] == workspace
    assert options['authorize_launch'] is True
    assert options['authorize_default_resume'] is True
    assert options['new_profile'] == 'fixture-named'
    assert not policy_path.exists() and not home.exists() and not workspace.exists()


def test_forwarded_preflight_expiry_refuses_before_attempt_or_dispatch(tmp_path):
    # Use a real durable source ticket and real endpoint binding; only transport
    # and clock are substituted. Root/cross-host qualification is not claimed.
    from arvyx_control.organizer_authority import OrganizerAuthority
    from arvyx_control.organizer_delegation import DelegationService
    from arvyx_control.executor_endpoint import ExecutorEndpoint
    from arvyx_control.replica_authority import authority_context
    from test_durable_organizer_journey import seed
    from delegation_fixture_helpers import issue, capabilities
    clock = [100.0]
    with authority_context(tmp_path/'vault'), patch('time.time', side_effect=lambda: clock[0]):
        policy = OrganizerAuthority(database=tmp_path/'policy.sqlite')
        actor, worker = seed(policy)
        policy.bind_executor(worker, machine='machine-a', environments=('host',))
        endpoint = ExecutorEndpoint('http://127.0.0.1:12345', 'synthetic',
            machine='machine-a', agent='worker', session='session-exact', environments=('host',))
        service = DelegationService(tmp_path/'requests.sqlite', policy, actor,
            {('machine-a', 'worker', 'session-exact'): endpoint})
        plan = dict(machine='machine-a', executing_agent='worker', session='session-exact',
                    operation='invoke_host', environment='host', goal='fixture only')
        calls = []
        def transport(path, data=None, *, deadline=None):
            calls.append(path)
            assert policy._backend.depth == 0
            if path != 'capabilities':
                pytest.fail('expired forwarded consent must not dispatch')
            clock[0] = 201.0
            return capabilities(policy, machine='machine-a', agent='worker',
                session='session-exact', environments=['host'])
        endpoint._call = transport
        try:
            effect = issue(policy, actor, worker, plan, expires=200.0)
            with pytest.raises(PermissionError, match='expired during binding discovery'):
                service.route('delegations/fenced-execute', 'POST', effect)
            assert calls == ['capabilities']
            assert service.db.execute('SELECT count(*) FROM organizer_requests').fetchone()[0] == 0
        finally:
            service.close()
            policy.close()
