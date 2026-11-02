import pytest
from arvyx_control.agent_sessions import RoutingError
from arvyx_control.hermes_profile_launch import NewHermesProfile


def test_reference_plan_is_clean_and_requires_confirmation(tmp_path):
    root = tmp_path/'.hermes'; root.mkdir()
    workspace = tmp_path/'workspace'; workspace.mkdir()
    adapter = NewHermesProfile('amc-clean-test', root=root, executable='/bin/hermes')
    with pytest.raises(RoutingError, match='confirmation'):
        adapter.prepare(workspace)
    assert not adapter.home.exists()
    history = adapter.prepare(workspace, confirmed=True)
    argv, env = history.launch_plan(workspace, authorized=True)
    assert '--resume' not in argv
    assert env['HERMES_HOME'] == str(adapter.home)
    assert set(p.name for p in adapter.home.iterdir()) == {'config.yaml'}
    assert 'openai-codex' in (adapter.home/'config.yaml').read_text()
    assert 'OPENAI_API_KEY' not in env
    with pytest.raises(RoutingError, match='exists'):
        adapter.prepare(workspace, confirmed=True)


@pytest.mark.parametrize('name', ['default', '../escape', '', 'a/b'])
def test_invalid_name_refused(tmp_path, name):
    with pytest.raises(RoutingError):
        NewHermesProfile(name, root=tmp_path)


def test_workspace_identity_rejected(tmp_path):
    root = tmp_path/'root'; root.mkdir()
    workspace = tmp_path/'workspace'; workspace.mkdir()
    (workspace/'AGENTS.md').write_text('existing identity')
    with pytest.raises(RoutingError, match='workspace identity'):
        NewHermesProfile('clean', root=root).prepare(workspace, confirmed=True)
