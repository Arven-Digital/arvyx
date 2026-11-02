"""Local-only creation contract; no harnesses or provider calls are exercised."""
import hashlib
import sqlite3
from dataclasses import FrozenInstanceError

import pytest

from arvyx_control.agent_creation import (
    AgentCreation, AgentCreationError, CreationRequest, IdentityFile,
)


@pytest.fixture
def service(tmp_path):
    root = tmp_path / 'profiles'
    root.mkdir()
    db = sqlite3.connect(':memory:')
    return AgentCreation(db, root, workspace_id='workspace', local_host='local',
                         isolated_harnesses={'hermes'})


def request(name='Ada', **kwargs):
    return CreationRequest(name=name, harness='hermes', owner_host='local', **kwargs)


def approved(source, name='SOUL.md', content='A deliberately clean identity.\n'):
    (source / name).write_text(content)
    return IdentityFile(name, hashlib.sha256(content.encode()).hexdigest())


def test_clean_identity_and_immutable_separate_ids(service):
    agent = service.create(request(provider_auth_handle='vault:shared-provider'))
    assert agent.kind == 'new_agent'
    assert agent.provider_auth_handle == 'vault:shared-provider'
    assert agent.agent_id != agent.session_namespace != agent.memory_namespace
    assert list((service.profiles_root / agent.agent_id).iterdir()) == []
    with pytest.raises(FrozenInstanceError):
        agent.agent_id = 'changed'
    other = service.create(request('Grace', provider_auth_handle='vault:shared-provider'))
    assert other.provider_auth_handle == agent.provider_auth_handle
    assert other.memory_namespace != agent.memory_namespace


@pytest.mark.parametrize('name', ['', '  ', '\n', ' Ada ', 'ada', 'Ａｄａ'])
def test_invalid_or_workspace_duplicate_names(service, name):
    service.create(request())
    with pytest.raises(AgentCreationError):
        service.create(request(name))
    assert len(service.list_agents()) == 1


def test_attach_is_not_creation(service):
    attached = service.attach(host='local', session_id='existing-session')
    assert attached.kind == 'existing_attach'
    assert attached.session_id == 'existing-session'
    assert not hasattr(attached, 'agent_id')
    assert service.list_agents() == ()


def test_remote_owner_and_unsupported_isolation_fail_closed(service):
    with pytest.raises(AgentCreationError):
        service.create(request('Remote', remote_workspace_id='remote-workspace'))
    with pytest.raises(AgentCreationError):
        service.create(CreationRequest('Remote', 'hermes', 'remote'))
    agent = service.create(CreationRequest('Remote', 'hermes', 'remote',
                                          remote_workspace_id='owned-workspace'))
    assert agent.owner_host == 'remote'
    assert agent.remote_workspace_id == 'owned-workspace'
    assert agent.status == 'metadata_only'
    with pytest.raises(AgentCreationError):
        service.create(CreationRequest('Unsupported', 'unknown', 'local'))


def test_selected_approved_copy_preserves_source(service, tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    selected = approved(source)
    (source / 'USER.md').write_text('Not selected')
    (source / 'credentials.json').write_text('Not transferable')
    agent = service.create(request(source_root=source, identity_files=(selected,)))
    destination = service.profiles_root / agent.agent_id
    assert sorted(p.name for p in destination.iterdir()) == ['SOUL.md']
    assert (destination / 'SOUL.md').read_bytes() == (source / 'SOUL.md').read_bytes()
    assert (source / 'USER.md').read_text() == 'Not selected'
    assert (source / 'credentials.json').exists()


@pytest.mark.parametrize('name', ['../SOUL.md', '/SOUL.md', 'nested/SOUL.md',
                                  'credentials.json', '.env', 'MEMORY.md'])
def test_traversal_and_nonidentity_rejected(service, tmp_path, name):
    with pytest.raises(AgentCreationError):
        service.create(request(source_root=tmp_path,
                               identity_files=(IdentityFile(name, '0' * 64),)))
    assert service.list_agents() == ()
    assert list(service.profiles_root.iterdir()) == []


def test_symlink_secret_and_unapproved_content_rejected(service, tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    item = approved(source)
    (source / 'SOUL.md').unlink()
    (source / 'SOUL.md').symlink_to(tmp_path / 'outside')
    with pytest.raises(AgentCreationError):
        service.create(request(source_root=source, identity_files=(item,)))
    (source / 'SOUL.md').unlink()
    item = approved(source, content='api_key=sk-' + 'x' * 48)
    with pytest.raises(AgentCreationError):
        service.create(request(source_root=source, identity_files=(item,)))
    item = approved(source)
    (source / 'SOUL.md').write_text('Changed since approval')
    with pytest.raises(AgentCreationError):
        service.create(request(source_root=source, identity_files=(item,)))
    assert service.list_agents() == ()


def test_database_failure_rolls_back_files_and_name(service, tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    item = approved(source)
    service.db.execute("CREATE TRIGGER reject_agent BEFORE INSERT ON created_agents "
                       "BEGIN SELECT RAISE(ABORT, 'injected failure'); END")
    service.db.commit()
    with pytest.raises(AgentCreationError):
        service.create(request(source_root=source, identity_files=(item,)))
    assert list(service.profiles_root.iterdir()) == []
    assert service.list_agents() == ()
    assert (source / 'SOUL.md').read_text() == 'A deliberately clean identity.\n'
    service.db.execute('DROP TRIGGER reject_agent')
    service.db.commit()
    assert service.create(request()).name == 'Ada'


def test_profile_root_symlink_rejected(service, tmp_path):
    link = tmp_path / 'link'
    link.symlink_to(service.profiles_root, target_is_directory=True)
    other = AgentCreation(sqlite3.connect(':memory:'), link, workspace_id='workspace',
                          local_host='local', isolated_harnesses={'hermes'})
    with pytest.raises(AgentCreationError):
        other.create(request())


def test_existing_profile_is_never_overwritten(service, monkeypatch):
    from arvyx_control import agent_creation
    identifier = 'a' * 32
    existing = service.profiles_root / identifier
    existing.mkdir()
    (existing / 'SOUL.md').write_text('Original owner')
    class FixedUUID:
        hex = identifier
    monkeypatch.setattr(agent_creation.uuid, 'uuid4', FixedUUID)
    with pytest.raises(AgentCreationError):
        service.create(request())
    assert (existing / 'SOUL.md').read_text() == 'Original owner'
    assert service.list_agents() == ()


def test_file_failure_rolls_back(service, tmp_path, monkeypatch):
    from arvyx_control import agent_creation
    source = tmp_path / 'source'
    source.mkdir()
    item = approved(source)
    def fail(_fd):
        raise OSError('injected fsync failure')
    monkeypatch.setattr(agent_creation.os, 'fsync', fail)
    with pytest.raises(AgentCreationError):
        service.create(request(source_root=source, identity_files=(item,)))
    assert service.list_agents() == ()
    assert list(service.profiles_root.iterdir()) == []
    assert (source / 'SOUL.md').exists()


def test_hardlink_and_ancestor_symlink_rejected(service, tmp_path):
    import os
    source = tmp_path / 'source'
    source.mkdir()
    item = approved(source)
    os.link(source / 'SOUL.md', source / 'alias')
    with pytest.raises(AgentCreationError):
        service.create(request(source_root=source, identity_files=(item,)))
    (source / 'alias').unlink()
    link = tmp_path / 'alias-root'
    link.symlink_to(source, target_is_directory=True)
    with pytest.raises(AgentCreationError):
        service.create(request(source_root=link, identity_files=(item,)))
    assert (source / 'SOUL.md').exists()


def test_workspace_duplicate_constraint_across_connections(tmp_path):
    root = tmp_path / 'profiles'
    root.mkdir()
    path = tmp_path / 'catalog.sqlite'
    one = AgentCreation(sqlite3.connect(path), root, workspace_id='same',
                        local_host='local', isolated_harnesses={'hermes'})
    two = AgentCreation(sqlite3.connect(path), root, workspace_id='same',
                        local_host='other', isolated_harnesses={'hermes'})
    one.create(request())
    with pytest.raises(AgentCreationError):
        two.create(CreationRequest('ADA', 'hermes', 'other'))
    assert len(two.list_agents()) == 1
    assert len(list(root.iterdir())) == 1


def test_default_capabilities_fail_closed(tmp_path):
    service = AgentCreation(sqlite3.connect(':memory:'), tmp_path,
                            workspace_id='workspace', local_host='local')
    with pytest.raises(AgentCreationError):
        service.create(request())
    assert list(tmp_path.iterdir()) == []


def test_auth_handle_not_arbitrary_credentials(service):
    with pytest.raises(AgentCreationError):
        service.create(request(provider_auth_handle='sk-' + 'x' * 48))


def test_post_commit_close_failure_reports_published_identity(service, monkeypatch):
    from arvyx_control import agent_creation
    real_close = agent_creation.os.close
    injected = []

    def fail_after_commit(fd):
        real_close(fd)
        if (not injected and not service.db.in_transaction
                and service.db.execute('SELECT COUNT(*) FROM created_agents').fetchone()[0] == 1):
            injected.append(fd)
            raise OSError('injected post-publication close failure')

    with monkeypatch.context() as scoped:
        scoped.setattr(agent_creation.os, 'close', fail_after_commit)
        with pytest.raises(AgentCreationError, match='published; cleanup failed; do not retry') as error:
            service.create(request())
    assert injected
    agent, = service.list_agents()
    assert agent.agent_id in str(error.value)
    assert 'nothing published' not in str(error.value)
    assert (service.profiles_root / agent.agent_id).is_dir()
