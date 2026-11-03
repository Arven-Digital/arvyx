"""Authored offline; NOT_EXECUTED. Synthetic fixtures are not product acceptance.

Run only after integration into a complete candidate and explicit test permission.
"""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
from test_local_onboarding_services import services
import os

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='tests open directories with POSIX flags')


def test_rev0023_duplicate_classifications_fail_before_validation(tmp_path):
    source = Path(__file__).resolve().parents[3] / 'scripts/public_release_boundary.py'
    spec = importlib.util.spec_from_file_location('focus75_boundary', source)
    boundary = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(boundary)
    manifest = tmp_path / 'manifest.json'
    for document in (
        '{"version":1,"paths":{"a":"private-only","a":"public-approved"}}',
        '{"version":1,"paths":{},"paths":{"a":"public-approved"}}',
    ):
        manifest.write_text(document)
        with pytest.raises(boundary.BoundaryError, match='duplicate key'):
            boundary.load_manifest(manifest)
    manifest.write_text(json.dumps({'version': 1, 'paths': {'a': 'private-only'}}))
    assert boundary.validate_tracked_paths(manifest, ['a']) == {'a': 'private-only'}
    with pytest.raises(boundary.BoundaryError, match='unclassified tracked paths'):
        boundary.validate_tracked_paths(manifest, ['a', 'b'])
    with pytest.raises(boundary.BoundaryError, match='not tracked'):
        boundary.validate_tracked_paths(manifest, [])


def test_rev0024_check_cli_preserves_explicit_capability(monkeypatch, tmp_path):
    from arvyx_control import native_install
    observed = []
    def inspect(destination, *, required_capability):
        observed.append((destination, required_capability))
        # Synthetic refusal only; never enroll or approve an artifact.
        raise ValueError('requested capability unavailable')
    monkeypatch.setattr(native_install, 'check', inspect)
    assert native_install.main(['--check', str(tmp_path), '--require-capability', 'onboarding-v1']) == 2
    assert observed == [(tmp_path, 'onboarding-v1')]


def test_rev0024_check_passes_requirement_to_byte_verifier(monkeypatch, tmp_path):
    import os
    from arvyx_control import native_install
    (tmp_path / 'native-install.json').write_text('{"binary_sha256":"synthetic"}')
    monkeypatch.setattr(native_install, 'open_native_directory', lambda p: os.open(p, os.O_RDONLY | os.O_DIRECTORY))
    monkeypatch.setattr(native_install, 'read_native_bytes', lambda p: b'synthetic-not-approved')
    observed = []
    def refuse(data, binding, *, required_capability):
        observed.append(required_capability)
        raise ValueError('synthetic verifier refuses; no trust granted')
    monkeypatch.setattr(native_install, 'verify_native_bytes', refuse)
    with pytest.raises(ValueError, match='no trust granted'):
        native_install.check(tmp_path, required_capability='onboarding-v1')
    assert observed == ['onboarding-v1']


def test_rev0045_primary_without_binding_has_actionable_refusal(monkeypatch, tmp_path):
    from arvyx_control.cockpit import LocalCockpit
    from arvyx_control import cockpit_primary
    closed = []
    class Registry:
        def __init__(self, *args): pass
        def snapshot(self): return {'agent_id': 'human-primary'}
        def close(self): closed.append(True)
    monkeypatch.setattr(cockpit_primary, 'PrimaryAgentRegistry', Registry)
    owner = SimpleNamespace(_human=lambda actor: None, state=tmp_path/'state', organizer_bindings={})
    # Unit-only validation branch; deliberately not an authority-boundary proof.
    with pytest.raises(ValueError, match='selected primary has no configured native organizer binding'):
        LocalCockpit.open_organizer.__wrapped__(owner, actor='synthetic-human')
    assert closed == [True]
    assert owner.organizer_bindings == {}
    for value in ([], 3, ''):
        with pytest.raises(ValueError):
            LocalCockpit.open_organizer.__wrapped__(owner, value, actor='synthetic-human')


def test_rev0065_metadata_creation_and_recovery_never_claim_native_session(services):
    _, call, _, _ = services
    status, prepared = call('agents/prepare', dict(name='Metadata Only', harness='hermes', environment='metadata', identity_mode='clean'))
    assert status == 200
    status, result = call('agents/commit', dict(consent_id=prepared['consent_id'], consent_sha256=prepared['sha256'], confirmed=True))
    assert status == 201
    assert result['metadata_only'] is True
    assert result['environment'] == 'metadata'
    assert result['execution'] is False
    assert result['native_session_created'] is False
    status, recovery = call('agents/attempts/' + prepared['consent_id'])
    assert status == 200
    assert recovery['result'] == result
