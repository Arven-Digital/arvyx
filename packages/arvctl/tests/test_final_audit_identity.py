"""Source-only regression specifications; execution requires separate approval."""
import json
from unittest.mock import Mock

import pytest

from arvyx_control import evidence
from arvyx_control.audit import AuditCheck, AuditResult
from arvyx_control.onboarding_cli import Onboarding


def audit_result():
    return AuditResult(False, True, [
        AuditCheck('private_context', 'scan', False, [], ['missing denylist']),
        AuditCheck('vault_doctor', 'doctor', True, [], []),
        AuditCheck('demo', 'demo', True, [], []),
    ], ['release review missing'])


def test_operation_reuses_one_audit_but_not_vault_checks(monkeypatch, tmp_path):
    monkeypatch.setattr(evidence._AuditOperation, '_binding', lambda self: b'bound')
    full = Mock(return_value=audit_result())
    doctor = Mock(return_value=AuditCheck('vault_doctor', 'doctor', False, [], ['bad vault']))
    demo = Mock(return_value=AuditCheck('demo', 'demo', True, [], []))
    monkeypatch.setattr(evidence, 'run_audit', full)
    monkeypatch.setattr(evidence, '_doctor_check', doctor)
    monkeypatch.setattr(evidence, '_demo_check', demo)
    with evidence._audit_operation(tmp_path) as operation:
        first = operation.audit(tmp_path, tmp_path / 'one')
        first.release_blockers.clear()  # consumer mutation cannot corrupt reuse
        second = operation.audit(tmp_path, tmp_path / 'two')
        assert second.release_blockers == ['release review missing',
            'audit check failed: private_context', 'audit check failed: vault_doctor']
        assert second.ok is False
        assert second.checks[0].findings == ['missing denylist']
    assert full.call_count == 1
    doctor.assert_called_once_with(tmp_path / 'two')
    demo.assert_called_once_with(tmp_path / 'two')
    with pytest.raises(ValueError):
        operation.audit(tmp_path, tmp_path / 'three')
    with evidence._audit_operation(tmp_path) as fresh:
        fresh.audit(tmp_path, tmp_path / 'one')
    assert full.call_count == 2


def test_release_report_threads_one_invocation_operation(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from arvyx_control import release_candidate
    monkeypatch.setattr(evidence._AuditOperation, '_binding', lambda self: b'bound')
    full = Mock(return_value=audit_result())
    monkeypatch.setattr(evidence, 'run_audit', full)
    monkeypatch.setattr(evidence, '_doctor_check', lambda v: AuditCheck('vault_doctor', '', True, [], []))
    monkeypatch.setattr(evidence, '_demo_check', lambda v: AuditCheck('demo', '', True, [], []))
    operations = []
    def export(**kwargs):
        operation = kwargs['_operation']
        operations.append(operation)
        audit = operation.audit(kwargs['repo'], kwargs['vault']).to_dict()
        return SimpleNamespace(release_blockers=['release review missing'], to_dict=lambda: {
            'audit': audit, 'recall_benchmarks': {'lexical': {'ok': True}},
            'readiness': {'score': 100}, 'worktree': {'clean': True}})
    def dogfood(**kwargs):
        operation = kwargs['_operation']
        operations.append(operation)
        result = operation.audit(kwargs['repo'], tmp_path / 'synthetic-vault')
        return SimpleNamespace(ok=result.ok, to_dict=lambda: {'ok': result.ok})
    monkeypatch.setattr(release_candidate, 'export_evidence', export)
    monkeypatch.setattr(release_candidate, 'dogfood_self', dogfood)
    monkeypatch.setattr(release_candidate, '_non_release_grade_signers', lambda *a, **k: set())
    report = release_candidate.release_candidate_report(tmp_path, tmp_path / 'vault', tmp_path / 'cases')
    assert full.call_count == 1
    assert operations[0] is operations[1]
    assert operations[0].active is False
    assert not report.private_preview_allowed
    assert not report.public_release_allowed


def test_operation_rejects_repo_or_policy_drift(monkeypatch, tmp_path):
    binding = [b'first']
    monkeypatch.setattr(evidence._AuditOperation, '_binding', lambda self: binding[0])
    monkeypatch.setattr(evidence, 'run_audit', Mock(return_value=audit_result()))
    operation = evidence._AuditOperation(tmp_path)
    with pytest.raises(ValueError):
        operation.audit(tmp_path / 'other', tmp_path)
    binding[0] = b'changed'
    with pytest.raises(ValueError):
        operation.audit(tmp_path, tmp_path)
    evidence.run_audit.assert_not_called()


def test_operation_rejects_drift_during_audit(monkeypatch, tmp_path):
    binding = [b'first']
    monkeypatch.setattr(evidence._AuditOperation, '_binding', lambda self: binding[0])
    def drift(**kwargs):
        binding[0] = b'changed'
        return audit_result()
    monkeypatch.setattr(evidence, 'run_audit', drift)
    operation = evidence._AuditOperation(tmp_path)
    with pytest.raises(ValueError):
        operation.audit(tmp_path, tmp_path)


def test_binding_covers_external_terms_environment_and_ignored_reviews(monkeypatch, tmp_path):
    # Git calls are isolated here; this specifies binding semantics, not git acceptance.
    monkeypatch.setattr(evidence.subprocess, 'run', lambda *a, **k: Mock(returncode=0, stdout=b'tree'))
    monkeypatch.setattr(evidence, 'iter_source_files', lambda repo: [repo / 'source.py'])
    terms = ['synthetic-test-term']
    monkeypatch.setattr(evidence, 'load_private_denylist', lambda repo: terms)
    source = tmp_path / 'source.py'
    source.write_text('initial')
    operation = evidence._AuditOperation(tmp_path)
    source.write_text('changed')
    assert operation._binding() != operation.binding
    source.write_text('initial')
    terms.append('second-synthetic-term')
    assert operation._binding() != operation.binding
    terms.pop()
    monkeypatch.setenv('AMC_TEST_POLICY', 'changed')
    assert operation._binding() != operation.binding
    monkeypatch.delenv('AMC_TEST_POLICY')
    review = tmp_path / '.arvyx/release-reviews/security-audit.attestation.json'
    review.parent.mkdir(parents=True)
    review.write_text('{}')
    assert operation._binding() != operation.binding


def test_immutable_organizer_reopen_and_display_rename(tmp_path):
    store = Onboarding(tmp_path / 'state')
    record = store.connect({'id': 'candidate-one'}, 'Alice')
    identity = record['connection_id']
    with pytest.raises(ValueError):
        store.organizer('Alice')
    store.organizer(identity)
    record['name'] = 'Renamed'
    with store.db:
        store.db.execute('UPDATE connections SET name=?, record=? WHERE id=?',
                         ('Renamed', json.dumps(record), 'candidate-one'))
    store.close()
    store = Onboarding(tmp_path / 'state')
    try:
        authority, actor = store.authority()
        assert actor.principal == identity
        assert authority.authorize(actor, operation='create_agent', machine='local').allowed
        assert not authority.authorize(actor, operation='invoke_root', machine='local').allowed
    finally:
        store.close()


def test_legacy_never_guessed_and_explicit_migration_is_atomic(tmp_path):
    store = Onboarding(tmp_path / 'state')
    try:
        first = store.connect({'id': 'row-one'}, 'Alice')
        second = store.connect({'id': 'row-two'}, 'Bob')
        # Simulate pre-identity connection rows without deriving IDs from names.
        first.pop('connection_id')
        with store.db:
            store.db.execute('UPDATE connections SET record=? WHERE id=?', (json.dumps(first), 'row-one'))
            store.db.execute("INSERT INTO setup VALUES('organizer','Alice')")
        assert store.status()['organizer']['migration_required'] is True
        with pytest.raises(ValueError):
            store.authority()
        with pytest.raises(ValueError):
            store.create('NoBypass')
        with pytest.raises(ValueError):
            store.organizer(second['connection_id'])
        for kwargs in (
            dict(expected_legacy='Alice', connection_row_id='row-one'),
            dict(expected_legacy='wrong', connection_row_id='row-one', confirmed=True),
            dict(expected_legacy='Alice', connection_row_id='missing', confirmed=True),
        ):
            with pytest.raises(ValueError):
                store.migrate_legacy_organizer(**kwargs)
            assert store.status()['organizer']['legacy_value'] == 'Alice'
        # Explicit selection need not match the legacy display name: no inference.
        identity = store.migrate_legacy_organizer(expected_legacy='Alice',
                        connection_row_id='row-two', confirmed=True)
        assert identity == second['connection_id']
        assert store.authority()[1].principal == identity
    finally:
        store.close()


def test_legacy_connection_gets_new_id_only_on_explicit_selection(tmp_path):
    store = Onboarding(tmp_path / 'state')
    try:
        record = store.connect({'id': 'row'}, 'Alice')
        record.pop('connection_id')
        with store.db:
            store.db.execute('UPDATE connections SET record=? WHERE id=?', (json.dumps(record), 'row'))
            store.db.execute("INSERT INTO setup VALUES('organizer','Alice')")
        identity = store.migrate_legacy_organizer(expected_legacy='Alice', connection_row_id='row', confirmed=True)
        assert identity.startswith('connection:')
        assert store.authority()[1].principal == identity
        with store.db:
            store.db.execute("DELETE FROM connections WHERE id='row'")
        with pytest.raises(ValueError):
            store.authority()
    finally:
        store.close()



def test_binding_ignores_vault_runtime_state_but_not_vault_sources(tmp_path):
    # Regression (CI package-smoke): auditing an in-repository vault creates its
    # .arvyx index cache and lock during the operation; that is derived state.
    import subprocess
    from arvyx_control import evidence
    repo = tmp_path / "repo"
    vault = repo / "fixtures" / "synthetic-vault"
    (vault / "projects").mkdir(parents=True)
    (vault / "projects" / "note.md").write_text("# Note\n", encoding="utf-8")
    (repo / ".gitignore").write_text(".arvyx/\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                    "commit", "-q", "-m", "fixture"], check=True)
    operation = evidence._AuditOperation(repo)
    (vault / ".arvyx").mkdir()
    (vault / ".arvyx" / "index.json").write_text("{}", encoding="utf-8")
    (vault / ".arvyx" / "index-publication.lock").write_text("", encoding="utf-8")
    operation.validate(repo)
    (vault / "projects" / "note.md").write_text("# Changed\n", encoding="utf-8")
    with pytest.raises(ValueError, match="source or policy changed"):
        operation.validate(repo)
    fresh = evidence._AuditOperation(repo)
    (repo / "config").mkdir()
    (repo / "config" / "policy.txt").write_text("ignored policy still binds\n", encoding="utf-8")
    with pytest.raises(ValueError, match="source or policy changed"):
        fresh.validate(repo)
