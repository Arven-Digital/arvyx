import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
from unittest import mock
import urllib.error
from email.message import Message

import pytest

ROOT = Path(__file__).resolve().parents[3]


def load_guard():
    source = ROOT/'deploy/hermes-patches/hermes_patch_guard.py'
    if not source.is_file():
        pytest.skip('deployment patch guard is not part of this checkout')
    spec = importlib.util.spec_from_file_location('ops_guard', source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_guard_conflict_is_unknown_not_delivery():
    guard = load_guard()
    error = urllib.error.HTTPError('http://127.0.0.1:8766/mcp', 409, 'Conflict', Message(), io.BytesIO(b'{"error":"operation_reconciliation_required"}'))
    with mock.patch.object(guard._OPENER, 'open', side_effect=error):
        with pytest.raises(RuntimeError, match='effect unknown; reconcile operation hermes-patch-guard-'):
            guard.post_thread('http://127.0.0.1:8766', 'synthetic', agent='fixture', notify='reviewer', missing=['marker'])


def test_guard_redirect_handler_never_builds_a_forwarded_request():
    guard = load_guard()
    assert guard._NoRedirect().redirect_request(None, None, 302, '', {}, 'https://other.invalid/') is None


def test_guard_requires_matching_confirmed_thread():
    guard = load_guard()
    def reply(request, **kwargs):
        body = json.loads(request.data)
        title = body['params']['arguments']['title']
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps({'result': {'structuredContent': {'id': 'thread_'+'a'*12+'_'+'b'*6, 'target': 'reviewer', 'title': title}}}).encode()
        return response
    with mock.patch.object(guard._OPENER, 'open', side_effect=reply):
        assert guard.post_thread('http://127.0.0.1:8766', 'synthetic', agent='fixture', notify='reviewer', missing=['marker']) == 'posted'
    response = mock.MagicMock()
    response.__enter__.return_value.read.return_value = b'{"result":{}}'
    with mock.patch.object(guard._OPENER, 'open', return_value=response):
        with pytest.raises(RuntimeError, match='matching thread identity'):
            guard.post_thread('http://127.0.0.1:8766', 'synthetic', agent='fixture', notify='reviewer', missing=['marker'])


def canonical_program():
    text = (ROOT/'.github/workflows/release-provenance.yml').read_text()
    block = text.split('- name: Require successful canonical CI on exact tag SHA', 1)[1]
    block = block.split("python - <<'PY'\n", 1)[1].split('\n          PY', 1)[0]
    return '\n'.join(line[10:] for line in block.splitlines())


def canonical_fixture():
    repo, sha = 'fixture/repository', 'a'*40
    run = dict(id=11, run_number=3, run_attempt=2, check_suite_id=22, head_sha=sha,
               path='.github/workflows/ci.yml', repository={'full_name': repo},
               head_repository={'full_name': repo}, event='push', status='completed', conclusion='success')
    names = ['test'] + [f'{system} / Python {version}' for system in ('ubuntu-latest', 'macos-latest', 'windows-latest') for version in ('3.11', '3.12', '3.13')]
    jobs, checks = [], []
    for index, name in enumerate(names):
        url = f'https://api.github.com/repos/{repo}/check-runs/{100+index}'
        jobs.append(dict(name=name, run_id=11, head_sha=sha, status='completed', conclusion='success', check_run_url=url))
        checks.append(dict(name=name, url=url, head_sha=sha, status='completed', conclusion='success', app={'slug': 'github-actions'}, check_suite={'id': 22}))
    return repo, sha, run, jobs, checks


def evaluate_canonical(tmp_path, runs, jobs, checks):
    repo, sha, *_ = canonical_fixture()
    (tmp_path/'ci-runs.json').write_text(json.dumps([{'workflow_runs': runs}]))
    # Required checks can span pages; they must bind the exact run's jobs.
    (tmp_path/'check-runs.json').write_text(json.dumps([{'check_runs': checks[:1]}, {'check_runs': checks[1:]}]))
    with mock.patch.dict(os.environ, RUNNER_TEMP=str(tmp_path), GITHUB_REPOSITORY=repo, GITHUB_SHA=sha), mock.patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, json.dumps([{'jobs': jobs}]))):
        exec(compile(canonical_program(), '<canonical-CI-regression>', 'exec'), {})


def test_canonical_ci_accepts_bound_success_across_pages(tmp_path):
    _, _, run, jobs, checks = canonical_fixture()
    evaluate_canonical(tmp_path, [run], jobs, checks)


@pytest.mark.parametrize('mutation', ['latest_failed', 'wrong_app', 'wrong_suite', 'foreign_job', 'missing_check', 'duplicate_job'])
def test_canonical_ci_refuses_unbound_or_nonlatest_success(tmp_path, mutation):
    _, _, run, jobs, checks = canonical_fixture()
    runs = [run]
    if mutation == 'latest_failed':
        failed = copy.deepcopy(run); failed.update(id=12, run_number=4, conclusion='failure'); runs.append(failed)
    elif mutation == 'wrong_app': checks[0]['app']['slug'] = 'other-app'
    elif mutation == 'wrong_suite': checks[0]['check_suite']['id'] = 99
    elif mutation == 'foreign_job': jobs[0]['run_id'] = 99
    elif mutation == 'missing_check': checks.pop(0)  # the aggregate `test` check is required by every edition of the gate
    elif mutation == 'duplicate_job': jobs.append(copy.deepcopy(jobs[0]))
    with pytest.raises(SystemExit):
        evaluate_canonical(tmp_path, runs, jobs, checks)


def test_capture_source_binds_ephemeral_child_and_served_identity():
    text = (ROOT/'apps/control-center-web/scripts/capture.mjs').read_text()
    assert "(('127.0.0.1', 0)" in text
    assert 'const port = 4177' not in text
    assert 'JSON.stringify(await response.json()) === JSON.stringify(BUILD)' in text
    assert 'response.headerValue("x-amc-capture")' in text


def test_negative_terminal_claims_are_unmeasured():
    installed = (ROOT/'scripts/terminal_installed_acceptance.py').read_text()
    assert 'provider_input_sent=None, fresh_startup_invoked=None, auth_resolver_invoked=None' in installed
    mouse = (ROOT/'scripts/terminal_native_mouse_acceptance.py').read_text()
    assert "'typed_provider_input':None" in mouse
    assert "'search_consumed_by_client':None" in mouse
    assert "receipt['unmeasured']" in mouse
