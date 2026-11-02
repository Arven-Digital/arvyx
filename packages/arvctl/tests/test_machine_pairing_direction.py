import json
import os
import subprocess
import shutil
import sys
import time


def test_main_issues_remote_confirms_main_approves(tmp_path):
    module = [sys.executable, '-m', 'arvyx_control.machine_pairing_cli']
    def run(*args):
        return subprocess.run(module + list(args), capture_output=True, text=True, timeout=10)
    main = ['--state-dir', str(tmp_path/'main')]
    server = subprocess.Popen(module + ['serve', *main, '--port', '0'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    amc = [sys.executable, '-m', 'arvyx_control.onboarding_cli']
    assert server.stdout is not None
    try:
        url = json.loads(server.stdout.readline())['url']
        remote = ['--state-dir', str(tmp_path/'remote'), '--url', url, '--name', 'remote']
        issued = run('issue', *main)
        assert issued.returncode == 0, issued.stderr
        code = json.loads(issued.stdout)['code']
        claimed = subprocess.run([*amc, '-confirm', code, *remote], capture_output=True, text=True, timeout=10)
        assert claimed.returncode == 0, claimed.stderr
        claim = json.loads(claimed.stdout)
        assert claim['status'] == 'pending_main_approval'
        assert 'code' not in claim
        fp = claim['fingerprint']
        pending = json.loads(run('pending', *main).stdout)['claims']
        assert len(pending) == 1 and pending[0]['fingerprint'] == fp
        reviewed = json.dumps(pending[0])
        assert not (tmp_path/'remote'/'pairing.sqlite3').exists()
        assert not json.loads(run('check', *remote).stdout)['allowed']
        assert run('confirm', code, *remote).returncode != 0
        review = ['--review-snapshot', reviewed]
        # The CLI never refreshes the reviewed record implicitly.
        assert run('approve', fp, *main, '--actor', 'owner', '--approve').returncode != 0
        tampered = json.dumps(dict(pending[0], name='not-what-was-reviewed'))
        assert run('approve', fp, *main, '--actor', 'owner', '--approve', '--review-snapshot', tampered).returncode != 0
        assert run('approve', fp, *main, '--actor', 'owner', *review).returncode != 0
        assert not json.loads(run('check', *remote).stdout)['allowed']
        assert run('approve', fp, *main, '--actor', 'owner', '--approve', *review).returncode == 0
        assert json.loads(run('check', *remote).stdout)['allowed']
        assert run('approve', fp, *main, '--actor', 'owner', '--approve', *review).returncode != 0
        issued = json.loads(run('issue', *main).stdout)
        assert run('confirm', issued['code'], *remote).returncode == 0
        second = json.loads(run('pending', *main).stdout)['claims']
        assert len(second) == 1 and second[0]['claim_id'] != pending[0]['claim_id']
        second_review = ['--review-snapshot', json.dumps(second[0])]
        assert run('deny', fp, *main, '--actor', 'owner', *second_review).returncode == 0
        # Denying one pending claim is not fingerprint-wide revocation: the
        # existing approved enrollment remains until an explicit revoke.
        assert json.loads(run('check', *remote).stdout)['allowed']
        assert run('approve', fp, *main, '--actor', 'owner', '--approve', *second_review).returncode != 0
        short = json.loads(run('issue', *main, '--ttl', '0.01').stdout)
        time.sleep(.03)
        assert run('confirm', short['code'], *remote).returncode != 0
        assert code.encode() not in (tmp_path/'main'/'pairing.sqlite3').read_bytes()
    finally:
        server.terminate()
        server.wait(timeout=10)


def test_claim_and_approval_expiry_and_old_direction_rejected(tmp_path):
    import pytest
    from arvyx_control.machine_pairing import MachineIdentity
    from arvyx_control.machine_pairing_transport import PairingTransport, load_identity
    now = [1000.0]
    transport = PairingTransport(tmp_path/'main', clock=lambda: now[0])
    key = load_identity(tmp_path/'remote')
    public = transport.public(key, 'remote')
    identity = MachineIdentity(**public)
    try:
        with pytest.raises(ValueError, match='invalid purpose'):
            transport.challenge({**public, 'purpose': 'request'})
        ticket = transport.store.issue(actor='owner', ttl=1)
        assert transport.store.claim(ticket.code, identity).allowed
        now[0] += 1
        decision = transport.store.decide(identity.fingerprint, actor='owner', approved=True)
        assert not decision.allowed and decision.reason == 'expired'
        assert not transport.store.check(identity).allowed
        assert not transport.store.claim(ticket.code, identity).allowed
        ticket = transport.store.issue(actor='owner')
        assert transport.store.claim(ticket.code, identity).allowed
        transport.store.revoke(identity, actor='owner')
        assert not transport.store.decide(identity.fingerprint, actor='owner', approved=True).allowed
    finally:
        transport.close()
