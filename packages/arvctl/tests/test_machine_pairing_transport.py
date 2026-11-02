import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.request

import pytest

from arvyx_control.machine_pairing import MachineIdentity
from arvyx_control.machine_pairing_transport import PairingTransport, load_identity


def proof(identity, challenge):
    return base64.b64encode(identity.sign(base64.b64decode(challenge['message']))).decode()


def test_storage_identity_failed_stage_does_not_poison_final_key(tmp_path, monkeypatch):
    # NOT_EXECUTED: source-only regression for the publication boundary.
    from arvyx_control import machine_pairing_transport as transport
    directory = tmp_path / 'identity'
    with monkeypatch.context() as fault:
        fault.setattr(transport.os, 'fsync', lambda _: (_ for _ in ()).throw(OSError('synthetic barrier')))
        with pytest.raises(OSError):
            load_identity(directory)
    assert not (directory / 'identity.key').exists()
    load_identity(directory)
    assert (directory / 'identity.key').stat().st_size == 32


def test_storage_identity_poisoned_legacy_file_requires_explicit_recovery(tmp_path):
    directory = tmp_path / 'identity'
    directory.mkdir(mode=0o700)
    path = directory / 'identity.key'
    path.write_bytes(b'partial')
    path.chmod(0o600)
    with pytest.raises(ValueError, match='explicit identity recovery'):
        load_identity(directory)
    assert path.read_bytes() == b'partial'


def test_proof_approval_replay_and_persistence(tmp_path):
    key = load_identity(tmp_path / 'remote')
    transport = PairingTransport(tmp_path / 'main')
    public = transport.public(key, 'remote')
    challenge = transport.challenge({**public, 'purpose': 'confirm'})
    with pytest.raises(ValueError):
        transport.prove({'challenge': challenge['challenge'], 'signature': base64.b64encode(b'x'*64).decode()})
    with pytest.raises(ValueError):
        transport.prove({'challenge': challenge['challenge'], 'signature': proof(key, challenge)})
    ticket = transport.store.issue(actor='operator')
    challenge = transport.challenge({**public, 'purpose': 'confirm', 'code': ticket.code})
    claim = transport.prove({'challenge': challenge['challenge'], 'signature': proof(key, challenge), 'code': ticket.code})
    assert claim['status'] == 'pending_main_approval'
    assert not transport.store.decide(claim['fingerprint'], actor='operator').allowed
    assert transport.store.decide(claim['fingerprint'], actor='operator', approved=True).allowed
    transport.close()
    transport = PairingTransport(tmp_path / 'main')
    key = load_identity(tmp_path / 'remote')
    challenge = transport.challenge({**public, 'purpose': 'check'})
    assert transport.prove({'challenge': challenge['challenge'], 'signature': proof(key, challenge)})['allowed']
    transport.store.revoke(MachineIdentity(**public), actor='operator')
    challenge = transport.challenge({**public, 'purpose': 'check'})
    assert not transport.prove({'challenge': challenge['challenge'], 'signature': proof(key, challenge)})['allowed']
    transport.close()


def test_expiry_and_persistent_rate(tmp_path):
    now = [1000.0]
    transport = PairingTransport(tmp_path / 'main', clock=lambda: now[0], limit=2)
    key = load_identity(tmp_path / 'remote')
    data = {**transport.public(key, 'remote'), 'purpose': 'confirm'}
    challenge = transport.challenge(data)
    now[0] += 31
    with pytest.raises(ValueError, match='expired'):
        transport.prove({'challenge': challenge['challenge'], 'signature': proof(key, challenge)})
    transport.challenge(data)
    transport.close()
    transport = PairingTransport(tmp_path / 'main', clock=lambda: now[0], limit=2)
    with pytest.raises(ValueError, match='rate_limited'):
        transport.challenge(data)
    transport.close()


def test_two_process_http_lifecycle(tmp_path):
    env = dict(os.environ)
    module = [sys.executable, '-m', 'arvyx_control.machine_pairing_cli']
    server = subprocess.Popen(module + ['serve', '--state-dir', str(tmp_path/'main'), '--port', '0'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    assert server.stdout is not None
    try:
        ready = json.loads(server.stdout.readline())
        url = ready['url']
        def run(*args):
            return subprocess.run(module + list(args), env=env, capture_output=True, text=True, timeout=10)
        args = ['--state-dir', str(tmp_path/'remote'), '--url', url, '--name', 'separate-machine']
        issued = run('issue', '--state-dir', str(tmp_path/'main'))
        assert issued.returncode == 0, issued.stderr
        ticket = json.loads(issued.stdout)
        claim = run('confirm', ticket['code'], *args)
        assert claim.returncode == 0, claim.stderr
        fingerprint = json.loads(claim.stdout)['fingerprint']
        denied = run('check', *args)
        assert json.loads(denied.stdout)['allowed'] is False
        pending = json.loads(run('pending', '--state-dir', str(tmp_path/'main')).stdout)['claims']
        assert len(pending) == 1 and pending[0]['fingerprint'] == fingerprint
        approval = run('approve', fingerprint, '--state-dir', str(tmp_path/'main'), '--actor', 'operator', '--approve',
                       '--review-snapshot', json.dumps(pending[0]))
        assert approval.returncode == 0, approval.stderr
        assert json.loads(run('check', *args).stdout)['allowed'] is True
        assert run('confirm', ticket['code'], *args).returncode != 0
    finally:
        server.terminate()
        server.wait(timeout=10)
