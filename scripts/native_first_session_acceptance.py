#!/usr/bin/env python3
"""Real disposable PTY/native acceptance; no credentials or provider messages.

Explicit inputs only. This is not CI and does not download/install a binary.
The selected Hermes source/dependency closure must already be provisioned and
trusted. Never point this harness at an existing profile, owner or frontend.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import select
import signal
import sqlite3
import struct
import subprocess
import sys
import termios
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ('root', 'hermes-source', 'hermes-python', 'binary', 'policy', 'receipt'):
        parser.add_argument('--'+field, type=Path, required=True)
    parser.add_argument('--python-sha256', required=True)
    parser.add_argument('--confirm-disposable', action='store_true', required=True)
    parser.add_argument('--strace', type=Path, help='Optional installed strace for no AF_INET/AF_INET6 connect evidence')
    args = parser.parse_args()
    root = args.root.absolute()
    if root.exists() or root.is_symlink():
        parser.error('root must be absent; this harness never adopts existing state')
    from arvyx_control.cockpit_client import request
    from arvyx_control.cockpit_arvyx import frontend_environment
    from arvyx_control.native_artifact_policy import VerifiedNative
    argv = [sys.executable, '-m', 'arvyx_control.onboarding_cli', 'first-session',
            '--first-session-root', str(root), '--hermes-python', str(args.hermes_python),
            '--hermes-source', str(args.hermes_source), '--python-sha256', args.python_sha256,
            '--arvyx-binary', str(args.binary), '--execution-policy', str(args.policy),
            '--execution-mode', 'host']
    trace = args.receipt.with_suffix('.network-trace')
    if args.strace:
        argv = [str(args.strace), '-f', '-e', 'trace=connect,sendto,sendmsg', '-o', str(trace), *argv]
    raw = bytearray()
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(argv[0], argv)
    confirmed = detached = False
    status = None
    observed = None
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', 40, 160, 0, 0))
        deadline = time.monotonic()+60
        while time.monotonic() < deadline:
            if select.select([fd], [], [], .1)[0]:
                try:
                    data = os.read(fd, 262144)
                except OSError:
                    break
                if not data:
                    break
                raw.extend(data)
            if not confirmed and b'to confirm:' in raw:
                os.write(fd, ('NEW '+str(root)+'\r').encode())
                confirmed = True
            if not detached and b'Run setup now?' in raw:
                record = json.loads((root/'first-session.json').read_text())
                assert record['binding_verified'] and record['state'] == 'setup_required'
                proof = record['proof']
                identity = request(root/'owner', 'native', sid=proof['owner_session'], actor='operator')
                assert identity['conversation'] == proof['conversation'] and identity['tool'] == 'hermes'
                live = request(root/'owner', 'list')[0]
                assert live['status'] == 'running'
                owned_pids = json.loads((root/'frontend/processes.json').read_text())
                owned_pids['native_setup'] = live['pid']
                with VerifiedNative(args.binary) as admitted:
                    snapshot = json.loads(admitted.invoke(subprocess.check_output,
                        ['--session', 'amc', 'api', 'snapshot'],
                        env=frontend_environment(root/'frontend'), timeout=5))['result']['snapshot']
                pane = next(p for p in snapshot['panes'] if p['pane_id'] == record['presentation']['pane'])
                assert pane['workspace_id'] == record['presentation']['workspace']
                assert pane['tab_id'] == record['presentation']['tab']
                observed = dict(identity=identity, presentation=record['presentation'])
                # A frontend detach gesture only; never answer setup or send a prompt.
                os.write(fd, b'\x02q')
                detached = True
            child, candidate_status = os.waitpid(pid, os.WNOHANG)
            if child:
                status = candidate_status
                break
        if status is None:
            child, candidate_status = os.waitpid(pid, os.WNOHANG)
            if child:
                status = candidate_status
        if status is None:
            # Only this disposable harness child; never discovered live processes.
            os.kill(pid, signal.SIGINT)
            _, status = os.waitpid(pid, 0)
        assert os.waitstatus_to_exitcode(status) == 0, raw.decode(errors='replace')[-3000:]
        assert confirmed and detached and observed
        record = json.loads((root/'first-session.json').read_text())
        assert record['detached'] and record['attach_exit'] == 0
        assert record['owner_status'] == 'closed' and record['state'] == 'setup_required'
        assert record['cleanup'] == dict(verified=True, unresolved=[],
                                        frontend=dict(verified=True, unresolved=[]))
        with sqlite3.connect((root/'profile/state.db').as_uri()+'?mode=ro', uri=True) as db:
            sessions = db.execute('SELECT id,cwd FROM sessions').fetchall()
            messages = db.execute('SELECT COUNT(*) FROM messages').fetchone()[0]
        assert sessions == [(record['proof']['conversation'], str(root/'workspace'))]
        assert messages == 0
        assert not any((root/'profile'/n).exists() for n in ('.env', 'auth.json', 'config.yaml'))
        with sqlite3.connect((root/'owner/runtime/sessions.sqlite').as_uri()+'?mode=ro', uri=True) as db:
            bindings = db.execute('SELECT conversation FROM native_bindings').fetchall()
            pane_rows = db.execute('SELECT pane,workspace,tab FROM native_frontend_panes').fetchall()
            cleanup = db.execute('SELECT COUNT(*) FROM cleanup_ownership').fetchone()[0]
        assert bindings == [(record['proof']['conversation'],)]
        assert pane_rows == [(record['presentation']['pane'], record['presentation']['workspace'], record['presentation']['tab'])]
        assert cleanup == 0
        for owned in owned_pids.values():
            try:
                os.kill(owned, 0)
            except ProcessLookupError:
                continue
            raise AssertionError('owned disposable process still exists after cleanup')
        assert not (root/'owner/runtime/cockpit.sock').exists()
        assert not (root/'owner/pilot.json').exists()
        assert not (root/'owner/vault/agents/demobot').exists()
        from arvyx_control.machine_enrollment import verify
        verify(root/'owner', 'local')
        network = None
        if args.strace:
            text = trace.read_text()
            assert 'sa_family=AF_INET' not in text
            network = 'No AF_INET/AF_INET6 connect/sendto/sendmsg in traced process tree'
        result = dict(status='PASS', real_pty=True, real_native=True, setup_required=True,
                      authenticated=False, provider_messages=messages, exact_binding=True,
                      attached_and_detached=True, own_cleanup_verified=True,
                      binary_sha256=record['binary_sha256'], python_sha256=record['python_sha256'],
                      network=network, observed=observed, retained_root=str(root),
                      first_session_receipt=record)
        args.receipt.write_text(json.dumps(result, indent=2)+'\n')
        print(json.dumps(result, indent=2))
    finally:
        os.close(fd)
        if status is None:
            try:
                os.kill(pid, signal.SIGINT)
                os.waitpid(pid, 0)
            except ProcessLookupError:
                pass
        # All captured content belongs to this credential-free disposable surface.
        args.receipt.with_suffix('.pty').write_bytes(raw)


if __name__ == '__main__':
    main()
