"""Installed-wheel acceptance with two isolated owners and real curses PTY.

Usage: python scripts/cockpit_terminal_acceptance.py --python /isolated/venv/bin/python --output /private/receipt-dir
No existing pilot, credentials, provider, network endpoint or production service.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import signal
import socket
import struct
import subprocess
import termios
import tempfile
import time


def verify_archive_page(page):
    """Verify the expected deduplicated note and complete page contract."""
    assert len(page['records']) == 1
    record = page['records'][0]
    assert record['event_id'] == 'acceptance-one'
    assert record['source'] == 'operator-note'
    assert record['text'] == 'Synthetic installed PTY acceptance'
    assert page['next_after'] == record['sequence']
    assert page['has_more'] is False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--python', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    # Resolving the executable symlink would escape the installed virtualenv.
    python = str(args.python.absolute())
    environment = {key: value for key, value in os.environ.items() if key not in {'PYTHONPATH', 'PYTHONHOME'}}
    environment['TERM'] = 'xterm-256color'
    owners = []
    child = None
    master = None
    transcript = bytearray()
    # AF_UNIX sockaddr paths are short; keep fixture state in managed scratch.
    state_root = Path(tempfile.mkdtemp(prefix='amct-', dir=os.environ['TMPDIR']))

    def invoke(home, *argv):
        return subprocess.check_output([python, '-m', 'arvyx_control.cockpit_client', '--home', str(home), *argv], env=environment, text=True)

    def rpc(home, operation, **fields):
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(5)
            client.connect(str(home / 'runtime/cockpit.sock'))
            client.sendall(json.dumps(dict(operation=operation, **fields)).encode() + b'\n')
            with client.makefile('rb') as stream:
                result = json.loads(stream.readline(1048576))
        if not result['ok']:
            raise ValueError(result['error'])
        return result['result']

    def wait(check, timeout=8):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if check():
                return
            time.sleep(.02)
        raise AssertionError('acceptance deadline exceeded')

    def collect(needle):
        if select.select([master], [], [], .05)[0]:
            try:
                transcript.extend(os.read(master, 65536))
            except OSError as exc:
                if exc.errno != 5:
                    raise
        return needle in transcript

    try:
        homes = []
        for host in ['fixture-a', 'fixture-b']:
            home = state_root / host
            invoke(home, 'init')
            log = (output / (host + '.log')).open('wb')
            process = subprocess.Popen([python, '-m', 'arvyx_control.cockpit', '--root', str(home / 'runtime'), '--vault', str(home / 'vault'), '--state', str(home / 'events.jsonl'), '--host', host, 'serve', '--execution-policy', os.environ['AMC_EXECUTION_POLICY']], env=environment, stdout=log, stderr=log)
            owners.append((process, log))
            wait(lambda: (home / 'runtime/cockpit.sock').exists())
            homes.append(home)
        home, remote = homes
        first = json.loads(invoke(home, 'new', 'same-name', '--title', 'PTY first', '--environment', 'host'))
        second = json.loads(invoke(home, 'new', 'second', '--title', 'PTY second', '--environment', 'host'))
        remote_session = json.loads(invoke(remote, 'new', 'same-name', '--title', 'Other host same short name', '--environment', 'host'))
        assert first['id'] != remote_session['id']
        assert rpc(home, 'snapshot', actor='operator')['host'] == 'fixture-a'
        # A genuine installed Endpoint refuses the wrong machine before mutation.
        probe = 'from pathlib import Path; from arvyx_control.cockpit_transport import Endpoint; import sys; Endpoint(Path(sys.argv[1]),host="WRONG",state=sys.argv[2]).call("end",sid=sys.argv[3],actor="operator")'
        denied = subprocess.run([python, '-c', probe, str(home), str(home / 'events.jsonl'), first['id']], env=environment, capture_output=True, text=True)
        assert denied.returncode != 0 and 'identity mismatch' in denied.stderr
        assert rpc(home, 'list')[0]['status'] == 'running'
        for item, marker in [(first, 'FIRST_PREVIEW'), (second, 'SECOND_PREVIEW')]:
            lease = rpc(home, 'attach', sid=item['id'], actor='operator')
            rpc(home, 'write', sid=item['id'], text='printf "' + marker + '\\n"\n', attachment=lease['attachment'], actor='operator')
            rpc(home, 'detach', sid=item['id'], attachment=lease['attachment'], actor='operator')
            wait(lambda: marker in rpc(home, 'read', sid=item['id'], actor='operator')['output'])
        rpc(home, 'layout', panels=[first['id'], second['id']], selected=first['id'], revision=0, actor='operator')
        child, master = pty.fork()
        if child == 0:
            os.execve(python, [python, '-m', 'arvyx_control.cockpit_client', '--home', str(home), 'ui'], environment)
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack('HHHH', 34, 160, 0, 0))
        wait(lambda: collect(b'FIRST_PREVIEW'))
        wait(lambda: collect(b'SECOND_PREVIEW'))
        os.write(master, b'j')
        wait(lambda: rpc(home, 'view')['selected'] == second['id'])
        os.write(master, b'x')
        wait(lambda: second['id'] not in rpc(home, 'view')['panels'])
        assert all(row['status'] == 'running' for row in rpc(home, 'list'))
        os.write(master, b't')
        wait(lambda: len(rpc(home, 'view')['panels']) == 2)
        # Force selected second from a second client and observe the same owner.
        view = rpc(home, 'view')
        rpc(home, 'select', sid=second['id'], revision=view['revision'], actor='operator')
        # Let the navigator observe the externally changed revision before Enter.
        time.sleep(.6)
        os.write(master, b'\r')
        wait(lambda: next(row for row in rpc(home, 'snapshot', actor='operator')['sessions'] if row['id'] == second['id'])['human_attached'])
        os.write(master, b'printf routed > routing.txt\n')
        wait(lambda: (Path(second['workspace']) / 'routing.txt').exists())
        assert not (Path(first['workspace']) / 'routing.txt').exists()
        os.write(master, b'\x1d')
        time.sleep(.2)
        os.write(master, b'q')
        wait(lambda: os.waitpid(child, os.WNOHANG)[0] != 0)
        child = None
        assert all(row['status'] == 'running' for row in rpc(home, 'list'))
        draft = json.loads(invoke(home, 'draft', 'stage', first['id'], '--text', 'DRAFT_NOT_AUTO_SENT'))
        assert draft['status'] == 'draft'
        assert 'DRAFT_NOT_AUTO_SENT' not in rpc(home, 'read', sid=first['id'], actor='operator')['output']
        invoke(home, 'archive', first['id'], '--event-id', 'acceptance-one', '--source', 'operator-note', '--text', 'Synthetic installed PTY acceptance')
        invoke(home, 'archive', first['id'], '--event-id', 'acceptance-one', '--source', 'operator-note', '--text', 'Synthetic installed PTY acceptance')
        verify_archive_page(json.loads(invoke(home, 'archive', first['id'])))
        # Shell exits; binding a named fixture native conversation is explicit.
        lease = rpc(home, 'attach', sid=first['id'], actor='operator')
        rpc(home, 'write', sid=first['id'], text='exit\n', attachment=lease['attachment'], actor='operator')
        wait(lambda: rpc(home, 'list')[0]['status'] == 'stopped')
        invoke(home, 'native', 'bind', first['id'], '--tool', 'fixture', '--conversation', 'acceptance-native-123')
        invoke(home, 'native', 'resume', first['id'], '--fixture')
        wait(lambda: 'NATIVE acceptance-native-123' in rpc(home, 'read', sid=first['id'], actor='operator')['output'])
        for current, sessions in [(home, [first, second]), (remote, [remote_session])]:
            for item in sessions:
                rpc(current, 'end', sid=item['id'], actor='operator')
                assert Path(item['workspace']).is_dir()
        receipt = {'status': 'PASS', 'installed_python': python, 'real_curses_pty': True,
                   'fixture_state': str(state_root),
                   'two_owner_hosts': ['fixture-a', 'fixture-b'], 'shared_pane_previews': True,
                   'wrong_host_mutation_rejected': True, 'same_short_name_distinct_hosts': True,
                   'hide_detaches_without_end': True, 'selection_routes_only_selected_task': True,
                   'draft_never_auto_sent': True, 'archive_deduplicated': True,
                   'explicit_native_fixture_conversation': 'acceptance-native-123',
                   'end_preserved_workspaces': True, 'provider_calls': 0,
                   'limitations': ['No actual SSH server or external provider invoked', 'Read-only pane previews, native VT through attach']}
        (output / 'acceptance.json').write_text(json.dumps(receipt, indent=2) + '\n')
        print(json.dumps(receipt, indent=2))
    finally:
        (output / 'terminal.raw').write_bytes(transcript)
        if child:
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)
        if master is not None:
            os.close(master)
        for process, log in reversed(owners):
            process.send_signal(signal.SIGINT)
            process.wait(timeout=10)
            log.close()


if __name__ == '__main__':
    main()
