"""Exercise the installed local cockpit with a real PTY, not mocked rendering."""
import json
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
HOME = Path(tempfile.mkdtemp(prefix='acceptance-pilot-', dir=ROOT / 'receipts'))
EXE = ROOT / '.pilot-venv/bin/arvyx-cockpit'
PYTHON = ROOT / '.pilot-venv/bin/python'
HOME.mkdir(mode=0o700, parents=True, exist_ok=True)


def cli(*args):
    return subprocess.check_output([str(EXE), '--home', str(HOME), *args], text=True)


def rpc(operation, **fields):
    code = 'from pathlib import Path; from arvyx_control.cockpit_client import request; import json,sys; print(json.dumps(request(Path(sys.argv[1]),sys.argv[2],**json.loads(sys.argv[3]))))'
    return json.loads(subprocess.check_output([str(PYTHON), '-c', code, str(HOME), operation, json.dumps(fields)], text=True))


def wait(check, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(.03)
    raise AssertionError('acceptance deadline exceeded')


cli('init')
log = (HOME / 'owner.log').open('wb')
server = subprocess.Popen([str(EXE), '--home', str(HOME), 'serve', '--execution-policy', os.environ['AMC_EXECUTION_POLICY']], stdout=log, stderr=log)
pid = None
try:
    wait(lambda: (HOME / 'runtime/cockpit.sock').exists())
    first = json.loads(cli('new', 'first', '--title', 'Verify terminal routing', '--environment', 'host'))
    second = json.loads(cli('new', 'second', '--title', 'Verify separate task workspace', '--environment', 'host'))
    view = rpc('view')
    rpc('select', sid=first['id'], revision=view['revision'], actor='operator')
    private_cwd = HOME / 'private-client'
    private_cwd.mkdir(mode=0o700)
    pid, master = pty.fork()
    if pid == 0:
        os.chdir(private_cwd)
        os.environ['TERM'] = 'xterm-256color'
        os.execv(str(EXE), [str(EXE), '--home', str(HOME), 'ui'])
    import fcntl
    import struct
    import termios
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack('HHHH', 30, 140, 0, 0))
    transcript = bytearray()

    def collect(needle):
        if select.select([master], [], [], .1)[0]:
            try:
                transcript.extend(os.read(master, 65536))
            except OSError as exc:
                if exc.errno != 5:
                    raise
        return needle in transcript

    wait(lambda: collect(b'AMC / LOCAL COCKPIT'))
    old_headers = transcript.count(b'AMC / LOCAL COCKPIT')
    os.write(master, b'p')
    wait(lambda: collect(b'PRIVATE LOCAL SHELL'))
    os.write(master, b'printf private > local-only.txt; exit\n')
    wait(lambda: (private_cwd / 'local-only.txt').exists())
    wait(lambda: collect(b'AMC / LOCAL COCKPIT') and transcript.count(b'AMC / LOCAL COCKPIT') > old_headers)
    assert len(rpc('list')) == 2
    assert not any((Path(item['workspace']) / 'local-only.txt').exists() for item in (first, second))
    os.write(master, b'j')
    wait(lambda: rpc('view')['selected'] == second['id'])
    attach_cursor = len(transcript)
    os.write(master, b'\r')
    wait(lambda: collect(b'$ ') and b'$ ' in transcript[attach_cursor:])
    os.write(master, b"printf 'SECOND_ONLY' > routed.txt; printf '\342\202\254\\n'\n")
    wait(lambda: (Path(second['workspace']) / 'routed.txt').exists())
    assert not (Path(first['workspace']) / 'routed.txt').exists()
    wait(lambda: collect('€'.encode()))
    os.write(master, b'\x1d')
    time.sleep(.3)
    os.write(master, b'q')
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        ended, status = os.waitpid(pid, os.WNOHANG)
        if ended:
            assert os.waitstatus_to_exitcode(status) == 0
            pid = None
            break
        collect(b'not-a-real-marker')
    assert pid is None, 'navigator failed to exit'
    os.close(master)
    assert all(item['status'] == 'running' for item in rpc('list'))
    page = cli('web').strip()
    assert Path(page).is_file()
    (ROOT / 'receipts/terminal.raw').write_bytes(transcript)
    receipt = {'installed_executable': str(EXE), 'sessions': [first['id'], second['id']],
               'private_shell_only_on_client_cwd_not_registered': True,
               'shared_selection': second['id'], 'real_pty_navigation': True,
               'input_routed_only_to_selected_task': True, 'utf8_round_trip': True,
               'detach_preserved_both_processes': True, 'dashboard': page}
    for item in (first, second):
        rpc('end', sid=item['id'], actor='operator')
        assert Path(item['workspace']).exists()
    receipt['end_preserved_workspaces'] = True
    (ROOT / 'receipts/acceptance.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt, indent=2))
finally:
    if 'transcript' in globals():
        (ROOT / 'receipts/terminal-last-attempt.raw').write_bytes(transcript)
    if pid is not None:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
    server.send_signal(signal.SIGINT)
    server.wait(timeout=10)
    log.close()
