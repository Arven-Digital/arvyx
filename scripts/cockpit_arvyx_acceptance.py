"""Actual Arvyx released frontend over an isolated AMC owner; no providers."""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import select
import shlex
import struct
import subprocess
import sys
import termios
import time

from arvyx_control.cockpit_client import initialize, request
from arvyx_control.cockpit_arvyx import frontend_environment, launch_plan

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'receipts/frontend'
STATE = ROOT / 'run7'
BINARY = OUT / 'herdr-source/target/release/herdr'
EXPECTED = 'd35b3e1a5952ad1b216341411270ab713ef8074cde3034f020aaaa72e8ebecd9'


def wait(check, seconds=10):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if check():
            return
        time.sleep(.05)
    raise AssertionError('deadline expired')


def main():
    assert hashlib.sha256(BINARY.read_bytes()).hexdigest() == EXPECTED
    OUT.mkdir(parents=True, exist_ok=True)
    STATE.mkdir(mode=0o700, exist_ok=False)
    amc = STATE / 'a'
    home = STATE / 'h'
    home.mkdir(mode=0o700)
    initialize(amc)
    env = frontend_environment(home)
    env['PYTHONPATH'] = str(ROOT / 'packages/arvctl/src')
    owner_log = (OUT / 'owner.log').open('wb')
    owner = subprocess.Popen([sys.executable, '-m', 'arvyx_control.cockpit_client', '--home', str(amc), 'serve', '--execution-policy', os.environ['AMC_EXECUTION_POLICY']], env=env, stdout=owner_log, stderr=owner_log)
    arvyx = None
    client = None
    master = None
    raw = bytearray()
    actions = []

    def cli(*args):
        output = subprocess.check_output([str(BINARY), '--session', 'f', *args], env=env, timeout=10)
        with (OUT / 'arvyx-cli.jsonl').open('a') as log:
            log.write(json.dumps({'args': args, 'output': output.decode()}) + '\n')
        return json.loads(output) if output.strip().startswith(b'{') else output.decode()

    def drain(seconds=.4):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if select.select([master], [], [], .05)[0]:
                try:
                    raw.extend(os.read(master, 262144))
                except OSError:
                    return

    try:
        wait(lambda: (amc / 'runtime/cockpit.sock').exists())
        sessions = []
        for name in ['build', 'review']:
            result = subprocess.check_output([sys.executable, '-m', 'arvyx_control.cockpit_client', '--home', str(amc), 'new', name, '--title', 'Synthetic frontend ' + name, '--environment', 'host'], env=env, text=True)
            sessions.append(json.loads(result))
        config = home / '.config/herdr/config.toml'
        config.parent.mkdir(parents=True)
        config.write_text('onboarding = false\n[update]\nversion_check = false\nmanifest_check = false\n[terminal]\nshell_mode = "non_login"\n')
        arvyx_log = (OUT / 'arvyx.log').open('wb')
        arvyx = subprocess.Popen([str(BINARY), '--session', 'f', 'server'], env=env, stdout=arvyx_log, stderr=arvyx_log)
        wait(lambda: (home / '.config/herdr/sessions/f/herdr.sock').exists())
        plan = launch_plan(request(amc, 'list'), 'laptop-a')
        bindings = []
        workspace = None
        for item in plan:
            if workspace is None:
                result = cli('workspace', 'create', '--cwd', str(ROOT), '--label', 'AMC local fixture', '--no-focus')['result']
                workspace = result['workspace']['workspace_id']
                pane = result['root_pane']['pane_id']
            else:
                result = cli('tab', 'create', '--workspace', workspace, '--cwd', str(ROOT), '--label', item['name'], '--no-focus')['result']
                pane = result['root_pane']['pane_id']
            command = shlex.join([sys.executable, '-m', 'arvyx_control.cockpit_arvyx', '--home', str(amc), '--sid', item['sid']])
            cli('pane', 'run', pane, command)
            bindings.append(item | {'pane': pane})
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 34, 160, 0, 0))
        client = subprocess.Popen([str(BINARY), 'session', 'attach', 'f'], stdin=slave, stdout=slave, stderr=slave, env=env, start_new_session=True)
        os.close(slave)
        drain(2)
        # Real native text input through Arvyx -> existing lease transport -> AMC PTY.
        os.write(master, b'printf "ARVYX_AMC_REAL_INPUT\\n"\r')
        drain(1)
        outputs = [request(amc, 'read', sid=item['sid'], actor='operator')['output'] for item in bindings]
        assert any('ARVYX_AMC_REAL_INPUT' in output for output in outputs), outputs
        actions.append('native input reached AMC owner PTY')
        (OUT / 'arvyx-amc-160x34.raw').write_bytes(raw)
        before = cli('api', 'snapshot')['result']['snapshot']
        (OUT / 'before-mouse.json').write_text(json.dumps(before, indent=2))
        # Arvyx handles SGR mouse, tab clicks, wheel scroll and terminal resize.
        os.write(master, b'\x1b[<0;40;1M\x1b[<0;40;1m')
        drain()
        after = cli('api', 'snapshot')['result']['snapshot']
        (OUT / 'after-mouse.json').write_text(json.dumps(after, indent=2))
        assert next(tab['tab_id'] for tab in before['tabs'] if tab['focused']) != next(tab['tab_id'] for tab in after['tabs'] if tab['focused'])
        actions.append('SGR mouse click switched actual focused Arvyx tab')
        os.write(master, b'printf "SECOND_TAB_TARGET\\n"\r')
        drain(1)
        assert 'SECOND_TAB_TARGET' in request(amc, 'read', sid=bindings[1]['sid'], actor='operator')['output']
        assert 'SECOND_TAB_TARGET' not in request(amc, 'read', sid=bindings[0]['sid'], actor='operator')['output']
        actions.append('mouse-selected tab routed native input only to its bound AMC session')
        os.write(master, b'i=0; while [ "$i" -lt 100 ]; do printf "SCROLL_%s\\n" "$i"; i=$((i+1)); done\r')
        drain(1)
        os.write(master, b'\x1b[<64;80;12M\x1b[<64;80;12M\x1b[<64;80;12M')
        drain()
        scrolled = cli('api', 'snapshot')['result']['snapshot']
        assert next(p for p in scrolled['panes'] if p['pane_id'] == bindings[1]['pane'])['scroll']['offset_from_bottom'] > 0
        actions.append('real mouse wheel moved retained Arvyx scrollback')
        os.write(master, b'\x1b[<65;80;12M')
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack('HHHH', 40, 180, 0, 0))
        import signal
        os.kill(client.pid, signal.SIGWINCH)
        drain(1)
        resized = cli('api', 'snapshot')['result']['snapshot']
        assert next(p for p in resized['panes'] if p['pane_id'] == bindings[1]['pane'])['scroll']['viewport_rows'] == 39
        actions.append('SIGWINCH resized actual active terminal viewport to39 rows')
        os.write(master, b'\x02q')
        drain(1)
        client.wait(timeout=5)
        assert client.returncode == 0
        assert all(row['status'] == 'running' for row in request(amc, 'list'))
        actions.append('frontend detach preserved AMC processes')
        (OUT / 'arvyx-acceptance.json').write_text(json.dumps({'binary_sha256': EXPECTED, 'source_commit': '5bd900d88c80d95f5b145397e45bbeea398b8165', 'release': False, 'bindings': bindings, 'actions': actions, 'rows': 34, 'columns': 160, 'complete_product_acceptance': False}, indent=2) + '\n')
    finally:
        (OUT / 'arvyx-amc.raw').write_bytes(raw)
        if client and client.poll() is None:
            client.terminate()
            client.wait(timeout=5)
        if master is not None:
            os.close(master)
        if arvyx:
            subprocess.run([str(BINARY), '--session', 'f', 'server', 'stop'], env=env, timeout=10, capture_output=True)
            arvyx.wait(timeout=10)
            arvyx_log.close()
        owner.terminate()
        owner.wait(timeout=10)
        owner_log.close()


if __name__ == '__main__':
    main()
