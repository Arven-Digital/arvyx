"""Exercise the actual frontend launcher against preserved synthetic sessions."""
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import struct
import subprocess
import sys
import termios
import time

from arvyx_control.cockpit_client import initialize, request
from arvyx_control.control import create_task
from arvyx_control.cockpit_arvyx import frontend_environment

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'receipts/frontend'
HOME = ROOT / 'run12/a'
FRONTEND = ROOT / 'run12/l'
BINARY = OUT / 'herdr-source/target/release/herdr'
HOME.parent.mkdir(mode=0o700, exist_ok=False)
initialize(HOME)
env = frontend_environment(ROOT / 'run5/h')
env['PYTHONPATH'] = str(ROOT / 'packages/arvctl/src')
log = (OUT / 'launcher-owner.log').open('wb')
owner = subprocess.Popen([sys.executable, '-m', 'arvyx_control.cockpit_client', '--home', str(HOME), 'serve', '--execution-policy', os.environ['AMC_EXECUTION_POLICY']], env=env, stdout=log, stderr=log)
client = None
master = None
raw = bytearray()
try:
    deadline = time.monotonic() + 10
    while True:
        try:
            sessions = request(HOME, 'list')
            break
        except OSError:
            assert time.monotonic() < deadline
            time.sleep(.05)
    for name in ['build', 'review']:
        subprocess.check_output([sys.executable, '-m', 'arvyx_control.cockpit_client', '--home', str(HOME), 'new', name, '--title', 'Synthetic launcher ' + name, '--environment', 'host'], env=env)
    sessions = request(HOME, 'list')
    master, slave = pty.openpty()
    task = create_task(HOME / 'events.jsonl', 'Explicit synthetic native binding', owner='demobot').task
    native = request(HOME, 'open', project='demo-agent', task=task.id, name='fixture-native', actor='operator')
    request(HOME, 'bind_native', sid=native['id'], tool='fixture', conversation='fixture-conversation-exact', actor='operator')
    request(HOME, 'start_native', sid=native['id'], fixture=True, actor='operator')
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 34, 160, 0, 0))
    client = subprocess.Popen([sys.executable, '-m', 'arvyx_control.cockpit_arvyx', '--home', str(HOME), '--frontend-home', str(FRONTEND), '--binary', str(BINARY)], env=env, stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
    os.close(slave)

    def drain(seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if select.select([master], [], [], .05)[0]:
                try:
                    raw.extend(os.read(master, 262144))
                except OSError:
                    break
    drain(2)
    assert client.poll() is None, raw.decode(errors='replace')
    output = subprocess.check_output([str(BINARY), '--session', 'amc', 'api', 'snapshot'], env=frontend_environment(FRONTEND), timeout=5)
    upstream_snapshot = json.loads(output)['result']['snapshot']
    (OUT / 'native-binding-upstream-snapshot.json').write_text(json.dumps(upstream_snapshot, indent=2))
    assert 'fixture-conversation-exact' in output.decode(), 'Exact native binding was not reported to actual Arvyx'
    os.write(master, b'printf "ACTUAL_LAUNCHER_OK\\n"\r')
    drain(1)
    assert any('ACTUAL_LAUNCHER_OK' in request(HOME, 'read', sid=s['id'], actor='operator')['output'] for s in sessions)
    os.write(master, b'\x1b[<0;40;1M\x1b[<0;40;1m')
    deadline = time.monotonic() + 5
    while request(HOME, 'view')['selected'] != sessions[1]['id']:
        assert time.monotonic() < deadline, 'Arvyx mouse focus did not reach AMC shared view'
        drain(.1)
    view = request(HOME, 'view')
    panels = list(dict.fromkeys([*view['panels'], sessions[0]['id']]))
    request(HOME, 'layout', panels=panels, selected=sessions[0]['id'], revision=view['revision'], actor='operator')
    deadline = time.monotonic() + 5
    while True:
        output = subprocess.check_output([str(BINARY), '--session', 'amc', 'api', 'snapshot'], env=frontend_environment(FRONTEND), timeout=5)
        panes = json.loads(output)['result']['snapshot']['panes']
        if next(p['pane_id'] for p in panes if p['focused']) == 'w1:p1':
            break
        assert time.monotonic() < deadline, 'AMC shared selection did not reach Arvyx focus'
        drain(.1)
    os.write(master, b'\x02q')
    drain(1)
    assert client.wait(timeout=5) == 0
    assert all(s['status'] == 'running' for s in request(HOME, 'list'))
    (OUT / 'launcher-acceptance.json').write_text(json.dumps({'launcher': 'actual CLI module', 'native_input_reached_owner': True, 'two_way_shared_focus': True, 'detach_preserved_owner_sessions': True, 'bindings': json.loads((FRONTEND / 'bindings.json').read_text())}, indent=2) + '\n')
finally:
    (OUT / 'launcher-160x34.raw').write_bytes(raw)
    if client and client.poll() is None:
        client.terminate()
        client.wait(timeout=5)
    if master is not None:
        os.close(master)
    subprocess.run([str(BINARY), '--session', 'amc', 'server', 'stop'], env=frontend_environment(FRONTEND), timeout=10, capture_output=True)
    owner.terminate()
    owner.wait(timeout=10)
    log.close()
