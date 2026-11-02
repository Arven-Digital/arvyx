"""Actual Arvyx over two local owner sockets; no real remote/provider claim."""
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time
from arvyx_control.cockpit import LocalCockpit
from arvyx_control.cockpit_client import initialize, request
from arvyx_control.cockpit_arvyx import frontend_environment
from arvyx_control.control import create_task

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'receipts/frontend/governed-delta'
OUT.mkdir(parents=True, exist_ok=True)
BINARY = ROOT / 'receipts/frontend/herdr-source/target/release/herdr'
BASE = Path(tempfile.mkdtemp(prefix='fleet-ui-'))
ENV = dict(os.environ, PYTHONPATH=str(ROOT / 'packages/arvctl/src'))
homes = {host: BASE / host for host in ('east', 'west')}
processes, logs, ids = [], [], {}
client = None
master = None
raw = bytearray()
frontend = BASE / 'frontend'
try:
    for host, home in homes.items():
        initialize(home)
        owner = LocalCockpit(home / 'runtime', home / 'vault', home / 'events.jsonl', host)
        try:
            task = create_task(owner.state, 'Explicit two-owner frontend fixture', owner='demobot').task
            ids[host] = owner.open(project='demo-agent', task=task.id, name='same-name', actor='operator')['id']
        finally:
            owner.close()
    config = BASE / 'fleet.json'
    config.write_text(json.dumps({'west': {'root': str(homes['west']), 'state': str(homes['west'] / 'events.jsonl')}}))
    config.chmod(0o600)
    for host in ('west', 'east'):
        home = homes[host]
        argv = [sys.executable, '-m', 'arvyx_control.cockpit', '--root', str(home / 'runtime'), '--vault', str(home / 'vault'), '--state', str(home / 'events.jsonl'), '--host', host]
        if host == 'east':
            argv += ['--fleet-config', str(config)]
        log = (OUT / (host + '-owner.log')).open('wb')
        logs.append(log)
        process = subprocess.Popen(argv + ['serve'], env=ENV, stdout=log, stderr=log)
        processes.append(process)
        deadline = time.monotonic() + 10
        while True:
            try:
                request(home, 'capabilities')
                break
            except (OSError, ValueError):
                assert process.poll() is None and time.monotonic() < deadline
                time.sleep(.05)
    coordinator = homes['east']
    for host in homes:
        sid = host + ':' + ids[host]
        request(coordinator, 'bind_native', sid=sid, tool='fixture', conversation='fleet-ui-' + host, actor='operator')
        request(coordinator, 'start_native', sid=sid, fixture=True, actor='operator')
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 34, 160, 0, 0))
    client = subprocess.Popen([sys.executable, '-m', 'arvyx_control.cockpit_arvyx', '--home', str(coordinator), '--frontend-home', str(frontend), '--binary', str(BINARY)], env=ENV, stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
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
    native = json.loads(subprocess.check_output([str(BINARY), '--session', 'amc', 'api', 'snapshot'], env=frontend_environment(frontend)))['result']['snapshot']
    bindings = json.loads((frontend / 'bindings.json').read_text())
    assert {item['host'] for item in bindings['bindings']} == {'east', 'west'}
    assert len({pane['workspace_id'] for pane in native['panes']}) == 2, 'Same-name projects collapsed across hosts'
    target = 'west:' + ids['west']
    view = request(coordinator, 'view')
    request(coordinator, 'select', sid=target, revision=view['revision'], actor='operator')
    drain(1)
    os.write(master, b'EXACT_WEST_INPUT\r')
    drain(1)
    west = request(coordinator, 'read', sid=target, actor='operator')['output']
    east = request(coordinator, 'read', sid='east:' + ids['east'], actor='operator')['output']
    assert 'REPLY EXACT_WEST_INPUT' in west, 'Input did not reach selected host'
    assert 'EXACT_WEST_INPUT' not in east, 'Input leaked into another host'
    (OUT / 'arvyx-fleet-active.raw').write_bytes(raw)
    os.write(master, b'\x02q')
    drain(1)
    assert client.wait(timeout=5) == 0
    assert all(row['status'] == 'running' for row in request(coordinator, 'list'))
    report = {'status': 'PASS', 'fixture_only': True, 'actual_arvyx': True,
              'two_owner_sockets': True, 'distinct_host_project_rails': True,
              'exact_host_input_routing': True, 'detach_preserved_processes': True,
              'real_remote_machine_or_provider_validation': False, 'preserved_fixture_home': str(BASE)}
    (OUT / 'arvyx-fleet.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
finally:
    (OUT / 'arvyx-fleet-160x34.raw').write_bytes(raw)
    if client and client.poll() is None:
        client.terminate()
        client.wait(timeout=10)
    if master is not None:
        os.close(master)
    if frontend.exists():
        subprocess.run([str(BINARY), '--session', 'amc', 'server', 'stop'], env=frontend_environment(frontend), capture_output=True, timeout=10)
    for process in reversed(processes):
        process.send_signal(signal.SIGINT)
        process.wait(timeout=10)
    for log in logs:
        log.close()
