#!/usr/bin/env python3
"""Real local two-owner socket acceptance; no SSH/provider or credential access."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

from arvyx_control.cockpit import LocalCockpit
from arvyx_control.cockpit_client import initialize, request
from arvyx_control.control import create_task


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    processes = {}
    logs = []
    with tempfile.TemporaryDirectory(prefix='fleet-acceptance-') as directory:
        root = Path(directory)
        homes = {host: root / host for host in ('host-a', 'host-b')}
        sessions = {}
        for host, home in homes.items():
            initialize(home)
            owner = LocalCockpit(home / 'runtime', home / 'vault', home / 'events.jsonl', host)
            try:
                task = create_task(owner.state, 'Fleet acceptance', owner='demobot').task
                sessions[host] = owner.open(project='demo-agent', task=task.id, name='same-name', actor='operator')['id']
            finally:
                owner.close()
        fleet = root / 'fleet.json'
        fleet.write_text(json.dumps({'host-b': {'root': str(homes['host-b']), 'state': str(homes['host-b'] / 'events.jsonl')}}))
        fleet.chmod(0o600)
        def launch(host):
            home = homes[host]
            command = [sys.executable, '-m', 'arvyx_control.cockpit', '--root', str(home / 'runtime'),
                       '--vault', str(home / 'vault'), '--state', str(home / 'events.jsonl'), '--host', host]
            if host == 'host-a':
                command += ['--fleet-config', str(fleet)]
            command += ['serve']
            log = (args.output / (host + '.log')).open('ab')
            logs.append(log)
            processes[host] = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                try:
                    request(home, 'capabilities')
                    return
                except (OSError, ValueError):
                    if processes[host].poll() is not None:
                        raise RuntimeError('fixture owner failed; inspect local log')
                    time.sleep(.05)
            raise RuntimeError('fixture owner socket readiness timeout')
        def stop(host):
            process = processes.pop(host)
            process.send_signal(signal.SIGINT)
            process.wait(timeout=10)
            assert not (homes[host] / 'runtime/cockpit.sock').exists()
        try:
            launch('host-b')
            launch('host-a')
            model = request(homes['host-a'], 'snapshot', actor='operator')
            assert len(model['sessions']) == 2
            target = 'host-b:' + sessions['host-b']
            selected = request(homes['host-a'], 'select', sid=target, revision=0, actor='operator')
            assert request(homes['host-a'], 'view') == selected
            try:
                request(homes['host-a'], 'select', sid='host-a:' + sessions['host-a'], revision=0, actor='operator')
            except ValueError:
                pass
            else:
                raise AssertionError('stale client overwrote shared selection')
            request(homes['host-a'], 'bind_native', sid=target, tool='fixture', conversation='native-fleet-fixture', actor='operator')
            request(homes['host-a'], 'start_native', sid=target, fixture=True, actor='operator')
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if 'native-fleet-fixture' in request(homes['host-a'], 'read', sid=target, actor='operator')['output']:
                    break
                time.sleep(.02)
            else:
                raise AssertionError('native fixture output not routed through coordinator')
            request(homes['host-a'], 'delegate', sid=target, operator='rowan', goal='fixture', limits='no provider', actor='operator')
            stop('host-b')
            offline = request(homes['host-a'], 'snapshot', actor='operator')
            assert any(session['id'] == target and session['online'] is False for session in offline['sessions'])
            cancellation = request(homes['host-a'], 'take_control_scope', scope='operator', target='rowan', actor='operator')
            assert cancellation['acknowledged'] is False
            launch('host-b')
            assert request(homes['host-a'], 'view')['selected'] == target
            acknowledged = request(homes['host-a'], 'take_control', sid=target, actor='operator')
            assert acknowledged['acknowledged'] is True
            report = {'status': 'PASS', 'two_real_owner_sockets': True, 'shared_revision_conflict': True,
                      'native_fixture_routed': True, 'offline_cached_session': True,
                      'offline_stop_acknowledged': False, 'explicit_reconnect_stop_acknowledged': True,
                      'provider_or_ssh_invoked': False}
            (args.output / 'acceptance.json').write_text(json.dumps(report, indent=2) + '\n')
            print(json.dumps(report))
        finally:
            for host in list(processes):
                stop(host)
            for stream in logs:
                stream.close()


if __name__ == '__main__':
    main()
