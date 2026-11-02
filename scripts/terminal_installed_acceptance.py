"""Exercise the installed AMC CLI against an existing owner, never native startup."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import select
import struct
import subprocess
import termios
import time

from arvyx_control.cockpit_client import request
from arvyx_control.cockpit_arvyx import frontend_environment

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'receipts/terminal-ready'
CLI = OUT / 'venv/bin/amc'
receipt = json.loads((ROOT / 'receipts/live-demo/herdr-native-acceptance.json').read_text())
owner = Path(receipt['owner_home'])
frontend = Path(receipt['frontend_home'])
binary = ROOT / 'receipts/frontend/herdr-source/target/release/herdr'
command = [str(CLI), 'terminal', '--native-owner', str(owner), '--frontend-home', str(frontend), '--arvyx-binary', str(binary)]
env = dict(os.environ)
env.pop('PYTHONPATH', None)
help_result = subprocess.run([str(CLI), '--help'], env=env, text=True, capture_output=True, check=True)
assert '--new-hermes-profile NAME' in help_result.stdout
assert '--authorize-default-resume' in help_result.stdout
(OUT / 'installed-help.txt').write_text(help_result.stdout)
before = request(owner, 'list')
native_before = request(owner, 'native', sid=receipt['native_session'], actor='operator')
binding_before = (frontend / 'bindings.json').read_bytes()
# Hash only: never parse credentials or invoke their native resolver.
auth = Path.home() / '.hermes/auth.json'
auth_before = hashlib.sha256(auth.read_bytes()).hexdigest() if auth.exists() else None
master, slave = pty.openpty()
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 34, 160, 0, 0))
child = subprocess.Popen(command, env=env, stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
os.close(slave)
raw = bytearray()

def drain(seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if select.select([master], [], [], .05)[0]:
            try:
                raw.extend(os.read(master, 262144))
            except OSError:
                break

def wait_for(text):
    end = time.monotonic() + 10
    while text not in raw and time.monotonic() < end:
        drain(.1)
    assert text in raw, 'expected menu prompt not reached: ' + repr(text)

def snapshot():
    return json.loads(subprocess.check_output([str(binary), '--session', 'amc', 'api', 'snapshot'], env=frontend_environment(frontend), timeout=5))['result']['snapshot']

try:
    wait_for(b'Select agent [1 / quit]: ')
    os.write(master, b'1\n')
    wait_for(b'Sessions [recent5 / all / new / quit]: ')
    os.write(master, b'recent5\n')
    wait_for(b'Open number / back: ')
    assert receipt['conversation'].encode() in raw
    os.write(master, b'1\n')
    wait_for(b'Opening exact native conversation.')
    drain(2)
    bindings = json.loads(binding_before)['bindings']
    selected = next(x for x in bindings if x['sid'] == receipt['native_session'])
    pane = next(x for x in snapshot()['panes'] if x['pane_id'] == selected['pane'])
    assert snapshot()['focused_tab_id'] == pane['tab_id']
    # Only the Arvyx detach chord: no prompt text or Enter after attachment.
    os.write(master, b'\x02q')
    drain(1)
    assert child.wait(timeout=5) == 0
    assert b'Detached; existing owner/native sessions preserved.' in raw
    after = request(owner, 'list')
    assert [(x['id'], x['status']) for x in before] == [(x['id'], x['status']) for x in after]
    assert request(owner, 'native', sid=receipt['native_session'], actor='operator') == native_before
    assert (frontend / 'bindings.json').read_bytes() == binding_before
    auth_after = hashlib.sha256(auth.read_bytes()).hexdigest() if auth.exists() else None
    assert auth_before == auth_after
    result = dict(installed_executable=str(CLI), command=command, help_exit=help_result.returncode,
                  actual_pty=True, exact_conversation=receipt['conversation'], actual_arvyx=True,
                  detach_exit=child.returncode, native_binding_preserved=True, frontend_binding_preserved=True,
                  owner_sessions_preserved=True, root_auth_hash_unchanged=True,
                  provider_input_sent=None, fresh_startup_invoked=None, auth_resolver_invoked=None,
                  unmeasured=['Provider input delivery, native startup and auth-resolver invocation were not instrumented; unchanged state/auth bytes do not prove absence.'],
                  raw_bytes=len(raw))
    (OUT / 'installed-pty.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
finally:
    (OUT / 'installed-pty.raw').write_bytes(raw)
    if child.poll() is None:
        child.terminate()
        child.wait(timeout=5)
    os.close(master)
