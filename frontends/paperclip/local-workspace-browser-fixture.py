# Disposable explicitly synthetic shell-only acceptance; never actual agent evidence.
import importlib.util
import json
from pathlib import Path
import signal
import threading
import time
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('local_contract_tests',ROOT/'packages/arvctl/tests/test_cockpit_local.py')
assert spec is not None and spec.loader is not None
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
fixture=module.HarmlessOwnerConnectionTests('test_actual_socket_native_election_selection_disconnect_and_persistence')
fixture.setUp()
fixture.server.frontend=Path(__file__).resolve().parent/'dist-next-local'
fixture.server._refresh_frontend()
print(json.dumps({'origin':fixture.server.origin,'synthetic':True,'runtime':'/bin/cat only','capability_fixture':'browser-local-test-capability-32bytes'}),flush=True)
stop=threading.Event()
signal.signal(signal.SIGTERM,lambda *_:stop.set())
signal.signal(signal.SIGINT,lambda *_:stop.set())
try:
 while not stop.wait(0.5):
  marker=Path(__file__).resolve().parent/'end-disposable-beta'
  if marker.exists():
   fixture.owner.end(fixture.sessions['beta'],actor='operator')
   marker.unlink()
finally: fixture.doCleanups()
