from types import SimpleNamespace
from test_local_handler_wire import request
from arvyx_control.local_exploration import ExplorationHandler

def test_explore_and_skip_need_no_owner_or_registry(tmp_path):
    server=SimpleNamespace(origin='http://127.0.0.1:12345',frontend_asset=lambda path:b'<html>Arvyx</html>' if path=='/' else None)
    before=set(tmp_path.iterdir())
    status,caps=request(ExplorationHandler,server,'/api/public-onboarding/capabilities',auth=False)
    assert status==200 and caps['can_skip'] and caps['organizer'] is None and not caps['owner_connected']
    assert request(ExplorationHandler,server,'/api/public-onboarding/agents/commit',dict(confirmed=True),auth=False)[0]==409
    assert request(ExplorationHandler,server,'/api/snapshot',auth=False)[0]==409
    assert set(tmp_path.iterdir())==before
