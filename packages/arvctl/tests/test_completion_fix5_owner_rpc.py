"""Private storage facade and actual handler; only synthetic disposable captures."""
import json
import os
from pathlib import Path
import shutil
import socket
import threading
from unittest.mock import patch
import pytest
from test_completion_fix5_D import owner,capture_row,acknowledge
from arvyx_control import cockpit,cockpit_client,capture_offload
from retention_fixture_helpers import retention_receipt

pytestmark = pytest.mark.skipif(not hasattr(socket, 'AF_UNIX'), reason='raw Unix-socket owner transport; Windows uses the loopback endpoint (test_owner_endpoint)')


def pure_request(owner,body):
    responses=[]
    with patch.object(cockpit_client,'receive_frame',return_value=json.dumps(body).encode()),patch.object(cockpit_client,'send_frame',side_effect=lambda client,data,*args:responses.append(json.loads(data))):
        cockpit.handle_connection(object(),owner,object())
    return responses[0]


def test_exact_confirmed_offload_facade_routes_to_local_owner(owner,tmp_path):
    first,second=tmp_path/'one',tmp_path/'two';first.mkdir();second.mkdir()
    capture_row(owner,'one\n');one=acknowledge(owner,first)
    capture_row(owner,'two\n');two=acknowledge(owner,first)
    request: dict[str, object]=dict(operation='relocate_capture_offload',directory=str(second),actor='operator',expected_head=two['sha256'],confirmed=True)
    assert pure_request(owner,request)['ok'] is False # Missing chain never rebinds.
    shutil.copyfile(first/(two['sha256']+'.json'),second/(two['sha256']+'.json'))
    assert pure_request(owner,request)['ok'] is False # Partial chain never rebinds.
    shutil.copyfile(first/(one['sha256']+'.json'),second/(one['sha256']+'.json'))
    request['retention_receipt']=retention_receipt(owner,second,two['sha256'],kind='relocate')
    for change in (dict(actor='agent'),dict(confirmed=False),dict(expected_head=one['sha256'])):
        assert pure_request(owner,dict(request,**change))['ok'] is False
    assert pure_request(owner,request)['result']['released']==0
    assert len(capture_offload.read_offload_chain(second,two['sha256']))==2
    with pytest.raises(ValueError):owner.prepare_capture_offload(first,actor='operator')


def test_offload_facade_explicit_copy_preserves_bound_history(owner,tmp_path):
    first,second=tmp_path/'one',tmp_path/'two';first.mkdir();second.mkdir()
    capture_row(owner,'one\n');one=acknowledge(owner,first)
    # Independent synthetic retained version exists while target cache is empty.
    request: dict[str, object]=dict(operation='relocate_capture_offload',directory=str(second),actor='operator',expected_head=one['sha256'],confirmed=True,copy_from_bound=True)
    request['retention_receipt']=retention_receipt(owner,second,one['sha256'],kind='relocate',retained_source=first)
    assert not list(second.iterdir())
    result=pure_request(owner,request)
    assert result['ok'],result
    assert (first/(one['sha256']+'.json')).read_bytes()==(second/(one['sha256']+'.json')).read_bytes()


@pytest.mark.skipif(os.environ.get('AMC_FIX5_OWNER_HOST_UNIX')!='1',reason='parent-host disposable Unix sockets only')
def test_real_private_owner_unix_offload_relocation(owner,tmp_path,monkeypatch):
    first,second=tmp_path/'one',tmp_path/'two';first.mkdir();second.mkdir()
    capture_row(owner,'synthetic archive\n');one=acknowledge(owner,first)
    receipt=retention_receipt(owner,second,one['sha256'],kind='relocate',retained_source=first)
    monkeypatch.chdir(owner.root)
    listener=socket.socket(socket.AF_UNIX);listener.bind('cockpit.sock');listener.listen(1);listener.settimeout(6)
    outcome=[]
    def request():
        outcome.append(cockpit_client.request(Path('..'),'relocate_capture_offload',directory=str(second),actor='operator',expected_head=one['sha256'],confirmed=True,copy_from_bound=True,retention_receipt=receipt))
    thread=threading.Thread(target=request);thread.start()
    try:
        client,_=listener.accept()
        with client:cockpit.handle_connection(client,owner,object())
        thread.join(6);assert not thread.is_alive()
        assert outcome[0]['released']==0
        assert len(capture_offload.read_offload_chain(second,one['sha256']))==1
    finally:listener.close();thread.join(6)
