import json,hashlib
import pytest
from test_pass2_external_units import external

def test_shared_memory_exports_use_only_reviewed_governed_selection(external):
    from arvyx_control.external_memory import reviewed_memory_snapshot
    api,store,call,grant,root=external
    vault=api.vault;path=vault/'projects'/'selected'/'MEMORY.md';path.parent.mkdir(parents=True);path.write_text('---\nstatus: active\n---\n# Memory\nApproved shared fact.\n')
    relative=path.relative_to(vault).as_posix();digest=hashlib.sha256(path.read_bytes()).hexdigest()
    snapshot=reviewed_memory_snapshot(vault,{relative:digest})
    api.documents['artifact:result']=snapshot
    assert call('GET',f'/external/grants/{grant}/resources/artifact/result')[0]==403
    status,fresh=call('POST','/external/grants',dict(recipient='cloud',resources=['artifact:result'],operations=['read','lookup','list','search'],provenance='explicit fresh manifest review'),who='issuer-test')
    assert status==201,fresh
    grant=fresh['id']
    status,result=call('GET',f'/external/grants/{grant}/resources/artifact/result');assert status==200,result
    assert result['files'][0]['path']==relative
    raw=path.parent/'raw'/'secret.md';raw.parent.mkdir();raw.write_text('private')
    with pytest.raises(ValueError):reviewed_memory_snapshot(vault,{raw.relative_to(vault).as_posix():hashlib.sha256(raw.read_bytes()).hexdigest()})
    with pytest.raises(ValueError):reviewed_memory_snapshot(vault,{relative:'0'*64})
