"""Malformed retry keys are request errors, never a fake storage outage."""
from arvyx_control.api import handle_api_request
from arvyx_control.vault import init_vault
import pytest

@pytest.mark.parametrize('key',['short',1234567890123456,'has a space here','line\nbreak-000001'])
def test_invalid_retry_key_is_400_before_any_write(tmp_path,key):
    vault=tmp_path/'vault';init_vault(vault);state=tmp_path/'events.jsonl'
    response=handle_api_request('POST','/memory/session',dict(agent='demobot',content='Reviewed metadata.',idempotency_key=key),vault=vault,state=state,bearer_secret='fixture-only',authorization='Bearer fixture-only',allow_unauthenticated_demo=False)
    assert response.status==400,response.body
    assert not state.exists()
