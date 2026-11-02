"""Additional admission regressions; NOT_EXECUTED in this fix round."""
import json
from pathlib import Path
from unittest import mock

import pytest

from arvyx_control import api, mcp, mutation_dispatch as dispatch


@pytest.mark.parametrize("body", [None, [], True, 0, "request", {},
    {"jsonrpc": "1.0", "method": "tools/call"},
    {"jsonrpc": "2.0", "method": "ping", "id": False},
    {"jsonrpc": "2.0", "method": "ping", "params": []}])
def test_direct_claim_cannot_admit_invalid_envelope(body):
    with mock.patch.object(dispatch, "claim_operation") as claim:
        with pytest.raises(dispatch.InvalidMCPRequest):
            dispatch.claim_mutation(Path("unused.sqlite"), vault=Path("unused-vault"),
                principal_scope="mcp:stdio", action="MCP:control.bus_post",
                idempotency_key="test-test-test-00", body=body, route="/mcp")
    claim.assert_not_called()


@pytest.mark.parametrize("body", [None, [], False, 0, "request"])
def test_http_nonobject_never_classifies_claims_or_audits(tmp_path, body):
    with mock.patch.object(api, "resolve_identity", return_value=None), \
         mock.patch.object(api, "_requires_audit_success") as classify, \
         mock.patch.object(api, "claim_mutation") as claim, \
         mock.patch.object(api, "append_audit") as audit, \
         mock.patch.object(api, "_handle_api_request") as effect:
        response = api.handle_api_request("POST", "/mcp", body,
            tmp_path / "vault", tmp_path / "events")
    rpc = json.loads(response.body)
    assert response.status == 400
    assert rpc["error"]["code"] == -32600
    assert rpc["id"] is None
    classify.assert_not_called()
    claim.assert_not_called()
    audit.assert_not_called()
    effect.assert_not_called()


@pytest.mark.parametrize("request_id", [0, None, "correlation", 1.25])
def test_http_valid_ids_reach_shared_dispatch_without_claim(tmp_path, request_id):
    body = {"jsonrpc": "2.0", "method": "ping", "id": request_id}
    with mock.patch.object(api, "resolve_identity", return_value=None), \
         mock.patch.object(api, "claim_mutation") as claim, \
         mock.patch.object(api, "append_audit"), \
         mock.patch.object(api, "_handle_api_request", return_value=api.ApiResponse(
             200, json.dumps({"jsonrpc": "2.0", "id": request_id, "result": {}}))) as effect:
        response = api.handle_api_request("POST", "/mcp", body,
            tmp_path / "vault", tmp_path / "events")
    effect.assert_called_once()
    claim.assert_not_called()
    assert json.loads(response.body)["id"] == request_id


@pytest.mark.parametrize("tool", ["memory.forget", "memory.restore"])
@pytest.mark.parametrize("key", ["!" + "a" * 15, "a" * 15 + "!", "a b" * 8])
def test_domain_key_sources_all_refuse_before_claim(tool, key):
    body = {"jsonrpc": "2.0", "id": 0, "method": "tools/call",
            "params": {"name": tool, "arguments": {}}}
    for source in ("header", "body", "arguments"):
        candidate = json.loads(json.dumps(body))
        explicit = key if source == "header" else None
        if source == "body":
            candidate["idempotency_key"] = key
        if source == "arguments":
            candidate["params"]["arguments"]["idempotency_key"] = key
        with pytest.raises(ValueError):
            dispatch.resolve_mutation_key(candidate, route="/mcp", explicit=explicit)
