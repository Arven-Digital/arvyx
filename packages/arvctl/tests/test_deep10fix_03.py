"""Lane 03 regressions using synthetic files and no services or providers."""
import copy
import json
import sqlite3
from contextlib import closing
from unittest import mock

import pytest

from arvyx_control import api, audit_log, forget, mcp, mutation_dispatch


KEY = "test-test-test-03"
TOOLS = ("memory.forget", "memory.restore")
ABSENT = object()


@pytest.fixture
def lane(tmp_path):
    vault = tmp_path / "vault"
    source = vault / "projects/demo-agent/STATUS.md"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"# Synthetic lane 03 memory\nDisposable fixture only.\n")
    return {"vault": vault, "source": source, "state": tmp_path / "events.jsonl",
            "audit": tmp_path / "audit.jsonl"}


def request(tool="control.bus_post", request_id=1):
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
            "params": {"name": tool, "arguments": {
                "message": "synthetic lane 03 message", "actor": "operator",
                "idempotency_key": KEY}}}


def domain_request(lane, tool):
    body = request(tool)
    args = {"actor": "operator", "idempotency_key": KEY}
    if tool == "memory.forget":
        args.update(project="demo-agent", source_path="projects/demo-agent/STATUS.md",
                    reason_category="superseded", batch_id="synthetic-batch")
    else:
        result = forget.soft_forget(
            lane["vault"], "demo-agent", "projects/demo-agent/STATUS.md",
            "superseded", "synthetic-batch", "operator", "synthetic-setup-key-0001")
        args["tombstone_path"] = result.tombstone_path
    body["params"]["arguments"] = args
    return body


def stdio(lane, body):
    line = mcp.handle_json_line(json.dumps(body), vault=lane["vault"], state=lane["state"],
                               allowed_tools=set(mcp.tools_for_profile("operator")),
                               secret_audit_log=lane["audit"])
    return None if line is None else json.loads(line)


def http(lane, body):
    return api.handle_api_request(
        "POST", "/mcp", body, vault=lane["vault"], state=lane["state"],
        bearer_secret="synthetic-fixture-bearer", authorization="Bearer synthetic-fixture-bearer",
        mcp_profile="operator", audit_log=lane["audit"])


def audit_events(lane):
    return [json.loads(line) for line in lane["audit"].read_text().splitlines()]


def operations(lane):
    store = audit_log.journal_path(lane["audit"])
    assert store.is_file(), "common operation journal must exist"
    with closing(sqlite3.connect(store)) as connection, connection:
        return connection.execute("SELECT action, state FROM operations").fetchall()


def effect_files(lane):
    return {str(p.relative_to(lane["vault"])): p.read_bytes()
            for p in lane["vault"].rglob("*")
            if p.is_file() and p != lane["vault"] / ".arvyx/vault.lock"}


def domain_function(tool):
    return "soft_forget" if tool == "memory.forget" else "restore_forgotten"


def test_0301_catalog_has_one_complete_durable_partition():
    governed = set(mcp.TOOL_NAMES) - set(mcp.READ_TOOL_NAMES)
    assert set(mcp.IDEMPOTENCY_REQUIRED_TOOL_NAMES) == governed
    assert not (set(mcp.MUTATING_TOOL_NAMES) & set(mcp.READ_TOOL_NAMES))


@pytest.mark.parametrize("tool", TOOLS)
def test_0301_shared_intent_and_dispatch_fence_precede_real_effect(lane, tool):
    body = domain_request(lane, tool)
    real = getattr(mcp, domain_function(tool))

    def checked_effect(**kwargs):
        assert operations(lane) == [("MCP:" + tool, "dispatching")]
        events = audit_events(lane)
        assert [(e["phase"], e["tool"]) for e in events] == [("intent", tool)]
        return real(**kwargs)

    with mock.patch.object(mcp, domain_function(tool), side_effect=checked_effect) as effect:
        response = stdio(lane, body)
    assert response["result"]["structuredContent"]["status"] == (
        "forgotten" if tool == "memory.forget" else "restored")
    effect.assert_called_once()
    assert operations(lane) == [("MCP:" + tool, "completed")]
    events = audit_events(lane)
    assert [e["phase"] for e in events] == ["intent", "outcome"]
    assert len({e["operation_id"] for e in events}) == 1
    assert events[-1]["decision"] == "allowed"
    assert audit_log.verify_chain(lane["audit"]).ok
    completed = effect_files(lane)
    body["id"] = 2
    with mock.patch.object(mcp, domain_function(tool)) as effect:
        retry = stdio(lane, body)
    assert retry["id"] == 2
    assert retry["error"]["message"] == "operation_completed_no_replay"
    effect.assert_not_called()
    assert effect_files(lane) == completed
    assert len(audit_events(lane)) == 2


@pytest.mark.parametrize("tool", TOOLS)
def test_0301_failed_intent_prevents_effect_and_same_key_can_retry(lane, tool):
    body = domain_request(lane, tool)
    before = effect_files(lane)
    with mock.patch.object(mcp, "append_audit_once", side_effect=OSError("synthetic intent failure")), \
         mock.patch.object(mcp, domain_function(tool), wraps=getattr(mcp, domain_function(tool))) as effect:
        response = stdio(lane, body)
    assert "error" in response
    effect.assert_not_called()
    assert effect_files(lane) == before
    assert operations(lane) == [("MCP:" + tool, "claimed")]
    body["id"] = 2
    assert "result" in stdio(lane, body)
    assert operations(lane) == [("MCP:" + tool, "completed")]
    assert [e["phase"] for e in audit_events(lane)] == ["intent", "outcome"]


@pytest.mark.parametrize("tool", TOOLS)
def test_0301_pending_outcome_retry_completes_audit_without_redispatch(lane, tool):
    body = domain_request(lane, tool)
    append = mcp.append_audit_once

    def fail_outcome(path, event):
        if event["phase"] == "outcome":
            raise OSError("synthetic outcome failure")
        return append(path, event)

    with mock.patch.object(mcp, "append_audit_once", side_effect=fail_outcome), \
         mock.patch.object(mcp, domain_function(tool), wraps=getattr(mcp, domain_function(tool))) as effect:
        response = stdio(lane, body)
    assert "error" in response
    effect.assert_called_once()
    assert operations(lane) == [("MCP:" + tool, "outcome_pending")]
    completed = effect_files(lane)
    body["id"] = 2
    with mock.patch.object(mcp, domain_function(tool)) as effect:
        retry = stdio(lane, body)
    assert retry["error"]["message"] == "operation_completed_no_replay"
    effect.assert_not_called()
    assert effect_files(lane) == completed
    assert operations(lane) == [("MCP:" + tool, "completed")]
    assert [e["phase"] for e in audit_events(lane)] == ["intent", "outcome"]


@pytest.mark.parametrize("tool", TOOLS)
def test_0301_interrupted_dispatch_requires_reconciliation(lane, tool):
    body = domain_request(lane, tool)
    real = getattr(mcp, domain_function(tool))

    def interrupted(**kwargs):
        real(**kwargs)
        raise OSError("synthetic interruption after domain receipt")

    with mock.patch.object(mcp, domain_function(tool), side_effect=interrupted):
        assert "error" in stdio(lane, body)
    completed = effect_files(lane)
    assert operations(lane) == [("MCP:" + tool, "dispatching")]
    with mock.patch.object(mcp, domain_function(tool)) as effect:
        response = stdio(lane, body)
    assert response["error"]["message"] == "operation reconciliation is required"
    effect.assert_not_called()
    assert effect_files(lane) == completed


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize("marker", [".arvyx-replica", ".arvyx/failover.json"])
def test_0301_replica_markers_still_refuse_before_claim(lane, tool, marker):
    body = domain_request(lane, tool)
    path = lane["vault"] / marker
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("synthetic marker")
    before = effect_files(lane)
    with mock.patch.object(mutation_dispatch, "claim_mutation") as claim:
        response = stdio(lane, body)
    assert "replica mutation authority unavailable" in response["error"]["message"]
    claim.assert_not_called()
    assert effect_files(lane) == before


@pytest.mark.parametrize("tool", TOOLS)
def test_0301_transport_key_reaches_domain_without_changing_grammar(lane, tool):
    body = domain_request(lane, tool)
    body["idempotency_key"] = body["params"]["arguments"].pop("idempotency_key")
    assert "result" in stdio(lane, body)
    assert operations(lane) == [("MCP:" + tool, "completed")]


@pytest.mark.parametrize("tool", TOOLS)
def test_0301_domain_key_refusal_precedes_claim(lane, tool):
    body = domain_request(lane, tool)
    body["params"]["arguments"]["idempotency_key"] = "!synthetic-unsafe-key"
    before = effect_files(lane)
    with mock.patch.object(mutation_dispatch, "claim_mutation") as claim:
        response = stdio(lane, body)
    assert "domain grammar" in response["error"]["message"]
    claim.assert_not_called()
    assert effect_files(lane) == before


INVALID_ENVELOPES = [
    ("jsonrpc", ABSENT), ("jsonrpc", "1.0"), ("jsonrpc", 2),
    ("id", {}), ("id", []), ("id", True), ("id", False),
    ("id", float("nan")), ("id", float("inf")),
    ("method", ABSENT), ("method", None), ("method", []),
    ("params", None), ("params", []), ("params", "invalid"), ("params", 0),
]


def malformed(field, value):
    body = request()
    if value is ABSENT:
        body.pop(field)
    else:
        body[field] = value
    return body


@pytest.mark.parametrize("field,value", INVALID_ENVELOPES)
def test_0302_stdio_invalid_envelopes_never_claim_or_dispatch(lane, field, value):
    body = malformed(field, value)
    with mock.patch.object(mutation_dispatch, "claim_mutation") as claim, \
         mock.patch.object(mcp, "_call_tool", return_value={}) as effect:
        response = stdio(lane, body)
    assert response["error"]["code"] == -32600
    assert response["id"] is None if field == "id" else response["id"] == 1
    claim.assert_not_called()
    effect.assert_not_called()
    assert not audit_log.journal_path(lane["audit"]).exists()
    assert stdio(lane, {"jsonrpc": "2.0", "id": 2, "method": "ping"})["result"] == {}


@pytest.mark.parametrize("field,value", INVALID_ENVELOPES)
def test_0302_http_invalid_envelopes_never_claim_or_dispatch(lane, field, value):
    body = malformed(field, value)
    with mock.patch.object(api, "claim_mutation") as claim, \
         mock.patch.object(mcp, "_call_tool", return_value={}) as effect:
        response = http(lane, body)
    claim.assert_not_called()
    effect.assert_not_called()
    assert not lane["state"].exists()
    rpc = json.loads(response.body) if isinstance(response.body, str) else response.body
    assert response.status == 400
    assert rpc["error"]["code"] == -32600
    assert http(lane, {"jsonrpc": "2.0", "id": 2, "method": "ping"}).status == 200


def test_0302_invalid_version_without_id_is_not_a_notification(lane):
    body = request()
    body.pop("id")
    body["jsonrpc"] = "1.0"
    with mock.patch.object(mutation_dispatch, "claim_mutation") as claim:
        response = stdio(lane, body)
    assert response["id"] is None
    assert response["error"]["code"] == -32600
    claim.assert_not_called()


@pytest.mark.parametrize("transport", [stdio, http])
def test_0302_malformed_bus_request_cannot_write_disposable_state(lane, transport):
    body = request()
    body["jsonrpc"] = "1.0"
    transport(lane, body)
    assert not lane["state"].exists()
    assert not audit_log.journal_path(lane["audit"]).exists()


def test_0302_http_preadmission_error_preserves_protocol_response_for_api_owner():
    with pytest.raises(ValueError) as error:
        mutation_dispatch.validate_mutation_input(malformed("id", True), "/mcp")
    assert error.value.response == {
        "jsonrpc": "2.0", "id": None,
        "error": {"code": -32600, "message": "invalid JSON-RPC request"}}


def test_0302_http_invalid_envelope_has_jsonrpc_error_contract(lane):
    response = http(lane, malformed("id", True))
    rpc = json.loads(response.body) if isinstance(response.body, str) else response.body
    assert rpc == {"jsonrpc": "2.0", "id": None,
                   "error": {"code": -32600, "message": "invalid JSON-RPC request"}}


@pytest.mark.parametrize("request_id", [0, None, "request", 1.25])
def test_0302_valid_scalar_ids_and_absent_params_survive(lane, request_id):
    response = stdio(lane, {"jsonrpc": "2.0", "id": request_id, "method": "ping"})
    assert response == {"jsonrpc": "2.0", "id": request_id, "result": {}}


def test_0302_valid_notification_and_following_frame(lane):
    assert stdio(lane, {"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert stdio(lane, {"jsonrpc": "2.0", "id": 0, "method": "ping"})["id"] == 0


def test_0302_valid_mutation_notification_retains_durable_audit(lane):
    body = domain_request(lane, "memory.forget")
    body.pop("id")
    assert stdio(lane, body) is None
    assert not lane["source"].exists()
    assert [e["phase"] for e in audit_events(lane)] == ["intent", "outcome"]


def test_0302_validation_does_not_change_semantic_hash_or_input(lane):
    body = request()
    before = copy.deepcopy(body)
    digest = mutation_dispatch.canonical_mutation_body(body, "/mcp")
    mutation_dispatch.validate_mutation_input(body, "/mcp")
    assert body == before
    body["id"] = 2
    assert mutation_dispatch.canonical_mutation_body(body, "/mcp") == digest
