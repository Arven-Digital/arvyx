"""Review50 R07/R08/R09 regressions. Authored only; NOT EXECUTED in fix lane."""
import io
import json
from email.message import Message

import pytest

from arvyx_control import api, cli, mcp, operation_journal as journal
from arvyx_control.replica_authority import authority_context


def test_operation_cli_uses_original_namespace(tmp_path, capsys):
    vault = tmp_path / "vault"
    vault.mkdir()
    state = tmp_path / "control.jsonl"
    audit = tmp_path / "audit.jsonl"
    store = journal.journal_path(audit)
    claim = journal.claim_operation(store, vault=vault, state=state,
        principal_scope="mcp:stdio", action="MCP:control.task_create",
        idempotency_key="review50-operation-key", request_hash="fixed-test-digest")
    with authority_context(vault, state):
        journal.set_operation_state(store, claim.operation_id, "intent_durable")
        assert journal.try_begin_dispatch(store, claim.operation_id, "test-dispatch")
    prefix = ["--authority-vault", str(vault), "operation"]
    common = ["--audit-log", str(audit), "--state", str(state), "--json"]
    assert cli.main(prefix + ["list"] + common) == 0
    assert json.loads(capsys.readouterr().out)["operations"][0]["operation_id"] == claim.operation_id
    assert cli.main(prefix + ["list", "--audit-log", str(audit), "--state", str(tmp_path / "foreign")]) == 1
    assert "namespace mismatch" in capsys.readouterr().err
    assert cli.main(prefix + ["list", "--audit-log", str(audit)]) == 1
    assert "namespace mismatch" in capsys.readouterr().err
    assert cli.main(prefix + ["reconcile", claim.operation_id] + common + [
        "--resolution", "reject-unknown", "--confirm-unknown-may-have-dispatched"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == "rejected" and result["redispatched"] is False


@pytest.mark.parametrize("request_id", [0, None, "correlated"])
def test_read_io_failure_does_not_kill_stdio(tmp_path, monkeypatch, request_id):
    def fail(**kwargs):
        raise PermissionError("private path must not enter response")
    monkeypatch.setattr(mcp, "_call_tool", fail)
    body = {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
            "params": {"name": "memory.recall", "arguments": {"question": "q"}}}
    answer = json.loads(mcp.handle_json_line(json.dumps(body), tmp_path))
    assert answer["id"] == request_id and answer["error"]["code"] == -32000
    assert "private path" not in json.dumps(answer)
    body.pop("id")
    assert mcp.handle_json_line(json.dumps(body), tmp_path) is None
    assert json.loads(mcp.handle_json_line('{"jsonrpc":"2.0","id":2,"method":"ping"}', tmp_path))["result"] == {}


def test_pre_admission_io_failure_is_contained(tmp_path, monkeypatch):
    from arvyx_control import replica_authority
    def fail(vault):
        raise OSError("authority storage unavailable")
    monkeypatch.setattr(replica_authority, "assert_mutation_authority", fail)
    body = {"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {
        "name": "memory.session_set", "arguments": {"agent": "test", "content": "body",
        "idempotency_key": "review50-session-key"}}}
    result = mcp.handle_request(body, tmp_path, allowed_tools={"memory.session_set"})
    assert result["id"] == 8 and "error" in result
    assert "nothing retried" in result["error"]["message"]


def handler_without_network(tmp_path, monkeypatch):
    from arvyx_control import secret_delivery
    monkeypatch.setattr(secret_delivery, "dispatch", lambda *args: False)
    handler_type = api.make_handler(tmp_path / "vault", tmp_path / "control.jsonl")
    handler = object.__new__(handler_type)
    handler.path = "/mcp"
    handler.command = "POST"
    handler.headers = Message()
    handler.close_connection = False
    replies = []
    handler._write = replies.append
    handler._preauthorize = lambda method: True
    return handler, replies


@pytest.mark.parametrize("raw", [b'{', b'\xff', b'{"id":1,"id":2}', b'[' * 2000])
def test_http_parser_failures_are_raw_jsonrpc(tmp_path, monkeypatch, raw):
    handler, replies = handler_without_network(tmp_path, monkeypatch)
    class Connection:
        def gettimeout(self): return None
        def settimeout(self, value): pass
    handler.connection = Connection()
    handler.rfile = io.BytesIO(raw)
    handler.headers["Content-Length"] = str(len(raw))
    handler.do_POST()
    response = replies[0]
    assert isinstance(response.body, str)  # _write must not add ApiResponse status/body wrapper.
    wire = json.loads(response.body)
    assert wire["jsonrpc"] == "2.0" and wire["id"] is None
    assert wire["error"]["code"] == -32700


@pytest.mark.parametrize("request_id", [0, None, "request-50"])
def test_http_escaped_exception_correlation_and_notification_silence(tmp_path, monkeypatch, request_id):
    handler, replies = handler_without_network(tmp_path, monkeypatch)
    calls = []
    def fail(**kwargs):
        calls.append(kwargs)
        raise RuntimeError("private exception detail")
    monkeypatch.setattr(api, "handle_api_request", fail)
    body = {"jsonrpc": "2.0", "id": request_id, "method": "ping"}
    handler._handle(body)
    wire = json.loads(replies[-1].body)
    assert wire["id"] == request_id and wire["error"]["code"] == -32603
    assert "private exception detail" not in replies[-1].body
    assert "nothing retried" in wire["error"]["message"]
    body.pop("id")
    handler._handle(body)
    assert replies[-1].status == 202 and replies[-1].body == ""
    assert len(calls) == 2  # Exactly one attempt per request; never replay.


def test_outer_error_does_not_misclassify_invalid_envelope_as_notification():
    response = api._mcp_wire_failure({}, api.ApiResponse(500, {"error": "internal error"}))
    assert json.loads(response.body)["error"]["code"] == -32600
    invalid_id = api._mcp_wire_failure({"jsonrpc": "2.0", "method": "ping", "id": True},
                                     api.ApiResponse(500, {"error": "internal error"}))
    assert json.loads(invalid_id.body)["id"] is None
