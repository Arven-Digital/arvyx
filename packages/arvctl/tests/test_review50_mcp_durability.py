"""Additional review50 durability regressions; authored, not executed."""
import json

from arvyx_control import cli, mcp, operation_journal as journal
from arvyx_control.replica_authority import authority_context


def test_complete_audit_uses_exact_original_state_without_replay(tmp_path, capsys):
    vault = tmp_path / "vault"
    vault.mkdir()
    state = tmp_path / "control.jsonl"
    audit = tmp_path / "audit.jsonl"
    store = journal.journal_path(audit)
    claim = journal.claim_operation(store, vault=vault, state=state,
        principal_scope="mcp:stdio", action="MCP:memory.session_set",
        idempotency_key="review50-complete-key", request_hash="fixed-digest")
    outcome = {"event_id": claim.operation_id + ":outcome", "operation_id": claim.operation_id,
               "phase": "outcome", "surface": "mcp-stdio", "decision": "allowed"}
    with authority_context(vault, state):
        journal.set_operation_state(store, claim.operation_id, "outcome_pending", safe_outcome=outcome)
    assert cli.main(["--authority-vault", str(vault), "operation", "reconcile", claim.operation_id,
        "--audit-log", str(audit), "--state", str(state), "--resolution", "complete-audit", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == "completed" and result["redispatched"] is False
    with authority_context(vault, state):
        assert journal.operation_record(store, claim.operation_id).state == "completed"


def test_dispatched_io_failure_stays_unknown_and_does_not_replay(tmp_path, monkeypatch):
    vault = tmp_path / "vault"
    vault.mkdir()
    state = tmp_path / "control.jsonl"
    audit = tmp_path / "audit.jsonl"
    calls = []
    def fail(**kwargs):
        calls.append(kwargs)
        raise PermissionError("effect may have happened")
    monkeypatch.setattr(mcp, "_call_tool", fail)
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "memory.session_set", "arguments": {"agent": "test", "content": "body",
        "idempotency_key": "review50-unknown-key"}}}
    options = dict(vault=vault, state=state, secret_audit_log=audit, allowed_tools={"memory.session_set"})
    first = mcp.handle_request(body, **options)
    assert "uncertain" in first["error"]["message"]
    with authority_context(vault, state):
        records = journal.pending_operation_records(journal.journal_path(audit))
        assert len(records) == 1 and records[0].state == "dispatching"
    second = mcp.handle_request(body, **options)
    assert "reconciliation" in second["error"]["message"]
    assert len(calls) == 1
