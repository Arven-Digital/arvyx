from arvyx_control.replica_authority import authority_context
"""Candidate 23 findings 6, 10 and 11: offline behavioral regressions."""
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import re

import pytest

from arvyx_control import audit, control, mcp

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("sol23_private_scan", ROOT / "scripts/private_context_scan.py")
assert SPEC is not None and SPEC.loader is not None
scanner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scanner)
EXAMPLE = Path("fixtures/private-denylist.example.txt")
# The reviewed example bytes come from the fixture itself, so this source carries no
# denylisted term: a checkout scanned with the example denylist (the public CI
# fallback) stays clean, and the exemption is bound to exactly those bytes.
EXAMPLE_BYTES = (ROOT / EXAMPLE).read_bytes()
assert EXAMPLE_BYTES.endswith(b"\n") and b"\r" not in EXAMPLE_BYTES and not EXAMPLE_BYTES.startswith(b"\xef\xbb\xbf")
EXAMPLE_FIRST_NAME = EXAMPLE_BYTES.split(b"\n", 1)[0].decode("utf-8")


@pytest.mark.parametrize("engine", [scanner, audit])
@pytest.mark.parametrize("body, expected", [
    (("gh" + "p_" + "A" * 36).encode(), True),
    (("gh" + "p_" + "A" * 36).encode("utf-16"), True),
    (('"gh' + 'p_" +\n"' + "A" * 36 + '"').encode(), True),
    (b"\xff\xfe\xff", True),
    (EXAMPLE_BYTES, False),
    (EXAMPLE_BYTES + b"changed\n", True),
    (EXAMPLE_BYTES.replace(b"\n", b"\r\n"), True),
    (b"\xef\xbb\xbf" + EXAMPLE_BYTES, True),
])
def test_example_only_exempts_exact_reviewed_names(tmp_path, monkeypatch, engine, body, expected):
    target = tmp_path / EXAMPLE
    target.parent.mkdir()
    target.write_bytes(body)
    # Isolated detector configuration, not a substituted production denylist.
    monkeypatch.setattr(audit, "private_name_patterns", lambda *a, **k: [re.compile(re.escape(EXAMPLE_FIRST_NAME))])
    monkeypatch.setattr(audit, "private_name_exempt_paths", lambda *a: set())
    monkeypatch.setattr(audit, "load_secret_scan_allowlist", lambda *a: set())
    hits = engine.scan(tmp_path)[0] if engine is scanner else engine._private_context_check(tmp_path).findings
    assert bool(hits) is expected


def test_approved_expiry_listing_preserves_consumed_history(tmp_path):
    with authority_context(tmp_path, tmp_path / 'events.jsonl'):
        state = tmp_path / "events.jsonl"
        first = control.request_approval(state, "synthetic command", requester="demo", ttl_seconds=60)
        control.approve_request(state, first.approval.id, "operator")
        second = control.request_approval(state, "other synthetic command", requester="demo", ttl_seconds=60)
        control.approve_request(state, second.approval.id, "operator")
        control.consume_approval(state, second.approval.id, "other synthetic command", actor="demo")
        before = state.read_bytes()
        future = datetime.now(timezone.utc) + timedelta(seconds=120)
        assert [a.id for a in control.list_approvals(state, status="expired", now=future).approvals] == [first.approval.id]
        assert [a.id for a in control.list_approvals(state, status="consumed", now=future).approvals] == [second.approval.id]
        assert control.list_approvals(state, status="approved", now=future).approvals == []
        assert state.read_bytes() == before


def test_expired_approved_rest_and_mcp(tmp_path, monkeypatch):
    with authority_context(tmp_path, tmp_path / 'events.jsonl'):
        from arvyx_control import api
        from arvyx_control.auth import Identity
        state = tmp_path / "events.jsonl"
        old = "2000-01-01T00:00:00Z"
        monkeypatch.setattr(control, "_now", lambda: old)
        approval = control.request_approval(state, "synthetic command", requester="demo", ttl_seconds=60)
        # Approval authorization uses the real wall clock: set up a historical event,
        # rather than weakening the expiry check to approve an already expired grant.
        from dataclasses import replace
        event = control._event("approval.approved", approval.approval.id, old,
            replace(approval.approval, status="approved").to_dict())
        control._append_event_unlocked(state, event)
        before = state.read_bytes()
        monkeypatch.setattr(api, "resolve_identity", lambda *a, **k: Identity("demo", frozenset({"control.read"}), "agent"))
        response = api.handle_api_request("GET", "/approvals", None, tmp_path, state, authorization="Bearer synthetic")
        assert response.status == 200
        assert response.body["approvals"][0]["status"] == "expired"
        result = mcp._call_tool({"name": "control.approval_list", "arguments": {"status": "expired"}}, tmp_path, state, {"control.approval_list"})
        assert result["structuredContent"]["approvals"][0]["status"] == "expired"
        with pytest.raises(ValueError, match="expired"):
            control.consume_approval(state, approval.approval.id, "synthetic command", actor="demo")
        assert state.read_bytes() == before


def test_thread_reply_schema_matches_domain_key_maximum(tmp_path):
    with authority_context(tmp_path, tmp_path / 'events.jsonl'):
        tool = mcp._tools({"control.thread_reply"})[0]
        schema = tool["inputSchema"]["properties"]["idempotency_key"]
        assert schema["maxLength"] == 128
        assert control._validate_idempotency_key("x" * schema["maxLength"]) == "x" * 128
        with pytest.raises(ValueError, match="128"):
            control._validate_idempotency_key("x" * (schema["maxLength"] + 1))
        state = tmp_path / "events.jsonl"
        thread = control.post_thread(state, title="Example", body="Example", actor="demo", target="all", thread_type="status").thread
        args = {"thread_id": thread.id, "text": "Example reply", "actor": "demo", "idempotency_key": "x" * 128}
        call = {"name": "control.thread_reply", "arguments": args}
        first = mcp._call_tool(call, tmp_path, state, {"control.thread_reply"})
        assert mcp._call_tool(call, tmp_path, state, {"control.thread_reply"}) == first
        args["idempotency_key"] += "x"
        with pytest.raises(ValueError, match="128"):
            mcp._call_tool(call, tmp_path, state, {"control.thread_reply"})
