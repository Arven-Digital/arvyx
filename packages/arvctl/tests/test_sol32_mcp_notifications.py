"""Private core MCP notification regressions; no external runtimes or providers."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from arvyx_control.api import handle_api_request
from arvyx_control.mcp import handle_json_line, handle_request


MESSAGES = [
    {"jsonrpc": "2.0", "method": "ping"},
    {"jsonrpc": "2.0", "id": 7, "method": "notifications/initialized"},
    {"jsonrpc": "2.0", "id": 8, "method": "tools/list"},
]


def test_actual_core_cli_notification_sequence(tmp_path):
    proc = subprocess.run(
        [sys.executable, "-m", "arvyx_control.cli", "mcp", "--vault", str(tmp_path),
         "--state", str(tmp_path / "events")],
        input="".join(json.dumps(p) + "\n" for p in MESSAGES),
        text=True, capture_output=True, timeout=15, env=os.environ.copy(),
    )
    assert proc.returncode == 0, proc.stderr
    responses = [json.loads(line) for line in proc.stdout.splitlines()]
    assert [p["id"] for p in responses] == [7, 8]
    assert responses[0]["error"]["code"] == -32601
    assert "tools" in responses[1]["result"]


@pytest.mark.parametrize("method,params", [
    ("ping", {}), ("tools/list", {}), ("notifications/initialized", {}),
    ("unknown", {}), ("tools/call", {"name": "not-allowlisted"}),
    ("tools/call", {"name": "secret.resolve", "arguments": {}}),
])
def test_notifications_suppress_success_and_error_responses(tmp_path, method, params):
    assert handle_request({"jsonrpc": "2.0", "method": method, "params": params},
                          tmp_path, allowed_tools={"secret.resolve"}) is None


@pytest.mark.parametrize("request_id", [0, 7, "request", None])
def test_id_presence_not_truthiness(tmp_path, request_id):
    result = handle_request({"jsonrpc": "2.0", "id": request_id, "method": "notifications/initialized"}, tmp_path)
    assert result["id"] == request_id
    assert result["error"]["code"] == -32601


@pytest.mark.parametrize("line,code", [("[", -32700), ("[]", -32600), ("null", -32600)])
def test_invalid_frames_still_reply(tmp_path, line, code):
    assert json.loads(handle_json_line(line, tmp_path))["error"]["code"] == code


def test_http_contract(tmp_path):
    responses = [handle_api_request(
        method="POST", path="/mcp", body=payload, vault=tmp_path,
        state=tmp_path / "events", bearer_secret=None, authorization=None,
    ) for payload in MESSAGES]
    assert [r.status for r in responses] == [202, 200, 200]
    assert responses[0].body == ""
    rpc = [json.loads(r.body) if isinstance(r.body, str) else r.body for r in responses[1:]]
    assert [p["id"] for p in rpc] == [7, 8]
    assert rpc[0]["error"]["code"] == -32601


def test_notification_retains_durable_secret_failure_audits(tmp_path):
    audit = tmp_path / "audit.jsonl"
    payload = {"jsonrpc": "2.0", "method": "tools/call", "params": {
        "name": "secret.resolve", "arguments": {
            "ref": "invalid-reference", "idempotency_key": "notification-audit-check",
        },
    }}
    assert handle_request(payload, tmp_path, state=tmp_path / "events",
                          allowed_tools={"secret.resolve"}, secret_audit_log=audit) is None
    rows = [json.loads(line) for line in audit.read_text().splitlines()]
    assert [row["phase"] for row in rows] == ["intent", "outcome"]
    assert rows[-1]["decision"] == "error"


def test_invalid_object_without_method_is_not_silenced(tmp_path):
    result = handle_request({}, tmp_path)
    assert result["id"] is None
    assert "error" in result


def test_actual_cli_oversized_frame_recovery(tmp_path):
    from arvyx_control.stdio_bounds import MAX_STDIO_BYTES
    proc = subprocess.run(
        [sys.executable, "-m", "arvyx_control.cli", "mcp", "--vault", str(tmp_path)],
        input="x" * (MAX_STDIO_BYTES + 1) + "\n" +
              "".join(json.dumps(p) + "\n" for p in MESSAGES),
        text=True, capture_output=True, timeout=15,
    )
    assert proc.returncode == 0, proc.stderr
    responses = [json.loads(line) for line in proc.stdout.splitlines()]
    assert [r["id"] for r in responses] == [None, 7, 8]
    assert responses[0]["error"]["code"] == -32700
