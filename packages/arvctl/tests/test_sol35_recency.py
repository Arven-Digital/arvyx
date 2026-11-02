"""Offline recency boundary regressions through the actual CLI and REST handler."""
import json
import os
import subprocess
import sys

import pytest

from arvyx_control.api import handle_api_request


INVALID = [10**400, "NaN", float("nan"), "Infinity", float("inf"), "-Infinity",
           "1e400", True, False, [], {}, "invalid", " "]


def seed(vault):
    project = vault / "projects" / "sample"
    project.mkdir(parents=True)
    for name in ("A", "B"):
        (project / f"{name}.md").write_text("# Relay\n\nRelay quorum policy is three of five machines.\n")


def call(value, request_id, tool="memory.recall"):
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": {
        "name": tool, "arguments": {"question": "relay quorum policy", "project": "sample",
                                    "recency_half_life_days": value}}}


@pytest.mark.parametrize("value", INVALID)
@pytest.mark.parametrize("tool", ["memory.recall", "memory.context_pack"])
def test_actual_cli_rejects_invalid_recency_and_recovers(tmp_path, value, tool):
    seed(tmp_path)
    messages = [call(value, 1, tool), {"jsonrpc": "2.0", "id": 2, "method": "ping"},
                call(None, 3, tool)]
    proc = subprocess.run([sys.executable, "-m", "arvyx_control.cli", "mcp", "--vault", str(tmp_path),
                           "--state", str(tmp_path / "events")],
                          input="".join(json.dumps(m) + "\n" for m in messages),
                          text=True, capture_output=True, timeout=15, env=os.environ.copy())
    assert proc.returncode == 0, proc.stderr
    responses = [json.loads(line) for line in proc.stdout.splitlines()]
    assert [r["id"] for r in responses] == [1, 2, 3]
    # Existing tool-validation refusals use the server's request-level -32000 contract.
    assert responses[0]["error"]["code"] == -32000
    assert "recency_half_life_days" in responses[0]["error"]["message"]
    assert "result" in responses[1]
    result = responses[2]["result"]
    structured = result.get("structuredContent")
    if structured is None:
        structured = json.loads(result["content"][0]["text"])
    assert len(structured["sources"]) == 2


def rest(vault, value):
    return handle_api_request(method="POST", path="/memory/recall",
        body={"question": "relay quorum policy", "project": "sample", "recency_half_life_days": value},
        vault=vault, state=vault / "events", bearer_secret=None, authorization=None)


@pytest.mark.parametrize("value", INVALID)
def test_rest_rejects_invalid_recency_without_losing_matches(tmp_path, value):
    seed(tmp_path)
    response = rest(tmp_path, value)
    assert response.status == 400
    assert "recency_half_life_days" in str(response.body)
    valid = rest(tmp_path, None)
    assert valid.status == 200
    assert len(valid.body["sources"]) == 2


@pytest.mark.parametrize("value", [None, "", 0, -1, 30, 0.5, "30", "0.5", 1e308])
def test_rest_preserves_valid_recency(tmp_path, value):
    seed(tmp_path)
    response = rest(tmp_path, value)
    assert response.status == 200
    assert len(response.body["sources"]) == 2
