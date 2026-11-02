"""REV-0535: HTTP MCP admission/durability failures stay on the JSON-RPC wire.

Every request goes through a real loopback ``BoundedThreadingHTTPServer`` and
the production ``ArvyxApiHandler`` (``do_POST`` -> ``handle_api_request`` ->
``_write``). Claim and audit stores are the real SQLite journal and JSONL audit
log; failures are injected only at the storage boundary (a corrupt journal
file, a foreign authority namespace, the audit append primitive, or a
concurrent dispatch owner winning the real journal fence). Synthetic data only.
"""
from __future__ import annotations

import http.client
import json
import sqlite3
import threading
import uuid
from pathlib import Path
from unittest import mock

import pytest

from arvyx_control import api, audit_log
from arvyx_control.operation_journal import journal_path, try_begin_dispatch
from arvyx_control.replica_authority import authority_context
from arvyx_control.vault import init_vault

# Synthetic values generated per run: no credential-shaped literal lives in source.
OPERATOR_BEARER = "synthetic-" + uuid.uuid4().hex
KEY = "rev0535-" + uuid.uuid4().hex
NOTIFY = object()


class Lane:
    def __init__(self, root: Path, *, audit: Path | None = None) -> None:
        self.vault, self.state = root / "vault", root / "events.jsonl"
        self.audit = audit or root / "audit.jsonl"
        with authority_context(self.vault, self.state):
            init_vault(self.vault)
        handler = api.make_handler(self.vault, self.state, bearer_secret=OPERATOR_BEARER,
                                   mcp_profile="operator", audit_log=self.audit)
        self.server = api.BoundedThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def post(self, body: dict) -> tuple[int, bytes]:
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=15)
        try:
            connection.request("POST", "/mcp", body=json.dumps(body).encode(), headers={
                "Authorization": "Bearer " + OPERATOR_BEARER, "Content-Type": "application/json"})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def effects(self) -> list[str]:
        """Durable bus.message effects, i.e. the real side effect of the tool."""
        if not self.state.exists():
            return []
        return [json.loads(line)["payload"]["message"]
                for line in self.state.read_text().splitlines()
                if line.strip() and json.loads(line).get("type") == "bus.message"]

    def audit_events(self) -> list[dict]:
        if not self.audit.exists():
            return []
        return [json.loads(line) for line in self.audit.read_text().splitlines() if line.strip()]


@pytest.fixture
def lane(tmp_path):
    created = Lane(tmp_path / "a")
    yield created
    created.close()


def request(message: str, request_id=1, key: str | None = KEY) -> dict:
    arguments = {"message": message, "actor": "operator"}
    if key is not None:
        arguments["idempotency_key"] = key
    body = {"jsonrpc": "2.0", "method": "tools/call",
            "params": {"name": "control.bus_post", "arguments": arguments}}
    if request_id is not NOTIFY:
        body["id"] = request_id
    return body


def assert_wire_error(status: int, raw: bytes, *, expected_status: int, request_id, message: str) -> dict:
    assert status == expected_status, raw
    wire = json.loads(raw)
    # Raw JSON-RPC, not the ApiResponse.to_json {"status","body"} REST wrapper.
    assert set(wire) == {"jsonrpc", "id", "error"}, wire
    assert wire["jsonrpc"] == "2.0"
    assert type(wire["id"]) is type(request_id) and wire["id"] == request_id
    assert type(wire["error"]["code"]) is int and wire["error"]["code"] < 0
    assert wire["error"]["message"] == message, wire
    return wire


def assert_notification_silent(status: int, raw: bytes) -> None:
    assert (status, raw) == (202, b"")


def outcome_events(lane: Lane) -> list[dict]:
    return [event for event in lane.audit_events() if event.get("phase") == "outcome"]


def fail_audit_phase(phase: str):
    """Fail only the real audit append primitive for one phase."""
    real = audit_log._append_locked

    def append(path, event):
        if event.get("phase") == phase:
            raise OSError("synthetic audit storage failure")
        return real(path, event)
    return mock.patch.object(audit_log, "_append_locked", side_effect=append)


# --- conflicting content under the same key ---------------------------------

@pytest.mark.parametrize("second_id", [2, "request-two", 0, NOTIFY])
def test_conflicting_content_same_key(lane, second_id):
    assert lane.post(request("original", 1))[0] == 200
    status, raw = lane.post(request("changed semantic content", second_id))
    if second_id is NOTIFY:
        assert_notification_silent(status, raw)
    else:
        wire = assert_wire_error(status, raw, expected_status=409, request_id=second_id,
                                 message="idempotency_conflict")
        assert wire["error"]["data"]["operation_id"]
    assert lane.effects() == ["original"]
    assert len(outcome_events(lane)) == 1


# --- missing and invalid keys -------------------------------------------------

@pytest.mark.parametrize("request_id", [4, NOTIFY])
@pytest.mark.parametrize("key,expected_status,message", [
    (None, 428, "idempotency_key_required"),
    ("short", 400, "idempotency key must be 16-256 printable ASCII characters"),
    ("has whitespace in it 0001", 400, "idempotency key must be 16-256 printable ASCII characters"),
])
def test_missing_or_invalid_key(lane, request_id, key, expected_status, message):
    status, raw = lane.post(request("never admitted", request_id, key=key))
    if request_id is NOTIFY:
        assert_notification_silent(status, raw)
    else:
        assert_wire_error(status, raw, expected_status=expected_status, request_id=request_id,
                          message=message)
    assert lane.effects() == []
    assert lane.audit_events() == []


# --- journal namespace refusal ----------------------------------------------

@pytest.mark.parametrize("request_id", [7, NOTIFY])
def test_namespace_refusal(lane, tmp_path, request_id):
    assert lane.post(request("bound to authority a", 1))[0] == 200
    # A second authority sharing the first authority's journal must refuse.
    foreign = Lane(tmp_path / "b", audit=lane.audit)
    try:
        status, raw = foreign.post(request("foreign authority", request_id,
                                           key="rev0535-foreign-key-0001"))
        if request_id is NOTIFY:
            assert_notification_silent(status, raw)
        else:
            wire = assert_wire_error(status, raw, expected_status=503, request_id=request_id,
                                     message="operation_journal_namespace_unavailable")
            assert wire["error"]["data"]["retry_safe"] is False
        assert foreign.effects() == []
    finally:
        foreign.close()
    assert lane.effects() == ["bound to authority a"]


# --- claim-storage failure ----------------------------------------------------

@pytest.mark.parametrize("request_id", [8, NOTIFY])
def test_claim_storage_failure(lane, request_id):
    store = journal_path(lane.audit)
    store.parent.mkdir(parents=True, exist_ok=True)
    store.write_bytes(b"synthetic corrupt journal, not a sqlite database" * 64)
    status, raw = lane.post(request("claim cannot be stored", request_id))
    if request_id is NOTIFY:
        assert_notification_silent(status, raw)
    else:
        assert_wire_error(status, raw, expected_status=503, request_id=request_id,
                          message="operation journal unavailable")
    assert lane.effects() == []


# --- intent audit failure (before dispatch) -----------------------------------

@pytest.mark.parametrize("request_id", [9, NOTIFY])
def test_intent_audit_failure_refuses_before_effect(lane, request_id):
    with fail_audit_phase("intent"):
        status, raw = lane.post(request("intent not durable", request_id))
    if request_id is NOTIFY:
        assert_notification_silent(status, raw)
    else:
        assert_wire_error(status, raw, expected_status=503, request_id=request_id,
                          message="audit log write failed; mutation was not attempted")
    assert lane.effects() == []


# --- in-progress and unreconciled dispatch ------------------------------------

@pytest.mark.parametrize("request_id", [10, NOTIFY])
def test_in_progress_then_reconciliation_required(lane, request_id):
    real = api.try_begin_dispatch

    def concurrent_owner_wins(path, operation_id, owner):
        # Another worker takes the real journal dispatch fence first.
        assert real(path, operation_id, "synthetic-concurrent-owner")
        return real(path, operation_id, owner)

    with mock.patch.object(api, "try_begin_dispatch", side_effect=concurrent_owner_wins):
        status, raw = lane.post(request("raced", request_id))
    if request_id is NOTIFY:
        assert_notification_silent(status, raw)
    else:
        assert_wire_error(status, raw, expected_status=409, request_id=request_id,
                          message="operation_in_progress")
    # The same request is now held by an unfinished dispatch: no replay.
    retry_id = 11 if request_id is not NOTIFY else NOTIFY
    status, raw = lane.post(request("raced", retry_id))
    if retry_id is NOTIFY:
        assert_notification_silent(status, raw)
    else:
        assert_wire_error(status, raw, expected_status=409, request_id=retry_id,
                          message="operation_reconciliation_required")
    assert lane.effects() == []


# --- audit-completion failure after the effect --------------------------------

@pytest.mark.parametrize("request_id", [12, NOTIFY])
def test_audit_completion_failure_never_replays_effect(lane, request_id):
    with fail_audit_phase("outcome"):
        status, raw = lane.post(request("effect once", request_id))
        if request_id is NOTIFY:
            assert_notification_silent(status, raw)
        else:
            assert_wire_error(status, raw, expected_status=503, request_id=request_id,
                              message="audit_completion_pending")
        assert lane.effects() == ["effect once"]
        assert outcome_events(lane) == []
        # Retrying while the audit store still fails: completion stays pending.
        retry = 13 if request_id is not NOTIFY else NOTIFY
        status, raw = lane.post(request("effect once", retry))
        if retry is NOTIFY:
            assert_notification_silent(status, raw)
        else:
            assert_wire_error(status, raw, expected_status=503, request_id=retry,
                              message="audit_completion_pending")
    # Store recovered: the frozen outcome is recorded once; the effect is not replayed.
    final = 14 if request_id is not NOTIFY else NOTIFY
    status, raw = lane.post(request("effect once", final))
    if final is NOTIFY:
        assert_notification_silent(status, raw)
    else:
        assert_wire_error(status, raw, expected_status=409, request_id=final,
                          message="operation_completed_no_replay")
    status, raw = lane.post(request("effect once", 15))
    assert_wire_error(status, raw, expected_status=409, request_id=15,
                      message="operation_completed_no_replay")
    assert lane.effects() == ["effect once"]
    assert len(outcome_events(lane)) == 1


# --- journal transition failure after durable intent --------------------------

@pytest.mark.parametrize("request_id", [16, NOTIFY])
def test_intent_transition_failure_is_uncertain(lane, request_id):
    with mock.patch.object(api, "transition_operation_state",
                           side_effect=sqlite3.OperationalError("synthetic journal failure")):
        status, raw = lane.post(request("transition failed", request_id))
    if request_id is NOTIFY:
        assert_notification_silent(status, raw)
    else:
        wire = assert_wire_error(status, raw, expected_status=503, request_id=request_id,
                                 message="operation_reconciliation_required")
        assert wire["error"]["data"]["retry_safe"] is False
    assert lane.effects() == []


def test_successful_identified_request_is_unchanged(lane):
    status, raw = lane.post(request("plain success", "ok-1"))
    wire = json.loads(raw)
    assert status == 200 and wire["id"] == "ok-1" and "result" in wire and "error" not in wire
    status, raw = lane.post(request("plain notification", NOTIFY, key=KEY + "-notify"))
    assert_notification_silent(status, raw)
    assert lane.effects() == ["plain success", "plain notification"]
