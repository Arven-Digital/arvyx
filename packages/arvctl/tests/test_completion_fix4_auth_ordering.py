"""Disposable, in-process authentication ordering checks; no sockets/providers."""
import copy
import io
import json
from contextlib import ExitStack
from types import SimpleNamespace
from unittest import mock

import pytest

from arvyx_control import api
from arvyx_control.auth import issue_token
from arvyx_control.replica_authority import authority_context


def rpc(method="tools/list", params=None, *, notification=False):
    value = {"jsonrpc": "2.0", "method": method}
    if not notification:
        value["id"] = 19
    if params is not None:
        value["params"] = params
    return value


MUTATION = rpc("tools/call", {"name": "memory.suggest", "arguments": {
    "project": "fixture", "title": "synthetic", "content": "fixture only",
    "author": "fixture", "idempotency_key": "auth-ordering-fixture-key",
}})
MALFORMED_PARAMS = rpc("tools/call", {"name": "memory.suggest", "arguments": []})
CASES = [
    ("POST", "/mcp", {}),
    ("POST", "/mcp", []),
    ("POST", "/mcp", rpc()),
    ("POST", "/mcp", MALFORMED_PARAMS),
    ("POST", "/mcp", MUTATION),
    ("POST", "/mcp", rpc("ping", notification=True)),
    ("POST", "/mcp", rpc("tools/call", {"name": "memory.suggest", "arguments": []}, notification=True)),
    ("POST", "/memory/recall", {"question": "fixture"}),
    ("POST", "/memory/suggest", MUTATION["params"]["arguments"]),
    ("POST", "/tasks", {"title": "fixture", "owner": "fixture", "idempotency_key": "auth-ordering-task-key"}),
    ("GET", "/control/tasks", {}),
]


class Input(io.BytesIO):
    body_reads = 0

    def read(self, *args):
        self.body_reads += 1
        return super().read(*args)


class Wire:
    """Only the stream/timeout methods BaseHTTPRequestHandler needs."""

    def __init__(self, request):
        self.input = Input(request)
        self.output = io.BytesIO()
        self.timeout = None

    def makefile(self, *args):
        return self.input

    def sendall(self, value):
        self.output.write(value)

    def gettimeout(self):
        return self.timeout

    def settimeout(self, value):
        self.timeout = value


@pytest.fixture
def domain(tmp_path):
    vault = tmp_path / "vault"
    vault.mkdir()
    state = tmp_path / "state" / "events.jsonl"
    audit = tmp_path / "audit" / "requests.jsonl"
    registry = vault / "registry" / "agents"
    registry.mkdir(parents=True)
    (registry / "reader.json").write_text(json.dumps({"scopes": ["memory.read"]}))
    with authority_context(vault, state):
        token = issue_token(vault, "reader", scopes=["memory.read"]).token
        yield SimpleNamespace(root=tmp_path, vault=vault, state=state, audit=audit, token=token)


def snapshot(root):
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def invoke(domain, boundary, demo, method, path, body, authorization, *, raw=None, secret=None):
    options = dict(vault=domain.vault, state=domain.state, audit_log=domain.audit,
                   allow_unauthenticated_demo=demo, mcp_profile="operator", bearer_secret=secret)
    if boundary != "http":
        target = api.handle_api_request if boundary == "direct" else api._handle_api_request
        return target(method=method, path=path, body=copy.deepcopy(body),
                      authorization=authorization, **options)
    data = json.dumps(body).encode() if raw is None else raw
    header = "" if authorization is None else "Authorization: " + authorization + "\r\n"
    request = (f"{method} {path} HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n"
               f"Content-Length: {len(data)}\r\n{header}\r\n").encode() + data
    wire = Wire(request)
    api.make_handler(**options)(wire, ("127.0.0.1", 12345), SimpleNamespace())
    head, payload = wire.output.getvalue().split(b"\r\n\r\n", 1)
    status = int(head.split(b" ")[1])
    if not payload:return api.ApiResponse(status,''),wire.input.body_reads
    parsed = json.loads(payload)
    # Dictionary API bodies use the HTTP status/body wrapper; MCP strings do not.
    response = api.ApiResponse(status, parsed["body"] if "status" in parsed else parsed)
    return response, wire.input.body_reads


@pytest.mark.parametrize("boundary", ["direct", "core", "http"])
@pytest.mark.parametrize("demo", [False, True])
@pytest.mark.parametrize("method,path,body", CASES)
def test_explicit_bad_credentials_precede_protocol_and_persistence(domain, boundary, demo, method, path, body):
    before = snapshot(domain.root)
    with ExitStack() as stack:
        watched = [stack.enter_context(mock.patch.object(api, name, wraps=getattr(api, name)))
                   for name in ("claim_mutation", "append_audit", "append_audit_once", "handle_request",
                                "suggest_memory", "create_task", "recall")]
        for credential in ("Bearer cloud-token", "Bearer invalid-core-token", "Basic invalid", ""):
            result = invoke(domain, boundary, demo, method, path, body, credential)
            response, reads = result if boundary == "http" else (result, None)
            assert response.status == 401
            assert response.body == {"ok": False, "error": "unauthorized"}
            if method == "POST" and boundary == "http":
                assert reads == 0
        assert all(w.call_count == 0 for w in watched)
    assert snapshot(domain.root) == before


@pytest.mark.parametrize("demo", [False, True])
def test_http_bad_credentials_precede_json_decode(domain, demo):
    before = snapshot(domain.root)
    response, reads = invoke(domain, "http", demo, "POST", "/mcp", {}, "Bearer cloud-token", raw=b"{")
    assert response.status == 401
    assert reads == 0
    assert snapshot(domain.root) == before


@pytest.mark.parametrize("boundary", ["direct", "http"])
@pytest.mark.parametrize("credential", ["scoped", "operator", "anonymous-demo"])
@pytest.mark.parametrize("body,status,code", [
    ({}, 400, -32600),
    ([], 400, -32600),
    (MALFORMED_PARAMS, 400, -32602),
    (rpc("tools/call", {"name": "memory.suggest", "arguments": []}, notification=True), 202, None),
    (rpc("ping", notification=True), 202, None),
])
def test_admitted_mcp_keeps_validation_and_notification_semantics(domain, boundary, credential, body, status, code):
    authorization = {"scoped": "Bearer " + domain.token, "operator": "Bearer fixture-operator",
                     "anonymous-demo": None}[credential]
    with mock.patch.object(api, "claim_mutation", wraps=api.claim_mutation) as claim, \
         mock.patch.object(api, "suggest_memory", wraps=api.suggest_memory) as effect:
        result = invoke(domain, boundary, credential == "anonymous-demo", "POST", "/mcp", body,
                        authorization, secret="fixture-operator" if credential == "operator" else None)
        response = result[0] if boundary == "http" else result
        assert response.status == status
        payload = json.loads(response.body) if isinstance(response.body, str) and response.body else response.body
        if code is not None:
            assert payload["error"]["code"] == code
        else:
            assert payload == ''
        claim.assert_not_called()
        effect.assert_not_called()


@pytest.mark.parametrize("boundary", ["direct", "http"])
@pytest.mark.parametrize("demo", [False, True])
def test_scoped_identity_never_inherits_demo_scopes(domain, boundary, demo):
    headers = "Bearer " + domain.token
    for method, path, body, expected in [
        ("POST", "/memory/recall", {"question": "fixture"}, 200),
        ("GET", "/tasks", {}, 403),
        ("POST", "/mcp", rpc(), 200),
        ("POST", "/mcp", rpc("tools/call", {"name": "control.task_list", "arguments": {}}), 200),
    ]:
        result = invoke(domain, boundary, demo, method, path, body, headers)
        response = result[0] if boundary == "http" else result
        assert response.status == expected
        if path == "/mcp":
            payload = json.loads(response.body) if isinstance(response.body, str) else response.body
            if body["method"] == "tools/list":
                assert all(t["name"].startswith("memory.") for t in payload["result"]["tools"])
            else:
                assert "error" in payload


@pytest.mark.parametrize("boundary", ["direct", "http"])
def test_anonymous_demo_still_admits_core_read_and_write(domain, boundary):
    for method, path, body, status in [
        ("POST", "/memory/recall", {"question": "fixture"}, 200),
        ("GET", "/tasks", {}, 200),
        ("POST", "/tasks", {"title": "demo fixture", "owner": "fixture",
                             "idempotency_key": "anonymous-demo-task-key"}, 201),
    ]:
        result = invoke(domain, boundary, True, method, path, body, None)
        response = result[0] if boundary == "http" else result
        assert response.status == status
    assert domain.state.is_file()
