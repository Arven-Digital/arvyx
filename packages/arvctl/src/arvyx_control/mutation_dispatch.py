"""Shared mutation command/key boundary; keys are not request content."""
from typing import Any
from pathlib import Path
from .operation_journal import OperationClaim, claim_operation, request_digest


class InvalidMCPRequest(ValueError):
    """Protocol error retained for transport-owned pre-admission responses."""

    def __init__(self, request_id: object = None):
        super().__init__("invalid JSON-RPC request")
        self.response = {
            "jsonrpc": "2.0", "id": request_id,
            "error": {"code": -32600, "message": str(self)},
        }


class InvalidMCPParams(InvalidMCPRequest):
    """A valid envelope with invalid tool parameters; notifications stay silent."""

    def __init__(self, payload: dict[str, Any], message: str = "tools/call params.name must be text"):
        ValueError.__init__(self, message)
        self.response = None if "id" not in payload else {
            "jsonrpc": "2.0", "id": payload.get("id"),
            "error": {"code": -32602, "message": str(self)},
        }


def validate_mcp_tool_name(payload: dict[str, Any]) -> None:
    if payload.get("method") == "tools/call":
        params = payload.get("params")
        if not isinstance(params, dict) or not isinstance(params.get("name"), str):
            raise InvalidMCPParams(payload)
        if "arguments" in params and not isinstance(params["arguments"], dict):
            raise InvalidMCPParams(payload, "tools/call params.arguments must be an object")


def validate_mcp_envelope(payload: object) -> None:
    """Validate this server's named-parameter JSON-RPC request envelope.

    Invalid envelopes are never notifications. Only a valid correlation id
    may be reflected in an error; Python booleans are not JSON-RPC numbers.
    """
    import math

    if not isinstance(payload, dict):
        raise InvalidMCPRequest()
    request_id = payload.get("id")
    valid_id = (
        request_id is None
        or isinstance(request_id, str)
        or type(request_id) is int
        or (type(request_id) is float and math.isfinite(request_id))
    )
    if not valid_id:
        raise InvalidMCPRequest()
    if (payload.get("jsonrpc") != "2.0"
            or not isinstance(payload.get("method"), str)
            or ("params" in payload and not isinstance(payload["params"], dict))):
        raise InvalidMCPRequest(request_id)
    validate_mcp_tool_name(payload)


def resolve_mutation_key(
    body: dict[str, Any], *, route: str, explicit: str | None
) -> str | None:
    if route == "/mcp":
        validate_mcp_tool_name(body)
    candidates = [value for value in (explicit, body.get("idempotency_key")) if value is not None]
    if route == "/mcp":
        params = body.get("params") if isinstance(body.get("params"), dict) else {}
        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        if arguments.get("idempotency_key") is not None:
            candidates.append(arguments["idempotency_key"])
    from .operation_journal import validate_mutation_key
    for value in candidates:
        validate_mutation_key(value)
    validate_domain_key(body, route, candidates[0] if candidates else None)
    normalized = candidates
    if len(set(normalized)) > 1:
        raise ValueError("idempotency key sources do not match")
    return normalized[0] if normalized else None


def canonical_mutation_body(body: dict[str, Any], route: str) -> dict[str, Any]:
    canonical = dict(body)
    canonical.pop("idempotency_key", None)
    if route == "/mcp":
        canonical.pop("id", None)
    if route == "/mcp" and isinstance(canonical.get("params"), dict):
        params = dict(canonical["params"])
        if isinstance(params.get("arguments"), dict):
            arguments = dict(params["arguments"])
            arguments.pop("idempotency_key", None)
            params["arguments"] = arguments
        canonical["params"] = params
    return canonical


def claim_mutation(
    store: Path, *, vault: Path, principal_scope: str, action: str, idempotency_key: str,
    body: dict[str, Any], route: str, legacy_action: str | None = None, state: Path | None = None,
) -> OperationClaim:
    """One principal-bound durable admission contract for HTTP and stdio.

    The caller owns intent/outcome audit and dispatch fencing. Hash the original
    semantic request, not the command enriched with resolved transport metadata.
    """
    # Defense in depth for direct admission callers: malformed MCP requests
    # must never reserve a key even when a transport forgets its early check.
    if route == "/mcp":
        validate_mcp_envelope(body)
    canonical = canonical_mutation_body(body, route)
    legacy = dict(canonical)
    if route == "/mcp" and "id" in body:
        legacy["id"] = body["id"]
    return claim_operation(
        store, vault=vault, state=state, principal_scope=principal_scope, action=action,
        idempotency_key=idempotency_key,
        request_hash=("mcp-semantic-v2:" if route == "/mcp" else "") + request_digest(canonical),
        legacy_request_hash=request_digest(legacy) if route == "/mcp" else None,
        legacy_action=legacy_action,
    )


def mutation_command(body: dict[str, Any], route: str, key: str) -> dict[str, Any]:
    command = dict(body)
    command["idempotency_key"] = key
    if route == "/mcp":
        validate_mcp_envelope(body)
        raw_params = command.get("params")
        params = dict(raw_params) if isinstance(raw_params, dict) else {}
        raw_arguments = params.get("arguments")
        arguments = dict(raw_arguments) if isinstance(raw_arguments, dict) else {}
        arguments["idempotency_key"] = key
        params["arguments"] = arguments
        command["params"] = params
    return command


FORGET_KEY_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{15,255}$"

def validate_domain_key(body: dict[str, Any], route: str, key: str | None) -> None:
    import re
    if route == "/control/transcripts" and body.get("event_id") != key:
        raise ValueError("transcript event ID must match idempotency key")
    if route == "/mcp":
        validate_mcp_tool_name(body)
    params = body.get("params")
    if route == "/mcp" and isinstance(params, dict) and isinstance(params.get("name"), str) and params.get("name") in {"memory.forget", "memory.restore"}:
        if key is not None and not re.fullmatch(FORGET_KEY_PATTERN, key):
            raise ValueError("forget/restore idempotency key violates domain grammar")

def validate_mutation_input(body: dict[str, Any], route: str) -> None:
    """Reject malformed MCP envelopes and heartbeat inputs before admission."""
    if route == "/mcp":
        validate_mcp_envelope(body)
    import re
    if re.fullmatch(r"/executions/[^/]+/heartbeat", route):
        lease = body.get("lease_seconds", 120)
        from .execution import MAX_LEASE_SECONDS
        if type(lease) is not int or not 1 <= lease <= MAX_LEASE_SECONDS:
            raise ValueError(f"lease_seconds must be an integer from 1 to {MAX_LEASE_SECONDS}")
