from __future__ import annotations

from .diagnostics import REPORTED, TRACE, capture, get_reporter

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
import hashlib
import json
from pathlib import Path
import re
import socket
import sqlite3
import sys
import threading
import time
from typing import Any, Optional
from urllib.parse import parse_qs, urlsplit
import uuid
from .audit_log import append_audit, append_audit_once, default_audit_log, recent_events
from .request_metadata import journal_action, legacy_journal_action, request_metadata, route_metadata
from .operation_journal import (
    JournalNamespaceError,
    journal_path,
    set_operation_state,
    transition_operation_state,
    try_begin_dispatch,
)

from .control import (
    ACTIONABLE_THREAD_TYPES,
    Approval,
    ControlEvent,
    Thread,
    accept_handoff,
    acknowledge_thread,
    approval_effective_status,
    approve_request,
    complete_task,
    complete_handoff,
    complete_thread,
    consume_approval,
    create_handoff,
    create_task,
    list_approvals,
    list_bus_messages,
    list_handoffs,
    list_pending_threads,
    list_tasks,
    list_thread_inbox,
    same_agent_identity,
    post_bus_message,
    post_thread,
    read_all_threads,
    read_events,
    request_approval,
    review_handoff,
)
from .auth import (
    ALL_SCOPES,
    SCOPE_CONTROL_DELIVERY,
    SCOPE_CONTROL_READ,
    SCOPE_CONTROL_WRITE,
    SCOPE_MEMORY_CURATE,
    SCOPE_MEMORY_READ,
    SCOPE_MEMORY_REFINE,
    SCOPE_MEMORY_SUGGEST,
    SCOPE_REPLICA_READ,
    SCOPE_SECRET_RESOLVE,
    SCOPE_SESSION_READ,
    SCOPE_SESSION_WRITE,
    TOKENS_DIR,
    Identity,
    resolve_identity,
    tools_for_scopes,
)
from .brokers import BrokerError, InspectionGuard, list_brokers, parse_ref, resolve_ref
from .digest import build_digest
from .replica import build_manifest, read_state_file, read_vault_file, replica_status
from .mcp import READ_TOOL_NAMES, handle_request, tools_for_profile
from .recall import coerce_int, recall
from .session import get_session, set_session
from .store import manifest_state
from .dispatcher import RouteDocument, load_route_document
from .execution import (
    acknowledge_execution_steer,
    cancel_execution,
    close_execution,
    heartbeat_execution_as_target,
    hold_execution,
    list_execution_events,
    project_executions,
    queue_health,
    replay_execution,
    request_execution_steer,
    resume_execution,
)
from .watchdog import WATCHDOG_TICK_STALE_SECONDS, project_watchdog_tick
from .forget import restore_forgotten, soft_forget
from .decisions import answer_decision
from .outbox import (
    EXECUTION_WAKE_MODE,
    OutboxItem,
    cancel_unroutable,
    project_dispatcher_tick,
    project_materialization_checkpoint,
    project_outbox,
    record_receipt,
    replay,
    resolve_dead_letter,
)
from .writes import (
    PENDING_LANE,
    REFINING_LANE,
    memory_suggestion_batch_schema,
    list_pending,
    list_refining,
    promote_memory,
    refine_memory,
    reject_memory,
    suggest_memory,
    suggest_memory_batch,
)

MAX_BODY_BYTES = 1_048_576
REQUEST_BODY_TIMEOUT_SECONDS = 10
MAX_SERVER_WORKERS = 64
CONTINUATION_STALE_SECONDS = 3_600
# War-room desk presets the dashboard renders (static/index.html DESK_PRESETS).
DASHBOARD_DESKS = ("engineering", "security", "research", "operations")
PUBLIC_PATHS = {"/", "/dashboard", "/health"}
_DENIAL_AUDIT_BUCKETS: dict[tuple[str, int], int] = {}
_DENIAL_AUDIT_LOCK = threading.Lock()

# Scopes available to a request that presents no credentials at all.
# Reads from curated memory are the only unauthenticated surface; every
# mutation requires an identity unless the demo escape hatch is passed.
UNAUTHENTICATED_SCOPES = frozenset({SCOPE_MEMORY_READ})


@dataclass(frozen=True)
class ApiResponse:
    status: int
    body: dict[str, Any] | str
    content_type: str = "application/json"
    # Internal classification only; never serialized into the HTTP body.
    dispatch_decision: str | None = None

    def to_json(self) -> str:
        if not isinstance(self.body, dict):
            return json.dumps({"status": self.status, "body": self.body}, sort_keys=True)
        return json.dumps({"status": self.status, "body": self.body}, sort_keys=True)


from .replica_authority import bound_entry

def _mcp_wire_failure(body: Any, response: ApiResponse, *, code: int = -32000) -> ApiResponse:
    """Serialize outer failures without answering validated notifications."""
    from .mutation_dispatch import InvalidMCPRequest, validate_mcp_envelope

    if response.status == 401:
        return response  # Do not echo identifiers from unauthenticated bodies.
    try:
        validate_mcp_envelope(body)
    except InvalidMCPRequest as exc:
        wire = exc.response
    else:
        if "id" not in body:
            return ApiResponse(202, "", dispatch_decision=response.dispatch_decision)
        data = response.body if isinstance(response.body, dict) else {"error": "request_refused"}
        wire = {"jsonrpc": "2.0", "id": body["id"], "error": {
            "code": code, "message": str(data.get("error", "request_refused")), "data": data,
        }}
    if wire is None:
        return ApiResponse(202, "", dispatch_decision=response.dispatch_decision)
    return ApiResponse(response.status, json.dumps(wire, sort_keys=True),
                       dispatch_decision=response.dispatch_decision)


def _mcp_parse_failure(status: int, message: str) -> ApiResponse:
    # No trustworthy envelope (and therefore no notification/id) exists yet.
    return ApiResponse(status, json.dumps({"jsonrpc": "2.0", "id": None,
                       "error": {"code": -32700, "message": message}}, sort_keys=True))


def _mcp_wire_response(function):
    """Keep every admission/recovery failure on the JSON-RPC wire contract."""
    from functools import wraps
    @wraps(function)
    def wrapped(*args,**kwargs):
        method=kwargs.get('method',args[0] if args else None)
        path=kwargs.get('path',args[1] if len(args)>1 else '')
        body=kwargs.get('body',args[2] if len(args)>2 else None)
        response=function(*args,**kwargs)
        if str(method).upper()!='POST' or urlsplit(path).path!='/mcp':return response
        # Authentication precedes protocol parsing/correlation. Invalid
        # credentials never become an accepted notification or an ID echo.
        if response.status==401:return response
        value=response.body
        if isinstance(value,str):
            try:value=json.loads(value)
            except (ValueError,TypeError):pass
        if isinstance(value,dict) and value.get('jsonrpc')=='2.0':return response
        if response.status>=400:
            return _mcp_wire_failure(body, response)
        return response
    return wrapped

@bound_entry
@_mcp_wire_response
def handle_api_request(
    method: str,
    path: str,
    body: Any,
    vault: Path,
    state: Path,
    bearer_secret: str | None = None,
    authorization: Optional[str] = None,
    mcp_profile: str = "read-only",
    allow_unauthenticated_demo: bool = False,
    audit_log: Path | None = None,
    idempotency_key: str | None = None,
    delivery_routes: Path | None = None,
    inspection_guard: InspectionGuard | None = None,
) -> ApiResponse:
    route = urlsplit(path).path
    if method.upper() == "POST" and re.fullmatch(r"/operator-archive/[^/]+", route):
        from .operator_archive import generic_archive_enabled
        if not generic_archive_enabled():
            return ApiResponse(503, {"error": "generic operator archive disabled"})
    if route == "/diagnostics" or route.startswith("/diagnostics/"):
        # Separate metadata store: never journal browser payloads in business audit.
        return _handle_api_request(method=method, path=path, body=body, vault=vault,
                                   state=state, bearer_secret=bearer_secret,
                                   authorization=authorization, mcp_profile=mcp_profile,
                                   allow_unauthenticated_demo=False, audit_log=audit_log,
                                   delivery_routes=delivery_routes, inspection_guard=inspection_guard)
    if route.startswith("/secret-delivery"):
        return ApiResponse(503, {"error": "secret-delivery-http-intake-only"})
    identity = resolve_identity(vault, authorization, shared_secret=bearer_secret)
    # Explicit credentials never inherit demo anonymity. Reject before MCP
    # validation, mutation admission or any business audit/journal writes.
    if identity is None and (authorization is not None or bearer_secret) and route not in PUBLIC_PATHS:
        return ApiResponse(401, {"ok": False, "error": "unauthorized"})
    if method.upper() == "POST" and _is_retirement_route(route):
        denied = _operator_only(identity)
        if denied is not None:
            return denied
    if method.upper() == "POST" and route == "/mcp":
        from .mutation_dispatch import InvalidMCPRequest, validate_mcp_envelope
        try:
            validate_mcp_envelope(body)
        except InvalidMCPRequest as exc:
            if exc.response is None:
                return ApiResponse(202, "", dispatch_decision="error")
            return ApiResponse(400, json.dumps(exc.response, sort_keys=True), dispatch_decision="error")
    request_body = body or {}
    requires_audit = _requires_audit_success(method.upper(), route, request_body)
    resolved_audit_log = audit_log or default_audit_log(state)
    operation_id: str | None = None
    operation_store = journal_path(resolved_audit_log)
    if requires_audit:
        if identity is None and not allow_unauthenticated_demo:
            response = _handle_api_request(
                method=method,
                path=path,
                body=body,
                vault=vault,
                state=state,
                bearer_secret=bearer_secret,
                authorization=authorization,
                identity_snapshot=(identity,),
                mcp_profile=mcp_profile,
                allow_unauthenticated_demo=allow_unauthenticated_demo,
                audit_log=audit_log,
                delivery_routes=delivery_routes,
                inspection_guard=inspection_guard,
            )
            if route not in PUBLIC_PATHS:
                _audit_api_request(
                    audit_log=resolved_audit_log,
                    vault=vault,
                    method=method.upper(),
                    route=route,
                    body=request_body,
                    response=response,
                    bearer_secret=bearer_secret,
                    authorization=authorization,
                    identity_snapshot=(identity,),
                    operation_id=None,
                )
            return response
        try:
            validate_mutation_input(request_body, route)
            key = _request_idempotency_key(request_body, route=route, explicit=idempotency_key)
        except ValueError as exc:
            return ApiResponse(400, {"ok": False, "error": str(exc)})
        if key is None and allow_unauthenticated_demo:
            key = f"demo-{uuid.uuid4().hex}"
        if key is None:
            return ApiResponse(428, {"ok": False, "error": "idempotency_key_required"})
        principal = f"{identity.kind}:{identity.agent_id}" if identity else "demo:anonymous"
        action = _canonical_action(method.upper(), route, request_body)
        try:
            claim = claim_mutation(
                operation_store,
                vault=vault,
                state=state,
                principal_scope=principal,
                action=action,
                idempotency_key=key,
                body=request_body,
                route=route,
                legacy_action=legacy_journal_action(method.upper(), route),
            )
        except JournalNamespaceError as exc:
            return ApiResponse(503, {"ok": False, "error": "operation_journal_namespace_unavailable",
                                     "detail": str(exc), "retry_safe": False})
        except (sqlite3.Error, OSError, RuntimeError, ValueError) as exc:
            capture(exc, component="api", code="journal_claim")
            return ApiResponse(503, {"ok": False, "error": "operation journal unavailable"})
        operation_id = claim.operation_id
        if claim.conflict:
            return ApiResponse(409, {"ok": False, "error": "idempotency_conflict", "operation_id": operation_id})
        if (not claim.created and method.upper() == "POST"
                and route == "/control/transcripts" and identity is not None
                and claim.state in {"dispatching", "completed", "outcome_pending"}):
            # Transcript publication is serialized and keyed by event ID. An
            # interrupted dispatch may have failed before the event append;
            # retry that publication with current producer authorization. A
            # frozen outcome may only repair an already existing event.
            # Exact journal binding precedes all producer effects/barriers.
            if _required_scope("POST", route) not in identity.scopes:
                return ApiResponse(403, {"ok": False, "error": "transcript write scope required"})
            try:
                from .replica_authority import assert_mutation_authority
                from .cockpit_archive_authority import append_transcript
                assert_mutation_authority(vault)
                payload = dict(request_body)
                payload.pop("idempotency_key", None)
                actor = _actor(identity, payload.pop("actor", None), "")
                if payload.get("event_id") != key:
                    raise ValueError("transcript event ID must match idempotency key")
                receipt = append_transcript(vault, state, payload, actor=actor,
                                            replay_only=claim.state != "dispatching")
                response = ApiResponse(200, receipt)
                outcome = _build_api_audit_event(
                    vault=vault, method="POST", route=route, body=request_body,
                    response=response, bearer_secret=bearer_secret,
                    authorization=authorization, identity_snapshot=(identity,),
                    operation_id=operation_id,
                )
                # Retain an already frozen audit outcome; repairing storage must
                # not invent a second outcome identity for the original operation.
                if claim.safe_outcome:
                    outcome = dict(claim.safe_outcome)
                    for field in ("method", "route", "mcp_method", "tool"):
                        outcome.pop(field, None)
                    outcome.update(request_metadata("POST", route, request_body))
                if claim.state != "completed":
                    set_operation_state(operation_store, operation_id, "outcome_pending",
                                        safe_outcome=outcome, http_status=200)
                append_audit_once(resolved_audit_log, outcome)
                set_operation_state(operation_store, operation_id, "completed")
                return response
            except (sqlite3.Error, OSError, RuntimeError, ValueError) as exc:
                capture(exc, component="api", code="transcript_recovery")
                return ApiResponse(503, {"ok": False, "error": "operation_reconciliation_required",
                                         "operation_id": operation_id})
        if not claim.created:
            if claim.state == "outcome_pending" and claim.safe_outcome:
                try:
                    # Historical outcomes may predate the metadata boundary.
                    # Actor/key/request binding was checked by the journal above;
                    # replace metadata only, retaining the original outcome identity.
                    retry_outcome = dict(claim.safe_outcome)
                    for field in ("method", "route", "mcp_method", "tool"):
                        retry_outcome.pop(field, None)
                    retry_outcome.update(request_metadata(method.upper(), route, request_body))
                    append_audit_once(resolved_audit_log, retry_outcome)
                    set_operation_state(operation_store, operation_id, "completed")
                except (sqlite3.Error, OSError, RuntimeError, ValueError) as exc:
                    capture(exc, component="api", code="audit_retry")
                    return ApiResponse(503, {"ok": False, "error": "audit_completion_pending", "operation_id": operation_id})
                error = "secret_value_not_replayable" if route == "/secret/resolve" else "operation_completed_no_replay"
                return _completed_mutation_response(route, request_body, error, operation_id)
            if claim.state == "completed":
                error = "secret_value_not_replayable" if route == "/secret/resolve" else "operation_completed_no_replay"
                return _completed_mutation_response(route, request_body, error, operation_id)
            if claim.state not in {"claimed", "intent_durable"}:
                return ApiResponse(409, {"ok": False, "error": "operation_reconciliation_required", "operation_id": operation_id})
        if claim.state == "claimed":
            if not _audit_api_intent(
                audit_log=resolved_audit_log,
                vault=vault,
                method=method.upper(),
                route=route,
                body=request_body,
                bearer_secret=bearer_secret,
                authorization=authorization,
                identity_snapshot=(identity,),
                operation_id=operation_id,
            ):
                return ApiResponse(503, {"ok": False, "error": "audit log write failed; mutation was not attempted", "operation_id": operation_id})
            try:
                transition_operation_state(
                    operation_store,
                    operation_id,
                    expected_state="claimed",
                    new_state="intent_durable",
                )
            except (sqlite3.Error, OSError, RuntimeError) as exc:
                capture(exc, component="api", code="intent_transition")
                return _uncertain_mutation_response(route, request_body, operation_id)
        dispatch_owner = uuid.uuid4().hex
        try:
            dispatched = try_begin_dispatch(operation_store, operation_id, dispatch_owner)
        except (sqlite3.Error, OSError, RuntimeError) as exc:
            capture(exc, component="api", code="dispatch_transition")
            return _uncertain_mutation_response(route, request_body, operation_id)
        if not dispatched:
            return ApiResponse(
                409,
                {"ok": False, "error": "operation_in_progress", "operation_id": operation_id},
            )
    try:
        return _dispatch_and_record(
            method=method, path=path, body=body, request_body=request_body,
            route=route, key=key if requires_audit else None,
            requires_audit=requires_audit, operation_id=operation_id,
            operation_store=operation_store, resolved_audit_log=resolved_audit_log,
            vault=vault, state=state, bearer_secret=bearer_secret,
            authorization=authorization, identity=identity, mcp_profile=mcp_profile,
            allow_unauthenticated_demo=allow_unauthenticated_demo,
            audit_log=audit_log, delivery_routes=delivery_routes, inspection_guard=inspection_guard)
    except (sqlite3.Error, OSError, RuntimeError) as exc:
        if not requires_audit or operation_id is None:
            raise
        capture(exc, component="api", code="dispatch_uncertain")
        # A handler or later audit barrier may have committed before failing.
        # Keep the durable dispatch fence; never mark this completed/retryable
        # from an exception class, and never echo storage/provider error text.
        return _uncertain_mutation_response(route, request_body, operation_id)


def _uncertain_mutation_response(route, request_body, operation_id):
    data = {"operation_id": operation_id, "outcome": "uncertain", "retry_safe": False}
    if route == '/mcp':
        if 'id' not in request_body:
            return ApiResponse(202, '')
        return ApiResponse(503, json.dumps({"jsonrpc": "2.0", "id": request_body['id'],
            "error": {"code": -32000, "message": "operation_reconciliation_required", "data": data}}, sort_keys=True))
    return ApiResponse(503, {"ok": False, "error": "operation_reconciliation_required", **data})


def _dispatch_and_record(*, method, path, body, request_body, route, key,
        requires_audit, operation_id, operation_store, resolved_audit_log, vault,
        state, bearer_secret, authorization, identity, mcp_profile,
        allow_unauthenticated_demo, audit_log, delivery_routes, inspection_guard):
    dispatch_body = mutation_command(request_body, route, key) if requires_audit else body
    response = _handle_api_request(
        method=method,
        path=path,
        body=dispatch_body,
        vault=vault,
        state=state,
        bearer_secret=bearer_secret,
        authorization=authorization,
        identity_snapshot=(identity,),
        mcp_profile=mcp_profile,
        allow_unauthenticated_demo=allow_unauthenticated_demo,
        audit_log=audit_log,
        delivery_routes=delivery_routes,
        inspection_guard=inspection_guard,
    )
    if route not in PUBLIC_PATHS:
        outcome_event = _build_api_audit_event(
            vault=vault,
            method=method.upper(),
            route=route,
            body=body or {},
            response=response,
            bearer_secret=bearer_secret,
            authorization=authorization,
            identity_snapshot=(identity,),
            operation_id=operation_id,
        )
        if requires_audit and operation_id:
            set_operation_state(
                operation_store,
                operation_id,
                "outcome_pending",
                safe_outcome=outcome_event,
                http_status=response.status,
            )
        try:
            if operation_id:
                append_audit_once(resolved_audit_log, outcome_event)
            else:
                append_audit(resolved_audit_log, outcome_event)
        except OSError as exc:
            capture(exc, component="api", code="audit_outcome")
            if requires_audit and operation_id:
                return ApiResponse(503, {"ok": False, "error": "audit_completion_pending", "operation_id": operation_id})
        else:
            if requires_audit and operation_id:
                set_operation_state(operation_store, operation_id, "completed")
    return response


from .mutation_dispatch import resolve_mutation_key as _request_idempotency_key
from .mutation_dispatch import canonical_mutation_body as _canonical_request_body, mutation_command, claim_mutation, validate_mutation_input


def _completed_mutation_response(
    route: str, request_body: dict[str, Any], error: str, operation_id: str,
) -> ApiResponse:
    if route == "/mcp":
        if "id" not in request_body:
            return ApiResponse(202, "")
        return ApiResponse(409, json.dumps(
            {"jsonrpc": "2.0", "id": request_body["id"],
             "error": {"code": -32000, "message": error,
                       "data": {"operation_id": operation_id}}}, sort_keys=True))
    return ApiResponse(409, {"ok": False, "error": error, "operation_id": operation_id})


def _route_body(body: dict[str, Any]) -> dict[str, Any]:
    """Caller-supplied route fields, with platform-level metadata removed.

    ``idempotency_key`` is accepted from the request body on every route by
    ``_request_idempotency_key``, and the journal claim plus the durable intent
    audit are written before the route handler runs. A route body allowlist
    that rejected the key would therefore answer 400 after the key was already
    claimed (and the outcome path marks the operation completed), so the
    caller's retry with that key could never succeed: a valid mutation refused,
    plus a permanently burned key.
    """
    return {key: value for key, value in body.items() if key != "idempotency_key"}



def _canonical_action(method: str, route: str, body: dict[str, Any]) -> str:
    return journal_action(method, route, body)


# MCP tools whose tools/call is a pure read: exempt from the audit-success /
# idempotency-key gate. Derived from mcp.READ_TOOL_NAMES, the single source of
# truth for read-only tools; test_mcp_audit_gate_exempts_every_read_tool pins
# the invariant so a new read tool can never silently regress into the 428
# write path (incident 2026-08-31: execution_session_return_get blocked Odin).
MCP_AUDIT_EXEMPT_TOOLS = frozenset(READ_TOOL_NAMES)


def _effective_mcp_profile(server_profile: str, identity: Identity | None) -> str:
    """Cap identity-bound agent tokens at the ``agent`` profile.

    The effective MCP surface is ``profile ∩ scopes``. Production runs the API
    with ``--mcp-profile operator`` so the dashboard and ``arvctl`` (shared
    operator secret) keep the full surface, but that must not hand a bound
    agent token the authority-bearing tools the agent profile withholds
    (approval decisions, handoff review). Operator/global callers keep the
    server profile; a ``read-only`` server stays read-only for everyone.
    """
    if identity is not None and identity.binds_actor and server_profile == "operator":
        return "agent"
    return server_profile


def _requires_audit_success(method: str, route: str, body: dict[str, Any]) -> bool:
    if route == "/secret/resolve":
        return True
    if route == "/mcp":
        params = body.get("params") if isinstance(body.get("params"), dict) else {}
        if body.get("method") != "tools/call":
            return False
        return str(params.get("name", "")) not in MCP_AUDIT_EXEMPT_TOOLS
    if method != "POST":
        return method in {"PUT", "PATCH", "DELETE"}
    # POST routes that do not change state. /mcp is mixed (tools/list is a read,
    # tools/call may write); its writes stay best-effort audited rather than
    # fail an entire batch on a read. secret.resolve is handled above because
    # resolving a real value must never succeed without an audit receipt.
    return route not in {"/memory/recall", "/mcp"}


def _audit_api_intent(
    audit_log: Path,
    vault: Path,
    method: str,
    route: str,
    body: dict[str, Any],
    bearer_secret: str | None,
    authorization: Optional[str],
    operation_id: Optional[str],
    identity_snapshot: tuple[Identity | None] | None = None,
) -> bool:
    identity = identity_snapshot[0] if identity_snapshot is not None else resolve_identity(vault, authorization, shared_secret=bearer_secret)
    event: dict[str, Any] = {
        "event_id": f"{operation_id}:intent",
        "surface": "api",
        "phase": "intent",
        **request_metadata(method, route, body),
        "decision": "pending",
        "identity": identity.agent_id if identity else "anonymous",
        "identity_kind": identity.kind if identity else "none",
        "operation_id": operation_id,
    }
    if route == "/mcp":
        params = body.get("params") if isinstance(body.get("params"), dict) else {}
        if params.get("name"):
            args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            if params["name"] == "secret.resolve" and args.get("ref"):
                event["secret_ref"] = _bounded_secret_ref(args["ref"])
    if route == "/secret/resolve" and body.get("ref"):
        event["secret_ref"] = _bounded_secret_ref(body["ref"])
    try:
        append_audit_once(audit_log, event)
    except OSError as exc:
        capture(exc, component="api", code="audit_intent")
        return False
    return True


def _build_api_audit_event(
    vault: Path,
    method: str,
    route: str,
    body: dict[str, Any],
    response: ApiResponse,
    bearer_secret: str | None,
    authorization: Optional[str],
    operation_id: Optional[str],
    identity_snapshot: tuple[Identity | None] | None = None,
) -> dict[str, Any]:
    identity = identity_snapshot[0] if identity_snapshot is not None else resolve_identity(vault, authorization, shared_secret=bearer_secret)
    if response.dispatch_decision is not None:
        decision = response.dispatch_decision
    elif route == "/mcp" and response.status < 400 and _mcp_response_has_error(response):
        decision = "error"
    elif response.status < 400:
        decision = "allowed"
    elif response.status in {401, 403}:
        decision = "denied"
    else:
        decision = "error"
    event: dict[str, Any] = {
        "surface": "api",
        "phase": "outcome" if operation_id else "request",
        "operation_id": operation_id,
        **request_metadata(method, route, body),
        "status": response.status,
        "decision": decision,
        "identity": identity.agent_id if identity else "anonymous",
        "identity_kind": identity.kind if identity else "none",
    }
    if operation_id:
        event["event_id"] = f"{operation_id}:outcome"
    if route == "/mcp":
        params = body.get("params") if isinstance(body.get("params"), dict) else {}
        if params.get("name"):
            args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            if params["name"] == "secret.resolve" and args.get("ref"):
                event["secret_ref"] = _bounded_secret_ref(args["ref"])
    if route == "/secret/resolve" and body.get("ref"):
        event["secret_ref"] = _bounded_secret_ref(body["ref"])
    return event


def _audit_api_request(
    audit_log: Path,
    vault: Path,
    method: str,
    route: str,
    body: dict[str, Any],
    response: ApiResponse,
    bearer_secret: str | None,
    authorization: Optional[str],
    operation_id: Optional[str],
    identity_snapshot: tuple[Identity | None] | None = None,
) -> bool:
    event = _build_api_audit_event(
        vault=vault,
        method=method,
        route=route,
        body=body,
        response=response,
        bearer_secret=bearer_secret,
        authorization=authorization,
        operation_id=operation_id,
        identity_snapshot=identity_snapshot,
    )
    try:
        if operation_id:
            append_audit_once(audit_log, event)
        else:
            append_audit(audit_log, event)
    except OSError as exc:
        capture(exc, component="api", code="audit_outcome")
        return False
    return True


def _bounded_secret_ref(value: object) -> str:
    raw = str(value)
    try:
        return parse_ref(raw).uri
    except BrokerError:
        digest = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]
        return f"invalid-ref:sha256:{digest}"


def _claim_denial_audit_slot(route: str, status: int) -> bool:
    safe_route = route_metadata(route)
    normalized = "<unknown>" if safe_route.startswith("unknown:sha256:") else safe_route
    bucket = int(time.monotonic() // 60)
    key = (normalized, status)
    with _DENIAL_AUDIT_LOCK:
        stale = [item for item, seen_bucket in _DENIAL_AUDIT_BUCKETS.items() if seen_bucket != bucket]
        for item in stale:
            _DENIAL_AUDIT_BUCKETS.pop(item, None)
        if _DENIAL_AUDIT_BUCKETS.get(key) == bucket:
            return False
        if len(_DENIAL_AUDIT_BUCKETS) >= 128:
            return False
        _DENIAL_AUDIT_BUCKETS[key] = bucket
    return True


def _with_pending_audit(response: ApiResponse, operation_id: Optional[str]) -> ApiResponse:
    audit = {"completion": "pending", "operation_id": operation_id}
    if isinstance(response.body, dict):
        body = dict(response.body)
        body["audit"] = audit
    else:
        body = {"ok": True, "result": response.body, "audit": audit}
    return ApiResponse(response.status, body, content_type=response.content_type)


def _mcp_response_has_error(response: ApiResponse) -> bool:
    body: Any
    if isinstance(response.body, str):
        try:
            body = json.loads(response.body)
        except json.JSONDecodeError:
            return False
    else:
        body = response.body
    if not isinstance(body, dict):
        return False
    return isinstance(body.get("error"), dict)


def _handle_api_request(
    method: str,
    path: str,
    body: dict[str, Any] | None,
    vault: Path,
    state: Path,
    bearer_secret: str | None = None,
    authorization: Optional[str] = None,
    mcp_profile: str = "read-only",
    allow_unauthenticated_demo: bool = False,
    audit_log: Path | None = None,
    delivery_routes: Path | None = None,
    inspection_guard: InspectionGuard | None = None,
    identity_snapshot: tuple[Identity | None] | None = None,
) -> ApiResponse:
    method = method.upper()
    body = body or {}
    parsed_path = urlsplit(path)
    route = parsed_path.path
    query = parse_qs(parsed_path.query)
    if method == "POST" and re.fullmatch(r"/operator-archive/[^/]+", route):
        from .operator_archive import generic_archive_enabled
        if not generic_archive_enabled():
            return ApiResponse(503, {"error": "generic operator archive disabled"})

    try:
        if method == "GET" and route in {"/", "/dashboard"}:
            return ApiResponse(200, _dashboard_html(), content_type="text/html; charset=utf-8")
        if method == "GET" and route == "/health":
            return ApiResponse(200, {"ok": True, "service": "arvyx-control-api"})

        identity = identity_snapshot[0] if identity_snapshot is not None else resolve_identity(vault, authorization, shared_secret=bearer_secret)
        if method == "POST" and _is_retirement_route(route):
            denied = _operator_only(identity)
            if denied is not None:
                return denied
        if authorization is not None and identity is None and route not in PUBLIC_PATHS:
            return ApiResponse(401, {"ok": False, "error": "unauthorized"})
        if bearer_secret and identity is None and route not in PUBLIC_PATHS:
            return ApiResponse(401, {"ok": False, "error": "unauthorized"})
        if identity is not None:
            scopes = identity.scopes
        elif allow_unauthenticated_demo:
            scopes = ALL_SCOPES
        else:
            scopes = UNAUTHENTICATED_SCOPES
        required_scope = _required_scope(method, route)
        if required_scope is not None and required_scope not in scopes:
            if identity is not None:
                return ApiResponse(
                    403,
                    {"ok": False, "error": f"identity {identity.agent_id} lacks scope: {required_scope}"},
                )
            return ApiResponse(
                401,
                {
                    "ok": False,
                    "error": (
                        f"authentication required for scope {required_scope}; issue an agent token "
                        "with 'arvyx auth issue' or serve with --allow-unauthenticated-demo"
                    ),
                },
            )

        # MCP's transport POST can be read-only; its shared tool dispatcher
        # applies the semantic mutation fence. Other non-read requests must
        # not escape merely because business audit classification omitted them.
        if method not in {"GET", "HEAD", "OPTIONS"} and route != "/mcp":
            from .replica_authority import assert_mutation_authority
            assert_mutation_authority(vault)

        if route == "/diagnostics" or route.startswith("/diagnostics/"):
            denied = _operator_only(identity)
            if denied is not None:
                return denied
            reporter = get_reporter()
            if method == "GET" and route in {"/diagnostics", "/diagnostics/status"}:
                result = reporter.read()
                return ApiResponse(200, result if route == "/diagnostics" else {"status": result["status"]})
            if method == "GET" and route == "/diagnostics/feed":
                return ApiResponse(200, reporter.feed(int(query.get("after", ["0"])[0])))
            if method == "GET" and re.fullmatch(r"/diagnostics/groups/[0-9a-f]{64}", route):
                return ApiResponse(200, reporter.read(route.rsplit("/", 1)[1]))
            if method == "POST" and route == "/diagnostics/client":
                trace = reporter.client(body)
                return ApiResponse(202 if trace else 429, {"accepted": bool(trace), "trace_id": trace, "trust": "untrusted-client"})
            return ApiResponse(404, {"error": "diagnostic route not found"})

        if method == "GET" and route == "/summary":
            denied = _operator_only(identity)
            if denied is not None:
                return denied
            return ApiResponse(
                200,
                _operator_summary(
                    vault=vault,
                    state=state,
                    mcp_profile=mcp_profile,
                    query=query,
                ),
            )
        if method == "GET" and route == "/control-plane":
            denied = _operator_only(identity)
            if denied is not None:
                return denied
            return ApiResponse(
                200, _control_plane(vault=vault, state=state, delivery_routes=delivery_routes)
            )
        if method == "GET" and route == "/digest":
            return ApiResponse(
                200,
                build_digest(
                    state=state,
                    vault=vault,
                    agent=_query_string(query, "agent"),
                    window_hours=min(_query_positive_int(query, "window_hours") or 24, 24 * 90),
                    # Hot checkpoint prose requires its distinct session.read scope;
                    # ordinary curated-memory readers must not inherit it.
                    include_session=SCOPE_SESSION_READ in scopes,
                ).to_dict(),
            )
        if method == "GET" and route == "/audit/events":
            limit = min(_query_positive_int(query, "limit") or 50, 500)
            return ApiResponse(
                200,
                recent_events(audit_log or default_audit_log(state), limit=limit).to_dict(),
            )
        if method == "POST" and route == "/secret/resolve":
            resolved = resolve_ref(str(body.get("ref", "")), repo=vault)
            return ApiResponse(200, resolved.to_dict(include_value=True))
        if method == "GET" and route == "/secret/brokers":
            return ApiResponse(200, {"brokers": list_brokers(repo=vault)})
        if method == "GET" and route == "/replica/manifest":
            return ApiResponse(
                200,
                build_manifest(
                    vault=vault,
                    state=state if state.is_file() else None,
                    audit_log=(audit_log or default_audit_log(state)),
                ),
            )
        if method == "GET" and route == "/replica/file":
            file_path = _query_string(query, "path")
            if not file_path:
                raise ValueError("path query parameter is required")
            return ApiResponse(200, read_vault_file(vault=vault, relative=file_path))
        if method == "GET" and route == "/replica/state":
            name = _query_string(query, "name")
            if not name:
                raise ValueError("name query parameter is required")
            size_text = _query_string(query, "size")
            digest = _query_string(query, "sha256")
            if size_text is None or not size_text.isascii() or not size_text.isdecimal() or len(size_text) > 8:
                raise ValueError("bounded size query parameter is required")
            if not digest:
                raise ValueError("sha256 query parameter is required")
            return ApiResponse(
                200,
                read_state_file(
                    name=name,
                    state=state,
                    audit_log=(audit_log or default_audit_log(state)),
                    size=int(size_text),
                    sha256=digest,
                ),
            )
        if method == "POST" and route == "/mcp":
            effective_profile = _effective_mcp_profile(mcp_profile, identity)
            allowed_tools = set(tools_for_profile(effective_profile)) & tools_for_scopes(scopes)
            dispatch_outcome: dict[str, str] = {}
            mcp_response = handle_request(
                body,
                vault=vault,
                state=state,
                allowed_tools=allowed_tools,
                actor=identity.agent_id if identity is not None and identity.binds_actor else None,
                include_session=SCOPE_SESSION_READ in scopes,
                principal_scope=f"{identity.kind}:{identity.agent_id}" if identity else "demo:anonymous",
                # Provide the durable audit lane the MCP layer requires: the same
                # log the API layer writes to. Without it every HTTP secret.resolve
                # is refused ("audit log is required"); dropping it to silence that
                # is exactly the regression this guards against.
                secret_audit_log=(audit_log or default_audit_log(state)),
                inspection_guard=inspection_guard,
                mutation_claimed=True,
                dispatch_outcome=dispatch_outcome,
            )
            if mcp_response is None:  # JSON-RPC notification
                return ApiResponse(202, "", dispatch_decision=dispatch_outcome.get("decision"))
            return ApiResponse(200, json.dumps(mcp_response, sort_keys=True), dispatch_decision=dispatch_outcome.get("decision"))
        if method == "POST" and route == "/control/transcripts":
            from .cockpit_archive_authority import append_transcript
            payload = dict(body)
            payload.pop('idempotency_key', None)
            actor = _actor(identity, payload.pop('actor', None), '')
            return ApiResponse(201, append_transcript(vault, state, payload, actor=actor))
        transcript_receipt_match = re.fullmatch(r'/control/transcripts/([^/]+)', route)
        if method == "GET" and transcript_receipt_match:
            from .cockpit_archive_authority import transcript_receipt
            return ApiResponse(200, transcript_receipt(vault, state, transcript_receipt_match.group(1), identity=identity))
        if method == "POST" and route == "/memory/recall":
            result = recall(
                question=str(body.get("question", "")),
                vault=vault,
                project=_optional_string(body.get("project")),
                max_tokens=coerce_int(body.get("max_tokens"), 350),
                limit=coerce_int(body.get("limit"), 4),
                retrieval_mode=str(body.get("retrieval_mode", "lexical")),
                recency_half_life_days=_optional_float(body.get("recency_half_life_days")),
            )
            return ApiResponse(200, result.to_dict())
        if method == "GET" and route == "/memory/session":
            agent = _query_string(query, "agent")
            if not agent:
                raise ValueError("agent query parameter is required")
            return ApiResponse(200, get_session(vault=vault, agent=agent).to_dict())
        if method == "POST" and route == "/memory/session":
            agent = _actor(identity, body.get("agent"), str(body.get("agent", "")))
            result = set_session(vault=vault, agent=agent, content=str(body.get("content", "")))
            return ApiResponse(201, result.to_dict())
        if method == "POST" and route == "/memory/suggest":
            tags_value = body.get("tags")
            result = suggest_memory(
                vault=vault,
                project=str(body.get("project", "")),
                title=str(body.get("title", "")),
                content=str(body.get("content", "")),
                author=_actor(identity, body.get("author"), ""),
                tags=[str(tag) for tag in tags_value] if isinstance(tags_value, list) else None,
            )
            return ApiResponse(201, result.to_dict())
        if method == "POST" and route == "/memory/suggest-batch":
            payload = {
                key: value
                for key, value in body.items()
                if key not in {"project", "author", "idempotency_key"}
            }
            result = suggest_memory_batch(
                vault=vault,
                project=str(body.get("project", "")),
                author=_actor(identity, body.get("author"), ""),
                payload=payload,
            )
            return ApiResponse(201, result.to_dict())
        if method == "GET" and route == "/schemas/memory-suggest-batch":
            return ApiResponse(200, memory_suggestion_batch_schema(include_envelope=True))
        if method == "GET" and route == "/memory/pending":
            project = _query_string(query, "project")
            if not project:
                raise ValueError("project query parameter is required")
            return ApiResponse(200, list_pending(vault=vault, project=project).to_dict())
        if method == "POST" and route == "/memory/refine":
            content_value = body.get("content")
            result = refine_memory(
                vault=vault,
                project=str(body.get("project", "")),
                source_path=str(body.get("source_path", "")),
                refined_by=_actor(identity, body.get("refined_by"), ""),
                content=str(content_value) if content_value is not None else None,
                notes=str(body.get("notes", "")),
            )
            return ApiResponse(200, result.to_dict())
        if method == "GET" and route == "/memory/refining":
            project = _query_string(query, "project")
            if not project:
                raise ValueError("project query parameter is required")
            return ApiResponse(200, list_refining(vault=vault, project=project).to_dict())
        if method == "POST" and route == "/memory/promote":
            result = promote_memory(
                vault=vault,
                project=str(body.get("project", "")),
                source_path=str(body.get("source_path", "")),
                promoted_by=_actor(identity, body.get("promoted_by"), "operator"),
            )
            return ApiResponse(200, result.to_dict())
        if method == "POST" and route == "/memory/reject":
            result = reject_memory(
                vault=vault,
                project=str(body.get("project", "")),
                source_path=str(body.get("source_path", "")),
                rejected_by=_actor(identity, body.get("rejected_by"), "operator"),
                reason=str(body.get("reason", "")),
            )
            return ApiResponse(200, result.to_dict())
        if method == "POST" and route == "/memory/forget":
            result = soft_forget(
                vault=vault, project=_optional_string(body.get("project")) or "", source_path=_optional_string(body.get("source_path")) or "",
                reason_category=_optional_string(body.get("reason_category")) or "", batch_id=_optional_string(body.get("batch_id")) or "",
                actor=_actor(identity, body.get("actor"), "operator"),
                idempotency_key=_optional_string(body.get("idempotency_key")) or "", dry_run=body.get("dry_run") is True,
            )
            return ApiResponse(200, result.to_dict())
        if method == "POST" and route == "/memory/restore":
            result = restore_forgotten(
                vault=vault, tombstone_path=_optional_string(body.get("tombstone_path")) or "",
                actor=_actor(identity, body.get("actor"), "operator"),
                idempotency_key=_optional_string(body.get("idempotency_key")) or "",
            )
            return ApiResponse(200, result.to_dict())
        if method == "GET" and route == "/tasks":
            return ApiResponse(200, list_tasks(state=state).to_dict())
        if method == "POST" and route == "/tasks":
            result = create_task(
                state=state,
                title=body.get("title"),
                owner=_actor(identity, body.get("owner"), ""),
                idempotency_key=_optional_string(body.get("idempotency_key")),
                principal_scope=f"{identity.kind}:{identity.agent_id}" if identity else "demo:anonymous",
                created_by=identity.agent_id if identity is not None and identity.binds_actor else "operator",
            )
            return ApiResponse(201, result.to_dict())
        task_done_match = re.fullmatch(r"/tasks/([^/]+)/done", route)
        if method == "POST" and task_done_match:
            result = complete_task(
                state=state,
                task_id=task_done_match.group(1),
                actor=identity.agent_id if identity is not None and identity.binds_actor else None,
            )
            return ApiResponse(200, result.to_dict())
        if method == "GET" and route == "/approvals":
            return ApiResponse(200, list_approvals(state=state).to_dict())
        if method == "POST" and route == "/approvals/request":
            result = request_approval(
                state=state,
                command=str(body.get("command", "")),
                requester=_actor(identity, body.get("requester"), ""),
                reason=str(body.get("reason", "")),
                ttl_seconds=coerce_int(body.get("ttl_seconds"), 3600),
                idempotency_key=_optional_string(body.get("idempotency_key")),
                principal_scope=f"{identity.kind}:{identity.agent_id}" if identity else "demo:anonymous",
            )
            return ApiResponse(201, result.to_dict())
        approval_approve_match = re.fullmatch(r"/approvals/([^/]+)/approve", route)
        if method == "POST" and approval_approve_match:
            # control.write permits agent coordination, not approval decisions.
            # Explicit anonymous demo mode retains its local demonstration path;
            # an authenticated non-operator never inherits that exception.
            if not (identity is not None and identity.kind == "operator") and not (
                identity is None and allow_unauthenticated_demo
            ):
                return ApiResponse(403, {"ok": False, "error": "operator identity required for approval decisions"})
            result = approve_request(
                state=state,
                approval_id=approval_approve_match.group(1),
                approver=_actor(identity, body.get("approver"), "operator"),
            )
            return ApiResponse(200, result.to_dict())
        approval_consume_match = re.fullmatch(r"/approvals/([^/]+)/consume", route)
        if method == "POST" and approval_consume_match:
            result = consume_approval(
                state=state,
                approval_id=approval_consume_match.group(1),
                command=str(body.get("command", "")),
                actor=identity.agent_id if identity is not None and identity.binds_actor else None,
            )
            return ApiResponse(200, result.to_dict())
        if method == "GET" and route == "/handoffs":
            return ApiResponse(200, _handoff_list(state=state, query=query))
        if method == "POST" and route == "/handoffs":
            result = create_handoff(
                state=state,
                title=str(body.get("title", "")),
                from_agent=_actor(identity, body.get("from_agent"), ""),
                to_agent=str(body.get("to_agent", "operator")),
                summary=str(body.get("summary", "")),
                idempotency_key=_optional_string(body.get("idempotency_key")),
                principal_scope=f"{identity.kind}:{identity.agent_id}" if identity else "demo:anonymous",
                actor_identity_bound=bool(identity is not None and identity.binds_actor),
            )
            return ApiResponse(201, result.to_dict())
        handoff_accept_match = re.fullmatch(r"/handoffs/([^/]+)/accept", route)
        if method == "POST" and handoff_accept_match:
            result = accept_handoff(
                state=state,
                handoff_id=handoff_accept_match.group(1),
                actor=_actor(identity, body.get("actor"), "operator"),
                actor_identity_bound=bool(identity is not None and identity.binds_actor),
            )
            return ApiResponse(200, result.to_dict())
        handoff_review_match = re.fullmatch(r"/handoffs/([^/]+)/review", route)
        if method == "POST" and handoff_review_match:
            if identity is None or identity.kind != "operator":
                return ApiResponse(403, {"ok": False, "error": "operator identity required for handoff review"})
            result = review_handoff(
                state=state,
                handoff_id=handoff_review_match.group(1),
                reviewer=_actor(identity, body.get("reviewer"), "operator"),
                decision=str(body.get("decision", "approved")),
                notes=str(body.get("notes", "")),
            )
            return ApiResponse(200, result.to_dict())
        handoff_complete_match = re.fullmatch(r"/handoffs/([^/]+)/complete", route)
        if method == "POST" and handoff_complete_match:
            result = complete_handoff(
                state=state,
                handoff_id=handoff_complete_match.group(1),
                actor=_actor(identity, body.get("actor"), "operator"),
                actor_identity_bound=bool(identity is not None and identity.binds_actor),
            )
            return ApiResponse(200, result.to_dict())
        if method == "GET" and route == "/threads":
            target, denied = _thread_scope(identity, _thread_target_query(query))
            if denied is not None:
                return denied
            return ApiResponse(200, list_thread_inbox(state=state, target=target).to_dict())
        if method == "GET" and route == "/threads/pending":
            target, denied = _thread_scope(identity, _thread_target_query(query))
            if denied is not None:
                return denied
            return ApiResponse(200, list_pending_threads(state=state, target=target).to_dict())
        if method == "POST" and route == "/threads":
            result = post_thread(
                state=state,
                title=str(body.get("title", "")),
                body=str(body.get("body", "")),
                thread_type=str(body.get("type", "ask")),
                actor=_actor(identity, body.get("actor"), ""),
                target=str(body.get("target", "operator")),
                channel=str(body.get("channel", "ops")),
                severity=str(body.get("severity", "notice")),
                completion_artifact=str(body.get("completion_artifact") or ""),
                completion_anchor=str(body.get("completion_anchor") or ""),
                continuation_thread_id=str(body.get("continuation_thread_id") or ""),
                actor_identity_bound=bool(identity is not None and identity.binds_actor),
            )
            return ApiResponse(201, result.to_dict())
        if method == "POST" and route == "/threads/read-all":
            # canonical key is "target"; "agent" stays as a legacy alias
            requested = _optional_string(body.get("target")) or _optional_string(body.get("agent"))
            target, denied = _thread_scope(identity, requested)
            if denied is not None:
                return denied
            result = read_all_threads(
                state=state,
                target=target or "operator",
                include_pending=bool(body.get("include_pending", False)),
            )
            return ApiResponse(200, result.to_dict())
        thread_ack_match = re.fullmatch(r"/threads/([^/]+)/ack", route)
        if method == "POST" and thread_ack_match:
            denied = _deny_foreign_thread_mutation(identity, state, thread_ack_match.group(1))
            if denied is not None:
                return denied
            result = acknowledge_thread(
                state=state,
                thread_id=thread_ack_match.group(1),
                actor=_actor(identity, body.get("actor"), "operator"),
                text=str(body.get("text", "")),
                actor_identity_bound=bool(identity is not None and identity.binds_actor),
            )
            return ApiResponse(200, result.to_dict())
        thread_done_match = re.fullmatch(r"/threads/([^/]+)/done", route)
        if method == "POST" and thread_done_match:
            denied = _deny_foreign_thread_mutation(identity, state, thread_done_match.group(1))
            if denied is not None:
                return denied
            result = complete_thread(
                state=state,
                thread_id=thread_done_match.group(1),
                actor=_actor(identity, body.get("actor"), "operator"),
                text=str(body.get("text", "")),
                evidence_artifact=str(body.get("evidence_artifact") or ""),
                evidence_anchor=str(body.get("evidence_anchor") or ""),
                evidence_method=str(body.get("evidence_method") or ""),
                actor_identity_bound=bool(identity is not None and identity.binds_actor),
            )
            return ApiResponse(200, result.to_dict())
        if method == "GET" and route == "/deliveries/health":
            denied = _operator_only(identity)
            if denied is not None:
                return denied
            return ApiResponse(200, _delivery_health(state))
        if method == "GET" and route == "/deliveries/dead-letter":
            denied = _operator_only(identity)
            if denied is not None:
                return denied
            try:
                configured_targets = _authoritative_delivery_targets(delivery_routes)
            except ValueError:
                configured_targets = None
            items = sorted(
                (item for item in project_outbox(state).values() if item.status == "dead_lettered"),
                key=lambda item: (item.updated_at, item.id),
            )
            return ApiResponse(
                200,
                {
                    "deliveries": [
                        _dead_letter_summary(item, configured_targets=configured_targets)
                        for item in items
                    ]
                },
            )
        dismissal_match = re.fullmatch(r"/operator-alert-dismissal/([^/]+)", route)
        if method == "POST" and dismissal_match:
            from .operator_alert_dismissal import dismiss_alert
            denied = _operator_only(identity)
            if denied is not None:
                return denied
            route_body = dict(_route_body(body))
            dry_run = route_body.pop("dry_run", True)
            result = dismiss_alert(state, record_id=dismissal_match.group(1), request=route_body,
                                   identity=identity, dry_run=dry_run)
            return ApiResponse(200, result)
        archive_match = re.fullmatch(r"/operator-archive/([^/]+)", route)
        if method == "POST" and archive_match:
            from .operator_archive import archive_record
            denied = _operator_only(identity)
            if denied is not None:
                return denied
            route_body = dict(_route_body(body))
            # Unlike legacy retirement, no omitted flag can apply a write.
            dry_run = route_body.pop("dry_run", True)
            result = archive_record(state, record_id=archive_match.group(1), request=route_body,
                                    identity=identity, dry_run=dry_run)
            return ApiResponse(200, result)
        thread_retire_match = re.fullmatch(r"/threads/([^/]+)/retire", route)
        delivery_retire_match = re.fullmatch(r"/deliveries/([^/]+)/retire", route)
        if method == "POST" and (thread_retire_match or delivery_retire_match):
            from .retirement import retire_thread, retire_pending_delivery
            denied = _operator_only(identity)
            if denied is not None:
                return denied
            request = dict(_route_body(body))
            dry_run = request.pop("dry_run", False)
            if thread_retire_match:
                result = retire_thread(state, thread_id=thread_retire_match.group(1),
                                       request=request, identity=identity, dry_run=dry_run)
            else:
                result = retire_pending_delivery(state, outbox_id=delivery_retire_match.group(1),
                                                 request=request, identity=identity, dry_run=dry_run)
            return ApiResponse(200, result)
        delivery_replay_match = re.fullmatch(r"/deliveries/([^/]+)/replay", route)
        if method == "POST" and delivery_replay_match:
            denied = _operator_only(identity)
            if denied is not None:
                return denied
            outbox_id = delivery_replay_match.group(1)
            original = project_outbox(state).get(outbox_id)
            if original is None:
                raise ValueError(f"unknown outbox item: {outbox_id}")
            configured_targets = _authoritative_delivery_targets(delivery_routes)
            if original.target not in configured_targets:
                raise ValueError(f"delivery target is not configured for replay: {outbox_id}")
            result = replay(state, outbox_id=outbox_id)
            return ApiResponse(201, result.to_dict())
        delivery_resolve_match = re.fullmatch(r"/deliveries/([^/]+)/resolve", route)
        if method == "POST" and delivery_resolve_match:
            denied = _operator_only(identity)
            if denied is not None:
                return denied
            route_body = _route_body(body)
            if not set(route_body) <= {"resolution_category", "detail"} or "resolution_category" not in route_body:
                raise ValueError("resolve body must contain resolution_category and optional detail")
            result = resolve_dead_letter(
                state,
                outbox_id=delivery_resolve_match.group(1),
                resolution_category=str(route_body.get("resolution_category", "")),
                resolved_by="operator",
                detail=str(route_body.get("detail", "")),
            )
            return ApiResponse(200, result.to_dict())
        delivery_cancel_match = re.fullmatch(r"/deliveries/([^/]+)/cancel", route)
        if method == "POST" and delivery_cancel_match:
            denied = _operator_only(identity)
            if denied is not None:
                return denied
            route_body = _route_body(body)
            if set(route_body) != {"reason_category"}:
                raise ValueError("cancel body must contain only reason_category")
            document = _authoritative_delivery_document(delivery_routes)
            configured_targets = set(document.routes)
            tick = project_dispatcher_tick(state)
            if not tick["initialized"]:
                raise ValueError("dispatcher route configuration is not initialized")
            tick_age = _health_age(datetime.now(timezone.utc), str(tick["last_tick_at"]))
            if tick_age is None or tick_age > 300:
                raise ValueError("dispatcher route configuration is stale; cancellation refused")
            tick_targets = tick.get("configured_targets", [])
            if not isinstance(tick_targets, list) or not all(isinstance(target, str) for target in tick_targets):
                raise ValueError("dispatcher route configuration is malformed; cancellation refused")
            attested_sha256 = str(tick.get("route_sha256", ""))
            if attested_sha256 and attested_sha256 != document.sha256:
                # The dispatcher attested that it loaded a different route
                # document than the one this API resolves. Divergent config is
                # never a safe basis for irreversible cancellation.
                raise ValueError(
                    "dispatcher-attested route document hash does not match the loaded route configuration; "
                    "cancellation refused"
                )
            configured_targets.update(tick_targets)
            result = cancel_unroutable(
                state,
                outbox_id=delivery_cancel_match.group(1),
                configured_targets=configured_targets,
                reason_category=str(route_body.get("reason_category", "")),
            )
            return ApiResponse(200, result.to_dict())
        if method == "GET" and route == "/deliveries":
            requested = _query_string(query, "target")
            target, denied = _thread_scope(identity, requested)
            if denied is not None:
                return denied
            status_filter = _query_string(query, "status")
            items = sorted(project_outbox(state).values(), key=lambda item: (item.created_at, item.id))
            if target:
                items = [item for item in items if same_agent_identity(item.target, target)]
            if status_filter:
                items = [item for item in items if item.status == status_filter]
            return ApiResponse(200, {"deliveries": [item.to_dict() for item in items]})
        decision_answer_match = re.fullmatch(r"/decisions/(decision_[0-9a-f]{24})/answer", route)
        if method == "POST" and decision_answer_match:
            # Called by the target agent's gateway code (not its model) when the operator presses
            # a card button or replies to the card. The agent identity only proves which
            # gateway relays it; authority comes from the nonce, the card's exact message
            # id, and the operator allowlist, all checked in answer_decision.
            if identity is None or not identity.binds_actor:
                return ApiResponse(403, {"ok": False, "error": "agent identity required for decision answer"})
            route_body = _route_body(body)
            allowed = {"choice", "text", "nonce", "operator_user_id", "platform", "chat_id", "message_id"}
            if not set(route_body) <= allowed:
                raise ValueError("decision answer body has unknown fields")
            answered = answer_decision(
                state,
                decision_id=decision_answer_match.group(1),
                actor=identity.agent_id,
                choice=str(route_body.get("choice", "")),
                text=str(route_body.get("text", "")),
                nonce=str(route_body.get("nonce", "")),
                operator_user_id=str(route_body.get("operator_user_id", "")),
                platform=str(route_body.get("platform", "")),
                message_id=str(route_body.get("message_id", "")),
            )
            return ApiResponse(200, {"ok": True, "status": answered.status, "decision_id": answered.decision_id,
                                     "choice": answered.choice})
        delivery_receipt_match = re.fullmatch(r"/deliveries/([^/]+)/receipt", route)
        if method == "POST" and delivery_receipt_match:
            if identity is None or not identity.binds_actor:
                return ApiResponse(403, {"ok": False, "error": "agent identity required for delivery receipt"})
            result = record_receipt(
                state,
                outbox_id=delivery_receipt_match.group(1),
                actor=identity.agent_id,
                status=str(body.get("status", "")),
                detail=str(body.get("detail", "")),
            )
            return ApiResponse(200, result.to_dict())
        if method == "GET" and route == "/fleet/health":
            denied = _operator_only(identity)
            if denied is not None:
                return denied
            plane = _control_plane(vault=vault, state=state, delivery_routes=delivery_routes)
            return ApiResponse(200, dict(plane["fleet"]))
        if method == "GET" and route == "/executions/health":
            denied = _operator_only(identity)
            if denied is not None:
                return denied
            capable = _authoritative_delivery_targets(delivery_routes)
            health = queue_health(state, execution_capable_targets=capable)
            health["watchdog"] = project_watchdog_tick(state)
            return ApiResponse(200, health)
        execution_replay_match = re.fullmatch(r"/executions/([^/]+)/replay", route)
        if method == "POST" and execution_replay_match:
            denied = _operator_only(identity)
            if denied is not None:
                return denied
            execution_id = execution_replay_match.group(1)
            execution = project_executions(state).get(execution_id)
            if execution is None:
                raise ValueError(f"unknown execution: {execution_id}")
            configured_targets = _authoritative_delivery_targets(delivery_routes)
            if execution.target not in configured_targets:
                raise ValueError(f"execution target is not configured for replay: {execution_id}")
            result = replay_execution(state, execution_id=execution_id, replayed_by="operator")
            return ApiResponse(201, result.to_dict())
        execution_hold_match = re.fullmatch(r"/executions/([^/]+)/hold", route)
        if method == "POST" and execution_hold_match:
            denied = _operator_only(identity)
            if denied is not None:
                return denied
            result = hold_execution(
                state,
                execution_id=execution_hold_match.group(1),
                reason=str(body.get("reason", "")),
                held_by="operator",
            )
            return ApiResponse(200, result.to_dict())
        execution_close_match = re.fullmatch(r"/executions/([^/]+)/close", route)
        if method == "POST" and execution_close_match:
            denied = _operator_only(identity)
            if denied is not None:
                return denied
            route_body = _route_body(body)
            if not set(route_body) <= {"resolution_category", "reason"} or "resolution_category" not in route_body:
                raise ValueError("close body must contain resolution_category and optional reason")
            result = close_execution(
                state,
                execution_id=execution_close_match.group(1),
                resolution_category=str(route_body.get("resolution_category", "")),
                reason=str(route_body.get("reason", "")),
                closed_by="operator",
            )
            return ApiResponse(200, result.to_dict())
        if method == "GET" and route == "/executions":
            target, denied = _thread_scope(identity, _query_string(query, "target"))
            if denied is not None:
                return denied
            status_filter = _query_string(query, "status")
            executions = sorted(
                project_executions(state).values(), key=lambda item: (item.created_at, item.id)
            )
            if target:
                executions = [item for item in executions if same_agent_identity(item.target, target)]
            if status_filter:
                executions = [item for item in executions if item.status == status_filter]
            return ApiResponse(200, {"executions": [item.to_dict() for item in executions]})
        execution_events_match = re.fullmatch(r"/executions/([^/]+)/events", route)
        if method == "GET" and execution_events_match:
            execution_id = execution_events_match.group(1)
            # Authorise from the checkpoint-accelerated projection; the listing below streams
            # the log. The whole-log snapshot refused any log over 16 MiB, which broke this
            # route in production (134 MiB log) even though list_execution_events streams.
            execution = project_executions(state).get(execution_id)
            if execution is None:
                raise ValueError(f"unknown execution: {execution_id}")
            if identity is not None and identity.binds_actor and execution.target != identity.agent_id:
                return ApiResponse(403, {"ok": False, "error": "identity may only read its own execution events"})
            return ApiResponse(200, list_execution_events(
                state, execution_id=execution_id,
                target=identity.agent_id if identity is not None and identity.binds_actor else "",
                after=_query_string(query, "after") or "",
                limit=_query_positive_int(query, "limit") or 100,
            ))
        execution_cancel_match = re.fullmatch(r"/executions/([^/]+)/cancel", route)
        if method == "POST" and execution_cancel_match:
            denied = _operator_only(identity)
            if denied is not None:
                return denied
            result = cancel_execution(state, execution_id=execution_cancel_match.group(1), reason=str(body.get("reason", "")), cancelled_by="operator")
            return ApiResponse(200, result.to_dict())
        execution_resume_match = re.fullmatch(r"/executions/([^/]+)/resume", route)
        if method == "POST" and execution_resume_match:
            denied = _operator_only(identity)
            if denied is not None:
                return denied
            result = resume_execution(state, execution_id=execution_resume_match.group(1), resumed_by="operator")
            return ApiResponse(200, result.to_dict())
        execution_steer_match = re.fullmatch(r"/executions/([^/]+)/steer", route)
        if method == "POST" and execution_steer_match:
            denied = _operator_only(identity)
            if denied is not None:
                return denied
            result = request_execution_steer(state, execution_id=execution_steer_match.group(1), attempt_id=str(body.get("attempt_id", "")), message=str(body.get("message", "")), requested_by="operator", idempotency_key=str(body.get("idempotency_key", "")))
            return ApiResponse(201, {"steer": result})
        execution_steer_ack_match = re.fullmatch(r"/executions/([^/]+)/steer-acknowledgement", route)
        if method == "POST" and execution_steer_ack_match:
            if identity is None or not identity.binds_actor:
                return ApiResponse(403, {"ok": False, "error": "agent identity required for steer acknowledgement"})
            result = acknowledge_execution_steer(state, execution_id=execution_steer_ack_match.group(1), attempt_id=str(body.get("attempt_id", "")), request_id=str(body.get("request_id", "")), actor=identity.agent_id, message=str(body.get("message", "")), idempotency_key=str(body.get("idempotency_key", "")))
            return ApiResponse(200, {"steer_acknowledgement": result})
        execution_heartbeat_match = re.fullmatch(r"/executions/([^/]+)/heartbeat", route)
        if method == "POST" and execution_heartbeat_match:
            if identity is None or not identity.binds_actor:
                return ApiResponse(
                    403, {"ok": False, "error": "agent identity required for execution heartbeat"}
                )
            lease_seconds = body.get("lease_seconds")
            result = heartbeat_execution_as_target(
                state,
                execution_id=execution_heartbeat_match.group(1),
                attempt_id=str(body.get("attempt_id", "")),
                actor=identity.agent_id,
                # Matches the MCP tool default so both surfaces renew the same
                # production worker interval.
                lease_seconds=int(lease_seconds) if lease_seconds is not None else 120,
                detail=str(body.get("detail", "")),
            )
            return ApiResponse(200, result.to_dict())
        execution_get_match = re.fullmatch(r"/executions/([^/]+)", route)
        if method == "GET" and execution_get_match:
            execution = project_executions(state).get(execution_get_match.group(1))
            if execution is None:
                raise ValueError(f"unknown execution: {execution_get_match.group(1)}")
            if identity is not None and identity.binds_actor and execution.target != identity.agent_id:
                return ApiResponse(
                    403,
                    {
                        "ok": False,
                        "error": (
                            f"execution {execution.id} targets {execution.target}; "
                            f"identity {identity.agent_id} may only read its own executions"
                        ),
                    },
                )
            return ApiResponse(200, {"execution": execution.to_dict()})
        if method == "GET" and route == "/bus":
            return ApiResponse(200, list_bus_messages(state=state).to_dict())
        if method == "POST" and route == "/bus":
            result = post_bus_message(
                state=state,
                message=str(body.get("message", "")),
                channel=str(body.get("channel", "ops")),
                actor=_actor(identity, body.get("actor"), ""),
                severity=str(body.get("severity", "notice")),
                idempotency_key=_optional_string(body.get("idempotency_key")),
                principal_scope=f"{identity.kind}:{identity.agent_id}" if identity else "demo:anonymous",
            )
            return ApiResponse(201, result.to_dict())
    except (FileNotFoundError, ValueError) as exc:
        capture(exc, component="api", code="refusal", expected=True)
        return ApiResponse(400, {"ok": False, "error": str(exc)})

    return ApiResponse(404, {"ok": False, "error": f"route not found: {method} {route}"})


def make_handler(
    vault: Path,
    state: Path,
    bearer_secret: str | None = None,
    mcp_profile: str = "read-only",
    allow_unauthenticated_demo: bool = False,
    audit_log: Path | None = None,
    delivery_routes: Path | None = None,
    inspection_guard: InspectionGuard | None = None,
    secret_delivery=None,
) -> type[BaseHTTPRequestHandler]:
    from .secret_delivery import dispatch as dispatch_secret_delivery
    from .replica_authority import authority_context, ReplicaAuthorityUnavailable

    class ArvyxApiHandler(BaseHTTPRequestHandler):
        server_version = "ArvyxControlAPI/0.1"

        def do_GET(self) -> None:  # noqa: N802
            if dispatch_secret_delivery(self, secret_delivery, vault, bearer_secret):
                return
            route = urlsplit(self.path).path
            if route not in PUBLIC_PATHS and not self._preauthorize("GET"):
                return
            self._handle({})

        def _body_failure(self, status: int, message: str) -> None:
            response = (_mcp_parse_failure(status, message)
                        if urlsplit(self.path).path == "/mcp"
                        else ApiResponse(status, {"ok": False, "error": message}))
            self._write(response)

        def do_POST(self) -> None:  # noqa: N802
            if dispatch_secret_delivery(self, secret_delivery, vault, bearer_secret):
                return
            try:
                lengths = self.headers.get_all("Content-Length", [])
                if len(lengths) > 1 or self.headers.get_all("Transfer-Encoding", []):
                    self.close_connection = True
                    raise ValueError("ambiguous request framing")
                length = int(lengths[0] if lengths else "0")
            except ValueError:
                self._body_failure(400, "invalid Content-Length")
                return
            # reject a negative length: it slips past the cap check and makes
            # rfile.read(-1) read the whole connection into memory (OOM DoS)
            body_limit = 2048 if urlsplit(self.path).path == "/diagnostics/client" else MAX_BODY_BYTES
            if length < 0 or length > body_limit:
                self._body_failure(413, "request body too large")
                return
            if not self._preauthorize("POST"):
                return
            previous_timeout = self.connection.gettimeout()
            self.connection.settimeout(REQUEST_BODY_TIMEOUT_SECONDS)
            try:
                consumed = self.rfile.read(length) if length else b""
                if len(consumed) != length:
                    self.close_connection = True
                    self._body_failure(400, "incomplete request body")
                    return
                def unique_fields(pairs):
                    result = {}
                    for key, value in pairs:
                        if key in result:
                            raise ValueError("duplicate JSON field")
                        result[key] = value
                    return result
                raw = consumed.decode("utf-8") if length else "{}"
                from .security import bounded_json_loads
                # Explicit product bound on nesting: the interpreter's own recursion
                # limit differs between Python versions and is not the contract.
                body = bounded_json_loads(raw, object_pairs_hook=unique_fields)
            except (TimeoutError, socket.timeout):
                self._body_failure(408, "request body timed out")
                return
            except UnicodeDecodeError:
                self._body_failure(400, "request body must be valid UTF-8")
                return
            except (ValueError, RecursionError):
                # RecursionError: deeply nested JSON is not a JSONDecodeError
                self._body_failure(400, "invalid or too deeply nested JSON body")
                return
            finally:
                self.connection.settimeout(previous_timeout)
            if not isinstance(body, dict) and urlsplit(self.path).path != "/mcp":
                self._write(ApiResponse(400, {"ok": False, "error": "body must be a JSON object"}))
                return
            self._handle(body)

        def _preauthorize(self, method: str) -> bool:
            route = urlsplit(self.path).path
            authorization = self.headers.get("Authorization")
            try:
                identity = resolve_identity(
                    vault,
                    authorization,
                    shared_secret=bearer_secret,
                )
            except Exception as exc:  # noqa: BLE001 - do not leak auth-store failures
                self.diagnostic_trace = capture(exc, component="api", code="auth_store") or uuid.uuid4().hex
                self._write(ApiResponse(500, {"ok": False, "error": "internal error"}))
                return False
            if identity is None and (authorization is not None or bearer_secret) and route not in PUBLIC_PATHS:
                # Refuse foreign/invalid credentials before reading a payload
                # or creating persistent denial/audit/operation state.
                self._write(ApiResponse(401, {"ok": False, "error": "unauthorized"}))
                return False
            if method == "POST" and _is_retirement_route(route):
                denied = _operator_only(identity)
                if denied is not None:
                    self._audit_preauth_denial(method, route, 403)
                    self._write(denied)
                    return False
            if identity is None and authorization is None and allow_unauthenticated_demo:
                return True
            required_scope = _required_scope(method, route)
            auth_configured = bool(bearer_secret) or any((vault.resolve() / TOKENS_DIR).glob("*.json"))
            anonymous_read = (
                not auth_configured
                and not authorization
                and required_scope in UNAUTHENTICATED_SCOPES
            )
            if identity is None and anonymous_read:
                return True
            if identity is None:
                self._audit_preauth_denial(method, route, 401)
                self._write(ApiResponse(401, {"ok": False, "error": "unauthorized"}))
                return False
            if required_scope is not None and required_scope not in identity.scopes:
                self._audit_preauth_denial(method, route, 403)
                self._write(ApiResponse(403, {"ok": False, "error": "insufficient scope"}))
                return False
            return True

        def _audit_preauth_denial(self, method: str, route: str, status: int) -> None:
            if not _claim_denial_audit_slot(route, status):
                return
            event = {
                "surface": "api",
                "phase": "preauth",
                **request_metadata(method, route),
                "status": status,
                "decision": "denied",
                "identity": "anonymous",
                "identity_kind": "none",
            }
            try:
                # The HTTP worker owns this configured domain before request
                # admission. Credentials and request fields cannot select it;
                # an authorization denial must not require authorization to audit.
                with authority_context(vault, state):
                    append_audit(audit_log or default_audit_log(state), event)
            except (OSError, ReplicaAuthorityUnavailable) as exc:
                capture(exc, component="api", code="audit_denial")

        def log_message(self, format: str, *args: object) -> None:
            return

        def _handle(self, body: Any) -> None:
            self.diagnostic_trace = uuid.uuid4().hex
            trace_token = TRACE.set(self.diagnostic_trace)
            reported_token = REPORTED.set(None)
            try:
                response = handle_api_request(
                    method=self.command,
                    path=self.path,
                    body=body,
                    vault=vault,
                    state=state,
                    bearer_secret=bearer_secret,
                    authorization=self.headers.get("Authorization"),
                    mcp_profile=mcp_profile,
                    allow_unauthenticated_demo=allow_unauthenticated_demo,
                    audit_log=audit_log,
                    idempotency_key=self.headers.get("Idempotency-Key"),
                    delivery_routes=delivery_routes,
                    inspection_guard=inspection_guard,
                )
            except Exception as exc:  # noqa: BLE001 - never leak a traceback / crash the worker
                if REPORTED.get() is not exc:
                    capture(exc, component="api", code="http_boundary")
                response = ApiResponse(500, {"ok": False, "error": "internal error"})
                if self.command == "POST" and urlsplit(self.path).path == "/mcp":
                    response = _mcp_wire_failure(body, ApiResponse(500, {
                        "error": "internal error; mutation outcome may be uncertain; "
                                 "reconciliation required before retry; nothing retried",
                    }), code=-32603)
            finally:
                TRACE.reset(trace_token)
                REPORTED.reset(reported_token)
            self._write(response)

        def _write(self, response: ApiResponse) -> None:
            if isinstance(response.body, dict):
                data = response.to_json().encode("utf-8")
            else:
                data = response.body.encode("utf-8")
            try:
                self.send_response(response.status)
                self.send_header("Content-Type", response.content_type)
                self.send_header("X-AMC-Trace-ID", getattr(self, "diagnostic_trace", uuid.uuid4().hex))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Cache-Control", "no-store")
                self.send_header(
                    "Content-Security-Policy",
                    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
                )
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
                return

    return ArvyxApiHandler


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = MAX_SERVER_WORKERS
    request_lifetime_seconds = 30

    def get_request(self):
        request, address = super().get_request()
        # Installed before BaseHTTPRequestHandler reads even the request line.
        request.settimeout(self.request_lifetime_seconds)
        return request, address

    def __init__(self, *args: Any, max_workers: int = MAX_SERVER_WORKERS, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._worker_slots = threading.BoundedSemaphore(max_workers)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._worker_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._worker_slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        # An idle timeout alone can be renewed forever by a slow byte stream.
        # Shutdown interrupts buffered header/body reads even while bytes arrive.
        def expire():
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # Already closed by normal completion.

        deadline = threading.Timer(self.request_lifetime_seconds, expire)
        deadline.daemon = True
        deadline.start()
        try:
            super().process_request_thread(request, client_address)
        finally:
            deadline.cancel()
            deadline.join()
            self._worker_slots.release()


def serve_api(
    host: str,
    port: int,
    vault: Path,
    state: Path,
    bearer_secret: str | None = None,
    mcp_profile: str = "read-only",
    allow_unauthenticated_demo: bool = False,
    audit_log: Path | None = None,
    delivery_routes: Path | None = None,
) -> None:
    if delivery_routes is None:
        raise ValueError("--delivery-routes is required")
    if not bearer_secret and not _is_loopback_host(host):
        raise ValueError("refusing to bind non-loopback host without --auth-env")
    if allow_unauthenticated_demo and not _is_loopback_host(host):
        raise ValueError("--allow-unauthenticated-demo is loopback-only")
    server = BoundedThreadingHTTPServer(
        (host, port),
        make_handler(
            vault=vault,
            state=state,
            bearer_secret=bearer_secret,
            mcp_profile=mcp_profile,
            allow_unauthenticated_demo=allow_unauthenticated_demo,
            audit_log=audit_log,
            delivery_routes=delivery_routes,
            inspection_guard=InspectionGuard(),
        ),
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()


def _optional_float(value: object) -> float | None:
    if value is None or value == "":
        return None
    import math

    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ValueError("recency_half_life_days must be a finite number")
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("recency_half_life_days must be a finite number") from exc
    if not math.isfinite(result):
        raise ValueError("recency_half_life_days must be a finite number")
    return result


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _query_string(query: dict[str, list[str]], key: str) -> str | None:
    values = query.get(key, [])
    if not values:
        return None
    return _optional_string(values[-1])


def _query_positive_int(query: dict[str, list[str]], key: str) -> int | None:
    value = _query_string(query, key)
    if value is None:
        return None
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"{key} must be an integer") from exc
    if parsed < 1:
        raise ValueError(f"{key} must be greater than zero")
    return parsed


def _required_scope(method: str, route: str) -> str | None:
    if route in PUBLIC_PATHS:
        return None
    if route == "/mcp":
        return None  # enforced per tool via tools_for_scopes
    if route.startswith("/replica/"):
        return SCOPE_REPLICA_READ
    if route.startswith("/secret/"):
        return SCOPE_SECRET_RESOLVE
    if route.startswith("/audit/"):
        return SCOPE_CONTROL_READ
    if route == "/control-plane":
        return SCOPE_CONTROL_READ
    if route == "/memory/recall":
        return SCOPE_MEMORY_READ
    if route == "/memory/session" and method == "POST":
        return SCOPE_SESSION_WRITE
    if route == "/memory/session":
        return SCOPE_SESSION_READ
    if route in {"/memory/suggest", "/memory/suggest-batch", "/memory/pending", "/schemas/memory-suggest-batch"}:
        return SCOPE_MEMORY_SUGGEST
    if route in {"/memory/refine", "/memory/refining"}:
        return SCOPE_MEMORY_REFINE
    if route in {"/memory/promote", "/memory/reject", "/memory/forget", "/memory/restore"}:
        return SCOPE_MEMORY_CURATE
    if route == "/deliveries" or route.startswith("/deliveries/"):
        return SCOPE_CONTROL_DELIVERY
    if method == "GET":
        return SCOPE_CONTROL_READ
    return SCOPE_CONTROL_WRITE


def _actor(identity: Identity | None, body_value: object, default: str) -> str:
    if identity is not None and identity.binds_actor:
        return identity.agent_id
    value = str(body_value).strip() if body_value is not None else ""
    if not value and not default:
        raise ValueError("explicit author/owner identity is required for an unbound write")
    return value or default


def _is_loopback_host(host: str) -> bool:
    return host in {"127.0.0.1", "localhost", "::1"}


def _thread_target_query(query: dict[str, list[str]]) -> str | None:
    # canonical key is "target"; "agent" stays as a legacy alias
    return _query_string(query, "target") or _query_string(query, "agent")


def _authoritative_delivery_document(delivery_routes: Path | None) -> RouteDocument:
    """Load the current route document for irreversible operator delivery actions."""
    if delivery_routes is None:
        raise ValueError("authoritative delivery route configuration is required")
    try:
        document = load_route_document(delivery_routes)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("authoritative delivery route configuration is unavailable or invalid") from exc
    if not document.routes:
        raise ValueError("authoritative delivery route configuration is empty")
    return document


def _authoritative_delivery_targets(delivery_routes: Path | None) -> set[str]:
    """Load current route IDs for irreversible operator delivery actions."""
    return set(_authoritative_delivery_document(delivery_routes).routes)


def _is_retirement_route(route: str) -> bool:
    return (re.fullmatch(r"/(?:threads|deliveries)/[^/]+/retire", route) is not None
            or re.fullmatch(r"/operator-(?:archive|alert-dismissal)/[^/]+", route) is not None)


def _operator_only(identity: Identity | None) -> ApiResponse | None:
    if identity is not None and identity.kind == "operator":
        return None
    return ApiResponse(403, {"ok": False, "error": "operator identity required for delivery operations"})


def _dead_letter_summary(
    item: OutboxItem, *, configured_targets: set[str] | None = None
) -> dict[str, object]:
    if item.payload.get("delivery_mode") == EXECUTION_WAKE_MODE:
        replayable = False
        replay_blocked_reason = (
            "execution wakes are redelivered only by the execution lineage; replay the execution"
        )
    elif configured_targets is None:
        replayable = False
        replay_blocked_reason = "route configuration unavailable"
    elif item.target in configured_targets:
        replayable = True
        replay_blocked_reason = ""
    else:
        replayable = False
        replay_blocked_reason = "target is not in the authoritative route map"
    return {
        "id": item.id,
        "subject_id": item.subject_id,
        "target": item.target,
        "epoch": item.epoch,
        "status": item.status,
        "attempts": item.attempts,
        "failures": item.failures,
        "created_at": item.created_at,
        "updated_at": item.updated_at,
        "failure_detail": item.failure_detail,
        "resolution_category": item.resolution_category,
        "prior_resolution_category": item.prior_resolution_category,
        "resolved_by": item.resolved_by,
        "resolved_at": item.resolved_at,
        "resolution_detail": item.resolution_detail,
        "replayable": replayable,
        "replay_blocked_reason": replay_blocked_reason,
    }


def _thread_scope(identity: Identity | None, requested: str | None) -> tuple[str | None, ApiResponse | None]:
    """Constrain identity-bound agents to their own thread inbox.

    Operator/global callers pass through unchanged (no target means all
    threads). An identity-bound agent defaults to its own inbox, and an
    explicit foreign target is rejected rather than silently coerced so
    client bugs surface instead of hiding.
    """
    if identity is None or not identity.binds_actor:
        return requested, None
    if requested and not same_agent_identity(requested, identity.agent_id):
        return None, ApiResponse(
            403,
            {
                "ok": False,
                "error": f"identity {identity.agent_id} may only access its own threads (requested target: {requested})",
            },
        )
    return identity.agent_id, None


def _deny_foreign_thread_mutation(identity: Identity | None, state: Path, thread_id: str) -> ApiResponse | None:
    """Identity-bound agents may only ack/done threads targeted to them.

    An unknown thread id falls through so the domain raises its usual
    'unknown thread' error; operator/global callers may mutate any thread.
    """
    if identity is None or not identity.binds_actor:
        return None
    thread = next((item for item in list_thread_inbox(state=state).threads if item.id == thread_id), None)
    if thread is not None and not same_agent_identity(thread.target, identity.agent_id):
        return ApiResponse(
            403,
            {
                "ok": False,
                "error": (
                    f"thread {thread_id} targets {thread.target}; "
                    f"identity {identity.agent_id} may only ack/done its own threads"
                ),
            },
        )
    return None


def _handoff_list(state: Path, query: dict[str, list[str]]) -> dict[str, Any]:
    status = _query_string(query, "status")
    to_agent = _query_string(query, "to_agent")
    handoffs = list_handoffs(state=state, status=status).handoffs
    if to_agent:
        handoffs = [handoff for handoff in handoffs if handoff.to_agent == to_agent]
    return {"handoffs": [handoff.to_dict() for handoff in handoffs]}


def _bound_work_cards(cards: list[dict[str, object]], limit: int) -> list[dict[str, object]]:
    ordered = sorted(
        cards,
        key=lambda card: (str(card["updated_at"]), str(card["kind"]), str(card["id"])),
        reverse=True,
    )
    current = [card for card in ordered if card["lane"] not in {"done", "retired"}]
    history = [card for card in ordered if card["lane"] in {"done", "retired"}]
    return (current + history)[:limit]


def _workload_by_agent(cards: list[dict[str, object]]) -> tuple[dict[str, dict[str, int | bool]], dict[str, str]]:
    work_by_agent: dict[str, dict[str, int | bool]] = {}
    latest_by_agent: dict[str, str] = {}
    for card in cards:
        owner = str(card["owner"])
        load = work_by_agent.setdefault(
            owner,
            {"queued": 0, "active": 0, "review": 0, "done": 0, "retired": 0, "current": 0, "total": 0, "bounded": False},
        )
        lane = str(card["lane"])
        load[lane] = int(load[lane]) + 1
        if lane not in {"done", "retired"}:
            load["current"] = int(load["current"]) + 1
        load["total"] = int(load["total"]) + 1
        updated_at = str(card.get("updated_at", ""))
        if updated_at > latest_by_agent.get(owner, ""):
            latest_by_agent[owner] = updated_at
    return work_by_agent, latest_by_agent


def _continuation_by_agent(
    threads: list[Any],
    *,
    now: datetime,
    stale_seconds: int = CONTINUATION_STALE_SECONDS,
) -> dict[str, dict[str, object]]:
    """Project bounded ACK-to-progress health without exposing thread bodies."""
    grouped: dict[str, list[dict[str, object]]] = {}
    for thread in threads:
        if not thread.pending or thread.status not in {"acked", "acknowledged"}:
            continue
        progress_at = str(thread.latest_at or thread.acked_at or "")
        age = _health_age(now, progress_at)
        stale = age is None or age >= stale_seconds
        grouped.setdefault(str(thread.target), []).append({
            "id": str(thread.id),
            "type": str(thread.type),
            "status": str(thread.status),
            "acked_at": str(thread.acked_at or ""),
            "last_progress_at": progress_at,
            "progress_age_seconds": age,
            "stale": stale,
        })
    projected: dict[str, dict[str, object]] = {}
    for agent_id, subjects in grouped.items():
        ordered = sorted(
            subjects,
            key=lambda subject: (str(subject["last_progress_at"]), str(subject["id"])),
        )
        stale_count = sum(1 for subject in ordered if subject["stale"])
        ages = [
            age for subject in ordered
            if isinstance((age := subject["progress_age_seconds"]), int)
        ]
        projected[agent_id] = {
            "state": "stale" if stale_count else "active",
            "active_count": len(ordered),
            "stale_count": stale_count,
            "oldest_progress_age_seconds": max(ages) if ages else None,
            "stale_after_seconds": stale_seconds,
            "subjects": ordered[:20],
            "subjects_truncated": len(ordered) > 20,
        }
    return projected


def _fleet_verdict(
    state: Path,
    *,
    delivery: dict[str, Any],
    continuation: dict[str, Any],
    delivery_routes: Path | None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Compose the fail-closed headline fleet verdict.

    An empty pending inbox and an empty outbox are not proof of health: the
    durable execution queue, the watchdog posture, and route configuration are
    folded in so "no work in flight" and "healthy" stay distinguishable. Any
    actionable red layer makes the whole verdict red; softer signals degrade
    it to amber; green means every layer affirmatively reported clean.
    """
    red: list[str] = []
    amber: list[str] = []
    execution_health: dict[str, Any] = {}
    try:
        capable = _authoritative_delivery_targets(delivery_routes)
    except ValueError:
        capable = None
    if capable is None:
        red.append("route_configuration_unavailable")
    else:
        execution_health = queue_health(state, execution_capable_targets=capable, now=now)
        if execution_health["acked_without_live_execution_count"]:
            red.append("acked_without_live_execution")
        if execution_health["dead_lettered_count"]:
            red.append("dead_lettered_executions")
        if execution_health["held_count"]:
            red.append("held_executions")
        if execution_health["leased_without_recent_heartbeat_count"]:
            amber.append("leased_without_recent_heartbeat")
    if not delivery.get("ok", False):
        red.append("delivery_attention")
    watchdog = project_watchdog_tick(state)
    watchdog_age = _health_age(now or datetime.now(timezone.utc), str(watchdog.get("last_tick_at", "")))
    if not watchdog.get("initialized"):
        # No watchdog tick means the fleet is flying without its detection
        # loop; that is degraded even when every queue currently looks clean.
        amber.append("watchdog_uninitialized")
    elif watchdog_age is None or watchdog_age > WATCHDOG_TICK_STALE_SECONDS:
        # Ticks are coalesced, but one is recorded at least every heartbeat; three
        # missed heartbeats means the detection loop itself has stopped.
        amber.append("watchdog_stale")
    if watchdog.get("initialized") and watchdog.get("attention"):
        # The watchdog saw something the queue counters alone cannot express
        # (unreachable targets, receipt-less delivered wakes). The next clean
        # tick clears it.
        amber.append("watchdog_attention")
    if continuation.get("stale_count"):
        amber.append("stale_continuations")
    verdict = "red" if red else ("amber" if amber else "green")
    return {
        "verdict": verdict,
        "red": red,
        "amber": amber,
        "execution": execution_health,
        "watchdog": watchdog,
    }


def _control_plane(
    vault: Path, state: Path, delivery_routes: Path | None = None
) -> dict[str, Any]:
    """Build a bounded fleet projection without exposing memory content."""
    now = datetime.now(timezone.utc)
    events = read_events(state)
    tasks = list_tasks(state=state, events=events).tasks
    handoffs = list_handoffs(state=state, events=events).handoffs
    threads = list_thread_inbox(state=state, events=events).threads
    continuations_by_agent = _continuation_by_agent(threads, now=now)
    cards: list[dict[str, object]] = []
    for task in tasks:
        cards.append({
            "id": task.id,
            "kind": "task",
            "title": task.title,
            "owner": task.owner,
            "source_status": task.status,
            "status": task.status,
            "lane": task.status if task.status in {"done", "retired"} else "queued",
            "retirement": task.retirement,
            "created_at": task.created_at,
            "updated_at": task.updated_at,
        })
    handoff_lanes = {"open": "queued", "accepted": "active", "reviewed": "review", "completed": "done", "retired": "retired"}
    for handoff in handoffs:
        cards.append({
            "id": handoff.id,
            "kind": "handoff",
            "title": handoff.title,
            "owner": handoff.to_agent,
            "actor": handoff.from_agent,
            "source_status": handoff.status,
            "status": handoff.status,
            "lane": handoff_lanes.get(handoff.status, "queued"),
            "retirement": handoff.retirement,
            "created_at": handoff.created_at,
            "updated_at": handoff.updated_at,
        })
    for thread in threads:
        if thread.type not in ACTIONABLE_THREAD_TYPES:
            continue
        lane = thread.status if thread.status in {"done", "retired"} else ("active" if thread.status in {"acked", "acknowledged"} else "queued")
        cards.append({
            "id": thread.id,
            "kind": "thread",
            "thread_type": thread.type,
            "title": thread.title,
            "owner": thread.target,
            "actor": thread.actor,
            "source_status": thread.status,
            "status": thread.status,
            "lane": lane,
            "pending": thread.pending,
            "unread": thread.unread,
            "severity": thread.severity,
            "created_at": thread.created_at,
            "updated_at": thread.latest_at,
            "retirement": thread.retirement,
            "evidence": {
                "artifact": thread.evidence_artifact,
                "anchor": thread.evidence_anchor,
                "method": thread.evidence_method,
            },
        })
    all_cards = cards
    total_cards = len(all_cards)
    cards = _bound_work_cards(all_cards, limit=200)

    work_by_agent, latest_by_agent = _workload_by_agent(all_cards)
    blocker_rank = {"info": 0, "notice": 1, "warn": 2, "critical": 3, "unknown": 4}
    blockers_by_agent: dict[str, dict[str, Any]] = {}
    for thread in threads:
        if not thread.pending or thread.type != "blocker":
            continue
        raw_severity = str(thread.severity or "info").casefold()
        severity = raw_severity if raw_severity in blocker_rank else "unknown"
        blocker = blockers_by_agent.setdefault(thread.target, {"count": 0, "highest_severity": "info"})
        blocker["count"] = int(blocker["count"]) + 1
        if blocker_rank[severity] > blocker_rank.get(str(blocker["highest_severity"]), 0):
            blocker["highest_severity"] = severity

    registry_stats: dict[str, int] = {}
    agent_records = _registry_records(vault / "registry" / "agents", limit=100, stats=registry_stats)
    runtime_index = _registry_index(vault / "registry" / "runtimes", limit=200)
    machine_index = _registry_index(vault / "registry" / "machines", limit=200)
    agents: list[dict[str, object]] = []
    invalid_agent_ids = 0
    for record in agent_records:
        agent_id = str(record.get("id", "")).strip()
        if not re.fullmatch(r"[a-z0-9_-]{1,100}", agent_id):
            invalid_agent_ids += 1
            continue
        load = work_by_agent.get(
            agent_id,
            {"queued": 0, "active": 0, "review": 0, "done": 0, "retired": 0, "current": 0, "total": 0, "bounded": False},
        )
        blocker = blockers_by_agent.get(agent_id, {"count": 0, "highest_severity": "info"})
        status = ("blocked" if blocker["count"] else "active" if load["active"] or load["review"]
                  else "waiting" if load["queued"] else "idle")
        skills = record.get("skills")
        reported = isinstance(skills, list)
        skill_values: set[str] = set()
        if isinstance(skills, list):
            for skill in skills:
                value = skill if isinstance(skill, str) else (
                    skill.get("name") or skill.get("id") if isinstance(skill, dict) else None
                )
                if isinstance(value, str) and value.strip():
                    skill_values.add(value.strip()[:120])
        skill_items = sorted(skill_values)[:200]
        scopes = record.get("scopes")
        agents.append({
            "id": agent_id,
            "display_name": str(record.get("display_name", agent_id))[:120],
            "runtime": _registry_reference(runtime_index, record.get("runtime_id")),
            "machine": _registry_reference(machine_index, record.get("machine_id")),
            "scopes": sorted({scope[:120] for scope in scopes if isinstance(scope, str)})[:100]
            if isinstance(scopes, list) else [],
            "skills": {"reported": reported, "count": len(skill_items), "items": skill_items},
            "memory": _memory_footprint(vault / "agents" / agent_id),
            "presence": {"state": "registered", "source": "registry", "heartbeat_at": None},
            "work": load,
            "blockers": blocker,
            "continuation": continuations_by_agent.get(agent_id, {
                "state": "idle",
                "active_count": 0,
                "stale_count": 0,
                "oldest_progress_age_seconds": None,
                "stale_after_seconds": CONTINUATION_STALE_SECONDS,
                "subjects": [],
                "subjects_truncated": False,
            }),
            "status": status,
            "latest_activity_at": latest_by_agent.get(agent_id, ""),
            "dashboard": _dashboard_hints(record.get("dashboard")),
        })
    agents.sort(key=lambda agent: str(agent["id"]))
    continuation_active_counts: list[int] = []
    continuation_stale_counts: list[int] = []
    stale_agents: list[str] = []
    registered_agent_ids = {str(agent["id"]) for agent in agents}
    for agent_id, item in continuations_by_agent.items():
        if agent_id not in registered_agent_ids:
            continue
        active_count = item["active_count"]
        stale_count = item["stale_count"]
        if isinstance(active_count, int):
            continuation_active_counts.append(active_count)
        if isinstance(stale_count, int):
            continuation_stale_counts.append(stale_count)
            if stale_count > 0:
                stale_agents.append(agent_id)
    continuation_summary = {
        "active_count": sum(continuation_active_counts),
        "stale_count": sum(continuation_stale_counts),
        "stale_agents": sorted(stale_agents),
        "stale_after_seconds": CONTINUATION_STALE_SECONDS,
    }
    event_count = len(events)
    timestamps = [event.timestamp for event in events]
    first_timestamp = min(timestamps) if timestamps else None
    latest_at = max(timestamps) if timestamps else ""
    bounded_events = [_safe_control_event(event) for event in reversed(events[-100:])]
    delivery = _delivery_health(state, now=now)
    fleet = _fleet_verdict(
        state,
        delivery=delivery,
        continuation=continuation_summary,
        delivery_routes=delivery_routes,
        now=now,
    )
    return {
        "ok": True,
        "schema": "arvyx-control-plane/v1",
        "generated_at": now.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "source": {
            "event_count": event_count,
            "events": event_count,
            "first_timestamp": first_timestamp,
            "last_timestamp": latest_at,
            "freshness_seconds": _health_age(now, latest_at),
            "retention": "append-only-jsonl",
            "bounds": {
                "cards_total": total_cards,
                "cards_returned": len(cards),
                "cards_truncated": total_cards > len(cards),
                "agents_discovered": registry_stats.get("discovered", len(agent_records)),
                "agents_returned": len(agents),
                "agents_invalid": registry_stats.get("invalid", 0) + invalid_agent_ids,
                "agents_truncated": bool(registry_stats.get("truncated", 0)),
                "events_returned": len(bounded_events),
                "events_truncated": event_count > len(bounded_events),
            },
        },
        "cards": cards,
        "kanban": {lane: [card for card in cards if card["lane"] == lane] for lane in ("queued", "active", "review", "done", "retired")},
        "agents": agents,
        "continuation": continuation_summary,
        "events": bounded_events,
        "activity": _event_activity(events, now),
        "delivery": delivery,
        "fleet": fleet,
    }


def _registry_records(
    directory: Path,
    *,
    limit: int,
    stats: dict[str, int] | None = None,
) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    paths = sorted(directory.glob("*.json")) if directory.is_dir() else []
    invalid = 0
    for path in paths[:limit]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            invalid += 1
            continue
        if isinstance(value, dict):
            records.append(value)
        else:
            invalid += 1
    if stats is not None:
        stats.update(
            discovered=len(paths),
            invalid=invalid,
            truncated=int(len(paths) > limit),
        )
    return records


def _dashboard_hints(value: object) -> dict[str, object]:
    """Operator presentation hints from an agent registry record.

    The registry is operator-owned vault data, so this is where a deployment
    says which war-room desk an agent sits at and which agents to hide,
    without naming any agent in tracked code. Only a known desk preset and an
    explicit boolean ``hidden`` pass through; anything else is dropped.
    An explicit boolean ``squad`` puts the agent on the operator fleet surface.
    """
    hints: dict[str, object] = {"desk": None, "hidden": False, "squad": False}
    if isinstance(value, dict):
        desk = value.get("desk")
        if isinstance(desk, str) and desk in DASHBOARD_DESKS:
            hints["desk"] = desk
        hints["hidden"] = value.get("hidden") is True
        hints["squad"] = value.get("squad") is True
    return hints


def _registry_index(directory: Path, *, limit: int) -> dict[str, dict[str, object]]:
    return {
        str(record.get("id")): record
        for record in _registry_records(directory, limit=limit)
        if isinstance(record.get("id"), str)
    }


def _registry_reference(index: dict[str, dict[str, object]], value: object) -> dict[str, str]:
    item_id = str(value or "").strip()[:120]
    result = {"id": item_id, "display_name": item_id}
    if not item_id or not re.fullmatch(r"[A-Za-z0-9._-]{1,120}", item_id):
        return result
    record = index.get(item_id)
    if record is not None:
        result["display_name"] = str(record.get("display_name", item_id))[:120]
    return result


def _memory_footprint(directory: Path) -> dict[str, int]:
    documents = lines = byte_count = curated = raw = session = 0
    if directory.is_dir():
        for path in sorted(directory.rglob("*.md")):
            if not path.is_file() or path.is_symlink():
                continue
            try:
                relative = path.relative_to(directory)
                data = path.read_bytes()
            except (OSError, ValueError):
                continue
            documents += 1
            byte_count += len(data)
            lines += len(data.splitlines())
            if relative.name == "MEMORY.md":
                curated += 1
            if relative.name == "SESSION-STATE.md":
                session += 1
            if "raw" in relative.parts:
                raw += 1
    return {
        "documents": documents,
        "lines": lines,
        "bytes": byte_count,
        "curated_documents": curated,
        "raw_documents": raw,
        "session_documents": session,
    }


def _safe_control_event(event: ControlEvent) -> dict[str, object]:
    payload = event.payload if isinstance(event.payload, dict) else {}
    safe: dict[str, object] = {"id": event.id, "type": event.type, "subject_id": event.task_id,
                               "timestamp": event.timestamp}
    for key in (
        "actor", "owner", "target", "from_agent", "to_agent", "title", "status", "severity", "channel",
        "posted_by", "acked_by", "done_by", "reviewer", "completed_by",
    ):
        value = payload.get(key)
        if isinstance(value, (str, int, float, bool)):
            safe[key] = str(value)[:120]
    if "actor" not in safe:
        safe["actor"] = str(payload.get("owner") or payload.get("from_agent") or "")[:120]
    if "target" not in safe:
        safe["target"] = str(payload.get("target") or payload.get("to_agent") or "")[:120]

    principal_key = {
        "handoff.created": "from_agent",
        "handoff.accepted": "to_agent",
        "handoff.reviewed": "reviewer",
        "handoff.completed": "completed_by",
        "thread.created": "actor",
        "thread.message.posted": "posted_by",
        "thread.acknowledged": "acked_by",
        "thread.done": "done_by",
    }.get(event.type)
    performed_by = str(payload.get(principal_key) or "").strip()[:120] if principal_key else ""
    if performed_by:
        safe["performed_by"] = performed_by

    if event.type == "handoff.created" and performed_by:
        route_target = str(payload.get("to_agent") or "").strip()[:120]
        if route_target:
            safe["route_target"] = route_target
    elif event.type == "thread.created" and performed_by:
        route_target = str(payload.get("target") or "").strip()[:120]
        if route_target:
            safe["route_target"] = route_target
    elif event.type == "thread.message.posted" and performed_by:
        actor = str(payload.get("actor") or "").strip()[:120]
        target = str(payload.get("target") or "").strip()[:120]
        performed_fold = performed_by.casefold()
        route_target = target if performed_fold == actor.casefold() else actor if performed_fold == target.casefold() else ""
        if route_target:
            safe["route_target"] = route_target
    return safe


def _event_activity(events: list[ControlEvent], now: datetime) -> dict[str, list[dict[str, object]]]:
    end = now.replace(minute=0, second=0, microsecond=0)
    starts = [end - timedelta(hours=offset) for offset in range(11, -1, -1)]
    counts = [0] * 12
    event_type_counts: dict[str, int] = {}
    for event in events:
        event_type_counts[event.type] = event_type_counts.get(event.type, 0) + 1
        try:
            instant = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00")).astimezone(timezone.utc)
        except (AttributeError, ValueError):
            continue
        index = int((instant - starts[0]).total_seconds() // 3600)
        if 0 <= index < 12:
            counts[index] += 1
    buckets = [
        {
            "start": start.isoformat().replace("+00:00", "Z"),
            "label": start.strftime("%H:%M"),
            "count": counts[index],
        }
        for index, start in enumerate(starts)
    ]
    event_types = [
        {"type": event_type, "count": count}
        for event_type, count in sorted(event_type_counts.items(), key=lambda item: (-item[1], item[0]))[:20]
    ]
    return {"buckets": buckets, "event_types": event_types}


def _approval_effective_status(approval: Approval, now: datetime) -> str:
    # One definition, in the domain layer: the operator summary and the control
    # listing surfaces must not be able to disagree about what is still live.
    return approval_effective_status(approval, now)


def _operator_summary(
    state: Path,
    mcp_profile: str,
    vault: Path | None = None,
    query: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    query = query or {}
    tasks = list_tasks(state=state).tasks
    approvals = list_approvals(state=state).approvals
    handoffs = list_handoffs(state=state).handoffs
    messages = list_bus_messages(state=state).messages
    threads = list_thread_inbox(state=state).threads
    manifest = manifest_state(state)
    handoff_status = _query_string(query, "handoff_status")
    handoff_to_agent = _query_string(query, "handoff_to_agent")
    retain_events = _query_positive_int(query, "retain_events")
    handoff_limit = _query_positive_int(query, "handoff_limit") or 5
    handoff_sla_hours = _query_positive_int(query, "handoff_sla_hours") or 24
    filtered_handoffs = [handoff for handoff in handoffs if handoff.status == handoff_status] if handoff_status else handoffs
    if handoff_to_agent:
        filtered_handoffs = [handoff for handoff in filtered_handoffs if handoff.to_agent == handoff_to_agent]
    projection_retention = f"sqlite-events:last-{retain_events}" if retain_events is not None else "sqlite-events:configurable"
    now = datetime.now(timezone.utc)
    return {
        "ok": True,
        "service": "arvyx-control-api",
        "mcp_profile": mcp_profile,
        "mcp_tools": tools_for_profile(mcp_profile),
        "filters": {
            "handoff_status": handoff_status or "",
            "handoff_to_agent": handoff_to_agent or "",
            "handoff_limit": handoff_limit,
            "handoff_sla_hours": handoff_sla_hours,
            "retain_events": retain_events,
        },
        "store": {
            "source": {
                "events": manifest.events,
                "first_timestamp": manifest.first_timestamp,
                "last_timestamp": manifest.last_timestamp,
                "retention": manifest.retention,
                "sha256": manifest.sha256,
            },
            "projection": {
                "retention": projection_retention,
                "default": "sqlite-events:all",
                "bounded_by": "store sync --retain-events N",
            },
        },
        "counts": {
            "tasks": _count_by_status((task.status for task in tasks)),
            "approvals": _count_by_status((_approval_effective_status(approval, now) for approval in approvals)),
            "handoffs": _count_by_status((handoff.status for handoff in handoffs)),
            "bus_messages": {"total": len(messages)},
            "threads": _thread_counts(threads),
        },
        "handoff_queue": {
            "presets": _handoff_queue_presets(sla_hours=handoff_sla_hours),
            "workload": _handoff_workload(handoffs),
        },
        "memory_queue": _memory_queue(vault),
        "posture": _posture(vault=vault, mcp_profile=mcp_profile),
        "recent": {
            "tasks": [task.to_dict() for task in tasks[:5]],
            "approvals": [approval.to_dict() for approval in approvals[:5]],
            "handoffs": [
                _handoff_summary_item(handoff.to_dict(), now=now, sla_hours=handoff_sla_hours)
                for handoff in filtered_handoffs[:handoff_limit]
            ],
            "bus_messages": [message.to_dict() for message in messages[:5]],
            "threads": [
                thread.to_dict()
                for thread in sorted(threads, key=lambda thread: (thread.latest_at, thread.id), reverse=True)[:8]
            ],
        },
    }


def _thread_counts(threads: list[Thread]) -> dict[str, int]:
    counts = _count_by_status(thread.status for thread in threads)
    counts["pending"] = sum(1 for thread in threads if thread.pending)
    counts["unread"] = sum(1 for thread in threads if thread.unread)
    return counts


def _memory_queue(vault: Path | None) -> dict[str, Any]:
    """Count governed-write items awaiting attention, by lane and project."""
    by_project: dict[str, dict[str, int]] = {}
    total_pending = 0
    total_refining = 0
    projects_root = (vault / "projects") if vault is not None else None
    if projects_root is not None and projects_root.is_dir():
        for project_dir in sorted(projects_root.iterdir()):
            if not project_dir.is_dir():
                continue
            pending = _count_lane(project_dir, PENDING_LANE)
            refining = _count_lane(project_dir, REFINING_LANE)
            if pending or refining:
                by_project[project_dir.name] = {"pending": pending, "refining": refining}
            total_pending += pending
            total_refining += refining
    return {"pending": total_pending, "refining": total_refining, "by_project": by_project}


def _count_lane(project_dir: Path, lane: str) -> int:
    lane_dir = project_dir / lane
    return len(list(lane_dir.glob("*.md"))) if lane_dir.is_dir() else 0


def _posture(vault: Path | None, mcp_profile: str) -> dict[str, Any]:
    """Provider / session / fallback / hardening posture for the operator.

    Audit-chain status is deliberately NOT here: it lives on the dedicated
    audit panel (GET /audit/events). Recomputing it on every /summary meant a
    full audit-log read on the dashboard hot path and duplicated that panel.
    """
    session_agents = 0
    if vault is not None and (vault / "agents").is_dir():
        session_agents = sum(1 for _ in (vault / "agents").glob("*/SESSION-STATE.md"))
    fallback: dict[str, Any] = {"role": "unknown"}
    if vault is not None:
        status = replica_status(vault).to_dict()
        status["role"] = "replica" if status.get("is_replica") else "primary"
        fallback = status
    return {
        "provider": {"mcp_profile": mcp_profile, "mcp_tools": len(tools_for_profile(mcp_profile))},
        "session": {"agents_with_state": session_agents},
        "fallback": fallback,
        "hardening": {
            "secret_redaction": True,
            "unauthenticated_scopes": sorted(UNAUTHENTICATED_SCOPES),
        },
    }


def _delivery_health(
    state: Path,
    *,
    now: datetime | None = None,
    stale_after_seconds: int = 300,
    work_grace_seconds: int = 60,
) -> dict[str, object]:
    current = now or datetime.now(timezone.utc)
    items = list(project_outbox(state).values())
    counts = _count_by_status(item.status for item in items)

    dead = [item for item in items if item.status == "dead_lettered"]
    ambiguous_deliveries = [item for item in items if item.status == "ambiguous_delivery"]
    replayed_keys = {
        (item.subject_id, item.target, item.payload_hash, item.epoch - 1)
        for item in items
        if item.epoch > 0
    }
    # A dead letter stops being actionable through either recovery lane:
    # an exact replay (epoch+1 sibling) or an explicit append-only
    # classification (outbox.resolved). Neither erases the evidence.
    unresolved_dead_letters = sum(
        (
            not item.resolution_category
            or item.resolution_category == "ambiguous_not_delivered"
        )
        and (item.subject_id, item.target, item.payload_hash, item.epoch) not in replayed_keys
        for item in dead
    )

    materialization = project_materialization_checkpoint(state)
    materialization_age = _health_age(current, str(materialization["advanced_at"]))
    materialization["age_seconds"] = materialization_age
    # An idle source log legitimately has an old checkpoint. Dispatcher
    # heartbeat/result health is the liveness authority; checkpoint age remains
    # informational for operators.
    materialization["stale"] = False

    tick = project_dispatcher_tick(state)
    tick_age = _health_age(current, str(tick["last_tick_at"]))
    configured_targets = set(str(target) for target in tick.pop("configured_targets"))
    dispatcher = {
        **tick,
        "age_seconds": tick_age,
        "stale": tick_age is None or tick_age > stale_after_seconds,
        "configured_target_count": len(configured_targets),
    }

    active = [item for item in items if item.status in {"pending", "leased"}]
    aged = [(item, _health_age(current, item.created_at)) for item in active]
    aged = [(item, age) for item, age in aged if age is not None and age > work_grace_seconds]
    aged_pending = [(item, age) for item, age in aged if item.failures == 0]
    aged_retrying = [(item, age) for item, age in aged if item.failures > 0]
    unroutable = [(item, age) for item, age in aged if item.target not in configured_targets]
    work = {
        "grace_seconds": work_grace_seconds,
        "backlog_count": len(active),
        "aged_backlog_count": len(aged),
        "oldest_backlog_age_seconds": max((age for _, age in aged), default=0),
        "aged_pending_count": len(aged_pending),
        "oldest_pending_age_seconds": max((age for _, age in aged_pending), default=0),
        "aged_retrying_count": len(aged_retrying),
        "oldest_retrying_age_seconds": max((age for _, age in aged_retrying), default=0),
        "unroutable_count": len(unroutable),
        "oldest_unroutable_age_seconds": max((age for _, age in unroutable), default=0),
        "unroutable_targets": sorted({item.target for item, _ in unroutable}),
    }

    attention: list[str] = []
    if unresolved_dead_letters:
        attention.append("unresolved_dead_letters")
    if ambiguous_deliveries:
        attention.append("ambiguous_delivery")
    if not materialization["initialized"]:
        attention.append("materialization_uninitialized")
    if not dispatcher["initialized"]:
        attention.append("dispatcher_uninitialized")
    elif dispatcher["stale"]:
        attention.append("dispatcher_stale")
    elif not dispatcher["healthy"]:
        attention.append("dispatcher_unhealthy")
    if dispatcher.get("skipped_unconfigured_targets"):
        attention.append("materialization_skipped_unconfigured_targets")
    if aged_pending:
        attention.append("aged_pending")
    if aged_retrying:
        attention.append("aged_retrying")
    if unroutable:
        attention.append("unroutable_pending")
    return {
        "ok": not attention,
        "attention": attention,
        "counts": counts,
        "unresolved_dead_letters": unresolved_dead_letters,
        "ambiguous_delivery_count": len(ambiguous_deliveries),
        "materialization": materialization,
        "dispatcher": dispatcher,
        "work": work,
    }


def _health_age(now: datetime, timestamp: str) -> int | None:
    if not timestamp:
        return None
    try:
        instant = datetime.fromisoformat(timestamp[:-1] + "+00:00" if timestamp.endswith("Z") else timestamp)
    except ValueError:
        return None
    if instant.tzinfo is None:
        return None
    return max(0, int((now - instant.astimezone(timezone.utc)).total_seconds()))


def _count_by_status(values: object) -> dict[str, int]:
    counts: dict[str, int] = {"total": 0}
    for value in values:
        key = str(value)
        counts[key] = counts.get(key, 0) + 1
        counts["total"] += 1
    return counts


def _handoff_queue_presets(sla_hours: int) -> list[dict[str, Any]]:
    return [
        {
            "id": "operator-open",
            "label": "Operator open",
            "params": {
                "handoff_status": "open",
                "handoff_to_agent": "operator",
                "handoff_limit": 10,
                "handoff_sla_hours": sla_hours,
            },
        },
        {
            "id": "operator-review",
            "label": "Operator review",
            "params": {
                "handoff_status": "accepted",
                "handoff_to_agent": "operator",
                "handoff_limit": 10,
                "handoff_sla_hours": sla_hours,
            },
        },
        {
            "id": "ready-to-complete",
            "label": "Ready to complete",
            "params": {
                "handoff_status": "reviewed",
                "handoff_limit": 10,
                "handoff_sla_hours": sla_hours,
            },
        },
    ]


def _handoff_workload(handoffs: object) -> dict[str, list[dict[str, Any]]]:
    assignees: dict[str, dict[str, int]] = {}
    reviewers: dict[str, dict[str, int]] = {}
    for handoff in handoffs:
        assignee = getattr(handoff, "to_agent", "") or "unassigned"
        assignee_counts = assignees.setdefault(assignee, {"total": 0})
        assignee_counts["total"] += 1
        assignee_counts[handoff.status] = assignee_counts.get(handoff.status, 0) + 1

        reviewer = getattr(handoff, "reviewer", "") or ""
        if reviewer:
            reviewer_counts = reviewers.setdefault(reviewer, {"total": 0})
            reviewer_counts["total"] += 1
            reviewer_counts[handoff.status] = reviewer_counts.get(handoff.status, 0) + 1
            decision = getattr(handoff, "review_decision", "") or "undecided"
            reviewer_counts[decision] = reviewer_counts.get(decision, 0) + 1

    return {
        "assignees": _workload_rows(assignees, "agent"),
        "reviewers": _workload_rows(reviewers, "reviewer"),
    }


def _workload_rows(counts_by_name: dict[str, dict[str, int]], name_key: str) -> list[dict[str, Any]]:
    rows = [{name_key: name, **counts} for name, counts in counts_by_name.items()]
    return sorted(rows, key=lambda row: (-int(row.get("total", 0)), str(row.get(name_key, ""))))


def _handoff_summary_item(handoff: dict[str, Any], now: datetime, sla_hours: int) -> dict[str, Any]:
    age_seconds = _age_seconds(str(handoff.get("created_at", "")), now=now)
    age_hours = round(age_seconds / 3600, 2)
    if handoff.get("status") in {"completed", "retired"}:
        sla_status = "closed"
    elif age_hours >= sla_hours:
        sla_status = "breached"
    else:
        sla_status = "within"
    return {
        **handoff,
        "age_hours": age_hours,
        "sla_hours": sla_hours,
        "sla_status": sla_status,
    }


def _age_seconds(timestamp: str, now: datetime) -> int:
    if not timestamp:
        return 0
    try:
        created_at = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return 0
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    return max(0, int((now - created_at).total_seconds()))


def _dashboard_html() -> str:
    return resources.files("arvyx_control").joinpath("static/index.html").read_text(encoding="utf-8")
