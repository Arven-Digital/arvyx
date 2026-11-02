"""Canonical, non-authoritative metadata for audit and operation storage.

Never feed these labels back into routing, scope checks or request hashing.
Dynamic route targets remain distinct in journal actions through a full digest.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .mcp import TOOL_NAMES

HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"})
MCP_METHODS = frozenset({"initialize", "ping", "tools/list", "tools/call"})
KNOWN_TOOLS = frozenset(TOOL_NAMES)
STATIC_ROUTES = frozenset({
    "/", "/dashboard", "/health", "/summary", "/control-plane", "/digest", "/audit/events",
    "/secret/resolve", "/secret/brokers", "/replica/manifest", "/replica/file", "/replica/state", "/mcp",
    "/control/transcripts", "/memory/recall", "/memory/session", "/memory/suggest", "/memory/suggest-batch",
    "/schemas/memory-suggest-batch", "/memory/pending", "/memory/refine", "/memory/refining",
    "/memory/promote", "/memory/reject", "/memory/forget", "/memory/restore", "/tasks", "/approvals",
    "/approvals/request", "/handoffs", "/threads", "/threads/pending", "/threads/read-all",
    "/deliveries/health", "/deliveries/dead-letter", "/deliveries", "/fleet/health", "/executions/health",
    "/executions", "/bus", "/diagnostics", "/diagnostics/status", "/diagnostics/feed", "/diagnostics/client",
})
# Match the routing grammar, not a permissive pathname character allowlist.
# A matched target is always removed; its spelling is never persisted.
DYNAMIC_ROUTES = (
    (r"/control/transcripts/[^/]+", "/control/transcripts/{id}"),
    (r"/tasks/[^/]+/done", "/tasks/{id}/done"),
    (r"/approvals/[^/]+/(approve|consume)", "/approvals/{id}/{action}"),
    (r"/handoffs/[^/]+/(accept|review|complete)", "/handoffs/{id}/{action}"),
    (r"/threads/[^/]+/(ack|done|retire)", "/threads/{id}/{action}"),
    (r"/operator-(archive|alert-dismissal)/[^/]+", "/operator-{action}/{id}"),
    (r"/deliveries/[^/]+/(retire|replay|resolve|cancel|receipt)", "/deliveries/{id}/{action}"),
    (r"/decisions/decision_[0-9a-f]{24}/answer", "/decisions/{id}/answer"),
    (r"/executions/[^/]+/(replay|hold|close|events|cancel|resume|steer|steer-acknowledgement|heartbeat)", "/executions/{id}/{action}"),
    (r"/executions/[^/]+", "/executions/{id}"),
    (r"/diagnostics/groups/[0-9a-f]{64}", "/diagnostics/groups/{id}"),
)


def metadata_digest(value: object) -> str:
    # Strings retain their complete identity, including surrogate code points.
    # Non-string JSON values have a distinct encoding from string inputs.
    encoded = ("str:" + value if isinstance(value, str) else
               "json:" + json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    return hashlib.sha256(encoded.encode("utf-8", errors="surrogatepass")).hexdigest()


def known_or_digest(value: object, known: frozenset[str]) -> str:
    return value if isinstance(value, str) and value in known else "unknown:sha256:" + metadata_digest(value)


def route_metadata(route: str) -> str:
    if route in STATIC_ROUTES:
        return route
    for pattern, template in DYNAMIC_ROUTES:
        match = re.fullmatch(pattern, route)
        if match:
            return template.replace("{action}", match.group(1)) if "{action}" in template else template
    return "unknown:sha256:" + metadata_digest(route)


def request_metadata(method: str, route: str, body: dict[str, Any] | None = None) -> dict[str, str]:
    metadata = {"method": known_or_digest(method, HTTP_METHODS), "route": route_metadata(route)}
    if route == "/mcp":
        body = body or {}
        raw_params = body.get("params")
        params = raw_params if isinstance(raw_params, dict) else {}
        metadata["mcp_method"] = known_or_digest(body.get("method", ""), MCP_METHODS)
        if "name" in params:
            metadata["tool"] = known_or_digest(params["name"], KNOWN_TOOLS)
    return metadata


def legacy_journal_action(method: str, route: str) -> str | None:
    """Lookup-only spelling for a recognized dynamic route; never persist it.

    Static routes and known MCP tools already retain their historical actions.
    Unknown metadata is deliberately ineligible for a raw compatibility lookup.
    """
    safe_route = route_metadata(route)
    if method in HTTP_METHODS and safe_route != route and not safe_route.startswith("unknown:sha256:"):
        return f"{method}:{route}"
    return None


def journal_action(method: str, route: str, body: dict[str, Any]) -> str:
    metadata = request_metadata(method, route, body)
    if route == "/mcp":
        # Preserve existing known-tool action identity, including malformed method
        # envelopes; this helper must not redefine the idempotency policy.
        raw_params = body.get("params")
        params = raw_params if isinstance(raw_params, dict) else {}
        return "MCP:" + known_or_digest(params.get("name", "unknown"), KNOWN_TOOLS)
    safe_route = metadata["route"]
    if safe_route != route and not safe_route.startswith("unknown:sha256:"):
        safe_route += ":sha256:" + metadata_digest(route)
    return metadata["method"] + ":" + safe_route
