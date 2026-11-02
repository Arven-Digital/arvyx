"""Transport-independent request handling for the read-only API.

``handle_request`` is the whole contract: method gate, route lookup,
fail-closed bearer authentication through ``arvyx_control.auth``, strict
query validation, view construction, and output sanitization. The HTTP
server in ``server.py`` only moves bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from arvyx_control.diagnostics import capture
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from arvyx_control.auth import SCOPE_CONTROL_READ, resolve_identity

from . import API_VERSION, SCHEMA, SERVICE, __version__
from . import views
from .views import LANES, CARD_KINDS, Param, QueryError, Sources

ALLOWED_METHODS = ("GET",)
REQUIRED_SCOPE = SCOPE_CONTROL_READ
# "Bearer " plus the longest operator secret arvyx_control accepts.
MAX_AUTHORIZATION_CHARS = 4200
AUTH_REALM = 'Bearer realm="arvyx-control-center", scope="control.read"'

ViewBuilder = Callable[[Sources, Mapping[str, Any]], dict[str, Any]]


@dataclass(frozen=True)
class AppConfig:
    sources: Sources
    # The operator shared secret, when configured; never logged or echoed.
    bearer_secret: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class Response:
    status: int
    body: dict[str, Any]
    headers: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class Route:
    path: str
    view: str
    summary: str
    build: ViewBuilder
    public: bool = False
    params: tuple[Param, ...] = ()

    def describe(self) -> dict[str, Any]:
        return {
            "method": "GET",
            "path": self.path,
            "view": self.view,
            "summary": self.summary,
            "auth": "none" if self.public else "bearer",
            "scope": None if self.public else REQUIRED_SCOPE,
            "params": [param.describe() for param in self.params],
        }


def _health(sources: Sources, params: Mapping[str, Any]) -> dict[str, Any]:
    # Liveness only: deliberately reads no vault, event, or audit state, so
    # the one unauthenticated data route discloses nothing about the fleet.
    return {
        "ok": True,
        "schema": SCHEMA,
        "service": SERVICE,
        "version": __version__,
        "api_version": API_VERSION,
        "read_only": True,
        "generated_at": views.stamp(views.utc_now()),
    }


def _route_index(sources: Sources, params: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "ok": True,
        "schema": SCHEMA,
        "service": SERVICE,
        "api_version": API_VERSION,
        "read_only": True,
        "generated_at": views.stamp(views.utc_now()),
        "methods": list(ALLOWED_METHODS),
        "auth": {
            "scheme": "bearer",
            "required_scope": REQUIRED_SCOPE,
            "public_routes": [route.path for route in ROUTES if route.public],
        },
        "limits": {"max_string_chars": views.MAX_STRING_CHARS, "max_nested_list_items": views.MAX_NESTED_LIST_ITEMS},
        "routes": [route.describe() for route in ROUTES],
    }


def _limit(default: int, maximum: int, noun: str) -> Param:
    return Param("limit", "integer", f"Maximum {noun} returned.", default=default, maximum=maximum)


ROUTES: tuple[Route, ...] = (
    Route("/v1/health", "health", "Liveness only; reads no state.", _health, public=True),
    Route("/v1/routes", "routes", "Machine-readable index of every route, its auth, and its parameters.",
          _route_index, public=True),
    Route("/v1/command-deck", "command-deck",
          "Fleet verdict, delivery posture, lane pressure, lifecycle counts, squad and memory-queue totals.",
          views.command_deck),
    Route("/v1/work-board", "work-board",
          "Queued/active/review/done/retired lanes of tasks, handoffs, and actionable threads.",
          views.work_board,
          params=(
              Param("lane", "enum", "Return only this lane.", choices=LANES),
              Param("owner", "id", "Return only cards owned by this agent id."),
              Param("kind", "enum", "Return only this card kind.", choices=CARD_KINDS),
              _limit(50, 200, "cards per lane"),
          )),
    Route("/v1/squad", "squad",
          "Registry agents with runtime/machine labels, scopes, workload, blockers, continuation, "
          "skills reporting, and memory footprint counts.",
          views.squad,
          params=(Param("agent", "id", "Return only this agent id."), _limit(100, 100, "agents"))),
    Route("/v1/signal", "signal", "Newest-first safe event metadata and hourly activity buckets.",
          views.signal, params=(_limit(50, 100, "events"),)),
    Route("/v1/governance", "governance",
          "Approvals, audit-chain integrity, retention, replica, and memory-queue posture.",
          views.governance, params=(_limit(20, 100, "approvals"),)),
    Route("/v1/delivery", "delivery", "Outbox delivery health and the fail-closed fleet verdict.",
          views.delivery),
)
ROUTE_TABLE: dict[str, Route] = {route.path: route for route in ROUTES}


def handle_request(method: str, target: str, authorization: str | None, config: AppConfig) -> Response:
    """Read business sources; faults enqueue metadata to a separate diagnostic sink."""
    # The method gate runs first and unconditionally: there are no mutation
    # routes to authorize, so a non-GET request is refused before auth and
    # before any body could matter.
    if method not in ALLOWED_METHODS:
        return _error(
            405,
            "method_not_allowed",
            "this API is read-only; only GET is supported",
            headers=(("Allow", ", ".join(ALLOWED_METHODS)),),
        )
    parts = urlsplit(target)
    route = ROUTE_TABLE.get(parts.path)
    # Authenticate everything that is not an explicitly public route, unknown
    # paths included, so route existence is not probeable without a token.
    if route is None or not route.public:
        denied = _authorize(authorization, config)
        if denied is not None:
            return denied
    if route is None:
        return _error(404, "not_found", "unknown route; see GET /v1/routes")
    try:
        params = views.parse_query(route.params, parts.query)
    except QueryError as exc:
        return _error(400, "invalid_query", str(exc))
    try:
        body = route.build(config.sources, params)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        # A torn or malformed source must not render as an empty, healthy
        # fleet. Only allowlisted metadata goes to the separate diagnostics sink.
        capture(exc, component="api", code="read_model_projection")
        return _error(503, "projection_unavailable", "the read model could not be built from the configured sources")
    return Response(200, views.sanitize(body))


def _authorize(authorization: str | None, config: AppConfig) -> Response | None:
    """Fail closed: only a valid bearer identity holding control.read passes.

    Identity resolution is the operator API's own (``resolve_identity``):
    the operator shared secret, or a per-agent token whose sha256 is stored
    under the vault's ``registry/tokens``. There is no anonymous or demo
    bypass, including when no credentials are configured at all.
    """
    if authorization is not None and len(authorization) > MAX_AUTHORIZATION_CHARS:
        return _unauthorized()
    try:
        identity = resolve_identity(config.sources.vault, authorization, shared_secret=config.bearer_secret)
    except Exception as exc:  # noqa: BLE001 - an unreadable token store denies
        capture(exc, component="api", code="read_model_auth")
        return _error(503, "auth_unavailable", "authentication is temporarily unavailable")
    if identity is None:
        return _unauthorized()
    if REQUIRED_SCOPE not in identity.scopes:
        return _error(403, "insufficient_scope", f"this API requires the {REQUIRED_SCOPE} scope")
    return None


def _unauthorized() -> Response:
    return _error(
        401,
        "unauthorized",
        f"a bearer token with the {REQUIRED_SCOPE} scope is required",
        headers=(("WWW-Authenticate", AUTH_REALM),),
    )


def _error(
    status: int, code: str, message: str, *, headers: tuple[tuple[str, str], ...] = ()
) -> Response:
    return Response(status, {"ok": False, "schema": SCHEMA, "error": code, "message": message}, headers)
