"""Metadata-first, exact native-session routing; no provider or owner mutation.

Inject trusted adapters keyed by complete SessionTarget (including connection
incarnation). Adapters must atomically revalidate target, connectivity and session
existence at dispatch; never resume/create/queue/retry on a failed selection.
The coordinator must authorize callers before exposing this service. Identifiers
are opaque and never normalized or resolved by display name. This module does
not discover machines, open providers, or claim adapter liveness as authentication.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import base64
import secrets
import threading
import time
import json
from typing import Mapping, Protocol, Sequence


class RoutingError(ValueError):
    """Exact destination unavailable or not present; no fallback is permitted."""


class StaleRouteError(RoutingError):
    """Connection or metadata snapshot no longer matches the request."""


class DisconnectedError(ConnectionError):
    """Destination disconnected; operation was not queued or retried."""


def _identifier(value):
    if not isinstance(value, str) or not value or not value.strip():
        raise ValueError('nonempty exact identifier required')


@dataclass(frozen=True)
class SessionTarget:
    machine_id: str
    agent_id: str
    workspace_id: str
    connection_id: str

    def __post_init__(self):
        for value in asdict(self).values():
            _identifier(value)


@dataclass(frozen=True)
class SessionRoute:
    target: SessionTarget
    session_id: str

    def __post_init__(self):
        if not isinstance(self.target, SessionTarget):
            raise ValueError('exact session target required')
        _identifier(self.session_id)


@dataclass(frozen=True)
class SessionMetadata:
    route: SessionRoute
    title: str
    updated_at: float

    def __post_init__(self):
        import math
        if not isinstance(self.route, SessionRoute) or not isinstance(self.title, str):
            raise ValueError('invalid session metadata')
        if (isinstance(self.updated_at, bool) or
                not isinstance(self.updated_at, (float, int)) or
                not math.isfinite(self.updated_at)):
            raise ValueError('finite session timestamp required')


@dataclass(frozen=True)
class SessionPage:
    items: tuple[SessionMetadata, ...]
    total: int
    next_cursor: str | None

    def to_dict(self):
        """JSON-safe transport retaining exact routes and total collection size."""
        return asdict(self)


class SessionAdapter(Protocol):
    """metadata must return the complete lightweight collection, not a hidden cap.

    perform must revalidate the connection incarnation and session atomically.
    It may execute only 'select' (load conversation) or explicit 'new'. Exceptions
    propagate without retry; a transport failure must never mean queued success.
    """
    target: SessionTarget
    connected: bool

    def metadata(self, target: SessionTarget) -> Sequence[SessionMetadata]: ...

    def perform(self, target: SessionTarget, action: str, session_id: str | None = None, *, publication_guard=None): ...


MAX_METADATA_FIELD_BYTES = 4096
MAX_METADATA_BYTES = 8 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
MAX_PAGE_BYTES = 512 * 1024


def metadata_bytes(item):
    fields = [item.title, item.route.session_id, *asdict(item.route.target).values()]
    if any(len(value) > MAX_METADATA_FIELD_BYTES or len(value.encode('utf-8')) > MAX_METADATA_FIELD_BYTES for value in fields):
        raise RoutingError('metadata field byte budget exceeded; enumeration incomplete')
    return len(json.dumps(asdict(item)).encode('utf-8'))


class AgentSessions:
    def __init__(self, adapters: Mapping[SessionTarget, SessionAdapter], *,
                 snapshot_ttl=120, clock=time.monotonic, max_snapshots=64):
        if snapshot_ttl <= 0 or max_snapshots < 1:
            raise ValueError('positive snapshot TTL and capacity required')
        self._adapters = dict(adapters)
        self._snapshot_ttl, self._clock = snapshot_ttl, clock
        self._max_snapshots, self._snapshots = max_snapshots, {}
        self._lock = threading.RLock()

    def _adapter(self, target):
        if not isinstance(target, SessionTarget):
            raise RoutingError('exact machine/agent/workspace/connection required')
        adapter = self._adapters.get(target)
        if adapter is None:
            raise RoutingError('exact destination unavailable; no fallback')
        if adapter.target != target:
            raise StaleRouteError('stale connection incarnation')
        if not adapter.connected:
            raise DisconnectedError('destination disconnected; not queued or retried')
        return adapter

    def _metadata(self, target):
        adapter = self._adapter(target)
        items = []
        size = 0
        seen = set()
        for item in adapter.metadata(target):
            if not isinstance(item, SessionMetadata) or item.route.target != target:
                raise RoutingError('adapter returned a different destination')
            if item.route.session_id in seen:
                raise RoutingError('duplicate session identity')
            seen.add(item.route.session_id)
            size += metadata_bytes(item)
            if size > MAX_METADATA_BYTES:
                raise RoutingError('metadata collection byte budget exceeded; enumeration incomplete')
            items.append(item)
        self._adapter(target)
        return tuple(sorted(items, key=lambda x: (-x.updated_at, x.route.session_id)))

    def recent(self, target: SessionTarget) -> tuple[SessionMetadata, ...]:
        return self._metadata(target)[:5]

    def all(self, target: SessionTarget, *, query: str = '', limit: int = 100,
            cursor: str | None = None) -> SessionPage:
        """Search a TTL-bound metadata snapshot with stable first-request ordering.

        Pagination is a transport boundary, not a maximum collection size. Clients
        must follow next_cursor until None to enumerate All. No transcripts load.
        """
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError('page limit must be between 1 and 1000')
        if not isinstance(query, str):
            raise ValueError('search query must be text')
        if len(query) > MAX_METADATA_FIELD_BYTES or len(query.encode('utf-8')) > MAX_METADATA_FIELD_BYTES:
            raise RoutingError('metadata query byte budget exceeded; enumeration incomplete')
        # Freeze both order and membership at the first request. Activity/title
        # updates cannot move records across offsets. Selection still revalidates
        # current existence and the exact connection at dispatch.
        with self._lock:
            self._adapter(target)
            now = self._clock()
            self._snapshots = {key: value for key, value in self._snapshots.items()
                               if value[0] > now}
            offset = 0
            if cursor is None:
                items = tuple(item for item in self._metadata(target)
                              if query.casefold() in (item.title + '\n' + item.route.session_id).casefold())
                snapshot = secrets.token_urlsafe(24)
                size = sum(metadata_bytes(item) for item in items) + len(query.encode('utf-8')) + len(json.dumps(asdict(target)).encode('utf-8'))
                if size > MAX_SNAPSHOT_BYTES:
                    raise RoutingError('metadata snapshot byte budget exceeded; enumeration incomplete')
                if len(self._snapshots) >= self._max_snapshots:
                    del self._snapshots[next(iter(self._snapshots))]
                retained = sum(value[4] for value in self._snapshots.values())
                while self._snapshots and retained + size > MAX_SNAPSHOT_BYTES:
                    retained -= self._snapshots.pop(next(iter(self._snapshots)))[4]
                self._snapshots[snapshot] = (now + self._snapshot_ttl, target, query, items, size)
            else:
                try:
                    if not isinstance(cursor, str) or len(cursor) > 1024:
                        raise ValueError
                    token = json.loads(base64.b64decode(cursor.encode(), altchars=b'-_', validate=True))
                    snapshot, offset = token['snapshot'], token['offset']
                    expiry, saved_target, saved_query, items, size = self._snapshots[snapshot]
                    if (saved_target != target or saved_query != query or type(offset) is not int
                            or not 0 < offset < len(items)):
                        raise ValueError
                except (ValueError, TypeError, KeyError, UnicodeError) as exc:
                    raise StaleRouteError('invalid, expired or stale metadata cursor; reload collection') from exc
            end = offset
            page_bytes = 1024
            for item in items[offset:offset + limit]:
                size = metadata_bytes(item) + 2
                if page_bytes + size > MAX_PAGE_BYTES:
                    break
                page_bytes += size
                end += 1
            if end == offset and offset < len(items):
                raise RoutingError('metadata page byte budget exceeded; enumeration incomplete')
            next_cursor = None
            if end < len(items):
                next_cursor = base64.urlsafe_b64encode(json.dumps(
                    {'snapshot': snapshot, 'offset': end}).encode()).decode()
            return SessionPage(items[offset:end], len(items), next_cursor)

    def select(self, route: SessionRoute):
        if not isinstance(route, SessionRoute):
            raise RoutingError('exact session route required')
        if not any(item.route == route for item in self._metadata(route.target)):
            raise RoutingError('session missing at exact destination; no fallback')
        from .public_onboarding_api import assert_request_active
        assert_request_active()
        from .reviewed_actions import call_with_publication_guard
        return call_with_publication_guard(self._adapter(route.target).perform, route.target, 'select', route.session_id)

    def new(self, target: SessionTarget) -> SessionMetadata:
        """Only this explicit action may create a session. Never auto-select it."""
        from .public_onboarding_api import assert_request_active
        assert_request_active()
        from .reviewed_actions import call_with_publication_guard
        created = call_with_publication_guard(self._adapter(target).perform, target, 'new')
        if not isinstance(created, SessionMetadata) or created.route.target != target:
            raise RoutingError('adapter created session at a different destination')
        if not any(item.route == created.route for item in self._metadata(target)):
            raise RoutingError('created session could not be verified at exact destination')
        return created
