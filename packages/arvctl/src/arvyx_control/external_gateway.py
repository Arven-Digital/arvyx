"""External-only adapter; never delegate to the shared HTTP/MCP router.

Integration contract (ExternalAPI implements the bounded read-only transport):
1. Authenticate external credentials separately from auth.Identity and construct
   ExternalIdentity server-side. Never accept principal/actor from request JSON.
   Reject external credentials on existing /mcp, memory and control routes before
   anonymous/demo fallback. Existing Identity.binds_actor binds only kind=agent;
   adding kind=external there alone would leave writes unbound.
2. Adapt the core grant authority to GrantChecker.allows. It must check current
   recipient, issuer/export authority, resource exclusions, operation, exact tool,
   expiry and revocation on EVERY call. Do not translate control.read or memory
   scopes into grants. Errors and non-True decisions deny; no decision caching.
3. Mount a separate external HTTP namespace /external/resources and MCP endpoint
   /external/mcp. Map exact lookup/read/write to access, and list/search to
   discover. Advertise ONLY the five external.* tools below (not shared schemas).
   Never expose squad registry, totals, hidden IDs, debug errors or shared tools.
4. Backend reads must return export-safe resource DTOs, not raw internal task
   records with squad links. Supply discover only bounded manifest references;
   apply pagination/counts AFTER filtering. Search only the authorized export.
   Resolve opaque artifact/workspace IDs through hash-pinned manifests, with
   traversal/symlink/secret exclusions in the backend; IDs are NOT host paths.
5. Backend writes must use actor supplied here, a closed per-resource schema,
   audit records and idempotency, never dispatch arbitrary tool names or nested
   identity fields. This adapter intentionally does not grant shell/delegation.
6. Bind core check and backend commit/read to one authority transaction/lock to
   close revocation TOCTOU. Recheck active subscriptions per delivery, not only
   handshake. Until that exists, do not expose streaming/download endpoints.
7. Add transport integration tests for bypasses, anonymous fallback, MCP discovery,
   output redaction, no cross-principal caches, audit failure and concurrent revoke.

Risks: authentication is not implemented here; ExternalIdentity is trusted input,
not evidence of successful authentication. Backend DTO safety, atomic grant/use,
manifest integrity and audit durability are required integration responsibilities.
Revocation cannot retract already disclosed bytes. This module opens no listener,
imports no shared router, and makes no production-security-completion claim.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Mapping, Protocol


class AccessDenied(PermissionError):
    """Uniform denial: no resource existence or authority details."""

    def __init__(self) -> None:
        super().__init__('access denied')


_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z')
_RESOURCE_KINDS = frozenset({'prompt', 'task', 'skill', 'artifact', 'workspace'})
_TOOLS = {op: 'external.' + op for op in ('lookup', 'read', 'write', 'list', 'search')}
_ACTOR_FIELDS = frozenset({'actor', 'author', 'owner', 'principal', 'agent_id',
                           'from_agent', 'created_by', 'requester', 'identity'})


def _valid_id(value: object) -> bool:
    return isinstance(value, str) and bool(_ID.fullmatch(value)) and '..' not in value


@dataclass(frozen=True)
class ExternalIdentity:
    """Principal resolved by a trusted external authenticator, not a squad agent."""

    principal: str

    def __post_init__(self) -> None:
        if not _valid_id(self.principal):
            raise ValueError('invalid external principal')


@dataclass(frozen=True)
class Resource:
    """Exact opaque export reference. No globs, paths or implicit descendants."""

    kind: str
    identifier: str

    def __post_init__(self) -> None:
        if self.kind not in _RESOURCE_KINDS or not _valid_id(self.identifier):
            raise ValueError('invalid external resource')


class GrantChecker(Protocol):
    def allows(self, *, principal: str, resource: Resource,
               operation: str, tool: str) -> bool:
        """Fresh exact decision including expiry/revocation; no ambient membership."""
        ...


class ExportBackend(Protocol):
    def lookup(self, *, resource: Resource, actor: str) -> Mapping[str, object]:
        """Return exact metadata only; lookup does not authorize file contents."""
        ...

    def read(self, *, resource: Resource, actor: str) -> Mapping[str, object]:
        """Return an export-safe DTO, never an unrestricted internal record."""
        ...

    def write(self, *, resource: Resource, actor: str,
              payload: Mapping[str, object]) -> Mapping[str, object]:
        """Validate a closed schema and persist as the server-bound actor."""
        ...


class ExternalGateway:
    def __init__(self, checker: GrantChecker, backend: ExportBackend) -> None:
        self._checker = checker
        self._backend = backend

    def _allowed(self, identity: ExternalIdentity, resource: Resource,
                 operation: str, tool: str) -> bool:
        if type(identity) is not ExternalIdentity or type(resource) is not Resource:
            return False
        try:
            return self._checker.allows(principal=identity.principal,
                                        resource=resource, operation=operation,
                                        tool=tool) is True
        except Exception:
            return False

    def access(self, identity: ExternalIdentity, resource: Resource,
               operation: str, *, payload: Mapping[str, object] | None = None
               ) -> Mapping[str, object]:
        if operation not in ('lookup', 'read', 'write'):
            raise AccessDenied()
        if not self._allowed(identity, resource, operation, _TOOLS[operation]):
            raise AccessDenied()
        if operation == 'write':
            body = dict(payload) if payload is not None else {}
            if _ACTOR_FIELDS.intersection(body):
                raise AccessDenied()
            return self._backend.write(resource=resource, actor=identity.principal, payload=body)
        if payload is not None:
            raise AccessDenied()
        if operation=='lookup':
            lookup=getattr(self._backend,'lookup',None)
            if not callable(lookup):raise AccessDenied()
            return lookup(resource=resource,actor=identity.principal)
        return self._backend.read(resource=resource, actor=identity.principal)

    def discover(self, identity: ExternalIdentity, resources: list[Resource], *,
                 operation: str = 'list', query: str = ''
                 ) -> list[Mapping[str, object]]:
        """Filter exact manifest references before loading/searching any content.

        A list/search grant never implies read; both decisions name the discovery
        tool. No broad store query, existence probe or unfiltered total is used.
        """
        if type(identity) is not ExternalIdentity or operation not in ('list', 'search'):
            raise AccessDenied()
        tool = _TOOLS[operation]
        result = []
        seen = set()
        for resource in resources:
            if type(resource) is not Resource:
                raise AccessDenied()
            if resource in seen:
                continue
            seen.add(resource)
            if not self._allowed(identity, resource, operation, tool):
                continue
            if not self._allowed(identity, resource, 'read', tool):
                continue
            item = self._backend.read(resource=resource, actor=identity.principal)
            if operation == 'list' or query.casefold() in str(item).casefold():
                result.append(item)
        return result
