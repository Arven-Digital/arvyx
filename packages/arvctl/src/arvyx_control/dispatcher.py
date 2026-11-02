from __future__ import annotations

from .diagnostics import boundary, capture

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
from typing import Callable, Mapping

from .agent_delivery import (
    AgentDeliveryResult,
    AgentRoute,
    deliver_outbox_item,
    validate_agent_route,
)
from .outbox import (
    OutboxItem,
    assignment_notice_for_delivery,
    claim_due,
    defer_lease,
    enqueue,
    mark_delivered,
    should_record_dispatcher_tick,
    mark_delivery_ambiguous,
    record_dispatcher_tick,
    record_failure,
)
from .execution import project_executions
from .liveness import DISPATCHER_COMPONENT, write_tick_record
from . import projection_cache
from .decisions import classify_decision_card_dispatch
from .session_return import (
    classify_session_return_dispatch,
    enqueue_session_return_continuation,
)



#: Non-agent parties that author threads (the watchdog's stale-work and HOLD pages). A reply to
#: one of their threads names them as the other party, but they have no delivery route, so they
#: are observed like operator instead of turning dispatcher health red (2026-09-25).
SYSTEM_PARTIES = frozenset({"arvyx-watchdog"})


@dataclass(frozen=True)
class DispatchTickResult:
    claimed: int
    delivered: int
    retrying: int
    dead_lettered: int
    ambiguous: int = 0
    capped_targets: tuple[str, ...] = ()
    lost_leases: int = 0
    processing_errors: tuple[str, ...] = ()
    deferred_to_next_tick: int = 0
    quarantined_items: tuple[str, ...] = ()
    configuration_errors: tuple[str, ...] = ()
    materialized: int = 0
    materialization_remaining: bool = False
    skipped_unconfigured_targets: tuple[str, ...] = ()
    skipped_intentional_human_targets: tuple[str, ...] = ()
    dry_run: bool = False

    @property
    def ok(self) -> bool:
        return (
            not self.configuration_errors
            and not self.processing_errors
            and self.lost_leases == 0
            and not self.quarantined_items
            and self.retrying == 0
            and self.dead_lettered == 0
            and self.ambiguous == 0
            and not self.skipped_unconfigured_targets
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "claimed": self.claimed,
            "delivered": self.delivered,
            "retrying": self.retrying,
            "dead_lettered": self.dead_lettered,
            "ambiguous": self.ambiguous,
            "capped_targets": list(self.capped_targets),
            "lost_leases": self.lost_leases,
            "processing_errors": list(self.processing_errors),
            "deferred_to_next_tick": self.deferred_to_next_tick,
            "quarantined_items": list(self.quarantined_items),
            "configuration_errors": list(self.configuration_errors),
            "materialized": self.materialized,
            "materialization_remaining": self.materialization_remaining,
            "skipped_unconfigured_targets": list(self.skipped_unconfigured_targets),
            "skipped_intentional_human_targets": list(self.skipped_intentional_human_targets),
            "dry_run": self.dry_run,
        }


@boundary("dispatcher")
def dispatch_once(
    state: Path,
    *,
    routes: Mapping[str, AgentRoute],
    worker: str,
    deliver_after: str,
    now: datetime | None = None,
    limit: int = 5,
    per_target_limit: int = 5,
    lease_seconds: int = 120,
    max_attempts: int = 8,
    environ: Mapping[str, str] | None = None,
    deliverer: Callable[..., AgentDeliveryResult] = deliver_outbox_item,
    clock: Callable[[], datetime] | None = None,
    materialization_limit: int = 100,
    max_watermark_age_seconds: int = 86400,
    intentional_human_targets: set[str] | None = None,
    dry_run: bool = False,
    route_revision: str = "",
    route_sha256: str = "",
    exact_allowlist: list[dict[str, str]] | None = None,
) -> DispatchTickResult:
    """Run one bounded delivery cycle.

    All route references are validated before any claim is appended. Network
    calls happen after ``claim_due`` releases the control-state lock.
    """
    from .replica_authority import assert_state_authority
    if not dry_run:
        assert_state_authority(state)
    clock_fn = clock or (lambda: datetime.now(timezone.utc))
    tick_start = clock_fn()
    # ``claim_now`` is this tick's own reference time. It is the right basis for
    # the tick deadline and for the tick record (see the documented exception for
    # watchdog tick records), but it must never reach domain writes: a claim
    # stamped with the tick start predates the thread that caused it. ``now`` is
    # forwarded unchanged so a real append samples the clock where it happens.
    claim_now = now or tick_start
    errors = validate_routes(routes, environ=environ)
    if not routes:
        errors.append("at least one delivery route is required")
    if limit < 1 or per_target_limit < 1 or lease_seconds < 1 or materialization_limit < 1:
        errors.append("limit, per_target_limit, lease_seconds, and materialization_limit must be positive")
    if max_watermark_age_seconds < 1:
        errors.append("max_watermark_age_seconds must be positive")
    if routes:
        required_lease = limit * (max(route.timeout_seconds for route in routes.values()) + 2) + 5
        if lease_seconds < required_lease:
            errors.append(
                f"lease_seconds must be at least {required_lease} for limit={limit} and configured route timeouts"
            )
    if errors:
        return DispatchTickResult(0, 0, 0, 0, configuration_errors=tuple(errors))

    deferred_by_target_cap: dict[str, int] = {}
    quarantined: list[str] = []
    reclaim_dead_letters: list[str] = []
    reclaim_ambiguities: list[str] = []
    materialization_report: dict[str, object] = {}
    try:
        claimed = claim_due(
            state,
            worker=worker,
            now=now,
            lease_seconds=lease_seconds,
            limit=limit,
            deliver_after=deliver_after,
            targets=set(routes),
            intentional_human_targets=intentional_human_targets,
            per_target_limit=per_target_limit,
            max_attempts=max_attempts,
            deferred_by_target_cap=deferred_by_target_cap,
            quarantined=quarantined,
            dead_lettered_on_reclaim=reclaim_dead_letters,
            ambiguous_on_reclaim=reclaim_ambiguities,
            materialization_limit=materialization_limit,
            materialization_report=materialization_report,
            max_watermark_age_seconds=max_watermark_age_seconds,
            dry_run=dry_run,
            exact_allowlist=exact_allowlist,
        )
    except ValueError as exc:
        return DispatchTickResult(0, 0, 0, 0, configuration_errors=(str(exc),), dry_run=dry_run)
    delivered = 0
    retrying = 0
    dead_lettered = len(reclaim_dead_letters)
    ambiguous = len(reclaim_ambiguities)
    runtime_configuration_errors: tuple[str, ...] = ()
    if materialization_report.get("bootstrap_expired"):
        runtime_configuration_errors = (
            "bootstrap watermark is older than max_watermark_age_seconds; "
            "source materialization is blocked until an operator supplies a current bootstrap floor",
        )
    lost_leases = 0
    processing_errors: list[str] = []
    deferred_to_next_tick = 0
    max_timeout = max(route.timeout_seconds for route in routes.values())
    deadline = tick_start + timedelta(seconds=lease_seconds - max_timeout - 2)
    for index, item in enumerate(claimed):
        if clock_fn() >= deadline:
            for pending_item in claimed[index:]:
                try:
                    defer_lease(
                        state,
                        outbox_id=pending_item.id,
                        worker=worker,
                        claim_attempts=pending_item.attempts,
                        now=clock_fn(),
                    )
                    deferred_to_next_tick += 1
                except ValueError:
                    lost_leases += 1
                    processing_errors.append(f"{pending_item.id}: lease lost before deferral")
                except Exception as exc:
                    capture(exc, component="dispatcher", code="defer")
                    processing_errors.append(f"{pending_item.id}: deferral raised {type(exc).__name__}")
            break
        delivery_now = clock_fn()
        refusal = None
        card_refusal = None
        try:
            if item.payload.get("delivery_mode") == "session_return":
                # Owner + exact live attempt, revalidated right before I/O. A
                # refused return is never re-targeted to another identity.
                refusal = classify_session_return_dispatch(
                    state,
                    execution_id=str(item.payload.get("execution_id", "")),
                    attempt_id=str(item.payload.get("attempt_id", "")),
                    target=item.target,
                    now=delivery_now,
                )
            elif item.payload.get("delivery_mode") == "decision_card":
                # Revalidated right before I/O: never send a card for an answered,
                # unknown, or retargeted decision.
                card_refusal = classify_decision_card_dispatch(
                    state, decision_id=str(item.payload.get("decision_id", "")), target=item.target,
                )
            if refusal is not None:
                result = AgentDeliveryResult(False, "permanent", None, refusal.detail)
            elif card_refusal is not None:
                result = AgentDeliveryResult(False, "permanent", None, card_refusal)
            else:
                result = deliverer(assignment_notice_for_delivery(state, item), routes[item.target], now=delivery_now, environ=environ)
        except Exception as exc:  # isolate one broken adapter call from the rest of the leased batch
            capture(exc, component="dispatcher", code="adapter")
            result = AgentDeliveryResult(
                False,
                "ambiguous",
                None,
                f"delivery adapter raised {type(exc).__name__}",
            )
        try:
            if result.accepted:
                finalized = mark_delivered(
                    state,
                    outbox_id=item.id,
                    worker=worker,
                    claim_attempts=item.attempts,
                    now=clock_fn(),
                    provider_receipt=(
                        result.provider_receipt
                        if item.payload.get("delivery_mode") in {"session_return", "decision_card"}
                        else ""
                    ),
                )
                if finalized.status == "ambiguous_delivery":
                    ambiguous += 1
                    continue
                delivered += 1
                if (
                    item.payload.get("delivery_mode") == "session_return"
                    and result.provider_receipt
                    and exact_allowlist is None
                ):
                    # The provider receipt is durable now; give the target one
                    # bounded continuation wake so it can read the receipt
                    # back and write canonical completion even if its original
                    # session already exited. Failures here never undo the
                    # recorded delivery.
                    try:
                        # Best-effort latency optimization only: normal claim
                        # ticks recover missing wakes from this durable receipt.
                        enqueue_session_return_continuation(state, finalized, now=clock_fn())
                    except Exception as exc:
                        capture(exc, component="dispatcher", code="continuation")
                        processing_errors.append(
                            f"{item.id}: continuation enqueue raised {type(exc).__name__}"
                        )
                continue
            if result.classification == "ambiguous":
                mark_delivery_ambiguous(
                    state,
                    outbox_id=item.id,
                    worker=worker,
                    claim_attempts=item.attempts,
                    detail=result.detail,
                    now=clock_fn(),
                )
                ambiguous += 1
                continue
            classified = refusal is not None and bool(refusal.resolution_category)
            failed = record_failure(
                state,
                outbox_id=item.id,
                worker=worker,
                claim_attempts=item.attempts,
                detail=result.detail,
                transient=result.classification == "transient",
                max_attempts=max_attempts,
                now=clock_fn(),
                resolution_category=refusal.resolution_category if classified else "",
                resolved_by="dispatcher" if classified else "",
                resolution_detail=(
                    f"classified by dispatcher {worker} from authoritative execution state: "
                    "the fenced attempt can never become live again; the owning execution's live "
                    "attempt must request its own return"
                    if classified else ""
                ),
            )
            if failed.status == "dead_lettered":
                dead_lettered += 1
            else:
                retrying += 1
        except ValueError:
            lost_leases += 1
            processing_errors.append(f"{item.id}: lease lost before finalization")
        except Exception as exc:  # preserve the remaining batch without exposing exception text
            capture(exc, component="dispatcher", code="finalize")
            processing_errors.append(f"{item.id}: finalization raised {type(exc).__name__}")
    capped_targets = tuple(sorted(deferred_by_target_cap))
    result = DispatchTickResult(
        len(claimed),
        delivered,
        retrying,
        dead_lettered,
        ambiguous=ambiguous,
        capped_targets=capped_targets,
        lost_leases=lost_leases,
        processing_errors=tuple(processing_errors),
        deferred_to_next_tick=deferred_to_next_tick,
        quarantined_items=tuple(quarantined),
        configuration_errors=runtime_configuration_errors,
        materialized=int(str(materialization_report.get("materialized", 0))),
        materialization_remaining=bool(materialization_report.get("remaining", False)),
        skipped_unconfigured_targets=tuple(materialization_report.get("skipped_unconfigured_targets", ())),
        skipped_intentional_human_targets=tuple(materialization_report.get("skipped_intentional_human_targets", ())),
        dry_run=dry_run,
    )
    if not dry_run and exact_allowlist is None:
        # A tick that did something is always written. A tick that changed nothing
        # is liveness noise: it is coalesced down to a bounded heartbeat so the
        # append-only log does not grow by megabytes a day of "nothing happened".
        # The activity test is deliberately any-difference-from-quiet, so an
        # unhealthy, saturated, capped, or skipping dispatcher always records.
        tick_has_work = bool(
            result.claimed
            or result.delivered
            or result.retrying
            or result.dead_lettered
            or result.ambiguous
            or result.capped_targets
            or result.lost_leases
            or result.processing_errors
            or result.quarantined_items
            or result.materialized
            or result.materialization_remaining
            or result.skipped_unconfigured_targets
            or result.skipped_intentional_human_targets
            or result.deferred_to_next_tick
            or not result.ok
        )
        # The record is a snapshot, so the cycle's own content counts as activity:
        # a changed route attestation, target set, health flag, or skip state must
        # never sit behind the heartbeat.
        tick_snapshot = {
            "healthy": result.ok,
            "configured_targets": sorted(set(routes)),
            "materialization_remaining": result.materialization_remaining,
            "skipped_unconfigured_targets": result.skipped_unconfigured_targets,
            "skipped_intentional_human_targets": result.skipped_intentional_human_targets,
            "route_revision": route_revision,
            "route_sha256": route_sha256,
        }
        if should_record_dispatcher_tick(
            state, has_work=tick_has_work, now=claim_now, snapshot=tick_snapshot
        ):
            record_dispatcher_tick(
                state,
                configured_targets=set(routes),
                healthy=result.ok,
                materialization_remaining=result.materialization_remaining,
                skipped_unconfigured_targets=result.skipped_unconfigured_targets,
                skipped_intentional_human_targets=result.skipped_intentional_human_targets,
                route_revision=route_revision,
                route_sha256=route_sha256,
                now=claim_now,
            )
    return result


def validate_routes(
    routes: Mapping[str, AgentRoute],
    *,
    environ: Mapping[str, str] | None,
) -> list[str]:
    if not routes:
        return ["no agent delivery routes configured"]
    errors: list[str] = []
    for target, route in sorted(routes.items()):
        if target != target.strip() or route.agent_id != route.agent_id.strip():
            errors.append(f"route identity must not contain surrounding whitespace: {target!r}")
            continue
        if target.casefold() == "all":
            errors.append("route key all is reserved for registered-agent fanout")
            continue
        if target != target.casefold() or route.agent_id != route.agent_id.casefold():
            errors.append(f"route identity must be canonical lowercase: {target!r}")
            continue
        if target != route.agent_id:
            errors.append(f"route key does not match agent_id: {target}")
            continue
        error = validate_agent_route(route, environ=environ)
        if error:
            errors.append(f"route {target}: {error}")
    return errors


ROUTE_DOCUMENT_SCHEMA = "v2.agent-delivery-routes/1"
_ROUTE_DOCUMENT_TOP_LEVEL_KEYS = frozenset({"routes", "schema", "revision", "approved_at", "owner", "previous"})
_ROUTE_DOCUMENT_PREVIOUS_KEYS = frozenset({"revision", "sha256"})


@dataclass(frozen=True)
class RouteDocument:
    """A loaded agent-delivery route file plus its version attestation metadata."""

    routes: dict[str, AgentRoute]
    sha256: str
    schema: str = ""
    revision: str = ""
    approved_at: str = ""
    owner: str = ""
    previous_revision: str = ""
    previous_sha256: str = ""

    @property
    def versioned(self) -> bool:
        return bool(self.revision)

    @property
    def attested_sha256(self) -> str:
        """Hash consumers attest as loaded; empty until the document is versioned."""
        return self.sha256 if self.versioned else ""


def _metadata_string(raw: Mapping[str, object], key: str) -> str:
    if key not in raw:
        return ""
    value = raw[key]
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"route config {key} must be a non-empty string without surrounding whitespace")
    return value


def _is_sha256_hex(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _rfc3339_is_malformed(value: str) -> bool:
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return True
    return parsed.tzinfo is None


def load_route_document(path: Path) -> RouteDocument:
    """Load and validate the versioned secret-reference-only route document.

    The canonical content hashed into ``sha256`` is the raw file bytes exactly
    as stored on disk, so the value matches ``sha256sum <file>`` and any byte
    change (metadata, whitespace, or newline rewrites included) is a new
    document. Unknown top-level keys fail closed; a document without metadata
    still loads but is observably unversioned (empty ``revision``).
    """
    data = path.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    try:
        raw = json.loads(data.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError("route config must be UTF-8 encoded JSON") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("routes"), dict):
        raise ValueError("route config must contain an object named routes")
    unknown_top_level = set(raw) - _ROUTE_DOCUMENT_TOP_LEVEL_KEYS
    if unknown_top_level:
        raise ValueError(
            "route config has unsupported top-level keys: " + ", ".join(sorted(str(key) for key in unknown_top_level))
        )
    schema = _metadata_string(raw, "schema")
    if schema and schema != ROUTE_DOCUMENT_SCHEMA:
        raise ValueError(f"route config schema must be {ROUTE_DOCUMENT_SCHEMA}")
    revision = _metadata_string(raw, "revision")
    approved_at = _metadata_string(raw, "approved_at")
    if approved_at and _rfc3339_is_malformed(approved_at):
        raise ValueError("route config approved_at must be a timezone-aware RFC3339 timestamp")
    owner = _metadata_string(raw, "owner")
    previous_revision = ""
    previous_sha256 = ""
    if "previous" in raw:
        previous = raw["previous"]
        if not isinstance(previous, dict) or set(previous) != _ROUTE_DOCUMENT_PREVIOUS_KEYS:
            raise ValueError("route config previous must be an object with exactly revision and sha256")
        previous_revision = _metadata_string(previous, "revision")
        previous_sha256 = _metadata_string(previous, "sha256")
        if not _is_sha256_hex(previous_sha256):
            raise ValueError("route config previous sha256 must be 64 lowercase hex characters")
    routes: dict[str, AgentRoute] = {}
    for target, value in raw["routes"].items():
        if not isinstance(target, str) or not isinstance(value, dict):
            raise ValueError("each route must be an object keyed by target agent")
        allowed = {
            "runtime", "url_env", "credential_env", "timeout_seconds",
            "return_runtime", "return_url_env", "return_credential_env",
        }
        unknown = set(value) - allowed
        if unknown:
            raise ValueError(f"route {target} has unsupported keys: {', '.join(sorted(unknown))}")
        routes[target] = AgentRoute(
            agent_id=target,
            runtime=str(value.get("runtime", "")),
            url_env=str(value.get("url_env", "")),
            credential_env=str(value.get("credential_env", "")),
            timeout_seconds=int(value.get("timeout_seconds", 10)),
            return_runtime=str(value.get("return_runtime", "")),
            return_url_env=str(value.get("return_url_env", "")),
            return_credential_env=str(value.get("return_credential_env", "")),
        )
    return RouteDocument(
        routes=routes,
        sha256=sha256,
        schema=schema,
        revision=revision,
        approved_at=approved_at,
        owner=owner,
        previous_revision=previous_revision,
        previous_sha256=previous_sha256,
    )


def load_routes(path: Path) -> dict[str, AgentRoute]:
    """Load secret-reference-only routing configuration."""
    return load_route_document(path).routes


def _sealed_metadata(field: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"route config {field} must be a non-empty string")
    if value != value.strip():
        raise ValueError(f"route config {field} must not contain surrounding whitespace")
    return value


def _reference_name_errors(routes: Mapping[str, AgentRoute]) -> list[str]:
    """Reference *names* may not carry surrounding whitespace.

    `validate_agent_route` looks the raw name up in the environment, so a
    padded name is reported as "not configured" and the operator chases a
    missing value instead of the typo. Name it precisely here.
    """
    errors: list[str] = []
    for target, route in sorted(routes.items()):
        for field, value in (
            ("url_env", route.url_env),
            ("credential_env", route.credential_env),
            ("return_url_env", route.return_url_env),
            ("return_credential_env", route.return_credential_env),
        ):
            if value and value != value.strip():
                errors.append(f"{target}: {field} must not contain surrounding whitespace")
    return errors


def _placeholder_environ(routes: Mapping[str, AgentRoute]) -> dict[str, str]:
    """Values that satisfy every env *presence* rule, distinct per name.

    Structural validation must not depend on the sealing process holding the
    deployment's secrets: the question is whether the document would be usable
    in an environment where its references are configured. Distinct values also
    keep the session-return rules that compare two references from firing on
    the placeholder itself.
    """
    environ: dict[str, str] = {}
    for route in routes.values():
        for name in (
            route.url_env, route.credential_env,
            route.return_url_env, route.return_credential_env,
        ):
            name = name.strip()
            if name:
                environ.setdefault(name, f"https://127.0.0.1/{name}")
    return environ


def _referenced_environ(
    routes: Mapping[str, AgentRoute],
    *,
    environ: Mapping[str, str] | None,
    placeholders: Mapping[str, str],
) -> tuple[dict[str, str], list[str]]:
    """Merge the real environment over placeholders for every blank reference.

    Returns the merged environment plus the references that are absent or blank
    in the real one. Present values win, so a configured-but-invalid value is
    still seen by validation (and therefore refused) instead of being filed as
    "not configured".
    """
    real = os.environ if environ is None else environ
    merged = dict(placeholders)
    unresolved: list[str] = []
    for target, route in sorted(routes.items()):
        names = [route.url_env, route.credential_env]
        if route.return_url_env.strip() or route.return_credential_env.strip():
            names.extend([route.return_url_env, route.return_credential_env])
        for raw_name in names:
            name = raw_name.strip()
            if not name:
                continue
            value = str(real.get(name, ""))
            if value.strip():
                merged[name] = value
            else:
                unresolved.append(f"{target}: {name}")
    return merged, unresolved


def _copy_file_metadata(source: Path, source_stat: os.stat_result, destination: Path) -> None:
    """Copy mode, ownership and extended attributes onto a sealed document.

    The atomic replace writes a new inode, and the deployed route file's access
    for the unprivileged container uid can be granted through an ACL entry, so
    metadata that cannot be preserved fails the seal instead of silently
    removing the reader's access to its own configuration.

    The stat is passed in rather than taken here: mode and ownership must come
    from the same observation that was verified with the document body, not a
    second look at a file that may have changed meanwhile.

    Ownership is copied only when the sealer is privileged enough to change it;
    mode and ACLs always travel with the file.
    """
    os.chmod(destination, stat.S_IMODE(source_stat.st_mode))
    try:
        os.chown(destination, source_stat.st_uid, source_stat.st_gid)
    except PermissionError:
        # A non-root sealer keeps its own owner; mode and ACLs carry the access
        # the running consumer actually depends on.
        pass
    for name in os.listxattr(source):
        try:
            os.setxattr(destination, name, os.getxattr(source, name))
        except OSError as exc:
            raise ValueError(
                f"cannot preserve extended attribute {name!r} on the sealed document: {exc.strerror}"
            ) from exc


def seal_route_document(
    source: Path,
    *,
    revision: str,
    owner: str,
    approved_at: str,
    destination: Path | None = None,
    dry_run: bool = False,
    environ: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Write a versioned route document derived from ``source``.

    The routes object is copied verbatim and the metadata is validated by the
    same rules the dispatcher enforces when it loads a document. The document
    must also be structurally valid: an attestation stamped on a route table the
    dispatcher would refuse at dispatch time would say "approved" about
    something unrunnable. References the sealing process cannot resolve are
    reported without refusing the seal, because the values live on the
    consuming host. The staged bytes are verified from disk before the swap, so
    the reported ``sha256`` is the attested value the dispatcher will record
    rather than a claim about it.
    """
    document = load_route_document(source)
    revision = _sealed_metadata("revision", revision)
    owner = _sealed_metadata("owner", owner)
    approved_at = _sealed_metadata("approved_at", approved_at)
    if _rfc3339_is_malformed(approved_at):
        raise ValueError("route config approved_at must be a timezone-aware RFC3339 timestamp")
    if revision == document.revision:
        raise ValueError("route config revision must differ from the current revision")
    if revision == document.previous_revision:
        raise ValueError(
            "route config revision must not reuse the revision it replaces"
        )
    placeholders = _placeholder_environ(document.routes)
    # The dispatcher runs validate_routes, not just the per-route check, so the
    # seal runs the same table-level rules (empty table, reserved target names,
    # canonical casing, whitespace) before it stamps an approval on anything.
    structural_errors = validate_routes(document.routes, environ=placeholders)
    structural_errors = _reference_name_errors(document.routes) + structural_errors
    if structural_errors:
        raise ValueError(
            "route document is not structurally valid: " + "; ".join(structural_errors)
        )
    merged_environ, unresolved_references = _referenced_environ(
        document.routes, environ=environ, placeholders=placeholders
    )
    value_errors = validate_routes(document.routes, environ=merged_environ)
    if value_errors:
        # Absence cannot be the cause here: every blank reference was replaced
        # by a placeholder, so these are configured-but-invalid values.
        raise ValueError(
            "route document has invalid configured references: " + "; ".join(value_errors)
        )
    target = destination or source
    if destination is not None and target.exists():
        raise ValueError(f"refusing to overwrite existing route document: {target}")

    # The routes body must be the bytes that were validated, not a second read:
    # if the document changes between the load above and this read, the sealed
    # table would be one that never passed validation. Compare the hash of the
    # bytes about to be copied against the hash the loader attested.
    source_bytes = source.read_bytes()
    if hashlib.sha256(source_bytes).hexdigest() != document.sha256:
        raise ValueError(
            f"route document changed while it was being sealed: {source}"
        )
    # One observation of the source's metadata, taken with the bytes that were
    # verified: the replace copies this, never a second look at the file.
    source_stat = source.stat()
    raw = json.loads(source_bytes.decode("utf-8"))
    payload: dict[str, object] = {
        "schema": ROUTE_DOCUMENT_SCHEMA,
        "revision": revision,
        "approved_at": approved_at,
        "owner": owner,
    }
    if document.versioned:
        # Only a revision that actually existed is worth naming as previous.
        payload["previous"] = {"revision": document.revision, "sha256": document.sha256}
    payload["routes"] = raw["routes"]

    data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    sha256 = hashlib.sha256(data).hexdigest()
    report: dict[str, object] = {
        "ok": True,
        "path": str(target),
        "schema": ROUTE_DOCUMENT_SCHEMA,
        "revision": revision,
        "owner": owner,
        "approved_at": approved_at,
        "sha256": sha256,
        "route_sha256": sha256,
        "bytes": len(data),
        "versioned": True,
        "targets": sorted(document.routes),
        "previous_revision": document.revision if document.versioned else "",
        "previous_sha256": document.sha256 if document.versioned else "",
        "unresolved_references": unresolved_references,
        "dry_run": dry_run,
    }
    if dry_run:
        return report

    fd, temporary = tempfile.mkstemp(prefix="." + target.name + ".", dir=str(target.parent))
    temporary_path = Path(temporary)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())

        # Verify the staged bytes before the swap: a verification failure must
        # leave the previous document exactly where it was, and the staged file
        # must not carry the source's mode/ACLs until it is known to be good.
        staged = load_route_document(temporary_path)
        if not staged.versioned or staged.revision != revision or staged.sha256 != sha256:
            raise ValueError(f"sealed route document failed verification: {target}")
        if json.loads(temporary_path.read_bytes().decode("utf-8"))["routes"] != raw["routes"]:
            raise ValueError("sealed route document changed the routes body")
        _copy_file_metadata(source, source_stat, temporary_path)

        if destination is None:
            os.replace(temporary_path, target)
        else:
            # `--out` promised not to overwrite: link refuses an existing path
            # that appeared after the precheck instead of clobbering it.
            try:
                os.link(temporary_path, target)
            except FileExistsError as exc:
                raise ValueError(f"refusing to overwrite existing route document: {target}") from exc
            temporary_path.unlink()
        directory = os.open(str(target.parent), os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()

    sealed = load_route_document(target)
    if sealed.attested_sha256 != sha256:
        # The report must never carry two different hashes for one document: if
        # the file changed between the swap and this read, fail closed.
        raise ValueError(f"sealed route document changed after the swap: {target}")
    report["route_sha256"] = sealed.attested_sha256
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m arvyx_control.dispatcher")
    parser.add_argument("--vault", type=Path, required=True, help="Actual vault authority for this worker")
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--routes", type=Path, required=True)
    parser.add_argument("--deliver-after", required=True)
    parser.add_argument("--worker", default=f"{socket.gethostname()}-{os.getpid()}")
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--per-target-limit", type=int, default=5)
    parser.add_argument("--lease-seconds", type=int, default=120)
    parser.add_argument("--max-attempts", type=int, default=8)
    parser.add_argument("--materialization-limit", type=int, default=100)
    parser.add_argument("--max-watermark-age-seconds", type=int, default=86400)
    parser.add_argument(
        "--intentional-human-targets",
        default=os.environ.get("ARVYX_AGENT_INTENTIONAL_HUMAN_TARGETS", ""),
        help="Comma-separated non-agent targets that should be observed without making health red",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--exact-allowlist", type=Path, help="Existing fresh outbox tuple JSON list; no global fallback or continuation creation")
    parser.add_argument(
        "--projection-checkpoint-min-tail-bytes",
        type=int,
        default=projection_cache.DEFAULT_MIN_TAIL_BYTES,
        help=(
            "Refresh the derived read-path projection checkpoint once this many "
            "uncovered log bytes accumulate (0 = every tick, negative = never)."
        ),
    )
    parser.add_argument(
        "--projection-checkpoint-max-log-bytes",
        type=int,
        default=projection_cache.DEFAULT_MAX_LOG_BYTES,
        help="Never build the projection checkpoint above this log size.",
    )
    args = parser.parse_args(argv)
    from .replica_authority import authority_context
    with authority_context(getattr(args, "vault", None), getattr(args, "state", None)):
        return _authority_dispatch(args, parser)


def _authority_dispatch(args, parser):
    from .replica_authority import assert_state_authority
    assert_state_authority(args.state)
    # A dry run is not a tick: it must not refresh the liveness record that
    # proves real ticks are finishing.
    tick: dict[str, str] = {"result": "error", "detail": "tick did not finish"}
    try:
        return _run_tick(args, tick)
    finally:
        if not args.dry_run and args.exact_allowlist is None:
            write_tick_record(
                args.state,
                component=DISPATCHER_COMPONENT,
                result=tick["result"],
                detail=tick["detail"],
                route_revision=tick.get("route_revision", ""),
                route_sha256=tick.get("route_sha256", ""),
            )


def _refresh_projection_checkpoint(
    state: Path,
    *,
    min_tail_bytes: int,
    max_log_bytes: int = projection_cache.DEFAULT_MAX_LOG_BYTES,
    dry_run: bool,
) -> dict[str, object] | None:
    """Keep the derived read-path checkpoint warm off the request path.

    A dry run must not write anything, so it reports nothing. A failed refresh is
    reported but never fails the tick: the checkpoint is an optimisation.
    """
    if dry_run or min_tail_bytes < 0:
        return None
    return projection_cache.maybe_refresh_projection_checkpoint(
        state, min_tail_bytes=min_tail_bytes, max_log_bytes=max_log_bytes
    )


def _tick_liveness(result: DispatchTickResult) -> tuple[str, str]:
    """Map one cycle onto the liveness vocabulary: ok, idle, or error.

    Retries and dead letters are delivery outcomes the probe reads from the
    event log; only a cycle that could not do its own job is an ``error``.
    """
    detail = (
        f"claimed={result.claimed} delivered={result.delivered} retrying={result.retrying} "
        f"dead_lettered={result.dead_lettered} ambiguous={result.ambiguous} "
        f"materialized={result.materialized}"
    )
    if result.configuration_errors or result.processing_errors or result.lost_leases:
        problems = "; ".join(list(result.configuration_errors) + list(result.processing_errors))
        return "error", f"{detail} lost_leases={result.lost_leases} errors: {problems or 'none'}"
    if result.claimed == 0 and result.materialized == 0:
        return "idle", detail
    return "ok", detail


def _run_tick(args: argparse.Namespace, tick: dict[str, str]) -> int:
    try:
        exact_allowlist = None
        if args.exact_allowlist is not None:
            exact_allowlist = json.loads(args.exact_allowlist.read_text())
            if not isinstance(exact_allowlist, list) or not exact_allowlist:
                raise ValueError("exact allowlist must be a non-empty JSON list")
        document = load_route_document(args.routes)
        tick["route_revision"] = document.revision
        tick["route_sha256"] = document.attested_sha256
        result = dispatch_once(
            args.state,
            routes=document.routes,
            worker=args.worker,
            deliver_after=args.deliver_after,
            limit=args.limit,
            per_target_limit=args.per_target_limit,
            lease_seconds=args.lease_seconds,
            max_attempts=args.max_attempts,
            materialization_limit=args.materialization_limit,
            max_watermark_age_seconds=args.max_watermark_age_seconds,
            intentional_human_targets={
                target.strip()
                for target in args.intentional_human_targets.split(",")
                if target.strip()
            } | SYSTEM_PARTIES,
            dry_run=args.dry_run,
            route_revision=document.revision,
            route_sha256=document.attested_sha256,
            exact_allowlist=exact_allowlist,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        capture(exc, component="dispatcher", code="setup", expected=isinstance(exc, ValueError))
        tick["detail"] = f"tick refused: {exc}"
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 2
    tick["result"], tick["detail"] = _tick_liveness(result)
    output = result.to_dict()
    refresh = _refresh_projection_checkpoint(
        args.state,
        min_tail_bytes=args.projection_checkpoint_min_tail_bytes,
        max_log_bytes=args.projection_checkpoint_max_log_bytes,
        dry_run=args.dry_run or args.exact_allowlist is not None,
    )
    if refresh is not None:
        output["projection_checkpoint"] = refresh
    output["route_revision"] = document.revision
    output["route_sha256"] = document.attested_sha256
    print(json.dumps(output, sort_keys=True))
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
