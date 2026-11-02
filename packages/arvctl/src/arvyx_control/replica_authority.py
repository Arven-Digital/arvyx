"""Fail-closed admission while replication lacks journal/effect authority.

The current JSONL/vault replication protocol does not capture an atomic cut of
operation claims and their effects. Neither an existing local SQLite file nor
sync_complete is evidence that those authorities match. There is deliberately
no configuration flag, force override, or on-disk opt-in to bypass this fence.
"""
from pathlib import Path
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
import inspect
from typing import NoReturn

from .locks import check_inherited_deadline

_authority: ContextVar[tuple[Path, Path | None] | None] = ContextVar("replica_mutation_authority", default=None)


@contextmanager
def authority_context(vault: Path | None, state: Path | None = None):
    """Bind caller-owned configuration, never infer a vault from a state path."""
    check_inherited_deadline()
    binding = None if vault is None else (Path(vault).resolve(), None if state is None else Path(state).resolve())
    check_inherited_deadline()
    previous = _authority.get()
    if previous is not None and binding is not None and binding[0] == previous[0] and binding[1] is None:
        binding = previous  # A vault-only callee cannot discard its caller's exact state.
    if previous is not None and previous != binding:
        raise ReplicaAuthorityUnavailable("nested vault/state authority binding mismatch")
    token = _authority.set(binding)
    try:
        yield
    finally:
        _authority.reset(token)


def assert_state_authority(state: Path) -> None:
    binding = _authority.get()
    if binding is None or binding[1] != Path(state).resolve():
        raise ReplicaAuthorityUnavailable(
            "state mutation requires authority_context(actual_vault, exact_state); "
            "state paths do not identify a vault")
    assert_mutation_authority(binding[0])


def assert_bound_authority() -> None:
    binding = _authority.get()
    if binding is None:
        raise ReplicaAuthorityUnavailable("mutation dispatch requires explicit vault authority context")
    assert_mutation_authority(binding[0])


def owner_entry(function):
    """Use the service's immutable caller-owned vault/state binding per thread."""
    @wraps(function)
    def invoke(self, *args, **kwargs):
        if self.vault is None:
            assert_bound_authority()
            return function(self, *args, **kwargs)
        with authority_context(self.vault, getattr(self, 'state', None)):
            assert_mutation_authority(self.vault)
            return function(self, *args, **kwargs)
    return invoke


def bound_entry(function):
    """Bind trusted vault/state arguments for a synchronous public dispatch."""
    signature = inspect.signature(function)
    @wraps(function)
    def invoke(*args, **kwargs):
        values = signature.bind(*args, **kwargs)
        values.apply_defaults()
        state = values.arguments.get('state')
        if state is None and function.__module__.endswith('.mcp'):
            state = Path('tmp/control-events.jsonl')
        with authority_context(values.arguments['vault'], state):
            check_inherited_deadline()
            result = function(*args, **kwargs)
            # Do not convert a completed mutation into a post-effect timeout.
            if str(values.arguments.get('method', '')).upper() in {'GET', 'HEAD'}:
                check_inherited_deadline()
            return result
    return invoke


class ReplicaAuthorityUnavailable(ValueError):
    """The local role cannot safely admit governed mutations."""


# Pre-rename replica marker; kept here (private-only) for quarantine/status checks.
LEGACY_REPLICA_MARKER = ".arven-replica"


def assert_mutation_authority(vault: Path) -> None:
    """Reject replicas and all historical/prepared/completed promotions.

    Check under the caller's authority lock before any effect. In particular,
    do not parse lineage to decide whether to fail closed: malformed lineage,
    historical lineage without a phase, and interrupted marker publication all
    require reconciliation rather than an empty fresh operation journal.
    """
    check_inherited_deadline()
    candidate=Path(vault)/'.arvyx-restored-candidate.json'
    if candidate.exists() or candidate.is_symlink():
        raise ReplicaAuthorityUnavailable('restored composition is quarantined; bearer and incarnation authority must be independently reprovisioned')
    root = vault.resolve()
    # Pre-rename namespace: replica/failover/restored markers and the vault lock
    # lived under the retired hidden directory below. The rename is a clean break
    # without automatic migration, so any legacy namespace quarantines mutation
    # until an operator explicitly migrates it; otherwise legacy replica markers
    # would fail open and old/new processes would lock different files.
    for relative in (".arven", ".arven-replica", ".arven-restored-candidate.json", ".arvyx/.arven"):
        check_inherited_deadline()
        try:
            (root / relative).lstat()
        except FileNotFoundError:
            continue
        raise ReplicaAuthorityUnavailable(
            "pre-rename vault namespace present; mutation refused until it is "
            "explicitly migrated to .arvyx (see docs/runbooks/pre-rename-vault-migration.md)")
    for relative in (".arvyx-replica", ".arvyx/failover.json"):
        check_inherited_deadline()
        candidate = root / relative
        # lstat distinguishes absence from inaccessible/malformed paths, and
        # also refuses dangling symlinks rather than treating them as absence.
        try:
            candidate.lstat()
        except FileNotFoundError:
            continue
        raise ReplicaAuthorityUnavailable(
            "replica mutation authority unavailable: matching operation-journal "
            "and effect authority has not been captured and restored"
        )


def assert_promotion_authority(vault: Path) -> NoReturn:
    """No current replica generation is eligible for writable promotion.

    Keep this refusal at the shared promotion primitive, not in HTTP, so manual
    CLI, automatic/forced failover, and interrupted promotion retries agree.
    A future implementation must validate a consistently captured journal and
    effect generation here; mere file existence must never authorize writes.
    """
    raise ReplicaAuthorityUnavailable(
        "replica promotion refused: matching operation-journal and effect "
        "authority is not replicated; writable failover is unavailable"
    )
