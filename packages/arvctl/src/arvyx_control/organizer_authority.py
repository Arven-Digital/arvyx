"""Abstract AMC organizer authority; no commands, transport, or external grants.

Only trusted provisioning/authentication code may hold an OrganizerAuthority and
call its provisioning methods. Never expose those methods to request payloads.
Identity handles are process-local authentication results, not serialized caller
claims: an equal or copied Identity is not authenticated. Transport integrations
must resolve authenticated sessions to the original handle, never provision one
from a submitted principal/role. Root availability alone confers no AMC role.

Decisions describe current authority, not transferable execution capabilities.
Dispatch rechecks all live state and returns only a decision; it executes nothing.
A real executor must serialize its eventual effect with authoritative revocation
checks. This module intentionally does not replace scoped external grant policy.
"""
from dataclasses import dataclass
import threading


def _identifier(value):
    if not isinstance(value, str) or not value.strip() or '*' in value or '\x00' in value:
        raise ValueError('explicit nonempty identifier required')
    return value


@dataclass(frozen=True, slots=True, eq=False)
class Identity:
    principal: str
    kind: str


@dataclass(frozen=True, slots=True)
class AuthorityDecision:
    sequence: int
    allowed: bool
    reason: str
    initiating_principal: str | None
    initiating_organizer: str | None
    executing_agent: str | None
    machine: str
    operation: str
    authority_chain: tuple[str, ...]


class OrganizerAuthority:
    """Trusted local registry; never a caller-accessible role-management API.

    Enrollment, identities, organizer assignment and executor bindings come only
    from trusted provisioning. Revocation/liveness updates and decisions share a
    lock. Audit contains allowed and denied decisions in order, without secrets.
    Without a database instances are isolated. Explicit private SQLite persistence
    shares provisioning/revocation and ordered audit across instances; handles
    remain local and cannot be authenticated by a serialized principal claim.
    """

    def __init__(self, database=None):
        self._lock = threading.RLock()
        self._identities = {}
        self._organizers = set()
        self._machines = {}
        self._agents = {}
        self._execution_modes = {}
        self._audit = []
        self._backend = None
        if database is not None:
            from .organizer_durable import PolicyStorage
            self._backend = PolicyStorage(self, database)
            self._lock = self._backend

    def identity_handle(self, principal):
        """Trusted credential resolvers only; never authenticate a submitted name.

        Reopening persistence creates new process-local handles. Existing transport
        authentication must bind a credential to one of them independently.
        """
        with self._lock:
            if principal not in self._identities:
                raise PermissionError('identity was not provisioned')
            return self._identities[principal]

    def close(self):
        if self._backend is not None:
            self._backend.close()

    def _known(self, identity):
        return (type(identity) is Identity
                and self._identities.get(identity.principal) is identity)

    def _authority_changed(self):
        # Invalidate on each governed mutation, even revoke/re-enable within one
        # outer transaction whose final serialized state happens to be equal.
        if self._backend is not None:
            from .remote_effect_fence import assert_no_unsettled
            assert_no_unsettled(self._backend.db)
            self._backend.db.execute('UPDATE organizer_fence_state SET generation=generation+1 WHERE singleton=1')

    def provision_identity(self, principal, *, kind, organizer=False):
        """Trusted provisioning only. Principal and kind cannot be rebound.

        Persisted callers must supply immutable connected identity IDs, never
        reconstruct an identity from a display name. Legacy names require an
        explicit owner migration before this API is called. This registry does
        not infer identity from discovery metadata or grant OS executor powers.
        """
        principal = _identifier(principal)
        if kind not in ('internal', 'external') or type(organizer) is not bool:
            raise ValueError('explicit identity kind and boolean organizer required')
        if organizer and kind != 'internal':
            raise ValueError('external principals cannot be organizers')
        with self._lock:
            if principal in self._identities:
                raise ValueError('identity already provisioned')
            identity = Identity(principal, kind)
            self._authority_changed()
            self._identities[principal] = identity
            if organizer:
                self._organizers.add(principal)
            return identity

    def set_organizer(self, identity, enabled):
        """Trusted role assignment/revocation, not an organizer operation."""
        if type(enabled) is not bool:
            raise ValueError('boolean required')
        with self._lock:
            if not self._known(identity) or identity.kind != 'internal':
                raise PermissionError('trusted internal identity required')
            self._authority_changed()
            if enabled:
                self._organizers.add(identity.principal)
            else:
                self._organizers.discard(identity.principal)

    def enroll_machine(self, machine):
        """Trusted machine enrollment or explicit reconnection."""
        self.set_machine_state(machine, 'connected')

    def set_machine_state(self, machine, state):
        machine = _identifier(machine)
        if state not in ('connected', 'disconnected', 'unenrolled'):
            raise ValueError('invalid machine state')
        with self._lock:
            self._authority_changed()
            self._machines[machine] = state
            if state == 'unenrolled':
                self._agents = {principal: binding for principal, binding in self._agents.items()
                                if binding[0] != machine}

    def bind_agent(self, identity, *, machine, root=False):
        """Trusted attestation of an internal executor and its effective root."""
        machine = _identifier(machine)
        if type(root) is not bool:
            raise ValueError('boolean root required')
        with self._lock:
            if not self._known(identity) or identity.kind != 'internal':
                raise PermissionError('trusted internal executor required')
            self._authority_changed()
            self._agents[identity.principal] = (machine, root)
            self._execution_modes.pop(identity.principal,None)

    def bind_executor(self, identity, *, machine, environments):
        """Trusted provisioning of independently verified sandbox/host executors.

        Does not install an executor or infer OS isolation/privileges. The exact
        agent must already belong to this machine. Root retains its separate
        effective-root attestation; no mode implies any other mode.
        """
        machine=_identifier(machine)
        if not isinstance(environments,(tuple,list,frozenset,set)) or set(environments)-{'sandbox','host'}:
            raise ValueError('explicit supported executor modes required')
        with self._lock:
            if (not self._known(identity) or identity.kind!='internal'
                    or self._agents.get(identity.principal,(None,))[0]!=machine):
                raise PermissionError('exact bound internal executor required')
            self._authority_changed()
            self._execution_modes[identity.principal]=sorted(set(environments))

    def authorize(self, actor, *, operation, machine, executing_agent=None):
        """Default-deny decision on exact enrolled target; no role claim input.

        Management means permission to create/manage internal AMC agents, never
        permission to provision identity, change organizer roles, enroll machines,
        issue external grants, or promote an external principal.
        """
        operation, machine = _identifier(operation), _identifier(machine)
        with self._lock:
            known = self._known(actor)
            organizer = (known and actor.kind == 'internal'
                         and actor.principal in self._organizers)
            executor_known = self._known(executing_agent)
            principal = actor.principal if known else None
            executor = executing_agent.principal if isinstance(executing_agent, Identity) and executor_known else None
            reason = 'allowed'
            if not organizer:
                reason = 'authenticated organizer required'
            elif self._machines.get(machine) != 'connected':
                reason = 'connected enrolled machine required'
            elif operation in ('create_agent', 'manage_agent'):
                if executing_agent is not None:
                    reason = 'management does not delegate executor authority'
            elif operation == 'invoke_root':
                if (not executor_known or not isinstance(executing_agent, Identity)
                        or executing_agent.kind != 'internal'
                        or self._agents.get(executor) != (machine, True)):
                    reason = 'effective enrolled executor root required'
            elif operation in ('invoke_sandbox','invoke_host'):
                mode=operation.removeprefix('invoke_')
                if (not executor_known or executing_agent.kind!='internal'
                        or self._agents.get(executor,(None,))[0]!=machine
                        or mode not in self._execution_modes.get(executor,())):
                    reason = 'effective enrolled executor mode required'
            else:
                reason = 'operation outside organizer authority'
            allowed = reason == 'allowed'
            chain = ()
            if allowed:
                assert principal is not None
                if operation in ('invoke_root','invoke_sandbox','invoke_host'):
                    assert executor is not None
                    chain = (principal, executor, machine, operation.removeprefix('invoke_'))
                else:
                    chain = (principal, machine, operation)
            decision = AuthorityDecision(
                len(self._audit) + 1, allowed, reason, principal,
                principal if organizer else None, executor, machine, operation, chain)
            self._audit.append(decision)
            return decision

    def dispatch(self, actor, *, operation, machine, executing_agent=None):
        """Fresh abstract dispatch decision, never execute or replay a ticket."""
        from .replica_authority import assert_bound_authority
        assert_bound_authority()
        return self.authorize(actor, operation=operation, machine=machine,
                              executing_agent=executing_agent)

    def audit(self):
        """Trusted immutable snapshot, not an external enumeration endpoint."""
        with self._lock:
            return tuple(self._audit)
