"""Organizer-owned Harness² improvement records, not an independent agent.

Trusted local API, not a public command executor. ProbeSpec is provisioned by
trusted code, NEVER from a task/candidate or HTTP payload. The caller must supply
an OS-sandboxed, no-network/no-provider local checker when stronger isolation is
needed; a temporary working directory alone is not a security sandbox.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import sqlite3
from contextlib import closing
import subprocess
import sys
import tempfile
import time
import uuid

from .agent_sessions import AgentSessions, SessionRoute
from .brokers import _wait_owned_command, _cleanup_owned_command, _require_owned_command_support


PAPER = 'https://arxiv.org/html/2610.14224v1'
# These are inert data components consumed only by a separately trusted checker.
COMPONENTS = frozenset({'procedure', 'tool_guidance', 'domain_workflow'})


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def text(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 65536:
        raise ValueError('bounded nonempty text required')
    return value


def harness(value):
    if not isinstance(value, dict) or not value or not value.keys() <= COMPONENTS:
        raise ValueError('component outside closed improvement scope')
    return {k: text(v) for k, v in value.items()}


def input_path(name):
    """Return the same relative input spelling at admission and publication."""
    if not isinstance(name, str) or not name or any(c in name for c in ('\\', ':', '\x00')):
        raise ValueError('unsafe input path')
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or not path.parts:
        raise ValueError('unsafe input path')
    if path.parts[0] == 'inputs':
        if len(path.parts) < 2:
            raise ValueError('unsafe input path')
        return PurePosixPath(*path.parts[1:])
    if '/' in name or len(path.parts) != 1:
        raise ValueError('unsafe input path')
    return path


@dataclass(frozen=True)
class ProbeSpec:
    """Trusted deterministic local Python checker; no candidate commands."""
    script: Path
    script_digest: str
    timeout: float = 5

    @classmethod
    def from_script(cls, script, *, timeout=5):
        script = Path(script).resolve(strict=True)
        if isinstance(timeout, bool) or not math.isfinite(timeout) or not 0 < timeout <= 30:
            raise ValueError('probe timeout must be finite and at most 30 seconds')
        return cls(script, hashlib.sha256(script.read_bytes()).hexdigest(), timeout)

    def source(self):
        source = self.script.read_bytes()
        if hashlib.sha256(source).hexdigest() != self.script_digest:
            raise ValueError('trusted probe script drift')
        if not math.isfinite(self.timeout) or not 0 < self.timeout <= 30:
            raise ValueError('invalid probe timeout')
        return source


class HarnessImprovement:
    """One durable dedicated session per exact organizer/session-target scope.

    SQLite serializes lifecycle transitions, including local probe effects. All
    methods recheck existing organizer authority. Identity and authority objects
    are trusted process-local handles, never reconstructed from persisted claims.
    """

    def __init__(self, path, authority, actor, target, probe_spec: ProbeSpec):
        self.path = Path(path)
        self.authority, self.actor, self.target, self.spec = authority, actor, target, probe_spec
        self._authorize()
        probe_spec.source()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._transaction(initial=True) as state:
            scope = {'organizer': actor.principal, 'target': asdict(target)}
            if state:
                if state['scope'] != scope or state['probe_spec'] != self._spec_identity():
                    raise ValueError('persisted scope/probe specification mismatch')
            else:
                state.update(scope=scope, probe_spec=self._spec_identity(), tasks={}, library={},
                             session={'id': 'harness-improvement:' + str(uuid.uuid4()),
                                      'target': asdict(target), 'organizer': actor.principal,
                                      'purpose': 'main-organizer-harness-improvement',
                                      'native_status': 'not_opened', 'native_session_id': None})

    def _spec_identity(self):
        return {'script_digest': self.spec.script_digest, 'timeout': self.spec.timeout,
                'python': sys.executable}

    def _authorize(self):
        decision = self.authority.authorize(self.actor, operation='manage_agent', machine=self.target.machine_id)
        if not decision.allowed or self.target.agent_id != self.actor.principal:
            raise PermissionError('authenticated main organizer at exact own agent target required')
        return decision

    @contextmanager
    def _transaction(self, initial=False):
        self._authorize()
        with closing(sqlite3.connect(self.path, timeout=40)) as db, db:
            db.execute('CREATE TABLE IF NOT EXISTS improvement (singleton INTEGER PRIMARY KEY CHECK(singleton=1), payload TEXT NOT NULL)')
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT payload FROM improvement WHERE singleton=1').fetchone()
            state = json.loads(row[0]) if row else {}
            if not initial and state['scope'] != {'organizer': self.actor.principal, 'target': asdict(self.target)}:
                raise ValueError('persisted scope mismatch')
            yield state
            self._authorize()
            db.execute('INSERT OR REPLACE INTO improvement VALUES (1, ?)', (json.dumps(state, sort_keys=True),))

    def snapshot(self):
        with self._transaction() as state:
            return json.loads(json.dumps(state))

    def session(self):
        return self.snapshot()['session']

    def open_native(self, sessions: AgentSessions):
        """Explicit create via existing adapter; no provider invocation or retries.

        Persist intent before dispatch. Ambiguous failures require reconciliation,
        not a second new call. Native identity differs from durable purpose id.
        """
        with self._transaction() as state:
            if state['session']['native_status'] != 'not_opened':
                return dict(state['session'])
            state['session']['native_status'] = 'opening_requires_reconciliation'
        try:
            created = sessions.new(self.target)
        except Exception as exc:
            with self._transaction() as state:
                state['session'].update(native_status='handoff_required',
                    error_type=type(exc).__name__, handoff=(
                    'Wire trusted AgentSessions.new(target) for the exact persisted target; '
                    'reconcile metadata for any session created by the prior intent before retrying. '
                    'Bind its verified SessionMetadata.route.session_id to this purpose record; '
                    'do not provision an agent or invoke a provider.'))
                return dict(state['session'])
        with self._transaction() as state:
            state['session'].update(native_status='opened', native_session_id=created.route.session_id)
            return dict(state['session'])

    def start_task(self, task_id, baseline, inputs, *, max_runs=8, max_candidates=2, max_seconds=60):
        text(task_id)
        baseline = harness(baseline)
        for n in (max_runs, max_candidates):
            if type(n) is not int or not 1 <= n <= 32:
                raise ValueError('bounded positive integer budget required')
        if isinstance(max_seconds, bool) or not math.isfinite(max_seconds) or not 0 < max_seconds <= 600:
            raise ValueError('bounded wall-clock budget required')
        if not isinstance(inputs, dict) or len(inputs) > 64:
            raise ValueError('bounded input files required')
        canonical_inputs = {}
        for name, content in inputs.items():
            canonical = 'inputs/' + input_path(name).as_posix()
            if canonical in canonical_inputs:
                raise ValueError('duplicate input path')
            if not isinstance(content, str) or len(content) > 65536:
                raise ValueError('bounded text inputs required')
            canonical_inputs[canonical] = content
        inputs = canonical_inputs
        with self._transaction() as state:
            if task_id in state['tasks']:
                raise ValueError('task already exists; never replay completed tasks')
            state['tasks'][task_id] = dict(baseline=baseline, active=baseline, inputs=inputs,
                input_digest=digest(inputs), candidates={}, baseline_receipt=None, decisions=[],
                status='propose', runs=0, max_runs=max_runs, max_candidates=max_candidates,
                deadline=time.time() + max_seconds, library_snapshot=list(state['library']),
                paper=PAPER)
            return task_id

    def _task(self, state, task_id):
        t = state['tasks'][task_id]
        if t['status'] not in ('propose', 'probe'):
            raise ValueError('task stopped or terminal')
        if time.time() >= t['deadline']:
            raise ValueError('wall-clock budget exhausted')
        return t

    def propose(self, task_id, scope, patch, hypothesis):
        patch = harness(patch)
        text(hypothesis)
        if scope not in ('invariant', 'domain'):
            raise ValueError('invariant/domain scope required')
        with self._transaction() as state:
            t = self._task(state, task_id)
            if t['status'] != 'propose':
                raise ValueError('proposal pool frozen after probing starts')
            cid = digest([scope, patch, hypothesis])
            if cid in t['candidates']:
                return cid
            if len(t['candidates']) >= t['max_candidates']:
                raise ValueError('candidate budget exhausted')
            t['candidates'][cid] = dict(scope=scope, patch=patch, hypothesis=hypothesis,
                harness={**t['baseline'], **patch}, baseline_digest=digest(t['baseline']), receipt=None)
            return cid

    def _reserve(self, t, count):
        if t['runs'] + count > t['max_runs'] or time.time() >= t['deadline']:
            raise ValueError('probe run/time budget exhausted')
        t['runs'] += count

    @contextmanager
    def _effects(self):
        # Independent durable observations survive rollback of the lifecycle
        # transaction that spans the trusted local checker. Never used to retry.
        with closing(sqlite3.connect(self.path.with_name(self.path.name + '.effects.sqlite'))) as db, db:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('CREATE TABLE IF NOT EXISTS effects (id TEXT PRIMARY KEY, binding TEXT NOT NULL, receipt TEXT)')
            yield db

    def _run_recorded(self, t, configuration, slot):
        operation = t['pending_operation']
        dispatch_id = digest([operation['id'], slot])
        binding = dict(operation_id=operation['id'], slot=slot,
            script_digest=self.spec.script_digest, input_digest=t['input_digest'],
            harness_digest=digest(configuration))
        with self._effects() as db:
            # INSERT (not upsert) fences even an accidental same-operation retry.
            db.execute('INSERT INTO effects VALUES(?,?,NULL)', (dispatch_id, json.dumps(binding, sort_keys=True)))
        receipt = self._run(t, configuration)
        with self._effects() as db:
            db.execute('UPDATE effects SET receipt=? WHERE id=? AND receipt IS NULL',
                       (json.dumps(receipt, sort_keys=True), dispatch_id))
        return receipt

    def reconcile_interrupted(self, task_id, *, operation_id):
        """Trusted organizer-only terminal resolution, never automatic replay.

        The lifecycle write lock excludes a still-running second transaction.
        An earlier reserved caller that has not acquired it will see the terminal
        status and refuse dispatch. Completed observations are retained for human
        review; missing receipts remain uncertain, not fabricated no-effect proof.
        Legacy pending operations without a dispatch identity stay unresolved.
        """
        with self._transaction() as state:
            t = state['tasks'][task_id]
            operation = t.get('pending_operation')
            if (t['status'] not in {'probing_requires_reconciliation', 'composing_requires_reconciliation'}
                    or not operation or operation['id'] != operation_id):
                raise ValueError('exact interrupted operation identity required; legacy records need manual inspection')
            evidence = []
            with self._effects() as db:
                for slot, harness_digest in operation['runs'].items():
                    dispatch_id = digest([operation_id, slot])
                    row = db.execute('SELECT binding,receipt FROM effects WHERE id=?', (dispatch_id,)).fetchone()
                    expected = dict(operation_id=operation_id, slot=slot,
                        script_digest=self.spec.script_digest, input_digest=t['input_digest'],
                        harness_digest=harness_digest)
                    receipt = None
                    if row:
                        if json.loads(row[0]) != expected:
                            raise ValueError('dispatch evidence binding mismatch')
                        receipt = json.loads(row[1]) if row[1] else None
                        if receipt is not None and any(receipt.get(k) != expected[k]
                                for k in ('script_digest', 'input_digest', 'harness_digest')):
                            raise ValueError('effect receipt binding mismatch')
                    evidence.append(dict(dispatch_id=dispatch_id, binding=expected,
                        status='observed' if receipt is not None else ('uncertain' if row else 'not_dispatched'),
                        receipt=receipt))
            resolution = dict(status='interrupted', operation_id=operation_id,
                evidence=evidence, automatic_retry=False, adoption_authorized=False)
            t['status'] = 'interrupted'
            t['decisions'].append(resolution)
            # Budgets, prior active harness and all receipts/history are retained.
            return json.loads(json.dumps(resolution))

    def _run(self, t, configuration):
        source = self.spec.source()
        started = time.time()
        receipt = dict(id=str(uuid.uuid4()), argv=[sys.executable, '-I', '<isolated>/probe.py'],
            script_digest=self.spec.script_digest, harness_digest=digest(configuration),
            input_digest=t['input_digest'], returncode=None, stdout='', stderr='',
            truncated=False, failure=None, started_at=started, finished_at=started,
            process_started=False, environment='isolated-cwd-minimal-env-not-os-sandbox',
            evidence_kind='local_process_observation_not_quality_ground_truth')
        timeout = min(self.spec.timeout, t['deadline'] - started)
        deadline = time.monotonic() + max(0, timeout)
        if timeout <= 0:
            receipt['failure'] = 'deadline'
            return receipt
        scratch = Path(os.environ.get('TMPDIR', str(self.path.parent)))
        with tempfile.TemporaryDirectory(prefix='amc-probe-', dir=scratch) as directory:
            root = Path(directory)
            (root / 'harness.json').write_text(json.dumps(configuration, sort_keys=True), newline="\n")
            (root / 'probe.py').write_bytes(source)
            for name, content in t['inputs'].items():
                # Revalidate legacy persisted tasks too; never remove a prefix
                # from the unnormalized spelling and join a resulting absolute path.
                path = root / 'inputs' / input_path(name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, newline="\n")
            argv = [sys.executable, '-I', str(root / 'probe.py')]
            # Disk capture avoids unbounded pipe memory. Trusted checker owns its
            # own output limits; output is truncated in the durable receipt.
            with (root / 'stdout').open('w+b') as out, (root / 'stderr').open('w+b') as err:
                if time.monotonic() >= deadline or time.time() >= t['deadline']:
                    receipt.update(failure='deadline', finished_at=time.time())
                    return receipt
                _require_owned_command_support()
                process = subprocess.Popen(argv, cwd=root, env={'PATH': os.defpath,
                    'HOME': directory, 'TMPDIR': directory, 'LANG': 'C.UTF-8'},
                    stdin=subprocess.DEVNULL, stdout=out, stderr=err, start_new_session=True)
                failure = None
                try:
                    _wait_owned_command(process, deadline)
                except TimeoutError:
                    failure = 'timeout'
                finally:
                    # Preserve the unreaped leader identity through group cleanup.
                    _cleanup_owned_command(process)
                out.seek(0)
                err.seek(0)
                stdout, stderr = out.read(65537), err.read(65537)
            receipt.update(returncode=process.returncode,
                stdout=stdout[:65536].decode(errors='replace'), stderr=stderr[:65536].decode(errors='replace'),
                truncated=len(stdout) > 65536 or len(stderr) > 65536, failure=failure,
                finished_at=time.time(), process_started=True)
            return receipt

    @staticmethod
    def _ok(receipt):
        return receipt['returncode'] == 0 and not receipt.get('failure') and not receipt.get('truncated')

    def probe(self, task_id, candidate_id):
        with self._transaction() as state:
            t = self._task(state, task_id)
            c = t['candidates'][candidate_id]
            if c['receipt'] is not None:
                return json.loads(json.dumps(c['receipt']))
            self.spec.source()
            self._reserve(t, 1 + (t['baseline_receipt'] is None))
            # Commit budget and pending state BEFORE any process effects. A
            # crash cannot refund consumed work or cause automatic replay.
            t['status'] = 'probing_requires_reconciliation'
            t['pending_operation'] = dict(id=uuid.uuid4().hex, kind='probe',
                candidate_id=candidate_id, runs={
                    **({'baseline': digest(t['baseline'])} if t['baseline_receipt'] is None else {}),
                    'candidate': digest(c['harness'])})
        with self._transaction() as state:
            t = state['tasks'][task_id]
            if t['status'] != 'probing_requires_reconciliation':
                raise ValueError('probe stopped before dispatch')
            c = t['candidates'][candidate_id]
            if t['baseline_receipt'] is None:
                t['baseline_receipt'] = self._run_recorded(t, t['baseline'], 'baseline')
            candidate = self._run_recorded(t, c['harness'], 'candidate')
            t['status'] = 'probe'
            baseline = t['baseline_receipt']
            contrast = ('regression' if self._ok(baseline) and not self._ok(candidate) else
                        'process_recovery' if not self._ok(baseline) and self._ok(candidate) else
                        'no_supported_gain')
            c['receipt'] = dict(baseline=baseline, candidate=candidate, contrast=contrast,
                                candidate_id=candidate_id)
            return json.loads(json.dumps(c['receipt']))

    def compose(self, task_id, candidate_ids, observation):
        text(observation)
        if not isinstance(candidate_ids, list) or len(set(candidate_ids)) != len(candidate_ids):
            raise ValueError('unique candidate selection required')
        with self._transaction() as state:
            t = self._task(state, task_id)
            if t['baseline_receipt'] is None:
                raise ValueError('real baseline probe evidence required before compose')
            successor = dict(t['baseline'])
            merged = {}
            evidence = []
            for cid in candidate_ids:
                c = t['candidates'][cid]
                r = c['receipt']
                if r is None:
                    raise ValueError('real candidate probe evidence required')
                if r['contrast'] != 'process_recovery':
                    raise ValueError('unsupported change or regression; keep baseline')
                for key, value in c['patch'].items():
                    if key in merged and merged[key] != value:
                        raise ValueError('conflicting composition requires separate proposal/probe')
                    merged[key] = value
                evidence.append(r['candidate']['id'])
            successor.update(merged)
            self.spec.source()
            self._reserve(t, 1)
            t['status'] = 'composing_requires_reconciliation'
            t['pending_operation'] = dict(id=uuid.uuid4().hex, kind='compose',
                candidate_ids=list(candidate_ids), runs={'successor': digest(successor)})
        with self._transaction() as state:
            t = state['tasks'][task_id]
            if t['status'] != 'composing_requires_reconciliation':
                raise ValueError('composition stopped before dispatch')
            receipt = self._run_recorded(t, successor, 'successor')
            adopted = bool(candidate_ids) and self._ok(receipt)
            status = 'composed' if adopted else 'kept_baseline'
            t.update(status=status, active=successor if adopted else t['baseline'], successor=receipt,
                     selected=candidate_ids if adopted else [])
            t['decisions'].append(dict(status=status, observation=observation, evidence=evidence,
                successor_receipt=receipt['id'], rollback_required=bool(candidate_ids) and not adopted))
            return dict(status=status, active=t['active'], successor=receipt)

    def reflect(self, task_id, cue, lesson):
        text(cue)
        text(lesson)
        with self._transaction() as state:
            t = state['tasks'][task_id]
            if t['status'] != 'composed':
                raise ValueError('no supported adopted execution contrast; NO_ENTRY')
            pid = digest([task_id, cue, lesson])
            proposal = dict(id=pid, task_id=task_id, cue=cue, lesson=lesson,
                harness=t['active'], evidence=t['decisions'][-1], status='proposed_not_applied',
                transfer_verified=False, confidence='low: limited local deterministic process contrast',
                requires_organizer_review=True, paper=PAPER)
            state['library'].setdefault(pid, proposal)
            return json.loads(json.dumps(state['library'][pid]))

    def stop(self, task_id, reason):
        text(reason)
        with self._transaction() as state:
            t = state['tasks'][task_id]
            t['status'] = 'stopped'
            t['decisions'].append({'status': 'stopped', 'reason': reason})

    def rollback(self, task_id, reason):
        text(reason)
        with self._transaction() as state:
            t = state['tasks'][task_id]
            t.update(active=dict(t['baseline']), status='rolled_back')
            for entry in state['library'].values():
                if entry['task_id'] == task_id:
                    entry['status'] = 'withdrawn'
            t['decisions'].append({'status': 'rolled_back', 'reason': reason})
            return {'status': t['status'], 'active': dict(t['active'])}
