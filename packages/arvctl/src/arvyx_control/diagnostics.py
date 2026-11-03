"""Local, metadata-only diagnostics. Never part of the control event authority.

Capture does no disk/network I/O: a bounded queue feeds a daemon sink. Failures
are counted locally, not reported recursively. No exception strings or locals.
"""
from __future__ import annotations

import atexit
from collections import Counter
from contextvars import ContextVar
from contextlib import closing, contextmanager
import stat
from functools import wraps
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import sqlite3
import threading
import time
import uuid

from . import private_paths
from . import __version__

TRACE: ContextVar[str | None] = ContextVar('diagnostic_trace', default=None)
REPORTED: ContextVar[BaseException | None] = ContextVar('diagnostic_reported', default=None)
COMPONENTS = frozenset({'api', 'worker', 'dispatcher', 'watchdog', 'cli', 'mcp', 'delivery', 'browser', 'liveness'})


STORE_SCHEMA = {
    'groups': 'CREATE TABLE groups (fingerprint TEXT PRIMARY KEY, payload TEXT NOT NULL, count INTEGER NOT NULL, first REAL NOT NULL, last REAL NOT NULL)',
    'feed': 'CREATE TABLE feed (id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT NOT NULL, kind TEXT NOT NULL, time REAL NOT NULL)',
    'health': 'CREATE TABLE health (instance TEXT PRIMARY KEY, counters TEXT NOT NULL, heartbeat REAL NOT NULL)',
    'retention': 'CREATE TABLE retention (singleton INTEGER PRIMARY KEY CHECK(singleton=1), floor INTEGER NOT NULL)',
}
_LEGACY_STORE_SCHEMA = {k: v for k, v in STORE_SCHEMA.items() if k != 'retention'}


def _name(value):
    return value if isinstance(value, str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.<>-]{0,95}', value) else 'unknown'


# SQLite POSIX locks are process-scoped: raw header inspection must not close
# a descriptor while another local reporter owns a SQLite transaction.
_STORE_LOCK = threading.RLock()


def _serialized_read(fn):
    @wraps(fn)
    def run(*args, **kwargs):
        with _STORE_LOCK:
            return fn(*args, **kwargs)
    return run


class Reporter:
    def __init__(self, path, *, max_groups=512, retention_seconds=604800, regression_seconds=3600, observer=False):
        self.path = Path(path).absolute() if path else None
        self.observer = observer
        build = os.environ.get('ARVYX_RELEASE_BUILD_ID')
        self.release = (__version__ if build is None else
                        build if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', build) else 'invalid-build-id')
        self.instance = uuid.uuid4().hex
        self.max_groups = max(1, min(512, max_groups))
        self.retention_seconds = max(1, min(604800, retention_seconds))
        self.regression_seconds = max(0, regression_seconds)
        self.counts = Counter()
        self.queue = queue.Queue(maxsize=256)
        self.client_lock = threading.Lock()
        self.client_window = 0
        self.client_count = 0
        self.thread = None
        self.stopped = False
        if self.path and not self.observer:
            self.thread = threading.Thread(target=self._worker, name='amc-diagnostics', daemon=True)
            self.thread.start()

    def capture(self, exc, *, component, code, expected=False, trace_id=None):
        """Only fixed source codes and code-object metadata may cross this boundary."""
        trace = trace_id or TRACE.get() or uuid.uuid4().hex
        try:
            if expected:
                self.counts['expected'] += 1
                return trace
            if not self.path or self.stopped or self.observer:
                self.counts['disabled'] += 1
                return trace
            frames = []
            tb = exc.__traceback__
            visited = 0
            while tb is not None and len(frames) < 16 and visited < 64:
                visited += 1
                frame = tb.tb_frame
                module = frame.f_globals.get('__name__', '')
                # Source only, never filenames, source lines, arguments or locals.
                if isinstance(module, str) and (module.startswith(('arvyx_control.', 'arvyx_control_center_api.', 'test_diagnostics'))):
                    frames.append({'module': _name(module), 'function': _name(frame.f_code.co_name), 'line': tb.tb_lineno})
                tb = tb.tb_next
            component = component if component in COMPONENTS else 'unknown'
            event = {'component': component, 'code': _name(code), 'exception': _name(type(exc).__name__),
                     'frames': frames, 'release': self.release, 'trust': 'server', 'trace_id': trace}
            signature = {k: event[k] for k in ('component', 'code', 'exception', 'frames', 'release')}
            event['fingerprint'] = hashlib.sha256(json.dumps(signature, sort_keys=True).encode()).hexdigest()
            event['time'] = time.time()
            self.queue.put_nowait(event)
            self.counts['queued'] += 1
        except queue.Full:
            self.counts['queue_dropped'] += 1
        except Exception:
            self.counts['capture_failures'] += 1
        return trace

    def client(self, body):
        # Global process budget (not attacker-selected keys); no client text is saved.
        with self.client_lock:
            window = int(time.monotonic() // 60)
            if window != self.client_window:
                self.client_window, self.client_count = window, 0
            if self.client_count >= 20:
                self.counts['rate_limited'] += 1
                return None
            self.client_count += 1
        kind = body.get('kind') if isinstance(body, dict) else None
        code = kind if kind in {'error', 'unhandledrejection', 'fetch'} else 'error'
        return self.capture(RuntimeError(), component='browser', code=code)

    def _validate_store(self, db):
        # Identity reads precede every writable PRAGMA or schema operation.
        if (db.execute('PRAGMA application_id').fetchone()[0] != 0x414D4344
                or db.execute('PRAGMA user_version').fetchone()[0] != 1):
            raise ValueError('not a dedicated diagnostic store')
        schema = dict(db.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name!='sqlite_sequence'"))
        if schema != STORE_SCHEMA and schema != _LEGACY_STORE_SCHEMA:
            raise ValueError('unexpected diagnostic schema')

    def _initialize(self):
        # Publish a COMPLETE identified store atomically, never an empty placeholder.
        # Hard-link publication cannot overwrite another creator or a foreign file.
        import tempfile
        assert self.path is not None
        fd, name = tempfile.mkstemp(prefix='.amc-diagnostics-', dir=self.path.parent)
        os.close(fd)
        temporary = Path(name)
        try:
            with closing(sqlite3.connect(temporary)) as db:
                with db:
                    db.execute('PRAGMA application_id=0x414D4344')
                    db.execute('PRAGMA user_version=1')
                    for sql in STORE_SCHEMA.values():
                        db.execute(sql)
            try:
                os.link(temporary, self.path)
            except FileExistsError:
                pass
        finally:
            temporary.unlink()

    def _check_path(self):
        assert self.path is not None
        mode = self.path.lstat().st_mode
        if not stat.S_ISREG(mode) or not private_paths.is_private_mode(mode, path=self.path):
            raise PermissionError('unsafe diagnostic store')
        # Inspect identity without opening SQLite: foreign files (including WAL)
        # must never acquire SQLite sidecars or trigger journal recovery.
        with self.path.open('rb') as source:
            header = source.read(100)
        if (len(header) != 100 or header[:16] != b'SQLite format 3\x00'
                or header[18:20] != b'\x01\x01'
                or int.from_bytes(header[68:72], 'big') != 0x414D4344
                or int.from_bytes(header[60:64], 'big') != 1):
            raise ValueError('not a dedicated diagnostic store')
        # Use normal SQLite locking, not immutable=1 on a live mutable database.
        with closing(sqlite3.connect(self.path.as_uri() + '?mode=ro', uri=True, timeout=.2)) as db:
            self._validate_store(db)

    @contextmanager
    def _connect(self):
        with _STORE_LOCK:
            with self._locked_connect() as db:
                yield db

    @contextmanager
    def _locked_connect(self):
        assert self.path is not None
        if self.observer:
            raise PermissionError('diagnostic observer is read-only')
        try:
            self.path.lstat()
        except FileNotFoundError:
            self._initialize()
        self._check_path()
        db = sqlite3.connect(self.path.as_uri() + '?mode=rw', uri=True, timeout=.2)
        try:
            with db:
                db.execute('BEGIN IMMEDIATE')
                self._validate_store(db)
                db.execute('PRAGMA max_page_count=4096')
                if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='retention'").fetchone():
                    db.execute(STORE_SCHEMA['retention'])
                # AUTOINCREMENT's durable high-water survives an empty feed.
                # Bootstrap legacy stores without resetting their lost history.
                high = db.execute("SELECT seq FROM sqlite_sequence WHERE name='feed'").fetchone()
                minimum = db.execute('SELECT min(id) FROM feed').fetchone()[0]
                floor = minimum - 1 if minimum is not None else (high[0] if high else 0)
                db.execute('INSERT OR IGNORE INTO retention VALUES(1,?)', (floor,))
                yield db
        finally:
            db.close()

    def _store(self, event):
        event = dict(event)  # retries must retain the original immutable queued metadata
        with self._connect() as db:
            now = event.pop('time')
            fp = event['fingerprint']
            if event['component'] == 'browser':
                event['trust'] = 'untrusted-client'
            db.execute('DELETE FROM groups WHERE last < ?', (now - self.retention_seconds,))
            prior = db.execute('SELECT last FROM groups WHERE fingerprint=?', (fp,)).fetchone()
            kind = 'NEW' if prior is None else ('REGRESSED' if now - prior[0] >= self.regression_seconds else None)
            db.execute('INSERT INTO groups VALUES (?, ?, 1, ?, ?) ON CONFLICT(fingerprint) DO UPDATE SET payload=CASE WHEN excluded.last>=last THEN excluded.payload ELSE payload END, count=count+1, first=min(first,excluded.first), last=max(last,excluded.last)', (fp, json.dumps(event, sort_keys=True), now, now))
            if kind:
                db.execute('INSERT INTO feed(fingerprint,kind,time) VALUES (?,?,?)', (fp, kind, now))
            # Ties on `last` are real where the clock is coarse (Windows before Python
            # 3.13 reports time.time() in 15.6 ms steps): the newest group wins them.
            db.execute('DELETE FROM groups WHERE fingerprint NOT IN (SELECT fingerprint FROM groups ORDER BY last DESC, rowid DESC LIMIT ?)', (self.max_groups,))
            prune = 'id NOT IN (SELECT id FROM feed ORDER BY id DESC LIMIT 1024) OR time < ?'
            # Record the highest lost cursor in the SAME transaction as pruning,
            # including non-prefix expiry from out-of-order observations.
            removed = db.execute('SELECT max(id) FROM feed WHERE ' + prune, (now-self.retention_seconds,)).fetchone()[0]
            if removed is not None:
                db.execute('UPDATE retention SET floor=max(floor,?) WHERE singleton=1', (removed,))
            db.execute('DELETE FROM feed WHERE ' + prune, (now-self.retention_seconds,))
            db.execute('INSERT INTO health VALUES (?,?,?) ON CONFLICT(instance) DO UPDATE SET counters=excluded.counters, heartbeat=excluded.heartbeat', (self.instance, json.dumps(dict(self.counts)), time.time()))

    def _health(self):
        with self._connect() as db:
            db.execute('INSERT INTO health VALUES (?,?,?) ON CONFLICT(instance) DO UPDATE SET counters=excluded.counters, heartbeat=excluded.heartbeat', (self.instance, json.dumps(dict(self.counts)), time.time()))
            db.execute('DELETE FROM health WHERE heartbeat < ? OR instance NOT IN (SELECT instance FROM health ORDER BY heartbeat DESC LIMIT 128)', (time.time()-self.retention_seconds,))

    def _retry(self, action):
        # Only SQLite BUSY/LOCKED is safely retryable after transaction rollback.
        # No waits happen on the domain thread; permanent I/O failures drop visibly.
        for attempt in range(3):
            try:
                action()
                return
            except sqlite3.OperationalError as exc:
                if getattr(exc, 'sqlite_errorcode', 0) & 255 not in {5, 6} or attempt == 2:
                    raise
                self.counts['sink_retries'] += 1

    def _worker(self):
        while True:
            try:
                event = self.queue.get(timeout=10)
            except queue.Empty:
                try:
                    self._retry(self._health)
                except Exception:
                    self.counts['sink_failures'] += 1
                continue
            try:
                if event is None:
                    return
                if event == 'health':
                    self._retry(self._health)
                else:
                    self._retry(lambda: self._store(event))
                    self.counts['stored'] += 1
            except Exception:
                self.counts['sink_failures'] += 1
            finally:
                self.queue.task_done()

    def flush(self, timeout=2):
        if self.path and not self.stopped and not self.observer:
            try:
                self.queue.put_nowait('health')
            except queue.Full:
                pass
        deadline = time.monotonic() + timeout
        while self.queue.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(.005)
        return not self.queue.unfinished_tasks

    def close(self):
        self.flush()
        self.stopped = True
        if self.thread:
            try:
                self.queue.put_nowait(None)
            except queue.Full:
                pass
            # Bounded, but long enough for an in-flight store to finish and release
            # its connection: Windows cannot delete the store while it is open.
            self.thread.join(timeout=5)

    @_serialized_read
    def read(self, fingerprint=None):
        status: dict = {key: self.counts[key] for key in ('queued', 'stored', 'disabled', 'expected', 'queue_dropped', 'capture_failures', 'sink_failures', 'sink_retries', 'rate_limited')}
        status.update({'enabled': self.path is not None, 'queue_depth': self.queue.qsize(), 'counter_scope': 'this-process', 'retention_seconds': self.retention_seconds, 'max_groups': self.max_groups, 'max_feed': 1024, 'max_database_bytes': 16777216, 'available': False})
        status.update(persisted_counters={}, last_sink_heartbeat=None)
        groups = []
        if self.path:
            try:
                self._check_path()
                with closing(sqlite3.connect(self.path.as_uri() + '?mode=ro', uri=True, timeout=.2)) as db:
                    self._validate_store(db)
                    rows = db.execute('SELECT payload,count,first,last FROM groups WHERE last>=? ORDER BY last DESC LIMIT 512', (time.time()-self.retention_seconds,)).fetchall()
                    health = db.execute('SELECT counters,heartbeat FROM health ORDER BY heartbeat DESC LIMIT 128').fetchall()
                totals = Counter()
                for counters, heartbeat in health:
                    totals.update(json.loads(counters))
                status['persisted_counters'] = dict(totals)
                status['last_sink_heartbeat'] = max((h for _, h in health), default=None)
                groups = [dict(json.loads(p), count=c, first_seen=f, last_seen=l) for p,c,f,l in rows]
                if fingerprint:
                    groups = [g for g in groups if g['fingerprint'] == fingerprint]
                status['available'] = True
            except Exception:
                status['read_failed'] = True
        return {'status': status, 'groups': groups}

    @_serialized_read
    def feed(self, after=0, limit=100):
        after = max(0, int(after))
        result = {'events': [], 'cursor': after, 'checkpoint': after, 'gap': False, 'status': self.read()['status']}
        if not self.path:
            return result
        try:
            self._check_path()
            with closing(sqlite3.connect(self.path.as_uri() + '?mode=ro', uri=True, timeout=.2)) as db:
                self._validate_store(db)
                minimum = db.execute('SELECT min(id) FROM feed').fetchone()[0]
                if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='retention'").fetchone():
                    retained = db.execute('SELECT floor FROM retention WHERE singleton=1').fetchone()
                else:
                    retained = None
                high = db.execute("SELECT seq FROM sqlite_sequence WHERE name='feed'").fetchone()
                floor = max(retained[0] if retained else 0,
                            minimum - 1 if minimum is not None else (high[0] if high else 0))
                resume = max(after, floor)
                rows = db.execute('SELECT feed.id,feed.fingerprint,feed.kind,feed.time,groups.payload,groups.count FROM feed LEFT JOIN groups ON groups.fingerprint=feed.fingerprint WHERE feed.id>? ORDER BY feed.id LIMIT ?', (resume, max(1,min(100,int(limit))))).fetchall()
            result['gap'] = after < floor
            result['cursor'] = result['checkpoint'] = resume
            result['events'] = []
            for i, f, k, t, payload, count in rows:
                metadata = json.loads(payload) if payload else {}
                result['events'].append(dict(cursor=i, fingerprint=f, kind=k, time=t, severity='error', source='amc-diagnostics',
                                             component=metadata.get('component', 'pruned'), trust=metadata.get('trust', 'unknown'),
                                             release=metadata.get('release'), count=count, trace_id=metadata.get('trace_id'),
                                             detail_path='/diagnostics/groups/'+f))
            if rows:
                result['cursor'] = rows[-1][0]
                result['checkpoint'] = result['cursor']
        except Exception:
            result['status']['read_failed'] = True
        return result


_reporter = None
_reporter_lock = threading.Lock()


def get_reporter():
    global _reporter
    if _reporter is None:
        with _reporter_lock:
            if _reporter is None:
                _reporter = Reporter(os.environ.get('ARVYX_DIAGNOSTICS_DB'))
                atexit.register(_reporter.close)
    return _reporter


def capture(exc, *, component, code, expected=False):
    try:
        return get_reporter().capture(exc, component=component, code=code, expected=expected)
    except Exception:
        return None


def boundary(component):
    """Explicit entrypoint only: report then re-raise; domain semantics unchanged."""
    def decorate(fn):
        @wraps(fn)
        def run(*args, **kwargs):
            root = TRACE.get() is None
            reported_token = REPORTED.set(None) if root else None
            token = TRACE.set(TRACE.get() or uuid.uuid4().hex)
            try:
                return fn(*args, **kwargs)
            except Exception as exc:
                if REPORTED.get() is not exc:
                    capture(exc, component=component, code='boundary', expected=isinstance(exc, ValueError))
                    REPORTED.set(exc)
                raise
            finally:
                TRACE.reset(token)
                if reported_token is not None:
                    REPORTED.reset(reported_token)
        return run
    return decorate


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description='Local operator diagnostics (OS file permissions apply).')
    parser.add_argument('command', choices=['status', 'list', 'feed', 'canary'])
    parser.add_argument('--after', type=int, default=0, help='Last acknowledged monotonic feed cursor')
    args = parser.parse_args(argv)
    if args.command == 'canary':
        from .diagnostics_canary import run
        result = run()
    else:
        reporter = Reporter(os.environ.get('ARVYX_DIAGNOSTICS_DB'), observer=True)
        result = reporter.feed(args.after) if args.command == 'feed' else reporter.read()
        if args.command == 'status':
            result.pop('groups', None)
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get('ok', not result.get('status', {}).get('read_failed', False)) else 1


if __name__ == '__main__':
    raise SystemExit(main())
