"""Local sanitized work capture/outbox and explicit native transcript records.

Not workspace backup, curated memory, or automatic unauthenticated publication.
Secret-shape screening is not a guarantee against all possible sensitive text.
"""
import codecs
import hashlib
import json
import re
import uuid
from types import SimpleNamespace
from .control import _reject_secret_shaped_text

TRANSCRIPT_CAPACITY = 16 * 1024 * 1024
ARCHIVE_PAGE_BYTES = 900 * 1024  # Includes JSON escaping; room for transport envelope.


def _transcript_charge_sql(prefix=''):
    # Payload, duplicated unique/session index identifiers, and row/page allowance.
    return '512+' + '+'.join(
        str(multiplier) + '*LENGTH(CAST(' + prefix + field + ' AS BLOB))'
        for field, multiplier in (('event_id', 2), ('session', 2), ('source', 1), ('text', 1), ('sha256', 1)))


CAPTURE_CAPACITY = 256 * 1024 * 1024
_PEM_MARKER = re.compile(rb'(BEGIN|END) ((?:(?:RSA|OPENSSH|EC|DSA|ENCRYPTED) )?PRIVATE KEY)$')
_PEM_TOKENS = tuple((kind + ' ' + prefix + 'PRIVATE KEY').encode('ascii')
                    for kind in ('BEGIN', 'END')
                    for prefix in ('', 'RSA ', 'OPENSSH ', 'EC ', 'DSA ', 'ENCRYPTED '))
_PEM_PREFIXES = frozenset(token[:end] for token in _PEM_TOKENS for end in range(1, len(token) + 1))
# Python IGNORECASE includes these non-ASCII equivalents; canonical markers
# also admit Unicode whitespace after BEGIN/END. Keep UTF-8 prefix state bounded.
_PEM_UTF8 = {char.encode('utf-8'): value for char, value in
             [('İ', ord('I')), ('ı', ord('I')), ('ſ', ord('S')), ('K', ord('K'))]}
_PEM_UTF8.update({chr(code).encode('utf-8'): 32 for code in
                  (0x85, 0xa0, 0x1680, *range(0x2000, 0x200b), 0x2028, 0x2029, 0x202f, 0x205f, 0x3000)})
_PEM_UTF8_PREFIXES = frozenset(token[:end] for token in _PEM_UTF8 for end in range(1, len(token)))


def _screen_pem(state, data):
    """Bounded streaming equivalent of canonical delimiter context.

    Labels match case-insensitively; True is an irrevocably poisoned nested
    block, a label is an active block, and False is outside a block.
    Whitespace normalization is conservative for terminal/control boundaries.
    """
    touched = bool(state.private_block)
    for byte in data:
        if byte >= 128 or state.screen_candidate:
            candidate = (state.screen_candidate or b'') + bytes([byte])
            state.screen_candidate = None
            if candidate in _PEM_UTF8_PREFIXES:
                state.screen_candidate = candidate
                continue
            if candidate in _PEM_UTF8:
                byte = _PEM_UTF8[candidate]
                if byte != 32 and (state.screen_tail or state.private_block):
                    # Canonical label.upper() preserves some Unicode distinctions;
                    # never let normalization make an uncertain ending close it.
                    state.private_block = True
                    touched = True
            else:
                # Unknown or incomplete UTF-8 must not disappear into a valid
                # END delimiter. Preserve uncertainty across feeds and reopen.
                if state.private_block:
                    state.private_block = True
                    touched = True
                state.screen_tail = b''
                if byte >= 128:
                    continue
        if state.screen_escape == 'escape':
            state.screen_escape = 'csi' if byte == ord('[') else None
            continue
        if state.screen_escape == 'csi':
            if 0x40 <= byte <= 0x7e:
                state.screen_escape = None
            continue
        if byte == 0x1b:
            state.screen_escape = 'escape'
            continue
        if byte in b' \t\r\n\v\f\x1c\x1d\x1e\x1f':
            if state.screen_tail.endswith(b' '):
                continue
            byte = 32
        elif byte < 32 or byte > 126:
            continue
        state.screen_tail = (state.screen_tail + bytes([byte]).upper())[-64:]
        match = _PEM_MARKER.search(state.screen_tail)
        if match:
            kind, label = match.groups()
            if kind == b'BEGIN':
                state.private_block = True if state.private_block else label.decode('ascii')
                touched = True
            elif state.private_block == label.decode('ascii'):
                state.private_block = False
            state.screen_tail = b''
        else:
            # Persist only a known delimiter prefix, never a rolling body tail.
            while state.screen_tail and state.screen_tail not in _PEM_PREFIXES:
                state.screen_tail = state.screen_tail[1:]
    return touched


class ContextProvenanceRequired(ValueError):
    """Legacy syntax cannot prove that Unicode uncertainty was preserved."""


def _context_state(raw) -> dict:
    try:
        if not isinstance(raw, str) or len(raw) > 2048:
            raise ValueError
        value = json.loads(raw)
        if type(value) is not dict:
            raise ValueError
        if set(value) in ({'version', 'state'}, {'version', 'state', 'archive_run'}) and type(value['version']) is int and value['version'] == 2:
            value = dict(schema=2, state=value['state'], archive_run=value.get('archive_run'))
        if set(value) != {'schema', 'state', 'archive_run'} or type(value['schema']) is not int or value['schema'] != 2:
            raise ValueError
        state = value['state']
        if type(state) is not list or len(state) != 4:
            raise ValueError
        private, tail, escape, candidate = state
        labels = {token.decode().removeprefix('BEGIN ') for token in _PEM_TOKENS if token.startswith(b'BEGIN ')}
        if not (type(private) is bool or type(private) is str and private in labels):
            raise ValueError
        if type(tail) is not str or (tail and tail.encode('ascii') not in _PEM_PREFIXES):
            raise ValueError
        if escape not in (None, 'escape', 'csi') or type(candidate) is not str:
            raise ValueError
        decoded = bytes.fromhex(candidate)
        if decoded and decoded not in _PEM_UTF8_PREFIXES:
            raise ValueError
        run = value['archive_run']
        if run is not None and (not isinstance(run, str) or not re.fullmatch(r'native-v2-[a-f0-9]{32}', run)):
            raise ValueError
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ContextProvenanceRequired('legacy or invalid scanner provenance; inspect_capture_context and confirmed reconcile_capture_context required; history retained') from None


def _context_dump(state, archive_run=None):
    value: dict = dict(version=2, state=[state.private_block, state.screen_tail.decode('ascii'),
        state.screen_escape, (state.screen_candidate or b'').hex()])
    if archive_run is not None:
        value['archive_run'] = archive_run
    raw = json.dumps(value)
    _context_state(raw)
    return raw


def _native_source_key(sid, binding, runtime):
    # Paths and incarnation, not content timestamps: ordinary DB appends are safe.
    home, store = runtime.home.resolve(strict=True), runtime.store.resolve(strict=True)
    h, d = home.stat(), store.stat()
    identity = [sid, binding['tool'], binding['conversation'], str(home),
                h.st_dev, h.st_ino, str(store), d.st_dev, d.st_ino]
    return hashlib.sha256(json.dumps(identity).encode()).hexdigest()


def _native_context_key(owner, sid, actor):
    binding = owner.native(sid, actor=actor)
    if binding is None or binding['tool'] not in owner.native_runtimes:
        raise ValueError('explicit verified native runtime required')
    runtime = owner.native_runtimes[binding['tool']]
    runtime.plan(binding['conversation'], owner._get(sid)['workspace'])
    return _native_source_key(sid, binding, runtime), binding, runtime


def inspect_context_recovery(owner, sid, *, actor, kind):
    """A digest of exact retained context/authority, never secret-bearing state."""
    owner._human(actor)
    if kind not in ('capture', 'native'):
        raise ValueError('exact capture or native context required')
    with owner.lock:
        _capture_schema(owner)
        key = sid
        native = None
        if kind == 'native':
            key, binding, runtime = _native_context_key(owner, sid, actor)
            if owner.db.execute("SELECT 1 FROM sqlite_master WHERE name='native_archive_context'").fetchone() is None:
                raise ValueError('no retained native context to reconcile')
            row = owner.db.execute('SELECT cursor,pem FROM native_archive_context WHERE run=?', (key,)).fetchone()
            info = runtime.store.stat()
            native = [binding, [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns]]
        else:
            row = owner.db.execute('SELECT pem FROM capture_screen_context WHERE session=?', (sid,)).fetchone()
        runs = [tuple(r) for r in owner.db.execute('SELECT run,status FROM capture_runs WHERE session=? ORDER BY run LIMIT 10001', (sid,))]
        if len(runs) > 10000:
            raise ValueError('context recovery run budget exceeded; history retained')
        boundary = dict(session=sid, kind=kind, key=key, context=list(row) if row else None,
            runs=runs, native=native, owner_incarnation=getattr(owner, 'incarnation', None),
            legacy_native_cursor=(tuple(owner.db.execute('SELECT cursor FROM native_archive_cursor WHERE session=?',(sid,)).fetchone() or ()) if kind=='native' else None),
            records=tuple(owner.db.execute('SELECT COUNT(*),COALESCE(MAX(sequence),0) FROM work_capture WHERE session=?', (sid,)).fetchone()))
        digest = hashlib.sha256(json.dumps(boundary, sort_keys=True).encode()).hexdigest()
        return dict(session=sid, kind=kind, sha256=digest, recovery='fresh-stopped-stream' if kind == 'capture' else 'reimport-from-zero-retain-original-history')


def reconcile_context(owner, sid, *, actor, kind, expected, confirmed=False, clean_boundary_confirmed=False):
    """Explicit operator recovery. No retained archive record is changed/deleted.

    Capture requires an attested new clean stream after process termination.
    Native import always rescans from zero in a new event namespace. The old
    context remains quarantined and charged, including closed/false ambiguity.
    """
    owner._human(actor)
    if confirmed is not True:
        raise ValueError('explicit context recovery confirmation required')
    with owner.lock, owner.db:
        if not owner.db.in_transaction:
            owner.db.execute('BEGIN IMMEDIATE')
        proof = inspect_context_recovery(owner, sid, actor=actor, kind=kind)
        if expected != proof:
            raise ValueError('exact current context recovery proof required')
        current = owner._get(sid)
        cleanup = owner.db.execute("SELECT 1 FROM sqlite_master WHERE name='cleanup_ownership'").fetchone()
        if (sid in owner.live or current.get('status') not in ('stopped','ended') or current.get('pid') is not None
                or cleanup and owner.db.execute('SELECT 1 FROM cleanup_ownership WHERE session=?', (sid,)).fetchone()):
            raise ValueError('stopped owner session with no live process required')
        if kind == 'capture' and clean_boundary_confirmed is not True:
            raise ValueError('separate clean stream boundary attestation required; old history is not clearance')
        from .public_onboarding_api import assert_request_active
        assert_request_active()
        key = sid if kind == 'capture' else _native_context_key(owner, sid, actor)[0]
        table, column = ('capture_screen_context', 'session') if kind == 'capture' else ('native_archive_context', 'run')
        row = owner.db.execute('SELECT pem FROM '+table+' WHERE '+column+'=?', (key,)).fetchone()
        if row is not None:
            try:
                _context_state(row[0])
            except ContextProvenanceRequired:
                pass
            else:
                parsed=_context_state(row[0])
                if kind!='capture' or not parsed['state'][0]:
                    raise ValueError('current clear context is not recovery authority')
        retained = 'quarantine-' + proof['sha256']
        charge = 2048 + len(sid.encode()) + len(retained.encode())
        used = owner.db.execute('SELECT bytes+metadata_bytes FROM capture_accounting WHERE id=1').fetchone()[0]
        if used + charge > _capture_limit(owner):
            raise BufferError('context recovery capacity reached; history and context retained')
        owner.db.execute('CREATE TABLE IF NOT EXISTS capture_context_reconciliations(sha256 TEXT PRIMARY KEY,session TEXT NOT NULL,kind TEXT NOT NULL)')
        owner.db.execute('INSERT INTO capture_context_reconciliations VALUES(?,?,?)', (proof['sha256'], sid, kind))
        # Existing context is moved, never interpreted as a new scanner state.
        owner.db.execute('UPDATE '+table+' SET '+column+'=? WHERE '+column+'=?', (retained, key))
        state = SimpleNamespace(private_block=False, screen_tail=b'', screen_escape=None, screen_candidate=None)
        raw = _context_dump(state, None if kind == 'capture' else 'native-v2-'+proof['sha256'][:32])
        if kind == 'capture':
            owner.db.execute('INSERT INTO capture_screen_context VALUES(?,?)', (sid, raw))
        else:
            owner.db.execute('INSERT INTO native_archive_context VALUES(?,?,0,?)', (key, sid, raw))
            owner.db.execute('INSERT OR REPLACE INTO native_archive_cursor VALUES(?,0)', (sid,))
            owner.db.execute('CREATE TABLE IF NOT EXISTS native_archive_cursor_provenance(session TEXT PRIMARY KEY,context_id TEXT NOT NULL)')
            owner.db.execute('INSERT OR REPLACE INTO native_archive_cursor_provenance VALUES(?,?)',(sid,key))
        owner.db.execute('UPDATE capture_accounting SET metadata_bytes=metadata_bytes+? WHERE id=1', (1024+len(retained.encode()),))
        return dict(reconciled=True, history_retained=True, **proof)


def _schema(owner):
    owner.db.execute('''CREATE TABLE IF NOT EXISTS transcript_records (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE NOT NULL,
        session TEXT NOT NULL, source TEXT NOT NULL, text TEXT NOT NULL, sha256 TEXT NOT NULL)''')
    owner.db.execute('CREATE INDEX IF NOT EXISTS transcript_session_sequence ON transcript_records(session,sequence)')
    owner.db.execute('CREATE TABLE IF NOT EXISTS transcript_accounting(id INTEGER PRIMARY KEY CHECK(id=1), bytes INTEGER NOT NULL CHECK(bytes>=0))')
    if owner.db.execute('SELECT 1 FROM transcript_accounting WHERE id=1').fetchone() is None:
        owner.db.execute('INSERT INTO transcript_accounting SELECT 1,COALESCE(SUM(' + _transcript_charge_sql() + '),0) FROM transcript_records')
    for action, timing, change in (
        ('insert', 'INSERT', '+' + _transcript_charge_sql('new.')),
        ('delete', 'DELETE', '-(' + _transcript_charge_sql('old.') + ')'),
        ('update', 'UPDATE', '-(' + _transcript_charge_sql('old.') + ')+(' + _transcript_charge_sql('new.') + ')')):
        owner.db.execute('CREATE TRIGGER IF NOT EXISTS transcript_' + action + ' AFTER ' + timing + ' ON transcript_records BEGIN UPDATE transcript_accounting SET bytes=bytes' + change + ' WHERE id=1; END')


def records(owner, sid, *, actor, after=0):
    owner._human(actor)
    if type(after) is not int or after < 0:
        raise ValueError('invalid archive cursor')
    with owner.lock:
        owner._get(sid)
        _schema(owner)
        page = {'records': [], 'next_after': after, 'has_more': False}
        used = 256  # Envelope, cursor and delimiters, independent of record content.
        for row in owner.db.execute('SELECT * FROM transcript_records WHERE session=? AND sequence>? ORDER BY sequence LIMIT 101', (sid, after)):
            record = dict(row)
            charge = len(json.dumps(record).encode('utf-8')) + 2
            if len(page['records']) == 100 or used + charge > ARCHIVE_PAGE_BYTES:
                if not page['records']:
                    raise ValueError('archive record exceeds page budget; history retained')
                page['has_more'] = True
                break
            page['records'].append(record)
            page['next_after'] = record['sequence']
            used += charge
        return page


def append_record(owner, sid, *, event_id, source, text, actor):
    owner._human(actor)
    if not isinstance(event_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', event_id):
        raise ValueError('explicit bounded event ID required')
    if source not in {'native-transcript', 'operator-note', 'terminal-preview'}:
        raise ValueError('explicit transcript provenance required')
    if not isinstance(text, str) or not text.strip() or len(text.encode()) > 65536:
        raise ValueError('bounded transcript text required')
    _reject_secret_shaped_text(transcript=text)
    digest = hashlib.sha256((sid + '\x00' + source + '\x00' + text).encode()).hexdigest()
    with owner.lock, owner.db:
        if not owner.db.in_transaction:
            owner.db.execute('BEGIN IMMEDIATE')
        owner._get(sid)
        _schema(owner)
        previous = owner.db.execute('SELECT * FROM transcript_records WHERE event_id=?', (event_id,)).fetchone()
        if previous:
            if previous['sha256'] != digest:
                raise ValueError('archive event conflict')
            return dict(previous)
        size = owner.db.execute('SELECT bytes FROM transcript_accounting WHERE id=1').fetchone()[0]
        charge = 512 + sum(len(value.encode()) * multiplier for value, multiplier in
                           ((event_id, 2), (sid, 2), (source, 1), (text, 1), (digest, 1)))
        if size + charge > TRANSCRIPT_CAPACITY:
            raise ValueError('local archive capacity reached; no silent retention deletion')
        owner.db.execute('INSERT INTO transcript_records(event_id,session,source,text,sha256) VALUES (?, ?, ?, ?, ?)', (event_id, sid, source, text, digest))
        owner.db.commit()
        return dict(owner.db.execute('SELECT * FROM transcript_records WHERE event_id=?', (event_id,)).fetchone())


def _metadata_sql(prefix=''):
    # Fixed row/index allowance also bounds synchronization work for empty lines.
    return '256+' + '+'.join('LENGTH(CAST(' + prefix + field + ' AS BLOB))'
                            for field in ('event_id', 'session', 'run'))


def _record_charge(event_id, sid, run, text):
    return 256 + sum(len(value.encode('utf-8')) for value in (event_id, sid, run, text))


def _capture_schema(owner):
    owner.db.execute('''CREATE TABLE IF NOT EXISTS work_capture (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE NOT NULL,
        session TEXT NOT NULL, run TEXT NOT NULL, text TEXT NOT NULL,
        delivered INTEGER NOT NULL DEFAULT 0)''')
    owner.db.execute('CREATE INDEX IF NOT EXISTS work_capture_pending ON work_capture(sequence) WHERE delivered=0')
    owner.db.execute('CREATE TABLE IF NOT EXISTS capture_delivery_context(event_id TEXT PRIMARY KEY, context TEXT NOT NULL)')
    owner.db.execute('CREATE TABLE IF NOT EXISTS capture_screen_context(session TEXT PRIMARY KEY, pem TEXT NOT NULL)')
    owner.db.execute('CREATE TABLE IF NOT EXISTS capture_sync_cursor(id INTEGER PRIMARY KEY CHECK(id=1), sequence INTEGER NOT NULL)')
    owner.db.execute('CREATE TABLE IF NOT EXISTS capture_capacity_policy(revision INTEGER PRIMARY KEY AUTOINCREMENT, bytes INTEGER NOT NULL, actor TEXT NOT NULL, reason TEXT NOT NULL)')
    owner.db.execute('''CREATE TABLE IF NOT EXISTS capture_runs (
        run TEXT PRIMARY KEY, session TEXT NOT NULL, status TEXT NOT NULL)''')
    owner.db.execute('CREATE TABLE IF NOT EXISTS capture_accounting(id INTEGER PRIMARY KEY CHECK(id=1), bytes INTEGER NOT NULL CHECK(bytes>=0))')
    if owner.db.execute('SELECT bytes FROM capture_accounting WHERE id=1').fetchone() is None:
        owner.db.execute('INSERT INTO capture_accounting(id,bytes) SELECT 1,COALESCE(SUM(LENGTH(CAST(text AS BLOB))),0) FROM work_capture')
    # Keep text-byte receipts compatible, but permanently charge each retained
    # row and its identifiers/indexes too. Migration runs once, in the caller's
    # transaction; delivered rows remain charged until explicitly deleted.
    if 'metadata_bytes' not in {row[1] for row in owner.db.execute('PRAGMA table_info(capture_accounting)')}:
        owner.db.execute('ALTER TABLE capture_accounting ADD COLUMN metadata_bytes INTEGER NOT NULL DEFAULT 0 CHECK(metadata_bytes>=0)')
        owner.db.execute('UPDATE capture_accounting SET metadata_bytes=(SELECT COALESCE(SUM(' + _metadata_sql() + '),0) FROM work_capture) WHERE id=1')
        for name in ('capture_insert', 'capture_delete', 'capture_update'):
            owner.db.execute('DROP TRIGGER IF EXISTS ' + name)
    owner.db.execute('CREATE TRIGGER IF NOT EXISTS capture_insert AFTER INSERT ON work_capture BEGIN '
                     'UPDATE capture_accounting SET bytes=bytes+LENGTH(CAST(new.text AS BLOB)), '
                     'metadata_bytes=metadata_bytes+' + _metadata_sql('new.') + ' WHERE id=1; END')
    owner.db.execute('CREATE TRIGGER IF NOT EXISTS capture_delete AFTER DELETE ON work_capture BEGIN '
                     'UPDATE capture_accounting SET bytes=bytes-LENGTH(CAST(old.text AS BLOB)), '
                     'metadata_bytes=metadata_bytes-(' + _metadata_sql('old.') + ') WHERE id=1; END')
    owner.db.execute('CREATE TRIGGER IF NOT EXISTS capture_update AFTER UPDATE OF text,event_id,session,run ON work_capture BEGIN '
                     'UPDATE capture_accounting SET bytes=bytes-LENGTH(CAST(old.text AS BLOB))+LENGTH(CAST(new.text AS BLOB)), '
                     'metadata_bytes=metadata_bytes-(' + _metadata_sql('old.') + ')+(' + _metadata_sql('new.') + ') WHERE id=1; END')
    owner.db.execute("CREATE INDEX IF NOT EXISTS capture_runs_open ON capture_runs(run) WHERE status='open'")
    # A durable migration marker avoids recounting run history on every feed.
    owner.db.execute('CREATE TABLE IF NOT EXISTS capture_run_accounting_version(id INTEGER PRIMARY KEY CHECK(id=1))')
    def run_charge(prefix):
        return '512+2*LENGTH(CAST(' + prefix + 'run AS BLOB))+2*LENGTH(CAST(' + prefix + 'session AS BLOB))'
    if owner.db.execute('SELECT 1 FROM capture_run_accounting_version').fetchone() is None:
        owner.db.execute('UPDATE capture_accounting SET metadata_bytes=metadata_bytes+(SELECT COALESCE(SUM(' + run_charge('') + '),0) FROM capture_runs) WHERE id=1')
        owner.db.execute('INSERT INTO capture_run_accounting_version VALUES(1)')
    for action, timing, change in (
        ('insert', 'INSERT', '+(' + run_charge('new.') + ')'),
        ('delete', 'DELETE', '-(' + run_charge('old.') + ')'),
        ('update', 'UPDATE OF run,session', '-(' + run_charge('old.') + ')+(' + run_charge('new.') + ')')):
        owner.db.execute('CREATE TRIGGER IF NOT EXISTS capture_run_' + action + ' AFTER ' + timing + ' ON capture_runs BEGIN UPDATE capture_accounting SET metadata_bytes=metadata_bytes' + change + ' WHERE id=1; END')
    owner.db.execute('CREATE TABLE IF NOT EXISTS native_archive_context(run TEXT PRIMARY KEY, session TEXT NOT NULL, cursor INTEGER NOT NULL, pem TEXT NOT NULL)')
    owner.db.execute('CREATE TABLE IF NOT EXISTS capture_native_accounting_version(id INTEGER PRIMARY KEY CHECK(id=1))')
    if owner.db.execute('SELECT 1 FROM capture_native_accounting_version').fetchone() is None:
        terms = [('work_capture', _metadata_sql()),
                 ('capture_runs', run_charge('')),
                 ('capture_delivery_context', '512+LENGTH(CAST(context AS BLOB))+LENGTH(CAST(event_id AS BLOB))'),
                 ('capture_capacity_policy', '512+LENGTH(CAST(reason AS BLOB))'),
                 ('capture_screen_context', '1024+LENGTH(CAST(session AS BLOB))'),
                 ('native_archive_context', '1024+LENGTH(CAST(session AS BLOB))')]
        total = sum(owner.db.execute('SELECT COALESCE(SUM('+charge+'),0) FROM '+table).fetchone()[0]
                    for table, charge in terms)
        if owner.db.execute("SELECT 1 FROM sqlite_master WHERE name='capture_context_reconciliations'").fetchone():
            total += owner.db.execute("SELECT COALESCE(SUM(1024+LENGTH(CAST('quarantine-'||sha256 AS BLOB))),0) FROM capture_context_reconciliations").fetchone()[0]
        owner.db.execute('UPDATE capture_accounting SET metadata_bytes=? WHERE id=1', (total,))
        owner.db.execute('INSERT INTO capture_native_accounting_version VALUES(1)')
    owner.db.execute("CREATE TRIGGER IF NOT EXISTS native_context_insert AFTER INSERT ON native_archive_context BEGIN UPDATE capture_accounting SET metadata_bytes=metadata_bytes+1024+LENGTH(CAST(new.session AS BLOB)) WHERE id=1; END")
    owner.db.execute('CREATE TRIGGER IF NOT EXISTS capture_context_insert AFTER INSERT ON capture_delivery_context BEGIN UPDATE capture_accounting SET metadata_bytes=metadata_bytes+512+LENGTH(CAST(new.context AS BLOB))+LENGTH(CAST(new.event_id AS BLOB)) WHERE id=1; END')
    owner.db.execute('CREATE TRIGGER IF NOT EXISTS capture_policy_insert AFTER INSERT ON capture_capacity_policy BEGIN UPDATE capture_accounting SET metadata_bytes=metadata_bytes+512+LENGTH(CAST(new.reason AS BLOB)) WHERE id=1; END')
    owner.db.execute('CREATE TRIGGER IF NOT EXISTS capture_screen_insert AFTER INSERT ON capture_screen_context BEGIN UPDATE capture_accounting SET metadata_bytes=metadata_bytes+1024+LENGTH(CAST(new.session AS BLOB)) WHERE id=1; END')


def _capture_limit(owner):
    row = owner.db.execute('SELECT bytes FROM capture_capacity_policy ORDER BY revision DESC LIMIT 1').fetchone()
    return row[0] if row else CAPTURE_CAPACITY


def raise_capture_capacity(owner, *, actor, expected_bytes, capacity_bytes, reason):
    """Human-only, monotonic capacity expansion; never prune history to resume.

    The operator must provision backing storage separately. This is a logical
    admission limit, not a disk reservation. Existing records and run tails stay.
    """
    owner._human(actor)
    if (type(expected_bytes) is not int or type(capacity_bytes) is not int
            or not expected_bytes < capacity_bytes <= 1024 ** 4
            or not isinstance(reason, str) or not reason.strip() or len(reason.encode()) > 1024):
        raise ValueError('explicit monotonic bounded capacity and reason required')
    _reject_secret_shaped_text(reason=reason)
    with owner.lock, owner.db:
        if not owner.db.in_transaction:
            owner.db.execute('BEGIN IMMEDIATE')
        _capture_schema(owner)
        if _capture_limit(owner) != expected_bytes:
            raise ValueError('stale capture capacity policy')
        owner.db.execute('INSERT INTO capture_capacity_policy(bytes,actor,reason) VALUES(?,?,?)',
                         (capacity_bytes, actor, reason))
    return {'capacity_bytes': capacity_bytes, 'retention': 'no automatic deletion'}


class LocalCaptureExportRefused(ValueError):
    """Local lifecycle targets have no authorized shared archive attribution."""


def capture_delivery_payload(owner, row):
    """Freeze wire metadata before first dispatch; retries reuse original input."""
    with owner.lock, owner.db:
        if not owner.db.in_transaction:
            owner.db.execute('BEGIN IMMEDIATE')
        _capture_schema(owner)
        stored = owner.db.execute('SELECT * FROM work_capture WHERE event_id=?', (row['event_id'],)).fetchone()
        keys = ('event_id', 'session', 'run', 'text')
        if stored is None or any(stored[key] != row[key] for key in keys):
            raise ValueError('capture delivery must bind exact retained row')
        frozen = owner.db.execute('SELECT context FROM capture_delivery_context WHERE event_id=?', (row['event_id'],)).fetchone()
        if frozen:
            context = json.loads(frozen[0])
        else:
            session = owner._get(row['session'])
            context = dict(project=session['project'] or '', task=session['task'] or '', host=owner.host)
            if session['kind'] == 'organizer':
                agent = owner.db.execute('SELECT agent FROM native_organizers WHERE session=?', (session['id'],)).fetchone()[0]
                context.update(kind='organizer', agent=agent)
            else:
                if session['kind']=='local':
                    raise LocalCaptureExportRefused('local session archive policy unavailable; records retained locally')
                project = json.loads((owner.vault / 'registry/projects' / (session['project'] + '.json')).read_text())
                agent = project['owner_agent_id']
            context['actor'] = agent
            raw = json.dumps(context, sort_keys=True)
            if len(raw.encode()) > 2048:
                raise ValueError('bounded capture delivery context required')
            # Bounded recovery metadata is admitted even at the data quota:
            # refusing it would prevent delivery of the rows filling the quota.
            owner.db.execute('INSERT INTO capture_delivery_context VALUES(?,?)', (row['event_id'], raw))
        payload = {key: row[key] for key in keys}
        payload.update(context, idempotency_key=row['event_id'])
    return payload


def export_capture(owner, *, actor, after=0, limit=100):
    """Read-only paginated export of all retained sanitized rows, delivered too."""
    owner._human(actor)
    if type(after) is not int or after < 0 or type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError('bounded exact capture export cursor required')
    with owner.lock:
        _capture_schema(owner)
        rows = [dict(row) for row in owner.db.execute(
            'SELECT * FROM work_capture WHERE sequence>? ORDER BY sequence LIMIT ?', (after, limit + 1))]
        page, used = [], 256
        for row in rows:
            charge = len(json.dumps(row).encode()) + 2
            if len(page) == limit or used + charge > ARCHIVE_PAGE_BYTES:
                if not page:
                    raise ValueError('capture export row exceeds page budget; history retained')
                break
            page.append(row)
            used += charge
        return {'records': page, 'next_after': page[-1]['sequence'] if page else after,
                'has_more': len(rows) > len(page), 'retention': 'export does not delete history'}


class WorkCapture:
    """Sanitized line records before the volatile display ring.

    Incomplete lines are never written unexamined. An interrupted run remains
    visibly open: a crash may lose its uncompleted tail, never silently appear
    complete. Private client shells do not construct this recorder.
    """
    def __init__(self, owner, sid, run=None):
        self.owner, self.sid, self.run = owner, sid, run or uuid.uuid4().hex
        self.buffer = bytearray()
        self.overlong = False
        self.private_block = False
        self.screen_tail = b''
        self.screen_candidate = None
        self.screen_escape = None
        self.line_private = False
        self.ordinary_tail = ''
        self.ordinary_context = ''
        self.ordinary_escape = None
        self.ordinary_decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')
        with owner.lock, owner.db:
            if not owner.db.in_transaction:
                owner.db.execute('BEGIN IMMEDIATE')
            owner._get(sid)
            _capture_schema(owner)
            self._load_screen()
            charge = 512 + 2 * len(self.run.encode()) + 2 * len(sid.encode())
            if owner.db.execute('SELECT 1 FROM capture_screen_context WHERE session=?', (sid,)).fetchone() is None:
                charge += 1024 + len(sid.encode())
            size = owner.db.execute('SELECT bytes+metadata_bytes FROM capture_accounting WHERE id=1').fetchone()[0]
            if size + charge > _capture_limit(owner):
                raise BufferError('capture capacity reached; run not started, history retained')
            self._save_screen()
            owner.db.execute('INSERT INTO capture_runs VALUES (?, ?, ?)', (self.run, sid, 'open'))
            owner.db.commit()

    def abort_before_process(self):
        """Retain charged evidence without claiming an interrupted process."""
        with self.owner.lock, self.owner.db:
            self.owner.db.execute("UPDATE capture_runs SET status='aborted-before-process' WHERE run=? AND status='open'", (self.run,))

    def _load_screen(self):
        row = self.owner.db.execute('SELECT pem FROM capture_screen_context WHERE session=?', (self.sid,)).fetchone()
        if row is None:
            if self.owner.db.execute('SELECT 1 FROM capture_runs WHERE session=? LIMIT 1', (self.sid,)).fetchone():
                raise ContextProvenanceRequired('legacy capture lacks scanner provenance; inspect_capture_context and confirmed reconciliation required')
            self.private_block, self.screen_tail, self.screen_escape, self.screen_candidate = False, b'', None, None
        else:
            value = _context_state(row[0])
            self.private_block, tail, self.screen_escape, candidate = value['state']
            self.screen_tail = tail.encode('ascii')
            self.screen_candidate = bytes.fromhex(candidate) or None
        self.line_private = self.line_private or bool(self.private_block)

    def _save_screen(self):
        # Only bounded delimiter syntax is durable, never body/context bytes.
        pem = _context_dump(self)
        self.owner.db.execute('INSERT INTO capture_screen_context VALUES(?,?) ON CONFLICT(session) DO UPDATE SET pem=excluded.pem', (self.sid, pem))

    def _write(self, text):
        with self.owner.lock:
            size = self.owner.db.execute('SELECT bytes+metadata_bytes FROM capture_accounting WHERE id=1').fetchone()[0]
            if size + _record_charge('0' * 32, self.sid, self.run, text) > _capture_limit(self.owner):
                raise BufferError('capture capacity reached; buffered tail retained, run incomplete')
            self.owner.db.execute('INSERT INTO work_capture(event_id,session,run,text) VALUES (?, ?, ?, ?)',
                                  (uuid.uuid4().hex, self.sid, self.run, text))

    def feed(self, data):
        with self.owner.lock:
            previous = (bytes(self.buffer), self.overlong, self.private_block,
                        self.screen_tail, self.screen_candidate, self.screen_escape, self.line_private,
                        self.ordinary_tail, self.ordinary_context, self.ordinary_decoder.getstate(), self.ordinary_escape)
            try:
                if not self.owner.db.in_transaction:
                    self.owner.db.execute('BEGIN IMMEDIATE')
                self._load_screen()
                size = self.owner.db.execute('SELECT bytes+metadata_bytes FROM capture_accounting WHERE id=1').fetchone()[0]
                # Conservative expansion allowance includes redaction markers
                # for every newline in a private-key block.
                if size + len(data) * 40 + len(self.buffer) + 4096 > _capture_limit(self.owner):
                    raise BufferError('capture capacity reached; terminal output backpressured, no records deleted')
                parts = data.split(b'\n')
                for index, part in enumerate(parts):
                    if index < len(parts) - 1:
                        part += b'\n'
                    self._screen(part)
                    self.buffer.extend(part)
                    if len(self.buffer) > 16384:
                        self.buffer.clear()
                        self.overlong = True
                    if part.endswith(b'\n'):
                        self._line()
                self._save_screen()
                self.owner.db.commit()
            except Exception:
                self.owner.db.rollback()
                self.buffer = bytearray(previous[0])
                self.overlong = previous[1]
                self.private_block = previous[2]
                self.screen_tail, self.screen_candidate, self.screen_escape, self.line_private = previous[3:7]
                self.ordinary_tail, self.ordinary_context = previous[7:9]
                self.ordinary_decoder.setstate(previous[9])
                self.ordinary_escape = previous[10]
                raise

    def _screen(self, data):
        self.line_private = _screen_pem(self, data) or self.line_private
        # Collapse arbitrary cross-line whitespace before bounding context, even
        # on omitted overlong lines. Canonical screening happens in _line before
        # persistence; no raw context is persisted.
        printable = []
        for char in self.ordinary_decoder.decode(data):
            if self.ordinary_escape == 'csi':
                if '@' <= char <= '~':
                    self.ordinary_escape = None
                continue
            if self.ordinary_escape == 'escape':
                self.ordinary_escape = None
                if char == '[':
                    self.ordinary_escape = 'csi'
                    continue
            if char == '\x1b':
                self.ordinary_escape = 'escape'
            elif char.isspace():
                printable.append(' ')
            elif char.isprintable():
                printable.append(char)
        decoded = ''.join(printable)
        for start in range(0, len(decoded), 128):
            text = re.sub(r'\s+', ' ', self.ordinary_tail + decoded[start:start + 128])
            self.ordinary_tail = text[-256:]

    def _line(self):
        text = self.buffer.decode('utf-8', errors='replace')
        if self.overlong:
            text = '[overlong output line omitted]\n'
        else:
            # Strip terminal control escapes before examining the printable text.
            text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text)
            screened = ''.join(c if c.isprintable() else ' ' if c.isspace() else '' for c in text)
            text = ''.join(c for c in text if c.isprintable() or c in '\n\t')
            try:
                _reject_secret_shaped_text(transcript=self.ordinary_context + screened)
            except ValueError:
                self.ordinary_tail = ''
                text = '[redacted secret-shaped output line]\n'
        self.ordinary_context = self.ordinary_tail
        if self.line_private:
            text = '[redacted private-key block line]\n'
        self.buffer.clear()
        self.overlong = False
        self.line_private = bool(self.private_block)
        if text:
            self._write(text)

    def finish(self):
        with self.owner.lock:
            previous = (bytes(self.buffer), self.overlong, self.private_block,
                        self.screen_tail, self.screen_candidate, self.screen_escape, self.line_private,
                        self.ordinary_tail, self.ordinary_context, self.ordinary_decoder.getstate(), self.ordinary_escape)
            try:
                if not self.owner.db.in_transaction:
                    self.owner.db.execute('BEGIN IMMEDIATE')
                self._load_screen()
                if self.buffer or self.overlong:
                    self._line()
                self.owner.db.execute("UPDATE capture_runs SET status='complete' WHERE run=?", (self.run,))
                self._save_screen()
                self.owner.db.commit()
            except Exception:
                self.owner.db.rollback()
                self.buffer = bytearray(previous[0])
                self.overlong, self.private_block = previous[1:3]
                self.screen_tail, self.screen_candidate, self.screen_escape, self.line_private = previous[3:7]
                self.ordinary_tail, self.ordinary_context = previous[7:9]
                self.ordinary_decoder.setstate(previous[9])
                self.ordinary_escape = previous[10]
                raise


def pending_capture(owner, limit=100000):
    with owner.lock:
        _capture_schema(owner)
        return [dict(row) for row in owner.db.execute(
            'SELECT * FROM work_capture WHERE delivered=0 ORDER BY sequence LIMIT ?', (limit,))]


def capture_status(owner):
    with owner.lock:
        _capture_schema(owner)
        opened = {row[0] for row in owner.db.execute("SELECT run FROM capture_runs WHERE status='open'")}
        live = {item['recorder'].run for item in owner.live.values() if item.get('fd') is not None and 'recorder' in item}
        return {'pending': owner.db.execute('SELECT COUNT(*) FROM work_capture WHERE delivered=0').fetchone()[0],
                'open_runs': len(opened), 'interrupted_runs': len(opened - live),
                'aborted_runs': owner.db.execute("SELECT COUNT(*) FROM capture_runs WHERE status='aborted-before-process'").fetchone()[0],
                'sync': owner.archive_sync, 'capacity_bytes': _capture_limit(owner),
                'used_bytes': owner.db.execute('SELECT bytes+metadata_bytes FROM capture_accounting WHERE id=1').fetchone()[0],
                'capacity_policy': 'refuse new capture; retain tail; explicit human capacity expansion',
                'retention': 'no automatic deletion'}


def import_native(owner, sid, *, actor):
    owner._human(actor)
    with owner.lock:
        binding = owner.native(sid, actor=actor)
        if binding is None or binding['tool'] not in owner.native_runtimes:
            raise ValueError('explicit verified native runtime required')
        runtime = owner.native_runtimes[binding['tool']]
        runtime.plan(binding['conversation'], owner._get(sid)['workspace'])
        _capture_schema(owner)
        owner.db.execute('CREATE TABLE IF NOT EXISTS native_archive_cursor(session TEXT PRIMARY KEY, cursor INTEGER NOT NULL)')
        owner.db.execute('CREATE TABLE IF NOT EXISTS native_archive_cursor_provenance(session TEXT PRIMARY KEY,context_id TEXT NOT NULL)')
        owner.db.execute('CREATE TABLE IF NOT EXISTS native_archive_context(run TEXT PRIMARY KEY, session TEXT NOT NULL, cursor INTEGER NOT NULL, pem TEXT NOT NULL)')
        # State contains only a delimiter suffix/label, never message bodies.
        owner.db.execute("CREATE TRIGGER IF NOT EXISTS native_context_insert AFTER INSERT ON native_archive_context BEGIN UPDATE capture_accounting SET metadata_bytes=metadata_bytes+1024+LENGTH(CAST(new.session AS BLOB)) WHERE id=1; END")
        context_id = _native_source_key(sid, binding, runtime)
        # Preserve pre-migration event identities when replaying legacy cursors.
        run = 'native-v2-' + context_id[:32]
        row = owner.db.execute('SELECT cursor,pem FROM native_archive_context WHERE run=?', (context_id,)).fetchone()
        cursor = row['cursor'] if row else 0
        # Legacy clearance is quarantined. Explicit recovery rescans from zero
        # in a new namespace while preserving original event identities/history.
        legacy_cursor = owner.db.execute('SELECT cursor FROM native_archive_cursor WHERE session=?', (sid,)).fetchone() if row is None else None
        provenance=owner.db.execute('SELECT context_id FROM native_archive_cursor_provenance WHERE session=?',(sid,)).fetchone()
        if legacy_cursor is not None:
            raise ContextProvenanceRequired('native source changed or legacy cursor lacks source-bound provenance; explicit reimport required; history retained')
        if provenance is not None and provenance[0] != context_id:
            raise ContextProvenanceRequired('native source changed; explicit reimport required; history retained')
        value = _context_state(row['pem']) if row else dict(state=[False, '', None, ''], archive_run=None)
        state = value['state']
        run = value['archive_run'] or run
        context = SimpleNamespace(private_block=state[0], screen_tail=state[1].encode('ascii'), screen_escape=state[2], screen_candidate=bytes.fromhex(state[3]) or None)
        records = runtime.transcript(binding['conversation'], after=cursor)
        pending = []
        for record in records:
            text = str(record['role']) + ': ' + str(record['content'] or '')
            private = _screen_pem(context, text.encode())
            _screen_pem(context, b'\n')
            if len(text.encode()) > 65536:
                text = '[overlong native message omitted]'
            try:
                _reject_secret_shaped_text(transcript=text)
            except ValueError:
                text = '[redacted native message]'
            if private:
                text = '[redacted native message]'
            event_id = hashlib.sha256((run + ':' + str(record['id'])).encode()).hexdigest()
            pending.append((event_id, sid, run, text))
            cursor = record['id']
        if _native_source_key(sid, binding, runtime) != context_id:
            raise ContextProvenanceRequired('native source changed during import; history retained')
        with owner.db:
            size = owner.db.execute('SELECT bytes+metadata_bytes FROM capture_accounting WHERE id=1').fetchone()[0]
            context_charge = 0 if row else 1024 + len(sid.encode())
            additions = {}
            for record in pending:
                existing = owner.db.execute('SELECT event_id,session,run,text FROM work_capture WHERE event_id=?', (record[0],)).fetchone()
                prior = tuple(existing) if existing is not None else additions.get(record[0])
                if prior is not None:
                    if prior != record:
                        raise ValueError('native archive identity/content conflict; explicit reconciliation required')
                else:
                    additions[record[0]] = record
            if size + context_charge + sum(_record_charge(*record) for record in additions.values()) > _capture_limit(owner):
                raise BufferError('native archive capacity reached; source cursor not advanced')
            owner.db.executemany('INSERT INTO work_capture(event_id,session,run,text) VALUES(?,?,?,?)', additions.values())
            pem = _context_dump(context, value['archive_run'])
            owner.db.execute('INSERT INTO native_archive_context VALUES(?,?,?,?) ON CONFLICT(run) DO UPDATE SET cursor=excluded.cursor,pem=excluded.pem', (context_id, sid, cursor, pem))
            owner.db.execute('INSERT OR REPLACE INTO native_archive_cursor VALUES(?,?)', (sid, cursor))
            owner.db.execute('INSERT OR REPLACE INTO native_archive_cursor_provenance VALUES(?,?)', (sid, context_id))
        return {'imported': len(records), 'cursor': cursor,
                'has_more': getattr(records, 'has_more', len(records) == 100), 'curated_memory': False}


def sync_capture(owner, sink):
    """Explicit governed sink only; exact event acknowledgment, retry is idempotent.

    A sink must authenticate against existing AMC authority and deduplicate by
    event_id. There is deliberately no guessed network endpoint or identity.
    """
    sent = 0
    acknowledged = []
    with owner.lock:
        _capture_schema(owner)
        cursor = owner.db.execute('SELECT sequence FROM capture_sync_cursor WHERE id=1').fetchone()
        after = cursor[0] if cursor else 0
        batch = [dict(row) for row in owner.db.execute(
            'SELECT * FROM work_capture WHERE delivered=0 ORDER BY CASE WHEN sequence>? THEN 0 ELSE 1 END,sequence LIMIT 100', (after,))]
    for row in batch:
        try:
            acknowledgment = sink(dict(row))
        except LocalCaptureExportRefused as exc:
            with owner.lock, owner.db:
                owner.db.execute('INSERT INTO session_attention VALUES(?,?,?) ON CONFLICT(session) DO NOTHING',
                                 (row['session'],'archive-refused',str(exc)))
            continue
        except (OSError, ValueError, RuntimeError):
            continue
        if acknowledgment != row['event_id']:
            continue
        acknowledged.append((row['event_id'],))
        sent += 1
    with owner.lock:
        if batch:
            owner.db.execute('INSERT INTO capture_sync_cursor VALUES(1,?) ON CONFLICT(id) DO UPDATE SET sequence=excluded.sequence', (batch[-1]['sequence'],))
        owner.db.executemany('UPDATE work_capture SET delivered=1 WHERE event_id=?', acknowledged)
        owner.db.commit()
    return sent
