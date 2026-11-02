"""Local explicit prompt drafts, never reconnect-triggered input."""
import hashlib
import uuid
from .control import _reject_secret_shaped_text


def _schema(owner):
    owner.db.execute('''CREATE TABLE IF NOT EXISTS prompt_drafts (
        id TEXT PRIMARY KEY, session TEXT NOT NULL, text TEXT NOT NULL,
        sha256 TEXT NOT NULL, status TEXT NOT NULL)''')


def drafts(owner, sid, *, actor, after=0, limit=50, identifier=None):
    owner._human(actor)
    if (type(after) is not int or not 0 <= after <= 2**63 - 1
            or type(limit) is not int or not 1 <= limit <= 50
            or (identifier is not None and (not isinstance(identifier, str) or len(identifier) != 32))):
        raise ValueError('bounded draft cursor/limit/identifier required')
    with owner.lock:
        owner._get(sid)
        _schema(owner)
        # List-compatible keyset pages; cursor is the last returned row's cursor.
        # Exact selection never needs to materialize any earlier history.
        return [dict(row) for row in owner.db.execute(
            'SELECT rowid AS cursor,* FROM prompt_drafts WHERE session=? AND rowid>? '
            'AND (? IS NULL OR id=?) ORDER BY rowid LIMIT ?',
            (sid, after, identifier, identifier, limit))]


def stage_draft(owner, sid, text, *, actor, context='', context_consent=False):
    owner._human(actor)
    if context and context_consent is not True:
        raise ValueError('separate explicit context consent required')
    if any(not isinstance(value, str) for value in (text, context)):
        raise ValueError('text/context must be strings')
    payload = context + '\n\n' + text if context else text
    if not payload.strip() or len(payload.encode()) > 4095 or '\x00' in payload:
        raise ValueError('bounded draft required')
    _reject_secret_shaped_text(draft=payload)
    with owner.lock:
        if owner._get(sid)['status'] == 'ended':
            raise ValueError('session ended')
        _schema(owner)
        identifier = uuid.uuid4().hex
        digest = hashlib.sha256((sid + '\x00' + payload).encode()).hexdigest()
        owner.db.execute('INSERT INTO prompt_drafts VALUES (?, ?, ?, ?, ?)', (identifier, sid, payload, digest, 'draft'))
        owner.db.commit()
        return dict(owner.db.execute('SELECT * FROM prompt_drafts WHERE id=?', (identifier,)).fetchone())


def send_draft(owner, identifier, *, consent, attachment, actor, sid=None):
    owner._human(actor)
    with owner.lock:
        _schema(owner)
        found = owner.db.execute('SELECT * FROM prompt_drafts WHERE id=?', (identifier,)).fetchone()
        if found is None:
            raise ValueError('unknown draft')
        row = dict(found)
        if sid is not None and row['session'] != sid:
            raise ValueError('draft does not belong to exact fleet session')
        if row['status'] != 'draft':
            raise ValueError('draft already attempted/ambiguous; reconcile manually')
        if consent != row['sha256']:
            raise ValueError('exact draft consent required')
        # Persist ambiguous BEFORE attempting transport. Exception/crash cannot
        # leave a replayable draft after input may have reached the native tool.
        owner.db.execute("UPDATE prompt_drafts SET status='ambiguous' WHERE id=?", (identifier,))
        owner.db.commit()
        ack = owner.write(row['session'], row['text'] + '\n', actor=actor, attachment=attachment)
        status = 'accepted-not-delivered' if ack['accepted'] else 'rejected'
        owner.db.execute('UPDATE prompt_drafts SET status=? WHERE id=?', (status, identifier))
        owner.db.commit()
        return dict(ack, draft_status=status)
