"""REV-0560: session authority is rechecked after a genuinely blocked reservation.

The production chain is driven unchanged: ``SecretDelivery.handle`` (intake,
CSRF/session checks, ``publication_guard``) -> ``operate`` -> the real
file-backed ``Receipts.reserve`` on SQLite. A second SQLite connection holds
the database write lock (``BEGIN IMMEDIATE``), so the reservation's INSERT
really waits in SQLite's busy handler while the session is expired, removed,
replaced, or while wall-clock time crosses the session or principal expiry.

Only the true external boundary is substituted: the remote target's
``exchange`` (the network peer) is a counting stub. No clock patching.
"""
import io
import json
import sqlite3
from contextlib import closing
import threading
import time
import uuid
from email.message import Message
from types import SimpleNamespace

import pytest

from arvyx_control.secret_delivery import COOKIE, SecretDelivery, Session
from arvyx_control.secret_delivery_protocol import Principal, Receipts
from arvyx_control.vault import init_vault
import os

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='secret delivery destinations are defined by POSIX uid and mode semantics')

HOLD = 0.3  # seconds the competing writer keeps the lock after reserve blocks


def _root(tmp_path):
    tmp_path.chmod(0o700)
    store = tmp_path / 'receipts'
    store.mkdir(mode=0o700)
    store.chmod(0o700)
    return store


def _handler(service, sid, csrf, payload):
    raw = json.dumps(payload).encode()
    headers = Message()
    for k, v in [('Origin', service.origin), ('X-Secret-Delivery', '1'), ('Cookie', COOKIE + '=' + sid),
                 ('X-Secret-CSRF', csrf), ('Content-Type', 'application/json'), ('Content-Length', str(len(raw)))]:
        headers[k] = v
    statuses = []
    return SimpleNamespace(connection=SimpleNamespace(settimeout=lambda _: None), path='/secret-delivery/send',
                           command='POST', headers=headers, rfile=io.BytesIO(raw), wfile=io.BytesIO(),
                           send_response=statuses.append, send_header=lambda *a: None, end_headers=lambda: None,
                           statuses=statuses)


def _prepared_payload(session, delivery_id, value):
    confirmation = uuid.uuid4().hex
    session.preparations[confirmation] = ('synthetic', 'OTHER', 'version-1', False, time.time() + 90)
    return dict(target='synthetic', key='OTHER', value=value, delivery_id=delivery_id,
                confirmation=confirmation, overwrite=False)


def _row(path, delivery_id):
    with closing(sqlite3.connect(path, timeout=0)) as db, db:
        return db.execute('SELECT status FROM receipts WHERE id=?', (delivery_id,)).fetchone()


@pytest.mark.parametrize('change', ['expire', 'remove', 'replace', 'session-clock', 'principal-clock', 'unchanged'])
def test_rev0560_blocked_sqlite_reservation_rechecks_session_before_dispatch(tmp_path, change):
    store = _root(tmp_path)
    vault = tmp_path / 'vault'
    init_vault(vault)
    calls = []
    target = SimpleNamespace(id='synthetic', agent='demobot', runtime='codex-demo', allowed_keys=('OTHER',),
                             exchange=lambda v: calls.append(v) or {'status': 'saved'})
    receipts = Receipts(store / 'ingress.sqlite')
    service = SecretDelivery('https://synthetic.invalid', [target], receipts, vault=vault)
    now = time.time()
    # Expiry is crossed in real wall-clock time while SQLite blocks reserve.
    session_ttl = 0.6 if change == 'session-clock' else 120
    principal_ttl = 0.6 if change == 'principal-clock' else 300
    sid, csrf = uuid.uuid4().hex, uuid.uuid4().hex
    session = Session('human', csrf, now + session_ttl)
    service.sessions[sid] = session
    principal = Principal('human', now + principal_ttl)
    value = 'synthetic-' + uuid.uuid4().hex
    delivery_id = 'synthetic-' + uuid.uuid4().hex[:16]
    handler = _handler(service, sid, csrf, _prepared_payload(session, delivery_id, value))

    holder = sqlite3.connect(receipts.path, timeout=0, isolation_level=None)
    holder.execute('BEGIN IMMEDIATE')  # genuine competing writer
    worker = threading.Thread(target=service.handle, args=(handler, principal), daemon=True)
    started = time.monotonic()
    try:
        worker.start()
        deadline = time.monotonic() + 5
        while not receipts.lock.locked():  # reserve() holds this lock around its INSERT
            assert worker.is_alive() and time.monotonic() < deadline, 'never reached reservation'
            time.sleep(0.005)
        time.sleep(HOLD)
        # The reservation is really blocked: worker alive, nothing reserved, nothing sent.
        assert worker.is_alive()
        assert _row(receipts.path, delivery_id) is None
        assert calls == []
        if change == 'expire':
            session.expires = 0
        elif change == 'remove':
            service.sessions.pop(sid)
        elif change == 'replace':
            service.sessions[sid] = Session('human', csrf, time.time() + 120)
        elif change in ('session-clock', 'principal-clock'):
            while time.time() <= now + 0.65:
                time.sleep(0.01)
    finally:
        holder.execute('COMMIT')
        holder.close()
    worker.join(10)
    assert not worker.is_alive()
    assert time.monotonic() - started >= HOLD  # dispatch decision followed the blocked reservation

    body = handler.wfile.getvalue().decode()
    assert value not in body
    durable = Receipts(receipts.path).get(delivery_id, 'human')  # reopened store, not cache
    if change == 'unchanged':
        assert len(calls) == 1 and calls[0]['delivery_id'] == delivery_id
        assert durable['status'] == 'saved'
    else:
        assert calls == []
        assert durable['status'] == 'ambiguous'
        assert handler.statuses == [200] and json.loads(body)['receipt']['status'] == 'ambiguous'

    # No automatic replay: a fresh, valid session resubmitting the same delivery
    # id receives the retained receipt and causes no further target exchange.
    sent = len(calls)
    sid2, csrf2 = uuid.uuid4().hex, uuid.uuid4().hex
    fresh = Session('human', csrf2, time.time() + 120)
    service.sessions[sid2] = fresh
    retry = _handler(service, sid2, csrf2, _prepared_payload(fresh, delivery_id, 'synthetic-' + uuid.uuid4().hex))
    service.handle(retry, Principal('human', time.time() + 300))
    assert len(calls) == sent
    assert json.loads(retry.wfile.getvalue())['receipt']['status'] == durable['status']
    assert _row(receipts.path, delivery_id) == (durable['status'],)
