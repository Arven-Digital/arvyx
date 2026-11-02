"""Qualified-store attestation admission, NOT physical retention from signatures.

See docs/capture-retained-generations.md. There is deliberately no issuer here.
Unqualified ordinary directories cannot authorize pruning or storage adoption.
"""
import hashlib
import json
import os
import re
import time

MAX_RECEIPT = 16 * 1024
DOMAIN = 'amc.capture.retained-generation.v1'


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def snapshot(receipt):
    """Detach caller-owned mutable objects before verification and persistence."""
    try:
        raw = encoded(receipt)
    except (ValueError, TypeError, RecursionError):
        raise ValueError('bounded closed retention receipt required') from None
    if len(raw) > MAX_RECEIPT:
        raise ValueError('bounded closed retention receipt required')
    return json.loads(raw)


def hex64(value):
    return isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value) is not None


def schema(owner):
    owner.db.execute('''CREATE TABLE IF NOT EXISTS capture_retention_trust(
        key_id TEXT PRIMARY KEY,public_key TEXT NOT NULL,storage TEXT NOT NULL,
        qualification TEXT NOT NULL,revoked INTEGER NOT NULL CHECK(revoked IN(0,1)))''')
    owner.db.execute('''CREATE TABLE IF NOT EXISTS capture_retention_accepted(
        singleton INTEGER PRIMARY KEY CHECK(singleton=1),receipt TEXT NOT NULL)''')


def _storage(value):
    from .capture_offload import storage_identity
    if type(value) is not dict or set(value) != {'directory', 'device', 'inode'}:
        raise ValueError('exact retention storage identity required')
    if type(value['directory']) is not str or any(type(value[n]) is not int for n in ('device', 'inode')):
        raise ValueError('exact retention storage identity required')
    if storage_identity(value['directory']) != value:
        raise ValueError('retention storage incarnation changed')


def trust(owner, storage, public_key, qualification, *, actor, confirmed=False):
    """Explicit human pin of an independently qualified store, never enrollment.

    qualification hashes the reviewed external enforcement evidence. Caller must
    not represent a generated hash or self-signed promise as store qualification.
    This source operation does not perform or certify that operational review.
    """
    owner._human(actor)
    if confirmed is not True or not hex64(public_key) or not hex64(qualification):
        raise ValueError('explicit qualified retention issuer confirmation required')
    storage = snapshot(storage)
    key_id = hashlib.sha256(bytes.fromhex(public_key)).hexdigest()
    with owner.lock, owner.db:
        _storage(storage)
        from .capture_offload import schema as offload_schema
        offload_schema(owner)
        row = owner.db.execute('SELECT public_key,storage,qualification,revoked FROM capture_retention_trust WHERE key_id=?', (key_id,)).fetchone()
        expected = (public_key, encoded(storage).decode(), qualification, 0)
        if row is not None and tuple(row) != expected:
            raise ValueError('retention issuer pin immutable; revoked pins cannot be reenrolled')
        if row is None:
            if owner.db.execute('SELECT count(*) FROM capture_retention_trust').fetchone()[0] >= 8:
                raise ValueError('retention trust capacity reached; no automatic trust eviction')
            owner.db.execute('INSERT INTO capture_retention_trust VALUES(?,?,?,?,0)', (key_id, *expected[:3]))
    return dict(key_id=key_id, storage=storage, qualification=qualification, physical_retention_qualified_here=False)


def revoke(owner, key_id, *, actor, confirmed=False):
    owner._human(actor)
    if confirmed is not True or not hex64(key_id):
        raise ValueError('explicit exact retention issuer revocation required')
    with owner.lock, owner.db:
        from .capture_offload import schema as offload_schema
        offload_schema(owner)
        if not owner.db.execute('SELECT 1 FROM capture_retention_trust WHERE key_id=?', (key_id,)).fetchone():
            raise ValueError('unknown retention issuer')
        owner.db.execute('UPDATE capture_retention_trust SET revoked=1 WHERE key_id=?', (key_id,))
        from .capture_offload_verify import clear
        clear(owner)
    return dict(revoked=key_id, prior_retention_obligations_unchanged=True)


def scope(owner, storage, latest, through, kind):
    from .capture_offload import head
    database = owner.db.execute('PRAGMA database_list').fetchone()[2]
    if not database:
        raise ValueError('durable owner database required for retained generation')
    info = os.stat(database)
    row = owner.db.execute('SELECT directory,device,inode FROM capture_offload_storage WHERE singleton=1').fetchone()
    bound = dict(directory=row[0], device=row[1], inode=row[2]) if row else None
    old, after = head(owner)
    return dict(domain=DOMAIN, operation=kind,
                owner_database=dict(device=info.st_dev, inode=info.st_ino),
                storage=storage, previous_storage=bound, previous_head=old,
                previous_through=after, head=latest, through=through)


def request(owner, storage, latest, through, kind, *, actor):
    """Unsigned exact request for the external issuer, with no payload disclosure."""
    owner._human(actor)
    if kind not in ('ack', 'relocate') or not hex64(latest) or type(through) is not int or through <= 0:
        raise ValueError('exact retained-generation operation required')
    with owner.lock:
        from .capture_offload import schema as offload_schema
        offload_schema(owner)
        storage = snapshot(storage)
        _storage(storage)
        return scope(owner, storage, latest, through, kind)


def verify(owner, receipt, storage, latest, through, kind):
    """Called under owner lock, and again after final writer reservation.

    A successful result is qualified supplier authority, not proof of media.
    Admission expiry never expires prior indefinite retention obligations.
    """
    if kind not in ('ack', 'relocate') or not hex64(latest) or type(through) is not int or through <= 0:
        raise ValueError('exact retained generation required')
    receipt = snapshot(receipt)
    if type(receipt) is not dict or set(receipt) != {'payload', 'signature'}:
        raise ValueError('bounded closed retention receipt required')
    payload = receipt['payload']
    expected = scope(owner, storage, latest, through, kind)
    extra = {'key_id', 'qualification', 'generation', 'issued_at', 'admit_before', 'enforcement'}
    if type(payload) is not dict or set(payload) != set(expected) | extra:
        raise ValueError('closed exact retention payload required')
    # JSON booleans cannot stand in for integer identity/sequence fields.
    if encoded({k: payload[k] for k in expected}) != encoded(expected):
        raise ValueError('retention receipt scope changed')
    if not all(hex64(payload[k]) for k in ('key_id', 'qualification', 'generation')):
        raise ValueError('exact retention issuer and generation required')
    issued, expires = payload['issued_at'], payload['admit_before']
    now = time.time()
    if type(issued) is not int or type(expires) is not int or not issued <= now < expires or not 0 < expires - issued <= 3600:
        raise ValueError('retention receipt admission expired or not yet valid')
    enforcement = payload['enforcement']
    if (type(enforcement) is not dict or set(enforcement) != {'mode', 'versions', 'evidence'}
            or enforcement['mode'] != 'irrevocable-indefinite-complete-chain'
            or not hex64(enforcement['versions']) or not hex64(enforcement['evidence'])):
        raise ValueError('enforced immutable complete-generation retention required')
    schema(owner)
    row = owner.db.execute('SELECT public_key,storage,qualification,revoked FROM capture_retention_trust WHERE key_id=?', (payload['key_id'],)).fetchone()
    if row is None or row[3] != 0 or row[1] != encoded(storage).decode() or row[2] != payload['qualification']:
        raise ValueError('untrusted or revoked retention issuer')
    _storage(storage)
    signature = receipt['signature']
    if not isinstance(signature, str) or not re.fullmatch('[a-f0-9]{128}', signature):
        raise ValueError('exact retention signature required')
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        raise ValueError('retention signature verification dependency unavailable') from None
    from cryptography.exceptions import InvalidSignature
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(row[0])).verify(bytes.fromhex(signature), encoded(payload))
    except (InvalidSignature, ValueError):
        raise ValueError('retention signature invalid') from None
    # An authenticated renewal can extend admission time for the SAME immutable
    # commitment without imposing a lifetime chain-size limit. Every call still
    # verifies the current signature/expiry/revocation; differing scope, issuer,
    # qualification, generation or version-set starts independent progress.
    return digest({k: v for k, v in payload.items() if k not in {'issued_at', 'admit_before'}})


def accept(owner, receipt):
    """Atomic with head advance/rebind; caller MUST just have verified admission."""
    owner.db.execute('INSERT OR REPLACE INTO capture_retention_accepted VALUES(1,?)', (encoded(receipt).decode(),))
