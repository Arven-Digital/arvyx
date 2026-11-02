"""Real signatures over a fixture-only retained copy; never imported by product."""
import hashlib
import time


def retention_receipt(owner, directory, latest, *, kind='ack', retained_source=None):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from arvyx_control.capture_offload import bundle_read, chain, storage_identity, encoded
    from arvyx_control.capture_retention import trust, request
    storage = storage_identity(directory)
    fixtures = getattr(owner, '_synthetic_retention_stores', None)
    if fixtures is None:
        fixtures = owner._synthetic_retention_stores = {}
    key = encoded(storage)
    if key not in fixtures:
        signer = Ed25519PrivateKey.generate()
        public = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        qualification = hashlib.sha256(b'SYNTHETIC TEST STORE - NOT REAL RETENTION QUALIFICATION').hexdigest()
        pin = trust(owner, storage, public, qualification, actor='operator', confirmed=True)
        fixtures[key] = dict(signer=signer, pin=pin, objects={})
    fixture = fixtures[key]
    # A target's independent retained store may already hold the full version
    # set while its ordinary read cache is empty. Never pretend cache copying
    # creates the independent store commitment under test.
    origin = directory if retained_source is None else retained_source
    newest = bundle_read(origin, latest)
    current = latest
    for bundle in chain(origin, latest, through=newest['through']):
        fixture['objects'][current] = encoded(bundle)
        current = bundle['previous']
    payload = request(owner, storage, latest, newest['through'], kind, actor='operator')
    now = int(time.time())
    payload.update(key_id=fixture['pin']['key_id'], qualification=fixture['pin']['qualification'],
                   generation=hashlib.sha256(encoded(sorted(fixture['objects']))).hexdigest(),
                   issued_at=now, admit_before=now+3600,
                   enforcement=dict(mode='irrevocable-indefinite-complete-chain',
                                    versions=hashlib.sha256(encoded(sorted(fixture['objects']))).hexdigest(),
                                    evidence=hashlib.sha256(b'SYNTHETIC RETAINED FIXTURE COPY').hexdigest()))
    return dict(payload=payload, signature=fixture['signer'].sign(encoded(payload)).hex())
