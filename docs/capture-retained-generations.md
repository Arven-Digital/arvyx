# Retained capture generations (private implementation contract)

Status: source protocol under implementation; not storage qualification or release approval.

## Trust and physical retention

An ordinary directory is an untrusted read cache, not authority to erase local
capture. Content hashes, fsync, inode pinning and resumable walks prove reads,
not continued existence. No source-only algorithm can prove physical retention
on an externally mutable filesystem.

The supported boundary is an independently operated retention-enforcing store
and its Ed25519 attestation issuer. Before use, the human explicitly pins the
issuer public key, storage identity and SHA-256 of an independently reviewed
storage-enforcement qualification document. The document must establish enforced
irrevocable indefinite retention (including all predecessors), immutable object
versions, durable commit before attestation, authenticated retrieval and a
loss/incident contract. A mutable-directory process that merely signs promises
is NOT a qualified issuer. This implementation does not install a store, issue
credentials, qualify a supplier, or manufacture a physical-retention proof.
Without such a separately qualified issuer there is no pruning or adoption.

## Generation and admission

A v1 receipt is a closed JSON envelope with payload and Ed25519 signature.
The signed payload binds the domain, pinned qualification hash and key ID,
exact storage directory/device/inode, exact owner-database device/inode,
current head and sequence, requested new complete-chain head and through,
operation (ack or relocate), unique generation ID, issue/admit-before times,
and an immutable complete-chain retention enforcement object.
The chain's SHA-256 head is its recursive content root: each immutable bundle
binds all row bytes and predecessor digest through genesis. The issuer MUST
validate continuity through genesis and lock ALL these versions before issuing;
locking only the newest object is not sufficient. The enforced object carries
the store's immutable version-set identifier and independent evidence reference.
Only the prequalified issuer can assert these facts; the client has no issuing
helper. The signed statement remains a supplier attestation, not direct proof
of physical media durability. Enforcement and disaster-loss behavior require
separate operational qualification.

A bounded local walk still validates bundle syntax, continuity and local run
membership. Its cursor is keyed by the authenticated immutable commitment hash
(all payload fields except admission timestamps) as well as head, storage and
owner DB incarnation. Every continuation and the final
SQLite admission reverify the receipt against current pinned, nonrevoked trust,
wall-clock admission validity and exact operation scope. No saved cursor becomes
retention authority. Expired receipts require a fresh authenticated issuer renewal;
only unchanged scope/issuer/qualification/generation/enforced version-set can
resume the existing cursor. Admission timestamps do not change those perpetual
retention facts. A different commitment restarts the bounded walk. This avoids
a one-hour lifetime limit on large chains; there is no unbounded full-history
fallback. Admission is serialized with the
human trust mutation by the owner lock. A final expiry check follows SQLite
writer reservation. Unknown/malformed/untrusted receipts preserve capture and
storage binding. Prepare/copy may produce cache bytes without authority; ack and
relocate cannot release/rebind without the appropriate receipt.

## Replay, expiry and revocation

Receipts have at most a one-hour admission window. They bind old head as well as
new head: successful ack advances head atomically with the accepted receipt;
replay then fails the exact-prefix compare. Relocation is idempotent only while
its exact old head/storage/DB identity still matches. Key revocation or key
replacement invalidates pending jobs, never allows their ready bits to bypass
admission, and forbids new use. Admission expiration/revocation DOES NOT release
the store's irrevocable indefinite retention obligation for previously accepted
generations. A store with revocable/finite object locks is unsupported by v1.
Clock rollback before issuance is rejected; trustworthy host time and human key
administration are deployment prerequisites, not claims of this offline source.

## Recovery and boundedness

A fixed singleton accepted-generation receipt accompanies the existing durable
head; no per-history local receipt list grows. Each new complete generation
retains its predecessors forever. At most eight bounded progress jobs coexist.
Local run digest marks remain bounded by existing runs. Receipt JSON is capped
at 16 KiB. Existing explicit paging remains available; there is no automatic
network retrieval or automatic deletion of either cache/archive objects.

Relocation requires a new target-store commitment for the full same chain,
including a separately qualified target identity. Copying is not commitment.
Recovery/capture inventory still independently checks all classified offload
bytes while offline/quiescent; accepted metadata is not a substitute for copying
history. A restored DB/directory has new device/inode identity and must obtain
fresh admission via explicit relocation; copied trust/receipts do not silently
authorize pruning in a new incarnation. Missing receipts/keys/qualified storage
leave rows and authority intact. Loss of previously retained data is an incident:
freeze further pruning/adoption, restore from independently retained versions,
and do not claim that preserved head metadata reconstructs missing payloads.
No retention-aware remote recovery service is provisioned here.

## Qualification still required

All regressions are authored, NOT_EXECUTED. Signature failure, stale segment
removal, expiry during writer wait, revoked keys, wrong scope/incarnation,
relocation, interrupted SQLite commit, issuer misbehavior, retained-version
retrieval and disaster recovery need authorized execution and independent review.
The bounded protocol exists only with the independent storage contract; the
current ordinary directory alone remains incapable of bounded safe pruning.
