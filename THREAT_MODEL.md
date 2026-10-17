# Threat model

tamperlog makes an audit trail tamper-evident, not tamper-proof. Tamper
evidence means: any change to history after the fact is detectable by
comparison against a commitment the changer could not reach. This document
says, per layer, who can do what, what the layer detects, and what it cannot.
It follows Schneier and Kelsey's limit, which no design escapes: nothing
protects entries written after an attacker controls the writer, and nothing
prevents deletion; cryptography guarantees detection when the log next meets
a party the attacker does not control.

## Actors

| Actor | Holds |
|---|---|
| Application bug | the application's code path; may skip or garble events |
| Compromised application | the application's database credentials, and any signing key in process memory |
| Database client with INSERT | the application role's password, issuing raw SQL |
| DBA / superuser | the table owner or a superuser; can disable triggers, rewrite rows, restore a different backup |
| Infrastructure administrator | the object storage account, the database service, backups |
| Outsider | network access only |

## Layer 1: application chain (package tamperlog)

Mechanism: each record carries `seq`, `prev_hash` and
`hash = H(domain ‖ ids ‖ prev_hash ‖ canonical(record))`, computed in Go
inside the business transaction under a per-stream lock. Canonical encodings
are injective and byte-exact. Timestamps come from the store clock and may not
regress beyond a tolerance. Every record names its encoder and hasher and a
stream keeps one pair.

Detects: accidental corruption, a naive edit of any field, reordering,
deletion inside a stream, a timestamp that regresses, a record linked with
another algorithm, a stream extended by a differently configured appender.

Cannot detect: an edit of the newest record that also recomputes its hash; a
rewrite of the whole chain from the edited record onward by anyone who can
write rows (the encoding is public and unkeyed); deletion of a stream's tail;
deletion of an entire stream; events that were never written. The chain head
stored only in the database is a consistency check, not evidence.

Residual for a compromised application: it writes plausible events, withholds
events, and (until the next seal) can do so without trace. Mitigations are
outside the library: fail the request when Append fails, short-lived
credentials, per-handler audit coverage tests, alert on silence from busy
handlers.

## Layer 2: database (shipped SQL, store/*)

Mechanism: CHECK constraints mirror the Go validation; a BEFORE INSERT
trigger takes the same per-stream lock and refuses a record unless `seq` is
the head plus one, `prev_hash` is the head's hash (genesis for `seq` 1), `at`
is within 5 s of the database clock (read after the lock) and not more than
1 s before the head, the encoder and hasher match the head, attribute values
are strings and, for the default `binary/v1` + `sha256` pair, the hash equals
the one PostgreSQL recomputes from the row; triggers refuse UPDATE, DELETE and
TRUNCATE for every role and are `ENABLE ALWAYS` on PostgreSQL so
`session_replication_role = replica` does not silence them; seals and proofs
have the same protections (one proof per seal and provider); the role
template makes a sealed `NOLOGIN` owner and an INSERT-only application role.

Detects or prevents: for a client holding only INSERT (the application role,
a compromised application), prevents backdating, duplicate sequence numbers,
skipped locks, every UPDATE, DELETE and TRUNCATE, and, with the default
algorithms on PostgreSQL, chain poisoning (a wrong hash that would break the
chain forever). With `sha3-256` or `sha512-256`, which PostgreSQL cannot
compute without extensions, and on SQLite, a wrong hash is not refused and is
caught by the next verification instead.

Cannot prevent: the table owner, a superuser, anyone with ADMIN on the owner
role, root on the database host. They can disable triggers, rewrite rows and
re-enable triggers. On a managed service the provider holds superuser; the
"DBA" threat is the service administrator credential and the provider's
staff. SQLite triggers stop nothing against anyone with write access to the
file. Layer 2 narrows who must be detected by layers 3 and 4; it does not
remove them.

## Layer 3: seals in write-once storage (package seal, sinks)

Mechanism: at a fixed interval a seal lists every stream's head sequence and
hash, first kept sequence, encoder and hasher, the retention drops since the
previous seal, and the SHA-256 of the previous seal. Seals are stored in the
database and pushed to sinks: a filesystem directory or an S3 bucket with
Object Lock. Seals are written even when nothing changed. Optionally a seal
is signed (Ed25519 or HMAC).

Detects, given one sink copy the attacker cannot rewrite: any rewrite of
records up to the sealed head (the sealed head hash no longer matches),
deletion of a stream's tail below the sealed head, deletion of a stream, a
seal removed from the database (the seal chain and the sink's copy disagree),
a seal replaced in the database (the sink holds other bytes; the next seal's
`prev_seal_hash` breaks), a quiet period claimed where there was activity or
the reverse. A seal signature additionally lets a verifier reject seals not
produced by the key holder, which stops an attacker who can write sink objects
but has no key.

Cannot detect: changes inside the current interval (bounded by the interval,
default one hour); rewrites by someone who controls both the database and
every sink (the infrastructure administrator), unless layer 4 anchors exist;
a compromised writer with the signing key producing signed seals over a
rewritten chain (a key in process memory is only as safe as the process).
Object Lock in COMPLIANCE mode survives the storage account's own
administrators until retention expires; account or project deletion is
provider-specific and undocumented for some providers. Store sinks under a
different administrative domain than the database, and prefer two.

## Layer 4: external anchors (package anchor, anchor/rfc3161)

Mechanism: the SHA-256 of each seal is sent to an RFC 3161 time-stamp
authority, which returns a signed token binding the hash to a time. The
token is verified cryptographically against pinned roots and the authority's
qualified status can be checked against the EU Trusted List. Anchoring never
blocks seals or business writes; a seal left unanchored past a grace period
is recorded in the system stream. Proofs are stored beside seals and in
sinks.

Detects: anyone inside the operator, the database provider and the storage
provider presenting a history different from the one that existed at the
attested time, including a complete rewrite of chain, seals and sink copies;
backdating of seals; a seal sequence truncated after anchoring. Under eIDAS
Art. 41(2) a qualified token carries the legal presumption of the accuracy of
its time and the integrity of the data bound to it.

Cannot detect: events inside the interval before the next anchored seal;
events never written; a compromised authority (mitigation: RFC 3161 advises
tokens from two authorities, and the `Provider` interface takes several).
Loss of all proofs (database and every sink) removes layer 4 for the affected
seals; copies pushed to a party outside the operator (the DPO, a customer, an
auditor) close that gap.

## Verification

Verification starts from the outermost layer: proofs are validated, then the
seal chain and sink copies, then the live chain against the sealed heads and
drops. A verifier that starts from the live table and checks its own
consistency proves nothing about a rewritten chain. The continuous verifier
runs inside the application's trust domain, which is acceptable because the
attacker it looks for is the privileged one who cannot forge proofs; its
outcome is appended to the system stream and should also go to monitoring.
The offline CLI runs the same checks over an export bundle with no access to
the system, which is what an auditor or regulator needs.

Incremental verification re-links only records after a checkpoint. It still
checks every seal, re-hashes every sealed head and compares the checkpoint
record, so a rewrite that reaches a sealed head or the checkpoint is caught;
an edit of a non-head record before the checkpoint that keeps its stored hash
is not seen until the next full walk, which the runner forces on a schedule
(default daily). The verifier also lists every configured sink and reports
seals a sink holds beyond the source's last seal, which is how a rollback of
database and records to an older authentic state shows up, and applies
freshness policies (latest seal age, maximum interval, future skew) so an
old but authentic state does not stay "verified" forever.

Gaps are accepted only at the start of a stream: retention removes the
oldest records. An inner gap is an error even with a sealed drop event, so
appending a drop event cannot legitimise a deletion in the middle of history
(a layout that drops inner ranges can opt in). Drop events not yet listed in a
seal leave their gap pending rather than verified.

## Retention and erasure

Dropping old records leaves a gap. A gap is legitimate only when drop events
in the system stream chain across it with matching edge hashes and their
digests appear in a seal. A gap without such events is a deletion. The system
stream itself should never expire. Payloads live outside the chain behind a
salted commitment, so GDPR erasure removes the payload and its salt and leaves
the chain verifiable; the commitment then proves only that something was
committed to, which is the intended outcome and should be stated in the DPIA.
Identifiers in records must be pseudonyms, because nothing in a chain can be
erased.

## Summary matrix

P = prevents, D = detects, D† = detects once a seal or anchor exists, blank = blind.

| Actor and act | L1 chain | L2 database | L3 seals in WORM | L4 anchors |
|---|---|---|---|---|
| Application bug garbles a record | D | P (trigger refuses) | | |
| Application withholds events | | | | |
| Compromised application fabricates events | | | | D† only against backdating |
| INSERT client backdates or poisons | | P | | |
| INSERT client updates or deletes | | P | | |
| DBA rewrites rows and recomputes | | | D† | D† |
| DBA deletes a tail or a stream | | | D† | D† |
| DBA disables triggers | | | D† (effects) | D† (effects) |
| Storage admin deletes sink objects before retention | | | P (COMPLIANCE) | D† |
| Operator with DB and all sinks rewrites everything | | | | D† |
| Everyone colludes, including the TSA | | | | |
