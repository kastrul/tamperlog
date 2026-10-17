# Adopting tamperlog in a system with an existing chain (PADI)

tamperlog's `binary/v1` encoding is modelled on PADI's `audit.link()` but is
not byte-compatible: identifiers are opaque strings rather than 16-byte UUIDs,
attributes are hashed, and the hash input is domain-separated and names the
encoder and hasher. PADI's existing records therefore cannot be verified by
tamperlog's `Chain.Walk`, and tamperlog records cannot be verified by PADI's
walker. Two ways to adopt the library:

## 1. Cut over with a bridging record (recommended)

1. Stop appending to the old chain at a chosen moment `T`. Record each old
   stream's final head `(seq, hash)` and verify the old chain one last time
   with its own walker.
2. Start new tamperlog streams under the same names. As the first record of
   each stream (seq 1, linking to genesis), append a bridging event, for
   example action `chain.migrated`, entity `stream`, with attributes
   `legacy_head_seq`, `legacy_head_hash` (hex) and `legacy_encoding`
   (`padi/link-v1`). The bridging record is hashed like any other, so the old
   head becomes part of the new chain's history.
3. Seal immediately and anchor the first seal, so the moment of migration is
   attested externally.
4. Keep the old table read-only (revoke INSERT) and keep the old walker and
   its golden vector in the repository for as long as the old records are
   retained; the verifier for old history is the old code.

An auditor then has two artefacts: the old chain verified by the old walker up
to its final head, and the new chain whose first record commits to that head.

## 2. Convert history (not recommended)

Re-encoding every old record under `binary/v1` and recomputing the chain
produces a new history whose hashes nobody anchored at the time the events
happened. That is a rewrite, and tamper evidence is about detecting rewrites.
Only do this if no seal or external commitment of the old chain exists and
the old records are being treated as unverified data anyway, and say so in
the DPIA.

## Mapping PADI fields

| PADI | tamperlog |
|---|---|
| `Stream` (`audit`, `auth`, `chat`, `classification`) | `Stream`, same names allowed |
| `ActorID`, `SubjectID`, `EntityID` (UUIDv7) | `Actor`, `Subject`, `EntityID` as the canonical UUID string; keep the "pseudonymous UUID only" rule in the application |
| `Action`, `Entity` | same, now also allowing digits |
| `PayloadHash` (SHA-256) | `PayloadHash`; prefer `tamperlog.Commit` with a salt kept beside the payload |
| `At` from `clock_timestamp()` under `pg_advisory_xact_lock` | `Head.Now` from the same query, same lock key shape (`tamperlog:` prefix instead of `eelvisiit.audit:`) |
| `partition.drop` event with a text digest | `tamperlog.DropEvent` in the system stream with edge hashes in attributes |
| E17 hourly seals (planned) | `seal.Writer` with the S3 Object Lock sink |
| qualified timestamps (planned) | `anchor/rfc3161` with SK ID Solutions; `eutl` for qualified status |
| `audit.Walk` and the quarterly restore drill | `verify.Verifier`, `verify.Runner` nightly, `tamperlog verify --bundle` offline |

## Database objects

PADI's migrations already give the owner/role separation the role template
produces. The BEFORE INSERT trigger in `store/postgres/sql/schema.sql` is the
one the research report recommended as step 2; it can be applied to PADI's
table with the column names adjusted (`encoder` and `hasher` columns are new).
PADI's partition lifecycle functions remain the operator's; see
`docs/backends/postgres.md` for how drops and the verifier fit together.
