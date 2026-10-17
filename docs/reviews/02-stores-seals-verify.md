# Codex review 2: stores, seals, anchoring runner, verifier, bundle, sinks

Date: 2026-10-17. Reviewer: Codex CLI (`codex exec --sandbox read-only`).
Scope: `store/postgres`, `store/pgx`, `store/pgsql`, `store/sqlite`,
`seal/writer.go`, `sign`, `anchor/runner.go`, `verify`, `bundle`,
`seal/sinks/fs`, `seal/sinks/s3lock`. The reviewer reproduced finding 11 in a
SQLite database; the rest came from source inspection.

| # | Severity | Finding | Action |
|---|---|---|---|
| 1 | High | Unsealed drop events legitimised deletions: a fabricated drop event with the right edge hashes made a gap "bridged" with only a warning | Only sealed drops authorise a gap; a pending drop leaves the gap unverified with `chain_gap_pending`. In addition, gaps are accepted only at the start of a stream (retention removes the oldest records); an inner gap is `chain_inner_gap` even when sealed, unless `WithAllowInnerGaps` is set for legacy layouts. Tests `TestInnerGapsAreErrorsEvenWhenSealed`, `TestMultipleConsecutiveDropsBridge` |
| 2 | High | Incremental verification never re-reads records before the checkpoint, so an edit that keeps the stored hash, or a deletion of a non-head record, stays hidden | Sealed heads before the checkpoint are now re-hashed, not only compared; `WithIncremental(fullEvery)` forces a full walk every `fullEvery` (default 24 h); `Report.Full` says which kind ran; the limit is stated in the option's documentation and in THREAT_MODEL.md |
| 3 | High | Evidence discovery only through the mutable source: a rollback of database and records to an older authentic seal was invisible even with later seals intact in a sink | `reconcileSinks` lists every sink's seal keys and reports seals beyond the source's last seal as `sink_extra_seal`, reading them back to say how far the chain continues; works also when the source has no seals at all. Test `TestSinkInventoryRevealsRollback` |
| 4 | High | Pagination stopped at the first short page, so a deleted seal in the middle hid every later seal (verifier, export, resync) | All three read `LastSeal` first and page up to it; the dense-sequence check then reports the hole |
| 5 | High | The PostgreSQL trigger checked linkage but not the hash: an INSERT-only client could poison the chain with a valid link and a garbage hash; non-string JSON attribute values were accepted | `tamperlog_canonical_binary_v1` and `tamperlog_link_binary_v1_sha256` reproduce the Go encoding in SQL and the trigger refuses a mismatching hash for the default `binary/v1` + `sha256` pair; attribute values must be strings. Other hasher pairs get shape checks only, which the schema comment and THREAT_MODEL.md state. Integration test asserts the SQL canonical bytes and link equal the Go golden vector and that a wrong hash is refused |
| 6 | Medium | Trigger read `clock_timestamp()` before waiting for the advisory lock | Clock read after the lock |
| 7 | Medium | `Config.Schema` spliced into SQL without validation | `NewStore` validates the identifier and every method returns the configuration error |
| 8 | Medium | Verifier runner raced on the checkpoint map across concurrent `Once` calls | `Once` holds the mutex for its whole duration and passes a deep copy |
| 9 | Medium | Several proofs per seal and provider collided in sinks and bundles; `ErrExists` was treated as success | Primary key `(seal_seq, provider)` in PostgreSQL, SQLite and memory; conformance test for the duplicate; `Resync` and the bundle exporter read back an existing object and fail on different bytes (`seal.PutOrCompare`, `ErrConflict`) |
| 10 | Medium | No freshness or interval policy for seals; future-dated seals accepted | `WithMaxSealAge`, `WithMaxSealInterval`, `WithFutureSkew` (default 5 min, error), `WithMaxAnchorDelay` (default 24 h, warning). Test `TestFreshnessPolicies` |
| 11 | Medium | SQLite `INSERT OR REPLACE` replaced a proof without firing the DELETE trigger when `recursive_triggers` is off | Proof INSERT trigger refuses an existing `(seal_seq, provider)`; `Open` sets `recursive_triggers(ON)` |
| 12 | Low | Ed25519 verifier accepted malformed keys and retained caller slices | Lengths validated at construction (`NewEd25519Verifier` now returns an error); keys cloned |

Confirmed sound by the reviewer: explicit READ COMMITTED with separate lock
and head statements, dense-sequence protection against forks, parameterised
SQL for values, explicit checks of seal bytes, hashes, signatures, predecessor
links and imprints, gap bridging edge-hash checks, the filesystem sink's
exclusive-link publication, S3 conditional writes and version checks.
