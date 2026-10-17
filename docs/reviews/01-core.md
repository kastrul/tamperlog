# Codex review 1: core package

Date: 2026-10-17. Reviewer: Codex CLI (`codex exec --sandbox read-only`),
prompt asked for correctness, API design, concurrency, cryptographic
soundness, validation and documentation gaps over the root package,
`encoding/jcs`, `internal/jcs`, `seal`, `store/memory` and `internal/storetest`.
Raw transcript: `raw-01-core.txt` (not committed; summary below).

| # | Severity | Finding | Action |
|---|---|---|---|
| 1 | High | Stream algorithms not pinned: appenders with different encoders or hashers could extend one stream because all shipped digests are 32 bytes | Every `Record` now carries `Encoder` and `Hasher` identifiers; `Head` returns the head's pair; `Appender.Append` refuses a mismatch with `ErrAlgorithmMismatch`; `Walk` reports `ReasonAlgorithm`; PostgreSQL trigger compares with the head; conformance test `AlgorithmChangeIsRefused` |
| 2 | High | Timestamps truncated to microseconds silently, so a stored `At` could differ from the hashed one by up to 999 ns and still verify | `ValidateTime` requires microsecond alignment and the range `[MinTime, MaxTime]`; both encoders refuse other values; appender validates after stamping; tests for nanosecond, pre-1970 and post-`MaxTime` values |
| 3 | High | Memory store: `Heads` and `FirstSeqs` read slices under a different lock than writers | Each stream now has an append-ownership lock (channel) and a separate `RWMutex` over its records; readers take the read lock; test `HeadsWhileAppending` runs under `-race` |
| 4 | Medium | Time regression bound documented but never enforced on append | `Head.At` added; `stamp` refuses a time more than the tolerance before the head, for store-clock and caller-time modes; test `TestTimeRegressionIsRefused` |
| 5 | Medium | Memory seal getters returned aliased slices | Deep copies on every read path; conformance test `ReadResultsAreCopies` mutates results and re-reads |
| 6 | Medium | Memory lock waits ignored context cancellation; lock order undocumented | Channel-based lock with `select` on `ctx.Done()`; `Store` doc states the fixed lock order rule; conformance test `HeadWaitHonoursContext` |
| 7 | Medium | `seal.Parse` accepted structurally invalid documents | `Seal.Validate` shared by `Canonical` and `Parse`: sequence bounds, genesis rule, sorted unique legal stream names, algorithm IDs, ranges, digest sizes, writer, signature/key_id pairing; `Parse` also rejects trailing data; `seal_test.go` added |
| 8 | Medium | `Log.Append` leaked the transaction on a panic in a hook or encoder | Deferred `Rollback(context.WithoutCancel(ctx))` right after `Begin`; test `TestLogAppendRollsBackOnPanic` |
| 9 | Low | Package doc formula omitted length prefixes; golden vectors covered four of six pairs; SPEC and THREAT_MODEL absent | Formula corrected; golden test iterates every encoder and hasher pair and checks full canonical bytes; SPEC.md and THREAT_MODEL.md are written in the documentation step |

Confirmed sound by the reviewer: length-prefixed algorithm identifiers in the
hash input, separate domain for drop digests, UTF-8 and size validation, JCS
escaping and UTF-16 key order, genesis handling and overlapping-page guidance
in `Walk`, the package documentation's statement of the chain's limits.
