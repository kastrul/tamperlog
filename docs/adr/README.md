# Architecture decision records

One file per decision, numbered in the order taken. A superseded record stays
and points at its replacement. Format: Context, Decision, Consequences.

| ADR | Title |
|---|---|
| [0001](0001-hash-chain-in-application-as-system-of-record.md) | Hash chain computed in the application is the system of record |
| [0002](0002-store-bound-to-caller-transaction.md) | Store is bound to the caller's transaction |
| [0003](0003-pluggable-canonical-encoding.md) | Canonical encoding is pluggable; binary/v1 default, jcs/v1 shipped |
| [0004](0004-domain-separated-hash-input.md) | Hash input is domain-separated and pins encoder and hasher |
| [0005](0005-event-model-fixed-core-plus-attributes.md) | Event model: fixed core fields, opaque string identifiers, ordered attributes |
| [0006](0006-timestamp-from-store-clock.md) | Timestamp comes from the store clock; caller time is opt-in with skew bounds |
| [0007](0007-payload-commitments-only.md) | Payloads are committed to by hash, never stored in the chain |
| [0008](0008-chained-seals.md) | Seals are chained JCS documents over all stream heads, unsigned by default |
| [0009](0009-anchoring-policy.md) | Anchoring: RFC 3161 first; write the seal, then anchor; record failure in a system stream |
| [0010](0010-database-hardening-shipped-as-sql.md) | Database hardening is shipped as SQL and triggers per backend |
| [0011](0011-configurable-stream-locking.md) | Stream locking is configurable: advisory lock or head row |
| [0012](0012-single-module-minimal-core.md) | Single module; root package depends on the standard library only |
| [0013](0013-versioning-and-frozen-wire-formats.md) | v0.x Go API; wire formats frozen and versioned by identifier |
| [0014](0014-retention-hooks-and-drop-digests.md) | Retention is supported by hooks and drop digests, not automated |
| [0015](0015-verification-from-the-outer-layer.md) | Verification starts from the outermost layer |
