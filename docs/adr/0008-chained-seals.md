# 0008. Seals are chained JCS documents over all stream heads, unsigned by default

Status: accepted, 2026-10-17.

## Context

A chain head stored only in the database is a consistency check, not evidence.
Azure SQL ledger uploads digests every 30 seconds; CloudTrail delivers hourly
signed digest files that reference the previous digest and emits empty digests
so absence of activity is also attested.

## Decision

A `seal.Writer` produces, every interval (default 1 h), one document:

```json
{"schema":"tamperlog.seal/1","sealed_at":"…","prev_seal_hash":"…",
 "streams":[{"stream":"…","encoder":"binary/v1","hasher":"sha256",
             "first_kept_seq":1,"head_seq":1234,"head_hash":"…"}],
 "drops":["…"],"writer":"…","key_id":"…","signature":"…"}
```

serialised with RFC 8785 JCS. `prev_seal_hash` is the SHA-256 of the previous
seal's canonical bytes, so the seal sequence is itself a chain. Seals are
written even when no head changed. A `Signer` is optional; when configured,
`signature` covers the canonical bytes without the `signature` member. Seals
are stored in a seal table and pushed to every configured `Sink`.

## Consequences

- A deleted or replaced seal is visible without any external party.
- The document names no person; it holds stream names, sequence numbers,
  hashes and times.
- The TSA token (ADR 0009) binds to the seal's SHA-256.
