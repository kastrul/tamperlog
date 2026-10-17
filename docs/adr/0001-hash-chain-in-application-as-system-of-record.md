# 0001. Hash chain computed in the application is the system of record

Status: accepted, 2026-10-17.

## Context

The research report compared six designs: in-database trigger hash chains,
application-layer HMAC or signatures, Merkle logs with external anchoring,
ledger databases, PostgreSQL platform controls and SIEM retention. Every
single-operator mechanism reduces to the same guarantee: tampering is
detectable only by comparison against a commitment the tamperer cannot reach.
An in-database chain can be recomputed by anyone who can disable a trigger. A
ledger database adds a second stateful system and the dual-write problem
without adding provable integrity.

## Decision

The library computes the per-stream hash chain in Go, in the same transaction
as the business change, and treats that chain as the system of record. The
database only stores links and checks their shape (ADR 0010). Seals (ADR 0008)
and anchors (ADR 0009) carry the commitment outside the database. Ledger
databases, per-event signatures and Merkle inclusion proofs are not
implemented.

## Consequences

- The canonical encoding and hash input are part of the evidence and must be
  specified byte-exactly (`SPEC.md`) so a verifier with no access to the
  library can recompute every link.
- A compromised application can still write plausible events and withhold
  events. The threat model states this limit plainly.
- Throughput of one stream is bounded by the stream lock held from `Head` to
  commit. Callers append last in their transaction and shard busy workloads
  into several streams.
