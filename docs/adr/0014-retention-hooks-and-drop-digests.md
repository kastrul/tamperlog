# 0014. Retention is supported by hooks and drop digests, not automated

Status: accepted, 2026-10-17.

## Context

Health data retention runs from one to thirty years per stream. Dropping old
records leaves a gap in `seq`; a verifier must distinguish a legitimate drop
from a deletion. PADI bridges gaps with a `partition.drop` event whose payload
hash commits to the dropped range. Partition DDL differs per backend and
deployment.

## Decision

The library defines `tamperlog.DropDigest(hasher, stream, firstSeq,
firstPrevHash, lastSeq, lastHash)` and the convention that a `retention.drop`
event in the system stream carries that digest as `PayloadHash` with the range
in attributes. Seals include the digests of drops since the previous seal. The
verifier accepts a gap only when a sealed drop digest matches the hashes at its
edges. Partition creation and dropping are documented for PostgreSQL and left
to the user.

## Consequences

- A stream's newest record must never be dropped, so no stream restarts from
  genesis.
- Drop events live in the system stream, which by convention never expires.
