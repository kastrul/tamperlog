# 0009. Anchoring: RFC 3161 first; write the seal, then anchor; record failure in a system stream

Status: accepted, 2026-10-17.

## Context

An RFC 3161 token proves a hash existed by `genTime`; a qualified token from
an EU Trusted List provider carries the eIDAS Art. 41(2) presumption. SK ID
Solutions offers a free demo endpoint and published prices. X-Road batches
timestamps, tolerates TSA outages for a bounded period, and logs the gap.
OpenTimestamps is a useful free second anchor but was not selected for v0.1.

## Decision

- `anchor.Anchor` interface: `Anchor(ctx, digest) (Proof, error)` and
  `Verify(ctx, digest, Proof) error`.
- `anchor/rfc3161` implements a TSA client with full token verification
  (CMS signature, ESSCertID, imprint, nonce, chain to pinned roots, timestamping
  EKU) and `anchor/rfc3161/eutl` loads the EU List of Trusted Lists to check
  provider status at `genTime`.
- The seal is written to the seal table and sinks first. Anchoring runs
  afterwards with exponential backoff up to a grace period (default 4 h). When
  the grace period passes, an `anchor.failed` event is appended to the system
  stream `_tamperlog` and `Hooks.OnAnchorFailed` fires. Business writes never
  wait for anchoring.
- Proofs are stored beside the seal (table and sinks) under the seal's key with
  a provider suffix.

## Consequences

- A TSA outage leaves seals without tokens for its duration; the verifier
  reports those seals as unanchored rather than broken.
- The system stream is included in seals, so the record of a failure is itself
  sealed.
- Additional providers plug in behind the interface.
