# 0015. Verification starts from the outermost layer

Status: accepted, 2026-10-17.

## Context

A verifier that starts from the live table and checks its own consistency
proves nothing about a rewritten chain. The artefacts an insider could not have
produced after the fact are the anchors, then the seals in write-once storage,
then the chain.

## Decision

`verify.Verifier` runs in this order: validate anchor proofs for each seal;
check the seal chain (`prev_seal_hash`, no missing interval, no second version
of a key); compare sealed heads with the live chain at the sealed sequence;
walk the chain between seals (links, contiguity, clock monotonicity, gaps
matched to sealed drops). It returns a `Report` with one finding per stream at
the first failure, and records `chain.verified` or `chain.broken` in the system
stream when run continuously. The offline CLI runs the same code against an
export bundle and a root pool, without a database.

## Consequences

- Verification is incremental from the last verified head to bound cost.
- A verifier in the application's trust domain is acceptable because the
  attacker it looks for is the privileged one, who cannot forge seals and
  tokens.
