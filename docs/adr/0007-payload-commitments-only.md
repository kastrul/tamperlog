# 0007. Payloads are committed to by hash, never stored in the chain

Status: accepted, 2026-10-17.

## Context

GDPR Article 17 erasure and an immutable chain conflict unless personal data
stays out of the chain. The accepted pattern is to store a hash commitment in
the immutable record and the payload in an erasable table. A plain hash of
low-entropy personal data can be brute-forced.

## Decision

`Event.PayloadHash` is the only payload field. The library ships
`tamperlog.Commit(hasher, salt, payload)` returning `HMAC(salt, payload)` and
documents storing the salt beside the erasable payload. Payload storage is the
caller's responsibility; the library does not ship a payload table.

## Consequences

- Erasing a payload leaves the chain verifiable; the commitment becomes
  unverifiable, which is the intended outcome and is documented for DPIAs.
- The verifier never needs payloads.
- Identifiers in the core fields must be pseudonyms, since they cannot be
  erased.
