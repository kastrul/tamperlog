# 0004. Hash input is domain-separated and pins encoder and hasher

Status: accepted, 2026-10-17.

## Context

A hash over `prev_hash ‖ row` is enough for a single fixed format. With
pluggable encoders and hashers, a verifier must know which pair produced a
link, and a link produced under one pair must not be presentable as a link
under another. Schneier and Kelsey recommend a nonce that identifies the
application, version, protocol and step in every authenticated value.

## Decision

```
hash = H( "tamperlog/v1" ‖ len(encoderID) ‖ encoderID ‖ len(hasherID) ‖ hasherID
          ‖ prev_hash ‖ canonical(record) )
```

Lengths are 4-byte big-endian. `prev_hash` for the first record of a stream
is `H.Size()` zero bytes. `H` is one of the registered hashers (`sha256`,
`sha3-256`, `sha512-256`).

## Consequences

- Links are bound to their algorithms. The seal records encoder and hasher per
  stream, so an offline verifier can select them without the database.
- The genesis value depends on the hasher's output size, so hashers of
  different sizes cannot be mixed in one stream.
- `SPEC.md` carries test vectors for every shipped hasher and encoder pair.
