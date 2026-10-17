# 0003. Canonical encoding is pluggable; binary/v1 default, jcs/v1 shipped

Status: accepted, 2026-10-17.

## Context

Hashes are computed over bytes. Re-serialising a record at verification time
is the most common failure in audit-log systems: JSON key order, number
formatting and timestamp text all drift. Two approaches are sound: an
injective length-prefixed binary form (PADI's cryptobyte style) and RFC 8785
JSON Canonicalization Scheme, which auditors can read.

## Decision

`Encoder` is an interface with an identifier and `Encode(Record) []byte`. The
library ships:

- `binary/v1`: fields in fixed order, integers as 8-byte big-endian, variable
  fields as 4-byte big-endian length followed by bytes, attributes as a count
  followed by sorted key and value pairs. Default.
- `jcs/v1`: the record as an I-JSON object serialised per RFC 8785.

The encoder identifier is part of the hash input (ADR 0004) and is recorded in
every seal, so a stream cannot silently change encoding.

## Consequences

- Each encoder has golden vectors in `SPEC.md` and tests; an edit to either
  breaks the vectors, which is the intent.
- A stream uses one encoder for its lifetime. Changing it means a new stream
  or a documented re-genesis.
- Users may implement their own `Encoder` but then own its specification.
