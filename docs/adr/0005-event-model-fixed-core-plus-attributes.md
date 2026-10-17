# 0005. Event model: fixed core fields, opaque string identifiers, ordered attributes

Status: accepted, 2026-10-17.

## Context

Healthcare audit models (HL7 FHIR AuditEvent, EHDS Annex II, IHE ATNA) agree on
acting user, subject, action, resource, time and a purpose or context. PADI
uses UUIDs for identifiers. A generic opaque payload would push structure onto
callers and make queries impossible; a strict UUID type would exclude ULIDs,
pseudonyms and external systems.

## Decision

```go
type Event struct {
    Stream, Actor, Subject, Action, Entity, EntityID string
    PayloadHash []byte
    Attributes  map[string]string
    At          time.Time
}
```

Identifiers are opaque UTF-8 strings; the empty string means absent and is
encoded as a zero-length field. `Action` and `Entity` are required and limited
to lowercase ASCII words joined by `.` or `_`. `Attributes` is encoded in
byte-wise key order and is for small, non-identifying context such as
`purpose=treatment`. `PayloadHash` is nil or exactly the hasher's size.

## Consequences

- No dependency on a UUID package. Callers that want UUID semantics validate
  before appending.
- Attribute keys and values are hashed, so they must not contain personal data
  that may need erasure; the documentation says so.
- Validation rules are enforced in Go and mirrored as CHECK constraints in the
  shipped SQL.
