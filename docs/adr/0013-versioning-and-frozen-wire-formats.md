# 0013. v0.x Go API; wire formats frozen and versioned by identifier

Status: accepted, 2026-10-17.

## Context

An audit chain written today must verify in ten years. The Go API, by
contrast, will improve with use.

## Decision

The module starts at v0.1.0 and follows semantic versioning; minor releases
may change the Go API until v1. Every wire format carries an identifier
(`binary/v1`, `jcs/v1`, `sha256`, `tamperlog.seal/1`, `tamperlog.bundle/1`,
`tamperlog/v1` domain). Once a format identifier ships in a tagged release its
bytes never change; a change is a new identifier, and old identifiers remain
verifiable forever. `CHANGELOG.md` records both API and format changes.

## Consequences

- `SPEC.md` is normative; a change to it that alters existing bytes is a bug.
- Verifiers must support every identifier ever released.
