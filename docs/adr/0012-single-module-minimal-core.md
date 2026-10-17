# 0012. Single module; root package depends on the standard library only

Status: accepted, 2026-10-17.

## Context

Backends and providers need pgx, modernc sqlite, aws-sdk-go-v2, kong and
OpenTelemetry. Importers of the core should not pay for them. Nested modules
add release coordination for a small library.

## Decision

One `go.mod`. The root package `tamperlog`, `encoding/*`, `hash`, `sign`,
`seal`, `anchor`, `verify` and `bundle` import only the standard library and
`golang.org/x/crypto` where the standard library lacks a primitive. Heavy
dependencies live in `store/pgx`, `store/pgsql`, `store/sqlite`,
`seal/sinks/s3lock`, `otel` and `cmd/tamperlog`. Go's module graph pruning
means importers of the root only download what their packages import.

## Consequences

- `go.sum` lists all dependencies, but builds of the core pull none of the
  heavy ones.
- A `depguard` lint rule keeps the core free of third-party imports.
- Splitting into nested modules later is a non-breaking change for importers.
