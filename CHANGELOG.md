# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Wire format identifiers are listed
separately because they are frozen independently of the Go API (ADR 0013).

## [Unreleased]

Initial development towards v0.1.0.

### Added

- Core: `Event`, `Record`, `Store`, `Provider`, `Appender` (same-transaction
  append), `Log` (own transaction), `Chain` with domain-separated hash input
  and `Walk`, per-stream pinned encoder and hasher, canonical microsecond
  timestamps, store-clock stamping with opt-in caller time and skew bounds,
  payload commitments (`Commit`), retention drop events with edge hashes
  (`DropEvent`, `ParseDrop`).
- Encoders `binary/v1` (default) and `jcs/v1`; hashers `sha256` (default),
  `sha3-256`, `sha512-256`.
- Stores: in-memory; PostgreSQL over pgx and database/sql with shipped
  schema, BEFORE INSERT link trigger that recomputes `binary/v1`+`sha256`
  hashes, append-only triggers (`ENABLE ALWAYS`), advisory or head-row
  locking, role template with postconditions; SQLite over modernc.org/sqlite
  with equivalent triggers. Conformance suite shared by all backends.
- Seals: `tamperlog.seal/1` chained JCS documents, writer with interval, drop
  listing, optional Ed25519 or HMAC signature, sinks (write-once filesystem,
  S3 Object Lock with conditional writes, checksums, version checks and a
  bucket preflight), resync.
- Anchors: provider interface, runner with backoff, grace period and
  `anchor.failed` system events; RFC 3161 client and full token verifier
  (CMS, ESSCertID, chain to pinned roots, EKU, policy, accuracy); EU Trusted
  List loader with cache for qualified-status checks.
- Verifier: anchors, seal chain, sink inventory and copies, live chain
  against sealed heads, prefix-only sealed drop bridging, freshness policies,
  incremental runs with periodic full walks, `chain.verified` and
  `chain.broken` system events; export bundle `tamperlog.bundle/1` for
  offline verification.
- OpenTelemetry metrics through hooks; `tamperlog` CLI (migrate, append,
  seal, anchor, verify, export, resync, inspect).
- Documentation: README, SPEC.md, THREAT_MODEL.md, design document, fifteen
  ADRs, backend, anchor and sink guides, PADI migration note, examples, two
  independent review rounds with their outcomes.

### Wire formats introduced

- `tamperlog/v1` hash domain, `tamperlog.drop/v1` drop digest domain,
  `binary/v1`, `jcs/v1`, `sha256`, `sha3-256`, `sha512-256`,
  `tamperlog.seal/1`, `tamperlog.bundle/1`, sink keys
  `seals/<12 digits>.json` and `seals/<12 digits>.<provider>.proof`.
