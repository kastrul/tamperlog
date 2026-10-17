# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Wire format identifiers are listed
separately because they are frozen independently of the Go API (ADR 0013).

## [Unreleased]

### Added

- Core: `Event`, `Record`, `Store`, `Appender`, `Log`, `Walk`.
- Encoders `binary/v1` and `jcs/v1`; hashers `sha256`, `sha3-256`, `sha512-256`.
- Stores: memory, PostgreSQL (pgx and database/sql), SQLite.
- Seals, sinks (filesystem, S3 Object Lock), RFC 3161 anchoring, EU Trusted List loader.
- Verifier, export bundle, `tamperlog` CLI.

### Wire formats introduced

- `tamperlog/v1` hash domain, `binary/v1`, `jcs/v1`, `tamperlog.seal/1`, `tamperlog.bundle/1`.
