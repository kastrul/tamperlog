# tamperlog design

Status: approved 2026-10-17. Decisions are recorded individually in `docs/adr/`.
Wire formats are specified normatively in `SPEC.md`; what each layer defends
against is in `THREAT_MODEL.md`.

## What it is

`github.com/kastrul/tamperlog` is a reusable Go library for tamper-evident
audit trails. It implements the layered design from the report: an
application-side hash chain per stream (L1), shipped database hardening SQL
(L2), chained seals written to write-once storage (L3), and external anchoring
with RFC 3161 qualified timestamps (L4), plus a verifier that starts from the
outermost layer and works inward.

Apache-2.0. `go 1.27`. Single module; root package depends only on the
standard library and `golang.org/x/crypto`. Backends, anchors, sinks, OTel and
the CLI live in subpackages so importers pay only for what they use.
Private GitHub repository `kastrul/tamperlog`, pushed after each milestone.

## Decisions from the interview

| Topic | Decision |
|---|---|
| Repo | New folder `/Users/jan/workspace/personal/tamperlog`, fresh `git init`, private `kastrul/tamperlog` |
| Licence, Go | Apache-2.0, `go 1.27` |
| Backends | PostgreSQL via pgx/v5; PostgreSQL via `database/sql`; SQLite via modernc (pure Go); exported in-memory store |
| Transactions | Core `Appender` joins the caller's transaction (`Store` bound to a Tx). Convenience `Log.Append` opens and commits its own transaction |
| Event model | Fixed core: `Stream`, `Seq`, `At`, `Actor`, `Subject`, `Action`, `Entity`, `EntityID`, `PayloadHash` plus ordered `Attributes map[string]string`. IDs are opaque strings; empty means absent |
| Timestamp | Default: database clock read under the stream lock. `WithCallerTime()` opt-in; Go rejects `At` outside ±5 s of the store clock or more than 1 s before the previous event. PG trigger enforces the same bounds |
| Payload | Commitment only: optional 32-byte `PayloadHash`. Helper for salted commitments so an erased payload cannot be brute-forced from the hash |
| Encoding | `Encoder` interface. Ship `binary/v1` (length-prefixed, big-endian, PADI-style) as default and `jcs/v1` (RFC 8785). Encoder ID is part of the domain-separated hash input |
| Hashing | `Hasher` interface. Ship SHA-256 (default), SHA3-256, SHA-512/256. Algorithm ID pinned in hash input and in seals |
| Keyed modes | No per-row keys. `Signer` interface (Sign, Verify, KeyID) applied to seals. Ship Ed25519 and HMAC-SHA256 signers. KMS/Vault left as interface with documented example |
| Seals | One chained seal per interval (default 1 h) over all stream heads. JCS JSON: `schema`, `sealed_at`, `prev_seal_hash`, per stream `{stream, first_kept_seq, head_seq, head_hash, encoder, hasher}`, `drops` (retention drop digests since last seal), `writer`, optional `signature` + `key_id`. Empty seals when idle. Stored in a seal table and pushed to sinks |
| Anchors | RFC 3161 TSA client (own ASN.1 implementation; SK demo endpoint in examples and integration tests). Full token verification: CMS signature, ESSCertID, imprint, nonce, chain to pinned roots, timestamping EKU. Plus EU Trusted List loader (LOTL and national TL parsing to check QTSP status at `genTime`). OpenTimestamps not shipped; `Anchor` interface allows it later |
| Sinks | `Sink` interface. Ship S3 Object Lock sink (aws-sdk-go-v2, `If-None-Match: *`, verify single version) and filesystem write-once sink |
| Anchor failure | Seal always written locally. Anchoring retried with backoff up to grace period (default 4 h), then `anchor.failed` event appended and hook fires. Business writes never blocked |
| Verification | Library API (`Walk`, incremental `VerifyStream`, `VerifySeals`, structured `Report`); offline CLI; continuous `Verifier` runner; self-describing export bundle (events JSONL, seals, tokens, manifest) |
| Database helpers | Per backend: embedded schema SQL (tables, refuse-change trigger, BEFORE INSERT invariant trigger, role grant template), `Migrate(ctx, db)`, documented manual path |
| Locking | Configurable: PG advisory `xact` lock per stream (default) or head-row `SELECT ... FOR UPDATE`. SQLite: `BEGIN IMMEDIATE`. Memory: mutex |
| Retention | Hooks only: `DropDigest(...)` helper, `retention.drop` event convention, verifier accepts gaps bridged by sealed drop digests. Partition DDL documented, not automated |
| System stream | Reserved stream `_tamperlog` for `seal.written`, `anchor.failed`, `chain.verified`, `chain.broken`, `retention.drop`. Renamable by option |
| Observability | `*slog.Logger` option (default discard); OpenTelemetry metrics in `otel` subpackage (API only); `Hooks` struct |
| Config | Functional options; no env or file loading in core. CLI uses kong with flags and env |
| Stability | v0.x. Go API may change; wire formats (`binary/v1`, `jcs/v1`, `seal/1`, bundle/1) frozen once released and versioned by ID |
| CLI | `cmd/tamperlog` (kong): `verify`, `seal`, `export`, `anchor`, `migrate` |
| Tests | Unit tests with golden vectors and property tests (`pgregory.net/rapid`); integration tests behind `-tags integration` with DSN from env (`TAMPERLOG_PG_DSN`), `docker-compose.yml` provided; `go test -race`; golangci-lint v2 strict preset; GitHub Actions |
| Docs | README with quick start and architecture diagram; godoc on every exported identifier; THREAT_MODEL.md; docs/design.md; docs/adr/; SPEC.md (normative wire formats and test vectors); docs/backends/*.md; docs/migration-from-padi.md; examples/; CHANGELOG.md; docs/reviews/ (Codex review notes) |
| PADI compatibility | Not byte-compatible. Migration document explains re-genesis or cut-over with a bridging event |

## Package layout

```
tamperlog/                 core: Event, Record, Head, Store, Appender, Log, Walk, errors, options
  encoding/binary          binary/v1 canonical encoder
  encoding/jcs             jcs/v1 canonical encoder (RFC 8785)
  hash/                    Hasher registry: sha256, sha3-256, sha512-256
  sign/                    Signer interface, ed25519, hmac
  seal/                    Seal format, Writer, Sink interface, seal verification
  seal/sinks/fs            write-once filesystem sink
  seal/sinks/s3lock        S3 Object Lock sink
  anchor/                  Anchor interface, retry policy, pending store
  anchor/rfc3161           TSA client, token parser, verifier
  anchor/rfc3161/eutl      EU Trusted List loader
  verify/                  Verifier runner, Report, bundle reader
  bundle/                  export bundle writer and reader
  store/memory             in-memory Store
  store/pgx                PostgreSQL via pgx/v5 (+ embedded SQL)
  store/pgsql              PostgreSQL via database/sql (+ shared SQL)
  store/sqlite             SQLite via modernc.org/sqlite (+ embedded SQL)
  otel/                    OpenTelemetry metrics instrumentation
  cmd/tamperlog            kong CLI
  internal/storetest       conformance suite every Store must pass
  docs/, examples/, SPEC.md, THREAT_MODEL.md, CHANGELOG.md
```

## Core API sketch

```go
type Event struct {
    Stream, Actor, Subject, Action, Entity, EntityID string
    PayloadHash []byte            // nil or 32 bytes
    Attributes  map[string]string // encoded in key order
    At          time.Time         // zero unless WithCallerTime
}

type Record struct {
    Event
    Seq      int64
    At       time.Time
    PrevHash []byte
    Hash     []byte
}

type Head struct { Seq int64; Hash []byte; Now time.Time }

// Store is bound to one transaction.
type Store interface {
    Head(ctx, stream) (Head, error)        // locks stream until tx end
    Insert(ctx, Record) error
    Range(ctx, stream, first, last int64) ([]Record, error)
}

// StoreProvider opens transactions for Log, the seal writer and the verifier.
type StoreProvider interface {
    Begin(ctx) (Tx, error)                 // Tx embeds Store + Commit/Rollback
    Heads(ctx) (map[string]Head, error)
    FirstSeqs(ctx) (map[string]int64, error)
    Seals: PutSeal, LastSeal, Seals(range)
}

a := tamperlog.New(tamperlog.WithEncoder(binary.V1), tamperlog.WithHasher(hash.SHA256))
rec, err := a.Append(ctx, store /* tx-bound */, ev)   // same-transaction append
log := tamperlog.NewLog(provider, opts...)            // convenience, own tx
```

Hash input: `H(domain ‖ encoderID ‖ hasherID ‖ prevHash ‖ canonical(record))`,
where `domain = "tamperlog/v1"`. Genesis `prevHash` is 32 zero bytes (hash
length for the chosen hasher).

## Build order

1. Scaffold: module, licence, lint, CI, docs skeleton, ADRs 0001–0010.
2. Core: Event, encoders, hashers, Appender, Walk, golden vectors, property tests, memory store, conformance suite.
3. Stores: pgx, pgsql, sqlite with SQL, triggers, migrations, integration tests.
4. Seals: format, writer, fs sink, s3lock sink, seal verification.
5. Anchors: rfc3161 client and verifier, eutl loader, retry policy.
6. Verify: library API, continuous runner, bundle format, CLI.
7. Docs: README, SPEC, THREAT_MODEL, backends, examples, migration note, CHANGELOG.
8. Codex review after steps 2, 3, 4+5, 6, 7; notes in docs/reviews/.

## Deliberately out of scope for v0.1

OpenTimestamps provider; KMS and Vault signers (interface only); automated
PostgreSQL partition lifecycle; MySQL/MariaDB store; PADI byte-compatible
encoder; Merkle inclusion proofs; logical replication tooling.
