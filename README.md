# tamperlog

Tamper-evident audit trails for Go services: a per-stream hash chain written
in your own database transaction, periodic seals in write-once storage,
RFC 3161 timestamps on every seal (qualified under eIDAS when the authority
you configure is a qualified trust service provider), and a verifier that
starts from the evidence an insider cannot forge and works inward.

Built for a health-data platform (GDPR Article 9, EU MDR, NIS2, E-ITS), where
the question an auditor asks is not "do you have logs" but "can your own
database administrator rewrite them without anyone noticing". tamperlog's
answer is detection by comparison against commitments stored where that
administrator cannot write.

```
go get github.com/kastrul/tamperlog
```

Go 1.27. Apache-2.0. v0.x: the Go API may still change; wire formats are
frozen and versioned (SPEC.md).

## How it fits together

```
┌──────────────────────────────────────────────────────────────────────┐
│ L4  external anchors        anchor/rfc3161 (+ eutl for qualified     │
│     RFC 3161 token binds    status)                                  │
│     each seal hash to time  defends against: everyone inside the     │
│                             operator, DB and storage providers       │
├──────────────────────────────────────────────────────────────────────┤
│ L3  seals in WORM storage   seal.Writer → seal table + sinks         │
│     hourly chained JCS doc  (fs, S3 Object Lock)                      │
│     of every stream head    defends against: DBA rewriting rows,     │
│                             deleting tails or streams                │
├──────────────────────────────────────────────────────────────────────┤
│ L2  database                shipped SQL: CHECKs, BEFORE INSERT       │
│     triggers check links,   trigger (seq, prev_hash, clock, hash),   │
│     refuse change           append-only triggers, role template      │
│                             defends against: INSERT-only clients     │
├──────────────────────────────────────────────────────────────────────┤
│ L1  application chain       tamperlog.Appender in your transaction   │
│     hash = H(domain‖ids‖    canonical encoding, dense seq, store     │
│     prev‖canonical(record)) clock; defends against: naive edits      │
└──────────────────────────────────────────────────────────────────────┘
  verification runs top-down: proofs → seal chain + sink copies → live
  chain against sealed heads and sealed retention drops
```

THREAT_MODEL.md states, per layer, who can do what and what is detected.

## Quick start

```go
import (
    "github.com/kastrul/tamperlog"
    tlpgx "github.com/kastrul/tamperlog/store/pgx"
)

// Once, from a migration step with a migration credential:
_ = tlpgx.Migrate(ctx, pool, tlpgx.WithSchema("audit"))

appender := tamperlog.New()

// In every handler that touches patient data, inside the business transaction:
tx, _ := pool.Begin(ctx)
defer tx.Rollback(ctx)
// ... the business write ...
_, err := appender.Append(ctx, tlpgx.Bind(tx, tlpgx.WithSchema("audit")), tamperlog.Event{
    Stream:     "access",
    Actor:      clinicianPseudonym,   // never a name or national identifier
    Subject:    patientPseudonym,
    Action:     "record.read",
    Entity:     "patient_record",
    EntityID:   recordID,
    Attributes: map[string]string{"purpose": "treatment"},
})
if err != nil {
    return err // fail the request: an unrecorded access must not succeed
}
return tx.Commit(ctx)
```

Then, as a background job (one instance per deployment):

```go
provider := tlpgx.New(pool, tlpgx.WithSchema("audit"))
sink := s3lock.New(s3Client, "audit-seals")            // bucket with COMPLIANCE Object Lock
writer := seal.NewWriter(provider, seal.WithSinks(sink), seal.WithWriterName("myapp 1.4.2"))
go writer.Run(ctx, time.Hour, onError)

tsa := rfc3161.NewProvider(
    rfc3161.New("https://tsa.sk.ee/..."),                  // SK ID Solutions (qualified)
    rfc3161.NewVerifier(skRoots, rfc3161.WithQualifiedChecker(eutl.Checker(list, nil))),
)
runner := anchor.NewRunner(provider, tsa, anchor.WithSinks(sink), anchor.WithLog(tamperlog.NewLog(provider)))
go runner.Run(ctx)

v := verify.New(verify.WithAnchors(tsa), verify.WithSinks(sink), verify.WithMaxSealAge(3*time.Hour))
go verify.NewRunner(v, verify.FromProvider(provider), verify.WithLog(tamperlog.NewLog(provider)), verify.WithIncremental(24*time.Hour)).Run(ctx, time.Hour)
```

`examples/` holds runnable versions for memory, PostgreSQL and SQLite.

## Packages

| Package | What |
|---|---|
| `tamperlog` | `Event`, `Record`, `Store`, `Appender`, `Log`, `Chain.Walk`, hashers, `binary/v1` encoder, payload commitments, drop events |
| `encoding/jcs` | `jcs/v1` encoder (RFC 8785), human-readable canonical form |
| `store/pgx`, `store/pgsql`, `store/postgres` | PostgreSQL over pgx or database/sql; shared SQL, triggers, role template |
| `store/sqlite` | SQLite over modernc.org/sqlite (pure Go) |
| `store/memory` | in-memory reference implementation |
| `seal`, `seal/sinks/fs`, `seal/sinks/s3lock` | seal format and writer, write-once sinks |
| `sign` | Ed25519 and HMAC seal signers |
| `anchor`, `anchor/rfc3161`, `anchor/rfc3161/eutl` | anchoring runner, RFC 3161 client and verifier, EU Trusted List loader |
| `verify` | verifier library and continuous runner |
| `bundle` | export bundle for offline verification |
| `otel` | OpenTelemetry metrics through hook points |
| `cmd/tamperlog` | CLI |

The root package and `seal`, `sign`, `anchor`, `verify`, `bundle` depend on
the standard library and `golang.org/x/crypto` only; drivers and SDKs live in
their subpackages.

## CLI

```bash
go install github.com/kastrul/tamperlog/cmd/tamperlog@latest

tamperlog migrate --driver pgx --dsn "$DSN" --schema audit
tamperlog seal    --driver pgx --dsn "$DSN" --schema audit --sink-dir /srv/seals --interval 1h
tamperlog anchor  --driver pgx --dsn "$DSN" --schema audit --sink-dir /srv/seals \
                  --tsa-url http://tsa.demo.sk.ee/tsa --tsa-roots sk-test-tsa-ca.pem
tamperlog verify  --driver pgx --dsn "$DSN" --schema audit --sink-dir /srv/seals \
                  --tsa-roots sk-test-tsa-ca.pem --max-seal-age 3h
tamperlog export  --driver pgx --dsn "$DSN" --schema audit --out /tmp/bundle
tamperlog verify  --bundle /tmp/bundle --tsa-roots sk-test-tsa-ca.pem --no-sinks   # no database needed
tamperlog inspect token /srv/seals/seals/000000000001.rfc3161.proof
```

`verify` refuses to run unless every external layer is either configured or
explicitly skipped (`--tsa-roots` or `--no-anchors`; a sink or `--no-sinks`;
`--max-seal-age` or `--no-freshness`), and prints the scope it ran with. It
exits 0 when every check passes, 1 when a finding has severity error, 2 when
the evidence could not be read (source or sink errors) or the configuration is
rejected; in continuous mode the status reflects the last report when the
process is stopped. Flags double as environment variables (`TAMPERLOG_DSN`,
…). The SK ID Solutions demo endpoint and its test CA
certificate (`TEST of SK TSA CA 2023E`, from the SK certificate repository)
work without an account; production access is a contract with SK.

## What it does not do

- It does not stop a compromised application from writing plausible events
  or withholding them. Fail the request when `Append` fails, keep credentials
  short-lived, and alert on silence.
- It does not make a database administrator unable to edit rows. It makes the
  edit visible at the next full verification that has seals and anchors to
  compare against (an incremental run re-links only new records; records
  newer than the last seal are not yet committed to anything).
- It does not store payloads. Commit to them with `tamperlog.Commit` and keep
  them in an erasable table, so GDPR erasure leaves the chain intact.
- Shipped in v0.1: no OpenTimestamps provider, no KMS or Vault signer (the
  interfaces are there), no automated partition lifecycle, no MySQL backend.

## Documentation

| | |
|---|---|
| SPEC.md | normative wire formats and test vectors |
| THREAT_MODEL.md | per-layer defends / cannot defend |
| docs/design.md, docs/adr/ | design and the fifteen decisions behind it |
| docs/backends/ | PostgreSQL, SQLite, memory: SQL, triggers, roles, transactions |
| docs/anchors/ | RFC 3161 client and verifier, EU Trusted List |
| docs/sinks/ | S3 Object Lock bucket requirements and policies |
| docs/migration-from-padi.md | adopting the library next to an existing chain |
| docs/reviews/ | independent review rounds and what changed |
| CHANGELOG.md | releases, API and format changes |

## Development

```bash
make test            # unit tests, race detector
docker compose up -d # PostgreSQL on port 55433
export TAMPERLOG_PG_DSN='postgres://tamperlog:tamperlog@localhost:55433/tamperlog?sslmode=disable'
make integration     # PostgreSQL integration tests
make lint            # golangci-lint v2, strict preset
```

Live network tests are opt-in: `TAMPERLOG_TSA_LIVE=1` (SK demo TSA),
`TAMPERLOG_EUTL_LIVE=1` (EU Trusted List), `TAMPERLOG_S3_ENDPOINT` and
friends (a real bucket).
