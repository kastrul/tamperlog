# SQLite backend

Package `github.com/kastrul/tamperlog/store/sqlite` is a
`tamperlog.Provider` and `seal.Store` over `database/sql` with the pure Go
driver `modernc.org/sqlite`. It needs no cgo and no build tag. It suits
single-host services, desktop and edge deployments, and tests of code that
will run on PostgreSQL in production.

## Opening and migrating

```go
db, err := sqlite.Open("/var/lib/app/audit.db")
if err != nil { ... }
defer db.Close()
if err := sqlite.Migrate(ctx, db); err != nil { ... }
p := sqlite.New(db)
log := tamperlog.NewLog(p)
```

`Open` accepts a file path or a `file:` URI with an optional query string and
adds `_pragma=busy_timeout(5000)`, `_pragma=journal_mode(WAL)` and
`_pragma=foreign_keys(ON)`. The pragmas apply to every connection the pool
opens. Do not use `:memory:`: `database/sql` opens several connections and
each would see its own empty database. If you open the pool yourself, set at
least `busy_timeout` on every connection, or a second writer fails at once
instead of waiting.

`Migrate` runs the embedded schema (`sql/schema.sql`, also available as
`sqlite.Schema()` for your own migration tooling) in one transaction. It is
idempotent: tables are created `IF NOT EXISTS`, triggers are dropped and
recreated, and the version row is inserted `OR IGNORE`. Run it on every start.

## Binding to your transaction

When an event records a business change, append it in the same transaction so
both commit or roll back together:

```go
tx, err := db.BeginTx(ctx, nil)
if err != nil { ... }
defer tx.Rollback()
// ... business writes ...
if _, err := appender.Append(ctx, sqlite.Bind(tx), event); err != nil {
    return err // the business change must fail too
}
return tx.Commit()
```

Call `Append` last. `Head` takes SQLite's single writer lock for the rest of
the transaction, so everything after it runs while other appenders wait.

### How the lock works

SQLite allows one writer per database at a time. `Head` writes the stream's
row in `tamperlog_stream_head` (`INSERT OR IGNORE`, so the second and later
calls change nothing) as its first statement. That write takes the database
writer lock until the transaction ends, which serialises appenders
database-wide rather than per stream. A second writer waits; `Head` honours
the context, so a deadline or cancellation returns an error instead of waiting
forever. Readers (`Range` in a transaction that has not called `Head`,
`Heads`, `FirstSeqs`, the seal methods) never block writers and never wait for
them, because of WAL mode.

Call `Head` before you read in the same transaction. A transaction that holds a
read snapshot cannot wait for the writer lock: if another writer committed in
the meantime SQLite returns `SQLITE_BUSY_SNAPSHOT` and the transaction must be
retried. `Appender.Append` and `Log.Append` always call `Head` first.

## Clock

SQLite has no server clock. `Head.Now` is the process clock (`time.Now`, or
the function given to `sqlite.WithClock`), and the BEFORE INSERT trigger
compares the stamped time with SQLite's own `julianday('now')`, which is the
same process clock. The consequences:

- A compromised application can lie about the time within 5 seconds, exactly
  as on PostgreSQL; beyond that the trigger refuses the row.
- A clock injected for tests must stay within 5 seconds of real time, or
  inserts fail at the trigger. Inject a clock to control `Head.Now` in tests
  that do not insert, or keep it near real time.
- Verifiers use the same one second time tolerance as every other backend.

## Storage format

| Column | Type | Note |
|---|---|---|
| `at`, `sealed_at`, `obtained_at` | `INTEGER` | Unix microseconds, UTC |
| `payload_hash`, `prev_hash`, `hash`, `body` | `BLOB` | `payload_hash` is `NULL` when absent |
| `attributes` | `TEXT` | JSON object; `{}` when empty |
| `encoder`, `hasher` | `TEXT` | the record's algorithm identifiers |

`Range` reads timestamps back as UTC `time.Time`, a `NULL` payload hash as a
nil slice and `{}` attributes as a nil map.

## What the triggers enforce

- `tamperlog_event`, `tamperlog_seal` and `tamperlog_proof` refuse `UPDATE`
  and `DELETE`, including `DELETE` without `WHERE`. SQLite has no `TRUNCATE`.
- A new event must have `seq = head + 1` (1 for an empty stream), `prev_hash`
  equal to the head's hash (all zero bytes of the hash length for seq 1), the
  same `encoder` and `hasher` as the head, `at` within 5 seconds of the SQLite
  clock and not more than one second before the head's `at`.
- A new seal must have `seq = last + 1`.
- A new proof must point at a stored seal. The foreign key says the same but
  SQLite enforces it only with `foreign_keys = ON`; the trigger holds either way.
- CHECK constraints mirror `Event.Validate`: name shapes (via `GLOB`, exact
  for these grammars), byte lengths, hash lengths between 32 and 64 bytes,
  `prev_hash` and `payload_hash` the same length as `hash`, attributes a JSON
  object, and column types (`typeof`) so SQLite's loose typing cannot smuggle
  text into a hash column.

## What the triggers do not enforce

SQLite has no roles. Anyone who can open the database file for writing can
drop a trigger, run `PRAGMA writable_schema`, rewrite rows, or edit pages with
a hex editor; a trigger is advisory against the file owner. The triggers stop
mistakes and careless clients: an application that forgets to compute the
head, a migration that would backfill, an operator's ad hoc `DELETE`.

Tamper evidence comes from the layers above the chain:

- seals written to a sink the application host cannot overwrite (another
  machine, object storage with Object Lock, a directory owned by the DPO);
- anchors from a timestamp authority over seal hashes;
- the verifier, which starts from the outermost layer.

Restrict file permissions to the service user, keep the database on a volume
with backups you can compare against, and write seals somewhere else.

## WAL mode

`Open` sets `journal_mode=WAL`. WAL is persistent in the database file and
creates `-wal` and `-shm` files beside it; copy all three or use the `.backup`
command when you back the database up. WAL lets readers run while a writer
holds the lock, which is what keeps `Heads`, `FirstSeqs` and the seal writer
from waiting behind appenders. WAL does not work on network file systems; keep
the file on local disk.

## Conformance

`go test ./store/sqlite/...` runs the shared conformance suite in
`internal/storetest` against a temporary file database plus tests that the
triggers refuse updates, deletes, wrong sequence numbers, wrong `prev_hash`,
algorithm changes and backdated timestamps.
