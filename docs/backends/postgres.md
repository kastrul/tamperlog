# PostgreSQL backend

Two packages share one schema and one body of logic (`store/postgres`):

| Package | Use when |
|---|---|
| `store/pgx` | the application uses `github.com/jackc/pgx/v5` directly (pool and `pgx.Tx`) |
| `store/pgsql` | the application uses `database/sql` with pgx's stdlib adapter, lib/pq or another PostgreSQL driver |

Tested against PostgreSQL 18; the SQL uses nothing newer than PostgreSQL 14
(`hashtextextended`, `ENABLE ALWAYS TRIGGER`, `jsonb_typeof`).

## Install the schema

```go
pool, _ := pgxpool.New(ctx, dsn)
if err := pgx.Migrate(ctx, pool, pgx.WithSchema("audit")); err != nil { … }
```

`Migrate` runs `store/postgres/sql/schema.sql` with `__SCHEMA__` replaced; it
is idempotent. The connecting role needs `CREATE` on the schema and the right
to create functions and triggers, which the application role must not have,
so run it from a migration step with a migration credential. Projects with
their own migration tooling render the SQL with `postgres.Schema(name)` and
ship it as a migration; the file is also readable as-is.

Then, once, with administrator credentials, apply the role template
(`postgres.Roles(schema, appRole)` renders `sql/roles.sql`): it creates the
sealed `NOLOGIN` owner `tamperlog_owner`, moves the tables and functions to
it, grants `SELECT, INSERT` on the tables to the application role and nothing
else, and fails with a clear error if the result is weaker than intended.

## Tables

| Table | Holds |
|---|---|
| `tamperlog_event` | one row per record; primary key `(stream, seq)`; CHECK constraints mirror the Go validation (stream, action and entity patterns, identifier lengths, hash sizes, `attributes` is a JSON object) |
| `tamperlog_stream_head` | one row per stream, used only as a lock target in head-row mode |
| `tamperlog_seal` | `seq`, `sealed_at`, `hash` (SHA-256 of `body`), `body` (canonical seal bytes) |
| `tamperlog_proof` | `seal_seq`, `provider`, `obtained_at`, `body`; one proof per seal and provider |
| `tamperlog_schema` | installed schema version |

Column types: `at`, `sealed_at`, `obtained_at` are `timestamptz`
(microsecond precision, which the library's canonical time matches); hashes
are `bytea`; `attributes` is `jsonb`. The canonical bytes that are hashed are
recomputed in Go from the columns, never from a `jsonb` rendering, so
`jsonb`'s key reordering is harmless.

## Triggers

| Trigger | Fires on | Effect |
|---|---|---|
| `tamperlog_event_check_link` | BEFORE INSERT | takes `pg_advisory_xact_lock(hashtextextended('tamperlog:' \|\| stream, 0))`, then refuses the row unless `seq = head + 1` (1 for an empty stream), `prev_hash = head.hash` (32 zero bytes for seq 1), `at` within 5 s of `clock_timestamp()` read after the lock and not more than 1 s before the head's `at`, `encoder`/`hasher` equal the head's, every attribute value is a string, and, for `binary/v1` + `sha256`, `hash` equals `tamperlog_link_binary_v1_sha256(NEW)`, the Go link recomputed in SQL (`tamperlog_canonical_binary_v1` reproduces SPEC.md section 1.2 byte for byte and is asserted against the golden vector in the integration tests) |
| `tamperlog_event_append_only` | BEFORE UPDATE OR DELETE | raises `insufficient_privilege` |
| `tamperlog_event_no_truncate` | BEFORE TRUNCATE | raises |
| `tamperlog_seal_check` | BEFORE INSERT | seal `seq` must be the last plus one |
| `tamperlog_seal_append_only`, `tamperlog_seal_no_truncate`, `tamperlog_proof_append_only`, `tamperlog_proof_no_truncate` | | raise |

All triggers are `ENABLE ALWAYS`, so `SET session_replication_role = replica`
(a superuser's usual way of silencing triggers) does not disable them.

What the triggers achieve: a client that holds only `INSERT` (the application
role, or an attacker who stole its password) cannot backdate, cannot create
duplicate sequence numbers, cannot change or remove anything, and with the
default algorithms cannot insert a wrong hash that would poison the chain.
With `sha3-256` or `sha512-256` the hash is not recomputed (PostgreSQL has no
built-in SHA-3) and a wrong hash is caught by the verifier instead.

What they do not achieve: the table owner, a superuser, anyone with `ADMIN`
on `tamperlog_owner`, or root on the host can `ALTER TABLE … DISABLE
TRIGGER`, rewrite rows and re-enable. On a managed service the provider holds
superuser and the service administrator credential is owner-tier. Those actors
are detected by seals and anchors, not prevented here (THREAT_MODEL.md).

## Transactions

`pgx.Bind(tx)` / `pgsql.Bind(tx)` wrap a transaction the application opened,
so the audit record commits or rolls back with the business change. Rules:

- Append **last** in the transaction. `Head` holds the stream's advisory lock
  until commit; everything after it serialises behind other appenders.
- Use `READ COMMITTED` (the default). The lock and the head read are separate
  statements, and the second takes a fresh snapshot that sees the previous
  lock holder's commit. Under `REPEATABLE READ` or `SERIALIZABLE` the snapshot
  predates the lock and the append would reuse a sequence number; the trigger
  then refuses it, so the failure is loud, but avoid it.
- Several streams in one transaction: lock them in a fixed order (sort the
  stream names) to avoid deadlocks.

`pgx.New(pool)` / `pgsql.New(db)` give a `Provider` for `tamperlog.Log`, the
seal writer, the anchor runner and the verifier. Its `Begin` opens
`READ COMMITTED` transactions.

## Lock modes

`WithLockMode(postgres.LockAdvisory)` (default): transaction-scoped advisory
lock keyed by the stream name. No rows, no bloat; visible in `pg_locks` as
`advisory` with the hashed key. The trigger takes the same key, so a client
that skipped the Go lock is still serialised.

`WithLockMode(postgres.LockHeadRow)`: `INSERT … ON CONFLICT DO NOTHING` plus
`SELECT … FOR UPDATE` on `tamperlog_stream_head`. Visible by stream name in
`pg_locks`; portable to databases without advisory locks; one extra row per
stream.

## Partitioning and retention

The shipped table is not partitioned. To partition by `at` (monthly, as a
health platform with multi-year retention will want), create the table with
`PARTITION BY RANGE (at)` and a primary key `(stream, seq, at)` instead; the
trigger still enforces uniqueness of `(stream, seq)` under the lock. Dropping a
partition is a retention drop: in the same transaction, append a
`tamperlog.DropEvent` for every stream range the partition holds (edge hashes
come from the first and last row of that stream in the partition), then drop.
A stream's newest row must never be in a dropped partition. The verifier
accepts the resulting gap only when those drop events are sealed. PADI's
`SECURITY DEFINER` lifecycle functions are a worked example of doing this
server-side.

## Backups and replication

Logical replication of `tamperlog_event`, `tamperlog_seal` and
`tamperlog_proof` with `publish = 'insert'` to a vault under a different
administrator gives a second copy that never receives UPDATE or DELETE. It is
outside the library; the research notes in the design document describe the
operational caveats (slot retention, failover slots).

## Integration tests

```bash
docker compose up -d
export TAMPERLOG_PG_DSN='postgres://tamperlog:tamperlog@localhost:55433/tamperlog?sslmode=disable'
go test -race -tags integration ./store/pgx/ ./store/pgsql/
```

Each subtest creates its own schema and drops it afterwards. The tests include
the conformance suite in both lock modes, caller-transaction binding, every
trigger refusal, and the `session_replication_role = replica` bypass attempt.
