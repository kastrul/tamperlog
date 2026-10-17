# 0002. Store is bound to the caller's transaction

Status: accepted, 2026-10-17.

## Context

An audit event must commit or roll back with the change it records; otherwise
a failed business write leaves a phantom event or a successful write leaves no
trace. The only atomic unit available to a Go service on one database is the
local transaction. PADI's implementation binds its store to the caller's `Tx`.
Some callers (seal writer, verifier, small services) have no business
transaction and want a one-call append.

## Decision

`tamperlog.Store` is an interface over one open transaction: `Head` (locks the
stream until the transaction ends and returns the last link plus the store
clock), `Insert`, `Range`. Each backend offers a constructor that wraps its
native transaction type (`pgx.Tx`, `*sql.Tx`, SQLite connection). The
`Appender` never opens a transaction.

A `StoreProvider` interface (`Begin`, `Heads`, `FirstSeqs`, seal table access)
is what the convenience `Log`, the seal writer and the verifier use. `Log.Append`
opens, appends and commits in one call for callers without a business
transaction.

## Consequences

- Callers that need atomicity use `Appender.Append(ctx, store, event)` with a
  store bound to their transaction and call it last, because the stream lock
  is held until commit.
- Isolation: the backend documentation states that the head must be read after
  the lock under a snapshot that sees the previous holder's commit (READ
  COMMITTED on PostgreSQL).
- The in-memory store implements both interfaces and is the reference for the
  conformance suite in `internal/storetest`.
