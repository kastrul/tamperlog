# 0011. Stream locking is configurable: advisory lock or head row

Status: accepted, 2026-10-17.

## Context

A hash chain needs a single writer per stream at the moment the previous hash
is read. PostgreSQL offers transaction-scoped advisory locks (no row, no
bloat) and row locks on a head table (portable, visible in `pg_locks` with a
name). SQLite serialises writers with `BEGIN IMMEDIATE`.

## Decision

PostgreSQL stores take a `LockMode` option: `LockAdvisory` (default,
`pg_advisory_xact_lock(hashtextextended('tamperlog:' || stream, 0))`) or
`LockHeadRow` (`SELECT … FOR UPDATE` on `tamperlog_stream_head`, inserting the
row on first use). The BEFORE INSERT trigger uses the same advisory key, which
is re-entrant within the transaction. SQLite uses `BEGIN IMMEDIATE`. The memory
store uses a per-stream mutex released on commit or rollback.

## Consequences

- The head-row mode keeps a redundant head table that the trigger also
  validates against the event table.
- Lock order is documented: callers that append to several streams in one
  transaction must do so in a fixed order.
