# 0010. Database hardening is shipped as SQL and triggers per backend

Status: accepted, 2026-10-17.

## Context

The application role should be unable to update, delete, backdate or poison
the chain. PostgreSQL can enforce `seq = head + 1`, `prev_hash = head.hash`,
timestamp bounds and append-only semantics in triggers. Leaving this to each
user's DBA means most deployments never get it.

## Decision

Each backend embeds its schema SQL and exposes `Migrate(ctx, db)`:

- event table with CHECK constraints mirroring the Go validation;
- seal and proof tables;
- BEFORE UPDATE OR DELETE trigger that raises;
- PostgreSQL: BEFORE INSERT trigger that takes the same advisory lock, checks
  head linkage and clock bounds; both triggers `ENABLE ALWAYS`;
- SQLite: equivalent triggers using `RAISE(ABORT)`;
- a role and grant template for PostgreSQL (`INSERT, SELECT` only for the
  application role; sealed `NOLOGIN` owner) that the user applies with
  administrator credentials.

## Consequences

- The SQL is documented in `docs/backends/*.md` for users who run their own
  migration tooling.
- The library states what the triggers do not stop: the table owner, a
  superuser, or anyone who can disable triggers. Seals and anchors detect
  those.
