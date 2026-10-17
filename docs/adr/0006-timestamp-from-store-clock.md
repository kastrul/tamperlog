# 0006. Timestamp comes from the store clock; caller time is opt-in with skew bounds

Status: accepted, 2026-10-17.

## Context

A caller-supplied timestamp lets a compromised application backdate events.
PADI reads `clock_timestamp()` under the stream lock. Some callers record
events that happened elsewhere and must keep the original time.

## Decision

By default `Store.Head` returns the store's clock and the appender stamps the
record with it. `WithCallerTime()` makes the appender accept `Event.At`, but it
rejects values more than `SkewTolerance` (default 5 s) from the store clock or
more than 1 s before the previous record's time. The PostgreSQL BEFORE INSERT
trigger enforces the same bounds, so the database checks what Go asserts.

## Consequences

- Monotonic-within-tolerance timestamps per stream; verifiers check this.
- Callers with genuinely late events record the original time in an attribute
  and let the chain carry the write time.
- The in-memory store takes an injectable clock for deterministic tests.
