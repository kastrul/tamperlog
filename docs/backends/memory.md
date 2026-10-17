# In-memory backend

`store/memory` keeps every stream in a slice and is the reference
implementation of the storage contract. Use it in unit tests, examples and
tools; nothing is durable.

```go
s := memory.New(memory.WithClock(func() time.Time { … }))
log := tamperlog.NewLog(s)
```

Behaviour worth knowing:

- `Head` takes a per-stream append lock held until `Commit` or `Rollback`,
  and honours context cancellation while waiting.
- Readers (`Heads`, `FirstSeqs`, `Range`) use a separate read-write mutex
  over the records, so sealing and verifying never block on an open
  transaction.
- Every read returns copies; mutating a result does not touch the store.
- `Records`, `Replace` and `Drop` are test helpers that simulate reading the
  table directly, a privileged rewrite and a retention drop. They exist so
  the verifier can be exercised; they are not part of any interface.
- The clock defaults to `time.Now`; inject one for deterministic timestamps.

It passes the same conformance suite (`internal/storetest`) as the database
backends.
