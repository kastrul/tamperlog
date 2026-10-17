package sqlite_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kastrul/tamperlog"
	"github.com/kastrul/tamperlog/internal/storetest"
	"github.com/kastrul/tamperlog/store/sqlite"
)

// open returns a migrated temp-file database and a provider over it.
func open(t *testing.T) (*sql.DB, *sqlite.Provider) {
	t.Helper()
	db, err := sqlite.Open(filepath.Join(t.TempDir(), "tamperlog.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := sqlite.Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	return db, sqlite.New(db)
}

func TestConformance(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T) storetest.Provider {
		_, p := open(t)
		return p
	})
}

func TestMigrateIsIdempotent(t *testing.T) {
	t.Parallel()
	db, p := open(t)
	if _, err := tamperlog.NewLog(p).Append(t.Context(), event("s", "a")); err != nil {
		t.Fatal(err)
	}
	if err := sqlite.Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	var version, triggers int
	if err := db.QueryRowContext(t.Context(), `SELECT max(version) FROM tamperlog_schema`).Scan(&version); err != nil || version != sqlite.SchemaVersion {
		t.Fatalf("schema version = %d, %v", version, err)
	}
	if err := db.QueryRowContext(t.Context(), `SELECT count(*) FROM sqlite_master WHERE type = 'trigger' AND name GLOB 'tamperlog_*'`).Scan(&triggers); err != nil || triggers != 9 {
		t.Fatalf("%d triggers, %v", triggers, err)
	}
	heads, err := p.Heads(t.Context())
	if err != nil || heads["s"].Seq != 1 {
		t.Fatalf("data lost across migrate: %+v, %v", heads, err)
	}
}

func event(stream, action string) tamperlog.Event {
	return tamperlog.Event{Stream: stream, Actor: "u1", Action: action, Entity: "thing", EntityID: "t1", Attributes: map[string]string{"purpose": "test"}}
}

// mustFail runs the statement and requires an error whose text contains want.
func mustFail(t *testing.T, db *sql.DB, want, query string, args ...any) {
	t.Helper()
	_, err := db.ExecContext(t.Context(), query, args...)
	if err == nil {
		t.Fatalf("%s: accepted, want refusal containing %q", query, want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("%s: error %q does not mention %q", query, err, want)
	}
}

func TestTriggersRefuseChanges(t *testing.T) {
	t.Parallel()
	db, p := open(t)
	c := t.Context()
	log := tamperlog.NewLog(p)
	var head tamperlog.Record
	for _, a := range []string{"a", "b"} {
		var err error
		if head, err = log.Append(c, event("s", a)); err != nil {
			t.Fatal(err)
		}
	}
	zero := make([]byte, len(head.Hash))
	now := time.Now().UnixMicro()

	t.Run("UpdateEvent", func(t *testing.T) {
		mustFail(t, db, "append-only", `UPDATE tamperlog_event SET actor = 'x' WHERE stream = 's' AND seq = 1`)
	})
	t.Run("DeleteEvent", func(t *testing.T) {
		mustFail(t, db, "append-only", `DELETE FROM tamperlog_event WHERE stream = 's' AND seq = 2`)
		mustFail(t, db, "append-only", `DELETE FROM tamperlog_event`)
	})
	insert := `INSERT INTO tamperlog_event (stream, seq, at, actor, subject, action, entity, entity_id, encoder, hasher, payload_hash, attributes, prev_hash, hash)
VALUES (?, ?, ?, '', '', 'x', 'y', '', ?, ?, NULL, '{}', ?, ?)`
	t.Run("WrongSeq", func(t *testing.T) {
		mustFail(t, db, "seq does not follow", insert, "s", 4, now, head.Encoder, head.Hasher, head.Hash, head.Hash)
		mustFail(t, db, "seq does not follow", insert, "fresh", 2, now, head.Encoder, head.Hasher, zero, head.Hash)
	})
	t.Run("WrongPrevHash", func(t *testing.T) {
		mustFail(t, db, "prev_hash does not match", insert, "s", 3, now, head.Encoder, head.Hasher, zero, head.Hash)
		mustFail(t, db, "prev_hash does not match", insert, "fresh", 1, now, head.Encoder, head.Hasher, head.Hash, head.Hash)
	})
	t.Run("WrongAlgorithm", func(t *testing.T) {
		mustFail(t, db, "encoder or hasher", insert, "s", 3, now, head.Encoder, "sha3-256", head.Hash, head.Hash)
		mustFail(t, db, "encoder or hasher", insert, "s", 3, now, "jcs/v1", head.Hasher, head.Hash, head.Hash)
	})
	t.Run("BackdatedAt", func(t *testing.T) {
		mustFail(t, db, "database clock", insert, "s", 3, now-6_000_000, head.Encoder, head.Hasher, head.Hash, head.Hash)
		mustFail(t, db, "database clock", insert, "s", 3, now+6_000_000, head.Encoder, head.Hasher, head.Hash, head.Hash)
	})
	t.Run("AtPrecedesHead", func(t *testing.T) {
		// A head stamped 4 s in the future is within the clock window; a
		// record 2 s before it is within the window too but regresses.
		future := time.Now().Add(4 * time.Second).UnixMicro()
		if _, err := db.ExecContext(c, insert, "ahead", 1, future, head.Encoder, head.Hasher, zero, head.Hash); err != nil {
			t.Fatal(err)
		}
		mustFail(t, db, "precedes the stream head", insert, "ahead", 2, future-2_000_000, head.Encoder, head.Hasher, head.Hash, head.Hash)
	})
	t.Run("CheckConstraints", func(t *testing.T) {
		mustFail(t, db, "CHECK", insert, "Bad Stream", 1, now, head.Encoder, head.Hasher, zero, head.Hash)
		mustFail(t, db, "CHECK", insert, "short", 1, now, head.Encoder, head.Hasher, zero[:8], head.Hash[:8])
		mustFail(t, db, "CHECK", insert, "s", 3, now, "", head.Hasher, head.Hash, head.Hash)
	})
	t.Run("ValidInsertPasses", func(t *testing.T) {
		if _, err := db.ExecContext(c, insert, "s", 3, now, head.Encoder, head.Hasher, head.Hash, head.Hash); err != nil {
			t.Fatal(err)
		}
	})

	body := []byte(`{"seq":1}`)
	if _, err := db.ExecContext(c, `INSERT INTO tamperlog_seal (seq, sealed_at, hash, body) VALUES (1, ?, ?, ?)`, now, zero[:32], body); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(c, `INSERT INTO tamperlog_proof (seal_seq, provider, obtained_at, body) VALUES (1, 'rfc3161', ?, ?)`, now, body); err != nil {
		t.Fatal(err)
	}
	t.Run("SealAndProofAppendOnly", func(t *testing.T) {
		mustFail(t, db, "append-only", `UPDATE tamperlog_seal SET body = x'00' WHERE seq = 1`)
		mustFail(t, db, "append-only", `DELETE FROM tamperlog_seal WHERE seq = 1`)
		mustFail(t, db, "append-only", `UPDATE tamperlog_proof SET body = x'00'`)
		mustFail(t, db, "append-only", `DELETE FROM tamperlog_proof`)
	})
	t.Run("SealSeqAndProofTarget", func(t *testing.T) {
		mustFail(t, db, "seal seq does not follow", `INSERT INTO tamperlog_seal (seq, sealed_at, hash, body) VALUES (3, ?, ?, ?)`, now, zero[:32], body)
		mustFail(t, db, "unknown seal", `INSERT INTO tamperlog_proof (seal_seq, provider, obtained_at, body) VALUES (7, 'rfc3161', ?, ?)`, now, body)
	})
}

func TestBindUsesCallerTransaction(t *testing.T) {
	t.Parallel()
	db, p := open(t)
	c := t.Context()
	a := tamperlog.New()

	tx, err := db.BeginTx(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Append(c, sqlite.Bind(tx), event("s", "a")); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if heads, err := p.Heads(c); err != nil || len(heads) != 0 {
		t.Fatalf("rolled back append is visible: %+v, %v", heads, err)
	}

	tx, err = db.BeginTx(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := a.Append(c, sqlite.Bind(tx), event("s", "a"))
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	heads, err := p.Heads(c)
	if err != nil || heads["s"].Seq != 1 || string(heads["s"].Hash) != string(r.Hash) {
		t.Fatalf("heads after commit = %+v, %v", heads, err)
	}
}

func TestClockIsInjectable(t *testing.T) {
	t.Parallel()
	db, _ := open(t)
	fixed := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	p := sqlite.New(db, sqlite.WithClock(func() time.Time { return fixed }))
	tx, err := p.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context()) //nolint:errcheck // cleanup
	h, err := tx.Head(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	if !h.Now.Equal(fixed) {
		t.Fatalf("Now = %s, want %s", h.Now, fixed)
	}
}

func TestOpenKeepsCallerQuery(t *testing.T) {
	t.Parallel()
	db, err := sqlite.Open(filepath.Join(t.TempDir(), "q.db") + "?_pragma=synchronous(NORMAL)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck // cleanup
	var sync, fk, timeout int
	var journal string
	row := db.QueryRowContext(context.Background(), `SELECT (SELECT synchronous FROM pragma_synchronous), (SELECT foreign_keys FROM pragma_foreign_keys), (SELECT timeout FROM pragma_busy_timeout), (SELECT journal_mode FROM pragma_journal_mode)`)
	if err := row.Scan(&sync, &fk, &timeout, &journal); err != nil {
		t.Fatal(err)
	}
	if sync != 1 || fk != 1 || timeout != 5000 || journal != "wal" {
		t.Fatalf("synchronous=%d foreign_keys=%d busy_timeout=%d journal_mode=%s", sync, fk, timeout, journal)
	}
}
