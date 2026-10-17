//go:build integration

package pgx_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kastrul/tamperlog"
	"github.com/kastrul/tamperlog/internal/storetest"
	"github.com/kastrul/tamperlog/store/pgx"
	"github.com/kastrul/tamperlog/store/postgres"
)

// dsn is read from TAMPERLOG_PG_DSN; see docker-compose.yml.
func dsn(t *testing.T) string {
	t.Helper()
	d := os.Getenv("TAMPERLOG_PG_DSN")
	if d == "" {
		t.Skip("TAMPERLOG_PG_DSN not set")
	}
	return d
}

// freshSchema creates a schema with a unique name, migrates it and drops it
// on cleanup, so subtests do not see each other's rows.
func freshSchema(t *testing.T, opts ...pgx.Option) (*pgxpool.Pool, string) {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn(t))
	if err != nil {
		t.Fatal(err)
	}
	schema := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' {
			return r
		}
		return '_'
	}, fmt.Sprintf("t_%d_%s", time.Now().UnixNano()%1_000_000_000, strings.ToLower(t.Name())[:min(20, len(t.Name()))]))
	if _, err := pool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		pool.Close()
	})
	if err := pgx.Migrate(ctx, pool, append(opts, pgx.WithSchema(schema))...); err != nil {
		t.Fatal(err)
	}
	// Idempotent.
	if err := pgx.Migrate(ctx, pool, append(opts, pgx.WithSchema(schema))...); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	return pool, schema
}

func TestConformanceAdvisory(t *testing.T) {
	storetest.Run(t, func(t *testing.T) storetest.Provider {
		pool, schema := freshSchema(t)
		return pgx.New(pool, pgx.WithSchema(schema))
	})
}

func TestConformanceHeadRow(t *testing.T) {
	storetest.Run(t, func(t *testing.T) storetest.Provider {
		pool, schema := freshSchema(t)
		return pgx.New(pool, pgx.WithSchema(schema), pgx.WithLockMode(postgres.LockHeadRow))
	})
}

func TestBindJoinsCallerTransaction(t *testing.T) {
	ctx := context.Background()
	pool, schema := freshSchema(t)
	a := tamperlog.New()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "CREATE TABLE "+schema+".business (id int)"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "INSERT INTO "+schema+".business VALUES (1)"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Append(ctx, pgx.Bind(tx, pgx.WithSchema(schema)), tamperlog.Event{Stream: "s", Action: "create", Entity: "business", EntityID: "1"}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	heads, err := pgx.New(pool, pgx.WithSchema(schema)).Heads(ctx)
	if err != nil || len(heads) != 0 {
		t.Fatalf("rolled back append is visible: %+v, %v", heads, err)
	}
}

// The triggers refuse what a client holding only INSERT could otherwise do.
func TestTriggersEnforceChainShape(t *testing.T) {
	ctx := context.Background()
	pool, schema := freshSchema(t)
	p := pgx.New(pool, pgx.WithSchema(schema))
	r, err := tamperlog.NewLog(p).Append(ctx, tamperlog.Event{Stream: "s", Action: "a", Entity: "e"})
	if err != nil {
		t.Fatal(err)
	}
	ev := schema + ".tamperlog_event"
	insert := "INSERT INTO " + ev + " (stream, seq, at, encoder, hasher, actor, subject, action, entity, entity_id, payload_hash, attributes, prev_hash, hash) VALUES ($1,$2,$3,$4,$5,'','','a','e','',NULL,'{}',$6,$7)"
	zero := make([]byte, 32)
	cases := map[string][]any{
		"wrong seq":         {"s", int64(3), time.Now(), "binary/v1", "sha256", r.Hash, zero},
		"wrong prev_hash":   {"s", int64(2), time.Now(), "binary/v1", "sha256", zero, zero},
		"backdated":         {"s", int64(2), time.Now().Add(-time.Minute), "binary/v1", "sha256", r.Hash, zero},
		"future":            {"s", int64(2), time.Now().Add(time.Minute), "binary/v1", "sha256", r.Hash, zero},
		"other hasher":      {"s", int64(2), time.Now(), "binary/v1", "sha3-256", r.Hash, zero},
		"first not genesis": {"t", int64(1), time.Now(), "binary/v1", "sha256", r.Hash, zero},
		"first not seq 1":   {"t", int64(2), time.Now(), "binary/v1", "sha256", zero, zero},
	}
	for name, args := range cases {
		_, err := pool.Exec(ctx, insert, args...)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23000" {
			t.Errorf("%s: %v, want integrity_constraint_violation", name, err)
		}
	}
	for name, stmt := range map[string]string{
		"update":   "UPDATE " + ev + " SET actor = 'x' WHERE seq = 1",
		"delete":   "DELETE FROM " + ev,
		"truncate": "TRUNCATE " + ev,
	} {
		_, err := pool.Exec(ctx, stmt)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("%s: %v, want insufficient_privilege", name, err)
		}
	}
	// A correct manual insert still works, so the trigger is not simply
	// refusing everything.
	next := tamperlog.Record{Event: tamperlog.Event{Stream: "s", Action: "a", Entity: "e"}, Seq: 2, At: time.Now().UTC().Truncate(time.Microsecond), Encoder: "binary/v1", Hasher: "sha256", PrevHash: r.Hash}
	next.Hash, _ = tamperlog.NewChain(nil, nil).Link(next)
	if _, err := pool.Exec(ctx, insert, "s", int64(2), next.At, "binary/v1", "sha256", r.Hash, next.Hash); err != nil {
		t.Fatalf("valid manual insert refused: %v", err)
	}
	// Seals too.
	if _, err := pool.Exec(ctx, "INSERT INTO "+schema+".tamperlog_seal (seq, sealed_at, hash, body) VALUES (5, now(), $1, 'x')", zero); err == nil {
		t.Error("seal seq 5 accepted before seq 1")
	}
}

// Triggers fire even when a superuser disables ordinary triggers through
// session_replication_role, because they are ENABLE ALWAYS.
func TestTriggersFireUnderReplicaRole(t *testing.T) {
	ctx := context.Background()
	pool, schema := freshSchema(t)
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SET session_replication_role = replica"); err != nil {
		t.Skipf("cannot set session_replication_role (needs superuser): %v", err)
	}
	_, err = conn.Exec(ctx, "INSERT INTO "+schema+".tamperlog_event (stream, seq, at, encoder, hasher, action, entity, prev_hash, hash) VALUES ('s', 7, now(), 'binary/v1', 'sha256', 'a', 'e', $1, $1)", make([]byte, 32))
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23000" {
		t.Fatalf("insert under replica role: %v, want the check trigger to fire", err)
	}
}

func TestRolesTemplateRenders(t *testing.T) {
	s, err := postgres.Roles("audit", "my_app")
	if err != nil || !strings.Contains(s, "GRANT SELECT, INSERT ON audit.tamperlog_event       TO my_app") {
		t.Fatalf("%v\n%s", err, s)
	}
	if _, err := postgres.Roles("audit", "bad;role"); err == nil {
		t.Fatal("injection accepted")
	}
	if _, err := postgres.Schema("Bad Schema"); err == nil {
		t.Fatal("bad schema accepted")
	}
}
