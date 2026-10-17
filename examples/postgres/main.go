// Command postgres shows the same-transaction append with pgx: a business row
// and its audit record commit together or not at all.
//
//	docker compose up -d
//	TAMPERLOG_PG_DSN='postgres://tamperlog:tamperlog@localhost:55433/tamperlog?sslmode=disable' go run ./examples/postgres
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kastrul/tamperlog"
	tlpgx "github.com/kastrul/tamperlog/store/pgx"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx := context.Background()
	dsn := os.Getenv("TAMPERLOG_PG_DSN")
	if dsn == "" {
		return errors.New("set TAMPERLOG_PG_DSN")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()

	// Normally a migration step with a migration credential, not the app.
	if err := tlpgx.Migrate(ctx, pool, tlpgx.WithSchema("example")); err != nil {
		return err
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS example.consent (id text PRIMARY KEY, given boolean NOT NULL)`); err != nil {
		return err
	}

	appender := tamperlog.New()

	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	if _, err := tx.Exec(ctx, `INSERT INTO example.consent VALUES ($1, true) ON CONFLICT (id) DO UPDATE SET given = true`, "c-1"); err != nil {
		return err
	}
	// Last in the transaction: the stream lock is held until commit.
	rec, err := appender.Append(ctx, tlpgx.Bind(tx, tlpgx.WithSchema("example")), tamperlog.Event{
		Stream: "consent", Actor: "clinician-7", Subject: "patient-42", Action: "consent.given", Entity: "consent", EntityID: "c-1",
	})
	if err != nil {
		return err // the business write is rolled back with it
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	fmt.Printf("committed consent c-1 with audit record %s/%d\n", rec.Stream, rec.Seq)

	heads, err := tlpgx.New(pool, tlpgx.WithSchema("example")).Heads(ctx)
	if err != nil {
		return err
	}
	for name, h := range heads {
		fmt.Printf("stream %s head %d %x\n", name, h.Seq, h.Hash[:8])
	}
	return nil
}
