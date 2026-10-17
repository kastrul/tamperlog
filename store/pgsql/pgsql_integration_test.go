//go:build integration

package pgsql_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver "pgx"

	"github.com/kastrul/tamperlog/internal/storetest"
	"github.com/kastrul/tamperlog/store/pgsql"
	"github.com/kastrul/tamperlog/store/postgres"
)

func freshSchema(t *testing.T) (*sql.DB, string) {
	t.Helper()
	dsn := os.Getenv("TAMPERLOG_PG_DSN")
	if dsn == "" {
		t.Skip("TAMPERLOG_PG_DSN not set")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' {
			return r
		}
		return '_'
	}, fmt.Sprintf("q_%d_%s", time.Now().UnixNano()%1_000_000_000, strings.ToLower(t.Name())[:min(20, len(t.Name()))]))
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		_ = db.Close()
	})
	if err := pgsql.Migrate(ctx, db, pgsql.WithSchema(schema)); err != nil {
		t.Fatal(err)
	}
	return db, schema
}

func TestConformanceAdvisory(t *testing.T) {
	storetest.Run(t, func(t *testing.T) storetest.Provider {
		db, schema := freshSchema(t)
		return pgsql.New(db, pgsql.WithSchema(schema))
	})
}

func TestConformanceHeadRow(t *testing.T) {
	storetest.Run(t, func(t *testing.T) storetest.Provider {
		db, schema := freshSchema(t)
		return pgsql.New(db, pgsql.WithSchema(schema), pgsql.WithLockMode(postgres.LockHeadRow))
	})
}
