// Package pgsql is the PostgreSQL backend over database/sql, for applications
// that use pgx's stdlib adapter, lib/pq or another PostgreSQL driver with
// $1-style placeholders. It shares its SQL and logic with store/pgx through
// store/postgres.
//
// [Bind] wraps a *sql.Tx the caller opened; [New] wraps a *sql.DB. Appending
// transactions must run at READ COMMITTED (the PostgreSQL default). The driver
// must scan timestamptz into time.Time, bytea into []byte and jsonb into
// []byte, which pgx/stdlib and lib/pq both do.
package pgsql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/kastrul/tamperlog"
	"github.com/kastrul/tamperlog/seal"
	"github.com/kastrul/tamperlog/store/postgres"
)

// Option configures the backend.
type Option func(*postgres.Config)

// WithSchema sets the PostgreSQL schema holding the tamperlog tables
// (default "public").
func WithSchema(schema string) Option { return func(c *postgres.Config) { c.Schema = schema } }

// WithLockMode selects advisory (default) or head-row stream locking.
func WithLockMode(m postgres.LockMode) Option { return func(c *postgres.Config) { c.LockMode = m } }

func config(opts []Option) postgres.Config {
	var c postgres.Config
	for _, o := range opts {
		o(&c)
	}
	return c
}

// Bind returns a [tamperlog.Store] over tx. The caller commits or rolls back.
func Bind(tx *sql.Tx, opts ...Option) tamperlog.Store {
	return postgres.NewStore(querier{tx}, config(opts))
}

// Provider is a [tamperlog.Provider] and [seal.Store] over a *sql.DB.
type Provider struct {
	db  *sql.DB
	cfg postgres.Config
}

var (
	_ tamperlog.Provider = (*Provider)(nil)
	_ seal.Store         = (*Provider)(nil)
)

// New returns a Provider over db.
func New(db *sql.DB, opts ...Option) *Provider {
	return &Provider{db: db, cfg: config(opts)}
}

// Migrate installs or upgrades the schema. The connecting role must be
// allowed to create tables, functions and triggers.
func Migrate(ctx context.Context, db *sql.DB, opts ...Option) error {
	return postgres.Migrate(ctx, querier{db}, config(opts).Schema)
}

// Begin opens a READ COMMITTED transaction.
func (p *Provider) Begin(ctx context.Context) (tamperlog.Tx, error) {
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("pgsql: begin: %w", err)
	}
	return &txn{Store: postgres.NewStore(querier{tx}, p.cfg), tx: tx}, nil
}

// Heads returns every non-empty stream's last link.
func (p *Provider) Heads(ctx context.Context) (map[string]tamperlog.Head, error) {
	return p.store().Heads(ctx)
}

// FirstSeqs returns every non-empty stream's smallest kept sequence number.
func (p *Provider) FirstSeqs(ctx context.Context) (map[string]int64, error) {
	return p.store().FirstSeqs(ctx)
}

// PutSeal stores a seal in its own implicit transaction.
func (p *Provider) PutSeal(ctx context.Context, s seal.Stored) error {
	return p.store().PutSeal(ctx, s)
}

// LastSeal returns the newest seal.
func (p *Provider) LastSeal(ctx context.Context) (seal.Stored, bool, error) {
	return p.store().LastSeal(ctx)
}

// Seals returns seals first..last.
func (p *Provider) Seals(ctx context.Context, first, last int64) ([]seal.Stored, error) {
	return p.store().Seals(ctx, first, last)
}

// PutProof stores a proof.
func (p *Provider) PutProof(ctx context.Context, pr seal.Proof) error {
	return p.store().PutProof(ctx, pr)
}

// Proofs returns the proofs of one seal.
func (p *Provider) Proofs(ctx context.Context, sealSeq int64) ([]seal.Proof, error) {
	return p.store().Proofs(ctx, sealSeq)
}

// Unanchored returns seals without a proof from provider.
func (p *Provider) Unanchored(ctx context.Context, provider string, limit int) ([]seal.Stored, error) {
	return p.store().Unanchored(ctx, provider, limit)
}

func (p *Provider) store() *postgres.Store { return postgres.NewStore(querier{p.db}, p.cfg) }

type txn struct {
	*postgres.Store
	tx *sql.Tx
}

func (t *txn) Commit(context.Context) error {
	if err := t.tx.Commit(); err != nil {
		return fmt.Errorf("pgsql: commit: %w", err)
	}
	return nil
}

// Rollback after Commit is a no-op.
func (t *txn) Rollback(context.Context) error {
	err := t.tx.Rollback()
	if err == nil || errors.Is(err, sql.ErrTxDone) {
		return nil
	}
	return fmt.Errorf("pgsql: rollback: %w", err)
}

// execQuerier is what *sql.DB and *sql.Tx share.
type execQuerier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type querier struct{ q execQuerier }

func (q querier) Exec(ctx context.Context, query string, args ...any) error {
	_, err := q.q.ExecContext(ctx, query, args...)
	return err
}

func (q querier) QueryRow(ctx context.Context, query string, args ...any) postgres.Row {
	return q.q.QueryRowContext(ctx, query, args...)
}

func (q querier) Query(ctx context.Context, query string, args ...any) (postgres.Rows, error) {
	rows, err := q.q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return rows, nil
}
