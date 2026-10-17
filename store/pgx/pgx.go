// Package pgx is the PostgreSQL backend over github.com/jackc/pgx/v5.
//
// Two entry points: [Bind] wraps a pgx.Tx the caller already opened, so an
// audit record commits with the business change it records; [New] wraps a
// pool for callers without a transaction (the convenience [tamperlog.Log],
// the seal writer and the verifier). Appending transactions must run at READ
// COMMITTED, pgx's default: the stream lock and the head read are separate
// statements and the second must see the previous lock holder's commit.
//
// Schema and triggers are documented in docs/backends/postgres.md and
// installed with [Migrate].
package pgx

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

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
func Bind(tx pgx.Tx, opts ...Option) tamperlog.Store {
	return postgres.NewStore(querier{tx}, config(opts))
}

// Provider is a [tamperlog.Provider] and [seal.Store] over a pool.
type Provider struct {
	pool *pgxpool.Pool
	cfg  postgres.Config
}

var (
	_ tamperlog.Provider = (*Provider)(nil)
	_ seal.Store         = (*Provider)(nil)
)

// New returns a Provider over pool.
func New(pool *pgxpool.Pool, opts ...Option) *Provider {
	return &Provider{pool: pool, cfg: config(opts)}
}

// Migrate installs or upgrades the schema through the pool. The connecting
// role must be allowed to create tables, functions and triggers; the
// application role normally is not, so run this from a migration step.
func Migrate(ctx context.Context, pool *pgxpool.Pool, opts ...Option) error {
	return postgres.Migrate(ctx, querier{pool}, config(opts).Schema)
}

// Begin opens a READ COMMITTED transaction.
func (p *Provider) Begin(ctx context.Context) (tamperlog.Tx, error) {
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("pgx: begin: %w", err)
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

func (p *Provider) store() *postgres.Store { return postgres.NewStore(querier{p.pool}, p.cfg) }

// txn is an open transaction.
type txn struct {
	*postgres.Store
	tx pgx.Tx
}

func (t *txn) Commit(ctx context.Context) error {
	if err := t.tx.Commit(ctx); err != nil {
		return fmt.Errorf("pgx: commit: %w", err)
	}
	return nil
}

// Rollback after Commit is a no-op.
func (t *txn) Rollback(ctx context.Context) error {
	err := t.tx.Rollback(ctx)
	if err == nil || errors.Is(err, pgx.ErrTxClosed) {
		return nil
	}
	return fmt.Errorf("pgx: rollback: %w", err)
}

// execQuerier is what pgx.Tx and *pgxpool.Pool share.
type execQuerier interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type querier struct{ q execQuerier }

func (q querier) Exec(ctx context.Context, sql string, args ...any) error {
	_, err := q.q.Exec(ctx, sql, args...)
	return err
}

func (q querier) QueryRow(ctx context.Context, sql string, args ...any) postgres.Row {
	return q.q.QueryRow(ctx, sql, args...)
}

func (q querier) Query(ctx context.Context, sql string, args ...any) (postgres.Rows, error) {
	rows, err := q.q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgxRows{rows}, nil
}

type pgxRows struct{ pgx.Rows }

func (r pgxRows) Close() error { r.Rows.Close(); return nil }
