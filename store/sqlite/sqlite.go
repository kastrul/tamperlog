// Package sqlite is the SQLite backend: a [tamperlog.Provider] and
// [seal.Store] over database/sql with the pure Go driver modernc.org/sqlite,
// so it builds without cgo and without a build tag.
//
// The schema in sql/schema.sql stores one row per record with CHECK
// constraints that mirror the Go validation, a BEFORE INSERT trigger that
// checks dense sequence numbers, prev_hash linkage, a constant encoder and
// hasher per stream and clock bounds, and triggers that refuse UPDATE and
// DELETE on every tamperlog table. [Migrate] installs it; it is idempotent.
//
// SQLite allows one writer per database at a time. Head writes the stream's
// row in tamperlog_stream_head (INSERT OR IGNORE) as its first statement; that
// write takes the database writer lock for the rest of the transaction, and a
// second writer waits (busy_timeout, 5 s, or until its context ends) instead
// of failing. Streams are therefore serialised database-wide, not per stream.
// A transaction must call Head before it reads: a transaction that already
// holds a read snapshot cannot wait for the writer lock and fails with
// SQLITE_BUSY_SNAPSHOT when another writer committed in the meantime.
// Appender.Append and Log.Append always call Head first.
//
// SQLite has no server clock. [Head] returns the process clock (time.Now, or
// the function passed to [WithClock]); the BEFORE INSERT trigger compares the
// stamped time with SQLite's own clock, which is the same process clock. A
// clock injected for tests must stay within 5 seconds of real time or inserts
// fail.
//
// What the triggers do not stop: anyone who can open the database file for
// writing can drop a trigger, rewrite rows or edit pages directly. Seals and
// anchors are the detection; the triggers stop mistakes and careless clients.
package sqlite

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	sqlite3 "modernc.org/sqlite" // registers the "sqlite" driver

	"github.com/kastrul/tamperlog"
)

//go:embed sql/schema.sql
var schemaSQL string

// SchemaVersion is the version sql/schema.sql installs.
const SchemaVersion = 1

// Schema returns the embedded schema SQL for users who run their own
// migration tooling. It is idempotent.
func Schema() string { return schemaSQL }

// Migrate runs the schema through db in one transaction. Run it with a
// connection that may create tables and triggers.
func Migrate(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: migrate: %w", err)
	}
	if _, err := tx.ExecContext(ctx, schemaSQL); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("sqlite: migrate: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: migrate: %w", err)
	}
	return nil
}

// Open opens a SQLite database with modernc.org/sqlite. dsn is a file path or
// a "file:" URI, optionally with a query string; Open adds
// _pragma=busy_timeout(5000), _pragma=journal_mode(WAL),
// _pragma=foreign_keys(ON) and _pragma=recursive_triggers(ON) (so INSERT OR
// REPLACE cannot delete behind the DELETE triggers), which apply to every
// pooled connection. Do not
// pass :memory:, since database/sql opens several connections and each would
// see its own empty database. The caller owns the returned pool and runs
// [Migrate] before [New].
func Open(dsn string) (*sql.DB, error) {
	path, query, _ := strings.Cut(dsn, "?")
	q, err := url.ParseQuery(query)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open %q: %w", dsn, err)
	}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "foreign_keys(ON)")
	q.Add("_pragma", "recursive_triggers(ON)")
	db, err := sql.Open("sqlite", path+"?"+q.Encode())
	if err != nil {
		return nil, fmt.Errorf("sqlite: open %q: %w", dsn, err)
	}
	return db, nil
}

type options struct {
	clock func() time.Time
}

// Option configures a [Provider] or a store from [Bind].
type Option func(*options)

// WithClock replaces the clock [tamperlog.Store.Head] reports (default
// time.Now). SQLite has no server clock, so this is the process clock; the
// BEFORE INSERT trigger rejects a record stamped more than 5 seconds from
// SQLite's own reading of the same clock.
func WithClock(now func() time.Time) Option { return func(o *options) { o.clock = now } }

func newOptions(opts []Option) options {
	o := options{clock: time.Now}
	for _, fn := range opts {
		fn(&o)
	}
	return o
}

// querier is the slice of *sql.DB and *sql.Tx the store uses.
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Provider implements [tamperlog.Provider] and [seal.Store] over a pool
// returned by [Open] or opened by the caller with the modernc.org/sqlite
// driver. Use [New].
type Provider struct {
	db   *sql.DB
	opts options
}

// New returns a Provider over db, which must already hold the schema (see
// [Migrate]). A pool not opened by [Open] should set busy_timeout on every
// connection, or a second writer fails at once instead of waiting.
func New(db *sql.DB, opts ...Option) *Provider {
	return &Provider{db: db, opts: newOptions(opts)}
}

// Bind returns a [tamperlog.Store] over a transaction the caller owns and
// will commit or roll back. Call [tamperlog.Appender.Append] last in the
// transaction: Head takes the database writer lock until the transaction ends.
func Bind(tx *sql.Tx, opts ...Option) tamperlog.Store {
	return &store{q: tx, opts: newOptions(opts)}
}

// Begin opens a deferred transaction; the first Head makes it a writer.
func (p *Provider) Begin(ctx context.Context) (tamperlog.Tx, error) {
	sqlTx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("sqlite: begin: %w", err)
	}
	return &tx{store: store{q: sqlTx, opts: p.opts}, tx: sqlTx}, nil
}

// Heads returns every non-empty stream's last link without locking.
func (p *Provider) Heads(ctx context.Context) (map[string]tamperlog.Head, error) {
	// With max(), SQLite takes the bare columns from the row holding the maximum.
	rows, err := p.db.QueryContext(ctx, `SELECT stream, max(seq), hash, at, encoder, hasher FROM tamperlog_event GROUP BY stream`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: heads: %w", err)
	}
	defer rows.Close() //nolint:errcheck // rows are read to the end below
	out := map[string]tamperlog.Head{}
	for rows.Next() {
		var name string
		var h tamperlog.Head
		var at int64
		if err := rows.Scan(&name, &h.Seq, &h.Hash, &at, &h.Encoder, &h.Hasher); err != nil {
			return nil, fmt.Errorf("sqlite: heads: %w", err)
		}
		h.At = micros(at)
		out[name] = h
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: heads: %w", err)
	}
	return out, rows.Close()
}

// FirstSeqs returns every non-empty stream's smallest kept sequence number.
func (p *Provider) FirstSeqs(ctx context.Context) (map[string]int64, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT stream, min(seq) FROM tamperlog_event GROUP BY stream`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: first seqs: %w", err)
	}
	defer rows.Close() //nolint:errcheck // rows are read to the end below
	out := map[string]int64{}
	for rows.Next() {
		var name string
		var seq int64
		if err := rows.Scan(&name, &seq); err != nil {
			return nil, fmt.Errorf("sqlite: first seqs: %w", err)
		}
		out[name] = seq
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: first seqs: %w", err)
	}
	return out, rows.Close()
}

// store implements tamperlog.Store over one transaction.
type store struct {
	q    querier
	opts options
}

// Head validates the stream name, takes the database writer lock by writing
// the stream's row in tamperlog_stream_head (INSERT OR IGNORE, so the second
// and later calls change nothing), and returns the last link and the process
// clock. It waits for a running writer until ctx ends.
func (s *store) Head(ctx context.Context, stream string) (tamperlog.Head, error) {
	if err := tamperlog.ValidateStream(stream); err != nil {
		return tamperlog.Head{}, err
	}
	if err := s.lock(ctx, stream); err != nil {
		return tamperlog.Head{}, fmt.Errorf("sqlite: lock %s: %w", stream, err)
	}
	h := tamperlog.Head{Now: s.opts.clock()}
	var at int64
	err := s.q.QueryRowContext(ctx, `SELECT seq, hash, at, encoder, hasher FROM tamperlog_event WHERE stream = ? ORDER BY seq DESC LIMIT 1`, stream).
		Scan(&h.Seq, &h.Hash, &at, &h.Encoder, &h.Hasher)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return h, nil
	case err != nil:
		return tamperlog.Head{}, fmt.Errorf("sqlite: head %s: %w", stream, err)
	}
	h.At = micros(at)
	return h, nil
}

// lockStep is the busy_timeout, in milliseconds, used while waiting for the
// writer lock: SQLite's busy handler does not notice sqlite3_interrupt, so the
// wait is cut into steps and ctx is checked between them.
const lockStep = 100

// lock takes the writer lock for the transaction by writing the stream's row.
// The connection's busy_timeout is lowered to lockStep for the attempt and
// restored afterwards, also when ctx has ended.
func (s *store) lock(ctx context.Context, stream string) error {
	var saved int
	if err := s.q.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&saved); err != nil {
		return err
	}
	if _, err := s.q.ExecContext(ctx, `PRAGMA busy_timeout = `+strconv.Itoa(lockStep)); err != nil {
		return err
	}
	defer func() {
		_, _ = s.q.ExecContext(context.WithoutCancel(ctx), `PRAGMA busy_timeout = `+strconv.Itoa(saved)) //nolint:gosec // integer read from the connection's own pragma
	}()
	for {
		_, err := s.q.ExecContext(ctx, `INSERT OR IGNORE INTO tamperlog_stream_head (stream) VALUES (?)`, stream)
		if err == nil {
			return nil
		}
		if !isBusy(err) {
			return err
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
	}
}

// isBusy reports whether err is SQLITE_BUSY from a running writer, the case
// worth waiting for. SQLITE_BUSY_SNAPSHOT (the transaction read before it
// wrote and the database moved on) cannot succeed by waiting.
func isBusy(err error) bool {
	var e *sqlite3.Error
	if !errors.As(err, &e) {
		return false
	}
	const busy, busySnapshot = 5, 517
	return e.Code()&0xff == busy && e.Code() != busySnapshot
}

// Insert writes r. The primary key refuses a duplicate (stream, seq) and the
// BEFORE INSERT trigger refuses a record that does not extend the head.
func (s *store) Insert(ctx context.Context, r tamperlog.Record) error {
	attrs, err := json.Marshal(nonNil(r.Attributes))
	if err != nil {
		return fmt.Errorf("sqlite: attributes: %w", err)
	}
	var payload any
	if r.PayloadHash != nil {
		payload = r.PayloadHash
	}
	_, err = s.q.ExecContext(ctx, `
INSERT INTO tamperlog_event (stream, seq, at, actor, subject, action, entity, entity_id, encoder, hasher, payload_hash, attributes, prev_hash, hash)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Stream, r.Seq, r.At.UnixMicro(), r.Actor, r.Subject, r.Action, r.Entity, r.EntityID, r.Encoder, r.Hasher, payload, string(attrs), r.PrevHash, r.Hash)
	if err != nil {
		return fmt.Errorf("sqlite: insert %s/%d: %w", r.Stream, r.Seq, err)
	}
	return nil
}

// Range reads records first..last of stream in order.
func (s *store) Range(ctx context.Context, stream string, first, last int64) ([]tamperlog.Record, error) {
	rows, err := s.q.QueryContext(ctx, `
SELECT stream, seq, at, actor, subject, action, entity, entity_id, encoder, hasher, payload_hash, attributes, prev_hash, hash
FROM tamperlog_event WHERE stream = ? AND seq BETWEEN ? AND ? ORDER BY seq`, stream, first, last)
	if err != nil {
		return nil, fmt.Errorf("sqlite: range %s: %w", stream, err)
	}
	defer rows.Close() //nolint:errcheck // rows are read to the end below
	var out []tamperlog.Record
	for rows.Next() {
		var r tamperlog.Record
		var at int64
		var attrs string
		if err := rows.Scan(&r.Stream, &r.Seq, &at, &r.Actor, &r.Subject, &r.Action, &r.Entity, &r.EntityID, &r.Encoder, &r.Hasher, &r.PayloadHash, &attrs, &r.PrevHash, &r.Hash); err != nil {
			return nil, fmt.Errorf("sqlite: range %s: %w", stream, err)
		}
		if err := json.Unmarshal([]byte(attrs), &r.Attributes); err != nil {
			return nil, fmt.Errorf("sqlite: %s/%d attributes: %w", stream, r.Seq, err)
		}
		if len(r.Attributes) == 0 {
			r.Attributes = nil
		}
		if len(r.PayloadHash) == 0 {
			r.PayloadHash = nil
		}
		r.At = micros(at)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: range %s: %w", stream, err)
	}
	return out, rows.Close()
}

// tx is a transaction the provider opened.
type tx struct {
	store
	tx *sql.Tx
}

// Commit commits the transaction.
func (t *tx) Commit(context.Context) error {
	if err := t.tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: commit: %w", err)
	}
	return nil
}

// Rollback rolls the transaction back. After Commit it is a no-op.
func (t *tx) Rollback(context.Context) error {
	if err := t.tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		return fmt.Errorf("sqlite: rollback: %w", err)
	}
	return nil
}

// micros converts stored microseconds to a UTC time.
func micros(us int64) time.Time { return time.UnixMicro(us).UTC() }

func nonNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}
