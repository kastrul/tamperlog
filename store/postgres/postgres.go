// Package postgres holds the PostgreSQL schema and the store logic shared by
// the pgx and database/sql backends. Applications import store/pgx or
// store/pgsql; this package has no driver dependency and is useful on its own
// only for rendering the SQL.
//
// The schema (see sql/schema.sql) stores one row per record with a BEFORE
// INSERT trigger that checks dense sequence numbers, prev_hash linkage and
// clock bounds under the same advisory lock the Go appender takes, and
// triggers that refuse UPDATE, DELETE and TRUNCATE for every role. The role
// template in sql/roles.sql makes a sealed NOLOGIN owner and an INSERT-only
// application role.
package postgres

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/kastrul/tamperlog"
	"github.com/kastrul/tamperlog/seal"
)

//go:embed sql/*.sql
var sqlFS embed.FS

// SchemaVersion is the version sql/schema.sql installs.
const SchemaVersion = 1

var identRE = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// Schema renders sql/schema.sql for the given schema name (an unquoted
// lowercase identifier; "public" by default). Run it with a role that may
// create tables and functions; it is idempotent.
func Schema(schema string) (string, error) { return render("sql/schema.sql", schema, "") }

// Roles renders sql/roles.sql: ownership by a sealed NOLOGIN role and
// SELECT, INSERT grants to appRole. Run it with administrator credentials.
func Roles(schema, appRole string) (string, error) {
	if !identRE.MatchString(appRole) {
		return "", fmt.Errorf("postgres: invalid role name %q", appRole)
	}
	return render("sql/roles.sql", schema, appRole)
}

func render(name, schema, appRole string) (string, error) {
	if schema == "" {
		schema = "public"
	}
	if !identRE.MatchString(schema) {
		return "", fmt.Errorf("postgres: invalid schema name %q", schema)
	}
	b, err := sqlFS.ReadFile(name)
	if err != nil {
		return "", err
	}
	s := strings.ReplaceAll(string(b), "__SCHEMA__", schema)
	s = strings.ReplaceAll(s, "__APP_ROLE__", appRole)
	return s, nil
}

// LockMode selects how a stream is locked from Head until the transaction
// ends (ADR 0011).
type LockMode int

const (
	// LockAdvisory takes pg_advisory_xact_lock(hashtextextended('tamperlog:' || stream, 0)).
	// No row is written; the BEFORE INSERT trigger takes the same key.
	LockAdvisory LockMode = iota
	// LockHeadRow locks the stream's row in tamperlog_stream_head with
	// SELECT ... FOR UPDATE, inserting it on first use. Visible by name in
	// pg_locks; keeps one extra row per stream.
	LockHeadRow
)

// Config is shared by both backends.
type Config struct {
	Schema   string
	LockMode LockMode
}

// Row is one result row of a query.
type Row interface {
	Scan(dest ...any) error
}

// Rows is a result set.
type Rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close() error
}

// Querier is the slice of a driver the store logic needs. The pgx and
// database/sql backends adapt their transaction and pool types to it.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) error
	QueryRow(ctx context.Context, sql string, args ...any) Row
	Query(ctx context.Context, sql string, args ...any) (Rows, error)
}

// Store implements [tamperlog.Store] over a Querier bound to one transaction.
type Store struct {
	q   Querier
	cfg Config
	t   string // schema-qualified table prefix, e.g. "public.tamperlog_"
}

// NewStore binds the store logic to q, which must represent one open
// transaction.
func NewStore(q Querier, cfg Config) *Store {
	if cfg.Schema == "" {
		cfg.Schema = "public"
	}
	return &Store{q: q, cfg: cfg, t: cfg.Schema + ".tamperlog_"}
}

// Head locks the stream and returns its last link and clock_timestamp().
// The lock and the head read are separate statements on purpose: under READ
// COMMITTED the second statement takes a new snapshot that sees the previous
// lock holder's committed row. REPEATABLE READ or SERIALIZABLE transactions
// would reuse an older snapshot and must not be used for appends.
func (s *Store) Head(ctx context.Context, stream string) (tamperlog.Head, error) {
	if err := tamperlog.ValidateStream(stream); err != nil {
		return tamperlog.Head{}, err
	}
	switch s.cfg.LockMode {
	case LockAdvisory:
		if err := s.q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "tamperlog:"+stream); err != nil {
			return tamperlog.Head{}, fmt.Errorf("postgres: lock %s: %w", stream, err)
		}
	case LockHeadRow:
		if err := s.q.Exec(ctx, `INSERT INTO `+s.t+`stream_head (stream) VALUES ($1) ON CONFLICT DO NOTHING`, stream); err != nil {
			return tamperlog.Head{}, fmt.Errorf("postgres: head row %s: %w", stream, err)
		}
		if err := s.q.Exec(ctx, `SELECT stream FROM `+s.t+`stream_head WHERE stream = $1 FOR UPDATE`, stream); err != nil {
			return tamperlog.Head{}, fmt.Errorf("postgres: lock head row %s: %w", stream, err)
		}
	default:
		return tamperlog.Head{}, fmt.Errorf("postgres: unknown lock mode %d", s.cfg.LockMode)
	}
	var h tamperlog.Head
	var at *time.Time
	var enc, hs *string
	err := s.q.QueryRow(ctx, `
SELECT clock_timestamp(), coalesce(last.seq, 0), last.hash, last.at, last.encoder, last.hasher
FROM (SELECT 1) AS one
LEFT JOIN LATERAL (
  SELECT e.seq, e.hash, e.at, e.encoder, e.hasher FROM `+s.t+`event AS e WHERE e.stream = $1 ORDER BY e.seq DESC LIMIT 1
) AS last ON true`, stream).Scan(&h.Now, &h.Seq, &h.Hash, &at, &enc, &hs)
	if err != nil {
		return tamperlog.Head{}, fmt.Errorf("postgres: head %s: %w", stream, err)
	}
	if at != nil {
		h.At = at.UTC()
	}
	if enc != nil {
		h.Encoder = *enc
	}
	if hs != nil {
		h.Hasher = *hs
	}
	h.Now = h.Now.UTC()
	return h, nil
}

// Insert writes r. The BEFORE INSERT trigger rejects a record that does not
// extend the head.
func (s *Store) Insert(ctx context.Context, r tamperlog.Record) error {
	attrs, err := json.Marshal(nonNil(r.Attributes))
	if err != nil {
		return fmt.Errorf("postgres: attributes: %w", err)
	}
	return s.q.Exec(ctx, `
INSERT INTO `+s.t+`event (stream, seq, at, encoder, hasher, actor, subject, action, entity, entity_id, payload_hash, attributes, prev_hash, hash)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb, $13, $14)`,
		r.Stream, r.Seq, r.At, r.Encoder, r.Hasher, r.Actor, r.Subject, r.Action, r.Entity, r.EntityID, r.PayloadHash, string(attrs), r.PrevHash, r.Hash)
}

// Range reads records first..last of stream in order.
func (s *Store) Range(ctx context.Context, stream string, first, last int64) ([]tamperlog.Record, error) {
	rows, err := s.q.Query(ctx, `
SELECT stream, seq, at, encoder, hasher, actor, subject, action, entity, entity_id, payload_hash, attributes, prev_hash, hash
FROM `+s.t+`event WHERE stream = $1 AND seq BETWEEN $2 AND $3 ORDER BY seq`, stream, first, last)
	if err != nil {
		return nil, fmt.Errorf("postgres: range %s: %w", stream, err)
	}
	defer rows.Close() //nolint:errcheck // rows are read to the end below
	var out []tamperlog.Record
	for rows.Next() {
		var r tamperlog.Record
		var attrs []byte
		if err := rows.Scan(&r.Stream, &r.Seq, &r.At, &r.Encoder, &r.Hasher, &r.Actor, &r.Subject, &r.Action, &r.Entity, &r.EntityID, &r.PayloadHash, &attrs, &r.PrevHash, &r.Hash); err != nil {
			return nil, fmt.Errorf("postgres: range %s: %w", stream, err)
		}
		if len(attrs) > 0 {
			if err := json.Unmarshal(attrs, &r.Attributes); err != nil {
				return nil, fmt.Errorf("postgres: %s/%d attributes: %w", stream, r.Seq, err)
			}
		}
		if len(r.Attributes) == 0 {
			r.Attributes = nil
		}
		if len(r.PayloadHash) == 0 {
			r.PayloadHash = nil
		}
		r.At = r.At.UTC()
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: range %s: %w", stream, err)
	}
	return out, rows.Close()
}

func nonNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// Heads returns every non-empty stream's last link.
func (s *Store) Heads(ctx context.Context) (map[string]tamperlog.Head, error) {
	rows, err := s.q.Query(ctx, `SELECT DISTINCT ON (stream) stream, seq, hash, at, encoder, hasher FROM `+s.t+`event ORDER BY stream, seq DESC`)
	if err != nil {
		return nil, fmt.Errorf("postgres: heads: %w", err)
	}
	defer rows.Close() //nolint:errcheck // rows are read to the end below
	out := map[string]tamperlog.Head{}
	for rows.Next() {
		var name string
		var h tamperlog.Head
		if err := rows.Scan(&name, &h.Seq, &h.Hash, &h.At, &h.Encoder, &h.Hasher); err != nil {
			return nil, fmt.Errorf("postgres: heads: %w", err)
		}
		h.At = h.At.UTC()
		out[name] = h
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: heads: %w", err)
	}
	return out, rows.Close()
}

// FirstSeqs returns every non-empty stream's smallest kept sequence number.
func (s *Store) FirstSeqs(ctx context.Context) (map[string]int64, error) {
	rows, err := s.q.Query(ctx, `SELECT stream, min(seq) FROM `+s.t+`event GROUP BY stream`)
	if err != nil {
		return nil, fmt.Errorf("postgres: first seqs: %w", err)
	}
	defer rows.Close() //nolint:errcheck // rows are read to the end below
	out := map[string]int64{}
	for rows.Next() {
		var name string
		var seq int64
		if err := rows.Scan(&name, &seq); err != nil {
			return nil, fmt.Errorf("postgres: first seqs: %w", err)
		}
		out[name] = seq
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: first seqs: %w", err)
	}
	return out, rows.Close()
}

// PutSeal stores a seal; the trigger enforces dense sequence numbers.
func (s *Store) PutSeal(ctx context.Context, st seal.Stored) error {
	return s.q.Exec(ctx, `INSERT INTO `+s.t+`seal (seq, sealed_at, hash, body) VALUES ($1, $2, $3, $4)`, st.Seq, st.SealedAt, st.Hash, st.Bytes)
}

// LastSeal returns the newest seal.
func (s *Store) LastSeal(ctx context.Context) (seal.Stored, bool, error) {
	var st seal.Stored
	var seq *int64
	err := s.q.QueryRow(ctx, `
SELECT last.seq, last.sealed_at, last.hash, last.body FROM (SELECT 1) AS one
LEFT JOIN LATERAL (SELECT seq, sealed_at, hash, body FROM `+s.t+`seal ORDER BY seq DESC LIMIT 1) AS last ON true`).
		Scan(&seq, &st.SealedAt, &st.Hash, &st.Bytes)
	if err != nil {
		return seal.Stored{}, false, fmt.Errorf("postgres: last seal: %w", err)
	}
	if seq == nil {
		return seal.Stored{}, false, nil
	}
	st.Seq = *seq
	st.SealedAt = st.SealedAt.UTC()
	return st, true, nil
}

// Seals returns seals first..last.
func (s *Store) Seals(ctx context.Context, first, last int64) ([]seal.Stored, error) {
	rows, err := s.q.Query(ctx, `SELECT seq, sealed_at, hash, body FROM `+s.t+`seal WHERE seq BETWEEN $1 AND $2 ORDER BY seq`, first, last)
	if err != nil {
		return nil, fmt.Errorf("postgres: seals: %w", err)
	}
	return scanSeals(rows)
}

func scanSeals(rows Rows) ([]seal.Stored, error) {
	defer rows.Close() //nolint:errcheck // rows are read to the end below
	var out []seal.Stored
	for rows.Next() {
		var st seal.Stored
		if err := rows.Scan(&st.Seq, &st.SealedAt, &st.Hash, &st.Bytes); err != nil {
			return nil, fmt.Errorf("postgres: seals: %w", err)
		}
		st.SealedAt = st.SealedAt.UTC()
		out = append(out, st)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: seals: %w", err)
	}
	return out, rows.Close()
}

// PutProof stores p; the foreign key refuses an unknown seal.
func (s *Store) PutProof(ctx context.Context, p seal.Proof) error {
	return s.q.Exec(ctx, `INSERT INTO `+s.t+`proof (seal_seq, provider, obtained_at, body) VALUES ($1, $2, $3, $4)`, p.SealSeq, p.Provider, p.ObtainedAt, p.Bytes)
}

// Proofs returns the proofs of one seal.
func (s *Store) Proofs(ctx context.Context, sealSeq int64) ([]seal.Proof, error) {
	rows, err := s.q.Query(ctx, `SELECT seal_seq, provider, obtained_at, body FROM `+s.t+`proof WHERE seal_seq = $1 ORDER BY obtained_at`, sealSeq)
	if err != nil {
		return nil, fmt.Errorf("postgres: proofs: %w", err)
	}
	defer rows.Close() //nolint:errcheck // rows are read to the end below
	var out []seal.Proof
	for rows.Next() {
		var p seal.Proof
		if err := rows.Scan(&p.SealSeq, &p.Provider, &p.ObtainedAt, &p.Bytes); err != nil {
			return nil, fmt.Errorf("postgres: proofs: %w", err)
		}
		p.ObtainedAt = p.ObtainedAt.UTC()
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: proofs: %w", err)
	}
	return out, rows.Close()
}

// Unanchored returns up to limit seals without a proof from provider.
func (s *Store) Unanchored(ctx context.Context, provider string, limit int) ([]seal.Stored, error) {
	rows, err := s.q.Query(ctx, `
SELECT s.seq, s.sealed_at, s.hash, s.body FROM `+s.t+`seal AS s
WHERE NOT EXISTS (SELECT FROM `+s.t+`proof AS p WHERE p.seal_seq = s.seq AND p.provider = $1)
ORDER BY s.seq LIMIT $2`, provider, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: unanchored: %w", err)
	}
	return scanSeals(rows)
}

// Migrate runs the schema through q. Pass a Querier over a connection or
// pool that may create tables and functions.
func Migrate(ctx context.Context, q Querier, schema string) error {
	sql, err := Schema(schema)
	if err != nil {
		return err
	}
	if err := q.Exec(ctx, sql); err != nil {
		return fmt.Errorf("postgres: migrate: %w", err)
	}
	return nil
}

// ErrNotTransaction is returned when a backend is bound to something that is
// not a transaction.
var ErrNotTransaction = errors.New("postgres: store must be bound to a transaction")
