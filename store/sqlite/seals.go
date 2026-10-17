package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/kastrul/tamperlog/seal"
)

// PutSeal stores a seal. The BEFORE INSERT trigger refuses a seq that does
// not follow the last seal and the primary key refuses a duplicate.
func (p *Provider) PutSeal(ctx context.Context, st seal.Stored) error {
	_, err := p.db.ExecContext(ctx, `INSERT INTO tamperlog_seal (seq, sealed_at, hash, body) VALUES (?, ?, ?, ?)`,
		st.Seq, st.SealedAt.UnixMicro(), st.Hash, st.Bytes)
	if err != nil {
		return fmt.Errorf("sqlite: put seal %d: %w", st.Seq, err)
	}
	return nil
}

// LastSeal returns the newest seal.
func (p *Provider) LastSeal(ctx context.Context) (seal.Stored, bool, error) {
	var st seal.Stored
	var sealedAt int64
	err := p.db.QueryRowContext(ctx, `SELECT seq, sealed_at, hash, body FROM tamperlog_seal ORDER BY seq DESC LIMIT 1`).
		Scan(&st.Seq, &sealedAt, &st.Hash, &st.Bytes)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return seal.Stored{}, false, nil
	case err != nil:
		return seal.Stored{}, false, fmt.Errorf("sqlite: last seal: %w", err)
	}
	st.SealedAt = micros(sealedAt)
	return st, true, nil
}

// Seals returns seals first..last in order.
func (p *Provider) Seals(ctx context.Context, first, last int64) ([]seal.Stored, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT seq, sealed_at, hash, body FROM tamperlog_seal WHERE seq BETWEEN ? AND ? ORDER BY seq`, first, last)
	if err != nil {
		return nil, fmt.Errorf("sqlite: seals: %w", err)
	}
	return scanSeals(rows)
}

func scanSeals(rows *sql.Rows) ([]seal.Stored, error) {
	defer rows.Close() //nolint:errcheck // rows are read to the end below
	var out []seal.Stored
	for rows.Next() {
		var st seal.Stored
		var sealedAt int64
		if err := rows.Scan(&st.Seq, &sealedAt, &st.Hash, &st.Bytes); err != nil {
			return nil, fmt.Errorf("sqlite: seals: %w", err)
		}
		st.SealedAt = micros(sealedAt)
		out = append(out, st)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: seals: %w", err)
	}
	return out, rows.Close()
}

// PutProof stores p. The foreign key and the BEFORE INSERT trigger both
// refuse a proof for an unknown seal.
func (p *Provider) PutProof(ctx context.Context, pr seal.Proof) error {
	_, err := p.db.ExecContext(ctx, `INSERT INTO tamperlog_proof (seal_seq, provider, obtained_at, body) VALUES (?, ?, ?, ?)`,
		pr.SealSeq, pr.Provider, pr.ObtainedAt.UnixMicro(), pr.Bytes)
	if err != nil {
		return fmt.Errorf("sqlite: put proof %d/%s: %w", pr.SealSeq, pr.Provider, err)
	}
	return nil
}

// Proofs returns the proofs of one seal in the order they were obtained.
func (p *Provider) Proofs(ctx context.Context, sealSeq int64) ([]seal.Proof, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT seal_seq, provider, obtained_at, body FROM tamperlog_proof WHERE seal_seq = ? ORDER BY obtained_at, provider`, sealSeq)
	if err != nil {
		return nil, fmt.Errorf("sqlite: proofs: %w", err)
	}
	defer rows.Close() //nolint:errcheck // rows are read to the end below
	var out []seal.Proof
	for rows.Next() {
		var pr seal.Proof
		var obtainedAt int64
		if err := rows.Scan(&pr.SealSeq, &pr.Provider, &obtainedAt, &pr.Bytes); err != nil {
			return nil, fmt.Errorf("sqlite: proofs: %w", err)
		}
		pr.ObtainedAt = micros(obtainedAt)
		out = append(out, pr)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: proofs: %w", err)
	}
	return out, rows.Close()
}

// Unanchored returns up to limit seals, oldest first, without a proof from
// provider.
func (p *Provider) Unanchored(ctx context.Context, provider string, limit int) ([]seal.Stored, error) {
	rows, err := p.db.QueryContext(ctx, `
SELECT s.seq, s.sealed_at, s.hash, s.body FROM tamperlog_seal AS s
WHERE NOT EXISTS (SELECT 1 FROM tamperlog_proof AS p WHERE p.seal_seq = s.seq AND p.provider = ?)
ORDER BY s.seq LIMIT ?`, provider, limit)
	if err != nil {
		return nil, fmt.Errorf("sqlite: unanchored: %w", err)
	}
	return scanSeals(rows)
}
