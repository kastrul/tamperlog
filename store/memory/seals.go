package memory

import (
	"context"
	"fmt"
	"slices"

	"github.com/kastrul/tamperlog/seal"
)

// sealBook is the in-memory seal.Store.
type sealBook struct {
	seals  []seal.Stored
	proofs map[int64][]seal.Proof
}

func newSealBook() *sealBook { return &sealBook{proofs: map[int64][]seal.Proof{}} }

// PutSeal stores s; its Seq must follow the last one.
func (s *Store) PutSeal(_ context.Context, st seal.Stored) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	want := int64(len(s.seals.seals)) + 1
	if st.Seq != want {
		return fmt.Errorf("memory: seal seq %d, want %d", st.Seq, want)
	}
	st.Bytes = slices.Clone(st.Bytes)
	st.Hash = slices.Clone(st.Hash)
	s.seals.seals = append(s.seals.seals, st)
	return nil
}

// LastSeal returns the newest seal.
func (s *Store) LastSeal(context.Context) (seal.Stored, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := len(s.seals.seals); n > 0 {
		return s.seals.seals[n-1], true, nil
	}
	return seal.Stored{}, false, nil
}

// Seals returns seals first..last.
func (s *Store) Seals(_ context.Context, first, last int64) ([]seal.Stored, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []seal.Stored
	for _, st := range s.seals.seals {
		if st.Seq >= first && st.Seq <= last {
			out = append(out, st)
		}
	}
	return out, nil
}

// PutProof stores p.
func (s *Store) PutProof(_ context.Context, p seal.Proof) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.SealSeq < 1 || p.SealSeq > int64(len(s.seals.seals)) {
		return fmt.Errorf("memory: proof for unknown seal %d", p.SealSeq)
	}
	p.Bytes = slices.Clone(p.Bytes)
	s.seals.proofs[p.SealSeq] = append(s.seals.proofs[p.SealSeq], p)
	return nil
}

// Proofs returns the proofs of one seal.
func (s *Store) Proofs(_ context.Context, sealSeq int64) ([]seal.Proof, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.seals.proofs[sealSeq]), nil
}

// Unanchored returns seals without a proof from provider, oldest first.
func (s *Store) Unanchored(_ context.Context, provider string, limit int) ([]seal.Stored, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []seal.Stored
	for _, st := range s.seals.seals {
		if len(out) >= limit {
			break
		}
		if !slices.ContainsFunc(s.seals.proofs[st.Seq], func(p seal.Proof) bool { return p.Provider == provider }) {
			out = append(out, st)
		}
	}
	return out, nil
}
