// Package memory is an in-memory [tamperlog.Provider] and [seal.Store] for
// tests, examples and as the reference implementation of the storage contract.
// It keeps every stream in a slice, locks a stream from Head until the
// transaction ends, and stamps records with an injectable clock. Nothing is
// durable.
package memory

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/kastrul/tamperlog"
)

// Store holds streams in memory. The zero value is not usable; use [New].
type Store struct {
	clock func() time.Time

	mu      sync.Mutex // guards the streams map and the seal book
	streams map[string]*stream
	seals   *sealBook
}

// stream separates two concerns: owner is the append lock a transaction holds
// from Head to Commit or Rollback (a channel so waiting honours ctx), data
// guards the records for readers and the committing writer.
type stream struct {
	owner chan struct{}
	data  sync.RWMutex
	recs  []tamperlog.Record
}

func newStream() *stream { return &stream{owner: make(chan struct{}, 1)} }

// acquire takes the append lock or returns ctx.Err().
func (st *stream) acquire(ctx context.Context) error {
	select {
	case st.owner <- struct{}{}:
		return nil
	default:
	}
	select {
	case st.owner <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (st *stream) release() { <-st.owner }

// Option configures a Store.
type Option func(*Store)

// WithClock replaces the store clock (default time.Now). Tests pass a clock
// that advances deterministically.
func WithClock(now func() time.Time) Option { return func(s *Store) { s.clock = now } }

// New returns an empty store.
func New(opts ...Option) *Store {
	s := &Store{clock: time.Now, streams: map[string]*stream{}, seals: newSealBook()}
	for _, o := range opts {
		o(s)
	}
	return s
}

func (s *Store) stream(name string) *stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.streams[name]
	if !ok {
		st = newStream()
		s.streams[name] = st
	}
	return st
}

// snapshot returns the streams map entries under s.mu, so callers can take
// per-stream locks without holding s.mu.
func (s *Store) snapshot() map[string]*stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return maps.Clone(s.streams)
}

// Begin opens a transaction. Records inserted through it become visible to
// other transactions on Commit; Rollback discards them and releases every
// stream lock the transaction took.
func (s *Store) Begin(context.Context) (tamperlog.Tx, error) {
	return &tx{s: s, locked: map[string]*stream{}}, nil
}

// Heads returns each non-empty stream's last link.
func (s *Store) Heads(context.Context) (map[string]tamperlog.Head, error) {
	out := map[string]tamperlog.Head{}
	for name, st := range s.snapshot() {
		st.data.RLock()
		if n := len(st.recs); n > 0 {
			out[name] = headOf(st.recs[n-1], time.Time{})
		}
		st.data.RUnlock()
	}
	return out, nil
}

// FirstSeqs returns each non-empty stream's smallest kept sequence number.
func (s *Store) FirstSeqs(context.Context) (map[string]int64, error) {
	out := map[string]int64{}
	for name, st := range s.snapshot() {
		st.data.RLock()
		if len(st.recs) > 0 {
			out[name] = st.recs[0].Seq
		}
		st.data.RUnlock()
	}
	return out, nil
}

// Records returns a copy of stream's records in sequence order. It is for
// tests and tooling, not part of any library interface.
func (s *Store) Records(name string) []tamperlog.Record {
	st := s.stream(name)
	st.data.RLock()
	defer st.data.RUnlock()
	return cloneRecords(st.recs)
}

// Replace overwrites stream's records, simulating a privileged user who
// rewrites history. Tests use it to exercise the verifier.
func (s *Store) Replace(name string, recs []tamperlog.Record) {
	st := s.stream(name)
	st.data.Lock()
	defer st.data.Unlock()
	st.recs = cloneRecords(recs)
}

// Drop removes stream's records with first <= Seq <= last, simulating a
// retention drop. The caller records the matching drop event.
func (s *Store) Drop(name string, first, last int64) {
	st := s.stream(name)
	st.data.Lock()
	defer st.data.Unlock()
	st.recs = slices.DeleteFunc(st.recs, func(r tamperlog.Record) bool { return r.Seq >= first && r.Seq <= last })
}

func headOf(r tamperlog.Record, now time.Time) tamperlog.Head {
	return tamperlog.Head{Seq: r.Seq, Hash: slices.Clone(r.Hash), At: r.At, Encoder: r.Encoder, Hasher: r.Hasher, Now: now}
}

// tx is one transaction: pending inserts plus the stream locks it holds.
type tx struct {
	s       *Store
	locked  map[string]*stream
	pending []tamperlog.Record
	done    bool
}

var errDone = errors.New("memory: transaction already finished")

// Head locks the stream for this transaction and returns its last link.
func (t *tx) Head(ctx context.Context, name string) (tamperlog.Head, error) {
	if t.done {
		return tamperlog.Head{}, errDone
	}
	if err := tamperlog.ValidateStream(name); err != nil {
		return tamperlog.Head{}, err
	}
	st, held := t.locked[name]
	if !held {
		st = t.s.stream(name)
		if err := st.acquire(ctx); err != nil {
			return tamperlog.Head{}, fmt.Errorf("memory: lock %s: %w", name, err)
		}
		t.locked[name] = st
	}
	now := t.s.clock()
	// Pending records of this transaction are the newest.
	for i := len(t.pending) - 1; i >= 0; i-- {
		if t.pending[i].Stream == name {
			return headOf(t.pending[i], now), nil
		}
	}
	st.data.RLock()
	defer st.data.RUnlock()
	if n := len(st.recs); n > 0 {
		return headOf(st.recs[n-1], now), nil
	}
	return tamperlog.Head{Now: now}, nil
}

// Insert stages r; it must follow a Head on the same stream in this
// transaction and must not duplicate a sequence number.
func (t *tx) Insert(ctx context.Context, r tamperlog.Record) error {
	if t.done {
		return errDone
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	st, held := t.locked[r.Stream]
	if !held {
		return fmt.Errorf("memory: insert into %s without Head in this transaction", r.Stream)
	}
	for _, p := range t.pending {
		if p.Stream == r.Stream && p.Seq == r.Seq {
			return fmt.Errorf("memory: duplicate %s/%d", r.Stream, r.Seq)
		}
	}
	st.data.RLock()
	_, dup := slices.BinarySearchFunc(st.recs, r.Seq, func(x tamperlog.Record, seq int64) int { return int(x.Seq - seq) })
	st.data.RUnlock()
	if dup {
		return fmt.Errorf("memory: duplicate %s/%d", r.Stream, r.Seq)
	}
	t.pending = append(t.pending, cloneRecord(r))
	return nil
}

// Range reads committed records plus this transaction's pending ones.
func (t *tx) Range(ctx context.Context, name string, first, last int64) ([]tamperlog.Record, error) {
	if t.done {
		return nil, errDone
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	st := t.s.stream(name)
	st.data.RLock()
	var out []tamperlog.Record
	for _, r := range st.recs {
		if r.Seq >= first && r.Seq <= last {
			out = append(out, cloneRecord(r))
		}
	}
	st.data.RUnlock()
	for _, r := range t.pending {
		if r.Stream == name && r.Seq >= first && r.Seq <= last {
			out = append(out, cloneRecord(r))
		}
	}
	return out, nil
}

// Commit publishes pending records and releases stream locks.
func (t *tx) Commit(ctx context.Context) error {
	if t.done {
		return errDone
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, r := range t.pending {
		st := t.locked[r.Stream]
		st.data.Lock()
		st.recs = append(st.recs, r)
		st.data.Unlock()
	}
	t.finish()
	return nil
}

// Rollback discards pending records and releases stream locks. After Commit it
// is a no-op.
func (t *tx) Rollback(context.Context) error {
	if t.done {
		return nil
	}
	t.finish()
	return nil
}

func (t *tx) finish() {
	t.done = true
	t.pending = nil
	for _, st := range t.locked {
		st.release()
	}
	t.locked = nil
}

func cloneRecord(r tamperlog.Record) tamperlog.Record {
	r.PrevHash = slices.Clone(r.PrevHash)
	r.Hash = slices.Clone(r.Hash)
	r.PayloadHash = slices.Clone(r.PayloadHash)
	if r.Attributes != nil {
		r.Attributes = maps.Clone(r.Attributes)
	}
	return r
}

func cloneRecords(recs []tamperlog.Record) []tamperlog.Record {
	out := make([]tamperlog.Record, len(recs))
	for i, r := range recs {
		out[i] = cloneRecord(r)
	}
	return out
}
