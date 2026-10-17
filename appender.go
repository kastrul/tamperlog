package tamperlog

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"
)

// DefaultSkewTolerance bounds how far a caller-supplied timestamp may differ
// from the store clock when [WithCallerTime] is used.
const DefaultSkewTolerance = 5 * time.Second

// Hooks are callbacks the appender invokes. Each is optional. They run
// synchronously inside Append, after the store accepted the record and before
// Append returns; a slow hook slows the caller's transaction.
type Hooks struct {
	// OnAppend receives every record linked by this appender.
	OnAppend func(ctx context.Context, r Record)
}

// Option configures an [Appender] or [Log].
type Option func(*config)

type config struct {
	chain        Chain
	callerTime   bool
	skew         time.Duration
	timeTol      time.Duration
	systemStream string
	logger       *slog.Logger
	hooks        Hooks
}

func newConfig(opts []Option) config {
	c := config{
		chain:        NewChain(nil, nil),
		skew:         DefaultSkewTolerance,
		timeTol:      DefaultTimeTolerance,
		systemStream: SystemStream,
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	for _, o := range opts {
		o(&c)
	}
	return c
}

// WithEncoder selects the canonical encoder (default [BinaryV1]).
func WithEncoder(enc Encoder) Option { return func(c *config) { c.chain.Encoder = enc } }

// WithHasher selects the hash function (default [SHA256]).
func WithHasher(h Hasher) Option { return func(c *config) { c.chain.Hasher = h } }

// WithCallerTime makes the appender stamp records with Event.Time instead of
// the store clock. The value must lie within the skew tolerance of the store
// clock ([WithSkewTolerance]) and not precede the previous record by more
// than the time tolerance, or Append fails with [ErrClockSkew].
func WithCallerTime() Option { return func(c *config) { c.callerTime = true } }

// WithSkewTolerance sets how far a caller-supplied time may differ from the
// store clock (default [DefaultSkewTolerance]).
func WithSkewTolerance(d time.Duration) Option { return func(c *config) { c.skew = d } }

// WithTimeTolerance sets how far a record may precede its predecessor
// (default [DefaultTimeTolerance]). The same value must be used by verifiers.
func WithTimeTolerance(d time.Duration) Option { return func(c *config) { c.timeTol = d } }

// WithSystemStream renames the stream the library's own components write to
// (default [SystemStream]).
func WithSystemStream(name string) Option { return func(c *config) { c.systemStream = name } }

// WithLogger sets the logger; by default nothing is logged. The appender logs
// at Debug on every append and at Warn on every refusal.
func WithLogger(l *slog.Logger) Option { return func(c *config) { c.logger = l } }

// WithHooks installs callbacks.
func WithHooks(h Hooks) Option { return func(c *config) { c.hooks = h } }

// ErrClockSkew is returned when a caller-supplied time is outside the allowed
// bounds.
var ErrClockSkew = errors.New("tamperlog: timestamp outside tolerance")

// Appender links events into streams through a [Store]. It holds no database
// state and is safe for concurrent use.
type Appender struct {
	cfg config
}

// New returns an Appender with the given options.
func New(opts ...Option) *Appender {
	a := &Appender{cfg: newConfig(opts)}
	a.cfg.chain = NewChain(a.cfg.chain.Encoder, a.cfg.chain.Hasher)
	return a
}

// Chain returns the encoder and hasher the appender links with.
func (a *Appender) Chain() Chain { return a.cfg.chain }

// SystemStream returns the stream name the library's components write to.
func (a *Appender) SystemStream() string { return a.cfg.systemStream }

// TimeTolerance returns the configured time tolerance for verifiers.
func (a *Appender) TimeTolerance() time.Duration { return a.cfg.timeTol }

// Append validates e, locks its stream through s, links it to the head and
// inserts it. The record commits or rolls back with s's transaction. Call it
// last in the transaction: the stream lock is held until the transaction
// ends. A failure must fail the business operation too, or the event is lost.
func (a *Appender) Append(ctx context.Context, s Store, e Event) (Record, error) {
	if err := e.Validate(a.cfg.chain.Hasher.Size()); err != nil {
		a.cfg.logger.WarnContext(ctx, "tamperlog append refused", "stream", e.Stream, "err", err)
		return Record{}, err
	}
	h, err := s.Head(ctx, e.Stream)
	if err != nil {
		return Record{}, fmt.Errorf("tamperlog: head of %s: %w", e.Stream, err)
	}
	if h.Seq >= MaxSeq {
		return Record{}, fmt.Errorf("tamperlog: stream %s reached the maximum sequence number", e.Stream)
	}
	prev := h.Hash
	if h.Seq == 0 {
		prev = a.cfg.chain.Genesis()
	} else if len(prev) != a.cfg.chain.Hasher.Size() {
		return Record{}, fmt.Errorf("tamperlog: head of %s has a %d-byte hash, want %d", e.Stream, len(prev), a.cfg.chain.Hasher.Size())
	}
	at, err := a.stamp(e, h)
	if err != nil {
		a.cfg.logger.WarnContext(ctx, "tamperlog append refused", "stream", e.Stream, "err", err)
		return Record{}, err
	}
	r := Record{Event: e, Seq: h.Seq + 1, At: at, PrevHash: prev}
	r.Time = time.Time{}
	if r.Hash, err = a.cfg.chain.Link(r); err != nil {
		return Record{}, fmt.Errorf("tamperlog: link %s/%d: %w", e.Stream, r.Seq, err)
	}
	if err := s.Insert(ctx, r); err != nil {
		return Record{}, fmt.Errorf("tamperlog: insert %s/%d: %w", e.Stream, r.Seq, err)
	}
	a.cfg.logger.DebugContext(ctx, "tamperlog appended", "stream", r.Stream, "seq", r.Seq, "action", r.Action)
	if a.cfg.hooks.OnAppend != nil {
		a.cfg.hooks.OnAppend(ctx, r)
	}
	return r, nil
}

// stamp decides the record's timestamp: the store clock, or the caller's time
// when enabled and within bounds. The result is UTC at microsecond precision,
// the precision every shipped backend stores.
func (a *Appender) stamp(e Event, h Head) (time.Time, error) {
	if h.Now.IsZero() {
		return time.Time{}, errors.New("tamperlog: store returned no clock")
	}
	now := h.Now.UTC().Truncate(time.Microsecond)
	if !a.cfg.callerTime {
		return now, nil
	}
	if e.Time.IsZero() {
		return time.Time{}, fmt.Errorf("%w: caller time enabled but Event.Time is zero", ErrClockSkew)
	}
	at := e.Time.UTC().Truncate(time.Microsecond)
	if d := at.Sub(now); d > a.cfg.skew || d < -a.cfg.skew {
		return time.Time{}, fmt.Errorf("%w: %s is %s from the store clock %s", ErrClockSkew, at.Format(time.RFC3339Nano), d, now.Format(time.RFC3339Nano))
	}
	return at, nil
}

// Log is the convenience wrapper for callers without a business transaction:
// each Append opens a transaction on the provider, links the event and
// commits. Prefer [Appender.Append] inside the transaction of the change being
// recorded whenever one exists.
type Log struct {
	p Provider
	a *Appender
}

// NewLog returns a Log over p.
func NewLog(p Provider, opts ...Option) *Log {
	return &Log{p: p, a: New(opts...)}
}

// Appender returns the underlying appender for use inside caller transactions.
func (l *Log) Appender() *Appender { return l.a }

// Provider returns the provider the log was built on.
func (l *Log) Provider() Provider { return l.p }

// Append links e in its own transaction and commits.
func (l *Log) Append(ctx context.Context, e Event) (Record, error) {
	tx, err := l.p.Begin(ctx)
	if err != nil {
		return Record{}, fmt.Errorf("tamperlog: begin: %w", err)
	}
	r, err := l.a.Append(ctx, tx, e)
	if err != nil {
		_ = tx.Rollback(ctx)
		return Record{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		_ = tx.Rollback(ctx)
		return Record{}, fmt.Errorf("tamperlog: commit %s/%d: %w", r.Stream, r.Seq, err)
	}
	return r, nil
}
