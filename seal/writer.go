package seal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/kastrul/tamperlog"
)

// Signer signs seal documents. Implementations live in package sign (Ed25519,
// HMAC); a KMS or Vault Transit client implements the same interface.
type Signer interface {
	// KeyID identifies the key so a verifier can select the public key or
	// secret; it is written into the seal.
	KeyID() string
	// Sign returns a signature over data.
	Sign(ctx context.Context, data []byte) ([]byte, error)
}

// Verifier checks signatures made by a [Signer].
type Verifier interface {
	// Verify reports whether sig is a valid signature over data by keyID.
	Verify(ctx context.Context, keyID string, data, sig []byte) error
}

// Provider is what the writer needs from storage: stream heads and the seal
// table. Every shipped store implements it.
type Provider interface {
	tamperlog.Provider
	Store
}

// WriterOption configures a [Writer].
type WriterOption func(*Writer)

// WithSinks adds write-once sinks that receive every seal's canonical bytes
// under [Key]. A sink failure is logged and reported through Hooks but does
// not fail the seal: the seal table is the source and sinks are copies.
func WithSinks(s ...Sink) WriterOption { return func(w *Writer) { w.sinks = append(w.sinks, s...) } }

// WithSigner signs each seal; the key identifier and signature become part
// of the document.
func WithSigner(s Signer) WriterOption { return func(w *Writer) { w.signer = s } }

// WithWriterName sets the "writer" member (default "tamperlog"). Include the
// application and version so an auditor knows which software wrote a seal.
func WithWriterName(name string) WriterOption { return func(w *Writer) { w.name = name } }

// WithClock replaces the clock used for sealed_at (default time.Now).
func WithClock(now func() time.Time) WriterOption { return func(w *Writer) { w.now = now } }

// WithLogger sets the logger; by default nothing is logged.
func WithLogger(l *slog.Logger) WriterOption { return func(w *Writer) { w.logger = l } }

// WithSystemStream names the stream whose retention drop events are listed
// in seals (default [tamperlog.SystemStream]).
func WithSystemStream(name string) WriterOption { return func(w *Writer) { w.systemStream = name } }

// WithWriterHooks installs callbacks.
func WithWriterHooks(h WriterHooks) WriterOption { return func(w *Writer) { w.hooks = h } }

// WriterHooks are callbacks invoked by the writer.
type WriterHooks struct {
	// OnSeal receives every seal after it is stored.
	OnSeal func(ctx context.Context, s Stored)
	// OnSinkError is called when a sink refuses or fails a put.
	OnSinkError func(ctx context.Context, sink Sink, key string, err error)
}

// Writer produces seals. One writer per deployment: a second writer racing on
// the same store fails on the dense seal sequence rather than forking it.
type Writer struct {
	p            Provider
	sinks        []Sink
	signer       Signer
	name         string
	now          func() time.Time
	logger       *slog.Logger
	systemStream string
	hooks        WriterHooks
}

// NewWriter returns a Writer over p.
func NewWriter(p Provider, opts ...WriterOption) *Writer {
	w := &Writer{
		p:            p,
		name:         "tamperlog",
		now:          time.Now,
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		systemStream: tamperlog.SystemStream,
	}
	for _, o := range opts {
		o(w)
	}
	return w
}

// Seal writes one seal of the current heads and returns it. It is safe to
// call at any time; a seal that changes nothing is still written, so that a
// quiet hour is attested like a busy one. Drops lists the retention drop
// digests recorded in the system stream since the previous seal.
func (w *Writer) Seal(ctx context.Context) (Stored, error) {
	last, hasLast, err := w.p.LastSeal(ctx)
	if err != nil {
		return Stored{}, fmt.Errorf("seal: last seal: %w", err)
	}
	s := &Seal{
		Schema:       Schema,
		Seq:          1,
		SealedAt:     w.now().UTC().Truncate(time.Microsecond),
		PrevSealHash: GenesisHash,
		Writer:       w.name,
		Drops:        []Hex{},
	}
	var prev *Seal
	if hasLast {
		prev, err = Parse(last.Bytes)
		if err != nil {
			return Stored{}, fmt.Errorf("seal: previous seal %d: %w", last.Seq, err)
		}
		s.Seq = last.Seq + 1
		s.PrevSealHash = last.Hash
		if !s.SealedAt.After(prev.SealedAt) {
			return Stored{}, fmt.Errorf("seal: clock %s is not after the previous seal at %s", s.SealedAt, prev.SealedAt)
		}
	}
	if s.Streams, err = w.heads(ctx); err != nil {
		return Stored{}, err
	}
	if s.Drops, err = w.drops(ctx, prev, s.Streams); err != nil {
		return Stored{}, err
	}
	if w.signer != nil {
		s.KeyID = w.signer.KeyID()
		data, err := s.SigningBytes()
		if err != nil {
			return Stored{}, err
		}
		if s.Signature, err = w.signer.Sign(ctx, data); err != nil {
			return Stored{}, fmt.Errorf("seal: sign: %w", err)
		}
	}
	canonical, err := s.Canonical()
	if err != nil {
		return Stored{}, err
	}
	st := Stored{Seq: s.Seq, SealedAt: s.SealedAt, Hash: Hash(canonical), Bytes: canonical}
	if err := w.p.PutSeal(ctx, st); err != nil {
		return Stored{}, fmt.Errorf("seal: store seal %d: %w", st.Seq, err)
	}
	w.logger.InfoContext(ctx, "tamperlog seal written", "seq", st.Seq, "streams", len(s.Streams), "drops", len(s.Drops))
	w.sink(ctx, Key(st.Seq), st.Bytes)
	if w.hooks.OnSeal != nil {
		w.hooks.OnSeal(ctx, st)
	}
	return st, nil
}

// heads reads every stream's head and first kept sequence, sorted by name.
func (w *Writer) heads(ctx context.Context) ([]StreamHead, error) {
	heads, err := w.p.Heads(ctx)
	if err != nil {
		return nil, fmt.Errorf("seal: heads: %w", err)
	}
	firsts, err := w.p.FirstSeqs(ctx)
	if err != nil {
		return nil, fmt.Errorf("seal: first seqs: %w", err)
	}
	out := make([]StreamHead, 0, len(heads))
	for name, h := range heads {
		first, ok := firsts[name]
		if !ok || first < 1 || first > h.Seq {
			return nil, fmt.Errorf("seal: stream %s: first kept seq %d, head %d", name, first, h.Seq)
		}
		if h.Encoder == "" || h.Hasher == "" {
			return nil, fmt.Errorf("seal: stream %s: head does not name its encoder and hasher", name)
		}
		out = append(out, StreamHead{Stream: name, Encoder: h.Encoder, Hasher: h.Hasher, FirstKeptSeq: first, HeadSeq: h.Seq, HeadHash: h.Hash})
	}
	slices.SortFunc(out, func(a, b StreamHead) int { return strings.Compare(a.Stream, b.Stream) })
	return out, nil
}

// drops returns the payload hashes of retention.drop events appended to the
// system stream after the previous seal's head of that stream.
func (w *Writer) drops(ctx context.Context, prev *Seal, heads []StreamHead) ([]Hex, error) {
	var from, to int64
	for _, h := range heads {
		if h.Stream == w.systemStream {
			to = h.HeadSeq
			from = h.FirstKeptSeq
		}
	}
	if to == 0 {
		return []Hex{}, nil
	}
	if prev != nil {
		for _, h := range prev.Streams {
			if h.Stream == w.systemStream && h.HeadSeq+1 > from {
				from = h.HeadSeq + 1
			}
		}
	}
	if from > to {
		return []Hex{}, nil
	}
	tx, err := w.p.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("seal: begin: %w", err)
	}
	defer tx.Rollback(context.WithoutCancel(ctx)) //nolint:errcheck // read-only transaction
	out := []Hex{}
	const page = 1000
	for lo := from; lo <= to; lo += page {
		hi := min(lo+page-1, to)
		recs, err := tx.Range(ctx, w.systemStream, lo, hi)
		if err != nil {
			return nil, fmt.Errorf("seal: system stream %d..%d: %w", lo, hi, err)
		}
		for _, r := range recs {
			if r.Action == tamperlog.DropAction && len(r.PayloadHash) > 0 {
				out = append(out, Hex(bytes.Clone(r.PayloadHash)))
			}
		}
	}
	return out, nil
}

// sink pushes data to every sink, tolerating failures.
func (w *Writer) sink(ctx context.Context, key string, data []byte) {
	for _, s := range w.sinks {
		if err := s.Put(ctx, key, data); err != nil {
			w.logger.ErrorContext(ctx, "tamperlog sink put failed", "key", key, "sink", fmt.Sprintf("%T", s), "err", err)
			if w.hooks.OnSinkError != nil {
				w.hooks.OnSinkError(ctx, s, key, err)
			}
		}
	}
}

// Resync pushes to every sink each stored seal and proof whose key the sink
// lacks, so a sink added later or one that was unreachable catches up. It
// returns the number of objects written and the first error, after trying
// every object.
func (w *Writer) Resync(ctx context.Context) (int, error) {
	var written int
	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, s := range w.sinks {
		have, err := s.List(ctx, "seals/")
		if err != nil {
			note(fmt.Errorf("seal: resync list: %w", err))
			continue
		}
		present := map[string]bool{}
		for _, k := range have {
			present[k] = true
		}
		const page = 500
		for lo := int64(1); ; lo += page {
			seals, err := w.p.Seals(ctx, lo, lo+page-1)
			if err != nil {
				note(fmt.Errorf("seal: resync seals: %w", err))
				break
			}
			if len(seals) == 0 {
				break
			}
			for _, st := range seals {
				if !present[Key(st.Seq)] {
					if err := s.Put(ctx, Key(st.Seq), st.Bytes); err != nil && !errors.Is(err, ErrExists) {
						note(err)
					} else {
						written++
					}
				}
				proofs, err := w.p.Proofs(ctx, st.Seq)
				if err != nil {
					note(err)
					continue
				}
				for _, p := range proofs {
					k := ProofKey(st.Seq, p.Provider)
					if present[k] {
						continue
					}
					if err := s.Put(ctx, k, p.Bytes); err != nil && !errors.Is(err, ErrExists) {
						note(err)
					} else {
						written++
						present[k] = true
					}
				}
			}
		}
	}
	return written, firstErr
}

// Run seals every interval until ctx ends. The first seal is written
// immediately. Errors are logged and reported through hooks; Run only returns
// ctx.Err(). Deployments with several application instances run exactly one
// Run loop, for example on a leader or a dedicated job.
func (w *Writer) Run(ctx context.Context, interval time.Duration, onError func(error)) error {
	if interval <= 0 {
		interval = time.Hour
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if _, err := w.Seal(ctx); err != nil {
			w.logger.ErrorContext(ctx, "tamperlog seal failed", "err", err)
			if onError != nil {
				onError(err)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}
