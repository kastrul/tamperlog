// Package verify compares anchors, seals and the chain, in that order
// (ADR 0015): the artefacts an insider could not have produced after the fact
// come first, and the live chain is checked against them rather than against
// itself.
//
// A [Verifier] reads from a [Source], which is either a live store
// ([FromProvider]) or an export bundle (package bundle), and produces a
// [Report] with one or more [Finding]s per layer. The same code runs in the
// application (continuous verification through [Runner]) and in the offline
// CLI, so an auditor holding the seals, the proofs, the trust roots and a
// copy of the records can repeat the check without access to the system.
//
// What it checks:
//
//   - every seal parses canonically, its sequence is dense, it links to its
//     predecessor's hash, its time increases, its signature verifies when a
//     signature verifier is configured;
//   - every proof verifies under its provider and attests a time at or after
//     the seal time; seals older than the grace period without a proof are
//     reported;
//   - every configured sink holds the same bytes as the store for every seal
//     and proof;
//   - across seals, a stream's head never moves backwards and its first kept
//     sequence only moves forward;
//   - every stream named in the latest seal still exists and its live head is
//     at or beyond the sealed head;
//   - every kept record links correctly (sequence, encoder and hasher,
//     prev_hash, hash, time monotonicity), every sealed head hash matches
//     the record at that sequence, and every gap is bridged by drop events
//     whose digests appear in a seal.
package verify

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/kastrul/tamperlog"
	"github.com/kastrul/tamperlog/anchor"
	"github.com/kastrul/tamperlog/encoding/jcs"
	canon "github.com/kastrul/tamperlog/internal/jcs"
	"github.com/kastrul/tamperlog/seal"
)

// Source is what the verifier reads. [FromProvider] adapts a live store; the
// bundle package adapts an export.
type Source interface {
	Heads(ctx context.Context) (map[string]tamperlog.Head, error)
	FirstSeqs(ctx context.Context) (map[string]int64, error)
	Range(ctx context.Context, stream string, first, last int64) ([]tamperlog.Record, error)
	LastSeal(ctx context.Context) (seal.Stored, bool, error)
	Seals(ctx context.Context, first, last int64) ([]seal.Stored, error)
	Proofs(ctx context.Context, sealSeq int64) ([]seal.Proof, error)
}

// FromProvider adapts a live store. Each Range runs in its own read
// transaction.
func FromProvider(p seal.Provider) Source { return providerSource{p} }

type providerSource struct{ p seal.Provider }

func (s providerSource) Heads(ctx context.Context) (map[string]tamperlog.Head, error) {
	return s.p.Heads(ctx)
}

func (s providerSource) FirstSeqs(ctx context.Context) (map[string]int64, error) {
	return s.p.FirstSeqs(ctx)
}

func (s providerSource) Range(ctx context.Context, stream string, first, last int64) ([]tamperlog.Record, error) {
	tx, err := s.p.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx)) //nolint:errcheck // read-only
	return tx.Range(ctx, stream, first, last)
}

func (s providerSource) LastSeal(ctx context.Context) (seal.Stored, bool, error) {
	return s.p.LastSeal(ctx)
}

func (s providerSource) Seals(ctx context.Context, first, last int64) ([]seal.Stored, error) {
	return s.p.Seals(ctx, first, last)
}

func (s providerSource) Proofs(ctx context.Context, sealSeq int64) ([]seal.Proof, error) {
	return s.p.Proofs(ctx, sealSeq)
}

// Severity of a finding.
type Severity string

// Severities. An Error means the evidence does not hold; a Warning means a
// check could not be completed or a policy expectation was missed; Info is
// context for the reader.
const (
	Error   Severity = "error"
	Warning Severity = "warning"
	Info    Severity = "info"
)

// Layer names where a finding was made.
type Layer string

// Layers, outermost first.
const (
	LayerAnchor Layer = "anchor"
	LayerSeal   Layer = "seal"
	LayerSink   Layer = "sink"
	LayerChain  Layer = "chain"
)

// Finding is one observation.
type Finding struct {
	Severity Severity `json:"severity"`
	Layer    Layer    `json:"layer"`
	Code     string   `json:"code"`
	Message  string   `json:"message"`
	Stream   string   `json:"stream,omitempty"`
	Seq      int64    `json:"seq,omitempty"`      // record sequence for chain findings
	SealSeq  int64    `json:"seal_seq,omitempty"` // seal sequence for seal, anchor and sink findings
}

func (f Finding) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %s", f.Severity, f.Layer, f.Code)
	if f.Stream != "" {
		fmt.Fprintf(&b, " stream=%s", f.Stream)
	}
	if f.Seq != 0 {
		fmt.Fprintf(&b, " seq=%d", f.Seq)
	}
	if f.SealSeq != 0 {
		fmt.Fprintf(&b, " seal=%d", f.SealSeq)
	}
	return b.String() + ": " + f.Message
}

// Finding codes. They are stable identifiers for alerting.
const (
	CodeSealParse        = "seal_parse"
	CodeSealSequence     = "seal_sequence"
	CodeSealChain        = "seal_chain"
	CodeSealTime         = "seal_time"
	CodeSealSignature    = "seal_signature"
	CodeSealUnsigned     = "seal_unsigned"
	CodeSealRegression   = "seal_regression"
	CodeProofInvalid     = "proof_invalid"
	CodeProofTime        = "proof_time"
	CodeProofMissing     = "proof_missing"
	CodeProofUnqualified = "proof_unqualified"
	CodeProofUnknown     = "proof_unknown_provider"
	CodeSinkMissing      = "sink_missing"
	CodeSinkMismatch     = "sink_mismatch"
	CodeSinkError        = "sink_error"
	CodeStreamMissing    = "stream_missing"
	CodeStreamTruncated  = "stream_truncated"
	CodeStreamAlgorithm  = "stream_algorithm"
	CodeStreamUnknown    = "stream_unknown_algorithm"
	CodeChainBroken      = "chain_broken"
	CodeChainHead        = "chain_sealed_head"
	CodeChainGap         = "chain_gap"
	CodeChainDrop        = "chain_drop_event"
	CodeChainUnsealed    = "chain_unsealed_records"
	CodeChainFirstKept   = "chain_first_kept"
	CodeNoSeals          = "no_seals"
	CodeSourceError      = "source_error"
	CodeStreamNotSealed  = "stream_not_sealed"
	CodeSinkExtra        = "sink_extra_seal"
	CodeSealStale        = "seal_stale"
	CodeSealInterval     = "seal_interval"
	CodeSealFuture       = "seal_future"
	CodeProofDelay       = "proof_delay"
	CodeChainGapPending  = "chain_gap_pending"
	CodeChainInnerGap    = "chain_inner_gap"
)

// StreamReport summarises one stream.
type StreamReport struct {
	Stream       string `json:"stream"`
	Encoder      string `json:"encoder"`
	Hasher       string `json:"hasher"`
	FirstKeptSeq int64  `json:"first_kept_seq"`
	HeadSeq      int64  `json:"head_seq"`
	HeadHash     string `json:"head_hash"`
	Records      int64  `json:"records"`        // records read and linked
	SealedHead   int64  `json:"sealed_head"`    // head sequence in the latest seal, 0 if unsealed
	Unsealed     int64  `json:"unsealed"`       // records after the latest sealed head
	Gaps         []Gap  `json:"gaps"`           // ranges absent from the source
	Verified     bool   `json:"verified"`       // no error findings on this stream
	VerifiedUpTo int64  `json:"verified_up_to"` // last sequence whose link was checked
}

// Gap is a range of sequence numbers absent from the source.
type Gap struct {
	First   int64 `json:"first"`
	Last    int64 `json:"last"`
	Bridged bool  `json:"bridged"` // matched by sealed drop events
}

// SealReport summarises the seal chain.
type SealReport struct {
	Count     int64     `json:"count"`
	FirstSeq  int64     `json:"first_seq"`
	LastSeq   int64     `json:"last_seq"`
	LastAt    time.Time `json:"last_at"`
	Anchored  int64     `json:"anchored"`  // seals with at least one valid proof
	Qualified int64     `json:"qualified"` // seals with a proof from a qualified authority
}

// Scope records which checks a run was configured to perform, so a reader
// of the report can tell a full verification from one with layers disabled.
type Scope struct {
	Anchors           []string      `json:"anchors"`            // provider identifiers whose proofs are verified
	Sinks             int           `json:"sinks"`              // sinks whose copies and inventories are compared
	SignatureRequired bool          `json:"signature_required"` // every seal must carry a verifiable signature
	MaxSealAge        time.Duration `json:"max_seal_age"`       // 0: not enforced
	MaxSealInterval   time.Duration `json:"max_seal_interval"`  // 0: not enforced
	AnchorGrace       time.Duration `json:"anchor_grace"`
	AllowInnerGaps    bool          `json:"allow_inner_gaps"`
}

// String is a one-line description for logs.
func (s Scope) String() string {
	anchors := "none"
	if len(s.Anchors) > 0 {
		anchors = strings.Join(s.Anchors, ",")
	}
	age := "off"
	if s.MaxSealAge > 0 {
		age = s.MaxSealAge.String()
	}
	return fmt.Sprintf("anchors=%s sinks=%d signatures=%v max_seal_age=%s inner_gaps=%v", anchors, s.Sinks, s.SignatureRequired, age, s.AllowInnerGaps)
}

// Report is the verifier's result.
type Report struct {
	StartedAt  time.Time               `json:"started_at"`
	FinishedAt time.Time               `json:"finished_at"`
	Full       bool                    `json:"full"` // every record re-linked (no checkpoints used)
	Scope      Scope                   `json:"scope"`
	Seals      SealReport              `json:"seals"`
	Streams    map[string]StreamReport `json:"streams"`
	Findings   []Finding               `json:"findings"`
}

// Operational reports whether a finding is an error reading the source or a
// sink rather than an integrity failure. Callers map these to a different
// exit status: the evidence was not checked, not found wanting.
func (r *Report) Operational() bool {
	for _, f := range r.Findings {
		if f.Severity == Error && (f.Code == CodeSourceError || f.Code == CodeSinkError) {
			return true
		}
	}
	return false
}

// OK reports whether no finding has severity Error.
func (r *Report) OK() bool {
	for _, f := range r.Findings {
		if f.Severity == Error {
			return false
		}
	}
	return true
}

// Errors returns the error findings.
func (r *Report) Errors() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Severity == Error {
			out = append(out, f)
		}
	}
	return out
}

func (r *Report) add(f Finding) { r.Findings = append(r.Findings, f) }

// Summary is one line for logs and alerts.
func (r *Report) Summary() string {
	var e, w int
	for _, f := range r.Findings {
		switch f.Severity {
		case Error:
			e++
		case Warning:
			w++
		case Info:
		}
	}
	state := "verified"
	if e > 0 {
		state = "BROKEN"
	}
	mode := "full"
	if !r.Full {
		mode = "incremental"
	}
	return fmt.Sprintf("%s: %d streams, %d seals (%d anchored), %d errors, %d warnings, %s, %s run, scope %s", state, len(r.Streams), r.Seals.Count, r.Seals.Anchored, e, w, r.FinishedAt.Sub(r.StartedAt).Round(time.Millisecond), mode, r.Scope)
}

// HeadsDigest is SHA-256 over the JCS encoding of every stream's head
// sequence and hash as seen by this run. The runner records it as the
// payload hash of chain.verified and chain.broken events, so the outcome
// commits to what was verified.
func (r *Report) HeadsDigest() []byte {
	m := map[string]any{}
	for name, s := range r.Streams {
		m[name] = map[string]any{"head_seq": s.HeadSeq, "head_hash": s.HeadHash}
	}
	b, err := canon.Marshal(m)
	if err != nil {
		return nil
	}
	return seal.Hash(b)
}

// Option configures a [Verifier].
type Option func(*Verifier)

// WithAnchors registers proof verifiers by provider identifier. Proofs from
// providers not registered are reported as unknown (warning).
func WithAnchors(p ...anchor.Provider) Option {
	return func(v *Verifier) {
		for _, x := range p {
			v.anchors[x.ID()] = x
		}
	}
}

// WithSinks adds sinks whose copies of seals and proofs are compared with
// the source.
func WithSinks(s ...seal.Sink) Option { return func(v *Verifier) { v.sinks = append(v.sinks, s...) } }

// WithSignatureVerifier requires every seal to carry a signature that
// verifies with sv.
func WithSignatureVerifier(sv seal.Verifier) Option { return func(v *Verifier) { v.sigVerifier = sv } }

// WithEncoders registers encoders by identifier beyond the shipped ones.
func WithEncoders(e ...tamperlog.Encoder) Option {
	return func(v *Verifier) {
		for _, x := range e {
			v.encoders[x.ID()] = x
		}
	}
}

// WithTimeTolerance sets how far a record may precede its predecessor
// (default [tamperlog.DefaultTimeTolerance]); use the appender's value.
func WithTimeTolerance(d time.Duration) Option { return func(v *Verifier) { v.timeTol = d } }

// WithAnchorGrace sets how old an unanchored seal may be before it is an
// error rather than a warning (default 4 h, matching the runner). Zero
// disables the escalation.
func WithAnchorGrace(d time.Duration) Option { return func(v *Verifier) { v.anchorGrace = d } }

// WithAnchorSkew sets how far an attested time may precede the seal time
// (default 1 minute): the TSA's clock and the writer's clock differ.
func WithAnchorSkew(d time.Duration) Option { return func(v *Verifier) { v.anchorSkew = d } }

// WithSystemStream names the stream holding drop events (default
// [tamperlog.SystemStream]).
func WithSystemStream(name string) Option { return func(v *Verifier) { v.systemStream = name } }

// WithPageSize sets how many records one Range call reads (default 1000).
func WithPageSize(n int) Option { return func(v *Verifier) { v.page = int64(n) } }

// WithClock replaces the clock used for grace computations (default time.Now).
func WithClock(now func() time.Time) Option { return func(v *Verifier) { v.now = now } }

// WithLogger sets the logger; by default nothing is logged.
func WithLogger(l *slog.Logger) Option { return func(v *Verifier) { v.logger = l } }

// WithRequireQualified reports a seal whose proofs are all from
// non-qualified authorities as a warning instead of info.
func WithRequireQualified() Option { return func(v *Verifier) { v.requireQualified = true } }

// WithMaxSealAge makes a latest seal older than d an error: the writer has
// stopped, or the source was rolled back to an old but authentic state. Zero
// (default) disables the check; set it to a few seal intervals.
func WithMaxSealAge(d time.Duration) Option { return func(v *Verifier) { v.maxSealAge = d } }

// WithMaxSealInterval makes a gap longer than d between consecutive seals an
// error. Zero (default) disables the check.
func WithMaxSealInterval(d time.Duration) Option { return func(v *Verifier) { v.maxSealInterval = d } }

// WithFutureSkew sets how far a seal time may lie in the future (default 5
// minutes); beyond it the seal is an error.
func WithFutureSkew(d time.Duration) Option { return func(v *Verifier) { v.futureSkew = d } }

// WithMaxAnchorDelay reports a proof attested more than d after the seal time
// as a warning (default 24 h): a proof bounds when the seal existed by, not
// when it claims to have been written. Zero disables the check.
func WithMaxAnchorDelay(d time.Duration) Option { return func(v *Verifier) { v.maxAnchorDelay = d } }

// WithAllowInnerGaps accepts sealed drops inside a stream, not only at its
// start. By default a legitimate retention drop removes the oldest records,
// so a gap must begin at sequence 1; an inner gap is an error even with a
// sealed drop event, which stops anyone who can append to the system stream
// from legitimising a deletion in the middle of history. Enable this only
// for storage layouts that drop inner ranges (legacy partitions).
func WithAllowInnerGaps() Option { return func(v *Verifier) { v.allowInnerGaps = true } }

// Verifier runs the checks. It holds no state between runs except what is
// passed through [Checkpoint]s.
type Verifier struct {
	anchors          map[string]anchor.Provider
	sinks            []seal.Sink
	sigVerifier      seal.Verifier
	encoders         map[string]tamperlog.Encoder
	timeTol          time.Duration
	anchorGrace      time.Duration
	anchorSkew       time.Duration
	systemStream     string
	page             int64
	now              func() time.Time
	logger           *slog.Logger
	requireQualified bool
	maxSealAge       time.Duration
	maxSealInterval  time.Duration
	futureSkew       time.Duration
	maxAnchorDelay   time.Duration
	allowInnerGaps   bool
}

// New returns a Verifier.
func New(opts ...Option) *Verifier {
	v := &Verifier{
		anchors:        map[string]anchor.Provider{},
		encoders:       map[string]tamperlog.Encoder{tamperlog.BinaryV1.ID(): tamperlog.BinaryV1, jcs.V1.ID(): jcs.V1},
		timeTol:        tamperlog.DefaultTimeTolerance,
		anchorGrace:    4 * time.Hour,
		anchorSkew:     time.Minute,
		systemStream:   tamperlog.SystemStream,
		page:           1000,
		now:            time.Now,
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		futureSkew:     5 * time.Minute,
		maxAnchorDelay: 24 * time.Hour,
	}
	for _, o := range opts {
		o(v)
	}
	return v
}

// Checkpoint is where a previous run left a stream: the last record whose
// link was verified. Passing checkpoints makes a run incremental; the run
// still checks every seal and every sealed head, and re-reads one record
// before the checkpoint to verify the boundary link.
type Checkpoint struct {
	Seq  int64
	Hash []byte
}

// Verify runs every check and returns the report. checkpoints may be nil.
func (v *Verifier) Verify(ctx context.Context, src Source, checkpoints map[string]Checkpoint) *Report {
	r := &Report{StartedAt: v.now().UTC(), Streams: map[string]StreamReport{}, Full: len(checkpoints) == 0, Scope: v.scope()}
	seals, drops := v.verifySeals(ctx, src, r)
	v.verifyStreams(ctx, src, r, seals, drops, checkpoints)
	r.FinishedAt = v.now().UTC()
	sort.SliceStable(r.Findings, func(i, j int) bool { return rank(r.Findings[i].Severity) < rank(r.Findings[j].Severity) })
	v.logger.InfoContext(ctx, "tamperlog verification finished", "summary", r.Summary())
	return r
}

func (v *Verifier) scope() Scope {
	sc := Scope{Sinks: len(v.sinks), SignatureRequired: v.sigVerifier != nil, MaxSealAge: v.maxSealAge, MaxSealInterval: v.maxSealInterval, AnchorGrace: v.anchorGrace, AllowInnerGaps: v.allowInnerGaps, Anchors: slices.Sorted(maps.Keys(v.anchors))}
	if sc.Anchors == nil {
		sc.Anchors = []string{}
	}
	return sc
}

func rank(s Severity) int {
	switch s {
	case Error:
		return 0
	case Warning:
		return 1
	default:
		return 2
	}
}

// parsedSeal is a seal with its stored form.
type parsedSeal struct {
	seal.Stored
	doc *seal.Seal
}

// verifySeals checks the seal chain, proofs and sinks. It returns the parsed
// seals in order and the set of sealed drop digests.
func (v *Verifier) verifySeals(ctx context.Context, src Source, r *Report) ([]parsedSeal, map[string]int64) {
	drops := map[string]int64{} // hex digest -> seal seq that lists it
	var seals []parsedSeal
	last, hasLast, err := src.LastSeal(ctx)
	if err != nil {
		r.add(Finding{Severity: Error, Layer: LayerSeal, Code: CodeSourceError, Message: "reading last seal: " + err.Error()})
		return seals, drops
	}
	if hasLast {
		for lo := int64(1); lo <= last.Seq; lo += v.page {
			batch, err := src.Seals(ctx, lo, min(lo+v.page-1, last.Seq))
			if err != nil {
				r.add(Finding{Severity: Error, Layer: LayerSeal, Code: CodeSourceError, Message: "reading seals: " + err.Error()})
				return seals, drops
			}
			for _, st := range batch {
				seals = append(seals, parsedSeal{Stored: st})
			}
		}
	}
	v.reconcileSinks(ctx, r, seals)
	if len(seals) == 0 {
		r.add(Finding{Severity: Warning, Layer: LayerSeal, Code: CodeNoSeals, Message: "no seals exist; the chain is only checked for internal consistency"})
		return nil, drops
	}
	if v.maxSealAge > 0 && v.now().Sub(last.SealedAt) > v.maxSealAge {
		r.add(Finding{Severity: Error, Layer: LayerSeal, Code: CodeSealStale, SealSeq: last.Seq, Message: fmt.Sprintf("latest seal is %s old, limit %s: the writer stopped or the source was rolled back", v.now().Sub(last.SealedAt).Round(time.Minute), v.maxSealAge)})
	}
	r.Seals.Count = int64(len(seals))
	r.Seals.FirstSeq = seals[0].Seq
	r.Seals.LastSeq = seals[len(seals)-1].Seq
	var prev *parsedSeal
	heads := map[string]seal.StreamHead{}
	for i := range seals {
		s := &seals[i]
		if prev != nil && s.Seq != prev.Seq+1 {
			r.add(Finding{Severity: Error, Layer: LayerSeal, Code: CodeSealSequence, SealSeq: s.Seq, Message: fmt.Sprintf("seal %d follows seal %d: a seal is missing", s.Seq, prev.Seq)})
		} else if prev == nil && s.Seq != 1 {
			r.add(Finding{Severity: Error, Layer: LayerSeal, Code: CodeSealSequence, SealSeq: s.Seq, Message: fmt.Sprintf("first seal is %d, not 1", s.Seq)})
		}
		if !bytes.Equal(s.Hash, seal.Hash(s.Bytes)) {
			r.add(Finding{Severity: Error, Layer: LayerSeal, Code: CodeSealParse, SealSeq: s.Seq, Message: "stored hash does not match stored bytes"})
		}
		doc, err := seal.Parse(s.Bytes)
		if err != nil {
			r.add(Finding{Severity: Error, Layer: LayerSeal, Code: CodeSealParse, SealSeq: s.Seq, Message: err.Error()})
			prev = s
			continue
		}
		s.doc = doc
		if doc.Seq != s.Seq {
			r.add(Finding{Severity: Error, Layer: LayerSeal, Code: CodeSealSequence, SealSeq: s.Seq, Message: fmt.Sprintf("document says seq %d", doc.Seq)})
		}
		switch {
		case prev == nil:
			if !bytes.Equal(doc.PrevSealHash, seal.GenesisHash) && s.Seq == 1 {
				r.add(Finding{Severity: Error, Layer: LayerSeal, Code: CodeSealChain, SealSeq: s.Seq, Message: "first seal does not link to genesis"})
			}
		case !bytes.Equal(doc.PrevSealHash, prev.Hash):
			r.add(Finding{Severity: Error, Layer: LayerSeal, Code: CodeSealChain, SealSeq: s.Seq, Message: fmt.Sprintf("prev_seal_hash does not match seal %d", prev.Seq)})
		}
		if prev != nil && prev.doc != nil && !doc.SealedAt.After(prev.doc.SealedAt) {
			r.add(Finding{Severity: Error, Layer: LayerSeal, Code: CodeSealTime, SealSeq: s.Seq, Message: fmt.Sprintf("sealed_at %s is not after seal %d at %s", doc.SealedAt.Format(time.RFC3339Nano), prev.Seq, prev.doc.SealedAt.Format(time.RFC3339Nano))})
		}
		if prev != nil && prev.doc != nil && v.maxSealInterval > 0 && doc.SealedAt.Sub(prev.doc.SealedAt) > v.maxSealInterval {
			r.add(Finding{Severity: Error, Layer: LayerSeal, Code: CodeSealInterval, SealSeq: s.Seq, Message: fmt.Sprintf("%s passed between seal %d and seal %d, limit %s", doc.SealedAt.Sub(prev.doc.SealedAt).Round(time.Second), prev.Seq, s.Seq, v.maxSealInterval)})
		}
		if v.futureSkew > 0 && doc.SealedAt.After(v.now().Add(v.futureSkew)) {
			r.add(Finding{Severity: Error, Layer: LayerSeal, Code: CodeSealFuture, SealSeq: s.Seq, Message: fmt.Sprintf("sealed_at %s is in the future", doc.SealedAt.Format(time.RFC3339))})
		}
		if !doc.SealedAt.Equal(s.SealedAt) {
			r.add(Finding{Severity: Error, Layer: LayerSeal, Code: CodeSealTime, SealSeq: s.Seq, Message: "stored sealed_at differs from the document"})
		}
		v.verifySignature(ctx, r, s)
		for _, h := range doc.Streams {
			if p, ok := heads[h.Stream]; ok {
				switch {
				case h.HeadSeq < p.HeadSeq:
					r.add(Finding{Severity: Error, Layer: LayerSeal, Code: CodeSealRegression, SealSeq: s.Seq, Stream: h.Stream, Message: fmt.Sprintf("head moved back from %d to %d", p.HeadSeq, h.HeadSeq)})
				case h.HeadSeq == p.HeadSeq && !bytes.Equal(h.HeadHash, p.HeadHash):
					r.add(Finding{Severity: Error, Layer: LayerSeal, Code: CodeSealRegression, SealSeq: s.Seq, Stream: h.Stream, Message: fmt.Sprintf("head %d has a different hash than in an earlier seal", h.HeadSeq)})
				case h.FirstKeptSeq < p.FirstKeptSeq:
					r.add(Finding{Severity: Error, Layer: LayerSeal, Code: CodeSealRegression, SealSeq: s.Seq, Stream: h.Stream, Message: fmt.Sprintf("first kept seq moved back from %d to %d", p.FirstKeptSeq, h.FirstKeptSeq)})
				case h.Encoder != p.Encoder || h.Hasher != p.Hasher:
					r.add(Finding{Severity: Error, Layer: LayerSeal, Code: CodeSealRegression, SealSeq: s.Seq, Stream: h.Stream, Message: "encoder or hasher changed between seals"})
				}
			}
			heads[h.Stream] = h
		}
		for _, d := range doc.Drops {
			if _, dup := drops[hex.EncodeToString(d)]; !dup {
				drops[hex.EncodeToString(d)] = s.Seq
			}
		}
		v.verifyProofs(ctx, src, r, s)
		v.verifySinks(ctx, src, r, s)
		prev = s
	}
	if last := seals[len(seals)-1]; last.doc != nil {
		r.Seals.LastAt = last.doc.SealedAt
	}
	return seals, drops
}

// reconcileSinks lists every sink's seal keys and reports seals a sink holds
// beyond the source's last seal: the source was rolled back, or a sink
// received seals the database never had. Either way the sink's copy is read
// and checked to continue the chain from the source's last seal, so the
// report can say how far the rollback goes.
func (v *Verifier) reconcileSinks(ctx context.Context, r *Report, seals []parsedSeal) {
	if len(v.sinks) == 0 {
		return
	}
	var lastSeq int64
	var lastHash []byte
	if n := len(seals); n > 0 {
		lastSeq, lastHash = seals[n-1].Seq, seals[n-1].Hash
	}
	for _, sink := range v.sinks {
		name := fmt.Sprintf("%T", sink)
		keys, err := sink.List(ctx, "seals/")
		if err != nil {
			r.add(Finding{Severity: Error, Layer: LayerSink, Code: CodeSinkError, Message: fmt.Sprintf("%s: list: %v", name, err)})
			continue
		}
		var extra []int64
		for _, k := range keys {
			var seq int64
			if _, err := fmt.Sscanf(k, "seals/%d.json", &seq); err != nil || !strings.HasSuffix(k, ".json") {
				continue
			}
			if seq > lastSeq {
				extra = append(extra, seq)
			}
		}
		if len(extra) == 0 {
			continue
		}
		slices.Sort(extra)
		prevHash := lastHash
		if lastSeq == 0 {
			prevHash = seal.GenesisHash
		}
		linked := 0
		for i, seq := range extra {
			if seq != lastSeq+int64(i)+1 {
				break
			}
			data, err := sink.Get(ctx, seal.Key(seq))
			if err != nil {
				break
			}
			doc, err := seal.Parse(data)
			if err != nil || doc.Seq != seq || !bytes.Equal(doc.PrevSealHash, prevHash) {
				break
			}
			prevHash = seal.Hash(data)
			linked++
		}
		msg := fmt.Sprintf("%s holds %d seal(s) beyond the source's last seal %d (%d..%d)", name, len(extra), lastSeq, extra[0], extra[len(extra)-1])
		if linked > 0 {
			msg += fmt.Sprintf("; %d of them continue the source's seal chain, so the source was rolled back to seal %d", linked, lastSeq)
		}
		r.add(Finding{Severity: Error, Layer: LayerSink, Code: CodeSinkExtra, SealSeq: extra[0], Message: msg})
	}
}

func (v *Verifier) verifySignature(ctx context.Context, r *Report, s *parsedSeal) {
	if v.sigVerifier == nil {
		return
	}
	if s.doc.KeyID == "" {
		r.add(Finding{Severity: Error, Layer: LayerSeal, Code: CodeSealUnsigned, SealSeq: s.Seq, Message: "seal is not signed but a signature verifier is configured"})
		return
	}
	data, err := s.doc.SigningBytes()
	if err == nil {
		err = v.sigVerifier.Verify(ctx, s.doc.KeyID, data, s.doc.Signature)
	}
	if err != nil {
		r.add(Finding{Severity: Error, Layer: LayerSeal, Code: CodeSealSignature, SealSeq: s.Seq, Message: fmt.Sprintf("signature by %s: %v", s.doc.KeyID, err)})
	}
}

func (v *Verifier) verifyProofs(ctx context.Context, src Source, r *Report, s *parsedSeal) {
	proofs, err := src.Proofs(ctx, s.Seq)
	if err != nil {
		r.add(Finding{Severity: Error, Layer: LayerAnchor, Code: CodeSourceError, SealSeq: s.Seq, Message: "reading proofs: " + err.Error()})
		return
	}
	var valid, qualified int
	for _, p := range proofs {
		prov, ok := v.anchors[p.Provider]
		if !ok {
			r.add(Finding{Severity: Warning, Layer: LayerAnchor, Code: CodeProofUnknown, SealSeq: s.Seq, Message: fmt.Sprintf("proof from %q cannot be verified: no verifier configured", p.Provider)})
			continue
		}
		att, err := prov.Verify(ctx, s.Hash, p.Bytes)
		if err != nil {
			r.add(Finding{Severity: Error, Layer: LayerAnchor, Code: CodeProofInvalid, SealSeq: s.Seq, Message: fmt.Sprintf("%s proof: %v", p.Provider, err)})
			continue
		}
		if att.Time.Before(s.SealedAt.Add(-v.anchorSkew)) {
			r.add(Finding{Severity: Error, Layer: LayerAnchor, Code: CodeProofTime, SealSeq: s.Seq, Message: fmt.Sprintf("%s attests %s, before the seal time %s", p.Provider, att.Time.Format(time.RFC3339), s.SealedAt.Format(time.RFC3339))})
			continue
		}
		if v.maxAnchorDelay > 0 && att.Time.After(s.SealedAt.Add(v.maxAnchorDelay)) {
			r.add(Finding{Severity: Warning, Layer: LayerAnchor, Code: CodeProofDelay, SealSeq: s.Seq, Message: fmt.Sprintf("%s attests %s, %s after the seal time; the proof bounds existence by then, not the seal time itself", p.Provider, att.Time.Format(time.RFC3339), att.Time.Sub(s.SealedAt).Round(time.Minute))})
		}
		valid++
		if att.Qualified {
			qualified++
		}
		r.add(Finding{Severity: Info, Layer: LayerAnchor, Code: "proof_ok", SealSeq: s.Seq, Message: fmt.Sprintf("%s by %s at %s (qualified=%v)", p.Provider, att.Authority, att.Time.Format(time.RFC3339), att.Qualified)})
	}
	switch {
	case valid > 0:
		r.Seals.Anchored++
		if qualified > 0 {
			r.Seals.Qualified++
		} else if v.requireQualified {
			r.add(Finding{Severity: Warning, Layer: LayerAnchor, Code: CodeProofUnqualified, SealSeq: s.Seq, Message: "no proof from a qualified authority"})
		}
	case len(v.anchors) == 0:
		// Nothing configured: nothing expected.
	case v.anchorGrace > 0 && v.now().Sub(s.SealedAt) > v.anchorGrace:
		r.add(Finding{Severity: Error, Layer: LayerAnchor, Code: CodeProofMissing, SealSeq: s.Seq, Message: fmt.Sprintf("no valid proof %s after sealing", v.now().Sub(s.SealedAt).Round(time.Minute))})
	default:
		r.add(Finding{Severity: Warning, Layer: LayerAnchor, Code: CodeProofMissing, SealSeq: s.Seq, Message: "not yet anchored"})
	}
}

func (v *Verifier) verifySinks(ctx context.Context, src Source, r *Report, s *parsedSeal) {
	if len(v.sinks) == 0 {
		return
	}
	proofs, _ := src.Proofs(ctx, s.Seq)
	for _, sink := range v.sinks {
		name := fmt.Sprintf("%T", sink)
		got, err := sink.Get(ctx, seal.Key(s.Seq))
		switch {
		case errors.Is(err, seal.ErrNotFound):
			r.add(Finding{Severity: Warning, Layer: LayerSink, Code: CodeSinkMissing, SealSeq: s.Seq, Message: fmt.Sprintf("%s lacks %s", name, seal.Key(s.Seq))})
		case err != nil:
			r.add(Finding{Severity: Error, Layer: LayerSink, Code: CodeSinkError, SealSeq: s.Seq, Message: fmt.Sprintf("%s: %v", name, err)})
		case !bytes.Equal(got, s.Bytes):
			r.add(Finding{Severity: Error, Layer: LayerSink, Code: CodeSinkMismatch, SealSeq: s.Seq, Message: fmt.Sprintf("%s holds different bytes for %s", name, seal.Key(s.Seq))})
		}
		for _, p := range proofs {
			k := seal.ProofKey(s.Seq, p.Provider)
			got, err := sink.Get(ctx, k)
			switch {
			case errors.Is(err, seal.ErrNotFound):
				r.add(Finding{Severity: Warning, Layer: LayerSink, Code: CodeSinkMissing, SealSeq: s.Seq, Message: fmt.Sprintf("%s lacks %s", name, k)})
			case err != nil:
				r.add(Finding{Severity: Error, Layer: LayerSink, Code: CodeSinkError, SealSeq: s.Seq, Message: fmt.Sprintf("%s: %v", name, err)})
			case !bytes.Equal(got, p.Bytes):
				r.add(Finding{Severity: Error, Layer: LayerSink, Code: CodeSinkMismatch, SealSeq: s.Seq, Message: fmt.Sprintf("%s holds different bytes for %s", name, k)})
			}
		}
	}
}

// verifyStreams walks every stream against the sealed heads and drops.
func (v *Verifier) verifyStreams(ctx context.Context, src Source, r *Report, seals []parsedSeal, sealedDrops map[string]int64, checkpoints map[string]Checkpoint) {
	heads, err := src.Heads(ctx)
	if err != nil {
		r.add(Finding{Severity: Error, Layer: LayerChain, Code: CodeSourceError, Message: "reading heads: " + err.Error()})
		return
	}
	firsts, err := src.FirstSeqs(ctx)
	if err != nil {
		r.add(Finding{Severity: Error, Layer: LayerChain, Code: CodeSourceError, Message: "reading first seqs: " + err.Error()})
		return
	}
	// Sealed heads per stream per sequence, and the latest sealed state.
	sealedAt := map[string]map[int64][]byte{} // stream -> seq -> hash
	latest := map[string]seal.StreamHead{}
	for _, s := range seals {
		if s.doc == nil {
			continue
		}
		for _, h := range s.doc.Streams {
			if sealedAt[h.Stream] == nil {
				sealedAt[h.Stream] = map[int64][]byte{}
			}
			sealedAt[h.Stream][h.HeadSeq] = h.HeadHash
			latest[h.Stream] = h
		}
	}
	// Drop events from the system stream, by stream.
	dropEvents := v.loadDrops(ctx, src, r, heads, firsts, sealedDrops)

	names := slices.Sorted(maps.Keys(heads))
	for name := range latest {
		if _, ok := heads[name]; !ok {
			r.add(Finding{Severity: Error, Layer: LayerChain, Code: CodeStreamMissing, Stream: name, Message: fmt.Sprintf("stream sealed at head %d no longer exists", latest[name].HeadSeq)})
			r.Streams[name] = StreamReport{Stream: name, SealedHead: latest[name].HeadSeq, Gaps: []Gap{}}
		}
	}
	for _, name := range names {
		r.Streams[name] = v.verifyStream(ctx, src, r, name, heads[name], firsts[name], latest[name], sealedAt[name], dropEvents[name], checkpoints[name])
	}
}

// drop is a parsed drop event and whether a seal lists its digest.
type drop struct {
	tamperlog.Drop
	sealed bool
}

// loadDrops reads every drop event in the system stream and marks each as
// sealed or pending. Only sealed drops authorise a gap; a pending drop (newer
// than the last seal) leaves its gap unverified with a warning until the next
// seal lists it.
func (v *Verifier) loadDrops(ctx context.Context, src Source, r *Report, heads map[string]tamperlog.Head, firsts map[string]int64, sealedDrops map[string]int64) map[string][]drop {
	out := map[string][]drop{}
	h, ok := heads[v.systemStream]
	if !ok {
		return out
	}
	hasher, err := tamperlog.LookupHasher(h.Hasher)
	if err != nil {
		return out // reported by the stream walk
	}
	for lo := firsts[v.systemStream]; lo <= h.Seq; lo += v.page {
		recs, err := src.Range(ctx, v.systemStream, lo, min(lo+v.page-1, h.Seq))
		if err != nil {
			r.add(Finding{Severity: Error, Layer: LayerChain, Code: CodeSourceError, Stream: v.systemStream, Message: "reading drop events: " + err.Error()})
			return out
		}
		for _, rec := range recs {
			d, isDrop, err := tamperlog.ParseDrop(hasher, rec)
			if !isDrop {
				continue
			}
			if err != nil {
				r.add(Finding{Severity: Error, Layer: LayerChain, Code: CodeChainDrop, Stream: v.systemStream, Seq: rec.Seq, Message: err.Error()})
				continue
			}
			_, sealed := sealedDrops[hex.EncodeToString(d.Digest)]
			if !sealed {
				r.add(Finding{Severity: Warning, Layer: LayerChain, Code: CodeChainDrop, Stream: d.Stream, Seq: rec.Seq, Message: fmt.Sprintf("drop of %d..%d is recorded but not yet sealed", d.FirstSeq, d.LastSeq)})
			}
			out[d.Stream] = append(out[d.Stream], drop{Drop: d, sealed: sealed})
		}
	}
	return out
}

// verifyStream walks one stream.
func (v *Verifier) verifyStream(ctx context.Context, src Source, r *Report, name string, head tamperlog.Head, first int64, sealed seal.StreamHead, sealedHeads map[int64][]byte, drops []drop, cp Checkpoint) (sr StreamReport) {
	sr = StreamReport{Stream: name, Encoder: head.Encoder, Hasher: head.Hasher, FirstKeptSeq: first, HeadSeq: head.Seq, HeadHash: hex.EncodeToString(head.Hash), SealedHead: sealed.HeadSeq, Gaps: []Gap{}}
	errs := len(r.Errors())
	defer func() { sr.Verified = len(r.Errors()) == errs }()
	fail := func(code string, seq int64, msg string) {
		r.add(Finding{Severity: Error, Layer: LayerChain, Code: code, Stream: name, Seq: seq, Message: msg})
	}
	if sealed.HeadSeq == 0 {
		r.add(Finding{Severity: Info, Layer: LayerChain, Code: CodeStreamNotSealed, Stream: name, Message: "stream has never been sealed"})
	} else {
		if head.Seq < sealed.HeadSeq {
			fail(CodeStreamTruncated, head.Seq, fmt.Sprintf("live head %d is behind the sealed head %d", head.Seq, sealed.HeadSeq))
		}
		if head.Encoder != sealed.Encoder || head.Hasher != sealed.Hasher {
			fail(CodeStreamAlgorithm, head.Seq, fmt.Sprintf("live stream uses %s/%s, seal says %s/%s", head.Encoder, head.Hasher, sealed.Encoder, sealed.Hasher))
		}
		if first < sealed.FirstKeptSeq {
			r.add(Finding{Severity: Warning, Layer: LayerChain, Code: CodeChainFirstKept, Stream: name, Seq: first, Message: fmt.Sprintf("first kept seq %d is before the sealed %d: records reappeared", first, sealed.FirstKeptSeq)})
		}
		sr.Unsealed = max(0, head.Seq-sealed.HeadSeq)
		if sr.Unsealed > 0 {
			r.add(Finding{Severity: Info, Layer: LayerChain, Code: CodeChainUnsealed, Stream: name, Seq: head.Seq, Message: fmt.Sprintf("%d records after the last sealed head %d are not yet sealed", sr.Unsealed, sealed.HeadSeq)})
		}
	}
	enc, ok := v.encoders[head.Encoder]
	hasher, err := tamperlog.LookupHasher(head.Hasher)
	if !ok || err != nil {
		fail(CodeStreamUnknown, head.Seq, fmt.Sprintf("cannot verify %s/%s: unknown encoder or hasher", head.Encoder, head.Hasher))
		return sr
	}
	chain := tamperlog.Chain{Encoder: enc, Hasher: hasher}

	// Where to start: the first kept record, or the checkpoint record so the
	// boundary link is re-verified.
	start := first
	if cp.Seq >= first && cp.Seq <= head.Seq {
		start = cp.Seq
	}
	leadingGap := start == first && first > 1
	var prevRec *tamperlog.Record
	for lo := start; lo <= head.Seq; {
		hi := min(lo+v.page-1, head.Seq)
		recs, err := src.Range(ctx, name, lo, hi)
		if err != nil {
			fail(CodeSourceError, lo, "reading records: "+err.Error())
			return sr
		}
		if len(recs) == 0 {
			if hi >= head.Seq {
				fail(CodeChainGap, lo, fmt.Sprintf("records %d..%d are missing and the head is %d", lo, head.Seq, head.Seq))
				return sr
			}
			lo = hi + 1
			continue
		}
		if leadingGap {
			// Records 1..first-1 were dropped: the drop events must chain
			// from genesis to the first kept record.
			v.bridge(r, &sr, name, chain, nil, true, 1, first-1, &recs[0], drops)
			leadingGap = false
		}
		if prevRec != nil && recs[0].Seq != prevRec.Seq+1 {
			v.bridge(r, &sr, name, chain, prevRec, false, prevRec.Seq+1, recs[0].Seq-1, &recs[0], drops)
		} else if prevRec == nil && recs[0].Seq != start {
			fail(CodeChainGap, start, fmt.Sprintf("records %d..%d are missing", start, recs[0].Seq-1))
			return sr
		}
		if cp.Seq > 0 && prevRec == nil && recs[0].Seq == cp.Seq && !bytes.Equal(recs[0].Hash, cp.Hash) {
			fail(CodeChainBroken, cp.Seq, "record at the checkpoint has a different hash than when it was last verified")
		}
		// Walk this page, including the boundary link to prevRec; inner gaps
		// split the walk and must be bridged.
		page := recs
		if prevRec != nil && recs[0].Seq == prevRec.Seq+1 {
			page = append([]tamperlog.Record{*prevRec}, recs...)
		}
		segStart := 0
		for i := 1; i <= len(page); i++ {
			if i < len(page) && page[i].Seq == page[i-1].Seq+1 {
				continue
			}
			seg := page[segStart:i]
			if err := chain.Walk(name, seg[0].Seq, seg, tamperlog.WalkOptions{TimeTolerance: v.timeTol}); err != nil {
				var broken *tamperlog.BrokenChainError
				if errors.As(err, &broken) {
					fail(CodeChainBroken, broken.Seq, string(broken.Reason)+ifDetail(broken.Detail))
				} else {
					fail(CodeChainBroken, seg[0].Seq, err.Error())
				}
				return sr
			}
			if i < len(page) {
				v.bridge(r, &sr, name, chain, &page[i-1], false, page[i-1].Seq+1, page[i].Seq-1, &page[i], drops)
			}
			segStart = i
		}
		for i := range recs {
			if want, ok := sealedHeads[recs[i].Seq]; ok && !bytes.Equal(want, recs[i].Hash) {
				fail(CodeChainHead, recs[i].Seq, "record hash differs from the hash sealed for this sequence number")
			}
			sr.Records++
		}
		last := recs[len(recs)-1]
		prevRec = &last
		sr.VerifiedUpTo = last.Seq
		lo = last.Seq + 1
	}
	// Sealed heads before the start of an incremental walk are read one by
	// one: a rewrite before the checkpoint that stops short of it would
	// otherwise go unnoticed until the next full run.
	for seq, want := range sealedHeads {
		if seq >= start || seq < first {
			continue
		}
		recs, err := src.Range(ctx, name, seq, seq)
		switch {
		case err != nil:
			fail(CodeSourceError, seq, "reading sealed head: "+err.Error())
		case len(recs) == 0:
			fail(CodeChainHead, seq, "record sealed at this sequence number is missing")
		case !bytes.Equal(recs[0].Hash, want):
			fail(CodeChainHead, seq, "record hash differs from the hash sealed for this sequence number")
		default:
			if got, err := chain.Link(recs[0]); err != nil || !bytes.Equal(got, want) {
				fail(CodeChainHead, seq, "record content no longer hashes to the sealed hash")
			}
		}
	}
	if prevRec == nil {
		fail(CodeChainGap, first, "no records could be read")
		return sr
	}
	if !bytes.Equal(prevRec.Hash, head.Hash) || prevRec.Seq != head.Seq {
		fail(CodeChainBroken, head.Seq, fmt.Sprintf("last record read is %d, head reports %d", prevRec.Seq, head.Seq))
	}
	return sr
}

func ifDetail(d string) string {
	if d == "" {
		return ""
	}
	return " (" + d + ")"
}

// bridge checks that the gap first..last between before (nil at the start
// of a stream) and after is covered by sealed drop events whose edge hashes
// chain from before's hash (or genesis) to after's prev_hash. Gaps not at the
// start of the stream are errors unless WithAllowInnerGaps is set. Pending
// (unsealed) drops leave the gap unverified with a warning.
func (v *Verifier) bridge(r *Report, sr *StreamReport, name string, chain tamperlog.Chain, before *tamperlog.Record, atGenesis bool, first, last int64, after *tamperlog.Record, drops []drop) {
	gap := Gap{First: first, Last: last}
	defer func() { sr.Gaps = append(sr.Gaps, gap) }()
	if !atGenesis && !v.allowInnerGaps {
		r.add(Finding{Severity: Error, Layer: LayerChain, Code: CodeChainInnerGap, Stream: name, Seq: first, Message: fmt.Sprintf("records %d..%d are missing from the middle of the stream; retention only drops from the start", first, last)})
		return
	}
	var running []byte
	switch {
	case before != nil:
		running = before.Hash
	default:
		running = chain.Genesis()
	}
	seq := first
	pending := false
	for seq <= last {
		var found *drop
		for i := range drops {
			d := &drops[i]
			if d.FirstSeq == seq && bytes.Equal(d.FirstPrevHash, running) {
				found = d
				break
			}
		}
		if found == nil {
			r.add(Finding{Severity: Error, Layer: LayerChain, Code: CodeChainGap, Stream: name, Seq: seq, Message: fmt.Sprintf("records %d..%d are missing and no drop event starts at %d with the expected edge hash", seq, last, seq)})
			return
		}
		if !found.sealed {
			pending = true
		}
		running = found.LastHash
		seq = found.LastSeq + 1
	}
	if seq != last+1 {
		r.add(Finding{Severity: Error, Layer: LayerChain, Code: CodeChainGap, Stream: name, Seq: last, Message: fmt.Sprintf("drop events overshoot the gap %d..%d", first, last)})
		return
	}
	if !bytes.Equal(after.PrevHash, running) {
		r.add(Finding{Severity: Error, Layer: LayerChain, Code: CodeChainGap, Stream: name, Seq: after.Seq, Message: fmt.Sprintf("record %d does not link to the last dropped record's hash", after.Seq)})
		return
	}
	if pending {
		r.add(Finding{Severity: Warning, Layer: LayerChain, Code: CodeChainGapPending, Stream: name, Seq: first, Message: fmt.Sprintf("gap %d..%d is bridged by drop events that no seal lists yet", first, last)})
		return
	}
	gap.Bridged = true
}
