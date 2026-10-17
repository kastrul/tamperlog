package anchor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/kastrul/tamperlog"
	"github.com/kastrul/tamperlog/seal"
)

// FailedAction is the action of the system-stream event the runner appends
// when a seal stays unanchored past the grace period.
const FailedAction = "anchor.failed"

// RunnerOption configures a [Runner].
type RunnerOption func(*Runner)

// WithGrace sets how long a seal may stay unanchored before an anchor.failed
// event is recorded (default 4 h, the X-Road acceptable failure period).
func WithGrace(d time.Duration) RunnerOption { return func(r *Runner) { r.grace = d } }

// WithBackoff sets the retry delay bounds (default 30 s to 15 min, doubling
// with jitter).
func WithBackoff(minDelay, maxDelay time.Duration) RunnerOption {
	return func(r *Runner) { r.minDelay, r.maxDelay = minDelay, maxDelay }
}

// WithBatch sets how many unanchored seals one pass handles (default 50).
func WithBatch(n int) RunnerOption { return func(r *Runner) { r.batch = n } }

// WithSinks adds sinks that receive every proof under [seal.ProofKey].
func WithSinks(s ...seal.Sink) RunnerOption {
	return func(r *Runner) { r.sinks = append(r.sinks, s...) }
}

// WithLog sets the log used to record anchor.failed events. Without it the
// failure is only logged and reported through hooks.
func WithLog(l *tamperlog.Log) RunnerOption { return func(r *Runner) { r.log = l } }

// WithLogger sets the logger; by default nothing is logged.
func WithLogger(l *slog.Logger) RunnerOption { return func(r *Runner) { r.logger = l } }

// WithClock replaces the clock (default time.Now).
func WithClock(now func() time.Time) RunnerOption { return func(r *Runner) { r.now = now } }

// WithRunnerHooks installs callbacks.
func WithRunnerHooks(h RunnerHooks) RunnerOption { return func(r *Runner) { r.hooks = h } }

// RunnerHooks are callbacks invoked by the runner.
type RunnerHooks struct {
	// OnAnchored receives every proof after it is stored.
	OnAnchored func(ctx context.Context, p seal.Proof, a Attestation)
	// OnAnchorFailed is called once per seal when the grace period passes
	// without a proof. It fires again on later passes while the seal stays
	// unanchored only if the recorded event could not be written.
	OnAnchorFailed func(ctx context.Context, s seal.Stored, err error)
}

// Runner anchors seals that lack a proof from its provider.
type Runner struct {
	store    seal.Store
	provider Provider
	sinks    []seal.Sink
	log      *tamperlog.Log
	logger   *slog.Logger
	now      func() time.Time
	hooks    RunnerHooks
	grace    time.Duration
	minDelay time.Duration
	maxDelay time.Duration
	batch    int

	failed map[int64]bool // seals whose failure was recorded this process
}

// NewRunner returns a Runner anchoring seals in store with provider.
func NewRunner(store seal.Store, provider Provider, opts ...RunnerOption) *Runner {
	r := &Runner{
		store:    store,
		provider: provider,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:      time.Now,
		grace:    4 * time.Hour,
		minDelay: 30 * time.Second,
		maxDelay: 15 * time.Minute,
		batch:    50,
		failed:   map[int64]bool{},
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Once anchors up to one batch of unanchored seals, oldest first, and returns
// how many proofs it stored. A provider error stops the pass (the next pass
// retries) and is returned; seals past the grace period have their failure
// recorded first.
func (r *Runner) Once(ctx context.Context) (int, error) {
	seals, err := r.store.Unanchored(ctx, r.provider.ID(), r.batch)
	if err != nil {
		return 0, fmt.Errorf("anchor: unanchored seals: %w", err)
	}
	var n int
	for _, s := range seals {
		if err := r.anchorOne(ctx, s); err != nil {
			if age := r.now().Sub(s.SealedAt); age > r.grace && !r.failed[s.Seq] {
				r.recordFailure(ctx, s, err)
			}
			return n, err
		}
		n++
	}
	return n, nil
}

func (r *Runner) anchorOne(ctx context.Context, s seal.Stored) error {
	proof, err := r.provider.Anchor(ctx, s.Hash)
	if err != nil {
		r.logger.WarnContext(ctx, "tamperlog anchor failed", "seal", s.Seq, "provider", r.provider.ID(), "err", err)
		return fmt.Errorf("anchor: seal %d via %s: %w", s.Seq, r.provider.ID(), err)
	}
	att, err := r.provider.Verify(ctx, s.Hash, proof)
	if err != nil {
		return fmt.Errorf("anchor: seal %d: fresh proof does not verify: %w", s.Seq, err)
	}
	p := seal.Proof{SealSeq: s.Seq, Provider: r.provider.ID(), ObtainedAt: r.now().UTC().Truncate(time.Microsecond), Bytes: proof}
	if err := r.store.PutProof(ctx, p); err != nil {
		return fmt.Errorf("anchor: store proof for seal %d: %w", s.Seq, err)
	}
	r.logger.InfoContext(ctx, "tamperlog seal anchored", "seal", s.Seq, "provider", r.provider.ID(), "at", att.Time, "authority", att.Authority, "qualified", att.Qualified)
	for _, sink := range r.sinks {
		if err := sink.Put(ctx, seal.ProofKey(s.Seq, p.Provider), proof); err != nil && !errors.Is(err, seal.ErrExists) {
			r.logger.ErrorContext(ctx, "tamperlog proof sink put failed", "seal", s.Seq, "err", err)
		}
	}
	if r.hooks.OnAnchored != nil {
		r.hooks.OnAnchored(ctx, p, att)
	}
	return nil
}

// recordFailure appends an anchor.failed event to the system stream, so the
// gap is itself sealed, and fires the hook.
func (r *Runner) recordFailure(ctx context.Context, s seal.Stored, cause error) {
	r.logger.ErrorContext(ctx, "tamperlog seal unanchored past grace", "seal", s.Seq, "provider", r.provider.ID(), "grace", r.grace, "err", cause)
	if r.hooks.OnAnchorFailed != nil {
		r.hooks.OnAnchorFailed(ctx, s, cause)
	}
	if r.log == nil {
		r.failed[s.Seq] = true
		return
	}
	_, err := r.log.Append(ctx, tamperlog.Event{
		Stream:      r.log.Appender().SystemStream(),
		Action:      FailedAction,
		Entity:      "seal",
		EntityID:    fmt.Sprint(s.Seq),
		PayloadHash: padTo(s.Hash, r.log.Appender().Chain().Hasher.Size()),
		Attributes: map[string]string{
			"provider": r.provider.ID(),
			"grace":    r.grace.String(),
		},
	})
	if err != nil {
		r.logger.ErrorContext(ctx, "tamperlog could not record anchor failure", "seal", s.Seq, "err", err)
		return
	}
	r.failed[s.Seq] = true
}

// padTo returns h when it already has size n, else nil (the event then
// carries the seal sequence number but no commitment).
func padTo(h []byte, n int) []byte {
	if len(h) == n {
		return h
	}
	return nil
}

// Run anchors continuously until ctx ends: it runs Once, then sleeps
// minDelay while work remains or succeeded and backs off exponentially with
// jitter up to maxDelay after an error. It returns ctx.Err().
func (r *Runner) Run(ctx context.Context) error {
	delay := r.minDelay
	for {
		n, err := r.Once(ctx)
		switch {
		case err != nil:
			delay = min(delay*2, r.maxDelay)
		default:
			delay = r.minDelay
			if n == r.batch {
				delay = 0 // more to do
			}
		}
		jitter := time.Duration(rand.Int64N(int64(delay)/10 + 1)) //nolint:gosec // jitter, not security
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay + jitter):
		}
	}
}
