package verify

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/kastrul/tamperlog"
)

// Actions of the system-stream events a [Runner] records.
const (
	VerifiedAction = "chain.verified"
	BrokenAction   = "chain.broken"
)

// RunnerOption configures a [Runner].
type RunnerOption func(*Runner)

// WithLog records chain.verified and chain.broken events through l. The
// payload hash commits to the heads that were verified ([Report.HeadsDigest]).
func WithLog(l *tamperlog.Log) RunnerOption { return func(r *Runner) { r.log = l } }

// WithOnReport installs a callback invoked with every report.
func WithOnReport(fn func(ctx context.Context, rep *Report)) RunnerOption {
	return func(r *Runner) { r.onReport = fn }
}

// WithIncremental keeps per-stream checkpoints between runs so each run
// re-links only the records after the checkpoint. Every seal, every sealed
// head (re-hashed) and the checkpoint record are still checked, but an edit of
// a non-head record before the checkpoint that keeps its stored hash is not
// seen until the next full walk; fullEvery (default 24 h) forces one. A
// broken run also resets the checkpoints.
func WithIncremental(fullEvery time.Duration) RunnerOption {
	return func(r *Runner) {
		r.incremental = true
		if fullEvery > 0 {
			r.fullEvery = fullEvery
		}
	}
}

// Runner verifies on an interval. Runs are serialised: a second Once waits
// for the first.
type Runner struct {
	v           *Verifier
	src         Source
	log         *tamperlog.Log
	onReport    func(ctx context.Context, rep *Report)
	incremental bool
	fullEvery   time.Duration

	mu          sync.Mutex // held for the whole of Once
	checkpoints map[string]Checkpoint
	lastFull    time.Time
}

// NewRunner returns a Runner verifying src with v.
func NewRunner(v *Verifier, src Source, opts ...RunnerOption) *Runner {
	r := &Runner{v: v, src: src, checkpoints: map[string]Checkpoint{}, fullEvery: 24 * time.Hour}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Once verifies once, records the outcome and returns the report.
func (r *Runner) Once(ctx context.Context) *Report {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.v.now()
	var cps map[string]Checkpoint
	full := !r.incremental || r.lastFull.IsZero() || now.Sub(r.lastFull) >= r.fullEvery
	if !full {
		cps = make(map[string]Checkpoint, len(r.checkpoints))
		for k, v := range r.checkpoints {
			cps[k] = Checkpoint{Seq: v.Seq, Hash: append([]byte(nil), v.Hash...)}
		}
	}

	rep := r.v.Verify(ctx, r.src, cps)
	rep.Full = full

	if rep.OK() && r.incremental {
		if full {
			r.lastFull = now
		}
		for name, s := range rep.Streams {
			if s.VerifiedUpTo > 0 {
				r.checkpoints[name] = Checkpoint{Seq: s.VerifiedUpTo, Hash: mustHex(s.HeadHash)}
			}
		}
	} else {
		r.checkpoints = map[string]Checkpoint{}
		r.lastFull = time.Time{}
	}

	if r.log != nil {
		r.record(ctx, rep)
	}
	if r.onReport != nil {
		r.onReport(ctx, rep)
	}
	return rep
}

func (r *Runner) record(ctx context.Context, rep *Report) {
	ev := tamperlog.Event{
		Stream:      r.log.Appender().SystemStream(),
		Action:      VerifiedAction,
		Entity:      "chain",
		PayloadHash: fit(rep.HeadsDigest(), r.log.Appender().Chain().Hasher.Size()),
		Attributes: map[string]string{
			"streams": strconv.Itoa(len(rep.Streams)),
			"seals":   strconv.FormatInt(rep.Seals.Count, 10),
		},
	}
	if errs := rep.Errors(); len(errs) > 0 {
		ev.Action = BrokenAction
		ev.Attributes["errors"] = strconv.Itoa(len(errs))
		ev.Attributes["first_code"] = errs[0].Code
		if errs[0].Stream != "" {
			ev.Attributes["first_stream"] = errs[0].Stream
		}
		if errs[0].Seq != 0 {
			ev.Attributes["first_seq"] = strconv.FormatInt(errs[0].Seq, 10)
		}
	}
	if _, err := r.log.Append(ctx, ev); err != nil {
		r.v.logger.ErrorContext(ctx, "tamperlog could not record verification outcome", "err", err)
	}
}

func fit(h []byte, n int) []byte {
	if len(h) == n {
		return h
	}
	return nil
}

func mustHex(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := range b {
		v, err := strconv.ParseUint(s[2*i:2*i+2], 16, 8)
		if err != nil {
			return nil
		}
		b[i] = byte(v)
	}
	return b
}

// Run verifies every interval until ctx ends and returns ctx.Err(). The
// first run starts immediately.
func (r *Runner) Run(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		return fmt.Errorf("verify: interval must be positive")
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		r.Once(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}
