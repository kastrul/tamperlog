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
// re-links only new records (seals and sealed heads are always checked in
// full). A broken run resets the checkpoints so the next run walks
// everything.
func WithIncremental() RunnerOption { return func(r *Runner) { r.incremental = true } }

// Runner verifies on an interval.
type Runner struct {
	v           *Verifier
	src         Source
	log         *tamperlog.Log
	onReport    func(ctx context.Context, rep *Report)
	incremental bool

	mu          sync.Mutex
	checkpoints map[string]Checkpoint
}

// NewRunner returns a Runner verifying src with v.
func NewRunner(v *Verifier, src Source, opts ...RunnerOption) *Runner {
	r := &Runner{v: v, src: src, checkpoints: map[string]Checkpoint{}}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Once verifies once, records the outcome and returns the report.
func (r *Runner) Once(ctx context.Context) *Report {
	r.mu.Lock()
	cps := r.checkpoints
	if !r.incremental {
		cps = nil
	}
	r.mu.Unlock()

	rep := r.v.Verify(ctx, r.src, cps)

	r.mu.Lock()
	if rep.OK() && r.incremental {
		for name, s := range rep.Streams {
			if s.VerifiedUpTo > 0 {
				r.checkpoints[name] = Checkpoint{Seq: s.VerifiedUpTo, Hash: mustHex(s.HeadHash)}
			}
		}
	} else {
		r.checkpoints = map[string]Checkpoint{}
	}
	r.mu.Unlock()

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
