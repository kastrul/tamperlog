package anchor_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kastrul/tamperlog"
	"github.com/kastrul/tamperlog/anchor"
	"github.com/kastrul/tamperlog/seal"
	"github.com/kastrul/tamperlog/seal/sinks/fs"
	"github.com/kastrul/tamperlog/store/memory"
)

// fakeProvider returns the digest reversed as its proof and fails on demand.
type fakeProvider struct {
	fail  error
	calls int
}

func (f *fakeProvider) ID() string { return "fake" }

func (f *fakeProvider) Anchor(_ context.Context, digest []byte) ([]byte, error) {
	f.calls++
	if f.fail != nil {
		return nil, f.fail
	}
	out := make([]byte, len(digest))
	for i, b := range digest {
		out[len(digest)-1-i] = b
	}
	return out, nil
}

func (f *fakeProvider) Verify(_ context.Context, digest, proof []byte) (anchor.Attestation, error) {
	want, _ := f.Anchor(context.Background(), digest)
	f.calls--
	if !bytes.Equal(want, proof) {
		return anchor.Attestation{}, anchor.ErrInvalidProof
	}
	return anchor.Attestation{Time: time.Unix(0, 0), Authority: "fake"}, nil
}

func TestRunnerAnchorsUnanchoredSeals(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := memory.New()
	w := seal.NewWriter(s)
	for range 3 {
		if _, err := w.Seal(ctx); err != nil {
			t.Fatal(err)
		}
	}
	sink, _ := fs.New(t.TempDir())
	fp := &fakeProvider{}
	var anchored []int64
	r := anchor.NewRunner(s, fp, anchor.WithSinks(sink), anchor.WithRunnerHooks(anchor.RunnerHooks{
		OnAnchored: func(_ context.Context, p seal.Proof, a anchor.Attestation) {
			if a.Authority != "fake" {
				t.Errorf("attestation = %+v", a)
			}
			anchored = append(anchored, p.SealSeq)
		},
	}))
	n, err := r.Once(ctx)
	if err != nil || n != 3 {
		t.Fatalf("Once = %d, %v", n, err)
	}
	if len(anchored) != 3 || anchored[0] != 1 || anchored[2] != 3 {
		t.Fatalf("anchored %v", anchored)
	}
	proofs, _ := s.Proofs(ctx, 2)
	if len(proofs) != 1 || proofs[0].Provider != "fake" {
		t.Fatalf("proofs = %+v", proofs)
	}
	if got, err := sink.Get(ctx, seal.ProofKey(2, "fake")); err != nil || !bytes.Equal(got, proofs[0].Bytes) {
		t.Fatalf("proof in sink: %v", err)
	}
	n, err = r.Once(ctx)
	if err != nil || n != 0 {
		t.Fatalf("second Once = %d, %v", n, err)
	}
	if fp.calls != 3 {
		t.Fatalf("provider called %d times", fp.calls)
	}
}

func TestRunnerRecordsFailurePastGrace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 10, 17, 14, 0, 0, 0, time.UTC)
	s := memory.New(memory.WithClock(func() time.Time { return now }))
	log := tamperlog.NewLog(s)
	w := seal.NewWriter(s, seal.WithClock(func() time.Time { return now }))
	st, err := w.Seal(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fp := &fakeProvider{fail: errors.New("tsa down")}
	var failed []int64
	r := anchor.NewRunner(s, fp, anchor.WithGrace(time.Hour), anchor.WithLog(log), anchor.WithClock(func() time.Time { return now }),
		anchor.WithRunnerHooks(anchor.RunnerHooks{OnAnchorFailed: func(_ context.Context, s seal.Stored, _ error) { failed = append(failed, s.Seq) }}))

	// Inside the grace period: error, no event.
	now = now.Add(30 * time.Minute)
	if _, err := r.Once(ctx); err == nil {
		t.Fatal("expected provider error")
	}
	if len(failed) != 0 || len(s.Records(tamperlog.SystemStream)) != 0 {
		t.Fatal("failure recorded inside grace")
	}
	// Past the grace period: one anchor.failed event, once.
	now = now.Add(time.Hour)
	for range 2 {
		if _, err := r.Once(ctx); err == nil {
			t.Fatal("expected provider error")
		}
	}
	recs := s.Records(tamperlog.SystemStream)
	if len(failed) != 1 || len(recs) != 1 || recs[0].Action != anchor.FailedAction || recs[0].EntityID != "1" || !bytes.Equal(recs[0].PayloadHash, st.Hash) || recs[0].Attributes["provider"] != "fake" {
		t.Fatalf("failed = %v, records = %+v", failed, recs)
	}
	// Recovery anchors the seal; the failure event stays in the chain.
	fp.fail = nil
	if n, err := r.Once(ctx); err != nil || n != 1 {
		t.Fatalf("after recovery: %d, %v", n, err)
	}
}

func TestRunnerRejectsUnverifiableProof(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := memory.New()
	if _, err := seal.NewWriter(s).Seal(ctx); err != nil {
		t.Fatal(err)
	}
	r := anchor.NewRunner(s, badProvider{})
	if _, err := r.Once(ctx); !errors.Is(err, anchor.ErrInvalidProof) {
		t.Fatalf("Once = %v", err)
	}
	if proofs, _ := s.Proofs(ctx, 1); len(proofs) != 0 {
		t.Fatal("unverifiable proof stored")
	}
}

type badProvider struct{}

func (badProvider) ID() string                                     { return "bad" }
func (badProvider) Anchor(context.Context, []byte) ([]byte, error) { return []byte("junk"), nil }
func (badProvider) Verify(context.Context, []byte, []byte) (anchor.Attestation, error) {
	return anchor.Attestation{}, anchor.ErrInvalidProof
}

func TestRunnerRunStopsWithContext(t *testing.T) {
	t.Parallel()
	s := memory.New()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	r := anchor.NewRunner(s, &fakeProvider{}, anchor.WithBackoff(10*time.Millisecond, 50*time.Millisecond))
	if err := r.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}
