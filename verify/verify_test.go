package verify_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/kastrul/tamperlog"
	"github.com/kastrul/tamperlog/anchor"
	"github.com/kastrul/tamperlog/seal"
	"github.com/kastrul/tamperlog/seal/sinks/fs"
	"github.com/kastrul/tamperlog/sign"
	"github.com/kastrul/tamperlog/store/memory"
	"github.com/kastrul/tamperlog/verify"
)

// fixture is a store with two streams, three seals, a drop and proofs.
type fixture struct {
	store  *memory.Store
	log    *tamperlog.Log
	writer *seal.Writer
	sink   *fs.Sink
	prov   *okProvider
	now    time.Time
	clock  func() time.Time
}

type okProvider struct{ bad bool }

func (okProvider) ID() string { return "ok" }
func (p okProvider) Anchor(_ context.Context, d []byte) ([]byte, error) {
	return append([]byte("proof:"), d...), nil
}

func (p okProvider) Verify(_ context.Context, d, proof []byte) (anchor.Attestation, error) {
	if p.bad || !bytes.Equal(proof, append([]byte("proof:"), d...)) {
		return anchor.Attestation{}, anchor.ErrInvalidProof
	}
	return anchor.Attestation{Time: time.Date(2026, 10, 17, 15, 0, 0, 0, time.UTC), Authority: "test tsa", Qualified: true}, nil
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{now: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC), prov: &okProvider{}}
	f.clock = func() time.Time { f.now = f.now.Add(time.Second); return f.now }
	f.store = memory.New(memory.WithClock(f.clock))
	f.log = tamperlog.NewLog(f.store)
	sink, err := fs.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f.sink = sink
	f.writer = seal.NewWriter(f.store, seal.WithClock(f.clock), seal.WithSinks(sink))
	return f
}

func (f *fixture) append(t *testing.T, stream string, n int) {
	t.Helper()
	for i := range n {
		if _, err := f.log.Append(context.Background(), tamperlog.Event{Stream: stream, Action: "a", Entity: "e", EntityID: fmt.Sprint(i)}); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *fixture) seal(t *testing.T) seal.Stored {
	t.Helper()
	st, err := f.writer.Seal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func (f *fixture) anchorAll(t *testing.T) {
	t.Helper()
	r := anchor.NewRunner(f.store, f.prov, anchor.WithSinks(f.sink), anchor.WithClock(f.clock))
	if _, err := r.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// drop removes first..last of stream after recording the drop event.
func (f *fixture) drop(t *testing.T, stream string, first, last int64) {
	t.Helper()
	recs := f.store.Records(stream)
	var firstPrev, lastHash []byte
	for _, r := range recs {
		if r.Seq == first {
			firstPrev = r.PrevHash
		}
		if r.Seq == last {
			lastHash = r.Hash
		}
	}
	if _, err := f.log.Append(context.Background(), tamperlog.DropEvent(tamperlog.SHA256, tamperlog.SystemStream, stream, first, firstPrev, last, lastHash)); err != nil {
		t.Fatal(err)
	}
	f.store.Drop(stream, first, last)
}

func (f *fixture) verifier(opts ...verify.Option) *verify.Verifier {
	return verify.New(append([]verify.Option{verify.WithAnchors(f.prov), verify.WithSinks(f.sink), verify.WithClock(f.clock), verify.WithPageSize(3)}, opts...)...)
}

func codes(r *verify.Report, sev verify.Severity) map[string]int {
	m := map[string]int{}
	for _, f := range r.Findings {
		if f.Severity == sev {
			m[f.Code]++
		}
	}
	return m
}

func TestHealthyDeploymentVerifies(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.append(t, "audit", 7)
	f.append(t, "auth", 2)
	f.seal(t)
	f.append(t, "audit", 4)
	f.drop(t, "audit", 1, 3)
	f.seal(t)
	f.drop(t, "audit", 4, 5)
	f.seal(t)
	f.anchorAll(t)
	f.append(t, "audit", 1) // unsealed tail

	rep := f.verifier().Verify(context.Background(), verify.FromProvider(f.store), nil)
	if !rep.OK() {
		t.Fatalf("errors: %v", rep.Errors())
	}
	if rep.Seals.Count != 3 || rep.Seals.Anchored != 3 || rep.Seals.Qualified != 3 {
		t.Fatalf("seals = %+v", rep.Seals)
	}
	a := rep.Streams["audit"]
	if a.FirstKeptSeq != 6 || a.HeadSeq != 12 || a.Records != 7 || a.SealedHead != 11 || a.Unsealed != 1 || !a.Verified || len(a.Gaps) != 1 || !a.Gaps[0].Bridged || a.Gaps[0].First != 1 || a.Gaps[0].Last != 5 {
		t.Fatalf("audit = %+v", a)
	}
	if w := codes(rep, verify.Warning); len(w) != 0 {
		t.Fatalf("warnings: %v", w)
	}
	if !bytes.Equal(rep.HeadsDigest(), rep.HeadsDigest()) || len(rep.HeadsDigest()) != 32 {
		t.Fatal("heads digest")
	}
	t.Log(rep.Summary())
}

func TestNoSealsIsAWarning(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.append(t, "audit", 3)
	rep := f.verifier().Verify(context.Background(), verify.FromProvider(f.store), nil)
	if !rep.OK() || codes(rep, verify.Warning)[verify.CodeNoSeals] != 1 {
		t.Fatalf("%v", rep.Findings)
	}
}

func TestDetectsTampering(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cases := map[string]struct {
		mutate func(t *testing.T, f *fixture)
		code   string
		stream string
	}{
		"edited record, hash recomputed": {func(_ *testing.T, f *fixture) {
			recs := f.store.Records("audit")
			recs[2].Actor = "mallory"
			recs[2].Hash, _ = tamperlog.NewChain(nil, nil).Link(recs[2])
			f.store.Replace("audit", recs)
		}, verify.CodeChainBroken, "audit"},
		"edited record, hash kept": {func(_ *testing.T, f *fixture) {
			recs := f.store.Records("audit")
			recs[2].Action = "b"
			f.store.Replace("audit", recs)
		}, verify.CodeChainBroken, "audit"},
		"whole chain recomputed": {func(_ *testing.T, f *fixture) {
			recs := f.store.Records("audit")
			recs[1].Actor = "mallory"
			chain := tamperlog.NewChain(nil, nil)
			prev := chain.Genesis()
			for i := range recs {
				recs[i].PrevHash = prev
				recs[i].Hash, _ = chain.Link(recs[i])
				prev = recs[i].Hash
			}
			f.store.Replace("audit", recs)
		}, verify.CodeChainHead, "audit"},
		"tail deleted": {func(_ *testing.T, f *fixture) {
			f.store.Drop("audit", 5, 5)
		}, verify.CodeStreamTruncated, "audit"},
		"middle deleted without drop event": {func(_ *testing.T, f *fixture) {
			f.store.Drop("audit", 2, 2)
		}, verify.CodeChainInnerGap, "audit"},
		"start deleted without drop event": {func(_ *testing.T, f *fixture) {
			f.store.Drop("audit", 1, 1)
		}, verify.CodeChainGap, "audit"},
		"stream deleted": {func(_ *testing.T, f *fixture) {
			f.store.Replace("auth", nil)
		}, verify.CodeStreamMissing, "auth"},
		"no change": {func(_ *testing.T, f *fixture) {
			f.store.Replace("audit", f.store.Records("audit"))
		}, "", ""},
		"sink copy differs": {func(t *testing.T, f *fixture) {
			dir := t.TempDir()
			other, _ := fs.New(dir)
			_ = other.Put(ctx, seal.Key(1), []byte(`{"forged":true}`))
			f.sink = other
		}, verify.CodeSinkMismatch, ""},
		"proof invalid": {func(_ *testing.T, f *fixture) {
			f.prov.bad = true
		}, verify.CodeProofInvalid, ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			f.append(t, "audit", 5)
			f.append(t, "auth", 1)
			f.seal(t)
			f.anchorAll(t)
			c.mutate(t, f)
			rep := f.verifier().Verify(ctx, verify.FromProvider(f.store), nil)
			if c.code == "" {
				if !rep.OK() {
					t.Fatalf("unexpected errors: %v", rep.Errors())
				}
				return
			}
			if rep.OK() {
				t.Fatalf("tampering not detected: %v", rep.Findings)
			}
			errs := codes(rep, verify.Error)
			if errs[c.code] == 0 {
				t.Fatalf("want %s, got %v", c.code, rep.Errors())
			}
			if c.stream != "" && rep.Streams[c.stream].Verified {
				t.Fatalf("stream %s reported verified", c.stream)
			}
		})
	}
}

func TestUnanchoredSealEscalatesAfterGrace(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.append(t, "audit", 1)
	f.seal(t)
	rep := f.verifier().Verify(context.Background(), verify.FromProvider(f.store), nil)
	if !rep.OK() || codes(rep, verify.Warning)[verify.CodeProofMissing] != 1 {
		t.Fatalf("%v", rep.Findings)
	}
	f.now = f.now.Add(5 * time.Hour)
	rep = f.verifier().Verify(context.Background(), verify.FromProvider(f.store), nil)
	if rep.OK() || codes(rep, verify.Error)[verify.CodeProofMissing] != 1 {
		t.Fatalf("%v", rep.Findings)
	}
	// Without anchors configured nothing is expected.
	rep = verify.New(verify.WithClock(f.clock)).Verify(context.Background(), verify.FromProvider(f.store), nil)
	if !rep.OK() || len(codes(rep, verify.Warning)) != 0 {
		t.Fatalf("%v", rep.Findings)
	}
}

func TestSignatureVerifierRequiresSignatures(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)
	f.append(t, "audit", 1)
	f.seal(t) // unsigned
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := sign.NewEd25519("k", priv)
	f.writer = seal.NewWriter(f.store, seal.WithClock(f.clock), seal.WithSinks(f.sink), seal.WithSigner(signer))
	f.seal(t) // signed
	sv, err := sign.NewEd25519Verifier(map[string]ed25519.PublicKey{"k": pub})
	if err != nil {
		t.Fatal(err)
	}
	v := f.verifier(verify.WithSignatureVerifier(sv))
	rep := v.Verify(ctx, verify.FromProvider(f.store), nil)
	errs := codes(rep, verify.Error)
	if errs[verify.CodeSealUnsigned] != 1 || errs[verify.CodeSealSignature] != 0 {
		t.Fatalf("%v", rep.Errors())
	}
	wrongKey, _ := sign.NewEd25519Verifier(map[string]ed25519.PublicKey{"k": make([]byte, 32)})
	wrong := f.verifier(verify.WithSignatureVerifier(wrongKey))
	if _, err := sign.NewEd25519Verifier(map[string]ed25519.PublicKey{"k": []byte{1}}); err == nil {
		t.Fatal("short public key accepted")
	}
	if codes(wrong.Verify(ctx, verify.FromProvider(f.store), nil), verify.Error)[verify.CodeSealSignature] != 1 {
		t.Fatal("wrong key accepted")
	}
}

func TestRunnerRecordsOutcomeAndCheckpoints(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)
	f.append(t, "audit", 4)
	f.seal(t)
	f.anchorAll(t)
	var reports int
	r := verify.NewRunner(f.verifier(), verify.FromProvider(f.store), verify.WithLog(f.log), verify.WithIncremental(time.Hour),
		verify.WithOnReport(func(context.Context, *verify.Report) { reports++ }))
	rep := r.Once(ctx)
	if !rep.OK() {
		t.Fatal(rep.Errors())
	}
	sys := f.store.Records(tamperlog.SystemStream)
	if len(sys) != 1 || sys[0].Action != verify.VerifiedAction || !bytes.Equal(sys[0].PayloadHash, rep.HeadsDigest()) {
		t.Fatalf("system stream = %+v", sys)
	}
	// Second run is incremental: only the new record and the boundary are read.
	f.append(t, "audit", 2)
	rep = r.Once(ctx)
	if !rep.OK() || rep.Streams["audit"].Records != 3 { // checkpoint record + 2 new
		t.Fatalf("incremental run = %+v, %v", rep.Streams["audit"], rep.Errors())
	}
	// Tamper before the checkpoint: a full run must be forced by the caller
	// (or by a broken run); the sealed head check still catches a change at
	// a sealed sequence.
	recs := f.store.Records("audit")
	recs[3].Action = "x"
	recs[3].Hash, _ = tamperlog.NewChain(nil, nil).Link(recs[3])
	f.store.Replace("audit", recs)
	rep = r.Once(ctx)
	if rep.OK() {
		t.Fatal("tampered checkpoint record not detected")
	}
	sys = f.store.Records(tamperlog.SystemStream)
	if sys[len(sys)-1].Action != verify.BrokenAction || sys[len(sys)-1].Attributes["first_stream"] != "audit" {
		t.Fatalf("broken event = %+v", sys[len(sys)-1])
	}
	if reports != 3 {
		t.Fatal(reports)
	}
	cctx, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel()
	if err := r.Run(cctx, 50*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

func TestMultipleConsecutiveDropsBridge(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.append(t, "audit", 10)
	f.seal(t)
	f.drop(t, "audit", 1, 4)
	f.seal(t)
	f.drop(t, "audit", 5, 7)
	f.seal(t)
	f.anchorAll(t)
	rep := f.verifier().Verify(context.Background(), verify.FromProvider(f.store), nil)
	if !rep.OK() {
		t.Fatal(rep.Errors())
	}
	g := rep.Streams["audit"].Gaps
	if len(g) != 1 || !g[0].Bridged || g[0].First != 1 || g[0].Last != 7 {
		t.Fatalf("gaps = %+v", g)
	}
	// A drop event whose digest was never sealed leaves the gap pending: a
	// warning, not bridged, not an error.
	f.drop(t, "audit", 8, 8)
	rep = f.verifier().Verify(context.Background(), verify.FromProvider(f.store), nil)
	if !rep.OK() || codes(rep, verify.Warning)[verify.CodeChainDrop] != 1 || codes(rep, verify.Warning)[verify.CodeChainGapPending] != 1 || rep.Streams["audit"].Gaps[0].Bridged {
		t.Fatalf("%v %+v", rep.Findings, rep.Streams["audit"].Gaps)
	}
	f.seal(t)
	rep = f.verifier().Verify(context.Background(), verify.FromProvider(f.store), nil)
	if !rep.OK() || !rep.Streams["audit"].Gaps[0].Bridged {
		t.Fatalf("%v", rep.Findings)
	}
}

func TestInnerGapsAreErrorsEvenWhenSealed(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.append(t, "audit", 6)
	f.seal(t)
	f.drop(t, "audit", 3, 4) // a DBA deletes and records a drop
	f.seal(t)                // the writer seals it blindly
	f.anchorAll(t)
	rep := f.verifier().Verify(context.Background(), verify.FromProvider(f.store), nil)
	if rep.OK() || codes(rep, verify.Error)[verify.CodeChainInnerGap] != 1 {
		t.Fatalf("%v", rep.Findings)
	}
	rep = f.verifier(verify.WithAllowInnerGaps()).Verify(context.Background(), verify.FromProvider(f.store), nil)
	if !rep.OK() {
		t.Fatalf("%v", rep.Errors())
	}
}

func TestSinkInventoryRevealsRollback(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)
	f.append(t, "audit", 2)
	f.seal(t)
	f.append(t, "audit", 2)
	f.seal(t)
	f.seal(t)
	// A DBA restores the database to the state after seal 1; the sink keeps
	// seals 2 and 3.
	restored := memory.New(memory.WithClock(f.clock))
	rlog := tamperlog.NewLog(restored)
	for _, r := range f.store.Records("audit")[:2] {
		if _, err := rlog.Append(ctx, r.Event); err != nil {
			t.Fatal(err)
		}
	}
	s1, _, _ := f.store.LastSeal(ctx)
	seals, _ := f.store.Seals(ctx, 1, 1)
	_ = s1
	if err := restored.PutSeal(ctx, seals[0]); err != nil {
		t.Fatal(err)
	}
	rep := verify.New(verify.WithSinks(f.sink), verify.WithClock(f.clock)).Verify(ctx, verify.FromProvider(restored), nil)
	if rep.OK() || codes(rep, verify.Error)[verify.CodeSinkExtra] != 1 {
		t.Fatalf("%v", rep.Findings)
	}
	// Even with every seal gone from the store, the sink inventory speaks.
	empty := memory.New()
	rep = verify.New(verify.WithSinks(f.sink)).Verify(ctx, verify.FromProvider(empty), nil)
	if rep.OK() || codes(rep, verify.Error)[verify.CodeSinkExtra] != 1 {
		t.Fatalf("%v", rep.Findings)
	}
}

func TestFreshnessPolicies(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)
	f.append(t, "audit", 1)
	f.seal(t)
	f.now = f.now.Add(3 * time.Hour)
	f.seal(t)
	f.anchorAll(t)
	rep := f.verifier(verify.WithMaxSealInterval(2*time.Hour)).Verify(ctx, verify.FromProvider(f.store), nil)
	if codes(rep, verify.Error)[verify.CodeSealInterval] != 1 {
		t.Fatalf("%v", rep.Findings)
	}
	f.now = f.now.Add(48 * time.Hour)
	rep = f.verifier(verify.WithMaxSealAge(24*time.Hour)).Verify(ctx, verify.FromProvider(f.store), nil)
	if codes(rep, verify.Error)[verify.CodeSealStale] != 1 {
		t.Fatalf("%v", rep.Findings)
	}
	// A seal dated in the future is refused.
	f.now = f.now.Add(-100 * time.Hour)
	rep = f.verifier().Verify(ctx, verify.FromProvider(f.store), nil)
	if codes(rep, verify.Error)[verify.CodeSealFuture] == 0 {
		t.Fatalf("%v", rep.Findings)
	}
}
