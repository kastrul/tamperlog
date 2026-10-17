package seal_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/kastrul/tamperlog"
	"github.com/kastrul/tamperlog/seal"
	"github.com/kastrul/tamperlog/seal/sinks/fs"
	"github.com/kastrul/tamperlog/sign"
	"github.com/kastrul/tamperlog/store/memory"
)

func TestWriterChainsSeals(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 10, 17, 14, 0, 0, 0, time.UTC)
	clock := func() time.Time { now = now.Add(time.Minute); return now }
	s := memory.New(memory.WithClock(clock))
	log := tamperlog.NewLog(s)
	sink, _ := fs.New(t.TempDir())
	w := seal.NewWriter(s, seal.WithSinks(sink), seal.WithClock(clock), seal.WithWriterName("test 1.0"))

	// An empty store still seals: a quiet hour is attested.
	first, err := w.Seal(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p1, err := seal.Parse(first.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if p1.Seq != 1 || len(p1.Streams) != 0 || !bytes.Equal(p1.PrevSealHash, seal.GenesisHash) || p1.Writer != "test 1.0" || len(p1.Drops) != 0 {
		t.Fatalf("first seal = %+v", p1)
	}

	for _, st := range []string{"b", "a", "b"} {
		if _, err := log.Append(ctx, tamperlog.Event{Stream: st, Action: "x", Entity: "y"}); err != nil {
			t.Fatal(err)
		}
	}
	// A drop in the system stream is listed once, in the next seal.
	recs := s.Records("b")
	drop := tamperlog.DropEvent(tamperlog.SHA256, tamperlog.SystemStream, "b", 1, recs[0].PrevHash, 1, recs[0].Hash)
	if _, err := log.Append(ctx, drop); err != nil {
		t.Fatal(err)
	}
	s.Drop("b", 1, 1)

	second, err := w.Seal(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := seal.Parse(second.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if p2.Seq != 2 || !bytes.Equal(p2.PrevSealHash, first.Hash) || !p2.SealedAt.After(p1.SealedAt) {
		t.Fatalf("second seal = %+v", p2)
	}
	if len(p2.Streams) != 3 || p2.Streams[0].Stream != tamperlog.SystemStream || p2.Streams[1].Stream != "a" || p2.Streams[2].Stream != "b" {
		t.Fatalf("streams = %+v", p2.Streams)
	}
	if b := p2.Streams[2]; b.FirstKeptSeq != 2 || b.HeadSeq != 2 || !bytes.Equal(b.HeadHash, recs[1].Hash) || b.Encoder != "binary/v1" || b.Hasher != "sha256" {
		t.Fatalf("stream b = %+v", b)
	}
	if len(p2.Drops) != 1 || !bytes.Equal(p2.Drops[0], drop.PayloadHash) {
		t.Fatalf("drops = %x", p2.Drops)
	}

	third, err := w.Seal(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p3, _ := seal.Parse(third.Bytes)
	if len(p3.Drops) != 0 || !bytes.Equal(p3.PrevSealHash, second.Hash) {
		t.Fatalf("third seal repeats drops or breaks the chain: %+v", p3)
	}

	// Sinks hold the exact bytes under the seal key.
	got, err := sink.Get(ctx, seal.Key(2))
	if err != nil || !bytes.Equal(got, second.Bytes) {
		t.Fatalf("sink copy differs: %v", err)
	}
	// Store and sink agree.
	last, ok, _ := s.LastSeal(ctx)
	if !ok || last.Seq != 3 || !bytes.Equal(last.Hash, seal.Hash(third.Bytes)) {
		t.Fatalf("last seal = %+v", last)
	}
}

func TestWriterRefusesClockRegression(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 10, 17, 14, 0, 0, 0, time.UTC)
	s := memory.New()
	w := seal.NewWriter(s, seal.WithClock(func() time.Time { return now }))
	if _, err := w.Seal(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Seal(ctx); err == nil {
		t.Fatal("same timestamp accepted")
	}
	now = now.Add(time.Second)
	if _, err := w.Seal(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestWriterSignsAndResyncs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := sign.NewEd25519("k2026", priv)
	if err != nil {
		t.Fatal(err)
	}
	s := memory.New()
	w := seal.NewWriter(s, seal.WithSigner(signer))
	st, err := w.Seal(ctx)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := seal.Parse(st.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.KeyID != "k2026" || len(parsed.Signature) != ed25519.SignatureSize {
		t.Fatalf("seal = %+v", parsed)
	}
	v, err := sign.NewEd25519Verifier(map[string]ed25519.PublicKey{"k2026": pub})
	if err != nil {
		t.Fatal(err)
	}
	if err := sign.VerifySeal(ctx, v, parsed); err != nil {
		t.Fatal(err)
	}
	parsed.Writer = "forged"
	if err := sign.VerifySeal(ctx, v, parsed); !errors.Is(err, sign.ErrBadSignature) {
		t.Fatalf("forged seal: %v", err)
	}
	parsed.KeyID = "other"
	if err := sign.VerifySeal(ctx, v, parsed); !errors.Is(err, sign.ErrUnknownKey) {
		t.Fatalf("unknown key: %v", err)
	}
	if err := sign.VerifySeal(ctx, v, &seal.Seal{}); !errors.Is(err, sign.ErrUnsigned) {
		t.Fatalf("unsigned: %v", err)
	}

	// A sink added later catches up through Resync, proofs included.
	if err := s.PutProof(ctx, seal.Proof{SealSeq: 1, Provider: "rfc3161", ObtainedAt: time.Now(), Bytes: []byte("tok")}); err != nil {
		t.Fatal(err)
	}
	sink, _ := fs.New(t.TempDir())
	w2 := seal.NewWriter(s, seal.WithSigner(signer), seal.WithSinks(sink))
	n, err := w2.Resync(ctx)
	if err != nil || n != 2 {
		t.Fatalf("resync = %d, %v", n, err)
	}
	if got, err := sink.Get(ctx, seal.ProofKey(1, "rfc3161")); err != nil || string(got) != "tok" {
		t.Fatalf("proof in sink = %q, %v", got, err)
	}
	n, err = w2.Resync(ctx)
	if err != nil || n != 0 {
		t.Fatalf("second resync = %d, %v", n, err)
	}
}

func TestHMACSigner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	key := bytes.Repeat([]byte{7}, 32)
	h, err := sign.NewHMAC("shared", key)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := h.Sign(ctx, []byte("data"))
	if err := h.Verify(ctx, "shared", []byte("data"), sig); err != nil {
		t.Fatal(err)
	}
	if err := h.Verify(ctx, "shared", []byte("datb"), sig); !errors.Is(err, sign.ErrBadSignature) {
		t.Fatal(err)
	}
	if _, err := sign.NewHMAC("short", []byte("x")); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestWriterRunSealsOnInterval(t *testing.T) {
	t.Parallel()
	s := memory.New()
	w := seal.NewWriter(s)
	ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
	defer cancel()
	err := w.Run(ctx, 100*time.Millisecond, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	last, ok, _ := s.LastSeal(context.Background())
	if !ok || last.Seq < 3 {
		t.Fatalf("expected at least 3 seals, got %+v", last)
	}
}
