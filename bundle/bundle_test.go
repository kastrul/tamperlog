package bundle_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kastrul/tamperlog"
	"github.com/kastrul/tamperlog/anchor"
	"github.com/kastrul/tamperlog/bundle"
	"github.com/kastrul/tamperlog/seal"
	"github.com/kastrul/tamperlog/store/memory"
	"github.com/kastrul/tamperlog/verify"
)

type fakeProvider struct{}

func (fakeProvider) ID() string { return "fake" }
func (fakeProvider) Anchor(_ context.Context, d []byte) ([]byte, error) {
	return append([]byte("p"), d...), nil
}

func (fakeProvider) Verify(_ context.Context, d, p []byte) (anchor.Attestation, error) {
	if !bytes.Equal(p, append([]byte("p"), d...)) {
		return anchor.Attestation{}, anchor.ErrInvalidProof
	}
	return anchor.Attestation{Time: time.Now(), Authority: "fake"}, nil
}

func TestExportAndVerifyOffline(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { now = now.Add(time.Second); return now }
	s := memory.New(memory.WithClock(clock))
	log := tamperlog.NewLog(s)
	for i := range 5 {
		ev := tamperlog.Event{Stream: "audit", Action: "read", Entity: "record", EntityID: "r1", Actor: "u1", Attributes: map[string]string{"purpose": "treatment"}}
		if i == 2 {
			ev.PayloadHash = bytes.Repeat([]byte{9}, 32)
			ev.Attributes = nil
		}
		if _, err := log.Append(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := log.Append(ctx, tamperlog.Event{Stream: "auth", Action: "login", Entity: "session"}); err != nil {
		t.Fatal(err)
	}
	w := seal.NewWriter(s, seal.WithClock(clock))
	for range 2 {
		if _, err := w.Seal(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := anchor.NewRunner(s, fakeProvider{}).Once(ctx); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(t.TempDir(), "bundle")
	m, err := bundle.Export(ctx, verify.FromProvider(s), dir, bundle.ExportOptions{Writer: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Streams) != 2 || m.Streams[0].Stream != "audit" || m.Streams[0].Records != 5 || m.Seals.Count != 2 || m.Proofs["fake"] != 2 {
		t.Fatalf("manifest = %+v", m)
	}
	if _, err := bundle.Export(ctx, verify.FromProvider(s), dir, bundle.ExportOptions{}); err == nil {
		t.Fatal("export into a non-empty directory accepted")
	}

	b, err := bundle.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Records round-trip byte for byte.
	live := s.Records("audit")
	got, err := b.Range(ctx, "audit", 1, 5)
	if err != nil || len(got) != 5 {
		t.Fatal(err)
	}
	for i := range live {
		if !bytes.Equal(got[i].Hash, live[i].Hash) || !got[i].At.Equal(live[i].At) || got[i].Encoder != live[i].Encoder || !bytes.Equal(got[i].PayloadHash, live[i].PayloadHash) || len(got[i].Attributes) != len(live[i].Attributes) {
			t.Fatalf("record %d differs:\n%+v\n%+v", i, got[i], live[i])
		}
	}
	rep := verify.New(verify.WithAnchors(fakeProvider{})).Verify(ctx, b, nil)
	if !rep.OK() || rep.Seals.Anchored != 2 || rep.Streams["audit"].Records != 5 {
		t.Fatalf("offline verification: %v %+v", rep.Errors(), rep.Seals)
	}

	// A tampered stream file is caught by the manifest digest.
	path := filepath.Join(dir, "streams", "audit.jsonl")
	data, _ := os.ReadFile(path)
	_ = os.Chmod(path, 0o600)
	if err := os.WriteFile(path, bytes.Replace(data, []byte(`"actor":"u1"`), []byte(`"actor":"u2"`), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.Open(dir); err == nil {
		t.Fatal("tampered stream file opened")
	}
}

func TestLineRoundTrip(t *testing.T) {
	t.Parallel()
	r := tamperlog.Record{
		Event:    tamperlog.Event{Stream: "s", Actor: "a", Action: "x", Entity: "y", Attributes: map[string]string{"k": "v"}},
		Seq:      3,
		At:       time.Date(2026, 1, 2, 3, 4, 5, 678000, time.UTC),
		Encoder:  "binary/v1",
		Hasher:   "sha256",
		PrevHash: bytes.Repeat([]byte{1}, 32),
		Hash:     bytes.Repeat([]byte{2}, 32),
	}
	back, err := bundle.FromRecord(r).Record()
	if err != nil {
		t.Fatal(err)
	}
	if back.Seq != 3 || !back.At.Equal(r.At) || !bytes.Equal(back.Hash, r.Hash) || back.PayloadHash != nil || back.Attributes["k"] != "v" {
		t.Fatalf("%+v", back)
	}
	bad := bundle.FromRecord(r)
	bad.Hash = "zz"
	if _, err := bad.Record(); err == nil {
		t.Fatal("bad hex accepted")
	}
}
