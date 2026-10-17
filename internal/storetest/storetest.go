// Package storetest is the conformance suite every storage backend must pass.
// A backend's test calls [Run] with a factory that returns a fresh, empty
// provider that also implements [seal.Store].
package storetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/kastrul/tamperlog"
	"github.com/kastrul/tamperlog/seal"
)

// Provider is what a backend under test must offer.
type Provider interface {
	tamperlog.Provider
	seal.Store
}

// Factory returns a fresh, empty provider for one subtest. Cleanup is
// registered on t.
type Factory func(t *testing.T) Provider

// Run executes the conformance suite.
func Run(t *testing.T, newProvider Factory) {
	t.Helper()
	tests := map[string]func(t *testing.T, p Provider){
		"EmptyHeadIsGenesis":         testEmptyHead,
		"AppendLinksAndRangeReads":   testAppendRange,
		"RollbackLeavesNoTrace":      testRollback,
		"DuplicateSeqIsRefused":      testDuplicate,
		"ConcurrentAppendsAreDense":  testConcurrent,
		"HeadLockBlocksOtherWriters": testHeadLock,
		"HeadsAndFirstSeqs":          testHeadsFirstSeqs,
		"HeadClockAdvances":          testClock,
		"InvalidStreamIsRefused":     testInvalidStream,
		"HeadReportsAlgorithmsAndAt": testHeadAlgorithms,
		"AlgorithmChangeIsRefused":   testAlgorithmMismatch,
		"HeadWaitHonoursContext":     testHeadCancel,
		"HeadsWhileAppending":        testHeadsConcurrent,
		"ReadResultsAreCopies":       testCopies,
		"SealsChainAndProofs":        testSeals,
	}
	for name, fn := range tests {
		t.Run(name, func(t *testing.T) {
			fn(t, newProvider(t))
		})
	}
}

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

func event(stream, action string) tamperlog.Event {
	return tamperlog.Event{Stream: stream, Actor: "u1", Action: action, Entity: "thing", EntityID: "t1", Attributes: map[string]string{"purpose": "test"}}
}

func testEmptyHead(t *testing.T, p Provider) {
	c := ctx(t)
	tx, err := p.Begin(c)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(c) //nolint:errcheck // cleanup
	h, err := tx.Head(c, "s")
	if err != nil {
		t.Fatal(err)
	}
	if h.Seq != 0 || len(h.Hash) != 0 || h.Now.IsZero() {
		t.Fatalf("empty head = %+v", h)
	}
}

func testAppendRange(t *testing.T, p Provider) {
	c := ctx(t)
	log := tamperlog.NewLog(p)
	want := make([]tamperlog.Record, 0, 5)
	for i := range 5 {
		r, err := log.Append(c, event("s", fmt.Sprintf("a%d", i)))
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, r)
	}
	tx, err := p.Begin(c)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(c) //nolint:errcheck // cleanup
	got, err := tx.Range(c, "s", 1, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("range returned %d records", len(got))
	}
	for i := range got {
		assertRecordEqual(t, got[i], want[i])
	}
	if err := log.Appender().Chain().Walk("s", 1, got, tamperlog.WalkOptions{TimeTolerance: time.Second}); err != nil {
		t.Fatal(err)
	}
	part, err := tx.Range(c, "s", 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(part) != 2 || part[0].Seq != 2 || part[1].Seq != 3 {
		t.Fatalf("partial range = %v", part)
	}
}

func assertRecordEqual(t *testing.T, got, want tamperlog.Record) {
	t.Helper()
	if got.Stream != want.Stream || got.Seq != want.Seq || !got.At.Equal(want.At) ||
		got.Actor != want.Actor || got.Subject != want.Subject || got.Action != want.Action ||
		got.Entity != want.Entity || got.EntityID != want.EntityID ||
		!bytes.Equal(got.PayloadHash, want.PayloadHash) || !bytes.Equal(got.PrevHash, want.PrevHash) || !bytes.Equal(got.Hash, want.Hash) ||
		len(got.Attributes) != len(want.Attributes) {
		t.Fatalf("record read back differs:\n got %+v\nwant %+v", got, want)
	}
	for k, v := range want.Attributes {
		if got.Attributes[k] != v {
			t.Fatalf("attribute %s = %q, want %q", k, got.Attributes[k], v)
		}
	}
	if got.At.Location() != time.UTC {
		t.Fatalf("At location = %v, want UTC", got.At.Location())
	}
	if got.PayloadHash != nil && len(got.PayloadHash) == 0 {
		t.Fatal("absent payload hash read back as empty slice, want nil")
	}
}

func testRollback(t *testing.T, p Provider) {
	c := ctx(t)
	a := tamperlog.New()
	tx, err := p.Begin(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Append(c, tx, event("s", "a")); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(c); err != nil {
		t.Fatal(err)
	}
	heads, err := p.Heads(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := heads["s"]; ok {
		t.Fatal("rolled back record is visible")
	}
	// The next append starts from genesis again.
	r, err := tamperlog.NewLog(p).Append(c, event("s", "b"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Seq != 1 {
		t.Fatalf("seq after rollback = %d", r.Seq)
	}
}

func testDuplicate(t *testing.T, p Provider) {
	c := ctx(t)
	r, err := tamperlog.NewLog(p).Append(c, event("s", "a"))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := p.Begin(c)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(c) //nolint:errcheck // cleanup
	if _, err := tx.Head(c, "s"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Insert(c, r); err == nil {
		t.Fatal("duplicate (stream, seq) accepted")
	}
}

func testConcurrent(t *testing.T, p Provider) {
	c := ctx(t)
	log := tamperlog.NewLog(p)
	const workers, each = 8, 10
	var wg sync.WaitGroup
	errs := make(chan error, workers*each)
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				if _, err := log.Append(c, event("s", fmt.Sprintf("w%d.i%d", w, i))); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	tx, err := p.Begin(c)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(c) //nolint:errcheck // cleanup
	recs, err := tx.Range(c, "s", 1, workers*each)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != workers*each {
		t.Fatalf("%d records, want %d", len(recs), workers*each)
	}
	if err := log.Appender().Chain().Walk("s", 1, recs, tamperlog.WalkOptions{TimeTolerance: time.Second}); err != nil {
		t.Fatal(err)
	}
}

func testHeadLock(t *testing.T, p Provider) {
	c := ctx(t)
	tx1, err := p.Begin(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx1.Head(c, "s"); err != nil {
		t.Fatal(err)
	}
	acquired := make(chan error, 1)
	go func() {
		tx2, err := p.Begin(c)
		if err != nil {
			acquired <- err
			return
		}
		defer tx2.Rollback(c) //nolint:errcheck // cleanup
		_, err = tx2.Head(c, "s")
		acquired <- err
	}()
	select {
	case err := <-acquired:
		t.Fatalf("second Head returned while first transaction holds the stream: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	if err := tx1.Rollback(c); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-acquired:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second Head still blocked after the first transaction ended")
	}
}

func testHeadAlgorithms(t *testing.T, p Provider) {
	c := ctx(t)
	r, err := tamperlog.NewLog(p).Append(c, event("s", "a"))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := p.Begin(c)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(c) //nolint:errcheck // cleanup
	h, err := tx.Head(c, "s")
	if err != nil {
		t.Fatal(err)
	}
	if h.Seq != 1 || !bytes.Equal(h.Hash, r.Hash) || !h.At.Equal(r.At) || h.Encoder != "binary/v1" || h.Hasher != "sha256" {
		t.Fatalf("head = %+v, record = %+v", h, r)
	}
	heads, err := p.Heads(c)
	if err != nil {
		t.Fatal(err)
	}
	if g := heads["s"]; g.Encoder != "binary/v1" || g.Hasher != "sha256" || !g.At.Equal(r.At) {
		t.Fatalf("Heads()[s] = %+v", g)
	}
	recs, err := tx.Range(c, "s", 1, 1)
	if err != nil || len(recs) != 1 || recs[0].Encoder != "binary/v1" || recs[0].Hasher != "sha256" {
		t.Fatalf("range = %+v, %v", recs, err)
	}
}

func testAlgorithmMismatch(t *testing.T, p Provider) {
	c := ctx(t)
	if _, err := tamperlog.NewLog(p).Append(c, event("s", "a")); err != nil {
		t.Fatal(err)
	}
	_, err := tamperlog.NewLog(p, tamperlog.WithHasher(tamperlog.SHA3256)).Append(c, event("s", "b"))
	if !errors.Is(err, tamperlog.ErrAlgorithmMismatch) {
		t.Fatalf("append with another hasher: %v, want ErrAlgorithmMismatch", err)
	}
	// A different stream may use a different pair.
	if _, err := tamperlog.NewLog(p, tamperlog.WithHasher(tamperlog.SHA3256)).Append(c, event("t", "b")); err != nil {
		t.Fatal(err)
	}
}

func testHeadCancel(t *testing.T, p Provider) {
	c := ctx(t)
	tx1, err := p.Begin(c)
	if err != nil {
		t.Fatal(err)
	}
	defer tx1.Rollback(c) //nolint:errcheck // cleanup
	if _, err := tx1.Head(c, "s"); err != nil {
		t.Fatal(err)
	}
	c2, cancel := context.WithTimeout(c, 300*time.Millisecond)
	defer cancel()
	tx2, err := p.Begin(c2)
	if err != nil {
		t.Fatal(err)
	}
	defer tx2.Rollback(c) //nolint:errcheck // cleanup
	start := time.Now()
	_, err = tx2.Head(c2, "s")
	if err == nil {
		t.Fatal("second Head succeeded while the stream was held")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("Head did not return promptly after cancellation: %v", err)
	}
}

func testHeadsConcurrent(t *testing.T, p Provider) {
	c := ctx(t)
	log := tamperlog.NewLog(p)
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
			}
			if _, err := log.Append(c, event("s", fmt.Sprintf("a%d", i))); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for range 20 {
		if _, err := p.Heads(c); err != nil {
			t.Error(err)
		}
		if _, err := p.FirstSeqs(c); err != nil {
			t.Error(err)
		}
	}
	close(done)
	wg.Wait()
}

func testCopies(t *testing.T, p Provider) {
	c := ctx(t)
	r, err := tamperlog.NewLog(p).Append(c, event("s", "a"))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := p.Begin(c)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(c) //nolint:errcheck // cleanup
	recs, err := tx.Range(c, "s", 1, 1)
	if err != nil || len(recs) != 1 {
		t.Fatal(err)
	}
	recs[0].Hash[0] ^= 1
	recs[0].Attributes["purpose"] = "changed"
	again, err := tx.Range(c, "s", 1, 1)
	if err != nil || !bytes.Equal(again[0].Hash, r.Hash) || again[0].Attributes["purpose"] != "test" {
		t.Fatalf("mutation through a read result changed stored data: %+v, %v", again, err)
	}
	body := []byte(`{"seq":1}`)
	if err := p.PutSeal(c, seal.Stored{Seq: 1, SealedAt: time.Now(), Hash: seal.Hash(body), Bytes: body}); err != nil {
		t.Fatal(err)
	}
	last, _, err := p.LastSeal(c)
	if err != nil {
		t.Fatal(err)
	}
	last.Bytes[0] = 'X'
	last.Hash[0] ^= 1
	again2, _, err := p.LastSeal(c)
	if err != nil || !bytes.Equal(again2.Bytes, body) || !bytes.Equal(again2.Hash, seal.Hash(body)) {
		t.Fatalf("mutation through LastSeal changed stored seal: %+v, %v", again2, err)
	}
}

func testHeadsFirstSeqs(t *testing.T, p Provider) {
	c := ctx(t)
	log := tamperlog.NewLog(p)
	var last tamperlog.Record
	for i := range 3 {
		var err error
		if last, err = log.Append(c, event("a", fmt.Sprintf("x%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := log.Append(c, event("b", "y")); err != nil {
		t.Fatal(err)
	}
	heads, err := p.Heads(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(heads) != 2 || heads["a"].Seq != 3 || !bytes.Equal(heads["a"].Hash, last.Hash) || heads["b"].Seq != 1 {
		t.Fatalf("heads = %+v", heads)
	}
	firsts, err := p.FirstSeqs(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(firsts) != 2 || firsts["a"] != 1 || firsts["b"] != 1 {
		t.Fatalf("first seqs = %+v", firsts)
	}
}

func testClock(t *testing.T, p Provider) {
	c := ctx(t)
	tx, err := p.Begin(c)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(c) //nolint:errcheck // cleanup
	h1, err := tx.Head(c, "s")
	if err != nil {
		t.Fatal(err)
	}
	h2, err := tx.Head(c, "s")
	if err != nil {
		t.Fatal(err)
	}
	if h2.Now.Before(h1.Now) {
		t.Fatalf("clock went backwards: %s then %s", h1.Now, h2.Now)
	}
	if d := time.Since(h1.Now); d < -time.Minute || d > time.Minute {
		t.Fatalf("store clock %s is %s from the test clock", h1.Now, d)
	}
}

func testInvalidStream(t *testing.T, p Provider) {
	c := ctx(t)
	tx, err := p.Begin(c)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(c) //nolint:errcheck // cleanup
	if _, err := tx.Head(c, "Not Valid"); !errors.Is(err, tamperlog.ErrInvalidEvent) {
		t.Fatalf("Head with invalid stream: %v, want ErrInvalidEvent", err)
	}
}

func testSeals(t *testing.T, p Provider) {
	c := ctx(t)
	if _, ok, err := p.LastSeal(c); err != nil || ok {
		t.Fatalf("LastSeal on empty store = ok %v, err %v", ok, err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	mk := func(seq int64) seal.Stored {
		b := []byte(fmt.Sprintf(`{"seq":%d}`, seq))
		return seal.Stored{Seq: seq, SealedAt: now.Add(time.Duration(seq) * time.Hour), Hash: seal.Hash(b), Bytes: b}
	}
	if err := p.PutSeal(c, mk(2)); err == nil {
		t.Fatal("seal seq 2 accepted before seq 1")
	}
	for seq := int64(1); seq <= 3; seq++ {
		if err := p.PutSeal(c, mk(seq)); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.PutSeal(c, mk(3)); err == nil {
		t.Fatal("duplicate seal accepted")
	}
	last, ok, err := p.LastSeal(c)
	if err != nil || !ok || last.Seq != 3 || !bytes.Equal(last.Bytes, mk(3).Bytes) || !last.SealedAt.Equal(mk(3).SealedAt) {
		t.Fatalf("LastSeal = %+v, %v, %v", last, ok, err)
	}
	seals, err := p.Seals(c, 2, 3)
	if err != nil || len(seals) != 2 || seals[0].Seq != 2 || seals[1].Seq != 3 {
		t.Fatalf("Seals(2,3) = %+v, %v", seals, err)
	}
	un, err := p.Unanchored(c, "rfc3161", 10)
	if err != nil || len(un) != 3 {
		t.Fatalf("Unanchored = %d, %v", len(un), err)
	}
	if err := p.PutProof(c, seal.Proof{SealSeq: 2, Provider: "rfc3161", ObtainedAt: now, Bytes: []byte("tok")}); err != nil {
		t.Fatal(err)
	}
	if err := p.PutProof(c, seal.Proof{SealSeq: 9, Provider: "rfc3161", ObtainedAt: now, Bytes: []byte("tok")}); err == nil {
		t.Fatal("proof for unknown seal accepted")
	}
	un, err = p.Unanchored(c, "rfc3161", 10)
	if err != nil || len(un) != 2 || un[0].Seq != 1 || un[1].Seq != 3 {
		t.Fatalf("Unanchored after proof = %+v, %v", un, err)
	}
	un, err = p.Unanchored(c, "rfc3161", 1)
	if err != nil || len(un) != 1 {
		t.Fatalf("Unanchored limit 1 = %d, %v", len(un), err)
	}
	proofs, err := p.Proofs(c, 2)
	if err != nil || len(proofs) != 1 || proofs[0].Provider != "rfc3161" || string(proofs[0].Bytes) != "tok" || !proofs[0].ObtainedAt.Equal(now) {
		t.Fatalf("Proofs(2) = %+v, %v", proofs, err)
	}
	if proofs, err := p.Proofs(c, 1); err != nil || len(proofs) != 0 {
		t.Fatalf("Proofs(1) = %+v, %v", proofs, err)
	}
}
