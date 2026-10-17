package tamperlog_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/kastrul/tamperlog"
	"github.com/kastrul/tamperlog/encoding/jcs"
	"github.com/kastrul/tamperlog/store/memory"
)

// goldenRecord is the record behind every golden vector in SPEC.md. Changing
// any shipped encoder or hasher must change the vectors, and an offline
// verifier in another language must reproduce them.
func goldenRecord() tamperlog.Record {
	payload := bytes.Repeat([]byte{0xaa}, 32)
	return tamperlog.Record{
		Event: tamperlog.Event{
			Stream:      "chat",
			Actor:       "0199f5a0-0000-7000-8000-000000000001",
			Subject:     "",
			Action:      "message.read",
			Entity:      "chat_message",
			EntityID:    "0199f5a0-0000-7000-8000-000000000002",
			PayloadHash: payload,
			Attributes:  map[string]string{"purpose": "treatment", "channel": "web"},
		},
		Seq:      1,
		At:       time.Date(2026, 10, 13, 12, 0, 0, 123456000, time.UTC),
		PrevHash: make([]byte, 32),
	}
}

func TestGoldenVectors(t *testing.T) {
	t.Parallel()
	type vector struct {
		name          string
		enc           tamperlog.Encoder
		h             tamperlog.Hasher
		wantCanonical string
		wantHash      string
	}
	cases := make([]vector, 0, 2*len(tamperlog.Hashers()))
	for _, enc := range []tamperlog.Encoder{tamperlog.BinaryV1, jcs.V1} {
		for _, h := range tamperlog.Hashers() {
			name := enc.ID() + " " + h.ID()
			want, ok := goldenHashes[name]
			if !ok {
				t.Fatalf("no golden hash for %s", name)
			}
			canonical := goldenBinaryV1
			if enc == jcs.V1 {
				canonical = hex.EncodeToString([]byte(goldenJCSV1))
			}
			cases = append(cases, vector{name, enc, h, canonical, want})
		}
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			chain := tamperlog.NewChain(c.enc, c.h)
			r := goldenRecord()
			canonical, err := c.enc.Encode(r)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(canonical); got != c.wantCanonical {
				t.Fatalf("canonical = %s", got)
			}
			got, err := chain.Link(r)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(got) != c.wantHash {
				t.Fatalf("link = %x, want %s", got, c.wantHash)
			}
		})
	}
}

func TestEncodersRejectNonCanonicalTimes(t *testing.T) {
	t.Parallel()
	for _, enc := range []tamperlog.Encoder{tamperlog.BinaryV1, jcs.V1} {
		r := goldenRecord()
		r.At = r.At.Add(time.Nanosecond)
		if _, err := enc.Encode(r); !errors.Is(err, tamperlog.ErrInvalidEvent) {
			t.Errorf("%s: nanosecond time: %v", enc.ID(), err)
		}
		r.At = tamperlog.MaxTime.Add(time.Microsecond)
		if _, err := enc.Encode(r); !errors.Is(err, tamperlog.ErrInvalidEvent) {
			t.Errorf("%s: time after MaxTime: %v", enc.ID(), err)
		}
		r.At = time.Unix(-1, 0)
		if _, err := enc.Encode(r); !errors.Is(err, tamperlog.ErrInvalidEvent) {
			t.Errorf("%s: time before 1970: %v", enc.ID(), err)
		}
		r = goldenRecord()
		r.Seq = tamperlog.MaxSeq + 1
		if _, err := enc.Encode(r); err == nil {
			t.Errorf("%s: seq above MaxSeq accepted", enc.ID())
		}
	}
}

func TestTimeRegressionIsRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	s := memory.New(memory.WithClock(func() time.Time { return now }))
	log := tamperlog.NewLog(s, tamperlog.WithCallerTime())
	if _, err := log.Append(ctx, tamperlog.Event{Stream: "s", Action: "a", Entity: "e", Time: now.Add(4 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	_, err := log.Append(ctx, tamperlog.Event{Stream: "s", Action: "a", Entity: "e", Time: now.Add(2 * time.Second)})
	if !errors.Is(err, tamperlog.ErrClockSkew) {
		t.Fatalf("regression of 2 s with 1 s tolerance: %v", err)
	}
	if _, err := log.Append(ctx, tamperlog.Event{Stream: "s", Action: "a", Entity: "e", Time: now.Add(3500 * time.Millisecond)}); err != nil {
		t.Fatalf("regression within tolerance: %v", err)
	}
	// A store clock that jumps backwards is refused too.
	now = now.Add(-time.Hour)
	if _, err := tamperlog.NewLog(s).Append(ctx, tamperlog.Event{Stream: "s", Action: "a", Entity: "e"}); !errors.Is(err, tamperlog.ErrClockSkew) {
		t.Fatalf("store clock regression: %v", err)
	}
}

func TestLogAppendRollsBackOnPanic(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := memory.New()
	log := tamperlog.NewLog(s, tamperlog.WithHooks(tamperlog.Hooks{OnAppend: func(context.Context, tamperlog.Record) { panic("hook") }}))
	func() {
		defer func() { _ = recover() }()
		_, _ = log.Append(ctx, tamperlog.Event{Stream: "s", Action: "a", Entity: "e"})
	}()
	c, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if _, err := tamperlog.NewLog(s).Append(c, tamperlog.Event{Stream: "s", Action: "a", Entity: "e"}); err != nil {
		t.Fatalf("stream still locked after a panicking hook: %v", err)
	}
}

func TestAppendLinksAStream(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	s := memory.New(memory.WithClock(func() time.Time { now = now.Add(time.Millisecond); return now }))
	log := tamperlog.NewLog(s)
	for range 3 {
		if _, err := log.Append(ctx, tamperlog.Event{Stream: "audit", Action: "message.read", Entity: "chat_message"}); err != nil {
			t.Fatal(err)
		}
	}
	recs := s.Records("audit")
	chain := log.Appender().Chain()
	for i, r := range recs {
		want := chain.Genesis()
		if i > 0 {
			want = recs[i-1].Hash
		}
		link, _ := chain.Link(r)
		if r.Seq != int64(i+1) || !bytes.Equal(r.PrevHash, want) || !bytes.Equal(link, r.Hash) {
			t.Fatalf("record %d is not linked: %+v", i, r)
		}
	}
	if err := chain.Walk("audit", 1, recs, tamperlog.WalkOptions{TimeTolerance: time.Second}); err != nil {
		t.Fatal(err)
	}
	if err := chain.Walk("audit", 2, recs[1:], tamperlog.WalkOptions{}); err != nil {
		t.Fatalf("a range from the middle: %v", err)
	}
}

func TestAppendRefusesInvalidEvents(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	log := tamperlog.NewLog(memory.New())
	bad := []tamperlog.Event{
		{Stream: "", Action: "a", Entity: "e"},
		{Stream: "Audit", Action: "a", Entity: "e"},
		{Stream: "audit", Action: "", Entity: "e"},
		{Stream: "audit", Action: "A", Entity: "e"},
		{Stream: "audit", Action: "a..b", Entity: "e"},
		{Stream: "audit", Action: "a", Entity: "e", PayloadHash: []byte{1}},
		{Stream: "audit", Action: "a", Entity: "e", Actor: "x\x00y"},
		{Stream: "audit", Action: "a", Entity: "e", Attributes: map[string]string{"Bad Key": "v"}},
		{Stream: "audit", Action: "a", Entity: "e", Attributes: map[string]string{"k": "\xff"}},
	}
	for i, e := range bad {
		if _, err := log.Append(ctx, e); !errors.Is(err, tamperlog.ErrInvalidEvent) {
			t.Errorf("event %d: %v, want ErrInvalidEvent", i, err)
		}
	}
}

func TestCallerTime(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	s := memory.New(memory.WithClock(func() time.Time { return now }))
	log := tamperlog.NewLog(s, tamperlog.WithCallerTime())
	ev := tamperlog.Event{Stream: "s", Action: "a", Entity: "e", Time: now.Add(2 * time.Second).In(time.FixedZone("x", 3600))}
	r, err := log.Append(ctx, ev)
	if err != nil {
		t.Fatal(err)
	}
	if !r.At.Equal(now.Add(2*time.Second)) || r.At.Location() != time.UTC || !r.Time.IsZero() {
		t.Fatalf("record At = %s (%v), Event.Time = %s", r.At, r.At.Location(), r.Time)
	}
	ev.Time = now.Add(6 * time.Second)
	if _, err := log.Append(ctx, ev); !errors.Is(err, tamperlog.ErrClockSkew) {
		t.Fatalf("skewed time: %v", err)
	}
	ev.Time = time.Time{}
	if _, err := log.Append(ctx, ev); !errors.Is(err, tamperlog.ErrClockSkew) {
		t.Fatalf("zero time: %v", err)
	}
	// Without the option the caller's time is ignored.
	r, err = tamperlog.NewLog(s).Append(ctx, tamperlog.Event{Stream: "other", Action: "a", Entity: "e", Time: now.Add(time.Hour)})
	if err != nil || !r.At.Equal(now) {
		t.Fatalf("default stamping: %s, %v", r.At, err)
	}
}

func TestHooksAndSystemStream(t *testing.T) {
	t.Parallel()
	var seen []tamperlog.Record
	a := tamperlog.New(tamperlog.WithHooks(tamperlog.Hooks{OnAppend: func(_ context.Context, r tamperlog.Record) { seen = append(seen, r) }}), tamperlog.WithSystemStream("sys"))
	if a.SystemStream() != "sys" {
		t.Fatal(a.SystemStream())
	}
	s := memory.New()
	tx, _ := s.Begin(context.Background())
	if _, err := a.Append(context.Background(), tx, tamperlog.Event{Stream: "s", Action: "a", Entity: "e"}); err != nil {
		t.Fatal(err)
	}
	_ = tx.Commit(context.Background())
	if len(seen) != 1 || seen[0].Seq != 1 {
		t.Fatalf("hook saw %+v", seen)
	}
}

func TestLookupHasher(t *testing.T) {
	t.Parallel()
	for _, h := range tamperlog.Hashers() {
		got, err := tamperlog.LookupHasher(h.ID())
		if err != nil || got.ID() != h.ID() || got.Size() != 32 {
			t.Fatalf("%s: %v", h.ID(), err)
		}
	}
	if _, err := tamperlog.LookupHasher("md5"); err == nil {
		t.Fatal("md5 accepted")
	}
}

func TestCommitAndDropDigest(t *testing.T) {
	t.Parallel()
	c := tamperlog.Commit(tamperlog.SHA256, []byte("salt"), []byte("payload"))
	if hex.EncodeToString(c) != goldenCommit {
		t.Fatalf("commit = %x", c)
	}
	d := tamperlog.DropDigest(tamperlog.SHA256, "s", 1, make([]byte, 32), 10, bytes.Repeat([]byte{1}, 32))
	if hex.EncodeToString(d) != goldenDropDigest {
		t.Fatalf("drop digest = %x", d)
	}
	ev := tamperlog.DropEvent(tamperlog.SHA256, tamperlog.SystemStream, "s", 1, make([]byte, 32), 10, bytes.Repeat([]byte{1}, 32))
	if ev.Stream != "_tamperlog" || ev.Action != "retention.drop" || ev.EntityID != "s" || !bytes.Equal(ev.PayloadHash, d) || ev.Attributes["last_seq"] != "10" {
		t.Fatalf("drop event = %+v", ev)
	}
	if err := ev.Validate(32); err != nil {
		t.Fatal(err)
	}
}

type edit struct {
	name    string
	content bool // content edits change the canonical record; the others only a stored hash
	apply   func(*tamperlog.Record)
}

var edits = []edit{
	{"stream", true, func(r *tamperlog.Record) { r.Stream = "other" }},
	{"seq", true, func(r *tamperlog.Record) { r.Seq++ }},
	{"at", true, func(r *tamperlog.Record) { r.At = r.At.Add(time.Microsecond) }},
	{"actor", true, func(r *tamperlog.Record) { r.Actor += "x" }},
	{"subject", true, func(r *tamperlog.Record) { r.Subject += "x" }},
	{"action", true, func(r *tamperlog.Record) { r.Action += "x" }},
	{"entity", true, func(r *tamperlog.Record) { r.Entity += "x" }},
	{"entity_id", true, func(r *tamperlog.Record) { r.EntityID += "x" }},
	{"payload_hash", true, func(r *tamperlog.Record) {
		if r.PayloadHash == nil {
			r.PayloadHash = make([]byte, 32)
			return
		}
		p := bytes.Clone(r.PayloadHash)
		p[0] ^= 1
		r.PayloadHash = p
	}},
	{"attribute", true, func(r *tamperlog.Record) {
		m := map[string]string{}
		for k, v := range r.Attributes {
			m[k] = v
		}
		m["zz"] = "added"
		r.Attributes = m
	}},
	{"encoder", false, func(r *tamperlog.Record) { r.Encoder += "x" }},
	{"hasher", false, func(r *tamperlog.Record) { r.Hasher += "x" }},
	{"prev_hash", false, func(r *tamperlog.Record) { r.PrevHash = bytes.Clone(r.PrevHash); r.PrevHash[0] ^= 1 }},
	{"hash", false, func(r *tamperlog.Record) { r.Hash = bytes.Clone(r.Hash); r.Hash[0] ^= 1 }},
}

func eventGen() *rapid.Generator[tamperlog.Event] {
	id := rapid.OneOf(rapid.Just(""), rapid.StringMatching(`[a-z0-9-]{1,36}`), rapid.StringOfN(rapid.RuneFrom([]rune("aä€😀")), 1, 8, -1))
	name := rapid.StringMatching(`[a-z][a-z0-9]{0,7}([._][a-z0-9]{1,8}){0,2}`)
	return rapid.Custom(func(t *rapid.T) tamperlog.Event {
		e := tamperlog.Event{
			Stream:   "audit",
			Actor:    id.Draw(t, "actor"),
			Subject:  id.Draw(t, "subject"),
			Action:   name.Draw(t, "action"),
			Entity:   name.Draw(t, "entity"),
			EntityID: id.Draw(t, "entity_id"),
		}
		if rapid.Bool().Draw(t, "has_payload") {
			e.PayloadHash = rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(t, "payload")
		}
		n := rapid.IntRange(0, 3).Draw(t, "attrs")
		if n > 0 {
			e.Attributes = map[string]string{}
			for i := 0; i < n; i++ {
				e.Attributes[rapid.StringMatching(`[a-z][a-z0-9_]{0,6}`).Draw(t, "key")] = id.Draw(t, "value")
			}
		}
		return e
	})
}

// Any single-record edit or deletion is caught by Walk at the edited record,
// or at the next one when the edit also recomputes the record's own hash,
// and a content edit changes every hash from that record on when the chain
// is recomputed from genesis. Holds for every shipped encoder and hasher.
func TestWalkDetectsAnySingleRecordChange(t *testing.T) {
	t.Parallel()
	encoders := []tamperlog.Encoder{tamperlog.BinaryV1, jcs.V1}
	rapid.Check(t, func(t *rapid.T) {
		enc := rapid.SampledFrom(encoders).Draw(t, "encoder")
		h := rapid.SampledFrom(tamperlog.Hashers()).Draw(t, "hasher")
		now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
		s := memory.New(memory.WithClock(func() time.Time { now = now.Add(time.Millisecond); return now }))
		log := tamperlog.NewLog(s, tamperlog.WithEncoder(enc), tamperlog.WithHasher(h))
		chain := log.Appender().Chain()
		n := rapid.IntRange(1, 12).Draw(t, "n")
		for range n {
			if _, err := log.Append(context.Background(), eventGen().Draw(t, "event")); err != nil {
				t.Fatal(err)
			}
		}
		orig := s.Records("audit")
		if err := chain.Walk("audit", 1, orig, tamperlog.WalkOptions{TimeTolerance: time.Second}); err != nil {
			t.Fatalf("untouched chain: %v", err)
		}
		k := rapid.IntRange(0, n-1).Draw(t, "k")
		last := k == n-1
		seq := int64(k + 1)
		recs := append([]tamperlog.Record(nil), orig...)

		var wantSeq int64 // 0: Walk cannot tell
		if rapid.Bool().Draw(t, "delete") {
			recs = append(recs[:k], recs[k+1:]...)
			if !last {
				wantSeq = seq
			}
		} else {
			e := rapid.SampledFrom(edits).Draw(t, "edit")
			e.apply(&recs[k])
			rehash := e.name != "hash" && rapid.Bool().Draw(t, "rehash")
			if rehash {
				recs[k].Hash, _ = chain.Link(recs[k])
			}
			switch {
			case !rehash, !e.content, e.name == "stream", e.name == "seq":
				wantSeq = seq
			case !last:
				wantSeq = seq + 1
			}
			if e.content {
				running := chain.Genesis()
				for j := range recs {
					r := recs[j]
					r.PrevHash = running
					running, _ = chain.Link(r)
					if !bytes.Equal(running, orig[j].Hash) != (j >= k) {
						t.Fatalf("%s edit at record %d: recomputed hash of record %d broken = %v", e.name, k, j, j < k)
					}
				}
			}
		}

		err := chain.Walk("audit", 1, recs, tamperlog.WalkOptions{})
		var broken *tamperlog.BrokenChainError
		switch {
		case wantSeq == 0 && err != nil:
			t.Fatalf("unexpected %v", err)
		case wantSeq != 0 && (!errors.As(err, &broken) || broken.Seq != wantSeq):
			t.Fatalf("Walk() = %v, want a break at seq %d", err, wantSeq)
		}
	})
}

// Encoders are injective over the generated event space: distinct records
// never share canonical bytes.
func TestEncodersAreInjective(t *testing.T) {
	t.Parallel()
	for _, enc := range []tamperlog.Encoder{tamperlog.BinaryV1, jcs.V1} {
		t.Run(enc.ID(), func(t *testing.T) {
			t.Parallel()
			rapid.Check(t, func(t *rapid.T) {
				at := time.UnixMicro(int64(rapid.IntRange(0, 1<<40).Draw(t, "at"))).UTC()
				a := tamperlog.Record{Event: eventGen().Draw(t, "a"), Seq: int64(rapid.IntRange(1, 1000).Draw(t, "seqa")), At: at}
				b := tamperlog.Record{Event: eventGen().Draw(t, "b"), Seq: int64(rapid.IntRange(1, 1000).Draw(t, "seqb")), At: at.Add(time.Duration(rapid.IntRange(0, 3).Draw(t, "dt")) * time.Microsecond)}
				ea, err := enc.Encode(a)
				if err != nil {
					t.Fatal(err)
				}
				eb, err := enc.Encode(b)
				if err != nil {
					t.Fatal(err)
				}
				same := recordsEqual(a, b)
				if bytes.Equal(ea, eb) != same {
					t.Fatalf("equal records %v but equal encodings %v\n%+v\n%+v", same, !same, a, b)
				}
			})
		})
	}
}

func recordsEqual(a, b tamperlog.Record) bool {
	if a.Stream != b.Stream || a.Seq != b.Seq || !a.At.Equal(b.At) || a.Actor != b.Actor || a.Subject != b.Subject ||
		a.Action != b.Action || a.Entity != b.Entity || a.EntityID != b.EntityID || !bytes.Equal(a.PayloadHash, b.PayloadHash) ||
		len(a.Attributes) != len(b.Attributes) {
		return false
	}
	for k, v := range a.Attributes {
		if b.Attributes[k] != v {
			return false
		}
	}
	return true
}
