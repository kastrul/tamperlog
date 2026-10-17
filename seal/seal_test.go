package seal_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/kastrul/tamperlog/seal"
)

func valid() *seal.Seal {
	return &seal.Seal{
		Schema:       seal.Schema,
		Seq:          1,
		SealedAt:     time.Date(2026, 10, 17, 14, 0, 0, 0, time.UTC),
		PrevSealHash: seal.GenesisHash,
		Streams: []seal.StreamHead{
			{Stream: "audit", Encoder: "binary/v1", Hasher: "sha256", FirstKeptSeq: 1, HeadSeq: 10, HeadHash: bytes.Repeat([]byte{1}, 32)},
			{Stream: "auth", Encoder: "binary/v1", Hasher: "sha256", FirstKeptSeq: 3, HeadSeq: 3, HeadHash: bytes.Repeat([]byte{2}, 32)},
		},
		Drops:  []seal.Hex{bytes.Repeat([]byte{3}, 32)},
		Writer: "tamperlog-test",
	}
}

func TestCanonicalRoundTrip(t *testing.T) {
	t.Parallel()
	s := valid()
	b, err := s.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"drops":["0303030303030303030303030303030303030303030303030303030303030303"],"prev_seal_hash":"0000000000000000000000000000000000000000000000000000000000000000","schema":"tamperlog.seal/1","sealed_at":"2026-10-17T14:00:00Z","seq":1,"streams":[{"encoder":"binary/v1","first_kept_seq":1,"hasher":"sha256","head_hash":"0101010101010101010101010101010101010101010101010101010101010101","head_seq":10,"stream":"audit"},{"encoder":"binary/v1","first_kept_seq":3,"hasher":"sha256","head_hash":"0202020202020202020202020202020202020202020202020202020202020202","head_seq":3,"stream":"auth"}],"writer":"tamperlog-test"}`
	if string(b) != want {
		t.Fatalf("canonical =\n%s\nwant\n%s", b, want)
	}
	p, err := seal.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if p.Seq != 1 || len(p.Streams) != 2 || p.Streams[1].HeadSeq != 3 || !p.SealedAt.Equal(s.SealedAt) {
		t.Fatalf("parsed %+v", p)
	}
	if _, err := seal.Parse(append([]byte("  "), b...)); !errors.Is(err, seal.ErrNotCanonical) {
		t.Fatalf("non-canonical bytes accepted: %v", err)
	}
	if _, err := seal.Parse(bytes.Replace(b, []byte(`"seq":1`), []byte(`"seq":1,"extra":true`), 1)); err == nil {
		t.Fatal("unknown member accepted")
	}
}

func TestSigningBytesExcludeSignature(t *testing.T) {
	t.Parallel()
	s := valid()
	unsigned, _ := s.Canonical()
	s.KeyID = "k1"
	s.Signature = bytes.Repeat([]byte{9}, 64)
	signing, err := s.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	full, err := s.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(signing, []byte(`"key_id":"k1"`)) || bytes.Contains(signing, []byte("signature")) {
		t.Fatalf("signing bytes = %s", signing)
	}
	if !bytes.Contains(full, []byte(`"signature":"0909`)) {
		t.Fatalf("canonical = %s", full)
	}
	if bytes.Equal(unsigned, signing) {
		t.Fatal("key_id did not change the signing bytes")
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()
	cases := map[string]func(*seal.Seal){
		"schema":          func(s *seal.Seal) { s.Schema = "x" },
		"seq zero":        func(s *seal.Seal) { s.Seq = 0 },
		"genesis":         func(s *seal.Seal) { s.PrevSealHash = bytes.Repeat([]byte{1}, 32) },
		"prev hash size":  func(s *seal.Seal) { s.Seq = 2; s.PrevSealHash = []byte{1} },
		"unsorted":        func(s *seal.Seal) { s.Streams[0], s.Streams[1] = s.Streams[1], s.Streams[0] },
		"duplicate":       func(s *seal.Seal) { s.Streams[1].Stream = "audit" },
		"bad stream name": func(s *seal.Seal) { s.Streams[0].Stream = "Audit" },
		"no encoder":      func(s *seal.Seal) { s.Streams[0].Encoder = "" },
		"range":           func(s *seal.Seal) { s.Streams[0].FirstKeptSeq = 11 },
		"first kept zero": func(s *seal.Seal) { s.Streams[0].FirstKeptSeq = 0 },
		"head hash size":  func(s *seal.Seal) { s.Streams[0].HeadHash = []byte{1} },
		"drop size":       func(s *seal.Seal) { s.Drops = []seal.Hex{{1}} },
		"writer":          func(s *seal.Seal) { s.Writer = "" },
		"signature only":  func(s *seal.Seal) { s.Signature = []byte{1} },
		"key id only":     func(s *seal.Seal) { s.KeyID = "k" },
	}
	for name, mutate := range cases {
		s := valid()
		mutate(s)
		if err := s.Validate(); !errors.Is(err, seal.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := s.Canonical(); err == nil {
			t.Errorf("%s: Canonical accepted an invalid seal", name)
		}
	}
	s := valid()
	s.Seq = 2
	s.PrevSealHash = bytes.Repeat([]byte{7}, 32)
	s.Streams = nil
	s.Drops = nil
	if err := s.Validate(); err != nil {
		t.Fatalf("empty seal with predecessor: %v", err)
	}
}

func TestKeys(t *testing.T) {
	t.Parallel()
	if seal.Key(42) != "seals/000000000042.json" || seal.ProofKey(42, "rfc3161") != "seals/000000000042.rfc3161.proof" {
		t.Fatal(seal.Key(42), seal.ProofKey(42, "rfc3161"))
	}
	if !bytes.Equal(seal.Hash([]byte("x")), seal.Hash([]byte("x"))) || len(seal.Hash(nil)) != 32 {
		t.Fatal("hash")
	}
}
