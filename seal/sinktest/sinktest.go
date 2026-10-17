// Package sinktest is the conformance suite for [seal.Sink] implementations.
package sinktest

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kastrul/tamperlog/seal"
)

// Run checks write-once semantics, reads and listing. newSink returns an
// empty sink; cleanup is registered on t.
func Run(t *testing.T, newSink func(t *testing.T) seal.Sink) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	s := newSink(t)

	if _, err := s.Get(ctx, seal.Key(1)); !errors.Is(err, seal.ErrNotFound) {
		t.Fatalf("Get missing = %v, want ErrNotFound", err)
	}
	keys, err := s.List(ctx, "seals/")
	if err != nil || len(keys) != 0 {
		t.Fatalf("List empty = %v, %v", keys, err)
	}
	for seq := int64(1); seq <= 3; seq++ {
		if err := s.Put(ctx, seal.Key(seq), []byte{byte(seq)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Put(ctx, seal.ProofKey(2, "rfc3161"), []byte("proof")); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, seal.Key(2), []byte("replaced")); !errors.Is(err, seal.ErrExists) {
		t.Fatalf("overwrite = %v, want ErrExists", err)
	}
	got, err := s.Get(ctx, seal.Key(2))
	if err != nil || !bytes.Equal(got, []byte{2}) {
		t.Fatalf("Get after refused overwrite = %q, %v", got, err)
	}
	keys, err = s.List(ctx, "seals/")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{seal.Key(1), seal.Key(2), seal.ProofKey(2, "rfc3161"), seal.Key(3)}
	if len(keys) != len(want) {
		t.Fatalf("List = %v, want %v", keys, want)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Fatalf("List = %v, want %v", keys, want)
		}
	}
	keys, err = s.List(ctx, "seals/000000000003")
	if err != nil || len(keys) != 1 || keys[0] != seal.Key(3) {
		t.Fatalf("List prefix = %v, %v", keys, err)
	}
	for _, bad := range []string{"", "/abs", "../up", "seals/../x"} {
		if err := s.Put(ctx, bad, []byte("x")); err == nil {
			t.Errorf("Put(%q) accepted", bad)
		}
	}
}
