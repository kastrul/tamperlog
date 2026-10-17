package memory_test

import (
	"testing"
	"time"

	"github.com/kastrul/tamperlog/internal/storetest"
	"github.com/kastrul/tamperlog/store/memory"
)

func TestConformance(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(*testing.T) storetest.Provider { return memory.New() })
}

func TestClockIsInjectable(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	s := memory.New(memory.WithClock(func() time.Time { now = now.Add(time.Second); return now }))
	tx, err := s.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context()) //nolint:errcheck // cleanup
	h, err := tx.Head(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	if !h.Now.Equal(time.Date(2026, 10, 17, 12, 0, 1, 0, time.UTC)) {
		t.Fatalf("Now = %s", h.Now)
	}
}
