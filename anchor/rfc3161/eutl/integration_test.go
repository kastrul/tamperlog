//go:build integration

package eutl

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestLiveEstonianList loads the real LOTL and the Estonian list. It runs
// only with TAMPERLOG_EUTL_LIVE=1 because it needs the network and the
// national host may rate-limit or challenge automated clients.
func TestLiveEstonianList(t *testing.T) {
	if os.Getenv("TAMPERLOG_EUTL_LIVE") != "1" {
		t.Skip("set TAMPERLOG_EUTL_LIVE=1 to load the live trusted lists")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	list, err := NewLoader(WithCacheDir(t.TempDir()), WithTerritories("EE")).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("LOTL sequence %d issued %s next update %s, %d pointers",
		list.LOTL.SequenceNumber, list.LOTL.ListIssueDateTime.Format(time.RFC3339), list.LOTL.NextUpdate.Format(time.RFC3339), len(list.LOTL.Pointers))
	if err := list.Errors["EE"]; err != nil {
		t.Fatalf("EE list did not load: %v", err)
	}
	if time.Now().After(list.LOTL.NextUpdate) {
		t.Errorf("LOTL NextUpdate %s has passed", list.LOTL.NextUpdate)
	}
	found := 0
	for _, s := range list.Services {
		if s.Type != TypeQTST {
			continue
		}
		found++
		cur := s.History[len(s.History)-1]
		t.Logf("EE QTST: provider %q service %q status %s since %s (%d certificates, %d periods)",
			s.Provider, s.Name, cur.Status, cur.From.Format(time.DateOnly), len(cur.Identity.Certificates), len(s.History))
	}
	if found == 0 {
		t.Fatal("no QTST service on the Estonian list")
	}
}
