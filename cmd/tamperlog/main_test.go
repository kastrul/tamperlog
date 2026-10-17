package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/alecthomas/kong"
)

// runCLI parses args against the command tree and runs them, capturing
// stdout.
func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var c cli
	parser, err := kong.New(&c, kong.Name("tamperlog"), kong.Exit(func(int) {}))
	if err != nil {
		t.Fatal(err)
	}
	k, err := parser.Parse(args)
	if err != nil {
		return "", err
	}
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	runErr := k.Run(&runContext{ctx: context.Background(), logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String(), runErr
}

func TestSQLiteEndToEnd(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "audit.db")
	sink := filepath.Join(dir, "sink")
	store := []string{"--driver", "sqlite", "--dsn", db}

	if _, err := runCLI(t, append([]string{"migrate"}, store...)...); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := runCLI(t, append([]string{"append", "--stream", "audit", "--action", "record.read", "--entity", "patient_record", "--entity-id", "r1", "--actor", "u1", "--attr", "purpose=treatment"}, store...)...); err != nil {
			t.Fatal(err)
		}
	}
	out, err := runCLI(t, append([]string{"seal", "--once", "--sink-dir", sink}, store...)...)
	if err != nil || !bytes.Contains([]byte(out), []byte("seal 1 ")) {
		t.Fatalf("seal: %v\n%s", err, out)
	}
	// Without an explicit scope the command refuses to run (exit 2).
	_, err = runCLI(t, append([]string{"verify", "--sink-dir", sink}, store...)...)
	var scopeExit *exitError
	if !asExit(err, &scopeExit) || scopeExit.code != 2 {
		t.Fatalf("verify without scope: %v", err)
	}
	out, err = runCLI(t, append([]string{"verify", "--sink-dir", sink, "--no-anchors", "--max-seal-age", "24h"}, store...)...)
	if err != nil || !bytes.Contains([]byte(out), []byte("verified: 1 streams, 1 seals")) {
		t.Fatalf("verify: %v\n%s", err, out)
	}
	bundleDir := filepath.Join(dir, "bundle")
	if _, err := runCLI(t, append([]string{"export", "--out", bundleDir}, store...)...); err != nil {
		t.Fatal(err)
	}
	out, err = runCLI(t, "verify", "--bundle", bundleDir, "--sink-dir", sink, "--json", "--no-anchors")
	if err != nil || !bytes.Contains([]byte(out), []byte(`"full": true`)) {
		t.Fatalf("offline verify: %v\n%s", err, out)
	}
	if _, err := runCLI(t, "inspect", "seal", filepath.Join(sink, "seals", "000000000001.json")); err != nil {
		t.Fatal(err)
	}
	// A tampered sink copy is a verification failure with exit code 1.
	p := filepath.Join(sink, "seals", "000000000001.json")
	_ = os.Chmod(p, 0o600)
	if err := os.WriteFile(p, []byte(`{"forged":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = runCLI(t, append([]string{"verify", "--sink-dir", sink, "--no-anchors", "--max-seal-age", "24h"}, store...)...)
	var exit *exitError
	if !asExit(err, &exit) || exit.code != 1 {
		t.Fatalf("tampered sink: %v", err)
	}
	// An unreadable source is an operational failure (exit 2), not a finding.
	_, err = runCLI(t, "verify", "--driver", "sqlite", "--dsn", filepath.Join(dir, "missing.db"), "--no-sinks", "--no-anchors", "--no-freshness")
	if !asExit(err, &exit) || exit.code != 2 {
		t.Fatalf("missing database: %v", err)
	}
}
