package otel_test

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel/metric/noop"

	"github.com/kastrul/tamperlog"
	"github.com/kastrul/tamperlog/anchor"
	tlotel "github.com/kastrul/tamperlog/otel"
	"github.com/kastrul/tamperlog/seal"
	"github.com/kastrul/tamperlog/verify"
)

func TestHooksDoNotPanic(t *testing.T) {
	t.Parallel()
	m, err := tlotel.New(noop.NewMeterProvider().Meter("test"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	m.AppenderHooks().OnAppend(ctx, tamperlog.Record{Event: tamperlog.Event{Stream: "s", Action: "a"}})
	m.WriterHooks().OnSeal(ctx, seal.Stored{})
	m.WriterHooks().OnSinkError(ctx, nil, "k", nil)
	m.RunnerHooks().OnAnchored(ctx, seal.Proof{Provider: "p"}, anchor.Attestation{})
	m.RunnerHooks().OnAnchorFailed(ctx, seal.Stored{}, nil)
	m.OnReport()(ctx, &verify.Report{StartedAt: time.Now(), FinishedAt: time.Now(), Streams: map[string]verify.StreamReport{"s": {HeadSeq: 3}}, Findings: []verify.Finding{{Severity: verify.Error, Layer: verify.LayerChain, Code: "x"}}})
}
