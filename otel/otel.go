// Package otel instruments tamperlog with OpenTelemetry metrics through the
// hook points of the appender, the seal writer, the anchor runner and the
// verifier. It depends on the OpenTelemetry API only; the application
// installs the SDK and exporter.
//
// Instruments (all with the prefix "tamperlog."):
//
//	tamperlog.appends            counter      {stream, action}
//	tamperlog.seals              counter      {}
//	tamperlog.seal_sink_errors   counter      {sink}
//	tamperlog.anchors            counter      {provider, qualified}
//	tamperlog.anchor_failures    counter      {provider}
//	tamperlog.verifications      counter      {outcome}
//	tamperlog.verify_findings    counter      {severity, layer, code}
//	tamperlog.verify_duration    histogram    seconds
//	tamperlog.head_seq           gauge        {stream}   last seen head after verification
//	tamperlog.unanchored_seals   gauge                   seals without a valid proof in the last run
package otel

import (
	"context"
	"fmt"
	"strconv"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/kastrul/tamperlog"
	"github.com/kastrul/tamperlog/anchor"
	"github.com/kastrul/tamperlog/seal"
	"github.com/kastrul/tamperlog/verify"
)

// Metrics holds the instruments.
type Metrics struct {
	appends        metric.Int64Counter
	seals          metric.Int64Counter
	sinkErrors     metric.Int64Counter
	anchors        metric.Int64Counter
	anchorFailures metric.Int64Counter
	verifications  metric.Int64Counter
	findings       metric.Int64Counter
	verifyDuration metric.Float64Histogram
	headSeq        metric.Int64Gauge
	unanchored     metric.Int64Gauge
}

// New creates the instruments on m.
func New(m metric.Meter) (*Metrics, error) {
	var x Metrics
	var err error
	if x.appends, err = m.Int64Counter("tamperlog.appends", metric.WithDescription("Records appended")); err != nil {
		return nil, err
	}
	if x.seals, err = m.Int64Counter("tamperlog.seals", metric.WithDescription("Seals written")); err != nil {
		return nil, err
	}
	if x.sinkErrors, err = m.Int64Counter("tamperlog.seal_sink_errors", metric.WithDescription("Failed sink puts")); err != nil {
		return nil, err
	}
	if x.anchors, err = m.Int64Counter("tamperlog.anchors", metric.WithDescription("Proofs obtained")); err != nil {
		return nil, err
	}
	if x.anchorFailures, err = m.Int64Counter("tamperlog.anchor_failures", metric.WithDescription("Seals unanchored past the grace period")); err != nil {
		return nil, err
	}
	if x.verifications, err = m.Int64Counter("tamperlog.verifications", metric.WithDescription("Verification runs by outcome")); err != nil {
		return nil, err
	}
	if x.findings, err = m.Int64Counter("tamperlog.verify_findings", metric.WithDescription("Verification findings")); err != nil {
		return nil, err
	}
	if x.verifyDuration, err = m.Float64Histogram("tamperlog.verify_duration", metric.WithDescription("Verification run duration"), metric.WithUnit("s")); err != nil {
		return nil, err
	}
	if x.headSeq, err = m.Int64Gauge("tamperlog.head_seq", metric.WithDescription("Head sequence per stream at the last verification")); err != nil {
		return nil, err
	}
	if x.unanchored, err = m.Int64Gauge("tamperlog.unanchored_seals", metric.WithDescription("Seals without a valid proof at the last verification")); err != nil {
		return nil, err
	}
	return &x, nil
}

// AppenderHooks returns hooks for [tamperlog.WithHooks].
func (x *Metrics) AppenderHooks() tamperlog.Hooks {
	return tamperlog.Hooks{OnAppend: func(ctx context.Context, r tamperlog.Record) {
		x.appends.Add(ctx, 1, metric.WithAttributes(attribute.String("stream", r.Stream), attribute.String("action", r.Action)))
	}}
}

// WriterHooks returns hooks for [seal.WithWriterHooks].
func (x *Metrics) WriterHooks() seal.WriterHooks {
	return seal.WriterHooks{
		OnSeal: func(ctx context.Context, _ seal.Stored) { x.seals.Add(ctx, 1) },
		OnSinkError: func(ctx context.Context, s seal.Sink, _ string, _ error) {
			x.sinkErrors.Add(ctx, 1, metric.WithAttributes(attribute.String("sink", fmt.Sprintf("%T", s))))
		},
	}
}

// RunnerHooks returns hooks for [anchor.WithRunnerHooks].
func (x *Metrics) RunnerHooks() anchor.RunnerHooks {
	return anchor.RunnerHooks{
		OnAnchored: func(ctx context.Context, p seal.Proof, a anchor.Attestation) {
			x.anchors.Add(ctx, 1, metric.WithAttributes(attribute.String("provider", p.Provider), attribute.Bool("qualified", a.Qualified)))
		},
		OnAnchorFailed: func(ctx context.Context, _ seal.Stored, _ error) {
			x.anchorFailures.Add(ctx, 1)
		},
	}
}

// OnReport returns a callback for [verify.WithOnReport].
func (x *Metrics) OnReport() func(ctx context.Context, rep *verify.Report) {
	return func(ctx context.Context, rep *verify.Report) {
		outcome := "verified"
		if !rep.OK() {
			outcome = "broken"
		}
		x.verifications.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", outcome)))
		x.verifyDuration.Record(ctx, rep.FinishedAt.Sub(rep.StartedAt).Seconds())
		for _, f := range rep.Findings {
			x.findings.Add(ctx, 1, metric.WithAttributes(attribute.String("severity", string(f.Severity)), attribute.String("layer", string(f.Layer)), attribute.String("code", f.Code)))
		}
		for name, s := range rep.Streams {
			x.headSeq.Record(ctx, s.HeadSeq, metric.WithAttributes(attribute.String("stream", name)))
		}
		x.unanchored.Record(ctx, rep.Seals.Count-rep.Seals.Anchored)
	}
}

// Attr is a helper for callers adding their own attributes.
func Attr(key string, seq int64) attribute.KeyValue {
	return attribute.String(key, strconv.FormatInt(seq, 10))
}
