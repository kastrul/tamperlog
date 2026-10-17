// Command sealing runs the whole pipeline in memory: append, seal to a
// directory sink, anchor at the SK ID Solutions demo TSA when TAMPERLOG_TSA_ROOTS
// points at its test CA (otherwise anchoring is skipped), verify, export a
// bundle and verify that bundle offline.
//
//	TAMPERLOG_TSA_ROOTS=test_sk_tsa_ca_2023e.pem go run ./examples/sealing
package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/kastrul/tamperlog"
	"github.com/kastrul/tamperlog/anchor"
	"github.com/kastrul/tamperlog/anchor/rfc3161"
	"github.com/kastrul/tamperlog/bundle"
	"github.com/kastrul/tamperlog/seal"
	"github.com/kastrul/tamperlog/seal/sinks/fs"
	"github.com/kastrul/tamperlog/store/memory"
	"github.com/kastrul/tamperlog/verify"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx := context.Background()
	dir, err := os.MkdirTemp("", "tamperlog-sealing")
	if err != nil {
		return err
	}
	fmt.Println("working directory:", dir)

	store := memory.New()
	audit := tamperlog.NewLog(store)
	for i := range 5 {
		if _, err := audit.Append(ctx, tamperlog.Event{Stream: "access", Actor: "clinician-7", Subject: "patient-42", Action: "record.read", Entity: "patient_record", EntityID: fmt.Sprintf("r%d", i)}); err != nil {
			return err
		}
	}

	sink, err := fs.New(filepath.Join(dir, "sink"))
	if err != nil {
		return err
	}
	writer := seal.NewWriter(store, seal.WithSinks(sink), seal.WithWriterName("sealing-example"))
	st, err := writer.Seal(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("seal %d written, hash %x\n", st.Seq, st.Hash)

	var vopts []verify.Option
	if rootsFile := os.Getenv("TAMPERLOG_TSA_ROOTS"); rootsFile != "" {
		pemBytes, err := os.ReadFile(rootsFile) //nolint:gosec // operator-supplied path
		if err != nil {
			return err
		}
		roots := x509.NewCertPool()
		roots.AppendCertsFromPEM(pemBytes)
		tsa := rfc3161.NewProvider(rfc3161.New("http://tsa.demo.sk.ee/tsa"), rfc3161.NewVerifier(roots))
		runner := anchor.NewRunner(store, tsa, anchor.WithSinks(sink), anchor.WithLog(audit),
			anchor.WithRunnerHooks(anchor.RunnerHooks{OnAnchored: func(_ context.Context, p seal.Proof, a anchor.Attestation) {
				fmt.Printf("seal %d anchored by %q at %s (accuracy %s)\n", p.SealSeq, a.Authority, a.Time.Format(time.RFC3339), a.Accuracy)
			}}))
		if _, err := runner.Once(ctx); err != nil {
			return err
		}
		vopts = append(vopts, verify.WithAnchors(tsa))
	} else {
		fmt.Println("TAMPERLOG_TSA_ROOTS not set: skipping anchoring")
	}

	v := verify.New(append(vopts, verify.WithSinks(sink))...)
	fmt.Println("online:", v.Verify(ctx, verify.FromProvider(store), nil).Summary())

	bundleDir := filepath.Join(dir, "bundle")
	if _, err := bundle.Export(ctx, verify.FromProvider(store), bundleDir, bundle.ExportOptions{Writer: "sealing-example"}); err != nil {
		return err
	}
	b, err := bundle.Open(bundleDir)
	if err != nil {
		return err
	}
	fmt.Println("offline:", v.Verify(ctx, b, nil).Summary())
	return nil
}
