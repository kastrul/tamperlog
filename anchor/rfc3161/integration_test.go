//go:build integration

package rfc3161_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/kastrul/tamperlog/anchor/rfc3161"
)

// TestLiveTSA anchors a random digest with a real TSA.
//
//	TAMPERLOG_TSA_URL             endpoint; when empty, SK's demo endpoint is
//	                              used only if TAMPERLOG_TSA_LIVE=1, else skip
//	TAMPERLOG_TSA_TRUST_RESPONSE  "1" verifies the token with a root pool built
//	                              from the top certificate the response itself
//	                              carries. That proves the token is internally
//	                              consistent, not that it comes from SK: a real
//	                              deployment pins SK's published root instead
//	                              (docs/anchors/rfc3161.md).
func TestLiveTSA(t *testing.T) {
	tsaURL := os.Getenv("TAMPERLOG_TSA_URL")
	if tsaURL == "" {
		if os.Getenv("TAMPERLOG_TSA_LIVE") != "1" {
			t.Skip("set TAMPERLOG_TSA_URL or TAMPERLOG_TSA_LIVE=1 to talk to a TSA")
		}
		tsaURL = "http://tsa.demo.sk.ee/tsa"
	}
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(seed[:])

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	client := rfc3161.New(tsaURL, rfc3161.WithUserAgent("tamperlog integration test"))
	token, err := client.Anchor(ctx, digest[:])
	if err != nil {
		var uerr *url.Error
		var nerr net.Error
		if errors.As(err, &uerr) || errors.As(err, &nerr) || errors.Is(err, context.DeadlineExceeded) {
			t.Skipf("TSA unreachable: %v", err)
		}
		t.Fatalf("Anchor: %v", err)
	}

	tok, err := rfc3161.ParseToken(token)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	t.Logf("token: %d bytes, genTime %s, accuracy %s, policy %s, serial %s, tsa %q, %d certificates",
		len(token), tok.GenTime.Format(time.RFC3339Nano), tok.Accuracy, tok.Policy, tok.SerialNumber, tok.TSA, len(tok.Certificates))
	for _, c := range tok.Certificates {
		t.Logf("  certificate: subject %q issuer %q not after %s", c.Subject, c.Issuer, c.NotAfter.Format(time.RFC3339))
	}
	if !bytes.Equal(tok.MessageImprint.HashedMessage, digest[:]) {
		t.Fatal("imprint differs from the digest sent")
	}
	if tok.SignerCertificate == nil {
		t.Fatal("response carries no signer certificate; was certReq honoured?")
	}
	if time.Since(tok.GenTime).Abs() > 10*time.Minute {
		t.Errorf("genTime %s is far from local time %s", tok.GenTime, time.Now().UTC())
	}

	if os.Getenv("TAMPERLOG_TSA_TRUST_RESPONSE") != "1" {
		t.Log("verification skipped: set TAMPERLOG_TSA_TRUST_RESPONSE=1 to verify against the response's own top certificate, or pin the operator's root in a real deployment")
		return
	}
	roots := x509.NewCertPool()
	roots.AddCert(topOfChain(tok.Certificates, tok.SignerCertificate))
	v := rfc3161.NewVerifier(roots)
	att, err := v.Verify(ctx, digest[:], token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	t.Logf("verified (trust anchored in the response itself): time %s accuracy %s authority %q details %v",
		att.Time.Format(time.RFC3339), att.Accuracy, att.Authority, att.Details)
	if _, err := v.Verify(ctx, seed[:], token); err == nil {
		t.Fatal("token verified against a different digest")
	}
}

// topOfChain follows issuer links from the signer through the included
// certificates and returns the last one reached.
func topOfChain(certs []*x509.Certificate, signer *x509.Certificate) *x509.Certificate {
	cur := signer
	for range certs {
		var next *x509.Certificate
		for _, c := range certs {
			if !c.Equal(cur) && bytes.Equal(c.RawSubject, cur.RawIssuer) {
				next = c
				break
			}
		}
		if next == nil {
			break
		}
		cur = next
	}
	return cur
}
