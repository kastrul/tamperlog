package rfc3161_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/kastrul/tamperlog/anchor"
	"github.com/kastrul/tamperlog/anchor/rfc3161"
)

func digestOf(s string) []byte {
	d := sha256.Sum256([]byte(s))
	return d[:]
}

// anchorWith runs Provider.Anchor against the test TSA and returns the token.
func anchorWith(t *testing.T, s *tsa, digest []byte, opts ...rfc3161.Option) ([]byte, error) {
	t.Helper()
	srv := s.serve()
	p := rfc3161.NewProvider(rfc3161.New(srv.URL, opts...), rfc3161.NewVerifier(s.roots(), opts...))
	return p.Anchor(context.Background(), digest)
}

func mustAnchor(t *testing.T, s *tsa, digest []byte, opts ...rfc3161.Option) []byte {
	t.Helper()
	tok, err := anchorWith(t, s, digest, opts...)
	if err != nil {
		t.Fatalf("Anchor: %v", err)
	}
	return tok
}

func wantInvalid(t *testing.T, err error, substr string) {
	t.Helper()
	if err == nil {
		t.Fatalf("want error containing %q, got nil", substr)
	}
	if !errors.Is(err, anchor.ErrInvalidProof) {
		t.Fatalf("error %v does not wrap anchor.ErrInvalidProof", err)
	}
	if !strings.Contains(err.Error(), substr) {
		t.Fatalf("error %q does not contain %q", err, substr)
	}
}

func TestRoundTrip(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*tsa)
	}{
		{"ecdsa-p256", func(*tsa) {}},
		{"rsa-2048-pkcs1-rsaEncryption", func(s *tsa) { s.scheme = schemeRSAPKCS1 }},
		{"rsa-2048-pkcs1-sha256WithRSA", func(s *tsa) { s.scheme = schemeRSASHA256 }},
		{"rsa-2048-pss", func(s *tsa) { s.scheme = schemeRSAPSS }},
		{"ess-v1-sha1", func(s *tsa) { s.essV1 = true }},
		{"ess-v2-sha512", func(s *tsa) { s.essV2Hash = oidSHA512 }},
		{"with-root-and-tsa-name", func(s *tsa) { s.includeRoot = true; s.includeTSAName = true }},
		{"fractional-gentime", func(s *tsa) {
			s.genTimeRaw = s.genTime.Format("20060102150405") + ".25Z"
			s.genTime = s.genTime.Add(250 * time.Millisecond)
		}},
		{"accuracy-millis-micros", func(s *tsa) { s.accuracy = 1*time.Second + 500*time.Millisecond + 7*time.Microsecond }},
		{"no-accuracy", func(s *tsa) { s.accuracy = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTSA(t, schemeECDSA)
			tc.setup(s)
			if s.scheme != schemeECDSA {
				s.key = testRSAKey(t)
				s.cert = s.root.issueTSA(t, s.key, ekuCritical, "tamperlog TEST TSA RSA")
			}
			digest := digestOf("seal " + tc.name)
			token := mustAnchor(t, s, digest)

			v := rfc3161.NewVerifier(s.roots())
			att, err := v.Verify(context.Background(), digest, token)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !att.Time.Equal(s.genTime) {
				t.Errorf("Time = %s, want %s", att.Time, s.genTime)
			}
			if att.Accuracy != s.accuracy {
				t.Errorf("Accuracy = %s, want %s", att.Accuracy, s.accuracy)
			}
			if att.Authority != s.cert.Subject.String() {
				t.Errorf("Authority = %q, want %q", att.Authority, s.cert.Subject.String())
			}
			if att.Qualified {
				t.Error("Qualified = true without a checker")
			}
			if att.Details["policy"] != oidSKPolicy.String() {
				t.Errorf("policy = %q", att.Details["policy"])
			}
			if att.Details["serial"] != s.serial.String() {
				t.Errorf("serial = %q, want %s", att.Details["serial"], s.serial)
			}
			fp := sha256.Sum256(s.cert.Raw)
			if att.Details["signer_sha256"] != hex.EncodeToString(fp[:]) {
				t.Errorf("signer_sha256 = %q", att.Details["signer_sha256"])
			}
			if _, ok := att.Details["tsa"]; ok != s.includeTSAName {
				t.Errorf("tsa detail present = %v, want %v", ok, s.includeTSAName)
			}
			if s.includeTSAName && att.Details["tsa"] != s.cert.Subject.String() {
				t.Errorf("tsa = %q", att.Details["tsa"])
			}

			// Ensure the token is the ContentInfo, not the whole response.
			if _, err := rfc3161.ParseToken(token); err != nil {
				t.Fatalf("ParseToken: %v", err)
			}
		})
	}
}

func TestParseTokenFields(t *testing.T) {
	s := newTSA(t, schemeECDSA)
	s.includeRoot = true
	digest := digestOf("fields")
	token := mustAnchor(t, s, digest)
	tok, err := rfc3161.ParseToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if !tok.GenTime.Equal(s.genTime) || tok.Accuracy != time.Second || !tok.Policy.Equal(oidSKPolicy) {
		t.Errorf("GenTime/Accuracy/Policy = %s %s %s", tok.GenTime, tok.Accuracy, tok.Policy)
	}
	if tok.SerialNumber.Cmp(s.serial) != 0 || tok.Nonce == nil || tok.Nonce.Sign() == 0 {
		t.Errorf("SerialNumber = %s, Nonce = %v", tok.SerialNumber, tok.Nonce)
	}
	if !tok.MessageImprint.HashAlgorithm.Equal(oidSHA256) || !bytes.Equal(tok.MessageImprint.HashedMessage, digest) {
		t.Errorf("MessageImprint = %+v", tok.MessageImprint)
	}
	if tok.SignerCertificate == nil || !tok.SignerCertificate.Equal(s.cert) {
		t.Error("SignerCertificate is not the TSA certificate")
	}
	if len(tok.Certificates) != 2 {
		t.Errorf("Certificates = %d, want 2", len(tok.Certificates))
	}
}

func TestClientRequest(t *testing.T) {
	s := newTSA(t, schemeECDSA)
	srv := s.serve()
	digest := digestOf("request")
	c := rfc3161.New(srv.URL, rfc3161.WithPolicy(oidSKPolicy), rfc3161.WithUserAgent("tamperlog-test/1"))
	if _, err := c.Anchor(context.Background(), digest); err != nil {
		t.Fatal(err)
	}
	req := s.lastRequest
	if req.Version != 1 {
		t.Errorf("version = %d", req.Version)
	}
	if !req.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) {
		t.Errorf("hash algorithm = %s", req.MessageImprint.HashAlgorithm.Algorithm)
	}
	if p := req.MessageImprint.HashAlgorithm.Parameters; p.Tag != asn1.TagNull || p.Class != asn1.ClassUniversal {
		t.Errorf("hash algorithm parameters = %+v, want NULL", p)
	}
	if !bytes.Equal(req.MessageImprint.HashedMessage, digest) {
		t.Error("imprint differs")
	}
	if !req.ReqPolicy.Equal(oidSKPolicy) {
		t.Errorf("reqPolicy = %s", req.ReqPolicy)
	}
	if req.Nonce == nil || req.Nonce.BitLen() > 64 {
		t.Errorf("nonce = %v", req.Nonce)
	}
	if !req.CertReq {
		t.Error("certReq not set")
	}
	if got := s.lastHeaders.Get("Content-Type"); got != rfc3161.ContentTypeQuery {
		t.Errorf("Content-Type = %q", got)
	}
	if got := s.lastHeaders.Get("Accept"); got != rfc3161.ContentTypeReply {
		t.Errorf("Accept = %q", got)
	}
	if got := s.lastHeaders.Get("User-Agent"); got != "tamperlog-test/1" {
		t.Errorf("User-Agent = %q", got)
	}

	// Second request: certReq off and no policy.
	c = rfc3161.New(srv.URL, rfc3161.WithCertReq(false))
	_, _ = c.Anchor(context.Background(), digest)
	if s.lastRequest.CertReq || s.lastRequest.ReqPolicy != nil {
		t.Errorf("certReq=%v reqPolicy=%v, want false and nil", s.lastRequest.CertReq, s.lastRequest.ReqPolicy)
	}
}

func TestClientRejectsBadDigestLength(t *testing.T) {
	c := rfc3161.New("http://127.0.0.1:1/never")
	if _, err := c.Anchor(context.Background(), []byte("short")); err == nil || !strings.Contains(err.Error(), "32") {
		t.Fatalf("err = %v", err)
	}
}

func TestClientTransportErrors(t *testing.T) {
	ct := func(v string) *string { return &v }
	cases := []struct {
		name  string
		setup func(*tsa)
		want  string
	}{
		{"http-500", func(s *tsa) { s.httpStatus = http.StatusInternalServerError }, "HTTP 500"},
		{"wrong-content-type", func(s *tsa) { s.contentType = ct("text/html") }, "content type"},
		{"oversized", func(s *tsa) { s.rawBody = make([]byte, rfc3161.MaxResponseSize+1) }, "exceeds"},
		{"trailing-bytes", func(s *tsa) { s.rawBody = append(s.respond(digestOf("x"), nil), 0) }, "trailing"},
		{"garbage", func(s *tsa) { s.rawBody = []byte("not DER") }, "malformed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTSA(t, schemeECDSA)
			tc.setup(s)
			srv := s.serve()
			_, err := rfc3161.New(srv.URL).Anchor(context.Background(), digestOf("x"))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestClientToleratesMissingContentType(t *testing.T) {
	s := newTSA(t, schemeECDSA)
	empty := ""
	s.contentType = &empty
	srv := s.serve()
	if _, err := rfc3161.New(srv.URL).Anchor(context.Background(), digestOf("x")); err != nil {
		t.Fatal(err)
	}
}

func TestClientReportsStatusRejection(t *testing.T) {
	s := newTSA(t, schemeECDSA)
	s.status = rfc3161.StatusRejection
	s.failInfoBits = []int{15, 25}
	s.statusStrings = []string{"policy not supported"}
	srv := s.serve()
	_, err := rfc3161.New(srv.URL).Anchor(context.Background(), digestOf("x"))
	var se *rfc3161.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("err = %v, want *StatusError", err)
	}
	if se.Status != rfc3161.StatusRejection || !se.FailInfo.Has("unacceptedPolicy") || !se.FailInfo.Has("systemFailure") {
		t.Errorf("StatusError = %+v", se)
	}
	for _, want := range []string{"status 2 (rejection)", "unacceptedPolicy", "systemFailure", "policy not supported"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q lacks %q", err, want)
		}
	}

	s.status = rfc3161.StatusWaiting
	s.failInfoBits = nil
	s.statusStrings = nil
	_, err = rfc3161.New(srv.URL).Anchor(context.Background(), digestOf("x"))
	if !errors.As(err, &se) || se.Status != rfc3161.StatusWaiting {
		t.Fatalf("err = %v", err)
	}
}

func TestClientRejectsWrongNonce(t *testing.T) {
	s := newTSA(t, schemeECDSA)
	s.nonceOverride = bigInt(42)
	srv := s.serve()
	if _, err := rfc3161.New(srv.URL).Anchor(context.Background(), digestOf("x")); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("err = %v", err)
	}
	s.nonceOverride = nil
	s.dropNonce = true
	if _, err := rfc3161.New(srv.URL).Anchor(context.Background(), digestOf("x")); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("err = %v", err)
	}
}

func TestClientRejectsImprintMismatch(t *testing.T) {
	s := newTSA(t, schemeECDSA)
	s.imprintOverride = digestOf("other")
	srv := s.serve()
	if _, err := rfc3161.New(srv.URL).Anchor(context.Background(), digestOf("x")); err == nil || !strings.Contains(err.Error(), "imprint") {
		t.Fatalf("err = %v", err)
	}
}

func TestVerifyRejectsDifferentDigest(t *testing.T) {
	s := newTSA(t, schemeECDSA)
	token := mustAnchor(t, s, digestOf("one"))
	v := rfc3161.NewVerifier(s.roots())
	_, err := v.Verify(context.Background(), digestOf("two"), token)
	wantInvalid(t, err, "messageImprint")
	_, err = v.Verify(context.Background(), []byte("short"), token)
	wantInvalid(t, err, "32")
}

func TestVerifyRejectsTamperedTSTInfo(t *testing.T) {
	s := newTSA(t, schemeECDSA)
	digest := digestOf("tamper")
	token := mustAnchor(t, s, digest)
	v := rfc3161.NewVerifier(s.roots())

	// Flip one byte of the serial number inside the TSTInfo without touching
	// the imprint: the message-digest attribute no longer matches.
	tok, _ := rfc3161.ParseToken(token)
	serial := tok.SerialNumber.Bytes()
	idx := bytes.Index(token, serial)
	if idx < 0 {
		t.Fatal("serial not found in token")
	}
	bad := bytes.Clone(token)
	bad[idx+len(serial)-1] ^= 0x01
	_, err := v.Verify(context.Background(), digest, bad)
	wantInvalid(t, err, "message-digest")

	// The provider catches the same at anchoring time.
	s.tamper = func(tst []byte) []byte {
		out := bytes.Clone(tst)
		i := bytes.Index(out, s.serial.Bytes())
		out[i+len(s.serial.Bytes())-1] ^= 0x01 // the serial, so the client's imprint and nonce checks still pass
		return out
	}
	_, err = anchorWith(t, s, digest)
	if err == nil || !strings.Contains(err.Error(), "fresh token rejected") || !errors.Is(err, anchor.ErrInvalidProof) {
		t.Fatalf("err = %v", err)
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	s := newTSA(t, schemeECDSA)
	digest := digestOf("sig")
	token := mustAnchor(t, s, digest)
	bad := bytes.Clone(token)
	bad[len(bad)-1] ^= 0x01 // last byte of the signature OCTET STRING
	_, err := rfc3161.NewVerifier(s.roots()).Verify(context.Background(), digest, bad)
	wantInvalid(t, err, "signature")
}

func TestVerifyRejectsEKU(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind ekuKind
		want string
	}{
		{"non-critical", ekuNonCritical, "not critical"},
		{"missing", ekuMissing, "key usage"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTSA(t, schemeECDSA)
			s.cert = s.root.issueTSA(t, s.key, tc.kind, "tamperlog TEST TSA")
			_, err := anchorWith(t, s, digestOf("eku"))
			wantInvalid(t, err, tc.want)
		})
	}
}

func TestVerifyRejectsUnrelatedRoot(t *testing.T) {
	s := newTSA(t, schemeECDSA)
	s.includeRoot = true
	digest := digestOf("root")
	token := mustAnchor(t, s, digest)
	other := x509.NewCertPool()
	other.AddCert(newRoot(t, "SOMEBODY ELSE").cert)
	_, err := rfc3161.NewVerifier(other).Verify(context.Background(), digest, token)
	wantInvalid(t, err, "certificate chain")

	// No roots at all: never the system pool.
	_, err = rfc3161.NewVerifier(nil).Verify(context.Background(), digest, token)
	wantInvalid(t, err, "no roots")
	_, err = rfc3161.NewVerifier(x509.NewCertPool()).Verify(context.Background(), digest, token)
	wantInvalid(t, err, "certificate chain")
}

func TestVerifyIntermediatesOption(t *testing.T) {
	s := newTSA(t, schemeECDSA)
	// Issue the TSA from an intermediate that is not included in the token.
	inter := newRoot(t, "tamperlog TEST INTERMEDIATE")
	interDER, err := x509.CreateCertificate(rand.Reader, inter.cert, s.root.cert, inter.key.Public(), s.root.key)
	if err != nil {
		t.Fatal(err)
	}
	inter.cert, err = x509.ParseCertificate(interDER)
	if err != nil {
		t.Fatal(err)
	}
	s.cert = inter.issueTSA(t, s.key, ekuCritical, "tamperlog TEST TSA")
	srv := s.serve()
	digest := digestOf("inter")
	token, err := rfc3161.New(srv.URL).Anchor(context.Background(), digest)
	if err != nil {
		t.Fatal(err)
	}
	_, err = rfc3161.NewVerifier(s.roots()).Verify(context.Background(), digest, token)
	wantInvalid(t, err, "certificate chain")
	pool := x509.NewCertPool()
	pool.AddCert(inter.cert)
	if _, err := rfc3161.NewVerifier(s.roots(), rfc3161.WithIntermediates(pool)).Verify(context.Background(), digest, token); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejectsExpiredAtGenTime(t *testing.T) {
	s := newTSA(t, schemeECDSA)
	s.genTime = s.cert.NotAfter.Add(time.Hour).Truncate(time.Second)
	_, err := anchorWith(t, s, digestOf("late"))
	wantInvalid(t, err, "certificate chain")
}

func TestVerifyRequiredPolicies(t *testing.T) {
	s := newTSA(t, schemeECDSA)
	digest := digestOf("policy")
	token := mustAnchor(t, s, digest)
	_, err := rfc3161.NewVerifier(s.roots(), rfc3161.WithRequiredPolicies(oidOtherPolicy)).Verify(context.Background(), digest, token)
	wantInvalid(t, err, "policy")
	if _, err := rfc3161.NewVerifier(s.roots(), rfc3161.WithRequiredPolicies(oidOtherPolicy, oidSKPolicy)).Verify(context.Background(), digest, token); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyMaxAccuracy(t *testing.T) {
	s := newTSA(t, schemeECDSA)
	s.accuracy = 2 * time.Second
	digest := digestOf("acc")
	token := mustAnchor(t, s, digest)
	_, err := rfc3161.NewVerifier(s.roots(), rfc3161.WithMaxAccuracy(time.Second)).Verify(context.Background(), digest, token)
	wantInvalid(t, err, "accuracy")
	if _, err := rfc3161.NewVerifier(s.roots(), rfc3161.WithMaxAccuracy(2*time.Second)).Verify(context.Background(), digest, token); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyESSCertID(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*tsa)
		want  string
	}{
		{"v2-mismatch", func(s *tsa) { s.essMismatch = true }, "signing-certificate-v2"},
		{"v1-mismatch", func(s *tsa) { s.essV1 = true; s.essMismatch = true }, "signing-certificate:"},
		{"missing", func(s *tsa) { s.omitESS = true }, "signing-certificate attribute missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTSA(t, schemeECDSA)
			tc.setup(s)
			_, err := anchorWith(t, s, digestOf("ess"))
			wantInvalid(t, err, tc.want)
		})
	}
}

func TestVerifyRejectsMismatchedAlgorithms(t *testing.T) {
	s := newTSA(t, schemeRSAPKCS1)
	s.sigAlgOverride = oidSHA384WithRSA // digestAlgorithm says SHA-256
	_, err := anchorWith(t, s, digestOf("alg"))
	wantInvalid(t, err, "disagrees")

	s = newTSA(t, schemeECDSA)
	s.sigAlgOverride = oidSHA256WithRSA // RSA algorithm, ECDSA key
	_, err = anchorWith(t, s, digestOf("alg"))
	wantInvalid(t, err, "signer key is")
}

func TestVerifyRejectsSignerNotIncluded(t *testing.T) {
	s := newTSA(t, schemeECDSA)
	s.omitCerts = true
	_, err := anchorWith(t, s, digestOf("nocerts"))
	wantInvalid(t, err, "signer certificate")
}

func TestVerifyQualifiedChecker(t *testing.T) {
	s := newTSA(t, schemeECDSA)
	digest := digestOf("q")
	token := mustAnchor(t, s, digest)
	var gotCert *x509.Certificate
	var gotAt time.Time
	v := rfc3161.NewVerifier(s.roots(), rfc3161.WithQualifiedChecker(func(c *x509.Certificate, at time.Time) (bool, error) {
		gotCert, gotAt = c, at
		return true, nil
	}))
	att, err := v.Verify(context.Background(), digest, token)
	if err != nil {
		t.Fatal(err)
	}
	if !att.Qualified || !gotCert.Equal(s.cert) || !gotAt.Equal(s.genTime) {
		t.Errorf("Qualified=%v cert ok=%v at=%s", att.Qualified, gotCert.Equal(s.cert), gotAt)
	}
	v = rfc3161.NewVerifier(s.roots(), rfc3161.WithQualifiedChecker(func(*x509.Certificate, time.Time) (bool, error) {
		return false, errors.New("trusted list unavailable")
	}))
	_, err = v.Verify(context.Background(), digest, token)
	wantInvalid(t, err, "trusted list unavailable")
}

func TestVerifyHonoursContext(t *testing.T) {
	s := newTSA(t, schemeECDSA)
	digest := digestOf("ctx")
	token := mustAnchor(t, s, digest)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := rfc3161.NewVerifier(s.roots()).Verify(ctx, digest, token)
	wantInvalid(t, err, "context canceled")
}

func TestParseTokenRejects(t *testing.T) {
	s := newTSA(t, schemeECDSA)
	good := s.token(digestOf("p"), bigInt(7))
	if _, err := rfc3161.ParseToken(good); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		token func() []byte
		want  string
	}{
		{"trailing", func() []byte { return append(bytes.Clone(good), 0x00) }, "trailing"},
		{"truncated", func() []byte { return good[:len(good)-3] }, "malformed"},
		{"empty", func() []byte { return nil }, "malformed"},
		{"two-signerinfos", func() []byte {
			s2 := newTSA(t, schemeECDSA)
			s2.duplicateSigner = true
			return s2.token(digestOf("p"), nil)
		}, "more than one SignerInfo"},
		{"critical-extension", func() []byte {
			s2 := newTSA(t, schemeECDSA)
			s2.criticalExt = true
			return s2.token(digestOf("p"), nil)
		}, "critical extension"},
		{"bad-gentime", func() []byte {
			s2 := newTSA(t, schemeECDSA)
			s2.genTimeRaw = "20261301000000Z"
			return s2.token(digestOf("p"), nil)
		}, "genTime"},
		{"local-gentime", func() []byte {
			s2 := newTSA(t, schemeECDSA)
			s2.genTimeRaw = "20261001000000+0200"
			return s2.token(digestOf("p"), nil)
		}, "genTime"},
		{"gentime-bare-dot", func() []byte {
			s2 := newTSA(t, schemeECDSA)
			s2.genTimeRaw = "20261001000000.Z"
			return s2.token(digestOf("p"), nil)
		}, "genTime"},
		{"gentime-fraction-trailing-zero", func() []byte {
			s2 := newTSA(t, schemeECDSA)
			s2.genTimeRaw = "20261001000000.250Z"
			return s2.token(digestOf("p"), nil)
		}, "trailing zeros"},
		{"gentime-fraction-zero", func() []byte {
			s2 := newTSA(t, schemeECDSA)
			s2.genTimeRaw = "20261001000000.0Z"
			return s2.token(digestOf("p"), nil)
		}, "trailing zeros"},
		{"signeddata-version-1", func() []byte {
			s2 := newTSA(t, schemeECDSA)
			s2.sdVersion = 1
			return s2.token(digestOf("p"), nil)
		}, "SignedData version 1, want 3"},
		{"signeddata-version-5", func() []byte {
			s2 := newTSA(t, schemeECDSA)
			s2.sdVersion = 5
			return s2.token(digestOf("p"), nil)
		}, "SignedData version 5, want 3"},
		{"unsorted-signed-attributes", func() []byte {
			s2 := newTSA(t, schemeECDSA)
			s2.unsortedAttrs = true
			return s2.token(digestOf("p"), nil)
		}, "DER order"},
		{"too-many-attributes", func() []byte {
			s2 := newTSA(t, schemeECDSA)
			s2.extraAttrs = 62 // 3 real ones + 62 = 65
			return s2.token(digestOf("p"), nil)
		}, "more than 64 signed attributes"},
		{"too-many-certificates", func() []byte {
			s2 := newTSA(t, schemeECDSA)
			s2.extraCerts = 32 // signer + 32 = 33
			return s2.token(digestOf("p"), nil)
		}, "more than 32"},
		{"oversized", func() []byte { return make([]byte, rfc3161.MaxTokenSize+1) }, "exceeds"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := rfc3161.ParseToken(tc.token())
			if err == nil || !errors.Is(err, rfc3161.ErrMalformed) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want ErrMalformed containing %q", err, tc.want)
			}
		})
	}
}

func TestParseTokenAcceptsLimits(t *testing.T) {
	// Exactly at the attribute and certificate limits the token still parses
	// and verifies; the limits bound malice, not real tokens.
	s := newTSA(t, schemeECDSA)
	s.extraAttrs = 61 // 3 + 61 = 64
	s.extraCerts = 31 // signer + 31 = 32
	digest := digestOf("limits")
	if _, err := anchorWith(t, s, digest); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejectsOversizedToken(t *testing.T) {
	s := newTSA(t, schemeECDSA)
	big := make([]byte, rfc3161.MaxTokenSize+1)
	_, err := rfc3161.NewVerifier(s.roots()).Verify(context.Background(), digestOf("x"), big)
	wantInvalid(t, err, "at most")
	if _, err := rfc3161.ParseToken(big); err == nil || !errors.Is(err, rfc3161.ErrMalformed) {
		t.Fatalf("ParseToken: err = %v", err)
	}
}

func TestParseTokenAccuracyBounds(t *testing.T) {
	secs := func(v int64) func(*cryptobyte.Builder) {
		return func(acc *cryptobyte.Builder) { acc.AddASN1Int64(v) }
	}
	millis := func(v int64) func(*cryptobyte.Builder) {
		return func(acc *cryptobyte.Builder) { acc.AddASN1Int64WithTag(v, cbasn1.Tag(0).ContextSpecific()) }
	}
	micros := func(v int64) func(*cryptobyte.Builder) {
		return func(acc *cryptobyte.Builder) { acc.AddASN1Int64WithTag(v, cbasn1.Tag(1).ContextSpecific()) }
	}
	cases := []struct {
		name string
		raw  func(*cryptobyte.Builder)
		want string // "" when the token must parse
		dur  time.Duration
	}{
		// 9,223,372,037 s * 1e9 wraps a time.Duration negative; it must be
		// rejected at parse time, never reach WithMaxAccuracy as a negative.
		{"seconds-overflow", secs(9_223_372_037), "accuracy seconds", 0},
		{"seconds-negative", secs(-1), "accuracy seconds", 0},
		{"seconds-max", secs(1 << 31), "", (1 << 31) * time.Second},
		{"seconds-above-max", secs(1<<31 + 1), "accuracy seconds", 0},
		{"millis-zero", millis(0), "accuracy millis 0", 0},
		{"millis-1000", millis(1000), "accuracy millis 1000", 0},
		{"millis-negative", millis(-5), "accuracy millis", 0},
		{"millis-999", millis(999), "", 999 * time.Millisecond},
		{"micros-zero", micros(0), "accuracy micros 0", 0},
		{"micros-1000", micros(1000), "accuracy micros 1000", 0},
		{"micros-1", micros(1), "", time.Microsecond},
		{"empty", func(*cryptobyte.Builder) {}, "", 0},
		{"all-max", func(acc *cryptobyte.Builder) {
			secs(1 << 31)(acc)
			millis(999)(acc)
			micros(999)(acc)
		}, "", (1<<31)*time.Second + 999*time.Millisecond + 999*time.Microsecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTSA(t, schemeECDSA)
			s.accuracyRaw = tc.raw
			tok, err := rfc3161.ParseToken(s.token(digestOf("acc"), nil))
			if tc.want != "" {
				if err == nil || !errors.Is(err, rfc3161.ErrMalformed) || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("err = %v, want ErrMalformed containing %q", err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseToken: %v", err)
			}
			if tok.Accuracy != tc.dur {
				t.Fatalf("Accuracy = %s, want %s", tok.Accuracy, tc.dur)
			}
		})
	}
}

func TestVerifyMaxAccuracyRejectsOverflowingAccuracy(t *testing.T) {
	s := newTSA(t, schemeECDSA)
	s.accuracyRaw = func(acc *cryptobyte.Builder) { acc.AddASN1Int64(9_223_372_037) }
	_, err := anchorWith(t, s, digestOf("overflow"), rfc3161.WithMaxAccuracy(time.Second))
	if err == nil || !strings.Contains(err.Error(), "accuracy") {
		t.Fatalf("err = %v, want an accuracy rejection", err)
	}
}

func TestVerifyPSSSaltLength(t *testing.T) {
	intp := func(v int) *int { return &v }
	cases := []struct {
		name     string
		declared *int
		actual   int
		want     string // "" when the token must verify
	}{
		{"declared-32-actual-32", intp(32), 32, ""},
		{"declared-20-actual-20", intp(20), 20, ""},
		{"declared-32-actual-20", intp(32), 20, "RSASSA-PSS"},
		{"declared-20-actual-32", intp(20), 32, "RSASSA-PSS"},
		{"declared-0", intp(0), 32, "salt length 0"},
		{"declared-negative", intp(-1), 32, "salt length"},
		{"declared-513", intp(513), 32, "salt length"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTSA(t, schemeRSAPSS)
			s.pssSaltDeclared = tc.declared
			s.pssSaltActual = tc.actual
			_, err := anchorWith(t, s, digestOf("pss"))
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Anchor: %v", err)
				}
				return
			}
			wantInvalid(t, err, tc.want)
		})
	}
}

func TestClientRejectsPolicyMismatch(t *testing.T) {
	s := newTSA(t, schemeECDSA)
	s.policy = oidOtherPolicy
	srv := s.serve()
	_, err := rfc3161.New(srv.URL, rfc3161.WithPolicy(oidSKPolicy)).Anchor(context.Background(), digestOf("pol"))
	if err == nil || !strings.Contains(err.Error(), "policy") || !strings.Contains(err.Error(), oidOtherPolicy.String()) {
		t.Fatalf("err = %v, want a policy mismatch naming %s", err, oidOtherPolicy)
	}
	// Without a requested policy the client accepts whatever the TSA chose.
	if _, err := rfc3161.New(srv.URL).Anchor(context.Background(), digestOf("pol")); err != nil {
		t.Fatalf("Anchor without WithPolicy: %v", err)
	}
	// The requested policy itself passes.
	s.policy = oidSKPolicy
	if _, err := rfc3161.New(srv.URL, rfc3161.WithPolicy(oidSKPolicy)).Anchor(context.Background(), digestOf("pol")); err != nil {
		t.Fatalf("Anchor with matching policy: %v", err)
	}
}

func TestVerifyESSCertIDStructure(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*tsa)
		want  string // "" when the token must verify
	}{
		{"v2-with-policies", func(s *tsa) { s.essPolicies = true }, ""},
		{"v1-with-policies", func(s *tsa) { s.essV1 = true; s.essPolicies = true }, ""},
		{"v2-signer-then-root", func(s *tsa) { s.essRootSecond = true }, ""},
		{"v1-signer-then-root", func(s *tsa) { s.essV1 = true; s.essRootSecond = true }, ""},
		{"v2-root-then-signer", func(s *tsa) { s.essRootFirst = true }, "certHash does not match"},
		{"v1-root-then-signer", func(s *tsa) { s.essV1 = true; s.essRootFirst = true }, "certHash does not match"},
		{"v2-issuer-serial-without-directory-name", func(s *tsa) { s.essNoDirName = true }, "directoryName"},
		{"v1-issuer-serial-without-directory-name", func(s *tsa) { s.essV1 = true; s.essNoDirName = true }, "directoryName"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTSA(t, schemeECDSA)
			tc.setup(s)
			_, err := anchorWith(t, s, digestOf("ess"))
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Anchor: %v", err)
				}
				return
			}
			wantInvalid(t, err, tc.want)
		})
	}
}

func TestProviderID(t *testing.T) {
	p := rfc3161.NewProvider(rfc3161.New("http://127.0.0.1:1"), rfc3161.NewVerifier(nil))
	if p.ID() != "rfc3161" {
		t.Fatalf("ID = %q", p.ID())
	}
}

func TestProviderVerifyDelegates(t *testing.T) {
	s := newTSA(t, schemeECDSA)
	digest := digestOf("delegate")
	srv := s.serve()
	p := rfc3161.NewProvider(rfc3161.New(srv.URL), rfc3161.NewVerifier(s.roots(), rfc3161.WithRequiredPolicies(oidSKPolicy)))
	token, err := p.Anchor(context.Background(), digest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Verify(context.Background(), digest, token); err != nil {
		t.Fatal(err)
	}
	_, err = p.Verify(context.Background(), digestOf("not it"), token)
	wantInvalid(t, err, "messageImprint")
}

func FuzzParseToken(f *testing.F) {
	s := newTSA(f, schemeECDSA)
	f.Add(s.token(digestOf("seed"), bigInt(1)))
	s.includeRoot, s.includeTSAName = true, true
	f.Add(s.token(digestOf("seed2"), nil))
	f.Fuzz(func(t *testing.T, data []byte) {
		tok, err := rfc3161.ParseToken(data)
		if err == nil && (tok == nil || tok.SerialNumber == nil) {
			t.Fatal("nil token without error")
		}
	})
}
