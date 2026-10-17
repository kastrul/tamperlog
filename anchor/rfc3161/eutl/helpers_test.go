package eutl

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testCA loads the fixture CA certificate (the digital identity of the
// "Example Qualified TSA" service in testdata/ee-tl.xml) and its key.
func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	return loadCert(t, "ca.pem"), loadKey(t, "ca-key.pem")
}

// loadCert reads a PEM certificate from testdata.
func loadCert(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	block := loadPEM(t, name)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// loadKey reads a PEM EC private key from testdata.
func loadKey(t *testing.T, name string) *ecdsa.PrivateKey {
	t.Helper()
	block := loadPEM(t, name)
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func loadPEM(t *testing.T, name string) *pem.Block {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatalf("testdata/%s: no PEM block", name)
	}
	return block
}

// issue creates a certificate with a fresh key, the given subject and key
// identifier, signed by parent (self-signed when parent is nil).
func issue(t *testing.T, subject pkix.Name, ski []byte, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return issueWithKey(t, subject, ski, key, parent, parentKey)
}

// issueWithKey is issue for a given subject key.
func issueWithKey(t *testing.T, subject pkix.Name, ski []byte, key *ecdsa.PrivateKey, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      subject,
		NotBefore:    time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2046, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		SubjectKeyId: ski,
	}
	signer := parentKey
	if parent == nil {
		parent, signer = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func loadFixtureTL(t *testing.T) *TL {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "ee-tl.xml"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	tl, err := ParseTL(f)
	if err != nil {
		t.Fatal(err)
	}
	return tl
}

func fixtureList(t *testing.T) *List {
	t.Helper()
	return listOf(loadFixtureTL(t))
}

func listOf(tl *TL) *List {
	return &List{Lists: map[string]*TL{tl.Territory: tl}, Services: tl.Services, Errors: map[string]error{}}
}

func date(y int, m time.Month, d int) time.Time {
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// readFixture returns the bytes of a testdata file.
func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
