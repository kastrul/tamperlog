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
	cb, err := os.ReadFile(filepath.Join("testdata", "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(cb)
	if block == nil {
		t.Fatal("testdata/ca.pem: no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := os.ReadFile(filepath.Join("testdata", "ca-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ = pem.Decode(kb)
	if block == nil {
		t.Fatal("testdata/ca-key.pem: no PEM block")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// issue creates a certificate with the given subject and key identifier,
// signed by parent (self-signed when parent is nil).
func issue(t *testing.T, subject pkix.Name, ski []byte, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
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
	tl := loadFixtureTL(t)
	return &List{Lists: map[string]*TL{tl.Territory: tl}, Services: tl.Services, Errors: map[string]error{}}
}

func date(y int, m time.Month, d int) time.Time {
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}
