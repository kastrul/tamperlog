package eutl

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"
)

func TestLookupByCertificate(t *testing.T) {
	list := fixtureList(t)
	ca, _ := testCA(t)
	matches := list.Lookup(ca, nil)
	if len(matches) != 1 {
		t.Fatalf("matches = %+v", matches)
	}
	m := matches[0]
	if m.By != ByCertificate || m.Service.Name != "Example Qualified TSA" || !m.Certificate.Equal(ca) {
		t.Fatalf("match = %+v", m)
	}
}

func TestLookupViaChain(t *testing.T) {
	list := fixtureList(t)
	ca, key := testCA(t)
	tsu := issue(t, pkix.Name{CommonName: "Example TSU 2026", Organization: []string{"Example Qualified Services AS"}, Country: []string{"EE"}}, []byte{9, 9, 9}, ca, key)
	if got := list.Lookup(tsu, nil); len(got) != 0 {
		t.Fatalf("leaf alone must not match, got %+v", got)
	}
	matches := list.Lookup(tsu, []*x509.Certificate{ca})
	if len(matches) != 1 || matches[0].By != ByCertificate || !matches[0].Certificate.Equal(ca) {
		t.Fatalf("matches = %+v", matches)
	}
}

func TestLookupBySKI(t *testing.T) {
	list := fixtureList(t)
	ski := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	cert := issue(t, pkix.Name{CommonName: "Anything", Country: []string{"EE"}}, ski, nil, nil)
	matches := list.Lookup(cert, nil)
	if len(matches) != 1 || matches[0].By != BySKI || matches[0].Service.Name != "Example SKI TSA" {
		t.Fatalf("matches = %+v", matches)
	}
}

func TestLookupBySubject(t *testing.T) {
	list := fixtureList(t)
	cert := issue(t, pkix.Name{CommonName: "Example Legacy TSA", Organization: []string{"Example Qualified Services AS"}, Country: []string{"EE"}}, []byte{7, 7, 7}, nil, nil)
	matches := list.Lookup(cert, nil)
	if len(matches) != 1 || matches[0].By != BySubject || matches[0].Service.Name != "Example Legacy TSA" {
		t.Fatalf("matches = %+v", matches)
	}
	// A certificate that merely shares the subject of the qualified service's CA
	// matches by subject only; the real CA matches by certificate and wins.
	ca, _ := testCA(t)
	impostor := issue(t, ca.Subject, []byte{1}, nil, nil)
	matches = list.Lookup(impostor, nil)
	if len(matches) != 1 || matches[0].By != BySubject {
		t.Fatalf("impostor matches = %+v", matches)
	}
	matches = list.Lookup(impostor, []*x509.Certificate{ca})
	if len(matches) != 1 || matches[0].By != ByCertificate {
		t.Fatalf("strongest match must win, got %+v", matches)
	}
	if got := list.Lookup(nil, nil); got != nil {
		t.Fatalf("nil certificate must yield nil, got %+v", got)
	}
}

func TestQualified(t *testing.T) {
	list := fixtureList(t)
	ca, key := testCA(t)
	tsu := issue(t, pkix.Name{CommonName: "Example TSU 2026"}, nil, ca, key)
	chain := []*x509.Certificate{ca}

	cases := []struct {
		at   time.Time
		want bool
	}{
		{date(2015, 6, 1), false},  // not yet listed
		{date(2016, 3, 1), false},  // listed as non-qualified TSA under supervision
		{date(2016, 7, 1), true},   // granted takes effect
		{date(2026, 10, 17), true}, // granted
		{date(2029, 12, 31), true}, // last day before withdrawal
		{date(2030, 1, 1), false},  // withdrawn
		{date(2031, 1, 1), false},  // withdrawn
	}
	for _, tc := range cases {
		got, matches, err := list.Qualified(tsu, chain, tc.at)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("Qualified at %s = %v, want %v (matches %+v)", tc.at.Format(time.DateOnly), got, tc.want, matches)
		}
		if len(matches) != 1 {
			t.Errorf("at %s: matches = %d", tc.at.Format(time.DateOnly), len(matches))
		}
	}

	ski := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	skiCert := issue(t, pkix.Name{CommonName: "SKI TSU"}, ski, nil, nil)
	if ok, _, err := list.Qualified(skiCert, nil, date(2021, 1, 1)); err != nil || !ok {
		t.Fatalf("SKI service at 2021 = %v, %v", ok, err)
	}
	if ok, _, err := list.Qualified(skiCert, nil, date(2019, 1, 1)); err != nil || ok {
		t.Fatalf("SKI service at 2019 = %v, %v", ok, err)
	}

	legacy := issue(t, pkix.Name{CommonName: "Example Legacy TSA", Organization: []string{"Example Qualified Services AS"}, Country: []string{"EE"}}, nil, nil, nil)
	ok, matches, err := list.Qualified(legacy, nil, date(2026, 1, 1))
	if err != nil || ok || len(matches) != 1 {
		t.Fatalf("legacy TSA = %v, %+v, %v", ok, matches, err)
	}

	unknown := issue(t, pkix.Name{CommonName: "Unknown"}, nil, nil, nil)
	ok, matches, err = list.Qualified(unknown, nil, date(2026, 1, 1))
	if err != nil || ok || matches != nil {
		t.Fatalf("unknown = %v, %+v, %v", ok, matches, err)
	}

	if _, _, err := list.Qualified(nil, nil, date(2026, 1, 1)); err == nil {
		t.Fatal("nil certificate must error")
	}
	if _, _, err := list.Qualified(ca, nil, time.Time{}); err == nil {
		t.Fatal("zero time must error")
	}
	var none *List
	if _, _, err := none.Qualified(ca, nil, date(2026, 1, 1)); err == nil {
		t.Fatal("nil list must error")
	}
}

func TestChecker(t *testing.T) {
	list := fixtureList(t)
	ca, key := testCA(t)
	tsu := issue(t, pkix.Name{CommonName: "Example TSU 2026"}, nil, ca, key)

	noChain := Checker(list, nil)
	if ok, err := noChain(tsu, date(2026, 1, 1)); err != nil || ok {
		t.Fatalf("without chain resolver = %v, %v", ok, err)
	}
	withChain := Checker(list, func(c *x509.Certificate) []*x509.Certificate {
		if c.Equal(tsu) {
			return []*x509.Certificate{ca}
		}
		return nil
	})
	if ok, err := withChain(tsu, date(2026, 1, 1)); err != nil || !ok {
		t.Fatalf("with chain resolver = %v, %v", ok, err)
	}
	if ok, err := withChain(tsu, date(2031, 1, 1)); err != nil || ok {
		t.Fatalf("after withdrawal = %v, %v", ok, err)
	}
	if _, err := Checker(nil, nil)(tsu, date(2026, 1, 1)); err == nil {
		t.Fatal("nil list must error")
	}
}

func TestKeyIdentifierDerived(t *testing.T) {
	cert := issue(t, pkix.Name{CommonName: "No SKI"}, nil, nil, nil)
	if len(cert.SubjectKeyId) != 0 {
		t.Skip("crypto/x509 populated SubjectKeyId for a leaf; derivation path not exercised")
	}
	if ki := keyIdentifier(cert); len(ki) != 20 {
		t.Fatalf("derived key identifier length = %d", len(ki))
	}
}
