package eutl

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"regexp"
	"strings"
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
	// The certificate is listed only in the current period; the two history
	// instances name the subject, so they match weakly and are reported as such.
	if len(m.Periods) != 3 {
		t.Fatalf("periods = %+v", m.Periods)
	}
	for i, pm := range m.Periods {
		want := BySubject
		if i == 2 {
			want = ByCertificate
		}
		if pm.By != want || !pm.Period.From.Equal(m.Service.History[i].From) {
			t.Errorf("period %d = %s from %s, want %s", i, pm.By, pm.Period.From.Format(time.DateOnly), want)
		}
	}
}

func TestLookupByPublicKey(t *testing.T) {
	list := fixtureList(t)
	ca, key := testCA(t)
	reissued := issueWithKey(t, ca.Subject, []byte{5, 5, 5}, key, nil, nil)
	matches := list.Lookup(reissued, nil)
	if len(matches) != 1 || matches[0].By != ByPublicKey || matches[0].Service.Name != "Example Qualified TSA" {
		t.Fatalf("matches = %+v", matches)
	}
	if ok, _, err := list.Qualified(reissued, nil, date(2026, 1, 1)); err != nil || !ok {
		t.Fatalf("same key in a re-issued certificate = %v, %v", ok, err)
	}
	// In 2026 the period in force is a subject-only history instance, which
	// refers to the current key under the subject it names: the same key under
	// another subject matches the current period only and is not qualified then.
	renamed := issueWithKey(t, pkix.Name{CommonName: "Re-issued root"}, nil, key, nil, nil)
	matches = list.Lookup(renamed, nil)
	if len(matches) != 1 || matches[0].By != ByPublicKey || len(matches[0].Periods) != 1 {
		t.Fatalf("renamed matches = %+v", matches)
	}
	if ok, _, err := list.Qualified(renamed, nil, date(2026, 1, 1)); err != nil || ok {
		t.Fatalf("same key, other subject, subject-only period = %v, %v", ok, err)
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
	skiKey := loadKey(t, "ski-key.pem")
	// The listed X509SKI is the SHA-1 of this key; the certificate asserts an
	// unrelated SubjectKeyId extension, which must not matter.
	cert := issueWithKey(t, pkix.Name{CommonName: "Anything", Country: []string{"EE"}}, []byte{9, 9, 9}, skiKey, nil, nil)
	matches := list.Lookup(cert, nil)
	if len(matches) != 1 || matches[0].By != BySKI || matches[0].Service.Name != "Example SKI TSA" {
		t.Fatalf("matches = %+v", matches)
	}

	// A certificate that asserts the listed value as its SubjectKeyId but
	// holds another key does not match: the extension is issuer-chosen.
	impostor := issue(t, pkix.Name{CommonName: "Anything", Country: []string{"EE"}}, publicKeyIdentifier(cert), nil, nil)
	if got := list.Lookup(impostor, nil); len(got) != 0 {
		t.Fatalf("asserted SKI must not match, got %+v", got)
	}

	// An X509SKI listed next to an X509Certificate is ignored: the rotating
	// service carries the retired key's SKI beside the 2022 certificate, so
	// the retired key matches the history periods only.
	old := loadCert(t, "rotated-old.pem")
	matches = list.Lookup(old, nil)
	if len(matches) != 1 || matches[0].Service.Name != "Example Rotating TSA" || matches[0].By != ByCertificate {
		t.Fatalf("retired key matches = %+v", matches)
	}
	if len(matches[0].Periods) != 2 {
		t.Fatalf("retired key periods = %+v", matches[0].Periods)
	}
	for _, pm := range matches[0].Periods {
		if pm.Period.From.Equal(date(2022, 1, 1)) {
			t.Fatalf("retired key must not match the current period through the stale SKI: %+v", pm)
		}
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

	skiCert := issueWithKey(t, pkix.Name{CommonName: "SKI TSU"}, nil, loadKey(t, "ski-key.pem"), nil, nil)
	if ok, _, err := list.Qualified(skiCert, nil, date(2021, 1, 1)); err != nil || !ok {
		t.Fatalf("SKI service at 2021 = %v, %v", ok, err)
	}
	if ok, _, err := list.Qualified(skiCert, nil, date(2019, 1, 1)); err != nil || ok {
		t.Fatalf("SKI service at 2019 = %v, %v", ok, err)
	}

	unknown := issue(t, pkix.Name{CommonName: "Unknown"}, nil, nil, nil)
	ok, matches, err := list.Qualified(unknown, nil, date(2026, 1, 1))
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

// TestQualifiedWeakMatchesNeverCount pins the rule that a subject-name match,
// and an SKI listed beside a non-matching certificate, never make a
// certificate qualified.
func TestQualifiedWeakMatchesNeverCount(t *testing.T) {
	list := fixtureList(t)
	ca, _ := testCA(t)

	// Same subject as the qualified CA, another key, no listed certificate.
	impostor := issue(t, ca.Subject, nil, nil, nil)
	ok, matches, err := list.Qualified(impostor, nil, date(2026, 1, 1))
	if err != nil || ok || len(matches) != 1 || matches[0].By != BySubject {
		t.Fatalf("subject impostor = %v, %+v, %v", ok, matches, err)
	}

	// Subject of a non-qualified service.
	legacy := issue(t, pkix.Name{CommonName: "Example Legacy TSA", Organization: []string{"Example Qualified Services AS"}, Country: []string{"EE"}}, nil, nil, nil)
	ok, matches, err = list.Qualified(legacy, nil, date(2026, 1, 1))
	if err != nil || ok || len(matches) != 1 {
		t.Fatalf("legacy TSA = %v, %+v, %v", ok, matches, err)
	}

	// The retired key's SKI is listed beside the current certificate of the
	// rotating service; the certificate does not match, so the SKI does not count.
	old := loadCert(t, "rotated-old.pem")
	if got := list.Services[3].Current().Identity.SKIs; len(got) != 1 || string(got[0]) != string(publicKeyIdentifier(old)) {
		t.Fatalf("fixture must list the retired key's SKI in the current identity, got %x", got)
	}
	if ok, _, err := list.Qualified(old, nil, date(2023, 1, 1)); err != nil || ok {
		t.Fatalf("SKI beside a non-matching certificate counted: %v, %v", ok, err)
	}
}

// TestQualifiedPerPeriod covers the rotating service: a key listed only in
// history periods qualifies only inside its own granted period.
func TestQualifiedPerPeriod(t *testing.T) {
	list := fixtureList(t)
	old, cur := loadCert(t, "rotated-old.pem"), loadCert(t, "rotated-new.pem")
	cases := []struct {
		name string
		cert *x509.Certificate
		at   time.Time
		want bool
	}{
		{"old key before listing", old, date(2017, 6, 1), false},
		{"old key in its granted period", old, date(2019, 6, 1), true},
		{"old key while withdrawn", old, date(2021, 6, 1), false},
		{"old key in the later granted period of the new key", old, date(2023, 1, 1), false},
		{"new key in its granted period", cur, date(2023, 1, 1), true},
		{"new key in the old key's period", cur, date(2019, 6, 1), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, matches, err := list.Qualified(tc.cert, nil, tc.at)
			if err != nil {
				t.Fatal(err)
			}
			if ok != tc.want {
				t.Fatalf("Qualified = %v, want %v (matches %+v)", ok, tc.want, matches)
			}
			svc := list.Services[3]
			if got := svc.QualifiedAt(tc.cert, nil, tc.at); got != tc.want {
				t.Fatalf("Service.QualifiedAt = %v, want %v", got, tc.want)
			}
		})
	}

	// Through a chain: a TSU issued by the old CA.
	tsu := issue(t, pkix.Name{CommonName: "Rotating TSU"}, nil, old, loadKey(t, "rotated-old-key.pem"))
	chain := []*x509.Certificate{old}
	if ok, _, err := list.Qualified(tsu, chain, date(2019, 6, 1)); err != nil || !ok {
		t.Fatalf("TSU under old CA in 2019 = %v, %v", ok, err)
	}
	if ok, _, err := list.Qualified(tsu, chain, date(2023, 1, 1)); err != nil || ok {
		t.Fatalf("TSU under old CA in 2023 = %v, %v", ok, err)
	}
}

// TestQualifiedSubjectOnlyHistory covers history instances that carry no key
// material: they refer to the current key, and only to it.
func TestQualifiedSubjectOnlyHistory(t *testing.T) {
	fixture := string(readFixture(t, "ee-tl.xml"))
	ca, _ := testCA(t)

	// The fixture's granted 2016 instance names the CA's subject: qualified.
	if ok, _, err := fixtureList(t).Qualified(ca, nil, date(2026, 1, 1)); err != nil || !ok {
		t.Fatalf("subject-only history with matching current key = %v, %v", ok, err)
	}

	// Another subject in the history instance: the instance refers to a
	// different identity, so the current key does not qualify there.
	other := strings.ReplaceAll(fixture, "CN=Example Qualified Services Root CA, O=Example Qualified Services AS, C=EE", "CN=Somebody Else, C=EE")
	tl, err := ParseTL(strings.NewReader(other))
	if err != nil {
		t.Fatal(err)
	}
	if ok, _, err := listOf(tl).Qualified(ca, nil, date(2026, 1, 1)); err != nil || ok {
		t.Fatalf("subject-only history naming another subject = %v, %v", ok, err)
	}

	// No digital identity at all in the history instances: taken to be the
	// current one, which still has to authenticate the certificate by key.
	stripped := regexp.MustCompile(`(?s)<DigitalId>\s*<X509SubjectName>[^<]*</X509SubjectName>\s*</DigitalId>`).ReplaceAllString(fixture, "")
	if stripped == fixture {
		t.Fatal("fixture subject names not found")
	}
	tl, err = ParseTL(strings.NewReader(stripped))
	if err != nil {
		t.Fatal(err)
	}
	empty := listOf(tl)
	if ok, _, err := empty.Qualified(ca, nil, date(2026, 1, 1)); err != nil || !ok {
		t.Fatalf("empty history identity with current key = %v, %v", ok, err)
	}
	impostor := issue(t, ca.Subject, nil, nil, nil)
	if ok, m, err := empty.Qualified(impostor, nil, date(2026, 1, 1)); err != nil || ok || m != nil {
		t.Fatalf("empty history identity with another key = %v, %+v, %v", ok, m, err)
	}
}

func TestServiceProblems(t *testing.T) {
	fixture := string(readFixture(t, "ee-tl.xml"))
	ca, _ := testCA(t)
	cases := []struct {
		name string
		in   string
	}{
		{"duplicate StatusStartingTime", strings.Replace(fixture, "2016-01-15T00:00:00Z", "2016-07-01T00:00:00Z", 1)},
		{"history later than current status", strings.Replace(fixture, "2030-01-01T00:00:00Z", "2015-01-01T00:00:00Z", 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.in == fixture {
				t.Fatal("fixture text not found")
			}
			tl, err := ParseTL(strings.NewReader(tc.in))
			if err != nil {
				t.Fatal(err)
			}
			svc := tl.Services[0]
			if len(svc.Problems) == 0 {
				t.Fatalf("no problem recorded: %+v", svc.History)
			}
			if svc.QualifiedAt(ca, nil, date(2026, 1, 1)) {
				t.Fatal("a service with problems must not qualify")
			}
			if ok, _, err := listOf(tl).Qualified(ca, nil, date(2026, 1, 1)); err != nil || ok {
				t.Fatalf("list-level = %v, %v", ok, err)
			}
		})
	}
	if p := fixtureList(t).Services[0].Problems; len(p) != 0 {
		t.Fatalf("fixture must be clean, got %v", p)
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
	withChain := Checker(list, resolverFor(tsu, ca))
	if ok, err := withChain(tsu, date(2026, 1, 1)); err != nil || !ok {
		t.Fatalf("with chain resolver = %v, %v", ok, err)
	}
	if ok, err := withChain(tsu, date(2031, 1, 1)); err != nil || ok {
		t.Fatalf("after withdrawal = %v, %v", ok, err)
	}
	if _, err := Checker(nil, nil)(tsu, date(2026, 1, 1)); err == nil {
		t.Fatal("nil list must error")
	}
	if err := (Policy{}).Check(nil, time.Now()); err == nil {
		t.Fatal("nil list must fail the policy")
	}
}

func resolverFor(leaf, issuer *x509.Certificate) func(*x509.Certificate) []*x509.Certificate {
	return func(c *x509.Certificate) []*x509.Certificate {
		if c.Equal(leaf) {
			return []*x509.Certificate{issuer}
		}
		return nil
	}
}

func TestCheckerPolicyFresh(t *testing.T) {
	list := fixtureList(t)
	list.NextUpdate = date(2027, 4, 7) // the LOTL's; the EE list says 2027-03-01T09:00Z
	ca, key := testCA(t)
	tsu := issue(t, pkix.Name{CommonName: "Example TSU 2026"}, nil, ca, key)
	at := date(2026, 1, 1)
	clock := func(now time.Time) CheckerOption { return withClock(func() time.Time { return now }) }

	fresh := Checker(list, resolverFor(tsu, ca), WithPolicy(Policy{RequireFresh: true}), clock(date(2026, 10, 17)))
	if ok, err := fresh(tsu, at); err != nil || !ok {
		t.Fatalf("fresh lists = %v, %v", ok, err)
	}
	staleEE := Checker(list, resolverFor(tsu, ca), WithPolicy(Policy{RequireFresh: true}), clock(date(2027, 3, 2)))
	if ok, err := staleEE(tsu, at); !errors.Is(err, ErrListStale) || ok || !strings.Contains(err.Error(), "EE") {
		t.Fatalf("stale national list = %v, %v", ok, err)
	}
	staleLOTL := Checker(list, resolverFor(tsu, ca), WithPolicy(Policy{RequireFresh: true}), clock(date(2027, 5, 1)))
	if ok, err := staleLOTL(tsu, at); !errors.Is(err, ErrListStale) || ok || !strings.Contains(err.Error(), "LOTL") {
		t.Fatalf("stale LOTL = %v, %v", ok, err)
	}
	lenient := Checker(list, resolverFor(tsu, ca), clock(date(2027, 5, 1)))
	if ok, err := lenient(tsu, at); err != nil || !ok {
		t.Fatalf("without RequireFresh = %v, %v", ok, err)
	}

	// Closed lists carry no NextUpdate and are never stale.
	list.NextUpdate = time.Time{}
	list.Lists["EE"].NextUpdate = time.Time{}
	if ok, err := staleLOTL(tsu, at); err != nil || !ok {
		t.Fatalf("closed lists = %v, %v", ok, err)
	}
}

func TestCheckerPolicyTerritories(t *testing.T) {
	list := fixtureList(t)
	list.Errors["LV"] = errors.New("GET https://example.test/tsl/lv-tl.xml: 404 Not Found")
	ca, key := testCA(t)
	tsu := issue(t, pkix.Name{CommonName: "Example TSU 2026"}, nil, ca, key)
	at := date(2026, 1, 1)

	ok, err := Checker(list, resolverFor(tsu, ca), WithPolicy(Policy{RequireTerritories: []string{"ee"}}))(tsu, at)
	if err != nil || !ok {
		t.Fatalf("EE required and loaded = %v, %v", ok, err)
	}
	ok, err = Checker(list, resolverFor(tsu, ca), WithPolicy(Policy{RequireTerritories: []string{"EE", "LV"}}))(tsu, at)
	if !errors.Is(err, ErrTerritoryUnavailable) || ok || !strings.Contains(err.Error(), "404") {
		t.Fatalf("LV failed to load = %v, %v", ok, err)
	}
	ok, err = Checker(list, resolverFor(tsu, ca), WithPolicy(Policy{RequireTerritories: []string{"XX"}}))(tsu, at)
	if !errors.Is(err, ErrTerritoryUnavailable) || ok || !strings.Contains(err.Error(), "XX") {
		t.Fatalf("XX never pointed to = %v, %v", ok, err)
	}
	if ok, err := Checker(list, resolverFor(tsu, ca))(tsu, at); err != nil || !ok {
		t.Fatalf("errors ignored without RequireTerritories = %v, %v", ok, err)
	}
}

func TestCheckerPolicyHistorical(t *testing.T) {
	list := fixtureList(t)
	old, cur := loadCert(t, "rotated-old.pem"), loadCert(t, "rotated-new.pem")
	strict := Checker(list, nil)
	historical := Checker(list, nil, WithPolicy(Policy{AllowHistorical: true}))

	if ok, err := strict(old, date(2019, 6, 1)); err != nil || ok {
		t.Fatalf("retired key under default policy = %v, %v", ok, err)
	}
	if ok, err := historical(old, date(2019, 6, 1)); err != nil || !ok {
		t.Fatalf("retired key with AllowHistorical = %v, %v", ok, err)
	}
	for name, check := range map[string]func(*x509.Certificate, time.Time) (bool, error){"strict": strict, "historical": historical} {
		if ok, err := check(old, date(2023, 1, 1)); err != nil || ok {
			t.Fatalf("%s: retired key in the new key's period = %v, %v", name, ok, err)
		}
		if ok, err := check(cur, date(2023, 1, 1)); err != nil || !ok {
			t.Fatalf("%s: current key = %v, %v", name, ok, err)
		}
	}

	// A service that kept its key: the current identity authenticates the
	// certificate, so old tokens verify under the default policy too.
	ca, key := testCA(t)
	tsu := issue(t, pkix.Name{CommonName: "Example TSU 2016"}, nil, ca, key)
	if ok, err := Checker(list, resolverFor(tsu, ca))(tsu, date(2017, 1, 1)); err != nil || !ok {
		t.Fatalf("historical period, unchanged key = %v, %v", ok, err)
	}
}
