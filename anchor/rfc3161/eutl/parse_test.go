package eutl

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseLOTL(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "eu-lotl.xml"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	lotl, err := ParseLOTL(f)
	if err != nil {
		t.Fatal(err)
	}
	if lotl.Territory != "EU" || lotl.SequenceNumber != 397 {
		t.Fatalf("territory/sequence = %q/%d", lotl.Territory, lotl.SequenceNumber)
	}
	if !lotl.ListIssueDateTime.Equal(time.Date(2026, 10, 15, 14, 6, 46, 0, time.UTC)) {
		t.Fatalf("ListIssueDateTime = %v", lotl.ListIssueDateTime)
	}
	if !lotl.NextUpdate.Equal(time.Date(2027, 4, 7, 11, 6, 46, 0, time.UTC)) {
		t.Fatalf("NextUpdate = %v", lotl.NextUpdate)
	}
	if len(lotl.Pointers) != 4 {
		t.Fatalf("pointers = %d, want 4", len(lotl.Pointers))
	}
	want := []Pointer{
		{Territory: "EU", URL: "https://example.test/lotl/eu-lotl.xml", MimeType: MimeTypeXML, TSLType: TSLTypeLOTL},
		{Territory: "EE", URL: "https://example.test/tsl/ee-tl.pdf", MimeType: "application/pdf", TSLType: "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric"},
		{Territory: "EE", URL: "https://example.test/tsl/ee-tl.xml", MimeType: MimeTypeXML, TSLType: "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric"},
		{Territory: "LV", URL: "https://example.test/tsl/lv-tl.xml", MimeType: MimeTypeXML, TSLType: "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric"},
	}
	ca, _ := testCA(t)
	for i, p := range lotl.Pointers {
		w := want[i]
		if p.Territory != w.Territory || p.URL != w.URL || p.MimeType != w.MimeType || p.TSLType != w.TSLType {
			t.Errorf("pointer %d = %+v, want %+v", i, p, w)
		}
		if len(p.SigningCertificates) != 1 || !p.SigningCertificates[0].Equal(ca) {
			t.Errorf("pointer %d: signing certificates not exposed", i)
		}
		if len(p.RawSigningCertificates) != 1 {
			t.Errorf("pointer %d: raw signing certificates = %d", i, len(p.RawSigningCertificates))
		}
	}
}

func TestParseTL(t *testing.T) {
	tl := loadFixtureTL(t)
	if tl.Territory != "EE" || tl.SequenceNumber != 88 {
		t.Fatalf("territory/sequence = %q/%d", tl.Territory, tl.SequenceNumber)
	}
	if !tl.ListIssueDateTime.Equal(date(2026, 9, 1).Add(9*time.Hour)) || !tl.NextUpdate.Equal(date(2027, 3, 1).Add(9*time.Hour)) {
		t.Fatalf("issue/next = %v/%v", tl.ListIssueDateTime, tl.NextUpdate)
	}
	if len(tl.Services) != 4 {
		t.Fatalf("services = %d, want 4", len(tl.Services))
	}
	ca, _ := testCA(t)

	q := tl.Services[0]
	if q.Provider != "Example Qualified Services AS" || q.Name != "Example Qualified TSA" || q.Type != TypeQTST || q.Territory != "EE" {
		t.Fatalf("service 0 = %+v", q)
	}
	if len(q.Problems) != 0 {
		t.Fatalf("service 0 problems = %v", q.Problems)
	}
	wantHistory := []StatusPeriod{
		{Status: "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision", Type: TypeTSA, From: date(2016, 1, 15)},
		{Status: StatusGranted, Type: TypeQTST, From: date(2016, 7, 1)},
		{Status: StatusWithdrawn, Type: TypeQTST, From: date(2030, 1, 1)},
	}
	if len(q.History) != len(wantHistory) {
		t.Fatalf("history = %+v", q.History)
	}
	for i := range wantHistory {
		if q.History[i].Status != wantHistory[i].Status || q.History[i].Type != wantHistory[i].Type || !q.History[i].From.Equal(wantHistory[i].From) {
			t.Errorf("history[%d] = %+v, want %+v", i, q.History[i], wantHistory[i])
		}
	}
	// Identities stay with their period: the certificate is in the current
	// ServiceInformation only, the history instances name the subject.
	cur := q.Current()
	if !cur.From.Equal(date(2030, 1, 1)) || len(cur.Identity.Certificates) != 1 || !cur.Identity.Certificates[0].Equal(ca) || len(cur.Identity.SubjectNames) != 1 {
		t.Fatalf("current identity = %+v", cur.Identity)
	}
	for i := range 2 {
		id := q.History[i].Identity
		if len(id.Certificates) != 0 || len(id.SKIs) != 0 || len(id.SubjectNames) != 1 || id.SubjectNames[0] != cur.Identity.SubjectNames[0] {
			t.Fatalf("history[%d] identity = %+v", i, id)
		}
	}

	legacy := tl.Services[1]
	if legacy.Type != TypeTSA || legacy.Name != "Example Legacy TSA" || len(legacy.Current().Identity.SubjectNames) != 1 || len(legacy.Current().Identity.Certificates) != 0 {
		t.Fatalf("service 1 = %+v", legacy)
	}

	ski := tl.Services[2]
	if ski.Provider != "Näidis Ajatemplid OÜ" {
		t.Fatalf("service 2 provider = %q (first name when no English)", ski.Provider)
	}
	wantSKI, err := base64.StdEncoding.DecodeString("+cYWqpqOZSjF5qYXC07mLhBzOVg=")
	if err != nil {
		t.Fatal(err)
	}
	if got := ski.Current().Identity.SKIs; len(got) != 1 || !bytes.Equal(got[0], wantSKI) {
		t.Fatalf("service 2 SKIs = %x", got)
	}

	rot := tl.Services[3]
	old, cur2 := loadCert(t, "rotated-old.pem"), loadCert(t, "rotated-new.pem")
	if rot.Name != "Example Rotating TSA" || len(rot.History) != 3 || len(rot.Problems) != 0 {
		t.Fatalf("service 3 = %+v", rot)
	}
	for i, want := range []struct {
		status string
		from   time.Time
		cert   *x509.Certificate
	}{
		{StatusGranted, date(2018, 1, 1), old},
		{StatusWithdrawn, date(2021, 1, 1), old},
		{StatusGranted, date(2022, 1, 1), cur2},
	} {
		p := rot.History[i]
		if p.Status != want.status || !p.From.Equal(want.from) || len(p.Identity.Certificates) != 1 || !p.Identity.Certificates[0].Equal(want.cert) {
			t.Errorf("service 3 history[%d] = %+v", i, p)
		}
	}
	if id := rot.Current().Identity; len(id.SKIs) != 1 || len(id.SubjectNames) != 1 {
		t.Fatalf("service 3 current identity = %+v", id)
	}
}

func TestParseRejects(t *testing.T) {
	lotlXML, err := os.ReadFile(filepath.Join("testdata", "eu-lotl.xml"))
	if err != nil {
		t.Fatal(err)
	}
	tlXML, err := os.ReadFile(filepath.Join("testdata", "ee-tl.xml"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		lotl bool
		in   string
	}{
		{"garbage", true, "<html/>"},
		{"wrong namespace", false, `<TrustServiceStatusList xmlns="urn:other"><SchemeInformation/></TrustServiceStatusList>`},
		{"TL given to ParseLOTL", true, string(tlXML)},
		{"LOTL given to ParseTL", false, string(lotlXML)},
		{"missing sequence", false, strings.Replace(string(tlXML), "<TSLSequenceNumber>88</TSLSequenceNumber>", "", 1)},
		{"bad time", false, strings.Replace(string(tlXML), "2030-01-01T00:00:00Z", "someday", 1)},
		{"bad certificate base64", false, strings.Replace(string(tlXML), "<X509Certificate>MII", "<X509Certificate>!!!", 1)},
		{"missing status", false, strings.Replace(string(tlXML), "<ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>", "", 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.lotl {
				_, err = ParseLOTL(strings.NewReader(tc.in))
			} else {
				_, err = ParseTL(strings.NewReader(tc.in))
			}
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, ErrNotTrustedList) && !strings.Contains(err.Error(), "eutl:") {
				t.Fatalf("unexpected error %v", err)
			}
		})
	}
}

func TestParseClosedListHasZeroNextUpdate(t *testing.T) {
	tlXML, err := os.ReadFile(filepath.Join("testdata", "ee-tl.xml"))
	if err != nil {
		t.Fatal(err)
	}
	in := strings.Replace(string(tlXML), "<NextUpdate>\n            <dateTime>2027-03-01T09:00:00Z</dateTime>\n        </NextUpdate>", "<NextUpdate/>", 1)
	if in == string(tlXML) {
		t.Fatal("fixture NextUpdate not found")
	}
	tl, err := ParseTL(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if !tl.NextUpdate.IsZero() {
		t.Fatalf("NextUpdate = %v, want zero for a closed list", tl.NextUpdate)
	}
}

func TestParseToleratesUnknownElements(t *testing.T) {
	tlXML, err := os.ReadFile(filepath.Join("testdata", "ee-tl.xml"))
	if err != nil {
		t.Fatal(err)
	}
	in := strings.Replace(string(tlXML), "<TSPServices>", "<FutureElement xmlns=\"urn:future\"><Deep>x</Deep></FutureElement><TSPServices>", 1)
	tl, err := ParseTL(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(tl.Services) != 4 {
		t.Fatalf("services = %d", len(tl.Services))
	}
}

func TestParseDN(t *testing.T) {
	got, err := parseDN(`CN=eParaksts TSA A 2017, OID.2.5.4.97=NTRLV-40003011203, O=VAS Latvijas Valsts radio un televīzijas centrs, C=LV`)
	if err != nil {
		t.Fatal(err)
	}
	want := []attribute{{"C", "LV"}, {"CN", "eParaksts TSA A 2017"}, {"O", "VAS Latvijas Valsts radio un televīzijas centrs"}, {"ORGANIZATIONIDENTIFIER", "NTRLV-40003011203"}}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("attribute %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	if _, err := parseDN(`CN=#0c03616263`); err == nil {
		t.Fatal("hex value must be rejected")
	}
	if _, err := parseDN(`nonsense`); err == nil {
		t.Fatal("missing '=' must be rejected")
	}
	escaped, err := parseDN(`CN=Acme\, Inc.,O="Quoted, Org",C=EE`)
	if err != nil {
		t.Fatal(err)
	}
	if len(escaped) != 3 || escaped[1].value != "Acme, Inc." || escaped[2].value != "Quoted, Org" {
		t.Fatalf("escaped = %+v", escaped)
	}
}
