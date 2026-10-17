package eutl

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // RFC 5280 §4.2.1.2 key identifier derivation, not a security hash.
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Service type identifiers from ETSI TS 119 612 clause 5.5.1.
const (
	// TypeQTST is a qualified time-stamping service (eIDAS Art. 42).
	TypeQTST = "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST"
	// TypeTSSQC is a time-stamping service, not qualified, whose tokens are
	// issued by a qualified-certificate holder.
	TypeTSSQC = "http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-QC"
	// TypeTSA is a time-stamping service of unspecified (non-qualified) kind.
	TypeTSA = "http://uri.etsi.org/TrstSvc/Svctype/TSA"
)

// Service status identifiers from ETSI TS 119 612 clause 5.5.4.
const (
	// StatusGranted is the eIDAS status of a qualified service in operation.
	StatusGranted = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
	// StatusWithdrawn is the eIDAS status of a qualified service that lost
	// its qualified status.
	StatusWithdrawn = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn"
)

// Match methods reported in [Match.By], strongest first.
const (
	// ByCertificate means the list carries the exact DER certificate.
	ByCertificate = "certificate"
	// BySKI means the list carries the certificate's subject key identifier.
	BySKI = "ski"
	// BySubject means only the subject distinguished name matched. Treat as
	// weak evidence; it relies on the chain having been validated elsewhere.
	BySubject = "subject"
)

// StatusPeriod is one entry of a service's status history: the service had
// Status (and, when the list records it, Type) from From until the next
// period starts.
type StatusPeriod struct {
	// Status is the status URI, such as [StatusGranted].
	Status string
	// Type is the service type URI in force during the period; empty when the
	// list did not record one, in which case the service's current Type applies.
	Type string
	// From is when the status took effect (StatusStartingTime).
	From time.Time
}

// Service is one TSPService entry of a national trusted list.
type Service struct {
	// Territory is the scheme territory of the list, such as "EE".
	Territory string
	// Provider is the trust service provider's name (English when available).
	Provider string
	// Name is the service name (English when available).
	Name string
	// Type is the current service type URI, such as [TypeQTST].
	Type string
	// Certificates are the parsable X509Certificate digital identities of the
	// service, merged from the current information and every history instance.
	Certificates []*x509.Certificate
	// SKIs are the X509SKI digital identities (raw key identifier bytes).
	SKIs [][]byte
	// SubjectNames are the X509SubjectName digital identities as written.
	SubjectNames []string
	// History is every status period in ascending order of From; the last
	// element is the current status.
	History []StatusPeriod

	// rawCertificates holds the DER of every X509Certificate digital
	// identity, including ones crypto/x509 could not parse, for exact matching.
	rawCertificates [][]byte
}

// StatusAt returns the period in force at t, or false when the service was
// not yet listed.
func (s *Service) StatusAt(t time.Time) (StatusPeriod, bool) {
	var found StatusPeriod
	ok := false
	for _, p := range s.History {
		if p.From.After(t) {
			break
		}
		found, ok = p, true
	}
	return found, ok
}

// QualifiedAt reports whether the service was a granted qualified
// time-stamping service at t.
func (s *Service) QualifiedAt(t time.Time) bool {
	p, ok := s.StatusAt(t)
	if !ok || p.Status != StatusGranted {
		return false
	}
	typ := p.Type
	if typ == "" {
		typ = s.Type
	}
	return typ == TypeQTST
}

// Match is one service that identifies a certificate.
type Match struct {
	// Service is the matched service.
	Service *Service
	// By says how the match was made: [ByCertificate], [BySKI] or [BySubject].
	By string
	// Certificate is the certificate (the TSA certificate or a chain element)
	// that the service's digital identity matched.
	Certificate *x509.Certificate
}

// List is the merged content of the loaded trusted lists.
type List struct {
	// LOTL is the List of Trusted Lists the national lists were taken from;
	// nil when the List was assembled without one.
	LOTL *LOTL
	// Lists holds the metadata of every national list that loaded, by territory.
	Lists map[string]*TL
	// Services are all services of all loaded lists.
	Services []*Service
	// Errors records, by territory, national lists that failed to download
	// or parse and were therefore skipped.
	Errors map[string]error
	// LoadedAt is when the List was assembled.
	LoadedAt time.Time
}

// Lookup returns every service whose digital identity matches cert or one of
// the certificates in chain. Each service appears once, with the strongest
// match method found.
func (l *List) Lookup(cert *x509.Certificate, chain []*x509.Certificate) []Match {
	if l == nil || cert == nil {
		return nil
	}
	candidates := make([]*x509.Certificate, 0, 1+len(chain))
	candidates = append(candidates, cert)
	for _, c := range chain {
		if c != nil {
			candidates = append(candidates, c)
		}
	}
	best := map[*Service]Match{}
	var order []*Service
	for _, svc := range l.Services {
		for _, c := range candidates {
			by, ok := svc.matches(c)
			if !ok {
				continue
			}
			prev, seen := best[svc]
			if !seen {
				order = append(order, svc)
			}
			if !seen || rank(by) < rank(prev.By) {
				best[svc] = Match{Service: svc, By: by, Certificate: c}
			}
		}
	}
	if len(order) == 0 {
		return nil
	}
	out := make([]Match, 0, len(order))
	for _, svc := range order {
		out = append(out, best[svc])
	}
	return out
}

// Qualified reports whether cert was issued under a service that was a
// granted qualified time-stamping service at the time at, together with the
// services that matched. It returns an error for a nil certificate or a zero
// time; a certificate no list knows yields (false, nil, nil).
func (l *List) Qualified(cert *x509.Certificate, chain []*x509.Certificate, at time.Time) (bool, []Match, error) {
	if l == nil {
		return false, nil, errors.New("eutl: nil list")
	}
	if cert == nil {
		return false, nil, errors.New("eutl: nil certificate")
	}
	if at.IsZero() {
		return false, nil, errors.New("eutl: zero time")
	}
	matches := l.Lookup(cert, chain)
	for _, m := range matches {
		if m.Service.QualifiedAt(at) {
			return true, matches, nil
		}
	}
	return false, matches, nil
}

func rank(by string) int {
	switch by {
	case ByCertificate:
		return 0
	case BySKI:
		return 1
	default:
		return 2
	}
}

// matches reports whether and how the service's digital identity covers c.
func (s *Service) matches(c *x509.Certificate) (string, bool) {
	for _, raw := range s.rawCertificates {
		if bytes.Equal(raw, c.Raw) {
			return ByCertificate, true
		}
	}
	if ski := keyIdentifier(c); len(ski) > 0 {
		for _, want := range s.SKIs {
			if bytes.Equal(want, ski) {
				return BySKI, true
			}
		}
	}
	if len(s.SubjectNames) > 0 {
		have := subjectAttributes(c.Subject)
		for _, name := range s.SubjectNames {
			if want, err := parseDN(name); err == nil && equalAttributes(want, have) {
				return BySubject, true
			}
		}
	}
	return "", false
}

// keyIdentifier returns the certificate's subject key identifier, deriving
// it from the public key (RFC 5280 §4.2.1.2 method 1) when the extension is
// absent, which is how trusted lists compute X509SKI for such certificates.
func keyIdentifier(c *x509.Certificate) []byte {
	if len(c.SubjectKeyId) > 0 {
		return c.SubjectKeyId
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(c.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil
	}
	sum := sha1.Sum(spki.PublicKey.Bytes) //nolint:gosec // see keyIdentifier doc.
	return sum[:]
}

// attribute is one normalised relative distinguished name component.
type attribute struct{ key, value string }

var attributeNames = map[string]string{
	"2.5.4.3":                    "CN",
	"2.5.4.4":                    "SN",
	"2.5.4.5":                    "SERIALNUMBER",
	"2.5.4.6":                    "C",
	"2.5.4.7":                    "L",
	"2.5.4.8":                    "ST",
	"2.5.4.9":                    "STREET",
	"2.5.4.10":                   "O",
	"2.5.4.11":                   "OU",
	"2.5.4.12":                   "T",
	"2.5.4.17":                   "POSTALCODE",
	"2.5.4.42":                   "GIVENNAME",
	"2.5.4.46":                   "DNQ",
	"2.5.4.65":                   "PSEUDONYM",
	"2.5.4.97":                   "ORGANIZATIONIDENTIFIER",
	"0.9.2342.19200300.100.1.25": "DC",
	"1.2.840.113549.1.9.1":       "EMAILADDRESS",
}

var attributeAliases = map[string]string{
	"COMMONNAME":             "CN",
	"SURNAME":                "SN",
	"COUNTRY":                "C",
	"COUNTRYNAME":            "C",
	"LOCALITY":               "L",
	"LOCALITYNAME":           "L",
	"STATE":                  "ST",
	"S":                      "ST",
	"STATEORPROVINCENAME":    "ST",
	"ORGANIZATION":           "O",
	"ORGANIZATIONNAME":       "O",
	"ORGANIZATIONALUNIT":     "OU",
	"ORGANIZATIONALUNITNAME": "OU",
	"ORGANISATIONIDENTIFIER": "ORGANIZATIONIDENTIFIER",
	"OI":                     "ORGANIZATIONIDENTIFIER",
	"E":                      "EMAILADDRESS",
	"EMAIL":                  "EMAILADDRESS",
	"TITLE":                  "T",
	"GN":                     "GIVENNAME",
	"DOMAINCOMPONENT":        "DC",
}

func normaliseKey(k string) string {
	k = strings.ToUpper(strings.TrimSpace(k))
	k = strings.TrimPrefix(k, "OID.")
	if short, ok := attributeNames[k]; ok {
		return short
	}
	if short, ok := attributeAliases[k]; ok {
		return short
	}
	return k
}

func subjectAttributes(n pkix.Name) []attribute {
	out := make([]attribute, 0, len(n.Names))
	for _, atv := range n.Names {
		v, ok := atv.Value.(string)
		if !ok {
			continue
		}
		out = append(out, attribute{key: normaliseKey(atv.Type.String()), value: strings.TrimSpace(v)})
	}
	sortAttributes(out)
	return out
}

// parseDN splits an RFC 4514 string such as "CN=TSA, O=Example, C=EE" into
// attributes. Escaped commas and quoted values are honoured; hex-encoded
// values (#...) are rejected because the comparison is textual.
func parseDN(s string) ([]attribute, error) {
	var out []attribute
	var cur strings.Builder
	quoted, escaped := false, false
	flush := func() error {
		part := strings.TrimSpace(cur.String())
		cur.Reset()
		if part == "" {
			return nil
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return fmt.Errorf("eutl: malformed distinguished name %q", s)
		}
		v = strings.TrimSpace(v)
		if strings.HasPrefix(v, "#") {
			return fmt.Errorf("eutl: hex-encoded attribute in %q", s)
		}
		out = append(out, attribute{key: normaliseKey(k), value: v})
		return nil
	}
	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == '"':
			quoted = !quoted
		case (r == ',' || r == ';') && !quoted:
			if err := flush(); err != nil {
				return nil, err
			}
		default:
			cur.WriteRune(r)
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("eutl: empty distinguished name")
	}
	sortAttributes(out)
	return out, nil
}

func sortAttributes(a []attribute) {
	sort.Slice(a, func(i, j int) bool {
		if a[i].key != a[j].key {
			return a[i].key < a[j].key
		}
		return a[i].value < a[j].value
	})
}

func equalAttributes(a, b []attribute) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].key != b[i].key || !strings.EqualFold(a[i].value, b[i].value) {
			return false
		}
	}
	return true
}
