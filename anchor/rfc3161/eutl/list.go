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

// Match methods reported in [Match.By] and [PeriodMatch.By], strongest
// first. The first three are key-authenticated and can make a certificate
// qualified; [BySubject] is reported by [List.Lookup] for diagnosis only and
// never makes [List.Qualified] true.
const (
	// ByCertificate means the identity carries the exact DER certificate.
	ByCertificate = "certificate"
	// ByPublicKey means a listed certificate carries the same
	// SubjectPublicKeyInfo as the candidate (a re-issued CA certificate).
	ByPublicKey = "public-key"
	// BySKI means a listed X509SKI equals the SHA-1 of the candidate's public
	// key as computed by this package (RFC 5280 §4.2.1.2 method 1). The
	// SubjectKeyId extension the candidate asserts is never consulted, and
	// X509SKI values are ignored when the same identity also lists a
	// certificate, because the certificate is then the authoritative key.
	BySKI = "ski"
	// BySubject means only the subject distinguished name matched. Anyone
	// holding a certificate with that subject from any CA the verifier
	// trusts would match, so this is evidence for a human, not for Qualified.
	BySubject = "subject"
)

// Identity is the ServiceDigitalIdentity listed for one status period.
type Identity struct {
	// Certificates are the parsable X509Certificate digital identities.
	Certificates []*x509.Certificate
	// SKIs are the X509SKI digital identities (raw key identifier bytes).
	SKIs [][]byte
	// SubjectNames are the X509SubjectName digital identities as written.
	SubjectNames []string

	// rawCertificates holds the DER of every X509Certificate digital
	// identity, including ones crypto/x509 could not parse, for exact matching.
	rawCertificates [][]byte
}

// hasKeyMaterial reports whether the identity names a key at all, as opposed
// to a subject-name-only (or empty) history instance.
func (id *Identity) hasKeyMaterial() bool {
	return len(id.rawCertificates) > 0 || len(id.SKIs) > 0
}

// match reports whether and how the identity covers c. Only [BySubject] is
// a weak match; see the By constants for the rules.
func (id *Identity) match(c *x509.Certificate) (string, bool) {
	for _, raw := range id.rawCertificates {
		if bytes.Equal(raw, c.Raw) {
			return ByCertificate, true
		}
	}
	for _, listed := range id.Certificates {
		if len(listed.RawSubjectPublicKeyInfo) > 0 && bytes.Equal(listed.RawSubjectPublicKeyInfo, c.RawSubjectPublicKeyInfo) {
			return ByPublicKey, true
		}
	}
	if len(id.rawCertificates) == 0 {
		if ski := publicKeyIdentifier(c); len(ski) > 0 {
			for _, want := range id.SKIs {
				if bytes.Equal(want, ski) {
					return BySKI, true
				}
			}
		}
	}
	if id.matchesSubject(c) {
		return BySubject, true
	}
	return "", false
}

// strong reports whether the identity authenticates c by key.
func (id *Identity) strong(c *x509.Certificate) bool {
	by, ok := id.match(c)
	return ok && by != BySubject
}

func (id *Identity) matchesSubject(c *x509.Certificate) bool {
	if len(id.SubjectNames) == 0 {
		return false
	}
	have := subjectAttributes(c.Subject)
	for _, name := range id.SubjectNames {
		if want, err := parseDN(name); err == nil && equalAttributes(want, have) {
			return true
		}
	}
	return false
}

// StatusPeriod is one entry of a service's status history: the service had
// Status (and, when the list records it, Type) from From until the next
// period starts, and was identified by Identity during that period.
type StatusPeriod struct {
	// Status is the status URI, such as [StatusGranted].
	Status string
	// Type is the service type URI in force during the period; empty when the
	// list did not record one, in which case the service's current Type applies.
	Type string
	// From is when the status took effect (StatusStartingTime).
	From time.Time
	// Identity is the ServiceDigitalIdentity the list gives for this period:
	// the ServiceInformation's for the current period, the
	// ServiceHistoryInstance's for a historical one.
	Identity Identity
}

func (p *StatusPeriod) typeOr(def string) string {
	if p.Type != "" {
		return p.Type
	}
	return def
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
	// History is every status period in ascending order of From; the last
	// element is the current status (the ServiceInformation).
	History []StatusPeriod
	// Problems records structural defects of the entry, such as two status
	// periods starting at the same instant or a history instance dated after
	// the current status. A service with problems is never qualified.
	Problems []string
}

// Current returns the current status period (the ServiceInformation).
func (s *Service) Current() StatusPeriod {
	return s.History[len(s.History)-1]
}

// StatusAt returns the period in force at t, or false when the service was
// not yet listed.
func (s *Service) StatusAt(t time.Time) (StatusPeriod, bool) {
	i, ok := s.periodAt(t)
	if !ok {
		return StatusPeriod{}, false
	}
	return s.History[i], true
}

func (s *Service) periodAt(t time.Time) (int, bool) {
	found := -1
	for i := range s.History {
		if s.History[i].From.After(t) {
			break
		}
		found = i
	}
	return found, found >= 0
}

// QualifiedAt reports whether cert, or one of the certificates in chain, was
// the key-authenticated digital identity of this service while it was a
// granted qualified time-stamping service, at time at.
//
// The decision is made against the status period whose [From, next.From)
// contains at: its status must be [StatusGranted], its type [TypeQTST], and
// its Identity must authenticate the candidate by certificate, public key or
// computed key identifier. One exception accommodates lists whose history
// instances carry only an X509SubjectName (ETSI TS 119 612 lets them omit
// the certificate): a period whose Identity names no key is taken to refer
// to the key in the current ServiceInformation, so the candidate must be
// key-authenticated by the current period's Identity and must bear the
// subject name the history instance gives, if any. A subject-name match is
// never sufficient on its own, a key listed only in another period never
// qualifies outside that period, and a service with Problems never
// qualifies. Historical identities (keys listed only in a history instance)
// are accepted here; [Policy.AllowHistorical] controls that for [Checker].
func (s *Service) QualifiedAt(cert *x509.Certificate, chain []*x509.Certificate, at time.Time) bool {
	return s.qualifiedAt(candidates(cert, chain), at, true)
}

func (s *Service) qualifiedAt(cands []*x509.Certificate, at time.Time, allowHistorical bool) bool {
	if len(s.Problems) > 0 || len(cands) == 0 {
		return false
	}
	i, ok := s.periodAt(at)
	if !ok {
		return false
	}
	p := &s.History[i]
	if p.Status != StatusGranted || p.typeOr(s.Type) != TypeQTST {
		return false
	}
	cur := &s.History[len(s.History)-1].Identity
	for _, c := range cands {
		inCurrent := cur.strong(c)
		if p.Identity.strong(c) {
			if allowHistorical || inCurrent {
				return true
			}
			continue
		}
		if !p.Identity.hasKeyMaterial() && inCurrent && (len(p.Identity.SubjectNames) == 0 || p.Identity.matchesSubject(c)) {
			return true
		}
	}
	return false
}

// PeriodMatch is one status period whose identity matched a candidate.
type PeriodMatch struct {
	// Period is the matched status period.
	Period StatusPeriod
	// By says how the period's identity matched: one of the By constants.
	By string
	// Certificate is the candidate (the TSA certificate or a chain element)
	// that the period's identity matched.
	Certificate *x509.Certificate
}

// Match is one service that identifies a certificate.
type Match struct {
	// Service is the matched service.
	Service *Service
	// By is the strongest match method over Periods.
	By string
	// Certificate is the candidate that produced the strongest match.
	Certificate *x509.Certificate
	// Periods lists every status period whose identity matched, in
	// ascending order of From, with the strongest method found for each.
	Periods []PeriodMatch
}

// List is the merged content of the loaded trusted lists.
type List struct {
	// LOTL is the List of Trusted Lists the national lists were taken from;
	// nil when the List was assembled without one.
	LOTL *LOTL
	// IssuedAt is the LOTL's ListIssueDateTime; zero without a LOTL.
	IssuedAt time.Time
	// NextUpdate is the LOTL's NextUpdate; zero without a LOTL or for a
	// closed list. [Policy.RequireFresh] refuses a List past this time.
	NextUpdate time.Time
	// Lists holds every national list that loaded, by territory; each
	// carries its own NextUpdate.
	Lists map[string]*TL
	// Services are all services of all loaded lists.
	Services []*Service
	// Errors records, by territory, national lists that failed to download
	// or parse and were therefore skipped. [Policy.RequireTerritories]
	// turns such an entry into a check failure.
	Errors map[string]error
	// LoadedAt is when the List was assembled.
	LoadedAt time.Time
}

// Lookup returns every service whose digital identity, in any status period,
// matches cert or one of the certificates in chain. Each service appears
// once, with the strongest match method found and the periods that matched.
// Weak ([BySubject]) matches are included so callers can explain a negative
// [List.Qualified] answer; see the By constants.
func (l *List) Lookup(cert *x509.Certificate, chain []*x509.Certificate) []Match {
	if l == nil || cert == nil {
		return nil
	}
	cands := candidates(cert, chain)
	var out []Match
	for _, svc := range l.Services {
		m := Match{Service: svc}
		for _, p := range svc.History {
			var pm PeriodMatch
			for _, c := range cands {
				by, ok := p.Identity.match(c)
				if ok && (pm.By == "" || rank(by) < rank(pm.By)) {
					pm = PeriodMatch{Period: p, By: by, Certificate: c}
				}
			}
			if pm.By == "" {
				continue
			}
			m.Periods = append(m.Periods, pm)
			if m.By == "" || rank(pm.By) < rank(m.By) {
				m.By, m.Certificate = pm.By, pm.Certificate
			}
		}
		if len(m.Periods) > 0 {
			out = append(out, m)
		}
	}
	return out
}

// Qualified reports whether cert was issued under a service that was a
// granted qualified time-stamping service at the time at, together with the
// services that matched. The rule is that of [Service.QualifiedAt], with
// historical identities accepted. It returns an error for a nil certificate
// or a zero time; a certificate no list knows yields (false, nil, nil).
func (l *List) Qualified(cert *x509.Certificate, chain []*x509.Certificate, at time.Time) (bool, []Match, error) {
	return l.qualified(cert, chain, at, true)
}

func (l *List) qualified(cert *x509.Certificate, chain []*x509.Certificate, at time.Time, allowHistorical bool) (bool, []Match, error) {
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
	cands := candidates(cert, chain)
	for _, m := range matches {
		if m.Service.qualifiedAt(cands, at, allowHistorical) {
			return true, matches, nil
		}
	}
	return false, matches, nil
}

func candidates(cert *x509.Certificate, chain []*x509.Certificate) []*x509.Certificate {
	if cert == nil {
		return nil
	}
	out := make([]*x509.Certificate, 0, 1+len(chain))
	out = append(out, cert)
	for _, c := range chain {
		if c != nil {
			out = append(out, c)
		}
	}
	return out
}

func rank(by string) int {
	switch by {
	case ByCertificate:
		return 0
	case ByPublicKey:
		return 1
	case BySKI:
		return 2
	default:
		return 3
	}
}

// publicKeyIdentifier returns the SHA-1 of the certificate's subjectPublicKey
// bits (RFC 5280 §4.2.1.2 method 1), which is how trusted lists compute
// X509SKI. The SubjectKeyId extension the certificate asserts is
// deliberately not used: it is chosen by the certificate's issuer and would
// let any CA the verifier trusts mint a certificate that matches a listed key
// identifier.
func publicKeyIdentifier(c *x509.Certificate) []byte {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(c.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil
	}
	sum := sha1.Sum(spki.PublicKey.Bytes) //nolint:gosec // see publicKeyIdentifier doc.
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
		return nil, errors.New("eutl: empty distinguished name")
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
