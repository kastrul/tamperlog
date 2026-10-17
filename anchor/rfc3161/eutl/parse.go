package eutl

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

// XML namespaces of ETSI TS 119 612 trusted lists.
const (
	// NamespaceTSL is the main trusted list namespace.
	NamespaceTSL = "http://uri.etsi.org/02231/v2#"
	// NamespaceAdditionalTypes carries MimeType inside LOTL pointers.
	NamespaceAdditionalTypes = "http://uri.etsi.org/02231/v2/additionaltypes#"
)

// MimeTypeXML is the MimeType of a pointer to an XML trusted list; pointers
// with other types (application/pdf) are human-readable renderings.
const MimeTypeXML = "application/vnd.etsi.tsl+xml"

// TSLTypeLOTL is the TSLType of the List of Trusted Lists itself; the LOTL
// contains a pointer of this type to its own location.
const TSLTypeLOTL = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists"

// ErrNotTrustedList is returned when the document is not an ETSI trusted
// list or lacks a field this package relies on.
var ErrNotTrustedList = errors.New("eutl: not a trusted list")

// Pointer is one OtherTSLPointer of the LOTL: where a national list lives and
// which certificates sign it.
type Pointer struct {
	// Territory is the SchemeTerritory, such as "EE".
	Territory string
	// URL is the TSLLocation.
	URL string
	// MimeType is the pointer's MimeType; only [MimeTypeXML] is loadable.
	MimeType string
	// TSLType is the pointed list's type; [TSLTypeLOTL] for the self-pointer.
	TSLType string
	// SigningCertificates are the ServiceDigitalIdentities of the pointer:
	// the certificates entitled to sign the pointed list. They are exposed for
	// a future XML-DSig step; this package does not verify list signatures.
	SigningCertificates []*x509.Certificate
	// RawSigningCertificates holds the DER of every signing certificate,
	// including any that crypto/x509 could not parse.
	RawSigningCertificates [][]byte
}

// LOTL is the parsed List of Trusted Lists.
type LOTL struct {
	// Territory is the SchemeTerritory ("EU").
	Territory string
	// SequenceNumber is the TSLSequenceNumber.
	SequenceNumber int
	// ListIssueDateTime is when the list was issued.
	ListIssueDateTime time.Time
	// NextUpdate is when the publisher promises a newer list; callers should
	// refuse a list whose NextUpdate has passed. Zero when the list is closed
	// (an empty NextUpdate element, as on the frozen UK list).
	NextUpdate time.Time
	// Pointers are the OtherTSLPointer entries, including the self-pointer
	// and PDF renderings.
	Pointers []Pointer
}

// TL is the parsed national trusted list.
type TL struct {
	// Territory is the SchemeTerritory, such as "EE".
	Territory string
	// SequenceNumber is the TSLSequenceNumber.
	SequenceNumber int
	// ListIssueDateTime is when the list was issued.
	ListIssueDateTime time.Time
	// NextUpdate is when the publisher promises a newer list; zero when the
	// list is closed (empty NextUpdate element).
	NextUpdate time.Time
	// Services are the list's TSPService entries.
	Services []*Service
}

// XML shapes. Unknown elements are ignored by encoding/xml; the fields below
// are the ones this package reads.

type xmlList struct {
	XMLName   xml.Name      `xml:"http://uri.etsi.org/02231/v2# TrustServiceStatusList"`
	Scheme    xmlScheme     `xml:"http://uri.etsi.org/02231/v2# SchemeInformation"`
	Providers []xmlProvider `xml:"TrustServiceProviderList>TrustServiceProvider"`
}

type xmlScheme struct {
	SequenceNumber    string       `xml:"http://uri.etsi.org/02231/v2# TSLSequenceNumber"`
	TSLType           string       `xml:"http://uri.etsi.org/02231/v2# TSLType"`
	Territory         string       `xml:"http://uri.etsi.org/02231/v2# SchemeTerritory"`
	Pointers          []xmlPointer `xml:"PointersToOtherTSL>OtherTSLPointer"`
	ListIssueDateTime string       `xml:"http://uri.etsi.org/02231/v2# ListIssueDateTime"`
	NextUpdate        string       `xml:"NextUpdate>dateTime"`
}

type xmlPointer struct {
	Identities []xmlDigitalIdentity  `xml:"ServiceDigitalIdentities>ServiceDigitalIdentity"`
	Location   string                `xml:"http://uri.etsi.org/02231/v2# TSLLocation"`
	Other      []xmlOtherInformation `xml:"AdditionalInformation>OtherInformation"`
}

type xmlOtherInformation struct {
	TSLType   string `xml:"http://uri.etsi.org/02231/v2# TSLType"`
	Territory string `xml:"http://uri.etsi.org/02231/v2# SchemeTerritory"`
	MimeType  string `xml:"http://uri.etsi.org/02231/v2/additionaltypes# MimeType"`
}

type xmlDigitalIdentity struct {
	IDs []xmlDigitalID `xml:"http://uri.etsi.org/02231/v2# DigitalId"`
}

type xmlDigitalID struct {
	Certificate string `xml:"http://uri.etsi.org/02231/v2# X509Certificate"`
	SKI         string `xml:"http://uri.etsi.org/02231/v2# X509SKI"`
	SubjectName string `xml:"http://uri.etsi.org/02231/v2# X509SubjectName"`
}

type xmlName struct {
	Lang  string `xml:"lang,attr"`
	Value string `xml:",chardata"`
}

type xmlProvider struct {
	Names    []xmlName    `xml:"TSPInformation>TSPName>Name"`
	Services []xmlService `xml:"TSPServices>TSPService"`
}

type xmlService struct {
	Information xmlServiceInformation   `xml:"http://uri.etsi.org/02231/v2# ServiceInformation"`
	History     []xmlServiceInformation `xml:"ServiceHistory>ServiceHistoryInstance"`
}

type xmlServiceInformation struct {
	Type       string             `xml:"http://uri.etsi.org/02231/v2# ServiceTypeIdentifier"`
	Names      []xmlName          `xml:"ServiceName>Name"`
	Identity   xmlDigitalIdentity `xml:"http://uri.etsi.org/02231/v2# ServiceDigitalIdentity"`
	Status     string             `xml:"http://uri.etsi.org/02231/v2# ServiceStatus"`
	StatusFrom string             `xml:"http://uri.etsi.org/02231/v2# StatusStartingTime"`
}

// ParseLOTL parses the List of Trusted Lists.
func ParseLOTL(r io.Reader) (*LOTL, error) {
	doc, err := decode(r)
	if err != nil {
		return nil, err
	}
	if doc.Scheme.TSLType != TSLTypeLOTL {
		return nil, fmt.Errorf("%w: TSLType %q is not the list of the lists", ErrNotTrustedList, doc.Scheme.TSLType)
	}
	out := &LOTL{Territory: doc.Scheme.Territory}
	if out.SequenceNumber, out.ListIssueDateTime, out.NextUpdate, err = schemeFields(&doc.Scheme); err != nil {
		return nil, err
	}
	out.Pointers = make([]Pointer, 0, len(doc.Scheme.Pointers))
	for i := range doc.Scheme.Pointers {
		p, err := parsePointer(&doc.Scheme.Pointers[i])
		if err != nil {
			return nil, fmt.Errorf("eutl: pointer %d: %w", i, err)
		}
		out.Pointers = append(out.Pointers, p)
	}
	return out, nil
}

// ParseTL parses a national trusted list.
func ParseTL(r io.Reader) (*TL, error) {
	doc, err := decode(r)
	if err != nil {
		return nil, err
	}
	if doc.Scheme.TSLType == TSLTypeLOTL {
		return nil, fmt.Errorf("%w: document is the list of the lists, not a national list", ErrNotTrustedList)
	}
	if doc.Scheme.Territory == "" {
		return nil, fmt.Errorf("%w: missing SchemeTerritory", ErrNotTrustedList)
	}
	out := &TL{Territory: doc.Scheme.Territory}
	if out.SequenceNumber, out.ListIssueDateTime, out.NextUpdate, err = schemeFields(&doc.Scheme); err != nil {
		return nil, err
	}
	for pi := range doc.Providers {
		prov := &doc.Providers[pi]
		provider := pickName(prov.Names)
		for si := range prov.Services {
			svc, err := parseService(out.Territory, provider, &prov.Services[si])
			if err != nil {
				return nil, fmt.Errorf("eutl: %s: provider %q service %d: %w", out.Territory, provider, si, err)
			}
			out.Services = append(out.Services, svc)
		}
	}
	return out, nil
}

func decode(r io.Reader) (*xmlList, error) {
	var doc xmlList
	dec := xml.NewDecoder(r)
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotTrustedList, err)
	}
	if doc.XMLName.Space != NamespaceTSL {
		return nil, fmt.Errorf("%w: root namespace %q", ErrNotTrustedList, doc.XMLName.Space)
	}
	return &doc, nil
}

func schemeFields(s *xmlScheme) (int, time.Time, time.Time, error) {
	seq, err := strconv.Atoi(strings.TrimSpace(s.SequenceNumber))
	if err != nil {
		return 0, time.Time{}, time.Time{}, fmt.Errorf("%w: TSLSequenceNumber %q", ErrNotTrustedList, s.SequenceNumber)
	}
	issued, err := parseTime(s.ListIssueDateTime)
	if err != nil {
		return 0, time.Time{}, time.Time{}, fmt.Errorf("%w: ListIssueDateTime: %w", ErrNotTrustedList, err)
	}
	var next time.Time
	if strings.TrimSpace(s.NextUpdate) != "" { // empty NextUpdate marks a closed list
		if next, err = parseTime(s.NextUpdate); err != nil {
			return 0, time.Time{}, time.Time{}, fmt.Errorf("%w: NextUpdate: %w", ErrNotTrustedList, err)
		}
	}
	return seq, issued, next, nil
}

func parseTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, errors.New("missing")
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

func parsePointer(x *xmlPointer) (Pointer, error) {
	p := Pointer{URL: strings.TrimSpace(x.Location)}
	if p.URL == "" {
		return p, errors.New("missing TSLLocation")
	}
	for _, o := range x.Other {
		switch {
		case o.TSLType != "":
			p.TSLType = strings.TrimSpace(o.TSLType)
		case o.Territory != "":
			p.Territory = strings.TrimSpace(o.Territory)
		case o.MimeType != "":
			p.MimeType = strings.TrimSpace(o.MimeType)
		}
	}
	if p.Territory == "" {
		return p, errors.New("missing SchemeTerritory")
	}
	for _, id := range x.Identities {
		for _, d := range id.IDs {
			if d.Certificate == "" {
				continue
			}
			raw, err := decodeBase64(d.Certificate)
			if err != nil {
				return p, fmt.Errorf("signing certificate: %w", err)
			}
			p.RawSigningCertificates = append(p.RawSigningCertificates, raw)
			if c, err := x509.ParseCertificate(raw); err == nil {
				p.SigningCertificates = append(p.SigningCertificates, c)
			}
		}
	}
	return p, nil
}

func parseService(territory, provider string, x *xmlService) (*Service, error) {
	info := &x.Information
	svc := &Service{
		Territory: territory,
		Provider:  provider,
		Name:      pickName(info.Names),
		Type:      strings.TrimSpace(info.Type),
	}
	if svc.Type == "" {
		return nil, errors.New("missing ServiceTypeIdentifier")
	}
	seen := map[string]bool{}
	addIdentity := func(id *xmlDigitalIdentity) error {
		for _, d := range id.IDs {
			switch {
			case d.Certificate != "":
				raw, err := decodeBase64(d.Certificate)
				if err != nil {
					return fmt.Errorf("X509Certificate: %w", err)
				}
				if !seen["c:"+string(raw)] {
					seen["c:"+string(raw)] = true
					svc.rawCertificates = append(svc.rawCertificates, raw)
					if c, err := x509.ParseCertificate(raw); err == nil {
						svc.Certificates = append(svc.Certificates, c)
					}
				}
			case d.SKI != "":
				ski, err := decodeBase64(d.SKI)
				if err != nil {
					return fmt.Errorf("X509SKI: %w", err)
				}
				if !seen["s:"+string(ski)] {
					seen["s:"+string(ski)] = true
					svc.SKIs = append(svc.SKIs, ski)
				}
			case d.SubjectName != "":
				name := strings.TrimSpace(d.SubjectName)
				if !seen["n:"+name] {
					seen["n:"+name] = true
					svc.SubjectNames = append(svc.SubjectNames, name)
				}
			}
		}
		return nil
	}
	period := func(si *xmlServiceInformation) (StatusPeriod, error) {
		status := strings.TrimSpace(si.Status)
		if status == "" {
			return StatusPeriod{}, errors.New("missing ServiceStatus")
		}
		from, err := parseTime(si.StatusFrom)
		if err != nil {
			return StatusPeriod{}, fmt.Errorf("StatusStartingTime: %w", err)
		}
		return StatusPeriod{Status: status, Type: strings.TrimSpace(si.Type), From: from}, nil
	}
	if err := addIdentity(&info.Identity); err != nil {
		return nil, err
	}
	cur, err := period(info)
	if err != nil {
		return nil, err
	}
	svc.History = append(svc.History, cur)
	for i := range x.History {
		h := &x.History[i]
		if err := addIdentity(&h.Identity); err != nil {
			return nil, fmt.Errorf("history %d: %w", i, err)
		}
		p, err := period(h)
		if err != nil {
			return nil, fmt.Errorf("history %d: %w", i, err)
		}
		svc.History = append(svc.History, p)
	}
	sort.SliceStable(svc.History, func(i, j int) bool { return svc.History[i].From.Before(svc.History[j].From) })
	return svc, nil
}

// pickName prefers the English name, then the first one given.
func pickName(names []xmlName) string {
	first := ""
	for _, n := range names {
		v := strings.TrimSpace(n.Value)
		if v == "" {
			continue
		}
		if strings.EqualFold(n.Lang, "en") {
			return v
		}
		if first == "" {
			first = v
		}
	}
	return first
}

func decodeBase64(s string) ([]byte, error) {
	s = strings.Join(strings.Fields(s), "")
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}
	if len(raw) == 0 {
		return nil, errors.New("empty value")
	}
	return raw, nil
}
