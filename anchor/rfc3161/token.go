package rfc3161

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// ErrMalformed wraps every parse failure of a token, request or response.
var ErrMalformed = errors.New("rfc3161: malformed")

func malformed(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, a...))
}

// MessageImprint is the hash a token binds to a time.
type MessageImprint struct {
	// HashAlgorithm identifies the digest; a seal imprint is always SHA-256.
	HashAlgorithm asn1.ObjectIdentifier
	// HashedMessage is the digest value.
	HashedMessage []byte
}

// Token is a parsed, not verified, TimeStampToken. Every field is taken from
// the token as presented and means nothing until [Verifier.Verify] has
// accepted the token; tools may print it to describe what a token claims.
type Token struct {
	// GenTime is the TSTInfo genTime in UTC.
	GenTime time.Time
	// Accuracy is the TSTInfo accuracy as a duration, zero when absent.
	Accuracy time.Duration
	// Policy is the TSA policy under which the token was issued.
	Policy asn1.ObjectIdentifier
	// SerialNumber is the TSA's serial number for the token.
	SerialNumber *big.Int
	// Nonce echoes the request nonce; nil when absent.
	Nonce *big.Int
	// MessageImprint is the digest the token covers.
	MessageImprint MessageImprint
	// Ordering is the TSTInfo ordering flag.
	Ordering bool
	// TSA is the TSTInfo tsa name when present and of a kind this package
	// renders (directoryName, rfc822Name, dNSName or URI); otherwise empty.
	TSA string
	// SignerCertificate is the included certificate that the SignerInfo
	// identifies, or nil when the token does not carry it.
	SignerCertificate *x509.Certificate
	// Certificates are all certificates included in the token, in order.
	Certificates []*x509.Certificate

	sd *signedData
}

// signedData is the parsed CMS SignedData of a token.
type signedData struct {
	version          int64
	digestAlgorithms []algorithmIdentifier
	eContentType     asn1.ObjectIdentifier
	eContent         []byte // the TSTInfo DER (OCTET STRING contents)
	certs            []*x509.Certificate
	signer           signerInfo
}

// signerInfo is the single SignerInfo of a token.
type signerInfo struct {
	version            int64
	issuer             []byte // raw Name when sid is issuerAndSerialNumber
	serial             *big.Int
	subjectKeyID       []byte // when sid is subjectKeyIdentifier
	digestAlgorithm    algorithmIdentifier
	signedAttrsDER     []byte // the signed attributes re-tagged as SET OF: what the signature covers
	attrs              []attribute
	signatureAlgorithm algorithmIdentifier
	signature          []byte
}

// attribute is one signed Attribute with the DER of each of its values.
type attribute struct {
	oid    asn1.ObjectIdentifier
	values [][]byte
}

// ParseToken parses a DER TimeStampToken (the CMS ContentInfo a TSA returns
// inside TimeStampResp) and its TSTInfo. It checks structure only: that the
// token is well-formed DER without trailing bytes, is a SignedData carrying
// id-ct-TSTInfo with exactly one SignerInfo and signed attributes, that the
// TSTInfo is version 1 with no critical extensions, and that any included
// certificates parse. Nothing is verified; use [Verifier.Verify] for that.
func ParseToken(der []byte) (*Token, error) {
	sd, err := parseSignedData(der)
	if err != nil {
		return nil, err
	}
	tok, err := parseTSTInfo(sd.eContent)
	if err != nil {
		return nil, err
	}
	tok.sd = sd
	tok.Certificates = sd.certs
	tok.SignerCertificate, err = findSigner(sd)
	if err != nil {
		return nil, err
	}
	return tok, nil
}

func parseSignedData(der []byte) (*signedData, error) {
	s := cryptobyte.String(der)
	var ci cryptobyte.String
	if !s.ReadASN1(&ci, cbasn1.SEQUENCE) {
		return nil, malformed("token: not a ContentInfo")
	}
	if !s.Empty() {
		return nil, malformed("token: %d trailing bytes after ContentInfo", len(s))
	}
	var contentType asn1.ObjectIdentifier
	if !ci.ReadASN1ObjectIdentifier(&contentType) {
		return nil, malformed("token: contentType")
	}
	if !contentType.Equal(oidSignedData) {
		return nil, malformed("token: contentType %s, want id-signedData", contentType)
	}
	var content, sd cryptobyte.String
	if !ci.ReadASN1(&content, cbasn1.Tag(0).ContextSpecific().Constructed()) || !ci.Empty() {
		return nil, malformed("token: content")
	}
	if !content.ReadASN1(&sd, cbasn1.SEQUENCE) || !content.Empty() {
		return nil, malformed("token: SignedData")
	}
	out := &signedData{}
	var err error
	if out.version, err = readSmallInt(&sd, "SignedData version"); err != nil {
		return nil, malformed("%v", err)
	}
	if out.version < 1 || out.version > 5 {
		return nil, malformed("SignedData version %d", out.version)
	}
	var das cryptobyte.String
	if !sd.ReadASN1(&das, cbasn1.SET) {
		return nil, malformed("SignedData digestAlgorithms")
	}
	for !das.Empty() {
		alg, err := readAlgorithmIdentifier(&das)
		if err != nil {
			return nil, malformed("SignedData digestAlgorithms: %v", err)
		}
		out.digestAlgorithms = append(out.digestAlgorithms, alg)
	}
	if err := parseEncapContentInfo(&sd, out); err != nil {
		return nil, err
	}
	var certs cryptobyte.String
	var present bool
	if !sd.ReadOptionalASN1(&certs, &present, cbasn1.Tag(0).ContextSpecific().Constructed()) {
		return nil, malformed("SignedData certificates")
	}
	if present {
		if out.certs, err = parseCertificateSet(certs); err != nil {
			return nil, err
		}
	}
	var crls cryptobyte.String
	if !sd.ReadOptionalASN1(&crls, &present, cbasn1.Tag(1).ContextSpecific().Constructed()) {
		return nil, malformed("SignedData crls")
	}
	var sis cryptobyte.String
	if !sd.ReadASN1(&sis, cbasn1.SET) || !sd.Empty() {
		return nil, malformed("SignedData signerInfos")
	}
	n := 0
	for !sis.Empty() {
		n++
		if n > 1 {
			return nil, malformed("SignedData has more than one SignerInfo")
		}
		if out.signer, err = parseSignerInfo(&sis); err != nil {
			return nil, err
		}
	}
	if n == 0 {
		return nil, malformed("SignedData has no SignerInfo")
	}
	return out, nil
}

func parseEncapContentInfo(sd *cryptobyte.String, out *signedData) error {
	var eci cryptobyte.String
	if !sd.ReadASN1(&eci, cbasn1.SEQUENCE) {
		return malformed("encapContentInfo")
	}
	if !eci.ReadASN1ObjectIdentifier(&out.eContentType) {
		return malformed("encapContentInfo eContentType")
	}
	if !out.eContentType.Equal(oidCTTSTInfo) {
		return malformed("eContentType %s, want id-ct-TSTInfo", out.eContentType)
	}
	var wrapper, content cryptobyte.String
	if !eci.ReadASN1(&wrapper, cbasn1.Tag(0).ContextSpecific().Constructed()) || !eci.Empty() {
		return malformed("encapContentInfo eContent missing")
	}
	if !wrapper.ReadASN1(&content, cbasn1.OCTET_STRING) || !wrapper.Empty() {
		return malformed("encapContentInfo eContent")
	}
	out.eContent = []byte(content)
	return nil
}

// parseCertificateSet reads a CertificateSet. Only the certificate choice is
// accepted; attribute certificates and other forms have no role in a
// time-stamp token and are rejected rather than skipped.
func parseCertificateSet(set cryptobyte.String) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for !set.Empty() {
		var el cryptobyte.String
		if !set.PeekASN1Tag(cbasn1.SEQUENCE) {
			return nil, malformed("certificates: unsupported CertificateChoices")
		}
		if !set.ReadASN1Element(&el, cbasn1.SEQUENCE) {
			return nil, malformed("certificates: element")
		}
		c, err := x509.ParseCertificate(el)
		if err != nil {
			return nil, malformed("certificates: %v", err)
		}
		certs = append(certs, c)
	}
	return certs, nil
}

func parseSignerInfo(sis *cryptobyte.String) (signerInfo, error) {
	var si cryptobyte.String
	var out signerInfo
	if !sis.ReadASN1(&si, cbasn1.SEQUENCE) {
		return out, malformed("SignerInfo")
	}
	var err error
	if out.version, err = readSmallInt(&si, "SignerInfo version"); err != nil {
		return out, malformed("%v", err)
	}
	switch {
	case si.PeekASN1Tag(cbasn1.SEQUENCE):
		var ias cryptobyte.String
		if !si.ReadASN1(&ias, cbasn1.SEQUENCE) {
			return out, malformed("SignerInfo sid")
		}
		var issuer cryptobyte.String
		if !ias.ReadASN1Element(&issuer, cbasn1.SEQUENCE) {
			return out, malformed("SignerInfo sid issuer")
		}
		out.issuer = []byte(issuer)
		out.serial = new(big.Int)
		if !ias.ReadASN1Integer(out.serial) || !ias.Empty() {
			return out, malformed("SignerInfo sid serialNumber")
		}
		if out.version != 1 {
			return out, malformed("SignerInfo version %d with issuerAndSerialNumber, want 1", out.version)
		}
	case si.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific()):
		var ski cryptobyte.String
		if !si.ReadASN1(&ski, cbasn1.Tag(0).ContextSpecific()) || len(ski) == 0 {
			return out, malformed("SignerInfo sid subjectKeyIdentifier")
		}
		out.subjectKeyID = []byte(ski)
		if out.version != 3 {
			return out, malformed("SignerInfo version %d with subjectKeyIdentifier, want 3", out.version)
		}
	default:
		return out, malformed("SignerInfo sid: unknown choice")
	}
	if out.digestAlgorithm, err = readAlgorithmIdentifier(&si); err != nil {
		return out, malformed("SignerInfo digestAlgorithm: %v", err)
	}
	var attrsEl cryptobyte.String
	if !si.ReadASN1Element(&attrsEl, cbasn1.Tag(0).ContextSpecific().Constructed()) {
		return out, malformed("SignerInfo signedAttrs missing")
	}
	// The signature covers the attributes encoded as SET OF (tag 0x31)
	// rather than with the IMPLICIT [0] tag they carry in the SignerInfo
	// (RFC 5652 section 5.4). The length octets are identical.
	out.signedAttrsDER = bytes.Clone(attrsEl)
	out.signedAttrsDER[0] = byte(cbasn1.SET)
	attrs := attrsEl
	var attrsBody cryptobyte.String
	if !attrs.ReadASN1(&attrsBody, cbasn1.Tag(0).ContextSpecific().Constructed()) {
		return out, malformed("SignerInfo signedAttrs")
	}
	if out.attrs, err = parseAttributes(attrsBody); err != nil {
		return out, err
	}
	if out.signatureAlgorithm, err = readAlgorithmIdentifier(&si); err != nil {
		return out, malformed("SignerInfo signatureAlgorithm: %v", err)
	}
	var sig cryptobyte.String
	if !si.ReadASN1(&sig, cbasn1.OCTET_STRING) || len(sig) == 0 {
		return out, malformed("SignerInfo signature")
	}
	out.signature = []byte(sig)
	var unsigned cryptobyte.String
	var present bool
	if !si.ReadOptionalASN1(&unsigned, &present, cbasn1.Tag(1).ContextSpecific().Constructed()) || !si.Empty() {
		return out, malformed("SignerInfo trailing bytes")
	}
	return out, nil
}

// parseAttributes reads a SET OF Attribute. RFC 5652 section 5.3 forbids two
// attributes of the same type and requires at least one value each.
func parseAttributes(set cryptobyte.String) ([]attribute, error) {
	var attrs []attribute
	for !set.Empty() {
		var a cryptobyte.String
		if !set.ReadASN1(&a, cbasn1.SEQUENCE) {
			return nil, malformed("Attribute")
		}
		var attr attribute
		if !a.ReadASN1ObjectIdentifier(&attr.oid) {
			return nil, malformed("Attribute attrType")
		}
		var values cryptobyte.String
		if !a.ReadASN1(&values, cbasn1.SET) || !a.Empty() {
			return nil, malformed("Attribute %s attrValues", attr.oid)
		}
		for !values.Empty() {
			var v cryptobyte.String
			var tag cbasn1.Tag
			if !values.ReadAnyASN1Element(&v, &tag) {
				return nil, malformed("Attribute %s value", attr.oid)
			}
			attr.values = append(attr.values, []byte(v))
		}
		if len(attr.values) == 0 {
			return nil, malformed("Attribute %s has no value", attr.oid)
		}
		for _, prev := range attrs {
			if prev.oid.Equal(attr.oid) {
				return nil, malformed("Attribute %s appears twice", attr.oid)
			}
		}
		attrs = append(attrs, attr)
	}
	return attrs, nil
}

// attr returns the single value of the attribute with the given type, or nil.
// An attribute with several values where one is expected is an error.
func (si *signerInfo) attr(oid asn1.ObjectIdentifier) ([]byte, error) {
	for _, a := range si.attrs {
		if a.oid.Equal(oid) {
			if len(a.values) != 1 {
				return nil, malformed("Attribute %s has %d values, want 1", oid, len(a.values))
			}
			return a.values[0], nil
		}
	}
	return nil, nil
}

// findSigner locates the certificate the SignerInfo identifies among the
// included certificates. Two different certificates matching the identifier
// is ambiguous and rejected.
func findSigner(sd *signedData) (*x509.Certificate, error) {
	var found *x509.Certificate
	for _, c := range sd.certs {
		var match bool
		if sd.signer.serial != nil {
			match = bytes.Equal(c.RawIssuer, sd.signer.issuer) && c.SerialNumber.Cmp(sd.signer.serial) == 0
		} else {
			match = len(c.SubjectKeyId) > 0 && bytes.Equal(c.SubjectKeyId, sd.signer.subjectKeyID)
		}
		if !match {
			continue
		}
		if found != nil && !found.Equal(c) {
			return nil, malformed("two different certificates match the SignerIdentifier")
		}
		if found == nil {
			found = c
		}
	}
	return found, nil
}

func parseTSTInfo(der []byte) (*Token, error) {
	s := cryptobyte.String(der)
	var ti cryptobyte.String
	if !s.ReadASN1(&ti, cbasn1.SEQUENCE) {
		return nil, malformed("TSTInfo")
	}
	if !s.Empty() {
		return nil, malformed("TSTInfo: %d trailing bytes", len(s))
	}
	tok := &Token{}
	version, err := readSmallInt(&ti, "TSTInfo version")
	if err != nil {
		return nil, malformed("%v", err)
	}
	if version != 1 {
		return nil, malformed("TSTInfo version %d, want 1", version)
	}
	if !ti.ReadASN1ObjectIdentifier(&tok.Policy) {
		return nil, malformed("TSTInfo policy")
	}
	if tok.MessageImprint, err = readMessageImprint(&ti); err != nil {
		return nil, err
	}
	tok.SerialNumber = new(big.Int)
	if !ti.ReadASN1Integer(tok.SerialNumber) {
		return nil, malformed("TSTInfo serialNumber")
	}
	if tok.GenTime, err = readGeneralizedTime(&ti); err != nil {
		return nil, malformed("TSTInfo genTime: %v", err)
	}
	if tok.Accuracy, err = readAccuracy(&ti); err != nil {
		return nil, err
	}
	if ti.PeekASN1Tag(cbasn1.BOOLEAN) && !ti.ReadASN1Boolean(&tok.Ordering) {
		return nil, malformed("TSTInfo ordering")
	}
	if tok.Nonce, err = readOptionalBigInt(&ti); err != nil {
		return nil, malformed("TSTInfo nonce")
	}
	var tsa cryptobyte.String
	var present bool
	if !ti.ReadOptionalASN1(&tsa, &present, cbasn1.Tag(0).ContextSpecific().Constructed()) {
		return nil, malformed("TSTInfo tsa")
	}
	if present {
		if tok.TSA, err = parseGeneralName(tsa); err != nil {
			return nil, err
		}
	}
	var exts cryptobyte.String
	if !ti.ReadOptionalASN1(&exts, &present, cbasn1.Tag(1).ContextSpecific().Constructed()) {
		return nil, malformed("TSTInfo extensions")
	}
	if present {
		if err := checkExtensions(exts); err != nil {
			return nil, err
		}
	}
	if !ti.Empty() {
		return nil, malformed("TSTInfo: unexpected trailing fields")
	}
	return tok, nil
}

func readMessageImprint(s *cryptobyte.String) (MessageImprint, error) {
	var mi cryptobyte.String
	var out MessageImprint
	if !s.ReadASN1(&mi, cbasn1.SEQUENCE) {
		return out, malformed("MessageImprint")
	}
	alg, err := readAlgorithmIdentifier(&mi)
	if err != nil {
		return out, malformed("MessageImprint hashAlgorithm: %v", err)
	}
	if !alg.paramsAbsentOrNull() {
		return out, malformed("MessageImprint hashAlgorithm has parameters")
	}
	out.HashAlgorithm = alg.OID
	var hashed cryptobyte.String
	if !mi.ReadASN1(&hashed, cbasn1.OCTET_STRING) || !mi.Empty() {
		return out, malformed("MessageImprint hashedMessage")
	}
	out.HashedMessage = []byte(hashed)
	return out, nil
}

// readAccuracy reads the optional Accuracy SEQUENCE and returns it as a
// duration. Millis and micros are bounded to 0..999 as the schema intends.
func readAccuracy(s *cryptobyte.String) (time.Duration, error) {
	var acc cryptobyte.String
	var present bool
	if !s.ReadOptionalASN1(&acc, &present, cbasn1.SEQUENCE) {
		return 0, malformed("TSTInfo accuracy")
	}
	if !present {
		return 0, nil
	}
	var seconds, millis, micros int64
	if acc.PeekASN1Tag(cbasn1.INTEGER) {
		if !acc.ReadASN1Integer(&seconds) {
			return 0, malformed("accuracy seconds")
		}
	}
	if acc.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific()) && !acc.ReadASN1Int64WithTag(&millis, cbasn1.Tag(0).ContextSpecific()) {
		return 0, malformed("accuracy millis")
	}
	if acc.PeekASN1Tag(cbasn1.Tag(1).ContextSpecific()) && !acc.ReadASN1Int64WithTag(&micros, cbasn1.Tag(1).ContextSpecific()) {
		return 0, malformed("accuracy micros")
	}
	if !acc.Empty() {
		return 0, malformed("accuracy: trailing bytes")
	}
	const maxSeconds = int64(1 << 40) // far beyond any plausible accuracy, keeps the duration from overflowing
	if seconds < 0 || seconds > maxSeconds || millis < 0 || millis > 999 || micros < 0 || micros > 999 {
		return 0, malformed("accuracy out of range: %ds %dms %dus", seconds, millis, micros)
	}
	return time.Duration(seconds)*time.Second + time.Duration(millis)*time.Millisecond + time.Duration(micros)*time.Microsecond, nil
}

// parseGeneralName renders the GeneralName inside the explicit [0] tsa field.
// Unsupported name forms yield an empty string; they are informational only.
func parseGeneralName(s cryptobyte.String) (string, error) {
	var body cryptobyte.String
	var tag cbasn1.Tag
	if !s.ReadAnyASN1(&body, &tag) || !s.Empty() {
		return "", malformed("tsa GeneralName")
	}
	switch tag {
	case cbasn1.Tag(1).ContextSpecific(), cbasn1.Tag(2).ContextSpecific(), cbasn1.Tag(6).ContextSpecific():
		return string(body), nil
	case cbasn1.Tag(4).ContextSpecific().Constructed():
		var name pkix.RDNSequence
		rest, err := asn1.Unmarshal(body, &name)
		if err != nil || len(rest) != 0 {
			return "", malformed("tsa directoryName")
		}
		var n pkix.Name
		n.FillFromRDNSequence(&name)
		return n.String(), nil
	default:
		return "", nil
	}
}

// checkExtensions parses TSTInfo extensions and rejects any marked critical,
// since this package understands none (RFC 3161 section 2.4.2).
func checkExtensions(exts cryptobyte.String) error {
	for !exts.Empty() {
		var ext cryptobyte.String
		if !exts.ReadASN1(&ext, cbasn1.SEQUENCE) {
			return malformed("TSTInfo extension")
		}
		var id asn1.ObjectIdentifier
		if !ext.ReadASN1ObjectIdentifier(&id) {
			return malformed("TSTInfo extension extnID")
		}
		var critical bool
		if ext.PeekASN1Tag(cbasn1.BOOLEAN) && !ext.ReadASN1Boolean(&critical) {
			return malformed("TSTInfo extension critical")
		}
		var value cryptobyte.String
		if !ext.ReadASN1(&value, cbasn1.OCTET_STRING) || !ext.Empty() {
			return malformed("TSTInfo extension extnValue")
		}
		if critical {
			return malformed("TSTInfo has unknown critical extension %s", id)
		}
	}
	return nil
}
