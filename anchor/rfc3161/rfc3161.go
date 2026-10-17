// Package rfc3161 anchors seal hashes with an RFC 3161 time-stamp authority
// and verifies the tokens it returns.
//
// A [Client] sends a TimeStampReq over HTTP and returns the DER
// TimeStampToken (a CMS ContentInfo). A [Verifier] checks a token against the
// digest it is claimed to cover: the CMS signature, the content-type,
// message-digest and ESSCertID signed attributes, the message imprint, the
// certificate chain to pinned roots at genTime and the critical timeStamping
// extended key usage, and returns an [anchor.Attestation]. [Provider] joins
// the two as an [anchor.Provider] with ID "rfc3161" and verifies every fresh
// token before handing it back, so a misbehaving authority is caught at
// anchoring time rather than at audit time.
//
// The implementation is self-contained: ASN.1 is built and parsed with
// golang.org/x/crypto/cryptobyte, and nothing inside a token is trusted until
// it has been checked cryptographically or against the configured roots. A
// Verifier without roots rejects every token; it never falls back to the
// system certificate pool.
//
// See docs/anchors/rfc3161.md for what a token proves, how to obtain access to
// a TSA and which roots to pin.
package rfc3161

import (
	"crypto"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	// SHA-1 is registered for ESSCertID (RFC 2634) certificate hashes only;
	// no signature or imprint is accepted with it.
	_ "crypto/sha1" //nolint:gosec // ESSCertID v1 is defined over SHA-1; the signature itself never is
	_ "crypto/sha256"
	_ "crypto/sha512"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Object identifiers used by the protocol.
var (
	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidCTTSTInfo     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningCert   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	oidSigningCertV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}

	oidRSAEncryption   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidRSASSAPSS       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidMGF1            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	oidExtKeyUsage    = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidKPTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
)

// algorithmIdentifier is a parsed AlgorithmIdentifier. Params holds the raw
// parameters element when one is present.
type algorithmIdentifier struct {
	OID       asn1.ObjectIdentifier
	Params    []byte
	HasParams bool
}

// paramsAbsentOrNull reports whether the parameters are absent or an ASN.1
// NULL, the two encodings every algorithm accepted here allows.
func (a algorithmIdentifier) paramsAbsentOrNull() bool {
	return !a.HasParams || (len(a.Params) == 2 && a.Params[0] == 0x05 && a.Params[1] == 0x00)
}

// readAlgorithmIdentifier reads one AlgorithmIdentifier SEQUENCE from s.
func readAlgorithmIdentifier(s *cryptobyte.String) (algorithmIdentifier, error) {
	var seq cryptobyte.String
	var out algorithmIdentifier
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return out, fmt.Errorf("malformed AlgorithmIdentifier")
	}
	if !seq.ReadASN1ObjectIdentifier(&out.OID) {
		return out, fmt.Errorf("malformed AlgorithmIdentifier: algorithm")
	}
	if !seq.Empty() {
		var params cryptobyte.String
		var tag cbasn1.Tag
		if !seq.ReadAnyASN1Element(&params, &tag) {
			return out, fmt.Errorf("malformed AlgorithmIdentifier: parameters")
		}
		out.Params = []byte(params)
		out.HasParams = true
	}
	if !seq.Empty() {
		return out, fmt.Errorf("malformed AlgorithmIdentifier: trailing bytes")
	}
	return out, nil
}

// digestHash maps a digest algorithm identifier to a hash accepted for
// signatures and imprints. SHA-1 is deliberately absent.
func digestHash(oid asn1.ObjectIdentifier) (crypto.Hash, bool) {
	switch {
	case oid.Equal(oidSHA256):
		return crypto.SHA256, true
	case oid.Equal(oidSHA384):
		return crypto.SHA384, true
	case oid.Equal(oidSHA512):
		return crypto.SHA512, true
	}
	return 0, false
}

// certHash maps a hash algorithm identifier to a hash accepted for ESSCertID
// certificate references, where SHA-1 is mandated by RFC 2634 for the v1 form.
func certHash(oid asn1.ObjectIdentifier) (crypto.Hash, bool) {
	if oid.Equal(oidSHA1) {
		return crypto.SHA1, true
	}
	return digestHash(oid)
}

// readGeneralizedTime reads a GeneralizedTime in the form RFC 3161 section
// 2.4.2 requires: YYYYMMDDHHMMSS[.f+]Z, UTC only, seconds present.
func readGeneralizedTime(s *cryptobyte.String) (time.Time, error) {
	var raw cryptobyte.String
	if !s.ReadASN1(&raw, cbasn1.GeneralizedTime) {
		return time.Time{}, fmt.Errorf("malformed GeneralizedTime")
	}
	return parseGeneralizedTime(string(raw))
}

func parseGeneralizedTime(v string) (time.Time, error) {
	const minLen = len("YYYYMMDDHHMMSSZ")
	if len(v) < minLen || v[len(v)-1] != 'Z' {
		return time.Time{}, fmt.Errorf("GeneralizedTime %q: want YYYYMMDDHHMMSS[.f]Z", v)
	}
	body := v[:len(v)-1]
	var nanos int
	if len(body) > 14 {
		if body[14] != '.' || len(body) < 16 || len(body) > 24 {
			return time.Time{}, fmt.Errorf("GeneralizedTime %q: bad fraction", v)
		}
		frac := body[15:]
		scale := 1_000_000_000
		for _, c := range frac {
			if c < '0' || c > '9' {
				return time.Time{}, fmt.Errorf("GeneralizedTime %q: bad fraction", v)
			}
			scale /= 10
			nanos += int(c-'0') * scale
		}
		body = body[:14]
	}
	field := func(from, to int) (int, error) {
		n := 0
		for _, c := range body[from:to] {
			if c < '0' || c > '9' {
				return 0, fmt.Errorf("GeneralizedTime %q: non-digit", v)
			}
			n = n*10 + int(c-'0')
		}
		return n, nil
	}
	var parts [6]int
	bounds := [6][2]int{{0, 4}, {4, 6}, {6, 8}, {8, 10}, {10, 12}, {12, 14}}
	for i, b := range bounds {
		n, err := field(b[0], b[1])
		if err != nil {
			return time.Time{}, err
		}
		parts[i] = n
	}
	t := time.Date(parts[0], time.Month(parts[1]), parts[2], parts[3], parts[4], parts[5], nanos, time.UTC)
	// time.Date normalises out-of-range fields; a genTime that does not
	// round-trip was not a calendar date.
	if t.Year() != parts[0] || int(t.Month()) != parts[1] || t.Day() != parts[2] ||
		t.Hour() != parts[3] || t.Minute() != parts[4] || t.Second() != parts[5] {
		return time.Time{}, fmt.Errorf("GeneralizedTime %q: not a calendar date", v)
	}
	return t, nil
}

// readOptionalBigInt reads an INTEGER into a new big.Int when the next
// element is one; it returns nil when it is not.
func readOptionalBigInt(s *cryptobyte.String) (*big.Int, error) {
	if !s.PeekASN1Tag(cbasn1.INTEGER) {
		return nil, nil
	}
	n := new(big.Int)
	if !s.ReadASN1Integer(n) {
		return nil, fmt.Errorf("malformed INTEGER")
	}
	return n, nil
}

// readSmallInt reads an INTEGER that must fit in an int64.
func readSmallInt(s *cryptobyte.String, what string) (int64, error) {
	var n int64
	if !s.ReadASN1Integer(&n) {
		return 0, fmt.Errorf("malformed %s", what)
	}
	return n, nil
}
