package rfc3161

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// PKIStatus values (RFC 3161 section 2.4.2).
const (
	StatusGranted                = 0
	StatusGrantedWithMods        = 1
	StatusRejection              = 2
	StatusWaiting                = 3
	StatusRevocationWarning      = 4
	StatusRevocationNotification = 5
)

var statusNames = map[int]string{
	StatusGranted:                "granted",
	StatusGrantedWithMods:        "grantedWithMods",
	StatusRejection:              "rejection",
	StatusWaiting:                "waiting",
	StatusRevocationWarning:      "revocationWarning",
	StatusRevocationNotification: "revocationNotification",
}

// FailInfo is the PKIFailureInfo bit string of a rejected request.
type FailInfo asn1.BitString

var failInfoNames = map[int]string{
	0:  "badAlg",
	2:  "badRequest",
	5:  "badDataFormat",
	14: "timeNotAvailable",
	15: "unacceptedPolicy",
	16: "unacceptedExtension",
	17: "addInfoNotAvailable",
	25: "systemFailure",
}

// Names lists the set bits by their RFC 3161 names; unknown bits are
// rendered as "bitN".
func (f FailInfo) Names() []string {
	var names []string
	bs := asn1.BitString(f)
	for i := 0; i < bs.BitLength; i++ {
		if bs.At(i) == 0 {
			continue
		}
		if n, ok := failInfoNames[i]; ok {
			names = append(names, n)
		} else {
			names = append(names, fmt.Sprintf("bit%d", i))
		}
	}
	return names
}

// Has reports whether the named bit (such as "unacceptedPolicy") is set.
func (f FailInfo) Has(name string) bool {
	for _, n := range f.Names() {
		if n == name {
			return true
		}
	}
	return false
}

// StatusError is returned by [Client.Anchor] when the TSA answers with a
// status other than granted or grantedWithMods.
type StatusError struct {
	// Status is the PKIStatus value.
	Status int
	// StatusStrings holds the TSA's free-text explanations, if any.
	StatusStrings []string
	// FailInfo holds the failure bits, if any.
	FailInfo FailInfo
}

// Error describes the status, failure bits and status text.
func (e *StatusError) Error() string {
	name, ok := statusNames[e.Status]
	if !ok {
		name = "unknown"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "rfc3161: TSA returned status %d (%s)", e.Status, name)
	if names := e.FailInfo.Names(); len(names) > 0 {
		fmt.Fprintf(&b, ", failInfo %s", strings.Join(names, "|"))
	}
	if len(e.StatusStrings) > 0 {
		fmt.Fprintf(&b, ": %s", strings.Join(e.StatusStrings, "; "))
	}
	return b.String()
}

// buildRequest encodes a TimeStampReq for a SHA-256 imprint with a fresh
// 64-bit nonce and returns the DER and the nonce.
func buildRequest(digest []byte, policy asn1.ObjectIdentifier, certReq bool) ([]byte, *big.Int, error) {
	if len(digest) != sha256.Size {
		return nil, nil, fmt.Errorf("rfc3161: digest is %d bytes, want %d (SHA-256)", len(digest), sha256.Size)
	}
	var nb [8]byte
	if _, err := rand.Read(nb[:]); err != nil {
		return nil, nil, fmt.Errorf("rfc3161: nonce: %w", err)
	}
	nonce := new(big.Int).SetBytes(nb[:])
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(req *cryptobyte.Builder) {
		req.AddASN1Int64(1)
		req.AddASN1(cbasn1.SEQUENCE, func(mi *cryptobyte.Builder) {
			mi.AddASN1(cbasn1.SEQUENCE, func(alg *cryptobyte.Builder) {
				alg.AddASN1ObjectIdentifier(oidSHA256)
				alg.AddASN1NULL()
			})
			mi.AddASN1OctetString(digest)
		})
		if len(policy) > 0 {
			req.AddASN1ObjectIdentifier(policy)
		}
		req.AddASN1BigInt(nonce)
		if certReq {
			req.AddASN1Boolean(true)
		}
	})
	der, err := b.Bytes()
	if err != nil {
		return nil, nil, fmt.Errorf("rfc3161: encode request: %w", err)
	}
	return der, nonce, nil
}

// parseResponse decodes a TimeStampResp and returns the DER of the
// TimeStampToken when the status is granted or grantedWithMods. Any other
// status is returned as a *StatusError.
func parseResponse(der []byte) ([]byte, error) {
	s := cryptobyte.String(der)
	var resp, statusInfo cryptobyte.String
	if !s.ReadASN1(&resp, cbasn1.SEQUENCE) {
		return nil, malformed("TimeStampResp")
	}
	if !s.Empty() {
		return nil, malformed("TimeStampResp: %d trailing bytes", len(s))
	}
	if !resp.ReadASN1(&statusInfo, cbasn1.SEQUENCE) {
		return nil, malformed("PKIStatusInfo")
	}
	var status int64
	if !statusInfo.ReadASN1Integer(&status) {
		return nil, malformed("PKIStatusInfo status")
	}
	se := &StatusError{Status: int(status)}
	var texts cryptobyte.String
	var present bool
	if !statusInfo.ReadOptionalASN1(&texts, &present, cbasn1.SEQUENCE) {
		return nil, malformed("PKIStatusInfo statusString")
	}
	for !texts.Empty() {
		var t cryptobyte.String
		if !texts.ReadASN1(&t, cbasn1.UTF8String) {
			return nil, malformed("PKIStatusInfo statusString")
		}
		se.StatusStrings = append(se.StatusStrings, string(t))
	}
	if statusInfo.PeekASN1Tag(cbasn1.BIT_STRING) {
		var bs asn1.BitString
		if !statusInfo.ReadASN1BitString(&bs) {
			return nil, malformed("PKIStatusInfo failInfo")
		}
		se.FailInfo = FailInfo(bs)
	}
	if !statusInfo.Empty() {
		return nil, malformed("PKIStatusInfo: trailing bytes")
	}
	if status != StatusGranted && status != StatusGrantedWithMods {
		return nil, se
	}
	var token cryptobyte.String
	if !resp.ReadASN1Element(&token, cbasn1.SEQUENCE) {
		return nil, malformed("status %d but no TimeStampToken", status)
	}
	if !resp.Empty() {
		return nil, malformed("TimeStampResp: trailing bytes after token")
	}
	return []byte(token), nil
}
