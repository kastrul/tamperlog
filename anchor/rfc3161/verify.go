package rfc3161

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/kastrul/tamperlog/anchor"
)

// minRSABits is the smallest RSA modulus accepted for a token signature.
const minRSABits = 2048

// Verifier checks time-stamp tokens against pinned roots.
type Verifier struct {
	roots         *x509.CertPool
	intermediates *x509.CertPool
	policies      []asn1.ObjectIdentifier
	maxAccuracy   time.Duration
	qualified     func(cert *x509.Certificate, at time.Time) (bool, error)
}

// NewVerifier returns a Verifier that accepts tokens whose signer chains to
// roots at genTime. Pass the TSA operator's published root (see
// docs/anchors/rfc3161.md); a nil or empty pool rejects every token, the
// system pool is never consulted. Options meant for [Client] are ignored.
func NewVerifier(roots *x509.CertPool, opts ...Option) *Verifier {
	o := applyOptions(opts)
	return &Verifier{
		roots:         roots,
		intermediates: o.intermediates,
		policies:      o.policies,
		maxAccuracy:   o.maxAccuracy,
		qualified:     o.qualified,
	}
}

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", anchor.ErrInvalidProof, fmt.Sprintf(format, a...))
}

// Verify checks that token is a TimeStampToken over digest, the SHA-256 of a
// seal's canonical bytes, issued by an authority that chains to the pinned
// roots, and returns what it attests. Every failure wraps
// [anchor.ErrInvalidProof]. The checks are, in order: structure
// ([ParseToken]), message imprint, signer certificate present, CMS signature
// over the signed attributes, message-digest attribute against the TSTInfo,
// content-type attribute, ESSCertID or ESSCertIDv2 against the signer
// certificate, chain to roots at genTime with the timeStamping key purpose,
// critical extended key usage on the signer, required policies, maximum
// accuracy, and finally the qualified-status hook when one is configured.
func (v *Verifier) Verify(ctx context.Context, digest, token []byte) (anchor.Attestation, error) {
	if err := ctx.Err(); err != nil {
		return anchor.Attestation{}, invalid("%v", err)
	}
	if v.roots == nil {
		return anchor.Attestation{}, invalid("no roots configured")
	}
	tok, err := ParseToken(token)
	if err != nil {
		return anchor.Attestation{}, invalid("%v", err)
	}
	if len(digest) != sha256.Size {
		return anchor.Attestation{}, invalid("digest is %d bytes, want %d", len(digest), sha256.Size)
	}
	if !tok.MessageImprint.HashAlgorithm.Equal(oidSHA256) {
		return anchor.Attestation{}, invalid("messageImprint algorithm %s, want SHA-256", tok.MessageImprint.HashAlgorithm)
	}
	if subtle.ConstantTimeCompare(tok.MessageImprint.HashedMessage, digest) != 1 {
		return anchor.Attestation{}, invalid("messageImprint does not match digest")
	}
	cert := tok.SignerCertificate
	if cert == nil {
		return anchor.Attestation{}, invalid("token does not include the signer certificate")
	}
	sd := tok.sd
	if err := verifySignature(cert.PublicKey, &sd.signer, sd.digestAlgorithms); err != nil {
		return anchor.Attestation{}, invalid("signature: %v", err)
	}
	if err := checkSignedAttributes(sd, cert); err != nil {
		return anchor.Attestation{}, invalid("%v", err)
	}
	if err := v.verifyChain(cert, sd.certs, tok.GenTime); err != nil {
		return anchor.Attestation{}, invalid("%v", err)
	}
	if err := checkTimeStampingEKU(cert); err != nil {
		return anchor.Attestation{}, invalid("%v", err)
	}
	if len(v.policies) > 0 && !containsOID(v.policies, tok.Policy) {
		return anchor.Attestation{}, invalid("policy %s is not an accepted policy", tok.Policy)
	}
	if v.maxAccuracy > 0 && tok.Accuracy > v.maxAccuracy {
		return anchor.Attestation{}, invalid("accuracy %s exceeds maximum %s", tok.Accuracy, v.maxAccuracy)
	}
	qualified := false
	if v.qualified != nil {
		qualified, err = v.qualified(cert, tok.GenTime)
		if err != nil {
			return anchor.Attestation{}, invalid("qualified status: %v", err)
		}
	}
	fp := sha256.Sum256(cert.Raw)
	details := map[string]string{
		"policy":        tok.Policy.String(),
		"serial":        tok.SerialNumber.String(),
		"signer_sha256": hex.EncodeToString(fp[:]),
	}
	if tok.TSA != "" {
		details["tsa"] = tok.TSA
	}
	return anchor.Attestation{
		Time:      tok.GenTime,
		Accuracy:  tok.Accuracy,
		Authority: cert.Subject.String(),
		Qualified: qualified,
		Details:   details,
	}, nil
}

// verifySignature checks the SignerInfo signature over the signed attributes
// with the signer's public key. The digest algorithm must be one the
// SignedData lists, the signature algorithm must agree with it, and the key
// type must match the algorithm.
func verifySignature(pub crypto.PublicKey, si *signerInfo, listed []algorithmIdentifier) error {
	h, ok := digestHash(si.digestAlgorithm.OID)
	if !ok || !si.digestAlgorithm.paramsAbsentOrNull() {
		return fmt.Errorf("unsupported digest algorithm %s", si.digestAlgorithm.OID)
	}
	found := false
	for _, a := range listed {
		if a.OID.Equal(si.digestAlgorithm.OID) {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("digest algorithm %s not listed in SignedData", si.digestAlgorithm.OID)
	}
	hasher := h.New()
	hasher.Write(si.signedAttrsDER)
	sum := hasher.Sum(nil)

	alg := si.signatureAlgorithm
	switch {
	case alg.OID.Equal(oidRSAEncryption), alg.OID.Equal(oidSHA256WithRSA),
		alg.OID.Equal(oidSHA384WithRSA), alg.OID.Equal(oidSHA512WithRSA):
		if !alg.paramsAbsentOrNull() {
			return fmt.Errorf("RSA signature algorithm has parameters")
		}
		if want := rsaHashFor(alg.OID); want != 0 && want != h {
			return fmt.Errorf("signature algorithm %s disagrees with digest algorithm %s", alg.OID, si.digestAlgorithm.OID)
		}
		key, err := rsaKey(pub)
		if err != nil {
			return err
		}
		if err := rsa.VerifyPKCS1v15(key, h, sum, si.signature); err != nil {
			return fmt.Errorf("RSA PKCS#1 v1.5: %w", err)
		}
	case alg.OID.Equal(oidRSASSAPSS):
		opts, pssHash, err := parsePSSParams(alg)
		if err != nil {
			return err
		}
		if pssHash != h {
			return fmt.Errorf("RSASSA-PSS hash disagrees with digest algorithm %s", si.digestAlgorithm.OID)
		}
		key, err := rsaKey(pub)
		if err != nil {
			return err
		}
		if err := rsa.VerifyPSS(key, h, sum, si.signature, opts); err != nil {
			return fmt.Errorf("RSASSA-PSS: %w", err)
		}
	case alg.OID.Equal(oidECDSAWithSHA256), alg.OID.Equal(oidECDSAWithSHA384), alg.OID.Equal(oidECDSAWithSHA512):
		if !alg.paramsAbsentOrNull() {
			return fmt.Errorf("ECDSA signature algorithm has parameters")
		}
		if want := ecdsaHashFor(alg.OID); want != h {
			return fmt.Errorf("signature algorithm %s disagrees with digest algorithm %s", alg.OID, si.digestAlgorithm.OID)
		}
		key, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("signature algorithm %s but signer key is %T", alg.OID, pub)
		}
		if !ecdsa.VerifyASN1(key, sum, si.signature) {
			return fmt.Errorf("ECDSA signature does not verify")
		}
	default:
		return fmt.Errorf("unsupported signature algorithm %s", alg.OID)
	}
	return nil
}

func rsaKey(pub crypto.PublicKey) (*rsa.PublicKey, error) {
	key, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("RSA signature algorithm but signer key is %T", pub)
	}
	if key.N.BitLen() < minRSABits {
		return nil, fmt.Errorf("RSA key is %d bits, want at least %d", key.N.BitLen(), minRSABits)
	}
	return key, nil
}

func rsaHashFor(oid asn1.ObjectIdentifier) crypto.Hash {
	switch {
	case oid.Equal(oidSHA256WithRSA):
		return crypto.SHA256
	case oid.Equal(oidSHA384WithRSA):
		return crypto.SHA384
	case oid.Equal(oidSHA512WithRSA):
		return crypto.SHA512
	}
	return 0 // rsaEncryption: the digest algorithm decides
}

func ecdsaHashFor(oid asn1.ObjectIdentifier) crypto.Hash {
	switch {
	case oid.Equal(oidECDSAWithSHA256):
		return crypto.SHA256
	case oid.Equal(oidECDSAWithSHA384):
		return crypto.SHA384
	default:
		return crypto.SHA512
	}
}

// parsePSSParams reads RSASSA-PSS-params (RFC 4055 section 3.1). The hash
// must be stated (the SHA-1 default is not accepted), the mask generation
// function must be MGF1 with the same hash, and the trailer field must be 1.
func parsePSSParams(alg algorithmIdentifier) (*rsa.PSSOptions, crypto.Hash, error) {
	if !alg.HasParams {
		return nil, 0, fmt.Errorf("RSASSA-PSS without parameters")
	}
	s := cryptobyte.String(alg.Params)
	var params cryptobyte.String
	if !s.ReadASN1(&params, cbasn1.SEQUENCE) || !s.Empty() {
		return nil, 0, fmt.Errorf("RSASSA-PSS parameters malformed")
	}
	var hashWrapper, mgfWrapper cryptobyte.String
	var hasHash, hasMGF bool
	if !params.ReadOptionalASN1(&hashWrapper, &hasHash, cbasn1.Tag(0).ContextSpecific().Constructed()) || !hasHash {
		return nil, 0, fmt.Errorf("RSASSA-PSS hash algorithm missing")
	}
	hashAlg, err := readAlgorithmIdentifier(&hashWrapper)
	if err != nil || !hashWrapper.Empty() || !hashAlg.paramsAbsentOrNull() {
		return nil, 0, fmt.Errorf("RSASSA-PSS hash algorithm malformed")
	}
	h, ok := digestHash(hashAlg.OID)
	if !ok {
		return nil, 0, fmt.Errorf("RSASSA-PSS hash %s unsupported", hashAlg.OID)
	}
	if !params.ReadOptionalASN1(&mgfWrapper, &hasMGF, cbasn1.Tag(1).ContextSpecific().Constructed()) || !hasMGF {
		return nil, 0, fmt.Errorf("RSASSA-PSS mask generation function missing")
	}
	mgf, err := readAlgorithmIdentifier(&mgfWrapper)
	if err != nil || !mgfWrapper.Empty() || !mgf.OID.Equal(oidMGF1) || !mgf.HasParams {
		return nil, 0, fmt.Errorf("RSASSA-PSS mask generation function malformed or not MGF1")
	}
	mgfParams := cryptobyte.String(mgf.Params)
	mgfHash, err := readAlgorithmIdentifier(&mgfParams)
	if err != nil || !mgfParams.Empty() || !mgfHash.OID.Equal(hashAlg.OID) {
		return nil, 0, fmt.Errorf("RSASSA-PSS MGF1 hash disagrees with hash algorithm")
	}
	salt := int64(20)
	if !params.ReadOptionalASN1Integer(&salt, cbasn1.Tag(2).ContextSpecific().Constructed(), int64(20)) {
		return nil, 0, fmt.Errorf("RSASSA-PSS salt length malformed")
	}
	trailer := int64(1)
	if !params.ReadOptionalASN1Integer(&trailer, cbasn1.Tag(3).ContextSpecific().Constructed(), int64(1)) {
		return nil, 0, fmt.Errorf("RSASSA-PSS trailer field malformed")
	}
	if !params.Empty() || trailer != 1 || salt < 0 || salt > 512 {
		return nil, 0, fmt.Errorf("RSASSA-PSS parameters out of range")
	}
	return &rsa.PSSOptions{SaltLength: int(salt), Hash: h}, h, nil
}

// checkSignedAttributes verifies the content-type, message-digest and
// signing-certificate attributes against the encapsulated TSTInfo and the
// signer certificate.
func checkSignedAttributes(sd *signedData, cert *x509.Certificate) error {
	si := &sd.signer
	ct, err := si.attr(oidContentType)
	if err != nil {
		return err
	}
	if ct == nil {
		return fmt.Errorf("content-type attribute missing")
	}
	var ctOID asn1.ObjectIdentifier
	cts := cryptobyte.String(ct)
	if !cts.ReadASN1ObjectIdentifier(&ctOID) || !cts.Empty() || !ctOID.Equal(oidCTTSTInfo) {
		return fmt.Errorf("content-type attribute is not id-ct-TSTInfo")
	}

	md, err := si.attr(oidMessageDigest)
	if err != nil {
		return err
	}
	if md == nil {
		return fmt.Errorf("message-digest attribute missing")
	}
	var mdValue cryptobyte.String
	mds := cryptobyte.String(md)
	if !mds.ReadASN1(&mdValue, cbasn1.OCTET_STRING) || !mds.Empty() {
		return fmt.Errorf("message-digest attribute malformed")
	}
	h, _ := digestHash(si.digestAlgorithm.OID) // validated by verifySignature
	hasher := h.New()
	hasher.Write(sd.eContent)
	if subtle.ConstantTimeCompare(hasher.Sum(nil), mdValue) != 1 {
		return fmt.Errorf("message-digest attribute does not match TSTInfo")
	}

	v1, err := si.attr(oidSigningCert)
	if err != nil {
		return err
	}
	v2, err := si.attr(oidSigningCertV2)
	if err != nil {
		return err
	}
	if v1 == nil && v2 == nil {
		return fmt.Errorf("signing-certificate attribute missing")
	}
	if v1 != nil {
		if err := checkESSCertID(v1, false, cert); err != nil {
			return fmt.Errorf("signing-certificate: %w", err)
		}
	}
	if v2 != nil {
		if err := checkESSCertID(v2, true, cert); err != nil {
			return fmt.Errorf("signing-certificate-v2: %w", err)
		}
	}
	return nil
}

// checkESSCertID checks that the first ESSCertID (RFC 2634) or ESSCertIDv2
// (RFC 5035) in a SigningCertificate attribute value identifies cert: the
// certificate hash under the stated algorithm (SHA-1 for v1, SHA-256 by
// default for v2) and, when present, the issuer and serial number.
func checkESSCertID(value []byte, v2 bool, cert *x509.Certificate) error {
	s := cryptobyte.String(value)
	var sc, certs, id cryptobyte.String
	if !s.ReadASN1(&sc, cbasn1.SEQUENCE) || !s.Empty() || !sc.ReadASN1(&certs, cbasn1.SEQUENCE) {
		return fmt.Errorf("malformed")
	}
	if !certs.ReadASN1(&id, cbasn1.SEQUENCE) {
		return fmt.Errorf("no ESSCertID")
	}
	h := crypto.SHA1
	if v2 {
		h = crypto.SHA256
		if id.PeekASN1Tag(cbasn1.SEQUENCE) {
			alg, err := readAlgorithmIdentifier(&id)
			if err != nil || !alg.paramsAbsentOrNull() {
				return fmt.Errorf("malformed hashAlgorithm")
			}
			var ok bool
			if h, ok = certHash(alg.OID); !ok {
				return fmt.Errorf("unsupported hash %s", alg.OID)
			}
		}
	}
	var want cryptobyte.String
	if !id.ReadASN1(&want, cbasn1.OCTET_STRING) {
		return fmt.Errorf("malformed certHash")
	}
	hasher := h.New()
	hasher.Write(cert.Raw)
	if subtle.ConstantTimeCompare(hasher.Sum(nil), want) != 1 {
		return fmt.Errorf("certHash does not match the signer certificate")
	}
	var is cryptobyte.String
	var present bool
	if !id.ReadOptionalASN1(&is, &present, cbasn1.SEQUENCE) || !id.Empty() {
		return fmt.Errorf("malformed issuerSerial")
	}
	if !present {
		return nil
	}
	var names cryptobyte.String
	if !is.ReadASN1(&names, cbasn1.SEQUENCE) {
		return fmt.Errorf("malformed issuerSerial")
	}
	serial := new(big.Int)
	if !is.ReadASN1Integer(serial) || !is.Empty() {
		return fmt.Errorf("malformed issuerSerial")
	}
	if serial.Cmp(cert.SerialNumber) != 0 {
		return fmt.Errorf("issuerSerial serial does not match the signer certificate")
	}
	for !names.Empty() {
		var name cryptobyte.String
		var tag cbasn1.Tag
		if !names.ReadAnyASN1(&name, &tag) {
			return fmt.Errorf("malformed issuerSerial issuer")
		}
		if tag == cbasn1.Tag(4).ContextSpecific().Constructed() && !bytes.Equal(name, cert.RawIssuer) {
			return fmt.Errorf("issuerSerial issuer does not match the signer certificate")
		}
	}
	return nil
}

// verifyChain builds a chain from the signer to the pinned roots valid at
// genTime for the timeStamping key purpose, using configured intermediates
// and every other certificate the token includes.
func (v *Verifier) verifyChain(signer *x509.Certificate, included []*x509.Certificate, at time.Time) error {
	inter := x509.NewCertPool()
	if v.intermediates != nil {
		inter = v.intermediates.Clone()
	}
	for _, c := range included {
		if !c.Equal(signer) {
			inter.AddCert(c)
		}
	}
	_, err := signer.Verify(x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: inter,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	})
	if err != nil {
		return fmt.Errorf("certificate chain: %w", err)
	}
	return nil
}

// checkTimeStampingEKU requires the extended key usage extension to be
// present, marked critical and to list id-kp-timeStamping (RFC 3161 section
// 2.3). Chain verification accepts a non-critical extension and anyExtendedKeyUsage; this does not.
func checkTimeStampingEKU(cert *x509.Certificate) error {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidExtKeyUsage) {
			continue
		}
		if !ext.Critical {
			return fmt.Errorf("signer certificate: extended key usage is not critical")
		}
		s := cryptobyte.String(ext.Value)
		var seq cryptobyte.String
		if !s.ReadASN1(&seq, cbasn1.SEQUENCE) || !s.Empty() {
			return fmt.Errorf("signer certificate: extended key usage malformed")
		}
		for !seq.Empty() {
			var oid asn1.ObjectIdentifier
			if !seq.ReadASN1ObjectIdentifier(&oid) {
				return fmt.Errorf("signer certificate: extended key usage malformed")
			}
			if oid.Equal(oidKPTimeStamping) {
				return nil
			}
		}
		return fmt.Errorf("signer certificate: extended key usage lacks id-kp-timeStamping")
	}
	return fmt.Errorf("signer certificate: extended key usage extension missing")
}

func containsOID(set []asn1.ObjectIdentifier, oid asn1.ObjectIdentifier) bool {
	for _, o := range set {
		if o.Equal(oid) {
			return true
		}
	}
	return false
}
