package rfc3161_test

// A minimal time-stamp authority for tests. It parses TimeStampReq with
// encoding/asn1 and builds TSTInfo, CMS SignedData and TimeStampResp with
// cryptobyte, independently of the package under test, with knobs to produce
// each kind of bad answer the client and verifier must reject.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidSHA1            = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA512          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidSignedData      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidCTTSTInfo       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidContentType     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningCert     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	oidSigningCertV2   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	oidRSAEncryption   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidRSASSAPSS       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidMGF1            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidExtKeyUsage     = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidKPTimeStamping  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidSKPolicy        = asn1.ObjectIdentifier{0, 4, 0, 2023, 1, 1}
	oidOtherPolicy     = asn1.ObjectIdentifier{1, 2, 3, 4, 5}
)

type scheme int

const (
	schemeECDSA     scheme = iota
	schemeRSAPKCS1         // signatureAlgorithm rsaEncryption, as OpenSSL emits
	schemeRSASHA256        // signatureAlgorithm sha256WithRSAEncryption
	schemeRSAPSS
)

var (
	rsaOnce sync.Once
	rsaKey  *rsa.PrivateKey
)

func testRSAKey(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	rsaOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		rsaKey = k
	})
	return rsaKey
}

type ca struct {
	key  crypto.Signer
	cert *x509.Certificate
}

func newRoot(t testing.TB, name string) *ca {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name, Organization: []string{"tamperlog tests"}, Country: []string{"EE"}},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &ca{key: key, cert: cert}
}

// ekuKind selects how the TSA certificate carries extended key usage.
type ekuKind int

const (
	ekuCritical ekuKind = iota
	ekuNonCritical
	ekuMissing
)

func (c *ca) issueTSA(t testing.TB, key crypto.Signer, eku ekuKind, name string) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x1234567890),
		Subject:      pkix.Name{CommonName: name, Organization: []string{"tamperlog tests"}, Country: []string{"EE"}},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		SubjectKeyId: []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}
	if eku != ekuMissing {
		val, err := asn1.Marshal([]asn1.ObjectIdentifier{oidKPTimeStamping})
		if err != nil {
			t.Fatal(err)
		}
		tmpl.ExtraExtensions = []pkix.Extension{{Id: oidExtKeyUsage, Critical: eku == ekuCritical, Value: val}}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, key.Public(), c.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// tsa is the test authority. Zero-valued knobs give a correct answer.
type tsa struct {
	t      testing.TB
	root   *ca
	key    crypto.Signer
	cert   *x509.Certificate
	scheme scheme

	policy   asn1.ObjectIdentifier
	accuracy time.Duration
	genTime  time.Time
	serial   *big.Int

	// knobs
	genTimeRaw      string                      // literal GeneralizedTime instead of genTime
	accuracyRaw     func(*cryptobyte.Builder)   // build the Accuracy body by hand instead of from accuracy
	sdVersion       int64                       // SignedData version (0 = 3)
	includeRoot     bool                        // include the root in the certificates set
	extraCerts      int                         // append the root this many more times
	omitCerts       bool                        // leave the certificates set out
	includeTSAName  bool                        // set the tsa field to the signer's subject
	criticalExt     bool                        // add an unknown critical TSTInfo extension
	nonceOverride   *big.Int                    // echo this nonce instead of the request's
	dropNonce       bool                        // echo no nonce
	imprintOverride []byte                      // bind this imprint instead of the request's
	tamper          func(tstInfo []byte) []byte // alter the TSTInfo after signing
	essV1           bool                        // use signing-certificate (SHA-1) instead of v2
	essV2Hash       asn1.ObjectIdentifier       // explicit hash algorithm in ESSCertIDv2
	essMismatch     bool                        // hash the root instead of the signer
	essRootFirst    bool                        // put an ESSCertID for the root before the signer's
	essRootSecond   bool                        // put an ESSCertID for the root after the signer's
	essNoDirName    bool                        // issuerSerial names a dNSName only, no directoryName
	essPolicies     bool                        // add a policies field to the attribute
	omitESS         bool                        // leave the signing-certificate attribute out
	unsortedAttrs   bool                        // emit the signed attributes in reverse DER order
	extraAttrs      int                         // add this many filler attributes
	sigAlgOverride  asn1.ObjectIdentifier       // declare this signature algorithm
	pssSaltDeclared *int                        // RSASSA-PSS saltLength parameter (nil = 32)
	pssSaltActual   int                         // salt length used when signing with PSS (0 = 32)
	duplicateSigner bool                        // two SignerInfos
	status          int                         // PKIStatus to answer with (0 = granted)
	failInfoBits    []int                       // failInfo bits to set
	statusStrings   []string                    // statusString texts
	httpStatus      int                         // HTTP status code (0 = 200)
	contentType     *string                     // response Content-Type (nil = reply type)
	rawBody         []byte                      // send this body instead of a response
	lastRequest     *tsReq                      // the most recent parsed request
	lastHeaders     http.Header
}

func newTSA(t testing.TB, s scheme) *tsa {
	t.Helper()
	root := newRoot(t, "tamperlog TEST ROOT")
	var key crypto.Signer
	switch s {
	case schemeECDSA:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key = k
	default:
		key = testRSAKey(t)
	}
	return &tsa{
		t:        t,
		root:     root,
		key:      key,
		cert:     root.issueTSA(t, key, ekuCritical, "tamperlog TEST TSA"),
		scheme:   s,
		policy:   oidSKPolicy,
		accuracy: time.Second,
		genTime:  time.Now().UTC().Truncate(time.Second),
		serial:   big.NewInt(0x0102030405),
	}
}

func (s *tsa) roots() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(s.root.cert)
	return p
}

func (s *tsa) serve() *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(s.handle))
	s.t.Cleanup(srv.Close)
	return srv
}

type tsReq struct {
	Version        int
	MessageImprint struct {
		HashAlgorithm pkix.AlgorithmIdentifier
		HashedMessage []byte
	}
	ReqPolicy  asn1.ObjectIdentifier `asn1:"optional"`
	Nonce      *big.Int              `asn1:"optional"`
	CertReq    bool                  `asn1:"optional"`
	Extensions []pkix.Extension      `asn1:"optional,tag:0"`
}

func (s *tsa) handle(w http.ResponseWriter, r *http.Request) {
	s.lastHeaders = r.Header.Clone()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req tsReq
	rest, err := asn1.Unmarshal(body, &req)
	if err != nil || len(rest) != 0 {
		http.Error(w, "bad TimeStampReq", http.StatusBadRequest)
		return
	}
	s.lastRequest = &req
	if s.rawBody != nil {
		w.Header().Set("Content-Type", "application/timestamp-reply")
		_, _ = w.Write(s.rawBody)
		return
	}
	resp := s.respond(req.MessageImprint.HashedMessage, req.Nonce)
	switch {
	case s.contentType == nil:
		w.Header().Set("Content-Type", "application/timestamp-reply")
	case *s.contentType == "":
		w.Header()["Content-Type"] = nil // suppress net/http sniffing: send no header at all
	default:
		w.Header().Set("Content-Type", *s.contentType)
	}
	if s.httpStatus != 0 {
		w.WriteHeader(s.httpStatus)
	}
	_, _ = w.Write(resp)
}

// respond builds a TimeStampResp for the imprint and nonce.
func (s *tsa) respond(imprint []byte, nonce *big.Int) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(resp *cryptobyte.Builder) {
		resp.AddASN1(cbasn1.SEQUENCE, func(st *cryptobyte.Builder) {
			st.AddASN1Int64(int64(s.status))
			if len(s.statusStrings) > 0 {
				st.AddASN1(cbasn1.SEQUENCE, func(texts *cryptobyte.Builder) {
					for _, t := range s.statusStrings {
						texts.AddASN1(cbasn1.UTF8String, func(c *cryptobyte.Builder) { c.AddBytes([]byte(t)) })
					}
				})
			}
			if len(s.failInfoBits) > 0 {
				maxBit := 0
				for _, bit := range s.failInfoBits {
					if bit > maxBit {
						maxBit = bit
					}
				}
				bits := make([]byte, maxBit/8+1)
				for _, bit := range s.failInfoBits {
					bits[bit/8] |= 0x80 >> (bit % 8)
				}
				st.AddASN1(cbasn1.BIT_STRING, func(bs *cryptobyte.Builder) {
					bs.AddUint8(uint8(len(bits)*8 - maxBit - 1))
					bs.AddBytes(bits)
				})
			}
		})
		if s.status == 0 || s.status == 1 {
			resp.AddBytes(s.token(imprint, nonce))
		}
	})
	out, err := b.Bytes()
	if err != nil {
		s.t.Fatal(err)
	}
	return out
}

// token builds a TimeStampToken (CMS ContentInfo) over imprint.
func (s *tsa) token(imprint []byte, nonce *big.Int) []byte {
	if s.imprintOverride != nil {
		imprint = s.imprintOverride
	}
	if s.nonceOverride != nil {
		nonce = s.nonceOverride
	}
	if s.dropNonce {
		nonce = nil
	}
	tst := s.tstInfo(imprint, nonce)
	si := s.signerInfo(tst)
	if s.tamper != nil {
		tst = s.tamper(tst)
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(ci *cryptobyte.Builder) {
		ci.AddASN1ObjectIdentifier(oidSignedData)
		ci.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(c *cryptobyte.Builder) {
			c.AddASN1(cbasn1.SEQUENCE, func(sd *cryptobyte.Builder) {
				sdVersion := s.sdVersion
				if sdVersion == 0 {
					sdVersion = 3
				}
				sd.AddASN1Int64(sdVersion)
				sd.AddASN1(cbasn1.SET, func(set *cryptobyte.Builder) { addAlg(set, oidSHA256, true) })
				sd.AddASN1(cbasn1.SEQUENCE, func(eci *cryptobyte.Builder) {
					eci.AddASN1ObjectIdentifier(oidCTTSTInfo)
					eci.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(w *cryptobyte.Builder) {
						w.AddASN1OctetString(tst)
					})
				})
				if !s.omitCerts {
					sd.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(certs *cryptobyte.Builder) {
						certs.AddBytes(s.cert.Raw)
						if s.includeRoot {
							certs.AddBytes(s.root.cert.Raw)
						}
						for i := 0; i < s.extraCerts; i++ {
							certs.AddBytes(s.root.cert.Raw)
						}
					})
				}
				sd.AddASN1(cbasn1.SET, func(set *cryptobyte.Builder) {
					set.AddBytes(si)
					if s.duplicateSigner {
						set.AddBytes(si)
					}
				})
			})
		})
	})
	out, err := b.Bytes()
	if err != nil {
		s.t.Fatal(err)
	}
	return out
}

func addAlg(b *cryptobyte.Builder, oid asn1.ObjectIdentifier, null bool) {
	b.AddASN1(cbasn1.SEQUENCE, func(alg *cryptobyte.Builder) {
		alg.AddASN1ObjectIdentifier(oid)
		if null {
			alg.AddASN1NULL()
		}
	})
}

func (s *tsa) tstInfo(imprint []byte, nonce *big.Int) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(ti *cryptobyte.Builder) {
		ti.AddASN1Int64(1)
		ti.AddASN1ObjectIdentifier(s.policy)
		ti.AddASN1(cbasn1.SEQUENCE, func(mi *cryptobyte.Builder) {
			addAlg(mi, oidSHA256, true)
			mi.AddASN1OctetString(imprint)
		})
		ti.AddASN1BigInt(s.serial)
		if s.genTimeRaw != "" {
			ti.AddASN1(cbasn1.GeneralizedTime, func(g *cryptobyte.Builder) { g.AddBytes([]byte(s.genTimeRaw)) })
		} else {
			ti.AddASN1GeneralizedTime(s.genTime)
		}
		if s.accuracyRaw != nil {
			ti.AddASN1(cbasn1.SEQUENCE, s.accuracyRaw)
		} else if s.accuracy > 0 {
			ti.AddASN1(cbasn1.SEQUENCE, func(acc *cryptobyte.Builder) {
				secs := int64(s.accuracy / time.Second)
				rem := s.accuracy % time.Second
				millis := int64(rem / time.Millisecond)
				micros := int64((rem % time.Millisecond) / time.Microsecond)
				if secs > 0 {
					acc.AddASN1Int64(secs)
				}
				if millis > 0 {
					acc.AddASN1Int64WithTag(millis, cbasn1.Tag(0).ContextSpecific())
				}
				if micros > 0 {
					acc.AddASN1Int64WithTag(micros, cbasn1.Tag(1).ContextSpecific())
				}
			})
		}
		if nonce != nil {
			ti.AddASN1BigInt(nonce)
		}
		if s.includeTSAName {
			ti.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(tsaName *cryptobyte.Builder) {
				tsaName.AddASN1(cbasn1.Tag(4).ContextSpecific().Constructed(), func(dn *cryptobyte.Builder) {
					dn.AddBytes(s.cert.RawSubject)
				})
			})
		}
		if s.criticalExt {
			ti.AddASN1(cbasn1.Tag(1).ContextSpecific().Constructed(), func(exts *cryptobyte.Builder) {
				exts.AddASN1(cbasn1.SEQUENCE, func(ext *cryptobyte.Builder) {
					ext.AddASN1ObjectIdentifier(asn1.ObjectIdentifier{1, 2, 3, 4, 99})
					ext.AddASN1Boolean(true)
					ext.AddASN1OctetString([]byte{0x05, 0x00})
				})
			})
		}
	})
	out, err := b.Bytes()
	if err != nil {
		s.t.Fatal(err)
	}
	return out
}

func (s *tsa) signerInfo(tst []byte) []byte {
	digest := sha256.Sum256(tst)
	attrs := [][]byte{
		attribute(oidContentType, func(v *cryptobyte.Builder) { v.AddASN1ObjectIdentifier(oidCTTSTInfo) }),
		attribute(oidMessageDigest, func(v *cryptobyte.Builder) { v.AddASN1OctetString(digest[:]) }),
	}
	if !s.omitESS {
		attrs = append(attrs, s.essAttribute())
	}
	for i := 0; i < s.extraAttrs; i++ {
		oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, i + 1}
		attrs = append(attrs, attribute(oid, func(v *cryptobyte.Builder) { v.AddASN1NULL() }))
	}
	sort.Slice(attrs, func(i, j int) bool {
		less := bytes.Compare(attrs[i], attrs[j]) < 0
		return less != s.unsortedAttrs
	})
	var set cryptobyte.Builder
	set.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
		for _, a := range attrs {
			b.AddBytes(a)
		}
	})
	setDER, err := set.Bytes()
	if err != nil {
		s.t.Fatal(err)
	}
	signed := sha256.Sum256(setDER)
	var sig []byte
	switch s.scheme {
	case schemeECDSA:
		sig, err = ecdsa.SignASN1(rand.Reader, s.key.(*ecdsa.PrivateKey), signed[:])
	case schemeRSAPKCS1, schemeRSASHA256:
		sig, err = rsa.SignPKCS1v15(rand.Reader, s.key.(*rsa.PrivateKey), crypto.SHA256, signed[:])
	case schemeRSAPSS:
		salt := s.pssSaltActual
		if salt == 0 {
			salt = 32
		}
		sig, err = rsa.SignPSS(rand.Reader, s.key.(*rsa.PrivateKey), crypto.SHA256, signed[:], &rsa.PSSOptions{SaltLength: salt})
	}
	if err != nil {
		s.t.Fatal(err)
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(si *cryptobyte.Builder) {
		si.AddASN1Int64(1)
		si.AddASN1(cbasn1.SEQUENCE, func(ias *cryptobyte.Builder) {
			ias.AddBytes(s.cert.RawIssuer)
			ias.AddASN1BigInt(s.cert.SerialNumber)
		})
		addAlg(si, oidSHA256, true)
		// signedAttrs: the SET OF content under IMPLICIT [0].
		si.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(a *cryptobyte.Builder) {
			var inner cryptobyte.String = setDER
			var body cryptobyte.String
			if !inner.ReadASN1(&body, cbasn1.SET) {
				s.t.Fatal("set")
			}
			a.AddBytes(body)
		})
		s.addSignatureAlgorithm(si)
		si.AddASN1OctetString(sig)
	})
	out, err := b.Bytes()
	if err != nil {
		s.t.Fatal(err)
	}
	return out
}

func (s *tsa) addSignatureAlgorithm(si *cryptobyte.Builder) {
	if s.sigAlgOverride != nil {
		addAlg(si, s.sigAlgOverride, true)
		return
	}
	switch s.scheme {
	case schemeECDSA:
		addAlg(si, oidECDSAWithSHA256, false)
	case schemeRSAPKCS1:
		addAlg(si, oidRSAEncryption, true)
	case schemeRSASHA256:
		addAlg(si, oidSHA256WithRSA, true)
	case schemeRSAPSS:
		si.AddASN1(cbasn1.SEQUENCE, func(alg *cryptobyte.Builder) {
			alg.AddASN1ObjectIdentifier(oidRSASSAPSS)
			alg.AddASN1(cbasn1.SEQUENCE, func(p *cryptobyte.Builder) {
				p.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(h *cryptobyte.Builder) { addAlg(h, oidSHA256, true) })
				p.AddASN1(cbasn1.Tag(1).ContextSpecific().Constructed(), func(m *cryptobyte.Builder) {
					m.AddASN1(cbasn1.SEQUENCE, func(mgf *cryptobyte.Builder) {
						mgf.AddASN1ObjectIdentifier(oidMGF1)
						addAlg(mgf, oidSHA256, true)
					})
				})
				salt := int64(32)
				if s.pssSaltDeclared != nil {
					salt = int64(*s.pssSaltDeclared)
				}
				p.AddASN1(cbasn1.Tag(2).ContextSpecific().Constructed(), func(sl *cryptobyte.Builder) { sl.AddASN1Int64(salt) })
			})
		})
	}
}

func attribute(oid asn1.ObjectIdentifier, value func(*cryptobyte.Builder)) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(a *cryptobyte.Builder) {
		a.AddASN1ObjectIdentifier(oid)
		a.AddASN1(cbasn1.SET, value)
	})
	return b.BytesOrPanic()
}

// essAttribute builds signing-certificate (v1) or signing-certificate-v2
// with an issuerSerial, over the signer or, with essMismatch, the root. The
// essRootFirst and essRootSecond knobs add an ESSCertID for the root before
// or after the signer's, essNoDirName drops the directoryName from the
// issuerSerial, and essPolicies appends a policies field.
func (s *tsa) essAttribute() []byte {
	target := s.cert
	if s.essMismatch {
		target = s.root.cert
	}
	issuerSerial := func(b *cryptobyte.Builder, c *x509.Certificate) {
		b.AddASN1(cbasn1.SEQUENCE, func(is *cryptobyte.Builder) {
			is.AddASN1(cbasn1.SEQUENCE, func(names *cryptobyte.Builder) {
				if s.essNoDirName {
					names.AddASN1(cbasn1.Tag(2).ContextSpecific(), func(dns *cryptobyte.Builder) {
						dns.AddBytes([]byte("tsa.example"))
					})
					return
				}
				names.AddASN1(cbasn1.Tag(4).ContextSpecific().Constructed(), func(dn *cryptobyte.Builder) {
					dn.AddBytes(c.RawIssuer)
				})
			})
			is.AddASN1BigInt(c.SerialNumber)
		})
	}
	h := crypto.SHA256
	if s.essV1 {
		h = crypto.SHA1
	} else if s.essV2Hash != nil {
		switch {
		case s.essV2Hash.Equal(oidSHA512):
			h = crypto.SHA512
		case s.essV2Hash.Equal(oidSHA1):
			h = crypto.SHA1
		}
	}
	essCertID := func(certs *cryptobyte.Builder, c *x509.Certificate) {
		hasher := h.New()
		hasher.Write(c.Raw)
		sum := hasher.Sum(nil)
		certs.AddASN1(cbasn1.SEQUENCE, func(id *cryptobyte.Builder) {
			if !s.essV1 && s.essV2Hash != nil {
				addAlg(id, s.essV2Hash, false)
			}
			id.AddASN1OctetString(sum)
			issuerSerial(id, c)
		})
	}
	oid := oidSigningCertV2
	if s.essV1 {
		oid = oidSigningCert
	}
	return attribute(oid, func(v *cryptobyte.Builder) {
		v.AddASN1(cbasn1.SEQUENCE, func(sc *cryptobyte.Builder) {
			sc.AddASN1(cbasn1.SEQUENCE, func(certs *cryptobyte.Builder) {
				if s.essRootFirst {
					essCertID(certs, s.root.cert)
				}
				essCertID(certs, target)
				if s.essRootSecond {
					essCertID(certs, s.root.cert)
				}
			})
			if s.essPolicies {
				sc.AddASN1(cbasn1.SEQUENCE, func(pols *cryptobyte.Builder) {
					pols.AddASN1(cbasn1.SEQUENCE, func(pi *cryptobyte.Builder) {
						pi.AddASN1ObjectIdentifier(oidSKPolicy)
					})
					pols.AddASN1(cbasn1.SEQUENCE, func(pi *cryptobyte.Builder) {
						pi.AddASN1ObjectIdentifier(oidOtherPolicy)
						pi.AddASN1(cbasn1.SEQUENCE, func(quals *cryptobyte.Builder) {
							quals.AddASN1(cbasn1.SEQUENCE, func(q *cryptobyte.Builder) {
								q.AddASN1ObjectIdentifier(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1})
								q.AddASN1(cbasn1.IA5String, func(u *cryptobyte.Builder) { u.AddBytes([]byte("https://tsa.example/cps")) })
							})
						})
					})
				})
			}
		})
	})
}

func bigInt(v int64) *big.Int { return big.NewInt(v) }
