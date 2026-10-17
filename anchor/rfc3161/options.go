package rfc3161

import (
	"crypto/x509"
	"encoding/asn1"
	"net/http"
	"time"
)

// Option configures a [Client] or a [Verifier]. Each option applies to one of
// the two and is ignored by the other.
type Option func(*options)

type options struct {
	// Client
	httpClient *http.Client
	policy     asn1.ObjectIdentifier
	timeout    time.Duration
	certReq    bool
	userAgent  string
	// Verifier
	intermediates *x509.CertPool
	policies      []asn1.ObjectIdentifier
	maxAccuracy   time.Duration
	qualified     func(cert *x509.Certificate, at time.Time) (bool, error)
}

func applyOptions(opts []Option) options {
	o := options{timeout: DefaultTimeout, certReq: true}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// WithHTTPClient sets the HTTP client a [Client] uses (default: a dedicated
// http.Client with the default transport).
func WithHTTPClient(hc *http.Client) Option { return func(o *options) { o.httpClient = hc } }

// WithPolicy asks the TSA to issue under a specific policy (reqPolicy). The
// [Client] rejects a token issued under any other policy (RFC 3161 section
// 2.4.2). Set [WithRequiredPolicies] on the Verifier as well so that stored
// tokens are held to the same policy at audit time.
func WithPolicy(oid asn1.ObjectIdentifier) Option { return func(o *options) { o.policy = oid } }

// WithTimeout bounds one request of a [Client] (default 30 s).
func WithTimeout(d time.Duration) Option { return func(o *options) { o.timeout = d } }

// WithCertReq sets the certReq flag of the request (default true). With
// false the TSA omits its certificate from the token, and the shipped
// [Verifier] then rejects the token: it requires the signer certificate to
// be inside the token. Certificates supplied through [WithIntermediates] do
// not substitute for it; they only help to build the chain from that signer
// to the roots. Leave this on unless the tokens are verified elsewhere.
func WithCertReq(v bool) Option { return func(o *options) { o.certReq = v } }

// WithUserAgent sets the User-Agent header a [Client] sends.
func WithUserAgent(ua string) Option { return func(o *options) { o.userAgent = ua } }

// WithIntermediates supplies intermediate certificates a [Verifier] may use
// in addition to those included in a token.
func WithIntermediates(pool *x509.CertPool) Option {
	return func(o *options) { o.intermediates = pool }
}

// WithRequiredPolicies makes a [Verifier] reject tokens whose TSA policy is
// not one of the given identifiers. SK ID Solutions issues under
// 0.4.0.2023.1.1 (ETSI EN 319 422 best-practices policy).
func WithRequiredPolicies(oids ...asn1.ObjectIdentifier) Option {
	return func(o *options) { o.policies = append(o.policies, oids...) }
}

// WithMaxAccuracy makes a [Verifier] reject tokens whose stated accuracy is
// worse than d. Zero (the default) accepts any accuracy, including none.
func WithMaxAccuracy(d time.Duration) Option { return func(o *options) { o.maxAccuracy = d } }

// WithQualifiedChecker installs the hook that decides whether the signer
// certificate belonged to a qualified trust service at the token's genTime
// (eIDAS Art. 41(2)); anchor/rfc3161/eutl supplies one backed by the EU
// trusted lists. Without a hook Attestation.Qualified is always false. An
// error from the hook fails verification.
func WithQualifiedChecker(fn func(cert *x509.Certificate, at time.Time) (bool, error)) Option {
	return func(o *options) { o.qualified = fn }
}
