package rfc3161

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"
)

// MIME types of RFC 3161 section 3.4.
const (
	ContentTypeQuery = "application/timestamp-query"
	ContentTypeReply = "application/timestamp-reply"
)

// MaxResponseSize bounds the TimeStampResp body a Client reads.
const MaxResponseSize = 1 << 20

// DefaultTimeout bounds one request when [WithTimeout] is not given.
const DefaultTimeout = 30 * time.Second

// Client obtains tokens from one TSA over HTTP.
type Client struct {
	url       string
	http      *http.Client
	policy    asn1.ObjectIdentifier
	timeout   time.Duration
	certReq   bool
	userAgent string
}

// New returns a Client for the TSA at url, such as http://tsa.demo.sk.ee/tsa.
// By default it uses a dedicated http.Client with the default transport, a
// 30 s timeout per request, no requested policy and certReq set so the
// response carries the signer's certificate chain. Options meant for
// [Verifier] are ignored.
func New(url string, opts ...Option) *Client {
	o := applyOptions(opts)
	c := &Client{
		url:       url,
		http:      o.httpClient,
		policy:    o.policy,
		timeout:   o.timeout,
		certReq:   o.certReq,
		userAgent: o.userAgent,
	}
	if c.http == nil {
		c.http = &http.Client{}
	}
	if c.timeout <= 0 {
		c.timeout = DefaultTimeout
	}
	return c
}

// Anchor requests a time-stamp over digest, the 32-byte SHA-256 of a seal,
// and returns the DER TimeStampToken (the CMS ContentInfo, not the whole
// response). It checks the HTTP status and content type, that the TSA
// granted the request, and that the token's message imprint and nonce match
// the request; a refused request is reported as a *[StatusError]. The token
// is parsed but not verified: run [Verifier.Verify] or use [Provider].
func (c *Client) Anchor(ctx context.Context, digest []byte) ([]byte, error) {
	reqDER, nonce, err := buildRequest(digest, c.policy, c.certReq)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(reqDER))
	if err != nil {
		return nil, fmt.Errorf("rfc3161: %w", err)
	}
	req.Header.Set("Content-Type", ContentTypeQuery)
	req.Header.Set("Accept", ContentTypeReply)
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rfc3161: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rfc3161: TSA answered HTTP %s", resp.Status)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		mt, _, err := mime.ParseMediaType(ct)
		if err != nil || mt != ContentTypeReply {
			return nil, fmt.Errorf("rfc3161: TSA answered with content type %q, want %s", ct, ContentTypeReply)
		}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("rfc3161: read response: %w", err)
	}
	if len(body) > MaxResponseSize {
		return nil, fmt.Errorf("rfc3161: response exceeds %d bytes", MaxResponseSize)
	}
	token, err := parseResponse(body)
	if err != nil {
		var se *StatusError
		if errors.As(err, &se) {
			return nil, err
		}
		return nil, fmt.Errorf("rfc3161: response: %w", err)
	}
	tok, err := ParseToken(token)
	if err != nil {
		return nil, fmt.Errorf("rfc3161: response token: %w", err)
	}
	if !tok.MessageImprint.HashAlgorithm.Equal(oidSHA256) ||
		subtle.ConstantTimeCompare(tok.MessageImprint.HashedMessage, digest) != 1 {
		return nil, errors.New("rfc3161: response token covers a different message imprint")
	}
	if tok.Nonce == nil || tok.Nonce.Cmp(nonce) != 0 {
		return nil, errors.New("rfc3161: response token does not echo the request nonce")
	}
	return token, nil
}
