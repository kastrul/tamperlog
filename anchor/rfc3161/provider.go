package rfc3161

import (
	"context"
	"fmt"

	"github.com/kastrul/tamperlog/anchor"
)

// ProviderID is the identifier stored with every proof this provider makes.
const ProviderID = "rfc3161"

// Provider is an [anchor.Provider] backed by a [Client] and a [Verifier].
type Provider struct {
	client   *Client
	verifier *Verifier
}

// NewProvider combines a client and a verifier. Anchor verifies every fresh
// token with the verifier before returning it, so a TSA that answers with a
// token that does not verify against the pinned roots fails at anchoring
// time, not at audit time.
func NewProvider(client *Client, verifier *Verifier) *Provider {
	return &Provider{client: client, verifier: verifier}
}

// ID returns "rfc3161".
func (p *Provider) ID() string { return ProviderID }

// Anchor obtains a token for digest and verifies it before returning it.
func (p *Provider) Anchor(ctx context.Context, digest []byte) ([]byte, error) {
	token, err := p.client.Anchor(ctx, digest)
	if err != nil {
		return nil, err
	}
	if _, err := p.verifier.Verify(ctx, digest, token); err != nil {
		return nil, fmt.Errorf("rfc3161: fresh token rejected: %w", err)
	}
	return token, nil
}

// Verify checks proof against digest with the verifier.
func (p *Provider) Verify(ctx context.Context, digest, proof []byte) (anchor.Attestation, error) {
	return p.verifier.Verify(ctx, digest, proof)
}

var _ anchor.Provider = (*Provider)(nil)
