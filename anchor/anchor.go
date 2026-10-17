// Package anchor carries a seal's hash to a party outside the operator's
// control and verifies the evidence that party returns.
//
// A [Provider] turns a 32-byte seal hash into proof bytes (for RFC 3161, a
// DER TimeStampToken) and later verifies such bytes against the hash,
// returning an [Attestation] that says what the proof establishes: that the
// hash existed no later than a time, according to a named authority.
// anchor/rfc3161 is the shipped provider; OpenTimestamps or a KSI gateway
// would implement the same interface.
//
// A [Runner] anchors every seal that lacks a proof from its provider, retrying
// with backoff for a grace period and recording a failure in the system stream
// when the grace period passes (ADR 0009). Seals are written before anchoring
// and never wait for it.
package anchor

import (
	"context"
	"errors"
	"time"
)

// Provider is one external anchoring service.
type Provider interface {
	// ID is the stable identifier stored with every proof, such as "rfc3161".
	// It must match ^[a-z0-9][a-z0-9._-]*$ and be at most 63 bytes.
	ID() string
	// Anchor submits digest, the SHA-256 of a seal's canonical bytes, and
	// returns the provider's proof bytes.
	Anchor(ctx context.Context, digest []byte) ([]byte, error)
	// Verify checks proof against digest and returns what it attests. It must
	// not trust anything inside proof that it has not verified
	// cryptographically or against configured trust anchors.
	Verify(ctx context.Context, digest []byte, proof []byte) (Attestation, error)
}

// Attestation is what a verified proof establishes.
type Attestation struct {
	// Time is the instant the authority bound to the digest; the digest
	// existed no later than Time + Accuracy.
	Time time.Time
	// Accuracy is the authority's stated uncertainty around Time, or zero.
	Accuracy time.Duration
	// Authority names the party that issued the proof, such as the TSA
	// certificate's subject.
	Authority string
	// Qualified reports whether the provider could establish that the
	// authority had qualified status at Time (eIDAS Art. 41(2)); false also
	// when the provider has no way to check.
	Qualified bool
	// Details holds provider-specific facts for reports, such as policy
	// identifiers or serial numbers.
	Details map[string]string
}

// ErrInvalidProof is wrapped by every verification failure.
var ErrInvalidProof = errors.New("anchor: proof does not verify")
