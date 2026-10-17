// Package sign provides seal signers: Ed25519 with a local private key and
// HMAC-SHA256 with a shared secret. Both implement [seal.Signer] and
// [seal.Verifier]. A signer is optional (ADR 0008): the seal chain and the
// external anchor are the evidence, and a signature adds origin
// authentication for deployments that want it, or that keep the key in a KMS
// or Vault Transit behind the same interface.
//
// Ed25519 lets anyone with the public key verify; HMAC lets only key holders
// verify, and a key holder can forge, so HMAC suits a single verifier that is
// also trusted not to forge (for example the DPO's offline verifier).
package sign

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/kastrul/tamperlog/seal"
)

// ErrBadSignature is returned when a signature does not verify.
var ErrBadSignature = errors.New("sign: bad signature")

// ErrUnknownKey is returned when a verifier does not hold the key named by
// a seal.
var ErrUnknownKey = errors.New("sign: unknown key id")

// Ed25519 signs with a local Ed25519 private key. The key is in process
// memory; a compromised process can sign anything, which is why seals are
// anchored externally as well.
type Ed25519 struct {
	keyID string
	priv  ed25519.PrivateKey
}

// NewEd25519 returns a signer for priv under keyID.
func NewEd25519(keyID string, priv ed25519.PrivateKey) (*Ed25519, error) {
	if keyID == "" {
		return nil, errors.New("sign: empty key id")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("sign: private key is %d bytes, want %d", len(priv), ed25519.PrivateKeySize)
	}
	return &Ed25519{keyID: keyID, priv: priv}, nil
}

// KeyID returns the key identifier.
func (s *Ed25519) KeyID() string { return s.keyID }

// Sign signs data.
func (s *Ed25519) Sign(_ context.Context, data []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, data), nil
}

// Public returns the public key for distribution to verifiers.
func (s *Ed25519) Public() ed25519.PublicKey {
	return s.priv.Public().(ed25519.PublicKey) //nolint:errcheck,forcetypeassert // ed25519 private keys always yield ed25519 public keys
}

// Ed25519Verifier verifies seals signed by one or more Ed25519 keys, by key
// identifier. Keep retired keys so old seals stay verifiable.
type Ed25519Verifier struct {
	keys map[string]ed25519.PublicKey
}

// NewEd25519Verifier returns a verifier for the given keys.
func NewEd25519Verifier(keys map[string]ed25519.PublicKey) *Ed25519Verifier {
	m := make(map[string]ed25519.PublicKey, len(keys))
	for k, v := range keys {
		m[k] = v
	}
	return &Ed25519Verifier{keys: m}
}

// Verify checks sig over data by keyID.
func (v *Ed25519Verifier) Verify(_ context.Context, keyID string, data, sig []byte) error {
	pub, ok := v.keys[keyID]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownKey, keyID)
	}
	if !ed25519.Verify(pub, data, sig) {
		return ErrBadSignature
	}
	return nil
}

// HMAC signs with HMAC-SHA256 under a shared secret. Whoever can verify can
// also forge, so it does not provide non-repudiation.
type HMAC struct {
	keyID string
	key   []byte
}

// NewHMAC returns a signer for key (at least 32 bytes) under keyID.
func NewHMAC(keyID string, key []byte) (*HMAC, error) {
	if keyID == "" {
		return nil, errors.New("sign: empty key id")
	}
	if len(key) < 32 {
		return nil, fmt.Errorf("sign: HMAC key is %d bytes, want at least 32", len(key))
	}
	return &HMAC{keyID: keyID, key: append([]byte(nil), key...)}, nil
}

// KeyID returns the key identifier.
func (s *HMAC) KeyID() string { return s.keyID }

// Sign returns HMAC-SHA256(key, data).
func (s *HMAC) Sign(_ context.Context, data []byte) ([]byte, error) {
	m := hmac.New(sha256.New, s.key)
	m.Write(data)
	return m.Sum(nil), nil
}

// Verify recomputes the tag and compares in constant time. Only the signer's
// own key identifier is accepted.
func (s *HMAC) Verify(ctx context.Context, keyID string, data, sig []byte) error {
	if keyID != s.keyID {
		return fmt.Errorf("%w: %q", ErrUnknownKey, keyID)
	}
	want, _ := s.Sign(ctx, data)
	if subtle.ConstantTimeCompare(want, sig) != 1 {
		return ErrBadSignature
	}
	return nil
}

// VerifySeal checks a parsed seal's signature with v. An unsigned seal
// returns [ErrUnsigned]; callers decide whether that is acceptable.
func VerifySeal(ctx context.Context, v seal.Verifier, s *seal.Seal) error {
	if s.KeyID == "" {
		return ErrUnsigned
	}
	data, err := s.SigningBytes()
	if err != nil {
		return err
	}
	return v.Verify(ctx, s.KeyID, data, s.Signature)
}

// ErrUnsigned is returned by [VerifySeal] for a seal without a signature.
var ErrUnsigned = errors.New("sign: seal is not signed")

var (
	_ seal.Signer   = (*Ed25519)(nil)
	_ seal.Verifier = (*Ed25519Verifier)(nil)
	_ seal.Signer   = (*HMAC)(nil)
	_ seal.Verifier = (*HMAC)(nil)
)
