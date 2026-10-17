// Package seal commits to every stream head at a point in time and carries
// that commitment outside the database.
//
// A [Seal] is a small JSON document, serialised with RFC 8785 JCS, that lists
// each stream's encoder, hasher, first kept and head sequence numbers and head
// hash, the retention drop digests since the previous seal, and the SHA-256 of
// the previous seal's canonical bytes. The seal sequence is therefore itself a
// chain: a deleted or replaced seal is visible without any external party.
// Seals are written at a fixed interval even when nothing changed, so absence
// of activity is attested too.
//
// A [Writer] produces seals from a [tamperlog.Provider], stores them in a
// [Store] and pushes the same bytes to every [Sink]; the anchor package then
// obtains external proofs over the seal hash. The canonical format is
// specified in SPEC.md under "tamperlog.seal/1".
package seal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/kastrul/tamperlog"
	"github.com/kastrul/tamperlog/internal/jcs"
)

// Schema identifies the seal document format.
const Schema = "tamperlog.seal/1"

// StreamHead is one stream's state inside a seal.
type StreamHead struct {
	Stream       string `json:"stream"`
	Encoder      string `json:"encoder"`
	Hasher       string `json:"hasher"`
	FirstKeptSeq int64  `json:"first_kept_seq"`
	HeadSeq      int64  `json:"head_seq"`
	HeadHash     Hex    `json:"head_hash"`
}

// Hex is a byte slice that marshals as lowercase hexadecimal.
type Hex []byte

// MarshalJSON encodes h as a lowercase hex string.
func (h Hex) MarshalJSON() ([]byte, error) { return json.Marshal(hex.EncodeToString(h)) }

// UnmarshalJSON decodes a hex string.
func (h *Hex) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	d, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	*h = d
	return nil
}

// Seal is the document. Seq is the seal's position in the seal chain, starting
// at 1. PrevSealHash is the SHA-256 of the previous seal's canonical bytes, or
// 32 zero bytes for Seq 1. Streams are sorted by name. Drops are the
// retention drop digests appended to the system stream since the previous
// seal, in sequence order. Writer identifies the software that wrote the seal.
// KeyID and Signature are present only when a signer is configured; Signature
// covers the canonical bytes of the document without the "signature" member.
type Seal struct {
	Schema       string       `json:"schema"`
	Seq          int64        `json:"seq"`
	SealedAt     time.Time    `json:"sealed_at"`
	PrevSealHash Hex          `json:"prev_seal_hash"`
	Streams      []StreamHead `json:"streams"`
	Drops        []Hex        `json:"drops"`
	Writer       string       `json:"writer"`
	KeyID        string       `json:"key_id,omitempty"`
	Signature    Hex          `json:"signature,omitempty"`
}

// GenesisHash is PrevSealHash of the first seal.
var GenesisHash = make([]byte, sha256.Size)

// MaxSeq bounds seal sequence numbers so every encoder can represent them.
const MaxSeq = 1<<53 - 1

// ErrInvalid wraps every structural failure found by [Seal.Validate].
var ErrInvalid = errors.New("seal: invalid")

// Validate checks the document's structure: schema, sequence bounds, genesis
// rule for Seq 1, a 32-byte PrevSealHash, streams sorted by name without
// duplicates and with legal names, non-empty algorithm identifiers,
// 1 <= first_kept_seq <= head_seq <= MaxSeq, head hashes and drop digests of
// 32 to 64 bytes, a non-empty writer, and signature and key_id present
// together. Comparison with the previous seal and with the live chain is the
// verifier's job.
func (s *Seal) Validate() error {
	fail := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
	}
	if s.Schema != Schema {
		return fail("schema %q, want %q", s.Schema, Schema)
	}
	if s.Seq < 1 || s.Seq > MaxSeq {
		return fail("seq %d out of range", s.Seq)
	}
	if s.SealedAt.IsZero() || s.SealedAt.Year() < 1970 || s.SealedAt.Year() > 9999 {
		return fail("sealed_at %s out of range", s.SealedAt)
	}
	if len(s.PrevSealHash) != sha256.Size {
		return fail("prev_seal_hash is %d bytes, want %d", len(s.PrevSealHash), sha256.Size)
	}
	if s.Seq == 1 && !bytes.Equal(s.PrevSealHash, GenesisHash) {
		return fail("first seal must link to genesis")
	}
	for i, h := range s.Streams {
		if err := tamperlog.ValidateStream(h.Stream); err != nil {
			return fail("stream %d: %v", i, err)
		}
		if i > 0 && s.Streams[i-1].Stream >= h.Stream {
			return fail("streams not sorted or duplicated at %q", h.Stream)
		}
		if h.Encoder == "" || len(h.Encoder) > 63 || h.Hasher == "" || len(h.Hasher) > 63 {
			return fail("stream %s: encoder or hasher identifier missing", h.Stream)
		}
		if h.FirstKeptSeq < 1 || h.HeadSeq < h.FirstKeptSeq || h.HeadSeq > MaxSeq {
			return fail("stream %s: range %d..%d", h.Stream, h.FirstKeptSeq, h.HeadSeq)
		}
		if len(h.HeadHash) < 32 || len(h.HeadHash) > 64 {
			return fail("stream %s: head hash is %d bytes", h.Stream, len(h.HeadHash))
		}
	}
	for i, d := range s.Drops {
		if len(d) < 32 || len(d) > 64 {
			return fail("drop %d is %d bytes", i, len(d))
		}
	}
	if s.Writer == "" || len(s.Writer) > 255 {
		return fail("writer missing or too long")
	}
	if (s.KeyID == "") != (len(s.Signature) == 0) {
		return fail("key_id and signature must be present together")
	}
	return nil
}

// Canonical returns the RFC 8785 serialisation of s including the signature
// when present. These are the bytes stored, sunk and hashed.
func (s *Seal) Canonical() ([]byte, error) { return s.canonical(true) }

// SigningBytes returns the canonical serialisation without the "signature"
// member; a signer signs these bytes.
func (s *Seal) SigningBytes() ([]byte, error) { return s.canonical(false) }

func (s *Seal) canonical(withSignature bool) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	streams := make([]any, len(s.Streams))
	for i, h := range s.Streams {
		streams[i] = map[string]any{
			"stream":         h.Stream,
			"encoder":        h.Encoder,
			"hasher":         h.Hasher,
			"first_kept_seq": h.FirstKeptSeq,
			"head_seq":       h.HeadSeq,
			"head_hash":      hex.EncodeToString(h.HeadHash),
		}
	}
	drops := make([]any, len(s.Drops))
	for i, d := range s.Drops {
		drops[i] = hex.EncodeToString(d)
	}
	m := map[string]any{
		"schema":         s.Schema,
		"seq":            s.Seq,
		"sealed_at":      s.SealedAt.UTC().Format(time.RFC3339Nano),
		"prev_seal_hash": hex.EncodeToString(s.PrevSealHash),
		"streams":        streams,
		"drops":          drops,
		"writer":         s.Writer,
	}
	if s.KeyID != "" {
		m["key_id"] = s.KeyID
	}
	if withSignature && len(s.Signature) > 0 {
		m["signature"] = hex.EncodeToString(s.Signature)
	}
	return jcs.Marshal(m)
}

// Hash returns SHA-256 of canonical seal bytes: the value anchors commit to
// and the next seal's PrevSealHash.
func Hash(canonical []byte) []byte {
	h := sha256.Sum256(canonical)
	return h[:]
}

// ErrNotCanonical is returned by [Parse] when the input is not the exact
// canonical serialisation of the seal it describes.
var ErrNotCanonical = errors.New("seal: bytes are not canonical")

// Parse decodes canonical seal bytes and checks that re-serialising yields the
// same bytes, so a verifier never hashes a re-formatted document.
func Parse(b []byte) (*Seal, error) {
	var s Seal
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("seal: parse: %w", err)
	}
	if dec.More() {
		return nil, ErrNotCanonical
	}
	again, err := s.Canonical()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(again, b) {
		return nil, ErrNotCanonical
	}
	return &s, nil
}

// Stored is a seal as kept in a [Store]: its canonical bytes plus derived
// fields for indexing.
type Stored struct {
	Seq      int64
	SealedAt time.Time
	Hash     []byte // SHA-256 of Bytes
	Bytes    []byte // canonical seal document
}

// Proof is an external anchor's evidence over a seal hash, as returned by an
// anchor provider. Provider is the provider identifier, such as "rfc3161";
// Bytes is the provider's token or receipt.
type Proof struct {
	SealSeq    int64
	Provider   string
	ObtainedAt time.Time
	Bytes      []byte
}

// Store persists seals and proofs. Backends in store/* implement it beside
// [tamperlog.Provider]. Implementations must refuse a seal whose Seq is not
// the last seal's Seq plus one, and must refuse to overwrite a seal.
type Store interface {
	PutSeal(ctx context.Context, s Stored) error
	// LastSeal returns the newest seal; ok is false when none exists.
	LastSeal(ctx context.Context) (s Stored, ok bool, err error)
	// Seals returns seals with first <= Seq <= last in order.
	Seals(ctx context.Context, first, last int64) ([]Stored, error)
	PutProof(ctx context.Context, p Proof) error
	// Proofs returns every proof stored for the seal.
	Proofs(ctx context.Context, sealSeq int64) ([]Proof, error)
	// Unanchored returns up to limit seals, oldest first, that have no proof
	// from provider.
	Unanchored(ctx context.Context, provider string, limit int) ([]Stored, error)
}

// Sink is write-once storage outside the database: a directory, an object
// store with Object Lock, a remote copy held by the DPO. Put must fail with
// [ErrExists] when the key already exists; a verifier treats a key whose
// content differs from the stored seal as evidence of tampering.
type Sink interface {
	Put(ctx context.Context, key string, data []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
	// List returns keys with the prefix in lexical order.
	List(ctx context.Context, prefix string) ([]string, error)
}

// ErrExists is returned by [Sink.Put] when the key already holds an object.
var ErrExists = errors.New("seal: key already exists")

// ErrNotFound is returned by [Sink.Get] for a missing key.
var ErrNotFound = errors.New("seal: key not found")

// Key returns the sink key of seal seq: "seals/<seq as 12 digits>.json".
// Proofs use ProofKey. Fixed-width digits keep lexical and numeric order
// equal, which List relies on.
func Key(seq int64) string { return fmt.Sprintf("seals/%012d.json", seq) }

// ProofKey returns the sink key of a proof: "seals/<seq>.<provider>.proof".
func ProofKey(seq int64, provider string) string {
	return fmt.Sprintf("seals/%012d.%s.proof", seq, provider)
}
