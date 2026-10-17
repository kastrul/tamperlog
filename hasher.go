package tamperlog

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"fmt"
	"hash"
)

// Hasher names a hash function. The ID is part of every link's hash input
// (see [Chain]) and is recorded in seals, so it must never change for a given
// algorithm.
type Hasher interface {
	// ID is the stable identifier, such as "sha256".
	ID() string
	// Size is the digest length in bytes; the genesis value is Size zero bytes.
	Size() int
	// New returns a fresh hash state.
	New() hash.Hash
}

// Shipped hashers. SHA256 is the default.
var (
	SHA256    Hasher = hasher{id: "sha256", size: sha256.Size, ctor: sha256.New}
	SHA3256   Hasher = hasher{id: "sha3-256", size: 32, ctor: func() hash.Hash { return sha3.New256() }}
	SHA512256 Hasher = hasher{id: "sha512-256", size: sha512.Size256, ctor: sha512.New512_256}
)

// Hashers lists every shipped hasher in a stable order.
func Hashers() []Hasher { return []Hasher{SHA256, SHA3256, SHA512256} }

// LookupHasher returns the shipped hasher with the given ID.
func LookupHasher(id string) (Hasher, error) {
	for _, h := range Hashers() {
		if h.ID() == id {
			return h, nil
		}
	}
	return nil, fmt.Errorf("tamperlog: unknown hasher %q", id)
}

type hasher struct {
	id   string
	size int
	ctor func() hash.Hash
}

func (h hasher) ID() string     { return h.id }
func (h hasher) Size() int      { return h.size }
func (h hasher) New() hash.Hash { return h.ctor() }

// Commit returns HMAC(salt, payload) under h, the recommended payload
// commitment for [Event.PayloadHash]. A fresh random salt of at least 16 bytes
// is stored beside the erasable payload; erasing both leaves a commitment that
// cannot be brute-forced from low-entropy content. The chain stays verifiable
// after erasure, and the commitment becomes unverifiable, which is the
// intended outcome.
func Commit(h Hasher, salt, payload []byte) []byte {
	m := hmac.New(h.New, salt)
	m.Write(payload)
	return m.Sum(nil)
}
