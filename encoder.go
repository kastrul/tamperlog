package tamperlog

import (
	"encoding/binary"
	"fmt"
)

// Encoder produces the canonical bytes of a record that are hashed. The
// encoding must be injective: two records that differ in any hashed field
// must encode differently. The ID is part of every link's hash input and is
// recorded in seals.
//
// Hashed fields are Stream, Seq, At, Actor, Subject, Action, Entity, EntityID,
// PayloadHash and Attributes. PrevHash and Hash are not encoded; PrevHash
// enters the hash input separately.
type Encoder interface {
	// ID is the stable identifier, such as "binary/v1".
	ID() string
	// Encode returns the canonical bytes of r, or an error when r holds a
	// value the encoding cannot represent.
	Encode(r Record) ([]byte, error)
}

// BinaryV1 is the default encoder, identifier "binary/v1": a length-prefixed
// binary form in fixed field order. Integers are 8-byte big-endian; every
// variable-length field is a 4-byte big-endian length followed by its bytes;
// an absent identifier or payload hash is a zero-length field. Attributes are
// an 8-byte count followed by key and value pairs in byte-wise key order.
//
//	stream | seq | at (Unix microseconds) | actor | subject | action | entity
//	| entity_id | payload_hash | count | (key | value)*
//
// Changing this breaks every existing chain; a change is a new identifier.
var BinaryV1 Encoder = binaryV1{}

type binaryV1 struct{}

func (binaryV1) ID() string { return "binary/v1" }

func (binaryV1) Encode(r Record) ([]byte, error) {
	if r.Seq < 0 || r.Seq > MaxSeq {
		return nil, fmt.Errorf("binary/v1: seq %d out of range", r.Seq)
	}
	if err := ValidateTime(r.At); err != nil {
		return nil, fmt.Errorf("binary/v1: %w", err)
	}
	b := make([]byte, 0, 256)
	b = appendField(b, []byte(r.Stream))
	b = binary.BigEndian.AppendUint64(b, uint64(r.Seq))
	b = binary.BigEndian.AppendUint64(b, uint64(r.At.UnixMicro())) //nolint:gosec // two's complement keeps it injective
	b = appendField(b, []byte(r.Actor))
	b = appendField(b, []byte(r.Subject))
	b = appendField(b, []byte(r.Action))
	b = appendField(b, []byte(r.Entity))
	b = appendField(b, []byte(r.EntityID))
	b = appendField(b, r.PayloadHash)
	keys := sortedAttributeKeys(r.Attributes)
	b = binary.BigEndian.AppendUint64(b, uint64(len(keys)))
	for _, k := range keys {
		b = appendField(b, []byte(k))
		b = appendField(b, []byte(r.Attributes[k]))
	}
	return b, nil
}

// appendField appends f as a 4-byte big-endian length followed by its bytes.
func appendField(b, f []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(f))) //nolint:gosec // fields are capped far below 4 GiB
	return append(b, f...)
}
