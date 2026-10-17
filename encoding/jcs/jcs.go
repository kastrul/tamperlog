// Package jcs provides the "jcs/v1" canonical record encoder: the hashed
// fields of a record as an RFC 8785 JSON object, so an auditor can read the
// exact bytes that were hashed.
//
// The object has these members, serialised in RFC 8785 order with no
// whitespace:
//
//	{"action":"…","actor":"…","at":<Unix microseconds>,"attributes":{…},
//	 "entity":"…","entity_id":"…","payload_hash":"<hex or empty>",
//	 "seq":<n>,"stream":"…","subject":"…"}
//
// Absent identifiers are empty strings and an absent payload hash is the empty
// string. Integers must be below 2^53, which [tamperlog.MaxSeq] guarantees for
// seq and which holds for microsecond timestamps until the year 2255.
package jcs

import (
	"encoding/hex"
	"fmt"

	"github.com/kastrul/tamperlog"
	"github.com/kastrul/tamperlog/internal/jcs"
)

// V1 is the "jcs/v1" encoder.
var V1 tamperlog.Encoder = v1{}

type v1 struct{}

func (v1) ID() string { return "jcs/v1" }

func (v1) Encode(r tamperlog.Record) ([]byte, error) {
	if r.Seq < 0 || r.Seq > tamperlog.MaxSeq {
		return nil, fmt.Errorf("jcs/v1: seq %d out of range", r.Seq)
	}
	if err := tamperlog.ValidateTime(r.At); err != nil {
		return nil, fmt.Errorf("jcs/v1: %w", err)
	}
	attrs := make(map[string]any, len(r.Attributes))
	for k, v := range r.Attributes {
		attrs[k] = v
	}
	return jcs.Marshal(map[string]any{
		"stream":       r.Stream,
		"seq":          r.Seq,
		"at":           r.At.UnixMicro(),
		"actor":        r.Actor,
		"subject":      r.Subject,
		"action":       r.Action,
		"entity":       r.Entity,
		"entity_id":    r.EntityID,
		"payload_hash": hex.EncodeToString(r.PayloadHash),
		"attributes":   attrs,
	})
}
