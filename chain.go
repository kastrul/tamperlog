package tamperlog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

// Domain is the fixed prefix of every link's hash input. It separates
// tamperlog links from any other use of the same hash function.
const Domain = "tamperlog/v1"

// dropDomain prefixes retention drop digests (see [DropDigest]).
const dropDomain = "tamperlog.drop/v1"

// Chain is the cryptographic core: an encoder and a hasher. Its zero value is
// not usable; use [NewChain] or the fields directly.
type Chain struct {
	Encoder Encoder
	Hasher  Hasher
}

// NewChain returns a Chain with the defaults ([BinaryV1], [SHA256]) where enc
// or h is nil.
func NewChain(enc Encoder, h Hasher) Chain {
	if enc == nil {
		enc = BinaryV1
	}
	if h == nil {
		h = SHA256
	}
	return Chain{Encoder: enc, Hasher: h}
}

// Genesis is the PrevHash of a stream's first record: Hasher.Size() zero bytes.
func (c Chain) Genesis() []byte { return make([]byte, c.Hasher.Size()) }

// Link returns the hash of r given its PrevHash:
//
//	H( Domain ‖ len(encoderID) ‖ encoderID ‖ len(hasherID) ‖ hasherID ‖ prevHash ‖ canonical(r) )
//
// with 4-byte big-endian lengths. r.Hash is ignored.
func (c Chain) Link(r Record) ([]byte, error) {
	canonical, err := c.Encoder.Encode(r)
	if err != nil {
		return nil, err
	}
	if len(r.PrevHash) != c.Hasher.Size() {
		return nil, fmt.Errorf("tamperlog: prev_hash is %d bytes, want %d", len(r.PrevHash), c.Hasher.Size())
	}
	h := c.Hasher.New()
	h.Write([]byte(Domain))
	h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(c.Encoder.ID())))) //nolint:gosec // short identifier
	h.Write([]byte(c.Encoder.ID()))
	h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(c.Hasher.ID())))) //nolint:gosec // short identifier
	h.Write([]byte(c.Hasher.ID()))
	h.Write(r.PrevHash)
	h.Write(canonical)
	return h.Sum(nil), nil
}

// Reason classifies why [Chain.Walk] stopped.
type Reason string

// Reasons reported in [BrokenChainError].
const (
	ReasonWrongStream     Reason = "record belongs to another stream"
	ReasonSeqMismatch     Reason = "unexpected sequence number"
	ReasonNotGenesis      Reason = "first record does not link to genesis"
	ReasonPrevHash        Reason = "prev_hash does not match the previous record"
	ReasonHashMismatch    Reason = "hash does not match the record"
	ReasonTimeRegression  Reason = "timestamp precedes the previous record by more than the tolerance"
	ReasonEncodingFailure Reason = "record cannot be encoded"
	ReasonAlgorithm       Reason = "record names another encoder or hasher"
)

// BrokenChainError reports the first sequence number at which a walk fails.
type BrokenChainError struct {
	Stream string
	Seq    int64
	Reason Reason
	Detail string
}

func (e *BrokenChainError) Error() string {
	s := fmt.Sprintf("tamperlog: chain %s broken at seq %d: %s", e.Stream, e.Seq, e.Reason)
	if e.Detail != "" {
		s += " (" + e.Detail + ")"
	}
	return s
}

// WalkOptions tune [Chain.Walk].
type WalkOptions struct {
	// TimeTolerance is how far a record's At may precede its predecessor's
	// before the walk reports ReasonTimeRegression. Zero disables the check.
	// Appenders enforce DefaultTimeTolerance, so verifiers pass the same.
	TimeTolerance time.Duration
}

// DefaultTimeTolerance is how far a record's timestamp may precede its
// predecessor's. Store clocks read under the stream lock are monotonic in
// practice; the tolerance covers clock adjustments on the database host.
const DefaultTimeTolerance = time.Second

// Walk verifies recs as the records of stream from sequence first onward:
// contiguous sequence numbers, the chain's encoder and hasher named on every
// record, each PrevHash equal to the previous Hash (the genesis value when
// first is 1), each Hash recomputed from its record and, when
// opts.TimeTolerance is set, timestamps that do not regress. It returns a
// *BrokenChainError at the first failure.
//
// An edit to the last record that also recomputes its hash leaves no later
// link to break; seals and anchors are what detect that. Walk long ranges in
// pages that overlap by one record so the boundary link is checked too.
func (c Chain) Walk(stream string, first int64, recs []Record, opts WalkOptions) error {
	want := first
	for i := range recs {
		r := &recs[i]
		fail := func(reason Reason, detail string) error {
			return &BrokenChainError{Stream: stream, Seq: want, Reason: reason, Detail: detail}
		}
		switch {
		case r.Stream != stream:
			return fail(ReasonWrongStream, fmt.Sprintf("found %q", r.Stream))
		case r.Seq != want:
			return fail(ReasonSeqMismatch, fmt.Sprintf("found seq %d", r.Seq))
		case i == 0 && want == 1 && !bytes.Equal(r.PrevHash, c.Genesis()):
			return fail(ReasonNotGenesis, "")
		case r.Encoder != c.Encoder.ID() || r.Hasher != c.Hasher.ID():
			return fail(ReasonAlgorithm, fmt.Sprintf("record says %s/%s, chain is %s/%s", r.Encoder, r.Hasher, c.Encoder.ID(), c.Hasher.ID()))
		case i > 0 && !bytes.Equal(r.PrevHash, recs[i-1].Hash):
			return fail(ReasonPrevHash, "")
		case i > 0 && opts.TimeTolerance > 0 && r.At.Before(recs[i-1].At.Add(-opts.TimeTolerance)):
			return fail(ReasonTimeRegression, fmt.Sprintf("%s after %s", r.At.Format(time.RFC3339Nano), recs[i-1].At.Format(time.RFC3339Nano)))
		}
		got, err := c.Link(*r)
		if err != nil {
			return fail(ReasonEncodingFailure, err.Error())
		}
		if !bytes.Equal(got, r.Hash) {
			return fail(ReasonHashMismatch, "")
		}
		want++
	}
	return nil
}

// DropDigest commits to a dropped range of a stream: the sequence numbers and
// the hashes at its edges, so a verifier can tell a retention drop from a
// deletion. firstPrevHash is the PrevHash of the first dropped record and
// lastHash the Hash of the last; the records after the gap link to lastHash.
//
//	H( "tamperlog.drop/v1" ‖ len(stream) ‖ stream ‖ firstSeq ‖ len(firstPrevHash) ‖ firstPrevHash
//	   ‖ lastSeq ‖ len(lastHash) ‖ lastHash )
//
// Lengths are 4-byte and sequence numbers 8-byte big-endian. The digest is the
// PayloadHash of a "retention.drop" event in the system stream (see
// [DropEvent]) and is listed in the next seal.
func DropDigest(h Hasher, stream string, firstSeq int64, firstPrevHash []byte, lastSeq int64, lastHash []byte) []byte {
	d := h.New()
	d.Write([]byte(dropDomain))
	d.Write(appendField(nil, []byte(stream)))
	d.Write(binary.BigEndian.AppendUint64(nil, uint64(firstSeq))) //nolint:gosec // sequence numbers are positive
	d.Write(appendField(nil, firstPrevHash))
	d.Write(binary.BigEndian.AppendUint64(nil, uint64(lastSeq))) //nolint:gosec // sequence numbers are positive
	d.Write(appendField(nil, lastHash))
	return d.Sum(nil)
}

// DropEvent returns the system-stream event that records a retention drop of
// stream's records firstSeq..lastSeq, with [DropDigest] as its PayloadHash and
// the range in attributes. Append it in the same transaction as the drop,
// before the drop, so a failed drop leaves no orphan event.
func DropEvent(h Hasher, systemStream, stream string, firstSeq int64, firstPrevHash []byte, lastSeq int64, lastHash []byte) Event {
	return Event{
		Stream:      systemStream,
		Action:      "retention.drop",
		Entity:      "stream",
		EntityID:    stream,
		PayloadHash: DropDigest(h, stream, firstSeq, firstPrevHash, lastSeq, lastHash),
		Attributes: map[string]string{
			"first_seq": fmt.Sprint(firstSeq),
			"last_seq":  fmt.Sprint(lastSeq),
		},
	}
}
