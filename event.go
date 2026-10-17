package tamperlog

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// SystemStream is the stream the library's own components append to: seal and
// anchor outcomes, verifier outcomes and retention drops. It is included in
// seals like any other stream and by convention never expires. Change it with
// [WithSystemStream].
const SystemStream = "_tamperlog"

// Limits on event fields. They are enforced by [Event.Validate] and mirrored by
// the CHECK constraints in the shipped SQL.
const (
	MaxStreamLen    = 63   // bytes
	MaxNameLen      = 63   // bytes, for Action and Entity
	MaxIDLen        = 255  // bytes, for Actor, Subject and EntityID
	MaxAttributes   = 32   // entries
	MaxAttrKeyLen   = 63   // bytes
	MaxAttrValueLen = 1024 // bytes
	MaxSeq          = 1<<53 - 1
)

var (
	streamRE = regexp.MustCompile(`^[a-z_][a-z0-9_]*(\.[a-z0-9_]+)*$`)
	nameRE   = regexp.MustCompile(`^[a-z][a-z0-9]*([._][a-z0-9]+)*$`)
	attrRE   = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$`)
)

// Event is what a caller records. Stream, Action and Entity are required.
// Actor, Subject and EntityID are opaque identifiers; the empty string means
// absent. Callers processing personal data pass pseudonyms here, never names
// or national identifiers, because nothing in a chain can be erased.
//
// PayloadHash commits to content kept in an erasable table (see [Commit]); it
// is nil or exactly the hasher's size. Attributes carry small, non-identifying
// context such as purpose of use; they are hashed in byte-wise key order.
//
// Time is ignored unless the appender was built with [WithCallerTime]; by
// default the store's clock stamps the record. The stamped time is
// [Record.At].
type Event struct {
	Stream      string
	Actor       string
	Subject     string
	Action      string
	Entity      string
	EntityID    string
	PayloadHash []byte
	Attributes  map[string]string
	Time        time.Time
}

// Record is an Event linked into its stream. At is the stamped time in UTC
// with microsecond precision. PrevHash is the previous record's Hash, or the
// genesis value for Seq 1.
type Record struct {
	Event

	Seq      int64
	At       time.Time
	PrevHash []byte
	Hash     []byte
}

// Head is a stream's last link: Seq 0 and Hash nil when the stream is empty.
// Now is the store's clock at the time the head was read, used to stamp the
// next record.
type Head struct {
	Seq  int64
	Hash []byte
	Now  time.Time
}

// Store is one open transaction on a backend. Implementations are bound to a
// transaction object of their database; they never commit.
type Store interface {
	// Head locks stream against other appenders until the transaction ends
	// and returns its last link and the store's clock. Concurrent appends to
	// one stream therefore take turns, and the sequence stays dense.
	Head(ctx context.Context, stream string) (Head, error)
	// Insert writes r. It must fail if (r.Stream, r.Seq) already exists.
	Insert(ctx context.Context, r Record) error
	// Range returns the records of stream with first <= Seq <= last in
	// sequence order. Missing sequence numbers are simply absent; Walk and the
	// verifier decide what a gap means.
	Range(ctx context.Context, stream string, first, last int64) ([]Record, error)
}

// Tx is a Store that the library opened itself and must finish.
type Tx interface {
	Store
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// Provider opens transactions and answers questions about all streams. The
// convenience [Log], the seal writer and the verifier use it; appenders bound
// to a caller's transaction do not need it.
type Provider interface {
	// Begin opens a transaction. Rollback after Commit must be a no-op.
	Begin(ctx context.Context) (Tx, error)
	// Heads returns every non-empty stream's last link without locking.
	// Head.Now is unset.
	Heads(ctx context.Context) (map[string]Head, error)
	// FirstSeqs returns every non-empty stream's smallest kept sequence
	// number, which is greater than 1 once retention has dropped records.
	FirstSeqs(ctx context.Context) (map[string]int64, error)
}

// ErrInvalidEvent wraps every validation failure reported by [Event.Validate].
var ErrInvalidEvent = errors.New("tamperlog: invalid event")

// Validate reports the first rule the event breaks, wrapped in
// [ErrInvalidEvent]. hashSize is the configured hasher's output size, which
// PayloadHash must match when present.
func (e Event) Validate(hashSize int) error {
	fail := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidEvent, fmt.Sprintf(format, a...))
	}
	if err := ValidateStream(e.Stream); err != nil {
		return err
	}
	if err := validateName("action", e.Action); err != nil {
		return fail("%v", err)
	}
	if err := validateName("entity", e.Entity); err != nil {
		return fail("%v", err)
	}
	for _, id := range []struct{ name, v string }{{"actor", e.Actor}, {"subject", e.Subject}, {"entity_id", e.EntityID}} {
		if err := validateID(id.name, id.v); err != nil {
			return fail("%v", err)
		}
	}
	if e.PayloadHash != nil && len(e.PayloadHash) != hashSize {
		return fail("payload_hash is %d bytes, want %d", len(e.PayloadHash), hashSize)
	}
	if len(e.Attributes) > MaxAttributes {
		return fail("%d attributes, max %d", len(e.Attributes), MaxAttributes)
	}
	for k, v := range e.Attributes {
		if len(k) == 0 || len(k) > MaxAttrKeyLen || !attrRE.MatchString(k) {
			return fail("attribute key %q is not a lowercase dotted word of at most %d bytes", k, MaxAttrKeyLen)
		}
		if len(v) > MaxAttrValueLen || !utf8.ValidString(v) || hasControl(v) {
			return fail("attribute %q value is not valid UTF-8 text of at most %d bytes", k, MaxAttrValueLen)
		}
	}
	return nil
}

// ValidateStream reports whether name is a legal stream name: lowercase ASCII
// words of letters, digits and underscores joined by dots, starting with a
// letter or underscore, at most [MaxStreamLen] bytes.
func ValidateStream(name string) error {
	if len(name) == 0 || len(name) > MaxStreamLen || !streamRE.MatchString(name) {
		return fmt.Errorf("%w: stream %q is not a lowercase dotted word of at most %d bytes", ErrInvalidEvent, name, MaxStreamLen)
	}
	return nil
}

func validateName(field, v string) error {
	if len(v) == 0 || len(v) > MaxNameLen || !nameRE.MatchString(v) {
		return fmt.Errorf("%s %q is not a lowercase word of letters and digits joined by '.' or '_', 1 to %d bytes", field, v, MaxNameLen)
	}
	return nil
}

func validateID(field, v string) error {
	if len(v) > MaxIDLen {
		return fmt.Errorf("%s is %d bytes, max %d", field, len(v), MaxIDLen)
	}
	if !utf8.ValidString(v) || hasControl(v) {
		return fmt.Errorf("%s is not valid UTF-8 text without control characters", field)
	}
	return nil
}

func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// sortedAttributeKeys returns the attribute keys in byte-wise order, the order
// every encoder uses.
func sortedAttributeKeys(m map[string]string) []string {
	return slices.Sorted(maps.Keys(m))
}
