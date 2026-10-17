// Package bundle exports a self-describing copy of records, seals and proofs
// that the offline verifier reads without any database: the format
// "tamperlog.bundle/1".
//
// A bundle is a directory (or any [seal.Sink]-like key space):
//
//	manifest.json                         schema, creation time, per-stream file digests
//	streams/<stream>.jsonl                one record per line, see [Line]
//	seals/<seq>.json                      canonical seal bytes, same keys as sinks
//	seals/<seq>.<provider>.proof          proof bytes, same keys as sinks
//
// Seal and proof keys equal those used by sinks, so a write-once sink
// directory plus exported streams is a bundle, and a bundle's seals directory
// can be compared with a sink. The manifest lists SHA-256 digests of the
// stream files; the verifier recomputes every link anyway, so the digests
// serve transport integrity, not evidence.
package bundle

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/kastrul/tamperlog"
	"github.com/kastrul/tamperlog/seal"
	"github.com/kastrul/tamperlog/seal/sinks/fs"
	"github.com/kastrul/tamperlog/verify"
)

// Schema identifies the bundle format.
const Schema = "tamperlog.bundle/1"

// Manifest describes a bundle.
type Manifest struct {
	Schema    string         `json:"schema"`
	CreatedAt time.Time      `json:"created_at"`
	Writer    string         `json:"writer"`
	Streams   []StreamEntry  `json:"streams"`
	Seals     SealRange      `json:"seals"`
	Proofs    map[string]int `json:"proofs"` // provider -> count
}

// StreamEntry describes one exported stream file.
type StreamEntry struct {
	Stream   string `json:"stream"`
	File     string `json:"file"`
	FirstSeq int64  `json:"first_seq"`
	LastSeq  int64  `json:"last_seq"`
	Records  int64  `json:"records"`
	SHA256   string `json:"sha256"`
}

// SealRange is the range of exported seals.
type SealRange struct {
	FirstSeq int64 `json:"first_seq"`
	LastSeq  int64 `json:"last_seq"`
	Count    int64 `json:"count"`
}

// Line is one record as written to a stream file: JSON with hex hashes and
// an RFC 3339 time at microsecond precision.
type Line struct {
	Stream      string            `json:"stream"`
	Seq         int64             `json:"seq"`
	At          time.Time         `json:"at"`
	Encoder     string            `json:"encoder"`
	Hasher      string            `json:"hasher"`
	Actor       string            `json:"actor"`
	Subject     string            `json:"subject"`
	Action      string            `json:"action"`
	Entity      string            `json:"entity"`
	EntityID    string            `json:"entity_id"`
	PayloadHash string            `json:"payload_hash,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	PrevHash    string            `json:"prev_hash"`
	Hash        string            `json:"hash"`
}

// FromRecord converts a record.
func FromRecord(r tamperlog.Record) Line {
	return Line{
		Stream: r.Stream, Seq: r.Seq, At: r.At.UTC(), Encoder: r.Encoder, Hasher: r.Hasher,
		Actor: r.Actor, Subject: r.Subject, Action: r.Action, Entity: r.Entity, EntityID: r.EntityID,
		PayloadHash: hex.EncodeToString(r.PayloadHash), Attributes: r.Attributes,
		PrevHash: hex.EncodeToString(r.PrevHash), Hash: hex.EncodeToString(r.Hash),
	}
}

// Record converts back.
func (l Line) Record() (tamperlog.Record, error) {
	r := tamperlog.Record{
		Event:   tamperlog.Event{Stream: l.Stream, Actor: l.Actor, Subject: l.Subject, Action: l.Action, Entity: l.Entity, EntityID: l.EntityID, Attributes: l.Attributes},
		Seq:     l.Seq,
		At:      l.At.UTC(),
		Encoder: l.Encoder,
		Hasher:  l.Hasher,
	}
	var err error
	if l.PayloadHash != "" {
		if r.PayloadHash, err = hex.DecodeString(l.PayloadHash); err != nil {
			return r, fmt.Errorf("bundle: %s/%d payload_hash: %w", l.Stream, l.Seq, err)
		}
	}
	if r.PrevHash, err = hex.DecodeString(l.PrevHash); err != nil {
		return r, fmt.Errorf("bundle: %s/%d prev_hash: %w", l.Stream, l.Seq, err)
	}
	if r.Hash, err = hex.DecodeString(l.Hash); err != nil {
		return r, fmt.Errorf("bundle: %s/%d hash: %w", l.Stream, l.Seq, err)
	}
	if len(r.Attributes) == 0 {
		r.Attributes = nil
	}
	return r, nil
}

// ExportOptions tune [Export].
type ExportOptions struct {
	// Writer names the software writing the bundle.
	Writer string
	// PageSize is how many records one read fetches (default 1000).
	PageSize int64
	// Streams restricts the export to these streams; nil means all.
	Streams []string
}

// Export writes a bundle of src to dir, which must not exist or be empty.
// Seals and proofs are written through a write-once filesystem sink, so an
// export never overwrites evidence.
func Export(ctx context.Context, src verify.Source, dir string, opts ExportOptions) (*Manifest, error) {
	if opts.PageSize <= 0 {
		opts.PageSize = 1000
	}
	if opts.Writer == "" {
		opts.Writer = "tamperlog"
	}
	if entries, err := os.ReadDir(dir); err == nil && len(entries) > 0 {
		return nil, fmt.Errorf("bundle: %s is not empty", dir)
	}
	if err := os.MkdirAll(filepath.Join(dir, "streams"), 0o750); err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	m := &Manifest{Schema: Schema, CreatedAt: time.Now().UTC().Truncate(time.Microsecond), Writer: opts.Writer, Proofs: map[string]int{}}

	heads, err := src.Heads(ctx)
	if err != nil {
		return nil, fmt.Errorf("bundle: heads: %w", err)
	}
	firsts, err := src.FirstSeqs(ctx)
	if err != nil {
		return nil, fmt.Errorf("bundle: first seqs: %w", err)
	}
	names := slices.Sorted(maps.Keys(heads))
	if opts.Streams != nil {
		names = slices.DeleteFunc(names, func(n string) bool { return !slices.Contains(opts.Streams, n) })
	}
	for _, name := range names {
		e, err := exportStream(ctx, src, dir, name, firsts[name], heads[name].Seq, opts.PageSize)
		if err != nil {
			return nil, err
		}
		m.Streams = append(m.Streams, e)
	}

	sink, err := fs.New(dir)
	if err != nil {
		return nil, err
	}
	last, hasSeals, err := src.LastSeal(ctx)
	if err != nil {
		return nil, fmt.Errorf("bundle: last seal: %w", err)
	}
	if !hasSeals {
		last.Seq = 0
	}
	for lo := int64(1); lo <= last.Seq; lo += opts.PageSize {
		seals, err := src.Seals(ctx, lo, min(lo+opts.PageSize-1, last.Seq))
		if err != nil {
			return nil, fmt.Errorf("bundle: seals: %w", err)
		}
		for _, s := range seals {
			if err := sink.Put(ctx, seal.Key(s.Seq), s.Bytes); err != nil {
				return nil, err
			}
			if m.Seals.FirstSeq == 0 {
				m.Seals.FirstSeq = s.Seq
			}
			m.Seals.LastSeq = s.Seq
			m.Seals.Count++
			proofs, err := src.Proofs(ctx, s.Seq)
			if err != nil {
				return nil, fmt.Errorf("bundle: proofs of seal %d: %w", s.Seq, err)
			}
			for _, p := range proofs {
				if err := sink.Put(ctx, seal.ProofKey(s.Seq, p.Provider), p.Bytes); err != nil {
					return nil, err
				}
				m.Proofs[p.Provider]++
			}
		}
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), append(b, '\n'), 0o440); err != nil { //nolint:gosec // group-readable on purpose
		return nil, fmt.Errorf("bundle: manifest: %w", err)
	}
	return m, nil
}

func exportStream(ctx context.Context, src verify.Source, dir, name string, first, head, page int64) (StreamEntry, error) {
	rel := filepath.ToSlash(filepath.Join("streams", name+".jsonl"))
	f, err := os.OpenFile(filepath.Join(dir, filepath.FromSlash(rel)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o440) //nolint:gosec // name is a validated stream name
	if err != nil {
		return StreamEntry{}, fmt.Errorf("bundle: %w", err)
	}
	defer f.Close() //nolint:errcheck // closed explicitly below on success
	h := sha256.New()
	w := bufio.NewWriter(io.MultiWriter(f, h))
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	e := StreamEntry{Stream: name, File: rel, FirstSeq: first, LastSeq: head}
	for lo := first; lo <= head; lo += page {
		recs, err := src.Range(ctx, name, lo, min(lo+page-1, head))
		if err != nil {
			return StreamEntry{}, fmt.Errorf("bundle: %s: %w", name, err)
		}
		for _, r := range recs {
			if err := enc.Encode(FromRecord(r)); err != nil {
				return StreamEntry{}, fmt.Errorf("bundle: %s/%d: %w", name, r.Seq, err)
			}
			e.Records++
		}
	}
	if err := w.Flush(); err != nil {
		return StreamEntry{}, err
	}
	if err := f.Close(); err != nil {
		return StreamEntry{}, err
	}
	e.SHA256 = hex.EncodeToString(h.Sum(nil))
	return e, nil
}

// Bundle is an opened bundle; it implements [verify.Source].
type Bundle struct {
	dir      string
	manifest Manifest
	sink     *fs.Sink
	streams  map[string][]tamperlog.Record // loaded lazily
}

// Open reads a bundle's manifest and checks the stream file digests.
func Open(dir string) (*Bundle, error) {
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json")) //nolint:gosec // dir is the bundle the caller chose
	if err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("bundle: manifest: %w", err)
	}
	if m.Schema != Schema {
		return nil, fmt.Errorf("bundle: schema %q, want %q", m.Schema, Schema)
	}
	for _, e := range m.Streams {
		if strings.Contains(e.File, "..") || filepath.IsAbs(e.File) {
			return nil, fmt.Errorf("bundle: invalid file path %q", e.File)
		}
		data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(e.File))) //nolint:gosec // relative path checked above
		if err != nil {
			return nil, fmt.Errorf("bundle: %w", err)
		}
		if got := sha256.Sum256(data); hex.EncodeToString(got[:]) != e.SHA256 {
			return nil, fmt.Errorf("bundle: %s: digest mismatch", e.File)
		}
	}
	sink, err := fs.New(dir)
	if err != nil {
		return nil, err
	}
	return &Bundle{dir: dir, manifest: m, sink: sink, streams: map[string][]tamperlog.Record{}}, nil
}

// Manifest returns the parsed manifest.
func (b *Bundle) Manifest() Manifest { return b.manifest }

// Sink returns the bundle's seal directory as a sink, for cross-checking
// with another copy.
func (b *Bundle) Sink() seal.Sink { return b.sink }

func (b *Bundle) load(name string) ([]tamperlog.Record, error) {
	if recs, ok := b.streams[name]; ok {
		return recs, nil
	}
	var entry *StreamEntry
	for i := range b.manifest.Streams {
		if b.manifest.Streams[i].Stream == name {
			entry = &b.manifest.Streams[i]
		}
	}
	if entry == nil {
		return nil, nil
	}
	f, err := os.Open(filepath.Join(b.dir, filepath.FromSlash(entry.File))) //nolint:gosec // path validated in Open
	if err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	var recs []tamperlog.Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		var l Line
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			return nil, fmt.Errorf("bundle: %s: %w", entry.File, err)
		}
		r, err := l.Record()
		if err != nil {
			return nil, err
		}
		recs = append(recs, r)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("bundle: %s: %w", entry.File, err)
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].Seq < recs[j].Seq })
	b.streams[name] = recs
	return recs, nil
}

// Heads returns the last record of every stream file.
func (b *Bundle) Heads(context.Context) (map[string]tamperlog.Head, error) {
	out := map[string]tamperlog.Head{}
	for _, e := range b.manifest.Streams {
		recs, err := b.load(e.Stream)
		if err != nil {
			return nil, err
		}
		if n := len(recs); n > 0 {
			r := recs[n-1]
			out[e.Stream] = tamperlog.Head{Seq: r.Seq, Hash: r.Hash, At: r.At, Encoder: r.Encoder, Hasher: r.Hasher}
		}
	}
	return out, nil
}

// FirstSeqs returns the first record of every stream file.
func (b *Bundle) FirstSeqs(context.Context) (map[string]int64, error) {
	out := map[string]int64{}
	for _, e := range b.manifest.Streams {
		recs, err := b.load(e.Stream)
		if err != nil {
			return nil, err
		}
		if len(recs) > 0 {
			out[e.Stream] = recs[0].Seq
		}
	}
	return out, nil
}

// Range returns records first..last of a stream.
func (b *Bundle) Range(_ context.Context, stream string, first, last int64) ([]tamperlog.Record, error) {
	recs, err := b.load(stream)
	if err != nil {
		return nil, err
	}
	var out []tamperlog.Record
	for _, r := range recs {
		if r.Seq >= first && r.Seq <= last {
			out = append(out, r)
		}
	}
	return out, nil
}

// LastSeal returns the highest-numbered seal file.
func (b *Bundle) LastSeal(ctx context.Context) (seal.Stored, bool, error) {
	seals, err := b.Seals(ctx, b.manifest.Seals.LastSeq, b.manifest.Seals.LastSeq)
	if err != nil || len(seals) == 0 {
		return seal.Stored{}, false, err
	}
	return seals[0], true, nil
}

// Seals returns seal files first..last.
func (b *Bundle) Seals(ctx context.Context, first, last int64) ([]seal.Stored, error) {
	var out []seal.Stored
	for seq := max(first, 1); seq <= last; seq++ {
		data, err := b.sink.Get(ctx, seal.Key(seq))
		if errors.Is(err, seal.ErrNotFound) {
			if seq > b.manifest.Seals.LastSeq {
				break
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		st := seal.Stored{Seq: seq, Hash: seal.Hash(data), Bytes: data}
		if doc, err := seal.Parse(data); err == nil {
			st.SealedAt = doc.SealedAt
		}
		out = append(out, st)
	}
	return out, nil
}

// Proofs returns the proof files of one seal.
func (b *Bundle) Proofs(ctx context.Context, sealSeq int64) ([]seal.Proof, error) {
	prefix := fmt.Sprintf("seals/%012d.", sealSeq)
	keys, err := b.sink.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	var out []seal.Proof
	for _, k := range keys {
		if !strings.HasSuffix(k, ".proof") {
			continue
		}
		provider := strings.TrimSuffix(strings.TrimPrefix(k, prefix), ".proof")
		data, err := b.sink.Get(ctx, k)
		if err != nil {
			return nil, err
		}
		out = append(out, seal.Proof{SealSeq: sealSeq, Provider: provider, Bytes: data})
	}
	return out, nil
}

var _ verify.Source = (*Bundle)(nil)
