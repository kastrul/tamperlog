// Package s3lock is a [seal.Sink] on an S3 bucket with Object Lock, the only
// storage in the tamperlog design that holds against the account's own
// administrators: a version written under COMPLIANCE retention cannot be
// deleted or shortened by anyone, including the root user, until the
// retention date passes.
//
// The sink writes every key once. Put sends If-None-Match: * so a store that
// honours conditional writes refuses an existing key atomically, and it sends
// the SHA-256 of the data so the store rejects a corrupted upload. Because
// Object Lock protects versions, not keys, a second Put of a locked key on a
// store that ignores If-None-Match does not overwrite anything: it adds a
// second version and the first stays. The sink therefore treats a key with
// more than one version as evidence of a conflicting writer and fails with
// [ErrMultipleVersions] after Put and before returning data from Get, unless
// [WithVerifyVersions] is turned off. A verifier must apply the same rule
// (ADR 0008): a seal key with two versions is a failure, never "take the
// newest".
//
// Retention does not stop anyone with s3:DeleteObject from adding a delete
// marker on top of a locked version. The marker hides the key from GetObject
// and from ListObjectsV2 while the version underneath stays intact, so an
// administrator rolling back the database could hide the later seals from a
// naive verifier. The sink therefore reads the bucket through
// ListObjectVersions: List returns every key that has any version or delete
// marker, and Get fails with [ErrHidden] rather than [seal.ErrNotFound] when
// a key the store calls missing still has versions.
//
// [Sink.Check] and [Sink.Describe] are the operator's preflight: they report
// whether the bucket has Object Lock, in which mode and with what default
// retention, whether versioning is on, and, with [WithProbeKey], whether a
// versioned delete of a freshly written object is in fact refused by
// retention. Run it against every new bucket and every new provider before
// citing retention to an auditor; the docs in docs/sinks/s3lock.md cover
// bucket setup, IAM and the differences between AWS and Hetzner Object
// Storage.
package s3lock

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/kastrul/tamperlog/seal"
)

// ErrMultipleVersions is returned by [Sink.Put] and [Sink.Get] when the key
// holds more than one object version or a delete marker. On a locked bucket
// that means a second writer put the key, or someone tried to hide it: the
// first version is still there and a verifier must report the key as broken
// rather than read either copy.
var ErrMultipleVersions = errors.New("s3lock: key has multiple versions")

// ErrHidden is returned by [Sink.Get] when the store answers NoSuchKey for a
// key that still has object versions or delete markers: a delete marker is
// the current version. On a locked bucket the data underneath cannot have
// been destroyed, so the key is hidden, not missing, and a verifier must
// report it as an error, never as an absent seal. It does not wrap
// [seal.ErrNotFound]. [Sink.Versions] shows the marker and what it covers.
var ErrHidden = errors.New("s3lock: key is hidden behind a delete marker")

// Retention is the per-object retention [Sink.Put] requests when
// [WithRetention] is set.
type Retention struct {
	Mode     types.ObjectLockMode
	Duration time.Duration
}

// Sink is a write-once [seal.Sink] on one bucket. Create it with [New].
type Sink struct {
	client            *s3.Client
	bucket            string
	prefix            string
	retention         *Retention
	contentType       string
	requireLock       bool
	requireCompliance bool
	verifyVersions    bool
	probeKey          string
	now               func() time.Time
}

// Option configures a [Sink].
type Option func(*Sink)

// WithPrefix puts every key under prefix inside the bucket. Leading slashes
// are dropped and a trailing slash is added when missing, so "audit" and
// "audit/" are the same prefix. Keys returned by List are relative to it.
func WithPrefix(prefix string) Option {
	return func(s *Sink) {
		p := strings.TrimLeft(prefix, "/")
		if p != "" && !strings.HasSuffix(p, "/") {
			p += "/"
		}
		s.prefix = p
	}
}

// WithRetention makes every Put request Object Lock retention of mode
// (COMPLIANCE or GOVERNANCE) until now plus duration. Without it the sink
// sends no retention headers and relies on the bucket's default retention,
// which is the recommended setup because the writer credential then needs no
// retention permissions at all and cannot weaken anything.
//
// An explicit per-object retention replaces the bucket default for that
// object; it does not add to it. On AWS a Put may therefore set a shorter
// period or GOVERNANCE mode on a bucket whose default is ten years of
// COMPLIANCE, unless a bucket policy with the
// s3:object-lock-remaining-retention-days condition refuses it (see
// docs/sinks/s3lock.md). [Sink.Check] fails with [ErrWeakRetention] when the
// configured retention is shorter than the bucket default or GOVERNANCE on a
// COMPLIANCE bucket. Durations are not validated at option time so that tests
// can use short ones.
func WithRetention(mode types.ObjectLockMode, duration time.Duration) Option {
	return func(s *Sink) { s.retention = &Retention{Mode: mode, Duration: duration} }
}

// WithContentType sets one Content-Type for every object. The default is
// application/json for keys ending in .json and application/octet-stream
// otherwise.
func WithContentType(ct string) Option {
	return func(s *Sink) { s.contentType = ct }
}

// WithRequireLockedBucket makes [Sink.Check] fail unless the bucket reports
// Object Lock enabled. Set it in production; leave it off only for a
// development bucket.
func WithRequireLockedBucket(require bool) Option {
	return func(s *Sink) { s.requireLock = require }
}

// WithRequireCompliance makes [Sink.Check] fail with [ErrNotCompliance]
// unless the retention mode objects will carry is COMPLIANCE: the
// [WithRetention] mode when set, otherwise the bucket's default retention
// mode, and the mode the write probe observed when a probe ran. GOVERNANCE
// retention is removed by any principal holding
// s3:BypassGovernanceRetention, which account administrators usually do, so
// only COMPLIANCE meets the administrator threat model. Set it in production
// together with [WithRequireLockedBucket].
func WithRequireCompliance(require bool) Option {
	return func(s *Sink) { s.requireCompliance = require }
}

// WithVerifyVersions controls the single-version check after Put and before
// Get (default true). Turning it off saves one ListObjectVersions call per
// operation, at the price of trusting If-None-Match alone to refuse duplicate
// keys. Keep it on for any store whose conditional-write support has not been
// verified with the write probe. It does not remove the need for
// s3:ListBucketVersions: List and the delete-marker check behind [ErrHidden]
// always read versions.
func WithVerifyVersions(verify bool) Option {
	return func(s *Sink) { s.verifyVersions = verify }
}

// WithProbeKey makes [Sink.Check] and [Sink.Describe] write a small object
// under key (relative to the prefix), read its retention back and attempt a
// versioned delete of it, to observe whether retention refuses the delete.
// Each run leaves one more locked version under the probe key for the
// retention period; pick a key outside the seals/ namespace, such as
// "probe/check".
func WithProbeKey(key string) Option {
	return func(s *Sink) { s.probeKey = key }
}

// New returns a Sink on bucket using client. The client decides endpoint,
// region, credentials and path style; see docs/sinks/s3lock.md for the
// Hetzner and AWS settings.
func New(client *s3.Client, bucket string, opts ...Option) *Sink {
	s := &Sink{
		client:         client,
		bucket:         bucket,
		verifyVersions: true,
		now:            time.Now,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Bucket returns the bucket name.
func (s *Sink) Bucket() string { return s.bucket }

// Prefix returns the normalised key prefix, "" when none.
func (s *Sink) Prefix() string { return s.prefix }

// validKey accepts the keys [seal.Key] and [seal.ProofKey] produce and
// anything shaped like them: non-empty, relative, clean, no "." or ".."
// segments, printable characters only, under the S3 limit of 1024 bytes.
func validKey(key string) error {
	switch {
	case key == "":
		return errors.New("s3lock: empty key")
	case len(key) > 1024:
		return fmt.Errorf("s3lock: key longer than 1024 bytes")
	case strings.HasPrefix(key, "/"), strings.HasSuffix(key, "/"):
		return fmt.Errorf("s3lock: invalid key %q", key)
	case path.Clean(key) != key:
		return fmt.Errorf("s3lock: invalid key %q", key)
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == "." || seg == ".." {
			return fmt.Errorf("s3lock: invalid key %q", key)
		}
	}
	for _, r := range key {
		if !unicode.IsPrint(r) {
			return fmt.Errorf("s3lock: invalid key %q", key)
		}
	}
	return nil
}

func (s *Sink) fullKey(key string) (string, error) {
	if err := validKey(key); err != nil {
		return "", err
	}
	return s.prefix + key, nil
}

func (s *Sink) contentTypeFor(key string) string {
	if s.contentType != "" {
		return s.contentType
	}
	if strings.HasSuffix(key, ".json") {
		return "application/json"
	}
	return "application/octet-stream"
}

// errorCode returns the S3 error code and HTTP status carried by err, either
// of which may be empty when the SDK did not attach them.
func errorCode(err error) (code string, status int) {
	var ae interface{ ErrorCode() string }
	if errors.As(err, &ae) {
		code = ae.ErrorCode()
	}
	var re interface{ HTTPStatusCode() int }
	if errors.As(err, &re) {
		status = re.HTTPStatusCode()
	}
	return code, status
}

func isExists(err error) bool {
	code, status := errorCode(err)
	return status == http.StatusPreconditionFailed || code == "PreconditionFailed" ||
		status == http.StatusConflict || code == "ConditionalRequestConflict"
}

func isNotFound(err error) bool {
	var nsk *types.NoSuchKey
	var nf *types.NotFound
	if errors.As(err, &nsk) || errors.As(err, &nf) {
		return true
	}
	code, status := errorCode(err)
	return status == http.StatusNotFound || code == "NoSuchKey" || code == "NotFound"
}

func isAccessDenied(err error) bool {
	code, status := errorCode(err)
	return status == http.StatusForbidden || code == "AccessDenied"
}

// Put uploads data under key with If-None-Match: * and its SHA-256 checksum,
// requesting per-object retention when [WithRetention] is set. An existing
// key, reported by the store as 412 PreconditionFailed or 409
// ConditionalRequestConflict, fails with [seal.ErrExists]. With version
// verification on, Put then lists the key's versions and fails with
// [ErrMultipleVersions] when more than one exists.
//
// A transport retry whose first attempt reached the store reports ErrExists
// although the data was written; a caller that must know reads the key back
// and compares.
func (s *Sink) Put(ctx context.Context, key string, data []byte) error {
	full, err := s.fullKey(key)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	in := &s3.PutObjectInput{
		Bucket:         aws.String(s.bucket),
		Key:            aws.String(full),
		Body:           bytes.NewReader(data),
		ContentLength:  aws.Int64(int64(len(data))),
		ContentType:    aws.String(s.contentTypeFor(key)),
		IfNoneMatch:    aws.String("*"),
		ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(sum[:])),
	}
	if s.retention != nil {
		in.ObjectLockMode = s.retention.Mode
		in.ObjectLockRetainUntilDate = aws.Time(s.now().Add(s.retention.Duration).UTC())
	}
	if _, err := s.client.PutObject(ctx, in); err != nil {
		if isExists(err) {
			return fmt.Errorf("%w: %s", seal.ErrExists, key)
		}
		return fmt.Errorf("s3lock: put %s: %w", key, err)
	}
	if s.verifyVersions {
		return s.requireSingleVersion(ctx, key, full)
	}
	return nil
}

// Get downloads key. When the store answers NoSuchKey, Get lists the key's
// versions: a key with no version at all fails with [seal.ErrNotFound], a
// key with versions or delete markers fails with [ErrHidden]. With version
// verification on, a readable key holding more than one version or a
// non-current delete marker fails with [ErrMultipleVersions] instead of
// returning the newest.
func (s *Sink) Get(ctx context.Context, key string) ([]byte, error) {
	full, err := s.fullKey(key)
	if err != nil {
		return nil, err
	}
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(full),
	})
	if err != nil {
		if isNotFound(err) {
			return nil, s.missingOrHidden(ctx, key, full)
		}
		return nil, fmt.Errorf("s3lock: get %s: %w", key, err)
	}
	data, err := io.ReadAll(out.Body)
	if cerr := out.Body.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, fmt.Errorf("s3lock: get %s: %w", key, err)
	}
	if s.verifyVersions {
		if err := s.requireSingleVersion(ctx, key, full); err != nil {
			return nil, err
		}
	}
	return data, nil
}

// missingOrHidden decides between [seal.ErrNotFound] and [ErrHidden] for a
// key GetObject could not find.
func (s *Sink) missingOrHidden(ctx context.Context, key, full string) error {
	vs, err := s.versions(ctx, key, full)
	if err != nil {
		return err
	}
	if len(vs) == 0 {
		return fmt.Errorf("%w: %s", seal.ErrNotFound, key)
	}
	markers := 0
	for _, v := range vs {
		if v.DeleteMarker {
			markers++
		}
	}
	return fmt.Errorf("%w: %s has %d delete marker(s) over %d version(s)", ErrHidden, key, markers, len(vs)-markers)
}

// List returns the keys under prefix, relative to the sink's own prefix, in
// lexical order. It pages through ListObjectVersions rather than
// ListObjectsV2 and returns every key that has any version or delete marker,
// so a key hidden behind a delete marker is still listed; Get on such a key
// fails with [ErrHidden].
func (s *Sink) List(ctx context.Context, prefix string) ([]string, error) {
	full := s.prefix + strings.TrimLeft(prefix, "/")
	in := &s3.ListObjectVersionsInput{Bucket: aws.String(s.bucket)}
	if full != "" {
		in.Prefix = aws.String(full)
	}
	seen := map[string]bool{}
	var keys []string
	add := func(k *string) {
		key := aws.ToString(k)
		if !strings.HasPrefix(key, s.prefix) || seen[key] {
			return
		}
		seen[key] = true
		keys = append(keys, strings.TrimPrefix(key, s.prefix))
	}
	p := s3.NewListObjectVersionsPaginator(s.client, in)
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("s3lock: list %s: %w", prefix, err)
		}
		for _, v := range page.Versions {
			add(v.Key)
		}
		for _, d := range page.DeleteMarkers {
			add(d.Key)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

// Version is one object version or delete marker under a key.
type Version struct {
	VersionID    string
	LastModified time.Time
	Size         int64
	ETag         string
	IsLatest     bool
	DeleteMarker bool
}

// Versions returns every version and delete marker under key, the latest
// first and then newest to oldest. A verifier or the CLI uses it to show why
// a key failed with [ErrMultipleVersions] or [ErrHidden]; it needs
// s3:ListBucketVersions.
func (s *Sink) Versions(ctx context.Context, key string) ([]Version, error) {
	full, err := s.fullKey(key)
	if err != nil {
		return nil, err
	}
	return s.versions(ctx, key, full)
}

func (s *Sink) versions(ctx context.Context, key, full string) ([]Version, error) {
	var vs []Version
	p := s3.NewListObjectVersionsPaginator(s.client, &s3.ListObjectVersionsInput{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(full),
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("s3lock: versions of %s: %w", key, err)
		}
		for _, v := range page.Versions {
			if aws.ToString(v.Key) != full {
				continue
			}
			vs = append(vs, Version{
				VersionID:    aws.ToString(v.VersionId),
				LastModified: aws.ToTime(v.LastModified),
				Size:         aws.ToInt64(v.Size),
				ETag:         aws.ToString(v.ETag),
				IsLatest:     aws.ToBool(v.IsLatest),
			})
		}
		for _, d := range page.DeleteMarkers {
			if aws.ToString(d.Key) != full {
				continue
			}
			vs = append(vs, Version{
				VersionID:    aws.ToString(d.VersionId),
				LastModified: aws.ToTime(d.LastModified),
				IsLatest:     aws.ToBool(d.IsLatest),
				DeleteMarker: true,
			})
		}
	}
	sort.SliceStable(vs, func(i, j int) bool {
		if vs[i].IsLatest != vs[j].IsLatest {
			return vs[i].IsLatest
		}
		return vs[i].LastModified.After(vs[j].LastModified)
	})
	return vs, nil
}

func (s *Sink) requireSingleVersion(ctx context.Context, key, full string) error {
	vs, err := s.versions(ctx, key, full)
	if err != nil {
		return err
	}
	if len(vs) > 1 {
		return fmt.Errorf("%w: %s has %d versions", ErrMultipleVersions, key, len(vs))
	}
	return nil
}
