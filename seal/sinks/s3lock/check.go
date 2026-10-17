package s3lock

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// ErrNotLocked is returned by [Sink.Check] when [WithRequireLockedBucket] is
// set and the bucket reports no Object Lock configuration.
var ErrNotLocked = errors.New("s3lock: bucket has no Object Lock")

// ErrNotVersioned is returned by [Sink.Check] when bucket versioning is not
// Enabled. Object Lock requires versioning, and so does the version check
// behind [ErrMultipleVersions].
var ErrNotVersioned = errors.New("s3lock: bucket versioning is not enabled")

// ErrUnprotected is returned by [Sink.Check] when objects written by this
// sink would not be under retention: the bucket has no default retention and
// the sink sends none, or the write probe's version could be deleted.
var ErrUnprotected = errors.New("s3lock: objects are not protected by retention")

// Info is what [Sink.Describe] learned about the bucket.
type Info struct {
	Bucket string
	Prefix string

	// LockEnabled is true when GetObjectLockConfiguration reports
	// ObjectLockEnabled. LockStatus carries the store's reply when it did
	// not, for stores that answer NotImplemented rather than NotFound.
	LockEnabled bool
	LockStatus  string

	// DefaultMode, DefaultDays and DefaultYears are the bucket's default
	// retention; DefaultMode is empty when the bucket has none.
	DefaultMode  types.ObjectLockRetentionMode
	DefaultDays  int32
	DefaultYears int32

	// Versioning is the bucket versioning status, empty when it was never
	// enabled.
	Versioning types.BucketVersioningStatus

	// Retention is the per-object retention this sink sends, nil when it
	// relies on the bucket default.
	Retention *Retention

	// Probe is the result of the write probe, nil without [WithProbeKey].
	Probe *ProbeResult
}

// ProbeResult is the outcome of the write probe: a small object written
// under the probe key, inspected with HeadObject and then deleted by version.
type ProbeResult struct {
	Key       string
	VersionID string

	// Mode and RetainUntil are the lock HeadObject reported on the new
	// version; both are empty when the store did not return them, which
	// also happens when the credential lacks s3:GetObjectRetention.
	Mode        types.ObjectLockMode
	RetainUntil time.Time

	// DeleteDenied is true when the versioned delete was refused with
	// AccessDenied, which is what a retained version must do. Deleted is
	// true when the delete went through. DeleteError holds any other reply.
	DeleteDenied bool
	Deleted      bool
	DeleteError  string
}

// Describe queries the bucket and returns the facts without judging them:
// HeadBucket, GetObjectLockConfiguration, GetBucketVersioning and, with
// [WithProbeKey], the write probe. It fails only when a call fails for a
// reason other than "no lock configuration".
func (s *Sink) Describe(ctx context.Context) (Info, error) {
	info := Info{Bucket: s.bucket, Prefix: s.prefix, Retention: s.retention}

	if _, err := s.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(s.bucket)}); err != nil {
		return info, fmt.Errorf("s3lock: bucket %q: %w", s.bucket, err)
	}

	lock, err := s.client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{Bucket: aws.String(s.bucket)})
	switch {
	case err == nil:
		s.fillLock(&info, lock.ObjectLockConfiguration)
	case isNoLockConfiguration(err):
		code, status := errorCode(err)
		info.LockStatus = fmt.Sprintf("%s (HTTP %d)", code, status)
	default:
		return info, fmt.Errorf("s3lock: object lock configuration of %q: %w", s.bucket, err)
	}

	ver, err := s.client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(s.bucket)})
	if err != nil {
		return info, fmt.Errorf("s3lock: versioning of %q: %w", s.bucket, err)
	}
	info.Versioning = ver.Status

	if s.probeKey != "" {
		info.Probe, err = s.probe(ctx)
		if err != nil {
			return info, err
		}
	}
	return info, nil
}

func (*Sink) fillLock(info *Info, cfg *types.ObjectLockConfiguration) {
	if cfg == nil || cfg.ObjectLockEnabled != types.ObjectLockEnabledEnabled {
		info.LockStatus = "configuration present but ObjectLockEnabled not set"
		return
	}
	info.LockEnabled = true
	if cfg.Rule == nil || cfg.Rule.DefaultRetention == nil {
		return
	}
	dr := cfg.Rule.DefaultRetention
	info.DefaultMode = dr.Mode
	info.DefaultDays = aws.ToInt32(dr.Days)
	info.DefaultYears = aws.ToInt32(dr.Years)
}

// isNoLockConfiguration recognises the replies that mean "this bucket has no
// Object Lock": AWS answers 404 ObjectLockConfigurationNotFoundError; some
// S3-compatible stores answer 501 NotImplemented.
func isNoLockConfiguration(err error) bool {
	code, status := errorCode(err)
	return code == "ObjectLockConfigurationNotFoundError" || code == "NotImplemented" ||
		status == http.StatusNotFound || status == http.StatusNotImplemented
}

// probe writes a tiny object under the probe key and tries to delete that
// version. It does not send If-None-Match, so repeated runs stack versions
// under the probe key; each one stays for the retention period.
func (s *Sink) probe(ctx context.Context) (*ProbeResult, error) {
	full, err := s.fullKey(s.probeKey)
	if err != nil {
		return nil, err
	}
	res := &ProbeResult{Key: s.probeKey}
	body := []byte("tamperlog s3lock probe " + s.now().UTC().Format(time.RFC3339Nano) + "\n")
	in := &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(full),
		Body:          strings.NewReader(string(body)),
		ContentLength: aws.Int64(int64(len(body))),
		ContentType:   aws.String("text/plain"),
	}
	if s.retention != nil {
		in.ObjectLockMode = s.retention.Mode
		in.ObjectLockRetainUntilDate = aws.Time(s.now().Add(s.retention.Duration).UTC())
	}
	put, err := s.client.PutObject(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("s3lock: probe put %s: %w", s.probeKey, err)
	}
	res.VersionID = aws.ToString(put.VersionId)

	head, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket:    aws.String(s.bucket),
		Key:       aws.String(full),
		VersionId: versionIDOrNil(res.VersionID),
	})
	if err == nil {
		res.Mode = head.ObjectLockMode
		res.RetainUntil = aws.ToTime(head.ObjectLockRetainUntilDate)
	}

	_, err = s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket:    aws.String(s.bucket),
		Key:       aws.String(full),
		VersionId: versionIDOrNil(res.VersionID),
	})
	switch {
	case err == nil:
		res.Deleted = true
	case isAccessDenied(err):
		res.DeleteDenied = true
	default:
		res.DeleteError = err.Error()
	}
	return res, nil
}

func versionIDOrNil(id string) *string {
	if id == "" {
		return nil
	}
	return aws.String(id)
}

// Check runs [Sink.Describe] and judges the result for use as evidence
// storage. It returns a joined error naming every problem found: the bucket
// is unreachable; versioning is not Enabled ([ErrNotVersioned]); Object Lock
// is required but absent ([ErrNotLocked]); objects would carry no retention,
// or the probe version could be deleted ([ErrUnprotected]); the probe's
// delete failed for a reason other than AccessDenied. A nil error means the
// bucket is fit for the configuration, with the caveat that without a probe
// the retention mode is read from configuration, not observed.
func (s *Sink) Check(ctx context.Context) error {
	info, err := s.Describe(ctx)
	if err != nil {
		return err
	}
	var problems []error
	if info.Versioning != types.BucketVersioningStatusEnabled {
		problems = append(problems, fmt.Errorf("%w: status %q", ErrNotVersioned, info.Versioning))
	}
	if !info.LockEnabled && s.requireLock {
		problems = append(problems, fmt.Errorf("%w: %s", ErrNotLocked, info.LockStatus))
	}
	if info.LockEnabled && info.DefaultMode == "" && s.retention == nil {
		problems = append(problems, fmt.Errorf("%w: bucket has no default retention and the sink sends none", ErrUnprotected))
	}
	if p := info.Probe; p != nil {
		switch {
		case p.Deleted:
			problems = append(problems, fmt.Errorf("%w: versioned delete of probe %s (version %s) succeeded", ErrUnprotected, p.Key, p.VersionID))
		case p.DeleteError != "":
			problems = append(problems, fmt.Errorf("s3lock: probe %s: delete failed for a reason other than AccessDenied: %s", p.Key, p.DeleteError))
		}
	}
	return errors.Join(problems...)
}
