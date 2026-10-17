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

// ErrNotCompliance is returned by [Sink.Check] when [WithRequireCompliance]
// is set and the retention mode objects will carry is not COMPLIANCE.
// GOVERNANCE is bypassable by anyone holding s3:BypassGovernanceRetention.
var ErrNotCompliance = errors.New("s3lock: retention mode is not COMPLIANCE")

// ErrWeakRetention is returned by [Sink.Check] when the [WithRetention]
// setting would weaken what the bucket default gives: a duration that is not
// positive or shorter than the default, or GOVERNANCE mode on a bucket whose
// default is COMPLIANCE. An explicit per-object retention replaces the
// default, it does not extend it.
var ErrWeakRetention = errors.New("s3lock: per-object retention is weaker than the bucket default")

// ErrProbeInconclusive is returned by [Sink.Check] when the write probe ran
// but did not demonstrate retention: see [ProbeResult.Conclusive].
var ErrProbeInconclusive = errors.New("s3lock: write probe is inconclusive")

// Info is what [Sink.Describe] learned about the bucket and, after
// [Sink.Check], what it concluded. [Info.String] renders it for an operator.
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

	// EffectiveMode is the retention mode objects written by this sink
	// carry: the mode the probe observed when it reported one, otherwise the
	// [WithRetention] mode, otherwise the bucket default. Empty when none
	// applies.
	EffectiveMode types.ObjectLockMode

	// Probe is the result of the write probe, nil without [WithProbeKey].
	Probe *ProbeResult

	// Problems lists what [Sink.Check] found wrong, one entry per error in
	// the joined error it returns. Empty after Describe and after a Check
	// that passed.
	Problems []string
}

// ProbeResult is the outcome of the write probe: a small object written
// under the probe key, inspected with HeadObject and then deleted by version.
type ProbeResult struct {
	Key       string
	VersionID string

	// Mode and RetainUntil are the lock HeadObject reported on the new
	// version; both are empty when the store did not return them, which
	// also happens when the credential lacks s3:GetObjectRetention.
	// HeadError holds a failed HeadObject.
	Mode        types.ObjectLockMode
	RetainUntil time.Time
	HeadError   string

	// DeleteDenied is true when the versioned delete was refused with
	// AccessDenied. Deleted is true when the delete went through.
	// DeleteError holds any other reply. All three are false and empty when
	// the delete was not attempted because PutObject returned no version
	// id: an unversioned delete would only add a delete marker.
	DeleteDenied bool
	Deleted      bool
	DeleteError  string

	// Conclusive is true only when PutObject returned a version id,
	// HeadObject on that version reported a lock mode with a retain-until
	// date in the future, and the versioned delete was refused with
	// AccessDenied. An AccessDenied alone proves nothing: IAM denies deletes
	// too. Reason says which condition failed.
	Conclusive bool
	Reason     string
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

	switch {
	case info.Probe != nil && info.Probe.Mode != "":
		info.EffectiveMode = info.Probe.Mode
	case s.retention != nil:
		info.EffectiveMode = s.retention.Mode
	case info.DefaultMode != "":
		info.EffectiveMode = types.ObjectLockMode(info.DefaultMode)
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

// probe writes a tiny object under the probe key, reads its retention back
// and tries to delete that version. It does not send If-None-Match, so
// repeated runs stack versions under the probe key; each one stays for the
// retention period.
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
	if err != nil {
		res.HeadError = err.Error()
	} else {
		res.Mode = head.ObjectLockMode
		res.RetainUntil = aws.ToTime(head.ObjectLockRetainUntilDate)
	}

	if res.VersionID != "" {
		_, err = s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket:    aws.String(s.bucket),
			Key:       aws.String(full),
			VersionId: aws.String(res.VersionID),
		})
		switch {
		case err == nil:
			res.Deleted = true
		case isAccessDenied(err):
			res.DeleteDenied = true
		default:
			res.DeleteError = err.Error()
		}
	}
	res.judge(s.now())
	return res, nil
}

// judge sets Conclusive and Reason from the observations.
func (p *ProbeResult) judge(now time.Time) {
	switch {
	case p.VersionID == "":
		p.Reason = "PutObject returned no version id, so the delete was not attempted; versioning is off or the store does not report version ids"
	case p.Deleted:
		p.Reason = "versioned delete succeeded"
	case p.DeleteError != "":
		p.Reason = "delete failed for a reason other than AccessDenied: " + p.DeleteError
	case p.HeadError != "":
		p.Reason = "HeadObject failed, so the version's retention is unknown and the AccessDenied may come from IAM alone: " + p.HeadError
	case p.Mode == "":
		p.Reason = "HeadObject reported no retention on the version (credential lacks s3:GetObjectRetention, or the version is not retained), so the AccessDenied may come from IAM alone"
	case !p.RetainUntil.After(now):
		p.Reason = fmt.Sprintf("retain-until %s is not in the future, so the AccessDenied comes from IAM, not retention", p.RetainUntil.UTC().Format(time.RFC3339))
	case !p.DeleteDenied:
		p.Reason = "delete outcome unknown"
	default:
		p.Conclusive = true
	}
}

func versionIDOrNil(id string) *string {
	if id == "" {
		return nil
	}
	return aws.String(id)
}

// Check runs [Sink.Describe] and judges the result for use as evidence
// storage. It returns the Info with [Info.Problems] filled and a joined
// error naming every problem found: the bucket is unreachable; versioning is
// not Enabled ([ErrNotVersioned]); Object Lock is required but absent
// ([ErrNotLocked]); objects would carry no retention, or the probe version
// could be deleted ([ErrUnprotected]); the [WithRetention] setting is weaker
// than the bucket default ([ErrWeakRetention]); COMPLIANCE is required but
// the effective mode is something else ([ErrNotCompliance]); the probe ran
// but did not demonstrate retention ([ErrProbeInconclusive]). A nil error
// means the bucket is fit for the configuration; whether the configuration
// itself meets the administrator threat model is [Info.Adequate].
func (s *Sink) Check(ctx context.Context) (Info, error) {
	info, err := s.Describe(ctx)
	if err != nil {
		return info, err
	}
	var problems []error
	add := func(e error) {
		problems = append(problems, e)
		info.Problems = append(info.Problems, e.Error())
	}
	if info.Versioning != types.BucketVersioningStatusEnabled {
		add(fmt.Errorf("%w: status %q", ErrNotVersioned, info.Versioning))
	}
	if !info.LockEnabled && s.requireLock {
		add(fmt.Errorf("%w: %s", ErrNotLocked, info.LockStatus))
	}
	if info.LockEnabled && info.DefaultMode == "" && s.retention == nil {
		add(fmt.Errorf("%w: bucket has no default retention and the sink sends none", ErrUnprotected))
	}
	if s.retention != nil {
		if err := s.checkRetention(info); err != nil {
			add(err)
		}
	}
	if s.requireCompliance && info.EffectiveMode != types.ObjectLockModeCompliance {
		add(fmt.Errorf("%w: %s", ErrNotCompliance, s.modeSource(info)))
	}
	if p := info.Probe; p != nil {
		switch {
		case p.Deleted:
			add(fmt.Errorf("%w: versioned delete of probe %s (version %s) succeeded", ErrUnprotected, p.Key, p.VersionID))
		case !p.Conclusive:
			add(fmt.Errorf("%w: probe %s: %s", ErrProbeInconclusive, p.Key, p.Reason))
		}
	}
	return info, errors.Join(problems...)
}

// checkRetention compares the configured per-object retention with the
// bucket default.
func (s *Sink) checkRetention(info Info) error {
	r := s.retention
	switch r.Mode {
	case types.ObjectLockModeCompliance, types.ObjectLockModeGovernance:
	default:
		return fmt.Errorf("%w: unknown mode %q", ErrWeakRetention, r.Mode)
	}
	if r.Duration <= 0 {
		return fmt.Errorf("%w: duration %s is not positive", ErrWeakRetention, r.Duration)
	}
	if info.DefaultMode == "" {
		return nil
	}
	if r.Mode == types.ObjectLockModeGovernance && info.DefaultMode == types.ObjectLockRetentionModeCompliance {
		return fmt.Errorf("%w: GOVERNANCE on a bucket whose default is COMPLIANCE", ErrWeakRetention)
	}
	if d := info.DefaultRetention(); r.Duration < d {
		return fmt.Errorf("%w: %s is shorter than the bucket default %s", ErrWeakRetention, formatDuration(r.Duration), formatDuration(d))
	}
	return nil
}

// modeSource names where the effective mode comes from, for error messages.
func (s *Sink) modeSource(info Info) string {
	switch {
	case info.Probe != nil && info.Probe.Mode != "":
		return fmt.Sprintf("probe observed %s", info.Probe.Mode)
	case s.retention != nil:
		return fmt.Sprintf("WithRetention mode is %s", s.retention.Mode)
	case info.DefaultMode != "":
		return fmt.Sprintf("bucket default mode is %s", info.DefaultMode)
	default:
		return "no retention mode applies"
	}
}

// DefaultRetention returns the bucket's default retention as a duration,
// counting a year as 365 days the way S3 does, or 0 when the bucket has no
// default.
func (i Info) DefaultRetention() time.Duration {
	return time.Duration(i.DefaultDays)*24*time.Hour + time.Duration(i.DefaultYears)*365*24*time.Hour
}

// Adequate reports whether the facts meet the administrator threat model:
// Check found no problems, Object Lock is enabled, versioning is Enabled, the
// effective retention mode is COMPLIANCE and, when a probe ran, it was
// conclusive. Without a probe the mode is read from configuration, not
// observed; String says so.
func (i Info) Adequate() bool { return i.inadequacy() == "" }

func (i Info) inadequacy() string {
	switch {
	case len(i.Problems) > 0:
		return "Check found problems"
	case !i.LockEnabled:
		return "Object Lock is not enabled"
	case i.Versioning != types.BucketVersioningStatusEnabled:
		return "versioning is not Enabled"
	case i.EffectiveMode == "":
		return "objects carry no retention"
	case i.EffectiveMode != types.ObjectLockModeCompliance:
		return fmt.Sprintf("retention mode is %s; only COMPLIANCE holds against administrators, GOVERNANCE is removable with s3:BypassGovernanceRetention", i.EffectiveMode)
	case i.Probe != nil && !i.Probe.Conclusive:
		return "write probe is inconclusive: " + i.Probe.Reason
	default:
		return ""
	}
}

// String summarises the bucket for an operator: lock mode and default
// retention, versioning, the per-object retention, the effective mode, the
// probe result and whether the configuration is adequate for the
// administrator threat model, followed by the problems Check found.
func (i Info) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "bucket %s", i.Bucket)
	if i.Prefix != "" {
		fmt.Fprintf(&b, " prefix %s", i.Prefix)
	}
	b.WriteString("\nobject lock: ")
	switch {
	case !i.LockEnabled:
		fmt.Fprintf(&b, "not enabled (%s)", i.LockStatus)
	case i.DefaultMode == "":
		b.WriteString("enabled, no default retention")
	default:
		fmt.Fprintf(&b, "enabled, default retention %s for %s", i.DefaultMode, formatDuration(i.DefaultRetention()))
	}
	if i.Versioning == "" {
		b.WriteString("\nversioning: never enabled")
	} else {
		fmt.Fprintf(&b, "\nversioning: %s", i.Versioning)
	}
	if i.Retention == nil {
		b.WriteString("\nper-object retention: none, bucket default applies")
	} else {
		fmt.Fprintf(&b, "\nper-object retention: %s for %s", i.Retention.Mode, formatDuration(i.Retention.Duration))
	}
	if i.EffectiveMode == "" {
		b.WriteString("\neffective mode: none")
	} else {
		fmt.Fprintf(&b, "\neffective mode: %s", i.EffectiveMode)
	}
	b.WriteString("\nprobe: ")
	switch p := i.Probe; {
	case p == nil:
		b.WriteString("not run (mode read from configuration, not observed)")
	case p.Conclusive:
		fmt.Fprintf(&b, "%s version %s: %s until %s, versioned delete refused (conclusive)", p.Key, p.VersionID, p.Mode, p.RetainUntil.UTC().Format(time.RFC3339))
	default:
		fmt.Fprintf(&b, "%s version %q: inconclusive, %s", p.Key, p.VersionID, p.Reason)
	}
	if why := i.inadequacy(); why == "" {
		b.WriteString("\nverdict: adequate for the administrator threat model")
	} else {
		fmt.Fprintf(&b, "\nverdict: NOT adequate for the administrator threat model: %s", why)
	}
	for _, p := range i.Problems {
		fmt.Fprintf(&b, "\nproblem: %s", p)
	}
	return b.String()
}

// formatDuration prints whole days as days and everything else as Go does.
func formatDuration(d time.Duration) string {
	const day = 24 * time.Hour
	if d > 0 && d%day == 0 {
		return fmt.Sprintf("%d days", d/day)
	}
	return d.String()
}
