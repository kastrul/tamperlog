package s3lock

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/kastrul/tamperlog/seal"
	"github.com/kastrul/tamperlog/seal/sinktest"
)

func newTestSink(t *testing.T, f *fakeS3, opts ...Option) *Sink {
	t.Helper()
	return New(f.start(t), f.bucket, opts...)
}

func TestConformance(t *testing.T) {
	t.Parallel()
	sinktest.Run(t, func(t *testing.T) seal.Sink {
		return newTestSink(t, newFakeS3("tamperlog-test"))
	})
}

func TestConformanceWithPrefix(t *testing.T) {
	t.Parallel()
	sinktest.Run(t, func(t *testing.T) seal.Sink {
		return newTestSink(t, newFakeS3("tamperlog-test"), WithPrefix("/audit/prod"))
	})
}

func TestPutMapsConditionalFailuresToErrExists(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		conflict bool
	}{
		{"412 PreconditionFailed", false},
		{"409 ConditionalRequestConflict", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFakeS3("b")
			f.rejectConditional = tc.conflict
			s := newTestSink(t, f)
			ctx := context.Background()
			if err := s.Put(ctx, seal.Key(1), []byte("one")); err != nil {
				t.Fatal(err)
			}
			err := s.Put(ctx, seal.Key(1), []byte("two"))
			if !errors.Is(err, seal.ErrExists) {
				t.Fatalf("second Put = %v, want ErrExists", err)
			}
			if len(f.objects[seal.Key(1)]) != 1 {
				t.Fatalf("store holds %d versions, want 1", len(f.objects[seal.Key(1)]))
			}
		})
	}
}

func TestPutDetectsSecondVersionWhenStoreIgnoresIfNoneMatch(t *testing.T) {
	t.Parallel()
	f := newFakeS3("b")
	f.ignoreIfNoneMatch = true
	s := newTestSink(t, f)
	ctx := context.Background()
	if err := s.Put(ctx, seal.Key(1), []byte("one")); err != nil {
		t.Fatal(err)
	}
	err := s.Put(ctx, seal.Key(1), []byte("two"))
	if !errors.Is(err, ErrMultipleVersions) {
		t.Fatalf("second Put = %v, want ErrMultipleVersions", err)
	}
	vs, err := s.Versions(ctx, seal.Key(1))
	if err != nil || len(vs) != 2 {
		t.Fatalf("Versions = %v, %v", vs, err)
	}
	if !vs[0].IsLatest || vs[0].Size != 3 || vs[0].ETag == "" || vs[0].VersionID == "" || vs[0].LastModified.IsZero() {
		t.Fatalf("newest version incomplete: %+v", vs[0])
	}
}

func TestGetRefusesMultipleVersions(t *testing.T) {
	t.Parallel()
	f := newFakeS3("b")
	client := f.start(t)
	ctx := context.Background()
	strict := New(client, f.bucket)
	if err := strict.Put(ctx, seal.Key(7), []byte("first")); err != nil {
		t.Fatal(err)
	}
	f.addVersion(seal.Key(7), []byte("second"))

	_, err := strict.Get(ctx, seal.Key(7))
	if !errors.Is(err, ErrMultipleVersions) {
		t.Fatalf("Get = %v, want ErrMultipleVersions", err)
	}
	lax := New(client, f.bucket, WithVerifyVersions(false))
	got, err := lax.Get(ctx, seal.Key(7))
	if err != nil || string(got) != "second" {
		t.Fatalf("Get without verification = %q, %v", got, err)
	}
}

func TestGetRefusesDeleteMarker(t *testing.T) {
	t.Parallel()
	f := newFakeS3("b")
	s := newTestSink(t, f)
	ctx := context.Background()
	if err := s.Put(ctx, seal.Key(1), []byte("x")); err != nil {
		t.Fatal(err)
	}
	f.addDeleteMarker(seal.Key(1)) // what a simple DELETE does on a versioned bucket
	_, err := s.Get(ctx, seal.Key(1))
	if !errors.Is(err, ErrHidden) || errors.Is(err, seal.ErrNotFound) {
		t.Fatalf("Get behind delete marker = %v, want ErrHidden and not ErrNotFound", err)
	}
	if !strings.Contains(err.Error(), "1 delete marker(s) over 1 version(s)") {
		t.Errorf("ErrHidden message = %q", err)
	}
	vs, err := s.Versions(ctx, seal.Key(1))
	if err != nil || len(vs) != 2 || !vs[0].DeleteMarker || vs[1].DeleteMarker {
		t.Fatalf("Versions = %+v, %v; want one marker then one version", vs, err)
	}
	if _, err := s.Get(ctx, seal.Key(2)); !errors.Is(err, seal.ErrNotFound) {
		t.Fatalf("Get of a key with no versions = %v, want ErrNotFound", err)
	}
}

func TestListIncludesKeysHiddenByDeleteMarkers(t *testing.T) {
	t.Parallel()
	f := newFakeS3("b")
	s := newTestSink(t, f, WithPrefix("audit"))
	ctx := context.Background()
	for seq := int64(1); seq <= 4; seq++ {
		if err := s.Put(ctx, seal.Key(seq), []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	// An administrator rolling the database back to seal 2 hides 3 and 4.
	f.addDeleteMarker("audit/" + seal.Key(3))
	f.addDeleteMarker("audit/" + seal.Key(4))
	// A key that only ever received a delete marker is listed too.
	f.addDeleteMarker("audit/" + seal.Key(5))

	keys, err := s.List(ctx, "seals/")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{seal.Key(1), seal.Key(2), seal.Key(3), seal.Key(4), seal.Key(5)}
	if fmt.Sprint(keys) != fmt.Sprint(want) {
		t.Fatalf("List = %v, want %v", keys, want)
	}
	for _, seq := range []int64{3, 4, 5} {
		if _, err := s.Get(ctx, seal.Key(seq)); !errors.Is(err, ErrHidden) {
			t.Errorf("Get(%s) = %v, want ErrHidden", seal.Key(seq), err)
		}
	}
	if got, err := s.Get(ctx, seal.Key(2)); err != nil || string(got) != "x" {
		t.Errorf("Get of an untouched key = %q, %v", got, err)
	}
	// The lax sink still reports hidden keys: the check does not depend on
	// WithVerifyVersions.
	lax := New(f.start(t), f.bucket, WithPrefix("audit"), WithVerifyVersions(false))
	if _, err := lax.Get(ctx, seal.Key(3)); !errors.Is(err, ErrHidden) {
		t.Errorf("lax Get(hidden) = %v, want ErrHidden", err)
	}
}

func TestListPaginatesOverManyVersions(t *testing.T) {
	t.Parallel()
	f := newFakeS3("b")
	f.versionPageSize = 7 // force many pages with few keys
	const keys, versions = 5, 30
	for i := 1; i <= keys; i++ {
		for v := 0; v < versions; v++ {
			f.addVersion(seal.Key(int64(i)), []byte("v"))
		}
		if i%2 == 0 {
			f.addDeleteMarker(seal.Key(int64(i)))
		}
	}
	f.addVersion("other/x", []byte("outside"))
	s := newTestSink(t, f)
	got, err := s.List(context.Background(), "seals/")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != keys {
		t.Fatalf("List returned %d keys, want %d: %v", len(got), keys, got)
	}
	for i, k := range got {
		if want := seal.Key(int64(i + 1)); k != want {
			t.Fatalf("keys[%d] = %q, want %q", i, k, want)
		}
	}
	vs, err := s.Versions(context.Background(), seal.Key(2))
	if err != nil || len(vs) != versions+1 || !vs[0].DeleteMarker {
		t.Fatalf("Versions across pages = %d, %v; want %d with a marker first", len(vs), err, versions+1)
	}
}

func TestPutSendsChecksumAndContentType(t *testing.T) {
	t.Parallel()
	f := newFakeS3("b")
	s := newTestSink(t, f)
	ctx := context.Background()
	data := []byte(`{"schema":"tamperlog.seal/1"}`)
	if err := s.Put(ctx, seal.Key(1), data); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, seal.ProofKey(1, "rfc3161"), []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if got, want := f.puts[0].Get("x-amz-checksum-sha256"), base64.StdEncoding.EncodeToString(sum[:]); got != want {
		t.Errorf("checksum header = %q, want %q", got, want)
	}
	if got := f.puts[0].Get("If-None-Match"); got != "*" {
		t.Errorf("If-None-Match = %q, want *", got)
	}
	if got := f.puts[0].Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type for .json = %q", got)
	}
	if got := f.puts[1].Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("Content-Type for .proof = %q", got)
	}
	for _, h := range []string{"x-amz-object-lock-mode", "x-amz-object-lock-retain-until-date"} {
		if got := f.puts[0].Get(h); got != "" {
			t.Errorf("%s sent without WithRetention: %q", h, got)
		}
	}

	fixed := newFakeS3("b")
	custom := newTestSink(t, fixed, WithContentType("text/plain"))
	if err := custom.Put(ctx, seal.Key(1), data); err != nil {
		t.Fatal(err)
	}
	if got := fixed.puts[0].Get("Content-Type"); got != "text/plain" {
		t.Errorf("WithContentType ignored: %q", got)
	}
}

func TestPutSendsRetentionWhenConfigured(t *testing.T) {
	t.Parallel()
	f := newFakeS3("b")
	s := newTestSink(t, f, WithRetention(types.ObjectLockModeCompliance, 48*time.Hour))
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	if err := s.Put(context.Background(), seal.Key(1), []byte("x")); err != nil {
		t.Fatal(err)
	}
	h := f.puts[0]
	if got := h.Get("x-amz-object-lock-mode"); got != "COMPLIANCE" {
		t.Errorf("mode header = %q", got)
	}
	until, err := time.Parse(time.RFC3339, h.Get("x-amz-object-lock-retain-until-date"))
	if err != nil || !until.Equal(now.Add(48*time.Hour)) {
		t.Errorf("retain-until header = %q, %v; want %s", h.Get("x-amz-object-lock-retain-until-date"), err, now.Add(48*time.Hour))
	}
	v := f.latest(seal.Key(1))
	if v.lockMode != "COMPLIANCE" || !v.retainUntil.Equal(until) {
		t.Errorf("stored lock = %s until %s", v.lockMode, v.retainUntil)
	}
}

func TestListPaginatesAndStripsPrefix(t *testing.T) {
	t.Parallel()
	f := newFakeS3("b")
	const n = 2345
	for i := 1; i <= n; i++ {
		f.addVersion("tenant/a/"+seal.Key(int64(i)), []byte("s"))
	}
	f.addVersion("tenant/b/"+seal.Key(1), []byte("other prefix"))
	f.addVersion("tenant/a/manifest.json", []byte("outside seals/"))
	s := newTestSink(t, f, WithPrefix("tenant/a"))
	keys, err := s.List(context.Background(), "seals/")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != n {
		t.Fatalf("List returned %d keys, want %d", len(keys), n)
	}
	for i, k := range keys {
		if want := seal.Key(int64(i + 1)); k != want {
			t.Fatalf("keys[%d] = %q, want %q", i, k, want)
		}
	}
	all, err := s.List(context.Background(), "")
	if err != nil || len(all) != n+1 || all[0] != "manifest.json" {
		t.Fatalf("List(\"\") = %d keys, %v; want %d starting with manifest.json", len(all), err, n+1)
	}
}

func TestDescribeAndCheck(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("locked bucket passes with probe", func(t *testing.T) {
		t.Parallel()
		f := newFakeS3("b")
		s := newTestSink(t, f, WithRequireLockedBucket(true), WithProbeKey("probe/check"))
		info, err := s.Describe(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !info.LockEnabled || info.DefaultMode != types.ObjectLockRetentionModeCompliance || info.DefaultDays != 30 {
			t.Errorf("lock facts = %+v", info)
		}
		if info.Versioning != types.BucketVersioningStatusEnabled {
			t.Errorf("versioning = %q", info.Versioning)
		}
		p := info.Probe
		if p == nil || !p.DeleteDenied || p.Deleted || p.DeleteError != "" {
			t.Fatalf("probe = %+v", p)
		}
		if p.Mode != types.ObjectLockModeCompliance || p.RetainUntil.IsZero() || p.VersionID == "" {
			t.Errorf("probe lock facts = %+v", p)
		}
		if !p.Conclusive || p.Reason != "" {
			t.Errorf("probe not conclusive: %+v", p)
		}
		checked, err := s.Check(ctx)
		if err != nil {
			t.Errorf("Check = %v", err)
		}
		if len(checked.Problems) != 0 || !checked.Adequate() || checked.EffectiveMode != types.ObjectLockModeCompliance {
			t.Errorf("Check info = %+v", checked)
		}
		if _, ok := f.objects["probe/check"]; !ok {
			t.Error("probe object was removed")
		}
	})

	t.Run("bucket without lock", func(t *testing.T) {
		t.Parallel()
		f := newFakeS3("b")
		f.lockEnabled = false
		f.defaultMode = ""
		info, err := newTestSink(t, f).Describe(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if info.LockEnabled || info.DefaultMode != "" || !strings.Contains(info.LockStatus, "ObjectLockConfigurationNotFoundError") {
			t.Errorf("Describe = %+v", info)
		}
		checked, err := newTestSink(t, f).Check(ctx)
		if err != nil {
			t.Errorf("Check without requirement = %v, want nil", err)
		}
		if checked.Adequate() || !strings.Contains(checked.String(), "NOT adequate") {
			t.Errorf("unlocked bucket judged adequate:\n%s", checked)
		}
		checked, err = newTestSink(t, f, WithRequireLockedBucket(true)).Check(ctx)
		if !errors.Is(err, ErrNotLocked) || len(checked.Problems) != 1 {
			t.Errorf("Check with requirement = %v, %v, want ErrNotLocked", err, checked.Problems)
		}
		_, err = newTestSink(t, f, WithProbeKey("probe/check")).Check(ctx)
		if !errors.Is(err, ErrUnprotected) {
			t.Errorf("Check with probe = %v, want ErrUnprotected", err)
		}
	})

	t.Run("lock without default retention", func(t *testing.T) {
		t.Parallel()
		f := newFakeS3("b")
		f.defaultMode = ""
		if _, err := newTestSink(t, f).Check(ctx); !errors.Is(err, ErrUnprotected) {
			t.Errorf("Check = %v, want ErrUnprotected", err)
		}
		s := newTestSink(t, f, WithRetention(types.ObjectLockModeGovernance, time.Hour), WithProbeKey("probe/check"))
		checked, err := s.Check(ctx)
		if err != nil {
			t.Errorf("Check with per-object retention = %v", err)
		}
		if checked.EffectiveMode != types.ObjectLockModeGovernance || checked.Adequate() {
			t.Errorf("GOVERNANCE judged adequate: %+v", checked)
		}
	})

	t.Run("versioning suspended", func(t *testing.T) {
		t.Parallel()
		f := newFakeS3("b")
		f.versioning = "Suspended"
		_, err := newTestSink(t, f).Check(ctx)
		if !errors.Is(err, ErrNotVersioned) || !strings.Contains(err.Error(), "Suspended") {
			t.Errorf("Check = %v, want ErrNotVersioned", err)
		}
	})

	t.Run("missing bucket", func(t *testing.T) {
		t.Parallel()
		f := newFakeS3("b")
		s := New(f.start(t), "other")
		if _, err := s.Describe(ctx); err == nil {
			t.Error("Describe of a missing bucket succeeded")
		}
	})
}

func TestKeyValidation(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{"", "/abs", "../up", "seals/../x", "a/./b", "a//b", "trailing/", "tab\tkey", strings.Repeat("k", 1025)} {
		if err := validKey(bad); err == nil {
			t.Errorf("validKey(%q) accepted", bad)
		}
	}
	for _, good := range []string{seal.Key(1), seal.ProofKey(1, "rfc3161"), "a", "a/b c/d.e", "x..y"} {
		if err := validKey(good); err != nil {
			t.Errorf("validKey(%q) = %v", good, err)
		}
	}
}

func TestExampleRoundTrip(t *testing.T) {
	t.Parallel()
	s := newTestSink(t, newFakeS3("b"), WithPrefix("audit"))
	ctx := context.Background()
	var want bytes.Buffer
	for seq := int64(1); seq <= 3; seq++ {
		fmt.Fprintf(&want, "%d", seq)
		if err := s.Put(ctx, seal.Key(seq), want.Bytes()); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Get(ctx, seal.Key(3))
	if err != nil || !bytes.Equal(got, []byte("123")) {
		t.Fatalf("Get = %q, %v", got, err)
	}
}

func TestProbeInconclusive(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		setup  func(*fakeS3)
		opts   []Option
		reason string
	}{
		{
			name:   "IAM denies the delete on an unretained version",
			setup:  func(f *fakeS3) { f.lockEnabled, f.defaultMode, f.denyDeletes = false, "", true },
			reason: "no retention on the version",
		},
		{
			name:   "PutObject returns no version id",
			setup:  func(f *fakeS3) { f.omitVersionIDs = true },
			reason: "no version id",
		},
		{
			name:   "HeadObject hides retention",
			setup:  func(f *fakeS3) { f.hideRetention = true },
			reason: "no retention on the version",
		},
		{
			name:   "retain-until already passed",
			setup:  func(f *fakeS3) { f.defaultMode, f.denyDeletes = "", true },
			opts:   []Option{WithRetention(types.ObjectLockModeCompliance, -time.Hour)},
			reason: "not in the future",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFakeS3("b")
			tc.setup(f)
			s := newTestSink(t, f, append(tc.opts, WithProbeKey("probe/check"))...)
			info, err := s.Check(ctx)
			if !errors.Is(err, ErrProbeInconclusive) {
				t.Fatalf("Check = %v, want ErrProbeInconclusive", err)
			}
			p := info.Probe
			if p == nil || p.Conclusive || p.Deleted || !strings.Contains(p.Reason, tc.reason) {
				t.Fatalf("probe = %+v, want inconclusive with reason containing %q", p, tc.reason)
			}
			if info.Adequate() || !strings.Contains(info.String(), "inconclusive") {
				t.Errorf("info judged adequate:\n%s", info)
			}
		})
	}

	t.Run("version id missing skips the delete", func(t *testing.T) {
		t.Parallel()
		f := newFakeS3("b")
		f.omitVersionIDs = true
		info, _ := newTestSink(t, f, WithProbeKey("probe/check")).Check(ctx)
		p := info.Probe
		if p.DeleteDenied || p.Deleted || p.DeleteError != "" || p.VersionID != "" {
			t.Fatalf("probe = %+v, want no delete attempted", p)
		}
		if vs := f.objects["probe/check"]; len(vs) != 1 || vs[0].deleteMarker {
			t.Fatalf("probe key versions = %d, want the single put version and no marker", len(vs))
		}
	})
}

func TestCheckRequireCompliance(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("bucket default GOVERNANCE", func(t *testing.T) {
		t.Parallel()
		f := newFakeS3("b")
		f.defaultMode = "GOVERNANCE"
		info, err := newTestSink(t, f, WithRequireCompliance(true), WithProbeKey("probe/check")).Check(ctx)
		if !errors.Is(err, ErrNotCompliance) || !strings.Contains(err.Error(), "probe observed GOVERNANCE") {
			t.Fatalf("Check = %v, want ErrNotCompliance from the probe", err)
		}
		if info.EffectiveMode != types.ObjectLockModeGovernance || info.Adequate() {
			t.Errorf("info = %+v", info)
		}
		if _, err := newTestSink(t, f).Check(ctx); err != nil {
			t.Errorf("Check without the requirement = %v, want nil", err)
		}
		_, err = newTestSink(t, f, WithRequireCompliance(true)).Check(ctx)
		if !errors.Is(err, ErrNotCompliance) || !strings.Contains(err.Error(), "bucket default mode is GOVERNANCE") {
			t.Errorf("Check without probe = %v, want ErrNotCompliance from the bucket default", err)
		}
	})

	t.Run("per-object GOVERNANCE on an unretained bucket", func(t *testing.T) {
		t.Parallel()
		f := newFakeS3("b")
		f.defaultMode = ""
		_, err := newTestSink(t, f, WithRequireCompliance(true), WithRetention(types.ObjectLockModeGovernance, time.Hour)).Check(ctx)
		if !errors.Is(err, ErrNotCompliance) || !strings.Contains(err.Error(), "WithRetention mode is GOVERNANCE") {
			t.Fatalf("Check = %v, want ErrNotCompliance", err)
		}
		info, err := newTestSink(t, f, WithRequireCompliance(true), WithRetention(types.ObjectLockModeCompliance, time.Hour), WithProbeKey("probe/check")).Check(ctx)
		if err != nil || !info.Adequate() {
			t.Fatalf("Check with COMPLIANCE = %v, adequate %v", err, info.Adequate())
		}
	})

	t.Run("no retention at all", func(t *testing.T) {
		t.Parallel()
		f := newFakeS3("b")
		f.lockEnabled, f.defaultMode = false, ""
		_, err := newTestSink(t, f, WithRequireCompliance(true)).Check(ctx)
		if !errors.Is(err, ErrNotCompliance) || !strings.Contains(err.Error(), "no retention mode applies") {
			t.Fatalf("Check = %v, want ErrNotCompliance", err)
		}
	})
}

func TestCheckWeakRetention(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const day = 24 * time.Hour
	for _, tc := range []struct {
		name string
		mode types.ObjectLockMode
		d    time.Duration
		want bool // ErrWeakRetention expected
	}{
		{"shorter than the 30 day default", types.ObjectLockModeCompliance, 10 * day, true},
		{"GOVERNANCE on a COMPLIANCE default", types.ObjectLockModeGovernance, 60 * day, true},
		{"zero duration", types.ObjectLockModeCompliance, 0, true},
		{"unknown mode", types.ObjectLockMode("LEGAL"), 60 * day, true},
		{"equal to the default", types.ObjectLockModeCompliance, 30 * day, false},
		{"longer than the default", types.ObjectLockModeCompliance, 60 * day, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFakeS3("b")
			info, err := newTestSink(t, f, WithRetention(tc.mode, tc.d)).Check(ctx)
			if got := errors.Is(err, ErrWeakRetention); got != tc.want {
				t.Fatalf("Check = %v, want ErrWeakRetention %v", err, tc.want)
			}
			if tc.want && len(info.Problems) != 1 {
				t.Errorf("Problems = %v, want one", info.Problems)
			}
		})
	}

	t.Run("default in years", func(t *testing.T) {
		t.Parallel()
		info := Info{DefaultYears: 10}
		if got := info.DefaultRetention(); got != 3650*day {
			t.Errorf("DefaultRetention = %s, want 3650 days", got)
		}
	})

	t.Run("no bucket default", func(t *testing.T) {
		t.Parallel()
		f := newFakeS3("b")
		f.defaultMode = ""
		if _, err := newTestSink(t, f, WithRetention(types.ObjectLockModeGovernance, time.Hour)).Check(ctx); err != nil {
			t.Errorf("Check = %v, want nil when nothing is weakened", err)
		}
	})
}

func TestInfoString(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFakeS3("b")
	info, err := newTestSink(t, f, WithPrefix("prod"), WithProbeKey("probe/check")).Check(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := info.String()
	for _, want := range []string{
		"bucket b prefix prod/",
		"object lock: enabled, default retention COMPLIANCE for 30 days",
		"versioning: Enabled",
		"per-object retention: none, bucket default applies",
		"effective mode: COMPLIANCE",
		"probe: probe/check version v0001: COMPLIANCE until ",
		"versioned delete refused (conclusive)",
		"verdict: adequate for the administrator threat model",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("String() lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "problem:") {
		t.Errorf("String() lists problems after a clean Check:\n%s", got)
	}

	g := newFakeS3("b")
	g.defaultMode, g.versioning = "GOVERNANCE", "Suspended"
	info, err = newTestSink(t, g, WithRetention(types.ObjectLockModeGovernance, 48*time.Hour)).Check(ctx)
	if !errors.Is(err, ErrNotVersioned) {
		t.Fatalf("Check = %v", err)
	}
	got = info.String()
	for _, want := range []string{
		"versioning: Suspended",
		"per-object retention: GOVERNANCE for 2 days",
		"probe: not run (mode read from configuration, not observed)",
		"verdict: NOT adequate for the administrator threat model: Check found problems",
		"problem: s3lock: bucket versioning is not enabled: status \"Suspended\"",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("String() lacks %q:\n%s", want, got)
		}
	}

	plain := Info{Bucket: "b", LockEnabled: true, Versioning: types.BucketVersioningStatusEnabled, DefaultMode: types.ObjectLockRetentionModeGovernance, EffectiveMode: types.ObjectLockModeGovernance}
	if plain.Adequate() || !strings.Contains(plain.String(), "GOVERNANCE is removable with s3:BypassGovernanceRetention") {
		t.Errorf("GOVERNANCE verdict:\n%s", plain)
	}
}
