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
	if _, err := s.Get(ctx, seal.Key(1)); !errors.Is(err, seal.ErrNotFound) {
		t.Fatalf("Get behind delete marker = %v, want ErrNotFound", err)
	}
	vs, err := s.Versions(ctx, seal.Key(1))
	if err != nil || len(vs) != 2 || !vs[0].DeleteMarker || vs[1].DeleteMarker {
		t.Fatalf("Versions = %+v, %v; want one marker then one version", vs, err)
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
		if err := s.Check(ctx); err != nil {
			t.Errorf("Check = %v", err)
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
		if err := newTestSink(t, f).Check(ctx); err != nil {
			t.Errorf("Check without requirement = %v, want nil", err)
		}
		err = newTestSink(t, f, WithRequireLockedBucket(true)).Check(ctx)
		if !errors.Is(err, ErrNotLocked) {
			t.Errorf("Check with requirement = %v, want ErrNotLocked", err)
		}
		err = newTestSink(t, f, WithProbeKey("probe/check")).Check(ctx)
		if !errors.Is(err, ErrUnprotected) {
			t.Errorf("Check with probe = %v, want ErrUnprotected", err)
		}
	})

	t.Run("lock without default retention", func(t *testing.T) {
		t.Parallel()
		f := newFakeS3("b")
		f.defaultMode = ""
		if err := newTestSink(t, f).Check(ctx); !errors.Is(err, ErrUnprotected) {
			t.Errorf("Check = %v, want ErrUnprotected", err)
		}
		s := newTestSink(t, f, WithRetention(types.ObjectLockModeGovernance, time.Hour), WithProbeKey("probe/check"))
		if err := s.Check(ctx); err != nil {
			t.Errorf("Check with per-object retention = %v", err)
		}
	})

	t.Run("versioning suspended", func(t *testing.T) {
		t.Parallel()
		f := newFakeS3("b")
		f.versioning = "Suspended"
		err := newTestSink(t, f).Check(ctx)
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
