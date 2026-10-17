//go:build integration

package s3lock

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/kastrul/tamperlog/seal"
)

// TestIntegration runs against a real endpoint when TAMPERLOG_S3_ENDPOINT,
// TAMPERLOG_S3_BUCKET, AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are set,
// for example a Hetzner Object Storage bucket created with Object Lock:
//
//	TAMPERLOG_S3_ENDPOINT=https://fsn1.your-objectstorage.com \
//	TAMPERLOG_S3_BUCKET=tamperlog-it AWS_REGION=fsn1 \
//	AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \
//	go test -tags integration -run TestIntegration -v ./seal/sinks/s3lock/
//
// Optional: TAMPERLOG_S3_PREFIX (key prefix), TAMPERLOG_S3_PROBE_KEY (runs
// the write probe; each run leaves a locked version under that key). Every
// object the test writes uses a unique prefix and stays in the bucket for the
// retention period; that is the point of the bucket.
func TestIntegration(t *testing.T) {
	endpoint := os.Getenv("TAMPERLOG_S3_ENDPOINT")
	bucket := os.Getenv("TAMPERLOG_S3_BUCKET")
	if endpoint == "" || bucket == "" || os.Getenv("AWS_ACCESS_KEY_ID") == "" || os.Getenv("AWS_SECRET_ACCESS_KEY") == "" {
		t.Skip("set TAMPERLOG_S3_ENDPOINT, TAMPERLOG_S3_BUCKET, AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
	})

	opts := []Option{WithPrefix(os.Getenv("TAMPERLOG_S3_PREFIX"))}
	if probe := os.Getenv("TAMPERLOG_S3_PROBE_KEY"); probe != "" {
		opts = append(opts, WithProbeKey(probe))
	}
	s := New(client, bucket, opts...)

	info, err := s.Describe(ctx)
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	t.Logf("bucket %s: lock=%v status=%q default=%s days=%d years=%d versioning=%q",
		info.Bucket, info.LockEnabled, info.LockStatus, info.DefaultMode, info.DefaultDays, info.DefaultYears, info.Versioning)
	if info.Probe != nil {
		t.Logf("probe %s version %s: mode=%s until=%s denied=%v deleted=%v err=%q",
			info.Probe.Key, info.Probe.VersionID, info.Probe.Mode, info.Probe.RetainUntil,
			info.Probe.DeleteDenied, info.Probe.Deleted, info.Probe.DeleteError)
	}
	checked, err := s.Check(ctx)
	t.Logf("Check:\n%s", checked)
	if err != nil {
		t.Errorf("Check: %v", err)
	}

	run := fmt.Sprintf("integration/%s", time.Now().UTC().Format("20060102T150405.000000000Z"))
	key := run + "/" + seal.Key(1)
	data := []byte(`{"integration":"` + run + `"}`)
	if err := s.Put(ctx, key, data); err != nil {
		t.Fatalf("Put: %v", err)
	}
	err = s.Put(ctx, key, []byte(`{"integration":"second writer"}`))
	switch {
	case errors.Is(err, seal.ErrExists):
		t.Log("second Put refused by If-None-Match (ErrExists)")
	case errors.Is(err, ErrMultipleVersions):
		t.Log("store ignored If-None-Match; second version detected (ErrMultipleVersions)")
	default:
		t.Fatalf("second Put = %v, want ErrExists or ErrMultipleVersions", err)
	}

	vs, err := s.Versions(ctx, key)
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	for _, v := range vs {
		t.Logf("version %s latest=%v size=%d etag=%s modified=%s marker=%v", v.VersionID, v.IsLatest, v.Size, v.ETag, v.LastModified, v.DeleteMarker)
	}
	if len(vs) == 1 {
		got, err := s.Get(ctx, key)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("Get = %q, %v", got, err)
		}
	}
	keys, err := s.List(ctx, run+"/")
	if err != nil || len(keys) != 1 || keys[0] != key {
		t.Fatalf("List = %v, %v", keys, err)
	}
}
