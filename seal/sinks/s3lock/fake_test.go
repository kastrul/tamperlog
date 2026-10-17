package s3lock

import (
	"crypto/md5" //nolint:gosec // ETag format only
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// fakeS3 is the smallest S3 that the sink exercises: path-style requests on
// one bucket, versioned objects, If-None-Match on PutObject, SHA-256
// checksum headers, Object Lock retention per version, and the bucket
// queries Describe makes. Everything the sink does not call returns 501.
type fakeS3 struct {
	mu      sync.Mutex
	bucket  string
	objects map[string][]*fakeVersion // oldest first
	seq     int
	now     func() time.Time

	versioning        string // "Enabled", "Suspended" or ""
	lockEnabled       bool
	defaultMode       string
	defaultDays       int32
	ignoreIfNoneMatch bool // behave like a store without conditional writes
	rejectConditional bool // answer 409 ConditionalRequestConflict instead of 412
	denyDeletes       bool // refuse every DeleteObject with AccessDenied, as an IAM policy would
	omitVersionIDs    bool // leave x-amz-version-id out of PutObject replies
	hideRetention     bool // leave the lock headers out of HeadObject/GetObject replies
	versionPageSize   int  // max-keys cap for ListObjectVersions, 1000 when 0

	puts []http.Header // headers of every PutObject, for assertions
}

type fakeVersion struct {
	id           string
	data         []byte
	etag         string
	contentType  string
	checksum     string
	modified     time.Time
	lockMode     string
	retainUntil  time.Time
	deleteMarker bool
}

func newFakeS3(bucket string) *fakeS3 {
	return &fakeS3{
		bucket:      bucket,
		objects:     map[string][]*fakeVersion{},
		now:         time.Now,
		versioning:  "Enabled",
		lockEnabled: true,
		defaultMode: "COMPLIANCE",
		defaultDays: 30,
	}
}

// start serves the fake and returns an S3 client pointed at it.
func (f *fakeS3) start(t *testing.T) *s3.Client {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return s3.New(s3.Options{
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("test", "test", ""),
		BaseEndpoint: aws.String(srv.URL),
		UsePathStyle: true,
	})
}

// addVersion injects a version directly, bypassing If-None-Match, the way
// a second writer on a store without conditional writes would.
func (f *fakeS3) addVersion(key string, data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.put(key, data, "application/octet-stream", "", time.Time{})
}

// addDeleteMarker hides key behind a delete marker, as a simple DELETE does
// on a versioned bucket.
func (f *fakeS3) addDeleteMarker(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	f.objects[key] = append(f.objects[key], &fakeVersion{id: fmt.Sprintf("v%04d", f.seq), modified: f.now().UTC(), deleteMarker: true})
}

func (f *fakeS3) put(key string, data []byte, contentType, lockMode string, retainUntil time.Time) *fakeVersion {
	f.seq++
	sum := md5.Sum(data) //nolint:gosec // ETag format only
	csum := sha256.Sum256(data)
	if lockMode == "" && f.lockEnabled && f.defaultMode != "" {
		lockMode = f.defaultMode
		retainUntil = f.now().Add(time.Duration(f.defaultDays) * 24 * time.Hour)
	}
	v := &fakeVersion{
		id:          fmt.Sprintf("v%04d", f.seq),
		data:        data,
		etag:        `"` + hex.EncodeToString(sum[:]) + `"`,
		contentType: contentType,
		checksum:    base64.StdEncoding.EncodeToString(csum[:]),
		modified:    f.now().UTC().Truncate(time.Second),
		lockMode:    lockMode,
		retainUntil: retainUntil,
	}
	if f.versioning != "Enabled" {
		f.objects[key] = nil
		v.id = "null"
	}
	f.objects[key] = append(f.objects[key], v)
	return v
}

func (f *fakeS3) latest(key string) *fakeVersion {
	vs := f.objects[key]
	if len(vs) == 0 {
		return nil
	}
	return vs[len(vs)-1]
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	rest := strings.TrimPrefix(r.URL.Path, "/")
	bucket, key, _ := strings.Cut(rest, "/")
	if bucket != f.bucket {
		s3Error(w, http.StatusNotFound, "NoSuchBucket", "no such bucket")
		return
	}
	q := r.URL.Query()
	if key == "" {
		f.serveBucket(w, r, q)
		return
	}
	switch r.Method {
	case http.MethodPut:
		f.putObject(w, r, key)
	case http.MethodGet, http.MethodHead:
		f.getObject(w, r, key, q.Get("versionId"))
	case http.MethodDelete:
		f.deleteObject(w, key, q.Get("versionId"))
	default:
		s3Error(w, http.StatusNotImplemented, "NotImplemented", r.Method)
	}
}

func (f *fakeS3) serveBucket(w http.ResponseWriter, r *http.Request, q map[string][]string) {
	_, hasLock := q["object-lock"]
	_, hasVersioning := q["versioning"]
	_, hasVersions := q["versions"]
	switch {
	case r.Method == http.MethodHead:
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodGet && hasLock:
		f.lockConfiguration(w)
	case r.Method == http.MethodGet && hasVersioning:
		type cfg struct {
			XMLName xml.Name `xml:"VersioningConfiguration"`
			Status  string   `xml:"Status,omitempty"`
		}
		writeXML(w, cfg{Status: f.versioning})
	case r.Method == http.MethodGet && hasVersions:
		f.listVersions(w, q)
	case r.Method == http.MethodGet && q["list-type"] != nil && q["list-type"][0] == "2":
		f.listObjectsV2(w, q)
	default:
		s3Error(w, http.StatusNotImplemented, "NotImplemented", r.Method+" "+r.URL.RawQuery)
	}
}

func (f *fakeS3) lockConfiguration(w http.ResponseWriter) {
	if !f.lockEnabled {
		s3Error(w, http.StatusNotFound, "ObjectLockConfigurationNotFoundError", "Object Lock configuration does not exist for this bucket")
		return
	}
	type retention struct {
		Mode string `xml:"Mode"`
		Days int32  `xml:"Days,omitempty"`
	}
	type rule struct {
		DefaultRetention *retention `xml:"DefaultRetention"`
	}
	type cfg struct {
		XMLName           xml.Name `xml:"ObjectLockConfiguration"`
		ObjectLockEnabled string   `xml:"ObjectLockEnabled"`
		Rule              *rule    `xml:"Rule,omitempty"`
	}
	c := cfg{ObjectLockEnabled: "Enabled"}
	if f.defaultMode != "" {
		c.Rule = &rule{DefaultRetention: &retention{Mode: f.defaultMode, Days: f.defaultDays}}
	}
	writeXML(w, c)
}

func (f *fakeS3) sortedKeys() []string {
	keys := make([]string, 0, len(f.objects))
	for k := range f.objects {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (f *fakeS3) listObjectsV2(w http.ResponseWriter, q map[string][]string) {
	prefix := first(q, "prefix")
	after := first(q, "continuation-token")
	maxKeys := 1000
	if m := first(q, "max-keys"); m != "" {
		maxKeys, _ = strconv.Atoi(m)
	}
	type object struct {
		Key          string `xml:"Key"`
		LastModified string `xml:"LastModified"`
		ETag         string `xml:"ETag"`
		Size         int    `xml:"Size"`
	}
	type result struct {
		XMLName               xml.Name `xml:"ListBucketResult"`
		Name                  string   `xml:"Name"`
		Prefix                string   `xml:"Prefix"`
		MaxKeys               int      `xml:"MaxKeys"`
		KeyCount              int      `xml:"KeyCount"`
		IsTruncated           bool     `xml:"IsTruncated"`
		NextContinuationToken string   `xml:"NextContinuationToken,omitempty"`
		Contents              []object `xml:"Contents"`
	}
	res := result{Name: f.bucket, Prefix: prefix, MaxKeys: maxKeys}
	for _, k := range f.sortedKeys() {
		if !strings.HasPrefix(k, prefix) || k <= after {
			continue
		}
		v := f.latest(k)
		if v == nil || v.deleteMarker {
			continue
		}
		if len(res.Contents) == maxKeys {
			res.IsTruncated = true
			res.NextContinuationToken = res.Contents[len(res.Contents)-1].Key
			break
		}
		res.Contents = append(res.Contents, object{
			Key: k, LastModified: v.modified.Format("2006-01-02T15:04:05.000Z"), ETag: v.etag, Size: len(v.data),
		})
	}
	res.KeyCount = len(res.Contents)
	writeXML(w, res)
}

// listVersions serves ListObjectVersions the way AWS pages it: entries
// ordered by key and then newest version first, at most max-keys per page,
// with NextKeyMarker and NextVersionIdMarker pointing at the last entry
// returned.
func (f *fakeS3) listVersions(w http.ResponseWriter, q map[string][]string) {
	prefix := first(q, "prefix")
	keyMarker := first(q, "key-marker")
	vidMarker := first(q, "version-id-marker")
	maxKeys := 1000
	if m := first(q, "max-keys"); m != "" {
		maxKeys, _ = strconv.Atoi(m)
	}
	if f.versionPageSize > 0 && maxKeys > f.versionPageSize {
		maxKeys = f.versionPageSize
	}
	type version struct {
		Key          string `xml:"Key"`
		VersionID    string `xml:"VersionId"`
		IsLatest     bool   `xml:"IsLatest"`
		LastModified string `xml:"LastModified"`
		ETag         string `xml:"ETag,omitempty"`
		Size         int    `xml:"Size"`
	}
	type result struct {
		XMLName             xml.Name  `xml:"ListVersionsResult"`
		Name                string    `xml:"Name"`
		Prefix              string    `xml:"Prefix"`
		KeyMarker           string    `xml:"KeyMarker"`
		VersionIDMarker     string    `xml:"VersionIdMarker"`
		MaxKeys             int       `xml:"MaxKeys"`
		IsTruncated         bool      `xml:"IsTruncated"`
		NextKeyMarker       string    `xml:"NextKeyMarker,omitempty"`
		NextVersionIDMarker string    `xml:"NextVersionIdMarker,omitempty"`
		Versions            []version `xml:"Version"`
		DeleteMarkers       []version `xml:"DeleteMarker"`
	}
	type entry struct {
		key    string
		v      *fakeVersion
		latest bool
	}
	var all []entry
	for _, k := range f.sortedKeys() {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		vs := f.objects[k]
		for i := len(vs) - 1; i >= 0; i-- { // newest first, like AWS
			all = append(all, entry{key: k, v: vs[i], latest: i == len(vs)-1})
		}
	}
	start := 0
	switch {
	case keyMarker == "":
	case vidMarker == "":
		for start < len(all) && all[start].key <= keyMarker {
			start++
		}
	default:
		for start < len(all) && (all[start].key != keyMarker || all[start].v.id != vidMarker) {
			start++
		}
		if start < len(all) {
			start++
		}
	}
	end := min(start+maxKeys, len(all))
	res := result{Name: f.bucket, Prefix: prefix, KeyMarker: keyMarker, VersionIDMarker: vidMarker, MaxKeys: maxKeys}
	for _, e := range all[start:end] {
		x := version{
			Key: e.key, VersionID: e.v.id, IsLatest: e.latest,
			LastModified: e.v.modified.Format("2006-01-02T15:04:05.000Z"), ETag: e.v.etag, Size: len(e.v.data),
		}
		if e.v.deleteMarker {
			res.DeleteMarkers = append(res.DeleteMarkers, x)
		} else {
			res.Versions = append(res.Versions, x)
		}
	}
	if end < len(all) {
		res.IsTruncated = true
		res.NextKeyMarker = all[end-1].key
		res.NextVersionIDMarker = all[end-1].v.id
	}
	writeXML(w, res)
}

func (f *fakeS3) putObject(w http.ResponseWriter, r *http.Request, key string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s3Error(w, http.StatusBadRequest, "IncompleteBody", err.Error())
		return
	}
	f.puts = append(f.puts, r.Header.Clone())
	if want := r.Header.Get("x-amz-checksum-sha256"); want != "" {
		sum := sha256.Sum256(body)
		if got := base64.StdEncoding.EncodeToString(sum[:]); got != want {
			s3Error(w, http.StatusBadRequest, "BadDigest", "checksum mismatch")
			return
		}
	}
	if r.Header.Get("If-None-Match") == "*" && !f.ignoreIfNoneMatch {
		if v := f.latest(key); v != nil && !v.deleteMarker {
			if f.rejectConditional {
				s3Error(w, http.StatusConflict, "ConditionalRequestConflict", "conditional request in progress")
				return
			}
			s3Error(w, http.StatusPreconditionFailed, "PreconditionFailed", "at least one precondition failed")
			return
		}
	}
	var retainUntil time.Time
	if d := r.Header.Get("x-amz-object-lock-retain-until-date"); d != "" {
		retainUntil, err = time.Parse(time.RFC3339, d)
		if err != nil {
			s3Error(w, http.StatusBadRequest, "InvalidArgument", "bad retain-until date")
			return
		}
	}
	v := f.put(key, body, r.Header.Get("Content-Type"), r.Header.Get("x-amz-object-lock-mode"), retainUntil)
	w.Header().Set("ETag", v.etag)
	if !f.omitVersionIDs {
		w.Header().Set("x-amz-version-id", v.id)
	}
	w.Header().Set("x-amz-checksum-sha256", v.checksum)
	w.WriteHeader(http.StatusOK)
}

func (f *fakeS3) getObject(w http.ResponseWriter, r *http.Request, key, versionID string) {
	var v *fakeVersion
	if versionID == "" {
		v = f.latest(key)
	} else {
		for _, c := range f.objects[key] {
			if c.id == versionID {
				v = c
			}
		}
	}
	if v == nil || v.deleteMarker {
		if v != nil {
			w.Header().Set("x-amz-delete-marker", "true")
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		s3Error(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")
		return
	}
	h := w.Header()
	h.Set("ETag", v.etag)
	h.Set("Content-Type", v.contentType)
	h.Set("Content-Length", strconv.Itoa(len(v.data)))
	h.Set("Last-Modified", v.modified.Format(http.TimeFormat))
	h.Set("x-amz-version-id", v.id)
	h.Set("x-amz-checksum-sha256", v.checksum)
	if v.lockMode != "" && !f.hideRetention {
		h.Set("x-amz-object-lock-mode", v.lockMode)
		h.Set("x-amz-object-lock-retain-until-date", v.retainUntil.UTC().Format(time.RFC3339))
	}
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(v.data)
	}
}

func (f *fakeS3) deleteObject(w http.ResponseWriter, key, versionID string) {
	if f.denyDeletes {
		s3Error(w, http.StatusForbidden, "AccessDenied", "User is not authorized to perform: s3:DeleteObjectVersion")
		return
	}
	vs := f.objects[key]
	if versionID == "" {
		if f.versioning == "Enabled" {
			f.seq++
			f.objects[key] = append(vs, &fakeVersion{id: fmt.Sprintf("v%04d", f.seq), modified: f.now().UTC(), deleteMarker: true})
		} else {
			delete(f.objects, key)
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	for i, v := range vs {
		if v.id != versionID {
			continue
		}
		if v.lockMode != "" && v.retainUntil.After(f.now()) {
			s3Error(w, http.StatusForbidden, "AccessDenied", "Access Denied because object protected by object lock.")
			return
		}
		f.objects[key] = append(vs[:i:i], vs[i+1:]...)
		if len(f.objects[key]) == 0 {
			delete(f.objects, key)
		}
		break
	}
	w.WriteHeader(http.StatusNoContent)
}

func first(q map[string][]string, name string) string {
	if v := q[name]; len(v) > 0 {
		return v[0]
	}
	return ""
}

func writeXML(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, xml.Header)
	_ = xml.NewEncoder(w).Encode(v)
}

func s3Error(w http.ResponseWriter, status int, code, message string) {
	type e struct {
		XMLName   xml.Name `xml:"Error"`
		Code      string   `xml:"Code"`
		Message   string   `xml:"Message"`
		RequestID string   `xml:"RequestId"`
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, xml.Header)
	_ = xml.NewEncoder(w).Encode(e{Code: code, Message: message, RequestID: "fake"})
}
