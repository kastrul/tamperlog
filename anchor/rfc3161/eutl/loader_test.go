package eutl

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// tlServer serves the fixtures over TLS, rewriting the fixture host to its
// own address, with ETag / Last-Modified and conditional-request support.
type tlServer struct {
	*httptest.Server
	mu       sync.Mutex
	requests []*http.Request
	missing  map[string]bool
	status   map[string]int
	bodies   map[string]string
}

func newTLServer(t *testing.T) *tlServer {
	t.Helper()
	s := &tlServer{missing: map[string]bool{}, status: map[string]int{}, bodies: map[string]string{}}
	s.Server = httptest.NewUnstartedServer(http.HandlerFunc(s.handle))
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.StartTLS()
	t.Cleanup(s.Close)
	for name, path := range map[string]string{"eu-lotl.xml": "/lotl/eu-lotl.xml", "ee-tl.xml": "/tsl/ee-tl.xml"} {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		s.bodies[path] = strings.ReplaceAll(string(b), "https://example.test", s.URL)
	}
	return s
}

const lastModified = "Thu, 15 Oct 2026 16:30:51 GMT"

func (s *tlServer) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.requests = append(s.requests, r.Clone(context.Background()))
	body, ok := s.bodies[r.URL.Path]
	missing := s.missing[r.URL.Path]
	status := s.status[r.URL.Path]
	s.mu.Unlock()
	if status != 0 {
		w.WriteHeader(status)
		return
	}
	if !ok || missing {
		http.NotFound(w, r)
		return
	}
	sum := sha256.Sum256([]byte(body))
	etag := `"` + hex.EncodeToString(sum[:8]) + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Last-Modified", lastModified)
	// If-None-Match takes precedence over If-Modified-Since (RFC 9110 §13.1.3).
	notModified := r.Header.Get("If-None-Match") == etag
	if r.Header.Get("If-None-Match") == "" {
		notModified = r.Header.Get("If-Modified-Since") == lastModified
	}
	if notModified {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.etsi.tsl+xml")
	_, _ = w.Write([]byte(body))
}

func (s *tlServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

func (s *tlServer) paths() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.requests))
	for _, r := range s.requests {
		out = append(out, r.URL.Path)
	}
	return out
}

func (s *tlServer) loader(t *testing.T, opts ...Option) *Loader {
	t.Helper()
	all := make([]Option, 0, 2+len(opts))
	all = append(all, WithHTTPClient(s.Client()), WithLOTLURL(s.URL+"/lotl/eu-lotl.xml"))
	return NewLoader(append(all, opts...)...)
}

func TestLoadWithoutCache(t *testing.T) {
	s := newTLServer(t)
	list, err := s.loader(t).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if list.LOTL == nil || list.LOTL.SequenceNumber != 397 {
		t.Fatalf("LOTL = %+v", list.LOTL)
	}
	if len(list.Services) != 3 || list.Lists["EE"] == nil {
		t.Fatalf("services = %d, lists = %v", len(list.Services), list.Lists)
	}
	if err := list.Errors["LV"]; err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("LV error = %v, want 404 recorded", err)
	}
	if len(list.Errors) != 1 {
		t.Fatalf("errors = %v", list.Errors)
	}
	if s.count() != 3 { // LOTL, EE, LV; never the PDF or the self-pointer
		t.Fatalf("requests = %v", s.paths())
	}
	if list.LoadedAt.IsZero() {
		t.Fatal("LoadedAt not set")
	}
}

func TestCacheLifecycle(t *testing.T) {
	s := newTLServer(t)
	dir := t.TempDir()
	ctx := context.Background()

	// 1. First load fetches everything.
	l := s.loader(t, WithCacheDir(dir), WithTerritories("EE"))
	if _, err := l.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if s.count() != 2 {
		t.Fatalf("first load: requests = %v", s.paths())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 { // two lists, two .meta sidecars
		t.Fatalf("cache entries = %d", len(entries))
	}
	metaPath := l.CachePath(s.URL+"/lotl/eu-lotl.xml") + ".meta"
	mb, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mb), `"etag":"\"`) || !strings.Contains(string(mb), lastModified) {
		t.Fatalf("meta = %s", mb)
	}

	// 2. Second load within max age touches the network not at all.
	list, err := s.loader(t, WithCacheDir(dir), WithTerritories("EE")).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if s.count() != 2 || len(list.Services) != 3 {
		t.Fatalf("second load: requests = %v, services = %d", s.paths(), len(list.Services))
	}

	// 3. After max age the loader revalidates and accepts 304.
	time.Sleep(2 * time.Millisecond)
	list, err = s.loader(t, WithCacheDir(dir), WithTerritories("EE"), WithMaxAge(time.Millisecond)).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if s.count() != 4 || len(list.Services) != 3 {
		t.Fatalf("third load: requests = %v, services = %d", s.paths(), len(list.Services))
	}
	s.mu.Lock()
	for _, r := range s.requests[2:] {
		if r.Header.Get("If-None-Match") == "" || r.Header.Get("If-Modified-Since") != lastModified {
			t.Errorf("revalidation of %s lacked conditional headers: %v", r.URL.Path, r.Header)
		}
	}
	s.mu.Unlock()

	// 4. The 304 refreshed the fetch time, so the next load is served from cache again.
	if _, err := s.loader(t, WithCacheDir(dir), WithTerritories("EE")).Load(ctx); err != nil {
		t.Fatal(err)
	}
	if s.count() != 4 {
		t.Fatalf("fourth load: requests = %v", s.paths())
	}

	// 5. Offline mode reads the cache regardless of age and fails for anything missing.
	list, err = s.loader(t, WithCacheDir(dir), WithOffline(), WithMaxAge(time.Nanosecond)).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if s.count() != 4 || len(list.Services) != 3 {
		t.Fatalf("offline load: requests = %v, services = %d", s.paths(), len(list.Services))
	}
	if !errors.Is(list.Errors["LV"], ErrNotCached) {
		t.Fatalf("offline LV error = %v", list.Errors["LV"])
	}
	if _, err := NewLoader(WithOffline()).Load(ctx); err == nil {
		t.Fatal("offline without cache dir must fail")
	}
	if _, err := s.loader(t, WithCacheDir(t.TempDir()), WithOffline()).Load(ctx); !errors.Is(err, ErrNotCached) {
		t.Fatalf("offline with empty cache = %v", err)
	}
}

func TestCacheRefetchesChangedBody(t *testing.T) {
	s := newTLServer(t)
	dir := t.TempDir()
	ctx := context.Background()
	if _, err := s.loader(t, WithCacheDir(dir), WithTerritories("EE")).Load(ctx); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.bodies["/tsl/ee-tl.xml"] = strings.Replace(s.bodies["/tsl/ee-tl.xml"], "<TSLSequenceNumber>88<", "<TSLSequenceNumber>89<", 1)
	s.mu.Unlock()
	time.Sleep(2 * time.Millisecond)
	list, err := s.loader(t, WithCacheDir(dir), WithTerritories("EE"), WithMaxAge(time.Millisecond)).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if list.Lists["EE"].SequenceNumber != 89 {
		t.Fatalf("sequence = %d, want refreshed 89", list.Lists["EE"].SequenceNumber)
	}
}

func TestTerritoryFilter(t *testing.T) {
	s := newTLServer(t)
	list, err := s.loader(t, WithTerritories("ee")).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Errors) != 0 || len(list.Services) != 3 {
		t.Fatalf("errors = %v, services = %d", list.Errors, len(list.Services))
	}
	for _, p := range s.paths() {
		if strings.Contains(p, "lv-tl") {
			t.Fatalf("LV must not be requested: %v", s.paths())
		}
	}
	list, err = s.loader(t, WithTerritories("LV")).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Services) != 0 || list.Errors["LV"] == nil {
		t.Fatalf("LV only: services = %d, errors = %v", len(list.Services), list.Errors)
	}
}

func TestFailingNationalListRecorded(t *testing.T) {
	s := newTLServer(t)
	s.mu.Lock()
	s.status["/tsl/ee-tl.xml"] = http.StatusInternalServerError
	s.mu.Unlock()
	list, err := s.loader(t).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Services) != 0 || list.Errors["EE"] == nil || !strings.Contains(list.Errors["EE"].Error(), "500") {
		t.Fatalf("services = %d, errors = %v", len(list.Services), list.Errors)
	}

	// A list that downloads but does not parse is recorded too.
	s.mu.Lock()
	delete(s.status, "/tsl/ee-tl.xml")
	s.bodies["/tsl/ee-tl.xml"] = "<broken"
	s.mu.Unlock()
	list, err = s.loader(t).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(list.Errors["EE"], ErrNotTrustedList) {
		t.Fatalf("EE parse error = %v", list.Errors["EE"])
	}

	// A list whose territory disagrees with the LOTL pointer is rejected.
	ee, err := os.ReadFile(filepath.Join("testdata", "ee-tl.xml"))
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.bodies["/tsl/ee-tl.xml"] = strings.Replace(string(ee), "<SchemeTerritory>EE</SchemeTerritory>", "<SchemeTerritory>XX</SchemeTerritory>", 1)
	s.mu.Unlock()
	list, err = s.loader(t).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if list.Errors["EE"] == nil || !strings.Contains(list.Errors["EE"].Error(), `"XX"`) {
		t.Fatalf("territory mismatch error = %v", list.Errors["EE"])
	}
}

func TestLOTLFailureIsFatal(t *testing.T) {
	s := newTLServer(t)
	s.mu.Lock()
	s.missing["/lotl/eu-lotl.xml"] = true
	s.mu.Unlock()
	if _, err := s.loader(t).Load(context.Background()); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("err = %v", err)
	}
	s.mu.Lock()
	s.missing["/lotl/eu-lotl.xml"] = false
	s.bodies["/lotl/eu-lotl.xml"] = "not xml"
	s.mu.Unlock()
	if _, err := s.loader(t).Load(context.Background()); !errors.Is(err, ErrNotTrustedList) {
		t.Fatalf("err = %v", err)
	}
}

func TestPinnedLOTL(t *testing.T) {
	s := newTLServer(t)
	s.mu.Lock()
	sum := sha256.Sum256([]byte(s.bodies["/lotl/eu-lotl.xml"]))
	s.mu.Unlock()
	good := hex.EncodeToString(sum[:])

	_, err := s.loader(t, WithPinnedLOTLSHA256(strings.Repeat("00", 32))).Load(context.Background())
	if !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("mismatch err = %v", err)
	}
	if s.count() != 1 {
		t.Fatalf("no national list may be fetched after a pin mismatch: %v", s.paths())
	}
	list, err := s.loader(t, WithPinnedLOTLSHA256(strings.ToUpper(good))).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Services) != 3 {
		t.Fatalf("services = %d", len(list.Services))
	}
}

func TestInsecureURLs(t *testing.T) {
	s := newTLServer(t)
	s.mu.Lock()
	s.bodies["/lotl/eu-lotl.xml"] = strings.Replace(s.bodies["/lotl/eu-lotl.xml"], s.URL+"/tsl/ee-tl.xml", "http://"+strings.TrimPrefix(s.URL, "https://")+"/tsl/ee-tl.xml", 1)
	s.mu.Unlock()
	list, err := s.loader(t, WithTerritories("EE")).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(list.Errors["EE"], ErrInsecureURL) {
		t.Fatalf("EE error = %v", list.Errors["EE"])
	}
	if _, err := NewLoader(WithLOTLURL("http://example.test/lotl.xml")).Load(context.Background()); !errors.Is(err, ErrInsecureURL) {
		t.Fatalf("http LOTL err = %v", err)
	}
}

func TestBodyLimit(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		chunk := strings.Repeat("x", 1<<20)
		for range (MaxBodySize >> 20) + 1 {
			_, _ = w.Write([]byte(chunk))
		}
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, err := NewLoader(WithHTTPClient(srv.Client()), WithLOTLURL(srv.URL+"/big.xml")).Load(context.Background())
	if !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("err = %v", err)
	}
}

func TestContextCancelled(t *testing.T) {
	s := newTLServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.loader(t).Load(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}
