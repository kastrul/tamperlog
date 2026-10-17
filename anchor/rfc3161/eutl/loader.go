package eutl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DefaultLOTLURL is where the European Commission publishes the LOTL.
const DefaultLOTLURL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"

// DefaultMaxAge is how long a cached list is served without revalidation.
const DefaultMaxAge = 24 * time.Hour

// MaxBodySize bounds every downloaded list (32 MiB).
const MaxBodySize = 32 << 20

// Errors returned by [Loader.Load].
var (
	// ErrPinMismatch means the LOTL bytes do not hash to the pinned SHA-256.
	ErrPinMismatch = errors.New("eutl: LOTL does not match pinned SHA-256")
	// ErrNotCached means [WithOffline] is set and a list is not in the cache.
	ErrNotCached = errors.New("eutl: not in cache")
	// ErrInsecureURL means a list location does not use https.
	ErrInsecureURL = errors.New("eutl: list location is not https")
	// ErrBodyTooLarge means a list exceeded [MaxBodySize].
	ErrBodyTooLarge = errors.New("eutl: list body exceeds size limit")
	// ErrTooManyRedirects means a download followed more than [MaxRedirects].
	ErrTooManyRedirects = errors.New("eutl: too many redirects")
)

// MaxRedirects bounds the redirect hops the loader follows for one list;
// every hop must stay on https.
const MaxRedirects = 5

// Option configures a [Loader].
type Option func(*Loader)

// WithHTTPClient sets the HTTP client; the default is a client with a
// 60-second timeout. The loader uses a copy whose CheckRedirect refuses
// any hop to a non-https URL and more than [MaxRedirects] hops, calling the
// client's own CheckRedirect, if any, afterwards.
func WithHTTPClient(c *http.Client) Option {
	return func(l *Loader) { l.client = c }
}

// WithLOTLURL overrides [DefaultLOTLURL]; useful for mirrors and tests.
func WithLOTLURL(u string) Option {
	return func(l *Loader) { l.lotlURL = u }
}

// WithCacheDir stores every downloaded list in dir as <sha256(url)>.xml with
// a sibling .meta JSON file (fetch time, ETag, Last-Modified). Without a
// cache directory every Load downloads everything.
func WithCacheDir(dir string) Option {
	return func(l *Loader) { l.cacheDir = dir }
}

// WithMaxAge sets how long a cached list is served without contacting the
// publisher (default [DefaultMaxAge]). Older entries are revalidated with
// If-None-Match / If-Modified-Since.
func WithMaxAge(d time.Duration) Option {
	return func(l *Loader) { l.maxAge = d }
}

// WithTerritories restricts loading to the given scheme territories (ISO
// 3166-1 codes such as "EE"); the default loads every XML pointer.
func WithTerritories(territories ...string) Option {
	return func(l *Loader) {
		l.territories = map[string]bool{}
		for _, t := range territories {
			l.territories[strings.ToUpper(strings.TrimSpace(t))] = true
		}
	}
}

// WithPinnedLOTLSHA256 makes Load fail with [ErrPinMismatch] unless the
// LOTL bytes hash to the given hex digest. Use it for reproducible offline
// verification bundles where the exact list is part of the evidence.
func WithPinnedLOTLSHA256(hexDigest string) Option {
	return func(l *Loader) { l.pin = strings.ToLower(strings.TrimSpace(hexDigest)) }
}

// WithOffline makes Load read only the cache, regardless of age, and fail
// with [ErrNotCached] for anything missing. It requires [WithCacheDir].
func WithOffline() Option {
	return func(l *Loader) { l.offline = true }
}

// WithConcurrency bounds how many national lists download at once
// (default 4).
func WithConcurrency(n int) Option {
	return func(l *Loader) {
		if n > 0 {
			l.concurrency = n
		}
	}
}

// Loader downloads the LOTL and the national lists it points to.
type Loader struct {
	client      *http.Client
	lotlURL     string
	cacheDir    string
	maxAge      time.Duration
	territories map[string]bool
	pin         string
	offline     bool
	concurrency int
	now         func() time.Time
}

// NewLoader returns a Loader with the EC LOTL URL, a 24-hour cache max age,
// no cache directory and all territories.
func NewLoader(opts ...Option) *Loader {
	l := &Loader{
		client:      &http.Client{Timeout: 60 * time.Second},
		lotlURL:     DefaultLOTLURL,
		maxAge:      DefaultMaxAge,
		concurrency: 4,
		now:         time.Now,
	}
	for _, o := range opts {
		o(l)
	}
	l.client = httpsOnlyClient(l.client)
	return l
}

// httpsOnlyClient returns a copy of c that refuses redirects leaving https
// and more than [MaxRedirects] hops. Checking only the initial URL would let
// a publisher (or anyone who can answer for it) bounce the download to a
// plaintext location.
func httpsOnlyClient(c *http.Client) *http.Client {
	if c == nil {
		c = &http.Client{Timeout: 60 * time.Second}
	}
	cc := *c
	inner := c.CheckRedirect
	cc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= MaxRedirects {
			return fmt.Errorf("%w: stopped after %d hops at %s", ErrTooManyRedirects, len(via), req.URL.Redacted())
		}
		if req.URL.Scheme != "https" {
			return fmt.Errorf("%w: redirected to %s", ErrInsecureURL, req.URL.Redacted())
		}
		if inner != nil {
			return inner(req, via)
		}
		return nil
	}
	return &cc
}

// Load fetches the LOTL and then, concurrently, every national XML list it
// selects. A national list that fails to download or parse is skipped and
// recorded in [List.Errors] under its territory; Load fails only when the
// LOTL itself cannot be loaded, fails the pin, or the context ends.
func (l *Loader) Load(ctx context.Context) (*List, error) {
	if l.offline && l.cacheDir == "" {
		return nil, errors.New("eutl: WithOffline requires WithCacheDir")
	}
	raw, err := l.fetch(ctx, l.lotlURL)
	if err != nil {
		return nil, fmt.Errorf("eutl: load LOTL: %w", err)
	}
	if l.pin != "" {
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != l.pin {
			return nil, fmt.Errorf("%w: got %s", ErrPinMismatch, hex.EncodeToString(sum[:]))
		}
	}
	lotl, err := ParseLOTL(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("eutl: parse LOTL: %w", err)
	}

	out := &List{
		LOTL:       lotl,
		IssuedAt:   lotl.ListIssueDateTime,
		NextUpdate: lotl.NextUpdate,
		Lists:      map[string]*TL{},
		Errors:     map[string]error{},
		LoadedAt:   l.now().UTC(),
	}
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, l.concurrency)
	)
	for i := range lotl.Pointers {
		p := &lotl.Pointers[i]
		if !l.selects(p) {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				mu.Lock()
				out.Errors[p.Territory] = ctx.Err()
				mu.Unlock()
				return
			}
			tl, err := l.loadTL(ctx, p)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				out.Errors[p.Territory] = err
				return
			}
			out.Lists[p.Territory] = tl
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Deterministic order: pointer order of the LOTL.
	for i := range lotl.Pointers {
		if tl, ok := out.Lists[lotl.Pointers[i].Territory]; ok && l.selects(&lotl.Pointers[i]) {
			out.Services = append(out.Services, tl.Services...)
		}
	}
	return out, nil
}

// selects reports whether a pointer is a national XML list to load.
func (l *Loader) selects(p *Pointer) bool {
	if p.MimeType != MimeTypeXML || p.TSLType == TSLTypeLOTL || p.URL == l.lotlURL {
		return false
	}
	if l.territories != nil && !l.territories[strings.ToUpper(p.Territory)] {
		return false
	}
	return true
}

func (l *Loader) loadTL(ctx context.Context, p *Pointer) (*TL, error) {
	raw, err := l.fetch(ctx, p.URL)
	if err != nil {
		return nil, err
	}
	tl, err := ParseTL(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(tl.Territory, p.Territory) {
		return nil, fmt.Errorf("%w: list at %s declares territory %q, LOTL says %q", ErrNotTrustedList, p.URL, tl.Territory, p.Territory)
	}
	return tl, nil
}

// cacheMeta is the sidecar JSON next to a cached list.
type cacheMeta struct {
	URL          string    `json:"url"`
	FetchedAt    time.Time `json:"fetched_at"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
}

// fetch returns the bytes of the list at rawURL, from the cache when fresh
// enough or after conditional revalidation otherwise.
func (l *Loader) fetch(ctx context.Context, rawURL string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("eutl: %q: %w", rawURL, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("%w: %s", ErrInsecureURL, rawURL)
	}

	var (
		cached []byte
		meta   cacheMeta
		have   bool
	)
	if l.cacheDir != "" {
		cached, meta, have = l.readCache(rawURL)
		if have && (l.offline || l.now().Sub(meta.FetchedAt) < l.maxAge) {
			return cached, nil
		}
		if l.offline {
			return nil, fmt.Errorf("%w: %s", ErrNotCached, rawURL)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	// Some publishers (CZ) answer 406 unless */* is acceptable.
	req.Header.Set("Accept", MimeTypeXML+", application/xml;q=0.9, text/xml;q=0.9, */*;q=0.1")
	if have {
		if meta.ETag != "" {
			req.Header.Set("If-None-Match", meta.ETag)
		}
		if meta.LastModified != "" {
			req.Header.Set("If-Modified-Since", meta.LastModified)
		}
	}
	resp, err := l.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusNotModified && have:
		meta.FetchedAt = l.now().UTC()
		if err := l.writeCache(rawURL, nil, meta); err != nil {
			return nil, err
		}
		return cached, nil
	case resp.StatusCode != http.StatusOK:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("eutl: GET %s: %s", rawURL, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodySize+1))
	if err != nil {
		return nil, fmt.Errorf("eutl: GET %s: %w", rawURL, err)
	}
	if len(body) > MaxBodySize {
		return nil, fmt.Errorf("%w: %s", ErrBodyTooLarge, rawURL)
	}
	if l.cacheDir != "" {
		meta = cacheMeta{
			URL:          rawURL,
			FetchedAt:    l.now().UTC(),
			ETag:         resp.Header.Get("ETag"),
			LastModified: resp.Header.Get("Last-Modified"),
		}
		if err := l.writeCache(rawURL, body, meta); err != nil {
			return nil, err
		}
	}
	return body, nil
}

// CachePath returns the file the loader uses to cache the list at rawURL
// (its .meta sidecar has the same name with ".meta" appended).
func (l *Loader) CachePath(rawURL string) string {
	sum := sha256.Sum256([]byte(rawURL))
	return filepath.Join(l.cacheDir, hex.EncodeToString(sum[:])+".xml")
}

func (l *Loader) readCache(rawURL string) ([]byte, cacheMeta, bool) {
	path := l.CachePath(rawURL)
	var meta cacheMeta
	mb, err := os.ReadFile(path + ".meta") //nolint:gosec // path is derived from a hash inside the configured cache directory.
	if err != nil || json.Unmarshal(mb, &meta) != nil || meta.URL != rawURL {
		return nil, cacheMeta{}, false
	}
	body, err := os.ReadFile(path) //nolint:gosec // see above.
	if err != nil || len(body) == 0 {
		return nil, cacheMeta{}, false
	}
	return body, meta, true
}

// writeCache stores body (when not nil) and meta atomically.
func (l *Loader) writeCache(rawURL string, body []byte, meta cacheMeta) error {
	if err := os.MkdirAll(l.cacheDir, 0o700); err != nil {
		return fmt.Errorf("eutl: cache: %w", err)
	}
	path := l.CachePath(rawURL)
	if body != nil {
		if err := writeFileAtomic(path, body); err != nil {
			return fmt.Errorf("eutl: cache: %w", err)
		}
	}
	mb, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(path+".meta", mb); err != nil {
		return fmt.Errorf("eutl: cache: %w", err)
	}
	return nil
}

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}
