// Package fs is a write-once directory [seal.Sink] for development, tests and
// offline bundles. Put creates the file with O_EXCL, so an existing key is
// never overwritten by this process; the directory's permissions and the
// filesystem decide what other users may do. It is not WORM storage: anyone
// with write access to the directory can replace a file. Use seal/sinks/s3lock
// or copy the directory to media under another administrator for evidence.
package fs

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kastrul/tamperlog/seal"
)

// Sink writes under a root directory.
type Sink struct {
	root string
}

// New returns a Sink rooted at dir, creating it if needed.
func New(dir string) (*Sink, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("fs sink: %w", err)
	}
	return &Sink{root: dir}, nil
}

func (s *Sink) pathOf(key string) (string, error) {
	clean := path.Clean("/" + key)
	if clean == "/" || strings.Contains(key, "..") || strings.HasPrefix(key, "/") {
		return "", fmt.Errorf("fs sink: invalid key %q", key)
	}
	return filepath.Join(s.root, filepath.FromSlash(clean[1:])), nil
}

// Put writes data to key, failing with [seal.ErrExists] if the key exists.
// The write goes to a temporary file in the same directory and is linked into
// place with an exclusive create, so a reader never sees a partial file.
func (s *Sink) Put(_ context.Context, key string, data []byte) error {
	p, err := s.pathOf(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return fmt.Errorf("fs sink: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tamperlog-*")
	if err != nil {
		return fmt.Errorf("fs sink: %w", err)
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck // best-effort cleanup of the temp file
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fs sink: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fs sink: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("fs sink: %w", err)
	}
	if err := os.Link(tmp.Name(), p); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%w: %s", seal.ErrExists, key)
		}
		return fmt.Errorf("fs sink: %w", err)
	}
	if err := os.Chmod(p, 0o440); err != nil { //nolint:gosec // group-readable on purpose: a verifier runs as another user
		return fmt.Errorf("fs sink: %w", err)
	}
	return nil
}

// Get reads key.
func (s *Sink) Get(_ context.Context, key string) ([]byte, error) {
	p, err := s.pathOf(key)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p) //nolint:gosec // p is confined to the root by pathOf
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", seal.ErrNotFound, key)
	}
	if err != nil {
		return nil, fmt.Errorf("fs sink: %w", err)
	}
	return b, nil
}

// List returns keys under prefix in lexical order.
func (s *Sink) List(_ context.Context, prefix string) ([]string, error) {
	var keys []string
	err := filepath.WalkDir(s.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || strings.HasPrefix(d.Name(), ".tamperlog-") {
			return nil
		}
		rel, err := filepath.Rel(s.root, p)
		if err != nil {
			return err
		}
		key := filepath.ToSlash(rel)
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("fs sink: %w", err)
	}
	sort.Strings(keys)
	return keys, nil
}
