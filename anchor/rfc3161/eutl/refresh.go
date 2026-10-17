package eutl

import (
	"context"
	"crypto/x509"
	"errors"
	"sync"
	"time"
)

// Refresher keeps a [List] current by reloading it on an interval, so a
// long-running verifier does not trust one snapshot forever. Create one
// with [Loader.LoadWithRefresh].
type Refresher struct {
	mu   sync.RWMutex
	list *List
	err  error
	done chan struct{}
}

// LoadWithRefresh loads the lists once, failing as [Loader.Load] would, and
// then reloads them every interval until ctx ends. A reload that fails keeps
// the previous List and is reported by [Refresher.Err] until a later reload
// succeeds; combine with [Policy.RequireFresh] so that a list that could not
// be refreshed past its NextUpdate stops qualifying anything.
func (l *Loader) LoadWithRefresh(ctx context.Context, every time.Duration) (*Refresher, error) {
	if every <= 0 {
		return nil, errors.New("eutl: refresh interval must be positive")
	}
	list, err := l.Load(ctx)
	if err != nil {
		return nil, err
	}
	r := &Refresher{list: list, done: make(chan struct{})}
	go r.run(ctx, l, every)
	return r, nil
}

func (r *Refresher) run(ctx context.Context, l *Loader, every time.Duration) {
	defer close(r.done)
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		list, err := l.Load(ctx)
		if err != nil && ctx.Err() != nil {
			return
		}
		r.mu.Lock()
		if err != nil {
			r.err = err
		} else {
			r.list, r.err = list, nil
		}
		r.mu.Unlock()
	}
}

// Current returns the most recently loaded List. It is never nil.
func (r *Refresher) Current() *List {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.list
}

// Err returns the error of the latest reload, or nil when it succeeded.
func (r *Refresher) Err() error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.err
}

// Done is closed once the refresh loop has stopped, after the context given
// to [Loader.LoadWithRefresh] ended.
func (r *Refresher) Done() <-chan struct{} {
	return r.done
}

// Checker is [Checker] over [Refresher.Current], consulting the latest List
// on every call.
func (r *Refresher) Checker(chainResolver func(cert *x509.Certificate) []*x509.Certificate, opts ...CheckerOption) func(cert *x509.Certificate, at time.Time) (bool, error) {
	return newChecker(r.Current, chainResolver, opts)
}
