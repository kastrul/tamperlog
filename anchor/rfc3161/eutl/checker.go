package eutl

import (
	"crypto/x509"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Errors returned by [Policy.Check] and therefore by a [Checker] whose
// policy is not met. The rfc3161 verifier wraps them in
// anchor.ErrInvalidProof, so a stale or incomplete list fails verification
// instead of silently yielding Qualified = false.
var (
	// ErrListStale means the LOTL or a loaded national list is past its
	// NextUpdate.
	ErrListStale = errors.New("eutl: trusted list is past its NextUpdate")
	// ErrTerritoryUnavailable means a territory named in
	// [Policy.RequireTerritories] did not load.
	ErrTerritoryUnavailable = errors.New("eutl: required trusted list is unavailable")
)

// Policy is what a [Checker] demands of the [List] before and while it
// answers. The zero Policy accepts any loaded list and only certificates the
// current ServiceInformation identifies.
type Policy struct {
	// RequireFresh fails every check while the LOTL's NextUpdate or that of
	// any loaded national list is in the past at check time. Closed lists
	// (zero NextUpdate) are never stale.
	RequireFresh bool
	// RequireTerritories fails every check while one of these scheme
	// territories (ISO 3166-1 codes such as "EE") is not among the loaded
	// lists, whether because it failed to download or parse (see
	// [List.Errors]) or because it was filtered out.
	RequireTerritories []string
	// AllowHistorical accepts a certificate that is key-authenticated only by
	// a ServiceHistoryInstance, that is a key the service no longer lists in
	// its ServiceInformation, for the granted period in which it was listed.
	// When false (the default) the current ServiceInformation's identity must
	// authenticate the certificate as well; the period containing the
	// time-stamp's time must still be granted and QTST either way, so
	// verifying old tokens of a service that kept its key works without it.
	AllowHistorical bool
}

// Check reports whether list satisfies the policy at time now; it returns
// nil when it does.
func (p Policy) Check(list *List, now time.Time) error {
	if list == nil {
		return errors.New("eutl: no trusted list loaded")
	}
	if p.RequireFresh {
		if !list.NextUpdate.IsZero() && now.After(list.NextUpdate) {
			return fmt.Errorf("%w: LOTL NextUpdate %s", ErrListStale, list.NextUpdate.Format(time.RFC3339))
		}
		territories := make([]string, 0, len(list.Lists))
		for t := range list.Lists {
			territories = append(territories, t)
		}
		sort.Strings(territories)
		for _, t := range territories {
			tl := list.Lists[t]
			if tl != nil && !tl.NextUpdate.IsZero() && now.After(tl.NextUpdate) {
				return fmt.Errorf("%w: %s NextUpdate %s", ErrListStale, t, tl.NextUpdate.Format(time.RFC3339))
			}
		}
	}
	for _, t := range p.RequireTerritories {
		t = strings.ToUpper(strings.TrimSpace(t))
		if _, ok := list.Lists[t]; ok {
			continue
		}
		if err := list.Errors[t]; err != nil {
			return fmt.Errorf("%w: %s: %w", ErrTerritoryUnavailable, t, err)
		}
		return fmt.Errorf("%w: %s was not loaded", ErrTerritoryUnavailable, t)
	}
	return nil
}

// CheckerOption configures [Checker] and [Refresher.Checker].
type CheckerOption func(*checkerConfig)

type checkerConfig struct {
	policy Policy
	now    func() time.Time
}

// WithPolicy sets the [Policy] the checker enforces.
func WithPolicy(p Policy) CheckerOption {
	return func(c *checkerConfig) { c.policy = p }
}

// withClock replaces the clock used for freshness checks (tests).
func withClock(now func() time.Time) CheckerOption {
	return func(c *checkerConfig) { c.now = now }
}

// Checker adapts a loaded [List] to the function shape that the rfc3161
// verifier's WithQualifiedChecker option takes. chainResolver, when not nil,
// supplies the CA certificates above cert so that services identified by an
// issuing CA rather than by the time-stamp unit certificate are found. The
// returned function errors, rather than answering false, when list is nil or
// does not satisfy the configured [Policy]; the verifier reports that as a
// verification failure. For a list that is reloaded periodically use
// [Loader.LoadWithRefresh] and [Refresher.Checker].
func Checker(list *List, chainResolver func(cert *x509.Certificate) []*x509.Certificate, opts ...CheckerOption) func(cert *x509.Certificate, at time.Time) (bool, error) {
	return newChecker(func() *List { return list }, chainResolver, opts)
}

func newChecker(current func() *List, chainResolver func(cert *x509.Certificate) []*x509.Certificate, opts []CheckerOption) func(cert *x509.Certificate, at time.Time) (bool, error) {
	cfg := checkerConfig{now: time.Now}
	for _, o := range opts {
		o(&cfg)
	}
	return func(cert *x509.Certificate, at time.Time) (bool, error) {
		list := current()
		if list == nil {
			return false, errors.New("eutl: no trusted list loaded")
		}
		if err := cfg.policy.Check(list, cfg.now()); err != nil {
			return false, err
		}
		var chain []*x509.Certificate
		if chainResolver != nil {
			chain = chainResolver(cert)
		}
		ok, _, err := list.qualified(cert, chain, at, cfg.policy.AllowHistorical)
		return ok, err
	}
}
