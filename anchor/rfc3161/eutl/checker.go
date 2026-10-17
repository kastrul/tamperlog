package eutl

import (
	"crypto/x509"
	"errors"
	"time"
)

// Checker adapts a loaded [List] to the function shape that the rfc3161
// verifier's WithQualifiedChecker option takes. chainResolver, when not nil,
// supplies the CA certificates above cert so that services identified by an
// issuing CA rather than by the time-stamp unit certificate are found.
func Checker(list *List, chainResolver func(cert *x509.Certificate) []*x509.Certificate) func(cert *x509.Certificate, at time.Time) (bool, error) {
	return func(cert *x509.Certificate, at time.Time) (bool, error) {
		if list == nil {
			return false, errors.New("eutl: no trusted list loaded")
		}
		var chain []*x509.Certificate
		if chainResolver != nil {
			chain = chainResolver(cert)
		}
		ok, _, err := list.Qualified(cert, chain, at)
		return ok, err
	}
}
