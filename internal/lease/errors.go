// Package lease creates and verifies short-lived, device-bound activation
// leases. Its compact wire format is intentionally strict: there is exactly
// one accepted encoding for every valid lease.
package lease

import "errors"

var (
	ErrMalformedToken      = errors.New("lease: malformed token")
	ErrInvalidSignature    = errors.New("lease: invalid signature")
	ErrInvalidClaims       = errors.New("lease: invalid claims")
	ErrNonCanonicalPayload = errors.New("lease: non-canonical payload")
	ErrKeyMismatch         = errors.New("lease: key ID mismatch")
	ErrIssuerMismatch      = errors.New("lease: issuer mismatch")
	ErrAudienceMismatch    = errors.New("lease: audience mismatch")
	ErrDeviceMismatch      = errors.New("lease: device key thumbprint mismatch")
	ErrInvalidOptions      = errors.New("lease: invalid verification options")
	ErrIssuedInFuture      = errors.New("lease: issued in the future")
	ErrNotYetValid         = errors.New("lease: not yet valid")
	ErrExpired             = errors.New("lease: expired")
	ErrInvalidPublicKey    = errors.New("lease: invalid public key")
)
