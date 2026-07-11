package license

import "errors"

var (
	// ErrInvalidClaims means a token's claims are incomplete, malformed, or
	// internally inconsistent.
	ErrInvalidClaims = errors.New("license: invalid claims")

	// ErrMalformedToken means a compact license token cannot be decoded using
	// the exact dlic1 wire format.
	ErrMalformedToken = errors.New("license: malformed token")

	// ErrNonCanonicalPayload means the JSON payload was valid JSON but was not
	// the one deterministic representation emitted by this package.
	ErrNonCanonicalPayload = errors.New("license: non-canonical payload")

	// ErrInvalidSignature means the token was not signed by the supplied key.
	ErrInvalidSignature = errors.New("license: invalid signature")

	// ErrKeyMismatch means claims name a different key than the supplied key.
	ErrKeyMismatch      = errors.New("license: key ID mismatch")
	ErrWrongKeyPurpose  = errors.New("license: wrong key purpose")
	ErrIssuerMismatch   = errors.New("license: issuer mismatch")
	ErrAudienceMismatch = errors.New("license: audience mismatch")

	// ErrInvalidKeyFile means an encrypted or public key file is malformed or
	// uses unsupported/unsafe parameters.
	ErrInvalidKeyFile = errors.New("license: invalid key file")

	// ErrKeyDecryption means a key file could not be authenticated. This error
	// intentionally does not distinguish a bad passphrase from tampering.
	ErrKeyDecryption = errors.New("license: key decryption failed")

	// ErrNotYetValid and ErrExpired are returned by temporal validation.
	ErrNotYetValid = errors.New("license: not yet valid")
	ErrExpired     = errors.New("license: expired")
)
