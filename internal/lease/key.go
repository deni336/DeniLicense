package lease

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"

	licensekey "github.com/deni336/DeniLicense/internal/license"
)

const (
	jwkKeyType   = "OKP"
	jwkCurve     = "Ed25519"
	jwkAlgorithm = "EdDSA"
	jwkUse       = "sig"
)

// JWK is the public, safe-to-distribute representation of an Ed25519 lease
// verification key. Its fields follow RFC 8037 JWK naming.
type JWK struct {
	KeyType   string `json:"kty"`
	Curve     string `json:"crv"`
	Algorithm string `json:"alg"`
	Use       string `json:"use"`
	KeyID     string `json:"kid"`
	X         string `json:"x"`
}

// JWKS is suitable for publishing a rotation set to clients.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// NewJWK converts an Ed25519 public key to a validated public descriptor.
func NewJWK(publicKey ed25519.PublicKey) (JWK, error) {
	if err := validateEd25519PublicKey(publicKey); err != nil {
		return JWK{}, err
	}
	return JWK{
		KeyType:   jwkKeyType,
		Curve:     jwkCurve,
		Algorithm: jwkAlgorithm,
		Use:       jwkUse,
		KeyID:     KeyID(publicKey),
		X:         base64.RawURLEncoding.EncodeToString(publicKey),
	}, nil
}

// Validate checks both JWK metadata and the binding between kid and x.
func (j JWK) Validate() error {
	if j.KeyType != jwkKeyType || j.Curve != jwkCurve || j.Algorithm != jwkAlgorithm || j.Use != jwkUse {
		return fmt.Errorf("%w: expected OKP/Ed25519/EdDSA/sig metadata", ErrInvalidPublicKey)
	}
	publicKey, err := decodeRawBase64URL(j.X)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: x must be a canonical Ed25519 public key", ErrInvalidPublicKey)
	}
	if err := validateEd25519PublicKey(publicKey); err != nil {
		return err
	}
	if !validDigest(j.KeyID) || !equalPublicValue(j.KeyID, digestBytes(publicKey)) {
		return fmt.Errorf("%w: kid does not match x", ErrInvalidPublicKey)
	}
	return nil
}

// PublicKey returns an independent copy of the JWK's Ed25519 public key.
func (j JWK) PublicKey() (ed25519.PublicKey, error) {
	if err := j.Validate(); err != nil {
		return nil, err
	}
	decoded, _ := decodeRawBase64URL(j.X)
	return ed25519.PublicKey(append([]byte(nil), decoded...)), nil
}

// Lookup returns the unique validated key with kid. Duplicate key IDs make a
// set invalid rather than silently selecting one entry.
func (set JWKS) Lookup(kid string) (JWK, error) {
	if !validDigest(kid) {
		return JWK{}, fmt.Errorf("%w: invalid kid", ErrInvalidPublicKey)
	}
	var match *JWK
	seen := make(map[string]struct{}, len(set.Keys))
	for index := range set.Keys {
		key := set.Keys[index]
		if err := key.Validate(); err != nil {
			return JWK{}, fmt.Errorf("%w: keys[%d]: %v", ErrInvalidPublicKey, index, err)
		}
		if _, exists := seen[key.KeyID]; exists {
			return JWK{}, fmt.Errorf("%w: duplicate kid %q", ErrInvalidPublicKey, key.KeyID)
		}
		seen[key.KeyID] = struct{}{}
		if key.KeyID == kid {
			copyOfKey := key
			match = &copyOfKey
		}
	}
	if match == nil {
		return JWK{}, errors.New("lease: public key not found")
	}
	return *match, nil
}

// KeyID is the full SHA-256 digest of the raw Ed25519 public key, encoded as
// unpadded base64url. Invalid-length values return an empty string.
func KeyID(publicKey ed25519.PublicKey) string {
	if len(publicKey) != ed25519.PublicKeySize {
		return ""
	}
	return digestBytes(publicKey)
}

// DeviceKeyThumbprint binds a lease to the exact raw Ed25519 device key.
func DeviceKeyThumbprint(publicKey ed25519.PublicKey) (string, error) {
	if err := validateEd25519PublicKey(publicKey); err != nil {
		return "", fmt.Errorf("%w: invalid device key: %v", ErrInvalidPublicKey, err)
	}
	return digestBytes(publicKey), nil
}

func validateEd25519PublicKey(publicKey []byte) error {
	if err := licensekey.ValidateEd25519PublicKey(publicKey); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}
	return nil
}
