package lease

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	TokenVersion    = "dllease1"
	MaxPayloadBytes = 16 * 1024
	MaxTokenBytes   = 24 * 1024
	MaxClockLeeway  = 10 * time.Minute

	// The NUL-delimited prefix makes signatures from this protocol unusable in
	// other Ed25519 protocols, even if they happen to sign similar bytes.
	signatureDomain = "DeniLicense\x00activation-lease\x00v1\x00"
)

// VerifyOptions contains mandatory relying-party context. A zero Now reads
// the current clock. ClockLeeway is allowed only for clock synchronization;
// values over MaxClockLeeway are rejected.
type VerifyOptions struct {
	ExpectedIssuer              string
	ExpectedAudience            string
	ExpectedDeviceKeyThumbprint string
	Now                         time.Time
	ClockLeeway                 time.Duration
}

// Sign returns dllease1.<canonical payload>.<Ed25519 signature>. The signer is
// supplied only for this call and is never retained. It must expose an
// Ed25519 public key and implement pure Ed25519 signing (Hash(0)).
func Sign(claims Claims, signer crypto.Signer) (string, error) {
	if signer == nil {
		return "", errors.New("lease: nil signer")
	}
	publicKey, ok := signer.Public().(ed25519.PublicKey)
	if !ok {
		return "", fmt.Errorf("%w: signer must expose an Ed25519 public key", ErrInvalidPublicKey)
	}
	publicKey = append(ed25519.PublicKey(nil), publicKey...)
	if err := validateEd25519PublicKey(publicKey); err != nil {
		return "", err
	}
	if !equalPublicValue(claims.KeyID, KeyID(publicKey)) {
		return "", ErrKeyMismatch
	}
	payload, err := claims.CanonicalJSON()
	if err != nil {
		return "", err
	}
	if len(payload) == 0 || len(payload) > MaxPayloadBytes {
		return "", fmt.Errorf("%w: payload exceeds %d bytes", ErrMalformedToken, MaxPayloadBytes)
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	message := signingMessage(encodedPayload)
	signature, err := signer.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil {
		return "", fmt.Errorf("lease: sign: %w", err)
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, message, signature) {
		return "", errors.New("lease: signer returned an invalid Ed25519 signature")
	}
	token := TokenVersion + "." + encodedPayload + "." + base64.RawURLEncoding.EncodeToString(signature)
	if len(token) > MaxTokenBytes {
		return "", fmt.Errorf("%w: token exceeds %d bytes", ErrMalformedToken, MaxTokenBytes)
	}
	return token, nil
}

// Verify authenticates a token and enforces its issuer, audience, device
// binding, and validity window. All three identity expectations are required.
func Verify(token string, publicKey ed25519.PublicKey, options VerifyOptions) (Claims, error) {
	publicKey = append(ed25519.PublicKey(nil), publicKey...)
	if err := validateEd25519PublicKey(publicKey); err != nil {
		return Claims{}, err
	}
	if err := validateVerifyOptions(options); err != nil {
		return Claims{}, err
	}
	if len(token) == 0 || len(token) > MaxTokenBytes {
		return Claims{}, fmt.Errorf("%w: invalid token size", ErrMalformedToken)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != TokenVersion {
		return Claims{}, fmt.Errorf("%w: expected three dllease1 components", ErrMalformedToken)
	}
	maxEncodedPayload := base64.RawURLEncoding.EncodedLen(MaxPayloadBytes)
	if len(parts[1]) == 0 || len(parts[1]) > maxEncodedPayload {
		return Claims{}, fmt.Errorf("%w: invalid payload component size", ErrMalformedToken)
	}
	if len(parts[2]) != base64.RawURLEncoding.EncodedLen(ed25519.SignatureSize) {
		return Claims{}, fmt.Errorf("%w: invalid signature component size", ErrMalformedToken)
	}
	payload, err := decodeRawBase64URL(parts[1])
	if err != nil || len(payload) == 0 || len(payload) > MaxPayloadBytes {
		return Claims{}, fmt.Errorf("%w: invalid payload encoding", ErrMalformedToken)
	}
	signature, err := decodeRawBase64URL(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Claims{}, fmt.Errorf("%w: invalid signature encoding", ErrMalformedToken)
	}
	if !ed25519.Verify(publicKey, signingMessage(parts[1]), signature) {
		return Claims{}, ErrInvalidSignature
	}
	claims, err := parseCanonicalClaims(payload)
	if err != nil {
		return Claims{}, err
	}
	if !equalPublicValue(claims.KeyID, KeyID(publicKey)) {
		return Claims{}, ErrKeyMismatch
	}
	if claims.Issuer != options.ExpectedIssuer {
		return Claims{}, ErrIssuerMismatch
	}
	if claims.Audience != options.ExpectedAudience {
		return Claims{}, ErrAudienceMismatch
	}
	if !equalPublicValue(claims.DeviceKeyThumbprint, options.ExpectedDeviceKeyThumbprint) {
		return Claims{}, ErrDeviceMismatch
	}
	now := options.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if claims.IssuedAt.After(now.Add(options.ClockLeeway)) {
		return Claims{}, ErrIssuedInFuture
	}
	if claims.NotBefore.After(now.Add(options.ClockLeeway)) {
		return Claims{}, ErrNotYetValid
	}
	if !now.Add(-options.ClockLeeway).Before(claims.ExpiresAt) {
		return Claims{}, ErrExpired
	}
	return claims, nil
}

// VerifyJWK is Verify with a validated public JWK descriptor.
func VerifyJWK(token string, key JWK, options VerifyOptions) (Claims, error) {
	publicKey, err := key.PublicKey()
	if err != nil {
		return Claims{}, err
	}
	return Verify(token, publicKey, options)
}

func validateVerifyOptions(options VerifyOptions) error {
	if err := validateText("expected issuer", options.ExpectedIssuer, MaxIssuerBytes); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidOptions, err)
	}
	if err := validateAudience(options.ExpectedAudience); err != nil {
		return fmt.Errorf("%w: expected audience: %v", ErrInvalidOptions, err)
	}
	if !validDigest(options.ExpectedDeviceKeyThumbprint) {
		return fmt.Errorf("%w: expected device key thumbprint must be a full SHA-256 base64url digest", ErrInvalidOptions)
	}
	if options.ClockLeeway < 0 || options.ClockLeeway > MaxClockLeeway {
		return fmt.Errorf("%w: clock leeway must be between 0 and %s", ErrInvalidOptions, MaxClockLeeway)
	}
	return nil
}

func signingMessage(encodedPayload string) []byte {
	return []byte(signatureDomain + TokenVersion + "." + encodedPayload)
}

func decodeRawBase64URL(component string) ([]byte, error) {
	if component == "" || strings.Contains(component, "=") {
		return nil, errors.New("empty or padded base64url")
	}
	for _, character := range []byte(component) {
		if !((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_') {
			return nil, errors.New("invalid base64url character")
		}
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(component)
	if err != nil {
		return nil, err
	}
	if base64.RawURLEncoding.EncodeToString(decoded) != component {
		return nil, errors.New("non-canonical base64url")
	}
	return decoded, nil
}

func equalPublicValue(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
