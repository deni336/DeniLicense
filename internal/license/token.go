package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	TokenVersion    = "dlic1"
	MaxPayloadBytes = 16 * 1024
	MaxTokenBytes   = 24 * 1024
	MaxClockSkew    = 10 * time.Minute
)

// VerificationOptions adds required application-context and wall-clock checks
// after signature verification. ExpectedIssuer and ExpectedAudience must both
// be set. A zero Now uses the current UTC time.
type VerificationOptions struct {
	ExpectedIssuer   string
	ExpectedAudience string
	Now              time.Time
	ClockSkew        time.Duration
}

// SignToken emits dlic1.<payload>.<signature>. Ed25519 signs the ASCII version
// and encoded payload together, binding both the format version and content.
func SignToken(claims Claims, key *SigningKey) (string, error) {
	if !key.valid() {
		return "", errors.New("license: invalid signing key")
	}
	if key.purpose != PurposeOfflineLicenseIssuer {
		return "", ErrWrongKeyPurpose
	}
	if claims.KeyID != key.KeyID() {
		return "", ErrKeyMismatch
	}
	payload, err := claims.CanonicalJSON()
	if err != nil {
		return "", err
	}
	if len(payload) > MaxPayloadBytes {
		return "", fmt.Errorf("%w: payload exceeds %d bytes", ErrMalformedToken, MaxPayloadBytes)
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := TokenVersion + "." + encodedPayload
	signature := ed25519.Sign(key.private, []byte(signingInput))
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
	if len(token) > MaxTokenBytes {
		return "", fmt.Errorf("%w: token exceeds %d bytes", ErrMalformedToken, MaxTokenBytes)
	}
	return token, nil
}

// VerifyToken authenticates and parses a token. It intentionally does not use
// the wall clock; call VerifyTokenForUse or Claims.ValidateAt at the point of
// use. This separation allows a future-dated offline grant to be imported.
func VerifyToken(token string, key VerificationKey) (Claims, error) {
	if !key.valid() {
		return Claims{}, errors.New("license: invalid verification key")
	}
	if key.purpose != PurposeOfflineLicenseIssuer {
		return Claims{}, ErrWrongKeyPurpose
	}
	compact, err := parseCompactToken(token)
	if err != nil {
		return Claims{}, err
	}
	if !ed25519.Verify(key.public, []byte(compact.signingInput), compact.signature) {
		return Claims{}, ErrInvalidSignature
	}
	claims, err := parseCanonicalClaims(compact.payload)
	if err != nil {
		return Claims{}, err
	}
	if claims.KeyID != key.KeyID() {
		return Claims{}, ErrKeyMismatch
	}
	return claims, nil
}

// InspectUnverified strictly decodes a token without checking its signature.
// Its returned fields are attacker-controlled and MUST only be used to select
// a locally trusted verification key. Call VerifyToken with that key before
// importing a grant or making any authorization decision.
func InspectUnverified(token string) (Claims, error) {
	compact, err := parseCompactToken(token)
	if err != nil {
		return Claims{}, err
	}
	return parseCanonicalClaims(compact.payload)
}

type compactToken struct {
	signingInput string
	payload      []byte
	signature    []byte
}

func parseCompactToken(token string) (compactToken, error) {
	if len(token) == 0 || len(token) > MaxTokenBytes {
		return compactToken{}, fmt.Errorf("%w: invalid token size", ErrMalformedToken)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != TokenVersion {
		return compactToken{}, fmt.Errorf("%w: expected three dlic1 components", ErrMalformedToken)
	}
	maxEncodedPayload := base64.RawURLEncoding.EncodedLen(MaxPayloadBytes)
	if len(parts[1]) == 0 || len(parts[1]) > maxEncodedPayload {
		return compactToken{}, fmt.Errorf("%w: invalid payload component size", ErrMalformedToken)
	}
	if len(parts[2]) != base64.RawURLEncoding.EncodedLen(ed25519.SignatureSize) {
		return compactToken{}, fmt.Errorf("%w: invalid signature component size", ErrMalformedToken)
	}
	payload, err := decodeRawBase64URL(parts[1])
	if err != nil || len(payload) > MaxPayloadBytes {
		return compactToken{}, fmt.Errorf("%w: invalid payload encoding", ErrMalformedToken)
	}
	signature, err := decodeRawBase64URL(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return compactToken{}, fmt.Errorf("%w: invalid signature encoding", ErrMalformedToken)
	}
	return compactToken{
		signingInput: parts[0] + "." + parts[1],
		payload:      payload,
		signature:    signature,
	}, nil
}

// VerifyTokenForUse performs signature, issuer, audience, and temporal checks.
func VerifyTokenForUse(token string, key VerificationKey, options VerificationOptions) (Claims, error) {
	claims, err := VerifyToken(token, key)
	if err != nil {
		return Claims{}, err
	}
	if options.ExpectedIssuer == "" {
		return Claims{}, invalidClaim("expected_issuer", "must not be empty")
	}
	if options.ExpectedAudience == "" {
		return Claims{}, invalidClaim("expected_audience", "must not be empty")
	}
	if claims.Issuer != options.ExpectedIssuer {
		return Claims{}, ErrIssuerMismatch
	}
	if claims.Audience != options.ExpectedAudience {
		return Claims{}, ErrAudienceMismatch
	}
	if options.ClockSkew < 0 || options.ClockSkew > MaxClockSkew {
		return Claims{}, invalidClaim("clock_skew", fmt.Sprintf("must be between 0 and %s", MaxClockSkew))
	}
	now := options.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := claims.ValidateAt(now, options.ClockSkew); err != nil {
		return Claims{}, err
	}
	return claims, nil
}

func decodeRawBase64URL(component string) ([]byte, error) {
	if component == "" || strings.Contains(component, "=") {
		return nil, errors.New("empty or padded base64url")
	}
	for _, c := range []byte(component) {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
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
