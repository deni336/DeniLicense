// Package client exposes the safe, public verification surface used by Go
// product integrations. It never accepts or contains a DeniLicense private
// signing key.
package client

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/deni336/DeniLicense/internal/lease"
	"github.com/deni336/DeniLicense/internal/license"
	"github.com/google/uuid"
)

type ActivationClaims = lease.Claims
type VerifyOptions = lease.VerifyOptions
type JWK = lease.JWK
type JWKS = lease.JWKS

const (
	ActivationLeaseVersion  = lease.TokenVersion
	MaxActivationLeaseBytes = lease.MaxTokenBytes
)

// VerifyLease authenticates a device-bound activation lease. Expected issuer,
// product audience, and device thumbprint are mandatory in options.
func VerifyLease(token string, publicKey ed25519.PublicKey, options VerifyOptions) (ActivationClaims, error) {
	return lease.Verify(token, publicKey, options)
}

func VerifyLeaseJWK(token string, key JWK, options VerifyOptions) (ActivationClaims, error) {
	return lease.VerifyJWK(token, key, options)
}

func DeviceKeyThumbprint(publicKey ed25519.PublicKey) (string, error) {
	return lease.DeviceKeyThumbprint(publicKey)
}

// RenewalChallenge contains the security-relevant fields returned by the
// activation-challenge API. SignRenewalChallenge reconstructs the transcript
// from these fields instead of treating the server-provided transcript as an
// arbitrary message to sign.
type RenewalChallenge struct {
	ChallengeID  string `json:"challengeId"`
	ActivationID string `json:"activationId"`
	Nonce        string `json:"nonce"`
	Algorithm    string `json:"algorithm"`
	Transcript   string `json:"transcript"`
}

const renewalTranscriptDomain = "DeniLicense\x00activation-renewal\x00v1\x00"

// SignRenewalChallenge validates a structured challenge, binds it to the
// activation the caller expects, reconstructs the exact renewal transcript,
// and signs it directly with standard Ed25519.
func SignRenewalChallenge(privateKey ed25519.PrivateKey, challenge RenewalChallenge, expectedActivationID string) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", errors.New("denilicense client: invalid Ed25519 private key length")
	}
	privateCopy := append(ed25519.PrivateKey(nil), privateKey...)
	defer clear(privateCopy)
	canonicalPrivate := ed25519.NewKeyFromSeed(privateCopy[:ed25519.SeedSize])
	defer clear(canonicalPrivate)
	if subtle.ConstantTimeCompare(canonicalPrivate, privateCopy) != 1 {
		return "", errors.New("denilicense client: inconsistent Ed25519 private key")
	}
	publicKey := canonicalPrivate.Public().(ed25519.PublicKey)
	if err := license.ValidateEd25519PublicKey(publicKey); err != nil {
		return "", err
	}
	if challenge.Algorithm != "Ed25519" {
		return "", errors.New("denilicense client: renewal algorithm must be Ed25519")
	}
	challengeID, err := parseCanonicalUUID("challengeId", challenge.ChallengeID)
	if err != nil {
		return "", err
	}
	activationID, err := parseCanonicalUUID("activationId", challenge.ActivationID)
	if err != nil {
		return "", err
	}
	expectedID, err := parseCanonicalUUID("expected activation ID", expectedActivationID)
	if err != nil {
		return "", err
	}
	if activationID != expectedID {
		return "", errors.New("denilicense client: challenge activation does not match the expected activation")
	}
	nonce, err := decodeFixedBase64URL(challenge.Nonce, 32)
	if err != nil {
		return "", fmt.Errorf("denilicense client: invalid renewal nonce: %w", err)
	}
	canonicalNonce := base64.RawURLEncoding.EncodeToString(nonce)
	transcript := []byte(renewalTranscriptDomain + challengeID.String() + "\x00" + activationID.String() + "\x00" + canonicalNonce)
	encodedTranscript := base64.RawURLEncoding.EncodeToString(transcript)
	if challenge.Transcript != encodedTranscript {
		return "", errors.New("denilicense client: renewal transcript does not match the structured challenge")
	}
	signature := ed25519.Sign(canonicalPrivate, transcript)
	return base64.RawURLEncoding.EncodeToString(signature), nil
}

func parseCanonicalUUID(field, value string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(value)
	version := parsed.Version()
	if err != nil || parsed == uuid.Nil || parsed.String() != value || parsed.Variant() != uuid.RFC4122 || version < 1 || version > 8 {
		return uuid.Nil, fmt.Errorf("denilicense client: %s must be a canonical non-zero RFC UUID", field)
	}
	return parsed, nil
}

func decodeFixedBase64URL(value string, expectedBytes int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != expectedBytes || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("value is not canonical unpadded base64url of the expected size")
	}
	return decoded, nil
}
