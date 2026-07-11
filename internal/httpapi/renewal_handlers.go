package httpapi

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/deni336/DeniLicense/internal/license"
	storeerrors "github.com/deni336/DeniLicense/internal/store"
	"github.com/deni336/DeniLicense/internal/store/postgres"
	"github.com/google/uuid"
)

const renewalChallengeTTL = 5 * time.Minute

type renewalChallengeRequest struct {
	ActivationID string `json:"activationId"`
}

func (s *Server) createRenewalChallenge(w http.ResponseWriter, r *http.Request) {
	var request renewalChallengeRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeProblem(w, r, err)
		return
	}
	activationID, err := uuid.Parse(request.ActivationID)
	if err != nil {
		writeProblem(w, r, storeerrors.ErrInvalid)
		return
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		writeProblem(w, r, err)
		return
	}
	nonceText := base64.RawURLEncoding.EncodeToString(nonce)
	nonceHash := s.renewalNonceHash(nonce)
	challengeID := uuid.New()
	now := time.Now().UTC()
	expiresAt := now.Add(renewalChallengeTTL)
	if err := s.db.CreateRenewalChallenge(r.Context(), challengeID, activationID, nonceHash, expiresAt, now); err != nil {
		writeProblem(w, r, storeerrors.ErrInvalid)
		return
	}
	transcript := renewalTranscript(challengeID, activationID, nonceText)
	writeJSON(w, http.StatusCreated, map[string]any{
		"challengeId":  challengeID,
		"activationId": activationID,
		"nonce":        nonceText,
		"expiresAt":    expiresAt,
		"algorithm":    "Ed25519",
		"transcript":   base64.RawURLEncoding.EncodeToString(transcript),
	})
}

type completeRenewalRequest struct {
	ChallengeID string `json:"challengeId"`
	Nonce       string `json:"nonce"`
	Signature   string `json:"signature"`
}

func (s *Server) completeRenewalChallenge(w http.ResponseWriter, r *http.Request) {
	var request completeRenewalRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeProblem(w, r, err)
		return
	}
	challengeID, err := uuid.Parse(request.ChallengeID)
	if err != nil {
		writeProblem(w, r, storeerrors.ErrInvalid)
		return
	}
	nonce, err := decodeCanonicalBase64URL(request.Nonce, 32)
	if err != nil {
		writeProblem(w, r, storeerrors.ErrInvalid)
		return
	}
	signature, err := decodeCanonicalBase64URL(request.Signature, ed25519.SignatureSize)
	if err != nil {
		writeProblem(w, r, storeerrors.ErrInvalid)
		return
	}
	challenge, err := s.db.RenewalChallenge(r.Context(), challengeID)
	now := time.Now().UTC()
	providedHash := s.renewalNonceHash(nonce)
	if err != nil || challenge.ConsumedAt != nil || !challenge.ExpiresAt.After(now) || !hmac.Equal(challenge.NonceHash[:], providedHash[:]) {
		writeProblem(w, r, storeerrors.ErrInvalid)
		return
	}
	if err := license.ValidateEd25519PublicKey(ed25519.PublicKey(challenge.DevicePublicKey)); err != nil {
		writeProblem(w, r, storeerrors.ErrInvalid)
		return
	}
	transcript := renewalTranscript(challengeID, challenge.ActivationID, request.Nonce)
	if !ed25519.Verify(ed25519.PublicKey(challenge.DevicePublicKey), transcript, signature) {
		writeProblem(w, r, storeerrors.ErrInvalid)
		return
	}
	audit := postgres.AuditEvent{
		ActorKind: "device", Action: "activation.renew", TargetType: "activation",
		RequestID: requestIDFrom(r.Context()), Outcome: "success",
	}
	licensed, activation, err := s.db.ConsumeRenewalChallenge(r.Context(), challengeID, providedHash, now, s.config.ActivationLeaseTTL, audit)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	leaseToken, err := s.signActivationLease(licensed, activation, ed25519.PublicKey(challenge.DevicePublicKey), activation.LastSeenAt)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"activation": activation,
		"lease":      leaseToken,
	})
}

func (s *Server) renewalNonceHash(nonce []byte) [32]byte {
	mac := hmac.New(sha256.New, s.config.DevicePepper)
	_, _ = mac.Write([]byte("DeniLicense/activation-renewal-nonce/v1\x00"))
	_, _ = mac.Write(nonce)
	var digest [32]byte
	copy(digest[:], mac.Sum(nil))
	return digest
}

func renewalTranscript(challengeID, activationID uuid.UUID, canonicalNonce string) []byte {
	return []byte("DeniLicense\x00activation-renewal\x00v1\x00" + challengeID.String() + "\x00" + activationID.String() + "\x00" + canonicalNonce)
}

func decodeCanonicalBase64URL(value string, expectedBytes int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != expectedBytes || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, storeerrors.ErrInvalid
	}
	return decoded, nil
}
