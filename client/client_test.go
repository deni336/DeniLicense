package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/google/uuid"
)

func TestSignRenewalChallenge(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	challenge := testRenewalChallenge(t)
	signatureText, err := SignRenewalChallenge(privateKey, challenge, challenge.ActivationID)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(signatureText)
	if err != nil {
		t.Fatal(err)
	}
	transcript, err := base64.RawURLEncoding.Strict().DecodeString(challenge.Transcript)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(publicKey, transcript, signature) {
		t.Fatal("renewal signature did not verify")
	}
}

func TestRenewalChallengeBindsExpectedActivation(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	challenge := testRenewalChallenge(t)
	if _, err := SignRenewalChallenge(privateKey, challenge, uuid.NewString()); err == nil {
		t.Fatal("challenge for another activation was accepted")
	}
}

func TestRenewalChallengeRejectsTamperedTranscript(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	challenge := testRenewalChallenge(t)
	challenge.Transcript = base64.RawURLEncoding.EncodeToString([]byte("attacker-chosen message"))
	if _, err := SignRenewalChallenge(privateKey, challenge, challenge.ActivationID); err == nil {
		t.Fatal("attacker-chosen transcript was signed")
	}
}

func TestRenewalChallengeRejectsMalformedFields(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	baseline := testRenewalChallenge(t)
	tests := []struct {
		name   string
		mutate func(*RenewalChallenge)
	}{
		{"wrong algorithm", func(value *RenewalChallenge) { value.Algorithm = "RSA" }},
		{"noncanonical challenge ID", func(value *RenewalChallenge) { value.ChallengeID = "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE" }},
		{"nil activation ID", func(value *RenewalChallenge) { value.ActivationID = uuid.Nil.String() }},
		{"padded nonce", func(value *RenewalChallenge) { value.Nonce += "=" }},
		{"short nonce", func(value *RenewalChallenge) { value.Nonce = base64.RawURLEncoding.EncodeToString([]byte("short")) }},
		{"missing transcript", func(value *RenewalChallenge) { value.Transcript = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			challenge := baseline
			test.mutate(&challenge)
			if _, err := SignRenewalChallenge(privateKey, challenge, baseline.ActivationID); err == nil {
				t.Fatal("malformed challenge was accepted")
			}
		})
	}
}

func TestRenewalChallengeRejectsInconsistentPrivateKey(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	inconsistent := append(ed25519.PrivateKey(nil), privateKey...)
	copy(inconsistent[ed25519.SeedSize:], otherPublic)
	challenge := testRenewalChallenge(t)
	if _, err := SignRenewalChallenge(inconsistent, challenge, challenge.ActivationID); err == nil {
		t.Fatal("inconsistent Ed25519 private key was accepted")
	}
	if _, err := SignRenewalChallenge(privateKey[:ed25519.SeedSize], challenge, challenge.ActivationID); err == nil {
		t.Fatal("short Ed25519 private key was accepted")
	}
}

func testRenewalChallenge(t *testing.T) RenewalChallenge {
	t.Helper()
	challengeID := uuid.NewString()
	activationID := uuid.NewString()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	nonceText := base64.RawURLEncoding.EncodeToString(nonce)
	transcript := []byte("DeniLicense\x00activation-renewal\x00v1\x00" + challengeID + "\x00" + activationID + "\x00" + nonceText)
	return RenewalChallenge{
		ChallengeID: challengeID, ActivationID: activationID, Nonce: nonceText,
		Algorithm: "Ed25519", Transcript: base64.RawURLEncoding.EncodeToString(transcript),
	}
}
