package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestTokenSignVerifyRoundTrip(t *testing.T) {
	key := testSigningKey(t, PurposeOfflineLicenseIssuer)
	claims := testClaims(t, key)
	first, err := SignToken(claims, key)
	if err != nil {
		t.Fatal(err)
	}
	second, err := SignToken(claims, key)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("Ed25519 token signing was not deterministic")
	}
	if !strings.HasPrefix(first, "dlic1.") || strings.Contains(first, "=") {
		t.Fatalf("bad compact format: %s", first)
	}
	parsed, err := VerifyToken(first, key.VerificationKey())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Serial != claims.Serial || parsed.KeyID != key.KeyID() || parsed.ClaimCodeSHA256 != claims.ClaimCodeSHA256 || parsed.ClaimCodeSuffix != claims.ClaimCodeSuffix {
		t.Fatalf("parsed claims mismatch: %#v", parsed)
	}
}

func TestTokenRejectsTamperingAndMalformedComponents(t *testing.T) {
	key := testSigningKey(t, PurposeOfflineLicenseIssuer)
	token, err := SignToken(testClaims(t, key), key)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")

	tamperedSignature := parts[2]
	if tamperedSignature[0] == 'A' {
		tamperedSignature = "B" + tamperedSignature[1:]
	} else {
		tamperedSignature = "A" + tamperedSignature[1:]
	}
	tests := []struct {
		name  string
		token string
		want  error
	}{
		{"wrong version", "dlic2." + parts[1] + "." + parts[2], ErrMalformedToken},
		{"missing component", parts[0] + "." + parts[1], ErrMalformedToken},
		{"extra component", token + ".x", ErrMalformedToken},
		{"empty payload", parts[0] + ".." + parts[2], ErrMalformedToken},
		{"payload padding", parts[0] + "." + parts[1] + "=." + parts[2], ErrMalformedToken},
		{"signature padding", token + "=", ErrMalformedToken},
		{"standard base64", parts[0] + ".+" + parts[1][1:] + "." + parts[2], ErrMalformedToken},
		{"bad signature", parts[0] + "." + parts[1] + "." + tamperedSignature, ErrInvalidSignature},
		{"too large", strings.Repeat("x", MaxTokenBytes+1), ErrMalformedToken},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifyToken(tt.token, key.VerificationKey())
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestTokenAuthenticatesNonCanonicalPayloadBeforeRejectingIt(t *testing.T) {
	key := testSigningKey(t, PurposeOfflineLicenseIssuer)
	payload, err := testClaims(t, key).CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	payload = append([]byte(" "), payload...)
	token := signRawPayload(payload, key)
	if _, err := VerifyToken(token, key.VerificationKey()); !errors.Is(err, ErrNonCanonicalPayload) {
		t.Fatalf("error = %v, want ErrNonCanonicalPayload", err)
	}

	unknown := append(append([]byte(nil), payload[1:len(payload)-1]...), []byte(`,"unknown":true}`)...)
	if _, err := VerifyToken(signRawPayload(unknown, key), key.VerificationKey()); !errors.Is(err, ErrInvalidClaims) {
		t.Fatalf("unknown field error = %v", err)
	}
}

func TestInspectUnverifiedIsStrictButDoesNotTrustSignature(t *testing.T) {
	key := testSigningKey(t, PurposeOfflineLicenseIssuer)
	claims := testClaims(t, key)
	token, err := SignToken(claims, key)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	forgedSignature := parts[2]
	if forgedSignature[0] == 'A' {
		forgedSignature = "B" + forgedSignature[1:]
	} else {
		forgedSignature = "A" + forgedSignature[1:]
	}
	forged := parts[0] + "." + parts[1] + "." + forgedSignature

	inspected, err := InspectUnverified(forged)
	if err != nil {
		t.Fatal(err)
	}
	if inspected.KeyID != key.KeyID() || inspected.Serial != claims.Serial {
		t.Fatalf("inspected claims mismatch: %#v", inspected)
	}
	if _, err := VerifyToken(forged, key.VerificationKey()); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("forged VerifyToken error = %v", err)
	}

	payload, err := claims.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InspectUnverified(signRawPayload(append([]byte(" "), payload...), key)); !errors.Is(err, ErrNonCanonicalPayload) {
		t.Fatalf("noncanonical InspectUnverified error = %v", err)
	}
	if _, err := InspectUnverified("dlic1.bad.bad"); !errors.Is(err, ErrMalformedToken) {
		t.Fatalf("malformed InspectUnverified error = %v", err)
	}
}

func TestTokenKeyIDAndPurposeSeparation(t *testing.T) {
	issuer := testSigningKey(t, PurposeOfflineLicenseIssuer)
	other := make([]byte, ed25519.SeedSize)
	other[0] = 99
	otherIssuer, err := NewSigningKeyFromSeed(other, PurposeOfflineLicenseIssuer)
	if err != nil {
		t.Fatal(err)
	}
	receiptKey, err := NewSigningKeyFromSeed(other, PurposeActivationReceiptSigner)
	if err != nil {
		t.Fatal(err)
	}

	claims := testClaims(t, issuer)
	if _, err := SignToken(claims, otherIssuer); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("wrong signing key error = %v", err)
	}
	if _, err := SignToken(claims, receiptKey); !errors.Is(err, ErrWrongKeyPurpose) {
		t.Fatalf("receipt signing key error = %v", err)
	}
	token, err := SignToken(claims, issuer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyToken(token, otherIssuer.VerificationKey()); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("other public key error = %v", err)
	}
	if _, err := VerifyToken(token, receiptKey.VerificationKey()); !errors.Is(err, ErrWrongKeyPurpose) {
		t.Fatalf("receipt public key error = %v", err)
	}
}

func TestVerifyTokenForUse(t *testing.T) {
	key := testSigningKey(t, PurposeOfflineLicenseIssuer)
	claims := testClaims(t, key)
	token, err := SignToken(claims, key)
	if err != nil {
		t.Fatal(err)
	}
	options := VerificationOptions{
		ExpectedIssuer:   claims.Issuer,
		ExpectedAudience: claims.Audience,
		Now:              claims.NotBefore,
	}
	if _, err := VerifyTokenForUse(token, key.VerificationKey(), options); err != nil {
		t.Fatal(err)
	}
	options.ExpectedIssuer = "different"
	if _, err := VerifyTokenForUse(token, key.VerificationKey(), options); !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("issuer error = %v", err)
	}
	options.ExpectedIssuer = claims.Issuer
	options.ExpectedAudience = "different"
	if _, err := VerifyTokenForUse(token, key.VerificationKey(), options); !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("audience error = %v", err)
	}
	options.ExpectedAudience = claims.Audience
	options.ClockSkew = MaxClockSkew + time.Nanosecond
	if _, err := VerifyTokenForUse(token, key.VerificationKey(), options); !errors.Is(err, ErrInvalidClaims) {
		t.Fatalf("clock skew error = %v", err)
	}
	options.ClockSkew = 0
	options.ExpectedIssuer = ""
	if _, err := VerifyTokenForUse(token, key.VerificationKey(), options); !errors.Is(err, ErrInvalidClaims) {
		t.Fatalf("missing expected issuer error = %v", err)
	}
	options.ExpectedIssuer = claims.Issuer
	options.ExpectedAudience = ""
	if _, err := VerifyTokenForUse(token, key.VerificationKey(), options); !errors.Is(err, ErrInvalidClaims) {
		t.Fatalf("missing expected audience error = %v", err)
	}
}

func signRawPayload(payload []byte, key *SigningKey) string {
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	input := TokenVersion + "." + encoded
	signature := ed25519.Sign(key.private, []byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}
