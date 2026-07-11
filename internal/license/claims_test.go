package license

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func testSigningKey(t testing.TB, purpose KeyPurpose) *SigningKey {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	key, err := NewSigningKeyFromSeed(seed, purpose)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testClaims(t testing.TB, key *SigningKey) Claims {
	t.Helper()
	codeHash := sha256.Sum256([]byte("domain-separated test code material"))
	codeDigest := EncodeClaimCodeSHA256(codeHash)
	expires := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	return Claims{
		Issuer:          "https://licenses.example.test",
		KeyID:           key.KeyID(),
		Audience:        "desktop.pro",
		Serial:          "123e4567-e89b-12d3-a456-426614174000",
		Subject:         "customer-2048",
		ClaimCodeSHA256: codeDigest,
		ClaimCodeSuffix: "42NV",
		IssuedAt:        time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		NotBefore:       time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		ExpiresAt:       &expires,
		MaxActivations:  3,
		Entitlements: map[string]any{
			"edition":       "pro",
			"feature.audit": true,
			"seats":         int64(25),
		},
	}
}

func TestClaimsCanonicalJSON(t *testing.T) {
	key := testSigningKey(t, PurposeOfflineLicenseIssuer)
	claims := testClaims(t, key)
	encoded, err := claims.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"iss":"https://licenses.example.test","kid":"` + key.KeyID() + `","aud":"desktop.pro","jti":"123e4567-e89b-12d3-a456-426614174000","sub":"customer-2048","claim_code_sha256":"` + claims.ClaimCodeSHA256 + `","claim_code_suffix":"42NV","iat":"2026-01-02T03:04:05Z","nbf":"2026-01-02T03:04:05Z","exp":"2027-01-02T03:04:05Z","max_activations":3,"entitlements":{"edition":"pro","feature.audit":true,"seats":25}}`
	if string(encoded) != expected {
		t.Fatalf("canonical JSON mismatch\n got: %s\nwant: %s", encoded, expected)
	}

	parsed, err := parseCanonicalClaims(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := parsed.Entitlements["seats"].(int64); !ok || got != 25 {
		t.Fatalf("integer entitlement = %#v (%T)", parsed.Entitlements["seats"], parsed.Entitlements["seats"])
	}
}

func TestClaimsRejectNonCanonicalAndUnknownJSON(t *testing.T) {
	key := testSigningKey(t, PurposeOfflineLicenseIssuer)
	canonical, err := testClaims(t, key).CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		payload []byte
		want    error
	}{
		{"leading whitespace", append([]byte(" "), canonical...), ErrNonCanonicalPayload},
		{"trailing whitespace", append(append([]byte(nil), canonical...), '\n'), ErrNonCanonicalPayload},
		{"unknown field", append(append([]byte(nil), canonical[:len(canonical)-1]...), []byte(`,"extra":true}`)...), ErrInvalidClaims},
		{"duplicate field", append([]byte(`{"iss":"shadow",`), canonical[1:]...), ErrInvalidClaims},
		{"case-aliased field", append(append([]byte(nil), canonical[:len(canonical)-1]...), []byte(`,"ISS":"shadow"}`)...), ErrInvalidClaims},
		{"null expiry", []byte(strings.Replace(string(canonical), `"exp":"2027-01-02T03:04:05Z"`, `"exp":null`, 1)), ErrNonCanonicalPayload},
		{"non-integer number", []byte(strings.Replace(string(canonical), `"seats":25`, `"seats":2.5e1`, 1)), ErrInvalidClaims},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseCanonicalClaims(tt.payload)
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestClaimsValidation(t *testing.T) {
	key := testSigningKey(t, PurposeOfflineLicenseIssuer)
	base := testClaims(t, key)

	tests := []struct {
		name   string
		mutate func(*Claims)
	}{
		{"missing issuer", func(c *Claims) { c.Issuer = "" }},
		{"bad audience", func(c *Claims) { c.Audience = "bad product" }},
		{"uppercase uuid", func(c *Claims) { c.Serial = strings.ToUpper(c.Serial) }},
		{"zero uuid", func(c *Claims) { c.Serial = "00000000-0000-0000-0000-000000000000" }},
		{"missing subject", func(c *Claims) { c.Subject = "" }},
		{"bad key id", func(c *Claims) { c.KeyID = "abc" }},
		{"bad claim code digest", func(c *Claims) { c.ClaimCodeSHA256 += "=" }},
		{"missing claim code suffix", func(c *Claims) { c.ClaimCodeSuffix = "" }},
		{"lowercase claim code suffix", func(c *Claims) { c.ClaimCodeSuffix = "42nv" }},
		{"ambiguous claim code suffix", func(c *Claims) { c.ClaimCodeSuffix = "I0LU" }},
		{"local iat", func(c *Claims) { c.IssuedAt = c.IssuedAt.In(time.FixedZone("zero", 0)) }},
		{"not-before before issue", func(c *Claims) { c.NotBefore = c.IssuedAt.Add(-time.Second) }},
		{"expiry before start", func(c *Claims) { v := c.NotBefore; c.ExpiresAt = &v }},
		{"zero activations", func(c *Claims) { c.MaxActivations = 0 }},
		{"nil entitlements", func(c *Claims) { c.Entitlements = nil }},
		{"bad entitlement name", func(c *Claims) { c.Entitlements = map[string]any{"Upper": true} }},
		{"float entitlement", func(c *Claims) { c.Entitlements = map[string]any{"ratio": 1.0} }},
		{"nested entitlement", func(c *Claims) { c.Entitlements = map[string]any{"config": map[string]any{}} }},
		{"huge unsigned entitlement", func(c *Claims) { c.Entitlements = map[string]any{"limit": ^uint64(0)} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := base
			claims.Entitlements = cloneEntitlements(base.Entitlements)
			tt.mutate(&claims)
			if err := claims.Validate(); !errors.Is(err, ErrInvalidClaims) {
				t.Fatalf("Validate error = %v, want ErrInvalidClaims", err)
			}
		})
	}
}

func TestClaimsValidateAt(t *testing.T) {
	key := testSigningKey(t, PurposeOfflineLicenseIssuer)
	claims := testClaims(t, key)
	if err := claims.ValidateAt(claims.NotBefore.Add(-time.Minute), 0); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("before nbf: %v", err)
	}
	if err := claims.ValidateAt(claims.NotBefore.Add(-time.Minute), time.Minute); err != nil {
		t.Fatalf("leeway at nbf: %v", err)
	}
	if err := claims.ValidateAt(*claims.ExpiresAt, 0); !errors.Is(err, ErrExpired) {
		t.Fatalf("at expiry: %v", err)
	}
	if err := claims.ValidateAt(claims.ExpiresAt.Add(time.Minute), time.Minute); !errors.Is(err, ErrExpired) {
		t.Fatalf("expiry plus leeway boundary: %v", err)
	}
	if err := claims.ValidateAt(claims.NotBefore, MaxClockSkew+time.Nanosecond); !errors.Is(err, ErrInvalidClaims) {
		t.Fatalf("excessive leeway: %v", err)
	}
}

func TestGenerateSerialAndClaimCodeDigestEncoding(t *testing.T) {
	first, err := GenerateSerial()
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateSerial()
	if err != nil {
		t.Fatal(err)
	}
	if !validUUID(first) || !validUUID(second) || first == second {
		t.Fatalf("invalid or repeated UUIDs: %q %q", first, second)
	}
	if first[14] != '4' || !strings.ContainsRune("89ab", rune(first[19])) {
		t.Fatalf("not an RFC 4122 v4 UUID: %s", first)
	}

	wantHash := sha256.Sum256([]byte("a high entropy code"))
	want := base64.RawURLEncoding.EncodeToString(wantHash[:])
	got := EncodeClaimCodeSHA256(wantHash)
	if got != want || !validDigest(got) {
		t.Fatalf("digest = %q, want %q", got, want)
	}
	decoded, err := DecodeClaimCodeSHA256(got)
	if err != nil || decoded != wantHash {
		t.Fatalf("decoded digest = %x, %v", decoded, err)
	}
	if _, err := DecodeClaimCodeSHA256("not-a-digest"); err == nil {
		t.Fatal("invalid encoded digest accepted")
	}
}

func TestRejectDuplicateJSONKeysNested(t *testing.T) {
	var target struct {
		Outer map[string]any `json:"outer"`
	}
	err := decodeJSONObjectStrict([]byte(`{"outer":{"a":1,"a":2}}`), &target)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate nested key error = %v", err)
	}
	if err := decodeJSONObjectStrict([]byte(`{"outer":{},"unknown":1}`), &target); err == nil {
		t.Fatal("unknown field accepted")
	}
	deep := strings.Repeat("[", 34) + "0" + strings.Repeat("]", 34)
	if err := rejectDuplicateJSONKeys([]byte(deep)); err == nil || !strings.Contains(err.Error(), "too deep") {
		t.Fatalf("deep JSON error = %v", err)
	}
}

func cloneEntitlements(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func TestClaimsJSONDoesNotAcceptExtraValue(t *testing.T) {
	key := testSigningKey(t, PurposeOfflineLicenseIssuer)
	payload, err := json.Marshal(testClaims(t, key))
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload, []byte(` {}`)...)
	if _, err := parseCanonicalClaims(payload); !errors.Is(err, ErrInvalidClaims) {
		t.Fatalf("error = %v, want ErrInvalidClaims", err)
	}
}
