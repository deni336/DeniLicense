package lease

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

func FuzzVerify(f *testing.F) {
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	device := ed25519.NewKeyFromSeed([]byte(strings.Repeat("d", ed25519.SeedSize))).Public().(ed25519.PublicKey)
	deviceThumbprint, _ := DeviceKeyThumbprint(device)
	now := time.Date(2026, 7, 11, 20, 0, 0, 0, time.UTC)
	claims := Claims{
		Version:             ClaimsVersion,
		Type:                ClaimsType,
		Issuer:              "issuer.example",
		KeyID:               KeyID(public),
		JWTID:               "33333333-3333-4333-8333-333333333333",
		LicenseID:           "11111111-1111-4111-8111-111111111111",
		ActivationID:        "22222222-2222-4222-8222-222222222222",
		Audience:            "desktop.pro",
		LicenseRevision:     1,
		DeviceKeyThumbprint: deviceThumbprint,
		Entitlements:        map[string]any{"enabled": true, "seats": int64(3)},
		IssuedAt:            now.Add(-time.Minute),
		NotBefore:           now.Add(-time.Minute),
		ExpiresAt:           now.Add(time.Hour),
	}
	token, err := Sign(claims, private)
	if err != nil {
		f.Fatal(err)
	}
	options := VerifyOptions{
		ExpectedIssuer:              claims.Issuer,
		ExpectedAudience:            claims.Audience,
		ExpectedDeviceKeyThumbprint: deviceThumbprint,
		Now:                         now,
		ClockLeeway:                 time.Second,
	}
	f.Add(token)
	f.Add("")
	f.Add("dllease1.e30.AA")
	f.Fuzz(func(t *testing.T, candidate string) {
		_, _ = Verify(candidate, public, options)
	})
}

func FuzzCanonicalClaimsParser(f *testing.F) {
	fixture := newTestFixture(f)
	payload, err := fixture.claims.CanonicalJSON()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(payload)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"ver":1,"ver":1}`))
	f.Fuzz(func(t *testing.T, candidate []byte) {
		if len(candidate) > MaxPayloadBytes {
			return
		}
		_, _ = parseCanonicalClaims(candidate)
	})
}
