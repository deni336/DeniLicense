package lease

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

type testFixture struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
	device  ed25519.PublicKey
	claims  Claims
	options VerifyOptions
	token   string
}

type testHelper interface {
	Helper()
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}

func newTestFixture(t testHelper) testFixture {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	deviceThumbprint, err := DeviceKeyThumbprint(device)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 11, 20, 0, 0, 123_000_000, time.UTC)
	claims := Claims{
		Version:             ClaimsVersion,
		Type:                ClaimsType,
		Issuer:              "https://licenses.example.test",
		KeyID:               KeyID(public),
		JWTID:               "33333333-3333-4333-8333-333333333333",
		LicenseID:           "11111111-1111-4111-8111-111111111111",
		ActivationID:        "22222222-2222-4222-8222-222222222222",
		Audience:            "desktop.pro",
		LicenseRevision:     7,
		DeviceKeyThumbprint: deviceThumbprint,
		Entitlements: map[string]any{
			"feature.enabled": true,
			"plan":            "professional",
			"seats":           int64(5),
		},
		IssuedAt:  now.Add(-time.Minute),
		NotBefore: now.Add(-30 * time.Second),
		ExpiresAt: now.Add(time.Hour),
	}
	options := VerifyOptions{
		ExpectedIssuer:              claims.Issuer,
		ExpectedAudience:            claims.Audience,
		ExpectedDeviceKeyThumbprint: deviceThumbprint,
		Now:                         now,
		ClockLeeway:                 5 * time.Second,
	}
	token, err := Sign(claims, private)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return testFixture{private: private, public: public, device: device, claims: claims, options: options, token: token}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	fixture := newTestFixture(t)
	if !strings.HasPrefix(fixture.token, TokenVersion+".") {
		t.Fatalf("token = %q", fixture.token)
	}
	got, err := Verify(fixture.token, fixture.public, fixture.options)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !reflect.DeepEqual(got, fixture.claims) {
		t.Fatalf("claims mismatch:\n got: %#v\nwant: %#v", got, fixture.claims)
	}
}

func TestNewJWTID(t *testing.T) {
	first, err := NewJWTID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewJWTID()
	if err != nil {
		t.Fatal(err)
	}
	if !validUUID(first) || !validUUID(second) {
		t.Fatalf("invalid generated IDs: %q, %q", first, second)
	}
	if first == second {
		t.Fatalf("duplicate generated ID: %q", first)
	}
	if first[14] != '4' || (first[19] != '8' && first[19] != '9' && first[19] != 'a' && first[19] != 'b') {
		t.Fatalf("not an RFC 4122 version 4 UUID: %q", first)
	}
}

func TestJWKRoundTripAndVerification(t *testing.T) {
	fixture := newTestFixture(t)
	jwk, err := NewJWK(fixture.public)
	if err != nil {
		t.Fatal(err)
	}
	if jwk.KeyType != "OKP" || jwk.Curve != "Ed25519" || jwk.Algorithm != "EdDSA" || jwk.Use != "sig" {
		t.Fatalf("unexpected JWK metadata: %#v", jwk)
	}
	if jwk.KeyID != fixture.claims.KeyID || jwk.X != base64.RawURLEncoding.EncodeToString(fixture.public) {
		t.Fatalf("unexpected JWK key material: %#v", jwk)
	}
	if _, err := VerifyJWK(fixture.token, jwk, fixture.options); err != nil {
		t.Fatalf("VerifyJWK: %v", err)
	}

	set := JWKS{Keys: []JWK{jwk}}
	got, err := set.Lookup(jwk.KeyID)
	if err != nil || got != jwk {
		t.Fatalf("Lookup = (%#v, %v)", got, err)
	}

	bad := jwk
	bad.KeyID = strings.Repeat("A", 43)
	if err := bad.Validate(); !errors.Is(err, ErrInvalidPublicKey) {
		t.Fatalf("Validate bad JWK = %v", err)
	}
	if _, err := (JWKS{Keys: []JWK{jwk, jwk}}).Lookup(jwk.KeyID); !errors.Is(err, ErrInvalidPublicKey) {
		t.Fatalf("duplicate JWKS Lookup = %v", err)
	}
}

func TestRejectsUnsafeEd25519PublicKeys(t *testing.T) {
	fixture := newTestFixture(t)
	identity := make(ed25519.PublicKey, ed25519.PublicKeySize)
	identity[0] = 1
	lowOrder := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for name, publicKey := range map[string]ed25519.PublicKey{
		"identity":  identity,
		"low order": lowOrder,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewJWK(publicKey); !errors.Is(err, ErrInvalidPublicKey) {
				t.Fatalf("NewJWK = %v", err)
			}
			if _, err := DeviceKeyThumbprint(publicKey); !errors.Is(err, ErrInvalidPublicKey) {
				t.Fatalf("DeviceKeyThumbprint = %v", err)
			}
			if _, err := Verify(fixture.token, publicKey, fixture.options); !errors.Is(err, ErrInvalidPublicKey) {
				t.Fatalf("Verify = %v", err)
			}
		})
	}
}

func TestTamperingAndWrongKeyFail(t *testing.T) {
	fixture := newTestFixture(t)
	parts := strings.Split(fixture.token, ".")

	payloadTamper := append([]byte(nil), parts[1]...)
	if payloadTamper[len(payloadTamper)/2] == 'A' {
		payloadTamper[len(payloadTamper)/2] = 'B'
	} else {
		payloadTamper[len(payloadTamper)/2] = 'A'
	}
	signatureTamper := append([]byte(nil), parts[2]...)
	if signatureTamper[0] == 'A' {
		signatureTamper[0] = 'B'
	} else {
		signatureTamper[0] = 'A'
	}

	wrongPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		token  string
		public ed25519.PublicKey
	}{
		{"payload", parts[0] + "." + string(payloadTamper) + "." + parts[2], fixture.public},
		{"signature", parts[0] + "." + parts[1] + "." + string(signatureTamper), fixture.public},
		{"wrong key", fixture.token, wrongPublic},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Verify(test.token, test.public, fixture.options); !errors.Is(err, ErrInvalidSignature) {
				t.Fatalf("Verify = %v, want ErrInvalidSignature", err)
			}
		})
	}
}

func TestAudienceAndDeviceBinding(t *testing.T) {
	fixture := newTestFixture(t)
	wrongIssuer := fixture.options
	wrongIssuer.ExpectedIssuer = "https://other.example.test"
	if _, err := Verify(fixture.token, fixture.public, wrongIssuer); !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("wrong issuer = %v", err)
	}

	wrongAudience := fixture.options
	wrongAudience.ExpectedAudience = "another.product"
	if _, err := Verify(fixture.token, fixture.public, wrongAudience); !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("wrong audience = %v", err)
	}

	otherDevice, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongDevice := fixture.options
	wrongDevice.ExpectedDeviceKeyThumbprint, err = DeviceKeyThumbprint(otherDevice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(fixture.token, fixture.public, wrongDevice); !errors.Is(err, ErrDeviceMismatch) {
		t.Fatalf("wrong device = %v", err)
	}
}

func TestTemporalValidationAndLeeway(t *testing.T) {
	fixture := newTestFixture(t)
	now := fixture.options.Now
	tests := []struct {
		name   string
		change func(*Claims)
		want   error
	}{
		{
			name: "issued in future",
			change: func(claims *Claims) {
				claims.IssuedAt = now.Add(time.Minute)
			},
			want: ErrIssuedInFuture,
		},
		{
			name: "not before",
			change: func(claims *Claims) {
				claims.NotBefore = now.Add(time.Minute)
			},
			want: ErrNotYetValid,
		},
		{
			name: "expired",
			change: func(claims *Claims) {
				claims.ExpiresAt = now.Add(-fixture.options.ClockLeeway - time.Second)
			},
			want: ErrExpired,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims := fixture.claims
			test.change(&claims)
			token, err := Sign(claims, fixture.private)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if _, err := Verify(token, fixture.public, fixture.options); !errors.Is(err, test.want) {
				t.Fatalf("Verify = %v, want %v", err, test.want)
			}
		})
	}

	claims := fixture.claims
	claims.IssuedAt = now.Add(MaxClockLeeway)
	claims.NotBefore = now.Add(MaxClockLeeway)
	token, err := Sign(claims, fixture.private)
	if err != nil {
		t.Fatal(err)
	}
	options := fixture.options
	options.ClockLeeway = MaxClockLeeway
	if _, err := Verify(token, fixture.public, options); err != nil {
		t.Fatalf("exact leeway boundary: %v", err)
	}
	options.ClockLeeway++
	if _, err := Verify(token, fixture.public, options); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("over max clock leeway = %v", err)
	}

	// exp is exclusive, including at the far edge of permitted leeway.
	options = fixture.options
	options.ClockLeeway = 0
	options.Now = fixture.claims.ExpiresAt
	if _, err := Verify(fixture.token, fixture.public, options); !errors.Is(err, ErrExpired) {
		t.Fatalf("at exp = %v", err)
	}
	options.ClockLeeway = 5 * time.Second
	options.Now = fixture.claims.ExpiresAt.Add(options.ClockLeeway)
	if _, err := Verify(fixture.token, fixture.public, options); !errors.Is(err, ErrExpired) {
		t.Fatalf("at exp plus leeway = %v", err)
	}
	options.Now = options.Now.Add(-time.Nanosecond)
	if _, err := Verify(fixture.token, fixture.public, options); err != nil {
		t.Fatalf("inside expiry leeway = %v", err)
	}
}

func TestStrictCompactAndCanonicalValidation(t *testing.T) {
	fixture := newTestFixture(t)
	parts := strings.Split(fixture.token, ".")
	malformed := []string{
		"",
		TokenVersion,
		"other." + parts[1] + "." + parts[2],
		fixture.token + ".extra",
		TokenVersion + ".." + parts[2],
		TokenVersion + "." + parts[1] + "=." + parts[2],
		TokenVersion + "." + parts[1] + "." + parts[2] + "=",
		TokenVersion + ".*." + parts[2],
		TokenVersion + "." + parts[1] + ".AA",
		TokenVersion + "." + parts[1] + "." + parts[2][:len(parts[2])-1] + "B",
		strings.Repeat("x", MaxTokenBytes+1),
	}
	for index, token := range malformed {
		if _, err := Verify(token, fixture.public, fixture.options); !errors.Is(err, ErrMalformedToken) {
			t.Errorf("malformed[%d] = %v", index, err)
		}
	}

	canonical, err := fixture.claims.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	unknown := append(append([]byte(nil), canonical[:len(canonical)-1]...), []byte(`,"unknown":true}`)...)
	if _, err := Verify(signRaw(t, unknown, fixture.private), fixture.public, fixture.options); !errors.Is(err, ErrInvalidClaims) {
		t.Fatalf("unknown field = %v", err)
	}
	duplicate := []byte(strings.Replace(string(canonical), `{"ver":1,`, `{"ver":1,"ver":1,`, 1))
	if _, err := Verify(signRaw(t, duplicate, fixture.private), fixture.public, fixture.options); !errors.Is(err, ErrInvalidClaims) {
		t.Fatalf("duplicate field = %v", err)
	}
	noncanonical := append([]byte(" "), canonical...)
	if _, err := Verify(signRaw(t, noncanonical, fixture.private), fixture.public, fixture.options); !errors.Is(err, ErrNonCanonicalPayload) {
		t.Fatalf("non-canonical payload = %v", err)
	}

	// A signature over the compact input without the protocol domain is not a
	// valid lease signature.
	plainInput := []byte(TokenVersion + "." + parts[1])
	plainSignature := ed25519.Sign(fixture.private, plainInput)
	plainToken := TokenVersion + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(plainSignature)
	if _, err := Verify(plainToken, fixture.public, fixture.options); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("non-domain-separated signature = %v", err)
	}
}

func TestClaimsRejectUnsupportedValuesAndNonUTC(t *testing.T) {
	fixture := newTestFixture(t)
	tests := []struct {
		name   string
		change func(*Claims)
	}{
		{"wrong version", func(c *Claims) { c.Version = 2 }},
		{"wrong type", func(c *Claims) { c.Type = "license" }},
		{"noncanonical uuid", func(c *Claims) { c.JWTID = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA" }},
		{"revision zero", func(c *Claims) { c.LicenseRevision = 0 }},
		{"int is not int64", func(c *Claims) { c.Entitlements = map[string]any{"seats": int(5)} }},
		{"float", func(c *Claims) { c.Entitlements = map[string]any{"seats": 5.0} }},
		{"nested value", func(c *Claims) { c.Entitlements = map[string]any{"nested": map[string]any{}} }},
		{"non UTC", func(c *Claims) { c.IssuedAt = c.IssuedAt.In(time.FixedZone("offset", 3600)) }},
		{"expiry before nbf", func(c *Claims) { c.ExpiresAt = c.NotBefore }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims := fixture.claims
			test.change(&claims)
			if _, err := Sign(claims, fixture.private); !errors.Is(err, ErrInvalidClaims) {
				t.Fatalf("Sign = %v", err)
			}
		})
	}
}

func TestSignRejectsKeyMismatchAndBadSigner(t *testing.T) {
	fixture := newTestFixture(t)
	otherPublic, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Sign(fixture.claims, otherPrivate); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("key mismatch = %v (other public %x)", err, otherPublic[:4])
	}
	if _, err := Sign(fixture.claims, badSigner{public: fixture.public}); err == nil {
		t.Fatal("bad signer returned a token")
	}
}

func TestVerifyRequiresContext(t *testing.T) {
	fixture := newTestFixture(t)
	options := fixture.options
	options.ExpectedIssuer = ""
	if _, err := Verify(fixture.token, fixture.public, options); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("blank issuer = %v", err)
	}
	options = fixture.options
	options.ExpectedAudience = ""
	if _, err := Verify(fixture.token, fixture.public, options); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("blank audience = %v", err)
	}
	options = fixture.options
	options.ExpectedDeviceKeyThumbprint = ""
	if _, err := Verify(fixture.token, fixture.public, options); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("blank device = %v", err)
	}
	options = fixture.options
	options.ClockLeeway = -1
	if _, err := Verify(fixture.token, fixture.public, options); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("negative leeway = %v", err)
	}
}

func signRaw(t testing.TB, payload []byte, private ed25519.PrivateKey) string {
	t.Helper()
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	signature := ed25519.Sign(private, signingMessage(encodedPayload))
	return TokenVersion + "." + encodedPayload + "." + base64.RawURLEncoding.EncodeToString(signature)
}

type badSigner struct {
	public ed25519.PublicKey
}

func (s badSigner) Public() crypto.PublicKey { return s.public }

func (s badSigner) Sign(randSource io.Reader, digest []byte, options crypto.SignerOpts) ([]byte, error) {
	return make([]byte, ed25519.SignatureSize), nil
}
