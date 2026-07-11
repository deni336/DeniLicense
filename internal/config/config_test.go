package config

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func validTestConfig() Config {
	secret := []byte(strings.Repeat("x", 32))
	return Config{
		Environment: Development, DatabaseURL: "postgres://db.example/denilicense?sslmode=disable",
		TokenPepper: secret, DevicePepper: secret, IssuancePepper: secret,
		AccessTokenTTL: 15 * time.Minute, RefreshTokenTTL: 24 * time.Hour,
		VerificationTTL: 30 * time.Minute, PasswordResetTTL: 30 * time.Minute,
		ActivationLeaseTTL: 24 * time.Hour, RegistrationMode: RegistrationClosed,
	}
}

func TestValidateRejectsUnsafeProductionConfig(t *testing.T) {
	secret := []byte(strings.Repeat("x", 32))
	cfg := Config{
		Environment:        Production,
		DatabaseURL:        "postgres://example",
		TokenPepper:        secret,
		DevicePepper:       secret,
		IssuancePepper:     secret,
		AccessTokenTTL:     60_000_000_000,
		RefreshTokenTTL:    120_000_000_000,
		ActivationLeaseTTL: 3_600_000_000_000,
		RegistrationMode:   RegistrationOpen,
		AllowedOrigins:     []string{"*"},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected wildcard production origin to be rejected")
	}
}

func TestLoadDecodesSecrets(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))
	t.Setenv("DENILICENSE_DATABASE_URL", "postgres://example")
	t.Setenv("DENILICENSE_ENV", "test")
	t.Setenv("DENILICENSE_TOKEN_PEPPER", encoded)
	t.Setenv("DENILICENSE_DEVICE_PEPPER", encoded)
	t.Setenv("DENILICENSE_ISSUANCE_PEPPER", encoded)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := len(cfg.TokenPepper); got != 32 {
		t.Fatalf("token pepper length = %d", got)
	}
}

func TestLoadRejectsMalformedBoolean(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))
	t.Setenv("DENILICENSE_ENV", "test")
	t.Setenv("DENILICENSE_DATABASE_URL", "postgres://example")
	t.Setenv("DENILICENSE_TOKEN_PEPPER", encoded)
	t.Setenv("DENILICENSE_DEVICE_PEPPER", encoded)
	t.Setenv("DENILICENSE_ISSUANCE_PEPPER", encoded)
	t.Setenv("DENILICENSE_EXPOSE_DEV_TOKENS", "sometimes")
	if _, err := Load(); err == nil {
		t.Fatal("malformed boolean was silently accepted")
	}
}

func TestValidateRejectsActivationIssuerThatCannotBeSigned(t *testing.T) {
	cfg := validTestConfig()
	cfg.ActivationKeyFile = "activation.key.json"
	for _, issuer := range []string{"", "https://licenses.example/\nforged", strings.Repeat("i", 257)} {
		cfg.ActivationIssuer = issuer
		if err := cfg.Validate(); err == nil {
			t.Fatalf("accepted invalid activation issuer %q", issuer)
		}
	}
	cfg.ActivationIssuer = "https://licenses.example"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid activation issuer rejected: %v", err)
	}
}

func TestValidateCORSOrigins(t *testing.T) {
	for _, origin := range []string{"*", "null", "https://app.example/path", "https://user@app.example", "https://app.example?x=1"} {
		cfg := validTestConfig()
		cfg.AllowedOrigins = []string{origin}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("accepted invalid CORS origin %q", origin)
		}
	}
	cfg := validTestConfig()
	cfg.AllowedOrigins = []string{"http://localhost:3000"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid development origin rejected: %v", err)
	}
	cfg.Environment = Production
	cfg.DatabaseURL = "postgres://db.example/denilicense?sslmode=verify-full"
	if err := cfg.Validate(); err == nil {
		t.Fatal("production HTTP origin was accepted")
	}
}

func TestValidateProductionDatabaseTLSIsUnambiguous(t *testing.T) {
	for _, databaseURL := range []string{
		"postgres://db.example/denilicense?sslmode=disable",
		"postgres://db.example/denilicense",
		"postgres://db.example/denilicense?sslmode=verify-full&sslmode=disable",
		"postgres://db.example/denilicense?sslmode=verify-full#ignored",
	} {
		if err := ValidateDatabaseURL(databaseURL, true); err == nil {
			t.Fatalf("accepted unsafe production database URL %q", databaseURL)
		}
	}
	if err := ValidateDatabaseURL("postgres://db.example/denilicense?sslmode=verify-full", true); err != nil {
		t.Fatalf("valid production database URL rejected: %v", err)
	}
}
