package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/deni336/DeniLicense/internal/lease"
)

type Environment string

const (
	Development Environment = "development"
	Test        Environment = "test"
	Production  Environment = "production"
)

type RegistrationMode string

const (
	RegistrationOpen   RegistrationMode = "open"
	RegistrationClosed RegistrationMode = "closed"
)

type Config struct {
	Environment                    Environment
	HTTPAddress                    string
	DatabaseURL                    string
	TokenPepper                    []byte
	DevicePepper                   []byte
	IssuancePepper                 []byte
	PasswordPepper                 []byte
	AccessTokenTTL                 time.Duration
	RefreshTokenTTL                time.Duration
	VerificationTTL                time.Duration
	PasswordResetTTL               time.Duration
	ActivationLeaseTTL             time.Duration
	RegistrationMode               RegistrationMode
	AllowedOrigins                 []string
	TrustedProxyCIDRs              []string
	ExposeDevTokens                bool
	PublicAppURL                   string
	EmailWebhookURL                string
	EmailWebhookBearer             string
	ActivationIssuer               string
	ActivationKeyFile              string
	ActivationVerificationKeyFiles []string
	ActivationKeyPassphraseFile    string
	AutoMigrate                    bool
	ShutdownTimeout                time.Duration
}

func Load() (Config, error) {
	environment := Environment(strings.TrimSpace(os.Getenv("DENILICENSE_ENV")))
	if environment == "" {
		return Config{}, errors.New("DENILICENSE_ENV is required")
	}
	accessTTL, err := parseDuration("DENILICENSE_ACCESS_TOKEN_TTL", 15*time.Minute)
	if err != nil {
		return Config{}, err
	}
	refreshTTL, err := parseDuration("DENILICENSE_REFRESH_TOKEN_TTL", 30*24*time.Hour)
	if err != nil {
		return Config{}, err
	}
	verificationTTL, err := parseDuration("DENILICENSE_EMAIL_VERIFICATION_TTL", 30*time.Minute)
	if err != nil {
		return Config{}, err
	}
	passwordResetTTL, err := parseDuration("DENILICENSE_PASSWORD_RESET_TTL", 30*time.Minute)
	if err != nil {
		return Config{}, err
	}
	leaseTTL, err := parseDuration("DENILICENSE_ACTIVATION_LEASE_TTL", 24*time.Hour)
	if err != nil {
		return Config{}, err
	}
	shutdownTimeout, err := parseDuration("DENILICENSE_SHUTDOWN_TIMEOUT", 15*time.Second)
	if err != nil {
		return Config{}, err
	}
	exposeTokens, err := parseBool("DENILICENSE_EXPOSE_DEV_TOKENS", false)
	if err != nil {
		return Config{}, err
	}
	autoMigrate, err := parseBool("DENILICENSE_AUTO_MIGRATE", environment != Production)
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		Environment:                    environment,
		HTTPAddress:                    env("DENILICENSE_HTTP_ADDRESS", ":8080"),
		DatabaseURL:                    strings.TrimSpace(os.Getenv("DENILICENSE_DATABASE_URL")),
		AccessTokenTTL:                 accessTTL,
		RefreshTokenTTL:                refreshTTL,
		VerificationTTL:                verificationTTL,
		PasswordResetTTL:               passwordResetTTL,
		ActivationLeaseTTL:             leaseTTL,
		RegistrationMode:               RegistrationMode(env("DENILICENSE_REGISTRATION_MODE", string(RegistrationClosed))),
		AllowedOrigins:                 csv(os.Getenv("DENILICENSE_ALLOWED_ORIGINS")),
		TrustedProxyCIDRs:              csv(os.Getenv("DENILICENSE_TRUSTED_PROXY_CIDRS")),
		ExposeDevTokens:                exposeTokens,
		PublicAppURL:                   strings.TrimRight(strings.TrimSpace(os.Getenv("DENILICENSE_PUBLIC_APP_URL")), "/"),
		EmailWebhookURL:                strings.TrimSpace(os.Getenv("DENILICENSE_EMAIL_WEBHOOK_URL")),
		EmailWebhookBearer:             strings.TrimSpace(os.Getenv("DENILICENSE_EMAIL_WEBHOOK_BEARER")),
		ActivationIssuer:               strings.TrimSpace(os.Getenv("DENILICENSE_ACTIVATION_ISSUER")),
		ActivationKeyFile:              strings.TrimSpace(os.Getenv("DENILICENSE_ACTIVATION_KEY_FILE")),
		ActivationVerificationKeyFiles: csv(os.Getenv("DENILICENSE_ACTIVATION_VERIFICATION_KEY_FILES")),
		ActivationKeyPassphraseFile:    strings.TrimSpace(os.Getenv("DENILICENSE_ACTIVATION_KEY_PASSPHRASE_FILE")),
		AutoMigrate:                    autoMigrate,
		ShutdownTimeout:                shutdownTimeout,
	}

	if cfg.TokenPepper, err = secret("DENILICENSE_TOKEN_PEPPER"); err != nil {
		return Config{}, err
	}
	if cfg.DevicePepper, err = secret("DENILICENSE_DEVICE_PEPPER"); err != nil {
		return Config{}, err
	}
	if cfg.IssuancePepper, err = secret("DENILICENSE_ISSUANCE_PEPPER"); err != nil {
		return Config{}, err
	}
	if cfg.PasswordPepper, err = optionalSecret("DENILICENSE_PASSWORD_PEPPER"); err != nil {
		return Config{}, err
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.Environment != Development && c.Environment != Test && c.Environment != Production {
		return fmt.Errorf("DENILICENSE_ENV must be development, test, or production")
	}
	if c.DatabaseURL == "" {
		return errors.New("DENILICENSE_DATABASE_URL is required")
	}
	if err := ValidateDatabaseURL(c.DatabaseURL, c.Environment == Production); err != nil {
		return err
	}
	if len(c.TokenPepper) < 32 {
		return errors.New("DENILICENSE_TOKEN_PEPPER must decode to at least 32 bytes")
	}
	if len(c.DevicePepper) < 32 {
		return errors.New("DENILICENSE_DEVICE_PEPPER must decode to at least 32 bytes")
	}
	if len(c.IssuancePepper) < 32 {
		return errors.New("DENILICENSE_ISSUANCE_PEPPER must decode to at least 32 bytes")
	}
	if len(c.PasswordPepper) != 0 && len(c.PasswordPepper) < 32 {
		return errors.New("DENILICENSE_PASSWORD_PEPPER must decode to at least 32 bytes when configured")
	}
	if c.AccessTokenTTL < time.Minute || c.AccessTokenTTL > time.Hour {
		return errors.New("access token TTL must be between one minute and one hour")
	}
	if c.RefreshTokenTTL <= c.AccessTokenTTL || c.RefreshTokenTTL > 90*24*time.Hour {
		return errors.New("refresh token TTL must be longer than access TTL and at most 90 days")
	}
	if c.VerificationTTL < 5*time.Minute || c.VerificationTTL > 24*time.Hour || c.PasswordResetTTL < 5*time.Minute || c.PasswordResetTTL > 24*time.Hour {
		return errors.New("verification and password-reset TTLs must be between five minutes and 24 hours")
	}
	if c.ActivationLeaseTTL < time.Hour || c.ActivationLeaseTTL > 7*24*time.Hour {
		return errors.New("activation lease TTL must be between one hour and seven days")
	}
	if c.RegistrationMode != RegistrationOpen && c.RegistrationMode != RegistrationClosed {
		return errors.New("registration mode must be open or closed")
	}
	for _, network := range c.TrustedProxyCIDRs {
		if _, _, err := net.ParseCIDR(network); err != nil {
			return fmt.Errorf("invalid trusted proxy CIDR %q", network)
		}
	}
	for _, origin := range c.AllowedOrigins {
		parsedOrigin, err := url.Parse(origin)
		if err != nil || parsedOrigin.Hostname() == "" || parsedOrigin.User != nil || parsedOrigin.RawQuery != "" ||
			parsedOrigin.Fragment != "" || parsedOrigin.Path != "" || (parsedOrigin.Scheme != "http" && parsedOrigin.Scheme != "https") {
			return fmt.Errorf("invalid CORS origin %q", origin)
		}
		if c.Environment == Production && parsedOrigin.Scheme != "https" {
			return fmt.Errorf("production CORS origin %q must use HTTPS", origin)
		}
	}
	if c.Environment == Production {
		if c.ExposeDevTokens {
			return errors.New("development tokens cannot be exposed in production")
		}
		if c.EmailWebhookURL == "" {
			return errors.New("production account recovery requires DENILICENSE_EMAIL_WEBHOOK_URL")
		}
	}
	if c.RegistrationMode == RegistrationOpen && c.EmailWebhookURL == "" && !c.ExposeDevTokens {
		return errors.New("open registration requires DENILICENSE_EMAIL_WEBHOOK_URL or development token exposure")
	}
	if c.EmailWebhookURL != "" {
		if c.PublicAppURL == "" {
			return errors.New("DENILICENSE_PUBLIC_APP_URL is required with the email webhook")
		}
		if len(c.EmailWebhookBearer) < 32 {
			return errors.New("DENILICENSE_EMAIL_WEBHOOK_BEARER must contain at least 32 characters")
		}
		webhookURL, err := validateServiceURL(c.EmailWebhookURL)
		if err != nil || webhookURL.RawQuery != "" {
			return errors.New("DENILICENSE_EMAIL_WEBHOOK_URL must be an absolute HTTP(S) URL without credentials, query, or fragment")
		}
		publicURL, err := validateServiceURL(c.PublicAppURL)
		if err != nil || publicURL.RawQuery != "" {
			return errors.New("DENILICENSE_PUBLIC_APP_URL must be an absolute HTTP(S) URL without credentials, query, or fragment")
		}
		if c.Environment == Production && (webhookURL.Scheme != "https" || publicURL.Scheme != "https") {
			return errors.New("email webhook and public app URLs must use HTTPS in production")
		}
	}
	if (c.ActivationKeyFile == "") != (c.ActivationIssuer == "") {
		return errors.New("activation issuer and activation key file must be configured together")
	}
	if c.ActivationIssuer != "" {
		if err := lease.ValidateIssuer(c.ActivationIssuer); err != nil {
			return fmt.Errorf("DENILICENSE_ACTIVATION_ISSUER is invalid: %w", err)
		}
	}
	if c.Environment == Production && c.ActivationKeyFile != "" && c.ActivationKeyPassphraseFile == "" {
		return errors.New("production activation keys require DENILICENSE_ACTIVATION_KEY_PASSPHRASE_FILE")
	}
	if len(c.ActivationVerificationKeyFiles) > 32 {
		return errors.New("at most 32 activation verification key files may be configured")
	}
	return nil
}

// ValidateDatabaseURL is shared by the full service configuration and the
// migration-only command, which intentionally does not require application
// peppers or signing keys.
func ValidateDatabaseURL(value string, requireVerifiedTLS bool) error {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.Hostname() == "" || parsed.Fragment != "" {
		return errors.New("DENILICENSE_DATABASE_URL must be a valid postgres URL")
	}
	if requireVerifiedTLS {
		sslModes := parsed.Query()["sslmode"]
		if len(sslModes) != 1 || sslModes[0] != "verify-full" {
			return errors.New("production PostgreSQL requires exactly one sslmode=verify-full parameter")
		}
	}
	return nil
}

func validateServiceURL(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, errors.New("invalid service URL")
	}
	return parsed, nil
}

func secret(name string) ([]byte, error) {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return nil, fmt.Errorf("%s is required and must be unpadded base64url", name)
	}
	b, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("%s must be unpadded base64url: %w", name, err)
	}
	return b, nil
}

func optionalSecret(name string) ([]byte, error) {
	if strings.TrimSpace(os.Getenv(name)) == "" {
		return nil, nil
	}
	return secret(name)
}

func env(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

func csv(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if item := strings.TrimSpace(part); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func parseBool(name string, fallback bool) (bool, error) {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s must be true or false: %w", name, err)
	}
	return b, nil
}

func parseDuration(name string, fallback time.Duration) (time.Duration, error) {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s must be a Go duration: %w", name, err)
	}
	return d, nil
}
