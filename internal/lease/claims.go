package lease

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	ClaimsVersion = 1
	ClaimsType    = "activation-lease"

	MaxIssuerBytes            = 256
	MaxAudienceBytes          = 128
	MaxEntitlements           = 128
	MaxEntitlementKeyBytes    = 128
	MaxEntitlementStringBytes = 4096
	maxJSONDepth              = 16
)

// ValidateIssuer checks the exact issuer text contract used in signed leases.
func ValidateIssuer(value string) error {
	return validateText("iss", value, MaxIssuerBytes)
}

// Claims is the authenticated body of an activation lease. JWTID must be a
// newly generated value for each lease, even when every other claim is the
// same. Entitlement values are exactly bool, string, or int64.
//
// All times must have time.UTC as their location. ExpiresAt is the exclusive
// upper bound of the lease's validity interval.
type Claims struct {
	Version             int            `json:"ver"`
	Type                string         `json:"typ"`
	Issuer              string         `json:"iss"`
	KeyID               string         `json:"kid"`
	JWTID               string         `json:"jti"`
	LicenseID           string         `json:"license_id"`
	ActivationID        string         `json:"activation_id"`
	Audience            string         `json:"aud"`
	LicenseRevision     int64          `json:"license_revision"`
	DeviceKeyThumbprint string         `json:"device_key_sha256"`
	Entitlements        map[string]any `json:"entitlements"`
	IssuedAt            time.Time      `json:"iat"`
	NotBefore           time.Time      `json:"nbf"`
	ExpiresAt           time.Time      `json:"exp"`
}

// NewJWTID returns a random RFC 4122 version 4 UUID suitable for a lease jti.
// Uniqueness still needs to be enforced by the issuer's persistence layer.
func NewJWTID() (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return "", fmt.Errorf("lease: generate jti: %w", err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return formatUUID(value), nil
}

// Validate checks all context-independent claim invariants.
func (c Claims) Validate() error {
	if c.Version != ClaimsVersion {
		return invalidClaim("ver", fmt.Sprintf("must be %d", ClaimsVersion))
	}
	if c.Type != ClaimsType {
		return invalidClaim("typ", fmt.Sprintf("must be %q", ClaimsType))
	}
	if err := ValidateIssuer(c.Issuer); err != nil {
		return err
	}
	if !validDigest(c.KeyID) {
		return invalidClaim("kid", "must be a full unpadded base64url SHA-256 digest")
	}
	if !validUUID(c.JWTID) {
		return invalidClaim("jti", "must be a canonical, non-zero RFC UUID")
	}
	if !validUUID(c.LicenseID) {
		return invalidClaim("license_id", "must be a canonical, non-zero RFC UUID")
	}
	if !validUUID(c.ActivationID) {
		return invalidClaim("activation_id", "must be a canonical, non-zero RFC UUID")
	}
	if err := validateAudience(c.Audience); err != nil {
		return err
	}
	if c.LicenseRevision <= 0 {
		return invalidClaim("license_revision", "must be greater than zero")
	}
	if !validDigest(c.DeviceKeyThumbprint) {
		return invalidClaim("device_key_sha256", "must be a full unpadded base64url SHA-256 digest")
	}
	if c.Entitlements == nil {
		return invalidClaim("entitlements", "must be an object (an empty object is allowed)")
	}
	if len(c.Entitlements) > MaxEntitlements {
		return invalidClaim("entitlements", fmt.Sprintf("must contain at most %d entries", MaxEntitlements))
	}
	for name, value := range c.Entitlements {
		if err := validateEntitlementName(name); err != nil {
			return err
		}
		if err := validateEntitlementValue(name, value); err != nil {
			return err
		}
	}
	if err := validateUTCTime("iat", c.IssuedAt); err != nil {
		return err
	}
	if err := validateUTCTime("nbf", c.NotBefore); err != nil {
		return err
	}
	if err := validateUTCTime("exp", c.ExpiresAt); err != nil {
		return err
	}
	if !c.ExpiresAt.After(c.IssuedAt) || !c.ExpiresAt.After(c.NotBefore) {
		return invalidClaim("exp", "must be after iat and nbf")
	}
	return nil
}

// CanonicalJSON returns the only accepted JSON representation of c.
func (c Claims) CanonicalJSON() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("%w: encode claims: %v", ErrInvalidClaims, err)
	}
	return payload, nil
}

func parseCanonicalClaims(payload []byte) (Claims, error) {
	type wireClaims struct {
		Version             int                        `json:"ver"`
		Type                string                     `json:"typ"`
		Issuer              string                     `json:"iss"`
		KeyID               string                     `json:"kid"`
		JWTID               string                     `json:"jti"`
		LicenseID           string                     `json:"license_id"`
		ActivationID        string                     `json:"activation_id"`
		Audience            string                     `json:"aud"`
		LicenseRevision     int64                      `json:"license_revision"`
		DeviceKeyThumbprint string                     `json:"device_key_sha256"`
		Entitlements        map[string]json.RawMessage `json:"entitlements"`
		IssuedAt            time.Time                  `json:"iat"`
		NotBefore           time.Time                  `json:"nbf"`
		ExpiresAt           time.Time                  `json:"exp"`
	}

	var wire wireClaims
	if err := decodeJSONObjectStrict(payload, &wire); err != nil {
		return Claims{}, fmt.Errorf("%w: %v", ErrInvalidClaims, err)
	}
	claims := Claims{
		Version:             wire.Version,
		Type:                wire.Type,
		Issuer:              wire.Issuer,
		KeyID:               wire.KeyID,
		JWTID:               wire.JWTID,
		LicenseID:           wire.LicenseID,
		ActivationID:        wire.ActivationID,
		Audience:            wire.Audience,
		LicenseRevision:     wire.LicenseRevision,
		DeviceKeyThumbprint: wire.DeviceKeyThumbprint,
		Entitlements:        make(map[string]any, len(wire.Entitlements)),
		IssuedAt:            wire.IssuedAt,
		NotBefore:           wire.NotBefore,
		ExpiresAt:           wire.ExpiresAt,
	}
	if wire.Entitlements == nil {
		claims.Entitlements = nil
	}
	for name, raw := range wire.Entitlements {
		value, err := decodeEntitlement(raw)
		if err != nil {
			return Claims{}, invalidClaim("entitlements."+name, err.Error())
		}
		claims.Entitlements[name] = value
	}
	canonical, err := claims.CanonicalJSON()
	if err != nil {
		return Claims{}, err
	}
	if !bytes.Equal(payload, canonical) {
		return Claims{}, ErrNonCanonicalPayload
	}
	return claims, nil
}

func decodeEntitlement(raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	switch value := value.(type) {
	case bool, string:
		return value, nil
	case json.Number:
		integer, err := value.Int64()
		if err != nil {
			return nil, errors.New("must be an integer in the int64 range")
		}
		return integer, nil
	default:
		return nil, errors.New("must be a boolean, string, or int64")
	}
}

func validateAudience(value string) error {
	if value == "" || len(value) > MaxAudienceBytes {
		return invalidClaim("aud", fmt.Sprintf("must contain 1 to %d bytes", MaxAudienceBytes))
	}
	for index, r := range value {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') ||
			(index > 0 && (r == '.' || r == '_' || r == '-'))) {
			return invalidClaim("aud", "must use ASCII letters, digits, '.', '_' or '-'")
		}
	}
	return nil
}

func validateText(field, value string, maxBytes int) error {
	if value == "" || len(value) > maxBytes || !utf8.ValidString(value) {
		return invalidClaim(field, fmt.Sprintf("must be valid UTF-8 containing 1 to %d bytes", maxBytes))
	}
	if value != strings.TrimSpace(value) || containsControl(value) {
		return invalidClaim(field, "must not have surrounding whitespace or control characters")
	}
	return nil
}

func validateEntitlementName(name string) error {
	if name == "" || len(name) > MaxEntitlementKeyBytes {
		return invalidClaim("entitlements", fmt.Sprintf("names must contain 1 to %d bytes", MaxEntitlementKeyBytes))
	}
	for index, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') ||
			(index > 0 && (r == '.' || r == '_' || r == '-'))) {
			return invalidClaim("entitlements."+name, "name must use lowercase ASCII letters, digits, '.', '_' or '-'")
		}
	}
	return nil
}

func validateEntitlementValue(name string, value any) error {
	switch value := value.(type) {
	case bool, int64:
		return nil
	case string:
		if !utf8.ValidString(value) || len(value) > MaxEntitlementStringBytes || containsControl(value) {
			return invalidClaim("entitlements."+name,
				fmt.Sprintf("string must be valid, control-free UTF-8 of at most %d bytes", MaxEntitlementStringBytes))
		}
		return nil
	default:
		return invalidClaim("entitlements."+name, "must be a boolean, string, or int64")
	}
}

func validateUTCTime(field string, value time.Time) error {
	if value.IsZero() {
		return invalidClaim(field, "must not be zero")
	}
	if value.Location() != time.UTC {
		return invalidClaim(field, "must use time.UTC")
	}
	if value.Year() < 1970 || value.Year() > 9999 {
		return invalidClaim(field, "year must be between 1970 and 9999")
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != 43 || strings.Contains(value, "=") {
		return false
	}
	decoded, err := decodeRawBase64URL(value)
	return err == nil && len(decoded) == sha256.Size
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	compact := strings.ReplaceAll(value, "-", "")
	if len(compact) != 32 || compact != strings.ToLower(compact) {
		return false
	}
	decoded, err := hex.DecodeString(compact)
	if err != nil || len(decoded) != 16 {
		return false
	}
	var nonzero byte
	for _, b := range decoded {
		nonzero |= b
	}
	// RFC 4122 / RFC 9562 UUID variant and a currently assigned version.
	version := decoded[6] >> 4
	return nonzero != 0 && decoded[8]&0xc0 == 0x80 && version >= 1 && version <= 8
}

func formatUUID(value [16]byte) string {
	var destination [36]byte
	hex.Encode(destination[0:8], value[0:4])
	destination[8] = '-'
	hex.Encode(destination[9:13], value[4:6])
	destination[13] = '-'
	hex.Encode(destination[14:18], value[6:8])
	destination[18] = '-'
	hex.Encode(destination[19:23], value[8:10])
	destination[23] = '-'
	hex.Encode(destination[24:36], value[10:16])
	return string(destination[:])
}

func containsControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func invalidClaim(field, reason string) error {
	return fmt.Errorf("%w: %s %s", ErrInvalidClaims, field, reason)
}

func decodeJSONObjectStrict(data []byte, destination any) error {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

// rejectDuplicateJSONKeys walks nested values as well as the top-level object.
func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, 0); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func scanJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("JSON nesting exceeds %d levels", maxJSONDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

// digestBytes returns a full SHA-256 digest in canonical, unpadded base64url.
func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
