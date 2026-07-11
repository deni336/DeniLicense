package license

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
	MaxIssuerBytes            = 256
	MaxAudienceBytes          = 128
	MaxSubjectBytes           = 320
	MaxEntitlements           = 128
	MaxEntitlementKeyBytes    = 128
	MaxEntitlementStringBytes = 4096
	MaxActivations            = 100_000
)

// Claims is the signed body of an offline license grant. Subject is either a
// normalized email address or an application's stable customer reference.
// Entitlement values are deliberately limited to bool, string, and integer.
//
// Time values must use time.UTC. They are serialized by encoding/json as
// RFC3339 strings, preserving deterministic nanosecond precision.
type Claims struct {
	Issuer          string         `json:"iss"`
	KeyID           string         `json:"kid"`
	Audience        string         `json:"aud"`
	Serial          string         `json:"jti"`
	Subject         string         `json:"sub"`
	ClaimCodeSHA256 string         `json:"claim_code_sha256"`
	ClaimCodeSuffix string         `json:"claim_code_suffix"`
	IssuedAt        time.Time      `json:"iat"`
	NotBefore       time.Time      `json:"nbf"`
	ExpiresAt       *time.Time     `json:"exp,omitempty"`
	MaxActivations  int            `json:"max_activations"`
	Entitlements    map[string]any `json:"entitlements"`
}

// Validate checks the complete, context-independent claims contract.
func (c Claims) Validate() error {
	if err := validateText("issuer", c.Issuer, MaxIssuerBytes, false); err != nil {
		return err
	}
	if err := validateProductID(c.Audience); err != nil {
		return err
	}
	if !validUUID(c.Serial) {
		return invalidClaim("jti", "must be a canonical, non-zero UUID")
	}
	if err := validateText("sub", c.Subject, MaxSubjectBytes, false); err != nil {
		return err
	}
	if !validDigest(c.KeyID) {
		return invalidClaim("kid", "must be an unpadded base64url SHA-256 digest")
	}
	if !validDigest(c.ClaimCodeSHA256) {
		return invalidClaim("claim_code_sha256", "must be an unpadded base64url SHA-256 digest")
	}
	if !validClaimCodeSuffix(c.ClaimCodeSuffix) {
		return invalidClaim("claim_code_suffix", "must be exactly 4 uppercase Crockford Base32 characters")
	}
	if err := validateUTCTime("iat", c.IssuedAt); err != nil {
		return err
	}
	if err := validateUTCTime("nbf", c.NotBefore); err != nil {
		return err
	}
	if c.NotBefore.Before(c.IssuedAt) {
		return invalidClaim("nbf", "must not be before iat")
	}
	if c.ExpiresAt != nil {
		if err := validateUTCTime("exp", *c.ExpiresAt); err != nil {
			return err
		}
		if !c.ExpiresAt.After(c.NotBefore) || !c.ExpiresAt.After(c.IssuedAt) {
			return invalidClaim("exp", "must be after iat and nbf")
		}
	}
	if c.MaxActivations < 1 || c.MaxActivations > MaxActivations {
		return invalidClaim("max_activations", fmt.Sprintf("must be between 1 and %d", MaxActivations))
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
	return nil
}

// ValidateAt checks whether the grant can be used at now. Leeway is a bounded
// allowance for clock skew and must not be negative.
func (c Claims) ValidateAt(now time.Time, leeway time.Duration) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if now.IsZero() {
		return invalidClaim("now", "must not be zero")
	}
	if leeway < 0 || leeway > MaxClockSkew {
		return invalidClaim("leeway", fmt.Sprintf("must be between 0 and %s", MaxClockSkew))
	}
	if now.Add(leeway).Before(c.NotBefore) {
		return ErrNotYetValid
	}
	if c.ExpiresAt != nil && !now.Add(-leeway).Before(*c.ExpiresAt) {
		return ErrExpired
	}
	return nil
}

// CanonicalJSON returns the one accepted JSON representation of claims.
func (c Claims) CanonicalJSON() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(c)
}

// GenerateSerial returns a cryptographically random RFC 4122 version 4 UUID.
func GenerateSerial() (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", fmt.Errorf("license: generate serial: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return formatUUID(b), nil
}

// EncodeClaimCodeSHA256 encodes the exact 32-byte lookup digest produced by a
// claim-code generator. It deliberately does not accept or hash a raw/display
// code, avoiding disagreement with domain-separated server-side hashing.
func EncodeClaimCodeSHA256(digest [sha256.Size]byte) string {
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// DecodeClaimCodeSHA256 decodes a claims value into its database-ready digest.
func DecodeClaimCodeSHA256(value string) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	if !validDigest(value) {
		return digest, errors.New("license: invalid claim-code SHA-256 digest")
	}
	decoded, _ := base64.RawURLEncoding.Strict().DecodeString(value)
	copy(digest[:], decoded)
	return digest, nil
}

func parseCanonicalClaims(payload []byte) (Claims, error) {
	// Decode entitlement values separately so JSON numbers can be required to
	// be integers without ever making a float64 round trip.
	type wireClaims struct {
		Issuer          string                     `json:"iss"`
		KeyID           string                     `json:"kid"`
		Audience        string                     `json:"aud"`
		Serial          string                     `json:"jti"`
		Subject         string                     `json:"sub"`
		ClaimCodeSHA256 string                     `json:"claim_code_sha256"`
		ClaimCodeSuffix string                     `json:"claim_code_suffix"`
		IssuedAt        time.Time                  `json:"iat"`
		NotBefore       time.Time                  `json:"nbf"`
		ExpiresAt       *time.Time                 `json:"exp,omitempty"`
		MaxActivations  int                        `json:"max_activations"`
		Entitlements    map[string]json.RawMessage `json:"entitlements"`
	}

	if _, err := requireExactJSONObjectFields(payload,
		[]string{"iss", "kid", "aud", "jti", "sub", "claim_code_sha256", "claim_code_suffix", "iat", "nbf", "max_activations", "entitlements"},
		[]string{"exp"},
	); err != nil {
		return Claims{}, fmt.Errorf("%w: %v", ErrInvalidClaims, err)
	}
	var wire wireClaims
	if err := decodeJSONObjectStrict(payload, &wire); err != nil {
		return Claims{}, fmt.Errorf("%w: %v", ErrInvalidClaims, err)
	}
	claims := Claims{
		Issuer:          wire.Issuer,
		KeyID:           wire.KeyID,
		Audience:        wire.Audience,
		Serial:          wire.Serial,
		Subject:         wire.Subject,
		ClaimCodeSHA256: wire.ClaimCodeSHA256,
		ClaimCodeSuffix: wire.ClaimCodeSuffix,
		IssuedAt:        wire.IssuedAt,
		NotBefore:       wire.NotBefore,
		ExpiresAt:       wire.ExpiresAt,
		MaxActivations:  wire.MaxActivations,
		Entitlements:    make(map[string]any, len(wire.Entitlements)),
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
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	if err := requireJSONEOF(dec); err != nil {
		return nil, err
	}
	switch value := value.(type) {
	case bool, string:
		return value, nil
	case json.Number:
		n, err := value.Int64()
		if err != nil {
			return nil, errors.New("must be an integer in the int64 range")
		}
		return n, nil
	default:
		return nil, errors.New("must be a boolean, string, or integer")
	}
}

func validateEntitlementName(name string) error {
	if name == "" || len(name) > MaxEntitlementKeyBytes {
		return invalidClaim("entitlements", fmt.Sprintf("names must contain 1 to %d bytes", MaxEntitlementKeyBytes))
	}
	for i, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || (i > 0 && (r == '.' || r == '_' || r == '-'))) {
			return invalidClaim("entitlements."+name, "name must use lowercase ASCII letters, digits, '.', '_' or '-'")
		}
	}
	return nil
}

func validateEntitlementValue(name string, value any) error {
	switch value := value.(type) {
	case bool:
		return nil
	case string:
		if !utf8.ValidString(value) || len(value) > MaxEntitlementStringBytes || containsControl(value) {
			return invalidClaim("entitlements."+name, fmt.Sprintf("string must be valid, control-free UTF-8 of at most %d bytes", MaxEntitlementStringBytes))
		}
		return nil
	case int, int8, int16, int32, int64:
		return nil
	case uint:
		if uint64(value) <= uint64(^uint64(0)>>1) {
			return nil
		}
	case uint8, uint16, uint32:
		return nil
	case uint64:
		if value <= uint64(^uint64(0)>>1) {
			return nil
		}
	}
	return invalidClaim("entitlements."+name, "must be a boolean, string, or signed 64-bit integer")
}

func validateText(field, value string, max int, allowEmpty bool) error {
	if (!allowEmpty && value == "") || len(value) > max || !utf8.ValidString(value) {
		return invalidClaim(field, fmt.Sprintf("must be valid UTF-8 containing 1 to %d bytes", max))
	}
	if value != strings.TrimSpace(value) || containsControl(value) {
		return invalidClaim(field, "must not have surrounding whitespace or control characters")
	}
	return nil
}

func validateProductID(value string) error {
	if value == "" || len(value) > MaxAudienceBytes {
		return invalidClaim("aud", fmt.Sprintf("must contain 1 to %d bytes", MaxAudienceBytes))
	}
	for i, r := range value {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || (i > 0 && (r == '.' || r == '_' || r == '-'))) {
			return invalidClaim("aud", "must use ASCII letters, digits, '.', '_' or '-'")
		}
	}
	return nil
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

func containsControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func validDigest(value string) bool {
	if len(value) != 43 || strings.Contains(value, "=") {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validClaimCodeSuffix(value string) bool {
	const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	if len(value) != 4 {
		return false
	}
	for i := range value {
		if !strings.ContainsRune(crockford, rune(value[i])) {
			return false
		}
	}
	return true
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	compact := strings.ReplaceAll(value, "-", "")
	if len(compact) != 32 || strings.ToLower(compact) != compact {
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
	return nonzero != 0
}

func formatUUID(value [16]byte) string {
	var dst [36]byte
	hex.Encode(dst[0:8], value[0:4])
	dst[8] = '-'
	hex.Encode(dst[9:13], value[4:6])
	dst[13] = '-'
	hex.Encode(dst[14:18], value[6:8])
	dst[18] = '-'
	hex.Encode(dst[19:23], value[8:10])
	dst[23] = '-'
	hex.Encode(dst[24:36], value[10:16])
	return string(dst[:])
}

func invalidClaim(field, reason string) error {
	return fmt.Errorf("%w: %s %s", ErrInvalidClaims, field, reason)
}

func decodeJSONObjectStrict(data []byte, dst any) error {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return requireJSONEOF(dec)
}

// requireExactJSONObjectFields prevents encoding/json's case-insensitive
// struct matching from turning differently-spelled security metadata into
// last-one-wins aliases. Object member order and whitespace remain irrelevant.
func requireExactJSONObjectFields(data []byte, required, optional []string) (map[string]json.RawMessage, error) {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var object map[string]json.RawMessage
	if err := dec.Decode(&object); err != nil {
		return nil, err
	}
	if err := requireJSONEOF(dec); err != nil {
		return nil, err
	}
	if object == nil {
		return nil, errors.New("JSON value must be an object")
	}
	allowed := make(map[string]struct{}, len(required)+len(optional))
	for _, name := range required {
		allowed[name] = struct{}{}
	}
	for _, name := range optional {
		allowed[name] = struct{}{}
	}
	for name := range object {
		if _, ok := allowed[name]; !ok {
			return nil, fmt.Errorf("unknown JSON field %q", name)
		}
	}
	for _, name := range required {
		if _, ok := object[name]; !ok {
			return nil, fmt.Errorf("missing JSON field %q", name)
		}
	}
	return object, nil
}

func requireJSONEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

// rejectDuplicateJSONKeys walks arbitrary JSON so duplicate members cannot be
// smuggled into either claims or authenticated key metadata.
func rejectDuplicateJSONKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := scanJSONValue(dec, 0); err != nil {
		return err
	}
	return requireJSONEOF(dec)
}

func scanJSONValue(dec *json.Decoder, depth int) error {
	const maxJSONDepth = 32
	if depth > maxJSONDepth {
		return errors.New("JSON nesting is too deep")
	}
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyToken, err := dec.Token()
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
			if err := scanJSONValue(dec, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			if err != nil {
				return err
			}
			return errors.New("unterminated JSON object")
		}
	case '[':
		for dec.More() {
			if err := scanJSONValue(dec, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			if err != nil {
				return err
			}
			return errors.New("unterminated JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}
