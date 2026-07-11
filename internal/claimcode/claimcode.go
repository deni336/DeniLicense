// Package claimcode creates and validates one-time human-readable license claim codes.
// The checksum catches transcription errors; security comes from 160 random bits.
package claimcode

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
)

const (
	prefix          = "DNL1"
	randomByteCount = 20
	payloadLength   = 32
	checksumLength  = 2
	encodedLength   = payloadLength + checksumLength
)

var (
	crockford = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)
	ErrFormat = errors.New("invalid claim code format")
)

// Generate returns the display form, its domain-separated database digest, and
// a non-sensitive four-character suffix suitable for support screens.
func Generate() (display string, digest [32]byte, suffix string, err error) {
	raw := make([]byte, randomByteCount)
	if _, err = rand.Read(raw); err != nil {
		return "", digest, "", fmt.Errorf("generate claim code: %w", err)
	}
	return FromEntropy(raw)
}

// FromEntropy encodes exactly 160 secret bits supplied by a trusted CSPRNG or
// domain-separated PRF. It exists for retry-safe online issuance.
func FromEntropy(raw []byte) (display string, digest [32]byte, suffix string, err error) {
	if len(raw) != randomByteCount {
		return "", digest, "", fmt.Errorf("claim code entropy must be exactly %d bytes", randomByteCount)
	}
	payload := crockford.EncodeToString(raw)
	check := checksum(payload)
	canonical := prefix + payload + check
	digest = DigestRaw(raw)
	return group(canonical), digest, payload[len(payload)-4:], nil
}

// Parse validates separators, Crockford characters, prefix, and checksum. It
// returns the random bytes so callers can compute the lookup digest.
func Parse(input string) ([]byte, error) {
	canonical := normalize(input)
	if len(canonical) != len(prefix)+encodedLength || !strings.HasPrefix(canonical, prefix) {
		return nil, ErrFormat
	}
	payload := canonical[len(prefix) : len(prefix)+payloadLength]
	provided := canonical[len(prefix)+payloadLength:]
	expected := checksum(payload)
	if subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
		return nil, ErrFormat
	}
	raw, err := crockford.DecodeString(payload)
	if err != nil || len(raw) != randomByteCount {
		return nil, ErrFormat
	}
	return raw, nil
}

func Digest(input string) ([32]byte, error) {
	raw, err := Parse(input)
	if err != nil {
		return [32]byte{}, err
	}
	return DigestRaw(raw), nil
}

func DigestRaw(raw []byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("DeniLicense/claim-code/v1\x00"))
	_, _ = h.Write(raw)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func Suffix(input string) (string, error) {
	raw, err := Parse(input)
	if err != nil {
		return "", err
	}
	payload := crockford.EncodeToString(raw)
	return payload[len(payload)-4:], nil
}

func checksum(payload string) string {
	sum := sha256.Sum256([]byte("DeniLicense/claim-code-check/v1\x00" + payload))
	// Ten checksum bits become exactly two Crockford characters.
	v := uint16(sum[0])<<2 | uint16(sum[1])>>6
	return string([]byte{
		"0123456789ABCDEFGHJKMNPQRSTVWXYZ"[(v>>5)&31],
		"0123456789ABCDEFGHJKMNPQRSTVWXYZ"[v&31],
	})
}

func normalize(input string) string {
	input = strings.ToUpper(strings.TrimSpace(input))
	var b strings.Builder
	b.Grow(len(input))
	for _, r := range input {
		switch r {
		case '-', ' ', '\t', '\r', '\n':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func group(canonical string) string {
	// Keep the version visibly separate, then group the body for transcription.
	body := canonical[len(prefix):]
	var b strings.Builder
	b.WriteString(prefix)
	for len(body) > 0 {
		b.WriteByte('-')
		n := 5
		if len(body) < n {
			n = len(body)
		}
		b.WriteString(body[:n])
		body = body[n:]
	}
	return b.String()
}
