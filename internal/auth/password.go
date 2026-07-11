package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	passwordMinRunes = 15
	passwordMaxBytes = 1024
	defaultMemory    = 64 * 1024 // KiB
	defaultTime      = 3
	defaultThreads   = 1
	defaultSaltLen   = 16
	defaultKeyLen    = 32
)

var (
	ErrPasswordLength = fmt.Errorf("password must contain at least %d characters and at most %d bytes", passwordMinRunes, passwordMaxBytes)
	ErrInvalidHash    = errors.New("invalid password hash")
	// Each Argon2id operation uses 64 MiB. Bounding concurrency prevents a
	// burst of otherwise valid auth requests from exhausting server memory.
	argon2Gate = make(chan struct{}, 2)
)

type PasswordHasher struct {
	pepper []byte
}

func NewPasswordHasher(pepper []byte) *PasswordHasher {
	return &PasswordHasher{pepper: append([]byte(nil), pepper...)}
}

func (h *PasswordHasher) Hash(password string) (string, error) {
	if err := ValidatePassword(password); err != nil {
		return "", err
	}
	salt := make([]byte, defaultSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	input := h.input(password)
	defer clear(input)
	argon2Gate <- struct{}{}
	key := argon2.IDKey(input, salt, defaultTime, defaultMemory, defaultThreads, defaultKeyLen)
	<-argon2Gate
	defer clear(key)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		defaultMemory,
		defaultTime,
		defaultThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

func (h *PasswordHasher) Verify(encoded, password string) (bool, error) {
	params, salt, expected, err := parsePHC(encoded)
	if err != nil {
		return false, err
	}
	input := h.input(password)
	defer clear(input)
	argon2Gate <- struct{}{}
	actual := argon2.IDKey(input, salt, params.time, params.memory, params.threads, uint32(len(expected)))
	<-argon2Gate
	defer clear(actual)
	defer clear(expected)
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

func ValidatePassword(password string) error {
	if !utf8.ValidString(password) || utf8.RuneCountInString(password) < passwordMinRunes || len(password) > passwordMaxBytes {
		return ErrPasswordLength
	}
	return nil
}

func (h *PasswordHasher) input(password string) []byte {
	if len(h.pepper) == 0 {
		return []byte(password)
	}
	mac := hmac.New(sha256.New, h.pepper)
	_, _ = mac.Write([]byte("DeniLicense/password/v1\x00"))
	_, _ = mac.Write([]byte(password))
	return mac.Sum(nil)
}

type phcParams struct {
	memory  uint32
	time    uint32
	threads uint8
}

func parsePHC(encoded string) (phcParams, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return phcParams{}, nil, nil, ErrInvalidHash
	}
	var p phcParams
	values := strings.Split(parts[3], ",")
	if len(values) != 3 {
		return phcParams{}, nil, nil, ErrInvalidHash
	}
	for _, value := range values {
		kv := strings.SplitN(value, "=", 2)
		if len(kv) != 2 {
			return phcParams{}, nil, nil, ErrInvalidHash
		}
		n, err := strconv.ParseUint(kv[1], 10, 32)
		if err != nil {
			return phcParams{}, nil, nil, ErrInvalidHash
		}
		switch kv[0] {
		case "m":
			p.memory = uint32(n)
		case "t":
			p.time = uint32(n)
		case "p":
			if n > 255 {
				return phcParams{}, nil, nil, ErrInvalidHash
			}
			p.threads = uint8(n)
		default:
			return phcParams{}, nil, nil, ErrInvalidHash
		}
	}
	// Bounds prevent a malicious database value from causing resource exhaustion.
	if p.memory < 19*1024 || p.memory > 1024*1024 || p.time < 1 || p.time > 10 || p.threads < 1 || p.threads > 16 {
		return phcParams{}, nil, nil, ErrInvalidHash
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) < 16 || len(salt) > 64 {
		return phcParams{}, nil, nil, ErrInvalidHash
	}
	expected, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(expected) < 16 || len(expected) > 64 {
		return phcParams{}, nil, nil, ErrInvalidHash
	}
	return p, salt, expected, nil
}
