package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

type TokenKind string

const (
	AccessToken            TokenKind = "dlat"
	RefreshToken           TokenKind = "dlrt"
	EmailVerificationToken TokenKind = "dlev"
	PasswordResetToken     TokenKind = "dlpr"
)

var ErrTokenFormat = errors.New("invalid token format")

func NewToken(kind TokenKind) (string, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return string(kind) + "_" + base64.RawURLEncoding.EncodeToString(random), nil
}

func HashToken(pepper []byte, kind TokenKind, token string) ([32]byte, error) {
	if !validToken(kind, token) {
		return [32]byte{}, ErrTokenFormat
	}
	mac := hmac.New(sha256.New, pepper)
	_, _ = mac.Write([]byte("DeniLicense/token/v1\x00"))
	_, _ = mac.Write([]byte(kind))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(token))
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out, nil
}

func validToken(kind TokenKind, token string) bool {
	prefix := string(kind) + "_"
	if !strings.HasPrefix(token, prefix) || len(token) != len(prefix)+43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token[len(prefix):])
	return err == nil && len(decoded) == 32
}
