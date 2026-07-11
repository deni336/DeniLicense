// Package identity contains shared first-party account identity rules.
package identity

import (
	"errors"
	"net/mail"
	"strings"
	"unicode"
)

var ErrInvalidEmail = errors.New("identity: invalid email address")

// NormalizeEmail enforces the exact address contract used by registration,
// login, recovery, administration, and the one-time owner bootstrap.
func NormalizeEmail(value string) (display, normalized string, err error) {
	for _, character := range value {
		if character > unicode.MaxASCII || unicode.IsControl(character) {
			return "", "", ErrInvalidEmail
		}
	}
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 254 {
		return "", "", ErrInvalidEmail
	}
	address, err := mail.ParseAddress(value)
	if err != nil || address.Name != "" || address.Address != value {
		return "", "", ErrInvalidEmail
	}
	parts := strings.Split(address.Address, "@")
	if len(parts) != 2 || parts[0] == "" || !strings.Contains(parts[1], ".") {
		return "", "", ErrInvalidEmail
	}
	return address.Address, strings.ToLower(address.Address), nil
}
