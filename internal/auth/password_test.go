package auth

import (
	"strings"
	"testing"
)

func TestPasswordHashAndVerify(t *testing.T) {
	h := NewPasswordHasher([]byte(strings.Repeat("p", 32)))
	encoded, err := h.Hash("a long memorable password")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := h.Verify(encoded, "a long memorable password"); err != nil || !ok {
		t.Fatalf("verify = %v, %v", ok, err)
	}
	if ok, err := h.Verify(encoded, "a different long password"); err != nil || ok {
		t.Fatalf("wrong password verify = %v, %v", ok, err)
	}
}

func TestPasswordRejectsShortValue(t *testing.T) {
	h := NewPasswordHasher(nil)
	if _, err := h.Hash("too short"); err == nil {
		t.Fatal("short password accepted")
	}
}

func TestPHCParserBoundsResourceUse(t *testing.T) {
	encoded := "$argon2id$v=19$m=999999999,t=3,p=1$MTIzNDU2Nzg5MDEyMzQ1Ng$MTIzNDU2Nzg5MDEyMzQ1Ng"
	if _, _, _, err := parsePHC(encoded); err == nil {
		t.Fatal("unbounded memory setting accepted")
	}
}
