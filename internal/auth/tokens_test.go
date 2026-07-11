package auth

import (
	"bytes"
	"testing"
)

func TestTokensAreTypedAndHashed(t *testing.T) {
	pepper := bytes.Repeat([]byte{1}, 32)
	token, err := NewToken(AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	accessHash, err := HashToken(pepper, AccessToken, token)
	if err != nil {
		t.Fatal(err)
	}
	if accessHash == [32]byte{} {
		t.Fatal("unexpected zero hash")
	}
	if _, err := HashToken(pepper, RefreshToken, token); err == nil {
		t.Fatal("accepted an access token as a refresh token")
	}
}
