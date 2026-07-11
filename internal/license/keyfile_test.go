package license

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestEncryptedSigningKeyRoundTrip(t *testing.T) {
	key := testSigningKey(t, PurposeOfflineLicenseIssuer)
	passphrase := []byte("correct horse battery staple")
	passphraseCopy := append([]byte(nil), passphrase...)
	params := ScryptParams{N: MinScryptN, R: 8, P: 1}

	first, err := EncryptSigningKey(key, passphrase, params)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EncryptSigningKey(key, passphrase, params)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("encrypted key files reused random salt/nonce")
	}
	if !bytes.Equal(passphrase, passphraseCopy) {
		t.Fatal("passphrase buffer was modified")
	}
	seedText := base64.RawURLEncoding.EncodeToString(key.private.Seed())
	if strings.Contains(string(first), seedText) {
		t.Fatal("key file exposes plaintext seed")
	}

	decrypted, err := DecryptSigningKey(first, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted.KeyID() != key.KeyID() || decrypted.Purpose() != key.Purpose() {
		t.Fatalf("decrypted key mismatch: %s %s", decrypted.KeyID(), decrypted.Purpose())
	}
	claims := testClaims(t, decrypted)
	token, err := SignToken(claims, decrypted)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyToken(token, key.VerificationKey()); err != nil {
		t.Fatalf("decrypted key cannot reproduce signatures: %v", err)
	}

	if _, err := DecryptSigningKey(first, []byte("wrong password")); !errors.Is(err, ErrKeyDecryption) {
		t.Fatalf("wrong password error = %v", err)
	}
}

func TestEncryptedKeyAuthenticatesMetadataAndCiphertext(t *testing.T) {
	key := testSigningKey(t, PurposeOfflineLicenseIssuer)
	passphrase := []byte("test passphrase!")
	encoded, err := EncryptSigningKey(key, passphrase, ScryptParams{N: MinScryptN, R: 8, P: 1})
	if err != nil {
		t.Fatal(err)
	}
	var original encryptedKeyFileJSON
	if err := json.Unmarshal(encoded, &original); err != nil {
		t.Fatal(err)
	}

	t.Run("purpose", func(t *testing.T) {
		file := original
		file.Purpose = PurposeActivationReceiptSigner
		tampered, _ := json.Marshal(file)
		if _, err := DecryptSigningKey(tampered, passphrase); !errors.Is(err, ErrKeyDecryption) {
			t.Fatalf("tampered purpose error = %v", err)
		}
	})

	t.Run("nonce", func(t *testing.T) {
		file := original
		nonce, _ := base64.RawURLEncoding.DecodeString(file.Cipher.Nonce)
		nonce[0] ^= 1
		file.Cipher.Nonce = base64.RawURLEncoding.EncodeToString(nonce)
		tampered, _ := json.Marshal(file)
		if _, err := DecryptSigningKey(tampered, passphrase); !errors.Is(err, ErrKeyDecryption) {
			t.Fatalf("tampered nonce error = %v", err)
		}
	})

	t.Run("ciphertext", func(t *testing.T) {
		file := original
		ciphertext, _ := base64.RawURLEncoding.DecodeString(file.Cipher.Ciphertext)
		ciphertext[0] ^= 1
		file.Cipher.Ciphertext = base64.RawURLEncoding.EncodeToString(ciphertext)
		tampered, _ := json.Marshal(file)
		if _, err := DecryptSigningKey(tampered, passphrase); !errors.Is(err, ErrKeyDecryption) {
			t.Fatalf("tampered ciphertext error = %v", err)
		}
	})

	t.Run("public key id consistency", func(t *testing.T) {
		file := original
		file.KeyID = strings.Repeat("A", 43)
		tampered, _ := json.Marshal(file)
		if _, err := DecryptSigningKey(tampered, passphrase); !errors.Is(err, ErrInvalidKeyFile) {
			t.Fatalf("inconsistent key ID error = %v", err)
		}
	})

	t.Run("unknown field", func(t *testing.T) {
		tampered := append(append([]byte(nil), encoded[:len(encoded)-1]...), []byte(`,"extra":true}`)...)
		if _, err := DecryptSigningKey(tampered, passphrase); !errors.Is(err, ErrInvalidKeyFile) {
			t.Fatalf("unknown field error = %v", err)
		}
	})

	t.Run("case-aliased field", func(t *testing.T) {
		tampered := append(append([]byte(nil), encoded[:len(encoded)-1]...), []byte(`,"PURPOSE":"offline-license-issuer"}`)...)
		if _, err := DecryptSigningKey(tampered, passphrase); !errors.Is(err, ErrInvalidKeyFile) {
			t.Fatalf("case-aliased field error = %v", err)
		}
	})
}

func TestPublicKeyFileRoundTripAndStrictness(t *testing.T) {
	key := testSigningKey(t, PurposeActivationReceiptSigner).VerificationKey()
	encoded, err := MarshalPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, encoded, "", "  "); err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePublicKey(pretty.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.KeyID() != key.KeyID() || parsed.Purpose() != key.Purpose() {
		t.Fatalf("public key mismatch: %s %s", parsed.KeyID(), parsed.Purpose())
	}

	var file publicKeyFileJSON
	if err := json.Unmarshal(encoded, &file); err != nil {
		t.Fatal(err)
	}
	file.KeyID = strings.Repeat("A", 43)
	tampered, _ := json.Marshal(file)
	if _, err := ParsePublicKey(tampered); !errors.Is(err, ErrInvalidKeyFile) {
		t.Fatalf("tampered key ID error = %v", err)
	}
	unknown := append(append([]byte(nil), encoded[:len(encoded)-1]...), []byte(`,"extra":true}`)...)
	if _, err := ParsePublicKey(unknown); !errors.Is(err, ErrInvalidKeyFile) {
		t.Fatalf("unknown field error = %v", err)
	}
	caseAlias := append(append([]byte(nil), encoded[:len(encoded)-1]...), []byte(`,"PURPOSE":"activation-receipt-signer"}`)...)
	if _, err := ParsePublicKey(caseAlias); !errors.Is(err, ErrInvalidKeyFile) {
		t.Fatalf("case-aliased field error = %v", err)
	}
}

func TestScryptParameterBounds(t *testing.T) {
	valid := DefaultScryptParams()
	if err := valid.Validate(); err != nil {
		t.Fatalf("defaults invalid: %v", err)
	}
	tests := []ScryptParams{
		{N: MinScryptN - 1, R: 8, P: 1},
		{N: MinScryptN + 1, R: 8, P: 1},
		{N: MaxScryptN * 2, R: 8, P: 1},
		{N: MinScryptN, R: 7, P: 1},
		{N: MinScryptN, R: 8, P: 0},
		{N: MinScryptN, R: 8, P: 5},
		{N: MaxScryptN, R: 32, P: 16},
		{N: 1 << 19, R: 8, P: 16},
	}
	for _, params := range tests {
		if err := params.Validate(); !errors.Is(err, ErrInvalidKeyFile) {
			t.Errorf("params %+v error = %v", params, err)
		}
	}
}

func TestKeyFileInputBounds(t *testing.T) {
	if _, err := DecryptSigningKey(bytes.Repeat([]byte{'x'}, MaxKeyFileBytes+1), []byte("pw")); !errors.Is(err, ErrInvalidKeyFile) {
		t.Fatalf("oversize encrypted file error = %v", err)
	}
	if _, err := ParsePublicKey(bytes.Repeat([]byte{'x'}, MaxKeyFileBytes+1)); !errors.Is(err, ErrInvalidKeyFile) {
		t.Fatalf("oversize public file error = %v", err)
	}
	if _, err := EncryptSigningKey(testSigningKey(t, PurposeOfflineLicenseIssuer), nil, DefaultScryptParams()); err == nil {
		t.Fatal("empty passphrase accepted")
	}
	if _, err := EncryptSigningKey(testSigningKey(t, PurposeOfflineLicenseIssuer), []byte("short"), DefaultScryptParams()); err == nil {
		t.Fatal("short new passphrase accepted")
	}
}
