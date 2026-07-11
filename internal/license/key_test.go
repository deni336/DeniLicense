package license

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"
)

func TestDeriveKeyIDUsesFullSHA256(t *testing.T) {
	key := testSigningKey(t, PurposeOfflineLicenseIssuer)
	public := key.VerificationKey().Ed25519PublicKey()
	digest := sha256.Sum256(public)
	want := base64.RawURLEncoding.EncodeToString(digest[:])
	got, err := DeriveKeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	if got != want || len(got) != 43 {
		t.Fatalf("KeyID = %q, want full digest %q", got, want)
	}
	if _, err := DeriveKeyID(public[:len(public)-1]); err == nil {
		t.Fatal("short public key accepted")
	}
}

func TestKeyConstructorsCopyAndValidateMaterial(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 42
	key, err := NewSigningKeyFromSeed(seed, PurposeOfflineLicenseIssuer)
	if err != nil {
		t.Fatal(err)
	}
	id := key.KeyID()
	seed[0] ^= 0xff
	if key.KeyID() != id {
		t.Fatal("signing key retained caller seed")
	}

	public := key.VerificationKey().Ed25519PublicKey()
	verification, err := NewVerificationKey(public, PurposeOfflineLicenseIssuer)
	if err != nil {
		t.Fatal(err)
	}
	public[0] ^= 0xff
	if verification.KeyID() != id {
		t.Fatal("verification key retained caller public key")
	}
	exported := verification.Ed25519PublicKey()
	exported[0] ^= 0xff
	if verification.KeyID() != id {
		t.Fatal("Ed25519PublicKey exposed internal storage")
	}

	private := append(ed25519.PrivateKey(nil), key.private...)
	private[len(private)-1] ^= 1
	if _, err := NewSigningKey(private, PurposeOfflineLicenseIssuer); err == nil {
		t.Fatal("inconsistent private key accepted")
	}
	if _, err := GenerateSigningKey("unknown"); !errors.Is(err, ErrWrongKeyPurpose) {
		t.Fatalf("unknown purpose error = %v", err)
	}
}

func TestVerificationKeyRejectsUnsafeEd25519Points(t *testing.T) {
	for i := 0; i < 16; i++ {
		generated, err := GenerateSigningKey(PurposeOfflineLicenseIssuer)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateEd25519PublicKey(generated.Public().(ed25519.PublicKey)); err != nil {
			t.Fatalf("generated public key %d rejected: %v", i, err)
		}
	}

	identity := make(ed25519.PublicKey, ed25519.PublicKeySize)
	identity[0] = 1
	forged := make([]byte, ed25519.SignatureSize)
	forged[0] = 1 // R is the identity; S is zero.
	if !ed25519.Verify(identity, []byte("any message"), forged) {
		t.Fatal("stdlib behavior changed: identity-key regression vector no longer verifies")
	}
	if _, err := NewVerificationKey(identity, PurposeOfflineLicenseIssuer); err == nil {
		t.Fatal("identity public key accepted")
	}

	orderTwo := make(ed25519.PublicKey, ed25519.PublicKeySize)
	orderTwo[0] = 0xec // y = p-1, x = 0.
	for i := 1; i < len(orderTwo)-1; i++ {
		orderTwo[i] = 0xff
	}
	orderTwo[len(orderTwo)-1] = 0x7f
	if _, err := NewVerificationKey(orderTwo, PurposeOfflineLicenseIssuer); err == nil {
		t.Fatal("order-two public key accepted")
	}
	orderFour := make(ed25519.PublicKey, ed25519.PublicKeySize) // y = 0.
	if _, err := NewVerificationKey(orderFour, PurposeOfflineLicenseIssuer); err == nil {
		t.Fatal("order-four public key accepted")
	}
	orderFour[31] = 0x80 // The other square root's sign.
	if _, err := NewVerificationKey(orderFour, PurposeOfflineLicenseIssuer); err == nil {
		t.Fatal("second order-four public key accepted")
	}

	noncanonical := append(ed25519.PublicKey(nil), orderTwo...)
	noncanonical[0] = 0xed // y = p is outside the canonical field range.
	if _, err := NewVerificationKey(noncanonical, PurposeOfflineLicenseIssuer); err == nil {
		t.Fatal("non-canonical public key encoding accepted")
	}

	generated := testSigningKey(t, PurposeOfflineLicenseIssuer)
	primePoint, err := decodeEd25519Point(generated.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	torsionPoint, err := decodeEd25519Point(orderTwo)
	if err != nil {
		t.Fatal(err)
	}
	mixedOrder := encodeTestEd25519Point(t, edwardsPointAdd(primePoint, torsionPoint))
	if err := ValidateEd25519PublicKey(mixedOrder); err == nil {
		t.Fatal("mixed-order public key accepted")
	}
}

func TestSigningKeyImplementsCryptoSigner(t *testing.T) {
	key := testSigningKey(t, PurposeActivationReceiptSigner)
	message := []byte("dlic-receipt-v1.payload")
	signature, err := key.Sign(nil, message, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok || !ed25519.Verify(public, message, signature) {
		t.Fatal("crypto.Signer signature did not verify")
	}
	public[0] ^= 0xff
	if key.KeyID() == "" || key.KeyID() == mustDeriveKeyID(t, public) {
		t.Fatal("crypto.Signer Public exposed internal storage")
	}
	if _, err := key.Sign(nil, message, crypto.SHA256); err == nil {
		t.Fatal("prehashed Ed25519 input accepted")
	}
	issuer := testSigningKey(t, PurposeOfflineLicenseIssuer)
	if _, err := issuer.Sign(nil, message, crypto.Hash(0)); !errors.Is(err, ErrWrongKeyPurpose) {
		t.Fatalf("offline issuer crypto.Signer error = %v", err)
	}
}

func mustDeriveKeyID(t *testing.T, public ed25519.PublicKey) string {
	t.Helper()
	id, err := DeriveKeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func encodeTestEd25519Point(t *testing.T, point extendedEdwardsPoint) ed25519.PublicKey {
	t.Helper()
	inverse := new(big.Int).ModInverse(point.z, edwardsP)
	if inverse == nil {
		t.Fatal("test point has zero projective denominator")
	}
	x := edwardsMul(point.x, inverse)
	y := edwardsMul(point.y, inverse)
	bigEndian := y.Bytes()
	encoded := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for i := range bigEndian {
		encoded[i] = bigEndian[len(bigEndian)-1-i]
	}
	if x.Bit(0) != 0 {
		encoded[31] |= 0x80
	}
	return encoded
}
