package license

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// KeyPurpose prevents an activation receipt key from accidentally being used
// as an offline license issuer (or vice versa).
type KeyPurpose string

const (
	PurposeOfflineLicenseIssuer    KeyPurpose = "offline-license-issuer"
	PurposeActivationReceiptSigner KeyPurpose = "activation-receipt-signer"
)

const keyAlgorithm = "ed25519"

// SigningKey holds an Ed25519 key and its non-secret purpose metadata. Secret
// key bytes are never exposed by this type.
type SigningKey struct {
	purpose KeyPurpose
	private ed25519.PrivateKey
}

// VerificationKey is the safe-to-distribute public half of a SigningKey.
type VerificationKey struct {
	purpose KeyPurpose
	public  ed25519.PublicKey
}

var _ crypto.Signer = (*SigningKey)(nil)

// GenerateSigningKey creates a new key using the operating system CSPRNG.
func GenerateSigningKey(purpose KeyPurpose) (*SigningKey, error) {
	if !purpose.valid() {
		return nil, fmt.Errorf("%w: %q", ErrWrongKeyPurpose, purpose)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("license: generate Ed25519 key: %w", err)
	}
	return &SigningKey{purpose: purpose, private: private}, nil
}

// NewSigningKeyFromSeed imports a 32-byte Ed25519 seed. The input is copied.
func NewSigningKeyFromSeed(seed []byte, purpose KeyPurpose) (*SigningKey, error) {
	if !purpose.valid() {
		return nil, fmt.Errorf("%w: %q", ErrWrongKeyPurpose, purpose)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("license: Ed25519 seed must be %d bytes", ed25519.SeedSize)
	}
	private := ed25519.NewKeyFromSeed(seed)
	return &SigningKey{purpose: purpose, private: private}, nil
}

// NewSigningKey imports a standard 64-byte Ed25519 private key. The input is
// copied and checked for a self-consistent public suffix.
func NewSigningKey(private ed25519.PrivateKey, purpose KeyPurpose) (*SigningKey, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("license: Ed25519 private key must be %d bytes", ed25519.PrivateKeySize)
	}
	key, err := NewSigningKeyFromSeed(private.Seed(), purpose)
	if err != nil {
		return nil, err
	}
	if !equalBytes(key.private, private) {
		wipe(key.private)
		return nil, errors.New("license: inconsistent Ed25519 private key")
	}
	return key, nil
}

// NewVerificationKey imports an Ed25519 public key. The input is copied.
func NewVerificationKey(public ed25519.PublicKey, purpose KeyPurpose) (VerificationKey, error) {
	if !purpose.valid() {
		return VerificationKey{}, fmt.Errorf("%w: %q", ErrWrongKeyPurpose, purpose)
	}
	if len(public) != ed25519.PublicKeySize {
		return VerificationKey{}, fmt.Errorf("license: Ed25519 public key must be %d bytes", ed25519.PublicKeySize)
	}
	if err := ValidateEd25519PublicKey(public); err != nil {
		return VerificationKey{}, fmt.Errorf("license: unsafe Ed25519 public key: %w", err)
	}
	return VerificationKey{purpose: purpose, public: append(ed25519.PublicKey(nil), public...)}, nil
}

func (k *SigningKey) valid() bool {
	return k != nil && k.purpose.valid() && len(k.private) == ed25519.PrivateKeySize
}

func (k VerificationKey) valid() bool {
	return k.purpose.valid() && len(k.public) == ed25519.PublicKeySize
}

func (p KeyPurpose) valid() bool {
	return p == PurposeOfflineLicenseIssuer || p == PurposeActivationReceiptSigner
}

// Purpose returns the cryptographically authenticated intended use.
func (k *SigningKey) Purpose() KeyPurpose {
	if k == nil {
		return ""
	}
	return k.purpose
}

func (k VerificationKey) Purpose() KeyPurpose { return k.purpose }

// VerificationKey returns the purpose-bearing public key used by the token
// verification APIs.
func (k *SigningKey) VerificationKey() VerificationKey {
	if !k.valid() {
		return VerificationKey{}
	}
	public := k.private.Public().(ed25519.PublicKey)
	return VerificationKey{purpose: k.purpose, public: append(ed25519.PublicKey(nil), public...)}
}

// Public implements crypto.Signer and returns an independent Ed25519 public
// key copy. Call VerificationKey when purpose metadata is also required.
func (k *SigningKey) Public() crypto.PublicKey {
	if !k.valid() {
		return nil
	}
	public := k.private.Public().(ed25519.PublicKey)
	return append(ed25519.PublicKey(nil), public...)
}

// Sign implements crypto.Signer for activation-receipt keys. Offline issuer
// keys are deliberately rejected and can only sign the canonical license
// format through SignToken. Ed25519 signs messages directly, so prehashed input
// is rejected; standard Ed25519 signatures are deterministic.
func (k *SigningKey) Sign(random io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if !k.valid() {
		return nil, errors.New("license: invalid signing key")
	}
	if k.purpose != PurposeActivationReceiptSigner {
		return nil, ErrWrongKeyPurpose
	}
	if opts != nil && opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("license: Ed25519 requires an unhashed message")
	}
	if opts == nil {
		return ed25519.Sign(k.private, message), nil
	}
	return k.private.Sign(random, message, opts)
}

// Ed25519PublicKey returns an independent copy for integration with standard
// library APIs.
func (k VerificationKey) Ed25519PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), k.public...)
}

func (k *SigningKey) KeyID() string { return k.VerificationKey().KeyID() }

func (k VerificationKey) KeyID() string {
	if !k.valid() {
		return ""
	}
	id, _ := DeriveKeyID(k.public)
	return id
}

// DeriveKeyID is the full untruncated SHA-256 digest of an Ed25519 public key,
// encoded using unpadded base64url.
func DeriveKeyID(public ed25519.PublicKey) (string, error) {
	if len(public) != ed25519.PublicKeySize {
		return "", fmt.Errorf("license: Ed25519 public key must be %d bytes", ed25519.PublicKeySize)
	}
	digest := sha256.Sum256(public)
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var different byte
	for i := range a {
		different |= a[i] ^ b[i]
	}
	return different == 0
}

func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
