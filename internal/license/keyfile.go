package license

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/scrypt"
)

const (
	keyFileVersion       = 1
	encryptedKeyFormat   = "dlic-encrypted-private-key"
	publicKeyFormat      = "dlic-public-key"
	kdfAlgorithm         = "scrypt"
	cipherAlgorithm      = "aes-256-gcm"
	keyFileSaltBytes     = 16
	MaxKeyFileBytes      = 16 * 1024
	MinPassphraseBytes   = 16
	MaxPassphraseBytes   = 1024 * 1024
	MinScryptN           = 1 << 14
	MaxScryptN           = 1 << 20
	MaxScryptMemoryBytes = 128 * 1024 * 1024
	MaxScryptWork        = 1 << 21
)

// Serializing the rare key-file KDF operation prevents concurrent malformed
// local files from multiplying the bounded memory allocation.
var scryptGate = make(chan struct{}, 1)

// ScryptParams controls private-key-at-rest protection. Validate is always run
// before allocating memory, including for attacker-controlled key files.
type ScryptParams struct {
	N int `json:"n"`
	R int `json:"r"`
	P int `json:"p"`
}

// DefaultScryptParams returns the production baseline (about 128 MiB RAM).
func DefaultScryptParams() ScryptParams {
	return ScryptParams{N: 1 << 17, R: 8, P: 1}
}

func (p ScryptParams) Validate() error {
	if p.N < MinScryptN || p.N > MaxScryptN || p.N&(p.N-1) != 0 {
		return fmt.Errorf("%w: scrypt N must be a power of two between %d and %d", ErrInvalidKeyFile, MinScryptN, MaxScryptN)
	}
	if p.R < 8 || p.R > 32 {
		return fmt.Errorf("%w: scrypt r must be between 8 and 32", ErrInvalidKeyFile)
	}
	if p.P < 1 || p.P > 4 {
		return fmt.Errorf("%w: scrypt p must be between 1 and 4", ErrInvalidKeyFile)
	}
	memory := uint64(128) * uint64(p.N) * uint64(p.R)
	if memory > MaxScryptMemoryBytes {
		return fmt.Errorf("%w: scrypt memory cost exceeds %d bytes", ErrInvalidKeyFile, MaxScryptMemoryBytes)
	}
	// Bound CPU work independently of RAM and prevent integer overflow in
	// downstream implementations.
	work := uint64(p.N) * uint64(p.R) * uint64(p.P)
	if work > MaxScryptWork {
		return fmt.Errorf("%w: scrypt work factor is too large", ErrInvalidKeyFile)
	}
	return nil
}

type encryptedKeyFileJSON struct {
	Format    string        `json:"format"`
	Version   int           `json:"version"`
	Algorithm string        `json:"algorithm"`
	Purpose   KeyPurpose    `json:"purpose"`
	KeyID     string        `json:"key_id"`
	PublicKey string        `json:"public_key"`
	KDF       keyFileKDF    `json:"kdf"`
	Cipher    keyFileCipher `json:"cipher"`
}

type keyFileKDF struct {
	Algorithm string `json:"algorithm"`
	ScryptParams
	Salt string `json:"salt"`
}

type keyFileCipher struct {
	Algorithm  string `json:"algorithm"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type keyFileAAD struct {
	Format    string            `json:"format"`
	Version   int               `json:"version"`
	Algorithm string            `json:"algorithm"`
	Purpose   KeyPurpose        `json:"purpose"`
	KeyID     string            `json:"key_id"`
	PublicKey string            `json:"public_key"`
	KDF       keyFileKDF        `json:"kdf"`
	Cipher    keyFileCipherMeta `json:"cipher"`
}

type keyFileCipherMeta struct {
	Algorithm string `json:"algorithm"`
	Nonce     string `json:"nonce"`
}

type publicKeyFileJSON struct {
	Format    string     `json:"format"`
	Version   int        `json:"version"`
	Algorithm string     `json:"algorithm"`
	Purpose   KeyPurpose `json:"purpose"`
	KeyID     string     `json:"key_id"`
	PublicKey string     `json:"public_key"`
}

// EncryptSigningKey returns a canonical JSON key file. The 32-byte Ed25519
// seed is protected by scrypt and AES-256-GCM; all public metadata (including
// purpose, KDF settings, salt, and nonce) is authenticated as GCM AAD.
func EncryptSigningKey(key *SigningKey, passphrase []byte, params ScryptParams) ([]byte, error) {
	if !key.valid() {
		return nil, errors.New("license: invalid signing key")
	}
	if err := validateNewPassphrase(passphrase); err != nil {
		return nil, err
	}
	if err := params.Validate(); err != nil {
		return nil, err
	}

	salt := make([]byte, keyFileSaltBytes)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("license: generate key salt: %w", err)
	}
	derived, err := deriveScryptKey(passphrase, salt, params)
	if err != nil {
		return nil, fmt.Errorf("license: derive key encryption key: %w", err)
	}
	defer wipe(derived)
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, fmt.Errorf("license: initialize AES: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("license: initialize GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("license: generate key nonce: %w", err)
	}
	public := key.VerificationKey()
	file := encryptedKeyFileJSON{
		Format:    encryptedKeyFormat,
		Version:   keyFileVersion,
		Algorithm: keyAlgorithm,
		Purpose:   key.purpose,
		KeyID:     public.KeyID(),
		PublicKey: base64.RawURLEncoding.EncodeToString(public.public),
		KDF: keyFileKDF{
			Algorithm:    kdfAlgorithm,
			ScryptParams: params,
			Salt:         base64.RawURLEncoding.EncodeToString(salt),
		},
		Cipher: keyFileCipher{
			Algorithm: cipherAlgorithm,
			Nonce:     base64.RawURLEncoding.EncodeToString(nonce),
		},
	}
	aad, err := marshalKeyFileAAD(file)
	if err != nil {
		return nil, err
	}
	seed := key.private.Seed()
	defer wipe(seed)
	file.Cipher.Ciphertext = base64.RawURLEncoding.EncodeToString(gcm.Seal(nil, nonce, seed, aad))
	encoded, err := json.Marshal(file)
	if err != nil {
		return nil, fmt.Errorf("license: marshal encrypted key: %w", err)
	}
	if len(encoded) > MaxKeyFileBytes {
		return nil, fmt.Errorf("%w: encrypted key file too large", ErrInvalidKeyFile)
	}
	return encoded, nil
}

// DecryptSigningKey parses, authenticates, and decrypts an encrypted key file.
// Authentication failures deliberately collapse bad passwords and tampering
// into ErrKeyDecryption.
func DecryptSigningKey(encoded, passphrase []byte) (*SigningKey, error) {
	if len(encoded) == 0 || len(encoded) > MaxKeyFileBytes {
		return nil, fmt.Errorf("%w: invalid key file size", ErrInvalidKeyFile)
	}
	if err := validatePassphrase(passphrase); err != nil {
		return nil, err
	}
	if err := validateEncryptedKeyJSONShape(encoded); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKeyFile, err)
	}
	var file encryptedKeyFileJSON
	if err := decodeJSONObjectStrict(encoded, &file); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKeyFile, err)
	}
	salt, nonce, ciphertext, public, err := validateEncryptedKeyFile(file)
	if err != nil {
		return nil, err
	}
	derived, err := deriveScryptKey(passphrase, salt, file.KDF.ScryptParams)
	if err != nil {
		return nil, fmt.Errorf("%w: key derivation", ErrKeyDecryption)
	}
	defer wipe(derived)
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, fmt.Errorf("%w: cipher setup", ErrKeyDecryption)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: cipher setup", ErrKeyDecryption)
	}
	aad, err := marshalKeyFileAAD(file)
	if err != nil {
		return nil, err
	}
	seed, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrKeyDecryption
	}
	defer wipe(seed)
	if len(seed) != ed25519.SeedSize {
		return nil, ErrKeyDecryption
	}
	key, err := NewSigningKeyFromSeed(seed, file.Purpose)
	if err != nil {
		return nil, ErrKeyDecryption
	}
	actualPublic := key.VerificationKey()
	if !equalBytes(actualPublic.public, public) || actualPublic.KeyID() != file.KeyID {
		wipe(key.private)
		return nil, ErrKeyDecryption
	}
	return key, nil
}

// MarshalPublicKey exports canonical, non-secret JSON for distribution to
// license verifiers.
func MarshalPublicKey(key VerificationKey) ([]byte, error) {
	if !key.valid() {
		return nil, errors.New("license: invalid verification key")
	}
	file := publicKeyFileJSON{
		Format:    publicKeyFormat,
		Version:   keyFileVersion,
		Algorithm: keyAlgorithm,
		Purpose:   key.purpose,
		KeyID:     key.KeyID(),
		PublicKey: base64.RawURLEncoding.EncodeToString(key.public),
	}
	return json.Marshal(file)
}

// ParsePublicKey strictly imports a public-key JSON file.
func ParsePublicKey(encoded []byte) (VerificationKey, error) {
	if len(encoded) == 0 || len(encoded) > MaxKeyFileBytes {
		return VerificationKey{}, fmt.Errorf("%w: invalid public key file size", ErrInvalidKeyFile)
	}
	if _, err := requireExactJSONObjectFields(encoded,
		[]string{"format", "version", "algorithm", "purpose", "key_id", "public_key"}, nil,
	); err != nil {
		return VerificationKey{}, fmt.Errorf("%w: %v", ErrInvalidKeyFile, err)
	}
	var file publicKeyFileJSON
	if err := decodeJSONObjectStrict(encoded, &file); err != nil {
		return VerificationKey{}, fmt.Errorf("%w: %v", ErrInvalidKeyFile, err)
	}
	if file.Format != publicKeyFormat || file.Version != keyFileVersion || file.Algorithm != keyAlgorithm || !file.Purpose.valid() {
		return VerificationKey{}, fmt.Errorf("%w: unsupported public key metadata", ErrInvalidKeyFile)
	}
	public, err := decodeFixedBase64URL(file.PublicKey, ed25519.PublicKeySize)
	if err != nil || !validDigest(file.KeyID) {
		return VerificationKey{}, fmt.Errorf("%w: invalid public key material", ErrInvalidKeyFile)
	}
	key, err := NewVerificationKey(ed25519.PublicKey(public), file.Purpose)
	if err != nil || key.KeyID() != file.KeyID {
		return VerificationKey{}, fmt.Errorf("%w: public key ID mismatch", ErrInvalidKeyFile)
	}
	return key, nil
}

func validateEncryptedKeyJSONShape(encoded []byte) error {
	object, err := requireExactJSONObjectFields(encoded,
		[]string{"format", "version", "algorithm", "purpose", "key_id", "public_key", "kdf", "cipher"}, nil,
	)
	if err != nil {
		return err
	}
	if _, err := requireExactJSONObjectFields(object["kdf"],
		[]string{"algorithm", "n", "r", "p", "salt"}, nil,
	); err != nil {
		return fmt.Errorf("kdf: %w", err)
	}
	if _, err := requireExactJSONObjectFields(object["cipher"],
		[]string{"algorithm", "nonce", "ciphertext"}, nil,
	); err != nil {
		return fmt.Errorf("cipher: %w", err)
	}
	return nil
}

func validateEncryptedKeyFile(file encryptedKeyFileJSON) (salt, nonce, ciphertext, public []byte, err error) {
	if file.Format != encryptedKeyFormat || file.Version != keyFileVersion || file.Algorithm != keyAlgorithm || !file.Purpose.valid() {
		return nil, nil, nil, nil, fmt.Errorf("%w: unsupported encrypted key metadata", ErrInvalidKeyFile)
	}
	if file.KDF.Algorithm != kdfAlgorithm || file.Cipher.Algorithm != cipherAlgorithm {
		return nil, nil, nil, nil, fmt.Errorf("%w: unsupported key protection algorithms", ErrInvalidKeyFile)
	}
	if err := file.KDF.ScryptParams.Validate(); err != nil {
		return nil, nil, nil, nil, err
	}
	salt, err = decodeFixedBase64URL(file.KDF.Salt, keyFileSaltBytes)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("%w: invalid KDF salt", ErrInvalidKeyFile)
	}
	nonce, err = decodeFixedBase64URL(file.Cipher.Nonce, 12)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("%w: invalid GCM nonce", ErrInvalidKeyFile)
	}
	ciphertext, err = decodeFixedBase64URL(file.Cipher.Ciphertext, ed25519.SeedSize+16)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("%w: invalid encrypted key material", ErrInvalidKeyFile)
	}
	public, err = decodeFixedBase64URL(file.PublicKey, ed25519.PublicKeySize)
	if err != nil || !validDigest(file.KeyID) {
		return nil, nil, nil, nil, fmt.Errorf("%w: invalid public key material", ErrInvalidKeyFile)
	}
	if err := ValidateEd25519PublicKey(public); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("%w: unsafe public key material", ErrInvalidKeyFile)
	}
	derivedID, _ := DeriveKeyID(ed25519.PublicKey(public))
	if derivedID != file.KeyID {
		return nil, nil, nil, nil, fmt.Errorf("%w: public key ID mismatch", ErrInvalidKeyFile)
	}
	return salt, nonce, ciphertext, public, nil
}

func marshalKeyFileAAD(file encryptedKeyFileJSON) ([]byte, error) {
	aad := keyFileAAD{
		Format:    file.Format,
		Version:   file.Version,
		Algorithm: file.Algorithm,
		Purpose:   file.Purpose,
		KeyID:     file.KeyID,
		PublicKey: file.PublicKey,
		KDF:       file.KDF,
		Cipher: keyFileCipherMeta{
			Algorithm: file.Cipher.Algorithm,
			Nonce:     file.Cipher.Nonce,
		},
	}
	encoded, err := json.Marshal(aad)
	if err != nil {
		return nil, fmt.Errorf("license: marshal authenticated key metadata: %w", err)
	}
	return encoded, nil
}

func decodeFixedBase64URL(value string, size int) ([]byte, error) {
	decoded, err := decodeRawBase64URL(value)
	if err != nil || len(decoded) != size {
		return nil, errors.New("invalid fixed-size base64url value")
	}
	return decoded, nil
}

func validatePassphrase(passphrase []byte) error {
	if len(passphrase) == 0 {
		return errors.New("license: passphrase must not be empty")
	}
	if len(passphrase) > MaxPassphraseBytes {
		return fmt.Errorf("license: passphrase exceeds %d bytes", MaxPassphraseBytes)
	}
	return nil
}

func validateNewPassphrase(passphrase []byte) error {
	if err := validatePassphrase(passphrase); err != nil {
		return err
	}
	if len(passphrase) < MinPassphraseBytes {
		return fmt.Errorf("license: new passphrase must contain at least %d bytes", MinPassphraseBytes)
	}
	return nil
}

func deriveScryptKey(passphrase, salt []byte, params ScryptParams) ([]byte, error) {
	scryptGate <- struct{}{}
	defer func() { <-scryptGate }()
	return scrypt.Key(passphrase, salt, params.N, params.R, params.P, 32)
}
