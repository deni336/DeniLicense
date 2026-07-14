"""Purpose-bound Ed25519 keys and authenticated encrypted key files."""

from __future__ import annotations

import hmac
import os
import threading
from dataclasses import dataclass
from typing import Any, Literal

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .common import (
    DeniLicenseError,
    InvalidPublicKey,
    b64url_decode,
    b64url_encode,
    canonical_json,
    digest_bytes,
    is_digest,
    require_exact_fields,
    strict_json_loads,
    validate_ed25519_public_key,
)

KeyPurpose = Literal["offline-license-issuer", "activation-receipt-signer"]
OFFLINE_LICENSE_ISSUER: KeyPurpose = "offline-license-issuer"
ACTIVATION_RECEIPT_SIGNER: KeyPurpose = "activation-receipt-signer"
_PURPOSES = {OFFLINE_LICENSE_ISSUER, ACTIVATION_RECEIPT_SIGNER}

MAX_KEY_FILE_BYTES = 16 * 1024
MIN_PASSPHRASE_BYTES = 16
MAX_PASSPHRASE_BYTES = 1024 * 1024
_SCRYPT_GATE = threading.Lock()


class WrongKeyPurpose(DeniLicenseError):
    pass


class InvalidKeyFile(DeniLicenseError):
    pass


class KeyDecryptionFailed(DeniLicenseError):
    pass


@dataclass(frozen=True, slots=True)
class ScryptParams:
    n: int = 1 << 17
    r: int = 8
    p: int = 1

    def validate(self) -> None:
        if self.n < 1 << 14 or self.n > 1 << 20 or self.n & (self.n - 1):
            raise InvalidKeyFile("scrypt n must be a power of two between 16384 and 1048576")
        if self.r < 8 or self.r > 32:
            raise InvalidKeyFile("scrypt r must be between 8 and 32")
        if self.p < 1 or self.p > 4:
            raise InvalidKeyFile("scrypt p must be between 1 and 4")
        if 128 * self.n * self.r > 128 * 1024 * 1024:
            raise InvalidKeyFile("scrypt memory cost is too large")
        if self.n * self.r * self.p > 1 << 21:
            raise InvalidKeyFile("scrypt work factor is too large")


@dataclass(frozen=True, slots=True)
class VerificationKey:
    purpose: KeyPurpose
    public_bytes: bytes

    def __post_init__(self) -> None:
        if self.purpose not in _PURPOSES:
            raise WrongKeyPurpose(f"unknown key purpose {self.purpose!r}")
        copied = bytes(self.public_bytes)
        validate_ed25519_public_key(copied)
        object.__setattr__(self, "public_bytes", copied)

    @property
    def key_id(self) -> str:
        return digest_bytes(self.public_bytes)

    @property
    def public_key(self) -> Ed25519PublicKey:
        return Ed25519PublicKey.from_public_bytes(self.public_bytes)


class SigningKey:
    """An Ed25519 private key whose purpose is enforced at signing boundaries."""

    __slots__ = ("_key", "purpose")

    def __init__(self, key: Ed25519PrivateKey, purpose: KeyPurpose) -> None:
        if purpose not in _PURPOSES:
            raise WrongKeyPurpose(f"unknown key purpose {purpose!r}")
        self.purpose = purpose
        self._key = key
        validate_ed25519_public_key(self.public_bytes)

    @classmethod
    def generate(cls, purpose: KeyPurpose) -> SigningKey:
        return cls(Ed25519PrivateKey.generate(), purpose)

    @classmethod
    def from_seed(cls, seed: bytes, purpose: KeyPurpose) -> SigningKey:
        if not isinstance(seed, bytes) or len(seed) != 32:
            raise DeniLicenseError("Ed25519 seed must be exactly 32 bytes")
        return cls(Ed25519PrivateKey.from_private_bytes(bytes(seed)), purpose)

    @property
    def public_bytes(self) -> bytes:
        return self._key.public_key().public_bytes_raw()

    @property
    def key_id(self) -> str:
        return digest_bytes(self.public_bytes)

    @property
    def verification_key(self) -> VerificationKey:
        return VerificationKey(self.purpose, self.public_bytes)

    def _seed(self) -> bytes:
        return self._key.private_bytes_raw()

    def sign_license(self, message: bytes) -> bytes:
        if self.purpose != OFFLINE_LICENSE_ISSUER:
            raise WrongKeyPurpose("key is not an offline license issuer")
        return self._key.sign(message)

    def sign_activation(self, message: bytes) -> bytes:
        if self.purpose != ACTIVATION_RECEIPT_SIGNER:
            raise WrongKeyPurpose("key is not an activation receipt signer")
        return self._key.sign(message)


def encrypt_signing_key(
    key: SigningKey,
    passphrase: bytes | str,
    params: ScryptParams | None = None,
) -> bytes:
    if params is None:
        params = ScryptParams()
    secret = _passphrase_bytes(passphrase, new=True)
    params.validate()
    salt = os.urandom(16)
    nonce = os.urandom(12)
    public = b64url_encode(key.public_bytes)
    kdf = {"algorithm": "scrypt", "n": params.n, "r": params.r, "p": params.p, "salt": b64url_encode(salt)}
    cipher = {"algorithm": "aes-256-gcm", "nonce": b64url_encode(nonce), "ciphertext": ""}
    document: dict[str, Any] = {
        "format": "dlic-encrypted-private-key",
        "version": 1,
        "algorithm": "ed25519",
        "purpose": key.purpose,
        "key_id": key.key_id,
        "public_key": public,
        "kdf": kdf,
        "cipher": cipher,
    }
    aad = _key_file_aad(document)
    derived = _derive(secret, salt, params)
    try:
        cipher["ciphertext"] = b64url_encode(AESGCM(derived).encrypt(nonce, key._seed(), aad))
    finally:
        derived = b"\x00" * len(derived)
    encoded = canonical_json(document)
    if len(encoded) > MAX_KEY_FILE_BYTES:
        raise InvalidKeyFile("encrypted key file exceeds size limit")
    return encoded


def decrypt_signing_key(encoded: bytes, passphrase: bytes | str) -> SigningKey:
    if not encoded or len(encoded) > MAX_KEY_FILE_BYTES:
        raise InvalidKeyFile("invalid encrypted key file size")
    secret = _passphrase_bytes(passphrase, new=False)
    try:
        document = require_exact_fields(
            strict_json_loads(encoded),
            ("format", "version", "algorithm", "purpose", "key_id", "public_key", "kdf", "cipher"),
        )
        kdf = require_exact_fields(document["kdf"], ("algorithm", "n", "r", "p", "salt"))
        cipher = require_exact_fields(document["cipher"], ("algorithm", "nonce", "ciphertext"))
        if (
            document["format"] != "dlic-encrypted-private-key"
            or document["version"] != 1
            or isinstance(document["version"], bool)
            or document["algorithm"] != "ed25519"
            or document["purpose"] not in _PURPOSES
            or kdf["algorithm"] != "scrypt"
            or cipher["algorithm"] != "aes-256-gcm"
        ):
            raise InvalidKeyFile("unsupported encrypted key metadata")
        if any(isinstance(kdf[name], bool) or not isinstance(kdf[name], int) for name in ("n", "r", "p")):
            raise InvalidKeyFile("invalid scrypt parameters")
        params = ScryptParams(kdf["n"], kdf["r"], kdf["p"])
        params.validate()
        salt = b64url_decode(kdf["salt"], size=16)
        nonce = b64url_decode(cipher["nonce"], size=12)
        ciphertext = b64url_decode(cipher["ciphertext"], size=48)
        public_bytes = b64url_decode(document["public_key"], size=32)
        public = VerificationKey(document["purpose"], public_bytes)
        if not is_digest(document["key_id"]) or not hmac.compare_digest(document["key_id"], public.key_id):
            raise InvalidKeyFile("public key ID mismatch")
    except InvalidPublicKey as exc:
        raise InvalidKeyFile("unsafe public key material") from exc
    except (KeyError, TypeError, DeniLicenseError) as exc:
        if isinstance(exc, InvalidKeyFile):
            raise
        raise InvalidKeyFile("malformed encrypted key file") from exc

    derived = _derive(secret, salt, params)
    try:
        try:
            seed = AESGCM(derived).decrypt(nonce, ciphertext, _key_file_aad(document))
        except InvalidTag as exc:
            raise KeyDecryptionFailed("key decryption failed") from exc
    finally:
        derived = b"\x00" * len(derived)
    try:
        key = SigningKey.from_seed(seed, document["purpose"])
    except DeniLicenseError as exc:
        raise KeyDecryptionFailed("key decryption failed") from exc
    if not hmac.compare_digest(key.public_bytes, public_bytes) or not hmac.compare_digest(
        key.key_id, document["key_id"]
    ):
        raise KeyDecryptionFailed("key decryption failed")
    return key


def marshal_public_key(key: VerificationKey) -> bytes:
    return canonical_json(
        {
            "format": "dlic-public-key",
            "version": 1,
            "algorithm": "ed25519",
            "purpose": key.purpose,
            "key_id": key.key_id,
            "public_key": b64url_encode(key.public_bytes),
        }
    )


def parse_public_key(encoded: bytes) -> VerificationKey:
    if not encoded or len(encoded) > MAX_KEY_FILE_BYTES:
        raise InvalidKeyFile("invalid public key file size")
    try:
        document = require_exact_fields(
            strict_json_loads(encoded), ("format", "version", "algorithm", "purpose", "key_id", "public_key")
        )
        if (
            document["format"] != "dlic-public-key"
            or document["version"] != 1
            or isinstance(document["version"], bool)
            or document["algorithm"] != "ed25519"
            or document["purpose"] not in _PURPOSES
        ):
            raise InvalidKeyFile("unsupported public key metadata")
        key = VerificationKey(document["purpose"], b64url_decode(document["public_key"], size=32))
        if not is_digest(document["key_id"]) or not hmac.compare_digest(document["key_id"], key.key_id):
            raise InvalidKeyFile("public key ID mismatch")
        return key
    except InvalidPublicKey as exc:
        raise InvalidKeyFile("unsafe public key material") from exc
    except (KeyError, TypeError, DeniLicenseError) as exc:
        if isinstance(exc, InvalidKeyFile):
            raise
        raise InvalidKeyFile("malformed public key file") from exc


def _key_file_aad(document: dict[str, Any]) -> bytes:
    return canonical_json(
        {
            "format": document["format"],
            "version": document["version"],
            "algorithm": document["algorithm"],
            "purpose": document["purpose"],
            "key_id": document["key_id"],
            "public_key": document["public_key"],
            "kdf": document["kdf"],
            "cipher": {"algorithm": document["cipher"]["algorithm"], "nonce": document["cipher"]["nonce"]},
        }
    )


def _derive(passphrase: bytes, salt: bytes, params: ScryptParams) -> bytes:
    with _SCRYPT_GATE:
        return Scrypt(salt=salt, length=32, n=params.n, r=params.r, p=params.p).derive(passphrase)


def _passphrase_bytes(value: bytes | str, *, new: bool) -> bytes:
    if isinstance(value, str):
        value = value.encode("utf-8")
    if not isinstance(value, bytes) or not value or len(value) > MAX_PASSPHRASE_BYTES:
        raise DeniLicenseError("passphrase must be non-empty and within the size limit")
    if new and len(value) < MIN_PASSPHRASE_BYTES:
        raise DeniLicenseError(f"new passphrase must contain at least {MIN_PASSPHRASE_BYTES} bytes")
    return value
