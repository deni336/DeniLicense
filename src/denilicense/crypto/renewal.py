"""Structured proof-of-possession transcripts for lease renewal."""

from __future__ import annotations

import hmac
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .common import DeniLicenseError, b64url_decode, b64url_encode, validate_ed25519_public_key, validate_uuid

_DOMAIN = b"DeniLicense\x00activation-renewal\x00v1\x00"


@dataclass(frozen=True, slots=True)
class RenewalChallenge:
    challenge_id: str
    activation_id: str
    nonce: str
    algorithm: str
    transcript: str

    @classmethod
    def from_dict(cls, value: object) -> RenewalChallenge:
        if not isinstance(value, dict) or set(value) != {
            "challengeId",
            "activationId",
            "nonce",
            "algorithm",
            "transcript",
        }:
            raise DeniLicenseError("invalid renewal challenge object")
        return cls(
            challenge_id=value["challengeId"],
            activation_id=value["activationId"],
            nonce=value["nonce"],
            algorithm=value["algorithm"],
            transcript=value["transcript"],
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "challengeId": self.challenge_id,
            "activationId": self.activation_id,
            "nonce": self.nonce,
            "algorithm": self.algorithm,
            "transcript": self.transcript,
        }


def renewal_transcript(challenge_id: str, activation_id: str, nonce: str) -> bytes:
    validate_uuid(challenge_id, require_rfc_variant=True)
    validate_uuid(activation_id, require_rfc_variant=True)
    raw_nonce = b64url_decode(nonce, size=32)
    return (
        _DOMAIN
        + challenge_id.encode("ascii")
        + b"\x00"
        + activation_id.encode("ascii")
        + b"\x00"
        + b64url_encode(raw_nonce).encode("ascii")
    )


def validate_renewal_challenge(challenge: RenewalChallenge, expected_activation_id: str) -> bytes:
    if challenge.algorithm != "Ed25519":
        raise DeniLicenseError("renewal algorithm must be Ed25519")
    validate_uuid(expected_activation_id, require_rfc_variant=True)
    if not hmac.compare_digest(challenge.activation_id, expected_activation_id):
        raise DeniLicenseError("challenge activation does not match the expected activation")
    transcript = renewal_transcript(challenge.challenge_id, challenge.activation_id, challenge.nonce)
    if not hmac.compare_digest(challenge.transcript, b64url_encode(transcript)):
        raise DeniLicenseError("renewal transcript does not match the structured challenge")
    return transcript


def sign_renewal_challenge(
    private_key: bytes | Ed25519PrivateKey,
    challenge: RenewalChallenge,
    expected_activation_id: str,
) -> str:
    key = _private_key(private_key)
    validate_ed25519_public_key(key.public_key().public_bytes_raw())
    transcript = validate_renewal_challenge(challenge, expected_activation_id)
    return b64url_encode(key.sign(transcript))


def verify_renewal_signature(public_key: bytes, challenge: RenewalChallenge, signature: str) -> None:
    validate_ed25519_public_key(public_key)
    transcript = renewal_transcript(challenge.challenge_id, challenge.activation_id, challenge.nonce)
    if challenge.algorithm != "Ed25519" or not hmac.compare_digest(
        challenge.transcript, b64url_encode(transcript)
    ):
        raise DeniLicenseError("invalid structured renewal challenge")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(b64url_decode(signature, size=64), transcript)
    except InvalidSignature as exc:
        raise DeniLicenseError("invalid renewal proof signature") from exc


def _private_key(value: bytes | Ed25519PrivateKey) -> Ed25519PrivateKey:
    if isinstance(value, Ed25519PrivateKey):
        return value
    if not isinstance(value, bytes) or len(value) not in (32, 64):
        raise DeniLicenseError("device private key must be a 32-byte seed or standard 64-byte Ed25519 key")
    seed = value[:32]
    key = Ed25519PrivateKey.from_private_bytes(seed)
    if len(value) == 64 and not hmac.compare_digest(value[32:], key.public_key().public_bytes_raw()):
        raise DeniLicenseError("inconsistent Ed25519 private key")
    return key
