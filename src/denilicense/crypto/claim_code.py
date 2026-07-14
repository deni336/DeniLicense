"""Human-readable, checksummed claim codes containing 160 random bits."""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

from .common import DeniLicenseError

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_DECODE = {character: index for index, character in enumerate(_ALPHABET)}
_PREFIX = "DNL1"
_PAYLOAD_LENGTH = 32
_DOMAIN = b"DeniLicense/claim-code/v1\x00"
_CHECK_DOMAIN = b"DeniLicense/claim-code-check/v1\x00"


class InvalidClaimCode(DeniLicenseError):
    pass


@dataclass(frozen=True, slots=True)
class ClaimCode:
    display: str
    digest: bytes
    suffix: str


def generate() -> ClaimCode:
    return from_entropy(os.urandom(20))


def from_entropy(entropy: bytes) -> ClaimCode:
    if not isinstance(entropy, bytes) or len(entropy) != 20:
        raise DeniLicenseError("claim code entropy must be exactly 20 bytes")
    payload = _encode(entropy)
    canonical = _PREFIX + payload + _checksum(payload)
    groups = [canonical[:4], *(canonical[index : index + 5] for index in range(4, len(canonical), 5))]
    return ClaimCode("-".join(groups), digest_raw(entropy), payload[-4:])


def parse(value: str) -> bytes:
    if not isinstance(value, str):
        raise InvalidClaimCode("invalid claim code format")
    canonical = "".join(character for character in value.strip().upper() if character not in "- \t\r\n")
    if len(canonical) != 38 or not canonical.startswith(_PREFIX):
        raise InvalidClaimCode("invalid claim code format")
    payload, supplied = canonical[4:36], canonical[36:]
    if not hmac.compare_digest(supplied, _checksum(payload)):
        raise InvalidClaimCode("invalid claim code format")
    try:
        decoded = _decode(payload)
    except (KeyError, ValueError) as exc:
        raise InvalidClaimCode("invalid claim code format") from exc
    if len(decoded) != 20:
        raise InvalidClaimCode("invalid claim code format")
    return decoded


def digest(value: str) -> bytes:
    return digest_raw(parse(value))


def digest_raw(entropy: bytes) -> bytes:
    return hashlib.sha256(_DOMAIN + entropy).digest()


def suffix(value: str) -> str:
    return _encode(parse(value))[-4:]


def _checksum(payload: str) -> str:
    checksum = hashlib.sha256(_CHECK_DOMAIN + payload.encode("ascii")).digest()
    number = (checksum[0] << 2) | (checksum[1] >> 6)
    return _ALPHABET[(number >> 5) & 31] + _ALPHABET[number & 31]


def _encode(value: bytes) -> str:
    number = int.from_bytes(value, "big")
    return "".join(_ALPHABET[(number >> shift) & 31] for shift in range(155, -1, -5))


def _decode(value: str) -> bytes:
    if len(value) != _PAYLOAD_LENGTH:
        raise ValueError("invalid length")
    number = 0
    for character in value:
        number = (number << 5) | _DECODE[character]
    return number.to_bytes(20, "big")
