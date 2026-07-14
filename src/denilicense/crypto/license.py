"""Strict, canonical ``dlic1`` offline license grants."""

from __future__ import annotations

import hmac
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.exceptions import InvalidSignature as CryptographyInvalidSignature

from .common import (
    DeniLicenseError,
    InvalidClaims,
    NonCanonicalPayload,
    b64url_decode,
    b64url_encode,
    canonical_json,
    format_rfc3339,
    format_rfc3339_preserving,
    is_digest,
    parse_rfc3339,
    require_exact_fields,
    strict_json_loads,
    time_order_key,
    validate_entitlements,
    validate_identifier,
    validate_text,
    validate_uuid,
)
from .keys import OFFLINE_LICENSE_ISSUER, SigningKey, VerificationKey, WrongKeyPurpose

TOKEN_VERSION = "dlic1"  # noqa: S105 - public wire-format identifier, not a secret
MAX_PAYLOAD_BYTES = 16 * 1024
MAX_TOKEN_BYTES = 24 * 1024
MAX_CLOCK_SKEW = timedelta(minutes=10)
_CROCKFORD = frozenset("0123456789ABCDEFGHJKMNPQRSTVWXYZ")


class MalformedToken(DeniLicenseError):
    pass


class InvalidSignature(DeniLicenseError):
    pass


class KeyMismatch(DeniLicenseError):
    pass


class IssuerMismatch(DeniLicenseError):
    pass


class AudienceMismatch(DeniLicenseError):
    pass


class NotYetValid(DeniLicenseError):
    pass


class Expired(DeniLicenseError):
    pass


@dataclass(slots=True)
class LicenseClaims:
    issuer: str
    key_id: str
    audience: str
    serial: str
    subject: str
    claim_code_sha256: str
    claim_code_suffix: str
    issued_at: datetime
    not_before: datetime
    expires_at: datetime | None
    max_activations: int
    entitlements: dict[str, bool | str | int] = field(default_factory=dict)
    _issued_at_wire: str | None = field(default=None, repr=False, compare=False)
    _not_before_wire: str | None = field(default=None, repr=False, compare=False)
    _expires_at_wire: str | None = field(default=None, repr=False, compare=False)

    def validate(self) -> None:
        validate_text("iss", self.issuer, 256)
        validate_identifier("aud", self.audience, 128)
        validate_uuid(self.serial, require_rfc_variant=False)
        validate_text("sub", self.subject, 320)
        if not is_digest(self.key_id):
            raise InvalidClaims("kid must be an unpadded base64url SHA-256 digest")
        if not is_digest(self.claim_code_sha256):
            raise InvalidClaims("claim_code_sha256 must be an unpadded base64url SHA-256 digest")
        if (
            not isinstance(self.claim_code_suffix, str)
            or len(self.claim_code_suffix) != 4
            or any(character not in _CROCKFORD for character in self.claim_code_suffix)
        ):
            raise InvalidClaims("claim_code_suffix must contain four uppercase Crockford characters")
        format_rfc3339(self.issued_at)
        format_rfc3339(self.not_before)
        if time_order_key(self.not_before, self._not_before_wire) < time_order_key(
            self.issued_at, self._issued_at_wire
        ):
            raise InvalidClaims("nbf must not be before iat")
        if self.expires_at is not None:
            format_rfc3339(self.expires_at)
            expires_key = time_order_key(self.expires_at, self._expires_at_wire)
            if expires_key <= time_order_key(
                self.not_before, self._not_before_wire
            ) or expires_key <= time_order_key(self.issued_at, self._issued_at_wire):
                raise InvalidClaims("exp must be after iat and nbf")
        if (
            isinstance(self.max_activations, bool)
            or not isinstance(self.max_activations, int)
            or not 1 <= self.max_activations <= 100_000
        ):
            raise InvalidClaims("max_activations must be between 1 and 100000")
        self.entitlements = validate_entitlements(self.entitlements)

    def validate_at(self, now: datetime, clock_skew: timedelta = timedelta()) -> None:
        self.validate()
        _validate_skew(clock_skew)
        if now.tzinfo is None:
            raise InvalidClaims("now must include a timezone")
        if time_order_key(now + clock_skew) < time_order_key(self.not_before, self._not_before_wire):
            raise NotYetValid("license is not yet valid")
        if self.expires_at is not None and time_order_key(now - clock_skew) >= time_order_key(
            self.expires_at, self._expires_at_wire
        ):
            raise Expired("license has expired")

    def to_wire(self) -> dict[str, Any]:
        self.validate()
        result: dict[str, Any] = {
            "iss": self.issuer,
            "kid": self.key_id,
            "aud": self.audience,
            "jti": self.serial,
            "sub": self.subject,
            "claim_code_sha256": self.claim_code_sha256,
            "claim_code_suffix": self.claim_code_suffix,
            "iat": format_rfc3339_preserving(self.issued_at, self._issued_at_wire),
            "nbf": format_rfc3339_preserving(self.not_before, self._not_before_wire),
        }
        if self.expires_at is not None:
            result["exp"] = format_rfc3339_preserving(self.expires_at, self._expires_at_wire)
        result["max_activations"] = self.max_activations
        # encoding/json orders map keys lexicographically even though struct
        # fields retain declaration order.
        result["entitlements"] = {name: self.entitlements[name] for name in sorted(self.entitlements)}
        return result

    def canonical_json(self) -> bytes:
        return canonical_json(self.to_wire())

    @classmethod
    def from_payload(cls, payload: bytes) -> LicenseClaims:
        try:
            wire = require_exact_fields(
                strict_json_loads(payload, max_bytes=MAX_PAYLOAD_BYTES),
                (
                    "iss",
                    "kid",
                    "aud",
                    "jti",
                    "sub",
                    "claim_code_sha256",
                    "claim_code_suffix",
                    "iat",
                    "nbf",
                    "max_activations",
                    "entitlements",
                ),
                ("exp",),
            )
            claims = cls(
                issuer=wire["iss"],
                key_id=wire["kid"],
                audience=wire["aud"],
                serial=wire["jti"],
                subject=wire["sub"],
                claim_code_sha256=wire["claim_code_sha256"],
                claim_code_suffix=wire["claim_code_suffix"],
                issued_at=parse_rfc3339(wire["iat"]),
                not_before=parse_rfc3339(wire["nbf"]),
                expires_at=parse_rfc3339(wire["exp"]) if "exp" in wire and wire["exp"] is not None else None,
                max_activations=wire["max_activations"],
                entitlements=wire["entitlements"],
                _issued_at_wire=wire["iat"],
                _not_before_wire=wire["nbf"],
                _expires_at_wire=wire.get("exp"),
            )
            claims.validate()
        except (KeyError, TypeError, DeniLicenseError) as exc:
            if isinstance(exc, NonCanonicalPayload):
                raise
            raise InvalidClaims("invalid offline license claims") from exc
        if claims.canonical_json() != payload:
            raise NonCanonicalPayload("license payload is not canonical JSON")
        return claims


@dataclass(frozen=True, slots=True)
class VerificationOptions:
    expected_issuer: str
    expected_audience: str
    now: datetime | None = None
    clock_skew: timedelta = timedelta()


def generate_serial() -> str:
    return str(uuid.uuid4())


def encode_claim_code_digest(digest: bytes) -> str:
    if not isinstance(digest, bytes) or len(digest) != 32:
        raise DeniLicenseError("claim-code digest must be exactly 32 bytes")
    return b64url_encode(digest)


def decode_claim_code_digest(value: str) -> bytes:
    return b64url_decode(value, size=32)


def sign_token(claims: LicenseClaims, key: SigningKey) -> str:
    if key.purpose != OFFLINE_LICENSE_ISSUER:
        raise WrongKeyPurpose("offline grants require an offline issuer key")
    if not hmac.compare_digest(claims.key_id, key.key_id):
        raise KeyMismatch("license key ID does not match signing key")
    payload = claims.canonical_json()
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise MalformedToken("license payload exceeds size limit")
    encoded = b64url_encode(payload)
    signing_input = f"{TOKEN_VERSION}.{encoded}".encode("ascii")
    token = signing_input.decode("ascii") + "." + b64url_encode(key.sign_license(signing_input))
    if len(token) > MAX_TOKEN_BYTES:
        raise MalformedToken("license token exceeds size limit")
    return token


def verify_token(token: str, key: VerificationKey) -> LicenseClaims:
    if key.purpose != OFFLINE_LICENSE_ISSUER:
        raise WrongKeyPurpose("offline grants require an offline issuer key")
    signing_input, payload, signature = _parse_token(token)
    try:
        key.public_key.verify(signature, signing_input)
    except CryptographyInvalidSignature as exc:
        raise InvalidSignature("invalid offline license signature") from exc
    claims = LicenseClaims.from_payload(payload)
    if not hmac.compare_digest(claims.key_id, key.key_id):
        raise KeyMismatch("license key ID does not match verification key")
    return claims


def inspect_unverified(token: str) -> LicenseClaims:
    """Decode attacker-controlled claims; use only to select a trusted local key."""
    _, payload, _ = _parse_token(token)
    return LicenseClaims.from_payload(payload)


def verify_token_for_use(token: str, key: VerificationKey, options: VerificationOptions) -> LicenseClaims:
    claims = verify_token(token, key)
    if not options.expected_issuer or not options.expected_audience:
        raise InvalidClaims("expected issuer and audience are required")
    if claims.issuer != options.expected_issuer:
        raise IssuerMismatch("license issuer does not match")
    if claims.audience != options.expected_audience:
        raise AudienceMismatch("license audience does not match")
    now = options.now or datetime.now(UTC)
    claims.validate_at(now, options.clock_skew)
    return claims


def _parse_token(token: str) -> tuple[bytes, bytes, bytes]:
    if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_BYTES:
        raise MalformedToken("invalid license token size")
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != TOKEN_VERSION:
        raise MalformedToken("expected three dlic1 components")
    if not parts[1] or len(parts[1]) > ((MAX_PAYLOAD_BYTES + 2) // 3) * 4:
        raise MalformedToken("invalid payload component size")
    try:
        payload = b64url_decode(parts[1])
        signature = b64url_decode(parts[2], size=64)
    except DeniLicenseError as exc:
        raise MalformedToken("invalid license token encoding") from exc
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise MalformedToken("license payload exceeds size limit")
    return f"{parts[0]}.{parts[1]}".encode("ascii"), payload, signature


def _validate_skew(value: timedelta) -> None:
    if not isinstance(value, timedelta) or value < timedelta() or value > MAX_CLOCK_SKEW:
        raise InvalidClaims("clock skew must be between zero and ten minutes")
