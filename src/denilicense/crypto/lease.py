"""Strict, device-bound ``dllease1`` activation leases."""

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
    InvalidPublicKey,
    NonCanonicalPayload,
    b64url_decode,
    b64url_encode,
    canonical_json,
    digest_bytes,
    format_rfc3339,
    format_rfc3339_preserving,
    is_digest,
    parse_rfc3339,
    require_exact_fields,
    strict_json_loads,
    time_order_key,
    validate_ed25519_public_key,
    validate_entitlements,
    validate_identifier,
    validate_text,
    validate_uuid,
)
from .keys import ACTIVATION_RECEIPT_SIGNER, SigningKey, VerificationKey, WrongKeyPurpose

TOKEN_VERSION = "dllease1"  # noqa: S105 - public wire-format identifier, not a secret
CLAIMS_VERSION = 1
CLAIMS_TYPE = "activation-lease"
MAX_PAYLOAD_BYTES = 16 * 1024
MAX_TOKEN_BYTES = 24 * 1024
MAX_CLOCK_LEEWAY = timedelta(minutes=10)
_SIGNATURE_DOMAIN = b"DeniLicense\x00activation-lease\x00v1\x00"


class MalformedLease(DeniLicenseError):
    pass


class InvalidLeaseSignature(DeniLicenseError):
    pass


class LeaseKeyMismatch(DeniLicenseError):
    pass


class LeaseContextMismatch(DeniLicenseError):
    pass


class LeaseTimeError(DeniLicenseError):
    pass


@dataclass(slots=True)
class LeaseClaims:
    issuer: str
    key_id: str
    jwt_id: str
    license_id: str
    activation_id: str
    audience: str
    license_revision: int
    device_key_thumbprint: str
    entitlements: dict[str, bool | str | int]
    issued_at: datetime
    not_before: datetime
    expires_at: datetime
    version: int = CLAIMS_VERSION
    type: str = CLAIMS_TYPE
    _issued_at_wire: str | None = field(default=None, repr=False, compare=False)
    _not_before_wire: str | None = field(default=None, repr=False, compare=False)
    _expires_at_wire: str | None = field(default=None, repr=False, compare=False)

    def validate(self) -> None:
        if isinstance(self.version, bool) or self.version != CLAIMS_VERSION:
            raise InvalidClaims("ver must be 1")
        if self.type != CLAIMS_TYPE:
            raise InvalidClaims("typ must be activation-lease")
        validate_text("iss", self.issuer, 256)
        if not is_digest(self.key_id):
            raise InvalidClaims("kid must be a full SHA-256 base64url digest")
        validate_uuid(self.jwt_id, require_rfc_variant=True)
        validate_uuid(self.license_id, require_rfc_variant=True)
        validate_uuid(self.activation_id, require_rfc_variant=True)
        validate_identifier("aud", self.audience, 128)
        if (
            isinstance(self.license_revision, bool)
            or not isinstance(self.license_revision, int)
            or self.license_revision <= 0
        ):
            raise InvalidClaims("license_revision must be greater than zero")
        if not is_digest(self.device_key_thumbprint):
            raise InvalidClaims("device_key_sha256 must be a full SHA-256 base64url digest")
        self.entitlements = validate_entitlements(self.entitlements)
        format_rfc3339(self.issued_at)
        format_rfc3339(self.not_before)
        format_rfc3339(self.expires_at)
        expires_key = time_order_key(self.expires_at, self._expires_at_wire)
        if expires_key <= time_order_key(
            self.issued_at, self._issued_at_wire
        ) or expires_key <= time_order_key(self.not_before, self._not_before_wire):
            raise InvalidClaims("exp must be after iat and nbf")

    def to_wire(self) -> dict[str, Any]:
        self.validate()
        return {
            "ver": self.version,
            "typ": self.type,
            "iss": self.issuer,
            "kid": self.key_id,
            "jti": self.jwt_id,
            "license_id": self.license_id,
            "activation_id": self.activation_id,
            "aud": self.audience,
            "license_revision": self.license_revision,
            "device_key_sha256": self.device_key_thumbprint,
            "entitlements": {name: self.entitlements[name] for name in sorted(self.entitlements)},
            "iat": format_rfc3339_preserving(self.issued_at, self._issued_at_wire),
            "nbf": format_rfc3339_preserving(self.not_before, self._not_before_wire),
            "exp": format_rfc3339_preserving(self.expires_at, self._expires_at_wire),
        }

    def canonical_json(self) -> bytes:
        return canonical_json(self.to_wire())

    @classmethod
    def from_payload(cls, payload: bytes) -> LeaseClaims:
        fields = (
            "ver",
            "typ",
            "iss",
            "kid",
            "jti",
            "license_id",
            "activation_id",
            "aud",
            "license_revision",
            "device_key_sha256",
            "entitlements",
            "iat",
            "nbf",
            "exp",
        )
        try:
            wire = require_exact_fields(strict_json_loads(payload, max_bytes=MAX_PAYLOAD_BYTES), fields)
            claims = cls(
                version=wire["ver"],
                type=wire["typ"],
                issuer=wire["iss"],
                key_id=wire["kid"],
                jwt_id=wire["jti"],
                license_id=wire["license_id"],
                activation_id=wire["activation_id"],
                audience=wire["aud"],
                license_revision=wire["license_revision"],
                device_key_thumbprint=wire["device_key_sha256"],
                entitlements=wire["entitlements"],
                issued_at=parse_rfc3339(wire["iat"]),
                not_before=parse_rfc3339(wire["nbf"]),
                expires_at=parse_rfc3339(wire["exp"]),
                _issued_at_wire=wire["iat"],
                _not_before_wire=wire["nbf"],
                _expires_at_wire=wire["exp"],
            )
            claims.validate()
        except (KeyError, TypeError, DeniLicenseError) as exc:
            if isinstance(exc, NonCanonicalPayload):
                raise
            raise InvalidClaims("invalid activation lease claims") from exc
        if claims.canonical_json() != payload:
            raise NonCanonicalPayload("lease payload is not canonical JSON")
        return claims


@dataclass(frozen=True, slots=True)
class VerifyOptions:
    expected_issuer: str
    expected_audience: str
    expected_device_key_thumbprint: str
    now: datetime | None = None
    clock_leeway: timedelta = timedelta()

    def validate(self) -> None:
        validate_text("expected issuer", self.expected_issuer, 256)
        validate_identifier("expected audience", self.expected_audience, 128)
        if not is_digest(self.expected_device_key_thumbprint):
            raise InvalidClaims("expected device key thumbprint must be a SHA-256 base64url digest")
        if (
            not isinstance(self.clock_leeway, timedelta)
            or not timedelta() <= self.clock_leeway <= MAX_CLOCK_LEEWAY
        ):
            raise InvalidClaims("clock leeway must be between zero and ten minutes")


@dataclass(frozen=True, slots=True)
class JWK:
    key_type: str
    curve: str
    algorithm: str
    use: str
    key_id: str
    x: str

    @classmethod
    def from_public_key(cls, public_key: bytes) -> JWK:
        validate_ed25519_public_key(public_key)
        return cls("OKP", "Ed25519", "EdDSA", "sig", key_id(public_key), b64url_encode(public_key))

    @classmethod
    def from_dict(cls, value: Any) -> JWK:
        wire = require_exact_fields(value, ("kty", "crv", "alg", "use", "kid", "x"))
        key = cls(wire["kty"], wire["crv"], wire["alg"], wire["use"], wire["kid"], wire["x"])
        key.validate()
        return key

    def to_dict(self) -> dict[str, str]:
        return {
            "kty": self.key_type,
            "crv": self.curve,
            "alg": self.algorithm,
            "use": self.use,
            "kid": self.key_id,
            "x": self.x,
        }

    def validate(self) -> None:
        if (self.key_type, self.curve, self.algorithm, self.use) != ("OKP", "Ed25519", "EdDSA", "sig"):
            raise InvalidPublicKey("expected OKP/Ed25519/EdDSA/sig metadata")
        public = b64url_decode(self.x, size=32)
        validate_ed25519_public_key(public)
        if not is_digest(self.key_id) or not hmac.compare_digest(self.key_id, key_id(public)):
            raise InvalidPublicKey("JWK kid does not match x")

    @property
    def public_bytes(self) -> bytes:
        self.validate()
        return b64url_decode(self.x, size=32)


@dataclass(frozen=True, slots=True)
class JWKS:
    keys: tuple[JWK, ...] = field(default_factory=tuple)

    @classmethod
    def from_dict(cls, value: Any) -> JWKS:
        wire = require_exact_fields(value, ("keys",))
        if not isinstance(wire["keys"], list):
            raise InvalidPublicKey("JWKS keys must be an array")
        return cls(tuple(JWK.from_dict(item) for item in wire["keys"]))

    def to_dict(self) -> dict[str, list[dict[str, str]]]:
        return {"keys": [key.to_dict() for key in self.keys]}

    def lookup(self, wanted_key_id: str) -> JWK:
        if not is_digest(wanted_key_id):
            raise InvalidPublicKey("invalid JWK key ID")
        seen: set[str] = set()
        result: JWK | None = None
        for key in self.keys:
            key.validate()
            if key.key_id in seen:
                raise InvalidPublicKey("duplicate key ID in JWKS")
            seen.add(key.key_id)
            if hmac.compare_digest(key.key_id, wanted_key_id):
                result = key
        if result is None:
            raise InvalidPublicKey("public key not found")
        return result


def new_jwt_id() -> str:
    return str(uuid.uuid4())


def key_id(public_key: bytes) -> str:
    return digest_bytes(public_key) if isinstance(public_key, bytes) and len(public_key) == 32 else ""


def device_key_thumbprint(public_key: bytes) -> str:
    validate_ed25519_public_key(public_key)
    return digest_bytes(public_key)


def sign_lease(claims: LeaseClaims, key: SigningKey) -> str:
    if key.purpose != ACTIVATION_RECEIPT_SIGNER:
        raise WrongKeyPurpose("activation leases require an activation receipt signer")
    if not hmac.compare_digest(claims.key_id, key.key_id):
        raise LeaseKeyMismatch("lease key ID does not match signing key")
    payload = claims.canonical_json()
    if not payload or len(payload) > MAX_PAYLOAD_BYTES:
        raise MalformedLease("lease payload exceeds size limit")
    encoded = b64url_encode(payload)
    message = _SIGNATURE_DOMAIN + f"{TOKEN_VERSION}.{encoded}".encode("ascii")
    signature = key.sign_activation(message)
    token = f"{TOKEN_VERSION}.{encoded}.{b64url_encode(signature)}"
    if len(token) > MAX_TOKEN_BYTES:
        raise MalformedLease("lease token exceeds size limit")
    return token


def verify_lease(token: str, public_key: bytes | VerificationKey, options: VerifyOptions) -> LeaseClaims:
    public = public_key.public_bytes if isinstance(public_key, VerificationKey) else bytes(public_key)
    if isinstance(public_key, VerificationKey) and public_key.purpose != ACTIVATION_RECEIPT_SIGNER:
        raise WrongKeyPurpose("activation leases require an activation receipt signer")
    validate_ed25519_public_key(public)
    options.validate()
    if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_BYTES:
        raise MalformedLease("invalid lease token size")
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != TOKEN_VERSION:
        raise MalformedLease("expected three dllease1 components")
    try:
        payload = b64url_decode(parts[1])
        signature = b64url_decode(parts[2], size=64)
    except DeniLicenseError as exc:
        raise MalformedLease("invalid lease token encoding") from exc
    if not payload or len(payload) > MAX_PAYLOAD_BYTES:
        raise MalformedLease("lease payload exceeds size limit")
    message = _SIGNATURE_DOMAIN + f"{TOKEN_VERSION}.{parts[1]}".encode("ascii")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
    except CryptographyInvalidSignature as exc:
        raise InvalidLeaseSignature("invalid activation lease signature") from exc
    claims = LeaseClaims.from_payload(payload)
    if not hmac.compare_digest(claims.key_id, key_id(public)):
        raise LeaseKeyMismatch("lease key ID does not match verification key")
    if claims.issuer != options.expected_issuer:
        raise LeaseContextMismatch("lease issuer does not match")
    if claims.audience != options.expected_audience:
        raise LeaseContextMismatch("lease audience does not match")
    if not hmac.compare_digest(claims.device_key_thumbprint, options.expected_device_key_thumbprint):
        raise LeaseContextMismatch("lease device key does not match")
    now = options.now or datetime.now(UTC)
    if now.tzinfo is None:
        raise InvalidClaims("verification time must include a timezone")
    if time_order_key(claims.issued_at, claims._issued_at_wire) > time_order_key(now + options.clock_leeway):
        raise LeaseTimeError("lease was issued in the future")
    if time_order_key(claims.not_before, claims._not_before_wire) > time_order_key(
        now + options.clock_leeway
    ):
        raise LeaseTimeError("lease is not yet valid")
    if time_order_key(now - options.clock_leeway) >= time_order_key(
        claims.expires_at, claims._expires_at_wire
    ):
        raise LeaseTimeError("lease has expired")
    return claims


def verify_lease_jwk(token: str, key: JWK, options: VerifyOptions) -> LeaseClaims:
    return verify_lease(token, key.public_bytes, options)
