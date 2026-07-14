"""Strict HTTP request schemas for the DeniLicense API."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, field_validator

PRODUCT_CODE = re.compile(r"^[A-Z][A-Z0-9_-]{1,63}$")
ISSUER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{1,255}$")
ENTITLEMENT_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
RFC3339 = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)


def parse_rfc3339_datetime(value: Any) -> datetime:
    """Permit only explicit RFC 3339 strings through otherwise strict models."""
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and RFC3339.fullmatch(value):
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ValueError("timestamp must be valid RFC 3339") from exc
    else:
        raise ValueError("timestamp must be an RFC 3339 string")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed


RequestDatetime = Annotated[datetime, BeforeValidator(parse_rfc3339_datetime)]


class StrictRequest(BaseModel):
    """Reject unknown fields, coercion, and incorrectly cased aliases."""

    model_config = ConfigDict(extra="forbid", strict=True, populate_by_name=False)


class RegisterRequest(StrictRequest):
    email: Annotated[str, Field(min_length=3, max_length=254)]
    password: Annotated[str, Field(min_length=1, max_length=1024)]


class EmailRequest(StrictRequest):
    email: Annotated[str, Field(min_length=1, max_length=254)]


class TokenRequest(StrictRequest):
    token: Annotated[str, Field(min_length=1, max_length=128)]


class LoginRequest(RegisterRequest):
    pass


class RefreshRequest(StrictRequest):
    refresh_token: Annotated[str, Field(alias="refreshToken", min_length=1, max_length=128)]


class PasswordResetConfirmRequest(StrictRequest):
    token: Annotated[str, Field(min_length=1, max_length=128)]
    new_password: Annotated[str, Field(alias="newPassword", min_length=1, max_length=1024)]


class CreateProductRequest(StrictRequest):
    code: Annotated[str, Field(min_length=2, max_length=64)]
    name: Annotated[str, Field(min_length=1, max_length=120)]
    description: Annotated[str, Field(max_length=2000)] = ""


class RegisterIssuerRequest(StrictRequest):
    issuer: Annotated[str, Field(min_length=2, max_length=256)]
    public_key_document: Annotated[str, Field(alias="publicKeyDocument", min_length=1, max_length=16 * 1024)]
    not_before: RequestDatetime | None = Field(default=None, alias="notBefore")
    not_after: RequestDatetime | None = Field(default=None, alias="notAfter")


class IssuerStatusRequest(StrictRequest):
    status: Literal["active", "retired", "revoked"]


Entitlement = bool | int | str


def validate_entitlements(value: Any) -> dict[str, Entitlement]:
    if not isinstance(value, dict) or len(value) > 128:
        raise ValueError("entitlements must be an object with at most 128 entries")
    result: dict[str, Entitlement] = {}
    for name, item in value.items():
        if not isinstance(name, str) or not ENTITLEMENT_NAME.fullmatch(name):
            raise ValueError("invalid entitlement name")
        if (
            type(item) is bool
            or (type(item) is int and -(2**63) <= item <= 2**63 - 1)
            or (
                isinstance(item, str)
                and len(item) <= 4096
                and not any(ord(character) < 32 or ord(character) == 127 for character in item)
            )
        ):
            result[name] = item
        else:
            raise ValueError("entitlement values must be booleans, integers, or bounded text")
    return result


class CreateLicenseRequest(StrictRequest):
    product_code: Annotated[str, Field(alias="productCode", min_length=2, max_length=64)]
    subject: Annotated[str, Field(max_length=320)] = ""
    not_before: RequestDatetime | None = Field(default=None, alias="notBefore")
    expires_at: RequestDatetime | None = Field(default=None, alias="expiresAt")
    max_activations: Annotated[int, Field(alias="maxActivations", ge=1, le=100_000)]
    offline_grace_seconds: Annotated[int, Field(alias="offlineGraceSeconds", ge=0, le=30 * 86_400)] = 0
    perpetual: bool = False
    entitlements: dict[str, Entitlement]

    @field_validator("entitlements")
    @classmethod
    def _entitlements(cls, value: Any) -> dict[str, Entitlement]:
        return validate_entitlements(value)


class ImportLicenseRequest(StrictRequest):
    artifact: Annotated[str, Field(min_length=1, max_length=24 * 1024)]


class ClaimLicenseRequest(StrictRequest):
    claim_code: Annotated[str, Field(alias="claimCode", min_length=1, max_length=128)]


class ActivationRequest(StrictRequest):
    device_public_key: Annotated[str, Field(alias="devicePublicKey", min_length=43, max_length=43)]
    label: Annotated[str, Field(max_length=120)] = ""


class LicenseStateRequest(StrictRequest):
    state: Literal["active", "suspended", "revoked"]


class RenewalChallengeRequest(StrictRequest):
    activation_id: Annotated[str, Field(alias="activationId", min_length=36, max_length=36)]


class CompleteRenewalRequest(StrictRequest):
    challenge_id: Annotated[str, Field(alias="challengeId", min_length=36, max_length=36)]
    nonce: Annotated[str, Field(min_length=43, max_length=43)]
    signature: Annotated[str, Field(min_length=86, max_length=86)]


UserRole = Literal["platform_owner", "license_admin", "support", "auditor", "customer"]


class CreateManagedUserRequest(StrictRequest):
    email: Annotated[str, Field(min_length=3, max_length=254)]
    role: UserRole


class UserRoleRequest(StrictRequest):
    role: UserRole


class UserStatusRequest(StrictRequest):
    status: Literal["active", "disabled"]


class UserAccessRequest(StrictRequest):
    role: UserRole
    status: Literal["active", "disabled"]
