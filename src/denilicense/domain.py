"""Typed domain objects shared by the persistence and HTTP layers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID


class Role(StrEnum):
    PLATFORM_OWNER = "platform_owner"
    LICENSE_ADMIN = "license_admin"
    SUPPORT = "support"
    AUDITOR = "auditor"
    CUSTOMER = "customer"

    @property
    def is_privileged(self) -> bool:
        return self is not Role.CUSTOMER


@dataclass(frozen=True, slots=True)
class User:
    id: UUID
    email: str
    role: Role
    status: str
    email_verified_at: datetime | None
    created_at: datetime
    password_setup_required: bool = False
    archived_at: datetime | None = None
    deleted_at: datetime | None = None
    revision: int = 1


@dataclass(frozen=True, slots=True)
class UserCredential:
    user: User
    password_hash: str


@dataclass(frozen=True, slots=True)
class Principal:
    user: User
    session_id: UUID


@dataclass(frozen=True, slots=True)
class AccountSession:
    id: UUID
    created_at: datetime
    last_seen_at: datetime
    access_expires_at: datetime
    refresh_expires_at: datetime


@dataclass(frozen=True, slots=True)
class Product:
    id: UUID
    code: str
    name: str
    description: str
    status: str
    created_at: datetime
    updated_at: datetime
    revision: int = 1


@dataclass(frozen=True, slots=True)
class IssuerKey:
    key_id: str
    issuer: str
    public_key: bytes
    status: str
    not_before: datetime
    not_after: datetime | None
    created_at: datetime


@dataclass(frozen=True, slots=True)
class License:
    id: UUID
    serial: UUID
    product_id: UUID
    product_code: str
    owner_user_id: UUID | None
    owner_email: str
    source: str
    state: str
    subject: str
    issued_at: datetime
    not_before: datetime
    expires_at: datetime | None
    max_activations: int
    offline_grace_seconds: int
    entitlements: dict[str, Any]
    metadata: dict[str, Any]
    revision: int
    claim_code_suffix: str
    claimed_at: datetime | None
    created_at: datetime
    updated_at: datetime
    archived_at: datetime | None = None
    deleted_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class LicenseRequest:
    id: UUID
    requester_user_id: UUID
    requester_email: str
    product_id: UUID
    product_code: str
    product_name: str
    requested_activations: int
    message: str
    status: str
    admin_notes: str
    reviewed_by: UUID | None
    reviewed_at: datetime | None
    fulfilled_license_id: UUID | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class Activation:
    id: UUID
    license_id: UUID
    device_key_thumbprint: bytes
    label: str
    state: str
    activated_at: datetime
    last_seen_at: datetime
    lease_expires_at: datetime
    deactivated_at: datetime | None


@dataclass(frozen=True, slots=True)
class AdminActivation:
    """An installation record enriched with its administrative license context.

    The device thumbprint is a stable pseudonymous identifier for the
    installation key.  It is not a hardware fingerprint and must not be
    presented as proof of a particular physical machine.
    """

    id: UUID
    license_id: UUID
    license_serial: UUID
    product_code: str
    owner_user_id: UUID | None
    owner_email: str
    device_key_thumbprint: bytes
    label: str
    state: str
    activated_at: datetime
    last_seen_at: datetime
    lease_expires_at: datetime
    deactivated_at: datetime | None


@dataclass(frozen=True, slots=True)
class DashboardSummary:
    total_licenses: int
    active_licenses: int
    suspended_licenses: int
    revoked_licenses: int
    claimed_licenses: int
    unclaimed_licenses: int
    total_activations: int
    active_activations: int
    deactivated_activations: int
    current_leases: int
    expiring_licenses_30_days: int
    total_users: int
    active_users: int
    total_products: int
    active_products: int


@dataclass(frozen=True, slots=True)
class RenewalChallenge:
    id: UUID
    activation_id: UUID
    nonce_hash: bytes
    device_public_key: bytes
    expires_at: datetime
    consumed_at: datetime | None


@dataclass(frozen=True, slots=True)
class AuditRecord:
    id: int
    occurred_at: datetime
    actor_user_id: UUID | None
    actor_kind: str
    action: str
    target_type: str
    target_id: str
    request_id: str
    outcome: str
    details: dict[str, Any]


@dataclass(slots=True)
class AuditEvent:
    action: str
    target_type: str
    actor_user_id: UUID | None = None
    actor_kind: str = "user"
    target_id: str = ""
    request_id: str = "unknown"
    outcome: str = "success"
    details: dict[str, Any] = field(default_factory=dict)


class StoreError(Exception):
    """Base class for expected persistence outcomes."""


class NotFoundError(StoreError):
    pass


class ConflictError(StoreError):
    pass


class InvalidError(StoreError):
    pass


class UnauthorizedError(StoreError):
    pass


class RefreshReuseError(StoreError):
    pass


class SeatLimitError(StoreError):
    pass


class LicenseStateError(StoreError):
    pass


class AlreadyClaimedError(StoreError):
    pass
