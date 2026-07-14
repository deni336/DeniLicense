# ruff: noqa: S608
"""Synchronous PostgreSQL persistence for DeniLicense.

All state-changing security operations use explicit transactions. Locks are
acquired in the canonical license -> activation -> challenge order.
"""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any
from uuid import UUID

from psycopg import Connection
from psycopg.errors import UniqueViolation
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from .database import migrate, ping, verify_migrations
from .domain import (
    Activation,
    AdminActivation,
    AuditEvent,
    AuditRecord,
    ConflictError,
    DashboardSummary,
    InvalidError,
    IssuerKey,
    License,
    LicenseStateError,
    NotFoundError,
    Principal,
    Product,
    RefreshReuseError,
    RenewalChallenge,
    Role,
    SeatLimitError,
    UnauthorizedError,
    User,
    UserCredential,
)

UTC = UTC
OWNER_MANAGEMENT_LOCK = 1_947_259_832
CLEANUP_BATCH_SIZE = 1_000
VALID_ROLES = frozenset(Role)


@dataclass(frozen=True, slots=True)
class CreateUserParams:
    id: UUID
    email: str
    normalized_email: str
    password_hash: str
    role: Role
    verification_token_id: UUID
    verification_token_hash: bytes
    verification_token_expiry: datetime


@dataclass(frozen=True, slots=True)
class CreateManagedUserParams:
    id: UUID
    email: str
    normalized_email: str
    password_hash: str
    role: Role
    password_reset_token_id: UUID
    password_reset_token_hash: bytes
    password_reset_token_expiry: datetime
    actor_user_id: UUID
    audit: AuditEvent


@dataclass(frozen=True, slots=True)
class CreateSessionParams:
    session_id: UUID
    family_id: UUID
    user_id: UUID
    access_hash: bytes
    access_expires_at: datetime
    refresh_token_id: UUID
    refresh_hash: bytes
    refresh_expires_at: datetime


@dataclass(frozen=True, slots=True)
class RotateSessionParams:
    old_refresh_hash: bytes
    new_refresh_id: UUID
    new_refresh_hash: bytes
    new_access_hash: bytes
    access_expires_at: datetime
    refresh_expires_at: datetime
    now: datetime


@dataclass(frozen=True, slots=True)
class RotateSessionResult:
    access_expires_at: datetime
    refresh_expires_at: datetime


@dataclass(frozen=True, slots=True)
class CreateProductParams:
    id: UUID
    code: str
    name: str
    description: str
    created_by: UUID
    audit: AuditEvent


@dataclass(frozen=True, slots=True)
class RegisterIssuerParams:
    key_id: str
    issuer: str
    public_key: bytes
    fingerprint: bytes
    not_before: datetime
    not_after: datetime | None
    created_by: UUID
    audit: AuditEvent


@dataclass(frozen=True, slots=True)
class CreateLicenseParams:
    id: UUID
    serial: UUID
    product_id: UUID
    source: str
    issuer_key_id: str | None
    import_artifact: str | None
    import_artifact_hash: bytes | None
    creation_request_hash: bytes | None
    claim_code_hash: bytes
    claim_code_suffix: str
    subject: str
    issued_at: datetime
    not_before: datetime
    expires_at: datetime | None
    max_activations: int
    offline_grace_seconds: int
    entitlements: dict[str, Any]
    metadata: dict[str, Any]
    created_by: UUID
    audit: AuditEvent


@dataclass(frozen=True, slots=True)
class ActivateParams:
    id: UUID
    license_id: UUID
    owner_user_id: UUID
    device_public_key: bytes
    label: str
    now: datetime
    lease_expires_at: datetime
    audit: AuditEvent


@dataclass(frozen=True, slots=True)
class UpdateUserAccessParams:
    user_id: UUID
    actor_user_id: UUID
    role: Role | None = None
    status: str | None = None
    audit: AuditEvent = field(default_factory=lambda: AuditEvent("user.access_update", "user"))


@dataclass(frozen=True, slots=True)
class LicenseListFilter:
    serial: UUID | None = None
    owner_normalized_email: str = ""
    claim_code_suffix: str = ""
    product_code: str = ""
    state: str = ""
    limit: int = 100


@dataclass(frozen=True, slots=True)
class AuditListFilter:
    before_id: int = 0
    action: str = ""
    target_type: str = ""
    target_id: str = ""
    actor_user_id: UUID | None = None
    limit: int = 100


@dataclass(frozen=True, slots=True)
class AdminActivationListFilter:
    license_id: UUID | None = None
    serial: UUID | None = None
    owner_normalized_email: str = ""
    product_code: str = ""
    state: str = ""
    label: str = ""
    device_key_thumbprint: bytes | None = None
    limit: int = 100


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise InvalidError("timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _hash32(value: bytes, name: str) -> bytes:
    value = bytes(value)
    if len(value) != 32:
        raise InvalidError(f"{name} must contain exactly 32 bytes")
    return value


def _user(row: Mapping[str, Any]) -> User:
    return User(
        id=row["id"],
        email=row["email"],
        role=Role(row["role"]),
        status=row["status"],
        email_verified_at=row["email_verified_at"],
        created_at=row["created_at"],
    )


def _product(row: Mapping[str, Any]) -> Product:
    return Product(**{name: row[name] for name in Product.__dataclass_fields__})


def _issuer(row: Mapping[str, Any]) -> IssuerKey:
    return IssuerKey(
        key_id=row["key_id"],
        issuer=row["issuer"],
        public_key=bytes(row["public_key"]),
        status=row["status"],
        not_before=row["not_before"],
        not_after=row["not_after"],
        created_at=row["created_at"],
    )


def _license(row: Mapping[str, Any]) -> License:
    return License(**{name: row[name] for name in License.__dataclass_fields__})


def _activation(row: Mapping[str, Any]) -> Activation:
    values = {name: row[name] for name in Activation.__dataclass_fields__}
    values["device_key_thumbprint"] = bytes(values["device_key_thumbprint"])
    return Activation(**values)


def _admin_activation(row: Mapping[str, Any]) -> AdminActivation:
    values = {name: row[name] for name in AdminActivation.__dataclass_fields__}
    values["device_key_thumbprint"] = bytes(values["device_key_thumbprint"])
    return AdminActivation(**values)


USER_SELECT = "id, email, role, status, email_verified_at, created_at"
PRODUCT_SELECT = "id, code, name, description, status, created_at, updated_at"
ACTIVATION_SELECT = (
    "id, license_id, device_key_thumbprint, label, state, "
    "activated_at, last_seen_at, lease_expires_at, deactivated_at"
)
LICENSE_SELECT = """
    SELECT l.id, l.serial, l.product_id, p.code AS product_code,
           l.owner_user_id, COALESCE(u.email, '') AS owner_email,
           l.source, l.state, l.subject, l.issued_at, l.not_before, l.expires_at,
           l.max_activations, l.offline_grace_seconds, l.entitlements, l.metadata,
           l.revision, l.claim_code_suffix, l.claim_consumed_at AS claimed_at,
           l.created_at, l.updated_at
    FROM licenses l
    JOIN products p ON p.id = l.product_id
    LEFT JOIN users u ON u.id = l.owner_user_id
"""


class Store:
    def __init__(self, pool: ConnectionPool):
        self.pool = pool

    def close(self) -> None:
        self.pool.close()

    def ping(self) -> None:
        ping(self.pool)

    def migrate(self) -> None:
        migrate(self.pool)

    def verify_migrations(self) -> None:
        verify_migrations(self.pool)

    def create_user(self, params: CreateUserParams) -> User:
        token_hash = _hash32(params.verification_token_hash, "verification token hash")
        try:
            with self.pool.connection() as conn, conn.transaction():
                row = conn.execute(
                    f"""
                    INSERT INTO users (id, email, normalized_email, password_hash, role)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING {USER_SELECT}
                    """,
                    (
                        params.id,
                        params.email,
                        params.normalized_email,
                        params.password_hash,
                        params.role.value,
                    ),
                ).fetchone()
                conn.execute(
                    """INSERT INTO email_verification_tokens (id, user_id, token_hash, expires_at)
                       VALUES (%s, %s, %s, %s)""",
                    (
                        params.verification_token_id,
                        params.id,
                        token_hash,
                        _utc(params.verification_token_expiry),
                    ),
                )
                return _user(row)
        except UniqueViolation as exc:
            raise ConflictError("email or token already exists") from exc

    def create_managed_user(self, params: CreateManagedUserParams) -> User:
        """Create an owner-provisioned, verified account with a setup token.

        The acting owner's access is checked again under the owner-management
        lock so a concurrent demotion cannot race a privileged account create.
        The caller supplies a high-entropy, unusable password hash; the new
        user establishes their own password with the single-use reset token.
        """

        if params.role not in VALID_ROLES:
            raise InvalidError("invalid role")
        token_hash = _hash32(params.password_reset_token_hash, "password reset token hash")
        try:
            with self.pool.connection() as conn, conn.transaction():
                conn.execute("SELECT pg_advisory_xact_lock(%s)", (OWNER_MANAGEMENT_LOCK,))
                actor = conn.execute(
                    "SELECT role, status FROM users WHERE id=%s FOR SHARE",
                    (params.actor_user_id,),
                ).fetchone()
                if actor is None or actor["role"] != Role.PLATFORM_OWNER.value or actor["status"] != "active":
                    raise UnauthorizedError("actor is not an active platform owner")
                now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
                row = conn.execute(
                    f"""INSERT INTO users
                        (id, email, normalized_email, password_hash, role, email_verified_at)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        RETURNING {USER_SELECT}""",
                    (
                        params.id,
                        params.email,
                        params.normalized_email,
                        params.password_hash,
                        params.role.value,
                        now,
                    ),
                ).fetchone()
                conn.execute(
                    """INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at)
                       VALUES (%s, %s, %s, %s)""",
                    (
                        params.password_reset_token_id,
                        params.id,
                        token_hash,
                        _utc(params.password_reset_token_expiry),
                    ),
                )
                details = dict(params.audit.details)
                details.update(
                    {
                        "role": params.role.value,
                        "status": "active",
                        "passwordSetupRequired": True,
                    }
                )
                self._insert_audit(
                    conn,
                    replace(params.audit, target_id=str(params.id), details=details),
                )
                return _user(row)
        except UniqueViolation as exc:
            raise ConflictError("email or token already exists") from exc

    def user_credential_by_email(self, normalized_email: str) -> UserCredential:
        with self.pool.connection() as conn:
            row = conn.execute(
                f"SELECT {USER_SELECT}, password_hash FROM users WHERE normalized_email = %s",
                (normalized_email,),
            ).fetchone()
        if row is None:
            raise NotFoundError("user not found")
        return UserCredential(_user(row), row["password_hash"])

    def verify_email(self, token_hash: bytes, now: datetime) -> User:
        token_hash = _hash32(token_hash, "verification token hash")
        now = _utc(now)
        with self.pool.connection() as conn, conn.transaction():
            row = conn.execute(
                "SELECT user_id FROM email_verification_tokens WHERE token_hash = %s",
                (token_hash,),
            ).fetchone()
            if row is None:
                raise NotFoundError("verification token not found")
            user_id = row["user_id"]
            if conn.execute("SELECT id FROM users WHERE id = %s FOR UPDATE", (user_id,)).fetchone() is None:
                raise NotFoundError("user not found")
            token = conn.execute(
                """UPDATE email_verification_tokens SET consumed_at = %s
                   WHERE token_hash = %s AND consumed_at IS NULL AND expires_at > %s
                   RETURNING id""",
                (now, token_hash, now),
            ).fetchone()
            if token is None:
                raise NotFoundError("verification token is invalid or expired")
            user_row = conn.execute(
                f"""UPDATE users SET email_verified_at = COALESCE(email_verified_at, %s), updated_at = %s
                    WHERE id = %s RETURNING {USER_SELECT}""",
                (now, now, user_id),
            ).fetchone()
            conn.execute(
                """UPDATE email_verification_tokens SET consumed_at = COALESCE(consumed_at, %s)
                   WHERE user_id = %s""",
                (now, user_id),
            )
            self._insert_audit(
                conn,
                AuditEvent(
                    "user.email_verify",
                    "user",
                    actor_kind="anonymous",
                    target_id=str(user_id),
                    request_id="auth-token",
                ),
            )
            return _user(user_row)

    def replace_email_verification_token(
        self, normalized_email: str, token_id: UUID, token_hash: bytes, expires_at: datetime
    ) -> tuple[str, bool]:
        return self._replace_account_token(
            "email_verification_tokens",
            normalized_email,
            token_id,
            token_hash,
            expires_at,
            require_unverified=True,
        )

    def replace_password_reset_token(
        self, normalized_email: str, token_id: UUID, token_hash: bytes, expires_at: datetime
    ) -> tuple[str, bool]:
        return self._replace_account_token(
            "password_reset_tokens",
            normalized_email,
            token_id,
            token_hash,
            expires_at,
            require_unverified=False,
        )

    def _replace_account_token(
        self,
        table: str,
        normalized_email: str,
        token_id: UUID,
        token_hash: bytes,
        expires_at: datetime,
        *,
        require_unverified: bool,
    ) -> tuple[str, bool]:
        # table is an internal constant selected by the two public wrappers.
        if table not in {"email_verification_tokens", "password_reset_tokens"}:
            raise AssertionError("invalid token table")
        token_hash = _hash32(token_hash, "account token hash")
        predicate = "AND email_verified_at IS NULL" if require_unverified else ""
        with self.pool.connection() as conn, conn.transaction():
            row = conn.execute(
                f"""SELECT id, email FROM users
                    WHERE normalized_email = %s AND status = 'active' {predicate} FOR UPDATE""",
                (normalized_email,),
            ).fetchone()
            if row is None:
                return "", False
            conn.execute(
                f"INSERT INTO {table} (id, user_id, token_hash, expires_at) VALUES (%s, %s, %s, %s)",
                (token_id, row["id"], token_hash, _utc(expires_at)),
            )
            return row["email"], True

    def consume_password_reset_token(self, token_hash: bytes, new_password_hash: str, now: datetime) -> None:
        token_hash = _hash32(token_hash, "password reset token hash")
        now = _utc(now)
        with self.pool.connection() as conn, conn.transaction():
            row = conn.execute(
                "SELECT user_id FROM password_reset_tokens WHERE token_hash = %s", (token_hash,)
            ).fetchone()
            if row is None:
                raise NotFoundError("password reset token not found")
            user_id = row["user_id"]
            if (
                conn.execute(
                    "SELECT id FROM users WHERE id = %s AND status = 'active' FOR UPDATE", (user_id,)
                ).fetchone()
                is None
            ):
                raise NotFoundError("active user not found")
            consumed = conn.execute(
                """UPDATE password_reset_tokens SET consumed_at = %s
                   WHERE token_hash = %s AND consumed_at IS NULL AND expires_at > %s RETURNING id""",
                (now, token_hash, now),
            ).fetchone()
            if consumed is None:
                raise NotFoundError("password reset token is invalid or expired")
            conn.execute(
                "UPDATE users SET password_hash = %s, updated_at = %s WHERE id = %s",
                (new_password_hash, now, user_id),
            )
            conn.execute(
                """UPDATE password_reset_tokens SET consumed_at = COALESCE(consumed_at, %s)
                   WHERE user_id = %s""",
                (now, user_id),
            )
            conn.execute(
                "UPDATE sessions SET revoked_at = COALESCE(revoked_at, %s) WHERE user_id = %s",
                (now, user_id),
            )
            self._insert_audit(
                conn,
                AuditEvent(
                    "user.password_reset",
                    "user",
                    actor_kind="anonymous",
                    target_id=str(user_id),
                    request_id="password-reset-token",
                ),
            )

    def create_session(self, params: CreateSessionParams) -> None:
        access_hash = _hash32(params.access_hash, "access token hash")
        refresh_hash = _hash32(params.refresh_hash, "refresh token hash")
        access_expiry = _utc(params.access_expires_at)
        refresh_expiry = _utc(params.refresh_expires_at)
        if access_expiry > refresh_expiry:
            raise InvalidError("access expiry cannot exceed refresh expiry")
        with self.pool.connection() as conn, conn.transaction():
            user = conn.execute(
                """SELECT id FROM users WHERE id=%s AND status='active'
                   AND email_verified_at IS NOT NULL FOR SHARE""",
                (params.user_id,),
            ).fetchone()
            if user is None:
                raise UnauthorizedError("user cannot start a session")
            now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
            if access_expiry <= now or refresh_expiry <= now:
                raise InvalidError("session expiry must be in the future")
            conn.execute(
                """INSERT INTO sessions
                   (id, family_id, user_id, access_token_hash, access_expires_at, refresh_expires_at)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (
                    params.session_id,
                    params.family_id,
                    params.user_id,
                    access_hash,
                    access_expiry,
                    refresh_expiry,
                ),
            )
            conn.execute(
                """INSERT INTO refresh_tokens (id, session_id, token_hash, expires_at)
                   VALUES (%s, %s, %s, %s)""",
                (params.refresh_token_id, params.session_id, refresh_hash, refresh_expiry),
            )

    def principal_by_access_hash(self, access_hash: bytes, now: datetime) -> Principal:
        access_hash = _hash32(access_hash, "access token hash")
        with self.pool.connection() as conn:
            row = conn.execute(
                f"""SELECT {", ".join("u." + name.strip() for name in USER_SELECT.split(","))},
                           s.id AS session_id
                    FROM sessions s JOIN users u ON u.id = s.user_id
                    WHERE s.access_token_hash = %s AND s.revoked_at IS NULL
                      AND s.access_expires_at > %s AND u.status = 'active'""",
                (access_hash, _utc(now)),
            ).fetchone()
        if row is None:
            raise UnauthorizedError("access token is not valid")
        return Principal(_user(row), row["session_id"])

    def rotate_session(self, params: RotateSessionParams) -> RotateSessionResult:
        old_hash = _hash32(params.old_refresh_hash, "refresh token hash")
        new_refresh_hash = _hash32(params.new_refresh_hash, "new refresh token hash")
        new_access_hash = _hash32(params.new_access_hash, "new access token hash")
        now = _utc(params.now)
        reused = False
        result: RotateSessionResult | None = None
        with self.pool.connection() as conn, conn.transaction():
            family = conn.execute(
                """SELECT s.family_id FROM refresh_tokens rt
                   JOIN sessions s ON s.id=rt.session_id WHERE rt.token_hash=%s""",
                (old_hash,),
            ).fetchone()
            if family is None:
                raise UnauthorizedError("refresh token is not valid")
            # One rotation per family avoids sibling refreshes deadlocking while
            # they revoke or update overlapping session rows.
            conn.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (str(family["family_id"]),),
            )
            row = conn.execute(
                """SELECT rt.id, rt.session_id, s.family_id, rt.used_at, s.revoked_at,
                          rt.expires_at AS token_expiry, s.refresh_expires_at AS session_refresh_expiry
                   FROM refresh_tokens rt JOIN sessions s ON s.id = rt.session_id
                   WHERE rt.token_hash = %s FOR UPDATE OF rt, s""",
                (old_hash,),
            ).fetchone()
            if row is None:
                raise UnauthorizedError("refresh token is not valid")
            if row["used_at"] is not None:
                conn.execute(
                    "UPDATE sessions SET revoked_at = COALESCE(revoked_at, %s) WHERE family_id = %s",
                    (now, row["family_id"]),
                )
                reused = True
            elif (
                row["revoked_at"] is not None
                or row["token_expiry"] <= now
                or row["session_refresh_expiry"] <= now
            ):
                raise UnauthorizedError("refresh token is not valid")
            else:
                access_expiry = min(_utc(params.access_expires_at), row["session_refresh_expiry"])
                refresh_expiry = min(_utc(params.refresh_expires_at), row["session_refresh_expiry"])
                if access_expiry <= now or refresh_expiry <= now:
                    raise UnauthorizedError("refresh token is not valid")
                conn.execute("UPDATE refresh_tokens SET used_at = %s WHERE id = %s", (now, row["id"]))
                conn.execute(
                    """UPDATE sessions SET access_token_hash = %s, access_expires_at = %s,
                              last_seen_at = %s WHERE id = %s""",
                    (new_access_hash, access_expiry, now, row["session_id"]),
                )
                conn.execute(
                    """INSERT INTO refresh_tokens (id, session_id, token_hash, expires_at)
                       VALUES (%s,%s,%s,%s)""",
                    (params.new_refresh_id, row["session_id"], new_refresh_hash, refresh_expiry),
                )
                result = RotateSessionResult(access_expiry, refresh_expiry)
        if reused:
            raise RefreshReuseError("refresh token reuse detected; token family revoked")
        assert result is not None
        return result

    def revoke_session(self, session_id: UUID, now: datetime) -> None:
        with self.pool.connection() as conn, conn.transaction():
            row = conn.execute(
                """UPDATE sessions SET revoked_at = COALESCE(revoked_at, %s)
                   WHERE id = %s RETURNING id""",
                (_utc(now), session_id),
            ).fetchone()
            if row is None:
                raise NotFoundError("session not found")

    def revoke_all_user_sessions(self, user_id: UUID, now: datetime) -> None:
        with self.pool.connection() as conn, conn.transaction():
            conn.execute(
                "UPDATE sessions SET revoked_at = COALESCE(revoked_at, %s) WHERE user_id = %s",
                (_utc(now), user_id),
            )

    def bootstrap_owner(
        self, user_id: UUID, email: str, normalized_email: str, password_hash: str, now: datetime
    ) -> User:
        try:
            with self.pool.connection() as conn, conn.transaction():
                conn.execute("SELECT pg_advisory_xact_lock(%s)", (OWNER_MANAGEMENT_LOCK,))
                if conn.execute(
                    "SELECT EXISTS (SELECT 1 FROM users WHERE role = 'platform_owner') AS exists"
                ).fetchone()["exists"]:
                    raise ConflictError("a platform owner already exists")
                row = conn.execute(
                    f"""INSERT INTO users
                        (id, email, normalized_email, password_hash, role, email_verified_at)
                        VALUES (%s,%s,%s,%s,'platform_owner',%s) RETURNING {USER_SELECT}""",
                    (user_id, email, normalized_email, password_hash, _utc(now)),
                ).fetchone()
                self._insert_audit(
                    conn,
                    AuditEvent(
                        "platform_owner.bootstrap",
                        "user",
                        actor_kind="system",
                        target_id=str(user_id),
                        request_id="bootstrap-cli",
                    ),
                )
                return _user(row)
        except UniqueViolation as exc:
            raise ConflictError("owner account already exists") from exc

    def create_product(self, params: CreateProductParams) -> Product:
        try:
            with self.pool.connection() as conn, conn.transaction():
                row = conn.execute(
                    f"""INSERT INTO products (id, code, name, description, created_by)
                        VALUES (%s,%s,%s,%s,%s) RETURNING {PRODUCT_SELECT}""",
                    (params.id, params.code, params.name, params.description, params.created_by),
                ).fetchone()
                self._insert_audit(conn, replace(params.audit, target_id=str(params.id)))
                return _product(row)
        except UniqueViolation as exc:
            raise ConflictError("product code already exists") from exc

    def list_products(self, include_retired: bool = False) -> list[Product]:
        predicate = "" if include_retired else " WHERE status = 'active'"
        with self.pool.connection() as conn:
            rows = conn.execute(f"SELECT {PRODUCT_SELECT} FROM products{predicate} ORDER BY code").fetchall()
        return [_product(row) for row in rows]

    def product_by_code(self, code: str) -> Product:
        with self.pool.connection() as conn:
            row = conn.execute(f"SELECT {PRODUCT_SELECT} FROM products WHERE code = %s", (code,)).fetchone()
        if row is None:
            raise NotFoundError("product not found")
        return _product(row)

    def register_issuer(self, params: RegisterIssuerParams) -> IssuerKey:
        fingerprint = _hash32(params.fingerprint, "issuer fingerprint")
        if len(params.public_key) != 32:
            raise InvalidError("issuer public key must contain exactly 32 bytes")
        try:
            with self.pool.connection() as conn, conn.transaction():
                row = conn.execute(
                    """INSERT INTO issuer_keys
                       (key_id, issuer, public_key, fingerprint_sha256, not_before, not_after, created_by)
                       VALUES (%s,%s,%s,%s,%s,%s,%s)
                       RETURNING key_id, issuer, public_key, status, not_before, not_after, created_at""",
                    (
                        params.key_id,
                        params.issuer,
                        params.public_key,
                        fingerprint,
                        _utc(params.not_before),
                        _utc(params.not_after) if params.not_after else None,
                        params.created_by,
                    ),
                ).fetchone()
                self._insert_audit(conn, replace(params.audit, target_id=params.key_id))
                return _issuer(row)
        except UniqueViolation as exc:
            raise ConflictError("issuer key or fingerprint already exists") from exc

    def issuer_by_key_id(self, key_id: str) -> IssuerKey:
        with self.pool.connection() as conn:
            row = conn.execute(
                """SELECT key_id, issuer, public_key, status, not_before, not_after, created_at
                   FROM issuer_keys WHERE key_id = %s""",
                (key_id,),
            ).fetchone()
        if row is None:
            raise NotFoundError("issuer key not found")
        return _issuer(row)

    def list_issuers(self, status: str = "", limit: int = 100) -> list[IssuerKey]:
        self._validate_limit(limit)
        if status and status not in {"active", "retired", "revoked"}:
            raise InvalidError("invalid issuer status")
        with self.pool.connection() as conn:
            rows = conn.execute(
                """SELECT key_id, issuer, public_key, status, not_before, not_after, created_at
                   FROM issuer_keys WHERE (%s='' OR status=%s)
                   ORDER BY created_at DESC, key_id DESC LIMIT %s""",
                (status, status, limit),
            ).fetchall()
        return [_issuer(row) for row in rows]

    def update_issuer_status(self, key_id: str, status: str, actor: UUID, audit: AuditEvent) -> None:
        if status not in {"active", "retired", "revoked"}:
            raise InvalidError("invalid issuer status")
        with self.pool.connection() as conn, conn.transaction():
            row = conn.execute(
                "SELECT status FROM issuer_keys WHERE key_id = %s FOR UPDATE", (key_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError("issuer key not found")
            current = row["status"]
            if current == "revoked" and status != "revoked":
                raise ConflictError("a revoked issuer key cannot be reactivated")
            if current == status:
                return
            conn.execute(
                "UPDATE issuer_keys SET status = %s, updated_at = now() WHERE key_id = %s",
                (status, key_id),
            )
            self._insert_audit(conn, replace(audit, actor_user_id=actor, target_id=key_id))

    def create_license(self, params: CreateLicenseParams) -> tuple[License, bool]:
        _hash32(params.claim_code_hash, "claim code hash")
        if params.import_artifact_hash is not None:
            _hash32(params.import_artifact_hash, "import artifact hash")
        if params.creation_request_hash is not None:
            _hash32(params.creation_request_hash, "creation request hash")
        if params.source not in {"offline_import", "online"}:
            raise InvalidError("invalid license source")
        try:
            with self.pool.connection() as conn, conn.transaction():
                conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (str(params.serial),))
                existing = conn.execute(
                    """SELECT id, source, import_artifact_hash, creation_request_hash
                       FROM licenses WHERE serial = %s FOR UPDATE""",
                    (params.serial,),
                ).fetchone()
                if existing is not None:
                    same_offline = (
                        params.source == "offline_import"
                        and existing["source"] == params.source
                        and params.import_artifact_hash is not None
                        and hmac.compare_digest(
                            bytes(existing["import_artifact_hash"] or b""), params.import_artifact_hash
                        )
                    )
                    same_online = (
                        params.source == "online"
                        and existing["source"] == params.source
                        and params.creation_request_hash is not None
                        and hmac.compare_digest(
                            bytes(existing["creation_request_hash"] or b""), params.creation_request_hash
                        )
                    )
                    if same_offline or same_online:
                        return self._license_by_id_conn(conn, existing["id"]), True
                    raise ConflictError("serial is already associated with different license data")
                if params.source == "offline_import":
                    if params.issuer_key_id is None:
                        raise InvalidError("offline import requires an issuer key")
                    issuer = conn.execute(
                        """SELECT status, not_before, not_after FROM issuer_keys
                           WHERE key_id = %s FOR SHARE""",
                        (params.issuer_key_id,),
                    ).fetchone()
                    issued_at = _utc(params.issued_at)
                    if (
                        issuer is None
                        or issuer["status"] != "active"
                        or issued_at < issuer["not_before"]
                        or (issuer["not_after"] is not None and issued_at >= issuer["not_after"])
                    ):
                        raise InvalidError("issuer key is not valid at the license issue time")
                conn.execute(
                    """INSERT INTO licenses
                       (id, serial, product_id, source, issuer_key_id, import_artifact,
                        import_artifact_hash, creation_request_hash, claim_code_hash,
                        claim_code_suffix, subject, issued_at, not_before, expires_at,
                        max_activations, offline_grace_seconds, entitlements, metadata, created_by)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (
                        params.id,
                        params.serial,
                        params.product_id,
                        params.source,
                        params.issuer_key_id,
                        params.import_artifact,
                        params.import_artifact_hash,
                        params.creation_request_hash,
                        params.claim_code_hash,
                        params.claim_code_suffix,
                        params.subject,
                        _utc(params.issued_at),
                        _utc(params.not_before),
                        _utc(params.expires_at) if params.expires_at else None,
                        params.max_activations,
                        params.offline_grace_seconds,
                        Jsonb(params.entitlements),
                        Jsonb(params.metadata),
                        params.created_by,
                    ),
                )
                self._insert_audit(conn, replace(params.audit, target_id=str(params.id)))
                return self._license_by_id_conn(conn, params.id), False
        except UniqueViolation as exc:
            raise ConflictError("license identifiers already exist") from exc

    def claim_license(self, code_hash: bytes, user_id: UUID, now: datetime, audit: AuditEvent) -> License:
        code_hash = _hash32(code_hash, "claim code hash")
        now = _utc(now)
        with self.pool.connection() as conn, conn.transaction():
            row = conn.execute(
                """SELECT id, owner_user_id, state, not_before, expires_at
                   FROM licenses WHERE claim_code_hash = %s FOR UPDATE""",
                (code_hash,),
            ).fetchone()
            # The invalid result deliberately does not distinguish unknown,
            # claimed, expired, and revoked codes.
            if row is None:
                raise InvalidError("claim code is invalid")
            if row["owner_user_id"] is not None:
                if row["owner_user_id"] == user_id:
                    return self._license_by_id_conn(conn, row["id"])
                raise InvalidError("claim code is invalid")
            if (
                row["state"] != "active"
                or now < row["not_before"]
                or (row["expires_at"] is not None and now >= row["expires_at"])
            ):
                raise InvalidError("claim code is invalid")
            conn.execute(
                """UPDATE licenses SET owner_user_id = %s, claim_consumed_at = %s, updated_at = %s
                   WHERE id = %s""",
                (user_id, now, now, row["id"]),
            )
            self._insert_audit(conn, replace(audit, target_id=str(row["id"])))
            return self._license_by_id_conn(conn, row["id"])

    def list_user_licenses(self, user_id: UUID) -> list[License]:
        with self.pool.connection() as conn:
            rows = conn.execute(
                LICENSE_SELECT + " WHERE l.owner_user_id = %s ORDER BY l.created_at DESC", (user_id,)
            ).fetchall()
        return [_license(row) for row in rows]

    def license_for_owner(self, license_id: UUID, user_id: UUID) -> License:
        with self.pool.connection() as conn:
            row = conn.execute(
                LICENSE_SELECT + " WHERE l.id = %s AND l.owner_user_id = %s", (license_id, user_id)
            ).fetchone()
        if row is None:
            raise NotFoundError("license not found")
        return _license(row)

    def activate(self, params: ActivateParams) -> tuple[License, Activation, bool]:
        lease_ttl = _utc(params.lease_expires_at) - _utc(params.now)
        if lease_ttl <= timedelta(0):
            raise InvalidError("lease TTL must be positive")
        if len(params.device_public_key) != 32:
            raise InvalidError("device public key must contain exactly 32 bytes")
        thumbprint = sha256(b"DeniLicense/device-key/v1\x00" + params.device_public_key).digest()
        with self.pool.connection() as conn, conn.transaction():
            license = self._lock_owned_license(conn, params.license_id, params.owner_user_id)
            now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
            lease_expires_at = now + lease_ttl
            if (
                license.state != "active"
                or now < license.not_before
                or (license.expires_at is not None and now >= license.expires_at)
            ):
                raise LicenseStateError("license is not currently usable")
            lease_expires_at = min(
                lease_expires_at,
                now + timedelta(seconds=license.offline_grace_seconds),
                license.expires_at or datetime.max.replace(tzinfo=UTC),
            )
            row = conn.execute(
                f"""SELECT {ACTIVATION_SELECT} FROM activations
                    WHERE license_id = %s AND device_key_thumbprint = %s FOR UPDATE""",
                (params.license_id, thumbprint),
            ).fetchone()
            if row is not None and row["state"] == "active":
                refreshed = conn.execute(
                    f"""UPDATE activations SET last_seen_at = GREATEST(last_seen_at, %s),
                              lease_expires_at = %s, label = %s, updated_at = %s
                        WHERE id = %s RETURNING {ACTIVATION_SELECT}""",
                    (now, lease_expires_at, params.label, now, row["id"]),
                ).fetchone()
                return license, _activation(refreshed), True
            active_count = conn.execute(
                "SELECT count(*) AS count FROM activations WHERE license_id = %s AND state = 'active'",
                (params.license_id,),
            ).fetchone()["count"]
            if active_count >= license.max_activations:
                raise SeatLimitError("activation limit reached")
            if row is not None:
                activated = conn.execute(
                    f"""UPDATE activations SET state = 'active', deactivated_at = NULL, label = %s,
                              activated_at = %s, last_seen_at = %s, lease_expires_at = %s, updated_at = %s
                        WHERE id = %s RETURNING {ACTIVATION_SELECT}""",
                    (params.label, now, now, lease_expires_at, now, row["id"]),
                ).fetchone()
            else:
                activated = conn.execute(
                    f"""INSERT INTO activations
                        (id, license_id, device_key_thumbprint, device_public_key, label, lease_expires_at)
                        VALUES (%s,%s,%s,%s,%s,%s) RETURNING {ACTIVATION_SELECT}""",
                    (
                        params.id,
                        params.license_id,
                        thumbprint,
                        params.device_public_key,
                        params.label,
                        lease_expires_at,
                    ),
                ).fetchone()
            self._insert_audit(conn, replace(params.audit, target_id=str(activated["id"])))
            return license, _activation(activated), False

    def deactivate(self, activation_id: UUID, owner_user_id: UUID, now: datetime, audit: AuditEvent) -> None:
        with self.pool.connection() as conn, conn.transaction():
            row = conn.execute(
                """UPDATE activations a SET state = 'deactivated', deactivated_at = %s, updated_at = %s
                   FROM licenses l WHERE a.id = %s AND l.id = a.license_id
                   AND l.owner_user_id = %s AND a.state = 'active' RETURNING a.id""",
                (_utc(now), _utc(now), activation_id, owner_user_id),
            ).fetchone()
            if row is None:
                exists = conn.execute(
                    """SELECT EXISTS (SELECT 1 FROM activations a JOIN licenses l ON l.id=a.license_id
                       WHERE a.id=%s AND l.owner_user_id=%s) AS exists""",
                    (activation_id, owner_user_id),
                ).fetchone()["exists"]
                if not exists:
                    raise NotFoundError("activation not found")
                return
            self._insert_audit(conn, replace(audit, target_id=str(activation_id)))

    def set_license_state(self, license_id: UUID, state: str, now: datetime, audit: AuditEvent) -> None:
        if state not in {"active", "suspended", "revoked"}:
            raise InvalidError("invalid license state")
        now = _utc(now)
        with self.pool.connection() as conn, conn.transaction():
            row = conn.execute(
                "SELECT state FROM licenses WHERE id = %s FOR UPDATE", (license_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError("license not found")
            if row["state"] == "revoked" and state != "revoked":
                raise ConflictError("a revoked license cannot be reactivated")
            if row["state"] == state:
                return
            conn.execute(
                "UPDATE licenses SET state=%s, revision=revision+1, updated_at=%s WHERE id=%s",
                (state, now, license_id),
            )
            if state != "active":
                conn.execute(
                    """UPDATE activations SET state='deactivated', deactivated_at=%s, updated_at=%s
                       WHERE license_id=%s AND state='active'""",
                    (now, now, license_id),
                )
            self._insert_audit(conn, replace(audit, target_id=str(license_id)))

    def create_renewal_challenge(
        self,
        challenge_id: UUID,
        activation_id: UUID,
        nonce_hash: bytes,
        expires_at: datetime,
        now: datetime,
    ) -> None:
        nonce_hash = _hash32(nonce_hash, "renewal nonce hash")
        expires_at, now = _utc(expires_at), _utc(now)
        if expires_at <= now:
            raise InvalidError("challenge expiry must be in the future")
        with self.pool.connection() as conn, conn.transaction():
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (str(activation_id),))
            conn.execute(
                "DELETE FROM activation_challenges WHERE activation_id=%s AND expires_at <= %s",
                (activation_id, now),
            )
            outstanding = conn.execute(
                """SELECT count(*) AS count FROM activation_challenges
                   WHERE activation_id=%s AND consumed_at IS NULL AND expires_at>%s""",
                (activation_id, now),
            ).fetchone()["count"]
            if outstanding >= 5:
                raise InvalidError("too many outstanding renewal challenges")
            row = conn.execute(
                """INSERT INTO activation_challenges (id, activation_id, nonce_hash, expires_at)
                   SELECT %s, a.id, %s, %s FROM activations a
                   JOIN licenses l ON l.id=a.license_id
                   WHERE a.id=%s AND a.state='active' AND l.state='active'
                     AND l.not_before<=%s AND (l.expires_at IS NULL OR l.expires_at>%s)
                   RETURNING id""",
                (challenge_id, nonce_hash, expires_at, activation_id, now, now),
            ).fetchone()
            if row is None:
                raise InvalidError("activation is not renewable")

    def renewal_challenge(self, challenge_id: UUID) -> RenewalChallenge:
        with self.pool.connection() as conn:
            row = conn.execute(
                """SELECT c.id, c.activation_id, c.nonce_hash, a.device_public_key,
                          c.expires_at, c.consumed_at
                   FROM activation_challenges c JOIN activations a ON a.id=c.activation_id
                   WHERE c.id=%s""",
                (challenge_id,),
            ).fetchone()
        if row is None:
            raise InvalidError("challenge is invalid")
        nonce_hash, public_key = bytes(row["nonce_hash"]), bytes(row["device_public_key"])
        if len(nonce_hash) != 32 or len(public_key) != 32:
            raise InvalidError("challenge data is invalid")
        return RenewalChallenge(
            row["id"],
            row["activation_id"],
            nonce_hash,
            public_key,
            row["expires_at"],
            row["consumed_at"],
        )

    def consume_renewal_challenge(
        self,
        challenge_id: UUID,
        nonce_hash: bytes,
        now: datetime,
        lease_ttl: timedelta,
        audit: AuditEvent,
    ) -> tuple[License, Activation]:
        nonce_hash = _hash32(nonce_hash, "renewal nonce hash")
        if lease_ttl <= timedelta(0):
            raise InvalidError("lease TTL must be positive")
        with self.pool.connection() as conn, conn.transaction():
            # Lookups below intentionally do not lock until both identifiers
            # are known. All mutators then lock license -> activation -> challenge.
            ids = conn.execute(
                """SELECT c.activation_id, a.license_id FROM activation_challenges c
                   JOIN activations a ON a.id=c.activation_id
                   WHERE c.id=%s AND c.nonce_hash=%s""",
                (challenge_id, nonce_hash),
            ).fetchone()
            if ids is None:
                raise InvalidError("challenge is invalid")
            license = self._lock_license(conn, ids["license_id"])
            activation_row = conn.execute(
                "SELECT state FROM activations WHERE id=%s AND license_id=%s FOR UPDATE",
                (ids["activation_id"], ids["license_id"]),
            ).fetchone()
            if activation_row is None:
                raise InvalidError("challenge is invalid")
            challenge = conn.execute(
                """SELECT expires_at, consumed_at FROM activation_challenges
                   WHERE id=%s AND activation_id=%s AND nonce_hash=%s FOR UPDATE""",
                (challenge_id, ids["activation_id"], nonce_hash),
            ).fetchone()
            if challenge is None:
                raise InvalidError("challenge is invalid")
            # The caller's timestamp is not trusted across time spent waiting
            # for row locks.
            db_now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
            if (
                challenge["consumed_at"] is not None
                or challenge["expires_at"] <= db_now
                or activation_row["state"] != "active"
            ):
                raise InvalidError("challenge is invalid")
            if (
                license.state != "active"
                or db_now < license.not_before
                or (license.expires_at is not None and db_now >= license.expires_at)
            ):
                raise LicenseStateError("license is not currently usable")
            lease_expiry = min(
                db_now + lease_ttl,
                db_now + timedelta(seconds=license.offline_grace_seconds),
                license.expires_at or datetime.max.replace(tzinfo=UTC),
            )
            conn.execute(
                "UPDATE activation_challenges SET consumed_at=%s WHERE id=%s",
                (db_now, challenge_id),
            )
            updated = conn.execute(
                f"""UPDATE activations SET last_seen_at=GREATEST(last_seen_at,%s),
                           lease_expires_at=%s, updated_at=%s
                    WHERE id=%s AND state='active' RETURNING {ACTIVATION_SELECT}""",
                (db_now, lease_expiry, db_now, ids["activation_id"]),
            ).fetchone()
            if updated is None:
                raise LicenseStateError("activation is no longer active")
            self._insert_audit(conn, replace(audit, target_id=str(ids["activation_id"])))
            return license, _activation(updated)

    def user_by_id(self, user_id: UUID) -> User:
        with self.pool.connection() as conn:
            row = conn.execute(f"SELECT {USER_SELECT} FROM users WHERE id=%s", (user_id,)).fetchone()
        if row is None:
            raise NotFoundError("user not found")
        return _user(row)

    def list_users(self, normalized_email: str = "", limit: int = 100) -> list[User]:
        self._validate_limit(limit)
        with self.pool.connection() as conn:
            rows = conn.execute(
                f"""SELECT {USER_SELECT} FROM users
                    WHERE (%s='' OR normalized_email=%s)
                    ORDER BY created_at DESC, id DESC LIMIT %s""",
                (normalized_email, normalized_email, limit),
            ).fetchall()
        return [_user(row) for row in rows]

    def update_user_access(self, params: UpdateUserAccessParams) -> User:
        if params.role is None and params.status is None:
            raise InvalidError("set at least one of role or status")
        if params.role is not None and params.role not in VALID_ROLES:
            raise InvalidError("invalid role")
        if params.status is not None and params.status not in {"active", "disabled"}:
            raise InvalidError("invalid user status")
        with self.pool.connection() as conn, conn.transaction():
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (OWNER_MANAGEMENT_LOCK,))
            if params.actor_user_id == params.user_id:
                actor = conn.execute(
                    f"SELECT {USER_SELECT} FROM users WHERE id=%s FOR UPDATE",
                    (params.actor_user_id,),
                ).fetchone()
                row = actor
            else:
                actor = conn.execute(
                    "SELECT role, status FROM users WHERE id=%s FOR SHARE",
                    (params.actor_user_id,),
                ).fetchone()
                row = conn.execute(
                    f"SELECT {USER_SELECT} FROM users WHERE id=%s FOR UPDATE", (params.user_id,)
                ).fetchone()
            if actor is None or actor["role"] != Role.PLATFORM_OWNER.value or actor["status"] != "active":
                raise UnauthorizedError("actor is not an active platform owner")
            if row is None:
                raise NotFoundError("user not found")
            current = _user(row)
            role = params.role or current.role
            status = params.status or current.status
            if params.actor_user_id == params.user_id and (
                role is not Role.PLATFORM_OWNER or status != "active"
            ):
                raise ConflictError("a platform owner cannot demote or disable their own account")
            if role == current.role and status == current.status:
                return current
            if (
                current.role is Role.PLATFORM_OWNER
                and current.status == "active"
                and not (role is Role.PLATFORM_OWNER and status == "active")
            ):
                owners = conn.execute(
                    "SELECT count(*) AS count FROM users WHERE role='platform_owner' AND status='active'"
                ).fetchone()["count"]
                if owners <= 1:
                    raise ConflictError("cannot remove or disable the last active platform owner")
            now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
            updated_row = conn.execute(
                f"""UPDATE users SET role=%s, status=%s, updated_at=%s WHERE id=%s
                    RETURNING {USER_SELECT}""",
                (role.value, status, now, params.user_id),
            ).fetchone()
            updated = _user(updated_row)
            conn.execute(
                "UPDATE sessions SET revoked_at=COALESCE(revoked_at,%s) WHERE user_id=%s",
                (now, params.user_id),
            )
            details = dict(params.audit.details)
            details.update(
                {
                    "previousRole": current.role.value,
                    "role": updated.role.value,
                    "previousStatus": current.status,
                    "status": updated.status,
                }
            )
            self._insert_audit(
                conn,
                replace(
                    params.audit,
                    target_id=str(params.user_id),
                    details=details,
                ),
            )
            return updated

    def list_licenses(self, filters: LicenseListFilter | None = None) -> list[License]:
        filters = filters or LicenseListFilter()
        self._validate_limit(filters.limit)
        with self.pool.connection() as conn:
            rows = conn.execute(
                LICENSE_SELECT
                + """
                WHERE (%s::uuid IS NULL OR l.serial=%s)
                  AND (%s='' OR u.normalized_email=%s)
                  AND (%s='' OR l.claim_code_suffix=%s)
                  AND (%s='' OR p.code=%s)
                  AND (%s='' OR l.state=%s)
                ORDER BY l.created_at DESC, l.id DESC LIMIT %s
                """,
                (
                    filters.serial,
                    filters.serial,
                    filters.owner_normalized_email,
                    filters.owner_normalized_email,
                    filters.claim_code_suffix,
                    filters.claim_code_suffix,
                    filters.product_code,
                    filters.product_code,
                    filters.state,
                    filters.state,
                    filters.limit,
                ),
            ).fetchall()
        return [_license(row) for row in rows]

    def license_by_id(self, license_id: UUID) -> License:
        with self.pool.connection() as conn:
            return self._license_by_id_conn(conn, license_id)

    def list_activations_for_owner(self, license_id: UUID, owner_id: UUID) -> list[Activation]:
        with self.pool.connection() as conn:
            exists = conn.execute(
                "SELECT EXISTS(SELECT 1 FROM licenses WHERE id=%s AND owner_user_id=%s) AS exists",
                (license_id, owner_id),
            ).fetchone()["exists"]
            if not exists:
                raise NotFoundError("license not found")
            return self._list_activations_conn(conn, license_id)

    def list_activations(self, license_id: UUID) -> list[Activation]:
        with self.pool.connection() as conn:
            exists = conn.execute(
                "SELECT EXISTS(SELECT 1 FROM licenses WHERE id=%s) AS exists", (license_id,)
            ).fetchone()["exists"]
            if not exists:
                raise NotFoundError("license not found")
            return self._list_activations_conn(conn, license_id)

    def list_admin_activations(
        self, filters: AdminActivationListFilter | None = None
    ) -> list[AdminActivation]:
        """List installation keys with their administrative license context."""

        filters = filters or AdminActivationListFilter()
        self._validate_limit(filters.limit)
        if filters.state and filters.state not in {"active", "deactivated"}:
            raise InvalidError("invalid activation state")
        if len(filters.owner_normalized_email) > 254:
            raise InvalidError("owner email filter is too long")
        if len(filters.product_code) > 64:
            raise InvalidError("product code filter is too long")
        if len(filters.label) > 120:
            raise InvalidError("activation label filter is too long")
        thumbprint = filters.device_key_thumbprint
        if thumbprint is not None:
            thumbprint = _hash32(thumbprint, "device key thumbprint")
        with self.pool.connection() as conn:
            rows = conn.execute(
                """SELECT a.id, a.license_id, l.serial AS license_serial,
                          p.code AS product_code, l.owner_user_id,
                          COALESCE(u.email, '') AS owner_email,
                          a.device_key_thumbprint, a.label, a.state,
                          a.activated_at, a.last_seen_at, a.lease_expires_at,
                          a.deactivated_at
                   FROM activations a
                   JOIN licenses l ON l.id=a.license_id
                   JOIN products p ON p.id=l.product_id
                   LEFT JOIN users u ON u.id=l.owner_user_id
                   WHERE (%s::uuid IS NULL OR a.license_id=%s)
                     AND (%s::uuid IS NULL OR l.serial=%s)
                     AND (%s='' OR u.normalized_email=%s)
                     AND (%s='' OR p.code=%s)
                     AND (%s='' OR a.state=%s)
                     AND (%s='' OR position(lower(%s) in lower(a.label))>0)
                     AND (%s::bytea IS NULL OR a.device_key_thumbprint=%s)
                   ORDER BY a.activated_at DESC, a.id DESC LIMIT %s""",
                (
                    filters.license_id,
                    filters.license_id,
                    filters.serial,
                    filters.serial,
                    filters.owner_normalized_email,
                    filters.owner_normalized_email,
                    filters.product_code,
                    filters.product_code,
                    filters.state,
                    filters.state,
                    filters.label,
                    filters.label,
                    thumbprint,
                    thumbprint,
                    filters.limit,
                ),
            ).fetchall()
        return [_admin_activation(row) for row in rows]

    def dashboard_summary(self) -> DashboardSummary:
        """Return bounded aggregate counts used by the management dashboard."""

        with self.pool.connection() as conn:
            row = conn.execute(
                """SELECT
                    (SELECT count(*) FROM licenses) AS total_licenses,
                    (SELECT count(*) FROM licenses WHERE state='active') AS active_licenses,
                    (SELECT count(*) FROM licenses WHERE state='suspended') AS suspended_licenses,
                    (SELECT count(*) FROM licenses WHERE state='revoked') AS revoked_licenses,
                    (SELECT count(*) FROM licenses WHERE owner_user_id IS NOT NULL) AS claimed_licenses,
                    (SELECT count(*) FROM licenses WHERE owner_user_id IS NULL) AS unclaimed_licenses,
                    (SELECT count(*) FROM activations) AS total_activations,
                    (SELECT count(*) FROM activations WHERE state='active') AS active_activations,
                    (SELECT count(*) FROM activations WHERE state='deactivated') AS deactivated_activations,
                    (SELECT count(*) FROM activations
                       WHERE state='active' AND lease_expires_at>clock_timestamp()) AS current_leases,
                    (SELECT count(*) FROM licenses
                       WHERE state='active' AND expires_at>clock_timestamp()
                         AND expires_at<=clock_timestamp()+interval '30 days')
                        AS expiring_licenses_30_days,
                    (SELECT count(*) FROM users) AS total_users,
                    (SELECT count(*) FROM users WHERE status='active') AS active_users,
                    (SELECT count(*) FROM products) AS total_products,
                    (SELECT count(*) FROM products WHERE status='active') AS active_products"""
            ).fetchone()
        if row is None:
            raise RuntimeError("dashboard aggregate query returned no row")
        return DashboardSummary(**{name: int(row[name]) for name in DashboardSummary.__dataclass_fields__})

    def deactivate_activation(self, activation_id: UUID, audit: AuditEvent) -> None:
        with self.pool.connection() as conn, conn.transaction():
            now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
            row = conn.execute(
                """UPDATE activations SET state='deactivated', deactivated_at=%s, updated_at=%s
                   WHERE id=%s AND state='active' RETURNING id""",
                (now, now, activation_id),
            ).fetchone()
            if row is None:
                exists = conn.execute(
                    "SELECT EXISTS(SELECT 1 FROM activations WHERE id=%s) AS exists", (activation_id,)
                ).fetchone()["exists"]
                if not exists:
                    raise NotFoundError("activation not found")
                return
            self._insert_audit(conn, replace(audit, target_id=str(activation_id)))

    def list_audit_events(self, filters: AuditListFilter | None = None) -> list[AuditRecord]:
        filters = filters or AuditListFilter()
        self._validate_limit(filters.limit)
        if filters.before_id < 0:
            raise InvalidError("before_id cannot be negative")
        with self.pool.connection() as conn:
            rows = conn.execute(
                """SELECT id, occurred_at, actor_user_id, actor_kind, action, target_type,
                          target_id, request_id, outcome, details FROM audit_events
                   WHERE (%s=0 OR id<%s) AND (%s='' OR action=%s)
                     AND (%s='' OR target_type=%s) AND (%s='' OR target_id=%s)
                     AND (%s::uuid IS NULL OR actor_user_id=%s)
                   ORDER BY id DESC LIMIT %s""",
                (
                    filters.before_id,
                    filters.before_id,
                    filters.action,
                    filters.action,
                    filters.target_type,
                    filters.target_type,
                    filters.target_id,
                    filters.target_id,
                    filters.actor_user_id,
                    filters.actor_user_id,
                    filters.limit,
                ),
            ).fetchall()
        return [AuditRecord(**{name: row[name] for name in AuditRecord.__dataclass_fields__}) for row in rows]

    def cleanup_expired_security_state(self, now: datetime) -> None:
        boundary = _utc(now) - timedelta(hours=24)
        tables = (
            ("activation_challenges", "expires_at"),
            ("email_verification_tokens", "expires_at"),
            ("password_reset_tokens", "expires_at"),
            ("refresh_tokens", "expires_at"),
            # Delete refresh rows first so session cascade deletion cannot
            # invert the refresh -> session locking order used by rotation.
            ("sessions", "refresh_expires_at"),
        )
        with self.pool.connection() as conn:
            for table, column in tables:
                while True:
                    with conn.transaction():
                        # Identifiers come exclusively from the constant tuple.
                        cursor = conn.execute(
                            f"""DELETE FROM {table} WHERE ctid IN
                                (SELECT ctid FROM {table} WHERE {column}<%s LIMIT %s)""",
                            (boundary, CLEANUP_BATCH_SIZE),
                        )
                    if cursor.rowcount < CLEANUP_BATCH_SIZE:
                        break

    @staticmethod
    def _validate_limit(limit: int) -> None:
        if not 1 <= limit <= 200:
            raise InvalidError("limit must be between 1 and 200")

    @staticmethod
    def _insert_audit(conn: Connection, event: AuditEvent) -> None:
        request_id = event.request_id.strip() or "unknown"
        conn.execute(
            """INSERT INTO audit_events
               (actor_user_id, actor_kind, action, target_type, target_id, request_id, outcome, details)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (
                event.actor_user_id,
                event.actor_kind or "user",
                event.action,
                event.target_type,
                event.target_id,
                request_id,
                event.outcome or "success",
                Jsonb(event.details),
            ),
        )

    @staticmethod
    def _list_activations_conn(conn: Connection, license_id: UUID) -> list[Activation]:
        rows = conn.execute(
            f"""SELECT {ACTIVATION_SELECT} FROM activations WHERE license_id=%s
                ORDER BY activated_at DESC, id DESC""",
            (license_id,),
        ).fetchall()
        return [_activation(row) for row in rows]

    @staticmethod
    def _license_by_id_conn(conn: Connection, license_id: UUID) -> License:
        row = conn.execute(LICENSE_SELECT + " WHERE l.id=%s", (license_id,)).fetchone()
        if row is None:
            raise NotFoundError("license not found")
        return _license(row)

    @classmethod
    def _lock_license(cls, conn: Connection, license_id: UUID) -> License:
        row = conn.execute(LICENSE_SELECT + " WHERE l.id=%s FOR UPDATE OF l", (license_id,)).fetchone()
        if row is None:
            raise NotFoundError("license not found")
        return _license(row)

    @classmethod
    def _lock_owned_license(cls, conn: Connection, license_id: UUID, owner_id: UUID) -> License:
        row = conn.execute(
            LICENSE_SELECT + " WHERE l.id=%s AND l.owner_user_id=%s FOR UPDATE OF l",
            (license_id, owner_id),
        ).fetchone()
        if row is None:
            raise NotFoundError("license not found")
        return _license(row)
