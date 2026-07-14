from __future__ import annotations

from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from psycopg.errors import UniqueViolation

from denilicense.domain import (
    ConflictError,
    RefreshReuseError,
    Role,
    SeatLimitError,
    UnauthorizedError,
)
from denilicense.store import (
    PENDING_REGISTRATION_PASSWORD_HASH,
    ActivateParams,
    AuditEvent,
    CreateManagedUserParams,
    RegisterPendingUserParams,
    RotateSessionParams,
    Store,
    UpdateUserAccessParams,
)

NOW = datetime(2026, 7, 12, tzinfo=UTC)


class Result:
    def __init__(self, *, one=None, all_=None, rowcount=0):
        self.one = one
        self.all = [] if all_ is None else all_
        self.rowcount = rowcount

    def fetchone(self):
        return self.one

    def fetchall(self):
        return self.all


class Transaction:
    def __init__(self, connection):
        self.connection = connection

    def __enter__(self):
        return self

    def __exit__(self, exc_type, _exc, _traceback):
        if exc_type is None:
            self.connection.commits += 1
        else:
            self.connection.rollbacks += 1


class ScriptedConnection:
    def __init__(self, script):
        self.script = list(script)
        self.sql = []
        self.commits = 0
        self.rollbacks = 0

    def execute(self, sql, params=None):
        normalized = " ".join(str(sql).split())
        self.sql.append((normalized, params))
        assert self.script, f"unexpected SQL: {normalized}"
        fragment, result = self.script.pop(0)
        assert fragment in normalized
        if isinstance(result, BaseException):
            raise result
        return result

    def transaction(self):
        return Transaction(self)


class FakePool:
    def __init__(self, connection):
        self.connection_value = connection

    def connection(self):
        return nullcontext(self.connection_value)


def user_row(
    user_id,
    *,
    email="owner@example.com",
    role="platform_owner",
    status="active",
    verified=True,
    password_set=True,
):
    return {
        "id": user_id,
        "email": email,
        "role": role,
        "status": status,
        "email_verified_at": NOW if verified else None,
        "created_at": NOW,
        "password_set_at": NOW if password_set else None,
        "archived_at": None,
        "deleted_at": None,
        "revision": 1,
    }


def license_row(license_id, owner_id):
    return {
        "id": license_id,
        "serial": uuid4(),
        "product_id": uuid4(),
        "product_code": "DESKTOP",
        "owner_user_id": owner_id,
        "owner_email": "owner@example.com",
        "source": "online",
        "state": "active",
        "subject": "",
        "issued_at": NOW - timedelta(days=1),
        "not_before": NOW - timedelta(days=1),
        "expires_at": None,
        "max_activations": 1,
        "offline_grace_seconds": 86_400,
        "entitlements": {},
        "metadata": {},
        "revision": 1,
        "claim_code_suffix": "ABCD",
        "claimed_at": NOW,
        "created_at": NOW,
        "updated_at": NOW,
    }


def test_duplicate_pending_registration_neutralizes_password_and_rotates_token():
    user_id, token_id = uuid4(), uuid4()
    expires_at = NOW + timedelta(minutes=30)
    connection = ScriptedConnection(
        [
            ("ON CONFLICT (normalized_email) DO NOTHING", Result(one=None)),
            (
                "FROM users WHERE normalized_email=%s FOR UPDATE",
                Result(
                    one={
                        **user_row(
                            user_id,
                            email="victim@example.com",
                            role="customer",
                            verified=False,
                        ),
                        "password_set_at": NOW,
                    }
                ),
            ),
            ("UPDATE users SET password_hash=%s", Result()),
            ("UPDATE sessions SET revoked_at", Result(rowcount=1)),
            ("DELETE FROM password_reset_tokens", Result()),
            ("DELETE FROM email_verification_tokens", Result(rowcount=1)),
            ("INSERT INTO email_verification_tokens", Result()),
        ]
    )

    recipient, pending = Store(FakePool(connection)).register_pending_user(
        RegisterPendingUserParams(
            id=uuid4(),
            email="victim@example.com",
            normalized_email="victim@example.com",
            verification_token_id=token_id,
            verification_token_hash=b"v" * 32,
            verification_token_expiry=expires_at,
        )
    )

    assert (recipient, pending) == ("victim@example.com", True)
    assert connection.sql[2][1] == (PENDING_REGISTRATION_PASSWORD_HASH, user_id)
    assert connection.sql[5][1] == (user_id,)
    assert connection.sql[6][1] == (token_id, user_id, b"v" * 32, expires_at)
    assert connection.commits == 1
    assert not connection.script


def test_verification_atomically_installs_first_password_and_revokes_legacy_sessions():
    user_id = uuid4()
    completed = {
        **user_row(user_id, email="victim@example.com", role="customer"),
        "revision": 2,
    }
    connection = ScriptedConnection(
        [
            ("FROM email_verification_tokens WHERE token_hash", Result(one={"user_id": user_id})),
            ("email_verified_at IS NULL", Result(one={"id": user_id})),
            ("UPDATE email_verification_tokens SET consumed_at", Result(one={"id": uuid4()})),
            ("UPDATE users SET password_hash=%s", Result(one=completed)),
            ("UPDATE email_verification_tokens SET consumed_at", Result()),
            ("DELETE FROM password_reset_tokens", Result()),
            ("UPDATE sessions SET revoked_at", Result(rowcount=1)),
            ("INSERT INTO audit_events", Result()),
        ]
    )

    verified = Store(FakePool(connection)).verify_email(
        b"t" * 32,
        "hashed:victim-selected-password",
        NOW,
    )

    assert verified.email_verified_at == NOW
    assert verified.password_setup_required is False
    assert connection.sql[3][1] == (
        "hashed:victim-selected-password",
        NOW,
        NOW,
        NOW,
        user_id,
    )
    assert connection.sql[6][1] == (NOW, user_id)
    assert connection.commits == 1
    assert not connection.script


def test_unverified_customer_cannot_be_promoted_to_a_privileged_role():
    actor_id, pending_id = uuid4(), uuid4()
    connection = ScriptedConnection(
        [
            ("pg_advisory_xact_lock", Result()),
            (
                "SELECT role, status FROM users",
                Result(one={"role": "platform_owner", "status": "active"}),
            ),
            (
                "FROM users WHERE id=%s FOR UPDATE",
                Result(
                    one=user_row(
                        pending_id,
                        email="victim@example.com",
                        role="customer",
                        verified=False,
                        password_set=False,
                    )
                ),
            ),
        ]
    )

    with pytest.raises(ConflictError, match="email verification"):
        Store(FakePool(connection)).update_user_access(
            UpdateUserAccessParams(
                user_id=pending_id,
                actor_user_id=actor_id,
                role=Role.AUDITOR,
                status="active",
            )
        )

    assert connection.rollbacks == 1
    assert not connection.script


def test_refresh_reuse_revokes_family_and_commits_before_error():
    family_id = uuid4()
    connection = ScriptedConnection(
        [
            ("SELECT s.family_id", Result(one={"family_id": family_id})),
            ("pg_advisory_xact_lock", Result()),
            (
                "FOR UPDATE OF rt, s",
                Result(
                    one={
                        "id": uuid4(),
                        "session_id": uuid4(),
                        "family_id": family_id,
                        "used_at": NOW,
                        "revoked_at": None,
                        "token_expiry": NOW + timedelta(hours=1),
                        "session_refresh_expiry": NOW + timedelta(days=1),
                    }
                ),
            ),
            ("UPDATE sessions SET revoked_at", Result(rowcount=2)),
        ]
    )
    store = Store(FakePool(connection))
    params = RotateSessionParams(
        old_refresh_hash=b"o" * 32,
        new_refresh_id=uuid4(),
        new_refresh_hash=b"r" * 32,
        new_access_hash=b"a" * 32,
        access_expires_at=NOW + timedelta(minutes=15),
        refresh_expires_at=NOW + timedelta(days=1),
        now=NOW,
    )

    with pytest.raises(RefreshReuseError):
        store.rotate_session(params)

    assert connection.commits == 1
    assert connection.rollbacks == 0
    assert connection.sql[3][1] == (NOW, family_id)


@pytest.mark.parametrize(
    ("role", "status"),
    [
        (Role.CUSTOMER, "active"),
        (Role.PLATFORM_OWNER, "disabled"),
    ],
)
def test_owner_cannot_demote_or_disable_their_own_account(role, status):
    owner_id = uuid4()
    connection = ScriptedConnection(
        [
            ("pg_advisory_xact_lock", Result()),
            ("FROM users WHERE id=%s FOR UPDATE", Result(one=user_row(owner_id))),
        ]
    )
    store = Store(FakePool(connection))

    with pytest.raises(ConflictError, match="own account"):
        store.update_user_access(
            UpdateUserAccessParams(
                user_id=owner_id,
                actor_user_id=owner_id,
                role=role,
                status=status,
                audit=AuditEvent("user.role_update", "user"),
            )
        )

    assert connection.commits == 0
    assert connection.rollbacks == 1
    assert not connection.script


def test_last_active_owner_guard_remains_transactional_defense_in_depth():
    actor_id, owner_id = uuid4(), uuid4()
    connection = ScriptedConnection(
        [
            ("pg_advisory_xact_lock", Result()),
            (
                "SELECT role, status FROM users",
                Result(one={"role": "platform_owner", "status": "active"}),
            ),
            ("FROM users WHERE id=%s FOR UPDATE", Result(one=user_row(owner_id))),
            ("count(*) AS count", Result(one={"count": 1})),
        ]
    )
    store = Store(FakePool(connection))

    with pytest.raises(ConflictError, match="last active platform owner"):
        store.update_user_access(
            UpdateUserAccessParams(
                user_id=owner_id,
                actor_user_id=actor_id,
                role=Role.CUSTOMER,
                status="active",
                audit=AuditEvent("user.access_change", "user"),
            )
        )

    assert connection.commits == 0
    assert connection.rollbacks == 1
    assert not connection.script


def test_access_change_rechecks_actor_and_rejects_stale_owner_session():
    actor_id, user_id = uuid4(), uuid4()
    connection = ScriptedConnection(
        [
            ("pg_advisory_xact_lock", Result()),
            (
                "SELECT role, status FROM users",
                Result(one={"role": "license_admin", "status": "active"}),
            ),
            (
                "FROM users WHERE id=%s FOR UPDATE",
                Result(one=user_row(user_id, role="customer")),
            ),
        ]
    )
    store = Store(FakePool(connection))

    with pytest.raises(UnauthorizedError, match="active platform owner"):
        store.update_user_access(
            UpdateUserAccessParams(
                user_id=user_id,
                actor_user_id=actor_id,
                role=Role.AUDITOR,
                status="active",
            )
        )

    assert connection.rollbacks == 1
    assert not connection.script


def test_atomic_access_change_revokes_all_target_sessions_and_audits_both_fields():
    actor_id, user_id = uuid4(), uuid4()
    connection = ScriptedConnection(
        [
            ("pg_advisory_xact_lock", Result()),
            (
                "SELECT role, status FROM users",
                Result(one={"role": "platform_owner", "status": "active"}),
            ),
            (
                "FROM users WHERE id=%s FOR UPDATE",
                Result(one=user_row(user_id, email="user@example.com", role="customer")),
            ),
            ("clock_timestamp()", Result(one={"now": NOW})),
            (
                "UPDATE users SET role=%s, status=%s",
                Result(
                    one=user_row(
                        user_id,
                        email="user@example.com",
                        role="auditor",
                        status="disabled",
                    )
                ),
            ),
            ("UPDATE sessions SET revoked_at", Result(rowcount=3)),
            ("INSERT INTO audit_events", Result()),
        ]
    )
    store = Store(FakePool(connection))

    updated = store.update_user_access(
        UpdateUserAccessParams(
            user_id=user_id,
            actor_user_id=actor_id,
            role=Role.AUDITOR,
            status="disabled",
            audit=AuditEvent("user.access_change", "user", actor_user_id=actor_id),
        )
    )

    assert updated.role is Role.AUDITOR
    assert updated.status == "disabled"
    assert connection.commits == 1
    assert connection.rollbacks == 0
    assert connection.sql[4][1] == (Role.AUDITOR.value, "disabled", NOW, user_id)
    assert connection.sql[5][1] == (NOW, user_id)
    audit_parameters = connection.sql[6][1]
    assert audit_parameters[0] == actor_id
    assert audit_parameters[2] == "user.access_change"
    assert audit_parameters[4] == str(user_id)
    assert audit_parameters[7].obj == {
        "previousRole": "customer",
        "role": "auditor",
        "previousStatus": "active",
        "status": "disabled",
    }
    assert not connection.script


def test_noop_access_update_does_not_revoke_sessions_or_create_audit_event():
    actor_id, user_id = uuid4(), uuid4()
    connection = ScriptedConnection(
        [
            ("pg_advisory_xact_lock", Result()),
            (
                "SELECT role, status FROM users",
                Result(one={"role": "platform_owner", "status": "active"}),
            ),
            (
                "FROM users WHERE id=%s FOR UPDATE",
                Result(one=user_row(user_id, role="auditor")),
            ),
        ]
    )

    unchanged = Store(FakePool(connection)).update_user_access(
        UpdateUserAccessParams(
            user_id=user_id,
            actor_user_id=actor_id,
            role=Role.AUDITOR,
            status="active",
        )
    )

    assert unchanged.role is Role.AUDITOR
    assert connection.commits == 1
    assert len(connection.sql) == 3
    assert not connection.script


def test_managed_user_creation_is_verified_transactional_and_audited():
    actor_id, user_id, token_id = uuid4(), uuid4(), uuid4()
    expires_at = NOW + timedelta(minutes=30)
    created_row = user_row(
        user_id,
        email="new-admin@example.com",
        role="license_admin",
    )
    connection = ScriptedConnection(
        [
            ("pg_advisory_xact_lock", Result()),
            (
                "SELECT role, status FROM users",
                Result(one={"role": "platform_owner", "status": "active"}),
            ),
            ("clock_timestamp()", Result(one={"now": NOW})),
            ("INSERT INTO users", Result(one=created_row)),
            ("INSERT INTO password_reset_tokens", Result()),
            ("INSERT INTO audit_events", Result()),
        ]
    )
    params = CreateManagedUserParams(
        id=user_id,
        email="new-admin@example.com",
        normalized_email="new-admin@example.com",
        password_hash="unusable-hash",  # noqa: S106 - test fixture
        role=Role.LICENSE_ADMIN,
        password_reset_token_id=token_id,
        password_reset_token_hash=b"t" * 32,
        password_reset_token_expiry=expires_at,
        actor_user_id=actor_id,
        audit=AuditEvent("user.create", "user", actor_user_id=actor_id),
    )

    created = Store(FakePool(connection)).create_managed_user(params)

    assert created.role is Role.LICENSE_ADMIN
    assert created.email_verified_at == NOW
    assert connection.sql[3][1] == (
        user_id,
        "new-admin@example.com",
        "new-admin@example.com",
        "unusable-hash",
        "license_admin",
        NOW,
    )
    assert connection.sql[4][1] == (token_id, user_id, b"t" * 32, expires_at)
    assert connection.sql[5][1][7].obj == {
        "role": "license_admin",
        "status": "active",
        "passwordSetupRequired": True,
    }
    assert connection.commits == 1
    assert not connection.script


def test_managed_user_duplicate_email_is_a_conflict_and_rolls_back():
    actor_id, user_id = uuid4(), uuid4()
    connection = ScriptedConnection(
        [
            ("pg_advisory_xact_lock", Result()),
            (
                "SELECT role, status FROM users",
                Result(one={"role": "platform_owner", "status": "active"}),
            ),
            ("clock_timestamp()", Result(one={"now": NOW})),
            ("INSERT INTO users", UniqueViolation("duplicate normalized_email")),
        ]
    )

    with pytest.raises(ConflictError, match="email or token already exists"):
        Store(FakePool(connection)).create_managed_user(
            CreateManagedUserParams(
                id=user_id,
                email="Owner@Example.com",
                normalized_email="owner@example.com",
                password_hash="unusable-hash",  # noqa: S106 - test fixture
                role=Role.AUDITOR,
                password_reset_token_id=uuid4(),
                password_reset_token_hash=b"r" * 32,
                password_reset_token_expiry=NOW + timedelta(minutes=30),
                actor_user_id=actor_id,
                audit=AuditEvent("user.create", "user", actor_user_id=actor_id),
            )
        )

    assert connection.commits == 0
    assert connection.rollbacks == 1
    assert not connection.script


def test_managed_user_creation_rechecks_actor_under_owner_lock():
    actor_id = uuid4()
    connection = ScriptedConnection(
        [
            ("pg_advisory_xact_lock", Result()),
            (
                "SELECT role, status FROM users",
                Result(one={"role": "auditor", "status": "active"}),
            ),
        ]
    )

    with pytest.raises(UnauthorizedError, match="active platform owner"):
        Store(FakePool(connection)).create_managed_user(
            CreateManagedUserParams(
                id=uuid4(),
                email="new@example.com",
                normalized_email="new@example.com",
                password_hash="unusable-hash",  # noqa: S106 - test fixture
                role=Role.LICENSE_ADMIN,
                password_reset_token_id=uuid4(),
                password_reset_token_hash=b"r" * 32,
                password_reset_token_expiry=NOW + timedelta(minutes=30),
                actor_user_id=actor_id,
                audit=AuditEvent("user.create", "user", actor_user_id=actor_id),
            )
        )

    assert connection.commits == 0
    assert connection.rollbacks == 1
    assert not connection.script


def test_activation_locks_license_before_counting_seats():
    license_id, owner_id = uuid4(), uuid4()
    connection = ScriptedConnection(
        [
            ("FOR UPDATE OF l", Result(one=license_row(license_id, owner_id))),
            ("clock_timestamp()", Result(one={"now": NOW})),
            ("device_key_thumbprint", Result(one=None)),
            ("count(*) AS count", Result(one={"count": 1})),
        ]
    )
    store = Store(FakePool(connection))

    with pytest.raises(SeatLimitError):
        store.activate(
            ActivateParams(
                id=uuid4(),
                license_id=license_id,
                owner_user_id=owner_id,
                device_public_key=b"d" * 32,
                label="laptop",
                now=NOW,
                lease_expires_at=NOW + timedelta(hours=1),
                audit=AuditEvent("activation.create", "activation"),
            )
        )

    assert "FOR UPDATE OF l" in connection.sql[0][0]
    assert connection.rollbacks == 1
