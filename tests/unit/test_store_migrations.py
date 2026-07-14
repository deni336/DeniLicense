from __future__ import annotations

from contextlib import nullcontext
from hashlib import sha256

import pytest
from psycopg_pool import PoolTimeout

import denilicense.database as database
from denilicense.database import migration_catalog, verify_migrations


class Rows:
    def __init__(self, values):
        self.values = values

    def fetchall(self):
        return self.values


class VerifyConnection:
    def __init__(self, ledger):
        self.ledger = ledger
        self.statements = []

    def execute(self, sql, _params=None):
        normalized = " ".join(sql.split())
        self.statements.append(normalized)
        if "FROM schema_migrations" in normalized:
            return Rows(self.ledger)
        return Rows([])

    def commit(self):
        pass


class VerifyPool:
    def __init__(self, connection):
        self.value = connection

    def connection(self):
        return nullcontext(self.value)


class UnavailablePool:
    instance = None

    def __init__(self, **_kwargs):
        self.closed = False
        type(self).instance = self

    @staticmethod
    def check_connection(_connection):
        pass

    def wait(self, *, timeout):
        assert timeout == 10
        raise PoolTimeout("test database unavailable")

    def close(self):
        self.closed = True


def test_open_pool_translates_timeout_and_closes_workers(monkeypatch):
    monkeypatch.setattr(database, "ConnectionPool", UnavailablePool)

    with pytest.raises(RuntimeError, match="PostgreSQL did not become reachable"):
        database.open_pool("postgresql://user:password@localhost/database")

    assert UnavailablePool.instance.closed is True


def test_catalog_normalizes_line_endings_before_checksum(tmp_path):
    body = b"SELECT 1;\r\nSELECT 2;\r\n"
    (tmp_path / "001_initial.sql").write_bytes(body)
    migration = migration_catalog(tmp_path)[0]
    expected = b"SELECT 1;\nSELECT 2;\n"

    assert migration.sql == expected
    assert migration.checksum == sha256(expected).digest()


def test_catalog_rejects_duplicate_numeric_versions(tmp_path):
    (tmp_path / "001_one.sql").write_text("SELECT 1", encoding="utf-8")
    (tmp_path / "001_two.sql").write_text("SELECT 2", encoding="utf-8")

    with pytest.raises(RuntimeError, match="duplicate version"):
        migration_catalog(tmp_path)


def test_verify_migrations_performs_no_ddl(tmp_path):
    body = b"CREATE TABLE example(id integer);\n"
    (tmp_path / "001_initial.sql").write_bytes(body)
    connection = VerifyConnection(
        [
            {
                "version": 1,
                "filename": "001_initial.sql",
                "checksum": sha256(body).digest(),
            }
        ]
    )

    verify_migrations(VerifyPool(connection), path=tmp_path)

    assert connection.statements
    assert all(statement.startswith("SELECT ") for statement in connection.statements)


def test_email_first_migration_neutralizes_unverified_credentials_and_enforces_invariants():
    migration = next(item for item in migration_catalog() if item.version == 3)
    sql = migration.sql.decode("utf-8")

    assert migration.filename == "003_email_first_registration.sql"
    assert "UPDATE sessions s" in sql
    assert "u.email_verified_at IS NULL" in sql
    assert "DELETE FROM password_reset_tokens" in sql
    assert "password_hash = '!pending-registration-v1'" in sql
    assert "password_set_at = NULL" in sql
    assert "role = 'customer'" in sql
    assert "users_unverified_role_check" in sql
    assert "users_unverified_credential_check" in sql
