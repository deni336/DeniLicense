"""PostgreSQL pool creation and immutable, checksummed SQL migrations."""

from __future__ import annotations

import re
from dataclasses import dataclass
from hashlib import sha256
from importlib.resources import files
from pathlib import Path

from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

MIGRATION_LOCK = 1_947_259_831
_MIGRATION_NAME = re.compile(r"^(?P<version>[0-9]+)_.+\.sql$")


@dataclass(frozen=True, slots=True)
class Migration:
    version: int
    filename: str
    sql: bytes
    checksum: bytes


def migration_catalog(path: Path | None = None) -> tuple[Migration, ...]:
    """Load the catalog in numeric order and reject duplicate/invalid versions."""
    root = path or Path(str(files("denilicense").joinpath("migrations")))
    found: list[Migration] = []
    versions: dict[int, str] = {}
    for source in root.iterdir():
        if not source.is_file() or source.suffix != ".sql":
            continue
        match = _MIGRATION_NAME.fullmatch(source.name)
        if match is None:
            raise RuntimeError(f"migration {source.name!r} has no valid numeric prefix")
        version = int(match.group("version"))
        if version <= 0:
            raise RuntimeError(f"migration {source.name!r} has an invalid version")
        if version in versions:
            raise RuntimeError(
                f"migrations {versions[version]!r} and {source.name!r} use duplicate version {version}"
            )
        versions[version] = source.name
        body = source.read_bytes().replace(b"\r\n", b"\n")
        found.append(Migration(version, source.name, body, sha256(body).digest()))
    if not found:
        raise RuntimeError("the migration catalog is empty")
    found.sort(key=lambda item: item.version)
    return tuple(found)


def open_pool(database_url: str, *, min_size: int = 2, max_size: int = 20) -> ConnectionPool:
    pool = ConnectionPool(
        conninfo=database_url,
        min_size=min_size,
        max_size=max_size,
        timeout=10,
        max_lifetime=3600,
        max_idle=900,
        check=ConnectionPool.check_connection,
        kwargs={"row_factory": dict_row},
        open=True,
    )
    pool.wait(timeout=10)
    return pool


def migrate(pool: ConnectionPool, *, path: Path | None = None) -> None:
    catalog = migration_catalog(path)
    with pool.connection() as conn:
        conn.execute("SELECT pg_advisory_lock(%s)", (MIGRATION_LOCK,))
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version bigint PRIMARY KEY,
                    filename text NOT NULL,
                    checksum bytea NOT NULL CHECK (octet_length(checksum) = 32),
                    applied_at timestamptz NOT NULL DEFAULT now()
                )
                """
            )
            conn.commit()
            for item in catalog:
                row = conn.execute(
                    "SELECT filename, checksum FROM schema_migrations WHERE version = %s",
                    (item.version,),
                ).fetchone()
                if row is not None:
                    if row["filename"] != item.filename or bytes(row["checksum"]) != item.checksum:
                        raise RuntimeError(
                            f"applied migration {item.version} does not match embedded filename/checksum"
                        )
                    continue
                with conn.transaction():
                    conn.execute(item.sql.decode("utf-8"))
                    conn.execute(
                        "INSERT INTO schema_migrations(version, filename, checksum) VALUES (%s, %s, %s)",
                        (item.version, item.filename, item.checksum),
                    )
        finally:
            # Session locks must be explicitly released before returning this
            # pooled connection, even when migration validation fails.
            conn.execute("SELECT pg_advisory_unlock(%s)", (MIGRATION_LOCK,))
            conn.commit()


def verify_migrations(pool: ConnectionPool, *, path: Path | None = None) -> None:
    """Verify the exact catalog without issuing CREATE/ALTER/DROP statements."""
    catalog = migration_catalog(path)
    with pool.connection() as conn:
        conn.execute("SELECT pg_advisory_lock(%s)", (MIGRATION_LOCK,))
        try:
            rows = conn.execute(
                "SELECT version, filename, checksum FROM schema_migrations ORDER BY version"
            ).fetchall()
            if len(rows) != len(catalog):
                if len(rows) > len(catalog):
                    unknown_version = rows[len(catalog)]["version"]
                    raise RuntimeError(f"database has unknown migration version {unknown_version}")
                missing = catalog[len(rows)].version
                raise RuntimeError(f"database is missing migration {missing}")
            for row, expected in zip(rows, catalog, strict=True):
                if (
                    row["version"] != expected.version
                    or row["filename"] != expected.filename
                    or bytes(row["checksum"]) != expected.checksum
                ):
                    raise RuntimeError(
                        f"database migration {row['version']} does not match the embedded catalog"
                    )
        finally:
            conn.execute("SELECT pg_advisory_unlock(%s)", (MIGRATION_LOCK,))
            conn.commit()


def ping(pool: ConnectionPool) -> None:
    with pool.connection() as conn:
        conn.execute("SELECT 1").fetchone()
