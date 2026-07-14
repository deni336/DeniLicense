"""Service administration and ASGI server command-line entry point."""

from __future__ import annotations

import argparse
import getpass
import logging
import os
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import uvicorn
from psycopg_pool import ConnectionPool

from .auth import PasswordManager, normalize_email
from .config import ConfigurationError, Settings, validate_database_url
from .crypto.keys import (
    ACTIVATION_RECEIPT_SIGNER,
    MAX_KEY_FILE_BYTES,
    SigningKey,
    VerificationKey,
    decrypt_signing_key,
    parse_public_key,
)
from .database import migrate, open_pool, verify_migrations
from .store import ConflictError, Store

_MAX_PASSPHRASE_BYTES = 1024 * 1024


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="denilicense")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("serve", help="run the HTTP API")
    subparsers.add_parser("migrate", help="apply checksummed PostgreSQL migrations")
    bootstrap = subparsers.add_parser("bootstrap-owner", help="create the first platform owner")
    bootstrap.add_argument("--email", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    command = args.command or "serve"
    try:
        if command == "migrate":
            _migrate_only()
        elif command == "bootstrap-owner":
            _bootstrap_owner(args.email)
        elif command == "serve":
            _serve()
        else:  # pragma: no cover - argparse owns the choices
            parser.error(f"unknown command {command!r}")
    except (ConfigurationError, OSError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


def _migrate_only() -> None:
    database_url = os.getenv("DENILICENSE_DATABASE_URL", "").strip()
    environment = os.getenv("DENILICENSE_ENV", "").strip()
    validate_database_url(database_url, require_verified_tls=environment == "production")
    pool = open_pool(database_url, min_size=1, max_size=2)
    try:
        migrate(pool)
    finally:
        pool.close()


def _bootstrap_owner(email_value: str) -> None:
    settings = Settings.from_env()
    display_email, normalized_email = normalize_email(email_value)
    password = _bootstrap_password()
    password_hash = PasswordManager(settings.password_pepper).hash(password)
    pool = open_pool(settings.database_url, min_size=1, max_size=2)
    try:
        _prepare_database(settings, pool)
        try:
            user = Store(pool).bootstrap_owner(
                uuid4(), display_email, normalized_email, password_hash, datetime.now(UTC)
            )
        except ConflictError as exc:
            raise RuntimeError("a platform owner already exists; use authenticated role management") from exc
    finally:
        pool.close()
    print(f"Created platform owner {user.email} ({user.id})")


def _serve() -> None:
    # Importing the application lazily keeps migration and bootstrap commands
    # independent from HTTP initialization.
    from .api import create_app

    settings = Settings.from_env()
    signer = _load_activation_signer(settings)
    verification_keys = _load_activation_verification_keys(settings)
    pool = open_pool(settings.database_url)
    try:
        _prepare_database(settings, pool)
        store = Store(pool)
        app = create_app(
            settings,
            store,
            PasswordManager(settings.password_pepper),
            activation_signer=signer,
            activation_verification_keys=verification_keys,
        )
        stop_maintenance = threading.Event()
        maintenance = threading.Thread(
            target=_run_maintenance,
            args=(store, stop_maintenance),
            name="security-state-maintenance",
            daemon=True,
        )
        maintenance.start()
        logging.getLogger(__name__).info(
            "DeniLicense listening on %s:%d", settings.http_host, settings.http_port
        )
        uvicorn.run(
            app,
            host=settings.http_host,
            port=settings.http_port,
            access_log=False,
            limit_concurrency=1024,
            timeout_keep_alive=60,
            timeout_graceful_shutdown=max(1, int(settings.shutdown_timeout.total_seconds())),
            server_header=False,
        )
        stop_maintenance.set()
        maintenance.join(timeout=2)
    finally:
        pool.close()


def _prepare_database(settings: Settings, pool: ConnectionPool) -> None:
    if settings.auto_migrate:
        migrate(pool)
    else:
        try:
            verify_migrations(pool)
        except RuntimeError as exc:
            raise RuntimeError(
                "database migration verification failed; run `denilicense migrate` with the migration role"
            ) from exc


def _load_activation_signer(settings: Settings) -> SigningKey:
    if settings.activation_key_file is None or not settings.activation_issuer:
        raise ConfigurationError(
            "DENILICENSE_ACTIVATION_KEY_FILE and DENILICENSE_ACTIVATION_ISSUER are required to serve"
        )
    encoded = _read_bounded(settings.activation_key_file, MAX_KEY_FILE_BYTES)
    if settings.activation_key_passphrase_file is not None:
        passphrase = (
            _read_bounded(settings.activation_key_passphrase_file, _MAX_PASSPHRASE_BYTES)
            .removesuffix(b"\n")
            .removesuffix(b"\r")
        )
    elif settings.environment != "production":
        passphrase = os.getenv("DENILICENSE_ACTIVATION_KEY_PASSPHRASE", "").encode()
    else:
        passphrase = b""
    if not passphrase:
        raise ConfigurationError("activation key passphrase is required")
    signer = decrypt_signing_key(encoded, passphrase)
    if signer.purpose != ACTIVATION_RECEIPT_SIGNER:
        raise ConfigurationError("configured activation key has the wrong purpose")
    return signer


def _load_activation_verification_keys(settings: Settings) -> tuple[VerificationKey, ...]:
    keys: list[VerificationKey] = []
    for path in settings.activation_verification_key_files:
        key = parse_public_key(_read_bounded(path, MAX_KEY_FILE_BYTES))
        if key.purpose != ACTIVATION_RECEIPT_SIGNER:
            raise ConfigurationError(f"activation verification key {path} has the wrong purpose")
        keys.append(key)
    return tuple(keys)


def _run_maintenance(store: Store, stop: threading.Event) -> None:
    while True:
        try:
            store.cleanup_expired_security_state(datetime.now(UTC))
        except Exception:
            logging.getLogger(__name__).exception("security-state cleanup failed")
        if stop.wait(3600):
            return


def _bootstrap_password() -> str:
    configured = os.getenv("DENILICENSE_BOOTSTRAP_PASSWORD", "")
    if configured:
        return configured
    if not sys.stdin.isatty():
        raise ConfigurationError("no terminal is available; set DENILICENSE_BOOTSTRAP_PASSWORD securely")
    password = getpass.getpass("New platform owner password: ")
    repeated = getpass.getpass("Confirm password: ")
    if password != repeated:
        raise ConfigurationError("passwords did not match")
    return password


def _read_bounded(path: Path, limit: int) -> bytes:
    encoded = path.read_bytes()
    if not encoded or len(encoded) > limit:
        raise ConfigurationError(f"{path} has an invalid size")
    return encoded
