"""Development entry point for running DeniLicense from the repository.

Examples:
    python main.py
    python main.py serve
    python main.py migrate
    python main.py bootstrap-owner --email owner@example.com

Configuration is read from the DENILICENSE_* environment variables. Running
without a command starts the complete HTTP service.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

_DEVELOPMENT_DEFAULTS = {
    "DENILICENSE_ENV": "development",
    "DENILICENSE_HTTP_ADDRESS": "127.0.0.1:8081",
    "DENILICENSE_DATABASE_URL": (
        "postgres://denilicense:denilicense-development-only@127.0.0.1:5432/denilicense?sslmode=disable"
    ),
    "DENILICENSE_TOKEN_PEPPER": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "DENILICENSE_DEVICE_PEPPER": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
    "DENILICENSE_ISSUANCE_PEPPER": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI",
    "DENILICENSE_REGISTRATION_MODE": "open",
    "DENILICENSE_EXPOSE_DEV_TOKENS": "true",
    "DENILICENSE_ALLOWED_ORIGINS": ("http://localhost:3000,http://127.0.0.1:8081,http://localhost:8081"),
    "DENILICENSE_AUTO_MIGRATE": "true",
    "DENILICENSE_ACTIVATION_ISSUER": "http://127.0.0.1:8081",
    "DENILICENSE_ACTIVATION_KEY_PASSPHRASE": "denilicense-local-development-passphrase",
}


def _configure_development(source: Path) -> None:
    """Supply safe-to-discard defaults only when no environment was selected."""
    if os.getenv("DENILICENSE_ENV", "").strip():
        return

    root = source.parent
    key_directory = root / "data" / "development"
    private_key = key_directory / "activation.key.json"
    public_key = key_directory / "activation.public.json"
    defaults = {
        **_DEVELOPMENT_DEFAULTS,
        "DENILICENSE_ACTIVATION_KEY_FILE": str(private_key),
    }
    for name, value in defaults.items():
        os.environ.setdefault(name, value)

    _ensure_development_key(private_key, public_key)
    print(
        "DeniLicense development defaults enabled: API http://127.0.0.1:8081, PostgreSQL 127.0.0.1:5432",
        file=sys.stderr,
    )


def _ensure_development_key(private_path: Path, public_path: Path) -> None:
    from denilicense.crypto import (
        ACTIVATION_RECEIPT_SIGNER,
        SigningKey,
        decrypt_signing_key,
        encrypt_signing_key,
        marshal_public_key,
    )

    passphrase = os.environ["DENILICENSE_ACTIVATION_KEY_PASSPHRASE"]
    private_exists = private_path.is_file()
    public_exists = public_path.is_file()
    if public_exists and not private_exists:
        raise RuntimeError(f"development activation public key exists without its private key: {public_path}")

    private_path.parent.mkdir(parents=True, exist_ok=True)
    if private_exists:
        key = decrypt_signing_key(private_path.read_bytes(), passphrase)
    else:
        key = SigningKey.generate(ACTIVATION_RECEIPT_SIGNER)
        private_path.write_bytes(encrypt_signing_key(key, passphrase))

    if not public_exists:
        public_path.write_bytes(marshal_public_key(key.verification_key))


def main() -> int:
    """Load the local source tree and dispatch to the service CLI."""
    source = Path(__file__).resolve().parent / "src"
    if not source.is_dir():
        print(f"error: DeniLicense source directory not found: {source}", file=sys.stderr)
        return 1
    sys.path.insert(0, str(source))

    try:
        _configure_development(source)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"error: could not initialize development configuration: {exc}", file=sys.stderr)
        return 1

    from denilicense.cli import main as service_main

    return service_main()


if __name__ == "__main__":
    raise SystemExit(main())
