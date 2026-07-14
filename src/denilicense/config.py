from __future__ import annotations

import base64
import ipaddress
import os
import re
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlparse


class ConfigurationError(ValueError):
    pass


_DURATION_PART = re.compile(r"(?P<amount>\d+)(?P<unit>ms|s|m|h)")


def parse_duration(value: str) -> timedelta:
    value = value.strip()
    if not value:
        raise ConfigurationError("duration cannot be empty")
    position = 0
    seconds = 0.0
    for match in _DURATION_PART.finditer(value):
        if match.start() != position:
            raise ConfigurationError(f"invalid duration {value!r}")
        amount = int(match.group("amount"))
        unit = match.group("unit")
        seconds += amount * {"ms": 0.001, "s": 1, "m": 60, "h": 3600}[unit]
        position = match.end()
    if position != len(value) or seconds <= 0:
        raise ConfigurationError(f"invalid duration {value!r}")
    return timedelta(seconds=seconds)


def _duration(name: str, default: str) -> timedelta:
    return parse_duration(os.getenv(name, default))


def _boolean(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    normalized = value.strip().lower()
    if normalized in {"true", "1"}:
        return True
    if normalized in {"false", "0"}:
        return False
    raise ConfigurationError(f"{name} must be true or false")


def _csv(name: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in os.getenv(name, "").split(",") if part.strip())


def _secret(name: str, *, optional: bool = False) -> bytes:
    encoded = os.getenv(name, "").strip()
    if not encoded and optional:
        return b""
    if not encoded:
        raise ConfigurationError(f"{name} is required")
    if "=" in encoded:
        raise ConfigurationError(f"{name} must use unpadded base64url")
    try:
        decoded = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must use unpadded base64url") from exc
    if len(decoded) < 32:
        raise ConfigurationError(f"{name} must decode to at least 32 bytes")
    return decoded


def _require_independent_secrets(secrets: dict[str, bytes]) -> None:
    """Reject production deployments that reuse one secret for several purposes."""

    configured = [(name, value) for name, value in secrets.items() if value]
    for index, (left_name, left_value) in enumerate(configured):
        for right_name, right_value in configured[index + 1 :]:
            if left_value == right_value:
                raise ConfigurationError(
                    f"{left_name} and {right_name} must use independent values in production"
                )


def _service_url(name: str, value: str, *, production: bool) -> str:
    parsed = urlparse(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ConfigurationError(
            f"{name} must be an absolute HTTP(S) URL without credentials, query, or fragment"
        )
    if production and parsed.scheme != "https":
        raise ConfigurationError(f"{name} must use HTTPS in production")
    return value.rstrip("/")


def validate_database_url(value: str, *, require_verified_tls: bool) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"postgres", "postgresql"} or not parsed.hostname or parsed.fragment:
        raise ConfigurationError("DENILICENSE_DATABASE_URL must be a valid PostgreSQL URL")
    if require_verified_tls:
        modes = parse_qs(parsed.query, keep_blank_values=True).get("sslmode", [])
        if modes != ["verify-full"]:
            raise ConfigurationError(
                "production PostgreSQL requires exactly one sslmode=verify-full parameter"
            )
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    environment: str
    http_host: str
    http_port: int
    database_url: str
    token_pepper: bytes
    device_pepper: bytes
    issuance_pepper: bytes
    password_pepper: bytes
    access_token_ttl: timedelta
    refresh_token_ttl: timedelta
    verification_ttl: timedelta
    password_reset_ttl: timedelta
    activation_lease_ttl: timedelta
    registration_mode: str
    allowed_origins: tuple[str, ...]
    trusted_proxy_cidrs: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    expose_dev_tokens: bool
    public_app_url: str
    email_webhook_url: str
    email_webhook_bearer: str
    activation_issuer: str
    activation_key_file: Path | None
    activation_key_passphrase_file: Path | None
    activation_verification_key_files: tuple[Path, ...]
    auto_migrate: bool
    shutdown_timeout: timedelta

    @classmethod
    def from_env(cls) -> Settings:
        environment = os.getenv("DENILICENSE_ENV", "").strip()
        if environment not in {"development", "test", "production"}:
            raise ConfigurationError("DENILICENSE_ENV must be development, test, or production")
        production = environment == "production"
        address = os.getenv("DENILICENSE_HTTP_ADDRESS", ":8080").strip()
        if ":" not in address:
            raise ConfigurationError("DENILICENSE_HTTP_ADDRESS must use host:port")
        host, raw_port = address.rsplit(":", 1)
        try:
            port = int(raw_port)
        except ValueError as exc:
            raise ConfigurationError("DENILICENSE_HTTP_ADDRESS has an invalid port") from exc
        if not 1 <= port <= 65535:
            raise ConfigurationError("DENILICENSE_HTTP_ADDRESS has an invalid port")
        database_url = validate_database_url(
            os.getenv("DENILICENSE_DATABASE_URL", "").strip(), require_verified_tls=production
        )
        access_ttl = _duration("DENILICENSE_ACCESS_TOKEN_TTL", "15m")
        refresh_ttl = _duration("DENILICENSE_REFRESH_TOKEN_TTL", "720h")
        verification_ttl = _duration("DENILICENSE_EMAIL_VERIFICATION_TTL", "30m")
        reset_ttl = _duration("DENILICENSE_PASSWORD_RESET_TTL", "30m")
        lease_ttl = _duration("DENILICENSE_ACTIVATION_LEASE_TTL", "24h")
        shutdown_timeout = _duration("DENILICENSE_SHUTDOWN_TIMEOUT", "15s")
        if not timedelta(minutes=1) <= access_ttl <= timedelta(hours=1):
            raise ConfigurationError("access token TTL must be between one minute and one hour")
        if not access_ttl < refresh_ttl <= timedelta(days=90):
            raise ConfigurationError("refresh token TTL must be longer than access TTL and at most 90 days")
        if not timedelta(minutes=5) <= verification_ttl <= timedelta(days=1):
            raise ConfigurationError("verification TTL must be between five minutes and 24 hours")
        if not timedelta(minutes=5) <= reset_ttl <= timedelta(days=1):
            raise ConfigurationError("password reset TTL must be between five minutes and 24 hours")
        if not timedelta(hours=1) <= lease_ttl <= timedelta(days=7):
            raise ConfigurationError("activation lease TTL must be between one hour and seven days")
        registration_mode = os.getenv("DENILICENSE_REGISTRATION_MODE", "closed").strip()
        if registration_mode not in {"open", "closed"}:
            raise ConfigurationError("registration mode must be open or closed")
        expose_dev_tokens = _boolean("DENILICENSE_EXPOSE_DEV_TOKENS", False)
        if production and expose_dev_tokens:
            raise ConfigurationError("development tokens cannot be exposed in production")
        origins = _csv("DENILICENSE_ALLOWED_ORIGINS")
        for origin in origins:
            parsed = urlparse(origin)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.path
                or parsed.query
                or parsed.fragment
                or parsed.username is not None
            ):
                raise ConfigurationError(f"invalid CORS origin {origin!r}")
            if production and parsed.scheme != "https":
                raise ConfigurationError(f"production CORS origin {origin!r} must use HTTPS")
        try:
            proxies = tuple(
                ipaddress.ip_network(value, strict=False) for value in _csv("DENILICENSE_TRUSTED_PROXY_CIDRS")
            )
        except ValueError as exc:
            raise ConfigurationError(f"invalid trusted proxy CIDR: {exc}") from exc
        webhook = os.getenv("DENILICENSE_EMAIL_WEBHOOK_URL", "").strip()
        public_url = os.getenv("DENILICENSE_PUBLIC_APP_URL", "").strip()
        webhook_bearer = os.getenv("DENILICENSE_EMAIL_WEBHOOK_BEARER", "").strip()
        if production and not webhook:
            raise ConfigurationError("production account recovery requires DENILICENSE_EMAIL_WEBHOOK_URL")
        if registration_mode == "open" and not webhook and not expose_dev_tokens:
            raise ConfigurationError(
                "open registration requires an email webhook or development token exposure"
            )
        if webhook:
            webhook = _service_url("DENILICENSE_EMAIL_WEBHOOK_URL", webhook, production=production)
            public_url = _service_url("DENILICENSE_PUBLIC_APP_URL", public_url, production=production)
            if len(webhook_bearer) < 32:
                raise ConfigurationError(
                    "DENILICENSE_EMAIL_WEBHOOK_BEARER must contain at least 32 characters"
                )
        issuer = os.getenv("DENILICENSE_ACTIVATION_ISSUER", "").strip()
        key_file_value = os.getenv("DENILICENSE_ACTIVATION_KEY_FILE", "").strip()
        if bool(issuer) != bool(key_file_value):
            raise ConfigurationError("activation issuer and key file must be configured together")
        if issuer and (len(issuer.encode()) > 256 or any(ord(char) < 32 for char in issuer)):
            raise ConfigurationError("DENILICENSE_ACTIVATION_ISSUER is invalid")
        passphrase_file_value = os.getenv("DENILICENSE_ACTIVATION_KEY_PASSPHRASE_FILE", "").strip()
        if production and key_file_value and not passphrase_file_value:
            raise ConfigurationError("production activation keys require a passphrase file")
        verification_files = tuple(
            Path(value) for value in _csv("DENILICENSE_ACTIVATION_VERIFICATION_KEY_FILES")
        )
        if len(verification_files) > 32:
            raise ConfigurationError("at most 32 activation verification keys may be configured")
        token_pepper = _secret("DENILICENSE_TOKEN_PEPPER")
        device_pepper = _secret("DENILICENSE_DEVICE_PEPPER")
        issuance_pepper = _secret("DENILICENSE_ISSUANCE_PEPPER")
        password_pepper = _secret("DENILICENSE_PASSWORD_PEPPER", optional=True)
        if production:
            _require_independent_secrets(
                {
                    "DENILICENSE_TOKEN_PEPPER": token_pepper,
                    "DENILICENSE_DEVICE_PEPPER": device_pepper,
                    "DENILICENSE_ISSUANCE_PEPPER": issuance_pepper,
                    "DENILICENSE_PASSWORD_PEPPER": password_pepper,
                }
            )
        return cls(
            environment=environment,
            http_host=host or "0.0.0.0",  # noqa: S104 - container listener is intentionally configurable
            http_port=port,
            database_url=database_url,
            token_pepper=token_pepper,
            device_pepper=device_pepper,
            issuance_pepper=issuance_pepper,
            password_pepper=password_pepper,
            access_token_ttl=access_ttl,
            refresh_token_ttl=refresh_ttl,
            verification_ttl=verification_ttl,
            password_reset_ttl=reset_ttl,
            activation_lease_ttl=lease_ttl,
            registration_mode=registration_mode,
            allowed_origins=origins,
            trusted_proxy_cidrs=proxies,
            expose_dev_tokens=expose_dev_tokens,
            public_app_url=public_url.rstrip("/"),
            email_webhook_url=webhook,
            email_webhook_bearer=webhook_bearer,
            activation_issuer=issuer,
            activation_key_file=Path(key_file_value) if key_file_value else None,
            activation_key_passphrase_file=Path(passphrase_file_value) if passphrase_file_value else None,
            activation_verification_key_files=verification_files,
            auto_migrate=_boolean("DENILICENSE_AUTO_MIGRATE", not production),
            shutdown_timeout=shutdown_timeout,
        )
