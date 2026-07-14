import base64

import pytest

from denilicense.config import ConfigurationError, Settings, parse_duration, validate_database_url


def _set_base_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = base64.urlsafe_b64encode(b"s" * 32).decode().rstrip("=")
    values = {
        "DENILICENSE_ENV": "test",
        "DENILICENSE_DATABASE_URL": "postgresql://db.example/denilicense?sslmode=disable",
        "DENILICENSE_TOKEN_PEPPER": secret,
        "DENILICENSE_DEVICE_PEPPER": secret,
        "DENILICENSE_ISSUANCE_PEPPER": secret,
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)


def test_settings_loads_strict_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_base_environment(monkeypatch)
    settings = Settings.from_env()
    assert len(settings.token_pepper) == 32
    assert settings.auto_migrate is True


def test_duration_parser_supports_go_style_values() -> None:
    assert parse_duration("1h30m").total_seconds() == 5400
    with pytest.raises(ConfigurationError):
        parse_duration("1 hour")


def test_production_database_tls_cannot_be_ambiguous() -> None:
    validate_database_url("postgresql://db.example/app?sslmode=verify-full", require_verified_tls=True)
    for value in (
        "postgresql://db.example/app",
        "postgresql://db.example/app?sslmode=disable",
        "postgresql://db.example/app?sslmode=verify-full&sslmode=disable",
    ):
        with pytest.raises(ConfigurationError):
            validate_database_url(value, require_verified_tls=True)
