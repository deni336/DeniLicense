import base64
from pathlib import Path

import pytest
import yaml

from denilicense.config import ConfigurationError, Settings, parse_duration, validate_database_url


def test_compose_keeps_host_database_access_separate_from_integration_network() -> None:
    compose_path = Path(__file__).resolve().parents[2] / "compose.yaml"
    compose = yaml.safe_load(compose_path.read_text(encoding="utf-8"))

    postgres = compose["services"]["postgres"]
    api = compose["services"]["api"]
    assert postgres["ports"] == ["127.0.0.1:5432:5432"]
    assert postgres["networks"] == ["database"]
    assert compose["networks"]["database"] in (None, {})
    assert "integrations" not in postgres["networks"]
    assert api["networks"]["integrations"]["aliases"] == ["denilicense-api"]


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


def test_production_requires_independent_peppers(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_base_environment(monkeypatch)
    monkeypatch.setenv("DENILICENSE_ENV", "production")
    monkeypatch.setenv(
        "DENILICENSE_DATABASE_URL",
        "postgresql://db.example/denilicense?sslmode=verify-full",
    )
    monkeypatch.setenv("DENILICENSE_EMAIL_WEBHOOK_URL", "https://mailer.example/v1/send")
    monkeypatch.setenv("DENILICENSE_PUBLIC_APP_URL", "https://licenses.example")
    monkeypatch.setenv("DENILICENSE_EMAIL_WEBHOOK_BEARER", "b" * 32)

    with pytest.raises(ConfigurationError, match="must use independent values"):
        Settings.from_env()


def test_production_accepts_distinct_peppers(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_base_environment(monkeypatch)
    monkeypatch.setenv("DENILICENSE_ENV", "production")
    monkeypatch.setenv(
        "DENILICENSE_DATABASE_URL",
        "postgresql://db.example/denilicense?sslmode=verify-full",
    )
    monkeypatch.setenv("DENILICENSE_EMAIL_WEBHOOK_URL", "https://mailer.example/v1/send")
    monkeypatch.setenv("DENILICENSE_PUBLIC_APP_URL", "https://licenses.example")
    monkeypatch.setenv("DENILICENSE_EMAIL_WEBHOOK_BEARER", "b" * 32)
    for index, name in enumerate(
        (
            "DENILICENSE_TOKEN_PEPPER",
            "DENILICENSE_DEVICE_PEPPER",
            "DENILICENSE_ISSUANCE_PEPPER",
            "DENILICENSE_PASSWORD_PEPPER",
        ),
        start=1,
    ):
        value = base64.urlsafe_b64encode(bytes([index]) * 32).decode().rstrip("=")
        monkeypatch.setenv(name, value)

    settings = Settings.from_env()

    assert (
        len(
            {
                settings.token_pepper,
                settings.device_pepper,
                settings.issuance_pepper,
                settings.password_pepper,
            }
        )
        == 4
    )
