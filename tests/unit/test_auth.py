import pytest

from denilicense.auth import (
    ACCESS_TOKEN,
    AuthenticationError,
    PasswordManager,
    hash_token,
    new_token,
    normalize_email,
)


def test_email_normalization_is_shared_and_strict() -> None:
    assert normalize_email("Owner@Example.COM") == ("Owner@Example.COM", "owner@example.com")
    invalid = ("owner@localhost", "Display <owner@example.com>", "owner@example.com\n", "owner@例.example")
    for value in invalid:
        with pytest.raises(AuthenticationError):
            normalize_email(value)


def test_password_hash_and_verify_with_pepper() -> None:
    manager = PasswordManager(b"p" * 32)
    encoded = manager.hash("correct horse battery staple")
    assert manager.verify(encoded, "correct horse battery staple")
    assert not manager.verify(encoded, "incorrect horse battery staple")
    assert not manager.verify(encoded, "invalid surrogate \ud800")


def test_opaque_tokens_are_strict_and_domain_separated() -> None:
    token = new_token(ACCESS_TOKEN)
    digest = hash_token(b"p" * 32, ACCESS_TOKEN, token)
    assert len(digest) == 32
    with pytest.raises(AuthenticationError):
        hash_token(b"p" * 32, ACCESS_TOKEN, token + "=")
