from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import threading
from dataclasses import dataclass

from argon2.exceptions import VerificationError, VerifyMismatchError
from argon2.low_level import ARGON2_VERSION, Type, hash_secret, verify_secret

ACCESS_TOKEN = "dlat"  # noqa: S105 - public token type prefix, not a credential
REFRESH_TOKEN = "dlrt"  # noqa: S105 - public token type prefix, not a credential
EMAIL_VERIFICATION_TOKEN = "dlev"  # noqa: S105 - public token type prefix
PASSWORD_RESET_TOKEN = "dlpr"  # noqa: S105 - public token type prefix
TOKEN_KINDS = {ACCESS_TOKEN, REFRESH_TOKEN, EMAIL_VERIFICATION_TOKEN, PASSWORD_RESET_TOKEN}

PASSWORD_MIN_CHARS = 15
PASSWORD_MAX_BYTES = 1024
ARGON_MEMORY_KIB = 64 * 1024
ARGON_TIME_COST = 3
ARGON_PARALLELISM = 1
ARGON_HASH_LEN = 32
ARGON_SALT_LEN = 16

_ARGON_GATE = threading.BoundedSemaphore(2)
_PHC = re.compile(
    rb"^\$argon2id\$v=(?P<version>\d+)\$m=(?P<memory>\d+),t=(?P<time>\d+),p=(?P<parallel>\d+)"
    rb"\$(?P<salt>[A-Za-z0-9+/]+)\$(?P<hash>[A-Za-z0-9+/]+)$"
)
_LOCAL_PART = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$")
_DOMAIN_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class AuthenticationError(ValueError):
    pass


def _raw_urlsafe(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_raw_urlsafe(value: str) -> bytes:
    if not value or "=" in value:
        raise AuthenticationError("invalid base64url")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except ValueError as exc:
        raise AuthenticationError("invalid base64url") from exc
    if _raw_urlsafe(decoded) != value:
        raise AuthenticationError("non-canonical base64url")
    return decoded


def normalize_email(value: str) -> tuple[str, str]:
    if any(ord(char) > 127 or ord(char) < 32 or ord(char) == 127 for char in value):
        raise AuthenticationError("invalid email")
    display = value.strip()
    if not display or len(display) > 254 or display.count("@") != 1:
        raise AuthenticationError("invalid email")
    local, domain = display.rsplit("@", 1)
    if (
        not 1 <= len(local) <= 64
        or not _LOCAL_PART.fullmatch(local)
        or local.startswith(".")
        or local.endswith(".")
        or ".." in local
    ):
        raise AuthenticationError("invalid email")
    labels = domain.split(".")
    if len(labels) < 2 or any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise AuthenticationError("invalid email")
    return display, display.lower()


def validate_password(password: str) -> None:
    try:
        encoded = password.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise AuthenticationError("password is not valid UTF-8") from exc
    if len(password) < PASSWORD_MIN_CHARS or len(encoded) > PASSWORD_MAX_BYTES:
        raise AuthenticationError(
            f"password must contain at least {PASSWORD_MIN_CHARS} characters "
            f"and at most {PASSWORD_MAX_BYTES} bytes"
        )


@dataclass(frozen=True, slots=True)
class PasswordManager:
    pepper: bytes = b""

    def _input(self, password: str) -> bytes:
        encoded = password.encode("utf-8")
        if not self.pepper:
            return encoded
        return hmac.new(self.pepper, b"DeniLicense/password/v1\x00" + encoded, hashlib.sha256).digest()

    def hash(self, password: str) -> str:
        validate_password(password)
        with _ARGON_GATE:
            encoded = hash_secret(
                self._input(password),
                secrets.token_bytes(ARGON_SALT_LEN),
                time_cost=ARGON_TIME_COST,
                memory_cost=ARGON_MEMORY_KIB,
                parallelism=ARGON_PARALLELISM,
                hash_len=ARGON_HASH_LEN,
                type=Type.ID,
                version=ARGON2_VERSION,
            )
        return encoded.decode("ascii")

    def verify(self, encoded_hash: str, password: str) -> bool:
        try:
            encoded = encoded_hash.encode("ascii", "strict")
            password_bytes = password.encode("utf-8")
        except UnicodeEncodeError, UnicodeDecodeError:
            return False
        match = _PHC.fullmatch(encoded)
        if not match:
            return False
        version = int(match.group("version"))
        memory = int(match.group("memory"))
        time_cost = int(match.group("time"))
        parallelism = int(match.group("parallel"))
        if (
            version != ARGON2_VERSION
            or not 19 * 1024 <= memory <= 1024 * 1024
            or not 1 <= time_cost <= 10
            or not 1 <= parallelism <= 16
        ):
            return False
        if len(password_bytes) > PASSWORD_MAX_BYTES:
            return False
        try:
            with _ARGON_GATE:
                return verify_secret(encoded, self._input(password), Type.ID)
        except VerificationError, VerifyMismatchError, ValueError:
            return False


def new_token(kind: str) -> str:
    if kind not in TOKEN_KINDS:
        raise AuthenticationError("unknown token kind")
    return f"{kind}_{_raw_urlsafe(secrets.token_bytes(32))}"


def hash_token(pepper: bytes, kind: str, token: str) -> bytes:
    if kind not in TOKEN_KINDS:
        raise AuthenticationError("unknown token kind")
    prefix = f"{kind}_"
    if not token.startswith(prefix) or len(token) != len(prefix) + 43:
        raise AuthenticationError("invalid token")
    random_part = _decode_raw_urlsafe(token[len(prefix) :])
    if len(random_part) != 32:
        raise AuthenticationError("invalid token")
    return hmac.new(
        pepper,
        b"DeniLicense/token/v1\x00" + kind.encode() + b"\x00" + token.encode(),
        hashlib.sha256,
    ).digest()
