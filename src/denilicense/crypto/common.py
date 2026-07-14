"""Strict, compatibility-preserving primitives for DeniLicense artifacts."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import unicodedata
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any


class DeniLicenseError(ValueError):
    """Base class for rejected cryptographic artifacts."""


class InvalidClaims(DeniLicenseError):
    pass


class NonCanonicalPayload(DeniLicenseError):
    pass


class InvalidPublicKey(DeniLicenseError):
    pass


_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
MAX_ENTITLEMENTS_JSON_BYTES = 12 * 1024
_P = (1 << 255) - 19
_D = (-121665 * pow(121666, -1, _P)) % _P
_L = (1 << 252) + 27742317777372353535851937790883648493


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_decode(value: str, *, size: int | None = None) -> bytes:
    if not isinstance(value, str) or not value or "=" in value or not _B64URL_RE.fullmatch(value):
        raise DeniLicenseError("value is not canonical unpadded base64url")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise DeniLicenseError("value is not canonical unpadded base64url") from exc
    if b64url_encode(decoded) != value or (size is not None and len(decoded) != size):
        raise DeniLicenseError("value is not canonical unpadded base64url of the expected size")
    return decoded


def is_digest(value: str) -> bool:
    try:
        return len(value) == 43 and len(b64url_decode(value, size=32)) == 32
    except DeniLicenseError, TypeError:
        return False


def digest_bytes(value: bytes) -> str:
    return b64url_encode(hashlib.sha256(value).digest())


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DeniLicenseError(f"duplicate JSON field {key!r}")
        result[key] = value
    return result


def strict_json_loads(data: bytes | str, *, max_bytes: int | None = None) -> Any:
    if isinstance(data, bytes):
        if max_bytes is not None and len(data) > max_bytes:
            raise DeniLicenseError("JSON exceeds size limit")
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise DeniLicenseError("JSON is not valid UTF-8") from exc
    elif isinstance(data, str):
        text = data
        if max_bytes is not None:
            try:
                if len(text.encode("utf-8")) > max_bytes:
                    raise DeniLicenseError("JSON exceeds size limit")
            except UnicodeEncodeError as exc:
                raise DeniLicenseError("JSON is not valid UTF-8") from exc
    else:
        raise TypeError("JSON input must be bytes or str")
    try:
        return json.loads(
            text,
            object_pairs_hook=_pairs_no_duplicates,
            parse_float=lambda _value: (_ for _ in ()).throw(
                DeniLicenseError("floating-point JSON numbers are forbidden")
            ),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                DeniLicenseError("non-finite JSON numbers are forbidden")
            ),
        )
    except DeniLicenseError:
        raise
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise DeniLicenseError("invalid JSON") from exc


def require_exact_fields(value: Any, required: Iterable[str], optional: Iterable[str] = ()) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DeniLicenseError("JSON value must be an object")
    required_set = set(required)
    allowed = required_set | set(optional)
    unknown = set(value) - allowed
    missing = required_set - set(value)
    if unknown:
        raise DeniLicenseError(f"unknown JSON field {sorted(unknown)[0]!r}")
    if missing:
        raise DeniLicenseError(f"missing JSON field {sorted(missing)[0]!r}")
    return value


def canonical_json(value: Any) -> bytes:
    # This matches encoding/json's compact UTF-8 representation, including its
    # default HTML escaping. Dict insertion order carries the stable wire-field order.
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    encoded = encoded.replace("&", r"\u0026").replace("<", r"\u003c").replace(">", r"\u003e")
    encoded = encoded.replace("\u2028", r"\u2028").replace("\u2029", r"\u2029")
    return encoded.encode("utf-8")


def format_rfc3339(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise InvalidClaims("time must use UTC")
    if value.year < 1970 or value.year > 9999:
        raise InvalidClaims("time year must be between 1970 and 9999")
    base = value.strftime("%Y-%m-%dT%H:%M:%S")
    if value.microsecond:
        base += "." + f"{value.microsecond:06d}".rstrip("0")
    return base + "Z"


def parse_rfc3339(value: Any) -> datetime:
    if not isinstance(value, str):
        raise InvalidClaims("time must be an RFC3339 UTC string")
    match = re.fullmatch(
        r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z",
        value,
    )
    if match is None or (match[7] is not None and match[7].endswith("0")):
        raise NonCanonicalPayload("non-canonical RFC3339 timestamp")
    fraction = (match[7] or "").ljust(9, "0")
    try:
        parsed = datetime(*(int(part) for part in match.groups()[:6]), int(fraction[:6]), tzinfo=UTC)
    except ValueError as exc:
        raise InvalidClaims("time must be an RFC3339 UTC string") from exc
    return parsed


def format_rfc3339_preserving(value: datetime, original: str | None) -> str:
    """Retain the last three wire nanosecond digits when a parsed claim is re-encoded."""
    if original is not None:
        parsed = parse_rfc3339(original)
        if parsed == value:
            return original
    return format_rfc3339(value)


def time_order_key(value: datetime, original: str | None = None) -> int:
    """A nanosecond ordering key for UTC claims and ordinary aware datetimes."""
    if value.tzinfo is None:
        raise InvalidClaims("time must include a timezone")
    utc = value.astimezone(UTC)
    nanoseconds = utc.microsecond * 1000
    if original is not None and parse_rfc3339(original) == value:
        match = re.search(r"\.(\d{1,9})Z$", original)
        if match is not None:
            nanoseconds = int(match[1].ljust(9, "0"))
    seconds = ((utc.toordinal() * 24 + utc.hour) * 60 + utc.minute) * 60 + utc.second
    return seconds * 1_000_000_000 + nanoseconds


def validate_text(field: str, value: Any, max_bytes: int) -> str:
    try:
        encoded_length = len(value.encode("utf-8")) if isinstance(value, str) else 0
    except UnicodeEncodeError as exc:
        raise InvalidClaims(f"{field} must be valid UTF-8") from exc
    if not isinstance(value, str) or not value or encoded_length > max_bytes:
        raise InvalidClaims(f"{field} must contain 1 to {max_bytes} UTF-8 bytes")
    if value != value.strip() or any(unicodedata.category(character).startswith("C") for character in value):
        raise InvalidClaims(f"{field} must not have surrounding whitespace or control characters")
    return value


def validate_identifier(field: str, value: Any, max_bytes: int, *, lowercase: bool = False) -> str:
    try:
        encoded_length = len(value.encode("utf-8")) if isinstance(value, str) else 0
    except UnicodeEncodeError as exc:
        raise InvalidClaims(f"{field} must be valid UTF-8") from exc
    if not isinstance(value, str) or not value or encoded_length > max_bytes:
        raise InvalidClaims(f"{field} must contain 1 to {max_bytes} bytes")
    first = "a-z0-9" if lowercase else "A-Za-z0-9"
    expression = rf"^[{first}][{first}._-]*$"
    if not re.fullmatch(expression, value, flags=re.ASCII):
        raise InvalidClaims(f"{field} has invalid characters")
    return value


def validate_entitlements(value: Any) -> dict[str, bool | str | int]:
    if not isinstance(value, dict):
        raise InvalidClaims("entitlements must be an object")
    if len(value) > 128:
        raise InvalidClaims("entitlements must contain at most 128 entries")
    result: dict[str, bool | str | int] = {}
    for name, item in value.items():
        validate_identifier(f"entitlements.{name}", name, 128, lowercase=True)
        try:
            string_bytes = len(item.encode("utf-8")) if isinstance(item, str) else 0
        except UnicodeEncodeError as exc:
            raise InvalidClaims(f"entitlements.{name} must be valid UTF-8") from exc
        if (
            isinstance(item, bool)
            or (isinstance(item, int) and -(1 << 63) <= item < (1 << 63))
            or (
                isinstance(item, str)
                and string_bytes <= 4096
                and not any(unicodedata.category(character).startswith("C") for character in item)
            )
        ):
            pass
        else:
            raise InvalidClaims(f"entitlements.{name} must be a boolean, string, or signed 64-bit integer")
        result[name] = item
    encoded = canonical_json({name: result[name] for name in sorted(result)})
    if len(encoded) > MAX_ENTITLEMENTS_JSON_BYTES:
        raise InvalidClaims(f"entitlements must encode to at most {MAX_ENTITLEMENTS_JSON_BYTES} bytes")
    return result


def validate_uuid(value: Any, *, require_rfc_variant: bool) -> str:
    if not isinstance(value, str) or len(value) != 36 or value.lower() != value:
        raise InvalidClaims("UUID must be canonical and non-zero")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise InvalidClaims("UUID must be canonical and non-zero") from exc
    if parsed.int == 0 or str(parsed) != value:
        raise InvalidClaims("UUID must be canonical and non-zero")
    if require_rfc_variant and (parsed.variant != uuid.RFC_4122 or parsed.version not in range(1, 9)):
        raise InvalidClaims("UUID must have an RFC variant and assigned version")
    return value


def validate_ed25519_public_key(encoded: bytes) -> None:
    """Reject non-canonical, identity, low-order, and mixed-order points."""
    if not isinstance(encoded, bytes) or len(encoded) != 32:
        raise InvalidPublicKey("invalid Ed25519 public key length")
    value = bytearray(encoded)
    x_sign = value[31] >> 7
    value[31] &= 0x7F
    y = int.from_bytes(value, "little")
    if y >= _P:
        raise InvalidPublicKey("non-canonical Ed25519 public key")
    y_squared = y * y % _P
    denominator = (_D * y_squared + 1) % _P
    if denominator == 0:
        raise InvalidPublicKey("invalid Ed25519 public key")
    x_squared = (y_squared - 1) * pow(denominator, -1, _P) % _P
    # p == 5 mod 8. sqrt candidate and the sqrt(-1) correction.
    x = pow(x_squared, (_P + 3) // 8, _P)
    if x * x % _P != x_squared:
        x = x * pow(2, (_P - 1) // 4, _P) % _P
    if x * x % _P != x_squared:
        raise InvalidPublicKey("Ed25519 public key is not on the curve")
    if x & 1 != x_sign:
        x = _P - x
    if x == 0 and x_sign:
        raise InvalidPublicKey("non-canonical Ed25519 public key sign bit")

    point = (x, y, 1, x * y % _P)
    if _is_identity(point):
        raise InvalidPublicKey("Ed25519 identity public key is not allowed")
    if not _is_identity(_scalar_mult(point, _L)):
        raise InvalidPublicKey("Ed25519 public key is not in the prime-order subgroup")


def _point_add(
    left: tuple[int, int, int, int], right: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * _D * t1 * t2 % _P
    d = 2 * z1 * z2 % _P
    e, f, g, h = (b - a) % _P, (d - c) % _P, (d + c) % _P, (b + a) % _P
    return e * f % _P, g * h % _P, f * g % _P, e * h % _P


def _scalar_mult(point: tuple[int, int, int, int], scalar: int) -> tuple[int, int, int, int]:
    result = (0, 1, 1, 0)
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def _is_identity(point: tuple[int, int, int, int]) -> bool:
    x, y, z, _ = point
    return z != 0 and x == 0 and y == z
