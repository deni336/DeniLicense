"""Network-free command-line issuer for DeniLicense offline grants."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import secrets
import sys
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .crypto.claim_code import generate as generate_claim_code
from .crypto.common import DeniLicenseError, b64url_encode, format_rfc3339
from .crypto.keys import (
    ACTIVATION_RECEIPT_SIGNER,
    MAX_KEY_FILE_BYTES,
    OFFLINE_LICENSE_ISSUER,
    SigningKey,
    decrypt_signing_key,
    encrypt_signing_key,
    marshal_public_key,
    parse_public_key,
)
from .crypto.license import (
    MAX_TOKEN_BYTES,
    LicenseClaims,
    VerificationOptions,
    encode_claim_code_digest,
    generate_serial,
    sign_token,
    verify_token,
    verify_token_for_use,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="denilic", description="DeniLicense network-free offline issuer")
    subparsers = parser.add_subparsers(dest="command", required=True)

    keygen = subparsers.add_parser("keygen", help="generate a passphrase-encrypted Ed25519 key")
    keygen.add_argument("--purpose", choices=("license", "activation"), default="license")
    keygen.add_argument("--private", type=Path, default=Path("issuer.key.json"))
    keygen.add_argument("--public", type=Path, default=Path("issuer.public.json"))

    public = subparsers.add_parser("public-key", help="export a public key from an encrypted key")
    public.add_argument("--private", type=Path, default=Path("issuer.key.json"))
    public.add_argument("--out", type=Path, default=Path("issuer.public.json"))

    issue = subparsers.add_parser("issue", help="create a claim code and signed offline grant")
    issue.add_argument("--key", type=Path, default=Path("issuer.key.json"))
    issue.add_argument("--issuer", required=True)
    issue.add_argument("--product", required=True)
    issue.add_argument("--subject", default="unassigned")
    issue.add_argument("--max-activations", type=int, default=1)
    issue.add_argument("--not-before")
    expiry = issue.add_mutually_exclusive_group(required=True)
    expiry.add_argument("--expires")
    expiry.add_argument("--valid-for")
    expiry.add_argument("--perpetual", action="store_true")
    issue.add_argument("--entitlement", action="append", default=[], metavar="KEY=VALUE")
    issue.add_argument("--out", type=Path, default=Path("license.dlicense"))

    verify = subparsers.add_parser("verify", help="verify and inspect a signed grant")
    verify.add_argument("--public", type=Path, default=Path("issuer.public.json"))
    verify.add_argument("--artifact", type=Path, default=Path("license.dlicense"))
    verify.add_argument("--issuer")
    verify.add_argument("--product")
    verify.add_argument("--ignore-time", action="store_true")

    subparsers.add_parser("secret", help="generate a 32-byte base64url configuration secret")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "keygen":
            _keygen(args)
        elif args.command == "public-key":
            _public_key(args)
        elif args.command == "issue":
            _issue(args)
        elif args.command == "verify":
            _verify(args)
        elif args.command == "secret":
            print(b64url_encode(secrets.token_bytes(32)))
        else:  # pragma: no cover - guarded by argparse
            parser.error("unknown command")
    except (DeniLicenseError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


def _keygen(args: argparse.Namespace) -> None:
    if args.private.resolve() == args.public.resolve():
        raise ValueError("private and public paths must differ")
    _ensure_absent(args.private)
    _ensure_absent(args.public)
    passphrase = _read_passphrase(confirm=True)
    purpose = OFFLINE_LICENSE_ISSUER if args.purpose == "license" else ACTIVATION_RECEIPT_SIGNER
    key = SigningKey.generate(purpose)
    _write_new(args.private, encrypt_signing_key(key, passphrase), 0o600)
    try:
        _write_new(args.public, marshal_public_key(key.verification_key), 0o644)
    except Exception:
        args.private.unlink(missing_ok=True)
        raise
    print(f"Key ID: {key.key_id}\nPrivate key: {args.private}\nPublic key: {args.public}")


def _public_key(args: argparse.Namespace) -> None:
    _ensure_absent(args.out)
    key = _load_key(args.private)
    _write_new(args.out, marshal_public_key(key.verification_key), 0o644)
    print(f"Key ID: {key.key_id}\nPublic key: {args.out}")


def _issue(args: argparse.Namespace) -> None:
    _ensure_absent(args.out)
    now = datetime.now(UTC).replace(microsecond=0)
    not_before = _parse_time(args.not_before) if args.not_before else now
    expires_at: datetime | None = None
    if args.expires:
        expires_at = _parse_time(args.expires)
    elif args.valid_for:
        duration = _parse_duration(args.valid_for)
        if not timedelta(hours=1) <= duration <= timedelta(days=3650):
            raise ValueError("--valid-for must be between one hour and ten years")
        expires_at = not_before + duration
    key = _load_key(args.key)
    if key.purpose != OFFLINE_LICENSE_ISSUER:
        raise ValueError("the supplied key is not an offline license issuer key")
    code = generate_claim_code()
    claims = LicenseClaims(
        issuer=args.issuer,
        key_id=key.key_id,
        audience=args.product.upper(),
        serial=generate_serial(),
        subject=args.subject,
        claim_code_sha256=encode_claim_code_digest(code.digest),
        claim_code_suffix=code.suffix,
        issued_at=now,
        not_before=not_before,
        expires_at=expires_at,
        max_activations=args.max_activations,
        entitlements=_parse_entitlements(args.entitlement),
    )
    artifact = sign_token(claims, key)
    _write_new(args.out, (artifact + "\n").encode("ascii"), 0o600)
    print(
        f"Claim code (shown once): {code.display}\nArtifact: {args.out}\n"
        f"Serial: {claims.serial}\nKey ID: {key.key_id}"
    )


def _verify(args: argparse.Namespace) -> None:
    if not args.ignore_time and (not args.issuer or not args.product):
        raise ValueError("--issuer and --product are required unless --ignore-time is explicit")
    key = parse_public_key(_read_bounded(args.public, MAX_KEY_FILE_BYTES))
    artifact = _read_bounded(args.artifact, MAX_TOKEN_BYTES + 1).decode("ascii").strip()
    if args.ignore_time:
        claims = verify_token(artifact, key)
    else:
        claims = verify_token_for_use(
            artifact,
            key,
            VerificationOptions(args.issuer, args.product.upper(), clock_skew=timedelta(minutes=1)),
        )
    print("VALID")
    print(json.dumps(claims.to_wire(), indent=2, ensure_ascii=False))


def _load_key(path: Path) -> SigningKey:
    return decrypt_signing_key(_read_bounded(path, MAX_KEY_FILE_BYTES), _read_passphrase(confirm=False))


def _read_passphrase(*, confirm: bool) -> str:
    environment = os.environ.get("DENILICENSE_KEY_PASSPHRASE")
    if environment:
        return environment
    if not sys.stdin.isatty():
        raise ValueError("no terminal available; set DENILICENSE_KEY_PASSPHRASE securely")
    value = getpass.getpass("New key passphrase: " if confirm else "Key passphrase: ")
    if confirm and value != getpass.getpass("Confirm passphrase: "):
        raise ValueError("passphrases did not match")
    return value


def _parse_entitlements(values: list[str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for value in values:
        if "=" not in value:
            raise ValueError("entitlement must use key=value")
        name, raw = value.split("=", 1)
        if not name or name in result:
            raise ValueError(f"invalid or duplicate entitlement {name!r}")
        if raw == "true":
            parsed: Any = True
        elif raw == "false":
            parsed = False
        elif re.fullmatch(r"-?(0|[1-9][0-9]*)", raw):
            parsed = int(raw)
        else:
            parsed = raw
        result[name] = parsed
    return result


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid RFC3339 time {value!r}") from exc
    if parsed.tzinfo is None:
        raise ValueError("RFC3339 time must include an offset")
    parsed = parsed.astimezone(UTC)
    format_rfc3339(parsed)
    return parsed


def _parse_duration(value: str) -> timedelta:
    matches = list(re.finditer(r"([0-9]+(?:\.[0-9]+)?)(h|m|s)", value))
    if not matches or "".join(match.group(0) for match in matches) != value:
        raise ValueError("duration must use concatenated h, m, and s units, for example 8760h")
    seconds = sum(float(match.group(1)) * {"h": 3600, "m": 60, "s": 1}[match.group(2)] for match in matches)
    return timedelta(seconds=seconds)


def _read_bounded(path: Path, limit: int) -> bytes:
    with path.open("rb") as handle:
        value = handle.read(limit + 1)
    if len(value) > limit:
        raise ValueError(f"{path} exceeds size limit")
    return value


def _ensure_absent(path: Path) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite existing file: {path}")


def _write_new(path: Path, value: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
