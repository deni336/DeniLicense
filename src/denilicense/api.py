"""FastAPI HTTP service for authentication, licensing, and administration."""

import hashlib
import hmac
import json
import logging
import mimetypes
import re
import secrets
import sysconfig
from collections.abc import AsyncIterator, Callable, Sequence
from contextlib import asynccontextmanager
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from importlib import resources
from pathlib import Path
from typing import Annotated, Any, NoReturn
from urllib.parse import urlencode
from uuid import UUID, uuid4

import yaml
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.routing import APIRoute
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from . import auth
from .config import Settings
from .crypto import (
    ACTIVATION_RECEIPT_SIGNER,
    JWK,
    JWKS,
    OFFLINE_LICENSE_ISSUER,
    DeniLicenseError,
    LeaseClaims,
    SigningKey,
    VerificationKey,
    claim_code_digest,
    device_key_thumbprint,
    inspect_unverified,
    new_jwt_id,
    parse_public_key,
    sign_lease,
    verify_renewal_signature,
    verify_token,
)
from .crypto import (
    RenewalChallenge as CryptoRenewalChallenge,
)
from .crypto.claim_code import from_entropy as claim_code_from_entropy
from .crypto.common import b64url_decode, b64url_encode, canonical_json, validate_ed25519_public_key
from .domain import (
    AuditEvent,
    ConflictError,
    InvalidError,
    LicenseStateError,
    NotFoundError,
    Principal,
    RefreshReuseError,
    Role,
    SeatLimitError,
    StoreError,
    UnauthorizedError,
)
from .emailer import EmailJob, EmailSender
from .middleware import ClientSourceResolver, RateLimiter, RequestMiddleware
from .schemas import (
    ActivationRequest,
    ApproveLicenseRequest,
    ChangePasswordRequest,
    ClaimLicenseRequest,
    CompleteRenewalRequest,
    CreateCustomerLicenseRequest,
    CreateLicenseRequest,
    CreateManagedUserRequest,
    CreateProductRequest,
    DeleteLicenseRequest,
    DeleteUserRequest,
    DenyLicenseRequest,
    EmailRequest,
    ImportLicenseRequest,
    IssuerStatusRequest,
    LicenseStateRequest,
    LifecycleRequest,
    LoginRequest,
    PasswordResetConfirmRequest,
    ProductStatusRequest,
    RefreshRequest,
    RegisterIssuerRequest,
    RegisterRequest,
    RenewalChallengeRequest,
    UserAccessRequest,
    UserRoleRequest,
    UserStatusRequest,
    VerifyEmailRequest,
)
from .store import (
    ActivateParams,
    AdminActivationListFilter,
    AuditListFilter,
    CreateLicenseParams,
    CreateLicenseRequestParams,
    CreateManagedUserParams,
    CreateProductParams,
    CreateSessionParams,
    LicenseListFilter,
    LicenseRequestListFilter,
    RegisterIssuerParams,
    RegisterPendingUserParams,
    ResendPasswordSetupParams,
    RotateSessionParams,
    Store,
    UpdateUserAccessParams,
)

logger = logging.getLogger("denilicense.api")
MAX_JSON_BODY = 64 * 1024
RENEWAL_CHALLENGE_TTL = timedelta(minutes=5)
PRODUCT_CODE = re.compile(r"^[A-Z][A-Z0-9_-]{1,63}$")
ISSUER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{1,255}$")
IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
CLAIM_SUFFIX = re.compile(r"^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{4}$")
HASHED_ASSET = re.compile(r"(?:^|[._-])[0-9a-f]{8,}(?:[._-]|$)", re.IGNORECASE)


class APIError(Exception):
    def __init__(self, status: int, code: str, title: str, detail: str) -> None:
        self.status = status
        self.code = code
        self.title = title
        self.detail = detail
        super().__init__(detail)


INVALID = APIError(400, "invalid_request", "Invalid request", "The request was not valid.")
UNAUTHENTICATED = APIError(
    401, "authentication_required", "Authentication required", "Authentication failed."
)
UNVERIFIED = APIError(
    403,
    "email_verification_required",
    "Email verification required",
    "Verify the account email before continuing.",
)
FORBIDDEN = APIError(403, "forbidden", "Forbidden", "You do not have permission to perform this action.")
NOT_FOUND = APIError(404, "not_found", "Not found", "The requested resource was not found.")
METHOD_NOT_ALLOWED = APIError(
    405,
    "method_not_allowed",
    "Method not allowed",
    "The HTTP method is not allowed for this resource.",
)
CONFLICT = APIError(409, "conflict", "Conflict", "The request conflicts with existing state.")
REFRESH_REUSE = APIError(
    401,
    "session_compromised",
    "Session revoked",
    "Refresh-token reuse was detected; the session has been revoked.",
)
SEAT_LIMIT = APIError(
    409,
    "activation_limit_reached",
    "Activation limit reached",
    "No activation seats are currently available.",
)
LICENSE_UNAVAILABLE = APIError(
    409,
    "license_unavailable",
    "License unavailable",
    "The license is not currently usable.",
)
RATE_LIMITED = APIError(429, "rate_limited", "Too many requests", "Wait before trying again.")
INTERNAL = APIError(500, "internal_error", "Internal server error", "The request could not be completed.")


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "request-id-unavailable")


def _problem(request: Request, error: APIError, headers: dict[str, str] | None = None) -> JSONResponse:
    response = JSONResponse(
        {
            "type": f"https://docs.denilicense.local/problems/{error.code}",
            "title": error.title,
            "status": error.status,
            "code": error.code,
            "detail": error.detail,
            "requestId": _request_id(request),
        },
        status_code=error.status,
        media_type="application/problem+json",
        headers=headers,
    )
    response.headers["Cache-Control"] = "no-store"
    if error.status == 401:
        response.headers.setdefault("WWW-Authenticate", "Bearer")
    return response


def _raise(error: APIError) -> NoReturn:
    raise APIError(error.status, error.code, error.title, error.detail)


def _new(error: APIError) -> APIError:
    return APIError(error.status, error.code, error.title, error.detail)


def _camel(name: str) -> str:
    head, *tail = name.split("_")
    return head + "".join(part.capitalize() for part in tail)


def _wire(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {_camel(key): _wire(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): _wire(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_wire(item) for item in value]
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, bytes):
        return b64url_encode(value)
    if isinstance(value, Enum):
        return value.value
    return value


def _json(value: Any, status: int = 200, *, public_max_age: int | None = None) -> JSONResponse:
    response = JSONResponse(_wire(value), status_code=status)
    response.headers["Cache-Control"] = (
        f"public, max-age={public_max_age}" if public_max_age is not None else "no-store"
    )
    return response


def _ui_resource(asset_path: str) -> Any:
    """Resolve a packaged UI resource without permitting path traversal."""

    components = asset_path.split("/")
    if (
        not asset_path
        or len(asset_path) > 2048
        or any(component in {"", ".", ".."} for component in components)
        or any(
            component.startswith(".") or len(component) > 255 or "\\" in component or "\x00" in component
            for component in components
        )
    ):
        _raise(NOT_FOUND)
    candidate = resources.files("denilicense").joinpath("ui", *components)
    if not candidate.is_file():
        _raise(NOT_FOUND)
    return candidate


def _ui_response(request: Request, asset_path: str) -> Response:
    resource = _ui_resource(asset_path)
    content = resource.read_bytes()
    media_type = mimetypes.guess_type(asset_path)[0] or "application/octet-stream"
    if media_type == "text/html":
        ui_root = resources.files("denilicense").joinpath("ui")
        html = content.decode("utf-8")
        for asset_name in ("app.css", "app.js"):
            asset_digest = hashlib.sha256(ui_root.joinpath(asset_name).read_bytes()).hexdigest()
            html = html.replace(
                f"/ui/{asset_name}",
                f"/ui/{asset_name}?v={asset_digest[:16]}",
            )
        content = html.encode("utf-8")
        return Response(content, media_type=media_type, headers={"Cache-Control": "no-store"})

    digest = hashlib.sha256(content).hexdigest()
    etag = f'"{digest}"'
    version_matches = request.query_params.get("v") == digest[:16]
    cache_control = (
        "public, max-age=31536000, immutable"
        if HASHED_ASSET.search(resource.name) or version_matches
        else "public, max-age=0, must-revalidate"
    )
    headers = {"Cache-Control": cache_control, "ETag": etag}
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers=headers)
    return Response(content, media_type=media_type, headers=headers)


def _entitlement_guide() -> str:
    candidates = (
        Path(__file__).resolve().parents[2] / "docs" / "ENTITLEMENTS.md",
        Path(sysconfig.get_path("data")) / "share" / "denilicense" / "docs" / "ENTITLEMENTS.md",
    )
    for candidate in candidates:
        try:
            if candidate.is_file() and candidate.stat().st_size <= 256 * 1024:
                return candidate.read_text(encoding="utf-8")
        except OSError:
            continue
    _raise(NOT_FOUND)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        _raise(INVALID)
    return value.astimezone(UTC)


def _uuid(value: str, *, canonical: bool = False) -> UUID:
    try:
        result = UUID(value)
    except ValueError, TypeError, AttributeError:
        _raise(INVALID)
    if canonical and str(result) != value:
        _raise(INVALID)
    return result


def _json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    seen: set[str] = set()
    for key, value in pairs:
        folded = key.casefold()
        if folded in seen:
            raise ValueError("duplicate JSON key")
        seen.add(folded)
        result[key] = value
    return result


def _depth(value: Any, level: int = 0) -> None:
    if level > 32:
        raise ValueError("JSON nesting limit exceeded")
    if isinstance(value, dict):
        for item in value.values():
            _depth(item, level + 1)
    elif isinstance(value, list):
        for item in value:
            _depth(item, level + 1)


class StrictJSONRoute(APIRoute):
    def get_route_handler(self) -> Callable[[Request], Any]:
        handler = super().get_route_handler()
        requires_body = self.body_field is not None

        async def strict_handler(request: Request) -> Any:
            if requires_body and request.method in {"POST", "PUT", "PATCH"}:
                content_type = request.headers.get("content-type", "").split(";", 1)[0]
                if content_type.strip().lower() != "application/json":
                    _raise(INVALID)
                body = await request.body()
                if not body or len(body) > MAX_JSON_BODY:
                    _raise(INVALID)
                try:
                    value = json.loads(body, object_pairs_hook=_json_pairs)
                    if not isinstance(value, dict):
                        raise ValueError("top-level JSON value must be an object")
                    _depth(value)
                except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
                    raise _new(INVALID) from exc
            return await handler(request)

        return strict_handler


class OriginGuardMiddleware:
    def __init__(self, app: ASGIApp, origins: Sequence[str]) -> None:
        self.app = app
        self.origins = frozenset(origins)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        raw_origin = headers.get(b"origin")
        origin = raw_origin.decode("latin-1") if raw_origin else ""
        if origin and origin not in self.origins:
            request = Request(scope, receive=receive)
            await _problem(request, FORBIDDEN)(scope, receive, send)
            return
        if scope["method"] == "OPTIONS":
            response = Response(status_code=204)
            if origin:
                self._headers(response.headers, origin)
            await response(scope, receive, send)
            return

        async def wrapped_send(message: Message) -> None:
            if origin and message["type"] == "http.response.start":
                response_headers = list(message.get("headers", []))
                response_headers.extend(
                    [
                        (b"access-control-allow-origin", origin.encode("latin-1")),
                        (b"vary", b"Origin"),
                        (
                            b"access-control-allow-headers",
                            b"Authorization, Content-Type, Idempotency-Key",
                        ),
                        (b"access-control-allow-methods", b"GET, POST, DELETE, OPTIONS"),
                        (b"access-control-max-age", b"600"),
                    ]
                )
                message["headers"] = response_headers
            await send(message)

        await self.app(scope, receive, wrapped_send)

    @staticmethod
    def _headers(headers: Any, origin: str) -> None:
        headers["Access-Control-Allow-Origin"] = origin
        headers["Vary"] = "Origin"
        headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, Idempotency-Key"
        headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
        headers["Access-Control-Max-Age"] = "600"


def _audit(request: Request, action: str, target_type: str) -> AuditEvent:
    principal: Principal = request.state.principal
    return AuditEvent(
        action=action,
        target_type=target_type,
        actor_user_id=principal.user.id,
        request_id=_request_id(request),
    )


def _map_error(error: Exception) -> APIError:
    if isinstance(error, (InvalidError, DeniLicenseError, auth.AuthenticationError)):
        return INVALID
    if isinstance(error, UnauthorizedError):
        return UNAUTHENTICATED
    if isinstance(error, NotFoundError):
        return NOT_FOUND
    if isinstance(error, ConflictError):
        return CONFLICT
    if isinstance(error, RefreshReuseError):
        return REFRESH_REUSE
    if isinstance(error, SeatLimitError):
        return SEAT_LIMIT
    if isinstance(error, LicenseStateError):
        return LICENSE_UNAVAILABLE
    return INTERNAL


def create_app(
    settings: Settings,
    store: Store,
    password_manager: auth.PasswordManager,
    activation_signer: SigningKey | None = None,
    activation_verification_keys: Sequence[VerificationKey] = (),
) -> FastAPI:
    """Build the complete HTTP application around explicit dependencies."""

    if activation_signer is not None and activation_signer.purpose != ACTIVATION_RECEIPT_SIGNER:
        raise ValueError("activation signer has the wrong purpose")
    if len(activation_verification_keys) > 32:
        raise ValueError("too many retained activation verification keys")

    email = EmailSender(settings.email_webhook_url, settings.email_webhook_bearer, settings.public_app_url)
    resolver = ClientSourceResolver(settings.trusted_proxy_cidrs, settings.device_pepper)
    login_limiter = RateLimiter(10, 60, resolver)
    auth_token_limiter = RateLimiter(20, 60, resolver)
    email_action_limiter = RateLimiter(5, 3600, resolver)
    password_change_limiter = RateLimiter(5, 60, resolver)
    registration_limiter = RateLimiter(5, 3600, resolver)
    claim_limiter = RateLimiter(10, 3600, resolver)
    license_request_limiter = RateLimiter(10, 3600, resolver)
    invitation_limiter = RateLimiter(20, 3600, resolver)
    renewal_limiter = RateLimiter(120, 60, resolver)
    dummy_password = password_manager.hash("dummy password used for timing only")

    jwks: list[JWK] = []
    seen: set[str] = set()
    if activation_signer is not None:
        current = JWK.from_public_key(activation_signer.public_bytes)
        jwks.append(current)
        seen.add(current.key_id)
    for retained in activation_verification_keys:
        if retained.purpose != ACTIVATION_RECEIPT_SIGNER:
            raise ValueError("retained activation key has the wrong purpose")
        jwk = JWK.from_public_key(retained.public_bytes)
        if jwk.key_id not in seen:
            jwks.append(jwk)
            seen.add(jwk.key_id)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        email.close(settings.shutdown_timeout.total_seconds())

    app = FastAPI(
        title="DeniLicense API",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
        lifespan=lifespan,
    )
    app.router.route_class = StrictJSONRoute
    app.state.store = store
    app.state.email = email
    app.state.activation_signer = activation_signer
    app.state.activation_jwks = JWKS(tuple(jwks))
    bearer_scheme = HTTPBearer(
        auto_error=False,
        scheme_name="BearerAuth",
        description="Opaque DeniLicense access token returned by the login or refresh endpoint.",
    )

    app.add_middleware(OriginGuardMiddleware, origins=settings.allowed_origins)
    app.add_middleware(RequestMiddleware, resolver=resolver, production=settings.environment == "production")

    @app.exception_handler(APIError)
    async def api_error_handler(request: Request, error: APIError) -> JSONResponse:
        return _problem(request, error)

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, _: RequestValidationError) -> JSONResponse:
        return _problem(request, INVALID)

    @app.exception_handler(HTTPException)
    async def http_error_handler(request: Request, error: HTTPException) -> JSONResponse:
        if error.status_code == 404:
            mapped = NOT_FOUND
        elif error.status_code == 405:
            mapped = METHOD_NOT_ALLOWED
        elif error.status_code == 429:
            mapped = RATE_LIMITED
        else:
            mapped = APIError(error.status_code, "http_error", "Request failed", "The request failed.")
        return _problem(request, mapped, dict(error.headers or {}))

    # Register expected domain outcomes below Exception so Starlette's outer
    # server-error middleware does not re-raise them after sending a response,
    # which would otherwise tear down a healthy keep-alive connection.
    @app.exception_handler(StoreError)
    @app.exception_handler(DeniLicenseError)
    @app.exception_handler(auth.AuthenticationError)
    async def expected_error_handler(request: Request, error: Exception) -> JSONResponse:
        return _problem(request, _map_error(error))

    @app.exception_handler(Exception)
    async def unexpected_handler(request: Request, _: Exception) -> JSONResponse:
        logger.exception("request failed", extra={"request_id": _request_id(request)})
        return _problem(request, INTERNAL)

    def principal(
        request: Request,
        credentials: Annotated[
            HTTPAuthorizationCredentials | None,
            Depends(bearer_scheme),
        ],
    ) -> Principal:
        if credentials is None or credentials.scheme.lower() != "bearer":
            _raise(UNAUTHENTICATED)
        token = credentials.credentials.strip()
        if not token:
            _raise(UNAUTHENTICATED)
        try:
            digest = auth.hash_token(settings.token_pepper, auth.ACCESS_TOKEN, token)
            value = store.principal_by_access_hash(digest, datetime.now(UTC))
        except (auth.AuthenticationError, UnauthorizedError, NotFoundError) as exc:
            raise _new(UNAUTHENTICATED) from exc
        request.state.principal = value
        return value

    def verified(value: Annotated[Principal, Depends(principal)]) -> Principal:
        if value.user.email_verified_at is None:
            _raise(UNVERIFIED)
        return value

    def roles(*allowed: Role) -> Callable[[Principal], Principal]:
        def dependency(value: Annotated[Principal, Depends(verified)]) -> Principal:
            if value.user.role not in allowed:
                _raise(FORBIDDEN)
            return value

        return dependency

    PrincipalDependency = Annotated[Principal, Depends(principal)]
    VerifiedDependency = Annotated[Principal, Depends(verified)]
    OwnerDependency = Annotated[Principal, Depends(roles(Role.PLATFORM_OWNER))]
    LicenseWriterDependency = Annotated[Principal, Depends(roles(Role.PLATFORM_OWNER, Role.LICENSE_ADMIN))]
    ManagementReaderDependency = Annotated[
        Principal,
        Depends(roles(Role.PLATFORM_OWNER, Role.LICENSE_ADMIN, Role.SUPPORT, Role.AUDITOR)),
    ]
    ActivationManagerDependency = Annotated[
        Principal, Depends(roles(Role.PLATFORM_OWNER, Role.LICENSE_ADMIN, Role.SUPPORT))
    ]
    AuditReaderDependency = Annotated[Principal, Depends(roles(Role.PLATFORM_OWNER, Role.AUDITOR))]
    CustomerDependency = Annotated[Principal, Depends(roles(Role.CUSTOMER))]

    def limit(request: Request, fallback: int = 100) -> int:
        raw = request.query_params.get("limit", "").strip()
        if not raw:
            return fallback
        try:
            value = int(raw)
        except ValueError as exc:
            raise _new(INVALID) from exc
        if not 1 <= value <= 200:
            _raise(INVALID)
        return value

    def signed_lease(licensed: Any, activation: Any, public_key: bytes, now: datetime) -> str:
        if activation_signer is None or not settings.activation_issuer:
            raise RuntimeError("activation signing is not configured")
        return sign_lease(
            LeaseClaims(
                issuer=settings.activation_issuer,
                key_id=activation_signer.key_id,
                jwt_id=new_jwt_id(),
                license_id=str(licensed.id),
                activation_id=str(activation.id),
                audience=licensed.product_code,
                license_revision=licensed.revision,
                device_key_thumbprint=device_key_thumbprint(public_key),
                entitlements=licensed.entitlements,
                issued_at=now.astimezone(UTC),
                not_before=now.astimezone(UTC),
                expires_at=activation.lease_expires_at.astimezone(UTC),
            ),
            activation_signer,
        )

    @app.get("/", include_in_schema=False)
    def ui_root() -> RedirectResponse:
        return RedirectResponse("/ui/", status_code=307, headers={"Cache-Control": "no-store"})

    @app.get("/ui", include_in_schema=False)
    def ui_redirect() -> RedirectResponse:
        return RedirectResponse("/ui/", status_code=307, headers={"Cache-Control": "no-store"})

    @app.get("/reset-password", include_in_schema=False)
    def password_setup_redirect(request: Request) -> RedirectResponse:
        token = request.query_params.get("token", "")
        query = {"action": "reset-password"}
        if 1 <= len(token) <= 128 and not any(
            ord(character) < 32 or ord(character) == 127 for character in token
        ):
            query["token"] = token
        return RedirectResponse(
            "/ui/?" + urlencode(query),
            status_code=307,
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/verify-email", include_in_schema=False)
    def email_verification_redirect(request: Request) -> RedirectResponse:
        token = request.query_params.get("token", "")
        query = {"action": "verify-email"}
        if 1 <= len(token) <= 128 and not any(
            ord(character) < 32 or ord(character) == 127 for character in token
        ):
            query["token"] = token
        return RedirectResponse(
            "/ui/?" + urlencode(query),
            status_code=307,
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/ui/", include_in_schema=False)
    def ui_index(request: Request) -> Response:
        return _ui_response(request, "index.html")

    @app.get("/ui/{asset_path:path}", include_in_schema=False)
    def ui_asset(asset_path: str, request: Request) -> Response:
        return _ui_response(request, asset_path)

    @app.get("/live")
    def live() -> JSONResponse:
        return _json({"status": "ok"})

    @app.get("/ready")
    def ready() -> JSONResponse:
        try:
            store.ping()
        except Exception as exc:
            raise RuntimeError("database unavailable") from exc
        return _json({"status": "ready"})

    @app.get("/openapi.yaml", include_in_schema=False)
    def openapi_yaml() -> PlainTextResponse:
        return PlainTextResponse(
            yaml.safe_dump(app.openapi(), sort_keys=False),
            media_type="application/yaml",
            headers={"Cache-Control": "public, max-age=300"},
        )

    @app.get("/docs/entitlements", include_in_schema=False)
    def entitlement_guide() -> PlainTextResponse:
        return PlainTextResponse(
            _entitlement_guide(),
            media_type="text/markdown",
            headers={"Cache-Control": "public, max-age=300"},
        )

    @app.get("/.well-known/denilicense-activation-keys.json")
    def activation_keys() -> JSONResponse:
        return _json(app.state.activation_jwks.to_dict(), public_max_age=300)

    @app.get("/api/v1/products")
    def public_products() -> JSONResponse:
        return _json({"items": store.list_products(False)})

    @app.get("/api/v1/public/config")
    def public_config() -> JSONResponse:
        return _json(
            {
                "registrationOpen": settings.registration_mode == "open",
                "passwordMinCharacters": auth.PASSWORD_MIN_CHARS,
            },
            public_max_age=60,
        )

    @app.post("/api/v1/auth/register", status_code=202)
    def register(body: RegisterRequest, request: Request) -> JSONResponse:
        registration_limiter.enforce(request)
        if settings.registration_mode != "open":
            _raise(FORBIDDEN)
        try:
            email_address, normalized = auth.normalize_email(body.email)
            token = auth.new_token(auth.EMAIL_VERIFICATION_TOKEN)
            token_hash = auth.hash_token(settings.token_pepper, auth.EMAIL_VERIFICATION_TOKEN, token)
        except auth.AuthenticationError as exc:
            raise _new(INVALID) from exc
        recipient, pending = ("", False)
        try:
            recipient, pending = store.register_pending_user(
                RegisterPendingUserParams(
                    id=uuid4(),
                    email=email_address,
                    normalized_email=normalized,
                    verification_token_id=uuid4(),
                    verification_token_hash=token_hash,
                    verification_token_expiry=datetime.now(UTC) + settings.verification_ttl,
                )
            )
        except ConflictError:
            pending = False
        if pending:
            email.enqueue(EmailJob("verification", recipient, token, _request_id(request)))
        response: dict[str, Any] = {"accepted": True, "verificationRequired": True}
        if pending and settings.expose_dev_tokens:
            response["developmentVerificationToken"] = token
        return _json(response, 202)

    @app.post("/api/v1/auth/verification/request", status_code=202)
    def request_verification(body: EmailRequest, request: Request) -> JSONResponse:
        email_action_limiter.enforce(request)
        try:
            _, normalized = auth.normalize_email(body.email)
        except auth.AuthenticationError:
            normalized = ""
        token = auth.new_token(auth.EMAIL_VERIFICATION_TOKEN)
        token_hash = auth.hash_token(settings.token_pepper, auth.EMAIL_VERIFICATION_TOKEN, token)
        recipient, created = ("", False)
        if normalized:
            recipient, created = store.replace_email_verification_token(
                normalized, uuid4(), token_hash, datetime.now(UTC) + settings.verification_ttl
            )
        if created:
            email.enqueue(EmailJob("verification", recipient, token, _request_id(request)))
        response: dict[str, Any] = {"accepted": True}
        if created and settings.expose_dev_tokens:
            response["developmentVerificationToken"] = token
        return _json(response, 202)

    @app.post("/api/v1/auth/verify-email")
    def verify_email(body: VerifyEmailRequest, request: Request) -> JSONResponse:
        auth_token_limiter.enforce(request)
        try:
            token_hash = auth.hash_token(settings.token_pepper, auth.EMAIL_VERIFICATION_TOKEN, body.token)
            password_hash = password_manager.hash(body.new_password)
            user = store.verify_email(token_hash, password_hash, datetime.now(UTC))
        except (auth.AuthenticationError, NotFoundError, InvalidError) as exc:
            raise _new(INVALID) from exc
        return _json({"user": user})

    def new_session(user: Any) -> dict[str, Any]:
        now = datetime.now(UTC)
        access_token = auth.new_token(auth.ACCESS_TOKEN)
        refresh_token = auth.new_token(auth.REFRESH_TOKEN)
        access_expiry = now + settings.access_token_ttl
        refresh_expiry = now + settings.refresh_token_ttl
        store.create_session(
            CreateSessionParams(
                session_id=uuid4(),
                family_id=uuid4(),
                user_id=user.id,
                access_hash=auth.hash_token(settings.token_pepper, auth.ACCESS_TOKEN, access_token),
                access_expires_at=access_expiry,
                refresh_token_id=uuid4(),
                refresh_hash=auth.hash_token(settings.token_pepper, auth.REFRESH_TOKEN, refresh_token),
                refresh_expires_at=refresh_expiry,
            )
        )
        return {
            "accessToken": access_token,
            "accessExpiresAt": access_expiry,
            "refreshToken": refresh_token,
            "refreshExpiresAt": refresh_expiry,
            "user": user,
        }

    @app.post("/api/v1/auth/login")
    def login(body: LoginRequest, request: Request) -> JSONResponse:
        login_limiter.enforce(request)
        try:
            _, normalized = auth.normalize_email(body.email)
        except auth.AuthenticationError as exc:
            password_manager.verify(dummy_password, body.password)
            raise _new(UNAUTHENTICATED) from exc
        try:
            credential = store.user_credential_by_email(normalized)
            encoded = (
                credential.password_hash
                if credential.user.email_verified_at is not None
                and not credential.user.password_setup_required
                else dummy_password
            )
        except NotFoundError:
            credential = None
            encoded = dummy_password
        valid = password_manager.verify(encoded, body.password)
        if (
            credential is None
            or not valid
            or credential.user.status != "active"
            or credential.user.email_verified_at is None
            or credential.user.password_setup_required
        ):
            _raise(UNAUTHENTICATED)
        return _json(new_session(credential.user))

    @app.post("/api/v1/auth/refresh")
    def refresh(body: RefreshRequest, request: Request) -> JSONResponse:
        auth_token_limiter.enforce(request)
        try:
            old_hash = auth.hash_token(settings.token_pepper, auth.REFRESH_TOKEN, body.refresh_token)
        except auth.AuthenticationError as exc:
            raise _new(UNAUTHENTICATED) from exc
        access_token = auth.new_token(auth.ACCESS_TOKEN)
        refresh_token = auth.new_token(auth.REFRESH_TOKEN)
        now = datetime.now(UTC)
        try:
            rotated = store.rotate_session(
                RotateSessionParams(
                    old_refresh_hash=old_hash,
                    new_refresh_id=uuid4(),
                    new_refresh_hash=auth.hash_token(
                        settings.token_pepper, auth.REFRESH_TOKEN, refresh_token
                    ),
                    new_access_hash=auth.hash_token(settings.token_pepper, auth.ACCESS_TOKEN, access_token),
                    access_expires_at=now + settings.access_token_ttl,
                    refresh_expires_at=now + settings.refresh_token_ttl,
                    now=now,
                )
            )
        except RefreshReuseError as exc:
            logger.warning("refresh token reuse", extra={"request_id": _request_id(request)})
            raise _new(REFRESH_REUSE) from exc
        except UnauthorizedError as exc:
            raise _new(UNAUTHENTICATED) from exc
        return _json(
            {
                "accessToken": access_token,
                "accessExpiresAt": rotated.access_expires_at,
                "refreshToken": refresh_token,
                "refreshExpiresAt": rotated.refresh_expires_at,
            }
        )

    @app.post("/api/v1/auth/password-reset/request", status_code=202)
    def request_password_reset(body: EmailRequest, request: Request) -> JSONResponse:
        email_action_limiter.enforce(request)
        try:
            _, normalized = auth.normalize_email(body.email)
        except auth.AuthenticationError:
            normalized = ""
        token = auth.new_token(auth.PASSWORD_RESET_TOKEN)
        token_hash = auth.hash_token(settings.token_pepper, auth.PASSWORD_RESET_TOKEN, token)
        recipient, created = ("", False)
        if normalized:
            recipient, created = store.replace_password_reset_token(
                normalized, uuid4(), token_hash, datetime.now(UTC) + settings.password_reset_ttl
            )
        if created:
            email.enqueue(EmailJob("password_reset", recipient, token, _request_id(request)))
        response: dict[str, Any] = {"accepted": True}
        if created and settings.expose_dev_tokens:
            response["developmentPasswordResetToken"] = token
        return _json(response, 202)

    @app.post("/api/v1/auth/password-reset/confirm", status_code=204)
    def confirm_password_reset(body: PasswordResetConfirmRequest, request: Request) -> Response:
        auth_token_limiter.enforce(request)
        try:
            token_hash = auth.hash_token(settings.token_pepper, auth.PASSWORD_RESET_TOKEN, body.token)
            encoded = password_manager.hash(body.new_password)
            store.consume_password_reset_token(token_hash, encoded, datetime.now(UTC))
        except (auth.AuthenticationError, NotFoundError, InvalidError) as exc:
            raise _new(INVALID) from exc
        return Response(status_code=204)

    @app.post("/api/v1/auth/logout", status_code=204)
    def logout(request: Request, value: PrincipalDependency) -> Response:
        store.revoke_session(value.session_id, datetime.now(UTC))
        return Response(status_code=204)

    @app.get("/api/v1/auth/me")
    def me(value: PrincipalDependency) -> JSONResponse:
        return _json({"user": value.user})

    @app.post("/api/v1/auth/password/change", status_code=204)
    def change_password(
        body: ChangePasswordRequest,
        request: Request,
        value: VerifiedDependency,
    ) -> Response:
        password_change_limiter.enforce(request)
        credential = store.user_credential_by_id(value.user.id)
        if not password_manager.verify(credential.password_hash, body.current_password):
            _raise(INVALID)
        if body.current_password == body.new_password:
            _raise(INVALID)
        try:
            new_password_hash = password_manager.hash(body.new_password)
        except auth.AuthenticationError as exc:
            raise _new(INVALID) from exc
        store.change_password(
            value.user.id,
            value.session_id,
            credential.password_hash,
            new_password_hash,
            datetime.now(UTC),
            _audit(request, "user.password_change", "user"),
        )
        return Response(status_code=204)

    @app.get("/api/v1/auth/sessions")
    def list_sessions(value: VerifiedDependency) -> JSONResponse:
        items = []
        for session in store.list_account_sessions(value.user.id, datetime.now(UTC)):
            item = _wire(session)
            item["isCurrent"] = session.id == value.session_id
            items.append(item)
        return _json({"items": items})

    @app.post("/api/v1/auth/sessions/revoke-others", status_code=204)
    def revoke_other_sessions(request: Request, value: VerifiedDependency) -> Response:
        store.revoke_other_user_sessions(
            value.user.id,
            value.session_id,
            datetime.now(UTC),
            _audit(request, "session.revoke_others", "user"),
        )
        return Response(status_code=204)

    @app.delete("/api/v1/auth/sessions/{session_id}", status_code=204)
    def revoke_account_session(
        session_id: str,
        request: Request,
        value: VerifiedDependency,
    ) -> Response:
        store.revoke_user_session(
            value.user.id,
            _uuid(session_id, canonical=True),
            datetime.now(UTC),
            _audit(request, "session.revoke", "session"),
        )
        return Response(status_code=204)

    @app.post("/api/v1/licenses/claim")
    def claim_license(
        body: ClaimLicenseRequest,
        request: Request,
        value: VerifiedDependency,
    ) -> JSONResponse:
        claim_limiter.enforce(request)
        try:
            digest = claim_code_digest(body.claim_code)
            licensed = store.claim_license(
                digest,
                value.user.id,
                datetime.now(UTC),
                _audit(request, "license.claim", "license"),
            )
        except (DeniLicenseError, InvalidError, NotFoundError, ConflictError) as exc:
            # Formatting, lookup, ownership, and state intentionally share one response.
            raise _new(INVALID) from exc
        return _json({"license": licensed})

    @app.post("/api/v1/license-requests", status_code=201)
    def create_customer_license_request(
        body: CreateCustomerLicenseRequest,
        request: Request,
        value: CustomerDependency,
    ) -> JSONResponse:
        license_request_limiter.enforce(request)
        product_code = body.product_code.strip().upper()
        if not PRODUCT_CODE.fullmatch(product_code):
            _raise(INVALID)
        try:
            product = store.product_by_code(product_code)
        except NotFoundError as exc:
            raise _new(NOT_FOUND) from exc
        item = store.create_license_request(
            CreateLicenseRequestParams(
                id=uuid4(),
                requester_user_id=value.user.id,
                product_id=product.id,
                requested_activations=body.requested_activations,
                message=body.message,
                audit=_audit(request, "license_request.create", "license_request"),
            )
        )
        return _json({"request": item}, 201)

    @app.get("/api/v1/license-requests")
    def list_customer_license_requests(
        request: Request,
        value: CustomerDependency,
    ) -> JSONResponse:
        status = request.query_params.get("status", "").strip()
        if status and status not in {"pending", "approved", "denied", "cancelled", "fulfilled"}:
            _raise(INVALID)
        return _json({"items": store.list_user_license_requests(value.user.id, status, limit(request))})

    @app.get("/api/v1/license-requests/{request_id}")
    def get_customer_license_request(
        request_id: str,
        value: CustomerDependency,
    ) -> JSONResponse:
        return _json({"request": store.license_request_for_user(_uuid(request_id), value.user.id)})

    @app.post("/api/v1/license-requests/{request_id}/cancel")
    def cancel_customer_license_request(
        request_id: str,
        request: Request,
        value: CustomerDependency,
    ) -> JSONResponse:
        item = store.cancel_license_request(
            _uuid(request_id),
            value.user.id,
            datetime.now(UTC),
            _audit(request, "license_request.cancel", "license_request"),
        )
        return _json({"request": item})

    @app.get("/api/v1/licenses")
    def list_customer_licenses(value: VerifiedDependency) -> JSONResponse:
        return _json({"items": store.list_user_licenses(value.user.id)})

    @app.get("/api/v1/licenses/{license_id}")
    def get_customer_license(license_id: str, value: VerifiedDependency) -> JSONResponse:
        try:
            item = store.license_for_owner(_uuid(license_id), value.user.id)
        except (InvalidError, NotFoundError, ValueError) as exc:
            raise _new(NOT_FOUND) from exc
        return _json({"license": item})

    @app.get("/api/v1/licenses/{license_id}/activations")
    def list_customer_activations(license_id: str, value: VerifiedDependency) -> JSONResponse:
        try:
            items = store.list_activations_for_owner(_uuid(license_id), value.user.id)
        except (InvalidError, NotFoundError, ValueError) as exc:
            raise _new(NOT_FOUND) from exc
        return _json({"items": items})

    @app.post("/api/v1/licenses/{license_id}/activations")
    def activate(
        license_id: str,
        body: ActivationRequest,
        request: Request,
        value: VerifiedDependency,
    ) -> JSONResponse:
        try:
            public_key = b64url_decode(body.device_public_key, size=32)
            validate_ed25519_public_key(public_key)
            now = datetime.now(UTC)
            licensed, activation, idempotent = store.activate(
                ActivateParams(
                    id=uuid4(),
                    license_id=_uuid(license_id),
                    owner_user_id=value.user.id,
                    device_public_key=public_key,
                    label=body.label.strip(),
                    now=now,
                    lease_expires_at=now + settings.activation_lease_ttl,
                    audit=_audit(request, "activation.create", "activation"),
                )
            )
            lease = signed_lease(licensed, activation, public_key, activation.last_seen_at)
        except (DeniLicenseError, InvalidError, ValueError) as exc:
            raise _new(INVALID) from exc
        return _json(
            {
                "activation": activation,
                "license": licensed,
                "lease": lease,
                "idempotent": idempotent,
            },
            200 if idempotent else 201,
        )

    @app.delete("/api/v1/activations/{activation_id}", status_code=204)
    def deactivate_customer_activation(
        activation_id: str,
        request: Request,
        value: VerifiedDependency,
    ) -> Response:
        try:
            store.deactivate(
                _uuid(activation_id),
                value.user.id,
                datetime.now(UTC),
                _audit(request, "activation.deactivate", "activation"),
            )
        except ValueError as exc:
            raise _new(NOT_FOUND) from exc
        return Response(status_code=204)

    @app.post("/api/v1/activation-challenges", status_code=201)
    def create_renewal_challenge(body: RenewalChallengeRequest, request: Request) -> JSONResponse:
        renewal_limiter.enforce(request)
        try:
            activation_id = _uuid(body.activation_id)
        except APIError as exc:
            raise _new(INVALID) from exc
        nonce = secrets.token_bytes(32)
        nonce_text = b64url_encode(nonce)
        nonce_hash = hmac.new(
            settings.device_pepper,
            b"DeniLicense/activation-renewal-nonce/v1\x00" + nonce,
            hashlib.sha256,
        ).digest()
        challenge_id = uuid4()
        now = datetime.now(UTC)
        expires_at = now + RENEWAL_CHALLENGE_TTL
        try:
            store.create_renewal_challenge(challenge_id, activation_id, nonce_hash, expires_at, now)
        except (InvalidError, NotFoundError, ConflictError) as exc:
            raise _new(INVALID) from exc
        transcript = (
            b"DeniLicense\x00activation-renewal\x00v1\x00"
            + str(challenge_id).encode()
            + b"\x00"
            + str(activation_id).encode()
            + b"\x00"
            + nonce_text.encode()
        )
        return _json(
            {
                "challengeId": challenge_id,
                "activationId": activation_id,
                "nonce": nonce_text,
                "expiresAt": expires_at,
                "algorithm": "Ed25519",
                "transcript": b64url_encode(transcript),
            },
            201,
        )

    @app.post("/api/v1/activation-challenges/complete")
    def complete_renewal_challenge(body: CompleteRenewalRequest, request: Request) -> JSONResponse:
        renewal_limiter.enforce(request)
        try:
            challenge_id = _uuid(body.challenge_id)
            nonce = b64url_decode(body.nonce, size=32)
            b64url_decode(body.signature, size=64)
            challenge = store.renewal_challenge(challenge_id)
            now = datetime.now(UTC)
            supplied_hash = hmac.new(
                settings.device_pepper,
                b"DeniLicense/activation-renewal-nonce/v1\x00" + nonce,
                hashlib.sha256,
            ).digest()
            if (
                challenge.consumed_at is not None
                or challenge.expires_at <= now
                or not hmac.compare_digest(challenge.nonce_hash, supplied_hash)
            ):
                _raise(INVALID)
            crypto_challenge = CryptoRenewalChallenge(
                challenge_id=str(challenge.id),
                activation_id=str(challenge.activation_id),
                nonce=body.nonce,
                algorithm="Ed25519",
                transcript=b64url_encode(
                    b"DeniLicense\x00activation-renewal\x00v1\x00"
                    + str(challenge.id).encode()
                    + b"\x00"
                    + str(challenge.activation_id).encode()
                    + b"\x00"
                    + body.nonce.encode()
                ),
            )
            verify_renewal_signature(challenge.device_public_key, crypto_challenge, body.signature)
            licensed, activation = store.consume_renewal_challenge(
                challenge_id,
                supplied_hash,
                now,
                settings.activation_lease_ttl,
                AuditEvent(
                    action="activation.renew",
                    target_type="activation",
                    actor_kind="device",
                    request_id=_request_id(request),
                ),
            )
            lease = signed_lease(licensed, activation, challenge.device_public_key, activation.last_seen_at)
        except (DeniLicenseError, InvalidError, NotFoundError, ConflictError, APIError) as exc:
            raise _new(INVALID) from exc
        return _json({"activation": activation, "lease": lease})

    @app.post("/api/v1/admin/products", status_code=201)
    def create_product(
        body: CreateProductRequest,
        request: Request,
        value: LicenseWriterDependency,
    ) -> JSONResponse:
        code = body.code.strip().upper()
        name = body.name.strip()
        description = body.description.strip()
        if not PRODUCT_CODE.fullmatch(code) or not name:
            _raise(INVALID)
        product = store.create_product(
            CreateProductParams(
                id=uuid4(),
                code=code,
                name=name,
                description=description,
                created_by=value.user.id,
                audit=_audit(request, "product.create", "product"),
            )
        )
        return _json({"product": product}, 201)

    @app.get("/api/v1/admin/dashboard")
    def admin_dashboard(_: ManagementReaderDependency) -> JSONResponse:
        return _json(
            {
                "summary": store.dashboard_summary(),
                "recentActivations": store.list_admin_activations(AdminActivationListFilter(limit=8)),
            }
        )

    @app.get("/api/v1/admin/products")
    def list_admin_products(request: Request, _: ManagementReaderDependency) -> JSONResponse:
        raw = request.query_params.get("includeRetired", "false").strip().lower()
        if raw not in {"true", "false"}:
            _raise(INVALID)
        return _json({"items": store.list_products(raw == "true")})

    @app.post("/api/v1/admin/products/{product_code}/status")
    def set_product_status(
        product_code: str,
        body: ProductStatusRequest,
        request: Request,
        value: LicenseWriterDependency,
    ) -> JSONResponse:
        code = product_code.strip().upper()
        if not PRODUCT_CODE.fullmatch(code):
            _raise(INVALID)
        product = store.update_product_status(
            code,
            body.status,
            value.user.id,
            body.expected_revision,
            _audit(request, f"product.{body.status}", "product"),
        )
        return _json({"product": product})

    @app.get("/api/v1/admin/issuers")
    def list_admin_issuers(request: Request, _: ManagementReaderDependency) -> JSONResponse:
        status = request.query_params.get("status", "").strip()
        if status and status not in {"active", "retired", "revoked"}:
            _raise(INVALID)
        return _json({"items": store.list_issuers(status, limit(request))})

    @app.post("/api/v1/admin/issuers", status_code=201)
    def register_issuer(
        body: RegisterIssuerRequest,
        request: Request,
        value: OwnerDependency,
    ) -> JSONResponse:
        issuer = body.issuer.strip()
        if not ISSUER.fullmatch(issuer):
            _raise(INVALID)
        try:
            verification_key = parse_public_key(body.public_key_document.encode())
        except DeniLicenseError as exc:
            raise _new(INVALID) from exc
        if verification_key.purpose != OFFLINE_LICENSE_ISSUER:
            _raise(INVALID)
        not_before = _utc(body.not_before) if body.not_before else datetime.now(UTC)
        not_after = _utc(body.not_after) if body.not_after else None
        if not_after is not None and not_after <= not_before:
            _raise(INVALID)
        item = store.register_issuer(
            RegisterIssuerParams(
                key_id=verification_key.key_id,
                issuer=issuer,
                public_key=verification_key.public_bytes,
                fingerprint=hashlib.sha256(verification_key.public_bytes).digest(),
                not_before=not_before,
                not_after=not_after,
                created_by=value.user.id,
                audit=_audit(request, "issuer.register", "issuer_key"),
            )
        )
        return _json({"issuerKey": item}, 201)

    @app.post("/api/v1/admin/issuers/{key_id}/status", status_code=204)
    def set_issuer_status(
        key_id: str,
        body: IssuerStatusRequest,
        request: Request,
        value: OwnerDependency,
    ) -> Response:
        if len(key_id) != 43:
            _raise(INVALID)
        store.update_issuer_status(
            key_id,
            body.status,
            value.user.id,
            _audit(request, "issuer.status_change", "issuer_key"),
        )
        return Response(status_code=204)

    def derive_issuance(
        purpose: str,
        actor: UUID,
        idempotency_key: str,
        request_hash: bytes = b"",
    ) -> bytes:
        message = (
            f"DeniLicense/online-issuance/{purpose}/v1\x00".encode()
            + actor.bytes
            + b"\x00"
            + idempotency_key.encode()
        )
        if request_hash:
            message += b"\x00" + request_hash
        return hmac.new(settings.issuance_pepper, message, hashlib.sha256).digest()

    def derive_request_issuance(purpose: str, request_id: UUID, request_hash: bytes) -> bytes:
        message = (
            f"DeniLicense/license-request-issuance/{purpose}/v1\x00".encode()
            + request_id.bytes
            + b"\x00"
            + request_hash
        )
        return hmac.new(settings.issuance_pepper, message, hashlib.sha256).digest()

    @app.get("/api/v1/admin/license-requests")
    def list_admin_license_requests(
        request: Request,
        _: ManagementReaderDependency,
    ) -> JSONResponse:
        status = request.query_params.get("status", "").strip()
        product_code = request.query_params.get("productCode", "").strip().upper()
        requester_email = request.query_params.get("requesterEmail", "").strip()
        if status and status not in {"pending", "approved", "denied", "cancelled", "fulfilled"}:
            _raise(INVALID)
        if product_code and not PRODUCT_CODE.fullmatch(product_code):
            _raise(INVALID)
        normalized = ""
        if requester_email:
            try:
                _, normalized = auth.normalize_email(requester_email)
            except auth.AuthenticationError as exc:
                raise _new(INVALID) from exc
        return _json(
            {
                "items": store.list_license_requests(
                    LicenseRequestListFilter(
                        status=status,
                        requester_normalized_email=normalized,
                        product_code=product_code,
                        limit=limit(request),
                    )
                )
            }
        )

    @app.get("/api/v1/admin/license-requests/{request_id}")
    def get_admin_license_request(
        request_id: str,
        _: ManagementReaderDependency,
    ) -> JSONResponse:
        return _json({"request": store.license_request_by_id(_uuid(request_id))})

    @app.post("/api/v1/admin/license-requests/{request_id}/deny")
    def deny_admin_license_request(
        request_id: str,
        body: DenyLicenseRequest,
        request: Request,
        value: LicenseWriterDependency,
    ) -> JSONResponse:
        item = store.deny_license_request(
            _uuid(request_id),
            value.user.id,
            body.admin_notes,
            datetime.now(UTC),
            _audit(request, "license_request.deny", "license_request"),
        )
        return _json({"request": item})

    @app.post("/api/v1/admin/license-requests/{request_id}/approve")
    def approve_admin_license_request(
        request_id: str,
        body: ApproveLicenseRequest,
        request: Request,
        value: LicenseWriterDependency,
    ) -> JSONResponse:
        request_uuid = _uuid(request_id)
        requested = store.license_request_by_id(request_uuid)
        subject = body.subject.strip()
        grace = body.offline_grace_seconds or 86_400
        if not 3600 <= grace <= 30 * 86_400:
            _raise(INVALID)
        if body.perpetual == (body.expires_at is not None):
            _raise(INVALID)
        now = datetime.now(UTC)
        not_before = _utc(body.not_before) if body.not_before else now
        expires_at = _utc(body.expires_at) if body.expires_at else None
        if expires_at is not None and (expires_at <= not_before or expires_at - now > timedelta(days=3650)):
            _raise(INVALID)
        material = canonical_json(
            {
                "entitlements": body.entitlements,
                "expires_at": expires_at.isoformat() if expires_at else None,
                "max_activations": body.max_activations,
                "not_before": not_before.isoformat() if body.not_before else None,
                "offline_grace_seconds": grace,
                "perpetual": body.perpetual,
                "product_code": requested.product_code,
                "request_id": str(request_uuid),
                "subject": subject,
            }
        )
        request_hash = hashlib.sha256(material).digest()
        raw_serial = bytearray(derive_request_issuance("serial", request_uuid, request_hash)[:16])
        raw_serial[6] = (raw_serial[6] & 0x0F) | 0x40
        raw_serial[8] = (raw_serial[8] & 0x3F) | 0x80
        serial = UUID(bytes=bytes(raw_serial))
        claim = claim_code_from_entropy(
            derive_request_issuance("claim-code", request_uuid, request_hash)[:20]
        )
        approved_request, licensed, idempotent = store.approve_license_request(
            request_uuid,
            CreateLicenseParams(
                id=uuid4(),
                serial=serial,
                product_id=requested.product_id,
                source="online",
                issuer_key_id=None,
                import_artifact=None,
                import_artifact_hash=None,
                creation_request_hash=request_hash,
                claim_code_hash=claim.digest,
                claim_code_suffix=claim.suffix,
                subject=subject,
                issued_at=now,
                not_before=not_before,
                expires_at=expires_at,
                max_activations=body.max_activations,
                offline_grace_seconds=grace,
                entitlements=body.entitlements,
                metadata={"licenseRequestId": str(request_uuid)},
                created_by=value.user.id,
                audit=_audit(request, "license.create_from_request", "license"),
            ),
            "",
            now,
            _audit(request, "license_request.approve", "license_request"),
        )
        return _json(
            {"request": approved_request, "license": licensed, "idempotent": idempotent},
            200 if idempotent else 201,
        )

    @app.post("/api/v1/admin/licenses", status_code=201)
    def create_online_license(
        body: CreateLicenseRequest,
        request: Request,
        idempotency_key: Annotated[str, Header(alias="Idempotency-Key")],
        value: LicenseWriterDependency,
    ) -> JSONResponse:
        idempotency_key = idempotency_key.strip()
        if not IDEMPOTENCY_KEY.fullmatch(idempotency_key):
            _raise(INVALID)
        product_code = body.product_code.strip().upper()
        subject = body.subject.strip()
        if not PRODUCT_CODE.fullmatch(product_code):
            _raise(INVALID)
        grace = body.offline_grace_seconds or 86_400
        if not 3600 <= grace <= 30 * 86_400:
            _raise(INVALID)
        if body.perpetual == (body.expires_at is not None):
            _raise(INVALID)
        try:
            product = store.product_by_code(product_code)
        except NotFoundError as exc:
            raise _new(NOT_FOUND) from exc
        now = datetime.now(UTC)
        not_before = _utc(body.not_before) if body.not_before else now
        expires_at = _utc(body.expires_at) if body.expires_at else None
        if expires_at is not None and (expires_at <= not_before or expires_at - now > timedelta(days=3650)):
            _raise(INVALID)
        material = canonical_json(
            {
                "entitlements": body.entitlements,
                "expires_at": expires_at.isoformat() if expires_at else None,
                "max_activations": body.max_activations,
                "not_before": not_before.isoformat() if body.not_before else None,
                "offline_grace_seconds": grace,
                "perpetual": body.perpetual,
                "product_code": product_code,
                "subject": subject,
            }
        )
        request_hash = hashlib.sha256(material).digest()
        raw_serial = bytearray(derive_issuance("serial", value.user.id, idempotency_key)[:16])
        raw_serial[6] = (raw_serial[6] & 0x0F) | 0x40
        raw_serial[8] = (raw_serial[8] & 0x3F) | 0x80
        serial = UUID(bytes=bytes(raw_serial))
        claim = claim_code_from_entropy(
            derive_issuance("claim-code", value.user.id, idempotency_key, request_hash)[:20]
        )
        licensed, idempotent = store.create_license(
            CreateLicenseParams(
                id=uuid4(),
                serial=serial,
                product_id=product.id,
                source="online",
                issuer_key_id=None,
                import_artifact=None,
                import_artifact_hash=None,
                creation_request_hash=request_hash,
                claim_code_hash=claim.digest,
                claim_code_suffix=claim.suffix,
                subject=subject,
                issued_at=now,
                not_before=not_before,
                expires_at=expires_at,
                max_activations=body.max_activations,
                offline_grace_seconds=grace,
                entitlements=body.entitlements,
                metadata={},
                created_by=value.user.id,
                audit=_audit(request, "license.create_online", "license"),
            )
        )
        return _json(
            {
                "license": licensed,
                "claimCode": claim.display,
                "idempotent": idempotent,
                "warning": (
                    "Store this claim code securely; the server retains only its digest. "
                    "The same idempotency key and request can recover it."
                ),
            },
            200 if idempotent else 201,
        )

    @app.post("/api/v1/admin/licenses/import", status_code=201)
    def import_offline_license(
        body: ImportLicenseRequest,
        request: Request,
        value: LicenseWriterDependency,
    ) -> JSONResponse:
        artifact = body.artifact.strip()
        try:
            untrusted = inspect_unverified(artifact)
            issuer_key = store.issuer_by_key_id(untrusted.key_id)
            claims = verify_token(
                artifact,
                VerificationKey(OFFLINE_LICENSE_ISSUER, issuer_key.public_key),
            )
            if claims.issuer != issuer_key.issuer:
                _raise(INVALID)
            now = datetime.now(UTC)
            if (
                claims.issued_at < issuer_key.not_before
                or (issuer_key.not_after is not None and claims.issued_at >= issuer_key.not_after)
                or claims.issued_at > now + timedelta(minutes=10)
                or (claims.expires_at is not None and claims.expires_at <= now)
            ):
                _raise(INVALID)
            product = store.product_by_code(claims.audience)
            serial = _uuid(claims.serial, canonical=True)
            digest = b64url_decode(claims.claim_code_sha256, size=32)
            licensed, idempotent = store.create_license(
                CreateLicenseParams(
                    id=uuid4(),
                    serial=serial,
                    product_id=product.id,
                    source="offline_import",
                    issuer_key_id=issuer_key.key_id,
                    import_artifact=artifact,
                    import_artifact_hash=hashlib.sha256(artifact.encode()).digest(),
                    creation_request_hash=None,
                    claim_code_hash=digest,
                    claim_code_suffix=claims.claim_code_suffix,
                    subject=claims.subject,
                    issued_at=claims.issued_at,
                    not_before=claims.not_before,
                    expires_at=claims.expires_at,
                    max_activations=claims.max_activations,
                    offline_grace_seconds=86_400,
                    entitlements=claims.entitlements,
                    metadata={},
                    created_by=value.user.id,
                    audit=_audit(request, "license.import_offline", "license"),
                )
            )
        except ConflictError:
            logger.warning("offline import serial conflict", extra={"request_id": _request_id(request)})
            raise
        except (DeniLicenseError, InvalidError, NotFoundError, APIError, ValueError) as exc:
            raise _new(INVALID) from exc
        return _json(
            {"license": licensed, "idempotent": idempotent},
            200 if idempotent else 201,
        )

    @app.post("/api/v1/admin/licenses/{license_id}/state", status_code=204)
    def set_license_state(
        license_id: str,
        body: LicenseStateRequest,
        request: Request,
        value: LicenseWriterDependency,
    ) -> Response:
        store.set_license_state(
            _uuid(license_id),
            body.state,
            value.user.id,
            datetime.now(UTC),
            _audit(request, "license.state_change", "license"),
        )
        return Response(status_code=204)

    @app.post("/api/v1/admin/licenses/{license_id}/archive")
    def archive_admin_license(
        license_id: str,
        body: LifecycleRequest,
        request: Request,
        value: LicenseWriterDependency,
    ) -> JSONResponse:
        item = store.archive_license(
            _uuid(license_id),
            value.user.id,
            datetime.now(UTC),
            _audit(request, "license.archive", "license"),
            expected_revision=body.expected_revision,
        )
        return _json({"license": item})

    @app.post("/api/v1/admin/licenses/{license_id}/restore")
    def restore_admin_license(
        license_id: str,
        body: LifecycleRequest,
        request: Request,
        value: LicenseWriterDependency,
    ) -> JSONResponse:
        item = store.restore_license(
            _uuid(license_id),
            value.user.id,
            datetime.now(UTC),
            _audit(request, "license.restore", "license"),
            expected_revision=body.expected_revision,
        )
        return _json({"license": item})

    @app.post("/api/v1/admin/licenses/{license_id}/delete", status_code=204)
    def delete_admin_license(
        license_id: str,
        body: DeleteLicenseRequest,
        request: Request,
        value: OwnerDependency,
    ) -> Response:
        identifier = _uuid(license_id)
        current = store.license_by_id(identifier)
        if body.serial != str(current.serial):
            _raise(CONFLICT)
        store.delete_license(
            identifier,
            value.user.id,
            datetime.now(UTC),
            _audit(request, "license.delete", "license"),
            expected_revision=body.expected_revision,
        )
        return Response(status_code=204)

    @app.get("/api/v1/admin/licenses")
    def list_admin_licenses(
        request: Request,
        value: ManagementReaderDependency,
    ) -> JSONResponse:
        filters = LicenseListFilter(limit=limit(request))
        serial_text = request.query_params.get("serial", "").strip()
        owner_email = request.query_params.get("ownerEmail", "").strip()
        suffix = request.query_params.get("claimCodeSuffix", "").strip().upper()
        product_code = request.query_params.get("productCode", "").strip().upper()
        state = request.query_params.get("state", "").strip()
        lifecycle = request.query_params.get("lifecycle", "current").strip()
        serial = None
        if serial_text:
            serial = _uuid(serial_text, canonical=True)
        normalized = ""
        if owner_email:
            try:
                _, normalized = auth.normalize_email(owner_email)
            except auth.AuthenticationError as exc:
                raise _new(INVALID) from exc
        if suffix and not CLAIM_SUFFIX.fullmatch(suffix):
            _raise(INVALID)
        if product_code and not PRODUCT_CODE.fullmatch(product_code):
            _raise(INVALID)
        if state and state not in {"active", "suspended", "revoked"}:
            _raise(INVALID)
        if lifecycle not in {"current", "archived", "deleted", "all"}:
            _raise(INVALID)
        if lifecycle in {"deleted", "all"} and value.user.role is not Role.PLATFORM_OWNER:
            _raise(FORBIDDEN)
        filters = LicenseListFilter(
            serial=serial,
            owner_normalized_email=normalized,
            claim_code_suffix=suffix,
            product_code=product_code,
            state=state,
            lifecycle=lifecycle,
            limit=filters.limit,
        )
        return _json({"items": store.list_licenses(filters)})

    @app.get("/api/v1/admin/licenses/{license_id}")
    def get_admin_license(
        license_id: str,
        value: ManagementReaderDependency,
    ) -> JSONResponse:
        item = store.license_by_id(
            _uuid(license_id),
            include_deleted=value.user.role is Role.PLATFORM_OWNER,
        )
        return _json({"license": item})

    @app.get("/api/v1/admin/licenses/{license_id}/activations")
    def list_admin_activations(
        license_id: str,
        value: ManagementReaderDependency,
    ) -> JSONResponse:
        return _json(
            {
                "items": store.list_activations(
                    _uuid(license_id),
                    include_deleted=value.user.role is Role.PLATFORM_OWNER,
                )
            }
        )

    @app.get("/api/v1/admin/activations")
    def list_all_admin_activations(
        request: Request,
        _: ManagementReaderDependency,
    ) -> JSONResponse:
        license_id_text = request.query_params.get("licenseId", "").strip()
        serial_text = request.query_params.get("serial", "").strip()
        owner_email = request.query_params.get("ownerEmail", "").strip()
        product_code = request.query_params.get("productCode", "").strip().upper()
        state = request.query_params.get("state", "").strip()
        label = request.query_params.get("label", "").strip()
        thumbprint_text = request.query_params.get("deviceKeyThumbprint", "").strip()

        if product_code and not PRODUCT_CODE.fullmatch(product_code):
            _raise(INVALID)
        if state and state not in {"active", "deactivated"}:
            _raise(INVALID)
        if len(label) > 120 or any(ord(character) < 32 or ord(character) == 127 for character in label):
            _raise(INVALID)
        normalized = ""
        if owner_email:
            try:
                _, normalized = auth.normalize_email(owner_email)
            except auth.AuthenticationError as exc:
                raise _new(INVALID) from exc
        try:
            thumbprint = b64url_decode(thumbprint_text, size=32) if thumbprint_text else None
        except DeniLicenseError as exc:
            raise _new(INVALID) from exc

        filters = AdminActivationListFilter(
            license_id=_uuid(license_id_text, canonical=True) if license_id_text else None,
            serial=_uuid(serial_text, canonical=True) if serial_text else None,
            owner_normalized_email=normalized,
            product_code=product_code,
            state=state,
            label=label,
            device_key_thumbprint=thumbprint,
            limit=limit(request),
        )
        return _json({"items": store.list_admin_activations(filters)})

    @app.delete("/api/v1/admin/activations/{activation_id}", status_code=204)
    def deactivate_admin_activation(
        activation_id: str,
        request: Request,
        value: ActivationManagerDependency,
    ) -> Response:
        store.deactivate_activation(
            _uuid(activation_id),
            value.user.id,
            _audit(request, "activation.admin_deactivate", "activation"),
        )
        return Response(status_code=204)

    @app.get("/api/v1/admin/users")
    def list_admin_users(request: Request, _: OwnerDependency) -> JSONResponse:
        normalized = ""
        raw_email = request.query_params.get("email", "").strip()
        if raw_email:
            try:
                _, normalized = auth.normalize_email(raw_email)
            except auth.AuthenticationError as exc:
                raise _new(INVALID) from exc
        lifecycle = request.query_params.get("lifecycle", "current").strip()
        if lifecycle not in {"current", "archived", "deleted", "all"}:
            _raise(INVALID)
        return _json({"items": store.list_users(normalized, limit(request), lifecycle=lifecycle)})

    @app.post("/api/v1/admin/users", status_code=201)
    def create_admin_user(
        body: CreateManagedUserRequest,
        request: Request,
        owner: OwnerDependency,
    ) -> JSONResponse:
        try:
            email_address, normalized = auth.normalize_email(body.email)
            setup_token = auth.new_token(auth.PASSWORD_RESET_TOKEN)
            setup_token_hash = auth.hash_token(settings.token_pepper, auth.PASSWORD_RESET_TOKEN, setup_token)
            # The generated secret is never returned or shared. It only makes
            # password login impossible until the invitee chooses a password.
            unusable_password_hash = password_manager.hash(secrets.token_urlsafe(48))
        except auth.AuthenticationError as exc:
            raise _new(INVALID) from exc
        user = store.create_managed_user(
            CreateManagedUserParams(
                id=uuid4(),
                email=email_address,
                normalized_email=normalized,
                password_hash=unusable_password_hash,
                role=Role(body.role),
                password_reset_token_id=uuid4(),
                password_reset_token_hash=setup_token_hash,
                password_reset_token_expiry=datetime.now(UTC) + settings.password_reset_ttl,
                actor_user_id=owner.user.id,
                audit=_audit(request, "user.create", "user"),
            )
        )
        delivered = email.enqueue(
            EmailJob("password_reset", email_address, setup_token, _request_id(request))
        )
        response: dict[str, Any] = {
            "user": user,
            "passwordSetupRequired": True,
            "invitationDelivery": "email" if delivered else "manual",
        }
        if settings.expose_dev_tokens:
            response["developmentPasswordResetToken"] = setup_token
        return _json(response, 201)

    @app.post("/api/v1/admin/users/{user_id}/invitation/resend", status_code=202)
    def resend_admin_user_invitation(
        user_id: str,
        request: Request,
        owner: OwnerDependency,
    ) -> JSONResponse:
        invitation_limiter.enforce(request)
        try:
            setup_token = auth.new_token(auth.PASSWORD_RESET_TOKEN)
            setup_token_hash = auth.hash_token(settings.token_pepper, auth.PASSWORD_RESET_TOKEN, setup_token)
        except auth.AuthenticationError as exc:
            raise _new(INVALID) from exc
        user = store.resend_password_setup(
            ResendPasswordSetupParams(
                user_id=_uuid(user_id),
                actor_user_id=owner.user.id,
                token_id=uuid4(),
                token_hash=setup_token_hash,
                expires_at=datetime.now(UTC) + settings.password_reset_ttl,
                audit=_audit(request, "user.invitation_resend", "user"),
            )
        )
        delivered = email.enqueue(EmailJob("password_reset", user.email, setup_token, _request_id(request)))
        response: dict[str, Any] = {
            "accepted": True,
            "user": user,
            "invitationDelivery": "email" if delivered else "manual",
        }
        if settings.expose_dev_tokens:
            response["developmentPasswordResetToken"] = setup_token
        return _json(response, 202)

    @app.post("/api/v1/admin/users/{user_id}/archive")
    def archive_admin_user(
        user_id: str,
        body: LifecycleRequest,
        request: Request,
        owner: OwnerDependency,
    ) -> JSONResponse:
        user = store.archive_user(
            _uuid(user_id),
            owner.user.id,
            datetime.now(UTC),
            _audit(request, "user.archive", "user"),
            expected_revision=body.expected_revision,
        )
        return _json({"user": user})

    @app.post("/api/v1/admin/users/{user_id}/restore")
    def restore_admin_user(
        user_id: str,
        body: LifecycleRequest,
        request: Request,
        owner: OwnerDependency,
    ) -> JSONResponse:
        user = store.restore_user(
            _uuid(user_id),
            owner.user.id,
            datetime.now(UTC),
            _audit(request, "user.restore", "user"),
            expected_revision=body.expected_revision,
        )
        return _json({"user": user})

    @app.post("/api/v1/admin/users/{user_id}/delete", status_code=204)
    def delete_admin_user(
        user_id: str,
        body: DeleteUserRequest,
        request: Request,
        owner: OwnerDependency,
    ) -> Response:
        identifier = _uuid(user_id)
        current = store.user_by_id(identifier)
        try:
            _, supplied = auth.normalize_email(body.email)
            _, expected = auth.normalize_email(current.email)
        except auth.AuthenticationError as exc:
            raise _new(CONFLICT) from exc
        if supplied != expected:
            _raise(CONFLICT)
        store.delete_user(
            identifier,
            owner.user.id,
            datetime.now(UTC),
            _audit(request, "user.delete", "user"),
            expected_revision=body.expected_revision,
        )
        return Response(status_code=204)

    @app.get("/api/v1/admin/users/{user_id}")
    def get_admin_user(user_id: str, _: OwnerDependency) -> JSONResponse:
        return _json({"user": store.user_by_id(_uuid(user_id), include_deleted=True)})

    @app.post("/api/v1/admin/users/{user_id}/role")
    def set_admin_user_role(
        user_id: str,
        body: UserRoleRequest,
        request: Request,
        owner: OwnerDependency,
    ) -> JSONResponse:
        user = store.update_user_access(
            UpdateUserAccessParams(
                user_id=_uuid(user_id),
                actor_user_id=owner.user.id,
                role=Role(body.role),
                expected_revision=body.expected_revision,
                audit=_audit(request, "user.role_change", "user"),
            )
        )
        return _json({"user": user})

    @app.post("/api/v1/admin/users/{user_id}/status")
    def set_admin_user_status(
        user_id: str,
        body: UserStatusRequest,
        request: Request,
        owner: OwnerDependency,
    ) -> JSONResponse:
        user = store.update_user_access(
            UpdateUserAccessParams(
                user_id=_uuid(user_id),
                actor_user_id=owner.user.id,
                status=body.status,
                expected_revision=body.expected_revision,
                audit=_audit(request, "user.status_change", "user"),
            )
        )
        return _json({"user": user})

    @app.post("/api/v1/admin/users/{user_id}/access")
    def set_admin_user_access(
        user_id: str,
        body: UserAccessRequest,
        request: Request,
        owner: OwnerDependency,
    ) -> JSONResponse:
        user = store.update_user_access(
            UpdateUserAccessParams(
                user_id=_uuid(user_id),
                actor_user_id=owner.user.id,
                role=Role(body.role),
                status=body.status,
                expected_revision=body.expected_revision,
                audit=_audit(request, "user.access_change", "user"),
            )
        )
        return _json({"user": user})

    @app.get("/api/v1/admin/audit-events")
    def list_audit_events(
        request: Request,
        _: AuditReaderDependency,
    ) -> JSONResponse:
        before_id_text = request.query_params.get("beforeId", "").strip()
        before_id = 0
        if before_id_text:
            try:
                before_id = int(before_id_text)
            except ValueError as exc:
                raise _new(INVALID) from exc
            if before_id <= 0:
                _raise(INVALID)
        action = request.query_params.get("action", "").strip()
        target_type = request.query_params.get("targetType", "").strip()
        target_id = request.query_params.get("targetId", "").strip()
        if (
            len(action) > 128
            or len(target_type) > 128
            or len(target_id) > 256
            or any(
                ord(character) < 32 or ord(character) == 127 for character in action + target_type + target_id
            )
        ):
            _raise(INVALID)
        actor_text = request.query_params.get("actorUserId", "").strip()
        actor = _uuid(actor_text) if actor_text else None
        filters = AuditListFilter(
            before_id=before_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            actor_user_id=actor,
            limit=limit(request),
        )
        return _json({"items": store.list_audit_events(filters)})

    return app
