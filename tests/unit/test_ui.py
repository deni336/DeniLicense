from __future__ import annotations

import hashlib
import re
import tomllib
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi.testclient import TestClient

from denilicense import auth
from denilicense.api import create_app
from denilicense.config import Settings
from denilicense.crypto.common import b64url_encode
from denilicense.domain import Principal, Role, User
from denilicense.store import AdminActivationListFilter


class _PasswordManager:
    def hash(self, password: str) -> str:
        return f"hashed:{password}"


class _Store:
    def __init__(self) -> None:
        now = datetime.now(UTC)
        self.principal = Principal(
            User(
                id=uuid4(),
                email="auditor@example.com",
                role=Role.AUDITOR,
                status="active",
                email_verified_at=now,
                created_at=now,
            ),
            uuid4(),
        )
        self.activation_filters: AdminActivationListFilter | None = None
        self.activation_filter_calls: list[AdminActivationListFilter] = []

    def ping(self) -> None:
        pass

    def principal_by_access_hash(self, digest: bytes, now: datetime) -> Principal:
        del digest, now
        return self.principal

    def dashboard_summary(self) -> dict[str, int]:
        return {"totalLicenses": 3, "activeActivations": 2}

    def list_admin_activations(self, filters: AdminActivationListFilter) -> list[Any]:
        self.activation_filters = filters
        self.activation_filter_calls.append(filters)
        return []

    def list_products(self, include_retired: bool = False) -> list[Any]:
        del include_retired
        return []

    def list_issuers(self, status: str = "", limit: int = 100) -> list[Any]:
        del status, limit
        return []


def _settings(*, origins: tuple[str, ...] = ()) -> Settings:
    return Settings(
        environment="test",
        http_host="127.0.0.1",
        http_port=8080,
        database_url="postgresql://test:test@localhost/test",
        token_pepper=b"t" * 32,
        device_pepper=b"d" * 32,
        issuance_pepper=b"i" * 32,
        password_pepper=b"",
        access_token_ttl=timedelta(minutes=15),
        refresh_token_ttl=timedelta(days=30),
        verification_ttl=timedelta(minutes=30),
        password_reset_ttl=timedelta(minutes=30),
        activation_lease_ttl=timedelta(hours=24),
        registration_mode="open",
        allowed_origins=origins,
        trusted_proxy_cidrs=(),
        expose_dev_tokens=True,
        public_app_url="http://localhost:8080",
        email_webhook_url="",
        email_webhook_bearer="",
        activation_issuer="",
        activation_key_file=None,
        activation_key_passphrase_file=None,
        activation_verification_key_files=(),
        auto_migrate=False,
        shutdown_timeout=timedelta(seconds=1),
    )


def _app(*, origins: tuple[str, ...] = (), store: _Store | None = None) -> Any:
    return create_app(
        _settings(origins=origins),
        store or _Store(),  # type: ignore[arg-type]
        _PasswordManager(),  # type: ignore[arg-type]
    )


def _authorization() -> dict[str, str]:
    return {"Authorization": f"Bearer {auth.new_token(auth.ACCESS_TOKEN)}"}


def _files(root: Traversable) -> Iterator[Traversable]:
    for item in root.iterdir():
        if item.is_dir():
            yield from _files(item)
        elif item.is_file():
            yield item


def test_ui_redirect_index_and_path_specific_security_policy() -> None:
    with TestClient(_app()) as client:
        redirect = client.get("/", follow_redirects=False)
        ui_redirect = client.get("/ui", follow_redirects=False)
        reset_redirect = client.get(
            "/reset-password",
            params={"token": "dlpr_example+token/value"},
            follow_redirects=False,
        )
        oversized_reset_redirect = client.get(
            "/reset-password",
            params={"token": "x" * 129},
            follow_redirects=False,
        )
        verification_redirect = client.get(
            "/verify-email",
            params={"token": "dlev_example+token/value"},
            follow_redirects=False,
        )
        index = client.get("/ui/")
        api = client.get("/live")
        lookalike = client.get("/ui-not-the-console")

    assert redirect.status_code == 307
    assert redirect.headers["location"] == "/ui/"
    assert redirect.headers["cache-control"] == "no-store"
    assert ui_redirect.status_code == 307
    assert ui_redirect.headers["location"] == "/ui/"
    assert reset_redirect.status_code == 307
    assert reset_redirect.headers["location"] == (
        "/ui/?action=reset-password&token=dlpr_example%2Btoken%2Fvalue"
    )
    assert reset_redirect.headers["cache-control"] == "no-store"
    assert oversized_reset_redirect.headers["location"] == "/ui/?action=reset-password"
    assert verification_redirect.status_code == 307
    assert verification_redirect.headers["location"] == (
        "/ui/?action=verify-email&token=dlev_example%2Btoken%2Fvalue"
    )
    assert verification_redirect.headers["cache-control"] == "no-store"
    assert index.status_code == 200
    assert index.headers["content-type"].startswith("text/html")
    assert index.headers["cache-control"] == "no-store"
    policy = index.headers["content-security-policy"]
    assert "script-src 'self'" in policy
    assert "style-src 'self'" in policy
    assert "connect-src 'self'" in policy
    assert "frame-ancestors 'none'" in policy
    assert "unsafe-inline" not in policy
    assert api.headers["content-security-policy"] == (
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    )
    assert lookalike.headers["content-security-policy"] == api.headers["content-security-policy"]


def test_packaged_assets_have_content_type_cache_validation_and_security_headers() -> None:
    ui = resources.files("denilicense").joinpath("ui")
    asset = next(item for item in _files(ui) if item.name.endswith((".css", ".js")))
    relative = str(asset).replace("\\", "/").split("/ui/", 1)[1]
    digest = hashlib.sha256(asset.read_bytes()).hexdigest()

    with TestClient(_app()) as client:
        index = client.get("/ui/")
        stable = client.get(f"/ui/{relative}")
        response = client.get(f"/ui/{relative}?v={digest[:16]}")
        unchanged = client.get(f"/ui/{relative}", headers={"If-None-Match": response.headers["etag"]})

    assert f"/ui/{relative}?v={digest[:16]}" in index.text
    assert stable.headers["cache-control"] == "public, max-age=0, must-revalidate"
    assert response.status_code == 200
    assert response.headers["content-type"] != "application/octet-stream"
    assert response.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert response.headers["etag"] == f'"{digest}"'
    assert len(response.headers["etag"]) == 66
    assert response.headers["x-content-type-options"] == "nosniff"
    assert unchanged.status_code == 304
    assert unchanged.headers["etag"] == response.headers["etag"]


def test_ui_rejects_missing_hidden_and_traversal_paths() -> None:
    with TestClient(_app()) as client:
        missing = client.get("/ui/not-present.js")
        hidden = client.get("/ui/.env")
        traversal = client.get("/ui/%2e%2e/README.md")

    for response in (missing, hidden, traversal):
        assert response.status_code == 404
        assert response.headers["content-type"].startswith("application/problem+json")
        assert response.json()["code"] == "not_found"


def test_ui_preserves_origin_guard() -> None:
    origin = "https://licenses.example.com"
    with TestClient(_app(origins=(origin,))) as client:
        denied = client.get("/ui/", headers={"Origin": "https://evil.example"})
        allowed = client.get("/ui/", headers={"Origin": origin})

    assert denied.status_code == 403
    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == origin


def test_ui_assets_are_declared_as_package_data() -> None:
    project_root = Path(__file__).resolve().parents[2]
    project = tomllib.loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))
    patterns = project["tool"]["setuptools"]["package-data"]["denilicense"]
    names = {item.name for item in _files(resources.files("denilicense").joinpath("ui"))}

    assert "ui/*" in patterns
    assert "ui/**/*" in patterns
    assert {"index.html", "app.js", "app.css"} <= names


def test_user_admin_ui_exposes_invites_role_access_and_memory_only_setup_tokens() -> None:
    ui = resources.files("denilicense").joinpath("ui")
    html = ui.joinpath("index.html").read_text(encoding="utf-8")
    script = ui.joinpath("app.js").read_text(encoding="utf-8")

    for element_id in (
        "create-user-button",
        "user-dialog",
        "role-guide",
        "password-reset-request-dialog",
        "password-setup-screen",
    ):
        assert f'id="{element_id}"' in html
    assert "POST" in script
    assert "`${API}/admin/users`" in script
    assert "`${API}/admin/users/${encodeURIComponent(user.id)}/access`" in script
    assert "`${API}/auth/password-reset/confirm`" in script
    assert 'history.replaceState(null, "", "/ui/")' in script
    assert "sessionStorage" in script
    assert "localStorage" not in script
    for unsafe_sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"):
        assert unsafe_sink not in script


def test_ui_routes_and_lifecycle_controls_are_wired_and_discoverable() -> None:
    ui = resources.files("denilicense").joinpath("ui")
    html = ui.joinpath("index.html").read_text(encoding="utf-8")
    script = ui.joinpath("app.js").read_text(encoding="utf-8")

    route_block = re.search(r"const routes = \{(.*?)\n\};", script, re.DOTALL)
    assert route_block is not None
    routes = set(re.findall(r"^\s{2}([a-z]+):", route_block.group(1), re.MULTILINE))
    nav_routes = set(re.findall(r'data-route="([a-z]+)"', html))
    views = set(re.findall(r'data-view="([a-z]+)"', html))
    assert routes == nav_routes == views
    assert 'if (route === "requests") await loadRequests();' in script

    assert 'id="license-lifecycle-console"' in html
    assert html.count('data-lifecycle-value="archived"') == 2
    assert html.count('data-lifecycle-value="deleted"') == 2
    for label in (
        'makeButton("Resend invite"',
        'makeButton("Archive"',
        'makeButton("Restore"',
        'makeButton("Delete"',
        'detailSection("Lifecycle management")',
    ):
        assert label in script


def test_ui_registration_state_transitions_and_accessibility_regressions() -> None:
    ui = resources.files("denilicense").joinpath("ui")
    html = ui.joinpath("index.html").read_text(encoding="utf-8")
    script = ui.joinpath("app.js").read_text(encoding="utf-8")
    styles = ui.joinpath("app.css").read_text(encoding="utf-8")

    assert 'name="registrationEmail"' in html
    assert 'name="registrationPassword"' not in html
    assert 'name="registrationConfirmation"' not in html
    assert 'id="email-verification-form"' in html
    assert 'name="newPassword"' in html
    assert 'name="confirmPassword"' in html
    assert "body: { email }" in script
    assert re.search(
        r"body:\s*\{\s*token:\s*emailVerificationToken,\s*newPassword:\s*password\s*\}",
        script,
    )
    assert "`${API}/auth/verification/request`" in script

    assert "`${API}/activations/${encodeURIComponent(activation.id)}`" in script
    assert "`${API}/admin/activations/${encodeURIComponent(activation.id)}`" in script
    assert "revoked: []" in script
    assert "Revocation is permanent." in script
    assert "This key is permanently revoked." in script

    assert "location.hash = target;\n      return;" in script
    for request_name in ("licenses", "requests", "machines", "products", "issuers", "users"):
        assert f"request !== listRequests.{request_name}" in script
    assert "function resetLicenseForm()" in script
    assert 'form.elements.entitlements.value = "{}";' in script

    dialogs = re.findall(r"<dialog\b([^>]*)>", html)
    assert dialogs
    assert all("aria-labelledby=" in attributes or "aria-label=" in attributes for attributes in dialogs)
    assert 'attributes: { scope: "col" }' in script
    assert 'attributes: { role: "status", "aria-live": "polite", "aria-busy": "true" }' in script
    assert ":focus-visible" in styles
    assert "overflow-y: auto" in styles
    assert ".filter-bar.user-filter-bar { grid-template-columns: 1fr; }" in styles


def test_ui_account_security_product_lifecycle_and_revision_guards() -> None:
    ui = resources.files("denilicense").joinpath("ui")
    html = ui.joinpath("index.html").read_text(encoding="utf-8")
    script = ui.joinpath("app.js").read_text(encoding="utf-8")

    for element_id in (
        "account-security-button",
        "account-security-dialog",
        "account-password-form",
        "account-sessions",
        "refresh-account-sessions",
        "revoke-other-sessions",
    ):
        assert f'id="{element_id}"' in html
    assert 'aria-labelledby="account-security-title"' in html
    assert 'autocomplete="current-password"' in html
    assert html.count('autocomplete="new-password"') >= 2
    assert "`${API}/auth/sessions`" in script
    assert "`${API}/auth/password/change`" in script
    assert "body: { currentPassword, newPassword }" in script
    assert "`${API}/auth/sessions/revoke-others`" in script
    assert "`${API}/auth/sessions/${encodeURIComponent(session.id)}`" in script
    assert 'showLogin("This browser session was revoked.' in script

    management_roles = '"platform_owner", "license_admin", "support", "auditor"'
    assert f"roles: [{management_roles}]" in script
    assert 'data-route="products" data-roles="platform_owner,license_admin,support,auditor"' in html
    assert 'byId("create-product-button").hidden = !isLicenseWriter();' in script
    assert "if (isManagementReader()) {" in script
    assert "`${API}/admin/products/${encodeURIComponent(product.code)}/status`" in script
    assert "body: { status, expectedRevision }" in script
    assert "body: { role, status, expectedRevision: user.revision }" in script
    assert "await loadProductsPage();" in script
    assert 'href="/docs/entitlements"' in html


def test_management_dashboard_routes_and_activation_filters() -> None:
    store = _Store()
    license_id = uuid4()
    serial = uuid4()
    thumbprint = b"m" * 32
    query = {
        "licenseId": str(license_id),
        "serial": str(serial),
        "ownerEmail": " Owner@Example.com ",
        "productCode": "desktop",
        "state": "active",
        "label": "workstation",
        "deviceKeyThumbprint": b64url_encode(thumbprint),
        "limit": "25",
    }
    with TestClient(_app(store=store)) as client:
        dashboard = client.get("/api/v1/admin/dashboard", headers=_authorization())
        activations = client.get("/api/v1/admin/activations", params=query, headers=_authorization())
        issuers = client.get("/api/v1/admin/issuers?status=active", headers=_authorization())
        products = client.get("/api/v1/admin/products?includeRetired=true", headers=_authorization())

    assert dashboard.status_code == 200
    assert dashboard.json()["summary"]["totalLicenses"] == 3
    assert dashboard.json()["recentActivations"] == []
    assert store.activation_filter_calls[0] == AdminActivationListFilter(limit=8)
    assert activations.status_code == 200
    assert issuers.status_code == 200
    assert products.status_code == 200
    assert store.activation_filters == AdminActivationListFilter(
        license_id=license_id,
        serial=serial,
        owner_normalized_email="owner@example.com",
        product_code="DESKTOP",
        state="active",
        label="workstation",
        device_key_thumbprint=thumbprint,
        limit=25,
    )


def test_management_filters_reject_malformed_values() -> None:
    headers = _authorization()
    with TestClient(_app()) as client:
        thumbprint = client.get("/api/v1/admin/activations?deviceKeyThumbprint=invalid", headers=headers)
        state = client.get("/api/v1/admin/activations?state=unknown", headers=headers)
        products = client.get("/api/v1/admin/products?includeRetired=yes", headers=headers)
        issuers = client.get("/api/v1/admin/issuers?status=disabled", headers=headers)

    for response in (thumbprint, state, products, issuers):
        assert response.status_code == 400
        assert response.json()["code"] == "invalid_request"
