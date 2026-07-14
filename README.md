# DeniLicense

DeniLicense is a first-party account and software-entitlement service with an air-gapped issuance workflow. An offline administrator can generate an encrypted issuer key, a high-entropy one-time claim code, and a signed license grant without any network connection. The online Python service receives only the public key and signed grant, then lets a registered customer claim and activate the license.

DeniLicense is not an OAuth or OpenID Connect implementation. Use those protocols for delegated access and external single sign-on. DeniLicense fits products that need first-party accounts plus cryptographic proof that an account or installation owns a software entitlement.

## What is included

- A Python 3.14 FastAPI service and network-free `denilic` issuer CLI.
- PostgreSQL migrations and transactional license, claim, activation, renewal, user-management, and audit state.
- Argon2id passwords, optional password peppering, opaque HMAC-indexed access tokens, rotating refresh tokens with reuse-family revocation, and self-service password/session controls.
- Non-enumerating registration, email verification, password-reset, and owner-managed invitation flows through a private email webhook.
- Five server-enforced roles with visible effective-permission summaries; only a platform owner can manage users or register an offline issuer.
- 160-bit Crockford Base32 claim codes. Only a domain-separated digest and four-character support suffix are stored.
- Purpose-bound Ed25519 keys encrypted with bounded scrypt and AES-256-GCM.
- Strict canonical `dlic1` offline grants and short-lived, device-bound `dllease1` activation leases.
- Exact offline re-import idempotency, conflicting-serial rejection, and retry-safe online issuance with idempotency keys.
- Transactional activation-seat enforcement and Ed25519 proof-of-possession renewal challenges.
- Revision-safe product retirement/reactivation that hides retired products and blocks new issuance without invalidating existing licenses.
- A public JWK set, bearer-aware OpenAPI document, problem-detail responses, CORS allowlisting, security headers, request IDs, rate limits, and audit records.
- A verification-only Python client surface for product integrations.

## Trust model

```text
Air-gapped issuer                Online DeniLicense                 Product installation
-----------------               ------------------                 --------------------
offline private key             issuer public key only             device private key
       |                                  |                                  |
claim code + signed grant ---> admin imports grant                          |
       |                                  |                                  |
customer receives code ------> account claims license                       |
                                          | <--- customer approves device public key
                                          | ---- signed, device-bound lease ->
                                          | <--- signed one-time renewal proof
                                          | ---- fresh short-lived lease ---->
```

The offline issuer private key never belongs on the server. The online activation signer is a separate key. Product code contains only public verification keys and its own installation private key.

## Container quick start

Docker with Compose is the only host requirement for this path:

```powershell
docker compose up --build -d --wait
docker compose run --rm api bootstrap-owner --email owner@example.com
```

The bootstrap command prompts for a password without placing it in shell history or process arguments. The development API listens on `http://127.0.0.1:8080`; its generated OpenAPI document is available at `http://127.0.0.1:8080/openapi.yaml`.

Open `http://127.0.0.1:8080/ui/` for the embedded operations console. The
role-aware dashboard provides license search and lifecycle controls, a global
machine/installation inventory, seat and lease status, online issuance,
offline artifact import, product and issuer management, secure user invitations,
role/status controls, and audit history. A machine ID is the pseudonymous fingerprint of the
installation's Ed25519 key; it is intentionally not an invasive hardware or IP
fingerprint.

Log in and create a product:

```powershell
$login = Invoke-RestMethod -Method Post http://127.0.0.1:8080/api/v1/auth/login `
  -ContentType application/json `
  -Body (@{ email='owner@example.com'; password='a password-manager value' } | ConvertTo-Json)
$headers = @{ Authorization = "Bearer $($login.accessToken)" }

Invoke-RestMethod -Method Post http://127.0.0.1:8080/api/v1/admin/products `
  -Headers $headers -ContentType application/json `
  -Body (@{ code='MYAPP'; name='My Application'; description='Desktop edition' } | ConvertTo-Json)
```

Compose deliberately uses predictable development secrets and an unencrypted database connection. Never deploy those settings.

To connect another containerized application, attach that service to the
existing `denilicense-network` bridge and use
`http://denilicense-api:8080` as its DeniLicense base URL. Do not enable host
networking or use `localhost` from inside the other container. The complete
Compose example and lease-issuer note are in the
[operations guide](docs/OPERATIONS.md#container-to-container-access).

## Python development

Requirements: CPython 3.14 and PostgreSQL 17 for a locally served instance. Docker can provide PostgreSQL if desired.

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

## Tests, formatting, lint, and dependency audit

```powershell
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\ruff.exe format --check src tests
.\.venv\Scripts\ruff.exe check src tests
.\.venv\Scripts\pip-audit.exe --requirement requirements.lock
```

The editable install provides two commands:

- `denilicense serve`, `denilicense migrate`, and `denilicense bootstrap-owner --email ...` administer the online service.
- `denilic keygen`, `denilic public-key`, `denilic issue`, `denilic verify`, and `denilic secret` support offline issuance and secret generation.

For repository-level testing, `python main.py` starts the complete HTTP service
directly from `src`. When no environment is selected, it provisions persistent
development-only signing material under `data/development`, connects to the
Compose PostgreSQL service on port 5432, and listens at
`http://127.0.0.1:8081`. It also accepts the same `serve`, `migrate`, and
`bootstrap-owner` subcommands as `denilicense`. Explicit `DENILICENSE_ENV`
configuration always disables these launcher defaults.

Copy `.env.example` into your local secret-management workflow, replace every placeholder, generate a separate activation key, and run schema migration before starting the service. Environment files are not loaded automatically by the application.

## Offline issuance

Install the Python package plus its pinned cryptography dependency from an audited offline wheelhouse. The issuer command performs no network operations.

Generate and protect an offline issuer key:

```powershell
New-Item -ItemType Directory -Force secrets | Out-Null
denilic keygen --purpose license `
  --private secrets/offline-issuer.key.json `
  --public secrets/offline-issuer.public.json
```

The command prompts for a passphrase of at least 16 bytes, refuses to overwrite files, and creates an encrypted private document. Keep both the private file and its passphrase offline. Transfer only `offline-issuer.public.json` to the online administrator and register it:

```powershell
$publicDocument = Get-Content -Raw secrets/offline-issuer.public.json
Invoke-RestMethod -Method Post http://127.0.0.1:8080/api/v1/admin/issuers `
  -Headers $headers -ContentType application/json `
  -Body (@{
    issuer='com.example.offline-issuer'
    publicKeyDocument=$publicDocument
  } | ConvertTo-Json)
```

Back on the disconnected workstation, issue a one-year grant:

```powershell
denilic issue `
  --key secrets/offline-issuer.key.json `
  --issuer com.example.offline-issuer `
  --product MYAPP `
  --subject customer-1042 `
  --valid-for 8760h `
  --max-activations 3 `
  --entitlement feature.reporting=true `
  --entitlement projects.max=100 `
  --out customer-1042.dlicense
```

`--expires`, `--valid-for`, or the explicit `--perpetual` option is required. The claim code is shown exactly once. Transfer the signed artifact to the administrator and send the claim code to the customer through a separate secure channel.

```powershell
$artifact = (Get-Content -Raw customer-1042.dlicense).Trim()
Invoke-RestMethod -Method Post http://127.0.0.1:8080/api/v1/admin/licenses/import `
  -Headers $headers -ContentType application/json `
  -Body (@{ artifact=$artifact } | ConvertTo-Json)
```

An exact re-import returns the existing license. The same serial with different signed bytes is rejected as a conflict and recorded as a security-relevant event.

## Customer and installation flow

1. Choose **Create customer account** in the embedded UI (or call `POST /api/v1/auth/register`) and provide only the email address. The one-time verification link proves ownership and is where the customer chooses the account's first password; no caller-selected password is retained before verification. Development Compose displays the link because it intentionally has no email webhook.
2. Log in and either submit a request from **License requests**, or claim an already-issued license with its one-time code. Owners and license administrators can review a request and issue a license directly to that customer without sending a claim secret.
3. Generate a distinct Ed25519 installation keypair and keep its private key in the strongest OS keystore available.
4. Approve the installation public key with `POST /api/v1/licenses/{licenseId}/activations`.
5. Verify the returned lease with `denilicense.client` and the keys at `/.well-known/denilicense-activation-keys.json`, binding the configured issuer, product, and installation-key thumbprint.
6. Before expiry, request `POST /api/v1/activation-challenges`, validate and sign its structured transcript, and complete it at `POST /api/v1/activation-challenges/complete`.

See [the entitlement guide](docs/ENTITLEMENTS.md) for naming, types, issuance,
safe feature and limit checks, schema evolution, offline behavior, and the
hostile-client boundary. See [client integration](docs/CLIENT_INTEGRATION.md)
for Python imports and exact verification rules.

## Administration and recovery

Customers can list their installations at `GET /api/v1/licenses/{licenseId}/activations` and retry `DELETE /api/v1/activations/{activationId}` to free an abandoned seat.

Platform owners can add an account from **Users → Add user**, choose its role, and review the resulting permission bundle before creating it. The account receives a single-use password-setup invitation; the owner never chooses or sees the user's password. Development mode exposes the setup link for manual testing, while production queues it through the configured private email webhook.

Pending setup invitations can be resent from the user detail panel. Resending invalidates every older setup link. Archiving immediately disables and signs out the user; restoring an archived user leaves it disabled until an owner explicitly re-enables access. Permanent deletion requires an archived user and anonymizes the account while preserving audit and license references. It is blocked while the account owns a non-revoked license.

Archiving a license suspends an active license, deactivates its current seats, and invalidates pending renewal challenges. Restoring it does not reactivate it. Permanent deletion requires the license to be both archived and revoked, and retains a cryptographic tombstone so its serial, claim digest, and issuance identity cannot be replayed. Destructive operations use the displayed revision to reject stale browser actions.

Every signed-in user can open **Account security** to change their password, review active sessions, revoke one session, or revoke every session except the current one. A password change keeps the verified current session and revokes the rest.

Privileged endpoints under `/api/v1/admin` support product and license issuance, product retirement/reactivation, issuer status, license state, administrative deactivation, user invitation and role/status management, and audit-event pagination. Product and user access changes require the displayed revision so stale consoles cannot silently overwrite newer decisions. Role or status changes are atomic and revoke all of that user's sessions. A transaction rechecks the acting owner, prevents self-demotion or self-disablement, and refuses to remove the final active platform owner.

## Production boundary

DeniLicense is a security-focused foundation, not a claim of a completed independent audit or a general-purpose identity provider. Before exposing it to customers:

- Terminate TLS at a trusted edge and require verified TLS to PostgreSQL; replace every development credential and pepper.
- Keep the offline issuer isolated, and move online activation signing behind KMS/HSM for high-value deployments.
- Add WebAuthn/passkeys and mandatory step-up MFA for privileged roles. Password and session protections are present; MFA ceremonies are not.
- Replace the bounded in-memory email queue with an encrypted transactional outbox or durable provider queue when delivery must survive a host crash.
- Put rate limiting in a shared edge or data store before running multiple replicas.
- Export audit events to independent immutable storage and alert on issuance, issuer, role, session-reuse, and revocation events.
- Test encrypted backups, issuance-pepper and signing-key recovery, RPO/RTO, dependency/SBOM scans, penetration testing, and independent cryptographic review.
- Add explicit tenant isolation and database row-level security before serving mutually untrusted organizations from one deployment.

Permanently offline software cannot receive instant revocation or provide authoritative concurrent-seat enforcement, and a customer controlling a machine can patch a local verifier. Finite signed leases and server-authoritative operations reduce that risk; they do not eliminate it.

Read the [security model](docs/SECURITY_MODEL.md) and [operations guide](docs/OPERATIONS.md) before deploying.
