-- DeniLicense's authoritative PostgreSQL schema.
-- Applied transactionally by: denilicense migrate

CREATE TABLE users (
    id                  uuid PRIMARY KEY,
    email               text NOT NULL,
    normalized_email    text NOT NULL UNIQUE,
    password_hash       text NOT NULL,
    role                text NOT NULL DEFAULT 'customer'
                        CHECK (role IN ('platform_owner', 'license_admin', 'support', 'auditor', 'customer')),
    status              text NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'disabled')),
    email_verified_at   timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE email_verification_tokens (
    id              uuid PRIMARY KEY,
    user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash      bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    expires_at      timestamptz NOT NULL,
    consumed_at     timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX email_verification_tokens_user_idx ON email_verification_tokens(user_id);
CREATE INDEX email_verification_tokens_expiry_idx ON email_verification_tokens(expires_at);

CREATE TABLE password_reset_tokens (
    id              uuid PRIMARY KEY,
    user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash      bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    expires_at      timestamptz NOT NULL,
    consumed_at     timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX password_reset_tokens_user_idx ON password_reset_tokens(user_id);
CREATE INDEX password_reset_tokens_expiry_idx ON password_reset_tokens(expires_at);

CREATE TABLE sessions (
    id                  uuid PRIMARY KEY,
    family_id           uuid NOT NULL,
    user_id             uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    access_token_hash   bytea NOT NULL UNIQUE CHECK (octet_length(access_token_hash) = 32),
    access_expires_at   timestamptz NOT NULL,
    refresh_expires_at  timestamptz NOT NULL,
    last_seen_at        timestamptz NOT NULL DEFAULT now(),
    revoked_at          timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    CHECK (refresh_expires_at >= access_expires_at)
);
CREATE INDEX sessions_user_idx ON sessions(user_id);
CREATE INDEX sessions_family_idx ON sessions(family_id);
CREATE INDEX sessions_refresh_expiry_idx ON sessions(refresh_expires_at);

CREATE TABLE refresh_tokens (
    id              uuid PRIMARY KEY,
    session_id      uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    token_hash      bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    expires_at      timestamptz NOT NULL,
    used_at         timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX refresh_tokens_session_idx ON refresh_tokens(session_id);
CREATE INDEX refresh_tokens_expiry_idx ON refresh_tokens(expires_at);

CREATE TABLE products (
    id              uuid PRIMARY KEY,
    code            text NOT NULL UNIQUE,
    name            text NOT NULL,
    description     text NOT NULL DEFAULT '',
    status          text NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'retired')),
    created_by      uuid NOT NULL REFERENCES users(id),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CHECK (code ~ '^[A-Z][A-Z0-9_-]{1,63}$'),
    CHECK (char_length(name) BETWEEN 1 AND 120)
);

CREATE TABLE issuer_keys (
    key_id              text PRIMARY KEY,
    issuer              text NOT NULL,
    public_key          bytea NOT NULL CHECK (octet_length(public_key) = 32),
    fingerprint_sha256  bytea NOT NULL UNIQUE CHECK (octet_length(fingerprint_sha256) = 32),
    purpose             text NOT NULL DEFAULT 'offline-license-issuer'
                        CHECK (purpose = 'offline-license-issuer'),
    status              text NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'retired', 'revoked')),
    not_before          timestamptz NOT NULL,
    not_after           timestamptz,
    created_by          uuid NOT NULL REFERENCES users(id),
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CHECK (not_after IS NULL OR not_after > not_before)
);
CREATE INDEX issuer_keys_issuer_idx ON issuer_keys(issuer);

CREATE TABLE licenses (
    id                      uuid PRIMARY KEY,
    serial                  uuid NOT NULL UNIQUE,
    product_id              uuid NOT NULL REFERENCES products(id),
    owner_user_id           uuid REFERENCES users(id),
    source                  text NOT NULL CHECK (source IN ('online', 'offline_import')),
    state                   text NOT NULL DEFAULT 'active'
                            CHECK (state IN ('active', 'suspended', 'revoked')),
    issuer_key_id           text REFERENCES issuer_keys(key_id),
    import_artifact         text,
    import_artifact_hash    bytea CHECK (import_artifact_hash IS NULL OR octet_length(import_artifact_hash) = 32),
    creation_request_hash   bytea CHECK (creation_request_hash IS NULL OR octet_length(creation_request_hash) = 32),
    claim_code_hash         bytea NOT NULL UNIQUE CHECK (octet_length(claim_code_hash) = 32),
    claim_code_suffix       text NOT NULL CHECK (char_length(claim_code_suffix) = 4),
    claim_consumed_at       timestamptz,
    subject                 text NOT NULL DEFAULT '',
    issued_at               timestamptz NOT NULL,
    not_before              timestamptz NOT NULL,
    expires_at              timestamptz,
    max_activations         integer NOT NULL CHECK (max_activations BETWEEN 1 AND 100000),
    offline_grace_seconds   integer NOT NULL DEFAULT 86400 CHECK (offline_grace_seconds BETWEEN 3600 AND 2592000),
    entitlements            jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(entitlements) = 'object'),
    metadata                jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata) = 'object'),
    revision                bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by              uuid NOT NULL REFERENCES users(id),
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    CHECK (expires_at IS NULL OR expires_at > not_before),
    CHECK ((source = 'offline_import') = (issuer_key_id IS NOT NULL)),
    CHECK ((source = 'offline_import') = (import_artifact IS NOT NULL)),
    CHECK ((source = 'offline_import') = (import_artifact_hash IS NOT NULL)),
    CHECK ((source = 'online') = (creation_request_hash IS NOT NULL)),
    CHECK ((owner_user_id IS NULL) = (claim_consumed_at IS NULL))
);
CREATE INDEX licenses_owner_idx ON licenses(owner_user_id, created_at DESC);
CREATE INDEX licenses_product_idx ON licenses(product_id, created_at DESC);
CREATE INDEX licenses_state_idx ON licenses(state);

CREATE TABLE activations (
    id                      uuid PRIMARY KEY,
    license_id              uuid NOT NULL REFERENCES licenses(id),
    device_key_thumbprint   bytea NOT NULL CHECK (octet_length(device_key_thumbprint) = 32),
    device_public_key       bytea NOT NULL CHECK (octet_length(device_public_key) = 32),
    label                   text NOT NULL DEFAULT '',
    state                   text NOT NULL DEFAULT 'active'
                            CHECK (state IN ('active', 'deactivated')),
    activated_at            timestamptz NOT NULL DEFAULT now(),
    last_seen_at            timestamptz NOT NULL DEFAULT now(),
    lease_expires_at        timestamptz NOT NULL,
    deactivated_at          timestamptz,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    UNIQUE (license_id, device_key_thumbprint),
    CHECK ((state = 'deactivated') = (deactivated_at IS NOT NULL))
);
CREATE INDEX activations_license_state_idx ON activations(license_id, state);

CREATE TABLE activation_challenges (
    id              uuid PRIMARY KEY,
    activation_id   uuid NOT NULL REFERENCES activations(id) ON DELETE CASCADE,
    nonce_hash      bytea NOT NULL UNIQUE CHECK (octet_length(nonce_hash) = 32),
    expires_at      timestamptz NOT NULL,
    consumed_at     timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX activation_challenges_activation_idx ON activation_challenges(activation_id, created_at DESC);
CREATE INDEX activation_challenges_expiry_idx ON activation_challenges(expires_at);

CREATE TABLE audit_events (
    id              bigserial PRIMARY KEY,
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    actor_user_id   uuid REFERENCES users(id),
    actor_kind      text NOT NULL CHECK (actor_kind IN ('user', 'device', 'system', 'anonymous')),
    action          text NOT NULL,
    target_type     text NOT NULL,
    target_id       text NOT NULL,
    request_id      text NOT NULL,
    outcome         text NOT NULL CHECK (outcome IN ('success', 'denied', 'failure')),
    details         jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(details) = 'object')
);
CREATE INDEX audit_events_occurred_idx ON audit_events(occurred_at DESC);
CREATE INDEX audit_events_actor_idx ON audit_events(actor_user_id, occurred_at DESC);
CREATE INDEX audit_events_target_idx ON audit_events(target_type, target_id, occurred_at DESC);
