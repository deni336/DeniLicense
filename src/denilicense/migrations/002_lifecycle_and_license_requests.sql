-- Reversible administration lifecycle and customer license-request workflow.

ALTER TABLE users
    ADD COLUMN password_set_at timestamptz,
    ADD COLUMN archived_at timestamptz,
    ADD COLUMN archived_by uuid REFERENCES users(id),
    ADD COLUMN deleted_at timestamptz,
    ADD COLUMN deleted_by uuid REFERENCES users(id),
    ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0);

-- Accounts created before this migration already had an administrator- or
-- customer-selected password. Future invitations explicitly leave this NULL.
UPDATE users SET password_set_at = updated_at;

-- Preserve setup-pending invitations created by versions that did not yet
-- persist password initialization explicitly. Managed creation was audited;
-- consuming its setup token was audited as a password reset.
UPDATE users u SET password_set_at = NULL
WHERE EXISTS (
    SELECT 1 FROM audit_events a
    WHERE a.action = 'user.create' AND a.target_type = 'user'
      AND a.target_id = u.id::text
)
AND NOT EXISTS (
    SELECT 1 FROM audit_events a
    WHERE a.action = 'user.password_reset' AND a.target_type = 'user'
      AND a.target_id = u.id::text
);

ALTER TABLE users
    ADD CONSTRAINT users_archived_actor_check CHECK (
        (archived_at IS NULL) = (archived_by IS NULL)
    ),
    ADD CONSTRAINT users_deleted_actor_check CHECK (
        (deleted_at IS NULL) = (deleted_by IS NULL)
    ),
    ADD CONSTRAINT users_archived_status_check CHECK (
        archived_at IS NULL OR status = 'disabled'
    ),
    ADD CONSTRAINT users_deleted_lifecycle_check CHECK (
        deleted_at IS NULL OR (
            archived_at IS NOT NULL
            AND status = 'disabled'
            AND role = 'customer'
            AND email_verified_at IS NULL
        )
    );

CREATE INDEX users_lifecycle_idx
    ON users(deleted_at, archived_at, created_at DESC);

ALTER TABLE licenses
    ADD COLUMN archived_at timestamptz,
    ADD COLUMN archived_by uuid REFERENCES users(id),
    ADD COLUMN deleted_at timestamptz,
    ADD COLUMN deleted_by uuid REFERENCES users(id);

ALTER TABLE licenses
    ADD CONSTRAINT licenses_archived_actor_check CHECK (
        (archived_at IS NULL) = (archived_by IS NULL)
    ),
    ADD CONSTRAINT licenses_deleted_actor_check CHECK (
        (deleted_at IS NULL) = (deleted_by IS NULL)
    ),
    ADD CONSTRAINT licenses_archived_state_check CHECK (
        archived_at IS NULL OR state IN ('suspended', 'revoked')
    ),
    ADD CONSTRAINT licenses_deleted_lifecycle_check CHECK (
        deleted_at IS NULL OR (archived_at IS NOT NULL AND state = 'revoked')
    );

CREATE INDEX licenses_lifecycle_idx
    ON licenses(deleted_at, archived_at, created_at DESC);

CREATE TABLE license_requests (
    id                      uuid PRIMARY KEY,
    requester_user_id       uuid NOT NULL REFERENCES users(id),
    product_id              uuid NOT NULL REFERENCES products(id),
    requested_activations   integer NOT NULL DEFAULT 1
                            CHECK (requested_activations BETWEEN 1 AND 100000),
    message                 text NOT NULL DEFAULT '' CHECK (char_length(message) <= 2000),
    status                  text NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending', 'approved', 'denied', 'cancelled', 'fulfilled')),
    admin_notes             text NOT NULL DEFAULT '' CHECK (char_length(admin_notes) <= 2000),
    reviewed_by             uuid REFERENCES users(id),
    reviewed_at             timestamptz,
    fulfilled_license_id    uuid UNIQUE REFERENCES licenses(id),
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    CHECK ((reviewed_by IS NULL) = (reviewed_at IS NULL)),
    CHECK ((status = 'fulfilled') = (fulfilled_license_id IS NOT NULL))
);

CREATE UNIQUE INDEX license_requests_one_open_product_idx
    ON license_requests(requester_user_id, product_id)
    WHERE status IN ('pending', 'approved');
CREATE INDEX license_requests_requester_idx
    ON license_requests(requester_user_id, created_at DESC);
CREATE INDEX license_requests_admin_queue_idx
    ON license_requests(status, created_at DESC);
