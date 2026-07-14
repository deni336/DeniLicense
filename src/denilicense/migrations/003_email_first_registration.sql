-- Convert public registration to an email-first credential ceremony.
--
-- Older releases stored a caller-selected password before proving ownership
-- of the email address. Every unverified credential is therefore untrusted.

UPDATE sessions s
SET revoked_at = COALESCE(s.revoked_at, clock_timestamp())
WHERE EXISTS (
    SELECT 1 FROM users u
    WHERE u.id = s.user_id AND u.email_verified_at IS NULL
);

DELETE FROM password_reset_tokens t
WHERE EXISTS (
    SELECT 1 FROM users u
    WHERE u.id = t.user_id AND u.email_verified_at IS NULL
);

INSERT INTO audit_events
    (actor_user_id, actor_kind, action, target_type, target_id, request_id, outcome, details)
SELECT NULL, 'system', 'user.pending_registration_migrated', 'user', u.id::text,
       'migration-003', 'success',
       jsonb_build_object(
           'previousRole', u.role,
           'credentialNeutralized', TRUE
       )
FROM users u
WHERE u.email_verified_at IS NULL
  AND u.deleted_at IS NULL;

UPDATE users
SET password_hash = '!pending-registration-v1',
    password_set_at = NULL,
    role = 'customer',
    revision = revision + 1,
    updated_at = clock_timestamp()
WHERE email_verified_at IS NULL
  AND deleted_at IS NULL;

ALTER TABLE users
    ADD CONSTRAINT users_unverified_role_check CHECK (
        email_verified_at IS NOT NULL OR role = 'customer'
    ),
    ADD CONSTRAINT users_unverified_credential_check CHECK (
        email_verified_at IS NOT NULL OR password_set_at IS NULL
    );
