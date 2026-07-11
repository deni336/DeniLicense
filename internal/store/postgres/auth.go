package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/deni336/DeniLicense/internal/domain"
	storeerrors "github.com/deni336/DeniLicense/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type UserCredential struct {
	User         domain.User
	PasswordHash string
}

type CreateUserParams struct {
	ID                      uuid.UUID
	Email                   string
	NormalizedEmail         string
	PasswordHash            string
	Role                    domain.Role
	VerificationTokenID     uuid.UUID
	VerificationTokenHash   [32]byte
	VerificationTokenExpiry time.Time
}

func (s *Store) CreateUser(ctx context.Context, p CreateUserParams) (domain.User, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return domain.User{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var user domain.User
	err = tx.QueryRow(ctx, `
		INSERT INTO users (id, email, normalized_email, password_hash, role)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, email, role, status, email_verified_at, created_at
	`, p.ID, p.Email, p.NormalizedEmail, p.PasswordHash, p.Role).Scan(
		&user.ID, &user.Email, &user.Role, &user.Status, &user.EmailVerifiedAt, &user.CreatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return domain.User{}, storeerrors.ErrConflict
		}
		return domain.User{}, fmt.Errorf("insert user: %w", err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO email_verification_tokens (id, user_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)
	`, p.VerificationTokenID, p.ID, p.VerificationTokenHash[:], p.VerificationTokenExpiry.UTC())
	if err != nil {
		return domain.User{}, fmt.Errorf("insert verification token: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.User{}, err
	}
	return user, nil
}

func (s *Store) UserCredentialByEmail(ctx context.Context, normalizedEmail string) (UserCredential, error) {
	var c UserCredential
	err := s.pool.QueryRow(ctx, `
		SELECT id, email, role, status, email_verified_at, created_at, password_hash
		FROM users WHERE normalized_email = $1
	`, normalizedEmail).Scan(
		&c.User.ID, &c.User.Email, &c.User.Role, &c.User.Status,
		&c.User.EmailVerifiedAt, &c.User.CreatedAt, &c.PasswordHash,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return UserCredential{}, storeerrors.ErrNotFound
	}
	if err != nil {
		return UserCredential{}, err
	}
	return c, nil
}

func (s *Store) VerifyEmail(ctx context.Context, tokenHash [32]byte, now time.Time) (domain.User, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return domain.User{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var userID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT user_id FROM email_verification_tokens WHERE token_hash = $1`, tokenHash[:]).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.User{}, storeerrors.ErrNotFound
	}
	if err != nil {
		return domain.User{}, err
	}
	if err := tx.QueryRow(ctx, `SELECT id FROM users WHERE id = $1 FOR UPDATE`, userID).Scan(&userID); err != nil {
		return domain.User{}, err
	}
	result, err := tx.Exec(ctx, `
		UPDATE email_verification_tokens SET consumed_at = $2
		WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > $2
	`, tokenHash[:], now.UTC())
	if err != nil {
		return domain.User{}, err
	}
	if result.RowsAffected() != 1 {
		return domain.User{}, storeerrors.ErrNotFound
	}
	var user domain.User
	err = tx.QueryRow(ctx, `
		UPDATE users SET email_verified_at = COALESCE(email_verified_at, $2), updated_at = $2
		WHERE id = $1
		RETURNING id, email, role, status, email_verified_at, created_at
	`, userID, now.UTC()).Scan(
		&user.ID, &user.Email, &user.Role, &user.Status, &user.EmailVerifiedAt, &user.CreatedAt,
	)
	if err != nil {
		return domain.User{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE email_verification_tokens SET consumed_at = COALESCE(consumed_at, $2)
		WHERE user_id = $1
	`, userID, now.UTC()); err != nil {
		return domain.User{}, err
	}
	if err := insertAudit(ctx, tx, AuditEvent{
		ActorKind: "anonymous", Action: "user.email_verify", TargetType: "user",
		TargetID: user.ID.String(), RequestID: "auth-token", Outcome: "success",
	}); err != nil {
		return domain.User{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.User{}, err
	}
	return user, nil
}

// ReplaceEmailVerificationToken issues a fresh single-use token only for an
// existing, active, unverified account. The bool is deliberately kept inside
// the service boundary so the HTTP response can remain non-enumerating.
func (s *Store) ReplaceEmailVerificationToken(ctx context.Context, normalizedEmail string, tokenID uuid.UUID, tokenHash [32]byte, expiresAt time.Time) (string, bool, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return "", false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var userID uuid.UUID
	var email string
	err = tx.QueryRow(ctx, `
		SELECT id, email FROM users
		WHERE normalized_email = $1 AND status = 'active' AND email_verified_at IS NULL
		FOR UPDATE
	`, normalizedEmail).Scan(&userID, &email)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO email_verification_tokens (id, user_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)
	`, tokenID, userID, tokenHash[:], expiresAt.UTC()); err != nil {
		return "", false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", false, err
	}
	return email, true, nil
}

func (s *Store) ReplacePasswordResetToken(ctx context.Context, normalizedEmail string, tokenID uuid.UUID, tokenHash [32]byte, expiresAt time.Time) (string, bool, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return "", false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var userID uuid.UUID
	var email string
	err = tx.QueryRow(ctx, `
		SELECT id, email FROM users
		WHERE normalized_email = $1 AND status = 'active'
		FOR UPDATE
	`, normalizedEmail).Scan(&userID, &email)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)
	`, tokenID, userID, tokenHash[:], expiresAt.UTC()); err != nil {
		return "", false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", false, err
	}
	return email, true, nil
}

func (s *Store) ConsumePasswordResetToken(ctx context.Context, tokenHash [32]byte, newPasswordHash string, now time.Time) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var userID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT user_id FROM password_reset_tokens WHERE token_hash = $1`, tokenHash[:]).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return storeerrors.ErrNotFound
	}
	if err != nil {
		return err
	}
	if err := tx.QueryRow(ctx, `SELECT id FROM users WHERE id = $1 AND status = 'active' FOR UPDATE`, userID).Scan(&userID); errors.Is(err, pgx.ErrNoRows) {
		return storeerrors.ErrNotFound
	} else if err != nil {
		return err
	}
	result, err := tx.Exec(ctx, `
		UPDATE password_reset_tokens SET consumed_at = $2
		WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > $2
	`, tokenHash[:], now.UTC())
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return storeerrors.ErrNotFound
	}
	result, err = tx.Exec(ctx, `
		UPDATE users SET password_hash = $2, updated_at = $3
		WHERE id = $1 AND status = 'active'
	`, userID, newPasswordHash, now.UTC())
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return storeerrors.ErrNotFound
	}
	if _, err := tx.Exec(ctx, `
		UPDATE password_reset_tokens SET consumed_at = COALESCE(consumed_at, $2)
		WHERE user_id = $1
	`, userID, now.UTC()); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at = COALESCE(revoked_at, $2) WHERE user_id = $1`, userID, now.UTC()); err != nil {
		return err
	}
	if err := insertAudit(ctx, tx, AuditEvent{
		ActorKind: "anonymous", Action: "user.password_reset", TargetType: "user",
		TargetID: userID.String(), RequestID: "password-reset-token", Outcome: "success",
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type CreateSessionParams struct {
	SessionID        uuid.UUID
	FamilyID         uuid.UUID
	UserID           uuid.UUID
	AccessHash       [32]byte
	AccessExpiresAt  time.Time
	RefreshTokenID   uuid.UUID
	RefreshHash      [32]byte
	RefreshExpiresAt time.Time
}

func (s *Store) CreateSession(ctx context.Context, p CreateSessionParams) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO sessions
		(id, family_id, user_id, access_token_hash, access_expires_at, refresh_expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, p.SessionID, p.FamilyID, p.UserID, p.AccessHash[:], p.AccessExpiresAt.UTC(), p.RefreshExpiresAt.UTC())
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO refresh_tokens (id, session_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)
	`, p.RefreshTokenID, p.SessionID, p.RefreshHash[:], p.RefreshExpiresAt.UTC())
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) PrincipalByAccessHash(ctx context.Context, accessHash [32]byte, now time.Time) (domain.Principal, error) {
	var p domain.Principal
	err := s.pool.QueryRow(ctx, `
		SELECT u.id, u.email, u.role, u.status, u.email_verified_at, u.created_at, s.id
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.access_token_hash = $1 AND s.revoked_at IS NULL
		  AND s.access_expires_at > $2 AND u.status = 'active'
	`, accessHash[:], now.UTC()).Scan(
		&p.User.ID, &p.User.Email, &p.User.Role, &p.User.Status,
		&p.User.EmailVerifiedAt, &p.User.CreatedAt, &p.SessionID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Principal{}, storeerrors.ErrUnauthorized
	}
	if err != nil {
		return domain.Principal{}, err
	}
	return p, nil
}

type RotateSessionParams struct {
	OldRefreshHash   [32]byte
	NewRefreshID     uuid.UUID
	NewRefreshHash   [32]byte
	NewAccessHash    [32]byte
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
	Now              time.Time
}

type RotateSessionResult struct {
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
}

func (s *Store) RotateSession(ctx context.Context, p RotateSessionParams) (RotateSessionResult, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return RotateSessionResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var tokenID, sessionID, familyID uuid.UUID
	var usedAt, revokedAt *time.Time
	var tokenExpiry, sessionRefreshExpiry time.Time
	err = tx.QueryRow(ctx, `
		SELECT rt.id, rt.session_id, s.family_id, rt.used_at, s.revoked_at,
		       rt.expires_at, s.refresh_expires_at
		FROM refresh_tokens rt JOIN sessions s ON s.id = rt.session_id
		WHERE rt.token_hash = $1
		FOR UPDATE OF rt, s
	`, p.OldRefreshHash[:]).Scan(
		&tokenID, &sessionID, &familyID, &usedAt, &revokedAt, &tokenExpiry, &sessionRefreshExpiry,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return RotateSessionResult{}, storeerrors.ErrUnauthorized
	}
	if err != nil {
		return RotateSessionResult{}, err
	}
	if usedAt != nil {
		if _, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at = COALESCE(revoked_at, $2) WHERE family_id = $1`, familyID, p.Now.UTC()); err != nil {
			return RotateSessionResult{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return RotateSessionResult{}, err
		}
		return RotateSessionResult{}, storeerrors.ErrRefreshReuse
	}
	if revokedAt != nil || !tokenExpiry.After(p.Now) || !sessionRefreshExpiry.After(p.Now) {
		return RotateSessionResult{}, storeerrors.ErrUnauthorized
	}
	effectiveAccessExpiry := p.AccessExpiresAt
	if effectiveAccessExpiry.After(sessionRefreshExpiry) {
		effectiveAccessExpiry = sessionRefreshExpiry
	}
	if !effectiveAccessExpiry.After(p.Now) {
		return RotateSessionResult{}, storeerrors.ErrUnauthorized
	}
	effectiveRefreshExpiry := p.RefreshExpiresAt
	if effectiveRefreshExpiry.After(sessionRefreshExpiry) {
		effectiveRefreshExpiry = sessionRefreshExpiry
	}
	if _, err := tx.Exec(ctx, `UPDATE refresh_tokens SET used_at = $2 WHERE id = $1`, tokenID, p.Now.UTC()); err != nil {
		return RotateSessionResult{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE sessions SET access_token_hash = $2, access_expires_at = $3, last_seen_at = $4
		WHERE id = $1
	`, sessionID, p.NewAccessHash[:], effectiveAccessExpiry.UTC(), p.Now.UTC()); err != nil {
		return RotateSessionResult{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO refresh_tokens (id, session_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)
	`, p.NewRefreshID, sessionID, p.NewRefreshHash[:], effectiveRefreshExpiry.UTC()); err != nil {
		return RotateSessionResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RotateSessionResult{}, err
	}
	return RotateSessionResult{AccessExpiresAt: effectiveAccessExpiry.UTC(), RefreshExpiresAt: effectiveRefreshExpiry.UTC()}, nil
}

func (s *Store) RevokeSession(ctx context.Context, sessionID uuid.UUID, now time.Time) error {
	result, err := s.pool.Exec(ctx, `UPDATE sessions SET revoked_at = COALESCE(revoked_at, $2) WHERE id = $1`, sessionID, now.UTC())
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return storeerrors.ErrNotFound
	}
	return nil
}

func (s *Store) RevokeAllUserSessions(ctx context.Context, userID uuid.UUID, now time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE sessions SET revoked_at = COALESCE(revoked_at, $2) WHERE user_id = $1`, userID, now.UTC())
	return err
}

func (s *Store) BootstrapOwner(ctx context.Context, id uuid.UUID, email, normalizedEmail, passwordHash string, now time.Time) (domain.User, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return domain.User{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(1947259832)"); err != nil {
		return domain.User{}, err
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE role = 'platform_owner')`).Scan(&exists); err != nil {
		return domain.User{}, err
	}
	if exists {
		return domain.User{}, storeerrors.ErrConflict
	}
	var user domain.User
	err = tx.QueryRow(ctx, `
		INSERT INTO users (id, email, normalized_email, password_hash, role, email_verified_at)
		VALUES ($1, $2, $3, $4, 'platform_owner', $5)
		RETURNING id, email, role, status, email_verified_at, created_at
	`, id, email, normalizedEmail, passwordHash, now.UTC()).Scan(
		&user.ID, &user.Email, &user.Role, &user.Status, &user.EmailVerifiedAt, &user.CreatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return domain.User{}, storeerrors.ErrConflict
		}
		return domain.User{}, err
	}
	if err := insertAudit(ctx, tx, AuditEvent{
		ActorKind: "system", Action: "platform_owner.bootstrap", TargetType: "user",
		TargetID: user.ID.String(), RequestID: "bootstrap-cli", Outcome: "success",
	}); err != nil {
		return domain.User{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.User{}, err
	}
	return user, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
