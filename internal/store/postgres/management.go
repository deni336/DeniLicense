package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/deni336/DeniLicense/internal/domain"
	storeerrors "github.com/deni336/DeniLicense/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const ownerManagementLock int64 = 1947259832

func (s *Store) UserByID(ctx context.Context, id uuid.UUID) (domain.User, error) {
	return scanUser(s.pool.QueryRow(ctx, `
		SELECT id, email, role, status, email_verified_at, created_at
		FROM users WHERE id = $1
	`, id))
}

func (s *Store) ListUsers(ctx context.Context, normalizedEmail string, limit int) ([]domain.User, error) {
	if limit < 1 || limit > 200 {
		return nil, storeerrors.ErrInvalid
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, email, role, status, email_verified_at, created_at
		FROM users
		WHERE ($1 = '' OR normalized_email = $1)
		ORDER BY created_at DESC, id DESC
		LIMIT $2
	`, normalizedEmail, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]domain.User, 0)
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, user)
	}
	return items, rows.Err()
}

type UpdateUserAccessParams struct {
	UserID uuid.UUID
	Role   *domain.Role
	Status *string
	Audit  AuditEvent
}

func (s *Store) UpdateUserAccess(ctx context.Context, p UpdateUserAccessParams) (domain.User, error) {
	if (p.Role == nil) == (p.Status == nil) {
		return domain.User{}, storeerrors.ErrInvalid
	}
	if p.Role != nil && !validRole(*p.Role) {
		return domain.User{}, storeerrors.ErrInvalid
	}
	if p.Status != nil && *p.Status != "active" && *p.Status != "disabled" {
		return domain.User{}, storeerrors.ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return domain.User{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, ownerManagementLock); err != nil {
		return domain.User{}, err
	}
	current, err := scanUser(tx.QueryRow(ctx, `
		SELECT id, email, role, status, email_verified_at, created_at
		FROM users WHERE id = $1 FOR UPDATE
	`, p.UserID))
	if err != nil {
		return domain.User{}, err
	}
	desiredRole := current.Role
	desiredStatus := current.Status
	if p.Role != nil {
		desiredRole = *p.Role
	}
	if p.Status != nil {
		desiredStatus = *p.Status
	}
	if desiredRole == current.Role && desiredStatus == current.Status {
		if err := tx.Commit(ctx); err != nil {
			return domain.User{}, err
		}
		return current, nil
	}
	wasActiveOwner := current.Role == domain.RolePlatformOwner && current.Status == "active"
	willBeActiveOwner := desiredRole == domain.RolePlatformOwner && desiredStatus == "active"
	if wasActiveOwner && !willBeActiveOwner {
		var activeOwners int
		if err := tx.QueryRow(ctx, `
			SELECT count(*) FROM users WHERE role = 'platform_owner' AND status = 'active'
		`).Scan(&activeOwners); err != nil {
			return domain.User{}, err
		}
		if activeOwners <= 1 {
			return domain.User{}, storeerrors.ErrConflict
		}
	}
	now := time.Now().UTC()
	updated, err := scanUser(tx.QueryRow(ctx, `
		UPDATE users SET role = $2, status = $3, updated_at = $4
		WHERE id = $1
		RETURNING id, email, role, status, email_verified_at, created_at
	`, p.UserID, desiredRole, desiredStatus, now))
	if err != nil {
		return domain.User{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE sessions SET revoked_at = COALESCE(revoked_at, $2) WHERE user_id = $1
	`, p.UserID, now); err != nil {
		return domain.User{}, err
	}
	if p.Audit.Details == nil {
		p.Audit.Details = make(map[string]any)
	}
	p.Audit.TargetID = p.UserID.String()
	p.Audit.Details["previousRole"] = current.Role
	p.Audit.Details["role"] = updated.Role
	p.Audit.Details["previousStatus"] = current.Status
	p.Audit.Details["status"] = updated.Status
	if err := insertAudit(ctx, tx, p.Audit); err != nil {
		return domain.User{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.User{}, err
	}
	return updated, nil
}

func validRole(role domain.Role) bool {
	switch role {
	case domain.RolePlatformOwner, domain.RoleLicenseAdmin, domain.RoleSupport, domain.RoleAuditor, domain.RoleCustomer:
		return true
	default:
		return false
	}
}

func scanUser(row rowScanner) (domain.User, error) {
	var user domain.User
	err := row.Scan(&user.ID, &user.Email, &user.Role, &user.Status, &user.EmailVerifiedAt, &user.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.User{}, storeerrors.ErrNotFound
	}
	return user, err
}

type LicenseListFilter struct {
	Serial               *uuid.UUID
	OwnerNormalizedEmail string
	ClaimCodeSuffix      string
	ProductCode          string
	State                string
	Limit                int
}

const managedLicenseSelect = `
	SELECT l.id, l.serial, l.product_id, p.code, l.owner_user_id, COALESCE(u.email, ''), l.source, l.state,
	       l.subject, l.issued_at, l.not_before, l.expires_at, l.max_activations,
	       l.offline_grace_seconds, l.entitlements, l.metadata, l.revision,
	       l.claim_code_suffix, l.claim_consumed_at, l.created_at, l.updated_at
	FROM licenses l
	JOIN products p ON p.id = l.product_id
	LEFT JOIN users u ON u.id = l.owner_user_id`

func (s *Store) ListLicenses(ctx context.Context, filter LicenseListFilter) ([]domain.License, error) {
	if filter.Limit < 1 || filter.Limit > 200 {
		return nil, storeerrors.ErrInvalid
	}
	var serial any
	if filter.Serial != nil {
		serial = *filter.Serial
	}
	rows, err := s.pool.Query(ctx, managedLicenseSelect+`
		WHERE ($1::uuid IS NULL OR l.serial = $1)
		  AND ($2 = '' OR u.normalized_email = $2)
		  AND ($3 = '' OR l.claim_code_suffix = $3)
		  AND ($4 = '' OR p.code = $4)
		  AND ($5 = '' OR l.state = $5)
		ORDER BY l.created_at DESC, l.id DESC
		LIMIT $6
	`, serial, filter.OwnerNormalizedEmail, filter.ClaimCodeSuffix, filter.ProductCode, filter.State, filter.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]domain.License, 0)
	for rows.Next() {
		license, err := scanManagedLicense(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, license)
	}
	return items, rows.Err()
}

func (s *Store) LicenseByID(ctx context.Context, id uuid.UUID) (domain.License, error) {
	license, err := scanManagedLicense(s.pool.QueryRow(ctx, managedLicenseSelect+` WHERE l.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.License{}, storeerrors.ErrNotFound
	}
	return license, err
}

func scanManagedLicense(row rowScanner) (domain.License, error) {
	var license domain.License
	err := row.Scan(
		&license.ID, &license.Serial, &license.ProductID, &license.ProductCode,
		&license.OwnerUserID, &license.OwnerEmail, &license.Source, &license.State,
		&license.Subject, &license.IssuedAt, &license.NotBefore, &license.ExpiresAt,
		&license.MaxActivations, &license.OfflineGraceSeconds, &license.Entitlements,
		&license.Metadata, &license.Revision, &license.ClaimCodeSuffix, &license.ClaimedAt,
		&license.CreatedAt, &license.UpdatedAt,
	)
	return license, err
}

const activationSelect = `
	SELECT id, license_id, label, state, activated_at, last_seen_at, lease_expires_at
	FROM activations`

func (s *Store) ListActivationsForOwner(ctx context.Context, licenseID, ownerID uuid.UUID) ([]domain.Activation, error) {
	var exists bool
	if err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM licenses WHERE id = $1 AND owner_user_id = $2)
	`, licenseID, ownerID).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, storeerrors.ErrNotFound
	}
	return s.listActivations(ctx, licenseID)
}

func (s *Store) ListActivations(ctx context.Context, licenseID uuid.UUID) ([]domain.Activation, error) {
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM licenses WHERE id = $1)`, licenseID).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, storeerrors.ErrNotFound
	}
	return s.listActivations(ctx, licenseID)
}

func (s *Store) listActivations(ctx context.Context, licenseID uuid.UUID) ([]domain.Activation, error) {
	rows, err := s.pool.Query(ctx, activationSelect+`
		WHERE license_id = $1 ORDER BY activated_at DESC, id DESC
	`, licenseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]domain.Activation, 0)
	for rows.Next() {
		var activation domain.Activation
		if err := rows.Scan(
			&activation.ID, &activation.LicenseID, &activation.Label, &activation.State,
			&activation.ActivatedAt, &activation.LastSeenAt, &activation.LeaseExpiresAt,
		); err != nil {
			return nil, err
		}
		items = append(items, activation)
	}
	return items, rows.Err()
}

func (s *Store) DeactivateActivation(ctx context.Context, activationID uuid.UUID, audit AuditEvent) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	now := time.Now().UTC()
	result, err := tx.Exec(ctx, `
		UPDATE activations SET state = 'deactivated', deactivated_at = $2, updated_at = $2
		WHERE id = $1 AND state = 'active'
	`, activationID, now)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM activations WHERE id = $1)`, activationID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return storeerrors.ErrNotFound
		}
		return tx.Commit(ctx)
	}
	audit.TargetID = activationID.String()
	if err := insertAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type AuditListFilter struct {
	BeforeID    int64
	Action      string
	TargetType  string
	TargetID    string
	ActorUserID *uuid.UUID
	Limit       int
}

func (s *Store) ListAuditEvents(ctx context.Context, filter AuditListFilter) ([]domain.AuditRecord, error) {
	if filter.BeforeID < 0 || filter.Limit < 1 || filter.Limit > 200 {
		return nil, storeerrors.ErrInvalid
	}
	var actor any
	if filter.ActorUserID != nil {
		actor = *filter.ActorUserID
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, occurred_at, actor_user_id, actor_kind, action, target_type,
		       target_id, request_id, outcome, details
		FROM audit_events
		WHERE ($1 = 0 OR id < $1)
		  AND ($2 = '' OR action = $2)
		  AND ($3 = '' OR target_type = $3)
		  AND ($4 = '' OR target_id = $4)
		  AND ($5::uuid IS NULL OR actor_user_id = $5)
		ORDER BY id DESC
		LIMIT $6
	`, filter.BeforeID, filter.Action, filter.TargetType, filter.TargetID, actor, filter.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]domain.AuditRecord, 0)
	for rows.Next() {
		var record domain.AuditRecord
		if err := rows.Scan(
			&record.ID, &record.OccurredAt, &record.ActorUserID, &record.ActorKind,
			&record.Action, &record.TargetType, &record.TargetID, &record.RequestID,
			&record.Outcome, &record.Details,
		); err != nil {
			return nil, err
		}
		items = append(items, record)
	}
	return items, rows.Err()
}
