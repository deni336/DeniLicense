package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/deni336/DeniLicense/internal/domain"
	storeerrors "github.com/deni336/DeniLicense/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type AuditEvent struct {
	ActorUserID *uuid.UUID
	ActorKind   string
	Action      string
	TargetType  string
	TargetID    string
	RequestID   string
	Outcome     string
	Details     map[string]any
}

type CreateProductParams struct {
	ID          uuid.UUID
	Code        string
	Name        string
	Description string
	CreatedBy   uuid.UUID
	Audit       AuditEvent
}

func (s *Store) CreateProduct(ctx context.Context, p CreateProductParams) (domain.Product, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.Product{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var product domain.Product
	err = tx.QueryRow(ctx, `
		INSERT INTO products (id, code, name, description, created_by)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, code, name, description, status, created_at, updated_at
	`, p.ID, p.Code, p.Name, p.Description, p.CreatedBy).Scan(
		&product.ID, &product.Code, &product.Name, &product.Description,
		&product.Status, &product.CreatedAt, &product.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return domain.Product{}, storeerrors.ErrConflict
		}
		return domain.Product{}, err
	}
	p.Audit.TargetID = product.ID.String()
	if err := insertAudit(ctx, tx, p.Audit); err != nil {
		return domain.Product{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.Product{}, err
	}
	return product, nil
}

func (s *Store) ListProducts(ctx context.Context, includeRetired bool) ([]domain.Product, error) {
	query := `SELECT id, code, name, description, status, created_at, updated_at FROM products`
	if !includeRetired {
		query += ` WHERE status = 'active'`
	}
	query += ` ORDER BY code`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	products := make([]domain.Product, 0)
	for rows.Next() {
		var p domain.Product
		if err := rows.Scan(&p.ID, &p.Code, &p.Name, &p.Description, &p.Status, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		products = append(products, p)
	}
	return products, rows.Err()
}

func (s *Store) ProductByCode(ctx context.Context, code string) (domain.Product, error) {
	var p domain.Product
	err := s.pool.QueryRow(ctx, `
		SELECT id, code, name, description, status, created_at, updated_at
		FROM products WHERE code = $1
	`, code).Scan(&p.ID, &p.Code, &p.Name, &p.Description, &p.Status, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Product{}, storeerrors.ErrNotFound
	}
	return p, err
}

type RegisterIssuerParams struct {
	KeyID       string
	Issuer      string
	PublicKey   []byte
	Fingerprint [32]byte
	NotBefore   time.Time
	NotAfter    *time.Time
	CreatedBy   uuid.UUID
	Audit       AuditEvent
}

func (s *Store) RegisterIssuer(ctx context.Context, p RegisterIssuerParams) (domain.IssuerKey, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.IssuerKey{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var key domain.IssuerKey
	err = tx.QueryRow(ctx, `
		INSERT INTO issuer_keys
		(key_id, issuer, public_key, fingerprint_sha256, not_before, not_after, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING key_id, issuer, public_key, status, not_before, not_after, created_at
	`, p.KeyID, p.Issuer, p.PublicKey, p.Fingerprint[:], p.NotBefore.UTC(), nullableTime(p.NotAfter), p.CreatedBy).Scan(
		&key.KeyID, &key.Issuer, &key.PublicKey, &key.Status, &key.NotBefore, &key.NotAfter, &key.CreatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return domain.IssuerKey{}, storeerrors.ErrConflict
		}
		return domain.IssuerKey{}, err
	}
	p.Audit.TargetID = key.KeyID
	if err := insertAudit(ctx, tx, p.Audit); err != nil {
		return domain.IssuerKey{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.IssuerKey{}, err
	}
	return key, nil
}

func (s *Store) IssuerByKeyID(ctx context.Context, keyID string) (domain.IssuerKey, error) {
	var key domain.IssuerKey
	err := s.pool.QueryRow(ctx, `
		SELECT key_id, issuer, public_key, status, not_before, not_after, created_at
		FROM issuer_keys WHERE key_id = $1
	`, keyID).Scan(&key.KeyID, &key.Issuer, &key.PublicKey, &key.Status, &key.NotBefore, &key.NotAfter, &key.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.IssuerKey{}, storeerrors.ErrNotFound
	}
	return key, err
}

func (s *Store) UpdateIssuerStatus(ctx context.Context, keyID, status string, actor uuid.UUID, audit AuditEvent) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var current string
	if err := tx.QueryRow(ctx, `SELECT status FROM issuer_keys WHERE key_id = $1 FOR UPDATE`, keyID).Scan(&current); errors.Is(err, pgx.ErrNoRows) {
		return storeerrors.ErrNotFound
	} else if err != nil {
		return err
	}
	if current == "revoked" && status != "revoked" {
		return storeerrors.ErrConflict
	}
	if current == status {
		return tx.Commit(ctx)
	}
	result, err := tx.Exec(ctx, `UPDATE issuer_keys SET status = $2, updated_at = now() WHERE key_id = $1`, keyID, status)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return storeerrors.ErrNotFound
	}
	audit.TargetID = keyID
	audit.ActorUserID = &actor
	if err := insertAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type CreateLicenseParams struct {
	ID                  uuid.UUID
	Serial              uuid.UUID
	ProductID           uuid.UUID
	Source              string
	IssuerKeyID         *string
	ImportArtifact      *string
	ImportArtifactHash  *[32]byte
	CreationRequestHash *[32]byte
	ClaimCodeHash       [32]byte
	ClaimCodeSuffix     string
	Subject             string
	IssuedAt            time.Time
	NotBefore           time.Time
	ExpiresAt           *time.Time
	MaxActivations      int
	OfflineGraceSeconds int
	Entitlements        map[string]any
	Metadata            map[string]any
	CreatedBy           uuid.UUID
	Audit               AuditEvent
}

// CreateLicense takes a transaction-scoped advisory lock for its serial. Exact
// offline re-imports and online idempotency retries return the original row;
// the same serial with different authenticated/request bytes is a conflict.
func (s *Store) CreateLicense(ctx context.Context, p CreateLicenseParams) (domain.License, bool, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return domain.License{}, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, p.Serial.String()); err != nil {
		return domain.License{}, false, err
	}
	if p.Source == "offline_import" || p.Source == "online" {
		var existingID uuid.UUID
		var existingSource string
		var existingArtifactHash, existingRequestHash []byte
		err := tx.QueryRow(ctx, `
			SELECT id, source, import_artifact_hash, creation_request_hash
			FROM licenses WHERE serial = $1 FOR UPDATE
		`, p.Serial).Scan(&existingID, &existingSource, &existingArtifactHash, &existingRequestHash)
		if err == nil {
			sameOffline := p.Source == "offline_import" && existingSource == p.Source && p.ImportArtifactHash != nil && equal32(existingArtifactHash, *p.ImportArtifactHash)
			sameOnline := p.Source == "online" && existingSource == p.Source && p.CreationRequestHash != nil && equal32(existingRequestHash, *p.CreationRequestHash)
			if sameOffline || sameOnline {
				license, loadErr := licenseByIDTx(ctx, tx, existingID)
				return license, true, loadErr
			}
			return domain.License{}, false, storeerrors.ErrConflict
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return domain.License{}, false, err
		}
	}
	if p.Source == "offline_import" {
		if p.IssuerKeyID == nil {
			return domain.License{}, false, storeerrors.ErrInvalid
		}
		var issuerStatus string
		var issuerNotBefore time.Time
		var issuerNotAfter *time.Time
		err := tx.QueryRow(ctx, `
			SELECT status, not_before, not_after FROM issuer_keys
			WHERE key_id = $1 FOR SHARE
		`, *p.IssuerKeyID).Scan(&issuerStatus, &issuerNotBefore, &issuerNotAfter)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.License{}, false, storeerrors.ErrInvalid
		}
		if err != nil {
			return domain.License{}, false, err
		}
		if issuerStatus != "active" || p.IssuedAt.Before(issuerNotBefore) || (issuerNotAfter != nil && !p.IssuedAt.Before(*issuerNotAfter)) {
			return domain.License{}, false, storeerrors.ErrInvalid
		}
	}

	entitlements, err := json.Marshal(p.Entitlements)
	if err != nil {
		return domain.License{}, false, storeerrors.ErrInvalid
	}
	metadata, err := json.Marshal(p.Metadata)
	if err != nil {
		return domain.License{}, false, storeerrors.ErrInvalid
	}
	var artifact any
	if p.ImportArtifact != nil {
		artifact = *p.ImportArtifact
	}
	var artifactHash any
	if p.ImportArtifactHash != nil {
		artifactHash = p.ImportArtifactHash[:]
	}
	var requestHash any
	if p.CreationRequestHash != nil {
		requestHash = p.CreationRequestHash[:]
	}
	var issuer any
	if p.IssuerKeyID != nil {
		issuer = *p.IssuerKeyID
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO licenses
		(id, serial, product_id, source, issuer_key_id, import_artifact, import_artifact_hash, creation_request_hash,
		 claim_code_hash, claim_code_suffix, subject, issued_at, not_before, expires_at,
		 max_activations, offline_grace_seconds, entitlements, metadata, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
	`, p.ID, p.Serial, p.ProductID, p.Source, issuer, artifact, artifactHash, requestHash,
		p.ClaimCodeHash[:], p.ClaimCodeSuffix, p.Subject, p.IssuedAt.UTC(), p.NotBefore.UTC(), nullableTime(p.ExpiresAt),
		p.MaxActivations, p.OfflineGraceSeconds, entitlements, metadata, p.CreatedBy)
	if err != nil {
		if isUniqueViolation(err) {
			return domain.License{}, false, storeerrors.ErrConflict
		}
		return domain.License{}, false, err
	}
	p.Audit.TargetID = p.ID.String()
	if err := insertAudit(ctx, tx, p.Audit); err != nil {
		return domain.License{}, false, err
	}
	license, err := licenseByIDTx(ctx, tx, p.ID)
	if err != nil {
		return domain.License{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.License{}, false, err
	}
	return license, false, nil
}

func (s *Store) ClaimLicense(ctx context.Context, codeHash [32]byte, userID uuid.UUID, now time.Time, audit AuditEvent) (domain.License, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return domain.License{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var id uuid.UUID
	var ownerID *uuid.UUID
	var state string
	var notBefore time.Time
	var expiresAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT id, owner_user_id, state, not_before, expires_at
		FROM licenses WHERE claim_code_hash = $1 FOR UPDATE
	`, codeHash[:]).Scan(&id, &ownerID, &state, &notBefore, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.License{}, storeerrors.ErrInvalid
	}
	if err != nil {
		return domain.License{}, err
	}
	if ownerID != nil {
		if *ownerID == userID {
			return licenseByIDTx(ctx, tx, id)
		}
		return domain.License{}, storeerrors.ErrInvalid
	}
	if state != "active" || now.Before(notBefore) || (expiresAt != nil && !now.Before(*expiresAt)) {
		return domain.License{}, storeerrors.ErrInvalid
	}
	_, err = tx.Exec(ctx, `
		UPDATE licenses SET owner_user_id = $2, claim_consumed_at = $3, updated_at = $3
		WHERE id = $1
	`, id, userID, now.UTC())
	if err != nil {
		return domain.License{}, err
	}
	audit.TargetID = id.String()
	if err := insertAudit(ctx, tx, audit); err != nil {
		return domain.License{}, err
	}
	license, err := licenseByIDTx(ctx, tx, id)
	if err != nil {
		return domain.License{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.License{}, err
	}
	return license, nil
}

func (s *Store) ListUserLicenses(ctx context.Context, userID uuid.UUID) ([]domain.License, error) {
	rows, err := s.pool.Query(ctx, licenseSelect+` WHERE l.owner_user_id = $1 ORDER BY l.created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	licenses := make([]domain.License, 0)
	for rows.Next() {
		license, err := scanLicense(rows)
		if err != nil {
			return nil, err
		}
		licenses = append(licenses, license)
	}
	return licenses, rows.Err()
}

func (s *Store) LicenseForOwner(ctx context.Context, licenseID, userID uuid.UUID) (domain.License, error) {
	license, err := scanLicense(s.pool.QueryRow(ctx, licenseSelect+` WHERE l.id = $1 AND l.owner_user_id = $2`, licenseID, userID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.License{}, storeerrors.ErrNotFound
	}
	return license, err
}

type ActivateParams struct {
	ID              uuid.UUID
	LicenseID       uuid.UUID
	OwnerUserID     uuid.UUID
	DevicePublicKey []byte
	Label           string
	Now             time.Time
	LeaseExpiresAt  time.Time
	Audit           AuditEvent
}

func (s *Store) Activate(ctx context.Context, p ActivateParams) (domain.License, domain.Activation, bool, error) {
	leaseTTL := p.LeaseExpiresAt.Sub(p.Now)
	if leaseTTL <= 0 {
		return domain.License{}, domain.Activation{}, false, storeerrors.ErrInvalid
	}
	thumbprint := deviceKeyThumbprint(p.DevicePublicKey)
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return domain.License{}, domain.Activation{}, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	license, err := lockOwnedLicense(ctx, tx, p.LicenseID, p.OwnerUserID)
	if err != nil {
		return domain.License{}, domain.Activation{}, false, err
	}
	p.Now = time.Now().UTC()
	p.LeaseExpiresAt = p.Now.Add(leaseTTL)
	if license.State != "active" || p.Now.Before(license.NotBefore) || (license.ExpiresAt != nil && !p.Now.Before(*license.ExpiresAt)) {
		return domain.License{}, domain.Activation{}, false, storeerrors.ErrLicenseState
	}
	graceExpiry := p.Now.Add(time.Duration(license.OfflineGraceSeconds) * time.Second)
	if p.LeaseExpiresAt.After(graceExpiry) {
		p.LeaseExpiresAt = graceExpiry
	}
	if license.ExpiresAt != nil && p.LeaseExpiresAt.After(*license.ExpiresAt) {
		p.LeaseExpiresAt = *license.ExpiresAt
	}
	var activation domain.Activation
	err = tx.QueryRow(ctx, `
		SELECT id, license_id, label, state, activated_at, last_seen_at, lease_expires_at
		FROM activations WHERE license_id = $1 AND device_key_thumbprint = $2 FOR UPDATE
	`, p.LicenseID, thumbprint[:]).Scan(
		&activation.ID, &activation.LicenseID, &activation.Label, &activation.State,
		&activation.ActivatedAt, &activation.LastSeenAt, &activation.LeaseExpiresAt,
	)
	if err == nil && activation.State == "active" {
		err = tx.QueryRow(ctx, `
			UPDATE activations SET last_seen_at = GREATEST(last_seen_at, $2), lease_expires_at = $3, label = $4, updated_at = $2
			WHERE id = $1
			RETURNING id, license_id, label, state, activated_at, last_seen_at, lease_expires_at
		`, activation.ID, p.Now.UTC(), p.LeaseExpiresAt.UTC(), p.Label).Scan(
			&activation.ID, &activation.LicenseID, &activation.Label, &activation.State,
			&activation.ActivatedAt, &activation.LastSeenAt, &activation.LeaseExpiresAt,
		)
		if err != nil {
			return domain.License{}, domain.Activation{}, false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return domain.License{}, domain.Activation{}, false, err
		}
		return license, activation, true, nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return domain.License{}, domain.Activation{}, false, err
	}
	var activeCount int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM activations WHERE license_id = $1 AND state = 'active'`, p.LicenseID).Scan(&activeCount); err != nil {
		return domain.License{}, domain.Activation{}, false, err
	}
	if activeCount >= license.MaxActivations {
		return domain.License{}, domain.Activation{}, false, storeerrors.ErrSeatLimit
	}
	if activation.ID != uuid.Nil {
		err = tx.QueryRow(ctx, `
			UPDATE activations SET state = 'active', deactivated_at = NULL, label = $2,
			activated_at = $3, last_seen_at = $3, lease_expires_at = $4, updated_at = $3
			WHERE id = $1
			RETURNING id, license_id, label, state, activated_at, last_seen_at, lease_expires_at
		`, activation.ID, p.Label, p.Now.UTC(), p.LeaseExpiresAt.UTC()).Scan(
			&activation.ID, &activation.LicenseID, &activation.Label, &activation.State,
			&activation.ActivatedAt, &activation.LastSeenAt, &activation.LeaseExpiresAt,
		)
	} else {
		err = tx.QueryRow(ctx, `
			INSERT INTO activations
			(id, license_id, device_key_thumbprint, device_public_key, label, lease_expires_at)
			VALUES ($1, $2, $3, $4, $5, $6)
			RETURNING id, license_id, label, state, activated_at, last_seen_at, lease_expires_at
		`, p.ID, p.LicenseID, thumbprint[:], p.DevicePublicKey, p.Label, p.LeaseExpiresAt.UTC()).Scan(
			&activation.ID, &activation.LicenseID, &activation.Label, &activation.State,
			&activation.ActivatedAt, &activation.LastSeenAt, &activation.LeaseExpiresAt,
		)
	}
	if err != nil {
		return domain.License{}, domain.Activation{}, false, err
	}
	p.Audit.TargetID = activation.ID.String()
	if err := insertAudit(ctx, tx, p.Audit); err != nil {
		return domain.License{}, domain.Activation{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.License{}, domain.Activation{}, false, err
	}
	return license, activation, false, nil
}

func (s *Store) Deactivate(ctx context.Context, activationID, ownerUserID uuid.UUID, now time.Time, audit AuditEvent) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	result, err := tx.Exec(ctx, `
		UPDATE activations a SET state = 'deactivated', deactivated_at = $3, updated_at = $3
		FROM licenses l
		WHERE a.id = $1 AND l.id = a.license_id AND l.owner_user_id = $2 AND a.state = 'active'
	`, activationID, ownerUserID, now.UTC())
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		var exists bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM activations a
				JOIN licenses l ON l.id = a.license_id
				WHERE a.id = $1 AND l.owner_user_id = $2
			)
		`, activationID, ownerUserID).Scan(&exists); err != nil {
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

func (s *Store) SetLicenseState(ctx context.Context, licenseID uuid.UUID, state string, now time.Time, audit AuditEvent) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var current string
	if err := tx.QueryRow(ctx, `SELECT state FROM licenses WHERE id = $1 FOR UPDATE`, licenseID).Scan(&current); errors.Is(err, pgx.ErrNoRows) {
		return storeerrors.ErrNotFound
	} else if err != nil {
		return err
	}
	if current == "revoked" && state != "revoked" {
		return storeerrors.ErrConflict
	}
	if current == state {
		return tx.Commit(ctx)
	}
	result, err := tx.Exec(ctx, `
		UPDATE licenses SET state = $2, revision = revision + 1, updated_at = $3 WHERE id = $1
	`, licenseID, state, now.UTC())
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return storeerrors.ErrNotFound
	}
	if state != "active" {
		_, err = tx.Exec(ctx, `
			UPDATE activations SET state = 'deactivated', deactivated_at = $2, updated_at = $2
			WHERE license_id = $1 AND state = 'active'
		`, licenseID, now.UTC())
		if err != nil {
			return err
		}
	}
	audit.TargetID = licenseID.String()
	if err := insertAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

const licenseSelect = `
	SELECT l.id, l.serial, l.product_id, p.code, l.owner_user_id, l.source, l.state,
	       l.subject, l.issued_at, l.not_before, l.expires_at, l.max_activations,
	       l.offline_grace_seconds, l.entitlements, l.metadata, l.revision,
	       l.claim_code_suffix, l.claim_consumed_at, l.created_at, l.updated_at
	FROM licenses l JOIN products p ON p.id = l.product_id`

type rowScanner interface{ Scan(...any) error }

func scanLicense(row rowScanner) (domain.License, error) {
	var l domain.License
	err := row.Scan(
		&l.ID, &l.Serial, &l.ProductID, &l.ProductCode, &l.OwnerUserID, &l.Source,
		&l.State, &l.Subject, &l.IssuedAt, &l.NotBefore, &l.ExpiresAt,
		&l.MaxActivations, &l.OfflineGraceSeconds, &l.Entitlements, &l.Metadata,
		&l.Revision, &l.ClaimCodeSuffix, &l.ClaimedAt, &l.CreatedAt, &l.UpdatedAt,
	)
	return l, err
}

func licenseByIDTx(ctx context.Context, tx pgx.Tx, id uuid.UUID) (domain.License, error) {
	license, err := scanLicense(tx.QueryRow(ctx, licenseSelect+` WHERE l.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.License{}, storeerrors.ErrNotFound
	}
	return license, err
}

func lockLicenseByID(ctx context.Context, tx pgx.Tx, id uuid.UUID) (domain.License, error) {
	license, err := scanLicense(tx.QueryRow(ctx, licenseSelect+` WHERE l.id = $1 FOR UPDATE OF l`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.License{}, storeerrors.ErrNotFound
	}
	return license, err
}

func lockOwnedLicense(ctx context.Context, tx pgx.Tx, licenseID, ownerID uuid.UUID) (domain.License, error) {
	license, err := scanLicense(tx.QueryRow(ctx, licenseSelect+` WHERE l.id = $1 AND l.owner_user_id = $2 FOR UPDATE OF l`, licenseID, ownerID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.License{}, storeerrors.ErrNotFound
	}
	return license, err
}

func insertAudit(ctx context.Context, tx pgx.Tx, e AuditEvent) error {
	if e.ActorKind == "" {
		e.ActorKind = "user"
	}
	if e.Outcome == "" {
		e.Outcome = "success"
	}
	if e.Details == nil {
		e.Details = map[string]any{}
	}
	if strings.TrimSpace(e.RequestID) == "" {
		e.RequestID = "unknown"
	}
	details, err := json.Marshal(e.Details)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO audit_events
		(actor_user_id, actor_kind, action, target_type, target_id, request_id, outcome, details)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	`, e.ActorUserID, e.ActorKind, e.Action, e.TargetType, e.TargetID, e.RequestID, e.Outcome, details)
	return err
}

func deviceKeyThumbprint(publicKey []byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("DeniLicense/device-key/v1\x00"))
	_, _ = h.Write(publicKey)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func equal32(value []byte, expected [32]byte) bool {
	return len(value) == 32 && string(value) == string(expected[:])
}
