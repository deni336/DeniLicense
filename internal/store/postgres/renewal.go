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

type RenewalChallenge struct {
	ID              uuid.UUID
	ActivationID    uuid.UUID
	NonceHash       [32]byte
	DevicePublicKey []byte
	ExpiresAt       time.Time
	ConsumedAt      *time.Time
}

func (s *Store) CreateRenewalChallenge(ctx context.Context, id, activationID uuid.UUID, nonceHash [32]byte, expiresAt, now time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, activationID.String()); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM activation_challenges WHERE activation_id = $1 AND expires_at <= $2`, activationID, now.UTC()); err != nil {
		return err
	}
	var outstanding int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM activation_challenges
		WHERE activation_id = $1 AND consumed_at IS NULL AND expires_at > $2
	`, activationID, now.UTC()).Scan(&outstanding); err != nil {
		return err
	}
	if outstanding >= 5 {
		return storeerrors.ErrInvalid
	}
	result, err := tx.Exec(ctx, `
		INSERT INTO activation_challenges (id, activation_id, nonce_hash, expires_at)
		SELECT $1, a.id, $3, $4
		FROM activations a JOIN licenses l ON l.id = a.license_id
		WHERE a.id = $2 AND a.state = 'active' AND l.state = 'active'
		  AND l.not_before <= $5 AND (l.expires_at IS NULL OR l.expires_at > $5)
	`, id, activationID, nonceHash[:], expiresAt.UTC(), now.UTC())
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return storeerrors.ErrInvalid
	}
	return tx.Commit(ctx)
}

func (s *Store) RenewalChallenge(ctx context.Context, id uuid.UUID) (RenewalChallenge, error) {
	var challenge RenewalChallenge
	var nonceHash []byte
	err := s.pool.QueryRow(ctx, `
		SELECT c.id, c.activation_id, c.nonce_hash, a.device_public_key,
		       c.expires_at, c.consumed_at
		FROM activation_challenges c
		JOIN activations a ON a.id = c.activation_id
		WHERE c.id = $1
	`, id).Scan(
		&challenge.ID, &challenge.ActivationID, &nonceHash, &challenge.DevicePublicKey,
		&challenge.ExpiresAt, &challenge.ConsumedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return RenewalChallenge{}, storeerrors.ErrInvalid
	}
	if err != nil {
		return RenewalChallenge{}, err
	}
	if len(nonceHash) != 32 || len(challenge.DevicePublicKey) != 32 {
		return RenewalChallenge{}, storeerrors.ErrInvalid
	}
	copy(challenge.NonceHash[:], nonceHash)
	return challenge, nil
}

func (s *Store) ConsumeRenewalChallenge(ctx context.Context, challengeID uuid.UUID, nonceHash [32]byte, now time.Time, leaseTTL time.Duration, audit AuditEvent) (domain.License, domain.Activation, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return domain.License{}, domain.Activation{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var activationID, licenseID uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT c.activation_id, a.license_id
		FROM activation_challenges c
		JOIN activations a ON a.id = c.activation_id
		WHERE c.id = $1 AND c.nonce_hash = $2
	`, challengeID, nonceHash[:]).Scan(&activationID, &licenseID)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.License{}, domain.Activation{}, storeerrors.ErrInvalid
	}
	if err != nil {
		return domain.License{}, domain.Activation{}, err
	}
	license, err := lockLicenseByID(ctx, tx, licenseID)
	if err != nil {
		return domain.License{}, domain.Activation{}, err
	}
	var activationState string
	if err := tx.QueryRow(ctx, `
		SELECT state FROM activations WHERE id = $1 AND license_id = $2 FOR UPDATE
	`, activationID, licenseID).Scan(&activationState); errors.Is(err, pgx.ErrNoRows) {
		return domain.License{}, domain.Activation{}, storeerrors.ErrInvalid
	} else if err != nil {
		return domain.License{}, domain.Activation{}, err
	}
	var expiresAt time.Time
	var consumedAt *time.Time
	if err := tx.QueryRow(ctx, `
		SELECT expires_at, consumed_at FROM activation_challenges
		WHERE id = $1 AND activation_id = $2 AND nonce_hash = $3 FOR UPDATE
	`, challengeID, activationID, nonceHash[:]).Scan(&expiresAt, &consumedAt); errors.Is(err, pgx.ErrNoRows) {
		return domain.License{}, domain.Activation{}, storeerrors.ErrInvalid
	} else if err != nil {
		return domain.License{}, domain.Activation{}, err
	}
	now = time.Now().UTC()
	if consumedAt != nil || !expiresAt.After(now) || activationState != "active" {
		return domain.License{}, domain.Activation{}, storeerrors.ErrInvalid
	}
	if license.State != "active" || now.Before(license.NotBefore) || (license.ExpiresAt != nil && !now.Before(*license.ExpiresAt)) {
		return domain.License{}, domain.Activation{}, storeerrors.ErrLicenseState
	}
	leaseExpiry := now.Add(leaseTTL)
	graceExpiry := now.Add(time.Duration(license.OfflineGraceSeconds) * time.Second)
	if leaseExpiry.After(graceExpiry) {
		leaseExpiry = graceExpiry
	}
	if license.ExpiresAt != nil && leaseExpiry.After(*license.ExpiresAt) {
		leaseExpiry = *license.ExpiresAt
	}
	if _, err := tx.Exec(ctx, `UPDATE activation_challenges SET consumed_at = $2 WHERE id = $1`, challengeID, now.UTC()); err != nil {
		return domain.License{}, domain.Activation{}, err
	}
	var activation domain.Activation
	err = tx.QueryRow(ctx, `
		UPDATE activations SET last_seen_at = GREATEST(last_seen_at, $2), lease_expires_at = $3, updated_at = $2
		WHERE id = $1 AND state = 'active'
		RETURNING id, license_id, label, state, activated_at, last_seen_at, lease_expires_at
	`, activationID, now.UTC(), leaseExpiry.UTC()).Scan(
		&activation.ID, &activation.LicenseID, &activation.Label, &activation.State,
		&activation.ActivatedAt, &activation.LastSeenAt, &activation.LeaseExpiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.License{}, domain.Activation{}, storeerrors.ErrLicenseState
	}
	if err != nil {
		return domain.License{}, domain.Activation{}, err
	}
	audit.TargetID = activationID.String()
	if err := insertAudit(ctx, tx, audit); err != nil {
		return domain.License{}, domain.Activation{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.License{}, domain.Activation{}, err
	}
	return license, activation, nil
}
