package postgres

import (
	"context"
	"fmt"
	"time"
)

const cleanupBatchSize = 1000

// CleanupExpiredSecurityState removes credentials only after they can no
// longer be used for replay detection or account recovery.
func (s *Store) CleanupExpiredSecurityState(ctx context.Context, now time.Time) error {
	retentionBoundary := now.UTC().Add(-24 * time.Hour)
	queries := []string{
		`DELETE FROM activation_challenges WHERE ctid IN (SELECT ctid FROM activation_challenges WHERE expires_at < $1 LIMIT $2)`,
		`DELETE FROM email_verification_tokens WHERE ctid IN (SELECT ctid FROM email_verification_tokens WHERE expires_at < $1 LIMIT $2)`,
		`DELETE FROM password_reset_tokens WHERE ctid IN (SELECT ctid FROM password_reset_tokens WHERE expires_at < $1 LIMIT $2)`,
		`DELETE FROM sessions WHERE ctid IN (SELECT ctid FROM sessions WHERE refresh_expires_at < $1 LIMIT $2)`,
		`DELETE FROM refresh_tokens WHERE ctid IN (SELECT ctid FROM refresh_tokens WHERE expires_at < $1 LIMIT $2)`,
	}
	for _, query := range queries {
		for {
			result, err := s.pool.Exec(ctx, query, retentionBoundary, cleanupBatchSize)
			if err != nil {
				return fmt.Errorf("clean expired security state: %w", err)
			}
			if result.RowsAffected() < cleanupBatchSize {
				break
			}
		}
	}
	return nil
}
