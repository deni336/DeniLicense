package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

type Store struct {
	pool *pgxpool.Pool
}

type migration struct {
	version  int64
	filename string
	sql      []byte
	checksum [32]byte
}

func Open(ctx context.Context, databaseURL string) (*Store, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database URL: %w", err)
	}
	config.MaxConns = 20
	config.MinConns = 2
	config.MaxConnLifetime = time.Hour
	config.MaxConnIdleTime = 15 * time.Minute
	config.HealthCheckPeriod = 30 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() { s.pool.Close() }

func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

func (s *Store) Migrate(ctx context.Context) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	// A stable application-specific lock prevents concurrent first-start migration.
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock(1947259831)"); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() { _, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock(1947259831)") }()

	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version bigint PRIMARY KEY,
			filename text NOT NULL,
			checksum bytea NOT NULL CHECK (octet_length(checksum) = 32),
			applied_at timestamptz NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}
	migrations, err := embeddedMigrations()
	if err != nil {
		return err
	}
	for _, migration := range migrations {
		var appliedFilename string
		var appliedChecksum []byte
		err := conn.QueryRow(ctx, `SELECT filename, checksum FROM schema_migrations WHERE version = $1`, migration.version).Scan(&appliedFilename, &appliedChecksum)
		if err == nil {
			if appliedFilename != migration.filename || !bytes.Equal(appliedChecksum, migration.checksum[:]) {
				return fmt.Errorf("applied migration %d does not match embedded filename/checksum", migration.version)
			}
			continue
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("inspect migration %d: %w", migration.version, err)
		}
		tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return fmt.Errorf("begin migration %d: %w", migration.version, err)
		}
		if _, err := tx.Exec(ctx, string(migration.sql)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply migration %d: %w", migration.version, err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO schema_migrations(version, filename, checksum) VALUES ($1, $2, $3)
		`, migration.version, migration.filename, migration.checksum[:]); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record migration %d: %w", migration.version, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %d: %w", migration.version, err)
		}
	}
	return nil
}

// VerifyMigrations checks the exact embedded migration catalog without
// issuing DDL, allowing the runtime service to use a role without CREATE or
// ALTER privileges after a separate migration job has completed.
func (s *Store) VerifyMigrations(ctx context.Context) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock(1947259831)"); err != nil {
		return fmt.Errorf("acquire migration verification lock: %w", err)
	}
	defer func() { _, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock(1947259831)") }()

	migrations, err := embeddedMigrations()
	if err != nil {
		return err
	}
	rows, err := conn.Query(ctx, `SELECT version, filename, checksum FROM schema_migrations ORDER BY version`)
	if err != nil {
		return fmt.Errorf("read migration ledger: %w", err)
	}
	defer rows.Close()
	index := 0
	for rows.Next() {
		var version int64
		var filename string
		var checksum []byte
		if err := rows.Scan(&version, &filename, &checksum); err != nil {
			return fmt.Errorf("scan migration ledger: %w", err)
		}
		if index >= len(migrations) {
			return fmt.Errorf("database has unknown migration version %d", version)
		}
		expected := migrations[index]
		if version != expected.version || filename != expected.filename || !bytes.Equal(checksum, expected.checksum[:]) {
			return fmt.Errorf("database migration %d does not match the embedded catalog", version)
		}
		index++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read migration ledger: %w", err)
	}
	if index != len(migrations) {
		return fmt.Errorf("database is missing migration %d", migrations[index].version)
	}
	return nil
}

func embeddedMigrations() ([]migration, error) {
	entries, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("list embedded migrations: %w", err)
	}
	migrations := make([]migration, 0, len(entries))
	seenVersions := make(map[int64]string)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(entry.Name(), "_")
		if !ok {
			return nil, fmt.Errorf("migration %q has no numeric prefix", entry.Name())
		}
		version, err := strconv.ParseInt(prefix, 10, 64)
		if err != nil || version <= 0 {
			return nil, fmt.Errorf("migration %q has an invalid version", entry.Name())
		}
		if previous, exists := seenVersions[version]; exists {
			return nil, fmt.Errorf("migrations %q and %q use duplicate version %d", previous, entry.Name(), version)
		}
		seenVersions[version] = entry.Name()
		sql, err := migrationFiles.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("read migration %d: %w", version, err)
		}
		// Git enforces LF for migrations, and normalization here makes the
		// checksum/application bytes deterministic for source archives too.
		sql = bytes.ReplaceAll(sql, []byte("\r\n"), []byte("\n"))
		migrations = append(migrations, migration{version: version, filename: entry.Name(), sql: sql, checksum: sha256.Sum256(sql)})
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].version < migrations[j].version })
	return migrations, nil
}

func nullableTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC()
}
