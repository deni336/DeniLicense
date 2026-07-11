package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/deni336/DeniLicense/internal/auth"
	"github.com/deni336/DeniLicense/internal/config"
	"github.com/deni336/DeniLicense/internal/httpapi"
	"github.com/deni336/DeniLicense/internal/identity"
	"github.com/deni336/DeniLicense/internal/license"
	storeerrors "github.com/deni336/DeniLicense/internal/store"
	"github.com/deni336/DeniLicense/internal/store/postgres"
	"github.com/google/uuid"
	"golang.org/x/term"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)
	if err := run(os.Args[1:]); err != nil {
		slog.Error("command failed", "error", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	command := "serve"
	if len(args) > 0 {
		command = args[0]
		args = args[1:]
	}
	if command == "migrate" {
		if len(args) != 0 {
			return errors.New("migrate does not accept positional arguments")
		}
		return migrateOnly()
	}
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	db, err := postgres.Open(ctx, cfg.DatabaseURL)
	cancel()
	if err != nil {
		return err
	}
	defer db.Close()

	switch command {
	case "serve":
		if len(args) != 0 {
			return errors.New("serve does not accept positional arguments")
		}
		migrationContext, stopMigration := context.WithTimeout(context.Background(), 2*time.Minute)
		defer stopMigration()
		if cfg.AutoMigrate {
			if err := db.Migrate(migrationContext); err != nil {
				return err
			}
		} else if err := db.VerifyMigrations(migrationContext); err != nil {
			return fmt.Errorf("verify database migrations (run `denilicense migrate` with the migration role): %w", err)
		}
		return serve(cfg, db)
	case "bootstrap-owner":
		return bootstrapOwner(cfg, db, args)
	default:
		return fmt.Errorf("unknown command %q (expected serve, migrate, or bootstrap-owner)", command)
	}
}

func migrateOnly() error {
	databaseURL := strings.TrimSpace(os.Getenv("DENILICENSE_DATABASE_URL"))
	if databaseURL == "" {
		return errors.New("DENILICENSE_DATABASE_URL is required")
	}
	requireTLS := config.Environment(strings.TrimSpace(os.Getenv("DENILICENSE_ENV"))) == config.Production
	if err := config.ValidateDatabaseURL(databaseURL, requireTLS); err != nil {
		return err
	}
	openContext, stopOpen := context.WithTimeout(context.Background(), 15*time.Second)
	db, err := postgres.Open(openContext, databaseURL)
	stopOpen()
	if err != nil {
		return err
	}
	defer db.Close()
	migrationContext, stopMigration := context.WithTimeout(context.Background(), 2*time.Minute)
	defer stopMigration()
	return db.Migrate(migrationContext)
}

func serve(cfg config.Config, db *postgres.Store) error {
	signer, err := loadActivationSigner(cfg)
	if err != nil {
		return err
	}
	verificationKeys, err := loadActivationVerificationKeys(cfg)
	if err != nil {
		return err
	}
	api, err := httpapi.New(cfg, db, signer, verificationKeys...)
	if err != nil {
		return err
	}
	defer func() {
		drainContext, cancelDrain := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancelDrain()
		if err := api.Close(drainContext); err != nil {
			slog.Error("email delivery drain failed", "error", err)
		}
	}()
	server := &http.Server{
		Addr:              cfg.HTTPAddress,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}
	maintenanceContext, stopMaintenance := context.WithCancel(context.Background())
	defer stopMaintenance()
	go runMaintenance(maintenanceContext, db)

	serverErr := make(chan error, 1)
	go func() {
		slog.Info("DeniLicense listening", "address", cfg.HTTPAddress, "environment", cfg.Environment)
		if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
		close(serverErr)
	}()

	signals, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-serverErr:
		return err
	case <-signals.Done():
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	return server.Shutdown(ctx)
}

func loadActivationVerificationKeys(cfg config.Config) ([]license.VerificationKey, error) {
	keys := make([]license.VerificationKey, 0, len(cfg.ActivationVerificationKeyFiles))
	for _, path := range cfg.ActivationVerificationKeyFiles {
		encoded, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read activation verification key %q: %w", path, err)
		}
		if len(encoded) == 0 || len(encoded) > license.MaxKeyFileBytes {
			return nil, fmt.Errorf("activation verification key %q has an invalid size", path)
		}
		key, err := license.ParsePublicKey(encoded)
		if err != nil {
			return nil, fmt.Errorf("parse activation verification key %q: %w", path, err)
		}
		if key.Purpose() != license.PurposeActivationReceiptSigner {
			return nil, fmt.Errorf("activation verification key %q has the wrong purpose", path)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func runMaintenance(ctx context.Context, db *postgres.Store) {
	run := func() {
		operationContext, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if err := db.CleanupExpiredSecurityState(operationContext, time.Now().UTC()); err != nil && !errors.Is(err, context.Canceled) {
			slog.Error("security-state cleanup failed", "error", err)
		}
	}
	run()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

func loadActivationSigner(cfg config.Config) (*license.SigningKey, error) {
	if cfg.ActivationKeyFile == "" || cfg.ActivationIssuer == "" {
		return nil, errors.New("DENILICENSE_ACTIVATION_KEY_FILE and DENILICENSE_ACTIVATION_ISSUER are required to serve")
	}
	encoded, err := os.ReadFile(cfg.ActivationKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read activation key: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > license.MaxKeyFileBytes {
		return nil, errors.New("activation key file has an invalid size")
	}
	var passphrase []byte
	if cfg.ActivationKeyPassphraseFile != "" {
		passphrase, err = os.ReadFile(cfg.ActivationKeyPassphraseFile)
		if err != nil {
			return nil, fmt.Errorf("read activation key passphrase: %w", err)
		}
		passphrase = trimOneLineEnding(passphrase)
	} else if cfg.Environment != config.Production {
		passphrase = []byte(os.Getenv("DENILICENSE_ACTIVATION_KEY_PASSPHRASE"))
	}
	if len(passphrase) == 0 {
		return nil, errors.New("activation key passphrase is required")
	}
	defer wipe(passphrase)
	signer, err := license.DecryptSigningKey(encoded, passphrase)
	if err != nil {
		return nil, fmt.Errorf("decrypt activation key: %w", err)
	}
	if signer.Purpose() != license.PurposeActivationReceiptSigner {
		return nil, errors.New("configured activation key has the wrong purpose")
	}
	return signer, nil
}

func trimOneLineEnding(value []byte) []byte {
	if len(value) > 0 && value[len(value)-1] == '\n' {
		value = value[:len(value)-1]
		if len(value) > 0 && value[len(value)-1] == '\r' {
			value = value[:len(value)-1]
		}
	}
	return value
}

func bootstrapOwner(cfg config.Config, db *postgres.Store, args []string) error {
	flags := flag.NewFlagSet("bootstrap-owner", flag.ContinueOnError)
	emailFlag := flags.String("email", "", "platform owner email")
	if err := flags.Parse(args); err != nil {
		return err
	}
	email, normalizedEmail, err := identity.NormalizeEmail(*emailFlag)
	if err != nil {
		return errors.New("a plain valid --email address is required")
	}
	password, err := bootstrapPassword()
	if err != nil {
		return err
	}
	defer wipe(password)
	hasher := auth.NewPasswordHasher(cfg.PasswordPepper)
	encoded, err := hasher.Hash(string(password))
	if err != nil {
		return err
	}
	operationContext, stopOperation := context.WithTimeout(context.Background(), 2*time.Minute)
	defer stopOperation()
	if cfg.AutoMigrate {
		if err := db.Migrate(operationContext); err != nil {
			return err
		}
	} else if err := db.VerifyMigrations(operationContext); err != nil {
		return fmt.Errorf("verify database migrations (run `denilicense migrate` with the migration role): %w", err)
	}
	user, err := db.BootstrapOwner(operationContext, uuid.New(), email, normalizedEmail, encoded, time.Now().UTC())
	if errors.Is(err, storeerrors.ErrConflict) {
		return errors.New("a platform owner already exists; use the authenticated role-management workflow")
	}
	if err != nil {
		return err
	}
	fmt.Printf("Created platform owner %s (%s)\n", user.Email, user.ID)
	return nil
}

func bootstrapPassword() ([]byte, error) {
	if value := os.Getenv("DENILICENSE_BOOTSTRAP_PASSWORD"); value != "" {
		return []byte(value), nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("no terminal available; set DENILICENSE_BOOTSTRAP_PASSWORD securely")
	}
	fmt.Fprint(os.Stderr, "New platform owner password: ")
	password, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	fmt.Fprint(os.Stderr, "Confirm password: ")
	repeated, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		wipe(password)
		return nil, err
	}
	defer wipe(repeated)
	if string(password) != string(repeated) {
		wipe(password)
		return nil, errors.New("passwords did not match")
	}
	return password, nil
}

func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
