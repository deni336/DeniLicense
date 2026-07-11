package httpapi

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/deni336/DeniLicense/internal/auth"
	"github.com/deni336/DeniLicense/internal/config"
	"github.com/deni336/DeniLicense/internal/domain"
	"github.com/deni336/DeniLicense/internal/lease"
	"github.com/deni336/DeniLicense/internal/license"
	"github.com/deni336/DeniLicense/internal/store/postgres"
	"github.com/go-chi/chi/v5"
)

type Server struct {
	config           config.Config
	db               *postgres.Store
	passwords        *auth.PasswordHasher
	dummyPassword    string
	loginLimiter     *rateLimiter
	claimLimiter     *rateLimiter
	renewalLimiter   *rateLimiter
	clientSources    clientSourceResolver
	email            *emailSender
	activationSigner *license.SigningKey
	activationKeys   lease.JWKS
}

// Close drains accepted email jobs during graceful service shutdown.
func (s *Server) Close(ctx context.Context) error {
	if s == nil || s.email == nil {
		return nil
	}
	return s.email.close(ctx)
}

func New(cfg config.Config, db *postgres.Store, signer *license.SigningKey, retainedKeys ...license.VerificationKey) (*Server, error) {
	if signer == nil || signer.Purpose() != license.PurposeActivationReceiptSigner || cfg.ActivationIssuer == "" {
		return nil, errors.New("an activation receipt signer and issuer are required")
	}
	public, ok := signer.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("activation signer is not Ed25519")
	}
	jwk, err := lease.NewJWK(public)
	if err != nil {
		return nil, err
	}
	if len(retainedKeys) > 32 {
		return nil, errors.New("too many retained activation keys")
	}
	activationKeys := lease.JWKS{Keys: []lease.JWK{jwk}}
	seenKeyIDs := map[string]struct{}{jwk.KeyID: {}}
	for _, retained := range retainedKeys {
		if retained.Purpose() != license.PurposeActivationReceiptSigner {
			return nil, errors.New("a retained activation key has the wrong purpose")
		}
		retainedJWK, err := lease.NewJWK(retained.Ed25519PublicKey())
		if err != nil {
			return nil, err
		}
		if _, duplicate := seenKeyIDs[retainedJWK.KeyID]; duplicate {
			continue
		}
		seenKeyIDs[retainedJWK.KeyID] = struct{}{}
		activationKeys.Keys = append(activationKeys.Keys, retainedJWK)
	}
	passwords := auth.NewPasswordHasher(cfg.PasswordPepper)
	dummy, err := passwords.Hash("dummy password used for timing only")
	if err != nil {
		return nil, err
	}
	clientSources, err := newClientSourceResolver(cfg.TrustedProxyCIDRs, cfg.DevicePepper)
	if err != nil {
		return nil, err
	}
	return &Server{
		config:           cfg,
		db:               db,
		passwords:        passwords,
		dummyPassword:    dummy,
		loginLimiter:     newRateLimiter(10, time.Minute, clientSources),
		claimLimiter:     newRateLimiter(10, time.Hour, clientSources),
		renewalLimiter:   newRateLimiter(120, time.Minute, clientSources),
		clientSources:    clientSources,
		email:            newEmailSender(cfg),
		activationSigner: signer,
		activationKeys:   activationKeys,
	}, nil
}

func (s *Server) Handler() http.Handler {
	router := chi.NewRouter()
	router.Use(requestMiddleware(s.config.Environment == config.Production))
	router.Use(loggingMiddleware(s.clientSources))
	router.Use(recoverMiddleware)
	if len(s.config.AllowedOrigins) > 0 {
		router.Use(corsMiddleware(s.config.AllowedOrigins))
	}

	router.Get("/live", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	router.Get("/ready", s.ready)
	router.Get("/openapi.yaml", serveOpenAPI)
	router.Get("/.well-known/denilicense-activation-keys.json", s.activationPublicKeys)
	router.Get("/api/v1/products", s.listPublicProducts)
	router.With(s.renewalLimiter.middleware).Post("/api/v1/activation-challenges", s.createRenewalChallenge)
	router.With(s.renewalLimiter.middleware).Post("/api/v1/activation-challenges/complete", s.completeRenewalChallenge)

	router.Route("/api/v1/auth", func(r chi.Router) {
		r.With(s.loginLimiter.middleware).Post("/register", s.register)
		r.With(s.loginLimiter.middleware).Post("/verify-email", s.verifyEmail)
		r.With(s.loginLimiter.middleware).Post("/verification/request", s.requestVerification)
		r.With(s.loginLimiter.middleware).Post("/login", s.login)
		r.With(s.loginLimiter.middleware).Post("/refresh", s.refresh)
		r.With(s.loginLimiter.middleware).Post("/password-reset/request", s.requestPasswordReset)
		r.With(s.loginLimiter.middleware).Post("/password-reset/confirm", s.confirmPasswordReset)
		r.Group(func(r chi.Router) {
			r.Use(func(next http.Handler) http.Handler { return authenticate(s.db, s.config.TokenPepper, next) })
			r.Post("/logout", s.logout)
			r.Get("/me", s.me)
		})
	})

	router.Group(func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler { return authenticate(s.db, s.config.TokenPepper, next) })
		r.Use(requireVerified)
		r.With(s.claimLimiter.middleware).Post("/api/v1/licenses/claim", s.claimLicense)
		r.Get("/api/v1/licenses", s.listLicenses)
		r.Get("/api/v1/licenses/{licenseID}", s.getLicense)
		r.Get("/api/v1/licenses/{licenseID}/activations", s.listLicenseActivations)
		r.Post("/api/v1/licenses/{licenseID}/activations", s.activate)
		r.Delete("/api/v1/activations/{activationID}", s.deactivate)
	})

	router.Route("/api/v1/admin", func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler { return authenticate(s.db, s.config.TokenPepper, next) })
		r.Use(requireVerified)
		r.Group(func(r chi.Router) {
			r.Use(requireRoles(domain.RolePlatformOwner, domain.RoleLicenseAdmin))
			r.Post("/products", s.createProduct)
			r.Post("/licenses", s.createOnlineLicense)
			r.Post("/licenses/import", s.importOfflineLicense)
			r.Post("/licenses/{licenseID}/state", s.setLicenseState)
		})
		r.Group(func(r chi.Router) {
			r.Use(requireRoles(domain.RolePlatformOwner, domain.RoleLicenseAdmin, domain.RoleSupport, domain.RoleAuditor))
			r.Get("/licenses", s.listAdminLicenses)
			r.Get("/licenses/{licenseID}", s.getAdminLicense)
			r.Get("/licenses/{licenseID}/activations", s.listAdminActivations)
		})
		r.Group(func(r chi.Router) {
			r.Use(requireRoles(domain.RolePlatformOwner, domain.RoleLicenseAdmin, domain.RoleSupport))
			r.Delete("/activations/{activationID}", s.deactivateAdminActivation)
		})
		r.Group(func(r chi.Router) {
			r.Use(requireRoles(domain.RolePlatformOwner))
			r.Post("/issuers", s.registerIssuer)
			r.Post("/issuers/{keyID}/status", s.setIssuerStatus)
			r.Get("/users", s.listAdminUsers)
			r.Get("/users/{userID}", s.getAdminUser)
			r.Post("/users/{userID}/role", s.setAdminUserRole)
			r.Post("/users/{userID}/status", s.setAdminUserStatus)
		})
		r.Group(func(r chi.Router) {
			r.Use(requireRoles(domain.RolePlatformOwner, domain.RoleAuditor))
			r.Get("/audit-events", s.listAuditEvents)
		})
	})
	router.NotFound(func(w http.ResponseWriter, r *http.Request) { writeProblem(w, r, errRouteNotFound) })
	router.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) { writeProblem(w, r, errMethodNotAllowed) })

	return router
}

func (s *Server) activationPublicKeys(w http.ResponseWriter, _ *http.Request) {
	writePublicJSON(w, http.StatusOK, 300, s.activationKeys)
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.db.Ping(ctx); err != nil {
		writeProblem(w, r, errors.New("database unavailable"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func corsMiddleware(origins []string) func(http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(origins))
	for _, origin := range origins {
		allowed[origin] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" {
				if _, ok := allowed[origin]; !ok {
					writeProblem(w, r, errForbidden)
					return
				}
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Idempotency-Key")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Max-Age", "600")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (s *Server) listPublicProducts(w http.ResponseWriter, r *http.Request) {
	products, err := s.db.ListProducts(r.Context(), false)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": products})
}

func auditFor(r *http.Request, action, targetType string) postgres.AuditEvent {
	principal := principalFrom(r.Context())
	return postgres.AuditEvent{
		ActorUserID: &principal.User.ID,
		ActorKind:   "user",
		Action:      action,
		TargetType:  targetType,
		RequestID:   requestIDFrom(r.Context()),
		Outcome:     "success",
	}
}

func logSecurityEvent(r *http.Request, event string, attributes ...any) {
	values := []any{"request_id", requestIDFrom(r.Context()), "event", event}
	values = append(values, attributes...)
	slog.WarnContext(r.Context(), "security event", values...)
}

func decodeEntitlements(encoded json.RawMessage) (map[string]any, error) {
	if len(encoded) == 0 {
		return map[string]any{}, nil
	}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.UseNumber()
	var values map[string]any
	if err := decoder.Decode(&values); err != nil || values == nil {
		return nil, errBadRequest
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, errBadRequest
	}
	if len(values) > 128 {
		return nil, errBadRequest
	}
	for key, value := range values {
		if !validEntitlementName(key) {
			return nil, errBadRequest
		}
		switch typed := value.(type) {
		case bool:
		case string:
			if len(typed) > 4096 {
				return nil, errBadRequest
			}
			for _, character := range typed {
				if unicode.IsControl(character) {
					return nil, errBadRequest
				}
			}
		case json.Number:
			n, err := typed.Int64()
			if err != nil {
				return nil, errBadRequest
			}
			values[key] = n
		default:
			return nil, errBadRequest
		}
	}
	return values, nil
}

func validEntitlementName(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			(index > 0 && (character == '.' || character == '_' || character == '-'))) {
			return false
		}
	}
	return true
}
