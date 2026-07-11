package httpapi

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/deni336/DeniLicense/internal/claimcode"
	"github.com/deni336/DeniLicense/internal/domain"
	"github.com/deni336/DeniLicense/internal/lease"
	"github.com/deni336/DeniLicense/internal/license"
	storeerrors "github.com/deni336/DeniLicense/internal/store"
	"github.com/deni336/DeniLicense/internal/store/postgres"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

var (
	productCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_-]{1,63}$`)
	issuerPattern      = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/-]{1,255}$`)
)

type createProductRequest struct {
	Code        string `json:"code"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (s *Server) createProduct(w http.ResponseWriter, r *http.Request) {
	var request createProductRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeProblem(w, r, err)
		return
	}
	request.Code = strings.ToUpper(strings.TrimSpace(request.Code))
	request.Name = strings.TrimSpace(request.Name)
	request.Description = strings.TrimSpace(request.Description)
	if !productCodePattern.MatchString(request.Code) || len(request.Name) == 0 || len(request.Name) > 120 || len(request.Description) > 2000 {
		writeProblem(w, r, errBadRequest)
		return
	}
	principal := principalFrom(r.Context())
	product, err := s.db.CreateProduct(r.Context(), postgres.CreateProductParams{
		ID: uuid.New(), Code: request.Code, Name: request.Name, Description: request.Description,
		CreatedBy: principal.User.ID, Audit: auditFor(r, "product.create", "product"),
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"product": product})
}

type registerIssuerRequest struct {
	Issuer            string     `json:"issuer"`
	PublicKeyDocument string     `json:"publicKeyDocument"`
	NotBefore         *time.Time `json:"notBefore,omitempty"`
	NotAfter          *time.Time `json:"notAfter,omitempty"`
}

func (s *Server) registerIssuer(w http.ResponseWriter, r *http.Request) {
	var request registerIssuerRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeProblem(w, r, err)
		return
	}
	request.Issuer = strings.TrimSpace(request.Issuer)
	if !issuerPattern.MatchString(request.Issuer) || len(request.PublicKeyDocument) > license.MaxKeyFileBytes {
		writeProblem(w, r, errBadRequest)
		return
	}
	verificationKey, err := license.ParsePublicKey([]byte(request.PublicKeyDocument))
	if err != nil || verificationKey.Purpose() != license.PurposeOfflineLicenseIssuer {
		writeProblem(w, r, errBadRequest)
		return
	}
	notBefore := time.Now().UTC()
	if request.NotBefore != nil {
		notBefore = request.NotBefore.UTC()
	}
	if request.NotAfter != nil && !request.NotAfter.After(notBefore) {
		writeProblem(w, r, errBadRequest)
		return
	}
	public := verificationKey.Ed25519PublicKey()
	fingerprint := sha256.Sum256(public)
	principal := principalFrom(r.Context())
	key, err := s.db.RegisterIssuer(r.Context(), postgres.RegisterIssuerParams{
		KeyID: verificationKey.KeyID(), Issuer: request.Issuer, PublicKey: public,
		Fingerprint: fingerprint, NotBefore: notBefore, NotAfter: request.NotAfter,
		CreatedBy: principal.User.ID, Audit: auditFor(r, "issuer.register", "issuer_key"),
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"issuerKey": key})
}

type issuerStatusRequest struct {
	Status string `json:"status"`
}

func (s *Server) setIssuerStatus(w http.ResponseWriter, r *http.Request) {
	var request issuerStatusRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeProblem(w, r, err)
		return
	}
	if request.Status != "active" && request.Status != "retired" && request.Status != "revoked" {
		writeProblem(w, r, errBadRequest)
		return
	}
	keyID := chi.URLParam(r, "keyID")
	if len(keyID) != 43 {
		writeProblem(w, r, errBadRequest)
		return
	}
	principal := principalFrom(r.Context())
	if err := s.db.UpdateIssuerStatus(r.Context(), keyID, request.Status, principal.User.ID, auditFor(r, "issuer.status_change", "issuer_key")); err != nil {
		writeProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type createLicenseRequest struct {
	ProductCode         string          `json:"productCode"`
	Subject             string          `json:"subject,omitempty"`
	NotBefore           *time.Time      `json:"notBefore,omitempty"`
	ExpiresAt           *time.Time      `json:"expiresAt,omitempty"`
	MaxActivations      int             `json:"maxActivations"`
	OfflineGraceSeconds int             `json:"offlineGraceSeconds,omitempty"`
	Perpetual           bool            `json:"perpetual,omitempty"`
	Entitlements        json.RawMessage `json:"entitlements"`
}

func (s *Server) createOnlineLicense(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if !validIdempotencyKey(idempotencyKey) {
		writeProblem(w, r, errBadRequest)
		return
	}
	var request createLicenseRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeProblem(w, r, err)
		return
	}
	request.ProductCode = strings.ToUpper(strings.TrimSpace(request.ProductCode))
	request.Subject = strings.TrimSpace(request.Subject)
	if !productCodePattern.MatchString(request.ProductCode) || len(request.Subject) > license.MaxSubjectBytes || request.MaxActivations < 1 || request.MaxActivations > 100000 {
		writeProblem(w, r, errBadRequest)
		return
	}
	grace := request.OfflineGraceSeconds
	if grace == 0 {
		grace = 86400
	}
	if grace < 3600 || grace > 30*86400 {
		writeProblem(w, r, errBadRequest)
		return
	}
	if request.Perpetual == (request.ExpiresAt != nil) {
		writeProblem(w, r, errBadRequest)
		return
	}
	entitlements, err := decodeEntitlements(request.Entitlements)
	if err != nil {
		writeProblem(w, r, errBadRequest)
		return
	}
	product, err := s.db.ProductByCode(r.Context(), request.ProductCode)
	if err != nil || product.Status != "active" {
		writeProblem(w, r, storeerrors.ErrNotFound)
		return
	}
	now := time.Now().UTC()
	notBefore := now
	if request.NotBefore != nil {
		value := request.NotBefore.UTC()
		request.NotBefore = &value
		notBefore = value
	}
	if request.ExpiresAt != nil {
		value := request.ExpiresAt.UTC()
		request.ExpiresAt = &value
		if !value.After(notBefore) || value.Sub(now) > 10*365*24*time.Hour {
			writeProblem(w, r, errBadRequest)
			return
		}
	}
	material, err := json.Marshal(struct {
		ProductCode         string         `json:"product_code"`
		Subject             string         `json:"subject"`
		NotBefore           *time.Time     `json:"not_before,omitempty"`
		ExpiresAt           *time.Time     `json:"expires_at,omitempty"`
		Perpetual           bool           `json:"perpetual"`
		MaxActivations      int            `json:"max_activations"`
		OfflineGraceSeconds int            `json:"offline_grace_seconds"`
		Entitlements        map[string]any `json:"entitlements"`
	}{request.ProductCode, request.Subject, request.NotBefore, request.ExpiresAt, request.Perpetual, request.MaxActivations, grace, entitlements})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	requestHash := sha256.Sum256(material)
	principal := principalFrom(r.Context())
	serialBytes := deriveOnlineIssuance(s.config.IssuancePepper, "serial", principal.User.ID, idempotencyKey, nil)
	serialBytes[6] = (serialBytes[6] & 0x0f) | 0x40
	serialBytes[8] = (serialBytes[8] & 0x3f) | 0x80
	serial, err := uuid.FromBytes(serialBytes[:16])
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	codeBytes := deriveOnlineIssuance(s.config.IssuancePepper, "claim-code", principal.User.ID, idempotencyKey, requestHash[:])
	code, digest, suffix, err := claimcode.FromEntropy(codeBytes[:20])
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	created, idempotent, err := s.db.CreateLicense(r.Context(), postgres.CreateLicenseParams{
		ID: uuid.New(), Serial: serial, ProductID: product.ID, Source: "online", CreationRequestHash: &requestHash,
		ClaimCodeHash: digest, ClaimCodeSuffix: suffix, Subject: request.Subject,
		IssuedAt: now, NotBefore: notBefore, ExpiresAt: request.ExpiresAt,
		MaxActivations: request.MaxActivations, OfflineGraceSeconds: grace,
		Entitlements: entitlements, Metadata: map[string]any{}, CreatedBy: principal.User.ID,
		Audit: auditFor(r, "license.create_online", "license"),
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	status := http.StatusCreated
	if idempotent {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{
		"license":    created,
		"claimCode":  code,
		"idempotent": idempotent,
		"warning":    "Store this claim code securely; the server retains only its digest. The same idempotency key and request can recover it.",
	})
}

func validIdempotencyKey(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for index, character := range []byte(value) {
		if !((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') || (index > 0 && (character == '.' || character == '_' || character == ':' || character == '-'))) {
			return false
		}
	}
	return true
}

func deriveOnlineIssuance(pepper []byte, purpose string, actor uuid.UUID, idempotencyKey string, requestHash []byte) [32]byte {
	mac := hmac.New(sha256.New, pepper)
	_, _ = mac.Write([]byte("DeniLicense/online-issuance/" + purpose + "/v1\x00"))
	_, _ = mac.Write(actor[:])
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(idempotencyKey))
	if len(requestHash) > 0 {
		_, _ = mac.Write([]byte{0})
		_, _ = mac.Write(requestHash)
	}
	var output [32]byte
	copy(output[:], mac.Sum(nil))
	return output
}

type importLicenseRequest struct {
	Artifact string `json:"artifact"`
}

func (s *Server) importOfflineLicense(w http.ResponseWriter, r *http.Request) {
	var request importLicenseRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeProblem(w, r, errBadRequest)
		return
	}
	request.Artifact = strings.TrimSpace(request.Artifact)
	if len(request.Artifact) == 0 || len(request.Artifact) > license.MaxTokenBytes {
		writeProblem(w, r, errBadRequest)
		return
	}
	untrusted, err := license.InspectUnverified(request.Artifact)
	if err != nil {
		writeProblem(w, r, errBadRequest)
		return
	}
	issuerKey, err := s.db.IssuerByKeyID(r.Context(), untrusted.KeyID)
	if err != nil {
		writeProblem(w, r, errBadRequest)
		return
	}
	verificationKey, err := license.NewVerificationKey(ed25519.PublicKey(issuerKey.PublicKey), license.PurposeOfflineLicenseIssuer)
	if err != nil {
		writeProblem(w, r, errBadRequest)
		return
	}
	claims, err := license.VerifyToken(request.Artifact, verificationKey)
	if err != nil || claims.Issuer != issuerKey.Issuer {
		writeProblem(w, r, errBadRequest)
		return
	}
	now := time.Now().UTC()
	if claims.IssuedAt.Before(issuerKey.NotBefore) || (issuerKey.NotAfter != nil && !claims.IssuedAt.Before(*issuerKey.NotAfter)) || claims.IssuedAt.After(now.Add(license.MaxClockSkew)) {
		writeProblem(w, r, errBadRequest)
		return
	}
	if claims.ExpiresAt != nil && !now.Before(*claims.ExpiresAt) {
		writeProblem(w, r, errBadRequest)
		return
	}
	product, err := s.db.ProductByCode(r.Context(), claims.Audience)
	if err != nil || product.Status != "active" {
		writeProblem(w, r, errBadRequest)
		return
	}
	serial, err := uuid.Parse(claims.Serial)
	if err != nil || serial.String() != claims.Serial {
		writeProblem(w, r, errBadRequest)
		return
	}
	claimDigest, err := license.DecodeClaimCodeSHA256(claims.ClaimCodeSHA256)
	if err != nil {
		writeProblem(w, r, errBadRequest)
		return
	}
	artifactHash := sha256.Sum256([]byte(request.Artifact))
	keyID := issuerKey.KeyID
	principal := principalFrom(r.Context())
	created, idempotent, err := s.db.CreateLicense(r.Context(), postgres.CreateLicenseParams{
		ID: uuid.New(), Serial: serial, ProductID: product.ID, Source: "offline_import",
		IssuerKeyID: &keyID, ImportArtifact: &request.Artifact, ImportArtifactHash: &artifactHash,
		ClaimCodeHash: claimDigest, ClaimCodeSuffix: claims.ClaimCodeSuffix, Subject: claims.Subject,
		IssuedAt: claims.IssuedAt, NotBefore: claims.NotBefore, ExpiresAt: claims.ExpiresAt,
		MaxActivations: claims.MaxActivations, OfflineGraceSeconds: 86400,
		Entitlements: claims.Entitlements, Metadata: map[string]any{}, CreatedBy: principal.User.ID,
		Audit: auditFor(r, "license.import_offline", "license"),
	})
	if err != nil {
		if errors.Is(err, storeerrors.ErrConflict) {
			logSecurityEvent(r, "offline_import_serial_conflict", "serial", claims.Serial, "key_id", claims.KeyID)
		}
		writeProblem(w, r, err)
		return
	}
	status := http.StatusCreated
	if idempotent {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"license": created, "idempotent": idempotent})
}

type claimLicenseRequest struct {
	ClaimCode string `json:"claimCode"`
}

func (s *Server) claimLicense(w http.ResponseWriter, r *http.Request) {
	var request claimLicenseRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeProblem(w, r, err)
		return
	}
	digest, err := claimcode.Digest(request.ClaimCode)
	if err != nil {
		// Do not disclose whether formatting, lookup, state, or ownership failed.
		writeProblem(w, r, storeerrors.ErrInvalid)
		return
	}
	principal := principalFrom(r.Context())
	created, err := s.db.ClaimLicense(r.Context(), digest, principal.User.ID, time.Now().UTC(), auditFor(r, "license.claim", "license"))
	if err != nil {
		writeProblem(w, r, storeerrors.ErrInvalid)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"license": created})
}

func (s *Server) listLicenses(w http.ResponseWriter, r *http.Request) {
	items, err := s.db.ListUserLicenses(r.Context(), principalFrom(r.Context()).User.ID)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) getLicense(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "licenseID"))
	if err != nil {
		writeProblem(w, r, storeerrors.ErrNotFound)
		return
	}
	item, err := s.db.LicenseForOwner(r.Context(), id, principalFrom(r.Context()).User.ID)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"license": item})
}

type activationRequest struct {
	DevicePublicKey string `json:"devicePublicKey"`
	Label           string `json:"label,omitempty"`
}

func (s *Server) activate(w http.ResponseWriter, r *http.Request) {
	licenseID, err := uuid.Parse(chi.URLParam(r, "licenseID"))
	if err != nil {
		writeProblem(w, r, storeerrors.ErrNotFound)
		return
	}
	var request activationRequest
	if err := decodeJSON(w, r, &request); err != nil || len(request.Label) > 120 {
		writeProblem(w, r, errBadRequest)
		return
	}
	publicKey, err := base64.RawURLEncoding.Strict().DecodeString(request.DevicePublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(publicKey) != request.DevicePublicKey {
		writeProblem(w, r, errBadRequest)
		return
	}
	if err := license.ValidateEd25519PublicKey(ed25519.PublicKey(publicKey)); err != nil {
		writeProblem(w, r, errBadRequest)
		return
	}
	now := time.Now().UTC()
	principal := principalFrom(r.Context())
	licensed, activation, idempotent, err := s.db.Activate(r.Context(), postgres.ActivateParams{
		ID: uuid.New(), LicenseID: licenseID, OwnerUserID: principal.User.ID,
		DevicePublicKey: publicKey, Label: strings.TrimSpace(request.Label), Now: now,
		LeaseExpiresAt: now.Add(s.config.ActivationLeaseTTL), Audit: auditFor(r, "activation.create", "activation"),
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	status := http.StatusCreated
	if idempotent {
		status = http.StatusOK
	}
	leaseToken, err := s.signActivationLease(licensed, activation, ed25519.PublicKey(publicKey), activation.LastSeenAt)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeJSON(w, status, map[string]any{
		"activation": activation,
		"license":    licensed,
		"lease":      leaseToken,
		"idempotent": idempotent,
	})
}

func (s *Server) signActivationLease(licensed domain.License, activation domain.Activation, publicKey ed25519.PublicKey, now time.Time) (string, error) {
	thumbprint, err := lease.DeviceKeyThumbprint(publicKey)
	if err != nil {
		return "", err
	}
	jti, err := lease.NewJWTID()
	if err != nil {
		return "", err
	}
	entitlements, err := decodeEntitlements(licensed.Entitlements)
	if err != nil {
		return "", err
	}
	return lease.Sign(lease.Claims{
		Version:             lease.ClaimsVersion,
		Type:                lease.ClaimsType,
		Issuer:              s.config.ActivationIssuer,
		KeyID:               s.activationSigner.KeyID(),
		JWTID:               jti,
		LicenseID:           licensed.ID.String(),
		ActivationID:        activation.ID.String(),
		Audience:            licensed.ProductCode,
		LicenseRevision:     licensed.Revision,
		DeviceKeyThumbprint: thumbprint,
		Entitlements:        entitlements,
		IssuedAt:            now.UTC(),
		NotBefore:           now.UTC(),
		ExpiresAt:           activation.LeaseExpiresAt.UTC(),
	}, s.activationSigner)
}

func (s *Server) deactivate(w http.ResponseWriter, r *http.Request) {
	activationID, err := uuid.Parse(chi.URLParam(r, "activationID"))
	if err != nil {
		writeProblem(w, r, storeerrors.ErrNotFound)
		return
	}
	principal := principalFrom(r.Context())
	if err := s.db.Deactivate(r.Context(), activationID, principal.User.ID, time.Now().UTC(), auditFor(r, "activation.deactivate", "activation")); err != nil {
		writeProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type licenseStateRequest struct {
	State string `json:"state"`
}

func (s *Server) setLicenseState(w http.ResponseWriter, r *http.Request) {
	licenseID, err := uuid.Parse(chi.URLParam(r, "licenseID"))
	if err != nil {
		writeProblem(w, r, storeerrors.ErrNotFound)
		return
	}
	var request licenseStateRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeProblem(w, r, err)
		return
	}
	if request.State != "active" && request.State != "suspended" && request.State != "revoked" {
		writeProblem(w, r, errBadRequest)
		return
	}
	if err := s.db.SetLicenseState(r.Context(), licenseID, request.State, time.Now().UTC(), auditFor(r, "license.state_change", "license")); err != nil {
		writeProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
