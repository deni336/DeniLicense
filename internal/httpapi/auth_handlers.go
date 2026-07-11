package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/deni336/DeniLicense/internal/auth"
	"github.com/deni336/DeniLicense/internal/config"
	"github.com/deni336/DeniLicense/internal/domain"
	"github.com/deni336/DeniLicense/internal/identity"
	storeerrors "github.com/deni336/DeniLicense/internal/store"
	"github.com/deni336/DeniLicense/internal/store/postgres"
	"github.com/google/uuid"
)

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	if s.config.RegistrationMode != config.RegistrationOpen {
		writeProblem(w, r, errForbidden)
		return
	}
	var request registerRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeProblem(w, r, err)
		return
	}
	email, normalized, err := normalizeEmail(request.Email)
	if err != nil {
		writeProblem(w, r, errBadRequest)
		return
	}
	passwordHash, err := s.passwords.Hash(request.Password)
	if err != nil {
		writeProblem(w, r, errBadRequest)
		return
	}
	verificationToken, err := auth.NewToken(auth.EmailVerificationToken)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	verificationHash, err := auth.HashToken(s.config.TokenPepper, auth.EmailVerificationToken, verificationToken)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	_, err = s.db.CreateUser(r.Context(), postgres.CreateUserParams{
		ID:                      uuid.New(),
		Email:                   email,
		NormalizedEmail:         normalized,
		PasswordHash:            passwordHash,
		Role:                    domain.RoleCustomer,
		VerificationTokenID:     uuid.New(),
		VerificationTokenHash:   verificationHash,
		VerificationTokenExpiry: time.Now().UTC().Add(s.config.VerificationTTL),
	})
	if err != nil && !errors.Is(err, storeerrors.ErrConflict) {
		writeProblem(w, r, err)
		return
	}
	if err == nil {
		s.email.enqueue("verification", email, verificationToken, requestIDFrom(r.Context()))
	}
	response := map[string]any{"accepted": true, "verificationRequired": true}
	if s.config.ExposeDevTokens && err == nil {
		response["developmentVerificationToken"] = verificationToken
	}
	// The production deployment guide requires an email-delivery adapter before
	// open registration is enabled. Responses intentionally do not reveal whether
	// the address already existed.
	writeJSON(w, http.StatusAccepted, response)
}

type requestVerificationRequest struct {
	Email string `json:"email"`
}

func (s *Server) requestVerification(w http.ResponseWriter, r *http.Request) {
	var request requestVerificationRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeProblem(w, r, err)
		return
	}
	_, normalized, normalizeErr := normalizeEmail(request.Email)
	token, err := auth.NewToken(auth.EmailVerificationToken)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	hash, err := auth.HashToken(s.config.TokenPepper, auth.EmailVerificationToken, token)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	email := ""
	created := false
	if normalizeErr == nil {
		email, created, err = s.db.ReplaceEmailVerificationToken(r.Context(), normalized, uuid.New(), hash, time.Now().UTC().Add(s.config.VerificationTTL))
		if err != nil {
			writeProblem(w, r, err)
			return
		}
	}
	if created {
		s.email.enqueue("verification", email, token, requestIDFrom(r.Context()))
	}
	response := map[string]any{"accepted": true}
	if created && s.config.ExposeDevTokens {
		response["developmentVerificationToken"] = token
	}
	writeJSON(w, http.StatusAccepted, response)
}

type verifyEmailRequest struct {
	Token string `json:"token"`
}

func (s *Server) verifyEmail(w http.ResponseWriter, r *http.Request) {
	var request verifyEmailRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeProblem(w, r, err)
		return
	}
	hash, err := auth.HashToken(s.config.TokenPepper, auth.EmailVerificationToken, request.Token)
	if err != nil {
		writeProblem(w, r, errBadRequest)
		return
	}
	user, err := s.db.VerifyEmail(r.Context(), hash, time.Now().UTC())
	if err != nil {
		writeProblem(w, r, errBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var request loginRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeProblem(w, r, err)
		return
	}
	_, normalized, err := normalizeEmail(request.Email)
	if err != nil || len(request.Password) > 1024 {
		writeProblem(w, r, errUnauthenticated)
		return
	}
	credential, lookupErr := s.db.UserCredentialByEmail(r.Context(), normalized)
	encoded := s.dummyPassword
	if lookupErr == nil {
		encoded = credential.PasswordHash
	}
	valid, verifyErr := s.passwords.Verify(encoded, request.Password)
	if verifyErr != nil || lookupErr != nil || !valid || credential.User.Status != "active" {
		writeProblem(w, r, errUnauthenticated)
		return
	}
	response, err := s.newSession(r, credential.User)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

type tokenResponse struct {
	AccessToken      string      `json:"accessToken"`
	AccessExpiresAt  time.Time   `json:"accessExpiresAt"`
	RefreshToken     string      `json:"refreshToken"`
	RefreshExpiresAt time.Time   `json:"refreshExpiresAt"`
	User             domain.User `json:"user"`
}

func (s *Server) newSession(r *http.Request, user domain.User) (tokenResponse, error) {
	now := time.Now().UTC()
	access, err := auth.NewToken(auth.AccessToken)
	if err != nil {
		return tokenResponse{}, err
	}
	refresh, err := auth.NewToken(auth.RefreshToken)
	if err != nil {
		return tokenResponse{}, err
	}
	accessHash, err := auth.HashToken(s.config.TokenPepper, auth.AccessToken, access)
	if err != nil {
		return tokenResponse{}, err
	}
	refreshHash, err := auth.HashToken(s.config.TokenPepper, auth.RefreshToken, refresh)
	if err != nil {
		return tokenResponse{}, err
	}
	accessExpiry := now.Add(s.config.AccessTokenTTL)
	refreshExpiry := now.Add(s.config.RefreshTokenTTL)
	err = s.db.CreateSession(r.Context(), postgres.CreateSessionParams{
		SessionID:        uuid.New(),
		FamilyID:         uuid.New(),
		UserID:           user.ID,
		AccessHash:       accessHash,
		AccessExpiresAt:  accessExpiry,
		RefreshTokenID:   uuid.New(),
		RefreshHash:      refreshHash,
		RefreshExpiresAt: refreshExpiry,
	})
	if err != nil {
		return tokenResponse{}, err
	}
	return tokenResponse{access, accessExpiry, refresh, refreshExpiry, user}, nil
}

type refreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

func (s *Server) refresh(w http.ResponseWriter, r *http.Request) {
	var request refreshRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeProblem(w, r, err)
		return
	}
	oldHash, err := auth.HashToken(s.config.TokenPepper, auth.RefreshToken, request.RefreshToken)
	if err != nil {
		writeProblem(w, r, errUnauthenticated)
		return
	}
	access, err := auth.NewToken(auth.AccessToken)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	refresh, err := auth.NewToken(auth.RefreshToken)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	accessHash, _ := auth.HashToken(s.config.TokenPepper, auth.AccessToken, access)
	refreshHash, _ := auth.HashToken(s.config.TokenPepper, auth.RefreshToken, refresh)
	now := time.Now().UTC()
	accessExpiry := now.Add(s.config.AccessTokenTTL)
	refreshExpiry := now.Add(s.config.RefreshTokenTTL)
	rotated, err := s.db.RotateSession(r.Context(), postgres.RotateSessionParams{
		OldRefreshHash:   oldHash,
		NewRefreshID:     uuid.New(),
		NewRefreshHash:   refreshHash,
		NewAccessHash:    accessHash,
		AccessExpiresAt:  accessExpiry,
		RefreshExpiresAt: refreshExpiry,
		Now:              now,
	})
	if err != nil {
		if errors.Is(err, storeerrors.ErrRefreshReuse) {
			logSecurityEvent(r, "refresh_token_reuse")
		}
		writeProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"accessToken": access, "accessExpiresAt": rotated.AccessExpiresAt,
		"refreshToken": refresh, "refreshExpiresAt": rotated.RefreshExpiresAt,
	})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	principal := principalFrom(r.Context())
	if err := s.db.RevokeSession(r.Context(), principal.SessionID, time.Now().UTC()); err != nil {
		writeProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"user": principalFrom(r.Context()).User})
}

type passwordResetRequest struct {
	Email string `json:"email"`
}

func (s *Server) requestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var request passwordResetRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeProblem(w, r, err)
		return
	}
	_, normalized, normalizeErr := normalizeEmail(request.Email)
	token, err := auth.NewToken(auth.PasswordResetToken)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	hash, err := auth.HashToken(s.config.TokenPepper, auth.PasswordResetToken, token)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	email := ""
	created := false
	if normalizeErr == nil {
		email, created, err = s.db.ReplacePasswordResetToken(r.Context(), normalized, uuid.New(), hash, time.Now().UTC().Add(s.config.PasswordResetTTL))
		if err != nil {
			writeProblem(w, r, err)
			return
		}
	}
	if created {
		s.email.enqueue("password_reset", email, token, requestIDFrom(r.Context()))
	}
	response := map[string]any{"accepted": true}
	if created && s.config.ExposeDevTokens {
		response["developmentPasswordResetToken"] = token
	}
	writeJSON(w, http.StatusAccepted, response)
}

type confirmPasswordResetRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"newPassword"`
}

func (s *Server) confirmPasswordReset(w http.ResponseWriter, r *http.Request) {
	var request confirmPasswordResetRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeProblem(w, r, err)
		return
	}
	tokenHash, err := auth.HashToken(s.config.TokenPepper, auth.PasswordResetToken, request.Token)
	if err != nil {
		writeProblem(w, r, errBadRequest)
		return
	}
	passwordHash, err := s.passwords.Hash(request.NewPassword)
	if err != nil {
		writeProblem(w, r, errBadRequest)
		return
	}
	if err := s.db.ConsumePasswordResetToken(r.Context(), tokenHash, passwordHash, time.Now().UTC()); err != nil {
		writeProblem(w, r, errBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func normalizeEmail(value string) (display, normalized string, err error) {
	display, normalized, err = identity.NormalizeEmail(value)
	if err != nil {
		return "", "", errBadRequest
	}
	return display, normalized, nil
}
