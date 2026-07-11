package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	storeerrors "github.com/deni336/DeniLicense/internal/store"
)

type problem struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Status    int    `json:"status"`
	Code      string `json:"code"`
	Detail    string `json:"detail,omitempty"`
	RequestID string `json:"requestId"`
}

func writeProblem(w http.ResponseWriter, r *http.Request, err error) {
	status := http.StatusInternalServerError
	code := "internal_error"
	title := "Internal server error"
	detail := "The request could not be completed."

	switch {
	case errors.Is(err, errBadRequest), errors.Is(err, storeerrors.ErrInvalid):
		status, code, title, detail = http.StatusBadRequest, "invalid_request", "Invalid request", "The request was not valid."
	case errors.Is(err, errUnauthenticated), errors.Is(err, storeerrors.ErrUnauthorized):
		status, code, title, detail = http.StatusUnauthorized, "authentication_required", "Authentication required", "Authentication failed."
	case errors.Is(err, errEmailUnverified):
		status, code, title, detail = http.StatusForbidden, "email_verification_required", "Email verification required", "Verify the account email before continuing."
	case errors.Is(err, errForbidden):
		status, code, title, detail = http.StatusForbidden, "forbidden", "Forbidden", "You do not have permission to perform this action."
	case errors.Is(err, storeerrors.ErrNotFound):
		status, code, title, detail = http.StatusNotFound, "not_found", "Not found", "The requested resource was not found."
	case errors.Is(err, errRouteNotFound):
		status, code, title, detail = http.StatusNotFound, "not_found", "Not found", "The requested resource was not found."
	case errors.Is(err, errMethodNotAllowed):
		status, code, title, detail = http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed", "The HTTP method is not allowed for this resource."
	case errors.Is(err, storeerrors.ErrConflict):
		status, code, title, detail = http.StatusConflict, "conflict", "Conflict", "The request conflicts with existing state."
	case errors.Is(err, storeerrors.ErrRefreshReuse):
		status, code, title, detail = http.StatusUnauthorized, "session_compromised", "Session revoked", "Refresh-token reuse was detected; the session has been revoked."
	case errors.Is(err, storeerrors.ErrSeatLimit):
		status, code, title, detail = http.StatusConflict, "activation_limit_reached", "Activation limit reached", "No activation seats are currently available."
	case errors.Is(err, storeerrors.ErrLicenseState):
		status, code, title, detail = http.StatusConflict, "license_unavailable", "License unavailable", "The license is not currently usable."
	case errors.Is(err, errRateLimited):
		status, code, title, detail = http.StatusTooManyRequests, "rate_limited", "Too many requests", "Wait before trying again."
	}

	requestID := requestIDFrom(r.Context())
	if status >= 500 {
		slog.ErrorContext(r.Context(), "request failed", "request_id", requestID, "error", err)
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problem{
		Type:      "https://docs.denilicense.local/problems/" + code,
		Title:     title,
		Status:    status,
		Code:      code,
		Detail:    detail,
		RequestID: requestID,
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writePublicJSON(w http.ResponseWriter, status int, maxAge int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", maxAge))
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
