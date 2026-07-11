package httpapi

import (
	"net/http"
	"strconv"
	"strings"
	"unicode"

	"github.com/deni336/DeniLicense/internal/domain"
	"github.com/deni336/DeniLicense/internal/store/postgres"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (s *Server) listLicenseActivations(w http.ResponseWriter, r *http.Request) {
	licenseID, err := uuid.Parse(chi.URLParam(r, "licenseID"))
	if err != nil {
		writeProblem(w, r, errBadRequest)
		return
	}
	items, err := s.db.ListActivationsForOwner(r.Context(), licenseID, principalFrom(r.Context()).User.ID)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) listAdminLicenses(w http.ResponseWriter, r *http.Request) {
	limit, err := managementLimit(r, 100)
	if err != nil {
		writeProblem(w, r, errBadRequest)
		return
	}
	filter := postgres.LicenseListFilter{Limit: limit}
	if value := strings.TrimSpace(r.URL.Query().Get("serial")); value != "" {
		serial, err := uuid.Parse(value)
		if err != nil || serial.String() != value {
			writeProblem(w, r, errBadRequest)
			return
		}
		filter.Serial = &serial
	}
	if value := strings.TrimSpace(r.URL.Query().Get("ownerEmail")); value != "" {
		_, normalized, err := normalizeEmail(value)
		if err != nil {
			writeProblem(w, r, errBadRequest)
			return
		}
		filter.OwnerNormalizedEmail = normalized
	}
	if value := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("claimCodeSuffix"))); value != "" {
		if !validClaimCodeSuffix(value) {
			writeProblem(w, r, errBadRequest)
			return
		}
		filter.ClaimCodeSuffix = value
	}
	if value := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("productCode"))); value != "" {
		if !productCodePattern.MatchString(value) {
			writeProblem(w, r, errBadRequest)
			return
		}
		filter.ProductCode = value
	}
	if value := strings.TrimSpace(r.URL.Query().Get("state")); value != "" {
		if value != "active" && value != "suspended" && value != "revoked" {
			writeProblem(w, r, errBadRequest)
			return
		}
		filter.State = value
	}
	items, err := s.db.ListLicenses(r.Context(), filter)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) getAdminLicense(w http.ResponseWriter, r *http.Request) {
	licenseID, err := uuid.Parse(chi.URLParam(r, "licenseID"))
	if err != nil {
		writeProblem(w, r, errBadRequest)
		return
	}
	license, err := s.db.LicenseByID(r.Context(), licenseID)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"license": license})
}

func (s *Server) listAdminActivations(w http.ResponseWriter, r *http.Request) {
	licenseID, err := uuid.Parse(chi.URLParam(r, "licenseID"))
	if err != nil {
		writeProblem(w, r, errBadRequest)
		return
	}
	items, err := s.db.ListActivations(r.Context(), licenseID)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) deactivateAdminActivation(w http.ResponseWriter, r *http.Request) {
	activationID, err := uuid.Parse(chi.URLParam(r, "activationID"))
	if err != nil {
		writeProblem(w, r, errBadRequest)
		return
	}
	if err := s.db.DeactivateActivation(r.Context(), activationID, auditFor(r, "activation.admin_deactivate", "activation")); err != nil {
		writeProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listAdminUsers(w http.ResponseWriter, r *http.Request) {
	limit, err := managementLimit(r, 100)
	if err != nil {
		writeProblem(w, r, errBadRequest)
		return
	}
	normalized := ""
	if value := strings.TrimSpace(r.URL.Query().Get("email")); value != "" {
		_, normalized, err = normalizeEmail(value)
		if err != nil {
			writeProblem(w, r, errBadRequest)
			return
		}
	}
	items, err := s.db.ListUsers(r.Context(), normalized, limit)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) getAdminUser(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		writeProblem(w, r, errBadRequest)
		return
	}
	user, err := s.db.UserByID(r.Context(), userID)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

type userRoleRequest struct {
	Role domain.Role `json:"role"`
}

func (s *Server) setAdminUserRole(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		writeProblem(w, r, errBadRequest)
		return
	}
	var request userRoleRequest
	if err := decodeJSON(w, r, &request); err != nil || !validManagementRole(request.Role) {
		writeProblem(w, r, errBadRequest)
		return
	}
	user, err := s.db.UpdateUserAccess(r.Context(), postgres.UpdateUserAccessParams{
		UserID: userID,
		Role:   &request.Role,
		Audit:  auditFor(r, "user.role_change", "user"),
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

type userStatusRequest struct {
	Status string `json:"status"`
}

func (s *Server) setAdminUserStatus(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		writeProblem(w, r, errBadRequest)
		return
	}
	var request userStatusRequest
	if err := decodeJSON(w, r, &request); err != nil || (request.Status != "active" && request.Status != "disabled") {
		writeProblem(w, r, errBadRequest)
		return
	}
	user, err := s.db.UpdateUserAccess(r.Context(), postgres.UpdateUserAccessParams{
		UserID: userID,
		Status: &request.Status,
		Audit:  auditFor(r, "user.status_change", "user"),
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

func (s *Server) listAuditEvents(w http.ResponseWriter, r *http.Request) {
	limit, err := managementLimit(r, 100)
	if err != nil {
		writeProblem(w, r, errBadRequest)
		return
	}
	filter := postgres.AuditListFilter{Limit: limit}
	if value := strings.TrimSpace(r.URL.Query().Get("beforeId")); value != "" {
		filter.BeforeID, err = strconv.ParseInt(value, 10, 64)
		if err != nil || filter.BeforeID <= 0 {
			writeProblem(w, r, errBadRequest)
			return
		}
	}
	filter.Action = strings.TrimSpace(r.URL.Query().Get("action"))
	filter.TargetType = strings.TrimSpace(r.URL.Query().Get("targetType"))
	filter.TargetID = strings.TrimSpace(r.URL.Query().Get("targetId"))
	if !validManagementFilter(filter.Action, 128) || !validManagementFilter(filter.TargetType, 128) || !validManagementFilter(filter.TargetID, 256) {
		writeProblem(w, r, errBadRequest)
		return
	}
	if value := strings.TrimSpace(r.URL.Query().Get("actorUserId")); value != "" {
		actorID, err := uuid.Parse(value)
		if err != nil {
			writeProblem(w, r, errBadRequest)
			return
		}
		filter.ActorUserID = &actorID
	}
	items, err := s.db.ListAuditEvents(r.Context(), filter)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func managementLimit(r *http.Request, fallback int) (int, error) {
	value := strings.TrimSpace(r.URL.Query().Get("limit"))
	if value == "" {
		return fallback, nil
	}
	limit, err := strconv.Atoi(value)
	if err != nil || limit < 1 || limit > 200 {
		return 0, errBadRequest
	}
	return limit, nil
}

func validClaimCodeSuffix(value string) bool {
	if len(value) != 4 {
		return false
	}
	for _, character := range value {
		if !strings.ContainsRune("0123456789ABCDEFGHJKMNPQRSTVWXYZ", character) {
			return false
		}
	}
	return true
}

func validManagementRole(role domain.Role) bool {
	switch role {
	case domain.RolePlatformOwner, domain.RoleLicenseAdmin, domain.RoleSupport, domain.RoleAuditor, domain.RoleCustomer:
		return true
	default:
		return false
	}
}

func validManagementFilter(value string, maxBytes int) bool {
	if len(value) > maxBytes || value != strings.TrimSpace(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
