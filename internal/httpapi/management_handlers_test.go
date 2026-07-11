package httpapi

import (
	"net/http/httptest"
	"testing"

	"github.com/deni336/DeniLicense/internal/domain"
)

func TestManagementLimit(t *testing.T) {
	tests := []struct {
		query string
		want  int
		ok    bool
	}{
		{"", 100, true},
		{"?limit=1", 1, true},
		{"?limit=200", 200, true},
		{"?limit=0", 0, false},
		{"?limit=201", 0, false},
		{"?limit=invalid", 0, false},
	}
	for _, test := range tests {
		request := httptest.NewRequest("GET", "/admin"+test.query, nil)
		got, err := managementLimit(request, 100)
		if (err == nil) != test.ok || got != test.want {
			t.Errorf("query %q: limit=%d err=%v", test.query, got, err)
		}
	}
}

func TestManagementValidators(t *testing.T) {
	for _, value := range []string{"0123", "ABYZ", "9JKM"} {
		if !validClaimCodeSuffix(value) {
			t.Errorf("valid suffix %q rejected", value)
		}
	}
	for _, value := range []string{"", "ABC", "ABCI", "abc1", "ABCD1"} {
		if validClaimCodeSuffix(value) {
			t.Errorf("invalid suffix %q accepted", value)
		}
	}
	for _, role := range []domain.Role{
		domain.RolePlatformOwner, domain.RoleLicenseAdmin, domain.RoleSupport,
		domain.RoleAuditor, domain.RoleCustomer,
	} {
		if !validManagementRole(role) {
			t.Errorf("valid role %q rejected", role)
		}
	}
	if validManagementRole("superuser") {
		t.Fatal("unknown role accepted")
	}
}
