package integration_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	deniclient "github.com/deni336/DeniLicense/client"
	"github.com/deni336/DeniLicense/internal/claimcode"
	"github.com/deni336/DeniLicense/internal/lease"
	"github.com/deni336/DeniLicense/internal/license"
	"github.com/google/uuid"
)

type apiClient struct {
	baseURL string
	http    *http.Client
}

func TestEndToEndLicensingFlow(t *testing.T) {
	baseURL := strings.TrimRight(os.Getenv("DENILICENSE_INTEGRATION_URL"), "/")
	if baseURL == "" {
		t.Skip("set DENILICENSE_INTEGRATION_URL to run PostgreSQL/API integration tests")
	}
	ownerEmail := envOr("DENILICENSE_INTEGRATION_OWNER_EMAIL", "owner@example.com")
	ownerPassword := envOr("DENILICENSE_INTEGRATION_OWNER_PASSWORD", "correct horse battery staple")
	client := apiClient{baseURL: baseURL, http: &http.Client{Timeout: 10 * time.Second}}

	owner := login(t, client, ownerEmail, ownerPassword)
	unique := strings.ToUpper(strings.ReplaceAll(uuid.NewString()[:8], "-", ""))
	productCode := "T" + unique
	status, _ := client.call(t, http.MethodPost, "/api/v1/admin/products", owner.AccessToken, map[string]any{
		"code": productCode, "name": "Integration Product", "description": "Automated end-to-end test",
	})
	requireStatus(t, status, http.StatusCreated)

	onlineRequest := map[string]any{
		"productCode": productCode, "subject": "online-integration", "expiresAt": time.Now().UTC().Add(24 * time.Hour),
		"maxActivations": 2, "entitlements": map[string]any{"feature.online": true},
	}
	idempotencyKey := "integration-" + strings.ToLower(unique)
	status, onlineBody := client.callHeaders(t, http.MethodPost, "/api/v1/admin/licenses", owner.AccessToken, map[string]string{"Idempotency-Key": idempotencyKey}, onlineRequest)
	requireStatus(t, status, http.StatusCreated)
	var onlineCreated struct {
		License struct {
			ID string `json:"id"`
		} `json:"license"`
		ClaimCode string `json:"claimCode"`
	}
	decode(t, onlineBody, &onlineCreated)
	status, onlineRetryBody := client.callHeaders(t, http.MethodPost, "/api/v1/admin/licenses", owner.AccessToken, map[string]string{"Idempotency-Key": idempotencyKey}, onlineRequest)
	requireStatus(t, status, http.StatusOK)
	var onlineRetried struct {
		License struct {
			ID string `json:"id"`
		} `json:"license"`
		ClaimCode  string `json:"claimCode"`
		Idempotent bool   `json:"idempotent"`
	}
	decode(t, onlineRetryBody, &onlineRetried)
	if !onlineRetried.Idempotent || onlineRetried.License.ID != onlineCreated.License.ID || onlineRetried.ClaimCode != onlineCreated.ClaimCode {
		t.Fatal("online retry did not return the same license and claim code")
	}
	changedOnlineRequest := map[string]any{
		"productCode": productCode, "subject": "changed-request", "expiresAt": time.Now().UTC().Add(24 * time.Hour),
		"maxActivations": 2, "entitlements": map[string]any{"feature.online": true},
	}
	status, _ = client.callHeaders(t, http.MethodPost, "/api/v1/admin/licenses", owner.AccessToken, map[string]string{"Idempotency-Key": idempotencyKey}, changedOnlineRequest)
	requireStatus(t, status, http.StatusConflict)

	issuerKey, err := license.GenerateSigningKey(license.PurposeOfflineLicenseIssuer)
	if err != nil {
		t.Fatal(err)
	}
	publicDocument, err := license.MarshalPublicKey(issuerKey.VerificationKey())
	if err != nil {
		t.Fatal(err)
	}
	issuer := "integration/" + strings.ToLower(unique)
	status, _ = client.call(t, http.MethodPost, "/api/v1/admin/issuers", owner.AccessToken, map[string]any{
		"issuer": issuer, "publicKeyDocument": string(publicDocument), "notBefore": time.Now().UTC().Add(-time.Minute),
	})
	requireStatus(t, status, http.StatusCreated)

	claimCode, claimDigest, suffix, err := claimcode.Generate()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(24 * time.Hour)
	serial := uuid.NewString()
	artifact, err := license.SignToken(license.Claims{
		Issuer: issuer, KeyID: issuerKey.KeyID(), Audience: productCode, Serial: serial,
		Subject: "integration-customer", ClaimCodeSHA256: license.EncodeClaimCodeSHA256(claimDigest),
		ClaimCodeSuffix: suffix, IssuedAt: now, NotBefore: now, ExpiresAt: &expires,
		MaxActivations: 1, Entitlements: map[string]any{"feature.integration": true, "projects.max": int64(5)},
	}, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	status, importedBody := client.call(t, http.MethodPost, "/api/v1/admin/licenses/import", owner.AccessToken, map[string]any{"artifact": artifact})
	requireStatus(t, status, http.StatusCreated)
	var imported struct {
		License struct {
			ID string `json:"id"`
		} `json:"license"`
		Idempotent bool `json:"idempotent"`
	}
	decode(t, importedBody, &imported)
	if imported.Idempotent || imported.License.ID == "" {
		t.Fatalf("unexpected initial import: %s", importedBody)
	}
	status, secondImport := client.call(t, http.MethodPost, "/api/v1/admin/licenses/import", owner.AccessToken, map[string]any{"artifact": artifact})
	requireStatus(t, status, http.StatusOK)
	var repeated struct {
		Idempotent bool `json:"idempotent"`
	}
	decode(t, secondImport, &repeated)
	if !repeated.Idempotent {
		t.Fatal("exact re-import was not idempotent")
	}
	_, conflictingDigest, conflictingSuffix, err := claimcode.Generate()
	if err != nil {
		t.Fatal(err)
	}
	conflictingArtifact, err := license.SignToken(license.Claims{
		Issuer: issuer, KeyID: issuerKey.KeyID(), Audience: productCode, Serial: serial,
		Subject: "conflicting-customer", ClaimCodeSHA256: license.EncodeClaimCodeSHA256(conflictingDigest),
		ClaimCodeSuffix: conflictingSuffix, IssuedAt: now, NotBefore: now, ExpiresAt: &expires,
		MaxActivations: 1, Entitlements: map[string]any{"feature.integration": true},
	}, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	status, _ = client.call(t, http.MethodPost, "/api/v1/admin/licenses/import", owner.AccessToken, map[string]any{"artifact": conflictingArtifact})
	requireStatus(t, status, http.StatusConflict)
	tampered := artifact[:len(artifact)-1] + alternateBase64Character(artifact[len(artifact)-1])
	status, _ = client.call(t, http.MethodPost, "/api/v1/admin/licenses/import", owner.AccessToken, map[string]any{"artifact": tampered})
	if status < 400 || status >= 500 {
		t.Fatalf("tampered import status = %d", status)
	}
	status, adminLicenseBody := client.call(t, http.MethodGet, "/api/v1/admin/licenses/"+imported.License.ID, owner.AccessToken, nil)
	requireStatus(t, status, http.StatusOK)
	var adminLicense struct {
		License struct {
			ID string `json:"id"`
		} `json:"license"`
	}
	decode(t, adminLicenseBody, &adminLicense)
	if adminLicense.License.ID != imported.License.ID {
		t.Fatalf("admin license lookup returned %q", adminLicense.License.ID)
	}
	status, adminLicenseListBody := client.call(t, http.MethodGet, "/api/v1/admin/licenses?claimCodeSuffix="+suffix, owner.AccessToken, nil)
	requireStatus(t, status, http.StatusOK)
	var adminLicenseList struct {
		Items []idItem `json:"items"`
	}
	decode(t, adminLicenseListBody, &adminLicenseList)
	if !containsID(adminLicenseList.Items, imported.License.ID) {
		t.Fatalf("admin license suffix lookup omitted %s", imported.License.ID)
	}

	customerEmail := "customer-" + strings.ToLower(unique) + "@example.com"
	status, registrationBody := client.call(t, http.MethodPost, "/api/v1/auth/register", "", map[string]any{
		"email": customerEmail, "password": "another correct horse battery staple",
	})
	requireStatus(t, status, http.StatusAccepted)
	var registration struct {
		Token string `json:"developmentVerificationToken"`
	}
	decode(t, registrationBody, &registration)
	if registration.Token == "" {
		t.Fatal("development verification token missing")
	}
	status, _ = client.call(t, http.MethodPost, "/api/v1/auth/verify-email", "", map[string]any{"token": registration.Token})
	requireStatus(t, status, http.StatusOK)
	customer := login(t, client, customerEmail, "another correct horse battery staple")

	status, claimBody := client.call(t, http.MethodPost, "/api/v1/licenses/claim", customer.AccessToken, map[string]any{"claimCode": claimCode})
	requireStatus(t, status, http.StatusOK)
	var claimed struct {
		License struct {
			ID string `json:"id"`
		} `json:"license"`
	}
	decode(t, claimBody, &claimed)
	if claimed.License.ID != imported.License.ID {
		t.Fatalf("claimed license %s, imported %s", claimed.License.ID, imported.License.ID)
	}

	devicePublic, devicePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	status, activationBody := client.call(t, http.MethodPost, "/api/v1/licenses/"+claimed.License.ID+"/activations", customer.AccessToken, map[string]any{
		"devicePublicKey": base64.RawURLEncoding.EncodeToString(devicePublic), "label": "integration device",
	})
	requireStatus(t, status, http.StatusCreated)
	var activated activationResponse
	decode(t, activationBody, &activated)
	verifyLease(t, client, activated.Lease, productCode, devicePublic)
	status, customerActivationsBody := client.call(t, http.MethodGet, "/api/v1/licenses/"+claimed.License.ID+"/activations", customer.AccessToken, nil)
	requireStatus(t, status, http.StatusOK)
	var customerActivations activationListResponse
	decode(t, customerActivationsBody, &customerActivations)
	if !containsID(customerActivations.Items, activated.Activation.ID) {
		t.Fatalf("customer activation list omitted %s", activated.Activation.ID)
	}
	status, adminActivationsBody := client.call(t, http.MethodGet, "/api/v1/admin/licenses/"+claimed.License.ID+"/activations", owner.AccessToken, nil)
	requireStatus(t, status, http.StatusOK)
	var adminActivations activationListResponse
	decode(t, adminActivationsBody, &adminActivations)
	if !containsID(adminActivations.Items, activated.Activation.ID) {
		t.Fatalf("admin activation list omitted %s", activated.Activation.ID)
	}

	secondPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	status, _ = client.call(t, http.MethodPost, "/api/v1/licenses/"+claimed.License.ID+"/activations", customer.AccessToken, map[string]any{
		"devicePublicKey": base64.RawURLEncoding.EncodeToString(secondPublic), "label": "seat overflow",
	})
	requireStatus(t, status, http.StatusConflict)

	status, challengeBody := client.call(t, http.MethodPost, "/api/v1/activation-challenges", "", map[string]any{"activationId": activated.Activation.ID})
	requireStatus(t, status, http.StatusCreated)
	var challenge deniclient.RenewalChallenge
	decode(t, challengeBody, &challenge)
	signatureText, err := deniclient.SignRenewalChallenge(devicePrivate, challenge, activated.Activation.ID)
	if err != nil {
		t.Fatal(err)
	}
	status, renewalBody := client.call(t, http.MethodPost, "/api/v1/activation-challenges/complete", "", map[string]any{
		"challengeId": challenge.ChallengeID, "nonce": challenge.Nonce,
		"signature": signatureText,
	})
	requireStatus(t, status, http.StatusOK)
	var renewed activationResponse
	decode(t, renewalBody, &renewed)
	verifyLease(t, client, renewed.Lease, productCode, devicePublic)
	status, _ = client.call(t, http.MethodPost, "/api/v1/activation-challenges/complete", "", map[string]any{
		"challengeId": challenge.ChallengeID, "nonce": challenge.Nonce,
		"signature": signatureText,
	})
	if status < 400 || status >= 500 {
		t.Fatalf("replayed challenge status = %d", status)
	}

	t.Run("seat allocation remains atomic", func(t *testing.T) {
		// The overflow request above is repeated concurrently to exercise the
		// license-row lock; all attempts must remain conflicts.
		var wait sync.WaitGroup
		statuses := make(chan int, 8)
		for i := 0; i < 8; i++ {
			wait.Add(1)
			go func() {
				defer wait.Done()
				public, _, _ := ed25519.GenerateKey(rand.Reader)
				status, _ := client.call(t, http.MethodPost, "/api/v1/licenses/"+claimed.License.ID+"/activations", customer.AccessToken, map[string]any{
					"devicePublicKey": base64.RawURLEncoding.EncodeToString(public), "label": "concurrent overflow",
				})
				statuses <- status
			}()
		}
		wait.Wait()
		close(statuses)
		for status := range statuses {
			if status != http.StatusConflict {
				t.Errorf("concurrent activation status = %d", status)
			}
		}
	})

	managementOwner := owner
	status, _ = client.call(t, http.MethodDelete, "/api/v1/admin/activations/"+activated.Activation.ID, managementOwner.AccessToken, nil)
	requireStatus(t, status, http.StatusNoContent)
	status, _ = client.call(t, http.MethodDelete, "/api/v1/admin/activations/"+activated.Activation.ID, managementOwner.AccessToken, nil)
	requireStatus(t, status, http.StatusNoContent)
	status, _ = client.call(t, http.MethodDelete, "/api/v1/activations/"+activated.Activation.ID, customer.AccessToken, nil)
	requireStatus(t, status, http.StatusNoContent)
	status, replacementActivationBody := client.call(t, http.MethodPost, "/api/v1/licenses/"+claimed.License.ID+"/activations", customer.AccessToken, map[string]any{
		"devicePublicKey": base64.RawURLEncoding.EncodeToString(secondPublic), "label": "replacement device",
	})
	requireStatus(t, status, http.StatusCreated)
	var replacementActivation activationResponse
	decode(t, replacementActivationBody, &replacementActivation)

	resetPassword := "a newly reset correct horse password"
	t.Run("password reset revokes existing sessions", func(t *testing.T) {
		status, body := client.call(t, http.MethodPost, "/api/v1/auth/password-reset/request", "", map[string]any{"email": customerEmail})
		requireStatus(t, status, http.StatusAccepted)
		var reset struct {
			Token string `json:"developmentPasswordResetToken"`
		}
		decode(t, body, &reset)
		if reset.Token == "" {
			t.Fatal("development password-reset token missing")
		}
		status, _ = client.call(t, http.MethodPost, "/api/v1/auth/password-reset/confirm", "", map[string]any{
			"token": reset.Token, "newPassword": resetPassword,
		})
		requireStatus(t, status, http.StatusNoContent)
		status, _ = client.call(t, http.MethodGet, "/api/v1/auth/me", customer.AccessToken, nil)
		requireStatus(t, status, http.StatusUnauthorized)
	})

	status, customerUsersBody := client.call(t, http.MethodGet, "/api/v1/admin/users?email="+url.QueryEscape(customerEmail), managementOwner.AccessToken, nil)
	requireStatus(t, status, http.StatusOK)
	var customerUsers userListResponse
	decode(t, customerUsersBody, &customerUsers)
	if len(customerUsers.Items) != 1 {
		t.Fatalf("customer user lookup returned %d items", len(customerUsers.Items))
	}
	customerID := customerUsers.Items[0].ID
	status, ownerUsersBody := client.call(t, http.MethodGet, "/api/v1/admin/users?email="+url.QueryEscape(ownerEmail), managementOwner.AccessToken, nil)
	requireStatus(t, status, http.StatusOK)
	var ownerUsers userListResponse
	decode(t, ownerUsersBody, &ownerUsers)
	if len(ownerUsers.Items) != 1 {
		t.Fatalf("owner user lookup returned %d items", len(ownerUsers.Items))
	}
	status, _ = client.call(t, http.MethodPost, "/api/v1/admin/users/"+ownerUsers.Items[0].ID+"/status", managementOwner.AccessToken, map[string]any{"status": "disabled"})
	requireStatus(t, status, http.StatusConflict)

	preRoleChange := login(t, client, customerEmail, resetPassword)
	status, roleBody := client.call(t, http.MethodPost, "/api/v1/admin/users/"+customerID+"/role", managementOwner.AccessToken, map[string]any{"role": "auditor"})
	requireStatus(t, status, http.StatusOK)
	var roleResult struct {
		User struct {
			Role string `json:"role"`
		} `json:"user"`
	}
	decode(t, roleBody, &roleResult)
	if roleResult.User.Role != "auditor" {
		t.Fatalf("updated role = %q", roleResult.User.Role)
	}
	status, _ = client.call(t, http.MethodGet, "/api/v1/auth/me", preRoleChange.AccessToken, nil)
	requireStatus(t, status, http.StatusUnauthorized)
	auditor := login(t, client, customerEmail, resetPassword)
	status, auditBody := client.call(t, http.MethodGet, "/api/v1/admin/audit-events?action=user.role_change", auditor.AccessToken, nil)
	requireStatus(t, status, http.StatusOK)
	var audits struct {
		Items []struct {
			TargetID string `json:"targetId"`
		} `json:"items"`
	}
	decode(t, auditBody, &audits)
	if len(audits.Items) == 0 || audits.Items[0].TargetID != customerID {
		t.Fatalf("role-change audit missing for %s", customerID)
	}
	status, _ = client.call(t, http.MethodGet, "/api/v1/admin/licenses/"+claimed.License.ID, auditor.AccessToken, nil)
	requireStatus(t, status, http.StatusOK)
	status, _ = client.call(t, http.MethodDelete, "/api/v1/admin/activations/"+replacementActivation.Activation.ID, auditor.AccessToken, nil)
	requireStatus(t, status, http.StatusForbidden)

	status, _ = client.call(t, http.MethodPost, "/api/v1/admin/licenses/"+claimed.License.ID+"/state", managementOwner.AccessToken, map[string]any{"state": "revoked"})
	requireStatus(t, status, http.StatusNoContent)
	status, _ = client.call(t, http.MethodPost, "/api/v1/admin/licenses/"+claimed.License.ID+"/state", managementOwner.AccessToken, map[string]any{"state": "revoked"})
	requireStatus(t, status, http.StatusNoContent)
	thirdPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	status, _ = client.call(t, http.MethodPost, "/api/v1/licenses/"+claimed.License.ID+"/activations", auditor.AccessToken, map[string]any{
		"devicePublicKey": base64.RawURLEncoding.EncodeToString(thirdPublic), "label": "revoked license",
	})
	requireStatus(t, status, http.StatusConflict)

	status, _ = client.call(t, http.MethodPost, "/api/v1/admin/issuers/"+issuerKey.KeyID()+"/status", managementOwner.AccessToken, map[string]any{"status": "revoked"})
	requireStatus(t, status, http.StatusNoContent)
	status, revokedReimport := client.call(t, http.MethodPost, "/api/v1/admin/licenses/import", managementOwner.AccessToken, map[string]any{"artifact": artifact})
	requireStatus(t, status, http.StatusOK)
	var revokedRepeated struct {
		Idempotent bool `json:"idempotent"`
	}
	decode(t, revokedReimport, &revokedRepeated)
	if !revokedRepeated.Idempotent {
		t.Fatal("exact re-import under revoked issuer was not idempotent")
	}
	_, rejectedDigest, rejectedSuffix, err := claimcode.Generate()
	if err != nil {
		t.Fatal(err)
	}
	rejectedArtifact, err := license.SignToken(license.Claims{
		Issuer: issuer, KeyID: issuerKey.KeyID(), Audience: productCode, Serial: uuid.NewString(),
		Subject: "revoked-issuer", ClaimCodeSHA256: license.EncodeClaimCodeSHA256(rejectedDigest),
		ClaimCodeSuffix: rejectedSuffix, IssuedAt: now, NotBefore: now, ExpiresAt: &expires,
		MaxActivations: 1, Entitlements: map[string]any{},
	}, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	status, _ = client.call(t, http.MethodPost, "/api/v1/admin/licenses/import", managementOwner.AccessToken, map[string]any{"artifact": rejectedArtifact})
	requireStatus(t, status, http.StatusBadRequest)
	status, _ = client.call(t, http.MethodPost, "/api/v1/admin/issuers/"+issuerKey.KeyID()+"/status", managementOwner.AccessToken, map[string]any{"status": "active"})
	requireStatus(t, status, http.StatusConflict)

	// Account-management coverage adds auth calls to this end-to-end flow. Give
	// the deliberately small in-process login bucket enough time to refill so it
	// does not mask refresh-family behavior.
	time.Sleep(7 * time.Second)
	t.Run("refresh reuse revokes token family", func(t *testing.T) {
		status, body := client.call(t, http.MethodPost, "/api/v1/auth/refresh", "", map[string]any{"refreshToken": owner.RefreshToken})
		requireStatus(t, status, http.StatusOK)
		var rotated struct {
			RefreshToken string `json:"refreshToken"`
		}
		decode(t, body, &rotated)
		status, _ = client.call(t, http.MethodPost, "/api/v1/auth/refresh", "", map[string]any{"refreshToken": owner.RefreshToken})
		requireStatus(t, status, http.StatusUnauthorized)
		status, _ = client.call(t, http.MethodPost, "/api/v1/auth/refresh", "", map[string]any{"refreshToken": rotated.RefreshToken})
		requireStatus(t, status, http.StatusUnauthorized)
	})
}

type loginResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type activationResponse struct {
	Activation struct {
		ID string `json:"id"`
	} `json:"activation"`
	Lease string `json:"lease"`
}

type activationListResponse struct {
	Items []idItem `json:"items"`
}

type userListResponse struct {
	Items []idItem `json:"items"`
}

type idItem struct {
	ID string `json:"id"`
}

func containsID(items []idItem, expected string) bool {
	for _, item := range items {
		if item.ID == expected {
			return true
		}
	}
	return false
}

func login(t *testing.T, client apiClient, email, password string) loginResponse {
	t.Helper()
	status, body := client.call(t, http.MethodPost, "/api/v1/auth/login", "", map[string]any{"email": email, "password": password})
	requireStatus(t, status, http.StatusOK)
	var response loginResponse
	decode(t, body, &response)
	return response
}

func verifyLease(t *testing.T, client apiClient, token, product string, devicePublic ed25519.PublicKey) {
	t.Helper()
	status, body := client.call(t, http.MethodGet, "/.well-known/denilicense-activation-keys.json", "", nil)
	requireStatus(t, status, http.StatusOK)
	var keys lease.JWKS
	decode(t, body, &keys)
	if len(keys.Keys) != 1 {
		t.Fatalf("JWKS key count = %d", len(keys.Keys))
	}
	thumbprint, err := lease.DeviceKeyThumbprint(devicePublic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lease.VerifyJWK(token, keys.Keys[0], lease.VerifyOptions{
		ExpectedIssuer: envOr("DENILICENSE_INTEGRATION_ISSUER", client.baseURL), ExpectedAudience: product,
		ExpectedDeviceKeyThumbprint: thumbprint, Now: time.Now().UTC(), ClockLeeway: time.Minute,
	}); err != nil {
		t.Fatalf("verify activation lease: %v", err)
	}
}

func (c apiClient) call(t *testing.T, method, path, bearer string, body any) (int, []byte) {
	return c.callHeaders(t, method, path, bearer, nil, body)
}

func (c apiClient) callHeaders(t *testing.T, method, path, bearer string, headers map[string]string, body any) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, c.baseURL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := c.http.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, responseBody
}

func decode(t *testing.T, encoded []byte, destination any) {
	t.Helper()
	if err := json.Unmarshal(encoded, destination); err != nil {
		t.Fatalf("decode %s: %v", encoded, err)
	}
}

func requireStatus(t *testing.T, got, want int) {
	t.Helper()
	if got != want {
		t.Fatalf("HTTP status = %d, want %d", got, want)
	}
}

func alternateBase64Character(value byte) string {
	if value == 'A' {
		return "B"
	}
	return "A"
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
