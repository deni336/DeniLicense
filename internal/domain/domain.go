package domain

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type Role string

const (
	RolePlatformOwner Role = "platform_owner"
	RoleLicenseAdmin  Role = "license_admin"
	RoleSupport       Role = "support"
	RoleAuditor       Role = "auditor"
	RoleCustomer      Role = "customer"
)

func (r Role) IsPrivileged() bool { return r != RoleCustomer }

type User struct {
	ID              uuid.UUID  `json:"id"`
	Email           string     `json:"email"`
	Role            Role       `json:"role"`
	Status          string     `json:"status"`
	EmailVerifiedAt *time.Time `json:"emailVerifiedAt,omitempty"`
	CreatedAt       time.Time  `json:"createdAt"`
}

type Product struct {
	ID          uuid.UUID `json:"id"`
	Code        string    `json:"code"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type IssuerKey struct {
	KeyID     string     `json:"keyId"`
	Issuer    string     `json:"issuer"`
	PublicKey []byte     `json:"-"`
	Status    string     `json:"status"`
	NotBefore time.Time  `json:"notBefore"`
	NotAfter  *time.Time `json:"notAfter,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
}

type License struct {
	ID                  uuid.UUID       `json:"id"`
	Serial              uuid.UUID       `json:"serial"`
	ProductID           uuid.UUID       `json:"productId"`
	ProductCode         string          `json:"productCode"`
	OwnerUserID         *uuid.UUID      `json:"ownerUserId,omitempty"`
	OwnerEmail          string          `json:"ownerEmail,omitempty"`
	Source              string          `json:"source"`
	State               string          `json:"state"`
	Subject             string          `json:"subject,omitempty"`
	IssuedAt            time.Time       `json:"issuedAt"`
	NotBefore           time.Time       `json:"notBefore"`
	ExpiresAt           *time.Time      `json:"expiresAt,omitempty"`
	MaxActivations      int             `json:"maxActivations"`
	OfflineGraceSeconds int             `json:"offlineGraceSeconds"`
	Entitlements        json.RawMessage `json:"entitlements"`
	Metadata            json.RawMessage `json:"metadata"`
	Revision            int64           `json:"revision"`
	ClaimCodeSuffix     string          `json:"claimCodeSuffix"`
	ClaimedAt           *time.Time      `json:"claimedAt,omitempty"`
	CreatedAt           time.Time       `json:"createdAt"`
	UpdatedAt           time.Time       `json:"updatedAt"`
}

type Activation struct {
	ID             uuid.UUID `json:"id"`
	LicenseID      uuid.UUID `json:"licenseId"`
	Label          string    `json:"label"`
	State          string    `json:"state"`
	ActivatedAt    time.Time `json:"activatedAt"`
	LastSeenAt     time.Time `json:"lastSeenAt"`
	LeaseExpiresAt time.Time `json:"leaseExpiresAt"`
}

type AuditRecord struct {
	ID          int64           `json:"id"`
	OccurredAt  time.Time       `json:"occurredAt"`
	ActorUserID *uuid.UUID      `json:"actorUserId,omitempty"`
	ActorKind   string          `json:"actorKind"`
	Action      string          `json:"action"`
	TargetType  string          `json:"targetType"`
	TargetID    string          `json:"targetId"`
	RequestID   string          `json:"requestId"`
	Outcome     string          `json:"outcome"`
	Details     json.RawMessage `json:"details"`
}

type Principal struct {
	User      User
	SessionID uuid.UUID
}
