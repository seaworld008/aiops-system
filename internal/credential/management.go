package credential

import (
	"context"
	"time"
)

const (
	DefaultManagementPageSize = 50
	MaxManagementPageSize     = 100
)

// ManagementScope is the exact OIDC-authorized database scope. Management
// queries and mutations must include both identifiers in the same SQL
// statement that reads or changes a revocation, so a caller cannot enumerate a
// valid revocation ID across workspace or environment boundaries.
type ManagementScope struct {
	WorkspaceID   string
	EnvironmentID string
}

type ManagementActor struct {
	// Subject is the trusted canonical "oidc:<sub>" identity. HTTP request
	// bodies and headers must never populate it.
	Subject       string
	PlatformAdmin bool
}

// ManagementRecord is the only credential-revocation projection allowed to
// cross into the OIDC control plane. It deliberately omits ciphertext,
// accessor HMAC/key ID, action/claim token digests, worker identity, and raw
// failure details.
type ManagementRecord struct {
	ID                     string           `json:"id"`
	WorkspaceID            string           `json:"workspace_id"`
	EnvironmentID          string           `json:"environment_id"`
	ActionID               string           `json:"action_id"`
	TargetKey              string           `json:"target_key"`
	ActionType             string           `json:"action_type"`
	ConnectorID            string           `json:"connector_id"`
	Status                 RevocationStatus `json:"status"`
	AccessorPresent        bool             `json:"accessor_present"`
	CredentialExpiresAt    time.Time        `json:"credential_expires_at"`
	Attempt                int              `json:"attempt"`
	FailureCount           int              `json:"failure_count"`
	FailureCode            FailureCode      `json:"failure_code,omitempty"`
	FailureDetailSHA256    string           `json:"failure_detail_sha256,omitempty"`
	AvailableAt            time.Time        `json:"available_at"`
	EvidenceHash           string           `json:"evidence_hash,omitempty"`
	ConfirmationCount      int              `json:"confirmation_count"`
	PlatformAdminConfirmed bool             `json:"platform_admin_confirmed"`
	ManualRequiredAt       time.Time        `json:"manual_required_at,omitempty"`
	RevokedAt              time.Time        `json:"revoked_at,omitempty"`
	Version                int64            `json:"version"`
	CreatedAt              time.Time        `json:"created_at"`
	UpdatedAt              time.Time        `json:"updated_at"`
}

type ManagementCursor struct {
	CreatedAt    time.Time
	RevocationID string
}

type ManagementListRequest struct {
	Scope  ManagementScope
	Actor  ManagementActor
	Status RevocationStatus
	Limit  int
	After  *ManagementCursor
}

type ManagementGetRequest struct {
	Scope        ManagementScope
	Actor        ManagementActor
	RevocationID string
}

type ManagementRequeueRequest struct {
	Scope        ManagementScope
	Actor        ManagementActor
	RevocationID string
}

type ManagementConfirmationRequest struct {
	Scope        ManagementScope
	Actor        ManagementActor
	RevocationID string
	EvidenceHash string
}

type ManagementPage struct {
	Items []ManagementRecord
	Next  *ManagementCursor
}

// ManagementStore is separate from Repository so the public control plane can
// be assembled without a credential ReferenceProtector and cannot accidentally
// select protected accessor material into its process.
type ManagementStore interface {
	ListManagement(context.Context, ManagementListRequest) (ManagementPage, error)
	GetManagement(context.Context, ManagementGetRequest) (ManagementRecord, error)
	RequeueManagement(context.Context, ManagementRequeueRequest) (ManagementRecord, error)
	ConfirmManagement(context.Context, ManagementConfirmationRequest) (ManagementRecord, error)
}

func ValidManagementScope(scope ManagementScope) bool {
	return uuidPattern.MatchString(scope.WorkspaceID) && uuidPattern.MatchString(scope.EnvironmentID)
}

func ValidManagementActor(actor ManagementActor) bool {
	return ValidConfirmationSubject(actor.Subject)
}

func ValidManagementCursor(cursor *ManagementCursor) bool {
	return cursor == nil || (!cursor.CreatedAt.IsZero() && cursor.CreatedAt.Location() == time.UTC &&
		cursor.CreatedAt == CanonicalCredentialExpiry(cursor.CreatedAt) && uuidPattern.MatchString(cursor.RevocationID))
}

func ValidManagementRecord(record ManagementRecord) bool {
	if !uuidPattern.MatchString(record.ID) || !ValidManagementScope(ManagementScope{
		WorkspaceID: record.WorkspaceID, EnvironmentID: record.EnvironmentID,
	}) || !ValidIdentifier(record.ActionID, 256) || !ValidIdentifier(record.TargetKey, 512) ||
		!ValidIdentifier(record.ActionType, 256) || !ValidIdentifier(record.ConnectorID, 256) ||
		!ValidRevocationStatus(record.Status) || record.Version < 1 || record.Attempt < 0 || record.FailureCount < 0 ||
		record.ConfirmationCount < 0 || record.ConfirmationCount > 2 ||
		(record.PlatformAdminConfirmed && record.ConfirmationCount == 0) ||
		!validManagementTime(record.CredentialExpiresAt) || !validManagementTime(record.AvailableAt) ||
		!validManagementTime(record.CreatedAt) || !validManagementTime(record.UpdatedAt) ||
		record.UpdatedAt.Before(record.CreatedAt) ||
		(!record.ManualRequiredAt.IsZero() && !validManagementTime(record.ManualRequiredAt)) ||
		(!record.RevokedAt.IsZero() && !validManagementTime(record.RevokedAt)) {
		return false
	}
	if !record.CredentialExpiresAt.After(record.CreatedAt) ||
		record.CredentialExpiresAt.Sub(record.CreatedAt) > MaxCredentialTTL ||
		!validManagementLifecycleTime(record.ManualRequiredAt, record.CreatedAt, record.UpdatedAt) ||
		!validManagementLifecycleTime(record.RevokedAt, record.CreatedAt, record.UpdatedAt) ||
		(!record.ManualRequiredAt.IsZero() && !record.RevokedAt.IsZero() && record.RevokedAt.Before(record.ManualRequiredAt)) {
		return false
	}
	if record.FailureCount == 0 {
		if record.FailureCode != "" || record.FailureDetailSHA256 != "" {
			return false
		}
	} else if !ValidFailureCode(record.FailureCode) || !ValidSHA256(record.FailureDetailSHA256) {
		return false
	}
	wantAccessor := record.Status == StatusAnchored || record.Status == StatusActive ||
		record.Status == StatusRevocationPending || record.Status == StatusRevoking || record.Status == StatusManualRequired
	if record.AccessorPresent != wantAccessor ||
		((record.Status == StatusPrepared || record.Status == StatusNoCredential || record.Status == StatusAnchored ||
			record.Status == StatusActive) && !record.ManualRequiredAt.IsZero()) ||
		(record.Status == StatusManualRequired && (record.ManualRequiredAt.IsZero() || record.FailureCount == 0)) ||
		(record.Status == StatusRevoking && record.Attempt == 0) ||
		(record.Status == StatusRevoked) != !record.RevokedAt.IsZero() {
		return false
	}
	if record.EvidenceHash == "" {
		return record.ConfirmationCount == 0 && !record.PlatformAdminConfirmed
	}
	if !ValidSHA256(record.EvidenceHash) {
		return false
	}
	if record.Status == StatusManualRequired {
		return record.ConfirmationCount == 1
	}
	return record.Status == StatusRevoked && record.ConfirmationCount == 2 && record.PlatformAdminConfirmed
}

func validManagementTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value == CanonicalCredentialExpiry(value)
}

func validManagementLifecycleTime(value, createdAt, updatedAt time.Time) bool {
	return value.IsZero() || (!value.Before(createdAt) && !value.After(updatedAt))
}
