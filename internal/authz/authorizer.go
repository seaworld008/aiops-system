package authz

import (
	"errors"
	"slices"
	"time"

	"github.com/seaworld008/aiops-system/internal/authn"
)

var (
	ErrForbidden                = errors.New("forbidden")
	ErrReauthenticationRequired = errors.New("recent OIDC authentication required")
)

type Permission string

const (
	PermissionAssetRead                   Permission = "ASSET_READ"
	PermissionAssetManage                 Permission = "ASSET_MANAGE"
	PermissionAssetBind                   Permission = "ASSET_BIND"
	PermissionAssetConflictResolve        Permission = "ASSET_CONFLICT_RESOLVE"
	PermissionAssetSourceRead             Permission = "ASSET_SOURCE_READ"
	PermissionAssetSourceManage           Permission = "ASSET_SOURCE_MANAGE"
	PermissionAssetSourceValidate         Permission = "ASSET_SOURCE_VALIDATE"
	PermissionAssetSourcePublish          Permission = "ASSET_SOURCE_PUBLISH"
	PermissionAssetSourceSync             Permission = "ASSET_SOURCE_SYNC"
	PermissionIncidentRead                Permission = "INCIDENT_READ"
	PermissionInvestigationRun            Permission = "INVESTIGATION_RUN"
	PermissionFeedbackWrite               Permission = "FEEDBACK_WRITE"
	PermissionActionPropose               Permission = "ACTION_PROPOSE"
	PermissionActionApprove               Permission = "ACTION_APPROVE"
	PermissionExecutionRequest            Permission = "EXECUTION_REQUEST"
	PermissionAuditRead                   Permission = "AUDIT_READ"
	PermissionAuditExport                 Permission = "AUDIT_EXPORT"
	PermissionCatalogManage               Permission = "CATALOG_MANAGE"
	PermissionCredentialRevocationRead    Permission = "CREDENTIAL_REVOCATION_READ"
	PermissionCredentialRevocationRequeue Permission = "CREDENTIAL_REVOCATION_REQUEUE"
	PermissionCredentialRevocationConfirm Permission = "CREDENTIAL_REVOCATION_CONFIRM"
)

type Request struct {
	Permission                  Permission
	WorkspaceID                 string
	EnvironmentID               string
	ServiceID                   string
	RequireRecentAuthentication bool
}

type Authorizer struct {
	recentAuthentication time.Duration
	clock                func() time.Time
}

func NewAuthorizer(recentAuthentication time.Duration, clock func() time.Time) (*Authorizer, error) {
	if recentAuthentication < time.Minute || recentAuthentication > 15*time.Minute {
		return nil, errors.New("recent authentication window must be between 1m and 15m")
	}
	if clock == nil {
		clock = time.Now
	}
	return &Authorizer{recentAuthentication: recentAuthentication, clock: clock}, nil
}

// IsPlatformAdmin derives the credential-management Platform Admin bit only
// from roles on the authenticated OIDC principal.
func IsPlatformAdmin(principal authn.Principal) bool {
	return slices.Contains(principal.Roles, authn.RoleAdmin)
}

func (authorizer *Authorizer) Authorize(principal authn.Principal, request Request) error {
	now := authorizer.clock().UTC()
	if principal.Subject == "" || principal.ExpiresAt.IsZero() || !now.Before(principal.ExpiresAt) ||
		request.WorkspaceID == "" || request.EnvironmentID == "" ||
		!slices.Contains(principal.WorkspaceIDs, request.WorkspaceID) || !slices.Contains(principal.EnvironmentIDs, request.EnvironmentID) {
		return ErrForbidden
	}
	if requiresService(request.Permission) && request.ServiceID == "" {
		return ErrForbidden
	}
	allowed := false
	for _, role := range principal.Roles {
		if role == authn.RoleServiceOwner && request.ServiceID != "" && !slices.Contains(principal.ServiceIDs, request.ServiceID) {
			continue
		}
		if roleAllows(role, request.Permission) {
			allowed = true
			break
		}
	}
	if !allowed {
		return ErrForbidden
	}
	if (request.RequireRecentAuthentication || requiresRecentAuthentication(request.Permission)) &&
		(principal.AuthenticatedAt.IsZero() || principal.AuthenticatedAt.After(now.Add(30*time.Second)) || now.Sub(principal.AuthenticatedAt) > authorizer.recentAuthentication) {
		return ErrReauthenticationRequired
	}
	return nil
}

func requiresRecentAuthentication(permission Permission) bool {
	switch permission {
	case PermissionActionApprove, PermissionExecutionRequest,
		PermissionCredentialRevocationRequeue, PermissionCredentialRevocationConfirm:
		return true
	default:
		return false
	}
}

func requiresService(permission Permission) bool {
	switch permission {
	case PermissionAssetBind, PermissionInvestigationRun, PermissionFeedbackWrite,
		PermissionActionPropose, PermissionActionApprove, PermissionExecutionRequest:
		return true
	default:
		return false
	}
}

func roleAllows(role authn.Role, permission Permission) bool {
	switch role {
	case authn.RoleViewer:
		return permission == PermissionAssetRead || permission == PermissionAssetSourceRead
	case authn.RoleSRE:
		return slices.Contains([]Permission{
			PermissionAssetRead, PermissionAssetSourceRead,
			PermissionIncidentRead, PermissionInvestigationRun, PermissionFeedbackWrite,
			PermissionActionPropose, PermissionActionApprove, PermissionExecutionRequest, PermissionAuditRead,
			PermissionCredentialRevocationRead, PermissionCredentialRevocationConfirm,
		}, permission)
	case authn.RoleServiceOwner:
		return slices.Contains([]Permission{
			PermissionAssetRead, PermissionAssetBind, PermissionAssetSourceRead,
			PermissionIncidentRead, PermissionInvestigationRun, PermissionFeedbackWrite, PermissionActionPropose, PermissionActionApprove,
		}, permission)
	case authn.RoleApprover:
		return permission == PermissionAssetRead || permission == PermissionAssetSourceRead ||
			permission == PermissionIncidentRead || permission == PermissionActionApprove
	case authn.RoleAuditor:
		return permission == PermissionAssetRead || permission == PermissionAssetSourceRead || permission == PermissionIncidentRead ||
			permission == PermissionAuditRead || permission == PermissionAuditExport ||
			permission == PermissionCredentialRevocationRead
	case authn.RoleAdmin:
		return slices.Contains([]Permission{
			PermissionAssetRead, PermissionAssetManage, PermissionAssetBind, PermissionAssetConflictResolve,
			PermissionAssetSourceRead, PermissionAssetSourceManage, PermissionAssetSourceValidate,
			PermissionAssetSourcePublish, PermissionAssetSourceSync,
			PermissionIncidentRead, PermissionAuditRead, PermissionAuditExport, PermissionCatalogManage,
			PermissionCredentialRevocationRead, PermissionCredentialRevocationRequeue, PermissionCredentialRevocationConfirm,
		}, permission)
	default:
		return false
	}
}
