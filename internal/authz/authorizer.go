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
	PermissionIncidentRead     Permission = "INCIDENT_READ"
	PermissionInvestigationRun Permission = "INVESTIGATION_RUN"
	PermissionFeedbackWrite    Permission = "FEEDBACK_WRITE"
	PermissionActionPropose    Permission = "ACTION_PROPOSE"
	PermissionActionApprove    Permission = "ACTION_APPROVE"
	PermissionExecutionRequest Permission = "EXECUTION_REQUEST"
	PermissionAuditRead        Permission = "AUDIT_READ"
	PermissionAuditExport      Permission = "AUDIT_EXPORT"
	PermissionCatalogManage    Permission = "CATALOG_MANAGE"
)

type Request struct {
	Permission    Permission
	WorkspaceID   string
	EnvironmentID string
	ServiceID     string
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
	if (request.Permission == PermissionActionApprove || request.Permission == PermissionExecutionRequest) &&
		(principal.AuthenticatedAt.IsZero() || principal.AuthenticatedAt.After(now.Add(30*time.Second)) || now.Sub(principal.AuthenticatedAt) > authorizer.recentAuthentication) {
		return ErrReauthenticationRequired
	}

	for _, role := range principal.Roles {
		if role == authn.RoleServiceOwner && request.ServiceID != "" && !slices.Contains(principal.ServiceIDs, request.ServiceID) {
			continue
		}
		if roleAllows(role, request.Permission) {
			return nil
		}
	}
	return ErrForbidden
}

func requiresService(permission Permission) bool {
	switch permission {
	case PermissionInvestigationRun, PermissionFeedbackWrite, PermissionActionPropose, PermissionActionApprove, PermissionExecutionRequest:
		return true
	default:
		return false
	}
}

func roleAllows(role authn.Role, permission Permission) bool {
	switch role {
	case authn.RoleSRE:
		return slices.Contains([]Permission{
			PermissionIncidentRead, PermissionInvestigationRun, PermissionFeedbackWrite,
			PermissionActionPropose, PermissionActionApprove, PermissionExecutionRequest, PermissionAuditRead,
		}, permission)
	case authn.RoleServiceOwner:
		return slices.Contains([]Permission{
			PermissionIncidentRead, PermissionInvestigationRun, PermissionFeedbackWrite, PermissionActionPropose, PermissionActionApprove,
		}, permission)
	case authn.RoleApprover:
		return permission == PermissionIncidentRead || permission == PermissionActionApprove
	case authn.RoleAuditor:
		return permission == PermissionIncidentRead || permission == PermissionAuditRead || permission == PermissionAuditExport
	case authn.RoleAdmin:
		return permission == PermissionIncidentRead || permission == PermissionAuditRead || permission == PermissionAuditExport || permission == PermissionCatalogManage
	default:
		return false
	}
}
