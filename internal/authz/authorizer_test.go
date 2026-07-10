package authz

import (
	"errors"
	"testing"
	"time"

	"github.com/aiops-system/control-plane/internal/authn"
)

func TestAuthorizerEnforcesWorkspaceEnvironmentAndServiceScope(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	authorizer, err := NewAuthorizer(5*time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewAuthorizer() error = %v", err)
	}
	owner := principal(now, authn.RoleServiceOwner)
	owner.ServiceIDs = []string{"service-payments"}

	if err := authorizer.Authorize(owner, Request{Permission: PermissionFeedbackWrite, WorkspaceID: "workspace-1", EnvironmentID: "PROD", ServiceID: "service-payments"}); err != nil {
		t.Fatalf("Authorize(valid owner) error = %v", err)
	}
	for _, request := range []Request{
		{Permission: PermissionFeedbackWrite, WorkspaceID: "workspace-2", EnvironmentID: "PROD", ServiceID: "service-payments"},
		{Permission: PermissionFeedbackWrite, WorkspaceID: "workspace-1", EnvironmentID: "STAGING", ServiceID: "service-payments"},
		{Permission: PermissionFeedbackWrite, WorkspaceID: "workspace-1", EnvironmentID: "PROD", ServiceID: "service-orders"},
	} {
		if err := authorizer.Authorize(owner, request); !errors.Is(err, ErrForbidden) {
			t.Fatalf("Authorize(%#v) error = %v", request, err)
		}
	}
}

func TestAuthorizerRequiresRecentOIDCAuthenticationForProductionControl(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	authorizer, err := NewAuthorizer(5*time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewAuthorizer() error = %v", err)
	}
	sre := principal(now, authn.RoleSRE)
	for _, permission := range []Permission{PermissionActionApprove, PermissionExecutionRequest} {
		if err := authorizer.Authorize(sre, Request{Permission: permission, WorkspaceID: "workspace-1", EnvironmentID: "PROD", ServiceID: "service-payments"}); err != nil {
			t.Fatalf("Authorize(%s) error = %v", permission, err)
		}
	}
	sre.AuthenticatedAt = now.Add(-5*time.Minute - time.Nanosecond)
	if err := authorizer.Authorize(sre, Request{Permission: PermissionActionApprove, WorkspaceID: "workspace-1", EnvironmentID: "PROD", ServiceID: "service-payments"}); !errors.Is(err, ErrReauthenticationRequired) {
		t.Fatalf("stale approval error = %v", err)
	}
}

func TestAuthorizerUsesDenyByDefaultRolePermissionMatrix(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	authorizer, err := NewAuthorizer(5*time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewAuthorizer() error = %v", err)
	}
	request := Request{WorkspaceID: "workspace-1", EnvironmentID: "PROD", ServiceID: "service-payments"}
	tests := []struct {
		role       authn.Role
		permission Permission
		allowed    bool
	}{
		{authn.RoleSRE, PermissionInvestigationRun, true},
		{authn.RoleSRE, PermissionExecutionRequest, true},
		{authn.RoleServiceOwner, PermissionExecutionRequest, false},
		{authn.RoleApprover, PermissionActionApprove, true},
		{authn.RoleAuditor, PermissionAuditExport, true},
		{authn.RoleAuditor, PermissionActionPropose, false},
		{authn.RoleAdmin, PermissionCatalogManage, true},
		{authn.RoleAdmin, PermissionExecutionRequest, false},
	}
	for _, test := range tests {
		candidate := principal(now, test.role)
		if test.role == authn.RoleServiceOwner {
			candidate.ServiceIDs = []string{"service-payments"}
		}
		request.Permission = test.permission
		err := authorizer.Authorize(candidate, request)
		if test.allowed && err != nil {
			t.Fatalf("role=%s permission=%s error=%v", test.role, test.permission, err)
		}
		if !test.allowed && !errors.Is(err, ErrForbidden) {
			t.Fatalf("role=%s permission=%s error=%v, want forbidden", test.role, test.permission, err)
		}
	}
}

func principal(now time.Time, role authn.Role) authn.Principal {
	return authn.Principal{
		Subject: "subject-1", AuthenticatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		Roles: []authn.Role{role}, WorkspaceIDs: []string{"workspace-1"}, EnvironmentIDs: []string{"PROD"},
	}
}
