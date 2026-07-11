package authz

import (
	"errors"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/authn"
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
		{authn.RoleAdmin, Permission("CREDENTIAL_REVOCATION_DELETE"), false},
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

func TestAuthorizerCredentialRevocationRoleMatrixDoesNotRequireServiceScope(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 11, 9, 0, 0, 0, time.UTC)
	authorizer, err := NewAuthorizer(5*time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewAuthorizer() error = %v", err)
	}
	request := Request{WorkspaceID: "workspace-1", EnvironmentID: "PROD"}
	tests := []struct {
		name       string
		role       authn.Role
		permission Permission
		allowed    bool
	}{
		{name: "sre reads", role: authn.RoleSRE, permission: PermissionCredentialRevocationRead, allowed: true},
		{name: "auditor reads", role: authn.RoleAuditor, permission: PermissionCredentialRevocationRead, allowed: true},
		{name: "admin reads", role: authn.RoleAdmin, permission: PermissionCredentialRevocationRead, allowed: true},
		{name: "sre cannot requeue", role: authn.RoleSRE, permission: PermissionCredentialRevocationRequeue, allowed: false},
		{name: "auditor cannot requeue", role: authn.RoleAuditor, permission: PermissionCredentialRevocationRequeue, allowed: false},
		{name: "admin requeues", role: authn.RoleAdmin, permission: PermissionCredentialRevocationRequeue, allowed: true},
		{name: "sre confirms", role: authn.RoleSRE, permission: PermissionCredentialRevocationConfirm, allowed: true},
		{name: "auditor cannot confirm", role: authn.RoleAuditor, permission: PermissionCredentialRevocationConfirm, allowed: false},
		{name: "admin confirms", role: authn.RoleAdmin, permission: PermissionCredentialRevocationConfirm, allowed: true},
		{name: "service owner cannot read", role: authn.RoleServiceOwner, permission: PermissionCredentialRevocationRead, allowed: false},
		{name: "approver cannot read", role: authn.RoleApprover, permission: PermissionCredentialRevocationRead, allowed: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := principal(now, test.role)
			candidate.ServiceIDs = nil
			request.Permission = test.permission

			err := authorizer.Authorize(candidate, request)
			if test.allowed && err != nil {
				t.Fatalf("Authorize() error = %v", err)
			}
			if !test.allowed && !errors.Is(err, ErrForbidden) {
				t.Fatalf("Authorize() error = %v, want forbidden", err)
			}
		})
	}
}

func TestAuthorizerRequiresRecentOIDCAuthenticationForCredentialRevocationMutations(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 11, 9, 0, 0, 0, time.UTC)
	authorizer, err := NewAuthorizer(5*time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewAuthorizer() error = %v", err)
	}
	request := Request{WorkspaceID: "workspace-1", EnvironmentID: "PROD"}
	for _, permission := range []Permission{PermissionCredentialRevocationRequeue, PermissionCredentialRevocationConfirm} {
		t.Run(string(permission), func(t *testing.T) {
			request.Permission = permission
			candidate := principal(now, authn.RoleAdmin)

			for _, authenticatedAt := range []time.Time{now.Add(-5 * time.Minute), now.Add(30 * time.Second)} {
				candidate.AuthenticatedAt = authenticatedAt
				if err := authorizer.Authorize(candidate, request); err != nil {
					t.Fatalf("Authorize(authenticated_at=%s) error = %v", authenticatedAt, err)
				}
			}

			for _, authenticatedAt := range []time.Time{
				time.Time{},
				now.Add(-5*time.Minute - time.Nanosecond),
				now.Add(30*time.Second + time.Nanosecond),
			} {
				candidate.AuthenticatedAt = authenticatedAt
				if err := authorizer.Authorize(candidate, request); !errors.Is(err, ErrReauthenticationRequired) {
					t.Fatalf("Authorize(authenticated_at=%s) error = %v, want reauthentication required", authenticatedAt, err)
				}
			}
		})
	}

	staleReader := principal(now, authn.RoleAuditor)
	staleReader.AuthenticatedAt = now.Add(-time.Hour)
	if err := authorizer.Authorize(staleReader, Request{
		Permission: PermissionCredentialRevocationRead, WorkspaceID: "workspace-1", EnvironmentID: "PROD",
	}); err != nil {
		t.Fatalf("Authorize(stale read) error = %v", err)
	}

	staleNonAdmin := principal(now, authn.RoleSRE)
	staleNonAdmin.AuthenticatedAt = now.Add(-time.Hour)
	if err := authorizer.Authorize(staleNonAdmin, Request{
		Permission: PermissionCredentialRevocationRequeue, WorkspaceID: "workspace-1", EnvironmentID: "PROD",
	}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("Authorize(stale non-admin requeue) error = %v, want forbidden", err)
	}
}

func TestAuthorizerCredentialRevocationOperationsRequireExactWorkspaceAndEnvironmentScope(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 11, 9, 0, 0, 0, time.UTC)
	authorizer, err := NewAuthorizer(5*time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewAuthorizer() error = %v", err)
	}
	admin := principal(now, authn.RoleAdmin)
	for _, permission := range []Permission{
		PermissionCredentialRevocationRead,
		PermissionCredentialRevocationRequeue,
		PermissionCredentialRevocationConfirm,
	} {
		for _, request := range []Request{
			{Permission: permission, WorkspaceID: "workspace-2", EnvironmentID: "PROD"},
			{Permission: permission, WorkspaceID: "workspace-1", EnvironmentID: "STAGING"},
			{Permission: permission, WorkspaceID: "", EnvironmentID: "PROD"},
			{Permission: permission, WorkspaceID: "workspace-1", EnvironmentID: ""},
		} {
			if err := authorizer.Authorize(admin, request); !errors.Is(err, ErrForbidden) {
				t.Fatalf("Authorize(%#v) error = %v, want forbidden", request, err)
			}
		}
	}
}

func TestIsPlatformAdminUsesOnlyTheVerifiedAdminRole(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		principal authn.Principal
		want      bool
	}{
		{name: "empty principal", principal: authn.Principal{}, want: false},
		{name: "sre only", principal: authn.Principal{Roles: []authn.Role{authn.RoleSRE}}, want: false},
		{name: "mixed roles without admin", principal: authn.Principal{Roles: []authn.Role{authn.RoleSRE, authn.RoleAuditor}}, want: false},
		{name: "admin only", principal: authn.Principal{Roles: []authn.Role{authn.RoleAdmin}}, want: true},
		{name: "mixed roles with admin", principal: authn.Principal{Roles: []authn.Role{authn.RoleSRE, authn.RoleAdmin}}, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := IsPlatformAdmin(test.principal); got != test.want {
				t.Fatalf("IsPlatformAdmin() = %t, want %t", got, test.want)
			}
		})
	}
}

func principal(now time.Time, role authn.Role) authn.Principal {
	return authn.Principal{
		Subject: "subject-1", AuthenticatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		Roles: []authn.Role{role}, WorkspaceIDs: []string{"workspace-1"}, EnvironmentIDs: []string{"PROD"},
	}
}
