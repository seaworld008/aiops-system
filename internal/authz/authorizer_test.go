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

func TestAssetPermissionMatrix(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 16, 9, 0, 0, 0, time.UTC)
	authorizer, err := NewAuthorizer(5*time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewAuthorizer() error = %v", err)
	}
	tests := []struct {
		name       string
		role       authn.Role
		permission Permission
		serviceID  string
		allowed    bool
	}{
		{name: "viewer reads", role: authn.RoleViewer, permission: PermissionAssetRead, allowed: true},
		{name: "viewer cannot manage", role: authn.RoleViewer, permission: PermissionAssetManage},
		{name: "sre reads", role: authn.RoleSRE, permission: PermissionAssetRead, allowed: true},
		{name: "sre cannot bind", role: authn.RoleSRE, permission: PermissionAssetBind, serviceID: "service-payments"},
		{name: "owner reads", role: authn.RoleServiceOwner, permission: PermissionAssetRead, allowed: true},
		{name: "owner binds owned service", role: authn.RoleServiceOwner, permission: PermissionAssetBind, serviceID: "service-payments", allowed: true},
		{name: "owner cannot bind without service", role: authn.RoleServiceOwner, permission: PermissionAssetBind},
		{name: "owner cannot bind other service", role: authn.RoleServiceOwner, permission: PermissionAssetBind, serviceID: "service-orders"},
		{name: "approver reads", role: authn.RoleApprover, permission: PermissionAssetRead, allowed: true},
		{name: "auditor reads", role: authn.RoleAuditor, permission: PermissionAssetRead, allowed: true},
		{name: "admin manages", role: authn.RoleAdmin, permission: PermissionAssetManage, allowed: true},
		{name: "admin binds with explicit service", role: authn.RoleAdmin, permission: PermissionAssetBind, serviceID: "service-payments", allowed: true},
		{name: "admin resolves", role: authn.RoleAdmin, permission: PermissionAssetConflictResolve, allowed: true},
		{name: "asset permissions never imply investigation", role: authn.RoleViewer, permission: PermissionInvestigationRun, serviceID: "service-payments"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := principal(now, test.role)
			candidate.ServiceIDs = []string{"service-payments"}
			err := authorizer.Authorize(candidate, Request{
				Permission:    test.permission,
				WorkspaceID:   "workspace-1",
				EnvironmentID: "PROD",
				ServiceID:     test.serviceID,
			})
			if test.allowed && err != nil {
				t.Fatalf("Authorize() error = %v", err)
			}
			if !test.allowed && !errors.Is(err, ErrForbidden) {
				t.Fatalf("Authorize() error = %v, want forbidden", err)
			}
		})
	}
}

func TestAssetPermissionsDoNotRequireRecentAuthentication(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 16, 9, 0, 0, 0, time.UTC)
	authorizer, err := NewAuthorizer(5*time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewAuthorizer() error = %v", err)
	}
	admin := principal(now, authn.RoleAdmin)
	admin.AuthenticatedAt = now.Add(-time.Hour)
	for _, permission := range []Permission{
		PermissionAssetRead,
		PermissionAssetManage,
		PermissionAssetBind,
		PermissionAssetConflictResolve,
	} {
		request := Request{
			Permission: permission, WorkspaceID: "workspace-1", EnvironmentID: "PROD",
		}
		if permission == PermissionAssetBind {
			request.ServiceID = "service-payments"
		}
		if err := authorizer.Authorize(admin, request); err != nil {
			t.Fatalf("Authorize(%s) error = %v", permission, err)
		}
	}
}

func TestSourcePermissionMatrix(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	authorizer, err := NewAuthorizer(5*time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewAuthorizer() error = %v", err)
	}
	request := Request{
		Permission:    Permission("ASSET_SOURCE_READ"),
		WorkspaceID:   "workspace-1",
		EnvironmentID: "PROD",
	}
	for _, role := range []authn.Role{
		authn.RoleViewer,
		authn.RoleSRE,
		authn.RoleServiceOwner,
		authn.RoleApprover,
		authn.RoleAuditor,
		authn.RoleAdmin,
	} {
		if err := authorizer.Authorize(principal(now, role), request); err != nil {
			t.Errorf("%s source read error = %v", role, err)
		}
	}
	for _, permission := range []Permission{
		Permission("ASSET_SOURCE_MANAGE"),
		Permission("ASSET_SOURCE_VALIDATE"),
		Permission("ASSET_SOURCE_PUBLISH"),
		Permission("ASSET_SOURCE_SYNC"),
	} {
		request.Permission = permission
		if err := authorizer.Authorize(principal(now, authn.RoleAdmin), request); err != nil {
			t.Errorf("admin %s error = %v", permission, err)
		}
		if err := authorizer.Authorize(principal(now, authn.RoleSRE), request); !errors.Is(err, ErrForbidden) {
			t.Errorf("SRE %s error = %v, want forbidden", permission, err)
		}
	}
}

func TestSourceHighRiskMutationsRequireExplicitRecentAuthentication(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	authorizer, err := NewAuthorizer(5*time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewAuthorizer() error = %v", err)
	}
	admin := principal(now, authn.RoleAdmin)
	admin.AuthenticatedAt = now.Add(-time.Hour)
	request := Request{
		Permission:    PermissionAssetSourceManage,
		WorkspaceID:   "workspace-1",
		EnvironmentID: "PROD",
	}
	if err := authorizer.Authorize(admin, request); err != nil {
		t.Fatalf("ordinary source manage error = %v", err)
	}
	request.RequireRecentAuthentication = true
	if err := authorizer.Authorize(admin, request); !errors.Is(err, ErrReauthenticationRequired) {
		t.Fatalf("high-risk source manage error = %v, want reauthentication", err)
	}
	request.Permission = PermissionAssetSourcePublish
	if err := authorizer.Authorize(admin, request); !errors.Is(err, ErrReauthenticationRequired) {
		t.Fatalf("source publish error = %v, want reauthentication", err)
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
