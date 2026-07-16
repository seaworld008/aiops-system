package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
)

func TestMappingRepositoryRejectsUninitializedAccessBeforeSQL(t *testing.T) {
	t.Parallel()

	repository := &Repository{}
	scope := assetcatalog.Scope{
		TenantID:      "10000000-0000-4000-8000-000000000201",
		WorkspaceID:   "20000000-0000-4000-8000-000000000201",
		EnvironmentID: "30000000-0000-4000-8000-000000000201",
	}
	if _, err := repository.ListRelationships(context.Background(), assetcatalog.ListRelationshipsRequest{
		Scope: scope, Limit: 10,
	}); !errors.Is(err, assetcatalog.ErrInvalidRequest) {
		t.Fatalf("ListRelationships(zero access) error = %v, want ErrInvalidRequest", err)
	}
	if _, err := repository.ListBindings(context.Background(), assetcatalog.ListBindingsRequest{
		Scope: scope, Limit: 10,
	}); !errors.Is(err, assetcatalog.ErrInvalidRequest) {
		t.Fatalf("ListBindings(zero access) error = %v, want ErrInvalidRequest", err)
	}
	if _, err := repository.ListConflicts(context.Background(), assetcatalog.ListConflictsRequest{
		Scope: scope, Limit: 10,
	}); !errors.Is(err, assetcatalog.ErrInvalidRequest) {
		t.Fatalf("ListConflicts(zero access) error = %v, want ErrInvalidRequest", err)
	}
}

func TestResolveConflictScopeRejectsMalformedIdentifiersBeforeSQL(t *testing.T) {
	t.Parallel()

	repository := &Repository{}
	if _, err := repository.ResolveConflictScope(context.Background(), "not-a-uuid", "also-not-a-uuid"); !errors.Is(err, assetcatalog.ErrInvalidRequest) {
		t.Fatalf("ResolveConflictScope() error = %v, want ErrInvalidRequest", err)
	}
}

func TestResolveConflictScopeReloadsCompositeWorkspaceEnvironment(t *testing.T) {
	t.Parallel()

	query := strings.ToLower(resolveConflictScopeSQL)
	for _, required := range []string{
		"join workspaces as workspace",
		"workspace.tenant_id = conflict.tenant_id",
		"workspace.id = conflict.workspace_id",
		"join environments as environment",
		"environment.tenant_id = conflict.tenant_id",
		"environment.workspace_id = conflict.workspace_id",
		"environment.id = conflict.environment_id",
	} {
		if !strings.Contains(query, required) {
			t.Fatalf("resolveConflictScopeSQL missing composite reload predicate %q", required)
		}
	}
}
