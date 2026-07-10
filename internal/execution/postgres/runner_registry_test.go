package postgres

import (
	"context"
	"testing"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/seaworld008/aiops-system/internal/executionlease"
)

func TestRunnerRegistryResolvesRevisionedExactScopeBindings(t *testing.T) {
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	defer database.Close()
	registry, err := NewRunnerRegistry(database)
	if err != nil {
		t.Fatalf("NewRunnerRegistry() error = %v", err)
	}
	database.ExpectBegin()
	database.ExpectQuery("SELECT tenant_id, runner_pool, enabled, scope_revision, max_concurrency").
		WithArgs("runner-1").
		WillReturnRows(pgxmock.NewRows([]string{"tenant_id", "runner_pool", "enabled", "scope_revision", "max_concurrency"}).
			AddRow("10000000-0000-4000-8000-000000000001", executionlease.PoolWrite, true, int64(7), 3))
	database.ExpectQuery("SELECT workspace_id::text, environment_id::text").
		WithArgs("runner-1", "10000000-0000-4000-8000-000000000001").
		WillReturnRows(pgxmock.NewRows([]string{"workspace_id", "environment_id"}).
			AddRow("workspace-1", "PROD").
			AddRow("workspace-2", "STAGING"))
	database.ExpectCommit()

	registration, err := registry.Resolve(context.Background(), "runner-1")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if registration.RunnerID != "runner-1" || registration.TenantID != "10000000-0000-4000-8000-000000000001" ||
		registration.ScopeRevision != 7 || registration.MaxConcurrency != 3 || len(registration.ScopeBindings) != 2 {
		t.Fatalf("Resolve() = %#v", registration)
	}
	scope, err := registration.Scope()
	if err != nil {
		t.Fatalf("Scope() error = %v", err)
	}
	bindings := scope.Bindings()
	if bindings[0].WorkspaceID != "workspace-1" || bindings[0].EnvironmentID != "PROD" ||
		bindings[1].WorkspaceID != "workspace-2" || bindings[1].EnvironmentID != "STAGING" {
		t.Fatalf("Scope().Bindings() = %#v", bindings)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet PostgreSQL expectations: %v", err)
	}
}
