package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/seaworld008/aiops-system/internal/execution"
	"github.com/seaworld008/aiops-system/internal/executionlease"
)

// RunnerRegistry resolves one transactionally consistent registration and its
// exact scope bindings. Certificate authentication is added by M3; queue code
// never accepts workspace/environment allowlists from a job request.
type RunnerRegistry struct {
	database DB
}

var _ execution.RunnerRegistrationRepository = (*RunnerRegistry)(nil)

func NewRunnerRegistry(database DB) (*RunnerRegistry, error) {
	if database == nil {
		return nil, fmt.Errorf("%w: PostgreSQL database is required", executionlease.ErrInvalidRequest)
	}
	return &RunnerRegistry{database: database}, nil
}

func (registry *RunnerRegistry) Resolve(ctx context.Context, runnerID string) (execution.RunnerRegistration, error) {
	if err := ctx.Err(); err != nil {
		return execution.RunnerRegistration{}, err
	}
	if !validIdentifier(runnerID, 256) {
		return execution.RunnerRegistration{}, executionlease.ErrInvalidRequest
	}
	tx, err := registry.database.Begin(ctx)
	if err != nil {
		return execution.RunnerRegistration{}, fmt.Errorf("begin runner registration lookup: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	registration := execution.RunnerRegistration{RunnerID: runnerID}
	var tenantID, pool string
	err = tx.QueryRow(ctx, `
		SELECT tenant_id, runner_pool, enabled, scope_revision, max_concurrency
		FROM runner_registrations
		WHERE runner_id = $1
		FOR SHARE
	`, runnerID).Scan(&tenantID, &pool, &registration.Enabled, &registration.ScopeRevision, &registration.MaxConcurrency)
	if errors.Is(err, pgx.ErrNoRows) {
		return execution.RunnerRegistration{}, executionlease.ErrNotFound
	}
	if err != nil {
		return execution.RunnerRegistration{}, fmt.Errorf("read runner registration: %w", err)
	}
	registration.TenantID = tenantID
	registration.Pool = executionlease.Pool(pool)

	rows, err := tx.Query(ctx, `
		SELECT workspace_id::text, environment_id::text
		FROM runner_scope_bindings
		WHERE runner_id = $1 AND tenant_id = $2
		ORDER BY workspace_id, environment_id
	`, runnerID, tenantID)
	if err != nil {
		return execution.RunnerRegistration{}, fmt.Errorf("read runner scope bindings: %w", err)
	}
	for rows.Next() {
		var binding execution.RunnerScopeBinding
		if err := rows.Scan(&binding.WorkspaceID, &binding.EnvironmentID); err != nil {
			rows.Close()
			return execution.RunnerRegistration{}, fmt.Errorf("scan runner scope binding: %w", err)
		}
		registration.ScopeBindings = append(registration.ScopeBindings, binding)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return execution.RunnerRegistration{}, fmt.Errorf("iterate runner scope bindings: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return execution.RunnerRegistration{}, fmt.Errorf("commit runner registration lookup: %w", err)
	}
	committed = true
	return registration, nil
}
