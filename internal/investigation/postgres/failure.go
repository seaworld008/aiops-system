package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/store"
)

func (repository *Repository) FailInvestigation(
	ctx context.Context,
	request investigation.FailInvestigationRequest,
) (investigation.FailInvestigationResult, error) {
	if err := ctx.Err(); err != nil {
		return investigation.FailInvestigationResult{}, err
	}
	if !validUUIDs(request.WorkspaceID, request.InvestigationID) ||
		!domain.ValidIdempotencyKey(request.IdempotencyKey) || !domain.ValidFailureCode(request.FailureCode) {
		return investigation.FailInvestigationResult{}, fmt.Errorf("%w: invalid investigation failure request", investigation.ErrInvalidRequest)
	}
	requestHash, err := investigation.FailInvestigationRequestHash(request)
	if err != nil {
		return investigation.FailInvestigationResult{}, err
	}
	tx, tenantID, err := beginWorkspace(ctx, repository, request.WorkspaceID)
	if err != nil {
		return investigation.FailInvestigationResult{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if err := lockIdempotencyKey(ctx, tx, tenantID, request.WorkspaceID, request.IdempotencyKey); err != nil {
		return investigation.FailInvestigationResult{}, err
	}
	existing, err := readIdempotencyRecord(ctx, tx, tenantID, request.WorkspaceID, request.IdempotencyKey)
	if err == nil {
		if err := requireIdempotencyReplay(existing, operationFailInvestigation, requestHash, requestVersionFailInvestigation); err != nil {
			return investigation.FailInvestigationResult{}, err
		}
		if existing.resourceType != "INVESTIGATION" || existing.resourceID != request.InvestigationID || len(existing.resultSnapshot) != 0 {
			return investigation.FailInvestigationResult{}, fmt.Errorf("read investigation failure replay: %w", errDatabaseOperation)
		}
		item, readErr := readRuntimeInvestigation(ctx, tx, tenantID, request.WorkspaceID, request.InvestigationID, "FOR SHARE OF investigation")
		if readErr != nil {
			if errors.Is(readErr, store.ErrNotFound) {
				return investigation.FailInvestigationResult{}, fmt.Errorf("read investigation failure replay: %w", errDatabaseOperation)
			}
			return investigation.FailInvestigationResult{}, readErr
		}
		if item.Status != domain.InvestigationFailed || item.FailureCode != request.FailureCode {
			return investigation.FailInvestigationResult{}, fmt.Errorf("read investigation failure replay: %w", errDatabaseOperation)
		}
		if err := commit(ctx, tx, "commit investigation failure replay"); err != nil {
			return investigation.FailInvestigationResult{}, err
		}
		committed = true
		return investigation.FailInvestigationResult{Investigation: item, Replayed: true}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return investigation.FailInvestigationResult{}, databaseError("read investigation failure idempotency", err)
	}

	tasks, err := lockInvestigationTasksForMutation(ctx, tx, tenantID, request.WorkspaceID, request.InvestigationID)
	if err != nil {
		return investigation.FailInvestigationResult{}, err
	}
	item, err := readRuntimeInvestigation(ctx, tx, tenantID, request.WorkspaceID, request.InvestigationID, "FOR NO KEY UPDATE OF investigation")
	if err != nil {
		return investigation.FailInvestigationResult{}, err
	}
	if len(tasks) < 1 || len(tasks) > 12 {
		return investigation.FailInvestigationResult{}, fmt.Errorf("read investigation tasks: %w", errDatabaseOperation)
	}
	if item.Status != domain.InvestigationQueued && item.Status != domain.InvestigationRunning {
		return investigation.FailInvestigationResult{}, investigation.ErrInvalidTransition
	}
	commitAt, err := investigationBoundaryTime(ctx, tx, tenantID, request.WorkspaceID, item, tasks)
	if err != nil {
		return investigation.FailInvestigationResult{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE tool_invocations AS task
		SET status = 'CANCELLED', evidence_id = NULL, output_hash = NULL,
			failure_code = $4, completed_at = $5, updated_at = $5
		WHERE task.tenant_id = $1 AND task.workspace_id = $2
		  AND task.investigation_id = $3 AND task.runtime_schema_version = $6
		  AND task.status IN ('QUEUED', 'RUNNING')
	`, tenantID, request.WorkspaceID, request.InvestigationID, request.FailureCode, commitAt, runtimeSchemaVersion); err != nil {
		return investigation.FailInvestigationResult{}, databaseError("cancel investigation read tasks", err)
	}
	item, err = scanInvestigation(tx.QueryRow(ctx, `
		UPDATE investigations AS investigation
		SET status = 'FAILED', model_status = 'CANCELLED', failure_code = $4,
			model_failure_code = NULL, completed_at = $5, updated_at = $5
		WHERE investigation.tenant_id = $1 AND investigation.workspace_id = $2
		  AND investigation.id = $3 AND investigation.runtime_schema_version = $6
		  AND investigation.status IN ('QUEUED', 'RUNNING')
		RETURNING `+investigationProjection,
		tenantID, request.WorkspaceID, request.InvestigationID, request.FailureCode, commitAt, runtimeSchemaVersion))
	if errors.Is(err, pgx.ErrNoRows) {
		return investigation.FailInvestigationResult{}, investigation.ErrInvalidTransition
	}
	if err != nil {
		return investigation.FailInvestigationResult{}, databaseError("fail investigation", err)
	}
	if err := insertIdempotencyRecord(ctx, tx, tenantID, request.WorkspaceID, request.IdempotencyKey, idempotencyRecord{
		operation: operationFailInvestigation, requestHash: requestHash, requestVersion: requestVersionFailInvestigation,
		resourceType: "INVESTIGATION", resourceID: item.ID,
	}); err != nil {
		return investigation.FailInvestigationResult{}, err
	}
	if err := commit(ctx, tx, "commit investigation failure"); err != nil {
		return investigation.FailInvestigationResult{}, err
	}
	committed = true
	return investigation.FailInvestigationResult{Investigation: item}, nil
}

func readRuntimeInvestigation(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, workspaceID, investigationID, lockingClause string,
) (domain.Investigation, error) {
	item, err := scanInvestigation(tx.QueryRow(ctx, `
		SELECT `+investigationProjection+`
		FROM investigations AS investigation
		WHERE investigation.tenant_id = $1 AND investigation.workspace_id = $2
		  AND investigation.id = $3 AND investigation.runtime_schema_version = $4
		`+lockingClause,
		tenantID, workspaceID, investigationID, runtimeSchemaVersion))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Investigation{}, store.ErrNotFound
	}
	if err != nil {
		return domain.Investigation{}, databaseError("read runtime investigation", err)
	}
	return item, nil
}

func lockInvestigationTasksForMutation(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, workspaceID, investigationID string,
) ([]domain.ReadTask, error) {
	rows, err := tx.Query(ctx, `
		SELECT `+taskProjection+`
		FROM tool_invocations AS task
		WHERE task.tenant_id = $1 AND task.workspace_id = $2
		  AND task.investigation_id = $3 AND task.runtime_schema_version = $4
		ORDER BY task.position, task.id
		FOR NO KEY UPDATE OF task
	`, tenantID, workspaceID, investigationID, runtimeSchemaVersion)
	if err != nil {
		return nil, databaseError("lock investigation tasks", err)
	}
	defer rows.Close()
	tasks := make([]domain.ReadTask, 0, 12)
	for rows.Next() {
		task, scanErr := scanTask(rows)
		if scanErr != nil {
			return nil, databaseError("scan locked investigation task", scanErr)
		}
		tasks = append(tasks, task)
	}
	if err := rows.Err(); err != nil {
		return nil, databaseError("iterate locked investigation tasks", err)
	}
	return tasks, nil
}

func investigationBoundaryTime(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, workspaceID string,
	item domain.Investigation,
	tasks []domain.ReadTask,
) (time.Time, error) {
	databaseNow, err := scopedDatabaseNow(ctx, tx, tenantID, workspaceID)
	if err != nil {
		return time.Time{}, err
	}
	boundary := databaseTime(databaseNow)
	for _, candidate := range []time.Time{item.CreatedAt, item.StartedAt, item.UpdatedAt} {
		if candidate.After(boundary) {
			boundary = candidate
		}
	}
	for _, task := range tasks {
		for _, candidate := range []time.Time{task.CreatedAt, task.StartedAt, task.CompletedAt, task.UpdatedAt} {
			if candidate.After(boundary) {
				boundary = candidate
			}
		}
	}
	return boundary.UTC().Truncate(time.Microsecond), nil
}
