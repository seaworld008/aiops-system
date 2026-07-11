package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/store"
)

func (repository *Repository) StartModel(
	ctx context.Context,
	request investigation.StartModelRequest,
) (investigation.StartModelResult, error) {
	if err := ctx.Err(); err != nil {
		return investigation.StartModelResult{}, err
	}
	if !validUUIDs(request.WorkspaceID, request.InvestigationID) ||
		!domain.ValidIdempotencyKey(request.IdempotencyKey) {
		return investigation.StartModelResult{}, fmt.Errorf("%w: invalid model start request", investigation.ErrInvalidRequest)
	}
	requestHash, err := investigation.StartModelRequestHash(request)
	if err != nil {
		return investigation.StartModelResult{}, err
	}
	tx, tenantID, err := beginWorkspace(ctx, repository, request.WorkspaceID)
	if err != nil {
		return investigation.StartModelResult{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if err := lockIdempotencyKey(ctx, tx, tenantID, request.WorkspaceID, request.IdempotencyKey); err != nil {
		return investigation.StartModelResult{}, err
	}
	existing, err := readIdempotencyRecord(ctx, tx, tenantID, request.WorkspaceID, request.IdempotencyKey)
	if err == nil {
		if err := requireIdempotencyReplay(existing, operationStartModel, requestHash, requestVersionStartModel); err != nil {
			return investigation.StartModelResult{}, err
		}
		if existing.resourceType != "INVESTIGATION" || existing.resourceID != request.InvestigationID ||
			existing.snapshotVersion != snapshotVersionStartModel {
			return investigation.StartModelResult{}, fmt.Errorf("read model start replay: %w", errDatabaseOperation)
		}
		result, decodeErr := decodeStartModelSnapshot(existing.resultSnapshot)
		if decodeErr != nil || result.Investigation.ID != request.InvestigationID ||
			result.Investigation.WorkspaceID != request.WorkspaceID {
			return investigation.StartModelResult{}, fmt.Errorf("read model start replay: %w", errDatabaseOperation)
		}
		if err := commit(ctx, tx, "commit model start replay"); err != nil {
			return investigation.StartModelResult{}, err
		}
		committed = true
		result.Replayed = true
		return result, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return investigation.StartModelResult{}, databaseError("read model start idempotency", err)
	}

	terminalTasks, taskCount, err := lockTerminalTasks(ctx, tx, tenantID, request.WorkspaceID, request.InvestigationID)
	if err != nil {
		return investigation.StartModelResult{}, err
	}
	item, err := scanInvestigation(tx.QueryRow(ctx, `
		SELECT `+investigationProjection+`
		FROM investigations AS investigation
		WHERE investigation.tenant_id = $1 AND investigation.workspace_id = $2
		  AND investigation.id = $3 AND investigation.runtime_schema_version = $4
		FOR NO KEY UPDATE OF investigation
	`, tenantID, request.WorkspaceID, request.InvestigationID, runtimeSchemaVersion))
	if errors.Is(err, pgx.ErrNoRows) {
		return investigation.StartModelResult{}, store.ErrNotFound
	}
	if err != nil {
		return investigation.StartModelResult{}, databaseError("lock investigation for model start", err)
	}
	if taskCount < 1 || taskCount > 12 {
		return investigation.StartModelResult{}, fmt.Errorf("read investigation tasks: %w", errDatabaseOperation)
	}
	if !terminalTasks {
		return investigation.StartModelResult{}, investigation.ErrInvalidTransition
	}
	if item.Status != domain.InvestigationRunning || item.ModelStatus != domain.ModelPending {
		return investigation.StartModelResult{}, investigation.ErrInvalidTransition
	}
	item, err = scanInvestigation(tx.QueryRow(ctx, `
		UPDATE investigations AS investigation
		SET model_status = 'RUNNING', updated_at = GREATEST(investigation.updated_at, clock_timestamp())
		WHERE investigation.tenant_id = $1 AND investigation.workspace_id = $2
		  AND investigation.id = $3 AND investigation.runtime_schema_version = $4
		  AND investigation.status = 'RUNNING' AND investigation.model_status = 'PENDING'
		RETURNING `+investigationProjection,
		tenantID, request.WorkspaceID, request.InvestigationID, runtimeSchemaVersion))
	if errors.Is(err, pgx.ErrNoRows) {
		return investigation.StartModelResult{}, investigation.ErrInvalidTransition
	}
	if err != nil {
		return investigation.StartModelResult{}, databaseError("start investigation model", err)
	}
	result := investigation.StartModelResult{Investigation: item}
	snapshot, digest, err := encodeStartModelSnapshot(result)
	if err != nil {
		return investigation.StartModelResult{}, fmt.Errorf("persist model start snapshot: %w", errDatabaseOperation)
	}
	if err := insertIdempotencyRecord(ctx, tx, tenantID, request.WorkspaceID, request.IdempotencyKey, idempotencyRecord{
		operation: operationStartModel, requestHash: requestHash, requestVersion: requestVersionStartModel,
		resourceType: "INVESTIGATION", resourceID: item.ID,
		resultSnapshot: snapshot, snapshotDigest: digest, snapshotVersion: snapshotVersionStartModel,
	}); err != nil {
		return investigation.StartModelResult{}, err
	}
	if err := commit(ctx, tx, "commit model start"); err != nil {
		return investigation.StartModelResult{}, err
	}
	committed = true
	return result, nil
}

func lockTerminalTasks(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, workspaceID, investigationID string,
) (bool, int, error) {
	rows, err := tx.Query(ctx, `
		SELECT task.status
		FROM tool_invocations AS task
		WHERE task.tenant_id = $1 AND task.workspace_id = $2
		  AND task.investigation_id = $3 AND task.runtime_schema_version = $4
		ORDER BY task.position, task.id
		FOR SHARE OF task
	`, tenantID, workspaceID, investigationID, runtimeSchemaVersion)
	if err != nil {
		return false, 0, databaseError("lock investigation read tasks", err)
	}
	defer rows.Close()
	taskCount := 0
	allTerminal := true
	for rows.Next() {
		var status domain.ReadTaskStatus
		if err := rows.Scan(&status); err != nil {
			return false, 0, databaseError("scan investigation read task state", err)
		}
		taskCount++
		switch status {
		case domain.ReadTaskEvidence, domain.ReadTaskFailed, domain.ReadTaskCancelled:
		default:
			allTerminal = false
		}
	}
	if err := rows.Err(); err != nil {
		return false, 0, databaseError("iterate investigation read task states", err)
	}
	return allTerminal, taskCount, nil
}
