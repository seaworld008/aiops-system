package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/store"
)

const investigationTaskSchemaVersion = "investigation-task.v1"

func (repository *Repository) CreateOrGetInvestigation(
	ctx context.Context,
	request investigation.CreateOrGetInvestigationRequest,
) (investigation.CreateOrGetInvestigationResult, error) {
	if ctx == nil {
		return investigation.CreateOrGetInvestigationResult{}, fmt.Errorf("%w: context is required", investigation.ErrInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return investigation.CreateOrGetInvestigationResult{}, err
	}
	if !validUUIDs(request.WorkspaceID, request.IncidentID) || !domain.ValidIdempotencyKey(request.IdempotencyKey) {
		return investigation.CreateOrGetInvestigationResult{}, fmt.Errorf("%w: invalid persistent investigation identity", investigation.ErrInvalidRequest)
	}
	canonicalTasks, taskHash, err := investigation.CanonicalTaskSpecs(request.Tasks)
	if err != nil {
		return investigation.CreateOrGetInvestigationResult{}, err
	}
	requestHash, err := investigation.CreateOrGetInvestigationRequestHash(request, taskHash)
	if err != nil {
		return investigation.CreateOrGetInvestigationResult{}, err
	}

	result, handled, err := repository.readCreateInvestigationReplay(
		ctx, request.WorkspaceID, request.IdempotencyKey, requestHash,
	)
	if handled || err != nil {
		return result, err
	}
	return repository.createOrBindInvestigation(ctx, request, canonicalTasks, requestHash)
}

func (repository *Repository) readCreateInvestigationReplay(
	ctx context.Context,
	workspaceID, idempotencyKey, requestHash string,
) (result investigation.CreateOrGetInvestigationResult, handled bool, returnedErr error) {
	tx, tenantID, err := beginWorkspace(ctx, repository, workspaceID)
	if err != nil {
		return result, false, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if err := lockIdempotencyKey(ctx, tx, tenantID, workspaceID, idempotencyKey); err != nil {
		return result, false, err
	}
	record, err := readIdempotencyRecord(ctx, tx, tenantID, workspaceID, idempotencyKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, false, nil
	}
	if err != nil {
		return result, false, databaseError("read investigation creation replay", err)
	}
	if err := validateCreateInvestigationRecord(record, requestHash); err != nil {
		return result, true, err
	}
	result, err = loadCreateInvestigationResult(
		ctx, tx, tenantID, workspaceID, record.resourceID, requestHash, false,
	)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return investigation.CreateOrGetInvestigationResult{}, true, fmt.Errorf("read investigation creation replay: %w", errDatabaseOperation)
		}
		return investigation.CreateOrGetInvestigationResult{}, true, err
	}
	if err := commit(ctx, tx, "commit investigation creation replay"); err != nil {
		return investigation.CreateOrGetInvestigationResult{}, true, err
	}
	committed = true
	return result, true, nil
}

func (repository *Repository) createOrBindInvestigation(
	ctx context.Context,
	request investigation.CreateOrGetInvestigationRequest,
	canonicalTasks []investigation.TaskSpec,
	requestHash string,
) (result investigation.CreateOrGetInvestigationResult, returnedErr error) {
	tx, tenantID, err := beginWorkspace(ctx, repository, request.WorkspaceID)
	if err != nil {
		return result, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if err := lockIdempotencyKey(ctx, tx, tenantID, request.WorkspaceID, request.IdempotencyKey); err != nil {
		return result, err
	}
	record, err := readIdempotencyRecord(ctx, tx, tenantID, request.WorkspaceID, request.IdempotencyKey)
	if err == nil {
		if err := validateCreateInvestigationRecord(record, requestHash); err != nil {
			return result, err
		}
		result, err = loadCreateInvestigationResult(
			ctx, tx, tenantID, request.WorkspaceID, record.resourceID, requestHash, false,
		)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return investigation.CreateOrGetInvestigationResult{}, fmt.Errorf("read concurrent investigation creation replay: %w", errDatabaseOperation)
			}
			return investigation.CreateOrGetInvestigationResult{}, err
		}
		if err := commit(ctx, tx, "commit concurrent investigation creation replay"); err != nil {
			return investigation.CreateOrGetInvestigationResult{}, err
		}
		committed = true
		return result, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return result, databaseError("recheck investigation creation replay", err)
	}

	incident, err := scanIncident(tx.QueryRow(ctx, `
		SELECT `+incidentProjection+`
		FROM incidents AS incident
		WHERE incident.tenant_id = $1 AND incident.workspace_id = $2 AND incident.id = $3
		  AND incident.runtime_schema_version = $4
		FOR NO KEY UPDATE OF incident
	`, tenantID, request.WorkspaceID, request.IncidentID, runtimeSchemaVersion))
	if errors.Is(err, pgx.ErrNoRows) {
		return result, store.ErrNotFound
	}
	if err != nil {
		return result, databaseError("lock investigation incident", err)
	}
	scope := investigation.TaskSpecScope{
		TenantID:      incident.TenantID,
		WorkspaceID:   incident.WorkspaceID,
		EnvironmentID: incident.EnvironmentID,
		ServiceID:     incident.ServiceID,
		MappingStatus: incident.MappingStatus,
	}
	if err := investigation.AuthorizeTaskSpecs(
		ctx, repository.taskSpecAuthorizer, scope, canonicalTasks,
	); err != nil {
		return result, err
	}

	active, activeFound, err := lockActiveInvestigation(ctx, tx, tenantID, request.WorkspaceID, request.IncidentID)
	if err != nil {
		return result, err
	}
	if activeFound {
		if active.RequestHash != requestHash {
			return result, store.ErrIdempotencyConflict
		}
		if err := bindCreateInvestigationIdempotency(
			ctx, tx, tenantID, request.WorkspaceID, request.IdempotencyKey, requestHash, active.ID,
		); err != nil {
			return result, err
		}
		result, err = loadCreateInvestigationResult(
			ctx, tx, tenantID, request.WorkspaceID, active.ID, requestHash, true,
		)
		if err != nil {
			return investigation.CreateOrGetInvestigationResult{}, err
		}
		if err := commit(ctx, tx, "commit active investigation binding"); err != nil {
			return investigation.CreateOrGetInvestigationResult{}, err
		}
		committed = true
		return result, nil
	}

	investigationID, taskIDs, err := repository.prepareInvestigationIDs(len(canonicalTasks))
	if err != nil {
		return result, err
	}
	created, err := insertRuntimeInvestigation(
		ctx, tx, tenantID, request, requestHash, investigationID, incident,
	)
	if err != nil {
		return result, mapCreateInsertError("insert runtime investigation", err)
	}
	createdTasks := make([]domain.ReadTask, 0, len(canonicalTasks))
	for index, spec := range canonicalTasks {
		task, insertErr := insertRuntimeTask(
			ctx, tx, tenantID, request.WorkspaceID, request.IncidentID,
			created.ID, taskIDs[index], index+1, spec, created.CreatedAt,
		)
		if insertErr != nil {
			return result, mapCreateInsertError("insert runtime investigation task", insertErr)
		}
		createdTasks = append(createdTasks, task)
	}
	if incident.Status == domain.IncidentOpen {
		updated, updateErr := tx.Exec(ctx, `
			UPDATE incidents AS incident
			SET status = 'INVESTIGATING',
				updated_at = GREATEST(incident.updated_at, $4::timestamptz),
				version = incident.version + 1
			WHERE incident.tenant_id = $1 AND incident.workspace_id = $2 AND incident.id = $3
			  AND incident.runtime_schema_version = $5 AND incident.status = 'OPEN'
		`, tenantID, request.WorkspaceID, request.IncidentID, created.CreatedAt, runtimeSchemaVersion)
		if updateErr != nil {
			return result, databaseError("transition incident to investigating", updateErr)
		}
		if updated.RowsAffected() != 1 {
			return result, store.ErrScopeViolation
		}
	}
	if err := bindCreateInvestigationIdempotency(
		ctx, tx, tenantID, request.WorkspaceID, request.IdempotencyKey, requestHash, created.ID,
	); err != nil {
		return result, err
	}
	if err := tx.Commit(ctx); err != nil {
		return result, databaseError("commit runtime investigation creation", err)
	}
	committed = true
	return investigation.CreateOrGetInvestigationResult{
		Investigation: created, Tasks: createdTasks, Created: true,
	}, nil
}

func validateCreateInvestigationRecord(record idempotencyRecord, requestHash string) error {
	if err := requireIdempotencyReplay(
		record, operationCreateInvestigation, requestHash, requestVersionCreateInvestigation,
	); err != nil {
		return err
	}
	if record.resourceType != "INVESTIGATION" || !validUUID(record.resourceID) || len(record.resultSnapshot) != 0 {
		return fmt.Errorf("read investigation creation replay: %w", errDatabaseOperation)
	}
	return nil
}

func bindCreateInvestigationIdempotency(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, workspaceID, idempotencyKey, requestHash, investigationID string,
) error {
	return insertIdempotencyRecord(ctx, tx, tenantID, workspaceID, idempotencyKey, idempotencyRecord{
		operation:      operationCreateInvestigation,
		requestHash:    requestHash,
		requestVersion: requestVersionCreateInvestigation,
		resourceType:   "INVESTIGATION",
		resourceID:     investigationID,
	})
}

func lockActiveInvestigation(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, workspaceID, incidentID string,
) (domain.Investigation, bool, error) {
	item, err := scanInvestigation(tx.QueryRow(ctx, `
		SELECT `+investigationProjection+`
		FROM investigations AS investigation
		WHERE investigation.tenant_id = $1 AND investigation.workspace_id = $2
		  AND investigation.incident_id = $3
		  AND investigation.runtime_schema_version = $4
		  AND investigation.status IN ('QUEUED', 'RUNNING')
		ORDER BY investigation.id
		LIMIT 1
		FOR NO KEY UPDATE OF investigation
	`, tenantID, workspaceID, incidentID, runtimeSchemaVersion))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Investigation{}, false, nil
	}
	if err != nil {
		return domain.Investigation{}, false, databaseError("lock active investigation", err)
	}
	return item, true, nil
}

func loadCreateInvestigationResult(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, workspaceID, investigationID, expectedRequestHash string,
	investigationAlreadyLocked bool,
) (investigation.CreateOrGetInvestigationResult, error) {
	var tasks []domain.ReadTask
	var err error
	if !investigationAlreadyLocked {
		// Runtime lifecycle writers lock tasks before their parent
		// Investigation. Replays follow the same order to avoid a lock-order
		// inversion with task completion or cancellation.
		tasks, err = loadInvestigationTasks(ctx, tx, tenantID, workspaceID, investigationID, true)
		if err != nil {
			return investigation.CreateOrGetInvestigationResult{}, err
		}
	}
	item, err := scanInvestigation(tx.QueryRow(ctx, `
		SELECT `+investigationProjection+`
		FROM investigations AS investigation
		WHERE investigation.tenant_id = $1 AND investigation.workspace_id = $2 AND investigation.id = $3
		  AND investigation.runtime_schema_version = $4
		FOR SHARE OF investigation
	`, tenantID, workspaceID, investigationID, runtimeSchemaVersion))
	if errors.Is(err, pgx.ErrNoRows) {
		return investigation.CreateOrGetInvestigationResult{}, store.ErrNotFound
	}
	if err != nil {
		return investigation.CreateOrGetInvestigationResult{}, databaseError("read investigation creation result", err)
	}
	if item.RequestHash != expectedRequestHash {
		return investigation.CreateOrGetInvestigationResult{}, fmt.Errorf(
			"read investigation creation result: %w", errDatabaseOperation,
		)
	}
	if investigationAlreadyLocked {
		// The caller already holds the parent row. A non-locking MVCC task read
		// cannot wait behind a lifecycle writer that holds a task while waiting
		// for this parent, so it cannot complete a deadlock cycle.
		tasks, err = loadInvestigationTasks(ctx, tx, tenantID, workspaceID, investigationID, false)
		if err != nil {
			return investigation.CreateOrGetInvestigationResult{}, err
		}
	}
	if err := validatePersistedCreateSemantics(item, tasks, expectedRequestHash); err != nil {
		return investigation.CreateOrGetInvestigationResult{}, err
	}
	return investigation.CreateOrGetInvestigationResult{Investigation: item, Tasks: tasks}, nil
}

func validatePersistedCreateSemantics(
	item domain.Investigation,
	tasks []domain.ReadTask,
	expectedRequestHash string,
) error {
	specs := make([]investigation.TaskSpec, len(tasks))
	for index, task := range tasks {
		if task.Position != index+1 {
			return fmt.Errorf("read investigation creation tasks: %w", errDatabaseOperation)
		}
		specs[index] = investigation.TaskSpec{
			Key: task.Key, ConnectorID: task.ConnectorID, Operation: task.Operation,
			Input: append([]byte(nil), task.Input...),
		}
	}
	canonical, taskHash, err := investigation.CanonicalTaskSpecs(specs)
	if err != nil || len(canonical) != len(specs) {
		return fmt.Errorf("read investigation creation semantics: %w", errDatabaseOperation)
	}
	for index := range canonical {
		if canonical[index].Key != specs[index].Key || canonical[index].ConnectorID != specs[index].ConnectorID ||
			canonical[index].Operation != specs[index].Operation || string(canonical[index].Input) != string(specs[index].Input) {
			return fmt.Errorf("read investigation creation semantics: %w", errDatabaseOperation)
		}
	}
	requestHash, err := investigation.CreateOrGetInvestigationRequestHash(
		investigation.CreateOrGetInvestigationRequest{IncidentID: item.IncidentID}, taskHash,
	)
	if err != nil || requestHash != item.RequestHash || requestHash != expectedRequestHash {
		return fmt.Errorf("read investigation creation semantics: %w", errDatabaseOperation)
	}
	return nil
}

func loadInvestigationTasks(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, workspaceID, investigationID string,
	lockRows bool,
) ([]domain.ReadTask, error) {
	query := `
		SELECT ` + taskProjection + `
		FROM tool_invocations AS task
		WHERE task.tenant_id = $1 AND task.workspace_id = $2 AND task.investigation_id = $3
		  AND task.runtime_schema_version = $4
		ORDER BY task.position, task.id`
	if lockRows {
		query += ` FOR SHARE OF task`
	}
	rows, err := tx.Query(ctx, query, tenantID, workspaceID, investigationID, runtimeSchemaVersion)
	if err != nil {
		return nil, databaseError("read investigation creation tasks", err)
	}
	defer rows.Close()
	tasks := make([]domain.ReadTask, 0, 12)
	for rows.Next() {
		task, scanErr := scanTask(rows)
		if scanErr != nil {
			return nil, databaseError("decode investigation creation task", scanErr)
		}
		tasks = append(tasks, task)
	}
	if err := rows.Err(); err != nil {
		return nil, databaseError("iterate investigation creation tasks", err)
	}
	if len(tasks) == 0 || len(tasks) > 12 {
		return nil, fmt.Errorf("read investigation creation tasks: %w", errDatabaseOperation)
	}
	return tasks, nil
}

func (repository *Repository) prepareInvestigationIDs(taskCount int) (string, []string, error) {
	investigationID, err := repository.newUUID()
	if err != nil {
		return "", nil, err
	}
	taskIDs := make([]string, taskCount)
	seen := make(map[string]struct{}, taskCount)
	for index := range taskIDs {
		taskID, idErr := repository.newUUID()
		if idErr != nil {
			return "", nil, idErr
		}
		if _, duplicate := seen[taskID]; duplicate {
			return "", nil, fmt.Errorf("%w: ID factory returned duplicate task IDs", investigation.ErrInvalidRequest)
		}
		seen[taskID] = struct{}{}
		taskIDs[index] = taskID
	}
	return investigationID, taskIDs, nil
}

func insertRuntimeInvestigation(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	request investigation.CreateOrGetInvestigationRequest,
	requestHash, investigationID string,
	incident domain.Incident,
) (domain.Investigation, error) {
	return scanInvestigation(tx.QueryRow(ctx, `
		WITH boundary AS MATERIALIZED (
			SELECT GREATEST(
				clock_timestamp(), $6::timestamptz, $7::timestamptz, $8::timestamptz
			) AS committed_at
		)
		INSERT INTO investigations AS investigation (
			id, tenant_id, workspace_id, incident_id, status,
			window_start, window_end, tool_schema_version, created_at,
			model_status, idempotency_key, request_hash, request_hash_version,
			updated_at, service_id_snapshot, environment_id_snapshot,
			mapping_status_snapshot, runtime_schema_version
		)
		SELECT $1, $2, $3, $4, 'QUEUED',
			$6, $7, $9, boundary.committed_at,
			'PENDING', $5, $10, $11,
			boundary.committed_at, $12, $13, $14, $15
		FROM boundary
		RETURNING `+investigationProjection,
		investigationID, tenantID, request.WorkspaceID, request.IncidentID, request.IdempotencyKey,
		incident.OpenedAt, incident.LastSignalAt, incident.UpdatedAt, investigationTaskSchemaVersion,
		requestHash, requestVersionCreateInvestigation, nullableInvestigationUUID(incident.ServiceID),
		nullableInvestigationUUID(incident.EnvironmentID), incident.MappingStatus, runtimeSchemaVersion,
	))
}

func insertRuntimeTask(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, workspaceID, incidentID, investigationID, taskID string,
	position int,
	spec investigation.TaskSpec,
	createdAt time.Time,
) (domain.ReadTask, error) {
	return scanTask(tx.QueryRow(ctx, `
		INSERT INTO tool_invocations AS task (
			id, tenant_id, workspace_id, investigation_id,
			tool_name, tool_version, input_hash, status,
			incident_id, task_key, position, input_document,
			created_at, updated_at, runtime_schema_version
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, 'QUEUED',
			$8, $9, $10, $11,
			$12, $12, $13
		)
		RETURNING `+taskProjection,
		taskID, tenantID, workspaceID, investigationID,
		spec.ConnectorID, spec.Operation, investigationInputHash(spec.Input),
		incidentID, spec.Key, position, []byte(spec.Input), createdAt.UTC(), runtimeSchemaVersion,
	))
}

func nullableInvestigationUUID(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func investigationInputHash(document []byte) string {
	digest := sha256.Sum256(document)
	return fmt.Sprintf("%x", digest[:])
}

func mapCreateInsertError(operation string, err error) error {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == "23505" &&
		(postgresError.ConstraintName == "investigations_pkey" || postgresError.ConstraintName == "tool_invocations_pkey") {
		return fmt.Errorf("%w: ID factory returned a duplicate persistent resource ID", investigation.ErrInvalidRequest)
	}
	return databaseError(operation, err)
}
