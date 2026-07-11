package postgres

import (
	"context"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/store"
)

func (repository *Repository) GetIncident(ctx context.Context, workspaceID, incidentID string) (domain.Incident, error) {
	if err := ctx.Err(); err != nil {
		return domain.Incident{}, err
	}
	if !validUUIDs(workspaceID, incidentID) {
		return domain.Incident{}, fmt.Errorf("%w: invalid incident scope", investigation.ErrInvalidRequest)
	}
	tx, tenantID, err := beginWorkspace(ctx, repository, workspaceID)
	if err != nil {
		return domain.Incident{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	item, err := scanIncident(tx.QueryRow(ctx, `
		SELECT `+incidentProjection+`
		FROM incidents AS incident
		WHERE incident.tenant_id = $1
		  AND incident.workspace_id = $2
		  AND incident.id = $3
		  AND incident.runtime_schema_version = $4
	`, tenantID, workspaceID, incidentID, runtimeSchemaVersion))
	if err != nil {
		return domain.Incident{}, databaseError("read incident", err)
	}
	if err := commit(ctx, tx, "commit incident read"); err != nil {
		return domain.Incident{}, err
	}
	committed = true
	return item, nil
}

func (repository *Repository) ListIncidents(ctx context.Context, request investigation.ListIncidentsRequest) ([]domain.Incident, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validUUID(request.WorkspaceID) || !validIncidentStatuses(request.Statuses) {
		return nil, fmt.Errorf("%w: invalid incident list filter", investigation.ErrInvalidRequest)
	}
	tx, tenantID, err := beginWorkspace(ctx, repository, request.WorkspaceID)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	query := `
		SELECT ` + incidentProjection + `
		FROM incidents AS incident
		WHERE incident.tenant_id = $1
		  AND incident.workspace_id = $2
		  AND incident.runtime_schema_version = $3`
	arguments := []any{tenantID, request.WorkspaceID, runtimeSchemaVersion}
	if len(request.Statuses) > 0 {
		query += ` AND incident.status = ANY($4::text[])`
		arguments = append(arguments, incidentStatusStrings(request.Statuses))
	}
	query += ` ORDER BY incident.opened_at, incident.id`
	rows, err := tx.Query(ctx, query, arguments...)
	if err != nil {
		return nil, databaseError("list incidents", err)
	}
	items := make([]domain.Incident, 0)
	for rows.Next() {
		item, scanErr := scanIncident(rows)
		if scanErr != nil {
			rows.Close()
			return nil, databaseError("scan incident list", scanErr)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, databaseError("iterate incident list", err)
	}
	rows.Close()
	sort.Slice(items, func(left, right int) bool {
		if !items[left].OpenedAt.Equal(items[right].OpenedAt) {
			return items[left].OpenedAt.Before(items[right].OpenedAt)
		}
		return items[left].ID < items[right].ID
	})
	if err := commit(ctx, tx, "commit incident list"); err != nil {
		return nil, err
	}
	committed = true
	return items, nil
}

func (repository *Repository) GetInvestigation(ctx context.Context, workspaceID, investigationID string) (domain.Investigation, error) {
	if err := ctx.Err(); err != nil {
		return domain.Investigation{}, err
	}
	if !validUUIDs(workspaceID, investigationID) {
		return domain.Investigation{}, fmt.Errorf("%w: invalid investigation scope", investigation.ErrInvalidRequest)
	}
	tx, tenantID, err := beginWorkspace(ctx, repository, workspaceID)
	if err != nil {
		return domain.Investigation{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	item, err := scanInvestigation(tx.QueryRow(ctx, `
		SELECT `+investigationProjection+`
		FROM investigations AS investigation
		WHERE investigation.tenant_id = $1
		  AND investigation.workspace_id = $2
		  AND investigation.id = $3
		  AND investigation.runtime_schema_version = $4
	`, tenantID, workspaceID, investigationID, runtimeSchemaVersion))
	if err != nil {
		return domain.Investigation{}, databaseError("read investigation", err)
	}
	if err := commit(ctx, tx, "commit investigation read"); err != nil {
		return domain.Investigation{}, err
	}
	committed = true
	return item, nil
}

func (repository *Repository) ListInvestigations(ctx context.Context, request investigation.ListInvestigationsRequest) ([]domain.Investigation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validUUID(request.WorkspaceID) || !validOptionalUUID(request.IncidentID) ||
		!validInvestigationStatuses(request.Statuses) {
		return nil, fmt.Errorf("%w: invalid investigation list filter", investigation.ErrInvalidRequest)
	}
	tx, tenantID, err := beginWorkspace(ctx, repository, request.WorkspaceID)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if request.IncidentID != "" {
		if err := requireRuntimeIncident(ctx, tx, tenantID, request.WorkspaceID, request.IncidentID); err != nil {
			return nil, err
		}
	}
	query := `
		SELECT ` + investigationProjection + `
		FROM investigations AS investigation
		WHERE investigation.tenant_id = $1
		  AND investigation.workspace_id = $2
		  AND investigation.runtime_schema_version = $3`
	arguments := []any{tenantID, request.WorkspaceID, runtimeSchemaVersion}
	nextArgument := 4
	if request.IncidentID != "" {
		query += fmt.Sprintf(` AND investigation.incident_id = $%d`, nextArgument)
		arguments = append(arguments, request.IncidentID)
		nextArgument++
	}
	if len(request.Statuses) > 0 {
		query += fmt.Sprintf(` AND investigation.status = ANY($%d::text[])`, nextArgument)
		arguments = append(arguments, investigationStatusStrings(request.Statuses))
	}
	query += ` ORDER BY investigation.created_at, investigation.id`
	rows, err := tx.Query(ctx, query, arguments...)
	if err != nil {
		return nil, databaseError("list investigations", err)
	}
	items := make([]domain.Investigation, 0)
	for rows.Next() {
		item, scanErr := scanInvestigation(rows)
		if scanErr != nil {
			rows.Close()
			return nil, databaseError("scan investigation list", scanErr)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, databaseError("iterate investigation list", err)
	}
	rows.Close()
	sort.Slice(items, func(left, right int) bool {
		if !items[left].CreatedAt.Equal(items[right].CreatedAt) {
			return items[left].CreatedAt.Before(items[right].CreatedAt)
		}
		return items[left].ID < items[right].ID
	})
	if err := commit(ctx, tx, "commit investigation list"); err != nil {
		return nil, err
	}
	committed = true
	return items, nil
}

func (repository *Repository) GetTask(ctx context.Context, workspaceID, taskID string) (domain.ReadTask, error) {
	if err := ctx.Err(); err != nil {
		return domain.ReadTask{}, err
	}
	if !validUUIDs(workspaceID, taskID) {
		return domain.ReadTask{}, fmt.Errorf("%w: invalid read task scope", investigation.ErrInvalidRequest)
	}
	tx, tenantID, err := beginWorkspace(ctx, repository, workspaceID)
	if err != nil {
		return domain.ReadTask{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	task, err := scanTask(tx.QueryRow(ctx, `
		SELECT `+taskProjection+`
		FROM tool_invocations AS task
		WHERE task.tenant_id = $1
		  AND task.workspace_id = $2
		  AND task.id = $3
		  AND task.runtime_schema_version = $4
	`, tenantID, workspaceID, taskID, runtimeSchemaVersion))
	if err != nil {
		return domain.ReadTask{}, databaseError("read read task", err)
	}
	if err := commit(ctx, tx, "commit read task read"); err != nil {
		return domain.ReadTask{}, err
	}
	committed = true
	return task, nil
}

func (repository *Repository) ListTasks(ctx context.Context, request investigation.ListTasksRequest) ([]domain.ReadTask, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validUUIDs(request.WorkspaceID, request.InvestigationID) || !validReadTaskStatuses(request.Statuses) {
		return nil, fmt.Errorf("%w: invalid read task list filter", investigation.ErrInvalidRequest)
	}
	tx, tenantID, err := beginWorkspace(ctx, repository, request.WorkspaceID)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if err := requireRuntimeInvestigation(ctx, tx, tenantID, request.WorkspaceID, request.InvestigationID); err != nil {
		return nil, err
	}
	query := `
		SELECT ` + taskProjection + `
		FROM tool_invocations AS task
		WHERE task.tenant_id = $1
		  AND task.workspace_id = $2
		  AND task.investigation_id = $3
		  AND task.runtime_schema_version = $4`
	arguments := []any{tenantID, request.WorkspaceID, request.InvestigationID, runtimeSchemaVersion}
	if len(request.Statuses) > 0 {
		query += ` AND task.status = ANY($5::text[])`
		arguments = append(arguments, readTaskStatusStrings(request.Statuses))
	}
	query += ` ORDER BY task.position, task.id`
	rows, err := tx.Query(ctx, query, arguments...)
	if err != nil {
		return nil, databaseError("list read tasks", err)
	}
	items := make([]domain.ReadTask, 0)
	for rows.Next() {
		item, scanErr := scanTask(rows)
		if scanErr != nil {
			rows.Close()
			return nil, databaseError("scan read task list", scanErr)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, databaseError("iterate read task list", err)
	}
	rows.Close()
	sort.Slice(items, func(left, right int) bool {
		if items[left].Position != items[right].Position {
			return items[left].Position < items[right].Position
		}
		return items[left].ID < items[right].ID
	})
	if err := commit(ctx, tx, "commit read task list"); err != nil {
		return nil, err
	}
	committed = true
	return items, nil
}

func (repository *Repository) GetEvidence(ctx context.Context, workspaceID, evidenceID string) (domain.Evidence, error) {
	if err := ctx.Err(); err != nil {
		return domain.Evidence{}, err
	}
	if !validUUIDs(workspaceID, evidenceID) {
		return domain.Evidence{}, fmt.Errorf("%w: invalid evidence scope", investigation.ErrInvalidRequest)
	}
	tx, tenantID, err := beginWorkspace(ctx, repository, workspaceID)
	if err != nil {
		return domain.Evidence{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	evidence, err := scanEvidence(tx.QueryRow(ctx, `
		SELECT `+evidenceProjection+`
		FROM evidence AS evidence_fact
		WHERE evidence_fact.tenant_id = $1
		  AND evidence_fact.workspace_id = $2
		  AND evidence_fact.id = $3
		  AND evidence_fact.runtime_schema_version = $4
	`, tenantID, workspaceID, evidenceID, runtimeSchemaVersion))
	if err != nil {
		return domain.Evidence{}, databaseError("read evidence", err)
	}
	if err := commit(ctx, tx, "commit evidence read"); err != nil {
		return domain.Evidence{}, err
	}
	committed = true
	return evidence, nil
}

func (repository *Repository) ListEvidence(ctx context.Context, request investigation.ListEvidenceRequest) ([]domain.Evidence, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validUUIDs(request.WorkspaceID, request.InvestigationID) || !validOptionalUUID(request.TaskID) {
		return nil, fmt.Errorf("%w: invalid evidence list filter", investigation.ErrInvalidRequest)
	}
	tx, tenantID, err := beginWorkspace(ctx, repository, request.WorkspaceID)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if err := requireRuntimeInvestigation(ctx, tx, tenantID, request.WorkspaceID, request.InvestigationID); err != nil {
		return nil, err
	}
	if request.TaskID != "" {
		if err := requireRuntimeTask(ctx, tx, tenantID, request.WorkspaceID, request.InvestigationID, request.TaskID); err != nil {
			return nil, err
		}
	}
	query := `
		SELECT ` + evidenceProjection + `
		FROM evidence AS evidence_fact
		WHERE evidence_fact.tenant_id = $1
		  AND evidence_fact.workspace_id = $2
		  AND evidence_fact.investigation_id = $3
		  AND evidence_fact.runtime_schema_version = $4`
	arguments := []any{tenantID, request.WorkspaceID, request.InvestigationID, runtimeSchemaVersion}
	if request.TaskID != "" {
		query += ` AND evidence_fact.task_id = $5`
		arguments = append(arguments, request.TaskID)
	}
	query += ` ORDER BY evidence_fact.collected_at, evidence_fact.created_at, evidence_fact.id`
	rows, err := tx.Query(ctx, query, arguments...)
	if err != nil {
		return nil, databaseError("list evidence", err)
	}
	items := make([]domain.Evidence, 0)
	for rows.Next() {
		item, scanErr := scanEvidence(rows)
		if scanErr != nil {
			rows.Close()
			return nil, databaseError("scan evidence list", scanErr)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, databaseError("iterate evidence list", err)
	}
	rows.Close()
	sort.Slice(items, func(left, right int) bool {
		if !items[left].CollectedAt.Equal(items[right].CollectedAt) {
			return items[left].CollectedAt.Before(items[right].CollectedAt)
		}
		if !items[left].CreatedAt.Equal(items[right].CreatedAt) {
			return items[left].CreatedAt.Before(items[right].CreatedAt)
		}
		return items[left].ID < items[right].ID
	})
	if err := commit(ctx, tx, "commit evidence list"); err != nil {
		return nil, err
	}
	committed = true
	return items, nil
}

func (repository *Repository) GetHypothesis(ctx context.Context, workspaceID, hypothesisID string) (domain.Hypothesis, error) {
	if err := ctx.Err(); err != nil {
		return domain.Hypothesis{}, err
	}
	if !validUUIDs(workspaceID, hypothesisID) {
		return domain.Hypothesis{}, fmt.Errorf("%w: invalid hypothesis scope", investigation.ErrInvalidRequest)
	}
	tx, tenantID, err := beginWorkspace(ctx, repository, workspaceID)
	if err != nil {
		return domain.Hypothesis{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	hypothesis, err := scanHypothesis(tx.QueryRow(ctx, `
		SELECT `+hypothesisProjection+`
		FROM hypotheses AS hypothesis
		WHERE hypothesis.tenant_id = $1
		  AND hypothesis.workspace_id = $2
		  AND hypothesis.id = $3
		  AND hypothesis.runtime_schema_version = $4
	`, tenantID, workspaceID, hypothesisID, runtimeSchemaVersion))
	if err != nil {
		return domain.Hypothesis{}, databaseError("read hypothesis", err)
	}
	if err := commit(ctx, tx, "commit hypothesis read"); err != nil {
		return domain.Hypothesis{}, err
	}
	committed = true
	return hypothesis, nil
}

func (repository *Repository) ListHypotheses(ctx context.Context, request investigation.ListHypothesesRequest) ([]domain.Hypothesis, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validUUIDs(request.WorkspaceID, request.InvestigationID) {
		return nil, fmt.Errorf("%w: invalid hypothesis list filter", investigation.ErrInvalidRequest)
	}
	tx, tenantID, err := beginWorkspace(ctx, repository, request.WorkspaceID)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if err := requireRuntimeInvestigation(ctx, tx, tenantID, request.WorkspaceID, request.InvestigationID); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `
		SELECT `+hypothesisProjection+`
		FROM hypotheses AS hypothesis
		WHERE hypothesis.tenant_id = $1
		  AND hypothesis.workspace_id = $2
		  AND hypothesis.investigation_id = $3
		  AND hypothesis.runtime_schema_version = $4
		ORDER BY hypothesis.rank, hypothesis.id
	`, tenantID, request.WorkspaceID, request.InvestigationID, runtimeSchemaVersion)
	if err != nil {
		return nil, databaseError("list hypotheses", err)
	}
	items := make([]domain.Hypothesis, 0)
	for rows.Next() {
		item, scanErr := scanHypothesis(rows)
		if scanErr != nil {
			rows.Close()
			return nil, databaseError("scan hypothesis list", scanErr)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, databaseError("iterate hypothesis list", err)
	}
	rows.Close()
	sort.Slice(items, func(left, right int) bool {
		if items[left].Rank != items[right].Rank {
			return items[left].Rank < items[right].Rank
		}
		return items[left].ID < items[right].ID
	})
	if err := commit(ctx, tx, "commit hypothesis list"); err != nil {
		return nil, err
	}
	committed = true
	return items, nil
}

func requireRuntimeIncident(ctx context.Context, tx pgx.Tx, tenantID, workspaceID, incidentID string) error {
	var exists bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM incidents AS incident
			WHERE incident.tenant_id = $1
			  AND incident.workspace_id = $2
			  AND incident.id = $3
			  AND incident.runtime_schema_version = $4
		)
	`, tenantID, workspaceID, incidentID, runtimeSchemaVersion).Scan(&exists); err != nil {
		return databaseError("verify incident scope", err)
	}
	if !exists {
		return store.ErrNotFound
	}
	return nil
}

func requireRuntimeInvestigation(ctx context.Context, tx pgx.Tx, tenantID, workspaceID, investigationID string) error {
	var exists bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM investigations AS investigation
			WHERE investigation.tenant_id = $1
			  AND investigation.workspace_id = $2
			  AND investigation.id = $3
			  AND investigation.runtime_schema_version = $4
		)
	`, tenantID, workspaceID, investigationID, runtimeSchemaVersion).Scan(&exists); err != nil {
		return databaseError("verify investigation scope", err)
	}
	if !exists {
		return store.ErrNotFound
	}
	return nil
}

func requireRuntimeTask(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	workspaceID string,
	investigationID string,
	taskID string,
) error {
	var exists bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM tool_invocations AS task
			WHERE task.tenant_id = $1
			  AND task.workspace_id = $2
			  AND task.investigation_id = $3
			  AND task.id = $4
			  AND task.runtime_schema_version = $5
		)
	`, tenantID, workspaceID, investigationID, taskID, runtimeSchemaVersion).Scan(&exists); err != nil {
		return databaseError("verify read task scope", err)
	}
	if !exists {
		return store.ErrNotFound
	}
	return nil
}

func validIncidentStatuses(statuses []domain.IncidentStatus) bool {
	for _, status := range statuses {
		switch status {
		case domain.IncidentOpen, domain.IncidentInvestigating, domain.IncidentMitigating,
			domain.IncidentResolved, domain.IncidentClosed:
		default:
			return false
		}
	}
	return true
}

func validInvestigationStatuses(statuses []domain.InvestigationStatus) bool {
	for _, status := range statuses {
		switch status {
		case domain.InvestigationQueued, domain.InvestigationRunning, domain.InvestigationPartial,
			domain.InvestigationCompleted, domain.InvestigationFailed, domain.InvestigationCancelled:
		default:
			return false
		}
	}
	return true
}

func validReadTaskStatuses(statuses []domain.ReadTaskStatus) bool {
	for _, status := range statuses {
		switch status {
		case domain.ReadTaskQueued, domain.ReadTaskRunning, domain.ReadTaskEvidence,
			domain.ReadTaskFailed, domain.ReadTaskCancelled:
		default:
			return false
		}
	}
	return true
}

func incidentStatusStrings(statuses []domain.IncidentStatus) []string {
	values := make([]string, len(statuses))
	for index, status := range statuses {
		values[index] = string(status)
	}
	return values
}

func investigationStatusStrings(statuses []domain.InvestigationStatus) []string {
	values := make([]string, len(statuses))
	for index, status := range statuses {
		values[index] = string(status)
	}
	return values
}

func readTaskStatusStrings(statuses []domain.ReadTaskStatus) []string {
	values := make([]string, len(statuses))
	for index, status := range statuses {
		values[index] = string(status)
	}
	return values
}
