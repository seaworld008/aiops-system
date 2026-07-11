package postgres

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/store"
)

func (repository *Repository) FinalizeInvestigation(
	ctx context.Context,
	request investigation.FinalizeInvestigationRequest,
) (investigation.FinalizeInvestigationResult, error) {
	if err := ctx.Err(); err != nil {
		return investigation.FinalizeInvestigationResult{}, err
	}
	if !validUUIDs(request.WorkspaceID, request.InvestigationID) ||
		!domain.ValidIdempotencyKey(request.IdempotencyKey) {
		return investigation.FinalizeInvestigationResult{}, fmt.Errorf("%w: invalid investigation finalization", investigation.ErrInvalidRequest)
	}
	normalized, requestHash, err := investigation.NormalizeFinalizeInvestigationRequest(request)
	if err != nil {
		return investigation.FinalizeInvestigationResult{}, err
	}
	request = normalized
	for _, spec := range request.Hypotheses {
		if !validUUIDs(spec.EvidenceIDs...) {
			return investigation.FinalizeInvestigationResult{}, fmt.Errorf("%w: evidence IDs must be persistent UUIDs", investigation.ErrInvalidRequest)
		}
	}

	tx, tenantID, err := beginWorkspace(ctx, repository, request.WorkspaceID)
	if err != nil {
		return investigation.FinalizeInvestigationResult{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if err := lockIdempotencyKey(ctx, tx, tenantID, request.WorkspaceID, request.IdempotencyKey); err != nil {
		return investigation.FinalizeInvestigationResult{}, err
	}
	existing, err := readIdempotencyRecord(ctx, tx, tenantID, request.WorkspaceID, request.IdempotencyKey)
	if err == nil {
		if err := requireIdempotencyReplay(existing, operationFinalizeInvestigation, requestHash, requestVersionFinalizeInvestigation); err != nil {
			return investigation.FinalizeInvestigationResult{}, err
		}
		if existing.resourceType != "INVESTIGATION" || existing.resourceID != request.InvestigationID ||
			existing.snapshotVersion != snapshotVersionFinalize {
			return investigation.FinalizeInvestigationResult{}, fmt.Errorf("read finalization replay: %w", errDatabaseOperation)
		}
		result, decodeErr := decodeFinalizeSnapshot(existing.resultSnapshot)
		if decodeErr != nil || result.Investigation.ID != request.InvestigationID ||
			result.Investigation.WorkspaceID != request.WorkspaceID {
			return investigation.FinalizeInvestigationResult{}, fmt.Errorf("read finalization replay: %w", errDatabaseOperation)
		}
		if err := commit(ctx, tx, "commit investigation finalization replay"); err != nil {
			return investigation.FinalizeInvestigationResult{}, err
		}
		committed = true
		result.Replayed = true
		return result, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return investigation.FinalizeInvestigationResult{}, databaseError("read investigation finalization idempotency", err)
	}

	tasks, err := lockInvestigationTasksForMutation(ctx, tx, tenantID, request.WorkspaceID, request.InvestigationID)
	if err != nil {
		return investigation.FinalizeInvestigationResult{}, err
	}
	item, err := readRuntimeInvestigation(ctx, tx, tenantID, request.WorkspaceID, request.InvestigationID, "FOR NO KEY UPDATE OF investigation")
	if err != nil {
		return investigation.FinalizeInvestigationResult{}, err
	}
	if len(tasks) < 1 || len(tasks) > 12 {
		return investigation.FinalizeInvestigationResult{}, fmt.Errorf("read investigation tasks: %w", errDatabaseOperation)
	}
	if item.Status != domain.InvestigationQueued && item.Status != domain.InvestigationRunning {
		return investigation.FinalizeInvestigationResult{}, investigation.ErrInvalidTransition
	}
	if !validPostgresModelFinalization(item.ModelStatus, request.ModelStatus) {
		return investigation.FinalizeInvestigationResult{}, investigation.ErrInvalidTransition
	}
	if request.Status == domain.InvestigationCompleted || request.Status == domain.InvestigationPartial {
		if item.Status != domain.InvestigationRunning {
			return investigation.FinalizeInvestigationResult{}, investigation.ErrInvalidTransition
		}
		derived, terminal := deriveInvestigationStatus(tasks)
		if !terminal || derived != request.Status {
			return investigation.FinalizeInvestigationResult{}, investigation.ErrInvalidTransition
		}
	}

	evidenceTimes, err := lockFinalizationEvidence(ctx, tx, tenantID, request.WorkspaceID, request.InvestigationID, request.Hypotheses)
	if err != nil {
		return investigation.FinalizeInvestigationResult{}, err
	}
	commitAt, err := investigationBoundaryTime(ctx, tx, tenantID, request.WorkspaceID, item, tasks)
	if err != nil {
		return investigation.FinalizeInvestigationResult{}, err
	}
	for _, candidate := range evidenceTimes {
		if candidate.After(commitAt) {
			commitAt = candidate
		}
	}
	commitAt = commitAt.UTC().Truncate(time.Microsecond)

	hypothesisIDs, err := repository.prepareHypothesisIDs(len(request.Hypotheses))
	if err != nil {
		return investigation.FinalizeInvestigationResult{}, err
	}
	createdHypotheses := make([]domain.Hypothesis, 0, len(request.Hypotheses))
	for index, spec := range request.Hypotheses {
		created, insertErr := insertRuntimeHypothesis(
			ctx, tx, tenantID, request.WorkspaceID, item.IncidentID, item.ID,
			hypothesisIDs[index], spec, commitAt,
		)
		if insertErr != nil {
			if errors.Is(insertErr, investigation.ErrInvalidRequest) {
				return investigation.FinalizeInvestigationResult{}, insertErr
			}
			return investigation.FinalizeInvestigationResult{}, databaseError("insert investigation hypothesis", insertErr)
		}
		for position, evidenceID := range spec.EvidenceIDs {
			if _, insertErr := tx.Exec(ctx, `
				INSERT INTO hypothesis_evidence (
					tenant_id, workspace_id, investigation_id, hypothesis_id,
					evidence_id, relation, position, runtime_schema_version
				) VALUES ($1, $2, $3, $4, $5, 'SUPPORTS', $6, $7)
			`, tenantID, request.WorkspaceID, item.ID, created.ID, evidenceID, position+1, runtimeSchemaVersion); insertErr != nil {
				return investigation.FinalizeInvestigationResult{}, databaseError("link investigation hypothesis evidence", insertErr)
			}
		}
		created.EvidenceIDs = append([]string(nil), spec.EvidenceIDs...)
		if err := created.Validate(); err != nil {
			return investigation.FinalizeInvestigationResult{}, fmt.Errorf("persist investigation hypothesis: %w", errDatabaseOperation)
		}
		createdHypotheses = append(createdHypotheses, created)
	}

	if request.Status == domain.InvestigationCancelled {
		if _, err := tx.Exec(ctx, `
			UPDATE tool_invocations AS task
			SET status = 'CANCELLED', evidence_id = NULL, output_hash = NULL,
				failure_code = $4, completed_at = $5, updated_at = $5
			WHERE task.tenant_id = $1 AND task.workspace_id = $2
			  AND task.investigation_id = $3 AND task.runtime_schema_version = $6
			  AND task.status IN ('QUEUED', 'RUNNING')
		`, tenantID, request.WorkspaceID, request.InvestigationID, request.FailureCode, commitAt, runtimeSchemaVersion); err != nil {
			return investigation.FinalizeInvestigationResult{}, databaseError("cancel finalization read tasks", err)
		}
	}
	item, err = scanInvestigation(tx.QueryRow(ctx, `
		UPDATE investigations AS investigation
		SET status = $4, model_status = $5,
			failure_code = $6, model_failure_code = $7,
			completed_at = $8, updated_at = $8
		WHERE investigation.tenant_id = $1 AND investigation.workspace_id = $2
		  AND investigation.id = $3 AND investigation.runtime_schema_version = $9
		  AND investigation.status IN ('QUEUED', 'RUNNING')
		RETURNING `+investigationProjection,
		tenantID, request.WorkspaceID, request.InvestigationID,
		request.Status, request.ModelStatus, nullableTextValue(request.FailureCode),
		nullableTextValue(request.ModelFailureCode), commitAt, runtimeSchemaVersion))
	if errors.Is(err, pgx.ErrNoRows) {
		return investigation.FinalizeInvestigationResult{}, investigation.ErrInvalidTransition
	}
	if err != nil {
		return investigation.FinalizeInvestigationResult{}, databaseError("finalize investigation", err)
	}
	result := investigation.FinalizeInvestigationResult{Investigation: item, Hypotheses: createdHypotheses}
	snapshot, digest, err := encodeFinalizeSnapshot(result)
	if err != nil {
		return investigation.FinalizeInvestigationResult{}, fmt.Errorf("persist finalization snapshot: %w", errDatabaseOperation)
	}
	if err := insertIdempotencyRecord(ctx, tx, tenantID, request.WorkspaceID, request.IdempotencyKey, idempotencyRecord{
		operation: operationFinalizeInvestigation, requestHash: requestHash, requestVersion: requestVersionFinalizeInvestigation,
		resourceType: "INVESTIGATION", resourceID: item.ID,
		resultSnapshot: snapshot, snapshotDigest: digest, snapshotVersion: snapshotVersionFinalize,
	}); err != nil {
		return investigation.FinalizeInvestigationResult{}, err
	}
	if err := commit(ctx, tx, "commit investigation finalization"); err != nil {
		return investigation.FinalizeInvestigationResult{}, err
	}
	committed = true
	return result, nil
}

func validPostgresModelFinalization(current, terminal domain.ModelStatus) bool {
	switch terminal {
	case domain.ModelCompleted, domain.ModelFailed:
		return current == domain.ModelRunning
	case domain.ModelSkipped:
		return current == domain.ModelPending
	case domain.ModelCancelled:
		return current == domain.ModelPending || current == domain.ModelRunning
	default:
		return false
	}
}

func deriveInvestigationStatus(tasks []domain.ReadTask) (domain.InvestigationStatus, bool) {
	status := domain.InvestigationCompleted
	for _, task := range tasks {
		switch task.Status {
		case domain.ReadTaskEvidence:
		case domain.ReadTaskFailed, domain.ReadTaskCancelled:
			status = domain.InvestigationPartial
		default:
			return "", false
		}
	}
	return status, true
}

func lockFinalizationEvidence(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, workspaceID, investigationID string,
	specs []investigation.HypothesisSpec,
) ([]time.Time, error) {
	unique := make(map[string]struct{})
	for _, spec := range specs {
		for _, evidenceID := range spec.EvidenceIDs {
			unique[evidenceID] = struct{}{}
		}
	}
	if len(unique) == 0 {
		return nil, nil
	}
	ids := make([]string, 0, len(unique))
	for evidenceID := range unique {
		ids = append(ids, evidenceID)
	}
	sort.Strings(ids)
	typedIDs, err := postgresUUIDArray(ids)
	if err != nil {
		return nil, fmt.Errorf("lock investigation finalization evidence: %w", errDatabaseOperation)
	}
	rows, err := tx.Query(ctx, `
		SELECT evidence_fact.id::text, evidence_fact.collected_at, evidence_fact.created_at
		FROM evidence AS evidence_fact
		WHERE evidence_fact.tenant_id = $1 AND evidence_fact.workspace_id = $2
		  AND evidence_fact.investigation_id = $3
		  AND evidence_fact.runtime_schema_version = $4
		  AND evidence_fact.id = ANY($5::uuid[])
		ORDER BY evidence_fact.id
		FOR SHARE OF evidence_fact
	`, tenantID, workspaceID, investigationID, runtimeSchemaVersion, typedIDs)
	if err != nil {
		return nil, databaseError("lock investigation finalization evidence", err)
	}
	defer rows.Close()
	found := make(map[string]struct{}, len(ids))
	times := make([]time.Time, 0, len(ids)*2)
	for rows.Next() {
		var evidenceID string
		var collectedAt, createdAt time.Time
		if err := rows.Scan(&evidenceID, &collectedAt, &createdAt); err != nil {
			return nil, databaseError("scan investigation finalization evidence", err)
		}
		if !validUUID(evidenceID) {
			return nil, fmt.Errorf("read investigation finalization evidence: %w", errDatabaseOperation)
		}
		found[evidenceID] = struct{}{}
		times = append(times, databaseTime(collectedAt), databaseTime(createdAt))
	}
	if err := rows.Err(); err != nil {
		return nil, databaseError("iterate investigation finalization evidence", err)
	}
	if len(found) != len(ids) {
		return nil, store.ErrNotFound
	}
	return times, nil
}

func postgresUUIDArray(values []string) ([]pgtype.UUID, error) {
	result := make([]pgtype.UUID, len(values))
	for index, value := range values {
		if !validUUID(value) {
			return nil, fmt.Errorf("invalid persistent UUID")
		}
		compact := strings.ReplaceAll(value, "-", "")
		if _, err := hex.Decode(result[index].Bytes[:], []byte(compact)); err != nil {
			return nil, fmt.Errorf("invalid persistent UUID")
		}
		result[index].Valid = true
	}
	return result, nil
}

func (repository *Repository) prepareHypothesisIDs(count int) ([]string, error) {
	ids := make([]string, count)
	seen := make(map[string]struct{}, count)
	for index := range ids {
		id, err := repository.newUUID()
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, fmt.Errorf("%w: ID factory returned duplicate hypothesis IDs", investigation.ErrInvalidRequest)
		}
		seen[id] = struct{}{}
		ids[index] = id
	}
	return ids, nil
}

func insertRuntimeHypothesis(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, workspaceID, incidentID, investigationID, hypothesisID string,
	spec investigation.HypothesisSpec,
	createdAt time.Time,
) (domain.Hypothesis, error) {
	band, err := investigation.ConfidenceBandFor(spec.Confidence)
	if err != nil {
		return domain.Hypothesis{}, err
	}
	unknowns := spec.Unknowns
	if unknowns == nil {
		unknowns = []string{}
	}
	result, err := tx.Exec(ctx, `
		INSERT INTO hypotheses AS hypothesis (
			id, tenant_id, workspace_id, incident_id, investigation_id,
			status, rank, confidence_band, summary, created_at,
			confidence, proposal_document, proposal_hash, unknowns, runtime_schema_version
		) VALUES (
			$1, $2, $3, $4, $5,
			'PROPOSED', $6, $7, $8, $9,
			$10, $11, $12, $13, $14
		)
		ON CONFLICT (id) DO NOTHING
	`,
		hypothesisID, tenantID, workspaceID, incidentID, investigationID,
		spec.Rank, string(band), spec.Summary, createdAt, spec.Confidence,
		[]byte(spec.Proposal), spec.ProposalHash, unknowns, runtimeSchemaVersion)
	if err != nil {
		return domain.Hypothesis{}, err
	}
	if result.RowsAffected() != 1 {
		return domain.Hypothesis{}, fmt.Errorf("%w: ID factory returned a duplicate hypothesis ID", investigation.ErrInvalidRequest)
	}
	return domain.Hypothesis{
		ID: hypothesisID, WorkspaceID: workspaceID, IncidentID: incidentID,
		InvestigationID: investigationID, Status: domain.HypothesisProposed,
		Rank: spec.Rank, Confidence: spec.Confidence, Summary: spec.Summary,
		Proposal: append([]byte(nil), spec.Proposal...), ProposalHash: spec.ProposalHash,
		Unknowns: append([]string{}, unknowns...), CreatedAt: createdAt,
	}, nil
}

func nullableTextValue(value string) any {
	if value == "" {
		return nil
	}
	return value
}
