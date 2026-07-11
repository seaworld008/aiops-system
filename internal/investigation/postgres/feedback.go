package postgres

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/store"
)

func (repository *Repository) RecordFeedback(
	ctx context.Context,
	request investigation.RecordFeedbackRequest,
) (investigation.RecordFeedbackResult, error) {
	if err := ctx.Err(); err != nil {
		return investigation.RecordFeedbackResult{}, err
	}
	if !validUUIDs(
		request.WorkspaceID,
		request.IncidentID,
		request.InvestigationID,
		request.HypothesisID,
	) || !domain.ValidResourceID(request.Actor.ID) ||
		!domain.ValidIdempotencyKey(request.IdempotencyKey) {
		return investigation.RecordFeedbackResult{}, fmt.Errorf("%w: invalid feedback identity", investigation.ErrInvalidRequest)
	}
	normalized, requestHash, err := investigation.NormalizeRecordFeedbackRequest(request)
	if err != nil {
		return investigation.RecordFeedbackResult{}, err
	}
	request = normalized

	tx, tenantID, err := beginWorkspace(ctx, repository, request.WorkspaceID)
	if err != nil {
		return investigation.RecordFeedbackResult{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if err := lockIdempotencyKey(ctx, tx, tenantID, request.WorkspaceID, request.IdempotencyKey); err != nil {
		return investigation.RecordFeedbackResult{}, err
	}
	existing, err := readIdempotencyRecord(ctx, tx, tenantID, request.WorkspaceID, request.IdempotencyKey)
	if err == nil {
		if err := requireIdempotencyReplay(existing, operationRecordFeedback, requestHash, requestVersionRecordFeedback); err != nil {
			return investigation.RecordFeedbackResult{}, err
		}
		if existing.resourceType != "FEEDBACK" || len(existing.resultSnapshot) != 0 {
			return investigation.RecordFeedbackResult{}, fmt.Errorf("read feedback replay: %w", errDatabaseOperation)
		}
		feedback, readErr := readRuntimeFeedback(
			ctx, tx, tenantID, request.WorkspaceID, request.IncidentID,
			request.InvestigationID, request.HypothesisID, existing.resourceID,
		)
		if readErr != nil {
			if errors.Is(readErr, store.ErrNotFound) {
				return investigation.RecordFeedbackResult{}, fmt.Errorf("read feedback replay: %w", errDatabaseOperation)
			}
			return investigation.RecordFeedbackResult{}, readErr
		}
		if feedback.Actor != request.Actor || feedback.Verdict != request.Verdict ||
			!bytes.Equal(feedback.Details, request.Details) {
			return investigation.RecordFeedbackResult{}, fmt.Errorf("read feedback replay: %w", errDatabaseOperation)
		}
		if err := commit(ctx, tx, "commit feedback replay"); err != nil {
			return investigation.RecordFeedbackResult{}, err
		}
		committed = true
		return investigation.RecordFeedbackResult{Feedback: feedback}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return investigation.RecordFeedbackResult{}, databaseError("read feedback idempotency", err)
	}

	incident, err := lockFeedbackIncident(ctx, tx, tenantID, request.WorkspaceID, request.IncidentID)
	if err != nil {
		return investigation.RecordFeedbackResult{}, err
	}
	item, err := lockFeedbackInvestigation(
		ctx, tx, tenantID, request.WorkspaceID, request.IncidentID, request.InvestigationID,
	)
	if err != nil {
		return investigation.RecordFeedbackResult{}, err
	}
	hypothesis, err := lockFeedbackHypothesis(
		ctx, tx, tenantID, request.WorkspaceID, request.IncidentID,
		request.InvestigationID, request.HypothesisID,
	)
	if err != nil {
		return investigation.RecordFeedbackResult{}, err
	}
	if item.Status != domain.InvestigationCompleted && item.Status != domain.InvestigationPartial {
		return investigation.RecordFeedbackResult{}, investigation.ErrInvalidTransition
	}
	if request.Verdict != domain.FeedbackInconclusive && hypothesis.Status != domain.HypothesisProposed {
		return investigation.RecordFeedbackResult{}, investigation.ErrInvalidTransition
	}
	if request.Verdict == domain.FeedbackConfirmed && incident.ConfirmedHypothesisID != "" {
		return investigation.RecordFeedbackResult{}, investigation.ErrInvalidTransition
	}

	feedbackID, err := repository.newUUID()
	if err != nil {
		return investigation.RecordFeedbackResult{}, err
	}
	commitAt, err := feedbackBoundaryTime(ctx, tx, tenantID, request.WorkspaceID, incident, item, hypothesis)
	if err != nil {
		return investigation.RecordFeedbackResult{}, err
	}
	feedback := domain.Feedback{
		ID: feedbackID, WorkspaceID: request.WorkspaceID, IncidentID: request.IncidentID,
		InvestigationID: request.InvestigationID, HypothesisID: request.HypothesisID,
		Actor: request.Actor, Verdict: request.Verdict,
		Details: append([]byte(nil), request.Details...), CreatedAt: commitAt,
	}
	if err := feedback.Validate(); err != nil {
		return investigation.RecordFeedbackResult{}, fmt.Errorf("persist feedback: %w", errDatabaseOperation)
	}

	switch request.Verdict {
	case domain.FeedbackConfirmed:
		if err := projectFeedbackHypothesis(ctx, tx, tenantID, request, domain.HypothesisConfirmed); err != nil {
			return investigation.RecordFeedbackResult{}, err
		}
		result, updateErr := tx.Exec(ctx, `
			UPDATE incidents AS incident
			SET confirmed_hypothesis_id = $4, updated_at = $5, version = incident.version + 1
			WHERE incident.tenant_id = $1 AND incident.workspace_id = $2
			  AND incident.id = $3 AND incident.runtime_schema_version = $6
			  AND incident.confirmed_hypothesis_id IS NULL
		`, tenantID, request.WorkspaceID, request.IncidentID, request.HypothesisID, commitAt, runtimeSchemaVersion)
		if updateErr != nil {
			return investigation.RecordFeedbackResult{}, databaseError("project confirmed incident root cause", updateErr)
		}
		if result.RowsAffected() != 1 {
			return investigation.RecordFeedbackResult{}, investigation.ErrInvalidTransition
		}
	case domain.FeedbackRejected:
		if err := projectFeedbackHypothesis(ctx, tx, tenantID, request, domain.HypothesisRejected); err != nil {
			return investigation.RecordFeedbackResult{}, err
		}
	case domain.FeedbackInconclusive:
	}

	result, err := tx.Exec(ctx, `
		INSERT INTO feedback (
			id, tenant_id, workspace_id, investigation_id, hypothesis_id,
			actor_id, kind, created_at, incident_id, actor_type,
			details_document, details_hash, runtime_schema_version
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10,
			$11, $12, $13
		)
		ON CONFLICT (id) DO NOTHING
	`, feedback.ID, tenantID, request.WorkspaceID, request.InvestigationID, request.HypothesisID,
		request.Actor.ID, request.Verdict, commitAt, request.IncidentID, request.Actor.Type,
		[]byte(request.Details), snapshotSHA256Hex(request.Details), runtimeSchemaVersion)
	if err != nil {
		return investigation.RecordFeedbackResult{}, databaseError("insert feedback", err)
	}
	if result.RowsAffected() != 1 {
		return investigation.RecordFeedbackResult{}, fmt.Errorf("%w: ID factory returned a duplicate feedback ID", investigation.ErrInvalidRequest)
	}
	if err := insertIdempotencyRecord(ctx, tx, tenantID, request.WorkspaceID, request.IdempotencyKey, idempotencyRecord{
		operation: operationRecordFeedback, requestHash: requestHash, requestVersion: requestVersionRecordFeedback,
		resourceType: "FEEDBACK", resourceID: feedback.ID,
	}); err != nil {
		return investigation.RecordFeedbackResult{}, err
	}
	if err := commit(ctx, tx, "commit feedback"); err != nil {
		return investigation.RecordFeedbackResult{}, err
	}
	committed = true
	return investigation.RecordFeedbackResult{Feedback: feedback, Created: true}, nil
}

func lockFeedbackIncident(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, workspaceID, incidentID string,
) (domain.Incident, error) {
	item, err := scanIncident(tx.QueryRow(ctx, `
		SELECT `+incidentProjection+`
		FROM incidents AS incident
		WHERE incident.tenant_id = $1 AND incident.workspace_id = $2
		  AND incident.id = $3 AND incident.runtime_schema_version = $4
		FOR NO KEY UPDATE OF incident
	`, tenantID, workspaceID, incidentID, runtimeSchemaVersion))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Incident{}, store.ErrNotFound
	}
	if err != nil {
		return domain.Incident{}, databaseError("lock feedback incident", err)
	}
	return item, nil
}

func lockFeedbackInvestigation(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, workspaceID, incidentID, investigationID string,
) (domain.Investigation, error) {
	item, err := scanInvestigation(tx.QueryRow(ctx, `
		SELECT `+investigationProjection+`
		FROM investigations AS investigation
		WHERE investigation.tenant_id = $1 AND investigation.workspace_id = $2
		  AND investigation.incident_id = $3 AND investigation.id = $4
		  AND investigation.runtime_schema_version = $5
		FOR SHARE OF investigation
	`, tenantID, workspaceID, incidentID, investigationID, runtimeSchemaVersion))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Investigation{}, store.ErrNotFound
	}
	if err != nil {
		return domain.Investigation{}, databaseError("lock feedback investigation", err)
	}
	return item, nil
}

func lockFeedbackHypothesis(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, workspaceID, incidentID, investigationID, hypothesisID string,
) (domain.Hypothesis, error) {
	item, err := scanHypothesis(tx.QueryRow(ctx, `
		SELECT `+hypothesisProjection+`
		FROM hypotheses AS hypothesis
		WHERE hypothesis.tenant_id = $1 AND hypothesis.workspace_id = $2
		  AND hypothesis.incident_id = $3 AND hypothesis.investigation_id = $4
		  AND hypothesis.id = $5 AND hypothesis.runtime_schema_version = $6
		FOR NO KEY UPDATE OF hypothesis
	`, tenantID, workspaceID, incidentID, investigationID, hypothesisID, runtimeSchemaVersion))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Hypothesis{}, store.ErrNotFound
	}
	if err != nil {
		return domain.Hypothesis{}, databaseError("lock feedback hypothesis", err)
	}
	return item, nil
}

func feedbackBoundaryTime(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, workspaceID string,
	incident domain.Incident,
	item domain.Investigation,
	hypothesis domain.Hypothesis,
) (time.Time, error) {
	databaseNow, err := scopedDatabaseNow(ctx, tx, tenantID, workspaceID)
	if err != nil {
		return time.Time{}, err
	}
	boundary := databaseTime(databaseNow)
	for _, candidate := range []time.Time{
		incident.OpenedAt, incident.LastSignalAt, incident.UpdatedAt,
		item.CreatedAt, item.StartedAt, item.CompletedAt, item.UpdatedAt,
		hypothesis.CreatedAt,
	} {
		if candidate.After(boundary) {
			boundary = candidate
		}
	}
	return boundary.UTC().Truncate(time.Microsecond), nil
}

func projectFeedbackHypothesis(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	request investigation.RecordFeedbackRequest,
	status domain.HypothesisStatus,
) error {
	result, err := tx.Exec(ctx, `
		UPDATE hypotheses AS hypothesis
		SET status = $6
		WHERE hypothesis.tenant_id = $1 AND hypothesis.workspace_id = $2
		  AND hypothesis.incident_id = $3 AND hypothesis.investigation_id = $4
		  AND hypothesis.id = $5 AND hypothesis.runtime_schema_version = $7
		  AND hypothesis.status = 'PROPOSED'
	`, tenantID, request.WorkspaceID, request.IncidentID, request.InvestigationID,
		request.HypothesisID, status, runtimeSchemaVersion)
	if err != nil {
		return databaseError("project feedback hypothesis", err)
	}
	if result.RowsAffected() != 1 {
		return investigation.ErrInvalidTransition
	}
	return nil
}

func readRuntimeFeedback(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, workspaceID, incidentID, investigationID, hypothesisID, feedbackID string,
) (domain.Feedback, error) {
	var feedback domain.Feedback
	var tenant, detailsHash string
	err := tx.QueryRow(ctx, `
		SELECT feedback.id::text, feedback.tenant_id::text, feedback.workspace_id::text,
		       feedback.incident_id::text, feedback.investigation_id::text,
		       feedback.hypothesis_id::text, feedback.actor_type, feedback.actor_id,
		       feedback.kind, feedback.details_document, feedback.details_hash,
		       feedback.created_at
		FROM feedback
		WHERE feedback.tenant_id = $1 AND feedback.workspace_id = $2
		  AND feedback.incident_id = $3 AND feedback.investigation_id = $4
		  AND feedback.hypothesis_id = $5 AND feedback.id = $6
		  AND feedback.runtime_schema_version = $7
		FOR SHARE OF feedback
	`, tenantID, workspaceID, incidentID, investigationID, hypothesisID, feedbackID, runtimeSchemaVersion).Scan(
		&feedback.ID, &tenant, &feedback.WorkspaceID, &feedback.IncidentID,
		&feedback.InvestigationID, &feedback.HypothesisID, &feedback.Actor.Type,
		&feedback.Actor.ID, &feedback.Verdict, &feedback.Details, &detailsHash,
		&feedback.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Feedback{}, store.ErrNotFound
	}
	if err != nil {
		return domain.Feedback{}, databaseError("read feedback", err)
	}
	if !validUUIDs(
		feedback.ID, tenant, feedback.WorkspaceID, feedback.IncidentID,
		feedback.InvestigationID, feedback.HypothesisID,
	) || detailsHash != snapshotSHA256Hex(feedback.Details) {
		return domain.Feedback{}, fmt.Errorf("decode feedback: %w", errDatabaseOperation)
	}
	feedback.Details = append([]byte(nil), feedback.Details...)
	feedback.CreatedAt = databaseTime(feedback.CreatedAt)
	if err := feedback.Validate(); err != nil {
		return domain.Feedback{}, fmt.Errorf("decode feedback: %w", errDatabaseOperation)
	}
	return feedback, nil
}
