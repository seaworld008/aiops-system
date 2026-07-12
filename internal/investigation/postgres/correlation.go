package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/store"
)

const (
	maximumCorrelationAttempts = 4
	incidentCreatedEventType   = "incident.created.v1"
)

type correlationRecord struct {
	incidentID     string
	correlationKey string
	mappingStatus  domain.MappingStatus
	serviceID      string
	environmentID  string
}

func (record correlationRecord) matches(request investigation.CorrelateSignalRequest) bool {
	return record.correlationKey == request.CorrelationKey &&
		record.mappingStatus == request.MappingStatus &&
		record.serviceID == request.ServiceID && record.environmentID == request.EnvironmentID
}

func (repository *Repository) CorrelateSignal(
	ctx context.Context,
	request investigation.CorrelateSignalRequest,
) (investigation.CorrelateSignalResult, error) {
	if ctx == nil {
		return investigation.CorrelateSignalResult{}, fmt.Errorf("%w: context is required", investigation.ErrInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return investigation.CorrelateSignalResult{}, err
	}
	if !validUUIDs(request.WorkspaceID, request.SignalID) ||
		!domain.ValidCorrelationKey(request.CorrelationKey) || !validCorrelationMapping(request) ||
		(request.ExpectedSignalHash != "" && !domain.ValidSHA256Hex(request.ExpectedSignalHash)) {
		return investigation.CorrelateSignalResult{}, fmt.Errorf("%w: invalid persistent signal correlation", investigation.ErrInvalidRequest)
	}

	var retryErr error
	for attempt := 0; attempt < maximumCorrelationAttempts; attempt++ {
		result, retry, err := repository.correlateSignalOnce(ctx, request)
		if !retry {
			return result, err
		}
		retryErr = err
		if err := ctx.Err(); err != nil {
			return investigation.CorrelateSignalResult{}, err
		}
	}
	return investigation.CorrelateSignalResult{}, databaseError("serialize signal correlation", retryErr)
}

func (repository *Repository) correlateSignalOnce(
	ctx context.Context,
	request investigation.CorrelateSignalRequest,
) (result investigation.CorrelateSignalResult, retry bool, returnedErr error) {
	tx, tenantID, err := beginWorkspace(ctx, repository, request.WorkspaceID)
	if err != nil {
		return result, false, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	var signalStatus string
	var observedAt time.Time
	if request.ExpectedSignalHash != "" {
		lockedSignal, lockErr := scanSignal(tx.QueryRow(ctx, `
			SELECT `+signalProjection+`
			FROM signals AS signal
			WHERE signal.tenant_id = $1 AND signal.workspace_id = $2 AND signal.id = $3
			FOR UPDATE OF signal
		`, tenantID, request.WorkspaceID, request.SignalID))
		err = lockErr
		if err == nil {
			actualHash, hashErr := investigation.RegisteredSignalSnapshotHash(investigation.RegisteredSignal{
				TenantID: tenantID, WorkspaceID: lockedSignal.WorkspaceID, Signal: lockedSignal,
			})
			if hashErr != nil || actualHash != request.ExpectedSignalHash {
				return result, false, store.ErrScopeViolation
			}
			signalStatus = lockedSignal.Status
			observedAt = lockedSignal.ObservedAt
		}
	} else {
		err = tx.QueryRow(ctx, `
			SELECT signal.status, signal.observed_at
			FROM signals AS signal
			WHERE signal.tenant_id = $1 AND signal.workspace_id = $2 AND signal.id = $3
			FOR UPDATE OF signal
		`, tenantID, request.WorkspaceID, request.SignalID).Scan(&signalStatus, &observedAt)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return result, false, store.ErrNotFound
	}
	if err != nil {
		return result, false, databaseError("lock signal for correlation", err)
	}
	if signalStatus != "firing" && signalStatus != "resolved" {
		return result, false, fmt.Errorf("lock signal for correlation: %w", errDatabaseOperation)
	}

	replay, found, err := readCorrelationReplay(ctx, tx, tenantID, request)
	if err != nil {
		return result, false, err
	}
	if found {
		if !replay.matches(request) {
			return result, false, store.ErrIdempotencyConflict
		}
		if replay.incidentID == "" && signalStatus != "resolved" {
			return result, false, fmt.Errorf("read durable signal correlation: %w", errDatabaseOperation)
		}
		if replay.incidentID != "" {
			incident, readErr := readCorrelationIncident(ctx, tx, tenantID, request.WorkspaceID, replay.incidentID)
			if readErr != nil {
				return result, false, readErr
			}
			if incident.CorrelationKey != replay.correlationKey || incident.MappingStatus != replay.mappingStatus ||
				incident.ServiceID != replay.serviceID || incident.EnvironmentID != replay.environmentID {
				return result, false, fmt.Errorf("read durable signal correlation: %w", errDatabaseOperation)
			}
			result = investigation.CorrelateSignalResult{Incident: incident, Associated: true}
		}
		if err := commit(ctx, tx, "commit signal correlation replay"); err != nil {
			return investigation.CorrelateSignalResult{}, retryableCorrelationError(err), err
		}
		committed = true
		return result, false, nil
	}

	active, activeFound, err := lockActiveCorrelationIncident(ctx, tx, tenantID, request.WorkspaceID, request.CorrelationKey)
	if err != nil {
		return result, false, err
	}
	if activeFound && (active.MappingStatus != request.MappingStatus || active.ServiceID != request.ServiceID ||
		active.EnvironmentID != request.EnvironmentID || active.CorrelationKey != request.CorrelationKey) {
		return result, false, store.ErrScopeViolation
	}

	if !activeFound && signalStatus == "resolved" {
		if err := insertSignalCorrelation(ctx, tx, tenantID, request, ""); err != nil {
			return result, retryableCorrelationError(err), mapCorrelationWriteError("persist resolved signal correlation tombstone", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return result, retryableCorrelationError(err), mapCorrelationWriteError("commit resolved signal correlation tombstone", err)
		}
		committed = true
		return result, false, nil
	}

	created := false
	if !activeFound {
		incidentID, idErr := repository.newUUID()
		if idErr != nil {
			return result, false, idErr
		}
		outboxID, idErr := repository.newUUID()
		if idErr != nil {
			return result, false, idErr
		}
		active, err = insertCorrelationIncident(ctx, tx, tenantID, request, incidentID, observedAt)
		if err != nil {
			return result, retryableCorrelationError(err), mapCorrelationWriteError("insert correlated incident", err)
		}
		if err := insertIncidentCreatedOutbox(ctx, tx, tenantID, request.WorkspaceID, outboxID, active); err != nil {
			return result, retryableCorrelationError(err), mapCorrelationWriteError("insert incident creation outbox event", err)
		}
		created = true
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO incident_signals (tenant_id, workspace_id, incident_id, signal_id)
		VALUES ($1, $2, $3, $4)
	`, tenantID, request.WorkspaceID, active.ID, request.SignalID); err != nil {
		return result, retryableCorrelationError(err), mapCorrelationWriteError("associate signal with incident", err)
	}
	if err := insertSignalCorrelation(ctx, tx, tenantID, request, active.ID); err != nil {
		return result, retryableCorrelationError(err), mapCorrelationWriteError("persist signal correlation", err)
	}
	if !created {
		active, err = updateCorrelationIncidentAggregate(ctx, tx, tenantID, request.WorkspaceID, active.ID, observedAt)
		if err != nil {
			return result, retryableCorrelationError(err), mapCorrelationWriteError("update correlated incident aggregate", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return result, retryableCorrelationError(err), mapCorrelationWriteError("commit signal correlation", err)
	}
	committed = true
	return investigation.CorrelateSignalResult{
		Incident: active, Created: created, Associated: true, Counted: true,
	}, false, nil
}

func readCorrelationReplay(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	request investigation.CorrelateSignalRequest,
) (correlationRecord, bool, error) {
	var record correlationRecord
	var incidentID, serviceID, environmentID pgtype.Text
	err := tx.QueryRow(ctx, `
		SELECT correlation.incident_id::text, correlation.correlation_key,
			correlation.mapping_status, correlation.service_id::text, correlation.environment_id::text
		FROM investigation_signal_correlations AS correlation
		WHERE correlation.tenant_id = $1 AND correlation.workspace_id = $2 AND correlation.signal_id = $3
	`, tenantID, request.WorkspaceID, request.SignalID).Scan(
		&incidentID, &record.correlationKey, &record.mappingStatus, &serviceID, &environmentID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return correlationRecord{}, false, nil
	}
	if err != nil {
		return correlationRecord{}, false, databaseError("read durable signal correlation", err)
	}
	if incidentID.Valid {
		record.incidentID = incidentID.String
	}
	if serviceID.Valid {
		record.serviceID = serviceID.String
	}
	if environmentID.Valid {
		record.environmentID = environmentID.String
	}
	if (record.incidentID != "" && !validUUID(record.incidentID)) || !validOptionalUUID(record.serviceID) ||
		!validOptionalUUID(record.environmentID) || !domain.ValidCorrelationKey(record.correlationKey) ||
		!validCorrelationMapping(investigation.CorrelateSignalRequest{
			MappingStatus: record.mappingStatus, ServiceID: record.serviceID, EnvironmentID: record.environmentID,
		}) {
		return correlationRecord{}, false, fmt.Errorf("read durable signal correlation: %w", errDatabaseOperation)
	}
	return record, true, nil
}

func lockActiveCorrelationIncident(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, workspaceID, correlationKey string,
) (domain.Incident, bool, error) {
	incident, err := scanIncident(tx.QueryRow(ctx, `
		SELECT `+incidentProjection+`
		FROM incidents AS incident
		WHERE incident.tenant_id = $1 AND incident.workspace_id = $2
		  AND incident.correlation_key = $3
		  AND incident.runtime_schema_version = $4
		  AND incident.status IN ('OPEN', 'INVESTIGATING', 'MITIGATING')
		ORDER BY incident.id
		LIMIT 1
		FOR NO KEY UPDATE OF incident
	`, tenantID, workspaceID, correlationKey, runtimeSchemaVersion))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Incident{}, false, nil
	}
	if err != nil {
		return domain.Incident{}, false, databaseError("lock active correlated incident", err)
	}
	return incident, true, nil
}

func readCorrelationIncident(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, workspaceID, incidentID string,
) (domain.Incident, error) {
	incident, err := scanIncident(tx.QueryRow(ctx, `
		SELECT `+incidentProjection+`
		FROM incidents AS incident
		WHERE incident.tenant_id = $1 AND incident.workspace_id = $2 AND incident.id = $3
		  AND incident.runtime_schema_version = $4
	`,
		tenantID, workspaceID, incidentID, runtimeSchemaVersion,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Incident{}, store.ErrNotFound
	}
	if err != nil {
		return domain.Incident{}, databaseError("read correlated incident", err)
	}
	return incident, nil
}

func insertCorrelationIncident(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	request investigation.CorrelateSignalRequest,
	incidentID string,
	observedAt time.Time,
) (domain.Incident, error) {
	return scanIncident(tx.QueryRow(ctx, `
		INSERT INTO incidents AS incident (
			id, tenant_id, workspace_id, service_id, environment_id,
			status, severity, title, opened_at, updated_at, version,
			correlation_key, mapping_status, last_signal_at, signal_count, runtime_schema_version
		) VALUES (
			$1, $2, $3, $4, $5, 'OPEN', 'UNKNOWN', 'Unclassified operational incident',
			$6, GREATEST(clock_timestamp(), $6::timestamptz), 1,
			$7, $8, $6, 1, $9
		)
		RETURNING `+incidentProjection,
		incidentID, tenantID, request.WorkspaceID, nullableCorrelationUUID(request.ServiceID),
		nullableCorrelationUUID(request.EnvironmentID), observedAt.UTC(), request.CorrelationKey,
		request.MappingStatus, runtimeSchemaVersion,
	))
}

func updateCorrelationIncidentAggregate(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, workspaceID, incidentID string,
	observedAt time.Time,
) (domain.Incident, error) {
	incident, err := scanIncident(tx.QueryRow(ctx, `
		UPDATE incidents AS incident
		SET opened_at = LEAST(incident.opened_at, $4::timestamptz),
			last_signal_at = GREATEST(incident.last_signal_at, $4::timestamptz),
			signal_count = incident.signal_count + 1,
			updated_at = GREATEST(incident.updated_at, $4::timestamptz, clock_timestamp()),
			version = incident.version + 1
		WHERE incident.tenant_id = $1 AND incident.workspace_id = $2 AND incident.id = $3
		  AND incident.runtime_schema_version = $5
		  AND incident.status IN ('OPEN', 'INVESTIGATING', 'MITIGATING')
		RETURNING `+incidentProjection,
		tenantID, workspaceID, incidentID, observedAt.UTC(), runtimeSchemaVersion,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Incident{}, store.ErrScopeViolation
	}
	return incident, err
}

func insertSignalCorrelation(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	request investigation.CorrelateSignalRequest,
	incidentID string,
) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO investigation_signal_correlations (
			tenant_id, workspace_id, signal_id, incident_id, correlation_key,
			mapping_status, service_id, environment_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, tenantID, request.WorkspaceID, request.SignalID, nullableCorrelationUUID(incidentID),
		request.CorrelationKey, request.MappingStatus, nullableCorrelationUUID(request.ServiceID),
		nullableCorrelationUUID(request.EnvironmentID))
	return err
}

func insertIncidentCreatedOutbox(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, workspaceID, outboxID string,
	incident domain.Incident,
) error {
	payload, err := json.Marshal(struct {
		IncidentID string `json:"incident_id"`
	}{IncidentID: incident.ID})
	if err != nil {
		return fmt.Errorf("encode incident creation outbox event: %w", err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO outbox_events (
			id, tenant_id, workspace_id, aggregate_type, aggregate_id, aggregate_version,
			event_type, payload, created_at, available_at
		) VALUES ($1, $2, $3, 'INCIDENT', $4, $5, $6, $7::jsonb,
			statement_timestamp(), statement_timestamp())
	`, outboxID, tenantID, workspaceID, incident.ID, incident.Version, incidentCreatedEventType, string(payload))
	return err
}

func validCorrelationMapping(request investigation.CorrelateSignalRequest) bool {
	if !validOptionalUUID(request.ServiceID) || !validOptionalUUID(request.EnvironmentID) {
		return false
	}
	switch request.MappingStatus {
	case domain.MappingExact:
		return request.ServiceID != "" && request.EnvironmentID != ""
	case domain.MappingAmbiguous, domain.MappingUnresolved:
		return true
	default:
		return false
	}
}

func nullableCorrelationUUID(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func retryableCorrelationError(err error) bool {
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) {
		return false
	}
	if postgresError.Code == "40001" || postgresError.Code == "40P01" {
		return true
	}
	return postgresError.Code == "23505" && postgresError.ConstraintName == "incidents_active_correlation_uk"
}

func mapCorrelationWriteError(operation string, err error) error {
	if retryableCorrelationError(err) {
		return err
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == "23505" &&
		(postgresError.ConstraintName == "incidents_pkey" || postgresError.ConstraintName == "outbox_events_pkey") {
		return fmt.Errorf("%w: ID factory returned a duplicate persistent resource ID", investigation.ErrInvalidRequest)
	}
	return databaseError(operation, err)
}
