package postgres

import (
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
)

type rowScanner interface {
	Scan(...any) error
}

// Projection constants deliberately name their table aliases. Mutating paths
// can use the same strict scanners through SELECT/RETURNING subqueries without
// allowing column-order drift between repository operations.
const signalProjection = `
	signal.id::text,
	signal.tenant_id::text,
	signal.workspace_id::text,
	signal.integration_id::text,
	signal.provider,
	signal.provider_event_id,
	signal.payload_hash,
	signal.fingerprint,
	signal.status,
	COALESCE(signal.payload_summary -> 'labels', '{}'::jsonb),
	signal.observed_at`

const incidentProjection = `
	incident.id::text,
	incident.tenant_id::text,
	incident.workspace_id::text,
	incident.service_id::text,
	incident.environment_id::text,
	incident.correlation_key,
	incident.mapping_status,
	incident.severity,
	incident.title,
	incident.status,
	incident.confirmed_hypothesis_id::text,
	incident.opened_at,
	incident.last_signal_at,
	incident.updated_at,
	incident.signal_count,
	incident.version`

const investigationProjection = `
	investigation.id::text,
	investigation.tenant_id::text,
	investigation.workspace_id::text,
	investigation.incident_id::text,
	investigation.status,
	investigation.model_status,
	investigation.idempotency_key,
	investigation.request_hash,
	investigation.request_hash_version,
	investigation.plan_schema_version,
	investigation.plan_manifest_digest,
	investigation.plan_registry_digest,
	investigation.plan_profile_digest,
	investigation.plan_tasks_hash,
	COALESCE(investigation.failure_code, ''),
	COALESCE(investigation.model_failure_code, ''),
	investigation.created_at,
	investigation.started_at,
	investigation.completed_at,
	investigation.updated_at`

const taskProjection = `
	task.id::text,
	task.tenant_id::text,
	task.workspace_id::text,
	task.incident_id::text,
	task.investigation_id::text,
	task.task_key,
	task.position,
	task.tool_name,
	task.tool_version,
	task.input_document,
	task.input_hash,
	task.read_runtime_schema_version,
	task.connector_digest,
	task.target_digest,
	task.executor_digest,
	task.runtime_digest,
	task.runtime_bound_at,
	task.status,
	task.evidence_id::text,
	COALESCE(task.failure_code, ''),
	task.created_at,
	task.started_at,
	task.completed_at,
	task.updated_at`

const evidenceProjection = `
	evidence_fact.id::text,
	evidence_fact.tenant_id::text,
	evidence_fact.workspace_id::text,
	evidence_fact.incident_id::text,
	evidence_fact.investigation_id::text,
	evidence_fact.task_id::text,
	evidence_fact.connector,
	evidence_fact.content_hash,
	evidence_fact.payload_document,
	evidence_fact.attributes,
	evidence_fact.collected_at,
	evidence_fact.created_at`

const hypothesisProjection = `
	hypothesis.id::text,
	hypothesis.tenant_id::text,
	hypothesis.workspace_id::text,
	hypothesis.incident_id::text,
	hypothesis.investigation_id::text,
	hypothesis.status,
	hypothesis.rank,
	hypothesis.confidence,
	hypothesis.confidence_band,
	hypothesis.summary,
	hypothesis.proposal_document,
	hypothesis.proposal_hash,
	hypothesis.unknowns,
	ARRAY(
		SELECT link.evidence_id::text
		FROM hypothesis_evidence AS link
		WHERE link.tenant_id = hypothesis.tenant_id
		  AND link.workspace_id = hypothesis.workspace_id
		  AND link.investigation_id = hypothesis.investigation_id
		  AND link.hypothesis_id = hypothesis.id
		  AND link.runtime_schema_version = 'investigation-runtime.v1'
		ORDER BY link.position, link.evidence_id
	),
	hypothesis.created_at`

func scanSignal(row rowScanner) (domain.Signal, error) {
	registered, err := scanRegisteredSignal(row)
	if err != nil {
		return domain.Signal{}, err
	}
	return registered.Signal, nil
}

func scanRegisteredSignal(row rowScanner) (investigation.RegisteredSignal, error) {
	var (
		signal      domain.Signal
		tenantID    string
		labelsBytes []byte
	)
	if err := row.Scan(
		&signal.ID,
		&tenantID,
		&signal.WorkspaceID,
		&signal.IntegrationID,
		&signal.Provider,
		&signal.ProviderEventID,
		&signal.PayloadHash,
		&signal.Fingerprint,
		&signal.Status,
		&labelsBytes,
		&signal.ObservedAt,
	); err != nil {
		return investigation.RegisteredSignal{}, err
	}
	if !validUUIDs(signal.ID, tenantID, signal.WorkspaceID, signal.IntegrationID) {
		return investigation.RegisteredSignal{}, invalidPersistedData("signal")
	}
	if err := json.Unmarshal(labelsBytes, &signal.Labels); err != nil || signal.Labels == nil {
		return investigation.RegisteredSignal{}, invalidPersistedData("signal")
	}
	signal.ObservedAt = databaseTime(signal.ObservedAt)
	normalized, err := investigation.NormalizeSignalForReplay(signal)
	if err != nil {
		return investigation.RegisteredSignal{}, invalidPersistedData("signal")
	}
	return investigation.RegisteredSignal{
		TenantID: tenantID, WorkspaceID: normalized.WorkspaceID, Signal: normalized,
	}, nil
}

func scanIncident(row rowScanner) (domain.Incident, error) {
	var (
		incident              domain.Incident
		serviceID             pgtype.Text
		environmentID         pgtype.Text
		confirmedHypothesisID pgtype.Text
	)
	if err := row.Scan(
		&incident.ID,
		&incident.TenantID,
		&incident.WorkspaceID,
		&serviceID,
		&environmentID,
		&incident.CorrelationKey,
		&incident.MappingStatus,
		&incident.Severity,
		&incident.Title,
		&incident.Status,
		&confirmedHypothesisID,
		&incident.OpenedAt,
		&incident.LastSignalAt,
		&incident.UpdatedAt,
		&incident.SignalCount,
		&incident.Version,
	); err != nil {
		return domain.Incident{}, err
	}
	var err error
	if incident.ServiceID, err = optionalUUIDText(serviceID); err != nil {
		return domain.Incident{}, invalidPersistedData("incident")
	}
	if incident.EnvironmentID, err = optionalUUIDText(environmentID); err != nil {
		return domain.Incident{}, invalidPersistedData("incident")
	}
	if incident.ConfirmedHypothesisID, err = optionalUUIDText(confirmedHypothesisID); err != nil {
		return domain.Incident{}, invalidPersistedData("incident")
	}
	if !validUUIDs(incident.ID, incident.TenantID, incident.WorkspaceID) {
		return domain.Incident{}, invalidPersistedData("incident")
	}
	incident.OpenedAt = databaseTime(incident.OpenedAt)
	incident.LastSignalAt = databaseTime(incident.LastSignalAt)
	incident.UpdatedAt = databaseTime(incident.UpdatedAt)
	if err := incident.Validate(); err != nil {
		return domain.Incident{}, invalidPersistedData("incident")
	}
	return incident, nil
}

func scanInvestigation(row rowScanner) (domain.Investigation, error) {
	var (
		item               domain.Investigation
		tenantID           string
		planSchemaVersion  pgtype.Text
		planManifestDigest pgtype.Text
		planRegistryDigest pgtype.Text
		planProfileDigest  pgtype.Text
		planTasksHash      pgtype.Text
		startedAt          pgtype.Timestamptz
		completedAt        pgtype.Timestamptz
	)
	if err := row.Scan(
		&item.ID,
		&tenantID,
		&item.WorkspaceID,
		&item.IncidentID,
		&item.Status,
		&item.ModelStatus,
		&item.IdempotencyKey,
		&item.RequestHash,
		&item.RequestHashVersion,
		&planSchemaVersion,
		&planManifestDigest,
		&planRegistryDigest,
		&planProfileDigest,
		&planTasksHash,
		&item.FailureCode,
		&item.ModelFailureCode,
		&item.CreatedAt,
		&startedAt,
		&completedAt,
		&item.UpdatedAt,
	); err != nil {
		return domain.Investigation{}, err
	}
	if !validUUIDs(item.ID, tenantID, item.WorkspaceID, item.IncidentID) {
		return domain.Investigation{}, invalidPersistedData("investigation")
	}
	planFields := []pgtype.Text{planSchemaVersion, planManifestDigest, planRegistryDigest, planProfileDigest, planTasksHash}
	planPresent := planFields[0].Valid
	for _, field := range planFields[1:] {
		if field.Valid != planPresent {
			return domain.Investigation{}, invalidPersistedData("investigation")
		}
	}
	if planPresent {
		item.PlanBinding = domain.InvestigationPlanBinding{
			SchemaVersion: planSchemaVersion.String, ManifestDigest: planManifestDigest.String,
			RegistryDigest: planRegistryDigest.String, ProfileDigest: planProfileDigest.String,
			TasksHash: planTasksHash.String,
		}
	}
	item.CreatedAt = databaseTime(item.CreatedAt)
	item.StartedAt = optionalDatabaseTimestamp(startedAt)
	item.CompletedAt = optionalDatabaseTimestamp(completedAt)
	item.UpdatedAt = databaseTime(item.UpdatedAt)
	if err := item.Validate(); err != nil {
		return domain.Investigation{}, invalidPersistedData("investigation")
	}
	return item, nil
}

func scanTask(row rowScanner) (domain.ReadTask, error) {
	var (
		task            domain.ReadTask
		tenantID        string
		evidenceID      pgtype.Text
		runtimeSchema   pgtype.Text
		connectorDigest pgtype.Text
		targetDigest    pgtype.Text
		executorDigest  pgtype.Text
		runtimeDigest   pgtype.Text
		runtimeBoundAt  pgtype.Timestamptz
		startedAt       pgtype.Timestamptz
		completed       pgtype.Timestamptz
	)
	if err := row.Scan(
		&task.ID,
		&tenantID,
		&task.WorkspaceID,
		&task.IncidentID,
		&task.InvestigationID,
		&task.Key,
		&task.Position,
		&task.ConnectorID,
		&task.Operation,
		&task.Input,
		&task.InputHash,
		&runtimeSchema,
		&connectorDigest,
		&targetDigest,
		&executorDigest,
		&runtimeDigest,
		&runtimeBoundAt,
		&task.Status,
		&evidenceID,
		&task.FailureCode,
		&task.CreatedAt,
		&startedAt,
		&completed,
		&task.UpdatedAt,
	); err != nil {
		return domain.ReadTask{}, err
	}
	var err error
	if task.EvidenceID, err = optionalUUIDText(evidenceID); err != nil {
		return domain.ReadTask{}, invalidPersistedData("read task")
	}
	if !validUUIDs(task.ID, tenantID, task.WorkspaceID, task.IncidentID, task.InvestigationID) {
		return domain.ReadTask{}, invalidPersistedData("read task")
	}
	runtimeTextFields := []pgtype.Text{runtimeSchema, connectorDigest, targetDigest, executorDigest, runtimeDigest}
	runtimePresent := runtimeTextFields[0].Valid
	for _, field := range runtimeTextFields[1:] {
		if field.Valid != runtimePresent {
			return domain.ReadTask{}, invalidPersistedData("read task")
		}
	}
	if runtimeBoundAt.Valid != runtimePresent {
		return domain.ReadTask{}, invalidPersistedData("read task")
	}
	if runtimePresent {
		task.RuntimeBinding = domain.ReadTaskRuntimeBinding{
			SchemaVersion: runtimeSchema.String, ConnectorDigest: connectorDigest.String,
			TargetDigest: targetDigest.String, ExecutorDigest: executorDigest.String,
			RuntimeDigest: runtimeDigest.String, BoundAt: databaseTime(runtimeBoundAt.Time),
		}
	}
	task.Input = append([]byte(nil), task.Input...)
	task.CreatedAt = databaseTime(task.CreatedAt)
	task.StartedAt = optionalDatabaseTimestamp(startedAt)
	task.CompletedAt = optionalDatabaseTimestamp(completed)
	task.UpdatedAt = databaseTime(task.UpdatedAt)
	if err := task.Validate(); err != nil {
		return domain.ReadTask{}, invalidPersistedData("read task")
	}
	return task, nil
}

func scanEvidence(row rowScanner) (domain.Evidence, error) {
	var (
		evidence        domain.Evidence
		tenantID        string
		attributesBytes []byte
	)
	if err := row.Scan(
		&evidence.ID,
		&tenantID,
		&evidence.WorkspaceID,
		&evidence.IncidentID,
		&evidence.InvestigationID,
		&evidence.TaskID,
		&evidence.ConnectorID,
		&evidence.ContentHash,
		&evidence.Payload,
		&attributesBytes,
		&evidence.CollectedAt,
		&evidence.CreatedAt,
	); err != nil {
		return domain.Evidence{}, err
	}
	if !validUUIDs(
		evidence.ID,
		tenantID,
		evidence.WorkspaceID,
		evidence.IncidentID,
		evidence.InvestigationID,
		evidence.TaskID,
	) {
		return domain.Evidence{}, invalidPersistedData("evidence")
	}
	if err := json.Unmarshal(attributesBytes, &evidence.Attributes); err != nil || evidence.Attributes == nil {
		return domain.Evidence{}, invalidPersistedData("evidence")
	}
	evidence.Payload = append([]byte(nil), evidence.Payload...)
	evidence.CollectedAt = databaseTime(evidence.CollectedAt)
	evidence.CreatedAt = databaseTime(evidence.CreatedAt)
	if err := evidence.Validate(); err != nil {
		return domain.Evidence{}, invalidPersistedData("evidence")
	}
	return evidence, nil
}

func scanHypothesis(row rowScanner) (domain.Hypothesis, error) {
	var (
		hypothesis     domain.Hypothesis
		tenantID       string
		confidenceBand string
	)
	if err := row.Scan(
		&hypothesis.ID,
		&tenantID,
		&hypothesis.WorkspaceID,
		&hypothesis.IncidentID,
		&hypothesis.InvestigationID,
		&hypothesis.Status,
		&hypothesis.Rank,
		&hypothesis.Confidence,
		&confidenceBand,
		&hypothesis.Summary,
		&hypothesis.Proposal,
		&hypothesis.ProposalHash,
		&hypothesis.Unknowns,
		&hypothesis.EvidenceIDs,
		&hypothesis.CreatedAt,
	); err != nil {
		return domain.Hypothesis{}, err
	}
	if !validUUIDs(hypothesis.ID, tenantID, hypothesis.WorkspaceID, hypothesis.IncidentID, hypothesis.InvestigationID) {
		return domain.Hypothesis{}, invalidPersistedData("hypothesis")
	}
	for _, evidenceID := range hypothesis.EvidenceIDs {
		if !validUUID(evidenceID) {
			return domain.Hypothesis{}, invalidPersistedData("hypothesis")
		}
	}
	if confidenceBand != expectedConfidenceBand(hypothesis.Confidence) {
		return domain.Hypothesis{}, invalidPersistedData("hypothesis")
	}
	hypothesis.Proposal = append([]byte(nil), hypothesis.Proposal...)
	hypothesis.Unknowns = append([]string{}, hypothesis.Unknowns...)
	hypothesis.EvidenceIDs = append([]string(nil), hypothesis.EvidenceIDs...)
	hypothesis.CreatedAt = databaseTime(hypothesis.CreatedAt)
	if err := hypothesis.Validate(); err != nil {
		return domain.Hypothesis{}, invalidPersistedData("hypothesis")
	}
	return hypothesis, nil
}

func expectedConfidenceBand(confidence float64) string {
	if math.IsNaN(confidence) || math.IsInf(confidence, 0) || confidence < 0 || confidence > 1 {
		return ""
	}
	if confidence < 0.5 {
		return "LOW"
	}
	if confidence < 0.8 {
		return "MEDIUM"
	}
	return "HIGH"
}

func databaseTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Time{}
	}
	return value.Round(0).UTC()
}

func optionalDatabaseTimestamp(value pgtype.Timestamptz) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return databaseTime(value.Time)
}

func invalidPersistedData(resource string) error {
	return fmt.Errorf("decode %s: %w", resource, errDatabaseOperation)
}
