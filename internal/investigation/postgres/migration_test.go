package postgres_test

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestInvestigationRuntimeUsesMigrationTenWithAtomicUpAndDown(t *testing.T) {
	gateway := readMigration(t, "000009_runner_gateway_mtls.up.sql")
	if !strings.Contains(gateway, "Runner Gateway") {
		t.Fatal("000009 must remain assigned to Runner Gateway/mTLS")
	}
	for _, name := range []string{
		"000010_investigation_runtime.up.sql",
		"000010_investigation_runtime.down.sql",
	} {
		migration := strings.TrimSpace(readMigration(t, name))
		if !strings.HasPrefix(migration, "BEGIN;") || !strings.HasSuffix(migration, "COMMIT;") {
			t.Fatalf("%s must be transactionally wrapped in BEGIN/COMMIT", name)
		}
	}
	up := normalizedMigration(t, "000010_investigation_runtime.up.sql")
	down := normalizedMigration(t, "000010_investigation_runtime.down.sql")
	for name, migration := range map[string]string{"up": up, "down": down} {
		if !strings.Contains(migration, "set local lock_timeout = '5s'") {
			t.Errorf("000010 %s migration must bound cutover lock acquisition", name)
		}
		if !strings.Contains(migration, "runner_scope_bindings, runner_registrations, runner_certificates, environments, services, signals, workspaces in access exclusive mode") {
			t.Errorf("000010 %s migration must deterministically pre-lock every existing dependency", name)
		}
	}
}

func TestInvestigationRuntimeMigrationPersistsScopedSignalCorrelation(t *testing.T) {
	up := normalizedMigration(t, "000010_investigation_runtime.up.sql")
	for _, required := range []string{
		"alter table incidents",
		"add column correlation_key text",
		"add column mapping_status text",
		"add column last_signal_at timestamptz",
		"add column signal_count integer",
		"add column runtime_schema_version text",
		"create unique index incidents_active_correlation_uk",
		"where runtime_schema_version = 'investigation-runtime.v1' and status in ('open', 'investigating', 'mitigating')",
		"create table investigation_signal_correlations",
		"primary key (tenant_id, workspace_id, signal_id)",
		"foreign key (tenant_id, workspace_id, signal_id) references signals (tenant_id, workspace_id, id)",
		"foreign key (tenant_id, workspace_id, incident_id) references incidents (tenant_id, workspace_id, id)",
		"create unique index incident_signals_single_incident_per_signal_uk",
		"constraint incident_signals_runtime_exact_association_uk unique (tenant_id, workspace_id, incident_id, signal_id)",
		"foreign key (tenant_id, workspace_id, incident_id, signal_id) references incident_signals (tenant_id, workspace_id, incident_id, signal_id) on delete restrict",
		"before update or delete on investigation_signal_correlations",
		"before truncate on investigation_signal_correlations",
		"resolved signal without an active incident requires a durable no-op tombstone",
		"incident.status in ('open', 'investigating', 'mitigating')",
		"for no key update of incident",
		"create constraint trigger incidents_runtime_signal_projection_guard",
		"create constraint trigger incident_signals_runtime_projection_guard",
		"create constraint trigger investigation_signal_correlations_runtime_projection_guard",
		"runtime incident signal aggregate does not match its durable correlation set",
		"max(signal.observed_at)",
		"create trigger signals_investigation_correlation_guard before update or delete on signals",
		"create trigger signals_investigation_correlation_no_truncate before truncate on signals",
		"signals referenced by investigation correlations are immutable",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("000010 up migration missing %q", required)
		}
	}
}

func TestInvestigationRuntimeMigrationConstrainsInvestigationLifecycle(t *testing.T) {
	up := normalizedMigration(t, "000010_investigation_runtime.up.sql")
	for _, required := range []string{
		"alter table investigations",
		"add column model_status text",
		"add column idempotency_key text",
		"add column request_hash text",
		"add column request_hash_version text",
		"add column failure_code text",
		"add column model_failure_code text",
		"add column started_at timestamptz",
		"add column updated_at timestamptz",
		"add column service_id_snapshot uuid",
		"add column environment_id_snapshot uuid",
		"add column mapping_status_snapshot text",
		"constraint investigations_runtime_lifecycle_ck check",
		"status = 'queued' and model_status = 'pending'",
		"status = 'running' and model_status in ('pending', 'running')",
		"status in ('partial', 'completed') and model_status in ('completed', 'failed', 'skipped')",
		"status in ('failed', 'cancelled') and model_status = 'cancelled'",
		"create unique index investigations_single_active_incident_uk",
		"where runtime_schema_version = 'investigation-runtime.v1' and status in ('queued', 'running')",
		"request_hash_version = 'investigation.create.v1'",
		"foreign key (tenant_id, workspace_id, service_id_snapshot) references services (tenant_id, workspace_id, id)",
		"foreign key (tenant_id, workspace_id, environment_id_snapshot) references environments (tenant_id, workspace_id, id)",
		"runtime investigation must commit atomically with between one and twelve read tasks",
		"window_start > '-infinity'::timestamptz and window_start < 'infinity'::timestamptz",
		"window_end > '-infinity'::timestamptz and window_end < 'infinity'::timestamptz",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("000010 up migration missing %q", required)
		}
	}
}

func TestInvestigationRuntimeMigrationStoresReadTasksAndRawEvidenceByHash(t *testing.T) {
	up := normalizedMigration(t, "000010_investigation_runtime.up.sql")
	for _, required := range []string{
		"alter table tool_invocations alter column started_at drop not null",
		"runtime_schema_version is null and incident_id is null and task_key is null and position is null and input_document is null and evidence_id is null and failure_code is null and created_at is null and updated_at is null and started_at is not null",
		"add column incident_id uuid",
		"add column task_key text",
		"add column position smallint",
		"add column input_document bytea",
		"add column evidence_id uuid",
		"constraint tool_invocations_runtime_lifecycle_ck check",
		"encode(sha256(input_document), 'hex') = input_hash",
		"create unique index tool_invocations_runtime_task_key_uk",
		"create unique index tool_invocations_runtime_position_uk",
		"alter table evidence",
		"add column task_id uuid",
		"add column payload_document bytea",
		"add column attributes jsonb",
		"encode(sha256(payload_document), 'hex') = content_hash",
		"create unique index evidence_runtime_task_uk",
		"foreign key (tenant_id, workspace_id, investigation_id, task_id, connector) references tool_invocations (tenant_id, workspace_id, investigation_id, id, tool_name)",
		"raw_ref is null",
		"create trigger evidence_runtime_insert_guard before insert on evidence",
		"runtime evidence can only be admitted while its parent and read task are active",
		"for share of task",
		"for no key update of parent",
		"create constraint trigger evidence_runtime_task_projection_guard",
		"runtime evidence must be exactly projected by its terminal read task",
		"create trigger evidence_runtime_immutable before update or delete on evidence",
		"create trigger evidence_runtime_no_truncate before truncate on evidence",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("000010 up migration missing %q", required)
		}
	}
	taskLock := strings.Index(up, "for share of task")
	parentLock := strings.Index(up, "for no key update of parent")
	if taskLock < 0 || parentLock < 0 || taskLock >= parentLock {
		t.Fatal("runtime evidence admission must lock its read task before its parent investigation")
	}
	if strings.Contains(up, "payload_document text") || strings.Contains(up, "input_document text") {
		t.Fatal("raw hashed JSON facts must be bytea, not text/JSONB rewrites")
	}
}

func TestInvestigationRuntimeMigrationPersistsRankedHypothesesAndHumanFeedback(t *testing.T) {
	up := normalizedMigration(t, "000010_investigation_runtime.up.sql")
	for _, required := range []string{
		"alter table hypotheses",
		"add column confidence double precision",
		"add column proposal_document bytea",
		"add column proposal_hash text",
		"add column unknowns text[]",
		"encode(sha256(proposal_document), 'hex') = proposal_hash",
		"create unique index hypotheses_runtime_rank_uk",
		"before insert or update on hypotheses",
		"runtime hypothesis must be inserted as proposed while its investigation is running",
		"parent_model_status <> 'running'",
		"constraint hypotheses_runtime_marker_scope_uk unique (tenant_id, workspace_id, incident_id, investigation_id, id, runtime_schema_version)",
		"constraint hypotheses_runtime_confirmation_marker_uk unique (tenant_id, workspace_id, incident_id, status, id, runtime_schema_version)",
		"alter table hypothesis_evidence",
		"add column position smallint",
		"create unique index hypothesis_evidence_runtime_position_uk",
		"create trigger hypothesis_evidence_runtime_insert_guard before insert on hypothesis_evidence",
		"runtime hypothesis evidence can only be added while its investigation is running",
		"select 1 from hypothesis_evidence where runtime_schema_version = 'investigation-runtime.v1'",
		"alter table feedback drop constraint feedback_kind_check",
		"drop constraint feedback_check",
		"add column incident_id uuid",
		"add column actor_type text",
		"add column details_document bytea",
		"add column details_hash text",
		"kind in ( 'helpful', 'not_helpful', 'confirm', 'reject', 'correct', 'confirmed', 'rejected', 'inconclusive' )",
		"actor_type = 'human'",
		"runtime_schema_version is null and incident_id is null and actor_type is null and details_document is null and details_hash is null and kind in ('helpful', 'not_helpful', 'confirm', 'reject', 'correct')",
		"constraint feedback_runtime_hypothesis_marker_fk foreign key (tenant_id, workspace_id, incident_id, investigation_id, hypothesis_id, runtime_schema_version)",
		"encode(sha256(details_document), 'hex') = details_hash",
		"before update or delete on feedback",
		"before truncate on feedback",
		"select 1 from feedback where runtime_schema_version = 'investigation-runtime.v1'",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("000010 up migration missing %q", required)
		}
	}
}

func TestInvestigationRuntimeMigrationOwnsWorkspaceIdempotencyAndAuthenticatedReceipts(t *testing.T) {
	up := normalizedMigration(t, "000010_investigation_runtime.up.sql")
	for _, required := range []string{
		"create table investigation_idempotency_records",
		"primary key (workspace_id, idempotency_key)",
		"operation in ( 'create_investigation', 'complete_task', 'start_model', 'finalize_investigation', 'fail_investigation', 'record_feedback' )",
		"octet_length(result_snapshot) between 2 and 8388608",
		"encode(sha256(result_snapshot), 'hex') = result_snapshot_sha256",
		"before update or delete on investigation_idempotency_records",
		"before truncate on investigation_idempotency_records",
		"create table runner_evidence_receipts",
		"environment_id uuid not null",
		"scope_revision bigint not null",
		"certificate_sha256 text not null",
		"foreign key (tenant_id, runner_id) references runner_registrations (tenant_id, runner_id)",
		"foreign key (runner_id, certificate_sha256) references runner_certificates (runner_id, certificate_sha256)",
		"create unique index runner_evidence_receipts_task_uk",
		"registration.enabled = true",
		"registration.runner_pool = 'read'",
		"registration.scope_revision = new.scope_revision",
		"binding.workspace_id = new.workspace_id",
		"binding.environment_id = new.environment_id",
		"certificate.status = 'active'",
		"certificate.not_before <= new.received_at",
		"certificate.not_after > new.received_at",
		"before update or delete on runner_evidence_receipts",
		"before truncate on runner_evidence_receipts",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("000010 up migration missing %q", required)
		}
	}
	receiptGuardStart := strings.Index(up, "create or replace function validate_runner_evidence_receipt_insert")
	receiptGuardEnd := strings.Index(up, "create trigger runner_evidence_receipts_insert_guard")
	if receiptGuardStart < 0 || receiptGuardEnd <= receiptGuardStart {
		t.Fatal("cannot locate runner evidence receipt guard")
	}
	receiptGuard := up[receiptGuardStart:receiptGuardEnd]
	bindingLock := strings.Index(receiptGuard, "from runner_scope_bindings as binding")
	registrationLock := strings.Index(receiptGuard, "from runner_registrations as registration")
	if bindingLock < 0 || registrationLock < 0 || bindingLock >= registrationLock {
		t.Fatal("runner evidence receipt guard must lock scope binding before registration")
	}
}

func TestInvestigationRuntimeChecksCannotPassThroughSQLNull(t *testing.T) {
	up := normalizedMigration(t, "000010_investigation_runtime.up.sql")
	for _, required := range []string{
		"correlation_key is not null and mapping_status is not null and last_signal_at is not null and signal_count is not null",
		"model_status is not null and idempotency_key is not null and request_hash is not null and request_hash_version is not null",
		"updated_at is not null and mapping_status_snapshot is not null",
		"completed_at is null or started_at is null or completed_at >= started_at",
		"task_key is not null and position is not null and input_document is not null and created_at is not null and updated_at is not null",
		"incident_id is not null and task_id is not null and payload_document is not null and attributes is not null",
		"confidence is not null and proposal_document is not null and proposal_hash is not null and unknowns is not null",
		"confidence < 0.5 and confidence_band = 'low'",
		"confidence >= 0.5 and confidence < 0.8 and confidence_band = 'medium'",
		"confidence >= 0.8 and confidence_band = 'high'",
		"position is not null and position between 1 and 64",
		"actor_type is not null and details_document is not null and details_hash is not null",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("000010 runtime CHECK remains NULL-bypassable; missing %q", required)
		}
	}
}

func TestInvestigationRuntimeDownMigrationRefusesDataLossAndRestoresLegacyShape(t *testing.T) {
	down := normalizedMigration(t, "000010_investigation_runtime.down.sql")
	for _, required := range []string{
		"lock table incidents, incident_signals, investigations, tool_invocations, evidence, hypotheses, hypothesis_evidence, feedback, investigation_signal_correlations, investigation_idempotency_records, runner_evidence_receipts",
		"errcode = '55000'",
		"message = 'unsafe investigation runtime rollback: m5 runtime state remains'",
		"select 1 from runner_evidence_receipts",
		"select 1 from investigation_idempotency_records",
		"select 1 from investigation_signal_correlations",
		"runtime_schema_version = 'investigation-runtime.v1'",
		"drop table runner_evidence_receipts",
		"drop table investigation_idempotency_records",
		"drop table investigation_signal_correlations",
		"alter table incident_signals drop constraint incident_signals_runtime_exact_association_uk",
		"drop trigger evidence_runtime_no_truncate on evidence",
		"drop trigger evidence_runtime_immutable on evidence",
		"drop trigger evidence_runtime_task_projection_guard on evidence",
		"drop trigger evidence_runtime_insert_guard on evidence",
		"drop function reject_evidence_runtime_mutation()",
		"drop function validate_runtime_evidence_task_projection()",
		"drop function validate_runtime_evidence_insert()",
		"drop trigger tool_invocations_runtime_parent_guard on tool_invocations",
		"drop function validate_tool_invocation_runtime_parent_lifecycle()",
		"drop trigger tool_invocations_runtime_no_truncate on tool_invocations",
		"drop trigger tool_invocations_runtime_no_delete on tool_invocations",
		"drop function reject_tool_invocation_runtime_removal()",
		"drop trigger hypothesis_evidence_runtime_insert_guard on hypothesis_evidence",
		"drop function validate_runtime_hypothesis_evidence_insert()",
		"drop constraint feedback_runtime_hypothesis_marker_fk",
		"drop constraint incidents_runtime_confirmed_hypothesis_fk",
		"drop constraint hypotheses_runtime_marker_scope_uk",
		"drop constraint hypotheses_runtime_confirmation_marker_uk",
		"drop trigger incidents_runtime_signal_projection_guard on incidents",
		"drop trigger incident_signals_runtime_projection_guard on incident_signals",
		"drop trigger investigation_signal_correlations_runtime_projection_guard on investigation_signal_correlations",
		"drop trigger signals_investigation_correlation_guard on signals",
		"drop trigger signals_investigation_correlation_no_truncate on signals",
		"drop function reject_correlated_signal_mutation()",
		"drop function validate_runtime_incident_signal_projection()",
		"drop trigger hypotheses_runtime_parent_set_guard on hypotheses",
		"drop trigger investigations_runtime_hypothesis_set_guard on investigations",
		"drop function investigation_runtime_hypothesis_set_valid(uuid, uuid, uuid)",
		"alter table tool_invocations alter column started_at set not null",
		"add constraint feedback_kind_check check (kind in ('helpful', 'not_helpful', 'confirm', 'reject', 'correct'))",
		"add constraint feedback_check check (kind not in ('confirm', 'reject', 'correct') or hypothesis_id is not null)",
		"drop function investigation_json_object_document_valid(bytea, integer)",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("000010 down migration missing %q", required)
		}
	}
}

func TestInvestigationRuntimeMigrationFreezesOwnershipAndBindsTerminalProofs(t *testing.T) {
	up := normalizedMigration(t, "000010_investigation_runtime.up.sql")
	for _, required := range []string{
		"create trigger incidents_runtime_mutation_guard before insert or update on incidents",
		"runtime incident must start open at version one without a confirmed root cause",
		"legacy rows cannot be promoted to investigation runtime by update",
		"old.correlation_key is distinct from new.correlation_key",
		"old.mapping_status is distinct from new.mapping_status",
		"old.service_id is distinct from new.service_id",
		"old.environment_id is distinct from new.environment_id",
		"new.signal_count < old.signal_count",
		"old is distinct from new and new.version <> old.version + 1",
		"create trigger investigations_runtime_transition_guard before insert or update on investigations",
		"if tg_op = 'insert' then select parent.* into incident",
		"incident.service_id is distinct from new.service_id_snapshot",
		"incident.environment_id is distinct from new.environment_id_snapshot",
		"incident.mapping_status is distinct from new.mapping_status_snapshot",
		"terminal investigation state is immutable",
		"create trigger tool_invocations_runtime_mutation_guard before update on tool_invocations",
		"terminal read task state is immutable",
		"create constraint trigger tool_invocations_runtime_parent_guard",
		"runtime read task state is incompatible with its parent investigation lifecycle",
		"runtime read tasks can only be inserted queued while the parent investigation is queued",
		"create trigger tool_invocations_runtime_no_delete before delete on tool_invocations",
		"create trigger tool_invocations_runtime_no_truncate before truncate on tool_invocations",
		"runtime read tasks are durable and cannot be removed",
		"runtime investigation must commit atomically with between one and twelve read tasks",
		"completed_at is null or started_at is null or completed_at >= started_at",
		"old.model_status = 'pending' and new.model_status = 'running'",
		"model cannot start before every runtime read task is terminal",
		"constraint hypotheses_runtime_exact_scope_uk unique (tenant_id, workspace_id, incident_id, investigation_id, id)",
		"create unique index hypotheses_runtime_confirmed_incident_uk",
		"where runtime_schema_version = 'investigation-runtime.v1' and status = 'confirmed'",
		"constraint feedback_runtime_hypothesis_marker_fk foreign key (tenant_id, workspace_id, incident_id, investigation_id, hypothesis_id, runtime_schema_version)",
		"truncated = false",
		"task.status = 'evidence'",
		"task.evidence_id = new.evidence_id",
		"task.output_hash = new.content_hash",
		"task.status in ('failed', 'cancelled')",
		"task.failure_code = new.failure_code",
		"runner evidence receipt does not match the committed terminal task result",
		"create constraint trigger hypotheses_runtime_feedback_guard",
		"deferrable initially deferred",
		"runtime hypothesis terminal verdict requires exact human feedback",
		"create constraint trigger feedback_runtime_projection_guard",
		"create constraint trigger hypotheses_runtime_evidence_guard",
		"runtime hypothesis requires at least one exact persisted evidence reference",
		"create constraint trigger investigations_runtime_hypothesis_set_guard",
		"create constraint trigger hypotheses_runtime_parent_set_guard",
		"runtime investigation model outcome does not match its exact hypothesis set",
		"runtime hypotheses must commit atomically with a completed model outcome",
		"return hypothesis_count between 1 and 20",
		"before update or delete on hypothesis_evidence",
		"before truncate on hypothesis_evidence",
		"runtime evidence is immutable",
		"evidence containing runtime facts cannot be truncated",
		"new.status <> 'proposed'",
		"constraint incidents_runtime_confirmed_hypothesis_fk foreign key (tenant_id, workspace_id, id, confirmed_hypothesis_status, confirmed_hypothesis_id, runtime_schema_version)",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("000010 up migration missing DB trust invariant %q", required)
		}
	}
}

func TestInvestigationRuntimeFunctionsPinTrustedSearchPath(t *testing.T) {
	up := readMigration(t, "000010_investigation_runtime.up.sql")
	functions := regexp.MustCompile(`(?mi)^CREATE (?:OR REPLACE )?FUNCTION\s+([a-z0-9_]+)\s*\(`).FindAllStringSubmatch(up, -1)
	if len(functions) == 0 {
		t.Fatal("000010 must declare trigger/helper functions")
	}
	if got := strings.Count(strings.ToLower(up), "set search_path from current"); got != len(functions) {
		t.Fatalf("000010 pinned search_path count = %d, want one for each of %d functions", got, len(functions))
	}
	normalized := strings.Join(strings.Fields(strings.ToLower(up)), " ")
	if !strings.Contains(normalized, "pg_catalog.set_config( 'search_path', pg_catalog.quote_ident(current_schema()) || ', pg_catalog, pg_temp', true )") {
		t.Fatal("000010 must capture the trusted migration schema with pg_temp explicitly last")
	}
}

func TestInvestigationRuntimeMigrationHasUniqueArtifactsAndNullSafeLegacyGuards(t *testing.T) {
	up := readMigration(t, "000010_investigation_runtime.up.sql")
	if strings.Contains(up, "runtime_schema_version <> 'investigation-runtime.v1'") {
		t.Fatal("PL/pgSQL runtime guards must use IS DISTINCT FROM so legacy NULL markers return safely")
	}
	for _, pattern := range []*regexp.Regexp{
		regexp.MustCompile(`(?mi)^CREATE (?:CONSTRAINT )?TRIGGER\s+([a-z0-9_]+)`),
		regexp.MustCompile(`(?mi)^CREATE TABLE\s+([a-z0-9_]+)`),
		regexp.MustCompile(`(?mi)^CREATE (?:UNIQUE )?INDEX\s+([a-z0-9_]+)`),
		regexp.MustCompile(`(?mi)^CREATE (?:OR REPLACE )?FUNCTION\s+([a-z0-9_]+)\s*\(`),
	} {
		seen := make(map[string]struct{})
		for _, match := range pattern.FindAllStringSubmatch(up, -1) {
			name := strings.ToLower(match[1])
			if _, duplicate := seen[name]; duplicate {
				t.Errorf("000010 up migration declares %q more than once", name)
			}
			seen[name] = struct{}{}
		}
	}
}

func readMigration(t *testing.T, name string) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve migration test path")
	}
	path := filepath.Clean(filepath.Join(filepath.Dir(filename), "../../../migrations", name))
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", name, err)
	}
	return string(contents)
}

func normalizedMigration(t *testing.T, name string) string {
	t.Helper()
	return strings.Join(strings.Fields(strings.ToLower(readMigration(t, name))), " ")
}
