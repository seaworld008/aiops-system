package postgres_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestActionQueueMigrationAtomicallyStoresMetadataAndFencedState(t *testing.T) {
	up := normalizedMigration(t, "000006_action_queue.up.sql")
	if !strings.HasPrefix(up, "BEGIN;") || !strings.HasSuffix(up, "COMMIT;") {
		t.Error("up migration must be transactionally wrapped in BEGIN/COMMIT")
	}
	for _, required := range []string{
		"CREATE TABLE action_queue",
		"action_id text PRIMARY KEY",
		"envelope jsonb NOT NULL",
		"submission_hash text NOT NULL",
		"plan_hash text NOT NULL",
		"workspace_id text NOT NULL",
		"environment_id text NOT NULL",
		"target_key text NOT NULL",
		"environment_revision text NOT NULL",
		"runner_pool text NOT NULL",
		"production boolean NOT NULL",
		"status text NOT NULL",
		"not_before timestamptz NOT NULL",
		"last_nack_hash text",
		"lease_token_sha256 text",
		"completed_lease_token_sha256 text",
		"lease_epoch bigint NOT NULL",
		"reconciliation_id text",
		"CHECK (runner_pool IN ('READ', 'WRITE'))",
		"CHECK (status IN ('QUEUED', 'LEASED', 'RUNNING', 'UNCERTAIN', 'SUCCEEDED', 'FAILED', 'CANCELLED'))",
		"CREATE UNIQUE INDEX action_queue_active_target_uk",
		"CREATE UNIQUE INDEX action_queue_single_production_write_uk",
		"WHERE runner_pool = 'WRITE' AND production = true AND status IN ('LEASED', 'RUNNING', 'UNCERTAIN')",
		"CREATE UNIQUE INDEX action_queue_reconciliation_id_uk",
		"CREATE INDEX action_queue_active_expiry_idx",
		"ON action_queue (lease_expires_at, action_id)",
		"WHERE status IN ('LEASED', 'RUNNING')",
		"reconciliation_id IS NOT NULL",
		"reconciliation_actor IS NOT NULL",
		"reconciliation_result_hash IS NOT NULL",
		"reconciled_at IS NOT NULL",
		"completed_lease_epoch > 0",
		"completed_lease_epoch = lease_epoch",
		"status IN ('LEASED', 'RUNNING') AND lease_epoch > 0",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("up migration missing %q", required)
		}
	}
	if strings.Contains(up, "lease_token text") || strings.Contains(up, "completed_lease_token text") {
		t.Error("database must persist only token hashes, never reusable lease bearer tokens")
	}
	if !strings.Contains(up, "WHERE status IN ('LEASED', 'RUNNING', 'UNCERTAIN')") {
		t.Error("target lock must survive uncertain outcomes")
	}
	if !strings.Contains(up, "status IN ('UNCERTAIN', 'SUCCEEDED', 'FAILED') AND completed_lease_token_sha256 IS NOT NULL") ||
		!strings.Contains(up, "runner_id IS NOT NULL AND completed_lease_token_sha256 IS NOT NULL") {
		t.Error("uncertain/success/failed states must all inherit a runner completed fence")
	}
	if strings.Contains(up, "completed_lease_token_sha256 IS NOT NULL OR reconciliation_id IS NOT NULL") {
		t.Error("reconciliation proof is additive and must not replace the runner completed fence")
	}
	for _, column := range []string{
		"submission_hash", "plan_hash", "last_nack_hash", "lease_token_sha256",
		"completed_lease_token_sha256", "result_hash", "reconciliation_result_hash",
	} {
		if !strings.Contains(up, "octet_length("+column+") = 64") ||
			!strings.Contains(up, column+` COLLATE "C" !~ '[^a-f0-9]'`) {
			t.Errorf("%s must be constrained to lowercase SHA-256", column)
		}
	}
}

func TestActionQueueDownMigrationRemovesAllArtifacts(t *testing.T) {
	down := normalizedMigration(t, "000006_action_queue.down.sql")
	if !strings.HasPrefix(down, "BEGIN;") || !strings.HasSuffix(down, "COMMIT;") {
		t.Error("down migration must be transactionally wrapped in BEGIN/COMMIT")
	}
	for _, required := range []string{
		"DROP INDEX IF EXISTS action_queue_active_expiry_idx",
		"DROP INDEX IF EXISTS action_queue_reconciliation_id_uk",
		"DROP INDEX IF EXISTS action_queue_single_production_write_uk",
		"DROP INDEX IF EXISTS action_queue_active_target_uk",
		"DROP TABLE IF EXISTS action_queue",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("down migration missing %q", required)
		}
	}
}

func TestRunnerExecutionHardeningMigrationExpandsQueueAndRegistrySafely(t *testing.T) {
	up := normalizedMigration(t, "000007_runner_execution_hardening.up.sql")
	for _, required := range []string{
		"COORDINATED CUTOVER PREREQUISITE",
		"ADD COLUMN idempotency_key text",
		"ADD COLUMN request_hash text",
		"ADD COLUMN scope_revision bigint",
		"ADD COLUMN authorization_expires_at timestamptz",
		"ADD COLUMN runner_tenant_id uuid",
		"ADD COLUMN runner_workspace_id uuid",
		"ADD COLUMN runner_environment_id uuid",
		"status IN ('QUEUED', 'CANCELLED') AND runner_tenant_id IS NULL AND runner_workspace_id IS NULL AND runner_environment_id IS NULL",
		"status IN ('LEASED', 'RUNNING') AND runner_tenant_id IS NOT NULL AND runner_workspace_id IS NOT NULL AND runner_environment_id IS NOT NULL",
		"lease_expires_at > last_heartbeat_at",
		"status IN ('FINALIZING', 'UNCERTAIN', 'SUCCEEDED', 'FAILED')",
		"ADD COLUMN heartbeat_seq bigint NOT NULL DEFAULT 0",
		"ADD COLUMN cancel_requested_at timestamptz",
		"ADD COLUMN completion_status text",
		"CREATE UNIQUE INDEX action_queue_workspace_idempotency_uk",
		"ALTER COLUMN authorization_expires_at SET NOT NULL",
		"status IN ('LEASED', 'RUNNING', 'FINALIZING', 'UNCERTAIN')",
		"CREATE TABLE runner_registrations",
		"CREATE TABLE runner_scope_bindings",
		"FOREIGN KEY (tenant_id, workspace_id, environment_id) REFERENCES environments (tenant_id, workspace_id, id)",
		"CREATE TRIGGER runner_scope_bindings_immutable",
		"CREATE TRIGGER runner_scope_bindings_revision",
		"CREATE TRIGGER runner_scope_bindings_no_truncate",
		"CREATE TABLE runner_certificates",
		"CONSTRAINT runner_certificates_revocation_shape_ck",
		"CREATE TABLE runner_result_receipts",
		"tenant_id uuid NOT NULL",
		"workspace_id uuid NOT NULL",
		"environment_id uuid NOT NULL",
		"FOREIGN KEY (runner_tenant_id, runner_id)",
		"FOREIGN KEY (tenant_id, runner_id)",
		"FOREIGN KEY (tenant_id, workspace_id, environment_id)",
		"CONSTRAINT runner_result_receipts_action_fence_fk",
		"runner_tenant_id, runner_workspace_id, runner_environment_id, action_id, runner_id, lease_epoch, scope_revision, result_hash, completion_status",
		"CREATE TRIGGER runner_result_receipts_no_truncate",
		"pg_column_size(summary) BETWEEN 2 AND 16384",
		"ADD COLUMN lease_token_sha256 text",
		"ADD COLUMN completed_lease_token_sha256 text",
		"SET lease_token = NULL, completed_lease_token = NULL",
		"CHECK (lease_token IS NULL AND completed_lease_token IS NULL)",
		"'FINALIZING', 'UNCERTAIN'",
		"unsafe runner hardening upgrade: active action queue must be drained",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("000007 up migration missing %q", required)
		}
	}
	if !strings.Contains(up, "encode(sha256(convert_to(lease_token, 'UTF8')), 'hex')") ||
		!strings.Contains(up, "encode(sha256(convert_to(completed_lease_token, 'UTF8')), 'hex')") {
		t.Error("000007 must backfill both legacy bearer-token columns with SHA-256")
	}
	if strings.Contains(up, "candidate.workspace_id::uuid") || strings.Contains(up, "candidate.environment_id::uuid") {
		t.Error("claim-side text identifiers must not be cast to UUID because legacy dirty data must fail closed per row")
	}
	if strings.Contains(up, "DROP COLUMN lease_token") || strings.Contains(up, "DROP COLUMN completed_lease_token") {
		t.Error("coordinated migration must retain legacy token columns as an empty compatibility shell")
	}
	if !strings.Contains(up, "lease_acquired_at IS NOT NULL AND lease_expires_at IS NOT NULL AND last_heartbeat_at IS NOT NULL AND lease_expires_at > last_heartbeat_at AND completed_at IS NULL") {
		t.Error("action_queue active leases must expire strictly after their last heartbeat")
	}
}

func TestRunnerExecutionHardeningDownMigrationRefusesUnsafeRollback(t *testing.T) {
	down := normalizedMigration(t, "000007_runner_execution_hardening.down.sql")
	for _, required := range []string{
		"LOCK TABLE action_queue, execution_leases, executions, runner_result_receipts, runner_certificates, runner_scope_bindings, runner_registrations IN ACCESS EXCLUSIVE MODE",
		"ERRCODE = '55000'",
		"status IN ('LEASED', 'RUNNING', 'FINALIZING', 'UNCERTAIN')",
		"WHERE status = 'QUEUED'",
		"runner_result_receipts",
		"runner_scope_bindings",
		"runner_registrations",
		"completed_lease_token_sha256 IS NOT NULL",
		"DROP TABLE runner_certificates",
		"DROP FUNCTION bump_runner_scope_revision()",
		"DROP FUNCTION reject_runner_scope_binding_update()",
		"DROP CONSTRAINT action_queue_runner_registration_fk",
		"DROP COLUMN runner_environment_id",
		"DROP COLUMN runner_workspace_id",
		"DROP COLUMN runner_tenant_id",
		"DROP TABLE runner_scope_bindings",
		"DROP TABLE runner_registrations",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("000007 down migration missing %q", required)
		}
	}
}

func TestRunnerGatewayMTLSMigrationHardensCertificateAndReceiptEvidence(t *testing.T) {
	up := normalizedMigration(t, "000009_runner_gateway_mtls.up.sql")
	if !strings.HasPrefix(up, "BEGIN;") || !strings.HasSuffix(up, "COMMIT;") {
		t.Error("000009 up migration must be transactionally wrapped in BEGIN/COMMIT")
	}
	for _, required := range []string{
		"LOCK TABLE action_queue, execution_leases, runner_result_receipts, runner_certificates, runner_registrations, credential_revocations IN ACCESS EXCLUSIVE MODE",
		"SELECT 1 FROM execution_leases WHERE status IN ('LEASED', 'RUNNING', 'UNCERTAIN')",
		"CREATE TRIGGER execution_leases_m3_cutover_guard",
		"CREATE OR REPLACE FUNCTION reject_legacy_execution_lease_activation() RETURNS trigger",
		"CONSTRAINT = 'execution_leases_m3_cutover_guard'",
		"ADD COLUMN credential_revocation_capable boolean NOT NULL DEFAULT false",
		"CONSTRAINT runner_registrations_revocation_capability_ck",
		"CONSTRAINT runner_certificates_metadata_ck",
		"CONSTRAINT runner_certificates_time_ck",
		"CREATE TRIGGER runner_certificates_lifecycle_guard",
		"CREATE TRIGGER runner_certificates_no_delete",
		"CREATE TRIGGER runner_certificates_no_truncate",
		"OLD.status = 'ACTIVE' AND NEW.status = 'REVOKED'",
		"NEW.created_at := transition_at",
		"NEW.revoked_at := transition_at",
		"schema_version = 'runner-result.v1'",
		"schema_version = 'runner-result.v2' AND certificate_sha256 IS NOT NULL",
		"receipt.schema_version IN ('runner-result.v1', 'runner-result.v2')",
		"CREATE TRIGGER runner_result_receipts_insert_guard",
		"NEW.schema_version <> 'runner-result.v2'",
		"registration.enabled = true",
		"registration.runner_pool = 'WRITE'",
		"certificate.status = 'ACTIVE'",
		"certificate.not_before <= NEW.received_at",
		"certificate.not_after > NEW.received_at",
		"FOR SHARE OF registration",
		"FOR SHARE OF certificate",
		"ADD COLUMN heartbeat_seq bigint NOT NULL DEFAULT 0",
		"NEW.heartbeat_seq = OLD.heartbeat_seq + 1",
		"NEW.heartbeat_seq := 0",
		"NEW.claimed_by IS DISTINCT FROM OLD.claimed_by",
		"NEW.claim_token_sha256 IS DISTINCT FROM OLD.claim_token_sha256",
		"NEW.claimed_at IS DISTINCT FROM OLD.claimed_at",
		"to_jsonb(NEW) - ARRAY[",
		"'heartbeat_seq', 'last_heartbeat_at', 'claim_expires_at', 'updated_at', 'version'",
		"NEW.claimed_at := transition_at",
		"NEW.last_heartbeat_at := transition_at",
		"NEW.claim_expires_at := transition_at + interval '30 seconds'",
		"binding.runner_id = NEW.claimed_by",
		"binding.tenant_id = NEW.tenant_id",
		"binding.workspace_id = NEW.workspace_id",
		"binding.environment_id = NEW.environment_id",
		"FOR SHARE OF binding",
		"'status', 'claim_epoch', 'claimed_by', 'claim_token_sha256', 'claimed_at'",
		"'claim_expires_at', 'last_heartbeat_at', 'attempt', 'heartbeat_seq', 'updated_at', 'version'",
		"CREATE TABLE credential_revocation_receipts",
		"PRIMARY KEY (revocation_id, claim_epoch)",
		"tenant_id uuid NOT NULL",
		"workspace_id uuid NOT NULL",
		"environment_id uuid NOT NULL",
		"scope_revision bigint NOT NULL",
		"issuer text NOT NULL",
		"issuer_revision text NOT NULL",
		"FOREIGN KEY (tenant_id, runner_id)",
		"FOREIGN KEY (tenant_id, workspace_id, environment_id)",
		"FOREIGN KEY (runner_id, certificate_sha256)",
		"REFERENCES runner_certificates (runner_id, certificate_sha256)",
		"CREATE TRIGGER credential_revocation_receipts_claim_guard",
		"CREATE CONSTRAINT TRIGGER credential_revocation_receipts_final_shape",
		"DEFERRABLE INITIALLY DEFERRED",
		"CREATE TRIGGER credential_revocation_receipts_immutable",
		"CREATE TRIGGER credential_revocation_receipts_no_truncate",
		"CREATE CONSTRAINT TRIGGER credential_revocations_completion_receipt_guard",
		"validate_credential_revocation_completion_receipt",
		"CREATE TABLE credential_revocation_system_receipts",
		"CREATE TRIGGER credential_revocations_system_recovery_receipt",
		"CREATE TRIGGER credential_revocation_system_receipts_insert_guard",
		"pg_trigger_depth() <> 2",
		"CREATE CONSTRAINT TRIGGER credential_revocation_system_receipts_final_shape",
		"CREATE TRIGGER credential_revocation_system_receipts_immutable",
		"CREATE TRIGGER credential_revocation_system_receipts_no_truncate",
		"recovery_kind = 'EXHAUSTED_WITHOUT_ACK'",
		"failure_code = 'UNKNOWN'",
		"failure_detail_sha256 = '5797f0f8a568d5f215e18706d1e9e08a55101b1ba68ced7926e77a6c253359fe'",
		"attempt - retry_cycle_attempt_base >= 12",
		"retry_cycle_started_at <= manual_required_at - interval '2 hours'",
		"claim_expires_at <= manual_required_at",
		"claimed_at timestamptz NOT NULL",
		"last_heartbeat_at timestamptz NOT NULL",
		"receipt.prior_failure_count = OLD.failure_count",
		"receipt.failure_count = NEW.failure_count",
		"receipt.parent_version = NEW.version",
		"receipt.claim_epoch = OLD.claim_epoch",
		"receipt.tenant_id = OLD.tenant_id",
		"receipt.workspace_id = OLD.workspace_id",
		"receipt.environment_id = OLD.environment_id",
		"receipt.runner_id = OLD.claimed_by",
		"receipt.issuer = OLD.issuer",
		"receipt.issuer_revision = OLD.issuer_revision",
		"receipt.claim_token_sha256 = OLD.claim_token_sha256",
		"receipt.heartbeat_seq = OLD.heartbeat_seq",
		"receipt.claimed_at = OLD.claimed_at",
		"receipt.last_heartbeat_at = OLD.last_heartbeat_at",
		"runner_proof_count + system_proof_count <> 1",
		"FROM credential_revocation_system_receipts AS sibling WHERE sibling.revocation_id = NEW.revocation_id AND sibling.claim_epoch = NEW.claim_epoch",
		"FROM credential_revocation_receipts AS sibling WHERE sibling.revocation_id = NEW.revocation_id AND sibling.claim_epoch = NEW.claim_epoch",
		"registration.scope_revision = NEW.scope_revision",
		"registration.tenant_id = NEW.tenant_id",
		"binding.workspace_id = NEW.workspace_id",
		"binding.environment_id = NEW.environment_id",
		"revocation.tenant_id = NEW.tenant_id",
		"revocation.workspace_id = NEW.workspace_id",
		"revocation.environment_id = NEW.environment_id",
		"revocation.issuer = NEW.issuer",
		"revocation.issuer_revision = NEW.issuer_revision",
		"parent.completed_claimed_by = NEW.runner_id",
		"action.lease_epoch = NEW.lease_epoch",
		"action.scope_revision = NEW.scope_revision",
		"action.result_hash = NEW.receipt_hash",
		"action.completion_status = NEW.completion_status",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("000009 up migration missing %q", required)
		}
	}
	registrationLock := strings.Index(up, "PERFORM 1 FROM runner_registrations AS registration WHERE registration.runner_id = NEW.runner_id")
	certificateLock := strings.Index(up, "PERFORM 1 FROM runner_certificates AS certificate WHERE certificate.runner_id = NEW.runner_id")
	actionLock := strings.Index(up, "PERFORM 1 FROM action_queue AS action WHERE action.action_id = NEW.action_id")
	if registrationLock < 0 || certificateLock <= registrationLock || actionLock <= certificateLock {
		t.Errorf("000009 result receipt lock order registration/certificate/action = %d/%d/%d", registrationLock, certificateLock, actionLock)
	}
	capture := normalizedTriggerFunction(t, up, "capture_credential_revocation_system_recovery")
	if strings.Contains(capture, "transition_at") || strings.Contains(capture, "received_at") ||
		!strings.Contains(capture, "OLD.claim_expires_at <= NEW.manual_required_at") {
		t.Error("system recovery eligibility must use only the database-controlled parent manual_required_at boundary")
	}
	if !strings.Contains(capture, "INSERT INTO credential_revocation_system_receipts") ||
		strings.Contains(capture, "INVALID_REFERENCE") {
		t.Error("system recovery capture must only mint database-verifiable exhausted receipts")
	}
	completionGuard := normalizedTriggerFunction(t, up, "validate_credential_revocation_completion_receipt")
	if strings.Contains(completionGuard, "AND NOT EXISTS") ||
		!strings.Contains(completionGuard, "runner_proof_count + system_proof_count <> 1") {
		t.Error("revocation parent completion must require exactly one Runner/system proof")
	}
	revocationClaimGuard := normalizedTriggerFunction(t, up, "validate_credential_revocation_receipt_claim")
	registrationLock = strings.Index(revocationClaimGuard, "FROM runner_registrations AS registration")
	certificateLock = strings.Index(revocationClaimGuard, "FROM runner_certificates AS certificate")
	bindingLock := strings.Index(revocationClaimGuard, "FROM runner_scope_bindings AS binding")
	parentLock := strings.Index(revocationClaimGuard, "FROM credential_revocations AS revocation")
	if registrationLock < 0 || certificateLock <= registrationLock || bindingLock <= certificateLock || parentLock <= bindingLock {
		t.Errorf("credential receipt lock order registration/certificate/binding/parent = %d/%d/%d/%d",
			registrationLock, certificateLock, bindingLock, parentLock)
	}
	for _, forbidden := range []string{
		" claim_token text",
		"raw_claim_token",
		"authorize_credential_revocation_protected_quarantine",
		"aiops.protected_quarantine",
		"PROTECTED_REFERENCE_INVALID",
		"parent.runner_id <> NEW.runner_id",
		"accessor text",
		"secret text",
		"receipt_required",
		"sequence_required",
	} {
		if strings.Contains(up, forbidden) {
			t.Errorf("000009 persists forbidden plaintext shape %q", forbidden)
		}
	}
}

func TestRunnerGatewayMTLSDownMigrationRefusesEvidenceLoss(t *testing.T) {
	down := normalizedMigration(t, "000009_runner_gateway_mtls.down.sql")
	if !strings.HasPrefix(down, "BEGIN;") || !strings.HasSuffix(down, "COMMIT;") {
		t.Error("000009 down migration must be transactionally wrapped in BEGIN/COMMIT")
	}
	for _, required := range []string{
		"LOCK TABLE action_queue, execution_leases, runner_result_receipts, runner_certificates, runner_registrations, credential_revocations, credential_revocation_receipts, credential_revocation_system_receipts, audit_records, outbox_events IN ACCESS EXCLUSIVE MODE",
		"status IN ('LEASED', 'RUNNING', 'FINALIZING', 'UNCERTAIN')",
		"SELECT 1 FROM execution_leases WHERE status IN ('LEASED', 'RUNNING', 'UNCERTAIN')",
		"schema_version = 'runner-result.v2'",
		"SELECT 1 FROM runner_certificates WHERE status = 'REVOKED'",
		"WHERE credential_revocation_capable = true",
		"status = 'REVOKING'",
		"heartbeat_seq <> 0",
		"SELECT 1 FROM credential_revocation_receipts",
		"SELECT 1 FROM credential_revocation_system_receipts",
		"action LIKE 'runner.gateway.%'",
		"event_type LIKE 'runner.gateway.%'",
		"ERRCODE = '55000'",
		"DROP TABLE credential_revocation_receipts",
		"DROP TABLE credential_revocation_system_receipts",
		"DROP TRIGGER credential_revocations_system_recovery_receipt ON credential_revocations",
		"DROP FUNCTION capture_credential_revocation_system_recovery()",
		"DROP FUNCTION reject_credential_revocation_system_receipt_mutation()",
		"DROP FUNCTION validate_credential_revocation_system_receipt_final_shape()",
		"DROP FUNCTION guard_credential_revocation_system_receipt_insert()",
		"DROP TRIGGER execution_leases_m3_cutover_guard ON execution_leases",
		"DROP FUNCTION reject_legacy_execution_lease_activation()",
		"DROP COLUMN heartbeat_seq",
		"DROP COLUMN credential_revocation_capable",
		"CHECK (schema_version = 'runner-result.v1')",
		"DROP TRIGGER runner_result_receipts_insert_guard ON runner_result_receipts",
		"DROP FUNCTION enforce_runner_result_receipt_insert()",
		"DROP TRIGGER credential_revocations_completion_receipt_guard ON credential_revocations",
		"DROP FUNCTION validate_credential_revocation_completion_receipt()",
		"CREATE OR REPLACE FUNCTION enforce_action_queue_credential_cleanup() RETURNS trigger",
		"CREATE OR REPLACE FUNCTION validate_action_queue_finalizing_receipt() RETURNS trigger",
		"receipt.schema_version = 'runner-result.v1'",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("000009 down migration missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"authorize_credential_revocation_protected_quarantine",
		"aiops.protected_quarantine",
		"raw_claim_token",
	} {
		if strings.Contains(down, forbidden) {
			t.Errorf("000009 down migration retains removed protected-reference authorization %q", forbidden)
		}
	}
}

func TestRunnerGatewayMTLSDownMigrationRestoresExactM2ReceiptFunctions(t *testing.T) {
	m2 := normalizedMigrationWithoutLineComments(t, "000008_credential_revocations.up.sql")
	down := normalizedMigrationWithoutLineComments(t, "000009_runner_gateway_mtls.down.sql")
	for _, name := range []string{
		"enforce_action_queue_credential_cleanup",
		"validate_action_queue_finalizing_receipt",
	} {
		want := normalizedTriggerFunction(t, m2, name)
		got := normalizedTriggerFunction(t, down, name)
		if got != want {
			t.Errorf("000009 down migration does not restore exact M2 function %s", name)
		}
	}
}

func TestCredentialProtectedReferenceRecoveryProbeCarriesNoSensitiveInput(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve credential repository source path")
	}
	contents, err := os.ReadFile(filepath.Join(
		filepath.Dir(filename), "..", "..", "credential", "postgres", "repository.go",
	))
	if err != nil {
		t.Fatalf("read credential repository source: %v", err)
	}
	source := string(contents)
	for _, required := range []string{
		"func hasCredentialRevocationSystemRecoverySchema",
		"FROM pg_catalog.pg_class AS relation",
		"JOIN pg_catalog.pg_namespace AS namespace",
		"JOIN pg_catalog.pg_attribute AS attribute",
		"namespace.nspname = current_schema()",
		"relation.relname = 'credential_revocation_system_receipts'",
		"attribute.attname = 'heartbeat_seq'",
		"credential.revocation.protected_reference_unavailable.v1",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("credential protected-reference recovery missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"authorizeProtectedReferenceQuarantine",
		"authorize_credential_revocation_protected_quarantine",
		"to_regprocedure",
		"aiops.protected_quarantine",
	} {
		if strings.Contains(source, forbidden) {
			t.Errorf("credential protected-reference recovery retains forbidden path %q", forbidden)
		}
	}
	probeStart := strings.Index(source, "func hasCredentialRevocationSystemRecoverySchema")
	probeEndOffset := strings.Index(source[probeStart+1:], "\nfunc ")
	if probeStart < 0 || probeEndOffset < 0 {
		t.Fatal("cannot isolate credential recovery schema probe")
	}
	probe := source[probeStart : probeStart+1+probeEndOffset]
	if strings.Contains(probe, "$1") || strings.Contains(strings.ToLower(probe), "token") {
		t.Error("credential recovery schema capability probe must not accept or bind token material")
	}
}

func normalizedMigration(t *testing.T, name string) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve migration test path")
	}
	contents, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "..", "migrations", name))
	if err != nil {
		t.Fatalf("read migration %s: %v", name, err)
	}
	return strings.Join(strings.Fields(string(contents)), " ")
}

func normalizedMigrationWithoutLineComments(t *testing.T, name string) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve migration test path")
	}
	contents, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "..", "migrations", name))
	if err != nil {
		t.Fatalf("read migration %s: %v", name, err)
	}
	lines := strings.Split(string(contents), "\n")
	for index := range lines {
		if comment := strings.Index(lines[index], "--"); comment >= 0 {
			lines[index] = lines[index][:comment]
		}
	}
	return strings.Join(strings.Fields(strings.Join(lines, "\n")), " ")
}

func normalizedTriggerFunction(t *testing.T, migration, name string) string {
	t.Helper()
	prefix := "CREATE OR REPLACE FUNCTION " + name + "() RETURNS trigger AS $$"
	start := strings.Index(migration, prefix)
	if start < 0 {
		t.Fatalf("migration missing function %s", name)
	}
	endOffset := strings.Index(migration[start:], "$$ LANGUAGE plpgsql;")
	if endOffset < 0 {
		t.Fatalf("migration function %s has no terminator", name)
	}
	return migration[start : start+endOffset+len("$$ LANGUAGE plpgsql;")]
}
