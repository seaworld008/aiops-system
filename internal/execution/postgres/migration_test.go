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
