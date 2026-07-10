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
