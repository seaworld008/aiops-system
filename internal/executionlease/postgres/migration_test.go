package postgres_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestExecutionLeaseMigrationProvidesDatabaseFencing(t *testing.T) {
	up := normalizedMigration(t, "000005_execution_leases.up.sql")

	for _, required := range []string{
		"CREATE TABLE execution_leases",
		"execution_id text PRIMARY KEY",
		"runner_pool text",
		"target_key text",
		"production boolean",
		"lease_token text",
		"lease_epoch bigint",
		"lease_acquired_at timestamptz",
		"lease_expires_at timestamptz",
		"last_heartbeat_at timestamptz",
		"started_at timestamptz",
		"completed_at timestamptz",
		"completed_lease_token text",
		"completed_lease_epoch bigint",
		"reconciliation_id text",
		"reconciliation_actor text",
		"reconciled_at timestamptz",
		"CHECK (runner_pool IN ('READ', 'WRITE'))",
		"CHECK (status IN ('QUEUED', 'LEASED', 'RUNNING', 'UNCERTAIN', 'SUCCEEDED', 'FAILED', 'CANCELLED'))",
		"CHECK (lease_epoch >= 0)",
		"CREATE UNIQUE INDEX execution_leases_active_target_uk",
		"ON execution_leases (target_key)",
		"CREATE UNIQUE INDEX execution_leases_single_production_write_uk",
		"ON execution_leases ((runner_pool))",
		"WHERE runner_pool = 'WRITE' AND production = true AND status IN ('LEASED', 'RUNNING', 'UNCERTAIN')",
		"CREATE UNIQUE INDEX execution_leases_reconciliation_id_uk",
		"ON execution_leases (reconciliation_id)",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("up migration missing %q", required)
		}
	}

	if !strings.Contains(up, "WHERE status IN ('LEASED', 'RUNNING', 'UNCERTAIN')") {
		t.Error("target uniqueness must include uncertain executions to prevent blind retries")
	}
	if !strings.Contains(up, "lease_token IS NOT NULL") || !strings.Contains(up, "lease_expires_at IS NOT NULL") {
		t.Error("active lease shape must require a token and expiry")
	}
	if !strings.Contains(up, "octet_length(execution_id) BETWEEN 1 AND 256") || !strings.Contains(up, "octet_length(runner_id) BETWEEN 1 AND 256") {
		t.Error("database identifier limits must match the public API")
	}
	if !strings.Contains(up, "status IN ('SUCCEEDED', 'FAILED', 'UNCERTAIN')") {
		t.Error("completion shape must permit a fenced UNCERTAIN result")
	}
	if !strings.Contains(up, "status IN ('SUCCEEDED', 'FAILED')") || !strings.Contains(up, "reconciliation_id IS NOT NULL") {
		t.Error("reconciliation proof must only resolve UNCERTAIN to SUCCEEDED or FAILED")
	}
	if strings.Count(up, "result_hash IS NOT NULL") < 3 {
		t.Error("every completed or reconciled proof branch must reject a NULL result hash explicitly")
	}
	if !strings.Contains(up, "octet_length(completed_lease_token) BETWEEN 1 AND 256") {
		t.Error("completed fence tokens must retain the public token bounds")
	}
}

func TestExecutionLeaseDownMigrationRemovesEveryLeaseArtifact(t *testing.T) {
	down := normalizedMigration(t, "000005_execution_leases.down.sql")

	for _, required := range []string{
		"DROP INDEX IF EXISTS execution_leases_reconciliation_id_uk",
		"DROP INDEX IF EXISTS execution_leases_single_production_write_uk",
		"DROP INDEX IF EXISTS execution_leases_active_target_uk",
		"DROP TABLE IF EXISTS execution_leases",
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
