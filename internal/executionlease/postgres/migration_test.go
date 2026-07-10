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
		"reconciliation_result_hash text",
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
	for _, identifierConstraint := range []string{
		`octet_length(execution_id) BETWEEN 1 AND 256 AND left(execution_id, 1) COLLATE "C" ~ '^[A-Za-z0-9]$' AND execution_id COLLATE "C" !~ '[^A-Za-z0-9._:/@-]'`,
		`octet_length(target_key) BETWEEN 1 AND 512 AND left(target_key, 1) COLLATE "C" ~ '^[A-Za-z0-9]$' AND target_key COLLATE "C" !~ '[^A-Za-z0-9._:/@-]'`,
		`octet_length(runner_id) BETWEEN 1 AND 256 AND left(runner_id, 1) COLLATE "C" ~ '^[A-Za-z0-9]$' AND runner_id COLLATE "C" !~ '[^A-Za-z0-9._:/@-]'`,
		`octet_length(lease_token) BETWEEN 1 AND 256 AND left(lease_token, 1) COLLATE "C" ~ '^[A-Za-z0-9]$' AND lease_token COLLATE "C" !~ '[^A-Za-z0-9._:/@-]'`,
		`octet_length(completed_lease_token) BETWEEN 1 AND 256 AND left(completed_lease_token, 1) COLLATE "C" ~ '^[A-Za-z0-9]$' AND completed_lease_token COLLATE "C" !~ '[^A-Za-z0-9._:/@-]'`,
		`octet_length(reconciliation_id) BETWEEN 1 AND 256 AND left(reconciliation_id, 1) COLLATE "C" ~ '^[A-Za-z0-9]$' AND reconciliation_id COLLATE "C" !~ '[^A-Za-z0-9._:/@-]'`,
		`octet_length(reconciliation_actor) BETWEEN 1 AND 256 AND left(reconciliation_actor, 1) COLLATE "C" ~ '^[A-Za-z0-9]$' AND reconciliation_actor COLLATE "C" !~ '[^A-Za-z0-9._:/@-]'`,
	} {
		if !strings.Contains(up, identifierConstraint) {
			t.Errorf("database identifier constraint must match Go: missing %q", identifierConstraint)
		}
	}
	if !strings.Contains(up, "status IN ('SUCCEEDED', 'FAILED', 'UNCERTAIN')") {
		t.Error("completion shape must permit a fenced UNCERTAIN result")
	}
	if !strings.Contains(up, "status IN ('SUCCEEDED', 'FAILED')") || !strings.Contains(up, "reconciliation_id IS NOT NULL") ||
		!strings.Contains(up, "reconciliation_result_hash IS NOT NULL") {
		t.Error("reconciliation proof must only resolve UNCERTAIN to SUCCEEDED or FAILED")
	}
	if strings.Contains(up, "reconciliation_id IS NOT NULL AND result_hash IS NOT NULL") {
		t.Error("reconciliation must not reuse or require the runner result_hash column")
	}
	for _, hashColumn := range []string{"result_hash", "reconciliation_result_hash"} {
		if !strings.Contains(up, "octet_length("+hashColumn+") = 64") ||
			!strings.Contains(up, hashColumn+` COLLATE "C" !~ '[^a-f0-9]'`) {
			t.Errorf("%s must be exactly 64 lowercase hexadecimal bytes", hashColumn)
		}
	}
	if strings.Contains(up, "~ '^[a-f0-9]{64}$'") {
		t.Error("PostgreSQL dollar anchors can admit a trailing newline and must not guard result hashes")
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
