package postgres_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInvestigationRunnerIngressMigrationIsAtomicAndPrelocksDependencies(t *testing.T) {
	expectedLocks := map[string]string{
		"000011_investigation_runner_ingress.up.sql":   "lock table runner_scope_bindings, runner_registrations, runner_certificates, tool_invocations, investigations, evidence, runner_evidence_receipts, investigation_idempotency_records, environments, workspaces in access exclusive mode",
		"000011_investigation_runner_ingress.down.sql": "lock table runner_scope_bindings, runner_registrations, runner_certificates, tool_invocations, investigation_task_attempts, investigations, evidence, runner_evidence_receipts, investigation_idempotency_records, environments, workspaces in access exclusive mode",
	}
	for name, expectedLock := range expectedLocks {
		migration := strings.TrimSpace(readMigration(t, name))
		if !strings.HasPrefix(migration, "BEGIN;") || !strings.HasSuffix(migration, "COMMIT;") {
			t.Fatalf("%s must be transactionally wrapped in BEGIN/COMMIT", name)
		}
		normalized := normalizeSQL(migration)
		for _, required := range []string{
			"set local lock_timeout = '5s'",
			"pg_catalog.set_config",
			"pg_catalog.quote_ident(current_schema()) || ', pg_catalog, pg_temp'",
			expectedLock,
		} {
			if !strings.Contains(normalized, required) {
				t.Errorf("%s missing migration boundary %q", name, required)
			}
		}
	}
}

func TestInvestigationRunnerIngressPersistsAppendHistoryFences(t *testing.T) {
	up := normalizedMigration(t, "000011_investigation_runner_ingress.up.sql")
	for _, required := range []string{
		"create table investigation_task_attempts",
		"tenant_id uuid not null",
		"workspace_id uuid not null",
		"environment_id uuid not null",
		"investigation_id uuid not null",
		"task_id uuid not null",
		"lease_epoch bigint not null",
		"lease_token_sha256 text not null",
		"runner_id text not null",
		"scope_revision bigint not null",
		"certificate_sha256 text not null",
		"certificate_not_after timestamptz not null",
		"heartbeat_seq bigint not null default 0",
		"lease_acquired_at timestamptz not null",
		"last_heartbeat_at timestamptz not null",
		"lease_expires_at timestamptz not null",
		"status text not null",
		"request_hash text",
		"receipt_hash text",
		"primary key (tenant_id, workspace_id, investigation_id, task_id, lease_epoch)",
		"foreign key (tenant_id, workspace_id, investigation_id, task_id) references tool_invocations (tenant_id, workspace_id, investigation_id, id)",
		"foreign key (tenant_id, workspace_id, investigation_id, environment_id) references investigations (tenant_id, workspace_id, id, environment_id_snapshot)",
		"foreign key (tenant_id, runner_id) references runner_registrations (tenant_id, runner_id)",
		"foreign key (runner_id, certificate_sha256) references runner_certificates (runner_id, certificate_sha256)",
		"create unique index investigation_task_attempts_active_task_uk",
		"where status in ('leased', 'running')",
		"create unique index investigation_task_attempts_token_hash_uk",
		"create index investigation_task_attempts_runner_active_idx",
		"create index investigation_task_attempts_expiry_idx",
		"create trigger investigation_task_attempts_insert_guard",
		"binding.workspace_id = new.workspace_id",
		"binding.environment_id = new.environment_id",
		"registration.runner_pool = 'read'",
		"registration.scope_revision = new.scope_revision",
		"select certificate.status, certificate.not_before, certificate.not_after into authenticated_certificate_status, authenticated_certificate_not_before, authenticated_certificate_not_after",
		"authenticated_certificate_status <> 'active'",
		"new.certificate_not_after := authenticated_certificate_not_after",
		"new.lease_expires_at <= transition_at",
		"new.lease_expires_at > authenticated_certificate_not_after",
		"lease_expires_at <= certificate_not_after",
		"create trigger investigation_task_attempts_lifecycle_guard",
		"create trigger investigation_task_attempts_no_delete",
		"create trigger investigation_task_attempts_no_truncate",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("000011 up migration missing %q", required)
		}
	}
	if strings.Contains(up, "lease_token text") {
		t.Fatal("attempt history must never persist a reusable bearer token")
	}
	for _, hash := range []string{"lease_token_sha256", "request_hash", "receipt_hash"} {
		if !strings.Contains(up, "octet_length("+hash+") = 64") ||
			!strings.Contains(up, hash+` collate "c" !~ '[^a-f0-9]'`) {
			t.Errorf("%s must be constrained to lowercase SHA-256", hash)
		}
	}
}

func TestInvestigationRunnerIngressConstrainsAttemptLifecycle(t *testing.T) {
	up := normalizedMigration(t, "000011_investigation_runner_ingress.up.sql")
	for _, required := range []string{
		"status in ('leased', 'running', 'completed', 'released', 'expired', 'cancelled')",
		"old.status = 'leased' and new.status in ('running', 'released', 'expired', 'cancelled')",
		"old.status = 'running' and new.status in ('completed', 'expired', 'cancelled')",
		"old.status in ('completed', 'released', 'expired', 'cancelled') then",
		"old.status = 'running' and new.status in ('running', 'cancelled')",
		"new.heartbeat_seq = old.heartbeat_seq + 1",
		"new.lease_expires_at > new.last_heartbeat_at",
		"old.lease_epoch is distinct from new.lease_epoch",
		"old.lease_token_sha256 is distinct from new.lease_token_sha256",
		"old.runner_id is distinct from new.runner_id",
		"old.scope_revision is distinct from new.scope_revision",
		"old.certificate_sha256 is distinct from new.certificate_sha256",
		"old.certificate_not_after is distinct from new.certificate_not_after",
		"old.started_at is distinct from new.started_at",
		"old.terminal_at is distinct from new.terminal_at",
		"old.updated_at is distinct from new.updated_at",
		"old is not distinct from new then",
		"new.status in ('running', 'completed', 'released')",
		"active investigation task attempt update requires its current exact scope binding",
		"active investigation task attempt update requires an enabled current read registration",
		"active investigation task attempt update requires its current active certificate",
		"authenticated_certificate_not_after <> new.certificate_not_after",
		"new.status = 'running' and new.lease_expires_at >= old.lease_expires_at",
		"new.status = 'cancelled' and new.lease_expires_at = old.lease_expires_at",
		"new.status = 'released' and old.lease_expires_at <= transition_at",
		"constraint = 'investigation_task_attempts_lease_current_guard'",
		"status = 'completed' and request_hash is not null and receipt_hash is not null",
		"status <> 'completed' and request_hash is null and receipt_hash is null",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("000011 lifecycle missing %q", required)
		}
	}
	if strings.Contains(up, "old.status in ('leased', 'running') and new.status = old.status") {
		t.Fatal("LEASED attempts must not heartbeat indefinitely before start")
	}
}

func TestInvestigationRunnerIngressUpgradesReceiptsWithoutRewritingV1(t *testing.T) {
	up := normalizedMigration(t, "000011_investigation_runner_ingress.up.sql")
	for _, required := range []string{
		"alter table runner_evidence_receipts add column lease_epoch bigint",
		"schema_version = 'runner-evidence.v1' and lease_epoch is null",
		"schema_version = 'runner-evidence.v2' and lease_epoch is not null and lease_epoch > 0",
		"runner_evidence_receipts_attempt_fence_fk",
		"tenant_id, workspace_id, investigation_id, task_id, lease_epoch, runner_id, scope_revision, certificate_sha256",
		"references investigation_task_attempts",
		"attempt.status = 'completed'",
		"attempt.request_hash = new.request_hash",
		"attempt.receipt_hash = new.receipt_hash",
		"create constraint trigger investigation_task_attempts_completion_projection_guard",
		"deferrable initially deferred",
		"receipt.schema_version = 'runner-evidence.v2'",
		"receipt.lease_epoch = new.lease_epoch",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("000011 receipt upgrade missing %q", required)
		}
	}
}

func TestInvestigationRunnerIngressReadsSecurityClocksOnlyAfterOrderedLocks(t *testing.T) {
	up := normalizedMigration(t, "000011_investigation_runner_ingress.up.sql")
	assertOrderedSQL(t, functionSQL(t, up,
		"create or replace function validate_investigation_task_attempt_insert()",
		"create trigger investigation_task_attempts_insert_guard"), []string{
		"from runner_scope_bindings as binding",
		"from runner_registrations as registration",
		"from runner_certificates as certificate",
		"from tool_invocations as task",
		"from investigation_task_attempts as existing",
		"from investigations as parent",
		"transition_at := clock_timestamp()",
	})
	assertOrderedSQL(t, functionSQL(t, up,
		"create or replace function enforce_investigation_task_attempt_lifecycle()",
		"create trigger investigation_task_attempts_lifecycle_guard"), []string{
		"from runner_scope_bindings as binding",
		"from runner_registrations as registration",
		"from runner_certificates as certificate",
		"transition_at := clock_timestamp()",
	})
	assertOrderedSQL(t, functionSQL(t, up,
		"create or replace function validate_runner_evidence_receipt_insert()",
		"create or replace function validate_investigation_task_attempt_completion()"), []string{
		"from runner_scope_bindings as binding",
		"from runner_registrations as registration",
		"from runner_certificates as certificate",
		"from tool_invocations as task",
		"from investigation_task_attempts as attempt",
		"from investigations as investigation",
		"receipt_at := clock_timestamp()",
		"new.received_at := receipt_at",
	})
}

func TestInvestigationRunnerIngressDownRefusesLossyRollback(t *testing.T) {
	down := normalizedMigration(t, "000011_investigation_runner_ingress.down.sql")
	for _, required := range []string{
		"if exists (select 1 from investigation_task_attempts)",
		"or exists (select 1 from runner_evidence_receipts where schema_version = 'runner-evidence.v2')",
		"errcode = '55000'",
		"unsafe investigation runner ingress rollback",
		"drop table investigation_task_attempts",
		"alter table runner_evidence_receipts drop column lease_epoch",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("000011 down migration missing %q", required)
		}
	}
}

func normalizedMigration(t *testing.T, name string) string {
	t.Helper()
	return normalizeSQL(readMigration(t, name))
}

func functionSQL(t *testing.T, migration, start, end string) string {
	t.Helper()
	startAt := strings.Index(migration, start)
	endAt := strings.Index(migration, end)
	if startAt < 0 || endAt <= startAt {
		t.Fatalf("cannot isolate SQL function between %q and %q", start, end)
	}
	return migration[startAt:endAt]
}

func assertOrderedSQL(t *testing.T, sql string, fragments []string) {
	t.Helper()
	position := -1
	for _, fragment := range fragments {
		next := strings.Index(sql, fragment)
		if next < 0 || next <= position {
			t.Fatalf("SQL lock/time fragment %q is absent or out of order", fragment)
		}
		position = next
	}
}

func normalizeSQL(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(value)), " ")
}

func readMigration(t *testing.T, name string) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve migration test path")
	}
	path := filepath.Join(filepath.Dir(filename), "../../../migrations", name)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration %s: %v", name, err)
	}
	return string(contents)
}
