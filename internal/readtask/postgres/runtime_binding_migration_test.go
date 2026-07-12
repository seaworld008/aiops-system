package postgres_test

import (
	"strings"
	"testing"
)

func TestInvestigationRuntimeBindingMigrationIsAtomicAndDrained(t *testing.T) {
	for _, name := range []string{
		"000013_investigation_runtime_binding.up.sql",
		"000013_investigation_runtime_binding.down.sql",
	} {
		migration := strings.TrimSpace(readMigration(t, name))
		if !strings.HasPrefix(migration, "BEGIN;") || !strings.HasSuffix(migration, "COMMIT;") {
			t.Fatalf("%s must be transactionally wrapped in BEGIN/COMMIT", name)
		}
		normalized := normalizeSQL(migration)
		for _, required := range []string{
			"set local lock_timeout = '5s'",
			"pg_catalog.set_config",
			"pg_catalog.quote_ident(current_schema()) || ', pg_catalog, pg_temp'",
			"lock table investigations, tool_invocations, investigation_task_attempts, runner_evidence_receipts, investigation_idempotency_records in access exclusive mode",
		} {
			if !strings.Contains(normalized, required) {
				t.Errorf("%s missing migration boundary %q", name, required)
			}
		}
	}

	up := normalizedMigration(t, "000013_investigation_runtime_binding.up.sql")
	for _, required := range []string{
		"if exists (select 1 from investigation_task_attempts where status in ('leased', 'running')",
		"or exists (select 1 from investigations where runtime_schema_version = 'investigation-runtime.v1' and status in ('queued', 'running') and plan_schema_version is null",
		"request_hash_version = 'investigation.create.v1'",
		"errcode = '55000'",
		"unsafe investigation runtime binding upgrade: active unbound investigation state remains",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("000013 up must fail closed before binding cutover; missing %q", required)
		}
	}
}

func TestInvestigationRuntimeBindingChecksCannotBeBypassedWithPartialNullTuples(t *testing.T) {
	up := normalizedMigration(t, "000013_investigation_runtime_binding.up.sql")
	for _, required := range []string{
		"runtime_schema_version is not null and runtime_schema_version = 'investigation-runtime.v1'",
		"plan_schema_version is not null and plan_schema_version = 'investigation-plan-manifest.v1'",
		"read_runtime_schema_version is not null and read_runtime_schema_version = 'read-task-runtime-binding.v1'",
		"plan_manifest_digest is not null and plan_registry_digest is not null",
		"connector_digest is not null and target_digest is not null",
		"runtime_bound_at is not null",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("000013 binding CHECK remains NULL-bypassable; missing %q", required)
		}
	}
}

func TestInvestigationRuntimeBindingPersistsImmutablePlanAndTaskBindingsWithoutBackfill(t *testing.T) {
	up := normalizedMigration(t, "000013_investigation_runtime_binding.up.sql")
	for _, required := range []string{
		"alter table investigations add column plan_schema_version text",
		"add column plan_manifest_digest text",
		"add column plan_registry_digest text",
		"add column plan_profile_digest text",
		"add column plan_tasks_hash text",
		"plan_schema_version = 'investigation-plan-manifest.v1'",
		"request_hash_version = 'investigation.create.v1'",
		"request_hash_version = 'investigation.create.v2'",
		"plan_manifest_digest is not null and plan_registry_digest is not null",
		"plan_profile_digest is not null and plan_tasks_hash is not null",
		"constraint investigations_plan_binding_scope_uk unique",
		"alter table tool_invocations add column read_runtime_schema_version text",
		"add column connector_digest text",
		"add column target_digest text",
		"add column executor_digest text",
		"add column runtime_digest text",
		"add column runtime_bound_at timestamptz",
		"read_runtime_schema_version = 'read-task-runtime-binding.v1'",
		"connector_digest is not null and target_digest is not null",
		"executor_digest is not null and runtime_digest is not null and runtime_bound_at is not null",
		"right(tool_name, 64) = connector_digest",
		"runtime_bound_at = created_at",
		"constraint tool_invocations_runtime_binding_scope_uk unique",
		"create trigger investigations_plan_binding_immutable",
		"create trigger tool_invocations_runtime_binding_immutable",
		"create trigger investigations_plan_binding_insert_guard",
		"new.request_hash_version is distinct from 'investigation.create.v2'",
		"constraint = 'investigations_plan_binding_insert_guard'",
		"create trigger tool_invocations_runtime_binding_insert_guard",
		"new.read_runtime_schema_version is distinct from 'read-task-runtime-binding.v1'",
		"from investigations as parent",
		"parent.request_hash_version = 'investigation.create.v2'",
		"constraint = 'tool_invocations_runtime_binding_parent_guard'",
		"create trigger investigation_idempotency_create_v2_insert_guard",
		"constraint = 'investigation_idempotency_create_v2_parent_guard'",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("000013 plan/task binding missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"update investigations set plan_",
		"update tool_invocations set read_runtime_",
		"coalesce(plan_manifest_digest",
		"coalesce(runtime_digest",
	} {
		if strings.Contains(up, forbidden) {
			t.Errorf("000013 must not synthesize or backfill persisted bindings: found %q", forbidden)
		}
	}
}

func TestInvestigationRuntimeBindingCopiesTrustedSnapshotsIntoNewAttempts(t *testing.T) {
	up := normalizedMigration(t, "000013_investigation_runtime_binding.up.sql")
	for _, required := range []string{
		"alter table investigation_task_attempts add column plan_schema_version text",
		"add column plan_manifest_digest text",
		"add column plan_registry_digest text",
		"add column plan_profile_digest text",
		"add column plan_tasks_hash text",
		"add column read_runtime_schema_version text",
		"add column connector_digest text",
		"add column target_digest text",
		"add column executor_digest text",
		"add column runtime_digest text",
		"add column runtime_bound_at timestamptz",
		"constraint investigation_task_attempts_plan_binding_fk foreign key",
		"references investigations",
		"constraint investigation_task_attempts_runtime_binding_fk foreign key",
		"references tool_invocations",
		"constraint investigation_task_attempts_runtime_receipt_fence_uk unique",
		"create or replace function bind_investigation_task_attempt_runtime()",
		"from tool_invocations as task",
		"task.read_runtime_schema_version = 'read-task-runtime-binding.v1'",
		"for share of task",
		"from investigations as parent",
		"parent.plan_schema_version = 'investigation-plan-manifest.v1'",
		"for share of parent",
		"new.plan_manifest_digest := trusted_plan_manifest_digest",
		"new.runtime_digest := trusted_runtime_digest",
		"create trigger investigation_task_attempts_runtime_binding_guard",
		"create trigger investigation_task_attempts_runtime_binding_immutable",
		"constraint = 'investigation_task_attempts_runtime_binding_guard'",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("000013 attempt snapshot binding missing %q", required)
		}
	}

	bind := functionSQL(t, up,
		"create or replace function bind_investigation_task_attempt_runtime()",
		"create trigger investigation_task_attempts_runtime_binding_guard")
	assertOrderedSQL(t, bind, []string{
		"from tool_invocations as task",
		"for share of task",
		"from investigations as parent",
		"for share of parent",
		"new.plan_schema_version := trusted_plan_schema_version",
		"new.read_runtime_schema_version := trusted_runtime_schema_version",
	})
}

func TestInvestigationRuntimeBindingRequiresV3ReceiptsWithExactAttemptSnapshot(t *testing.T) {
	up := normalizedMigration(t, "000013_investigation_runtime_binding.up.sql")
	for _, required := range []string{
		"alter table runner_evidence_receipts add column plan_schema_version text",
		"schema_version = 'runner-evidence.v1' and lease_epoch is null",
		"schema_version = 'runner-evidence.v2' and lease_epoch is not null and lease_epoch > 0",
		"schema_version = 'runner-evidence.v3' and lease_epoch is not null and lease_epoch > 0",
		"constraint runner_evidence_receipts_runtime_attempt_fence_fk foreign key",
		"references investigation_task_attempts",
		"if new.schema_version <> 'runner-evidence.v3' or new.lease_epoch is null then",
		"attempt.status = 'completed'",
		"attempt.request_hash = new.request_hash",
		"attempt.receipt_hash = new.receipt_hash",
		"new.plan_schema_version := trusted_plan_schema_version",
		"new.runtime_digest := trusted_runtime_digest",
		"receipt.schema_version = 'runner-evidence.v3'",
		"receipt.plan_manifest_digest = new.plan_manifest_digest",
		"receipt.runtime_digest = new.runtime_digest",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("000013 v3 receipt binding missing %q", required)
		}
	}

	receipt := functionSQL(t, up,
		"create or replace function validate_runner_evidence_receipt_insert()",
		"create or replace function validate_investigation_task_attempt_completion()")
	assertOrderedSQL(t, receipt, []string{
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

func TestInvestigationRuntimeBindingVersionsCompletionHashesWithoutRewritingHistory(t *testing.T) {
	up := normalizedMigration(t, "000013_investigation_runtime_binding.up.sql")
	for _, required := range []string{
		"alter table investigation_task_attempts add column request_hash_version text",
		"add column receipt_hash_version text",
		"status = 'completed' and request_hash_version is not null and receipt_hash_version is not null and request_hash_version = 'read-task-completion-request.v3' and receipt_hash_version = 'read-task-completion-receipt.v3'",
		"status <> 'completed' and request_hash_version is null and receipt_hash_version is null",
		"runtime_bound_at is null and request_hash_version is null and receipt_hash_version is null",
		"certificate_sha256, request_hash, request_hash_version, receipt_hash, receipt_hash_version",
		"alter table runner_evidence_receipts add column request_hash_version text",
		"schema_version = 'runner-evidence.v1' and lease_epoch is null and request_hash_version is null and receipt_hash_version is null",
		"schema_version = 'runner-evidence.v2' and lease_epoch is not null and lease_epoch > 0 and request_hash_version is null and receipt_hash_version is null",
		"schema_version = 'runner-evidence.v3' and lease_epoch is not null and lease_epoch > 0 and request_hash_version is not null and receipt_hash_version is not null and request_hash_version = 'read-task-completion-request.v3' and receipt_hash_version = 'read-task-completion-receipt.v3'",
		"if new.request_hash_version is distinct from 'read-task-completion-request.v3' or new.receipt_hash_version is distinct from 'read-task-completion-receipt.v3' then",
		"attempt.request_hash_version = 'read-task-completion-request.v3'",
		"attempt.receipt_hash_version = 'read-task-completion-receipt.v3'",
		"receipt.request_hash_version = new.request_hash_version",
		"receipt.receipt_hash_version = new.receipt_hash_version",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("000013 completion hash version binding missing %q", required)
		}
	}

	down := normalizedMigration(t, "000013_investigation_runtime_binding.down.sql")
	for _, required := range []string{
		"request_hash_version is not null or receipt_hash_version is not null",
		"drop column request_hash_version",
		"drop column receipt_hash_version",
		"drop trigger tool_invocations_runtime_binding_insert_guard",
		"drop trigger investigations_plan_binding_insert_guard",
		"drop trigger investigation_idempotency_create_v2_insert_guard",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("000013 completion hash version rollback missing %q", required)
		}
	}
}

func TestInvestigationRuntimeBindingDownRefusesAnyDurableBindingLoss(t *testing.T) {
	down := normalizedMigration(t, "000013_investigation_runtime_binding.down.sql")
	for _, required := range []string{
		"if exists (select 1 from investigation_task_attempts where status in ('leased', 'running')",
		"or exists (select 1 from investigations where plan_schema_version is not null",
		"or exists (select 1 from tool_invocations where read_runtime_schema_version is not null",
		"or exists (select 1 from investigation_task_attempts where request_hash_version is not null or receipt_hash_version is not null",
		"or plan_schema_version is not null or read_runtime_schema_version is not null",
		"or exists (select 1 from runner_evidence_receipts where schema_version = 'runner-evidence.v3'",
		"or exists (select 1 from investigation_idempotency_records where operation = 'create_investigation' and request_hash_version = 'investigation.create.v2'",
		"errcode = '55000'",
		"unsafe investigation runtime binding rollback: durable binding state remains",
		"drop column plan_schema_version",
		"drop column read_runtime_schema_version",
		"request_hash_version = 'investigation.create.v1'",
		"schema_version in ('runner-evidence.v1', 'runner-evidence.v2')",
		"receipt.schema_version = 'runner-evidence.v2'",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("000013 down safety/restore missing %q", required)
		}
	}

	assertOrderedSQL(t, down, []string{
		"drop constraint runner_evidence_receipts_runtime_attempt_fence_fk",
		"drop constraint investigation_task_attempts_runtime_receipt_fence_uk",
		"drop constraint tool_invocations_runtime_binding_scope_uk",
		"drop constraint investigations_plan_binding_scope_uk",
	})
}
