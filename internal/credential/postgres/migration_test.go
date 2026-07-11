package postgres

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestCredentialRevocationMigrationDefinesSecretSafeFencedLifecycle(t *testing.T) {
	up := readMigration(t, "000008_credential_revocations.up.sql")
	normalized := normalizeMigration(up)

	required := []string{
		"begin;",
		"create table credential_revocations",
		"create table credential_revocation_confirmations",
		"status in ('prepared', 'anchored', 'active', 'revocation_pending', 'revoking', 'revoked', 'manual_required', 'no_credential')",
		"unique (action_id, action_lease_epoch)",
		"foreign key (action_id) references action_queue (action_id) on delete restrict",
		"foreign key (tenant_id, workspace_id) references workspaces (tenant_id, id) on delete restrict",
		"foreign key (tenant_id, workspace_id, environment_id) references environments (tenant_id, workspace_id, id) on delete restrict",
		"foreign key (tenant_id, runner_id) references runner_registrations (tenant_id, runner_id) on delete restrict",
		"accessor_ciphertext bytea",
		"accessor_hmac bytea",
		"encryption_key_id text",
		"action_lease_token_sha256 text not null",
		"issuer_revision text not null",
		"child_create_permit_sha256 text not null",
		"child_create_authorized_at timestamptz",
		"child_create_ttl_seconds integer",
		"claim_token_sha256 text",
		"completed_claim_token_sha256 text",
		"octet_length(accessor_hmac) = 32",
		"octet_length(accessor_ciphertext) between 29 and 4124",
		"octet_length(action_lease_token_sha256) = 64",
		"octet_length(claim_token_sha256) = 64",
		"status = 'no_credential' and accessor_ciphertext is null and accessor_hmac is null and encryption_key_id is null",
		"status = 'revoked' and accessor_ciphertext is null and accessor_hmac is not null and encryption_key_id is null",
		"status = 'revoking' and claimed_by is not null and claim_token_sha256 is not null",
		"claim_expires_at > last_heartbeat_at",
		"credential_expires_at > created_at",
		"status = 'manual_required' and anchored_at is not null and revocation_requested_at is not null",
		"retry_cycle_started_at is not null and manual_required_at is not null and failure_count > 0",
		"failure_count > 0 and revoked_at is null",
		"failure_code in ('issuer_unavailable', 'rate_limited', 'timeout', 'authentication_failed', 'permission_denied', 'reference_not_found', 'invalid_reference', 'unknown')",
		"octet_length(failure_detail_sha256) = 64",
		"primary key (revocation_id, subject)",
		"subject like 'oidc:%'",
		"evidence_hash text not null",
		"platform_admin boolean not null",
		"reject_credential_revocation_reparenting",
		"reject_credential_confirmation_mutation",
		"before update or delete on credential_revocation_confirmations",
		"before truncate on credential_revocation_confirmations",
		"create constraint trigger credential_revocations_confirmation_shape",
		"create constraint trigger credential_revocation_confirmations_parent_shape",
		"deferrable initially deferred",
		"commit;",
	}
	for _, fragment := range required {
		if !strings.Contains(normalized, fragment) {
			t.Errorf("up migration missing %q", fragment)
		}
	}

	if strings.Contains(normalized, "foreign key (tenant_id, workspace_id, environment_id, action_id") ||
		strings.Contains(normalized, "references action_queue (runner_tenant_id") {
		t.Fatal("migration binds revocations to mutable action_queue active-lease columns")
	}
	for _, forbidden := range []*regexp.Regexp{
		regexp.MustCompile(`(?i)\baccessor\s+(?:text|varchar|bytea)`),
		regexp.MustCompile(`(?i)\b(?:child_token|dynamic_secret|lease_id)\b\s+(?:text|varchar|bytea)`),
		regexp.MustCompile(`(?i)\bclaim_token\b\s+(?:text|varchar|bytea|uuid)`),
	} {
		if forbidden.MatchString(up) {
			t.Fatalf("up migration contains forbidden plaintext column shape %q", forbidden.String())
		}
	}
}

func TestCredentialRevocationMigrationRequiresExactlyOneRevokedProof(t *testing.T) {
	normalized := normalizeMigration(readMigration(t, "000008_credential_revocations.up.sql"))
	for _, fragment := range []string{
		"constraint credential_revocations_revoked_proof_ck check",
		"status <> 'revoked' and completed_claim_epoch is null and completed_claim_token_sha256 is null and completed_claimed_by is null",
		"evidence_hash is null and completed_claim_epoch is not null and completed_claim_token_sha256 is not null and completed_claimed_by is not null",
		"evidence_hash is not null and completed_claim_epoch is null and completed_claim_token_sha256 is null and completed_claimed_by is null",
	} {
		if !strings.Contains(normalized, fragment) {
			t.Errorf("up migration missing revoked proof invariant %q", fragment)
		}
	}
}

func TestCredentialRevocationMigrationCapsCredentialTTLForPreparedRecoverySafety(t *testing.T) {
	normalized := normalizeMigration(readMigration(t, "000008_credential_revocations.up.sql"))
	if !strings.Contains(normalized, "credential_expires_at <= created_at + interval '15 minutes'") {
		t.Fatal("up migration does not durably cap credential TTL at 15 minutes")
	}
	if !strings.Contains(normalized,
		"create index credential_revocations_prepared_recovery_idx on credential_revocations (credential_expires_at, revocation_id) where status = 'prepared'") {
		t.Fatal("up migration does not index expired PREPARED recovery candidates")
	}
}

func TestCredentialRevocationMigrationBindsCompleteSignedCredentialSelection(t *testing.T) {
	normalized := normalizeMigration(readMigration(t, "000008_credential_revocations.up.sql"))
	for _, fragment := range []string{
		"action_type text not null",
		"credential_ttl_seconds integer not null",
		"credential_ttl_seconds between 1 and 900",
		"credential_expires_at <= created_at + make_interval(secs => credential_ttl_seconds)",
		"action.envelope ->> 'action_type' = new.action_type",
		"action.envelope #>> '{credential_scope,connector_id}' = new.connector_id",
		"action.envelope #>> '{credential_scope,permission}' = new.scope_permission",
		"action.envelope #>> '{credential_scope,resource}' = new.scope_resource",
		"action.envelope #>> '{credential_scope,ttl_seconds}' = new.credential_ttl_seconds::text",
		"old.action_type is distinct from new.action_type",
		"old.credential_ttl_seconds is distinct from new.credential_ttl_seconds",
	} {
		if !strings.Contains(normalized, fragment) {
			t.Errorf("up migration missing signed credential binding %q", fragment)
		}
	}
}

func TestCredentialRevocationMigrationRejectsFutureCreationTime(t *testing.T) {
	normalized := normalizeMigration(readMigration(t, "000008_credential_revocations.up.sql"))
	if !strings.Contains(normalized, "new.created_at > clock_timestamp()") {
		t.Fatal("up migration does not reject a future credential revocation creation time")
	}
}

func TestCredentialRevocationMigrationCapsExpiryAtActionAuthorization(t *testing.T) {
	normalized := normalizeMigration(readMigration(t, "000008_credential_revocations.up.sql"))
	if !strings.Contains(normalized, "new.credential_expires_at <= action.authorization_expires_at") {
		t.Fatal("up migration does not cap credential expiry at the immutable action authorization")
	}
}

func TestCredentialRevocationMigrationAddsAtomicActionCredentialMarker(t *testing.T) {
	normalized := normalizeMigration(readMigration(t, "000008_credential_revocations.up.sql"))
	for _, fragment := range []string{
		"lock table action_queue, execution_leases in access exclusive mode",
		"add column credential_expected boolean not null default false",
		"add column credential_lease_epoch bigint",
		"constraint action_queue_credential_marker_shape_ck check",
		"not credential_expected and credential_lease_epoch is null",
		"credential_expected and runner_pool = 'write' and production = false",
		"credential_lease_epoch is not null",
		"credential_lease_epoch > 0 and credential_lease_epoch = lease_epoch",
		"status <> 'queued'",
		"constraint credential_revocations_non_production_ck check (production = false)",
		"constraint action_queue_no_active_production_write_ck check ( runner_pool <> 'write' or production = false or status not in ('leased', 'running', 'finalizing', 'uncertain') )",
		"constraint execution_leases_no_active_production_write_ck check ( runner_pool <> 'write' or production = false or status not in ('leased', 'running', 'uncertain') )",
	} {
		if !strings.Contains(normalized, fragment) {
			t.Errorf("up migration missing atomic credential marker invariant %q", fragment)
		}
	}
}

func TestCredentialRevocationMigrationClosesActionMarkerAndCleanupBypasses(t *testing.T) {
	normalized := normalizeMigration(readMigration(t, "000008_credential_revocations.up.sql"))
	for _, fragment := range []string{
		"create or replace function enforce_action_queue_credential_cleanup()",
		"where runner_pool = 'write' and status in ('leased', 'running', 'finalizing', 'uncertain')",
		"where runner_pool = 'write' and status in ('leased', 'running', 'uncertain')",
		"old.credential_expected = false and new.credential_expected = true",
		") is not true or not exists ( select 1 from credential_revocations as revocation",
		"old.status = new.status",
		"old.status in ('leased', 'running')",
		"new.credential_lease_epoch = old.lease_epoch",
		"old.status = 'leased' and new.status = 'queued'",
		"old.status in ('running', 'finalizing', 'uncertain')",
		"old.status in ('leased', 'running') then old.lease_token_sha256",
		"else old.completed_lease_token_sha256",
		"constraint = 'action_queue_credential_marker_guard'",
		"constraint = 'action_queue_credential_cleanup_gate'",
		"if old.status = 'leased' and new.status = 'queued' then new.credential_expected := false; new.credential_lease_epoch := null; end if;",
		"create trigger action_queue_credential_cleanup_gate before insert or update on action_queue",
		"create or replace function validate_credential_revocation_action_marker()",
		"create constraint trigger credential_revocations_action_marker_shape",
		"after insert on credential_revocations",
		"deferrable initially deferred",
		"new.action_lease_token_sha256",
		"revocation.tenant_id = new.runner_tenant_id",
		"revocation.workspace_id = new.runner_workspace_id",
		"revocation.environment_id = new.runner_environment_id",
		"revocation.action_lease_token_sha256 = new.lease_token_sha256",
		"terminal.action_lease_token_sha256 = fence_token_sha256",
		"action.credential_expected = true",
		"action.credential_lease_epoch = new.action_lease_epoch",
	} {
		if !strings.Contains(normalized, fragment) {
			t.Errorf("up migration missing credential cleanup bypass defense %q", fragment)
		}
	}
	if count := strings.Count(normalized, "constraint = 'action_queue_credential_cleanup_gate'"); count != 1 {
		t.Fatalf("cleanup-pending constraint name occurs %d times, want only the active-to-inactive terminal gate", count)
	}
	functionStart := strings.Index(normalized, "create or replace function enforce_action_queue_credential_cleanup()")
	triggerStart := strings.Index(normalized, "create trigger action_queue_credential_cleanup_gate")
	if functionStart < 0 || triggerStart < 0 || triggerStart <= functionStart {
		t.Fatal("action credential cleanup trigger function boundaries are missing")
	}
	actionGuard := normalized[functionStart:triggerStart]
	for _, fragment := range []string{
		"if tg_op = 'insert' then",
		"if new.credential_expected = true or new.credential_lease_epoch is not null then",
		"constraint = 'action_queue_credential_marker_guard'",
		"return new; end if;",
	} {
		if !strings.Contains(actionGuard, fragment) {
			t.Errorf("action marker INSERT guard missing %q", fragment)
		}
	}
	for _, predicate := range []string{
		"terminal.action_id = old.action_id",
		"terminal.tenant_id = old.runner_tenant_id",
		"terminal.workspace_id = old.runner_workspace_id",
		"terminal.environment_id = old.runner_environment_id",
		"terminal.target_key = old.target_key",
		"terminal.production = old.production",
		"terminal.runner_id = old.runner_id",
		"terminal.action_lease_epoch = old.lease_epoch",
		"terminal.action_lease_token_sha256 = fence_token_sha256",
		"terminal.status in ('revoked', 'no_credential')",
	} {
		if !strings.Contains(normalized, predicate) {
			t.Errorf("up migration cleanup gate missing full-fence predicate %q", predicate)
		}
	}
	terminalQuery := strings.Index(normalized, "terminal.status in ('revoked', 'no_credential')")
	autoClear := strings.Index(normalized, "new.credential_expected := false")
	if terminalQuery < 0 || autoClear < 0 || autoClear < terminalQuery {
		t.Fatal("LEASED to QUEUED marker auto-clear must run only after the exact terminal cleanup query")
	}
}

func TestCredentialRevocationMigrationRoutesSubmissionIdentityOffHeartbeatTrigger(t *testing.T) {
	normalized := normalizeMigration(readMigration(t, "000008_credential_revocations.up.sql"))
	identityFunction := strings.Index(normalized, "create or replace function reject_action_queue_submission_identity_mutation()")
	identityTrigger := strings.Index(normalized, "create trigger action_queue_submission_identity_guard")
	terminalFunction := strings.Index(normalized, "create or replace function reject_action_queue_terminal_mutation()")
	terminalTrigger := strings.Index(normalized, "create trigger action_queue_00_terminal_immutable_guard")
	cleanupFunction := strings.Index(normalized, "create or replace function enforce_action_queue_credential_cleanup()")
	cleanupTrigger := strings.Index(normalized, "create trigger action_queue_credential_cleanup_gate")
	if identityFunction < 0 || identityTrigger <= identityFunction {
		t.Fatal("submission identity must use a dedicated trigger function")
	}
	if cleanupFunction < 0 || cleanupTrigger <= cleanupFunction {
		t.Fatal("credential cleanup trigger function boundaries are missing")
	}
	if terminalFunction < 0 || terminalTrigger <= terminalFunction || cleanupFunction <= terminalTrigger {
		t.Fatal("terminal immutability must use a dedicated trigger before the cleanup hot path")
	}

	identityGuard := normalized[identityFunction:identityTrigger]
	for _, field := range []string{
		"action_id",
		"envelope",
		"submission_hash",
		"idempotency_key",
		"request_hash",
		"request_hash_version",
		"plan_hash",
		"workspace_id",
		"environment_id",
		"target_key",
		"environment_revision",
		"authorization_expires_at",
		"runner_pool",
		"production",
		"created_at",
	} {
		fragment := "old." + field + " is distinct from new." + field
		if !strings.Contains(identityGuard, fragment) {
			t.Errorf("dedicated submission identity guard missing %q", fragment)
		}
	}
	if !strings.Contains(normalized,
		"before update of action_id, envelope, submission_hash, idempotency_key, request_hash, request_hash_version, plan_hash, workspace_id, environment_id, target_key, environment_revision, authorization_expires_at, runner_pool, production, created_at on action_queue") {
		t.Fatal("submission identity trigger must be column-routed away from heartbeat updates")
	}
	if strings.Contains(normalized[cleanupFunction:cleanupTrigger], "old is distinct from new") {
		t.Fatal("heartbeat cleanup trigger still performs a whole-row comparison")
	}
	if !strings.Contains(normalized[cleanupFunction:cleanupTrigger],
		"if old.status = 'finalizing' and new.status in ('succeeded', 'failed', 'uncertain') then if new.status is distinct from old.completion_status or not exists") {
		t.Fatal("FINALIZING receipt lookup must be structurally nested outside the heartbeat hot path")
	}
	if !strings.Contains(normalized,
		"create trigger action_queue_00_terminal_immutable_guard before update on action_queue for each row when (old.status in ('succeeded', 'failed', 'cancelled')) execute function reject_action_queue_terminal_mutation()") {
		t.Fatal("terminal whole-row comparison must be routed by a dedicated WHEN trigger")
	}

	down := normalizeMigration(readMigration(t, "000008_credential_revocations.down.sql"))
	for _, fragment := range []string{
		"drop trigger action_queue_00_terminal_immutable_guard on action_queue",
		"drop function reject_action_queue_terminal_mutation()",
		"drop trigger action_queue_submission_identity_guard on action_queue",
		"drop function reject_action_queue_submission_identity_mutation()",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("down migration missing dedicated submission identity rollback %q", fragment)
		}
	}
}

func TestCredentialRevocationMigrationFreezesActionSubmissionIdentityAndActiveFence(t *testing.T) {
	normalized := normalizeMigration(readMigration(t, "000008_credential_revocations.up.sql"))
	identityFunction := strings.Index(normalized, "create or replace function reject_action_queue_submission_identity_mutation()")
	identityTrigger := strings.Index(normalized, "create trigger action_queue_submission_identity_guard")
	if identityFunction < 0 || identityTrigger <= identityFunction {
		t.Fatal("action submission identity trigger function boundaries are missing")
	}
	identityGuard := normalized[identityFunction:identityTrigger]
	cleanupFunction := strings.Index(normalized, "create or replace function enforce_action_queue_credential_cleanup()")
	cleanupTrigger := strings.Index(normalized, "create trigger action_queue_credential_cleanup_gate")
	if cleanupFunction < 0 || cleanupTrigger <= cleanupFunction {
		t.Fatal("action credential cleanup trigger function boundaries are missing")
	}
	actionGuard := normalized[cleanupFunction:cleanupTrigger]

	for _, field := range []string{
		"action_id",
		"envelope",
		"submission_hash",
		"idempotency_key",
		"request_hash",
		"request_hash_version",
		"plan_hash",
		"workspace_id",
		"environment_id",
		"target_key",
		"environment_revision",
		"authorization_expires_at",
		"runner_pool",
		"production",
		"created_at",
	} {
		fragment := "old." + field + " is distinct from new." + field
		if !strings.Contains(identityGuard, fragment) {
			t.Errorf("action submission identity guard missing NULL-safe comparison %q", fragment)
		}
	}
	if strings.Contains(identityGuard, "old.not_before is distinct from new.not_before") {
		t.Fatal("action submission identity guard must allow not_before scheduling updates")
	}
	if !strings.Contains(identityGuard, "constraint = 'action_queue_submission_identity_guard'") {
		t.Fatal("dedicated submission identity guard must report its stable constraint name")
	}

	for _, fragment := range []string{
		"old.status in ('leased', 'running', 'finalizing', 'uncertain', 'succeeded', 'failed') and new.status in ('leased', 'running', 'finalizing', 'uncertain', 'succeeded', 'failed')",
		"old.runner_id is distinct from new.runner_id",
		"old.runner_tenant_id is distinct from new.runner_tenant_id",
		"old.runner_workspace_id is distinct from new.runner_workspace_id",
		"old.runner_environment_id is distinct from new.runner_environment_id",
		"old.scope_revision is distinct from new.scope_revision",
		"old.lease_epoch is distinct from new.lease_epoch",
		"case when old.status in ('leased', 'running') then old.lease_token_sha256 else old.completed_lease_token_sha256 end is distinct from case when new.status in ('leased', 'running') then new.lease_token_sha256 else new.completed_lease_token_sha256 end",
		"old.status in ('finalizing', 'uncertain', 'succeeded', 'failed') and old.completed_lease_epoch is distinct from new.completed_lease_epoch",
		"new.status in ('finalizing', 'uncertain', 'succeeded', 'failed') and new.completed_lease_epoch is distinct from new.lease_epoch",
		"constraint = 'action_queue_active_fence_guard'",
	} {
		if !strings.Contains(actionGuard, fragment) {
			t.Errorf("action active fence guard missing %q", fragment)
		}
	}
}

func TestCredentialRevocationMigrationEnforcesActionStateGraph(t *testing.T) {
	normalized := normalizeMigration(readMigration(t, "000008_credential_revocations.up.sql"))
	functionStart := strings.Index(normalized, "create or replace function enforce_action_queue_credential_cleanup()")
	triggerStart := strings.Index(normalized, "create trigger action_queue_credential_cleanup_gate")
	if functionStart < 0 || triggerStart <= functionStart {
		t.Fatal("action execution proof trigger function boundaries are missing")
	}
	actionGuard := normalized[functionStart:triggerStart]
	for _, fragment := range []string{
		"new.status <> 'queued'",
		"old.status is distinct from new.status",
		"old.status = 'queued' and new.status in ('leased', 'cancelled')",
		"old.status = 'leased' and new.status in ('running', 'queued', 'failed', 'cancelled')",
		"old.status = 'running' and new.status in ('finalizing', 'uncertain')",
		"old.status = 'finalizing' and new.status in ('succeeded', 'failed', 'uncertain')",
		"old.status = 'uncertain' and new.status in ('succeeded', 'failed')",
		"constraint = 'action_queue_state_transition_guard'",
	} {
		if !strings.Contains(actionGuard, fragment) {
			t.Errorf("action state graph missing %q", fragment)
		}
	}
}

func TestCredentialRevocationMigrationFreezesActionTerminalAndResultProof(t *testing.T) {
	normalized := normalizeMigration(readMigration(t, "000008_credential_revocations.up.sql"))
	terminalFunction := strings.Index(normalized, "create or replace function reject_action_queue_terminal_mutation()")
	terminalTrigger := strings.Index(normalized, "create trigger action_queue_00_terminal_immutable_guard")
	functionStart := strings.Index(normalized, "create or replace function enforce_action_queue_credential_cleanup()")
	triggerStart := strings.Index(normalized, "create trigger action_queue_credential_cleanup_gate")
	if terminalFunction < 0 || terminalTrigger <= terminalFunction || functionStart <= terminalTrigger || triggerStart <= functionStart {
		t.Fatal("action execution proof trigger function boundaries are missing")
	}
	terminalGuard := normalized[terminalFunction:terminalTrigger]
	actionGuard := normalized[functionStart:triggerStart]
	for _, fragment := range []string{
		"old is distinct from new",
		"constraint = 'action_queue_terminal_immutable_guard'",
	} {
		if !strings.Contains(terminalGuard, fragment) {
			t.Errorf("action terminal guard missing %q", fragment)
		}
	}
	for _, fragment := range []string{
		"old.status in ('finalizing', 'uncertain', 'succeeded', 'failed', 'cancelled')",
		"old.result_hash is distinct from new.result_hash",
		"old.completion_status is distinct from new.completion_status",
		"constraint = 'action_queue_result_proof_guard'",
	} {
		if !strings.Contains(actionGuard, fragment) {
			t.Errorf("action terminal/result proof guard missing %q", fragment)
		}
	}
}

func TestCredentialRevocationMigrationRejectsActionQueueRemoval(t *testing.T) {
	normalized := normalizeMigration(readMigration(t, "000008_credential_revocations.up.sql"))
	for _, fragment := range []string{
		"create or replace function reject_action_queue_removal()",
		"constraint = 'action_queue_history_immutable_guard'",
		"create trigger action_queue_no_delete before delete on action_queue for each row execute function reject_action_queue_removal()",
		"create trigger action_queue_no_truncate before truncate on action_queue for each statement execute function reject_action_queue_removal()",
	} {
		if !strings.Contains(normalized, fragment) {
			t.Errorf("action queue removal guard missing %q", fragment)
		}
	}

	down := normalizeMigration(readMigration(t, "000008_credential_revocations.down.sql"))
	for _, fragment := range []string{
		"drop trigger action_queue_no_truncate on action_queue",
		"drop trigger action_queue_no_delete on action_queue",
		"drop function reject_action_queue_removal()",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("down migration missing action queue removal guard rollback %q", fragment)
		}
	}
}

func TestCredentialRevocationMigrationRequiresExactActionCompletionProof(t *testing.T) {
	normalized := normalizeMigration(readMigration(t, "000008_credential_revocations.up.sql"))
	functionStart := strings.Index(normalized, "create or replace function enforce_action_queue_credential_cleanup()")
	triggerStart := strings.Index(normalized, "create trigger action_queue_credential_cleanup_gate")
	if functionStart < 0 || triggerStart <= functionStart {
		t.Fatal("action execution proof trigger function boundaries are missing")
	}
	actionGuard := normalized[functionStart:triggerStart]
	for _, fragment := range []string{
		"old.status = 'leased' and new.status = 'failed'",
		"new.completion_status is distinct from 'failed'",
		"constraint = 'action_queue_rejection_proof_guard'",
		"old.status = 'finalizing' and new.status in ('succeeded', 'failed', 'uncertain')",
		"new.status is distinct from old.completion_status",
		"from runner_result_receipts as receipt",
		"receipt.action_id = new.action_id",
		"receipt.tenant_id = new.runner_tenant_id",
		"receipt.workspace_id = new.runner_workspace_id",
		"receipt.environment_id = new.runner_environment_id",
		"receipt.runner_id = new.runner_id",
		"receipt.lease_epoch = new.lease_epoch",
		"receipt.scope_revision = new.scope_revision",
		"receipt.receipt_hash = new.result_hash",
		"receipt.completion_status = new.completion_status",
		"receipt.schema_version = 'runner-result.v1'",
		"constraint = 'action_queue_result_receipt_guard'",
		"old.status = 'uncertain' and new.status in ('succeeded', 'failed')",
		"new.reconciliation_id is null",
		"new.reconciliation_actor is null",
		"new.reconciliation_result_hash is null",
		"new.reconciled_at is null",
		"constraint = 'action_queue_reconciliation_proof_guard'",
	} {
		if !strings.Contains(actionGuard, fragment) {
			t.Errorf("action completion proof guard missing %q", fragment)
		}
	}
}

func TestCredentialRevocationMigrationDefersFinalizingReceiptProofUntilCommit(t *testing.T) {
	normalized := normalizeMigration(readMigration(t, "000008_credential_revocations.up.sql"))
	for _, fragment := range []string{
		"create or replace function validate_action_queue_finalizing_receipt()",
		"from runner_result_receipts as receipt",
		"receipt.action_id = new.action_id",
		"receipt.tenant_id = new.runner_tenant_id",
		"receipt.workspace_id = new.runner_workspace_id",
		"receipt.environment_id = new.runner_environment_id",
		"receipt.runner_id = new.runner_id",
		"receipt.lease_epoch = new.lease_epoch",
		"receipt.scope_revision = new.scope_revision",
		"receipt.receipt_hash = new.result_hash",
		"receipt.completion_status = new.completion_status",
		"receipt.schema_version = 'runner-result.v1'",
		"constraint = 'action_queue_finalizing_receipt_shape'",
		"create constraint trigger action_queue_finalizing_receipt_shape after insert or update on action_queue deferrable initially deferred for each row when (new.status = 'finalizing')",
	} {
		if !strings.Contains(normalized, fragment) {
			t.Errorf("deferred FINALIZING receipt proof missing %q", fragment)
		}
	}

	down := normalizeMigration(readMigration(t, "000008_credential_revocations.down.sql"))
	for _, fragment := range []string{
		"drop trigger action_queue_finalizing_receipt_shape on action_queue",
		"drop function validate_action_queue_finalizing_receipt()",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("down migration missing FINALIZING receipt proof rollback %q", fragment)
		}
	}
}

func TestCredentialRevocationMigrationRejectsPreexistingFinalizingWithoutExactReceipt(t *testing.T) {
	normalized := normalizeMigration(readMigration(t, "000008_credential_revocations.up.sql"))
	for _, fragment := range []string{
		"lock table action_queue, execution_leases in access exclusive mode",
		"from action_queue as finalizing where finalizing.status = 'finalizing' and not exists",
		"receipt.action_id = finalizing.action_id",
		"receipt.tenant_id = finalizing.runner_tenant_id",
		"receipt.workspace_id = finalizing.runner_workspace_id",
		"receipt.environment_id = finalizing.runner_environment_id",
		"receipt.runner_id = finalizing.runner_id",
		"receipt.lease_epoch = finalizing.lease_epoch",
		"receipt.scope_revision = finalizing.scope_revision",
		"receipt.receipt_hash = finalizing.result_hash",
		"receipt.completion_status = finalizing.completion_status",
		"receipt.schema_version = 'runner-result.v1'",
		"message = 'unsafe credential revocation upgrade: finalizing actions require exact runner result receipts'",
		"constraint = 'action_queue_finalizing_receipt_shape'",
	} {
		if !strings.Contains(normalized, fragment) {
			t.Errorf("FINALIZING upgrade preflight missing %q", fragment)
		}
	}
}

func TestCredentialRevocationMigrationsDrainBothWriteLeaseStores(t *testing.T) {
	for _, test := range []struct {
		name                string
		actionStates        string
		executionLeaseState string
	}{
		{
			name:                "000008_credential_revocations.up.sql",
			actionStates:        "from action_queue where runner_pool = 'write' and status in ('leased', 'running', 'finalizing', 'uncertain')",
			executionLeaseState: "from execution_leases where runner_pool = 'write' and status in ('leased', 'running', 'uncertain')",
		},
		{
			name:                "000008_credential_revocations.down.sql",
			actionStates:        "from action_queue where runner_pool = 'write' and status in ('leased', 'running', 'finalizing', 'uncertain')",
			executionLeaseState: "from execution_leases where runner_pool = 'write' and status in ('leased', 'running', 'uncertain')",
		},
	} {
		normalized := normalizeMigration(readMigration(t, test.name))
		if !strings.Contains(normalized, test.actionStates) {
			t.Errorf("%s does not drain active WRITE action_queue states", test.name)
		}
		if !strings.Contains(normalized, test.executionLeaseState) {
			t.Errorf("%s does not drain active WRITE execution_leases states", test.name)
		}
	}
}

func TestCredentialRevocationMigrationMakesAADIdentityImmutable(t *testing.T) {
	normalized := normalizeMigration(readMigration(t, "000008_credential_revocations.up.sql"))
	if !strings.Contains(normalized, "old.revocation_id is distinct from new.revocation_id") {
		t.Fatal("up migration permits changing the revocation ID bound into reference AAD")
	}
	if !strings.Contains(normalized, "old.issuer_revision is distinct from new.issuer_revision") {
		t.Fatal("up migration permits changing the issuer revision bound into reference AAD")
	}
	if !strings.Contains(normalized, "octet_length(issuer_revision) between 1 and 256") {
		t.Fatal("up migration does not constrain the issuer revision")
	}
}

func TestCredentialRevocationMigrationEnforcesInitialAndUpdatedLifecycleEdges(t *testing.T) {
	up := normalizeMigration(readMigration(t, "000008_credential_revocations.up.sql"))
	down := normalizeMigration(readMigration(t, "000008_credential_revocations.down.sql"))
	for _, fragment := range []string{
		"create or replace function enforce_credential_revocation_transition()",
		"if tg_op = 'insert' then",
		"new.status <> 'prepared' or new.version <> 1",
		"old.status in ('revoked', 'no_credential')",
		"new.version <> old.version + 1",
		"new.updated_at < old.updated_at",
		"new.claim_epoch < old.claim_epoch",
		"new.attempt < old.attempt",
		"new.failure_count < old.failure_count",
		"old.status = 'prepared' and new.status = 'anchored' and old.child_create_authorized_at is not null",
		"old.status = 'prepared' and new.status = 'no_credential'",
		"old.status = 'anchored' and new.status in ('active', 'revocation_pending')",
		"old.status = 'active' and new.status = 'revocation_pending'",
		"old.status = 'revocation_pending' and new.status = 'revoking'",
		"old.status = 'revoking' and new.status = 'revocation_pending'",
		"old.status = 'revoking' and new.status in ('manual_required', 'revoked')",
		"old.status = 'manual_required' and new.status in ('revocation_pending', 'revoked')",
		"create trigger credential_revocations_state_machine before insert or update on credential_revocations",
		"errcode = '55000'",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("up migration missing lifecycle invariant %q", fragment)
		}
	}
	if !strings.Contains(down, "drop function enforce_credential_revocation_transition()") {
		t.Fatal("down migration does not remove credential lifecycle transition function")
	}
}

func TestCredentialRevocationMigrationEnforcesSingleUseChildCreationAuthorization(t *testing.T) {
	normalized := normalizeMigration(readMigration(t, "000008_credential_revocations.up.sql"))
	for _, fragment := range []string{
		"octet_length(child_create_permit_sha256) = 64",
		"child_create_authorized_at is null and child_create_ttl_seconds is null",
		"child_create_authorized_at + child_create_ttl_seconds * interval '1 second' + interval '15 seconds' <= credential_expires_at",
		"new.child_create_authorized_at is not null or new.child_create_ttl_seconds is not null",
		"credential child creation authorization is immutable",
		"old.child_create_permit_sha256 is distinct from new.child_create_permit_sha256",
		"old.credential_expires_at <= clock_timestamp() - interval '1 minute'",
	} {
		if !strings.Contains(normalized, fragment) {
			t.Errorf("up migration missing child-create invariant %q", fragment)
		}
	}
}

func TestCredentialRevocationMigrationEnforcesRecoverableRetryCycles(t *testing.T) {
	normalized := normalizeMigration(readMigration(t, "000008_credential_revocations.up.sql"))
	for _, fragment := range []string{
		"retry_cycle_attempt_base integer not null default 0",
		"retry_cycle_started_at timestamptz",
		"retry_cycle_attempt_base >= 0 and retry_cycle_attempt_base <= attempt",
		"create index credential_revocations_managed_recovery_idx",
		"where status in ('anchored', 'active')",
		"create index credential_revocations_exhausted_recovery_idx",
		"include (attempt, retry_cycle_attempt_base, claim_expires_at)",
		"old.attempt - old.retry_cycle_attempt_base < 12",
		"old.retry_cycle_started_at > clock_timestamp() - interval '2 hours'",
		"old.attempt - old.retry_cycle_attempt_base >= 12",
		"old.retry_cycle_started_at <= clock_timestamp() - interval '2 hours'",
		"new.status := 'manual_required'",
		"new.retry_cycle_attempt_base = old.attempt",
		"credential revocation retry cycle may only reset after authorization loss or manual repair",
		"credential revocation may only reclaim an expired non-exhausted claim",
	} {
		if !strings.Contains(normalized, fragment) {
			t.Errorf("up migration missing retry-cycle invariant %q", fragment)
		}
	}
}

func TestCredentialRevocationMigrationPreventsAuditTruncateBypass(t *testing.T) {
	up := normalizeMigration(readMigration(t, "000008_credential_revocations.up.sql"))
	down := normalizeMigration(readMigration(t, "000008_credential_revocations.down.sql"))
	for _, fragment := range []string{
		"create trigger audit_records_no_truncate",
		"before truncate on audit_records",
		"for each statement execute function reject_audit_mutation()",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("up migration missing audit truncate defense %q", fragment)
		}
	}
	if !strings.Contains(down, "drop trigger audit_records_no_truncate on audit_records") {
		t.Fatal("down migration does not remove the M2A audit truncate trigger")
	}
}

func TestCredentialRevocationMigrationDocumentsCoordinatedWriteRunnerCutover(t *testing.T) {
	up := strings.ToLower(readMigration(t, "000008_credential_revocations.up.sql"))
	for _, warning := range []string{
		"stop and drain all old write runners",
		"mixed old/new write runners are unsupported",
		"do not enable the production write switch",
	} {
		if !strings.Contains(up, warning) {
			t.Errorf("up migration missing deployment warning %q", warning)
		}
	}
}

func TestCredentialRevocationMigrationsBlockEveryActiveWriteState(t *testing.T) {
	for _, name := range []string{"000008_credential_revocations.up.sql", "000008_credential_revocations.down.sql"} {
		normalized := normalizeMigration(readMigration(t, name))
		if !strings.Contains(normalized,
			"runner_pool = 'write' and status in ('leased', 'running', 'finalizing', 'uncertain')") {
			t.Errorf("%s does not block all active/uncertain WRITE states", name)
		}
	}
}

func TestCredentialRevocationDownMigrationGuardsUnsafeOrUndeliveredState(t *testing.T) {
	down := readMigration(t, "000008_credential_revocations.down.sql")
	normalized := normalizeMigration(down)
	required := []string{
		"begin;",
		"lock table action_queue, execution_leases, credential_revocations, credential_revocation_confirmations, audit_records, outbox_events in access exclusive mode",
		"status not in ('revoked', 'no_credential')",
		"accessor_ciphertext is not null",
		"encryption_key_id is not null",
		"evidence_hash is not null",
		"exists ( select 1 from credential_revocation_confirmations",
		"event_type like 'credential.revocation.%' and delivered_at is null",
		"errcode = '55000'",
		"drop table credential_revocation_confirmations",
		"drop table credential_revocations",
		"commit;",
	}
	for _, fragment := range required {
		if !strings.Contains(normalized, fragment) {
			t.Errorf("down migration missing %q", fragment)
		}
	}
	if !strings.Contains(strings.ToLower(down), "only revoked/no_credential rows without evidence and with fully delivered outbox events are safe to discard") {
		t.Fatal("down migration does not document the narrow terminal-state discard rule")
	}
}

func TestCredentialRevocationDownMigrationRemovesMarkerDefensesInSafeOrder(t *testing.T) {
	down := normalizeMigration(readMigration(t, "000008_credential_revocations.down.sql"))
	for _, fragment := range []string{
		"lock table action_queue, execution_leases, credential_revocations, credential_revocation_confirmations, audit_records, outbox_events in access exclusive mode",
		"drop trigger action_queue_finalizing_receipt_shape on action_queue",
		"drop function validate_action_queue_finalizing_receipt()",
		"drop trigger action_queue_submission_identity_guard on action_queue",
		"drop function reject_action_queue_submission_identity_mutation()",
		"drop trigger action_queue_credential_cleanup_gate on action_queue",
		"drop function enforce_action_queue_credential_cleanup()",
		"drop trigger credential_revocations_action_marker_shape on credential_revocations",
		"drop function validate_credential_revocation_action_marker()",
		"drop constraint action_queue_credential_marker_shape_ck",
		"drop constraint action_queue_no_active_production_write_ck",
		"drop column credential_lease_epoch",
		"drop column credential_expected",
		"drop constraint execution_leases_no_active_production_write_ck",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("down migration missing marker rollback step %q", fragment)
		}
	}

	receiptTrigger := strings.Index(down, "drop trigger action_queue_finalizing_receipt_shape on action_queue")
	identityTrigger := strings.Index(down, "drop trigger action_queue_submission_identity_guard on action_queue")
	actionTrigger := strings.Index(down, "drop trigger action_queue_credential_cleanup_gate on action_queue")
	markerTrigger := strings.Index(down, "drop trigger credential_revocations_action_marker_shape on credential_revocations")
	revocationTable := strings.Index(down, "drop table credential_revocations")
	markerColumn := strings.Index(down, "drop column credential_expected")
	legacyConstraint := strings.Index(down, "drop constraint execution_leases_no_active_production_write_ck")
	if receiptTrigger < 0 || identityTrigger < 0 || actionTrigger < 0 || markerTrigger < 0 || revocationTable < 0 ||
		markerColumn < 0 || legacyConstraint < 0 || receiptTrigger > revocationTable || identityTrigger > revocationTable ||
		actionTrigger > revocationTable || markerTrigger > revocationTable || revocationTable > markerColumn || markerColumn > legacyConstraint {
		t.Fatal("down migration removes credential marker defenses in an unsafe order")
	}
}

func readMigration(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join("..", "..", "..", "migrations", name)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(contents)
}

func normalizeMigration(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}
