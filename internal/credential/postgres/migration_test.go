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
		"status = 'manual_required' and anchored_at is not null and revocation_requested_at is not null and manual_required_at is not null and revoked_at is null",
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

func TestCredentialRevocationMigrationMakesAADIdentityImmutable(t *testing.T) {
	normalized := normalizeMigration(readMigration(t, "000008_credential_revocations.up.sql"))
	if !strings.Contains(normalized, "old.revocation_id is distinct from new.revocation_id") {
		t.Fatal("up migration permits changing the revocation ID bound into reference AAD")
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
		"old.status = 'revoking' and new.status in ('revocation_pending', 'manual_required', 'revoked')",
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
		"lock table action_queue, credential_revocations, credential_revocation_confirmations, audit_records, outbox_events in access exclusive mode",
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
