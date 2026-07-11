package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/seaworld008/aiops-system/internal/credential"
	"github.com/seaworld008/aiops-system/internal/requestmeta"
)

const (
	managementTestRevocationID = "10000000-0000-4000-8000-000000000030"
	managementTestWorkspaceID  = "40000000-0000-4000-8000-000000000030"
	managementTestEnvironment  = "50000000-0000-4000-8000-000000000030"
	managementTestTenantID     = "30000000-0000-4000-8000-000000000030"
)

func TestManagementGetUsesExactScopeSafeProjectionAndAtomicAudit(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err := NewManagement(database)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 11, 4, 0, 0, 0, time.UTC)

	database.ExpectBegin()
	expectManagementScope(database)
	database.ExpectQuery(`SELECT .* FROM credential_revocations AS revocation.*WHERE revocation\.revocation_id = \$1.*revocation\.workspace_id = \$2::uuid.*revocation\.environment_id = \$3::uuid`).
		WithArgs(managementTestRevocationID, managementTestWorkspaceID, managementTestEnvironment).
		WillReturnRows(managementRows().AddRow(managementRowValues(now)...))
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), managementTestTenantID, managementTestWorkspaceID, "USER", "oidc:operator-1",
			"credential.revocation.management.read", managementTestRevocationID, "request-management-1", "trace-management-1",
			pgxmock.AnyArg(), safeManagementDetails{requiredStatus: "MANUAL_REQUIRED", requiredVersion: 9}).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	ctx := requestmeta.With(context.Background(), requestmeta.Metadata{RequestID: "request-management-1", TraceID: "trace-management-1"})
	record, err := store.GetManagement(ctx, credential.ManagementGetRequest{
		Scope: credential.ManagementScope{WorkspaceID: managementTestWorkspaceID, EnvironmentID: managementTestEnvironment},
		Actor: credential.ManagementActor{Subject: "oidc:operator-1"}, RevocationID: managementTestRevocationID,
	})
	if err != nil {
		t.Fatalf("GetManagement() error = %v", err)
	}
	if record.ID != managementTestRevocationID || record.Status != credential.StatusManualRequired ||
		record.ConfirmationCount != 1 || record.PlatformAdminConfirmed || !record.AccessorPresent || record.Version != 9 {
		t.Fatalf("GetManagement() = %#v", record)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestNewManagementRejectsNilDatabase(t *testing.T) {
	t.Parallel()
	store, err := NewManagement(nil)
	if !errors.Is(err, credential.ErrInvalidRevocationRequest) || store != nil {
		t.Fatalf("NewManagement(nil) = %#v, %v", store, err)
	}
}

func TestManagementSQLProjectionsCannotSelectCredentialOrClaimMaterial(t *testing.T) {
	t.Parallel()
	forbidden := []string{
		"accessor_ciphertext", "accessor_hmac", "encryption_key_id", "action_lease_token_sha256",
		"claim_token_sha256", "claimed_by", "completed_claim_token_sha256", "completed_claimed_by",
		"completed_claim_epoch", "runner_id", "child_create_permit_sha256",
	}
	for _, fragment := range forbidden {
		if strings.Contains(strings.ToLower(managementProjection), fragment) {
			t.Fatalf("managementProjection selects forbidden field %q", fragment)
		}
	}
	source, err := os.ReadFile("management.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(source), "SELECT `+revocationProjection") {
		t.Fatal("management query reuses the secret-bearing repository projection")
	}
	rawSQL := regexp.MustCompile("(?s)`([^`]*)`").FindAllSubmatch(source, -1)
	for _, literal := range rawSQL {
		query := strings.ToLower(string(literal[1]))
		if !strings.Contains(query, "select") {
			continue
		}
		for _, fragment := range forbidden {
			if strings.Contains(query, fragment) {
				t.Fatalf("management SELECT query contains forbidden field %q: %s", fragment, query)
			}
		}
	}
}

func TestRepositoryManualTransitionsUseOneStableStatementTimestamp(t *testing.T) {
	t.Parallel()
	source, err := os.ReadFile("repository.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if count := strings.Count(text,
		"manual_required_at = statement_timestamp(), updated_at = statement_timestamp()"); count != 2 {
		t.Fatalf("stable non-fenced manual transition timestamp count = %d, want 2", count)
	}
	start := strings.Index(text, "func (repository *Repository) failClaim")
	end := strings.Index(text, "func (repository *Repository) RequeueManual")
	if start < 0 || end <= start {
		t.Fatal("failClaim source boundaries not found")
	}
	failClaimSource := text[start:end]
	if count := strings.Count(failClaimSource, "SELECT clock_timestamp()"); count != 1 {
		t.Fatalf("failClaim lock-after transition clock reads = %d, want exactly one", count)
	}
	for _, fragment := range []string{
		"where revocation_id = $1 and claimed_by = $2 and claim_token_sha256 = $3 and claim_epoch = $4",
		"for update",
		"retry_cycle_started_at <= $10 - make_interval",
		"else $10 + make_interval",
		"then $10",
		"updated_at = $10",
		"claim_expires_at > $10",
		"manual_required_at = $7, updated_at = $7",
		"claim_expires_at > $7",
	} {
		if !strings.Contains(strings.ToLower(failClaimSource), fragment) {
			t.Errorf("failClaim missing stable timestamp fragment %q", fragment)
		}
	}
}

func TestManagementGetAuditFailureRollsBackAndReturnsNoRecord(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err := NewManagement(database)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 11, 4, 30, 0, 0, time.UTC)
	database.ExpectBegin()
	expectManagementScope(database)
	database.ExpectQuery(`SELECT .* FROM credential_revocations AS revocation`).
		WithArgs(managementTestRevocationID, managementTestWorkspaceID, managementTestEnvironment).
		WillReturnRows(managementRows().AddRow(managementRowValues(now)...))
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), managementTestTenantID, managementTestWorkspaceID, "USER", "oidc:operator-audit-failure",
			"credential.revocation.management.read", managementTestRevocationID, pgxmock.AnyArg(), pgxmock.AnyArg(),
			pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnError(errors.New("forced audit failure"))
	database.ExpectRollback()

	record, err := store.GetManagement(context.Background(), credential.ManagementGetRequest{
		Scope: credential.ManagementScope{WorkspaceID: managementTestWorkspaceID, EnvironmentID: managementTestEnvironment},
		Actor: credential.ManagementActor{Subject: "oidc:operator-audit-failure"}, RevocationID: managementTestRevocationID,
	})
	if !errors.Is(err, credential.ErrRevocationPersistence) || record != (credential.ManagementRecord{}) {
		t.Fatalf("GetManagement(audit failure) = %#v, %v", record, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestManagementListEmptyPageStillResolvesExactScopeAndAuditFailureRollsBack(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err := NewManagement(database)
	if err != nil {
		t.Fatal(err)
	}
	database.ExpectBegin()
	expectManagementScope(database)
	database.ExpectQuery(`SELECT .* FROM credential_revocations AS revocation.*revocation\.workspace_id = \$1::uuid.*revocation\.environment_id = \$2::uuid.*revocation\.status = \$3`).
		WithArgs(managementTestWorkspaceID, managementTestEnvironment, "MANUAL_REQUIRED", nil, nil, credential.DefaultManagementPageSize+1).
		WillReturnRows(managementRows())
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), managementTestTenantID, managementTestWorkspaceID, "USER", "oidc:operator-empty-list",
			"credential.revocation.management.list", managementTestEnvironment, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
			safeManagementListDetails{wantCount: 0, wantNext: false, wantActorAdmin: false}).
		WillReturnError(errors.New("forced empty list audit failure"))
	database.ExpectRollback()

	page, err := store.ListManagement(context.Background(), credential.ManagementListRequest{
		Scope: credential.ManagementScope{WorkspaceID: managementTestWorkspaceID, EnvironmentID: managementTestEnvironment},
		Actor: credential.ManagementActor{Subject: "oidc:operator-empty-list"}, Status: credential.StatusManualRequired,
	})
	if !errors.Is(err, credential.ErrRevocationPersistence) || len(page.Items) != 0 || page.Next != nil {
		t.Fatalf("ListManagement(empty audit failure) = %#v, %v", page, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestManagementRejectsInvalidOrMismatchedSafeProjectionBeforeAudit(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 4, 45, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func([]any)
	}{
		{name: "tenant mismatch", mutate: func(values []any) { values[0] = "30000000-0000-4000-8000-000000000099" }},
		{name: "workspace mismatch", mutate: func(values []any) { values[2] = "40000000-0000-4000-8000-000000000099" }},
		{name: "invalid record", mutate: func(values []any) { values[21] = int64(0) }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			database, err := pgxmock.NewPool()
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			store, err := NewManagement(database)
			if err != nil {
				t.Fatal(err)
			}
			values := managementRowValues(now)
			test.mutate(values)
			database.ExpectBegin()
			expectManagementScope(database)
			database.ExpectQuery(`SELECT .* FROM credential_revocations AS revocation`).
				WithArgs(managementTestRevocationID, managementTestWorkspaceID, managementTestEnvironment).
				WillReturnRows(managementRows().AddRow(values...))
			database.ExpectRollback()

			record, err := store.GetManagement(context.Background(), credential.ManagementGetRequest{
				Scope: credential.ManagementScope{WorkspaceID: managementTestWorkspaceID, EnvironmentID: managementTestEnvironment},
				Actor: credential.ManagementActor{Subject: "oidc:operator-invalid-projection"}, RevocationID: managementTestRevocationID,
			})
			if !errors.Is(err, credential.ErrRevocationPersistence) || record != (credential.ManagementRecord{}) {
				t.Fatalf("GetManagement(invalid projection) = %#v, %v", record, err)
			}
			if err := database.ExpectationsWereMet(); err != nil {
				t.Fatalf("unmet expectations: %v", err)
			}
		})
	}
}

func TestManagementListUsesDescendingKeysetLimitPlusOneAndAuditsReturnedPage(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err := NewManagement(database)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 11, 5, 0, 0, 0, time.UTC)
	after := credential.ManagementCursor{CreatedAt: now.Add(time.Minute), RevocationID: "10000000-0000-4000-8000-000000000099"}
	rows := managementRows()
	for index, suffix := range []string{"33", "32", "31"} {
		values := managementRowValues(now.Add(-time.Duration(index) * time.Minute))
		values[1] = "10000000-0000-4000-8000-0000000000" + suffix
		rows.AddRow(values...)
	}

	database.ExpectBegin()
	expectManagementScope(database)
	database.ExpectQuery(`SELECT .* FROM credential_revocations AS revocation.*revocation\.workspace_id = \$1::uuid.*revocation\.environment_id = \$2::uuid.*revocation\.status = \$3.*revocation\.created_at, revocation\.revocation_id.*<.*ORDER BY revocation\.created_at DESC, revocation\.revocation_id DESC.*LIMIT \$6`).
		WithArgs(managementTestWorkspaceID, managementTestEnvironment, "MANUAL_REQUIRED", after.CreatedAt, after.RevocationID, 3).
		WillReturnRows(rows)
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), managementTestTenantID, managementTestWorkspaceID, "USER", "oidc:platform-admin-1",
			"credential.revocation.management.list", managementTestEnvironment, pgxmock.AnyArg(), pgxmock.AnyArg(),
			pgxmock.AnyArg(), safeManagementListDetails{wantCount: 2, wantNext: true, wantActorAdmin: true}).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	page, err := store.ListManagement(context.Background(), credential.ManagementListRequest{
		Scope:  credential.ManagementScope{WorkspaceID: managementTestWorkspaceID, EnvironmentID: managementTestEnvironment},
		Actor:  credential.ManagementActor{Subject: "oidc:platform-admin-1", PlatformAdmin: true},
		Status: credential.StatusManualRequired, Limit: 2, After: &after,
	})
	if err != nil {
		t.Fatalf("ListManagement() error = %v", err)
	}
	if len(page.Items) != 2 || page.Items[0].ID != "10000000-0000-4000-8000-000000000033" ||
		page.Items[1].ID != "10000000-0000-4000-8000-000000000032" || page.Next == nil ||
		page.Next.RevocationID != page.Items[1].ID || !page.Next.CreatedAt.Equal(page.Items[1].CreatedAt) {
		t.Fatalf("ListManagement() = %#v", page)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestManagementRequeueUsesExactScopeAndAtomicallyWritesSafeAuditAndOutbox(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err := NewManagement(database)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 11, 6, 0, 0, 0, time.UTC)
	values := managementRowValues(now)
	values[8] = "REVOCATION_PENDING"
	values[9] = true
	values[16] = nil
	values[17] = int32(0)
	values[18] = false
	values[21] = int64(10)
	details := managementDetailsMatcher{status: "REVOCATION_PENDING", version: 10, evidenceHash: "", confirmations: 0, adminConfirmed: false}

	database.ExpectBegin()
	expectManagementScope(database)
	database.ExpectQuery(`UPDATE credential_revocations AS revocation.*WHERE revocation\.revocation_id = \$1.*revocation\.workspace_id = \$2::uuid.*revocation\.environment_id = \$3::uuid.*status = 'MANUAL_REQUIRED'.*RETURNING revocation\.revocation_id::text`).
		WithArgs(managementTestRevocationID, managementTestWorkspaceID, managementTestEnvironment).
		WillReturnRows(pgxmock.NewRows([]string{"revocation_id"}).AddRow(managementTestRevocationID))
	expectManagementLock(database, true)
	database.ExpectQuery(`SELECT .* FROM credential_revocations AS revocation.*WHERE revocation\.revocation_id = \$1.*revocation\.workspace_id = \$2::uuid.*revocation\.environment_id = \$3::uuid`).
		WithArgs(managementTestRevocationID, managementTestWorkspaceID, managementTestEnvironment).
		WillReturnRows(managementRows().AddRow(values...))
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), managementTestTenantID, managementTestWorkspaceID, "USER", "oidc:platform-admin-requeue",
			"credential.revocation.requeued", managementTestRevocationID, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), details).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(pgxmock.AnyArg(), managementTestTenantID, managementTestWorkspaceID, managementTestRevocationID,
			int64(10), "credential.revocation.requeued.v1", details).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	record, err := store.RequeueManagement(context.Background(), credential.ManagementRequeueRequest{
		Scope:        credential.ManagementScope{WorkspaceID: managementTestWorkspaceID, EnvironmentID: managementTestEnvironment},
		Actor:        credential.ManagementActor{Subject: "oidc:platform-admin-requeue", PlatformAdmin: true},
		RevocationID: managementTestRevocationID,
	})
	if err != nil || record.Status != credential.StatusRevocationPending || record.Version != 10 || record.EvidenceHash != "" {
		t.Fatalf("RequeueManagement() = %#v, %v", record, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestManagementRequeueRequiresPlatformAdminBeforeDatabaseAccess(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err := NewManagement(database)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.RequeueManagement(context.Background(), credential.ManagementRequeueRequest{
		Scope: credential.ManagementScope{WorkspaceID: managementTestWorkspaceID, EnvironmentID: managementTestEnvironment},
		Actor: credential.ManagementActor{Subject: "oidc:operator-not-admin"}, RevocationID: managementTestRevocationID,
	})
	if !errors.Is(err, credential.ErrInvalidRevocationRequest) || record != (credential.ManagementRecord{}) {
		t.Fatalf("RequeueManagement(non-admin) = %#v, %v", record, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unexpected database access: %v", err)
	}
}

func TestManagementRequeueUnknownIDUsesExactScopedSecondaryReadAndAuditsAttemptWithoutOutbox(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err := NewManagement(database)
	if err != nil {
		t.Fatal(err)
	}
	database.ExpectBegin()
	expectManagementScope(database)
	database.ExpectQuery(`UPDATE credential_revocations AS revocation.*revocation\.revocation_id = \$1.*revocation\.workspace_id = \$2::uuid.*revocation\.environment_id = \$3::uuid`).
		WithArgs(managementTestRevocationID, managementTestWorkspaceID, managementTestEnvironment).
		WillReturnRows(pgxmock.NewRows([]string{"revocation_id"}))
	expectManagementLock(database, false)
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), managementTestTenantID, managementTestWorkspaceID, "USER", "oidc:platform-admin-unknown",
			"credential.revocation.requeue_not_found", managementTestRevocationID, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
			managementAttemptMatcher{decision: "NOT_FOUND", evidenceHash: ""}).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	record, err := store.RequeueManagement(context.Background(), credential.ManagementRequeueRequest{
		Scope:        credential.ManagementScope{WorkspaceID: managementTestWorkspaceID, EnvironmentID: managementTestEnvironment},
		Actor:        credential.ManagementActor{Subject: "oidc:platform-admin-unknown", PlatformAdmin: true},
		RevocationID: managementTestRevocationID,
	})
	if !errors.Is(err, credential.ErrRevocationNotFound) || record != (credential.ManagementRecord{}) {
		t.Fatalf("RequeueManagement(unknown) = %#v, %v", record, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestManagementRequeueReplayAuditsButDoesNotDuplicateOutboxEvent(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err := NewManagement(database)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 11, 6, 30, 0, 0, time.UTC)
	values := managementRowValues(now)
	values[8] = "REVOCATION_PENDING"
	values[16] = nil
	values[17] = int32(0)
	values[18] = false
	details := managementDetailsMatcher{status: "REVOCATION_PENDING", version: 9, evidenceHash: "", confirmations: 0, adminConfirmed: false}
	database.ExpectBegin()
	expectManagementScope(database)
	database.ExpectQuery(`UPDATE credential_revocations AS revocation`).
		WithArgs(managementTestRevocationID, managementTestWorkspaceID, managementTestEnvironment).
		WillReturnRows(pgxmock.NewRows([]string{"revocation_id"}))
	expectManagementLock(database, true)
	database.ExpectQuery(`SELECT .* FROM credential_revocations AS revocation.*revocation\.workspace_id = \$2::uuid.*revocation\.environment_id = \$3::uuid`).
		WithArgs(managementTestRevocationID, managementTestWorkspaceID, managementTestEnvironment).
		WillReturnRows(managementRows().AddRow(values...))
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), managementTestTenantID, managementTestWorkspaceID, "USER", "oidc:platform-admin-replay",
			"credential.revocation.requeue_replayed", managementTestRevocationID, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), details).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	record, err := store.RequeueManagement(context.Background(), credential.ManagementRequeueRequest{
		Scope: credential.ManagementScope{WorkspaceID: managementTestWorkspaceID, EnvironmentID: managementTestEnvironment},
		Actor: credential.ManagementActor{Subject: "oidc:platform-admin-replay", PlatformAdmin: true}, RevocationID: managementTestRevocationID,
	})
	if err != nil || record.Status != credential.StatusRevocationPending || record.Version != 9 {
		t.Fatalf("RequeueManagement(replay) = %#v, %v", record, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations (an outbox write would be unexpected): %v", err)
	}
}

func TestManagementRequeueOutboxFailureRollsBackStateAndAuditTransaction(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err := NewManagement(database)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 11, 6, 45, 0, 0, time.UTC)
	values := managementRowValues(now)
	values[8] = "REVOCATION_PENDING"
	values[16] = nil
	values[17] = int32(0)
	values[18] = false
	values[21] = int64(10)
	details := managementDetailsMatcher{status: "REVOCATION_PENDING", version: 10, evidenceHash: "", confirmations: 0, adminConfirmed: false}
	database.ExpectBegin()
	expectManagementScope(database)
	database.ExpectQuery(`UPDATE credential_revocations AS revocation`).
		WithArgs(managementTestRevocationID, managementTestWorkspaceID, managementTestEnvironment).
		WillReturnRows(pgxmock.NewRows([]string{"revocation_id"}).AddRow(managementTestRevocationID))
	expectManagementLock(database, true)
	database.ExpectQuery(`SELECT .* FROM credential_revocations AS revocation`).
		WithArgs(managementTestRevocationID, managementTestWorkspaceID, managementTestEnvironment).
		WillReturnRows(managementRows().AddRow(values...))
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), managementTestTenantID, managementTestWorkspaceID, "USER", "oidc:platform-admin-rollback",
			"credential.revocation.requeued", managementTestRevocationID, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), details).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(pgxmock.AnyArg(), managementTestTenantID, managementTestWorkspaceID, managementTestRevocationID,
			int64(10), "credential.revocation.requeued.v1", details).
		WillReturnError(errors.New("forced outbox failure"))
	database.ExpectRollback()

	record, err := store.RequeueManagement(context.Background(), credential.ManagementRequeueRequest{
		Scope:        credential.ManagementScope{WorkspaceID: managementTestWorkspaceID, EnvironmentID: managementTestEnvironment},
		Actor:        credential.ManagementActor{Subject: "oidc:platform-admin-rollback", PlatformAdmin: true},
		RevocationID: managementTestRevocationID,
	})
	if !errors.Is(err, credential.ErrRevocationPersistence) || record != (credential.ManagementRecord{}) {
		t.Fatalf("RequeueManagement(outbox failure) = %#v, %v", record, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestManagementFirstConfirmationKeepsManualRequiredAndWritesExactScopedEvent(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err := NewManagement(database)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 11, 7, 0, 0, 0, time.UTC)
	evidenceHash := strings.Repeat("a", 64)
	initial := managementRowValues(now)
	initial[16] = nil
	initial[17] = int32(0)
	initial[18] = false
	final := managementRowValues(now)
	final[16] = evidenceHash
	final[17] = int32(1)
	final[18] = false
	final[21] = int64(10)
	details := managementDetailsMatcher{status: "MANUAL_REQUIRED", version: 10, evidenceHash: evidenceHash, confirmations: 1, adminConfirmed: false}

	database.ExpectBegin()
	expectManagementScope(database)
	expectManagementLock(database, true)
	database.ExpectQuery(`SELECT .* FROM credential_revocations AS revocation.*revocation\.revocation_id = \$1.*revocation\.workspace_id = \$2::uuid.*revocation\.environment_id = \$3::uuid`).
		WithArgs(managementTestRevocationID, managementTestWorkspaceID, managementTestEnvironment).
		WillReturnRows(managementRows().AddRow(initial...))
	database.ExpectQuery(`SELECT confirmation\.subject.*FROM credential_revocation_confirmations AS confirmation.*JOIN credential_revocations AS revocation.*confirmation\.revocation_id = \$1.*revocation\.workspace_id = \$2::uuid.*revocation\.environment_id = \$3::uuid`).
		WithArgs(managementTestRevocationID, managementTestWorkspaceID, managementTestEnvironment).
		WillReturnRows(confirmationRows())
	database.ExpectQuery(`UPDATE credential_revocations AS revocation.*SET evidence_hash = \$4.*revocation\.revocation_id = \$1.*revocation\.workspace_id = \$2::uuid.*revocation\.environment_id = \$3::uuid.*RETURNING revocation\.revocation_id::text`).
		WithArgs(managementTestRevocationID, managementTestWorkspaceID, managementTestEnvironment, evidenceHash).
		WillReturnRows(pgxmock.NewRows([]string{"revocation_id"}).AddRow(managementTestRevocationID))
	database.ExpectQuery(`INSERT INTO credential_revocation_confirmations.*SELECT revocation\.revocation_id, \$4, \$5, \$6.*revocation\.revocation_id = \$1.*revocation\.workspace_id = \$2::uuid.*revocation\.environment_id = \$3::uuid.*RETURNING created_at`).
		WithArgs(managementTestRevocationID, managementTestWorkspaceID, managementTestEnvironment,
			"oidc:operator-confirm", evidenceHash, false).
		WillReturnRows(pgxmock.NewRows([]string{"created_at"}).AddRow(now))
	database.ExpectQuery(`SELECT .* FROM credential_revocations AS revocation.*WHERE revocation\.revocation_id = \$1.*revocation\.workspace_id = \$2::uuid.*revocation\.environment_id = \$3::uuid`).
		WithArgs(managementTestRevocationID, managementTestWorkspaceID, managementTestEnvironment).
		WillReturnRows(managementRows().AddRow(final...))
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), managementTestTenantID, managementTestWorkspaceID, "USER", "oidc:operator-confirm",
			"credential.revocation.confirmation_recorded", managementTestRevocationID, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), details).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(pgxmock.AnyArg(), managementTestTenantID, managementTestWorkspaceID, managementTestRevocationID,
			int64(10), "credential.revocation.confirmation_recorded.v1", details).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	record, err := store.ConfirmManagement(context.Background(), credential.ManagementConfirmationRequest{
		Scope: credential.ManagementScope{WorkspaceID: managementTestWorkspaceID, EnvironmentID: managementTestEnvironment},
		Actor: credential.ManagementActor{Subject: "oidc:operator-confirm"}, RevocationID: managementTestRevocationID,
		EvidenceHash: evidenceHash,
	})
	if err != nil || record.Status != credential.StatusManualRequired || record.EvidenceHash != evidenceHash ||
		record.ConfirmationCount != 1 || record.PlatformAdminConfirmed {
		t.Fatalf("ConfirmManagement(first) = %#v, %v", record, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestManagementSecondDistinctConfirmationRequiresAnAdminAndClearsDecryptableReference(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err := NewManagement(database)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	evidenceHash := strings.Repeat("b", 64)
	initial := managementRowValues(now)
	initial[16] = evidenceHash
	initial[17] = int32(1)
	initial[18] = false
	final := managementRowValues(now)
	final[8] = "REVOKED"
	final[9] = false
	final[16] = evidenceHash
	final[17] = int32(2)
	final[18] = true
	final[20] = now
	final[21] = int64(10)
	details := managementDetailsMatcher{status: "REVOKED", version: 10, evidenceHash: evidenceHash, confirmations: 2, adminConfirmed: true}

	database.ExpectBegin()
	expectManagementScope(database)
	expectManagementLock(database, true)
	database.ExpectQuery(`SELECT .* FROM credential_revocations AS revocation`).
		WithArgs(managementTestRevocationID, managementTestWorkspaceID, managementTestEnvironment).
		WillReturnRows(managementRows().AddRow(initial...))
	database.ExpectQuery(`SELECT confirmation\.subject.*FROM credential_revocation_confirmations AS confirmation.*revocation\.workspace_id = \$2::uuid.*revocation\.environment_id = \$3::uuid`).
		WithArgs(managementTestRevocationID, managementTestWorkspaceID, managementTestEnvironment).
		WillReturnRows(confirmationRows().AddRow("oidc:operator-first", evidenceHash, false, now.Add(-time.Minute)))
	database.ExpectQuery(`INSERT INTO credential_revocation_confirmations.*SELECT revocation\.revocation_id, \$4, \$5, \$6.*revocation\.workspace_id = \$2::uuid.*revocation\.environment_id = \$3::uuid`).
		WithArgs(managementTestRevocationID, managementTestWorkspaceID, managementTestEnvironment,
			"oidc:platform-admin-second", evidenceHash, true).
		WillReturnRows(pgxmock.NewRows([]string{"created_at"}).AddRow(now))
	database.ExpectQuery(`UPDATE credential_revocations AS revocation.*SET status = 'REVOKED', accessor_ciphertext = NULL, encryption_key_id = NULL.*revocation\.workspace_id = \$2::uuid.*revocation\.environment_id = \$3::uuid.*RETURNING revocation\.revocation_id::text`).
		WithArgs(managementTestRevocationID, managementTestWorkspaceID, managementTestEnvironment, evidenceHash).
		WillReturnRows(pgxmock.NewRows([]string{"revocation_id"}).AddRow(managementTestRevocationID))
	database.ExpectQuery(`SELECT .* FROM credential_revocations AS revocation.*WHERE revocation\.revocation_id = \$1.*revocation\.workspace_id = \$2::uuid.*revocation\.environment_id = \$3::uuid`).
		WithArgs(managementTestRevocationID, managementTestWorkspaceID, managementTestEnvironment).
		WillReturnRows(managementRows().AddRow(final...))
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), managementTestTenantID, managementTestWorkspaceID, "USER", "oidc:platform-admin-second",
			"credential.revocation.externally_confirmed", managementTestRevocationID, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), details).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(pgxmock.AnyArg(), managementTestTenantID, managementTestWorkspaceID, managementTestRevocationID,
			int64(10), "credential.revocation.externally_confirmed.v1", details).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	record, err := store.ConfirmManagement(context.Background(), credential.ManagementConfirmationRequest{
		Scope:        credential.ManagementScope{WorkspaceID: managementTestWorkspaceID, EnvironmentID: managementTestEnvironment},
		Actor:        credential.ManagementActor{Subject: "oidc:platform-admin-second", PlatformAdmin: true},
		RevocationID: managementTestRevocationID, EvidenceHash: evidenceHash,
	})
	if err != nil || record.Status != credential.StatusRevoked || record.AccessorPresent ||
		record.ConfirmationCount != 2 || !record.PlatformAdminConfirmed {
		t.Fatalf("ConfirmManagement(second) = %#v, %v", record, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestManagementConfirmationReplayAuditsWithoutDuplicatingOutbox(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err := NewManagement(database)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 11, 8, 30, 0, 0, time.UTC)
	evidenceHash := strings.Repeat("c", 64)
	values := managementRowValues(now)
	values[8] = "REVOKED"
	values[9] = false
	values[16] = evidenceHash
	values[17] = int32(2)
	values[18] = true
	values[20] = now
	details := managementDetailsMatcher{status: "REVOKED", version: 9, evidenceHash: evidenceHash, confirmations: 2, adminConfirmed: true}
	database.ExpectBegin()
	expectManagementScope(database)
	expectManagementLock(database, true)
	database.ExpectQuery(`SELECT .* FROM credential_revocations AS revocation`).
		WithArgs(managementTestRevocationID, managementTestWorkspaceID, managementTestEnvironment).
		WillReturnRows(managementRows().AddRow(values...))
	database.ExpectQuery(`SELECT confirmation\.subject.*FROM credential_revocation_confirmations AS confirmation`).
		WithArgs(managementTestRevocationID, managementTestWorkspaceID, managementTestEnvironment).
		WillReturnRows(confirmationRows().
			AddRow("oidc:operator-first", evidenceHash, false, now.Add(-time.Minute)).
			AddRow("oidc:platform-admin-replay", evidenceHash, true, now))
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), managementTestTenantID, managementTestWorkspaceID, "USER", "oidc:platform-admin-replay",
			"credential.revocation.confirmation_replayed", managementTestRevocationID, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), details).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	record, err := store.ConfirmManagement(context.Background(), credential.ManagementConfirmationRequest{
		Scope:        credential.ManagementScope{WorkspaceID: managementTestWorkspaceID, EnvironmentID: managementTestEnvironment},
		Actor:        credential.ManagementActor{Subject: "oidc:platform-admin-replay", PlatformAdmin: true},
		RevocationID: managementTestRevocationID, EvidenceHash: evidenceHash,
	})
	if err != nil || record.Status != credential.StatusRevoked || record.ConfirmationCount != 2 || !record.PlatformAdminConfirmed {
		t.Fatalf("ConfirmManagement(replay) = %#v, %v", record, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations (an outbox write would be unexpected): %v", err)
	}
}

func TestManagementSecondConfirmationRequiresAtLeastOnePlatformAdminAndAuditsRejection(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err := NewManagement(database)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 11, 8, 45, 0, 0, time.UTC)
	evidenceHash := strings.Repeat("d", 64)
	values := managementRowValues(now)
	values[16] = evidenceHash
	values[17] = int32(1)
	values[18] = false
	details := managementDetailsMatcher{status: "MANUAL_REQUIRED", version: 9, evidenceHash: evidenceHash, confirmations: 1, adminConfirmed: false}
	database.ExpectBegin()
	expectManagementScope(database)
	expectManagementLock(database, true)
	database.ExpectQuery(`SELECT .* FROM credential_revocations AS revocation`).
		WithArgs(managementTestRevocationID, managementTestWorkspaceID, managementTestEnvironment).
		WillReturnRows(managementRows().AddRow(values...))
	database.ExpectQuery(`SELECT confirmation\.subject.*FROM credential_revocation_confirmations AS confirmation`).
		WithArgs(managementTestRevocationID, managementTestWorkspaceID, managementTestEnvironment).
		WillReturnRows(confirmationRows().AddRow("oidc:operator-first", evidenceHash, false, now.Add(-time.Minute)))
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), managementTestTenantID, managementTestWorkspaceID, "USER", "oidc:operator-second",
			"credential.revocation.confirmation_rejected", managementTestRevocationID, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), details).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	record, err := store.ConfirmManagement(context.Background(), credential.ManagementConfirmationRequest{
		Scope: credential.ManagementScope{WorkspaceID: managementTestWorkspaceID, EnvironmentID: managementTestEnvironment},
		Actor: credential.ManagementActor{Subject: "oidc:operator-second"}, RevocationID: managementTestRevocationID,
		EvidenceHash: evidenceHash,
	})
	if !errors.Is(err, credential.ErrPlatformAdminRequired) || record != (credential.ManagementRecord{}) {
		t.Fatalf("ConfirmManagement(second non-admin) = %#v, %v", record, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations (an outbox write would be unexpected): %v", err)
	}
}

type safeManagementDetails struct {
	requiredStatus  string
	requiredVersion float64
}

type managementDetailsMatcher struct {
	status         string
	version        float64
	evidenceHash   string
	confirmations  float64
	adminConfirmed bool
}

type managementAttemptMatcher struct {
	decision     string
	evidenceHash string
}

func (matcher managementAttemptMatcher) Match(value any) bool {
	encoded, ok := value.(string)
	if !ok || strings.Contains(encoded, "ciphertext") || strings.Contains(encoded, "claim_token") ||
		strings.Contains(encoded, "claimed_by") || strings.Contains(encoded, "encryption_key_id") {
		return false
	}
	var details map[string]any
	if json.Unmarshal([]byte(encoded), &details) != nil {
		return false
	}
	return details["decision"] == matcher.decision && details["status"] == "" && details["version"] == float64(0) &&
		details["evidence_hash"] == matcher.evidenceHash && details["confirmation_count"] == float64(0) &&
		details["platform_admin_confirmed"] == false && details["failure_count"] == float64(0) &&
		details["failure_code"] == "" && details["failure_detail_sha256"] == ""
}

func (matcher managementDetailsMatcher) Match(value any) bool {
	encoded, ok := value.(string)
	if !ok {
		return false
	}
	for _, forbidden := range []string{
		"ciphertext", "accessor_hmac", "encryption_key_id", "claimed_by", "claim_token", "lease_token", "worker-canary",
	} {
		if strings.Contains(encoded, forbidden) {
			return false
		}
	}
	var details map[string]any
	if json.Unmarshal([]byte(encoded), &details) != nil {
		return false
	}
	return details["status"] == matcher.status && details["version"] == matcher.version &&
		details["evidence_hash"] == matcher.evidenceHash && details["confirmation_count"] == matcher.confirmations &&
		details["platform_admin_confirmed"] == matcher.adminConfirmed && details["failure_count"] == float64(3) &&
		details["failure_code"] == "PERMISSION_DENIED" && details["failure_detail_sha256"] == strings.Repeat("f", 64)
}

type safeManagementListDetails struct {
	wantCount      int
	wantNext       bool
	wantActorAdmin bool
}

func (matcher safeManagementListDetails) Match(value any) bool {
	encoded, ok := value.(string)
	if !ok || strings.Contains(encoded, "ciphertext") || strings.Contains(encoded, "claim_token") ||
		strings.Contains(encoded, "claimed_by") || strings.Contains(encoded, "encryption_key_id") {
		return false
	}
	var details struct {
		Status                 string           `json:"status"`
		Version                int64            `json:"version"`
		EvidenceHash           string           `json:"evidence_hash"`
		ConfirmationCount      int              `json:"confirmation_count"`
		PlatformAdminConfirmed bool             `json:"platform_admin_confirmed"`
		FailureCount           int              `json:"failure_count"`
		FailureCode            string           `json:"failure_code"`
		FailureDetailSHA256    string           `json:"failure_detail_sha256"`
		ReturnedCount          int              `json:"returned_count"`
		NextPage               bool             `json:"next_page"`
		Records                []map[string]any `json:"records"`
		ActorPlatformAdmin     bool             `json:"actor_platform_admin"`
	}
	if json.Unmarshal([]byte(encoded), &details) != nil || details.Status != "MANUAL_REQUIRED" ||
		details.ReturnedCount != matcher.wantCount || details.NextPage != matcher.wantNext ||
		len(details.Records) != matcher.wantCount || details.ActorPlatformAdmin != matcher.wantActorAdmin ||
		details.Version != 0 || details.EvidenceHash != "" || details.ConfirmationCount != 0 ||
		details.PlatformAdminConfirmed || details.FailureCount != 0 || details.FailureCode != "" ||
		details.FailureDetailSHA256 != "" {
		return false
	}
	for _, record := range details.Records {
		for _, field := range []string{"status", "version", "evidence_hash", "confirmation_count", "platform_admin_confirmed", "failure_count", "failure_code", "failure_detail_sha256"} {
			if _, ok := record[field]; !ok {
				return false
			}
		}
	}
	return true
}

func (matcher safeManagementDetails) Match(value any) bool {
	encoded, ok := value.(string)
	if !ok {
		return false
	}
	for _, forbidden := range []string{
		"ciphertext-canary", "accessor-canary", "lease-token-canary", "claim-token-canary", "worker-canary",
		"accessor_ciphertext", "accessor_hmac", "encryption_key_id", "claimed_by", "claim_token",
	} {
		if strings.Contains(encoded, forbidden) {
			return false
		}
	}
	var details map[string]any
	if json.Unmarshal([]byte(encoded), &details) != nil {
		return false
	}
	return details["status"] == matcher.requiredStatus && details["version"] == matcher.requiredVersion &&
		details["evidence_hash"] == strings.Repeat("e", 64) && details["confirmation_count"] == float64(1) &&
		details["platform_admin_confirmed"] == false && details["failure_count"] == float64(3) &&
		details["failure_code"] == "PERMISSION_DENIED" && details["failure_detail_sha256"] == strings.Repeat("f", 64)
}

func managementRows() *pgxmock.Rows {
	return pgxmock.NewRows([]string{
		"tenant_id", "revocation_id", "workspace_id", "environment_id", "action_id", "target_key", "action_type",
		"connector_id", "status", "accessor_present", "credential_expires_at", "attempt", "failure_count", "failure_code",
		"failure_detail_sha256", "available_at", "evidence_hash", "confirmation_count", "platform_admin_confirmed",
		"manual_required_at", "revoked_at", "version", "created_at", "updated_at",
	})
}

func confirmationRows() *pgxmock.Rows {
	return pgxmock.NewRows([]string{"subject", "evidence_hash", "platform_admin", "created_at"})
}

func expectManagementScope(database pgxmock.PgxPoolIface) {
	database.ExpectQuery(`SELECT tenant_id::text FROM environments WHERE workspace_id = \$1::uuid AND id = \$2::uuid`).
		WithArgs(managementTestWorkspaceID, managementTestEnvironment).
		WillReturnRows(pgxmock.NewRows([]string{"tenant_id"}).AddRow(managementTestTenantID))
}

func expectManagementLock(database pgxmock.PgxPoolIface, found bool) {
	rows := pgxmock.NewRows([]string{"revocation_id"})
	if found {
		rows.AddRow(managementTestRevocationID)
	}
	database.ExpectQuery(`SELECT revocation\.revocation_id::text FROM credential_revocations AS revocation.*revocation\.revocation_id = \$1.*revocation\.workspace_id = \$2::uuid.*revocation\.environment_id = \$3::uuid.*FOR UPDATE OF revocation`).
		WithArgs(managementTestRevocationID, managementTestWorkspaceID, managementTestEnvironment).
		WillReturnRows(rows)
}

func managementRowValues(now time.Time) []any {
	return []any{
		managementTestTenantID, managementTestRevocationID, managementTestWorkspaceID, managementTestEnvironment,
		"action-management-1", "cluster-a/payments", "KUBERNETES_ROLLOUT_RESTART", "kubernetes-nonprod",
		"MANUAL_REQUIRED", true, now.Add(5 * time.Minute), int32(4), int32(3), "PERMISSION_DENIED", strings.Repeat("f", 64),
		now, strings.Repeat("e", 64), int32(1), false, now.Add(-time.Minute), nil, int64(9), now.Add(-10 * time.Minute), now,
	}
}
