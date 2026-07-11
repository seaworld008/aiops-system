package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/seaworld008/aiops-system/internal/credential"
	"github.com/seaworld008/aiops-system/internal/execution"
	"github.com/seaworld008/aiops-system/internal/executionlease"
)

const runnerRevocationCertificateSHA256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

func TestClaimRevocationRunnerTxDefersSecretsUntilCommittedTicketFinalization(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	protector := repositoryTestProtector(t)
	rawToken := strings.Repeat("a", 64)
	repository, err := New(database, protector, Options{TokenSource: func() (string, error) { return rawToken, nil }})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 11, 19, 0, 0, 0, time.UTC)
	protected := protectTestReference(t, protector, []byte("vault-accessor-canary"))
	tokenDigest := credential.SHA256Hex([]byte(rawToken))
	scope := runnerCredentialScope(t, executionlease.PoolWrite)

	database.ExpectBegin()
	tx, err := database.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	expectRunnerRevocationPrincipal(database, scope.RunnerID(), scope.TenantID(), scope.ScopeRevision(), runnerRevocationCertificateSHA256)
	database.ExpectQuery(`(?s)WITH exact_scope.*unnest\(\$3::text\[\], \$4::text\[\]\).*JOIN runner_scope_bindings.*candidate\.tenant_id = \$2::uuid.*FOR UPDATE OF candidate SKIP LOCKED`).
		WithArgs(scope.RunnerID(), scope.TenantID(), []string{postgresTestWorkspaceID}, []string{postgresTestEnvironment},
			credential.MaxRevocationAttempts, credential.MaxRevocationElapsed.Seconds()).
		WillReturnRows(pgxmock.NewRows([]string{"revocation_id"}).AddRow(postgresTestRevocationID))
	database.ExpectQuery(`(?s)WITH claim_boundary AS \(\s*SELECT clock_timestamp\(\) AS boundary_at\s*\).*UPDATE credential_revocations AS candidate.*claimed_at = claim_boundary\.boundary_at, last_heartbeat_at = claim_boundary\.boundary_at.*claim_expires_at = claim_boundary\.boundary_at \+ interval '30 seconds'.*heartbeat_seq = 0.*updated_at = claim_boundary\.boundary_at.*FROM claim_boundary.*registration\.credential_revocation_capable = true.*binding\.workspace_id = candidate\.workspace_id.*certificate\.certificate_sha256 = \$8.*RETURNING`).
		WithArgs(postgresTestRevocationID, scope.RunnerID(), tokenDigest, scope.TenantID(),
			credential.MaxRevocationAttempts, credential.MaxRevocationElapsed.Seconds(), scope.ScopeRevision(),
			runnerRevocationCertificateSHA256).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusRevoking, Protected: protected, AvailableAt: now.Add(-time.Second), Version: 5,
			ClaimEpoch: 1, ClaimedBy: scope.RunnerID(), ClaimTokenSHA256: tokenDigest,
			ClaimedAt: now, ClaimExpiresAt: now.Add(30 * time.Second), HeartbeatAt: now, Attempt: 1,
		}))
	database.ExpectQuery(`SELECT heartbeat_seq FROM credential_revocations`).
		WithArgs(postgresTestRevocationID).
		WillReturnRows(pgxmock.NewRows([]string{"heartbeat_seq"}).AddRow(int64(0)))
	expectRunnerRevocationStateChange(database, "credential.revocation.claimed", "credential.revocation.claimed.v1", 5)

	ticket, err := repository.ClaimRevocationRunnerTx(context.Background(), tx, scope, runnerRevocationCertificateSHA256)
	if err != nil || ticket == nil {
		t.Fatalf("ClaimRevocationRunnerTx() = %#v, %v", ticket, err)
	}
	for _, rendered := range []string{fmt.Sprint(ticket), fmt.Sprintf("%#v", ticket), fmt.Sprintf("%+v", ticket)} {
		if strings.Contains(rendered, rawToken) || strings.Contains(rendered, "vault-accessor-canary") ||
			!strings.Contains(rendered, "REDACTED") {
			t.Fatalf("ticket rendering leaked secret: %q", rendered)
		}
	}
	if encoded, marshalErr := json.Marshal(ticket); !errors.Is(marshalErr, credential.ErrInvalidRevocationRequest) || encoded != nil {
		t.Fatalf("json.Marshal(ticket) = %q, %v", encoded, marshalErr)
	}

	// ClaimRunnerTx owns neither Begin nor Commit. The raw material remains
	// inaccessible until the caller commits and performs the explicit gate.
	database.ExpectCommit()
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	database.ExpectBegin()
	expectRunnerRevocationPrincipal(database, scope.RunnerID(), scope.TenantID(), scope.ScopeRevision(), runnerRevocationCertificateSHA256)
	database.ExpectQuery(`(?s)SELECT binding\.workspace_id::text, binding\.environment_id::text.*FOR SHARE OF binding`).
		WithArgs(scope.RunnerID(), scope.TenantID(), postgresTestWorkspaceID, postgresTestEnvironment).
		WillReturnRows(pgxmock.NewRows([]string{"workspace_id", "environment_id"}).
			AddRow(postgresTestWorkspaceID, postgresTestEnvironment))
	database.ExpectQuery(`(?s)SELECT .*FROM credential_revocations.*claim_expires_at > statement_timestamp\(\).*FOR SHARE`).
		WithArgs(postgresTestRevocationID, scope.TenantID(), postgresTestWorkspaceID, postgresTestEnvironment,
			int64(1), scope.RunnerID(), tokenDigest).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusRevoking, Protected: protected, AvailableAt: now.Add(-time.Second), Version: 5,
			ClaimEpoch: 1, ClaimedBy: scope.RunnerID(), ClaimTokenSHA256: tokenDigest,
			ClaimedAt: now, ClaimExpiresAt: now.Add(30 * time.Second), HeartbeatAt: now, Attempt: 1,
		}))
	database.ExpectQuery(`(?s)SELECT heartbeat_seq,.*last_heartbeat_at IS NOT DISTINCT FROM claimed_at.*claim_expires_at IS NOT DISTINCT FROM claimed_at \+ interval '30 seconds'`).
		WithArgs(postgresTestRevocationID).
		WillReturnRows(pgxmock.NewRows([]string{"heartbeat_seq", "initial_heartbeat", "canonical_expiry"}).
			AddRow(int64(0), true, true))
	database.ExpectCommit()

	claim, err := repository.FinalizeRevocationClaimAfterCommit(context.Background(), ticket)
	if err != nil {
		t.Fatalf("FinalizeRevocationClaimAfterCommit() error = %v", err)
	}
	defer claim.Accessor.Destroy()
	if claim.Fence.Token != rawToken || claim.Fence.WorkerID != scope.RunnerID() || claim.Fence.Epoch != 1 ||
		claim.Revocation.ID != postgresTestRevocationID || string(claim.Accessor.Bytes()) != "vault-accessor-canary" {
		t.Fatalf("finalized claim = %#v", claim)
	}
	if _, err := repository.FinalizeRevocationClaimAfterCommit(context.Background(), ticket); !errors.Is(err, credential.ErrInvalidRevocationRequest) {
		t.Fatalf("ticket reuse error = %v, want %v", err, credential.ErrInvalidRevocationRequest)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestFinalizeRevocationClaimRejectsRollbackCrossRepositoryAndDestroysSecrets(t *testing.T) {
	t.Parallel()
	newRepository := func(t *testing.T) (*Repository, pgxmock.PgxPoolIface) {
		t.Helper()
		database, err := pgxmock.NewPool()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(database.Close)
		repository, err := New(database, repositoryTestProtector(t), Options{})
		if err != nil {
			t.Fatal(err)
		}
		return repository, database
	}
	owner, ownerDB := newRepository(t)
	other, _ := newRepository(t)
	accessor, err := credential.NewSensitiveReference([]byte("cross-repository-canary"))
	if err != nil {
		t.Fatal(err)
	}
	ticket := &RunnerRevocationClaimTicket{
		owner: owner, rawToken: strings.Repeat("c", 64), accessor: accessor,
		revocation: credential.Revocation{ID: postgresTestRevocationID},
		claimEpoch: 1, claimTokenSHA256: credential.SHA256Hex([]byte(strings.Repeat("c", 64))),
		certificateSHA256: runnerRevocationCertificateSHA256,
	}
	if _, err := other.FinalizeRevocationClaimAfterCommit(context.Background(), ticket); !errors.Is(err, credential.ErrInvalidRevocationRequest) {
		t.Fatalf("cross repository finalization error = %v", err)
	}
	if got := accessor.Bytes(); len(got) != 0 {
		t.Fatalf("cross repository rejection retained accessor: %q", got)
	}
	if _, err := owner.FinalizeRevocationClaimAfterCommit(context.Background(), ticket); !errors.Is(err, credential.ErrInvalidRevocationRequest) {
		t.Fatalf("owner reuse after cross repository error = %v", err)
	}

	rollbackAccessor, err := credential.NewSensitiveReference([]byte("rolled-back-canary"))
	if err != nil {
		t.Fatal(err)
	}
	rollbackTicket := validRunnerRevocationTicket(owner, rollbackAccessor)
	ownerDB.ExpectBegin()
	expectRunnerRevocationPrincipal(ownerDB, "runner-write-1", postgresTestTenantID, 7, runnerRevocationCertificateSHA256)
	ownerDB.ExpectQuery(`(?s)SELECT binding\.workspace_id::text, binding\.environment_id::text.*FOR SHARE OF binding`).
		WithArgs("runner-write-1", postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment).
		WillReturnRows(pgxmock.NewRows([]string{"workspace_id", "environment_id"}).
			AddRow(postgresTestWorkspaceID, postgresTestEnvironment))
	ownerDB.ExpectQuery(`SELECT .* FROM credential_revocations`).
		WithArgs(postgresTestRevocationID, postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment,
			int64(1), "runner-write-1", rollbackTicket.claimTokenSHA256).
		WillReturnRows(pgxmock.NewRows(storedRevocationColumns()))
	ownerDB.ExpectRollback()
	if _, err := owner.FinalizeRevocationClaimAfterCommit(context.Background(), rollbackTicket); !errors.Is(err, credential.ErrStaleClaim) {
		t.Fatalf("rolled back claim finalization error = %v, want %v", err, credential.ErrStaleClaim)
	}
	if got := rollbackAccessor.Bytes(); len(got) != 0 {
		t.Fatalf("rolled back claim retained accessor: %q", got)
	}
	if err := ownerDB.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestClaimRevocationRunnerTxPoisonOnlyAlertsAndLeavesActiveClaimForDatabaseRecovery(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository, err := New(database, repositoryTestProtector(t), Options{TokenSource: func() (string, error) {
		return strings.Repeat("b", 64), nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 11, 19, 10, 0, 0, time.UTC)
	tokenDigest := credential.SHA256Hex([]byte(strings.Repeat("b", 64)))
	scope := runnerCredentialScope(t, executionlease.PoolWrite)

	database.ExpectBegin()
	tx, err := database.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	expectRunnerRevocationPrincipal(database, scope.RunnerID(), scope.TenantID(), scope.ScopeRevision(), runnerRevocationCertificateSHA256)
	database.ExpectQuery(`(?s)WITH exact_scope.*FOR UPDATE OF candidate SKIP LOCKED`).
		WithArgs(scope.RunnerID(), scope.TenantID(), []string{postgresTestWorkspaceID}, []string{postgresTestEnvironment},
			credential.MaxRevocationAttempts, credential.MaxRevocationElapsed.Seconds()).
		WillReturnRows(pgxmock.NewRows([]string{"revocation_id"}).AddRow(postgresTestRevocationID))
	database.ExpectQuery(`(?s)WITH claim_boundary AS.*UPDATE credential_revocations AS candidate.*FROM claim_boundary`).
		WithArgs(postgresTestRevocationID, scope.RunnerID(), tokenDigest, scope.TenantID(),
			credential.MaxRevocationAttempts, credential.MaxRevocationElapsed.Seconds(), scope.ScopeRevision(),
			runnerRevocationCertificateSHA256).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status:      credential.StatusRevoking,
			Protected:   credential.ProtectedReference{Ciphertext: []byte("not-a-valid-aead"), AccessorHMAC: make([]byte, 32), KeyID: "missing-key"},
			AvailableAt: now, Version: 8, ClaimEpoch: 3, ClaimedBy: scope.RunnerID(), ClaimTokenSHA256: tokenDigest,
			ClaimedAt: now, ClaimExpiresAt: now.Add(30 * time.Second), HeartbeatAt: now, Attempt: 3,
		}))
	database.ExpectQuery(`SELECT heartbeat_seq FROM credential_revocations`).
		WithArgs(postgresTestRevocationID).
		WillReturnRows(pgxmock.NewRows([]string{"heartbeat_seq"}).AddRow(int64(0)))
	expectRunnerRevocationStateChange(database, "credential.revocation.claimed", "credential.revocation.claimed.v1", 8)
	expectRunnerRevocationStateChange(database, "credential.revocation.protected_reference_unavailable",
		"credential.revocation.protected_reference_unavailable.v1", 8)

	ticket, err := repository.ClaimRevocationRunnerTx(context.Background(), tx, scope, runnerRevocationCertificateSHA256)
	if err != nil || ticket != nil {
		t.Fatalf("ClaimRevocationRunnerTx(poison) = %#v, %v", ticket, err)
	}
	// No MANUAL_REQUIRED update is expected. An unexpected quarantine query
	// fails pgxmock immediately; only the caller's rollback remains.
	database.ExpectRollback()
	if err := tx.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestClaimRevocationRunnerTxRequiresCurrentCapabilityCertificateAndExactPairedScope(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository, err := New(database, repositoryTestProtector(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	scope := runnerCredentialScope(t, executionlease.PoolWrite)
	database.ExpectBegin()
	tx, err := database.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	database.ExpectQuery(`(?s)FROM runner_registrations AS registration.*credential_revocation_capable = true.*FOR SHARE OF registration`).
		WithArgs(scope.RunnerID(), scope.TenantID(), scope.ScopeRevision()).
		WillReturnRows(pgxmock.NewRows([]string{"runner_id"}))
	if ticket, err := repository.ClaimRevocationRunnerTx(context.Background(), tx, scope, runnerRevocationCertificateSHA256); ticket != nil || !errors.Is(err, credential.ErrStaleClaim) {
		t.Fatalf("ClaimRevocationRunnerTx(disabled capability) = %#v, %v", ticket, err)
	}
	database.ExpectRollback()
	if err := tx.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestHeartbeatRevocationRunnerTxSequencesReplayWithoutRenewalAndUsesCallerTransaction(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository, err := New(database, repositoryTestProtector(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 11, 19, 20, 0, 0, time.UTC)
	rawToken := strings.Repeat("e", 64)
	fence := credential.ClaimFence{
		RevocationID: postgresTestRevocationID, WorkerID: "runner-write-1", Token: rawToken, Epoch: 3,
	}
	scope := runnerCredentialScope(t, executionlease.PoolWrite)
	tokenDigest := credential.SHA256Hex([]byte(rawToken))
	options := storedRowOptions{
		Status: credential.StatusRevoking, AvailableAt: now.Add(-time.Minute), Version: 8,
		ClaimEpoch: 3, ClaimedBy: scope.RunnerID(), ClaimTokenSHA256: tokenDigest,
		ClaimedAt: now, ClaimExpiresAt: now.Add(30 * time.Second), HeartbeatAt: now, Attempt: 3,
	}

	database.ExpectBegin()
	tx, err := database.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	expectRunnerRevocationPeek(database)
	expectRunnerRevocationCurrentScope(database, scope, true)
	expectRunnerRevocationClaimLock(database, fence, now, options, 0, true)
	database.ExpectQuery(`(?s)UPDATE credential_revocations AS revocation.*SET heartbeat_seq = \$5.*revocation\.heartbeat_seq \+ 1 = \$5.*credential_revocation_capable = true.*RETURNING`).
		WithArgs(fence.RevocationID, fence.WorkerID, tokenDigest, fence.Epoch, int64(1), scope.TenantID(),
			postgresTestWorkspaceID, postgresTestEnvironment, scope.ScopeRevision()).
		WillReturnRows(storedRevocationRows(now.Add(time.Second), storedRowOptions{
			Status: credential.StatusRevoking, AvailableAt: now.Add(-time.Minute), Version: 9,
			ClaimEpoch: 3, ClaimedBy: scope.RunnerID(), ClaimTokenSHA256: tokenDigest,
			ClaimedAt: now, ClaimExpiresAt: now.Add(31 * time.Second), HeartbeatAt: now.Add(time.Second), Attempt: 3,
		}))
	first, err := repository.HeartbeatRevocationRunnerTx(context.Background(), tx, scope, fence, 1)
	if err != nil || first.Directive != credential.RunnerRevocationContinue || first.AcceptedSequence != 1 ||
		!first.ClaimExpiresAt.Equal(now.Add(31*time.Second)) {
		t.Fatalf("HeartbeatRevocationRunnerTx(first) = %#v, %v", first, err)
	}

	// Exact replay returns the stored state and performs no UPDATE, so the
	// database lease cannot be extended by duplicated network delivery.
	replayOptions := options
	replayOptions.Version = 9
	replayOptions.HeartbeatAt = now.Add(time.Second)
	replayOptions.ClaimExpiresAt = now.Add(31 * time.Second)
	expectRunnerRevocationPeek(database)
	expectRunnerRevocationCurrentScope(database, scope, true)
	expectRunnerRevocationClaimLock(database, fence, now.Add(time.Second), replayOptions, 1, true)
	replayed, err := repository.HeartbeatRevocationRunnerTx(context.Background(), tx, scope, fence, 1)
	if err != nil || replayed.Directive != credential.RunnerRevocationContinue || replayed.AcceptedSequence != 1 ||
		!replayed.ClaimExpiresAt.Equal(first.ClaimExpiresAt) {
		t.Fatalf("HeartbeatRevocationRunnerTx(replay) = %#v, %v", replayed, err)
	}

	expectRunnerRevocationPeek(database)
	expectRunnerRevocationCurrentScope(database, scope, true)
	expectRunnerRevocationClaimLock(database, fence, now.Add(time.Second), replayOptions, 1, true)
	if result, err := repository.HeartbeatRevocationRunnerTx(context.Background(), tx, scope, fence, 3); !errors.Is(err, execution.ErrHeartbeatSequence) || result != (credential.RunnerRevocationHeartbeatResult{}) {
		t.Fatalf("HeartbeatRevocationRunnerTx(jump) = %#v, %v", result, err)
	}

	database.ExpectRollback()
	if err := tx.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestHeartbeatRevocationRunnerTxRejectsZeroBeforeSQLAndTerminatesWithoutUpdateAfterScopeLoss(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository, err := New(database, repositoryTestProtector(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	scope := runnerCredentialScope(t, executionlease.PoolWrite)
	rawToken := strings.Repeat("f", 64)
	fence := credential.ClaimFence{
		RevocationID: postgresTestRevocationID, WorkerID: scope.RunnerID(), Token: rawToken, Epoch: 2,
	}
	database.ExpectBegin()
	tx, err := database.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result, err := repository.HeartbeatRevocationRunnerTx(context.Background(), tx, scope, fence, 0); !errors.Is(err, credential.ErrInvalidRevocationRequest) || result != (credential.RunnerRevocationHeartbeatResult{}) {
		t.Fatalf("HeartbeatRevocationRunnerTx(sequence=0) = %#v, %v", result, err)
	}

	now := time.Date(2026, 7, 11, 19, 25, 0, 0, time.UTC)
	expectRunnerRevocationPeek(database)
	expectRunnerRevocationCurrentScope(database, scope, false)
	expectRunnerRevocationClaimLock(database, fence, now, storedRowOptions{
		Status: credential.StatusRevoking, AvailableAt: now, Version: 6,
		ClaimEpoch: 2, ClaimedBy: scope.RunnerID(), ClaimTokenSHA256: credential.SHA256Hex([]byte(rawToken)),
		ClaimedAt: now.Add(-time.Second), ClaimExpiresAt: now.Add(29 * time.Second),
		HeartbeatAt: now.Add(-time.Second), Attempt: 2,
	}, 0, true)
	terminated, err := repository.HeartbeatRevocationRunnerTx(context.Background(), tx, scope, fence, 1)
	if err != nil || terminated.Directive != credential.RunnerRevocationTerminate || terminated.AcceptedSequence != 1 {
		t.Fatalf("HeartbeatRevocationRunnerTx(scope lost) = %#v, %v", terminated, err)
	}

	// A jump remains a protocol conflict even after authorization loss and can
	// never be disguised as a successful TERMINATE response.
	expectRunnerRevocationPeek(database)
	expectRunnerRevocationCurrentScope(database, scope, false)
	expectRunnerRevocationClaimLock(database, fence, now, storedRowOptions{
		Status: credential.StatusRevoking, AvailableAt: now, Version: 6,
		ClaimEpoch: 2, ClaimedBy: scope.RunnerID(), ClaimTokenSHA256: credential.SHA256Hex([]byte(rawToken)),
		ClaimedAt: now.Add(-time.Second), ClaimExpiresAt: now.Add(29 * time.Second),
		HeartbeatAt: now.Add(-time.Second), Attempt: 2,
	}, 0, true)
	if _, err := repository.HeartbeatRevocationRunnerTx(context.Background(), tx, scope, fence, 2); !errors.Is(err, execution.ErrHeartbeatSequence) {
		t.Fatalf("HeartbeatRevocationRunnerTx(scope lost jump) error = %v", err)
	}
	database.ExpectRollback()
	if err := tx.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestCompleteRevocationRunnerTxInsertsCertificateBoundReceiptBeforeRevokedParent(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository, err := New(database, repositoryTestProtector(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 11, 19, 30, 0, 0, time.UTC)
	receivedAt := now.Add(250 * time.Millisecond)
	rawToken := strings.Repeat("1", 64)
	tokenDigest := credential.SHA256Hex([]byte(rawToken))
	fence := credential.ClaimFence{
		RevocationID: postgresTestRevocationID, WorkerID: "runner-write-1", Token: rawToken, Epoch: 4,
	}
	scope := runnerCredentialScope(t, executionlease.PoolWrite)
	parent := runnerRevocationReceiptParent(credential.StatusRevoking, fence.Epoch, fence.WorkerID, 0)
	completion := credential.RunnerRevocationCompletion{
		ClaimEpoch: fence.Epoch, Outcome: credential.RunnerRevocationRevoked,
	}
	wantReceipt, err := credential.BuildRunnerRevocationReceiptV1(credential.RunnerRevocationClaim{
		Revocation: parent, RunnerID: scope.RunnerID(), ScopeRevision: scope.ScopeRevision(),
		CertificateSHA256: runnerRevocationCertificateSHA256, ClaimTokenSHA256: tokenDigest,
		HeartbeatSequence: 2,
	}, completion, now)
	if err != nil {
		t.Fatal(err)
	}

	database.ExpectBegin()
	tx, err := database.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	expectRunnerRevocationPeek(database)
	expectRunnerRevocationPrincipal(database, scope.RunnerID(), scope.TenantID(), scope.ScopeRevision(), runnerRevocationCertificateSHA256)
	expectRunnerRevocationBinding(database, scope)
	expectRunnerRevocationClaimLock(database, fence, now, storedRowOptions{
		Status: credential.StatusRevoking, AvailableAt: now.Add(-time.Minute), Version: 9,
		ClaimEpoch: fence.Epoch, ClaimedBy: scope.RunnerID(), ClaimTokenSHA256: tokenDigest,
		ClaimedAt: now.Add(-time.Second), ClaimExpiresAt: now.Add(29 * time.Second),
		HeartbeatAt: now.Add(-time.Second), Attempt: 4,
	}, 2, true)
	database.ExpectQuery(`SELECT clock_timestamp\(\)`).
		WillReturnRows(pgxmock.NewRows([]string{"database_now"}).AddRow(now))
	// This expectation intentionally precedes the parent UPDATE. pgxmock will
	// fail the test if implementation order regresses.
	database.ExpectQuery(`(?s)INSERT INTO credential_revocation_receipts.*tenant_id, workspace_id, environment_id.*issuer, issuer_revision.*ON CONFLICT \(revocation_id, claim_epoch\) DO NOTHING.*RETURNING received_at`).
		WithArgs(
			postgresTestRevocationID, fence.Epoch, postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment,
			scope.RunnerID(), scope.ScopeRevision(), runnerRevocationCertificateSHA256, "vault-production", "rev-1",
			tokenDigest, int64(2), string(credential.RunnerRevocationRevoked), nil, nil, nil, wantReceipt.ReceiptHash,
		).
		WillReturnRows(pgxmock.NewRows([]string{"received_at"}).AddRow(receivedAt))
	database.ExpectQuery(`(?s)UPDATE credential_revocations AS revocation.*SET status = 'REVOKED'.*completed_claim_epoch = revocation\.claim_epoch.*accessor_ciphertext = NULL, encryption_key_id = NULL.*revoked_at = \$5::timestamptz.*RETURNING`).
		WithArgs(fence.RevocationID, fence.WorkerID, tokenDigest, fence.Epoch, receivedAt).
		WillReturnRows(storedRevocationRows(receivedAt, storedRowOptions{
			Status: credential.StatusRevoked, AvailableAt: now.Add(-time.Minute), Version: 10,
			ClaimEpoch: fence.Epoch, Attempt: 4,
			CompletedClaimEpoch: fence.Epoch, CompletedClaimedBy: scope.RunnerID(),
			CompletedClaimTokenSHA256: tokenDigest, RevokedAt: receivedAt,
		}))
	expectRunnerRevocationStateChange(database, "credential.revocation.completed", "credential.revocation.completed.v1", 10)

	result, err := repository.CompleteRevocationRunnerTx(context.Background(), tx, scope, fence,
		credential.RunnerRevocationRevoked, "", runnerRevocationCertificateSHA256)
	if err != nil || result.Revocation.Status != credential.StatusRevoked || result.RetryDelay != 0 ||
		result.Receipt.ReceiptHash != wantReceipt.ReceiptHash || !result.Receipt.ReceivedAt.Equal(receivedAt) {
		t.Fatalf("CompleteRevocationRunnerTx(REVOKED) = %#v, %v", result, err)
	}
	database.ExpectRollback()
	if err := tx.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestCompleteRevocationRunnerTxDerivesFailureEvidenceRetryAndFirstAlert(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository, err := New(database, repositoryTestProtector(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 11, 19, 35, 0, 0, time.UTC)
	receivedAt := now.Add(100 * time.Millisecond)
	rawToken := strings.Repeat("2", 64)
	tokenDigest := credential.SHA256Hex([]byte(rawToken))
	fence := credential.ClaimFence{
		RevocationID: postgresTestRevocationID, WorkerID: "runner-write-1", Token: rawToken, Epoch: 1,
	}
	scope := runnerCredentialScope(t, executionlease.PoolWrite)
	parent := runnerRevocationReceiptParent(credential.StatusRevoking, fence.Epoch, fence.WorkerID, 0)
	completion := credential.RunnerRevocationCompletion{
		ClaimEpoch: fence.Epoch, Outcome: credential.RunnerRevocationFailed, FailureCode: credential.FailureTimeout,
	}
	wantReceipt, err := credential.BuildRunnerRevocationReceiptV1(credential.RunnerRevocationClaim{
		Revocation: parent, RunnerID: scope.RunnerID(), ScopeRevision: scope.ScopeRevision(),
		CertificateSHA256: runnerRevocationCertificateSHA256, ClaimTokenSHA256: tokenDigest,
		HeartbeatSequence: 1,
	}, completion, now)
	if err != nil {
		t.Fatal(err)
	}

	database.ExpectBegin()
	tx, err := database.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	expectRunnerRevocationPeek(database)
	expectRunnerRevocationPrincipal(database, scope.RunnerID(), scope.TenantID(), scope.ScopeRevision(), runnerRevocationCertificateSHA256)
	expectRunnerRevocationBinding(database, scope)
	expectRunnerRevocationClaimLock(database, fence, now, storedRowOptions{
		Status: credential.StatusRevoking, AvailableAt: now.Add(-time.Minute), Version: 4,
		ClaimEpoch: fence.Epoch, ClaimedBy: scope.RunnerID(), ClaimTokenSHA256: tokenDigest,
		ClaimedAt: now.Add(-time.Second), ClaimExpiresAt: now.Add(29 * time.Second),
		HeartbeatAt: now.Add(-time.Second), Attempt: 1,
	}, 1, true)
	database.ExpectQuery(`SELECT clock_timestamp\(\)`).
		WillReturnRows(pgxmock.NewRows([]string{"database_now"}).AddRow(now))
	database.ExpectQuery(`INSERT INTO credential_revocation_receipts`).
		WithArgs(
			postgresTestRevocationID, fence.Epoch, postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment,
			scope.RunnerID(), scope.ScopeRevision(), runnerRevocationCertificateSHA256, "vault-production", "rev-1",
			tokenDigest, int64(1), string(credential.RunnerRevocationFailed), wantReceipt.FailureCount,
			string(credential.FailureTimeout), wantReceipt.FailureDetailSHA256, wantReceipt.ReceiptHash,
		).
		WillReturnRows(pgxmock.NewRows([]string{"received_at"}).AddRow(receivedAt))
	database.ExpectQuery(`(?s)UPDATE credential_revocations AS revocation.*SET status = CASE.*failure_count = \$5, failure_code = \$6, failure_detail_sha256 = \$7.*available_at = CASE.*manual_required_at = CASE.*RETURNING`).
		WithArgs(
			fence.RevocationID, fence.WorkerID, tokenDigest, fence.Epoch,
			1, string(credential.FailureTimeout), wantReceipt.FailureDetailSHA256,
			credential.MaxRevocationAttempts, credential.MaxRevocationElapsed.Seconds(), receivedAt,
			credential.MinRevocationRetryDelay.Seconds(),
		).
		WillReturnRows(storedRevocationRows(receivedAt, storedRowOptions{
			Status: credential.StatusRevocationPending, AvailableAt: receivedAt.Add(credential.MinRevocationRetryDelay),
			Version: 5, ClaimEpoch: fence.Epoch, Attempt: 1, FailureCount: 1,
			FailureCode: credential.FailureTimeout, FailureDetailSHA256: wantReceipt.FailureDetailSHA256,
		}))
	expectRunnerRevocationStateChange(database, "credential.revocation.failed", "credential.revocation.failed.v1", 5)

	result, err := repository.CompleteRevocationRunnerTx(context.Background(), tx, scope, fence,
		credential.RunnerRevocationFailed, credential.FailureTimeout, runnerRevocationCertificateSHA256)
	if err != nil || result.Revocation.Status != credential.StatusRevocationPending ||
		result.Revocation.FailureCount != 1 || result.Revocation.FailureCode != credential.FailureTimeout ||
		result.RetryDelay != credential.MinRevocationRetryDelay || result.Receipt != wantReceiptWithReceivedAt(wantReceipt, receivedAt) {
		t.Fatalf("CompleteRevocationRunnerTx(FAILED) = %#v, %v", result, err)
	}
	database.ExpectRollback()
	if err := tx.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestCompleteRevocationRunnerTxIdempotentTerminalReceiptAndConflicts(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository, err := New(database, repositoryTestProtector(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 11, 19, 40, 0, 0, time.UTC)
	rawToken := strings.Repeat("3", 64)
	tokenDigest := credential.SHA256Hex([]byte(rawToken))
	fence := credential.ClaimFence{
		RevocationID: postgresTestRevocationID, WorkerID: "runner-write-1", Token: rawToken, Epoch: 5,
	}
	scope := runnerCredentialScope(t, executionlease.PoolWrite)
	preCompletion := runnerRevocationReceiptParent(credential.StatusRevoking, fence.Epoch, fence.WorkerID, 0)
	completion := credential.RunnerRevocationCompletion{
		ClaimEpoch: fence.Epoch, Outcome: credential.RunnerRevocationRevoked,
	}
	receipt, err := credential.BuildRunnerRevocationReceiptV1(credential.RunnerRevocationClaim{
		Revocation: preCompletion, RunnerID: scope.RunnerID(), ScopeRevision: scope.ScopeRevision(),
		CertificateSHA256: runnerRevocationCertificateSHA256, ClaimTokenSHA256: tokenDigest,
		HeartbeatSequence: 2,
	}, completion, now)
	if err != nil {
		t.Fatal(err)
	}
	terminal := storedRowOptions{
		Status: credential.StatusRevoked, AvailableAt: now.Add(-time.Minute), Version: 12,
		ClaimEpoch: fence.Epoch, Attempt: 5,
		CompletedClaimEpoch: fence.Epoch, CompletedClaimedBy: scope.RunnerID(),
		CompletedClaimTokenSHA256: tokenDigest, RevokedAt: now,
	}

	database.ExpectBegin()
	tx, err := database.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	expectIdempotentRunnerRevocationPrefix(database, scope, fence, terminal, 2, runnerRevocationCertificateSHA256, now)
	database.ExpectQuery(`(?s)SELECT schema_version, revocation_id::text.*FROM credential_revocation_receipts`).
		WithArgs(fence.RevocationID, fence.Epoch).
		WillReturnRows(runnerRevocationReceiptRows(receipt))
	result, err := repository.CompleteRevocationRunnerTx(context.Background(), tx, scope, fence,
		credential.RunnerRevocationRevoked, "", runnerRevocationCertificateSHA256)
	if err != nil || result.Revocation.Status != credential.StatusRevoked || result.Receipt != receipt {
		t.Fatalf("CompleteRevocationRunnerTx(idempotent) = %#v, %v", result, err)
	}

	differentCertificate := strings.Repeat("d", 64)
	expectIdempotentRunnerRevocationPrefix(database, scope, fence, terminal, 2, differentCertificate, now)
	database.ExpectQuery(`(?s)SELECT schema_version, revocation_id::text.*FROM credential_revocation_receipts`).
		WithArgs(fence.RevocationID, fence.Epoch).
		WillReturnRows(runnerRevocationReceiptRows(receipt))
	if _, err := repository.CompleteRevocationRunnerTx(context.Background(), tx, scope, fence,
		credential.RunnerRevocationRevoked, "", differentCertificate); !errors.Is(err, credential.ErrCompletionConflict) {
		t.Fatalf("CompleteRevocationRunnerTx(certificate conflict) error = %v", err)
	}

	staleFence := fence
	staleFence.Token = strings.Repeat("4", 64)
	expectIdempotentRunnerRevocationPrefix(database, scope, staleFence, terminal, 2, runnerRevocationCertificateSHA256, now)
	database.ExpectQuery(`(?s)SELECT schema_version, revocation_id::text.*FROM credential_revocation_receipts`).
		WithArgs(staleFence.RevocationID, staleFence.Epoch).
		WillReturnRows(runnerRevocationReceiptRows(receipt))
	if _, err := repository.CompleteRevocationRunnerTx(context.Background(), tx, scope, staleFence,
		credential.RunnerRevocationRevoked, "", runnerRevocationCertificateSHA256); !errors.Is(err, credential.ErrStaleClaim) {
		t.Fatalf("CompleteRevocationRunnerTx(stale token) error = %v", err)
	}
	database.ExpectRollback()
	if err := tx.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func expectRunnerRevocationPrincipal(
	database pgxmock.PgxPoolIface,
	runnerID, tenantID string,
	scopeRevision int64,
	certificateSHA256 string,
) {
	database.ExpectQuery(`(?s)FROM runner_registrations AS registration.*registration\.enabled = true.*registration\.runner_pool = 'WRITE'.*registration\.credential_revocation_capable = true.*registration\.scope_revision = \$3.*FOR SHARE OF registration`).
		WithArgs(runnerID, tenantID, scopeRevision).
		WillReturnRows(pgxmock.NewRows([]string{"runner_id"}).AddRow(runnerID))
	database.ExpectQuery(`(?s)FROM runner_certificates AS certificate.*certificate\.certificate_sha256 = \$3.*certificate\.status = 'ACTIVE'.*FOR SHARE OF certificate`).
		WithArgs(runnerID, tenantID, certificateSHA256).
		WillReturnRows(pgxmock.NewRows([]string{"runner_id"}).AddRow(runnerID))
}

func expectRunnerRevocationBinding(database pgxmock.PgxPoolIface, scope execution.RunnerScope) {
	database.ExpectQuery(`(?s)SELECT binding\.workspace_id::text, binding\.environment_id::text.*FOR SHARE OF binding`).
		WithArgs(scope.RunnerID(), scope.TenantID(), postgresTestWorkspaceID, postgresTestEnvironment).
		WillReturnRows(pgxmock.NewRows([]string{"workspace_id", "environment_id"}).
			AddRow(postgresTestWorkspaceID, postgresTestEnvironment))
}

func expectRunnerRevocationPeek(database pgxmock.PgxPoolIface) {
	database.ExpectQuery(`(?s)SELECT tenant_id::text, workspace_id::text, environment_id::text.*FROM credential_revocations`).
		WithArgs(postgresTestRevocationID).
		WillReturnRows(pgxmock.NewRows([]string{"tenant_id", "workspace_id", "environment_id"}).
			AddRow(postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment))
}

func expectRunnerRevocationCurrentScope(
	database pgxmock.PgxPoolIface,
	scope execution.RunnerScope,
	bindingCurrent bool,
) {
	database.ExpectQuery(`(?s)SELECT registration\.runner_id.*FROM runner_registrations AS registration.*credential_revocation_capable = true.*FOR SHARE OF registration`).
		WithArgs(scope.RunnerID(), scope.TenantID(), scope.ScopeRevision()).
		WillReturnRows(pgxmock.NewRows([]string{"runner_id"}).AddRow(scope.RunnerID()))
	bindingRows := pgxmock.NewRows([]string{"workspace_id", "environment_id"})
	if bindingCurrent {
		bindingRows.AddRow(postgresTestWorkspaceID, postgresTestEnvironment)
	}
	database.ExpectQuery(`(?s)SELECT binding\.workspace_id::text, binding\.environment_id::text.*FOR SHARE OF binding`).
		WithArgs(scope.RunnerID(), scope.TenantID(), postgresTestWorkspaceID, postgresTestEnvironment).
		WillReturnRows(bindingRows)
}

func expectRunnerRevocationClaimLock(
	database pgxmock.PgxPoolIface,
	fence credential.ClaimFence,
	now time.Time,
	options storedRowOptions,
	heartbeatSequence int64,
	claimCurrent bool,
) {
	database.ExpectQuery(`(?s)SELECT .*FROM credential_revocations.*FOR UPDATE`).
		WithArgs(fence.RevocationID).
		WillReturnRows(storedRevocationRows(now, options))
	database.ExpectQuery(`(?s)SELECT heartbeat_seq, COALESCE\(claim_expires_at > statement_timestamp\(\), false\)`).
		WithArgs(fence.RevocationID).
		WillReturnRows(pgxmock.NewRows([]string{"heartbeat_seq", "claim_current"}).
			AddRow(heartbeatSequence, claimCurrent))
}

func expectIdempotentRunnerRevocationPrefix(
	database pgxmock.PgxPoolIface,
	scope execution.RunnerScope,
	fence credential.ClaimFence,
	terminal storedRowOptions,
	heartbeatSequence int64,
	certificateSHA256 string,
	now time.Time,
) {
	expectRunnerRevocationPeek(database)
	expectRunnerRevocationPrincipal(database, scope.RunnerID(), scope.TenantID(), scope.ScopeRevision(), certificateSHA256)
	expectRunnerRevocationBinding(database, scope)
	expectRunnerRevocationClaimLock(database, fence, now, terminal, heartbeatSequence, false)
}

func runnerRevocationReceiptRows(receipt credential.RunnerRevocationReceipt) *pgxmock.Rows {
	var failureCount, failureCode, failureDetail any
	if receipt.Outcome == credential.RunnerRevocationFailed {
		failureCount = receipt.FailureCount
		failureCode = string(receipt.FailureCode)
		failureDetail = receipt.FailureDetailSHA256
	}
	return pgxmock.NewRows([]string{
		"schema_version", "revocation_id", "tenant_id", "workspace_id", "environment_id",
		"runner_id", "scope_revision", "certificate_sha256", "issuer", "issuer_revision",
		"claim_epoch", "heartbeat_seq", "claim_token_sha256", "outcome", "failure_count",
		"failure_code", "failure_detail_sha256", "receipt_hash", "received_at",
	}).AddRow(
		receipt.SchemaVersion, receipt.RevocationID, receipt.TenantID, receipt.WorkspaceID, receipt.EnvironmentID,
		receipt.RunnerID, receipt.ScopeRevision, receipt.CertificateSHA256, receipt.Issuer, receipt.IssuerRevision,
		receipt.ClaimEpoch, receipt.HeartbeatSequence, receipt.ClaimTokenSHA256, string(receipt.Outcome), failureCount,
		failureCode, failureDetail, receipt.ReceiptHash, receipt.ReceivedAt,
	)
}

func expectRunnerRevocationStateChange(database pgxmock.PgxPoolIface, action, eventType string, version int64) {
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID, "RUNNER", "runner-write-1", action,
			postgresTestRevocationID, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID, postgresTestRevocationID,
			int64(version), eventType, pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
}

func validRunnerRevocationTicket(owner *Repository, accessor *credential.SensitiveReference) *RunnerRevocationClaimTicket {
	rawToken := strings.Repeat("d", 64)
	return &RunnerRevocationClaimTicket{
		owner: owner, rawToken: rawToken, accessor: accessor,
		revocation: credential.Revocation{
			ID: postgresTestRevocationID, TenantID: postgresTestTenantID,
			WorkspaceID: postgresTestWorkspaceID, EnvironmentID: postgresTestEnvironment,
			Issuer: "vault-production", IssuerRevision: "rev-1",
		},
		runnerID: "runner-write-1", tenantID: postgresTestTenantID,
		workspaceID: postgresTestWorkspaceID, environmentID: postgresTestEnvironment,
		scopeRevision: 7, certificateSHA256: runnerRevocationCertificateSHA256,
		claimEpoch: 1, claimTokenSHA256: credential.SHA256Hex([]byte(rawToken)),
	}
}

func runnerRevocationReceiptParent(
	status credential.RevocationStatus,
	claimEpoch int64,
	claimedBy string,
	failureCount int,
) credential.Revocation {
	return credential.Revocation{
		ID: postgresTestRevocationID, TenantID: postgresTestTenantID,
		WorkspaceID: postgresTestWorkspaceID, EnvironmentID: postgresTestEnvironment,
		ActionID: postgresTestActionID, Issuer: "vault-production", IssuerRevision: "rev-1",
		Status: status, ClaimEpoch: claimEpoch, ClaimedBy: claimedBy, FailureCount: failureCount,
	}
}

func wantReceiptWithReceivedAt(
	receipt credential.RunnerRevocationReceipt,
	receivedAt time.Time,
) credential.RunnerRevocationReceipt {
	receipt.ReceivedAt = receivedAt
	return receipt
}
