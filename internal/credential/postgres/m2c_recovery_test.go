package postgres

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/seaworld008/aiops-system/internal/credential"
)

func TestPostgresRetryRevocationRejectsDelayOutsideFixedBounds(t *testing.T) {
	repository := (*Repository)(nil)
	for _, delay := range []time.Duration{
		0,
		credential.MinRevocationRetryDelay - time.Nanosecond,
		credential.MaxRevocationRetryDelay + time.Nanosecond,
	} {
		_, err := repository.RetryRevocation(context.Background(), credential.RetryRevocationRequest{
			Fence: credential.ClaimFence{
				RevocationID: postgresTestRevocationID,
				WorkerID:     "revoker-boundary",
				Token:        "claim-token",
				Epoch:        1,
			},
			Delay:         delay,
			FailureCode:   credential.FailureTimeout,
			FailureDetail: []byte("worker.remote.timeout"),
		})
		if !errors.Is(err, credential.ErrInvalidRevocationRequest) {
			t.Fatalf("RetryRevocation(delay %s) error = %v", delay, err)
		}
	}
}

func TestPostgresRecoverExhaustedUsesDatabaseTimeAndWritesManualAlert(t *testing.T) {
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
	now := time.Date(2026, 7, 11, 14, 0, 0, 0, time.UTC)
	detailHash := credential.SHA256Hex([]byte(credential.FailureDetailExhaustedWithoutAck))
	protected := protectTestReference(t, repository.protector, []byte("exhausted-accessor"))

	database.ExpectBegin()
	database.ExpectQuery("SELECT revocation_id::text, tenant_id::text").
		WithArgs(10, credential.MaxRevocationAttempts, credential.MaxRevocationElapsed.Seconds()).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusRevoking, Protected: protected, AvailableAt: now.Add(-time.Minute), Version: 20,
			ClaimEpoch: 12, ClaimedBy: "crashed-worker", ClaimTokenSHA256: credential.SHA256Hex([]byte("lost-token")),
			ClaimedAt: now.Add(-time.Minute), ClaimExpiresAt: now.Add(-time.Second), HeartbeatAt: now.Add(-time.Minute),
			Attempt: credential.MaxRevocationAttempts,
		}))
	database.ExpectQuery("UPDATE credential_revocations.*SET status = 'MANUAL_REQUIRED'").
		WithArgs(postgresTestRevocationID, string(credential.FailureUnknown), detailHash,
			credential.MaxRevocationAttempts, credential.MaxRevocationElapsed.Seconds()).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusManualRequired, Protected: protected, AvailableAt: now.Add(-time.Minute), Version: 21,
			ClaimEpoch: 12, Attempt: credential.MaxRevocationAttempts, FailureCount: 1,
			FailureCode: credential.FailureUnknown, FailureDetailSHA256: detailHash, ManualAt: now,
		}))
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID, "SYSTEM", "credential-revocation-recovery",
			"credential.revocation.manual_required", postgresTestRevocationID,
			pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID, postgresTestRevocationID,
			int64(21), "credential.revocation.manual_required.v1", pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	recovered, err := repository.RecoverExhausted(context.Background(), credential.RecoverExhaustedRequest{Limit: 10})
	if err != nil || len(recovered) != 1 || recovered[0].Status != credential.StatusManualRequired ||
		recovered[0].FailureCode != credential.FailureUnknown || recovered[0].FailureDetailSHA256 != detailHash {
		t.Fatalf("RecoverExhausted() = %#v, %v", recovered, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestPostgresRetryRevocationAtomicallyEscalatesExhaustedCycle(t *testing.T) {
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
	now := time.Date(2026, 7, 11, 14, 30, 0, 0, time.UTC)
	claimToken := "twelfth-attempt-claim"
	claimDigest := credential.SHA256Hex([]byte(claimToken))
	detail := []byte("worker.remote.timeout")
	detailHash := credential.SHA256Hex(detail)
	protected := protectTestReference(t, repository.protector, []byte("twelfth-attempt-accessor"))

	database.ExpectBegin()
	expectFailedClaimLockAndClock(database, postgresTestRevocationID, "revoker-threshold", claimDigest, 12, now)
	database.ExpectQuery("UPDATE credential_revocations SET status = CASE").
		WithArgs(postgresTestRevocationID, "revoker-threshold", claimDigest, int64(12), string(credential.FailureTimeout),
			detailHash, credential.MinRevocationRetryDelay.Seconds(), credential.MaxRevocationAttempts,
			credential.MaxRevocationElapsed.Seconds(), now).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusManualRequired, Protected: protected, AvailableAt: now.Add(-time.Second), Version: 30,
			ClaimEpoch: 12, Attempt: credential.MaxRevocationAttempts, FailureCount: 1,
			FailureCode: credential.FailureTimeout, FailureDetailSHA256: detailHash, ManualAt: now,
		}))
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID, "SYSTEM", "revoker-threshold",
			"credential.revocation.manual_required", postgresTestRevocationID,
			pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID, postgresTestRevocationID,
			int64(30), "credential.revocation.manual_required.v1", pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	result, err := repository.RetryRevocation(context.Background(), credential.RetryRevocationRequest{
		Fence: credential.ClaimFence{
			RevocationID: postgresTestRevocationID, WorkerID: "revoker-threshold", Token: claimToken, Epoch: 12,
		},
		Delay: credential.MinRevocationRetryDelay, FailureCode: credential.FailureTimeout, FailureDetail: detail,
	})
	if err != nil || result.Status != credential.StatusManualRequired || result.ManualRequiredAt.IsZero() {
		t.Fatalf("RetryRevocation(exhausted) = %#v, %v", result, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestPostgresRecoverManagedPreservesAuthorizationLockOrder(t *testing.T) {
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
	now := time.Date(2026, 7, 11, 15, 0, 0, 0, time.UTC)
	fence := credential.ActionFence{
		ActionID: postgresTestActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4,
	}
	protected := protectTestReference(t, repository.protector, []byte("managed-recovery-accessor"))
	database.ExpectQuery("SELECT credential.revocation_id::text, credential.action_id, credential.runner_id").
		WithArgs(1, credential.ManagedAnchorRecoveryGrace.Seconds(), credential.MinPostChildFenceWindow.Seconds()).
		WillReturnRows(pgxmock.NewRows([]string{"revocation_id", "action_id", "runner_id", "managed_at"}).
			AddRow(postgresTestRevocationID, postgresTestActionID, fence.RunnerID, now.Add(-time.Minute)))
	database.ExpectBegin()
	database.ExpectQuery("SELECT tenant_id::text, runner_pool, enabled, scope_revision.*FOR SHARE").
		WithArgs(fence.RunnerID).
		WillReturnRows(runnerRegistrationRows(true, "WRITE", 7))
	database.ExpectQuery("SELECT action.action_id, workspace.tenant_id::text.*FOR SHARE OF action").
		WithArgs(fence.ActionID).
		WillReturnRows(actionInspectionRowsForState(now, fence, "RUNNING", now, 7))
	database.ExpectQuery("SELECT EXISTS.*FROM runner_scope_bindings").
		WithArgs(fence.RunnerID, postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment).
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	database.ExpectQuery("SELECT .* FROM credential_revocations.*FOR UPDATE").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusActive, Protected: protected, AvailableAt: now.Add(-time.Minute), Version: 6,
		}))
	database.ExpectQuery("SELECT clock_timestamp\\(\\)").
		WillReturnRows(pgxmock.NewRows([]string{"database_now"}).AddRow(now))
	database.ExpectQuery("UPDATE credential_revocations SET status = 'REVOCATION_PENDING'").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusRevocationPending, Protected: protected, AvailableAt: now, Version: 7,
		}))
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID, "SYSTEM", "credential-managed-recovery",
			"credential.revocation.requested", postgresTestRevocationID,
			pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID, postgresTestRevocationID,
			int64(7), "credential.revocation.requested.v1", pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	recovered, err := repository.RecoverManaged(context.Background(), credential.RecoverManagedRequest{Limit: 1})
	if err != nil || len(recovered) != 1 || recovered[0].Status != credential.StatusRevocationPending {
		t.Fatalf("RecoverManaged(cancelled) = %#v, %v", recovered, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestPostgresClaimQuarantinesPoisonWithoutStarvingValidCandidate(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	protector := repositoryTestProtector(t)
	tokens := []string{"poison-token-never-returned", "valid-token-returned"}
	tokenIndex := 0
	repository, err := New(database, protector, Options{TokenSource: func() (string, error) {
		token := tokens[tokenIndex]
		tokenIndex++
		return token, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 11, 16, 0, 0, 0, time.UTC)
	validRevocationID := "10000000-0000-4000-8000-000000000021"
	validActionID := "20000000-0000-4000-8000-000000000021"
	poisonProtected := protectTestReference(t, protector, []byte("poison-accessor"))
	poisonProtected.Ciphertext[0] ^= 0xff
	validProtected := protectTestReferenceFor(t, protector, validRevocationID, validActionID, 4, []byte("valid-accessor"))
	poisonDigest := credential.SHA256Hex([]byte(tokens[0]))
	validDigest := credential.SHA256Hex([]byte(tokens[1]))
	invalidDetailHash := credential.SHA256Hex([]byte(credential.FailureDetailProtectedRefInvalid))

	candidates := pgxmock.NewRows(storedRevocationColumns())
	addStoredRevocationRow(candidates, now, storedRowOptions{
		Status: credential.StatusRevocationPending, Protected: poisonProtected, AvailableAt: now.Add(-2 * time.Minute), Version: 4,
	})
	addStoredRevocationRow(candidates, now, storedRowOptions{
		RevocationID: validRevocationID, ActionID: validActionID,
		Status: credential.StatusRevocationPending, Protected: validProtected, AvailableAt: now.Add(-time.Minute), Version: 10,
	})

	database.ExpectBegin()
	database.ExpectQuery("SELECT revocation_id::text, tenant_id::text").
		WithArgs(2, credential.MaxRevocationAttempts, credential.MaxRevocationElapsed.Seconds()).
		WillReturnRows(candidates)
	expectClaimUpdate := func(id, worker, digest string, version int64, protected credential.ProtectedReference, actionID string) {
		database.ExpectQuery("UPDATE credential_revocations SET status = 'REVOKING'").
			WithArgs(id, worker, digest, credential.RevocationClaimLease.Seconds(),
				credential.MaxRevocationAttempts, credential.MaxRevocationElapsed.Seconds()).
			WillReturnRows(storedRevocationRows(now, storedRowOptions{
				RevocationID: id, ActionID: actionID, Status: credential.StatusRevoking, Protected: protected,
				AvailableAt: now.Add(-time.Minute), Version: version, ClaimEpoch: 1, ClaimedBy: worker,
				ClaimTokenSHA256: digest, ClaimedAt: now, ClaimExpiresAt: now.Add(credential.RevocationClaimLease),
				HeartbeatAt: now, Attempt: 1,
			}))
		database.ExpectExec("INSERT INTO audit_records").
			WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID, "SYSTEM", worker,
				"credential.revocation.claimed", id, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))
		database.ExpectExec("INSERT INTO outbox_events").
			WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID, id,
				version, "credential.revocation.claimed.v1", pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))
	}
	workerID := "revoker-poison-isolation"
	expectClaimUpdate(postgresTestRevocationID, workerID, poisonDigest, 5, poisonProtected, postgresTestActionID)
	database.ExpectQuery("UPDATE credential_revocations SET status = 'MANUAL_REQUIRED'").
		WithArgs(postgresTestRevocationID, workerID, poisonDigest, int64(1),
			string(credential.FailureInvalidReference), invalidDetailHash).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusManualRequired, Protected: poisonProtected, AvailableAt: now.Add(-time.Minute), Version: 6,
			ClaimEpoch: 1, Attempt: 1, FailureCount: 1, FailureCode: credential.FailureInvalidReference,
			FailureDetailSHA256: invalidDetailHash, ManualAt: now,
		}))
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID, "SYSTEM", workerID,
			"credential.revocation.manual_required", postgresTestRevocationID,
			pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID, postgresTestRevocationID,
			int64(6), "credential.revocation.manual_required.v1", pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	expectClaimUpdate(validRevocationID, workerID, validDigest, 11, validProtected, validActionID)
	database.ExpectCommit()

	claims, err := repository.ClaimRevocations(context.Background(), credential.ClaimRevocationsRequest{
		WorkerID: workerID, Limit: 2, LeaseDuration: credential.RevocationClaimLease,
	})
	if err != nil || len(claims) != 1 || claims[0].Revocation.ID != validRevocationID || claims[0].Fence.Token != tokens[1] {
		t.Fatalf("ClaimRevocations(poison isolation) = %#v, %v", claims, err)
	}
	accessor := claims[0].Accessor.Bytes()
	if !bytes.Equal(accessor, []byte("valid-accessor")) {
		clear(accessor)
		claims[0].Accessor.Destroy()
		t.Fatalf("valid accessor mismatch")
	}
	clear(accessor)
	claims[0].Accessor.Destroy()
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}
