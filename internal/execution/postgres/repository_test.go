package postgres

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/seaworld008/aiops-system/internal/action"
	"github.com/seaworld008/aiops-system/internal/execution"
	"github.com/seaworld008/aiops-system/internal/executionlease"
)

const testTenantID = "10000000-0000-4000-8000-000000000001"

var testLeaseToken = strings.Repeat("a", 64)

func TestCancellationIntentHashUsesBackendIndependentDomain(t *testing.T) {
	digest := sha256.Sum256([]byte("action-queue-cancel-intent.v1\x00REQUESTED"))
	want := hex.EncodeToString(digest[:])
	if got := cancellationResultHash(); got != want {
		t.Fatalf("cancellationResultHash() = %q, want %q", got, want)
	}
}

func TestSubmitAtomicallyPersistsImmutableEnvelopeMetadataAndQueuedLease(t *testing.T) {
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := signedTestEnvelope(t, now)
	submission := execution.ActionSubmission{
		Envelope: envelope, PlanHash: envelope.PlanHash,
		TargetKey:           "k8s-deployment:sha256:" + strings.Repeat("a", 64),
		EnvironmentRevision: "environment-1", Production: true, Pool: executionlease.PoolWrite,
	}
	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	want := executionlease.Execution{
		ExecutionID: envelope.ActionID, TargetKey: submission.TargetKey, Pool: submission.Pool,
		Production: true, Status: executionlease.StatusQueued, CreatedAt: now, UpdatedAt: now,
	}
	database.ExpectQuery(`(?s)INSERT INTO action_queue .*envelope.*submission_hash.*idempotency_key.*request_hash.*authorization_expires_at.*ON CONFLICT DO NOTHING.*RETURNING`).
		WithArgs(
			envelope.ActionID, string(envelopeJSON), pgxmock.AnyArg(), envelope.IdempotencyKey,
			pgxmock.AnyArg(), requestHashVersion, envelope.PlanHash,
			envelope.WorkspaceID, envelope.Target.EnvironmentID, submission.TargetKey,
			submission.EnvironmentRevision, envelope.ExpiresAt, submission.Pool, submission.Production,
		).
		WillReturnRows(actionQueueRows(want, envelopeJSON, envelope.PlanHash, submission.EnvironmentRevision,
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64)))

	got, err := repository.Submit(context.Background(), submission)
	if err != nil || got != want {
		t.Fatalf("Submit() = %#v, %v; want %#v", got, err, want)
	}
	assertExpectations(t, database)
}

func TestSubmitIsIdempotentOnlyForTheExactImmutableSubmission(t *testing.T) {
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := signedTestEnvelope(t, now)
	submission := execution.ActionSubmission{
		Envelope: envelope, PlanHash: envelope.PlanHash,
		TargetKey:           "k8s-deployment:sha256:" + strings.Repeat("a", 64),
		EnvironmentRevision: "environment-1", Production: true, Pool: executionlease.PoolWrite,
	}
	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	wantHash, err := hashSubmission(submission, envelopeJSON)
	if err != nil {
		t.Fatalf("hashSubmission() error = %v", err)
	}
	want := executionlease.Execution{
		ExecutionID: envelope.ActionID, TargetKey: submission.TargetKey, Pool: submission.Pool,
		Production: true, Status: executionlease.StatusQueued, CreatedAt: now, UpdatedAt: now,
	}

	for name, storedHash := range map[string]string{
		"exact duplicate":                        wantHash,
		"same id different immutable submission": strings.Repeat("f", 64),
	} {
		t.Run(name, func(t *testing.T) {
			database, repository := newActionQueueRepository(t)
			defer database.Close()
			database.ExpectQuery("INSERT INTO action_queue").
				WithArgs(
					envelope.ActionID, string(envelopeJSON), wantHash, envelope.IdempotencyKey,
					pgxmock.AnyArg(), requestHashVersion, envelope.PlanHash,
					envelope.WorkspaceID, envelope.Target.EnvironmentID, submission.TargetKey,
					submission.EnvironmentRevision, envelope.ExpiresAt, submission.Pool, submission.Production,
				).
				WillReturnRows(actionQueueRowsEmpty())
			database.ExpectQuery(`(?s)SELECT .*submission_hash.*FROM action_queue.*WHERE action_id = \$1 OR \(workspace_id = \$2 AND idempotency_key = \$3\)`).
				WithArgs(envelope.ActionID, envelope.WorkspaceID, envelope.IdempotencyKey).
				WillReturnRows(actionQueueRows(want, envelopeJSON, envelope.PlanHash, submission.EnvironmentRevision,
					envelope.WorkspaceID, envelope.Target.EnvironmentID, storedHash))

			got, err := repository.Submit(context.Background(), submission)
			if name == "exact duplicate" {
				if err != nil || got != want {
					t.Fatalf("Submit() = %#v, %v; want idempotent %#v", got, err, want)
				}
			} else if !errors.Is(err, execution.ErrJobConflict) {
				t.Fatalf("Submit() error = %v, want %v", err, execution.ErrJobConflict)
			}
			assertExpectations(t, database)
		})
	}
}

func TestSubmitSameActionIDRejectsDifferentRequestSemanticsWithSelfConsistentStoredRow(t *testing.T) {
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := signedTestEnvelope(t, now)
	original := execution.ActionSubmission{
		Envelope: envelope, PlanHash: envelope.PlanHash,
		TargetKey: "k8s-deployment:sha256:" + strings.Repeat("a", 64), EnvironmentRevision: "environment-1",
		Production: true, Pool: executionlease.PoolWrite,
	}
	changed := original
	changed.EnvironmentRevision = "environment-2"
	envelopeJSON, _ := json.Marshal(envelope)
	changedHash, err := hashSubmission(changed, envelopeJSON)
	if err != nil {
		t.Fatalf("hashSubmission(changed) error = %v", err)
	}
	storedExecution := executionlease.Execution{
		ExecutionID: envelope.ActionID, TargetKey: original.TargetKey, Pool: original.Pool,
		Production: true, Status: executionlease.StatusQueued, CreatedAt: now, UpdatedAt: now,
	}
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	database.ExpectQuery("INSERT INTO action_queue").
		WithArgs(
			envelope.ActionID, string(envelopeJSON), changedHash, envelope.IdempotencyKey,
			pgxmock.AnyArg(), requestHashVersion, envelope.PlanHash,
			envelope.WorkspaceID, envelope.Target.EnvironmentID, changed.TargetKey,
			changed.EnvironmentRevision, envelope.ExpiresAt, changed.Pool, changed.Production,
		).
		WillReturnRows(actionQueueRowsEmpty())
	database.ExpectQuery(`(?s)SELECT .*FROM action_queue.*WHERE action_id = \$1 OR \(workspace_id = \$2 AND idempotency_key = \$3\)`).
		WithArgs(envelope.ActionID, envelope.WorkspaceID, envelope.IdempotencyKey).
		WillReturnRows(actionQueueRows(storedExecution, envelopeJSON, envelope.PlanHash, original.EnvironmentRevision,
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64)))

	if _, err := repository.Submit(context.Background(), changed); !errors.Is(err, execution.ErrJobConflict) {
		t.Fatalf("Submit(different same-action semantics) error = %v, want %v", err, execution.ErrJobConflict)
	}
	assertExpectations(t, database)
}

func TestSubmitSemanticIdempotencyReturnsOriginalAcrossActionIdentity(t *testing.T) {
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	originalEnvelope := signedTestEnvelope(t, now)
	originalSubmission := execution.ActionSubmission{
		Envelope: originalEnvelope, PlanHash: originalEnvelope.PlanHash,
		TargetKey: "k8s-deployment:sha256:" + strings.Repeat("a", 64), EnvironmentRevision: "environment-1",
		Production: true, Pool: executionlease.PoolWrite,
	}
	originalJSON, _ := json.Marshal(originalEnvelope)
	original := executionlease.Execution{
		ExecutionID: originalEnvelope.ActionID, TargetKey: originalSubmission.TargetKey, Pool: originalSubmission.Pool,
		Production: true, Status: executionlease.StatusQueued, CreatedAt: now, UpdatedAt: now,
	}

	retryEnvelope := originalEnvelope
	retryEnvelope.ActionID = "action-semantic-retry"
	retryEnvelope.PlanHash = strings.Repeat("c", 64)
	retryEnvelope.TraceID = strings.Repeat("b", 32)
	retrySubmission := originalSubmission
	retrySubmission.Envelope = retryEnvelope
	retrySubmission.PlanHash = retryEnvelope.PlanHash
	retryJSON, _ := json.Marshal(retryEnvelope)
	retrySubmissionHash, err := hashSubmission(retrySubmission, retryJSON)
	if err != nil {
		t.Fatalf("hashSubmission(retry) error = %v", err)
	}

	database, repository := newActionQueueRepository(t)
	defer database.Close()
	database.ExpectQuery("INSERT INTO action_queue").
		WithArgs(
			retryEnvelope.ActionID, string(retryJSON), retrySubmissionHash, retryEnvelope.IdempotencyKey,
			pgxmock.AnyArg(), requestHashVersion, retryEnvelope.PlanHash,
			retryEnvelope.WorkspaceID, retryEnvelope.Target.EnvironmentID, retrySubmission.TargetKey,
			retrySubmission.EnvironmentRevision, retryEnvelope.ExpiresAt, retrySubmission.Pool, retrySubmission.Production,
		).
		WillReturnRows(actionQueueRowsEmpty())
	database.ExpectQuery(`(?s)SELECT .*FROM action_queue.*WHERE action_id = \$1 OR \(workspace_id = \$2 AND idempotency_key = \$3\)`).
		WithArgs(retryEnvelope.ActionID, retryEnvelope.WorkspaceID, retryEnvelope.IdempotencyKey).
		WillReturnRows(actionQueueRows(original, originalJSON, originalEnvelope.PlanHash, originalSubmission.EnvironmentRevision,
			originalEnvelope.WorkspaceID, originalEnvelope.Target.EnvironmentID, strings.Repeat("b", 64)))

	got, err := repository.Submit(context.Background(), retrySubmission)
	if err != nil || got.ExecutionID != original.ExecutionID {
		t.Fatalf("Submit(semantic retry) = %#v, %v; want original %q", got, err, original.ExecutionID)
	}
	assertExpectations(t, database)
}

func TestSubmitLegacySemanticIdempotencyReturnsOriginalForValidResignedActionIdentity(t *testing.T) {
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	originalEnvelope := signedTestEnvelope(t, now)
	originalSubmission := execution.ActionSubmission{
		Envelope: originalEnvelope, PlanHash: originalEnvelope.PlanHash,
		TargetKey: "k8s-deployment:sha256:" + strings.Repeat("a", 64), EnvironmentRevision: "environment-1",
		Production: true, Pool: executionlease.PoolWrite,
	}
	originalJSON, _ := json.Marshal(originalEnvelope)
	original := executionlease.Execution{
		ExecutionID: originalEnvelope.ActionID, TargetKey: originalSubmission.TargetKey, Pool: originalSubmission.Pool,
		Production: true, Status: executionlease.StatusQueued, CreatedAt: now, UpdatedAt: now,
	}

	retryEnvelope := originalEnvelope
	retryEnvelope.ActionID = "action-legacy-semantic-retry"
	retryEnvelope.TraceID = strings.Repeat("c", 32)
	retryEnvelope = resealTestEnvelope(t, retryEnvelope)
	retrySubmission := originalSubmission
	retrySubmission.Envelope = retryEnvelope
	retrySubmission.PlanHash = retryEnvelope.PlanHash
	retryJSON, _ := json.Marshal(retryEnvelope)
	retrySubmissionHash, err := hashSubmission(retrySubmission, retryJSON)
	if err != nil {
		t.Fatalf("hashSubmission(legacy retry) error = %v", err)
	}

	database, repository := newActionQueueRepository(t)
	defer database.Close()
	database.ExpectQuery("INSERT INTO action_queue").
		WithArgs(
			retryEnvelope.ActionID, string(retryJSON), retrySubmissionHash, retryEnvelope.IdempotencyKey,
			pgxmock.AnyArg(), requestHashVersion, retryEnvelope.PlanHash,
			retryEnvelope.WorkspaceID, retryEnvelope.Target.EnvironmentID, retrySubmission.TargetKey,
			retrySubmission.EnvironmentRevision, retryEnvelope.ExpiresAt, retrySubmission.Pool, retrySubmission.Production,
		).
		WillReturnRows(actionQueueRowsEmpty())
	database.ExpectQuery(`(?s)SELECT .*FROM action_queue.*WHERE action_id = \$1 OR \(workspace_id = \$2 AND idempotency_key = \$3\)`).
		WithArgs(retryEnvelope.ActionID, retryEnvelope.WorkspaceID, retryEnvelope.IdempotencyKey).
		WillReturnRows(actionQueueRowsDetailed(original, originalJSON, originalEnvelope.PlanHash, originalSubmission.EnvironmentRevision,
			originalEnvelope.WorkspaceID, originalEnvelope.Target.EnvironmentID, strings.Repeat("b", 64), nil, nil, nil, now, nil,
			"legacy-submission.v1"))

	got, err := repository.Submit(context.Background(), retrySubmission)
	if err != nil || got.ExecutionID != original.ExecutionID {
		t.Fatalf("Submit(legacy semantic retry) = %#v, %v; want original %q", got, err, original.ExecutionID)
	}
	assertExpectations(t, database)
}

func TestSubmitLegacySemanticIdempotencyRejectsDifferentRequestSemantics(t *testing.T) {
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := signedTestEnvelope(t, now)
	original := execution.ActionSubmission{
		Envelope: envelope, PlanHash: envelope.PlanHash,
		TargetKey: "k8s-deployment:sha256:" + strings.Repeat("a", 64), EnvironmentRevision: "environment-1",
		Production: true, Pool: executionlease.PoolWrite,
	}
	changed := original
	changed.EnvironmentRevision = "environment-2"
	envelopeJSON, _ := json.Marshal(envelope)
	changedHash, err := hashSubmission(changed, envelopeJSON)
	if err != nil {
		t.Fatalf("hashSubmission(changed legacy retry) error = %v", err)
	}
	storedExecution := executionlease.Execution{
		ExecutionID: envelope.ActionID, TargetKey: original.TargetKey, Pool: original.Pool,
		Production: true, Status: executionlease.StatusQueued, CreatedAt: now, UpdatedAt: now,
	}

	database, repository := newActionQueueRepository(t)
	defer database.Close()
	database.ExpectQuery("INSERT INTO action_queue").
		WithArgs(
			envelope.ActionID, string(envelopeJSON), changedHash, envelope.IdempotencyKey,
			pgxmock.AnyArg(), requestHashVersion, envelope.PlanHash,
			envelope.WorkspaceID, envelope.Target.EnvironmentID, changed.TargetKey,
			changed.EnvironmentRevision, envelope.ExpiresAt, changed.Pool, changed.Production,
		).
		WillReturnRows(actionQueueRowsEmpty())
	database.ExpectQuery(`(?s)SELECT .*FROM action_queue.*WHERE action_id = \$1 OR \(workspace_id = \$2 AND idempotency_key = \$3\)`).
		WithArgs(envelope.ActionID, envelope.WorkspaceID, envelope.IdempotencyKey).
		WillReturnRows(actionQueueRowsDetailed(storedExecution, envelopeJSON, envelope.PlanHash, original.EnvironmentRevision,
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), nil, nil, nil, now, nil,
			"legacy-submission.v1"))

	if _, err := repository.Submit(context.Background(), changed); !errors.Is(err, execution.ErrJobConflict) {
		t.Fatalf("Submit(different legacy semantics) error = %v, want %v", err, execution.ErrJobConflict)
	}
	assertExpectations(t, database)
}

func TestSubmitSameActionIDAllowsValidResignWithSameSemantics(t *testing.T) {
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	originalEnvelope := signedTestEnvelope(t, now)
	resignedEnvelope := signedTestEnvelope(t, now)
	if originalEnvelope.Signature.Value == resignedEnvelope.Signature.Value {
		t.Fatal("test setup produced identical signatures")
	}
	submission := execution.ActionSubmission{
		Envelope: resignedEnvelope, PlanHash: resignedEnvelope.PlanHash,
		TargetKey: "k8s-deployment:sha256:" + strings.Repeat("a", 64), EnvironmentRevision: "environment-1",
		Production: true, Pool: executionlease.PoolWrite,
	}
	resignedJSON, _ := json.Marshal(resignedEnvelope)
	resignedHash, err := hashSubmission(submission, resignedJSON)
	if err != nil {
		t.Fatalf("hashSubmission(resigned) error = %v", err)
	}
	originalJSON, _ := json.Marshal(originalEnvelope)
	original := executionlease.Execution{
		ExecutionID: originalEnvelope.ActionID, TargetKey: submission.TargetKey, Pool: submission.Pool,
		Production: true, Status: executionlease.StatusQueued, CreatedAt: now, UpdatedAt: now,
	}

	database, repository := newActionQueueRepository(t)
	defer database.Close()
	database.ExpectQuery("INSERT INTO action_queue").
		WithArgs(
			resignedEnvelope.ActionID, string(resignedJSON), resignedHash, resignedEnvelope.IdempotencyKey,
			pgxmock.AnyArg(), requestHashVersion, resignedEnvelope.PlanHash,
			resignedEnvelope.WorkspaceID, resignedEnvelope.Target.EnvironmentID, submission.TargetKey,
			submission.EnvironmentRevision, resignedEnvelope.ExpiresAt, submission.Pool, submission.Production,
		).
		WillReturnRows(actionQueueRowsEmpty())
	database.ExpectQuery(`(?s)SELECT .*FROM action_queue.*WHERE action_id = \$1 OR \(workspace_id = \$2 AND idempotency_key = \$3\)`).
		WithArgs(resignedEnvelope.ActionID, resignedEnvelope.WorkspaceID, resignedEnvelope.IdempotencyKey).
		WillReturnRows(actionQueueRows(original, originalJSON, originalEnvelope.PlanHash, submission.EnvironmentRevision,
			originalEnvelope.WorkspaceID, originalEnvelope.Target.EnvironmentID, strings.Repeat("b", 64)))

	got, err := repository.Submit(context.Background(), submission)
	if err != nil || got.ExecutionID != original.ExecutionID {
		t.Fatalf("Submit(valid resign) = %#v, %v; want original", got, err)
	}
	assertExpectations(t, database)
}

func TestClaimSweepsAndScopesBeforeAtomicallyLeasingWithSkipLocked(t *testing.T) {
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := signedTestEnvelopeWithExpiry(t, now, now.Add(2*time.Minute))
	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	targetKey := "k8s-deployment:sha256:" + strings.Repeat("a", 64)
	wantExecution := executionlease.Execution{
		ExecutionID: envelope.ActionID, TargetKey: targetKey, Pool: executionlease.PoolWrite,
		Production: true, Status: executionlease.StatusLeased, RunnerID: "runner-1",
		RunnerTenantID: "10000000-0000-4000-8000-000000000001", RunnerWorkspaceID: envelope.WorkspaceID,
		RunnerEnvironmentID: envelope.Target.EnvironmentID, ScopeRevision: 1,
		LeaseToken: testLeaseToken, LeaseEpoch: 1, LeaseAcquiredAt: now,
		LastHeartbeatAt: now, LeaseExpiresAt: envelope.ExpiresAt, CreatedAt: now.Add(-time.Minute), UpdatedAt: now,
	}
	wantTokenHash := tokenHash(testLeaseToken)
	database.ExpectBegin()
	database.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs(pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("SELECT", 1))
	database.ExpectExec("UPDATE action_queue AS expired_running").WithArgs(pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("UPDATE", 0))
	database.ExpectExec("UPDATE action_queue AS expired_finalizing").WillReturnResult(pgxmock.NewResult("UPDATE", 0))
	database.ExpectExec("UPDATE action_queue AS expired_lease").WillReturnResult(pgxmock.NewResult("UPDATE", 0))
	database.ExpectQuery(`(?s)SELECT candidate\.action_id, candidate\.lease_epoch, registration\.scope_revision,.*registration\.tenant_id::text, binding\.workspace_id::text, binding\.environment_id::text.*JOIN runner_scope_bindings.*binding\.workspace_id::text = candidate\.workspace_id.*binding\.environment_id::text = candidate\.environment_id.*registration\.max_concurrency.*FOR SHARE OF registration.*FOR UPDATE OF candidate SKIP LOCKED`).
		WithArgs(executionlease.PoolWrite, "runner-1", int64(1), wantExecution.RunnerTenantID).
		WillReturnRows(pgxmock.NewRows([]string{"action_id", "lease_epoch", "scope_revision", "tenant_id", "workspace_id", "environment_id"}).
			AddRow(envelope.ActionID, int64(0), int64(1), wantExecution.RunnerTenantID, envelope.WorkspaceID, envelope.Target.EnvironmentID))
	database.ExpectQuery(`(?s)UPDATE action_queue AS queued.*lease_expires_at = LEAST\(\s*statement_timestamp\(\) \+ make_interval\(secs => \$4::double precision\),\s*queued\.authorization_expires_at\s*\).*RETURNING`).
		WithArgs(envelope.ActionID, "runner-1", wantTokenHash, float64(300), int64(1),
			wantExecution.RunnerTenantID, envelope.WorkspaceID, envelope.Target.EnvironmentID).
		WillReturnRows(actionQueueRowsDetailed(wantExecution, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), wantTokenHash, nil, nil, now, nil))
	database.ExpectCommit()

	got, err := repository.Claim(context.Background(), execution.ActionClaimRequest{
		Scope:         testRunnerScope(t, "runner-1", "workspace-1", "PROD"),
		LeaseDuration: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if got.Execution != wantExecution || got.Envelope.PlanHash != envelope.PlanHash || got.EnvironmentRevision != "environment-1" || !got.Production {
		t.Fatalf("Claim() = %#v, want execution %#v", got, wantExecution)
	}
	assertExpectations(t, database)
}

func TestClaimSkipsExpiredAuthorizationUsingDatabaseClock(t *testing.T) {
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	database.ExpectBegin()
	database.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs(pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("SELECT", 1))
	database.ExpectExec("UPDATE action_queue AS expired_running").WithArgs(pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("UPDATE", 0))
	database.ExpectExec("UPDATE action_queue AS expired_finalizing").WillReturnResult(pgxmock.NewResult("UPDATE", 0))
	database.ExpectExec("UPDATE action_queue AS expired_lease").WillReturnResult(pgxmock.NewResult("UPDATE", 0))
	database.ExpectQuery(`(?s)SELECT candidate\.action_id.*WHERE candidate\.runner_pool = \$1.*candidate\.status = 'QUEUED'.*candidate\.authorization_expires_at > statement_timestamp\(\).*FOR UPDATE OF candidate SKIP LOCKED`).
		WithArgs(executionlease.PoolWrite, "runner-1", int64(1), testTenantID).
		WillReturnRows(pgxmock.NewRows([]string{"action_id", "lease_epoch", "scope_revision", "tenant_id", "workspace_id", "environment_id"}))
	database.ExpectCommit()

	_, err := repository.Claim(context.Background(), execution.ActionClaimRequest{
		Scope: testRunnerScope(t, "runner-1", "workspace-1", "PROD"), LeaseDuration: time.Minute,
	})
	if !errors.Is(err, executionlease.ErrNoLeaseAvailable) {
		t.Fatalf("Claim(expired authorization) error = %v, want %v", err, executionlease.ErrNoLeaseAvailable)
	}
	assertExpectations(t, database)
}

func TestClaimRetriesCandidateWhenAuthorizationExpiresBeforeFinalUpdate(t *testing.T) {
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	defer database.Close()
	secondToken := strings.Repeat("b", 64)
	tokenCalls := 0
	repository, err := New(database, Options{TokenSource: func() (string, error) {
		tokenCalls++
		if tokenCalls == 1 {
			return testLeaseToken, nil
		}
		return secondToken, nil
	}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	secondEnvelope := signedTestEnvelope(t, now)
	secondEnvelope.ActionID = "action-2"
	secondEnvelope.IdempotencyKey = "idem-action-2"
	secondEnvelope = resealTestEnvelope(t, secondEnvelope)
	secondEnvelopeJSON, _ := json.Marshal(secondEnvelope)
	want := executionlease.Execution{
		ExecutionID: secondEnvelope.ActionID, TargetKey: "k8s-deployment:sha256:" + strings.Repeat("b", 64),
		Pool: executionlease.PoolWrite, Production: false, Status: executionlease.StatusLeased,
		RunnerID: "runner-1", RunnerTenantID: testTenantID, RunnerWorkspaceID: secondEnvelope.WorkspaceID,
		RunnerEnvironmentID: secondEnvelope.Target.EnvironmentID, ScopeRevision: 1, LeaseToken: secondToken,
		LeaseEpoch: 1, LeaseAcquiredAt: now, LastHeartbeatAt: now, LeaseExpiresAt: now.Add(time.Minute),
		CreatedAt: now.Add(-time.Minute), UpdatedAt: now,
	}
	database.ExpectBegin()
	database.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs(pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("SELECT", 1))
	database.ExpectExec("UPDATE action_queue AS expired_running").WithArgs(pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("UPDATE", 0))
	database.ExpectExec("UPDATE action_queue AS expired_finalizing").WillReturnResult(pgxmock.NewResult("UPDATE", 0))
	database.ExpectExec("UPDATE action_queue AS expired_lease").WillReturnResult(pgxmock.NewResult("UPDATE", 0))
	candidateQuery := `(?s)SELECT candidate\.action_id.*candidate\.authorization_expires_at > statement_timestamp\(\).*FOR UPDATE OF candidate SKIP LOCKED`
	database.ExpectQuery(candidateQuery).
		WithArgs(executionlease.PoolWrite, "runner-1", int64(1), testTenantID).
		WillReturnRows(pgxmock.NewRows([]string{"action_id", "lease_epoch", "scope_revision", "tenant_id", "workspace_id", "environment_id"}).
			AddRow("action-1", int64(0), int64(1), testTenantID, "workspace-1", "PROD"))
	finalUpdate := `(?s)UPDATE action_queue AS queued.*lease_expires_at = LEAST\(.*queued\.authorization_expires_at.*\).*WHERE queued\.action_id = \$1 AND queued\.status = 'QUEUED' AND queued\.authorization_expires_at > statement_timestamp\(\).*RETURNING`
	database.ExpectQuery(finalUpdate).
		WithArgs("action-1", "runner-1", tokenHash(testLeaseToken), float64(60), int64(1), testTenantID, "workspace-1", "PROD").
		WillReturnRows(actionQueueRowsEmpty())
	database.ExpectQuery(candidateQuery).
		WithArgs(executionlease.PoolWrite, "runner-1", int64(1), testTenantID).
		WillReturnRows(pgxmock.NewRows([]string{"action_id", "lease_epoch", "scope_revision", "tenant_id", "workspace_id", "environment_id"}).
			AddRow(secondEnvelope.ActionID, int64(0), int64(1), testTenantID, secondEnvelope.WorkspaceID, secondEnvelope.Target.EnvironmentID))
	database.ExpectQuery(finalUpdate).
		WithArgs(secondEnvelope.ActionID, "runner-1", tokenHash(secondToken), float64(60), int64(1), testTenantID, secondEnvelope.WorkspaceID, secondEnvelope.Target.EnvironmentID).
		WillReturnRows(actionQueueRowsDetailed(want, secondEnvelopeJSON, secondEnvelope.PlanHash, "environment-1",
			secondEnvelope.WorkspaceID, secondEnvelope.Target.EnvironmentID, strings.Repeat("b", 64), tokenHash(secondToken), nil, nil, now, nil))
	database.ExpectCommit()

	claimed, err := repository.Claim(context.Background(), execution.ActionClaimRequest{
		Scope: testRunnerScope(t, "runner-1", "workspace-1", "PROD"), LeaseDuration: time.Minute,
	})
	if err != nil || claimed.Execution != want || tokenCalls != 2 {
		t.Fatalf("Claim(retry after authorization expiry) = %#v, %v; token calls=%d", claimed.Execution, err, tokenCalls)
	}
	assertExpectations(t, database)
}

func TestClaimRejectsTokenSourcesBelowTheEntropyContract(t *testing.T) {
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	defer database.Close()
	repository, err := New(database, Options{TokenSource: func() (string, error) { return "predictable-token", nil }})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	database.ExpectBegin()
	database.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs(pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("SELECT", 1))
	database.ExpectExec("UPDATE action_queue AS expired_running").WithArgs(pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("UPDATE", 0))
	database.ExpectExec("UPDATE action_queue AS expired_finalizing").WillReturnResult(pgxmock.NewResult("UPDATE", 0))
	database.ExpectExec("UPDATE action_queue AS expired_lease").WillReturnResult(pgxmock.NewResult("UPDATE", 0))
	database.ExpectQuery("SELECT candidate.action_id, candidate.lease_epoch, registration.scope_revision").
		WithArgs(executionlease.PoolWrite, "runner-1", int64(1), "10000000-0000-4000-8000-000000000001").
		WillReturnRows(pgxmock.NewRows([]string{"action_id", "lease_epoch", "scope_revision", "tenant_id", "workspace_id", "environment_id"}).
			AddRow("action-1", int64(0), int64(1), "10000000-0000-4000-8000-000000000001", "workspace-1", "PROD"))
	database.ExpectRollback()

	_, err = repository.Claim(context.Background(), execution.ActionClaimRequest{
		Scope:         testRunnerScope(t, "runner-1", "workspace-1", "PROD"),
		LeaseDuration: time.Minute,
	})
	if !errors.Is(err, executionlease.ErrInvalidRequest) {
		t.Fatalf("Claim() error = %v, want entropy rejection", err)
	}
	assertExpectations(t, database)
}

func TestLeaseMissUsesServerClockAndDistinguishesExpiredFromStarted(t *testing.T) {
	fence := executionlease.LeaseIdentity{ExecutionID: "action-1", RunnerID: "runner-1", Token: testLeaseToken, Epoch: 2}
	digest := tokenHash(fence.Token)
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := signedTestEnvelope(t, now)
	envelopeJSON, _ := json.Marshal(envelope)
	running := executionlease.Execution{
		ExecutionID: fence.ExecutionID, TargetKey: "k8s-deployment:sha256:" + strings.Repeat("a", 64),
		Pool: executionlease.PoolWrite, Production: true, Status: executionlease.StatusRunning,
		RunnerID: fence.RunnerID, RunnerTenantID: testTenantID, RunnerWorkspaceID: envelope.WorkspaceID,
		RunnerEnvironmentID: envelope.Target.EnvironmentID, ScopeRevision: 1, LeaseEpoch: fence.Epoch,
		LeaseAcquiredAt: now.Add(-time.Minute), LastHeartbeatAt: now.Add(-time.Minute), LeaseExpiresAt: now,
		StartedAt: now.Add(-time.Minute), CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
	}

	t.Run("expired matching heartbeat fence is stale", func(t *testing.T) {
		database, repository := newActionQueueRepository(t)
		defer database.Close()
		database.ExpectBegin()
		expectRunnerRegistrationLock(database, fence.RunnerID, testTenantID, executionlease.PoolWrite, true, 1)
		database.ExpectQuery(`(?s)SELECT .*FROM action_queue.*WHERE action_id = \$1.*FOR UPDATE`).
			WithArgs(fence.ExecutionID).
			WillReturnRows(actionQueueRowsDetailed(running, envelopeJSON, envelope.PlanHash, "environment-1",
				envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), digest, nil, nil, now, nil))
		database.ExpectQuery(`(?s)SELECT COALESCE\(lease_expires_at > statement_timestamp\(\), false\),.*authorization_expires_at > statement_timestamp\(\).*FROM action_queue`).
			WithArgs(fence.ExecutionID).
			WillReturnRows(pgxmock.NewRows([]string{"lease_current", "authorization_current"}).AddRow(false, true))
		database.ExpectRollback()
		_, err := repository.Heartbeat(context.Background(), execution.ActionHeartbeatRequest{Lease: fence, Sequence: 1, Extension: time.Minute})
		if !errors.Is(err, executionlease.ErrStaleLease) {
			t.Fatalf("Heartbeat() error = %v, want stale expired fence", err)
		}
		assertExpectations(t, database)
	})

	t.Run("nack after start is invalid transition", func(t *testing.T) {
		database, repository := newActionQueueRepository(t)
		defer database.Close()
		reason := execution.ActionQueueReason{Code: "TEMPORARY_FAILURE", DetailHash: strings.Repeat("d", 64)}
		reasonDigest, _ := reasonHash(reason)
		database.ExpectQuery("UPDATE action_queue").
			WithArgs(fence.ExecutionID, fence.RunnerID, digest, fence.Epoch, reasonDigest, float64(30)).
			WillReturnRows(actionQueueRowsEmpty())
		database.ExpectQuery(`(?s)SELECT runner_id, lease_epoch, lease_token_sha256, status,.*statement_timestamp\(\).*FROM action_queue.*WHERE action_id = \$1`).
			WithArgs(fence.ExecutionID).
			WillReturnRows(pgxmock.NewRows([]string{"runner_id", "lease_epoch", "lease_token_sha256", "status", "lease_current"}).
				AddRow(fence.RunnerID, fence.Epoch, digest, executionlease.StatusRunning, true))
		_, err := repository.Nack(context.Background(), execution.ActionNackRequest{
			Lease: fence, Reason: reason, RetryAfter: 30 * time.Second,
		})
		if !errors.Is(err, executionlease.ErrInvalidTransition) {
			t.Fatalf("Nack() error = %v, want invalid transition", err)
		}
		assertExpectations(t, database)
	})
}

func TestStartAndHeartbeatFenceWithTokenHashAndNeverReturnBearer(t *testing.T) {
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := signedTestEnvelope(t, now)
	envelopeJSON, _ := json.Marshal(envelope)
	fence := executionlease.LeaseIdentity{ExecutionID: envelope.ActionID, RunnerID: "runner-1", Token: testLeaseToken, Epoch: 2}
	targetKey := "k8s-deployment:sha256:" + strings.Repeat("a", 64)
	running := executionlease.Execution{
		ExecutionID: envelope.ActionID, TargetKey: targetKey, Pool: executionlease.PoolWrite,
		Production: true, Status: executionlease.StatusRunning, RunnerID: fence.RunnerID,
		RunnerTenantID: testTenantID, RunnerWorkspaceID: envelope.WorkspaceID, RunnerEnvironmentID: envelope.Target.EnvironmentID,
		ScopeRevision: 1,
		LeaseEpoch:    fence.Epoch, LeaseAcquiredAt: now.Add(-time.Minute), LastHeartbeatAt: now.Add(-time.Minute),
		LeaseExpiresAt: now.Add(time.Minute), StartedAt: now, CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
	}
	leased := running
	leased.Status = executionlease.StatusLeased
	leased.StartedAt = time.Time{}
	digest := tokenHash(fence.Token)
	database.ExpectBegin()
	expectRunnerRegistrationLock(database, fence.RunnerID, testTenantID, executionlease.PoolWrite, true, 1)
	database.ExpectQuery(`(?s)SELECT .*FROM action_queue.*WHERE action_id = \$1.*FOR UPDATE`).
		WithArgs(fence.ExecutionID).
		WillReturnRows(actionQueueRowsDetailed(leased, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), digest, nil, nil, now, nil))
	database.ExpectQuery(`(?s)UPDATE action_queue.*lease_token_sha256 = \$3.*lease_expires_at > statement_timestamp\(\).*RETURNING`).
		WithArgs(fence.ExecutionID, fence.RunnerID, digest, fence.Epoch).
		WillReturnRows(actionQueueRowsDetailed(running, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), digest, nil, nil, now, nil))
	database.ExpectCommit()
	started, err := repository.Start(context.Background(), fence)
	if err != nil || started.Status != executionlease.StatusRunning || started.LeaseToken != "" {
		t.Fatalf("Start() = %#v, %v", started, err)
	}

	running.LastHeartbeatAt = now
	running.LeaseExpiresAt = now.Add(2 * time.Minute)
	running.HeartbeatSeq = 1
	heartbeatInput := running
	heartbeatInput.LastHeartbeatAt = now.Add(-time.Minute)
	heartbeatInput.LeaseExpiresAt = now.Add(time.Minute)
	heartbeatInput.HeartbeatSeq = 0
	database.ExpectBegin()
	expectRunnerRegistrationLock(database, fence.RunnerID, testTenantID, executionlease.PoolWrite, true, 1)
	database.ExpectQuery(`(?s)SELECT .*FROM action_queue.*WHERE action_id = \$1.*FOR UPDATE`).
		WithArgs(fence.ExecutionID).
		WillReturnRows(actionQueueRowsDetailed(heartbeatInput, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), digest, nil, nil, now, nil))
	database.ExpectQuery(`(?s)SELECT COALESCE\(lease_expires_at > statement_timestamp\(\), false\),.*authorization_expires_at > statement_timestamp\(\).*FROM action_queue`).
		WithArgs(fence.ExecutionID).
		WillReturnRows(pgxmock.NewRows([]string{"lease_current", "authorization_current"}).AddRow(true, true))
	database.ExpectQuery(`(?s)UPDATE action_queue.*heartbeat_seq = \$5.*make_interval\(secs => \$6::double precision\).*lease_token_sha256 = \$3.*RETURNING`).
		WithArgs(fence.ExecutionID, fence.RunnerID, digest, fence.Epoch, int64(1), float64(120)).
		WillReturnRows(actionQueueRowsDetailed(running, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), digest, nil, nil, now, nil))
	database.ExpectCommit()
	heartbeat, err := repository.Heartbeat(context.Background(), execution.ActionHeartbeatRequest{Lease: fence, Sequence: 1, Extension: 2 * time.Minute})
	if err != nil || !heartbeat.Execution.LeaseExpiresAt.Equal(running.LeaseExpiresAt) || heartbeat.Execution.LeaseToken != "" {
		t.Fatalf("Heartbeat() = %#v, %v", heartbeat, err)
	}
	assertExpectations(t, database)
}

func TestStartFailsClosedWhenDatabaseAuthorizationBoundaryExpired(t *testing.T) {
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := signedTestEnvelope(t, now)
	envelopeJSON, _ := json.Marshal(envelope)
	fence := executionlease.LeaseIdentity{ExecutionID: envelope.ActionID, RunnerID: "runner-1", Token: testLeaseToken, Epoch: 2}
	leased := executionlease.Execution{
		ExecutionID: envelope.ActionID, TargetKey: "k8s-deployment:sha256:" + strings.Repeat("a", 64),
		Pool: executionlease.PoolWrite, Production: true, Status: executionlease.StatusLeased,
		RunnerID: fence.RunnerID, RunnerTenantID: testTenantID, RunnerWorkspaceID: envelope.WorkspaceID,
		RunnerEnvironmentID: envelope.Target.EnvironmentID, ScopeRevision: 1, LeaseEpoch: fence.Epoch,
		LeaseAcquiredAt: now.Add(-time.Minute), LastHeartbeatAt: now.Add(-time.Minute), LeaseExpiresAt: now.Add(time.Minute),
		CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
	}
	database.ExpectBegin()
	expectRunnerRegistrationLock(database, fence.RunnerID, testTenantID, executionlease.PoolWrite, true, 1)
	database.ExpectQuery(`(?s)SELECT .*FROM action_queue.*WHERE action_id = \$1.*FOR UPDATE`).
		WithArgs(fence.ExecutionID).
		WillReturnRows(actionQueueRowsDetailed(leased, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), tokenHash(fence.Token), nil, nil, now, nil))
	database.ExpectQuery(`(?s)UPDATE action_queue.*authorization_expires_at > statement_timestamp\(\).*RETURNING`).
		WithArgs(fence.ExecutionID, fence.RunnerID, tokenHash(fence.Token), fence.Epoch).
		WillReturnRows(actionQueueRowsEmpty())
	database.ExpectRollback()

	if _, err := repository.Start(context.Background(), fence); !errors.Is(err, executionlease.ErrStaleLease) {
		t.Fatalf("Start(expired authorization) error = %v, want %v", err, executionlease.ErrStaleLease)
	}
	assertExpectations(t, database)
}

func TestHeartbeatAtomicallyTerminatesWhenRunnerRegistrationRevisionChanged(t *testing.T) {
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := signedTestEnvelope(t, now)
	envelopeJSON, _ := json.Marshal(envelope)
	fence := executionlease.LeaseIdentity{ExecutionID: envelope.ActionID, RunnerID: "runner-1", Token: testLeaseToken, Epoch: 2}
	running := executionlease.Execution{
		ExecutionID: envelope.ActionID, TargetKey: "k8s-deployment:sha256:" + strings.Repeat("a", 64),
		Pool: executionlease.PoolWrite, Production: true, Status: executionlease.StatusRunning,
		RunnerID: fence.RunnerID, RunnerTenantID: testTenantID, RunnerWorkspaceID: envelope.WorkspaceID,
		RunnerEnvironmentID: envelope.Target.EnvironmentID, ScopeRevision: 1, LeaseEpoch: fence.Epoch,
		LeaseAcquiredAt: now.Add(-time.Minute), LastHeartbeatAt: now.Add(-time.Minute), LeaseExpiresAt: now.Add(time.Minute),
		StartedAt: now.Add(-time.Minute), CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
	}
	database.ExpectBegin()
	database.ExpectQuery(`(?s)SELECT tenant_id::text, runner_pool, enabled, scope_revision.*FROM runner_registrations.*WHERE runner_id = \$1.*FOR SHARE`).
		WithArgs(fence.RunnerID).
		WillReturnRows(pgxmock.NewRows([]string{"tenant_id", "runner_pool", "enabled", "scope_revision"}).
			AddRow(testTenantID, executionlease.PoolWrite, true, int64(2)))
	database.ExpectQuery(`(?s)SELECT .*FROM action_queue.*WHERE action_id = \$1.*FOR UPDATE`).
		WithArgs(fence.ExecutionID).
		WillReturnRows(actionQueueRowsDetailed(running, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), tokenHash(fence.Token), nil, nil, now, nil))
	database.ExpectCommit()

	result, err := repository.Heartbeat(context.Background(), execution.ActionHeartbeatRequest{
		Lease: fence, Sequence: 1, Extension: time.Minute,
	})
	if err != nil || result.Directive != execution.HeartbeatTerminate ||
		!result.Execution.LeaseExpiresAt.Equal(running.LeaseExpiresAt) {
		t.Fatalf("Heartbeat(scope revision changed) = %#v, %v", result, err)
	}
	assertExpectations(t, database)
}

func TestHeartbeatTerminatesWithoutExtensionAtDatabaseAuthorizationBoundary(t *testing.T) {
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := signedTestEnvelope(t, now)
	envelopeJSON, _ := json.Marshal(envelope)
	fence := executionlease.LeaseIdentity{ExecutionID: envelope.ActionID, RunnerID: "runner-1", Token: testLeaseToken, Epoch: 2}
	running := executionlease.Execution{
		ExecutionID: envelope.ActionID, TargetKey: "k8s-deployment:sha256:" + strings.Repeat("a", 64),
		Pool: executionlease.PoolWrite, Production: true, Status: executionlease.StatusRunning,
		RunnerID: fence.RunnerID, RunnerTenantID: testTenantID, RunnerWorkspaceID: envelope.WorkspaceID,
		RunnerEnvironmentID: envelope.Target.EnvironmentID, ScopeRevision: 1, LeaseEpoch: fence.Epoch,
		LeaseAcquiredAt: now.Add(-time.Minute), LastHeartbeatAt: now.Add(-time.Minute), LeaseExpiresAt: now.Add(time.Minute),
		StartedAt: now.Add(-time.Minute), CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
	}
	database.ExpectBegin()
	expectRunnerRegistrationLock(database, fence.RunnerID, testTenantID, executionlease.PoolWrite, true, 1)
	database.ExpectQuery(`(?s)SELECT .*FROM action_queue.*WHERE action_id = \$1.*FOR UPDATE`).
		WithArgs(fence.ExecutionID).
		WillReturnRows(actionQueueRowsDetailed(running, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), tokenHash(fence.Token), nil, nil, now, nil))
	database.ExpectQuery(`(?s)SELECT COALESCE\(lease_expires_at > statement_timestamp\(\), false\),.*authorization_expires_at > statement_timestamp\(\).*FROM action_queue`).
		WithArgs(fence.ExecutionID).
		WillReturnRows(pgxmock.NewRows([]string{"lease_current", "authorization_current"}).AddRow(false, false))
	database.ExpectCommit()

	result, err := repository.Heartbeat(context.Background(), execution.ActionHeartbeatRequest{
		Lease: fence, Sequence: 1, Extension: time.Minute,
	})
	if err != nil || result.Directive != execution.HeartbeatTerminate ||
		!result.Execution.LeaseExpiresAt.Equal(running.LeaseExpiresAt) {
		t.Fatalf("Heartbeat(expired authorization) = %#v, %v", result, err)
	}
	assertExpectations(t, database)
}

func TestHeartbeatTerminatesIfAuthorizationExpiresDuringAtomicUpdate(t *testing.T) {
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := signedTestEnvelope(t, now)
	envelopeJSON, _ := json.Marshal(envelope)
	fence := executionlease.LeaseIdentity{ExecutionID: envelope.ActionID, RunnerID: "runner-1", Token: testLeaseToken, Epoch: 2}
	running := executionlease.Execution{
		ExecutionID: envelope.ActionID, TargetKey: "k8s-deployment:sha256:" + strings.Repeat("a", 64),
		Pool: executionlease.PoolWrite, Production: true, Status: executionlease.StatusRunning,
		RunnerID: fence.RunnerID, RunnerTenantID: testTenantID, RunnerWorkspaceID: envelope.WorkspaceID,
		RunnerEnvironmentID: envelope.Target.EnvironmentID, ScopeRevision: 1, LeaseEpoch: fence.Epoch,
		LeaseAcquiredAt: now.Add(-time.Minute), LastHeartbeatAt: now.Add(-time.Minute), LeaseExpiresAt: now.Add(time.Minute),
		StartedAt: now.Add(-time.Minute), CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
	}
	database.ExpectBegin()
	expectRunnerRegistrationLock(database, fence.RunnerID, testTenantID, executionlease.PoolWrite, true, 1)
	database.ExpectQuery(`(?s)SELECT .*FROM action_queue.*WHERE action_id = \$1.*FOR UPDATE`).
		WithArgs(fence.ExecutionID).
		WillReturnRows(actionQueueRowsDetailed(running, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), tokenHash(fence.Token), nil, nil, now, nil))
	database.ExpectQuery(`(?s)SELECT COALESCE\(lease_expires_at > statement_timestamp\(\), false\),.*authorization_expires_at > statement_timestamp\(\).*FROM action_queue`).
		WithArgs(fence.ExecutionID).
		WillReturnRows(pgxmock.NewRows([]string{"lease_current", "authorization_current"}).AddRow(true, true))
	database.ExpectQuery(`(?s)UPDATE action_queue.*LEAST\(statement_timestamp\(\) \+ make_interval\(secs => \$6::double precision\), authorization_expires_at\).*RETURNING`).
		WithArgs(fence.ExecutionID, fence.RunnerID, tokenHash(fence.Token), fence.Epoch, int64(1), float64(60)).
		WillReturnRows(actionQueueRowsEmpty())
	database.ExpectQuery(`(?s)SELECT COALESCE\(lease_expires_at > statement_timestamp\(\), false\),.*authorization_expires_at > statement_timestamp\(\).*FROM action_queue`).
		WithArgs(fence.ExecutionID).
		WillReturnRows(pgxmock.NewRows([]string{"lease_current", "authorization_current"}).AddRow(true, false))
	database.ExpectCommit()

	result, err := repository.Heartbeat(context.Background(), execution.ActionHeartbeatRequest{
		Lease: fence, Sequence: 1, Extension: time.Minute,
	})
	if err != nil || result.Directive != execution.HeartbeatTerminate || result.Execution.HeartbeatSeq != 0 ||
		!result.Execution.LeaseExpiresAt.Equal(running.LeaseExpiresAt) {
		t.Fatalf("Heartbeat(expiry during update) = %#v, %v", result, err)
	}
	assertExpectations(t, database)
}

func TestCompleteAtomicallyConsumesFenceAndKeepsOnlyTokenHashForIdempotency(t *testing.T) {
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := signedTestEnvelope(t, now)
	envelopeJSON, _ := json.Marshal(envelope)
	fence := executionlease.LeaseIdentity{ExecutionID: envelope.ActionID, RunnerID: "runner-1", Token: testLeaseToken, Epoch: 3}
	digest := tokenHash(fence.Token)
	running := executionlease.Execution{
		ExecutionID: envelope.ActionID, TargetKey: "k8s-deployment:sha256:" + strings.Repeat("a", 64),
		Pool: executionlease.PoolWrite, Production: true, Status: executionlease.StatusRunning,
		RunnerID: fence.RunnerID, RunnerTenantID: testTenantID, RunnerWorkspaceID: envelope.WorkspaceID,
		RunnerEnvironmentID: envelope.Target.EnvironmentID, LeaseEpoch: fence.Epoch, LeaseAcquiredAt: now.Add(-2 * time.Minute),
		LeaseExpiresAt: now.Add(time.Minute), LastHeartbeatAt: now.Add(-time.Minute), StartedAt: now.Add(-time.Minute),
		ScopeRevision: 1, CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
	}
	summary := execution.ExecutorResult{Outcome: execution.ExecutorSucceeded, Code: "COMPLETED", Verification: execution.VerificationPassed}
	receipt, err := execution.BuildRunnerResultReceipt(execution.ClaimedAction{
		Execution: running, Envelope: envelope, PlanHash: envelope.PlanHash,
		TargetKey: running.TargetKey, EnvironmentRevision: "environment-1", Production: true,
	}, execution.ActionCompleteRequest{Lease: fence, Summary: summary}, executionlease.StatusSucceeded, time.Time{})
	if err != nil {
		t.Fatalf("BuildRunnerResultReceipt() error = %v", err)
	}
	finalizing := running
	finalizing.Status = executionlease.StatusFinalizing
	finalizing.CompletionStatus = executionlease.StatusSucceeded
	finalizing.ResultHash = receipt.ResultHash
	finalizing.LeaseExpiresAt = time.Time{}
	completed := finalizing
	completed.Status = executionlease.StatusSucceeded
	completed.CompletedAt = now
	database.ExpectBegin()
	expectRunnerRegistrationLock(database, fence.RunnerID, testTenantID, executionlease.PoolWrite, true, 1)
	database.ExpectQuery(`(?s)SELECT .* FROM action_queue WHERE action_id = \$1 FOR UPDATE`).
		WithArgs(fence.ExecutionID).
		WillReturnRows(actionQueueRowsDetailed(running, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), digest, nil, nil, now, nil))
	database.ExpectQuery(`(?s)UPDATE action_queue.*status = 'FINALIZING'.*completion_status = \$5.*result_hash = \$6.*completed_lease_token_sha256 = lease_token_sha256.*RETURNING`).
		WithArgs(fence.ExecutionID, fence.RunnerID, digest, fence.Epoch, executionlease.StatusSucceeded, receipt.ResultHash).
		WillReturnRows(actionQueueRowsDetailed(finalizing, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), nil, digest, fence.Epoch, now, nil))
	database.ExpectExec("INSERT INTO runner_result_receipts").
		WithArgs(fence.ExecutionID, testTenantID, envelope.WorkspaceID, envelope.Target.EnvironmentID,
			fence.RunnerID, fence.Epoch, int64(1), receipt.ResultHash, executionlease.StatusSucceeded, pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	got, err := repository.Complete(context.Background(), execution.ActionCompleteRequest{
		Lease: fence, Summary: summary,
	})
	if err != nil || got != finalizing || got.LeaseToken != "" {
		t.Fatalf("Complete() = %#v, %v; want %#v", got, err, finalizing)
	}
	database.ExpectBegin()
	expectRunnerRegistrationLock(database, fence.RunnerID, testTenantID, executionlease.PoolWrite, true, 1)
	database.ExpectQuery(`(?s)SELECT .* FROM action_queue WHERE action_id = \$1 FOR UPDATE`).
		WithArgs(fence.ExecutionID).
		WillReturnRows(actionQueueRowsDetailed(finalizing, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), nil, digest, fence.Epoch, now, nil))
	database.ExpectRollback()
	conflictingSummary := summary
	conflictingSummary.Code = "DIFFERENT_RESULT"
	if _, err := repository.Complete(context.Background(), execution.ActionCompleteRequest{
		Lease: fence, Summary: conflictingSummary,
	}); !errors.Is(err, executionlease.ErrCompletionConflict) {
		t.Fatalf("Complete(conflicting receipt) error = %v", err)
	}
	database.ExpectQuery(`(?s)UPDATE action_queue AS finalizing.*status = finalizing\.completion_status.*runner_result_receipts.*RETURNING`).
		WithArgs(fence.ExecutionID, fence.RunnerID, digest, fence.Epoch).
		WillReturnRows(actionQueueRowsDetailed(completed, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), nil, digest, fence.Epoch, now, nil))
	got, err = repository.Finalize(context.Background(), fence)
	if err != nil || got != completed {
		t.Fatalf("Finalize() = %#v, %v; want %#v", got, err, completed)
	}
	assertExpectations(t, database)
}

func TestCompleteRejectsReceiptWhenRunnerRegistrationRevisionChanged(t *testing.T) {
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := signedTestEnvelope(t, now)
	envelopeJSON, _ := json.Marshal(envelope)
	fence := executionlease.LeaseIdentity{ExecutionID: envelope.ActionID, RunnerID: "runner-1", Token: testLeaseToken, Epoch: 3}
	running := executionlease.Execution{
		ExecutionID: envelope.ActionID, TargetKey: "k8s-deployment:sha256:" + strings.Repeat("a", 64),
		Pool: executionlease.PoolWrite, Production: true, Status: executionlease.StatusRunning,
		RunnerID: fence.RunnerID, RunnerTenantID: testTenantID, RunnerWorkspaceID: envelope.WorkspaceID,
		RunnerEnvironmentID: envelope.Target.EnvironmentID, ScopeRevision: 1, LeaseEpoch: fence.Epoch,
		LeaseAcquiredAt: now.Add(-2 * time.Minute), LeaseExpiresAt: now.Add(time.Minute),
		LastHeartbeatAt: now.Add(-time.Minute), StartedAt: now.Add(-time.Minute), CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
	}
	database.ExpectBegin()
	database.ExpectQuery(`(?s)SELECT tenant_id::text, runner_pool, enabled, scope_revision.*FOR SHARE`).
		WithArgs(fence.RunnerID).
		WillReturnRows(pgxmock.NewRows([]string{"tenant_id", "runner_pool", "enabled", "scope_revision"}).
			AddRow(testTenantID, executionlease.PoolWrite, true, int64(2)))
	database.ExpectQuery(`(?s)SELECT .*FROM action_queue.*WHERE action_id = \$1 FOR UPDATE`).
		WithArgs(fence.ExecutionID).
		WillReturnRows(actionQueueRowsDetailed(running, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), tokenHash(fence.Token), nil, nil, now, nil))
	database.ExpectRollback()

	_, err := repository.Complete(context.Background(), execution.ActionCompleteRequest{
		Lease:   fence,
		Summary: execution.ExecutorResult{Outcome: execution.ExecutorSucceeded, Code: "COMPLETED", Verification: execution.VerificationPassed},
	})
	if !errors.Is(err, executionlease.ErrStaleLease) {
		t.Fatalf("Complete(scope revision changed) error = %v, want %v", err, executionlease.ErrStaleLease)
	}
	assertExpectations(t, database)
}

func TestCompleteIdempotentReceiptReadClassifiesConflictsAndPreservesDatabaseErrors(t *testing.T) {
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := signedTestEnvelope(t, now)
	envelopeJSON, _ := json.Marshal(envelope)
	fence := executionlease.LeaseIdentity{ExecutionID: envelope.ActionID, RunnerID: "runner-1", Token: testLeaseToken, Epoch: 3}
	digest := tokenHash(fence.Token)
	summary := execution.ExecutorResult{Outcome: execution.ExecutorSucceeded, Code: "COMPLETED", Verification: execution.VerificationPassed}
	finalizing := executionlease.Execution{
		ExecutionID: envelope.ActionID, TargetKey: "k8s-deployment:sha256:" + strings.Repeat("a", 64),
		Pool: executionlease.PoolWrite, Production: true, Status: executionlease.StatusFinalizing,
		CompletionStatus: executionlease.StatusSucceeded, RunnerID: fence.RunnerID, RunnerTenantID: testTenantID,
		RunnerWorkspaceID: envelope.WorkspaceID, RunnerEnvironmentID: envelope.Target.EnvironmentID,
		ScopeRevision: 1, LeaseEpoch: fence.Epoch, LeaseAcquiredAt: now.Add(-2 * time.Minute),
		LastHeartbeatAt: now.Add(-time.Minute), StartedAt: now.Add(-time.Minute), CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
	}
	receipt, err := execution.BuildRunnerResultReceipt(execution.ClaimedAction{
		Execution: finalizing, Envelope: envelope, PlanHash: envelope.PlanHash,
		TargetKey: finalizing.TargetKey, EnvironmentRevision: "environment-1", Production: true,
	}, execution.ActionCompleteRequest{Lease: fence, Summary: summary}, executionlease.StatusSucceeded, time.Time{})
	if err != nil {
		t.Fatalf("BuildRunnerResultReceipt() error = %v", err)
	}
	finalizing.ResultHash = receipt.ResultHash
	readErr := errors.New("receipt connection lost")
	tests := []struct {
		name          string
		storedHash    string
		readErr       error
		wantConflict  bool
		wantPreserved error
	}{
		{name: "missing receipt", wantConflict: true},
		{name: "mismatched receipt hash", storedHash: strings.Repeat("f", 64), wantConflict: true},
		{name: "database error", readErr: readErr, wantPreserved: readErr},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database, repository := newActionQueueRepository(t)
			defer database.Close()
			database.ExpectBegin()
			expectRunnerRegistrationLock(database, fence.RunnerID, testTenantID, executionlease.PoolWrite, true, 1)
			database.ExpectQuery(`(?s)SELECT .*FROM action_queue.*WHERE action_id = \$1 FOR UPDATE`).
				WithArgs(fence.ExecutionID).
				WillReturnRows(actionQueueRowsDetailed(finalizing, envelopeJSON, envelope.PlanHash, "environment-1",
					envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), nil, digest, fence.Epoch, now, nil))
			receiptExpectation := database.ExpectQuery(`SELECT receipt_hash FROM runner_result_receipts`).
				WithArgs(fence.ExecutionID, fence.Epoch)
			if test.readErr != nil {
				receiptExpectation.WillReturnError(test.readErr)
			} else {
				rows := pgxmock.NewRows([]string{"receipt_hash"})
				if test.storedHash != "" {
					rows.AddRow(test.storedHash)
				}
				receiptExpectation.WillReturnRows(rows)
			}
			database.ExpectRollback()

			_, completeErr := repository.Complete(context.Background(), execution.ActionCompleteRequest{Lease: fence, Summary: summary})
			if test.wantConflict && !errors.Is(completeErr, executionlease.ErrCompletionConflict) {
				t.Fatalf("Complete(idempotent receipt conflict) error = %v, want %v", completeErr, executionlease.ErrCompletionConflict)
			}
			if test.wantPreserved != nil && (!errors.Is(completeErr, test.wantPreserved) || errors.Is(completeErr, executionlease.ErrCompletionConflict)) {
				t.Fatalf("Complete(idempotent receipt read failure) error = %v, want wrapped database error", completeErr)
			}
			assertExpectations(t, database)
		})
	}
}

func TestRejectAndNackUseFencedStructuredReasonHashes(t *testing.T) {
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := signedTestEnvelope(t, now)
	envelopeJSON, _ := json.Marshal(envelope)
	fence := executionlease.LeaseIdentity{ExecutionID: envelope.ActionID, RunnerID: "runner-1", Token: testLeaseToken, Epoch: 1}
	digest := tokenHash(fence.Token)
	reason := execution.ActionQueueReason{Code: "PERMANENT_POLICY_DENIAL", DetailHash: strings.Repeat("d", 64)}
	reasonDigest, err := reasonHash(reason)
	if err != nil {
		t.Fatalf("reasonHash() error = %v", err)
	}
	targetKey := "k8s-deployment:sha256:" + strings.Repeat("a", 64)

	t.Run("reject is terminal", func(t *testing.T) {
		database, repository := newActionQueueRepository(t)
		defer database.Close()
		rejected := executionlease.Execution{
			ExecutionID: envelope.ActionID, TargetKey: targetKey, Pool: executionlease.PoolWrite,
			Production: true, Status: executionlease.StatusFailed, RunnerID: fence.RunnerID,
			LeaseEpoch: fence.Epoch, LeaseAcquiredAt: now.Add(-time.Minute), LastHeartbeatAt: now.Add(-time.Minute),
			CompletedAt: now, ResultHash: reasonDigest, CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
		}
		database.ExpectBegin()
		database.ExpectQuery(`(?s)UPDATE action_queue.*status = 'FAILED'.*completed_lease_token_sha256 = lease_token_sha256.*lease_token_sha256 = NULL.*result_hash = \$5.*status = 'LEASED'.*RETURNING`).
			WithArgs(fence.ExecutionID, fence.RunnerID, digest, fence.Epoch, reasonDigest).
			WillReturnRows(actionQueueRowsDetailed(rejected, envelopeJSON, envelope.PlanHash, "environment-1",
				envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), nil, digest, fence.Epoch, now, nil))
		database.ExpectCommit()
		got, err := repository.Reject(context.Background(), execution.ActionRejectRequest{Lease: fence, Reason: reason})
		if err != nil || got != rejected || got.LeaseToken != "" {
			t.Fatalf("Reject() = %#v, %v", got, err)
		}
		assertExpectations(t, database)
	})

	t.Run("nack queues with server-side backoff", func(t *testing.T) {
		database, repository := newActionQueueRepository(t)
		defer database.Close()
		queued := executionlease.Execution{
			ExecutionID: envelope.ActionID, TargetKey: targetKey, Pool: executionlease.PoolWrite,
			Production: true, Status: executionlease.StatusQueued, LeaseEpoch: fence.Epoch,
			CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
		}
		database.ExpectQuery(`(?s)UPDATE action_queue.*status = 'QUEUED'.*last_nack_hash = \$5.*not_before = statement_timestamp\(\) \+ make_interval\(secs => \$6::double precision\).*lease_token_sha256 = NULL.*status = 'LEASED'.*RETURNING`).
			WithArgs(fence.ExecutionID, fence.RunnerID, digest, fence.Epoch, reasonDigest, float64(30)).
			WillReturnRows(actionQueueRowsDetailed(queued, envelopeJSON, envelope.PlanHash, "environment-1",
				envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), nil, nil, nil, now.Add(30*time.Second), reasonDigest))
		got, err := repository.Nack(context.Background(), execution.ActionNackRequest{
			Lease: fence, Reason: reason, RetryAfter: 30 * time.Second,
		})
		if err != nil || got.Status != executionlease.StatusQueued || got.LeaseToken != "" {
			t.Fatalf("Nack() = %#v, %v", got, err)
		}
		assertExpectations(t, database)
	})
}

func TestSweepExpiredAndGetUseServerClockAndMaterializeUncertainState(t *testing.T) {
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := signedTestEnvelope(t, now)
	envelopeJSON, _ := json.Marshal(envelope)

	t.Run("global sweep", func(t *testing.T) {
		database, repository := newActionQueueRepository(t)
		defer database.Close()
		database.ExpectBegin()
		database.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs(pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("SELECT", 1))
		database.ExpectExec(`(?s)UPDATE action_queue AS expired_running.*completed_lease_token_sha256 = lease_token_sha256.*completed_lease_epoch = lease_epoch.*lease_token_sha256 = NULL`).
			WithArgs(expiredResultHash()).WillReturnResult(pgxmock.NewResult("UPDATE", 2))
		database.ExpectExec(`(?s)UPDATE action_queue AS expired_finalizing.*authorization_expires_at.*runner_result_receipts.*receipt_hash = expired_finalizing\.result_hash`).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		database.ExpectExec("UPDATE action_queue AS expired_lease").WillReturnResult(pgxmock.NewResult("UPDATE", 3))
		database.ExpectCommit()
		if err := repository.SweepExpired(context.Background()); err != nil {
			t.Fatalf("SweepExpired() error = %v", err)
		}
		assertExpectations(t, database)
	})

	t.Run("get materializes one target", func(t *testing.T) {
		database, repository := newActionQueueRepository(t)
		defer database.Close()
		database.ExpectBegin()
		database.ExpectExec("UPDATE action_queue AS expired_running").
			WithArgs(expiredResultHash(), envelope.ActionID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		database.ExpectExec("UPDATE action_queue AS expired_finalizing").
			WithArgs(envelope.ActionID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 0))
		database.ExpectExec("UPDATE action_queue AS expired_lease").
			WithArgs(envelope.ActionID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 0))
		database.ExpectCommit()
		uncertain := executionlease.Execution{
			ExecutionID: envelope.ActionID, TargetKey: "k8s-deployment:sha256:" + strings.Repeat("a", 64),
			Pool: executionlease.PoolWrite, Production: true, Status: executionlease.StatusUncertain,
			RunnerID: "runner-1", LeaseEpoch: 2, CompletedAt: now, ResultHash: expiredResultHash(),
			CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
		}
		database.ExpectQuery(`(?s)SELECT .*FROM action_queue.*WHERE action_id = \$1`).
			WithArgs(envelope.ActionID).
			WillReturnRows(actionQueueRowsDetailed(uncertain, envelopeJSON, envelope.PlanHash, "environment-1",
				envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), nil, tokenHash(testLeaseToken), int64(2), now, nil))
		got, err := repository.Get(context.Background(), envelope.ActionID)
		if err != nil || got != uncertain || got.LeaseToken != "" {
			t.Fatalf("Get() = %#v, %v", got, err)
		}
		assertExpectations(t, database)
	})
}

func TestReconcileAndCancelResolveUncertainOutcomesWithoutReusableToken(t *testing.T) {
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := signedTestEnvelope(t, now)
	envelopeJSON, _ := json.Marshal(envelope)
	targetKey := "k8s-deployment:sha256:" + strings.Repeat("a", 64)

	t.Run("reconcile", func(t *testing.T) {
		database, repository := newActionQueueRepository(t)
		defer database.Close()
		request := executionlease.ReconcileRequest{
			ExecutionID: envelope.ActionID, ReconciliationID: "reconciliation-1", ActorID: "sre-1",
			Status: executionlease.StatusSucceeded, ResultHash: strings.Repeat("e", 64),
		}
		reconciled := executionlease.Execution{
			ExecutionID: envelope.ActionID, TargetKey: targetKey, Pool: executionlease.PoolWrite,
			Production: true, Status: request.Status, RunnerID: "runner-1", LeaseEpoch: 2,
			CompletedAt: now.Add(-time.Minute), ResultHash: expiredResultHash(), CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
			ReconciliationID: request.ReconciliationID, ReconciliationActor: request.ActorID,
			ReconciliationResultHash: request.ResultHash, ReconciledAt: now,
		}
		database.ExpectBegin()
		database.ExpectExec("UPDATE action_queue AS expired_running").
			WithArgs(expiredResultHash(), envelope.ActionID).WillReturnResult(pgxmock.NewResult("UPDATE", 0))
		database.ExpectExec("UPDATE action_queue AS expired_finalizing").
			WithArgs(envelope.ActionID).WillReturnResult(pgxmock.NewResult("UPDATE", 0))
		database.ExpectExec("UPDATE action_queue AS expired_lease").
			WithArgs(envelope.ActionID).WillReturnResult(pgxmock.NewResult("UPDATE", 0))
		database.ExpectQuery(`(?s)UPDATE action_queue.*reconciliation_id = \$2.*status = \$4.*status = 'UNCERTAIN'.*RETURNING`).
			WithArgs(request.ExecutionID, request.ReconciliationID, request.ActorID, request.Status, request.ResultHash).
			WillReturnRows(actionQueueRowsDetailed(reconciled, envelopeJSON, envelope.PlanHash, "environment-1",
				envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), nil, tokenHash(testLeaseToken), int64(2), now, nil))
		database.ExpectCommit()
		got, err := repository.Reconcile(context.Background(), request)
		if err != nil || got != reconciled || got.LeaseToken != "" {
			t.Fatalf("Reconcile() = %#v, %v", got, err)
		}
		assertExpectations(t, database)
	})

	t.Run("cancel running persists intent without clearing fence", func(t *testing.T) {
		database, repository := newActionQueueRepository(t)
		defer database.Close()
		cancelled := executionlease.Execution{
			ExecutionID: envelope.ActionID, TargetKey: targetKey, Pool: executionlease.PoolWrite,
			Production: true, Status: executionlease.StatusRunning, RunnerID: "runner-1", ScopeRevision: 1, LeaseEpoch: 2,
			LeaseAcquiredAt: now.Add(-2 * time.Minute), LastHeartbeatAt: now.Add(-time.Minute), LeaseExpiresAt: now.Add(time.Minute),
			StartedAt: now.Add(-time.Minute), CancelRequestedAt: now, CancelReasonHash: cancellationResultHash(),
			CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
		}
		database.ExpectQuery(`(?s)UPDATE action_queue.*status = CASE WHEN status = 'RUNNING' THEN status ELSE 'CANCELLED' END.*cancel_requested_at = CASE WHEN status = 'RUNNING'.*lease_token_sha256 = CASE WHEN status = 'RUNNING' THEN lease_token_sha256 ELSE NULL END.*RETURNING`).
			WithArgs(envelope.ActionID, cancellationResultHash()).
			WillReturnRows(actionQueueRowsDetailed(cancelled, envelopeJSON, envelope.PlanHash, "environment-1",
				envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), tokenHash(testLeaseToken), nil, nil, now, nil))
		got, err := repository.Cancel(context.Background(), envelope.ActionID)
		if err != nil || got != cancelled || got.LeaseToken != "" {
			t.Fatalf("Cancel() = %#v, %v", got, err)
		}
		assertExpectations(t, database)
	})
}

func newActionQueueRepository(t *testing.T) (pgxmock.PgxPoolIface, *Repository) {
	t.Helper()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	repository, err := New(database, Options{TokenSource: func() (string, error) { return testLeaseToken, nil }})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return database, repository
}

func expectRunnerRegistrationLock(database pgxmock.PgxPoolIface, runnerID, tenantID string, pool executionlease.Pool, enabled bool, scopeRevision int64) {
	database.ExpectQuery(`(?s)SELECT tenant_id::text, runner_pool, enabled, scope_revision.*FROM runner_registrations.*WHERE runner_id = \$1.*FOR SHARE`).
		WithArgs(runnerID).
		WillReturnRows(pgxmock.NewRows([]string{"tenant_id", "runner_pool", "enabled", "scope_revision"}).
			AddRow(tenantID, pool, enabled, scopeRevision))
}

func testRunnerScope(t *testing.T, runnerID, workspaceID, environmentID string) execution.RunnerScope {
	t.Helper()
	scope, err := (execution.RunnerRegistration{
		RunnerID: runnerID, TenantID: testTenantID,
		Pool: executionlease.PoolWrite, Enabled: true, ScopeRevision: 1, MaxConcurrency: 1,
		ScopeBindings: []execution.RunnerScopeBinding{{WorkspaceID: workspaceID, EnvironmentID: environmentID}},
	}).Scope()
	if err != nil {
		t.Fatalf("RunnerRegistration.Scope() error = %v", err)
	}
	return scope
}

func actionQueueRows(value executionlease.Execution, envelopeJSON []byte, planHash, environmentRevision, workspaceID, environmentID, submissionHash string) *pgxmock.Rows {
	return actionQueueRowsDetailed(value, envelopeJSON, planHash, environmentRevision, workspaceID, environmentID, submissionHash, nil, nil, nil, value.CreatedAt, nil)
}

func actionQueueRowsDetailed(value executionlease.Execution, envelopeJSON []byte, planHash, environmentRevision, workspaceID, environmentID, submissionHash string, leaseTokenHash, completedLeaseTokenHash, completedLeaseEpoch, notBefore, lastNackHash any, storedRequestHashVersions ...string) *pgxmock.Rows {
	var envelope action.Envelope
	if err := json.Unmarshal(envelopeJSON, &envelope); err != nil {
		panic(err)
	}
	if submissionHash == strings.Repeat("b", 64) {
		computed, err := hashSubmission(execution.ActionSubmission{
			Envelope: envelope, PlanHash: planHash, TargetKey: value.TargetKey,
			EnvironmentRevision: environmentRevision, Production: value.Production, Pool: value.Pool,
		}, envelopeJSON)
		if err != nil {
			panic(err)
		}
		submissionHash = computed
	}
	requestHash, err := execution.RequestSemanticHash(execution.ActionSubmission{
		Envelope: envelope, PlanHash: planHash, TargetKey: value.TargetKey,
		EnvironmentRevision: environmentRevision, Production: value.Production, Pool: value.Pool,
	})
	if err != nil {
		panic(err)
	}
	storedRequestHashVersion := requestHashVersion
	if len(storedRequestHashVersions) > 0 {
		if len(storedRequestHashVersions) != 1 {
			panic("actionQueueRowsDetailed accepts at most one stored request hash version")
		}
		storedRequestHashVersion = storedRequestHashVersions[0]
		if storedRequestHashVersion == "legacy-submission.v1" {
			requestHash = submissionHash
		}
	}
	return actionQueueRowsEmpty().AddRow(
		value.ExecutionID, value.TargetKey, value.Pool, value.Production, value.Status,
		nullString(value.RunnerID), nullString(value.RunnerTenantID), nullString(value.RunnerWorkspaceID), nullString(value.RunnerEnvironmentID),
		value.LeaseEpoch, nullTime(value.LeaseExpiresAt), nullTime(value.LeaseAcquiredAt), nullTime(value.LastHeartbeatAt),
		nullTime(value.StartedAt), nullTime(value.CompletedAt), nullString(value.ResultHash), value.CreatedAt, value.UpdatedAt,
		nullString(value.ReconciliationID), nullString(value.ReconciliationActor), nullString(value.ReconciliationResultHash), nullTime(value.ReconciledAt),
		envelopeJSON, planHash, environmentRevision, envelope.ExpiresAt, workspaceID, environmentID,
		submissionHash, leaseTokenHash, completedLeaseTokenHash, completedLeaseEpoch, notBefore, lastNackHash,
		envelope.IdempotencyKey, requestHash, storedRequestHashVersion, nullInt64(value.ScopeRevision), value.HeartbeatSeq,
		nullTime(value.CancelRequestedAt), nullString(value.CancelReasonHash), nullString(string(value.CompletionStatus)),
	)
}

func actionQueueRowsEmpty() *pgxmock.Rows {
	return pgxmock.NewRows([]string{
		"action_id", "target_key", "runner_pool", "production", "status",
		"runner_id", "runner_tenant_id", "runner_workspace_id", "runner_environment_id",
		"lease_epoch", "lease_expires_at", "lease_acquired_at", "last_heartbeat_at",
		"started_at", "completed_at", "result_hash", "created_at", "updated_at",
		"reconciliation_id", "reconciliation_actor", "reconciliation_result_hash", "reconciled_at",
		"envelope", "plan_hash", "environment_revision", "authorization_expires_at", "workspace_id", "environment_id",
		"submission_hash", "lease_token_sha256", "completed_lease_token_sha256", "completed_lease_epoch",
		"not_before", "last_nack_hash",
		"idempotency_key", "request_hash", "request_hash_version", "scope_revision", "heartbeat_seq",
		"cancel_requested_at", "cancel_reason_hash", "completion_status",
	})
}

func nullInt64(value int64) any {
	if value == 0 {
		return nil
	}
	return value
}

func signedTestEnvelope(t *testing.T, now time.Time) action.Envelope {
	return signedTestEnvelopeWithExpiry(t, now, now.Add(30*time.Minute))
}

func signedTestEnvelopeWithExpiry(t *testing.T, now, expiresAt time.Time) action.Envelope {
	t.Helper()
	envelope := action.Envelope{
		SchemaVersion: action.SchemaVersionV1, ActionID: "action-1", WorkspaceID: "workspace-1",
		IncidentID: "incident-1", RequestedBy: "requester-1", ActionType: action.ActionKubernetesRolloutRestart,
		Target: action.TargetRef{ServiceID: "payments", EnvironmentID: "PROD", KubernetesDeployment: &action.KubernetesDeploymentTarget{
			ClusterID: "cluster-1", Namespace: "payments", Name: "api", UID: "uid-1", ResourceVersion: "7",
		}},
		Parameters: action.ActionParameters{KubernetesRolloutRestart: &action.KubernetesRolloutRestartParameters{Reason: "deadlock"}},
		ObservedState: action.ObservedState{KubernetesDeployment: &action.KubernetesDeploymentObservedState{
			Generation: 3, Replicas: 2, AvailableReplicas: 2, UpdatedReplicas: 2,
		}},
		Preconditions: action.Preconditions{MappingResult: "EXACT", ExpectedResourceVersion: "7", RequireWhitelist: true},
		Verification: action.VerificationPlan{
			Mode: "KUBERNETES_ROLLOUT", TimeoutSeconds: int32(min(int(expiresAt.Sub(now).Seconds()), 300)),
		},
		Compensation:  action.CompensationPlan{Mode: "MANUAL_ONLY", Summary: "runbook"},
		Risk:          action.RiskAssessment{Level: "MEDIUM", ReasonCodes: []string{"PRODUCTION_CHANGE", "RESTART"}},
		PolicyVersion: "policy.v1",
		CredentialScope: action.CredentialScope{
			ConnectorID: "kubernetes-prod", Permission: "PATCH_DEPLOYMENT_RESTART", Resource: "cluster-1/payments/deployment/api",
			TTLSeconds: int32(min(int(expiresAt.Sub(now).Seconds()), 600)),
		},
		IdempotencyKey: "idem-action-1", NotBefore: now, ExpiresAt: expiresAt, TraceID: strings.Repeat("a", 32),
	}
	return resealTestEnvelope(t, envelope)
}

func resealTestEnvelope(t *testing.T, envelope action.Envelope) action.Envelope {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	signer, err := action.NewEd25519Signer("queue-test-key", privateKey)
	if err != nil {
		t.Fatalf("action.NewEd25519Signer() error = %v", err)
	}
	sealed, err := action.Seal(context.Background(), envelope, envelope.RequestedBy, signer)
	if err != nil {
		t.Fatalf("action.Seal() error = %v", err)
	}
	return sealed
}

func nullString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}

func assertExpectations(t *testing.T, database pgxmock.PgxPoolIface) {
	t.Helper()
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("database expectations: %v", err)
	}
}
