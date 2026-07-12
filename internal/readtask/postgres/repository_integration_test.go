package postgres_test

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/seaworld008/aiops-system/internal/execution"
	"github.com/seaworld008/aiops-system/internal/readtask"
	readtaskpostgres "github.com/seaworld008/aiops-system/internal/readtask/postgres"
	"github.com/seaworld008/aiops-system/internal/runneridentity"
	runneridentitypostgres "github.com/seaworld008/aiops-system/internal/runneridentity/postgres"
	"github.com/seaworld008/aiops-system/internal/runneridentity/testpki"
)

const (
	integrationTenantID        = "11000000-0000-4000-8000-000000000001"
	integrationWorkspaceID     = "22000000-0000-4000-8000-000000000001"
	integrationEnvironmentID   = "33000000-0000-4000-8000-000000000001"
	integrationServiceID       = "44000000-0000-4000-8000-000000000001"
	integrationIntegrationID   = "55000000-0000-4000-8000-000000000001"
	integrationSignalID        = "66000000-0000-4000-8000-000000000001"
	integrationIncidentID      = "77000000-0000-4000-8000-000000000001"
	integrationInvestigationID = "88000000-0000-4000-8000-000000000001"
	integrationLifecycleTaskID = "99000000-0000-4000-8000-000000000001"
	integrationClaimTaskID     = "99000000-0000-4000-8000-000000000002"
	integrationFenceTaskID     = "99000000-0000-4000-8000-000000000003"
	integrationDriftTaskID     = "99000000-0000-4000-8000-000000000004"
	integrationEvidenceID      = "a1000000-0000-4000-8000-000000000001"
	integrationReceiptID       = "b1000000-0000-4000-8000-000000000001"
	integrationRunnerID        = "read-runner-repository-integration"
)

func TestRepositoryPostgres16PersistsAuthenticatedLifecycleAndCompletionReplay(t *testing.T) {
	fixture := newRepositoryIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	claim, err := repositoryRunnerTransaction(ctx, fixture, func(
		tx pgx.Tx,
		scope execution.RunnerScope,
		certificate readtask.CertificateBinding,
	) (readtask.Claim, error) {
		return fixture.tasks.ClaimRunnerTx(ctx, tx, scope, certificate, integrationLifecycleTaskID, 30*time.Second)
	})
	if err != nil {
		t.Fatalf("ClaimRunnerTx(real PostgreSQL) error = %v", err)
	}
	defer claim.Destroy()
	bearerToken, err := claim.TokenBytes()
	if err != nil {
		t.Fatalf("read claimed token: %v", err)
	}
	defer clear(bearerToken)
	decodedToken, err := base64.RawURLEncoding.DecodeString(string(bearerToken))
	if err != nil || len(bearerToken) != 43 || len(decodedToken) != 32 {
		t.Fatalf("claim token is not canonical base64url for 32 raw bytes: length=%d decoded=%d error=%v",
			len(bearerToken), len(decodedToken), err)
	}
	clear(decodedToken)

	started, err := repositoryRunnerTransaction(ctx, fixture, func(
		tx pgx.Tx,
		scope execution.RunnerScope,
		certificate readtask.CertificateBinding,
	) (readtask.Attempt, error) {
		return fixture.tasks.StartRunnerAuthorizedTx(
			ctx, tx, scope, certificate, readtask.Start{Fence: claim.Fence()},
			func(_ context.Context, descriptor readtask.Descriptor) error {
				if descriptor.TaskID != integrationLifecycleTaskID || descriptor.WorkspaceID != integrationWorkspaceID ||
					descriptor.EnvironmentID != integrationEnvironmentID {
					return readtask.ErrInvalidRequest
				}
				return nil
			},
		)
	})
	if err != nil || started.Status != readtask.AttemptRunning {
		t.Fatalf("StartRunnerAuthorizedTx(real PostgreSQL) = %#v, %v", started, err)
	}

	heartbeat, err := repositoryRunnerTransaction(ctx, fixture, func(
		tx pgx.Tx,
		scope execution.RunnerScope,
		certificate readtask.CertificateBinding,
	) (readtask.HeartbeatResult, error) {
		return fixture.tasks.HeartbeatRunnerTx(
			ctx, tx, scope, certificate,
			readtask.Heartbeat{Fence: claim.Fence(), Sequence: 1}, 30*time.Second,
		)
	})
	if err != nil || heartbeat.Directive != readtask.HeartbeatContinue || heartbeat.AcceptedSequence != 1 {
		t.Fatalf("HeartbeatRunnerTx(real PostgreSQL) = %#v, %v", heartbeat, err)
	}

	collectedAt := time.Now().UTC().Truncate(time.Microsecond)
	completion := readtask.Completion{
		Fence:   claim.Fence(),
		Outcome: readtask.CompletionEvidence,
		Evidence: &readtask.EvidenceCompletion{
			CollectedAt: collectedAt,
			Items: []json.RawMessage{
				json.RawMessage(`{"metric":"up","service":"payments","value":1}`),
			},
		},
	}
	completed, err := repositoryRunnerTransaction(ctx, fixture, func(
		tx pgx.Tx,
		scope execution.RunnerScope,
		certificate readtask.CertificateBinding,
	) (readtask.CompletionResult, error) {
		return fixture.tasks.CompleteRunnerAuthorizedTx(ctx, tx, scope, certificate, completion, trustedReadTaskCompletionAuthorizer)
	})
	if err != nil || completed.Replayed || completed.Attempt.Status != readtask.AttemptCompleted ||
		completed.EvidenceID != integrationEvidenceID || completed.ReceiptID != integrationReceiptID {
		t.Fatalf("CompleteRunnerAuthorizedTx(real PostgreSQL) = %#v, %v", completed, err)
	}
	verifyCommittedReadTaskCompletion(t, fixture.database, claim, bearerToken, completed)

	replayed, err := repositoryRunnerTransaction(ctx, fixture, func(
		tx pgx.Tx,
		scope execution.RunnerScope,
		certificate readtask.CertificateBinding,
	) (readtask.CompletionResult, error) {
		return fixture.tasks.CompleteRunnerAuthorizedTx(ctx, tx, scope, certificate, completion, trustedReadTaskCompletionAuthorizer)
	})
	if err != nil || !replayed.Replayed || replayed.EvidenceID != completed.EvidenceID ||
		replayed.ReceiptID != completed.ReceiptID ||
		replayed.Projection.RequestHash() != completed.Projection.RequestHash() ||
		replayed.Projection.ReceiptHash() != completed.Projection.ReceiptHash() {
		t.Fatalf("CompleteRunnerAuthorizedTx(replay) = %#v, %v", replayed, err)
	}

	changed := completion
	changed.Evidence = &readtask.EvidenceCompletion{
		CollectedAt: collectedAt,
		Items: []json.RawMessage{
			json.RawMessage(`{"metric":"up","service":"payments","value":0}`),
		},
	}
	_, err = repositoryRunnerTransaction(ctx, fixture, func(
		tx pgx.Tx,
		scope execution.RunnerScope,
		certificate readtask.CertificateBinding,
	) (readtask.CompletionResult, error) {
		return fixture.tasks.CompleteRunnerAuthorizedTx(ctx, tx, scope, certificate, changed, trustedReadTaskCompletionAuthorizer)
	})
	if !errors.Is(err, readtask.ErrCompletionConflict) {
		t.Fatalf("CompleteRunnerAuthorizedTx(changed replay) error = %v, want ErrCompletionConflict", err)
	}
	verifySingleCompletionProjection(t, fixture.database)
	verifyConcurrentSingleWinnerClaim(t, ctx, fixture)
	verifyOldEpochAndTokenRejected(t, ctx, fixture)
	verifyScopeRevisionDriftTerminatesAndTerminalHistoryIsImmutable(t, ctx, fixture)
	verifyUnsafeRunnerIngressDownIsAtomic(t, ctx, fixture)
}

func TestInvestigationRunnerIngressPostgres16AllowsEmptyDown(t *testing.T) {
	harness := newReadTaskPostgresHarness(t)
	harness.applyThroughRunnerIngress(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	connection, err := harness.migration.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire migration connection: %v", err)
	}
	defer connection.Release()
	if _, err := connection.Exec(ctx, readMigration(t, "000011_investigation_runner_ingress.down.sql")); err != nil {
		_, _ = connection.Exec(context.Background(), "ROLLBACK")
		t.Fatalf("apply empty investigation runner ingress down migration: %v", err)
	}
	var attemptTables, leaseEpochColumns int
	if err := harness.database.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM information_schema.tables
			 WHERE table_schema = current_schema() AND table_name = 'investigation_task_attempts'),
			(SELECT count(*) FROM information_schema.columns
			 WHERE table_schema = current_schema() AND table_name = 'runner_evidence_receipts'
			   AND column_name = 'lease_epoch')
	`).Scan(&attemptTables, &leaseEpochColumns); err != nil {
		t.Fatalf("inspect empty down migration: %v", err)
	}
	if attemptTables != 0 || leaseEpochColumns != 0 {
		t.Fatalf("empty down left M5B1 schema: attempts=%d lease_epoch_columns=%d", attemptTables, leaseEpochColumns)
	}
}

func verifyUnsafeRunnerIngressDownIsAtomic(
	t *testing.T,
	ctx context.Context,
	fixture *repositoryIntegrationFixture,
) {
	t.Helper()
	connection, err := fixture.migration.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire populated down migration connection: %v", err)
	}
	defer connection.Release()
	_, err = connection.Exec(ctx, readMigration(t, "000011_investigation_runner_ingress.down.sql"))
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != "55000" {
		_, _ = connection.Exec(context.Background(), "ROLLBACK")
		t.Fatalf("populated down migration error = %v, want SQLSTATE 55000", err)
	}
	_, _ = connection.Exec(context.Background(), "ROLLBACK")
	var attemptTables, leaseEpochColumns int
	if err := fixture.database.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM information_schema.tables
			 WHERE table_schema = current_schema() AND table_name = 'investigation_task_attempts'),
			(SELECT count(*) FROM information_schema.columns
			 WHERE table_schema = current_schema() AND table_name = 'runner_evidence_receipts'
			   AND column_name = 'lease_epoch')
	`).Scan(&attemptTables, &leaseEpochColumns); err != nil {
		t.Fatalf("inspect rejected populated down migration: %v", err)
	}
	if attemptTables != 1 || leaseEpochColumns != 1 {
		t.Fatalf("rejected down was not atomic: attempts=%d lease_epoch_columns=%d", attemptTables, leaseEpochColumns)
	}
}

func verifyScopeRevisionDriftTerminatesAndTerminalHistoryIsImmutable(
	t *testing.T,
	ctx context.Context,
	fixture *repositoryIntegrationFixture,
) {
	t.Helper()
	claim, err := repositoryRunnerTransaction(ctx, fixture, func(
		tx pgx.Tx,
		scope execution.RunnerScope,
		certificate readtask.CertificateBinding,
	) (readtask.Claim, error) {
		return fixture.tasks.ClaimRunnerTx(ctx, tx, scope, certificate, integrationDriftTaskID, 30*time.Second)
	})
	if err != nil {
		t.Fatalf("claim scope-drift task: %v", err)
	}
	defer claim.Destroy()
	_, err = repositoryRunnerTransaction(ctx, fixture, func(
		tx pgx.Tx,
		scope execution.RunnerScope,
		certificate readtask.CertificateBinding,
	) (readtask.Attempt, error) {
		return fixture.tasks.StartRunnerAuthorizedTx(
			ctx, tx, scope, certificate, readtask.Start{Fence: claim.Fence()}, trustedReadTaskAuthorizer,
		)
	})
	if err != nil {
		t.Fatalf("start scope-drift task: %v", err)
	}
	_, err = fixture.database.Exec(ctx, `
		UPDATE investigation_task_attempts
		SET started_at = started_at - interval '1 second'
		WHERE tenant_id = $1::uuid AND workspace_id = $2::uuid
		  AND investigation_id = $3::uuid AND task_id = $4::uuid AND lease_epoch = 1
	`, integrationTenantID, integrationWorkspaceID, integrationInvestigationID, integrationDriftTaskID)
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != "55000" ||
		postgresError.ConstraintName != "investigation_task_attempts_timestamp_guard" {
		t.Fatalf("started_at forgery error = %v, want timestamp_guard SQLSTATE 55000", err)
	}
	if _, err := fixture.database.Exec(ctx, `
		UPDATE runner_registrations
		SET scope_revision = scope_revision + 1
		WHERE tenant_id = $1::uuid AND runner_id = $2
	`, integrationTenantID, integrationRunnerID); err != nil {
		t.Fatalf("advance READ Runner scope revision: %v", err)
	}

	terminated, err := repositoryRunnerTransaction(ctx, fixture, func(
		tx pgx.Tx,
		scope execution.RunnerScope,
		certificate readtask.CertificateBinding,
	) (readtask.HeartbeatResult, error) {
		return fixture.tasks.HeartbeatRunnerTx(ctx, tx, scope, certificate,
			readtask.Heartbeat{Fence: claim.Fence(), Sequence: 1}, 30*time.Second)
	})
	if err != nil || terminated.Directive != readtask.HeartbeatTerminate ||
		terminated.AcceptedSequence != 1 || terminated.Attempt.Status != readtask.AttemptCancelled {
		t.Fatalf("heartbeat after scope revision drift = %#v, %v", terminated, err)
	}

	_, err = fixture.database.Exec(ctx, `
		UPDATE investigation_task_attempts
		SET status = status
		WHERE tenant_id = $1::uuid AND workspace_id = $2::uuid
		  AND investigation_id = $3::uuid AND task_id = $4::uuid AND lease_epoch = 1
	`, integrationTenantID, integrationWorkspaceID, integrationInvestigationID, integrationDriftTaskID)
	postgresError = nil
	if !errors.As(err, &postgresError) || postgresError.Code != "55000" ||
		postgresError.ConstraintName != "investigation_task_attempts_terminal_guard" {
		t.Fatalf("terminal no-op update error = %v, want immutable-history SQLSTATE 55000", err)
	}
}

func verifyConcurrentSingleWinnerClaim(
	t *testing.T,
	ctx context.Context,
	fixture *repositoryIntegrationFixture,
) {
	t.Helper()
	type result struct {
		claim readtask.Claim
		err   error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for range 2 {
		go func() {
			<-start
			claim, err := repositoryRunnerTransaction(ctx, fixture, func(
				tx pgx.Tx,
				scope execution.RunnerScope,
				certificate readtask.CertificateBinding,
			) (readtask.Claim, error) {
				return fixture.tasks.ClaimRunnerTx(
					ctx, tx, scope, certificate, integrationClaimTaskID, 30*time.Second,
				)
			})
			results <- result{claim: claim, err: err}
		}()
	}
	close(start)

	var winner readtask.Claim
	successes := 0
	noClaimAvailable := 0
	for range 2 {
		result := <-results
		switch {
		case result.err == nil:
			successes++
			winner = result.claim
		case errors.Is(result.err, readtask.ErrNoClaimAvailable):
			noClaimAvailable++
		default:
			t.Fatalf("concurrent ClaimRunnerTx error = %v", result.err)
		}
	}
	if successes != 1 || noClaimAvailable != 1 || !winner.Valid() {
		t.Fatalf("concurrent claims = success:%d unavailable:%d winner-valid:%t",
			successes, noClaimAvailable, winner.Valid())
	}
	defer winner.Destroy()

	var attemptRows, leasedRows int
	var maxEpoch int64
	if err := fixture.database.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE status = 'LEASED'), COALESCE(max(lease_epoch), 0)
		FROM investigation_task_attempts
		WHERE tenant_id = $1::uuid AND workspace_id = $2::uuid
		  AND investigation_id = $3::uuid AND task_id = $4::uuid
	`, integrationTenantID, integrationWorkspaceID, integrationInvestigationID,
		integrationClaimTaskID).Scan(&attemptRows, &leasedRows, &maxEpoch); err != nil {
		t.Fatalf("inspect concurrent claim attempts: %v", err)
	}
	if attemptRows != 1 || leasedRows != 1 || maxEpoch != 1 || winner.Attempt().Epoch != 1 {
		t.Fatalf("concurrent claim persistence = rows:%d leased:%d max-epoch:%d winner-epoch:%d",
			attemptRows, leasedRows, maxEpoch, winner.Attempt().Epoch)
	}

	released, err := repositoryRunnerTransaction(ctx, fixture, func(
		tx pgx.Tx,
		scope execution.RunnerScope,
		certificate readtask.CertificateBinding,
	) (readtask.Attempt, error) {
		return fixture.tasks.ReleaseRunnerTx(ctx, tx, scope, certificate, readtask.Release{
			Fence: winner.Fence(), ReasonCode: readtask.ReleaseLocalCapacityUnavailable,
		})
	})
	if err != nil || released.Status != readtask.AttemptReleased {
		t.Fatalf("release concurrent claim winner = %#v, %v", released, err)
	}
}

func verifyOldEpochAndTokenRejected(
	t *testing.T,
	ctx context.Context,
	fixture *repositoryIntegrationFixture,
) {
	t.Helper()
	oldClaim, err := repositoryRunnerTransaction(ctx, fixture, func(
		tx pgx.Tx,
		scope execution.RunnerScope,
		certificate readtask.CertificateBinding,
	) (readtask.Claim, error) {
		return fixture.tasks.ClaimRunnerTx(ctx, tx, scope, certificate, integrationFenceTaskID, 30*time.Second)
	})
	if err != nil {
		t.Fatalf("claim first fence epoch: %v", err)
	}
	defer oldClaim.Destroy()
	oldToken, err := oldClaim.TokenBytes()
	if err != nil {
		t.Fatalf("read first fence token: %v", err)
	}
	defer clear(oldToken)

	released, err := repositoryRunnerTransaction(ctx, fixture, func(
		tx pgx.Tx,
		scope execution.RunnerScope,
		certificate readtask.CertificateBinding,
	) (readtask.Attempt, error) {
		return fixture.tasks.ReleaseRunnerTx(ctx, tx, scope, certificate, readtask.Release{
			Fence: oldClaim.Fence(), ReasonCode: readtask.ReleaseTransientRunnerFailure,
		})
	})
	if err != nil || released.Status != readtask.AttemptReleased || released.Epoch != 1 {
		t.Fatalf("release first fence epoch = %#v, %v", released, err)
	}
	waitForReadTaskRetryWindow(t, ctx, fixture.database, integrationFenceTaskID)

	currentClaim, err := repositoryRunnerTransaction(ctx, fixture, func(
		tx pgx.Tx,
		scope execution.RunnerScope,
		certificate readtask.CertificateBinding,
	) (readtask.Claim, error) {
		return fixture.tasks.ClaimRunnerTx(ctx, tx, scope, certificate, integrationFenceTaskID, 30*time.Second)
	})
	if err != nil || currentClaim.Attempt().Epoch != 2 {
		t.Fatalf("claim second fence epoch = %#v, %v", currentClaim.Attempt(), err)
	}
	defer currentClaim.Destroy()

	_, err = repositoryRunnerTransaction(ctx, fixture, func(
		tx pgx.Tx,
		scope execution.RunnerScope,
		certificate readtask.CertificateBinding,
	) (readtask.Attempt, error) {
		return fixture.tasks.StartRunnerAuthorizedTx(
			ctx, tx, scope, certificate, readtask.Start{Fence: oldClaim.Fence()}, trustedReadTaskAuthorizer,
		)
	})
	if !errors.Is(err, readtask.ErrInvalidTransition) {
		t.Fatalf("start released epoch error = %v, want ErrInvalidTransition", err)
	}
	_, err = repositoryRunnerTransaction(ctx, fixture, func(
		tx pgx.Tx,
		scope execution.RunnerScope,
		certificate readtask.CertificateBinding,
	) (readtask.CompletionResult, error) {
		return fixture.tasks.CompleteRunnerAuthorizedTx(ctx, tx, scope, certificate, readtask.Completion{
			Fence: oldClaim.Fence(), Outcome: readtask.CompletionFailed, FailureCode: readtask.FailureUnknown,
		}, trustedReadTaskCompletionAuthorizer)
	})
	if !errors.Is(err, readtask.ErrProjectionRejected) {
		t.Fatalf("complete released epoch error = %v, want ErrProjectionRejected", err)
	}

	forgedFence, err := readtask.NewFence(
		integrationFenceTaskID, integrationRunnerID, oldToken, currentClaim.Attempt().Epoch,
	)
	if err != nil {
		t.Fatalf("construct current-epoch fence with old token: %v", err)
	}
	defer forgedFence.Destroy()
	_, err = repositoryRunnerTransaction(ctx, fixture, func(
		tx pgx.Tx,
		scope execution.RunnerScope,
		certificate readtask.CertificateBinding,
	) (readtask.Attempt, error) {
		return fixture.tasks.StartRunnerAuthorizedTx(
			ctx, tx, scope, certificate, readtask.Start{Fence: forgedFence}, trustedReadTaskAuthorizer,
		)
	})
	if !errors.Is(err, readtask.ErrStaleFence) {
		t.Fatalf("start current epoch with old token error = %v, want ErrStaleFence", err)
	}
	_, err = repositoryRunnerTransaction(ctx, fixture, func(
		tx pgx.Tx,
		scope execution.RunnerScope,
		certificate readtask.CertificateBinding,
	) (readtask.CompletionResult, error) {
		return fixture.tasks.CompleteRunnerAuthorizedTx(ctx, tx, scope, certificate, readtask.Completion{
			Fence: forgedFence, Outcome: readtask.CompletionFailed, FailureCode: readtask.FailureUnknown,
		}, trustedReadTaskCompletionAuthorizer)
	})
	if !errors.Is(err, readtask.ErrStaleFence) {
		t.Fatalf("complete current epoch with old token error = %v, want ErrStaleFence", err)
	}

	var attemptHistory, taskStatus string
	var evidenceRows, receiptRows int
	if err := fixture.database.QueryRow(ctx, `
		SELECT
			(SELECT string_agg(lease_epoch::text || ':' || status, ',' ORDER BY lease_epoch)
			 FROM investigation_task_attempts WHERE task_id = $1::uuid),
			(SELECT status FROM tool_invocations WHERE id = $1::uuid),
			(SELECT count(*) FROM evidence WHERE task_id = $1::uuid),
			(SELECT count(*) FROM runner_evidence_receipts WHERE task_id = $1::uuid)
	`, integrationFenceTaskID).Scan(&attemptHistory, &taskStatus, &evidenceRows, &receiptRows); err != nil {
		t.Fatalf("inspect rejected stale fences: %v", err)
	}
	if attemptHistory != "1:RELEASED,2:LEASED" || taskStatus != "QUEUED" ||
		evidenceRows != 0 || receiptRows != 0 {
		t.Fatalf("stale fence mutated state: history=%q task=%q evidence=%d receipts=%d",
			attemptHistory, taskStatus, evidenceRows, receiptRows)
	}

	released, err = repositoryRunnerTransaction(ctx, fixture, func(
		tx pgx.Tx,
		scope execution.RunnerScope,
		certificate readtask.CertificateBinding,
	) (readtask.Attempt, error) {
		return fixture.tasks.ReleaseRunnerTx(ctx, tx, scope, certificate, readtask.Release{
			Fence: currentClaim.Fence(), ReasonCode: readtask.ReleaseLocalCapacityUnavailable,
		})
	})
	if err != nil || released.Status != readtask.AttemptReleased || released.Epoch != 2 {
		t.Fatalf("release current fence epoch = %#v, %v", released, err)
	}
}

func waitForReadTaskRetryWindow(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	taskID string,
) {
	t.Helper()
	var seconds float64
	if err := database.QueryRow(ctx, `
		SELECT GREATEST(
			EXTRACT(EPOCH FROM (max(terminal_at) + interval '5 seconds' - clock_timestamp())),
			0
		)::double precision
		FROM investigation_task_attempts
		WHERE task_id = $1::uuid
	`, taskID).Scan(&seconds); err != nil {
		t.Fatalf("read READ task retry window: %v", err)
	}
	wait := time.Duration(seconds*float64(time.Second)) + 100*time.Millisecond
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatalf("wait for READ task retry window: %v", ctx.Err())
	}
}

func trustedReadTaskAuthorizer(context.Context, readtask.Descriptor) error { return nil }

func trustedReadTaskCompletionAuthorizer(context.Context, readtask.Descriptor, readtask.EvidenceCompletion) error {
	return nil
}

type repositoryIntegrationFixture struct {
	database   *pgxpool.Pool
	migration  *pgxpool.Pool
	identity   runneridentity.Identity
	identities *runneridentitypostgres.Repository
	tasks      *readtaskpostgres.Repository
}

func newRepositoryIntegrationFixture(t *testing.T) *repositoryIntegrationFixture {
	t.Helper()
	harness := newReadTaskPostgresHarness(t)
	harness.applyThroughRunnerIngress(t)
	identity := newRepositoryIntegrationIdentity(t)
	seedRuntimeInvestigation(t, harness.database)
	seedRepositoryIntegrationRunner(t, harness.database, identity)
	identities, err := runneridentitypostgres.New(harness.database)
	if err != nil {
		t.Fatalf("create Runner identity repository: %v", err)
	}
	var tokenSequence atomic.Uint32
	var idSequence atomic.Uint32
	ids := []string{integrationEvidenceID, integrationReceiptID}
	tasks, err := readtaskpostgres.New(harness.database, readtaskpostgres.Options{
		TokenSource: func() ([]byte, error) {
			value := byte('A' + tokenSequence.Add(1)%20)
			return bytes.Repeat([]byte{value}, 32), nil
		},
		IDSource: func() string {
			position := idSequence.Add(1)
			if position == 0 || int(position) > len(ids) {
				return "invalid"
			}
			return ids[position-1]
		},
	})
	if err != nil {
		t.Fatalf("create READ task repository: %v", err)
	}
	return &repositoryIntegrationFixture{
		database: harness.database, migration: harness.migration,
		identity: identity, identities: identities, tasks: tasks,
	}
}

func repositoryRunnerTransaction[T any](
	ctx context.Context,
	fixture *repositoryIntegrationFixture,
	operation func(pgx.Tx, execution.RunnerScope, readtask.CertificateBinding) (T, error),
) (T, error) {
	var zero T
	tx, err := fixture.database.Begin(ctx)
	if err != nil {
		return zero, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(context.Background())
		}
	}()
	authenticated, err := fixture.identities.AuthenticateTx(ctx, tx, fixture.identity)
	if err != nil {
		return zero, err
	}
	scope, err := authenticated.RunnerScope()
	if err != nil {
		return zero, err
	}
	certificate := readtask.CertificateBinding{
		SHA256: authenticated.CertificateSHA256(), NotAfter: authenticated.CertificateNotAfter(),
	}
	result, err := operation(tx, scope, certificate)
	if err != nil {
		return zero, err
	}
	if err := tx.Commit(ctx); err != nil {
		return zero, err
	}
	committed = true
	return result, nil
}

func verifyCommittedReadTaskCompletion(
	t *testing.T,
	database *pgxpool.Pool,
	claim readtask.Claim,
	bearerToken []byte,
	result readtask.CompletionResult,
) {
	t.Helper()
	ctx := context.Background()
	digest := sha256.Sum256(bearerToken)
	wantTokenHash := hex.EncodeToString(digest[:])
	var tokenHash, attemptStatus, requestHash, receiptHash, attemptDocument string
	if err := database.QueryRow(ctx, `
		SELECT lease_token_sha256, status, request_hash, receipt_hash, to_jsonb(attempt)::text
		FROM investigation_task_attempts AS attempt
		WHERE tenant_id = $1::uuid AND workspace_id = $2::uuid
		  AND investigation_id = $3::uuid AND task_id = $4::uuid AND lease_epoch = $5
	`, integrationTenantID, integrationWorkspaceID, integrationInvestigationID,
		integrationLifecycleTaskID, claim.Attempt().Epoch).Scan(
		&tokenHash, &attemptStatus, &requestHash, &receiptHash, &attemptDocument,
	); err != nil {
		t.Fatalf("read completed attempt: %v", err)
	}
	if tokenHash != wantTokenHash || attemptStatus != "COMPLETED" ||
		requestHash != result.Projection.RequestHash() || receiptHash != result.Projection.ReceiptHash() ||
		strings.Contains(attemptDocument, string(bearerToken)) {
		t.Fatalf("unsafe completed attempt: token=%q status=%q request=%q receipt=%q document=%q",
			tokenHash, attemptStatus, requestHash, receiptHash, attemptDocument)
	}
	var plaintextTokenColumns int
	if err := database.QueryRow(ctx, `
		SELECT count(*) FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'investigation_task_attempts'
		  AND column_name IN ('lease_token', 'token')
	`).Scan(&plaintextTokenColumns); err != nil || plaintextTokenColumns != 0 {
		t.Fatalf("plaintext token columns = %d, error = %v", plaintextTokenColumns, err)
	}

	var taskStatus, taskEvidenceID, taskHash string
	if err := database.QueryRow(ctx, `
		SELECT status, evidence_id::text, output_hash
		FROM tool_invocations WHERE tenant_id = $1::uuid AND id = $2::uuid
	`, integrationTenantID, integrationLifecycleTaskID).Scan(&taskStatus, &taskEvidenceID, &taskHash); err != nil {
		t.Fatalf("read completed task: %v", err)
	}
	if taskStatus != "EVIDENCE" || taskEvidenceID != result.EvidenceID || taskHash != result.Projection.ContentHash() {
		t.Fatalf("completed task = %q/%q/%q", taskStatus, taskEvidenceID, taskHash)
	}

	var evidencePayload []byte
	var evidenceHash, trustLevel string
	if err := database.QueryRow(ctx, `
		SELECT payload_document, content_hash, trust_level
		FROM evidence WHERE tenant_id = $1::uuid AND id = $2::uuid
	`, integrationTenantID, result.EvidenceID).Scan(&evidencePayload, &evidenceHash, &trustLevel); err != nil {
		t.Fatalf("read authenticated Evidence: %v", err)
	}
	if !bytes.Equal(evidencePayload, result.Projection.Payload()) || evidenceHash != result.Projection.ContentHash() ||
		trustLevel != "AUTHENTICATED_READ_RUNNER" {
		t.Fatalf("Evidence projection mismatch: hash=%q trust=%q payload=%s", evidenceHash, trustLevel, evidencePayload)
	}

	var schemaVersion string
	var leaseEpoch int64
	var receiptEvidenceID, receiptRequestHash, storedReceiptHash string
	if err := database.QueryRow(ctx, `
		SELECT schema_version, lease_epoch, evidence_id::text, request_hash, receipt_hash
		FROM runner_evidence_receipts
		WHERE tenant_id = $1::uuid AND id = $2::uuid
	`, integrationTenantID, result.ReceiptID).Scan(
		&schemaVersion, &leaseEpoch, &receiptEvidenceID, &receiptRequestHash, &storedReceiptHash,
	); err != nil {
		t.Fatalf("read immutable v2 receipt: %v", err)
	}
	if schemaVersion != "runner-evidence.v2" || leaseEpoch != claim.Attempt().Epoch ||
		receiptEvidenceID != result.EvidenceID || receiptRequestHash != result.Projection.RequestHash() ||
		storedReceiptHash != result.Projection.ReceiptHash() {
		t.Fatalf("receipt projection mismatch: %q/%d/%q/%q/%q", schemaVersion, leaseEpoch,
			receiptEvidenceID, receiptRequestHash, storedReceiptHash)
	}
	verifySingleCompletionProjection(t, database)
}

func verifySingleCompletionProjection(t *testing.T, database *pgxpool.Pool) {
	t.Helper()
	var boundRows, evidenceRows, receiptRows int
	err := database.QueryRow(context.Background(), `
		SELECT
			(SELECT count(*)
			 FROM investigation_task_attempts AS attempt
			 JOIN runner_evidence_receipts AS receipt
			   ON receipt.tenant_id = attempt.tenant_id
			  AND receipt.workspace_id = attempt.workspace_id
			  AND receipt.investigation_id = attempt.investigation_id
			  AND receipt.task_id = attempt.task_id
			  AND receipt.lease_epoch = attempt.lease_epoch
			  AND receipt.runner_id = attempt.runner_id
			  AND receipt.scope_revision = attempt.scope_revision
			  AND receipt.certificate_sha256 = attempt.certificate_sha256
			  AND receipt.request_hash = attempt.request_hash
			  AND receipt.receipt_hash = attempt.receipt_hash
			 JOIN evidence AS evidence
			   ON evidence.tenant_id = receipt.tenant_id
			  AND evidence.workspace_id = receipt.workspace_id
			  AND evidence.investigation_id = receipt.investigation_id
			  AND evidence.task_id = receipt.task_id
			  AND evidence.id = receipt.evidence_id
			  AND evidence.content_hash = receipt.content_hash
			 WHERE attempt.task_id = $1::uuid AND attempt.status = 'COMPLETED'
			   AND receipt.schema_version = 'runner-evidence.v2'),
			(SELECT count(*) FROM evidence WHERE task_id = $1::uuid),
			(SELECT count(*) FROM runner_evidence_receipts WHERE task_id = $1::uuid)
	`, integrationLifecycleTaskID).Scan(&boundRows, &evidenceRows, &receiptRows)
	if err != nil || boundRows != 1 || evidenceRows != 1 || receiptRows != 1 {
		t.Fatalf("atomic completion rows = bound:%d evidence:%d receipt:%d error:%v",
			boundRows, evidenceRows, receiptRows, err)
	}
}

type readTaskPostgresHarness struct {
	database  *pgxpool.Pool
	migration *pgxpool.Pool
	schema    string
}

func newReadTaskPostgresHarness(t *testing.T) *readTaskPostgresHarness {
	t.Helper()
	dsn := os.Getenv("AIOPS_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("AIOPS_TEST_POSTGRES_DSN is not configured; PostgreSQL 16 READ task repository tests were not run")
	}
	ctx := context.Background()
	adminConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse PostgreSQL integration DSN: %v", err)
	}
	admin, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatalf("connect PostgreSQL integration database: %v", err)
	}
	var serverVersion int
	if err := admin.QueryRow(ctx, `SELECT current_setting('server_version_num')::integer`).Scan(&serverVersion); err != nil {
		admin.Close()
		t.Fatalf("read PostgreSQL server version: %v", err)
	}
	if serverVersion/10000 != 16 {
		admin.Close()
		t.Fatalf("READ task integration harness requires PostgreSQL 16, got server_version_num=%d", serverVersion)
	}
	random := make([]byte, 8)
	if _, err := cryptorand.Read(random); err != nil {
		admin.Close()
		t.Fatalf("generate isolated schema: %v", err)
	}
	schema := "aiops_readtask_" + hex.EncodeToString(random)
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatalf("create isolated schema: %v", err)
	}
	newPool := func(mode pgx.QueryExecMode, maximum int32) *pgxpool.Pool {
		config, parseErr := pgxpool.ParseConfig(dsn)
		if parseErr != nil {
			t.Fatalf("parse isolated PostgreSQL config: %v", parseErr)
		}
		config.ConnConfig.DefaultQueryExecMode = mode
		if config.ConnConfig.RuntimeParams == nil {
			config.ConnConfig.RuntimeParams = make(map[string]string)
		}
		config.ConnConfig.RuntimeParams["search_path"] = schema
		if config.MaxConns < maximum {
			config.MaxConns = maximum
		}
		pool, poolErr := pgxpool.NewWithConfig(ctx, config)
		if poolErr != nil {
			t.Fatalf("connect isolated PostgreSQL schema: %v", poolErr)
		}
		return pool
	}
	migration := newPool(pgx.QueryExecModeSimpleProtocol, 2)
	database := newPool(pgx.QueryExecModeCacheStatement, 12)
	harness := &readTaskPostgresHarness{database: database, migration: migration, schema: schema}
	t.Cleanup(func() {
		database.Close()
		migration.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
	})
	return harness
}

func (harness *readTaskPostgresHarness) applyThroughRunnerIngress(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"000001_core.up.sql",
		"000002_scope_integrity.up.sql",
		"000003_outbox_fencing.up.sql",
		"000004_audit_details.up.sql",
		"000005_execution_leases.up.sql",
		"000006_action_queue.up.sql",
		"000007_runner_execution_hardening.up.sql",
		"000008_credential_revocations.up.sql",
		"000009_runner_gateway_mtls.up.sql",
		"000010_investigation_runtime.up.sql",
		"000011_investigation_runner_ingress.up.sql",
	} {
		if _, err := harness.migration.Exec(context.Background(), readMigration(t, name)); err != nil {
			t.Fatalf("apply migration %s: %v", name, err)
		}
	}
}

func seedRuntimeInvestigation(t *testing.T, database *pgxpool.Pool) {
	t.Helper()
	base := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	integrationExec(t, database, `INSERT INTO tenants (id, name) VALUES ($1::uuid, 'readtask-tenant')`, integrationTenantID)
	integrationExec(t, database, `
		INSERT INTO workspaces (id, tenant_id, name)
		VALUES ($1::uuid, $2::uuid, 'readtask-workspace')
	`, integrationWorkspaceID, integrationTenantID)
	integrationExec(t, database, `
		INSERT INTO environments (id, tenant_id, workspace_id, name, kind)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'readtask-staging', 'STAGING')
	`, integrationEnvironmentID, integrationTenantID, integrationWorkspaceID)
	integrationExec(t, database, `
		INSERT INTO services (id, tenant_id, workspace_id, name, owner_group)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'payments', 'payments-sre')
	`, integrationServiceID, integrationTenantID, integrationWorkspaceID)
	integrationExec(t, database, `
		INSERT INTO integrations (id, tenant_id, workspace_id, provider, name, secret_ref)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'alertmanager', 'alerts', 'vault://alerts')
	`, integrationIntegrationID, integrationTenantID, integrationWorkspaceID)
	integrationExec(t, database, `
		INSERT INTO signals (
			id, tenant_id, workspace_id, integration_id, provider, provider_event_id,
			payload_hash, fingerprint, status, observed_at, payload_summary
		) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 'alertmanager', 'readtask-event',
			$5, 'payments:staging:readtask', 'firing', $6, '{}')
	`, integrationSignalID, integrationTenantID, integrationWorkspaceID, integrationIntegrationID,
		strings.Repeat("a", 64), base.Add(time.Second))

	ctx := context.Background()
	incidentTx, err := database.Begin(ctx)
	if err != nil {
		t.Fatalf("begin runtime incident fixture: %v", err)
	}
	if _, err := incidentTx.Exec(ctx, `
		INSERT INTO incidents (
			id, tenant_id, workspace_id, service_id, environment_id, status, severity, title,
			opened_at, updated_at, version, correlation_key, mapping_status,
			last_signal_at, signal_count, runtime_schema_version
		) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, 'OPEN', 'SEV3',
			'readtask runtime incident', $6, $7, 1, 'payments:staging:readtask', 'EXACT',
			$6, 1, 'investigation-runtime.v1')
	`, integrationIncidentID, integrationTenantID, integrationWorkspaceID, integrationServiceID,
		integrationEnvironmentID, base.Add(time.Second), base.Add(2*time.Second)); err != nil {
		_ = incidentTx.Rollback(ctx)
		t.Fatalf("insert runtime incident: %v", err)
	}
	if _, err := incidentTx.Exec(ctx, `
		INSERT INTO incident_signals (tenant_id, workspace_id, incident_id, signal_id)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid)
	`, integrationTenantID, integrationWorkspaceID, integrationIncidentID, integrationSignalID); err != nil {
		_ = incidentTx.Rollback(ctx)
		t.Fatalf("associate runtime signal: %v", err)
	}
	if _, err := incidentTx.Exec(ctx, `
		INSERT INTO investigation_signal_correlations (
			tenant_id, workspace_id, signal_id, incident_id, correlation_key,
			mapping_status, service_id, environment_id
		) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 'payments:staging:readtask',
			'EXACT', $5::uuid, $6::uuid)
	`, integrationTenantID, integrationWorkspaceID, integrationSignalID, integrationIncidentID,
		integrationServiceID, integrationEnvironmentID); err != nil {
		_ = incidentTx.Rollback(ctx)
		t.Fatalf("persist runtime correlation: %v", err)
	}
	if err := incidentTx.Commit(ctx); err != nil {
		t.Fatalf("commit runtime incident fixture: %v", err)
	}

	createdAt := base.Add(3 * time.Second)
	investigationTx, err := database.Begin(ctx)
	if err != nil {
		t.Fatalf("begin runtime investigation fixture: %v", err)
	}
	if _, err := investigationTx.Exec(ctx, `
		INSERT INTO investigations (
			id, tenant_id, workspace_id, incident_id, status, window_start, window_end,
			tool_schema_version, created_at, model_status, idempotency_key, request_hash,
			request_hash_version, updated_at, service_id_snapshot, environment_id_snapshot,
			mapping_status_snapshot, runtime_schema_version
		) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 'QUEUED', $5, $6,
			'investigation-task.v1', $7, 'PENDING', 'investigate:readtask-runtime', $8,
			'investigation.create.v1', $7, $9::uuid, $10::uuid, 'EXACT', 'investigation-runtime.v1')
	`, integrationInvestigationID, integrationTenantID, integrationWorkspaceID, integrationIncidentID,
		base, base.Add(2*time.Second), createdAt, strings.Repeat("b", 64),
		integrationServiceID, integrationEnvironmentID); err != nil {
		_ = investigationTx.Rollback(ctx)
		t.Fatalf("insert runtime investigation: %v", err)
	}
	for index, taskID := range []string{
		integrationLifecycleTaskID, integrationClaimTaskID, integrationFenceTaskID, integrationDriftTaskID,
	} {
		input := []byte(fmt.Sprintf(`{"query":"up","window_seconds":%d}`, 300+index))
		digest := sha256.Sum256(input)
		if _, err := investigationTx.Exec(ctx, `
			INSERT INTO tool_invocations (
				id, tenant_id, workspace_id, investigation_id, tool_name, tool_version,
				input_hash, status, incident_id, task_key, position, input_document,
				created_at, updated_at, runtime_schema_version
			) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 'prometheus-staging', 'query_range',
				$5, 'QUEUED', $6::uuid, $7, $8, $9, $10, $10, 'investigation-runtime.v1')
		`, taskID, integrationTenantID, integrationWorkspaceID, integrationInvestigationID,
			hex.EncodeToString(digest[:]), integrationIncidentID, fmt.Sprintf("metrics.%d", index+1), index+1,
			input, createdAt); err != nil {
			_ = investigationTx.Rollback(ctx)
			t.Fatalf("insert runtime task %d: %v", index+1, err)
		}
	}
	if err := investigationTx.Commit(ctx); err != nil {
		t.Fatalf("commit runtime investigation fixture: %v", err)
	}
}

func seedRepositoryIntegrationRunner(t *testing.T, database *pgxpool.Pool, identity runneridentity.Identity) {
	t.Helper()
	integrationExec(t, database, `
		INSERT INTO runner_registrations (
			runner_id, tenant_id, spiffe_uri, runner_pool, enabled,
			scope_revision, max_concurrency, credential_revocation_capable
		) VALUES ($1, $2::uuid, $3, 'READ', true, 1, 4, false)
	`, integrationRunnerID, integrationTenantID, identity.SPIFFEURI())
	integrationExec(t, database, `
		INSERT INTO runner_scope_bindings (runner_id, tenant_id, workspace_id, environment_id)
		VALUES ($1, $2::uuid, $3::uuid, $4::uuid)
	`, integrationRunnerID, integrationTenantID, integrationWorkspaceID, integrationEnvironmentID)
	evidence := identity.Evidence()
	integrationExec(t, database, `
		INSERT INTO runner_certificates (
			certificate_sha256, runner_id, tenant_id, issuer_key_id, serial_hex,
			spki_sha256, status, not_before, not_after
		) VALUES ($1, $2, $3::uuid, $4, $5, $6, 'ACTIVE', $7, $8)
	`, evidence.LeafSHA256(), integrationRunnerID, integrationTenantID, evidence.AuthorityKeyIDHex(),
		evidence.SerialHex(), evidence.SPKISHA256(), evidence.NotBefore(), evidence.NotAfter())
}

func newRepositoryIntegrationIdentity(t *testing.T) runneridentity.Identity {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	readCA, err := testpki.NewAuthority("readtask-integration-read-root", now)
	if err != nil {
		t.Fatalf("create READ test CA: %v", err)
	}
	writeCA, err := testpki.NewAuthority("readtask-integration-write-root", now)
	if err != nil {
		t.Fatalf("create WRITE test CA: %v", err)
	}
	spiffeURI, err := url.Parse("spiffe://aiops.example/runner/read/readtask-integration")
	if err != nil {
		t.Fatalf("parse READ Runner SPIFFE URI: %v", err)
	}
	client, err := readCA.IssueClient(testpki.ClientOptions{URIs: []*url.URL{spiffeURI}}, now)
	if err != nil {
		t.Fatalf("issue READ Runner certificate: %v", err)
	}
	verifier, err := runneridentity.NewVerifier(runneridentity.Options{
		TrustDomain: "aiops.example", ReadRoots: []*x509.Certificate{readCA.Certificate},
		WriteRoots: []*x509.Certificate{writeCA.Certificate}, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("create Runner identity verifier: %v", err)
	}
	chains, err := client.Leaf.Verify(x509.VerifyOptions{
		Roots: readCA.CertPool(), CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatalf("verify READ Runner certificate: %v", err)
	}
	identity, err := verifier.IdentityFromConnectionState(tls.ConnectionState{
		Version: tls.VersionTLS13, HandshakeComplete: true,
		PeerCertificates: []*x509.Certificate{client.Leaf, readCA.Certificate}, VerifiedChains: chains,
	})
	if err != nil {
		t.Fatalf("derive READ Runner identity: %v", err)
	}
	return identity
}

func integrationExec(t *testing.T, database *pgxpool.Pool, query string, arguments ...any) {
	t.Helper()
	if _, err := database.Exec(context.Background(), query, arguments...); err != nil {
		t.Fatalf("exec READ task integration fixture: %v", err)
	}
}
