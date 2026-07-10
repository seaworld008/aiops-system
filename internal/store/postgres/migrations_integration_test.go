package postgres_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/seaworld008/aiops-system/internal/action"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/execution"
	executionpostgres "github.com/seaworld008/aiops-system/internal/execution/postgres"
	"github.com/seaworld008/aiops-system/internal/executionlease"
	"github.com/seaworld008/aiops-system/internal/store"
	postgresstore "github.com/seaworld008/aiops-system/internal/store/postgres"
)

func TestMigrationsEnforceScopeAndConfirmedRootCause(t *testing.T) {
	dsn := os.Getenv("AIOPS_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("AIOPS_TEST_POSTGRES_DSN is not configured")
	}
	ctx := context.Background()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	if config.MaxConns < 6 {
		config.MaxConns = 6
	}
	database, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("NewWithConfig() error = %v", err)
	}
	defer database.Close()
	if _, err := database.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatalf("reset test schema: %v", err)
	}

	migrationDirectory := migrationPath(t)
	applyMigrationsBefore(t, ctx, database, migrationDirectory, ".up.sql", "000007_runner_execution_hardening.up.sql")
	seedLegacyExecutionLeaseTokens(t, ctx, database)
	legacyAction := seedLegacyActionQueue(t, ctx, database)
	applyMigrationFile(t, ctx, database, filepath.Join(migrationDirectory, "000007_runner_execution_hardening.up.sql"))
	verifyLegacyExecutionLeaseTokenHashes(t, ctx, database)
	execSQL(t, ctx, database, `DELETE FROM execution_leases`)
	exerciseRealLegacySemanticRetry(t, ctx, database, legacyAction)

	const (
		tenant1        = "10000000-0000-4000-8000-000000000001"
		tenant2        = "10000000-0000-4000-8000-000000000002"
		workspace1     = "20000000-0000-4000-8000-000000000001"
		workspace2     = "20000000-0000-4000-8000-000000000002"
		environment1   = "25000000-0000-4000-8000-000000000001"
		service1       = "28000000-0000-4000-8000-000000000001"
		integration1   = "30000000-0000-4000-8000-000000000001"
		signal1        = "40000000-0000-4000-8000-000000000001"
		incident1      = "50000000-0000-4000-8000-000000000001"
		investigation1 = "60000000-0000-4000-8000-000000000001"
		hypothesis1    = "70000000-0000-4000-8000-000000000001"
	)
	execSQL(t, ctx, database, `INSERT INTO tenants (id, name) VALUES ($1, 'tenant-1'), ($2, 'tenant-2')`, tenant1, tenant2)
	execSQL(t, ctx, database, `INSERT INTO workspaces (id, tenant_id, name) VALUES ($1, $2, 'workspace-1'), ($3, $4, 'workspace-2')`, workspace1, tenant1, workspace2, tenant2)
	execSQL(t, ctx, database, `INSERT INTO environments (id, tenant_id, workspace_id, name, kind) VALUES ($1, $2, $3, 'production', 'PROD')`, environment1, tenant1, workspace1)
	execSQL(t, ctx, database, `INSERT INTO services (id, tenant_id, workspace_id, name, owner_group) VALUES ($1, $2, $3, 'payments', 'payments-sre')`, service1, tenant1, workspace1)
	execSQL(t, ctx, database, `INSERT INTO integrations (id, tenant_id, workspace_id, provider, name, secret_ref) VALUES ($1, $2, $3, 'alertmanager', 'alerts', 'vault://alerts')`, integration1, tenant1, workspace1)

	expectSQLState(t, ctx, database, "23503", `
		INSERT INTO signals (id, tenant_id, workspace_id, integration_id, provider, provider_event_id, payload_hash, fingerprint, observed_at)
		VALUES ($1, $2, $3, $4, 'alertmanager', 'cross-scope', 'hash', 'fingerprint', now())
	`, signal1, tenant2, workspace2, integration1)
	execSQL(t, ctx, database, `
		INSERT INTO signals (id, tenant_id, workspace_id, integration_id, provider, provider_event_id, payload_hash, fingerprint, observed_at)
		VALUES ($1, $2, $3, $4, 'alertmanager', 'event-1', 'hash', 'fingerprint', now())
	`, signal1, tenant1, workspace1, integration1)

	execSQL(t, ctx, database, `
		INSERT INTO incidents (id, tenant_id, workspace_id, status, severity, title, opened_at, updated_at)
		VALUES ($1, $2, $3, 'OPEN', 'SEV3', 'test incident', now(), now())
	`, incident1, tenant1, workspace1)
	execSQL(t, ctx, database, `
		INSERT INTO investigations (id, tenant_id, workspace_id, incident_id, status, window_start, window_end, tool_schema_version)
		VALUES ($1, $2, $3, $4, 'RUNNING', now() - interval '5 minutes', now(), 'v1')
	`, investigation1, tenant1, workspace1, incident1)
	execSQL(t, ctx, database, `
		INSERT INTO hypotheses (id, tenant_id, workspace_id, incident_id, investigation_id, status, rank, confidence_band, summary)
		VALUES ($1, $2, $3, $4, $5, 'PROPOSED', 1, 'MEDIUM', 'test hypothesis')
	`, hypothesis1, tenant1, workspace1, incident1, investigation1)

	expectSQLState(t, ctx, database, "23503", `UPDATE incidents SET confirmed_hypothesis_id = $1 WHERE id = $2`, hypothesis1, incident1)
	execSQL(t, ctx, database, `UPDATE hypotheses SET status = 'CONFIRMED' WHERE id = $1`, hypothesis1)
	execSQL(t, ctx, database, `UPDATE incidents SET confirmed_hypothesis_id = $1 WHERE id = $2`, hypothesis1, incident1)
	expectSQLState(t, ctx, database, "23503", `UPDATE hypotheses SET status = 'REJECTED' WHERE id = $1`, hypothesis1)
	expectSQLState(t, ctx, database, "23514", `
		INSERT INTO feedback (id, tenant_id, workspace_id, investigation_id, actor_id, kind)
		VALUES ('80000000-0000-4000-8000-000000000001', $1, $2, $3, 'user-1', 'CONFIRM')
	`, tenant1, workspace1, investigation1)

	// Exercise the real pgx repository against PostgreSQL 16, not only mocks.
	repository := postgresstore.New(database)
	const signal2 = "40000000-0000-4000-8000-000000000002"
	signalRecord := domain.Signal{
		ID: signal2, WorkspaceID: workspace1, IntegrationID: integration1,
		Provider: "alertmanager", ProviderEventID: "event-2", PayloadHash: "payload-hash-2",
		Fingerprint: "fingerprint-2", Status: "firing", Labels: map[string]string{"service": "checkout"},
		ObservedAt: time.Now().UTC(),
	}
	created, err := repository.CreateSignal(ctx, signalRecord)
	if err != nil || !created {
		t.Fatalf("real CreateSignal(created) = (%v, %v)", created, err)
	}
	created, err = repository.CreateSignal(ctx, signalRecord)
	if err != nil || created {
		t.Fatalf("real CreateSignal(duplicate) = (%v, %v)", created, err)
	}
	signalRecord.PayloadHash = "different-hash"
	if _, err := repository.CreateSignal(ctx, signalRecord); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("real CreateSignal(conflict) error = %v", err)
	}
	var auditCount int
	if err := database.QueryRow(ctx, `SELECT count(*) FROM audit_records WHERE action = 'signal.idempotency_conflict'`).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("conflict audit count = %d, error = %v", auditCount, err)
	}

	const incident2 = "50000000-0000-4000-8000-000000000002"
	if err := repository.CreateIncident(ctx, domain.NewIncident(incident2, workspace1, time.Now().UTC())); err != nil {
		t.Fatalf("real CreateIncident() error = %v", err)
	}
	var incidentOutboxCount int
	if err := database.QueryRow(ctx, `SELECT count(*) FROM outbox_events WHERE aggregate_id = $1`, incident2).Scan(&incidentOutboxCount); err != nil || incidentOutboxCount != 1 {
		t.Fatalf("incident outbox count = %d, error = %v", incidentOutboxCount, err)
	}

	const incident3 = "50000000-0000-4000-8000-000000000003"
	execSQL(t, ctx, database, `
		CREATE FUNCTION reject_test_outbox() RETURNS trigger AS $$
		BEGIN
			IF NEW.aggregate_id = '50000000-0000-4000-8000-000000000003'::uuid THEN
				RAISE EXCEPTION 'forced outbox failure';
			END IF;
			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER reject_test_outbox_insert BEFORE INSERT ON outbox_events
		FOR EACH ROW EXECUTE FUNCTION reject_test_outbox();
	`)
	if err := repository.CreateIncident(ctx, domain.NewIncident(incident3, workspace1, time.Now().UTC())); err == nil {
		t.Fatal("real CreateIncident() error = nil, want forced rollback")
	}
	var rolledBackCount int
	if err := database.QueryRow(ctx, `SELECT count(*) FROM incidents WHERE id = $1`, incident3).Scan(&rolledBackCount); err != nil || rolledBackCount != 0 {
		t.Fatalf("rolled-back incident count = %d, error = %v", rolledBackCount, err)
	}
	execSQL(t, ctx, database, `DROP TRIGGER reject_test_outbox_insert ON outbox_events; DROP FUNCTION reject_test_outbox()`)

	firstClaim, err := repository.ClaimOutbox(ctx, "dispatcher-1", 1, time.Minute)
	if err != nil || len(firstClaim) != 1 {
		t.Fatalf("real ClaimOutbox(first) = (%#v, %v)", firstClaim, err)
	}
	secondClaim, err := repository.ClaimOutbox(ctx, "dispatcher-2", 1, time.Minute)
	if err != nil || len(secondClaim) != 1 || secondClaim[0].ID == firstClaim[0].ID {
		t.Fatalf("real ClaimOutbox(second) = (%#v, %v)", secondClaim, err)
	}
	execSQL(t, ctx, database, `
		UPDATE outbox_events
		SET claimed_at = statement_timestamp() - interval '2 minutes',
			claim_expires_at = statement_timestamp() - interval '1 minute'
		WHERE id = $1
	`, firstClaim[0].ID)
	if err := repository.AckOutbox(ctx, firstClaim[0].ID, firstClaim[0].ClaimToken); !errors.Is(err, store.ErrStaleClaim) {
		t.Fatalf("real AckOutbox(expired) error = %v", err)
	}
	reclaimed, err := repository.ClaimOutbox(ctx, "dispatcher-3", 1, time.Minute)
	if err != nil || len(reclaimed) != 1 || reclaimed[0].ID != firstClaim[0].ID || reclaimed[0].ClaimToken == firstClaim[0].ClaimToken {
		t.Fatalf("real ClaimOutbox(reclaimed) = (%#v, %v)", reclaimed, err)
	}
	if err := repository.AckOutbox(ctx, reclaimed[0].ID, firstClaim[0].ClaimToken); !errors.Is(err, store.ErrStaleClaim) {
		t.Fatalf("real AckOutbox(old token) error = %v", err)
	}
	if err := repository.AckOutbox(ctx, reclaimed[0].ID, reclaimed[0].ClaimToken); err != nil {
		t.Fatalf("real AckOutbox(current token) error = %v", err)
	}
	if err := repository.AckOutbox(ctx, reclaimed[0].ID, reclaimed[0].ClaimToken); err != nil {
		t.Fatalf("real AckOutbox(idempotent retry) error = %v", err)
	}
	if err := repository.AckOutbox(ctx, reclaimed[0].ID, "00000000-0000-0000-0000-000000000099"); !errors.Is(err, store.ErrStaleClaim) {
		t.Fatalf("real AckOutbox(wrong delivered token) error = %v", err)
	}
	if err := repository.AckOutbox(ctx, secondClaim[0].ID, secondClaim[0].ClaimToken); err != nil {
		t.Fatalf("real AckOutbox(second) error = %v", err)
	}

	exerciseRealActionQueue(t, ctx, database, tenant1, workspace1, environment1, service1)
	expectSQLState(t, ctx, database, "P0001", `TRUNCATE runner_result_receipts`)
	expectMigrationSQLState(t, ctx, database, filepath.Join(migrationDirectory, "000007_runner_execution_hardening.down.sql"), "55000")
	execSQL(t, ctx, database, `DROP TRIGGER runner_result_receipts_no_truncate ON runner_result_receipts`)
	execSQL(t, ctx, database, `TRUNCATE runner_result_receipts`)
	execSQL(t, ctx, database, `DELETE FROM action_queue`)
	execSQL(t, ctx, database, `DELETE FROM runner_certificates`)
	execSQL(t, ctx, database, `DELETE FROM runner_scope_bindings`)
	execSQL(t, ctx, database, `DELETE FROM runner_registrations`)

	applyMigrations(t, ctx, database, migrationDirectory, ".down.sql", true)
	var relationName *string
	if err := database.QueryRow(ctx, `SELECT to_regclass('public.tenants')::text`).Scan(&relationName); err != nil {
		t.Fatalf("check down migration: %v", err)
	}
	if relationName != nil {
		t.Fatalf("tenants table remains after down migration: %s", *relationName)
	}
}

func exerciseRealActionQueue(t *testing.T, ctx context.Context, database *pgxpool.Pool, tenantID, workspaceID, environmentID, serviceID string) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate action integration signing key: %v", err)
	}
	signer, err := action.NewEd25519Signer("postgres-integration-key", privateKey)
	if err != nil {
		t.Fatalf("create action integration signer: %v", err)
	}
	queue, err := executionpostgres.New(database, executionpostgres.Options{})
	if err != nil {
		t.Fatalf("create real PostgreSQL ActionQueue: %v", err)
	}
	for _, runnerID := range []string{"runner-postgres-1", "runner-postgres-2", "runner-postgres-3", "runner-postgres-4", "runner-postgres-race", "runner-postgres-authorization"} {
		execSQL(t, ctx, database, `
			INSERT INTO runner_registrations (runner_id, tenant_id, spiffe_uri, runner_pool, enabled, scope_revision)
			VALUES ($1, $2, 'spiffe://integration.test/runner/write/' || $1, 'WRITE', true, 1)
		`, runnerID, tenantID)
		execSQL(t, ctx, database, `
			INSERT INTO runner_scope_bindings (runner_id, tenant_id, workspace_id, environment_id)
			VALUES ($1, $2, $3, $4)
		`, runnerID, tenantID, workspaceID, environmentID)
	}
	exerciseRealClaimAuthorization(t, ctx, database, queue, signer, workspaceID, environmentID, serviceID)
	exerciseRealRegistrationRaces(t, ctx, database, queue, signer, tenantID, workspaceID, environmentID, serviceID)
	expectSQLState(t, ctx, database, "55000", `TRUNCATE runner_scope_bindings`)
	execSQL(t, ctx, database, `
		INSERT INTO runner_certificates (
			certificate_sha256, runner_id, tenant_id, issuer_key_id, serial_hex, spki_sha256,
			status, not_before, not_after
		) VALUES ($1, 'runner-postgres-1', $2, 'integration-ca-1', '01', $3, 'ACTIVE', now() - interval '1 minute', now() + interval '1 hour')
	`, strings.Repeat("1", 64), tenantID, strings.Repeat("2", 64))
	expectSQLState(t, ctx, database, "23514", `
		INSERT INTO runner_certificates (
			certificate_sha256, runner_id, tenant_id, issuer_key_id, serial_hex, spki_sha256,
			status, not_before, not_after, revoked_at, revocation_reason
		) VALUES ($1, 'runner-postgres-1', $2, 'integration-ca-1', '02', $3, 'ACTIVE',
			now() - interval '1 minute', now() + interval '1 hour', now(), 'must not accompany ACTIVE')
	`, strings.Repeat("3", 64), tenantID, strings.Repeat("4", 64))
	now := time.Now().UTC()
	claimLockSubmission := realActionSubmission(t, signer, now, "90000000-0000-4000-8000-000000000097", workspaceID, environmentID,
		serviceID, "payments-claim-lock", 'f')
	claimLockSubmission.Production = false
	tokenRequested := make(chan struct{})
	releaseToken := make(chan struct{})
	var tokenRequestedOnce sync.Once
	var releaseTokenOnce sync.Once
	releaseTokenGate := func() {
		releaseTokenOnce.Do(func() { close(releaseToken) })
	}
	defer releaseTokenGate()
	claimLockQueue, err := executionpostgres.New(database, executionpostgres.Options{TokenSource: func() (string, error) {
		tokenRequestedOnce.Do(func() { close(tokenRequested) })
		<-releaseToken
		return strings.Repeat("9", 64), nil
	}})
	if err != nil {
		t.Fatalf("create claim-lock ActionQueue: %v", err)
	}
	if _, err := claimLockQueue.Submit(ctx, claimLockSubmission); err != nil {
		t.Fatalf("submit claim-lock action: %v", err)
	}
	type lockedClaimResult struct {
		claim execution.ClaimedAction
		err   error
	}
	lockedClaimDone := make(chan lockedClaimResult, 1)
	lockedScope := realRunnerScope(t, ctx, database, "runner-postgres-1")
	lockedClaimContext, cancelLockedClaim := context.WithTimeout(ctx, 5*time.Second)
	defer cancelLockedClaim()
	go func() {
		claim, claimErr := claimLockQueue.Claim(lockedClaimContext, execution.ActionClaimRequest{Scope: lockedScope, LeaseDuration: time.Minute})
		lockedClaimDone <- lockedClaimResult{claim: claim, err: claimErr}
	}()
	select {
	case <-tokenRequested:
	case <-lockedClaimContext.Done():
		t.Fatalf("claim did not reach token source while holding registry lock: %v", lockedClaimContext.Err())
	}
	deleteContext, cancelDelete := context.WithTimeout(ctx, 250*time.Millisecond)
	_, deleteErr := database.Exec(deleteContext, `
		DELETE FROM runner_scope_bindings
		WHERE runner_id = 'runner-postgres-1' AND tenant_id = $1 AND workspace_id = $2 AND environment_id = $3
	`, tenantID, workspaceID, environmentID)
	deleteContextErr := deleteContext.Err()
	cancelDelete()
	releaseTokenGate()
	var lockedClaim lockedClaimResult
	select {
	case lockedClaim = <-lockedClaimDone:
	case <-lockedClaimContext.Done():
		t.Fatalf("claim did not finish after token source release: %v", lockedClaimContext.Err())
	}
	if lockedClaim.err != nil {
		t.Fatalf("claim-lock Claim() error = %v", lockedClaim.err)
	}
	if deleteErr == nil || !errors.Is(deleteContextErr, context.DeadlineExceeded) {
		t.Fatalf("scope binding delete was not blocked by Claim registration lock: error=%v context=%v", deleteErr, deleteContextErr)
	}
	if _, err := claimLockQueue.Cancel(ctx, lockedClaim.claim.Execution.ExecutionID); err != nil {
		t.Fatalf("cancel claim-lock action: %v", err)
	}

	submissions := []execution.ActionSubmission{
		realActionSubmission(t, signer, now, "90000000-0000-4000-8000-000000000001", workspaceID, environmentID, serviceID, "payments-api", 'a'),
		realActionSubmission(t, signer, now, "90000000-0000-4000-8000-000000000002", workspaceID, environmentID, serviceID, "payments-worker", 'b'),
	}
	for _, submission := range submissions {
		if _, err := queue.Submit(ctx, submission); err != nil {
			t.Fatalf("real ActionQueue.Submit(%s): %v", submission.Envelope.ActionID, err)
		}
	}
	retried, err := queue.Submit(ctx, submissions[0])
	if err != nil || retried.ExecutionID != submissions[0].Envelope.ActionID {
		t.Fatalf("real ActionQueue.Submit(idempotent) = %#v, %v", retried, err)
	}
	semanticRetry := realActionSubmission(t, signer, now, "90000000-0000-4000-8000-000000000098", workspaceID, environmentID,
		serviceID, "payments-api", 'a', submissions[0].Envelope.IdempotencyKey)
	retried, err = queue.Submit(ctx, semanticRetry)
	if err != nil || retried.ExecutionID != submissions[0].Envelope.ActionID {
		t.Fatalf("real ActionQueue.Submit(semantic idempotency retry) = %#v, %v", retried, err)
	}
	conflicting := realActionSubmission(t, signer, now, "90000000-0000-4000-8000-000000000099", workspaceID, environmentID,
		serviceID, "payments-conflict", '9', submissions[0].Envelope.IdempotencyKey)
	if _, err := queue.Submit(ctx, conflicting); !errors.Is(err, execution.ErrIdempotencyConflict) {
		t.Fatalf("real ActionQueue.Submit(idempotency conflict) error = %v", err)
	}

	type claimResult struct {
		claim execution.ClaimedAction
		err   error
	}
	start := make(chan struct{})
	results := make(chan claimResult, 2)
	runnerIDs := []string{"runner-postgres-1", "runner-postgres-2"}
	runnerScopes := make([]execution.RunnerScope, len(runnerIDs))
	for index, runnerID := range runnerIDs {
		runnerScopes[index] = realRunnerScope(t, ctx, database, runnerID)
	}
	claimContext, cancelClaims := context.WithTimeout(ctx, 5*time.Second)
	defer cancelClaims()
	for _, runnerScope := range runnerScopes {
		runnerScope := runnerScope
		go func() {
			<-start
			claim, claimErr := queue.Claim(claimContext, execution.ActionClaimRequest{
				Scope:         runnerScope,
				LeaseDuration: time.Minute,
			})
			results <- claimResult{claim: claim, err: claimErr}
		}()
	}
	close(start)
	var claimed execution.ClaimedAction
	var winners, blocked int
	for range 2 {
		var result claimResult
		select {
		case result = <-results:
		case <-claimContext.Done():
			t.Fatalf("timed out waiting for concurrent ActionQueue.Claim results: %v", claimContext.Err())
		}
		switch {
		case result.err == nil:
			claimed = result.claim
			winners++
		case errors.Is(result.err, executionlease.ErrNoLeaseAvailable):
			blocked++
		default:
			t.Fatalf("real concurrent ActionQueue.Claim error: %v", result.err)
		}
	}
	if winners != 1 || blocked != 1 || claimed.Execution.LeaseToken == "" {
		t.Fatalf("real production claim winners=%d blocked=%d claim=%#v", winners, blocked, claimed)
	}
	var persistedTokenHash string
	if err := database.QueryRow(ctx, `SELECT lease_token_sha256 FROM action_queue WHERE action_id = $1`, claimed.Execution.ExecutionID).Scan(&persistedTokenHash); err != nil {
		t.Fatalf("read persisted action lease token hash: %v", err)
	}
	if len(persistedTokenHash) != 64 || persistedTokenHash == claimed.Execution.LeaseToken {
		t.Fatalf("database persisted an invalid or reusable action lease token: %q", persistedTokenHash)
	}

	fence := claimed.Execution.Fence()
	started, err := queue.Start(ctx, fence)
	if err != nil || started.Status != executionlease.StatusRunning || started.LeaseToken != "" {
		t.Fatalf("real ActionQueue.Start = %#v, %v", started, err)
	}
	heartbeat, err := queue.Heartbeat(ctx, execution.ActionHeartbeatRequest{Lease: fence, Sequence: 1, Extension: 2 * time.Minute})
	if err != nil || heartbeat.Execution.LeaseToken != "" || !heartbeat.Execution.LeaseExpiresAt.After(started.LeaseExpiresAt) {
		t.Fatalf("real ActionQueue.Heartbeat = %#v, %v", heartbeat, err)
	}
	heartbeatExpiry := heartbeat.Execution.LeaseExpiresAt
	replayedHeartbeat, err := queue.Heartbeat(ctx, execution.ActionHeartbeatRequest{Lease: fence, Sequence: 1, Extension: 2 * time.Minute})
	if err != nil || !replayedHeartbeat.Execution.LeaseExpiresAt.Equal(heartbeatExpiry) {
		t.Fatalf("real ActionQueue.Heartbeat(replay) = %#v, %v", replayedHeartbeat, err)
	}
	if _, err := queue.Heartbeat(ctx, execution.ActionHeartbeatRequest{Lease: fence, Sequence: 0, Extension: 2 * time.Minute}); !errors.Is(err, execution.ErrHeartbeatSequence) {
		t.Fatalf("real ActionQueue.Heartbeat(stale sequence) error = %v", err)
	}
	completion := execution.ActionCompleteRequest{
		Lease: fence, Summary: execution.ExecutorResult{
			Outcome: execution.ExecutorSucceeded, Code: "INTEGRATION_VERIFIED", Verification: execution.VerificationPassed, Changed: true,
		},
	}
	finalizing, err := queue.Complete(ctx, completion)
	if err != nil || finalizing.Status != executionlease.StatusFinalizing || finalizing.LeaseToken != "" {
		t.Fatalf("real ActionQueue.Complete = %#v, %v", finalizing, err)
	}
	if _, err := queue.Complete(ctx, completion); err != nil {
		t.Fatalf("real ActionQueue.Complete(idempotent): %v", err)
	}
	completed, err := queue.Finalize(ctx, fence)
	if err != nil || completed.Status != executionlease.StatusSucceeded {
		t.Fatalf("real ActionQueue.Finalize = %#v, %v", completed, err)
	}
	var receiptTenantID, receiptWorkspaceID, receiptEnvironmentID string
	if err := database.QueryRow(ctx, `
		SELECT runner_tenant_id::text, runner_workspace_id::text, runner_environment_id::text
		FROM action_queue WHERE action_id = $1
	`, completed.ExecutionID).Scan(&receiptTenantID, &receiptWorkspaceID, &receiptEnvironmentID); err != nil {
		t.Fatalf("read terminal action runner identity: %v", err)
	}
	if receiptTenantID != tenantID || receiptWorkspaceID != workspaceID || receiptEnvironmentID != environmentID {
		t.Fatalf("terminal action runner identity = (%q, %q, %q)", receiptTenantID, receiptWorkspaceID, receiptEnvironmentID)
	}

	second, err := queue.Claim(ctx, execution.ActionClaimRequest{
		Scope:         realRunnerScope(t, ctx, database, "runner-postgres-3"),
		LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatalf("real ActionQueue.Claim(after completion): %v", err)
	}
	secondFence := second.Execution.Fence()
	secondStarted, err := queue.Start(ctx, secondFence)
	if err != nil {
		t.Fatalf("real ActionQueue.Start(second): %v", err)
	}
	cancelled, err := queue.Cancel(ctx, second.Execution.ExecutionID)
	if err != nil || cancelled.Status != executionlease.StatusRunning || cancelled.CancelRequestedAt.IsZero() || cancelled.LeaseToken != "" {
		t.Fatalf("real ActionQueue.Cancel = %#v, %v", cancelled, err)
	}
	terminateHeartbeat, err := queue.Heartbeat(ctx, execution.ActionHeartbeatRequest{Lease: secondFence, Sequence: 1, Extension: 2 * time.Minute})
	if err != nil || terminateHeartbeat.Directive != execution.HeartbeatTerminate ||
		!terminateHeartbeat.Execution.LeaseExpiresAt.Equal(secondStarted.LeaseExpiresAt) {
		t.Fatalf("real ActionQueue.Heartbeat(cancel intent) = %#v, %v", terminateHeartbeat, err)
	}

	third := realActionSubmission(t, signer, now, "90000000-0000-4000-8000-000000000003", workspaceID, environmentID, serviceID, "payments-jobs", 'd')
	if _, err := queue.Submit(ctx, third); err != nil {
		t.Fatalf("real ActionQueue.Submit(third): %v", err)
	}
	cancelCompletion := execution.ActionCompleteRequest{
		Lease: secondFence, Summary: execution.ExecutorResult{
			Outcome: execution.ExecutorUncertain, Code: "CANCELLED_OUTCOME_UNKNOWN", Verification: execution.VerificationUnknown,
		},
	}
	secondFinalizing, err := queue.Complete(ctx, cancelCompletion)
	if err != nil || secondFinalizing.Status != executionlease.StatusFinalizing {
		t.Fatalf("real ActionQueue.Complete(cancelled running) = %#v, %v", secondFinalizing, err)
	}
	blockedClaim := execution.ActionClaimRequest{
		Scope: realRunnerScope(t, ctx, database, "runner-postgres-4"), LeaseDuration: time.Minute,
	}
	if _, err := queue.Claim(ctx, blockedClaim); !errors.Is(err, executionlease.ErrNoLeaseAvailable) {
		t.Fatalf("FINALIZING released production slot: %v", err)
	}
	secondUncertain, err := queue.Finalize(ctx, secondFence)
	if err != nil || secondUncertain.Status != executionlease.StatusUncertain {
		t.Fatalf("real ActionQueue.Finalize(cancelled running) = %#v, %v", secondUncertain, err)
	}
	if _, err := queue.Claim(ctx, blockedClaim); !errors.Is(err, executionlease.ErrNoLeaseAvailable) {
		t.Fatalf("UNCERTAIN released production slot: %v", err)
	}
	if _, err := queue.Reconcile(ctx, executionlease.ReconcileRequest{
		ExecutionID: second.Execution.ExecutionID, ReconciliationID: "reconcile-postgres-cancel",
		ActorID: "sre-postgres-1", Status: executionlease.StatusFailed, ResultHash: strings.Repeat("c", 64),
	}); err != nil {
		t.Fatalf("real ActionQueue.Reconcile(cancelled running): %v", err)
	}
	thirdClaim, err := queue.Claim(ctx, execution.ActionClaimRequest{
		Scope: blockedClaim.Scope, LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatalf("real ActionQueue.Claim(third): %v", err)
	}
	if _, err := queue.Start(ctx, thirdClaim.Execution.Fence()); err != nil {
		t.Fatalf("real ActionQueue.Start(third): %v", err)
	}
	execSQL(t, ctx, database, `UPDATE action_queue SET lease_expires_at = statement_timestamp() - interval '1 second' WHERE action_id = $1`, third.Envelope.ActionID)
	uncertain, err := queue.Get(ctx, third.Envelope.ActionID)
	if err != nil || uncertain.Status != executionlease.StatusUncertain || uncertain.LeaseToken != "" {
		t.Fatalf("real ActionQueue.Get(expired running) = %#v, %v", uncertain, err)
	}
	reconciled, err := queue.Reconcile(ctx, executionlease.ReconcileRequest{
		ExecutionID: third.Envelope.ActionID, ReconciliationID: "reconcile-postgres-1", ActorID: "sre-postgres-1",
		Status: executionlease.StatusFailed, ResultHash: strings.Repeat("e", 64),
	})
	if err != nil || reconciled.Status != executionlease.StatusFailed || reconciled.ReconciliationResultHash != strings.Repeat("e", 64) {
		t.Fatalf("real ActionQueue.Reconcile = %#v, %v", reconciled, err)
	}

	// Exercise the database proof constraints directly so application regressions
	// cannot create terminal state without a complete Runner or reconciliation proof.
	expectSQLState(t, ctx, database, "23514", `
		UPDATE action_queue
		SET reconciliation_id = 'incomplete-reconciliation', reconciliation_actor = NULL,
			reconciliation_result_hash = $2, reconciled_at = statement_timestamp()
		WHERE action_id = $1
	`, claimed.Execution.ExecutionID, strings.Repeat("f", 64))
	expectSQLState(t, ctx, database, "23514", `
		UPDATE action_queue
		SET completed_lease_token_sha256 = NULL, completed_lease_epoch = NULL
		WHERE action_id = $1
	`, claimed.Execution.ExecutionID)
	expectSQLState(t, ctx, database, "23514", `
		UPDATE action_queue
		SET status = 'LEASED', lease_epoch = 0,
			lease_token_sha256 = $2, lease_acquired_at = statement_timestamp(),
			lease_expires_at = statement_timestamp() + interval '1 minute',
			last_heartbeat_at = statement_timestamp(), completed_at = NULL,
			result_hash = NULL, updated_at = statement_timestamp()
		WHERE action_id = $1
	`, second.Execution.ExecutionID, strings.Repeat("a", 64))

	shapeSubmission := realActionSubmission(t, signer, now, "90000000-0000-4000-8000-000000000096", workspaceID, environmentID,
		serviceID, "payments-runner-identity-shape", '6')
	shapeSubmission.Production = false
	if _, err := queue.Submit(ctx, shapeSubmission); err != nil {
		t.Fatalf("submit runner identity shape action: %v", err)
	}
	expectSQLState(t, ctx, database, "23514", `
		UPDATE action_queue
		SET runner_id = 'runner-postgres-1', runner_tenant_id = $2,
			runner_workspace_id = $3, runner_environment_id = $4
		WHERE action_id = $1
	`, shapeSubmission.Envelope.ActionID, tenantID, workspaceID, environmentID)
	if _, err := queue.Cancel(ctx, shapeSubmission.Envelope.ActionID); err != nil {
		t.Fatalf("cancel runner identity shape action: %v", err)
	}
	expectSQLState(t, ctx, database, "23514", `
		UPDATE action_queue
		SET runner_id = 'runner-postgres-1', runner_tenant_id = $2,
			runner_workspace_id = $3, runner_environment_id = $4
		WHERE action_id = $1
	`, shapeSubmission.Envelope.ActionID, tenantID, workspaceID, environmentID)
}

func exerciseRealClaimAuthorization(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	queue execution.ActionQueue,
	signer action.Signer,
	workspaceID, environmentID, serviceID string,
) {
	t.Helper()
	databaseNow := time.Now().UTC()
	expired := realActionSubmission(t, signer, databaseNow.Add(-31*time.Minute),
		"90000000-0000-4000-8000-000000000094", workspaceID, environmentID, serviceID, "payments-expired-authorization", '4')
	expired.Production = false
	shortWindow := realActionSubmission(t, signer, databaseNow.Add(-28*time.Minute),
		"90000000-0000-4000-8000-000000000093", workspaceID, environmentID, serviceID, "payments-short-authorization", '3')
	shortWindow.Production = false
	for _, submission := range []execution.ActionSubmission{expired, shortWindow} {
		if _, err := queue.Submit(ctx, submission); err != nil {
			t.Fatalf("submit authorization-boundary action %s: %v", submission.Envelope.ActionID, err)
		}
	}
	claimed, err := queue.Claim(ctx, execution.ActionClaimRequest{
		Scope: realRunnerScope(t, ctx, database, "runner-postgres-authorization"), LeaseDuration: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Claim(short authorization window): %v", err)
	}
	if claimed.Execution.ExecutionID != shortWindow.Envelope.ActionID {
		t.Fatalf("Claim(short authorization window) action = %q, want %q", claimed.Execution.ExecutionID, shortWindow.Envelope.ActionID)
	}
	if delta := claimed.Execution.LeaseExpiresAt.Sub(shortWindow.Envelope.ExpiresAt); delta > time.Microsecond || delta < -time.Microsecond {
		t.Fatalf("Claim(short authorization window) lease expiry = %s, want cap %s", claimed.Execution.LeaseExpiresAt, shortWindow.Envelope.ExpiresAt)
	}
	storedExpired, err := queue.Get(ctx, expired.Envelope.ActionID)
	if err != nil || storedExpired.Status != executionlease.StatusQueued {
		t.Fatalf("Get(expired queued action) = %#v, %v", storedExpired, err)
	}
	retriedExpired, err := queue.Submit(ctx, expired)
	if err != nil || retriedExpired.ExecutionID != expired.Envelope.ActionID || retriedExpired.Status != executionlease.StatusQueued {
		t.Fatalf("Submit(expired queued retry) = %#v, %v", retriedExpired, err)
	}
	if _, err := queue.Cancel(ctx, shortWindow.Envelope.ActionID); err != nil {
		t.Fatalf("Cancel(short authorization window action): %v", err)
	}
}

type realExecutionCallResult struct {
	execution executionlease.Execution
	err       error
}

type realHeartbeatCallResult struct {
	heartbeat execution.ActionHeartbeatResult
	err       error
}

func exerciseRealRegistrationRaces(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	queue execution.ActionQueue,
	signer action.Signer,
	tenantID, workspaceID, environmentID, serviceID string,
) {
	t.Helper()
	const runnerID = "runner-postgres-race"
	now := time.Now().UTC()
	submission := realActionSubmission(t, signer, now, "90000000-0000-4000-8000-000000000095", workspaceID, environmentID,
		serviceID, "payments-registration-race", '5')
	submission.Production = false
	if _, err := queue.Submit(ctx, submission); err != nil {
		t.Fatalf("submit registration race action: %v", err)
	}
	claimed, err := queue.Claim(ctx, execution.ActionClaimRequest{
		Scope: realRunnerScope(t, ctx, database, runnerID), LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatalf("claim registration race action: %v", err)
	}
	fence := claimed.Execution.Fence()

	disableTx, disableXID := beginRunnerDisable(t, ctx, database, runnerID)
	defer rollbackTestTransaction(disableTx)
	startResults := make(chan realExecutionCallResult, 1)
	startDone := make(chan struct{})
	startContext, cancelStart := context.WithTimeout(ctx, 5*time.Second)
	defer cancelStart()
	go func() {
		value, callErr := queue.Start(startContext, fence)
		startResults <- realExecutionCallResult{execution: value, err: callErr}
		close(startDone)
	}()
	waitForTransactionWaiter(t, ctx, database, disableXID, startDone, "Start registration lock")
	commitTestTransaction(t, ctx, disableTx, "commit disabled runner before Start")
	startResult := awaitExecutionCall(t, startResults, "Start after runner disable")
	if !errors.Is(startResult.err, executionlease.ErrStaleLease) {
		t.Fatalf("Start(disable wins) = %#v, %v; want stale lease", startResult.execution, startResult.err)
	}
	assertActionStatus(t, ctx, database, fence.ExecutionID, executionlease.StatusLeased)
	setRunnerEnabled(t, ctx, database, runnerID, true)
	started, err := queue.Start(ctx, fence)
	if err != nil || started.Status != executionlease.StatusRunning {
		t.Fatalf("Start(after re-enable) = %#v, %v", started, err)
	}

	actionTx, actionXID := beginActionRowBlock(t, ctx, database, fence.ExecutionID)
	defer rollbackTestTransaction(actionTx)
	heartbeatResults := make(chan realHeartbeatCallResult, 1)
	heartbeatDone := make(chan struct{})
	heartbeatContext, cancelHeartbeat := context.WithTimeout(ctx, 5*time.Second)
	defer cancelHeartbeat()
	go func() {
		value, callErr := queue.Heartbeat(heartbeatContext, execution.ActionHeartbeatRequest{Lease: fence, Sequence: 1, Extension: 2 * time.Minute})
		heartbeatResults <- realHeartbeatCallResult{heartbeat: value, err: callErr}
		close(heartbeatDone)
	}()
	waitForTransactionWaiter(t, ctx, database, actionXID, heartbeatDone, "Heartbeat action lock")
	updateContext, cancelUpdate := context.WithTimeout(ctx, 250*time.Millisecond)
	_, disableErr := database.Exec(updateContext, `
		UPDATE runner_registrations SET enabled = false, updated_at = statement_timestamp() WHERE runner_id = $1
	`, runnerID)
	updateContextErr := updateContext.Err()
	cancelUpdate()
	disableWasBlocked := disableErr != nil && errors.Is(updateContextErr, context.DeadlineExceeded)
	commitTestTransaction(t, ctx, actionTx, "release Heartbeat action row")
	heartbeatResult := awaitHeartbeatCall(t, heartbeatResults, "Heartbeat holding registration lock")
	if !disableWasBlocked {
		t.Fatalf("runner disable was not blocked by Heartbeat registration lock: error=%v context=%v", disableErr, updateContextErr)
	}
	if heartbeatResult.err != nil || heartbeatResult.heartbeat.Directive != execution.HeartbeatContinue ||
		heartbeatResult.heartbeat.Execution.HeartbeatSeq != 1 {
		t.Fatalf("Heartbeat(operation wins) = %#v, %v", heartbeatResult.heartbeat, heartbeatResult.err)
	}

	beforeExpiry := heartbeatResult.heartbeat.Execution.LeaseExpiresAt
	disableTx, disableXID = beginRunnerDisable(t, ctx, database, runnerID)
	defer rollbackTestTransaction(disableTx)
	heartbeatResults = make(chan realHeartbeatCallResult, 1)
	heartbeatDone = make(chan struct{})
	expiredHeartbeatContext, cancelExpiredHeartbeat := context.WithTimeout(ctx, 5*time.Second)
	defer cancelExpiredHeartbeat()
	go func() {
		value, callErr := queue.Heartbeat(expiredHeartbeatContext, execution.ActionHeartbeatRequest{Lease: fence, Sequence: 2, Extension: 3 * time.Minute})
		heartbeatResults <- realHeartbeatCallResult{heartbeat: value, err: callErr}
		close(heartbeatDone)
	}()
	waitForTransactionWaiter(t, ctx, database, disableXID, heartbeatDone, "Heartbeat registration lock")
	commitTestTransaction(t, ctx, disableTx, "commit disabled runner before Heartbeat")
	heartbeatResult = awaitHeartbeatCall(t, heartbeatResults, "Heartbeat after runner disable")
	if heartbeatResult.err != nil || heartbeatResult.heartbeat.Directive != execution.HeartbeatTerminate ||
		heartbeatResult.heartbeat.Execution.HeartbeatSeq != 1 ||
		!heartbeatResult.heartbeat.Execution.LeaseExpiresAt.Equal(beforeExpiry) {
		t.Fatalf("Heartbeat(disable wins) = %#v, %v", heartbeatResult.heartbeat, heartbeatResult.err)
	}
	setRunnerEnabled(t, ctx, database, runnerID, true)

	completion := execution.ActionCompleteRequest{
		Lease: fence,
		Summary: execution.ExecutorResult{
			Outcome: execution.ExecutorSucceeded, Code: "REGISTRATION_RACE_VERIFIED", Verification: execution.VerificationPassed,
		},
	}
	disableTx, disableXID = beginRunnerDisable(t, ctx, database, runnerID)
	defer rollbackTestTransaction(disableTx)
	completeResults := make(chan realExecutionCallResult, 1)
	completeDone := make(chan struct{})
	completeContext, cancelComplete := context.WithTimeout(ctx, 5*time.Second)
	defer cancelComplete()
	go func() {
		value, callErr := queue.Complete(completeContext, completion)
		completeResults <- realExecutionCallResult{execution: value, err: callErr}
		close(completeDone)
	}()
	waitForTransactionWaiter(t, ctx, database, disableXID, completeDone, "Complete registration lock")
	commitTestTransaction(t, ctx, disableTx, "commit disabled runner before Complete")
	completeResult := awaitExecutionCall(t, completeResults, "Complete after runner disable")
	if !errors.Is(completeResult.err, executionlease.ErrStaleLease) {
		t.Fatalf("Complete(disable wins) = %#v, %v; want stale lease", completeResult.execution, completeResult.err)
	}
	assertActionStatus(t, ctx, database, fence.ExecutionID, executionlease.StatusRunning)
	var receiptCount int
	if err := database.QueryRow(ctx, `SELECT count(*) FROM runner_result_receipts WHERE action_id = $1`, fence.ExecutionID).Scan(&receiptCount); err != nil || receiptCount != 0 {
		t.Fatalf("receipt count after rejected Complete = %d, %v", receiptCount, err)
	}
	setRunnerEnabled(t, ctx, database, runnerID, true)
	finalizing, err := queue.Complete(ctx, completion)
	if err != nil || finalizing.Status != executionlease.StatusFinalizing {
		t.Fatalf("Complete(after re-enable) = %#v, %v", finalizing, err)
	}
	completed, err := queue.Finalize(ctx, fence)
	if err != nil || completed.Status != executionlease.StatusSucceeded {
		t.Fatalf("Finalize(registration race action) = %#v, %v", completed, err)
	}
}

func beginRunnerDisable(t *testing.T, ctx context.Context, database *pgxpool.Pool, runnerID string) (pgx.Tx, string) {
	t.Helper()
	operationContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := database.Begin(operationContext)
	if err != nil {
		t.Fatalf("begin runner disable transaction: %v", err)
	}
	handedOff := false
	defer func() {
		if !handedOff {
			rollbackTestTransaction(tx)
		}
	}()
	if _, err := tx.Exec(operationContext, `
		UPDATE runner_registrations SET enabled = false, updated_at = statement_timestamp() WHERE runner_id = $1
	`, runnerID); err != nil {
		t.Fatalf("disable runner in transaction: %v", err)
	}
	var xid string
	if err := tx.QueryRow(operationContext, `SELECT txid_current()::text`).Scan(&xid); err != nil {
		t.Fatalf("read runner disable transaction ID: %v", err)
	}
	handedOff = true
	return tx, xid
}

func beginActionRowBlock(t *testing.T, ctx context.Context, database *pgxpool.Pool, actionID string) (pgx.Tx, string) {
	t.Helper()
	operationContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := database.Begin(operationContext)
	if err != nil {
		t.Fatalf("begin action row blocker: %v", err)
	}
	handedOff := false
	defer func() {
		if !handedOff {
			rollbackTestTransaction(tx)
		}
	}()
	var lockedActionID string
	if err := tx.QueryRow(operationContext, `SELECT action_id FROM action_queue WHERE action_id = $1 FOR UPDATE`, actionID).Scan(&lockedActionID); err != nil {
		t.Fatalf("lock action row: %v", err)
	}
	var xid string
	if err := tx.QueryRow(operationContext, `SELECT txid_current()::text`).Scan(&xid); err != nil {
		t.Fatalf("read action blocker transaction ID: %v", err)
	}
	handedOff = true
	return tx, xid
}

func waitForTransactionWaiter(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	xid string,
	operationDone <-chan struct{},
	operation string,
) {
	t.Helper()
	waitContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := database.QueryRow(waitContext, `
			SELECT EXISTS (
				SELECT 1 FROM pg_locks
				WHERE locktype = 'transactionid' AND transactionid::text = $1 AND NOT granted
			)
		`, xid).Scan(&waiting); err != nil {
			t.Fatalf("observe %s waiter: %v", operation, err)
		}
		if waiting {
			return
		}
		select {
		case <-operationDone:
			t.Fatalf("%s completed before waiting on transaction %s", operation, xid)
		case <-ticker.C:
		case <-waitContext.Done():
			t.Fatalf("timed out observing %s wait on transaction %s", operation, xid)
		}
	}
}

func commitTestTransaction(t *testing.T, ctx context.Context, tx pgx.Tx, operation string) {
	t.Helper()
	commitContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := tx.Commit(commitContext); err != nil {
		t.Fatalf("%s: %v", operation, err)
	}
}

func rollbackTestTransaction(tx pgx.Tx) {
	rollbackContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(rollbackContext)
}

func setRunnerEnabled(t *testing.T, ctx context.Context, database *pgxpool.Pool, runnerID string, enabled bool) {
	t.Helper()
	if _, err := database.Exec(ctx, `
		UPDATE runner_registrations SET enabled = $2, updated_at = statement_timestamp() WHERE runner_id = $1
	`, runnerID, enabled); err != nil {
		t.Fatalf("set runner %s enabled=%t: %v", runnerID, enabled, err)
	}
}

func assertActionStatus(t *testing.T, ctx context.Context, database *pgxpool.Pool, actionID string, want executionlease.Status) {
	t.Helper()
	var status executionlease.Status
	if err := database.QueryRow(ctx, `SELECT status FROM action_queue WHERE action_id = $1`, actionID).Scan(&status); err != nil {
		t.Fatalf("read action %s status: %v", actionID, err)
	}
	if status != want {
		t.Fatalf("action %s status = %s, want %s", actionID, status, want)
	}
}

func awaitExecutionCall(t *testing.T, results <-chan realExecutionCallResult, operation string) realExecutionCallResult {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", operation)
		return realExecutionCallResult{}
	}
}

func awaitHeartbeatCall(t *testing.T, results <-chan realHeartbeatCallResult, operation string) realHeartbeatCallResult {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", operation)
		return realHeartbeatCallResult{}
	}
}

func realActionSubmission(t *testing.T, signer action.Signer, now time.Time, actionID, workspaceID, environmentID, serviceID, deployment string, digestByte byte, idempotencyKeys ...string) execution.ActionSubmission {
	t.Helper()
	envelope := action.Envelope{
		SchemaVersion: action.SchemaVersionV1, ActionID: actionID, WorkspaceID: workspaceID,
		IncidentID: "50000000-0000-4000-8000-000000000002", RequestedBy: "operator-postgres-1",
		ActionType: action.ActionKubernetesRolloutRestart,
		Target: action.TargetRef{ServiceID: serviceID, EnvironmentID: environmentID, KubernetesDeployment: &action.KubernetesDeploymentTarget{
			ClusterID: "cluster-postgres-1", Namespace: "payments", Name: deployment,
			UID: "uid-" + deployment, ResourceVersion: "7",
		}},
		Parameters: action.ActionParameters{KubernetesRolloutRestart: &action.KubernetesRolloutRestartParameters{Reason: "integration verification"}},
		ObservedState: action.ObservedState{KubernetesDeployment: &action.KubernetesDeploymentObservedState{
			Generation: 3, Replicas: 2, AvailableReplicas: 2, UpdatedReplicas: 2,
		}},
		Preconditions: action.Preconditions{MappingResult: "EXACT", ExpectedResourceVersion: "7", RequireWhitelist: true},
		Verification:  action.VerificationPlan{Mode: "KUBERNETES_ROLLOUT", TimeoutSeconds: 300},
		Compensation:  action.CompensationPlan{Mode: "MANUAL_ONLY", Summary: "integration test only"},
		Risk:          policyRisk(), PolicyVersion: "policy.v1",
		CredentialScope: action.CredentialScope{
			ConnectorID: "kubernetes-postgres", Permission: "PATCH_DEPLOYMENT_RESTART",
			Resource: "cluster-postgres-1/payments/deployment/" + deployment, TTLSeconds: 600,
		},
		IdempotencyKey: "idem-" + actionID, NotBefore: now, ExpiresAt: now.Add(30 * time.Minute),
		TraceID: strings.Repeat("f", 32),
	}
	if len(idempotencyKeys) > 0 {
		envelope.IdempotencyKey = idempotencyKeys[0]
	}
	sealed, err := action.Seal(context.Background(), envelope, envelope.RequestedBy, signer)
	if err != nil {
		t.Fatalf("seal real PostgreSQL action %s: %v", actionID, err)
	}
	return execution.ActionSubmission{
		Envelope: sealed, PlanHash: sealed.PlanHash,
		TargetKey:           "k8s-deployment:sha256:" + strings.Repeat(string(digestByte), 64),
		EnvironmentRevision: "environment-postgres-1", Production: true, Pool: executionlease.PoolWrite,
	}
}

func realRunnerScope(t *testing.T, ctx context.Context, database *pgxpool.Pool, runnerID string) execution.RunnerScope {
	t.Helper()
	registry, err := executionpostgres.NewRunnerRegistry(database)
	if err != nil {
		t.Fatalf("NewRunnerRegistry() error = %v", err)
	}
	registration, err := registry.Resolve(ctx, runnerID)
	if err != nil {
		t.Fatalf("RunnerRegistry.Resolve(%s) error = %v", runnerID, err)
	}
	scope, err := registration.Scope()
	if err != nil {
		t.Fatalf("RunnerRegistration.Scope() error = %v", err)
	}
	return scope
}

func policyRisk() action.RiskAssessment {
	return action.RiskAssessment{Level: "MEDIUM", ReasonCodes: []string{"PRODUCTION_CHANGE", "RESTART"}}
}

func migrationPath(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve migration test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "../../../migrations"))
}

type legacyActionQueueFixture struct {
	signer   action.Signer
	original execution.ActionSubmission
}

func seedLegacyActionQueue(t *testing.T, ctx context.Context, database *pgxpool.Pool) legacyActionQueueFixture {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate legacy action signing key: %v", err)
	}
	signer, err := action.NewEd25519Signer("legacy-action-key", privateKey)
	if err != nil {
		t.Fatalf("create legacy action signer: %v", err)
	}
	original := realActionSubmission(t, signer, time.Now().UTC(), "legacy-action-1", "legacy-workspace-1", "PROD",
		"legacy-service-1", "legacy-api", '7')
	original.Production = false
	envelopeJSON, err := json.Marshal(original.Envelope)
	if err != nil {
		t.Fatalf("marshal legacy action envelope: %v", err)
	}
	submissionHash := legacyActionSubmissionHash(t, original, envelopeJSON)
	execSQL(t, ctx, database, `
		INSERT INTO action_queue (
			action_id, envelope, submission_hash, plan_hash, workspace_id, environment_id,
			target_key, environment_revision, runner_pool, production, status, not_before, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'QUEUED', $11, statement_timestamp(), statement_timestamp())
	`, original.Envelope.ActionID, string(envelopeJSON), submissionHash, original.PlanHash,
		original.Envelope.WorkspaceID, original.Envelope.Target.EnvironmentID, original.TargetKey,
		original.EnvironmentRevision, original.Pool, original.Production, original.Envelope.NotBefore)
	return legacyActionQueueFixture{signer: signer, original: original}
}

func legacyActionSubmissionHash(t *testing.T, submission execution.ActionSubmission, envelopeJSON []byte) string {
	t.Helper()
	encoded, err := json.Marshal(struct {
		SchemaVersion       string              `json:"schema_version"`
		Envelope            json.RawMessage     `json:"envelope"`
		PlanHash            string              `json:"plan_hash"`
		TargetKey           string              `json:"target_key"`
		EnvironmentRevision string              `json:"environment_revision"`
		Production          bool                `json:"production"`
		Pool                executionlease.Pool `json:"pool"`
	}{
		SchemaVersion: "action-queue-submission.v1", Envelope: envelopeJSON,
		PlanHash: submission.PlanHash, TargetKey: submission.TargetKey,
		EnvironmentRevision: submission.EnvironmentRevision, Production: submission.Production, Pool: submission.Pool,
	})
	if err != nil {
		t.Fatalf("marshal legacy action submission hash input: %v", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func exerciseRealLegacySemanticRetry(t *testing.T, ctx context.Context, database *pgxpool.Pool, fixture legacyActionQueueFixture) {
	t.Helper()
	var requestHashVersion string
	if err := database.QueryRow(ctx, `SELECT request_hash_version FROM action_queue WHERE action_id = $1`,
		fixture.original.Envelope.ActionID).Scan(&requestHashVersion); err != nil {
		t.Fatalf("read migrated legacy action request hash version: %v", err)
	}
	if requestHashVersion != "legacy-submission.v1" {
		t.Fatalf("migrated legacy action request hash version = %q", requestHashVersion)
	}
	retryEnvelope := fixture.original.Envelope
	retryEnvelope.ActionID = "legacy-action-2"
	retryEnvelope.TraceID = strings.Repeat("e", 32)
	retryEnvelope, err := action.Seal(ctx, retryEnvelope, retryEnvelope.RequestedBy, fixture.signer)
	if err != nil {
		t.Fatalf("seal valid legacy semantic retry: %v", err)
	}
	if retryEnvelope.Signature.Value == fixture.original.Envelope.Signature.Value {
		t.Fatal("legacy semantic retry did not produce a second signature")
	}
	retry := fixture.original
	retry.Envelope = retryEnvelope
	retry.PlanHash = retryEnvelope.PlanHash
	queue, err := executionpostgres.New(database, executionpostgres.Options{})
	if err != nil {
		t.Fatalf("create action queue for legacy semantic retry: %v", err)
	}
	got, err := queue.Submit(ctx, retry)
	if err != nil || got.ExecutionID != fixture.original.Envelope.ActionID {
		t.Fatalf("Submit(real migrated legacy semantic retry) = %#v, %v", got, err)
	}
	var identityCount int
	if err := database.QueryRow(ctx, `SELECT count(*) FROM action_queue WHERE action_id IN ($1, $2)`,
		fixture.original.Envelope.ActionID, retryEnvelope.ActionID).Scan(&identityCount); err != nil || identityCount != 1 {
		t.Fatalf("legacy semantic retry action identity count = %d, %v", identityCount, err)
	}
}

func seedLegacyExecutionLeaseTokens(t *testing.T, ctx context.Context, database *pgxpool.Pool) {
	t.Helper()
	execSQL(t, ctx, database, `
		INSERT INTO execution_leases (
			execution_id, target_key, runner_pool, production, status, runner_id,
			lease_token, lease_epoch, lease_acquired_at, lease_expires_at, last_heartbeat_at,
			created_at, updated_at
		) VALUES (
			'legacy-active', 'legacy/active', 'READ', false, 'LEASED', 'legacy-runner',
			'legacy-active-secret', 1, statement_timestamp(), statement_timestamp() + interval '5 minutes',
			statement_timestamp(), statement_timestamp(), statement_timestamp()
		)
	`)
	execSQL(t, ctx, database, `
		INSERT INTO execution_leases (
			execution_id, target_key, runner_pool, production, status, runner_id,
			lease_epoch, completed_at, result_hash, completed_lease_token, completed_lease_epoch,
			created_at, updated_at
		) VALUES (
			'legacy-completed', 'legacy/completed', 'READ', false, 'SUCCEEDED', 'legacy-runner',
			1, statement_timestamp(), $1, 'legacy-completed-secret', 1,
			statement_timestamp(), statement_timestamp()
		)
	`, strings.Repeat("a", 64))
}

func verifyLegacyExecutionLeaseTokenHashes(t *testing.T, ctx context.Context, database *pgxpool.Pool) {
	t.Helper()
	for _, test := range []struct {
		executionID string
		token       string
		active      bool
	}{
		{executionID: "legacy-active", token: "legacy-active-secret", active: true},
		{executionID: "legacy-completed", token: "legacy-completed-secret", active: false},
	} {
		var plaintext, completedPlaintext, activeHash, completedHash *string
		if err := database.QueryRow(ctx, `
			SELECT lease_token, completed_lease_token, lease_token_sha256, completed_lease_token_sha256
			FROM execution_leases WHERE execution_id = $1
		`, test.executionID).Scan(&plaintext, &completedPlaintext, &activeHash, &completedHash); err != nil {
			t.Fatalf("read migrated execution lease %s: %v", test.executionID, err)
		}
		digest := sha256.Sum256([]byte(test.token))
		wantHash := hex.EncodeToString(digest[:])
		if plaintext != nil || completedPlaintext != nil {
			t.Fatalf("migration retained plaintext token for %s", test.executionID)
		}
		if test.active {
			if activeHash == nil || *activeHash != wantHash || completedHash != nil {
				t.Fatalf("active token hash for %s = (%v, %v), want %s", test.executionID, activeHash, completedHash, wantHash)
			}
		} else if completedHash == nil || *completedHash != wantHash || activeHash != nil {
			t.Fatalf("completed token hash for %s = (%v, %v), want %s", test.executionID, activeHash, completedHash, wantHash)
		}
	}
}

func applyMigrationsBefore(t *testing.T, ctx context.Context, database *pgxpool.Pool, directory, suffix, cutoff string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", directory, err)
	}
	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), suffix) && entry.Name() < cutoff {
			files = append(files, filepath.Join(directory, entry.Name()))
		}
	}
	sort.Strings(files)
	for _, file := range files {
		applyMigrationFile(t, ctx, database, file)
	}
}

func applyMigrationFile(t *testing.T, ctx context.Context, database *pgxpool.Pool, filename string) {
	t.Helper()
	contents, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", filename, err)
	}
	if _, err := database.Exec(ctx, string(contents)); err != nil {
		t.Fatalf("apply migration %s: %v", filepath.Base(filename), err)
	}
}

func expectMigrationSQLState(t *testing.T, ctx context.Context, database *pgxpool.Pool, filename, sqlState string) {
	t.Helper()
	contents, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", filename, err)
	}
	connection, err := database.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire PostgreSQL connection: %v", err)
	}
	defer connection.Release()
	_, execErr := connection.Exec(ctx, string(contents))
	if execErr == nil {
		t.Fatalf("migration %s unexpectedly succeeded", filepath.Base(filename))
	}
	var postgresError *pgconn.PgError
	if !errors.As(execErr, &postgresError) || postgresError.Code != sqlState {
		t.Fatalf("migration %s error = %v, want SQLSTATE %s", filepath.Base(filename), execErr, sqlState)
	}
	if _, err := connection.Exec(ctx, "ROLLBACK"); err != nil {
		t.Fatalf("rollback rejected migration %s: %v", filepath.Base(filename), err)
	}
}

func applyMigrations(t *testing.T, ctx context.Context, database *pgxpool.Pool, directory, suffix string, reverse bool) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", directory, err)
	}
	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), suffix) {
			files = append(files, filepath.Join(directory, entry.Name()))
		}
	}
	sort.Strings(files)
	if reverse {
		for left, right := 0, len(files)-1; left < right; left, right = left+1, right-1 {
			files[left], files[right] = files[right], files[left]
		}
	}
	for _, filename := range files {
		applyMigrationFile(t, ctx, database, filename)
	}
}

func execSQL(t *testing.T, ctx context.Context, database *pgxpool.Pool, query string, arguments ...any) {
	t.Helper()
	if _, err := database.Exec(ctx, query, arguments...); err != nil {
		t.Fatalf("exec SQL: %v", err)
	}
}

func expectSQLState(t *testing.T, ctx context.Context, database *pgxpool.Pool, sqlState, query string, arguments ...any) {
	t.Helper()
	_, err := database.Exec(ctx, query, arguments...)
	if err == nil {
		t.Fatal("SQL unexpectedly succeeded")
	}
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != sqlState {
		t.Fatalf("SQL error = %v, want SQLSTATE %s", err, sqlState)
	}
}
