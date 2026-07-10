package postgres_test

import (
	"bytes"
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
	"github.com/seaworld008/aiops-system/internal/credential"
	credentialpostgres "github.com/seaworld008/aiops-system/internal/credential/postgres"
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
	var serverVersion int
	if err := database.QueryRow(ctx, `SELECT current_setting('server_version_num')::integer`).Scan(&serverVersion); err != nil {
		t.Fatalf("read PostgreSQL server version: %v", err)
	}
	if serverVersion/10000 != 16 {
		t.Fatalf("integration harness requires PostgreSQL 16, got server_version_num=%d", serverVersion)
	}
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
	applyMigrationFile(t, ctx, database, filepath.Join(migrationDirectory, "000008_credential_revocations.up.sql"))
	exerciseRealCredentialRevocations(t, ctx, database, migrationDirectory,
		tenant1, tenant2, workspace1, workspace2, environment1, service1)
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

func exerciseRealCredentialRevocations(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	migrationDirectory, tenantID, otherTenantID, workspaceID, otherWorkspaceID, environmentID, serviceID string,
) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate credential revocation action key: %v", err)
	}
	signer, err := action.NewEd25519Signer("credential-revocation-integration-key", privateKey)
	if err != nil {
		t.Fatalf("create credential revocation action signer: %v", err)
	}
	queue, err := executionpostgres.New(database, executionpostgres.Options{})
	if err != nil {
		t.Fatalf("create credential revocation action queue: %v", err)
	}
	now := time.Now().UTC()
	submission := realActionSubmission(t, signer, now,
		"91000000-0000-4000-8000-000000000001", workspaceID, environmentID, serviceID,
		"payments-credential-revocation", '7')
	submission.Production = false
	if _, err := queue.Submit(ctx, submission); err != nil {
		t.Fatalf("submit credential revocation action: %v", err)
	}
	claimedAction, err := queue.Claim(ctx, execution.ActionClaimRequest{
		Scope: realRunnerScope(t, ctx, database, "runner-postgres-1"), LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatalf("claim credential revocation action: %v", err)
	}
	actionFence := credential.ActionFence{
		ActionID: claimedAction.Execution.ExecutionID, RunnerID: claimedAction.Execution.RunnerID,
		Token: claimedAction.Execution.LeaseToken, Epoch: claimedAction.Execution.LeaseEpoch,
	}
	if _, err := queue.Start(ctx, claimedAction.Execution.Fence()); err != nil {
		t.Fatalf("start credential revocation action: %v", err)
	}
	expectSQLState(t, ctx, database, "23503", `
		INSERT INTO credential_revocations (
			revocation_id, tenant_id, workspace_id, environment_id,
			action_id, target_key, production, runner_id, action_lease_epoch, action_lease_token_sha256,
			issuer, connector_id, scope_permission, scope_resource, credential_expires_at,
			child_create_permit_sha256
		) VALUES (
			'92000000-0000-4000-8000-000000000099', $1, $2, $3,
			$4, $5, false, $6, $7, $8,
			'vault-production', $9, $10, $11, statement_timestamp() + interval '5 minutes', repeat('a', 64)
		)
	`, otherTenantID, otherWorkspaceID, environmentID, actionFence.ActionID, submission.TargetKey,
		actionFence.RunnerID, actionFence.Epoch, credential.SHA256Hex([]byte(actionFence.Token)),
		submission.Envelope.CredentialScope.ConnectorID, submission.Envelope.CredentialScope.Permission,
		submission.Envelope.CredentialScope.Resource)
	protector, err := credential.NewAESGCMProtector(credential.KeyRing{
		ActiveKeyID: "credential-integration-key-1",
		Keys: map[string]credential.ProtectionKey{
			"credential-integration-key-1": {
				EncryptionKey: bytes.Repeat([]byte{0x31}, 32),
				HMACKey:       bytes.Repeat([]byte{0x32}, 32),
			},
		},
	})
	if err != nil {
		t.Fatalf("create credential reference protector: %v", err)
	}
	defer protector.Destroy()
	repository, err := credentialpostgres.New(database, protector, credentialpostgres.Options{})
	if err != nil {
		t.Fatalf("create credential revocation repository: %v", err)
	}
	expectSQLState(t, ctx, database, "P0001", `TRUNCATE audit_records`)
	credentialExpiry := now.Add(5*time.Minute + 999*time.Nanosecond)
	canonicalCredentialExpiry := credential.CanonicalCredentialExpiry(credentialExpiry)
	type prepareCallResult struct {
		result credential.PrepareResult
		err    error
	}
	prepareContext, cancelPrepare := context.WithTimeout(ctx, 5*time.Second)
	defer cancelPrepare()
	prepareStart := make(chan struct{})
	prepareResults := make(chan prepareCallResult, 2)
	for _, candidateID := range []string{
		"92000000-0000-4000-8000-000000000001",
		"92000000-0000-4000-8000-000000000002",
	} {
		candidateID := candidateID
		go func() {
			<-prepareStart
			result, prepareErr := repository.Prepare(prepareContext, credential.PrepareRequest{
				RevocationID: candidateID, Fence: actionFence, Issuer: "vault-production",
				CredentialExpiresAt: credentialExpiry,
			})
			prepareResults <- prepareCallResult{result: result, err: prepareErr}
		}()
	}
	close(prepareStart)
	createdWinners := 0
	revocationID := ""
	var childCreatePermit *credential.ChildCreatePermit
	for range 2 {
		var call prepareCallResult
		select {
		case call = <-prepareResults:
		case <-prepareContext.Done():
			t.Fatalf("timed out waiting for concurrent credential Prepare: %v", prepareContext.Err())
		}
		if call.err != nil {
			t.Fatalf("real concurrent credential Prepare: %v", call.err)
		}
		if call.result.Created {
			createdWinners++
			if call.result.Permit == nil {
				t.Fatal("real concurrent credential Prepare winner returned no child-create permit")
			}
			permitCopy := *call.result.Permit
			childCreatePermit = &permitCopy
		} else if call.result.Permit != nil {
			t.Fatal("real concurrent credential Prepare replay returned child-create permit")
		}
		if revocationID == "" {
			revocationID = call.result.Revocation.ID
		}
		if call.result.Revocation.ID != revocationID || call.result.Revocation.Status != credential.StatusPrepared ||
			call.result.Revocation.WorkspaceID != workspaceID || call.result.Revocation.EnvironmentID != environmentID ||
			call.result.Revocation.TargetKey != submission.TargetKey ||
			!call.result.Revocation.CredentialExpiresAt.Equal(canonicalCredentialExpiry) {
			t.Fatalf("real concurrent credential Prepare result = %#v", call.result)
		}
	}
	if createdWinners != 1 || childCreatePermit == nil {
		t.Fatalf("real concurrent credential Prepare Created winners = %d, want 1", createdWinners)
	}
	type childAuthorizationResult struct {
		authorization credential.ChildCreateAuthorization
		err           error
	}
	authorizeContext, cancelAuthorize := context.WithTimeout(ctx, 5*time.Second)
	defer cancelAuthorize()
	authorizeStart := make(chan struct{})
	authorizeResults := make(chan childAuthorizationResult, 2)
	for range 2 {
		go func() {
			<-authorizeStart
			authorization, authorizeErr := repository.AuthorizeChildCreate(authorizeContext, credential.AuthorizeChildCreateRequest{
				Permit: *childCreatePermit, Fence: actionFence,
			})
			authorizeResults <- childAuthorizationResult{authorization: authorization, err: authorizeErr}
		}()
	}
	close(authorizeStart)
	authorizationWinners, authorizationReplays := 0, 0
	var childAuthorization credential.ChildCreateAuthorization
	for range 2 {
		select {
		case result := <-authorizeResults:
			if result.err == nil {
				authorizationWinners++
				childAuthorization = result.authorization
			} else if errors.Is(result.err, credential.ErrChildCreateAlreadyAuthorized) {
				authorizationReplays++
			} else {
				t.Fatalf("real concurrent AuthorizeChildCreate error = %v", result.err)
			}
		case <-authorizeContext.Done():
			t.Fatalf("timed out waiting for concurrent AuthorizeChildCreate: %v", authorizeContext.Err())
		}
	}
	if authorizationWinners != 1 || authorizationReplays != 1 || childAuthorization.TTL < time.Second ||
		childAuthorization.DatabaseAuthorizedAt.Add(childAuthorization.TTL+credential.ChildCreateExpiryReserve).
			After(childAuthorization.CredentialExpiresAt) {
		t.Fatalf("real AuthorizeChildCreate winners/replays=%d/%d authorization=%#v",
			authorizationWinners, authorizationReplays, childAuthorization)
	}
	idempotent, err := repository.Prepare(ctx, credential.PrepareRequest{
		RevocationID: revocationID, Fence: actionFence, Issuer: "vault-production",
		CredentialExpiresAt: credentialExpiry,
	})
	if err != nil || idempotent.Created || idempotent.Permit != nil || idempotent.Revocation.ID != revocationID {
		t.Fatalf("real credential Prepare(idempotent) = %#v, %v", idempotent, err)
	}
	canonicalReplay, err := repository.Prepare(ctx, credential.PrepareRequest{
		RevocationID: "92000000-0000-4000-8000-000000000004", Fence: actionFence,
		Issuer: "vault-production", CredentialExpiresAt: credentialExpiry,
	})
	if err != nil || canonicalReplay.Created || canonicalReplay.Revocation.ID != revocationID {
		t.Fatalf("real credential Prepare(canonical replay) = %#v, %v", canonicalReplay, err)
	}
	conflicting := credential.PrepareRequest{
		RevocationID: "92000000-0000-4000-8000-000000000005", Fence: actionFence,
		Issuer: "different-issuer", CredentialExpiresAt: credentialExpiry,
	}
	if _, err := repository.Prepare(ctx, conflicting); !errors.Is(err, credential.ErrIdempotencyConflict) {
		t.Fatalf("real credential Prepare(conflicting semantics) error = %v", err)
	}

	// Exercise the primary revocation_id key and the canonical action/epoch key
	// in one real concurrent interleaving. Exactly one action may bind the
	// shared candidate; the other action remains free for a later Prepare.
	crossFences := make([]credential.ActionFence, 0, 2)
	for index, input := range []struct {
		actionID   string
		runnerID   string
		deployment string
		digestByte byte
	}{
		{actionID: "91000000-0000-4000-8000-000000000003", runnerID: "runner-postgres-3", deployment: "payments-credential-unique-a", digestByte: 'a'},
		{actionID: "91000000-0000-4000-8000-000000000004", runnerID: "runner-postgres-4", deployment: "payments-credential-unique-b", digestByte: 'b'},
	} {
		crossSubmission := realActionSubmission(t, signer, now, input.actionID, workspaceID, environmentID, serviceID,
			input.deployment, input.digestByte)
		crossSubmission.Production = false
		if _, err := queue.Submit(ctx, crossSubmission); err != nil {
			t.Fatalf("submit credential cross-unique action %d: %v", index, err)
		}
		crossAction, err := queue.Claim(ctx, execution.ActionClaimRequest{
			Scope: realRunnerScope(t, ctx, database, input.runnerID), LeaseDuration: time.Minute,
		})
		if err != nil || crossAction.Execution.ExecutionID != input.actionID {
			t.Fatalf("claim credential cross-unique action %d = %#v, %v", index, crossAction, err)
		}
		if _, err := queue.Start(ctx, crossAction.Execution.Fence()); err != nil {
			t.Fatalf("start credential cross-unique action %d: %v", index, err)
		}
		crossFences = append(crossFences, credential.ActionFence{
			ActionID: crossAction.Execution.ExecutionID, RunnerID: crossAction.Execution.RunnerID,
			Token: crossAction.Execution.LeaseToken, Epoch: crossAction.Execution.LeaseEpoch,
		})
	}
	const crossCandidateID = "92000000-0000-4000-8000-000000000012"
	crossContext, cancelCross := context.WithTimeout(ctx, 5*time.Second)
	defer cancelCross()
	crossStart := make(chan struct{})
	crossResults := make(chan prepareCallResult, len(crossFences))
	for _, crossFence := range crossFences {
		crossFence := crossFence
		go func() {
			<-crossStart
			result, prepareErr := repository.Prepare(crossContext, credential.PrepareRequest{
				RevocationID: crossCandidateID, Fence: crossFence, Issuer: "vault-production",
				CredentialExpiresAt: time.Now().UTC().Add(5 * time.Minute),
			})
			crossResults <- prepareCallResult{result: result, err: prepareErr}
		}()
	}
	close(crossStart)
	crossWinners, crossConflicts := 0, 0
	var crossWinnerFence, crossLoserFence credential.ActionFence
	var crossWinnerPermit *credential.ChildCreatePermit
	for range crossFences {
		var call prepareCallResult
		select {
		case call = <-crossResults:
		case <-crossContext.Done():
			t.Fatalf("timed out waiting for credential cross-unique Prepare: %v", crossContext.Err())
		}
		if call.err == nil {
			if !call.result.Created || call.result.Permit == nil || call.result.Revocation.ID != crossCandidateID {
				t.Fatalf("credential cross-unique winner = %#v", call.result)
			}
			permitCopy := *call.result.Permit
			crossWinnerPermit = &permitCopy
			crossWinners++
			for _, crossFence := range crossFences {
				if crossFence.ActionID == call.result.Revocation.ActionID {
					crossWinnerFence = crossFence
				}
			}
			continue
		}
		if !errors.Is(call.err, credential.ErrIdempotencyConflict) {
			t.Fatalf("credential cross-unique loser error = %v", call.err)
		}
		crossConflicts++
	}
	for _, crossFence := range crossFences {
		if crossFence.ActionID != crossWinnerFence.ActionID {
			crossLoserFence = crossFence
		}
	}
	if crossWinners != 1 || crossConflicts != 1 || crossWinnerFence.ActionID == "" || crossLoserFence.ActionID == "" || crossWinnerPermit == nil {
		t.Fatalf("credential cross-unique results winners/conflicts=%d/%d winner=%#v loser=%#v",
			crossWinners, crossConflicts, crossWinnerFence, crossLoserFence)
	}
	if _, err := repository.AuthorizeChildCreate(ctx, credential.AuthorizeChildCreateRequest{
		Permit: *crossWinnerPermit, Fence: crossWinnerFence,
	}); err != nil {
		t.Fatalf("authorize credential cross-unique winner: %v", err)
	}
	var crossCandidateRows int
	if err := database.QueryRow(ctx, `SELECT count(*) FROM credential_revocations WHERE revocation_id = $1`, crossCandidateID).
		Scan(&crossCandidateRows); err != nil || crossCandidateRows != 1 {
		t.Fatalf("credential cross-unique candidate rows = %d, %v", crossCandidateRows, err)
	}

	// Delay the anchored outbox write until the initially-current action has
	// less than the one-second post-child commit window. The final DB-time
	// recheck must still persist the accessor, but atomically request revocation.
	execSQL(t, ctx, database, `
		CREATE FUNCTION delay_test_anchor_outbox() RETURNS trigger AS $$
		BEGIN
			IF NEW.aggregate_id = '92000000-0000-4000-8000-000000000012'::uuid
			   AND NEW.event_type = 'credential.revocation.anchored.v1' THEN
				PERFORM pg_sleep(1.25);
			END IF;
			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER delay_test_anchor_outbox_insert
		BEFORE INSERT ON outbox_events
		FOR EACH ROW EXECUTE FUNCTION delay_test_anchor_outbox();
		UPDATE action_queue
		SET lease_expires_at = statement_timestamp() + interval '2 seconds'
		WHERE action_id = $1;
	`, crossWinnerFence.ActionID)
	anchorContext, cancelAnchor := context.WithTimeout(ctx, 5*time.Second)
	defer cancelAnchor()
	crossAccessor, _ := credential.NewSensitiveReference([]byte("cross-unique-commit-window-accessor"))
	anchorStartedAt := time.Now()
	crossAnchored, err := repository.RecordAnchor(anchorContext, credential.RecordAnchorRequest{
		RevocationID: crossCandidateID, Fence: crossWinnerFence, Accessor: crossAccessor,
	})
	anchorElapsed := time.Since(anchorStartedAt)
	crossAccessor.Destroy()
	if err != nil || crossAnchored.Status != credential.StatusRevocationPending || !crossAnchored.AccessorPresent {
		t.Fatalf("real RecordAnchor(commit window elapsed) = %#v, %v", crossAnchored, err)
	}
	if anchorElapsed < 1200*time.Millisecond {
		t.Fatalf("real RecordAnchor did not cross blocking outbox hook: elapsed=%s", anchorElapsed)
	}
	execSQL(t, ctx, database, `
		DROP TRIGGER delay_test_anchor_outbox_insert ON outbox_events;
		DROP FUNCTION delay_test_anchor_outbox();
	`)
	crossClaims, err := repository.ClaimRevocations(ctx, credential.ClaimRevocationsRequest{
		WorkerID: "credential-cross-unique-cleanup", Limit: 1, LeaseDuration: 30 * time.Second,
	})
	if err != nil || len(crossClaims) != 1 || crossClaims[0].Revocation.ID != crossCandidateID {
		t.Fatalf("claim credential cross-unique cleanup = %#v, %v", crossClaims, err)
	}
	crossClaims[0].Accessor.Destroy()
	if _, err := repository.CompleteRevocation(ctx, credential.CompleteRevocationRequest{Fence: crossClaims[0].Fence}); err != nil {
		t.Fatalf("complete credential cross-unique cleanup: %v", err)
	}

	// Delay Prepare's outbox write on the losing action. Its final live-fence
	// query must roll the entire transaction back once less than one second
	// remains, including both audit and outbox writes.
	const delayedPrepareID = "92000000-0000-4000-8000-000000000013"
	execSQL(t, ctx, database, `
		CREATE FUNCTION delay_test_prepare_outbox() RETURNS trigger AS $$
		BEGIN
			IF NEW.aggregate_id = '92000000-0000-4000-8000-000000000013'::uuid
			   AND NEW.event_type = 'credential.revocation.prepared.v1' THEN
				PERFORM pg_sleep(1.25);
			END IF;
			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER delay_test_prepare_outbox_insert
		BEFORE INSERT ON outbox_events
		FOR EACH ROW EXECUTE FUNCTION delay_test_prepare_outbox();
		UPDATE action_queue
		SET lease_expires_at = statement_timestamp() + interval '2 seconds'
		WHERE action_id = $1;
	`, crossLoserFence.ActionID)
	delayedPrepareContext, cancelDelayedPrepare := context.WithTimeout(ctx, 5*time.Second)
	defer cancelDelayedPrepare()
	delayedPrepareStartedAt := time.Now()
	delayedPrepare, delayedPrepareErr := repository.Prepare(delayedPrepareContext, credential.PrepareRequest{
		RevocationID: delayedPrepareID, Fence: crossLoserFence, Issuer: "vault-production",
		CredentialExpiresAt: time.Now().UTC().Add(5 * time.Minute),
	})
	delayedPrepareElapsed := time.Since(delayedPrepareStartedAt)
	if !errors.Is(delayedPrepareErr, credential.ErrStaleActionFence) || delayedPrepare.Created {
		t.Fatalf("real Prepare(commit window elapsed) = %#v, %v", delayedPrepare, delayedPrepareErr)
	}
	if delayedPrepareElapsed < 1200*time.Millisecond {
		t.Fatalf("real Prepare did not cross blocking outbox hook: elapsed=%s", delayedPrepareElapsed)
	}
	execSQL(t, ctx, database, `
		DROP TRIGGER delay_test_prepare_outbox_insert ON outbox_events;
		DROP FUNCTION delay_test_prepare_outbox();
	`)

	// An authorized PREPARED row remains recoverable only after its durable
	// absolute credential deadline plus grace. Race recovery against a stale
	// authorization attempt to prove that NO_CREDENTIAL wins without reopening
	// child creation.
	const authorizedExpiredRecoveryID = "92000000-0000-4000-8000-000000000016"
	authorizedExpiredPermitToken := "authorized-expired-child-create-permit"
	authorizedExpiredPermitDigest := credential.SHA256Hex([]byte(authorizedExpiredPermitToken))
	execSQL(t, ctx, database, `
		UPDATE action_queue
		SET lease_expires_at = clock_timestamp() + interval '2 minutes'
		WHERE action_id = $1;
		WITH clock AS (SELECT clock_timestamp() AS current_time)
		INSERT INTO credential_revocations (
			revocation_id, tenant_id, workspace_id, environment_id,
			action_id, target_key, production, runner_id, action_lease_epoch, action_lease_token_sha256,
			issuer, connector_id, scope_permission, scope_resource, credential_expires_at,
			child_create_permit_sha256, available_at, created_at, updated_at
		)
		SELECT $2, action.runner_tenant_id, action.runner_workspace_id, action.runner_environment_id,
			action.action_id, action.target_key, action.production, action.runner_id, action.lease_epoch,
			action.lease_token_sha256, 'vault-production',
			action.envelope #>> '{credential_scope,connector_id}',
			action.envelope #>> '{credential_scope,permission}',
			action.envelope #>> '{credential_scope,resource}',
			clock.current_time - interval '70 seconds', $3,
			clock.current_time - interval '2 minutes', clock.current_time - interval '2 minutes',
			clock.current_time - interval '2 minutes'
		FROM action_queue AS action CROSS JOIN clock
		WHERE action.action_id = $1;
		UPDATE credential_revocations
		SET child_create_authorized_at = created_at + interval '5 seconds',
			child_create_ttl_seconds = 10, updated_at = clock_timestamp(), version = version + 1
		WHERE revocation_id = $2;
	`, crossLoserFence.ActionID, authorizedExpiredRecoveryID, authorizedExpiredPermitDigest)
	authorizedRecoveryContext, cancelAuthorizedRecovery := context.WithTimeout(ctx, 5*time.Second)
	defer cancelAuthorizedRecovery()
	authorizedRecoveryStart := make(chan struct{})
	type authorizedPreparedRecoveryResult struct {
		revocations []credential.Revocation
		err         error
	}
	authorizedRecoveryResult := make(chan authorizedPreparedRecoveryResult, 1)
	authorizedRetryResult := make(chan error, 1)
	go func() {
		<-authorizedRecoveryStart
		revocations, recoverErr := repository.RecoverPrepared(authorizedRecoveryContext, credential.RecoverPreparedRequest{Limit: 1})
		authorizedRecoveryResult <- authorizedPreparedRecoveryResult{revocations: revocations, err: recoverErr}
	}()
	go func() {
		<-authorizedRecoveryStart
		_, authorizeErr := repository.AuthorizeChildCreate(authorizedRecoveryContext, credential.AuthorizeChildCreateRequest{
			Permit: credential.ChildCreatePermit{RevocationID: authorizedExpiredRecoveryID, Token: authorizedExpiredPermitToken},
			Fence:  crossLoserFence,
		})
		authorizedRetryResult <- authorizeErr
	}()
	close(authorizedRecoveryStart)
	var authorizedRecovered authorizedPreparedRecoveryResult
	select {
	case authorizedRecovered = <-authorizedRecoveryResult:
	case <-authorizedRecoveryContext.Done():
		t.Fatalf("timed out waiting for authorized PREPARED recovery: %v", authorizedRecoveryContext.Err())
	}
	if authorizedRecovered.err != nil || len(authorizedRecovered.revocations) != 1 ||
		authorizedRecovered.revocations[0].ID != authorizedExpiredRecoveryID ||
		authorizedRecovered.revocations[0].Status != credential.StatusNoCredential {
		t.Fatalf("authorized PREPARED recovery = %#v, %v", authorizedRecovered.revocations, authorizedRecovered.err)
	}
	select {
	case authorizeErr := <-authorizedRetryResult:
		if !errors.Is(authorizeErr, credential.ErrChildCreateAlreadyAuthorized) &&
			!errors.Is(authorizeErr, credential.ErrInvalidTransition) {
			t.Fatalf("AuthorizeChildCreate racing recovery error = %v", authorizeErr)
		}
	case <-authorizedRecoveryContext.Done():
		t.Fatalf("timed out waiting for authorization racing recovery: %v", authorizedRecoveryContext.Err())
	}

	// Re-lease the same action at a new epoch and race single-use child
	// authorization against the only safe pre-create terminal transition.
	if _, err := queue.Nack(ctx, execution.ActionNackRequest{
		Lease: executionlease.LeaseIdentity{
			ExecutionID: crossLoserFence.ActionID, RunnerID: crossLoserFence.RunnerID,
			Token: crossLoserFence.Token, Epoch: crossLoserFence.Epoch,
		},
		Reason:     execution.ActionQueueReason{Code: "CHILD_AUTH_RACE_REQUEUE", DetailHash: strings.Repeat("6", 64)},
		RetryAfter: time.Second,
	}); err != nil {
		t.Fatalf("requeue child authorization race action: %v", err)
	}
	execSQL(t, ctx, database, `
		UPDATE action_queue SET not_before = clock_timestamp() - interval '1 second' WHERE action_id = $1
	`, crossLoserFence.ActionID)
	raceAction, err := queue.Claim(ctx, execution.ActionClaimRequest{
		Scope: realRunnerScope(t, ctx, database, crossLoserFence.RunnerID), LeaseDuration: time.Minute,
	})
	if err != nil || raceAction.Execution.ExecutionID != crossLoserFence.ActionID {
		t.Fatalf("claim child authorization race action = %#v, %v", raceAction, err)
	}
	if _, err := queue.Start(ctx, raceAction.Execution.Fence()); err != nil {
		t.Fatalf("start child authorization race action: %v", err)
	}
	raceFence := credential.ActionFence{
		ActionID: raceAction.Execution.ExecutionID, RunnerID: raceAction.Execution.RunnerID,
		Token: raceAction.Execution.LeaseToken, Epoch: raceAction.Execution.LeaseEpoch,
	}
	const authorizationRaceRevocationID = "92000000-0000-4000-8000-000000000017"
	racePrepared, err := repository.Prepare(ctx, credential.PrepareRequest{
		RevocationID: authorizationRaceRevocationID, Fence: raceFence, Issuer: "vault-production",
		CredentialExpiresAt: time.Now().UTC().Add(5 * time.Minute),
	})
	if err != nil || !racePrepared.Created || racePrepared.Permit == nil {
		t.Fatalf("prepare child authorization race = %#v, %v", racePrepared, err)
	}
	type authorizationRaceResult struct {
		kind          string
		authorization credential.ChildCreateAuthorization
		revocation    credential.Revocation
		err           error
	}
	raceContext, cancelRace := context.WithTimeout(ctx, 5*time.Second)
	defer cancelRace()
	raceStart := make(chan struct{})
	raceResults := make(chan authorizationRaceResult, 2)
	go func() {
		<-raceStart
		authorization, authorizeErr := repository.AuthorizeChildCreate(raceContext, credential.AuthorizeChildCreateRequest{
			Permit: *racePrepared.Permit, Fence: raceFence,
		})
		raceResults <- authorizationRaceResult{kind: "authorize", authorization: authorization, err: authorizeErr}
	}()
	go func() {
		<-raceStart
		revocation, noCredentialErr := repository.RecordNoCredential(raceContext, credential.ActionTransitionRequest{
			RevocationID: authorizationRaceRevocationID, Fence: raceFence,
		})
		raceResults <- authorizationRaceResult{kind: "no_credential", revocation: revocation, err: noCredentialErr}
	}()
	close(raceStart)
	raceSuccesses := 0
	authorizationWon := false
	for range 2 {
		select {
		case result := <-raceResults:
			if result.err == nil {
				raceSuccesses++
				authorizationWon = result.kind == "authorize"
				continue
			}
			if !errors.Is(result.err, credential.ErrInvalidTransition) {
				t.Fatalf("child authorization/no-credential race %s error = %v", result.kind, result.err)
			}
		case <-raceContext.Done():
			t.Fatalf("timed out waiting for child authorization/no-credential race: %v", raceContext.Err())
		}
	}
	if raceSuccesses != 1 {
		t.Fatalf("child authorization/no-credential race successes = %d, want 1", raceSuccesses)
	}
	var raceStatus string
	var raceAuthorizedAt *time.Time
	if err := database.QueryRow(ctx, `
		SELECT status, child_create_authorized_at FROM credential_revocations WHERE revocation_id = $1
	`, authorizationRaceRevocationID).Scan(&raceStatus, &raceAuthorizedAt); err != nil {
		t.Fatalf("read child authorization race state: %v", err)
	}
	var raceAuditCount, raceOutboxCount int
	if err := database.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM audit_records
			 WHERE resource_id = $1 AND action IN (
				'credential.revocation.child_create_authorized', 'credential.revocation.no_credential'
			 )),
			(SELECT count(*) FROM outbox_events
			 WHERE aggregate_id = $1 AND event_type IN (
				'credential.revocation.child_create_authorized.v1', 'credential.revocation.no_credential.v1'
			 ))
	`, authorizationRaceRevocationID).Scan(&raceAuditCount, &raceOutboxCount); err != nil ||
		raceAuditCount != 1 || raceOutboxCount != 1 {
		t.Fatalf("child authorization race audit/outbox = %d/%d, %v", raceAuditCount, raceOutboxCount, err)
	}
	if authorizationWon {
		if raceStatus != string(credential.StatusPrepared) || raceAuthorizedAt == nil {
			t.Fatalf("authorized race state = %s/%v", raceStatus, raceAuthorizedAt)
		}
		raceAccessor, _ := credential.NewSensitiveReference([]byte("authorization-race-accessor"))
		if _, err := repository.RecordAnchor(ctx, credential.RecordAnchorRequest{
			RevocationID: authorizationRaceRevocationID, Fence: raceFence, Accessor: raceAccessor,
		}); err != nil {
			raceAccessor.Destroy()
			t.Fatalf("anchor authorization race cleanup: %v", err)
		}
		raceAccessor.Destroy()
		if _, err := repository.RequestRevocation(ctx, credential.ActionTransitionRequest{
			RevocationID: authorizationRaceRevocationID, Fence: raceFence,
		}); err != nil {
			t.Fatalf("request authorization race cleanup: %v", err)
		}
		raceClaims, err := repository.ClaimRevocations(ctx, credential.ClaimRevocationsRequest{
			WorkerID: "credential-authorization-race-cleanup", Limit: 1, LeaseDuration: 30 * time.Second,
		})
		if err != nil || len(raceClaims) != 1 || raceClaims[0].Revocation.ID != authorizationRaceRevocationID {
			t.Fatalf("claim authorization race cleanup = %#v, %v", raceClaims, err)
		}
		raceClaims[0].Accessor.Destroy()
		if _, err := repository.CompleteRevocation(ctx, credential.CompleteRevocationRequest{Fence: raceClaims[0].Fence}); err != nil {
			t.Fatalf("complete authorization race cleanup: %v", err)
		}
	} else if raceStatus != string(credential.StatusNoCredential) || raceAuthorizedAt != nil {
		t.Fatalf("no-credential race state = %s/%v", raceStatus, raceAuthorizedAt)
	}
	if _, err := queue.Nack(ctx, execution.ActionNackRequest{
		Lease:      raceAction.Execution.Fence(),
		Reason:     execution.ActionQueueReason{Code: "CHILD_AUTH_RACE_COMPLETE", DetailHash: strings.Repeat("5", 64)},
		RetryAfter: 30 * time.Minute,
	}); err != nil {
		t.Fatalf("drain child authorization race action: %v", err)
	}
	var delayedPrepareRows, delayedPrepareAudits, delayedPrepareOutbox int
	if err := database.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM credential_revocations WHERE revocation_id = $1),
			(SELECT count(*) FROM audit_records WHERE action = 'credential.revocation.prepared' AND resource_id = $1),
			(SELECT count(*) FROM outbox_events WHERE aggregate_id = $1 AND event_type = 'credential.revocation.prepared.v1')
	`, delayedPrepareID).Scan(&delayedPrepareRows, &delayedPrepareAudits, &delayedPrepareOutbox); err != nil ||
		delayedPrepareRows != 0 || delayedPrepareAudits != 0 || delayedPrepareOutbox != 0 {
		t.Fatalf("delayed Prepare rollback row/audit/outbox=%d/%d/%d, %v",
			delayedPrepareRows, delayedPrepareAudits, delayedPrepareOutbox, err)
	}
	expectSQLState(t, ctx, database, "55000", `
		INSERT INTO credential_revocations (
			revocation_id, tenant_id, workspace_id, environment_id,
			action_id, target_key, production, runner_id, action_lease_epoch, action_lease_token_sha256,
			issuer, connector_id, scope_permission, scope_resource, credential_expires_at,
			child_create_permit_sha256, status
		)
		SELECT '92000000-0000-4000-8000-000000000007', tenant_id, workspace_id, environment_id,
			action_id, target_key, production, runner_id, action_lease_epoch + 7000, action_lease_token_sha256,
			issuer, connector_id, scope_permission, scope_resource, statement_timestamp() + interval '5 minutes',
			repeat('7', 64), 'NO_CREDENTIAL'
		FROM credential_revocations WHERE revocation_id = $1
	`, revocationID)
	expectSQLState(t, ctx, database, "55000", `
		UPDATE credential_revocations
		SET status = 'ACTIVE', activated_at = statement_timestamp(),
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1
	`, revocationID)
	expectSQLState(t, ctx, database, "55000", `
		INSERT INTO credential_revocations (
			revocation_id, tenant_id, workspace_id, environment_id,
			action_id, target_key, production, runner_id, action_lease_epoch, action_lease_token_sha256,
			issuer, connector_id, scope_permission, scope_resource, credential_expires_at,
			child_create_permit_sha256, child_create_authorized_at, child_create_ttl_seconds
		)
		SELECT '92000000-0000-4000-8000-000000000015', tenant_id, workspace_id, environment_id,
			action_id, target_key, production, runner_id, action_lease_epoch + 7015, action_lease_token_sha256,
			issuer, connector_id, scope_permission, scope_resource, statement_timestamp() + interval '5 minutes',
			repeat('f', 64), statement_timestamp(), 30
		FROM credential_revocations WHERE revocation_id = $1
	`, revocationID)
	expectSQLState(t, ctx, database, "23514", `
		WITH clock AS (SELECT statement_timestamp() AS current_time)
		INSERT INTO credential_revocations (
			revocation_id, tenant_id, workspace_id, environment_id,
			action_id, target_key, production, runner_id, action_lease_epoch, action_lease_token_sha256,
			issuer, connector_id, scope_permission, scope_resource, credential_expires_at,
			child_create_permit_sha256,
			available_at, created_at, updated_at
		)
		SELECT '92000000-0000-4000-8000-000000000014', source.tenant_id, source.workspace_id, source.environment_id,
			source.action_id, source.target_key, source.production, source.runner_id,
			source.action_lease_epoch + 7004, source.action_lease_token_sha256,
			source.issuer, source.connector_id, source.scope_permission, source.scope_resource,
			clock.current_time + interval '15 minutes' + interval '1 microsecond', repeat('e', 64),
			clock.current_time, clock.current_time, clock.current_time
		FROM credential_revocations AS source CROSS JOIN clock
		WHERE source.revocation_id = $1
	`, revocationID)
	const noCredentialRevocationID = "92000000-0000-4000-8000-000000000008"
	execSQL(t, ctx, database, `
		INSERT INTO credential_revocations (
			revocation_id, tenant_id, workspace_id, environment_id,
			action_id, target_key, production, runner_id, action_lease_epoch, action_lease_token_sha256,
			issuer, connector_id, scope_permission, scope_resource, credential_expires_at,
			child_create_permit_sha256
		)
		SELECT $2, tenant_id, workspace_id, environment_id,
			action_id, target_key, production, runner_id, action_lease_epoch + 7001, action_lease_token_sha256,
			issuer, connector_id, scope_permission, scope_resource, statement_timestamp() + interval '5 minutes', repeat('8', 64)
		FROM credential_revocations WHERE revocation_id = $1
	`, revocationID, noCredentialRevocationID)
	expectSQLState(t, ctx, database, "23514", `
		UPDATE credential_revocations
		SET child_create_authorized_at = clock_timestamp(), child_create_ttl_seconds = 900,
			updated_at = clock_timestamp(), version = version + 1
		WHERE revocation_id = $1
	`, noCredentialRevocationID)
	expectSQLState(t, ctx, database, "55000", `
		UPDATE credential_revocations
		SET status = 'ANCHORED', updated_at = clock_timestamp(), version = version + 1
		WHERE revocation_id = $1
	`, noCredentialRevocationID)
	expectSQLState(t, ctx, database, "55000", `
		UPDATE credential_revocations
		SET child_create_permit_sha256 = repeat('a', 64),
			updated_at = clock_timestamp(), version = version + 1
		WHERE revocation_id = $1
	`, noCredentialRevocationID)
	execSQL(t, ctx, database, `
		UPDATE credential_revocations
		SET status = 'NO_CREDENTIAL', updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1
	`, noCredentialRevocationID)
	const authorizedNoCredentialGuardID = "92000000-0000-4000-8000-000000000018"
	execSQL(t, ctx, database, `
		WITH clock AS (SELECT clock_timestamp() AS current_time)
		INSERT INTO credential_revocations (
			revocation_id, tenant_id, workspace_id, environment_id,
			action_id, target_key, production, runner_id, action_lease_epoch, action_lease_token_sha256,
			issuer, connector_id, scope_permission, scope_resource, credential_expires_at,
			child_create_permit_sha256, available_at, created_at, updated_at
		)
		SELECT $2, source.tenant_id, source.workspace_id, source.environment_id,
			source.action_id, source.target_key, source.production, source.runner_id,
			source.action_lease_epoch + 7018, source.action_lease_token_sha256,
			source.issuer, source.connector_id, source.scope_permission, source.scope_resource,
			clock.current_time + interval '60 seconds', repeat('d', 64),
			clock.current_time, clock.current_time, clock.current_time
		FROM credential_revocations AS source CROSS JOIN clock WHERE source.revocation_id = $1;
		UPDATE credential_revocations
		SET child_create_authorized_at = created_at, child_create_ttl_seconds = 45,
			updated_at = clock_timestamp(), version = version + 1
		WHERE revocation_id = $2;
	`, revocationID, authorizedNoCredentialGuardID)
	expectSQLState(t, ctx, database, "55000", `
		UPDATE credential_revocations
		SET status = 'NO_CREDENTIAL', updated_at = clock_timestamp(), version = version + 1
		WHERE revocation_id = $1
	`, authorizedNoCredentialGuardID)
	for _, statement := range []string{
		`UPDATE credential_revocations SET updated_at = statement_timestamp(), version = version + 1 WHERE revocation_id = $1`,
		`UPDATE credential_revocations SET status = 'PREPARED', updated_at = statement_timestamp(), version = version + 1 WHERE revocation_id = $1`,
	} {
		expectSQLState(t, ctx, database, "55000", statement, noCredentialRevocationID)
	}

	insertPreparedRecoveryCandidate := func(id, permitDigest string, epochOffset int64, ageSeconds, ttlSeconds float64) {
		execSQL(t, ctx, database, `
			WITH clock AS (SELECT statement_timestamp() AS current_time)
			INSERT INTO credential_revocations (
				revocation_id, tenant_id, workspace_id, environment_id,
				action_id, target_key, production, runner_id, action_lease_epoch, action_lease_token_sha256,
				issuer, connector_id, scope_permission, scope_resource, credential_expires_at,
				child_create_permit_sha256,
				available_at, created_at, updated_at
			)
			SELECT $2, source.tenant_id, source.workspace_id, source.environment_id,
				source.action_id, source.target_key, source.production, source.runner_id,
				source.action_lease_epoch + $3, source.action_lease_token_sha256,
				source.issuer, source.connector_id, source.scope_permission, source.scope_resource,
				clock.current_time - make_interval(secs => $4::double precision) +
					make_interval(secs => $5::double precision),
				$6,
				clock.current_time - make_interval(secs => $4::double precision),
				clock.current_time - make_interval(secs => $4::double precision),
				clock.current_time - make_interval(secs => $4::double precision)
			FROM credential_revocations AS source CROSS JOIN clock
			WHERE source.revocation_id = $1
		`, revocationID, id, epochOffset, ageSeconds, ttlSeconds, permitDigest)
	}
	const (
		beforeRecoveryID   = "92000000-0000-4000-8000-000000000009"
		expiredRecoveryID  = "92000000-0000-4000-8000-000000000010"
		rollbackRecoveryID = "92000000-0000-4000-8000-000000000011"
	)
	// A two-minute absolute TTL proves recovery is keyed to the persisted
	// deadline rather than waiting for the maximum created_at+15m ceiling.
	defaultRecoveryPermit := strings.Repeat("9", 64)
	insertPreparedRecoveryCandidate(beforeRecoveryID, defaultRecoveryPermit, 8001, 2*60+30, 2*60)
	beforeRecovery, err := repository.RecoverPrepared(ctx, credential.RecoverPreparedRequest{Limit: 10})
	if err != nil || len(beforeRecovery) != 0 {
		t.Fatalf("real RecoverPrepared(before DB boundary) = %#v, %v", beforeRecovery, err)
	}
	insertPreparedRecoveryCandidate(expiredRecoveryID, defaultRecoveryPermit, 8002, 3*60, 2*60)
	type preparedRecoveryResult struct {
		revocations []credential.Revocation
		err         error
	}
	recoveryContext, cancelRecovery := context.WithTimeout(ctx, 5*time.Second)
	defer cancelRecovery()
	recoveryStart := make(chan struct{})
	recoveryResults := make(chan preparedRecoveryResult, 2)
	for range 2 {
		go func() {
			<-recoveryStart
			revocations, recoverErr := repository.RecoverPrepared(recoveryContext, credential.RecoverPreparedRequest{Limit: 1})
			recoveryResults <- preparedRecoveryResult{revocations: revocations, err: recoverErr}
		}()
	}
	close(recoveryStart)
	recoveryWinners := 0
	for range 2 {
		var result preparedRecoveryResult
		select {
		case result = <-recoveryResults:
		case <-recoveryContext.Done():
			t.Fatalf("timed out waiting for concurrent RecoverPrepared: %v", recoveryContext.Err())
		}
		if result.err != nil {
			t.Fatalf("real concurrent RecoverPrepared: %v", result.err)
		}
		if len(result.revocations) == 1 {
			if result.revocations[0].ID != expiredRecoveryID || result.revocations[0].Status != credential.StatusNoCredential {
				t.Fatalf("real RecoverPrepared winner = %#v", result.revocations)
			}
			recoveryWinners++
		}
	}
	if recoveryWinners != 1 {
		t.Fatalf("real concurrent RecoverPrepared winners = %d, want 1", recoveryWinners)
	}
	var recoveryAuditCount, recoveryOutboxCount int
	if err := database.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM audit_records WHERE action = 'credential.revocation.prepared_expired' AND resource_id = $1),
			(SELECT count(*) FROM outbox_events WHERE aggregate_id = $1 AND event_type = 'credential.revocation.prepared_expired.v1')
	`, expiredRecoveryID).Scan(&recoveryAuditCount, &recoveryOutboxCount); err != nil ||
		recoveryAuditCount != 1 || recoveryOutboxCount != 1 {
		t.Fatalf("prepared recovery audit/outbox = %d/%d, %v", recoveryAuditCount, recoveryOutboxCount, err)
	}

	insertPreparedRecoveryCandidate(rollbackRecoveryID, defaultRecoveryPermit, 8003, 3*60, 2*60)
	execSQL(t, ctx, database, `
		CREATE FUNCTION reject_test_prepared_recovery_outbox() RETURNS trigger AS $$
		BEGIN
			IF NEW.aggregate_id = '92000000-0000-4000-8000-000000000011'::uuid
			   AND NEW.event_type = 'credential.revocation.prepared_expired.v1' THEN
				RAISE EXCEPTION 'forced prepared recovery outbox failure';
			END IF;
			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER reject_test_prepared_recovery_outbox_insert
		BEFORE INSERT ON outbox_events
		FOR EACH ROW EXECUTE FUNCTION reject_test_prepared_recovery_outbox();
	`)
	if _, err := repository.RecoverPrepared(ctx, credential.RecoverPreparedRequest{Limit: 1}); !errors.Is(err, credential.ErrRevocationPersistence) {
		t.Fatalf("real RecoverPrepared(forced outbox rollback) error = %v", err)
	}
	var rollbackRecoveryStatus string
	var rollbackRecoveryVersion int64
	var rollbackRecoveryAudits, rollbackRecoveryOutbox int
	if err := database.QueryRow(ctx, `
		SELECT status, version,
			(SELECT count(*) FROM audit_records WHERE action = 'credential.revocation.prepared_expired' AND resource_id = $1),
			(SELECT count(*) FROM outbox_events WHERE aggregate_id = $1 AND event_type = 'credential.revocation.prepared_expired.v1')
		FROM credential_revocations WHERE revocation_id = $1
	`, rollbackRecoveryID).Scan(
		&rollbackRecoveryStatus, &rollbackRecoveryVersion, &rollbackRecoveryAudits, &rollbackRecoveryOutbox,
	); err != nil || rollbackRecoveryStatus != string(credential.StatusPrepared) || rollbackRecoveryVersion != 1 ||
		rollbackRecoveryAudits != 0 || rollbackRecoveryOutbox != 0 {
		t.Fatalf("prepared recovery rollback state = %s/v%d audit/outbox=%d/%d, %v",
			rollbackRecoveryStatus, rollbackRecoveryVersion, rollbackRecoveryAudits, rollbackRecoveryOutbox, err)
	}
	execSQL(t, ctx, database, `
		DROP TRIGGER reject_test_prepared_recovery_outbox_insert ON outbox_events;
		DROP FUNCTION reject_test_prepared_recovery_outbox();
	`)

	accessorValue := []byte("vault lease/accessor with spaces 租约")
	accessor, err := credential.NewSensitiveReference(accessorValue)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.RecordAnchor(ctx, credential.RecordAnchorRequest{
		RevocationID: revocationID, Fence: actionFence, Accessor: accessor,
	}); err != nil {
		t.Fatalf("real credential RecordAnchor: %v", err)
	}
	accessor.Destroy()
	if _, err := repository.Activate(ctx, credential.ActionTransitionRequest{RevocationID: revocationID, Fence: actionFence}); err != nil {
		t.Fatalf("real credential Activate: %v", err)
	}
	// A durable child-create permit may be prepared while LEASED, but it cannot
	// be consumed until Start has committed RUNNING. Race a subsequent cancel
	// intent against anchor persistence; either interleaving must converge on a
	// protected REVOCATION_PENDING record and never ACTIVE.
	nackSubmission := realActionSubmission(t, signer, now,
		"91000000-0000-4000-8000-000000000002", workspaceID, environmentID, serviceID,
		"payments-credential-cancel-recovery", '8')
	nackSubmission.Production = false
	if _, err := queue.Submit(ctx, nackSubmission); err != nil {
		t.Fatalf("submit credential Nack compatibility action: %v", err)
	}
	nackAction, err := queue.Claim(ctx, execution.ActionClaimRequest{
		Scope: realRunnerScope(t, ctx, database, "runner-postgres-2"), LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatalf("claim credential Nack compatibility action: %v", err)
	}
	nackFence := credential.ActionFence{
		ActionID: nackAction.Execution.ExecutionID, RunnerID: nackAction.Execution.RunnerID,
		Token: nackAction.Execution.LeaseToken, Epoch: nackAction.Execution.LeaseEpoch,
	}
	const nackRevocationID = "92000000-0000-4000-8000-000000000003"
	nackPrepared, err := repository.Prepare(ctx, credential.PrepareRequest{
		RevocationID: nackRevocationID, Fence: nackFence, Issuer: "vault-production",
		CredentialExpiresAt: now.Add(5 * time.Minute),
	})
	if err != nil || !nackPrepared.Created {
		t.Fatalf("prepare credential Nack compatibility revocation = %#v, %v", nackPrepared, err)
	}
	if nackPrepared.Permit == nil {
		t.Fatal("prepare credential Nack compatibility returned no permit")
	}
	if _, err := repository.AuthorizeChildCreate(ctx, credential.AuthorizeChildCreateRequest{
		Permit: *nackPrepared.Permit, Fence: nackFence,
	}); !errors.Is(err, credential.ErrStaleActionFence) {
		t.Fatalf("authorize credential before Start error = %v, want ErrStaleActionFence", err)
	}
	if _, err := queue.Start(ctx, nackAction.Execution.Fence()); err != nil {
		t.Fatalf("start credential cancellation race action: %v", err)
	}
	if _, err := repository.AuthorizeChildCreate(ctx, credential.AuthorizeChildCreateRequest{
		Permit: *nackPrepared.Permit, Fence: nackFence,
	}); err != nil {
		t.Fatalf("authorize credential after Start: %v", err)
	}
	if _, err := repository.Prepare(ctx, credential.PrepareRequest{
		RevocationID: nackRevocationID, Fence: actionFence, Issuer: "vault-production",
		CredentialExpiresAt: credentialExpiry,
	}); !errors.Is(err, credential.ErrIdempotencyConflict) {
		t.Fatalf("replay with candidate ID occupied by another action error = %v", err)
	}
	nackAccessor, _ := credential.NewSensitiveReference([]byte("cancel-recovery-accessor"))
	type cancelAnchorRaceResult struct {
		kind       string
		execution  executionlease.Execution
		revocation credential.Revocation
		err        error
	}
	cancelAnchorContext, cancelCancelAnchor := context.WithTimeout(ctx, 5*time.Second)
	defer cancelCancelAnchor()
	cancelAnchorStart := make(chan struct{})
	cancelAnchorResults := make(chan cancelAnchorRaceResult, 2)
	go func() {
		<-cancelAnchorStart
		cancelled, cancelErr := queue.Cancel(cancelAnchorContext, nackFence.ActionID)
		cancelAnchorResults <- cancelAnchorRaceResult{kind: "cancel", execution: cancelled, err: cancelErr}
	}()
	go func() {
		<-cancelAnchorStart
		anchored, anchorErr := repository.RecordAnchor(cancelAnchorContext, credential.RecordAnchorRequest{
			RevocationID: nackRevocationID, Fence: nackFence, Accessor: nackAccessor,
		})
		cancelAnchorResults <- cancelAnchorRaceResult{kind: "anchor", revocation: anchored, err: anchorErr}
	}()
	close(cancelAnchorStart)
	for range 2 {
		select {
		case result := <-cancelAnchorResults:
			if result.err != nil {
				t.Fatalf("cancel/anchor race %s error = %v", result.kind, result.err)
			}
			if result.kind == "cancel" && result.execution.Status != executionlease.StatusRunning {
				t.Fatalf("cancel/anchor race cancel result = %#v", result.execution)
			}
			if result.kind == "anchor" && result.revocation.Status != credential.StatusAnchored &&
				result.revocation.Status != credential.StatusRevocationPending {
				t.Fatalf("cancel/anchor race anchor result = %#v", result.revocation)
			}
		case <-cancelAnchorContext.Done():
			t.Fatalf("timed out waiting for cancel/anchor race: %v", cancelAnchorContext.Err())
		}
	}
	nackAnchored, err := repository.RecordAnchor(ctx, credential.RecordAnchorRequest{
		RevocationID: nackRevocationID, Fence: nackFence, Accessor: nackAccessor,
	})
	nackAccessor.Destroy()
	if err != nil || nackAnchored.Status != credential.StatusRevocationPending || !nackAnchored.AccessorPresent ||
		!nackAnchored.ActivatedAt.IsZero() {
		t.Fatalf("anchor credential after cancellation = %#v, %v", nackAnchored, err)
	}
	if recovered, err := repository.RequestRevocation(ctx, credential.ActionTransitionRequest{RevocationID: nackRevocationID}); err != nil || recovered.Status != credential.StatusRevocationPending {
		t.Fatalf("recover anchored revocation after cancellation: %v", err)
	}
	nackRecoveryClaims, err := repository.ClaimRevocations(ctx, credential.ClaimRevocationsRequest{
		WorkerID: "credential-nack-recovery-revoker", Limit: 1, LeaseDuration: 30 * time.Second,
	})
	if err != nil || len(nackRecoveryClaims) != 1 || nackRecoveryClaims[0].Revocation.ID != nackRevocationID {
		t.Fatalf("claim recovered cancelled revocation = %#v, %v", nackRecoveryClaims, err)
	}
	nackRecoveryClaims[0].Accessor.Destroy()
	if _, err := repository.CompleteRevocation(ctx, credential.CompleteRevocationRequest{Fence: nackRecoveryClaims[0].Fence}); err != nil {
		t.Fatalf("complete recovered cancelled revocation: %v", err)
	}
	if _, err := repository.CompleteRevocation(ctx, credential.CompleteRevocationRequest{Fence: nackRecoveryClaims[0].Fence}); err != nil {
		t.Fatalf("idempotent complete recovered cancelled revocation: %v", err)
	}
	for _, statement := range []string{
		`UPDATE credential_revocations SET updated_at = statement_timestamp(), version = version + 1 WHERE revocation_id = $1`,
		`UPDATE credential_revocations SET status = 'REVOCATION_PENDING', updated_at = statement_timestamp(), version = version + 1 WHERE revocation_id = $1`,
	} {
		expectSQLState(t, ctx, database, "55000", statement, nackRevocationID)
	}
	// Use a separate started action for the batch-decrypt rollback test; the
	// cancellation-race action intentionally remains RUNNING with termination
	// intent until its Runner observes the directive.
	batchSubmission := realActionSubmission(t, signer, now,
		"91000000-0000-4000-8000-000000000005", workspaceID, environmentID, serviceID,
		"payments-credential-batch-rollback", '9')
	batchSubmission.Production = false
	if _, err := queue.Submit(ctx, batchSubmission); err != nil {
		t.Fatalf("submit credential batch rollback action: %v", err)
	}
	batchAction, err := queue.Claim(ctx, execution.ActionClaimRequest{
		Scope: realRunnerScope(t, ctx, database, "runner-postgres-5"), LeaseDuration: time.Minute,
	})
	if err != nil || batchAction.Execution.ExecutionID != batchSubmission.Envelope.ActionID {
		t.Fatalf("claim credential batch rollback action = %#v, %v", batchAction, err)
	}
	batchFence := credential.ActionFence{
		ActionID: batchAction.Execution.ExecutionID, RunnerID: batchAction.Execution.RunnerID,
		Token: batchAction.Execution.LeaseToken, Epoch: batchAction.Execution.LeaseEpoch,
	}
	if _, err := queue.Start(ctx, batchAction.Execution.Fence()); err != nil {
		t.Fatalf("start credential batch rollback action: %v", err)
	}
	const batchRevocationID = "92000000-0000-4000-8000-000000000006"
	batchPrepared, err := repository.Prepare(ctx, credential.PrepareRequest{
		RevocationID: batchRevocationID, Fence: batchFence, Issuer: "vault-production",
		CredentialExpiresAt: credentialExpiry,
	})
	if err != nil || !batchPrepared.Created {
		t.Fatalf("prepare credential batch rollback revocation = %#v, %v", batchPrepared, err)
	}
	if batchPrepared.Permit == nil {
		t.Fatal("prepare credential batch rollback returned no permit")
	}
	if _, err := repository.AuthorizeChildCreate(ctx, credential.AuthorizeChildCreateRequest{
		Permit: *batchPrepared.Permit, Fence: batchFence,
	}); err != nil {
		t.Fatalf("authorize credential batch rollback revocation: %v", err)
	}
	batchAccessor, _ := credential.NewSensitiveReference([]byte("batch-corrupt-accessor"))
	if _, err := repository.RecordAnchor(ctx, credential.RecordAnchorRequest{
		RevocationID: batchRevocationID, Fence: batchFence, Accessor: batchAccessor,
	}); err != nil {
		t.Fatalf("anchor credential batch rollback revocation: %v", err)
	}
	batchAccessor.Destroy()
	if _, err := repository.RequestRevocation(ctx, credential.ActionTransitionRequest{
		RevocationID: batchRevocationID, Fence: batchFence,
	}); err != nil {
		t.Fatalf("request credential batch rollback revocation: %v", err)
	}
	var batchCiphertext []byte
	if err := database.QueryRow(ctx, `
		SELECT accessor_ciphertext FROM credential_revocations WHERE revocation_id = $1
	`, batchRevocationID).Scan(&batchCiphertext); err != nil {
		t.Fatalf("read batch rollback protected accessor: %v", err)
	}
	if _, err := repository.RequestRevocation(ctx, credential.ActionTransitionRequest{RevocationID: revocationID, Fence: actionFence}); err != nil {
		t.Fatalf("real credential RequestRevocation: %v", err)
	}
	var storedCiphertext, storedHMAC []byte
	var storedKeyID, storedActionFenceHash string
	if err := database.QueryRow(ctx, `
		SELECT accessor_ciphertext, accessor_hmac, encryption_key_id, action_lease_token_sha256
		FROM credential_revocations WHERE revocation_id = $1
	`, revocationID).Scan(&storedCiphertext, &storedHMAC, &storedKeyID, &storedActionFenceHash); err != nil {
		t.Fatalf("read protected credential reference: %v", err)
	}
	if len(storedCiphertext) < 29 || bytes.Contains(storedCiphertext, accessorValue) || len(storedHMAC) != 32 ||
		storedKeyID != "credential-integration-key-1" || storedActionFenceHash == actionFence.Token || len(storedActionFenceHash) != 64 {
		t.Fatalf("invalid protected credential storage shape: cipher=%d hmac=%d key=%q fence=%q",
			len(storedCiphertext), len(storedHMAC), storedKeyID, storedActionFenceHash)
	}
	expectSQLState(t, ctx, database, "55000", `
		UPDATE credential_revocations
		SET revocation_id = '92000000-0000-4000-8000-000000000098',
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1
	`, revocationID)
	expectSQLState(t, ctx, database, "23514", `
		UPDATE credential_revocations
		SET accessor_ciphertext = decode(repeat('aa', 4125), 'hex'),
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1
	`, revocationID)

	rebuiltPool, err := pgxpool.NewWithConfig(ctx, database.Config().Copy())
	if err != nil {
		t.Fatalf("rebuild PostgreSQL connection pool: %v", err)
	}
	defer rebuiltPool.Close()
	rebuilt, err := credentialpostgres.New(rebuiltPool, protector, credentialpostgres.Options{})
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := rebuilt.Get(ctx, revocationID)
	if err != nil || persisted.Status != credential.StatusRevocationPending || !persisted.AccessorPresent {
		t.Fatalf("rebuilt repository Get = %#v, %v", persisted, err)
	}

	// Corrupt the second legal pending candidate's AEAD body without changing
	// its schema shape. Claim must decrypt the whole batch before mutating rows.
	execSQL(t, ctx, database, `
		UPDATE credential_revocations
		SET available_at = statement_timestamp() - interval '2 minutes',
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1
	`, revocationID)
	execSQL(t, ctx, database, `
		UPDATE credential_revocations
		SET accessor_ciphertext = set_byte(
			accessor_ciphertext,
			octet_length(accessor_ciphertext) - 1,
			(get_byte(accessor_ciphertext, octet_length(accessor_ciphertext) - 1) + 1) % 256
		), updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1
	`, batchRevocationID)
	claimState := func(id string) string {
		var state string
		if err := database.QueryRow(ctx, `
			SELECT jsonb_build_object(
				'status', status, 'claim_epoch', claim_epoch, 'attempt', attempt,
				'version', version, 'updated_at', updated_at,
				'claimed_by', claimed_by, 'claim_token_sha256', claim_token_sha256,
				'claimed_at', claimed_at, 'claim_expires_at', claim_expires_at,
				'last_heartbeat_at', last_heartbeat_at
			)::text
			FROM credential_revocations WHERE revocation_id = $1
		`, id).Scan(&state); err != nil {
			t.Fatalf("read credential claim state %s: %v", id, err)
		}
		return state
	}
	beforeValidClaim := claimState(revocationID)
	beforeInvalidClaim := claimState(batchRevocationID)
	failedBatch, err := rebuilt.ClaimRevocations(ctx, credential.ClaimRevocationsRequest{
		WorkerID: "credential-batch-rollback-revoker", Limit: 2, LeaseDuration: 30 * time.Second,
	})
	if !errors.Is(err, credential.ErrReferenceProtection) || len(failedBatch) != 0 {
		t.Fatalf("real credential ClaimRevocations(corrupt batch) = %#v, %v", failedBatch, err)
	}
	if after := claimState(revocationID); after != beforeValidClaim {
		t.Fatalf("valid claim candidate mutated after batch decrypt failure: before=%s after=%s", beforeValidClaim, after)
	}
	if after := claimState(batchRevocationID); after != beforeInvalidClaim {
		t.Fatalf("invalid claim candidate mutated after batch decrypt failure: before=%s after=%s", beforeInvalidClaim, after)
	}
	execSQL(t, ctx, database, `
		UPDATE credential_revocations
		SET accessor_ciphertext = $2, available_at = statement_timestamp() + interval '1 day',
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1
	`, batchRevocationID, batchCiphertext)

	type claimResult struct {
		claims []credential.ClaimedRevocation
		err    error
	}
	claimContext, cancelCredentialClaims := context.WithTimeout(ctx, 5*time.Second)
	defer cancelCredentialClaims()
	start := make(chan struct{})
	results := make(chan claimResult, 2)
	for _, worker := range []string{"credential-revoker-1", "credential-revoker-2"} {
		worker := worker
		go func() {
			<-start
			claims, claimErr := rebuilt.ClaimRevocations(claimContext, credential.ClaimRevocationsRequest{
				WorkerID: worker, Limit: 1, LeaseDuration: 30 * time.Second,
			})
			results <- claimResult{claims: claims, err: claimErr}
		}()
	}
	close(start)
	var firstClaim credential.ClaimedRevocation
	winners := 0
	for range 2 {
		var result claimResult
		select {
		case result = <-results:
		case <-claimContext.Done():
			t.Fatalf("timed out waiting for concurrent credential claims: %v", claimContext.Err())
		}
		if result.err != nil {
			t.Fatalf("real concurrent credential claim: %v", result.err)
		}
		if len(result.claims) == 1 {
			firstClaim = result.claims[0]
			winners++
		}
	}
	if winners != 1 || firstClaim.Accessor == nil || string(firstClaim.Accessor.Bytes()) != string(accessorValue) {
		t.Fatalf("real credential claim winners=%d claim=%#v", winners, firstClaim)
	}
	expectSQLState(t, ctx, database, "23514", `
		UPDATE credential_revocations
		SET status = 'REVOKED',
			claimed_by = NULL, claim_token_sha256 = NULL, claimed_at = NULL,
			claim_expires_at = NULL, last_heartbeat_at = NULL,
			accessor_ciphertext = NULL, encryption_key_id = NULL,
			revoked_at = statement_timestamp(), updated_at = statement_timestamp(),
			version = version + 1
		WHERE revocation_id = $1
	`, revocationID)
	firstClaim.Accessor.Destroy()
	var storedClaimToken string
	if err := database.QueryRow(ctx, `SELECT claim_token_sha256 FROM credential_revocations WHERE revocation_id = $1`, revocationID).Scan(&storedClaimToken); err != nil {
		t.Fatalf("read credential claim token digest: %v", err)
	}
	if len(storedClaimToken) != 64 || storedClaimToken == firstClaim.Fence.Token {
		t.Fatalf("credential claim stored reusable token %q", storedClaimToken)
	}
	execSQL(t, ctx, database, `
		UPDATE credential_revocations
		SET claimed_at = statement_timestamp() - interval '3 minutes',
			last_heartbeat_at = statement_timestamp() - interval '2 minutes',
			claim_expires_at = statement_timestamp() - interval '1 minute',
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1
	`, revocationID)
	reclaimed, err := rebuilt.ClaimRevocations(ctx, credential.ClaimRevocationsRequest{
		WorkerID: "credential-revoker-3", Limit: 1, LeaseDuration: 30 * time.Second,
	})
	if err != nil || len(reclaimed) != 1 || reclaimed[0].Fence.Epoch != firstClaim.Fence.Epoch+1 ||
		reclaimed[0].Fence.Token == firstClaim.Fence.Token {
		t.Fatalf("real expired credential reclaim = %#v, %v", reclaimed, err)
	}
	reclaimed[0].Accessor.Destroy()
	if _, err := rebuilt.Heartbeat(ctx, credential.HeartbeatRequest{
		Fence: firstClaim.Fence, Extension: 30 * time.Second,
	}); !errors.Is(err, credential.ErrStaleClaim) {
		t.Fatalf("real credential Heartbeat(old fence) error = %v", err)
	}
	failureBody := []byte("vault upstream response body must never persist")
	execSQL(t, ctx, database, `
		CREATE FUNCTION reject_test_credential_failure_outbox() RETURNS trigger AS $$
		BEGIN
			IF NEW.event_type = 'credential.revocation.failed.v1' THEN
				RAISE EXCEPTION 'forced credential failure outbox rollback';
			END IF;
			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER reject_test_credential_failure_outbox_insert
		BEFORE INSERT ON outbox_events
		FOR EACH ROW EXECUTE FUNCTION reject_test_credential_failure_outbox();
	`)
	if _, err := rebuilt.RetryRevocation(ctx, credential.RetryRevocationRequest{
		Fence: reclaimed[0].Fence, Delay: 30 * time.Second,
		FailureCode: credential.FailureIssuerUnavailable, FailureDetail: failureBody,
	}); !errors.Is(err, credential.ErrRevocationPersistence) {
		t.Fatalf("real credential RetryRevocation(forced outbox rollback) error = %v", err)
	}
	var rollbackStatus string
	var rollbackFailureCount, rollbackAuditCount int
	if err := database.QueryRow(ctx, `
		SELECT status, failure_count,
			(SELECT count(*) FROM audit_records WHERE action = 'credential.revocation.failed' AND resource_id = $1)
		FROM credential_revocations WHERE revocation_id = $1
	`, revocationID).Scan(&rollbackStatus, &rollbackFailureCount, &rollbackAuditCount); err != nil {
		t.Fatal(err)
	}
	if rollbackStatus != string(credential.StatusRevoking) || rollbackFailureCount != 0 || rollbackAuditCount != 0 {
		t.Fatalf("first failure transaction was not atomic: status=%s failures=%d audits=%d",
			rollbackStatus, rollbackFailureCount, rollbackAuditCount)
	}
	execSQL(t, ctx, database, `
		DROP TRIGGER reject_test_credential_failure_outbox_insert ON outbox_events;
		DROP FUNCTION reject_test_credential_failure_outbox();
	`)
	beforeRetry := time.Now().UTC()
	retried, err := rebuilt.RetryRevocation(ctx, credential.RetryRevocationRequest{
		Fence: reclaimed[0].Fence, Delay: 30 * time.Second,
		FailureCode: credential.FailureIssuerUnavailable, FailureDetail: failureBody,
	})
	if err != nil || retried.Status != credential.StatusRevocationPending || retried.AvailableAt.Before(beforeRetry.Add(29*time.Second)) {
		t.Fatalf("real credential RetryRevocation = %#v, %v", retried, err)
	}
	var failureAuditCount, failureOutboxCount int
	if err := database.QueryRow(ctx, `SELECT count(*) FROM audit_records WHERE action = 'credential.revocation.failed' AND resource_id = $1`, revocationID).Scan(&failureAuditCount); err != nil {
		t.Fatal(err)
	}
	var failurePayload string
	if err := database.QueryRow(ctx, `
		SELECT count(*), min(payload::text)
		FROM outbox_events
		WHERE aggregate_id = $1 AND event_type = 'credential.revocation.failed.v1'
	`, revocationID).Scan(&failureOutboxCount, &failurePayload); err != nil {
		t.Fatal(err)
	}
	if failureAuditCount != 1 || failureOutboxCount != 1 || strings.Contains(failurePayload, string(failureBody)) ||
		strings.Contains(failurePayload, string(accessorValue)) || strings.Contains(failurePayload, reclaimed[0].Fence.Token) {
		t.Fatalf("unsafe first-failure audit/outbox: audit=%d outbox=%d payload=%s", failureAuditCount, failureOutboxCount, failurePayload)
	}
	execSQL(t, ctx, database, `
		UPDATE credential_revocations
		SET available_at = statement_timestamp() - interval '1 second',
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1
	`, revocationID)
	manualClaims, err := rebuilt.ClaimRevocations(ctx, credential.ClaimRevocationsRequest{
		WorkerID: "credential-revoker-4", Limit: 1, LeaseDuration: 30 * time.Second,
	})
	if err != nil || len(manualClaims) != 1 {
		t.Fatalf("real credential manual claim = %#v, %v", manualClaims, err)
	}
	manualClaims[0].Accessor.Destroy()
	manual, err := rebuilt.RequireManual(ctx, credential.RequireManualRequest{
		Fence: manualClaims[0].Fence, FailureCode: credential.FailurePermissionDenied, FailureDetail: []byte("permanent redacted failure"),
	})
	if err != nil || manual.Status != credential.StatusManualRequired {
		t.Fatalf("real credential RequireManual = %#v, %v", manual, err)
	}
	if _, err := rebuilt.RequeueManual(ctx, credential.RequeueManualRequest{
		RevocationID: revocationID, ActorSubject: "oidc:platform-admin-requeue",
	}); err != nil {
		t.Fatalf("real credential RequeueManual: %v", err)
	}
	execSQL(t, ctx, database, `
		UPDATE credential_revocations
		SET available_at = statement_timestamp() - interval '1 second',
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1
	`, revocationID)
	confirmationClaims, err := rebuilt.ClaimRevocations(ctx, credential.ClaimRevocationsRequest{
		WorkerID: "credential-revoker-5", Limit: 1, LeaseDuration: 30 * time.Second,
	})
	if err != nil || len(confirmationClaims) != 1 {
		t.Fatalf("real credential confirmation claim = %#v, %v", confirmationClaims, err)
	}
	confirmationClaims[0].Accessor.Destroy()
	if _, err := rebuilt.RequireManual(ctx, credential.RequireManualRequest{
		Fence: confirmationClaims[0].Fence, FailureCode: credential.FailurePermissionDenied, FailureDetail: []byte("external evidence required"),
	}); err != nil {
		t.Fatal(err)
	}
	evidenceHash := strings.Repeat("a", 64)
	firstConfirmation, err := rebuilt.SubmitExternalConfirmation(ctx, credential.ExternalConfirmationRequest{
		RevocationID: revocationID, Subject: "oidc:operator-1", EvidenceHash: evidenceHash,
	})
	if err != nil || firstConfirmation.Revocation.Status != credential.StatusManualRequired || len(firstConfirmation.Confirmations) != 1 {
		t.Fatalf("real first external confirmation = %#v, %v", firstConfirmation, err)
	}
	expectSQLState(t, ctx, database, "23514", `
		INSERT INTO credential_revocation_confirmations (
			revocation_id, subject, evidence_hash, platform_admin
		) VALUES ($1, 'oidc:direct-admin-without-parent-transition', $2, true)
	`, revocationID, evidenceHash)
	secondConfirmation, err := rebuilt.SubmitExternalConfirmation(ctx, credential.ExternalConfirmationRequest{
		RevocationID: revocationID, Subject: "oidc:platform-admin-1", EvidenceHash: evidenceHash, PlatformAdmin: true,
	})
	if err != nil || secondConfirmation.Revocation.Status != credential.StatusRevoked ||
		secondConfirmation.Revocation.AccessorPresent || len(secondConfirmation.Confirmations) != 2 {
		t.Fatalf("real second external confirmation = %#v, %v", secondConfirmation, err)
	}
	var finalCiphertext []byte
	var finalKeyID *string
	if err := database.QueryRow(ctx, `SELECT accessor_ciphertext, encryption_key_id FROM credential_revocations WHERE revocation_id = $1`, revocationID).
		Scan(&finalCiphertext, &finalKeyID); err != nil || finalCiphertext != nil || finalKeyID != nil {
		t.Fatalf("external confirmation retained decryptable accessor: cipher=%d key=%v err=%v", len(finalCiphertext), finalKeyID, err)
	}
	expectMigrationSQLState(t, ctx, database, filepath.Join(migrationDirectory, "000008_credential_revocations.down.sql"), "55000")

	// Explicit destructive cleanup is test-only and occurs after proving the
	// production down guard. It lets the shared harness continue through every
	// reverse migration without weakening the shipped migration.
	execSQL(t, ctx, database, `DROP TRIGGER credential_revocation_confirmations_no_mutation ON credential_revocation_confirmations`)
	execSQL(t, ctx, database, `DROP TRIGGER credential_revocation_confirmations_no_truncate ON credential_revocation_confirmations`)
	execSQL(t, ctx, database, `DELETE FROM credential_revocation_confirmations`)
	execSQL(t, ctx, database, `DROP TRIGGER credential_revocations_no_delete ON credential_revocations`)
	execSQL(t, ctx, database, `DROP TRIGGER credential_revocations_no_truncate ON credential_revocations`)
	execSQL(t, ctx, database, `DELETE FROM credential_revocations`)
	execSQL(t, ctx, database, `DELETE FROM outbox_events WHERE event_type LIKE 'credential.revocation.%'`)
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
	for _, runnerID := range []string{"runner-postgres-1", "runner-postgres-2", "runner-postgres-3", "runner-postgres-4", "runner-postgres-5", "runner-postgres-race", "runner-postgres-authorization"} {
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
	execSQL(t, ctx, database, `
		UPDATE action_queue
		SET lease_expires_at = statement_timestamp() - interval '1 second',
			last_heartbeat_at = statement_timestamp() - interval '2 seconds'
		WHERE action_id = $1
	`, third.Envelope.ActionID)
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
	go func(results chan<- realExecutionCallResult, done chan<- struct{}) {
		value, callErr := queue.Start(startContext, fence)
		results <- realExecutionCallResult{execution: value, err: callErr}
		close(done)
	}(startResults, startDone)
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
	operationHeartbeatResults := make(chan realHeartbeatCallResult, 1)
	operationHeartbeatDone := make(chan struct{})
	heartbeatContext, cancelHeartbeat := context.WithTimeout(ctx, 5*time.Second)
	defer cancelHeartbeat()
	go func(results chan<- realHeartbeatCallResult, done chan<- struct{}) {
		value, callErr := queue.Heartbeat(heartbeatContext, execution.ActionHeartbeatRequest{Lease: fence, Sequence: 1, Extension: 2 * time.Minute})
		results <- realHeartbeatCallResult{heartbeat: value, err: callErr}
		close(done)
	}(operationHeartbeatResults, operationHeartbeatDone)
	waitForTransactionWaiter(t, ctx, database, actionXID, operationHeartbeatDone, "Heartbeat action lock")
	updateContext, cancelUpdate := context.WithTimeout(ctx, 250*time.Millisecond)
	_, disableErr := database.Exec(updateContext, `
		UPDATE runner_registrations SET enabled = false, updated_at = statement_timestamp() WHERE runner_id = $1
	`, runnerID)
	updateContextErr := updateContext.Err()
	cancelUpdate()
	disableWasBlocked := disableErr != nil && errors.Is(updateContextErr, context.DeadlineExceeded)
	commitTestTransaction(t, ctx, actionTx, "release Heartbeat action row")
	heartbeatResult := awaitHeartbeatCall(t, operationHeartbeatResults, "Heartbeat holding registration lock")
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
	disabledHeartbeatResults := make(chan realHeartbeatCallResult, 1)
	disabledHeartbeatDone := make(chan struct{})
	expiredHeartbeatContext, cancelExpiredHeartbeat := context.WithTimeout(ctx, 5*time.Second)
	defer cancelExpiredHeartbeat()
	go func(results chan<- realHeartbeatCallResult, done chan<- struct{}) {
		value, callErr := queue.Heartbeat(expiredHeartbeatContext, execution.ActionHeartbeatRequest{Lease: fence, Sequence: 2, Extension: 3 * time.Minute})
		results <- realHeartbeatCallResult{heartbeat: value, err: callErr}
		close(done)
	}(disabledHeartbeatResults, disabledHeartbeatDone)
	waitForTransactionWaiter(t, ctx, database, disableXID, disabledHeartbeatDone, "Heartbeat registration lock")
	commitTestTransaction(t, ctx, disableTx, "commit disabled runner before Heartbeat")
	heartbeatResult = awaitHeartbeatCall(t, disabledHeartbeatResults, "Heartbeat after runner disable")
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
	go func(results chan<- realExecutionCallResult, done chan<- struct{}) {
		value, callErr := queue.Complete(completeContext, completion)
		results <- realExecutionCallResult{execution: value, err: callErr}
		close(done)
	}(completeResults, completeDone)
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
