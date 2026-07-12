package postgres_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
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
	"github.com/seaworld008/aiops-system/internal/runneridentity"
	runneridentitypostgres "github.com/seaworld008/aiops-system/internal/runneridentity/postgres"
	"github.com/seaworld008/aiops-system/internal/runneridentity/testpki"
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
	applyMigrationFile(t, ctx, database, filepath.Join(migrationDirectory, "000008_credential_revocations.up.sql"))
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

	firstClaim, err := repository.ClaimOutbox(ctx, store.ClaimOutboxRequest{
		EventType: "signal.ingested.v1", ConsumerID: "dispatcher-1", Limit: 1, Lease: time.Minute,
	})
	if err != nil || len(firstClaim) != 1 {
		t.Fatalf("real ClaimOutbox(first) = (%#v, %v)", firstClaim, err)
	}
	secondClaim, err := repository.ClaimOutbox(ctx, store.ClaimOutboxRequest{
		EventType: "incident.created.v1", ConsumerID: "dispatcher-2", Limit: 1, Lease: time.Minute,
	})
	if err != nil || len(secondClaim) != 1 || secondClaim[0].ID == firstClaim[0].ID {
		t.Fatalf("real ClaimOutbox(second) = (%#v, %v)", secondClaim, err)
	}
	execSQL(t, ctx, database, `
		UPDATE outbox_events
		SET claimed_at = statement_timestamp() - interval '2 minutes',
			claim_expires_at = statement_timestamp() - interval '1 minute'
		WHERE id = $1
	`, firstClaim[0].ID)
	if err := repository.AckOutbox(ctx, firstClaim[0].ID, "signal.ingested.v1", firstClaim[0].ClaimToken); !errors.Is(err, store.ErrStaleClaim) {
		t.Fatalf("real AckOutbox(expired) error = %v", err)
	}
	reclaimed, err := repository.ClaimOutbox(ctx, store.ClaimOutboxRequest{
		EventType: "signal.ingested.v1", ConsumerID: "dispatcher-3", Limit: 1, Lease: time.Minute,
	})
	if err != nil || len(reclaimed) != 1 || reclaimed[0].ID != firstClaim[0].ID || reclaimed[0].ClaimToken == firstClaim[0].ClaimToken {
		t.Fatalf("real ClaimOutbox(reclaimed) = (%#v, %v)", reclaimed, err)
	}
	if err := repository.AckOutbox(ctx, reclaimed[0].ID, "signal.ingested.v1", firstClaim[0].ClaimToken); !errors.Is(err, store.ErrStaleClaim) {
		t.Fatalf("real AckOutbox(old token) error = %v", err)
	}
	if err := repository.AckOutbox(ctx, reclaimed[0].ID, "signal.ingested.v1", reclaimed[0].ClaimToken); err != nil {
		t.Fatalf("real AckOutbox(current token) error = %v", err)
	}
	if err := repository.AckOutbox(ctx, reclaimed[0].ID, "signal.ingested.v1", reclaimed[0].ClaimToken); err != nil {
		t.Fatalf("real AckOutbox(idempotent retry) error = %v", err)
	}
	if err := repository.AckOutbox(ctx, reclaimed[0].ID, "signal.ingested.v1", "00000000-0000-0000-0000-000000000099"); !errors.Is(err, store.ErrStaleClaim) {
		t.Fatalf("real AckOutbox(wrong delivered token) error = %v", err)
	}
	if err := repository.AckOutbox(ctx, secondClaim[0].ID, "incident.created.v1", secondClaim[0].ClaimToken); err != nil {
		t.Fatalf("real AckOutbox(second) error = %v", err)
	}

	exerciseRealActionQueue(t, ctx, database, tenant1, workspace1, environment1, service1)
	exerciseRealCredentialRevocations(t, ctx, database, migrationDirectory,
		tenant1, tenant2, workspace1, workspace2, environment1, service1)
	expectSQLState(t, ctx, database, "P0001", `TRUNCATE runner_result_receipts`)
	expectMigrationSQLState(t, ctx, database, filepath.Join(migrationDirectory, "000007_runner_execution_hardening.down.sql"), "55000")
	execSQL(t, ctx, database, `DROP TRIGGER runner_result_receipts_no_truncate ON runner_result_receipts`)
	execSQL(t, ctx, database, `TRUNCATE runner_result_receipts`)
	// The production schema makes ActionQueue history immutable. The privileged
	// migration harness disables only the DELETE trigger after all guards have
	// been exercised so reverse-migration fixtures can be removed.
	execSQL(t, ctx, database, `ALTER TABLE action_queue DISABLE TRIGGER action_queue_no_delete`)
	execSQL(t, ctx, database, `DELETE FROM action_queue`)
	execSQL(t, ctx, database, `DROP TRIGGER IF EXISTS runner_certificates_no_delete ON runner_certificates`)
	execSQL(t, ctx, database, `DELETE FROM runner_certificates`)
	execSQL(t, ctx, database, `DELETE FROM runner_scope_bindings`)
	execSQL(t, ctx, database, `DELETE FROM runner_registrations`)

	// Apply the latest expand migration over the exercised legacy dataset so
	// the reverse pass only includes migrations that were actually installed.
	applyMigrationFile(t, ctx, database, filepath.Join(migrationDirectory, "000010_investigation_runtime.up.sql"))
	applyMigrationFile(t, ctx, database, filepath.Join(migrationDirectory, "000011_investigation_runner_ingress.up.sql"))
	outboxRoutingUp := filepath.Join(migrationDirectory, "000012_outbox_event_routing.up.sql")
	outboxRoutingDown := filepath.Join(migrationDirectory, "000012_outbox_event_routing.down.sql")
	applyMigrationFile(t, ctx, database, outboxRoutingUp)
	exerciseRealOutboxEventRouting(t, ctx, database, repository, tenant1, workspace1)
	var routingIndex, legacyDispatchIndex *string
	applyMigrationFile(t, ctx, database, outboxRoutingDown)
	if err := database.QueryRow(ctx, `
		SELECT to_regclass('public.outbox_event_routing_idx')::text,
		       to_regclass('public.outbox_dispatch_idx')::text
	`).Scan(&routingIndex, &legacyDispatchIndex); err != nil {
		t.Fatalf("check outbox routing down migration: %v", err)
	}
	if routingIndex != nil || legacyDispatchIndex == nil {
		t.Fatalf("outbox routing down indexes = new:%v legacy:%v", routingIndex, legacyDispatchIndex)
	}
	var routingFixtureCount int
	if err := database.QueryRow(ctx, `
		SELECT count(*) FROM outbox_events WHERE claimed_by LIKE 'routing-dispatcher-%'
		   OR aggregate_id::text LIKE '83000000-0000-4000-8000-%'
		   OR aggregate_id::text LIKE '84000000-0000-4000-8000-%'
	`).Scan(&routingFixtureCount); err != nil || routingFixtureCount != 7 {
		t.Fatalf("outbox routing down retained rows = %d, error = %v", routingFixtureCount, err)
	}
	applyMigrationFile(t, ctx, database, outboxRoutingUp)
	applyMigrations(t, ctx, database, migrationDirectory, ".down.sql", true)
	var relationName *string
	if err := database.QueryRow(ctx, `SELECT to_regclass('public.tenants')::text`).Scan(&relationName); err != nil {
		t.Fatalf("check down migration: %v", err)
	}
	if relationName != nil {
		t.Fatalf("tenants table remains after down migration: %s", *relationName)
	}
}

func exerciseRealOutboxEventRouting(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	repository *postgresstore.Store,
	tenantID, workspaceID string,
) {
	t.Helper()
	for index := 1; index <= 3; index++ {
		outboxID := fmt.Sprintf("82000000-0000-4000-8000-%012d", index)
		aggregateID := fmt.Sprintf("83000000-0000-4000-8000-%012d", index)
		execSQL(t, ctx, database, `
			INSERT INTO outbox_events (
				id, tenant_id, workspace_id, aggregate_type, aggregate_id, aggregate_version,
				event_type, payload, created_at, available_at
			) VALUES ($1, $2, $3, 'INCIDENT', $4, 1, 'incident.created.v1',
				jsonb_build_object('incident_id', $4::text),
				statement_timestamp() - interval '10 minutes', statement_timestamp() - interval '10 minutes')
		`, outboxID, tenantID, workspaceID, aggregateID)
		credentialOutboxID := fmt.Sprintf("85000000-0000-4000-8000-%012d", index)
		credentialAggregateID := fmt.Sprintf("84000000-0000-4000-8000-%012d", index)
		execSQL(t, ctx, database, `
			INSERT INTO outbox_events (
				id, tenant_id, workspace_id, aggregate_type, aggregate_id, aggregate_version,
				event_type, payload, created_at, available_at
			) VALUES ($1, $2, $3, 'CREDENTIAL_REVOCATION', $4, 1,
				'credential.revocation.requested.v1', jsonb_build_object('revocation_id', $4::text),
				statement_timestamp() - interval '20 minutes', statement_timestamp() - interval '20 minutes')
		`, credentialOutboxID, tenantID, workspaceID, credentialAggregateID)
	}
	const (
		signalOutboxID = "82000000-0000-4000-8000-000000000004"
		signalID       = "83000000-0000-4000-8000-000000000004"
	)
	execSQL(t, ctx, database, `
		INSERT INTO outbox_events (
			id, tenant_id, workspace_id, aggregate_type, aggregate_id, aggregate_version,
			event_type, payload, created_at, available_at
		) VALUES ($1, $2, $3, 'SIGNAL', $4, 1, 'signal.ingested.v1',
			jsonb_build_object('signal_id', $4::text), statement_timestamp(), statement_timestamp())
	`, signalOutboxID, tenantID, workspaceID, signalID)

	signals, err := repository.ClaimOutbox(ctx, store.ClaimOutboxRequest{
		EventType: "signal.ingested.v1", ConsumerID: "routing-dispatcher-signal", Limit: 1, Lease: time.Minute,
	})
	if err != nil || len(signals) != 1 || signals[0].ID != signalOutboxID || signals[0].Type != "signal.ingested.v1" {
		t.Fatalf("real exact signal ClaimOutbox() = (%#v, %v)", signals, err)
	}
	incidents, err := repository.ClaimOutbox(ctx, store.ClaimOutboxRequest{
		EventType: "incident.created.v1", ConsumerID: "routing-dispatcher-incident", Limit: 1, Lease: time.Minute,
	})
	if err != nil || len(incidents) != 1 || incidents[0].Type != "incident.created.v1" {
		t.Fatalf("real independent incident ClaimOutbox() = (%#v, %v)", incidents, err)
	}
	credentials, err := repository.ClaimOutbox(ctx, store.ClaimOutboxRequest{
		EventType: "credential.revocation.requested.v1", ConsumerID: "routing-dispatcher-credential", Limit: 3, Lease: time.Minute,
	})
	if err != nil || len(credentials) != 3 {
		t.Fatalf("real independent credential ClaimOutbox() = (%#v, %v)", credentials, err)
	}
	if err := repository.AckOutbox(ctx, signals[0].ID, "incident.created.v1", signals[0].ClaimToken); !errors.Is(err, store.ErrStaleClaim) {
		t.Fatalf("real AckOutbox(wrong type) error = %v", err)
	}
	if err := repository.RetryOutbox(
		ctx, signals[0].ID, "incident.created.v1", signals[0].ClaimToken,
		time.Now().UTC().Add(time.Minute), "wrong_handler",
	); !errors.Is(err, store.ErrStaleClaim) {
		t.Fatalf("real RetryOutbox(wrong type) error = %v", err)
	}
	if err := repository.AckOutbox(ctx, signals[0].ID, "signal.ingested.v1", signals[0].ClaimToken); err != nil {
		t.Fatalf("real AckOutbox(signal) error = %v", err)
	}
	if err := repository.AckOutbox(ctx, incidents[0].ID, "incident.created.v1", incidents[0].ClaimToken); err != nil {
		t.Fatalf("real AckOutbox(incident) error = %v", err)
	}
	for _, event := range credentials {
		if event.Type != "credential.revocation.requested.v1" {
			t.Fatalf("real credential dispatcher claimed %q", event.Type)
		}
		if err := repository.AckOutbox(ctx, event.ID, "credential.revocation.requested.v1", event.ClaimToken); err != nil {
			t.Fatalf("real AckOutbox(credential) error = %v", err)
		}
	}
}

func exerciseRealCredentialRevocations(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	migrationDirectory, tenantID, otherTenantID, workspaceID, otherWorkspaceID, environmentID, serviceID string,
) {
	t.Helper()
	const otherEnvironmentID = "25000000-0000-4000-8000-000000000002"
	execSQL(t, ctx, database, `
		INSERT INTO environments (id, tenant_id, workspace_id, name, kind)
		VALUES ($1, $2, $3, 'management-cross-scope', 'DEV')
	`, otherEnvironmentID, otherTenantID, otherWorkspaceID)
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
	expectDeferredConstraintAtCommit(t, ctx, database, "credential_revocations_action_marker_shape", `
		INSERT INTO credential_revocations (
			revocation_id, tenant_id, workspace_id, environment_id,
			action_id, target_key, production, runner_id, action_lease_epoch, action_lease_token_sha256,
			issuer, issuer_revision, action_type, connector_id, scope_permission, scope_resource,
			credential_ttl_seconds, credential_expires_at, child_create_permit_sha256
		)
		SELECT '92000000-0000-4000-8000-000000000021', action.runner_tenant_id,
			action.runner_workspace_id, action.runner_environment_id,
			action.action_id, action.target_key, action.production, action.runner_id, action.lease_epoch,
			action.lease_token_sha256, 'vault-production', 'rev-1', action.envelope ->> 'action_type',
			'tampered-connector', action.envelope #>> '{credential_scope,permission}',
			action.envelope #>> '{credential_scope,resource}',
			(action.envelope #>> '{credential_scope,ttl_seconds}')::integer,
			statement_timestamp() + interval '5 minutes', repeat('b', 64)
		FROM action_queue AS action
		WHERE action.action_id = $1 AND action.runner_id = $2 AND action.lease_epoch = $3
		  AND action.lease_token_sha256 = $4;

		UPDATE action_queue
		SET credential_expected = true,
			credential_lease_epoch = lease_epoch,
			updated_at = statement_timestamp()
		WHERE action_id = $1 AND runner_id = $2 AND lease_epoch = $3
		  AND lease_token_sha256 = $4;
	`, actionFence.ActionID, actionFence.RunnerID, actionFence.Epoch,
		credential.SHA256Hex([]byte(actionFence.Token)))
	authorizationBoundaryNow := time.Now().UTC()
	authorizationBoundarySubmission := realActionSubmission(t, signer, authorizationBoundaryNow.Add(-25*time.Minute),
		"91000000-0000-4000-8000-000000000023", workspaceID, environmentID, serviceID,
		"payments-credential-authorization-boundary", 'a')
	authorizationBoundarySubmission.Production = false
	if _, err := queue.Submit(ctx, authorizationBoundarySubmission); err != nil {
		t.Fatalf("submit credential authorization-boundary action: %v", err)
	}
	authorizationBoundaryAction, err := queue.Claim(ctx, execution.ActionClaimRequest{
		Scope: realRunnerScope(t, ctx, database, "runner-postgres-2"), LeaseDuration: time.Minute,
	})
	if err != nil || authorizationBoundaryAction.Execution.ExecutionID != authorizationBoundarySubmission.Envelope.ActionID {
		t.Fatalf("claim credential authorization-boundary action = %#v, %v", authorizationBoundaryAction, err)
	}
	authorizationBoundaryFence := credential.ActionFence{
		ActionID: authorizationBoundaryAction.Execution.ExecutionID,
		RunnerID: authorizationBoundaryAction.Execution.RunnerID,
		Token:    authorizationBoundaryAction.Execution.LeaseToken,
		Epoch:    authorizationBoundaryAction.Execution.LeaseEpoch,
	}
	expectDeferredConstraintAtCommit(t, ctx, database, "credential_revocations_action_marker_shape", `
		INSERT INTO credential_revocations (
			revocation_id, tenant_id, workspace_id, environment_id,
			action_id, target_key, production, runner_id, action_lease_epoch, action_lease_token_sha256,
			issuer, issuer_revision, action_type, connector_id, scope_permission, scope_resource,
			credential_ttl_seconds, credential_expires_at, child_create_permit_sha256
		)
		SELECT '92000000-0000-4000-8000-000000000023', action.runner_tenant_id,
			action.runner_workspace_id, action.runner_environment_id,
			action.action_id, action.target_key, action.production, action.runner_id, action.lease_epoch,
			action.lease_token_sha256, 'vault-production', 'rev-1', action.envelope ->> 'action_type',
			action.envelope #>> '{credential_scope,connector_id}',
			action.envelope #>> '{credential_scope,permission}',
			action.envelope #>> '{credential_scope,resource}',
			(action.envelope #>> '{credential_scope,ttl_seconds}')::integer,
			action.authorization_expires_at + interval '1 microsecond', repeat('d', 64)
		FROM action_queue AS action
		WHERE action.action_id = $1 AND action.runner_id = $2 AND action.lease_epoch = $3
		  AND action.lease_token_sha256 = $4;

		UPDATE action_queue
		SET credential_expected = true,
			credential_lease_epoch = lease_epoch,
			updated_at = statement_timestamp()
		WHERE action_id = $1 AND runner_id = $2 AND lease_epoch = $3
		  AND lease_token_sha256 = $4;
	`, authorizationBoundaryFence.ActionID, authorizationBoundaryFence.RunnerID,
		authorizationBoundaryFence.Epoch, credential.SHA256Hex([]byte(authorizationBoundaryFence.Token)))
	if _, err := queue.Nack(ctx, execution.ActionNackRequest{
		Lease: authorizationBoundaryAction.Execution.Fence(),
		Reason: execution.ActionQueueReason{
			Code: "CREDENTIAL_AUTHORIZATION_BOUNDARY_VERIFIED", DetailHash: strings.Repeat("a", 64),
		},
		RetryAfter: time.Second,
	}); err != nil {
		t.Fatalf("release credential authorization-boundary action: %v", err)
	}
	if cancelled, err := queue.Cancel(ctx, authorizationBoundaryAction.Execution.ExecutionID); err != nil ||
		cancelled.Status != executionlease.StatusCancelled {
		t.Fatalf("cancel credential authorization-boundary action = %#v, %v", cancelled, err)
	}
	expectSQLConstraint(t, ctx, database, "55000", "credential_revocations_created_at_guard", `
		WITH frozen_clock AS (SELECT clock_timestamp() AS current_time)
		INSERT INTO credential_revocations (
			revocation_id, tenant_id, workspace_id, environment_id,
			action_id, target_key, production, runner_id, action_lease_epoch, action_lease_token_sha256,
			issuer, issuer_revision, action_type, connector_id, scope_permission, scope_resource,
			credential_ttl_seconds, credential_expires_at, child_create_permit_sha256,
			created_at, updated_at
		)
		SELECT '92000000-0000-4000-8000-000000000022', action.runner_tenant_id,
			action.runner_workspace_id, action.runner_environment_id,
			action.action_id, action.target_key, action.production, action.runner_id, action.lease_epoch,
			action.lease_token_sha256, 'vault-production', 'rev-1', action.envelope ->> 'action_type',
			action.envelope #>> '{credential_scope,connector_id}',
			action.envelope #>> '{credential_scope,permission}',
			action.envelope #>> '{credential_scope,resource}',
			(action.envelope #>> '{credential_scope,ttl_seconds}')::integer,
			frozen_clock.current_time + interval '2 minutes', repeat('c', 64),
			frozen_clock.current_time + interval '1 minute', frozen_clock.current_time + interval '1 minute'
		FROM action_queue AS action CROSS JOIN frozen_clock
		WHERE action.action_id = $1 AND action.runner_id = $2 AND action.lease_epoch = $3
		  AND action.lease_token_sha256 = $4
	`, actionFence.ActionID, actionFence.RunnerID, actionFence.Epoch,
		credential.SHA256Hex([]byte(actionFence.Token)))
	expectSQLState(t, ctx, database, "23503", `
		INSERT INTO credential_revocations (
			revocation_id, tenant_id, workspace_id, environment_id,
			action_id, target_key, production, runner_id, action_lease_epoch, action_lease_token_sha256,
			issuer, issuer_revision, action_type, connector_id, scope_permission, scope_resource,
			credential_ttl_seconds, credential_expires_at, child_create_permit_sha256
		) VALUES (
			'92000000-0000-4000-8000-000000000099', $1, $2, $3,
			$4, $5, false, $6, $7, $8,
			'vault-production', 'rev-1', $9, $10, $11, $12, $13,
			statement_timestamp() + interval '5 minutes', repeat('a', 64)
		)
	`, otherTenantID, otherWorkspaceID, environmentID, actionFence.ActionID, submission.TargetKey,
		actionFence.RunnerID, actionFence.Epoch, credential.SHA256Hex([]byte(actionFence.Token)),
		string(submission.Envelope.ActionType), submission.Envelope.CredentialScope.ConnectorID,
		submission.Envelope.CredentialScope.Permission, submission.Envelope.CredentialScope.Resource,
		submission.Envelope.CredentialScope.TTLSeconds)
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
	signedTTL := time.Duration(submission.Envelope.CredentialScope.TTLSeconds) * time.Second
	if _, err := repository.Prepare(ctx, credential.PrepareRequest{
		RevocationID: "92000000-0000-4000-8000-000000000020", Fence: actionFence,
		Issuer: "vault-production", IssuerRevision: "rev-1",
		CredentialExpiresAt: time.Now().UTC().Add(signedTTL + time.Minute),
	}); !errors.Is(err, credential.ErrInvalidRevocationRequest) {
		t.Fatalf("real Prepare(expiry beyond signed TTL) error = %v", err)
	}
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
				RevocationID: candidateID, Fence: actionFence, Issuer: "vault-production", IssuerRevision: "rev-1",
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
			call.result.Revocation.ActionType != string(submission.Envelope.ActionType) ||
			call.result.Revocation.CredentialTTLSeconds != int32(submission.Envelope.CredentialScope.TTLSeconds) ||
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
		RevocationID: revocationID, Fence: actionFence, Issuer: "vault-production", IssuerRevision: "rev-1",
		CredentialExpiresAt: credentialExpiry,
	})
	if err != nil || idempotent.Created || idempotent.Permit != nil || idempotent.Revocation.ID != revocationID ||
		idempotent.Revocation.IssuerRevision != "rev-1" {
		t.Fatalf("real credential Prepare(idempotent) = %#v, %v", idempotent, err)
	}
	if _, err := repository.Prepare(ctx, credential.PrepareRequest{
		RevocationID: revocationID, Fence: actionFence, Issuer: "vault-production", IssuerRevision: "rev-2",
		CredentialExpiresAt: credentialExpiry,
	}); !errors.Is(err, credential.ErrIdempotencyConflict) {
		t.Fatalf("real credential Prepare(changed issuer revision) error = %v", err)
	}
	canonicalReplay, err := repository.Prepare(ctx, credential.PrepareRequest{
		RevocationID: "92000000-0000-4000-8000-000000000004", Fence: actionFence,
		Issuer: "vault-production", IssuerRevision: "rev-1", CredentialExpiresAt: credentialExpiry,
	})
	if err != nil || canonicalReplay.Created || canonicalReplay.Revocation.ID != revocationID {
		t.Fatalf("real credential Prepare(canonical replay) = %#v, %v", canonicalReplay, err)
	}
	conflicting := credential.PrepareRequest{
		RevocationID: "92000000-0000-4000-8000-000000000005", Fence: actionFence,
		Issuer: "different-issuer", IssuerRevision: "rev-1", CredentialExpiresAt: credentialExpiry,
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
				RevocationID: crossCandidateID, Fence: crossFence, Issuer: "vault-production", IssuerRevision: "rev-1",
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
		RevocationID: delayedPrepareID, Fence: crossLoserFence, Issuer: "vault-production", IssuerRevision: "rev-1",
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
	authorizedExpiredFence := claimStartedCredentialAction(t, ctx, database, queue, signer,
		"91000000-0000-4000-8000-000000000007", workspaceID, environmentID, serviceID,
		"payments-authorized-expired-recovery", 'c', "runner-postgres-fixture-authorized-expired")
	authorizedExpiredCreatedAt := time.Now().UTC().Add(-2 * time.Minute)
	insertPreparedCredentialForAction(t, ctx, database, authorizedExpiredFence,
		authorizedExpiredRecoveryID, authorizedExpiredPermitDigest,
		authorizedExpiredCreatedAt, authorizedExpiredCreatedAt.Add(50*time.Second),
		authorizedExpiredCreatedAt.Add(5*time.Second), 10*time.Second)
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
			Fence:  authorizedExpiredFence,
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

	// Use a dedicated LEASED action to exercise the only safe pre-start retry:
	// Nack it, re-lease it at a new epoch, then Start before racing single-use
	// child authorization against the terminal NO_CREDENTIAL transition. The
	// cross-unique actions above are already RUNNING and must never be Nacked.
	raceSubmission := realActionSubmission(t, signer, now,
		"91000000-0000-4000-8000-000000000006", workspaceID, environmentID, serviceID,
		"payments-credential-authorization-race", '6')
	raceSubmission.Production = false
	if _, err := queue.Submit(ctx, raceSubmission); err != nil {
		t.Fatalf("submit child authorization race action: %v", err)
	}
	initialRaceAction, err := queue.Claim(ctx, execution.ActionClaimRequest{
		Scope: realRunnerScope(t, ctx, database, "runner-postgres-authorization"), LeaseDuration: time.Minute,
	})
	if err != nil || initialRaceAction.Execution.ExecutionID != raceSubmission.Envelope.ActionID {
		t.Fatalf("claim initial child authorization race action = %#v, %v", initialRaceAction, err)
	}
	if _, err := queue.Nack(ctx, execution.ActionNackRequest{
		Lease:      initialRaceAction.Execution.Fence(),
		Reason:     execution.ActionQueueReason{Code: "CHILD_AUTH_RACE_REQUEUE", DetailHash: strings.Repeat("6", 64)},
		RetryAfter: time.Second,
	}); err != nil {
		t.Fatalf("requeue child authorization race action: %v", err)
	}
	execSQL(t, ctx, database, `
		UPDATE action_queue SET not_before = clock_timestamp() - interval '1 second' WHERE action_id = $1
	`, initialRaceAction.Execution.ExecutionID)
	raceAction, err := queue.Claim(ctx, execution.ActionClaimRequest{
		Scope: realRunnerScope(t, ctx, database, initialRaceAction.Execution.RunnerID), LeaseDuration: time.Minute,
	})
	if err != nil || raceAction.Execution.ExecutionID != initialRaceAction.Execution.ExecutionID ||
		raceAction.Execution.LeaseEpoch != initialRaceAction.Execution.LeaseEpoch+1 {
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
		RevocationID: authorizationRaceRevocationID, Fence: raceFence, Issuer: "vault-production", IssuerRevision: "rev-1",
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
	cancelledRaceAction, err := queue.Cancel(ctx, raceAction.Execution.ExecutionID)
	if err != nil || cancelledRaceAction.Status != executionlease.StatusRunning ||
		cancelledRaceAction.CancelRequestedAt.IsZero() {
		t.Fatalf("request child authorization race termination = %#v, %v", cancelledRaceAction, err)
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
			issuer, issuer_revision, action_type, connector_id, scope_permission, scope_resource,
			credential_ttl_seconds, credential_expires_at, child_create_permit_sha256, status
		)
		SELECT '92000000-0000-4000-8000-000000000007', tenant_id, workspace_id, environment_id,
			action_id, target_key, production, runner_id, action_lease_epoch + 7000, action_lease_token_sha256,
			issuer, issuer_revision, action_type, connector_id, scope_permission, scope_resource,
			credential_ttl_seconds, statement_timestamp() + interval '5 minutes',
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
		UPDATE credential_revocations
		SET issuer_revision = 'rev-2', updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1
	`, revocationID)
	expectSQLState(t, ctx, database, "55000", `
		UPDATE credential_revocations
		SET action_type = 'KUBERNETES_SCALE', updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1
	`, revocationID)
	expectSQLState(t, ctx, database, "55000", `
		UPDATE credential_revocations
		SET credential_ttl_seconds = credential_ttl_seconds - 1,
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1
	`, revocationID)
	expectSQLState(t, ctx, database, "55000", `
		INSERT INTO credential_revocations (
			revocation_id, tenant_id, workspace_id, environment_id,
			action_id, target_key, production, runner_id, action_lease_epoch, action_lease_token_sha256,
			issuer, issuer_revision, action_type, connector_id, scope_permission, scope_resource,
			credential_ttl_seconds, credential_expires_at,
			child_create_permit_sha256, child_create_authorized_at, child_create_ttl_seconds
		)
		SELECT '92000000-0000-4000-8000-000000000015', tenant_id, workspace_id, environment_id,
			action_id, target_key, production, runner_id, action_lease_epoch + 7015, action_lease_token_sha256,
			issuer, issuer_revision, action_type, connector_id, scope_permission, scope_resource,
			credential_ttl_seconds, statement_timestamp() + interval '5 minutes',
			repeat('f', 64), statement_timestamp(), 30
		FROM credential_revocations WHERE revocation_id = $1
	`, revocationID)
	expectSQLState(t, ctx, database, "23514", `
		WITH clock AS (SELECT statement_timestamp() AS current_time)
		INSERT INTO credential_revocations (
			revocation_id, tenant_id, workspace_id, environment_id,
			action_id, target_key, production, runner_id, action_lease_epoch, action_lease_token_sha256,
			issuer, issuer_revision, action_type, connector_id, scope_permission, scope_resource,
			credential_ttl_seconds, credential_expires_at,
			child_create_permit_sha256,
			available_at, created_at, updated_at
		)
		SELECT '92000000-0000-4000-8000-000000000014', source.tenant_id, source.workspace_id, source.environment_id,
			source.action_id, source.target_key, source.production, source.runner_id,
			source.action_lease_epoch + 7004, source.action_lease_token_sha256,
			source.issuer, source.issuer_revision, source.action_type, source.connector_id, source.scope_permission, source.scope_resource,
			source.credential_ttl_seconds,
			clock.current_time + interval '15 minutes' + interval '1 microsecond', repeat('e', 64),
			clock.current_time, clock.current_time, clock.current_time
		FROM credential_revocations AS source CROSS JOIN clock
		WHERE source.revocation_id = $1
	`, revocationID)
	// This row is otherwise a valid PREPARED insert. Its implicit transaction
	// must fail only when the initially-deferred exact action-marker proof runs
	// at COMMIT; a caller cannot persist an unanchored credential intent.
	expectDeferredConstraintAtCommit(t, ctx, database, "credential_revocations_action_marker_shape", `
		INSERT INTO credential_revocations (
			revocation_id, tenant_id, workspace_id, environment_id,
			action_id, target_key, production, runner_id, action_lease_epoch, action_lease_token_sha256,
			issuer, issuer_revision, action_type, connector_id, scope_permission, scope_resource,
			credential_ttl_seconds, credential_expires_at,
			child_create_permit_sha256
		)
		SELECT '92000000-0000-4000-8000-000000000019', tenant_id, workspace_id, environment_id,
			action_id, target_key, production, runner_id, action_lease_epoch + 7019, action_lease_token_sha256,
			issuer, issuer_revision, action_type, connector_id, scope_permission, scope_resource,
			credential_ttl_seconds,
			statement_timestamp() + interval '5 minutes', repeat('1', 64)
		FROM credential_revocations WHERE revocation_id = $1
	`, revocationID)
	const noCredentialRevocationID = "92000000-0000-4000-8000-000000000008"
	noCredentialFence := claimStartedCredentialAction(t, ctx, database, queue, signer,
		"91000000-0000-4000-8000-000000000008", workspaceID, environmentID, serviceID,
		"payments-no-credential-guard", 'd', "runner-postgres-fixture-no-credential")
	noCredentialCreatedAt := time.Now().UTC()
	insertPreparedCredentialForAction(t, ctx, database, noCredentialFence,
		noCredentialRevocationID, strings.Repeat("8", 64),
		noCredentialCreatedAt, noCredentialCreatedAt.Add(5*time.Minute), time.Time{}, 0)
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
	authorizedNoCredentialFence := claimStartedCredentialAction(t, ctx, database, queue, signer,
		"91000000-0000-4000-8000-000000000009", workspaceID, environmentID, serviceID,
		"payments-authorized-no-credential-guard", 'e', "runner-postgres-fixture-authorized-guard")
	authorizedNoCredentialCreatedAt := time.Now().UTC()
	insertPreparedCredentialForAction(t, ctx, database, authorizedNoCredentialFence,
		authorizedNoCredentialGuardID, strings.Repeat("d", 64),
		authorizedNoCredentialCreatedAt, authorizedNoCredentialCreatedAt.Add(time.Minute),
		authorizedNoCredentialCreatedAt, 45*time.Second)
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

	insertPreparedRecoveryCandidate := func(
		id, actionID, deployment string,
		digestByte byte,
		runnerID, permitDigest string,
		age, ttl time.Duration,
	) {
		fence := claimStartedCredentialAction(t, ctx, database, queue, signer,
			actionID, workspaceID, environmentID, serviceID, deployment, digestByte, runnerID)
		createdAt := time.Now().UTC().Add(-age)
		insertPreparedCredentialForAction(t, ctx, database, fence, id, permitDigest,
			createdAt, createdAt.Add(ttl), time.Time{}, 0)
	}
	const (
		beforeRecoveryID   = "92000000-0000-4000-8000-000000000009"
		expiredRecoveryID  = "92000000-0000-4000-8000-000000000010"
		rollbackRecoveryID = "92000000-0000-4000-8000-000000000011"
	)
	// A two-minute absolute TTL proves recovery is keyed to the persisted
	// deadline rather than waiting for the maximum created_at+15m ceiling.
	defaultRecoveryPermit := strings.Repeat("9", 64)
	insertPreparedRecoveryCandidate(beforeRecoveryID,
		"91000000-0000-4000-8000-000000000010", "payments-before-recovery-boundary", '0',
		"runner-postgres-fixture-recovery-before", defaultRecoveryPermit, 150*time.Second, 2*time.Minute)
	beforeRecovery, err := repository.RecoverPrepared(ctx, credential.RecoverPreparedRequest{Limit: 10})
	if err != nil || len(beforeRecovery) != 0 {
		t.Fatalf("real RecoverPrepared(before DB boundary) = %#v, %v", beforeRecovery, err)
	}
	insertPreparedRecoveryCandidate(expiredRecoveryID,
		"91000000-0000-4000-8000-000000000011", "payments-expired-recovery-boundary", '1',
		"runner-postgres-fixture-recovery-expired", defaultRecoveryPermit, 3*time.Minute, 2*time.Minute)
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

	insertPreparedRecoveryCandidate(rollbackRecoveryID,
		"91000000-0000-4000-8000-000000000012", "payments-recovery-rollback", '2',
		"runner-postgres-fixture-recovery-rollback", defaultRecoveryPermit, 3*time.Minute, 2*time.Minute)
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
		RevocationID: nackRevocationID, Fence: nackFence, Issuer: "vault-production", IssuerRevision: "rev-1",
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
		RevocationID: nackRevocationID, Fence: actionFence, Issuer: "vault-production", IssuerRevision: "rev-1",
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
		RevocationID: batchRevocationID, Fence: batchFence, Issuer: "vault-production", IssuerRevision: "rev-1",
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

	// Corrupt one legal pending candidate's AEAD body without changing its
	// schema shape. Claim must quarantine it without starving valid work.
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
		), available_at = statement_timestamp() - interval '3 minutes',
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1
	`, batchRevocationID)
	isolatedBatch, err := rebuilt.ClaimRevocations(ctx, credential.ClaimRevocationsRequest{
		WorkerID: "credential-batch-rollback-revoker", Limit: 2, LeaseDuration: 30 * time.Second,
	})
	if err != nil || len(isolatedBatch) != 1 || isolatedBatch[0].Revocation.ID != revocationID ||
		isolatedBatch[0].Accessor == nil || string(isolatedBatch[0].Accessor.Bytes()) != string(accessorValue) {
		t.Fatalf("real credential ClaimRevocations(poison isolation) = %#v, %v", isolatedBatch, err)
	}
	var poisonStatus, poisonFailureCode string
	var poisonClaimedBy, poisonClaimToken *string
	var poisonCiphertextPresent bool
	if err := database.QueryRow(ctx, `
		SELECT status, failure_code, claimed_by, claim_token_sha256, accessor_ciphertext IS NOT NULL
		FROM credential_revocations WHERE revocation_id = $1
	`, batchRevocationID).Scan(
		&poisonStatus, &poisonFailureCode, &poisonClaimedBy, &poisonClaimToken, &poisonCiphertextPresent,
	); err != nil {
		t.Fatalf("read quarantined credential reference: %v", err)
	}
	if poisonStatus != string(credential.StatusManualRequired) || poisonFailureCode != string(credential.FailureInvalidReference) ||
		poisonClaimedBy != nil || poisonClaimToken != nil || !poisonCiphertextPresent {
		t.Fatalf("invalid poison quarantine: status=%s failure=%s worker=%v token=%v ciphertext=%v",
			poisonStatus, poisonFailureCode, poisonClaimedBy, poisonClaimToken, poisonCiphertextPresent)
	}
	isolatedBatch[0].Accessor.Destroy()
	execSQL(t, ctx, database, `
		UPDATE credential_revocations
		SET claimed_at = statement_timestamp() - interval '3 minutes',
			last_heartbeat_at = statement_timestamp() - interval '2 minutes',
			claim_expires_at = statement_timestamp() - interval '1 minute',
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1
	`, revocationID)

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
	}); !errors.Is(err, credential.ErrRevocationPersistence) ||
		!strings.Contains(err.Error(), "insert credential revocation outbox event") {
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
	var beforeManagementManualAt, beforeManagementUpdatedAt time.Time
	var beforeManagementVersion int64
	if err := database.QueryRow(ctx, `
		SELECT manual_required_at, updated_at, version
		FROM credential_revocations WHERE revocation_id = $1
	`, revocationID).Scan(&beforeManagementManualAt, &beforeManagementUpdatedAt, &beforeManagementVersion); err != nil {
		t.Fatal(err)
	}
	expectSQLState(t, ctx, database, "55000", `
		UPDATE credential_revocations
		SET manual_required_at = updated_at + interval '1 day', version = version + 1
		WHERE revocation_id = $1 AND status = 'MANUAL_REQUIRED'
	`, revocationID)
	expectSQLState(t, ctx, database, "55000", `
		UPDATE credential_revocations
		SET manual_required_at = manual_required_at + interval '1 microsecond',
			updated_at = updated_at + interval '1 second', version = version + 1
		WHERE revocation_id = $1 AND status = 'MANUAL_REQUIRED'
	`, revocationID)
	expectSQLState(t, ctx, database, "23514", `
		UPDATE credential_revocations
		SET updated_at = 'infinity'::timestamptz, version = version + 1
		WHERE revocation_id = $1 AND status = 'MANUAL_REQUIRED'
	`, revocationID)
	var afterManagementManualAt, afterManagementUpdatedAt time.Time
	var afterManagementVersion int64
	if err := database.QueryRow(ctx, `
		SELECT manual_required_at, updated_at, version
		FROM credential_revocations WHERE revocation_id = $1
	`, revocationID).Scan(&afterManagementManualAt, &afterManagementUpdatedAt, &afterManagementVersion); err != nil ||
		!afterManagementManualAt.Equal(beforeManagementManualAt) ||
		!afterManagementUpdatedAt.Equal(beforeManagementUpdatedAt) || afterManagementVersion != beforeManagementVersion {
		t.Fatalf("management lifecycle time attacks did not roll back: manual=%s/%s updated=%s/%s version=%d/%d, %v",
			afterManagementManualAt, beforeManagementManualAt, afterManagementUpdatedAt, beforeManagementUpdatedAt,
			afterManagementVersion, beforeManagementVersion, err)
	}
	managementStore, err := credentialpostgres.NewManagement(database)
	if err != nil {
		t.Fatalf("create credential management store: %v", err)
	}
	managementScope := credential.ManagementScope{WorkspaceID: workspaceID, EnvironmentID: environmentID}
	managementAdmin := credential.ManagementActor{Subject: "oidc:platform-admin-requeue", PlatformAdmin: true}
	managedRecord, err := managementStore.GetManagement(ctx, credential.ManagementGetRequest{
		Scope: managementScope, Actor: credential.ManagementActor{Subject: "oidc:management-reader"}, RevocationID: revocationID,
	})
	if err != nil || managedRecord.Status != credential.StatusManualRequired || !managedRecord.AccessorPresent ||
		managedRecord.FailureCount == 0 || managedRecord.FailureDetailSHA256 == "" {
		t.Fatalf("real management GetManagement = %#v, %v", managedRecord, err)
	}
	managedJSON, err := json.Marshal(managedRecord)
	if err != nil {
		t.Fatal(err)
	}
	for _, canary := range []string{
		string(accessorValue), storedKeyID, actionFence.Token, firstClaim.Fence.Token,
		"accessor_ciphertext", "accessor_hmac", "encryption_key_id", "claim_token_sha256", "claimed_by", "runner_id",
	} {
		if canary != "" && bytes.Contains(managedJSON, []byte(canary)) {
			t.Fatalf("management record leaked credential/claim canary %q: %s", canary, managedJSON)
		}
	}
	if _, err := managementStore.GetManagement(ctx, credential.ManagementGetRequest{
		Scope: credential.ManagementScope{WorkspaceID: otherWorkspaceID, EnvironmentID: otherEnvironmentID},
		Actor: credential.ManagementActor{Subject: "oidc:cross-scope-reader"}, RevocationID: revocationID,
	}); !errors.Is(err, credential.ErrRevocationNotFound) {
		t.Fatalf("real management cross-scope GetManagement error = %v", err)
	}
	firstPage, err := managementStore.ListManagement(ctx, credential.ManagementListRequest{
		Scope: managementScope, Actor: credential.ManagementActor{Subject: "oidc:management-list-reader"},
		Status: credential.StatusManualRequired, Limit: 1,
	})
	if err != nil || len(firstPage.Items) != 1 || firstPage.Next == nil {
		t.Fatalf("real management first keyset page = %#v, %v", firstPage, err)
	}
	secondPage, err := managementStore.ListManagement(ctx, credential.ManagementListRequest{
		Scope: managementScope, Actor: credential.ManagementActor{Subject: "oidc:management-list-reader"},
		Status: credential.StatusManualRequired, Limit: 1, After: firstPage.Next,
	})
	if err != nil || len(secondPage.Items) != 1 || secondPage.Items[0].ID == firstPage.Items[0].ID {
		t.Fatalf("real management second keyset page = %#v, %v", secondPage, err)
	}
	var managementIndexDefinition string
	if err := database.QueryRow(ctx, `
		SELECT indexdef FROM pg_indexes
		WHERE schemaname = current_schema() AND indexname = 'credential_revocations_management_idx'
	`).Scan(&managementIndexDefinition); err != nil ||
		!strings.Contains(managementIndexDefinition, "(workspace_id, environment_id, status, created_at DESC, revocation_id DESC)") {
		t.Fatalf("credential management keyset index = %q, %v", managementIndexDefinition, err)
	}
	if _, err := managementStore.RequeueManagement(ctx, credential.ManagementRequeueRequest{
		Scope: credential.ManagementScope{WorkspaceID: otherWorkspaceID, EnvironmentID: otherEnvironmentID},
		Actor: managementAdmin, RevocationID: revocationID,
	}); !errors.Is(err, credential.ErrRevocationNotFound) {
		t.Fatalf("real management cross-scope RequeueManagement error = %v", err)
	}
	execSQL(t, ctx, database, `
		CREATE FUNCTION reject_test_management_requeue_outbox() RETURNS trigger AS $$
		BEGIN
			IF NEW.event_type = 'credential.revocation.requeued.v1' THEN
				RAISE EXCEPTION 'forced management requeue outbox failure';
			END IF;
			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER reject_test_management_requeue_outbox_insert
		BEFORE INSERT ON outbox_events
		FOR EACH ROW EXECUTE FUNCTION reject_test_management_requeue_outbox();
	`)
	if _, err := managementStore.RequeueManagement(ctx, credential.ManagementRequeueRequest{
		Scope: managementScope, Actor: managementAdmin, RevocationID: revocationID,
	}); !errors.Is(err, credential.ErrRevocationPersistence) {
		t.Fatalf("real management RequeueManagement(forced outbox rollback) error = %v", err)
	}
	var managementRollbackStatus string
	var managementRollbackAudit, managementRollbackOutbox int
	if err := database.QueryRow(ctx, `
		SELECT status,
			(SELECT count(*) FROM audit_records WHERE action = 'credential.revocation.requeued' AND resource_id = $1),
			(SELECT count(*) FROM outbox_events WHERE aggregate_id = $1 AND event_type = 'credential.revocation.requeued.v1')
		FROM credential_revocations WHERE revocation_id = $1
	`, revocationID).Scan(&managementRollbackStatus, &managementRollbackAudit, &managementRollbackOutbox); err != nil ||
		managementRollbackStatus != string(credential.StatusManualRequired) || managementRollbackAudit != 0 || managementRollbackOutbox != 0 {
		t.Fatalf("management requeue rollback state=%s audit/outbox=%d/%d, %v",
			managementRollbackStatus, managementRollbackAudit, managementRollbackOutbox, err)
	}
	execSQL(t, ctx, database, `
		DROP TRIGGER reject_test_management_requeue_outbox_insert ON outbox_events;
		DROP FUNCTION reject_test_management_requeue_outbox();
	`)
	type managementRequeueResult struct {
		record credential.ManagementRecord
		err    error
	}
	requeueContext, cancelManagementRequeues := context.WithTimeout(ctx, 5*time.Second)
	defer cancelManagementRequeues()
	requeueStart := make(chan struct{})
	requeueResults := make(chan managementRequeueResult, 2)
	for range 2 {
		go func() {
			<-requeueStart
			record, requeueErr := managementStore.RequeueManagement(requeueContext, credential.ManagementRequeueRequest{
				Scope: managementScope, Actor: managementAdmin, RevocationID: revocationID,
			})
			requeueResults <- managementRequeueResult{record: record, err: requeueErr}
		}()
	}
	close(requeueStart)
	var requeueVersion int64
	for range 2 {
		var result managementRequeueResult
		select {
		case result = <-requeueResults:
		case <-requeueContext.Done():
			t.Fatalf("timed out waiting for concurrent management requeues: %v", requeueContext.Err())
		}
		if result.err != nil || result.record.Status != credential.StatusRevocationPending {
			t.Fatalf("real concurrent management RequeueManagement = %#v, %v", result.record, result.err)
		}
		if requeueVersion == 0 {
			requeueVersion = result.record.Version
		} else if result.record.Version != requeueVersion {
			t.Fatalf("concurrent management requeues returned versions %d and %d", requeueVersion, result.record.Version)
		}
	}
	var managementRequeueOutbox, managementRequeueReplayAudit int
	if err := database.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM outbox_events WHERE aggregate_id = $1 AND event_type = 'credential.revocation.requeued.v1'),
			(SELECT count(*) FROM audit_records WHERE resource_id = $1 AND action = 'credential.revocation.requeue_replayed')
	`, revocationID).Scan(&managementRequeueOutbox, &managementRequeueReplayAudit); err != nil ||
		managementRequeueOutbox != 1 || managementRequeueReplayAudit != 1 {
		t.Fatalf("management requeue event/replay audit=%d/%d, %v",
			managementRequeueOutbox, managementRequeueReplayAudit, err)
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
	mismatchedEvidenceHash := strings.Repeat("b", 64)
	var beforeDirectAttackVersion int64
	if err := database.QueryRow(ctx, `SELECT version FROM credential_revocations WHERE revocation_id = $1`, revocationID).
		Scan(&beforeDirectAttackVersion); err != nil {
		t.Fatal(err)
	}
	expectSQLState(t, ctx, database, "23514", `
		UPDATE credential_revocations
		SET evidence_hash = $2, updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1 AND status = 'MANUAL_REQUIRED' AND evidence_hash IS NULL;
		INSERT INTO credential_revocation_confirmations (
			revocation_id, subject, evidence_hash, platform_admin
		) VALUES ($1, 'oidc:direct-non-admin-1', $2, false);
		INSERT INTO credential_revocation_confirmations (
			revocation_id, subject, evidence_hash, platform_admin
		) VALUES ($1, 'oidc:direct-non-admin-2', $2, false);
	`, revocationID, evidenceHash)
	expectSQLState(t, ctx, database, "23514", `
		UPDATE credential_revocations
		SET evidence_hash = $2, updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1 AND status = 'MANUAL_REQUIRED' AND evidence_hash IS NULL;
		INSERT INTO credential_revocation_confirmations (
			revocation_id, subject, evidence_hash, platform_admin
		) VALUES ($1, 'oidc:direct-hash-a', $2, false);
		INSERT INTO credential_revocation_confirmations (
			revocation_id, subject, evidence_hash, platform_admin
		) VALUES ($1, 'oidc:direct-hash-b-admin', $3, true);
	`, revocationID, evidenceHash, mismatchedEvidenceHash)
	var afterDirectAttackEvidence *string
	var afterDirectAttackVersion int64
	var afterDirectAttackConfirmations int
	if err := database.QueryRow(ctx, `
		SELECT revocation.evidence_hash, revocation.version,
			(SELECT count(*) FROM credential_revocation_confirmations AS confirmation
			 WHERE confirmation.revocation_id = revocation.revocation_id)
		FROM credential_revocations AS revocation
		WHERE revocation.revocation_id = $1
	`, revocationID).Scan(
		&afterDirectAttackEvidence, &afterDirectAttackVersion, &afterDirectAttackConfirmations,
	); err != nil || afterDirectAttackEvidence != nil || afterDirectAttackVersion != beforeDirectAttackVersion ||
		afterDirectAttackConfirmations != 0 {
		t.Fatalf("direct confirmation attacks did not roll back: evidence=%v version=%d/%d confirmations=%d, %v",
			afterDirectAttackEvidence, afterDirectAttackVersion, beforeDirectAttackVersion,
			afterDirectAttackConfirmations, err)
	}
	expectSQLState(t, ctx, database, "23514", `
		INSERT INTO credential_revocation_confirmations (
			revocation_id, subject, evidence_hash, platform_admin
		) VALUES ($1, 'oidc:direct-admin-without-parent-transition', $2, true)
	`, revocationID, evidenceHash)
	type managementConfirmationResult struct {
		record credential.ManagementRecord
		err    error
	}
	confirmationContext, cancelManagementConfirmations := context.WithTimeout(ctx, 5*time.Second)
	defer cancelManagementConfirmations()
	confirmationStart := make(chan struct{})
	confirmationResults := make(chan managementConfirmationResult, 2)
	for _, actor := range []credential.ManagementActor{
		{Subject: "oidc:operator-1"},
		{Subject: "oidc:platform-admin-1", PlatformAdmin: true},
	} {
		actor := actor
		go func() {
			<-confirmationStart
			record, confirmErr := managementStore.ConfirmManagement(confirmationContext, credential.ManagementConfirmationRequest{
				Scope: managementScope, Actor: actor, RevocationID: revocationID, EvidenceHash: evidenceHash,
			})
			confirmationResults <- managementConfirmationResult{record: record, err: confirmErr}
		}()
	}
	close(confirmationStart)
	var secondConfirmation credential.ManagementRecord
	manualConfirmationWinners := 0
	revokedConfirmationWinners := 0
	for range 2 {
		var result managementConfirmationResult
		select {
		case result = <-confirmationResults:
		case <-confirmationContext.Done():
			t.Fatalf("timed out waiting for concurrent management confirmations: %v", confirmationContext.Err())
		}
		if result.err != nil {
			t.Fatalf("real concurrent management confirmation = %#v, %v", result.record, result.err)
		}
		switch result.record.Status {
		case credential.StatusManualRequired:
			if result.record.ConfirmationCount != 1 {
				t.Fatalf("real first concurrent management confirmation = %#v", result.record)
			}
			manualConfirmationWinners++
		case credential.StatusRevoked:
			if result.record.AccessorPresent || result.record.ConfirmationCount != 2 ||
				!result.record.PlatformAdminConfirmed {
				t.Fatalf("real second concurrent management confirmation = %#v", result.record)
			}
			secondConfirmation = result.record
			revokedConfirmationWinners++
		default:
			t.Fatalf("unexpected concurrent management confirmation = %#v", result.record)
		}
	}
	if manualConfirmationWinners != 1 || revokedConfirmationWinners != 1 {
		t.Fatalf("concurrent management confirmation winners manual/revoked=%d/%d",
			manualConfirmationWinners, revokedConfirmationWinners)
	}
	replayedConfirmation, err := managementStore.ConfirmManagement(ctx, credential.ManagementConfirmationRequest{
		Scope: managementScope, Actor: credential.ManagementActor{Subject: "oidc:platform-admin-1", PlatformAdmin: true},
		RevocationID: revocationID, EvidenceHash: evidenceHash,
	})
	if err != nil || replayedConfirmation.Status != credential.StatusRevoked ||
		replayedConfirmation.Version != secondConfirmation.Version {
		t.Fatalf("real external confirmation replay = %#v, %v", replayedConfirmation, err)
	}
	var finalCiphertext []byte
	var finalKeyID *string
	if err := database.QueryRow(ctx, `SELECT accessor_ciphertext, encryption_key_id FROM credential_revocations WHERE revocation_id = $1`, revocationID).
		Scan(&finalCiphertext, &finalKeyID); err != nil || finalCiphertext != nil || finalKeyID != nil {
		t.Fatalf("external confirmation retained decryptable accessor: cipher=%d key=%v err=%v", len(finalCiphertext), finalKeyID, err)
	}
	var confirmationOutbox, confirmationReplayAudit int
	var confirmationPayload string
	if err := database.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM outbox_events WHERE aggregate_id = $1 AND event_type = 'credential.revocation.externally_confirmed.v1'),
			(SELECT count(*) FROM audit_records WHERE resource_id = $1 AND action = 'credential.revocation.confirmation_replayed'),
			(SELECT payload::text FROM outbox_events WHERE aggregate_id = $1 AND event_type = 'credential.revocation.externally_confirmed.v1')
	`, revocationID).Scan(&confirmationOutbox, &confirmationReplayAudit, &confirmationPayload); err != nil ||
		confirmationOutbox != 1 || confirmationReplayAudit != 1 || strings.Contains(confirmationPayload, string(accessorValue)) ||
		strings.Contains(confirmationPayload, storedKeyID) || strings.Contains(confirmationPayload, actionFence.Token) ||
		strings.Contains(confirmationPayload, firstClaim.Fence.Token) {
		t.Fatalf("unsafe management confirmation outbox/replay audit=%d/%d payload=%s, %v",
			confirmationOutbox, confirmationReplayAudit, confirmationPayload, err)
	}
	expectMigrationSQLState(t, ctx, database, filepath.Join(migrationDirectory, "000008_credential_revocations.down.sql"), "55000")

	// Drain all M2-only state before the coordinated M3 cutover. Triggers are
	// disabled only for this privileged migration harness and immediately
	// restored so M3 exercises the shipped immutable-history defenses.
	execSQL(t, ctx, database, `ALTER TABLE credential_revocation_confirmations DISABLE TRIGGER credential_revocation_confirmations_no_mutation`)
	execSQL(t, ctx, database, `DELETE FROM credential_revocation_confirmations`)
	execSQL(t, ctx, database, `ALTER TABLE credential_revocation_confirmations ENABLE TRIGGER credential_revocation_confirmations_no_mutation`)
	execSQL(t, ctx, database, `ALTER TABLE credential_revocations DISABLE TRIGGER credential_revocations_no_delete`)
	execSQL(t, ctx, database, `DELETE FROM credential_revocations`)
	execSQL(t, ctx, database, `ALTER TABLE credential_revocations ENABLE TRIGGER credential_revocations_no_delete`)
	execSQL(t, ctx, database, `DELETE FROM outbox_events WHERE event_type LIKE 'credential.revocation.%'`)
	execSQL(t, ctx, database, `ALTER TABLE runner_result_receipts DISABLE TRIGGER runner_result_receipts_immutable`)
	execSQL(t, ctx, database, `ALTER TABLE runner_result_receipts DISABLE TRIGGER runner_result_receipts_no_truncate`)
	execSQL(t, ctx, database, `TRUNCATE runner_result_receipts`)
	execSQL(t, ctx, database, `ALTER TABLE runner_result_receipts ENABLE TRIGGER runner_result_receipts_immutable`)
	execSQL(t, ctx, database, `ALTER TABLE runner_result_receipts ENABLE TRIGGER runner_result_receipts_no_truncate`)
	execSQL(t, ctx, database, `ALTER TABLE action_queue DISABLE TRIGGER action_queue_no_delete`)
	execSQL(t, ctx, database, `DELETE FROM action_queue`)
	execSQL(t, ctx, database, `ALTER TABLE action_queue ENABLE TRIGGER action_queue_no_delete`)

	const historicalActionID = "93900000-0000-4000-8000-000000000001"
	historicalFence := claimStartedCredentialAction(t, ctx, database, queue, signer,
		historicalActionID, workspaceID, environmentID, serviceID,
		"payments-historical-runner-result-v1", '9', "runner-postgres-1")
	historicalExecutionFence := executionlease.LeaseIdentity{
		ExecutionID: historicalFence.ActionID,
		RunnerID:    historicalFence.RunnerID,
		Token:       historicalFence.Token,
		Epoch:       historicalFence.Epoch,
	}
	recordNoCredentialForAction(t, ctx, database, historicalExecutionFence,
		"95900000-0000-4000-8000-000000000001")
	if finalizing, err := queue.Complete(ctx, execution.ActionCompleteRequest{
		Lease: historicalExecutionFence,
		Summary: execution.ExecutorResult{
			Outcome: execution.ExecutorSucceeded, Code: "HISTORICAL_V1_BEFORE_M3",
			Verification: execution.VerificationPassed,
		},
	}); err != nil || finalizing.Status != executionlease.StatusFinalizing {
		t.Fatalf("complete historical v1 action = %#v, %v", finalizing, err)
	}
	if completed, err := queue.Finalize(ctx, historicalExecutionFence); err != nil || completed.Status != executionlease.StatusSucceeded {
		t.Fatalf("finalize historical v1 action = %#v, %v", completed, err)
	}

	m3UpMigration := filepath.Join(migrationDirectory, "000009_runner_gateway_mtls.up.sql")
	m3DownMigration := filepath.Join(migrationDirectory, "000009_runner_gateway_mtls.down.sql")
	exerciseLegacyExecutionLeaseUpgradeGate(t, ctx, database, m3UpMigration)
	applyMigrationFile(t, ctx, database, m3UpMigration)
	exerciseLegacyExecutionLeasePostCutoverGate(t, ctx, database, m3DownMigration)
	var historicalV1Count int
	if err := database.QueryRow(ctx, `
		SELECT count(*) FROM runner_result_receipts
		WHERE action_id = $1 AND schema_version = 'runner-result.v1'
	`, historicalActionID).Scan(&historicalV1Count); err != nil || historicalV1Count != 1 {
		t.Fatalf("historical runner-result.v1 rows after M3 = %d, %v", historicalV1Count, err)
	}

	exerciseRealRunnerGatewayMigration(t, ctx, database, migrationDirectory, queue, repository, signer,
		tenantID, workspaceID, environmentID, serviceID)

	// M3 completion evidence is immutable in production. The harness removes it
	// only after every guard has been exercised so reverse migrations can run.
	execSQL(t, ctx, database, `ALTER TABLE credential_revocation_receipts DISABLE TRIGGER credential_revocation_receipts_immutable`)
	execSQL(t, ctx, database, `DELETE FROM credential_revocation_receipts`)
	execSQL(t, ctx, database, `ALTER TABLE credential_revocation_receipts ENABLE TRIGGER credential_revocation_receipts_immutable`)
	execSQL(t, ctx, database, `ALTER TABLE credential_revocation_system_receipts DISABLE TRIGGER credential_revocation_system_receipts_immutable`)
	execSQL(t, ctx, database, `DELETE FROM credential_revocation_system_receipts`)
	execSQL(t, ctx, database, `ALTER TABLE credential_revocation_system_receipts ENABLE TRIGGER credential_revocation_system_receipts_immutable`)
	execSQL(t, ctx, database, `ALTER TABLE credential_revocations DISABLE TRIGGER credential_revocations_no_delete`)
	execSQL(t, ctx, database, `DELETE FROM credential_revocations`)
	execSQL(t, ctx, database, `ALTER TABLE credential_revocations ENABLE TRIGGER credential_revocations_no_delete`)
	execSQL(t, ctx, database, `DELETE FROM outbox_events WHERE event_type LIKE 'credential.revocation.%'`)
}

func exerciseRealRunnerGatewayMigration(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	migrationDirectory string,
	queue execution.ActionQueue,
	repository *credentialpostgres.Repository,
	signer action.Signer,
	tenantID, workspaceID, environmentID, serviceID string,
) {
	t.Helper()
	const (
		runnerID            = "runner-postgres-m3-action"
		revocationRunnerID  = "runner-postgres-m3-revoker"
		transactionRunnerID = "runner-postgres-m3-tx-revoker"
	)
	registerRealWriteRunner(t, ctx, database, runnerID, tenantID, workspaceID, environmentID)
	registerRealWriteRunner(t, ctx, database, revocationRunnerID, tenantID, workspaceID, environmentID)
	registerRealWriteRunner(t, ctx, database, transactionRunnerID, tenantID, workspaceID, environmentID)
	execSQL(t, ctx, database, `
		UPDATE runner_registrations
		SET credential_revocation_capable = true, updated_at = statement_timestamp()
		WHERE runner_id IN ($1, $2, $3)
	`, runnerID, revocationRunnerID, transactionRunnerID)
	execSQL(t, ctx, database, `
		UPDATE runner_registrations
		SET max_concurrency = 4, updated_at = statement_timestamp()
		WHERE runner_id IN ($1, $2)
	`, runnerID, transactionRunnerID)

	var certificateSHA256 string
	if err := database.QueryRow(ctx, `
		SELECT certificate_sha256 FROM runner_certificates WHERE runner_id = $1
	`, runnerID).Scan(&certificateSHA256); err != nil {
		t.Fatalf("read M3 Runner certificate: %v", err)
	}
	var revocationCertificateSHA256 string
	var revocationScopeRevision int64
	if err := database.QueryRow(ctx, `
		SELECT certificate.certificate_sha256, registration.scope_revision
		FROM runner_certificates AS certificate
		JOIN runner_registrations AS registration USING (runner_id, tenant_id)
		WHERE certificate.runner_id = $1
	`, revocationRunnerID).Scan(&revocationCertificateSHA256, &revocationScopeRevision); err != nil {
		t.Fatalf("read M3 revocation Runner identity: %v", err)
	}
	certificateInsertStarted := time.Now().UTC()
	execSQL(t, ctx, database, `
		INSERT INTO runner_certificates (
			certificate_sha256, runner_id, tenant_id, issuer_key_id, serial_hex, spki_sha256,
			status, not_before, not_after, created_at
		) VALUES (repeat('6', 64), $1, $2, 'integration-created-at-ca', '66', repeat('5', 64),
			'ACTIVE', statement_timestamp() - interval '1 minute', statement_timestamp() + interval '1 hour',
			'2000-01-01T00:00:00Z'::timestamptz)
	`, runnerID, tenantID)
	var controlledCertificateCreatedAt time.Time
	if err := database.QueryRow(ctx, `
		SELECT created_at FROM runner_certificates WHERE certificate_sha256 = repeat('6', 64)
	`).Scan(&controlledCertificateCreatedAt); err != nil || controlledCertificateCreatedAt.Before(certificateInsertStarted) {
		t.Fatalf("database-controlled certificate created_at = %s, started=%s, err=%v",
			controlledCertificateCreatedAt, certificateInsertStarted, err)
	}
	expectSQLConstraint(t, ctx, database, "23514", "runner_certificates_time_ck", `
		INSERT INTO runner_certificates (
			certificate_sha256, runner_id, tenant_id, issuer_key_id, serial_hex, spki_sha256,
			status, not_before, not_after
		) VALUES (repeat('8', 64), $1, $2, 'integration-fixture-ca', '88', repeat('9', 64),
			'ACTIVE', statement_timestamp() - interval '1 minute', 'infinity'::timestamptz)
	`, runnerID, tenantID)
	expectSQLConstraint(t, ctx, database, "55000", "runner_certificates_lifecycle_guard", `
		UPDATE runner_certificates SET issuer_key_id = 'tampered-ca' WHERE certificate_sha256 = $1
	`, certificateSHA256)
	expectSQLState(t, ctx, database, "23514", `
		UPDATE runner_registrations SET runner_pool = 'READ' WHERE runner_id = $1
	`, runnerID)
	exerciseRealRunnerRevocationTransactions(t, ctx, database, queue, repository, signer,
		transactionRunnerID, tenantID, workspaceID, environmentID, serviceID)
	exerciseCredentialSystemRecoveryReceipts(t, ctx, database, queue, repository, signer,
		tenantID, workspaceID, environmentID, serviceID, runnerID)

	// Build one authenticated credential-revocation claim before creating any
	// M3 completion evidence. The rollback guard must reject the active claim.
	const credentialActionID = "94000000-0000-4000-8000-000000000001"
	credentialFence := claimStartedCredentialAction(t, ctx, database, queue, signer,
		credentialActionID, workspaceID, environmentID, serviceID,
		"payments-m3-credential-revocation", 'b', runnerID)
	const revocationID = "95000000-0000-4000-8000-000000000001"
	prepared, err := repository.Prepare(ctx, credential.PrepareRequest{
		RevocationID:        revocationID,
		Fence:               credentialFence,
		Issuer:              "vault-m3-integration",
		IssuerRevision:      "rev-1",
		CredentialExpiresAt: time.Now().UTC().Add(5 * time.Minute),
	})
	if err != nil || !prepared.Created || prepared.Permit == nil {
		t.Fatalf("prepare M3 credential revocation = %#v, %v", prepared, err)
	}
	if _, err := repository.AuthorizeChildCreate(ctx, credential.AuthorizeChildCreateRequest{
		Permit: *prepared.Permit, Fence: credentialFence,
	}); err != nil {
		t.Fatalf("authorize M3 child create: %v", err)
	}
	accessor, err := credential.NewSensitiveReference([]byte("m3-integration-accessor"))
	if err != nil {
		t.Fatalf("create M3 accessor: %v", err)
	}
	if _, err := repository.RecordAnchor(ctx, credential.RecordAnchorRequest{
		RevocationID: revocationID, Fence: credentialFence, Accessor: accessor,
	}); err != nil {
		accessor.Destroy()
		t.Fatalf("anchor M3 credential: %v", err)
	}
	accessor.Destroy()
	if _, err := repository.RequestRevocation(ctx, credential.ActionTransitionRequest{
		RevocationID: revocationID, Fence: credentialFence,
	}); err != nil {
		t.Fatalf("request M3 credential revocation: %v", err)
	}
	execSQL(t, ctx, database, `
		UPDATE credential_revocations
		SET available_at = '2000-01-01T00:00:00Z'::timestamptz,
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1
	`, revocationID)
	expectSQLConstraint(t, ctx, database, "55000", "credential_revocations_heartbeat_sequence_guard", `
		UPDATE credential_revocations
		SET status = 'REVOKING', claim_epoch = claim_epoch + 1,
			claimed_by = $2, claim_token_sha256 = repeat('3', 64),
			claimed_at = clock_timestamp(), last_heartbeat_at = clock_timestamp(),
			claim_expires_at = clock_timestamp() + interval '30 seconds',
			attempt = attempt + 1, heartbeat_seq = 0,
			failure_count = failure_count + 1, failure_code = 'TIMEOUT',
			failure_detail_sha256 = repeat('2', 64),
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1
	`, revocationID, runnerID)
	if legacyClaims, legacyErr := repository.ClaimRevocations(ctx, credential.ClaimRevocationsRequest{
		WorkerID: "legacy-m3-revoker", Limit: 1, LeaseDuration: 30 * time.Second,
	}); legacyErr == nil || len(legacyClaims) != 0 {
		for index := range legacyClaims {
			legacyClaims[index].Accessor.Destroy()
		}
		t.Fatalf("legacy revoker claim after M3 = %#v, %v; want rejected", legacyClaims, legacyErr)
	}
	// A revocation-capable Runner may differ from the action Runner, but it must
	// hold the exact current scope pair. Removing that pair makes a direct claim
	// fail closed; restoring it advances the registration revision before the
	// repository can claim the same pending credential.
	execSQL(t, ctx, database, `
		DELETE FROM runner_scope_bindings
		WHERE runner_id = $1 AND tenant_id = $2 AND workspace_id = $3 AND environment_id = $4
	`, revocationRunnerID, tenantID, workspaceID, environmentID)
	expectSQLConstraint(t, ctx, database, "23514", "credential_revocations_heartbeat_sequence_guard", `
		UPDATE credential_revocations
		SET status = 'REVOKING', claim_epoch = claim_epoch + 1,
			claimed_by = $2, claim_token_sha256 = repeat('4', 64),
			claimed_at = clock_timestamp(), last_heartbeat_at = clock_timestamp(),
			claim_expires_at = clock_timestamp() + interval '30 seconds',
			attempt = attempt + 1, updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1
	`, revocationID, revocationRunnerID)
	execSQL(t, ctx, database, `
		INSERT INTO runner_scope_bindings (runner_id, tenant_id, workspace_id, environment_id)
		VALUES ($1, $2, $3, $4)
	`, revocationRunnerID, tenantID, workspaceID, environmentID)
	if err := database.QueryRow(ctx, `
		SELECT scope_revision FROM runner_registrations WHERE runner_id = $1
	`, revocationRunnerID).Scan(&revocationScopeRevision); err != nil {
		t.Fatalf("read restored M3 revocation scope revision: %v", err)
	}

	claims, err := repository.ClaimRevocations(ctx, credential.ClaimRevocationsRequest{
		WorkerID: revocationRunnerID, Limit: 1, LeaseDuration: 30 * time.Second,
	})
	if err != nil || len(claims) != 1 || claims[0].Revocation.ID != revocationID {
		t.Fatalf("claim M3 credential revocation = %#v, %v", claims, err)
	}
	claim := claims[0].Fence
	claims[0].Accessor.Destroy()
	var claimedAt, firstHeartbeatAt, firstClaimExpiresAt time.Time
	if err := database.QueryRow(ctx, `
		SELECT claimed_at, last_heartbeat_at, claim_expires_at
		FROM credential_revocations WHERE revocation_id = $1
	`, revocationID).Scan(&claimedAt, &firstHeartbeatAt, &firstClaimExpiresAt); err != nil ||
		!claimedAt.Equal(firstHeartbeatAt) || firstClaimExpiresAt.Sub(firstHeartbeatAt) != 30*time.Second {
		t.Fatalf("database-controlled initial claim times = %s/%s/%s, %v",
			claimedAt, firstHeartbeatAt, firstClaimExpiresAt, err)
	}
	expectMigrationSQLState(t, ctx, database,
		filepath.Join(migrationDirectory, "000009_runner_gateway_mtls.down.sql"), "55000")

	// A capability Runner must advance exactly by one. Replaying, jumping, or
	// changing non-heartbeat state cannot change the persisted claim.
	expectSQLConstraint(t, ctx, database, "55000", "credential_revocations_heartbeat_sequence_guard", `
		UPDATE credential_revocations
		SET heartbeat_seq = 1, claimed_by = 'runner-postgres-m3-tampered',
			last_heartbeat_at = clock_timestamp(), claim_expires_at = clock_timestamp() + interval '1 minute',
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1
	`, revocationID)
	expectSQLConstraint(t, ctx, database, "55000", "credential_revocations_heartbeat_sequence_guard", `
		UPDATE credential_revocations
		SET heartbeat_seq = 1,
			failure_count = 1, failure_code = 'TIMEOUT', failure_detail_sha256 = repeat('1', 64),
			last_heartbeat_at = clock_timestamp(), claim_expires_at = clock_timestamp() + interval '1 minute',
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1
	`, revocationID)
	expectSQLConstraint(t, ctx, database, "55000", "credential_revocations_heartbeat_sequence_guard", `
		UPDATE credential_revocations
		SET updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1 AND heartbeat_seq = 0
	`, revocationID)
	execSQL(t, ctx, database, `
		WITH heartbeat_clock AS (SELECT clock_timestamp() + interval '1 millisecond' AS current_time)
		UPDATE credential_revocations AS revocation
		SET heartbeat_seq = 1,
			last_heartbeat_at = heartbeat_clock.current_time,
			claim_expires_at = heartbeat_clock.current_time + interval '1 minute',
			updated_at = heartbeat_clock.current_time,
			version = version + 1
		FROM heartbeat_clock
		WHERE revocation.revocation_id = $1
	`, revocationID)
	var sequencedHeartbeatAt, sequencedExpiry time.Time
	if err := database.QueryRow(ctx, `
		SELECT last_heartbeat_at, claim_expires_at FROM credential_revocations
		WHERE revocation_id = $1 AND heartbeat_seq = 1
	`, revocationID).Scan(&sequencedHeartbeatAt, &sequencedExpiry); err != nil ||
		sequencedExpiry.Sub(sequencedHeartbeatAt) != 30*time.Second {
		t.Fatalf("read sequenced revocation heartbeat: %v", err)
	}
	expectSQLConstraint(t, ctx, database, "55000", "credential_revocations_heartbeat_sequence_guard", `
		UPDATE credential_revocations
		SET claim_expires_at = claim_expires_at + interval '1 minute',
			last_heartbeat_at = last_heartbeat_at + interval '1 second',
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1 AND heartbeat_seq = 1
	`, revocationID)
	expectSQLConstraint(t, ctx, database, "55000", "credential_revocations_heartbeat_sequence_guard", `
		UPDATE credential_revocations
		SET heartbeat_seq = 3,
			claim_expires_at = claim_expires_at + interval '1 minute',
			last_heartbeat_at = last_heartbeat_at + interval '1 second',
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1
	`, revocationID)
	var expiryAfterReplay time.Time
	if err := database.QueryRow(ctx, `SELECT claim_expires_at FROM credential_revocations WHERE revocation_id = $1`, revocationID).
		Scan(&expiryAfterReplay); err != nil || !expiryAfterReplay.Equal(sequencedExpiry) {
		t.Fatalf("heartbeat replay changed expiry: before=%s after=%s err=%v", sequencedExpiry, expiryAfterReplay, err)
	}

	claimTokenSHA256 := credential.SHA256Hex([]byte(claim.Token))
	failureDetailSHA256 := strings.Repeat("a", 64)
	credentialReceiptInsert := `
		INSERT INTO credential_revocation_receipts (
			revocation_id, claim_epoch, tenant_id, workspace_id, environment_id,
			runner_id, scope_revision, certificate_sha256, issuer, issuer_revision, claim_token_sha256,
			heartbeat_seq, outcome, failure_count, failure_code, failure_detail_sha256, receipt_hash
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'vault-m3-integration', 'rev-1', $9,
			1, 'FAILED', 1, 'TIMEOUT', $10, repeat('9', 64))
	`
	expectSQLConstraint(t, ctx, database, "23514", "credential_revocation_receipts_claim_guard",
		credentialReceiptInsert, revocationID, claim.Epoch, tenantID, workspaceID, environmentID,
		revocationRunnerID, revocationScopeRevision+1, revocationCertificateSHA256, claimTokenSHA256, failureDetailSHA256)
	expectSQLConstraint(t, ctx, database, "23514", "credential_revocation_receipts_claim_guard",
		credentialReceiptInsert, revocationID, claim.Epoch, tenantID, workspaceID,
		"00000000-0000-4000-8000-000000000099", revocationRunnerID, revocationScopeRevision,
		revocationCertificateSHA256, claimTokenSHA256, failureDetailSHA256)
	expectDeferredConstraintAtCommit(t, ctx, database, "credential_revocations_completion_receipt_guard", `
		UPDATE credential_revocations
		SET status = 'REVOCATION_PENDING',
			claimed_by = NULL, claim_token_sha256 = NULL, claimed_at = NULL,
			claim_expires_at = NULL, last_heartbeat_at = NULL,
			failure_count = 1, failure_code = 'TIMEOUT', failure_detail_sha256 = $2,
			available_at = statement_timestamp() - interval '1 second',
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1
	`, revocationID, failureDetailSHA256)
	// The immediate trigger accepts the active claim, but the deferred trigger
	// rejects a receipt whose failure code diverges from the committed parent.
	expectDeferredConstraintAtCommit(t, ctx, database, "credential_revocation_receipts_final_shape", `
		INSERT INTO credential_revocation_receipts (
			revocation_id, claim_epoch, tenant_id, workspace_id, environment_id,
			runner_id, scope_revision, certificate_sha256, issuer, issuer_revision, claim_token_sha256,
			heartbeat_seq, outcome, failure_count, failure_code, failure_detail_sha256, receipt_hash
		) VALUES ($1, $2, $7, $8, $9, $3, $10, $4, 'vault-m3-integration', 'rev-1', $5,
			1, 'FAILED', 1, 'TIMEOUT', $6, repeat('b', 64));
		UPDATE credential_revocations
		SET status = 'REVOCATION_PENDING',
			claimed_by = NULL, claim_token_sha256 = NULL, claimed_at = NULL,
			claim_expires_at = NULL, last_heartbeat_at = NULL,
			failure_count = 1, failure_code = 'RATE_LIMITED', failure_detail_sha256 = repeat('c', 64),
			available_at = statement_timestamp() - interval '1 second',
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1;
	`, revocationID, claim.Epoch, revocationRunnerID, revocationCertificateSHA256,
		claimTokenSHA256, failureDetailSHA256, tenantID, workspaceID, environmentID, revocationScopeRevision)

	execSQL(t, ctx, database, `
		INSERT INTO credential_revocation_receipts (
			revocation_id, claim_epoch, tenant_id, workspace_id, environment_id,
			runner_id, scope_revision, certificate_sha256, issuer, issuer_revision, claim_token_sha256,
			heartbeat_seq, outcome, failure_count, failure_code, failure_detail_sha256, receipt_hash
		) VALUES ($1, $2, $7, $8, $9, $3, $10, $4, 'vault-m3-integration', 'rev-1', $5,
			1, 'FAILED', 1, 'TIMEOUT', $6, repeat('d', 64));
		UPDATE credential_revocations
		SET status = 'REVOCATION_PENDING',
			claimed_by = NULL, claim_token_sha256 = NULL, claimed_at = NULL,
			claim_expires_at = NULL, last_heartbeat_at = NULL,
			failure_count = 1, failure_code = 'TIMEOUT', failure_detail_sha256 = $6,
			available_at = statement_timestamp() - interval '1 second',
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1
	`, revocationID, claim.Epoch, revocationRunnerID, revocationCertificateSHA256,
		claimTokenSHA256, failureDetailSHA256, tenantID, workspaceID, environmentID, revocationScopeRevision)
	var failedStatus string
	var retainedSequence int64
	if err := database.QueryRow(ctx, `
		SELECT status, heartbeat_seq FROM credential_revocations WHERE revocation_id = $1
	`, revocationID).Scan(&failedStatus, &retainedSequence); err != nil ||
		failedStatus != string(credential.StatusRevocationPending) || retainedSequence != 1 {
		t.Fatalf("failed M3 receipt parent = %s/seq-%d, %v", failedStatus, retainedSequence, err)
	}

	claims, err = repository.ClaimRevocations(ctx, credential.ClaimRevocationsRequest{
		WorkerID: revocationRunnerID, Limit: 1, LeaseDuration: 30 * time.Second,
	})
	if err != nil || len(claims) != 1 || claims[0].Revocation.ID != revocationID {
		t.Fatalf("reclaim M3 credential revocation = %#v, %v", claims, err)
	}
	claim = claims[0].Fence
	claims[0].Accessor.Destroy()
	if err := database.QueryRow(ctx, `
		SELECT heartbeat_seq FROM credential_revocations WHERE revocation_id = $1
	`, revocationID).Scan(&retainedSequence); err != nil || retainedSequence != 0 {
		t.Fatalf("new M3 claim heartbeat sequence = %d, %v; want 0", retainedSequence, err)
	}
	execSQL(t, ctx, database, `
		WITH heartbeat_clock AS (SELECT clock_timestamp() + interval '1 millisecond' AS current_time)
		UPDATE credential_revocations AS revocation
		SET heartbeat_seq = 1,
			last_heartbeat_at = heartbeat_clock.current_time,
			claim_expires_at = heartbeat_clock.current_time + interval '1 minute',
			updated_at = heartbeat_clock.current_time,
			version = version + 1
		FROM heartbeat_clock
		WHERE revocation.revocation_id = $1
	`, revocationID)
	claimTokenSHA256 = credential.SHA256Hex([]byte(claim.Token))
	expectDeferredConstraintAtCommit(t, ctx, database, "credential_revocations_completion_receipt_guard", `
		UPDATE credential_revocations
		SET status = 'REVOKED',
			completed_claim_epoch = claim_epoch,
			completed_claim_token_sha256 = claim_token_sha256,
			completed_claimed_by = claimed_by,
			claimed_by = NULL, claim_token_sha256 = NULL, claimed_at = NULL,
			claim_expires_at = NULL, last_heartbeat_at = NULL,
			accessor_ciphertext = NULL, encryption_key_id = NULL,
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1
	`, revocationID)
	execSQL(t, ctx, database, `
		INSERT INTO credential_revocation_receipts (
			revocation_id, claim_epoch, tenant_id, workspace_id, environment_id,
			runner_id, scope_revision, certificate_sha256, issuer, issuer_revision, claim_token_sha256,
			heartbeat_seq, outcome, receipt_hash
		) VALUES ($1, $2, $6, $7, $8, $3, $9, $4, 'vault-m3-integration', 'rev-1', $5,
			1, 'REVOKED', repeat('e', 64));
		UPDATE credential_revocations
		SET status = 'REVOKED',
			completed_claim_epoch = claim_epoch,
			completed_claim_token_sha256 = claim_token_sha256,
			completed_claimed_by = claimed_by,
			claimed_by = NULL, claim_token_sha256 = NULL, claimed_at = NULL,
			claim_expires_at = NULL, last_heartbeat_at = NULL,
			accessor_ciphertext = NULL, encryption_key_id = NULL,
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1
	`, revocationID, claim.Epoch, revocationRunnerID, revocationCertificateSHA256,
		claimTokenSHA256, tenantID, workspaceID, environmentID, revocationScopeRevision)
	var revokedStatus string
	if err := database.QueryRow(ctx, `
		SELECT status, heartbeat_seq FROM credential_revocations WHERE revocation_id = $1
	`, revocationID).Scan(&revokedStatus, &retainedSequence); err != nil ||
		revokedStatus != string(credential.StatusRevoked) || retainedSequence != 1 {
		t.Fatalf("revoked M3 receipt parent = %s/seq-%d, %v", revokedStatus, retainedSequence, err)
	}
	expectSQLConstraint(t, ctx, database, "55000", "credential_revocation_receipts_immutable_guard", `
		UPDATE credential_revocation_receipts SET receipt_hash = repeat('f', 64) WHERE revocation_id = $1
	`, revocationID)
	expectSQLConstraint(t, ctx, database, "55000", "credential_revocation_receipts_immutable_guard", `
		DELETE FROM credential_revocation_receipts WHERE revocation_id = $1
	`, revocationID)
	expectSQLConstraint(t, ctx, database, "55000", "credential_revocation_receipts_immutable_guard", `
		TRUNCATE credential_revocation_receipts
	`)

	// runner-result.v2 requires a registered certificate and satisfies both
	// deferred FINALIZING proof and the terminal receipt guard. v1 rows created
	// by the existing repository remain valid throughout the same migration.
	const resultActionID = "94000000-0000-4000-8000-000000000002"
	resultFence := claimStartedCredentialAction(t, ctx, database, queue, signer,
		resultActionID, workspaceID, environmentID, serviceID,
		"payments-m3-result-v2", '2', runnerID)
	resultExecutionFence := executionlease.LeaseIdentity{
		ExecutionID: resultFence.ActionID,
		RunnerID:    resultFence.RunnerID,
		Token:       resultFence.Token,
		Epoch:       resultFence.Epoch,
	}
	recordNoCredentialForAction(t, ctx, database, resultExecutionFence,
		"95000000-0000-4000-8000-000000000002")
	resultHash := strings.Repeat("7", 64)
	var v1RowsBefore int
	if err := database.QueryRow(ctx, `
		SELECT count(*) FROM runner_result_receipts WHERE schema_version = 'runner-result.v1'
	`).Scan(&v1RowsBefore); err != nil || v1RowsBefore < 1 {
		t.Fatalf("historical v1 receipt count before rejection = %d, %v", v1RowsBefore, err)
	}
	expectSQLConstraintAndRollback(t, ctx, database, "23514", "runner_result_receipts_insert_guard", `
		UPDATE action_queue
		SET status = 'FINALIZING', completion_status = 'SUCCEEDED', result_hash = $2,
			completed_lease_token_sha256 = lease_token_sha256, completed_lease_epoch = lease_epoch,
			lease_token_sha256 = NULL, lease_expires_at = NULL, updated_at = statement_timestamp()
		WHERE action_id = $1;
		INSERT INTO runner_result_receipts (
			action_id, tenant_id, workspace_id, environment_id, runner_id, lease_epoch, scope_revision,
			certificate_sha256, receipt_hash, completion_status, schema_version, summary
		)
		SELECT action_id, runner_tenant_id, runner_workspace_id, runner_environment_id,
			runner_id, lease_epoch, scope_revision + 1, $3, result_hash, completion_status,
			'runner-result.v2', '{"outcome":"SUCCEEDED"}'::jsonb
		FROM action_queue WHERE action_id = $1
	`, resultActionID, resultHash, certificateSHA256)
	expectSQLConstraintAndRollback(t, ctx, database, "23514", "runner_result_receipts_insert_guard", `
		UPDATE action_queue
		SET status = 'FINALIZING', completion_status = 'SUCCEEDED', result_hash = $2,
			completed_lease_token_sha256 = lease_token_sha256, completed_lease_epoch = lease_epoch,
			lease_token_sha256 = NULL, lease_expires_at = NULL, updated_at = statement_timestamp()
		WHERE action_id = $1;
		INSERT INTO runner_result_receipts (
			action_id, tenant_id, workspace_id, environment_id, runner_id, lease_epoch, scope_revision,
			certificate_sha256, receipt_hash, completion_status, schema_version, summary
		)
		SELECT action_id, runner_tenant_id, runner_workspace_id, runner_environment_id,
			runner_id, lease_epoch, scope_revision, $3, repeat('8', 64), completion_status,
			'runner-result.v2', '{"outcome":"SUCCEEDED"}'::jsonb
		FROM action_queue WHERE action_id = $1
	`, resultActionID, resultHash, certificateSHA256)
	expectSQLConstraintAndRollback(t, ctx, database, "23514", "runner_result_receipts_insert_guard", `
		UPDATE action_queue
		SET status = 'FINALIZING', completion_status = 'SUCCEEDED', result_hash = $2,
			completed_lease_token_sha256 = lease_token_sha256, completed_lease_epoch = lease_epoch,
			lease_token_sha256 = NULL, lease_expires_at = NULL, updated_at = statement_timestamp()
		WHERE action_id = $1;
		INSERT INTO runner_result_receipts (
			action_id, tenant_id, workspace_id, environment_id, runner_id, lease_epoch, scope_revision,
			certificate_sha256, receipt_hash, completion_status, schema_version, summary
		)
		SELECT action_id, runner_tenant_id, runner_workspace_id, runner_environment_id,
			runner_id, lease_epoch, scope_revision, $3, result_hash, completion_status,
			'runner-result.v1', '{"outcome":"SUCCEEDED"}'::jsonb
		FROM action_queue WHERE action_id = $1
	`, resultActionID, resultHash, certificateSHA256)
	var v1RowsAfter int
	if err := database.QueryRow(ctx, `
		SELECT count(*) FROM runner_result_receipts WHERE schema_version = 'runner-result.v1'
	`).Scan(&v1RowsAfter); err != nil || v1RowsAfter != v1RowsBefore {
		t.Fatalf("new v1 receipt changed historical count = %d/%d, %v", v1RowsBefore, v1RowsAfter, err)
	}
	expectSQLConstraintAndRollback(t, ctx, database, "23514", "runner_result_receipts_insert_guard", `
		UPDATE action_queue
		SET status = 'FINALIZING', completion_status = 'SUCCEEDED', result_hash = $2,
			completed_lease_token_sha256 = lease_token_sha256, completed_lease_epoch = lease_epoch,
			lease_token_sha256 = NULL, lease_expires_at = NULL, updated_at = statement_timestamp()
		WHERE action_id = $1;
		INSERT INTO runner_result_receipts (
			action_id, tenant_id, workspace_id, environment_id, runner_id, lease_epoch, scope_revision,
			certificate_sha256, receipt_hash, completion_status, schema_version, summary
		)
		SELECT action_id, runner_tenant_id, runner_workspace_id, runner_environment_id,
			runner_id, lease_epoch, scope_revision, NULL, result_hash, completion_status,
			'runner-result.v2', '{"outcome":"SUCCEEDED"}'::jsonb
		FROM action_queue WHERE action_id = $1
	`, resultActionID, resultHash)
	assertActionStatus(t, ctx, database, resultActionID, executionlease.StatusRunning)
	execSQL(t, ctx, database, `
		UPDATE action_queue
		SET status = 'FINALIZING', completion_status = 'SUCCEEDED', result_hash = $2,
			completed_lease_token_sha256 = lease_token_sha256, completed_lease_epoch = lease_epoch,
			lease_token_sha256 = NULL, lease_expires_at = NULL, updated_at = statement_timestamp()
		WHERE action_id = $1;
		INSERT INTO runner_result_receipts (
			action_id, tenant_id, workspace_id, environment_id, runner_id, lease_epoch, scope_revision,
			certificate_sha256, receipt_hash, completion_status, schema_version, summary, received_at
		)
		SELECT action_id, runner_tenant_id, runner_workspace_id, runner_environment_id,
			runner_id, lease_epoch, scope_revision, $3, result_hash, completion_status,
			'runner-result.v2', '{"outcome":"SUCCEEDED"}'::jsonb, '2000-01-01T00:00:00Z'::timestamptz
		FROM action_queue WHERE action_id = $1
	`, resultActionID, resultHash, certificateSHA256)
	var controlledReceiptTime time.Time
	if err := database.QueryRow(ctx, `
		SELECT received_at FROM runner_result_receipts WHERE action_id = $1
	`, resultActionID).Scan(&controlledReceiptTime); err != nil || controlledReceiptTime.Before(certificateInsertStarted) {
		t.Fatalf("database-controlled v2 receipt time = %s, started=%s, err=%v",
			controlledReceiptTime, certificateInsertStarted, err)
	}
	execSQL(t, ctx, database, `
		UPDATE action_queue
		SET status = 'SUCCEEDED', completed_at = statement_timestamp(), updated_at = statement_timestamp()
		WHERE action_id = $1
	`, resultActionID)
	assertActionStatus(t, ctx, database, resultActionID, executionlease.StatusSucceeded)

	credentialResultHash := strings.Repeat("4", 64)
	execSQL(t, ctx, database, `
		UPDATE action_queue
		SET status = 'FINALIZING', completion_status = 'SUCCEEDED', result_hash = $2,
			completed_lease_token_sha256 = lease_token_sha256, completed_lease_epoch = lease_epoch,
			lease_token_sha256 = NULL, lease_expires_at = NULL, updated_at = statement_timestamp()
		WHERE action_id = $1;
		INSERT INTO runner_result_receipts (
			action_id, tenant_id, workspace_id, environment_id, runner_id, lease_epoch, scope_revision,
			certificate_sha256, receipt_hash, completion_status, schema_version, summary
		)
		SELECT action_id, runner_tenant_id, runner_workspace_id, runner_environment_id,
			runner_id, lease_epoch, scope_revision, $3, result_hash, completion_status,
			'runner-result.v2', '{"outcome":"SUCCEEDED","code":"M3_REVOCATION_RECEIPT_VERIFIED"}'::jsonb
		FROM action_queue WHERE action_id = $1
	`, credentialActionID, credentialResultHash, certificateSHA256)
	execSQL(t, ctx, database, `
		UPDATE action_queue
		SET status = 'SUCCEEDED', completed_at = statement_timestamp(), updated_at = statement_timestamp()
		WHERE action_id = $1
	`, credentialActionID)
	assertActionStatus(t, ctx, database, credentialActionID, executionlease.StatusSucceeded)

	execSQL(t, ctx, database, `
		UPDATE runner_certificates
		SET status = 'REVOKED', revocation_reason = 'M3 integration revocation'
		WHERE certificate_sha256 = $1
	`, certificateSHA256)
	var certificateStatus string
	var certificateRevokedAt time.Time
	if err := database.QueryRow(ctx, `
		SELECT status, revoked_at FROM runner_certificates WHERE certificate_sha256 = $1
	`, certificateSHA256).Scan(&certificateStatus, &certificateRevokedAt); err != nil ||
		certificateStatus != "REVOKED" || certificateRevokedAt.IsZero() {
		t.Fatalf("revoked Runner certificate = %s/%s, %v", certificateStatus, certificateRevokedAt, err)
	}
	expectSQLConstraint(t, ctx, database, "55000", "runner_certificates_lifecycle_guard", `
		UPDATE runner_certificates SET status = 'ACTIVE', revoked_at = NULL, revocation_reason = NULL
		WHERE certificate_sha256 = $1
	`, certificateSHA256)
	expectSQLConstraint(t, ctx, database, "55000", "runner_certificates_history_guard", `
		DELETE FROM runner_certificates WHERE certificate_sha256 = $1
	`, certificateSHA256)
	expectSQLState(t, ctx, database, "0A000", `
		TRUNCATE runner_certificates
	`)
	expectSQLConstraint(t, ctx, database, "55000", "runner_certificates_history_guard", `
		TRUNCATE runner_certificates CASCADE
	`)

	expectMigrationSQLState(t, ctx, database,
		filepath.Join(migrationDirectory, "000009_runner_gateway_mtls.down.sql"), "55000")
}

func exerciseRealRunnerRevocationTransactions(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	queue execution.ActionQueue,
	credentialRepository *credentialpostgres.Repository,
	signer action.Signer,
	runnerID, tenantID, workspaceID, environmentID, serviceID string,
) {
	t.Helper()
	const (
		decoyEnvironmentID  = "25000000-0000-4000-8000-000000000003"
		failedActionID      = "94200000-0000-4000-8000-000000000001"
		failedRevocationID  = "95200000-0000-4000-8000-000000000001"
		revokedActionID     = "94200000-0000-4000-8000-000000000002"
		revokedRevocationID = "95200000-0000-4000-8000-000000000002"
	)

	execSQL(t, ctx, database, `
		INSERT INTO environments (id, tenant_id, workspace_id, name, kind)
		VALUES ($1, $2, $3, 'runner-transaction-decoy', 'DEV')
	`, decoyEnvironmentID, tenantID, workspaceID)
	execSQL(t, ctx, database, `
		INSERT INTO runner_scope_bindings (runner_id, tenant_id, workspace_id, environment_id)
		VALUES ($1, $2, $3, $4)
	`, runnerID, tenantID, workspaceID, decoyEnvironmentID)

	identity := registerRealRunnerIdentityCertificate(t, ctx, database, runnerID, tenantID)
	identityRepository, err := runneridentitypostgres.New(database)
	if err != nil {
		t.Fatalf("create real Runner identity repository: %v", err)
	}

	prepareM3ClaimableRevocation(t, ctx, database, queue, credentialRepository, signer,
		failedActionID, failedRevocationID, workspaceID, environmentID, serviceID,
		"payments-m3-runner-tx-failed", 'e', runnerID)
	failedClaim := claimRealRunnerRevocation(t, ctx, database, identityRepository,
		credentialRepository, identity, failedRevocationID)
	defer failedClaim.Accessor.Destroy()
	assertRawRevocationTokenNotPersisted(t, ctx, database, failedClaim.Fence)

	var claimScopeRevision int64
	if err := database.QueryRow(ctx, `
		SELECT scope_revision FROM runner_registrations WHERE runner_id = $1
	`, runnerID).Scan(&claimScopeRevision); err != nil {
		t.Fatalf("read Runner claim scope revision: %v", err)
	}
	execSQL(t, ctx, database, `
		DELETE FROM runner_scope_bindings
		WHERE runner_id = $1 AND tenant_id = $2 AND workspace_id = $3 AND environment_id = $4
	`, runnerID, tenantID, workspaceID, environmentID)
	var narrowedScopeRevision int64
	if err := database.QueryRow(ctx, `
		SELECT scope_revision FROM runner_registrations WHERE runner_id = $1
	`, runnerID).Scan(&narrowedScopeRevision); err != nil || narrowedScopeRevision <= claimScopeRevision {
		t.Fatalf("narrowed Runner scope revision = %d after %d, %v", narrowedScopeRevision, claimScopeRevision, err)
	}
	terminated := heartbeatRealRunnerRevocation(t, ctx, database, identityRepository,
		credentialRepository, identity, failedClaim.Fence, 1)
	if terminated.Directive != credential.RunnerRevocationTerminate || terminated.AcceptedSequence != 1 {
		t.Fatalf("real Runner heartbeat after exact-scope loss = %#v", terminated)
	}
	var sequenceAfterTermination int64
	if err := database.QueryRow(ctx, `
		SELECT heartbeat_seq FROM credential_revocations WHERE revocation_id = $1
	`, failedRevocationID).Scan(&sequenceAfterTermination); err != nil || sequenceAfterTermination != 0 {
		t.Fatalf("terminated heartbeat persisted sequence = %d, %v", sequenceAfterTermination, err)
	}
	execSQL(t, ctx, database, `
		INSERT INTO runner_scope_bindings (runner_id, tenant_id, workspace_id, environment_id)
		VALUES ($1, $2, $3, $4)
	`, runnerID, tenantID, workspaceID, environmentID)
	var restoredScopeRevision int64
	if err := database.QueryRow(ctx, `
		SELECT scope_revision FROM runner_registrations WHERE runner_id = $1
	`, runnerID).Scan(&restoredScopeRevision); err != nil || restoredScopeRevision <= narrowedScopeRevision {
		t.Fatalf("restored Runner scope revision = %d after %d, %v", restoredScopeRevision, narrowedScopeRevision, err)
	}

	firstHeartbeat := heartbeatRealRunnerRevocation(t, ctx, database, identityRepository,
		credentialRepository, identity, failedClaim.Fence, 1)
	replayedHeartbeat := heartbeatRealRunnerRevocation(t, ctx, database, identityRepository,
		credentialRepository, identity, failedClaim.Fence, 1)
	if firstHeartbeat.Directive != credential.RunnerRevocationContinue ||
		replayedHeartbeat.Directive != credential.RunnerRevocationContinue ||
		firstHeartbeat.AcceptedSequence != 1 || replayedHeartbeat.AcceptedSequence != 1 ||
		!replayedHeartbeat.ClaimExpiresAt.Equal(firstHeartbeat.ClaimExpiresAt) {
		t.Fatalf("real Runner monotonic/replayed heartbeat = %#v / %#v", firstHeartbeat, replayedHeartbeat)
	}
	assertRevokedCertificateCannotAuthenticate(t, ctx, database, identityRepository, identity)

	failedCompletion := completeRealRunnerRevocation(t, ctx, database, identityRepository,
		credentialRepository, identity, failedClaim.Fence,
		credential.RunnerRevocationFailed, credential.FailureTimeout)
	if failedCompletion.Revocation.Status != credential.StatusRevocationPending ||
		failedCompletion.Receipt.Outcome != credential.RunnerRevocationFailed ||
		failedCompletion.Receipt.HeartbeatSequence != 1 || failedCompletion.RetryDelay <= 0 {
		t.Fatalf("real Runner failed revocation completion = %#v", failedCompletion)
	}
	assertRealRunnerRevocationReceipt(t, ctx, database, failedCompletion.Receipt, failedClaim.Fence)
	assertRawRevocationTokenNotPersisted(t, ctx, database, failedClaim.Fence)
	var failedCiphertext, failedHMAC []byte
	var failedKeyID *string
	var failureAuditCount, failureOutboxCount int
	if err := database.QueryRow(ctx, `
		SELECT parent.accessor_ciphertext, parent.accessor_hmac, parent.encryption_key_id,
			(SELECT count(*) FROM audit_records
			 WHERE resource_id = $1 AND action = 'credential.revocation.failed'),
			(SELECT count(*) FROM outbox_events
			 WHERE aggregate_id = $1::uuid AND event_type = 'credential.revocation.failed.v1')
		FROM credential_revocations AS parent WHERE parent.revocation_id = $1
	`, failedRevocationID).Scan(
		&failedCiphertext, &failedHMAC, &failedKeyID, &failureAuditCount, &failureOutboxCount,
	); err != nil || len(failedCiphertext) == 0 || len(failedHMAC) == 0 || failedKeyID == nil ||
		failureAuditCount != 1 || failureOutboxCount != 1 {
		t.Fatalf("failed Runner revocation retained reference/alert = cipher-%d hmac-%d key-%v audit-%d outbox-%d, %v",
			len(failedCiphertext), len(failedHMAC), failedKeyID, failureAuditCount, failureOutboxCount, err)
	}
	// Keep the retryable failure outside this Runner's current exact scope so
	// the next claim proves paired-scope selection instead of racing retry
	// backoff wall-clock time.
	execSQL(t, ctx, database, `
		DELETE FROM runner_scope_bindings
		WHERE runner_id = $1 AND tenant_id = $2 AND workspace_id = $3 AND environment_id = $4
	`, runnerID, tenantID, workspaceID, environmentID)

	prepareM3ClaimableRevocation(t, ctx, database, queue, credentialRepository, signer,
		revokedActionID, revokedRevocationID, workspaceID, decoyEnvironmentID, serviceID,
		"payments-m3-runner-tx-revoked", 'f', runnerID)
	var originalAccessorHMAC []byte
	if err := database.QueryRow(ctx, `
		SELECT accessor_hmac FROM credential_revocations WHERE revocation_id = $1
	`, revokedRevocationID).Scan(&originalAccessorHMAC); err != nil || len(originalAccessorHMAC) == 0 {
		t.Fatalf("read original Runner revocation accessor HMAC = %d, %v", len(originalAccessorHMAC), err)
	}
	revokedClaim := claimRealRunnerRevocation(t, ctx, database, identityRepository,
		credentialRepository, identity, revokedRevocationID)
	defer revokedClaim.Accessor.Destroy()
	heartbeat := heartbeatRealRunnerRevocation(t, ctx, database, identityRepository,
		credentialRepository, identity, revokedClaim.Fence, 1)
	if heartbeat.Directive != credential.RunnerRevocationContinue || heartbeat.AcceptedSequence != 1 {
		t.Fatalf("real Runner revoked-path heartbeat = %#v", heartbeat)
	}
	revokedCompletion := completeRealRunnerRevocation(t, ctx, database, identityRepository,
		credentialRepository, identity, revokedClaim.Fence,
		credential.RunnerRevocationRevoked, "")
	if revokedCompletion.Revocation.Status != credential.StatusRevoked ||
		revokedCompletion.Receipt.Outcome != credential.RunnerRevocationRevoked ||
		revokedCompletion.RetryDelay != 0 {
		t.Fatalf("real Runner revoked completion = %#v", revokedCompletion)
	}
	assertRealRunnerRevocationReceipt(t, ctx, database, revokedCompletion.Receipt, revokedClaim.Fence)
	assertRawRevocationTokenNotPersisted(t, ctx, database, revokedClaim.Fence)
	var revokedCiphertext []byte
	var retainedAccessorHMAC []byte
	var revokedKeyID *string
	if err := database.QueryRow(ctx, `
		SELECT accessor_ciphertext, accessor_hmac, encryption_key_id
		FROM credential_revocations WHERE revocation_id = $1
	`, revokedRevocationID).Scan(&revokedCiphertext, &retainedAccessorHMAC, &revokedKeyID); err != nil ||
		revokedCiphertext != nil || revokedKeyID != nil || !bytes.Equal(retainedAccessorHMAC, originalAccessorHMAC) {
		t.Fatalf("revoked Runner reference evidence = cipher-%d hmac-match-%t key-%v, %v",
			len(revokedCiphertext), bytes.Equal(retainedAccessorHMAC, originalAccessorHMAC), revokedKeyID, err)
	}
}

func registerRealRunnerIdentityCertificate(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	runnerID, tenantID string,
) runneridentity.Identity {
	t.Helper()
	now := time.Now().UTC()
	readAuthority, err := testpki.NewAuthority("runner-postgres-m3-read-root", now)
	if err != nil {
		t.Fatalf("create real READ Runner authority: %v", err)
	}
	writeAuthority, err := testpki.NewAuthority("runner-postgres-m3-write-root", now)
	if err != nil {
		t.Fatalf("create real WRITE Runner authority: %v", err)
	}
	spiffeURI, err := url.Parse("spiffe://integration.test/runner/write/" + runnerID)
	if err != nil {
		t.Fatalf("parse real Runner SPIFFE URI: %v", err)
	}
	client, err := writeAuthority.IssueClient(testpki.ClientOptions{URIs: []*url.URL{spiffeURI}}, now)
	if err != nil {
		t.Fatalf("issue real Runner client certificate: %v", err)
	}
	verifier, err := runneridentity.NewVerifier(runneridentity.Options{
		TrustDomain: "integration.test",
		ReadRoots:   []*x509.Certificate{readAuthority.Certificate},
		WriteRoots:  []*x509.Certificate{writeAuthority.Certificate},
		Clock:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("create real Runner identity verifier: %v", err)
	}
	chains, err := client.Leaf.Verify(x509.VerifyOptions{
		Roots: writeAuthority.CertPool(), CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatalf("verify real Runner client certificate: %v", err)
	}
	identity, err := verifier.IdentityFromConnectionState(tls.ConnectionState{
		Version: tls.VersionTLS13, HandshakeComplete: true,
		PeerCertificates: []*x509.Certificate{client.Leaf, writeAuthority.Certificate},
		VerifiedChains:   chains,
	})
	if err != nil {
		t.Fatalf("derive real Runner mTLS identity: %v", err)
	}
	evidence := identity.Evidence()
	execSQL(t, ctx, database, `
		INSERT INTO runner_certificates (
			certificate_sha256, runner_id, tenant_id, issuer_key_id, serial_hex, spki_sha256,
			status, not_before, not_after
		) VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE', $7, $8)
	`, evidence.LeafSHA256(), runnerID, tenantID, evidence.AuthorityKeyIDHex(),
		evidence.SerialHex(), evidence.SPKISHA256(), evidence.NotBefore(), evidence.NotAfter())
	return identity
}

func authenticateRealRunnerTx(
	t *testing.T,
	ctx context.Context,
	repository *runneridentitypostgres.Repository,
	tx pgx.Tx,
	identity runneridentity.Identity,
) (runneridentitypostgres.AuthenticatedRunner, execution.RunnerScope) {
	t.Helper()
	authenticated, err := repository.AuthenticateTx(ctx, tx, identity)
	if err != nil || !authenticated.Valid() || !authenticated.CredentialRevocationCapable() {
		t.Fatalf("authenticate real revocation-capable Runner = %#v, %v", authenticated, err)
	}
	scope, err := authenticated.RunnerScope()
	if err != nil {
		t.Fatalf("derive real authenticated Runner scope: %v", err)
	}
	return authenticated, scope
}

func claimRealRunnerRevocation(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	identityRepository *runneridentitypostgres.Repository,
	credentialRepository *credentialpostgres.Repository,
	identity runneridentity.Identity,
	revocationID string,
) credential.ClaimedRevocation {
	t.Helper()
	tx, err := database.Begin(ctx)
	if err != nil {
		t.Fatalf("begin real Runner revocation claim: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	authenticated, scope := authenticateRealRunnerTx(t, ctx, identityRepository, tx, identity)
	ticket, err := credentialRepository.ClaimRevocationRunnerTx(
		ctx, tx, scope, authenticated.CertificateSHA256())
	if err != nil || ticket == nil {
		t.Fatalf("claim real Runner revocation %s = %#v, %v", revocationID, ticket, err)
	}
	defer ticket.Discard()
	if rendered := fmt.Sprintf("%#v", ticket); strings.Contains(rendered, revocationID) ||
		strings.Contains(rendered, authenticated.CertificateSHA256()) {
		t.Fatalf("real Runner claim ticket rendered sensitive identity: %q", rendered)
	}
	if encoded, marshalErr := json.Marshal(ticket); marshalErr == nil || encoded != nil {
		t.Fatalf("real Runner claim ticket serialized = %q, %v", encoded, marshalErr)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit real Runner revocation claim: %v", err)
	}
	claim, err := credentialRepository.FinalizeRevocationClaimAfterCommit(ctx, ticket)
	if err != nil || claim.Revocation.ID != revocationID || claim.Fence.RevocationID != revocationID ||
		claim.Fence.WorkerID != authenticated.RunnerID() || claim.Fence.Token == "" || claim.Accessor == nil ||
		len(claim.Accessor.Bytes()) == 0 {
		if claim.Accessor != nil {
			claim.Accessor.Destroy()
		}
		t.Fatalf("finalize committed real Runner revocation claim = %#v, %v", claim.Revocation, err)
	}
	return claim
}

func heartbeatRealRunnerRevocation(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	identityRepository *runneridentitypostgres.Repository,
	credentialRepository *credentialpostgres.Repository,
	identity runneridentity.Identity,
	fence credential.ClaimFence,
	sequence int64,
) credential.RunnerRevocationHeartbeatResult {
	t.Helper()
	tx, err := database.Begin(ctx)
	if err != nil {
		t.Fatalf("begin real Runner revocation heartbeat: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, scope := authenticateRealRunnerTx(t, ctx, identityRepository, tx, identity)
	result, err := credentialRepository.HeartbeatRevocationRunnerTx(ctx, tx, scope, fence, sequence)
	if err != nil {
		t.Fatalf("heartbeat real Runner revocation sequence %d: %v", sequence, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit real Runner revocation heartbeat: %v", err)
	}
	return result
}

func completeRealRunnerRevocation(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	identityRepository *runneridentitypostgres.Repository,
	credentialRepository *credentialpostgres.Repository,
	identity runneridentity.Identity,
	fence credential.ClaimFence,
	outcome credential.RunnerRevocationOutcome,
	failureCode credential.FailureCode,
) credential.RunnerRevocationCompletionResult {
	t.Helper()
	tx, err := database.Begin(ctx)
	if err != nil {
		t.Fatalf("begin real Runner revocation completion: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	authenticated, scope := authenticateRealRunnerTx(t, ctx, identityRepository, tx, identity)
	result, err := credentialRepository.CompleteRevocationRunnerTx(
		ctx, tx, scope, fence, outcome, failureCode, authenticated.CertificateSHA256())
	if err != nil {
		t.Fatalf("complete real Runner revocation %s: %v", outcome, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit real Runner revocation completion: %v", err)
	}
	return result
}

func assertRevokedCertificateCannotAuthenticate(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	repository *runneridentitypostgres.Repository,
	identity runneridentity.Identity,
) {
	t.Helper()
	tx, err := database.Begin(ctx)
	if err != nil {
		t.Fatalf("begin Runner certificate loss proof: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		UPDATE runner_certificates
		SET status = 'REVOKED', revocation_reason = 'integration transaction proof'
		WHERE certificate_sha256 = $1
	`, identity.Evidence().LeafSHA256()); err != nil {
		t.Fatalf("temporarily revoke real Runner certificate: %v", err)
	}
	if authenticated, err := repository.AuthenticateTx(ctx, tx, identity); !errors.Is(err, runneridentity.ErrAuthenticationFailed) || authenticated.Valid() {
		t.Fatalf("AuthenticateTx(revoked certificate) = %#v, %v", authenticated, err)
	}
}

func assertRealRunnerRevocationReceipt(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	want credential.RunnerRevocationReceipt,
	fence credential.ClaimFence,
) {
	t.Helper()
	var outcome, claimTokenSHA256, receiptHash, certificateSHA256 string
	var heartbeatSequence int64
	if err := database.QueryRow(ctx, `
		SELECT outcome, claim_token_sha256, receipt_hash, certificate_sha256, heartbeat_seq
		FROM credential_revocation_receipts
		WHERE revocation_id = $1 AND claim_epoch = $2
	`, fence.RevocationID, fence.Epoch).Scan(
		&outcome, &claimTokenSHA256, &receiptHash, &certificateSHA256, &heartbeatSequence,
	); err != nil || outcome != string(want.Outcome) || claimTokenSHA256 != credential.SHA256Hex([]byte(fence.Token)) ||
		receiptHash != want.ReceiptHash || certificateSHA256 != want.CertificateSHA256 ||
		heartbeatSequence != want.HeartbeatSequence {
		t.Fatalf("real Runner revocation receipt = %s/%s/%s/%s/seq-%d, want %#v, %v",
			outcome, claimTokenSHA256, receiptHash, certificateSHA256, heartbeatSequence, want, err)
	}
}

func assertRawRevocationTokenNotPersisted(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	fence credential.ClaimFence,
) {
	t.Helper()
	var storedDigest string
	var parentLeak, receiptLeak, auditLeak, outboxLeak bool
	if err := database.QueryRow(ctx, `
		SELECT COALESCE(
			parent.claim_token_sha256,
			parent.completed_claim_token_sha256,
			(SELECT receipt.claim_token_sha256 FROM credential_revocation_receipts AS receipt
			 WHERE receipt.revocation_id = $1 AND receipt.claim_epoch = $3)
		),
			strpos(to_jsonb(parent)::text, $2) > 0,
			EXISTS (SELECT 1 FROM credential_revocation_receipts AS receipt
				WHERE receipt.revocation_id = $1 AND strpos(to_jsonb(receipt)::text, $2) > 0),
			EXISTS (SELECT 1 FROM audit_records AS audit
				WHERE audit.resource_id = $1::text AND strpos(to_jsonb(audit)::text, $2) > 0),
			EXISTS (SELECT 1 FROM outbox_events AS event
				WHERE event.aggregate_id = $1::uuid AND strpos(to_jsonb(event)::text, $2) > 0)
		FROM credential_revocations AS parent WHERE parent.revocation_id = $1
	`, fence.RevocationID, fence.Token, fence.Epoch).Scan(
		&storedDigest, &parentLeak, &receiptLeak, &auditLeak, &outboxLeak,
	); err != nil || storedDigest != credential.SHA256Hex([]byte(fence.Token)) ||
		parentLeak || receiptLeak || auditLeak || outboxLeak {
		t.Fatalf("raw Runner revocation token persistence = digest-match-%t leaks=%t/%t/%t/%t, %v",
			storedDigest == credential.SHA256Hex([]byte(fence.Token)),
			parentLeak, receiptLeak, auditLeak, outboxLeak, err)
	}
}

func exerciseCredentialSystemRecoveryReceipts(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	queue execution.ActionQueue,
	repository *credentialpostgres.Repository,
	signer action.Signer,
	tenantID, workspaceID, environmentID, serviceID, runnerID string,
) {
	t.Helper()
	const exhaustedDetailHash = "5797f0f8a568d5f215e18706d1e9e08a55101b1ba68ced7926e77a6c253359fe"

	// The system receipt is not an application-write API. Even a row with a
	// plausible shape is rejected unless it originates inside the parent
	// transition trigger.
	expectSQLConstraint(t, ctx, database, "55000", "credential_revocation_system_receipts_insert_guard", `
		INSERT INTO credential_revocation_system_receipts (
			revocation_id, claim_epoch, recovery_kind, claimed_by, claim_token_sha256,
			heartbeat_seq, attempt, retry_cycle_attempt_base, retry_cycle_started_at,
			claim_expires_at, prior_failure_count, failure_count, failure_code,
			failure_detail_sha256, parent_version, manual_required_at
		) VALUES (
			'95100000-0000-4000-8000-000000000099', 1, 'EXHAUSTED_WITHOUT_ACK',
			$1, repeat('1', 64), 0, 12, 0, statement_timestamp() - interval '3 hours',
			statement_timestamp() - interval '1 minute', 0, 1, 'UNKNOWN', $2, 2,
			statement_timestamp()
		)
	`, runnerID, exhaustedDetailHash)

	// Corrupt only the encrypted blob while it is pending. M3 must keep the
	// canonical REVOKING claim until its database-owned 30-second lease expires,
	// emit a redacted alert in the same transaction, and never return the raw
	// claim token or a protected accessor to the caller.
	const protectedActionID = "94100000-0000-4000-8000-000000000001"
	const protectedRevocationID = "95100000-0000-4000-8000-000000000001"
	prepareM3ClaimableRevocation(t, ctx, database, queue, repository, signer,
		protectedActionID, protectedRevocationID, workspaceID, environmentID, serviceID,
		"payments-m3-protected-reference", 'd', runnerID)
	execSQL(t, ctx, database, `
		UPDATE credential_revocations
		SET accessor_ciphertext = decode(repeat('00', 29), 'hex'),
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1
	`, protectedRevocationID)
	claims, err := repository.ClaimRevocations(ctx, credential.ClaimRevocationsRequest{
		WorkerID: runnerID, Limit: 1, LeaseDuration: 30 * time.Second,
	})
	for index := range claims {
		claims[index].Accessor.Destroy()
	}
	if err != nil || len(claims) != 0 {
		t.Fatalf("claim poisoned M3 protected reference = %#v, %v; want retained lease without secret", claims, err)
	}
	var poisonStatus, poisonClaimedBy, poisonClaimTokenSHA256 string
	var poisonAttempt int
	var poisonClaimedAt, poisonHeartbeatAt, poisonClaimExpiresAt time.Time
	if err := database.QueryRow(ctx, `
		SELECT status, claimed_by, claim_token_sha256, attempt,
			claimed_at, last_heartbeat_at, claim_expires_at
		FROM credential_revocations WHERE revocation_id = $1
	`, protectedRevocationID).Scan(
		&poisonStatus, &poisonClaimedBy, &poisonClaimTokenSHA256, &poisonAttempt,
		&poisonClaimedAt, &poisonHeartbeatAt, &poisonClaimExpiresAt,
	); err != nil || poisonStatus != string(credential.StatusRevoking) || poisonClaimedBy != runnerID ||
		len(poisonClaimTokenSHA256) != 64 || poisonAttempt != 1 ||
		!poisonClaimedAt.Equal(poisonHeartbeatAt) || poisonClaimExpiresAt.Sub(poisonClaimedAt) != 30*time.Second {
		t.Fatalf("retained poison claim = %s/%s/%s attempt=%d times=%s/%s/%s err=%v",
			poisonStatus, poisonClaimedBy, poisonClaimTokenSHA256, poisonAttempt,
			poisonClaimedAt, poisonHeartbeatAt, poisonClaimExpiresAt, err)
	}
	var poisonSystemReceipts, poisonAuditAlerts, poisonOutboxAlerts int
	var poisonAlertPayload string
	if err := database.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM credential_revocation_system_receipts WHERE revocation_id = $1),
			(SELECT count(*) FROM audit_records
			 WHERE resource_id = $1::text AND action = 'credential.revocation.protected_reference_unavailable'),
			(SELECT count(*) FROM outbox_events
			 WHERE aggregate_id = $1 AND event_type = 'credential.revocation.protected_reference_unavailable.v1'),
			(SELECT payload::text FROM outbox_events
			 WHERE aggregate_id = $1 AND event_type = 'credential.revocation.protected_reference_unavailable.v1')
	`, protectedRevocationID).Scan(
		&poisonSystemReceipts, &poisonAuditAlerts, &poisonOutboxAlerts, &poisonAlertPayload,
	); err != nil || poisonSystemReceipts != 0 || poisonAuditAlerts != 1 || poisonOutboxAlerts != 1 ||
		strings.Contains(poisonAlertPayload, "claim_token") || strings.Contains(poisonAlertPayload, "accessor") ||
		strings.Contains(poisonAlertPayload, "ciphertext") {
		t.Fatalf("poison alert evidence = receipts=%d audit=%d outbox=%d payload=%q err=%v",
			poisonSystemReceipts, poisonAuditAlerts, poisonOutboxAlerts, poisonAlertPayload, err)
	}

	// A live protected-reference error is not external proof of revocation. It
	// cannot transition the parent or manufacture a system receipt.
	manualTransition := `
		UPDATE credential_revocations
		SET status = 'MANUAL_REQUIRED',
			claimed_by = NULL, claim_token_sha256 = NULL, claimed_at = NULL,
			claim_expires_at = NULL, last_heartbeat_at = NULL,
			failure_count = failure_count + 1, failure_code = $2,
			failure_detail_sha256 = $3,
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1
	`
	expectDeferredConstraintAtCommit(t, ctx, database, "credential_revocations_completion_receipt_guard",
		manualTransition, protectedRevocationID, string(credential.FailureInvalidReference),
		credential.SHA256Hex([]byte(credential.FailureDetailProtectedRefInvalid)))

	// A nested relay reaches trigger depth two, but a fabricated exhausted row
	// still cannot match a committed parent transition at the deferred boundary.
	execSQL(t, ctx, database, `
		CREATE TABLE m3_system_receipt_relay (id integer PRIMARY KEY);
		CREATE FUNCTION relay_m3_system_receipt() RETURNS trigger AS $$
		BEGIN
			INSERT INTO credential_revocation_system_receipts (
				revocation_id, claim_epoch, recovery_kind, claimed_by, claim_token_sha256,
				heartbeat_seq, attempt, retry_cycle_attempt_base, retry_cycle_started_at,
				claimed_at, last_heartbeat_at, claim_expires_at,
				prior_failure_count, failure_count, failure_code, failure_detail_sha256,
				parent_version, manual_required_at
			)
			SELECT revocation_id, claim_epoch, 'EXHAUSTED_WITHOUT_ACK', claimed_by,
				claim_token_sha256, heartbeat_seq, retry_cycle_attempt_base + 12,
				retry_cycle_attempt_base, clock_timestamp() - interval '3 hours',
				clock_timestamp() - interval '2 minutes', clock_timestamp() - interval '2 minutes',
				clock_timestamp() - interval '1 minute', failure_count, failure_count + 1,
				'UNKNOWN', '`+exhaustedDetailHash+`', version + 1, clock_timestamp()
			FROM credential_revocations WHERE revocation_id = '`+protectedRevocationID+`'::uuid;
			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER relay_m3_system_receipt
		AFTER INSERT ON m3_system_receipt_relay
		FOR EACH ROW EXECUTE FUNCTION relay_m3_system_receipt();
	`)
	expectDeferredConstraintAtCommit(t, ctx, database, "credential_revocation_system_receipts_final_shape", `
		INSERT INTO m3_system_receipt_relay (id) VALUES (1)
	`)
	execSQL(t, ctx, database, `
		DROP TRIGGER relay_m3_system_receipt ON m3_system_receipt_relay;
		DROP FUNCTION relay_m3_system_receipt();
		DROP TABLE m3_system_receipt_relay;
	`)

	exhaustM3CredentialClaim(t, ctx, database, protectedRevocationID)
	recovered, err := repository.RecoverExhausted(ctx, credential.RecoverExhaustedRequest{Limit: 10})
	if err != nil || len(recovered) != 1 || recovered[0].ID != protectedRevocationID {
		t.Fatalf("recover poisoned M3 credential after exhaustion = %#v, %v", recovered, err)
	}
	assertCredentialSystemRecoveryReceipt(t, ctx, database, protectedRevocationID,
		"EXHAUSTED_WITHOUT_ACK", string(credential.FailureUnknown), exhaustedDetailHash)

	const exhaustedActionID = "94100000-0000-4000-8000-000000000002"
	const exhaustedRevocationID = "95100000-0000-4000-8000-000000000002"
	prepareM3ClaimableRevocation(t, ctx, database, queue, repository, signer,
		exhaustedActionID, exhaustedRevocationID, workspaceID, environmentID, serviceID,
		"payments-m3-exhausted-recovery", '3', runnerID)
	claims, err = repository.ClaimRevocations(ctx, credential.ClaimRevocationsRequest{
		WorkerID: runnerID, Limit: 1, LeaseDuration: 30 * time.Second,
	})
	if err != nil || len(claims) != 1 || claims[0].Revocation.ID != exhaustedRevocationID {
		t.Fatalf("claim M3 exhausted fixture = %#v, %v", claims, err)
	}
	claims[0].Accessor.Destroy()

	// A still-live claim cannot masquerade as crash recovery even with the
	// canonical UNKNOWN detail hash.
	expectDeferredConstraintAtCommit(t, ctx, database, "credential_revocations_completion_receipt_guard",
		manualTransition, exhaustedRevocationID, string(credential.FailureUnknown), exhaustedDetailHash)
	// Privileged fixture setup expires the already-authenticated claim without
	// exhausting its retry cycle. Expiry alone is not sufficient proof.
	execSQL(t, ctx, database, `ALTER TABLE credential_revocations DISABLE TRIGGER credential_revocations_heartbeat_sequence_guard`)
	execSQL(t, ctx, database, `ALTER TABLE credential_revocations DISABLE TRIGGER credential_revocations_state_machine`)
	execSQL(t, ctx, database, `
		UPDATE credential_revocations
		SET claimed_at = statement_timestamp() - interval '3 minutes',
			last_heartbeat_at = statement_timestamp() - interval '2 minutes',
			claim_expires_at = statement_timestamp() - interval '1 minute',
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1 AND status = 'REVOKING'
	`, exhaustedRevocationID)
	execSQL(t, ctx, database, `ALTER TABLE credential_revocations ENABLE TRIGGER credential_revocations_state_machine`)
	execSQL(t, ctx, database, `ALTER TABLE credential_revocations ENABLE TRIGGER credential_revocations_heartbeat_sequence_guard`)
	expectDeferredConstraintAtCommit(t, ctx, database, "credential_revocations_completion_receipt_guard",
		manualTransition, exhaustedRevocationID, string(credential.FailureUnknown), exhaustedDetailHash)

	// Privileged fixture setup now exhausts the retry counter. Production
	// callers cannot disable these triggers; this only constructs the exact
	// pre-crash row needed to exercise RecoverExhausted with database time.
	execSQL(t, ctx, database, `ALTER TABLE credential_revocations DISABLE TRIGGER credential_revocations_heartbeat_sequence_guard`)
	execSQL(t, ctx, database, `ALTER TABLE credential_revocations DISABLE TRIGGER credential_revocations_state_machine`)
	execSQL(t, ctx, database, `
		UPDATE credential_revocations
		SET attempt = retry_cycle_attempt_base + 12,
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1 AND status = 'REVOKING'
	`, exhaustedRevocationID)
	execSQL(t, ctx, database, `ALTER TABLE credential_revocations ENABLE TRIGGER credential_revocations_state_machine`)
	execSQL(t, ctx, database, `ALTER TABLE credential_revocations ENABLE TRIGGER credential_revocations_heartbeat_sequence_guard`)

	// An expired/exhausted row with the wrong detail still has no proof.
	expectDeferredConstraintAtCommit(t, ctx, database, "credential_revocations_completion_receipt_guard",
		manualTransition, exhaustedRevocationID, string(credential.FailureUnknown), strings.Repeat("e", 64))

	var revocationCertificateSHA256 string
	var revocationScopeRevision int64
	if err := database.QueryRow(ctx, `
		SELECT certificate.certificate_sha256, registration.scope_revision
		FROM runner_certificates AS certificate
		JOIN runner_registrations AS registration USING (runner_id, tenant_id)
		WHERE certificate.runner_id = $1 AND certificate.status = 'ACTIVE'
		ORDER BY certificate.certificate_sha256
		LIMIT 1
	`, runnerID).Scan(&revocationCertificateSHA256, &revocationScopeRevision); err != nil {
		t.Fatalf("read active identity for dual revocation proof: %v", err)
	}
	// Give the exhausted fixture one final short active window. The Runner child
	// is accepted during that window; after it expires, the same transaction's
	// database-verifiable recovery creates the system child. Both are
	// individually valid, but the deferred XOR guards must reject them together.
	execSQL(t, ctx, database, `ALTER TABLE credential_revocations DISABLE TRIGGER credential_revocations_heartbeat_sequence_guard`)
	execSQL(t, ctx, database, `ALTER TABLE credential_revocations DISABLE TRIGGER credential_revocations_state_machine`)
	execSQL(t, ctx, database, `
		UPDATE credential_revocations
		SET claim_expires_at = clock_timestamp() + interval '3 seconds',
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1 AND status = 'REVOKING'
	`, exhaustedRevocationID)
	execSQL(t, ctx, database, `ALTER TABLE credential_revocations ENABLE TRIGGER credential_revocations_state_machine`)
	execSQL(t, ctx, database, `ALTER TABLE credential_revocations ENABLE TRIGGER credential_revocations_heartbeat_sequence_guard`)
	expectDeferredConstraintAtCommit(t, ctx, database, "credential_revocation_receipts_final_shape", `
		INSERT INTO credential_revocation_receipts (
			revocation_id, claim_epoch, tenant_id, workspace_id, environment_id,
			runner_id, scope_revision, certificate_sha256, issuer, issuer_revision, claim_token_sha256,
			heartbeat_seq, outcome, failure_count, failure_code, failure_detail_sha256, receipt_hash
		)
		SELECT revocation_id, claim_epoch, tenant_id, workspace_id, environment_id,
			claimed_by, $2, $3, issuer, issuer_revision, claim_token_sha256,
			heartbeat_seq, 'FAILED', failure_count + 1, 'UNKNOWN', $4, repeat('b', 64)
		FROM credential_revocations WHERE revocation_id = $1;
		SELECT pg_sleep_until(claim_expires_at + interval '10 milliseconds')
		FROM credential_revocations WHERE revocation_id = $1;
		UPDATE credential_revocations
		SET status = 'MANUAL_REQUIRED',
			claimed_by = NULL, claim_token_sha256 = NULL, claimed_at = NULL,
			claim_expires_at = NULL, last_heartbeat_at = NULL,
			failure_count = failure_count + 1, failure_code = 'UNKNOWN',
			failure_detail_sha256 = $4,
			manual_required_at = statement_timestamp(),
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1;
	`, exhaustedRevocationID, revocationScopeRevision, revocationCertificateSHA256, exhaustedDetailHash)

	recovered, err = repository.RecoverExhausted(ctx, credential.RecoverExhaustedRequest{Limit: 10})
	if err != nil || len(recovered) != 1 || recovered[0].ID != exhaustedRevocationID {
		t.Fatalf("recover exhausted M3 credential = %#v, %v", recovered, err)
	}
	assertCredentialSystemRecoveryReceipt(t, ctx, database, exhaustedRevocationID,
		"EXHAUSTED_WITHOUT_ACK", string(credential.FailureUnknown), exhaustedDetailHash)

	for _, revocationID := range []string{protectedRevocationID, exhaustedRevocationID} {
		expectSQLConstraint(t, ctx, database, "55000", "credential_revocation_system_receipts_immutable_guard", `
			UPDATE credential_revocation_system_receipts
			SET failure_detail_sha256 = repeat('0', 64) WHERE revocation_id = $1
		`, revocationID)
		expectSQLConstraint(t, ctx, database, "55000", "credential_revocation_system_receipts_immutable_guard", `
			DELETE FROM credential_revocation_system_receipts WHERE revocation_id = $1
		`, revocationID)
	}
}

func exhaustM3CredentialClaim(t *testing.T, ctx context.Context, database *pgxpool.Pool, revocationID string) {
	t.Helper()
	execSQL(t, ctx, database, `ALTER TABLE credential_revocations DISABLE TRIGGER credential_revocations_heartbeat_sequence_guard`)
	execSQL(t, ctx, database, `ALTER TABLE credential_revocations DISABLE TRIGGER credential_revocations_state_machine`)
	execSQL(t, ctx, database, `
		UPDATE credential_revocations
		SET claimed_at = statement_timestamp() - interval '3 minutes',
			last_heartbeat_at = statement_timestamp() - interval '2 minutes',
			claim_expires_at = statement_timestamp() - interval '1 minute',
			attempt = retry_cycle_attempt_base + 12,
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1 AND status = 'REVOKING'
	`, revocationID)
	execSQL(t, ctx, database, `ALTER TABLE credential_revocations ENABLE TRIGGER credential_revocations_state_machine`)
	execSQL(t, ctx, database, `ALTER TABLE credential_revocations ENABLE TRIGGER credential_revocations_heartbeat_sequence_guard`)
}

func prepareM3ClaimableRevocation(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	queue execution.ActionQueue,
	repository *credentialpostgres.Repository,
	signer action.Signer,
	actionID, revocationID, workspaceID, environmentID, serviceID, target string,
	fill byte,
	runnerID string,
) credential.ActionFence {
	t.Helper()
	fence := claimStartedCredentialAction(t, ctx, database, queue, signer,
		actionID, workspaceID, environmentID, serviceID, target, fill, runnerID)
	prepared, err := repository.Prepare(ctx, credential.PrepareRequest{
		RevocationID: revocationID, Fence: fence, Issuer: "vault-m3-system-recovery",
		IssuerRevision: "rev-1", CredentialExpiresAt: time.Now().UTC().Add(5 * time.Minute),
	})
	if err != nil || !prepared.Created || prepared.Permit == nil {
		t.Fatalf("prepare M3 system recovery credential = %#v, %v", prepared, err)
	}
	if _, err := repository.AuthorizeChildCreate(ctx, credential.AuthorizeChildCreateRequest{
		Permit: *prepared.Permit, Fence: fence,
	}); err != nil {
		t.Fatalf("authorize M3 system recovery child create: %v", err)
	}
	accessor, err := credential.NewSensitiveReference([]byte("m3-system-recovery-" + revocationID))
	if err != nil {
		t.Fatalf("create M3 system recovery accessor: %v", err)
	}
	if _, err := repository.RecordAnchor(ctx, credential.RecordAnchorRequest{
		RevocationID: revocationID, Fence: fence, Accessor: accessor,
	}); err != nil {
		accessor.Destroy()
		t.Fatalf("anchor M3 system recovery credential: %v", err)
	}
	accessor.Destroy()
	if _, err := repository.RequestRevocation(ctx, credential.ActionTransitionRequest{
		RevocationID: revocationID, Fence: fence,
	}); err != nil {
		t.Fatalf("request M3 system recovery revocation: %v", err)
	}
	return fence
}

func assertCredentialSystemRecoveryReceipt(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	revocationID, wantKind, wantFailureCode, wantDetailHash string,
) {
	t.Helper()
	var status, failureCode, detailHash, kind string
	var failureCount, priorFailureCount int
	if err := database.QueryRow(ctx, `
		SELECT parent.status, parent.failure_count, parent.failure_code, parent.failure_detail_sha256,
			receipt.recovery_kind, receipt.prior_failure_count
		FROM credential_revocations AS parent
		JOIN credential_revocation_system_receipts AS receipt
		  ON receipt.revocation_id = parent.revocation_id
		WHERE parent.revocation_id = $1
	`, revocationID).Scan(&status, &failureCount, &failureCode, &detailHash, &kind, &priorFailureCount); err != nil ||
		status != string(credential.StatusManualRequired) || kind != wantKind || failureCode != wantFailureCode ||
		detailHash != wantDetailHash || failureCount != priorFailureCount+1 {
		t.Fatalf("system recovery receipt %s = status=%s failures=%d/%d code=%s detail=%s kind=%s err=%v",
			revocationID, status, priorFailureCount, failureCount, failureCode, detailHash, kind, err)
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
	for _, runnerID := range []string{
		"runner-postgres-fixture-authorized-expired",
		"runner-postgres-fixture-no-credential",
		"runner-postgres-fixture-authorized-guard",
		"runner-postgres-fixture-recovery-before",
		"runner-postgres-fixture-recovery-expired",
		"runner-postgres-fixture-recovery-rollback",
	} {
		registerRealWriteRunner(t, ctx, database, runnerID, tenantID, workspaceID, environmentID)
	}
	exerciseRealActionQueueProofGuards(t, ctx, database, queue, signer, workspaceID, environmentID, serviceID)
	exerciseRealActionQueueIdentityGuards(t, ctx, database, queue, signer, workspaceID, environmentID, serviceID)
	exerciseRealProductionWriteHardOff(t, ctx, database, queue, signer, workspaceID, environmentID, serviceID)
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
	// Both non-production jobs intentionally address the same target. The
	// target lock, rather than the removed global production slot, must select
	// exactly one concurrent winner.
	submissions[1].TargetKey = submissions[0].TargetKey
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
		t.Fatalf("real same-target claim winners=%d blocked=%d claim=%#v", winners, blocked, claimed)
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
	recordNoCredentialForAction(t, ctx, database, fence,
		"93000000-0000-4000-8000-000000000001")
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
	recordNoCredentialForAction(t, ctx, database, secondFence,
		"93000000-0000-4000-8000-000000000002")
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
	third.TargetKey = submissions[0].TargetKey
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
		t.Fatalf("FINALIZING released same-target lock: %v", err)
	}
	secondUncertain, err := queue.Finalize(ctx, secondFence)
	if err != nil || secondUncertain.Status != executionlease.StatusUncertain {
		t.Fatalf("real ActionQueue.Finalize(cancelled running) = %#v, %v", secondUncertain, err)
	}
	if _, err := queue.Claim(ctx, blockedClaim); !errors.Is(err, executionlease.ErrNoLeaseAvailable) {
		t.Fatalf("UNCERTAIN released same-target lock: %v", err)
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
	recordNoCredentialForAction(t, ctx, database, thirdClaim.Execution.Fence(),
		"93000000-0000-4000-8000-000000000003")
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
	expectSQLConstraint(t, ctx, database, "55000", "action_queue_terminal_immutable_guard", `
		UPDATE action_queue
		SET reconciliation_id = 'incomplete-reconciliation', reconciliation_actor = NULL,
			reconciliation_result_hash = $2, reconciled_at = statement_timestamp()
		WHERE action_id = $1
	`, claimed.Execution.ExecutionID, strings.Repeat("f", 64))
	expectSQLConstraint(t, ctx, database, "55000", "action_queue_terminal_immutable_guard", `
		UPDATE action_queue
		SET completed_lease_token_sha256 = NULL, completed_lease_epoch = NULL
		WHERE action_id = $1
	`, claimed.Execution.ExecutionID)
	expectSQLConstraint(t, ctx, database, "55000", "action_queue_terminal_immutable_guard", `
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
	expectSQLConstraint(t, ctx, database, "55000", "action_queue_terminal_immutable_guard", `
		UPDATE action_queue
		SET runner_id = 'runner-postgres-1', runner_tenant_id = $2,
			runner_workspace_id = $3, runner_environment_id = $4
		WHERE action_id = $1
	`, shapeSubmission.Envelope.ActionID, tenantID, workspaceID, environmentID)
}

func exerciseRealActionQueueProofGuards(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	queue execution.ActionQueue,
	signer action.Signer,
	workspaceID, environmentID, serviceID string,
) {
	t.Helper()

	rejectedSubmission := realActionSubmission(t, signer, time.Now().UTC(),
		"90000000-0000-4000-8000-000000000085", workspaceID, environmentID, serviceID,
		"payments-proof-reject", '4')
	if _, err := queue.Submit(ctx, rejectedSubmission); err != nil {
		t.Fatalf("submit rejection proof fixture: %v", err)
	}
	rejectedClaim, err := queue.Claim(ctx, execution.ActionClaimRequest{
		Scope: realRunnerScope(t, ctx, database, "runner-postgres-5"), LeaseDuration: time.Minute,
	})
	if err != nil || rejectedClaim.Execution.ExecutionID != rejectedSubmission.Envelope.ActionID {
		t.Fatalf("claim rejection proof fixture = %#v, %v", rejectedClaim, err)
	}
	expectSQLConstraint(t, ctx, database, "55000", "action_queue_active_fence_guard", `
		UPDATE action_queue
		SET status = 'FAILED', completion_status = 'FAILED', result_hash = repeat('1', 64),
			completed_lease_token_sha256 = repeat('0', 64), completed_lease_epoch = lease_epoch,
			lease_token_sha256 = NULL, lease_expires_at = NULL,
			completed_at = statement_timestamp(), updated_at = statement_timestamp()
		WHERE action_id = $1
	`, rejectedSubmission.Envelope.ActionID)
	expectSQLConstraint(t, ctx, database, "55000", "action_queue_rejection_proof_guard", `
		UPDATE action_queue
		SET status = 'FAILED', completion_status = 'SUCCEEDED', result_hash = repeat('2', 64),
			completed_lease_token_sha256 = lease_token_sha256, completed_lease_epoch = lease_epoch,
			lease_token_sha256 = NULL, lease_expires_at = NULL,
			completed_at = statement_timestamp(), updated_at = statement_timestamp()
		WHERE action_id = $1
	`, rejectedSubmission.Envelope.ActionID)
	rejected, err := queue.Reject(ctx, execution.ActionRejectRequest{
		Lease:  rejectedClaim.Execution.Fence(),
		Reason: execution.ActionQueueReason{Code: "PROOF_GUARD_REJECTED", DetailHash: strings.Repeat("3", 64)},
	})
	if err != nil || rejected.Status != executionlease.StatusFailed {
		t.Fatalf("Reject(proof guard fixture) = %#v, %v", rejected, err)
	}
	expectSQLConstraint(t, ctx, database, "55000", "action_queue_terminal_immutable_guard", `
		UPDATE action_queue
		SET completed_lease_token_sha256 = repeat('4', 64)
		WHERE action_id = $1
	`, rejectedSubmission.Envelope.ActionID)

	proofSubmission := realActionSubmission(t, signer, time.Now().UTC(),
		"90000000-0000-4000-8000-000000000086", workspaceID, environmentID, serviceID,
		"payments-finalizing-proof", '5')
	if _, err := queue.Submit(ctx, proofSubmission); err != nil {
		t.Fatalf("submit finalizing proof fixture: %v", err)
	}
	proofClaim, err := queue.Claim(ctx, execution.ActionClaimRequest{
		Scope: realRunnerScope(t, ctx, database, "runner-postgres-5"), LeaseDuration: time.Minute,
	})
	if err != nil || proofClaim.Execution.ExecutionID != proofSubmission.Envelope.ActionID {
		t.Fatalf("claim finalizing proof fixture = %#v, %v", proofClaim, err)
	}
	proofFence := proofClaim.Execution.Fence()
	if _, err := queue.Start(ctx, proofFence); err != nil {
		t.Fatalf("start finalizing proof fixture: %v", err)
	}
	expectSQLConstraint(t, ctx, database, "55000", "action_queue_state_transition_guard", `
		UPDATE action_queue SET status = 'SUCCEEDED' WHERE action_id = $1
	`, proofSubmission.Envelope.ActionID)
	expectDeferredConstraintAtCommit(t, ctx, database, "action_queue_finalizing_receipt_shape", `
		UPDATE action_queue
		SET status = 'FINALIZING', completion_status = 'UNCERTAIN', result_hash = repeat('5', 64),
			completed_lease_token_sha256 = lease_token_sha256, completed_lease_epoch = lease_epoch,
			lease_token_sha256 = NULL, lease_expires_at = NULL,
			updated_at = statement_timestamp()
		WHERE action_id = $1
	`, proofSubmission.Envelope.ActionID)
	assertActionStatus(t, ctx, database, proofSubmission.Envelope.ActionID, executionlease.StatusRunning)
	recordNoCredentialForAction(t, ctx, database, proofFence,
		"93000000-0000-4000-8000-000000000007")
	finalizing, err := queue.Complete(ctx, execution.ActionCompleteRequest{
		Lease: proofFence,
		Summary: execution.ExecutorResult{
			Outcome: execution.ExecutorUncertain, Code: "PROOF_GUARD_UNCERTAIN",
			Verification: execution.VerificationUnknown,
		},
	})
	if err != nil || finalizing.Status != executionlease.StatusFinalizing ||
		finalizing.CompletionStatus != executionlease.StatusUncertain {
		t.Fatalf("Complete(uncertain proof fixture) = %#v, %v", finalizing, err)
	}
	expectSQLConstraint(t, ctx, database, "55000", "action_queue_result_receipt_guard", `
		UPDATE action_queue
		SET status = 'FAILED', completed_at = statement_timestamp(), updated_at = statement_timestamp()
		WHERE action_id = $1
	`, proofSubmission.Envelope.ActionID)
	uncertain, err := queue.Finalize(ctx, proofFence)
	if err != nil || uncertain.Status != executionlease.StatusUncertain {
		t.Fatalf("Finalize(uncertain proof fixture) = %#v, %v", uncertain, err)
	}
	expectSQLConstraint(t, ctx, database, "55000", "action_queue_reconciliation_proof_guard", `
		UPDATE action_queue SET status = 'FAILED', updated_at = statement_timestamp() WHERE action_id = $1
	`, proofSubmission.Envelope.ActionID)
	reconciled, err := queue.Reconcile(ctx, executionlease.ReconcileRequest{
		ExecutionID:      proofSubmission.Envelope.ActionID,
		ReconciliationID: "reconcile-postgres-proof-guard",
		ActorID:          "sre-postgres-proof-guard",
		Status:           executionlease.StatusFailed,
		ResultHash:       strings.Repeat("6", 64),
	})
	if err != nil || reconciled.Status != executionlease.StatusFailed {
		t.Fatalf("Reconcile(proof guard fixture) = %#v, %v", reconciled, err)
	}
}

func exerciseRealActionQueueIdentityGuards(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	queue execution.ActionQueue,
	signer action.Signer,
	workspaceID, environmentID, serviceID string,
) {
	t.Helper()
	submissionMutations := []struct {
		name      string
		statement string
	}{
		{name: "action_id", statement: `UPDATE action_queue SET action_id = action_id || '-tampered' WHERE action_id = $1`},
		{name: "envelope", statement: `UPDATE action_queue SET envelope = envelope || '{"tampered":true}'::jsonb WHERE action_id = $1`},
		{name: "submission_hash", statement: `UPDATE action_queue SET submission_hash = repeat('1', 64) WHERE action_id = $1`},
		{name: "idempotency_key", statement: `UPDATE action_queue SET idempotency_key = idempotency_key || '-tampered' WHERE action_id = $1`},
		{name: "request_hash", statement: `UPDATE action_queue SET request_hash = repeat('2', 64) WHERE action_id = $1`},
		{name: "request_hash_version", statement: `UPDATE action_queue SET request_hash_version = 'legacy-submission.v1' WHERE action_id = $1`},
		{name: "plan_hash", statement: `UPDATE action_queue SET plan_hash = repeat('3', 64) WHERE action_id = $1`},
		{name: "workspace_id", statement: `UPDATE action_queue SET workspace_id = workspace_id || '-tampered' WHERE action_id = $1`},
		{name: "environment_id", statement: `UPDATE action_queue SET environment_id = environment_id || '-tampered' WHERE action_id = $1`},
		{name: "target_key", statement: `UPDATE action_queue SET target_key = target_key || '-tampered' WHERE action_id = $1`},
		{name: "environment_revision", statement: `UPDATE action_queue SET environment_revision = environment_revision || '-tampered' WHERE action_id = $1`},
		{name: "authorization_expires_at", statement: `UPDATE action_queue SET authorization_expires_at = authorization_expires_at + interval '1 minute' WHERE action_id = $1`},
		{name: "runner_pool", statement: `UPDATE action_queue SET runner_pool = 'READ' WHERE action_id = $1`},
		{name: "production", statement: `UPDATE action_queue SET production = true WHERE action_id = $1`},
		{name: "created_at", statement: `UPDATE action_queue SET created_at = created_at + interval '1 second' WHERE action_id = $1`},
	}
	assertSubmissionIdentityFrozen := func(state, actionID, targetKey string) {
		t.Helper()
		constraintName := "action_queue_submission_identity_guard"
		if state == "SUCCEEDED" || state == "FAILED" || state == "CANCELLED" {
			constraintName = "action_queue_terminal_immutable_guard"
		}
		for _, test := range submissionMutations {
			t.Run(strings.ToLower(state)+"_submission_"+test.name, func(t *testing.T) {
				expectSQLConstraint(t, ctx, database, "55000", constraintName,
					test.statement, actionID)
				var storedStatus, storedTarget string
				if err := database.QueryRow(ctx, `
					SELECT status, target_key FROM action_queue WHERE action_id = $1
				`, actionID).Scan(&storedStatus, &storedTarget); err != nil {
					t.Fatalf("read %s action after rejected %s mutation: %v", state, test.name, err)
				}
				if storedStatus != state || storedTarget != targetKey {
					t.Fatalf("%s action after rejected %s mutation = status %q target %q, want %q/%q",
						state, test.name, storedStatus, storedTarget, state, targetKey)
				}
			})
		}
	}

	queued := realActionSubmission(t, signer, time.Now().UTC(),
		"90000000-0000-4000-8000-000000000088", workspaceID, environmentID, serviceID,
		"payments-submission-identity-guard", '5')
	if _, err := queue.Submit(ctx, queued); err != nil {
		t.Fatalf("submit queued submission identity fixture: %v", err)
	}
	expectSQLConstraint(t, ctx, database, "55000", "action_queue_history_immutable_guard", `
		DELETE FROM action_queue WHERE action_id = $1
	`, queued.Envelope.ActionID)
	expectSQLConstraint(t, ctx, database, "55000", "action_queue_history_immutable_guard", `
		TRUNCATE action_queue CASCADE
	`)
	assertSubmissionIdentityFrozen("QUEUED", queued.Envelope.ActionID, queued.TargetKey)
	// Scheduling remains mutable without weakening the signed submission.
	execSQL(t, ctx, database, `
		UPDATE action_queue SET not_before = not_before + interval '1 second'
		WHERE action_id = $1
	`, queued.Envelope.ActionID)
	if _, err := queue.Cancel(ctx, queued.Envelope.ActionID); err != nil {
		t.Fatalf("cancel queued submission identity fixture: %v", err)
	}
	assertSubmissionIdentityFrozen("CANCELLED", queued.Envelope.ActionID, queued.TargetKey)

	now := time.Now().UTC()
	holder := realActionSubmission(t, signer, now,
		"90000000-0000-4000-8000-000000000089", workspaceID, environmentID, serviceID,
		"payments-active-fence-holder", '7')
	contender := realActionSubmission(t, signer, now,
		"90000000-0000-4000-8000-000000000090", workspaceID, environmentID, serviceID,
		"payments-active-fence-contender", '8')
	contender.TargetKey = holder.TargetKey
	if _, err := queue.Submit(ctx, holder); err != nil {
		t.Fatalf("submit active fence holder: %v", err)
	}
	if _, err := queue.Submit(ctx, contender); err != nil {
		t.Fatalf("submit active fence contender: %v", err)
	}
	execSQL(t, ctx, database, `
		UPDATE action_queue SET not_before = statement_timestamp() + interval '1 hour'
		WHERE action_id = $1
	`, contender.Envelope.ActionID)
	claimed, err := queue.Claim(ctx, execution.ActionClaimRequest{
		Scope: realRunnerScope(t, ctx, database, "runner-postgres-1"), LeaseDuration: 5 * time.Minute,
	})
	if err != nil || claimed.Execution.ExecutionID != holder.Envelope.ActionID {
		t.Fatalf("claim active fence holder = %#v, %v", claimed, err)
	}
	execSQL(t, ctx, database, `
		UPDATE action_queue SET not_before = statement_timestamp()
		WHERE action_id = $1
	`, contender.Envelope.ActionID)

	assertTargetLocked := func(state string) {
		t.Helper()
		if _, claimErr := queue.Claim(ctx, execution.ActionClaimRequest{
			Scope: realRunnerScope(t, ctx, database, "runner-postgres-2"), LeaseDuration: time.Minute,
		}); !errors.Is(claimErr, executionlease.ErrNoLeaseAvailable) {
			t.Fatalf("%s holder released original target after rejected mutation: %v", state, claimErr)
		}
	}
	assertActiveFenceFrozen := func(state string) {
		t.Helper()
		expectSQLConstraint(t, ctx, database, "55000", "action_queue_history_immutable_guard", `
			DELETE FROM action_queue WHERE action_id = $1
		`, holder.Envelope.ActionID)
		for _, test := range []struct {
			name           string
			constraintName string
			statement      string
		}{
			{name: "target", constraintName: "action_queue_submission_identity_guard", statement: `UPDATE action_queue SET target_key = target_key || '-tampered' WHERE action_id = $1`},
			{name: "runner", constraintName: "action_queue_active_fence_guard", statement: `UPDATE action_queue SET runner_id = NULL WHERE action_id = $1`},
			{name: "tenant", constraintName: "action_queue_active_fence_guard", statement: `UPDATE action_queue SET runner_tenant_id = NULL WHERE action_id = $1`},
			{name: "workspace", constraintName: "action_queue_active_fence_guard", statement: `UPDATE action_queue SET runner_workspace_id = NULL WHERE action_id = $1`},
			{name: "environment", constraintName: "action_queue_active_fence_guard", statement: `UPDATE action_queue SET runner_environment_id = NULL WHERE action_id = $1`},
			{name: "scope", constraintName: "action_queue_active_fence_guard", statement: `UPDATE action_queue SET scope_revision = NULL WHERE action_id = $1`},
			{name: "epoch", constraintName: "action_queue_active_fence_guard", statement: `UPDATE action_queue SET lease_epoch = lease_epoch + 1 WHERE action_id = $1`},
			{name: "token", constraintName: "action_queue_active_fence_guard", statement: `UPDATE action_queue SET lease_token_sha256 = NULL WHERE action_id = $1`},
		} {
			t.Run(strings.ToLower(state)+"_"+test.name, func(t *testing.T) {
				expectSQLConstraint(t, ctx, database, "55000", test.constraintName,
					test.statement, holder.Envelope.ActionID)
			})
		}
		assertTargetLocked(state)
	}
	assertCompletedFenceFrozen := func(state string) {
		t.Helper()
		expectSQLConstraint(t, ctx, database, "55000", "action_queue_history_immutable_guard", `
			DELETE FROM action_queue WHERE action_id = $1
		`, holder.Envelope.ActionID)
		for _, test := range []struct {
			name           string
			constraintName string
			statement      string
		}{
			{name: "target", constraintName: "action_queue_submission_identity_guard", statement: `UPDATE action_queue SET target_key = target_key || '-tampered' WHERE action_id = $1`},
			{name: "runner", constraintName: "action_queue_active_fence_guard", statement: `UPDATE action_queue SET runner_id = NULL WHERE action_id = $1`},
			{name: "scope", constraintName: "action_queue_active_fence_guard", statement: `UPDATE action_queue SET scope_revision = NULL WHERE action_id = $1`},
			{name: "epoch", constraintName: "action_queue_active_fence_guard", statement: `UPDATE action_queue SET lease_epoch = lease_epoch + 1 WHERE action_id = $1`},
			{name: "completed_epoch", constraintName: "action_queue_active_fence_guard", statement: `UPDATE action_queue SET completed_lease_epoch = NULL WHERE action_id = $1`},
			{name: "completed_token", constraintName: "action_queue_active_fence_guard", statement: `UPDATE action_queue SET completed_lease_token_sha256 = NULL WHERE action_id = $1`},
		} {
			t.Run(strings.ToLower(state)+"_"+test.name, func(t *testing.T) {
				expectSQLConstraint(t, ctx, database, "55000", test.constraintName,
					test.statement, holder.Envelope.ActionID)
			})
		}
		assertTargetLocked(state)
	}

	assertSubmissionIdentityFrozen("LEASED", holder.Envelope.ActionID, holder.TargetKey)
	assertActiveFenceFrozen("LEASED")
	fence := claimed.Execution.Fence()
	if _, err := queue.Start(ctx, fence); err != nil {
		t.Fatalf("start active fence holder: %v", err)
	}
	assertSubmissionIdentityFrozen("RUNNING", holder.Envelope.ActionID, holder.TargetKey)
	assertActiveFenceFrozen("RUNNING")
	for _, test := range []struct {
		name      string
		statement string
	}{
		{
			name: "substituted_completed_token",
			statement: `
				UPDATE action_queue
				SET status = 'FINALIZING', completion_status = 'UNCERTAIN', result_hash = repeat('4', 64),
					completed_lease_token_sha256 = repeat('0', 64), completed_lease_epoch = lease_epoch,
					lease_token_sha256 = NULL, lease_expires_at = NULL
				WHERE action_id = $1
			`,
		},
		{
			name: "substituted_completed_epoch",
			statement: `
				UPDATE action_queue
				SET status = 'FINALIZING', completion_status = 'UNCERTAIN', result_hash = repeat('4', 64),
					completed_lease_token_sha256 = lease_token_sha256, completed_lease_epoch = lease_epoch + 1,
					lease_token_sha256 = NULL, lease_expires_at = NULL
				WHERE action_id = $1
			`,
		},
	} {
		t.Run("running_transition_"+test.name, func(t *testing.T) {
			expectSQLConstraint(t, ctx, database, "55000", "action_queue_active_fence_guard",
				test.statement, holder.Envelope.ActionID)
		})
	}
	recordNoCredentialForAction(t, ctx, database, fence,
		"93000000-0000-4000-8000-000000000005")
	completion := execution.ActionCompleteRequest{
		Lease: fence,
		Summary: execution.ExecutorResult{
			Outcome: execution.ExecutorUncertain, Code: "IDENTITY_GUARD_FIXTURE",
			Verification: execution.VerificationUnknown,
		},
	}
	if finalizing, err := queue.Complete(ctx, completion); err != nil || finalizing.Status != executionlease.StatusFinalizing {
		t.Fatalf("complete active fence holder = %#v, %v", finalizing, err)
	}
	assertSubmissionIdentityFrozen("FINALIZING", holder.Envelope.ActionID, holder.TargetKey)
	assertCompletedFenceFrozen("FINALIZING")
	if uncertain, err := queue.Finalize(ctx, fence); err != nil || uncertain.Status != executionlease.StatusUncertain {
		t.Fatalf("finalize active fence holder = %#v, %v", uncertain, err)
	}
	assertSubmissionIdentityFrozen("UNCERTAIN", holder.Envelope.ActionID, holder.TargetKey)
	assertCompletedFenceFrozen("UNCERTAIN")
	if _, err := queue.Reconcile(ctx, executionlease.ReconcileRequest{
		ExecutionID:      holder.Envelope.ActionID,
		ReconciliationID: "reconcile-postgres-identity-guard", ActorID: "sre-postgres-identity-guard",
		Status: executionlease.StatusFailed, ResultHash: strings.Repeat("9", 64),
	}); err != nil {
		t.Fatalf("reconcile active fence holder: %v", err)
	}
	assertSubmissionIdentityFrozen("FAILED", holder.Envelope.ActionID, holder.TargetKey)
	expectSQLConstraint(t, ctx, database, "55000", "action_queue_history_immutable_guard", `
		DELETE FROM action_queue WHERE action_id = $1
	`, holder.Envelope.ActionID)
	contenderClaim, err := queue.Claim(ctx, execution.ActionClaimRequest{
		Scope: realRunnerScope(t, ctx, database, "runner-postgres-2"), LeaseDuration: time.Minute,
	})
	if err != nil || contenderClaim.Execution.ExecutionID != contender.Envelope.ActionID {
		t.Fatalf("claim contender after reconciliation = %#v, %v", contenderClaim, err)
	}
	if _, err := queue.Cancel(ctx, contender.Envelope.ActionID); err != nil {
		t.Fatalf("cancel active fence contender: %v", err)
	}

	succeeded := realActionSubmission(t, signer, time.Now().UTC(),
		"90000000-0000-4000-8000-000000000087", workspaceID, environmentID, serviceID,
		"payments-submission-identity-succeeded", '0')
	if _, err := queue.Submit(ctx, succeeded); err != nil {
		t.Fatalf("submit succeeded submission identity fixture: %v", err)
	}
	succeededClaim, err := queue.Claim(ctx, execution.ActionClaimRequest{
		Scope: realRunnerScope(t, ctx, database, "runner-postgres-1"), LeaseDuration: time.Minute,
	})
	if err != nil || succeededClaim.Execution.ExecutionID != succeeded.Envelope.ActionID {
		t.Fatalf("claim succeeded submission identity fixture = %#v, %v", succeededClaim, err)
	}
	succeededFence := succeededClaim.Execution.Fence()
	if _, err := queue.Start(ctx, succeededFence); err != nil {
		t.Fatalf("start succeeded submission identity fixture: %v", err)
	}
	recordNoCredentialForAction(t, ctx, database, succeededFence,
		"93000000-0000-4000-8000-000000000006")
	if finalizing, err := queue.Complete(ctx, execution.ActionCompleteRequest{
		Lease: succeededFence,
		Summary: execution.ExecutorResult{
			Outcome: execution.ExecutorSucceeded, Code: "IDENTITY_GUARD_SUCCEEDED",
			Verification: execution.VerificationPassed,
		},
	}); err != nil || finalizing.Status != executionlease.StatusFinalizing {
		t.Fatalf("complete succeeded submission identity fixture = %#v, %v", finalizing, err)
	}
	if terminal, err := queue.Finalize(ctx, succeededFence); err != nil || terminal.Status != executionlease.StatusSucceeded {
		t.Fatalf("finalize succeeded submission identity fixture = %#v, %v", terminal, err)
	}
	assertSubmissionIdentityFrozen("SUCCEEDED", succeeded.Envelope.ActionID, succeeded.TargetKey)
}

func exerciseRealProductionWriteHardOff(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	queue execution.ActionQueue,
	signer action.Signer,
	workspaceID, environmentID, serviceID string,
) {
	t.Helper()
	submission := realActionSubmission(t, signer, time.Now().UTC(),
		"90000000-0000-4000-8000-000000000091", workspaceID, environmentID, serviceID,
		"payments-production-hard-off", '1')
	submission.Production = true
	created, err := queue.Submit(ctx, submission)
	if err != nil || created.Status != executionlease.StatusQueued {
		t.Fatalf("Submit(production WRITE hard-off) = %#v, %v", created, err)
	}
	if _, err := queue.Claim(ctx, execution.ActionClaimRequest{
		Scope: realRunnerScope(t, ctx, database, "runner-postgres-1"), LeaseDuration: time.Minute,
	}); !errors.Is(err, executionlease.ErrNoLeaseAvailable) {
		t.Fatalf("Claim(production WRITE hard-off) error = %v, want ErrNoLeaseAvailable", err)
	}
	stored, err := queue.Get(ctx, submission.Envelope.ActionID)
	if err != nil || stored.Status != executionlease.StatusQueued || stored.RunnerID != "" || stored.LeaseEpoch != 0 {
		t.Fatalf("Get(production WRITE hard-off) = %#v, %v", stored, err)
	}
	var activeProductionWrites int
	if err := database.QueryRow(ctx, `
		SELECT count(*) FROM action_queue
		WHERE runner_pool = 'WRITE' AND production = true
		  AND status IN ('LEASED', 'RUNNING', 'FINALIZING', 'UNCERTAIN')
	`).Scan(&activeProductionWrites); err != nil || activeProductionWrites != 0 {
		t.Fatalf("active production WRITE actions = %d, %v", activeProductionWrites, err)
	}
	cancelled, err := queue.Cancel(ctx, submission.Envelope.ActionID)
	if err != nil || cancelled.Status != executionlease.StatusCancelled {
		t.Fatalf("Cancel(production WRITE hard-off) = %#v, %v", cancelled, err)
	}
}

func registerRealWriteRunner(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	runnerID, tenantID, workspaceID, environmentID string,
) {
	t.Helper()
	execSQL(t, ctx, database, `
		INSERT INTO runner_registrations (
			runner_id, tenant_id, spiffe_uri, runner_pool, enabled, scope_revision, max_concurrency
		) VALUES ($1, $2, 'spiffe://integration.test/runner/write/' || $1, 'WRITE', true, 1, 1)
	`, runnerID, tenantID)
	execSQL(t, ctx, database, `
		INSERT INTO runner_scope_bindings (runner_id, tenant_id, workspace_id, environment_id)
		VALUES ($1, $2, $3, $4)
	`, runnerID, tenantID, workspaceID, environmentID)
	certificateDigest := sha256.Sum256([]byte("integration-runner-certificate/" + runnerID))
	spkiDigest := sha256.Sum256([]byte("integration-runner-spki/" + runnerID))
	serialDigest := sha256.Sum256([]byte("integration-runner-serial/" + runnerID))
	execSQL(t, ctx, database, `
		INSERT INTO runner_certificates (
			certificate_sha256, runner_id, tenant_id, issuer_key_id, serial_hex, spki_sha256,
			status, not_before, not_after
		) VALUES ($1, $2, $3, 'integration-fixture-ca', $4, $5, 'ACTIVE',
			statement_timestamp() - interval '1 minute', statement_timestamp() + interval '1 hour')
	`, hex.EncodeToString(certificateDigest[:]), runnerID, tenantID,
		hex.EncodeToString(serialDigest[:16]), hex.EncodeToString(spkiDigest[:]))
}

// recordNoCredentialForAction exercises the real repository contract inside
// one outer transaction: PREPARED and the exact action marker become visible
// together, then NO_CREDENTIAL is persisted before the transaction commits.
// The deferred database proof is therefore part of the helper's success
// condition; no trigger or constraint is weakened for the integration test.
func recordNoCredentialForAction(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	fence executionlease.LeaseIdentity,
	revocationID string,
) {
	t.Helper()
	protector, err := credential.NewAESGCMProtector(credential.KeyRing{
		ActiveKeyID: "action-finalization-integration-key",
		Keys: map[string]credential.ProtectionKey{
			"action-finalization-integration-key": {
				EncryptionKey: bytes.Repeat([]byte{0x41}, 32),
				HMACKey:       bytes.Repeat([]byte{0x42}, 32),
			},
		},
	})
	if err != nil {
		t.Fatalf("create finalization credential protector: %v", err)
	}
	defer protector.Destroy()
	tx, err := database.Begin(ctx)
	if err != nil {
		t.Fatalf("begin finalization credential transaction: %v", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	repository, err := credentialpostgres.New(tx, protector, credentialpostgres.Options{})
	if err != nil {
		t.Fatalf("create transactional finalization credential repository: %v", err)
	}
	actionFence := credential.ActionFence{
		ActionID: fence.ExecutionID, RunnerID: fence.RunnerID, Token: fence.Token, Epoch: fence.Epoch,
	}
	prepared, err := repository.Prepare(ctx, credential.PrepareRequest{
		RevocationID:        revocationID,
		Fence:               actionFence,
		Issuer:              "integration-no-credential",
		IssuerRevision:      "v1",
		CredentialExpiresAt: time.Now().UTC().Add(5 * time.Minute),
	})
	if err != nil || !prepared.Created || prepared.Permit == nil || prepared.Revocation.Status != credential.StatusPrepared {
		t.Fatalf("Prepare(finalization NO_CREDENTIAL) = %#v, %v", prepared, err)
	}
	terminal, err := repository.RecordNoCredential(ctx, credential.ActionTransitionRequest{
		RevocationID: revocationID, Fence: actionFence,
	})
	if err != nil || terminal.Status != credential.StatusNoCredential {
		t.Fatalf("RecordNoCredential(finalization) = %#v, %v", terminal, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit finalization credential transaction: %v", err)
	}
	committed = true
	var exactTerminalRows int
	if err := database.QueryRow(ctx, `
		SELECT count(*)
		FROM credential_revocations AS credential
		JOIN action_queue AS action
		  ON action.action_id = credential.action_id
		 AND action.runner_tenant_id = credential.tenant_id
		 AND action.runner_workspace_id = credential.workspace_id
		 AND action.runner_environment_id = credential.environment_id
		 AND action.target_key = credential.target_key
		 AND action.production = credential.production
		 AND action.runner_id = credential.runner_id
		 AND action.lease_epoch = credential.action_lease_epoch
		 AND action.lease_token_sha256 = credential.action_lease_token_sha256
		WHERE credential.revocation_id = $1
		  AND credential.status = 'NO_CREDENTIAL'
		  AND action.credential_expected = true
		  AND action.credential_lease_epoch = action.lease_epoch
	`, revocationID).Scan(&exactTerminalRows); err != nil || exactTerminalRows != 1 {
		t.Fatalf("exact terminal credential rows for %s = %d, %v", revocationID, exactTerminalRows, err)
	}
}

func claimStartedCredentialAction(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	queue execution.ActionQueue,
	signer action.Signer,
	actionID, workspaceID, environmentID, serviceID, deployment string,
	digestByte byte,
	runnerID string,
) credential.ActionFence {
	t.Helper()
	submission := realActionSubmission(t, signer, time.Now().UTC(), actionID, workspaceID, environmentID,
		serviceID, deployment, digestByte)
	if _, err := queue.Submit(ctx, submission); err != nil {
		t.Fatalf("submit credential fixture action %s: %v", actionID, err)
	}
	claimed, err := queue.Claim(ctx, execution.ActionClaimRequest{
		Scope: realRunnerScope(t, ctx, database, runnerID), LeaseDuration: time.Minute,
	})
	if err != nil || claimed.Execution.ExecutionID != actionID {
		t.Fatalf("claim credential fixture action %s = %#v, %v", actionID, claimed, err)
	}
	if _, err := queue.Start(ctx, claimed.Execution.Fence()); err != nil {
		t.Fatalf("start credential fixture action %s: %v", actionID, err)
	}
	return credential.ActionFence{
		ActionID: claimed.Execution.ExecutionID,
		RunnerID: claimed.Execution.RunnerID,
		Token:    claimed.Execution.LeaseToken,
		Epoch:    claimed.Execution.LeaseEpoch,
	}
}

// insertPreparedCredentialForAction is reserved for recovery-boundary
// fixtures whose persisted timestamps cannot be produced through Prepare's
// current-time contract. Every row is attached to its own real RUNNING action
// and exact lease fence, and the marker plus deferred proof commit atomically.
func insertPreparedCredentialForAction(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	fence credential.ActionFence,
	revocationID, permitDigest string,
	createdAt, credentialExpiresAt time.Time,
	childCreateAuthorizedAt time.Time,
	childCreateTTL time.Duration,
) {
	t.Helper()
	tx, err := database.Begin(ctx)
	if err != nil {
		t.Fatalf("begin prepared credential fixture %s: %v", revocationID, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	tokenDigest := credential.SHA256Hex([]byte(fence.Token))
	result, err := tx.Exec(ctx, `
		INSERT INTO credential_revocations (
			revocation_id, tenant_id, workspace_id, environment_id,
			action_id, target_key, production, runner_id, action_lease_epoch, action_lease_token_sha256,
			issuer, issuer_revision, action_type, connector_id, scope_permission, scope_resource,
			credential_ttl_seconds, credential_expires_at,
			child_create_permit_sha256, available_at, created_at, updated_at
		)
		SELECT $5, action.runner_tenant_id, action.runner_workspace_id, action.runner_environment_id,
			action.action_id, action.target_key, action.production, action.runner_id, action.lease_epoch,
			action.lease_token_sha256, 'vault-production', 'rev-1', action.envelope ->> 'action_type',
			action.envelope #>> '{credential_scope,connector_id}',
			action.envelope #>> '{credential_scope,permission}',
			action.envelope #>> '{credential_scope,resource}',
			(action.envelope #>> '{credential_scope,ttl_seconds}')::integer,
			$6, $7, $8, $8, $8
		FROM action_queue AS action
		WHERE action.action_id = $1
		  AND action.runner_id = $2
		  AND action.lease_epoch = $3
		  AND action.lease_token_sha256 = $4
		  AND action.runner_pool = 'WRITE'
		  AND action.production = false
		  AND action.status = 'RUNNING'
	`, fence.ActionID, fence.RunnerID, fence.Epoch, tokenDigest, revocationID,
		credentialExpiresAt.UTC(), permitDigest, createdAt.UTC())
	if err != nil || result.RowsAffected() != 1 {
		t.Fatalf("insert prepared credential fixture %s rows=%d: %v", revocationID, result.RowsAffected(), err)
	}
	result, err = tx.Exec(ctx, `
		UPDATE action_queue
		SET credential_expected = true,
			credential_lease_epoch = lease_epoch,
			updated_at = statement_timestamp()
		WHERE action_id = $1
		  AND runner_id = $2
		  AND lease_epoch = $3
		  AND lease_token_sha256 = $4
		  AND status = 'RUNNING'
		  AND credential_expected = false
		  AND credential_lease_epoch IS NULL
	`, fence.ActionID, fence.RunnerID, fence.Epoch, tokenDigest)
	if err != nil || result.RowsAffected() != 1 {
		t.Fatalf("mark prepared credential fixture %s rows=%d: %v", revocationID, result.RowsAffected(), err)
	}
	if !childCreateAuthorizedAt.IsZero() {
		result, err = tx.Exec(ctx, `
			UPDATE credential_revocations
			SET child_create_authorized_at = $2,
				child_create_ttl_seconds = $3,
				updated_at = $2,
				version = version + 1
			WHERE revocation_id = $1 AND status = 'PREPARED'
		`, revocationID, childCreateAuthorizedAt.UTC(), int32(childCreateTTL/time.Second))
		if err != nil || result.RowsAffected() != 1 {
			t.Fatalf("authorize prepared credential fixture %s rows=%d: %v", revocationID, result.RowsAffected(), err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit prepared credential fixture %s: %v", revocationID, err)
	}
	committed = true
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
	recordNoCredentialForAction(t, ctx, database, fence,
		"93000000-0000-4000-8000-000000000004")
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
		EnvironmentRevision: "environment-postgres-1", Production: false, Pool: executionlease.PoolWrite,
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

func exerciseLegacyExecutionLeaseUpgradeGate(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	migration string,
) {
	t.Helper()
	for _, pool := range []string{"READ", "WRITE"} {
		executionID := "m3-up-active-" + strings.ToLower(pool)
		insertActiveLegacyExecutionLease(t, ctx, database, executionID, pool)
		expectMigrationConstraint(t, ctx, database, migration, "55000", "execution_leases_m3_cutover_guard")
		execSQL(t, ctx, database, `DELETE FROM execution_leases WHERE execution_id = $1`, executionID)
	}
}

func exerciseLegacyExecutionLeasePostCutoverGate(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	downMigration string,
) {
	t.Helper()
	for _, pool := range []string{"READ", "WRITE"} {
		executionID := "m3-post-cutover-" + strings.ToLower(pool)
		expectSQLConstraint(t, ctx, database, "55000", "execution_leases_m3_cutover_guard", `
			INSERT INTO execution_leases (
				execution_id, target_key, runner_pool, production, status, runner_id,
				lease_token_sha256, lease_epoch, lease_acquired_at, lease_expires_at,
				last_heartbeat_at, created_at, updated_at
			) VALUES (
				$1, $2, $3, false, 'LEASED', 'legacy-runner', repeat('a', 64), 1,
				statement_timestamp(), statement_timestamp() + interval '5 minutes',
				statement_timestamp(), statement_timestamp(), statement_timestamp()
			)
		`, executionID, "m3/post-cutover/"+strings.ToLower(pool), pool)

		execSQL(t, ctx, database, `
			INSERT INTO execution_leases (
				execution_id, target_key, runner_pool, production, status, created_at, updated_at
			) VALUES ($1, $2, $3, false, 'QUEUED', statement_timestamp(), statement_timestamp())
		`, executionID, "m3/post-cutover/"+strings.ToLower(pool), pool)
		expectSQLConstraint(t, ctx, database, "55000", "execution_leases_m3_cutover_guard", `
			UPDATE execution_leases
			SET status = 'LEASED', runner_id = 'legacy-runner', lease_token_sha256 = repeat('a', 64),
				lease_epoch = 1, lease_acquired_at = statement_timestamp(),
				last_heartbeat_at = statement_timestamp(),
				lease_expires_at = statement_timestamp() + interval '5 minutes',
				updated_at = statement_timestamp()
			WHERE execution_id = $1
		`, executionID)
		execSQL(t, ctx, database, `DELETE FROM execution_leases WHERE execution_id = $1`, executionID)

		execSQL(t, ctx, database, `ALTER TABLE execution_leases DISABLE TRIGGER execution_leases_m3_cutover_guard`)
		insertActiveLegacyExecutionLease(t, ctx, database, executionID, pool)
		execSQL(t, ctx, database, `ALTER TABLE execution_leases ENABLE TRIGGER execution_leases_m3_cutover_guard`)
		expectMigrationConstraint(t, ctx, database, downMigration, "55000", "execution_leases_m3_cutover_guard")
		execSQL(t, ctx, database, `DELETE FROM execution_leases WHERE execution_id = $1`, executionID)
	}
}

func insertActiveLegacyExecutionLease(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	executionID, pool string,
) {
	t.Helper()
	execSQL(t, ctx, database, `
		INSERT INTO execution_leases (
			execution_id, target_key, runner_pool, production, status, runner_id,
			lease_token_sha256, lease_epoch, lease_acquired_at, lease_expires_at,
			last_heartbeat_at, created_at, updated_at
		) VALUES (
			$1, $2, $3, false, 'LEASED', 'legacy-runner', repeat('a', 64), 1,
			statement_timestamp(), statement_timestamp() + interval '5 minutes',
			statement_timestamp(), statement_timestamp(), statement_timestamp()
		)
	`, executionID, "m3/cutover/"+strings.ToLower(pool), pool)
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

func expectMigrationConstraint(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	filename, sqlState, constraintName string,
) {
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
	if !errors.As(execErr, &postgresError) || postgresError.Code != sqlState ||
		postgresError.ConstraintName != constraintName {
		t.Fatalf("migration %s error = %v (constraint %q), want SQLSTATE %s constraint %q",
			filepath.Base(filename), execErr, postgresErrorConstraint(postgresError), sqlState, constraintName)
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

func expectSQLConstraint(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	sqlState, constraintName, query string,
	arguments ...any,
) {
	t.Helper()
	_, err := database.Exec(ctx, query, arguments...)
	if err == nil {
		t.Fatalf("SQL unexpectedly succeeded; want SQLSTATE %s constraint %q", sqlState, constraintName)
	}
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != sqlState || postgresError.ConstraintName != constraintName {
		t.Fatalf("SQL error = %v (constraint %q), want SQLSTATE %s constraint %q",
			err, postgresErrorConstraint(postgresError), sqlState, constraintName)
	}
}

func expectDeferredConstraintAtCommit(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	constraintName, query string,
	arguments ...any,
) {
	t.Helper()
	tx, err := database.Begin(ctx)
	if err != nil {
		t.Fatalf("begin deferred constraint transaction: %v", err)
	}
	finished := false
	defer func() {
		if !finished {
			_ = tx.Rollback(ctx)
		}
	}()
	if _, err := tx.Exec(ctx, query, arguments...); err != nil {
		t.Fatalf("statement failed before deferred constraint commit: %v", err)
	}
	err = tx.Commit(ctx)
	finished = true
	if err == nil {
		t.Fatal("deferred constraint commit unexpectedly succeeded")
	}
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != "23514" || postgresError.ConstraintName != constraintName {
		t.Fatalf("deferred commit error = %v (constraint %q), want SQLSTATE 23514 constraint %q",
			err, postgresErrorConstraint(postgresError), constraintName)
	}
}

func expectSQLConstraintAndRollback(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	sqlState, constraintName, query string,
	arguments ...any,
) {
	t.Helper()
	tx, err := database.Begin(ctx)
	if err != nil {
		t.Fatalf("begin rejected-statement transaction: %v", err)
	}
	finished := false
	defer func() {
		if !finished {
			_ = tx.Rollback(ctx)
		}
	}()
	_, execErr := tx.Exec(ctx, query, arguments...)
	if execErr == nil {
		_ = tx.Rollback(ctx)
		finished = true
		t.Fatalf("SQL unexpectedly succeeded; want SQLSTATE %s constraint %q", sqlState, constraintName)
	}
	var postgresError *pgconn.PgError
	if !errors.As(execErr, &postgresError) || postgresError.Code != sqlState || postgresError.ConstraintName != constraintName {
		_ = tx.Rollback(ctx)
		finished = true
		t.Fatalf("SQL error = %v (constraint %q), want SQLSTATE %s constraint %q",
			execErr, postgresErrorConstraint(postgresError), sqlState, constraintName)
	}
	if err := tx.Rollback(ctx); err != nil {
		finished = true
		t.Fatalf("rollback rejected-statement transaction: %v", err)
	}
	finished = true
}

func postgresErrorConstraint(err *pgconn.PgError) string {
	if err == nil {
		return ""
	}
	return err.ConstraintName
}
