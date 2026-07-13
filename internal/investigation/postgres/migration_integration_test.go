package postgres_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/seaworld008/aiops-system/internal/readtask"
)

const (
	testTenantID        = "10000000-0000-4000-8000-000000000001"
	testWorkspaceID     = "20000000-0000-4000-8000-000000000001"
	testEnvironmentID   = "25000000-0000-4000-8000-000000000001"
	testServiceID       = "28000000-0000-4000-8000-000000000001"
	testIncidentID      = "50000000-0000-4000-8000-000000000001"
	testInvestigationID = "60000000-0000-4000-8000-000000000001"
	testTaskID          = "65000000-0000-4000-8000-000000000001"
	testSignalID        = "40000000-0000-4000-8000-000000000001"
	testIntegrationID   = "30000000-0000-4000-8000-000000000001"
	testEvidenceID      = "68000000-0000-4000-8000-000000000001"
	testHypothesisID    = "70000000-0000-4000-8000-000000000001"
)

type runtimeFixture struct {
	harness *postgresHarness
	base    time.Time
}

func newRuntimeFixture(t *testing.T) runtimeFixture {
	t.Helper()
	harness := newPostgresHarness(t)
	harness.applyUpBeforeTen(t)
	base := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	execSQL(t, harness.db, `INSERT INTO tenants (id, name) VALUES ($1, 'tenant')`, testTenantID)
	execSQL(t, harness.db, `INSERT INTO workspaces (id, tenant_id, name) VALUES ($1, $2, 'workspace')`, testWorkspaceID, testTenantID)
	execSQL(t, harness.db, `
		INSERT INTO environments (id, tenant_id, workspace_id, name, kind)
		VALUES ($1, $2, $3, 'staging', 'STAGING')
	`, testEnvironmentID, testTenantID, testWorkspaceID)
	execSQL(t, harness.db, `
		INSERT INTO services (id, tenant_id, workspace_id, name, owner_group)
		VALUES ($1, $2, $3, 'payments', 'payments-sre')
	`, testServiceID, testTenantID, testWorkspaceID)
	execSQL(t, harness.db, `
		INSERT INTO integrations (id, tenant_id, workspace_id, provider, name, secret_ref)
		VALUES ($1, $2, $3, 'alertmanager', 'alerts', 'vault://alerts')
	`, testIntegrationID, testTenantID, testWorkspaceID)
	execSQL(t, harness.db, `
		INSERT INTO signals (
			id, tenant_id, workspace_id, integration_id, provider, provider_event_id,
			payload_hash, fingerprint, status, observed_at, payload_summary
		) VALUES ($1, $2, $3, $4, 'alertmanager', 'runtime-event', $5, 'payments:staging:latency',
			'firing', $6, '{"status":"firing","labels":{"service":"payments"}}')
	`, testSignalID, testTenantID, testWorkspaceID, testIntegrationID, strings.Repeat("a", 64), base.Add(time.Second))
	harness.applyMigration(t, "000010_investigation_runtime.up.sql")

	ctx := context.Background()
	incidentTx, err := harness.db.Begin(ctx)
	if err != nil {
		t.Fatalf("begin atomic incident fixture: %v", err)
	}
	incidentCommitted := false
	defer func() {
		if !incidentCommitted {
			_ = incidentTx.Rollback(ctx)
		}
	}()
	if _, err := incidentTx.Exec(ctx, `
		INSERT INTO incidents (
			id, tenant_id, workspace_id, service_id, environment_id, status, severity, title,
			opened_at, updated_at, version, correlation_key, mapping_status,
			last_signal_at, signal_count, runtime_schema_version
		) VALUES (
			$1, $2, $3, $4, $5, 'OPEN', 'SEV3', 'runtime incident',
			$6, $7, 1, 'payments:staging:latency', 'EXACT', $8, 1, 'investigation-runtime.v1'
		)
	`, testIncidentID, testTenantID, testWorkspaceID, testServiceID, testEnvironmentID,
		base.Add(time.Second), base.Add(2*time.Second), base.Add(time.Second)); err != nil {
		t.Fatalf("insert runtime incident: %v", err)
	}
	if _, err := incidentTx.Exec(ctx, `
		INSERT INTO incident_signals (tenant_id, workspace_id, incident_id, signal_id)
		VALUES ($1, $2, $3, $4)
	`, testTenantID, testWorkspaceID, testIncidentID, testSignalID); err != nil {
		t.Fatalf("associate runtime incident signal: %v", err)
	}
	if _, err := incidentTx.Exec(ctx, `
		INSERT INTO investigation_signal_correlations (
			tenant_id, workspace_id, signal_id, incident_id, correlation_key,
			mapping_status, service_id, environment_id
		) VALUES ($1, $2, $3, $4, 'payments:staging:latency', 'EXACT', $5, $6)
	`, testTenantID, testWorkspaceID, testSignalID, testIncidentID, testServiceID, testEnvironmentID); err != nil {
		t.Fatalf("insert runtime signal correlation: %v", err)
	}
	if err := incidentTx.Commit(ctx); err != nil {
		t.Fatalf("commit atomic incident fixture: %v", err)
	}
	incidentCommitted = true

	createdAt := base.Add(3 * time.Second)
	tx, err := harness.db.Begin(ctx)
	if err != nil {
		t.Fatalf("begin atomic investigation fixture: %v", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if _, err := tx.Exec(ctx, `
		INSERT INTO investigations (
			id, tenant_id, workspace_id, incident_id, status, window_start, window_end,
			tool_schema_version, created_at, model_status, idempotency_key, request_hash,
			request_hash_version, updated_at, service_id_snapshot, environment_id_snapshot,
			mapping_status_snapshot, runtime_schema_version
		) VALUES (
			$1, $2, $3, $4, 'QUEUED', $5, $6, 'investigation-task.v1', $7,
			'PENDING', 'investigate:runtime', $8, 'investigation.create.v1', $7,
			$9, $10, 'EXACT', 'investigation-runtime.v1'
		)
	`, testInvestigationID, testTenantID, testWorkspaceID, testIncidentID, base, base.Add(2*time.Second),
		createdAt, strings.Repeat("b", 64), testServiceID, testEnvironmentID); err != nil {
		t.Fatalf("insert runtime investigation: %v", err)
	}

	input := []byte(`{"lookback_minutes":15}`)
	if _, err := tx.Exec(ctx, `
		INSERT INTO tool_invocations (
			id, tenant_id, workspace_id, investigation_id, tool_name, tool_version,
			input_hash, status, incident_id, task_key, position, input_document,
			created_at, updated_at, runtime_schema_version
		) VALUES (
			$1, $2, $3, $4, 'prometheus-staging-v1-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', 'range_query', $5, 'QUEUED',
			$6, 'metrics', 1, $7, $8, $8, 'investigation-runtime.v1'
		)
	`, testTaskID, testTenantID, testWorkspaceID, testInvestigationID, sha256Hex(input),
		testIncidentID, input, createdAt); err != nil {
		t.Fatalf("insert runtime read task: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit atomic investigation fixture: %v", err)
	}
	committed = true
	return runtimeFixture{harness: harness, base: base}
}

func TestInvestigationRuntimeMigrationPreservesPureLegacyRowsAndCanRollBack(t *testing.T) {
	harness := newPostgresHarness(t)
	harness.applyUpBeforeTen(t)
	execSQL(t, harness.db, `INSERT INTO tenants (id, name) VALUES ($1, 'tenant')`, testTenantID)
	execSQL(t, harness.db, `INSERT INTO workspaces (id, tenant_id, name) VALUES ($1, $2, 'workspace')`, testWorkspaceID, testTenantID)
	execSQL(t, harness.db, `
		INSERT INTO incidents (id, tenant_id, workspace_id, status, severity, title, opened_at, updated_at)
		VALUES ($1, $2, $3, 'OPEN', 'SEV3', 'legacy incident', statement_timestamp(), statement_timestamp())
	`, testIncidentID, testTenantID, testWorkspaceID)
	execSQL(t, harness.db, `
		INSERT INTO investigations (
			id, tenant_id, workspace_id, incident_id, status,
			window_start, window_end, tool_schema_version, created_at
		) VALUES (
			$1, $2, $3, $4, 'RUNNING', statement_timestamp() - interval '5 minutes',
			statement_timestamp(), 'legacy-v1', statement_timestamp()
		)
	`, testInvestigationID, testTenantID, testWorkspaceID, testIncidentID)
	execSQL(t, harness.db, `
		INSERT INTO tool_invocations (
			id, tenant_id, workspace_id, investigation_id, tool_name, tool_version,
			input_hash, status, started_at
		) VALUES ($1, $2, $3, $4, 'legacy-tool', 'v1', repeat('a', 64), 'RUNNING', statement_timestamp())
	`, testTaskID, testTenantID, testWorkspaceID, testInvestigationID)
	execSQL(t, harness.db, `
		INSERT INTO feedback (
			id, tenant_id, workspace_id, investigation_id, actor_id, kind
		) VALUES ('80000000-0000-4000-8000-000000000001', $1, $2, $3, 'legacy-user', 'HELPFUL')
	`, testTenantID, testWorkspaceID, testInvestigationID)

	harness.applyMigration(t, "000010_investigation_runtime.up.sql")
	var incidentRuntime, investigationRuntime, taskRuntime, feedbackRuntime *string
	if err := harness.db.QueryRow(context.Background(), `
		SELECT incident.runtime_schema_version, investigation.runtime_schema_version,
		       task.runtime_schema_version, feedback.runtime_schema_version
		FROM incidents AS incident
		JOIN investigations AS investigation ON investigation.incident_id = incident.id
		JOIN tool_invocations AS task ON task.investigation_id = investigation.id
		JOIN feedback ON feedback.investigation_id = investigation.id
		WHERE incident.id = $1
	`, testIncidentID).Scan(&incidentRuntime, &investigationRuntime, &taskRuntime, &feedbackRuntime); err != nil {
		t.Fatalf("read migrated legacy rows: %v", err)
	}
	if incidentRuntime != nil || investigationRuntime != nil || taskRuntime != nil || feedbackRuntime != nil {
		t.Fatalf("legacy runtime markers = %v/%v/%v/%v, want all NULL",
			incidentRuntime, investigationRuntime, taskRuntime, feedbackRuntime)
	}
	execSQL(t, harness.db, `UPDATE incidents SET title = 'legacy updated' WHERE id = $1`, testIncidentID)
	execSQL(t, harness.db, `UPDATE investigations SET model_version = 'legacy-model-v2' WHERE id = $1`, testInvestigationID)
	execSQL(t, harness.db, `UPDATE tool_invocations SET status = 'COMPLETED', completed_at = statement_timestamp() WHERE id = $1`, testTaskID)
	execSQL(t, harness.db, `UPDATE feedback SET comment = 'legacy comment' WHERE id = '80000000-0000-4000-8000-000000000001'`)
	expectSQLState(t, harness.db, "55000", `
		UPDATE incidents
		SET correlation_key = 'legacy:promotion', mapping_status = 'UNRESOLVED',
		    last_signal_at = opened_at, signal_count = 1,
		    runtime_schema_version = 'investigation-runtime.v1'
		WHERE id = $1
	`, testIncidentID)
	var legacyTitle, legacyModel, legacyTaskStatus, legacyComment string
	if err := harness.db.QueryRow(context.Background(), `
		SELECT incident.title, investigation.model_version, task.status, feedback.comment
		FROM incidents AS incident
		JOIN investigations AS investigation ON investigation.incident_id = incident.id
		JOIN tool_invocations AS task ON task.investigation_id = investigation.id
		JOIN feedback ON feedback.investigation_id = investigation.id
		WHERE incident.id = $1
	`, testIncidentID).Scan(&legacyTitle, &legacyModel, &legacyTaskStatus, &legacyComment); err != nil {
		t.Fatalf("read updated legacy rows: %v", err)
	}
	if legacyTitle != "legacy updated" || legacyModel != "legacy-model-v2" ||
		legacyTaskStatus != "COMPLETED" || legacyComment != "legacy comment" {
		t.Fatalf("legacy updates = %q/%q/%q/%q, want migration-transparent updates",
			legacyTitle, legacyModel, legacyTaskStatus, legacyComment)
	}
	expectSQLConstraint(t, harness.db, "23514", "tool_invocations_runtime_shape_ck", `
		INSERT INTO tool_invocations (
			id, tenant_id, workspace_id, investigation_id, tool_name, tool_version,
			input_hash, status
		) VALUES (
			'65000000-0000-4000-8000-000000000099', $1, $2, $3,
			'legacy-null-start', 'v1', $4, 'RUNNING'
		)
	`, testTenantID, testWorkspaceID, testInvestigationID, strings.Repeat("f", 64))
	execSQL(t, harness.db, `TRUNCATE feedback`)
	execSQL(t, harness.db, `TRUNCATE hypothesis_evidence`)

	harness.applyMigration(t, "000010_investigation_runtime.down.sql")
	var runtimeColumnCount int
	if err := harness.db.QueryRow(context.Background(), `
		SELECT count(*)
		FROM information_schema.columns
		WHERE table_schema = current_schema()
		  AND table_name = 'incidents'
		  AND column_name = 'runtime_schema_version'
	`).Scan(&runtimeColumnCount); err != nil {
		t.Fatalf("inspect rolled-back schema: %v", err)
	}
	if runtimeColumnCount != 0 {
		t.Fatalf("runtime_schema_version column count = %d, want 0 after down", runtimeColumnCount)
	}
	expectSQLState(t, harness.db, "23514", `
		INSERT INTO feedback (
			id, tenant_id, workspace_id, investigation_id, actor_id, kind
		) VALUES ('80000000-0000-4000-8000-000000000002', $1, $2, $3, 'user', 'INCONCLUSIVE')
	`, testTenantID, testWorkspaceID, testInvestigationID)
}

func TestInvestigationRuntimeMigrationLocksScopeBindingBeforeRegistration(t *testing.T) {
	harness := newPostgresHarness(t)
	harness.applyUpBeforeTen(t)
	execSQL(t, harness.db, `INSERT INTO tenants (id, name) VALUES ($1, 'tenant')`, testTenantID)
	execSQL(t, harness.db, `INSERT INTO workspaces (id, tenant_id, name) VALUES ($1, $2, 'workspace')`, testWorkspaceID, testTenantID)
	execSQL(t, harness.db, `
		INSERT INTO environments (id, tenant_id, workspace_id, name, kind)
		VALUES ($1, $2, $3, 'staging', 'STAGING')
	`, testEnvironmentID, testTenantID, testWorkspaceID)
	const runnerID = "read-runner-migration-lock"
	execSQL(t, harness.db, `
		INSERT INTO runner_registrations (
			runner_id, tenant_id, spiffe_uri, runner_pool, enabled, scope_revision, max_concurrency
		) VALUES ($1, $2, $3, 'READ', true, 1, 1)
	`, runnerID, testTenantID, "spiffe://aiops.test/runner/read-pool/"+runnerID)
	execSQL(t, harness.db, `
		INSERT INTO runner_scope_bindings (runner_id, tenant_id, workspace_id, environment_id)
		VALUES ($1, $2, $3, $4)
	`, runnerID, testTenantID, testWorkspaceID, testEnvironmentID)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	scopeTx, err := harness.db.Begin(ctx)
	if err != nil {
		t.Fatalf("begin concurrent scope mutation: %v", err)
	}
	defer func() { _ = scopeTx.Rollback(context.Background()) }()
	scopeBackendPID := transactionBackendPID(t, scopeTx)
	if _, err := scopeTx.Exec(ctx, `LOCK TABLE runner_scope_bindings IN ROW EXCLUSIVE MODE`); err != nil {
		t.Fatalf("pre-lock scope binding table for mutation: %v", err)
	}
	if _, err := scopeTx.Exec(ctx, `
		SELECT 1
		FROM runner_scope_bindings
		WHERE tenant_id = $1 AND runner_id = $2
		  AND workspace_id = $3 AND environment_id = $4
		FOR UPDATE
	`, testTenantID, runnerID, testWorkspaceID, testEnvironmentID); err != nil {
		t.Fatalf("lock scope binding before migration: %v", err)
	}

	migrationConn, err := harness.db.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire dedicated migration connection: %v", err)
	}
	defer migrationConn.Release()
	var migrationBackendPID int32
	if err := migrationConn.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&migrationBackendPID); err != nil {
		t.Fatalf("read migration backend PID: %v", err)
	}
	migration := readMigration(t, "000010_investigation_runtime.up.sql")
	migrationResult := make(chan error, 1)
	go func() {
		_, execErr := migrationConn.Exec(ctx, migration)
		migrationResult <- execErr
	}()
	waitForBackendBlock(t, ctx, harness.db, migrationBackendPID, scopeBackendPID,
		migrationResult, "migration scope-binding table lock")

	if _, err := scopeTx.Exec(ctx, `
		DELETE FROM runner_scope_bindings
		WHERE tenant_id = $1 AND runner_id = $2
		  AND workspace_id = $3 AND environment_id = $4
	`, testTenantID, runnerID, testWorkspaceID, testEnvironmentID); err != nil {
		t.Fatalf("remove scope while migration waits on binding table: %v", err)
	}
	if err := scopeTx.Commit(ctx); err != nil {
		t.Fatalf("commit scope removal without migration lock-order deadlock: %v", err)
	}

	select {
	case err := <-migrationResult:
		if err != nil {
			t.Fatalf("apply migration after scope mutation releases binding: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("migration remained blocked after scope mutation: %v", ctx.Err())
	}
	var runtimeColumnCount int
	if err := harness.db.QueryRow(ctx, `
		SELECT count(*)
		FROM information_schema.columns
		WHERE table_schema = current_schema()
		  AND table_name = 'investigations'
		  AND column_name = 'runtime_schema_version'
	`).Scan(&runtimeColumnCount); err != nil {
		t.Fatalf("inspect migration after concurrent scope removal: %v", err)
	}
	if runtimeColumnCount != 1 {
		t.Fatalf("runtime_schema_version column count = %d, want 1", runtimeColumnCount)
	}
}

func TestReadEvidenceClockSkewMigrationBoundsSourceTimeAndRefusesUnsafeDown(t *testing.T) {
	fixture := newRuntimeFixture(t)
	database := fixture.harness.db
	fixture.harness.applyMigration(t, "000011_investigation_runner_ingress.up.sql")
	fixture.harness.applyMigration(t, "000014_read_evidence_clock_skew.up.sql")

	ctx := context.Background()
	startedAt := fixture.base.Add(5 * time.Second)
	tx, err := database.Begin(ctx)
	if err != nil {
		t.Fatalf("begin clock-skew parent transition: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `
		UPDATE tool_invocations
		SET status = 'RUNNING', started_at = $2, updated_at = $2
		WHERE id = $1
	`, testTaskID, startedAt); err != nil {
		t.Fatalf("start clock-skew read task: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE investigations
		SET status = 'RUNNING', started_at = $2, updated_at = $2
		WHERE id = $1
	`, testInvestigationID, startedAt); err != nil {
		t.Fatalf("start clock-skew investigation: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit clock-skew parent transition: %v", err)
	}

	payload := []byte(`{"clock_skew":"bounded"}`)
	forgedCreatedAt := fixture.base.Add(8 * time.Second)
	insertEvidence := `
		INSERT INTO evidence (
			id, tenant_id, workspace_id, investigation_id, connector, query_summary,
			collected_at, redacted_summary, content_hash, trust_level, truncated, created_at,
			incident_id, task_id, payload_document, attributes, runtime_schema_version
		) VALUES (
			$1, $2, $3, $4, 'prometheus-staging-v1-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
			'{}', clock_timestamp() + $5::interval, '{}', $6, 'AUTHENTICATED_READ_RUNNER', false, $7,
			$8, $9, $10, '{}', 'investigation-runtime.v1'
		)
	`
	expectSQLConstraint(t, database, "23514", "evidence_runtime_clock_skew_guard", insertEvidence,
		"68000000-0000-4000-8000-000000000101", testTenantID, testWorkspaceID, testInvestigationID,
		"3 seconds", sha256Hex(payload), forgedCreatedAt,
		testIncidentID, testTaskID, payload)
	validEvidenceID := "68000000-0000-4000-8000-000000000102"
	completionTx, err := database.Begin(ctx)
	if err != nil {
		t.Fatalf("begin bounded clock-skew completion: %v", err)
	}
	defer func() { _ = completionTx.Rollback(context.Background()) }()
	if _, err := completionTx.Exec(ctx, insertEvidence,
		validEvidenceID, testTenantID, testWorkspaceID, testInvestigationID,
		"1 second", sha256Hex(payload), forgedCreatedAt,
		testIncidentID, testTaskID, payload); err != nil {
		t.Fatalf("insert bounded clock-skew Evidence: %v", err)
	}
	if _, err := completionTx.Exec(ctx, `
		UPDATE tool_invocations
		SET status = 'EVIDENCE', evidence_id = $2, output_hash = $3,
			completed_at = $4, updated_at = $4
		WHERE id = $1
	`, testTaskID, validEvidenceID, sha256Hex(payload), forgedCreatedAt); err != nil {
		t.Fatalf("complete bounded clock-skew task: %v", err)
	}
	if err := completionTx.Commit(ctx); err != nil {
		t.Fatalf("commit bounded clock-skew Evidence: %v", err)
	}
	var collectedAt, serverCreatedAt time.Time
	if err := database.QueryRow(ctx, `
		SELECT collected_at, created_at FROM evidence WHERE id = $1
	`, validEvidenceID).Scan(&collectedAt, &serverCreatedAt); err != nil {
		t.Fatalf("read bounded clock-skew Evidence times: %v", err)
	}
	if !serverCreatedAt.After(forgedCreatedAt) || collectedAt.Sub(serverCreatedAt) <= 0 ||
		collectedAt.Sub(serverCreatedAt) > readtask.MaxEvidenceClockSkew {
		t.Fatalf("bounded clock-skew Evidence times = collected %s created %s forged %s",
			collectedAt, serverCreatedAt, forgedCreatedAt)
	}

	expectMigrationSQLState(t, database, "000014_read_evidence_clock_skew.down.sql", "55000")
}

func TestInvestigationRuntimeAdmissionRequiresInitialActiveAndAtomicFacts(t *testing.T) {
	fixture := newRuntimeFixture(t)
	database := fixture.harness.db
	base := fixture.base
	// PostgreSQL reports an ON DELETE RESTRICT violation as restrict_violation.
	expectSQLState(t, database, "23001", `
		DELETE FROM incident_signals
		WHERE tenant_id = $1 AND workspace_id = $2 AND signal_id = $3
	`, testTenantID, testWorkspaceID, testSignalID)

	expectSQLState(t, database, "23514", `
		INSERT INTO incidents (
			id, tenant_id, workspace_id, service_id, environment_id, status, severity, title,
			opened_at, updated_at, version, correlation_key, mapping_status,
			last_signal_at, signal_count, runtime_schema_version
		) VALUES (
			'50000000-0000-4000-8000-000000000010', $1, $2, $3, $4,
			'INVESTIGATING', 'SEV3', 'invalid initial state', $5, $6, 2,
			'payments:staging:invalid-initial', 'EXACT', $5, 1, 'investigation-runtime.v1'
		)
	`, testTenantID, testWorkspaceID, testServiceID, testEnvironmentID, base, base.Add(time.Second))

	secondIncidentID := "50000000-0000-4000-8000-000000000011"
	secondSignalID := "40000000-0000-4000-8000-000000000011"
	execSQL(t, database, `
		INSERT INTO signals (
			id, tenant_id, workspace_id, integration_id, provider, provider_event_id,
			payload_hash, fingerprint, status, observed_at, payload_summary
		) VALUES ($1, $2, $3, $4, 'alertmanager', 'runtime-event-2', $5,
			'payments:staging:second', 'firing', $6, '{}')
	`, secondSignalID, testTenantID, testWorkspaceID, testIntegrationID,
		strings.Repeat("8", 64), base.Add(time.Second))
	ctx := context.Background()
	tx, err := database.Begin(ctx)
	if err != nil {
		t.Fatalf("begin second incident transaction: %v", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if _, err := tx.Exec(ctx, `
		INSERT INTO incidents (
			id, tenant_id, workspace_id, service_id, environment_id, status, severity, title,
			opened_at, updated_at, version, correlation_key, mapping_status,
			last_signal_at, signal_count, runtime_schema_version
		) VALUES (
			$1, $2, $3, $4, $5, 'OPEN', 'SEV3', 'second runtime incident',
			$6, $7, 1, 'payments:staging:second', 'EXACT', $6, 1,
			'investigation-runtime.v1'
		)
	`, secondIncidentID, testTenantID, testWorkspaceID, testServiceID, testEnvironmentID,
		base.Add(time.Second), base.Add(2*time.Second)); err != nil {
		t.Fatalf("insert second runtime incident: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO incident_signals (tenant_id, workspace_id, incident_id, signal_id)
		VALUES ($1, $2, $3, $4)
	`, testTenantID, testWorkspaceID, secondIncidentID, secondSignalID); err != nil {
		t.Fatalf("associate second runtime signal: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO investigation_signal_correlations (
			tenant_id, workspace_id, signal_id, incident_id, correlation_key,
			mapping_status, service_id, environment_id
		) VALUES ($1, $2, $3, $4, 'payments:staging:second', 'EXACT', $5, $6)
	`, testTenantID, testWorkspaceID, secondSignalID, secondIncidentID,
		testServiceID, testEnvironmentID); err != nil {
		t.Fatalf("correlate second runtime signal: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit second runtime incident: %v", err)
	}
	committed = true

	expectSQLState(t, database, "23514", `
		UPDATE incidents
		SET signal_count = signal_count + 1, version = version + 1,
			updated_at = updated_at + interval '1 second'
		WHERE id = $1
	`, secondIncidentID)
	expectSQLState(t, database, "23514", `
		INSERT INTO investigations (
			id, tenant_id, workspace_id, incident_id, status, window_start, window_end,
			tool_schema_version, created_at, model_status, idempotency_key, request_hash,
			request_hash_version, updated_at, service_id_snapshot, environment_id_snapshot,
			mapping_status_snapshot, runtime_schema_version
		) VALUES (
			'60000000-0000-4000-8000-000000000011', $1, $2, $3, 'QUEUED', $4, $5,
			'investigation-task.v1', $6, 'PENDING', 'investigate:no-task-create', $7,
			'investigation.create.v1', $6, $8, $9, 'EXACT', 'investigation-runtime.v1'
		)
	`, testTenantID, testWorkspaceID, secondIncidentID, base, base.Add(time.Second),
		base.Add(3*time.Second), strings.Repeat("9", 64), testServiceID, testEnvironmentID)

	lateSignalID := "40000000-0000-4000-8000-000000000012"
	execSQL(t, database, `
		INSERT INTO signals (
			id, tenant_id, workspace_id, integration_id, provider, provider_event_id,
			payload_hash, fingerprint, status, observed_at, payload_summary
		) VALUES ($1, $2, $3, $4, 'alertmanager', 'runtime-event-late', $5,
			'payments:staging:late', 'firing', $6, '{}')
	`, lateSignalID, testTenantID, testWorkspaceID, testIntegrationID,
		strings.Repeat("7", 64), base.Add(4*time.Second))
	for index, status := range []string{"INVESTIGATING", "MITIGATING", "RESOLVED"} {
		changedAt := base.Add(time.Duration(index+2) * time.Second)
		execSQL(t, database, `
			UPDATE incidents
			SET status = $2, updated_at = $3, version = version + 1
			WHERE id = $1
		`, secondIncidentID, status, changedAt)
	}
	lateTx, err := database.Begin(ctx)
	if err != nil {
		t.Fatalf("begin late correlation transaction: %v", err)
	}
	if _, err := lateTx.Exec(ctx, `
		INSERT INTO incident_signals (tenant_id, workspace_id, incident_id, signal_id)
		VALUES ($1, $2, $3, $4)
	`, testTenantID, testWorkspaceID, secondIncidentID, lateSignalID); err != nil {
		_ = lateTx.Rollback(ctx)
		t.Fatalf("insert late signal association: %v", err)
	}
	_, err = lateTx.Exec(ctx, `
		INSERT INTO investigation_signal_correlations (
			tenant_id, workspace_id, signal_id, incident_id, correlation_key,
			mapping_status, service_id, environment_id
		) VALUES ($1, $2, $3, $4, 'payments:staging:second', 'EXACT', $5, $6)
	`, testTenantID, testWorkspaceID, lateSignalID, secondIncidentID,
		testServiceID, testEnvironmentID)
	expectErrorSQLState(t, err, "23514")
	_ = lateTx.Rollback(ctx)
}

func TestInvestigationRuntimeCorrelationLockSerializesConcurrentAggregateUpdates(t *testing.T) {
	fixture := newRuntimeFixture(t)
	database := fixture.harness.db
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	firstSignalID := "40000000-0000-4000-8000-000000000021"
	secondSignalID := "40000000-0000-4000-8000-000000000022"
	firstObservedAt := fixture.base.Add(2 * time.Second)
	secondObservedAt := fixture.base.Add(3 * time.Second)
	for index, signalID := range []string{firstSignalID, secondSignalID} {
		execSQL(t, database, `
			INSERT INTO signals (
				id, tenant_id, workspace_id, integration_id, provider, provider_event_id,
				payload_hash, fingerprint, status, observed_at, payload_summary
			) VALUES ($1, $2, $3, $4, 'alertmanager', $5, $6, $7, 'firing', $8, '{}')
		`, signalID, testTenantID, testWorkspaceID, testIntegrationID,
			"concurrent-event-"+signalID, strings.Repeat(string(rune('c'+index)), 64),
			"payments:staging:concurrent-"+signalID, []time.Time{firstObservedAt, secondObservedAt}[index])
	}

	firstTx, err := database.Begin(ctx)
	if err != nil {
		t.Fatalf("begin first correlation transaction: %v", err)
	}
	defer func() { _ = firstTx.Rollback(context.Background()) }()
	secondTx, err := database.Begin(ctx)
	if err != nil {
		t.Fatalf("begin second correlation transaction: %v", err)
	}
	defer func() { _ = secondTx.Rollback(context.Background()) }()
	firstBackendPID := transactionBackendPID(t, firstTx)
	secondBackendPID := transactionBackendPID(t, secondTx)

	insertAssociation := func(tx pgx.Tx, signalID string) error {
		_, execErr := tx.Exec(ctx, `
			INSERT INTO incident_signals (tenant_id, workspace_id, incident_id, signal_id)
			VALUES ($1, $2, $3, $4)
		`, testTenantID, testWorkspaceID, testIncidentID, signalID)
		return execErr
	}
	insertCorrelation := func(tx pgx.Tx, signalID string) error {
		_, execErr := tx.Exec(ctx, `
			INSERT INTO investigation_signal_correlations (
				tenant_id, workspace_id, signal_id, incident_id, correlation_key,
				mapping_status, service_id, environment_id
			) VALUES (
				$1, $2, $3, $4, 'payments:staging:latency', 'EXACT', $5, $6
			)
		`, testTenantID, testWorkspaceID, signalID, testIncidentID, testServiceID, testEnvironmentID)
		return execErr
	}
	if err := insertAssociation(firstTx, firstSignalID); err != nil {
		t.Fatalf("insert first concurrent association: %v", err)
	}
	if err := insertCorrelation(firstTx, firstSignalID); err != nil {
		t.Fatalf("insert first concurrent correlation: %v", err)
	}
	if err := insertAssociation(secondTx, secondSignalID); err != nil {
		t.Fatalf("insert second concurrent association: %v", err)
	}

	secondCorrelation := make(chan error, 1)
	go func() {
		secondCorrelation <- insertCorrelation(secondTx, secondSignalID)
	}()
	waitForBackendBlock(t, ctx, database, secondBackendPID, firstBackendPID,
		secondCorrelation, "second correlation parent lock")

	if _, err := firstTx.Exec(ctx, `
		UPDATE incidents
		SET signal_count = signal_count + 1, last_signal_at = $2,
			updated_at = GREATEST(updated_at, $2), version = version + 1
		WHERE id = $1
	`, testIncidentID, firstObservedAt); err != nil {
		t.Fatalf("update first concurrent aggregate: %v", err)
	}
	if err := firstTx.Commit(ctx); err != nil {
		t.Fatalf("commit first concurrent correlation: %v", err)
	}

	select {
	case err := <-secondCorrelation:
		if err != nil {
			t.Fatalf("second correlation after lock release: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("second correlation remained blocked: %v", ctx.Err())
	}
	if _, err := secondTx.Exec(ctx, `
		UPDATE incidents
		SET signal_count = signal_count + 1, last_signal_at = $2,
			updated_at = GREATEST(updated_at, $2), version = version + 1
		WHERE id = $1
	`, testIncidentID, secondObservedAt); err != nil {
		t.Fatalf("update second concurrent aggregate: %v", err)
	}
	if err := secondTx.Commit(ctx); err != nil {
		t.Fatalf("commit second concurrent correlation: %v", err)
	}

	var signalCount int
	var version int64
	var lastSignalAt time.Time
	if err := database.QueryRow(ctx, `
		SELECT signal_count, version, last_signal_at
		FROM incidents
		WHERE tenant_id = $1 AND workspace_id = $2 AND id = $3
	`, testTenantID, testWorkspaceID, testIncidentID).Scan(&signalCount, &version, &lastSignalAt); err != nil {
		t.Fatalf("read concurrent incident aggregate: %v", err)
	}
	if signalCount != 3 || version != 3 || !lastSignalAt.Equal(secondObservedAt) {
		t.Fatalf("concurrent aggregate = count %d version %d last %s", signalCount, version, lastSignalAt)
	}
}

func TestInvestigationRuntimeEvidenceAdmissionUsesTaskBeforeParentLockOrder(t *testing.T) {
	fixture := newRuntimeFixture(t)
	database := fixture.harness.db
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	taskTx, err := database.Begin(ctx)
	if err != nil {
		t.Fatalf("begin task transition transaction: %v", err)
	}
	defer func() { _ = taskTx.Rollback(context.Background()) }()
	evidenceTx, err := database.Begin(ctx)
	if err != nil {
		t.Fatalf("begin evidence admission transaction: %v", err)
	}
	defer func() { _ = evidenceTx.Rollback(context.Background()) }()
	taskBackendPID := transactionBackendPID(t, taskTx)
	evidenceBackendPID := transactionBackendPID(t, evidenceTx)

	startedAt := fixture.base.Add(5 * time.Second)
	if _, err := taskTx.Exec(ctx, `
		UPDATE tool_invocations
		SET status = 'RUNNING', started_at = $2, updated_at = $2
		WHERE id = $1
	`, testTaskID, startedAt); err != nil {
		t.Fatalf("start read task while parent transition is pending: %v", err)
	}

	payload := []byte(`{"series_count":2}`)
	evidenceInsert := make(chan error, 1)
	go func() {
		_, execErr := evidenceTx.Exec(ctx, `
			INSERT INTO evidence (
				id, tenant_id, workspace_id, investigation_id, connector, query_summary,
				collected_at, redacted_summary, content_hash, trust_level, truncated, created_at,
				incident_id, task_id, payload_document, attributes, runtime_schema_version
			) VALUES (
				$1, $2, $3, $4, 'prometheus-staging-v1-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', '{}', $5, '{}', $6,
				'AUTHENTICATED_READ_RUNNER', false, $7, $8, $9, $10, '{}',
				'investigation-runtime.v1'
			)
		`, testEvidenceID, testTenantID, testWorkspaceID, testInvestigationID,
			fixture.base.Add(time.Second), sha256Hex(payload), startedAt.Add(time.Second),
			testIncidentID, testTaskID, payload)
		evidenceInsert <- execErr
	}()
	waitForBackendBlock(t, ctx, database, evidenceBackendPID, taskBackendPID,
		evidenceInsert, "evidence admission task lock")

	if _, err := taskTx.Exec(ctx, `
		UPDATE investigations
		SET status = 'RUNNING', started_at = $2, updated_at = $2
		WHERE id = $1
	`, testInvestigationID, startedAt); err != nil {
		t.Fatalf("start parent while evidence waits on task: %v", err)
	}
	if err := taskTx.Commit(ctx); err != nil {
		t.Fatalf("commit task-before-parent transition without deadlock: %v", err)
	}

	select {
	case err := <-evidenceInsert:
		if err != nil {
			t.Fatalf("insert evidence after task lock release: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("evidence admission remained blocked after task commit: %v", ctx.Err())
	}
	completedAt := startedAt.Add(2 * time.Second)
	if _, err := evidenceTx.Exec(ctx, `
		UPDATE tool_invocations
		SET status = 'EVIDENCE', evidence_id = $2, output_hash = $3,
		    completed_at = $4, updated_at = $4
		WHERE id = $1
	`, testTaskID, testEvidenceID, sha256Hex(payload), completedAt); err != nil {
		t.Fatalf("complete evidence task after admission: %v", err)
	}
	if err := evidenceTx.Commit(ctx); err != nil {
		t.Fatalf("commit evidence admission without lock-order deadlock: %v", err)
	}

	var taskStatus string
	if err := database.QueryRow(ctx, `
		SELECT status FROM tool_invocations
		WHERE tenant_id = $1 AND workspace_id = $2 AND id = $3
	`, testTenantID, testWorkspaceID, testTaskID).Scan(&taskStatus); err != nil {
		t.Fatalf("read evidence task after concurrent admission: %v", err)
	}
	if taskStatus != "EVIDENCE" {
		t.Fatalf("task status = %q, want EVIDENCE", taskStatus)
	}
	scopeRevision, certificate := seedRuntimeRunner(t, database, "read-runner-success", "READ", true, false)
	execSQL(t, database, `
		INSERT INTO runner_evidence_receipts (
			id, tenant_id, workspace_id, environment_id, investigation_id, task_id,
			runner_id, scope_revision, certificate_sha256, connector_id,
			evidence_id, content_hash, idempotency_key, request_hash, receipt_hash, schema_version
		) VALUES (
			'69000000-0000-4000-8000-000000000021', $1, $2, $3, $4, $5,
			'read-runner-success', $6, $7, 'prometheus-staging-v1-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', $8, $9,
			'receipt:evidence-success', $10, $11, 'runner-evidence.v1'
		)
	`, testTenantID, testWorkspaceID, testEnvironmentID, testInvestigationID, testTaskID,
		scopeRevision, certificate, testEvidenceID, sha256Hex(payload), strings.Repeat("e", 64), strings.Repeat("f", 64))
}

func transactionBackendPID(t *testing.T, tx pgx.Tx) int32 {
	t.Helper()
	var backendPID int32
	if err := tx.QueryRow(context.Background(), `SELECT pg_backend_pid()`).Scan(&backendPID); err != nil {
		t.Fatalf("read PostgreSQL backend PID: %v", err)
	}
	return backendPID
}

func waitForBackendBlock(
	t *testing.T,
	ctx context.Context,
	database *pgxpool.Pool,
	blockedBackendPID int32,
	blockingBackendPID int32,
	statementResult <-chan error,
	description string,
) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		select {
		case err := <-statementResult:
			t.Fatalf("%s completed before the expected lock wait: %v", description, err)
		case <-ticker.C:
			var isBlocked bool
			if err := database.QueryRow(ctx, `
				SELECT $1::integer = ANY(pg_catalog.pg_blocking_pids($2::integer))
			`, blockingBackendPID, blockedBackendPID).Scan(&isBlocked); err != nil {
				t.Fatalf("inspect %s: %v", description, err)
			}
			if isBlocked {
				return
			}
		case <-timer.C:
			t.Fatalf("%s did not reach the expected PostgreSQL lock wait", description)
		case <-ctx.Done():
			t.Fatalf("wait for %s: %v", description, ctx.Err())
		}
	}
}

func TestInvestigationRuntimeRejectsNullFactsReparentingAndStateRegression(t *testing.T) {
	fixture := newRuntimeFixture(t)
	database := fixture.harness.db
	base := fixture.base
	expectSQLConstraint(t, database, "55000", "signals_investigation_correlation_guard", `
		UPDATE signals SET observed_at = observed_at + interval '1 second' WHERE id = $1
	`, testSignalID)
	expectSQLConstraint(t, database, "55000", "signals_investigation_correlation_guard", `
		DELETE FROM signals WHERE id = $1
	`, testSignalID)

	expectSQLState(t, database, "23514", `
		INSERT INTO incidents (
			id, tenant_id, workspace_id, service_id, environment_id, status, severity, title,
			opened_at, updated_at, version, correlation_key, mapping_status,
			last_signal_at, signal_count, runtime_schema_version
		) VALUES (
			'50000000-0000-4000-8000-000000000002', $1, $2, $3, $4, 'OPEN', 'SEV3', 'invalid null',
			$5, $6, 1, NULL, 'EXACT', $5, 1, 'investigation-runtime.v1'
		)
	`, testTenantID, testWorkspaceID, testServiceID, testEnvironmentID, base, base.Add(time.Second))
	expectSQLState(t, database, "23514", `
		INSERT INTO investigations (
			id, tenant_id, workspace_id, incident_id, status, window_start, window_end,
			tool_schema_version, created_at, model_status, idempotency_key, request_hash,
			request_hash_version, updated_at, service_id_snapshot, environment_id_snapshot,
			mapping_status_snapshot, runtime_schema_version
		) VALUES (
			'60000000-0000-4000-8000-000000000002', $1, $2, $3, 'QUEUED', $4, $5,
			'investigation-task.v1', $6, NULL, 'investigate:null-model', $7,
			'investigation.create.v1', $6, $8, $9, 'EXACT', 'investigation-runtime.v1'
		)
	`, testTenantID, testWorkspaceID, testIncidentID, base, base.Add(time.Second), base.Add(3*time.Second),
		strings.Repeat("c", 64), testServiceID, testEnvironmentID)
	expectSQLConstraint(t, database, "23514", "investigations_runtime_shape_ck", `
		INSERT INTO investigations (
			id, tenant_id, workspace_id, incident_id, status, window_start, window_end,
			tool_schema_version, created_at, model_status, idempotency_key, request_hash,
			request_hash_version, updated_at, service_id_snapshot, environment_id_snapshot,
			mapping_status_snapshot, runtime_schema_version
		) VALUES (
			'60000000-0000-4000-8000-000000000012', $1, $2, $3, 'QUEUED', $4, 'infinity',
			'investigation-task.v1', $5, 'PENDING', 'investigate:infinite-window', $6,
			'investigation.create.v1', $5, $7, $8, 'EXACT', 'investigation-runtime.v1'
		)
	`, testTenantID, testWorkspaceID, testIncidentID, base, base.Add(3*time.Second),
		strings.Repeat("1", 64), testServiceID, testEnvironmentID)
	expectSQLState(t, database, "23514", `
		INSERT INTO tool_invocations (
			id, tenant_id, workspace_id, investigation_id, tool_name, tool_version,
			input_hash, status, incident_id, task_key, position, input_document,
			created_at, updated_at, runtime_schema_version
		) VALUES (
			'65000000-0000-4000-8000-000000000002', $1, $2, $3, 'prometheus-staging-v1-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
			'range_query', $4, 'QUEUED', $5, 'null-input', 2, NULL, $6, $6,
			'investigation-runtime.v1'
		)
	`, testTenantID, testWorkspaceID, testInvestigationID, strings.Repeat("d", 64), testIncidentID, base.Add(3*time.Second))
	expectSQLState(t, database, "23514", `
		INSERT INTO investigations (
			id, tenant_id, workspace_id, incident_id, status, window_start, window_end,
			tool_schema_version, created_at, model_status, idempotency_key, request_hash,
			request_hash_version, failure_code, completed_at, updated_at,
			service_id_snapshot, environment_id_snapshot, mapping_status_snapshot,
			runtime_schema_version
		) VALUES (
			'60000000-0000-4000-8000-000000000004', $1, $2, $3, 'FAILED', $4, $5,
			'investigation-task.v1', $6, 'CANCELLED', 'investigate:no-tasks', $7,
			'investigation.create.v1', 'planning_failed', $6, $6, $8, $9, 'EXACT',
			'investigation-runtime.v1'
		)
	`, testTenantID, testWorkspaceID, testIncidentID, base, base.Add(time.Second), base.Add(4*time.Second),
		strings.Repeat("f", 64), testServiceID, testEnvironmentID)
	orphanPayload := []byte(`{"series_count":1}`)
	expectSQLState(t, database, "23514", `
		INSERT INTO evidence (
			id, tenant_id, workspace_id, investigation_id, connector, query_summary,
			collected_at, redacted_summary, content_hash, trust_level, truncated, created_at,
			incident_id, task_id, payload_document, attributes, runtime_schema_version
		) VALUES (
			$1, $2, $3, $4, 'prometheus-staging-v1-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', '{}', $5, '{}', $6,
			'AUTHENTICATED_READ_RUNNER', false, $7, $8, $9, $10, '{}',
			'investigation-runtime.v1'
		)
	`, testEvidenceID, testTenantID, testWorkspaceID, testInvestigationID, base.Add(time.Second),
		sha256Hex(orphanPayload), base.Add(5*time.Second), testIncidentID, testTaskID, orphanPayload)

	expectSQLState(t, database, "55000", `UPDATE incidents SET service_id = NULL WHERE id = $1`, testIncidentID)
	expectSQLState(t, database, "23514", `
		INSERT INTO investigations (
			id, tenant_id, workspace_id, incident_id, status, window_start, window_end,
			tool_schema_version, created_at, model_status, idempotency_key, request_hash,
			request_hash_version, updated_at, service_id_snapshot, environment_id_snapshot,
			mapping_status_snapshot, runtime_schema_version
		) VALUES (
			'60000000-0000-4000-8000-000000000003', $1, $2, $3, 'QUEUED', $4, $5,
			'investigation-task.v1', $6, 'PENDING', 'investigate:mismatch', $7,
			'investigation.create.v1', $6, NULL, $8, 'EXACT', 'investigation-runtime.v1'
		)
	`, testTenantID, testWorkspaceID, testIncidentID, base, base.Add(time.Second), base.Add(3*time.Second),
		strings.Repeat("e", 64), testEnvironmentID)
	expectSQLState(t, database, "55000", `
		UPDATE tool_invocations
		SET incident_id = '50000000-0000-4000-8000-000000000099'
		WHERE id = $1
	`, testTaskID)
	queuedTerminalAt := base.Add(9 * time.Second)
	expectSQLState(t, database, "23514", `
		UPDATE tool_invocations
		SET status = 'FAILED', started_at = $2, completed_at = $2,
		    failure_code = 'collector_failed', updated_at = $2
		WHERE id = $1
	`, testTaskID, queuedTerminalAt)

	startAt := base.Add(10 * time.Second)
	execSQL(t, database, `
		UPDATE investigations
		SET status = 'RUNNING', started_at = $2, updated_at = $2
		WHERE id = $1
	`, testInvestigationID, startAt)
	lateInput := []byte(`{"lookback_minutes":5}`)
	expectSQLState(t, database, "23514", `
		INSERT INTO tool_invocations (
			id, tenant_id, workspace_id, investigation_id, tool_name, tool_version,
			input_hash, status, incident_id, task_key, position, input_document,
			created_at, updated_at, runtime_schema_version
		) VALUES (
			'65000000-0000-4000-8000-000000000010', $1, $2, $3,
			'prometheus-staging-v1-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', 'range_query', $4, 'QUEUED', $5, 'late-task', 2,
			$6, $7, $7, 'investigation-runtime.v1'
		)
	`, testTenantID, testWorkspaceID, testInvestigationID, sha256Hex(lateInput),
		testIncidentID, lateInput, startAt)
	expectSQLState(t, database, "55000", `
		UPDATE investigations SET model_status = 'RUNNING', updated_at = $2 WHERE id = $1
	`, testInvestigationID, startAt.Add(time.Second))
	expectSQLState(t, database, "23514", `
		UPDATE tool_invocations
		SET status = 'FAILED', started_at = $2, completed_at = $3,
		    failure_code = 'collector_failed', updated_at = $2
		WHERE id = $1
	`, testTaskID, startAt.Add(2*time.Second), startAt.Add(time.Second))

	taskCompletedAt := startAt.Add(3 * time.Second)
	execSQL(t, database, `
		UPDATE tool_invocations
		SET status = 'FAILED', started_at = $2, completed_at = $2,
		    failure_code = 'collector_failed', updated_at = $2
		WHERE id = $1
	`, testTaskID, taskCompletedAt)
	execSQL(t, database, `
		UPDATE investigations SET model_status = 'RUNNING', updated_at = $2 WHERE id = $1
	`, testInvestigationID, taskCompletedAt)
	expectSQLState(t, database, "55000", `
		UPDATE investigations SET model_status = 'PENDING', updated_at = $2 WHERE id = $1
	`, testInvestigationID, taskCompletedAt.Add(time.Second))
	completedAt := taskCompletedAt.Add(time.Second)
	execSQL(t, database, `
		UPDATE investigations
		SET status = 'PARTIAL', model_status = 'FAILED', model_failure_code = 'model_unavailable',
		    completed_at = $2, updated_at = $2
		WHERE id = $1
	`, testInvestigationID, completedAt)
	expectSQLState(t, database, "23514", `
		INSERT INTO tool_invocations (
			id, tenant_id, workspace_id, investigation_id, tool_name, tool_version,
			input_hash, status, started_at, completed_at, output_hash, incident_id,
			task_key, position, input_document, failure_code, created_at, updated_at,
			runtime_schema_version
		) VALUES (
			'65000000-0000-4000-8000-000000000011', $1, $2, $3,
			'prometheus-staging-v1-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', 'range_query', $4, 'FAILED', $5, $5, NULL, $6,
			'late-terminal-task', 2, $7, 'late_failure', $5, $5,
			'investigation-runtime.v1'
		)
	`, testTenantID, testWorkspaceID, testInvestigationID, sha256Hex(lateInput),
		completedAt, testIncidentID, lateInput)
	expectSQLState(t, database, "55000", `
		UPDATE investigations
		SET status = 'RUNNING', model_status = 'RUNNING', completed_at = NULL, updated_at = $2
		WHERE id = $1
	`, testInvestigationID, completedAt.Add(time.Second))
	expectSQLState(t, database, "55000", `UPDATE tool_invocations SET status = 'QUEUED' WHERE id = $1`, testTaskID)
	expectSQLState(t, database, "55000", `DELETE FROM tool_invocations WHERE id = $1`, testTaskID)
	expectSQLState(t, database, "55000", `TRUNCATE tool_invocations CASCADE`)
}

func TestInvestigationRuntimeRequiresExactHumanFeedbackAndOneConfirmedRootCause(t *testing.T) {
	fixture := newRuntimeFixture(t)
	database := fixture.harness.db
	ctx := context.Background()
	payload := []byte(`{"series_count":3}`)
	completedAt := fixture.base.Add(10 * time.Second)
	tx, err := database.Begin(ctx)
	if err != nil {
		t.Fatalf("begin evidence transaction: %v", err)
	}
	finished := false
	defer func() {
		if !finished {
			_ = tx.Rollback(ctx)
		}
	}()
	if _, err := tx.Exec(ctx, `
		INSERT INTO evidence (
			id, tenant_id, workspace_id, investigation_id, connector, query_summary,
			collected_at, redacted_summary, content_hash, trust_level, truncated, created_at,
			incident_id, task_id, payload_document, attributes, runtime_schema_version
		) VALUES (
			$1, $2, $3, $4, 'prometheus-staging-v1-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', '{}', $5, $6::jsonb, $7,
			'AUTHENTICATED_READ_RUNNER', false, $8, $9, $10, $11, '{}', 'investigation-runtime.v1'
		)
	`, testEvidenceID, testTenantID, testWorkspaceID, testInvestigationID, fixture.base.Add(time.Second),
		string(payload), sha256Hex(payload), completedAt, testIncidentID, testTaskID, payload); err != nil {
		t.Fatalf("insert runtime evidence: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE tool_invocations
		SET status = 'EVIDENCE', evidence_id = $2, output_hash = $3,
		    started_at = $4, completed_at = $4, updated_at = $4
		WHERE id = $1
	`, testTaskID, testEvidenceID, sha256Hex(payload), completedAt); err != nil {
		t.Fatalf("complete evidence task: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE investigations
		SET status = 'RUNNING', started_at = $2, updated_at = $2
		WHERE id = $1
	`, testInvestigationID, completedAt); err != nil {
		t.Fatalf("start parent investigation with evidence task: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit evidence transaction: %v", err)
	}
	finished = true

	expectSQLState(t, database, "55000", `UPDATE evidence SET attributes = '{"mutated":true}' WHERE id = $1`, testEvidenceID)
	expectSQLState(t, database, "55000", `DELETE FROM evidence WHERE id = $1`, testEvidenceID)
	expectSQLState(t, database, "55000", `TRUNCATE evidence, tool_invocations CASCADE`)
	prematureProposal := []byte(`{"summary":"premature"}`)
	expectSQLConstraint(t, database, "23514", "hypotheses_runtime_initial_state_guard", `
		INSERT INTO hypotheses (
			id, tenant_id, workspace_id, incident_id, investigation_id, status, rank,
			confidence_band, summary, created_at, confidence, proposal_document,
			proposal_hash, unknowns, runtime_schema_version
		) VALUES (
			'70000000-0000-4000-8000-000000000099', $1, $2, $3, $4, 'PROPOSED', 99,
			'LOW', 'Premature hypothesis', $5, 0.1, $6, $7, ARRAY[]::text[],
			'investigation-runtime.v1'
		)
	`, testTenantID, testWorkspaceID, testIncidentID, testInvestigationID,
		completedAt, prematureProposal, sha256Hex(prematureProposal))
	execSQL(t, database, `
		UPDATE investigations SET model_status = 'RUNNING', updated_at = $2 WHERE id = $1
	`, testInvestigationID, completedAt.Add(time.Second))
	expectSQLConstraint(t, database, "23514", "investigations_runtime_hypothesis_set_guard", `
		UPDATE investigations
		SET status = 'COMPLETED', model_status = 'COMPLETED',
		    completed_at = $2, updated_at = $2
		WHERE id = $1
	`, testInvestigationID, completedAt.Add(2*time.Second))

	invalidProposal := []byte(`{"summary":"must not survive a failed model"}`)
	invalidTx, err := database.Begin(ctx)
	if err != nil {
		t.Fatalf("begin invalid model hypothesis transaction: %v", err)
	}
	insertRuntimeHypothesisTx(t, invalidTx, "70000000-0000-4000-8000-000000000098", 98, "LOW", 0.2,
		"Invalid failed-model hypothesis", invalidProposal, completedAt.Add(2*time.Second))
	if _, err := invalidTx.Exec(ctx, `
		UPDATE investigations
		SET status = 'COMPLETED', model_status = 'FAILED', model_failure_code = 'model_unavailable',
		    completed_at = $2, updated_at = $2
		WHERE id = $1
	`, testInvestigationID, completedAt.Add(2*time.Second)); err != nil {
		_ = invalidTx.Rollback(ctx)
		t.Fatalf("stage invalid failed-model finalization: %v", err)
	}
	err = invalidTx.Commit(ctx)
	expectErrorSQLState(t, err, "23514")
	_ = invalidTx.Rollback(ctx)

	proposal := []byte(`{"summary":"pool saturation"}`)
	secondHypothesisID := "70000000-0000-4000-8000-000000000002"
	finalizedAt := completedAt.Add(2 * time.Second)
	tx, err = database.Begin(ctx)
	if err != nil {
		t.Fatalf("begin atomic investigation finalization: %v", err)
	}
	finished = false
	defer func() {
		if !finished {
			_ = tx.Rollback(ctx)
		}
	}()
	insertRuntimeHypothesisTx(t, tx, testHypothesisID, 1, "HIGH", 0.84,
		"Pool saturation", proposal, finalizedAt)
	insertRuntimeHypothesisTx(t, tx, secondHypothesisID, 2, "MEDIUM", 0.62,
		"Retry amplification", proposal, finalizedAt)
	if _, err := tx.Exec(ctx, `
		UPDATE investigations
		SET status = 'COMPLETED', model_status = 'COMPLETED', completed_at = $2, updated_at = $2
		WHERE id = $1
	`, testInvestigationID, finalizedAt); err != nil {
		t.Fatalf("finalize investigation with persisted hypotheses: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit atomic investigation finalization: %v", err)
	}
	finished = true

	lateHypothesisID := "70000000-0000-4000-8000-000000000003"
	expectSQLState(t, database, "23514", `
		WITH inserted AS (
			INSERT INTO hypotheses (
				id, tenant_id, workspace_id, incident_id, investigation_id, status, rank,
				confidence_band, summary, created_at, confidence, proposal_document,
				proposal_hash, unknowns, runtime_schema_version
			) VALUES (
				$1, $2, $3, $4, $5, 'PROPOSED', 3, 'LOW', 'Late hypothesis', $6,
				0.2, $7, $8, ARRAY[]::text[], 'investigation-runtime.v1'
			) RETURNING id
		)
		INSERT INTO hypothesis_evidence (
			tenant_id, workspace_id, investigation_id, hypothesis_id, evidence_id,
			relation, position, runtime_schema_version
		)
		SELECT $2, $3, $5, id, $9, 'SUPPORTS', 1, 'investigation-runtime.v1'
		FROM inserted
	`, lateHypothesisID, testTenantID, testWorkspaceID, testIncidentID, testInvestigationID,
		finalizedAt, proposal, sha256Hex(proposal), testEvidenceID)

	legacyHypothesisID := "70000000-0000-4000-8000-000000000004"
	execSQL(t, database, `
		INSERT INTO hypotheses (
			id, tenant_id, workspace_id, incident_id, investigation_id, status, rank,
			confidence_band, summary, created_at
		) VALUES ($1, $2, $3, $4, $5, 'PROPOSED', 4, 'LOW', 'legacy compatibility', $6)
	`, legacyHypothesisID, testTenantID, testWorkspaceID, testIncidentID,
		testInvestigationID, finalizedAt)
	expectSQLState(t, database, "23514", `
		INSERT INTO hypothesis_evidence (
			tenant_id, workspace_id, investigation_id, hypothesis_id, evidence_id,
			relation, position, runtime_schema_version
		) VALUES ($1, $2, $3, $4, $5, 'SUPPORTS', 1, 'investigation-runtime.v1')
	`, testTenantID, testWorkspaceID, testInvestigationID, legacyHypothesisID, testEvidenceID)
	expectSQLState(t, database, "55000", `
		UPDATE hypotheses
		SET confidence = 0.3, proposal_document = $2, proposal_hash = $3,
		    unknowns = ARRAY[]::text[], runtime_schema_version = 'investigation-runtime.v1'
		WHERE id = $1
	`, legacyHypothesisID, proposal, sha256Hex(proposal))
	execSQL(t, database, `
		INSERT INTO hypothesis_evidence (
			tenant_id, workspace_id, investigation_id, hypothesis_id, evidence_id, relation
		) VALUES ($1, $2, $3, $4, $5, 'SUPPORTS')
	`, testTenantID, testWorkspaceID, testInvestigationID, legacyHypothesisID, testEvidenceID)
	expectSQLState(t, database, "55000", `
		UPDATE hypothesis_evidence
		SET position = 1, runtime_schema_version = 'investigation-runtime.v1'
		WHERE hypothesis_id = $1 AND evidence_id = $2
	`, legacyHypothesisID, testEvidenceID)
	execSQL(t, database, `UPDATE hypotheses SET status = 'CONFIRMED' WHERE id = $1`, legacyHypothesisID)
	expectSQLConstraint(t, database, "23503", "incidents_runtime_confirmed_hypothesis_fk", `
		UPDATE incidents
		SET confirmed_hypothesis_id = $2, updated_at = $3, version = version + 1
		WHERE id = $1
	`, testIncidentID, legacyHypothesisID, finalizedAt.Add(time.Second))
	legacyFeedbackDetails := []byte(`{"reason_code":"legacy_candidate"}`)
	expectSQLConstraint(t, database, "23503", "feedback_runtime_hypothesis_marker_fk", `
		INSERT INTO feedback (
			id, tenant_id, workspace_id, investigation_id, hypothesis_id, actor_id, kind,
			created_at, incident_id, actor_type, details_document, details_hash,
			runtime_schema_version
		) VALUES (
			'80000000-0000-4000-8000-000000000099', $1, $2, $3, $4,
			'user-legacy-check', 'INCONCLUSIVE', $5, $6, 'HUMAN', $7, $8,
			'investigation-runtime.v1'
		)
	`, testTenantID, testWorkspaceID, testInvestigationID, legacyHypothesisID,
		finalizedAt.Add(time.Second), testIncidentID, legacyFeedbackDetails,
		sha256Hex(legacyFeedbackDetails))

	expectSQLState(t, database, "23514", `UPDATE hypotheses SET status = 'CONFIRMED' WHERE id = $1`, testHypothesisID)

	feedbackDetails := []byte(`{"reason_code":"evidence_matches"}`)
	feedbackAt := completedAt.Add(3 * time.Second)
	tx, err = database.Begin(ctx)
	if err != nil {
		t.Fatalf("begin feedback transaction: %v", err)
	}
	finished = false
	defer func() {
		if !finished {
			_ = tx.Rollback(ctx)
		}
	}()
	if _, err := tx.Exec(ctx, `UPDATE hypotheses SET status = 'CONFIRMED' WHERE id = $1`, testHypothesisID); err != nil {
		t.Fatalf("confirm runtime hypothesis: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE incidents
		SET confirmed_hypothesis_id = $2, updated_at = $3, version = version + 1
		WHERE id = $1
	`, testIncidentID, testHypothesisID, feedbackAt); err != nil {
		t.Fatalf("project confirmed root cause: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO feedback (
			id, tenant_id, workspace_id, investigation_id, hypothesis_id, actor_id, kind,
			created_at, incident_id, actor_type, details_document, details_hash, runtime_schema_version
		) VALUES (
			'80000000-0000-4000-8000-000000000010', $1, $2, $3, $4, 'user-1', 'CONFIRMED',
			$5, $6, 'HUMAN', $7, $8, 'investigation-runtime.v1'
		)
	`, testTenantID, testWorkspaceID, testInvestigationID, testHypothesisID, feedbackAt,
		testIncidentID, feedbackDetails, sha256Hex(feedbackDetails)); err != nil {
		t.Fatalf("insert exact HUMAN feedback: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit exact HUMAN feedback: %v", err)
	}
	finished = true
	expectSQLState(t, database, "55000", `TRUNCATE feedback`)
	expectSQLState(t, database, "55000", `TRUNCATE hypothesis_evidence`)

	expectSQLState(t, database, "23514", `
		INSERT INTO feedback (
			id, tenant_id, workspace_id, investigation_id, hypothesis_id, actor_id, kind
		) VALUES (
			'80000000-0000-4000-8000-000000000011', $1, $2, $3, $4,
			'legacy-user', 'INCONCLUSIVE'
		)
	`, testTenantID, testWorkspaceID, testInvestigationID, testHypothesisID)
	execSQL(t, database, `
		INSERT INTO feedback (
			id, tenant_id, workspace_id, investigation_id, hypothesis_id, actor_id, kind
		) VALUES (
			'80000000-0000-4000-8000-000000000012', $1, $2, $3, $4,
			'legacy-user', 'HELPFUL'
		)
	`, testTenantID, testWorkspaceID, testInvestigationID, testHypothesisID)
	expectSQLState(t, database, "55000", `
		UPDATE feedback
		SET kind = 'INCONCLUSIVE', incident_id = $1, actor_type = 'HUMAN',
		    details_document = $2, details_hash = $3,
		    runtime_schema_version = 'investigation-runtime.v1'
		WHERE id = '80000000-0000-4000-8000-000000000012'
	`, testIncidentID, feedbackDetails, sha256Hex(feedbackDetails))

	expectSQLState(t, database, "23505", `UPDATE hypotheses SET status = 'CONFIRMED' WHERE id = $1`, secondHypothesisID)
}

func insertRuntimeHypothesisTx(
	t *testing.T,
	tx pgx.Tx,
	hypothesisID string,
	rank int,
	confidenceBand string,
	confidence float64,
	summary string,
	proposal []byte,
	createdAt time.Time,
) {
	t.Helper()
	ctx := context.Background()
	if _, err := tx.Exec(ctx, `
		INSERT INTO hypotheses (
			id, tenant_id, workspace_id, incident_id, investigation_id, status, rank,
			confidence_band, summary, created_at, confidence, proposal_document,
			proposal_hash, unknowns, runtime_schema_version
		) VALUES (
			$1, $2, $3, $4, $5, 'PROPOSED', $6, $7, $8, $9,
			$10, $11, $12, ARRAY[]::text[], 'investigation-runtime.v1'
		)
	`, hypothesisID, testTenantID, testWorkspaceID, testIncidentID, testInvestigationID,
		rank, confidenceBand, summary, createdAt, confidence, proposal, sha256Hex(proposal)); err != nil {
		t.Fatalf("insert runtime hypothesis: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO hypothesis_evidence (
			tenant_id, workspace_id, investigation_id, hypothesis_id, evidence_id,
			relation, position, runtime_schema_version
		) VALUES ($1, $2, $3, $4, $5, 'SUPPORTS', 1, 'investigation-runtime.v1')
	`, testTenantID, testWorkspaceID, testInvestigationID, hypothesisID, testEvidenceID); err != nil {
		t.Fatalf("insert runtime hypothesis evidence: %v", err)
	}
}

func TestRunnerEvidenceReceiptRequiresCurrentReadIdentityExactScopeAndTerminalResult(t *testing.T) {
	fixture := newRuntimeFixture(t)
	database := fixture.harness.db
	ctx := context.Background()
	completedAt := fixture.base.Add(10 * time.Second)
	tx, err := database.Begin(ctx)
	if err != nil {
		t.Fatalf("begin atomic task completion: %v", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if _, err := tx.Exec(ctx, `
		UPDATE tool_invocations
		SET status = 'FAILED', started_at = $2, completed_at = $2,
		    failure_code = 'collector_failed', updated_at = $2
		WHERE id = $1
	`, testTaskID, completedAt); err != nil {
		t.Fatalf("complete failed read task: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE investigations
		SET status = 'RUNNING', started_at = $2, updated_at = $2
		WHERE id = $1
	`, testInvestigationID, completedAt); err != nil {
		t.Fatalf("start parent investigation with failed task: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit atomic task completion: %v", err)
	}
	committed = true
	latePayload := []byte(`{"series_count":2}`)
	expectSQLState(t, database, "23514", `
		INSERT INTO evidence (
			id, tenant_id, workspace_id, investigation_id, connector, query_summary,
			collected_at, redacted_summary, content_hash, trust_level, truncated, created_at,
			incident_id, task_id, payload_document, attributes, runtime_schema_version
		) VALUES (
			$1, $2, $3, $4, 'prometheus-staging-v1-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', '{}', $5, '{}', $6,
			'AUTHENTICATED_READ_RUNNER', false, $5, $7, $8, $9, '{}',
			'investigation-runtime.v1'
		)
	`, testEvidenceID, testTenantID, testWorkspaceID, testInvestigationID, completedAt,
		sha256Hex(latePayload), testIncidentID, testTaskID, latePayload)

	readRevision, readCertificate := seedRuntimeRunner(t, database, "read-runner-1", "READ", true, false)
	writeRevision, writeCertificate := seedRuntimeRunner(t, database, "write-runner-1", "WRITE", true, false)
	noScopeRevision, noScopeCertificate := seedRuntimeRunner(t, database, "read-runner-no-scope", "READ", false, false)
	revokedRevision, revokedCertificate := seedRuntimeRunner(t, database, "read-runner-revoked", "READ", true, true)

	receiptInsert := `
		INSERT INTO runner_evidence_receipts (
			id, tenant_id, workspace_id, environment_id, investigation_id, task_id,
			runner_id, scope_revision, certificate_sha256, connector_id,
			failure_code, idempotency_key, request_hash, receipt_hash, schema_version
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'prometheus-staging-v1-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
			$10, $11, $12, $13, 'runner-evidence.v1')
	`
	expectSQLState(t, database, "23514", receiptInsert,
		"69000000-0000-4000-8000-000000000001", testTenantID, testWorkspaceID, testEnvironmentID,
		testInvestigationID, testTaskID, "write-runner-1", writeRevision, writeCertificate,
		"collector_failed", "receipt:write-pool", strings.Repeat("1", 64), strings.Repeat("2", 64))
	expectSQLState(t, database, "23514", receiptInsert,
		"69000000-0000-4000-8000-000000000002", testTenantID, testWorkspaceID, testEnvironmentID,
		testInvestigationID, testTaskID, "read-runner-1", readRevision+1, readCertificate,
		"collector_failed", "receipt:stale-revision", strings.Repeat("3", 64), strings.Repeat("4", 64))
	expectSQLState(t, database, "23514", receiptInsert,
		"69000000-0000-4000-8000-000000000003", testTenantID, testWorkspaceID, testEnvironmentID,
		testInvestigationID, testTaskID, "read-runner-no-scope", noScopeRevision, noScopeCertificate,
		"collector_failed", "receipt:no-scope", strings.Repeat("5", 64), strings.Repeat("6", 64))
	expectSQLState(t, database, "23514", receiptInsert,
		"69000000-0000-4000-8000-000000000004", testTenantID, testWorkspaceID, testEnvironmentID,
		testInvestigationID, testTaskID, "read-runner-revoked", revokedRevision, revokedCertificate,
		"collector_failed", "receipt:revoked", strings.Repeat("7", 64), strings.Repeat("8", 64))
	expectSQLState(t, database, "23514", receiptInsert,
		"69000000-0000-4000-8000-000000000005", testTenantID, testWorkspaceID, testEnvironmentID,
		testInvestigationID, testTaskID, "read-runner-1", readRevision, readCertificate,
		"different_failure", "receipt:result-mismatch", strings.Repeat("9", 64), strings.Repeat("a", 64))

	validReceiptID := "69000000-0000-4000-8000-000000000010"
	execSQL(t, database, receiptInsert,
		validReceiptID, testTenantID, testWorkspaceID, testEnvironmentID,
		testInvestigationID, testTaskID, "read-runner-1", readRevision, readCertificate,
		"collector_failed", "receipt:valid", strings.Repeat("b", 64), strings.Repeat("c", 64))
	expectSQLState(t, database, "55000", `UPDATE runner_evidence_receipts SET failure_code = 'changed' WHERE id = $1`, validReceiptID)
	expectSQLState(t, database, "55000", `TRUNCATE runner_evidence_receipts`)
	expectMigrationSQLState(t, database, "000010_investigation_runtime.down.sql", "55000")
}

func TestRunnerEvidenceReceiptScopeRemovalUsesBindingBeforeRegistrationLockOrder(t *testing.T) {
	fixture := newRuntimeFixture(t)
	database := fixture.harness.db
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	completedAt := fixture.base.Add(10 * time.Second)
	completionTx, err := database.Begin(ctx)
	if err != nil {
		t.Fatalf("begin receipt task completion: %v", err)
	}
	if _, err := completionTx.Exec(ctx, `
		UPDATE tool_invocations
		SET status = 'FAILED', started_at = $2, completed_at = $2,
		    failure_code = 'collector_failed', updated_at = $2
		WHERE id = $1
	`, testTaskID, completedAt); err != nil {
		_ = completionTx.Rollback(ctx)
		t.Fatalf("complete failed task for scope removal: %v", err)
	}
	if _, err := completionTx.Exec(ctx, `
		UPDATE investigations
		SET status = 'RUNNING', started_at = $2, updated_at = $2
		WHERE id = $1
	`, testInvestigationID, completedAt); err != nil {
		_ = completionTx.Rollback(ctx)
		t.Fatalf("start parent for scope removal: %v", err)
	}
	if err := completionTx.Commit(ctx); err != nil {
		t.Fatalf("commit receipt task completion: %v", err)
	}

	runnerID := "read-runner-scope-removal"
	scopeRevision, certificate := seedRuntimeRunner(t, database, runnerID, "READ", true, false)
	scopeTx, err := database.Begin(ctx)
	if err != nil {
		t.Fatalf("begin scope removal transaction: %v", err)
	}
	defer func() { _ = scopeTx.Rollback(context.Background()) }()
	receiptTx, err := database.Begin(ctx)
	if err != nil {
		t.Fatalf("begin concurrent receipt transaction: %v", err)
	}
	defer func() { _ = receiptTx.Rollback(context.Background()) }()
	scopeBackendPID := transactionBackendPID(t, scopeTx)
	receiptBackendPID := transactionBackendPID(t, receiptTx)

	if _, err := scopeTx.Exec(ctx, `
		SELECT 1
		FROM runner_scope_bindings
		WHERE tenant_id = $1 AND runner_id = $2
		  AND workspace_id = $3 AND environment_id = $4
		FOR UPDATE
	`, testTenantID, runnerID, testWorkspaceID, testEnvironmentID); err != nil {
		t.Fatalf("lock exact scope binding before removal: %v", err)
	}

	receiptInsert := make(chan error, 1)
	go func() {
		_, execErr := receiptTx.Exec(ctx, `
			INSERT INTO runner_evidence_receipts (
				id, tenant_id, workspace_id, environment_id, investigation_id, task_id,
				runner_id, scope_revision, certificate_sha256, connector_id,
				failure_code, idempotency_key, request_hash, receipt_hash, schema_version
			) VALUES (
				'69000000-0000-4000-8000-000000000020', $1, $2, $3, $4, $5,
				$6, $7, $8, 'prometheus-staging-v1-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', 'collector_failed',
				'receipt:scope-removal', $9, $10, 'runner-evidence.v1'
			)
		`, testTenantID, testWorkspaceID, testEnvironmentID, testInvestigationID, testTaskID,
			runnerID, scopeRevision, certificate, strings.Repeat("c", 64), strings.Repeat("d", 64))
		receiptInsert <- execErr
	}()
	waitForBackendBlock(t, ctx, database, receiptBackendPID, scopeBackendPID,
		receiptInsert, "runner evidence receipt scope binding lock")

	if _, err := scopeTx.Exec(ctx, `
		DELETE FROM runner_scope_bindings
		WHERE tenant_id = $1 AND runner_id = $2
		  AND workspace_id = $3 AND environment_id = $4
	`, testTenantID, runnerID, testWorkspaceID, testEnvironmentID); err != nil {
		t.Fatalf("remove scope while receipt waits on binding: %v", err)
	}
	if err := scopeTx.Commit(ctx); err != nil {
		t.Fatalf("commit scope removal without reverse-lock deadlock: %v", err)
	}

	select {
	case err := <-receiptInsert:
		expectErrorSQLState(t, err, "23514")
	case <-ctx.Done():
		t.Fatalf("receipt remained blocked after scope removal: %v", ctx.Err())
	}
	var currentRevision int64
	if err := database.QueryRow(ctx, `
		SELECT scope_revision
		FROM runner_registrations
		WHERE tenant_id = $1 AND runner_id = $2
	`, testTenantID, runnerID).Scan(&currentRevision); err != nil {
		t.Fatalf("read revision after concurrent scope removal: %v", err)
	}
	if currentRevision != scopeRevision+1 {
		t.Fatalf("scope revision = %d, want %d after removal", currentRevision, scopeRevision+1)
	}
}

func TestInvestigationIdempotencyLedgerIsWorkspaceWideHashedAndAppendOnly(t *testing.T) {
	fixture := newRuntimeFixture(t)
	database := fixture.harness.db
	snapshot := []byte(`{"investigation_id":"60000000-0000-4000-8000-000000000001"}`)
	insert := `
		INSERT INTO investigation_idempotency_records (
			tenant_id, workspace_id, idempotency_key, operation, request_hash,
			request_hash_version, resource_type, resource_id, result_snapshot,
			result_snapshot_sha256, result_snapshot_version
		) VALUES (
			$1, $2, $3, 'finalize_investigation', $4, 'investigation.finalize.v1',
			'INVESTIGATION', $5, $6, $7, 'investigation.finalize-result.v1'
		)
	`
	expectSQLState(t, database, "23514", insert,
		testTenantID, testWorkspaceID, "finalize:bad-snapshot", strings.Repeat("a", 64),
		testInvestigationID, snapshot, strings.Repeat("0", 64))
	key := "finalize:valid-snapshot"
	execSQL(t, database, insert,
		testTenantID, testWorkspaceID, key, strings.Repeat("b", 64),
		testInvestigationID, snapshot, sha256Hex(snapshot))
	expectSQLState(t, database, "23505", `
		INSERT INTO investigation_idempotency_records (
			tenant_id, workspace_id, idempotency_key, operation, request_hash,
			request_hash_version, resource_type, resource_id
		) VALUES ($1, $2, $3, 'fail_investigation', $4, 'investigation.fail.v1', 'INVESTIGATION', $5)
	`, testTenantID, testWorkspaceID, key, strings.Repeat("c", 64), testInvestigationID)
	expectSQLState(t, database, "55000", `
		UPDATE investigation_idempotency_records SET request_hash = $2
		WHERE workspace_id = $1 AND idempotency_key = $3
	`, testWorkspaceID, strings.Repeat("d", 64), key)
	expectSQLState(t, database, "55000", `DELETE FROM investigation_idempotency_records WHERE workspace_id = $1`, testWorkspaceID)
	expectSQLState(t, database, "55000", `TRUNCATE investigation_idempotency_records`)
}

func seedRuntimeRunner(
	t *testing.T,
	database *pgxpool.Pool,
	runnerID, pool string,
	withBinding, revoked bool,
) (int64, string) {
	t.Helper()
	certificateHash := sha256Hex([]byte("certificate:" + runnerID))
	execRunnerSQL(t, database, `
		INSERT INTO runner_registrations (
			runner_id, tenant_id, spiffe_uri, runner_pool, enabled, scope_revision, max_concurrency
		) VALUES ($1, $2, $3, $4, true, 1, 1)
	`, runnerID, testTenantID, "spiffe://aiops.test/runner/"+strings.ToLower(pool)+"/"+runnerID, pool)
	if withBinding {
		execRunnerSQL(t, database, `
			INSERT INTO runner_scope_bindings (runner_id, tenant_id, workspace_id, environment_id)
			VALUES ($1, $2, $3, $4)
		`, runnerID, testTenantID, testWorkspaceID, testEnvironmentID)
	}
	now := time.Now().UTC()
	execRunnerSQL(t, database, `
		INSERT INTO runner_certificates (
			certificate_sha256, runner_id, tenant_id, issuer_key_id, serial_hex,
			spki_sha256, status, not_before, not_after
		) VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE', $7, $8)
	`, certificateHash, runnerID, testTenantID, "issuer:"+runnerID,
		sha256Hex([]byte("serial:"+runnerID)), sha256Hex([]byte("spki:"+runnerID)),
		now.Add(-time.Minute), now.Add(time.Hour))
	if revoked {
		execRunnerSQL(t, database, `
			UPDATE runner_certificates SET status = 'REVOKED', revocation_reason = 'integration test'
			WHERE certificate_sha256 = $1
		`, certificateHash)
	}
	var revision int64
	if err := database.QueryRow(context.Background(), `
		SELECT scope_revision FROM runner_registrations WHERE runner_id = $1
	`, runnerID).Scan(&revision); err != nil {
		t.Fatalf("read runner scope revision: %v", err)
	}
	return revision, certificateHash
}

func execRunnerSQL(
	t *testing.T,
	database *pgxpool.Pool,
	query string,
	arguments ...any,
) {
	t.Helper()
	if _, err := database.Exec(context.Background(), query, arguments...); err != nil {
		t.Fatalf("seed runtime runner: %v", err)
	}
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
