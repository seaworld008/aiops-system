package postgres_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aiops-system/control-plane/internal/domain"
	"github.com/aiops-system/control-plane/internal/store"
	postgresstore "github.com/aiops-system/control-plane/internal/store/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
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
	database, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("NewWithConfig() error = %v", err)
	}
	defer database.Close()
	if _, err := database.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatalf("reset test schema: %v", err)
	}

	migrationDirectory := migrationPath(t)
	applyMigrations(t, ctx, database, migrationDirectory, ".up.sql", false)

	const (
		tenant1        = "10000000-0000-4000-8000-000000000001"
		tenant2        = "10000000-0000-4000-8000-000000000002"
		workspace1     = "20000000-0000-4000-8000-000000000001"
		workspace2     = "20000000-0000-4000-8000-000000000002"
		integration1   = "30000000-0000-4000-8000-000000000001"
		signal1        = "40000000-0000-4000-8000-000000000001"
		incident1      = "50000000-0000-4000-8000-000000000001"
		investigation1 = "60000000-0000-4000-8000-000000000001"
		hypothesis1    = "70000000-0000-4000-8000-000000000001"
	)
	execSQL(t, ctx, database, `INSERT INTO tenants (id, name) VALUES ($1, 'tenant-1'), ($2, 'tenant-2')`, tenant1, tenant2)
	execSQL(t, ctx, database, `INSERT INTO workspaces (id, tenant_id, name) VALUES ($1, $2, 'workspace-1'), ($3, $4, 'workspace-2')`, workspace1, tenant1, workspace2, tenant2)
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
	execSQL(t, ctx, database, `UPDATE outbox_events SET claim_expires_at = statement_timestamp() - interval '1 second' WHERE id = $1`, firstClaim[0].ID)
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

	applyMigrations(t, ctx, database, migrationDirectory, ".down.sql", true)
	var relationName *string
	if err := database.QueryRow(ctx, `SELECT to_regclass('public.tenants')::text`).Scan(&relationName); err != nil {
		t.Fatalf("check down migration: %v", err)
	}
	if relationName != nil {
		t.Fatalf("tenants table remains after down migration: %s", *relationName)
	}
}

func migrationPath(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve migration test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "../../../migrations"))
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
		contents, err := os.ReadFile(filename)
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", filename, err)
		}
		if _, err := database.Exec(ctx, string(contents)); err != nil {
			t.Fatalf("apply migration %s: %v", filepath.Base(filename), err)
		}
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
