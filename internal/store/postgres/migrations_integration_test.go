package postgres_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
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

	expectSQLFailure(t, ctx, database, `
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

	expectSQLFailure(t, ctx, database, `UPDATE incidents SET confirmed_hypothesis_id = $1 WHERE id = $2`, hypothesis1, incident1)
	execSQL(t, ctx, database, `UPDATE hypotheses SET status = 'CONFIRMED' WHERE id = $1`, hypothesis1)
	execSQL(t, ctx, database, `UPDATE incidents SET confirmed_hypothesis_id = $1 WHERE id = $2`, hypothesis1, incident1)
	expectSQLFailure(t, ctx, database, `UPDATE hypotheses SET status = 'REJECTED' WHERE id = $1`, hypothesis1)
	expectSQLFailure(t, ctx, database, `
		INSERT INTO feedback (id, tenant_id, workspace_id, investigation_id, actor_id, kind)
		VALUES ('80000000-0000-4000-8000-000000000001', $1, $2, $3, 'user-1', 'CONFIRM')
	`, tenant1, workspace1, investigation1)

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

func expectSQLFailure(t *testing.T, ctx context.Context, database *pgxpool.Pool, query string, arguments ...any) {
	t.Helper()
	if _, err := database.Exec(ctx, query, arguments...); err == nil {
		t.Fatal("SQL unexpectedly succeeded")
	}
}
