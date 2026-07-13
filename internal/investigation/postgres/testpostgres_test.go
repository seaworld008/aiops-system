package postgres_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type postgresHarness struct {
	admin  *pgxpool.Pool
	db     *pgxpool.Pool
	schema string
}

func newPostgresHarness(t *testing.T) *postgresHarness {
	t.Helper()
	dsn := os.Getenv("AIOPS_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("AIOPS_TEST_POSTGRES_DSN is not configured; real PostgreSQL 18.4 or newer 18.x migration tests were not run")
	}
	ctx := context.Background()
	adminConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse PostgreSQL test DSN: %v", err)
	}
	adminConfig.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	admin, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatalf("connect PostgreSQL test database: %v", err)
	}
	var serverVersion int
	if err := admin.QueryRow(ctx, `SELECT current_setting('server_version_num')::integer`).Scan(&serverVersion); err != nil {
		admin.Close()
		t.Fatalf("read PostgreSQL server version: %v", err)
	}
	if serverVersion < 180004 || serverVersion >= 190000 {
		admin.Close()
		t.Fatalf("integration harness requires PostgreSQL 18.4 or newer 18.x, got server_version_num=%d", serverVersion)
	}

	schema := "aiops_m5_" + randomHex(t, 8)
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatalf("create isolated PostgreSQL schema: %v", err)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatalf("parse isolated PostgreSQL config: %v", err)
	}
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = make(map[string]string)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	if config.MaxConns < 8 {
		config.MaxConns = 8
	}
	database, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatalf("connect isolated PostgreSQL schema: %v", err)
	}
	harness := &postgresHarness{admin: admin, db: database, schema: schema}
	t.Cleanup(func() {
		database.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
	})
	return harness
}

// extendedPool mirrors pgx's production-default extended protocol while the
// migration pool remains on simple protocol for transactional multi-statement
// migration files. Repository integration tests must use this pool so binary
// and text codec negotiation is exercised instead of being masked by simple
// interpolation.
func (harness *postgresHarness) extendedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig(os.Getenv("AIOPS_TEST_POSTGRES_DSN"))
	if err != nil {
		t.Fatalf("parse PostgreSQL extended-protocol test DSN: %v", err)
	}
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheStatement
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = make(map[string]string)
	}
	config.ConnConfig.RuntimeParams["search_path"] = harness.schema
	if config.MaxConns < 16 {
		config.MaxConns = 16
	}
	database, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatalf("connect extended-protocol PostgreSQL test pool: %v", err)
	}
	if err := database.Ping(context.Background()); err != nil {
		database.Close()
		t.Fatalf("ping extended-protocol PostgreSQL test pool: %v", err)
	}
	t.Cleanup(database.Close)
	return database
}

func (harness *postgresHarness) applyUpBeforeTen(t *testing.T) {
	t.Helper()
	harness.applyMigrations(t, ".up.sql", false, func(name string) bool {
		return name < "000010_investigation_runtime.up.sql"
	})
}

func (harness *postgresHarness) applyMigration(t *testing.T, name string) {
	t.Helper()
	contents := readMigration(t, name)
	if _, err := harness.db.Exec(context.Background(), contents); err != nil {
		t.Fatalf("apply migration %s: %v", name, err)
	}
}

func (harness *postgresHarness) applyMigrations(
	t *testing.T,
	suffix string,
	reverse bool,
	include func(string) bool,
) {
	t.Helper()
	directory := migrationDirectory(t)
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read migration directory: %v", err)
	}
	files := make([]string, 0)
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), suffix) && (include == nil || include(entry.Name())) {
			files = append(files, entry.Name())
		}
	}
	sort.Strings(files)
	if reverse {
		for left, right := 0, len(files)-1; left < right; left, right = left+1, right-1 {
			files[left], files[right] = files[right], files[left]
		}
	}
	for _, name := range files {
		harness.applyMigration(t, name)
	}
}

func migrationDirectory(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve migration integration test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "../../../migrations"))
}

func randomHex(t *testing.T, size int) string {
	t.Helper()
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		t.Fatalf("generate isolated schema name: %v", err)
	}
	return hex.EncodeToString(value)
}

func execSQL(t *testing.T, database *pgxpool.Pool, query string, arguments ...any) {
	t.Helper()
	if _, err := database.Exec(context.Background(), query, arguments...); err != nil {
		t.Fatalf("exec PostgreSQL fixture: %v", err)
	}
}

func expectSQLState(t *testing.T, database *pgxpool.Pool, sqlState, query string, arguments ...any) {
	t.Helper()
	_, err := database.Exec(context.Background(), query, arguments...)
	if err == nil {
		t.Fatalf("SQL unexpectedly succeeded; want SQLSTATE %s", sqlState)
	}
	expectErrorSQLState(t, err, sqlState)
}

func expectErrorSQLState(t *testing.T, err error, sqlState string) {
	t.Helper()
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != sqlState {
		t.Fatalf("SQL error = %v, want SQLSTATE %s", err, sqlState)
	}
}

func expectSQLConstraint(
	t *testing.T,
	database *pgxpool.Pool,
	sqlState string,
	constraint string,
	query string,
	arguments ...any,
) {
	t.Helper()
	_, err := database.Exec(context.Background(), query, arguments...)
	if err == nil {
		t.Fatalf("SQL unexpectedly succeeded; want constraint %s", constraint)
	}
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != sqlState || postgresError.ConstraintName != constraint {
		t.Fatalf("SQL error = %v, want SQLSTATE %s constraint %s", err, sqlState, constraint)
	}
}

func expectMigrationSQLState(t *testing.T, database *pgxpool.Pool, name, sqlState string) {
	t.Helper()
	_, err := database.Exec(context.Background(), readMigration(t, name))
	if err == nil {
		t.Fatalf("migration %s unexpectedly succeeded; want SQLSTATE %s", name, sqlState)
	}
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != sqlState {
		t.Fatalf("migration %s error = %v, want SQLSTATE %s", name, err, sqlState)
	}
}

func qualifiedName(schema, relation string) string {
	return fmt.Sprintf("%s.%s", pgx.Identifier{schema}.Sanitize(), pgx.Identifier{relation}.Sanitize())
}
