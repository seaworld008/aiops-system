package postgres_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/authn"
	"github.com/seaworld008/aiops-system/internal/authz"
	"github.com/seaworld008/aiops-system/internal/httpapi"
	"github.com/seaworld008/aiops-system/internal/overview"
	overviewpostgres "github.com/seaworld008/aiops-system/internal/overview/postgres"
)

const (
	integrationTenantA      = "91111111-1111-4111-8111-111111111111"
	integrationWorkspaceA   = "92222222-2222-4222-8222-222222222222"
	integrationEnvironmentA = "93333333-3333-4333-8333-333333333333"
	integrationSourceA      = "94444444-4444-4444-8444-444444444444"
	integrationRevisionA    = "95555555-5555-4555-8555-555555555555"
	integrationRunA         = "96666666-6666-4666-8666-666666666666"
	integrationAssetA1      = "97777777-7777-4777-8777-777777777771"
	integrationAssetA2      = "97777777-7777-4777-8777-777777777772"
	integrationConflictA    = "98888888-8888-4888-8888-888888888888"
	integrationBucketA      = "99999999-9999-4999-8999-999999999999"

	integrationTenantB      = "a1111111-1111-4111-8111-111111111111"
	integrationWorkspaceB   = "a2222222-2222-4222-8222-222222222222"
	integrationEnvironmentB = "a3333333-3333-4333-8333-333333333333"
	integrationSourceB      = "a4444444-4444-4444-8444-444444444444"
	integrationRevisionB    = "a5555555-5555-4555-8555-555555555555"
	integrationRunB         = "a6666666-6666-4666-8666-666666666666"
	integrationAssetB       = "a7777777-7777-4777-8777-777777777777"

	integrationApplicationName = "overview-task30-application"
	integrationMigrationName   = "overview-task30-migration"
)

func TestOverviewRepositoryPostgreSQL18TLSApplicationScopeAndTimeoutIntegration(t *testing.T) {
	harness := newOverviewHarness(t)
	harness.applyThroughAssets(t)
	seedOverviewScopes(t, harness.adminDatabase)

	repository, err := overviewpostgres.New(harness.application)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ctx := context.Background()
	scopeA := integrationScopeA()
	scopeB := integrationScopeB()

	resolved, err := repository.ResolveScope(ctx, integrationWorkspaceA, integrationEnvironmentA)
	if err != nil || resolved != scopeA {
		t.Fatalf("ResolveScope(A) = (%#v, %v), want exact A scope", resolved, err)
	}
	if _, err := repository.ResolveScope(
		ctx,
		integrationWorkspaceA,
		integrationEnvironmentB,
	); !errors.Is(err, assetcatalog.ErrNotFound) {
		t.Fatalf("ResolveScope(cross relationship) error = %v, want ErrNotFound", err)
	}
	for _, feature := range []overview.Feature{overview.FeatureAssets, overview.FeatureSources} {
		state, err := repository.State(ctx, scopeA, feature)
		if err != nil || state != overview.StateAvailable {
			t.Fatalf("State(A,%s) = (%s, %v), want AVAILABLE", feature, state, err)
		}
	}

	assetsA, err := repository.ReadAssetFacts(ctx, scopeA)
	if err != nil {
		t.Fatalf("ReadAssetFacts(A) error = %v", err)
	}
	assetsB, err := repository.ReadAssetFacts(ctx, scopeB)
	if err != nil {
		t.Fatalf("ReadAssetFacts(B) error = %v", err)
	}
	if assetsA.Total != 2 || assetsA.StaleCount != 1 || assetsA.OpenConflictCount != 1 ||
		assetsB.Total != 1 || assetsB.StaleCount != 0 || assetsB.OpenConflictCount != 0 {
		t.Fatalf("dual-scope asset facts = A:%#v B:%#v", assetsA, assetsB)
	}

	sourcesA, err := repository.ReadSourceFacts(ctx, scopeA)
	if err != nil {
		t.Fatalf("ReadSourceFacts(A) error = %v", err)
	}
	sourcesB, err := repository.ReadSourceFacts(ctx, scopeB)
	if err != nil {
		t.Fatalf("ReadSourceFacts(B) error = %v", err)
	}
	if sourcesA.Total != 1 || sourcesA.BackpressuredCount != 1 ||
		len(sourcesA.ProviderGates) != 1 ||
		sourcesA.ProviderGates[0].ProviderKind != "MANUAL_V1" ||
		sourcesB.Total != 1 || sourcesB.BackpressuredCount != 0 ||
		len(sourcesB.ProviderGates) != 1 ||
		sourcesB.ProviderGates[0].ProviderKind != "EXTERNAL_V1" {
		t.Fatalf("dual-scope source facts = A:%#v B:%#v", sourcesA, sourcesB)
	}

	now := time.Now().UTC()
	authorizer, err := authz.NewAuthorizer(5*time.Minute, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	service, err := overview.NewService(repository, repository, authorizer, overview.Options{
		QueryTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	principal := authn.Principal{
		Subject: "overview-integration-user", TenantID: integrationTenantA,
		Roles:           []authn.Role{authn.RoleViewer},
		WorkspaceIDs:    []string{integrationWorkspaceA},
		EnvironmentIDs:  []string{integrationEnvironmentA},
		AuthenticatedAt: now.Add(-time.Minute),
		ExpiresAt:       now.Add(time.Hour),
	}

	router := httpapi.NewRouter(httpapi.Dependencies{
		Authenticator: integrationAuthenticator{principal: principal},
		Overview:      service,
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(
		http.MethodGet,
		"/api/v1/workspaces/"+integrationWorkspaceA+
			"/environments/"+integrationEnvironmentA+"/overview",
		nil,
	))
	if response.Code != http.StatusOK {
		t.Fatalf("real repository overview HTTP = %d %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" ||
		!strings.HasPrefix(response.Header().Get("ETag"), `"overview:`) {
		t.Fatalf("overview headers = %#v", response.Header())
	}
	var projected map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &projected); err != nil {
		t.Fatalf("decode overview HTTP response: %v", err)
	}
	lowerBody := strings.ToLower(response.Body.String())
	for _, forbidden := range []string{
		integrationTenantA,
		"scope-a-external-1",
		"scope-a-external-2",
		`"tenant_id"`,
		`"credential"`,
		`"endpoint"`,
		`"checkpoint"`,
		`"lease_`,
		`"fence_`,
	} {
		if strings.Contains(lowerBody, strings.ToLower(forbidden)) {
			t.Errorf("real overview projection leaked %q: %s", forbidden, response.Body.String())
		}
	}

	crossScope := httptest.NewRecorder()
	router.ServeHTTP(crossScope, httptest.NewRequest(
		http.MethodGet,
		"/api/v1/workspaces/"+integrationWorkspaceB+
			"/environments/"+integrationEnvironmentB+"/overview",
		nil,
	))
	if crossScope.Code != http.StatusNotFound ||
		!strings.Contains(crossScope.Body.String(), `"code":"overview_not_found"`) ||
		strings.Contains(crossScope.Body.String(), integrationTenantB) {
		t.Fatalf("cross-scope overview = %d %s", crossScope.Code, crossScope.Body.String())
	}

	lock, err := harness.adminDatabase.Begin(ctx)
	if err != nil {
		t.Fatalf("begin asset timeout lock: %v", err)
	}
	defer func() { _ = lock.Rollback(context.Background()) }()
	if _, err := lock.Exec(ctx, `LOCK TABLE public.assets IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatalf("lock assets for timeout projection: %v", err)
	}
	started := time.Now()
	partial, err := service.Get(ctx, principal, integrationWorkspaceA, integrationEnvironmentA)
	if err != nil {
		t.Fatalf("Get(partial) error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 700*time.Millisecond {
		t.Fatalf("partition timeout elapsed = %s, want bounded result", elapsed)
	}
	if partial.Sections[overview.FeatureAssets].State != overview.StatePartial ||
		partial.Sections[overview.FeatureSources].State != overview.StateAvailable ||
		partial.Sections[overview.FeatureSources].SourceFacts == nil ||
		partial.Sections[overview.FeatureConnections].State != overview.StateNotStarted {
		t.Fatalf("partition timeout snapshot = %#v", partial.Sections)
	}
}

type integrationAuthenticator struct {
	principal authn.Principal
}

func (authenticator integrationAuthenticator) Authenticate(*http.Request) (authn.Principal, error) {
	return authenticator.principal, nil
}

type overviewHarness struct {
	control       *pgxpool.Pool
	adminDatabase *pgxpool.Pool
	migration     *pgxpool.Pool
	application   *pgxpool.Pool
	databaseName  string
}

func newOverviewHarness(t *testing.T) *overviewHarness {
	t.Helper()
	adminDSN := strings.TrimSpace(os.Getenv("AIOPS_TEST_POSTGRES_DSN"))
	migrationDSN := strings.TrimSpace(os.Getenv("AIOPS_TEST_POSTGRES_MIGRATION_DSN"))
	applicationDSN := strings.TrimSpace(os.Getenv("AIOPS_TEST_POSTGRES_APPLICATION_DSN"))
	if adminDSN == "" || migrationDSN == "" || applicationDSN == "" {
		t.Fatal("all PostgreSQL test-control, migration, and application DSNs are required; overview integration cannot skip")
	}
	if adminDSN == migrationDSN || adminDSN == applicationDSN || migrationDSN == applicationDSN {
		t.Fatal("PostgreSQL test-control, migration, and application DSNs must be distinct")
	}
	adminConfig := parseOverviewPoolConfig(t, adminDSN, "aiops", "overview-task30-control")
	migrationConfig := parseOverviewPoolConfig(
		t,
		migrationDSN,
		"aiops_migrator",
		integrationMigrationName,
	)
	applicationConfig := parseOverviewPoolConfig(
		t,
		applicationDSN,
		"aiops_control_plane_workload",
		integrationApplicationName,
	)
	controlDatabase := adminConfig.ConnConfig.Database
	if controlDatabase != "aiops_test" ||
		migrationConfig.ConnConfig.Database != controlDatabase ||
		applicationConfig.ConnConfig.Database != controlDatabase {
		t.Fatal("all PostgreSQL DSNs must name the dedicated aiops_test control database")
	}

	ctx := context.Background()
	control, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatalf("connect PostgreSQL test-control database: %v", err)
	}
	var serverVersion int
	if err := control.QueryRow(ctx, `
		SELECT current_setting('server_version_num')::integer
	`).Scan(&serverVersion); err != nil {
		control.Close()
		t.Fatalf("read PostgreSQL server version: %v", err)
	}
	if serverVersion != 180004 {
		control.Close()
		t.Fatalf("overview integration requires exact PostgreSQL 18.4, got server_version_num=%d", serverVersion)
	}

	databaseName := "aiops_overview_test_" + randomOverviewHex(t, 12)
	identifier := pgx.Identifier{databaseName}.Sanitize()
	harness := &overviewHarness{control: control, databaseName: databaseName}
	created := false
	t.Cleanup(func() {
		if harness.application != nil {
			harness.application.Close()
		}
		if harness.migration != nil {
			harness.migration.Close()
		}
		if harness.adminDatabase != nil {
			harness.adminDatabase.Close()
		}
		if created {
			if _, err := control.Exec(
				context.Background(),
				"DROP DATABASE IF EXISTS "+identifier+" WITH (FORCE)",
			); err != nil {
				t.Errorf("drop isolated overview database %s: %v", databaseName, err)
			}
		}
		control.Close()
	})
	if _, err := control.Exec(
		ctx,
		"CREATE DATABASE "+identifier+" WITH TEMPLATE template0 OWNER aiops_schema_owner",
	); err != nil {
		t.Fatalf("create isolated overview database: %v", err)
	}
	created = true
	if _, err := control.Exec(ctx, `
		SET ROLE aiops_schema_owner;
		REVOKE ALL ON DATABASE `+identifier+` FROM PUBLIC;
		REVOKE ALL ON DATABASE `+identifier+` FROM aiops_control_plane_runtime;
		GRANT CONNECT ON DATABASE `+identifier+` TO aiops_migrator;
		GRANT CONNECT ON DATABASE `+identifier+` TO aiops_control_plane_workload;
		RESET ROLE;
	`); err != nil {
		t.Fatalf("provision isolated overview database ACL: %v", err)
	}

	adminDatabaseConfig := adminConfig.Copy()
	adminDatabaseConfig.ConnConfig.Database = databaseName
	adminDatabase, err := pgxpool.NewWithConfig(ctx, adminDatabaseConfig)
	if err != nil {
		t.Fatalf("connect isolated overview database as test-control: %v", err)
	}
	harness.adminDatabase = adminDatabase
	if _, err := adminDatabase.Exec(ctx, `
		ALTER SCHEMA public OWNER TO aiops_schema_owner;
		SET ROLE aiops_schema_owner;
		REVOKE ALL ON SCHEMA public FROM PUBLIC;
		REVOKE ALL ON SCHEMA public FROM aiops_migrator;
		REVOKE ALL ON SCHEMA public FROM aiops_control_plane_workload;
		GRANT CREATE, USAGE ON SCHEMA public TO aiops_schema_owner;
		GRANT USAGE ON SCHEMA public TO aiops_control_plane_runtime;
		RESET ROLE;
	`); err != nil {
		t.Fatalf("provision isolated overview schema ACL: %v", err)
	}

	migrationConfig.ConnConfig.Database = databaseName
	migration, err := pgxpool.NewWithConfig(ctx, migrationConfig)
	if err != nil {
		t.Fatalf("connect isolated overview migration identity: %v", err)
	}
	harness.migration = migration
	applicationConfig.ConnConfig.Database = databaseName
	application, err := pgxpool.NewWithConfig(ctx, applicationConfig)
	if err != nil {
		t.Fatalf("connect isolated overview application identity: %v", err)
	}
	harness.application = application
	assertOverviewPoolIdentity(
		t,
		migration,
		"aiops_migrator",
		integrationMigrationName,
	)
	assertOverviewPoolIdentity(
		t,
		application,
		"aiops_control_plane_workload",
		integrationApplicationName,
	)
	return harness
}

func parseOverviewPoolConfig(
	t *testing.T,
	dsn string,
	expectedUser string,
	applicationName string,
) *pgxpool.Config {
	t.Helper()
	if !strings.Contains(dsn, "sslmode=verify-full") {
		t.Fatalf("%s DSN must require sslmode=verify-full", expectedUser)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse %s PostgreSQL DSN: invalid configuration", expectedUser)
	}
	if config.ConnConfig.User != expectedUser || config.ConnConfig.TLSConfig == nil {
		t.Fatalf("%s PostgreSQL DSN has wrong identity or lacks TLS", expectedUser)
	}
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = make(map[string]string)
	}
	config.ConnConfig.RuntimeParams["search_path"] = "pg_catalog,public,pg_temp"
	config.ConnConfig.RuntimeParams["application_name"] = applicationName
	if config.MaxConns < 8 {
		config.MaxConns = 8
	}
	return config
}

func assertOverviewPoolIdentity(
	t *testing.T,
	pool *pgxpool.Pool,
	expectedUser string,
	expectedApplicationName string,
) {
	t.Helper()
	var sessionUser, currentUser, applicationName, sslVersion string
	var ssl bool
	if err := pool.QueryRow(context.Background(), `
		SELECT
		  session_user,
		  current_user,
		  current_setting('application_name'),
		  ssl.ssl,
		  ssl.version
		FROM pg_catalog.pg_stat_ssl AS ssl
		WHERE ssl.pid = pg_catalog.pg_backend_pid()
	`).Scan(&sessionUser, &currentUser, &applicationName, &ssl, &sslVersion); err != nil {
		t.Fatalf("read %s PostgreSQL TLS identity: %v", expectedUser, err)
	}
	if sessionUser != expectedUser || currentUser != expectedUser ||
		applicationName != expectedApplicationName || !ssl || sslVersion != "TLSv1.3" {
		t.Fatalf(
			"PostgreSQL identity/TLS = session:%q current:%q app:%q ssl:%v version:%q",
			sessionUser,
			currentUser,
			applicationName,
			ssl,
			sslVersion,
		)
	}
}

func (harness *overviewHarness) applyThroughAssets(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(overviewMigrationDirectory(t))
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	var files []string
	for _, entry := range entries {
		if !entry.IsDir() &&
			strings.HasSuffix(entry.Name(), ".up.sql") &&
			entry.Name() <= "000015_assets_catalog.up.sql" {
			files = append(files, entry.Name())
		}
	}
	sort.Strings(files)
	if len(files) != 15 {
		t.Fatalf("migration set through 000015 has %d files, want 15", len(files))
	}
	for _, name := range files {
		harness.applyMigration(t, name)
	}
}

func (harness *overviewHarness) applyMigration(t *testing.T, name string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(overviewMigrationDirectory(t), name))
	if err != nil {
		t.Fatalf("read migration %s: %v", name, err)
	}
	source := string(raw)
	if name == "000012_outbox_event_routing.up.sql" {
		config := harness.migration.Config().ConnConfig.Copy()
		connection, err := pgx.ConnectConfig(context.Background(), config)
		if err != nil {
			t.Fatalf("connect nontransactional migration %s: %v", name, err)
		}
		defer func() { _ = connection.Close(context.Background()) }()
		if _, err := connection.Exec(context.Background(), `
			SET search_path = pg_catalog, public, pg_temp;
			SET ROLE aiops_schema_owner;
		`); err != nil {
			t.Fatalf("prepare nontransactional migration %s: %v", name, err)
		}
		if _, err := connection.Exec(context.Background(), source); err != nil {
			failOverviewMigration(t, name, err)
		}
		if _, err := connection.Exec(context.Background(), `RESET ROLE`); err != nil {
			t.Fatalf("reset role after %s: %v", name, err)
		}
		return
	}
	if name != "000015_assets_catalog.up.sql" {
		const begin = "BEGIN;"
		offset := strings.Index(source, begin)
		if offset < 0 {
			t.Fatalf("transactional migration %s lacks BEGIN", name)
		}
		offset += len(begin)
		source = source[:offset] + `
SET LOCAL ROLE aiops_schema_owner;
SET LOCAL search_path = public, pg_catalog, pg_temp;
` + source[offset:]
	}
	connection, err := harness.migration.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire migration connection for %s: %v", name, err)
	}
	defer connection.Release()
	if _, err := connection.Exec(context.Background(), source); err != nil {
		_ = connection.Conn().Close(context.Background())
		failOverviewMigration(t, name, err)
	}
	if _, err := connection.Exec(context.Background(), `RESET ROLE`); err != nil {
		t.Fatalf("reset role after %s: %v", name, err)
	}
}

func failOverviewMigration(t *testing.T, name string, err error) {
	t.Helper()
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		t.Fatalf(
			"apply migration %s: %s (SQLSTATE %s)",
			name,
			postgresError.Message,
			postgresError.Code,
		)
	}
	t.Fatalf("apply migration %s: %v", name, err)
}

func overviewMigrationDirectory(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate overview integration source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "migrations"))
}

func seedOverviewScopes(t *testing.T, database *pgxpool.Pool) {
	t.Helper()
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin overview fixtures: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(context.Background(), `
		SET LOCAL session_replication_role = replica;

		INSERT INTO tenants (id,name) VALUES
		  ('`+integrationTenantA+`','overview-tenant-a'),
		  ('`+integrationTenantB+`','overview-tenant-b');
		INSERT INTO workspaces (id,tenant_id,name) VALUES
		  ('`+integrationWorkspaceA+`','`+integrationTenantA+`','overview-workspace-a'),
		  ('`+integrationWorkspaceB+`','`+integrationTenantB+`','overview-workspace-b');
		INSERT INTO environments (id,tenant_id,workspace_id,name,kind) VALUES
		  ('`+integrationEnvironmentA+`','`+integrationTenantA+`','`+integrationWorkspaceA+`','overview-environment-a','PROD'),
		  ('`+integrationEnvironmentB+`','`+integrationTenantB+`','`+integrationWorkspaceB+`','overview-environment-b','PROD');

		INSERT INTO asset_sources (
		  id,tenant_id,workspace_id,source_kind,provider_kind,name,status,gate_status,
		  create_idempotency_key,create_request_hash
		) VALUES
		  ('`+integrationSourceA+`','`+integrationTenantA+`','`+integrationWorkspaceA+`',
		   'MANUAL','MANUAL_V1','overview-source-a','ACTIVE','UNAVAILABLE',
		   'overview-source-a',repeat('a',64)),
		  ('`+integrationSourceB+`','`+integrationTenantB+`','`+integrationWorkspaceB+`',
		   'EXTERNAL_CMDB','EXTERNAL_V1','overview-source-b','DEGRADED','DEGRADED',
		   'overview-source-b',repeat('b',64));

		INSERT INTO asset_source_revisions (
		  id,tenant_id,workspace_id,source_id,revision,
		  canonical_profile_manifest,profile_manifest_sha256,
		  canonical_provider_schema,canonical_provider_schema_sha256,
		  sync_mode,authority_scope_digest,source_definition_digest,canonical_revision_digest,
		  rate_limit_requests,rate_limit_window_seconds,backpressure_base_seconds,backpressure_max_seconds,
		  profile_code,created_by,change_reason_code,expected_source_version
		) VALUES
		  ('`+integrationRevisionA+`','`+integrationTenantA+`','`+integrationWorkspaceA+`','`+integrationSourceA+`',1,
		   convert_to('{}','UTF8'),encode(sha256(convert_to('{}','UTF8')),'hex'),
		   convert_to('{}','UTF8'),encode(sha256(convert_to('{}','UTF8')),'hex'),
		   'MANUAL',repeat('1',64),repeat('2',64),repeat('3',64),
		   1,1,1,1,'MANUAL_V1','overview-fixture','INITIAL_CREATE',1),
		  ('`+integrationRevisionB+`','`+integrationTenantB+`','`+integrationWorkspaceB+`','`+integrationSourceB+`',1,
		   convert_to('{}','UTF8'),encode(sha256(convert_to('{}','UTF8')),'hex'),
		   convert_to('{}','UTF8'),encode(sha256(convert_to('{}','UTF8')),'hex'),
		   'ON_DEMAND',repeat('4',64),repeat('5',64),repeat('6',64),
		   10,60,1,60,'EXTERNAL_V1','overview-fixture','INITIAL_CREATE',1);

		INSERT INTO asset_source_revision_authorities (
		  tenant_id,workspace_id,source_id,source_revision,environment_id,canonical_ordinal
		) VALUES
		  ('`+integrationTenantA+`','`+integrationWorkspaceA+`','`+integrationSourceA+`',1,'`+integrationEnvironmentA+`',1),
		  ('`+integrationTenantB+`','`+integrationWorkspaceB+`','`+integrationSourceB+`',1,'`+integrationEnvironmentB+`',1);

		INSERT INTO asset_source_runs (
		  id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
		  run_kind,trigger_type,gate_revision,idempotency_key,request_hash
		) VALUES
		  ('`+integrationRunA+`','`+integrationTenantA+`','`+integrationWorkspaceA+`','`+integrationSourceA+`',1,
		   repeat('3',64),'DISCOVERY','HUMAN',0,'overview-run-a',repeat('7',64)),
		  ('`+integrationRunB+`','`+integrationTenantB+`','`+integrationWorkspaceB+`','`+integrationSourceB+`',1,
		   repeat('6',64),'DISCOVERY','HUMAN',0,'overview-run-b',repeat('8',64));

		INSERT INTO assets (
		  id,tenant_id,workspace_id,environment_id,source_id,provider_kind,external_id,kind,
		  display_name,lifecycle,mapping_status,last_observation_id,last_observation_chain_sha256,
		  last_observed_at,last_source_revision,create_idempotency_key,create_request_hash
		) VALUES
		  ('`+integrationAssetA1+`','`+integrationTenantA+`','`+integrationWorkspaceA+`','`+integrationEnvironmentA+`',
		   '`+integrationSourceA+`','MANUAL_V1','scope-a-external-1','LINUX_VM','scope a host 1',
		   'ACTIVE','EXACT','97111111-1111-4111-8111-111111111111',repeat('9',64),
		   statement_timestamp(),1,'overview-asset-a1',repeat('a',64)),
		  ('`+integrationAssetA2+`','`+integrationTenantA+`','`+integrationWorkspaceA+`','`+integrationEnvironmentA+`',
		   '`+integrationSourceA+`','MANUAL_V1','scope-a-external-2','LINUX_VM','scope a host 2',
		   'STALE','UNRESOLVED','97222222-2222-4222-8222-222222222222',repeat('a',64),
		   statement_timestamp()-interval '1 hour',1,'overview-asset-a2',repeat('b',64)),
		  ('`+integrationAssetB+`','`+integrationTenantB+`','`+integrationWorkspaceB+`','`+integrationEnvironmentB+`',
		   '`+integrationSourceB+`','EXTERNAL_V1','scope-b-external','CLOUD_RESOURCE','scope b resource',
		   'QUARANTINED','AMBIGUOUS','a7111111-1111-4111-8111-111111111111',repeat('b',64),
		   statement_timestamp(),1,'overview-asset-b',repeat('c',64));

		INSERT INTO asset_conflicts (
		  id,tenant_id,workspace_id,environment_id,asset_id,candidate_asset_id,
		  source_id,observation_id,conflict_type,status
		) VALUES (
		  '`+integrationConflictA+`','`+integrationTenantA+`','`+integrationWorkspaceA+`','`+integrationEnvironmentA+`',
		  '`+integrationAssetA1+`','`+integrationAssetA2+`','`+integrationSourceA+`',
		  '97333333-3333-4333-8333-333333333333','DUPLICATE_IDENTITY','OPEN'
		);

		INSERT INTO asset_source_limit_buckets (
		  id,tenant_id,workspace_id,bucket_kind,bucket_key,source_id,next_token_at
		) VALUES (
		  '`+integrationBucketA+`','`+integrationTenantA+`','`+integrationWorkspaceA+`',
		  'SOURCE','`+integrationSourceA+`','`+integrationSourceA+`',
		  statement_timestamp()+interval '5 minutes'
		);
	`); err != nil {
		t.Fatalf("seed real overview facts: %v", err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit overview fixtures: %v", err)
	}
}

func integrationScopeA() assetcatalog.Scope {
	return assetcatalog.Scope{
		TenantID:      integrationTenantA,
		WorkspaceID:   integrationWorkspaceA,
		EnvironmentID: integrationEnvironmentA,
	}
}

func integrationScopeB() assetcatalog.Scope {
	return assetcatalog.Scope{
		TenantID:      integrationTenantB,
		WorkspaceID:   integrationWorkspaceB,
		EnvironmentID: integrationEnvironmentB,
	}
}

func randomOverviewHex(t *testing.T, size int) string {
	t.Helper()
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		t.Fatalf("generate overview database suffix: %v", err)
	}
	return hex.EncodeToString(value)
}
