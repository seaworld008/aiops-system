package postgres_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	assetpostgres "github.com/seaworld008/aiops-system/internal/assetcatalog/postgres"
	storepostgres "github.com/seaworld008/aiops-system/internal/store/postgres"
)

type assetCatalogHarness struct {
	admin       *pgxpool.Pool
	db          *pgxpool.Pool
	migration   *pgxpool.Pool
	application *pgxpool.Pool
	name        string
}

var safeAssetCatalogControlDatabase = regexp.MustCompile(`^aiops_test(_[a-z0-9]+)*$`)

func newAssetCatalogHarness(t *testing.T) *assetCatalogHarness {
	t.Helper()
	adminDSN := strings.TrimSpace(os.Getenv("AIOPS_TEST_POSTGRES_DSN"))
	if adminDSN == "" {
		t.Skip("AIOPS_TEST_POSTGRES_DSN is not configured; real PostgreSQL 18.4 migration tests were not run")
	}
	migrationDSN := strings.TrimSpace(os.Getenv("AIOPS_TEST_POSTGRES_MIGRATION_DSN"))
	applicationDSN := strings.TrimSpace(os.Getenv("AIOPS_TEST_POSTGRES_APPLICATION_DSN"))
	if migrationDSN == "" || applicationDSN == "" {
		t.Fatal("AIOPS_TEST_POSTGRES_MIGRATION_DSN and AIOPS_TEST_POSTGRES_APPLICATION_DSN are required when the real PostgreSQL harness is enabled")
	}
	if adminDSN == migrationDSN || adminDSN == applicationDSN || migrationDSN == applicationDSN {
		t.Fatal("test-control, migration, and application PostgreSQL DSNs must be distinct")
	}
	ctx := context.Background()
	adminConfig, err := pgxpool.ParseConfig(adminDSN)
	if err != nil {
		t.Fatal("parse PostgreSQL test-control DSN: invalid configuration")
	}
	controlName := adminConfig.ConnConfig.Database
	if !assetCatalogControlDatabaseNameSafe(controlName) {
		t.Fatalf("AIOPS_TEST_POSTGRES_DSN must name a dedicated safe test control database, got %q", controlName)
	}
	migrationConfig, err := assetCatalogRolePoolConfig(migrationDSN, controlName, "aiops_migrator")
	if err != nil {
		t.Fatal(err)
	}
	applicationConfig, err := assetCatalogRolePoolConfig(applicationDSN, controlName, "aiops_control_plane_workload")
	if err != nil {
		t.Fatal(err)
	}
	adminConfig.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	admin, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatalf("connect PostgreSQL test control database: %v", err)
	}
	var serverVersion int
	if err := admin.QueryRow(ctx, `SELECT current_setting('server_version_num')::integer`).Scan(&serverVersion); err != nil {
		admin.Close()
		t.Fatalf("read PostgreSQL server version: %v", err)
	}
	if serverVersion < 180004 || serverVersion >= 190000 {
		admin.Close()
		t.Fatalf("integration harness requires PostgreSQL 18.4 or newer 18.x, got %d", serverVersion)
	}

	databaseName := "aiops_assets_test_" + randomAssetHex(t, 16)
	identifier := pgx.Identifier{databaseName}.Sanitize()
	var database, migration, application *pgxpool.Pool
	created := false
	t.Cleanup(func() {
		if application != nil {
			application.Close()
		}
		if migration != nil {
			migration.Close()
		}
		if database != nil {
			database.Close()
		}
		if created {
			if _, err := admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+identifier+" WITH (FORCE)"); err != nil {
				t.Errorf("drop isolated physical PostgreSQL database %s: %v", databaseName, err)
			}
		}
		admin.Close()
	})
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+identifier+" WITH TEMPLATE template0 OWNER aiops_schema_owner"); err != nil {
		t.Fatalf("create isolated physical PostgreSQL test database %s; ownership unconfirmed, refusing destructive cleanup: %v", databaseName, err)
	}
	created = true
	if _, err := admin.Exec(ctx, `SET ROLE aiops_schema_owner;
REVOKE ALL ON DATABASE `+identifier+` FROM PUBLIC;
REVOKE ALL ON DATABASE `+identifier+` FROM aiops_control_plane_runtime;
GRANT CONNECT ON DATABASE `+identifier+` TO aiops_migrator;
GRANT CONNECT ON DATABASE `+identifier+` TO aiops_control_plane_workload;
RESET ROLE;`); err != nil {
		t.Fatalf("preprovision isolated PostgreSQL database ACL: %v", err)
	}

	config, err := pgxpool.ParseConfig(adminDSN)
	if err != nil {
		t.Fatal("parse isolated PostgreSQL test-control config: invalid configuration")
	}
	config.ConnConfig.Database = databaseName
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = make(map[string]string)
	}
	config.ConnConfig.RuntimeParams["search_path"] = "public"
	if config.MaxConns < 12 {
		config.MaxConns = 12
	}
	database, err = pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect isolated physical PostgreSQL database: %v", err)
	}
	if err := database.Ping(ctx); err != nil {
		t.Fatalf("ping isolated physical PostgreSQL database: %v", err)
	}
	if _, err := database.Exec(ctx, `ALTER SCHEMA public OWNER TO aiops_schema_owner;
SET ROLE aiops_schema_owner;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM aiops_migrator;
REVOKE ALL ON SCHEMA public FROM aiops_control_plane_workload;
GRANT CREATE, USAGE ON SCHEMA public TO aiops_schema_owner;
GRANT USAGE ON SCHEMA public TO aiops_control_plane_runtime;
RESET ROLE;`); err != nil {
		t.Fatalf("preprovision isolated PostgreSQL trusted schema ACL: %v", err)
	}

	migrationConfig.ConnConfig.Database = databaseName
	migration, err = pgxpool.NewWithConfig(ctx, migrationConfig)
	if err != nil {
		t.Fatal("connect isolated PostgreSQL migration identity: unavailable")
	}
	if err := migration.Ping(ctx); err != nil {
		t.Fatal("ping isolated PostgreSQL migration identity: unavailable")
	}
	applicationConfig.ConnConfig.Database = databaseName
	application, err = pgxpool.NewWithConfig(ctx, applicationConfig)
	if err != nil {
		t.Fatal("connect isolated PostgreSQL application identity: unavailable")
	}
	if err := application.Ping(ctx); err != nil {
		t.Fatal("ping isolated PostgreSQL application identity: unavailable")
	}
	assertAssetCatalogPoolIdentity(t, migration, "aiops_migrator")
	assertAssetCatalogPoolIdentity(t, application, "aiops_control_plane_workload")
	harness := &assetCatalogHarness{
		admin: admin, db: database, migration: migration, application: application, name: databaseName,
	}
	return harness
}

func assetCatalogRolePoolConfig(dsn, controlName, expectedUser string) (*pgxpool.Config, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse %s PostgreSQL DSN: invalid configuration", expectedUser)
	}
	if config.ConnConfig.Database != controlName {
		return nil, fmt.Errorf("%s PostgreSQL DSN must name the same safe test control database", expectedUser)
	}
	if config.ConnConfig.User != expectedUser {
		return nil, fmt.Errorf("PostgreSQL DSN identity must be %s", expectedUser)
	}
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = make(map[string]string)
	}
	config.ConnConfig.RuntimeParams["search_path"] = "pg_catalog,public,pg_temp"
	if config.MaxConns < 12 {
		config.MaxConns = 12
	}
	return config, nil
}

func assertAssetCatalogPoolIdentity(t *testing.T, pool *pgxpool.Pool, expected string) {
	t.Helper()
	var sessionUser, currentUser string
	if err := pool.QueryRow(context.Background(), `SELECT session_user, current_user`).Scan(&sessionUser, &currentUser); err != nil {
		t.Fatalf("read %s PostgreSQL identity: %v", expected, err)
	}
	if sessionUser != expected || currentUser != expected {
		t.Fatalf("PostgreSQL identity = session:%q current:%q, want %q", sessionUser, currentUser, expected)
	}
}

func (h *assetCatalogHarness) applyThroughAssetCatalog(t *testing.T) {
	t.Helper()
	h.applyUpThrough(t, "000015_assets_catalog.up.sql")
}

func (h *assetCatalogHarness) applyUpThrough(t *testing.T, cutoff string) {
	t.Helper()
	entries, err := os.ReadDir(migrationDirectory(t))
	if err != nil {
		t.Fatalf("read migration directory: %v", err)
	}
	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".up.sql") && entry.Name() <= cutoff {
			files = append(files, entry.Name())
		}
	}
	sort.Strings(files)
	want := 15
	if cutoff == "000014_read_evidence_clock_skew.up.sql" {
		want = 14
	}
	if len(files) != want {
		t.Fatalf("migration set through %s has %d files, want %d", cutoff, len(files), want)
	}
	for _, name := range files {
		h.applyMigration(t, name)
	}
}

func (h *assetCatalogHarness) applyMigration(t *testing.T, name string) {
	t.Helper()
	source := readMigration(t, name)
	if strings.HasPrefix(name, "000012_outbox_event_routing.") {
		h.applyNontransactionalMigration(t, name, source)
		return
	}
	connection, err := h.migration.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire dedicated migration connection for %s: %v", name, err)
	}
	defer connection.Release()
	assertAssetCatalogConnectionIdentity(t, connection, "aiops_migrator")
	if !strings.HasPrefix(name, "000015_assets_catalog.") {
		source = assetCatalogMigrationWithLocalOwner(t, name, source)
	}
	if _, err := connection.Exec(context.Background(), source); err != nil {
		_ = connection.Conn().Close(context.Background())
		failAssetCatalogMigration(t, name, err)
	}
	if _, err := connection.Exec(context.Background(), `RESET ROLE`); err != nil {
		_ = connection.Conn().Close(context.Background())
		t.Fatalf("reset migration role after %s: %v", name, err)
	}
	assertAssetCatalogConnectionIdentity(t, connection, "aiops_migrator")
}

func (h *assetCatalogHarness) applyNontransactionalMigration(t *testing.T, name, source string) {
	t.Helper()
	config := h.migration.Config().ConnConfig.Copy()
	connection, err := pgx.ConnectConfig(context.Background(), config)
	if err != nil {
		t.Fatalf("open fresh nontransactional migration connection for %s: %v", name, err)
	}
	defer func() { _ = connection.Close(context.Background()) }()
	assertAssetCatalogPGXIdentity(t, connection, "aiops_migrator")
	if _, err := connection.Exec(context.Background(), `SET search_path = pg_catalog, public, pg_temp`); err != nil {
		t.Fatalf("pin nontransactional migration search_path for %s: %v", name, err)
	}
	if _, err := connection.Exec(context.Background(), `SET ROLE aiops_schema_owner`); err != nil {
		t.Fatalf("set nontransactional migration owner for %s: %v", name, err)
	}
	if _, err := connection.Exec(context.Background(), source); err != nil {
		failAssetCatalogMigration(t, name, err)
	}
	if _, err := connection.Exec(context.Background(), `RESET ROLE`); err != nil {
		t.Fatalf("reset nontransactional migration role after %s: %v", name, err)
	}
	assertAssetCatalogPGXIdentity(t, connection, "aiops_migrator")
}

func assetCatalogMigrationWithLocalOwner(t *testing.T, name, source string) string {
	t.Helper()
	trimmed := strings.TrimLeft(source, " \t\r\n")
	if !strings.HasPrefix(trimmed, "BEGIN;") {
		t.Fatalf("transactional migration %s does not start with BEGIN", name)
	}
	offset := strings.Index(source, "BEGIN;") + len("BEGIN;")
	return source[:offset] + `
SET LOCAL ROLE aiops_schema_owner;
SET LOCAL search_path = public, pg_catalog, pg_temp;` + source[offset:]
}

func assertAssetCatalogConnectionIdentity(t *testing.T, connection *pgxpool.Conn, expected string) {
	t.Helper()
	var sessionUser, currentUser string
	if err := connection.QueryRow(context.Background(), `SELECT session_user, current_user`).Scan(&sessionUser, &currentUser); err != nil {
		t.Fatalf("read %s migration connection identity: %v", expected, err)
	}
	if sessionUser != expected || currentUser != expected {
		t.Fatalf("migration connection identity = session:%q current:%q, want %q", sessionUser, currentUser, expected)
	}
}

func assertAssetCatalogPGXIdentity(t *testing.T, connection *pgx.Conn, expected string) {
	t.Helper()
	var sessionUser, currentUser string
	if err := connection.QueryRow(context.Background(), `SELECT session_user, current_user`).Scan(&sessionUser, &currentUser); err != nil {
		t.Fatalf("read %s nontransactional identity: %v", expected, err)
	}
	if sessionUser != expected || currentUser != expected {
		t.Fatalf("nontransactional identity = session:%q current:%q, want %q", sessionUser, currentUser, expected)
	}
}

func failAssetCatalogMigration(t *testing.T, name string, err error) {
	t.Helper()
	if databaseError, ok := err.(*pgconn.PgError); ok {
		t.Fatalf("apply migration %s: %s (SQLSTATE %s, position %d, where %s)",
			name, databaseError.Message, databaseError.Code, databaseError.Position, databaseError.Where)
	}
	t.Fatalf("apply migration %s: %v", name, err)
}

type assetCatalogFixture struct {
	tenantID               string
	workspaceID            string
	environmentID          string
	integrationID          string
	serviceID              string
	sourceID               string
	revisionID             string
	validationRunID        string
	runID                  string
	observationID          string
	secondObservationID    string
	assetID                string
	secondAssetID          string
	typeDetailID           string
	conflictID             string
	relationshipID         string
	bindingID              string
	revisionDigest         string
	sourceDefinitionDigest string
}

func newAssetCatalogFixture() assetCatalogFixture {
	return assetCatalogFixture{
		tenantID: "10000000-0000-4000-8000-000000000201", workspaceID: "20000000-0000-4000-8000-000000000201",
		environmentID: "30000000-0000-4000-8000-000000000201", integrationID: "40000000-0000-4000-8000-000000000201",
		serviceID: "50000000-0000-4000-8000-000000000201", sourceID: "60000000-0000-4000-8000-000000000201",
		revisionID: "61000000-0000-4000-8000-000000000201", validationRunID: "62000000-0000-4000-8000-000000000200",
		runID: "62000000-0000-4000-8000-000000000201", observationID: "63000000-0000-4000-8000-000000000201",
		secondObservationID: "63000000-0000-4000-8000-000000000202", assetID: "64000000-0000-4000-8000-000000000201",
		secondAssetID: "64000000-0000-4000-8000-000000000202", typeDetailID: "65000000-0000-4000-8000-000000000201",
		conflictID: "66000000-0000-4000-8000-000000000201", relationshipID: "67000000-0000-4000-8000-000000000201",
		bindingID: "68000000-0000-4000-8000-000000000201", revisionDigest: strings.Repeat("d", 64),
		sourceDefinitionDigest: strings.Repeat("c", 64),
	}
}

func seedDraftAssetCatalog(t *testing.T, database *pgxpool.Pool) assetCatalogFixture {
	t.Helper()
	fixture := newAssetCatalogFixture()
	profile := []byte(correctiveManualProfileManifestV1)
	providerSchema := []byte(`{"additionalProperties":false,"properties":{},"type":"object"}`)
	profileDigest := sha256.Sum256(profile)
	providerSchemaDigest := sha256.Sum256(providerSchema)
	authorityDigest := assetCatalogCorrectiveFramedDigest(
		[]byte("asset-source-authority-scope.v1"),
		[]byte("1"),
		[]byte(fixture.environmentID),
	)
	fixture.sourceDefinitionDigest = assetCatalogCorrectiveFramedDigest(
		[]byte("asset-source-definition.v2"),
		[]byte("MANUAL"),
		[]byte("MANUAL_V1"),
		[]byte("MANUAL_V1"),
		profileDigest[:],
		providerSchemaDigest[:],
	)
	fixture.revisionDigest = assetCatalogCorrectiveFramedDigest(
		[]byte("asset-source-revision-binding.v1"),
		[]byte(fixture.tenantID),
		[]byte(fixture.workspaceID),
		[]byte(fixture.sourceID),
		[]byte("1"),
		assetCatalogCorrectiveDecodeDigest(t, fixture.sourceDefinitionDigest),
		nil,
		[]byte("MANUAL"),
		nil,
		nil,
		nil,
		assetCatalogCorrectiveDecodeDigest(t, authorityDigest),
		[]byte("1"),
		[]byte("1"),
		[]byte("1"),
		[]byte("1"),
		[]byte("MANUAL_V1"),
		nil,
		nil,
		nil,
	)

	transaction, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin draft asset catalog fixture: %v", err)
	}
	defer func() { _ = transaction.Rollback(context.Background()) }()
	execAssetSQL(t, transaction, `INSERT INTO tenants (id,name) VALUES ($1,'fixture-tenant')`, fixture.tenantID)
	execAssetSQL(t, transaction, `INSERT INTO workspaces (id,tenant_id,name) VALUES ($1,$2,'fixture-workspace')`, fixture.workspaceID, fixture.tenantID)
	execAssetSQL(t, transaction, `INSERT INTO environments (id,tenant_id,workspace_id,name,kind) VALUES ($1,$2,$3,'fixture-production','PROD')`, fixture.environmentID, fixture.tenantID, fixture.workspaceID)
	execAssetSQL(t, transaction, `INSERT INTO integrations (id,tenant_id,workspace_id,provider,name,secret_ref,config) VALUES ($1,$2,$3,'manual','fixture-integration','opaque://sanitized','{"future":"preserve"}')`, fixture.integrationID, fixture.tenantID, fixture.workspaceID)
	execAssetSQL(t, transaction, `INSERT INTO services (id,tenant_id,workspace_id,name,owner_group,labels) VALUES ($1,$2,$3,'fixture-service','fixture-sre','{"future":"preserve"}')`, fixture.serviceID, fixture.tenantID, fixture.workspaceID)
	execAssetSQL(t, transaction, `INSERT INTO service_bindings (id,tenant_id,workspace_id,service_id,environment_id,mapping_status) VALUES ('51000000-0000-4000-8000-000000000201',$1,$2,$3,$4,'EXACT')`, fixture.tenantID, fixture.workspaceID, fixture.serviceID, fixture.environmentID)
	execAssetSQL(t, transaction, `
		INSERT INTO asset_sources (id,tenant_id,workspace_id,source_kind,provider_kind,name,create_idempotency_key,create_request_hash)
		VALUES ($1,$2,$3,'MANUAL','MANUAL_V1','fixture-source','fixture-source-create',repeat('a',64))
	`, fixture.sourceID, fixture.tenantID, fixture.workspaceID)
	execAssetSQL(t, transaction, `
		INSERT INTO asset_source_revisions (
			id,tenant_id,workspace_id,source_id,revision,
			canonical_profile_manifest,profile_manifest_sha256,
			canonical_provider_schema,canonical_provider_schema_sha256,
			sync_mode,authority_scope_digest,source_definition_digest,canonical_revision_digest,
			credential_reference_id,trust_reference_id,network_policy_reference_id,rate_limit_requests,
			rate_limit_window_seconds,backpressure_base_seconds,backpressure_max_seconds,profile_code,
			created_by,change_reason_code,expected_source_version
		) VALUES ($1,$2,$3,$4,1,$5,$6,$7,$8,'MANUAL',$9,$10,$11,
			NULL,NULL,NULL,1,1,1,1,'MANUAL_V1','fixture-human','INITIAL_CREATE',1)
	`, fixture.revisionID, fixture.tenantID, fixture.workspaceID, fixture.sourceID,
		profile, hex.EncodeToString(profileDigest[:]), providerSchema, hex.EncodeToString(providerSchemaDigest[:]),
		authorityDigest, fixture.sourceDefinitionDigest, fixture.revisionDigest)
	execAssetSQL(t, transaction, `
		INSERT INTO asset_source_revision_authorities (
			tenant_id,workspace_id,source_id,source_revision,environment_id,canonical_ordinal
		) VALUES ($1,$2,$3,1,$4,1)
	`, fixture.tenantID, fixture.workspaceID, fixture.sourceID, fixture.environmentID)
	if err := transaction.Commit(context.Background()); err != nil {
		t.Fatalf("commit draft asset catalog fixture: %v", err)
	}
	return fixture
}

func seedGovernedManualCatalog(t *testing.T, database *pgxpool.Pool) assetCatalogFixture {
	t.Helper()
	fixture := seedDraftAssetCatalog(t, database)
	proof := strings.Repeat("e", 64)
	validationFinalization, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin validation closure: %v", err)
	}
	defer func() { _ = validationFinalization.Rollback(context.Background()) }()
	execAssetSQL(t, validationFinalization, `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,trigger_type,gate_revision,idempotency_key,request_hash,checkpoint_version
		) SELECT $1,$2,$3,$4,1,$5,'VALIDATION','HUMAN',gate_revision,'validate-revision-1',repeat('1',64),0
		FROM asset_sources WHERE id=$4
	`, fixture.validationRunID, fixture.tenantID, fixture.workspaceID, fixture.sourceID, fixture.revisionDigest)
	execAssetSQL(t, validationFinalization, `
		UPDATE asset_source_revisions SET state='VALIDATING',validation_run_id=$2,validation_digest=NULL,version=version+1
		WHERE id=$1
	`, fixture.revisionID, fixture.validationRunID)
	execAssetSQL(t, validationFinalization, `
		UPDATE asset_source_runs SET status='RUNNING',stage_code='VALIDATING',lease_owner='validation-worker',
			lease_expires_at=statement_timestamp()+interval '5 minutes',fence_epoch=1,fence_token_hash=repeat('2',64),
			heartbeat_sequence=1,heartbeat_at=statement_timestamp(),version=version+1 WHERE id=$1
	`, fixture.validationRunID)
	validationCleanupDigest := sourceRunNoCredentialDigest(t, validationFinalization, fixture.validationRunID)
	insertCleanupAudit(t, validationFinalization, fixture, fixture.validationRunID, 0, validationCleanupDigest)
	execAssetSQL(t, validationFinalization, `
		UPDATE asset_source_runs SET status='FINALIZING',stage_code='CLEANING_UP',work_result_kind='VALIDATION_PROOF',
			work_result_status='SUCCEEDED',work_result_digest=$2,work_result_recorded_at=statement_timestamp(),
			validation_outcome='SUCCEEDED',validation_digest=$2,validation_proof_digest=$2,
			cleanup_status='NO_CREDENTIAL',cleanup_digest=$3,version=version+1 WHERE id=$1
	`, fixture.validationRunID, proof, validationCleanupDigest)
	validationTerminalDigest := sourceRunTerminalDigest(t, validationFinalization, fixture.validationRunID, "SUCCEEDED", nil)
	insertTerminalAudit(t, validationFinalization, fixture, fixture.validationRunID, validationTerminalDigest)
	execAssetSQL(t, validationFinalization, `
		UPDATE asset_source_runs
		SET status='SUCCEEDED',stage_code='COMPLETED',terminal_command_sha256=$2,version=version+1
		WHERE id=$1
	`, fixture.validationRunID, validationTerminalDigest)
	execAssetSQL(t, validationFinalization, `
		UPDATE asset_source_revisions
		SET state='VALIDATED',validation_digest=$2,version=version+1
		WHERE id=$1
	`, fixture.revisionID, proof)
	if err := validationFinalization.Commit(context.Background()); err != nil {
		t.Fatalf("commit validation terminal closure: %v", err)
	}
	execAssetSQL(t, database, `UPDATE asset_source_revisions SET state='PUBLISHED',version=version+1 WHERE id=$1`, fixture.revisionID)
	execAssetSQL(t, database, `
		UPDATE asset_sources SET gate_status='AVAILABLE',gate_reason_code=NULL,gate_revision=gate_revision+1,
			validated_run_id=$2,validation_digest=$3,validated_binding_digest=$4,version=version+1 WHERE id=$1
	`, fixture.sourceID, fixture.validationRunID, proof, fixture.revisionDigest)

	manualMutation, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin manual mutation closure: %v", err)
	}
	defer func() { _ = manualMutation.Rollback(context.Background()) }()
	execAssetSQL(t, manualMutation, `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,run_kind,trigger_type,
			gate_revision,idempotency_key,request_hash,checkpoint_version,cursor_before_sha256
		) SELECT $1,$2,$3,$4,1,$5,'MANUAL_MUTATION','HUMAN',gate_revision,'manual-mutation-1',repeat('5',64),checkpoint_version,checkpoint_sha256
		FROM asset_sources WHERE id=$4
	`, fixture.runID, fixture.tenantID, fixture.workspaceID, fixture.sourceID, fixture.revisionDigest)
	execAssetSQL(t, manualMutation, `
		UPDATE asset_source_runs SET status='RUNNING',stage_code='READING',lease_owner='manual-api',
			lease_expires_at=statement_timestamp()+interval '5 minutes',fence_epoch=1,fence_token_hash=repeat('6',64),
			heartbeat_sequence=1,heartbeat_at=statement_timestamp(),version=version+1 WHERE id=$1
	`, fixture.runID)
	execAssetSQL(t, manualMutation, `UPDATE asset_source_runs SET stage_code='NORMALIZING',version=version+1 WHERE id=$1`, fixture.runID)
	execAssetSQL(t, manualMutation, `UPDATE asset_source_runs SET stage_code='APPLYING',version=version+1 WHERE id=$1`, fixture.runID)

	insertManualObservation(t, manualMutation, fixture, fixture.observationID, fixture.assetID,
		"manual-host-a", "fixture-host-a", strings.Repeat("7", 64))
	insertManualObservation(t, manualMutation, fixture, fixture.secondObservationID, fixture.secondAssetID,
		"manual-host-b", "fixture-host-b", strings.Repeat("8", 64))
	seedManualProjectionEdges(t, manualMutation, fixture)
	execAssetSQL(t, manualMutation, `
		INSERT INTO audit_records (
			id,tenant_id,workspace_id,actor_type,actor_id,action,resource_type,resource_id,
			request_id,trace_id,payload_hash
		) VALUES (
			gen_random_uuid(),$1,$2,'SYSTEM','manual-api','PAGE_APPLIED','ASSET_SOURCE_RUN',$3,
			'source-page:'||$3||':1','manual-page-trace',repeat('9',64)
		)
	`, fixture.tenantID, fixture.workspaceID, fixture.runID)
	execAssetSQL(t, manualMutation, `
		INSERT INTO audit_records (
			id,tenant_id,workspace_id,actor_type,actor_id,action,resource_type,resource_id,
			request_id,trace_id,payload_hash
		) VALUES (
			gen_random_uuid(),$1,$2,'SYSTEM','manual-api','RELATION_PAGE_COMMITTED','ASSET_SOURCE_RUN',$3,
			'source-relation-page:'||$3||':1','manual-relation-page-trace',repeat('6',64)
		)
	`, fixture.tenantID, fixture.workspaceID, fixture.runID)
	manualCleanupDigest := sourceRunNoCredentialDigest(t, manualMutation, fixture.runID)
	insertCleanupAudit(t, manualMutation, fixture, fixture.runID, 0, manualCleanupDigest)
	execAssetSQL(t, manualMutation, `
		UPDATE asset_sources SET checkpoint_version=1,version=version+1 WHERE id=$1
	`, fixture.sourceID)
	execAssetSQL(t, manualMutation, `
		UPDATE asset_source_runs SET status='FINALIZING',stage_code='CLEANING_UP',page_sequence=1,page_digest=repeat('9',64),
			relation_page_sequence=1,relation_page_digest=repeat('6',64),checkpoint_version=1,
			final_page=true,complete_snapshot=false,effective_complete_snapshot=false,
			observed_count=2,created_count=2,heartbeat_sequence=heartbeat_sequence+1,
			heartbeat_at=statement_timestamp(),lease_expires_at=statement_timestamp()+interval '5 minutes',
			work_result_kind='DATA_PROJECTION',work_result_status='SUCCEEDED',work_result_digest=repeat('b',64),
			work_result_recorded_at=statement_timestamp(),cleanup_status='NO_CREDENTIAL',cleanup_digest=$2,
			version=version+1 WHERE id=$1
	`, fixture.runID, manualCleanupDigest)
	manualTerminalDigest := sourceRunTerminalDigest(t, manualMutation, fixture.runID, "SUCCEEDED", nil)
	insertTerminalAudit(t, manualMutation, fixture, fixture.runID, manualTerminalDigest)
	execAssetSQL(t, manualMutation, `
		UPDATE asset_source_runs
		SET status='SUCCEEDED',stage_code='COMPLETED',terminal_command_sha256=$2,version=version+1
		WHERE id=$1
	`, fixture.runID, manualTerminalDigest)
	execAssetSQL(t, manualMutation, `
		UPDATE asset_sources SET last_success_run_id=$2,
			last_success_at=(SELECT completed_at FROM asset_source_runs WHERE id=$2),
			version=version+1 WHERE id=$1
	`, fixture.sourceID, fixture.runID)
	if err := manualMutation.Commit(context.Background()); err != nil {
		t.Fatalf("commit manual mutation closure: %v", err)
	}
	return fixture
}

func seedRepresentativeAssetCatalog(t *testing.T, database *pgxpool.Pool) assetCatalogFixture {
	t.Helper()
	return seedGovernedManualCatalog(t, database)
}

type assetSQLExecutor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

type assetSQLQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func insertManualObservation(t *testing.T, database assetSQLExecutor, fixture assetCatalogFixture, observationID, assetID, externalID, displayName, chain string) {
	t.Helper()
	execAssetSQL(t, database, `
		WITH accepted AS (SELECT transaction_timestamp() AS observed_at), payload AS (
			SELECT observed_at,
				convert_to(jsonb_build_object('display_name',$7,'kind','LINUX_VM')::text,'UTF8') AS document,
				convert_to(jsonb_build_object('display_name',jsonb_build_object(
					'source_id',$4::text,'provider_kind','MANUAL_V1','source_revision',1,
					'observed_at',to_char(observed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
					'provider_path_code','manual.display_name','confidence',100,'ownership','SOURCE'))::text,'UTF8') AS provenance
			FROM accepted
		), inserted AS (
			INSERT INTO asset_observations (
				id,tenant_id,workspace_id,environment_id,source_id,run_id,provider_kind,external_id,
				source_revision,canonical_revision_digest,source_definition_digest,observed_at,freshness_kind,
				freshness_order_sequence,provider_version_sha256,provider_fact_sha256,fingerprint_sha256,
				provider_provenance_sha256,observation_chain_sha256,accepted_checkpoint_version,
				run_fence_epoch,run_page_sequence,schema_version,normalized_document,document_sha256,
				field_provenance,field_provenance_sha256
		) SELECT $1,$2,$3,$5,$4,$6,'MANUAL_V1',$8,1,$9,$12,observed_at,'CATALOG_SEQUENCE',1,
				repeat('1',64),repeat('2',64),repeat('3',64),repeat('4',64),$10,1,1,1,'asset.v1',document,
				encode(sha256(document),'hex'),provenance,encode(sha256(provenance),'hex') FROM payload
			RETURNING observed_at
		)
		INSERT INTO assets (
			id,tenant_id,workspace_id,environment_id,source_id,provider_kind,external_id,kind,display_name,
			last_observation_id,last_observation_chain_sha256,last_observed_at,last_source_revision,
			create_idempotency_key,create_request_hash
		) SELECT $11,$2,$3,$5,$4,'MANUAL_V1',$8,'LINUX_VM',$7,$1,$10,observed_at,1,
			'create-'||$8,repeat('5',64) FROM inserted
	`, observationID, fixture.tenantID, fixture.workspaceID, fixture.sourceID, fixture.environmentID,
		fixture.runID, displayName, externalID, fixture.revisionDigest, chain, assetID,
		fixture.sourceDefinitionDigest)
}

func seedManualProjectionEdges(t *testing.T, database assetSQLExecutor, fixture assetCatalogFixture) {
	t.Helper()
	details := []byte(`{"cpu_count":4}`)
	execAssetSQL(t, database, `
		INSERT INTO asset_type_details (
			id,tenant_id,workspace_id,environment_id,asset_id,source_id,provider_kind,external_id,
			source_revision,source_observed_at,source_observation_chain_sha256,revision,schema_version,
			source_observation_id,details_document,details_sha256,actor_id
		) SELECT $1,$2,$3,$4,$5,$6,'MANUAL_V1','manual-host-a',1,o.observed_at,o.observation_chain_sha256,
			1,'linux-vm.v1',o.id,$7,encode(sha256($7),'hex'),'fixture-human'
		FROM asset_observations o WHERE o.id=$8
	`, fixture.typeDetailID, fixture.tenantID, fixture.workspaceID, fixture.environmentID, fixture.assetID,
		fixture.sourceID, details, fixture.observationID)
	execAssetSQL(t, database, `
		INSERT INTO asset_conflicts (
			id,tenant_id,workspace_id,environment_id,asset_id,candidate_asset_id,source_id,observation_id,
			conflict_type,status
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'FINGERPRINT_COLLISION','OPEN')
	`, fixture.conflictID, fixture.tenantID, fixture.workspaceID, fixture.environmentID, fixture.assetID,
		fixture.secondAssetID, fixture.sourceID, fixture.observationID)
	execAssetSQL(t, database, `
		INSERT INTO asset_relationships (
			id,tenant_id,workspace_id,source_id,source_revision,canonical_revision_digest,last_run_id,
			last_page_sequence,relation_page_sha256,accepted_checkpoint_version,run_fence_epoch,
			source_environment_id,target_environment_id,
			source_asset_id,target_asset_id,from_external_id,to_external_id,relationship_type,
			provider_path_code,confidence,freshness_kind,freshness_order_sequence,provider_version_sha256,
			relation_fact_sha256,provenance,provenance_source_id,status,idempotency_key,request_hash
		) VALUES ($1,$2,$3,$4,1,$5,$6,1,repeat('6',64),1,1,$7,$7,$8,$9,'manual-host-a','manual-host-b',
			'DEPENDS_ON','manual.depends_on',100,'CATALOG_SEQUENCE',1,repeat('7',64),repeat('8',64),
			'DISCOVERED',$4,'ACTIVE','relationship-create',repeat('9',64))
	`, fixture.relationshipID, fixture.tenantID, fixture.workspaceID, fixture.sourceID,
		fixture.revisionDigest, fixture.runID, fixture.environmentID, fixture.assetID, fixture.secondAssetID)
	execAssetSQL(t, database, `
		INSERT INTO service_asset_bindings (
			id,tenant_id,workspace_id,environment_id,service_id,asset_id,binding_role,mapping_status,
			provenance,provenance_source_id,status,idempotency_key,request_hash
		) VALUES ($1,$2,$3,$4,$5,$6,'PRIMARY_RUNTIME','EXACT','DISCOVERED',$7,'ACTIVE','binding-create',repeat('a',64))
	`, fixture.bindingID, fixture.tenantID, fixture.workspaceID, fixture.environmentID, fixture.serviceID,
		fixture.assetID, fixture.sourceID)
}

func insertTerminalAudit(t *testing.T, database assetSQLExecutor, fixture assetCatalogFixture, runID, digest string) {
	t.Helper()
	execAssetSQL(t, database, `
		INSERT INTO audit_records (
			id,tenant_id,workspace_id,actor_type,actor_id,action,resource_type,resource_id,
			request_id,trace_id,payload_hash
		) SELECT gen_random_uuid(),$1,$2,'SYSTEM',run.lease_owner,'TERMINAL_COMMITTED',
			'ASSET_SOURCE_RUN',$3,'source-terminal:'||$3,'fixture-trace',$4
		FROM asset_source_runs AS run
		WHERE run.id=$3
	`, fixture.tenantID, fixture.workspaceID, runID, digest)
}

func insertCleanupAudit(
	t *testing.T,
	database assetSQLExecutor,
	fixture assetCatalogFixture,
	runID string,
	attemptEpoch int64,
	digest string,
) {
	t.Helper()
	execAssetSQL(t, database, `
		INSERT INTO audit_records (
			id,tenant_id,workspace_id,actor_type,actor_id,action,resource_type,resource_id,
			request_id,trace_id,payload_hash
		) SELECT
			gen_random_uuid(),$1,$2,'SYSTEM',run.lease_owner,'ATTEMPT_CLEANED',
			'ASSET_SOURCE_RUN',$3,'source-attempt:'||$3||':'||$4,'fixture-cleanup-trace',$5
		FROM asset_source_runs AS run
		WHERE run.id=$3
	`, fixture.tenantID, fixture.workspaceID, runID, attemptEpoch, digest)
}

func sourceRunNoCredentialDigest(t *testing.T, database assetSQLQuerier, runID string) string {
	t.Helper()
	var digest string
	if err := database.QueryRow(context.Background(), `
		SELECT asset_catalog_source_run_no_credential_digest(run)
		FROM asset_source_runs AS run
		WHERE run.id=$1
	`, runID).Scan(&digest); err != nil {
		t.Fatalf("derive no-credential cleanup digest: %v", err)
	}
	return digest
}

func sourceRunTerminalDigest(
	t *testing.T,
	database assetSQLQuerier,
	runID string,
	desiredStatus string,
	desiredFailureCode any,
) string {
	t.Helper()
	var digest string
	if err := database.QueryRow(context.Background(), `
		SELECT asset_catalog_source_run_terminal_digest(run,$2,$3)
		FROM asset_source_runs AS run
		WHERE run.id=$1
	`, runID, desiredStatus, desiredFailureCode).Scan(&digest); err != nil {
		t.Fatalf("derive terminal command digest: %v", err)
	}
	return digest
}

func migrationDirectory(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve migration integration test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "../../../migrations"))
}

func randomAssetHex(t *testing.T, size int) string {
	t.Helper()
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		t.Fatalf("read test randomness: %v", err)
	}
	return hex.EncodeToString(value)
}

func expectAssetSQLState(t *testing.T, database *pgxpool.Pool, state, query string, arguments ...any) {
	t.Helper()
	_, err := database.Exec(context.Background(), query, arguments...)
	if err == nil {
		t.Fatalf("query succeeded, want SQLSTATE %s", state)
	}
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) || databaseError.Code != state {
		t.Fatalf("query error=%v, want SQLSTATE %s", err, state)
	}
}

func execAssetSQL(t *testing.T, database assetSQLExecutor, query string, arguments ...any) {
	t.Helper()
	if _, err := database.Exec(context.Background(), query, arguments...); err != nil {
		t.Fatalf("exec asset catalog fixture: %v", err)
	}
}

func TestAssetCatalogMigration(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	var version int
	if err := harness.db.QueryRow(context.Background(), `SELECT current_setting('server_version_num')::integer`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version < 180004 || version >= 190000 {
		t.Fatalf("PostgreSQL version=%d", version)
	}
	var tableCount int
	if err := harness.db.QueryRow(context.Background(), `
		SELECT count(*) FROM information_schema.tables
		WHERE table_schema='public' AND table_name = ANY($1)
	`, []string{"asset_sources", "asset_source_revisions", "asset_source_revision_authorities", "asset_source_runs",
		"asset_source_limit_buckets", "asset_source_limit_permits", "asset_observations", "assets",
		"asset_type_details", "asset_conflicts", "asset_relationships", "service_asset_bindings"}).Scan(&tableCount); err != nil {
		t.Fatal(err)
	}
	if tableCount != 12 {
		t.Fatalf("asset catalog table count=%d, want 12", tableCount)
	}
	var foreignKeyCount int
	if err := harness.db.QueryRow(context.Background(), `
		SELECT count(*)
		FROM pg_catalog.pg_constraint AS constraint_record
		JOIN pg_catalog.pg_class AS relation ON relation.oid=constraint_record.conrelid
		JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=relation.relnamespace
		WHERE namespace.nspname='public'
		  AND relation.relname=ANY($1)
		  AND constraint_record.contype='f'
	`, assetCatalogTableNames()).Scan(&foreignKeyCount); err != nil {
		t.Fatal(err)
	}
	if foreignKeyCount != 44 {
		t.Fatalf("asset catalog foreign key count=%d, want 44", foreignKeyCount)
	}
	roleAdmission := storepostgres.NewDatabaseRoleAdmission(harness.application, "public")
	if err := roleAdmission.Check(context.Background()); err != nil {
		t.Fatalf("application database-role admission: %v", err)
	}
}

func TestAssetCatalogMigrationDigestClosure(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)

	const (
		tenantID      = "10000000-0000-4000-8000-000000000151"
		workspaceID   = "20000000-0000-4000-8000-000000000151"
		environmentID = "30000000-0000-4000-8000-000000000151"
		sourceID      = "60000000-0000-4000-8000-000000000151"
		revisionID    = "61000000-0000-4000-8000-000000000151"
	)
	profile := []byte(correctiveManualProfileManifestV1)
	providerSchema := []byte(`{"additionalProperties":false,"properties":{},"type":"object"}`)
	profileDigest := sha256.Sum256(profile)
	providerSchemaDigest := sha256.Sum256(providerSchema)
	if got, want := hex.EncodeToString(profileDigest[:]), "57d171caef88e859700dde32fda6b9a982b25b50deca47c6246945c8dfb60b96"; got != want {
		t.Fatalf("MANUAL profile digest = %s, want %s", got, want)
	}
	if got, want := hex.EncodeToString(providerSchemaDigest[:]), "99334726611ccf58a148b0814696bfa6fe08c1b2d027e946beccf5a74331c9aa"; got != want {
		t.Fatalf("MANUAL provider schema digest = %s, want %s", got, want)
	}

	authorityDigest := assetCatalogCorrectiveFramedDigest(
		[]byte("asset-source-authority-scope.v1"),
		[]byte("1"),
		[]byte(environmentID),
	)
	definitionDigest := assetCatalogCorrectiveFramedDigest(
		[]byte("asset-source-definition.v2"),
		[]byte("MANUAL"),
		[]byte("MANUAL_V1"),
		[]byte("MANUAL_V1"),
		profileDigest[:],
		providerSchemaDigest[:],
	)
	if got, want := definitionDigest, "7a0c248c3ebd32dae4e94b516d6f56608d4f1a25cd33d0fe467b54200824984c"; got != want {
		t.Fatalf("MANUAL definition digest = %s, want %s", got, want)
	}
	bindingDigest := assetCatalogCorrectiveFramedDigest(
		[]byte("asset-source-revision-binding.v1"),
		[]byte(tenantID),
		[]byte(workspaceID),
		[]byte(sourceID),
		[]byte("1"),
		assetCatalogCorrectiveDecodeDigest(t, definitionDigest),
		nil,
		[]byte("MANUAL"),
		nil,
		nil,
		nil,
		assetCatalogCorrectiveDecodeDigest(t, authorityDigest),
		[]byte("1"),
		[]byte("1"),
		[]byte("1"),
		[]byte("1"),
		[]byte("MANUAL_V1"),
		nil,
		nil,
		nil,
	)

	transaction, err := harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin corrective digest fixture: %v", err)
	}
	defer func() { _ = transaction.Rollback(context.Background()) }()
	execAssetSQL(t, transaction, `INSERT INTO tenants (id,name) VALUES ($1,'digest-tenant')`, tenantID)
	execAssetSQL(t, transaction, `INSERT INTO workspaces (id,tenant_id,name) VALUES ($1,$2,'digest-workspace')`, workspaceID, tenantID)
	execAssetSQL(t, transaction, `
		INSERT INTO environments (id,tenant_id,workspace_id,name,kind)
		VALUES ($1,$2,$3,'digest-production','PROD')
	`, environmentID, tenantID, workspaceID)
	execAssetSQL(t, transaction, `
		INSERT INTO asset_sources (
			id,tenant_id,workspace_id,source_kind,provider_kind,name,
			create_idempotency_key,create_request_hash
		) VALUES ($1,$2,$3,'MANUAL','MANUAL_V1','digest-source','digest-source-create',repeat('a',64))
	`, sourceID, tenantID, workspaceID)
	execAssetSQL(t, transaction, `
		INSERT INTO asset_source_revisions (
			id,tenant_id,workspace_id,source_id,revision,
			canonical_profile_manifest,profile_manifest_sha256,
			canonical_provider_schema,canonical_provider_schema_sha256,
			sync_mode,authority_scope_digest,source_definition_digest,canonical_revision_digest,
			rate_limit_requests,rate_limit_window_seconds,backpressure_base_seconds,
			backpressure_max_seconds,profile_code,created_by,change_reason_code,
			expected_source_version
		) VALUES (
			$1,$2,$3,$4,1,$5,$6,$7,$8,'MANUAL',$9,$10,$11,
			1,1,1,1,'MANUAL_V1','digest-reviewer','INITIAL_CREATE',1
		)
	`, revisionID, tenantID, workspaceID, sourceID, profile, hex.EncodeToString(profileDigest[:]),
		providerSchema, hex.EncodeToString(providerSchemaDigest[:]), authorityDigest, definitionDigest, bindingDigest)
	execAssetSQL(t, transaction, `
		INSERT INTO asset_source_revision_authorities (
			tenant_id,workspace_id,source_id,source_revision,environment_id,canonical_ordinal
		) VALUES ($1,$2,$3,1,$4,1)
	`, tenantID, workspaceID, sourceID, environmentID)
	if err := transaction.Commit(context.Background()); err != nil {
		t.Fatalf("commit corrective digest closure: %v", err)
	}

	var actualAuthority, actualDefinition, actualBinding, recomputedBinding string
	if err := harness.application.QueryRow(context.Background(), `
		SELECT candidate.authority_scope_digest,
			candidate.source_definition_digest,
			candidate.canonical_revision_digest,
			public.asset_catalog_source_revision_binding_digest(candidate)
		FROM public.asset_source_revisions AS candidate
		WHERE candidate.id=$1
	`, revisionID).Scan(&actualAuthority, &actualDefinition, &actualBinding, &recomputedBinding); err != nil {
		t.Fatalf("read corrective digest closure through application identity: %v", err)
	}
	if actualAuthority != authorityDigest || actualDefinition != definitionDigest ||
		actualBinding != bindingDigest || recomputedBinding != bindingDigest {
		t.Fatalf(
			"digest closure authority=%s definition=%s binding=%s recomputed=%s",
			actualAuthority,
			actualDefinition,
			actualBinding,
			recomputedBinding,
		)
	}
}

func assetCatalogCorrectiveFramedDigest(fields ...[]byte) string {
	framed := make([]byte, 0, len(fields)*8)
	var size [4]byte
	for _, field := range fields {
		if field == nil {
			framed = append(framed, 0)
			continue
		}
		framed = append(framed, 1)
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		framed = append(framed, size[:]...)
		framed = append(framed, field...)
	}
	digest := sha256.Sum256(framed)
	return hex.EncodeToString(digest[:])
}

func assetCatalogCorrectiveDecodeDigest(t *testing.T, encoded string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != sha256.Size {
		t.Fatalf("decode corrective SHA-256 %q: %v", encoded, err)
	}
	return decoded
}

func TestAssetCatalogMigrationEnvironmentMappingModeParity(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyUpThrough(t, "000014_read_evidence_clock_skew.up.sql")
	admission := assetpostgres.NewSchemaAdmission(harness.application, "public")

	harness.applyMigration(t, "000015_assets_catalog.up.sql")
	if err := admission.Check(context.Background()); err != nil {
		t.Fatalf("schema admission after first 000015 up: %v", err)
	}
	harness.applyMigration(t, "000015_assets_catalog.down.sql")
	harness.applyMigration(t, "000015_assets_catalog.up.sql")
	if err := admission.Check(context.Background()); err != nil {
		t.Fatalf("schema admission after 000015 up/down/up: %v", err)
	}

	t.Run("explicit item accepts two authorities", func(t *testing.T) {
		candidate := newCorrectiveMatrixCandidate(t, 2)
		candidate.environmentMappingMode = "EXPLICIT_ITEM_ENVIRONMENT"
		candidate.refreshProfileManifest()
		requireCorrectiveMatrixCandidateCommit(t, harness.db, candidate)
	})

	t.Run("legacy multi fails closed", func(t *testing.T) {
		candidate := newCorrectiveMatrixCandidate(t, 2)
		candidate.environmentMappingMode = "MULTI_ENVIRONMENT"
		candidate.refreshProfileManifest()
		expectCorrectiveMatrixCandidateError(t, harness.db, candidate,
			"23514", "asset_source_revisions_profile_manifest_guard")
	})
}

func TestAssetCatalogMigrationCorrectivePersistentContractMatrix(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)

	authorityEnvironmentFK := requireCorrectiveMatrixConstraintName(
		t, harness.db, "asset_source_revision_authorities", "f",
		[]string{"tenant_id", "workspace_id", "environment_id"},
	)
	authorityEnvironmentPK := requireCorrectiveMatrixConstraintName(
		t, harness.db, "asset_source_revision_authorities", "p",
		[]string{"tenant_id", "workspace_id", "source_id", "source_revision", "environment_id"},
	)
	authorityOrdinalUK := requireCorrectiveMatrixConstraintName(
		t, harness.db, "asset_source_revision_authorities", "u",
		[]string{"tenant_id", "workspace_id", "source_id", "source_revision", "canonical_ordinal"},
	)

	t.Run("authority canonical success", func(t *testing.T) {
		candidate := newCorrectiveMatrixCandidate(t, 3)
		requireCorrectiveMatrixCandidateCommit(t, harness.db, candidate)
	})

	t.Run("authority absent", func(t *testing.T) {
		candidate := newCorrectiveMatrixCandidate(t, 1)
		candidate.authorities = nil
		candidate.environmentMappingMode = "EXPLICIT_ITEM_ENVIRONMENT"
		candidate.refreshProfileManifest()
		expectCorrectiveMatrixCandidateError(t, harness.db, candidate,
			"23514", "asset_source_revision_authorities_order_guard")
	})

	t.Run("authority cross scope", func(t *testing.T) {
		candidate := newCorrectiveMatrixCandidate(t, 1)
		candidate.foreignEnvironment = &correctiveMatrixForeignEnvironment{
			workspaceID:   correctiveMatrixUUID(t),
			environmentID: correctiveMatrixUUID(t),
		}
		candidate.authorities = []correctiveMatrixAuthority{{
			environmentID: candidate.foreignEnvironment.environmentID,
			ordinal:       1,
		}}
		expectCorrectiveMatrixCandidateError(t, harness.db, candidate, "23503", authorityEnvironmentFK)
	})

	t.Run("authority unsorted", func(t *testing.T) {
		candidate := newCorrectiveMatrixCandidate(t, 2)
		candidate.authorities[0].ordinal = 2
		candidate.authorities[1].ordinal = 1
		expectCorrectiveMatrixCandidateError(t, harness.db, candidate,
			"23514", "asset_source_revision_authorities_order_guard")
	})

	t.Run("authority duplicate environment", func(t *testing.T) {
		candidate := newCorrectiveMatrixCandidate(t, 1)
		candidate.authorities = append(candidate.authorities, correctiveMatrixAuthority{
			environmentID: candidate.environmentIDs[0],
			ordinal:       2,
		})
		candidate.environmentMappingMode = "EXPLICIT_ITEM_ENVIRONMENT"
		candidate.refreshProfileManifest()
		expectCorrectiveMatrixCandidateError(t, harness.db, candidate, "23505", authorityEnvironmentPK)
	})

	t.Run("authority duplicate ordinal", func(t *testing.T) {
		candidate := newCorrectiveMatrixCandidate(t, 2)
		candidate.authorities[1].ordinal = candidate.authorities[0].ordinal
		expectCorrectiveMatrixCandidateError(t, harness.db, candidate, "23505", authorityOrdinalUK)
	})

	t.Run("authority digest mismatch", func(t *testing.T) {
		candidate := newCorrectiveMatrixCandidate(t, 2)
		mismatchedDigest := strings.Repeat("f", 64)
		candidate.authorityDigestOverride = &mismatchedDigest
		expectCorrectiveMatrixCandidateError(t, harness.db, candidate,
			"23514", "asset_source_revisions_digest_closure_guard")
	})

	t.Run("source definition digest mismatch", func(t *testing.T) {
		candidate := newCorrectiveMatrixCandidate(t, 1)
		mismatchedDigest := strings.Repeat("e", 64)
		candidate.sourceDefinitionDigestOverride = &mismatchedDigest
		expectCorrectiveMatrixCandidateError(t, harness.db, candidate,
			"23514", "asset_source_revisions_digest_closure_guard")
	})

	t.Run("canonical binding digest mismatch", func(t *testing.T) {
		candidate := newCorrectiveMatrixCandidate(t, 1)
		mismatchedDigest := strings.Repeat("d", 64)
		candidate.bindingDigestOverride = &mismatchedDigest
		expectCorrectiveMatrixCandidateError(t, harness.db, candidate,
			"23514", "asset_source_revisions_digest_closure_guard")
	})

	t.Run("authority late append", func(t *testing.T) {
		candidate := newCorrectiveMatrixCandidate(t, 2)
		candidate.authorities = candidate.authorities[:1]
		candidate.environmentMappingMode = "EXPLICIT_ITEM_ENVIRONMENT"
		candidate.refreshProfileManifest()
		requireCorrectiveMatrixCandidateCommit(t, harness.db, candidate)

		transaction, err := harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
		if err != nil {
			t.Fatalf("begin corrective matrix late-authority transaction: %v", err)
		}
		_, mutationErr := transaction.Exec(context.Background(), `
			INSERT INTO asset_source_revision_authorities (
				tenant_id,workspace_id,source_id,source_revision,environment_id,canonical_ordinal
			) VALUES ($1,$2,$3,1,$4,2)
		`, candidate.tenantID, candidate.workspaceID, candidate.sourceID, candidate.environmentIDs[1])
		if mutationErr == nil {
			mutationErr = transaction.Commit(context.Background())
		} else {
			_ = transaction.Rollback(context.Background())
		}
		assertCorrectiveMatrixPostgresError(t, mutationErr,
			"55000", "asset_source_revision_authorities_parent_guard")

		var authorityCount int64
		if err := harness.db.QueryRow(context.Background(), `
			SELECT count(*) FROM asset_source_revision_authorities WHERE source_id=$1
		`, candidate.sourceID).Scan(&authorityCount); err != nil {
			t.Fatalf("count authority rows after rejected late append: %v", err)
		}
		if authorityCount != 1 {
			t.Fatalf("late authority rejection left %d rows, want original one", authorityCount)
		}
	})

	t.Run("Profile canonical success", func(t *testing.T) {
		candidate := newCorrectiveMatrixCandidate(t, 1)
		requireCorrectiveMatrixCandidateCommit(t, harness.db, candidate)
	})

	t.Run("Profile whitespace", func(t *testing.T) {
		candidate := newCorrectiveMatrixCandidate(t, 1)
		candidate.profileManifest = append([]byte("\n"), candidate.profileManifest...)
		expectCorrectiveMatrixCandidateError(t, harness.db, candidate,
			"23514", "asset_source_revisions_canonical_content_guard")
	})

	t.Run("Profile key order", func(t *testing.T) {
		candidate := newCorrectiveMatrixCandidate(t, 1)
		const canonicalPrefix = `{"backpressure_base_seconds":1,"backpressure_max_seconds":60,`
		const reorderedPrefix = `{"backpressure_max_seconds":60,"backpressure_base_seconds":1,`
		if !strings.HasPrefix(string(candidate.profileManifest), canonicalPrefix) {
			t.Fatal("corrective matrix canonical Profile prefix drifted")
		}
		candidate.profileManifest = []byte(reorderedPrefix + strings.TrimPrefix(
			string(candidate.profileManifest), canonicalPrefix,
		))
		expectCorrectiveMatrixCandidateError(t, harness.db, candidate,
			"23514", "asset_source_revisions_canonical_content_guard")
	})

	t.Run("Profile duplicate key", func(t *testing.T) {
		candidate := newCorrectiveMatrixCandidate(t, 1)
		const canonicalPrefix = `{"backpressure_base_seconds":1,`
		if !strings.HasPrefix(string(candidate.profileManifest), canonicalPrefix) {
			t.Fatal("corrective matrix canonical Profile prefix drifted")
		}
		candidate.profileManifest = []byte(canonicalPrefix +
			`"backpressure_base_seconds":1,` + strings.TrimPrefix(
			string(candidate.profileManifest), canonicalPrefix,
		))
		expectCorrectiveMatrixCandidateError(t, harness.db, candidate,
			"23514", "asset_source_revisions_schema_ck")
	})

	t.Run("Profile unknown key", func(t *testing.T) {
		candidate := newCorrectiveMatrixCandidate(t, 1)
		manifest := string(candidate.profileManifest)
		if !strings.HasSuffix(manifest, "}") {
			t.Fatal("corrective matrix canonical Profile suffix drifted")
		}
		candidate.profileManifest = []byte(strings.TrimSuffix(manifest, "}") +
			`,"unknown_key":"UNKNOWN"}`)
		expectCorrectiveMatrixCandidateError(t, harness.db, candidate,
			"23514", "asset_source_revisions_profile_manifest_guard")
	})

	t.Run("Profile exact 16385 byte oversize", func(t *testing.T) {
		candidate := newCorrectiveMatrixCandidate(t, 1)
		const prefix = `{"padding":"`
		const suffix = `"}`
		candidate.profileManifest = []byte(prefix + strings.Repeat("x", 16385-len(prefix)-len(suffix)) + suffix)
		if len(candidate.profileManifest) != 16385 {
			t.Fatalf("oversize Profile length=%d, want exactly 16385", len(candidate.profileManifest))
		}
		expectCorrectiveMatrixCandidateError(t, harness.db, candidate,
			"23514", "asset_source_revisions_schema_ck")
	})

	futureHookRestored := false
	t.Cleanup(func() {
		if !futureHookRestored {
			setCorrectiveMatrixInitialFutureHook(t, harness, false)
		}
	})
	setCorrectiveMatrixInitialFutureHook(t, harness, true)

	t.Run("typed K8S matching pair success", func(t *testing.T) {
		candidate := newCorrectiveMatrixFutureCandidate(t, "KUBERNETES_OPERATOR")
		typedCode := candidate.profileCode
		preparedDigest := strings.Repeat("1", 64)
		candidate.manifestTypedExtension = &typedCode
		candidate.typedExtensionCode = &typedCode
		candidate.preparedExtensionDigest = &preparedDigest
		candidate.refreshProfileManifest()
		requireCorrectiveMatrixCandidateCommit(t, harness.db, candidate)
	})

	t.Run("typed K8S null pair", func(t *testing.T) {
		candidate := newCorrectiveMatrixFutureCandidate(t, "KUBERNETES_OPERATOR")
		expectCorrectiveMatrixCandidateError(t, harness.db, candidate,
			"23514", "asset_source_revisions_typed_extension_guard")
	})

	t.Run("typed K8S code only", func(t *testing.T) {
		candidate := newCorrectiveMatrixFutureCandidate(t, "KUBERNETES_OPERATOR")
		typedCode := candidate.profileCode
		candidate.manifestTypedExtension = &typedCode
		candidate.typedExtensionCode = &typedCode
		candidate.refreshProfileManifest()
		expectCorrectiveMatrixCandidateError(t, harness.db, candidate,
			"23514", "asset_source_revisions_typed_extension_ck")
	})

	t.Run("typed K8S digest only", func(t *testing.T) {
		candidate := newCorrectiveMatrixFutureCandidate(t, "KUBERNETES_OPERATOR")
		preparedDigest := strings.Repeat("2", 64)
		candidate.preparedExtensionDigest = &preparedDigest
		candidate.refreshProfileManifest()
		expectCorrectiveMatrixCandidateError(t, harness.db, candidate,
			"23514", "asset_source_revisions_typed_extension_ck")
	})

	t.Run("typed K8S code mismatch", func(t *testing.T) {
		candidate := newCorrectiveMatrixFutureCandidate(t, "KUBERNETES_OPERATOR")
		typedCode := "MATRIX_K8S_OTHER_V1"
		preparedDigest := strings.Repeat("3", 64)
		candidate.manifestTypedExtension = &typedCode
		candidate.typedExtensionCode = &typedCode
		candidate.preparedExtensionDigest = &preparedDigest
		candidate.refreshProfileManifest()
		expectCorrectiveMatrixCandidateError(t, harness.db, candidate,
			"23514", "asset_source_revisions_typed_extension_guard")
	})

	t.Run("typed AWX null pair success", func(t *testing.T) {
		candidate := newCorrectiveMatrixFutureCandidate(t, "AWX_INVENTORY")
		requireCorrectiveMatrixCandidateCommit(t, harness.db, candidate)
	})

	t.Run("typed AWX present pair", func(t *testing.T) {
		candidate := newCorrectiveMatrixFutureCandidate(t, "AWX_INVENTORY")
		typedCode := candidate.profileCode
		preparedDigest := strings.Repeat("4", 64)
		candidate.manifestTypedExtension = &typedCode
		candidate.typedExtensionCode = &typedCode
		candidate.preparedExtensionDigest = &preparedDigest
		candidate.refreshProfileManifest()
		expectCorrectiveMatrixCandidateError(t, harness.db, candidate,
			"23514", "asset_source_revisions_typed_extension_guard")
	})

	setCorrectiveMatrixInitialFutureHook(t, harness, false)
	futureHookRestored = true

	t.Run("future hook exact default restored", func(t *testing.T) {
		var admitted bool
		if err := harness.application.QueryRow(context.Background(), `
			SELECT public.asset_catalog_future_source_gate_admitted(NULL::public.asset_sources)
		`).Scan(&admitted); err != nil {
			t.Fatalf("call restored corrective matrix future hook: %v", err)
		}
		if admitted {
			t.Fatal("restored corrective matrix future hook admitted a source, want exact fail-closed default")
		}
		if err := assetpostgres.NewSchemaAdmission(harness.application, "public").Check(context.Background()); err != nil {
			t.Fatalf("schema admission after restoring corrective matrix future hook: %v", err)
		}
	})

	t.Run("opaque reference truth table", func(t *testing.T) {
		transaction, err := harness.application.BeginTx(context.Background(), pgx.TxOptions{
			IsoLevel: pgx.Serializable, AccessMode: pgx.ReadOnly,
		})
		if err != nil {
			t.Fatalf("begin corrective matrix opaque truth-table transaction: %v", err)
		}
		defer func() { _ = transaction.Rollback(context.Background()) }()
		cases := []struct {
			name      string
			candidate string
			want      bool
		}{
			{name: "safe opaque id", candidate: "credential-ref_01.v1", want: true},
			{name: "URL", candidate: "https://example.invalid/token", want: false},
			{name: "DSN", candidate: "postgres://user:pass@db/prod", want: false},
			{name: "Vault path", candidate: "kv/data/team/credential", want: false},
			{name: "PEM", candidate: "-----BEGIN PRIVATE KEY-----", want: false},
			{name: "Header", candidate: "Authorization: Bearer token", want: false},
		}
		for _, testCase := range cases {
			var valid bool
			if err := transaction.QueryRow(context.Background(), `
				SELECT public.asset_catalog_opaque_reference_valid($1)
			`, testCase.candidate).Scan(&valid); err != nil {
				t.Fatalf("evaluate corrective matrix opaque %s: %v", testCase.name, err)
			}
			if valid != testCase.want {
				t.Fatalf("opaque %s validity=%t, want %t", testCase.name, valid, testCase.want)
			}
		}
		if err := transaction.Commit(context.Background()); err != nil {
			t.Fatalf("commit corrective matrix opaque truth-table transaction: %v", err)
		}
	})

	t.Run("opaque safe references persist", func(t *testing.T) {
		candidate := newCorrectiveMatrixCandidate(t, 1)
		credentialReference := "credential-ref_01.v1"
		trustReference := "trust-anchor_02.v1"
		networkReference := "network-policy_03.v1"
		candidate.credentialReference = &credentialReference
		candidate.trustReference = &trustReference
		candidate.networkReference = &networkReference
		candidate.refreshProfileManifest()
		requireCorrectiveMatrixCandidateCommit(t, harness.db, candidate)
	})

	invalidOpaqueReferences := []struct {
		name      string
		candidate string
		apply     func(*correctiveMatrixCandidate, *string)
	}{
		{
			name:      "opaque credential URL rejected",
			candidate: "https://example.invalid/token",
			apply: func(candidate *correctiveMatrixCandidate, value *string) {
				candidate.credentialReference = value
			},
		},
		{
			name:      "opaque credential DSN rejected",
			candidate: "postgres://user:pass@db/prod",
			apply: func(candidate *correctiveMatrixCandidate, value *string) {
				candidate.credentialReference = value
			},
		},
		{
			name:      "opaque trust Vault path rejected",
			candidate: "kv/data/team/credential",
			apply: func(candidate *correctiveMatrixCandidate, value *string) {
				candidate.trustReference = value
			},
		},
		{
			name:      "opaque trust PEM rejected",
			candidate: "-----BEGIN PRIVATE KEY-----",
			apply: func(candidate *correctiveMatrixCandidate, value *string) {
				candidate.trustReference = value
			},
		},
		{
			name:      "opaque network Header rejected",
			candidate: "Authorization: Bearer token",
			apply: func(candidate *correctiveMatrixCandidate, value *string) {
				candidate.networkReference = value
			},
		},
	}
	for _, testCase := range invalidOpaqueReferences {
		t.Run(testCase.name, func(t *testing.T) {
			candidate := newCorrectiveMatrixCandidate(t, 1)
			value := testCase.candidate
			testCase.apply(&candidate, &value)
			candidate.refreshProfileManifest()
			expectCorrectiveMatrixCandidateError(t, harness.db, candidate,
				"23514", "asset_source_revisions_reference_ck")
		})
	}
}

type correctiveMatrixAuthority struct {
	environmentID string
	ordinal       int32
}

type correctiveMatrixForeignEnvironment struct {
	workspaceID   string
	environmentID string
}

type correctiveMatrixCandidate struct {
	label                          string
	tenantID                       string
	workspaceID                    string
	sourceID                       string
	revisionID                     string
	environmentIDs                 []string
	foreignEnvironment             *correctiveMatrixForeignEnvironment
	authorities                    []correctiveMatrixAuthority
	sourceKind                     string
	providerKind                   string
	profileCode                    string
	syncMode                       string
	environmentMappingMode         string
	integrationID                  *string
	credentialReference            *string
	trustReference                 *string
	networkReference               *string
	scheduleExpression             *string
	manifestTypedExtension         *string
	typedExtensionCode             *string
	preparedExtensionDigest        *string
	rateLimitRequests              int32
	rateLimitWindowSeconds         int32
	backpressureBaseSeconds        int32
	backpressureMaxSeconds         int32
	profileManifest                []byte
	providerSchema                 []byte
	authorityDigestOverride        *string
	sourceDefinitionDigestOverride *string
	bindingDigestOverride          *string
}

type correctiveMatrixDigests struct {
	profileManifest string
	providerSchema  string
	authority       string
	definition      string
	binding         string
}

func newCorrectiveMatrixCandidate(t *testing.T, environmentCount int) correctiveMatrixCandidate {
	t.Helper()
	if environmentCount < 1 {
		t.Fatalf("corrective matrix environment count=%d, want at least one persisted Environment", environmentCount)
	}
	candidate := correctiveMatrixCandidate{
		label:                   randomAssetHex(t, 8),
		tenantID:                correctiveMatrixUUID(t),
		workspaceID:             correctiveMatrixUUID(t),
		sourceID:                correctiveMatrixUUID(t),
		revisionID:              correctiveMatrixUUID(t),
		sourceKind:              "EXTERNAL_CMDB",
		providerKind:            "MATRIX_EXTERNAL_V1",
		profileCode:             "MATRIX_EXTERNAL_V1",
		syncMode:                "ON_DEMAND",
		rateLimitRequests:       100,
		rateLimitWindowSeconds:  60,
		backpressureBaseSeconds: 1,
		backpressureMaxSeconds:  60,
		providerSchema:          []byte(`{"additionalProperties":false,"properties":{},"type":"object"}`),
	}
	for range environmentCount {
		candidate.environmentIDs = append(candidate.environmentIDs, correctiveMatrixUUID(t))
	}
	sort.Strings(candidate.environmentIDs)
	for index, environmentID := range candidate.environmentIDs {
		candidate.authorities = append(candidate.authorities, correctiveMatrixAuthority{
			environmentID: environmentID,
			ordinal:       int32(index + 1),
		})
	}
	if environmentCount == 1 {
		candidate.environmentMappingMode = "SINGLE_ENVIRONMENT"
	} else {
		candidate.environmentMappingMode = "EXPLICIT_ITEM_ENVIRONMENT"
	}
	candidate.refreshProfileManifest()
	return candidate
}

func newCorrectiveMatrixFutureCandidate(t *testing.T, sourceKind string) correctiveMatrixCandidate {
	t.Helper()
	candidate := newCorrectiveMatrixCandidate(t, 1)
	candidate.sourceKind = sourceKind
	switch sourceKind {
	case "KUBERNETES_OPERATOR":
		candidate.providerKind = "MATRIX_K8S_V1"
		candidate.profileCode = "MATRIX_K8S_V1"
	case "AWX_INVENTORY":
		candidate.providerKind = "MATRIX_AWX_V1"
		candidate.profileCode = "MATRIX_AWX_V1"
	default:
		t.Fatalf("unsupported corrective matrix future Source kind %q", sourceKind)
	}
	candidate.refreshProfileManifest()
	return candidate
}

func (candidate *correctiveMatrixCandidate) refreshProfileManifest() {
	integrationMode := "NONE"
	if candidate.integrationID != nil {
		integrationMode = "REQUIRED"
	}
	credentialPurpose := "NONE"
	if candidate.credentialReference != nil {
		credentialPurpose = "DISCOVERY_READ"
	}
	trustMode := "NONE"
	if candidate.trustReference != nil {
		trustMode = "REQUIRED"
	}
	networkMode := "NONE"
	if candidate.networkReference != nil {
		networkMode = "REQUIRED"
	}
	scheduleMode := "NONE"
	if candidate.scheduleExpression != nil {
		scheduleMode = "REQUIRED"
	}
	typedExtension := "null"
	if candidate.manifestTypedExtension != nil {
		typedExtension = fmt.Sprintf("%q", *candidate.manifestTypedExtension)
	}
	candidate.profileManifest = []byte(fmt.Sprintf(
		`{"backpressure_base_seconds":%d,"backpressure_max_seconds":%d,"compatibility_class":%q,"credential_purpose":%q,"dlp_policy_code":"ASSET_SAFE_V1","environment_mapping_mode":%q,"freshness_kind":"OBJECT_SEQUENCE","integration_mode":%q,"max_document_bytes":65536,"max_page_bytes":1048576,"max_page_items":100,"max_page_relations":100,"network_mode":%q,"parser_code":%q,"profile_code":%q,"provider_kind":%q,"rate_limit_requests":%d,"rate_limit_window_seconds":%d,"relationship_types":[],"schedule_mode":%q,"source_kind":%q,"sync_mode":%q,"trust_mode":%q,"trusted_path_codes":["MATRIX_DISPLAY_NAME"],"typed_extension_code":%s,"version":"asset-source-profile-manifest.v1"}`,
		candidate.backpressureBaseSeconds,
		candidate.backpressureMaxSeconds,
		candidate.profileCode,
		credentialPurpose,
		candidate.environmentMappingMode,
		integrationMode,
		networkMode,
		candidate.profileCode,
		candidate.profileCode,
		candidate.providerKind,
		candidate.rateLimitRequests,
		candidate.rateLimitWindowSeconds,
		scheduleMode,
		candidate.sourceKind,
		candidate.syncMode,
		trustMode,
		typedExtension,
	))
}

func (candidate correctiveMatrixCandidate) digests(t *testing.T) correctiveMatrixDigests {
	t.Helper()
	profileHash := sha256.Sum256(candidate.profileManifest)
	providerHash := sha256.Sum256(candidate.providerSchema)
	authorityIDs := make([]string, 0, len(candidate.authorities))
	for _, authority := range candidate.authorities {
		authorityIDs = append(authorityIDs, authority.environmentID)
	}
	sort.Strings(authorityIDs)
	authorityFrames := [][]byte{
		[]byte("asset-source-authority-scope.v1"),
		[]byte(fmt.Sprintf("%d", len(authorityIDs))),
	}
	for _, environmentID := range authorityIDs {
		authorityFrames = append(authorityFrames, []byte(environmentID))
	}
	authorityDigest := assetCatalogCorrectiveFramedDigest(authorityFrames...)
	if candidate.authorityDigestOverride != nil {
		authorityDigest = *candidate.authorityDigestOverride
	}
	definitionDigest := assetCatalogCorrectiveFramedDigest(
		[]byte("asset-source-definition.v2"),
		[]byte(candidate.sourceKind),
		[]byte(candidate.providerKind),
		[]byte(candidate.profileCode),
		profileHash[:],
		providerHash[:],
	)
	if candidate.sourceDefinitionDigestOverride != nil {
		definitionDigest = *candidate.sourceDefinitionDigestOverride
	}
	var preparedDigest []byte
	if candidate.preparedExtensionDigest != nil {
		preparedDigest = assetCatalogCorrectiveDecodeDigest(t, *candidate.preparedExtensionDigest)
	}
	bindingDigest := assetCatalogCorrectiveFramedDigest(
		[]byte("asset-source-revision-binding.v1"),
		[]byte(candidate.tenantID),
		[]byte(candidate.workspaceID),
		[]byte(candidate.sourceID),
		[]byte("1"),
		assetCatalogCorrectiveDecodeDigest(t, definitionDigest),
		correctiveMatrixOptionalBytes(candidate.integrationID),
		[]byte(candidate.syncMode),
		correctiveMatrixOptionalBytes(candidate.credentialReference),
		correctiveMatrixOptionalBytes(candidate.trustReference),
		correctiveMatrixOptionalBytes(candidate.networkReference),
		assetCatalogCorrectiveDecodeDigest(t, authorityDigest),
		[]byte(fmt.Sprintf("%d", candidate.rateLimitRequests)),
		[]byte(fmt.Sprintf("%d", candidate.rateLimitWindowSeconds)),
		[]byte(fmt.Sprintf("%d", candidate.backpressureBaseSeconds)),
		[]byte(fmt.Sprintf("%d", candidate.backpressureMaxSeconds)),
		[]byte(candidate.profileCode),
		correctiveMatrixOptionalBytes(candidate.scheduleExpression),
		correctiveMatrixOptionalBytes(candidate.typedExtensionCode),
		preparedDigest,
	)
	if candidate.bindingDigestOverride != nil {
		bindingDigest = *candidate.bindingDigestOverride
	}
	return correctiveMatrixDigests{
		profileManifest: hex.EncodeToString(profileHash[:]),
		providerSchema:  hex.EncodeToString(providerHash[:]),
		authority:       authorityDigest,
		definition:      definitionDigest,
		binding:         bindingDigest,
	}
}

func correctiveMatrixUUID(t *testing.T) string {
	t.Helper()
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		t.Fatalf("read corrective matrix UUID randomness: %v", err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", value[:4], value[4:6], value[6:8], value[8:10], value[10:])
}

func correctiveMatrixOptionalBytes(value *string) []byte {
	if value == nil {
		return nil
	}
	return []byte(*value)
}

func correctiveMatrixOptionalValue(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func commitCorrectiveMatrixCandidate(
	t *testing.T,
	database *pgxpool.Pool,
	candidate correctiveMatrixCandidate,
) (correctiveMatrixDigests, error) {
	t.Helper()
	digests := candidate.digests(t)
	transaction, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin corrective matrix transaction: %v", err)
	}
	if err := insertCorrectiveMatrixCandidate(transaction, candidate, digests); err != nil {
		if rollbackErr := transaction.Rollback(context.Background()); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			t.Fatalf("rollback rejected corrective matrix transaction: %v", rollbackErr)
		}
		return digests, err
	}
	if err := transaction.Commit(context.Background()); err != nil {
		_ = transaction.Rollback(context.Background())
		return digests, err
	}
	return digests, nil
}

func insertCorrectiveMatrixCandidate(
	transaction pgx.Tx,
	candidate correctiveMatrixCandidate,
	digests correctiveMatrixDigests,
) error {
	ctx := context.Background()
	if _, err := transaction.Exec(ctx, `INSERT INTO tenants (id,name) VALUES ($1,$2)`,
		candidate.tenantID, "matrix-tenant-"+candidate.label); err != nil {
		return fmt.Errorf("insert corrective matrix tenant: %w", err)
	}
	if _, err := transaction.Exec(ctx, `INSERT INTO workspaces (id,tenant_id,name) VALUES ($1,$2,$3)`,
		candidate.workspaceID, candidate.tenantID, "matrix-workspace-"+candidate.label); err != nil {
		return fmt.Errorf("insert corrective matrix workspace: %w", err)
	}
	for index, environmentID := range candidate.environmentIDs {
		if _, err := transaction.Exec(ctx, `
			INSERT INTO environments (id,tenant_id,workspace_id,name,kind)
			VALUES ($1,$2,$3,$4,'PROD')
		`, environmentID, candidate.tenantID, candidate.workspaceID,
			fmt.Sprintf("matrix-environment-%s-%d", candidate.label, index+1)); err != nil {
			return fmt.Errorf("insert corrective matrix Environment: %w", err)
		}
	}
	if candidate.foreignEnvironment != nil {
		if _, err := transaction.Exec(ctx, `INSERT INTO workspaces (id,tenant_id,name) VALUES ($1,$2,$3)`,
			candidate.foreignEnvironment.workspaceID, candidate.tenantID,
			"matrix-foreign-workspace-"+candidate.label); err != nil {
			return fmt.Errorf("insert corrective matrix foreign Workspace: %w", err)
		}
		if _, err := transaction.Exec(ctx, `
			INSERT INTO environments (id,tenant_id,workspace_id,name,kind)
			VALUES ($1,$2,$3,$4,'PROD')
		`, candidate.foreignEnvironment.environmentID, candidate.tenantID,
			candidate.foreignEnvironment.workspaceID, "matrix-foreign-environment-"+candidate.label); err != nil {
			return fmt.Errorf("insert corrective matrix foreign Environment: %w", err)
		}
	}
	if _, err := transaction.Exec(ctx, `
		INSERT INTO asset_sources (
			id,tenant_id,workspace_id,source_kind,provider_kind,name,
			create_idempotency_key,create_request_hash
		) VALUES ($1,$2,$3,$4,$5,$6,$7,repeat('a',64))
	`, candidate.sourceID, candidate.tenantID, candidate.workspaceID,
		candidate.sourceKind, candidate.providerKind, "matrix-source-"+candidate.label,
		"matrix-source-"+candidate.label); err != nil {
		return fmt.Errorf("insert corrective matrix Source: %w", err)
	}
	if _, err := transaction.Exec(ctx, `
		INSERT INTO asset_source_revisions (
			id,tenant_id,workspace_id,source_id,revision,
			canonical_profile_manifest,profile_manifest_sha256,
			canonical_provider_schema,canonical_provider_schema_sha256,
			integration_id,sync_mode,authority_scope_digest,source_definition_digest,
			canonical_revision_digest,credential_reference_id,trust_reference_id,
			network_policy_reference_id,rate_limit_requests,rate_limit_window_seconds,
			backpressure_base_seconds,backpressure_max_seconds,profile_code,
			schedule_expression,typed_extension_code,prepared_extension_digest,
			created_by,change_reason_code,expected_source_version
		) VALUES (
			$1,$2,$3,$4,1,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
			$17,$18,$19,$20,$21,$22,$23,$24,'matrix-reviewer','INITIAL_CREATE',1
		)
	`, candidate.revisionID, candidate.tenantID, candidate.workspaceID, candidate.sourceID,
		candidate.profileManifest, digests.profileManifest, candidate.providerSchema, digests.providerSchema,
		correctiveMatrixOptionalValue(candidate.integrationID), candidate.syncMode, digests.authority,
		digests.definition, digests.binding, correctiveMatrixOptionalValue(candidate.credentialReference),
		correctiveMatrixOptionalValue(candidate.trustReference), correctiveMatrixOptionalValue(candidate.networkReference),
		candidate.rateLimitRequests, candidate.rateLimitWindowSeconds, candidate.backpressureBaseSeconds,
		candidate.backpressureMaxSeconds, candidate.profileCode, correctiveMatrixOptionalValue(candidate.scheduleExpression),
		correctiveMatrixOptionalValue(candidate.typedExtensionCode),
		correctiveMatrixOptionalValue(candidate.preparedExtensionDigest)); err != nil {
		return fmt.Errorf("insert corrective matrix Source Revision: %w", err)
	}
	for _, authority := range candidate.authorities {
		if _, err := transaction.Exec(ctx, `
			INSERT INTO asset_source_revision_authorities (
				tenant_id,workspace_id,source_id,source_revision,environment_id,canonical_ordinal
			) VALUES ($1,$2,$3,1,$4,$5)
		`, candidate.tenantID, candidate.workspaceID, candidate.sourceID,
			authority.environmentID, authority.ordinal); err != nil {
			return fmt.Errorf("insert corrective matrix authority: %w", err)
		}
	}
	return nil
}

func expectCorrectiveMatrixCandidateError(
	t *testing.T,
	database *pgxpool.Pool,
	candidate correctiveMatrixCandidate,
	state string,
	constraint string,
) {
	t.Helper()
	_, err := commitCorrectiveMatrixCandidate(t, database, candidate)
	assertCorrectiveMatrixPostgresError(t, err, state, constraint)
	assertCorrectiveMatrixCandidateRolledBack(t, database, candidate)
}

func assertCorrectiveMatrixPostgresError(t *testing.T, err error, state, constraint string) {
	t.Helper()
	if err == nil {
		t.Fatalf("corrective matrix SQL unexpectedly succeeded; want %s/%s", state, constraint)
	}
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) {
		t.Fatalf("corrective matrix error=%v, want PostgreSQL %s/%s", err, state, constraint)
	}
	if databaseError.Code != state || databaseError.ConstraintName != constraint {
		t.Fatalf("corrective matrix error=%s/%s (%v), want %s/%s",
			databaseError.Code, databaseError.ConstraintName, err, state, constraint)
	}
}

func assertCorrectiveMatrixCandidateRolledBack(
	t *testing.T,
	database *pgxpool.Pool,
	candidate correctiveMatrixCandidate,
) {
	t.Helper()
	var tenantCount, workspaceCount, environmentCount, sourceCount, revisionCount, authorityCount int64
	if err := database.QueryRow(context.Background(), `
		SELECT
			(SELECT count(*) FROM tenants WHERE id=$1),
			(SELECT count(*) FROM workspaces WHERE tenant_id=$1),
			(SELECT count(*) FROM environments WHERE tenant_id=$1),
			(SELECT count(*) FROM asset_sources WHERE id=$2),
			(SELECT count(*) FROM asset_source_revisions WHERE id=$3),
			(SELECT count(*) FROM asset_source_revision_authorities WHERE source_id=$2)
	`, candidate.tenantID, candidate.sourceID, candidate.revisionID).Scan(
		&tenantCount, &workspaceCount, &environmentCount, &sourceCount, &revisionCount, &authorityCount,
	); err != nil {
		t.Fatalf("inspect corrective matrix rollback: %v", err)
	}
	if tenantCount != 0 || workspaceCount != 0 || environmentCount != 0 ||
		sourceCount != 0 || revisionCount != 0 || authorityCount != 0 {
		t.Fatalf("rejected corrective matrix transaction persisted rows tenant=%d workspace=%d environment=%d source=%d revision=%d authority=%d",
			tenantCount, workspaceCount, environmentCount, sourceCount, revisionCount, authorityCount)
	}
}

func requireCorrectiveMatrixCandidateCommit(
	t *testing.T,
	database *pgxpool.Pool,
	candidate correctiveMatrixCandidate,
) correctiveMatrixDigests {
	t.Helper()
	digests, err := commitCorrectiveMatrixCandidate(t, database, candidate)
	if err != nil {
		var databaseError *pgconn.PgError
		if errors.As(err, &databaseError) {
			t.Fatalf("commit corrective matrix candidate: SQLSTATE %s constraint %s: %s",
				databaseError.Code, databaseError.ConstraintName, databaseError.Message)
		}
		t.Fatalf("commit corrective matrix candidate: %v", err)
	}
	assertCorrectiveMatrixPersistedClosure(t, database, candidate, digests)
	return digests
}

func assertCorrectiveMatrixPersistedClosure(
	t *testing.T,
	database *pgxpool.Pool,
	candidate correctiveMatrixCandidate,
	digests correctiveMatrixDigests,
) {
	t.Helper()
	var profile []byte
	var profileDigest, providerDigest, authorityDigest, definitionDigest, bindingDigest, recomputedBinding string
	var credentialReference, trustReference, networkReference, typedCode, preparedDigest *string
	if err := database.QueryRow(context.Background(), `
		SELECT canonical_profile_manifest,profile_manifest_sha256,canonical_provider_schema_sha256,
			authority_scope_digest,source_definition_digest,canonical_revision_digest,
			public.asset_catalog_source_revision_binding_digest(candidate_revision),
			credential_reference_id,trust_reference_id,network_policy_reference_id,
			typed_extension_code,prepared_extension_digest
		FROM public.asset_source_revisions AS candidate_revision
		WHERE candidate_revision.id=$1
	`, candidate.revisionID).Scan(
		&profile, &profileDigest, &providerDigest, &authorityDigest, &definitionDigest,
		&bindingDigest, &recomputedBinding, &credentialReference, &trustReference,
		&networkReference, &typedCode, &preparedDigest,
	); err != nil {
		t.Fatalf("read persisted corrective matrix closure: %v", err)
	}
	if string(profile) != string(candidate.profileManifest) || profileDigest != digests.profileManifest ||
		providerDigest != digests.providerSchema || authorityDigest != digests.authority ||
		definitionDigest != digests.definition || bindingDigest != digests.binding ||
		recomputedBinding != digests.binding ||
		!correctiveMatrixOptionalStringEqual(credentialReference, candidate.credentialReference) ||
		!correctiveMatrixOptionalStringEqual(trustReference, candidate.trustReference) ||
		!correctiveMatrixOptionalStringEqual(networkReference, candidate.networkReference) ||
		!correctiveMatrixOptionalStringEqual(typedCode, candidate.typedExtensionCode) ||
		!correctiveMatrixOptionalStringEqual(preparedDigest, candidate.preparedExtensionDigest) {
		t.Fatalf("persisted corrective matrix closure drifted for source %s", candidate.sourceID)
	}
	var environmentIDs []string
	var ordinals []int32
	if err := database.QueryRow(context.Background(), `
		SELECT pg_catalog.array_agg(environment_id::text ORDER BY canonical_ordinal),
			pg_catalog.array_agg(canonical_ordinal ORDER BY canonical_ordinal)
		FROM public.asset_source_revision_authorities
		WHERE tenant_id=$1 AND workspace_id=$2 AND source_id=$3 AND source_revision=1
	`, candidate.tenantID, candidate.workspaceID, candidate.sourceID).Scan(&environmentIDs, &ordinals); err != nil {
		t.Fatalf("read persisted corrective matrix authorities: %v", err)
	}
	expectedAuthorities := append([]correctiveMatrixAuthority(nil), candidate.authorities...)
	sort.Slice(expectedAuthorities, func(left, right int) bool {
		return expectedAuthorities[left].ordinal < expectedAuthorities[right].ordinal
	})
	var expectedEnvironmentIDs []string
	var expectedOrdinals []int32
	for _, authority := range expectedAuthorities {
		expectedEnvironmentIDs = append(expectedEnvironmentIDs, authority.environmentID)
		expectedOrdinals = append(expectedOrdinals, authority.ordinal)
	}
	if strings.Join(environmentIDs, "\n") != strings.Join(expectedEnvironmentIDs, "\n") ||
		fmt.Sprint(ordinals) != fmt.Sprint(expectedOrdinals) {
		t.Fatalf("persisted corrective matrix authorities ids=%v ordinals=%v, want ids=%v ordinals=%v",
			environmentIDs, ordinals, expectedEnvironmentIDs, expectedOrdinals)
	}
}

func correctiveMatrixOptionalStringEqual(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func requireCorrectiveMatrixConstraintName(
	t *testing.T,
	database *pgxpool.Pool,
	tableName string,
	constraintType string,
	columns []string,
) string {
	t.Helper()
	rows, err := database.Query(context.Background(), `
		SELECT constraint_record.conname
		FROM pg_catalog.pg_constraint AS constraint_record
		JOIN pg_catalog.pg_class AS relation ON relation.oid=constraint_record.conrelid
		JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=relation.relnamespace
		WHERE namespace.nspname='public'
		  AND relation.relname=$1
		  AND constraint_record.contype::text=$2
		  AND ARRAY(
			SELECT attribute.attname
			FROM pg_catalog.unnest(constraint_record.conkey) WITH ORDINALITY AS key_column(attnum,ordinality)
			JOIN pg_catalog.pg_attribute AS attribute
			  ON attribute.attrelid=constraint_record.conrelid
			 AND attribute.attnum=key_column.attnum
			ORDER BY key_column.ordinality
		  )::text[]=$3::text[]
		ORDER BY constraint_record.conname COLLATE "C"
	`, tableName, constraintType, columns)
	if err != nil {
		t.Fatalf("resolve corrective matrix constraint on %s%v: %v", tableName, columns, err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan corrective matrix constraint on %s%v: %v", tableName, columns, err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate corrective matrix constraint on %s%v: %v", tableName, columns, err)
	}
	if len(names) != 1 {
		t.Fatalf("constraint resolution on %s type=%s columns=%v returned %v, want exactly one",
			tableName, constraintType, columns, names)
	}
	return names[0]
}

func setCorrectiveMatrixInitialFutureHook(t *testing.T, harness *assetCatalogHarness, admit bool) {
	t.Helper()
	body := `BEGIN
    RETURN false;
END;`
	if admit {
		body = `BEGIN
    RETURN candidate.source_kind IN ('KUBERNETES_OPERATOR', 'AWX_INVENTORY')
       AND candidate.gate_status = 'UNAVAILABLE'
       AND candidate.gate_revision = 0
       AND candidate.version = 2
       AND candidate.published_revision IS NULL
       AND candidate.validated_run_id IS NULL
       AND candidate.checkpoint_revision = 0
       AND candidate.checkpoint_version = 0;
END;`
	}
	ddl := `CREATE OR REPLACE FUNCTION public.asset_catalog_future_source_gate_admitted(candidate public.asset_sources)
RETURNS boolean AS $function$
` + body + `
$function$ LANGUAGE plpgsql STABLE SECURITY INVOKER
SET search_path = pg_catalog, public, pg_temp`
	connection, err := harness.migration.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire corrective matrix migration connection: %v", err)
	}
	defer connection.Release()
	assertAssetCatalogConnectionIdentity(t, connection, "aiops_migrator")
	transaction, err := connection.BeginTx(context.Background(), pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin corrective matrix hook transaction: %v", err)
	}
	defer func() { _ = transaction.Rollback(context.Background()) }()
	if _, err := transaction.Exec(context.Background(), `SET LOCAL ROLE aiops_schema_owner`); err != nil {
		t.Fatalf("set corrective matrix hook owner role: %v", err)
	}
	var sessionUser, currentUser string
	if err := transaction.QueryRow(context.Background(), `SELECT session_user,current_user`).Scan(&sessionUser, &currentUser); err != nil {
		t.Fatalf("read corrective matrix hook migration identity: %v", err)
	}
	if sessionUser != "aiops_migrator" || currentUser != "aiops_schema_owner" {
		t.Fatalf("corrective matrix hook identity=session:%q current:%q, want migrator/schema owner", sessionUser, currentUser)
	}
	if _, err := transaction.Exec(context.Background(), ddl); err != nil {
		t.Fatalf("replace corrective matrix future hook: %v", err)
	}
	if _, err := transaction.Exec(context.Background(), `RESET ROLE`); err != nil {
		t.Fatalf("reset corrective matrix hook owner role: %v", err)
	}
	if err := transaction.QueryRow(context.Background(), `SELECT session_user,current_user`).Scan(&sessionUser, &currentUser); err != nil {
		t.Fatalf("read reset corrective matrix hook migration identity: %v", err)
	}
	if sessionUser != "aiops_migrator" || currentUser != "aiops_migrator" {
		t.Fatalf("reset corrective matrix hook identity=session:%q current:%q, want migrator", sessionUser, currentUser)
	}
	if err := transaction.Commit(context.Background()); err != nil {
		t.Fatalf("commit corrective matrix future hook: %v", err)
	}
}

func TestAssetCatalogMigrationCompatibility(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyUpThrough(t, "000014_read_evidence_clock_skew.up.sql")
	admission := assetpostgres.NewSchemaAdmission(harness.application, "public")
	if err := admission.Check(context.Background()); !errors.Is(err, assetpostgres.ErrAssetCatalogUnavailable) {
		t.Fatalf("pre-000015 admission error=%v", err)
	}
	harness.applyMigration(t, "000015_assets_catalog.up.sql")
	if err := admission.Check(context.Background()); err != nil {
		t.Fatalf("post-000015 admission: %v", err)
	}
}

func TestAssetCatalogMigrationEmptyRollback(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	harness.applyMigration(t, "000015_assets_catalog.down.sql")
}

func TestAssetCatalogMigrationEmptyRollbackRestoresPredecessorCatalog(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyUpThrough(t, "000014_read_evidence_clock_skew.up.sql")
	before := assetCatalogPredecessorFingerprint(t, harness.db)
	harness.applyMigration(t, "000015_assets_catalog.up.sql")
	harness.applyMigration(t, "000015_assets_catalog.down.sql")
	after := assetCatalogPredecessorFingerprint(t, harness.db)
	if after != before {
		t.Fatalf("000015 empty rollback predecessor fingerprint=%s, want %s", after, before)
	}
}

func assetCatalogPredecessorFingerprint(t *testing.T, database *pgxpool.Pool) string {
	t.Helper()
	transaction, err := database.BeginTx(context.Background(), pgx.TxOptions{
		IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		t.Fatalf("begin 000015 predecessor catalog fingerprint: %v", err)
	}
	defer func() { _ = transaction.Rollback(context.Background()) }()
	if _, err := transaction.Exec(context.Background(), `SET LOCAL quote_all_identifiers = off`); err != nil {
		t.Fatalf("pin predecessor catalog identifier deparse: %v", err)
	}
	if _, err := transaction.Exec(context.Background(), `SET LOCAL search_path = pg_catalog, pg_temp`); err != nil {
		t.Fatalf("pin predecessor catalog search path: %v", err)
	}
	var fingerprint string
	if err := transaction.QueryRow(context.Background(), `
		WITH trusted_namespace AS MATERIALIZED (
			SELECT namespace.oid, namespace.nspname, namespace.nspowner AS owner_oid,
				COALESCE(namespace.nspacl, pg_catalog.acldefault('n', namespace.nspowner)) AS acl
			FROM pg_catalog.pg_namespace AS namespace
			WHERE namespace.nspname='public'
		),
		relation_names(name) AS (
			SELECT pg_catalog.unnest($1::text[])
		),
		relations AS MATERIALIZED (
			SELECT relation.oid, relation.relname, relation.relowner AS owner_oid,
				COALESCE(relation.relacl, pg_catalog.acldefault('r', relation.relowner)) AS acl,
				relation.relkind, relation.relpersistence, relation.reloptions,
				relation.relrowsecurity, relation.relforcerowsecurity, relation.relreplident
			FROM pg_catalog.pg_class AS relation
			JOIN trusted_namespace AS namespace ON namespace.oid=relation.relnamespace
			JOIN relation_names AS expected ON expected.name=relation.relname
		),
		authorization_objects AS MATERIALIZED (
			SELECT 'schema'::text AS object_kind, namespace.nspname AS object_name,
				namespace.owner_oid, namespace.acl
			FROM trusted_namespace AS namespace
			UNION ALL
			SELECT 'relation', relation.relname, relation.owner_oid, relation.acl
			FROM relations AS relation
			UNION ALL
			SELECT 'column', relation.relname || '.' || attribute.attname,
				relation.owner_oid,
				COALESCE(attribute.attacl, pg_catalog.acldefault('c', relation.owner_oid))
			FROM relations AS relation
			JOIN pg_catalog.pg_attribute AS attribute
			  ON attribute.attrelid=relation.oid
			 AND attribute.attnum > 0
			 AND NOT attribute.attisdropped
		),
		owner_records AS (
			SELECT object_record.object_kind || pg_catalog.chr(31) || object_record.object_name ||
				pg_catalog.chr(31) || pg_catalog.pg_get_userbyid(object_record.owner_oid) AS payload
			FROM authorization_objects AS object_record
			WHERE object_record.object_kind <> 'column'
		),
		acl_records AS (
			SELECT object_record.object_kind || pg_catalog.chr(31) || object_record.object_name ||
				pg_catalog.chr(31) ||
				CASE WHEN entry.grantee=0::oid THEN 'PUBLIC'
					ELSE pg_catalog.pg_get_userbyid(entry.grantee) END ||
				pg_catalog.chr(31) || pg_catalog.pg_get_userbyid(entry.grantor) ||
				pg_catalog.chr(31) || entry.privilege_type || pg_catalog.chr(31) ||
				entry.is_grantable::text || pg_catalog.chr(31) || pg_catalog.count(*)::text AS payload
			FROM authorization_objects AS object_record
			CROSS JOIN LATERAL pg_catalog.aclexplode(object_record.acl) AS entry
			GROUP BY object_record.object_kind, object_record.object_name,
				entry.grantee, entry.grantor, entry.privilege_type, entry.is_grantable
		),
		surface_records AS (
			SELECT pg_catalog.jsonb_build_array(
				'relation-surface',
				table_record.relname,
				table_record.relkind::text,
				table_record.relpersistence::text,
				table_record.reloptions,
				table_record.relrowsecurity,
				table_record.relforcerowsecurity,
				table_record.relreplident::text
			)::text AS payload
			FROM relations AS table_record
			WHERE table_record.relname IN ('audit_records','outbox_events')
			UNION ALL
			SELECT pg_catalog.jsonb_build_array(
				'index-surface',
				table_record.relname,
				index_record.relname,
				index_metadata.indisunique,
				index_metadata.indisprimary,
				index_metadata.indisexclusion,
				index_metadata.indimmediate,
				index_metadata.indisvalid,
				index_metadata.indisready,
				index_metadata.indislive,
				index_metadata.indisreplident,
				index_metadata.indnullsnotdistinct,
				index_record.reloptions,
				pg_catalog.pg_get_expr(index_metadata.indexprs, index_metadata.indrelid, false),
				pg_catalog.pg_get_expr(index_metadata.indpred, index_metadata.indrelid, false),
				pg_catalog.pg_get_indexdef(index_record.oid, 0, false)
			)::text
			FROM relations AS table_record
			JOIN pg_catalog.pg_index AS index_metadata ON index_metadata.indrelid=table_record.oid
			JOIN pg_catalog.pg_class AS index_record ON index_record.oid=index_metadata.indexrelid
			WHERE table_record.relname IN ('audit_records','outbox_events')
			UNION ALL
			SELECT pg_catalog.jsonb_build_array(
				'trigger-surface',
				table_record.relname,
				trigger_record.tgname,
				trigger_record.tgenabled::text,
				trigger_record.tgisinternal,
				trigger_record.tgtype,
				trigger_record.tgdeferrable,
				trigger_record.tginitdeferred,
				trigger_record.tgattr::text,
				pg_catalog.encode(trigger_record.tgargs, 'hex'),
				pg_catalog.pg_get_expr(trigger_record.tgqual, trigger_record.tgrelid, false),
				pg_catalog.pg_get_triggerdef(trigger_record.oid, false)
			)::text
			FROM relations AS table_record
			JOIN pg_catalog.pg_trigger AS trigger_record ON trigger_record.tgrelid=table_record.oid
			WHERE table_record.relname IN ('audit_records','outbox_events')
			UNION ALL
			SELECT pg_catalog.jsonb_build_array(
				'relation-comment',
				table_record.relname,
				description.objsubid,
				attribute.attname,
				description.description
			)::text
			FROM relations AS table_record
			JOIN pg_catalog.pg_description AS description
			  ON description.classoid='pg_catalog.pg_class'::pg_catalog.regclass
			 AND description.objoid=table_record.oid
			LEFT JOIN pg_catalog.pg_attribute AS attribute
			  ON attribute.attrelid=table_record.oid
			 AND attribute.attnum=description.objsubid
			WHERE table_record.relname IN ('audit_records','outbox_events')
			UNION ALL
			SELECT pg_catalog.jsonb_build_array(
				'index-comment',
				table_record.relname,
				index_record.relname,
				description.description
			)::text
			FROM relations AS table_record
			JOIN pg_catalog.pg_index AS index_metadata ON index_metadata.indrelid=table_record.oid
			JOIN pg_catalog.pg_class AS index_record ON index_record.oid=index_metadata.indexrelid
			JOIN pg_catalog.pg_description AS description
			  ON description.classoid='pg_catalog.pg_class'::pg_catalog.regclass
			 AND description.objoid=index_record.oid
			 AND description.objsubid=0
			WHERE table_record.relname IN ('audit_records','outbox_events')
			UNION ALL
			SELECT pg_catalog.jsonb_build_array(
				'trigger-comment',
				table_record.relname,
				trigger_record.tgname,
				description.description
			)::text
			FROM relations AS table_record
			JOIN pg_catalog.pg_trigger AS trigger_record ON trigger_record.tgrelid=table_record.oid
			JOIN pg_catalog.pg_description AS description
			  ON description.classoid='pg_catalog.pg_trigger'::pg_catalog.regclass
			 AND description.objoid=trigger_record.oid
			 AND description.objsubid=0
			WHERE table_record.relname IN ('audit_records','outbox_events')
			UNION ALL
			SELECT pg_catalog.jsonb_build_array(
				'constraint-comment',
				table_record.relname,
				constraint_record.conname,
				description.description
			)::text
			FROM relations AS table_record
			JOIN pg_catalog.pg_constraint AS constraint_record ON constraint_record.conrelid=table_record.oid
			JOIN pg_catalog.pg_description AS description
			  ON description.classoid='pg_catalog.pg_constraint'::pg_catalog.regclass
			 AND description.objoid=constraint_record.oid
			 AND description.objsubid=0
			WHERE table_record.relname IN ('audit_records','outbox_events')
		),
		records AS (
			SELECT payload FROM owner_records
			UNION ALL SELECT payload FROM acl_records
			UNION ALL SELECT payload FROM surface_records
		)
		SELECT pg_catalog.encode(
			pg_catalog.sha256(
				pg_catalog.convert_to(
					COALESCE(
						pg_catalog.string_agg(payload, E'\n' ORDER BY payload COLLATE "C"),
						''
					),
					'UTF8'
				)
			),
			'hex'
		)
		FROM records
	`, []string{
		"workspaces", "environments", "services", "service_bindings",
		"audit_records", "outbox_events",
	}).Scan(&fingerprint); err != nil {
		t.Fatalf("fingerprint 000015 predecessor catalog: %v", err)
	}
	if err := transaction.Rollback(context.Background()); err != nil {
		t.Fatalf("rollback 000015 predecessor catalog fingerprint: %v", err)
	}
	return fingerprint
}

func TestAssetCatalogMigrationDownNowaitConflictRollsBack(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	for _, relation := range assetCatalogDownLockTableNames() {
		t.Run(relation, func(t *testing.T) {
			holder, err := harness.db.Begin(context.Background())
			if err != nil {
				t.Fatalf("begin down conflict holder: %v", err)
			}
			defer func() { _ = holder.Rollback(context.Background()) }()
			if _, err := holder.Exec(context.Background(), "LOCK TABLE "+
				pgx.Identifier{"public", relation}.Sanitize()+" IN ACCESS SHARE MODE"); err != nil {
				t.Fatalf("hold down-lock member %s: %v", relation, err)
			}

			_, downErr := harness.migration.Exec(
				context.Background(),
				readMigration(t, "000015_assets_catalog.down.sql"),
			)
			var postgresError *pgconn.PgError
			if !errors.As(downErr, &postgresError) || postgresError.Code != "55P03" {
				t.Fatalf("conflicting one-shot down error=%v, want SQLSTATE 55P03", downErr)
			}
			assertAssetCatalogOwnedTableCount(t, harness.db, 12)
			if err := assetpostgres.NewSchemaAdmission(harness.application, "public").Check(context.Background()); err != nil {
				t.Fatalf("schema admission after conflicting down rollback: %v", err)
			}

			if err := holder.Rollback(context.Background()); err != nil {
				t.Fatalf("release down conflict holder: %v", err)
			}
			harness.applyMigration(t, "000015_assets_catalog.down.sql")
			assertAssetCatalogOwnedTableCount(t, harness.db, 0)
			harness.applyMigration(t, "000015_assets_catalog.up.sql")
			if err := assetpostgres.NewSchemaAdmission(harness.application, "public").Check(context.Background()); err != nil {
				t.Fatalf("schema admission after released-lock retry: %v", err)
			}
		})
	}
}

func TestAssetCatalogMigrationDownHoldsCompleteLockSetBeforeCleanup(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)

	const advisoryKey int64 = 15000180015
	execAssetSQL(t, harness.db, `
		CREATE SCHEMA asset_catalog_test_hooks;
		CREATE FUNCTION asset_catalog_test_hooks.pause_down_after_lock()
		RETURNS event_trigger
		LANGUAGE plpgsql
		SET search_path = pg_catalog, pg_temp
		AS $function$
		BEGIN
			PERFORM pg_catalog.pg_advisory_xact_lock(15000180015::bigint);
		END
		$function$;
		CREATE EVENT TRIGGER asset_catalog_test_pause_down
		ON ddl_command_start
		EXECUTE FUNCTION asset_catalog_test_hooks.pause_down_after_lock();
	`)

	holder, err := harness.db.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire advisory-lock holder: %v", err)
	}
	defer holder.Release()
	if _, err := holder.Exec(context.Background(), `
		SELECT pg_catalog.pg_advisory_lock($1::bigint)
	`, advisoryKey); err != nil {
		t.Fatalf("hold down observation advisory lock: %v", err)
	}
	advisoryHeld := true

	downResult := make(chan error, 1)
	downPending := true
	t.Cleanup(func() {
		if advisoryHeld {
			_, _ = holder.Exec(context.Background(), `SELECT pg_catalog.pg_advisory_unlock($1::bigint)`, advisoryKey)
		}
		if downPending {
			select {
			case <-downResult:
			case <-time.After(6 * time.Second):
			}
		}
		_, _ = harness.db.Exec(context.Background(), `DROP EVENT TRIGGER IF EXISTS asset_catalog_test_pause_down`)
		_, _ = harness.db.Exec(context.Background(), `DROP FUNCTION IF EXISTS asset_catalog_test_hooks.pause_down_after_lock()`)
		_, _ = harness.db.Exec(context.Background(), `DROP SCHEMA IF EXISTS asset_catalog_test_hooks`)
	})
	downSQL := readMigration(t, "000015_assets_catalog.down.sql")
	go func() {
		_, downErr := harness.migration.Exec(
			context.Background(),
			downSQL,
		)
		downResult <- downErr
	}()

	var migrationPID int32
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		err = harness.db.QueryRow(context.Background(), `
			SELECT activity.pid
			FROM pg_catalog.pg_stat_activity AS activity
			JOIN pg_catalog.pg_locks AS waiting ON waiting.pid=activity.pid
			WHERE activity.datname=pg_catalog.current_database()
			  AND activity.usename='aiops_migrator'
			  AND waiting.locktype='advisory'
			  AND NOT waiting.granted
			ORDER BY activity.query_start DESC
			LIMIT 1
		`).Scan(&migrationPID)
		if err == nil {
			break
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("observe blocked down migration: %v", err)
		}
		select {
		case downErr := <-downResult:
			downPending = false
			t.Fatalf("down migration completed before lock observation: %v", downErr)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal("down migration did not reach the post-lock observation boundary")
	}

	var lockedRelations []string
	if err := harness.db.QueryRow(context.Background(), `
		SELECT COALESCE(pg_catalog.array_agg(relation.relname ORDER BY relation.relname), ARRAY[]::text[])
		FROM pg_catalog.pg_locks AS held
		JOIN pg_catalog.pg_class AS relation ON relation.oid=held.relation
		JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=relation.relnamespace
		WHERE held.pid=$1
		  AND held.locktype='relation'
		  AND held.mode='AccessExclusiveLock'
		  AND held.granted
		  AND namespace.nspname='public'
	`, migrationPID).Scan(&lockedRelations); err != nil {
		t.Fatalf("observe down relation locks: %v", err)
	}
	wantRelations := assetCatalogDownLockTableNames()
	sort.Strings(wantRelations)
	if strings.Join(lockedRelations, "\n") != strings.Join(wantRelations, "\n") {
		t.Fatalf("down held relations=%v, want %v", lockedRelations, wantRelations)
	}

	lateTransaction, err := harness.db.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin transaction after down acquired locks: %v", err)
	}
	_, lateErr := lateTransaction.Exec(context.Background(), `
		LOCK TABLE public.asset_sources IN ROW EXCLUSIVE MODE NOWAIT
	`)
	_ = lateTransaction.Rollback(context.Background())
	var postgresError *pgconn.PgError
	if !errors.As(lateErr, &postgresError) || postgresError.Code != "55P03" {
		t.Fatalf("post-lock transaction error=%v, want SQLSTATE 55P03", lateErr)
	}

	var unlocked bool
	if err := holder.QueryRow(context.Background(), `
		SELECT pg_catalog.pg_advisory_unlock($1::bigint)
	`, advisoryKey).Scan(&unlocked); err != nil || !unlocked {
		t.Fatalf("release down observation advisory lock: unlocked=%v error=%v", unlocked, err)
	}
	advisoryHeld = false
	select {
	case downErr := <-downResult:
		downPending = false
		if downErr != nil {
			t.Fatalf("complete observed down migration: %v", downErr)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("observed down migration did not complete after advisory release")
	}

	execAssetSQL(t, harness.db, `
		DROP EVENT TRIGGER asset_catalog_test_pause_down;
		DROP FUNCTION asset_catalog_test_hooks.pause_down_after_lock();
		DROP SCHEMA asset_catalog_test_hooks;
	`)
	assertAssetCatalogOwnedTableCount(t, harness.db, 0)
}

func assertAssetCatalogOwnedTableCount(t *testing.T, database *pgxpool.Pool, expected int) {
	t.Helper()
	var tableCount int
	if err := database.QueryRow(context.Background(), `
		SELECT count(*)
		FROM pg_catalog.pg_class AS relation
		JOIN pg_catalog.pg_namespace AS namespace
		  ON namespace.oid=relation.relnamespace
		WHERE namespace.nspname='public'
		  AND relation.relkind IN ('r','p')
		  AND relation.relname=ANY($1)
	`, assetCatalogTableNames()).Scan(&tableCount); err != nil {
		t.Fatalf("count catalog tables: %v", err)
	}
	if tableCount != expected {
		t.Fatalf("catalog table count=%d, want %d", tableCount, expected)
	}
}

func TestAssetCatalogMigrationCoreInvariants(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	expectAssetSQLState(t, harness.db, "55000", `UPDATE asset_observations SET source_revision=source_revision+1 WHERE id=$1`, fixture.observationID)
	expectAssetSQLState(t, harness.db, "55000", `DELETE FROM asset_type_details WHERE id=$1`, fixture.typeDetailID)
	expectAssetSQLState(t, harness.db, "55000", `UPDATE asset_source_revision_authorities SET canonical_ordinal=canonical_ordinal WHERE source_id=$1`, fixture.sourceID)
	expectAssetSQLState(t, harness.db, "55000", `UPDATE asset_source_revisions SET profile_code=profile_code WHERE id=$1`, fixture.revisionID)
	expectAssetSQLState(t, harness.db, "23514", `UPDATE assets SET lifecycle='STALE',version=version+1 WHERE id=$1`, fixture.assetID)
	execAssetSQL(t, harness.db, `UPDATE assets SET lifecycle='ACTIVE',version=version+1 WHERE id=$1`, fixture.assetID)
	execAssetSQL(t, harness.db, `UPDATE assets SET lifecycle='RETIRED',version=version+1 WHERE id=$1`, fixture.assetID)
	expectAssetSQLState(t, harness.db, "55000", `UPDATE assets SET lifecycle='ACTIVE',version=version+1 WHERE id=$1`, fixture.assetID)
	expectAssetSQLState(t, harness.db, "55000", readMigration(t, "000015_assets_catalog.down.sql"))
}

func TestAssetCatalogHarnessRejectsUnsafeControlDatabaseName(t *testing.T) {
	for _, name := range []string{
		"postgres", "template1", "production", "aiops", "contest", "latest", "production_test",
		"test_control_01", "aiops_testcontrol", "aiops_test_", "aiops_test_control-01",
	} {
		if assetCatalogControlDatabaseNameSafe(name) {
			t.Errorf("unsafe control database name accepted: %s", name)
		}
	}
	for _, name := range []string{"aiops_test", "aiops_test_control", "aiops_test_control_01"} {
		if !assetCatalogControlDatabaseNameSafe(name) {
			t.Errorf("safe test control database name rejected: %s", name)
		}
	}
}

func assetCatalogControlDatabaseNameSafe(name string) bool {
	return safeAssetCatalogControlDatabase.MatchString(name)
}

func assetCatalogTableNames() []string {
	return []string{"asset_sources", "asset_source_revisions", "asset_source_revision_authorities", "asset_source_runs",
		"asset_source_limit_buckets", "asset_source_limit_permits", "asset_observations", "assets",
		"asset_type_details", "asset_conflicts", "asset_relationships", "service_asset_bindings"}
}

func assetCatalogDownLockTableNames() []string {
	return append([]string{
		"tenants", "workspaces", "environments", "integrations", "services", "service_bindings",
		"audit_records", "outbox_events",
	}, assetCatalogTableNames()...)
}

func assetCatalogFixtureSummary(fixture assetCatalogFixture) string {
	return fmt.Sprintf("source=%s run=%s asset=%s", fixture.sourceID, fixture.runID, fixture.assetID)
}
