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
	`, []string{"asset_sources", "asset_source_revisions", "asset_source_revision_authorities", "asset_source_runs", "asset_observations", "assets",
		"asset_type_details", "asset_conflicts", "asset_relationships", "service_asset_bindings"}).Scan(&tableCount); err != nil {
		t.Fatal(err)
	}
	if tableCount != 10 {
		t.Fatalf("asset catalog table count=%d, want 10", tableCount)
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
			assertAssetCatalogOwnedTableCount(t, harness.db, 10)
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
	return []string{"asset_sources", "asset_source_revisions", "asset_source_revision_authorities", "asset_source_runs", "asset_observations", "assets",
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
