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
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type assetCatalogHarness struct {
	admin  *pgxpool.Pool
	db     *pgxpool.Pool
	schema string
}

func newAssetCatalogHarness(t *testing.T) *assetCatalogHarness {
	t.Helper()
	dsn := os.Getenv("AIOPS_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("AIOPS_TEST_POSTGRES_DSN is not configured; real PostgreSQL 18.4 migration tests were not run")
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

	schema := "aiops_assets_" + randomAssetHex(t, 8)
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
	if config.MaxConns < 12 {
		config.MaxConns = 12
	}
	database, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatalf("connect isolated PostgreSQL schema: %v", err)
	}
	harness := &assetCatalogHarness{admin: admin, db: database, schema: schema}
	t.Cleanup(func() {
		database.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
	})
	return harness
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
	files := make([]string, 0, 15)
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".up.sql") && entry.Name() <= cutoff {
			files = append(files, entry.Name())
		}
	}
	sort.Strings(files)
	wantCount := 15
	if cutoff == "000014_read_evidence_clock_skew.up.sql" {
		wantCount = 14
	}
	if len(files) != wantCount {
		t.Fatalf("migration set through %s has %d files, want %d", cutoff, len(files), wantCount)
	}
	for _, name := range files {
		if _, err := h.db.Exec(context.Background(), readMigration(t, name)); err != nil {
			t.Fatalf("apply migration %s: %v", name, err)
		}
	}
}

type assetCatalogFixture struct {
	tenantID       string
	workspaceID    string
	environmentID  string
	integrationID  string
	serviceID      string
	sourceID       string
	revisionID     string
	runID          string
	observationID  string
	assetID        string
	secondAssetID  string
	typeDetailID   string
	conflictID     string
	relationshipID string
	bindingID      string
	revisionDigest string
}

func seedRepresentativeAssetCatalog(t *testing.T, database *pgxpool.Pool) assetCatalogFixture {
	t.Helper()
	fixture := assetCatalogFixture{
		tenantID:       "10000000-0000-4000-8000-000000000201",
		workspaceID:    "20000000-0000-4000-8000-000000000201",
		environmentID:  "30000000-0000-4000-8000-000000000201",
		integrationID:  "40000000-0000-4000-8000-000000000201",
		serviceID:      "50000000-0000-4000-8000-000000000201",
		sourceID:       "60000000-0000-4000-8000-000000000201",
		revisionID:     "61000000-0000-4000-8000-000000000201",
		runID:          "62000000-0000-4000-8000-000000000201",
		observationID:  "63000000-0000-4000-8000-000000000201",
		assetID:        "64000000-0000-4000-8000-000000000201",
		secondAssetID:  "64000000-0000-4000-8000-000000000202",
		typeDetailID:   "65000000-0000-4000-8000-000000000201",
		conflictID:     "66000000-0000-4000-8000-000000000201",
		relationshipID: "67000000-0000-4000-8000-000000000201",
		bindingID:      "68000000-0000-4000-8000-000000000201",
		revisionDigest: strings.Repeat("d", 64),
	}
	execAssetSQL(t, database, `INSERT INTO tenants (id,name) VALUES ($1,'fixture-tenant')`, fixture.tenantID)
	execAssetSQL(t, database, `INSERT INTO workspaces (id,tenant_id,name) VALUES ($1,$2,'fixture-workspace')`, fixture.workspaceID, fixture.tenantID)
	execAssetSQL(t, database, `
		INSERT INTO environments (id,tenant_id,workspace_id,name,kind)
		VALUES ($1,$2,$3,'fixture-production','PROD')
	`, fixture.environmentID, fixture.tenantID, fixture.workspaceID)
	execAssetSQL(t, database, `
		INSERT INTO integrations (id,tenant_id,workspace_id,provider,name,secret_ref,config)
		VALUES ($1,$2,$3,'manual','fixture-integration','opaque://sanitized','{"future":"preserve"}')
	`, fixture.integrationID, fixture.tenantID, fixture.workspaceID)
	execAssetSQL(t, database, `
		INSERT INTO services (id,tenant_id,workspace_id,name,owner_group,labels)
		VALUES ($1,$2,$3,'fixture-service','fixture-sre','{"future":"preserve"}')
	`, fixture.serviceID, fixture.tenantID, fixture.workspaceID)
	execAssetSQL(t, database, `
		INSERT INTO asset_sources (
			id,tenant_id,workspace_id,source_kind,provider_kind,name,
			create_idempotency_key,create_request_hash
		) VALUES ($1,$2,$3,'MANUAL','MANUAL','fixture-source','fixture-source-create',repeat('a',64))
	`, fixture.sourceID, fixture.tenantID, fixture.workspaceID)
	canonicalSchema := []byte(`{"type":"object"}`)
	execAssetSQL(t, database, `
		INSERT INTO asset_source_revisions (
			id,tenant_id,workspace_id,source_id,revision,state,
			canonical_provider_schema,canonical_provider_schema_sha256,integration_id,sync_mode,
			authority_scope_digest,source_definition_digest,canonical_revision_digest,
			credential_reference_id,trust_reference_id,network_policy_reference_id,
			rate_limit_requests,rate_limit_window_seconds,backpressure_base_seconds,
			backpressure_max_seconds,profile_code,created_by,change_reason_code,expected_source_version
		) VALUES (
			$1,$2,$3,$4,1,'DRAFT',$5,encode(sha256($5),'hex'),$6,'MANUAL',
			repeat('b',64),repeat('c',64),$7,'credential-ref-1','trust-ref-1','network-policy-ref-1',
			100,60,1,60,'manual-v1','fixture-human','INITIAL_CREATE',1
		)
	`, fixture.revisionID, fixture.tenantID, fixture.workspaceID, fixture.sourceID, canonicalSchema, fixture.integrationID, fixture.revisionDigest)
	execAssetSQL(t, database, `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,status,trigger_type,definition_revision,gate_revision,idempotency_key,
			request_hash,completed_at
		) VALUES ($1,$2,$3,$4,1,$5,'DISCOVERY','SUCCEEDED','HUMAN',1,0,
			'fixture-run',repeat('e',64),statement_timestamp())
	`, fixture.runID, fixture.tenantID, fixture.workspaceID, fixture.sourceID, fixture.revisionDigest)
	provenance := []byte(fmt.Sprintf(
		`{"display_name":{"source_id":"%s","provider_kind":"MANUAL","source_revision":"1","observed_at":"2026-07-13T00:00:00Z","confidence":"HIGH","ownership":"SOURCE"}}`,
		fixture.sourceID,
	))
	insertObservation := func(id, externalID, display string) {
		execAssetSQL(t, database, `
			INSERT INTO asset_observations (
				id,tenant_id,workspace_id,environment_id,source_id,run_id,provider_kind,
				external_id,source_revision,observed_at,schema_version,normalized_document,
				document_sha256,field_provenance,field_provenance_sha256
			) VALUES ($1,$2,$3,$4,$5,$6,'MANUAL',$7,1,'2026-07-13T00:00:00Z','asset.v1',
				convert_to($8,'UTF8'),encode(sha256(convert_to($8,'UTF8')),'hex'),
				$9,encode(sha256($9),'hex'))
		`, id, fixture.tenantID, fixture.workspaceID, fixture.environmentID, fixture.sourceID,
			fixture.runID, externalID, fmt.Sprintf(`{"display_name":%q}`, display), provenance)
	}
	insertObservation(fixture.observationID, "fixture-external-1", "fixture-one")
	secondObservationID := "63000000-0000-4000-8000-000000000202"
	insertObservation(secondObservationID, "fixture-external-2", "fixture-two")
	insertAsset := func(id, observationID, externalID, display, key string) {
		execAssetSQL(t, database, `
			INSERT INTO assets (
				id,tenant_id,workspace_id,environment_id,source_id,provider_kind,external_id,
				kind,display_name,owner_group,criticality,classification,labels,lifecycle,
				mapping_status,last_observation_id,last_observed_at,last_source_revision,
				create_idempotency_key,create_request_hash
			) VALUES ($1,$2,$3,$4,$5,'MANUAL',$6,'HOST',$7,'fixture-sre','HIGH',
				'INTERNAL','{"safe":"label"}','DISCOVERED','EXACT',$8,
				'2026-07-13T00:00:00Z',1,$9,repeat('f',64))
		`, id, fixture.tenantID, fixture.workspaceID, fixture.environmentID, fixture.sourceID,
			externalID, display, observationID, key)
	}
	insertAsset(fixture.assetID, fixture.observationID, "fixture-external-1", "fixture-one", "fixture-asset-create-1")
	insertAsset(fixture.secondAssetID, secondObservationID, "fixture-external-2", "fixture-two", "fixture-asset-create-2")
	execAssetSQL(t, database, `
		INSERT INTO asset_type_details (
			id,tenant_id,workspace_id,environment_id,asset_id,revision,schema_version,
			source_observation_id,details_document,details_sha256,actor_id
		) VALUES ($1,$2,$3,$4,$5,1,'host.v1',$6,convert_to('{"cpu_count":4}','UTF8'),
			encode(sha256(convert_to('{"cpu_count":4}','UTF8')),'hex'),'fixture-human')
	`, fixture.typeDetailID, fixture.tenantID, fixture.workspaceID, fixture.environmentID, fixture.assetID, fixture.observationID)
	execAssetSQL(t, database, `
		INSERT INTO asset_conflicts (
			id,tenant_id,workspace_id,environment_id,asset_id,candidate_asset_id,source_id,
			observation_id,conflict_type,status
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'DUPLICATE_CANDIDATE','OPEN')
	`, fixture.conflictID, fixture.tenantID, fixture.workspaceID, fixture.environmentID,
		fixture.assetID, fixture.secondAssetID, fixture.sourceID, fixture.observationID)
	execAssetSQL(t, database, `
		INSERT INTO asset_relationships (
			id,tenant_id,workspace_id,source_environment_id,target_environment_id,
			source_asset_id,target_asset_id,relationship_type,provenance,provenance_source_id,
			status,idempotency_key,request_hash
		) VALUES ($1,$2,$3,$4,$4,$5,$6,'DEPENDS_ON','DISCOVERED',$7,'ACTIVE',
			'fixture-relationship',repeat('1',64))
	`, fixture.relationshipID, fixture.tenantID, fixture.workspaceID, fixture.environmentID,
		fixture.assetID, fixture.secondAssetID, fixture.sourceID)
	execAssetSQL(t, database, `
		INSERT INTO service_asset_bindings (
			id,tenant_id,workspace_id,environment_id,service_id,asset_id,binding_role,
			mapping_status,provenance,provenance_source_id,status,idempotency_key,request_hash
		) VALUES ($1,$2,$3,$4,$5,$6,'PRIMARY_RUNTIME','EXACT','DISCOVERED',$7,'ACTIVE',
			'fixture-binding',repeat('2',64))
	`, fixture.bindingID, fixture.tenantID, fixture.workspaceID, fixture.environmentID,
		fixture.serviceID, fixture.assetID, fixture.sourceID)
	return fixture
}

func migrationDirectory(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve asset catalog migration directory")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "../../../migrations"))
}

func randomAssetHex(t *testing.T, size int) string {
	t.Helper()
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		t.Fatalf("generate isolated schema name: %v", err)
	}
	return hex.EncodeToString(value)
}

func expectAssetSQLState(t *testing.T, database *pgxpool.Pool, state, query string, arguments ...any) {
	t.Helper()
	_, err := database.Exec(context.Background(), query, arguments...)
	if err == nil {
		t.Fatalf("SQL unexpectedly succeeded; want SQLSTATE %s", state)
	}
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != state {
		t.Fatalf("SQL error = %v, want SQLSTATE %s", err, state)
	}
}

func execAssetSQL(t *testing.T, database *pgxpool.Pool, query string, arguments ...any) {
	t.Helper()
	if _, err := database.Exec(context.Background(), query, arguments...); err != nil {
		t.Fatalf("exec asset catalog fixture: %v", err)
	}
}

func TestAssetCatalogMigration(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	database := harness.db

	const (
		tenant1      = "10000000-0000-4000-8000-000000000101"
		tenant2      = "10000000-0000-4000-8000-000000000102"
		workspace1   = "20000000-0000-4000-8000-000000000101"
		workspace2   = "20000000-0000-4000-8000-000000000102"
		environment1 = "30000000-0000-4000-8000-000000000101"
		environment2 = "30000000-0000-4000-8000-000000000102"
		integration1 = "40000000-0000-4000-8000-000000000101"
		service1     = "50000000-0000-4000-8000-000000000101"
	)
	execAssetSQL(t, database, `INSERT INTO tenants (id, name) VALUES ($1, 'tenant-one'), ($2, 'tenant-two')`, tenant1, tenant2)
	execAssetSQL(t, database, `
		INSERT INTO workspaces (id, tenant_id, name)
		VALUES ($1, $2, 'workspace-one'), ($3, $4, 'workspace-two')
	`, workspace1, tenant1, workspace2, tenant2)
	execAssetSQL(t, database, `
		INSERT INTO environments (id, tenant_id, workspace_id, name, kind)
		VALUES ($1, $2, $3, 'production', 'PROD'), ($4, $5, $6, 'production', 'PROD')
	`, environment1, tenant1, workspace1, environment2, tenant2, workspace2)
	execAssetSQL(t, database, `
		INSERT INTO integrations (id, tenant_id, workspace_id, provider, name, secret_ref, config)
		VALUES ($1, $2, $3, 'manual', 'manual-source', 'opaque://fixture', '{"unknown":{"preserved":true}}')
	`, integration1, tenant1, workspace1)
	execAssetSQL(t, database, `
		INSERT INTO services (id, tenant_id, workspace_id, name, owner_group, labels)
		VALUES ($1, $2, $3, 'checkout', 'checkout-sre', '{"unknown":"preserved"}')
	`, service1, tenant1, workspace1)

	var integrationConfig, serviceLabels string
	if err := database.QueryRow(context.Background(), `SELECT config::text FROM integrations WHERE id=$1`, integration1).Scan(&integrationConfig); err != nil {
		t.Fatalf("read legacy integration JSON: %v", err)
	}
	if err := database.QueryRow(context.Background(), `SELECT labels::text FROM services WHERE id=$1`, service1).Scan(&serviceLabels); err != nil {
		t.Fatalf("read legacy service JSON: %v", err)
	}
	if integrationConfig != `{"unknown": {"preserved": true}}` || serviceLabels != `{"unknown": "preserved"}` {
		t.Fatalf("000015 changed unknown legacy JSON: integration=%s service=%s", integrationConfig, serviceLabels)
	}

	expectAssetSQLState(t, database, "23503", `
		INSERT INTO asset_sources (
			id, tenant_id, workspace_id, source_kind, provider_kind, name,
			create_idempotency_key, create_request_hash
		) VALUES ($1, $2, $3, 'MANUAL', 'MANUAL', 'cross-scope', 'source-cross', repeat('a',64))
	`, "60000000-0000-4000-8000-000000000199", tenant1, workspace2)

	var legacyReadCount int
	if err := database.QueryRow(context.Background(), `SELECT count(*) FROM workspaces WHERE tenant_id=$1`, tenant1).Scan(&legacyReadCount); err != nil || legacyReadCount != 1 {
		t.Fatalf("000014-aware legacy workspace/session read count=%d error=%v", legacyReadCount, err)
	}
	var newCatalogVisible bool
	if err := database.QueryRow(context.Background(), `SELECT to_regclass('asset_sources') IS NOT NULL`).Scan(&newCatalogVisible); err != nil || !newCatalogVisible {
		t.Fatalf("migration version 15 asset catalog visibility=%v error=%v", newCatalogVisible, err)
	}
}

func TestAssetCatalogMigrationCompatibility(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyUpThrough(t, "000014_read_evidence_clock_skew.up.sql")
	const (
		tenantID      = "10000000-0000-4000-8000-000000000111"
		workspaceID   = "20000000-0000-4000-8000-000000000111"
		environmentID = "30000000-0000-4000-8000-000000000111"
		integrationID = "40000000-0000-4000-8000-000000000111"
		serviceID     = "50000000-0000-4000-8000-000000000111"
	)
	execAssetSQL(t, harness.db, `INSERT INTO tenants(id,name) VALUES($1,'compat-tenant')`, tenantID)
	execAssetSQL(t, harness.db, `INSERT INTO workspaces(id,tenant_id,name) VALUES($1,$2,'compat-workspace')`, workspaceID, tenantID)
	execAssetSQL(t, harness.db, `
		INSERT INTO environments(id,tenant_id,workspace_id,name,kind)
		VALUES($1,$2,$3,'compat-production','PROD')
	`, environmentID, tenantID, workspaceID)
	execAssetSQL(t, harness.db, `
		INSERT INTO integrations(id,tenant_id,workspace_id,provider,name,secret_ref,config)
		VALUES($1,$2,$3,'compat','compat-integration','opaque://compat','{"unknown":{"kept":true}}')
	`, integrationID, tenantID, workspaceID)
	execAssetSQL(t, harness.db, `
		INSERT INTO services(id,tenant_id,workspace_id,name,owner_group,labels)
		VALUES($1,$2,$3,'compat-service','compat-sre','{"unknown":"kept"}')
	`, serviceID, tenantID, workspaceID)

	status, code, err := assetCatalogAdmissionStatus(context.Background(), harness.db)
	if err != nil {
		t.Fatalf("check pre-000015 asset catalog admission: %v", err)
	}
	if status != 503 || code != "asset_catalog_unavailable" {
		t.Fatalf("pre-000015 admission=(%d,%s), want (503,asset_catalog_unavailable)", status, code)
	}
	legacyTables := []string{"tenants", "workspaces", "environments", "integrations", "services", "audit_records", "outbox_events"}
	before := collectLegacyHeapShape(t, harness.db, legacyTables)
	if _, err := harness.db.Exec(context.Background(), readMigration(t, "000015_assets_catalog.up.sql")); err != nil {
		t.Fatalf("apply compatibility 000015 migration: %v", err)
	}
	after := collectLegacyHeapShape(t, harness.db, legacyTables)
	for table, want := range before {
		if got := after[table]; got != want {
			t.Errorf("000015 rewrote or changed legacy table %s heap shape=%v, want %v", table, got, want)
		}
	}
	status, code, err = assetCatalogAdmissionStatus(context.Background(), harness.db)
	if err != nil {
		t.Fatalf("check post-000015 asset catalog admission: %v", err)
	}
	if status != 200 || code != "" {
		t.Fatalf("post-000015 admission=(%d,%s), want (200,empty)", status, code)
	}
	var sessionTenant, sessionWorkspace, integrationConfig, serviceLabels string
	if err := harness.db.QueryRow(context.Background(), `
		SELECT t.id::text,w.id::text,i.config::text,s.labels::text
		FROM tenants t
		JOIN workspaces w ON w.tenant_id=t.id
		JOIN integrations i ON i.tenant_id=t.id AND i.workspace_id=w.id
		JOIN services s ON s.tenant_id=t.id AND s.workspace_id=w.id
		WHERE t.id=$1
	`, tenantID).Scan(&sessionTenant, &sessionWorkspace, &integrationConfig, &serviceLabels); err != nil {
		t.Fatalf("000014-aware health/session read while 000015 exists: %v", err)
	}
	if sessionTenant != tenantID || sessionWorkspace != workspaceID ||
		integrationConfig != `{"unknown": {"kept": true}}` || serviceLabels != `{"unknown": "kept"}` {
		t.Fatalf("legacy health/session projection changed after 000015: tenant=%s workspace=%s integration=%s service=%s",
			sessionTenant, sessionWorkspace, integrationConfig, serviceLabels)
	}
}

type legacyHeapShape struct {
	fileNode    uint32
	columnCount int
}

func collectLegacyHeapShape(t *testing.T, database *pgxpool.Pool, tables []string) map[string]legacyHeapShape {
	t.Helper()
	result := make(map[string]legacyHeapShape, len(tables))
	for _, table := range tables {
		var shape legacyHeapShape
		if err := database.QueryRow(context.Background(), `
			SELECT pg_relation_filenode($1::regclass),count(*)::integer
			FROM pg_attribute WHERE attrelid=$1::regclass AND attnum>0 AND NOT attisdropped
		`, table).Scan(&shape.fileNode, &shape.columnCount); err != nil {
			t.Fatalf("collect legacy heap shape for %s: %v", table, err)
		}
		result[table] = shape
	}
	return result
}

func assetCatalogAdmissionStatus(ctx context.Context, database *pgxpool.Pool) (int, string, error) {
	var visibleCount int
	err := database.QueryRow(ctx, `
		SELECT count(*) FROM unnest(ARRAY[
			to_regclass('asset_sources'),to_regclass('asset_source_revisions'),
			to_regclass('asset_source_runs'),to_regclass('asset_observations'),to_regclass('assets'),
			to_regclass('asset_type_details'),to_regclass('asset_conflicts'),
			to_regclass('asset_relationships'),to_regclass('service_asset_bindings')
		]) AS relation_name WHERE relation_name IS NOT NULL
	`).Scan(&visibleCount)
	if err != nil {
		return 0, "", err
	}
	if visibleCount != 9 {
		return 503, "asset_catalog_unavailable", nil
	}
	return 200, "", nil
}

func TestAssetCatalogMigrationEmptyRollback(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	if _, err := harness.db.Exec(context.Background(), readMigration(t, "000015_assets_catalog.down.sql")); err != nil {
		t.Fatalf("empty 000015 rollback failed: %v", err)
	}
	var relation *string
	if err := harness.db.QueryRow(context.Background(), `SELECT to_regclass('asset_sources')::text`).Scan(&relation); err != nil {
		t.Fatalf("check empty rollback: %v", err)
	}
	if relation != nil {
		t.Fatalf("asset_sources remains after empty rollback: %s", *relation)
	}
}

func TestAssetCatalogMigrationCoreInvariants(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedRepresentativeAssetCatalog(t, harness.db)

	expectAssetSQLState(t, harness.db, "55000", `UPDATE asset_observations SET source_revision='tampered'`)
	expectAssetSQLState(t, harness.db, "55000", `DELETE FROM asset_observations WHERE id=$1`, fixture.observationID)
	expectAssetSQLState(t, harness.db, "55000", `UPDATE asset_type_details SET schema_version='tampered' WHERE id=$1`, fixture.typeDetailID)
	expectAssetSQLState(t, harness.db, "55000", `DELETE FROM asset_type_details WHERE id=$1`, fixture.typeDetailID)
	expectAssetSQLState(t, harness.db, "23514", `
		UPDATE assets SET lifecycle='STALE', version=version+1
		WHERE id=$1 AND lifecycle='DISCOVERED'
	`, fixture.assetID)
	execAssetSQL(t, harness.db, `UPDATE assets SET lifecycle='ACTIVE', version=version+1 WHERE id=$1`, fixture.assetID)
	var lifecycle string
	var version int64
	if err := harness.db.QueryRow(context.Background(), `SELECT lifecycle,version FROM assets WHERE id=$1`, fixture.assetID).Scan(&lifecycle, &version); err != nil {
		t.Fatalf("read valid asset transition: %v", err)
	}
	if lifecycle != "ACTIVE" || version != 2 {
		t.Fatalf("valid asset transition=(%s,%d), want (ACTIVE,2)", lifecycle, version)
	}
	execAssetSQL(t, harness.db, `UPDATE assets SET lifecycle='RETIRED', version=version+1 WHERE id=$1`, fixture.assetID)
	expectAssetSQLState(t, harness.db, "55000", `UPDATE assets SET lifecycle='ACTIVE', version=version+1 WHERE id=$1`, fixture.assetID)
	expectAssetSQLState(t, harness.db, "55000", `
		UPDATE assets SET environment_id='30000000-0000-4000-8000-000000000299', version=version+1 WHERE id=$1
	`, fixture.secondAssetID)

	expectAssetSQLState(t, harness.db, "23505", `
		INSERT INTO assets (
			id,tenant_id,workspace_id,environment_id,source_id,provider_kind,external_id,
			kind,display_name,last_observation_id,last_observed_at,last_source_revision,
			create_idempotency_key,create_request_hash
		) SELECT '64000000-0000-4000-8000-000000000299',tenant_id,workspace_id,environment_id,
			source_id,provider_kind,external_id,kind,'duplicate-dedupe',last_observation_id,
			last_observed_at,last_source_revision,'dedupe-other-key',repeat('3',64)
		FROM assets WHERE id=$1
	`, fixture.secondAssetID)
	expectAssetSQLState(t, harness.db, "23505", `
		INSERT INTO asset_relationships (
			id,tenant_id,workspace_id,source_environment_id,target_environment_id,
			source_asset_id,target_asset_id,relationship_type,provenance,status,idempotency_key,request_hash
		) SELECT '67000000-0000-4000-8000-000000000299',tenant_id,workspace_id,
			source_environment_id,target_environment_id,source_asset_id,target_asset_id,
			relationship_type,'MANUAL','ACTIVE','duplicate-edge',repeat('4',64)
		FROM asset_relationships WHERE id=$1
	`, fixture.relationshipID)
	expectAssetSQLState(t, harness.db, "23505", `
		INSERT INTO service_asset_bindings (
			id,tenant_id,workspace_id,environment_id,service_id,asset_id,binding_role,
			mapping_status,provenance,status,idempotency_key,request_hash
		) SELECT '68000000-0000-4000-8000-000000000299',tenant_id,workspace_id,environment_id,
			service_id,asset_id,binding_role,mapping_status,'MANUAL','ACTIVE','duplicate-binding',repeat('5',64)
		FROM service_asset_bindings WHERE id=$1
	`, fixture.bindingID)

	expectAssetSQLState(t, harness.db, "23514", `
		INSERT INTO asset_sources (
			id,tenant_id,workspace_id,source_kind,provider_kind,name,create_idempotency_key,create_request_hash
		) VALUES ('60000000-0000-4000-8000-000000000299',$1,$2,'MANUAL','MANUAL','bad-hash','bad-hash',repeat('A',64))
	`, fixture.tenantID, fixture.workspaceID)
	expectAssetSQLState(t, harness.db, "23514", `
		UPDATE assets SET labels=jsonb_build_object('oversized',repeat('x',17000)),version=version+1 WHERE id=$1
	`, fixture.secondAssetID)
	expectAssetSQLState(t, harness.db, "23514", `
		INSERT INTO asset_observations (
			id,tenant_id,workspace_id,environment_id,source_id,run_id,provider_kind,external_id,
			source_revision,observed_at,schema_version,normalized_document,document_sha256,
			field_provenance,field_provenance_sha256,tombstone,tombstone_reason_code,created_at
		) SELECT '63000000-0000-4000-8000-000000000298',tenant_id,workspace_id,environment_id,
			source_id,run_id,provider_kind,'bad-provenance',source_revision,observed_at,schema_version,
			normalized_document,document_sha256,convert_to('{"raw_provider_path":{"ownership":"SOURCE"}}','UTF8'),
			encode(sha256(convert_to('{"raw_provider_path":{"ownership":"SOURCE"}}','UTF8')),'hex'),
			tombstone,tombstone_reason_code,created_at
		FROM asset_observations WHERE id=$1
	`, fixture.observationID)
	expectAssetSQLState(t, harness.db, "23514", `
		INSERT INTO asset_observations (
			id,tenant_id,workspace_id,environment_id,source_id,run_id,provider_kind,external_id,
			source_revision,observed_at,schema_version,normalized_document,document_sha256,
			field_provenance,field_provenance_sha256,tombstone,tombstone_reason_code,created_at
		) SELECT '63000000-0000-4000-8000-000000000297',tenant_id,workspace_id,environment_id,
			source_id,run_id,provider_kind,'oversized-document',source_revision,observed_at,schema_version,
			convert_to(jsonb_build_object('oversized',repeat('x',70000))::text,'UTF8'),
			encode(sha256(convert_to(jsonb_build_object('oversized',repeat('x',70000))::text,'UTF8')),'hex'),
			field_provenance,field_provenance_sha256,tombstone,tombstone_reason_code,created_at
		FROM asset_observations WHERE id=$1
	`, fixture.observationID)
	expectAssetSQLState(t, harness.db, "23514", `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,status,trigger_type,definition_revision,gate_revision,idempotency_key,request_hash
		) VALUES ('62000000-0000-4000-8000-000000000299',$1,$2,$3,1,$4,
			'VALIDATION','FAILED','HUMAN',1,0,'bad-terminal',repeat('6',64))
	`, fixture.tenantID, fixture.workspaceID, fixture.sourceID, fixture.revisionDigest)
	expectAssetSQLState(t, harness.db, "23514", `
		UPDATE asset_sources SET checkpoint_ciphertext=convert_to('plaintext-cursor','UTF8'),
			checkpoint_key_id='key-1',checkpoint_sha256=encode(sha256(convert_to('plaintext-cursor','UTF8')),'hex'),
			checkpoint_revision=1,checkpoint_version=checkpoint_version+1,version=version+1
		WHERE id=$1
	`, fixture.sourceID)
	expectAssetSQLState(t, harness.db, "23514", `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,status,trigger_type,definition_revision,gate_revision,idempotency_key,request_hash,
			lease_owner,lease_expires_at,fence_epoch,fence_token_hash,heartbeat_sequence,started_at,heartbeat_at
		) VALUES ('62000000-0000-4000-8000-000000000298',$1,$2,$3,1,$4,
			'VALIDATION','RUNNING','HUMAN',1,0,'raw-fence',repeat('7',64),
			'worker-1',statement_timestamp()+interval '1 minute',1,'raw-fence-token',1,
			statement_timestamp(),statement_timestamp())
	`, fixture.tenantID, fixture.workspaceID, fixture.sourceID, fixture.revisionDigest)
	expectAssetSQLState(t, harness.db, "23505", `
		INSERT INTO asset_conflicts (
			id,tenant_id,workspace_id,environment_id,asset_id,candidate_asset_id,candidate_service_id,
			source_id,observation_id,conflict_type,field_name,existing_value_sha256,candidate_value_sha256,
			status,version,created_at,updated_at
		) SELECT '66000000-0000-4000-8000-000000000299',tenant_id,workspace_id,environment_id,
			asset_id,candidate_asset_id,candidate_service_id,source_id,observation_id,conflict_type,
			field_name,existing_value_sha256,candidate_value_sha256,status,1,created_at,updated_at
		FROM asset_conflicts WHERE id=$1
	`, fixture.conflictID)
	execAssetSQL(t, harness.db, `
		INSERT INTO audit_records (
			id,tenant_id,workspace_id,actor_type,actor_id,action,resource_type,resource_id,
			request_id,trace_id,payload_hash
		) VALUES ('69000000-0000-4000-8000-000000000201',$1,$2,'HUMAN','fixture-human',
			'asset.create','ASSET',$3,'fixture-audit-key','trace-fixture',repeat('a',64))
	`, fixture.tenantID, fixture.workspaceID, fixture.assetID)
	expectAssetSQLState(t, harness.db, "23505", `
		INSERT INTO audit_records (
			id,tenant_id,workspace_id,actor_type,actor_id,action,resource_type,resource_id,
			request_id,trace_id,payload_hash
		) VALUES ('69000000-0000-4000-8000-000000000202',$1,$2,'HUMAN','fixture-human',
			'asset.update','ASSET',$3,'fixture-audit-key','trace-fixture-2',repeat('a',64))
	`, fixture.tenantID, fixture.workspaceID, fixture.secondAssetID)
	expectAssetSQLState(t, harness.db, "23514", `
		INSERT INTO audit_records (
			id,tenant_id,workspace_id,actor_type,actor_id,action,resource_type,resource_id,
			request_id,trace_id,payload_hash
		) VALUES ('69000000-0000-4000-8000-000000000203',$1,$2,'HUMAN','fixture-human',
			'asset.create','ASSET',$3,'fixture-bad-audit-hash','trace-fixture-3',repeat('A',64))
	`, fixture.tenantID, fixture.workspaceID, fixture.secondAssetID)
	execAssetSQL(t, harness.db, `
		UPDATE asset_conflicts
		SET status='RESOLVED',resolution='CONFIRM_EXACT',resolution_reason_code='HUMAN_CONFIRMED',
			resolved_by='fixture-human',resolved_at=statement_timestamp(),
			resolution_idempotency_key='fixture-conflict-resolution',resolution_request_hash=repeat('b',64),
			version=version+1
		WHERE id=$1
	`, fixture.conflictID)
	expectAssetSQLState(t, harness.db, "55000", `
		UPDATE asset_conflicts
		SET status='OPEN',resolution=NULL,resolution_reason_code=NULL,resolved_by=NULL,resolved_at=NULL,
			resolution_idempotency_key=NULL,resolution_request_hash=NULL,version=version+1
		WHERE id=$1
	`, fixture.conflictID)

	expectAssetMigrationSQLState(t, harness.db, "000015_assets_catalog.down.sql", "55000")
}

func expectAssetMigrationSQLState(t *testing.T, database *pgxpool.Pool, name, state string) {
	t.Helper()
	connection, err := database.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire migration assertion connection: %v", err)
	}
	defer connection.Release()
	_, migrationErr := connection.Exec(context.Background(), readMigration(t, name))
	if migrationErr == nil {
		t.Fatalf("migration %s unexpectedly succeeded; want SQLSTATE %s", name, state)
	}
	var postgresError *pgconn.PgError
	if !errors.As(migrationErr, &postgresError) || postgresError.Code != state {
		t.Fatalf("migration %s error=%v, want SQLSTATE %s", name, migrationErr, state)
	}
	if _, rollbackErr := connection.Exec(context.Background(), "ROLLBACK"); rollbackErr != nil {
		t.Fatalf("rollback failed migration assertion: %v", rollbackErr)
	}
}

func TestAssetCatalogMigrationGateAndFencing(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedRepresentativeAssetCatalog(t, harness.db)
	validationRunID := "62000000-0000-4000-8000-000000000202"
	validationDigest := strings.Repeat("9", 64)
	execAssetSQL(t, harness.db, `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,status,trigger_type,definition_revision,gate_revision,idempotency_key,
			request_hash,validation_digest,completed_at
		) VALUES ($1,$2,$3,$4,1,$5,'VALIDATION','SUCCEEDED','HUMAN',1,0,
			'fixture-validation-run',repeat('8',64),$6,statement_timestamp())
	`, validationRunID, fixture.tenantID, fixture.workspaceID, fixture.sourceID, fixture.revisionDigest, validationDigest)

	expectAssetSQLState(t, harness.db, "23514", `
		UPDATE asset_sources SET gate_status='AVAILABLE',gate_revision=gate_revision+1,
			validated_run_id=$1,validation_digest=$2,validated_binding_digest=repeat('c',64),version=version+1
		WHERE id=$3
	`, fixture.runID, validationDigest, fixture.sourceID)

	execAssetSQL(t, harness.db, `UPDATE asset_source_revisions SET state='VALIDATING',version=version+1 WHERE id=$1`, fixture.revisionID)
	execAssetSQL(t, harness.db, `
		UPDATE asset_source_revisions SET state='VALIDATED',validation_run_id=$1,
			validation_digest=$2,version=version+1 WHERE id=$3
	`, validationRunID, validationDigest, fixture.revisionID)
	execAssetSQL(t, harness.db, `UPDATE asset_source_revisions SET state='PUBLISHED',version=version+1 WHERE id=$1`, fixture.revisionID)
	var publishedRevision *int64
	var publishedDigest *string
	var gateStatus string
	if err := harness.db.QueryRow(context.Background(), `
		SELECT published_revision,published_revision_digest,gate_status
		FROM asset_sources WHERE id=$1
	`, fixture.sourceID).Scan(&publishedRevision, &publishedDigest, &gateStatus); err != nil {
		t.Fatalf("read published source pointer: %v", err)
	}
	if publishedRevision == nil || *publishedRevision != 1 || publishedDigest == nil || *publishedDigest != fixture.revisionDigest || gateStatus != "UNAVAILABLE" {
		t.Fatalf("published source pointer=(%v,%v,%s), want (1,%s,UNAVAILABLE)", publishedRevision, publishedDigest, gateStatus, fixture.revisionDigest)
	}
	execAssetSQL(t, harness.db, `
		UPDATE asset_sources SET gate_status='AVAILABLE',gate_reason_code=NULL,
			gate_revision=gate_revision+1,validated_run_id=$1,validation_digest=$2,
			validated_binding_digest=repeat('c',64),version=version+1 WHERE id=$3
	`, validationRunID, validationDigest, fixture.sourceID)
	execAssetSQL(t, harness.db, `
		UPDATE asset_sources SET gate_status='AVAILABLE',gate_revision=gate_revision+1,
			validated_run_id=$1,validation_digest=$2,validated_binding_digest=repeat('c',64),version=version+1
		WHERE id=$3
	`, fixture.runID, validationDigest, fixture.sourceID)
	var driftStatus string
	var driftValidatedRun *string
	if err := harness.db.QueryRow(context.Background(), `
		SELECT gate_status,validated_run_id::text FROM asset_sources WHERE id=$1
	`, fixture.sourceID).Scan(&driftStatus, &driftValidatedRun); err != nil {
		t.Fatalf("read bound-reference drift reset: %v", err)
	}
	if driftStatus != "UNAVAILABLE" || driftValidatedRun != nil {
		t.Fatalf("bound-reference drift reset=(%s,%v), want (UNAVAILABLE,nil)", driftStatus, driftValidatedRun)
	}
	expectAssetSQLState(t, harness.db, "23514", `
		UPDATE asset_sources SET gate_status='AVAILABLE',gate_revision=gate_revision+1,
			validated_run_id=$1,validation_digest=$2,validated_binding_digest=repeat('c',64),version=version+1
		WHERE id=$3
	`, fixture.runID, validationDigest, fixture.sourceID)
	execAssetSQL(t, harness.db, `
		UPDATE asset_sources SET gate_status='AVAILABLE',gate_reason_code=NULL,
			gate_revision=gate_revision+1,validated_run_id=$1,validation_digest=$2,
			validated_binding_digest=repeat('c',64),version=version+1 WHERE id=$3
	`, validationRunID, validationDigest, fixture.sourceID)

	queuedRunID := "62000000-0000-4000-8000-000000000203"
	execAssetSQL(t, harness.db, `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,status,trigger_type,definition_revision,gate_revision,idempotency_key,request_hash
		) VALUES ($1,$2,$3,$4,1,$5,'DISCOVERY','QUEUED','API',1,4,
			'fixture-queued-run',repeat('7',64))
	`, queuedRunID, fixture.tenantID, fixture.workspaceID, fixture.sourceID, fixture.revisionDigest)
	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs SET status='RUNNING',lease_owner='worker-1',
			lease_expires_at=statement_timestamp()+interval '1 minute',fence_epoch=1,
			fence_token_hash=repeat('6',64),heartbeat_sequence=1,
			started_at=statement_timestamp(),heartbeat_at=statement_timestamp(),version=version+1
		WHERE id=$1
	`, queuedRunID)
	checkpointTx, err := harness.db.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin atomic page/checkpoint transaction: %v", err)
	}
	if _, err := checkpointTx.Exec(context.Background(), `
		UPDATE asset_sources
		SET checkpoint_ciphertext=decode(repeat('ab',32),'hex'),checkpoint_key_id='checkpoint-key-1',
			checkpoint_sha256=encode(sha256(decode(repeat('ab',32),'hex')),'hex'),
			checkpoint_revision=1,checkpoint_version=checkpoint_version+1,version=version+1
		WHERE id=$1
	`, fixture.sourceID); err != nil {
		_ = checkpointTx.Rollback(context.Background())
		t.Fatalf("advance encrypted checkpoint: %v", err)
	}
	if _, err := checkpointTx.Exec(context.Background(), `
		UPDATE asset_source_runs
		SET page_sequence=page_sequence+1,checkpoint_version=checkpoint_version+1,
			page_digest=repeat('5',64),cursor_after_sha256=repeat('4',64),
			heartbeat_sequence=heartbeat_sequence+1,heartbeat_at=statement_timestamp(),version=version+1
		WHERE id=$1
	`, queuedRunID); err != nil {
		_ = checkpointTx.Rollback(context.Background())
		t.Fatalf("advance successful page sequence: %v", err)
	}
	if err := checkpointTx.Commit(context.Background()); err != nil {
		t.Fatalf("commit atomic page/checkpoint transaction: %v", err)
	}
	expectAssetSQLState(t, harness.db, "55000", `
		UPDATE asset_source_runs
		SET page_sequence=page_sequence+1,checkpoint_version=checkpoint_version+1,
			page_digest=repeat('3',64),cursor_after_sha256=repeat('2',64),version=version+1
		WHERE id=$1
	`, queuedRunID)
	expectAssetSQLState(t, harness.db, "55000", `
		UPDATE asset_source_runs SET fence_epoch=0,version=version+1 WHERE id=$1
	`, queuedRunID)
	expectAssetSQLState(t, harness.db, "55000", `
		UPDATE asset_sources SET checkpoint_version=checkpoint_version-1,version=version+1 WHERE id=$1
	`, fixture.sourceID)
	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs SET status='FAILED',failure_code='UPSTREAM_UNAVAILABLE',
			completed_at=statement_timestamp(),version=version+1 WHERE id=$1
	`, queuedRunID)
	expectAssetSQLState(t, harness.db, "55000", `
		UPDATE asset_source_runs SET lease_owner='worker-2',version=version+1 WHERE id=$1
	`, queuedRunID)

	secondRevisionID := "61000000-0000-4000-8000-000000000202"
	secondRevisionDigest := strings.Repeat("a", 64)
	secondValidationRunID := "62000000-0000-4000-8000-000000000204"
	canonicalSchema := []byte(`{"type":"object","version":2}`)
	execAssetSQL(t, harness.db, `
		INSERT INTO asset_source_revisions (
			id,tenant_id,workspace_id,source_id,revision,state,
			canonical_provider_schema,canonical_provider_schema_sha256,integration_id,sync_mode,
			authority_scope_digest,source_definition_digest,canonical_revision_digest,
			credential_reference_id,trust_reference_id,network_policy_reference_id,
			rate_limit_requests,rate_limit_window_seconds,backpressure_base_seconds,
			backpressure_max_seconds,profile_code,created_by,change_reason_code,expected_source_version
		) VALUES ($1,$2,$3,$4,2,'DRAFT',$5,encode(sha256($5),'hex'),$6,'MANUAL',
			repeat('b',64),repeat('c',64),$7,'credential-ref-2','trust-ref-2','network-policy-ref-2',
			100,60,1,60,'manual-v2','fixture-human','REFERENCE_UPDATE',1)
	`, secondRevisionID, fixture.tenantID, fixture.workspaceID, fixture.sourceID, canonicalSchema, fixture.integrationID, secondRevisionDigest)
	expectAssetSQLState(t, harness.db, "55000", `
		UPDATE asset_source_revisions SET profile_code='mutated',version=version+1 WHERE id=$1
	`, secondRevisionID)
	execAssetSQL(t, harness.db, `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,status,trigger_type,definition_revision,gate_revision,idempotency_key,
			request_hash,validation_digest,completed_at
		) VALUES ($1,$2,$3,$4,2,$5,'VALIDATION','SUCCEEDED','HUMAN',2,2,
			'fixture-validation-run-v2',repeat('1',64),$6,statement_timestamp())
	`, secondValidationRunID, fixture.tenantID, fixture.workspaceID, fixture.sourceID, secondRevisionDigest, validationDigest)
	execAssetSQL(t, harness.db, `UPDATE asset_source_revisions SET state='VALIDATING',version=version+1 WHERE id=$1`, secondRevisionID)
	execAssetSQL(t, harness.db, `
		UPDATE asset_source_revisions SET state='VALIDATED',validation_run_id=$1,
			validation_digest=$2,version=version+1 WHERE id=$3
	`, secondValidationRunID, validationDigest, secondRevisionID)
	execAssetSQL(t, harness.db, `UPDATE asset_source_revisions SET state='PUBLISHED',version=version+1 WHERE id=$1`, secondRevisionID)
	var resetStatus string
	var resetValidatedRun *string
	var resetCheckpoint []byte
	if err := harness.db.QueryRow(context.Background(), `
		SELECT gate_status,validated_run_id::text,checkpoint_ciphertext
		FROM asset_sources WHERE id=$1
	`, fixture.sourceID).Scan(&resetStatus, &resetValidatedRun, &resetCheckpoint); err != nil {
		t.Fatalf("read publication drift reset: %v", err)
	}
	if resetStatus != "UNAVAILABLE" || resetValidatedRun != nil || resetCheckpoint != nil {
		t.Fatalf("publication drift reset=(%s,%v,%x), want unavailable and cleared validation/checkpoint", resetStatus, resetValidatedRun, resetCheckpoint)
	}
}

func TestAssetCatalogMigrationConcurrentLifecycleWrites(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedRepresentativeAssetCatalog(t, harness.db)
	ctx := context.Background()
	first, err := harness.db.Begin(ctx)
	if err != nil {
		t.Fatalf("begin first lifecycle transaction: %v", err)
	}
	defer func() { _ = first.Rollback(context.Background()) }()
	second, err := harness.db.Begin(ctx)
	if err != nil {
		t.Fatalf("begin second lifecycle transaction: %v", err)
	}
	defer func() { _ = second.Rollback(context.Background()) }()
	if _, err := first.Exec(ctx, `UPDATE assets SET lifecycle='ACTIVE',version=2 WHERE id=$1`, fixture.assetID); err != nil {
		t.Fatalf("first concurrent lifecycle update: %v", err)
	}
	result := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		_, updateErr := second.Exec(context.Background(), `UPDATE assets SET lifecycle='ACTIVE',version=2 WHERE id=$1`, fixture.assetID)
		result <- updateErr
	}()
	<-started
	select {
	case updateErr := <-result:
		t.Fatalf("second lifecycle update did not serialize behind the row lock: %v", updateErr)
	case <-time.After(100 * time.Millisecond):
	}
	if err := first.Commit(ctx); err != nil {
		t.Fatalf("commit first concurrent lifecycle update: %v", err)
	}
	select {
	case updateErr := <-result:
		if updateErr == nil {
			t.Fatal("both concurrent lifecycle writes succeeded")
		}
		var postgresError *pgconn.PgError
		if !errors.As(updateErr, &postgresError) || postgresError.Code != "55000" {
			t.Fatalf("second concurrent lifecycle update error=%v, want SQLSTATE 55000", updateErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second concurrent lifecycle update did not finish after first commit")
	}
}
