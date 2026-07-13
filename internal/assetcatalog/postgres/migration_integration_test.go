package postgres_test

import (
	"context"
	"crypto/rand"
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

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	assetpostgres "github.com/seaworld008/aiops-system/internal/assetcatalog/postgres"
)

type assetCatalogHarness struct {
	admin *pgxpool.Pool
	db    *pgxpool.Pool
	name  string
}

var safeAssetCatalogControlDatabase = regexp.MustCompile(`^aiops_test(_[a-z0-9]+)*$`)

func newAssetCatalogHarness(t *testing.T) *assetCatalogHarness {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("AIOPS_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("AIOPS_TEST_POSTGRES_DSN is not configured; real PostgreSQL 18.4 migration tests were not run")
	}
	ctx := context.Background()
	adminConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse PostgreSQL test DSN: %v", err)
	}
	controlName := adminConfig.ConnConfig.Database
	if !assetCatalogControlDatabaseNameSafe(controlName) {
		t.Fatalf("AIOPS_TEST_POSTGRES_DSN must name a dedicated safe test control database, got %q", controlName)
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
	var database *pgxpool.Pool
	created := false
	t.Cleanup(func() {
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
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+identifier+" WITH TEMPLATE template0"); err != nil {
		t.Fatalf("create isolated physical PostgreSQL test database %s; ownership unconfirmed, refusing destructive cleanup: %v", databaseName, err)
	}
	created = true
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse isolated PostgreSQL config: %v", err)
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
	harness := &assetCatalogHarness{admin: admin, db: database, name: databaseName}
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
		if _, err := h.db.Exec(context.Background(), readMigration(t, name)); err != nil {
			if databaseError, ok := err.(*pgconn.PgError); ok {
				t.Fatalf("apply migration %s: %s (SQLSTATE %s, position %d, where %s)",
					name, databaseError.Message, databaseError.Code, databaseError.Position, databaseError.Where)
			}
			t.Fatalf("apply migration %s: %v", name, err)
		}
	}
}

type assetCatalogFixture struct {
	tenantID            string
	workspaceID         string
	environmentID       string
	integrationID       string
	serviceID           string
	sourceID            string
	revisionID          string
	validationRunID     string
	runID               string
	observationID       string
	secondObservationID string
	assetID             string
	secondAssetID       string
	typeDetailID        string
	conflictID          string
	relationshipID      string
	bindingID           string
	revisionDigest      string
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
	}
}

func seedDraftAssetCatalog(t *testing.T, database *pgxpool.Pool) assetCatalogFixture {
	t.Helper()
	fixture := newAssetCatalogFixture()
	execAssetSQL(t, database, `INSERT INTO tenants (id,name) VALUES ($1,'fixture-tenant')`, fixture.tenantID)
	execAssetSQL(t, database, `INSERT INTO workspaces (id,tenant_id,name) VALUES ($1,$2,'fixture-workspace')`, fixture.workspaceID, fixture.tenantID)
	execAssetSQL(t, database, `INSERT INTO environments (id,tenant_id,workspace_id,name,kind) VALUES ($1,$2,$3,'fixture-production','PROD')`, fixture.environmentID, fixture.tenantID, fixture.workspaceID)
	execAssetSQL(t, database, `INSERT INTO integrations (id,tenant_id,workspace_id,provider,name,secret_ref,config) VALUES ($1,$2,$3,'manual','fixture-integration','opaque://sanitized','{"future":"preserve"}')`, fixture.integrationID, fixture.tenantID, fixture.workspaceID)
	execAssetSQL(t, database, `INSERT INTO services (id,tenant_id,workspace_id,name,owner_group,labels) VALUES ($1,$2,$3,'fixture-service','fixture-sre','{"future":"preserve"}')`, fixture.serviceID, fixture.tenantID, fixture.workspaceID)
	execAssetSQL(t, database, `INSERT INTO service_bindings (id,tenant_id,workspace_id,service_id,environment_id,mapping_status) VALUES ('51000000-0000-4000-8000-000000000201',$1,$2,$3,$4,'EXACT')`, fixture.tenantID, fixture.workspaceID, fixture.serviceID, fixture.environmentID)
	execAssetSQL(t, database, `
		INSERT INTO asset_sources (id,tenant_id,workspace_id,source_kind,provider_kind,name,create_idempotency_key,create_request_hash)
		VALUES ($1,$2,$3,'MANUAL','MANUAL_V1','fixture-source','fixture-source-create',repeat('a',64))
	`, fixture.sourceID, fixture.tenantID, fixture.workspaceID)
	canonicalSchema := []byte(`{"type":"object"}`)
	execAssetSQL(t, database, `
		INSERT INTO asset_source_revisions (
			id,tenant_id,workspace_id,source_id,revision,canonical_provider_schema,canonical_provider_schema_sha256,
			integration_id,sync_mode,authority_scope_digest,source_definition_digest,canonical_revision_digest,
		credential_reference_id,trust_reference_id,network_policy_reference_id,rate_limit_requests,
			rate_limit_window_seconds,backpressure_base_seconds,backpressure_max_seconds,profile_code,
			created_by,change_reason_code,expected_source_version
		) VALUES ($1,$2,$3,$4,1,$5,encode(sha256($5),'hex'),$6,'MANUAL',repeat('b',64),repeat('c',64),$7,
			NULL,NULL,NULL,100,60,1,60,'MANUAL_V1','fixture-human','INITIAL_CREATE',1)
	`, fixture.revisionID, fixture.tenantID, fixture.workspaceID, fixture.sourceID, canonicalSchema, fixture.integrationID, fixture.revisionDigest)
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
			) SELECT $1,$2,$3,$5,$4,$6,'MANUAL_V1',$8,1,$9,repeat('c',64),observed_at,'CATALOG_SEQUENCE',1,
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
		fixture.runID, displayName, externalID, fixture.revisionDigest, chain, assetID)
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
	`, []string{"asset_sources", "asset_source_revisions", "asset_source_runs", "asset_observations", "assets",
		"asset_type_details", "asset_conflicts", "asset_relationships", "service_asset_bindings"}).Scan(&tableCount); err != nil {
		t.Fatal(err)
	}
	if tableCount != 9 {
		t.Fatalf("asset catalog table count=%d, want 9", tableCount)
	}
}

func TestAssetCatalogMigrationCompatibility(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyUpThrough(t, "000014_read_evidence_clock_skew.up.sql")
	admission := assetpostgres.NewSchemaAdmission(harness.db, "public")
	if err := admission.Check(context.Background()); !errors.Is(err, assetpostgres.ErrAssetCatalogUnavailable) {
		t.Fatalf("pre-000015 admission error=%v", err)
	}
	if _, err := harness.db.Exec(context.Background(), readMigration(t, "000015_assets_catalog.up.sql")); err != nil {
		t.Fatalf("apply 000015 online: %v", err)
	}
	if err := admission.Check(context.Background()); err != nil {
		t.Fatalf("post-000015 admission: %v", err)
	}
}

func TestAssetCatalogMigrationEmptyRollback(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	if _, err := harness.db.Exec(context.Background(), readMigration(t, "000015_assets_catalog.down.sql")); err != nil {
		t.Fatalf("empty 000015 rollback failed: %v", err)
	}
}

func TestAssetCatalogMigrationCoreInvariants(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	expectAssetSQLState(t, harness.db, "55000", `UPDATE asset_observations SET source_revision=source_revision+1 WHERE id=$1`, fixture.observationID)
	expectAssetSQLState(t, harness.db, "55000", `DELETE FROM asset_type_details WHERE id=$1`, fixture.typeDetailID)
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
	return []string{"asset_sources", "asset_source_revisions", "asset_source_runs", "asset_observations", "assets",
		"asset_type_details", "asset_conflicts", "asset_relationships", "service_asset_bindings"}
}

func assetCatalogFixtureSummary(fixture assetCatalogFixture) string {
	return fmt.Sprintf("source=%s run=%s asset=%s", fixture.sourceID, fixture.runID, fixture.assetID)
}
