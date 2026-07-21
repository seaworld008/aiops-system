package postgres_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	assetpostgres "github.com/seaworld008/aiops-system/internal/assetcatalog/postgres"
	storepostgres "github.com/seaworld008/aiops-system/internal/store/postgres"
)

type recoveredTableProof struct {
	count    int64
	checksum string
}

func TestAssetCatalogRecovery(t *testing.T) {
	pair := prepareRecoveryPostgreSQLPair(t)
	assertRecoverySourceGateCapabilityClosed(t, pair.sourceHarness)
	assertRecoverySourceGateCapabilityClosed(t, pair.targetHarness)
	pair.sourceHarness.grantSourceGateCapabilityACLForTest(t)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := pair.sourceHarness.reconcileSourceGateCapabilityAfterSuccessfulDown(cancelled); err != nil {
		t.Fatalf("recovery pre-migration capability down reconciliation: %v", err)
	}
	assertRecoverySourceGateCapabilityClosed(t, pair.sourceHarness)
	source := pair.sourcePool
	pair.sourceHarness.applyThroughAssetCatalog(t)
	sourceCapabilitySchema, err := qualificationFixtureSchemaStateFor(
		context.Background(), pair.sourceHarness.application,
	)
	if err != nil {
		t.Fatalf("inspect recovery source capability schema: %v", err)
	}
	pair.sourceHarness.grantSourceGateCapabilityACLForTest(t)
	if err := pair.sourceHarness.reconcileSourceGateCapabilityACL(
		context.Background(),
		sourceGateCapabilityAdmissionCallbacksForCurrentBinary(),
	); err != nil {
		t.Fatalf("recovery source capability reconciliation: %v", err)
	}
	pair.sourceHarness.assertSourceGateCapabilityACLForSchemaState(t, sourceCapabilitySchema)
	fixture := seedRepresentativeAssetCatalog(t, source)
	seedRecoveryProjection(t, source, fixture)
	authoritativeSeed := fixture
	authoritativeSeed.observationID = "69000000-0000-4000-8000-000000000201"
	authoritativeSeed.secondObservationID = "69000000-0000-4000-8000-000000000202"
	authoritativeSeed.assetID = "6a000000-0000-4000-8000-000000000201"
	authoritativeSeed.secondAssetID = "6a000000-0000-4000-8000-000000000202"
	authoritativeSeed.typeDetailID = "6b000000-0000-4000-8000-000000000201"
	authoritativeSeed.conflictID = "6c000000-0000-4000-8000-000000000201"
	authoritativeSeed.relationshipID = "6d000000-0000-4000-8000-000000000201"
	authoritativeSeed.bindingID = "6e000000-0000-4000-8000-000000000201"
	authoritativeFixture := seedClosureAuthoritativeCompleteCatalogOnFixture(t, source, authoritativeSeed)
	assertRecoveryAdmissions(t, pair.sourceHarness)
	sourceQualificationSchema := verifyQualificationRecoveryReadiness(
		t, source, authoritativeFixture,
	)
	sourceProof := collectAssetCatalogProof(t, source)
	verifyAssetCatalogClosure(t, source, fixture, sourceQualificationSchema)
	verifyAuthoritativeCompletePointer(t, source, authoritativeFixture)
	assertRecoveryCatalogOwners(t, pair.sourceHarness.admin)
	pair.sourceHarness.assertSourceGateCapabilityACLForSchemaState(t, sourceQualificationSchema)

	backup := logicalDumpDatabase(t, pair.source)
	if len(backup) < 1024 || !strings.HasPrefix(string(backup[:5]), "PGDMP") {
		t.Fatalf("logical backup is unexpectedly small: %d bytes", len(backup))
	}
	backupSHA256 := sha256.Sum256(backup)
	t.Logf("logical recovery archive SHA-256=%x", backupSHA256)
	pair.sourceHarness.assertSourceGateCapabilityACLForSchemaState(t, sourceQualificationSchema)
	assertRecoverySourceGateCapabilityClosed(t, pair.targetHarness)
	assertRecoveryPoolIdentity(t, pair.targetHarness.migration, "aiops_migrator", "aiops_migrator")
	restoreLogicalDump(t, pair.target, backup)
	if err := pair.targetHarness.reconcileSourceGateCapabilityACL(
		context.Background(),
		sourceGateCapabilityAdmissionCallbacksForCurrentBinary(),
	); err != nil {
		t.Fatalf("recovery target capability reconciliation: %v", err)
	}
	target := pair.targetPool
	assertRecoveryAdmissions(t, pair.targetHarness)
	targetQualificationSchema := verifyQualificationRecoveryReadiness(
		t, target, authoritativeFixture,
	)
	pair.targetHarness.assertSourceGateCapabilityACLForSchemaState(t, targetQualificationSchema)
	targetProof := collectAssetCatalogProof(t, target)
	if len(sourceProof) != len(targetProof) {
		t.Fatalf("restored proof table count=%d, want %d", len(targetProof), len(sourceProof))
	}
	for table, want := range sourceProof {
		got, ok := targetProof[table]
		if !ok || got != want {
			t.Errorf("restored %s proof=%+v present=%v, want %+v", table, got, ok, want)
		}
	}
	verifyAssetCatalogClosure(t, target, fixture, targetQualificationSchema)
	verifyAuthoritativeCompletePointer(t, target, authoritativeFixture)
	verifyRecoveryAdmissionDriftMatrix(t, pair.targetHarness, pair.target, targetProof)
	verifyRestoredMutationGuards(t, target, fixture)
	execAssetSQL(t, target, `
		ALTER TABLE asset_observations DROP CONSTRAINT asset_observations_run_revision_fk
	`)
	if err := assetpostgres.NewSchemaAdmission(target, "public").Check(context.Background()); !errors.Is(err, assetpostgres.ErrAssetCatalogUnavailable) {
		t.Fatalf("schema admission after restored exact-FK removal error=%v, want %v",
			err, assetpostgres.ErrAssetCatalogUnavailable)
	}
	pair.targetHarness.grantSourceGateCapabilityACLForTest(t)
	if err := pair.targetHarness.reconcileSourceGateCapabilityACL(
		context.Background(),
		sourceGateCapabilityAdmissionCallbacksForCurrentBinary(),
	); !errors.Is(err, errSourceGateCapabilityUnavailable) {
		t.Fatalf("partial restored capability reconciliation error=%v, want %v",
			err, errSourceGateCapabilityUnavailable)
	}
	assertRecoverySourceGateCapabilityClosed(t, pair.targetHarness)
}

func assertRecoverySourceGateCapabilityClosed(t *testing.T, harness *assetCatalogHarness) {
	t.Helper()
	harness.assertSourceGateCapabilityACLAbsent(t)
	harness.assertSourceGateCapabilityConnectionsRejected(t)
}

func assertRecoveryAdmissions(t *testing.T, harness *assetCatalogHarness) {
	t.Helper()
	if err := assetpostgres.NewSchemaAdmission(harness.application, "public").Check(context.Background()); err != nil {
		t.Fatalf("recovery schema admission: %v", err)
	}
	if err := storepostgres.NewDatabaseRoleAdmission(harness.application, "public").Check(context.Background()); err != nil {
		t.Fatalf("recovery database-role admission: %v", err)
	}
}

func verifyRecoveryAdmissionDriftMatrix(
	t *testing.T,
	harness *assetCatalogHarness,
	container *recoveryPostgreSQLContainer,
	baseline map[string]recoveredTableProof,
) {
	t.Helper()
	database := pgx.Identifier{container.databaseName}.Sanitize()
	bootstrapAdmin := pgx.Identifier{container.username}.Sanitize()
	type admissionDrift struct {
		name                  string
		apply                 string
		repair                string
		schemaAdmissionReject bool
	}
	drifts := []admissionDrift{
		{
			name:   "role flag",
			apply:  `ALTER ROLE aiops_control_plane_runtime LOGIN`,
			repair: `ALTER ROLE aiops_control_plane_runtime NOLOGIN`,
		},
		{
			name: "membership option",
			apply: `GRANT aiops_control_plane_runtime TO aiops_control_plane_workload
				WITH ADMIN FALSE, INHERIT TRUE, SET TRUE`,
			repair: `GRANT aiops_control_plane_runtime TO aiops_control_plane_workload
				WITH ADMIN FALSE, INHERIT TRUE, SET FALSE`,
		},
		{
			name:                  "database owner",
			apply:                 "ALTER DATABASE " + database + " OWNER TO " + bootstrapAdmin,
			repair:                "ALTER DATABASE " + database + " OWNER TO aiops_schema_owner",
			schemaAdmissionReject: true,
		},
		{
			name:                  "database TEMP ACL",
			apply:                 "GRANT TEMPORARY ON DATABASE " + database + " TO aiops_control_plane_workload",
			repair:                "REVOKE TEMPORARY ON DATABASE " + database + " FROM aiops_control_plane_workload",
			schemaAdmissionReject: true,
		},
		{
			name:                  "schema owner",
			apply:                 "ALTER SCHEMA public OWNER TO " + bootstrapAdmin,
			repair:                `ALTER SCHEMA public OWNER TO aiops_schema_owner`,
			schemaAdmissionReject: true,
		},
		{
			name:                  "schema PUBLIC ACL",
			apply:                 `GRANT USAGE ON SCHEMA public TO PUBLIC`,
			repair:                `REVOKE USAGE ON SCHEMA public FROM PUBLIC`,
			schemaAdmissionReject: true,
		},
		{
			name:                  "relation owner",
			apply:                 "ALTER TABLE public.assets OWNER TO " + bootstrapAdmin,
			repair:                `ALTER TABLE public.assets OWNER TO aiops_schema_owner`,
			schemaAdmissionReject: true,
		},
		{
			name:                  "relation ACL",
			apply:                 `GRANT DELETE ON TABLE public.assets TO aiops_control_plane_runtime`,
			repair:                `REVOKE DELETE ON TABLE public.assets FROM aiops_control_plane_runtime`,
			schemaAdmissionReject: true,
		},
		{
			name:                  "function ACL",
			apply:                 `GRANT EXECUTE ON FUNCTION public.asset_catalog_sha256_valid(text) TO PUBLIC`,
			repair:                `REVOKE EXECUTE ON FUNCTION public.asset_catalog_sha256_valid(text) FROM PUBLIC`,
			schemaAdmissionReject: true,
		},
	}

	for _, drift := range drifts {
		drift := drift
		t.Run(drift.name, func(t *testing.T) {
			mustExecuteRecoveryDrift(t, harness.admin, drift.apply)
			repaired := false
			t.Cleanup(func() {
				if !repaired {
					mustExecuteRecoveryDrift(t, harness.admin, drift.repair)
				}
			})

			if err := storepostgres.NewDatabaseRoleAdmission(harness.application, "public").Check(context.Background()); !errors.Is(err, storepostgres.ErrDatabaseRoleUnavailable) {
				t.Fatalf("database-role admission after %s drift error=%v, want %v",
					drift.name, err, storepostgres.ErrDatabaseRoleUnavailable)
			}
			schemaErr := assetpostgres.NewSchemaAdmission(harness.application, "public").Check(context.Background())
			if drift.schemaAdmissionReject {
				if !errors.Is(schemaErr, assetpostgres.ErrAssetCatalogUnavailable) {
					t.Fatalf("schema admission after %s drift error=%v, want %v",
						drift.name, schemaErr, assetpostgres.ErrAssetCatalogUnavailable)
				}
			} else if schemaErr != nil {
				t.Fatalf("schema admission changed for role-only %s drift: %v", drift.name, schemaErr)
			}
			assertRecoveryProofEqual(t, collectAssetCatalogProof(t, harness.application), baseline)

			mustExecuteRecoveryDrift(t, harness.admin, drift.repair)
			repaired = true
			assertRecoveryAdmissions(t, harness)
			assertRecoveryProofEqual(t, collectAssetCatalogProof(t, harness.application), baseline)
		})
	}
}

func mustExecuteRecoveryDrift(t *testing.T, admin *pgxpool.Pool, statement string) {
	t.Helper()
	if _, err := admin.Exec(context.Background(), statement); err != nil {
		t.Fatalf("apply recovery admission drift fixture: %v", err)
	}
}

func assertRecoveryProofEqual(
	t *testing.T,
	actual map[string]recoveredTableProof,
	want map[string]recoveredTableProof,
) {
	t.Helper()
	if len(actual) != len(want) {
		t.Fatalf("recovery proof table count=%d, want %d", len(actual), len(want))
	}
	for table, wantTable := range want {
		if actualTable, ok := actual[table]; !ok || actualTable != wantTable {
			t.Fatalf("recovery proof for %s=%+v present=%v, want %+v",
				table, actualTable, ok, wantTable)
		}
	}
}

func verifyAuthoritativeCompletePointer(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
) {
	t.Helper()
	var exact bool
	if err := database.QueryRow(context.Background(), `
		SELECT source.status='ACTIVE' AND source.gate_status='AVAILABLE' AND
			source.published_revision=run.source_revision AND
			source.published_revision_digest=run.source_revision_digest AND
			source.last_success_run_id=run.id AND source.last_success_at=run.completed_at AND
			source.last_complete_snapshot_run_id=run.id AND
			source.last_complete_snapshot_at=run.completed_at AND
			run.status='SUCCEEDED' AND run.stage_code='COMPLETED' AND
			run.run_kind='DISCOVERY' AND run.final_page AND run.complete_snapshot AND
			run.effective_complete_snapshot AND run.completed_at IS NOT NULL
		FROM asset_sources AS source
		JOIN asset_source_runs AS run
		  ON run.tenant_id=source.tenant_id
		 AND run.workspace_id=source.workspace_id
		 AND run.source_id=source.id
		 AND run.id=source.last_complete_snapshot_run_id
		WHERE source.id=$1 AND run.id=$2
	`, fixture.sourceID, fixture.runID).Scan(&exact); err != nil {
		t.Fatalf("verify authoritative complete pointer: %v", err)
	}
	if !exact {
		t.Fatal("authoritative complete pointer is not bound to the exact current revision and completion")
	}
}

func verifyQualificationRecoveryReadiness(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
) qualificationFixtureSchemaState {
	t.Helper()
	state, err := qualificationFixtureSchemaStateFor(context.Background(), database)
	if err != nil {
		t.Fatalf("inspect recovery qualification fixture schema: %v", err)
	}
	if state == qualificationFixtureSchemaOld {
		var qualificationRuns int
		if err := database.QueryRow(context.Background(), `
			SELECT count(*) FROM asset_source_runs
			WHERE source_id=$1 AND run_kind='QUALIFICATION'
		`, fixture.sourceID).Scan(&qualificationRuns); err != nil {
			t.Fatalf("verify old-schema recovery qualification no-op: %v", err)
		}
		if qualificationRuns != 0 {
			t.Fatalf(
				"old-schema recovery contains %d qualification runs, want exact no-op",
				qualificationRuns,
			)
		}
		return state
	}

	var haReceiptDigest string
	if err := database.QueryRow(context.Background(), `
		SELECT qualification_receipt_digest
		FROM asset_source_runs
		WHERE source_id=$1 AND run_kind='QUALIFICATION'
		  AND qualification_evidence_kind='TWO_WORKER_HA'
	`, fixture.sourceID).Scan(&haReceiptDigest); err != nil {
		t.Fatalf("read restored HA receipt digest: %v", err)
	}
	expectedPriorReceiptsDigest := qualificationFixturePriorReceiptsDigest(
		t, []string{haReceiptDigest},
	)
	var ready bool
	if err := database.QueryRow(context.Background(), `
		SELECT
			source.status='ACTIVE' AND
			source.gate_status='AVAILABLE' AND source.gate_reason_code IS NULL AND
			source.gate_evidence_run_id=canary.id AND
			source.gate_evidence_digest=canary.qualification_receipt_digest AND
			source.gate_evidence_expires_at=canary.qualification_receipt_expires_at AND
			source.gate_evidence_expires_at>clock_timestamp() AND
			source.gate_revision=canary.gate_revision+1 AND
			ha.gate_revision=canary.gate_revision AND
			ha.source_revision=source.published_revision AND
			canary.source_revision=source.published_revision AND
			ha.source_revision_digest=source.published_revision_digest AND
			canary.source_revision_digest=source.published_revision_digest AND
			ha.qualification_binding_digest=source.published_revision_digest AND
			canary.qualification_binding_digest=source.published_revision_digest AND
			ha.run_kind='QUALIFICATION' AND canary.run_kind='QUALIFICATION' AND
			ha.status='SUCCEEDED' AND canary.status='SUCCEEDED' AND
			ha.stage_code='COMPLETED' AND canary.stage_code='COMPLETED' AND
			ha.cleanup_status='REVOKED' AND canary.cleanup_status='REVOKED' AND
			ha.cleanup_digest IS NOT NULL AND canary.cleanup_digest IS NOT NULL AND
			ha.ha_cleanup_receipt_digest=ha.cleanup_digest AND
			ha.work_result_kind='QUALIFICATION_PROOF' AND
			canary.work_result_kind='QUALIFICATION_PROOF' AND
			ha.work_result_status='SUCCEEDED' AND
			canary.work_result_status='SUCCEEDED' AND
			ha.work_result_digest=ha.qualification_result_digest AND
			canary.work_result_digest=canary.qualification_result_digest AND
			ha.qualification_receipt_issued_at>ha.work_result_recorded_at AND
			canary.qualification_receipt_issued_at>canary.work_result_recorded_at AND
			ha.qualification_receipt_expires_at>ha.qualification_receipt_issued_at AND
			canary.qualification_receipt_expires_at>
				canary.qualification_receipt_issued_at AND
			position('=' IN ha.qualification_signature)=0 AND
			position('=' IN canary.qualification_signature)=0 AND
			ha.qualification_evidence_kind='TWO_WORKER_HA' AND
			canary.qualification_evidence_kind='PROVIDER_CANARY' AND
			ha.qualification_scope_digest=canary.qualification_scope_digest AND
			ha.qualification_binding_digest=canary.qualification_binding_digest AND
			ha.qualification_profile_descriptor_digest=
				canary.qualification_profile_descriptor_digest AND
			ha.qualification_runtime_manifest_digest=
				canary.qualification_runtime_manifest_digest AND
			ha.qualification_lab_binding_digest=canary.qualification_lab_binding_digest AND
			canary.qualification_prior_receipts_digest=$2 AND
			ha.qualification_receipt_digest=$3 AND
			num_nonnulls(
				ha.cursor_before_sha256,ha.cursor_after_sha256,
				canary.cursor_before_sha256,canary.cursor_after_sha256
			)=0 AND
			ha.checkpoint_version=0 AND canary.checkpoint_version=0 AND
			ha.page_sequence=0 AND canary.page_sequence=0 AND
			ha.page_digest IS NULL AND canary.page_digest IS NULL AND
			ha.relation_page_sequence=0 AND canary.relation_page_sequence=0 AND
			ha.relation_page_digest IS NULL AND canary.relation_page_digest IS NULL AND
			NOT ha.final_page AND NOT canary.final_page AND
			NOT ha.complete_snapshot AND NOT canary.complete_snapshot AND
			NOT ha.effective_complete_snapshot AND NOT canary.effective_complete_snapshot AND
			ha.observed_count+canary.observed_count=0 AND
			ha.created_count+canary.created_count=0 AND
			ha.changed_count+canary.changed_count=0 AND
			ha.unchanged_count+canary.unchanged_count=0 AND
			ha.conflict_count+canary.conflict_count=0 AND
			ha.missing_count+canary.missing_count=0 AND
			ha.stale_count+canary.stale_count=0 AND
			ha.restored_count+canary.restored_count=0 AND
			ha.tombstoned_count+canary.tombstoned_count=0 AND
			ha.rejected_count+canary.rejected_count=0 AND
			source.last_success_run_id=success.id AND
			source.last_complete_snapshot_run_id=success.id AND success.id=$4 AND
			success.run_kind IN ('DISCOVERY','CSV_IMPORT','API_INGESTION','MANUAL_MUTATION') AND
			success.id<>ha.id AND success.id<>canary.id AND
			source.checkpoint_revision=source.published_revision AND
			source.checkpoint_version=success.checkpoint_version AND
			source.checkpoint_sha256=success.cursor_after_sha256 AND
			(SELECT count(*) FROM asset_observations AS observation
			 WHERE observation.run_id IN (ha.id,canary.id))=0 AND
			(SELECT count(*) FROM asset_relationships AS relationship
			 WHERE relationship.last_run_id IN (ha.id,canary.id))=0 AND
			num_nonnulls(
				ha.ha_owner_worker_identity_digest,ha.ha_takeover_worker_identity_digest,
				ha.ha_owner_process_instance_digest,ha.ha_takeover_process_instance_digest,
				ha.ha_takeover_receipt_digest,ha.ha_restart_receipt_digest,
				ha.ha_session_recovery_receipt_digest,ha.ha_cleanup_receipt_digest,
				ha.ha_response_loss_receipt_digest,ha.ha_fact_chain_digest
			)=10 AND
			ha.ha_owner_worker_identity_digest<>ha.ha_takeover_worker_identity_digest AND
			ha.ha_owner_process_instance_digest<>ha.ha_takeover_process_instance_digest AND
			num_nonnulls(
				canary.ha_owner_worker_identity_digest,
				canary.ha_takeover_worker_identity_digest,
				canary.ha_owner_process_instance_digest,
				canary.ha_takeover_process_instance_digest,
				canary.ha_takeover_receipt_digest,canary.ha_restart_receipt_digest,
				canary.ha_session_recovery_receipt_digest,canary.ha_cleanup_receipt_digest,
				canary.ha_response_loss_receipt_digest,canary.ha_fact_chain_digest
			)=0
		FROM asset_sources AS source
		JOIN asset_source_runs AS canary
		  ON canary.tenant_id=source.tenant_id
		 AND canary.workspace_id=source.workspace_id
		 AND canary.source_id=source.id
		 AND canary.id=source.gate_evidence_run_id
		JOIN asset_source_runs AS ha
		  ON ha.tenant_id=canary.tenant_id
		 AND ha.workspace_id=canary.workspace_id
		 AND ha.source_id=canary.source_id
		 AND ha.qualification_evidence_kind='TWO_WORKER_HA'
		 AND ha.qualification_receipt_expires_at=canary.qualification_receipt_expires_at
		JOIN asset_source_runs AS success
		  ON success.tenant_id=source.tenant_id
		 AND success.workspace_id=source.workspace_id
		 AND success.source_id=source.id
		 AND success.id=source.last_success_run_id
		WHERE source.id=$1
	`, fixture.sourceID, expectedPriorReceiptsDigest, haReceiptDigest, fixture.runID).Scan(&ready); err != nil {
		t.Fatalf("verify restored qualification gate/HA/canary readiness: %v", err)
	}
	if !ready {
		t.Fatal("restored qualification gate pointer and HA/canary receipts are not ready")
	}
	return state
}

func seedRecoveryProjection(t *testing.T, database *pgxpool.Pool, fixture assetCatalogFixture) {
	t.Helper()
	execAssetSQL(t, database, `UPDATE assets SET lifecycle='ACTIVE',version=version+1 WHERE id=$1`, fixture.assetID)
	seedRecoveryLimiterTruth(t, database, fixture)
	seedRecoveryAuditOutbox(t, database, fixture)
}

func seedRecoveryLimiterTruth(t *testing.T, database *pgxpool.Pool, fixture assetCatalogFixture) {
	t.Helper()
	transaction, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin recovery Limiter truth fixture: %v", err)
	}
	defer func() { _ = transaction.Rollback(context.Background()) }()
	const (
		sourceBucketID    = "6f000000-0000-4000-8000-000000000201"
		workspaceBucketID = "6f000000-0000-4000-8000-000000000202"
		providerBucketID  = "6f000000-0000-4000-8000-000000000203"
		acquireReceiptID  = "6f100000-0000-4000-8000-000000000201"
		releaseReceiptID  = "6f100000-0000-4000-8000-000000000202"
		acquiredAt        = "2026-07-16T00:00:00Z"
		expiresAt         = "2026-07-16T00:05:00Z"
	)
	execAssetSQL(t, transaction, `
		INSERT INTO asset_source_limit_buckets (
			id,tenant_id,workspace_id,bucket_kind,bucket_key,source_id,provider_kind,next_token_at
		) VALUES
			($1,$4,$5,'SOURCE',$6,$6,NULL,$7),
			($2,$4,$5,'WORKSPACE',$5,NULL,NULL,$7),
			($3,$4,$5,'PROVIDER','MANUAL_V1',NULL,'MANUAL_V1',$7)
	`, sourceBucketID, workspaceBucketID, providerBucketID,
		fixture.tenantID, fixture.workspaceID, fixture.sourceID, acquiredAt)
	execAssetSQL(t, transaction, `
		INSERT INTO asset_source_limit_permits (
			id,tenant_id,workspace_id,permit_id,record_kind,source_id,run_id,provider_kind,
			source_bucket_id,source_bucket_kind,source_bucket_key,
			workspace_bucket_id,workspace_bucket_kind,workspace_bucket_key,
			provider_bucket_id,provider_bucket_kind,provider_bucket_key,
			request_id,command_sha256,receipt_sha256,acquired_at,expires_at,created_at
		) VALUES (
			$1,$2,$3,$1,'ACQUIRE',$4,$5,'MANUAL_V1',
			$6,'SOURCE',$4,$7,'WORKSPACE',$3,$8,'PROVIDER','MANUAL_V1',
			'recovery-limiter-acquire',repeat('1',64),repeat('2',64),$9,$10,$9
		)
	`, acquireReceiptID, fixture.tenantID, fixture.workspaceID, fixture.sourceID, fixture.runID,
		sourceBucketID, workspaceBucketID, providerBucketID, acquiredAt, expiresAt)
	updateLimiterBuckets(t, transaction, acquireReceiptID, true,
		sourceBucketID, workspaceBucketID, providerBucketID)
	execAssetSQL(t, transaction, `
		INSERT INTO asset_source_limit_permits (
			id,tenant_id,workspace_id,permit_id,record_kind,source_id,run_id,provider_kind,
			source_bucket_id,source_bucket_kind,source_bucket_key,
			workspace_bucket_id,workspace_bucket_kind,workspace_bucket_key,
			provider_bucket_id,provider_bucket_kind,provider_bucket_key,
			request_id,command_sha256,receipt_sha256,acquired_at,expires_at,terminal_reason_code
		) VALUES (
			$1,$2,$3,$4,'RELEASE',$5,$6,'MANUAL_V1',
			$7,'SOURCE',$5,$8,'WORKSPACE',$3,$9,'PROVIDER','MANUAL_V1',
			'recovery-limiter-release',repeat('3',64),repeat('4',64),$10,$11,'RECOVERY_FIXTURE'
		)
	`, releaseReceiptID, fixture.tenantID, fixture.workspaceID, acquireReceiptID,
		fixture.sourceID, fixture.runID, sourceBucketID, workspaceBucketID, providerBucketID,
		acquiredAt, expiresAt)
	updateLimiterBuckets(t, transaction, releaseReceiptID, false,
		sourceBucketID, workspaceBucketID, providerBucketID)
	if err := transaction.Commit(context.Background()); err != nil {
		t.Fatalf("commit recovery Limiter truth fixture: %v", err)
	}
}

func verifyRestoredMutationGuards(t *testing.T, database *pgxpool.Pool, fixture assetCatalogFixture) {
	t.Helper()
	expectAssetSQLState(t, database, "55000", `
		UPDATE asset_observations SET source_revision=source_revision+1 WHERE id=$1
	`, fixture.observationID)
	expectAssetSQLState(t, database, "55000", `
		UPDATE asset_type_details SET actor_id='tampered' WHERE id=$1
	`, fixture.typeDetailID)
	expectAssetSQLState(t, database, "55000", `
		UPDATE asset_source_revision_authorities SET canonical_ordinal=canonical_ordinal+1
		WHERE tenant_id=$1 AND workspace_id=$2 AND source_id=$3 AND source_revision=1
	`, fixture.tenantID, fixture.workspaceID, fixture.sourceID)
	expectAssetSQLState(t, database, "55000", `
		UPDATE asset_source_limit_permits SET receipt_sha256=receipt_sha256
		WHERE id='6f100000-0000-4000-8000-000000000201'
	`)

	rows := []struct {
		table     string
		predicate string
		arguments []any
	}{
		{"asset_sources", "id=$1", []any{fixture.sourceID}},
		{"asset_source_revisions", "id=$1", []any{fixture.revisionID}},
		{"asset_source_revision_authorities", "tenant_id=$1 AND workspace_id=$2 AND source_id=$3 AND source_revision=1",
			[]any{fixture.tenantID, fixture.workspaceID, fixture.sourceID}},
		{"asset_source_runs", "id=$1", []any{fixture.runID}},
		{"asset_source_limit_buckets", "id='6f000000-0000-4000-8000-000000000201'", nil},
		{"asset_source_limit_permits", "id='6f100000-0000-4000-8000-000000000201'", nil},
		{"asset_observations", "id=$1", []any{fixture.observationID}},
		{"assets", "id=$1", []any{fixture.assetID}},
		{"asset_type_details", "id=$1", []any{fixture.typeDetailID}},
		{"asset_conflicts", "id=$1", []any{fixture.conflictID}},
		{"asset_relationships", "id=$1", []any{fixture.relationshipID}},
		{"service_asset_bindings", "id=$1", []any{fixture.bindingID}},
	}
	for _, row := range rows {
		query := fmt.Sprintf("DELETE FROM %s WHERE %s", pgx.Identifier{row.table}.Sanitize(), row.predicate)
		expectAssetSQLState(t, database, "55000", query, row.arguments...)
	}

	expectAssetSQLState(t, database, "P0001", `
		UPDATE audit_records SET action='tampered' WHERE request_id='recovery-audit'
	`)
	expectAssetSQLState(t, database, "23514", `
		UPDATE outbox_events SET attempts=-1 WHERE id='6a000000-0000-4000-8000-000000000201'
	`)
}

func seedRecoveryAuditOutbox(t *testing.T, database *pgxpool.Pool, fixture assetCatalogFixture) {
	t.Helper()
	payload := fmt.Sprintf(`{"audit_request_id":"recovery-audit","asset_id":%q}`, fixture.assetID)
	tx, err := database.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin recovery audit/outbox transaction: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(context.Background(), `
		INSERT INTO audit_records (
			id,tenant_id,workspace_id,actor_type,actor_id,action,resource_type,resource_id,
			request_id,trace_id,payload_hash
		) VALUES (
			'69000000-0000-4000-8000-000000000209',$1,$2,'HUMAN','fixture-human',
			'asset.recovery.proof','ASSET',$3,'recovery-audit','recovery-trace',
			encode(sha256(convert_to(($4::jsonb)::text,'UTF8')),'hex')
		)
	`, fixture.tenantID, fixture.workspaceID, fixture.assetID, payload); err != nil {
		t.Fatalf("insert recovery audit proof: %v", err)
	}
	if _, err := tx.Exec(context.Background(), `
		INSERT INTO outbox_events (
			id,tenant_id,workspace_id,aggregate_type,aggregate_id,aggregate_version,event_type,payload
		) VALUES (
			'6a000000-0000-4000-8000-000000000201',$1,$2,'ASSET',$3,2,
			'asset.recovery.proof.v1',$4::jsonb
		)
	`, fixture.tenantID, fixture.workspaceID, fixture.assetID, payload); err != nil {
		t.Fatalf("insert recovery outbox proof: %v", err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit recovery audit/outbox transaction: %v", err)
	}
}

func collectAssetCatalogProof(t *testing.T, database *pgxpool.Pool) map[string]recoveredTableProof {
	t.Helper()
	tables := []string{
		"asset_sources", "asset_source_revisions", "asset_source_runs",
		"asset_source_limit_buckets", "asset_source_limit_permits", "asset_observations",
		"asset_source_revision_authorities", "assets", "asset_type_details", "asset_conflicts",
		"asset_relationships", "service_asset_bindings",
		"audit_records", "outbox_events",
	}
	proof := make(map[string]recoveredTableProof, len(tables))
	for _, table := range tables {
		query := fmt.Sprintf(`
			SELECT count(*), encode(sha256(convert_to(COALESCE(
				string_agg(to_jsonb(row_value)::text, E'\n'
					ORDER BY (to_jsonb(row_value)::text) COLLATE "C"), ''
			), 'UTF8')), 'hex')
			FROM %s AS row_value
		`, pgx.Identifier{table}.Sanitize())
		var tableProof recoveredTableProof
		if err := database.QueryRow(context.Background(), query).Scan(&tableProof.count, &tableProof.checksum); err != nil {
			t.Fatalf("collect recovery proof for %s: %v", table, err)
		}
		if tableProof.count == 0 || len(tableProof.checksum) != 64 {
			t.Fatalf("invalid source recovery proof for %s: %+v", table, tableProof)
		}
		proof[table] = tableProof
	}
	return proof
}

func verifyAssetCatalogClosure(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	qualificationSchema qualificationFixtureSchemaState,
) {
	t.Helper()
	verifyCatalogForeignKeyClosure(t, database, qualificationSchema)
	verifyCatalogContentHashes(t, database, fixture)
	verifyCatalogFactCoordinates(t, database, fixture)
	verifyCatalogSourcePointers(t, database, fixture)
	verifyCatalogGovernanceReceipts(t, database, fixture)
	verifyRecoveryAuditOutboxLink(t, database)
}

func verifyCatalogForeignKeyClosure(
	t *testing.T,
	database *pgxpool.Pool,
	qualificationSchema qualificationFixtureSchemaState,
) {
	t.Helper()
	var brokenReferences int64
	if err := database.QueryRow(context.Background(), `
		SELECT
			(SELECT count(*) FROM asset_sources s LEFT JOIN workspaces w
			 ON w.tenant_id=s.tenant_id AND w.id=s.workspace_id WHERE w.id IS NULL) +
			(SELECT count(*) FROM asset_sources s LEFT JOIN asset_source_revisions r
			 ON r.tenant_id=s.tenant_id AND r.workspace_id=s.workspace_id AND r.source_id=s.id
			 AND r.revision=s.published_revision AND r.canonical_revision_digest=s.published_revision_digest
			 WHERE s.published_revision IS NOT NULL AND r.id IS NULL) +
			(SELECT count(*) FROM asset_sources s LEFT JOIN asset_source_runs r
			 ON r.tenant_id=s.tenant_id AND r.workspace_id=s.workspace_id AND r.source_id=s.id
			 AND r.id=s.validated_run_id WHERE s.validated_run_id IS NOT NULL AND r.id IS NULL) +
			(SELECT count(*) FROM asset_sources s LEFT JOIN asset_source_runs r
			 ON r.tenant_id=s.tenant_id AND r.workspace_id=s.workspace_id AND r.source_id=s.id
			 AND r.id=s.last_success_run_id WHERE s.last_success_run_id IS NOT NULL AND r.id IS NULL) +
			(SELECT count(*) FROM asset_sources s LEFT JOIN asset_source_runs r
			 ON r.tenant_id=s.tenant_id AND r.workspace_id=s.workspace_id AND r.source_id=s.id
			 AND r.id=s.last_complete_snapshot_run_id
			 WHERE s.last_complete_snapshot_run_id IS NOT NULL AND r.id IS NULL) +
			(SELECT count(*) FROM asset_source_revisions r LEFT JOIN asset_sources s
			 ON s.tenant_id=r.tenant_id AND s.workspace_id=r.workspace_id AND s.id=r.source_id WHERE s.id IS NULL) +
			(SELECT count(*) FROM asset_source_revision_authorities a LEFT JOIN asset_source_revisions r
			 ON r.tenant_id=a.tenant_id AND r.workspace_id=a.workspace_id AND r.source_id=a.source_id
			 AND r.revision=a.source_revision WHERE r.id IS NULL) +
			(SELECT count(*) FROM asset_source_revision_authorities a LEFT JOIN environments e
			 ON e.tenant_id=a.tenant_id AND e.workspace_id=a.workspace_id AND e.id=a.environment_id
			 WHERE e.id IS NULL) +
			(SELECT count(*) FROM asset_source_revisions r LEFT JOIN integrations i
			 ON i.tenant_id=r.tenant_id AND i.workspace_id=r.workspace_id AND i.id=r.integration_id
			 WHERE r.integration_id IS NOT NULL AND i.id IS NULL) +
			(SELECT count(*) FROM asset_source_revisions r LEFT JOIN asset_source_runs v
			 ON v.tenant_id=r.tenant_id AND v.workspace_id=r.workspace_id AND v.source_id=r.source_id
			 AND v.id=r.validation_run_id WHERE r.validation_run_id IS NOT NULL AND v.id IS NULL) +
			(SELECT count(*) FROM asset_source_runs r LEFT JOIN asset_source_revisions v
			 ON v.tenant_id=r.tenant_id AND v.workspace_id=r.workspace_id AND v.source_id=r.source_id
			 AND v.revision=r.source_revision AND v.canonical_revision_digest=r.source_revision_digest WHERE v.id IS NULL) +
			(SELECT count(*) FROM asset_source_limit_buckets b LEFT JOIN workspaces w
			 ON w.tenant_id=b.tenant_id AND w.id=b.workspace_id WHERE w.id IS NULL) +
			(SELECT count(*) FROM asset_source_limit_buckets b LEFT JOIN asset_sources s
			 ON s.tenant_id=b.tenant_id AND s.workspace_id=b.workspace_id AND s.id=b.source_id
			 WHERE b.source_id IS NOT NULL AND s.id IS NULL) +
			(SELECT count(*) FROM asset_source_limit_buckets b LEFT JOIN asset_source_limit_permits p
			 ON p.tenant_id=b.tenant_id AND p.workspace_id=b.workspace_id AND p.id=b.last_receipt_id
			 WHERE b.last_receipt_id IS NOT NULL AND p.id IS NULL) +
			(SELECT count(*) FROM asset_source_limit_permits p LEFT JOIN asset_sources s
			 ON s.tenant_id=p.tenant_id AND s.workspace_id=p.workspace_id AND s.id=p.source_id
			 AND s.provider_kind=p.provider_kind WHERE s.id IS NULL) +
			(SELECT count(*) FROM asset_source_limit_permits p LEFT JOIN asset_source_runs r
			 ON r.tenant_id=p.tenant_id AND r.workspace_id=p.workspace_id AND r.source_id=p.source_id
			 AND r.id=p.run_id WHERE r.id IS NULL) +
			(SELECT count(*) FROM asset_source_limit_permits p LEFT JOIN asset_source_limit_buckets b
			 ON b.tenant_id=p.tenant_id AND b.workspace_id=p.workspace_id AND b.id=p.source_bucket_id
			 AND b.bucket_kind=p.source_bucket_kind AND b.bucket_key=p.source_bucket_key WHERE b.id IS NULL) +
			(SELECT count(*) FROM asset_source_limit_permits p LEFT JOIN asset_source_limit_buckets b
			 ON b.tenant_id=p.tenant_id AND b.workspace_id=p.workspace_id AND b.id=p.workspace_bucket_id
			 AND b.bucket_kind=p.workspace_bucket_kind AND b.bucket_key=p.workspace_bucket_key WHERE b.id IS NULL) +
			(SELECT count(*) FROM asset_source_limit_permits p LEFT JOIN asset_source_limit_buckets b
			 ON b.tenant_id=p.tenant_id AND b.workspace_id=p.workspace_id AND b.id=p.provider_bucket_id
			 AND b.bucket_kind=p.provider_bucket_kind AND b.bucket_key=p.provider_bucket_key WHERE b.id IS NULL) +
			(SELECT count(*) FROM asset_source_limit_permits p LEFT JOIN asset_source_limit_permits a
			 ON a.tenant_id=p.tenant_id AND a.workspace_id=p.workspace_id AND a.id=p.permit_id
			 AND a.source_id=p.source_id AND a.run_id=p.run_id AND a.provider_kind=p.provider_kind
			 AND a.source_bucket_id=p.source_bucket_id AND a.source_bucket_kind=p.source_bucket_kind
			 AND a.source_bucket_key=p.source_bucket_key
			 AND a.workspace_bucket_id=p.workspace_bucket_id
			 AND a.workspace_bucket_kind=p.workspace_bucket_kind
			 AND a.workspace_bucket_key=p.workspace_bucket_key
			 AND a.provider_bucket_id=p.provider_bucket_id
			 AND a.provider_bucket_kind=p.provider_bucket_kind
			 AND a.provider_bucket_key=p.provider_bucket_key
			 AND a.acquired_at=p.acquired_at AND a.expires_at=p.expires_at WHERE a.id IS NULL) +
			(SELECT count(*) FROM asset_observations o LEFT JOIN environments e
			 ON e.tenant_id=o.tenant_id AND e.workspace_id=o.workspace_id AND e.id=o.environment_id
			 WHERE e.id IS NULL) +
			(SELECT count(*) FROM asset_observations o LEFT JOIN asset_source_runs r
			 ON r.tenant_id=o.tenant_id AND r.workspace_id=o.workspace_id AND r.source_id=o.source_id
			 AND r.id=o.run_id AND r.source_revision=o.source_revision
			 AND r.source_revision_digest=o.canonical_revision_digest WHERE r.id IS NULL) +
			(SELECT count(*) FROM asset_observations o LEFT JOIN asset_sources s
			 ON s.tenant_id=o.tenant_id AND s.workspace_id=o.workspace_id AND s.id=o.source_id
			 AND s.provider_kind=o.provider_kind WHERE s.id IS NULL) +
			(SELECT count(*) FROM asset_observations o LEFT JOIN asset_source_revisions r
			 ON r.tenant_id=o.tenant_id AND r.workspace_id=o.workspace_id AND r.source_id=o.source_id
			 AND r.revision=o.source_revision AND r.canonical_revision_digest=o.canonical_revision_digest
			 WHERE r.id IS NULL) +
			(SELECT count(*) FROM asset_observations o LEFT JOIN asset_observations previous
			 ON previous.tenant_id=o.tenant_id AND previous.workspace_id=o.workspace_id
			 AND previous.environment_id=o.environment_id AND previous.source_id=o.source_id
			 AND previous.provider_kind=o.provider_kind AND previous.external_id=o.external_id
			 AND previous.id=o.previous_observation_id
			 AND previous.observation_chain_sha256=o.previous_chain_sha256
			 WHERE o.previous_observation_id IS NOT NULL AND previous.id IS NULL) +
			(SELECT count(*) FROM assets a LEFT JOIN environments e
			 ON e.tenant_id=a.tenant_id AND e.workspace_id=a.workspace_id AND e.id=a.environment_id
			 WHERE e.id IS NULL) +
			(SELECT count(*) FROM assets a LEFT JOIN asset_sources s
			 ON s.tenant_id=a.tenant_id AND s.workspace_id=a.workspace_id AND s.id=a.source_id
			 AND s.provider_kind=a.provider_kind WHERE s.id IS NULL) +
			(SELECT count(*) FROM assets a LEFT JOIN asset_observations o
			 ON o.tenant_id=a.tenant_id AND o.workspace_id=a.workspace_id AND o.environment_id=a.environment_id
			 AND o.source_id=a.source_id AND o.provider_kind=a.provider_kind AND o.external_id=a.external_id
			 AND o.source_revision=a.last_source_revision AND o.observed_at=a.last_observed_at
			 AND o.observation_chain_sha256=a.last_observation_chain_sha256
			 AND o.id=a.last_observation_id WHERE o.id IS NULL) +
			(SELECT count(*) FROM assets a LEFT JOIN asset_source_revisions r
			 ON r.tenant_id=a.tenant_id AND r.workspace_id=a.workspace_id AND r.source_id=a.source_id
			 AND r.revision=a.last_source_revision WHERE r.id IS NULL) +
			(SELECT count(*) FROM asset_type_details d LEFT JOIN assets a
			 ON a.tenant_id=d.tenant_id AND a.workspace_id=d.workspace_id
			 AND a.environment_id=d.environment_id AND a.source_id=d.source_id
			 AND a.provider_kind=d.provider_kind AND a.external_id=d.external_id
			 AND a.id=d.asset_id WHERE a.id IS NULL) +
			(SELECT count(*) FROM asset_type_details d LEFT JOIN asset_observations o
			 ON o.tenant_id=d.tenant_id AND o.workspace_id=d.workspace_id
			 AND o.environment_id=d.environment_id AND o.source_id=d.source_id
			 AND o.provider_kind=d.provider_kind AND o.external_id=d.external_id
			 AND o.source_revision=d.source_revision AND o.observed_at=d.source_observed_at
			 AND o.observation_chain_sha256=d.source_observation_chain_sha256
			 AND o.id=d.source_observation_id WHERE o.id IS NULL) +
			(SELECT count(*) FROM asset_conflicts c LEFT JOIN assets a
			 ON a.tenant_id=c.tenant_id AND a.workspace_id=c.workspace_id AND a.environment_id=c.environment_id AND a.id=c.asset_id WHERE a.id IS NULL) +
			(SELECT count(*) FROM asset_conflicts c LEFT JOIN assets a
			 ON a.tenant_id=c.tenant_id AND a.workspace_id=c.workspace_id AND a.environment_id=c.environment_id
			 AND a.id=c.candidate_asset_id WHERE c.candidate_asset_id IS NOT NULL AND a.id IS NULL) +
			(SELECT count(*) FROM asset_conflicts c LEFT JOIN asset_observations o
			 ON o.tenant_id=c.tenant_id AND o.workspace_id=c.workspace_id AND o.environment_id=c.environment_id
			 AND o.source_id=c.source_id AND o.id=c.observation_id WHERE o.id IS NULL) +
			(SELECT count(*) FROM asset_conflicts c LEFT JOIN services s
			 ON s.tenant_id=c.tenant_id AND s.workspace_id=c.workspace_id AND s.id=c.candidate_service_id
			 WHERE c.candidate_service_id IS NOT NULL AND s.id IS NULL) +
			(SELECT count(*) FROM asset_relationships r LEFT JOIN asset_source_revisions v
			 ON v.tenant_id=r.tenant_id AND v.workspace_id=r.workspace_id AND v.source_id=r.source_id
			 AND v.revision=r.source_revision AND v.canonical_revision_digest=r.canonical_revision_digest
			 WHERE v.id IS NULL) +
			(SELECT count(*) FROM asset_relationships r LEFT JOIN asset_source_runs run
			 ON run.tenant_id=r.tenant_id AND run.workspace_id=r.workspace_id AND run.source_id=r.source_id
			 AND run.id=r.last_run_id AND run.source_revision=r.source_revision
			 AND run.source_revision_digest=r.canonical_revision_digest WHERE run.id IS NULL) +
			(SELECT count(*) FROM asset_relationships r LEFT JOIN assets a
			 ON a.tenant_id=r.tenant_id AND a.workspace_id=r.workspace_id
			 AND a.environment_id=r.source_environment_id AND a.source_id=r.source_id
			 AND a.external_id=r.from_external_id AND a.id=r.source_asset_id WHERE a.id IS NULL) +
			(SELECT count(*) FROM asset_relationships r LEFT JOIN assets a
			 ON a.tenant_id=r.tenant_id AND a.workspace_id=r.workspace_id
			 AND a.environment_id=r.target_environment_id AND a.source_id=r.source_id
			 AND a.external_id=r.to_external_id AND a.id=r.target_asset_id WHERE a.id IS NULL) +
			(SELECT count(*) FROM asset_relationships r LEFT JOIN asset_sources s
			 ON s.tenant_id=r.tenant_id AND s.workspace_id=r.workspace_id AND s.id=r.provenance_source_id
			 WHERE r.provenance_source_id IS NOT NULL AND s.id IS NULL) +
			(SELECT count(*) FROM service_asset_bindings b LEFT JOIN services s
			 ON s.tenant_id=b.tenant_id AND s.workspace_id=b.workspace_id AND s.id=b.service_id
			 WHERE s.id IS NULL) +
			(SELECT count(*) FROM service_asset_bindings b LEFT JOIN service_bindings s
			 ON s.service_id=b.service_id AND s.environment_id=b.environment_id WHERE s.service_id IS NULL) +
			(SELECT count(*) FROM service_asset_bindings b LEFT JOIN assets a
			 ON a.tenant_id=b.tenant_id AND a.workspace_id=b.workspace_id AND a.environment_id=b.environment_id
			 AND a.id=b.asset_id WHERE a.id IS NULL) +
			(SELECT count(*) FROM service_asset_bindings b LEFT JOIN assets a
			 ON a.tenant_id=b.tenant_id AND a.workspace_id=b.workspace_id
			 AND a.environment_id=b.environment_id AND a.source_id=b.provenance_source_id
			 AND a.id=b.asset_id WHERE b.provenance_source_id IS NOT NULL AND a.id IS NULL)
	`).Scan(&brokenReferences); err != nil {
		t.Fatalf("verify asset catalog foreign-key closure: %v", err)
	}
	if brokenReferences != 0 {
		t.Fatalf("asset catalog has %d broken parent references", brokenReferences)
	}

	var foreignKeys, invalidForeignKeys int64
	if err := database.QueryRow(context.Background(), `
		SELECT count(*), count(*) FILTER (
			WHERE NOT constraint_record.convalidated OR NOT constraint_record.conenforced
		)
		FROM pg_catalog.pg_constraint AS constraint_record
		JOIN pg_catalog.pg_class AS relation ON relation.oid=constraint_record.conrelid
		JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=relation.relnamespace
		WHERE namespace.nspname='public'
		  AND relation.relname = ANY($1::text[])
		  AND constraint_record.contype='f'
	`, []string{
		"asset_sources", "asset_source_revisions", "asset_source_revision_authorities",
		"asset_source_runs", "asset_source_limit_buckets", "asset_source_limit_permits",
		"asset_observations",
		"assets", "asset_type_details", "asset_conflicts", "asset_relationships", "service_asset_bindings",
	}).Scan(&foreignKeys, &invalidForeignKeys); err != nil {
		t.Fatalf("verify restored foreign-key validation state: %v", err)
	}
	expectedForeignKeys := int64(44)
	if qualificationSchema == qualificationFixtureSchemaFull {
		expectedForeignKeys = 45
	}
	if foreignKeys != expectedForeignKeys || invalidForeignKeys != 0 {
		t.Fatalf(
			"asset catalog foreign keys=(total:%d unvalidated:%d), want (%d,0) for %s qualification schema",
			foreignKeys,
			invalidForeignKeys,
			expectedForeignKeys,
			qualificationSchema,
		)
	}
}

func verifyRecoveryAuditOutboxLink(t *testing.T, database *pgxpool.Pool) {
	t.Helper()
	var auditOutboxLinked bool
	if err := database.QueryRow(context.Background(), `
		SELECT EXISTS (
			SELECT 1
			FROM audit_records AS audit
			JOIN outbox_events AS event
			  ON event.tenant_id = audit.tenant_id
			 AND event.workspace_id = audit.workspace_id
			 AND event.aggregate_id::text = audit.resource_id
			WHERE audit.request_id = 'recovery-audit'
			  AND event.payload->>'audit_request_id' = audit.request_id
			  AND audit.payload_hash = encode(sha256(convert_to(event.payload::text,'UTF8')),'hex')
		)
	`).Scan(&auditOutboxLinked); err != nil {
		t.Fatalf("verify restored audit/outbox linkage: %v", err)
	}
	if !auditOutboxLinked {
		t.Fatal("asset catalog audit/outbox proof is not content-linked")
	}
}

func verifyCatalogContentHashes(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
) {
	t.Helper()
	authorityDigest := assetCatalogCorrectiveFramedDigest(
		[]byte("asset-source-authority-scope.v1"),
		[]byte("1"),
		[]byte(fixture.environmentID),
	)
	var badHashes int64
	if err := database.QueryRow(context.Background(), `
		SELECT
			(SELECT count(*) FROM asset_source_revisions WHERE
				encode(sha256(canonical_profile_manifest),'hex')<>profile_manifest_sha256 OR
				encode(sha256(canonical_provider_schema),'hex')<>canonical_provider_schema_sha256 OR
				asset_catalog_source_revision_binding_digest(asset_source_revisions)<>canonical_revision_digest) +
			(SELECT CASE WHEN count(*)=1 AND bool_and(
				authority_scope_digest=$2 AND source_definition_digest=$3 AND canonical_revision_digest=$4
			) THEN 0 ELSE 1 END
			 FROM asset_source_revisions WHERE source_id=$1) +
			(SELECT count(*) FROM asset_observations WHERE encode(sha256(normalized_document),'hex')<>document_sha256
			 OR encode(sha256(field_provenance),'hex')<>field_provenance_sha256) +
			(SELECT count(*) FROM asset_type_details WHERE encode(sha256(details_document),'hex')<>details_sha256) +
			(SELECT count(*) FROM asset_sources WHERE checkpoint_ciphertext IS NOT NULL
				AND encode(sha256(checkpoint_ciphertext),'hex')<>checkpoint_sha256) +
			(SELECT count(*) FROM asset_source_runs WHERE
				(page_digest IS NOT NULL AND NOT asset_catalog_sha256_valid(page_digest)) OR
				(relation_page_digest IS NOT NULL AND NOT asset_catalog_sha256_valid(relation_page_digest))) +
			(SELECT count(*) FROM asset_relationships WHERE
				NOT asset_catalog_sha256_valid(relation_page_sha256) OR
				NOT asset_catalog_sha256_valid(provider_version_sha256) OR
				NOT asset_catalog_sha256_valid(relation_fact_sha256))
	`, fixture.sourceID, authorityDigest, fixture.sourceDefinitionDigest, fixture.revisionDigest).Scan(&badHashes); err != nil {
		t.Fatalf("verify asset catalog SHA-256 equality: %v", err)
	}
	if badHashes != 0 {
		t.Fatalf("asset catalog has %d invalid content hashes", badHashes)
	}
}

func verifyCatalogFactCoordinates(t *testing.T, database *pgxpool.Pool, fixture assetCatalogFixture) {
	t.Helper()
	var observationFactsValid bool
	if err := database.QueryRow(context.Background(), `
		SELECT count(*)=2 AND bool_and(
			o.freshness_kind='CATALOG_SEQUENCE' AND o.freshness_order_time IS NULL AND
			o.freshness_order_sequence=1 AND o.accepted_checkpoint_version=1 AND
			o.run_fence_epoch=1 AND o.run_page_sequence=1 AND o.source_revision=1 AND
			o.canonical_revision_digest=$2 AND
			asset_catalog_sha256_valid(o.provider_version_sha256) AND
			asset_catalog_sha256_valid(o.provider_fact_sha256) AND
			asset_catalog_sha256_valid(o.fingerprint_sha256) AND
			asset_catalog_sha256_valid(o.provider_provenance_sha256) AND
			asset_catalog_sha256_valid(o.observation_chain_sha256)
		)
		FROM asset_observations AS o
		WHERE o.source_id=$1
	`, fixture.sourceID, fixture.revisionDigest).Scan(&observationFactsValid); err != nil {
		t.Fatalf("verify restored observation freshness/chain coordinates: %v", err)
	}
	if !observationFactsValid {
		t.Fatal("restored observation freshness/chain coordinates are incomplete")
	}

	var relationshipValid, typeDetailValid bool
	if err := database.QueryRow(context.Background(), `
		SELECT r.last_run_id=$2 AND r.last_page_sequence=1 AND
			r.relation_page_sha256=repeat('6',64) AND r.freshness_kind='CATALOG_SEQUENCE' AND
			r.freshness_order_time IS NULL AND r.freshness_order_sequence=1 AND
			r.accepted_checkpoint_version=1 AND r.run_fence_epoch=1 AND
			r.source_revision=1 AND r.canonical_revision_digest=$3
		FROM asset_relationships AS r WHERE r.id=$1
	`, fixture.relationshipID, fixture.runID, fixture.revisionDigest).Scan(&relationshipValid); err != nil {
		t.Fatalf("verify restored relationship exact coordinates: %v", err)
	}
	if err := database.QueryRow(context.Background(), `
		SELECT d.asset_id=$2 AND d.source_id=$3 AND d.provider_kind='MANUAL_V1' AND
			d.external_id='manual-host-a' AND d.source_revision=1 AND
			d.source_observation_id=$4 AND
			d.source_observed_at=o.observed_at AND
			d.source_observation_chain_sha256=o.observation_chain_sha256 AND
			a.source_id=d.source_id AND a.provider_kind=d.provider_kind AND a.external_id=d.external_id
		FROM asset_type_details d
		JOIN asset_observations o ON o.id=d.source_observation_id
		JOIN assets a ON a.id=d.asset_id
		WHERE d.id=$1
	`, fixture.typeDetailID, fixture.assetID, fixture.sourceID, fixture.observationID).Scan(&typeDetailValid); err != nil {
		t.Fatalf("verify restored type-detail exact identity: %v", err)
	}
	if !relationshipValid || !typeDetailValid {
		t.Fatalf("restored relationship/type-detail coordinates valid=(%v,%v)", relationshipValid, typeDetailValid)
	}
}

func verifyCatalogSourcePointers(t *testing.T, database *pgxpool.Pool, fixture assetCatalogFixture) {
	t.Helper()
	var pointersValid bool
	if err := database.QueryRow(context.Background(), `
		SELECT s.published_revision=1 AND s.published_revision_digest=$3 AND
			r.state='PUBLISHED' AND s.gate_status='AVAILABLE' AND
			s.validated_run_id=$4 AND s.validation_digest IS NOT NULL AND
			s.validated_binding_digest=$3 AND
			s.last_success_run_id=$5 AND s.last_success_at=success.completed_at AND
			s.last_complete_snapshot_run_id IS NULL AND
			s.last_complete_snapshot_at IS NULL AND
			success.status='SUCCEEDED' AND success.run_kind IN (
				'DISCOVERY','CSV_IMPORT','API_INGESTION','MANUAL_MUTATION'
			) AND
			NOT success.complete_snapshot AND NOT success.effective_complete_snapshot AND
			a.lifecycle='ACTIVE' AND a.version=2
		FROM asset_sources s
		JOIN asset_source_revisions r ON r.tenant_id=s.tenant_id AND r.workspace_id=s.workspace_id
		 AND r.source_id=s.id AND r.revision=s.published_revision
		 AND r.canonical_revision_digest=s.published_revision_digest
		JOIN asset_source_runs success ON success.id=s.last_success_run_id
		JOIN assets a ON a.id=$2
		WHERE s.id=$1
	`, fixture.sourceID, fixture.assetID, fixture.revisionDigest,
		fixture.validationRunID, fixture.runID).Scan(&pointersValid); err != nil {
		t.Fatalf("verify restored source publication/success pointers: %v", err)
	}
	if !pointersValid {
		t.Fatal("restored source publication/success pointers are not exact")
	}
}

func verifyCatalogGovernanceReceipts(t *testing.T, database *pgxpool.Pool, fixture assetCatalogFixture) {
	t.Helper()
	var closureValid bool
	if err := database.QueryRow(context.Background(), `
		SELECT
			(SELECT count(*)=2
			 FROM asset_source_runs AS run
			 JOIN audit_records AS audit
			   ON audit.tenant_id=run.tenant_id
			  AND audit.workspace_id=run.workspace_id
			  AND audit.action='TERMINAL_COMMITTED'
			  AND audit.actor_type='SYSTEM' AND audit.actor_id=run.lease_owner
			  AND audit.resource_type='ASSET_SOURCE_RUN'
			  AND audit.resource_id=run.id::text
			  AND audit.request_id='source-terminal:'||run.id::text
			  AND audit.payload_hash=run.terminal_command_sha256
			 WHERE run.id IN ($2::uuid,$3::uuid)
			   AND run.terminal_command_sha256=
			       asset_catalog_source_run_terminal_digest(run,run.status,run.failure_code))
		AND
			(SELECT count(*)=2
			 FROM asset_source_runs AS run
			 JOIN audit_records AS audit
			   ON audit.tenant_id=run.tenant_id
			  AND audit.workspace_id=run.workspace_id
			  AND audit.action='ATTEMPT_CLEANED'
			  AND audit.actor_type='SYSTEM' AND audit.actor_id=run.lease_owner
			  AND audit.resource_type='ASSET_SOURCE_RUN'
			  AND audit.resource_id=run.id::text
			  AND audit.request_id='source-attempt:'||run.id::text||':0'
			  AND audit.payload_hash=run.cleanup_digest
			 WHERE run.id IN ($2::uuid,$3::uuid)
			   AND run.cleanup_status='NO_CREDENTIAL'
			   AND run.cleanup_digest=asset_catalog_source_run_no_credential_digest(run))
		AND EXISTS (
			SELECT 1
			FROM asset_source_runs AS run
			JOIN asset_sources AS source ON source.id=run.source_id
			JOIN audit_records AS page_audit
			  ON page_audit.tenant_id=run.tenant_id
			 AND page_audit.workspace_id=run.workspace_id
			 AND page_audit.action='PAGE_APPLIED'
			 AND page_audit.actor_type='SYSTEM' AND page_audit.actor_id=run.lease_owner
			 AND page_audit.resource_type='ASSET_SOURCE_RUN'
			 AND page_audit.resource_id=run.id::text
			 AND page_audit.request_id='source-page:'||run.id::text||':'||run.page_sequence::text
			 AND page_audit.payload_hash=run.page_digest
			JOIN audit_records AS relation_audit
			  ON relation_audit.tenant_id=run.tenant_id
			 AND relation_audit.workspace_id=run.workspace_id
			 AND relation_audit.action='RELATION_PAGE_COMMITTED'
			 AND relation_audit.actor_type='SYSTEM' AND relation_audit.actor_id=run.lease_owner
			 AND relation_audit.resource_type='ASSET_SOURCE_RUN'
			 AND relation_audit.resource_id=run.id::text
			 AND relation_audit.request_id='source-relation-page:'||run.id::text||':'||run.relation_page_sequence::text
			 AND relation_audit.payload_hash=run.relation_page_digest
			WHERE run.id=$3
			  AND source.id=$1
			  AND run.page_sequence=1 AND run.relation_page_sequence=1
			  AND run.checkpoint_version=1 AND source.checkpoint_version=1
			  AND run.observed_count=2
			  AND (SELECT count(*) FROM asset_observations AS observation
			       WHERE observation.run_id=run.id
			         AND observation.run_page_sequence=run.page_sequence
			         AND observation.accepted_checkpoint_version=run.checkpoint_version)=2
			  AND EXISTS (
				SELECT 1 FROM asset_relationships AS relationship
				WHERE relationship.id=$4
				  AND relationship.last_run_id=run.id
				  AND relationship.last_page_sequence=run.relation_page_sequence
				  AND relationship.relation_page_sha256=run.relation_page_digest
				  AND relationship.accepted_checkpoint_version=run.checkpoint_version
				  AND relationship.run_fence_epoch=run.fence_epoch
			  )
		)
	`, fixture.sourceID, fixture.validationRunID, fixture.runID,
		fixture.relationshipID).Scan(&closureValid); err != nil {
		t.Fatalf("verify restored terminal/cleanup/page governance receipts: %v", err)
	}
	if !closureValid {
		t.Fatal("restored terminal/cleanup/page governance receipts are not exact")
	}
}
