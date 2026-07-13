package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAssetCatalogRuntimeRejectsCrossScopeAndDriftedExactFacts(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)

	t.Run("binding cannot cross workspace", func(t *testing.T) {
		expectRuntimeContractError(t, harness.db, "23503", "", `
			INSERT INTO service_asset_bindings (
				id,tenant_id,workspace_id,environment_id,service_id,asset_id,binding_role,
				mapping_status,provenance,provenance_source_id,status,idempotency_key,
				request_hash,version
			)
			SELECT '81000000-0000-4000-8000-000000000001',tenant_id,
				'81000000-0000-4000-8000-000000000099',environment_id,service_id,asset_id,
				binding_role,mapping_status,provenance,provenance_source_id,status,
				'cross-workspace-binding',repeat('1',64),1
			FROM service_asset_bindings WHERE id=$1
		`, fixture.bindingID)
	})

	t.Run("type detail cannot cross environment", func(t *testing.T) {
		expectRuntimeContractError(t, harness.db, "23503", "", `
			INSERT INTO asset_type_details (
				id,tenant_id,workspace_id,environment_id,asset_id,source_id,provider_kind,
				external_id,source_revision,source_observed_at,source_observation_chain_sha256,
				revision,schema_version,source_observation_id,details_document,details_sha256,actor_id
			)
			SELECT '81000000-0000-4000-8000-000000000002',tenant_id,workspace_id,
				'81000000-0000-4000-8000-000000000098',asset_id,source_id,provider_kind,
				external_id,source_revision,source_observed_at,source_observation_chain_sha256,
				revision+100,schema_version,source_observation_id,details_document,details_sha256,
				'runtime-contract'
			FROM asset_type_details WHERE id=$1
		`, fixture.typeDetailID)
	})

	t.Run("type detail must bind the exact observation chain", func(t *testing.T) {
		expectRuntimeContractError(t, harness.db, "23503", "", `
			INSERT INTO asset_type_details (
				id,tenant_id,workspace_id,environment_id,asset_id,source_id,provider_kind,
				external_id,source_revision,source_observed_at,source_observation_chain_sha256,
				revision,schema_version,source_observation_id,details_document,details_sha256,actor_id
			)
			SELECT '81000000-0000-4000-8000-000000000003',tenant_id,workspace_id,
				environment_id,asset_id,source_id,provider_kind,external_id,source_revision,
				source_observed_at,repeat('f',64),revision+101,schema_version,
				source_observation_id,details_document,details_sha256,'runtime-contract'
			FROM asset_type_details WHERE id=$1
		`, fixture.typeDetailID)
	})

	t.Run("conflict source and observation are one exact edge", func(t *testing.T) {
		expectRuntimeContractError(t, harness.db, "23503", "", `
			INSERT INTO asset_conflicts (
				id,tenant_id,workspace_id,environment_id,asset_id,candidate_asset_id,
				candidate_service_id,source_id,observation_id,conflict_type,field_name,
				existing_value_sha256,candidate_value_sha256,status,resolution,
				resolution_reason_code,resolved_by,resolved_at,resolution_idempotency_key,
				resolution_request_hash,version
			)
			SELECT '81000000-0000-4000-8000-000000000004',tenant_id,workspace_id,
				environment_id,asset_id,candidate_asset_id,candidate_service_id,
				'81000000-0000-4000-8000-000000000097',observation_id,conflict_type,
				field_name,existing_value_sha256,candidate_value_sha256,'OPEN',NULL,NULL,
				NULL,NULL,NULL,NULL,1
			FROM asset_conflicts WHERE id=$1
		`, fixture.conflictID)
	})
}

func TestAssetCatalogRuntimeRejectsUnknownKindIdentityAndInvalidJSON(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)

	t.Run("unknown asset kind", func(t *testing.T) {
		expectRuntimeContractError(t, harness.db, "23514", "assets_kind_check", `
			INSERT INTO assets (
				id,tenant_id,workspace_id,environment_id,source_id,provider_kind,external_id,
				kind,display_name,owner_group,criticality,data_classification,labels,lifecycle,
				mapping_status,last_observation_id,last_observation_chain_sha256,last_observed_at,
				last_source_revision,create_idempotency_key,create_request_hash,version
			)
			SELECT '82000000-0000-4000-8000-000000000001',tenant_id,workspace_id,
				environment_id,source_id,provider_kind,external_id,'UNREVIEWED_KIND',display_name,
				owner_group,criticality,data_classification,labels,'DISCOVERED',mapping_status,
				last_observation_id,last_observation_chain_sha256,last_observed_at,
				last_source_revision,'unknown-kind-runtime',repeat('2',64),1
			FROM assets WHERE id=$1
		`, fixture.assetID)
	})

	identityCases := []struct {
		name       string
		id         string
		provider   string
		sourceName string
		requestKey string
		constraint string
	}{
		{"lowercase provider", "82000000-0000-4000-8000-000000000002", "external", "runtime-source", "runtime-source-provider", "asset_sources_provider_kind_check"},
		{"untrimmed name", "82000000-0000-4000-8000-000000000003", "EXTERNAL_V1", " runtime-source ", "runtime-source-name", "asset_sources_name_check"},
		{"noncanonical idempotency key", "82000000-0000-4000-8000-000000000004", "EXTERNAL_V1", "runtime-source", "UPPERCASE_KEY", "asset_sources_create_idempotency_key_check"},
	}
	for _, test := range identityCases {
		t.Run(test.name, func(t *testing.T) {
			expectRuntimeContractError(t, harness.db, "23514", test.constraint, `
				INSERT INTO asset_sources (
					id,tenant_id,workspace_id,source_kind,provider_kind,name,
					create_idempotency_key,create_request_hash
				) VALUES ($1,$2,$3,'EXTERNAL_CMDB',$4,$5,$6,repeat('3',64))
			`, test.id, fixture.tenantID, fixture.workspaceID, test.provider,
				test.sourceName, test.requestKey)
		})
	}

	for _, raw := range []string{
		`{"kind":"LINUX_VM","kind":"WINDOWS_VM"}`,
		`{"labels":{"owner":"sre","owner":"platform"}}`,
	} {
		var valid bool
		if err := harness.db.QueryRow(context.Background(), `
			SELECT asset_catalog_json_object_valid(convert_to($1,'UTF8'),2,65536)
		`, raw).Scan(&valid); err != nil {
			t.Fatalf("validate duplicate-key JSON: %v", err)
		}
		if valid {
			t.Errorf("duplicate-key JSON was accepted: %s", raw)
		}
	}

	t.Run("labels pair limit", func(t *testing.T) {
		expectRuntimeContractError(t, harness.db, "23514", "assets_labels_ck", `
			UPDATE assets
			SET labels=(
				SELECT jsonb_object_agg('key-'||value,value::text)
				FROM generate_series(1,65) AS value
			),version=version+1
			WHERE id=$1
		`, fixture.assetID)
	})
}

func TestAssetCatalogRuntimeObservationFreshnessAndReplayGuards(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)

	t.Run("valid tombstone keeps no document", func(t *testing.T) {
		withRuntimeContractManualRun(t, harness.db, fixture, func(tx pgx.Tx, run runtimeContractRun) {
			candidate := newRuntimeObservation(fixture, run,
				"83000000-0000-4000-8000-000000000001", "runtime-tombstone", "1")
			candidate.document = nil
			candidate.tombstone = true
			candidate.reason = "PROVIDER_REMOVED"
			if _, err := tx.Exec(context.Background(), insertRuntimeObservationSQL,
				runtimeObservationArguments(candidate)...); err != nil {
				t.Fatalf("insert positive observation admission assertion: %v", err)
			}
		})
	})

	tombstoneCases := []struct {
		name      string
		document  any
		tombstone bool
		reason    any
	}{
		{"live fact requires document", nil, false, nil},
		{"tombstone forbids document", `{"display_name":"removed"}`, true, "PROVIDER_REMOVED"},
		{"tombstone requires reason", nil, true, nil},
	}
	for index, test := range tombstoneCases {
		t.Run(test.name, func(t *testing.T) {
			expectRuntimeManualObservationError(t, harness.db, fixture,
				fmt.Sprintf("83000000-0000-4000-8000-%012d", index+10),
				fmt.Sprintf("runtime-tombstone-invalid-%d", index), fmt.Sprintf("%x", index+2),
				"23514", "asset_observations_document_ck", func(candidate *runtimeObservation) {
					candidate.document = test.document
					candidate.tombstone = test.tombstone
					candidate.reason = test.reason
				})
		})
	}

	t.Run("manual source rejects provider freshness", func(t *testing.T) {
		expectRuntimeManualObservationError(t, harness.db, fixture,
			"83000000-0000-4000-8000-000000000020", "runtime-provider-freshness", "5",
			"23514", "asset_observations_freshness_profile_guard", func(candidate *runtimeObservation) {
				candidate.freshnessKind = "OBJECT_SEQUENCE"
			})
	})

	t.Run("catalog sequence has no provider time", func(t *testing.T) {
		expectRuntimeManualObservationError(t, harness.db, fixture,
			"83000000-0000-4000-8000-000000000021", "runtime-catalog-time", "6",
			"23514", "asset_observations_freshness_ck", func(candidate *runtimeObservation) {
				candidate.freshnessTime = time.Now().UTC()
			})
	})

	t.Run("catalog sequence equals next checkpoint", func(t *testing.T) {
		expectRuntimeManualObservationError(t, harness.db, fixture,
			"83000000-0000-4000-8000-000000000022", "runtime-sequence-drift", "7",
			"23514", "asset_observations_catalog_sequence_guard", func(candidate *runtimeObservation) {
				candidate.freshnessSequence++
			})
	})

	t.Run("source definition digest is exact", func(t *testing.T) {
		expectRuntimeManualObservationError(t, harness.db, fixture,
			"83000000-0000-4000-8000-000000000023", "runtime-definition-drift", "8",
			"23503", "asset_observations_source_revision_fk", func(candidate *runtimeObservation) {
				candidate.sourceDefinitionDigest = strings.Repeat("f", 64)
			})
	})

	t.Run("fence and page coordinates are exact", func(t *testing.T) {
		expectRuntimeManualObservationError(t, harness.db, fixture,
			"83000000-0000-4000-8000-000000000024", "runtime-fence-drift", "9",
			"55000", "asset_observations_live_run_guard", func(candidate *runtimeObservation) {
				candidate.runFenceEpoch++
			})
	})

	t.Run("previous chain equals locked projection", func(t *testing.T) {
		var externalID string
		if err := harness.db.QueryRow(context.Background(), `
			SELECT external_id FROM assets WHERE id=$1
		`, fixture.assetID).Scan(&externalID); err != nil {
			t.Fatalf("read projected asset external id: %v", err)
		}
		expectRuntimeManualObservationError(t, harness.db, fixture,
			"83000000-0000-4000-8000-000000000025", externalID, "a",
			"55000", "asset_observations_previous_projection_guard", func(candidate *runtimeObservation) {
				candidate.previousID = fixture.observationID
				candidate.previousChain = strings.Repeat("e", 64)
			})
	})

	t.Run("same run object appears at most once", func(t *testing.T) {
		withRuntimeContractManualRun(t, harness.db, fixture, func(tx pgx.Tx, run runtimeContractRun) {
			first := newRuntimeObservation(fixture, run,
				"83000000-0000-4000-8000-000000000026", "runtime-same-run", "b")
			second := newRuntimeObservation(fixture, run,
				"83000000-0000-4000-8000-000000000027", "runtime-same-run", "c")
			if _, err := tx.Exec(context.Background(), insertRuntimeObservationSQL,
				runtimeObservationArguments(first)...); err != nil {
				t.Fatalf("insert first same-run observation: %v", err)
			}
			_, err := tx.Exec(context.Background(), insertRuntimeObservationSQL,
				runtimeObservationArguments(second)...)
			assertRuntimePostgresError(t, err, "23505", "asset_observations_same_run_object_uk")
		})
	})
}

func TestAssetCatalogRuntimeRejectsPhysicalDeleteAndTruncate(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)

	rows := []struct {
		table string
		id    string
	}{
		{"asset_sources", fixture.sourceID},
		{"asset_source_revisions", fixture.revisionID},
		{"asset_source_runs", fixture.runID},
		{"asset_observations", fixture.observationID},
		{"assets", fixture.assetID},
		{"asset_type_details", fixture.typeDetailID},
		{"asset_conflicts", fixture.conflictID},
		{"asset_relationships", fixture.relationshipID},
		{"service_asset_bindings", fixture.bindingID},
	}
	for _, row := range rows {
		t.Run("delete "+row.table, func(t *testing.T) {
			expectRuntimeContractError(t, harness.db, "55000", row.table+"_delete_guard",
				fmt.Sprintf("DELETE FROM %s WHERE id=$1", row.table), row.id)
		})
		t.Run("truncate "+row.table, func(t *testing.T) {
			expectRuntimeContractError(t, harness.db, "55000", row.table+"_truncate_guard",
				fmt.Sprintf("TRUNCATE TABLE %s CASCADE", row.table))
		})
	}
}

func TestAssetCatalogRuntimeLifecycleAndRetirement(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)

	var lifecycle string
	if err := harness.db.QueryRow(context.Background(), `
		SELECT lifecycle FROM assets WHERE id=$1
	`, fixture.assetID).Scan(&lifecycle); err != nil {
		t.Fatalf("read asset lifecycle: %v", err)
	}
	invalidTarget := map[string]string{
		"DISCOVERED":  "STALE",
		"ACTIVE":      "DISCOVERED",
		"STALE":       "DISCOVERED",
		"QUARANTINED": "STALE",
		"RETIRED":     "ACTIVE",
	}[lifecycle]
	if invalidTarget == "" {
		t.Fatalf("unexpected fixture lifecycle %q", lifecycle)
	}
	invalidState := "23514"
	invalidConstraint := "assets_lifecycle_guard"
	if lifecycle == "RETIRED" {
		invalidState = "55000"
		invalidConstraint = "assets_retired_terminal_guard"
	}
	expectRuntimeContractError(t, harness.db, invalidState, invalidConstraint, `
		UPDATE assets SET lifecycle=$1,version=version+1 WHERE id=$2
	`, invalidTarget, fixture.assetID)

	if lifecycle != "RETIRED" {
		execAssetSQL(t, harness.db, `
			UPDATE assets SET lifecycle='RETIRED',version=version+1 WHERE id=$1
		`, fixture.assetID)
	}
	expectRuntimeContractError(t, harness.db, "55000", "assets_retired_terminal_guard", `
		UPDATE assets SET lifecycle='ACTIVE',version=version+1 WHERE id=$1
	`, fixture.assetID)
}

func TestAssetCatalogRuntimeConcurrentCASAllowsOneWriter(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)

	var expectedVersion int64
	if err := harness.db.QueryRow(context.Background(), `
		SELECT version FROM assets WHERE id=$1
	`, fixture.assetID).Scan(&expectedVersion); err != nil {
		t.Fatalf("read asset version: %v", err)
	}

	type writeResult struct {
		rows int64
		err  error
	}
	results := make([]writeResult, 2)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for index := range results {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			tag, err := harness.db.Exec(ctx, `
				UPDATE assets
				SET owner_group=$1,version=version+1
				WHERE id=$2 AND version=$3
			`, fmt.Sprintf("runtime-writer-%d", index+1), fixture.assetID, expectedVersion)
			results[index] = writeResult{rows: tag.RowsAffected(), err: err}
		}(index)
	}
	close(start)
	workers.Wait()

	var affected int64
	for index, result := range results {
		if result.err != nil {
			t.Errorf("concurrent writer %d: %v", index+1, result.err)
		}
		affected += result.rows
	}
	if affected != 1 {
		t.Fatalf("concurrent CAS affected %d rows, want exactly one", affected)
	}
	var actualVersion int64
	if err := harness.db.QueryRow(context.Background(), `
		SELECT version FROM assets WHERE id=$1
	`, fixture.assetID).Scan(&actualVersion); err != nil {
		t.Fatalf("read asset version after concurrent writes: %v", err)
	}
	if actualVersion != expectedVersion+1 {
		t.Errorf("asset version=%d, want %d", actualVersion, expectedVersion+1)
	}
}

func TestAssetCatalogRuntimeSuccessPointersCannotRegressOrDrift(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)

	var lastSuccessID, lastCompleteID *string
	var lastSuccessAt, lastCompleteAt *time.Time
	if err := harness.db.QueryRow(context.Background(), `
		SELECT last_success_run_id::text,last_success_at,
			last_complete_snapshot_run_id::text,last_complete_snapshot_at
		FROM asset_sources WHERE id=$1
	`, fixture.sourceID).Scan(&lastSuccessID, &lastSuccessAt, &lastCompleteID, &lastCompleteAt); err != nil {
		t.Fatalf("read source success pointers: %v", err)
	}
	if lastSuccessID == nil || lastSuccessAt == nil {
		t.Fatal("governed MANUAL_MUTATION fixture must include its exact success pointer")
	}
	if lastCompleteID != nil || lastCompleteAt != nil {
		t.Fatal("MANUAL_MUTATION is not an authoritative complete snapshot")
	}

	expectRuntimeContractError(t, harness.db, "23514", "asset_sources_last_success_guard", `
		UPDATE asset_sources
		SET last_success_at=last_success_at-interval '1 microsecond',version=version+1
		WHERE id=$1
	`, fixture.sourceID)
	expectRuntimeContractError(t, harness.db, "23514", "asset_sources_last_complete_snapshot_guard", `
		UPDATE asset_sources
		SET last_complete_snapshot_run_id=$2,
			last_complete_snapshot_at=(SELECT completed_at FROM asset_source_runs WHERE id=$2),
			version=version+1
		WHERE id=$1
	`, fixture.sourceID, fixture.runID)
	expectRuntimeContractError(t, harness.db, "23514", "asset_sources_last_success_guard", `
		UPDATE asset_sources AS source
		SET last_success_run_id=source.validated_run_id,
			last_success_at=(
				SELECT run.completed_at FROM asset_source_runs AS run
				WHERE run.id=source.validated_run_id
			),version=source.version+1
		WHERE source.id=$1
	`, fixture.sourceID)
	expectRuntimeContractError(t, harness.db, "23514", "asset_sources_last_success_ck", `
		UPDATE asset_sources SET last_success_at=NULL,version=version+1 WHERE id=$1
	`, fixture.sourceID)
}

type runtimeContractRun struct {
	id                     string
	revision               int64
	revisionDigest         string
	sourceDefinitionDigest string
	providerKind           string
	checkpointVersion      int64
	fenceEpoch             int64
	pageSequence           int64
}

func startRuntimeContractManualRun(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
) runtimeContractRun {
	t.Helper()
	run := runtimeContractRun{id: "83f00000-0000-4000-8000-000000000001"}
	var gateRevision int64
	var checkpointSHA *string
	var sourceKind string
	if err := database.QueryRow(context.Background(), `
		SELECT source.published_revision,source.published_revision_digest,
			revision.source_definition_digest,source.gate_revision,
			source.checkpoint_version,source.checkpoint_sha256,source.provider_kind,source.source_kind
		FROM asset_sources AS source
		JOIN asset_source_revisions AS revision
		  ON revision.tenant_id=source.tenant_id
		 AND revision.workspace_id=source.workspace_id
		 AND revision.source_id=source.id
		 AND revision.revision=source.published_revision
		WHERE source.id=$1
	`, fixture.sourceID).Scan(&run.revision, &run.revisionDigest,
		&run.sourceDefinitionDigest, &gateRevision, &run.checkpointVersion, &checkpointSHA,
		&run.providerKind, &sourceKind); err != nil {
		t.Fatalf("read governed source admission: %v", err)
	}
	runKind, triggerType := "MANUAL_MUTATION", "HUMAN"
	if sourceKind != "MANUAL" {
		runKind, triggerType = "DISCOVERY", "SCHEDULED"
	}
	execAssetSQL(t, database, `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,trigger_type,gate_revision,idempotency_key,request_hash,
			cursor_before_sha256,checkpoint_version
		) VALUES ($1,$2,$3,$4,$5,$6,$10,$11,$7,
			'runtime-contract-run',repeat('4',64),$8,$9)
	`, run.id, fixture.tenantID, fixture.workspaceID, fixture.sourceID, run.revision,
		run.revisionDigest, gateRevision, checkpointSHA, run.checkpointVersion, runKind, triggerType)
	execAssetSQL(t, database, `
		UPDATE asset_source_runs
		SET status='RUNNING',stage_code='READING',lease_owner='runtime-manual-executor',
			lease_expires_at=statement_timestamp()+interval '10 minutes',fence_epoch=1,
			fence_token_hash=repeat('5',64),heartbeat_sequence=1,
			heartbeat_at=statement_timestamp(),version=version+1
		WHERE id=$1
	`, run.id)
	execAssetSQL(t, database, `
		UPDATE asset_source_runs SET stage_code='NORMALIZING',version=version+1 WHERE id=$1
	`, run.id)
	if err := database.QueryRow(context.Background(), `
		SELECT checkpoint_version,fence_epoch,page_sequence
		FROM asset_source_runs WHERE id=$1
	`, run.id).Scan(&run.checkpointVersion, &run.fenceEpoch, &run.pageSequence); err != nil {
		t.Fatalf("read live manual run coordinates: %v", err)
	}
	return run
}

type runtimeObservation struct {
	fixture                assetCatalogFixture
	run                    runtimeContractRun
	id                     string
	externalID             string
	freshnessKind          string
	freshnessTime          any
	freshnessSequence      int64
	previousID             any
	previousChain          any
	observationChain       string
	sourceDefinitionDigest string
	runFenceEpoch          int64
	runPageSequence        int64
	acceptedCheckpoint     int64
	document               any
	tombstone              bool
	reason                 any
}

func newRuntimeObservation(
	fixture assetCatalogFixture,
	run runtimeContractRun,
	id string,
	externalID string,
	digestCharacter string,
) runtimeObservation {
	return runtimeObservation{
		fixture:                fixture,
		run:                    run,
		id:                     id,
		externalID:             externalID,
		freshnessKind:          "CATALOG_SEQUENCE",
		freshnessSequence:      run.checkpointVersion + 1,
		observationChain:       strings.Repeat(digestCharacter, 64),
		sourceDefinitionDigest: run.sourceDefinitionDigest,
		runFenceEpoch:          run.fenceEpoch,
		runPageSequence:        run.pageSequence + 1,
		acceptedCheckpoint:     run.checkpointVersion + 1,
		document:               `{"display_name":"runtime"}`,
	}
}

const insertRuntimeObservationSQL = `
	WITH material AS (
		SELECT transaction_timestamp() AS accepted_at,
			CASE WHEN $24::text IS NULL THEN NULL::bytea ELSE convert_to($24::text,'UTF8') END AS document,
			convert_to(jsonb_build_object(
				'display_name',jsonb_build_object(
					'source_id',$5::text,
					'provider_kind',$27::text,
					'source_revision',$8::bigint,
					'observed_at',to_char(transaction_timestamp() AT TIME ZONE 'UTC',
						'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
					'provider_path_code','DISPLAY_NAME',
					'confidence',100,
					'ownership','SOURCE'
				)
			)::text,'UTF8') AS provenance
	)
	INSERT INTO asset_observations (
		id,tenant_id,workspace_id,environment_id,source_id,run_id,provider_kind,external_id,
		source_revision,canonical_revision_digest,source_definition_digest,observed_at,
		freshness_kind,freshness_order_time,freshness_order_sequence,provider_version_sha256,
		provider_fact_sha256,fingerprint_sha256,provider_provenance_sha256,
		previous_observation_id,previous_chain_sha256,observation_chain_sha256,
		accepted_checkpoint_version,run_fence_epoch,run_page_sequence,schema_version,
		normalized_document,document_sha256,field_provenance,field_provenance_sha256,
		tombstone,tombstone_reason_code
	)
	SELECT $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6::uuid,$27::text,$7::text,
		$8::bigint,$9::text,$10::text,material.accepted_at,$11::text,$12::timestamptz,
		$13::bigint,$14::text,$15::text,$16::text,$17::text,$18::uuid,$19::text,$20::text,
		$21::bigint,$22::bigint,$23::bigint,'asset.v1',material.document,
		CASE WHEN material.document IS NULL THEN NULL ELSE encode(sha256(material.document),'hex') END,
		material.provenance,encode(sha256(material.provenance),'hex'),$25::boolean,$26::text
	FROM material
`

func runtimeObservationArguments(candidate runtimeObservation) []any {
	return []any{
		candidate.id, candidate.fixture.tenantID, candidate.fixture.workspaceID,
		candidate.fixture.environmentID, candidate.fixture.sourceID, candidate.run.id,
		candidate.externalID, candidate.run.revision, candidate.run.revisionDigest,
		candidate.sourceDefinitionDigest, candidate.freshnessKind, candidate.freshnessTime,
		candidate.freshnessSequence, strings.Repeat("6", 64), strings.Repeat("7", 64),
		strings.Repeat("8", 64), strings.Repeat("9", 64), candidate.previousID,
		candidate.previousChain, candidate.observationChain, candidate.acceptedCheckpoint,
		candidate.runFenceEpoch, candidate.runPageSequence, candidate.document,
		candidate.tombstone, candidate.reason, candidate.run.providerKind,
	}
}

func withRuntimeContractManualRun(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	assertion func(pgx.Tx, runtimeContractRun),
) {
	t.Helper()
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin atomic manual observation assertion: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	run := startClosureManualMutationRunInTx(t, tx, fixture)
	assertion(tx, run)
}

func expectRuntimeManualObservationError(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	id string,
	externalID string,
	digestCharacter string,
	state string,
	constraint string,
	configure func(*runtimeObservation),
) {
	t.Helper()
	withRuntimeContractManualRun(t, database, fixture, func(tx pgx.Tx, run runtimeContractRun) {
		candidate := newRuntimeObservation(fixture, run, id, externalID, digestCharacter)
		configure(&candidate)
		_, err := tx.Exec(context.Background(), insertRuntimeObservationSQL,
			runtimeObservationArguments(candidate)...)
		assertRuntimePostgresError(t, err, state, constraint)
	})
}

func execRuntimeObservation(t *testing.T, database *pgxpool.Pool, candidate runtimeObservation) {
	t.Helper()
	tx, err := database.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin positive observation admission assertion: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(context.Background(), insertRuntimeObservationSQL,
		runtimeObservationArguments(candidate)...); err != nil {
		t.Fatalf("insert positive observation admission assertion: %v", err)
	}
}

func expectRuntimeObservationError(
	t *testing.T,
	database *pgxpool.Pool,
	state string,
	constraint string,
	candidate runtimeObservation,
) {
	t.Helper()
	expectRuntimeContractError(t, database, state, constraint,
		insertRuntimeObservationSQL, runtimeObservationArguments(candidate)...)
}

func expectRuntimeContractError(
	t *testing.T,
	database *pgxpool.Pool,
	state string,
	constraint string,
	query string,
	arguments ...any,
) {
	t.Helper()
	tx, err := database.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin isolated runtime-contract assertion: %v", err)
	}
	_, mutationErr := tx.Exec(context.Background(), query, arguments...)
	rollbackErr := tx.Rollback(context.Background())
	if rollbackErr != nil {
		t.Fatalf("rollback isolated runtime-contract assertion: %v", rollbackErr)
	}
	if mutationErr == nil {
		t.Fatalf("SQL unexpectedly succeeded; want SQLSTATE %s constraint %s", state, constraint)
	}
	var postgresError *pgconn.PgError
	if !errors.As(mutationErr, &postgresError) {
		t.Fatalf("SQL error=%v, want PostgreSQL error %s/%s", mutationErr, state, constraint)
	}
	if postgresError.Code != state {
		t.Fatalf("SQLSTATE=%s (%v), want %s", postgresError.Code, mutationErr, state)
	}
	if constraint != "" && postgresError.ConstraintName != constraint {
		t.Fatalf("constraint=%q (%v), want %q", postgresError.ConstraintName, mutationErr, constraint)
	}
}

func assertRuntimePostgresError(t *testing.T, err error, state, constraint string) {
	t.Helper()
	if err == nil {
		t.Fatalf("SQL unexpectedly succeeded; want SQLSTATE %s constraint %s", state, constraint)
	}
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) {
		t.Fatalf("SQL error=%v, want PostgreSQL error %s/%s", err, state, constraint)
	}
	if postgresError.Code != state || (constraint != "" && postgresError.ConstraintName != constraint) {
		t.Fatalf("SQL error=%s/%s (%v), want %s/%s", postgresError.Code,
			postgresError.ConstraintName, err, state, constraint)
	}
}
