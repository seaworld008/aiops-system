package postgres_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	scopeShapeSecondaryTenantID      = "91000000-0000-4000-8000-000000000001"
	scopeShapeSecondaryWorkspaceID   = "91000000-0000-4000-8000-000000000002"
	scopeShapeSecondaryEnvironmentID = "91000000-0000-4000-8000-000000000003"
	scopeShapeSecondaryIntegrationID = "91000000-0000-4000-8000-000000000004"
	scopeShapeSecondaryServiceID     = "91000000-0000-4000-8000-000000000005"
	scopeShapeSecondarySourceID      = "91000000-0000-4000-8000-000000000006"
	scopeShapeSecondaryRevisionID    = "91000000-0000-4000-8000-000000000007"
	scopeShapeUnboundServiceID       = "91000000-0000-4000-8000-000000000008"

	scopeShapeExternalRevisionTwoID = "91000000-0000-4000-8000-000000000009"
	scopeShapeExternalRevisionTwo   = int64(2)
)

func TestAssetCatalogScopeShapeAcceptanceRejectsExistingScopeMixes(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	primary := seedDraftAssetCatalog(t, harness.db)
	seedScopeShapeSecondaryScope(t, harness.db)

	t.Run("tenant and workspace both exist but are not one scope", func(t *testing.T) {
		expectRuntimeContractError(t, harness.db, "23503",
			"asset_sources_tenant_id_workspace_id_fkey", `
			INSERT INTO asset_sources (
				id,tenant_id,workspace_id,source_kind,provider_kind,name,
				create_idempotency_key,create_request_hash
			) VALUES (
				'91100000-0000-4000-8000-000000000001',$1,$2,
				'EXTERNAL_CMDB','SCOPE_MIX_V1','scope mix source',
				'scope-mix-source',repeat('1',64)
			)
		`, primary.tenantID, scopeShapeSecondaryWorkspaceID)
	})

	t.Run("source exists but not in the supplied tenant workspace", func(t *testing.T) {
		schema := []byte(`{"type":"object"}`)
		expectRuntimeContractError(t, harness.db, "23503",
			"asset_source_revisions_source_fk", `
			INSERT INTO asset_source_revisions (
				id,tenant_id,workspace_id,source_id,revision,
				canonical_provider_schema,canonical_provider_schema_sha256,
				integration_id,sync_mode,authority_scope_digest,source_definition_digest,
				canonical_revision_digest,credential_reference_id,rate_limit_requests,
				rate_limit_window_seconds,backpressure_base_seconds,
				backpressure_max_seconds,profile_code,created_by,change_reason_code,
				expected_source_version
			) VALUES (
				'91100000-0000-4000-8000-000000000002',$1,$2,$3,2,
				$4,encode(sha256($4),'hex'),$5,'ON_DEMAND',repeat('2',64),
				repeat('3',64),repeat('4',64),'opaque-credential',100,60,1,60,
				'SECONDARY_V1','scope-test','SCOPE_MIX',1
			)
		`, primary.tenantID, primary.workspaceID, scopeShapeSecondarySourceID,
			schema, primary.integrationID)
	})
}

func TestAssetCatalogScopeShapeAcceptanceRejectsServiceEnvironmentMixes(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	primary := seedGovernedManualCatalog(t, harness.db)
	seedScopeShapeSecondaryScope(t, harness.db)
	execAssetSQL(t, harness.db, `
		INSERT INTO services (id,tenant_id,workspace_id,name,owner_group,labels)
		VALUES ($1,$2,$3,'scope-unbound-service','scope-sre','{}')
	`, scopeShapeUnboundServiceID, primary.tenantID, primary.workspaceID)

	t.Run("service and environment exist but their cross pair is not eligible", func(t *testing.T) {
		expectRuntimeContractError(t, harness.db, "23503",
			"service_asset_bindings_service_environment_fk", `
			INSERT INTO service_asset_bindings (
				id,tenant_id,workspace_id,environment_id,service_id,asset_id,
				binding_role,mapping_status,provenance,provenance_source_id,
				status,idempotency_key,request_hash
			) VALUES (
				'91200000-0000-4000-8000-000000000001',$1,$2,$3,$4,$5,
				'DEPENDENCY','EXACT','MANUAL',NULL,'ACTIVE',
				'scope-cross-service-environment',repeat('1',64)
			)
		`, primary.tenantID, primary.workspaceID, scopeShapeSecondaryEnvironmentID,
			primary.serviceID, primary.assetID)
	})

	t.Run("existing service without service binding is ineligible", func(t *testing.T) {
		expectRuntimeContractError(t, harness.db, "23503",
			"service_asset_bindings_service_environment_fk", `
			INSERT INTO service_asset_bindings (
				id,tenant_id,workspace_id,environment_id,service_id,asset_id,
				binding_role,mapping_status,provenance,provenance_source_id,
				status,idempotency_key,request_hash
			) VALUES (
				'91200000-0000-4000-8000-000000000002',$1,$2,$3,$4,$5,
				'DEPENDENCY','EXACT','MANUAL',NULL,'ACTIVE',
				'scope-unbound-service-environment',repeat('2',64)
			)
		`, primary.tenantID, primary.workspaceID, primary.environmentID,
			scopeShapeUnboundServiceID, primary.assetID)
	})
}

func TestAssetCatalogScopeShapeAcceptanceLifecycleIdentityAndStaticUniqueness(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	seedScopeShapeSecondaryScope(t, harness.db)

	t.Run("legal lifecycle transition advances version exactly once", func(t *testing.T) {
		var before, after int64
		if err := harness.db.QueryRow(context.Background(), `
			SELECT version FROM assets WHERE id=$1
		`, fixture.assetID).Scan(&before); err != nil {
			t.Fatalf("read asset version before lifecycle transition: %v", err)
		}
		var lifecycle string
		if err := harness.db.QueryRow(context.Background(), `
			UPDATE assets SET lifecycle='ACTIVE',version=version+1
			WHERE id=$1 RETURNING lifecycle,version
		`, fixture.assetID).Scan(&lifecycle, &after); err != nil {
			t.Fatalf("apply legal lifecycle transition: %v", err)
		}
		if lifecycle != "ACTIVE" || after != before+1 {
			t.Fatalf("legal lifecycle result=%s/version %d, want ACTIVE/version %d",
				lifecycle, after, before+1)
		}
	})

	t.Run("existing environment cannot reparent asset identity", func(t *testing.T) {
		expectRuntimeContractError(t, harness.db, "55000", "assets_identity_guard", `
			UPDATE assets
			SET environment_id=$1,version=version+1
			WHERE id=$2
		`, scopeShapeSecondaryEnvironmentID, fixture.assetID)
	})

	t.Run("provider external identity is deduplicated", func(t *testing.T) {
		expectRuntimeContractError(t, harness.db, "23505",
			"assets_tenant_id_workspace_id_source_id_provider_kind_exter_key", `
			INSERT INTO assets (
				id,tenant_id,workspace_id,environment_id,source_id,provider_kind,
				external_id,kind,display_name,owner_group,criticality,
				data_classification,labels,lifecycle,mapping_status,last_observation_id,
				last_observation_chain_sha256,last_observed_at,last_source_revision,
				create_idempotency_key,create_request_hash,version
			)
			SELECT '91300000-0000-4000-8000-000000000001',tenant_id,workspace_id,
				environment_id,source_id,provider_kind,external_id,kind,display_name,
				owner_group,criticality,data_classification,labels,'DISCOVERED',
				mapping_status,last_observation_id,last_observation_chain_sha256,
				last_observed_at,last_source_revision,'scope-duplicate-external',
				repeat('3',64),1
			FROM assets WHERE id=$1
		`, fixture.assetID)
	})

	t.Run("creation idempotency is unique inside a workspace", func(t *testing.T) {
		expectRuntimeContractError(t, harness.db, "23505",
			"asset_sources_workspace_id_create_idempotency_key_key", `
			INSERT INTO asset_sources (
				id,tenant_id,workspace_id,source_kind,provider_kind,name,
				create_idempotency_key,create_request_hash
			) VALUES (
				'91300000-0000-4000-8000-000000000002',$1,$2,
				'EXTERNAL_CMDB','IDEMPOTENCY_V1','idempotency duplicate source',
				'fixture-source-create',repeat('4',64)
			)
		`, fixture.tenantID, fixture.workspaceID)
	})

	t.Run("active service asset binding is unique", func(t *testing.T) {
		expectRuntimeContractError(t, harness.db, "23505",
			"service_asset_bindings_active_uk", `
			INSERT INTO service_asset_bindings (
				id,tenant_id,workspace_id,environment_id,service_id,asset_id,
				binding_role,mapping_status,provenance,provenance_source_id,
				status,idempotency_key,request_hash,version
			)
			SELECT '91300000-0000-4000-8000-000000000003',tenant_id,workspace_id,
				environment_id,service_id,asset_id,binding_role,mapping_status,
				provenance,provenance_source_id,'ACTIVE','scope-active-binding-duplicate',
				repeat('5',64),1
			FROM service_asset_bindings WHERE id=$1
		`, fixture.bindingID)
	})
}

func TestAssetCatalogScopeShapeAcceptanceRejectsObservationDrift(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	external := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	seedScopeShapeSecondaryScope(t, harness.db)
	seedScopeShapeExternalRevisionTwo(t, harness.db, external)
	liveRun := startClosureExternalDiscoveryRun(t, harness.db, external)

	t.Run("observation provider exists but belongs to another source", func(t *testing.T) {
		candidate := newScopeShapeObservation(external, liveRun,
			"91400000-0000-4000-8000-000000000001", "scope-provider-drift")
		candidate.providerKind = "MANUAL_V1"
		candidate.provenanceProviderKind = candidate.providerKind
		expectScopeShapeObservationError(t, harness.db, candidate, "23503",
			"asset_observations_source_provider_fk")
	})

	t.Run("observation revision exists but is not its run revision", func(t *testing.T) {
		candidate := newScopeShapeObservation(external, liveRun,
			"91400000-0000-4000-8000-000000000002", "scope-revision-drift")
		candidate.sourceRevision = scopeShapeExternalRevisionTwo
		candidate.revisionDigest = scopeShapeRevisionDigest("c")
		candidate.sourceDefinitionDigest = scopeShapeRevisionDigest("b")
		candidate.provenanceRevision = scopeShapeExternalRevisionTwo
		expectScopeShapeObservationError(t, harness.db, candidate, "23503",
			"asset_observations_run_revision_fk")
	})

	t.Run("observation environment exists under another real scope", func(t *testing.T) {
		candidate := newScopeShapeObservation(external, liveRun,
			"91400000-0000-4000-8000-000000000003", "scope-environment-drift")
		candidate.environmentID = scopeShapeSecondaryEnvironmentID
		expectScopeShapeObservationError(t, harness.db, candidate, "23503",
			"asset_observations_tenant_id_workspace_id_environment_id_fkey")
	})

	t.Run("asset revision exists but is not its exact observation revision", func(t *testing.T) {
		candidate := newScopeShapeObservation(external, liveRun,
			"91400000-0000-4000-8000-000000000004", "scope-asset-revision-drift")
		expectScopeShapeAssetFromObservationError(t, harness.db, candidate,
			"91400000-0000-4000-8000-000000000005", external.environmentID,
			liveRun.providerKind, scopeShapeExternalRevisionTwo, "23503",
			"assets_last_observation_exact_fk")
	})

	t.Run("asset environment exists under another real scope", func(t *testing.T) {
		candidate := newScopeShapeObservation(external, liveRun,
			"91400000-0000-4000-8000-000000000006", "scope-asset-environment-drift")
		expectScopeShapeAssetFromObservationError(t, harness.db, candidate,
			"91400000-0000-4000-8000-000000000007", scopeShapeSecondaryEnvironmentID,
			liveRun.providerKind, liveRun.revision, "23503",
			"assets_tenant_id_workspace_id_environment_id_fkey")
	})

	t.Run("same run provider identity is deduplicated", func(t *testing.T) {
		first := newScopeShapeObservation(external, liveRun,
			"91400000-0000-4000-8000-000000000008", "scope-same-run-object")
		second := first
		second.id = "91400000-0000-4000-8000-000000000009"
		expectScopeShapeSameRunDuplicate(t, harness.db, first, second)
	})

	for _, test := range []struct {
		name       string
		mutate     func(*scopeShapeObservationCandidate)
		state      string
		constraint string
	}{
		{
			name: "provenance requires provider path",
			mutate: func(candidate *scopeShapeObservationCandidate) {
				candidate.providerPathCode = nil
			},
			state: "23514", constraint: "asset_observations_provenance_admission_guard",
		},
		{
			name: "provenance confidence is an integer",
			mutate: func(candidate *scopeShapeObservationCandidate) {
				candidate.confidence = 99.5
			},
			state: "23514", constraint: "asset_observations_provenance_admission_guard",
		},
		{
			name: "provenance semantic source coordinate equals row",
			mutate: func(candidate *scopeShapeObservationCandidate) {
				candidate.provenanceSourceID = scopeShapeSecondarySourceID
			},
			state: "23514", constraint: "asset_observations_provenance_fact_guard",
		},
		{
			name: "provenance rejects infinite canonical time",
			mutate: func(candidate *scopeShapeObservationCandidate) {
				candidate.provenanceObservedAt = "infinity"
			},
			state: "23514", constraint: "asset_observations_provenance_admission_guard",
		},
		{
			name: "observation rejects stale fence coordinate",
			mutate: func(candidate *scopeShapeObservationCandidate) {
				candidate.runFenceEpoch++
			},
			state: "55000", constraint: "asset_observations_live_run_guard",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := newScopeShapeObservation(external, liveRun,
				"91400000-0000-4000-8000-00000000000a", "scope-provenance-shape")
			test.mutate(&candidate)
			expectScopeShapeObservationError(t, harness.db, candidate, test.state,
				test.constraint)
		})
	}

	t.Run("raw fence token cannot replace live holder", func(t *testing.T) {
		expectRuntimeContractError(t, harness.db, "55000",
			"asset_source_runs_reclaim_guard", `
			UPDATE asset_source_runs
			SET fence_token_hash='raw-fence-token',version=version+1
			WHERE id=$1
		`, liveRun.id)
	})

	t.Run("current holder cannot forge next fence", func(t *testing.T) {
		expectRuntimeContractError(t, harness.db, "55000",
			"asset_source_runs_fence_guard", `
			UPDATE asset_source_runs
			SET fence_epoch=fence_epoch+1,version=version+1
			WHERE id=$1
		`, liveRun.id)
	})

	t.Run("source checkpoint cannot regress", func(t *testing.T) {
		expectRuntimeContractError(t, harness.db, "55000",
			"asset_sources_checkpoint_version_guard", `
			UPDATE asset_sources
			SET checkpoint_version=checkpoint_version-1,version=version+1
			WHERE id=$1
		`, external.sourceID)
	})

	t.Run("active relationship edge is unique", func(t *testing.T) {
		expectScopeShapeActiveRelationshipDuplicate(t, harness.db, external, liveRun)
	})
}

func TestAssetCatalogScopeShapeAcceptanceRejectsAssetDrift(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	manual := seedGovernedManualCatalog(t, harness.db)
	seedScopeShapeSecondaryScope(t, harness.db)
	seedScopeShapeSecondaryRevisionTwo(t, harness.db)

	t.Run("asset provider exists but belongs to another source", func(t *testing.T) {
		expectRuntimeContractError(t, harness.db, "23503", "assets_source_provider_fk", `
			INSERT INTO assets (
				id,tenant_id,workspace_id,environment_id,source_id,provider_kind,
				external_id,kind,display_name,owner_group,criticality,
				data_classification,labels,lifecycle,mapping_status,last_observation_id,
				last_observation_chain_sha256,last_observed_at,last_source_revision,
				create_idempotency_key,create_request_hash,version
			)
			SELECT '91400000-0000-4000-8000-000000000004',tenant_id,workspace_id,
				environment_id,source_id,'SECONDARY_V1',external_id,kind,display_name,
				owner_group,criticality,data_classification,labels,'DISCOVERED',
				mapping_status,last_observation_id,last_observation_chain_sha256,
				last_observed_at,last_source_revision,'scope-asset-provider-drift',
				repeat('4',64),1
			FROM assets WHERE id=$1
		`, manual.assetID)
	})

}

func TestAssetCatalogScopeShapeAcceptanceRejectsStoredShapeViolations(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	primary := seedDraftAssetCatalog(t, harness.db)
	seedScopeShapeSecondaryScope(t, harness.db)

	for _, test := range []struct {
		name     string
		document []byte
	}{
		{
			name:     "duplicate key provider schema reaches table check",
			document: []byte(`{"type":"object","type":"array"}`),
		},
		{
			name: "oversized provider schema reaches table check",
			document: []byte(`{"payload":"` + strings.Repeat("x", 65536) +
				`"}`),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			expectRuntimeContractError(t, harness.db, "23514",
				"asset_source_revisions_schema_ck", `
				INSERT INTO asset_source_revisions (
					id,tenant_id,workspace_id,source_id,revision,
					canonical_provider_schema,canonical_provider_schema_sha256,
					integration_id,sync_mode,authority_scope_digest,
					source_definition_digest,canonical_revision_digest,
					credential_reference_id,rate_limit_requests,
					rate_limit_window_seconds,backpressure_base_seconds,
					backpressure_max_seconds,profile_code,created_by,
					change_reason_code,expected_source_version
				) SELECT '91500000-0000-4000-8000-000000000001',$1,$2,$3,2,$4,
					encode(sha256($4),'hex'),$5,'ON_DEMAND',repeat('1',64),
					repeat('2',64),repeat('3',64),'opaque-credential',100,60,1,60,
					'SECONDARY_V1','scope-test','SHAPE_CHECK',source.version
				FROM asset_sources AS source WHERE source.id=$3
			`, scopeShapeSecondaryTenantID, scopeShapeSecondaryWorkspaceID,
				scopeShapeSecondarySourceID, test.document,
				scopeShapeSecondaryIntegrationID)
		})
	}

	t.Run("bad request hash reaches source table check", func(t *testing.T) {
		expectRuntimeContractError(t, harness.db, "23514",
			"asset_sources_create_request_hash_check", `
			INSERT INTO asset_sources (
				id,tenant_id,workspace_id,source_kind,provider_kind,name,
				create_idempotency_key,create_request_hash
			) VALUES (
				'91500000-0000-4000-8000-000000000002',$1,$2,
				'EXTERNAL_CMDB','BAD_HASH_V1','bad hash source',
				'scope-bad-hash','not-a-canonical-sha256'
			)
		`, primary.tenantID, primary.workspaceID)
	})

	t.Run("plaintext checkpoint cannot satisfy encrypted envelope", func(t *testing.T) {
		expectRuntimeContractError(t, harness.db, "23514", "asset_sources_checkpoint_ck", `
			WITH plaintext AS (
				SELECT convert_to(repeat('plaintext',5),'UTF8') AS payload
			)
			UPDATE asset_sources AS source
			SET checkpoint_ciphertext=plaintext.payload,
				checkpoint_key_id='opaque-key-id',
				checkpoint_sha256=encode(sha256(plaintext.payload),'hex'),
				checkpoint_revision=1,checkpoint_version=1,version=version+1
			FROM plaintext WHERE source.id=$1
		`, scopeShapeSecondarySourceID)
	})

	t.Run("infinite catalog time is rejected", func(t *testing.T) {
		expectRuntimeContractError(t, harness.db, "23514", "asset_sources_time_ck", `
			UPDATE asset_sources
			SET next_allowed_at='infinity'::timestamptz,version=version+1
			WHERE id=$1
		`, scopeShapeSecondarySourceID)
	})

	t.Run("direct terminal run shape is rejected before admission", func(t *testing.T) {
		expectRuntimeContractError(t, harness.db, "23514",
			"asset_source_runs_initial_state_guard", `
			INSERT INTO asset_source_runs (
				id,tenant_id,workspace_id,source_id,source_revision,
				source_revision_digest,run_kind,status,stage_code,trigger_type,
				gate_revision,idempotency_key,request_hash,checkpoint_version,
				completed_at,terminal_command_sha256
			) VALUES (
				'91500000-0000-4000-8000-000000000003',$1,$2,$3,1,$4,
				'MANUAL_MUTATION','SUCCEEDED','COMPLETED','HUMAN',0,
				'scope-direct-terminal',repeat('4',64),0,
				statement_timestamp(),repeat('5',64)
			)
		`, primary.tenantID, primary.workspaceID, primary.sourceID,
			primary.revisionDigest)
	})
}

type scopeShapeObservationCandidate struct {
	fixture                   assetCatalogFixture
	run                       runtimeContractRun
	id                        string
	externalID                string
	environmentID             string
	providerKind              string
	sourceRevision            int64
	revisionDigest            string
	sourceDefinitionDigest    string
	acceptedCheckpointVersion int64
	runFenceEpoch             int64
	runPageSequence           int64
	provenanceSourceID        string
	provenanceProviderKind    string
	provenanceRevision        int64
	providerPathCode          any
	confidence                any
	provenanceObservedAt      any
}

func newScopeShapeObservation(
	fixture assetCatalogFixture,
	run runtimeContractRun,
	id string,
	externalID string,
) scopeShapeObservationCandidate {
	return scopeShapeObservationCandidate{
		fixture:                   fixture,
		run:                       run,
		id:                        id,
		externalID:                externalID,
		environmentID:             fixture.environmentID,
		providerKind:              run.providerKind,
		sourceRevision:            run.revision,
		revisionDigest:            run.revisionDigest,
		sourceDefinitionDigest:    run.sourceDefinitionDigest,
		acceptedCheckpointVersion: run.checkpointVersion + 1,
		runFenceEpoch:             run.fenceEpoch,
		runPageSequence:           run.pageSequence + 1,
		provenanceSourceID:        fixture.sourceID,
		provenanceProviderKind:    run.providerKind,
		provenanceRevision:        run.revision,
		providerPathCode:          "asset.display_name",
		confidence:                100,
	}
}

const scopeShapeObservationInsertSQL = `
	WITH accepted AS (
		SELECT transaction_timestamp() AS observed_at
	), material AS (
		SELECT accepted.observed_at,
			convert_to(jsonb_build_object('display_name',$8::text)::text,'UTF8') AS document,
			convert_to(jsonb_build_object(
				'display_name',jsonb_strip_nulls(jsonb_build_object(
					'source_id',$15::text,
					'provider_kind',$16::text,
					'source_revision',$17::bigint,
					'observed_at',CASE WHEN $20::text IS NULL THEN
						to_char(accepted.observed_at AT TIME ZONE 'UTC',
							'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') ELSE $20::text END,
					'provider_path_code',$18::text,
					'confidence',$19::numeric,
					'ownership','SOURCE'
				))
			)::text,'UTF8') AS provenance
		FROM accepted
	)
	INSERT INTO asset_observations (
		id,tenant_id,workspace_id,environment_id,source_id,run_id,provider_kind,
		external_id,source_revision,canonical_revision_digest,source_definition_digest,
		observed_at,freshness_kind,freshness_order_sequence,provider_version_sha256,
		provider_fact_sha256,fingerprint_sha256,provider_provenance_sha256,
		observation_chain_sha256,accepted_checkpoint_version,run_fence_epoch,
		run_page_sequence,schema_version,normalized_document,document_sha256,
		field_provenance,field_provenance_sha256
	)
	SELECT $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6::uuid,$7::text,$8::text,
		$9::bigint,$10::text,$11::text,material.observed_at,'OBJECT_SEQUENCE',1,
		repeat('1',64),repeat('2',64),repeat('3',64),repeat('4',64),repeat('5',64),
		$12::bigint,$13::bigint,$14::bigint,'asset.v1',material.document,
		encode(sha256(material.document),'hex'),material.provenance,
		encode(sha256(material.provenance),'hex')
	FROM material
`

func scopeShapeObservationArguments(candidate scopeShapeObservationCandidate) []any {
	return []any{
		candidate.id, candidate.fixture.tenantID, candidate.fixture.workspaceID,
		candidate.environmentID, candidate.fixture.sourceID, candidate.run.id,
		candidate.providerKind, candidate.externalID, candidate.sourceRevision,
		candidate.revisionDigest, candidate.sourceDefinitionDigest,
		candidate.acceptedCheckpointVersion, candidate.runFenceEpoch,
		candidate.runPageSequence, candidate.provenanceSourceID,
		candidate.provenanceProviderKind, candidate.provenanceRevision,
		candidate.providerPathCode, candidate.confidence, candidate.provenanceObservedAt,
	}
}

func expectScopeShapeObservationError(
	t *testing.T,
	database *pgxpool.Pool,
	candidate scopeShapeObservationCandidate,
	state string,
	constraint string,
) {
	t.Helper()
	tx, err := database.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin scope-shape observation assertion: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	_, mutationErr := tx.Exec(context.Background(), scopeShapeObservationInsertSQL,
		scopeShapeObservationArguments(candidate)...)
	assertRuntimePostgresError(t, mutationErr, state, constraint)
}

func expectScopeShapeAssetFromObservationError(
	t *testing.T,
	database *pgxpool.Pool,
	candidate scopeShapeObservationCandidate,
	assetID string,
	environmentID string,
	providerKind string,
	lastSourceRevision int64,
	state string,
	constraint string,
) {
	t.Helper()
	tx, err := database.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin scope-shape asset assertion: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(context.Background(), scopeShapeObservationInsertSQL,
		scopeShapeObservationArguments(candidate)...); err != nil {
		t.Fatalf("insert unprojected observation for asset assertion: %v", err)
	}
	_, mutationErr := tx.Exec(context.Background(), `
		INSERT INTO assets (
			id,tenant_id,workspace_id,environment_id,source_id,provider_kind,
			external_id,kind,display_name,criticality,data_classification,labels,
			lifecycle,mapping_status,last_observation_id,
			last_observation_chain_sha256,last_observed_at,last_source_revision,
			create_idempotency_key,create_request_hash,version
		)
		SELECT $1,tenant_id,workspace_id,$2,source_id,$3,external_id,'LINUX_VM',
			external_id,'LOW','INTERNAL','{}','DISCOVERED','UNRESOLVED',id,
			observation_chain_sha256,observed_at,$4,'scope-asset-from-observation-'||$1::text,
			repeat('6',64),1
		FROM asset_observations WHERE id=$5
	`, assetID, environmentID, providerKind, lastSourceRevision, candidate.id)
	assertRuntimePostgresError(t, mutationErr, state, constraint)
}

func expectScopeShapeSameRunDuplicate(
	t *testing.T,
	database *pgxpool.Pool,
	first scopeShapeObservationCandidate,
	second scopeShapeObservationCandidate,
) {
	t.Helper()
	tx, err := database.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin same-run observation dedupe assertion: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(context.Background(), scopeShapeObservationInsertSQL,
		scopeShapeObservationArguments(first)...); err != nil {
		t.Fatalf("insert first same-run observation: %v", err)
	}
	_, duplicateErr := tx.Exec(context.Background(), scopeShapeObservationInsertSQL,
		scopeShapeObservationArguments(second)...)
	assertRuntimePostgresError(t, duplicateErr, "23505",
		"asset_observations_same_run_object_uk")
}

func expectScopeShapeActiveRelationshipDuplicate(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	run runtimeContractRun,
) {
	t.Helper()
	tx, err := database.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin active relationship uniqueness assertion: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	firstObservation := newScopeShapeObservation(fixture, run,
		"91600000-0000-4000-8000-000000000001", "scope-live-edge-from")
	secondObservation := newScopeShapeObservation(fixture, run,
		"91600000-0000-4000-8000-000000000002", "scope-live-edge-to")
	firstAssetID := "91600000-0000-4000-8000-000000000003"
	secondAssetID := "91600000-0000-4000-8000-000000000004"
	insertScopeShapeUnprojectedAsset(t, tx, firstObservation, firstAssetID)
	insertScopeShapeUnprojectedAsset(t, tx, secondObservation, secondAssetID)

	arguments := []any{
		"91600000-0000-4000-8000-000000000005", fixture.tenantID,
		fixture.workspaceID, fixture.sourceID, run.revision, run.revisionDigest,
		run.id, run.pageSequence + 1, run.checkpointVersion + 1, run.fenceEpoch,
		fixture.environmentID, firstAssetID, secondAssetID,
		firstObservation.externalID, secondObservation.externalID,
		"scope-live-active-edge-first",
	}
	if _, err := tx.Exec(context.Background(), scopeShapeRelationshipInsertSQL,
		arguments...); err != nil {
		t.Fatalf("insert first live active relationship: %v", err)
	}
	arguments[0] = "91600000-0000-4000-8000-000000000006"
	arguments[15] = "scope-live-active-edge-second"
	_, duplicateErr := tx.Exec(context.Background(), scopeShapeRelationshipInsertSQL,
		arguments...)
	assertRuntimePostgresError(t, duplicateErr, "23505", "asset_relationships_active_edge_uk")
}

func insertScopeShapeUnprojectedAsset(
	t *testing.T,
	database assetSQLExecutor,
	candidate scopeShapeObservationCandidate,
	assetID string,
) {
	t.Helper()
	if _, err := database.Exec(context.Background(), scopeShapeObservationInsertSQL,
		scopeShapeObservationArguments(candidate)...); err != nil {
		t.Fatalf("insert live unprojected observation: %v", err)
	}
	execAssetSQL(t, database, `
		INSERT INTO assets (
			id,tenant_id,workspace_id,environment_id,source_id,provider_kind,
			external_id,kind,display_name,criticality,data_classification,labels,
			lifecycle,mapping_status,last_observation_id,
			last_observation_chain_sha256,last_observed_at,last_source_revision,
			create_idempotency_key,create_request_hash,version
		)
		SELECT $1,tenant_id,workspace_id,environment_id,source_id,provider_kind,
			external_id,'LINUX_VM',external_id,'LOW','INTERNAL','{}','DISCOVERED',
			'UNRESOLVED',id,observation_chain_sha256,observed_at,source_revision,
			'scope-live-asset-'||$1::text,repeat('7',64),1
		FROM asset_observations WHERE id=$2
	`, assetID, candidate.id)
}

const scopeShapeRelationshipInsertSQL = `
	INSERT INTO asset_relationships (
		id,tenant_id,workspace_id,source_id,source_revision,
		canonical_revision_digest,last_run_id,last_page_sequence,
		relation_page_sha256,accepted_checkpoint_version,run_fence_epoch,
		source_environment_id,target_environment_id,source_asset_id,target_asset_id,
		from_external_id,to_external_id,relationship_type,provider_path_code,
		confidence,freshness_kind,freshness_order_sequence,provider_version_sha256,
		relation_fact_sha256,provenance,provenance_source_id,status,
		idempotency_key,request_hash,version
	) VALUES (
		$1,$2,$3,$4,$5,$6,$7,$8,repeat('8',64),$9,$10,$11,$11,$12,$13,$14,$15,
		'DEPENDS_ON','asset.depends_on',100,'OBJECT_SEQUENCE',1,repeat('9',64),
		repeat('a',64),'DISCOVERED',$4,'ACTIVE',$16,repeat('b',64),1
	)
`

func seedScopeShapeSecondaryScope(t *testing.T, database *pgxpool.Pool) {
	t.Helper()
	execAssetSQL(t, database, `
		INSERT INTO tenants (id,name) VALUES ($1,'scope-secondary-tenant')
	`, scopeShapeSecondaryTenantID)
	execAssetSQL(t, database, `
		INSERT INTO workspaces (id,tenant_id,name)
		VALUES ($1,$2,'scope-secondary-workspace')
	`, scopeShapeSecondaryWorkspaceID, scopeShapeSecondaryTenantID)
	execAssetSQL(t, database, `
		INSERT INTO environments (id,tenant_id,workspace_id,name,kind)
		VALUES ($1,$2,$3,'scope-secondary-production','PROD')
	`, scopeShapeSecondaryEnvironmentID, scopeShapeSecondaryTenantID,
		scopeShapeSecondaryWorkspaceID)
	execAssetSQL(t, database, `
		INSERT INTO integrations (
			id,tenant_id,workspace_id,provider,name,secret_ref,config
		) VALUES (
			$1,$2,$3,'manual','scope-secondary-integration',
			'opaque://scope-secondary','{}'
		)
	`, scopeShapeSecondaryIntegrationID, scopeShapeSecondaryTenantID,
		scopeShapeSecondaryWorkspaceID)
	execAssetSQL(t, database, `
		INSERT INTO services (id,tenant_id,workspace_id,name,owner_group,labels)
		VALUES ($1,$2,$3,'scope-secondary-service','scope-secondary-sre','{}')
	`, scopeShapeSecondaryServiceID, scopeShapeSecondaryTenantID,
		scopeShapeSecondaryWorkspaceID)
	execAssetSQL(t, database, `
		INSERT INTO service_bindings (
			id,tenant_id,workspace_id,service_id,environment_id,mapping_status
		) VALUES (
			'91000000-0000-4000-8000-00000000000a',$1,$2,$3,$4,'EXACT'
		)
	`, scopeShapeSecondaryTenantID, scopeShapeSecondaryWorkspaceID,
		scopeShapeSecondaryServiceID, scopeShapeSecondaryEnvironmentID)
	execAssetSQL(t, database, `
		INSERT INTO asset_sources (
			id,tenant_id,workspace_id,source_kind,provider_kind,name,
			create_idempotency_key,create_request_hash
		) VALUES (
			$1,$2,$3,'EXTERNAL_CMDB','SECONDARY_V1','scope secondary source',
			'scope-secondary-source',repeat('5',64)
		)
	`, scopeShapeSecondarySourceID, scopeShapeSecondaryTenantID,
		scopeShapeSecondaryWorkspaceID)
	schema := []byte(`{"type":"object"}`)
	execAssetSQL(t, database, `
		INSERT INTO asset_source_revisions (
			id,tenant_id,workspace_id,source_id,revision,
			canonical_provider_schema,canonical_provider_schema_sha256,
			integration_id,sync_mode,authority_scope_digest,source_definition_digest,
			canonical_revision_digest,credential_reference_id,rate_limit_requests,
			rate_limit_window_seconds,backpressure_base_seconds,
			backpressure_max_seconds,profile_code,created_by,change_reason_code,
			expected_source_version
		) SELECT $1,$2,$3,$4,1,$5,encode(sha256($5),'hex'),$6,'ON_DEMAND',
			repeat('6',64),repeat('7',64),repeat('8',64),'opaque-credential',
			100,60,1,60,'SECONDARY_V1','scope-test','INITIAL_CREATE',source.version
		FROM asset_sources AS source WHERE source.id=$4
	`, scopeShapeSecondaryRevisionID, scopeShapeSecondaryTenantID,
		scopeShapeSecondaryWorkspaceID, scopeShapeSecondarySourceID, schema,
		scopeShapeSecondaryIntegrationID)
}

func seedScopeShapeExternalRevisionTwo(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
) {
	t.Helper()
	schema := []byte(`{"type":"object","revision":2}`)
	execAssetSQL(t, database, `
		INSERT INTO asset_source_revisions (
			id,tenant_id,workspace_id,source_id,revision,
			canonical_provider_schema,canonical_provider_schema_sha256,
			integration_id,sync_mode,authority_scope_digest,source_definition_digest,
			canonical_revision_digest,credential_reference_id,rate_limit_requests,
			rate_limit_window_seconds,backpressure_base_seconds,
			backpressure_max_seconds,profile_code,created_by,change_reason_code,
			expected_source_version
		) SELECT $1,$2,$3,$4,$5,$6,encode(sha256($6),'hex'),$7,'ON_DEMAND',
			repeat('a',64),repeat('b',64),repeat('c',64),'opaque-credential',
			100,60,1,60,'EXTERNAL_V1','scope-test','REVISION_TWO',source.version
		FROM asset_sources AS source WHERE source.id=$4
	`, scopeShapeExternalRevisionTwoID, fixture.tenantID, fixture.workspaceID,
		fixture.sourceID, scopeShapeExternalRevisionTwo, schema, fixture.integrationID)
}

func seedScopeShapeSecondaryRevisionTwo(t *testing.T, database *pgxpool.Pool) {
	t.Helper()
	schema := []byte(`{"type":"object","revision":2}`)
	execAssetSQL(t, database, `
		INSERT INTO asset_source_revisions (
			id,tenant_id,workspace_id,source_id,revision,
			canonical_provider_schema,canonical_provider_schema_sha256,
			integration_id,sync_mode,authority_scope_digest,source_definition_digest,
			canonical_revision_digest,credential_reference_id,rate_limit_requests,
			rate_limit_window_seconds,backpressure_base_seconds,
			backpressure_max_seconds,profile_code,created_by,change_reason_code,
			expected_source_version
		) SELECT '91000000-0000-4000-8000-00000000000b',$1,$2,$3,2,$4,
			encode(sha256($4),'hex'),$5,'ON_DEMAND',repeat('9',64),repeat('a',64),
			repeat('b',64),'opaque-credential',100,60,1,60,'SECONDARY_V1',
			'scope-test','REVISION_TWO',source.version
		FROM asset_sources AS source WHERE source.id=$3
	`, scopeShapeSecondaryTenantID, scopeShapeSecondaryWorkspaceID,
		scopeShapeSecondarySourceID, schema, scopeShapeSecondaryIntegrationID)
}

func scopeShapeRevisionDigest(character string) string {
	return strings.Repeat(character, 64)
}

func readScopeShapeSourceVersion(t *testing.T, database *pgxpool.Pool, sourceID string) int64 {
	t.Helper()
	var version int64
	if err := database.QueryRow(context.Background(), `
		SELECT version FROM asset_sources WHERE id=$1
	`, sourceID).Scan(&version); err != nil {
		t.Fatalf("read source version: %v", err)
	}
	return version
}
