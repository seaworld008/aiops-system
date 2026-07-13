package postgres_test

import "testing"

func TestAssetCatalogRemainingScopeAcceptanceRejectsRunRevisionScopeMix(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	primary := seedDraftAssetCatalog(t, harness.db)
	seedScopeShapeSecondaryScope(t, harness.db)

	// Isolate the composite FK; the production admission guard still fails closed first.
	execAssetSQL(t, harness.db,
		`ALTER TABLE asset_source_runs DISABLE TRIGGER asset_source_runs_mutation_guard`)
	t.Cleanup(func() {
		_, _ = harness.db.Exec(t.Context(),
			`ALTER TABLE asset_source_runs ENABLE TRIGGER asset_source_runs_mutation_guard`)
	})

	expectRuntimeContractError(t, harness.db, "23503",
		"asset_source_runs_tenant_id_workspace_id_source_id_source__fkey", `
			INSERT INTO asset_source_runs (
				id,tenant_id,workspace_id,source_id,source_revision,
				source_revision_digest,run_kind,trigger_type,gate_revision,
				idempotency_key,request_hash,checkpoint_version
			) VALUES (
				'91600000-0000-4000-8000-000000000001',$1,$2,$3,1,
				repeat('8',64),'VALIDATION','HUMAN',0,
				'remaining-scope-run',repeat('1',64),0
			)
		`, primary.tenantID, primary.workspaceID, scopeShapeSecondarySourceID)
}

func TestAssetCatalogRemainingScopeAcceptanceRejectsRelationshipAssetScopeMix(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	run := startClosureExternalDiscoveryRun(t, harness.db, fixture)
	seedScopeShapeSecondaryScope(t, harness.db)

	expectRuntimeContractError(t, harness.db, "23503",
		"asset_relationships_source_asset_fk", `
			INSERT INTO asset_relationships (
				id,tenant_id,workspace_id,source_id,source_revision,
				canonical_revision_digest,last_run_id,last_page_sequence,
				relation_page_sha256,accepted_checkpoint_version,run_fence_epoch,
				source_environment_id,target_environment_id,
				source_asset_id,target_asset_id,from_external_id,to_external_id,
				relationship_type,provider_path_code,confidence,freshness_kind,
				freshness_order_sequence,provider_version_sha256,
				relation_fact_sha256,provenance,provenance_source_id,
				cross_environment_policy_reference_id,status,
				idempotency_key,request_hash,version
			) VALUES (
				'91600000-0000-4000-8000-000000000002',$1,$2,$3,$4,$5,$6,
				$7,repeat('2',64),$8,$9,$10,$11,$12,$13,
				'external-host-a','external-host-b','MANAGED_BY','scope.managed_by',
				100,'OBJECT_SEQUENCE',1,repeat('3',64),repeat('4',64),
				'DISCOVERED',$3,'scope-cross-environment','ACTIVE',
				'remaining-scope-relationship',repeat('5',64),1
			)
		`, fixture.tenantID, fixture.workspaceID, fixture.sourceID, run.revision,
		fixture.revisionDigest, run.id, run.pageSequence+1, run.checkpointVersion+1,
		run.fenceEpoch, scopeShapeSecondaryEnvironmentID, fixture.environmentID,
		fixture.assetID, fixture.secondAssetID)
}

func TestAssetCatalogRemainingScopeAcceptanceKeepsManualCheckpointOpaqueFieldsEmpty(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)

	expectRuntimeContractError(t, harness.db, "23514",
		"asset_sources_manual_checkpoint_guard", `
			WITH envelope AS (
				SELECT decode('01'||repeat('01',12)||repeat('02',16),'hex') AS value
			)
			UPDATE asset_sources AS source
			SET checkpoint_ciphertext=envelope.value,
				checkpoint_key_id='opaque-manual-checkpoint-test',
				checkpoint_sha256=encode(sha256(envelope.value),'hex'),
				checkpoint_version=source.checkpoint_version+1,
				version=source.version+1
			FROM envelope
			WHERE source.id=$1
		`, fixture.sourceID)

	var checkpointFieldsRemainEmpty bool
	if err := harness.db.QueryRow(t.Context(), `
		SELECT checkpoint_ciphertext IS NULL
		   AND checkpoint_key_id IS NULL
		   AND checkpoint_sha256 IS NULL
		FROM asset_sources
		WHERE id=$1
	`, fixture.sourceID).Scan(&checkpointFieldsRemainEmpty); err != nil {
		t.Fatalf("read manual checkpoint fields after rejected mutation: %v", err)
	}
	if !checkpointFieldsRemainEmpty {
		t.Fatal("rejected manual checkpoint mutation left ciphertext, key reference, or digest behind")
	}
}
