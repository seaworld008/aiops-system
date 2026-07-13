package postgres_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAssetCatalogExternalDiscoveryContinuesCheckpointWithoutReset(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)

	var initialCheckpoint int64
	var initialCheckpointSHA string
	if err := harness.db.QueryRow(context.Background(), `
		SELECT checkpoint_version,checkpoint_sha256
		FROM asset_sources WHERE id=$1
	`, fixture.sourceID).Scan(&initialCheckpoint, &initialCheckpointSHA); err != nil {
		t.Fatalf("read authoritative checkpoint before consecutive discovery: %v", err)
	}
	if initialCheckpoint <= 0 || initialCheckpointSHA == "" {
		t.Fatalf("authoritative fixture checkpoint=%d hash=%q, want persisted non-zero lineage",
			initialCheckpoint, initialCheckpointSHA)
	}

	run := startClosureExternalDiscoveryRun(t, harness.db, fixture)
	var cursorBefore string
	if err := harness.db.QueryRow(context.Background(), `
		SELECT cursor_before_sha256 FROM asset_source_runs WHERE id=$1
	`, run.id).Scan(&cursorBefore); err != nil {
		t.Fatalf("read consecutive discovery cursor: %v", err)
	}
	if run.checkpointVersion != initialCheckpoint || cursorBefore != initialCheckpointSHA {
		t.Fatalf("consecutive discovery admission checkpoint/hash=%d/%s, want %d/%s",
			run.checkpointVersion, cursorBefore, initialCheckpoint, initialCheckpointSHA)
	}

	pageDigest := strings.Repeat("a", 64)
	tx, err := harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin consecutive discovery page: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	observation := newRuntimeObservation(fixture, run,
		"8fa00000-0000-4000-8000-000000000001", "c1-replay-object", "b")
	observation.freshnessKind = "OBJECT_SEQUENCE"
	observation.freshnessSequence = 1
	if _, err := tx.Exec(context.Background(), insertRuntimeObservationSQL,
		runtimeObservationArguments(observation)...); err != nil {
		t.Fatalf("insert consecutive discovery observation: %v", err)
	}
	if err := insertClosurePageReceipt(tx, fixture, run.id, 1, pageDigest); err != nil {
		t.Fatalf("insert consecutive discovery page receipt: %v", err)
	}
	execAssetSQL(t, tx, `
		WITH envelope AS (
			SELECT decode('01'||repeat('0a',12)||repeat('0b',16),'hex') AS ciphertext
		)
		UPDATE asset_sources AS source
		SET checkpoint_ciphertext=envelope.ciphertext,
			checkpoint_key_id='opaque-c1-key-2',
			checkpoint_sha256=encode(sha256(envelope.ciphertext),'hex'),
			checkpoint_version=source.checkpoint_version+1,
			version=source.version+1
		FROM envelope WHERE source.id=$1
	`, fixture.sourceID)
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs
		SET stage_code='APPLYING',page_sequence=page_sequence+1,page_digest=$2,
			checkpoint_version=checkpoint_version+1,
			cursor_after_sha256=(SELECT checkpoint_sha256 FROM asset_sources WHERE id=$3),
			observed_count=observed_count+1,
			heartbeat_sequence=heartbeat_sequence+1,
			heartbeat_at=statement_timestamp(),
			lease_expires_at=lease_expires_at+interval '1 minute',version=version+1
		WHERE id=$1
	`, run.id, pageDigest, fixture.sourceID)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit consecutive discovery page: %v", err)
	}

	var sourceCheckpoint, runCheckpoint, pageSequence int64
	var sourceCheckpointSHA, runCursorBefore, runCursorAfter string
	if err := harness.db.QueryRow(context.Background(), `
		SELECT source.checkpoint_version,source.checkpoint_sha256,
			run.checkpoint_version,run.cursor_before_sha256,run.cursor_after_sha256,
			run.page_sequence
		FROM asset_sources AS source
		JOIN asset_source_runs AS run ON run.source_id=source.id
		WHERE source.id=$1 AND run.id=$2
	`, fixture.sourceID, run.id).Scan(
		&sourceCheckpoint, &sourceCheckpointSHA, &runCheckpoint,
		&runCursorBefore, &runCursorAfter, &pageSequence,
	); err != nil {
		t.Fatalf("read consecutive discovery page closure: %v", err)
	}
	if sourceCheckpoint != initialCheckpoint+1 || runCheckpoint != initialCheckpoint+1 ||
		pageSequence != 1 || runCursorBefore != initialCheckpointSHA ||
		runCursorAfter != sourceCheckpointSHA || runCursorAfter == runCursorBefore {
		t.Fatalf("consecutive discovery closure source=%d run=%d page=%d before=%s after=%s sourceHash=%s",
			sourceCheckpoint, runCheckpoint, pageSequence, runCursorBefore,
			runCursorAfter, sourceCheckpointSHA)
	}

	var receiptID, receiptAction, receiptHash string
	var auditCountBefore int64
	if err := harness.db.QueryRow(context.Background(), `
		SELECT id::text,action,payload_hash
		FROM audit_records
		WHERE workspace_id=$1 AND request_id='source-page:'||$2||':1'
	`, fixture.workspaceID, run.id).Scan(&receiptID, &receiptAction, &receiptHash); err != nil {
		t.Fatalf("read immutable same-page receipt: %v", err)
	}
	if receiptAction != "PAGE_APPLIED" || receiptHash != pageDigest {
		t.Fatalf("same-page receipt action/hash=%s/%s, want PAGE_APPLIED/%s",
			receiptAction, receiptHash, pageDigest)
	}
	if err := harness.db.QueryRow(context.Background(), `
		SELECT count(*) FROM audit_records
		WHERE workspace_id=$1 AND request_id='source-page:'||$2||':1'
	`, fixture.workspaceID, run.id).Scan(&auditCountBefore); err != nil {
		t.Fatalf("count immutable same-page receipt: %v", err)
	}

	replayTx, err := harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin exact same-page replay: %v", err)
	}
	var replayReceiptID string
	if err := replayTx.QueryRow(context.Background(), `
		SELECT id::text FROM audit_records
		WHERE tenant_id=$1 AND workspace_id=$2 AND action='PAGE_APPLIED'
		  AND resource_type='ASSET_SOURCE_RUN' AND resource_id=$3
		  AND request_id='source-page:'||$3||':1' AND payload_hash=$4
	`, fixture.tenantID, fixture.workspaceID, run.id, pageDigest).Scan(&replayReceiptID); err != nil {
		_ = replayTx.Rollback(context.Background())
		t.Fatalf("resolve exact same-page replay: %v", err)
	}
	if err := replayTx.Commit(context.Background()); err != nil {
		t.Fatalf("commit read-only exact same-page replay: %v", err)
	}
	if replayReceiptID != receiptID {
		t.Fatalf("exact same-page replay receipt=%s, want immutable receipt %s",
			replayReceiptID, receiptID)
	}

	var sourceNameBefore string
	var sourceVersionBefore int64
	if err := harness.db.QueryRow(context.Background(), `
		SELECT name,version FROM asset_sources WHERE id=$1
	`, fixture.sourceID).Scan(&sourceNameBefore, &sourceVersionBefore); err != nil {
		t.Fatalf("read source before changed replay: %v", err)
	}
	changedReplayTx, err := harness.db.BeginTx(
		context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable},
	)
	if err != nil {
		t.Fatalf("begin changed same-page replay: %v", err)
	}
	if _, err := changedReplayTx.Exec(context.Background(), `
		UPDATE asset_sources SET name='c1 changed replay must roll back',version=version+1
		WHERE id=$1
	`, fixture.sourceID); err != nil {
		_ = changedReplayTx.Rollback(context.Background())
		t.Fatalf("stage mutation before changed same-page replay: %v", err)
	}
	_, changedReplayErr := changedReplayTx.Exec(context.Background(), `
		INSERT INTO audit_records (
			id,tenant_id,workspace_id,actor_type,actor_id,action,resource_type,
			resource_id,request_id,trace_id,payload_hash
		) VALUES (
			gen_random_uuid(),$1,$2,'SYSTEM','closure-rollover-worker','PAGE_APPLIED',
			'ASSET_SOURCE_RUN',$3,'source-page:'||$3||':1','c1-changed-replay',repeat('f',64)
		)
	`, fixture.tenantID, fixture.workspaceID, run.id)
	assertRuntimePostgresError(t, changedReplayErr, "23505", "asset_management_idempotency_audit_uk")
	if err := changedReplayTx.Rollback(context.Background()); err != nil {
		t.Fatalf("roll back changed same-page replay transaction: %v", err)
	}

	var auditCountAfter int64
	if err := harness.db.QueryRow(context.Background(), `
		SELECT count(*) FROM audit_records
		WHERE workspace_id=$1 AND request_id='source-page:'||$2||':1'
	`, fixture.workspaceID, run.id).Scan(&auditCountAfter); err != nil {
		t.Fatalf("count same-page receipt after changed replay: %v", err)
	}
	if auditCountBefore != 1 || auditCountAfter != auditCountBefore {
		t.Fatalf("same-page replay changed receipt count from %d to %d", auditCountBefore, auditCountAfter)
	}
	var sourceNameAfter string
	var sourceVersionAfter int64
	if err := harness.db.QueryRow(context.Background(), `
		SELECT name,version FROM asset_sources WHERE id=$1
	`, fixture.sourceID).Scan(&sourceNameAfter, &sourceVersionAfter); err != nil {
		t.Fatalf("read source after changed replay rollback: %v", err)
	}
	if sourceNameAfter != sourceNameBefore || sourceVersionAfter != sourceVersionBefore {
		t.Fatalf("changed replay transaction leaked source name/version %q/%d, want %q/%d",
			sourceNameAfter, sourceVersionAfter, sourceNameBefore, sourceVersionBefore)
	}

	run.checkpointVersion = runCheckpoint
	run.pageSequence = pageSequence
	duplicate := newRuntimeObservation(fixture, run,
		"8fa00000-0000-4000-8000-000000000002", observation.externalID, "c")
	duplicate.freshnessKind = "OBJECT_SEQUENCE"
	duplicate.freshnessSequence = 2
	expectRuntimeContractError(t, harness.db, "23505", "asset_observations_same_run_object_uk",
		insertRuntimeObservationSQL, runtimeObservationArguments(duplicate)...)

	var finalSourceCheckpoint, finalRunCheckpoint, finalPageSequence int64
	if err := harness.db.QueryRow(context.Background(), `
		SELECT source.checkpoint_version,run.checkpoint_version,run.page_sequence
		FROM asset_sources AS source
		JOIN asset_source_runs AS run ON run.source_id=source.id
		WHERE source.id=$1 AND run.id=$2
	`, fixture.sourceID, run.id).Scan(
		&finalSourceCheckpoint, &finalRunCheckpoint, &finalPageSequence,
	); err != nil {
		t.Fatalf("read state after replay and cross-page rollback: %v", err)
	}
	if finalSourceCheckpoint != sourceCheckpoint || finalRunCheckpoint != runCheckpoint ||
		finalPageSequence != pageSequence {
		t.Fatalf("replay/duplicate rollback changed source/run/page from %d/%d/%d to %d/%d/%d",
			sourceCheckpoint, runCheckpoint, pageSequence,
			finalSourceCheckpoint, finalRunCheckpoint, finalPageSequence)
	}
}

func TestAssetCatalogExternalObservationFreshnessAndUnchangedFactAcrossRuns(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)

	firstRun := startC1ExternalDiscoveryRun(t, harness.db, fixture,
		"8fa10000-0000-4000-8000-000000000001", "c1-freshness-run-1", "1")
	firstObservation := newRuntimeObservation(fixture, firstRun,
		"8fa10000-0000-4000-8000-000000000002", "c1-stable-object", "2")
	firstObservation.freshnessKind = "OBJECT_SEQUENCE"
	firstObservation.freshnessSequence = 100
	assetID := "8fa10000-0000-4000-8000-000000000003"
	typeDetailID := "8fa10000-0000-4000-8000-000000000004"
	commitC1FinalObservationPage(t, harness.db, fixture, firstRun, firstObservation,
		strings.Repeat("7", 64), assetID, typeDetailID, true, 1, 0, "3", "4")
	closeC1ExternalSuccess(t, harness.db, fixture, firstRun.id)

	var firstChain, firstFact, firstCheckpointSHA string
	var firstAssetVersion, firstTypeDetailCount, firstTypeDetailRevision int64
	if err := harness.db.QueryRow(context.Background(), `
		SELECT observation.observation_chain_sha256,observation.provider_fact_sha256,
			asset.version,source.checkpoint_sha256,
			(SELECT count(*) FROM asset_type_details WHERE asset_id=asset.id),
			(SELECT max(revision) FROM asset_type_details WHERE asset_id=asset.id)
		FROM asset_observations AS observation
		JOIN assets AS asset ON asset.last_observation_id=observation.id
		JOIN asset_sources AS source ON source.id=observation.source_id
		WHERE observation.id=$1 AND asset.id=$2
	`, firstObservation.id, assetID).Scan(
		&firstChain, &firstFact, &firstAssetVersion, &firstCheckpointSHA,
		&firstTypeDetailCount, &firstTypeDetailRevision,
	); err != nil {
		t.Fatalf("read first external observation projection: %v", err)
	}
	if firstFact != strings.Repeat("7", 64) || firstTypeDetailCount != 1 ||
		firstTypeDetailRevision != 1 {
		t.Fatalf("first projection fact/details=%s/%d/%d, want stable fact and one detail revision",
			firstFact, firstTypeDetailCount, firstTypeDetailRevision)
	}

	secondRun := startC1ExternalDiscoveryRun(t, harness.db, fixture,
		"8fa10000-0000-4000-8000-000000000005", "c1-freshness-run-2", "5")
	var secondCursorBefore string
	if err := harness.db.QueryRow(context.Background(), `
		SELECT cursor_before_sha256 FROM asset_source_runs WHERE id=$1
	`, secondRun.id).Scan(&secondCursorBefore); err != nil {
		t.Fatalf("read later-run cursor before: %v", err)
	}
	if secondRun.checkpointVersion != firstRun.checkpointVersion+1 ||
		secondCursorBefore != firstCheckpointSHA {
		t.Fatalf("later run checkpoint/hash=%d/%s, want %d/%s",
			secondRun.checkpointVersion, secondCursorBefore,
			firstRun.checkpointVersion+1, firstCheckpointSHA)
	}

	for _, test := range []struct {
		name             string
		observationID    string
		freshness        int64
		providerFactHash string
	}{
		{"freshness regression", "8fa10000-0000-4000-8000-000000000006", 99, strings.Repeat("7", 64)},
		{"equal order different fact collision", "8fa10000-0000-4000-8000-000000000007", 100, strings.Repeat("8", 64)},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := newRuntimeObservation(fixture, secondRun,
				test.observationID, firstObservation.externalID, "6")
			candidate.freshnessKind = "OBJECT_SEQUENCE"
			candidate.freshnessSequence = test.freshness
			candidate.previousID = firstObservation.id
			candidate.previousChain = firstChain
			expectRuntimeContractError(t, harness.db, "55000",
				"asset_observations_freshness_monotonic_guard", insertRuntimeObservationSQL,
				c1ObservationArguments(candidate, test.providerFactHash)...)

			var observations int64
			if err := harness.db.QueryRow(context.Background(), `
				SELECT count(*) FROM asset_observations
				WHERE source_id=$1 AND external_id=$2
			`, fixture.sourceID, firstObservation.externalID).Scan(&observations); err != nil {
				t.Fatalf("count observations after rejected freshness replay: %v", err)
			}
			if observations != 1 {
				t.Fatalf("rejected freshness replay left %d observations, want 1", observations)
			}
		})
	}

	unchangedObservation := newRuntimeObservation(fixture, secondRun,
		"8fa10000-0000-4000-8000-000000000008", firstObservation.externalID, "9")
	unchangedObservation.freshnessKind = "OBJECT_SEQUENCE"
	unchangedObservation.freshnessSequence = 101
	unchangedObservation.previousID = firstObservation.id
	unchangedObservation.previousChain = firstChain
	commitC1FinalObservationPage(t, harness.db, fixture, secondRun, unchangedObservation,
		firstFact, assetID, typeDetailID, false, 0, 1, "a", "b")
	closeC1ExternalSuccess(t, harness.db, fixture, secondRun.id)

	var observationCount, distinctFactCount, distinctChainCount int64
	var assetVersion, typeDetailCount, typeDetailRevision int64
	var projectedObservationID string
	if err := harness.db.QueryRow(context.Background(), `
		SELECT count(*),count(DISTINCT provider_fact_sha256),
			count(DISTINCT observation_chain_sha256)
		FROM asset_observations
		WHERE source_id=$1 AND external_id=$2
	`, fixture.sourceID, firstObservation.externalID).Scan(
		&observationCount, &distinctFactCount, &distinctChainCount,
	); err != nil {
		t.Fatalf("read later-run unchanged observation chain: %v", err)
	}
	if err := harness.db.QueryRow(context.Background(), `
		SELECT asset.version,asset.last_observation_id::text,
			(SELECT count(*) FROM asset_type_details WHERE asset_id=asset.id),
			(SELECT max(revision) FROM asset_type_details WHERE asset_id=asset.id)
		FROM assets AS asset WHERE asset.id=$1
	`, assetID).Scan(
		&assetVersion, &projectedObservationID, &typeDetailCount, &typeDetailRevision,
	); err != nil {
		t.Fatalf("read later-run unchanged projection: %v", err)
	}
	if observationCount != 2 || distinctFactCount != 1 || distinctChainCount != 2 ||
		assetVersion != firstAssetVersion+1 || projectedObservationID != unchangedObservation.id ||
		typeDetailCount != firstTypeDetailCount || typeDetailRevision != firstTypeDetailRevision {
		t.Fatalf("unchanged later-run closure observations/facts/chains=%d/%d/%d asset=%d/%s details=%d/%d",
			observationCount, distinctFactCount, distinctChainCount, assetVersion,
			projectedObservationID, typeDetailCount, typeDetailRevision)
	}
}

func TestAssetCatalogExternalRevisionCASAndDirectTerminalInsertFailClosed(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)

	var sourceVersion, revisionCount int64
	if err := harness.db.QueryRow(context.Background(), `
		SELECT source.version,
			(SELECT count(*) FROM asset_source_revisions WHERE source_id=source.id)
		FROM asset_sources AS source WHERE source.id=$1
	`, fixture.sourceID).Scan(&sourceVersion, &revisionCount); err != nil {
		t.Fatalf("read external revision CAS baseline: %v", err)
	}

	t.Run("non-monotonic source revision", func(t *testing.T) {
		expectRuntimeContractError(t, harness.db, "55000",
			"asset_source_revisions_sequence_guard", c1ExternalRevisionInsertSQL,
			"8fa20000-0000-4000-8000-000000000001", fixture.tenantID,
			fixture.workspaceID, fixture.sourceID, int64(3), fixture.integrationID,
			strings.Repeat("1", 64), sourceVersion)
	})
	t.Run("stale source CAS", func(t *testing.T) {
		expectRuntimeContractError(t, harness.db, "55000",
			"asset_source_revisions_source_version_guard", c1ExternalRevisionInsertSQL,
			"8fa20000-0000-4000-8000-000000000002", fixture.tenantID,
			fixture.workspaceID, fixture.sourceID, int64(2), fixture.integrationID,
			strings.Repeat("2", 64), sourceVersion-1)
	})
	t.Run("direct terminal run insert", func(t *testing.T) {
		expectRuntimeContractError(t, harness.db, "23514",
			"asset_source_runs_initial_state_guard", `
				INSERT INTO asset_source_runs (
					id,tenant_id,workspace_id,source_id,source_revision,
					source_revision_digest,run_kind,status,stage_code,trigger_type,
					gate_revision,idempotency_key,request_hash,checkpoint_version,
					cursor_before_sha256,completed_at
				) SELECT '8fa20000-0000-4000-8000-000000000003',$1,$2,source.id,
					source.published_revision,source.published_revision_digest,'DISCOVERY',
					'SUCCEEDED','COMPLETED','SCHEDULED',source.gate_revision,
					'c1-direct-terminal',repeat('3',64),source.checkpoint_version,
					source.checkpoint_sha256,statement_timestamp()
				FROM asset_sources AS source WHERE source.id=$3
			`, fixture.tenantID, fixture.workspaceID, fixture.sourceID)
	})

	var sourceVersionAfter, revisionCountAfter, directTerminalCount int64
	if err := harness.db.QueryRow(context.Background(), `
		SELECT source.version,
			(SELECT count(*) FROM asset_source_revisions WHERE source_id=source.id),
			(SELECT count(*) FROM asset_source_runs
			 WHERE id='8fa20000-0000-4000-8000-000000000003')
		FROM asset_sources AS source WHERE source.id=$1
	`, fixture.sourceID).Scan(
		&sourceVersionAfter, &revisionCountAfter, &directTerminalCount,
	); err != nil {
		t.Fatalf("read external revision CAS rollback state: %v", err)
	}
	if sourceVersionAfter != sourceVersion || revisionCountAfter != revisionCount ||
		directTerminalCount != 0 {
		t.Fatalf("rejected revision/run mutations changed source/revisions/run=%d/%d/%d, want %d/%d/0",
			sourceVersionAfter, revisionCountAfter, directTerminalCount,
			sourceVersion, revisionCount)
	}
}

func TestAssetCatalogPublishedExternalBindingIsImmutableAndDriftClosesGate(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)

	immutableCases := []struct {
		name       string
		assignment string
	}{
		{"canonical schema", `canonical_provider_schema=convert_to('{"changed":true}','UTF8')`},
		{"integration", `integration_id=NULL`},
		{"sync mode", `sync_mode='SCHEDULED'`},
		{"authority scope", `authority_scope_digest=repeat('a',64)`},
		{"source definition", `source_definition_digest=repeat('a',64)`},
		{"canonical binding digest", `canonical_revision_digest=repeat('a',64)`},
		{"credential reference", `credential_reference_id='opaque-credential-changed'`},
		{"trust reference", `trust_reference_id='opaque-trust'`},
		{"network reference", `network_policy_reference_id='opaque-network'`},
		{"rate limit", `rate_limit_requests=101`},
		{"backpressure", `backpressure_max_seconds=61`},
		{"profile", `profile_code='EXTERNAL_V2'`},
		{"schedule", `schedule_expression='@daily'`},
	}
	for _, test := range immutableCases {
		t.Run(test.name, func(t *testing.T) {
			expectRuntimeContractError(t, harness.db, "55000",
				"asset_source_revisions_canonical_immutable_guard", `
					UPDATE asset_source_revisions SET `+test.assignment+`,version=version+1
					WHERE id=$1
				`, fixture.revisionID)
		})
	}

	publishClosureExternalSuccessor(t, harness.db, fixture)
	var publishedRevision, sourceGateRevision, validationGateRevision int64
	var oldState, gateStatus string
	if err := harness.db.QueryRow(context.Background(), `
		SELECT source.published_revision,source.gate_revision,source.gate_status,
			old_revision.state,validation_run.gate_revision
		FROM asset_sources AS source
		JOIN asset_source_revisions AS old_revision
		  ON old_revision.source_id=source.id AND old_revision.revision=1
		JOIN asset_source_revisions AS current_revision
		  ON current_revision.source_id=source.id
		 AND current_revision.revision=source.published_revision
		JOIN asset_source_runs AS validation_run
		  ON validation_run.id=current_revision.validation_run_id
		WHERE source.id=$1
	`, fixture.sourceID).Scan(
		&publishedRevision, &sourceGateRevision, &gateStatus, &oldState,
		&validationGateRevision,
	); err != nil {
		t.Fatalf("read successor publication gate arithmetic: %v", err)
	}
	if publishedRevision != 2 || oldState != "SUPERSEDED" || gateStatus != "AVAILABLE" ||
		sourceGateRevision != validationGateRevision+3 {
		t.Fatalf("successor publication revision/old/gate/epoch=%d/%s/%s/%d run=%d",
			publishedRevision, oldState, gateStatus, sourceGateRevision, validationGateRevision)
	}

	execAssetSQL(t, harness.db, `
		UPDATE asset_sources
		SET validated_binding_digest=repeat('f',64),version=version+1
		WHERE id=$1
	`, fixture.sourceID)
	var driftClosed bool
	if err := harness.db.QueryRow(context.Background(), `
		SELECT gate_status='UNAVAILABLE' AND gate_reason_code='BOUND_REFERENCE_DRIFT' AND
			gate_revision=$2+1 AND validated_run_id IS NULL AND validation_digest IS NULL AND
			validated_binding_digest IS NULL
		FROM asset_sources WHERE id=$1
	`, fixture.sourceID, sourceGateRevision).Scan(&driftClosed); err != nil {
		t.Fatalf("read binding drift gate closure: %v", err)
	}
	if !driftClosed {
		t.Fatal("persisted binding drift did not atomically fail close the available external source")
	}
}

func TestAssetCatalogExternalPageReceiptsCannotSwapActionRequestOrHash(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	run := startC1ExternalDiscoveryRun(t, harness.db, fixture,
		"8fa30000-0000-4000-8000-000000000001", "c1-receipt-swap-run", "1")

	pageDigest := strings.Repeat("2", 64)
	relationDigest := strings.Repeat("3", 64)
	itemRequest := "source-page:" + run.id + ":1"
	relationRequest := "source-relation-page:" + run.id + ":1"
	cases := []struct {
		name            string
		itemAction      string
		itemRequest     string
		itemHash        string
		relationAction  string
		relationRequest string
		relationHash    string
	}{
		{
			name: "swapped action", itemAction: "RELATION_PAGE_COMMITTED",
			itemRequest: itemRequest, itemHash: pageDigest, relationAction: "PAGE_APPLIED",
			relationRequest: relationRequest, relationHash: relationDigest,
		},
		{
			name: "swapped request", itemAction: "PAGE_APPLIED",
			itemRequest: relationRequest, itemHash: pageDigest,
			relationAction: "RELATION_PAGE_COMMITTED", relationRequest: itemRequest,
			relationHash: relationDigest,
		},
		{
			name: "swapped hash", itemAction: "PAGE_APPLIED",
			itemRequest: itemRequest, itemHash: relationDigest,
			relationAction: "RELATION_PAGE_COMMITTED", relationRequest: relationRequest,
			relationHash: pageDigest,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
				"asset_source_runs_page_closure_guard", func(tx pgx.Tx) error {
					if _, err := tx.Exec(context.Background(), `
						INSERT INTO audit_records (
							id,tenant_id,workspace_id,actor_type,actor_id,action,
							resource_type,resource_id,request_id,trace_id,payload_hash
						) VALUES
							(gen_random_uuid(),$1,$2,'SYSTEM','c1-external-worker',$4,
							 'ASSET_SOURCE_RUN',$3,$5,'c1-forged-item',$6),
							(gen_random_uuid(),$1,$2,'SYSTEM','c1-external-worker',$7,
							 'ASSET_SOURCE_RUN',$3,$8,'c1-forged-relation',$9)
					`, fixture.tenantID, fixture.workspaceID, run.id,
						test.itemAction, test.itemRequest, test.itemHash,
						test.relationAction, test.relationRequest, test.relationHash); err != nil {
						return err
					}
					if _, err := tx.Exec(context.Background(), `
						WITH envelope AS (
							SELECT decode('01'||repeat('04',12)||repeat('05',16),'hex') AS ciphertext
						)
						UPDATE asset_sources AS source
						SET checkpoint_ciphertext=envelope.ciphertext,
							checkpoint_key_id='opaque-c1-forged-key',
							checkpoint_sha256=encode(sha256(envelope.ciphertext),'hex'),
							checkpoint_version=source.checkpoint_version+1,
							version=source.version+1
						FROM envelope WHERE source.id=$1
					`, fixture.sourceID); err != nil {
						return err
					}
					_, err := tx.Exec(context.Background(), `
						UPDATE asset_source_runs
						SET stage_code='APPLYING',page_sequence=page_sequence+1,page_digest=$2,
							relation_page_sequence=relation_page_sequence+1,
							relation_page_digest=$4,
							checkpoint_version=checkpoint_version+1,
							cursor_after_sha256=(SELECT checkpoint_sha256 FROM asset_sources WHERE id=$3),
							heartbeat_sequence=heartbeat_sequence+1,
							heartbeat_at=statement_timestamp(),
							lease_expires_at=lease_expires_at+interval '1 minute',version=version+1
						WHERE id=$1
					`, run.id, pageDigest, fixture.sourceID, relationDigest)
					return err
				})

			var sourceCheckpoint, runCheckpoint, pageSequence, relationSequence int64
			if err := harness.db.QueryRow(context.Background(), `
				SELECT source.checkpoint_version,run.checkpoint_version,
					run.page_sequence,run.relation_page_sequence
				FROM asset_sources AS source
				JOIN asset_source_runs AS run ON run.source_id=source.id
				WHERE source.id=$1 AND run.id=$2
			`, fixture.sourceID, run.id).Scan(
				&sourceCheckpoint, &runCheckpoint, &pageSequence, &relationSequence,
			); err != nil {
				t.Fatalf("read forged receipt rollback state: %v", err)
			}
			if sourceCheckpoint != run.checkpointVersion || runCheckpoint != run.checkpointVersion ||
				pageSequence != 0 || relationSequence != 0 {
				t.Fatalf("forged receipt changed source/run/item/relation=%d/%d/%d/%d",
					sourceCheckpoint, runCheckpoint, pageSequence, relationSequence)
			}
		})
	}
}

func TestAssetCatalogTrulySuspendedExternalSourceCannotReuseOldValidation(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	run := startC1ExternalDiscoveryRun(t, harness.db, fixture,
		"8fa40000-0000-4000-8000-000000000001", "c1-suspension-run", "1")

	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs
		SET stage_code='CLEANING_UP',cleanup_status='PENDING',
			cleanup_attempt_id=gen_random_uuid(),cleanup_attempt_epoch=fence_epoch,
			version=version+1 WHERE id=$1
	`, run.id)
	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs
		SET status='FINALIZING',work_result_kind='FAILURE_INTENT',
			work_result_status='FAILED',work_result_digest=repeat('2',64),
			version=version+1 WHERE id=$1
	`, run.id)

	tx, err := harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin true external suspension closure: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var cleanupEpoch int64
	if err := tx.QueryRow(context.Background(), `
		SELECT cleanup_attempt_epoch FROM asset_source_runs WHERE id=$1
	`, run.id).Scan(&cleanupEpoch); err != nil {
		t.Fatalf("read true suspension cleanup epoch: %v", err)
	}
	cleanupDigest := strings.Repeat("3", 64)
	insertCleanupAudit(t, tx, fixture, run.id, cleanupEpoch, cleanupDigest)
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs
		SET cleanup_status='UNCERTAIN',cleanup_digest=$2,version=version+1
		WHERE id=$1
	`, run.id, cleanupDigest)
	var overrideDigest string
	if err := tx.QueryRow(context.Background(), `
		SELECT asset_catalog_source_run_failure_override_digest(run,'CLEANUP_UNCERTAIN')
		FROM asset_source_runs AS run WHERE id=$1
	`, run.id).Scan(&overrideDigest); err != nil {
		t.Fatalf("compute true suspension failure override: %v", err)
	}
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs
		SET failure_code='CLEANUP_UNCERTAIN',terminal_failure_override='CLEANUP_UNCERTAIN',
			terminal_failure_override_digest=$2,version=version+1 WHERE id=$1
	`, run.id, overrideDigest)
	terminalDigest := sourceRunTerminalDigest(t, tx, run.id, "FAILED", "CLEANUP_UNCERTAIN")
	insertTerminalAudit(t, tx, fixture, run.id, terminalDigest)
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs
		SET status='FAILED',stage_code='COMPLETED',terminal_command_sha256=$2,
			version=version+1 WHERE id=$1
	`, run.id, terminalDigest)
	execAssetSQL(t, tx, `
		UPDATE asset_sources
		SET gate_status='SUSPENDED',gate_reason_code='CLEANUP_UNCERTAIN',
			gate_revision=gate_revision+1,version=version+1 WHERE id=$1
	`, fixture.sourceID)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit true external suspension closure: %v", err)
	}

	var trulySuspended bool
	if err := harness.db.QueryRow(context.Background(), `
		SELECT source.status='ACTIVE' AND source.gate_status='SUSPENDED' AND
			source.gate_reason_code='CLEANUP_UNCERTAIN' AND
			source.gate_revision=run.gate_revision+1 AND
			source.validated_run_id IS NULL AND source.validation_digest IS NULL AND
			source.validated_binding_digest IS NULL AND run.status='FAILED' AND
			run.cleanup_status='UNCERTAIN' AND
			run.terminal_failure_override='CLEANUP_UNCERTAIN'
		FROM asset_sources AS source
		JOIN asset_source_runs AS run ON run.source_id=source.id
		WHERE source.id=$1 AND run.id=$2
	`, fixture.sourceID, run.id).Scan(&trulySuspended); err != nil {
		t.Fatalf("read true external suspension: %v", err)
	}
	if !trulySuspended {
		t.Fatal("external source did not reach SUSPENDED through an exact failed cleanup-uncertain run")
	}

	execAssetSQL(t, harness.db, `
		UPDATE asset_sources
		SET status='PAUSED',gate_status='UNAVAILABLE',
			gate_reason_code='SOURCE_NOT_ACTIVE',gate_revision=gate_revision+1,
			version=version+1 WHERE id=$1
	`, fixture.sourceID)
	execAssetSQL(t, harness.db, `
		UPDATE asset_sources SET status='ACTIVE',version=version+1 WHERE id=$1
	`, fixture.sourceID)
	var unavailableGateRevision int64
	if err := harness.db.QueryRow(context.Background(), `
		SELECT gate_revision FROM asset_sources
		WHERE id=$1 AND status='ACTIVE' AND gate_status='UNAVAILABLE'
		  AND gate_reason_code='SOURCE_NOT_ACTIVE'
	`, fixture.sourceID).Scan(&unavailableGateRevision); err != nil {
		t.Fatalf("read post-suspension unavailable gate: %v", err)
	}

	expectRuntimeContractError(t, harness.db, "23514", "asset_sources_available_gate_guard", `
		UPDATE asset_sources AS source
		SET gate_status='AVAILABLE',gate_reason_code=NULL,
			gate_revision=source.gate_revision+1,
			validated_run_id=revision.validation_run_id,
			validation_digest=revision.validation_digest,
			validated_binding_digest=revision.canonical_revision_digest,
			version=source.version+1
		FROM asset_source_revisions AS revision
		WHERE source.id=$1 AND revision.source_id=source.id AND revision.state='PUBLISHED'
	`, fixture.sourceID)

	var remainedClosed bool
	if err := harness.db.QueryRow(context.Background(), `
		SELECT status='ACTIVE' AND gate_status='UNAVAILABLE' AND
			gate_reason_code='SOURCE_NOT_ACTIVE' AND gate_revision=$2 AND
			validated_run_id IS NULL AND validation_digest IS NULL AND
			validated_binding_digest IS NULL
		FROM asset_sources WHERE id=$1
	`, fixture.sourceID, unavailableGateRevision).Scan(&remainedClosed); err != nil {
		t.Fatalf("read rejected old-validation reuse state: %v", err)
	}
	if !remainedClosed {
		t.Fatal("rejected old validation reuse changed the post-suspension unavailable gate")
	}
}

const c1ExternalRevisionInsertSQL = `
	INSERT INTO asset_source_revisions (
		id,tenant_id,workspace_id,source_id,revision,
		canonical_provider_schema,canonical_provider_schema_sha256,integration_id,sync_mode,
		authority_scope_digest,source_definition_digest,canonical_revision_digest,
		credential_reference_id,rate_limit_requests,rate_limit_window_seconds,
		backpressure_base_seconds,backpressure_max_seconds,profile_code,
		created_by,change_reason_code,expected_source_version
	) VALUES ($1,$2,$3,$4,$5,convert_to('{"type":"object"}','UTF8'),
		encode(sha256(convert_to('{"type":"object"}','UTF8')),'hex'),$6,'ON_DEMAND',
		repeat('4',64),repeat('5',64),$7,'opaque-credential',100,60,1,60,
		'EXTERNAL_V1','c1-test','DEFINITION_CHANGE',$8)
`

func startC1ExternalDiscoveryRun(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	runID string,
	idempotencyKey string,
	requestHashCharacter string,
) runtimeContractRun {
	t.Helper()
	run := runtimeContractRun{id: runID}
	var gateRevision int64
	var checkpointSHA string
	if err := database.QueryRow(context.Background(), `
		SELECT source.published_revision,source.published_revision_digest,
			revision.source_definition_digest,source.gate_revision,
			source.checkpoint_version,source.checkpoint_sha256,source.provider_kind
		FROM asset_sources AS source
		JOIN asset_source_revisions AS revision
		  ON revision.source_id=source.id AND revision.revision=source.published_revision
		WHERE source.id=$1
	`, fixture.sourceID).Scan(&run.revision, &run.revisionDigest,
		&run.sourceDefinitionDigest, &gateRevision, &run.checkpointVersion,
		&checkpointSHA, &run.providerKind); err != nil {
		t.Fatalf("read C1 external discovery admission: %v", err)
	}
	execAssetSQL(t, database, `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,trigger_type,gate_revision,idempotency_key,request_hash,
			cursor_before_sha256,checkpoint_version
		) VALUES ($1,$2,$3,$4,$5,$6,'DISCOVERY','SCHEDULED',$7,$8,$9,$10,$11)
	`, run.id, fixture.tenantID, fixture.workspaceID, fixture.sourceID, run.revision,
		run.revisionDigest, gateRevision, idempotencyKey,
		strings.Repeat(requestHashCharacter, 64), checkpointSHA, run.checkpointVersion)
	execAssetSQL(t, database, `
		UPDATE asset_source_runs
		SET status='RUNNING',stage_code='READING',lease_owner='c1-external-worker',
			lease_expires_at=statement_timestamp()+interval '10 minutes',fence_epoch=1,
			fence_token_hash=repeat('c',64),heartbeat_sequence=1,
			heartbeat_at=statement_timestamp(),version=version+1 WHERE id=$1
	`, run.id)
	execAssetSQL(t, database, `
		UPDATE asset_source_runs SET stage_code='NORMALIZING',version=version+1 WHERE id=$1
	`, run.id)
	if err := database.QueryRow(context.Background(), `
		SELECT checkpoint_version,fence_epoch,page_sequence
		FROM asset_source_runs WHERE id=$1
	`, run.id).Scan(&run.checkpointVersion, &run.fenceEpoch, &run.pageSequence); err != nil {
		t.Fatalf("read C1 external discovery coordinates: %v", err)
	}
	return run
}

func c1ObservationArguments(candidate runtimeObservation, providerFactHash string) []any {
	arguments := runtimeObservationArguments(candidate)
	arguments[14] = providerFactHash
	return arguments
}

func commitC1FinalObservationPage(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	run runtimeContractRun,
	observation runtimeObservation,
	providerFactHash string,
	assetID string,
	typeDetailID string,
	createProjection bool,
	createdCount int64,
	unchangedCount int64,
	pageDigestCharacter string,
	relationDigestCharacter string,
) {
	t.Helper()
	execAssetSQL(t, database, `
		UPDATE asset_source_runs
		SET cleanup_status='PENDING',cleanup_attempt_id=gen_random_uuid(),
			cleanup_attempt_epoch=fence_epoch,version=version+1 WHERE id=$1
	`, run.id)

	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin C1 final observation page: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(context.Background(), insertRuntimeObservationSQL,
		c1ObservationArguments(observation, providerFactHash)...); err != nil {
		t.Fatalf("insert C1 final observation: %v", err)
	}
	if createProjection {
		execAssetSQL(t, tx, `
			INSERT INTO assets (
				id,tenant_id,workspace_id,environment_id,source_id,provider_kind,external_id,
				kind,display_name,last_observation_id,last_observation_chain_sha256,
				last_observed_at,last_source_revision,create_idempotency_key,
				create_request_hash
			) SELECT $1,observation.tenant_id,observation.workspace_id,
				observation.environment_id,observation.source_id,observation.provider_kind,
				observation.external_id,'LINUX_VM','c1 stable object',observation.id,
				observation.observation_chain_sha256,observation.observed_at,
				observation.source_revision,'c1-create-stable-object',repeat('d',64)
			FROM asset_observations AS observation WHERE observation.id=$2
		`, assetID, observation.id)
		details := []byte(`{"cpu_count":4}`)
		execAssetSQL(t, tx, `
			INSERT INTO asset_type_details (
				id,tenant_id,workspace_id,environment_id,asset_id,source_id,provider_kind,
				external_id,source_revision,source_observed_at,
				source_observation_chain_sha256,revision,schema_version,
				source_observation_id,details_document,details_sha256,actor_id
			) SELECT $1,observation.tenant_id,observation.workspace_id,
				observation.environment_id,$2,observation.source_id,
				observation.provider_kind,observation.external_id,
				observation.source_revision,observation.observed_at,
				observation.observation_chain_sha256,1,'linux-vm.v1',observation.id,
				$4,encode(sha256($4),'hex'),'c1-external-worker'
			FROM asset_observations AS observation WHERE observation.id=$3
		`, typeDetailID, assetID, observation.id, details)
	} else {
		execAssetSQL(t, tx, `
			UPDATE assets AS asset
			SET display_name='c1 stable object',
				last_observation_id=observation.id,
				last_observation_chain_sha256=observation.observation_chain_sha256,
				last_observed_at=observation.observed_at,
				last_source_revision=observation.source_revision,
				version=asset.version+1
			FROM asset_observations AS observation
			WHERE asset.id=$1 AND observation.id=$2
		`, assetID, observation.id)
	}

	pageDigest := strings.Repeat(pageDigestCharacter, 64)
	relationDigest := strings.Repeat(relationDigestCharacter, 64)
	if err := insertClosurePageReceipt(tx, fixture, run.id, 1, pageDigest); err != nil {
		t.Fatalf("insert C1 final item receipt: %v", err)
	}
	if err := insertClosureRelationPageReceipt(tx, fixture, run.id, 1, relationDigest); err != nil {
		t.Fatalf("insert C1 final relation receipt: %v", err)
	}
	execAssetSQL(t, tx, `
		WITH envelope AS (
			SELECT decode('01'||repeat(substr($2,1,2),12)||repeat(substr($2,3,2),16),'hex') AS ciphertext
		)
		UPDATE asset_sources AS source
		SET checkpoint_ciphertext=envelope.ciphertext,
			checkpoint_key_id='opaque-c1-key-'||substr($2,1,1),
			checkpoint_sha256=encode(sha256(envelope.ciphertext),'hex'),
			checkpoint_version=source.checkpoint_version+1,version=source.version+1
		FROM envelope WHERE source.id=$1
	`, fixture.sourceID, pageDigest)
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs
		SET status='FINALIZING',stage_code='CLEANING_UP',
			page_sequence=page_sequence+1,page_digest=$2,
			relation_page_sequence=relation_page_sequence+1,relation_page_digest=$4,
			checkpoint_version=checkpoint_version+1,
			cursor_after_sha256=(SELECT checkpoint_sha256 FROM asset_sources WHERE id=$3),
			final_page=true,complete_snapshot=true,effective_complete_snapshot=true,
			observed_count=observed_count+1,created_count=created_count+$5,
			unchanged_count=unchanged_count+$6,
			heartbeat_sequence=heartbeat_sequence+1,
			heartbeat_at=statement_timestamp(),
			lease_expires_at=lease_expires_at+interval '1 minute',
			work_result_kind='DATA_PROJECTION',work_result_status='SUCCEEDED',
			work_result_digest=repeat('e',64),version=version+1
		WHERE id=$1
	`, run.id, pageDigest, fixture.sourceID, relationDigest, createdCount, unchangedCount)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit C1 final observation page: %v", err)
	}
}

func closeC1ExternalSuccess(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	runID string,
) {
	t.Helper()
	revokeClosureAttempt(t, database, fixture, runID, strings.Repeat("f", 64))
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin C1 external terminal closure: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	terminalDigest := sourceRunTerminalDigest(t, tx, runID, "SUCCEEDED", nil)
	insertTerminalAudit(t, tx, fixture, runID, terminalDigest)
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs
		SET status='SUCCEEDED',stage_code='COMPLETED',terminal_command_sha256=$2,
			version=version+1 WHERE id=$1
	`, runID, terminalDigest)
	execAssetSQL(t, tx, `
		UPDATE asset_sources
		SET last_success_run_id=$2,
			last_success_at=(SELECT completed_at FROM asset_source_runs WHERE id=$2),
			last_complete_snapshot_run_id=$2,
			last_complete_snapshot_at=(SELECT completed_at FROM asset_source_runs WHERE id=$2),
			version=version+1 WHERE id=$1
	`, fixture.sourceID, runID)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit C1 external terminal closure: %v", err)
	}
}
