package postgres_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAssetCatalogLaterRunUnchangedObservationMayReuseFreshnessOrder(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)

	firstRun := startC1ExternalDiscoveryRun(t, harness.db, fixture,
		"8fb10000-0000-4000-8000-000000000001", "freshness-domain-run-1", "1")
	firstObservation := newRuntimeObservation(fixture, firstRun,
		"8fb10000-0000-4000-8000-000000000002", "freshness-domain-object", "2")
	firstObservation.freshnessKind = "OBJECT_SEQUENCE"
	firstObservation.freshnessSequence = 100
	assetID := "8fb10000-0000-4000-8000-000000000003"
	typeDetailID := "8fb10000-0000-4000-8000-000000000004"
	providerFact := strings.Repeat("7", 64)
	commitC1FinalObservationPage(t, harness.db, fixture, firstRun, firstObservation,
		providerFact, assetID, typeDetailID, true, 1, 0, "3", "4")
	closeC1ExternalSuccess(t, harness.db, fixture, firstRun.id)

	var firstChain string
	var firstAssetVersion int64
	if err := harness.db.QueryRow(context.Background(), `
		SELECT observation.observation_chain_sha256,asset.version
		FROM asset_observations AS observation
		JOIN assets AS asset ON asset.last_observation_id=observation.id
		WHERE observation.id=$1 AND asset.id=$2
	`, firstObservation.id, assetID).Scan(&firstChain, &firstAssetVersion); err != nil {
		t.Fatalf("read initial freshness-domain projection: %v", err)
	}

	secondRun := startC1ExternalDiscoveryRun(t, harness.db, fixture,
		"8fb10000-0000-4000-8000-000000000005", "freshness-domain-run-2", "5")
	unchanged := newRuntimeObservation(fixture, secondRun,
		"8fb10000-0000-4000-8000-000000000006", firstObservation.externalID, "6")
	unchanged.freshnessKind = "OBJECT_SEQUENCE"
	unchanged.freshnessSequence = firstObservation.freshnessSequence
	unchanged.previousID = firstObservation.id
	unchanged.previousChain = firstChain
	commitC1FinalObservationPage(t, harness.db, fixture, secondRun, unchanged,
		providerFact, assetID, typeDetailID, false, 0, 1, "8", "9")
	closeC1ExternalSuccess(t, harness.db, fixture, secondRun.id)

	var observations, facts, chains, assetVersion, detailCount, detailRevision int64
	if err := harness.db.QueryRow(context.Background(), `
		SELECT count(*),count(DISTINCT observation.provider_fact_sha256),
			count(DISTINCT observation.observation_chain_sha256),max(asset.version),
			(SELECT count(*) FROM asset_type_details WHERE asset_id=$3),
			(SELECT max(revision) FROM asset_type_details WHERE asset_id=$3)
		FROM asset_observations AS observation
		JOIN assets AS asset ON asset.source_id=observation.source_id
		 AND asset.external_id=observation.external_id
		WHERE observation.source_id=$1 AND observation.external_id=$2
	`, fixture.sourceID, firstObservation.externalID, assetID).Scan(
		&observations, &facts, &chains, &assetVersion, &detailCount, &detailRevision,
	); err != nil {
		t.Fatalf("read unchanged later-run freshness domain: %v", err)
	}
	if observations != 2 || facts != 1 || chains != 2 ||
		assetVersion != firstAssetVersion+1 || detailCount != 1 || detailRevision != 1 {
		t.Fatalf("unchanged later run observations/facts/chains/asset/details=%d/%d/%d/%d/%d/%d",
			observations, facts, chains, assetVersion, detailCount, detailRevision)
	}
}

func TestAssetCatalogLaterRunUnchangedRelationshipMayReuseFreshnessOrder(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)

	var beforeVersion, beforeCheckpoint, beforeOrder int64
	var beforeKind, beforeProviderVersion, beforeFact string
	if err := harness.db.QueryRow(context.Background(), `
		SELECT relationship.version,source.checkpoint_version,
			relationship.freshness_kind,relationship.freshness_order_sequence,
			relationship.provider_version_sha256,relationship.relation_fact_sha256
		FROM asset_relationships AS relationship
		JOIN asset_sources AS source ON source.id=relationship.source_id
		WHERE relationship.id=$1
	`, fixture.relationshipID).Scan(&beforeVersion, &beforeCheckpoint, &beforeKind,
		&beforeOrder, &beforeProviderVersion, &beforeFact); err != nil {
		t.Fatalf("read initial relationship freshness domain: %v", err)
	}
	if beforeKind != "OBJECT_SEQUENCE" || beforeOrder != 1 ||
		beforeProviderVersion != strings.Repeat("7", 64) || beforeFact != strings.Repeat("8", 64) {
		t.Fatalf("initial relationship freshness=%s/%d version=%s fact=%s",
			beforeKind, beforeOrder, beforeProviderVersion, beforeFact)
	}

	run := startC1ExternalDiscoveryRun(t, harness.db, fixture,
		"8fb10000-0000-4000-8000-000000000007", "freshness-domain-relation-run", "7")
	pageDigest := strings.Repeat("a", 64)
	relationDigest := strings.Repeat("b", 64)
	tx, err := harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin later-run unchanged relationship page: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(context.Background(), `
		UPDATE asset_relationships
		SET source_revision=$2,canonical_revision_digest=$3,last_run_id=$4,
			last_page_sequence=1,relation_page_sha256=$5,
			accepted_checkpoint_version=$6,run_fence_epoch=$7,version=version+1
		WHERE id=$1
	`, fixture.relationshipID, run.revision, run.revisionDigest, run.id,
		relationDigest, run.checkpointVersion+1, run.fenceEpoch); err != nil {
		failFreshnessDomainDatabaseError(t, "update later-run equal-exact relationship", err)
	}
	if err := insertClosurePageReceipt(tx, fixture, run.id, 1, pageDigest); err != nil {
		t.Fatalf("insert later-run item page receipt: %v", err)
	}
	if err := insertClosureRelationPageReceipt(tx, fixture, run.id, 1, relationDigest); err != nil {
		t.Fatalf("insert later-run relation page receipt: %v", err)
	}
	execAssetSQL(t, tx, `
		WITH envelope AS (
			SELECT decode('01'||repeat('0e',12)||repeat('0f',16),'hex') AS ciphertext
		)
		UPDATE asset_sources AS source
		SET checkpoint_ciphertext=envelope.ciphertext,
			checkpoint_key_id='opaque-freshness-relation-key',
			checkpoint_sha256=encode(sha256(envelope.ciphertext),'hex'),
			checkpoint_version=source.checkpoint_version+1,version=source.version+1
		FROM envelope WHERE source.id=$1
	`, fixture.sourceID)
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs
		SET stage_code='APPLYING',page_sequence=page_sequence+1,page_digest=$2,
			relation_page_sequence=relation_page_sequence+1,relation_page_digest=$4,
			checkpoint_version=checkpoint_version+1,
			cursor_after_sha256=(SELECT checkpoint_sha256 FROM asset_sources WHERE id=$3),
			heartbeat_sequence=heartbeat_sequence+1,
			heartbeat_at=statement_timestamp(),
			lease_expires_at=lease_expires_at+interval '1 minute',version=version+1
		WHERE id=$1
	`, run.id, pageDigest, fixture.sourceID, relationDigest)
	if err := tx.Commit(context.Background()); err != nil {
		failFreshnessDomainDatabaseError(t, "commit later-run equal-exact relationship page", err)
	}

	var lastRun, kind, providerVersion, fact, sourceCheckpointSHA, runCursorAfter string
	var relationshipVersion, sourceCheckpoint, runCheckpoint, pageSequence,
		relationSequence, order, acceptedCheckpoint, fence int64
	if err := harness.db.QueryRow(context.Background(), `
		SELECT relationship.last_run_id::text,relationship.version,
			relationship.freshness_kind,relationship.freshness_order_sequence,
			relationship.provider_version_sha256,relationship.relation_fact_sha256,
			relationship.accepted_checkpoint_version,relationship.run_fence_epoch,
			source.checkpoint_version,source.checkpoint_sha256,
			run.checkpoint_version,run.page_sequence,run.relation_page_sequence,
			run.cursor_after_sha256
		FROM asset_relationships AS relationship
		JOIN asset_sources AS source ON source.id=relationship.source_id
		JOIN asset_source_runs AS run ON run.id=relationship.last_run_id
		WHERE relationship.id=$1
	`, fixture.relationshipID).Scan(&lastRun, &relationshipVersion, &kind, &order,
		&providerVersion, &fact, &acceptedCheckpoint, &fence, &sourceCheckpoint,
		&sourceCheckpointSHA, &runCheckpoint, &pageSequence, &relationSequence,
		&runCursorAfter); err != nil {
		t.Fatalf("read later-run unchanged relationship closure: %v", err)
	}
	if lastRun != run.id || relationshipVersion != beforeVersion+1 ||
		kind != beforeKind || order != beforeOrder || providerVersion != beforeProviderVersion ||
		fact != beforeFact || acceptedCheckpoint != beforeCheckpoint+1 || fence != run.fenceEpoch ||
		sourceCheckpoint != beforeCheckpoint+1 || runCheckpoint != beforeCheckpoint+1 ||
		pageSequence != 1 || relationSequence != 1 || runCursorAfter != sourceCheckpointSHA {
		t.Fatalf("later-run relationship closure run=%s version=%d freshness=%s/%d provider=%s fact=%s accepted=%d fence=%d source/run/page/relation=%d/%d/%d/%d cursor=%s/%s",
			lastRun, relationshipVersion, kind, order, providerVersion, fact,
			acceptedCheckpoint, fence, sourceCheckpoint, runCheckpoint, pageSequence,
			relationSequence, runCursorAfter, sourceCheckpointSHA)
	}
	var receiptCount int
	if err := harness.db.QueryRow(context.Background(), `
		SELECT count(*)::integer FROM audit_records
		WHERE tenant_id=$1 AND workspace_id=$2 AND actor_type='SYSTEM'
		  AND actor_id='c1-external-worker' AND resource_type='ASSET_SOURCE_RUN'
		  AND resource_id=$3 AND (
			(action='PAGE_APPLIED' AND request_id='source-page:'||$3||':1' AND payload_hash=$4) OR
			(action='RELATION_PAGE_COMMITTED' AND request_id='source-relation-page:'||$3||':1'
			 AND payload_hash=$5)
		  )
	`, fixture.tenantID, fixture.workspaceID, run.id, pageDigest,
		relationDigest).Scan(&receiptCount); err != nil {
		t.Fatalf("read later-run exact item/relation receipts: %v", err)
	}
	if receiptCount != 2 {
		t.Fatalf("later-run exact item/relation receipt count=%d, want 2", receiptCount)
	}
}

func TestAssetCatalogObservationEqualOrderRejectsChangedProviderTuple(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)

	var previousChain, freshnessKind, providerVersion, providerFact string
	var freshnessOrder int64
	if err := harness.db.QueryRow(context.Background(), `
		SELECT observation_chain_sha256,freshness_kind,freshness_order_sequence,
			provider_version_sha256,provider_fact_sha256
		FROM asset_observations WHERE id=$1
	`, fixture.observationID).Scan(&previousChain, &freshnessKind, &freshnessOrder,
		&providerVersion, &providerFact); err != nil {
		t.Fatalf("read observation freshness collision baseline: %v", err)
	}
	run := startC1ExternalDiscoveryRun(t, harness.db, fixture,
		"8fb10000-0000-4000-8000-000000000101", "freshness-observation-collision", "a")

	for _, test := range []struct {
		name            string
		observationID   string
		providerVersion string
		providerFact    string
	}{
		{
			name:            "provider version collision",
			observationID:   "8fb10000-0000-4000-8000-000000000102",
			providerVersion: strings.Repeat("a", 64),
			providerFact:    providerFact,
		},
		{
			name:            "provider fact collision",
			observationID:   "8fb10000-0000-4000-8000-000000000103",
			providerVersion: providerVersion,
			providerFact:    strings.Repeat("b", 64),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := newRuntimeObservation(fixture, run, test.observationID,
				"external-host-a", "c")
			candidate.freshnessKind = freshnessKind
			candidate.freshnessSequence = freshnessOrder
			candidate.previousID = fixture.observationID
			candidate.previousChain = previousChain
			arguments := runtimeObservationArguments(candidate)
			arguments[13] = test.providerVersion
			arguments[14] = test.providerFact
			expectRuntimeContractError(t, harness.db, "55000",
				"asset_observations_freshness_monotonic_guard",
				insertRuntimeObservationSQL, arguments...)

			var observationCount int64
			if err := harness.db.QueryRow(context.Background(), `
				SELECT count(*) FROM asset_observations
				WHERE source_id=$1 AND external_id='external-host-a'
			`, fixture.sourceID).Scan(&observationCount); err != nil {
				t.Fatalf("count observations after rejected collision: %v", err)
			}
			if observationCount != 1 {
				t.Fatalf("rejected observation collision left %d observations, want 1",
					observationCount)
			}
		})
	}
}

func TestAssetCatalogRelationshipEqualOrderRejectsChangedProviderTuple(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)

	var beforeRow, providerVersion, relationFact string
	if err := harness.db.QueryRow(context.Background(), `
		SELECT to_jsonb(relationship)::text,provider_version_sha256,relation_fact_sha256
		FROM asset_relationships AS relationship WHERE id=$1
	`, fixture.relationshipID).Scan(&beforeRow, &providerVersion, &relationFact); err != nil {
		t.Fatalf("read relationship freshness collision baseline: %v", err)
	}
	run := startC1ExternalDiscoveryRun(t, harness.db, fixture,
		"8fb10000-0000-4000-8000-000000000104", "freshness-relationship-collision", "d")

	for _, test := range []struct {
		name            string
		providerVersion string
		relationFact    string
	}{
		{
			name:            "provider version collision",
			providerVersion: strings.Repeat("c", 64),
			relationFact:    relationFact,
		},
		{
			name:            "relation fact collision",
			providerVersion: providerVersion,
			relationFact:    strings.Repeat("d", 64),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			expectRuntimeContractError(t, harness.db, "55000",
				"asset_relationships_freshness_monotonic_guard", `
					UPDATE asset_relationships
					SET source_revision=$2,canonical_revision_digest=$3,last_run_id=$4,
						last_page_sequence=1,relation_page_sha256=repeat('e',64),
						accepted_checkpoint_version=$5,run_fence_epoch=$6,
						provider_version_sha256=$7,relation_fact_sha256=$8,
						version=version+1
					WHERE id=$1
				`, fixture.relationshipID, run.revision, run.revisionDigest, run.id,
				run.checkpointVersion+1, run.fenceEpoch, test.providerVersion,
				test.relationFact)

			var afterRow string
			if err := harness.db.QueryRow(context.Background(), `
				SELECT to_jsonb(relationship)::text
				FROM asset_relationships AS relationship WHERE id=$1
			`, fixture.relationshipID).Scan(&afterRow); err != nil {
				t.Fatalf("read relationship after rejected collision: %v", err)
			}
			if afterRow != beforeRow {
				t.Fatal("rejected relationship collision changed the persisted row")
			}
		})
	}
}

func TestAssetCatalogCanonicalSuccessorResetsObservationAndRelationshipFreshnessDomain(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)

	var seedChain string
	if err := harness.db.QueryRow(context.Background(), `
		SELECT observation_chain_sha256 FROM asset_observations WHERE id=$1
	`, fixture.observationID).Scan(&seedChain); err != nil {
		t.Fatalf("read seed observation chain for successor reset: %v", err)
	}
	baselineRun := startC1ExternalDiscoveryRun(t, harness.db, fixture,
		"8fb10000-0000-4000-8000-000000000201", "freshness-successor-baseline", "2")
	baselineObservation := newRuntimeObservation(fixture, baselineRun,
		"8fb10000-0000-4000-8000-000000000202", "external-host-a", "3")
	baselineObservation.freshnessKind = "OBJECT_SEQUENCE"
	baselineObservation.freshnessSequence = 100
	baselineObservation.previousID = fixture.observationID
	baselineObservation.previousChain = seedChain
	commitFreshnessDomainObservationRelationshipPage(t, harness.db, fixture,
		baselineRun, baselineObservation, "OBJECT_SEQUENCE", 100, "4", "5")
	closeC1ExternalSuccess(t, harness.db, fixture, baselineRun.id)

	var baselineObservationOrder, baselineRelationshipOrder int64
	if err := harness.db.QueryRow(context.Background(), `
		SELECT observation.freshness_order_sequence,relationship.freshness_order_sequence
		FROM asset_observations AS observation
		JOIN asset_relationships AS relationship ON relationship.id=$2
		WHERE observation.id=$1
	`, baselineObservation.id, fixture.relationshipID).Scan(
		&baselineObservationOrder, &baselineRelationshipOrder,
	); err != nil {
		t.Fatalf("read revision-one freshness baseline: %v", err)
	}
	if baselineObservationOrder != 100 || baselineRelationshipOrder != 100 {
		t.Fatalf("revision-one freshness orders=%d/%d, want 100/100",
			baselineObservationOrder, baselineRelationshipOrder)
	}

	publishClosureExternalSuccessor(t, harness.db, fixture)
	successorRun := startClosureExternalDiscoveryRun(t, harness.db, fixture)

	var observationsBefore int64
	var relationshipBefore string
	if err := harness.db.QueryRow(context.Background(), `
		SELECT count(*) FROM asset_observations
		WHERE source_id=$1 AND external_id='external-host-a'
	`, fixture.sourceID).Scan(&observationsBefore); err != nil {
		t.Fatalf("count observations before stale revision attempts: %v", err)
	}
	if err := harness.db.QueryRow(context.Background(), `
		SELECT to_jsonb(relationship)::text
		FROM asset_relationships AS relationship WHERE id=$1
	`, fixture.relationshipID).Scan(&relationshipBefore); err != nil {
		t.Fatalf("read relationship before stale revision attempt: %v", err)
	}

	oldRun := successorRun
	oldRun.revision = 1
	oldRun.revisionDigest = fixture.revisionDigest
	oldRevisionObservation := newRuntimeObservation(fixture, oldRun,
		"8fb10000-0000-4000-8000-000000000203", "external-host-a", "6")
	oldRevisionObservation.freshnessKind = "OBJECT_SEQUENCE"
	oldRevisionObservation.freshnessSequence = 101
	oldRevisionObservation.previousID = baselineObservation.id
	oldRevisionObservation.previousChain = baselineObservation.observationChain
	oldRevisionObservation.sourceDefinitionDigest = fixture.sourceDefinitionDigest
	oldArguments := runtimeObservationArguments(oldRevisionObservation)
	oldArguments[13] = strings.Repeat("1", 64)
	oldArguments[14] = strings.Repeat("2", 64)
	expectRuntimeContractError(t, harness.db, "23503",
		"asset_observations_run_revision_fk", insertRuntimeObservationSQL, oldArguments...)
	expectRuntimeContractError(t, harness.db, "55000",
		"asset_relationships_run_admission_guard", `
			UPDATE asset_relationships
			SET source_revision=1,canonical_revision_digest=$2,last_run_id=$3,
				last_page_sequence=1,relation_page_sha256=repeat('7',64),
				accepted_checkpoint_version=1,run_fence_epoch=$4,
				freshness_kind='OBJECT_SEQUENCE',freshness_order_time=NULL,
				freshness_order_sequence=101,version=version+1
			WHERE id=$1
		`, fixture.relationshipID, fixture.revisionDigest, successorRun.id,
		successorRun.fenceEpoch)

	var observationsAfter int64
	var relationshipAfter string
	if err := harness.db.QueryRow(context.Background(), `
		SELECT count(*) FROM asset_observations
		WHERE source_id=$1 AND external_id='external-host-a'
	`, fixture.sourceID).Scan(&observationsAfter); err != nil {
		t.Fatalf("count observations after stale revision attempts: %v", err)
	}
	if err := harness.db.QueryRow(context.Background(), `
		SELECT to_jsonb(relationship)::text
		FROM asset_relationships AS relationship WHERE id=$1
	`, fixture.relationshipID).Scan(&relationshipAfter); err != nil {
		t.Fatalf("read relationship after stale revision attempt: %v", err)
	}
	if observationsAfter != observationsBefore || relationshipAfter != relationshipBefore {
		t.Fatal("rejected old-revision candidates changed observation or relationship state")
	}

	successorObservation := newRuntimeObservation(fixture, successorRun,
		"8fb10000-0000-4000-8000-000000000204", "external-host-a", "8")
	successorObservation.freshnessKind = "CHECKPOINT_SEQUENCE"
	successorObservation.freshnessSequence = 1
	successorObservation.previousID = baselineObservation.id
	successorObservation.previousChain = baselineObservation.observationChain
	commitFreshnessDomainObservationRelationshipPage(t, harness.db, fixture,
		successorRun, successorObservation, "CHECKPOINT_SEQUENCE", 1, "9", "a")
	closeC1ExternalSuccess(t, harness.db, fixture, successorRun.id)

	var observationRevision, relationshipRevision, observationOrder, relationshipOrder int64
	var observationKind, relationshipKind, observationDigest, relationshipDigest,
		observationFact, relationshipFact, projectedObservation, projectedRun string
	if err := harness.db.QueryRow(context.Background(), `
		SELECT observation.source_revision,observation.canonical_revision_digest,
			observation.freshness_kind,observation.freshness_order_sequence,
			observation.provider_fact_sha256,
			asset.last_observation_id::text,
			relationship.source_revision,relationship.canonical_revision_digest,
			relationship.freshness_kind,relationship.freshness_order_sequence,
			relationship.relation_fact_sha256,relationship.last_run_id::text
		FROM asset_observations AS observation
		JOIN assets AS asset ON asset.id=$2
		JOIN asset_relationships AS relationship ON relationship.id=$3
		WHERE observation.id=$1
	`, successorObservation.id, fixture.assetID, fixture.relationshipID).Scan(
		&observationRevision, &observationDigest, &observationKind, &observationOrder,
		&observationFact, &projectedObservation, &relationshipRevision, &relationshipDigest,
		&relationshipKind, &relationshipOrder, &relationshipFact, &projectedRun,
	); err != nil {
		t.Fatalf("read canonical successor freshness projections: %v", err)
	}
	if observationRevision != 2 || relationshipRevision != 2 ||
		observationDigest != successorRun.revisionDigest || relationshipDigest != successorRun.revisionDigest ||
		observationKind != "CHECKPOINT_SEQUENCE" || relationshipKind != "CHECKPOINT_SEQUENCE" ||
		observationOrder != 1 || relationshipOrder != 1 ||
		observationFact != strings.Repeat("4", 64) || relationshipFact != strings.Repeat("5", 64) ||
		projectedObservation != successorObservation.id || projectedRun != successorRun.id {
		t.Fatalf("successor freshness observation=%d/%s/%s/%d/%s projection=%s relationship=%d/%s/%s/%d/%s run=%s",
			observationRevision, observationDigest, observationKind, observationOrder,
			observationFact, projectedObservation, relationshipRevision, relationshipDigest,
			relationshipKind, relationshipOrder, relationshipFact, projectedRun)
	}

	var closureComplete bool
	if err := harness.db.QueryRow(context.Background(), `
		SELECT run.status='SUCCEEDED' AND run.stage_code='COMPLETED' AND
			run.page_sequence=1 AND run.relation_page_sequence=1 AND
			run.checkpoint_version=1 AND run.final_page AND run.complete_snapshot AND
			run.effective_complete_snapshot AND run.cursor_after_sha256=source.checkpoint_sha256 AND
			source.published_revision=2 AND source.checkpoint_revision=2 AND
			source.checkpoint_version=1 AND source.gate_status='AVAILABLE' AND
			source.last_success_run_id=run.id AND source.last_complete_snapshot_run_id=run.id AND
			(SELECT count(*) FROM audit_records AS audit
			 WHERE audit.tenant_id=run.tenant_id AND audit.workspace_id=run.workspace_id
			   AND audit.resource_id=run.id::text AND audit.actor_type='SYSTEM'
			   AND audit.action IN ('PAGE_APPLIED','RELATION_PAGE_COMMITTED'))=2
		FROM asset_source_runs AS run
		JOIN asset_sources AS source ON source.id=run.source_id
		WHERE run.id=$1
	`, successorRun.id).Scan(&closureComplete); err != nil {
		t.Fatalf("read canonical successor page and terminal closure: %v", err)
	}
	if !closureComplete {
		t.Fatal("canonical successor did not close observation, relationship, checkpoint, receipts, and terminal pointers")
	}
}

func TestAssetCatalogCheckpointRolloverDoesNotResetFreshnessDomain(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)

	var previousChain, providerVersion, providerFact string
	if err := harness.db.QueryRow(context.Background(), `
		SELECT observation_chain_sha256,provider_version_sha256,provider_fact_sha256
		FROM asset_observations WHERE id=$1
	`, fixture.observationID).Scan(&previousChain, &providerVersion, &providerFact); err != nil {
		t.Fatalf("read checkpoint-rollover observation baseline: %v", err)
	}
	baselineRun := startC1ExternalDiscoveryRun(t, harness.db, fixture,
		"8fb10000-0000-4000-8000-000000000301", "freshness-rollover-baseline", "b")
	baselineObservation := newRuntimeObservation(fixture, baselineRun,
		"8fb10000-0000-4000-8000-000000000302", "external-host-a", "c")
	baselineObservation.freshnessKind = "OBJECT_SEQUENCE"
	baselineObservation.freshnessSequence = 100
	baselineObservation.previousID = fixture.observationID
	baselineObservation.previousChain = previousChain
	commitFreshnessDomainObservationRelationshipPage(t, harness.db, fixture,
		baselineRun, baselineObservation, "OBJECT_SEQUENCE", 100, "d", "e")
	closeC1ExternalSuccess(t, harness.db, fixture, baselineRun.id)

	run := startClosureExternalDiscoveryRun(t, harness.db, fixture)
	bindClosureExternalRollover(t, harness.db, fixture, run)
	var observationsBefore int64
	if err := harness.db.QueryRow(context.Background(), `
		SELECT count(*) FROM asset_observations
		WHERE source_id=$1 AND external_id='external-host-a'
	`, fixture.sourceID).Scan(&observationsBefore); err != nil {
		t.Fatalf("count observations before rejected rollover reset: %v", err)
	}

	candidate := newRuntimeObservation(fixture, run,
		"8fb10000-0000-4000-8000-000000000303", "external-host-a", "f")
	candidate.freshnessKind = "OBJECT_SEQUENCE"
	candidate.freshnessSequence = 1
	candidate.previousID = baselineObservation.id
	candidate.previousChain = baselineObservation.observationChain
	arguments := runtimeObservationArguments(candidate)
	arguments[13] = providerVersion
	arguments[14] = providerFact
	expectRuntimeContractError(t, harness.db, "55000",
		"asset_observations_freshness_monotonic_guard",
		insertRuntimeObservationSQL, arguments...)

	var relationshipBefore, relationshipProviderVersion, relationshipFact string
	if err := harness.db.QueryRow(context.Background(), `
		SELECT to_jsonb(relationship)::text,provider_version_sha256,relation_fact_sha256
		FROM asset_relationships AS relationship WHERE id=$1
	`, fixture.relationshipID).Scan(
		&relationshipBefore, &relationshipProviderVersion, &relationshipFact,
	); err != nil {
		t.Fatalf("read checkpoint-rollover relationship baseline: %v", err)
	}
	expectRuntimeContractError(t, harness.db, "55000",
		"asset_relationships_freshness_monotonic_guard", `
			UPDATE asset_relationships
			SET source_revision=$2,canonical_revision_digest=$3,last_run_id=$4,
				last_page_sequence=1,relation_page_sha256=repeat('c',64),
				accepted_checkpoint_version=$5,run_fence_epoch=$6,
				freshness_kind='OBJECT_SEQUENCE',freshness_order_time=NULL,
				freshness_order_sequence=1,provider_version_sha256=$7,
				relation_fact_sha256=$8,version=version+1
			WHERE id=$1
		`, fixture.relationshipID, run.revision, run.revisionDigest, run.id,
		run.checkpointVersion+1, run.fenceEpoch, relationshipProviderVersion,
		relationshipFact)

	var observationCount int64
	var relationshipAfter string
	if err := harness.db.QueryRow(context.Background(), `
		SELECT count(*) FROM asset_observations
		WHERE source_id=$1 AND external_id='external-host-a'
	`, fixture.sourceID).Scan(&observationCount); err != nil {
		t.Fatalf("count observations after rejected rollover reset: %v", err)
	}
	if err := harness.db.QueryRow(context.Background(), `
		SELECT to_jsonb(relationship)::text
		FROM asset_relationships AS relationship WHERE id=$1
	`, fixture.relationshipID).Scan(&relationshipAfter); err != nil {
		t.Fatalf("read relationship after rejected rollover reset: %v", err)
	}
	if observationCount != observationsBefore || relationshipAfter != relationshipBefore {
		t.Fatal("rejected same-revision checkpoint rollover reset changed persisted freshness state")
	}
}

func commitFreshnessDomainObservationRelationshipPage(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	run runtimeContractRun,
	observation runtimeObservation,
	relationshipKind string,
	relationshipOrder int64,
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
		t.Fatalf("begin freshness-domain observation and relationship page: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	observationFact := strings.Repeat("2", 64)
	relationshipFact := strings.Repeat("8", 64)
	var changedCount, unchangedCount int64 = 0, 1
	if run.revision > 1 {
		observationFact = strings.Repeat("4", 64)
		relationshipFact = strings.Repeat("5", 64)
		changedCount, unchangedCount = 1, 0
	}
	observationArguments := runtimeObservationArguments(observation)
	observationArguments[13] = strings.Repeat("1", 64)
	observationArguments[14] = observationFact
	if _, err := tx.Exec(context.Background(), insertRuntimeObservationSQL,
		observationArguments...); err != nil {
		failFreshnessDomainDatabaseError(t, "insert freshness-domain observation", err)
	}
	execAssetSQL(t, tx, `
		UPDATE assets AS asset
		SET last_observation_id=observation.id,
			last_observation_chain_sha256=observation.observation_chain_sha256,
			last_observed_at=observation.observed_at,
			last_source_revision=observation.source_revision,
			version=asset.version+1
		FROM asset_observations AS observation
		WHERE asset.id=$1 AND observation.id=$2
	`, fixture.assetID, observation.id)

	pageDigest := strings.Repeat(pageDigestCharacter, 64)
	relationDigest := strings.Repeat(relationDigestCharacter, 64)
	if _, err := tx.Exec(context.Background(), `
		UPDATE asset_relationships
		SET source_revision=$2,canonical_revision_digest=$3,last_run_id=$4,
			last_page_sequence=1,relation_page_sha256=$5,
			accepted_checkpoint_version=$6,run_fence_epoch=$7,
			freshness_kind=$8,freshness_order_time=NULL,freshness_order_sequence=$9,
			provider_version_sha256=repeat('7',64),relation_fact_sha256=$10,
			version=version+1
		WHERE id=$1
	`, fixture.relationshipID, run.revision, run.revisionDigest, run.id,
		relationDigest, run.checkpointVersion+1, run.fenceEpoch, relationshipKind,
		relationshipOrder, relationshipFact); err != nil {
		failFreshnessDomainDatabaseError(t, "update freshness-domain relationship", err)
	}
	if err := insertClosurePageReceipt(tx, fixture, run.id, 1, pageDigest); err != nil {
		t.Fatalf("insert freshness-domain item page receipt: %v", err)
	}
	if err := insertClosureRelationPageReceipt(tx, fixture, run.id, 1, relationDigest); err != nil {
		t.Fatalf("insert freshness-domain relationship page receipt: %v", err)
	}
	execAssetSQL(t, tx, `
		WITH envelope AS (
			SELECT decode('01'||repeat(substr($2,1,2),12)||repeat(substr($2,3,2),16),'hex') AS ciphertext
		)
		UPDATE asset_sources AS source
		SET checkpoint_ciphertext=envelope.ciphertext,
			checkpoint_key_id='opaque-freshness-domain-key-'||substr($2,1,1),
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
			observed_count=observed_count+1,changed_count=changed_count+$5,
			unchanged_count=unchanged_count+$6,
			heartbeat_sequence=heartbeat_sequence+1,heartbeat_at=statement_timestamp(),
			lease_expires_at=lease_expires_at+interval '1 minute',
			work_result_kind='DATA_PROJECTION',work_result_status='SUCCEEDED',
			work_result_digest=repeat('e',64),version=version+1
		WHERE id=$1
	`, run.id, pageDigest, fixture.sourceID, relationDigest, changedCount, unchangedCount)
	if err := tx.Commit(context.Background()); err != nil {
		failFreshnessDomainDatabaseError(t, "commit freshness-domain observation and relationship page", err)
	}
}

func failFreshnessDomainDatabaseError(t *testing.T, operation string, err error) {
	t.Helper()
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		t.Fatalf("%s: SQLSTATE %s constraint %s: %s", operation, databaseError.Code,
			databaseError.ConstraintName, databaseError.Message)
	}
	t.Fatalf("%s: %v", operation, err)
}
