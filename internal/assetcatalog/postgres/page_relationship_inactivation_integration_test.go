package postgres_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
)

func TestPageCommitterCompleteMissingAdvancesCheckpointRelationshipFreshnessIntegration(t *testing.T) {
	requireRelationshipInactivationPostgres(t)
	baseline := newRelationshipFreshnessBaseline(t, assetcatalog.FreshnessCheckpointSequence)
	scenario := newRelationshipInactivationScenario(t, baseline, false)
	before := readRelationshipAtomicSnapshot(t, scenario)

	result, err := scenario.committer.ApplyPage(
		context.Background(), scenario.fence, scenario.coordinates, scenario.page,
	)
	if err != nil {
		assertCheckpointRelationshipInactivationRED(t, baseline, scenario, before, err)
	}
	assertRelationshipInactivationClosure(t, baseline, scenario, result, false)
}

func TestPageCommitterItemTombstoneAdvancesCheckpointRelationshipFreshnessIntegration(t *testing.T) {
	requireRelationshipInactivationPostgres(t)
	baseline := newRelationshipFreshnessBaseline(t, assetcatalog.FreshnessCheckpointSequence)
	scenario := newRelationshipInactivationScenario(t, baseline, true)
	before := readRelationshipAtomicSnapshot(t, scenario)

	result, err := scenario.committer.ApplyPage(
		context.Background(), scenario.fence, scenario.coordinates, scenario.page,
	)
	if err != nil {
		assertCheckpointRelationshipInactivationRED(t, baseline, scenario, before, err)
	}
	assertRelationshipInactivationClosure(t, baseline, scenario, result, true)
}

func TestPageCommitterRelationshipInactivationPreservesProviderFreshnessMatrixIntegration(t *testing.T) {
	requireRelationshipInactivationPostgres(t)
	for _, kind := range []assetcatalog.FreshnessKind{
		assetcatalog.FreshnessObjectSequence,
		assetcatalog.FreshnessObjectTimeSequence,
	} {
		t.Run(string(kind), func(t *testing.T) {
			baseline := newRelationshipFreshnessBaseline(t, kind)
			scenario := newRelationshipInactivationScenario(t, baseline, false)

			result, err := scenario.committer.ApplyPage(
				context.Background(), scenario.fence, scenario.coordinates, scenario.page,
			)
			if err != nil {
				t.Fatalf("%s complete-missing ApplyPage() error = %v", kind, err)
			}
			assertRelationshipInactivationClosure(t, baseline, scenario, result, false)
		})
	}
}

func TestPageCommitterNonManualCatalogRelationshipFreshnessRemainsRejectedIntegration(t *testing.T) {
	requireRelationshipInactivationPostgres(t)
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	run := startC1ExternalDiscoveryRun(
		t, harness.db, fixture,
		"83d10000-0000-4000-8000-000000000301",
		"relationship-catalog-rejection", "9",
	)

	var before string
	if err := harness.db.QueryRow(context.Background(), `
SELECT to_jsonb(relationship)::text
FROM asset_relationships AS relationship
WHERE relationship.id=$1::uuid
`, fixture.relationshipID).Scan(&before); err != nil {
		t.Fatal("read non-MANUAL catalog rejection baseline")
	}
	_, err := harness.db.Exec(context.Background(), `
UPDATE asset_relationships
SET source_revision=$2,canonical_revision_digest=$3,last_run_id=$4::uuid,
    last_page_sequence=1,accepted_checkpoint_version=$5,run_fence_epoch=$6,
    relation_page_sha256=repeat('b',64),
    freshness_kind='CATALOG_SEQUENCE',freshness_order_time=NULL,
    freshness_order_sequence=$5,version=version+1
WHERE id=$1::uuid
`, fixture.relationshipID, run.revision, run.revisionDigest, run.id,
		run.checkpointVersion+1, run.fenceEpoch)
	if pageCommitSQLState(err) != "55000" ||
		pageCommitConstraint(err) != "asset_relationships_run_admission_guard" {
		t.Fatalf("non-MANUAL CATALOG_SEQUENCE error = SQLSTATE %q constraint %q, want run admission guard",
			pageCommitSQLState(err), pageCommitConstraint(err))
	}

	var after string
	if err := harness.db.QueryRow(context.Background(), `
SELECT to_jsonb(relationship)::text
FROM asset_relationships AS relationship
WHERE relationship.id=$1::uuid
`, fixture.relationshipID).Scan(&after); err != nil {
		t.Fatal("read relationship after rejected non-MANUAL catalog freshness")
	}
	if after != before {
		t.Fatal("rejected non-MANUAL CATALOG_SEQUENCE changed the relationship")
	}
}

func TestPageCommitterRelationshipInactivationFaultsRollbackWholePageIntegration(t *testing.T) {
	requireRelationshipInactivationPostgres(t)
	tests := []struct {
		name      string
		table     string
		condition string
	}{
		{
			name:      "inactive audit",
			table:     "audit_records",
			condition: "WHEN (NEW.action='asset.source.relationship.inactive.v1')",
		},
		{
			name:      "inactive outbox",
			table:     "outbox_events",
			condition: "WHEN (NEW.event_type='asset.source.relationship.inactive.v1')",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			baseline := newRelationshipFreshnessBaseline(t, assetcatalog.FreshnessCheckpointSequence)
			scenario := newRelationshipInactivationScenario(t, baseline, false)
			before := readRelationshipAtomicSnapshot(t, scenario)
			installRelationshipInactivationFault(
				t, scenario.harness, test.table, test.condition,
			)

			result, err := scenario.committer.ApplyPage(
				context.Background(), scenario.fence, scenario.coordinates, scenario.page,
			)
			if result != (discoverysource.PageCommitResult{}) ||
				!errors.Is(err, discoverysource.ErrPageCommitUnavailable) ||
				err.Error() != discoverysource.ErrPageCommitUnavailable.Error() {
				t.Fatalf("faulted relationship closure = (%#v,%v), want stable unavailable", result, err)
			}
			for _, forbidden := range []string{
				"m1e-database-canary-secret",
				string(scenario.checkpointBytes),
				string(scenario.document),
				scenario.fenceDigest,
			} {
				if forbidden != "" && strings.Contains(err.Error(), forbidden) {
					t.Fatal("faulted relationship closure leaked protected material")
				}
			}
			assertRelationshipInactivationFaultReached(t, scenario.harness)
			after := readRelationshipAtomicSnapshot(t, scenario)
			if after != before {
				t.Fatalf("faulted relationship closure was not atomic:\nbefore=%#v\nafter=%#v", before, after)
			}
			assertNoRelationshipClosureEvidence(t, scenario)
		})
	}
}

func assertCheckpointRelationshipInactivationRED(
	t *testing.T,
	baseline relationshipFreshnessBaseline,
	scenario pageCommitScenario,
	before relationshipAtomicSnapshot,
	applyErr error,
) {
	t.Helper()
	if !errors.Is(applyErr, discoverysource.ErrPageCommitUnavailable) ||
		applyErr.Error() != discoverysource.ErrPageCommitUnavailable.Error() {
		t.Fatalf("checkpoint relationship closure error = %v, want stable unavailable", applyErr)
	}
	after := readRelationshipAtomicSnapshot(t, scenario)
	if after != before {
		t.Fatalf("checkpoint relationship rejection did not roll back the page:\nbefore=%#v\nafter=%#v",
			before, after)
	}
	assertNoRelationshipClosureEvidence(t, scenario)

	_, triggerErr := scenario.harness.db.Exec(context.Background(), `
UPDATE asset_relationships
SET source_revision=$2,canonical_revision_digest=$3,last_run_id=$4::uuid,
    last_page_sequence=1,accepted_checkpoint_version=2,run_fence_epoch=1,
    relation_page_sha256=repeat('b',64),status='INACTIVE',version=version+1
WHERE id=$1::uuid
`, baseline.relationship.ID, baseline.relationship.SourceRevision,
		baseline.fixture.revisionDigest, scenario.runID)
	if pageCommitSQLState(triggerErr) != "55000" ||
		pageCommitConstraint(triggerErr) != "asset_relationships_run_admission_guard" {
		t.Fatalf("checkpoint relationship RED diagnostic = SQLSTATE %q constraint %q",
			pageCommitSQLState(triggerErr), pageCommitConstraint(triggerErr))
	}
	t.Fatalf("checkpoint relationship closure reached asset_relationships_run_admission_guard and rolled back: %v",
		applyErr)
}

func installRelationshipInactivationFault(
	t *testing.T,
	harness *assetCatalogHarness,
	table, condition string,
) {
	t.Helper()
	execAssetSQL(t, harness.db, `CREATE SEQUENCE relationship_inactivation_fault_counter`)
	execAssetSQL(t, harness.db, `
GRANT USAGE,SELECT,UPDATE ON SEQUENCE relationship_inactivation_fault_counter
TO aiops_control_plane_workload
`)
	execAssetSQL(t, harness.db, `
CREATE FUNCTION relationship_inactivation_fault_probe() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 PERFORM nextval('relationship_inactivation_fault_counter');
 RETURN NEW;
END
$$
`)
	query := "CREATE TRIGGER aaa0_relationship_inactivation_fault_probe BEFORE INSERT ON " +
		pgx.Identifier{table}.Sanitize() + " FOR EACH ROW " + condition +
		" EXECUTE FUNCTION relationship_inactivation_fault_probe()"
	execAssetSQL(t, harness.db, query)
	installPageCommitFault(t, harness, table, "BEFORE", "INSERT", condition)
}

func assertRelationshipInactivationFaultReached(
	t *testing.T,
	harness *assetCatalogHarness,
) {
	t.Helper()
	var value int64
	var called bool
	if err := harness.db.QueryRow(context.Background(), `
SELECT last_value,is_called FROM relationship_inactivation_fault_counter
`).Scan(&value, &called); err != nil {
		t.Fatal("read relationship inactivation fault counter")
	}
	if !called || value != 1 {
		t.Fatalf("relationship inactivation fault counter = %d/%t, want 1/true", value, called)
	}
}

func requireRelationshipInactivationPostgres(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"AIOPS_TEST_POSTGRES_DSN",
		"AIOPS_TEST_POSTGRES_MIGRATION_DSN",
		"AIOPS_TEST_POSTGRES_APPLICATION_DSN",
	} {
		if strings.TrimSpace(os.Getenv(name)) == "" {
			t.Fatalf("%s is required for relationship inactivation integration tests", name)
		}
	}
}

type relationshipFreshnessBaseline struct {
	harness      *assetCatalogHarness
	fixture      assetCatalogFixture
	policy       assetdiscovery.FactPolicy
	newID        func() string
	relationship relationshipFreshnessSnapshot
}

type relationshipFreshnessSnapshot struct {
	ID, Status, LastRunID, RelationPageDigest string
	SourceRevision, LastPageSequence          int64
	AcceptedCheckpoint, FenceEpoch, Version   int64
	Kind                                      assetcatalog.FreshnessKind
	OrderTime                                 *time.Time
	OrderSequence                             int64
	ProviderVersion, RelationFact             string
}

func newRelationshipFreshnessBaseline(
	t *testing.T,
	kind assetcatalog.FreshnessKind,
) relationshipFreshnessBaseline {
	t.Helper()
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedRelationshipFreshnessSource(t, harness, kind)
	policy := pageCommitFactPolicy(fixture)
	policy.FreshnessKind = kind
	newID := deterministicAssetIDGenerator()
	first := newPageCommitScenarioForFixtureWithKey(
		t, harness, fixture,
		"83d10000-0000-4000-8000-000000000101",
		"relationship-freshness-first-worker",
		"relationship-freshness-first-run",
		policy, newID,
	)
	first.page.Items = []assetdiscovery.NormalizedItem{
		relationshipFreshnessItem(
			fixture, "relationship-node-a", "relationship node a",
			relationshipFreshnessCandidate(kind, 1, "1"),
		),
		relationshipFreshnessItem(
			fixture, "relationship-node-b", "relationship node b",
			relationshipFreshnessCandidate(kind, 1, "2"),
		),
	}
	first.page.Relations = []assetdiscovery.ObservedRelation{{
		SourceEnvironmentID: fixture.environmentID,
		TargetEnvironmentID: fixture.environmentID,
		FromExternalID:      "relationship-node-a",
		ToExternalID:        "relationship-node-b",
		Type:                assetcatalog.RelationshipDependsOn,
		ProviderPathCode:    "KIND",
		Confidence:          100,
		Freshness:           relationshipFreshnessCandidate(kind, 1, "3"),
	}}
	first.page.FinalPage = true
	first.page.CompleteSnapshot = true
	execAssetSQL(t, harness.db, `
UPDATE asset_source_runs
SET cleanup_status='PENDING',cleanup_attempt_id=gen_random_uuid(),
    cleanup_attempt_epoch=fence_epoch,version=version+1
WHERE id=$1::uuid
`, first.runID)
	result, err := first.committer.ApplyPage(
		context.Background(), first.fence, first.coordinates, first.page,
	)
	if err != nil || result.Replayed || result.CheckpointVersion != 1 ||
		!result.FinalPage || !result.CompleteSnapshot {
		t.Fatalf("first relationship page = (%#v,%v)", result, err)
	}
	closeC1ExternalSuccess(t, harness.db, fixture, first.runID)
	execAssetSQL(t, harness.db, `
UPDATE assets
SET lifecycle='ACTIVE',version=version+1
WHERE source_id=$1::uuid
`, fixture.sourceID)

	baseline := relationshipFreshnessBaseline{
		harness: harness, fixture: fixture, policy: policy, newID: newID,
	}
	baseline.relationship = readRelationshipFreshnessSnapshot(t, harness, fixture.sourceID)
	if baseline.relationship.Status != "ACTIVE" ||
		baseline.relationship.AcceptedCheckpoint != 1 ||
		baseline.relationship.LastPageSequence != 1 ||
		baseline.relationship.Version != 1 ||
		baseline.relationship.Kind != kind {
		t.Fatalf("first relationship closure = %#v", baseline.relationship)
	}
	if kind == assetcatalog.FreshnessCheckpointSequence &&
		baseline.relationship.OrderSequence != 1 {
		t.Fatalf("first checkpoint relationship sequence = %d, want 1",
			baseline.relationship.OrderSequence)
	}
	return baseline
}

func newRelationshipInactivationScenario(
	t *testing.T,
	baseline relationshipFreshnessBaseline,
	tombstone bool,
) pageCommitScenario {
	t.Helper()
	runID := "83d10000-0000-4000-8000-000000000201"
	owner := "relationship-complete-missing-worker"
	key := "relationship-complete-missing-run"
	if tombstone {
		runID = "83d10000-0000-4000-8000-000000000202"
		owner = "relationship-item-tombstone-worker"
		key = "relationship-item-tombstone-run"
	}
	scenario := newPageCommitScenarioForFixtureWithKey(
		t, baseline.harness, baseline.fixture, runID, owner, key,
		baseline.policy, baseline.newID,
	)
	freshness := relationshipFreshnessCandidate(baseline.relationship.Kind, 2, "4")
	if tombstone {
		scenario.page.Items = []assetdiscovery.NormalizedItem{{
			EnvironmentID:   baseline.fixture.environmentID,
			ProviderKind:    "EXTERNAL_V1",
			ExternalID:      "relationship-node-a",
			Freshness:       freshness,
			Tombstone:       true,
			TombstoneReason: "PROVIDER_DELETED",
			FieldProvenance: pageCommitTombstoneProvenance(),
		}}
	} else {
		scenario.page.Items = []assetdiscovery.NormalizedItem{
			relationshipFreshnessItem(
				baseline.fixture, "relationship-node-a", "relationship node a", freshness,
			),
		}
		scenario.page.CompleteSnapshot = true
	}
	scenario.page.FinalPage = true
	return scenario
}

func assertRelationshipInactivationClosure(
	t *testing.T,
	baseline relationshipFreshnessBaseline,
	scenario pageCommitScenario,
	result discoverysource.PageCommitResult,
	tombstone bool,
) {
	t.Helper()
	if result.RunID != scenario.runID || result.PageSequence != 1 ||
		result.CheckpointVersion != 2 || result.CheckpointSHA256 == "" ||
		result.PageDigestSHA256 == "" || result.RelationPageDigestSHA256 == "" ||
		!result.FinalPage || result.CompleteSnapshot == tombstone || result.Replayed {
		t.Fatalf("relationship inactivation result = %#v", result)
	}
	after := readRelationshipFreshnessSnapshot(t, baseline.harness, baseline.fixture.sourceID)
	if after.ID != baseline.relationship.ID || after.Status != "INACTIVE" ||
		after.LastRunID != scenario.runID || after.SourceRevision != 1 ||
		after.LastPageSequence != 1 || after.AcceptedCheckpoint != 2 ||
		after.FenceEpoch != 1 || after.RelationPageDigest != result.RelationPageDigestSHA256 ||
		after.Version != baseline.relationship.Version+1 || after.Kind != baseline.relationship.Kind ||
		after.ProviderVersion != baseline.relationship.ProviderVersion ||
		after.RelationFact != baseline.relationship.RelationFact {
		t.Fatalf("relationship inactivation coordinates/facts = %#v; baseline = %#v",
			after, baseline.relationship)
	}
	switch after.Kind {
	case assetcatalog.FreshnessCheckpointSequence:
		if after.OrderSequence != 2 || after.OrderTime != nil {
			t.Fatalf("checkpoint relationship freshness = %v/%d, want nil/2",
				after.OrderTime, after.OrderSequence)
		}
	case assetcatalog.FreshnessObjectSequence:
		if after.OrderSequence != baseline.relationship.OrderSequence || after.OrderTime != nil {
			t.Fatalf("object relationship freshness changed from %v/%d to %v/%d",
				baseline.relationship.OrderTime, baseline.relationship.OrderSequence,
				after.OrderTime, after.OrderSequence)
		}
	case assetcatalog.FreshnessObjectTimeSequence:
		if after.OrderTime == nil || baseline.relationship.OrderTime == nil ||
			!after.OrderTime.Equal(*baseline.relationship.OrderTime) ||
			after.OrderSequence != baseline.relationship.OrderSequence {
			t.Fatalf("time relationship freshness changed from %v/%d to %v/%d",
				baseline.relationship.OrderTime, baseline.relationship.OrderSequence,
				after.OrderTime, after.OrderSequence)
		}
	default:
		t.Fatalf("unexpected relationship freshness kind %q", after.Kind)
	}

	var (
		sourceCheckpoint, runCheckpoint, pageSequence, relationSequence int64
		missing, stale, tombstoned, observations, staleAssets           int64
		pageReceipts, relationReceipts, inactiveAudits, inactiveOutbox  int64
		sourceCheckpointSHA, runCheckpointSHA, runStatus, runStage      string
	)
	if err := baseline.harness.db.QueryRow(context.Background(), `
SELECT source.checkpoint_version,source.checkpoint_sha256,
       run.checkpoint_version,run.cursor_after_sha256,
       run.page_sequence,run.relation_page_sequence,run.status,run.stage_code,
       run.missing_count,run.stale_count,run.tombstoned_count,
       (SELECT count(*) FROM asset_observations WHERE run_id=run.id),
       (SELECT count(*) FROM assets WHERE source_id=source.id AND lifecycle='STALE'),
       (SELECT count(*) FROM audit_records
         WHERE request_id='source-page:'||run.id::text||':1' AND action='PAGE_APPLIED'),
       (SELECT count(*) FROM audit_records
         WHERE request_id='source-relation-page:'||run.id::text||':1'
           AND action='RELATION_PAGE_COMMITTED'),
       (SELECT count(*) FROM audit_records
         WHERE resource_id=$3 AND actor_id=$4
           AND action='asset.source.relationship.inactive.v1'),
       (SELECT count(*) FROM outbox_events
         WHERE aggregate_id=$3::uuid
           AND event_type='asset.source.relationship.inactive.v1')
FROM asset_sources AS source
JOIN asset_source_runs AS run ON run.source_id=source.id
WHERE source.id=$1::uuid AND run.id=$2::uuid
`, baseline.fixture.sourceID, scenario.runID, after.ID, scenario.owner).Scan(
		&sourceCheckpoint, &sourceCheckpointSHA, &runCheckpoint, &runCheckpointSHA,
		&pageSequence, &relationSequence, &runStatus, &runStage,
		&missing, &stale, &tombstoned, &observations, &staleAssets,
		&pageReceipts, &relationReceipts, &inactiveAudits, &inactiveOutbox,
	); err != nil {
		t.Fatal("read relationship inactivation transaction closure")
	}
	wantMissing, wantTombstoned := int64(1), int64(0)
	if tombstone {
		wantMissing, wantTombstoned = 0, 1
	}
	if sourceCheckpoint != 2 || runCheckpoint != 2 ||
		sourceCheckpointSHA != result.CheckpointSHA256 ||
		runCheckpointSHA != result.CheckpointSHA256 ||
		pageSequence != 1 || relationSequence != 1 ||
		runStatus != "FINALIZING" || runStage != "CLEANING_UP" ||
		missing != wantMissing || stale != 1 || tombstoned != wantTombstoned ||
		observations != 1 || staleAssets != 1 ||
		pageReceipts != 1 || relationReceipts != 1 ||
		inactiveAudits != 1 || inactiveOutbox != 1 {
		t.Fatalf("relationship page closure checkpoint=%d/%d sequence=%d/%d run=%s/%s counts=%d/%d/%d observations/assets=%d/%d receipts=%d/%d evidence=%d/%d",
			sourceCheckpoint, runCheckpoint, pageSequence, relationSequence,
			runStatus, runStage, missing, stale, tombstoned, observations, staleAssets,
			pageReceipts, relationReceipts, inactiveAudits, inactiveOutbox)
	}
}

type relationshipAtomicSnapshot struct {
	Relationship, Assets, Source, Run string
	Observations                      int64
}

func readRelationshipAtomicSnapshot(
	t *testing.T,
	scenario pageCommitScenario,
) relationshipAtomicSnapshot {
	t.Helper()
	var snapshot relationshipAtomicSnapshot
	if err := scenario.harness.db.QueryRow(context.Background(), `
SELECT relationship_row.value,asset_rows.value,
       to_jsonb(source)::text,to_jsonb(run)::text,
       (SELECT count(*) FROM asset_observations WHERE source_id=source.id)
FROM asset_sources AS source
JOIN asset_source_runs AS run ON run.source_id=source.id
CROSS JOIN LATERAL (
  SELECT to_jsonb(relationship)::text AS value
  FROM asset_relationships AS relationship
  WHERE relationship.source_id=source.id
) AS relationship_row
CROSS JOIN LATERAL (
  SELECT string_agg(to_jsonb(asset)::text,'' ORDER BY asset.id) AS value
  FROM assets AS asset
  WHERE asset.source_id=source.id
) AS asset_rows
WHERE source.id=$1::uuid AND run.id=$2::uuid
`, scenario.fixture.sourceID, scenario.runID).Scan(
		&snapshot.Relationship, &snapshot.Assets, &snapshot.Source, &snapshot.Run,
		&snapshot.Observations,
	); err != nil {
		t.Fatal("read relationship atomic snapshot")
	}
	return snapshot
}

func assertNoRelationshipClosureEvidence(t *testing.T, scenario pageCommitScenario) {
	t.Helper()
	var pageReceipts, relationReceipts, inactiveAudits, inactiveOutbox int64
	if err := scenario.harness.db.QueryRow(context.Background(), `
SELECT
  (SELECT count(*) FROM audit_records
    WHERE request_id='source-page:'||$1::text||':1' AND action='PAGE_APPLIED'),
  (SELECT count(*) FROM audit_records
    WHERE request_id='source-relation-page:'||$1::text||':1'
      AND action='RELATION_PAGE_COMMITTED'),
  (SELECT count(*) FROM audit_records
    WHERE actor_id=$2 AND action='asset.source.relationship.inactive.v1'),
  (SELECT count(*) FROM outbox_events
    WHERE event_type='asset.source.relationship.inactive.v1'
      AND aggregate_id=(SELECT id FROM asset_relationships WHERE source_id=$3::uuid))
`, scenario.runID, scenario.owner, scenario.fixture.sourceID).Scan(
		&pageReceipts, &relationReceipts, &inactiveAudits, &inactiveOutbox,
	); err != nil {
		t.Fatal("read faulted relationship evidence")
	}
	if pageReceipts != 0 || relationReceipts != 0 || inactiveAudits != 0 || inactiveOutbox != 0 {
		t.Fatalf("faulted relationship evidence persisted: receipts=%d/%d inactive=%d/%d",
			pageReceipts, relationReceipts, inactiveAudits, inactiveOutbox)
	}
}

func readRelationshipFreshnessSnapshot(
	t *testing.T,
	harness *assetCatalogHarness,
	sourceID string,
) relationshipFreshnessSnapshot {
	t.Helper()
	var snapshot relationshipFreshnessSnapshot
	if err := harness.db.QueryRow(context.Background(), `
SELECT id::text,status,last_run_id::text,relation_page_sha256,
       source_revision,last_page_sequence,accepted_checkpoint_version,
       run_fence_epoch,version,freshness_kind,freshness_order_time,
       freshness_order_sequence,provider_version_sha256,relation_fact_sha256
FROM asset_relationships
WHERE source_id=$1::uuid
`, sourceID).Scan(
		&snapshot.ID, &snapshot.Status, &snapshot.LastRunID, &snapshot.RelationPageDigest,
		&snapshot.SourceRevision, &snapshot.LastPageSequence,
		&snapshot.AcceptedCheckpoint, &snapshot.FenceEpoch, &snapshot.Version,
		&snapshot.Kind, &snapshot.OrderTime, &snapshot.OrderSequence,
		&snapshot.ProviderVersion, &snapshot.RelationFact,
	); err != nil {
		t.Fatal("read relationship freshness snapshot")
	}
	if snapshot.OrderTime != nil {
		value := snapshot.OrderTime.UTC()
		snapshot.OrderTime = &value
	}
	return snapshot
}

func relationshipFreshnessCandidate(
	kind assetcatalog.FreshnessKind,
	checkpoint int64,
	providerVersionCharacter string,
) assetdiscovery.FreshnessCandidate {
	sequence := int64(40) + checkpoint
	var orderTime *time.Time
	switch kind {
	case assetcatalog.FreshnessCatalogSequence, assetcatalog.FreshnessCheckpointSequence:
		sequence = checkpoint
	case assetcatalog.FreshnessObjectTimeSequence:
		value := time.Date(2026, 7, 18, 4, int(checkpoint), 0, 0, time.UTC)
		orderTime = &value
	}
	return assetdiscovery.FreshnessCandidate{
		Kind: kind, OrderTime: orderTime, OrderSequence: sequence,
		ProviderVersionSHA256: strings.Repeat(providerVersionCharacter, 64),
	}
}

func relationshipFreshnessItem(
	fixture assetCatalogFixture,
	externalID, displayName string,
	freshness assetdiscovery.FreshnessCandidate,
) assetdiscovery.NormalizedItem {
	document := []byte(`{"display_name":"` + displayName + `"}`)
	digest := sha256.Sum256(document)
	return assetdiscovery.NormalizedItem{
		EnvironmentID: fixture.environmentID, ProviderKind: "EXTERNAL_V1",
		ExternalID: externalID, Kind: assetcatalog.KindCloudResource,
		DisplayName: displayName, SchemaVersion: "asset.v1",
		Document: document, DocumentSHA256: hex.EncodeToString(digest[:]),
		Freshness: freshness, FieldProvenance: pageCommitFieldProvenance(),
	}
}

func seedRelationshipFreshnessSource(
	t *testing.T,
	harness *assetCatalogHarness,
	kind assetcatalog.FreshnessKind,
) assetCatalogFixture {
	t.Helper()
	fixture := seedDraftAssetCatalog(t, harness.db)
	fixture.sourceID = "83d10000-0000-4000-8000-000000000001"
	fixture.revisionID = "83d10000-0000-4000-8000-000000000002"
	fixture.validationRunID = "83d10000-0000-4000-8000-000000000003"

	profileText := strings.Replace(
		closureExternalProfileManifestV1,
		`"freshness_kind":"OBJECT_SEQUENCE"`,
		`"freshness_kind":"`+string(kind)+`"`,
		1,
	)
	if !strings.Contains(profileText, `"freshness_kind":"`+string(kind)+`"`) {
		t.Fatalf("relationship freshness profile did not select %s", kind)
	}
	profile := []byte(profileText)
	providerSchema := []byte(`{"type":"object"}`)
	profileDigest := sha256.Sum256(profile)
	providerSchemaDigest := sha256.Sum256(providerSchema)
	authorityDigest := assetCatalogCorrectiveFramedDigest(
		[]byte("asset-source-authority-scope.v1"), []byte("1"),
		[]byte(fixture.environmentID),
	)
	fixture.sourceDefinitionDigest = assetCatalogCorrectiveFramedDigest(
		[]byte("asset-source-definition.v2"), []byte("EXTERNAL_CMDB"),
		[]byte("EXTERNAL_V1"), []byte("EXTERNAL_V1"),
		profileDigest[:], providerSchemaDigest[:],
	)
	fixture.revisionDigest = assetCatalogCorrectiveFramedDigest(
		[]byte("asset-source-revision-binding.v1"), []byte(fixture.tenantID),
		[]byte(fixture.workspaceID), []byte(fixture.sourceID), []byte("1"),
		assetCatalogCorrectiveDecodeDigest(t, fixture.sourceDefinitionDigest),
		[]byte(fixture.integrationID), []byte("ON_DEMAND"),
		[]byte("opaque-credential"), nil, nil,
		assetCatalogCorrectiveDecodeDigest(t, authorityDigest),
		[]byte("100"), []byte("60"), []byte("1"), []byte("60"),
		[]byte("EXTERNAL_V1"), nil, nil, nil,
	)

	tx, err := harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatal("begin relationship freshness source definition")
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	execAssetSQL(t, tx, `
INSERT INTO asset_sources (
 id,tenant_id,workspace_id,source_kind,provider_kind,name,
 create_idempotency_key,create_request_hash
) VALUES ($1,$2,$3,'EXTERNAL_CMDB','EXTERNAL_V1',
          'relationship freshness source','relationship-freshness-source',repeat('1',64))
`, fixture.sourceID, fixture.tenantID, fixture.workspaceID)
	execAssetSQL(t, tx, `
INSERT INTO asset_source_revisions (
 id,tenant_id,workspace_id,source_id,revision,
 canonical_profile_manifest,profile_manifest_sha256,
 canonical_provider_schema,canonical_provider_schema_sha256,integration_id,sync_mode,
 authority_scope_digest,source_definition_digest,canonical_revision_digest,
 credential_reference_id,rate_limit_requests,rate_limit_window_seconds,
 backpressure_base_seconds,backpressure_max_seconds,profile_code,
 created_by,change_reason_code,expected_source_version
) SELECT $1,$2,$3,$4,1,$5,$6,$7,$8,$9,'ON_DEMAND',$10,$11,$12,
         'opaque-credential',100,60,1,60,'EXTERNAL_V1',
         'relationship-freshness-test','INITIAL_CREATE',source.version
  FROM asset_sources AS source WHERE source.id=$4
`, fixture.revisionID, fixture.tenantID, fixture.workspaceID, fixture.sourceID,
		profile, hex.EncodeToString(profileDigest[:]), providerSchema,
		hex.EncodeToString(providerSchemaDigest[:]), fixture.integrationID,
		authorityDigest, fixture.sourceDefinitionDigest, fixture.revisionDigest)
	execAssetSQL(t, tx, `
INSERT INTO asset_source_revision_authorities (
 tenant_id,workspace_id,source_id,source_revision,environment_id,canonical_ordinal
) VALUES ($1,$2,$3,1,$4,1)
`, fixture.tenantID, fixture.workspaceID, fixture.sourceID, fixture.environmentID)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatal("commit relationship freshness source definition")
	}

	execAssetSQL(t, harness.db, `
INSERT INTO asset_source_runs (
 id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
 run_kind,trigger_type,gate_revision,idempotency_key,request_hash,checkpoint_version
) SELECT $1,$2,$3,$4,1,$5,'VALIDATION','HUMAN',gate_revision,
         'relationship-freshness-validation',repeat('5',64),0
  FROM asset_sources WHERE id=$4
`, fixture.validationRunID, fixture.tenantID, fixture.workspaceID,
		fixture.sourceID, fixture.revisionDigest)
	execAssetSQL(t, harness.db, `
UPDATE asset_source_revisions
SET state='VALIDATING',validation_run_id=$2,version=version+1
WHERE id=$1
`, fixture.revisionID, fixture.validationRunID)
	execAssetSQL(t, harness.db, `
UPDATE asset_sources
SET gate_status='VALIDATING',gate_revision=gate_revision+1,
    validated_run_id=$2,validation_digest=NULL,validated_binding_digest=NULL,
    version=version+1
WHERE id=$1
`, fixture.sourceID, fixture.validationRunID)
	execAssetSQL(t, harness.db, `
UPDATE asset_source_runs
SET status='RUNNING',stage_code='VALIDATING',
    lease_owner='relationship-freshness-validation-worker',
    lease_expires_at=statement_timestamp()+interval '10 minutes',
    fence_epoch=1,fence_token_hash=repeat('6',64),heartbeat_sequence=1,
    heartbeat_at=statement_timestamp(),version=version+1
WHERE id=$1
`, fixture.validationRunID)
	finishClosureExternalValidation(t, harness.db, fixture, 1, strings.Repeat("7", 64))
	return fixture
}
