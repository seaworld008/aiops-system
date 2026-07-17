package postgres_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	assetpostgres "github.com/seaworld008/aiops-system/internal/assetcatalog/postgres"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
	"github.com/seaworld008/aiops-system/internal/assetsource/externalcmdb"
	"github.com/seaworld008/aiops-system/internal/discoverycheckpoint"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
	"github.com/seaworld008/aiops-system/internal/leasefence"
	"github.com/seaworld008/aiops-system/internal/sourceprofile"
)

func TestPageCommitterCommitsFirstPageAtomicallyIntegration(t *testing.T) {
	scenario := newPageCommitScenario(t, nil)
	result, err := scenario.committer.ApplyPage(
		context.Background(), scenario.fence, scenario.coordinates, scenario.page,
	)
	if err != nil {
		t.Fatalf("ApplyPage() error = %v", err)
	}
	if result.RunID != scenario.runID || result.PageSequence != 1 || result.CheckpointVersion != 1 ||
		result.CheckpointSHA256 == "" || result.PageDigestSHA256 == "" ||
		result.RelationPageDigestSHA256 == "" || result.FinalPage ||
		result.CompleteSnapshot || result.Replayed {
		t.Fatalf("ApplyPage() result = %#v", result)
	}
	if scenario.resolver.pageCalls != 1 || scenario.resolver.crossEnvironmentCalls != 0 {
		t.Fatalf("resolver calls = page:%d cross-environment:%d",
			scenario.resolver.pageCalls, scenario.resolver.crossEnvironmentCalls)
	}

	var (
		observations, assets, typeDetails, pageReceipts, relationReceipts, outbox               int
		sourceCheckpointVersion, runCheckpointVersion, runPageSequence, runRelationPageSequence int64
		sourceCheckpointSHA, runCheckpointSHA, runPageDigest, runRelationDigest                 string
		checkpointCiphertext                                                                    []byte
		serializedReceipts, serializedOutbox                                                    string
	)
	if err := scenario.harness.db.QueryRow(context.Background(), `
		SELECT
		  (SELECT count(*) FROM asset_observations WHERE run_id=$1::uuid),
		  (SELECT count(*) FROM assets WHERE source_id=$2::uuid AND external_id='provider-node-a'),
		  (SELECT count(*) FROM asset_type_details WHERE asset_id=(
		    SELECT id FROM assets WHERE source_id=$2::uuid AND external_id='provider-node-a'
		  )),
		  (SELECT count(*) FROM audit_records WHERE workspace_id=$3::uuid
		    AND request_id='source-page:'||$1||':1' AND action='PAGE_APPLIED'),
		  (SELECT count(*) FROM audit_records WHERE workspace_id=$3::uuid
		    AND request_id='source-relation-page:'||$1||':1' AND action='RELATION_PAGE_COMMITTED'),
		  (SELECT count(*) FROM outbox_events WHERE aggregate_id=(
		    SELECT id FROM assets WHERE source_id=$2::uuid AND external_id='provider-node-a'
		  )),
		  source.checkpoint_version,run.checkpoint_version,run.page_sequence,run.relation_page_sequence,
		  source.checkpoint_sha256,run.cursor_after_sha256,run.page_digest,run.relation_page_digest,
		  source.checkpoint_ciphertext,
		  COALESCE((SELECT string_agg(row_to_json(audit)::text,'') FROM audit_records AS audit
		    WHERE audit.workspace_id=$3::uuid AND audit.resource_id=$1),''),
		  COALESCE((SELECT string_agg(event.payload::text,'') FROM outbox_events AS event
		    WHERE event.workspace_id=$3::uuid), '')
		FROM asset_sources AS source
		JOIN asset_source_runs AS run ON run.source_id=source.id
		WHERE source.id=$2::uuid AND run.id=$1::uuid
		`, scenario.runID, scenario.fixture.sourceID, scenario.fixture.workspaceID).Scan(
		&observations, &assets, &typeDetails, &pageReceipts, &relationReceipts, &outbox,
		&sourceCheckpointVersion, &runCheckpointVersion, &runPageSequence, &runRelationPageSequence,
		&sourceCheckpointSHA, &runCheckpointSHA, &runPageDigest, &runRelationDigest,
		&checkpointCiphertext, &serializedReceipts, &serializedOutbox,
	); err != nil {
		t.Fatalf("read atomic page closure: %v", err)
	}
	if observations != 1 || assets != 1 || typeDetails != 1 || pageReceipts != 1 ||
		relationReceipts != 1 || outbox != 1 {
		t.Fatalf("atomic projection counts = observations:%d assets:%d details:%d page-receipts:%d relation-receipts:%d outbox:%d",
			observations, assets, typeDetails, pageReceipts, relationReceipts, outbox)
	}
	if sourceCheckpointVersion != 1 || runCheckpointVersion != 1 || runPageSequence != 1 ||
		runRelationPageSequence != 1 || sourceCheckpointSHA != result.CheckpointSHA256 ||
		runCheckpointSHA != result.CheckpointSHA256 || runPageDigest != result.PageDigestSHA256 ||
		runRelationDigest != result.RelationPageDigestSHA256 || len(checkpointCiphertext) == 0 {
		t.Fatalf("atomic checkpoint/run closure did not match result: %#v", result)
	}
	for _, encoded := range []string{serializedReceipts, serializedOutbox} {
		for _, forbidden := range []string{
			string(scenario.checkpointBytes), string(scenario.document), "provider-node-a", scenario.fenceDigest,
		} {
			if strings.Contains(encoded, forbidden) {
				t.Fatalf("receipt/outbox leaked forbidden page material")
			}
		}
	}
}

func TestPageCommitterReplayRejectsChangedProviderDocumentBytesIntegration(t *testing.T) {
	scenario := newPageCommitScenario(t, nil)
	if _, err := scenario.committer.ApplyPage(
		context.Background(), scenario.fence, scenario.coordinates, scenario.page,
	); err != nil {
		t.Fatalf("initial ApplyPage() error = %v", err)
	}
	changed := scenario.page
	changed.Items = append([]assetdiscovery.NormalizedItem(nil), scenario.page.Items...)
	changed.Items[0].Document = []byte(`{"display_name":"node-b"}`)
	result, err := scenario.committer.ApplyPage(
		context.Background(), scenario.fence, scenario.coordinates, changed,
	)
	if !errors.Is(err, discoverysource.ErrPageCommitConflict) || result != (discoverysource.PageCommitResult{}) {
		t.Fatalf("changed-document replay = (%#v,%v), want ErrPageCommitConflict", result, err)
	}
}

func TestPageCommitterReceiptFirstReplayAndMismatchMatrixIntegration(t *testing.T) {
	scenario := newPageCommitScenario(t, nil)
	committed, err := scenario.committer.ApplyPage(
		context.Background(), scenario.fence, scenario.coordinates, scenario.page,
	)
	if err != nil {
		t.Fatalf("initial ApplyPage() error = %v", err)
	}
	execAssetSQL(t, scenario.harness.db, `
UPDATE asset_sources
SET gate_status='UNAVAILABLE',gate_reason_code=NULL,
    gate_revision=gate_revision+1,version=version+1
WHERE id=$1
`, scenario.fixture.sourceID)

	staleRawFence := [32]byte{9, 8, 7, 6}
	staleFence, err := leasefence.FromQueueClaim(scenario.runID, scenario.owner, 2, &staleRawFence)
	if err != nil {
		t.Fatalf("build stale fence: %v", err)
	}
	replayed, err := scenario.committer.ApplyPage(
		context.Background(), staleFence, scenario.coordinates, scenario.page,
	)
	assertExactPageReplay(t, replayed, err, committed)

	scenario.fence.Destroy()
	replayed, err = scenario.committer.ApplyPage(
		context.Background(), scenario.fence, scenario.coordinates, scenario.page,
	)
	assertExactPageReplay(t, replayed, err, committed)

	changedCheckpoint := scenario.page
	changedCheckpoint.NextCheckpoint, err = discoverysource.NewCheckpoint(
		"EXTERNAL_V1", []byte(`{"cursor":"changed-page-1"}`),
	)
	if err != nil {
		t.Fatalf("changed checkpoint fixture: %v", err)
	}
	assertPageCommitError(t, scenario.committer, scenario.fence, scenario.coordinates,
		changedCheckpoint, discoverysource.ErrPageCommitConflict)

	changedFact := scenario.page
	changedFact.Items = append([]assetdiscovery.NormalizedItem(nil), scenario.page.Items...)
	changedFact.Items[0].DisplayName = "node-b"
	assertPageCommitError(t, scenario.committer, scenario.fence, scenario.coordinates,
		changedFact, discoverysource.ErrPageCommitConflict)

	changedFinal := scenario.page
	changedFinal.FinalPage = true
	assertPageCommitError(t, scenario.committer, scenario.fence, scenario.coordinates,
		changedFinal, discoverysource.ErrPageCommitConflict)

	var replacementMaster [32]byte
	for index := range replacementMaster {
		replacementMaster[index] = byte(255 - index)
	}
	replacementKeyring := newPageCommitKeyring(t, "m1e-checkpoint-key-v2", map[string][32]byte{
		"m1e-checkpoint-key-v2": replacementMaster,
	})
	replacementCommitter, err := assetpostgres.NewPageCommitter(
		scenario.repository, replacementKeyring, scenario.resolver,
	)
	if err != nil {
		t.Fatalf("replacement NewPageCommitter() error = %v", err)
	}
	assertPageCommitError(t, replacementCommitter, scenario.fence, scenario.coordinates,
		scenario.page, discoverysource.ErrPageCommitUnavailable)

	wrongProfile := scenario.page
	wrongProfile.NextCheckpoint, err = discoverysource.NewCheckpoint("OTHER_V1", scenario.checkpointBytes)
	if err != nil {
		t.Fatalf("wrong-profile checkpoint fixture: %v", err)
	}
	replacementKeyring.Destroy()
	assertPageCommitError(t, replacementCommitter, scenario.fence, scenario.coordinates,
		wrongProfile, discoverysource.ErrPageCommitInvalid)

	var observations, pageReceipts, relationReceipts int
	if err := scenario.harness.db.QueryRow(context.Background(), `
SELECT (SELECT count(*) FROM asset_observations WHERE run_id=$1::uuid),
       (SELECT count(*) FROM audit_records WHERE request_id='source-page:'||$1||':1'),
       (SELECT count(*) FROM audit_records WHERE request_id='source-relation-page:'||$1||':1')
`, scenario.runID).Scan(&observations, &pageReceipts, &relationReceipts); err != nil {
		t.Fatal("read replay closure counts")
	}
	if observations != 1 || pageReceipts != 1 || relationReceipts != 1 ||
		scenario.resolver.pageCalls != 1 || scenario.resolver.crossEnvironmentCalls != 0 {
		t.Fatalf("replay mutated closure: observations=%d page-receipts=%d relation-receipts=%d resolver=%d/%d",
			observations, pageReceipts, relationReceipts,
			scenario.resolver.pageCalls, scenario.resolver.crossEnvironmentCalls)
	}
}

func TestPageCommitterFreshWrongProfilePrecedesDestroyedKeyringIntegration(t *testing.T) {
	scenario := newPageCommitScenario(t, nil)
	wrongProfile := scenario.page
	var err error
	wrongProfile.NextCheckpoint, err = discoverysource.NewCheckpoint("OTHER_V1", scenario.checkpointBytes)
	if err != nil {
		t.Fatalf("wrong-profile checkpoint fixture: %v", err)
	}
	scenario.keyring.Destroy()
	assertPageCommitError(t, scenario.committer, scenario.fence, scenario.coordinates,
		wrongProfile, discoverysource.ErrPageCommitInvalid)
	assertUncommittedPageState(t, scenario)
}

func TestPageCommitterReusesSingleSealedEnvelopeAcrossSerializableRetryIntegration(t *testing.T) {
	scenario := newPageCommitScenario(t, nil)
	execAssetSQL(t, scenario.harness.db, `CREATE SEQUENCE m1e_page_retry_counter`)
	execAssetSQL(t, scenario.harness.db,
		`GRANT USAGE,SELECT,UPDATE ON SEQUENCE m1e_page_retry_counter TO aiops_control_plane_workload`)
	execAssetSQL(t, scenario.harness.db, `
CREATE FUNCTION m1e_retry_first_checkpoint_update() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF nextval('m1e_page_retry_counter')=1 THEN
  RAISE EXCEPTION 'retry canary' USING ERRCODE='40001';
 END IF;
 RETURN NEW;
END
$$`)
	execAssetSQL(t, scenario.harness.db, `
CREATE TRIGGER aaa_m1e_retry_first_checkpoint_update
BEFORE UPDATE ON asset_sources FOR EACH ROW
WHEN (NEW.checkpoint_version > OLD.checkpoint_version)
EXECUTE FUNCTION m1e_retry_first_checkpoint_update()`)

	tracer := &pageCommitEnvelopeTracer{}
	config := scenario.harness.application.Config().Copy()
	config.ConnConfig.Tracer = tracer
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal("create traced runtime pool")
	}
	t.Cleanup(pool.Close)
	repository, err := assetpostgres.New(pool, time.Now, deterministicAssetIDGenerator())
	if err != nil {
		t.Fatal("create traced page repository")
	}
	committer, err := assetpostgres.NewPageCommitter(repository, scenario.keyring, scenario.resolver)
	if err != nil {
		t.Fatal("create traced page committer")
	}
	result, err := committer.ApplyPage(context.Background(), scenario.fence, scenario.coordinates, scenario.page)
	if err != nil || result.Replayed || result.CheckpointVersion != 1 {
		t.Fatalf("retried ApplyPage() = (%#v,%v)", result, err)
	}
	var attempts int64
	if err := scenario.harness.db.QueryRow(context.Background(),
		`SELECT last_value FROM m1e_page_retry_counter`).Scan(&attempts); err != nil || attempts != 2 {
		t.Fatalf("serializable attempt count = %d, want 2", attempts)
	}
	envelopes := tracer.snapshot()
	if len(envelopes) != 2 || !bytes.Equal(envelopes[0], envelopes[1]) || len(envelopes[0]) < 29 {
		t.Fatalf("checkpoint envelope binds = %d equal=%t, want one sealed envelope reused twice",
			len(envelopes), len(envelopes) == 2 && bytes.Equal(envelopes[0], envelopes[1]))
	}
}

func TestPageCommitterRollsBackEveryAtomicBoundaryIntegration(t *testing.T) {
	tests := []struct {
		name      string
		table     string
		timing    string
		event     string
		condition string
	}{
		{name: "projection", table: "asset_observations", timing: "BEFORE", event: "INSERT"},
		{name: "receipt", table: "audit_records", timing: "BEFORE", event: "INSERT",
			condition: "WHEN (NEW.action='PAGE_APPLIED')"},
		{name: "checkpoint", table: "asset_sources", timing: "BEFORE", event: "UPDATE",
			condition: "WHEN (NEW.checkpoint_version > OLD.checkpoint_version)"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scenario := newPageCommitScenario(t, nil)
			installPageCommitFault(t, scenario.harness, test.table, test.timing, test.event, test.condition)
			result, err := scenario.committer.ApplyPage(
				context.Background(), scenario.fence, scenario.coordinates, scenario.page,
			)
			if result != (discoverysource.PageCommitResult{}) ||
				!errors.Is(err, discoverysource.ErrPageCommitUnavailable) ||
				err.Error() != discoverysource.ErrPageCommitUnavailable.Error() {
				t.Fatalf("faulted ApplyPage() did not return the stable unavailable error")
			}
			for _, forbidden := range []string{
				"m1e-database-canary-secret", string(scenario.checkpointBytes),
				string(scenario.document), scenario.fenceDigest,
			} {
				if strings.Contains(err.Error(), forbidden) {
					t.Fatal("faulted ApplyPage() leaked protected material")
				}
			}
			assertUncommittedPageState(t, scenario)
		})
	}
}

func TestPageCommitterConcurrentAdmissionDriftNeverUsesPreliminarySnapshotIntegration(t *testing.T) {
	tests := []struct {
		name  string
		drift func(*testing.T, pageCommitScenario)
	}{
		{
			name: "gate",
			drift: func(t *testing.T, scenario pageCommitScenario) {
				execAssetSQL(t, scenario.harness.db, `
UPDATE asset_sources
SET gate_status='UNAVAILABLE',gate_reason_code=NULL,
    gate_revision=gate_revision+1,version=version+1
WHERE id=$1
`, scenario.fixture.sourceID)
			},
		},
		{
			name: "published revision pointer",
			drift: func(t *testing.T, scenario pageCommitScenario) {
				fixture := seedClosureExternalSuccessorDefinition(
					t, scenario.harness.db, scenario.fixture,
					"83f00000-0000-4000-8000-000000000021", 2, "EXTERNAL_V1",
					[]byte(`{"type":"object","version":2}`), "DEFINITION_CHANGE",
				)
				execAssetSQL(t, scenario.harness.db, `ALTER TABLE asset_sources DISABLE TRIGGER USER`)
				t.Cleanup(func() {
					_, _ = scenario.harness.db.Exec(context.Background(),
						`ALTER TABLE asset_sources ENABLE TRIGGER USER`)
				})
				execAssetSQL(t, scenario.harness.db, `
UPDATE asset_sources
SET published_revision=2,published_revision_digest=$2,version=version+1
WHERE id=$1
`, scenario.fixture.sourceID, fixture.revisionDigest)
				execAssetSQL(t, scenario.harness.db, `ALTER TABLE asset_sources ENABLE TRIGGER USER`)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			baseID := deterministicAssetIDGenerator()
			var once sync.Once
			scenario := newPageCommitScenario(t, func() string {
				once.Do(func() {
					close(entered)
					<-release
				})
				return baseID()
			})
			type outcome struct {
				result discoverysource.PageCommitResult
				err    error
			}
			outcomes := make(chan outcome, 1)
			go func() {
				result, err := scenario.committer.ApplyPage(
					context.Background(), scenario.fence, scenario.coordinates, scenario.page,
				)
				outcomes <- outcome{result: result, err: err}
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				close(release)
				t.Fatal("ApplyPage() did not reach the sealed preliminary boundary")
			}
			test.drift(t, scenario)
			close(release)
			select {
			case actual := <-outcomes:
				if actual.result != (discoverysource.PageCommitResult{}) ||
					!errors.Is(actual.err, discoverysource.ErrPageCommitConflict) ||
					actual.err.Error() != discoverysource.ErrPageCommitConflict.Error() {
					t.Fatalf("drifted ApplyPage() = (%#v,%v), want stable conflict", actual.result, actual.err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("drifted ApplyPage() did not return")
			}
			assertUncommittedPageState(t, scenario)
		})
	}
}

func TestPageCommitterScopeCheckpointAndFenceDriftFailClosedIntegration(t *testing.T) {
	t.Run("scope", func(t *testing.T) {
		scenario := newPageCommitScenario(t, nil)
		coordinates := scenario.coordinates
		coordinates.Locator.Scope.TenantID = "20000000-0000-4000-8000-000000000099"
		assertPageCommitError(t, scenario.committer, scenario.fence, coordinates,
			scenario.page, discoverysource.ErrPageCommitConflict)
		assertUncommittedPageState(t, scenario)
	})
	t.Run("checkpoint", func(t *testing.T) {
		scenario := newPageCommitScenario(t, nil)
		execAssetSQL(t, scenario.harness.db, `ALTER TABLE asset_source_runs DISABLE TRIGGER USER`)
		t.Cleanup(func() {
			_, _ = scenario.harness.db.Exec(context.Background(),
				`ALTER TABLE asset_source_runs ENABLE TRIGGER USER`)
		})
		execAssetSQL(t, scenario.harness.db,
			`UPDATE asset_source_runs SET checkpoint_version=1 WHERE id=$1`, scenario.runID)
		execAssetSQL(t, scenario.harness.db, `ALTER TABLE asset_source_runs ENABLE TRIGGER USER`)
		assertPageCommitError(t, scenario.committer, scenario.fence, scenario.coordinates,
			scenario.page, discoverysource.ErrPageCommitConflict)
		assertUncommittedPageStateWithRunCheckpoint(t, scenario, 1)
	})
	t.Run("stale fence", func(t *testing.T) {
		scenario := newPageCommitScenario(t, nil)
		raw := [32]byte{42}
		stale, err := leasefence.FromQueueClaim(scenario.runID, scenario.owner, 2, &raw)
		if err != nil {
			t.Fatal("create stale fence")
		}
		assertPageCommitError(t, scenario.committer, stale, scenario.coordinates,
			scenario.page, discoverysource.ErrPageCommitConflict)
		assertUncommittedPageState(t, scenario)
	})
	t.Run("destroyed fence", func(t *testing.T) {
		scenario := newPageCommitScenario(t, nil)
		scenario.fence.Destroy()
		assertPageCommitError(t, scenario.committer, scenario.fence, scenario.coordinates,
			scenario.page, discoverysource.ErrPageCommitConflict)
		assertUncommittedPageState(t, scenario)
	})
}

func TestPageCommitterRejectsSameRunObjectCollisionIntegration(t *testing.T) {
	scenario := newPageCommitScenario(t, nil)
	if _, err := scenario.committer.ApplyPage(
		context.Background(), scenario.fence, scenario.coordinates, scenario.page,
	); err != nil {
		t.Fatalf("commit first page: %v", err)
	}
	execAssetSQL(t, scenario.harness.db, `
UPDATE asset_source_runs SET stage_code='NORMALIZING',version=version+1 WHERE id=$1
`, scenario.runID)
	second := scenario.page
	second.NextCheckpoint, _ = discoverysource.NewCheckpoint(
		"EXTERNAL_V1", []byte(`{"cursor":"opaque-page-2"}`),
	)
	second.Items = append([]assetdiscovery.NormalizedItem(nil), scenario.page.Items...)
	second.Items[0].Freshness.OrderSequence = 2
	second.Items[0].Freshness.ProviderVersionSHA256 = strings.Repeat("2", 64)
	coordinates := scenario.coordinates
	coordinates.PageSequence = 2
	assertPageCommitError(t, scenario.committer, scenario.fence, coordinates,
		second, discoverysource.ErrPageCommitConflict)
	var observations, secondPageReceipt, secondRelationReceipt int
	var sourceCheckpoint, runCheckpoint, pageSequence, relationSequence int64
	if err := scenario.harness.db.QueryRow(context.Background(), `
SELECT (SELECT count(*) FROM asset_observations WHERE run_id=$1::uuid),
       (SELECT count(*) FROM audit_records WHERE request_id='source-page:'||$1||':2'),
       (SELECT count(*) FROM audit_records WHERE request_id='source-relation-page:'||$1||':2'),
       source.checkpoint_version,run.checkpoint_version,run.page_sequence,run.relation_page_sequence
FROM asset_sources AS source JOIN asset_source_runs AS run ON run.source_id=source.id
WHERE source.id=$2::uuid AND run.id=$1::uuid
`, scenario.runID, scenario.fixture.sourceID).Scan(
		&observations, &secondPageReceipt, &secondRelationReceipt,
		&sourceCheckpoint, &runCheckpoint, &pageSequence, &relationSequence,
	); err != nil {
		t.Fatal("read same-run collision state")
	}
	if observations != 1 || secondPageReceipt != 0 || secondRelationReceipt != 0 ||
		sourceCheckpoint != 1 || runCheckpoint != 1 || pageSequence != 1 || relationSequence != 1 {
		t.Fatalf("same-run collision advanced page state: observations=%d receipts=%d/%d checkpoint=%d/%d sequence=%d/%d",
			observations, secondPageReceipt, secondRelationReceipt, sourceCheckpoint, runCheckpoint,
			pageSequence, relationSequence)
	}
}

func TestPageCommitterRejectsFreshnessAndKindDriftIntegration(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*testing.T, *assetCatalogHarness, assetCatalogFixture)
		mutate  func(*assetdiscovery.NormalizedItem)
	}{
		{
			name: "equal-order semantic collision",
			mutate: func(item *assetdiscovery.NormalizedItem) {
				item.DisplayName = "changed-at-equal-order"
				item.Document = []byte(`{"display_name":"changed-at-equal-order"}`)
				digest := sha256.Sum256(item.Document)
				item.DocumentSHA256 = hex.EncodeToString(digest[:])
			},
		},
		{
			name: "order regression",
			prepare: func(t *testing.T, harness *assetCatalogHarness, fixture assetCatalogFixture) {
				execAssetSQL(t, harness.db, `ALTER TABLE asset_observations DISABLE TRIGGER USER`)
				t.Cleanup(func() {
					_, _ = harness.db.Exec(context.Background(),
						`ALTER TABLE asset_observations ENABLE TRIGGER USER`)
				})
				execAssetSQL(t, harness.db, `
UPDATE asset_observations SET freshness_order_sequence=2 WHERE id=$1
`, fixture.observationID)
				execAssetSQL(t, harness.db, `ALTER TABLE asset_observations ENABLE TRIGGER USER`)
			},
		},
		{
			name: "immutable kind drift",
			mutate: func(item *assetdiscovery.NormalizedItem) {
				item.Kind = assetcatalog.KindCloudResource
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newAssetCatalogHarness(t)
			harness.applyThroughAssetCatalog(t)
			fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
			if test.prepare != nil {
				test.prepare(t, harness, fixture)
			}
			policy := pageCommitFactPolicy(fixture)
			policy.AllowedDocumentFields = map[assetcatalog.Kind][]string{
				assetcatalog.KindLinuxVM:       {"display_name"},
				assetcatalog.KindCloudResource: {"display_name"},
			}
			scenario := newPageCommitScenarioForFixture(
				t, harness, fixture, "83f00000-0000-4000-8000-000000000031",
				"m1e-freshness-worker", policy, nil,
			)
			document := []byte(`{"display_name":"closure-host-a"}`)
			digest := sha256.Sum256(document)
			item := assetdiscovery.NormalizedItem{
				EnvironmentID: fixture.environmentID, ProviderKind: "EXTERNAL_V1",
				ExternalID: "external-host-a", Kind: assetcatalog.KindLinuxVM,
				DisplayName: "closure-host-a", SchemaVersion: "asset.v1",
				Document: document, DocumentSHA256: hex.EncodeToString(digest[:]),
				Freshness: assetdiscovery.FreshnessCandidate{
					Kind: assetcatalog.FreshnessObjectSequence, OrderSequence: 1,
					ProviderVersionSHA256: strings.Repeat("1", 64),
				},
				FieldProvenance: pageCommitFieldProvenance(),
			}
			if test.mutate != nil {
				test.mutate(&item)
			}
			scenario.page.Items = []assetdiscovery.NormalizedItem{item}
			assertPageCommitError(t, scenario.committer, scenario.fence, scenario.coordinates,
				scenario.page, discoverysource.ErrPageCommitConflict)
			assertUncommittedPageStateAt(t, scenario, 1, 1)
		})
	}
}

func TestPageCommitterProjectsFingerprintConflictWithoutCandidateAssetIntegration(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	manual := seedGovernedManualCatalog(t, harness.db)
	external := seedClosureExternalValidationOnFixture(t, harness.db, manual)
	finishClosureExternalValidation(t, harness.db, external, 1, strings.Repeat("7", 64))

	fingerprintCode, fingerprintValue := "SERIAL_NUMBER", "same-device"
	fingerprintDigest := pageCommitFingerprintDigest(t, fingerprintCode, fingerprintValue)
	execAssetSQL(t, harness.db, `ALTER TABLE asset_observations DISABLE TRIGGER USER`)
	t.Cleanup(func() {
		_, _ = harness.db.Exec(context.Background(),
			`ALTER TABLE asset_observations ENABLE TRIGGER USER`)
	})
	execAssetSQL(t, harness.db, `
UPDATE asset_observations SET fingerprint_sha256=$2 WHERE id=$1
`, manual.observationID, fingerprintDigest)
	execAssetSQL(t, harness.db, `ALTER TABLE asset_observations ENABLE TRIGGER USER`)
	execAssetSQL(t, harness.db, `
UPDATE assets SET mapping_status='EXACT',version=version+1 WHERE id=$1
`, manual.assetID)
	var seededFingerprint string
	if err := harness.db.QueryRow(context.Background(), `
SELECT observation.fingerprint_sha256
FROM assets AS asset JOIN asset_observations AS observation ON observation.id=asset.last_observation_id
WHERE asset.id=$1::uuid
`, manual.assetID).Scan(&seededFingerprint); err != nil || seededFingerprint != fingerprintDigest {
		t.Fatal("cross-source fingerprint candidate fixture is not exact")
	}

	scenario := newPageCommitScenarioForFixture(
		t, harness, external, "83f00000-0000-4000-8000-000000000032",
		"m1e-fingerprint-worker", pageCommitFactPolicy(external), nil,
	)
	document := []byte(`{"display_name":"candidate"}`)
	documentDigest := sha256.Sum256(document)
	scenario.page.Items = []assetdiscovery.NormalizedItem{{
		EnvironmentID: external.environmentID, ProviderKind: "EXTERNAL_V1",
		ExternalID: "fingerprint-candidate", Kind: assetcatalog.KindCloudResource,
		DisplayName: "candidate", SchemaVersion: "asset.v1", Document: document,
		DocumentSHA256: hex.EncodeToString(documentDigest[:]),
		Freshness: assetdiscovery.FreshnessCandidate{
			Kind: assetcatalog.FreshnessObjectSequence, OrderSequence: 1,
			ProviderVersionSHA256: strings.Repeat("1", 64),
		},
		FieldProvenance: pageCommitFieldProvenance(),
		Fingerprints:    map[string]string{fingerprintCode: fingerprintValue},
	}}
	result, err := scenario.committer.ApplyPage(
		context.Background(), scenario.fence, scenario.coordinates, scenario.page,
	)
	if err != nil || result.Replayed {
		t.Fatalf("fingerprint page ApplyPage() = (%#v,%v)", result, err)
	}
	var observations, assets, details, conflicts int
	var observedFingerprint string
	if err := harness.db.QueryRow(context.Background(), `
SELECT count(*),min(fingerprint_sha256)
FROM asset_observations WHERE run_id=$1::uuid
`, scenario.runID).Scan(&observations, &observedFingerprint); err != nil {
		t.Fatal("read fingerprint candidate observation")
	}
	if err := harness.db.QueryRow(context.Background(), `
SELECT (SELECT count(*) FROM assets WHERE source_id=$1::uuid AND external_id='fingerprint-candidate'),
       (SELECT count(*) FROM asset_type_details WHERE source_id=$1::uuid AND external_id='fingerprint-candidate'),
       (SELECT count(*) FROM asset_conflicts WHERE source_id=$1::uuid)
`, external.sourceID).Scan(&assets, &details, &conflicts); err != nil {
		t.Fatal("read fingerprint projection counts")
	}
	if observedFingerprint != fingerprintDigest || conflicts != 1 {
		t.Fatalf("fingerprint conflict was not projected: observed=%s expected=%s conflicts=%d",
			observedFingerprint, fingerprintDigest, conflicts)
	}
	var conflictAssetID, conflictSourceID, conflictObservationID, existingHash, candidateHash string
	var mappingStatus string
	var runConflict, runRejected, mappingAudit, mappingOutbox int64
	if err := harness.db.QueryRow(context.Background(), `
SELECT conflict.asset_id::text,conflict.source_id::text,conflict.observation_id::text,
	   conflict.existing_value_sha256,conflict.candidate_value_sha256,
	   matched.mapping_status,run.conflict_count,run.rejected_count,
	   (SELECT count(*) FROM audit_records
	     WHERE resource_id=matched.id::text AND actor_id=$2
	       AND action='asset.source.asset.mapping.ambiguous.v1'),
	   (SELECT count(*) FROM outbox_events
	     WHERE aggregate_id=matched.id
	       AND event_type='asset.source.asset.mapping.ambiguous.v1')
FROM asset_source_runs AS run
JOIN asset_conflicts AS conflict ON conflict.source_id=run.source_id
JOIN assets AS matched ON matched.id=conflict.asset_id
WHERE run.id=$1::uuid
	`, scenario.runID, scenario.owner).Scan(
		&conflictAssetID, &conflictSourceID,
		&conflictObservationID, &existingHash, &candidateHash, &mappingStatus,
		&runConflict, &runRejected, &mappingAudit, &mappingOutbox,
	); err != nil {
		t.Fatal("read fingerprint conflict projection")
	}
	if observations != 1 || assets != 0 || details != 0 || conflicts != 1 ||
		conflictAssetID != manual.assetID || conflictSourceID != external.sourceID ||
		conflictObservationID == "" || existingHash != fingerprintDigest || candidateHash != fingerprintDigest ||
		mappingStatus != "AMBIGUOUS" || runConflict != 1 || runRejected != 1 ||
		mappingAudit != 1 || mappingOutbox != 1 {
		t.Fatalf("fingerprint conflict projection mismatch: observations=%d assets=%d details=%d conflicts=%d mapping=%s counts=%d/%d evidence=%d/%d",
			observations, assets, details, conflicts, mappingStatus, runConflict, runRejected,
			mappingAudit, mappingOutbox)
	}
}

func TestPageCommitterFinalCompleteSnapshotClosesOnlySourceOwnedProjectionIntegration(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	execAssetSQL(t, harness.db, `
UPDATE assets SET lifecycle='ACTIVE',version=version+1 WHERE source_id=$1
`, fixture.sourceID)
	execAssetSQL(t, harness.db, `ALTER TABLE asset_relationships DISABLE TRIGGER USER`)
	t.Cleanup(func() {
		_, _ = harness.db.Exec(context.Background(),
			`ALTER TABLE asset_relationships ENABLE TRIGGER USER`)
	})
	execAssetSQL(t, harness.db, `
INSERT INTO asset_relationships (
 id,tenant_id,workspace_id,source_id,source_revision,canonical_revision_digest,last_run_id,
 last_page_sequence,relation_page_sha256,accepted_checkpoint_version,run_fence_epoch,
 source_environment_id,target_environment_id,source_asset_id,target_asset_id,
 from_external_id,to_external_id,relationship_type,provider_path_code,confidence,freshness_kind,
 freshness_order_sequence,provider_version_sha256,relation_fact_sha256,provenance,
 provenance_source_id,status,idempotency_key,request_hash
) VALUES (
 '83f00000-0000-4000-8000-000000000041',$1,$2,$3,1,$4,$5,1,repeat('d',64),1,1,
 $6,$6,$7,$8,'external-host-a','external-host-b','RUNS_ON','manual.keep',100,
 'OBJECT_SEQUENCE',1,repeat('e',64),repeat('f',64),'MANUAL',NULL,'ACTIVE',
 'm1e-manual-relationship',repeat('a',64)
)
`, fixture.tenantID, fixture.workspaceID, fixture.sourceID, fixture.revisionDigest,
		fixture.runID, fixture.environmentID, fixture.assetID, fixture.secondAssetID)
	execAssetSQL(t, harness.db, `ALTER TABLE asset_relationships ENABLE TRIGGER USER`)

	scenario := newPageCommitScenarioForFixture(
		t, harness, fixture, "83f00000-0000-4000-8000-000000000042",
		"m1e-closure-worker", pageCommitFactPolicy(fixture), nil,
	)
	scenario.page.FinalPage = true
	scenario.page.CompleteSnapshot = true
	result, err := scenario.committer.ApplyPage(
		context.Background(), scenario.fence, scenario.coordinates, scenario.page,
	)
	if err != nil || !result.FinalPage || !result.CompleteSnapshot || result.Replayed ||
		result.CheckpointVersion != 2 ||
		result.RelationPageDigestSHA256 != "b89ad607e709ef2ea85f7fc6eb0f80e32ae3ecf234220907a0fe718825f7c151" {
		t.Fatalf("complete closure ApplyPage() = (%#v,%v)", result, err)
	}
	var staleAssets, observations, details, discoveredInactive, manualActive int
	var status, stage, relationshipRun, relationshipDigest string
	var effective bool
	var missing, stale, relationshipPage, relationshipCheckpoint, relationshipFence int64
	var staleAudit, staleOutbox, inactiveAudit, inactiveOutbox int64
	if err := harness.db.QueryRow(context.Background(), `
SELECT (SELECT count(*) FROM assets WHERE source_id=$1::uuid AND lifecycle='STALE'),
       (SELECT count(*) FROM asset_observations WHERE source_id=$1::uuid),
       (SELECT count(*) FROM asset_type_details WHERE source_id=$1::uuid),
       (SELECT count(*) FROM asset_relationships
         WHERE source_id=$1::uuid AND provenance='DISCOVERED' AND status='INACTIVE'),
       (SELECT count(*) FROM asset_relationships
         WHERE source_id=$1::uuid AND provenance='MANUAL' AND status='ACTIVE'),
       run.status,run.stage_code,run.effective_complete_snapshot,run.missing_count,run.stale_count,
	   relationship.last_run_id::text,relationship.last_page_sequence,
	   relationship.accepted_checkpoint_version,relationship.run_fence_epoch,
	   relationship.relation_page_sha256,
	   (SELECT count(*) FROM audit_records
	     WHERE actor_id=$3 AND action='asset.source.asset.stale.v1'
	       AND resource_id IN ($4,$5)),
	   (SELECT count(*) FROM outbox_events
	     WHERE event_type='asset.source.asset.stale.v1'
	       AND aggregate_id IN ($4::uuid,$5::uuid)),
	   (SELECT count(*) FROM audit_records
	     WHERE actor_id=$3 AND action='asset.source.relationship.inactive.v1'
	       AND resource_id=$6),
	   (SELECT count(*) FROM outbox_events
	     WHERE event_type='asset.source.relationship.inactive.v1'
	       AND aggregate_id=$6::uuid)
FROM asset_source_runs AS run
JOIN asset_relationships AS relationship
	ON relationship.source_id=run.source_id AND relationship.provenance='DISCOVERED'
WHERE run.id=$2::uuid
	`, fixture.sourceID, scenario.runID, scenario.owner, fixture.assetID,
		fixture.secondAssetID, fixture.relationshipID).Scan(
		&staleAssets, &observations, &details, &discoveredInactive, &manualActive,
		&status, &stage, &effective, &missing, &stale, &relationshipRun,
		&relationshipPage, &relationshipCheckpoint, &relationshipFence, &relationshipDigest,
		&staleAudit, &staleOutbox, &inactiveAudit, &inactiveOutbox,
	); err != nil {
		t.Fatal("read complete snapshot closure")
	}
	if staleAssets != 2 || observations != 2 || details != 1 || discoveredInactive != 1 || manualActive != 1 ||
		status != "FINALIZING" || stage != "CLEANING_UP" || !effective || missing != 2 || stale != 2 ||
		relationshipRun != scenario.runID || relationshipPage != 1 || relationshipCheckpoint != 2 ||
		relationshipFence != 1 || relationshipDigest != result.RelationPageDigestSHA256 ||
		staleAudit != 2 || staleOutbox != 2 || inactiveAudit != 1 || inactiveOutbox != 1 {
		t.Fatalf("complete closure mismatch: assets=%d observations=%d details=%d relations=%d/%d run=%s/%s effective=%t counts=%d/%d evidence=%d/%d/%d/%d",
			staleAssets, observations, details, discoveredInactive, manualActive,
			status, stage, effective, missing, stale,
			staleAudit, staleOutbox, inactiveAudit, inactiveOutbox)
	}
}

func TestPageCommitterCrossEnvironmentPolicyResolverMatrixIntegration(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture, environments := seedPublishedExplicitPageCommitSource(t, harness)
	policy := pageCommitFactPolicy(fixture)
	policy.EnvironmentMapping = assetcatalog.EnvironmentMappingExplicitItem
	policy.AuthorityEnvironmentIDs = append([]string(nil), environments...)
	scenario := newPageCommitScenarioForFixture(
		t, harness, fixture, "83e00000-0000-4000-8000-000000000004",
		"m1e-cross-environment-worker", policy, nil,
	)

	newItem := func(environmentID, externalID, name, version string) assetdiscovery.NormalizedItem {
		document := []byte(`{"display_name":"` + name + `"}`)
		digest := sha256.Sum256(document)
		return assetdiscovery.NormalizedItem{
			EnvironmentID: environmentID, ProviderKind: "EXTERNAL_V1", ExternalID: externalID,
			Kind: assetcatalog.KindCloudResource, DisplayName: name, SchemaVersion: "asset.v1",
			Document: document, DocumentSHA256: hex.EncodeToString(digest[:]),
			Freshness: assetdiscovery.FreshnessCandidate{
				Kind: assetcatalog.FreshnessObjectSequence, OrderSequence: 1,
				ProviderVersionSHA256: strings.Repeat(version, 64),
			},
			FieldProvenance: pageCommitFieldProvenance(),
		}
	}
	expectedReference := assetcatalog.PolicyReferenceID("cross-env-policy-v1")
	sameEnvironment := assetdiscovery.ObservedRelation{
		SourceEnvironmentID: environments[0], TargetEnvironmentID: environments[0],
		FromExternalID: "node-a", ToExternalID: "node-c",
		Type: assetcatalog.RelationshipDependsOn, ProviderPathCode: "DISPLAY_NAME", Confidence: 100,
		Freshness: assetdiscovery.FreshnessCandidate{
			Kind: assetcatalog.FreshnessObjectSequence, OrderSequence: 1,
			ProviderVersionSHA256: strings.Repeat("4", 64),
		},
	}
	crossEnvironment := assetdiscovery.ObservedRelation{
		SourceEnvironmentID: environments[0], TargetEnvironmentID: environments[1],
		FromExternalID: "node-a", ToExternalID: "node-b",
		Type: assetcatalog.RelationshipDependsOn, ProviderPathCode: "KIND",
		CrossEnvironmentPolicyReferenceID: expectedReference, Confidence: 100,
		Freshness: assetdiscovery.FreshnessCandidate{
			Kind: assetcatalog.FreshnessObjectSequence, OrderSequence: 1,
			ProviderVersionSHA256: strings.Repeat("5", 64),
		},
	}
	scenario.page.Items = []assetdiscovery.NormalizedItem{
		newItem(environments[0], "node-a", "node-a", "1"),
		newItem(environments[1], "node-b", "node-b", "2"),
		newItem(environments[0], "node-c", "node-c", "3"),
	}
	scenario.page.Relations = []assetdiscovery.ObservedRelation{sameEnvironment, crossEnvironment}

	invalidSame := scenario.page
	invalidSame.Relations = append([]assetdiscovery.ObservedRelation(nil), scenario.page.Relations...)
	invalidSame.Relations[0].CrossEnvironmentPolicyReferenceID = expectedReference
	assertPageCommitError(t, scenario.committer, scenario.fence, scenario.coordinates,
		invalidSame, discoverysource.ErrPageCommitInvalid)
	if scenario.resolver.crossEnvironmentCalls != 0 {
		t.Fatal("same-environment relation invoked cross-environment resolver")
	}

	for _, invalidReference := range []assetcatalog.PolicyReferenceID{"", "invalid reference"} {
		invalid := scenario.page
		invalid.Relations = append([]assetdiscovery.ObservedRelation(nil), scenario.page.Relations...)
		invalid.Relations[1].CrossEnvironmentPolicyReferenceID = invalidReference
		assertPageCommitError(t, scenario.committer, scenario.fence, scenario.coordinates,
			invalid, discoverysource.ErrPageCommitInvalid)
	}
	if scenario.resolver.crossEnvironmentCalls != 0 {
		t.Fatal("structurally invalid reference invoked cross-environment resolver")
	}

	scenario.resolver.crossErr = errors.New("resolver-sensitive-canary")
	assertPageCommitError(t, scenario.committer, scenario.fence, scenario.coordinates,
		scenario.page, discoverysource.ErrPageCommitUnavailable)
	scenario.resolver.crossErr = nil
	for _, unavailableReference := range []assetcatalog.PolicyReferenceID{"", "invalid reference"} {
		scenario.resolver.crossEnvironmentID = unavailableReference
		assertPageCommitError(t, scenario.committer, scenario.fence, scenario.coordinates,
			scenario.page, discoverysource.ErrPageCommitUnavailable)
	}
	scenario.resolver.crossEnvironmentID = "cross-env-policy-other"
	assertPageCommitError(t, scenario.committer, scenario.fence, scenario.coordinates,
		scenario.page, discoverysource.ErrPageCommitInvalid)
	scenario.resolver.crossEnvironmentID = expectedReference
	committed, err := scenario.committer.ApplyPage(
		context.Background(), scenario.fence, scenario.coordinates, scenario.page,
	)
	if err != nil || committed.Replayed {
		t.Fatalf("authorized cross-environment ApplyPage() = (%#v,%v)", committed, err)
	}

	for _, revision := range append(
		append([]assetcatalog.SourceRevision(nil), scenario.resolver.pageRevisions...),
		scenario.resolver.crossEnvironmentRevisions...,
	) {
		if revision.ID != fixture.revisionID || revision.Revision != 1 ||
			revision.CanonicalRevisionDigest != fixture.revisionDigest ||
			!slices.Equal(revision.AuthorityEnvironmentIDs, environments) {
			t.Fatal("resolver did not receive the exact locked revision clone")
		}
	}
	if scenario.resolver.crossEnvironmentCalls != 5 ||
		len(scenario.resolver.crossEnvironmentCoordinates) != 5 {
		t.Fatalf("cross-environment resolver calls = %d/%d, want 5 exact calls",
			scenario.resolver.crossEnvironmentCalls, len(scenario.resolver.crossEnvironmentCoordinates))
	}
	for _, coordinates := range scenario.resolver.crossEnvironmentCoordinates {
		if coordinates != (discoverysource.CrossEnvironmentRelationPolicyCoordinates{
			SourceEnvironmentID: environments[0], TargetEnvironmentID: environments[1],
			RelationshipType: assetcatalog.RelationshipDependsOn, ProviderPathCode: "KIND",
		}) {
			t.Fatalf("cross-environment resolver coordinates = %#v", coordinates)
		}
	}

	changedReference := scenario.page
	changedReference.Relations = append([]assetdiscovery.ObservedRelation(nil), scenario.page.Relations...)
	changedReference.Relations[1].CrossEnvironmentPolicyReferenceID = "cross-env-policy-other"
	beforeReplayCalls := scenario.resolver.crossEnvironmentCalls
	assertPageCommitError(t, scenario.committer, scenario.fence, scenario.coordinates,
		changedReference, discoverysource.ErrPageCommitConflict)
	if scenario.resolver.crossEnvironmentCalls != beforeReplayCalls {
		t.Fatal("changed-reference receipt replay invoked live resolver")
	}

	var persistedReference, serializedEvidence string
	if err := harness.db.QueryRow(context.Background(), `
SELECT relationship.cross_environment_policy_reference_id,
       COALESCE((SELECT string_agg(row_to_json(audit)::text,'') FROM audit_records AS audit
                 WHERE audit.workspace_id=$1::uuid AND audit.actor_id=$2), '') ||
       COALESCE((SELECT string_agg(event.payload::text,'') FROM outbox_events AS event
                 WHERE event.workspace_id=$1::uuid), '')
FROM asset_relationships AS relationship
WHERE relationship.source_id=$3::uuid
  AND relationship.source_environment_id<>relationship.target_environment_id
`, fixture.workspaceID, scenario.owner, fixture.sourceID).Scan(
		&persistedReference, &serializedEvidence,
	); err != nil {
		t.Fatal("read cross-environment projection evidence")
	}
	if persistedReference != string(expectedReference) {
		t.Fatal("cross-environment relationship did not retain the authorized reference")
	}
	for _, forbidden := range []string{
		string(expectedReference), "cross-env-policy-other", "resolver-sensitive-canary",
		string(scenario.checkpointBytes), "node-a", "node-b", "node-c", scenario.fenceDigest,
	} {
		if strings.Contains(serializedEvidence, forbidden) {
			t.Fatal("cross-environment receipt/audit/outbox leaked protected material")
		}
	}
}

func TestPageCommitterRelationOnlyPageUpdatesExactRelationshipIdentityIntegration(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	execAssetSQL(t, harness.db, `ALTER TABLE asset_relationships DISABLE TRIGGER USER`)
	t.Cleanup(func() {
		_, _ = harness.db.Exec(context.Background(),
			`ALTER TABLE asset_relationships ENABLE TRIGGER USER`)
	})
	execAssetSQL(t, harness.db, `
UPDATE asset_relationships SET provider_path_code='KIND' WHERE id=$1
`, fixture.relationshipID)
	execAssetSQL(t, harness.db, `ALTER TABLE asset_relationships ENABLE TRIGGER USER`)

	scenario := newPageCommitScenarioForFixture(
		t, harness, fixture, "83f00000-0000-4000-8000-000000000051",
		"m1e-relation-worker", pageCommitFactPolicy(fixture), nil,
	)
	scenario.page.Relations = []assetdiscovery.ObservedRelation{{
		SourceEnvironmentID: fixture.environmentID, TargetEnvironmentID: fixture.environmentID,
		FromExternalID: "external-host-a", ToExternalID: "external-host-b",
		Type: assetcatalog.RelationshipDependsOn, ProviderPathCode: "KIND", Confidence: 90,
		Freshness: assetdiscovery.FreshnessCandidate{
			Kind: assetcatalog.FreshnessObjectSequence, OrderSequence: 2,
			ProviderVersionSHA256: strings.Repeat("9", 64),
		},
	}}
	result, err := scenario.committer.ApplyPage(
		context.Background(), scenario.fence, scenario.coordinates, scenario.page,
	)
	if err != nil || result.Replayed || result.RelationPageDigestSHA256 == "" {
		t.Fatalf("relation-only ApplyPage() = (%#v,%v)", result, err)
	}
	var relationshipID, lastRunID, auditResourceID, outboxAggregateID string
	var version, pageSequence, checkpointVersion, auditCount, outboxCount int64
	if err := harness.db.QueryRow(context.Background(), `
SELECT relationship.id::text,relationship.last_run_id::text,relationship.version,
       relationship.last_page_sequence,relationship.accepted_checkpoint_version,
       audit.resource_id,event.aggregate_id::text,
       (SELECT count(*) FROM audit_records WHERE resource_id=relationship.id::text
          AND action='asset.relationship.projected.v1' AND actor_id=$2),
       (SELECT count(*) FROM outbox_events WHERE aggregate_id=relationship.id
          AND event_type='asset.relationship.projected.v1')
FROM asset_relationships AS relationship
JOIN audit_records AS audit
  ON audit.resource_id=relationship.id::text AND audit.actor_id=$2
JOIN outbox_events AS event ON event.aggregate_id=relationship.id
WHERE relationship.id=$1::uuid
ORDER BY audit.created_at DESC,event.created_at DESC
LIMIT 1
`, fixture.relationshipID, scenario.owner).Scan(
		&relationshipID, &lastRunID, &version, &pageSequence, &checkpointVersion,
		&auditResourceID, &outboxAggregateID, &auditCount, &outboxCount,
	); err != nil {
		t.Fatal("read relation-only projection")
	}
	if relationshipID != fixture.relationshipID || lastRunID != scenario.runID || version != 2 ||
		pageSequence != 1 || checkpointVersion != 2 || auditResourceID != fixture.relationshipID ||
		outboxAggregateID != fixture.relationshipID || auditCount != 1 || outboxCount != 1 {
		t.Fatalf("relation identity side effects drifted: id=%s run=%s version=%d coordinates=%d/%d audit=%s/%d outbox=%s/%d",
			relationshipID, lastRunID, version, pageSequence, checkpointVersion,
			auditResourceID, auditCount, outboxAggregateID, outboxCount)
	}
}

func TestPageCommitterTombstoneAndRestorePreserveHistoryIntegration(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	var priorObservationID string
	var canSelect, canUpdate bool
	if err := harness.application.QueryRow(context.Background(), `
SELECT id::text,
       has_table_privilege(current_user,'public.asset_observations','SELECT'),
       has_table_privilege(current_user,'public.asset_observations','UPDATE')
FROM asset_observations WHERE id=$1::uuid
`, fixture.observationID).Scan(&priorObservationID, &canSelect, &canUpdate); err != nil ||
		priorObservationID != fixture.observationID || !canSelect || canUpdate {
		t.Fatal("runtime prior-observation plain-read ACL evidence is not exact")
	}
	_, lockErr := harness.application.Exec(context.Background(), `
SELECT id FROM asset_observations WHERE id=$1::uuid FOR SHARE
`, fixture.observationID)
	if pageCommitSQLState(lockErr) != "42501" {
		t.Fatalf("runtime prior-observation FOR SHARE SQLSTATE = %q, want 42501",
			pageCommitSQLState(lockErr))
	}
	execAssetSQL(t, harness.db, `
UPDATE assets SET lifecycle='ACTIVE',version=version+1 WHERE id=$1
`, fixture.assetID)
	policy := pageCommitFactPolicy(fixture)
	policy.AllowedDocumentFields = map[assetcatalog.Kind][]string{
		assetcatalog.KindLinuxVM: {"display_name"},
	}
	newID := deterministicAssetIDGenerator()
	tombstone := newPageCommitScenarioForFixtureWithKey(
		t, harness, fixture, "83f00000-0000-4000-8000-000000000052",
		"m1e-tombstone-worker", "m1e-tombstone-run", policy, newID,
	)
	tombstone.page.Items = []assetdiscovery.NormalizedItem{{
		EnvironmentID: fixture.environmentID, ProviderKind: "EXTERNAL_V1",
		ExternalID: "external-host-a", Tombstone: true, TombstoneReason: "PROVIDER_DELETED",
		Freshness: assetdiscovery.FreshnessCandidate{
			Kind: assetcatalog.FreshnessObjectSequence, OrderSequence: 2,
			ProviderVersionSHA256: strings.Repeat("a", 64),
		},
		FieldProvenance: pageCommitTombstoneProvenance(),
	}}
	tombstone.page.FinalPage = true
	execAssetSQL(t, harness.db, `
UPDATE asset_source_runs
SET cleanup_status='PENDING',cleanup_attempt_id=gen_random_uuid(),
    cleanup_attempt_epoch=fence_epoch,version=version+1
WHERE id=$1
`, tombstone.runID)
	result, err := tombstone.committer.ApplyPage(
		context.Background(), tombstone.fence, tombstone.coordinates, tombstone.page,
	)
	if err != nil || !result.FinalPage || result.CompleteSnapshot || result.Replayed {
		t.Fatalf("tombstone ApplyPage() = (%#v,%v)", result, err)
	}
	var lifecycle, schemaVersion, relationStatus string
	var normalizedDocument, documentSHA *string
	var tombstoned, stale, observations, details, inactiveAudit, inactiveOutbox int64
	if err := harness.db.QueryRow(context.Background(), `
SELECT asset.lifecycle,observation.schema_version,
	   convert_from(observation.normalized_document,'UTF8'),observation.document_sha256,
	   relationship.status,run.tombstoned_count,run.stale_count,
	   (SELECT count(*) FROM asset_observations
	     WHERE source_id=$1::uuid AND external_id='external-host-a'),
	   (SELECT count(*) FROM asset_type_details WHERE asset_id=$2::uuid),
	   (SELECT count(*) FROM audit_records
	     WHERE resource_id=relationship.id::text AND actor_id=$3
	       AND action='asset.source.relationship.inactive.v1'),
	   (SELECT count(*) FROM outbox_events
	     WHERE aggregate_id=relationship.id
	       AND event_type='asset.source.relationship.inactive.v1')
FROM assets AS asset
JOIN asset_observations AS observation ON observation.id=asset.last_observation_id
JOIN asset_relationships AS relationship
	ON relationship.source_id=asset.source_id AND relationship.source_asset_id=asset.id
JOIN asset_source_runs AS run ON run.id=observation.run_id
WHERE asset.id=$2::uuid
	`, fixture.sourceID, fixture.assetID, tombstone.owner).Scan(
		&lifecycle, &schemaVersion, &normalizedDocument, &documentSHA, &relationStatus,
		&tombstoned, &stale, &observations, &details, &inactiveAudit, &inactiveOutbox,
	); err != nil {
		t.Fatal("read tombstone projection")
	}
	if lifecycle != "STALE" || schemaVersion != "asset.v1" || normalizedDocument != nil ||
		documentSHA != nil || relationStatus != "INACTIVE" || tombstoned != 1 || stale != 1 ||
		observations != 2 || details != 1 || inactiveAudit != 1 || inactiveOutbox != 1 {
		t.Fatalf("tombstone projection mismatch: lifecycle=%s schema=%s relation=%s counts=%d/%d history=%d/%d evidence=%d/%d",
			lifecycle, schemaVersion, relationStatus, tombstoned, stale, observations, details,
			inactiveAudit, inactiveOutbox)
	}
	finishPageCommitRunForTest(t, harness, fixture, tombstone.runID)

	restore := newPageCommitScenarioForFixtureWithKey(
		t, harness, fixture, "83f00000-0000-4000-8000-000000000053",
		"m1e-restore-worker", "m1e-restore-run", policy, newID,
	)
	document := []byte(`{"display_name":"closure-host-a"}`)
	documentDigest := sha256.Sum256(document)
	restore.page.Items = []assetdiscovery.NormalizedItem{{
		EnvironmentID: fixture.environmentID, ProviderKind: "EXTERNAL_V1",
		ExternalID: "external-host-a", Kind: assetcatalog.KindLinuxVM,
		DisplayName: "closure-host-a", SchemaVersion: "asset.v1",
		Document: document, DocumentSHA256: hex.EncodeToString(documentDigest[:]),
		Freshness: assetdiscovery.FreshnessCandidate{
			Kind: assetcatalog.FreshnessObjectSequence, OrderSequence: 3,
			ProviderVersionSHA256: strings.Repeat("b", 64),
		},
		FieldProvenance: pageCommitFieldProvenance(),
	}}
	result, err = restore.committer.ApplyPage(
		context.Background(), restore.fence, restore.coordinates, restore.page,
	)
	if err != nil || result.Replayed {
		t.Fatalf("restore ApplyPage() = (%#v,%v)", result, err)
	}
	var restored, changed, restoreAudit, restoreOutbox int64
	if err := harness.db.QueryRow(context.Background(), `
SELECT asset.lifecycle,relationship.status,run.restored_count,run.changed_count,
       (SELECT count(*) FROM asset_observations
         WHERE source_id=$1::uuid AND external_id='external-host-a'),
       (SELECT count(*) FROM asset_type_details WHERE asset_id=$2::uuid),
       (SELECT count(*) FROM audit_records
         WHERE resource_id=$2 AND action='asset.source.asset.restored.v1' AND actor_id=$4),
       (SELECT count(*) FROM outbox_events
         WHERE aggregate_id=$2::uuid AND event_type='asset.source.asset.restored.v1')
FROM assets AS asset
JOIN asset_relationships AS relationship
  ON relationship.source_id=asset.source_id AND relationship.source_asset_id=asset.id
JOIN asset_source_runs AS run ON run.id=$3::uuid
WHERE asset.id=$2::uuid
`, fixture.sourceID, fixture.assetID, restore.runID, restore.owner).Scan(
		&lifecycle, &relationStatus, &restored, &changed, &observations, &details,
		&restoreAudit, &restoreOutbox,
	); err != nil {
		t.Fatal("read restore projection")
	}
	if lifecycle != "STALE" || relationStatus != "INACTIVE" || restored != 1 || changed != 1 ||
		observations != 3 || details != 2 || restoreAudit != 1 || restoreOutbox != 1 {
		t.Fatalf("restore projection mismatch: lifecycle=%s relation=%s counts=%d/%d history=%d/%d evidence=%d/%d",
			lifecycle, relationStatus, restored, changed, observations, details, restoreAudit, restoreOutbox)
	}
}

type pageCommitEnvelopeTracer struct {
	mu        sync.Mutex
	envelopes [][]byte
}

func (tracer *pageCommitEnvelopeTracer) TraceQueryStart(
	ctx context.Context,
	_ *pgx.Conn,
	data pgx.TraceQueryStartData,
) context.Context {
	if strings.Contains(data.SQL, "UPDATE asset_sources") && len(data.Args) > 4 {
		if envelope, ok := data.Args[4].([]byte); ok && len(envelope) >= 29 &&
			envelope[0] == discoverycheckpoint.CheckpointEnvelopeVersion {
			tracer.mu.Lock()
			tracer.envelopes = append(tracer.envelopes, bytes.Clone(envelope))
			tracer.mu.Unlock()
		}
	}
	return ctx
}

func (*pageCommitEnvelopeTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (tracer *pageCommitEnvelopeTracer) snapshot() [][]byte {
	tracer.mu.Lock()
	defer tracer.mu.Unlock()
	result := make([][]byte, len(tracer.envelopes))
	for index := range tracer.envelopes {
		result[index] = bytes.Clone(tracer.envelopes[index])
	}
	return result
}

func installPageCommitFault(
	t *testing.T,
	harness *assetCatalogHarness,
	table, timing, event, condition string,
) {
	t.Helper()
	execAssetSQL(t, harness.db, `
CREATE FUNCTION m1e_atomic_boundary_fault() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 RAISE EXCEPTION 'm1e-database-canary-secret' USING ERRCODE='55000';
END
$$`)
	query := "CREATE TRIGGER aaa_m1e_atomic_boundary_fault " + timing + " " + event +
		" ON " + pgx.Identifier{table}.Sanitize() + " FOR EACH ROW " + condition +
		" EXECUTE FUNCTION m1e_atomic_boundary_fault()"
	execAssetSQL(t, harness.db, query)
}

func assertExactPageReplay(
	t *testing.T,
	actual discoverysource.PageCommitResult,
	err error,
	committed discoverysource.PageCommitResult,
) {
	t.Helper()
	want := committed
	want.Replayed = true
	if err != nil || actual != want {
		t.Fatalf("exact replay = (%#v,%v), want %#v", actual, err, want)
	}
}

func assertPageCommitError(
	t *testing.T,
	committer *assetpostgres.PageCommitter,
	fence assetcatalog.LeaseFence,
	coordinates discoverysource.PageCommitCoordinates,
	page discoverysource.Page,
	want error,
) {
	t.Helper()
	result, err := committer.ApplyPage(context.Background(), fence, coordinates, page)
	if result != (discoverysource.PageCommitResult{}) || !errors.Is(err, want) || err.Error() != want.Error() {
		t.Fatalf("ApplyPage() = (%#v,%v), want stable %v", result, err, want)
	}
}

func assertUncommittedPageState(t *testing.T, scenario pageCommitScenario) {
	t.Helper()
	assertUncommittedPageStateAt(t, scenario, 0, 0)
}

func assertUncommittedPageStateWithRunCheckpoint(
	t *testing.T,
	scenario pageCommitScenario,
	wantRunCheckpoint int64,
) {
	t.Helper()
	assertUncommittedPageStateAt(t, scenario, 0, wantRunCheckpoint)
}

func assertUncommittedPageStateAt(
	t *testing.T,
	scenario pageCommitScenario,
	wantSourceCheckpoint, wantRunCheckpoint int64,
) {
	t.Helper()
	var observations, pageReceipts, relationReceipts int
	var sourceCheckpoint, runCheckpoint, pageSequence, relationSequence int64
	if err := scenario.harness.db.QueryRow(context.Background(), `
SELECT (SELECT count(*) FROM asset_observations WHERE run_id=$1::uuid),
       (SELECT count(*) FROM audit_records WHERE request_id='source-page:'||$1||':1'),
       (SELECT count(*) FROM audit_records WHERE request_id='source-relation-page:'||$1||':1'),
       source.checkpoint_version,run.checkpoint_version,run.page_sequence,run.relation_page_sequence
FROM asset_sources AS source JOIN asset_source_runs AS run ON run.source_id=source.id
WHERE source.id=$2::uuid AND run.id=$1::uuid
`, scenario.runID, scenario.fixture.sourceID).Scan(
		&observations, &pageReceipts, &relationReceipts,
		&sourceCheckpoint, &runCheckpoint, &pageSequence, &relationSequence,
	); err != nil {
		t.Fatal("read uncommitted page state")
	}
	if observations != 0 || pageReceipts != 0 || relationReceipts != 0 ||
		sourceCheckpoint != wantSourceCheckpoint || runCheckpoint != wantRunCheckpoint ||
		pageSequence != 0 || relationSequence != 0 {
		t.Fatalf("page state mutated: observations=%d receipts=%d/%d checkpoints=%d/%d sequences=%d/%d",
			observations, pageReceipts, relationReceipts, sourceCheckpoint, runCheckpoint, pageSequence, relationSequence)
	}
}

type pageCommitScenario struct {
	harness         *assetCatalogHarness
	fixture         assetCatalogFixture
	repository      *assetpostgres.Repository
	committer       *assetpostgres.PageCommitter
	keyring         *discoverycheckpoint.InMemoryKeyring
	resolver        *pageCommitPolicyResolver
	fence           assetcatalog.LeaseFence
	coordinates     discoverysource.PageCommitCoordinates
	page            discoverysource.Page
	runID           string
	owner           string
	fenceDigest     string
	checkpointBytes []byte
	document        []byte
	master          [32]byte
}

func newPageCommitScenario(t *testing.T, newID func() string) pageCommitScenario {
	t.Helper()
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	fixture = seedClosureExternalValidationOnFixture(t, harness.db, fixture)
	finishClosureExternalValidation(t, harness.db, fixture, 1, strings.Repeat("7", 64))

	runID := "83f00000-0000-4000-8000-000000000011"
	owner := "m1e-page-worker"
	rawFence := [32]byte{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31}
	fenceDigest := sha256.Sum256(rawFence[:])
	startPageCommitRun(t, harness, fixture, runID, owner, hex.EncodeToString(fenceDigest[:]))
	fence, err := leasefence.FromQueueClaim(runID, owner, 1, &rawFence)
	if err != nil {
		t.Fatalf("FromQueueClaim() error = %v", err)
	}

	var master [32]byte
	for index := range master {
		master[index] = byte(index + 1)
	}
	keyring := newPageCommitKeyring(t, "m1e-checkpoint-key-v1", map[string][32]byte{
		"m1e-checkpoint-key-v1": master,
	})
	if newID == nil {
		newID = deterministicAssetIDGenerator()
	}
	repository, err := assetpostgres.New(harness.application, time.Now, newID)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	resolver := &pageCommitPolicyResolver{policy: pageCommitFactPolicy(fixture)}
	committer, err := assetpostgres.NewPageCommitter(repository, keyring, resolver)
	if err != nil {
		t.Fatalf("NewPageCommitter() error = %v", err)
	}

	checkpointBytes := []byte(`{"cursor":"opaque-page-1"}`)
	checkpoint, err := discoverysource.NewCheckpoint("EXTERNAL_V1", checkpointBytes)
	if err != nil {
		t.Fatalf("NewCheckpoint() error = %v", err)
	}
	document := []byte(`{"display_name":"node-a"}`)
	documentDigest := sha256.Sum256(document)
	page := discoverysource.Page{
		Items: []assetdiscovery.NormalizedItem{{
			EnvironmentID:  fixture.environmentID,
			ProviderKind:   "EXTERNAL_V1",
			ExternalID:     "provider-node-a",
			Kind:           assetcatalog.KindCloudResource,
			DisplayName:    "node-a",
			SchemaVersion:  "asset.v1",
			Document:       document,
			DocumentSHA256: hex.EncodeToString(documentDigest[:]),
			Freshness: assetdiscovery.FreshnessCandidate{
				Kind:                  assetcatalog.FreshnessObjectSequence,
				OrderSequence:         1,
				ProviderVersionSHA256: strings.Repeat("1", 64),
			},
			FieldProvenance: pageCommitFieldProvenance(),
		}},
		NextCheckpoint: checkpoint,
	}
	coordinates := discoverysource.PageCommitCoordinates{
		Locator: assetcatalog.SourceLocator{
			Scope: assetcatalog.SourceScope{
				TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID,
			},
			SourceID: fixture.sourceID,
		},
		RunID: runID, PageSequence: 1,
	}
	return pageCommitScenario{
		harness: harness, fixture: fixture, repository: repository, committer: committer,
		keyring: keyring, resolver: resolver, fence: fence, coordinates: coordinates,
		page: page, runID: runID, owner: owner, fenceDigest: hex.EncodeToString(fenceDigest[:]),
		checkpointBytes: checkpointBytes, document: document, master: master,
	}
}

func newPageCommitScenarioForFixture(
	t *testing.T,
	harness *assetCatalogHarness,
	fixture assetCatalogFixture,
	runID, owner string,
	policy assetdiscovery.FactPolicy,
	newID func() string,
) pageCommitScenario {
	t.Helper()
	return newPageCommitScenarioForFixtureWithKey(
		t, harness, fixture, runID, owner, "m1e-first-page-run", policy, newID,
	)
}

func newPageCommitScenarioForFixtureWithKey(
	t *testing.T,
	harness *assetCatalogHarness,
	fixture assetCatalogFixture,
	runID, owner, idempotencyKey string,
	policy assetdiscovery.FactPolicy,
	newID func() string,
) pageCommitScenario {
	t.Helper()
	rawFence := [32]byte{2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32}
	fenceDigest := sha256.Sum256(rawFence[:])
	startPageCommitRunWithKey(
		t, harness, fixture, runID, owner, hex.EncodeToString(fenceDigest[:]), idempotencyKey,
	)
	fence, err := leasefence.FromQueueClaim(runID, owner, 1, &rawFence)
	if err != nil {
		t.Fatal("create page fixture fence")
	}
	var master [32]byte
	for index := range master {
		master[index] = byte(index + 33)
	}
	keyring := newPageCommitKeyring(t, "m1e-checkpoint-key-v1", map[string][32]byte{
		"m1e-checkpoint-key-v1": master,
	})
	if newID == nil {
		newID = deterministicAssetIDGenerator()
	}
	repository, err := assetpostgres.New(harness.application, time.Now, newID)
	if err != nil {
		t.Fatal("create page fixture repository")
	}
	resolver := &pageCommitPolicyResolver{policy: policy}
	committer, err := assetpostgres.NewPageCommitter(repository, keyring, resolver)
	if err != nil {
		t.Fatal("create page fixture committer")
	}
	checkpointBytes := []byte(`{"cursor":"opaque-custom-page-1"}`)
	checkpoint, err := discoverysource.NewCheckpoint("EXTERNAL_V1", checkpointBytes)
	if err != nil {
		t.Fatal("create page fixture checkpoint")
	}
	return pageCommitScenario{
		harness: harness, fixture: fixture, repository: repository, committer: committer,
		keyring: keyring, resolver: resolver, fence: fence,
		coordinates: discoverysource.PageCommitCoordinates{
			Locator: assetcatalog.SourceLocator{
				Scope: assetcatalog.SourceScope{
					TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID,
				},
				SourceID: fixture.sourceID,
			},
			RunID: runID, PageSequence: 1,
		},
		page:            discoverysource.Page{NextCheckpoint: checkpoint},
		runID:           runID,
		owner:           owner,
		fenceDigest:     hex.EncodeToString(fenceDigest[:]),
		checkpointBytes: checkpointBytes,
		master:          master,
	}
}

func seedPublishedExplicitPageCommitSource(
	t *testing.T,
	harness *assetCatalogHarness,
) (assetCatalogFixture, []string) {
	t.Helper()
	fixture := seedDraftAssetCatalog(t, harness.db)
	secondEnvironmentID := "30000000-0000-4000-8000-000000000202"
	environments := []string{fixture.environmentID, secondEnvironmentID}
	slices.Sort(environments)
	fixture.sourceID = "83e00000-0000-4000-8000-000000000001"
	fixture.revisionID = "83e00000-0000-4000-8000-000000000002"
	fixture.validationRunID = "83e00000-0000-4000-8000-000000000003"

	profileText := strings.Replace(
		closureExternalProfileManifestV1,
		`"environment_mapping_mode":"SINGLE_ENVIRONMENT"`,
		`"environment_mapping_mode":"EXPLICIT_ITEM_ENVIRONMENT"`,
		1,
	)
	if profileText == closureExternalProfileManifestV1 {
		t.Fatal("explicit page profile replacement did not occur")
	}
	profile := []byte(profileText)
	providerSchema := []byte(`{"type":"object"}`)
	profileDigest := sha256.Sum256(profile)
	providerSchemaDigest := sha256.Sum256(providerSchema)
	authorityDigest := assetCatalogCorrectiveFramedDigest(
		[]byte("asset-source-authority-scope.v1"), []byte("2"),
		[]byte(environments[0]), []byte(environments[1]),
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
		[]byte(fixture.integrationID), []byte("ON_DEMAND"), []byte("opaque-credential"),
		nil, nil, assetCatalogCorrectiveDecodeDigest(t, authorityDigest),
		[]byte("100"), []byte("60"), []byte("1"), []byte("60"),
		[]byte("EXTERNAL_V1"), nil, nil, nil,
	)

	tx, err := harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatal("begin explicit page source definition")
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	execAssetSQL(t, tx, `
INSERT INTO environments (id,tenant_id,workspace_id,name,kind)
VALUES ($1,$2,$3,'fixture-explicit','STAGING')
`, secondEnvironmentID, fixture.tenantID, fixture.workspaceID)
	execAssetSQL(t, tx, `
INSERT INTO asset_sources (
 id,tenant_id,workspace_id,source_kind,provider_kind,name,
 create_idempotency_key,create_request_hash
) VALUES ($1,$2,$3,'EXTERNAL_CMDB','EXTERNAL_V1','m1e explicit source',
          'm1e-explicit-source',repeat('1',64))
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
         'opaque-credential',100,60,1,60,'EXTERNAL_V1','m1e-test','INITIAL_CREATE',source.version
  FROM asset_sources AS source WHERE source.id=$4
`, fixture.revisionID, fixture.tenantID, fixture.workspaceID, fixture.sourceID,
		profile, hex.EncodeToString(profileDigest[:]), providerSchema,
		hex.EncodeToString(providerSchemaDigest[:]), fixture.integrationID,
		authorityDigest, fixture.sourceDefinitionDigest, fixture.revisionDigest)
	execAssetSQL(t, tx, `
INSERT INTO asset_source_revision_authorities (
 tenant_id,workspace_id,source_id,source_revision,environment_id,canonical_ordinal
) VALUES ($1,$2,$3,1,$4,1),($1,$2,$3,1,$5,2)
`, fixture.tenantID, fixture.workspaceID, fixture.sourceID, environments[0], environments[1])
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatal("commit explicit page source definition")
	}

	execAssetSQL(t, harness.db, `
INSERT INTO asset_source_runs (
 id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
 run_kind,trigger_type,gate_revision,idempotency_key,request_hash,checkpoint_version
) SELECT $1,$2,$3,$4,1,$5,'VALIDATION','HUMAN',gate_revision,
         'm1e-explicit-validation',repeat('5',64),0
  FROM asset_sources WHERE id=$4
`, fixture.validationRunID, fixture.tenantID, fixture.workspaceID,
		fixture.sourceID, fixture.revisionDigest)
	execAssetSQL(t, harness.db, `
UPDATE asset_source_revisions
SET state='VALIDATING',validation_run_id=$2,version=version+1 WHERE id=$1
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
SET status='RUNNING',stage_code='VALIDATING',lease_owner='m1e-explicit-validation-worker',
    lease_expires_at=statement_timestamp()+interval '10 minutes',fence_epoch=1,
    fence_token_hash=repeat('6',64),heartbeat_sequence=1,
    heartbeat_at=statement_timestamp(),version=version+1
WHERE id=$1
`, fixture.validationRunID)
	finishClosureExternalValidation(t, harness.db, fixture, 1, strings.Repeat("7", 64))
	return fixture, environments
}

func newPageCommitKeyring(
	t *testing.T,
	active string,
	retained map[string][32]byte,
) *discoverycheckpoint.InMemoryKeyring {
	t.Helper()
	keyring, err := discoverycheckpoint.NewInMemoryKeyring(active, retained)
	if err != nil {
		t.Fatalf("NewInMemoryKeyring() error = %v", err)
	}
	return keyring
}

func startPageCommitRun(
	t *testing.T,
	harness *assetCatalogHarness,
	fixture assetCatalogFixture,
	runID, owner, fenceDigest string,
) {
	t.Helper()
	startPageCommitRunWithKey(t, harness, fixture, runID, owner, fenceDigest, "m1e-first-page-run")
}

func startPageCommitRunWithKey(
	t *testing.T,
	harness *assetCatalogHarness,
	fixture assetCatalogFixture,
	runID, owner, fenceDigest, idempotencyKey string,
) {
	t.Helper()
	var (
		revision, gateRevision, checkpointVersion int64
		revisionDigest                            string
		checkpointSHA                             *string
	)
	if err := harness.db.QueryRow(context.Background(), `
		SELECT published_revision,published_revision_digest,gate_revision,
		       checkpoint_version,checkpoint_sha256
		FROM asset_sources WHERE id=$1
	`, fixture.sourceID).Scan(
		&revision, &revisionDigest, &gateRevision, &checkpointVersion, &checkpointSHA,
	); err != nil {
		t.Fatalf("read page commit source: %v", err)
	}
	execAssetSQL(t, harness.db, `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,trigger_type,gate_revision,idempotency_key,request_hash,
			cursor_before_sha256,checkpoint_version
			) VALUES ($1,$2,$3,$4,$5,$6,'DISCOVERY','SCHEDULED',$7,
				$10,repeat('4',64),$8,$9)
		`, runID, fixture.tenantID, fixture.workspaceID, fixture.sourceID, revision,
		revisionDigest, gateRevision, checkpointSHA, checkpointVersion, idempotencyKey)
	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs
		SET status='RUNNING',stage_code='READING',lease_owner=$2,
			lease_expires_at=statement_timestamp()+interval '10 minutes',fence_epoch=1,
			fence_token_hash=$3,heartbeat_sequence=1,
			heartbeat_at=statement_timestamp(),version=version+1
		WHERE id=$1
	`, runID, owner, fenceDigest)
	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs SET stage_code='NORMALIZING',version=version+1 WHERE id=$1
	`, runID)
}

func finishPageCommitRunForTest(
	t *testing.T,
	harness *assetCatalogHarness,
	fixture assetCatalogFixture,
	runID string,
) {
	t.Helper()
	revokeClosureAttempt(t, harness.db, fixture, runID, strings.Repeat("c", 64))
	tx, err := harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatal("begin page test terminal closure")
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	terminalDigest := sourceRunTerminalDigest(t, tx, runID, "SUCCEEDED", nil)
	insertTerminalAudit(t, tx, fixture, runID, terminalDigest)
	execAssetSQL(t, tx, `
UPDATE asset_source_runs
SET status='SUCCEEDED',stage_code='COMPLETED',terminal_command_sha256=$2,
    completed_at=statement_timestamp(),
    version=version+1
WHERE id=$1
`, runID, terminalDigest)
	execAssetSQL(t, tx, `
UPDATE asset_sources AS source
SET last_success_run_id=run.id,
    last_success_at=run.completed_at,
    last_complete_snapshot_run_id=CASE
      WHEN run.effective_complete_snapshot THEN run.id
      ELSE source.last_complete_snapshot_run_id
    END,
    last_complete_snapshot_at=CASE
      WHEN run.effective_complete_snapshot THEN run.completed_at
      ELSE source.last_complete_snapshot_at
    END,
    version=source.version+1
FROM asset_source_runs AS run
WHERE source.id=$1 AND run.id=$2
`, fixture.sourceID, runID)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit page test terminal closure: %v", err)
	}
}

type pageCommitPolicyResolver struct {
	policy                      assetdiscovery.FactPolicy
	pageCalls                   int
	crossEnvironmentCalls       int
	crossEnvironmentID          assetcatalog.PolicyReferenceID
	pageErr, crossErr           error
	pageRevisions               []assetcatalog.SourceRevision
	crossEnvironmentRevisions   []assetcatalog.SourceRevision
	crossEnvironmentCoordinates []discoverysource.CrossEnvironmentRelationPolicyCoordinates
}

func (resolver *pageCommitPolicyResolver) ResolvePageFactPolicy(
	_ context.Context,
	revision assetcatalog.SourceRevision,
) (assetdiscovery.FactPolicy, error) {
	resolver.pageCalls++
	resolver.pageRevisions = append(resolver.pageRevisions, revision.Clone())
	if resolver.pageErr != nil {
		return assetdiscovery.FactPolicy{}, resolver.pageErr
	}
	return resolver.policy.Clone(), nil
}

func (resolver *pageCommitPolicyResolver) ResolveCrossEnvironmentRelationPolicy(
	_ context.Context,
	revision assetcatalog.SourceRevision,
	coordinates discoverysource.CrossEnvironmentRelationPolicyCoordinates,
) (assetcatalog.PolicyReferenceID, error) {
	resolver.crossEnvironmentCalls++
	resolver.crossEnvironmentRevisions = append(resolver.crossEnvironmentRevisions, revision.Clone())
	resolver.crossEnvironmentCoordinates = append(resolver.crossEnvironmentCoordinates, coordinates)
	if resolver.crossErr != nil {
		return "", resolver.crossErr
	}
	return resolver.crossEnvironmentID, nil
}

func pageCommitFactPolicy(fixture assetCatalogFixture) assetdiscovery.FactPolicy {
	return assetdiscovery.FactPolicy{
		ProviderKind:            "EXTERNAL_V1",
		FreshnessKind:           assetcatalog.FreshnessObjectSequence,
		EnvironmentMapping:      assetcatalog.EnvironmentMappingSingle,
		AuthorityEnvironmentIDs: []string{fixture.environmentID},
		TrustedPathCodes:        []string{"DISPLAY_NAME", "EXTERNAL_ID", "KIND"},
		RelationshipTypes:       []assetcatalog.RelationshipType{assetcatalog.RelationshipDependsOn},
		AllowedDocumentFields: map[assetcatalog.Kind][]string{
			assetcatalog.KindCloudResource: {"display_name"},
		},
	}
}

func pageCommitFieldProvenance() []assetdiscovery.FieldProvenance {
	return []assetdiscovery.FieldProvenance{
		{FieldCode: "display_name", ProviderPathCode: "DISPLAY_NAME", Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100},
		{FieldCode: "environment_id", ProviderPathCode: "EXTERNAL_ID", Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100},
		{FieldCode: "external_id", ProviderPathCode: "EXTERNAL_ID", Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100},
		{FieldCode: "kind", ProviderPathCode: "KIND", Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100},
		{FieldCode: "provider_kind", ProviderPathCode: "KIND", Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100},
		{FieldCode: "type_details", ProviderPathCode: "KIND", Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100},
	}
}

func pageCommitTombstoneProvenance() []assetdiscovery.FieldProvenance {
	return []assetdiscovery.FieldProvenance{
		{FieldCode: "environment_id", ProviderPathCode: "EXTERNAL_ID", Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100},
		{FieldCode: "external_id", ProviderPathCode: "EXTERNAL_ID", Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100},
		{FieldCode: "provider_kind", ProviderPathCode: "KIND", Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100},
	}
}

func pageCommitFingerprintDigest(t *testing.T, code, value string) string {
	t.Helper()
	valueDigest := assetCatalogCorrectiveFramedDigest(
		[]byte("asset-fingerprint-value.v1"), []byte(code), []byte(value),
	)
	return assetCatalogCorrectiveFramedDigest(
		[]byte("asset-fingerprints.v1"), []byte("1"), []byte(code),
		assetCatalogCorrectiveDecodeDigest(t, valueDigest),
	)
}

func TestPageCommitterConstructorFailsClosed(t *testing.T) {
	if _, err := assetpostgres.NewPageCommitter(nil, nil, nil); !errors.Is(err, discoverysource.ErrPageCommitUnavailable) {
		t.Fatalf("NewPageCommitter(nil) error = %v, want ErrPageCommitUnavailable", err)
	}
}

func TestPageCommitterRuntimeReadsImmutableAuthoritiesWithoutChildRowLockIntegration(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	fixture = seedClosureExternalValidationOnFixture(t, harness.db, fixture)
	finishClosureExternalValidation(t, harness.db, fixture, 1, strings.Repeat("7", 64))
	ctx := context.Background()

	rows, err := harness.application.Query(ctx, `
SELECT environment_id::text,canonical_ordinal
FROM asset_source_revision_authorities
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
  AND source_id=$3::uuid AND source_revision=1
ORDER BY canonical_ordinal,environment_id
`, fixture.tenantID, fixture.workspaceID, fixture.sourceID)
	if err != nil {
		t.Fatal("runtime canonical authority read failed")
	}
	defer rows.Close()
	var environmentID string
	var ordinal int
	if !rows.Next() || rows.Scan(&environmentID, &ordinal) != nil || rows.Next() || rows.Err() != nil {
		t.Fatal("runtime canonical authority read did not return one exact row")
	}
	if environmentID != fixture.environmentID || ordinal != 1 {
		t.Fatalf("runtime authority closure = (%q,%d), want exact fixture closure", environmentID, ordinal)
	}

	_, err = harness.application.Exec(ctx, `
SELECT environment_id
FROM asset_source_revision_authorities
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
  AND source_id=$3::uuid AND source_revision=1
ORDER BY canonical_ordinal,environment_id
FOR SHARE
`, fixture.tenantID, fixture.workspaceID, fixture.sourceID)
	var sqlState interface{ SQLState() string }
	if !errors.As(err, &sqlState) || sqlState.SQLState() != "42501" {
		t.Fatalf("runtime child FOR SHARE SQLSTATE = %q, want 42501", pageCommitSQLState(err))
	}
}

func TestPageCommitterPublishedRevisionLockRejectsConcurrentAuthorityAppendIntegration(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	fixture = seedClosureExternalValidationOnFixture(t, harness.db, fixture)
	finishClosureExternalValidation(t, harness.db, fixture, 1, strings.Repeat("7", 64))
	secondEnvironmentID := "30000000-0000-4000-8000-000000000202"
	execAssetSQL(t, harness.db, `
INSERT INTO environments (id,tenant_id,workspace_id,name,kind)
VALUES ($1,$2,$3,'fixture-dr','STAGING')
`, secondEnvironmentID, fixture.tenantID, fixture.workspaceID)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reader, err := harness.application.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatal("begin authority reader transaction")
	}
	defer func() { _ = reader.Rollback(context.Background()) }()
	var revisionState string
	if err := reader.QueryRow(ctx, `
SELECT state FROM asset_source_revisions
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
  AND source_id=$3::uuid AND revision=1
FOR SHARE
`, fixture.tenantID, fixture.workspaceID, fixture.sourceID).Scan(&revisionState); err != nil || revisionState != "PUBLISHED" {
		t.Fatal("reader did not lock the exact published revision")
	}
	before := readPageCommitAuthorities(t, ctx, reader, fixture)

	writer, err := harness.application.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatal("begin concurrent authority writer transaction")
	}
	if _, err := writer.Exec(ctx, `
INSERT INTO asset_source_revision_authorities (
 tenant_id,workspace_id,source_id,source_revision,environment_id,canonical_ordinal
) VALUES ($1,$2,$3,1,$4,2)
`, fixture.tenantID, fixture.workspaceID, fixture.sourceID, secondEnvironmentID); err != nil {
		_ = writer.Rollback(ctx)
		t.Fatalf("concurrent append failed before deferred parent guard, SQLSTATE=%q", pageCommitSQLState(err))
	}
	commitErr := writer.Commit(ctx)
	var postgresError *pgconn.PgError
	if !errors.As(commitErr, &postgresError) || postgresError.Code != "55000" ||
		postgresError.ConstraintName != "asset_source_revision_authorities_parent_guard" {
		t.Fatalf("concurrent append commit = SQLSTATE %q constraint %q, want parent guard",
			pageCommitSQLState(commitErr), pageCommitConstraint(commitErr))
	}
	after := readPageCommitAuthorities(t, ctx, reader, fixture)
	if strings.Join(before, "|") != strings.Join(after, "|") {
		t.Fatalf("reader authority snapshot drifted: before=%v after=%v", before, after)
	}
	if err := reader.Commit(ctx); err != nil {
		t.Fatalf("commit unchanged authority reader: SQLSTATE=%q", pageCommitSQLState(err))
	}
	var persisted int
	if err := harness.db.QueryRow(ctx, `
SELECT count(*) FROM asset_source_revision_authorities
WHERE source_id=$1::uuid AND source_revision=1
`, fixture.sourceID).Scan(&persisted); err != nil || persisted != 1 {
		t.Fatalf("rolled-back concurrent authority count = %d, want 1", persisted)
	}
}

func TestPageCommitterPublishedAuthorityClosureIsImmutableIntegration(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	fixture = seedClosureExternalValidationOnFixture(t, harness.db, fixture)
	finishClosureExternalValidation(t, harness.db, fixture, 1, strings.Repeat("7", 64))
	ctx := context.Background()
	before := readPageCommitAuthorityClosureSnapshot(t, ctx, harness.db, fixture)

	mutations := []struct {
		name       string
		query      string
		constraint string
		arguments  []any
	}{
		{
			name: "update", constraint: "asset_source_revision_authorities_immutable",
			query:     `UPDATE asset_source_revision_authorities SET canonical_ordinal=canonical_ordinal WHERE source_id=$1::uuid`,
			arguments: []any{fixture.sourceID},
		},
		{
			name: "delete", constraint: "asset_source_revision_authorities_delete_guard",
			query:     `DELETE FROM asset_source_revision_authorities WHERE source_id=$1::uuid`,
			arguments: []any{fixture.sourceID},
		},
		{
			name: "truncate", constraint: "asset_source_revision_authorities_truncate_guard",
			query: `TRUNCATE TABLE asset_source_revision_authorities`,
		},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			if _, err := harness.application.Exec(ctx, mutation.query, mutation.arguments...); pageCommitSQLState(err) != "42501" {
				t.Fatalf("runtime published authority %s SQLSTATE = %q, want 42501",
					mutation.name, pageCommitSQLState(err))
			}
			_, err := harness.db.Exec(ctx, mutation.query, mutation.arguments...)
			var postgresError *pgconn.PgError
			if !errors.As(err, &postgresError) || postgresError.Code != "55000" ||
				postgresError.ConstraintName != mutation.constraint {
				t.Fatalf("published authority %s = SQLSTATE %q constraint %q, want immutable guard",
					mutation.name, pageCommitSQLState(err), pageCommitConstraint(err))
			}
			if after := readPageCommitAuthorityClosureSnapshot(t, ctx, harness.db, fixture); after != before {
				t.Fatalf("authority closure changed after rejected %s: before=%q after=%q", mutation.name, before, after)
			}
		})
	}
}

func readPageCommitAuthorityClosureSnapshot(
	t *testing.T,
	ctx context.Context,
	database interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	},
	fixture assetCatalogFixture,
) string {
	t.Helper()
	var count int
	var ordered, digest string
	if err := database.QueryRow(ctx, `
SELECT count(*),string_agg(authority.environment_id::text||':'||authority.canonical_ordinal::text,','
                          ORDER BY authority.canonical_ordinal,authority.environment_id),
       revision.authority_scope_digest
FROM asset_source_revisions AS revision
JOIN asset_source_revision_authorities AS authority
  ON authority.tenant_id=revision.tenant_id AND authority.workspace_id=revision.workspace_id
 AND authority.source_id=revision.source_id AND authority.source_revision=revision.revision
WHERE revision.tenant_id=$1::uuid AND revision.workspace_id=$2::uuid
  AND revision.source_id=$3::uuid AND revision.revision=1
GROUP BY revision.authority_scope_digest
`, fixture.tenantID, fixture.workspaceID, fixture.sourceID).Scan(&count, &ordered, &digest); err != nil {
		t.Fatal("read authority closure snapshot")
	}
	expectedDigest := assetCatalogCorrectiveFramedDigest(
		[]byte("asset-source-authority-scope.v1"), []byte("1"), []byte(fixture.environmentID),
	)
	if count != 1 || ordered != fixture.environmentID+":1" || digest != expectedDigest {
		t.Fatalf("authority closure snapshot is not exact: count=%d ordered=%q digest-match=%t",
			count, ordered, digest == expectedDigest)
	}
	return strconv.Itoa(count) + "|" + ordered + "|" + digest
}

func readPageCommitAuthorities(
	t *testing.T,
	ctx context.Context,
	database interface {
		Query(context.Context, string, ...any) (pgx.Rows, error)
	},
	fixture assetCatalogFixture,
) []string {
	t.Helper()
	rows, err := database.Query(ctx, `
SELECT environment_id::text,canonical_ordinal
FROM asset_source_revision_authorities
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
  AND source_id=$3::uuid AND source_revision=1
ORDER BY canonical_ordinal,environment_id
`, fixture.tenantID, fixture.workspaceID, fixture.sourceID)
	if err != nil {
		t.Fatal("read canonical authority closure")
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var environmentID string
		var ordinal int
		if err := rows.Scan(&environmentID, &ordinal); err != nil {
			t.Fatal("scan canonical authority closure")
		}
		result = append(result, environmentID+":"+strconv.Itoa(ordinal))
	}
	if rows.Err() != nil {
		t.Fatal("iterate canonical authority closure")
	}
	return result
}

func pageCommitSQLState(err error) string {
	var sqlState interface{ SQLState() string }
	if errors.As(err, &sqlState) {
		return sqlState.SQLState()
	}
	return ""
}

func pageCommitConstraint(err error) string {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		return postgresError.ConstraintName
	}
	return ""
}

func TestExternalCMDBTask18BPageAtomicFaultsPostgres(t *testing.T) {
	requireExternalCMDBTask18BPostgres(t)
	tests := []struct {
		name      string
		table     string
		timing    string
		event     string
		condition string
	}{
		{name: "asset projection", table: "asset_observations", timing: "BEFORE", event: "INSERT"},
		{name: "relation projection", table: "asset_relationships", timing: "BEFORE", event: "INSERT"},
		{
			name: "page receipt", table: "audit_records", timing: "BEFORE", event: "INSERT",
			condition: "WHEN (NEW.action='PAGE_APPLIED')",
		},
		{
			name: "relation receipt", table: "audit_records", timing: "BEFORE", event: "INSERT",
			condition: "WHEN (NEW.action='RELATION_PAGE_COMMITTED')",
		},
		{
			name: "checkpoint", table: "asset_sources", timing: "BEFORE", event: "UPDATE",
			condition: "WHEN (NEW.checkpoint_version > OLD.checkpoint_version)",
		},
		{
			name: "work result", table: "asset_source_runs", timing: "BEFORE", event: "UPDATE",
			condition: "WHEN (NEW.work_result_kind IS NOT NULL AND OLD.work_result_kind IS NULL)",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newAssetCatalogHarness(t)
			harness.applyThroughAssetCatalog(t)
			assertExternalCMDBTask18BPostgresTLS(t, harness)
			fixture := seedExternalCMDBTask18BPublishedSource(t, harness)
			scenario := newExternalCMDBTask18BPageScenario(
				t, harness, fixture, uuid.NewString(), "task18b-atomic-worker",
			)
			scenario.page = externalCMDBTask18BCompletePage(
				t, fixture.environmentID, 1, scenario.page.NextCheckpoint,
			)
			reserveExternalCMDBTask18BCleanup(t, harness.db, scenario.runID)
			installPageCommitFault(
				t, scenario.harness, test.table, test.timing, test.event, test.condition,
			)

			result, err := scenario.committer.ApplyPage(
				t.Context(), scenario.fence, scenario.coordinates, scenario.page,
			)
			if result != (discoverysource.PageCommitResult{}) ||
				!errors.Is(err, discoverysource.ErrPageCommitUnavailable) ||
				err.Error() != discoverysource.ErrPageCommitUnavailable.Error() {
				t.Fatalf("faulted CMDB ApplyPage() = (%#v,%v)", result, err)
			}
			assertExternalCMDBTask18BPageState(t, scenario, 0, 0, 0, 0, 0)
		})
	}
}

func TestExternalCMDBTask18BPageReplayChangedDigestAndOneTransactionPostgres(t *testing.T) {
	requireExternalCMDBTask18BPostgres(t)
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	assertExternalCMDBTask18BPostgresTLS(t, harness)
	fixture := seedExternalCMDBTask18BPublishedSource(t, harness)
	scenario := newExternalCMDBTask18BPageScenario(
		t, harness, fixture, uuid.NewString(), "task18b-replay-worker",
	)
	scenario.page = externalCMDBTask18BCompletePage(
		t, fixture.environmentID, 1, scenario.page.NextCheckpoint,
	)
	reserveExternalCMDBTask18BCleanup(t, harness.db, scenario.runID)
	committed, err := scenario.committer.ApplyPage(
		t.Context(), scenario.fence, scenario.coordinates, scenario.page,
	)
	if err != nil || committed.Replayed || !committed.FinalPage ||
		!committed.CompleteSnapshot {
		t.Fatalf("initial CMDB ApplyPage() = (%#v,%v)", committed, err)
	}
	assertExternalCMDBTask18BPageState(t, scenario, 2, 1, 1, 1, 1)
	replayed, err := scenario.committer.ApplyPage(
		t.Context(), scenario.fence, scenario.coordinates, scenario.page,
	)
	assertExactPageReplay(t, replayed, err, committed)

	tests := []struct {
		name   string
		change func(*testing.T, *discoverysource.Page)
	}{
		{name: "item", change: func(_ *testing.T, page *discoverysource.Page) {
			page.Items = append([]assetdiscovery.NormalizedItem(nil), page.Items...)
			page.Items[0].DisplayName = "changed-name"
		}},
		{name: "relation", change: func(_ *testing.T, page *discoverysource.Page) {
			page.Relations = append([]assetdiscovery.ObservedRelation(nil), page.Relations...)
			page.Relations[0].Type = assetcatalog.RelationshipManagedBy
		}},
		{name: "checkpoint", change: func(t *testing.T, page *discoverysource.Page) {
			t.Helper()
			var err error
			page.NextCheckpoint, err = discoverysource.NewCheckpoint(
				"CMDB_CATALOG_V1", []byte(`{"changed":"checkpoint"}`),
			)
			if err != nil {
				t.Fatalf("changed checkpoint: %v", err)
			}
		}},
		{name: "final flag", change: func(_ *testing.T, page *discoverysource.Page) {
			page.FinalPage = false
			page.CompleteSnapshot = false
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := cloneExternalCMDBTask18BPage(scenario.page)
			test.change(t, &changed)
			assertPageCommitError(
				t, scenario.committer, scenario.fence, scenario.coordinates,
				changed, discoverysource.ErrPageCommitConflict,
			)
			assertExternalCMDBTask18BPageState(t, scenario, 2, 1, 1, 1, 1)
		})
	}
}

func TestExternalCMDBTask18BCompleteOnlyMissingAndTombstoneRestorePostgres(t *testing.T) {
	requireExternalCMDBTask18BPostgres(t)
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	assertExternalCMDBTask18BPostgresTLS(t, harness)
	fixture := seedExternalCMDBTask18BPublishedSource(t, harness)

	initial := newExternalCMDBTask18BPageScenario(
		t, harness, fixture, uuid.NewString(), "task18b-initial-worker",
	)
	initial.page = externalCMDBTask18BCompletePage(
		t, fixture.environmentID, 1, initial.page.NextCheckpoint,
	)
	reserveExternalCMDBTask18BCleanup(t, harness.db, initial.runID)
	if _, err := initial.committer.ApplyPage(
		t.Context(), initial.fence, initial.coordinates, initial.page,
	); err != nil {
		t.Fatalf("initial complete CMDB page: %v", err)
	}
	finishPageCommitRunForTest(t, harness, fixture, initial.runID)
	execAssetSQL(t, harness.db, `
UPDATE assets SET lifecycle='ACTIVE',version=version+1 WHERE source_id=$1::uuid
`, fixture.sourceID)

	partial := newExternalCMDBTask18BPageScenario(
		t, harness, fixture, uuid.NewString(), "task18b-partial-worker",
	)
	partial.page = discoverysource.Page{
		Items: []assetdiscovery.NormalizedItem{
			externalCMDBTask18BLiveItem(t, fixture.environmentID, "cmdb-host-a", "host-a", 2),
		},
		NextCheckpoint: partial.page.NextCheckpoint,
		FinalPage:      true,
	}
	reserveExternalCMDBTask18BCleanup(t, harness.db, partial.runID)
	if _, err := partial.committer.ApplyPage(
		t.Context(), partial.fence, partial.coordinates, partial.page,
	); err != nil {
		t.Fatalf("partial CMDB page: %v", err)
	}
	assertExternalCMDBTask18BNoImplicitMissing(t, harness, fixture, partial.runID)
	finishPageCommitRunForTest(t, harness, fixture, partial.runID)

	tombstone := newExternalCMDBTask18BPageScenario(
		t, harness, fixture, uuid.NewString(), "task18b-tombstone-worker",
	)
	tombstone.page = discoverysource.Page{
		Items: []assetdiscovery.NormalizedItem{
			externalCMDBTask18BTombstone(
				fixture.environmentID, "cmdb-host-b", 3, "PROVIDER_DELETED",
			),
		},
		NextCheckpoint: tombstone.page.NextCheckpoint,
		FinalPage:      true,
	}
	reserveExternalCMDBTask18BCleanup(t, harness.db, tombstone.runID)
	if _, err := tombstone.committer.ApplyPage(
		t.Context(), tombstone.fence, tombstone.coordinates, tombstone.page,
	); err != nil {
		t.Fatalf("fixed-wire tombstone CMDB page: %v", err)
	}
	var lifecycle, relationStatus string
	var tombstoned, stale int64
	if err := harness.db.QueryRow(t.Context(), `
SELECT asset.lifecycle,relationship.status,run.tombstoned_count,run.stale_count
FROM assets AS asset
JOIN asset_relationships AS relationship
  ON relationship.source_id=asset.source_id AND relationship.target_asset_id=asset.id
JOIN asset_source_runs AS run ON run.id=$2::uuid
WHERE asset.source_id=$1::uuid AND asset.external_id='cmdb-host-b'
`, fixture.sourceID, tombstone.runID).Scan(
		&lifecycle, &relationStatus, &tombstoned, &stale,
	); err != nil {
		t.Fatalf("read CMDB tombstone projection: %v", err)
	}
	if lifecycle != "STALE" || relationStatus != "INACTIVE" || tombstoned != 1 || stale != 1 {
		t.Fatalf("CMDB tombstone projection = %s/%s %d/%d", lifecycle, relationStatus, tombstoned, stale)
	}
	finishPageCommitRunForTest(t, harness, fixture, tombstone.runID)

	restore := newExternalCMDBTask18BPageScenario(
		t, harness, fixture, uuid.NewString(), "task18b-restore-worker",
	)
	restore.page = discoverysource.Page{
		Items: []assetdiscovery.NormalizedItem{
			externalCMDBTask18BLiveItem(t, fixture.environmentID, "cmdb-host-b", "host-b", 4),
		},
		NextCheckpoint: restore.page.NextCheckpoint,
		FinalPage:      true,
	}
	reserveExternalCMDBTask18BCleanup(t, harness.db, restore.runID)
	if _, err := restore.committer.ApplyPage(
		t.Context(), restore.fence, restore.coordinates, restore.page,
	); err != nil {
		t.Fatalf("CMDB restore page: %v", err)
	}
	var restored, restoreAudit, restoreOutbox int64
	if err := harness.db.QueryRow(t.Context(), `
SELECT asset.lifecycle,run.restored_count,
       (SELECT count(*) FROM audit_records
        WHERE resource_id=asset.id::text AND action='asset.source.asset.restored.v1'),
       (SELECT count(*) FROM outbox_events
        WHERE aggregate_id=asset.id AND event_type='asset.source.asset.restored.v1')
FROM assets AS asset JOIN asset_source_runs AS run ON run.id=$2::uuid
WHERE asset.source_id=$1::uuid AND asset.external_id='cmdb-host-b'
`, fixture.sourceID, restore.runID).Scan(
		&lifecycle, &restored, &restoreAudit, &restoreOutbox,
	); err != nil {
		t.Fatalf("read CMDB restore projection: %v", err)
	}
	if lifecycle != "STALE" || restored != 1 || restoreAudit != 1 || restoreOutbox != 1 {
		t.Fatalf("CMDB restore projection = %s restored=%d evidence=%d/%d",
			lifecycle, restored, restoreAudit, restoreOutbox)
	}
	finishPageCommitRunForTest(t, harness, fixture, restore.runID)

	complete := newExternalCMDBTask18BPageScenario(
		t, harness, fixture, uuid.NewString(), "task18b-complete-worker",
	)
	complete.page = discoverysource.Page{
		Items: []assetdiscovery.NormalizedItem{
			externalCMDBTask18BLiveItem(t, fixture.environmentID, "cmdb-host-a", "host-a", 5),
		},
		NextCheckpoint:   complete.page.NextCheckpoint,
		FinalPage:        true,
		CompleteSnapshot: true,
	}
	reserveExternalCMDBTask18BCleanup(t, harness.db, complete.runID)
	if _, err := complete.committer.ApplyPage(
		t.Context(), complete.fence, complete.coordinates, complete.page,
	); err != nil {
		t.Fatalf("complete-only missing CMDB page: %v", err)
	}
	var effective bool
	var missing int64
	if err := harness.db.QueryRow(t.Context(), `
SELECT effective_complete_snapshot,missing_count,stale_count
FROM asset_source_runs WHERE id=$1::uuid
`, complete.runID).Scan(&effective, &missing, &stale); err != nil {
		t.Fatalf("read CMDB complete closure: %v", err)
	}
	if !effective || missing != 1 || stale != 0 {
		t.Fatalf("complete-only missing closure effective=%t missing/stale=%d/%d",
			effective, missing, stale)
	}
}

func TestExternalCMDBTask18BRejectedItemSuppressesImplicitMissingPostgres(t *testing.T) {
	requireExternalCMDBTask18BPostgres(t)
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	assertExternalCMDBTask18BPostgresTLS(t, harness)
	fixture := seedExternalCMDBTask18BPublishedSource(t, harness)

	initial := newExternalCMDBTask18BPageScenario(
		t, harness, fixture, uuid.NewString(), "task18b-rejected-initial-worker",
	)
	initial.page = externalCMDBTask18BCompletePage(
		t, fixture.environmentID, 1, initial.page.NextCheckpoint,
	)
	reserveExternalCMDBTask18BCleanup(t, harness.db, initial.runID)
	if _, err := initial.committer.ApplyPage(
		t.Context(), initial.fence, initial.coordinates, initial.page,
	); err != nil {
		t.Fatalf("initial rejected-item CMDB page: %v", err)
	}
	finishPageCommitRunForTest(t, harness, fixture, initial.runID)
	execAssetSQL(t, harness.db, `
UPDATE assets SET lifecycle='ACTIVE',version=version+1 WHERE source_id=$1::uuid
`, fixture.sourceID)

	rejected := newExternalCMDBTask18BPageScenario(
		t, harness, fixture, uuid.NewString(), "task18b-rejected-worker",
	)
	unknownTombstone := externalCMDBTask18BTombstone(
		fixture.environmentID, "cmdb-host-unknown", 2, "PROVIDER_DELETED",
	)
	rejected.page = discoverysource.Page{
		Items:            []assetdiscovery.NormalizedItem{unknownTombstone},
		NextCheckpoint:   rejected.page.NextCheckpoint,
		FinalPage:        true,
		CompleteSnapshot: true,
	}
	reserveExternalCMDBTask18BCleanup(t, harness.db, rejected.runID)
	result, err := rejected.committer.ApplyPage(
		t.Context(), rejected.fence, rejected.coordinates, rejected.page,
	)
	if err != nil || !result.FinalPage || !result.CompleteSnapshot {
		t.Fatalf("rejected-item CMDB ApplyPage() = (%#v,%v)", result, err)
	}
	var workStatus string
	var rejectedCount, conflicts, missing, stale, activeAssets, activeRelations int64
	var effective bool
	if err := harness.db.QueryRow(t.Context(), `
SELECT work_result_status,rejected_count,conflict_count,missing_count,stale_count,
       effective_complete_snapshot,
       (SELECT count(*) FROM assets
        WHERE source_id=$2::uuid AND lifecycle='ACTIVE'),
       (SELECT count(*) FROM asset_relationships
        WHERE source_id=$2::uuid AND status='ACTIVE')
FROM asset_source_runs WHERE id=$1::uuid
`, rejected.runID, fixture.sourceID).Scan(
		&workStatus, &rejectedCount, &conflicts, &missing, &stale, &effective,
		&activeAssets, &activeRelations,
	); err != nil {
		t.Fatalf("read rejected-item CMDB closure: %v", err)
	}
	if workStatus != "PARTIAL" || rejectedCount != 1 || conflicts != 0 ||
		missing != 1 || stale != 0 || effective ||
		activeAssets != 2 || activeRelations != 1 {
		t.Fatalf("rejected-item closure status=%s rejected/conflict=%d/%d missing/stale=%d/%d effective=%t active=%d/%d",
			workStatus, rejectedCount, conflicts, missing, stale, effective,
			activeAssets, activeRelations)
	}
}

func requireExternalCMDBTask18BPostgres(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"AIOPS_TEST_POSTGRES_DSN",
		"AIOPS_TEST_POSTGRES_MIGRATION_DSN",
		"AIOPS_TEST_POSTGRES_APPLICATION_DSN",
	} {
		if strings.TrimSpace(os.Getenv(name)) == "" {
			t.Fatalf("%s is required; Task 18B PostgreSQL tests may not skip", name)
		}
	}
}

func assertExternalCMDBTask18BPostgresTLS(
	t *testing.T,
	harness *assetCatalogHarness,
) {
	t.Helper()
	type expectedPool struct {
		name     string
		pool     *pgxpool.Pool
		identity string
	}
	pools := []expectedPool{
		{name: "migration", pool: harness.migration, identity: "aiops_migrator"},
		{name: "application", pool: harness.application, identity: "aiops_control_plane_workload"},
	}
	for _, candidate := range pools {
		var version int
		var sessionUser, currentUser, tlsVersion string
		var ssl bool
		if err := candidate.pool.QueryRow(t.Context(), `
SELECT current_setting('server_version_num')::integer,session_user,current_user,
       ssl,version
FROM pg_stat_ssl WHERE pid=pg_backend_pid()
`).Scan(&version, &sessionUser, &currentUser, &ssl, &tlsVersion); err != nil {
			t.Fatalf("read %s PostgreSQL TLS identity: %v", candidate.name, err)
		}
		if version < 180004 || version >= 190000 || !ssl || tlsVersion != "TLSv1.3" ||
			sessionUser != candidate.identity || currentUser != candidate.identity {
			t.Fatalf("%s PostgreSQL contract version=%d TLS=%t/%q identity=%q/%q",
				candidate.name, version, ssl, tlsVersion, sessionUser, currentUser)
		}
	}
}

func seedExternalCMDBTask18BPublishedSource(
	t *testing.T,
	harness *assetCatalogHarness,
) assetCatalogFixture {
	t.Helper()
	fixture := seedDraftAssetCatalog(t, harness.db)
	fixture.sourceID = uuid.NewString()
	fixture.revisionID = uuid.NewString()
	fixture.validationRunID = uuid.NewString()
	neutral := sourceprofile.ExternalCMDBV1()
	registration, err := neutral.Registration(sourceprofile.ExternalCMDBProfileReferences{
		IntegrationID:            fixture.integrationID,
		CredentialReferenceID:    "task18b-cmdb-read",
		TrustReferenceID:         "task18b-cmdb-trust",
		NetworkPolicyReferenceID: "task18b-cmdb-network",
	})
	if err != nil {
		t.Fatalf("External CMDB registration: %v", err)
	}
	profile := registration.Profile
	authorityIDs := []string{fixture.environmentID}
	authorityDigest, err := assetcatalog.AuthorityScopeDigest(authorityIDs)
	if err != nil {
		t.Fatalf("External CMDB authority digest: %v", err)
	}
	revision := assetcatalog.SourceRevision{
		ID:                            fixture.revisionID,
		SourceID:                      fixture.sourceID,
		TenantID:                      fixture.tenantID,
		WorkspaceID:                   fixture.workspaceID,
		Revision:                      1,
		Status:                        assetcatalog.SourceRevisionDraft,
		CanonicalProfileManifest:      profile.CanonicalProfileManifest,
		ProfileManifestSHA256:         profile.ProfileManifestSHA256,
		CanonicalProviderSchema:       profile.CanonicalProviderSchema,
		CanonicalProviderSchemaSHA256: profile.CanonicalProviderSchemaSHA256,
		IntegrationID:                 profile.IntegrationID,
		SyncMode:                      profile.SyncMode,
		CredentialReferenceID:         profile.CredentialReferenceID,
		TrustReferenceID:              profile.TrustReferenceID,
		NetworkPolicyReferenceID:      profile.NetworkPolicyReferenceID,
		AuthorityEnvironmentIDs:       authorityIDs,
		AuthorityScopeDigest:          authorityDigest,
		RateLimitRequests:             profile.RateLimitRequests,
		RateLimitWindowSeconds:        profile.RateLimitWindowSeconds,
		BackpressureBaseSeconds:       profile.BackpressureBaseSeconds,
		BackpressureMaxSeconds:        profile.BackpressureMaxSeconds,
		ProfileCode:                   profile.ProfileCode,
		CreatedBy:                     "task18b-test",
		ChangeReasonCode:              "INITIAL_CREATE",
		ExpectedSourceVersion:         1,
		Version:                       1,
		CreatedAt:                     time.Now().UTC().Truncate(time.Microsecond),
		UpdatedAt:                     time.Now().UTC().Truncate(time.Microsecond),
	}
	revision.SourceDefinitionDigest, err = assetcatalog.SourceDefinitionDigest(
		assetcatalog.Source{
			Kind: assetcatalog.SourceKindExternalCMDB, ProviderKind: "CMDB_CATALOG_V1",
		},
		revision,
	)
	if err != nil {
		t.Fatalf("External CMDB source definition digest: %v", err)
	}
	revision.CanonicalRevisionDigest = revision.BindingDigest()
	fixture.sourceDefinitionDigest = revision.SourceDefinitionDigest
	fixture.revisionDigest = revision.CanonicalRevisionDigest

	tx, err := harness.db.BeginTx(t.Context(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin External CMDB definition: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	execAssetSQL(t, tx, `
INSERT INTO asset_sources(
 id,tenant_id,workspace_id,source_kind,provider_kind,name,
 create_idempotency_key,create_request_hash
) VALUES($1,$2,$3,'EXTERNAL_CMDB','CMDB_CATALOG_V1','task18b external cmdb',
         $4,repeat('1',64))
`, fixture.sourceID, fixture.tenantID, fixture.workspaceID, "task18b-source-"+fixture.sourceID)
	execAssetSQL(t, tx, `
INSERT INTO asset_source_revisions(
 id,tenant_id,workspace_id,source_id,revision,
 canonical_profile_manifest,profile_manifest_sha256,
 canonical_provider_schema,canonical_provider_schema_sha256,
 integration_id,sync_mode,authority_scope_digest,source_definition_digest,
 canonical_revision_digest,credential_reference_id,trust_reference_id,
 network_policy_reference_id,rate_limit_requests,rate_limit_window_seconds,
 backpressure_base_seconds,backpressure_max_seconds,profile_code,
 created_by,change_reason_code,expected_source_version
) SELECT $1,$2,$3,$4,1,$5,$6,$7,$8,$9,'ON_DEMAND',$10,$11,$12,
         $13,$14,$15,5,1,1,60,'CMDB_CATALOG_V1',
         'task18b-test','INITIAL_CREATE',source.version
  FROM asset_sources AS source WHERE source.id=$4
`, fixture.revisionID, fixture.tenantID, fixture.workspaceID, fixture.sourceID,
		profile.CanonicalProfileManifest, profile.ProfileManifestSHA256,
		profile.CanonicalProviderSchema, profile.CanonicalProviderSchemaSHA256,
		fixture.integrationID, authorityDigest, fixture.sourceDefinitionDigest,
		fixture.revisionDigest, profile.CredentialReferenceID,
		profile.TrustReferenceID, profile.NetworkPolicyReferenceID)
	execAssetSQL(t, tx, `
INSERT INTO asset_source_revision_authorities(
 tenant_id,workspace_id,source_id,source_revision,environment_id,canonical_ordinal
) VALUES($1,$2,$3,1,$4,1)
`, fixture.tenantID, fixture.workspaceID, fixture.sourceID, fixture.environmentID)
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatalf("commit External CMDB definition: %v", err)
	}

	execAssetSQL(t, harness.db, `
INSERT INTO asset_source_runs(
 id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
 run_kind,trigger_type,gate_revision,idempotency_key,request_hash,checkpoint_version
) SELECT $1,$2,$3,$4,1,$5,'VALIDATION','HUMAN',gate_revision,
         $6,repeat('2',64),0 FROM asset_sources WHERE id=$4
`, fixture.validationRunID, fixture.tenantID, fixture.workspaceID,
		fixture.sourceID, fixture.revisionDigest, "task18b-validation-"+fixture.sourceID)
	execAssetSQL(t, harness.db, `
UPDATE asset_source_revisions
SET state='VALIDATING',validation_run_id=$2,version=version+1 WHERE id=$1
`, fixture.revisionID, fixture.validationRunID)
	execAssetSQL(t, harness.db, `
UPDATE asset_sources
SET gate_status='VALIDATING',gate_revision=gate_revision+1,
    validated_run_id=$2,validation_digest=NULL,validated_binding_digest=NULL,
    version=version+1 WHERE id=$1
`, fixture.sourceID, fixture.validationRunID)
	execAssetSQL(t, harness.db, `
UPDATE asset_source_runs
SET status='RUNNING',stage_code='VALIDATING',lease_owner='task18b-validation-worker',
    lease_expires_at=statement_timestamp()+interval '10 minutes',fence_epoch=1,
    fence_token_hash=repeat('6',64),heartbeat_sequence=1,
    heartbeat_at=statement_timestamp(),version=version+1 WHERE id=$1
`, fixture.validationRunID)
	finishClosureExternalValidation(
		t, harness.db, fixture, 1, strings.Repeat("7", 64),
	)
	return fixture
}

func newExternalCMDBTask18BPageScenario(
	t *testing.T,
	harness *assetCatalogHarness,
	fixture assetCatalogFixture,
	runID, owner string,
) pageCommitScenario {
	t.Helper()
	descriptor, err := externalcmdb.NewReconciliationDescriptor(sourceprofile.ExternalCMDBV1())
	if err != nil {
		t.Fatalf("NewReconciliationDescriptor(): %v", err)
	}
	policy, err := descriptor.FactPolicy([]string{fixture.environmentID})
	if err != nil {
		t.Fatalf("External CMDB FactPolicy(): %v", err)
	}
	scenario := newPageCommitScenarioForFixtureWithKey(
		t, harness, fixture, runID, owner, "task18b-page-"+runID,
		policy, uuid.NewString,
	)
	scenario.resolver = nil
	scenario.committer, err = assetpostgres.NewPageCommitter(
		scenario.repository, scenario.keyring, descriptor,
	)
	if err != nil {
		t.Fatalf("External CMDB NewPageCommitter(): %v", err)
	}
	scenario.page.NextCheckpoint, err = descriptor.NewCheckpoint()
	if err != nil {
		t.Fatalf("External CMDB NewCheckpoint(): %v", err)
	}
	return scenario
}

func externalCMDBTask18BCompletePage(
	t *testing.T,
	environmentID string,
	sequence int64,
	checkpoint discoverysource.Checkpoint,
) discoverysource.Page {
	t.Helper()
	return discoverysource.Page{
		Items: []assetdiscovery.NormalizedItem{
			externalCMDBTask18BLiveItem(t, environmentID, "cmdb-host-a", "host-a", sequence),
			externalCMDBTask18BLiveItem(t, environmentID, "cmdb-host-b", "host-b", sequence),
		},
		Relations: []assetdiscovery.ObservedRelation{{
			SourceEnvironmentID: environmentID,
			TargetEnvironmentID: environmentID,
			FromExternalID:      "cmdb-host-a",
			ToExternalID:        "cmdb-host-b",
			Type:                assetcatalog.RelationshipRunsOn,
			ProviderPathCode:    "CMDB_V1_RELATION",
			Confidence:          100,
			Freshness: assetdiscovery.FreshnessCandidate{
				Kind:                  assetcatalog.FreshnessObjectTimeSequence,
				OrderTime:             externalCMDBTask18BTime(sequence),
				OrderSequence:         sequence,
				ProviderVersionSHA256: strings.Repeat("9", 64),
			},
		}},
		NextCheckpoint:   checkpoint,
		FinalPage:        true,
		CompleteSnapshot: true,
	}
}

func externalCMDBTask18BLiveItem(
	t *testing.T,
	environmentID, externalID, displayName string,
	sequence int64,
) assetdiscovery.NormalizedItem {
	t.Helper()
	document := []byte(`{"architecture":"x86_64","hostname":"` + externalID + `"}`)
	digest := sha256.Sum256(document)
	return assetdiscovery.NormalizedItem{
		EnvironmentID:  environmentID,
		ProviderKind:   "CMDB_CATALOG_V1",
		ExternalID:     externalID,
		Kind:           assetcatalog.KindLinuxVM,
		DisplayName:    displayName,
		SchemaVersion:  "CMDB_CATALOG_V1",
		Document:       document,
		DocumentSHA256: hex.EncodeToString(digest[:]),
		Freshness: assetdiscovery.FreshnessCandidate{
			Kind:                  assetcatalog.FreshnessObjectTimeSequence,
			OrderTime:             externalCMDBTask18BTime(sequence),
			OrderSequence:         sequence,
			ProviderVersionSHA256: strings.Repeat(strconv.FormatInt(sequence%9+1, 10), 64),
		},
		FieldProvenance: externalCMDBTask18BLiveProvenance(),
		Fingerprints:    map[string]string{"provider_instance_id": externalID},
	}
}

func externalCMDBTask18BTombstone(
	environmentID, externalID string,
	sequence int64,
	reason string,
) assetdiscovery.NormalizedItem {
	return assetdiscovery.NormalizedItem{
		EnvironmentID:   environmentID,
		ProviderKind:    "CMDB_CATALOG_V1",
		ExternalID:      externalID,
		Tombstone:       true,
		TombstoneReason: reason,
		Freshness: assetdiscovery.FreshnessCandidate{
			Kind:                  assetcatalog.FreshnessObjectTimeSequence,
			OrderTime:             externalCMDBTask18BTime(sequence),
			OrderSequence:         sequence,
			ProviderVersionSHA256: strings.Repeat("8", 64),
		},
		FieldProvenance: []assetdiscovery.FieldProvenance{
			{
				FieldCode: "environment_id", ProviderPathCode: "CMDB_V1_ENVIRONMENT_ID",
				Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100,
			},
			{
				FieldCode: "external_id", ProviderPathCode: "CMDB_V1_EXTERNAL_ID",
				Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100,
			},
			{
				FieldCode: "provider_kind", ProviderPathCode: "CMDB_V1_PROVIDER_KIND",
				Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100,
			},
		},
	}
}

func externalCMDBTask18BLiveProvenance() []assetdiscovery.FieldProvenance {
	return []assetdiscovery.FieldProvenance{
		{
			FieldCode: "display_name", ProviderPathCode: "CMDB_V1_DISPLAY_NAME",
			Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100,
		},
		{
			FieldCode: "environment_id", ProviderPathCode: "CMDB_V1_ENVIRONMENT_ID",
			Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100,
		},
		{
			FieldCode: "external_id", ProviderPathCode: "CMDB_V1_EXTERNAL_ID",
			Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100,
		},
		{
			FieldCode: "kind", ProviderPathCode: "CMDB_V1_KIND",
			Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100,
		},
		{
			FieldCode: "provider_kind", ProviderPathCode: "CMDB_V1_PROVIDER_KIND",
			Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100,
		},
		{
			FieldCode: "type_details", ProviderPathCode: "CMDB_V1_TYPE_DETAILS",
			Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100,
		},
	}
}

func externalCMDBTask18BTime(sequence int64) *time.Time {
	value := time.Date(2026, 7, 18, 1, 0, int(sequence), 0, time.UTC)
	return &value
}

func reserveExternalCMDBTask18BCleanup(
	t *testing.T,
	database *pgxpool.Pool,
	runID string,
) {
	t.Helper()
	execAssetSQL(t, database, `
UPDATE asset_source_runs
SET cleanup_status='PENDING',cleanup_attempt_id=gen_random_uuid(),
    cleanup_attempt_epoch=fence_epoch,version=version+1
WHERE id=$1
`, runID)
}

func assertExternalCMDBTask18BNoImplicitMissing(
	t *testing.T,
	harness *assetCatalogHarness,
	fixture assetCatalogFixture,
	runID string,
) {
	t.Helper()
	var missing, stale, staleAssets, inactiveRelations int64
	if err := harness.db.QueryRow(t.Context(), `
SELECT run.missing_count,run.stale_count,
       (SELECT count(*) FROM assets
        WHERE source_id=$1::uuid AND lifecycle='STALE'),
       (SELECT count(*) FROM asset_relationships
        WHERE source_id=$1::uuid AND status='INACTIVE')
FROM asset_source_runs AS run WHERE run.id=$2::uuid
`, fixture.sourceID, runID).Scan(
		&missing, &stale, &staleAssets, &inactiveRelations,
	); err != nil {
		t.Fatalf("read no-missing closure: %v", err)
	}
	if missing != 0 || stale != 0 || staleAssets != 0 || inactiveRelations != 0 {
		t.Fatalf("partial page caused implicit missing: counts=%d/%d assets=%d relations=%d",
			missing, stale, staleAssets, inactiveRelations)
	}
}

func assertExternalCMDBTask18BPageState(
	t *testing.T,
	scenario pageCommitScenario,
	observations, relationships, pageReceipts, relationReceipts, checkpoint int64,
) {
	t.Helper()
	var actualObservations, actualRelationships, actualPageReceipts, actualRelationReceipts int64
	var sourceCheckpoint, runCheckpoint, pageSequence, relationSequence int64
	if err := scenario.harness.db.QueryRow(t.Context(), `
SELECT (SELECT count(*) FROM asset_observations WHERE run_id=$1::uuid),
       (SELECT count(*) FROM asset_relationships WHERE last_run_id=$1::uuid),
       (SELECT count(*) FROM audit_records
        WHERE request_id='source-page:'||$1||':1' AND action='PAGE_APPLIED'),
       (SELECT count(*) FROM audit_records
        WHERE request_id='source-relation-page:'||$1||':1'
          AND action='RELATION_PAGE_COMMITTED'),
       source.checkpoint_version,run.checkpoint_version,
       run.page_sequence,run.relation_page_sequence
FROM asset_sources AS source JOIN asset_source_runs AS run ON run.source_id=source.id
WHERE source.id=$2::uuid AND run.id=$1::uuid
`, scenario.runID, scenario.fixture.sourceID).Scan(
		&actualObservations, &actualRelationships,
		&actualPageReceipts, &actualRelationReceipts,
		&sourceCheckpoint, &runCheckpoint, &pageSequence, &relationSequence,
	); err != nil {
		t.Fatalf("read Task 18B page state: %v", err)
	}
	if actualObservations != observations || actualRelationships != relationships ||
		actualPageReceipts != pageReceipts || actualRelationReceipts != relationReceipts ||
		sourceCheckpoint != checkpoint || runCheckpoint != checkpoint ||
		pageSequence != checkpoint || relationSequence != checkpoint {
		t.Fatalf("Task 18B page state observations=%d relationships=%d receipts=%d/%d checkpoints=%d/%d sequences=%d/%d",
			actualObservations, actualRelationships, actualPageReceipts, actualRelationReceipts,
			sourceCheckpoint, runCheckpoint, pageSequence, relationSequence)
	}
}

func cloneExternalCMDBTask18BPage(page discoverysource.Page) discoverysource.Page {
	page.Items = append([]assetdiscovery.NormalizedItem(nil), page.Items...)
	for index := range page.Items {
		page.Items[index].Document = append([]byte(nil), page.Items[index].Document...)
		page.Items[index].FieldProvenance = append(
			[]assetdiscovery.FieldProvenance(nil), page.Items[index].FieldProvenance...,
		)
	}
	page.Relations = append([]assetdiscovery.ObservedRelation(nil), page.Relations...)
	page.NextCheckpoint = page.NextCheckpoint.Clone()
	return page
}
