package postgres_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	assetpostgres "github.com/seaworld008/aiops-system/internal/assetcatalog/postgres"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
	vsphereprovider "github.com/seaworld008/aiops-system/internal/assetsource/vsphere"
	"github.com/seaworld008/aiops-system/internal/discoverycleanup"
	"github.com/seaworld008/aiops-system/internal/discoveryqueue"
	queuepostgres "github.com/seaworld008/aiops-system/internal/discoveryqueue/postgres"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
	"github.com/seaworld008/aiops-system/internal/leasefence"
	"github.com/vmware/govmomi/simulator"
	"github.com/vmware/govmomi/vim25/types"
)

const vSphereProfileManifestV1 = `{"backpressure_base_seconds":1,"backpressure_max_seconds":60,"compatibility_class":"VSPHERE_VCENTER_V1","credential_purpose":"DISCOVERY_READ","dlp_policy_code":"ASSET_SAFE_V1","environment_mapping_mode":"SINGLE_ENVIRONMENT","freshness_kind":"CHECKPOINT_SEQUENCE","integration_mode":"REQUIRED","max_document_bytes":65536,"max_page_bytes":8388608,"max_page_items":500,"max_page_relations":2000,"network_mode":"REQUIRED","parser_code":"VSPHERE_VCENTER_V1","profile_code":"VSPHERE_VCENTER_V1","provider_kind":"VSPHERE_VCENTER_V1","rate_limit_requests":100,"rate_limit_window_seconds":60,"relationship_types":["CONTAINS","RUNS_ON"],"schedule_mode":"NONE","source_kind":"VSPHERE","sync_mode":"ON_DEMAND","trust_mode":"REQUIRED","trusted_path_codes":["VSPHERE_V1_CONTAINS","VSPHERE_V1_DISPLAY_NAME","VSPHERE_V1_ENVIRONMENT_ID","VSPHERE_V1_EXTERNAL_ID","VSPHERE_V1_KIND","VSPHERE_V1_PROVIDER_KIND","VSPHERE_V1_RUNS_ON","VSPHERE_V1_TYPE_DETAILS"],"typed_extension_code":null,"version":"asset-source-profile-manifest.v1"}`

func TestVCenterDiscoveryIntegrationRejectsStaleFenceWithoutObservationOrMissingProjection(
	t *testing.T,
) {
	scenario := newVCenterPageCommitScenario(
		t,
		"86a00000-0000-4000-8000-000000000011",
		"vsphere-stale-fence-run",
	)
	soap := newVCenterSOAPFixture(t, 0, 1, "")
	empty := emptyVCenterCheckpoint(t)
	pages := soap.snapshotPages(
		t,
		vCenterRuntimeBinding(scenario),
		scenario.fixture.environmentID,
		empty,
		500,
	)
	empty.Clear()
	defer clearVCenterPages(pages)
	if len(pages) == 0 ||
		!pages[len(pages)-1].FinalPage ||
		!pages[len(pages)-1].CompleteSnapshot {
		t.Fatalf("production vSphere stale-fence fixture pages = %d", len(pages))
	}
	scenario.page = pages[0]
	scenario.fence.Destroy()

	result, err := scenario.committer.ApplyPage(
		context.Background(),
		scenario.fence,
		scenario.coordinates,
		scenario.page,
	)
	if !errors.Is(err, discoverysource.ErrPageCommitConflict) ||
		result != (discoverysource.PageCommitResult{}) {
		t.Fatalf("ApplyPage(stale fence) = (%#v,%v)", result, err)
	}
	assertVCenterProjection(t, scenario, 0, 0, 0)
}

func TestVCenterDiscoveryIntegrationPartialPageNeverRunsMissingDetection(t *testing.T) {
	scenario := newVCenterPageCommitScenario(
		t,
		"86a00000-0000-4000-8000-000000000012",
		"vsphere-partial-page-run",
	)
	soap := newVCenterSOAPFixture(t, 1, 1, "")
	empty := emptyVCenterCheckpoint(t)
	pages := soap.snapshotPages(
		t,
		vCenterRuntimeBinding(scenario),
		scenario.fixture.environmentID,
		empty,
		2,
	)
	empty.Clear()
	defer clearVCenterPages(pages)
	if len(pages) < 2 || pages[0].FinalPage || pages[0].CompleteSnapshot {
		t.Fatalf("production vSphere partial fixture pages = %d", len(pages))
	}

	result := applyVCenterPage(t, &scenario, pages[0])
	if result.FinalPage || result.CompleteSnapshot || result.Replayed {
		t.Fatalf("ApplyPage(partial) = %#v", result)
	}
	assertVCenterProjection(
		t,
		scenario,
		len(pages[0].Items),
		len(pages[0].Relations),
		0,
	)
}

func TestVCenterDiscoveryIntegrationProviderReplaySurvivesPreCommitResponseLoss(
	t *testing.T,
) {
	scenario := newVCenterPageCommitScenario(
		t,
		"86a00000-0000-4000-8000-000000000018",
		"vsphere-provider-replay-response-loss-run",
	)
	soap := newVCenterSOAPFixture(t, 1, 1, "")
	empty := emptyVCenterCheckpoint(t)
	pages := soap.replayedSnapshotPages(
		t,
		vCenterRuntimeBinding(scenario),
		scenario.fixture.environmentID,
		empty,
		2,
	)
	empty.Clear()
	defer clearVCenterPages(pages)
	if len(pages) < 2 ||
		!pages[len(pages)-1].FinalPage ||
		!pages[len(pages)-1].CompleteSnapshot {
		t.Fatalf("replayed production vSphere snapshot pages = %d", len(pages))
	}
	reserveVCenterCleanupForPageTest(t, scenario)
	results := applyVCenterPages(t, &scenario, pages)
	closed := results[len(results)-1]
	if !closed.FinalPage || !closed.CompleteSnapshot || closed.Replayed {
		t.Fatalf("ApplyPage(provider replay closure) = %#v", closed)
	}
	items, relations := vCenterPageCounts(pages)
	assertVCenterProjection(t, scenario, items, relations, 0)
}

func TestVCenterDiscoveryIntegrationCompleteOnlyMissingAndSameRunReplay(t *testing.T) {
	first := newVCenterPageCommitScenario(
		t,
		"86a00000-0000-4000-8000-000000000013",
		"vsphere-complete-replay-run",
	)
	withDatastore := newVCenterSOAPFixture(t, 0, 1, "")
	empty := emptyVCenterCheckpoint(t)
	firstPages := withDatastore.snapshotPages(
		t,
		vCenterRuntimeBinding(first),
		first.fixture.environmentID,
		empty,
		500,
	)
	empty.Clear()
	defer clearVCenterPages(firstPages)
	if len(firstPages) == 0 ||
		!firstPages[len(firstPages)-1].FinalPage ||
		!firstPages[len(firstPages)-1].CompleteSnapshot {
		t.Fatalf("first production vSphere snapshot pages = %d", len(firstPages))
	}
	reserveVCenterCleanupForPageTest(t, first)
	results := applyVCenterPages(t, &first, firstPages)
	committed := results[len(results)-1]
	if !committed.FinalPage || !committed.CompleteSnapshot ||
		committed.Replayed || committed.RelationPageDigestSHA256 == "" {
		t.Fatalf("ApplyPage(complete) = %#v", committed)
	}
	replayed, err := first.committer.ApplyPage(
		context.Background(),
		first.fence,
		first.coordinates,
		firstPages[len(firstPages)-1],
	)
	if err != nil || !replayed.Replayed ||
		replayed.PageDigestSHA256 != committed.PageDigestSHA256 ||
		replayed.RelationPageDigestSHA256 != committed.RelationPageDigestSHA256 ||
		replayed.CheckpointSHA256 != committed.CheckpointSHA256 {
		t.Fatalf("ApplyPage(replay) = (%#v,%v)", replayed, err)
	}
	firstItems, firstRelations := vCenterPageCounts(firstPages)
	assertVCenterProjection(t, first, firstItems, firstRelations, 0)
	priorCheckpoint := firstPages[len(firstPages)-1].NextCheckpoint.Clone()
	defer priorCheckpoint.Clear()
	priorIDs := vCenterItemIDs(firstPages)
	finishVCenterCompleteRunForTest(t, first.harness, first.fixture, first.runID)
	execAssetSQL(t, first.harness.db, `
UPDATE assets
SET lifecycle='ACTIVE',version=version+1
WHERE source_id=$1::uuid
`, first.fixture.sourceID)

	second := newVCenterPageCommitScenarioForFixture(
		t,
		first.harness,
		first.fixture,
		"86a00000-0000-4000-8000-000000000017",
		"vsphere-complete-missing-run",
	)
	withoutDatastore := newVCenterSOAPFixture(t, 0, 0, withDatastore.instanceUUID)
	secondPages := withoutDatastore.snapshotPages(
		t,
		vCenterRuntimeBinding(second),
		second.fixture.environmentID,
		priorCheckpoint,
		500,
	)
	defer clearVCenterPages(secondPages)
	if len(secondPages) == 0 ||
		!secondPages[len(secondPages)-1].FinalPage ||
		!secondPages[len(secondPages)-1].CompleteSnapshot {
		t.Fatalf("successor production vSphere snapshot pages = %d", len(secondPages))
	}
	successorIDs := vCenterItemIDs(secondPages)
	var wantMissing int64
	var missingExternalID string
	for externalID := range priorIDs {
		if _, retained := successorIDs[externalID]; !retained {
			wantMissing++
			missingExternalID = externalID
		}
	}
	if wantMissing != 1 || missingExternalID == "" {
		t.Fatalf("vSphere simulator successor removed %d prior objects, want exactly 1", wantMissing)
	}
	relationshipBefore := readVCenterRelationshipFreshness(
		t,
		second.harness.db,
		second.fixture.sourceID,
		missingExternalID,
	)
	if len(relationshipBefore) == 0 {
		t.Fatalf("missing vSphere object %q had no active relationship", missingExternalID)
	}
	reserveVCenterCleanupForPageTest(t, second)
	for index, page := range secondPages {
		result := applyVCenterPage(t, &second, page)
		if index < len(secondPages)-1 {
			if result.FinalPage || result.CompleteSnapshot {
				t.Fatalf("intermediate successor page %d closed snapshot", index+1)
			}
			assertVCenterMissing(t, second, 0)
		}
	}
	assertVCenterMissing(t, second, wantMissing)
	relationshipAfter := readVCenterRelationshipFreshness(
		t,
		second.harness.db,
		second.fixture.sourceID,
		missingExternalID,
	)
	assertVCenterMissingRelationshipFreshnessAdvanced(
		t,
		relationshipBefore,
		relationshipAfter,
	)
}

func TestVCenterDiscoveryIntegrationBrokerLifecycleRolloverHandoff(t *testing.T) {
	scenario := newVCenterPageCommitScenario(
		t,
		"86a00000-0000-4000-8000-000000000019",
		"vsphere-broker-rollover-handoff-run",
	)
	soap := newVCenterSOAPFixture(t, 1, 1, "")
	binding := vCenterRuntimeBinding(scenario)
	coordinates := discoveryqueue.RunCoordinates{
		Scope: assetcatalog.SourceScope{
			TenantID:    scenario.fixture.tenantID,
			WorkspaceID: scenario.fixture.workspaceID,
		},
		RunID: scenario.runID,
	}
	rolloverAuthority := vsphereprovider.NewFullInventoryRolloverAuthority()
	t.Cleanup(rolloverAuthority.Destroy)
	material := soap.runtimeMaterial(
		t,
		scenario.fixture.environmentID,
		[]types.ManagedObjectReference{soap.root},
	)
	opener := &vCenterBrokerRolloverOpener{
		authority: rolloverAuthority,
		material:  &material,
	}
	proofAuthority := &vCenterBrokerProofAuthority{
		key: []byte("task21a-vsphere-broker-rollover-proof-key"),
	}
	broker, err := discoverycleanup.NewCleanupBroker(opener, proofAuthority)
	if err != nil {
		t.Fatalf("NewCleanupBroker() error = %v", err)
	}
	t.Cleanup(broker.Destroy)
	queue, err := queuepostgres.New(
		scenario.harness.application,
		broker,
		rolloverAuthority,
	)
	if err != nil {
		t.Fatalf("queuepostgres.New() error = %v", err)
	}
	attempt, err := queue.ReserveCleanupAttempt(
		context.Background(),
		scenario.fence,
		discoveryqueue.RunCommand{Coordinates: coordinates},
	)
	if err != nil {
		t.Fatalf("ReserveCleanupAttempt() error = %v", err)
	}
	openRequest := discoverycleanup.OpenAttemptRequest{
		Coordinates: coordinates,
		Attempt:     attempt,
	}
	session, err := broker.OpenAttempt(context.Background(), openRequest)
	if err != nil {
		t.Fatalf("OpenAttempt() error = %v", err)
	}
	t.Cleanup(session.Destroy)
	runtime, err := broker.BindAttemptRuntime(
		context.Background(),
		session,
		binding,
	)
	if err != nil {
		t.Fatalf("BindAttemptRuntime() error = %v", err)
	}
	factory, err := vsphereprovider.NewClientFactory(binding)
	if err != nil {
		t.Fatalf("NewClientFactory() error = %v", err)
	}
	provider, err := vsphereprovider.New(factory)
	if err != nil {
		t.Fatalf("vsphere.New() error = %v", err)
	}
	empty := emptyVCenterCheckpoint(t)
	request := vCenterDiscoverRequest(binding, empty, 2)
	outcome, err := provider.Discover(context.Background(), runtime, request)
	request.Checkpoint.Clear()
	empty.Clear()
	if err != nil {
		t.Fatalf("Discover(partial) error = %v", err)
	}
	partial, ok := outcome.(discoverysource.Page)
	if !ok || partial.FinalPage || partial.CompleteSnapshot {
		t.Fatalf("Discover(partial) outcome = %#v", outcome)
	}
	defer partial.NextCheckpoint.Clear()
	accepted := applyVCenterPage(t, &scenario, partial)
	if accepted.FinalPage || accepted.CompleteSnapshot ||
		accepted.CheckpointVersion != 1 ||
		accepted.CheckpointSHA256 == "" {
		t.Fatalf("ApplyPage(partial) = %#v", accepted)
	}

	var checkpointBefore *string
	var checkpointVersionBefore, pageSequenceBefore, missingBefore int64
	var checkpointCiphertextBefore []byte
	if err := scenario.harness.db.QueryRow(context.Background(), `
SELECT source.checkpoint_sha256,source.checkpoint_version,source.checkpoint_ciphertext,
       run.page_sequence,run.missing_count
FROM asset_sources AS source
JOIN asset_source_runs AS run ON run.source_id=source.id
WHERE run.id=$1::uuid
`, scenario.runID).Scan(
		&checkpointBefore,
		&checkpointVersionBefore,
		&checkpointCiphertextBefore,
		&pageSequenceBefore,
		&missingBefore,
	); err != nil {
		t.Fatalf("read accepted rollover checkpoint: %v", err)
	}
	command := discoveryqueue.RolloverCommand{
		Coordinates:    coordinates,
		ReasonCode:     "PROVIDER_SESSION_LOST",
		EvidenceDigest: strings.Repeat("8", 64),
	}
	responseLossQueue := &vCenterRolloverResponseLossQueue{Queue: queue}
	handoff, _, err := rolloverAuthority.BeginHandoff(
		context.Background(),
		responseLossQueue,
		scenario.fence,
		openRequest,
		command,
		accepted,
		partial.NextCheckpoint,
	)
	if handoff != nil || !errors.Is(err, discoveryqueue.ErrUnavailable) {
		if handoff != nil {
			handoff.Destroy()
		}
		t.Fatalf("BeginHandoff(response loss) = (%#v,%v)", handoff, err)
	}
	responseLossRequest := vCenterDiscoverRequest(
		binding,
		partial.NextCheckpoint,
		2,
	)
	responseLossOutcome, responseLossErr := provider.Discover(
		context.Background(),
		runtime,
		responseLossRequest,
	)
	responseLossRequest.Checkpoint.Clear()
	if responseLossOutcome != nil || responseLossErr == nil {
		t.Fatalf(
			"Discover(predecessor after handoff response loss) = (%#v,%v)",
			responseLossOutcome,
			responseLossErr,
		)
	}
	if rebound, bindErr := opener.handle.BindRuntime(
		context.Background(),
		binding,
	); rebound != (discoverysource.BoundRuntime{}) || bindErr == nil {
		t.Fatalf(
			"BindAttemptRuntime(predecessor after handoff response loss) = (%#v,%v)",
			rebound,
			bindErr,
		)
	}
	handoff, admitted, err := rolloverAuthority.BeginHandoff(
		context.Background(),
		responseLossQueue,
		scenario.fence,
		openRequest,
		command,
		accepted,
		partial.NextCheckpoint,
	)
	if err != nil || handoff == nil || !admitted.Replayed {
		if handoff != nil {
			handoff.Destroy()
		}
		t.Fatalf("BeginHandoff(replay) = (%#v,%#v,%v)", handoff, admitted, err)
	}
	defer handoff.Destroy()

	mintedRequest := vCenterDiscoverRequest(
		binding,
		partial.NextCheckpoint,
		2,
	)
	mintedOutcome, mintedErr := provider.Discover(
		context.Background(),
		runtime,
		mintedRequest,
	)
	mintedRequest.Checkpoint.Clear()
	if mintedOutcome != nil || mintedErr == nil {
		t.Fatalf(
			"Discover(predecessor after handoff mint) = (%#v,%v)",
			mintedOutcome,
			mintedErr,
		)
	}
	if rebound, bindErr := opener.handle.BindRuntime(
		context.Background(),
		binding,
	); rebound != (discoverysource.BoundRuntime{}) || bindErr == nil {
		t.Fatalf(
			"BindAttemptRuntime(predecessor after handoff mint) = (%#v,%v)",
			rebound,
			bindErr,
		)
	}
	var frozenCheckpoint *string
	var frozenCheckpointVersion, frozenPageSequence, frozenMissing int64
	var frozenCheckpointCiphertext []byte
	if err := scenario.harness.db.QueryRow(context.Background(), `
SELECT source.checkpoint_sha256,source.checkpoint_version,source.checkpoint_ciphertext,
       run.page_sequence,run.missing_count
FROM asset_sources AS source
JOIN asset_source_runs AS run ON run.source_id=source.id
WHERE run.id=$1::uuid
`, scenario.runID).Scan(
		&frozenCheckpoint,
		&frozenCheckpointVersion,
		&frozenCheckpointCiphertext,
		&frozenPageSequence,
		&frozenMissing,
	); err != nil {
		t.Fatalf("read frozen predecessor checkpoint: %v", err)
	}
	if checkpointBefore == nil || frozenCheckpoint == nil ||
		*frozenCheckpoint != *checkpointBefore ||
		frozenCheckpointVersion != checkpointVersionBefore ||
		!bytes.Equal(frozenCheckpointCiphertext, checkpointCiphertextBefore) ||
		frozenPageSequence != pageSequenceBefore ||
		frozenMissing != missingBefore {
		t.Fatalf(
			"frozen predecessor changed persisted state: checkpoint=%v/%d page=%d missing=%d",
			frozenCheckpoint,
			frozenCheckpointVersion,
			frozenPageSequence,
			frozenMissing,
		)
	}
	assertVCenterProjection(
		t,
		scenario,
		len(partial.Items),
		len(partial.Relations),
		0,
	)

	proof, err := broker.RevokeAttempt(context.Background(), attempt.AttemptID)
	if err != nil {
		t.Fatalf("RevokeAttempt() error = %v", err)
	}
	if proof.Status() != assetcatalog.CredentialCleanupRevoked ||
		proof.Attempt() != attempt ||
		broker.VerifyCleanupProof(context.Background(), proof) != nil {
		proof.Destroy()
		t.Fatalf("RevokeAttempt() proof = %#v", proof)
	}
	proof.Destroy()
	if revokeCalls, destroyCalls := opener.lifecycleCounts(); revokeCalls != 1 || destroyCalls != 1 {
		t.Fatalf(
			"Broker lifecycle Revoke/Destroy calls = %d/%d, want 1/1",
			revokeCalls,
			destroyCalls,
		)
	}
	oldRequest := vCenterDiscoverRequest(
		binding,
		partial.NextCheckpoint,
		2,
	)
	oldOutcome, oldErr := provider.Discover(
		context.Background(),
		runtime,
		oldRequest,
	)
	oldRequest.Checkpoint.Clear()
	if oldOutcome != nil || oldErr == nil {
		t.Fatalf("Discover(old runtime after Broker Destroy) = (%#v,%v)", oldOutcome, oldErr)
	}

	successorMaterial := soap.runtimeMaterial(
		t,
		scenario.fixture.environmentID,
		[]types.ManagedObjectReference{soap.root},
	)
	successor, err := handoff.NewSuccessor(
		context.Background(),
		responseLossQueue,
		scenario.fence,
		&successorMaterial,
		partial.NextCheckpoint,
	)
	if err != nil {
		t.Fatalf("NewSuccessor() error = %v", err)
	}
	t.Cleanup(successor.Destroy)
	successorRuntime, err := successor.BindRuntime(context.Background(), binding)
	if err != nil {
		t.Fatalf("BindRuntime(successor) error = %v", err)
	}
	successorPages := collectVCenterPagesFromRuntime(
		t,
		provider,
		successorRuntime,
		binding,
		scenario.fixture.environmentID,
		partial.NextCheckpoint,
		2,
	)
	defer clearVCenterPages(successorPages)
	if len(successorPages) == 0 ||
		!successorPages[len(successorPages)-1].FinalPage ||
		!successorPages[len(successorPages)-1].CompleteSnapshot {
		t.Fatalf("handoff successor pages = %d", len(successorPages))
	}
	for index, page := range successorPages {
		wantSequence := accepted.CheckpointVersion + int64(index) + 1
		for _, item := range page.Items {
			if item.Freshness.OrderSequence != wantSequence {
				t.Fatalf(
					"handoff successor item sequence = %d, want %d",
					item.Freshness.OrderSequence,
					wantSequence,
				)
			}
		}
		for _, relation := range page.Relations {
			if relation.Freshness.OrderSequence != wantSequence {
				t.Fatalf(
					"handoff successor relation sequence = %d, want %d",
					relation.Freshness.OrderSequence,
					wantSequence,
				)
			}
		}
	}
	results := applyVCenterPages(t, &scenario, successorPages)
	closed := results[len(results)-1]
	if !closed.FinalPage || !closed.CompleteSnapshot || closed.Replayed {
		t.Fatalf("handoff successor closure = %#v", closed)
	}
	var checkpointAfter *string
	var checkpointVersionAfter, missingAfter int64
	var checkpointCiphertextAfter []byte
	if err := scenario.harness.db.QueryRow(context.Background(), `
SELECT source.checkpoint_sha256,source.checkpoint_version,source.checkpoint_ciphertext,
       run.missing_count
FROM asset_sources AS source
JOIN asset_source_runs AS run ON run.source_id=source.id
WHERE run.id=$1::uuid
`, scenario.runID).Scan(
		&checkpointAfter,
		&checkpointVersionAfter,
		&checkpointCiphertextAfter,
		&missingAfter,
	); err != nil {
		t.Fatalf("read handoff successor checkpoint: %v", err)
	}
	if checkpointBefore == nil || checkpointAfter == nil ||
		checkpointVersionBefore != accepted.CheckpointVersion ||
		missingBefore != 0 || missingAfter != 0 ||
		checkpointVersionAfter <= checkpointVersionBefore ||
		bytes.Equal(checkpointCiphertextAfter, checkpointCiphertextBefore) ||
		*checkpointAfter == *checkpointBefore {
		t.Fatalf(
			"handoff checkpoint closure before=%v/%d/%d after=%v/%d/%d",
			checkpointBefore,
			checkpointVersionBefore,
			missingBefore,
			checkpointAfter,
			checkpointVersionAfter,
			missingAfter,
		)
	}
}

func TestVCenterDiscoveryIntegrationRolloverHandoffRejectsForeignDatabaseAttempt(
	t *testing.T,
) {
	fixture := newVCenterRolloverAdmissionFixture(
		t,
		"86a00000-0000-4000-8000-000000000020",
		"vsphere-rollover-foreign-database-attempt",
		0,
		func(attempt discoveryqueue.CleanupAttempt) discoveryqueue.CleanupAttempt {
			attempt.AttemptID = "86a00000-0000-4000-8000-000000000099"
			return attempt
		},
	)
	assertVCenterRolloverPreflightFailureFrozen(
		t,
		fixture,
		fixture.scenario.fence,
		nil,
	)
}

func TestVCenterDiscoveryIntegrationRolloverHandoffRejectsForeignFenceBeforeHandoff(
	t *testing.T,
) {
	fixture := newVCenterRolloverAdmissionFixture(
		t,
		"86a00000-0000-4000-8000-000000000022",
		"vsphere-rollover-foreign-fence-before-handoff",
		0,
		nil,
	)
	var raw [32]byte
	for index := range raw {
		raw[index] = byte(index + 71)
	}
	foreignFence, err := leasefence.FromQueueClaim(
		fixture.scenario.runID,
		"vsphere-rollover-foreign-fence-owner",
		fixture.openRequest.Attempt.AttemptEpoch,
		&raw,
	)
	if err != nil {
		t.Fatalf("FromQueueClaim(foreign) error = %v", err)
	}
	t.Cleanup(foreignFence.Destroy)
	assertVCenterRolloverPreflightFailureFrozen(
		t,
		fixture,
		foreignFence,
		discoveryqueue.ErrStaleFence,
	)
}

func TestVCenterDiscoveryIntegrationRolloverHandoffRejectsReclaimedFenceBeforeHandoff(
	t *testing.T,
) {
	fixture := newVCenterRolloverAdmissionFixture(
		t,
		"86a00000-0000-4000-8000-000000000023",
		"vsphere-rollover-reclaimed-fence-before-handoff",
		3*time.Second,
		nil,
	)
	if _, err := fixture.scenario.harness.db.Exec(
		context.Background(),
		`
SELECT pg_sleep(
  GREATEST(
    0,
    extract(epoch FROM lease_expires_at-clock_timestamp())+0.1
  )
)
FROM asset_source_runs
WHERE id=$1::uuid
`,
		fixture.scenario.runID,
	); err != nil {
		t.Fatalf("wait for preflight rollover lease expiry: %v", err)
	}
	reclaimed, err := fixture.queue.Reclaim(
		context.Background(),
		discoveryqueue.ReclaimCommand{
			Owner:         "vsphere-rollover-preflight-reclaim-worker",
			LeaseDuration: 5 * time.Second,
			ProviderKinds: []string{fixture.binding.ProviderKind},
		},
	)
	if err != nil {
		t.Fatalf("Reclaim() error = %v", err)
	}
	t.Cleanup(reclaimed.Destroy)
	if reclaimed.Run.ID != fixture.scenario.runID ||
		reclaimed.Run.FenceEpoch != fixture.openRequest.Attempt.AttemptEpoch+1 {
		t.Fatalf("preflight reclaimed rollover run = %#v", reclaimed.Run)
	}
	assertVCenterRolloverPreflightFailureFrozen(
		t,
		fixture,
		fixture.scenario.fence,
		discoveryqueue.ErrStaleFence,
	)
}

func TestVCenterDiscoveryIntegrationRolloverHandoffRejectsReclaimedFence(
	t *testing.T,
) {
	fixture := newVCenterRolloverAdmissionFixture(
		t,
		"86a00000-0000-4000-8000-000000000021",
		"vsphere-rollover-reclaimed-fence",
		3*time.Second,
		nil,
	)
	handoff, _, err := fixture.authority.BeginHandoff(
		context.Background(),
		fixture.queue,
		fixture.scenario.fence,
		fixture.openRequest,
		fixture.command,
		fixture.accepted,
		fixture.partial.NextCheckpoint,
	)
	if err != nil || handoff == nil {
		if handoff != nil {
			handoff.Destroy()
		}
		t.Fatalf("BeginHandoff() = (%#v,%v)", handoff, err)
	}
	defer handoff.Destroy()
	proof, err := fixture.broker.RevokeAttempt(
		context.Background(),
		fixture.openRequest.Attempt.AttemptID,
	)
	if err != nil {
		t.Fatalf("RevokeAttempt() error = %v", err)
	}
	proof.Destroy()
	if _, err := fixture.scenario.harness.db.Exec(
		context.Background(),
		`
SELECT pg_sleep(
  GREATEST(
    0,
    extract(epoch FROM lease_expires_at-clock_timestamp())+0.1
  )
)
FROM asset_source_runs
WHERE id=$1::uuid
`,
		fixture.scenario.runID,
	); err != nil {
		t.Fatalf("wait for rollover lease expiry: %v", err)
	}
	reclaimed, err := fixture.queue.Reclaim(
		context.Background(),
		discoveryqueue.ReclaimCommand{
			Owner:         "vsphere-rollover-reclaim-worker",
			LeaseDuration: 5 * time.Second,
			ProviderKinds: []string{fixture.binding.ProviderKind},
		},
	)
	if err != nil {
		t.Fatalf("Reclaim() error = %v", err)
	}
	t.Cleanup(reclaimed.Destroy)
	if reclaimed.Run.ID != fixture.scenario.runID ||
		reclaimed.Run.FenceEpoch != fixture.openRequest.Attempt.AttemptEpoch+1 {
		t.Fatalf("reclaimed rollover run = %#v", reclaimed.Run)
	}

	successorMaterial := fixture.soap.runtimeMaterial(
		t,
		fixture.scenario.fixture.environmentID,
		[]types.ManagedObjectReference{fixture.soap.root},
	)
	successor, successorErr := handoff.NewSuccessor(
		context.Background(),
		fixture.queue,
		fixture.scenario.fence,
		&successorMaterial,
		fixture.partial.NextCheckpoint,
	)
	if successor != nil {
		successor.Destroy()
	}
	if successor != nil || successorErr == nil {
		t.Fatalf("NewSuccessor(reclaimed fence) = (%#v,%v)", successor, successorErr)
	}
}

type vCenterRolloverAdmissionFixture struct {
	scenario    pageCommitScenario
	soap        vCenterSOAPFixture
	binding     discoverysource.RuntimeBinding
	authority   *vsphereprovider.FullInventoryRolloverAuthority
	broker      *discoverycleanup.CleanupBroker
	opener      *vCenterBrokerRolloverOpener
	queue       *queuepostgres.Repository
	provider    discoverysource.Provider
	runtime     discoverysource.BoundRuntime
	openRequest discoverycleanup.OpenAttemptRequest
	accepted    discoverysource.PageCommitResult
	partial     discoverysource.Page
	command     discoveryqueue.RolloverCommand
}

func newVCenterRolloverAdmissionFixture(
	t *testing.T,
	runID string,
	idempotencyKey string,
	leaseDuration time.Duration,
	mutateAttempt func(discoveryqueue.CleanupAttempt) discoveryqueue.CleanupAttempt,
) *vCenterRolloverAdmissionFixture {
	t.Helper()
	var scenario pageCommitScenario
	if leaseDuration > 0 {
		scenario = newVCenterPageCommitScenarioWithLease(
			t,
			runID,
			idempotencyKey,
			leaseDuration,
		)
	} else {
		scenario = newVCenterPageCommitScenario(t, runID, idempotencyKey)
	}
	soap := newVCenterSOAPFixture(t, 1, 1, "")
	binding := vCenterRuntimeBinding(scenario)
	coordinates := discoveryqueue.RunCoordinates{
		Scope: assetcatalog.SourceScope{
			TenantID:    scenario.fixture.tenantID,
			WorkspaceID: scenario.fixture.workspaceID,
		},
		RunID: scenario.runID,
	}
	authority := vsphereprovider.NewFullInventoryRolloverAuthority()
	t.Cleanup(authority.Destroy)
	material := soap.runtimeMaterial(
		t,
		scenario.fixture.environmentID,
		[]types.ManagedObjectReference{soap.root},
	)
	opener := &vCenterBrokerRolloverOpener{
		authority: authority,
		material:  &material,
	}
	broker, err := discoverycleanup.NewCleanupBroker(
		opener,
		&vCenterBrokerProofAuthority{
			key: []byte("task21a-vsphere-rollover-admission-proof-key"),
		},
	)
	if err != nil {
		t.Fatalf("NewCleanupBroker() error = %v", err)
	}
	t.Cleanup(broker.Destroy)
	queue, err := queuepostgres.New(
		scenario.harness.application,
		broker,
		authority,
	)
	if err != nil {
		t.Fatalf("queuepostgres.New() error = %v", err)
	}
	databaseAttempt, err := queue.ReserveCleanupAttempt(
		context.Background(),
		scenario.fence,
		discoveryqueue.RunCommand{Coordinates: coordinates},
	)
	if err != nil {
		t.Fatalf("ReserveCleanupAttempt() error = %v", err)
	}
	registeredAttempt := databaseAttempt
	if mutateAttempt != nil {
		registeredAttempt = mutateAttempt(registeredAttempt)
	}
	openRequest := discoverycleanup.OpenAttemptRequest{
		Coordinates: coordinates,
		Attempt:     registeredAttempt,
	}
	session, err := broker.OpenAttempt(context.Background(), openRequest)
	if err != nil {
		t.Fatalf("OpenAttempt() error = %v", err)
	}
	t.Cleanup(session.Destroy)
	runtime, err := broker.BindAttemptRuntime(
		context.Background(),
		session,
		binding,
	)
	if err != nil {
		t.Fatalf("BindAttemptRuntime() error = %v", err)
	}
	factory, err := vsphereprovider.NewClientFactory(binding)
	if err != nil {
		t.Fatalf("NewClientFactory() error = %v", err)
	}
	provider, err := vsphereprovider.New(factory)
	if err != nil {
		t.Fatalf("vsphere.New() error = %v", err)
	}
	empty := emptyVCenterCheckpoint(t)
	request := vCenterDiscoverRequest(binding, empty, 2)
	outcome, err := provider.Discover(context.Background(), runtime, request)
	request.Checkpoint.Clear()
	empty.Clear()
	if err != nil {
		t.Fatalf("Discover(partial) error = %v", err)
	}
	partial, ok := outcome.(discoverysource.Page)
	if !ok || partial.FinalPage || partial.CompleteSnapshot {
		t.Fatalf("Discover(partial) outcome = %#v", outcome)
	}
	t.Cleanup(partial.NextCheckpoint.Clear)
	accepted := applyVCenterPage(t, &scenario, partial)
	return &vCenterRolloverAdmissionFixture{
		scenario:    scenario,
		soap:        soap,
		binding:     binding,
		authority:   authority,
		broker:      broker,
		opener:      opener,
		queue:       queue,
		provider:    provider,
		runtime:     runtime,
		openRequest: openRequest,
		accepted:    accepted,
		partial:     partial,
		command: discoveryqueue.RolloverCommand{
			Coordinates:    coordinates,
			ReasonCode:     "PROVIDER_SESSION_LOST",
			EvidenceDigest: strings.Repeat("9", 64),
		},
	}
}

type vCenterRolloverPersistedState struct {
	checkpointSHA256     string
	checkpointVersion    int64
	checkpointCiphertext []byte
	pageSequence         int64
	missingCount         int64
	rolloverReason       string
	observations         int64
	relationships        int64
}

func readVCenterRolloverPersistedState(
	t *testing.T,
	fixture *vCenterRolloverAdmissionFixture,
) vCenterRolloverPersistedState {
	t.Helper()
	var state vCenterRolloverPersistedState
	if err := fixture.scenario.harness.db.QueryRow(context.Background(), `
SELECT
  COALESCE(source.checkpoint_sha256,''),
  source.checkpoint_version,
  source.checkpoint_ciphertext,
  run.page_sequence,
  run.missing_count,
  COALESCE(run.lineage_rollover_reason,''),
  (SELECT count(*) FROM asset_observations WHERE run_id=run.id),
  (SELECT count(*) FROM asset_relationships
   WHERE source_id=source.id AND last_run_id=run.id)
FROM asset_sources AS source
JOIN asset_source_runs AS run ON run.source_id=source.id
WHERE run.id=$1::uuid
`, fixture.scenario.runID).Scan(
		&state.checkpointSHA256,
		&state.checkpointVersion,
		&state.checkpointCiphertext,
		&state.pageSequence,
		&state.missingCount,
		&state.rolloverReason,
		&state.observations,
		&state.relationships,
	); err != nil {
		t.Fatalf("read vSphere rollover persisted state: %v", err)
	}
	return state
}

func assertVCenterRolloverPreflightFailureFrozen(
	t *testing.T,
	fixture *vCenterRolloverAdmissionFixture,
	fence assetcatalog.LeaseFence,
	wantErr error,
) {
	t.Helper()
	before := readVCenterRolloverPersistedState(t, fixture)
	defer clear(before.checkpointCiphertext)
	handoff, _, err := fixture.authority.BeginHandoff(
		context.Background(),
		fixture.queue,
		fence,
		fixture.openRequest,
		fixture.command,
		fixture.accepted,
		fixture.partial.NextCheckpoint,
	)
	if handoff != nil {
		handoff.Destroy()
	}
	if handoff != nil || err == nil ||
		wantErr != nil && !errors.Is(err, wantErr) {
		t.Fatalf("BeginHandoff(preflight failure) = (%#v,%v), want %v", handoff, err, wantErr)
	}
	request := vCenterDiscoverRequest(
		fixture.binding,
		fixture.partial.NextCheckpoint,
		2,
	)
	outcome, discoverErr := fixture.provider.Discover(
		context.Background(),
		fixture.runtime,
		request,
	)
	request.Checkpoint.Clear()
	if outcome != nil || discoverErr == nil {
		t.Fatalf(
			"Discover(predecessor after preflight failure) = (%#v,%v)",
			outcome,
			discoverErr,
		)
	}
	if rebound, bindErr := fixture.opener.handle.BindRuntime(
		context.Background(),
		fixture.binding,
	); rebound != (discoverysource.BoundRuntime{}) || bindErr == nil {
		t.Fatalf(
			"BindRuntime(predecessor after preflight failure) = (%#v,%v)",
			rebound,
			bindErr,
		)
	}
	after := readVCenterRolloverPersistedState(t, fixture)
	defer clear(after.checkpointCiphertext)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf(
			"preflight failure changed persisted state: checkpoint=%s/%d→%s/%d page=%d→%d missing=%d→%d rollover=%q→%q observations=%d→%d relations=%d→%d",
			before.checkpointSHA256,
			before.checkpointVersion,
			after.checkpointSHA256,
			after.checkpointVersion,
			before.pageSequence,
			after.pageSequence,
			before.missingCount,
			after.missingCount,
			before.rolloverReason,
			after.rolloverReason,
			before.observations,
			after.observations,
			before.relationships,
			after.relationships,
		)
	}
	assertVCenterProjection(
		t,
		fixture.scenario,
		len(fixture.partial.Items),
		len(fixture.partial.Relations),
		0,
	)
	proof, revokeErr := fixture.broker.RevokeAttempt(
		context.Background(),
		fixture.openRequest.Attempt.AttemptID,
	)
	if revokeErr != nil {
		t.Fatalf("RevokeAttempt(after preflight failure) error = %v", revokeErr)
	}
	if proof.Status() != assetcatalog.CredentialCleanupRevoked ||
		proof.Attempt() != fixture.openRequest.Attempt ||
		fixture.broker.VerifyCleanupProof(context.Background(), proof) != nil {
		proof.Destroy()
		t.Fatalf("RevokeAttempt(after preflight failure) proof = %#v", proof)
	}
	proof.Destroy()
	if revokeCalls, destroyCalls := fixture.opener.lifecycleCounts(); revokeCalls != 1 || destroyCalls != 1 {
		t.Fatalf(
			"preflight failure Broker lifecycle Revoke/Destroy = %d/%d, want 1/1",
			revokeCalls,
			destroyCalls,
		)
	}
}

func TestVCenterDiscoveryIntegrationLaterRunUnchangedAppendsObservation(t *testing.T) {
	first := newVCenterPageCommitScenario(
		t,
		"86a00000-0000-4000-8000-000000000014",
		"vsphere-first-unchanged-run",
	)
	soap := newVCenterSOAPFixture(t, 1, 1, "")
	empty := emptyVCenterCheckpoint(t)
	firstPages := soap.snapshotPages(
		t,
		vCenterRuntimeBinding(first),
		first.fixture.environmentID,
		empty,
		500,
	)
	empty.Clear()
	defer clearVCenterPages(firstPages)
	if len(firstPages) == 0 {
		t.Fatal("first unchanged vSphere snapshot is empty")
	}
	reserveVCenterCleanupForPageTest(t, first)
	applyVCenterPages(t, &first, firstPages)
	priorCheckpoint := firstPages[len(firstPages)-1].NextCheckpoint.Clone()
	defer priorCheckpoint.Clear()
	finishVCenterCompleteRunForTest(t, first.harness, first.fixture, first.runID)

	second := newVCenterPageCommitScenarioForFixture(
		t,
		first.harness,
		first.fixture,
		"86a00000-0000-4000-8000-000000000015",
		"vsphere-second-unchanged-run",
	)
	secondPages := soap.snapshotPages(
		t,
		vCenterRuntimeBinding(second),
		second.fixture.environmentID,
		priorCheckpoint,
		500,
	)
	defer clearVCenterPages(secondPages)
	if len(secondPages) == 0 {
		t.Fatal("second unchanged vSphere snapshot is empty")
	}
	applyVCenterPages(t, &second, secondPages)
	firstItems, firstRelations := vCenterPageCounts(firstPages)
	secondItems, secondRelations := vCenterPageCounts(secondPages)
	if firstItems != secondItems || firstRelations != secondRelations {
		t.Fatalf(
			"unchanged vSphere snapshots drifted: items %d/%d relations %d/%d",
			firstItems,
			secondItems,
			firstRelations,
			secondRelations,
		)
	}
	sampleExternalID := firstPages[0].Items[0].ExternalID

	var observations, assets, relationships int
	var lastObservationRun string
	if err := second.harness.db.QueryRow(context.Background(), `
SELECT
  (SELECT count(*) FROM asset_observations WHERE source_id=$1::uuid),
  (SELECT count(*) FROM assets WHERE source_id=$1::uuid),
  (SELECT count(*) FROM asset_relationships WHERE source_id=$1::uuid),
  (SELECT run_id::text FROM asset_observations
    WHERE source_id=$1::uuid AND external_id=$2
    ORDER BY accepted_checkpoint_version DESC LIMIT 1)
`, second.fixture.sourceID, sampleExternalID).Scan(
		&observations,
		&assets,
		&relationships,
		&lastObservationRun,
	); err != nil {
		t.Fatalf("read later-run vSphere projection: %v", err)
	}
	if observations != firstItems+secondItems ||
		assets != secondItems ||
		relationships != secondRelations ||
		lastObservationRun != second.runID {
		t.Fatalf(
			"later-run unchanged projection = observations:%d assets:%d relations:%d last:%s",
			observations,
			assets,
			relationships,
			lastObservationRun,
		)
	}
	assertVCenterProjection(t, second, secondItems, secondRelations, 0)
}

func TestVCenterDiscoveryIntegrationSessionLossRequiresGovernedRollover(t *testing.T) {
	scenario := newVCenterPageCommitScenario(
		t,
		"86a00000-0000-4000-8000-000000000016",
		"vsphere-session-loss-rollover-run",
	)
	soap := newVCenterSOAPFixture(t, 1, 1, "")
	empty := emptyVCenterCheckpoint(t)
	pages, predecessor := soap.partialSnapshotPages(
		t,
		vCenterRuntimeBinding(scenario),
		scenario.fixture.environmentID,
		empty,
		2,
	)
	empty.Clear()
	defer clearVCenterPages(pages)
	if len(pages) != 1 || pages[0].FinalPage || pages[0].CompleteSnapshot {
		t.Fatalf("production vSphere rollover fixture pages = %d", len(pages))
	}
	applyVCenterPage(t, &scenario, pages[0])

	verifier := &vSphereRolloverVerifier{}
	queue, err := queuepostgres.New(scenario.harness.application, verifier, verifier)
	if err != nil {
		t.Fatalf("queuepostgres.New() error = %v", err)
	}
	coordinates := discoveryqueue.RunCoordinates{
		Scope: assetcatalog.SourceScope{
			TenantID:    scenario.fixture.tenantID,
			WorkspaceID: scenario.fixture.workspaceID,
		},
		RunID: scenario.runID,
	}
	if _, err := queue.ReserveCleanupAttempt(
		context.Background(),
		scenario.fence,
		discoveryqueue.RunCommand{Coordinates: coordinates},
	); err != nil {
		t.Fatalf("ReserveCleanupAttempt() error = %v", err)
	}

	var checkpointBefore *string
	var checkpointVersionBefore int64
	var checkpointCiphertextBefore []byte
	if err := scenario.harness.db.QueryRow(context.Background(), `
SELECT checkpoint_sha256,checkpoint_version,checkpoint_ciphertext
FROM asset_sources WHERE id=$1::uuid
`, scenario.fixture.sourceID).Scan(
		&checkpointBefore,
		&checkpointVersionBefore,
		&checkpointCiphertextBefore,
	); err != nil {
		t.Fatalf("read checkpoint before rollover: %v", err)
	}
	command := discoveryqueue.RolloverCommand{
		Coordinates:    coordinates,
		ReasonCode:     "PROVIDER_SESSION_LOST",
		EvidenceDigest: strings.Repeat("9", 64),
	}
	bound, err := queue.BeginCheckpointLineageRollover(
		context.Background(), scenario.fence, command,
	)
	if err != nil || bound.Replayed ||
		bound.ReasonCode != command.ReasonCode ||
		bound.EvidenceDigest != command.EvidenceDigest {
		t.Fatalf("BeginCheckpointLineageRollover() = (%#v,%v)", bound, err)
	}
	replayed, err := queue.BeginCheckpointLineageRollover(
		context.Background(), scenario.fence, command,
	)
	if err != nil || !replayed.Replayed || replayed.GateRevision != bound.GateRevision {
		t.Fatalf("BeginCheckpointLineageRollover(replay) = (%#v,%v)", replayed, err)
	}

	var gateStatus, gateReason, runReason, runEvidence string
	var checkpointAfter *string
	var checkpointVersionAfter int64
	var checkpointCiphertextAfter []byte
	if err := scenario.harness.db.QueryRow(context.Background(), `
SELECT source.gate_status,source.gate_reason_code,
       source.checkpoint_sha256,source.checkpoint_version,source.checkpoint_ciphertext,
       run.lineage_rollover_reason,run.lineage_rollover_evidence_digest
FROM asset_sources AS source
JOIN asset_source_runs AS run ON run.source_id=source.id
WHERE run.id=$1::uuid
`, scenario.runID).Scan(
		&gateStatus,
		&gateReason,
		&checkpointAfter,
		&checkpointVersionAfter,
		&checkpointCiphertextAfter,
		&runReason,
		&runEvidence,
	); err != nil {
		t.Fatalf("read vSphere rollover state: %v", err)
	}
	if checkpointBefore == nil || checkpointAfter == nil ||
		*checkpointAfter != *checkpointBefore ||
		checkpointVersionAfter != checkpointVersionBefore ||
		!bytes.Equal(checkpointCiphertextAfter, checkpointCiphertextBefore) ||
		gateStatus != "DEGRADED" ||
		gateReason != "CHECKPOINT_LINEAGE_ROLLOVER" ||
		runReason != command.ReasonCode ||
		runEvidence != command.EvidenceDigest ||
		verifier.calls != 1 ||
		verifier.request.Coordinates != coordinates ||
		verifier.request.SourceID != scenario.fixture.sourceID ||
		verifier.request.ProviderKind != "VSPHERE_VCENTER_V1" ||
		verifier.request.SourceRevision != 1 ||
		verifier.request.SourceRevisionDigest != scenario.fixture.revisionDigest ||
		verifier.request.SourceDefinitionDigest != scenario.fixture.sourceDefinitionDigest ||
		verifier.request.ProfileCode != assetcatalog.ProfileCode("VSPHERE_VCENTER_V1") ||
		verifier.request.CheckpointVersion != checkpointVersionBefore ||
		verifier.request.CheckpointSHA256 != *checkpointBefore {
		t.Fatalf(
			"vSphere rollover did not preserve checkpoint and bind exact profile: gate=%s/%s checkpoint=%v/%d verifier=%d/%#v",
			gateStatus,
			gateReason,
			checkpointAfter,
			checkpointVersionAfter,
			verifier.calls,
			verifier.request,
		)
	}
	assertVCenterProjection(
		t,
		scenario,
		len(pages[0].Items),
		len(pages[0].Relations),
		0,
	)

	if err := predecessor.Revoke(context.Background()); err != nil {
		t.Fatalf("revoke governed rollover predecessor: %v", err)
	}
	ungovernedMaterial := soap.runtimeMaterial(
		t,
		scenario.fixture.environmentID,
		[]types.ManagedObjectReference{soap.root},
	)
	ungovernedSuccessor, ungovernedErr := predecessor.NewRolloverSuccessor(
		&ungovernedMaterial,
		pages[0].NextCheckpoint,
	)
	if ungovernedSuccessor != nil {
		ungovernedSuccessor.Destroy()
	}
	if ungovernedSuccessor != nil || ungovernedErr == nil {
		t.Fatalf(
			"NewRolloverSuccessor(ungoverned) = (%#v,%v)",
			ungovernedSuccessor,
			ungovernedErr,
		)
	}
	retainedAttempt, retainedErr := vsphereprovider.NewFullInventoryAttempt(
		&ungovernedMaterial,
	)
	if retainedAttempt != nil {
		retainedAttempt.Destroy()
	}
	if retainedAttempt != nil || retainedErr == nil {
		t.Fatalf(
			"ungoverned successor retained runtime material = (%#v,%v)",
			retainedAttempt,
			retainedErr,
		)
	}
	var unchangedCheckpoint *string
	var unchangedCheckpointVersion, unchangedPageSequence, unchangedMissing int64
	if err := scenario.harness.db.QueryRow(context.Background(), `
SELECT source.checkpoint_sha256,source.checkpoint_version,
       run.page_sequence,run.missing_count
FROM asset_sources AS source
JOIN asset_source_runs AS run ON run.source_id=source.id
WHERE run.id=$1::uuid
`, scenario.runID).Scan(
		&unchangedCheckpoint,
		&unchangedCheckpointVersion,
		&unchangedPageSequence,
		&unchangedMissing,
	); err != nil {
		t.Fatalf("read ungoverned rollover state: %v", err)
	}
	if unchangedCheckpoint == nil || checkpointAfter == nil ||
		*unchangedCheckpoint != *checkpointAfter ||
		unchangedCheckpointVersion != checkpointVersionAfter ||
		unchangedPageSequence != 1 ||
		unchangedMissing != 0 {
		t.Fatalf(
			"ungoverned rollover changed persisted state: checkpoint=%v/%d page=%d missing=%d",
			unchangedCheckpoint,
			unchangedCheckpointVersion,
			unchangedPageSequence,
			unchangedMissing,
		)
	}
	assertVCenterProjection(
		t,
		scenario,
		len(pages[0].Items),
		len(pages[0].Relations),
		0,
	)
}

func newVCenterPageCommitScenario(
	t *testing.T,
	runID string,
	idempotencyKey string,
) pageCommitScenario {
	t.Helper()
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedVCenterPublishedSource(t, harness.db)
	return newVCenterPageCommitScenarioForFixture(
		t, harness, fixture, runID, idempotencyKey,
	)
}

func newVCenterPageCommitScenarioWithLease(
	t *testing.T,
	runID string,
	idempotencyKey string,
	leaseDuration time.Duration,
) pageCommitScenario {
	t.Helper()
	if leaseDuration <= 0 || leaseDuration > discoveryqueue.MaxLeaseExtension {
		t.Fatalf("invalid vSphere test lease duration %s", leaseDuration)
	}
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedVCenterPublishedSource(t, harness.db)
	owner := "vsphere-page-worker"
	var rawFence [32]byte
	for index := range rawFence {
		rawFence[index] = byte(index + 21)
	}
	fenceDigest := sha256.Sum256(rawFence[:])
	var (
		revision, gateRevision, checkpointVersion int64
		revisionDigest                            string
		checkpointSHA                             *string
	)
	if err := harness.db.QueryRow(context.Background(), `
SELECT published_revision,published_revision_digest,gate_revision,
       checkpoint_version,checkpoint_sha256
FROM asset_sources
WHERE id=$1::uuid
`, fixture.sourceID).Scan(
		&revision,
		&revisionDigest,
		&gateRevision,
		&checkpointVersion,
		&checkpointSHA,
	); err != nil {
		t.Fatalf("read short-lease vSphere source: %v", err)
	}
	execAssetSQL(t, harness.db, `
INSERT INTO asset_source_runs (
  id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
  run_kind,trigger_type,gate_revision,idempotency_key,request_hash,
  cursor_before_sha256,checkpoint_version
) VALUES (
  $1,$2,$3,$4,$5,$6,'DISCOVERY','SCHEDULED',$7,$8,repeat('4',64),$9,$10
)
`, runID, fixture.tenantID, fixture.workspaceID, fixture.sourceID,
		revision, revisionDigest, gateRevision, idempotencyKey,
		checkpointSHA, checkpointVersion)
	execAssetSQL(t, harness.db, `
UPDATE asset_source_runs
SET status='RUNNING',
    stage_code='READING',
    lease_owner=$2,
    lease_expires_at=statement_timestamp()+($4::bigint*interval '1 microsecond'),
    fence_epoch=1,
    fence_token_hash=$3,
    heartbeat_sequence=1,
    heartbeat_at=statement_timestamp(),
    version=version+1
WHERE id=$1::uuid
`, runID, owner, hex.EncodeToString(fenceDigest[:]), leaseDuration.Microseconds())
	execAssetSQL(t, harness.db, `
UPDATE asset_source_runs
SET stage_code='NORMALIZING',version=version+1
WHERE id=$1::uuid
`, runID)
	fence, err := leasefence.FromQueueClaim(runID, owner, 1, &rawFence)
	if err != nil {
		t.Fatalf("FromQueueClaim(short lease) error = %v", err)
	}
	t.Cleanup(fence.Destroy)
	var master [32]byte
	for index := range master {
		master[index] = byte(index + 53)
	}
	keyring := newPageCommitKeyring(
		t,
		"vsphere-short-lease-checkpoint-key-v1",
		map[string][32]byte{
			"vsphere-short-lease-checkpoint-key-v1": master,
		},
	)
	repository, err := assetpostgres.New(
		harness.application,
		time.Now,
		uuid.NewString,
	)
	if err != nil {
		t.Fatalf("assetpostgres.New(short lease) error = %v", err)
	}
	resolver := &pageCommitPolicyResolver{
		policy: vSpherePageFactPolicy(fixture.environmentID),
	}
	committer, err := assetpostgres.NewPageCommitter(
		repository,
		keyring,
		resolver,
	)
	if err != nil {
		t.Fatalf("NewPageCommitter(short lease) error = %v", err)
	}
	return pageCommitScenario{
		harness:    harness,
		fixture:    fixture,
		repository: repository,
		committer:  committer,
		keyring:    keyring,
		resolver:   resolver,
		fence:      fence,
		coordinates: discoverysource.PageCommitCoordinates{
			Locator: assetcatalog.SourceLocator{
				Scope: assetcatalog.SourceScope{
					TenantID:    fixture.tenantID,
					WorkspaceID: fixture.workspaceID,
				},
				SourceID: fixture.sourceID,
			},
			RunID:        runID,
			PageSequence: 1,
		},
		runID:       runID,
		owner:       owner,
		fenceDigest: hex.EncodeToString(fenceDigest[:]),
		master:      master,
	}
}

func newVCenterPageCommitScenarioForFixture(
	t *testing.T,
	harness *assetCatalogHarness,
	fixture assetCatalogFixture,
	runID string,
	idempotencyKey string,
) pageCommitScenario {
	t.Helper()
	scenario := newPageCommitScenarioForFixtureWithKey(
		t,
		harness,
		fixture,
		runID,
		"vsphere-page-worker",
		idempotencyKey,
		vSpherePageFactPolicy(fixture.environmentID),
		uuid.NewString,
	)
	scenario.page.NextCheckpoint.Clear()
	scenario.page = discoverysource.Page{}
	return scenario
}

type vCenterSOAPFixture struct {
	endpointURL  string
	username     string
	password     string
	serverName   string
	certificate  *x509.Certificate
	instanceUUID string
	root         types.ManagedObjectReference
}

func newVCenterSOAPFixture(
	t *testing.T,
	machines int,
	datastores int,
	instanceUUID string,
) vCenterSOAPFixture {
	t.Helper()
	model := simulator.VPX()
	model.ClusterHost = 1
	model.Host = 0
	model.Machine = machines
	model.Datastore = datastores
	if err := model.Create(); err != nil {
		t.Fatalf("create vSphere simulator model: %v", err)
	}
	t.Cleanup(model.Remove)
	if instanceUUID != "" {
		model.ServiceContent.About.InstanceUuid = instanceUUID
	}
	model.Service.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server := model.Service.NewServer()
	t.Cleanup(server.Close)

	endpoint := *server.URL
	user := endpoint.User
	endpoint.User = nil
	if user == nil {
		t.Fatal("vSphere simulator URL has no credential")
	}
	password, ok := user.Password()
	if !ok || password == "" {
		t.Fatal("vSphere simulator URL has no password")
	}
	return vCenterSOAPFixture{
		endpointURL:  endpoint.String(),
		username:     user.Username(),
		password:     password,
		serverName:   endpoint.Hostname(),
		certificate:  server.Certificate(),
		instanceUUID: model.ServiceContent.About.InstanceUuid,
		root:         model.RootFolder.Reference(),
	}
}

func (fixture vCenterSOAPFixture) snapshotPages(
	t *testing.T,
	binding discoverysource.RuntimeBinding,
	environmentID string,
	openedCheckpoint discoverysource.Checkpoint,
	maxPageItems int64,
) []discoverysource.Page {
	t.Helper()
	pages, _ := fixture.snapshotPagesWithAttempt(
		t,
		binding,
		environmentID,
		openedCheckpoint,
		maxPageItems,
		0,
		false,
	)
	return pages
}

func (fixture vCenterSOAPFixture) replayedSnapshotPages(
	t *testing.T,
	binding discoverysource.RuntimeBinding,
	environmentID string,
	openedCheckpoint discoverysource.Checkpoint,
	maxPageItems int64,
) []discoverysource.Page {
	t.Helper()
	pages, _ := fixture.snapshotPagesWithAttempt(
		t,
		binding,
		environmentID,
		openedCheckpoint,
		maxPageItems,
		0,
		true,
	)
	return pages
}

func (fixture vCenterSOAPFixture) partialSnapshotPages(
	t *testing.T,
	binding discoverysource.RuntimeBinding,
	environmentID string,
	openedCheckpoint discoverysource.Checkpoint,
	maxPageItems int64,
) ([]discoverysource.Page, *vsphereprovider.FullInventoryAttempt) {
	t.Helper()
	return fixture.snapshotPagesWithAttempt(
		t,
		binding,
		environmentID,
		openedCheckpoint,
		maxPageItems,
		1,
		false,
	)
}

func vCenterDiscoverRequest(
	binding discoverysource.RuntimeBinding,
	checkpoint discoverysource.Checkpoint,
	maxPageItems int64,
) discoverysource.DiscoverRequest {
	return discoverysource.DiscoverRequest{
		Locator:              binding.Locator,
		SourceRevision:       binding.SourceRevision,
		SourceRevisionDigest: binding.SourceRevisionDigest,
		Checkpoint:           checkpoint.Clone(),
		Limits: discoverysource.Limits{
			MaxPageItems:     maxPageItems,
			MaxPageRelations: 2_000,
			MaxPageBytes:     8 << 20,
			MaxDocumentBytes: 64 << 10,
		},
	}
}

func collectVCenterPagesFromRuntime(
	t *testing.T,
	provider discoverysource.Provider,
	runtime discoverysource.BoundRuntime,
	binding discoverysource.RuntimeBinding,
	environmentID string,
	openedCheckpoint discoverysource.Checkpoint,
	maxPageItems int64,
) []discoverysource.Page {
	t.Helper()
	current := openedCheckpoint.Clone()
	defer current.Clear()
	pages := make([]discoverysource.Page, 0, 8)
	for len(pages) < 256 {
		request := vCenterDiscoverRequest(binding, current, maxPageItems)
		outcome, err := provider.Discover(context.Background(), runtime, request)
		if err != nil {
			request.Checkpoint.Clear()
			clearVCenterPages(pages)
			t.Fatalf("vSphere handoff successor Discover() error = %v", err)
		}
		page, ok := outcome.(discoverysource.Page)
		if !ok {
			request.Checkpoint.Clear()
			clearVCenterPages(pages)
			t.Fatalf("vSphere handoff successor outcome = %T, want Page", outcome)
		}
		if err := discoverysource.ValidateDiscoverResult(
			request,
			vSpherePageFactPolicy(environmentID),
			page,
			nil,
		); err != nil {
			request.Checkpoint.Clear()
			page.NextCheckpoint.Clear()
			clearVCenterPages(pages)
			t.Fatalf("vSphere handoff successor page violates contract: %v", err)
		}
		request.Checkpoint.Clear()
		next := page.NextCheckpoint.Clone()
		pages = append(pages, page)
		current.Clear()
		current = next
		if page.FinalPage {
			return pages
		}
	}
	clearVCenterPages(pages)
	t.Fatal("vSphere handoff successor exceeded bounded page count")
	return nil
}

func (fixture vCenterSOAPFixture) snapshotPagesWithAttempt(
	t *testing.T,
	binding discoverysource.RuntimeBinding,
	environmentID string,
	openedCheckpoint discoverysource.Checkpoint,
	maxPageItems int64,
	pageLimit int,
	replayEachPage bool,
) ([]discoverysource.Page, *vsphereprovider.FullInventoryAttempt) {
	t.Helper()
	material := fixture.runtimeMaterial(
		t,
		environmentID,
		[]types.ManagedObjectReference{fixture.root},
	)
	attempt, err := vsphereprovider.NewFullInventoryAttempt(&material)
	if err != nil {
		t.Fatalf("new vSphere full inventory attempt error = %v", err)
	}
	t.Cleanup(attempt.Destroy)
	runtime, err := attempt.BindRuntime(context.Background(), binding)
	if err != nil {
		t.Fatalf("BindRuntime() error = %v", err)
	}
	factory, err := vsphereprovider.NewClientFactory(binding)
	if err != nil {
		t.Fatalf("NewClientFactory() error = %v", err)
	}
	provider, err := vsphereprovider.New(factory)
	if err != nil {
		t.Fatalf("vsphere.New() error = %v", err)
	}

	current := openedCheckpoint.Clone()
	defer current.Clear()
	pages := make([]discoverysource.Page, 0, 4)
	for {
		callCheckpoint := current.Clone()
		request := discoverysource.DiscoverRequest{
			Locator:              binding.Locator,
			SourceRevision:       binding.SourceRevision,
			SourceRevisionDigest: binding.SourceRevisionDigest,
			Checkpoint:           callCheckpoint,
			Limits: discoverysource.Limits{
				MaxPageItems:     maxPageItems,
				MaxPageRelations: 2_000,
				MaxPageBytes:     8 << 20,
				MaxDocumentBytes: 64 << 10,
			},
		}
		outcome, discoverErr := provider.Discover(
			context.Background(),
			runtime,
			request,
		)
		if discoverErr != nil {
			callCheckpoint.Clear()
			clearVCenterPages(pages)
			t.Fatalf("vSphere Discover() error = %v", discoverErr)
		}
		page, ok := outcome.(discoverysource.Page)
		if !ok {
			callCheckpoint.Clear()
			clearVCenterPages(pages)
			t.Fatalf("vSphere Discover() outcome = %T, want Page", outcome)
		}
		if err := discoverysource.ValidateDiscoverResult(
			request,
			vSpherePageFactPolicy(environmentID),
			page,
			nil,
		); err != nil {
			callCheckpoint.Clear()
			page.NextCheckpoint.Clear()
			clearVCenterPages(pages)
			t.Fatalf("production vSphere page violates contract: %v", err)
		}
		if replayEachPage {
			replayRequest := request
			replayRequest.Checkpoint = callCheckpoint.Clone()
			replayOutcome, replayErr := provider.Discover(
				context.Background(),
				runtime,
				replayRequest,
			)
			if replayErr != nil {
				replayRequest.Checkpoint.Clear()
				callCheckpoint.Clear()
				page.NextCheckpoint.Clear()
				clearVCenterPages(pages)
				t.Fatalf("vSphere replay Discover() error = %v", replayErr)
			}
			replayedPage, replayed := replayOutcome.(discoverysource.Page)
			if !replayed {
				replayRequest.Checkpoint.Clear()
				callCheckpoint.Clear()
				page.NextCheckpoint.Clear()
				clearVCenterPages(pages)
				t.Fatalf(
					"vSphere replay Discover() outcome = %T, want Page",
					replayOutcome,
				)
			}
			if err := discoverysource.ValidateDiscoverResult(
				replayRequest,
				vSpherePageFactPolicy(environmentID),
				replayedPage,
				nil,
			); err != nil {
				replayRequest.Checkpoint.Clear()
				callCheckpoint.Clear()
				page.NextCheckpoint.Clear()
				replayedPage.NextCheckpoint.Clear()
				clearVCenterPages(pages)
				t.Fatalf("replayed production vSphere page violates contract: %v", err)
			}
			assertVCenterProviderPageReplay(t, page, replayedPage)
			replayRequest.Checkpoint.Clear()
			page.NextCheckpoint.Clear()
			page = replayedPage
		}
		callCheckpoint.Clear()
		next := page.NextCheckpoint.Clone()
		pages = append(pages, page)
		current.Clear()
		current = next
		if page.FinalPage || pageLimit > 0 && len(pages) >= pageLimit {
			return pages, attempt
		}
	}
}

func (fixture vCenterSOAPFixture) runtimeMaterial(
	t *testing.T,
	environmentID string,
	rootsValue []types.ManagedObjectReference,
) vsphereprovider.RuntimeMaterial {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(fixture.certificate)
	endpoint, err := vsphereprovider.NewEndpointHandle(fixture.endpointURL)
	if err != nil {
		t.Fatalf("NewEndpointHandle() error = %v", err)
	}
	credential, err := vsphereprovider.NewCredentialHandle(
		fixture.username,
		[]byte(fixture.password),
	)
	if err != nil {
		t.Fatalf("NewCredentialHandle() error = %v", err)
	}
	trust, err := vsphereprovider.NewTrustHandle(&tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
		ServerName: fixture.serverName,
	}, vsphereprovider.TLSCompatibilityStrict)
	if err != nil {
		t.Fatalf("NewTrustHandle() error = %v", err)
	}
	authority, err := vsphereprovider.NewAuthorityHandle(
		fixture.instanceUUID,
		environmentID,
		rootsValue,
	)
	if err != nil {
		t.Fatalf("NewAuthorityHandle() error = %v", err)
	}
	material, err := vsphereprovider.NewRuntimeMaterial(
		endpoint,
		credential,
		trust,
		authority,
	)
	if err != nil {
		t.Fatalf("NewRuntimeMaterial() error = %v", err)
	}
	return material
}

func vCenterRuntimeBinding(
	scenario pageCommitScenario,
) discoverysource.RuntimeBinding {
	return discoverysource.RuntimeBinding{
		Locator:              scenario.coordinates.Locator,
		SourceRevision:       1,
		SourceRevisionDigest: scenario.fixture.revisionDigest,
		RevisionStatus:       assetcatalog.SourceRevisionPublished,
		ProviderKind:         "VSPHERE_VCENTER_V1",
		ProfileCode:          assetcatalog.ProfileCode("VSPHERE_VCENTER_V1"),
	}
}

func emptyVCenterCheckpoint(t *testing.T) discoverysource.Checkpoint {
	t.Helper()
	checkpoint, err := discoverysource.NewCheckpoint(
		assetcatalog.ProfileCode("VSPHERE_VCENTER_V1"),
		nil,
	)
	if err != nil {
		t.Fatalf("NewCheckpoint() error = %v", err)
	}
	return checkpoint
}

func clearVCenterPages(pages []discoverysource.Page) {
	for index := range pages {
		pages[index].NextCheckpoint.Clear()
	}
}

func assertVCenterProviderPageReplay(
	t *testing.T,
	first discoverysource.Page,
	replayed discoverysource.Page,
) {
	t.Helper()
	if !reflect.DeepEqual(first.Items, replayed.Items) ||
		!reflect.DeepEqual(first.Relations, replayed.Relations) ||
		!first.NextCheckpoint.Equal(replayed.NextCheckpoint) ||
		first.FinalPage != replayed.FinalPage ||
		first.CompleteSnapshot != replayed.CompleteSnapshot {
		t.Fatalf(
			"vSphere provider replay drifted: items=%t relations=%t checkpoint=%t final=%t/%t complete=%t/%t",
			reflect.DeepEqual(first.Items, replayed.Items),
			reflect.DeepEqual(first.Relations, replayed.Relations),
			first.NextCheckpoint.Equal(replayed.NextCheckpoint),
			first.FinalPage,
			replayed.FinalPage,
			first.CompleteSnapshot,
			replayed.CompleteSnapshot,
		)
	}
}

func vCenterPageCounts(pages []discoverysource.Page) (int, int) {
	var items, relations int
	for _, page := range pages {
		items += len(page.Items)
		relations += len(page.Relations)
	}
	return items, relations
}

func vCenterItemIDs(pages []discoverysource.Page) map[string]struct{} {
	identities := make(map[string]struct{})
	for _, page := range pages {
		for _, item := range page.Items {
			identities[item.ExternalID] = struct{}{}
		}
	}
	return identities
}

type vCenterRelationshipFreshness struct {
	id                    string
	status                string
	kind                  string
	orderSequence         int64
	acceptedCheckpoint    int64
	providerVersionSHA256 string
	relationFactSHA256    string
}

func readVCenterRelationshipFreshness(
	t *testing.T,
	database *pgxpool.Pool,
	sourceID string,
	externalID string,
) []vCenterRelationshipFreshness {
	t.Helper()
	rows, err := database.Query(context.Background(), `
SELECT id::text,status,freshness_kind,freshness_order_sequence,
       accepted_checkpoint_version,provider_version_sha256,relation_fact_sha256
FROM asset_relationships
WHERE source_id=$1::uuid
  AND (from_external_id=$2 OR to_external_id=$2)
ORDER BY id
`, sourceID, externalID)
	if err != nil {
		t.Fatalf("read vSphere relationship freshness: %v", err)
	}
	defer rows.Close()
	values := make([]vCenterRelationshipFreshness, 0)
	for rows.Next() {
		var value vCenterRelationshipFreshness
		if err := rows.Scan(
			&value.id,
			&value.status,
			&value.kind,
			&value.orderSequence,
			&value.acceptedCheckpoint,
			&value.providerVersionSHA256,
			&value.relationFactSHA256,
		); err != nil {
			t.Fatalf("scan vSphere relationship freshness: %v", err)
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate vSphere relationship freshness: %v", err)
	}
	return values
}

func assertVCenterMissingRelationshipFreshnessAdvanced(
	t *testing.T,
	before []vCenterRelationshipFreshness,
	after []vCenterRelationshipFreshness,
) {
	t.Helper()
	if len(after) != len(before) {
		t.Fatalf("missing vSphere relationship rows changed from %d to %d", len(before), len(after))
	}
	for index := range before {
		prior := before[index]
		current := after[index]
		if prior.id != current.id ||
			prior.status != "ACTIVE" ||
			current.status != "INACTIVE" ||
			prior.kind != string(assetcatalog.FreshnessCheckpointSequence) ||
			current.kind != string(assetcatalog.FreshnessCheckpointSequence) ||
			prior.orderSequence != prior.acceptedCheckpoint ||
			current.orderSequence != current.acceptedCheckpoint ||
			current.acceptedCheckpoint <= prior.acceptedCheckpoint ||
			current.providerVersionSHA256 != prior.providerVersionSHA256 ||
			current.relationFactSHA256 != prior.relationFactSHA256 {
			t.Fatalf(
				"missing vSphere relationship freshness drifted: before=%#v after=%#v",
				prior,
				current,
			)
		}
	}
}

func applyVCenterPages(
	t *testing.T,
	scenario *pageCommitScenario,
	pages []discoverysource.Page,
) []discoverysource.PageCommitResult {
	t.Helper()
	results := make([]discoverysource.PageCommitResult, 0, len(pages))
	for _, page := range pages {
		results = append(results, applyVCenterPage(t, scenario, page))
	}
	return results
}

func applyVCenterPage(
	t *testing.T,
	scenario *pageCommitScenario,
	page discoverysource.Page,
) discoverysource.PageCommitResult {
	t.Helper()
	var pageSequence int64
	var stage string
	if err := scenario.harness.db.QueryRow(context.Background(), `
SELECT page_sequence,stage_code
FROM asset_source_runs
WHERE id=$1::uuid
`, scenario.runID).Scan(&pageSequence, &stage); err != nil {
		t.Fatalf("read vSphere page coordinates: %v", err)
	}
	if pageSequence > 0 && stage == string(assetcatalog.RunStageReading) {
		execAssetSQL(t, scenario.harness.db, `
UPDATE asset_source_runs
SET stage_code='NORMALIZING',version=version+1
WHERE id=$1::uuid AND stage_code='READING'
`, scenario.runID)
	}
	scenario.coordinates.PageSequence = pageSequence + 1
	scenario.page = page
	result, err := scenario.committer.ApplyPage(
		context.Background(),
		scenario.fence,
		scenario.coordinates,
		page,
	)
	if err != nil {
		t.Fatalf(
			"ApplyPage(sequence %d items=%d relations=%d final=%t complete=%t) error = %v",
			pageSequence+1,
			len(page.Items),
			len(page.Relations),
			page.FinalPage,
			page.CompleteSnapshot,
			err,
		)
	}
	return result
}

func reserveVCenterCleanupForPageTest(
	t *testing.T,
	scenario pageCommitScenario,
) {
	t.Helper()
	execAssetSQL(t, scenario.harness.db, `
UPDATE asset_source_runs
SET cleanup_status='PENDING',cleanup_attempt_id=gen_random_uuid(),
    cleanup_attempt_epoch=fence_epoch,version=version+1
WHERE id=$1::uuid
`, scenario.runID)
}

func assertVCenterMissing(
	t *testing.T,
	scenario pageCommitScenario,
	want int64,
) {
	t.Helper()
	var missing int64
	if err := scenario.harness.db.QueryRow(
		context.Background(),
		`SELECT missing_count FROM asset_source_runs WHERE id=$1::uuid`,
		scenario.runID,
	).Scan(&missing); err != nil {
		t.Fatalf("read vSphere missing count: %v", err)
	}
	if missing != want {
		t.Fatalf("vSphere missing count = %d, want %d", missing, want)
	}
}

func seedVCenterPublishedSource(
	t *testing.T,
	database *pgxpool.Pool,
) assetCatalogFixture {
	t.Helper()
	fixture := seedDraftAssetCatalog(t, database)
	fixture.sourceID = "86a00000-0000-4000-8000-000000000001"
	fixture.revisionID = "86a00000-0000-4000-8000-000000000002"
	fixture.validationRunID = "86a00000-0000-4000-8000-000000000003"

	profile := []byte(vSphereProfileManifestV1)
	providerSchema := []byte(`{"type":"object"}`)
	profileDigest := sha256.Sum256(profile)
	providerSchemaDigest := sha256.Sum256(providerSchema)
	authorityDigest := assetCatalogCorrectiveFramedDigest(
		[]byte("asset-source-authority-scope.v1"),
		[]byte("1"),
		[]byte(fixture.environmentID),
	)
	fixture.sourceDefinitionDigest = assetCatalogCorrectiveFramedDigest(
		[]byte("asset-source-definition.v2"),
		[]byte("VSPHERE"),
		[]byte("VSPHERE_VCENTER_V1"),
		[]byte("VSPHERE_VCENTER_V1"),
		profileDigest[:],
		providerSchemaDigest[:],
	)
	fixture.revisionDigest = assetCatalogCorrectiveFramedDigest(
		[]byte("asset-source-revision-binding.v1"),
		[]byte(fixture.tenantID),
		[]byte(fixture.workspaceID),
		[]byte(fixture.sourceID),
		[]byte("1"),
		assetCatalogCorrectiveDecodeDigest(t, fixture.sourceDefinitionDigest),
		[]byte(fixture.integrationID),
		[]byte("ON_DEMAND"),
		[]byte("opaque-credential"),
		[]byte("opaque-trust"),
		[]byte("opaque-network"),
		assetCatalogCorrectiveDecodeDigest(t, authorityDigest),
		[]byte("100"),
		[]byte("60"),
		[]byte("1"),
		[]byte("60"),
		[]byte("VSPHERE_VCENTER_V1"),
		nil,
		nil,
		nil,
	)

	transaction, err := database.BeginTx(
		context.Background(),
		pgx.TxOptions{IsoLevel: pgx.Serializable},
	)
	if err != nil {
		t.Fatalf("begin vSphere source definition: %v", err)
	}
	defer func() { _ = transaction.Rollback(context.Background()) }()
	execAssetSQL(t, transaction, `
INSERT INTO asset_sources (
 id,tenant_id,workspace_id,source_kind,provider_kind,name,
 create_idempotency_key,create_request_hash
) VALUES ($1,$2,$3,'VSPHERE','VSPHERE_VCENTER_V1','vSphere closed source',
          'vsphere-source-definition',repeat('1',64))
`, fixture.sourceID, fixture.tenantID, fixture.workspaceID)
	execAssetSQL(t, transaction, `
INSERT INTO asset_source_revisions (
 id,tenant_id,workspace_id,source_id,revision,
 canonical_profile_manifest,profile_manifest_sha256,
 canonical_provider_schema,canonical_provider_schema_sha256,integration_id,sync_mode,
 authority_scope_digest,source_definition_digest,canonical_revision_digest,
 credential_reference_id,trust_reference_id,network_policy_reference_id,
 rate_limit_requests,rate_limit_window_seconds,
 backpressure_base_seconds,backpressure_max_seconds,profile_code,
 created_by,change_reason_code,expected_source_version
) SELECT $1,$2,$3,$4,1,$5,$6,$7,$8,$9,'ON_DEMAND',
         $10,$11,$12,'opaque-credential','opaque-trust','opaque-network',
         100,60,1,60,'VSPHERE_VCENTER_V1',
         'vsphere-test','INITIAL_CREATE',source.version
  FROM asset_sources AS source WHERE source.id=$4
`, fixture.revisionID, fixture.tenantID, fixture.workspaceID, fixture.sourceID,
		profile, hex.EncodeToString(profileDigest[:]), providerSchema,
		hex.EncodeToString(providerSchemaDigest[:]), fixture.integrationID,
		authorityDigest, fixture.sourceDefinitionDigest, fixture.revisionDigest)
	execAssetSQL(t, transaction, `
INSERT INTO asset_source_revision_authorities (
 tenant_id,workspace_id,source_id,source_revision,environment_id,canonical_ordinal
) VALUES ($1,$2,$3,1,$4,1)
`, fixture.tenantID, fixture.workspaceID, fixture.sourceID, fixture.environmentID)
	if err := transaction.Commit(context.Background()); err != nil {
		t.Fatalf("commit vSphere source definition: %v", err)
	}

	execAssetSQL(t, database, `
INSERT INTO asset_source_runs (
 id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
 run_kind,trigger_type,gate_revision,idempotency_key,request_hash,checkpoint_version
) SELECT $1,$2,$3,$4,1,$5,'VALIDATION','HUMAN',gate_revision,
         'vsphere-validation',repeat('5',64),0
  FROM asset_sources WHERE id=$4
`, fixture.validationRunID, fixture.tenantID, fixture.workspaceID,
		fixture.sourceID, fixture.revisionDigest)
	execAssetSQL(t, database, `
UPDATE asset_source_revisions
SET state='VALIDATING',validation_run_id=$2,version=version+1 WHERE id=$1
`, fixture.revisionID, fixture.validationRunID)
	execAssetSQL(t, database, `
UPDATE asset_sources
SET gate_status='VALIDATING',gate_revision=gate_revision+1,
    validated_run_id=$2,validation_digest=NULL,validated_binding_digest=NULL,
    version=version+1
WHERE id=$1
`, fixture.sourceID, fixture.validationRunID)
	execAssetSQL(t, database, `
UPDATE asset_source_runs
SET status='RUNNING',stage_code='VALIDATING',lease_owner='vsphere-validation-worker',
    lease_expires_at=statement_timestamp()+interval '10 minutes',fence_epoch=1,
    fence_token_hash=repeat('6',64),heartbeat_sequence=1,
    heartbeat_at=statement_timestamp(),version=version+1
WHERE id=$1
`, fixture.validationRunID)
	finishClosureExternalValidation(t, database, fixture, 1, strings.Repeat("7", 64))
	return fixture
}

func vSpherePageFactPolicy(environmentID string) assetdiscovery.FactPolicy {
	documentFields := []string{
		"connection_state",
		"cpu_count",
		"guest_family_code",
		"memory_mb",
		"object_type",
		"power_state",
	}
	return assetdiscovery.FactPolicy{
		ProviderKind:            "VSPHERE_VCENTER_V1",
		FreshnessKind:           assetcatalog.FreshnessCheckpointSequence,
		EnvironmentMapping:      assetcatalog.EnvironmentMappingSingle,
		AuthorityEnvironmentIDs: []string{environmentID},
		TrustedPathCodes: []string{
			"VSPHERE_V1_CONTAINS",
			"VSPHERE_V1_DISPLAY_NAME",
			"VSPHERE_V1_ENVIRONMENT_ID",
			"VSPHERE_V1_EXTERNAL_ID",
			"VSPHERE_V1_KIND",
			"VSPHERE_V1_PROVIDER_KIND",
			"VSPHERE_V1_RUNS_ON",
			"VSPHERE_V1_TYPE_DETAILS",
		},
		RelationshipTypes: []assetcatalog.RelationshipType{
			assetcatalog.RelationshipContains,
			assetcatalog.RelationshipRunsOn,
		},
		AllowedDocumentFields: map[assetcatalog.Kind][]string{
			assetcatalog.KindCloudResource: slices.Clone(documentFields),
			assetcatalog.KindBareMetalHost: slices.Clone(documentFields),
			assetcatalog.KindLinuxVM:       slices.Clone(documentFields),
			assetcatalog.KindWindowsVM:     slices.Clone(documentFields),
		},
	}
}

func assertVCenterProjection(
	t *testing.T,
	scenario pageCommitScenario,
	wantObservations int,
	wantRelationships int,
	wantMissing int64,
) {
	t.Helper()
	var observations, relationships int
	var missing int64
	if err := scenario.harness.db.QueryRow(context.Background(), `
SELECT
  (SELECT count(*) FROM asset_observations WHERE run_id=$1::uuid),
  (SELECT count(*) FROM asset_relationships
    WHERE source_id=$2::uuid AND last_run_id=$1::uuid),
  missing_count
FROM asset_source_runs
WHERE id=$1::uuid
`, scenario.runID, scenario.fixture.sourceID).Scan(
		&observations,
		&relationships,
		&missing,
	); err != nil {
		t.Fatalf("read vSphere projection counts: %v", err)
	}
	if observations != wantObservations ||
		relationships != wantRelationships ||
		missing != wantMissing {
		t.Fatalf(
			"vSphere projection observations/relations/missing = %d/%d/%d, want %d/%d/%d",
			observations,
			relationships,
			missing,
			wantObservations,
			wantRelationships,
			wantMissing,
		)
	}
}

func finishVCenterCompleteRunForTest(
	t *testing.T,
	harness *assetCatalogHarness,
	fixture assetCatalogFixture,
	runID string,
) {
	t.Helper()
	revokeClosureAttempt(t, harness.db, fixture, runID, strings.Repeat("c", 64))
	transaction, err := harness.db.BeginTx(
		context.Background(),
		pgx.TxOptions{IsoLevel: pgx.Serializable},
	)
	if err != nil {
		t.Fatalf("begin vSphere complete terminal closure: %v", err)
	}
	defer func() { _ = transaction.Rollback(context.Background()) }()
	terminalDigest := sourceRunTerminalDigest(
		t,
		transaction,
		runID,
		"SUCCEEDED",
		nil,
	)
	insertTerminalAudit(t, transaction, fixture, runID, terminalDigest)
	execAssetSQL(t, transaction, `
UPDATE asset_source_runs
SET status='SUCCEEDED',stage_code='COMPLETED',terminal_command_sha256=$2,
    version=version+1
WHERE id=$1::uuid
`, runID, terminalDigest)
	execAssetSQL(t, transaction, `
UPDATE asset_sources
SET last_success_run_id=$2::uuid,
    last_success_at=(SELECT completed_at FROM asset_source_runs WHERE id=$2::uuid),
    last_complete_snapshot_run_id=$2::uuid,
    last_complete_snapshot_at=(SELECT completed_at FROM asset_source_runs WHERE id=$2::uuid),
    version=version+1
WHERE id=$1::uuid
`, fixture.sourceID, runID)
	if err := transaction.Commit(context.Background()); err != nil {
		t.Fatalf("commit vSphere complete terminal closure: %v", err)
	}
}

type vCenterBrokerRolloverOpener struct {
	mu        sync.Mutex
	authority *vsphereprovider.FullInventoryRolloverAuthority
	material  *vsphereprovider.RuntimeMaterial
	handle    *vCenterBrokerRolloverHandle
}

func (opener *vCenterBrokerRolloverOpener) OpenSession(
	ctx context.Context,
	request discoverycleanup.OpenAttemptRequest,
) (discoverycleanup.SessionHandle, error) {
	opener.mu.Lock()
	defer opener.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || opener.authority == nil ||
		opener.material == nil || opener.handle != nil {
		return nil, errors.New("vCenter rollover opener rejected")
	}
	attempt, err := opener.authority.NewAttempt(opener.material, request)
	opener.material = nil
	if err != nil {
		return nil, err
	}
	handle := &vCenterBrokerRolloverHandle{attempt: attempt}
	opener.handle = handle
	return handle, nil
}

func (opener *vCenterBrokerRolloverOpener) lifecycleCounts() (int, int) {
	opener.mu.Lock()
	handle := opener.handle
	opener.mu.Unlock()
	if handle == nil {
		return 0, 0
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	return handle.revokeCalls, handle.destroyCalls
}

type vCenterBrokerRolloverHandle struct {
	mu           sync.Mutex
	attempt      *vsphereprovider.FullInventoryAttempt
	revokeCalls  int
	destroyCalls int
}

func (handle *vCenterBrokerRolloverHandle) BindRuntime(
	ctx context.Context,
	binding discoverysource.RuntimeBinding,
) (discoverysource.BoundRuntime, error) {
	handle.mu.Lock()
	attempt := handle.attempt
	handle.mu.Unlock()
	if attempt == nil {
		return discoverysource.BoundRuntime{}, errors.New("vCenter rollover handle closed")
	}
	return attempt.BindRuntime(ctx, binding)
}

func (handle *vCenterBrokerRolloverHandle) Revoke(ctx context.Context) error {
	handle.mu.Lock()
	handle.revokeCalls++
	attempt := handle.attempt
	handle.mu.Unlock()
	if attempt == nil {
		return errors.New("vCenter rollover handle closed")
	}
	return attempt.Revoke(ctx)
}

func (handle *vCenterBrokerRolloverHandle) Destroy() {
	handle.mu.Lock()
	handle.destroyCalls++
	attempt := handle.attempt
	handle.attempt = nil
	handle.mu.Unlock()
	if attempt != nil {
		attempt.Destroy()
	}
}

type vCenterBrokerProofAuthority struct {
	key []byte
}

func (authority *vCenterBrokerProofAuthority) SignCleanupProof(
	ctx context.Context,
	digest []byte,
) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || len(digest) != sha256.Size ||
		len(authority.key) == 0 {
		return nil, errors.New("vCenter cleanup proof rejected")
	}
	mac := hmac.New(sha256.New, authority.key)
	_, _ = mac.Write(digest)
	return mac.Sum(nil), nil
}

func (authority *vCenterBrokerProofAuthority) VerifyCleanupProof(
	ctx context.Context,
	digest []byte,
	signature []byte,
) error {
	expected, err := authority.SignCleanupProof(ctx, digest)
	if err != nil {
		return err
	}
	defer clear(expected)
	if !hmac.Equal(expected, signature) {
		return errors.New("vCenter cleanup proof rejected")
	}
	return nil
}

type vCenterRolloverResponseLossQueue struct {
	discoveryqueue.Queue

	mu      sync.Mutex
	dropped bool
}

func (queue *vCenterRolloverResponseLossQueue) BeginCheckpointLineageRollover(
	ctx context.Context,
	fence assetcatalog.LeaseFence,
	command discoveryqueue.RolloverCommand,
) (discoveryqueue.RolloverResult, error) {
	result, err := queue.Queue.BeginCheckpointLineageRollover(ctx, fence, command)
	if err != nil {
		return discoveryqueue.RolloverResult{}, err
	}
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if !queue.dropped {
		queue.dropped = true
		return discoveryqueue.RolloverResult{}, discoveryqueue.ErrUnavailable
	}
	return result, nil
}

type vSphereRolloverVerifier struct {
	calls   int
	request discoveryqueue.CheckpointLineageRolloverRequest
}

func (*vSphereRolloverVerifier) VerifyCleanupProof(
	context.Context,
	discoveryqueue.CleanupProof,
) error {
	return nil
}

func (verifier *vSphereRolloverVerifier) VerifyCheckpointLineageRollover(
	_ context.Context,
	request discoveryqueue.CheckpointLineageRolloverRequest,
) error {
	verifier.calls++
	verifier.request = request
	return nil
}
