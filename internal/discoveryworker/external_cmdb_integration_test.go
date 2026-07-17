package discoveryworker_test

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
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
	"github.com/seaworld008/aiops-system/internal/assetsource/externalcmdb"
	"github.com/seaworld008/aiops-system/internal/discoverycheckpoint"
	"github.com/seaworld008/aiops-system/internal/discoverycleanup"
	"github.com/seaworld008/aiops-system/internal/discoverylimit"
	limitpostgres "github.com/seaworld008/aiops-system/internal/discoverylimit/postgres"
	"github.com/seaworld008/aiops-system/internal/discoveryqueue"
	queuepostgres "github.com/seaworld008/aiops-system/internal/discoveryqueue/postgres"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
	"github.com/seaworld008/aiops-system/internal/discoveryworker"
	"github.com/seaworld008/aiops-system/internal/sourceprofile"
)

const task18BProviderKind = "CMDB_CATALOG_V1"

func TestExternalCMDBTask18BWorkerCrashReclaimResponseLossPostgres(t *testing.T) {
	system := newTask18BSystem(t, task18BWireComplete, task18BOptions{
		responseLoss: true,
	})
	runID := system.seedDataRun(t, "crash-reclaim")
	crashed, err := system.realQueue.Claim(t.Context(), discoveryqueue.ClaimCommand{
		Owner:         "task18b-crashed-worker",
		LeaseDuration: 100 * time.Millisecond,
		ProviderKinds: []string{task18BProviderKind},
	})
	if err != nil {
		t.Fatalf("Claim(crashed worker) error = %v", err)
	}
	if crashed.Run.ID != runID || crashed.Run.FenceEpoch != 1 {
		t.Fatalf("crashed claim = %s/%d, want %s/1", crashed.Run.ID, crashed.Run.FenceEpoch, runID)
	}
	crashed.Destroy()
	pageReceipts, terminalReceipts, observations := system.sideEffectCounts(t, runID)
	if pageReceipts != 0 || terminalReceipts != 0 || observations != 0 ||
		system.readRun(t, runID).checkpointVersion != 0 {
		t.Fatalf("crash-before-commit wrote page/terminal/observations/checkpoint=%d/%d/%d/%d",
			pageReceipts, terminalReceipts, observations,
			system.readRun(t, runID).checkpointVersion)
	}
	time.Sleep(150 * time.Millisecond)
	system.resetEvidence()

	runErr := system.runUntil(t, runID, func(snapshot task18BRunSnapshot) bool {
		return snapshot.status == "SUCCEEDED"
	})
	if !errors.Is(runErr, context.Canceled) {
		t.Fatalf("Worker.Run() error = %v, want cancellation after terminal observation", runErr)
	}
	snapshot := system.readRun(t, runID)
	if snapshot.status != "SUCCEEDED" || snapshot.stage != "COMPLETED" ||
		snapshot.fenceEpoch != 2 || snapshot.pageSequence != 2 ||
		snapshot.checkpointVersion != 2 || !snapshot.effectiveComplete ||
		snapshot.cleanupStatus != "REVOKED" || snapshot.missing != 0 {
		t.Fatalf("durable reclaimed run = %#v", snapshot)
	}
	system.assertCompleteProjection(t, runID)
	if system.queue.reserveCalls != 2 || system.queue.cleanupCalls != 2 ||
		system.queue.completeCalls != 2 {
		t.Fatalf("response-loss calls reserve/cleanup/complete = %d/%d/%d, want 2/2/2",
			system.queue.reserveCalls, system.queue.cleanupCalls, system.queue.completeCalls)
	}
	if system.resolver.calls() != 1 || system.opener.boundCalls() != 1 ||
		system.server.callCount() != 3 || !system.opener.boundRuntimeCleared() {
		t.Fatalf("same-attempt runtime resolver/bind/http/clear = %d/%d/%d/%t",
			system.resolver.calls(), system.opener.boundCalls(),
			system.server.callCount(), system.opener.boundRuntimeCleared())
	}
	events := system.events.snapshot()
	lastPage := -1
	for index, event := range events {
		if event == "apply-page" {
			lastPage = index
		}
	}
	if lastPage < 0 {
		t.Fatalf("final page event missing from %v", events)
	}
	requireTask18BOrderedEvents(t, events[lastPage:],
		"apply-page", "heartbeat", "limiter-release", "runtime-clear",
		"revoke", "destroy", "record-cleanup", "complete")
	requireNoTask18BHeartbeatAfter(t, events, "record-cleanup")
}

func TestExternalCMDBTask18BWorkerPartialAndTimeoutDoNotMarkMissingPostgres(t *testing.T) {
	t.Run("partial", func(t *testing.T) {
		system := newTask18BSystem(t, task18BWirePartial, task18BOptions{})
		runID := system.seedDataRun(t, "partial")
		runErr := system.worker.Run(context.Background())
		if !errors.Is(runErr, discoveryworker.ErrWorkerUnavailable) {
			t.Fatalf("Worker.Run(partial) error = %v", runErr)
		}
		snapshot := system.readRun(t, runID)
		if snapshot.status != "FAILED" || snapshot.stage != "COMPLETED" ||
			snapshot.pageSequence != 1 || snapshot.effectiveComplete ||
			snapshot.completeSnapshot || snapshot.missing != 0 || snapshot.stale != 0 ||
			snapshot.cleanupStatus != "REVOKED" {
			t.Fatalf("partial run marked missing/stale = %#v", snapshot)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		system := newTask18BSystem(t, task18BWireTimeout, task18BOptions{})
		runID := system.seedDataRun(t, "timeout")
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		runErr := system.worker.Run(ctx)
		if !errors.Is(runErr, context.DeadlineExceeded) {
			t.Fatalf("Worker.Run(timeout) error = %v", runErr)
		}
		snapshot := system.readRun(t, runID)
		if snapshot.status != "FAILED" || snapshot.stage != "COMPLETED" ||
			snapshot.missing != 0 || snapshot.stale != 0 ||
			snapshot.cleanupStatus != "REVOKED" {
			t.Fatalf("timeout run closure = %#v", snapshot)
		}
		if !system.opener.boundRuntimeCleared() {
			t.Fatal("timeout runtime material was not zeroized")
		}
	})
}

func TestExternalCMDBTask18BWorkerDelayPersistsIntentAndCleansBeforeQueueDelayPostgres(t *testing.T) {
	system := newTask18BSystem(t, task18BWireDelay, task18BOptions{})
	runID := system.seedDataRun(t, "delay")
	system.resetEvidence()
	runErr := system.runUntil(t, runID, func(snapshot task18BRunSnapshot) bool {
		return snapshot.status == "DELAYED"
	})
	if !errors.Is(runErr, context.Canceled) {
		t.Fatalf("Worker.Run(delay) error = %v", runErr)
	}
	snapshot := system.readRun(t, runID)
	if snapshot.status != "DELAYED" || snapshot.stage != "DELAYED" ||
		snapshot.cleanupStatus != "REVOKED" || snapshot.pageSequence != 0 ||
		snapshot.pendingTransition {
		t.Fatalf("durable delay closure = %#v", snapshot)
	}
	requireTask18BOrderedEvents(t, system.events.snapshot(),
		"advance-delay-intent", "limiter-delay", "runtime-clear",
		"revoke", "destroy", "record-cleanup", "queue-delay")
	requireNoTask18BHeartbeatAfter(t, system.events.snapshot(), "record-cleanup")
	if system.queue.delayCalls != 1 || system.page.applyCalls != 0 ||
		system.server.callCount() != 2 || !system.opener.boundRuntimeCleared() {
		t.Fatalf("delay calls queue/page/http/clear = %d/%d/%d/%t",
			system.queue.delayCalls, system.page.applyCalls,
			system.server.callCount(), system.opener.boundRuntimeCleared())
	}
}

func TestExternalCMDBTask18BWorkerFixedWireTombstoneRestorePostgres(t *testing.T) {
	system := newTask18BSystem(t, task18BWireComplete, task18BOptions{})
	initialRunID := system.seedDataRun(t, "tombstone-initial")
	if err := system.runUntil(t, initialRunID, func(snapshot task18BRunSnapshot) bool {
		return snapshot.status == "SUCCEEDED"
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Worker.Run(initial tombstone fixture) error = %v", err)
	}
	task18BExec(t, system.harness.db, `
UPDATE assets SET lifecycle='ACTIVE',version=version+1 WHERE source_id=$1::uuid
`, system.source.sourceID)

	system.server.setMode(task18BWireTombstone)
	system.resetEvidence()
	time.Sleep(250 * time.Millisecond)
	tombstoneRunID := system.seedDataRun(t, "fixed-wire-tombstone")
	if err := system.runUntil(t, tombstoneRunID, func(snapshot task18BRunSnapshot) bool {
		return snapshot.status == "SUCCEEDED"
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Worker.Run(tombstone) error = %v", err)
	}
	var lifecycle, relationStatus, reason string
	var tombstoned, stale, observations int64
	var deleted bool
	if err := system.harness.db.QueryRow(t.Context(), `
SELECT asset.lifecycle,relationship.status,run.tombstoned_count,run.stale_count,
       observation.tombstone,observation.tombstone_reason_code,
       (SELECT count(*) FROM asset_observations
        WHERE source_id=$1::uuid AND external_id='task18b-host-a')
FROM assets AS asset
JOIN asset_observations AS observation ON observation.id=asset.last_observation_id
JOIN asset_relationships AS relationship
  ON relationship.source_id=asset.source_id AND relationship.source_asset_id=asset.id
JOIN asset_source_runs AS run ON run.id=$2::uuid
WHERE asset.source_id=$1::uuid AND asset.external_id='task18b-host-a'
`, system.source.sourceID, tombstoneRunID).Scan(
		&lifecycle, &relationStatus, &tombstoned, &stale,
		&deleted, &reason, &observations,
	); err != nil {
		t.Fatalf("read fixed-wire tombstone projection: %v", err)
	}
	if lifecycle != "STALE" || relationStatus != "INACTIVE" ||
		tombstoned != 1 || stale != 1 || !deleted ||
		reason != "PROVIDER_DELETED" || observations != 2 {
		t.Fatalf("fixed-wire tombstone lifecycle=%s relation=%s counts=%d/%d deleted=%t/%s history=%d",
			lifecycle, relationStatus, tombstoned, stale, deleted, reason, observations)
	}
	requireNoTask18BHeartbeatAfter(t, system.events.snapshot(), "record-cleanup")

	system.server.setMode(task18BWireRestore)
	system.resetEvidence()
	time.Sleep(250 * time.Millisecond)
	restoreRunID := system.seedDataRun(t, "fixed-wire-restore")
	if err := system.runUntil(t, restoreRunID, func(snapshot task18BRunSnapshot) bool {
		return snapshot.status == "SUCCEEDED"
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Worker.Run(restore) error = %v", err)
	}
	var restored, restoreAudit, restoreOutbox int64
	if err := system.harness.db.QueryRow(t.Context(), `
SELECT asset.lifecycle,relationship.status,run.restored_count,
       (SELECT count(*) FROM asset_observations
        WHERE source_id=$1::uuid AND external_id='task18b-host-a'),
       (SELECT count(*) FROM audit_records
        WHERE resource_id=asset.id::text AND action='asset.source.asset.restored.v1'),
       (SELECT count(*) FROM outbox_events
        WHERE aggregate_id=asset.id AND event_type='asset.source.asset.restored.v1')
FROM assets AS asset
JOIN asset_relationships AS relationship
  ON relationship.source_id=asset.source_id AND relationship.source_asset_id=asset.id
JOIN asset_source_runs AS run ON run.id=$2::uuid
WHERE asset.source_id=$1::uuid AND asset.external_id='task18b-host-a'
`, system.source.sourceID, restoreRunID).Scan(
		&lifecycle, &relationStatus, &restored, &observations,
		&restoreAudit, &restoreOutbox,
	); err != nil {
		t.Fatalf("read fixed-wire restore projection: %v", err)
	}
	if lifecycle != "STALE" || relationStatus != "ACTIVE" ||
		restored != 1 || observations != 3 || restoreAudit != 1 || restoreOutbox != 1 {
		t.Fatalf("fixed-wire restore lifecycle=%s relation=%s restored/history=%d/%d evidence=%d/%d",
			lifecycle, relationStatus, restored, observations, restoreAudit, restoreOutbox)
	}
	requireNoTask18BHeartbeatAfter(t, system.events.snapshot(), "record-cleanup")
}

func TestExternalCMDBTask18BWorkerRejectsForeignRuntimeBeforeProviderPostgres(t *testing.T) {
	system := newTask18BSystem(t, task18BWireComplete, task18BOptions{foreignRuntime: true})
	runID := system.seedDataRun(t, "foreign-runtime")
	system.resetEvidence()
	runErr := system.worker.Run(context.Background())
	if !errors.Is(runErr, discoveryworker.ErrClaimRejected) {
		t.Fatalf("Worker.Run(foreign runtime) error = %v", runErr)
	}
	snapshot := system.readRun(t, runID)
	if snapshot.status != "FAILED" || system.resolver.calls() != 0 ||
		system.server.callCount() != 0 || system.page.applyCalls != 0 ||
		!system.opener.boundRuntimeCleared() {
		t.Fatalf("foreign runtime closure run=%#v resolver/http/page/clear=%d/%d/%d/%t",
			snapshot, system.resolver.calls(), system.server.callCount(),
			system.page.applyCalls, system.opener.boundRuntimeCleared())
	}
	requireTask18BOrderedEvents(t, system.events.snapshot(),
		"bind-runtime", "runtime-clear", "revoke", "destroy", "record-cleanup")
}

func TestExternalCMDBTask18BWorkerStaleFenceBoundariesHaveNoUnauthorizedWritesPostgres(t *testing.T) {
	tests := []struct {
		name                 string
		options              task18BOptions
		wantHTTP             int
		wantPageReceipts     int64
		wantTerminalReceipts int64
		wantStatus           string
	}{
		{
			name:       "before provider",
			options:    task18BOptions{heartbeatFence: task18BFenceBeforeProvider},
			wantStatus: "RUNNING",
		},
		{
			name: "after provider",
			options: task18BOptions{
				heartbeatFence: task18BFenceAfterProvider,
			},
			wantHTTP:   2,
			wantStatus: "RUNNING",
		},
		{
			name: "apply page",
			options: task18BOptions{
				pageFence: true,
			},
			wantHTTP:   2,
			wantStatus: "RUNNING",
		},
		{
			name: "terminal",
			options: task18BOptions{
				heartbeatFence: task18BFenceTerminal,
			},
			wantHTTP:             3,
			wantPageReceipts:     2,
			wantTerminalReceipts: 0,
			wantStatus:           "FINALIZING",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			system := newTask18BSystem(t, task18BWireComplete, test.options)
			runID := system.seedDataRun(t, "fence-"+strings.ReplaceAll(test.name, " ", "-"))
			outboxBefore := system.countOutbox(t)
			system.resetEvidence()
			runErr := system.worker.Run(context.Background())
			if !errors.Is(runErr, discoveryworker.ErrClaimRejected) &&
				!errors.Is(runErr, discoveryworker.ErrWorkerUnavailable) {
				t.Fatalf("Worker.Run(stale %s) error = %v", test.name, runErr)
			}
			snapshot := system.readRun(t, runID)
			pageReceipts, terminalReceipts, observations := system.sideEffectCounts(t, runID)
			facts := system.readBoundaryFacts(t, runID)
			wantRelationships, wantCheckpoint := int64(0), int64(0)
			if test.wantPageReceipts > 0 {
				wantRelationships, wantCheckpoint = 1, 2
			}
			if snapshot.status != test.wantStatus ||
				system.server.callCount() != test.wantHTTP ||
				pageReceipts != test.wantPageReceipts ||
				terminalReceipts != test.wantTerminalReceipts ||
				(test.wantPageReceipts == 0 && observations != 0) ||
				facts.relationReceipts != test.wantPageReceipts ||
				facts.relationships != wantRelationships ||
				facts.sourceCheckpointVersion != wantCheckpoint ||
				facts.successPointers != 0 ||
				(test.wantPageReceipts == 0 && system.countOutbox(t) != outboxBefore) ||
				system.queue.takeoverCalls != 1 || system.queue.takeoverError != nil {
				t.Fatalf(
					"stale %s run=%#v http=%d page/terminal/observations=%d/%d/%d facts=%#v outbox=%d/%d takeover=%d/%v",
					test.name, snapshot, system.server.callCount(),
					pageReceipts, terminalReceipts, observations,
					facts, outboxBefore, system.countOutbox(t),
					system.queue.takeoverCalls, system.queue.takeoverError,
				)
			}
			if !system.opener.boundRuntimeCleared() {
				t.Fatalf("stale %s runtime material was not zeroized", test.name)
			}
		})
	}
}

type task18BOptions struct {
	responseLoss   bool
	foreignRuntime bool
	heartbeatFence task18BFenceMode
	pageFence      bool
}

type task18BFenceMode int

const (
	task18BFenceNone task18BFenceMode = iota
	task18BFenceBeforeProvider
	task18BFenceAfterProvider
	task18BFenceTerminal
)

type task18BSystem struct {
	harness    *task18BPostgresHarness
	source     task18BSource
	descriptor externalcmdb.ReconciliationDescriptor
	registry   assetcatalog.SourceProfileRegistry
	server     *task18BWireServer
	events     *task18BEvents
	opener     *task18BSessionOpener
	broker     *discoverycleanup.CleanupBroker
	realQueue  *queuepostgres.Repository
	queue      *task18BQueue
	limiter    *task18BLimiter
	page       *task18BPageCommitter
	resolver   *task18BResolver
	worker     *discoveryworker.Worker
	keyring    *discoverycheckpoint.InMemoryKeyring
}

func newTask18BSystem(
	t *testing.T,
	wireMode task18BWireMode,
	options task18BOptions,
) *task18BSystem {
	t.Helper()
	harness := newTask18BPostgresHarness(t)
	harness.applyMigrations(t)
	harness.assertTLSIdentities(t)
	descriptor, err := externalcmdb.NewReconciliationDescriptor(sourceprofile.ExternalCMDBV1())
	if err != nil {
		t.Fatalf("NewReconciliationDescriptor() error = %v", err)
	}
	source := newTask18BSource()
	registration, err := sourceprofile.ExternalCMDBV1().Registration(
		sourceprofile.ExternalCMDBProfileReferences{
			IntegrationID:            source.integrationID,
			CredentialReferenceID:    "task18b-cmdb-read",
			TrustReferenceID:         "task18b-cmdb-trust",
			NetworkPolicyReferenceID: "task18b-cmdb-network",
		},
	)
	if err != nil {
		t.Fatalf("External CMDB Registration() error = %v", err)
	}
	registry, err := assetcatalog.NewSourceProfileRegistry(registration)
	if err != nil {
		t.Fatalf("NewSourceProfileRegistry() error = %v", err)
	}
	server := newTask18BWireServer(t, wireMode)
	events := &task18BEvents{}
	opener := &task18BSessionOpener{
		server: server, environmentID: source.environmentID,
		foreignRuntime: options.foreignRuntime, events: events,
	}
	broker, err := discoverycleanup.NewCleanupBroker(opener, task18BProofAuthority{})
	if err != nil {
		t.Fatalf("NewCleanupBroker() error = %v", err)
	}
	t.Cleanup(broker.Destroy)
	realQueue, err := queuepostgres.New(harness.application, broker, task18BRolloverVerifier{})
	if err != nil {
		t.Fatalf("queuepostgres.New() error = %v", err)
	}
	seedTask18BPublishedSource(t, harness, realQueue, broker, &source, registration.Profile)
	opener.expected = source.runtimeBinding()

	var master [32]byte
	for index := range master {
		master[index] = byte(index + 71)
	}
	keyring, err := discoverycheckpoint.NewInMemoryKeyring(
		"task18b-checkpoint-key-v1",
		map[string][32]byte{"task18b-checkpoint-key-v1": master},
	)
	if err != nil {
		t.Fatalf("NewInMemoryKeyring() error = %v", err)
	}
	t.Cleanup(keyring.Destroy)
	codec, err := discoverycheckpoint.NewCheckpointCodec(keyring)
	if err != nil {
		t.Fatalf("NewCheckpointCodec() error = %v", err)
	}
	assetRepository, err := assetpostgres.NewWithSourceProfileRegistry(
		harness.application, time.Now, uuid.NewString, registry,
	)
	if err != nil {
		t.Fatalf("assetpostgres.NewWithSourceProfileRegistry() error = %v", err)
	}
	realPage, err := assetpostgres.NewPageCommitter(assetRepository, keyring, descriptor)
	if err != nil {
		t.Fatalf("NewPageCommitter() error = %v", err)
	}
	realLimiter, err := limitpostgres.New(harness.application, registry)
	if err != nil {
		t.Fatalf("limitpostgres.New() error = %v", err)
	}
	queue := &task18BQueue{
		Queue: realQueue, real: realQueue, admin: harness.db, events: events,
		responseLoss: options.responseLoss, fenceMode: options.heartbeatFence,
	}
	limiter := &task18BLimiter{Limiter: realLimiter, events: events}
	page := &task18BPageCommitter{
		PageCommitter: realPage, events: events, queue: queue,
		injectFence: options.pageFence,
	}
	resolver := &task18BResolver{
		descriptor: descriptor, environmentID: source.environmentID,
		pool: harness.application, sourceDefinitionDigest: source.sourceDefinitionDigest,
	}
	worker, err := discoveryworker.New(discoveryworker.Dependencies{
		Queue: queue, CleanupBroker: broker, Limiter: limiter,
		PageCommitter: page, Checkpoints: codec, ClaimRuntimeResolver: resolver,
		ClaimCommand: discoveryqueue.ClaimCommand{
			Owner:         "task18b-visible-worker",
			LeaseDuration: 2 * time.Second,
			ProviderKinds: []string{task18BProviderKind},
		},
	})
	if err != nil {
		t.Fatalf("discoveryworker.New() error = %v", err)
	}
	return &task18BSystem{
		harness: harness, source: source, descriptor: descriptor, registry: registry,
		server: server, events: events, opener: opener, broker: broker,
		realQueue: realQueue, queue: queue, limiter: limiter, page: page,
		resolver: resolver, worker: worker, keyring: keyring,
	}
}

func (system *task18BSystem) seedDataRun(t *testing.T, suffix string) string {
	t.Helper()
	runID := uuid.NewString()
	task18BExec(t, system.harness.db, `
INSERT INTO asset_source_runs(
 id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
 run_kind,trigger_type,gate_revision,idempotency_key,request_hash,
 cursor_before_sha256,checkpoint_version
)
SELECT $1,$2,$3,$4,published_revision,published_revision_digest,
       'DISCOVERY','SCHEDULED',gate_revision,$5,repeat('4',64),
       checkpoint_sha256,checkpoint_version
FROM asset_sources WHERE id=$4
`, runID, system.source.tenantID, system.source.workspaceID, system.source.sourceID,
		"task18b-data-"+suffix+"-"+runID)
	return runID
}

func (system *task18BSystem) runUntil(
	t *testing.T,
	runID string,
	done func(task18BRunSnapshot) bool,
) error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- system.worker.Run(ctx) }()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if done(system.readRun(t, runID)) {
			cancel()
			select {
			case err := <-result:
				return err
			case <-time.After(3 * time.Second):
				t.Fatal("Worker.Run() did not stop after terminal observation")
			}
		}
		select {
		case err := <-result:
			cancel()
			t.Fatalf("Worker.Run() stopped before expected durable state: %v; run=%#v events=%v http=%d heartbeat-command=%d",
				err, system.readRun(t, runID), system.events.snapshot(), system.server.callCount(),
				system.queue.lastHeartbeatSequence())
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	<-result
	t.Fatal("timed out waiting for durable Worker state")
	return nil
}

func (system *task18BSystem) resetEvidence() {
	system.events.reset()
	system.server.resetCalls()
	system.opener.resetRuntimeEvidence()
	system.resolver.reset()
	system.queue.reset()
	system.page.reset()
}

type task18BRunSnapshot struct {
	status, stage, cleanupStatus                   string
	fenceEpoch, pageSequence, checkpointVersion    int64
	heartbeatSequence                              int64
	missing, stale                                 int64
	finalPage, completeSnapshot, effectiveComplete bool
	pendingTransition                              bool
}

func (system *task18BSystem) readRun(t *testing.T, runID string) task18BRunSnapshot {
	t.Helper()
	var snapshot task18BRunSnapshot
	if err := system.harness.db.QueryRow(t.Context(), `
SELECT status,stage_code,cleanup_status,fence_epoch,page_sequence,checkpoint_version,
       heartbeat_sequence,missing_count,stale_count,
       final_page,complete_snapshot,effective_complete_snapshot,
       pending_transition IS NOT NULL
FROM asset_source_runs WHERE id=$1::uuid
`, runID).Scan(
		&snapshot.status, &snapshot.stage, &snapshot.cleanupStatus,
		&snapshot.fenceEpoch, &snapshot.pageSequence, &snapshot.checkpointVersion,
		&snapshot.heartbeatSequence, &snapshot.missing, &snapshot.stale, &snapshot.finalPage,
		&snapshot.completeSnapshot, &snapshot.effectiveComplete,
		&snapshot.pendingTransition,
	); err != nil {
		t.Fatalf("read Task18B run: %v", err)
	}
	return snapshot
}

func (system *task18BSystem) sideEffectCounts(
	t *testing.T,
	runID string,
) (int64, int64, int64) {
	t.Helper()
	var pageReceipts, terminalReceipts, observations int64
	if err := system.harness.db.QueryRow(t.Context(), `
SELECT
 (SELECT count(*) FROM audit_records
  WHERE resource_id=$1 AND action='PAGE_APPLIED'),
 (SELECT count(*) FROM audit_records
  WHERE resource_id=$1 AND action='TERMINAL_COMMITTED'),
 (SELECT count(*) FROM asset_observations WHERE run_id=$1::uuid)
`, runID).Scan(&pageReceipts, &terminalReceipts, &observations); err != nil {
		t.Fatalf("read Task18B side effects: %v", err)
	}
	return pageReceipts, terminalReceipts, observations
}

type task18BBoundaryFacts struct {
	relationReceipts        int64
	relationships           int64
	sourceCheckpointVersion int64
	successPointers         int64
}

func (system *task18BSystem) readBoundaryFacts(
	t *testing.T,
	runID string,
) task18BBoundaryFacts {
	t.Helper()
	var facts task18BBoundaryFacts
	if err := system.harness.db.QueryRow(t.Context(), `
SELECT
 (SELECT count(*) FROM audit_records
  WHERE resource_id=$2 AND action='RELATION_PAGE_COMMITTED'),
 (SELECT count(*) FROM asset_relationships WHERE source_id=$1::uuid),
 checkpoint_version,
 (CASE WHEN last_success_run_id=$2::uuid THEN 1 ELSE 0 END)+
 (CASE WHEN last_complete_snapshot_run_id=$2::uuid THEN 1 ELSE 0 END)
FROM asset_sources WHERE id=$1::uuid
`, system.source.sourceID, runID).Scan(
		&facts.relationReceipts, &facts.relationships,
		&facts.sourceCheckpointVersion, &facts.successPointers,
	); err != nil {
		t.Fatalf("read Task18B stale-boundary facts: %v", err)
	}
	return facts
}

func (system *task18BSystem) countOutbox(t *testing.T) int64 {
	t.Helper()
	var count int64
	if err := system.harness.db.QueryRow(
		t.Context(), `SELECT count(*) FROM outbox_events`,
	).Scan(&count); err != nil {
		t.Fatalf("count Task18B outbox events: %v", err)
	}
	return count
}

func (system *task18BSystem) assertCompleteProjection(t *testing.T, runID string) {
	t.Helper()
	var assets, relations, pageReceipts, relationReceipts, terminalReceipts int64
	var lastSuccess, lastComplete string
	if err := system.harness.db.QueryRow(t.Context(), `
SELECT
 (SELECT count(*) FROM assets WHERE source_id=$1::uuid),
 (SELECT count(*) FROM asset_relationships WHERE source_id=$1::uuid),
 (SELECT count(*) FROM audit_records
  WHERE resource_id=$2 AND action='PAGE_APPLIED'),
 (SELECT count(*) FROM audit_records
  WHERE resource_id=$2 AND action='RELATION_PAGE_COMMITTED'),
 (SELECT count(*) FROM audit_records
  WHERE resource_id=$2 AND action='TERMINAL_COMMITTED'),
 last_success_run_id::text,last_complete_snapshot_run_id::text
FROM asset_sources WHERE id=$1::uuid
`, system.source.sourceID, runID).Scan(
		&assets, &relations, &pageReceipts, &relationReceipts, &terminalReceipts,
		&lastSuccess, &lastComplete,
	); err != nil {
		t.Fatalf("read complete CMDB projection: %v", err)
	}
	if assets != 2 || relations != 1 || pageReceipts != 2 ||
		relationReceipts != 2 || terminalReceipts != 1 ||
		lastSuccess != runID || lastComplete != runID {
		t.Fatalf("complete projection assets/relations/pages/relations/terminal=%d/%d/%d/%d/%d pointers=%s/%s",
			assets, relations, pageReceipts, relationReceipts, terminalReceipts,
			lastSuccess, lastComplete)
	}
}

type task18BEvents struct {
	mu     sync.Mutex
	values []string
}

func (events *task18BEvents) add(value string) {
	events.mu.Lock()
	defer events.mu.Unlock()
	events.values = append(events.values, value)
}

func (events *task18BEvents) snapshot() []string {
	events.mu.Lock()
	defer events.mu.Unlock()
	return slices.Clone(events.values)
}

func (events *task18BEvents) reset() {
	events.mu.Lock()
	defer events.mu.Unlock()
	events.values = nil
}

func requireTask18BOrderedEvents(t *testing.T, events []string, expected ...string) {
	t.Helper()
	next := 0
	for _, event := range events {
		if next < len(expected) && event == expected[next] {
			next++
		}
	}
	if next != len(expected) {
		t.Fatalf("ordered events %v missing suffix %v from full %v", expected[:next], expected[next:], events)
	}
}

func requireNoTask18BHeartbeatAfter(t *testing.T, events []string, marker string) {
	t.Helper()
	index := slices.Index(events, marker)
	if index < 0 {
		t.Fatalf("event %q missing from %v", marker, events)
	}
	for _, event := range events[index+1:] {
		if strings.HasPrefix(event, "heartbeat") {
			t.Fatalf("heartbeat %q occurred after %q: %v", event, marker, events)
		}
	}
}

type task18BQueue struct {
	discoveryqueue.Queue
	real              *queuepostgres.Repository
	admin             *pgxpool.Pool
	events            *task18BEvents
	responseLoss      bool
	fenceMode         task18BFenceMode
	mu                sync.Mutex
	heartbeatCalls    int
	heartbeatSequence int64
	reserveCalls      int
	cleanupCalls      int
	completeCalls     int
	delayCalls        int
	failCalls         int
	reserveLost       bool
	cleanupLost       bool
	completeLost      bool
	takeoverCalls     int
	takeoverError     error
}

func (queue *task18BQueue) Heartbeat(
	ctx context.Context,
	fence assetcatalog.LeaseFence,
	command discoveryqueue.HeartbeatCommand,
) (discoveryqueue.HeartbeatResult, error) {
	queue.mu.Lock()
	queue.heartbeatCalls++
	queue.heartbeatSequence = command.Sequence
	call := queue.heartbeatCalls
	mode := queue.fenceMode
	queue.mu.Unlock()
	inject := mode == task18BFenceBeforeProvider && call == 1 ||
		mode == task18BFenceAfterProvider && call == 2
	if mode == task18BFenceTerminal {
		var status string
		if err := queue.admin.QueryRow(ctx,
			`SELECT status FROM asset_source_runs WHERE id=$1::uuid`,
			command.Coordinates.RunID,
		).Scan(&status); err == nil && status == "FINALIZING" {
			inject = true
		}
	}
	if inject {
		if err := queue.takeover(
			ctx, command.Coordinates.RunID, mode == task18BFenceTerminal,
		); err != nil {
			return discoveryqueue.HeartbeatResult{}, discoveryqueue.ErrUnavailable
		}
	}
	result, err := queue.Queue.Heartbeat(ctx, fence, command)
	switch {
	case err == nil:
		queue.events.add("heartbeat")
	case errors.Is(err, discoveryqueue.ErrStaleFence):
		queue.events.add("heartbeat-stale")
	case errors.Is(err, discoveryqueue.ErrIneligible):
		queue.events.add("heartbeat-ineligible")
	case errors.Is(err, discoveryqueue.ErrStateConflict):
		queue.events.add("heartbeat-conflict")
	default:
		queue.events.add("heartbeat-unavailable")
	}
	return result, err
}

func (queue *task18BQueue) AdvanceStage(
	ctx context.Context,
	fence assetcatalog.LeaseFence,
	command discoveryqueue.AdvanceStageCommand,
) (assetcatalog.SourceRun, error) {
	if command.Delay != nil {
		queue.events.add("advance-delay-intent")
	} else {
		queue.events.add("advance-stage")
	}
	return queue.Queue.AdvanceStage(ctx, fence, command)
}

func (queue *task18BQueue) ReserveCleanupAttempt(
	ctx context.Context,
	fence assetcatalog.LeaseFence,
	command discoveryqueue.RunCommand,
) (discoveryqueue.CleanupAttempt, error) {
	queue.mu.Lock()
	queue.reserveCalls++
	queue.mu.Unlock()
	queue.events.add("reserve-attempt")
	result, err := queue.Queue.ReserveCleanupAttempt(ctx, fence, command)
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if err == nil && queue.responseLoss && !queue.reserveLost {
		queue.reserveLost = true
		return discoveryqueue.CleanupAttempt{}, discoveryqueue.ErrUnavailable
	}
	return result, err
}

func (queue *task18BQueue) RecordCleanup(
	ctx context.Context,
	fence assetcatalog.LeaseFence,
	proof discoveryqueue.CleanupProof,
) (discoveryqueue.CleanupResult, error) {
	queue.mu.Lock()
	queue.cleanupCalls++
	queue.mu.Unlock()
	queue.events.add("record-cleanup")
	result, err := queue.Queue.RecordCleanup(ctx, fence, proof)
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if err == nil && queue.responseLoss && !queue.cleanupLost {
		queue.cleanupLost = true
		return discoveryqueue.CleanupResult{}, discoveryqueue.ErrUnavailable
	}
	return result, err
}

func (queue *task18BQueue) Complete(
	ctx context.Context,
	fence assetcatalog.LeaseFence,
	command discoveryqueue.TerminalCommand,
) (discoveryqueue.TerminalResult, error) {
	queue.mu.Lock()
	queue.completeCalls++
	queue.mu.Unlock()
	queue.events.add("complete")
	result, err := queue.Queue.Complete(ctx, fence, command)
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if err == nil && queue.responseLoss && !queue.completeLost {
		queue.completeLost = true
		return discoveryqueue.TerminalResult{}, discoveryqueue.ErrUnavailable
	}
	return result, err
}

func (queue *task18BQueue) Delay(
	ctx context.Context,
	fence assetcatalog.LeaseFence,
	command discoveryqueue.DelayCommand,
) (assetcatalog.SourceRun, error) {
	queue.mu.Lock()
	queue.delayCalls++
	queue.mu.Unlock()
	queue.events.add("queue-delay")
	return queue.Queue.Delay(ctx, fence, command)
}

func (queue *task18BQueue) Fail(
	ctx context.Context,
	fence assetcatalog.LeaseFence,
	command discoveryqueue.TerminalCommand,
) (discoveryqueue.TerminalResult, error) {
	queue.mu.Lock()
	queue.failCalls++
	queue.mu.Unlock()
	queue.events.add("fail")
	return queue.Queue.Fail(ctx, fence, command)
}

func (queue *task18BQueue) takeover(
	ctx context.Context,
	runID string,
	terminal bool,
) error {
	var expiresAt time.Time
	if err := queue.admin.QueryRow(ctx, `
SELECT lease_expires_at FROM asset_source_runs WHERE id=$1::uuid
`, runID).Scan(&expiresAt); err != nil {
		queue.recordTakeoverError(err)
		return err
	}
	wait := time.Until(expiresAt) + 20*time.Millisecond
	if wait > 0 {
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			queue.recordTakeoverError(ctx.Err())
			return ctx.Err()
		case <-timer.C:
		}
	}
	command := discoveryqueue.ReclaimCommand{
		Owner:         "task18b-takeover-worker",
		LeaseDuration: 2 * time.Second,
		ProviderKinds: []string{task18BProviderKind},
	}
	var claim discoveryqueue.ClaimResult
	var err error
	if terminal {
		claim, err = queue.real.ReclaimFinalizing(ctx, command)
	} else {
		claim, err = queue.real.Reclaim(ctx, command)
	}
	if err == nil {
		queue.events.add("takeover")
		claim.Destroy()
		queue.mu.Lock()
		queue.takeoverCalls++
		queue.mu.Unlock()
		return nil
	}
	queue.recordTakeoverError(err)
	return err
}

func (queue *task18BQueue) recordTakeoverError(err error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	queue.takeoverError = err
}

func (queue *task18BQueue) reset() {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	queue.heartbeatCalls = 0
	queue.heartbeatSequence = 0
	queue.reserveCalls = 0
	queue.cleanupCalls = 0
	queue.completeCalls = 0
	queue.delayCalls = 0
	queue.failCalls = 0
	queue.reserveLost = false
	queue.cleanupLost = false
	queue.completeLost = false
	queue.takeoverCalls = 0
	queue.takeoverError = nil
}

func (queue *task18BQueue) lastHeartbeatSequence() int64 {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	return queue.heartbeatSequence
}

type task18BLimiter struct {
	discoverylimit.Limiter
	events *task18BEvents
}

func (limiter *task18BLimiter) Acquire(
	ctx context.Context,
	command discoverylimit.AcquireCommand,
) (discoverylimit.Permit, error) {
	limiter.events.add("limiter-acquire")
	return limiter.Limiter.Acquire(ctx, command)
}

func (limiter *task18BLimiter) Release(
	ctx context.Context,
	command discoverylimit.ReleaseCommand,
) (discoverylimit.Receipt, error) {
	limiter.events.add("limiter-release")
	return limiter.Limiter.Release(ctx, command)
}

func (limiter *task18BLimiter) Delay(
	ctx context.Context,
	command discoverylimit.DelayCommand,
) (discoverylimit.Receipt, error) {
	limiter.events.add("limiter-delay")
	return limiter.Limiter.Delay(ctx, command)
}

type task18BPageCommitter struct {
	discoverysource.PageCommitter
	events      *task18BEvents
	queue       *task18BQueue
	injectFence bool
	mu          sync.Mutex
	applyCalls  int
	injected    bool
}

func (committer *task18BPageCommitter) ApplyPage(
	ctx context.Context,
	fence assetcatalog.LeaseFence,
	coordinates discoverysource.PageCommitCoordinates,
	page discoverysource.Page,
) (discoverysource.PageCommitResult, error) {
	committer.mu.Lock()
	committer.applyCalls++
	inject := committer.injectFence && !committer.injected
	if inject {
		committer.injected = true
	}
	committer.mu.Unlock()
	if inject {
		if err := committer.queue.takeover(ctx, coordinates.RunID, false); err != nil {
			return discoverysource.PageCommitResult{}, discoverysource.ErrPageCommitUnavailable
		}
	}
	committer.events.add("apply-page")
	return committer.PageCommitter.ApplyPage(ctx, fence, coordinates, page)
}

func (committer *task18BPageCommitter) reset() {
	committer.mu.Lock()
	defer committer.mu.Unlock()
	committer.applyCalls = 0
	committer.injected = false
}

type task18BResolver struct {
	descriptor             externalcmdb.ReconciliationDescriptor
	environmentID          string
	pool                   *pgxpool.Pool
	sourceDefinitionDigest string
	mu                     sync.Mutex
	resolveCalls           int
}

func (resolver *task18BResolver) ResolveOpenedAttempt(
	ctx context.Context,
	request discoveryworker.ResolveOpenedAttemptRequest,
) (discoveryworker.ClaimRuntime, error) {
	resolver.mu.Lock()
	resolver.resolveCalls++
	resolver.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return discoveryworker.ClaimRuntime{}, err
	}
	if request.RunKind() != assetcatalog.RunKindDiscovery ||
		request.CheckpointCodec() == nil {
		return discoveryworker.ClaimRuntime{}, discoveryworker.ErrClaimRuntimeBinding
	}
	provider, err := resolver.descriptor.NewProvider(request.RuntimeBinding())
	if err != nil {
		return discoveryworker.ClaimRuntime{}, err
	}
	var checkpoint discoverysource.Checkpoint
	if request.CheckpointVersion() == 0 {
		if request.CheckpointSHA256() != "" {
			return discoveryworker.ClaimRuntime{}, discoveryworker.ErrClaimRuntimeBinding
		}
		checkpoint, err = resolver.descriptor.NewCheckpoint()
	} else {
		checkpoint, err = resolver.openPersistedCheckpoint(ctx, request)
	}
	if err != nil {
		return discoveryworker.ClaimRuntime{}, err
	}
	policy, err := resolver.descriptor.FactPolicy([]string{resolver.environmentID})
	if err != nil {
		checkpoint.Clear()
		return discoveryworker.ClaimRuntime{}, err
	}
	return request.NewClaimRuntime(
		provider, &checkpoint, resolver.descriptor.Limits(), policy,
	)
}

func (resolver *task18BResolver) openPersistedCheckpoint(
	ctx context.Context,
	request discoveryworker.ResolveOpenedAttemptRequest,
) (discoverysource.Checkpoint, error) {
	if resolver.pool == nil || request.CheckpointVersion() <= 0 ||
		request.CheckpointSHA256() == "" {
		return discoverysource.Checkpoint{}, discoveryworker.ErrClaimRuntimeBinding
	}
	binding := request.RuntimeBinding()
	var envelope []byte
	var keyID, digest, sourceDefinitionDigest string
	var revision, version int64
	if err := resolver.pool.QueryRow(ctx, `
SELECT source.checkpoint_ciphertext,source.checkpoint_key_id,
       source.checkpoint_sha256,source.checkpoint_revision,
       source.checkpoint_version,revision.source_definition_digest
FROM asset_sources AS source
JOIN asset_source_revisions AS revision
  ON revision.tenant_id=source.tenant_id
 AND revision.workspace_id=source.workspace_id
 AND revision.source_id=source.id
 AND revision.revision=source.checkpoint_revision
WHERE source.tenant_id=$1::uuid AND source.workspace_id=$2::uuid
  AND source.id=$3::uuid
`, binding.Locator.Scope.TenantID, binding.Locator.Scope.WorkspaceID,
		binding.Locator.SourceID).Scan(
		&envelope, &keyID, &digest, &revision, &version, &sourceDefinitionDigest,
	); err != nil {
		return discoverysource.Checkpoint{}, discoveryworker.ErrClaimRuntimeBinding
	}
	defer clear(envelope)
	if revision != binding.SourceRevision || version != request.CheckpointVersion() ||
		digest != request.CheckpointSHA256() ||
		sourceDefinitionDigest != resolver.sourceDefinitionDigest {
		return discoverysource.Checkpoint{}, discoveryworker.ErrClaimRuntimeBinding
	}
	aad := discoverycheckpoint.CheckpointAAD{
		TenantID:                binding.Locator.Scope.TenantID,
		WorkspaceID:             binding.Locator.Scope.WorkspaceID,
		SourceID:                binding.Locator.SourceID,
		ProviderKind:            binding.ProviderKind,
		CheckpointRevision:      revision,
		CanonicalRevisionDigest: binding.SourceRevisionDigest,
		SourceDefinitionDigest:  sourceDefinitionDigest,
		CheckpointKeyID:         keyID,
		CheckpointVersion:       version,
	}
	return request.CheckpointCodec().Open(
		ctx, aad, resolver.descriptor.ProfileCode(),
		discoverycheckpoint.SealedCheckpoint{
			Envelope:        envelope,
			CheckpointKeyID: keyID, CheckpointSHA256: digest,
			CheckpointVersion: version,
		},
	)
}

func (resolver *task18BResolver) calls() int {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	return resolver.resolveCalls
}

func (resolver *task18BResolver) reset() {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	resolver.resolveCalls = 0
}

type task18BSessionOpener struct {
	server         *task18BWireServer
	environmentID  string
	expected       discoverysource.RuntimeBinding
	foreignRuntime bool
	events         *task18BEvents
	mu             sync.Mutex
	handles        []*task18BSessionHandle
}

func (opener *task18BSessionOpener) OpenSession(
	ctx context.Context,
	_ discoverycleanup.OpenAttemptRequest,
) (discoverycleanup.SessionHandle, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	handle := &task18BSessionHandle{
		opener: opener, server: opener.server, environmentID: opener.environmentID,
		expected: opener.expected, foreignRuntime: opener.foreignRuntime, events: opener.events,
	}
	opener.mu.Lock()
	opener.handles = append(opener.handles, handle)
	opener.mu.Unlock()
	opener.events.add("open-session")
	return handle, nil
}

func (opener *task18BSessionOpener) boundCalls() int {
	opener.mu.Lock()
	defer opener.mu.Unlock()
	total := 0
	for _, handle := range opener.handles {
		total += handle.bindCount()
	}
	return total
}

func (opener *task18BSessionOpener) boundRuntimeCleared() bool {
	opener.mu.Lock()
	defer opener.mu.Unlock()
	found := false
	for _, handle := range opener.handles {
		if handle.bindCount() == 0 {
			continue
		}
		found = true
		if !handle.wasCleared() {
			return false
		}
	}
	return found
}

func (opener *task18BSessionOpener) resetRuntimeEvidence() {
	opener.mu.Lock()
	defer opener.mu.Unlock()
	opener.handles = nil
}

type task18BSessionHandle struct {
	opener         *task18BSessionOpener
	server         *task18BWireServer
	environmentID  string
	expected       discoverysource.RuntimeBinding
	foreignRuntime bool
	events         *task18BEvents
	mu             sync.Mutex
	material       externalcmdb.RuntimeMaterial
	tokenBacking   []byte
	binds          int
	cleared        bool
	revoked        bool
	destroyed      bool
}

func (handle *task18BSessionHandle) BindRuntime(
	ctx context.Context,
	expected discoverysource.RuntimeBinding,
) (discoverysource.BoundRuntime, error) {
	handle.mu.Lock()
	defer handle.mu.Unlock()
	handle.binds++
	handle.events.add("bind-runtime")
	if err := ctx.Err(); err != nil {
		return discoverysource.BoundRuntime{}, err
	}
	if expected != handle.expected {
		return discoverysource.BoundRuntime{}, discoverycleanup.ErrAttemptDrift
	}
	actual := expected
	if handle.foreignRuntime {
		actual.SourceRevisionDigest = strings.Repeat("f", 64)
	}
	handle.tokenBacking = []byte("task18b-bearer-token")
	handle.material = externalcmdb.RuntimeMaterial{
		BaseURL:             handle.server.URL(),
		TLSConfig:           handle.server.clientTLS.Clone(),
		BearerToken:         handle.tokenBacking,
		ExpectedAuthorityID: "task18b-cmdb-authority",
		EnvironmentID:       handle.environmentID,
	}
	return discoverysource.BindRuntime(
		actual,
		&handle.material,
		func(*externalcmdb.RuntimeMaterial) error { return nil },
		func(material *externalcmdb.RuntimeMaterial) {
			handle.mu.Lock()
			material.Clear()
			handle.cleared = true
			handle.mu.Unlock()
			handle.events.add("runtime-clear")
		},
	)
}

func (handle *task18BSessionHandle) Revoke(ctx context.Context) error {
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	handle.revoked = true
	handle.events.add("revoke")
	return nil
}

func (handle *task18BSessionHandle) Destroy() {
	handle.mu.Lock()
	defer handle.mu.Unlock()
	handle.destroyed = true
	handle.events.add("destroy")
}

func (handle *task18BSessionHandle) bindCount() int {
	handle.mu.Lock()
	defer handle.mu.Unlock()
	return handle.binds
}

func (handle *task18BSessionHandle) wasCleared() bool {
	handle.mu.Lock()
	defer handle.mu.Unlock()
	for _, value := range handle.tokenBacking {
		if value != 0 {
			return false
		}
	}
	return handle.cleared && handle.material.BaseURL == "" &&
		handle.material.TLSConfig == nil && handle.material.BearerToken == nil &&
		handle.material.ExpectedAuthorityID == "" && handle.material.EnvironmentID == ""
}

type task18BProofAuthority struct{}

func (task18BProofAuthority) SignCleanupProof(
	ctx context.Context,
	digest []byte,
) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, []byte("task18b-cleanup-proof-authority"))
	_, _ = mac.Write(digest)
	return mac.Sum(nil), nil
}

func (task18BProofAuthority) VerifyCleanupProof(
	ctx context.Context,
	digest, signature []byte,
) error {
	expected, err := (task18BProofAuthority{}).SignCleanupProof(ctx, digest)
	if err != nil || !hmac.Equal(expected, signature) {
		return discoverycleanup.ErrProofAuthentication
	}
	return nil
}

type task18BRolloverVerifier struct{}

func (task18BRolloverVerifier) VerifyCheckpointLineageRollover(
	context.Context,
	discoveryqueue.CheckpointLineageRolloverRequest,
) error {
	return nil
}

type task18BWireMode int

const (
	task18BWireComplete task18BWireMode = iota
	task18BWirePartial
	task18BWireDelay
	task18BWireTimeout
	task18BWireTombstone
	task18BWireRestore
)

type task18BWireServer struct {
	server     *httptest.Server
	clientTLS  *tls.Config
	mode       task18BWireMode
	mu         sync.Mutex
	calls      []string
	violations []string
}

func newTask18BWireServer(t *testing.T, mode task18BWireMode) *task18BWireServer {
	t.Helper()
	wire := &task18BWireServer{mode: mode}
	now := time.Now().UTC()
	ca, caKey := task18BIssueCA(t, now)
	serverCertificate := task18BIssueLeaf(
		t, now, ca, caKey, 2, "task18b-external-cmdb-server",
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	)
	clientCertificate := task18BIssueLeaf(
		t, now, ca, caKey, 3, "task18b-discovery-worker",
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	server := httptest.NewUnstartedServer(http.HandlerFunc(wire.serveHTTP))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCertificate},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots,
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse Task18B CMDB URL: %v", err)
	}
	wire.server = server
	wire.clientTLS = &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: parsed.Hostname(),
		Certificates: []tls.Certificate{clientCertificate},
	}
	t.Cleanup(func() { wire.assertNoViolations(t) })
	return wire
}

func (server *task18BWireServer) serveHTTP(
	writer http.ResponseWriter,
	request *http.Request,
) {
	server.mu.Lock()
	server.calls = append(server.calls, request.URL.RequestURI())
	if request.TLS == nil || request.TLS.Version != tls.VersionTLS13 ||
		len(request.TLS.PeerCertificates) == 0 {
		server.violations = append(server.violations, "TLS/mTLS")
	}
	if request.Method != http.MethodGet || request.ContentLength != 0 ||
		request.Header.Get("Accept") != "application/json" ||
		request.Header.Get("Authorization") != "Bearer task18b-bearer-token" {
		server.violations = append(server.violations, "fixed request")
	}
	mode := server.mode
	server.mu.Unlock()

	if request.URL.Path == "/v1/assets" && mode == task18BWireTimeout {
		<-request.Context().Done()
		return
	}
	if request.URL.Path == "/v1/assets" && mode == task18BWireDelay {
		writer.Header().Set("Retry-After", "1")
		writer.WriteHeader(http.StatusTooManyRequests)
		return
	}
	if request.URL.Path == "/v1/assets" {
		timer := time.NewTimer(225 * time.Millisecond)
		select {
		case <-request.Context().Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
	writer.Header().Set("Content-Type", "application/json")
	switch request.URL.RequestURI() {
	case "/v1/capabilities":
		task18BWriteJSON(writer, map[string]any{
			"protocol_version":   "cmdb-catalog/v1",
			"authority_id":       "task18b-cmdb-authority",
			"snapshot_epoch":     "task18b-snapshot-0001",
			"max_page_size":      500,
			"supports_delta":     true,
			"supports_tombstone": true,
			"server_time":        time.Now().UTC().Truncate(time.Second).Format(time.RFC3339),
			"permissions":        []string{"assets.read", "relations.read"},
		})
	case "/v1/assets?limit=500":
		complete := mode != task18BWirePartial
		finalPage := mode != task18BWirePartial
		nextCursor := ""
		if mode == task18BWirePartial {
			nextCursor = "task18b-partial-next"
		}
		items := task18BLiveWireAssets("2026-07-18T01:00:", 11)
		if mode == task18BWireTombstone {
			items = []map[string]any{
				{
					"external_id": "task18b-host-a", "type_code": "LINUX_VM",
					"display_name": "", "object_revision": 31,
					"updated_at": "2026-07-18T02:00:01Z", "deleted": true,
					"tombstone_reason": "PROVIDER_DELETED",
					"attributes":       map[string]string{},
				},
				{
					"external_id": "task18b-service-a", "type_code": "SERVICE",
					"display_name": "task18b-service-a", "object_revision": 32,
					"updated_at": "2026-07-18T02:00:02Z", "deleted": false,
					"tombstone_reason": "", "attributes": map[string]string{
						"name": "task18b-service-a",
					},
				},
			}
		} else if mode == task18BWireRestore {
			items = task18BLiveWireAssets("2026-07-18T03:00:", 41)
		}
		task18BWriteJSON(writer, map[string]any{
			"items":       items,
			"next_cursor": nextCursor, "snapshot_epoch": "task18b-snapshot-0001",
			"final_page": finalPage, "complete_snapshot": complete,
		})
	case "/v1/relations?limit=2000":
		complete := mode == task18BWireComplete ||
			mode == task18BWireTombstone || mode == task18BWireRestore
		items := []map[string]any{{
			"external_id":      "task18b-relation-a",
			"from_external_id": "task18b-host-a",
			"to_external_id":   "task18b-service-a",
			"type_code":        "DEPENDS_ON", "object_revision": 21,
			"updated_at": "2026-07-18T01:00:03Z", "deleted": false,
		}}
		if mode == task18BWireTombstone {
			items = []map[string]any{}
		} else if mode == task18BWireRestore {
			items[0]["object_revision"] = 51
			items[0]["updated_at"] = "2026-07-18T03:00:03Z"
		}
		task18BWriteJSON(writer, map[string]any{
			"items":       items,
			"next_cursor": "", "snapshot_epoch": "task18b-snapshot-0001",
			"final_page": true, "complete_snapshot": complete,
		})
	default:
		http.NotFound(writer, request)
	}
}

func task18BWriteJSON(writer http.ResponseWriter, value any) {
	_ = json.NewEncoder(writer).Encode(value)
}

func task18BLiveWireAssets(prefix string, firstRevision int64) []map[string]any {
	return []map[string]any{
		{
			"external_id": "task18b-host-a", "type_code": "LINUX_VM",
			"display_name": "task18b-host-a", "object_revision": firstRevision,
			"updated_at": prefix + "01Z", "deleted": false,
			"tombstone_reason": "", "attributes": map[string]string{
				"architecture": "x86_64", "hostname": "task18b-host-a",
			},
		},
		{
			"external_id": "task18b-service-a", "type_code": "SERVICE",
			"display_name": "task18b-service-a", "object_revision": firstRevision + 1,
			"updated_at": prefix + "02Z", "deleted": false,
			"tombstone_reason": "", "attributes": map[string]string{
				"name": "task18b-service-a",
			},
		},
	}
}

func (server *task18BWireServer) URL() string { return server.server.URL }

func (server *task18BWireServer) callCount() int {
	server.mu.Lock()
	defer server.mu.Unlock()
	return len(server.calls)
}

func (server *task18BWireServer) resetCalls() {
	server.mu.Lock()
	defer server.mu.Unlock()
	server.calls = nil
}

func (server *task18BWireServer) setMode(mode task18BWireMode) {
	server.mu.Lock()
	defer server.mu.Unlock()
	server.mode = mode
}

func (server *task18BWireServer) assertNoViolations(t *testing.T) {
	t.Helper()
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.violations) != 0 {
		t.Errorf("Task18B CMDB mTLS wire violations = %v; calls=%v",
			server.violations, server.calls)
	}
}

func task18BIssueCA(
	t *testing.T,
	now time.Time,
) (*x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("generate Task18B CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "task18b-external-cmdb-ca"},
		NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(
		cryptorand.Reader, template, template, publicKey, privateKey,
	)
	if err != nil {
		t.Fatalf("create Task18B CA certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse Task18B CA certificate: %v", err)
	}
	return certificate, privateKey
}

func task18BIssueLeaf(
	t *testing.T,
	now time.Time,
	ca *x509.Certificate,
	caKey ed25519.PrivateKey,
	serial int64,
	commonName string,
	usage []x509.ExtKeyUsage,
) tls.Certificate {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("generate Task18B leaf key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: commonName},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usage,
	}
	if slices.Contains(usage, x509.ExtKeyUsageServerAuth) {
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(
		cryptorand.Reader, template, ca, publicKey, caKey,
	)
	if err != nil {
		t.Fatalf("create Task18B leaf certificate: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der, ca.Raw},
		PrivateKey:  privateKey,
	}
}

type task18BPostgresHarness struct {
	admin, db, migration, application *pgxpool.Pool
	name                              string
}

var task18BSafeControlDatabase = regexp.MustCompile(`^aiops_test(_[a-z0-9]+)*$`)

func newTask18BPostgresHarness(t *testing.T) *task18BPostgresHarness {
	t.Helper()
	adminDSN := strings.TrimSpace(os.Getenv("AIOPS_TEST_POSTGRES_DSN"))
	migrationDSN := strings.TrimSpace(os.Getenv("AIOPS_TEST_POSTGRES_MIGRATION_DSN"))
	applicationDSN := strings.TrimSpace(os.Getenv("AIOPS_TEST_POSTGRES_APPLICATION_DSN"))
	if adminDSN == "" || migrationDSN == "" || applicationDSN == "" {
		t.Fatal("Task18B requires all PostgreSQL 18.4 TLS identity DSNs; tests may not skip")
	}
	if adminDSN == migrationDSN || adminDSN == applicationDSN ||
		migrationDSN == applicationDSN {
		t.Fatal("Task18B PostgreSQL identities must be distinct")
	}
	ctx := context.Background()
	adminConfig, err := pgxpool.ParseConfig(adminDSN)
	if err != nil || !task18BSafeControlDatabase.MatchString(adminConfig.ConnConfig.Database) ||
		adminConfig.ConnConfig.User != "aiops" {
		t.Fatal("Task18B test-control DSN is not the dedicated aiops database identity")
	}
	controlName := adminConfig.ConnConfig.Database
	migrationConfig := task18BRoleConfig(
		t, migrationDSN, controlName, "aiops_migrator",
	)
	applicationConfig := task18BRoleConfig(
		t, applicationDSN, controlName, "aiops_control_plane_workload",
	)
	adminConfig.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	admin, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal("connect Task18B PostgreSQL test-control database")
	}
	var serverVersion int
	var sslEnabled bool
	if err := admin.QueryRow(ctx, `
SELECT current_setting('server_version_num')::integer,current_setting('ssl')='on'
`).Scan(&serverVersion, &sslEnabled); err != nil ||
		serverVersion < 180004 || serverVersion >= 190000 || !sslEnabled {
		admin.Close()
		t.Fatal("Task18B requires PostgreSQL 18.4+ 18.x with TLS")
	}

	databaseName := "aiops_worker_cmdb_test_" + task18BRandomHex(t, 16)
	identifier := pgx.Identifier{databaseName}.Sanitize()
	harness := &task18BPostgresHarness{admin: admin, name: databaseName}
	created := false
	t.Cleanup(func() {
		if harness.application != nil {
			harness.application.Close()
		}
		if harness.migration != nil {
			harness.migration.Close()
		}
		if harness.db != nil {
			harness.db.Close()
		}
		if created {
			if _, err := admin.Exec(
				context.Background(),
				"DROP DATABASE IF EXISTS "+identifier+" WITH (FORCE)",
			); err != nil {
				t.Errorf("drop isolated Task18B database %s: %v", databaseName, err)
			}
		}
		admin.Close()
	})
	if _, err := admin.Exec(
		ctx,
		"CREATE DATABASE "+identifier+" WITH TEMPLATE template0 OWNER aiops_schema_owner",
	); err != nil {
		t.Fatalf("create isolated Task18B database; cleanup ownership unconfirmed: %v", err)
	}
	created = true
	if _, err := admin.Exec(ctx, `SET ROLE aiops_schema_owner;
REVOKE ALL ON DATABASE `+identifier+` FROM PUBLIC;
REVOKE ALL ON DATABASE `+identifier+` FROM aiops_control_plane_runtime;
GRANT CONNECT ON DATABASE `+identifier+` TO aiops_migrator;
GRANT CONNECT ON DATABASE `+identifier+` TO aiops_control_plane_workload;
RESET ROLE;`); err != nil {
		t.Fatalf("preprovision Task18B database ACL: %v", err)
	}

	dbConfig, err := pgxpool.ParseConfig(adminDSN)
	if err != nil {
		t.Fatal("parse isolated Task18B control config")
	}
	dbConfig.ConnConfig.Database = databaseName
	dbConfig.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	if dbConfig.ConnConfig.RuntimeParams == nil {
		dbConfig.ConnConfig.RuntimeParams = make(map[string]string)
	}
	dbConfig.ConnConfig.RuntimeParams["search_path"] = "public"
	dbConfig.MaxConns = max(dbConfig.MaxConns, 16)
	harness.db, err = pgxpool.NewWithConfig(ctx, dbConfig)
	if err != nil {
		t.Fatal("connect isolated Task18B control database")
	}
	if _, err := harness.db.Exec(ctx, `ALTER SCHEMA public OWNER TO aiops_schema_owner;
SET ROLE aiops_schema_owner;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM aiops_migrator;
REVOKE ALL ON SCHEMA public FROM aiops_control_plane_workload;
GRANT CREATE, USAGE ON SCHEMA public TO aiops_schema_owner;
GRANT USAGE ON SCHEMA public TO aiops_control_plane_runtime;
RESET ROLE;`); err != nil {
		t.Fatalf("preprovision Task18B schema ACL: %v", err)
	}
	migrationConfig.ConnConfig.Database = databaseName
	harness.migration, err = pgxpool.NewWithConfig(ctx, migrationConfig)
	if err != nil {
		t.Fatal("connect isolated Task18B migration identity")
	}
	applicationConfig.ConnConfig.Database = databaseName
	harness.application, err = pgxpool.NewWithConfig(ctx, applicationConfig)
	if err != nil {
		t.Fatal("connect isolated Task18B application identity")
	}
	return harness
}

func task18BRoleConfig(
	t *testing.T,
	dsn, controlName, expectedUser string,
) *pgxpool.Config {
	t.Helper()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil || config.ConnConfig.Database != controlName ||
		config.ConnConfig.User != expectedUser {
		t.Fatalf("invalid Task18B PostgreSQL identity %s", expectedUser)
	}
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = make(map[string]string)
	}
	config.ConnConfig.RuntimeParams["search_path"] = "pg_catalog,public,pg_temp"
	config.MaxConns = max(config.MaxConns, 16)
	return config
}

func (harness *task18BPostgresHarness) assertTLSIdentities(t *testing.T) {
	t.Helper()
	for _, candidate := range []struct {
		name     string
		pool     *pgxpool.Pool
		identity string
	}{
		{name: "migration", pool: harness.migration, identity: "aiops_migrator"},
		{
			name: "application", pool: harness.application,
			identity: "aiops_control_plane_workload",
		},
	} {
		var version int
		var sessionUser, currentUser, tlsVersion string
		var ssl bool
		if err := candidate.pool.QueryRow(t.Context(), `
SELECT current_setting('server_version_num')::integer,session_user,current_user,
       ssl,version
FROM pg_stat_ssl WHERE pid=pg_backend_pid()
`).Scan(&version, &sessionUser, &currentUser, &ssl, &tlsVersion); err != nil {
			t.Fatalf("read Task18B %s PostgreSQL TLS identity: %v", candidate.name, err)
		}
		if version < 180004 || version >= 190000 || !ssl || tlsVersion != "TLSv1.3" ||
			sessionUser != candidate.identity || currentUser != candidate.identity {
			t.Fatalf("Task18B %s PostgreSQL contract version=%d TLS=%t/%q identity=%q/%q",
				candidate.name, version, ssl, tlsVersion, sessionUser, currentUser)
		}
	}
}

func (harness *task18BPostgresHarness) applyMigrations(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(task18BMigrationDirectory(t))
	if err != nil {
		t.Fatalf("read Task18B migration directory: %v", err)
	}
	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".up.sql") &&
			entry.Name() <= "000015_assets_catalog.up.sql" {
			files = append(files, entry.Name())
		}
	}
	sort.Strings(files)
	if len(files) != 15 {
		t.Fatalf("Task18B migration set through 000015 has %d files, want 15", len(files))
	}
	for _, name := range files {
		harness.applyMigration(t, name)
	}
}

func (harness *task18BPostgresHarness) applyMigration(t *testing.T, name string) {
	t.Helper()
	source, err := os.ReadFile(filepath.Join(task18BMigrationDirectory(t), name))
	if err != nil {
		t.Fatalf("read Task18B migration %s: %v", name, err)
	}
	if name == "000012_outbox_event_routing.up.sql" {
		config := harness.migration.Config().ConnConfig.Copy()
		connection, err := pgx.ConnectConfig(context.Background(), config)
		if err != nil {
			t.Fatalf("connect nontransactional Task18B migration %s", name)
		}
		defer func() { _ = connection.Close(context.Background()) }()
		if _, err := connection.Exec(context.Background(),
			`SET search_path=pg_catalog,public,pg_temp; SET ROLE aiops_schema_owner`,
		); err != nil {
			t.Fatalf("set Task18B nontransactional migration role: %v", err)
		}
		if _, err := connection.Exec(context.Background(), string(source)); err != nil {
			task18BFailMigration(t, name, err)
		}
		if _, err := connection.Exec(context.Background(), `RESET ROLE`); err != nil {
			t.Fatalf("reset Task18B nontransactional migration role: %v", err)
		}
		return
	}
	text := string(source)
	if name != "000015_assets_catalog.up.sql" {
		index := strings.Index(text, "BEGIN;")
		if index < 0 {
			t.Fatalf("Task18B migration %s does not start a transaction", name)
		}
		index += len("BEGIN;")
		text = text[:index] +
			"\nSET LOCAL ROLE aiops_schema_owner;\nSET LOCAL search_path=public,pg_catalog,pg_temp;" +
			text[index:]
	}
	connection, err := harness.migration.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire Task18B migration connection for %s", name)
	}
	defer connection.Release()
	if _, err := connection.Exec(context.Background(), text); err != nil {
		task18BFailMigration(t, name, err)
	}
	if _, err := connection.Exec(context.Background(), `RESET ROLE`); err != nil {
		t.Fatalf("reset Task18B migration role after %s: %v", name, err)
	}
}

func task18BFailMigration(t *testing.T, name string, err error) {
	t.Helper()
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		t.Fatalf("apply Task18B migration %s: %s (SQLSTATE %s, constraint %s)",
			name, databaseError.Message, databaseError.Code, databaseError.ConstraintName)
	}
	t.Fatalf("apply Task18B migration %s: %v", name, err)
}

func task18BMigrationDirectory(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve Task18B integration test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "../../migrations"))
}

func task18BRandomHex(t *testing.T, size int) string {
	t.Helper()
	value := make([]byte, size)
	if _, err := cryptorand.Read(value); err != nil {
		t.Fatalf("read Task18B database randomness: %v", err)
	}
	return hex.EncodeToString(value)
}

type task18BSource struct {
	tenantID, workspaceID, environmentID, integrationID string
	sourceID, revisionID, validationRunID               string
	revisionDigest, sourceDefinitionDigest              string
}

func newTask18BSource() task18BSource {
	return task18BSource{
		tenantID: uuid.NewString(), workspaceID: uuid.NewString(),
		environmentID: uuid.NewString(), integrationID: uuid.NewString(),
		sourceID: uuid.NewString(), revisionID: uuid.NewString(),
		validationRunID: uuid.NewString(),
	}
}

func (source task18BSource) scope() assetcatalog.SourceScope {
	return assetcatalog.SourceScope{
		TenantID: source.tenantID, WorkspaceID: source.workspaceID,
	}
}

func (source task18BSource) runtimeBinding() discoverysource.RuntimeBinding {
	return discoverysource.RuntimeBinding{
		Locator: assetcatalog.SourceLocator{
			Scope: source.scope(), SourceID: source.sourceID,
		},
		SourceRevision: 1, SourceRevisionDigest: source.revisionDigest,
		RevisionStatus: assetcatalog.SourceRevisionPublished,
		ProviderKind:   task18BProviderKind, ProfileCode: task18BProviderKind,
	}
}

func seedTask18BPublishedSource(
	t *testing.T,
	harness *task18BPostgresHarness,
	queue *queuepostgres.Repository,
	broker *discoverycleanup.CleanupBroker,
	source *task18BSource,
	profile assetcatalog.BuiltinSourceProfile,
) {
	t.Helper()
	task18BExec(t, harness.db, `
INSERT INTO tenants(id,name) VALUES($1,'task18b-tenant')
`, source.tenantID)
	task18BExec(t, harness.db, `
INSERT INTO workspaces(id,tenant_id,name) VALUES($1,$2,'task18b-workspace')
`, source.workspaceID, source.tenantID)
	task18BExec(t, harness.db, `
INSERT INTO environments(id,tenant_id,workspace_id,name,kind)
VALUES($1,$2,$3,'task18b-environment','PROD')
`, source.environmentID, source.tenantID, source.workspaceID)
	task18BExec(t, harness.db, `
INSERT INTO integrations(id,tenant_id,workspace_id,provider,name,secret_ref,config)
VALUES($1,$2,$3,'external','task18b-integration','opaque://task18b-cmdb','{}')
`, source.integrationID, source.tenantID, source.workspaceID)

	authority := []string{source.environmentID}
	authorityDigest, err := assetcatalog.AuthorityScopeDigest(authority)
	if err != nil {
		t.Fatalf("Task18B AuthorityScopeDigest() error = %v", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	revision := assetcatalog.SourceRevision{
		ID: source.revisionID, SourceID: source.sourceID,
		TenantID: source.tenantID, WorkspaceID: source.workspaceID,
		Revision: 1, Status: assetcatalog.SourceRevisionDraft,
		CanonicalProfileManifest:      profile.CanonicalProfileManifest,
		ProfileManifestSHA256:         profile.ProfileManifestSHA256,
		CanonicalProviderSchema:       profile.CanonicalProviderSchema,
		CanonicalProviderSchemaSHA256: profile.CanonicalProviderSchemaSHA256,
		IntegrationID:                 profile.IntegrationID, SyncMode: profile.SyncMode,
		CredentialReferenceID:    profile.CredentialReferenceID,
		TrustReferenceID:         profile.TrustReferenceID,
		NetworkPolicyReferenceID: profile.NetworkPolicyReferenceID,
		AuthorityEnvironmentIDs:  authority, AuthorityScopeDigest: authorityDigest,
		RateLimitRequests:       profile.RateLimitRequests,
		RateLimitWindowSeconds:  profile.RateLimitWindowSeconds,
		BackpressureBaseSeconds: profile.BackpressureBaseSeconds,
		BackpressureMaxSeconds:  profile.BackpressureMaxSeconds,
		ProfileCode:             profile.ProfileCode, CreatedBy: "task18b-test",
		ChangeReasonCode: "INITIAL_CREATE", ExpectedSourceVersion: 1,
		Version: 1, CreatedAt: now, UpdatedAt: now,
	}
	revision.SourceDefinitionDigest, err = assetcatalog.SourceDefinitionDigest(
		assetcatalog.Source{
			Kind: assetcatalog.SourceKindExternalCMDB, ProviderKind: task18BProviderKind,
		},
		revision,
	)
	if err != nil {
		t.Fatalf("Task18B SourceDefinitionDigest() error = %v", err)
	}
	revision.CanonicalRevisionDigest = revision.BindingDigest()
	if revision.Validate() != nil {
		t.Fatalf("Task18B draft revision fixture is invalid: %#v", revision)
	}
	source.sourceDefinitionDigest = revision.SourceDefinitionDigest
	source.revisionDigest = revision.CanonicalRevisionDigest

	tx, err := harness.db.BeginTx(t.Context(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin Task18B source definition: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	task18BExec(t, tx, `
INSERT INTO asset_sources(
 id,tenant_id,workspace_id,source_kind,provider_kind,name,
 create_idempotency_key,create_request_hash
) VALUES($1,$2,$3,'EXTERNAL_CMDB','CMDB_CATALOG_V1','task18b external cmdb',
         $4,repeat('1',64))
`, source.sourceID, source.tenantID, source.workspaceID, "task18b-source-"+source.sourceID)
	task18BExec(t, tx, `
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
`, source.revisionID, source.tenantID, source.workspaceID, source.sourceID,
		profile.CanonicalProfileManifest, profile.ProfileManifestSHA256,
		profile.CanonicalProviderSchema, profile.CanonicalProviderSchemaSHA256,
		source.integrationID, authorityDigest, source.sourceDefinitionDigest,
		source.revisionDigest, profile.CredentialReferenceID,
		profile.TrustReferenceID, profile.NetworkPolicyReferenceID)
	task18BExec(t, tx, `
INSERT INTO asset_source_revision_authorities(
 tenant_id,workspace_id,source_id,source_revision,environment_id,canonical_ordinal
) VALUES($1,$2,$3,1,$4,1)
`, source.tenantID, source.workspaceID, source.sourceID, source.environmentID)
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatalf("commit Task18B source definition: %v", err)
	}

	tx, err = harness.db.BeginTx(t.Context(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin Task18B validation admission: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	task18BExec(t, tx, `
INSERT INTO asset_source_runs(
 id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
 run_kind,trigger_type,gate_revision,idempotency_key,request_hash,checkpoint_version
) SELECT $1,$2,$3,$4,1,$5,'VALIDATION','HUMAN',gate_revision,
         $6,repeat('2',64),0 FROM asset_sources WHERE id=$4
`, source.validationRunID, source.tenantID, source.workspaceID, source.sourceID,
		source.revisionDigest, "task18b-validation-"+source.sourceID)
	task18BExec(t, tx, `
UPDATE asset_source_revisions
SET state='VALIDATING',validation_run_id=$2,version=version+1 WHERE id=$1
`, source.revisionID, source.validationRunID)
	task18BExec(t, tx, `
UPDATE asset_sources
SET gate_status='VALIDATING',gate_revision=gate_revision+1,
    validated_run_id=$2,validation_digest=NULL,validated_binding_digest=NULL,
    version=version+1 WHERE id=$1
`, source.sourceID, source.validationRunID)
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatalf("commit Task18B validation admission: %v", err)
	}

	claim, err := queue.Claim(t.Context(), discoveryqueue.ClaimCommand{
		Owner: "task18b-validation-closure", LeaseDuration: 2 * time.Second,
		ProviderKinds: []string{task18BProviderKind},
	})
	if err != nil {
		t.Fatalf("Claim(Task18B validation) error = %v", err)
	}
	defer claim.Destroy()
	coordinates := discoveryqueue.RunCoordinates{
		Scope: source.scope(), RunID: source.validationRunID,
	}
	attempt, err := queue.ReserveCleanupAttempt(
		t.Context(), claim.Fence, discoveryqueue.RunCommand{Coordinates: coordinates},
	)
	if err != nil {
		t.Fatalf("ReserveCleanupAttempt(Task18B validation) error = %v", err)
	}
	session, err := broker.OpenAttempt(t.Context(), discoverycleanup.OpenAttemptRequest{
		Coordinates: coordinates, Attempt: attempt,
	})
	if err != nil {
		t.Fatalf("OpenAttempt(Task18B validation) error = %v", err)
	}
	session.Destroy()
	work, err := queue.ProposeValidationResult(
		t.Context(), claim.Fence,
		discoveryqueue.ValidationResultCommand{
			Coordinates: coordinates, Proof: task18BValidationProof(),
		},
	)
	if err != nil {
		t.Fatalf("ProposeValidationResult(Task18B validation) error = %v", err)
	}
	proof, err := broker.RevokeAttempt(t.Context(), attempt.AttemptID)
	if err != nil {
		t.Fatalf("RevokeAttempt(Task18B validation) error = %v", err)
	}
	defer proof.Destroy()
	cleanup, err := queue.RecordCleanup(t.Context(), claim.Fence, proof)
	if err != nil {
		t.Fatalf("RecordCleanup(Task18B validation) error = %v", err)
	}
	if _, err := queue.Complete(t.Context(), claim.Fence, discoveryqueue.TerminalCommand{
		Coordinates: coordinates, DesiredStatus: assetcatalog.RunStatusSucceeded,
		WorkResultDigest: work.DigestSHA256,
		CleanupStatus:    cleanup.Status, CleanupDigest: cleanup.DigestSHA256,
	}); err != nil {
		t.Fatalf("Complete(Task18B validation) error = %v", err)
	}
	task18BExec(t, harness.db, `
UPDATE asset_source_revisions SET state='PUBLISHED',version=version+1 WHERE id=$1
`, source.revisionID)
	available, err := harness.db.BeginTx(
		t.Context(), pgx.TxOptions{IsoLevel: pgx.Serializable},
	)
	if err != nil {
		t.Fatalf("begin Task18B AVAILABLE closure: %v", err)
	}
	defer func() { _ = available.Rollback(context.Background()) }()
	task18BExec(t, available, `
UPDATE asset_sources
SET gate_status='AVAILABLE',gate_reason_code=NULL,gate_revision=gate_revision+1,
    validated_run_id=$2,validation_digest=$3,validated_binding_digest=$4,
    version=version+1
WHERE id=$1
`, source.sourceID, source.validationRunID, work.DigestSHA256, source.revisionDigest)
	if err := available.Commit(t.Context()); err != nil {
		t.Fatalf("commit Task18B AVAILABLE closure: %v", err)
	}
}

func task18BValidationProof() discoverysource.ValidationProof {
	return discoverysource.ValidationProof{
		Outcome: assetcatalog.ValidationOutcomeSucceeded,
		Code:    "VALIDATION_SUCCEEDED",
		Checks: []discoverysource.ValidationCheck{
			{Kind: discoverysource.ValidationCheckIdentity, Code: "IDENTITY_VERIFIED", Passed: true, Count: 1},
			{Kind: discoverysource.ValidationCheckTrustOrSignature, Code: "TRUST_OR_SIGNATURE_VERIFIED", Passed: true, Count: 1},
			{Kind: discoverysource.ValidationCheckNetwork, Code: "NETWORK_VERIFIED", Passed: true, Count: 1},
			{Kind: discoverysource.ValidationCheckCredentialOpen, Code: "CREDENTIAL_OPEN_VERIFIED", Passed: true, Count: 1},
			{Kind: discoverysource.ValidationCheckFixedProbe, Code: "FIXED_PROBE_VERIFIED", Passed: true, Count: 1},
			{Kind: discoverysource.ValidationCheckSchema, Code: "SCHEMA_VERIFIED", Passed: true, Count: 1},
			{Kind: discoverysource.ValidationCheckDLP, Code: "DLP_VERIFIED", Passed: true, Count: 1},
			{Kind: discoverysource.ValidationCheckBudget, Code: "BUDGET_VERIFIED", Passed: true, Count: 1},
		},
	}
}

type task18BSQLExecutor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func task18BExec(
	t *testing.T,
	executor task18BSQLExecutor,
	statement string,
	arguments ...any,
) {
	t.Helper()
	if _, err := executor.Exec(t.Context(), statement, arguments...); err != nil {
		var databaseError *pgconn.PgError
		if errors.As(err, &databaseError) {
			t.Fatalf("Task18B fixture SQL failed: %s (SQLSTATE %s, constraint %s)",
				databaseError.Message, databaseError.Code, databaseError.ConstraintName)
		}
		t.Fatalf("Task18B fixture SQL failed: %v", err)
	}
}
