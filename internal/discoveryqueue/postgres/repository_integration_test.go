package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
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
	"github.com/seaworld008/aiops-system/internal/discoveryqueue"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
)

func TestIntegrationConcurrentClaimHasOneWinner(t *testing.T) {
	harness := newQueueHarness(t)
	harness.applyMigrations(t)
	base := seedQueueBase(t, harness.db)
	fixture := seedValidationQueueRun(t, harness.db, base, "single-winner")

	first := newTestQueue(t, harness.application)
	second := newTestQueue(t, harness.application)
	command := discoveryqueue.ClaimCommand{
		Owner: "queue-concurrent-worker", LeaseDuration: 5 * time.Second,
		ProviderKinds: []string{fixture.providerKind},
	}
	type outcome struct {
		result discoveryqueue.ClaimResult
		err    error
	}
	start := make(chan struct{})
	outcomes := make(chan outcome, 2)
	var wait sync.WaitGroup
	for _, repository := range []*Repository{first, second} {
		wait.Add(1)
		go func(repository *Repository) {
			defer wait.Done()
			<-start
			result, err := repository.Claim(context.Background(), command)
			outcomes <- outcome{result: result, err: err}
		}(repository)
	}
	close(start)
	wait.Wait()
	close(outcomes)

	winners, empty := 0, 0
	for value := range outcomes {
		switch {
		case value.err == nil:
			winners++
			if value.result.Run.ID != fixture.runID || value.result.Run.FenceEpoch != 1 ||
				value.result.Run.HeartbeatSequence != 1 || value.result.Mode != discoveryqueue.ClaimModeProvider {
				t.Fatalf("winning claim = %#v", value.result.Run)
			}
			value.result.Destroy()
		case errors.Is(value.err, discoveryqueue.ErrNoWork):
			empty++
		default:
			t.Fatalf("concurrent Claim() error = %v", value.err)
		}
	}
	if winners != 1 || empty != 1 {
		t.Fatalf("concurrent outcomes winners=%d no-work=%d, want 1/1", winners, empty)
	}
}

func TestIntegrationExpiredReclaimAdvancesEpochAndRejectsOldFence(t *testing.T) {
	harness := newQueueHarness(t)
	harness.applyMigrations(t)
	base := seedQueueBase(t, harness.db)
	fixture := seedValidationQueueRun(t, harness.db, base, "expired-reclaim")
	repository := newTestQueue(t, harness.application)

	first, err := repository.Claim(context.Background(), discoveryqueue.ClaimCommand{
		Owner: "queue-worker-a", LeaseDuration: 75 * time.Millisecond,
		ProviderKinds: []string{fixture.providerKind},
	})
	if err != nil {
		t.Fatalf("first Claim() error = %v", err)
	}
	t.Cleanup(first.Destroy)
	time.Sleep(125 * time.Millisecond)
	second, err := repository.Reclaim(context.Background(), discoveryqueue.ReclaimCommand{
		Owner: "queue-worker-b", LeaseDuration: 5 * time.Second,
		ProviderKinds: []string{fixture.providerKind},
	})
	if err != nil {
		t.Fatalf("Reclaim() error = %v", err)
	}
	t.Cleanup(second.Destroy)
	if second.Run.FenceEpoch != first.Run.FenceEpoch+1 {
		t.Fatalf("epochs = %d,%d, want old+1", first.Run.FenceEpoch, second.Run.FenceEpoch)
	}
	_, err = repository.Heartbeat(context.Background(), first.Fence, discoveryqueue.HeartbeatCommand{
		Coordinates: discoveryqueue.RunCoordinates{
			Scope: assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID},
			RunID: fixture.runID,
		},
		Sequence:  first.Run.HeartbeatSequence + 1,
		Extension: time.Second,
	})
	if !errors.Is(err, discoveryqueue.ErrStaleFence) {
		t.Fatalf("old Heartbeat() error = %v, want ErrStaleFence", err)
	}
}

func TestIntegrationHeartbeatRequiresStrictNextSequence(t *testing.T) {
	harness := newQueueHarness(t)
	harness.applyMigrations(t)
	base := seedQueueBase(t, harness.db)
	fixture := seedValidationQueueRun(t, harness.db, base, "heartbeat-sequence")
	repository := newTestQueue(t, harness.application)
	claim, err := repository.Claim(context.Background(), discoveryqueue.ClaimCommand{
		Owner: "queue-heartbeat-worker", LeaseDuration: 5 * time.Second,
		ProviderKinds: []string{fixture.providerKind},
	})
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	t.Cleanup(claim.Destroy)
	coordinates := discoveryqueue.RunCoordinates{
		Scope: assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID},
		RunID: fixture.runID,
	}
	command := discoveryqueue.HeartbeatCommand{
		Coordinates: coordinates, Sequence: claim.Run.HeartbeatSequence + 2, Extension: time.Second,
	}
	if _, err := repository.Heartbeat(context.Background(), claim.Fence, command); !errors.Is(err, discoveryqueue.ErrStateConflict) {
		t.Fatalf("skipped Heartbeat() error = %v, want ErrStateConflict", err)
	}
	command.Sequence = claim.Run.HeartbeatSequence + 1
	heartbeat, err := repository.Heartbeat(context.Background(), claim.Fence, command)
	if err != nil {
		t.Fatalf("next Heartbeat() error = %v", err)
	}
	if heartbeat.Run.HeartbeatSequence != command.Sequence {
		t.Fatalf("heartbeat sequence = %d, want %d", heartbeat.Run.HeartbeatSequence, command.Sequence)
	}
	if _, err := repository.Heartbeat(context.Background(), claim.Fence, command); !errors.Is(err, discoveryqueue.ErrStateConflict) {
		t.Fatalf("replayed Heartbeat() error = %v, want ErrStateConflict", err)
	}
}

func TestIntegrationOldFenceIsRejectedAtEveryQueueMutationBoundary(t *testing.T) {
	harness := newQueueHarness(t)
	harness.applyMigrations(t)
	base := seedQueueBase(t, harness.db)
	fixture := seedValidationQueueRun(t, harness.db, base, "all-stale-boundaries")
	repository := newTestQueue(t, harness.application)
	first, err := repository.Claim(context.Background(), discoveryqueue.ClaimCommand{
		Owner: "queue-stale-worker-a", LeaseDuration: 100 * time.Millisecond,
		ProviderKinds: []string{fixture.providerKind},
	})
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	t.Cleanup(first.Destroy)
	coordinates := discoveryqueue.RunCoordinates{
		Scope: assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID},
		RunID: fixture.runID,
	}
	attempt, err := repository.ReserveCleanupAttempt(
		context.Background(), first.Fence, discoveryqueue.RunCommand{Coordinates: coordinates},
	)
	if err != nil {
		t.Fatalf("ReserveCleanupAttempt() error = %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	current, err := repository.Reclaim(context.Background(), discoveryqueue.ReclaimCommand{
		Owner: "queue-stale-worker-b", LeaseDuration: 5 * time.Second,
		ProviderKinds: []string{fixture.providerKind},
	})
	if err != nil {
		t.Fatalf("Reclaim() error = %v", err)
	}
	t.Cleanup(current.Destroy)
	if current.PersistedDelay == nil {
		t.Fatal("Reclaim() did not persist the cleanup-only delay intent")
	}
	intent := discoveryqueue.DelayIntent{
		Reason: current.PersistedDelay.Reason, NotBefore: current.PersistedDelay.NotBefore,
	}
	proof := newQueueCleanupProof(
		t, coordinates, attempt, assetcatalog.CredentialCleanupRevoked, strings.Repeat("a", 64),
	)
	workDigest := strings.Repeat("b", 64)
	cleanupDigest := strings.Repeat("c", 64)
	tests := []struct {
		name string
		call func() error
	}{
		{"Heartbeat", func() error {
			_, err := repository.Heartbeat(context.Background(), first.Fence, discoveryqueue.HeartbeatCommand{
				Coordinates: coordinates, Sequence: current.Run.HeartbeatSequence + 1, Extension: time.Second,
			})
			return err
		}},
		{"AdvanceStage", func() error {
			_, err := repository.AdvanceStage(context.Background(), first.Fence, discoveryqueue.AdvanceStageCommand{
				Coordinates: coordinates, From: assetcatalog.RunStageValidating,
				To: assetcatalog.RunStageCleaningUp, Delay: &intent,
			})
			return err
		}},
		{"ReserveCleanupAttempt", func() error {
			_, err := repository.ReserveCleanupAttempt(
				context.Background(), first.Fence, discoveryqueue.RunCommand{Coordinates: coordinates},
			)
			return err
		}},
		{"RecordCleanup", func() error {
			_, err := repository.RecordCleanup(context.Background(), first.Fence, proof)
			return err
		}},
		{"Delay", func() error {
			_, err := repository.Delay(context.Background(), first.Fence,
				discoveryqueue.DelayCommand{Coordinates: coordinates, Intent: intent})
			return err
		}},
		{"ProposeValidationResult", func() error {
			_, err := repository.ProposeValidationResult(context.Background(), first.Fence,
				discoveryqueue.ValidationResultCommand{Coordinates: coordinates, Proof: queueValidationSuccessProof()})
			return err
		}},
		{"PrepareFailureIntent", func() error {
			_, err := repository.PrepareFailureIntent(context.Background(), first.Fence,
				discoveryqueue.FailureIntentCommand{
					Coordinates: coordinates, FailureCode: "PROVIDER_FAILED",
					EvidenceDigest: strings.Repeat("d", 64),
				})
			return err
		}},
		{"BeginCheckpointLineageRollover", func() error {
			_, err := repository.BeginCheckpointLineageRollover(context.Background(), first.Fence,
				discoveryqueue.RolloverCommand{
					Coordinates: coordinates, ReasonCode: "PROVIDER_CURSOR_EXPIRED",
					EvidenceDigest: strings.Repeat("e", 64),
				})
			return err
		}},
		{"Complete", func() error {
			_, err := repository.Complete(context.Background(), first.Fence, discoveryqueue.TerminalCommand{
				Coordinates: coordinates, DesiredStatus: assetcatalog.RunStatusSucceeded,
				WorkResultDigest: workDigest,
				CleanupStatus:    assetcatalog.CredentialCleanupRevoked, CleanupDigest: cleanupDigest,
			})
			return err
		}},
		{"Fail", func() error {
			_, err := repository.Fail(context.Background(), first.Fence, discoveryqueue.TerminalCommand{
				Coordinates: coordinates, DesiredStatus: assetcatalog.RunStatusFailed,
				WorkResultDigest: workDigest,
				CleanupStatus:    assetcatalog.CredentialCleanupNotOpened,
				FailureCode:      "PROVIDER_FAILED",
			})
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); !errors.Is(err, discoveryqueue.ErrStaleFence) {
				t.Fatalf("old-fence %s error = %v, want ErrStaleFence", test.name, err)
			}
		})
	}
}

func TestIntegrationCancelIneligibleClosesValidationBinding(t *testing.T) {
	harness := newQueueHarness(t)
	harness.applyMigrations(t)
	base := seedQueueBase(t, harness.db)
	fixture := seedValidationQueueRun(t, harness.db, base, "cancel-ineligible")
	repository := newTestQueue(t, harness.application)

	queueExec(t, harness.db, `
UPDATE asset_sources SET status='PAUSED',version=version+1 WHERE id=$1
`, fixture.sourceID)
	cancelled, err := repository.CancelIneligible(context.Background(), discoveryqueue.CancelCommand{
		ProviderKinds: []string{fixture.providerKind},
	})
	if err != nil {
		t.Fatalf("CancelIneligible() error = %v", err)
	}
	if cancelled.Replayed || cancelled.Run.ID != fixture.runID ||
		cancelled.Run.Status != assetcatalog.RunStatusCancelled ||
		cancelled.Run.Stage != assetcatalog.RunStageCompleted || cancelled.Run.CompletedAt == nil {
		t.Fatalf("cancelled run = %#v", cancelled)
	}
	if _, err := repository.CancelIneligible(context.Background(), discoveryqueue.CancelCommand{
		ProviderKinds: []string{fixture.providerKind},
	}); !errors.Is(err, discoveryqueue.ErrNoWork) {
		t.Fatalf("second CancelIneligible() error = %v, want ErrNoWork", err)
	}

	var runStatus, revisionStatus, rejectionDigest string
	if err := harness.db.QueryRow(context.Background(), `
SELECT run.status,revision.state,revision.validation_digest
FROM asset_source_runs AS run
JOIN asset_source_revisions AS revision
  ON revision.source_id=run.source_id AND revision.revision=run.source_revision
WHERE run.id=$1
`, fixture.runID).Scan(&runStatus, &revisionStatus, &rejectionDigest); err != nil {
		t.Fatalf("read cancelled validation closure: %v", err)
	}
	if runStatus != "CANCELLED" || revisionStatus != "REJECTED" || rejectionDigest != strings.Repeat("2", 64) {
		t.Fatalf("cancel closure run=%s revision=%s digest=%s", runStatus, revisionStatus, rejectionDigest)
	}
}

func TestIntegrationReapDriftedPersistsFailureIntentWithoutProviderAccess(t *testing.T) {
	harness := newQueueHarness(t)
	harness.applyMigrations(t)
	base := seedQueueBase(t, harness.db)
	fixture := seedValidationQueueRun(t, harness.db, base, "reap-drifted")
	repository := newTestQueue(t, harness.application)
	first, err := repository.Claim(context.Background(), discoveryqueue.ClaimCommand{
		Owner: "queue-drift-worker-a", LeaseDuration: 75 * time.Millisecond,
		ProviderKinds: []string{fixture.providerKind},
	})
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	t.Cleanup(first.Destroy)
	queueExec(t, harness.db, `
UPDATE asset_sources SET status='PAUSED',version=version+1 WHERE id=$1
`, fixture.sourceID)
	time.Sleep(125 * time.Millisecond)

	reaped, err := repository.ReapDrifted(context.Background(), discoveryqueue.ReapCommand{
		Owner: "queue-drift-reaper", LeaseDuration: 5 * time.Second,
		ProviderKinds: []string{fixture.providerKind}, FailureCode: "SOURCE_DRIFT",
	})
	if err != nil {
		t.Fatalf("ReapDrifted() error = %v", err)
	}
	t.Cleanup(reaped.Destroy)
	if reaped.Run.FenceEpoch != first.Run.FenceEpoch+1 || reaped.Mode != discoveryqueue.ClaimModeTerminal ||
		reaped.Run.Status != assetcatalog.RunStatusFinalizing ||
		reaped.Run.Stage != assetcatalog.RunStageCleaningUp ||
		reaped.Run.WorkResultKind != assetcatalog.WorkResultFailureIntent ||
		reaped.Run.WorkResultStatus != assetcatalog.WorkResultStatusFailed ||
		reaped.Run.WorkResultDigest == "" || reaped.Run.FailureCode != "SOURCE_DRIFT" ||
		reaped.Run.CredentialCleanupStatus != assetcatalog.CredentialCleanupNotOpened {
		t.Fatalf("reaped run = %#v, mode=%s", reaped.Run, reaped.Mode)
	}
	coordinates := discoveryqueue.RunCoordinates{
		Scope: assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID},
		RunID: fixture.runID,
	}
	if _, err := repository.Heartbeat(context.Background(), first.Fence, discoveryqueue.HeartbeatCommand{
		Coordinates: coordinates, Sequence: first.Run.HeartbeatSequence + 1, Extension: time.Second,
	}); !errors.Is(err, discoveryqueue.ErrStaleFence) {
		t.Fatalf("old Heartbeat() error = %v, want ErrStaleFence", err)
	}
	if _, err := repository.Fail(context.Background(), reaped.Fence, discoveryqueue.TerminalCommand{
		Coordinates: coordinates, DesiredStatus: assetcatalog.RunStatusFailed,
		WorkResultDigest: reaped.Run.WorkResultDigest,
		CleanupStatus:    assetcatalog.CredentialCleanupNotOpened,
		FailureCode:      "SOURCE_DRIFT",
	}); err != nil {
		t.Fatalf("Fail(drifted) error = %v", err)
	}
	var runStatus, revisionStatus string
	if err := harness.db.QueryRow(context.Background(), `
SELECT run.status,revision.state
FROM asset_source_runs AS run
JOIN asset_source_revisions AS revision
  ON revision.source_id=run.source_id AND revision.revision=run.source_revision
WHERE run.id=$1
`, fixture.runID).Scan(&runStatus, &revisionStatus); err != nil {
		t.Fatalf("read reaped terminal closure: %v", err)
	}
	if runStatus != "FAILED" || revisionStatus != "REJECTED" {
		t.Fatalf("reaped terminal run=%s revision=%s", runStatus, revisionStatus)
	}
}

func TestIntegrationReapDriftedPendingAttemptIsCleanupOnly(t *testing.T) {
	harness := newQueueHarness(t)
	harness.applyMigrations(t)
	base := seedQueueBase(t, harness.db)
	fixture := seedValidationQueueRun(t, harness.db, base, "reap-drifted-pending")
	repository := newTestQueue(t, harness.application)
	first, err := repository.Claim(context.Background(), discoveryqueue.ClaimCommand{
		Owner: "queue-drift-pending-worker-a", LeaseDuration: 100 * time.Millisecond,
		ProviderKinds: []string{fixture.providerKind},
	})
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	t.Cleanup(first.Destroy)
	coordinates := discoveryqueue.RunCoordinates{
		Scope: assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID},
		RunID: fixture.runID,
	}
	attempt, err := repository.ReserveCleanupAttempt(
		context.Background(), first.Fence, discoveryqueue.RunCommand{Coordinates: coordinates},
	)
	if err != nil {
		t.Fatalf("ReserveCleanupAttempt() error = %v", err)
	}
	queueExec(t, harness.db, `
UPDATE asset_sources SET status='PAUSED',version=version+1 WHERE id=$1
`, fixture.sourceID)
	time.Sleep(150 * time.Millisecond)
	reaped, err := repository.ReapDrifted(context.Background(), discoveryqueue.ReapCommand{
		Owner: "queue-drift-pending-reaper", LeaseDuration: 5 * time.Second,
		ProviderKinds: []string{fixture.providerKind}, FailureCode: "SOURCE_DRIFT",
	})
	if err != nil {
		t.Fatalf("ReapDrifted() error = %v", err)
	}
	t.Cleanup(reaped.Destroy)
	if reaped.Mode != discoveryqueue.ClaimModeCleanupOnly || reaped.CleanupAttempt == nil ||
		*reaped.CleanupAttempt != attempt || reaped.Run.Status != assetcatalog.RunStatusFinalizing ||
		reaped.Run.WorkResultKind != assetcatalog.WorkResultFailureIntent ||
		reaped.Run.CredentialCleanupStatus != assetcatalog.CredentialCleanupPending {
		t.Fatalf("reaped pending run = %#v mode=%s attempt=%#v", reaped.Run, reaped.Mode, reaped.CleanupAttempt)
	}
	cleanupDigest := strings.Repeat("f", 64)
	proof := newQueueCleanupProof(
		t, coordinates, attempt, assetcatalog.CredentialCleanupRevoked, cleanupDigest,
	)
	if _, err := repository.RecordCleanup(context.Background(), reaped.Fence, proof); err != nil {
		t.Fatalf("RecordCleanup(reaped pending) error = %v", err)
	}
	if _, err := repository.Fail(context.Background(), reaped.Fence, discoveryqueue.TerminalCommand{
		Coordinates: coordinates, DesiredStatus: assetcatalog.RunStatusFailed,
		WorkResultDigest: reaped.Run.WorkResultDigest,
		CleanupStatus:    assetcatalog.CredentialCleanupRevoked, CleanupDigest: cleanupDigest,
		FailureCode: "SOURCE_DRIFT",
	}); err != nil {
		t.Fatalf("Fail(reaped pending) error = %v", err)
	}
}

func TestIntegrationReapDriftedConsumesPersistedDelayBeforeCancellation(t *testing.T) {
	harness := newQueueHarness(t)
	harness.applyMigrations(t)
	base := seedQueueBase(t, harness.db)
	fixture := seedValidationQueueRun(t, harness.db, base, "reap-drifted-delay")
	repository := newTestQueue(t, harness.application)
	first, err := repository.Claim(context.Background(), discoveryqueue.ClaimCommand{
		Owner: "queue-drift-delay-worker-a", LeaseDuration: 100 * time.Millisecond,
		ProviderKinds: []string{fixture.providerKind},
	})
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	t.Cleanup(first.Destroy)
	coordinates := discoveryqueue.RunCoordinates{
		Scope: assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID},
		RunID: fixture.runID,
	}
	attempt, err := repository.ReserveCleanupAttempt(
		context.Background(), first.Fence, discoveryqueue.RunCommand{Coordinates: coordinates},
	)
	if err != nil {
		t.Fatalf("ReserveCleanupAttempt() error = %v", err)
	}
	intent := discoveryqueue.DelayIntent{
		Reason:    discoveryqueue.DelayReasonTransportBackoff,
		NotBefore: time.Now().UTC().Add(2 * time.Second).Truncate(time.Microsecond),
	}
	if _, err := repository.AdvanceStage(context.Background(), first.Fence, discoveryqueue.AdvanceStageCommand{
		Coordinates: coordinates, From: assetcatalog.RunStageValidating,
		To: assetcatalog.RunStageCleaningUp, Delay: &intent,
	}); err != nil {
		t.Fatalf("AdvanceStage(cleanup) error = %v", err)
	}
	queueExec(t, harness.db, `
UPDATE asset_sources SET status='PAUSED',version=version+1 WHERE id=$1
`, fixture.sourceID)
	time.Sleep(150 * time.Millisecond)

	reaped, err := repository.ReapDrifted(context.Background(), discoveryqueue.ReapCommand{
		Owner: "queue-drift-delay-reaper", LeaseDuration: 5 * time.Second,
		ProviderKinds: []string{fixture.providerKind}, FailureCode: "SOURCE_DRIFT",
	})
	if err != nil {
		t.Fatalf("ReapDrifted() error = %v", err)
	}
	t.Cleanup(reaped.Destroy)
	if reaped.Mode != discoveryqueue.ClaimModeCleanupOnly || reaped.CleanupAttempt == nil ||
		*reaped.CleanupAttempt != attempt || reaped.PersistedDelay == nil ||
		reaped.PersistedDelay.Reason != intent.Reason ||
		!reaped.PersistedDelay.NotBefore.Equal(intent.NotBefore) ||
		reaped.Run.Status != assetcatalog.RunStatusRunning || reaped.Run.WorkResultKind != "" ||
		reaped.Run.CredentialCleanupStatus != assetcatalog.CredentialCleanupPending {
		t.Fatalf("reaped persisted delay = %#v run=%#v", reaped.PersistedDelay, reaped.Run)
	}
	proof := newQueueCleanupProof(
		t, coordinates, attempt, assetcatalog.CredentialCleanupRevoked, strings.Repeat("e", 64),
	)
	if _, err := repository.RecordCleanup(context.Background(), reaped.Fence, proof); err != nil {
		t.Fatalf("RecordCleanup(reaped delay) error = %v", err)
	}
	if _, err := repository.Delay(context.Background(), reaped.Fence, discoveryqueue.DelayCommand{
		Coordinates: coordinates, Intent: intent,
	}); err != nil {
		t.Fatalf("Delay(reaped drift) error = %v", err)
	}
	cancelled, err := repository.CancelIneligible(context.Background(), discoveryqueue.CancelCommand{
		ProviderKinds: []string{fixture.providerKind},
	})
	if err != nil {
		t.Fatalf("CancelIneligible() error = %v", err)
	}
	if cancelled.Run.ID != fixture.runID || cancelled.Run.Status != assetcatalog.RunStatusCancelled {
		t.Fatalf("cancelled drifted delay = %#v", cancelled.Run)
	}
	var revisionStatus string
	if err := harness.db.QueryRow(context.Background(), `
SELECT state FROM asset_source_revisions WHERE id=$1
`, fixture.revisionID).Scan(&revisionStatus); err != nil {
		t.Fatalf("read cancelled revision: %v", err)
	}
	if revisionStatus != "REJECTED" {
		t.Fatalf("cancelled revision state = %s, want REJECTED", revisionStatus)
	}
}

func TestIntegrationReapDriftedConsumesReceiptedDelayBeforeCancellation(t *testing.T) {
	harness := newQueueHarness(t)
	harness.applyMigrations(t)
	base := seedQueueBase(t, harness.db)
	fixture := seedValidationQueueRun(t, harness.db, base, "reap-drifted-clean-delay")
	repository := newTestQueue(t, harness.application)
	first, err := repository.Claim(context.Background(), discoveryqueue.ClaimCommand{
		Owner: "queue-drift-clean-delay-worker-a", LeaseDuration: 100 * time.Millisecond,
		ProviderKinds: []string{fixture.providerKind},
	})
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	t.Cleanup(first.Destroy)
	coordinates := discoveryqueue.RunCoordinates{
		Scope: assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID},
		RunID: fixture.runID,
	}
	attempt, err := repository.ReserveCleanupAttempt(
		context.Background(), first.Fence, discoveryqueue.RunCommand{Coordinates: coordinates},
	)
	if err != nil {
		t.Fatalf("ReserveCleanupAttempt() error = %v", err)
	}
	intent := discoveryqueue.DelayIntent{
		Reason:    discoveryqueue.DelayReasonTransportBackoff,
		NotBefore: time.Now().UTC().Add(2 * time.Second).Truncate(time.Microsecond),
	}
	if _, err := repository.AdvanceStage(context.Background(), first.Fence, discoveryqueue.AdvanceStageCommand{
		Coordinates: coordinates, From: assetcatalog.RunStageValidating,
		To: assetcatalog.RunStageCleaningUp, Delay: &intent,
	}); err != nil {
		t.Fatalf("AdvanceStage(cleanup) error = %v", err)
	}
	proof := newQueueCleanupProof(
		t, coordinates, attempt, assetcatalog.CredentialCleanupRevoked, strings.Repeat("d", 64),
	)
	if _, err := repository.RecordCleanup(context.Background(), first.Fence, proof); err != nil {
		t.Fatalf("RecordCleanup() error = %v", err)
	}
	queueExec(t, harness.db, `
UPDATE asset_sources SET status='PAUSED',version=version+1 WHERE id=$1
`, fixture.sourceID)
	time.Sleep(150 * time.Millisecond)

	reaped, err := repository.ReapDrifted(context.Background(), discoveryqueue.ReapCommand{
		Owner: "queue-drift-clean-delay-reaper", LeaseDuration: 5 * time.Second,
		ProviderKinds: []string{fixture.providerKind}, FailureCode: "SOURCE_DRIFT",
	})
	if err != nil {
		t.Fatalf("ReapDrifted() error = %v", err)
	}
	t.Cleanup(reaped.Destroy)
	if reaped.Mode != discoveryqueue.ClaimModeCleanupOnly || reaped.CleanupAttempt == nil ||
		*reaped.CleanupAttempt != attempt || reaped.PersistedDelay == nil ||
		reaped.PersistedDelay.Reason != intent.Reason ||
		!reaped.PersistedDelay.NotBefore.Equal(intent.NotBefore) ||
		reaped.Run.Status != assetcatalog.RunStatusRunning || reaped.Run.WorkResultKind != "" ||
		reaped.Run.CredentialCleanupStatus != assetcatalog.CredentialCleanupRevoked {
		t.Fatalf("reaped receipted delay = %#v run=%#v", reaped.PersistedDelay, reaped.Run)
	}
	if _, err := repository.Delay(context.Background(), reaped.Fence, discoveryqueue.DelayCommand{
		Coordinates: coordinates, Intent: intent,
	}); err != nil {
		t.Fatalf("Delay(reaped receipted drift) error = %v", err)
	}
	cancelled, err := repository.CancelIneligible(context.Background(), discoveryqueue.CancelCommand{
		ProviderKinds: []string{fixture.providerKind},
	})
	if err != nil {
		t.Fatalf("CancelIneligible() error = %v", err)
	}
	if cancelled.Run.ID != fixture.runID || cancelled.Run.Status != assetcatalog.RunStatusCancelled {
		t.Fatalf("cancelled receipted drift = %#v", cancelled.Run)
	}
}

func TestIntegrationCleanupAttemptReceiptAndDelayReplay(t *testing.T) {
	harness := newQueueHarness(t)
	harness.applyMigrations(t)
	base := seedQueueBase(t, harness.db)
	fixture := seedValidationQueueRun(t, harness.db, base, "cleanup-delay")
	repository := newTestQueue(t, harness.application)
	claim, err := repository.Claim(context.Background(), discoveryqueue.ClaimCommand{
		Owner: "queue-cleanup-worker", LeaseDuration: 5 * time.Second,
		ProviderKinds: []string{fixture.providerKind},
	})
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	t.Cleanup(claim.Destroy)
	coordinates := discoveryqueue.RunCoordinates{
		Scope: assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID},
		RunID: fixture.runID,
	}
	first, err := repository.ReserveCleanupAttempt(
		context.Background(), claim.Fence, discoveryqueue.RunCommand{Coordinates: coordinates},
	)
	if err != nil {
		t.Fatalf("ReserveCleanupAttempt() error = %v", err)
	}
	replay, err := repository.ReserveCleanupAttempt(
		context.Background(), claim.Fence, discoveryqueue.RunCommand{Coordinates: coordinates},
	)
	if err != nil || replay != first {
		t.Fatalf("reserve replay = %#v,%v, want %#v", replay, err, first)
	}
	intent := discoveryqueue.DelayIntent{
		Reason:    discoveryqueue.DelayReasonProviderRetryAfter,
		NotBefore: time.Now().UTC().Add(500 * time.Millisecond).Truncate(time.Microsecond),
	}
	if _, err := repository.AdvanceStage(context.Background(), claim.Fence, discoveryqueue.AdvanceStageCommand{
		Coordinates: coordinates, From: assetcatalog.RunStageValidating,
		To: assetcatalog.RunStageCleaningUp, Delay: &intent,
	}); err != nil {
		t.Fatalf("AdvanceStage(cleanup) error = %v", err)
	}
	row := readQueueRunRow(t, harness.application, coordinates)
	goDelayDigest, err := delayIntentDigest(row, intent)
	if err != nil {
		t.Fatalf("delayIntentDigest() error = %v", err)
	}
	var sqlDelayDigest string
	if err := harness.application.QueryRow(context.Background(), `
SELECT asset_catalog_source_run_delay_intent_digest(run,$2,$3)
FROM asset_source_runs AS run WHERE id=$1
`, fixture.runID, intent.Reason, intent.NotBefore).Scan(&sqlDelayDigest); err != nil {
		t.Fatalf("SQL delay intent digest: %v", err)
	}
	if row.pendingDigest == nil || *row.pendingDigest != goDelayDigest || goDelayDigest != sqlDelayDigest {
		t.Fatalf("delay digest persisted=%v Go=%s SQL=%s", row.pendingDigest, goDelayDigest, sqlDelayDigest)
	}
	proof := newQueueCleanupProof(t, coordinates, first, assetcatalog.CredentialCleanupRevoked, strings.Repeat("a", 64))
	cleaned, err := repository.RecordCleanup(context.Background(), claim.Fence, proof)
	if err != nil {
		t.Fatalf("RecordCleanup() error = %v", err)
	}
	cleanedReplay, err := repository.RecordCleanup(context.Background(), claim.Fence, proof)
	if err != nil || !cleanedReplay.Replayed || cleanedReplay.Attempt != cleaned.Attempt ||
		cleanedReplay.DigestSHA256 != cleaned.DigestSHA256 {
		t.Fatalf("cleanup replay = %#v,%v, first=%#v", cleanedReplay, err, cleaned)
	}
	var receipts int
	if err := harness.db.QueryRow(context.Background(), `
SELECT count(*) FROM audit_records
WHERE workspace_id=$1 AND request_id='source-attempt:'||$2||':'||$3::text
`, fixture.workspaceID, fixture.runID, first.AttemptEpoch).Scan(&receipts); err != nil || receipts != 1 {
		t.Fatalf("cleanup receipt count=%d error=%v, want 1", receipts, err)
	}
	delayed, err := repository.Delay(context.Background(), claim.Fence, discoveryqueue.DelayCommand{
		Coordinates: coordinates, Intent: intent,
	})
	if err != nil {
		t.Fatalf("Delay() error = %v", err)
	}
	if delayed.Status != assetcatalog.RunStatusDelayed || delayed.Stage != assetcatalog.RunStageDelayed ||
		delayed.LeaseExpiresAt != nil {
		t.Fatalf("delayed run = %#v", delayed)
	}
	time.Sleep(time.Until(intent.NotBefore) + 50*time.Millisecond)
	fresh, err := repository.Claim(context.Background(), discoveryqueue.ClaimCommand{
		Owner: "queue-cleanup-worker-next", LeaseDuration: 5 * time.Second,
		ProviderKinds: []string{fixture.providerKind},
	})
	if err != nil {
		t.Fatalf("fresh Claim() error = %v", err)
	}
	defer fresh.Destroy()
	if fresh.Run.FenceEpoch != claim.Run.FenceEpoch+1 ||
		fresh.Run.CredentialCleanupStatus != assetcatalog.CredentialCleanupNotOpened {
		t.Fatalf("fresh claim = %#v", fresh.Run)
	}
}

func TestIntegrationPendingCleanupReclaimPersistsExactTransportDelay(t *testing.T) {
	harness := newQueueHarness(t)
	harness.applyMigrations(t)
	base := seedQueueBase(t, harness.db)
	fixture := seedValidationQueueRun(t, harness.db, base, "pending-reclaim")
	repository := newTestQueue(t, harness.application)
	first, err := repository.Claim(context.Background(), discoveryqueue.ClaimCommand{
		Owner: "queue-pending-worker-a", LeaseDuration: 75 * time.Millisecond,
		ProviderKinds: []string{fixture.providerKind},
	})
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	t.Cleanup(first.Destroy)
	coordinates := discoveryqueue.RunCoordinates{
		Scope: assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID},
		RunID: fixture.runID,
	}
	attempt, err := repository.ReserveCleanupAttempt(
		context.Background(), first.Fence, discoveryqueue.RunCommand{Coordinates: coordinates},
	)
	if err != nil {
		t.Fatalf("ReserveCleanupAttempt() error = %v", err)
	}
	time.Sleep(125 * time.Millisecond)
	reclaimed, err := repository.Reclaim(context.Background(), discoveryqueue.ReclaimCommand{
		Owner: "queue-pending-worker-b", LeaseDuration: 5 * time.Second,
		ProviderKinds: []string{fixture.providerKind},
	})
	if err != nil {
		t.Fatalf("Reclaim() error = %v", err)
	}
	defer reclaimed.Destroy()
	if reclaimed.Mode != discoveryqueue.ClaimModeCleanupOnly || reclaimed.CleanupAttempt == nil ||
		*reclaimed.CleanupAttempt != attempt || reclaimed.PersistedDelay == nil ||
		reclaimed.PersistedDelay.Reason != discoveryqueue.DelayReasonTransportBackoff {
		t.Fatalf("pending reclaim = mode %s attempt %#v delay %#v", reclaimed.Mode, reclaimed.CleanupAttempt, reclaimed.PersistedDelay)
	}
	proof := newQueueCleanupProof(t, coordinates, attempt, assetcatalog.CredentialCleanupRevoked, strings.Repeat("b", 64))
	if _, err := repository.RecordCleanup(context.Background(), reclaimed.Fence, proof); err != nil {
		t.Fatalf("RecordCleanup(reclaimed) error = %v", err)
	}
	if _, err := repository.Delay(context.Background(), reclaimed.Fence, discoveryqueue.DelayCommand{
		Coordinates: coordinates,
		Intent: discoveryqueue.DelayIntent{
			Reason: reclaimed.PersistedDelay.Reason, NotBefore: reclaimed.PersistedDelay.NotBefore,
		},
	}); err != nil {
		t.Fatalf("Delay(reclaimed) error = %v", err)
	}
}

func TestIntegrationReclaimFinalizingConsumesFailureIntentBeforeAndAfterCleanup(t *testing.T) {
	for _, afterCleanup := range []bool{false, true} {
		name := "before-cleanup"
		if afterCleanup {
			name = "after-cleanup-receipt"
		}
		t.Run(name, func(t *testing.T) {
			harness := newQueueHarness(t)
			harness.applyMigrations(t)
			base := seedQueueBase(t, harness.db)
			fixture := seedValidationQueueRun(t, harness.db, base, "finalizing-"+name)
			repository := newTestQueue(t, harness.application)
			claim, err := repository.Claim(context.Background(), discoveryqueue.ClaimCommand{
				Owner: "queue-finalizing-worker-a", LeaseDuration: 300 * time.Millisecond,
				ProviderKinds: []string{fixture.providerKind},
			})
			if err != nil {
				t.Fatalf("Claim() error = %v", err)
			}
			t.Cleanup(claim.Destroy)
			coordinates := discoveryqueue.RunCoordinates{
				Scope: assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID},
				RunID: fixture.runID,
			}
			attempt, err := repository.ReserveCleanupAttempt(
				context.Background(), claim.Fence, discoveryqueue.RunCommand{Coordinates: coordinates},
			)
			if err != nil {
				t.Fatalf("ReserveCleanupAttempt() error = %v", err)
			}
			work, err := repository.PrepareFailureIntent(context.Background(), claim.Fence,
				discoveryqueue.FailureIntentCommand{
					Coordinates: coordinates, FailureCode: "PROVIDER_FAILED",
					EvidenceDigest: strings.Repeat("1", 64),
				})
			if err != nil {
				t.Fatalf("PrepareFailureIntent() error = %v", err)
			}
			cleanupDigest := strings.Repeat("2", 64)
			proof := newQueueCleanupProof(
				t, coordinates, attempt, assetcatalog.CredentialCleanupRevoked, cleanupDigest,
			)
			if afterCleanup {
				if _, err := repository.RecordCleanup(context.Background(), claim.Fence, proof); err != nil {
					t.Fatalf("RecordCleanup(before crash) error = %v", err)
				}
			}
			time.Sleep(350 * time.Millisecond)
			reclaimed, err := repository.ReclaimFinalizing(context.Background(), discoveryqueue.ReclaimCommand{
				Owner: "queue-finalizing-worker-b", LeaseDuration: 5 * time.Second,
				ProviderKinds: []string{fixture.providerKind},
			})
			if err != nil {
				t.Fatalf("ReclaimFinalizing() error = %v", err)
			}
			t.Cleanup(reclaimed.Destroy)
			expectedMode := discoveryqueue.ClaimModeCleanupOnly
			if afterCleanup {
				expectedMode = discoveryqueue.ClaimModeTerminal
			}
			if reclaimed.Run.FenceEpoch != claim.Run.FenceEpoch+1 || reclaimed.Mode != expectedMode ||
				reclaimed.Run.WorkResultDigest != work.DigestSHA256 ||
				reclaimed.Run.WorkResultKind != assetcatalog.WorkResultFailureIntent {
				t.Fatalf("reclaimed finalizing = %#v mode=%s", reclaimed.Run, reclaimed.Mode)
			}
			if _, err := repository.Heartbeat(context.Background(), claim.Fence, discoveryqueue.HeartbeatCommand{
				Coordinates: coordinates, Sequence: claim.Run.HeartbeatSequence + 1, Extension: time.Second,
			}); !errors.Is(err, discoveryqueue.ErrStaleFence) {
				t.Fatalf("old Heartbeat() error = %v, want ErrStaleFence", err)
			}
			if !afterCleanup {
				if _, err := repository.RecordCleanup(context.Background(), reclaimed.Fence, proof); err != nil {
					t.Fatalf("RecordCleanup(after reclaim) error = %v", err)
				}
			}
			if _, err := repository.Fail(context.Background(), reclaimed.Fence, discoveryqueue.TerminalCommand{
				Coordinates: coordinates, DesiredStatus: assetcatalog.RunStatusFailed,
				WorkResultDigest: work.DigestSHA256,
				CleanupStatus:    assetcatalog.CredentialCleanupRevoked, CleanupDigest: cleanupDigest,
				FailureCode: "PROVIDER_FAILED",
			}); err != nil {
				t.Fatalf("Fail(reclaimed finalizing) error = %v", err)
			}
			var status string
			var receipts int64
			if err := harness.db.QueryRow(context.Background(), `
SELECT status,(SELECT count(*) FROM audit_records AS audit
               WHERE audit.workspace_id=run.workspace_id
                 AND audit.request_id='source-terminal:'||run.id::text)
FROM asset_source_runs AS run WHERE id=$1
`, fixture.runID).Scan(&status, &receipts); err != nil {
				t.Fatalf("read reclaimed failure closure: %v", err)
			}
			if status != "FAILED" || receipts != 1 {
				t.Fatalf("reclaimed failure status=%s receipts=%d", status, receipts)
			}
		})
	}
}

func TestIntegrationValidationTerminalReceiptReplaysAfterFenceDestroy(t *testing.T) {
	harness := newQueueHarness(t)
	harness.applyMigrations(t)
	base := seedQueueBase(t, harness.db)
	fixture := seedValidationQueueRun(t, harness.db, base, "validation-terminal")
	repository := newTestQueue(t, harness.application)
	claim, err := repository.Claim(context.Background(), discoveryqueue.ClaimCommand{
		Owner: "queue-validation-worker", LeaseDuration: 5 * time.Second,
		ProviderKinds: []string{fixture.providerKind},
	})
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	t.Cleanup(claim.Destroy)
	coordinates := discoveryqueue.RunCoordinates{
		Scope: assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID},
		RunID: fixture.runID,
	}
	attempt, err := repository.ReserveCleanupAttempt(
		context.Background(), claim.Fence, discoveryqueue.RunCommand{Coordinates: coordinates},
	)
	if err != nil {
		t.Fatalf("ReserveCleanupAttempt() error = %v", err)
	}
	work, err := repository.ProposeValidationResult(context.Background(), claim.Fence, discoveryqueue.ValidationResultCommand{
		Coordinates: coordinates, Proof: queueValidationSuccessProof(),
	})
	if err != nil {
		t.Fatalf("ProposeValidationResult() error = %v", err)
	}
	cleanupDigest := strings.Repeat("c", 64)
	proof := newQueueCleanupProof(t, coordinates, attempt, assetcatalog.CredentialCleanupRevoked, cleanupDigest)
	if _, err := repository.RecordCleanup(context.Background(), claim.Fence, proof); err != nil {
		t.Fatalf("RecordCleanup() error = %v", err)
	}
	command := discoveryqueue.TerminalCommand{
		Coordinates: coordinates, DesiredStatus: assetcatalog.RunStatusSucceeded,
		WorkResultDigest: work.DigestSHA256,
		CleanupStatus:    assetcatalog.CredentialCleanupRevoked, CleanupDigest: cleanupDigest,
	}
	completed, err := repository.Complete(context.Background(), claim.Fence, command)
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	replay, err := repository.Complete(context.Background(), claim.Fence, command)
	if err != nil || !replay.Replayed || replay.CommandDigest != completed.CommandDigest ||
		!replay.CompletedAt.Equal(completed.CompletedAt) {
		t.Fatalf("terminal replay = %#v,%v, first=%#v", replay, err, completed)
	}
	changed := command
	changed.WorkResultDigest = strings.Repeat("d", 64)
	if _, err := repository.Complete(context.Background(), claim.Fence, changed); !errors.Is(err, discoveryqueue.ErrIdempotency) {
		t.Fatalf("changed terminal replay error = %v, want ErrIdempotency", err)
	}
	var runStatus, revisionStatus string
	var receipts int
	if err := harness.db.QueryRow(context.Background(), `
SELECT run.status,revision.state,
       (SELECT count(*) FROM audit_records AS audit
        WHERE audit.workspace_id=run.workspace_id
          AND audit.request_id='source-terminal:'||run.id::text)
FROM asset_source_runs AS run
JOIN asset_source_revisions AS revision
  ON revision.source_id=run.source_id AND revision.revision=run.source_revision
WHERE run.id=$1
`, fixture.runID).Scan(&runStatus, &revisionStatus, &receipts); err != nil {
		t.Fatalf("read validation terminal closure: %v", err)
	}
	if runStatus != "SUCCEEDED" || revisionStatus != "VALIDATED" || receipts != 1 {
		t.Fatalf("validation terminal=%s revision=%s receipts=%d", runStatus, revisionStatus, receipts)
	}
}

func TestIntegrationCleanupUncertainPreservesValidationResultAndSuspendsSource(t *testing.T) {
	harness := newQueueHarness(t)
	harness.applyMigrations(t)
	base := seedQueueBase(t, harness.db)
	fixture := seedValidationQueueRun(t, harness.db, base, "cleanup-uncertain")
	repository := newTestQueue(t, harness.application)
	claim, err := repository.Claim(context.Background(), discoveryqueue.ClaimCommand{
		Owner: "queue-uncertain-worker", LeaseDuration: 5 * time.Second,
		ProviderKinds: []string{fixture.providerKind},
	})
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	t.Cleanup(claim.Destroy)
	coordinates := discoveryqueue.RunCoordinates{
		Scope: assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID},
		RunID: fixture.runID,
	}
	attempt, err := repository.ReserveCleanupAttempt(
		context.Background(), claim.Fence, discoveryqueue.RunCommand{Coordinates: coordinates},
	)
	if err != nil {
		t.Fatalf("ReserveCleanupAttempt() error = %v", err)
	}
	work, err := repository.ProposeValidationResult(context.Background(), claim.Fence,
		discoveryqueue.ValidationResultCommand{Coordinates: coordinates, Proof: queueValidationSuccessProof()})
	if err != nil {
		t.Fatalf("ProposeValidationResult() error = %v", err)
	}
	cleanupDigest := strings.Repeat("6", 64)
	proof := newQueueCleanupProof(
		t, coordinates, attempt, assetcatalog.CredentialCleanupUncertain, cleanupDigest,
	)
	cleaned, err := repository.RecordCleanup(context.Background(), claim.Fence, proof)
	if err != nil {
		t.Fatalf("RecordCleanup(UNCERTAIN) error = %v", err)
	}
	if cleaned.Replayed || cleaned.Status != assetcatalog.CredentialCleanupUncertain {
		t.Fatalf("uncertain cleanup result = %#v", cleaned)
	}
	cleanedReplay, err := repository.RecordCleanup(context.Background(), claim.Fence, proof)
	if err != nil || !cleanedReplay.Replayed {
		t.Fatalf("uncertain cleanup replay = %#v,%v", cleanedReplay, err)
	}
	terminalCommand := discoveryqueue.TerminalCommand{
		Coordinates: coordinates, DesiredStatus: assetcatalog.RunStatusFailed,
		WorkResultDigest: work.DigestSHA256,
		CleanupStatus:    assetcatalog.CredentialCleanupUncertain, CleanupDigest: cleanupDigest,
		FailureCode: "CLEANUP_UNCERTAIN",
	}
	terminalReplay, err := repository.Fail(context.Background(), claim.Fence, terminalCommand)
	if err != nil || !terminalReplay.Replayed {
		t.Fatalf("Fail(UNCERTAIN replay) = %#v,%v", terminalReplay, err)
	}

	var (
		runStatus, cleanupStatus, persistedWork, override, failureCode string
		sourceGate, sourceReason, revisionStatus, rejectionDigest      string
		cleanupReceipts, terminalReceipts                              int64
	)
	if err := harness.db.QueryRow(context.Background(), `
SELECT run.status,run.cleanup_status,run.work_result_digest,
       run.terminal_failure_override,run.failure_code,
       source.gate_status,source.gate_reason_code,
       revision.state,revision.validation_digest,
       (SELECT count(*) FROM audit_records AS audit
        WHERE audit.workspace_id=run.workspace_id
          AND audit.request_id='source-attempt:'||run.id::text||':'||run.cleanup_attempt_epoch::text),
       (SELECT count(*) FROM audit_records AS audit
        WHERE audit.workspace_id=run.workspace_id
          AND audit.request_id='source-terminal:'||run.id::text)
FROM asset_source_runs AS run
JOIN asset_sources AS source ON source.id=run.source_id
JOIN asset_source_revisions AS revision
  ON revision.source_id=run.source_id AND revision.revision=run.source_revision
WHERE run.id=$1
`, fixture.runID).Scan(&runStatus, &cleanupStatus, &persistedWork, &override, &failureCode,
		&sourceGate, &sourceReason, &revisionStatus, &rejectionDigest,
		&cleanupReceipts, &terminalReceipts); err != nil {
		t.Fatalf("read uncertain cleanup closure: %v", err)
	}
	if runStatus != "FAILED" || cleanupStatus != "UNCERTAIN" || persistedWork != work.DigestSHA256 ||
		override != "CLEANUP_UNCERTAIN" || failureCode != "CLEANUP_UNCERTAIN" ||
		sourceGate != "SUSPENDED" || sourceReason != "CLEANUP_UNCERTAIN" ||
		revisionStatus != "REJECTED" || rejectionDigest == work.DigestSHA256 ||
		cleanupReceipts != 1 || terminalReceipts != 1 {
		t.Fatalf("uncertain closure run=%s cleanup=%s work=%s override=%s failure=%s source=%s/%s revision=%s/%s receipts=%d/%d",
			runStatus, cleanupStatus, persistedWork, override, failureCode,
			sourceGate, sourceReason, revisionStatus, rejectionDigest,
			cleanupReceipts, terminalReceipts)
	}
	row := readQueueRunRow(t, harness.application, coordinates)
	goOverrideDigest, err := failureOverrideDigest(row, "CLEANUP_UNCERTAIN")
	if err != nil {
		t.Fatalf("failureOverrideDigest() error = %v", err)
	}
	goTerminalDigest, err := terminalCommandDigest(row, assetcatalog.RunStatusFailed, "CLEANUP_UNCERTAIN")
	if err != nil {
		t.Fatalf("terminalCommandDigest() error = %v", err)
	}
	var sqlOverrideDigest, sqlTerminalDigest string
	if err := harness.application.QueryRow(context.Background(), `
SELECT asset_catalog_source_run_failure_override_digest(run,run.failure_code),
       asset_catalog_source_run_terminal_digest(run,run.status,run.failure_code)
FROM asset_source_runs AS run WHERE id=$1
`, fixture.runID).Scan(&sqlOverrideDigest, &sqlTerminalDigest); err != nil {
		t.Fatalf("SQL terminal digest parity: %v", err)
	}
	if row.terminalOverrideDigest == nil || *row.terminalOverrideDigest != goOverrideDigest ||
		goOverrideDigest != sqlOverrideDigest || row.terminalDigest == nil ||
		*row.terminalDigest != goTerminalDigest || goTerminalDigest != sqlTerminalDigest {
		t.Fatalf("digest parity override persisted=%v Go=%s SQL=%s terminal persisted=%v Go=%s SQL=%s",
			row.terminalOverrideDigest, goOverrideDigest, sqlOverrideDigest,
			row.terminalDigest, goTerminalDigest, sqlTerminalDigest)
	}
}

func TestIntegrationCheckpointLineageRolloverBindsExactRunAndLeavesCheckpoint(t *testing.T) {
	harness := newQueueHarness(t)
	harness.applyMigrations(t)
	base := seedQueueBase(t, harness.db)
	fixture := seedValidationQueueRun(t, harness.db, base, "rollover")
	verifier := &capturingRolloverVerifier{}
	repository, err := New(harness.application, acceptingCleanupVerifier{}, verifier)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	publishQueueFixture(t, harness, repository, fixture)
	fixture.runID = seedQueueDataRun(t, harness.db, fixture, "rollover-data")

	claim, err := repository.Claim(context.Background(), discoveryqueue.ClaimCommand{
		Owner: "queue-rollover-worker", LeaseDuration: 5 * time.Second,
		ProviderKinds: []string{fixture.providerKind},
	})
	if err != nil {
		t.Fatalf("Claim(data) error = %v", err)
	}
	t.Cleanup(claim.Destroy)
	coordinates := discoveryqueue.RunCoordinates{
		Scope: assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID},
		RunID: fixture.runID,
	}
	attempt, err := repository.ReserveCleanupAttempt(
		context.Background(), claim.Fence, discoveryqueue.RunCommand{Coordinates: coordinates},
	)
	if err != nil {
		t.Fatalf("ReserveCleanupAttempt(data) error = %v", err)
	}
	var checkpointBefore *string
	var checkpointVersionBefore int64
	var checkpointCiphertextBefore []byte
	if err := harness.db.QueryRow(context.Background(), `
SELECT checkpoint_sha256,checkpoint_version,checkpoint_ciphertext
FROM asset_sources WHERE id=$1
`, fixture.sourceID).Scan(&checkpointBefore, &checkpointVersionBefore, &checkpointCiphertextBefore); err != nil {
		t.Fatalf("read checkpoint before rollover: %v", err)
	}
	command := discoveryqueue.RolloverCommand{
		Coordinates: coordinates, ReasonCode: "PROVIDER_CURSOR_EXPIRED",
		EvidenceDigest: strings.Repeat("9", 64),
	}
	bound, err := repository.BeginCheckpointLineageRollover(context.Background(), claim.Fence, command)
	if err != nil {
		t.Fatalf("BeginCheckpointLineageRollover() error = %v", err)
	}
	if bound.Replayed || bound.ReasonCode != command.ReasonCode ||
		bound.EvidenceDigest != command.EvidenceDigest || bound.GateRevision != claim.Run.GateRevision+1 {
		t.Fatalf("rollover result = %#v", bound)
	}
	replay, err := repository.BeginCheckpointLineageRollover(context.Background(), claim.Fence, command)
	if err != nil || !replay.Replayed || replay.GateRevision != bound.GateRevision {
		t.Fatalf("rollover replay = %#v,%v, first=%#v", replay, err, bound)
	}
	changed := command
	changed.EvidenceDigest = strings.Repeat("8", 64)
	if _, err := repository.BeginCheckpointLineageRollover(context.Background(), claim.Fence, changed); !errors.Is(err, discoveryqueue.ErrIdempotency) {
		t.Fatalf("changed rollover replay error = %v, want ErrIdempotency", err)
	}

	var gateStatus, gateReason, runReason, runEvidence string
	var gateRevision, checkpointVersionAfter, receipts int64
	var checkpointAfter *string
	var checkpointCiphertextAfter []byte
	if err := harness.db.QueryRow(context.Background(), `
SELECT source.gate_status,source.gate_reason_code,source.gate_revision,
       source.checkpoint_sha256,source.checkpoint_version,source.checkpoint_ciphertext,
       run.lineage_rollover_reason,run.lineage_rollover_evidence_digest,
       (SELECT count(*) FROM audit_records AS audit
        WHERE audit.workspace_id=run.workspace_id
          AND audit.request_id='source-rollover:'||run.id::text)
FROM asset_sources AS source
JOIN asset_source_runs AS run ON run.source_id=source.id
WHERE run.id=$1
`, fixture.runID).Scan(&gateStatus, &gateReason, &gateRevision, &checkpointAfter,
		&checkpointVersionAfter, &checkpointCiphertextAfter, &runReason, &runEvidence, &receipts); err != nil {
		t.Fatalf("read rollover binding: %v", err)
	}
	if gateStatus != "DEGRADED" || gateReason != "CHECKPOINT_LINEAGE_ROLLOVER" ||
		gateRevision != bound.GateRevision || runReason != command.ReasonCode ||
		runEvidence != command.EvidenceDigest || receipts != 1 ||
		checkpointVersionAfter != checkpointVersionBefore ||
		!nullableStringEqual(checkpointAfter, checkpointBefore) ||
		!strings.EqualFold(hex.EncodeToString(checkpointCiphertextAfter), hex.EncodeToString(checkpointCiphertextBefore)) {
		t.Fatalf("rollover closure gate=%s/%s/%d run=%s/%s receipts=%d checkpoint=%v/%d",
			gateStatus, gateReason, gateRevision, runReason, runEvidence, receipts,
			checkpointAfter, checkpointVersionAfter)
	}
	if verifier.calls != 1 || verifier.request.Coordinates != coordinates ||
		verifier.request.SourceID != fixture.sourceID || verifier.request.ProviderKind != fixture.providerKind ||
		verifier.request.SourceRevision != 1 || verifier.request.SourceRevisionDigest != fixture.revisionDigest ||
		verifier.request.SourceDefinitionDigest != fixture.sourceDefinitionDigest ||
		verifier.request.ProfileCode != assetcatalog.ProfileCode(fixture.providerKind) ||
		verifier.request.CheckpointVersion != checkpointVersionBefore ||
		verifier.request.CheckpointSHA256 != stringValue(checkpointBefore) ||
		verifier.request.ReasonCode != command.ReasonCode ||
		verifier.request.EvidenceDigest != command.EvidenceDigest {
		t.Fatalf("rollover verifier calls=%d request=%#v", verifier.calls, verifier.request)
	}

	intent := discoveryqueue.DelayIntent{
		Reason:    discoveryqueue.DelayReasonTransportBackoff,
		NotBefore: time.Now().UTC().Add(500 * time.Millisecond).Truncate(time.Microsecond),
	}
	if _, err := repository.AdvanceStage(context.Background(), claim.Fence, discoveryqueue.AdvanceStageCommand{
		Coordinates: coordinates, From: assetcatalog.RunStageReading,
		To: assetcatalog.RunStageCleaningUp, Delay: &intent,
	}); err != nil {
		t.Fatalf("AdvanceStage(rollover recovery) error = %v", err)
	}
	proof := newQueueCleanupProof(
		t, coordinates, attempt, assetcatalog.CredentialCleanupRevoked, strings.Repeat("7", 64),
	)
	if _, err := repository.RecordCleanup(context.Background(), claim.Fence, proof); err != nil {
		t.Fatalf("RecordCleanup(rollover recovery) error = %v", err)
	}
	if _, err := repository.Delay(context.Background(), claim.Fence, discoveryqueue.DelayCommand{
		Coordinates: coordinates, Intent: intent,
	}); err != nil {
		t.Fatalf("Delay(rollover recovery) error = %v", err)
	}
	time.Sleep(time.Until(intent.NotBefore) + 25*time.Millisecond)
	fresh, err := repository.Claim(context.Background(), discoveryqueue.ClaimCommand{
		Owner: "queue-rollover-worker-next", LeaseDuration: 5 * time.Second,
		ProviderKinds: []string{fixture.providerKind},
	})
	if err != nil {
		t.Fatalf("Claim(rollover recovery) error = %v", err)
	}
	t.Cleanup(fresh.Destroy)
	if fresh.Run.ID != fixture.runID || fresh.Run.FenceEpoch != claim.Run.FenceEpoch+1 {
		t.Fatalf("fresh rollover claim = %#v", fresh.Run)
	}
	recoveredReplay, err := repository.BeginCheckpointLineageRollover(
		context.Background(), fresh.Fence, command,
	)
	if err != nil || !recoveredReplay.Replayed || recoveredReplay.GateRevision != bound.GateRevision {
		t.Fatalf("rollover recovery replay = %#v,%v, first=%#v", recoveredReplay, err, bound)
	}
	if verifier.calls != 1 {
		t.Fatalf("rollover recovery called verifier %d times, want 1", verifier.calls)
	}
}

func TestIntegrationCheckpointLineageRolloverFailureSuspendsExactGate(t *testing.T) {
	harness := newQueueHarness(t)
	harness.applyMigrations(t)
	base := seedQueueBase(t, harness.db)
	fixture := seedValidationQueueRun(t, harness.db, base, "rollover-failure")
	repository := newTestQueue(t, harness.application)
	publishQueueFixture(t, harness, repository, fixture)
	fixture.runID = seedQueueDataRun(t, harness.db, fixture, "rollover-failure")
	claim, err := repository.Claim(context.Background(), discoveryqueue.ClaimCommand{
		Owner: "queue-rollover-failure-worker", LeaseDuration: 5 * time.Second,
		ProviderKinds: []string{fixture.providerKind},
	})
	if err != nil {
		t.Fatalf("Claim(data) error = %v", err)
	}
	t.Cleanup(claim.Destroy)
	coordinates := discoveryqueue.RunCoordinates{
		Scope: assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID},
		RunID: fixture.runID,
	}
	attempt, err := repository.ReserveCleanupAttempt(
		context.Background(), claim.Fence, discoveryqueue.RunCommand{Coordinates: coordinates},
	)
	if err != nil {
		t.Fatalf("ReserveCleanupAttempt(data) error = %v", err)
	}
	rollover := discoveryqueue.RolloverCommand{
		Coordinates: coordinates, ReasonCode: "PROVIDER_CURSOR_EXPIRED",
		EvidenceDigest: strings.Repeat("3", 64),
	}
	bound, err := repository.BeginCheckpointLineageRollover(context.Background(), claim.Fence, rollover)
	if err != nil {
		t.Fatalf("BeginCheckpointLineageRollover() error = %v", err)
	}
	work, err := repository.PrepareFailureIntent(context.Background(), claim.Fence,
		discoveryqueue.FailureIntentCommand{
			Coordinates: coordinates, FailureCode: "PROVIDER_FAILED",
			EvidenceDigest: strings.Repeat("4", 64),
		})
	if err != nil {
		t.Fatalf("PrepareFailureIntent(rollover) error = %v", err)
	}
	cleanupDigest := strings.Repeat("5", 64)
	proof := newQueueCleanupProof(
		t, coordinates, attempt, assetcatalog.CredentialCleanupRevoked, cleanupDigest,
	)
	if _, err := repository.RecordCleanup(context.Background(), claim.Fence, proof); err != nil {
		t.Fatalf("RecordCleanup(rollover) error = %v", err)
	}
	if _, err := repository.Fail(context.Background(), claim.Fence, discoveryqueue.TerminalCommand{
		Coordinates: coordinates, DesiredStatus: assetcatalog.RunStatusFailed,
		WorkResultDigest: work.DigestSHA256,
		CleanupStatus:    assetcatalog.CredentialCleanupRevoked, CleanupDigest: cleanupDigest,
		FailureCode: "PROVIDER_FAILED",
	}); err != nil {
		t.Fatalf("Fail(rollover) error = %v", err)
	}
	replay, err := repository.BeginCheckpointLineageRollover(context.Background(), claim.Fence, rollover)
	if err != nil || !replay.Replayed || replay.GateRevision != bound.GateRevision {
		t.Fatalf("terminal rollover replay = %#v,%v, first=%#v", replay, err, bound)
	}
	var runStatus, gateStatus, gateReason string
	var gateRevision, lastSuccessFacts int64
	if err := harness.db.QueryRow(context.Background(), `
SELECT run.status,source.gate_status,source.gate_reason_code,source.gate_revision,
       num_nonnulls(source.last_success_run_id,source.last_success_at,
                    source.last_complete_snapshot_run_id,source.last_complete_snapshot_at)
FROM asset_source_runs AS run
JOIN asset_sources AS source ON source.id=run.source_id
WHERE run.id=$1
`, fixture.runID).Scan(&runStatus, &gateStatus, &gateReason, &gateRevision, &lastSuccessFacts); err != nil {
		t.Fatalf("read rollover failure closure: %v", err)
	}
	if runStatus != "FAILED" || gateStatus != "SUSPENDED" || gateReason != "PROVIDER_FAILED" ||
		gateRevision != claim.Run.GateRevision+2 || lastSuccessFacts != 0 {
		t.Fatalf("rollover failure run=%s gate=%s/%s/%d success-facts=%d",
			runStatus, gateStatus, gateReason, gateRevision, lastSuccessFacts)
	}
}

func TestIntegrationAdvanceStageFollowsClosedDataCycle(t *testing.T) {
	harness := newQueueHarness(t)
	harness.applyMigrations(t)
	base := seedQueueBase(t, harness.db)
	fixture := seedValidationQueueRun(t, harness.db, base, "stage-cycle")
	repository := newTestQueue(t, harness.application)
	publishQueueFixture(t, harness, repository, fixture)
	fixture.runID = seedQueueDataRun(t, harness.db, fixture, "stage-cycle")
	claim, err := repository.Claim(context.Background(), discoveryqueue.ClaimCommand{
		Owner: "queue-stage-worker", LeaseDuration: 5 * time.Second,
		ProviderKinds: []string{fixture.providerKind},
	})
	if err != nil {
		t.Fatalf("Claim(data) error = %v", err)
	}
	t.Cleanup(claim.Destroy)
	coordinates := discoveryqueue.RunCoordinates{
		Scope: assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID},
		RunID: fixture.runID,
	}
	transitions := [][2]assetcatalog.RunStage{
		{assetcatalog.RunStageReading, assetcatalog.RunStageNormalizing},
		{assetcatalog.RunStageNormalizing, assetcatalog.RunStageApplying},
		{assetcatalog.RunStageApplying, assetcatalog.RunStageReading},
	}
	for _, transition := range transitions {
		run, err := repository.AdvanceStage(context.Background(), claim.Fence, discoveryqueue.AdvanceStageCommand{
			Coordinates: coordinates, From: transition[0], To: transition[1],
		})
		if err != nil {
			t.Fatalf("AdvanceStage(%s->%s) error = %v", transition[0], transition[1], err)
		}
		if run.Stage != transition[1] {
			t.Fatalf("AdvanceStage(%s->%s) stage = %s", transition[0], transition[1], run.Stage)
		}
	}
}

func TestIntegrationProofVerifiersRejectWithoutPersistentMutation(t *testing.T) {
	t.Run("cleanup proof", func(t *testing.T) {
		harness := newQueueHarness(t)
		harness.applyMigrations(t)
		base := seedQueueBase(t, harness.db)
		fixture := seedValidationQueueRun(t, harness.db, base, "reject-cleanup-proof")
		repository, err := New(
			harness.application, rejectingCleanupVerifier{}, acceptingRolloverVerifier{},
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		claim, err := repository.Claim(context.Background(), discoveryqueue.ClaimCommand{
			Owner: "queue-reject-cleanup-worker", LeaseDuration: 5 * time.Second,
			ProviderKinds: []string{fixture.providerKind},
		})
		if err != nil {
			t.Fatalf("Claim() error = %v", err)
		}
		t.Cleanup(claim.Destroy)
		coordinates := discoveryqueue.RunCoordinates{
			Scope: assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID},
			RunID: fixture.runID,
		}
		attempt, err := repository.ReserveCleanupAttempt(
			context.Background(), claim.Fence, discoveryqueue.RunCommand{Coordinates: coordinates},
		)
		if err != nil {
			t.Fatalf("ReserveCleanupAttempt() error = %v", err)
		}
		intent := discoveryqueue.DelayIntent{
			Reason:    discoveryqueue.DelayReasonTransportBackoff,
			NotBefore: time.Now().UTC().Add(time.Second).Truncate(time.Microsecond),
		}
		if _, err := repository.AdvanceStage(context.Background(), claim.Fence,
			discoveryqueue.AdvanceStageCommand{
				Coordinates: coordinates, From: assetcatalog.RunStageValidating,
				To: assetcatalog.RunStageCleaningUp, Delay: &intent,
			}); err != nil {
			t.Fatalf("AdvanceStage(cleanup) error = %v", err)
		}
		proof := newQueueCleanupProof(
			t, coordinates, attempt, assetcatalog.CredentialCleanupRevoked, strings.Repeat("5", 64),
		)
		if _, err := repository.RecordCleanup(context.Background(), claim.Fence, proof); !errors.Is(err, discoveryqueue.ErrCleanupProof) {
			t.Fatalf("RecordCleanup(rejected proof) error = %v, want ErrCleanupProof", err)
		}
		var status string
		var receipts int64
		if err := harness.db.QueryRow(context.Background(), `
SELECT cleanup_status,(SELECT count(*) FROM audit_records AS audit
                       WHERE audit.workspace_id=run.workspace_id
                         AND audit.request_id='source-attempt:'||run.id::text||':'||run.cleanup_attempt_epoch::text)
FROM asset_source_runs AS run WHERE id=$1
`, fixture.runID).Scan(&status, &receipts); err != nil {
			t.Fatalf("read rejected cleanup proof state: %v", err)
		}
		if status != "PENDING" || receipts != 0 {
			t.Fatalf("rejected cleanup proof status=%s receipts=%d", status, receipts)
		}
	})

	t.Run("rollover evidence", func(t *testing.T) {
		harness := newQueueHarness(t)
		harness.applyMigrations(t)
		base := seedQueueBase(t, harness.db)
		fixture := seedValidationQueueRun(t, harness.db, base, "reject-rollover-proof")
		repository, err := New(
			harness.application, acceptingCleanupVerifier{}, rejectingRolloverVerifier{},
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		publishQueueFixture(t, harness, repository, fixture)
		fixture.runID = seedQueueDataRun(t, harness.db, fixture, "reject-rollover-proof")
		claim, err := repository.Claim(context.Background(), discoveryqueue.ClaimCommand{
			Owner: "queue-reject-rollover-worker", LeaseDuration: 5 * time.Second,
			ProviderKinds: []string{fixture.providerKind},
		})
		if err != nil {
			t.Fatalf("Claim(data) error = %v", err)
		}
		t.Cleanup(claim.Destroy)
		coordinates := discoveryqueue.RunCoordinates{
			Scope: assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID},
			RunID: fixture.runID,
		}
		if _, err := repository.ReserveCleanupAttempt(
			context.Background(), claim.Fence, discoveryqueue.RunCommand{Coordinates: coordinates},
		); err != nil {
			t.Fatalf("ReserveCleanupAttempt(data) error = %v", err)
		}
		if _, err := repository.BeginCheckpointLineageRollover(context.Background(), claim.Fence,
			discoveryqueue.RolloverCommand{
				Coordinates: coordinates, ReasonCode: "PROVIDER_CURSOR_EXPIRED",
				EvidenceDigest: strings.Repeat("4", 64),
			}); !errors.Is(err, discoveryqueue.ErrIneligible) {
			t.Fatalf("BeginCheckpointLineageRollover(rejected) error = %v, want ErrIneligible", err)
		}
		var gate string
		var lineage *string
		var receipts int64
		if err := harness.db.QueryRow(context.Background(), `
SELECT source.gate_status,run.lineage_rollover_reason,
       (SELECT count(*) FROM audit_records AS audit
        WHERE audit.workspace_id=run.workspace_id
          AND audit.request_id='source-rollover:'||run.id::text)
FROM asset_source_runs AS run
JOIN asset_sources AS source ON source.id=run.source_id
WHERE run.id=$1
`, fixture.runID).Scan(&gate, &lineage, &receipts); err != nil {
			t.Fatalf("read rejected rollover proof state: %v", err)
		}
		if gate != "AVAILABLE" || lineage != nil || receipts != 0 {
			t.Fatalf("rejected rollover gate=%s lineage=%v receipts=%d", gate, lineage, receipts)
		}
	})
}

func queueValidationSuccessProof() discoverysource.ValidationProof {
	kinds := []discoverysource.ValidationCheckKind{
		discoverysource.ValidationCheckIdentity,
		discoverysource.ValidationCheckTrustOrSignature,
		discoverysource.ValidationCheckNetwork,
		discoverysource.ValidationCheckCredentialOpen,
		discoverysource.ValidationCheckFixedProbe,
		discoverysource.ValidationCheckSchema,
		discoverysource.ValidationCheckDLP,
		discoverysource.ValidationCheckBudget,
	}
	codes := []string{
		"IDENTITY_VERIFIED", "TRUST_OR_SIGNATURE_VERIFIED", "NETWORK_VERIFIED",
		"CREDENTIAL_OPEN_VERIFIED", "FIXED_PROBE_VERIFIED", "SCHEMA_VERIFIED",
		"DLP_VERIFIED", "BUDGET_VERIFIED",
	}
	checks := make([]discoverysource.ValidationCheck, len(kinds))
	for index := range kinds {
		checks[index] = discoverysource.ValidationCheck{
			Kind: kinds[index], Code: codes[index], Passed: true, Count: int64(index + 1),
		}
	}
	checks[0].DigestSHA256 = strings.Repeat("e", 64)
	return discoverysource.ValidationProof{
		Outcome: assetcatalog.ValidationOutcomeSucceeded, Code: "VALIDATION_SUCCEEDED", Checks: checks,
	}
}

func newQueueCleanupProof(
	t *testing.T,
	coordinates discoveryqueue.RunCoordinates,
	attempt discoveryqueue.CleanupAttempt,
	status assetcatalog.CredentialCleanupStatus,
	digest string,
) discoveryqueue.CleanupProof {
	t.Helper()
	proof, err := discoveryqueue.NewCleanupProof(coordinates, attempt, status, digest, bytesOf(0x5a, 32))
	if err != nil {
		t.Fatalf("NewCleanupProof() error = %v", err)
	}
	t.Cleanup(proof.Destroy)
	return proof
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}

type queueHarness struct {
	admin, db, migration, application *pgxpool.Pool
	name                              string
}

var safeQueueControlDatabase = regexp.MustCompile(`^aiops_test(_[a-z0-9]+)*$`)

func newQueueHarness(t *testing.T) *queueHarness {
	t.Helper()
	adminDSN := strings.TrimSpace(os.Getenv("AIOPS_TEST_POSTGRES_DSN"))
	if adminDSN == "" {
		t.Skip("AIOPS_TEST_POSTGRES_DSN is not configured; real PostgreSQL 18.4 TLS tests were not run")
	}
	migrationDSN := strings.TrimSpace(os.Getenv("AIOPS_TEST_POSTGRES_MIGRATION_DSN"))
	applicationDSN := strings.TrimSpace(os.Getenv("AIOPS_TEST_POSTGRES_APPLICATION_DSN"))
	if migrationDSN == "" || applicationDSN == "" {
		t.Fatal("migration and application PostgreSQL identities are required")
	}
	if adminDSN == migrationDSN || adminDSN == applicationDSN || migrationDSN == applicationDSN {
		t.Fatal("PostgreSQL test identities must be distinct")
	}
	ctx := context.Background()
	adminConfig, err := pgxpool.ParseConfig(adminDSN)
	if err != nil || !safeQueueControlDatabase.MatchString(adminConfig.ConnConfig.Database) {
		t.Fatal("test-control PostgreSQL DSN is not a dedicated safe database")
	}
	controlName := adminConfig.ConnConfig.Database
	migrationConfig := queueRoleConfig(t, migrationDSN, controlName, "aiops_migrator")
	applicationConfig := queueRoleConfig(t, applicationDSN, controlName, "aiops_control_plane_workload")
	adminConfig.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	admin, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal("connect PostgreSQL test-control database: unavailable")
	}
	var serverVersion int
	var sslEnabled bool
	if err := admin.QueryRow(ctx, `SELECT current_setting('server_version_num')::integer,current_setting('ssl')='on'`).Scan(
		&serverVersion, &sslEnabled,
	); err != nil || serverVersion < 180004 || serverVersion >= 190000 || !sslEnabled {
		admin.Close()
		t.Fatal("integration harness requires PostgreSQL 18.4+ 18.x with TLS")
	}

	databaseName := "aiops_queue_test_" + randomQueueHex(t, 16)
	identifier := pgx.Identifier{databaseName}.Sanitize()
	harness := &queueHarness{admin: admin, name: databaseName}
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
			if _, err := admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+identifier+" WITH (FORCE)"); err != nil {
				t.Errorf("drop isolated Queue database %s: %v", databaseName, err)
			}
		}
		admin.Close()
	})
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+identifier+" WITH TEMPLATE template0 OWNER aiops_schema_owner"); err != nil {
		t.Fatalf("create isolated Queue database; cleanup ownership unconfirmed: %v", err)
	}
	created = true
	if _, err := admin.Exec(ctx, `SET ROLE aiops_schema_owner;
REVOKE ALL ON DATABASE `+identifier+` FROM PUBLIC;
REVOKE ALL ON DATABASE `+identifier+` FROM aiops_control_plane_runtime;
GRANT CONNECT ON DATABASE `+identifier+` TO aiops_migrator;
GRANT CONNECT ON DATABASE `+identifier+` TO aiops_control_plane_workload;
RESET ROLE;`); err != nil {
		t.Fatalf("preprovision isolated Queue database ACL: %v", err)
	}

	dbConfig, err := pgxpool.ParseConfig(adminDSN)
	if err != nil {
		t.Fatal("parse isolated test-control config")
	}
	dbConfig.ConnConfig.Database = databaseName
	dbConfig.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	if dbConfig.ConnConfig.RuntimeParams == nil {
		dbConfig.ConnConfig.RuntimeParams = make(map[string]string)
	}
	dbConfig.ConnConfig.RuntimeParams["search_path"] = "public"
	dbConfig.MaxConns = max(dbConfig.MaxConns, 12)
	harness.db, err = pgxpool.NewWithConfig(ctx, dbConfig)
	if err != nil {
		t.Fatal("connect isolated Queue test-control database")
	}
	if _, err := harness.db.Exec(ctx, `ALTER SCHEMA public OWNER TO aiops_schema_owner;
SET ROLE aiops_schema_owner;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM aiops_migrator;
REVOKE ALL ON SCHEMA public FROM aiops_control_plane_workload;
GRANT CREATE, USAGE ON SCHEMA public TO aiops_schema_owner;
GRANT USAGE ON SCHEMA public TO aiops_control_plane_runtime;
RESET ROLE;`); err != nil {
		t.Fatalf("preprovision Queue schema ACL: %v", err)
	}
	migrationConfig.ConnConfig.Database = databaseName
	harness.migration, err = pgxpool.NewWithConfig(ctx, migrationConfig)
	if err != nil {
		t.Fatal("connect isolated Queue migration identity")
	}
	applicationConfig.ConnConfig.Database = databaseName
	harness.application, err = pgxpool.NewWithConfig(ctx, applicationConfig)
	if err != nil {
		t.Fatal("connect isolated Queue application identity")
	}
	assertQueueIdentity(t, harness.migration, "aiops_migrator")
	assertQueueIdentity(t, harness.application, "aiops_control_plane_workload")
	return harness
}

func queueRoleConfig(t *testing.T, dsn, controlName, expectedUser string) *pgxpool.Config {
	t.Helper()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil || config.ConnConfig.Database != controlName || config.ConnConfig.User != expectedUser {
		t.Fatalf("invalid %s PostgreSQL test identity", expectedUser)
	}
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = make(map[string]string)
	}
	config.ConnConfig.RuntimeParams["search_path"] = "pg_catalog,public,pg_temp"
	config.MaxConns = max(config.MaxConns, 12)
	return config
}

func assertQueueIdentity(t *testing.T, pool *pgxpool.Pool, expected string) {
	t.Helper()
	var sessionUser, currentUser string
	if err := pool.QueryRow(context.Background(), `SELECT session_user,current_user`).Scan(&sessionUser, &currentUser); err != nil ||
		sessionUser != expected || currentUser != expected {
		t.Fatalf("PostgreSQL identity mismatch for %s", expected)
	}
}

func (harness *queueHarness) applyMigrations(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(queueMigrationDirectory(t))
	if err != nil {
		t.Fatalf("read migration directory: %v", err)
	}
	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".up.sql") && entry.Name() <= "000015_assets_catalog.up.sql" {
			files = append(files, entry.Name())
		}
	}
	sort.Strings(files)
	if len(files) != 15 {
		t.Fatalf("migration set through 000015 has %d files, want 15", len(files))
	}
	for _, name := range files {
		harness.applyMigration(t, name)
	}
}

func (harness *queueHarness) applyMigration(t *testing.T, name string) {
	t.Helper()
	source, err := os.ReadFile(filepath.Join(queueMigrationDirectory(t), name))
	if err != nil {
		t.Fatalf("read migration %s: %v", name, err)
	}
	if name == "000012_outbox_event_routing.up.sql" {
		config := harness.migration.Config().ConnConfig.Copy()
		connection, err := pgx.ConnectConfig(context.Background(), config)
		if err != nil {
			t.Fatalf("connect nontransactional migration %s", name)
		}
		defer func() { _ = connection.Close(context.Background()) }()
		if _, err := connection.Exec(context.Background(), `SET search_path=pg_catalog,public,pg_temp; SET ROLE aiops_schema_owner`); err != nil {
			t.Fatalf("set nontransactional migration role: %v", err)
		}
		if _, err := connection.Exec(context.Background(), string(source)); err != nil {
			failQueueMigration(t, name, err)
		}
		if _, err := connection.Exec(context.Background(), `RESET ROLE`); err != nil {
			t.Fatalf("reset nontransactional migration role: %v", err)
		}
		return
	}
	text := string(source)
	if name != "000015_assets_catalog.up.sql" {
		index := strings.Index(text, "BEGIN;")
		if index < 0 {
			t.Fatalf("migration %s does not start a transaction", name)
		}
		index += len("BEGIN;")
		text = text[:index] + "\nSET LOCAL ROLE aiops_schema_owner;\nSET LOCAL search_path=public,pg_catalog,pg_temp;" + text[index:]
	}
	connection, err := harness.migration.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire migration connection for %s", name)
	}
	defer connection.Release()
	if _, err := connection.Exec(context.Background(), text); err != nil {
		failQueueMigration(t, name, err)
	}
	if _, err := connection.Exec(context.Background(), `RESET ROLE`); err != nil {
		t.Fatalf("reset migration role after %s", name)
	}
}

func failQueueMigration(t *testing.T, name string, err error) {
	t.Helper()
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		t.Fatalf("apply migration %s: %s (SQLSTATE %s, constraint %s)",
			name, databaseError.Message, databaseError.Code, databaseError.ConstraintName)
	}
	t.Fatalf("apply migration %s: %v", name, err)
}

type queueBase struct {
	tenantID, workspaceID, environmentID, integrationID string
}

func seedQueueBase(t *testing.T, database *pgxpool.Pool) queueBase {
	t.Helper()
	base := queueBase{
		tenantID: uuid.NewString(), workspaceID: uuid.NewString(),
		environmentID: uuid.NewString(), integrationID: uuid.NewString(),
	}
	queueExec(t, database, `INSERT INTO tenants(id,name) VALUES($1,'queue-tenant')`, base.tenantID)
	queueExec(t, database, `INSERT INTO workspaces(id,tenant_id,name) VALUES($1,$2,'queue-workspace')`, base.workspaceID, base.tenantID)
	queueExec(t, database, `INSERT INTO environments(id,tenant_id,workspace_id,name,kind) VALUES($1,$2,$3,'queue-environment','PROD')`, base.environmentID, base.tenantID, base.workspaceID)
	queueExec(t, database, `INSERT INTO integrations(id,tenant_id,workspace_id,provider,name,secret_ref,config) VALUES($1,$2,$3,'external','queue-integration','opaque://queue-test','{}')`, base.integrationID, base.tenantID, base.workspaceID)
	return base
}

type queueFixture struct {
	queueBase
	sourceID, revisionID, runID                          string
	providerKind, revisionDigest, sourceDefinitionDigest string
}

const queueExternalProfile = `{"backpressure_base_seconds":1,"backpressure_max_seconds":60,"compatibility_class":"EXTERNAL_V1","credential_purpose":"DISCOVERY_READ","dlp_policy_code":"ASSET_SAFE_V1","environment_mapping_mode":"SINGLE_ENVIRONMENT","freshness_kind":"OBJECT_SEQUENCE","integration_mode":"REQUIRED","max_document_bytes":65536,"max_page_bytes":1048576,"max_page_items":100,"max_page_relations":100,"network_mode":"NONE","parser_code":"EXTERNAL_V1","profile_code":"EXTERNAL_V1","provider_kind":"EXTERNAL_V1","rate_limit_requests":100,"rate_limit_window_seconds":60,"relationship_types":["DEPENDS_ON"],"schedule_mode":"NONE","source_kind":"EXTERNAL_CMDB","sync_mode":"ON_DEMAND","trust_mode":"NONE","trusted_path_codes":["DISPLAY_NAME","EXTERNAL_ID","KIND"],"typed_extension_code":null,"version":"asset-source-profile-manifest.v1"}`

func seedValidationQueueRun(t *testing.T, database *pgxpool.Pool, base queueBase, suffix string) queueFixture {
	t.Helper()
	fixture := queueFixture{
		queueBase: base, sourceID: uuid.NewString(), revisionID: uuid.NewString(), runID: uuid.NewString(),
		providerKind: "EXTERNAL_V1",
	}
	profile := []byte(queueExternalProfile)
	providerSchema := []byte(`{"type":"object"}`)
	profileDigest := sha256.Sum256(profile)
	providerSchemaDigest := sha256.Sum256(providerSchema)
	authorityDigest := queueFramedDigest([]byte("asset-source-authority-scope.v1"), []byte("1"), []byte(base.environmentID))
	fixture.sourceDefinitionDigest = queueFramedDigest(
		[]byte("asset-source-definition.v2"), []byte("EXTERNAL_CMDB"), []byte(fixture.providerKind),
		[]byte(fixture.providerKind), profileDigest[:], providerSchemaDigest[:],
	)
	fixture.revisionDigest = queueFramedDigest(
		[]byte("asset-source-revision-binding.v1"), []byte(base.tenantID), []byte(base.workspaceID),
		[]byte(fixture.sourceID), []byte("1"), queueDecodeDigest(t, fixture.sourceDefinitionDigest),
		[]byte(base.integrationID), []byte("ON_DEMAND"), []byte("opaque-credential"), nil, nil,
		queueDecodeDigest(t, authorityDigest), []byte("100"), []byte("60"), []byte("1"), []byte("60"),
		[]byte(fixture.providerKind), nil, nil, nil,
	)

	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin Queue source definition: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	queueExec(t, tx, `INSERT INTO asset_sources(id,tenant_id,workspace_id,source_kind,provider_kind,name,create_idempotency_key,create_request_hash) VALUES($1,$2,$3,'EXTERNAL_CMDB',$4,$5,$6,repeat('1',64))`,
		fixture.sourceID, base.tenantID, base.workspaceID, fixture.providerKind, "queue-"+suffix, "queue-source-"+suffix)
	queueExec(t, tx, `
INSERT INTO asset_source_revisions(
 id,tenant_id,workspace_id,source_id,revision,canonical_profile_manifest,profile_manifest_sha256,
 canonical_provider_schema,canonical_provider_schema_sha256,integration_id,sync_mode,authority_scope_digest,
 source_definition_digest,canonical_revision_digest,credential_reference_id,rate_limit_requests,
 rate_limit_window_seconds,backpressure_base_seconds,backpressure_max_seconds,profile_code,
 created_by,change_reason_code,expected_source_version
) SELECT $1,$2,$3,$4,1,$5,$6,$7,$8,$9,'ON_DEMAND',$10,$11,$12,'opaque-credential',
         100,60,1,60,$13,'queue-test','INITIAL_CREATE',source.version
  FROM asset_sources AS source WHERE source.id=$4`,
		fixture.revisionID, base.tenantID, base.workspaceID, fixture.sourceID, profile,
		hex.EncodeToString(profileDigest[:]), providerSchema, hex.EncodeToString(providerSchemaDigest[:]),
		base.integrationID, authorityDigest, fixture.sourceDefinitionDigest, fixture.revisionDigest, fixture.providerKind)
	queueExec(t, tx, `INSERT INTO asset_source_revision_authorities(tenant_id,workspace_id,source_id,source_revision,environment_id,canonical_ordinal) VALUES($1,$2,$3,1,$4,1)`,
		base.tenantID, base.workspaceID, fixture.sourceID, base.environmentID)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit Queue source definition: %v", err)
	}

	tx, err = database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin Queue validation admission: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	queueExec(t, tx, `INSERT INTO asset_source_runs(id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,run_kind,trigger_type,gate_revision,idempotency_key,request_hash,checkpoint_version) SELECT $1,$2,$3,$4,1,$5,'VALIDATION','HUMAN',gate_revision,$6,repeat('2',64),0 FROM asset_sources WHERE id=$4`,
		fixture.runID, base.tenantID, base.workspaceID, fixture.sourceID, fixture.revisionDigest, "queue-run-"+suffix)
	queueExec(t, tx, `UPDATE asset_source_revisions SET state='VALIDATING',validation_run_id=$2,version=version+1 WHERE id=$1`, fixture.revisionID, fixture.runID)
	queueExec(t, tx, `UPDATE asset_sources SET gate_status='VALIDATING',gate_revision=gate_revision+1,validated_run_id=$2,validation_digest=NULL,validated_binding_digest=NULL,version=version+1 WHERE id=$1`, fixture.sourceID, fixture.runID)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit Queue validation admission: %v", err)
	}
	return fixture
}

func publishQueueFixture(
	t *testing.T,
	harness *queueHarness,
	repository *Repository,
	fixture queueFixture,
) {
	t.Helper()
	claim, err := repository.Claim(context.Background(), discoveryqueue.ClaimCommand{
		Owner: "queue-publish-validation-worker", LeaseDuration: 5 * time.Second,
		ProviderKinds: []string{fixture.providerKind},
	})
	if err != nil {
		t.Fatalf("Claim(validation for publish) error = %v", err)
	}
	t.Cleanup(claim.Destroy)
	coordinates := discoveryqueue.RunCoordinates{
		Scope: assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID},
		RunID: fixture.runID,
	}
	attempt, err := repository.ReserveCleanupAttempt(
		context.Background(), claim.Fence, discoveryqueue.RunCommand{Coordinates: coordinates},
	)
	if err != nil {
		t.Fatalf("ReserveCleanupAttempt(validation for publish) error = %v", err)
	}
	work, err := repository.ProposeValidationResult(context.Background(), claim.Fence,
		discoveryqueue.ValidationResultCommand{Coordinates: coordinates, Proof: queueValidationSuccessProof()})
	if err != nil {
		t.Fatalf("ProposeValidationResult(for publish) error = %v", err)
	}
	cleanupDigest := strings.Repeat("7", 64)
	proof := newQueueCleanupProof(
		t, coordinates, attempt, assetcatalog.CredentialCleanupRevoked, cleanupDigest,
	)
	if _, err := repository.RecordCleanup(context.Background(), claim.Fence, proof); err != nil {
		t.Fatalf("RecordCleanup(validation for publish) error = %v", err)
	}
	if _, err := repository.Complete(context.Background(), claim.Fence, discoveryqueue.TerminalCommand{
		Coordinates: coordinates, DesiredStatus: assetcatalog.RunStatusSucceeded,
		WorkResultDigest: work.DigestSHA256,
		CleanupStatus:    assetcatalog.CredentialCleanupRevoked, CleanupDigest: cleanupDigest,
	}); err != nil {
		t.Fatalf("Complete(validation for publish) error = %v", err)
	}
	queueExec(t, harness.db, `
UPDATE asset_source_revisions SET state='PUBLISHED',version=version+1 WHERE id=$1
`, fixture.revisionID)
	tx, err := harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin Queue AVAILABLE gate closure: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	queueExec(t, tx, `
UPDATE asset_sources
SET gate_status='AVAILABLE',gate_reason_code=NULL,gate_revision=gate_revision+1,
    validated_run_id=$2::uuid,validation_digest=$3,validated_binding_digest=$4,
    version=version+1
WHERE id=$1::uuid
`, fixture.sourceID, fixture.runID, work.DigestSHA256, fixture.revisionDigest)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit Queue AVAILABLE gate closure: %v", err)
	}
}

func seedQueueDataRun(
	t *testing.T,
	database *pgxpool.Pool,
	fixture queueFixture,
	suffix string,
) string {
	t.Helper()
	runID := uuid.NewString()
	queueExec(t, database, `
INSERT INTO asset_source_runs(
 id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
 run_kind,trigger_type,gate_revision,idempotency_key,request_hash,
 cursor_before_sha256,checkpoint_version
)
SELECT $1,$2,$3,$4,published_revision,published_revision_digest,
       'DISCOVERY','SCHEDULED',gate_revision,$5,repeat('4',64),
       checkpoint_sha256,checkpoint_version
FROM asset_sources WHERE id=$4
`, runID, fixture.tenantID, fixture.workspaceID, fixture.sourceID, "queue-data-"+suffix)
	return runID
}

func newTestQueue(t *testing.T, pool *pgxpool.Pool) *Repository {
	t.Helper()
	repository, err := New(pool, acceptingCleanupVerifier{}, acceptingRolloverVerifier{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return repository
}

type acceptingCleanupVerifier struct{}

func (acceptingCleanupVerifier) VerifyCleanupProof(context.Context, discoveryqueue.CleanupProof) error {
	return nil
}

type rejectingCleanupVerifier struct{}

func (rejectingCleanupVerifier) VerifyCleanupProof(context.Context, discoveryqueue.CleanupProof) error {
	return errors.New("rejected cleanup proof")
}

type acceptingRolloverVerifier struct{}

func (acceptingRolloverVerifier) VerifyCheckpointLineageRollover(
	context.Context,
	discoveryqueue.CheckpointLineageRolloverRequest,
) error {
	return nil
}

type rejectingRolloverVerifier struct{}

func (rejectingRolloverVerifier) VerifyCheckpointLineageRollover(
	context.Context,
	discoveryqueue.CheckpointLineageRolloverRequest,
) error {
	return errors.New("rejected rollover evidence")
}

type capturingRolloverVerifier struct {
	calls   int
	request discoveryqueue.CheckpointLineageRolloverRequest
}

func (verifier *capturingRolloverVerifier) VerifyCheckpointLineageRollover(
	_ context.Context,
	request discoveryqueue.CheckpointLineageRolloverRequest,
) error {
	verifier.calls++
	verifier.request = request
	return nil
}

type queueSQLExecutor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func readQueueRunRow(
	t *testing.T,
	pool *pgxpool.Pool,
	coordinates discoveryqueue.RunCoordinates,
) runRow {
	t.Helper()
	row, err := withSerializable(context.Background(), pool, func(tx pgx.Tx) (runRow, error) {
		return lockRun(context.Background(), tx, coordinates)
	})
	if err != nil {
		t.Fatalf("read Queue run row: %v", err)
	}
	return row
}

func queueExec(t *testing.T, executor queueSQLExecutor, statement string, arguments ...any) {
	t.Helper()
	if _, err := executor.Exec(context.Background(), statement, arguments...); err != nil {
		var databaseError *pgconn.PgError
		if errors.As(err, &databaseError) {
			t.Fatalf("Queue fixture SQL failed: %s (SQLSTATE %s, constraint %s)",
				databaseError.Message, databaseError.Code, databaseError.ConstraintName)
		}
		t.Fatalf("Queue fixture SQL failed: %v", err)
	}
}

func queueMigrationDirectory(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve Queue integration test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "../../../migrations"))
}

func randomQueueHex(t *testing.T, size int) string {
	t.Helper()
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		t.Fatalf("read Queue test randomness: %v", err)
	}
	return hex.EncodeToString(value)
}

func queueFramedDigest(values ...[]byte) string {
	hasher := sha256.New()
	for _, value := range values {
		if value == nil {
			_, _ = hasher.Write([]byte{0})
			continue
		}
		_, _ = hasher.Write([]byte{1})
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = hasher.Write(length[:])
		_, _ = hasher.Write(value)
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func queueDecodeDigest(t *testing.T, digest string) []byte {
	t.Helper()
	value, err := hex.DecodeString(digest)
	if err != nil || len(value) != sha256.Size {
		t.Fatalf("invalid Queue fixture digest %q", digest)
	}
	return value
}
