// Package discoveryworker owns the provider-neutral, attempt-bound discovery
// Worker core. Provider registration and production assembly are separate
// closed tasks.
package discoveryworker

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
	"github.com/seaworld008/aiops-system/internal/discoverycheckpoint"
	"github.com/seaworld008/aiops-system/internal/discoverycleanup"
	"github.com/seaworld008/aiops-system/internal/discoverylimit"
	"github.com/seaworld008/aiops-system/internal/discoveryqueue"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
	"github.com/seaworld008/aiops-system/internal/domain"
)

var (
	ErrInvalidDependencies = errors.New("discovery worker dependencies invalid")
	ErrClaimRejected       = errors.New("discovery worker claim rejected")
	ErrWorkerUnavailable   = errors.New("discovery worker unavailable")
	ErrCleanupUncertain    = errors.New("discovery worker cleanup uncertain")
)

// Dependencies contains only already-merged provider-neutral boundaries.
// ClaimCommand fixes the process owner, lease, and closed Provider set.
type Dependencies struct {
	Queue                discoveryqueue.Queue
	CleanupBroker        *discoverycleanup.CleanupBroker
	Limiter              discoverylimit.Limiter
	PageCommitter        discoverysource.PageCommitter
	Checkpoints          *discoverycheckpoint.CheckpointCodec
	ClaimRuntimeResolver ClaimRuntimeResolver
	ClaimCommand         discoveryqueue.ClaimCommand
}

type Worker struct {
	queue                discoveryqueue.Queue
	cleanupBroker        *discoverycleanup.CleanupBroker
	limiter              discoverylimit.Limiter
	pageCommitter        discoverysource.PageCommitter
	checkpoints          *discoverycheckpoint.CheckpointCodec
	claimRuntimeResolver ClaimRuntimeResolver
	claimCommand         discoveryqueue.ClaimCommand

	lifecycleMu sync.Mutex
	runCancel   context.CancelFunc
	runDone     chan struct{}
	running     bool
}

// New fails closed for every missing production boundary. It never installs a
// memory, fake, or permissive fallback.
func New(dependencies Dependencies) (*Worker, error) {
	if nilDependency(dependencies.Queue) || dependencies.CleanupBroker == nil ||
		nilDependency(dependencies.Limiter) || nilDependency(dependencies.PageCommitter) ||
		dependencies.Checkpoints == nil || nilDependency(dependencies.ClaimRuntimeResolver) ||
		dependencies.ClaimCommand.Validate() != nil {
		return nil, ErrInvalidDependencies
	}
	return &Worker{
		queue: dependencies.Queue, cleanupBroker: dependencies.CleanupBroker,
		limiter: dependencies.Limiter, pageCommitter: dependencies.PageCommitter,
		checkpoints: dependencies.Checkpoints, claimRuntimeResolver: dependencies.ClaimRuntimeResolver,
		claimCommand: dependencies.ClaimCommand.Clone(),
	}, nil
}

// Run claims one exact Queue handoff at a time until cancellation or a
// fail-closed processing error. A Worker instance cannot run concurrently.
func (worker *Worker) Run(ctx context.Context) error {
	if worker == nil || ctx == nil {
		return ErrWorkerUnavailable
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	worker.lifecycleMu.Lock()
	if worker.running {
		worker.lifecycleMu.Unlock()
		cancel()
		return ErrWorkerUnavailable
	}
	worker.running = true
	worker.runCancel = cancel
	worker.runDone = done
	worker.lifecycleMu.Unlock()
	defer func() {
		cancel()
		worker.lifecycleMu.Lock()
		worker.running = false
		worker.runCancel = nil
		close(done)
		worker.lifecycleMu.Unlock()
	}()

	for {
		claim, err := worker.nextClaim(runCtx)
		if errors.Is(err, discoveryqueue.ErrNoWork) {
			timer := time.NewTimer(25 * time.Millisecond)
			select {
			case <-runCtx.Done():
				timer.Stop()
				return runCtx.Err()
			case <-timer.C:
				continue
			}
		}
		if err != nil {
			if runCtx.Err() != nil {
				return runCtx.Err()
			}
			return ErrWorkerUnavailable
		}
		processErr := worker.processClaimSafely(runCtx, &claim)
		claim.Destroy()
		if processErr != nil {
			if runCtx.Err() != nil {
				return runCtx.Err()
			}
			return processErr
		}
	}
}

// Stop cancels new work and waits only until ctx expires for the current
// attempt's bounded cleanup.
func (worker *Worker) Stop(ctx context.Context) error {
	if worker == nil || ctx == nil {
		return ErrWorkerUnavailable
	}
	worker.lifecycleMu.Lock()
	cancel := worker.runCancel
	done := worker.runDone
	running := worker.running
	worker.lifecycleMu.Unlock()
	if !running {
		return nil
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (worker *Worker) nextClaim(ctx context.Context) (discoveryqueue.ClaimResult, error) {
	claimers := []func(context.Context, discoveryqueue.ClaimCommand) (discoveryqueue.ClaimResult, error){
		worker.queue.Claim,
		worker.queue.Reclaim,
		worker.queue.ReclaimFinalizing,
	}
	for _, claim := range claimers {
		result, err := claim(ctx, worker.claimCommand.Clone())
		if err == nil {
			return result, nil
		}
		if ctx.Err() != nil {
			return discoveryqueue.ClaimResult{}, ctx.Err()
		}
		if !errors.Is(err, discoveryqueue.ErrNoWork) {
			return discoveryqueue.ClaimResult{}, err
		}
	}
	return discoveryqueue.ClaimResult{}, discoveryqueue.ErrNoWork
}

func (worker *Worker) processClaimSafely(
	ctx context.Context,
	claim *discoveryqueue.ClaimResult,
) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrWorkerUnavailable
		}
	}()
	return worker.processClaim(ctx, claim)
}

func (worker *Worker) processClaim(ctx context.Context, claim *discoveryqueue.ClaimResult) error {
	if ctx == nil || worker == nil || claim == nil || !claim.Mode.Valid() {
		return ErrClaimRejected
	}
	coordinates := discoveryqueue.RunCoordinates{Scope: claim.Run.Scope, RunID: claim.Run.ID}
	if !coordinates.Valid() || claim.Run.SourceID == "" || claim.Run.SourceRevision <= 0 ||
		claim.Run.SourceRevisionDigest == "" || claim.Run.FenceEpoch <= 0 {
		return ErrClaimRejected
	}
	switch claim.Mode {
	case discoveryqueue.ClaimModeProvider:
		return worker.processProviderClaim(ctx, claim, coordinates)
	case discoveryqueue.ClaimModeCleanupOnly:
		return worker.processCleanupClaim(ctx, claim, coordinates, false)
	case discoveryqueue.ClaimModeTerminal:
		return worker.processCleanupClaim(ctx, claim, coordinates, true)
	default:
		return ErrClaimRejected
	}
}

func (worker *Worker) processProviderClaim(
	ctx context.Context,
	claim *discoveryqueue.ClaimResult,
	coordinates discoveryqueue.RunCoordinates,
) (returnedErr error) {
	if claim.CleanupAttempt != nil || claim.PersistedDelay != nil ||
		claim.Run.Status != assetcatalog.RunStatusRunning {
		return ErrClaimRejected
	}
	revisionStatus := assetcatalog.SourceRevisionPublished
	expectedStage := assetcatalog.RunStageReading
	var checkpoints *discoverycheckpoint.CheckpointCodec = worker.checkpoints
	checkpointSHA256 := claim.Run.CursorAfterSHA256
	if checkpointSHA256 == "" {
		checkpointSHA256 = claim.Run.CursorBeforeSHA256
	}
	switch claim.Run.Kind {
	case assetcatalog.RunKindValidation:
		revisionStatus = assetcatalog.SourceRevisionValidating
		expectedStage = assetcatalog.RunStageValidating
		checkpoints = nil
		checkpointSHA256 = ""
	case assetcatalog.RunKindDiscovery, assetcatalog.RunKindCSVImport, assetcatalog.RunKindAPIIngestion:
	default:
		return ErrClaimRejected
	}
	if claim.Run.Stage != expectedStage {
		return ErrClaimRejected
	}
	limitCoordinates := discoverylimit.Coordinates{
		Scope: claim.Run.Scope, SourceID: claim.Run.SourceID,
		RunID: claim.Run.ID, ProviderKind: claim.ProviderKind,
	}
	acquire := discoverylimit.AcquireCommand{
		Coordinates: limitCoordinates,
		RequestID: fmt.Sprintf(
			"worker-acquire:%s:%d:%d",
			claim.Run.ID, claim.Run.FenceEpoch, claim.Run.PageSequence+1,
		),
		TTL: worker.claimCommand.LeaseDuration,
	}
	permit, err := worker.limiter.Acquire(ctx, acquire)
	if err != nil || !permit.Valid() || permit.Coordinates != limitCoordinates ||
		permit.RequestID != acquire.RequestID {
		return ErrWorkerUnavailable
	}

	attempt, err := worker.reserveCleanupAttempt(ctx, claim, coordinates)
	if err != nil {
		_ = worker.releasePermit(ctx, permit, "ATTEMPT_RESERVE_FAILED")
		return err
	}
	opened := false
	cleaned := false
	permitTerminal := false
	hasPersistedIntent := false
	var runtime ClaimRuntime
	var openedRuntime discoverysource.BoundRuntime
	release := func(releaseCtx context.Context, reason string) error {
		err := worker.releasePermit(releaseCtx, permit, reason)
		if err == nil {
			permitTerminal = true
		}
		return err
	}
	defer func() {
		panicked := recover() != nil
		if panicked {
			returnedErr = ErrWorkerUnavailable
		}
		cleanupCtx, cancel := context.WithTimeout(
			context.Background(), worker.claimCommand.LeaseDuration,
		)
		defer cancel()
		if !permitTerminal {
			_ = worker.releasePermit(cleanupCtx, permit, "WORKER_ABORTED")
		}
		work, hasWork := claimWorkResult(claim)
		if opened && !cleaned && !hasPersistedIntent && !hasWork {
			failureCode := "WORKER_ABORTED"
			if panicked {
				failureCode = "PROVIDER_PANIC"
			} else if ctx.Err() != nil {
				failureCode = "WORKER_CANCELLED"
			}
			prepared, err := worker.prepareFailureIntent(
				cleanupCtx, claim, coordinates, failureCode,
			)
			if err == nil {
				work, hasWork = prepared, true
			}
		}
		runtime.destroy()
		openedRuntime.Clear()
		if opened && !cleaned {
			cleanup, err := worker.revokeAndRecord(cleanupCtx, claim, coordinates, attempt)
			if cleanup.Attempt == attempt {
				cleaned = true
			}
			if err == nil && hasWork {
				_ = worker.finishWork(cleanupCtx, claim, coordinates, work, cleanup)
			}
		}
	}()

	session, err := worker.cleanupBroker.OpenAttempt(ctx, discoverycleanup.OpenAttemptRequest{
		Coordinates: coordinates, Attempt: attempt,
	})
	if err != nil && session != nil {
		session.Destroy()
		session = nil
	}
	switch {
	case errors.Is(err, discoverycleanup.ErrAttemptDrift):
		_ = release(ctx, "ATTEMPT_OPEN_REJECTED")
		return ErrClaimRejected
	case err != nil &&
		!errors.Is(err, discoverycleanup.ErrSessionAuthentication) &&
		!errors.Is(err, discoverycleanup.ErrAttemptUncertain):
		_ = release(ctx, "ATTEMPT_OPEN_UNAVAILABLE")
		return ErrWorkerUnavailable
	case err == nil && session == nil:
		_ = release(ctx, "ATTEMPT_OPEN_UNAVAILABLE")
		return ErrWorkerUnavailable
	default:
		opened = true
	}
	if err != nil {
		notBefore := providerNotBefore(time.Second)
		intent := discoveryqueue.DelayIntent{
			Reason: discoveryqueue.DelayReasonTransportBackoff, NotBefore: notBefore,
		}
		updated, persistErr := worker.queue.AdvanceStage(
			ctx, claim.Fence,
			discoveryqueue.AdvanceStageCommand{
				Coordinates: coordinates, From: expectedStage,
				To: assetcatalog.RunStageCleaningUp, Delay: &intent,
			},
		)
		if persistErr != nil || updated.ID != claim.Run.ID ||
			updated.Stage != assetcatalog.RunStageCleaningUp {
			_ = release(ctx, "ATTEMPT_OPEN_FAILED")
			return ErrWorkerUnavailable
		}
		hasPersistedIntent = true
		claim.Run.Stage = updated.Stage
		if delayErr := worker.delayPermit(
			ctx, permit, discoveryqueue.DelayReasonTransportBackoff, notBefore,
		); delayErr != nil {
			return delayErr
		}
		permitTerminal = true
		cleanup, cleanupErr := worker.revokeAndRecord(ctx, claim, coordinates, attempt)
		if cleanup.Attempt == attempt {
			cleaned = true
		}
		if cleanupErr != nil {
			return cleanupErr
		}
		if _, delayErr := worker.queue.Delay(
			ctx, claim.Fence,
			discoveryqueue.DelayCommand{Coordinates: coordinates, Intent: intent},
		); delayErr != nil {
			return ErrWorkerUnavailable
		}
		return nil
	}
	defer session.Destroy()

	binding := discoverysource.RuntimeBinding{
		Locator: assetcatalog.SourceLocator{
			Scope: claim.Run.Scope, SourceID: claim.Run.SourceID,
		},
		SourceRevision:       claim.Run.SourceRevision,
		SourceRevisionDigest: claim.Run.SourceRevisionDigest,
		RevisionStatus:       revisionStatus,
		ProviderKind:         claim.ProviderKind,
		ProfileCode:          claim.ProfileCode,
	}
	openedRuntime, err = worker.cleanupBroker.BindAttemptRuntime(ctx, session, binding)
	if err != nil || openedRuntime.Binding() != binding {
		openedRuntime.Clear()
		_ = release(ctx, "RUNTIME_BINDING_REJECTED")
		return ErrClaimRejected
	}
	request, err := newResolveOpenedAttemptRequest(
		session, coordinates, attempt, binding, openedRuntime, claim.Run.Kind,
		claim.Run.CheckpointVersion, checkpointSHA256, checkpoints,
	)
	if err != nil {
		_ = release(ctx, "RUNTIME_BINDING_REJECTED")
		return ErrClaimRejected
	}
	runtime, err = worker.claimRuntimeResolver.ResolveOpenedAttempt(ctx, request)
	if err != nil || runtime.validate(request) != nil {
		runtime.destroy()
		_ = release(ctx, "RUNTIME_RESOLUTION_FAILED")
		return ErrClaimRejected
	}
	provider, providerRuntime, checkpoint, limits, policy, err := runtime.view(request)
	if err != nil || nilDependency(provider) || providerRuntime != openedRuntime ||
		providerRuntime.Binding() != binding {
		checkpoint.Clear()
		_ = release(ctx, "RUNTIME_VIEW_REJECTED")
		return ErrClaimRejected
	}
	if claim.Run.Kind != assetcatalog.RunKindValidation {
		return worker.processDataRuntime(
			ctx, claim, coordinates, request, provider, providerRuntime, checkpoint,
			limits, policy, &permit, &permitTerminal, &hasPersistedIntent,
			attempt, &runtime, &cleaned,
		)
	}
	checkpoint.Clear()

	if err := worker.heartbeat(ctx, claim, coordinates); err != nil {
		_ = release(ctx, "FENCE_REJECTED")
		return err
	}
	validationRequest := discoverysource.ValidationRequest{
		Locator: binding.Locator, SourceRevision: binding.SourceRevision,
		SourceRevisionDigest: binding.SourceRevisionDigest, Limits: limits,
	}
	proof, providerErr := provider.Validate(ctx, providerRuntime, validationRequest)
	if err := discoverysource.ValidateValidationResult(validationRequest, proof, providerErr); err != nil {
		_ = release(ctx, "PROVIDER_VALIDATION_FAILED")
		return ErrWorkerUnavailable
	}
	if providerRuntime.Binding() != binding {
		_ = release(ctx, "RUNTIME_DRIFTED")
		return ErrClaimRejected
	}
	if err := worker.heartbeat(ctx, claim, coordinates); err != nil {
		_ = release(ctx, "FENCE_REJECTED")
		return err
	}
	if err := release(ctx, "PROVIDER_CALL_COMPLETE"); err != nil {
		return err
	}
	work, err := worker.queue.ProposeValidationResult(
		ctx, claim.Fence,
		discoveryqueue.ValidationResultCommand{Coordinates: coordinates, Proof: proof},
	)
	if err != nil || work.Kind != assetcatalog.WorkResultValidationProof ||
		!work.Status.Valid() || !domain.ValidSHA256Hex(work.DigestSHA256) {
		return ErrWorkerUnavailable
	}
	claim.Run.Status = assetcatalog.RunStatusFinalizing
	claim.Run.Stage = assetcatalog.RunStageCleaningUp
	claim.Run.WorkResultKind = work.Kind
	claim.Run.WorkResultStatus = work.Status
	claim.Run.WorkResultDigest = work.DigestSHA256
	claim.Run.FailureCode = work.FailureCode

	runtime.destroy()
	cleanup, err := worker.revokeAndRecord(ctx, claim, coordinates, attempt)
	if err != nil {
		return err
	}
	cleaned = true
	return worker.finishWork(ctx, claim, coordinates, work, cleanup)
}

func (worker *Worker) processDataRuntime(
	ctx context.Context,
	claim *discoveryqueue.ClaimResult,
	coordinates discoveryqueue.RunCoordinates,
	request ResolveOpenedAttemptRequest,
	provider discoverysource.Provider,
	bound discoverysource.BoundRuntime,
	checkpoint discoverysource.Checkpoint,
	limits discoverysource.Limits,
	policy assetdiscovery.FactPolicy,
	permit *discoverylimit.Permit,
	permitTerminal *bool,
	hasPersistedIntent *bool,
	attempt discoveryqueue.CleanupAttempt,
	runtime *ClaimRuntime,
	cleaned *bool,
) error {
	defer checkpoint.Clear()
	release := func(reason string) error {
		err := worker.releasePermit(ctx, *permit, reason)
		if err == nil {
			*permitTerminal = true
		}
		return err
	}
	for {
		if err := worker.heartbeat(ctx, claim, coordinates); err != nil {
			_ = release("FENCE_REJECTED")
			return err
		}
		callCheckpoint := checkpoint.Clone()
		discoverRequest := discoverysource.DiscoverRequest{
			Locator:              request.RuntimeBinding().Locator,
			SourceRevision:       request.RuntimeBinding().SourceRevision,
			SourceRevisionDigest: request.RuntimeBinding().SourceRevisionDigest,
			Checkpoint:           callCheckpoint, Limits: limits,
		}
		outcome, providerErr := provider.Discover(ctx, bound, discoverRequest)
		validationErr := discoverysource.ValidateDiscoverResult(
			discoverRequest, policy, outcome, providerErr,
		)
		callCheckpoint.Clear()
		if validationErr != nil {
			_ = release("PROVIDER_DISCOVERY_FAILED")
			return ErrWorkerUnavailable
		}
		if bound.Binding() != request.RuntimeBinding() {
			_ = release("RUNTIME_DRIFTED")
			return ErrClaimRejected
		}
		if err := worker.heartbeat(ctx, claim, coordinates); err != nil {
			_ = release("FENCE_REJECTED")
			return err
		}
		switch value := outcome.(type) {
		case discoverysource.Page:
			updated, err := worker.queue.AdvanceStage(
				ctx, claim.Fence,
				discoveryqueue.AdvanceStageCommand{
					Coordinates: coordinates, From: assetcatalog.RunStageReading,
					To: assetcatalog.RunStageNormalizing,
				},
			)
			if err != nil || updated.ID != claim.Run.ID ||
				updated.Stage != assetcatalog.RunStageNormalizing {
				_ = release("PAGE_STAGE_FAILED")
				return ErrWorkerUnavailable
			}
			claim.Run.Stage = updated.Stage
			pageCoordinates := discoverysource.PageCommitCoordinates{
				Locator: request.RuntimeBinding().Locator,
				RunID:   claim.Run.ID, PageSequence: claim.Run.PageSequence + 1,
			}
			result, err := worker.pageCommitter.ApplyPage(
				ctx, claim.Fence, pageCoordinates, value,
			)
			if err != nil || result.RunID != claim.Run.ID ||
				result.PageSequence != pageCoordinates.PageSequence ||
				result.CheckpointVersion != claim.Run.CheckpointVersion+1 ||
				!domain.ValidSHA256Hex(result.CheckpointSHA256) ||
				!domain.ValidSHA256Hex(result.PageDigestSHA256) ||
				!domain.ValidSHA256Hex(result.RelationPageDigestSHA256) ||
				result.FinalPage != value.FinalPage ||
				result.CompleteSnapshot != value.CompleteSnapshot {
				_ = release("PAGE_COMMIT_FAILED")
				return ErrWorkerUnavailable
			}
			claim.Run.PageSequence = result.PageSequence
			claim.Run.CheckpointVersion = result.CheckpointVersion
			claim.Run.CursorAfterSHA256 = result.CheckpointSHA256
			claim.Run.HeartbeatSequence++
			if value.FinalPage {
				claim.Run.Status = assetcatalog.RunStatusFinalizing
				claim.Run.Stage = assetcatalog.RunStageCleaningUp
			} else {
				claim.Run.Stage = assetcatalog.RunStageReading
			}
			nextCheckpoint := value.NextCheckpoint.Clone()
			value.NextCheckpoint.Clear()
			checkpoint.Clear()
			checkpoint = nextCheckpoint
			if checkpoint.ProfileCode() != claim.ProfileCode {
				_ = release("CHECKPOINT_DRIFTED")
				return ErrClaimRejected
			}
			if err := release("PROVIDER_CALL_COMPLETE"); err != nil {
				return err
			}
			if !value.FinalPage {
				nextPermit, err := worker.acquirePermit(ctx, claim)
				if err != nil {
					return err
				}
				*permit = nextPermit
				*permitTerminal = false
				continue
			}
			runtime.destroy()
			cleanup, err := worker.revokeAndRecord(ctx, claim, coordinates, attempt)
			if err != nil {
				return err
			}
			*cleaned = true
			if err := worker.heartbeat(ctx, claim, coordinates); err != nil {
				return err
			}
			work := discoveryqueue.WorkResult{
				Kind: claim.Run.WorkResultKind, Status: claim.Run.WorkResultStatus,
				DigestSHA256: claim.Run.WorkResultDigest, FailureCode: claim.Run.FailureCode,
			}
			return worker.finishWork(ctx, claim, coordinates, work, cleanup)
		case discoverysource.Delay:
			notBefore := providerNotBefore(value.RetryAfter)
			intent := discoveryqueue.DelayIntent{
				Reason:    discoveryqueue.DelayReasonProviderRetryAfter,
				NotBefore: notBefore,
			}
			updated, err := worker.queue.AdvanceStage(
				ctx, claim.Fence,
				discoveryqueue.AdvanceStageCommand{
					Coordinates: coordinates, From: assetcatalog.RunStageReading,
					To: assetcatalog.RunStageCleaningUp, Delay: &intent,
				},
			)
			if err != nil || updated.ID != claim.Run.ID ||
				updated.Stage != assetcatalog.RunStageCleaningUp {
				_ = release("DELAY_STAGE_FAILED")
				return ErrWorkerUnavailable
			}
			claim.Run.Stage = updated.Stage
			*hasPersistedIntent = true
			if err := worker.delayPermit(
				ctx, *permit, discoveryqueue.DelayReasonProviderRetryAfter, notBefore,
			); err != nil {
				return err
			}
			*permitTerminal = true
			runtime.destroy()
			cleanup, err := worker.revokeAndRecord(ctx, claim, coordinates, attempt)
			if err != nil {
				return err
			}
			_ = cleanup
			*cleaned = true
			if _, err := worker.queue.Delay(
				ctx, claim.Fence,
				discoveryqueue.DelayCommand{Coordinates: coordinates, Intent: intent},
			); err != nil {
				return ErrWorkerUnavailable
			}
			return nil
		default:
			_ = release("OUTCOME_REJECTED")
			return ErrClaimRejected
		}
	}
}

func (worker *Worker) processCleanupClaim(
	ctx context.Context,
	claim *discoveryqueue.ClaimResult,
	coordinates discoveryqueue.RunCoordinates,
	terminal bool,
) error {
	if claim.Run.Stage != assetcatalog.RunStageCleaningUp {
		return ErrClaimRejected
	}
	if claim.PersistedDelay != nil {
		if terminal ||
			(claim.Run.Status != assetcatalog.RunStatusRunning &&
				claim.Run.Status != assetcatalog.RunStatusFinalizing) {
			return ErrClaimRejected
		}
	} else if claim.Run.Status != assetcatalog.RunStatusFinalizing {
		return ErrClaimRejected
	}
	if claim.CleanupAttempt == nil {
		if !terminal || claim.Run.CredentialCleanupStatus != assetcatalog.CredentialCleanupNotOpened {
			return ErrClaimRejected
		}
		return worker.finishWithoutCleanup(ctx, claim, coordinates)
	}
	attempt := *claim.CleanupAttempt
	if !attempt.Valid() || attempt.RunID != claim.Run.ID {
		return ErrClaimRejected
	}
	session, openErr := worker.cleanupBroker.OpenAttempt(ctx, discoverycleanup.OpenAttemptRequest{
		Coordinates: coordinates, Attempt: attempt,
	})
	if session != nil {
		session.Destroy()
	}
	switch {
	case errors.Is(openErr, discoverycleanup.ErrAttemptDrift):
		return ErrClaimRejected
	case openErr != nil &&
		!errors.Is(openErr, discoverycleanup.ErrAttemptClosed) &&
		!errors.Is(openErr, discoverycleanup.ErrSessionAuthentication) &&
		!errors.Is(openErr, discoverycleanup.ErrAttemptUncertain):
		return ErrWorkerUnavailable
	case openErr == nil && session == nil:
		return ErrWorkerUnavailable
	}
	cleanup, err := worker.revokeAndRecord(ctx, claim, coordinates, attempt)
	if err != nil {
		return err
	}
	if claim.PersistedDelay != nil {
		_, err := worker.queue.Delay(ctx, claim.Fence, discoveryqueue.DelayCommand{
			Coordinates: coordinates,
			Intent: discoveryqueue.DelayIntent{
				Reason: claim.PersistedDelay.Reason, NotBefore: claim.PersistedDelay.NotBefore,
			},
		})
		if err != nil {
			return ErrWorkerUnavailable
		}
		return nil
	}
	work := discoveryqueue.WorkResult{
		Kind: claim.Run.WorkResultKind, Status: claim.Run.WorkResultStatus,
		DigestSHA256: claim.Run.WorkResultDigest, FailureCode: claim.Run.FailureCode,
	}
	return worker.finishWork(ctx, claim, coordinates, work, cleanup)
}

func (worker *Worker) heartbeat(
	ctx context.Context,
	claim *discoveryqueue.ClaimResult,
	coordinates discoveryqueue.RunCoordinates,
) error {
	sequence := claim.Run.HeartbeatSequence + 1
	result, err := worker.queue.Heartbeat(ctx, claim.Fence, discoveryqueue.HeartbeatCommand{
		Coordinates: coordinates, Sequence: sequence,
		Extension: worker.claimCommand.LeaseDuration,
	})
	if err != nil {
		if errors.Is(err, discoveryqueue.ErrStaleFence) ||
			errors.Is(err, discoveryqueue.ErrIneligible) {
			return ErrClaimRejected
		}
		return ErrWorkerUnavailable
	}
	if result.Run.ID != claim.Run.ID || result.Run.SourceID != claim.Run.SourceID ||
		result.Run.Scope != claim.Run.Scope ||
		result.Run.SourceRevision != claim.Run.SourceRevision ||
		result.Run.SourceRevisionDigest != claim.Run.SourceRevisionDigest ||
		result.Run.FenceEpoch != claim.Run.FenceEpoch ||
		result.Run.HeartbeatSequence != sequence ||
		!result.LeaseExpiresAt.After(time.Now().UTC()) {
		return ErrClaimRejected
	}
	claim.Run = result.Run
	return nil
}

func (worker *Worker) releasePermit(
	ctx context.Context,
	permit discoverylimit.Permit,
	reason string,
) error {
	command := discoverylimit.ReleaseCommand{
		Coordinates: permit.Coordinates, PermitID: permit.PermitID,
		RequestID: "worker-release:" + permit.PermitID, ReasonCode: reason,
	}
	receipt, err := worker.limiter.Release(ctx, command)
	if err != nil || !receipt.Valid() || receipt.Kind != discoverylimit.ReceiptRelease ||
		receipt.PermitID != permit.PermitID || receipt.Coordinates != permit.Coordinates ||
		receipt.RequestID != command.RequestID {
		return ErrWorkerUnavailable
	}
	return nil
}

func (worker *Worker) acquirePermit(
	ctx context.Context,
	claim *discoveryqueue.ClaimResult,
) (discoverylimit.Permit, error) {
	coordinates := discoverylimit.Coordinates{
		Scope: claim.Run.Scope, SourceID: claim.Run.SourceID,
		RunID: claim.Run.ID, ProviderKind: claim.ProviderKind,
	}
	command := discoverylimit.AcquireCommand{
		Coordinates: coordinates,
		RequestID: fmt.Sprintf(
			"worker-acquire:%s:%d:%d",
			claim.Run.ID, claim.Run.FenceEpoch, claim.Run.PageSequence+1,
		),
		TTL: worker.claimCommand.LeaseDuration,
	}
	permit, err := worker.limiter.Acquire(ctx, command)
	if err != nil || !permit.Valid() || permit.Coordinates != coordinates ||
		permit.RequestID != command.RequestID {
		return discoverylimit.Permit{}, ErrWorkerUnavailable
	}
	return permit, nil
}

func (worker *Worker) delayPermit(
	ctx context.Context,
	permit discoverylimit.Permit,
	reason discoveryqueue.DelayReason,
	notBefore time.Time,
) error {
	if !reason.Valid() {
		return ErrClaimRejected
	}
	command := discoverylimit.DelayCommand{
		Coordinates: permit.Coordinates, PermitID: permit.PermitID,
		RequestID:  "worker-delay:" + permit.PermitID,
		ReasonCode: string(reason),
		NotBefore:  notBefore,
	}
	receipt, err := worker.limiter.Delay(ctx, command)
	if err != nil || !receipt.Valid() || receipt.Kind != discoverylimit.ReceiptDelay ||
		receipt.PermitID != permit.PermitID || receipt.Coordinates != permit.Coordinates ||
		receipt.RequestID != command.RequestID || receipt.ReasonCode != command.ReasonCode ||
		receipt.NotBefore == nil || !receipt.NotBefore.Equal(notBefore) {
		return ErrWorkerUnavailable
	}
	return nil
}

func (worker *Worker) prepareFailureIntent(
	ctx context.Context,
	claim *discoveryqueue.ClaimResult,
	coordinates discoveryqueue.RunCoordinates,
	failureCode string,
) (discoveryqueue.WorkResult, error) {
	evidence := sha256.Sum256([]byte(fmt.Sprintf(
		"discovery-worker-failure.v1\x00%s\x00%d\x00%s\x00%s",
		claim.Run.ID, claim.Run.FenceEpoch, claim.Run.SourceRevisionDigest, failureCode,
	)))
	command := discoveryqueue.FailureIntentCommand{
		Coordinates: coordinates, FailureCode: failureCode,
		EvidenceDigest: fmt.Sprintf("%x", evidence[:]),
	}
	if command.Validate() != nil {
		return discoveryqueue.WorkResult{}, ErrClaimRejected
	}
	var work discoveryqueue.WorkResult
	var err error
	for try := 0; try < 2; try++ {
		work, err = worker.queue.PrepareFailureIntent(ctx, claim.Fence, command)
		if err == nil || !retryableQueueResponseLoss(err) {
			break
		}
	}
	if err != nil {
		return discoveryqueue.WorkResult{}, ErrWorkerUnavailable
	}
	if work.Kind != assetcatalog.WorkResultFailureIntent ||
		work.Status != assetcatalog.WorkResultStatusFailed ||
		!domain.ValidSHA256Hex(work.DigestSHA256) ||
		work.FailureCode != failureCode {
		return discoveryqueue.WorkResult{}, ErrClaimRejected
	}
	claim.Run.Status = assetcatalog.RunStatusFinalizing
	claim.Run.Stage = assetcatalog.RunStageCleaningUp
	claim.Run.WorkResultKind = work.Kind
	claim.Run.WorkResultStatus = work.Status
	claim.Run.WorkResultDigest = work.DigestSHA256
	claim.Run.FailureCode = work.FailureCode
	return work, nil
}

func claimWorkResult(
	claim *discoveryqueue.ClaimResult,
) (discoveryqueue.WorkResult, bool) {
	if claim == nil || !claim.Run.WorkResultKind.Valid() ||
		!claim.Run.WorkResultStatus.Valid() ||
		!domain.ValidSHA256Hex(claim.Run.WorkResultDigest) ||
		(claim.Run.WorkResultStatus == assetcatalog.WorkResultStatusFailed &&
			claim.Run.FailureCode == "") {
		return discoveryqueue.WorkResult{}, false
	}
	return discoveryqueue.WorkResult{
		Kind: claim.Run.WorkResultKind, Status: claim.Run.WorkResultStatus,
		DigestSHA256: claim.Run.WorkResultDigest, FailureCode: claim.Run.FailureCode,
	}, true
}

func retryableQueueResponseLoss(err error) bool {
	return errors.Is(err, discoveryqueue.ErrUnavailable)
}

func (worker *Worker) reserveCleanupAttempt(
	ctx context.Context,
	claim *discoveryqueue.ClaimResult,
	coordinates discoveryqueue.RunCoordinates,
) (discoveryqueue.CleanupAttempt, error) {
	command := discoveryqueue.RunCommand{Coordinates: coordinates}
	var attempt discoveryqueue.CleanupAttempt
	var err error
	for try := 0; try < 2; try++ {
		attempt, err = worker.queue.ReserveCleanupAttempt(ctx, claim.Fence, command)
		if err == nil || !retryableQueueResponseLoss(err) {
			break
		}
	}
	if err != nil {
		return discoveryqueue.CleanupAttempt{}, ErrWorkerUnavailable
	}
	if !attempt.Valid() || attempt.RunID != claim.Run.ID ||
		attempt.AttemptEpoch != claim.Run.FenceEpoch {
		return discoveryqueue.CleanupAttempt{}, ErrClaimRejected
	}
	return attempt, nil
}

func providerNotBefore(retryAfter time.Duration) time.Time {
	effective := retryAfter.Truncate(time.Microsecond)
	if effective <= 0 {
		effective = time.Microsecond
	}
	return time.Now().UTC().Truncate(time.Microsecond).Add(effective)
}

func (worker *Worker) revokeAndRecord(
	ctx context.Context,
	claim *discoveryqueue.ClaimResult,
	coordinates discoveryqueue.RunCoordinates,
	attempt discoveryqueue.CleanupAttempt,
) (discoveryqueue.CleanupResult, error) {
	proof, err := worker.cleanupBroker.RevokeAttempt(ctx, attempt.AttemptID)
	if err != nil {
		return discoveryqueue.CleanupResult{}, ErrWorkerUnavailable
	}
	defer proof.Destroy()
	if proof.Coordinates() != coordinates || proof.Attempt() != attempt ||
		worker.cleanupBroker.VerifyCleanupProof(ctx, proof) != nil {
		return discoveryqueue.CleanupResult{}, ErrClaimRejected
	}
	var result discoveryqueue.CleanupResult
	for try := 0; try < 2; try++ {
		result, err = worker.queue.RecordCleanup(ctx, claim.Fence, proof)
		if err == nil || !retryableQueueResponseLoss(err) {
			break
		}
	}
	if err != nil {
		return discoveryqueue.CleanupResult{}, ErrWorkerUnavailable
	}
	if result.Attempt != attempt ||
		result.Status != proof.Status() || result.DigestSHA256 != proof.DigestSHA256() {
		return discoveryqueue.CleanupResult{}, ErrClaimRejected
	}
	if result.Status == assetcatalog.CredentialCleanupUncertain {
		return result, ErrCleanupUncertain
	}
	if result.Status != assetcatalog.CredentialCleanupRevoked {
		return discoveryqueue.CleanupResult{}, ErrClaimRejected
	}
	return result, nil
}

func (worker *Worker) finishWork(
	ctx context.Context,
	claim *discoveryqueue.ClaimResult,
	coordinates discoveryqueue.RunCoordinates,
	work discoveryqueue.WorkResult,
	cleanup discoveryqueue.CleanupResult,
) error {
	desired := assetcatalog.RunStatus(work.Status)
	command := discoveryqueue.TerminalCommand{
		Coordinates: coordinates, DesiredStatus: desired,
		WorkResultDigest: work.DigestSHA256,
		CleanupStatus:    cleanup.Status, CleanupDigest: cleanup.DigestSHA256,
	}
	if desired == assetcatalog.RunStatusFailed {
		command.FailureCode = work.FailureCode
		if command.FailureCode == "" && work.Kind == assetcatalog.WorkResultValidationProof {
			command.FailureCode = "VALIDATION_FAILED"
		}
		return worker.commitTerminal(ctx, claim, command, true)
	}
	if desired != assetcatalog.RunStatusSucceeded && desired != assetcatalog.RunStatusPartial {
		return ErrClaimRejected
	}
	return worker.commitTerminal(ctx, claim, command, false)
}

func (worker *Worker) commitTerminal(
	ctx context.Context,
	claim *discoveryqueue.ClaimResult,
	command discoveryqueue.TerminalCommand,
	failing bool,
) error {
	if command.Validate() != nil {
		return ErrClaimRejected
	}
	var result discoveryqueue.TerminalResult
	var err error
	for try := 0; try < 2; try++ {
		if failing {
			result, err = worker.queue.Fail(ctx, claim.Fence, command)
		} else {
			result, err = worker.queue.Complete(ctx, claim.Fence, command)
		}
		if err == nil || !retryableQueueResponseLoss(err) {
			break
		}
	}
	if err != nil {
		return ErrWorkerUnavailable
	}
	if result.RunID != command.Coordinates.RunID ||
		result.Status != command.DesiredStatus ||
		!domain.ValidSHA256Hex(result.CommandDigest) ||
		result.CompletedAt.IsZero() ||
		!result.CompletedAt.Equal(result.CompletedAt.Truncate(time.Microsecond)) {
		return ErrClaimRejected
	}
	return nil
}

func (worker *Worker) finishWithoutCleanup(
	ctx context.Context,
	claim *discoveryqueue.ClaimResult,
	coordinates discoveryqueue.RunCoordinates,
) error {
	work := discoveryqueue.WorkResult{
		Kind: claim.Run.WorkResultKind, Status: claim.Run.WorkResultStatus,
		DigestSHA256: claim.Run.WorkResultDigest, FailureCode: claim.Run.FailureCode,
	}
	return worker.finishWork(ctx, claim, coordinates, work, discoveryqueue.CleanupResult{
		Status: assetcatalog.CredentialCleanupNotOpened,
	})
}
