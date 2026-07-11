package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/seaworld008/aiops-system/internal/action"
	"github.com/seaworld008/aiops-system/internal/credential"
	"github.com/seaworld008/aiops-system/internal/executionlease"
	"github.com/seaworld008/aiops-system/internal/policy"
)

const (
	MaxEnvironmentSnapshotAge  = 15 * time.Second
	MaxSafetySnapshotAge       = 5 * time.Second
	MaxPreExecutionDecisionAge = 5 * time.Second

	maximumClockSkew = time.Second
	maximumLease     = 30 * time.Minute
	maximumFinalize  = 30 * time.Second
)

var (
	ErrInvalidAction          = errors.New("invalid verified action envelope")
	ErrEnvironmentUnavailable = errors.New("trusted environment state is unavailable")
	ErrEnvironmentDrift       = errors.New("trusted environment state changed after enqueue")
	ErrEnvironmentNotAllowed  = errors.New("runner is not allowed for the action environment")
	ErrClaimsDisabled         = errors.New("write execution claims are disabled")
	ErrCredentialDenied       = errors.New("execution credential is unavailable or denied")
	ErrPreExecutionDenied     = errors.New("pre-execution policy denied the action")
	ErrExecutionFailed        = errors.New("execution completed with a definite failure")
	ErrExecutionUncertain     = errors.New("execution outcome is uncertain")
	ErrJobNotFound            = errors.New("claimed execution has no verified action")
	ErrJobConflict            = errors.New("execution id is bound to a different verified action")
	ErrIdempotencyConflict    = errors.New("idempotency key is bound to different action semantics")
	ErrHeartbeatSequence      = errors.New("heartbeat sequence is stale or non-consecutive")
)

type EnvironmentSnapshot struct {
	WorkspaceID   string
	EnvironmentID string
	Production    bool
	Revision      string
	ObservedAt    time.Time
}

type EnvironmentResolver interface {
	Resolve(context.Context, string, string) (EnvironmentSnapshot, error)
}

type SafetyPhase string

const (
	SafetyPhaseClaim SafetyPhase = "claim"
	SafetyPhaseStart SafetyPhase = "start"
)

type SafetyRequest struct {
	Phase         SafetyPhase
	Pool          executionlease.Pool
	RunnerID      string
	WorkspaceID   string
	EnvironmentID string
	ConnectorID   string
	ActionType    action.ActionType
}

type ClaimSafetySnapshot struct {
	Enabled       bool
	Pool          executionlease.Pool
	RunnerID      string
	WorkspaceID   string
	EnvironmentID string
	ConnectorID   string
	ActionType    action.ActionType
	Revision      string
	ObservedAt    time.Time
}

type SafetyGate interface {
	Evaluate(context.Context, SafetyRequest) (ClaimSafetySnapshot, error)
}

type CredentialBroker interface {
	Prepare(context.Context, credential.PrepareDurableCredentialRequest) (credential.PreparedDurableCredential, error)
	Issue(context.Context, credential.PreparedDurableCredential) (credential.DurableCredential, error)
	RecordNoCredential(context.Context, credential.PreparedDurableCredential) (credential.Revocation, error)
	RequestRevocation(context.Context, credential.DurableCredential) (credential.Revocation, error)
}

type PreExecutionPolicy interface {
	EvaluateCredentialIssue(context.Context, action.Envelope) (policy.Decision, error)
	EvaluatePreExecution(context.Context, action.Envelope) (policy.Decision, error)
}

type ExecutorOutcome string

const (
	ExecutorSucceeded ExecutorOutcome = "SUCCEEDED"
	ExecutorFailed    ExecutorOutcome = "FAILED"
	ExecutorUncertain ExecutorOutcome = "UNCERTAIN"
)

type Verification string

const (
	VerificationPassed  Verification = "PASSED"
	VerificationFailed  Verification = "FAILED"
	VerificationUnknown Verification = "UNKNOWN"
)

type ExecutorResult struct {
	Outcome                  ExecutorOutcome `json:"outcome"`
	Code                     string          `json:"code"`
	Verification             Verification    `json:"verification"`
	Changed                  bool            `json:"changed"`
	ExternalOperationRefHash string          `json:"external_operation_ref_hash,omitempty"`
}

type CommandIdentity struct {
	ActionID      string
	WorkspaceID   string
	IncidentID    string
	ServiceID     string
	EnvironmentID string
	TraceID       string
}

type KubernetesRolloutRestartCommand struct {
	Identity      CommandIdentity
	Target        action.KubernetesDeploymentTarget
	Parameters    action.KubernetesRolloutRestartParameters
	ObservedState action.KubernetesDeploymentObservedState
	Preconditions action.Preconditions
	Verification  action.VerificationPlan
}

type KubernetesScaleCommand struct {
	Identity      CommandIdentity
	Target        action.KubernetesDeploymentTarget
	Parameters    action.KubernetesScaleParameters
	ObservedState action.KubernetesDeploymentObservedState
	Preconditions action.Preconditions
	Verification  action.VerificationPlan
}

type GitOpsRevertCommand struct {
	Identity      CommandIdentity
	Target        action.GitOpsTarget
	Parameters    action.GitOpsRevertParameters
	ObservedState action.GitOpsObservedState
	Preconditions action.Preconditions
	Verification  action.VerificationPlan
}

type AWXServiceRestartCommand struct {
	Identity      CommandIdentity
	Target        action.AWXTarget
	Parameters    action.AWXServiceRestartParameters
	ObservedState action.AWXServiceObservedState
	Preconditions action.Preconditions
	Verification  action.VerificationPlan
}

type KubernetesRolloutRestartExecutor interface {
	ExecuteRolloutRestart(context.Context, KubernetesRolloutRestartCommand, credential.DurableCredential) (ExecutorResult, error)
}

type KubernetesScaleExecutor interface {
	ExecuteScale(context.Context, KubernetesScaleCommand, credential.DurableCredential) (ExecutorResult, error)
}

type GitOpsRevertExecutor interface {
	ExecuteGitOpsRevert(context.Context, GitOpsRevertCommand, credential.DurableCredential) (ExecutorResult, error)
}

type AWXServiceRestartExecutor interface {
	ExecuteAWXServiceRestart(context.Context, AWXServiceRestartCommand, credential.DurableCredential) (ExecutorResult, error)
}

type Executors struct {
	KubernetesRolloutRestart KubernetesRolloutRestartExecutor
	KubernetesScale          KubernetesScaleExecutor
	GitOpsRevert             GitOpsRevertExecutor
	AWXServiceRestart        AWXServiceRestartExecutor
}

type Dependencies struct {
	Queue               ActionQueue
	RunnerRegistrations RunnerRegistrationRepository
	Keys                action.KeyResolver
	Environments        EnvironmentResolver
	Safety              SafetyGate
	Credentials         CredentialBroker
	Policy              PreExecutionPolicy
	Executors           Executors
}

type Options struct {
	RunnerID          string
	LeaseDuration     time.Duration
	HeartbeatInterval time.Duration
	FinalizeTimeout   time.Duration
	Clock             func() time.Time
}

type Service struct {
	dependencies      Dependencies
	runnerID          string
	leaseDuration     time.Duration
	heartbeatInterval time.Duration
	finalizeTimeout   time.Duration
	clock             func() time.Time
}

func NewService(dependencies Dependencies, options Options) (*Service, error) {
	if dependencies.Queue == nil || dependencies.RunnerRegistrations == nil || dependencies.Keys == nil ||
		dependencies.Environments == nil || dependencies.Safety == nil ||
		dependencies.Credentials == nil || dependencies.Policy == nil || dependencies.Executors.KubernetesRolloutRestart == nil ||
		dependencies.Executors.KubernetesScale == nil || dependencies.Executors.GitOpsRevert == nil || dependencies.Executors.AWXServiceRestart == nil {
		return nil, fmt.Errorf("all execution trust and typed executor dependencies are required")
	}
	if !validIdentifier(options.RunnerID, 256) || options.LeaseDuration < minimumActionLease || options.LeaseDuration > maximumLease {
		return nil, fmt.Errorf("enabled write runner registration with exact scope bindings and bounded lease duration is required")
	}
	if options.FinalizeTimeout == 0 {
		options.FinalizeTimeout = 5 * time.Second
	}
	if options.FinalizeTimeout < 0 || options.FinalizeTimeout > maximumFinalize {
		return nil, fmt.Errorf("finalize timeout must be at most 30 seconds")
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	if options.HeartbeatInterval == 0 {
		options.HeartbeatInterval = options.LeaseDuration / 3
	}
	if options.HeartbeatInterval <= 0 || options.HeartbeatInterval > options.LeaseDuration/3 {
		return nil, fmt.Errorf("heartbeat interval must be positive and at most one third of the lease duration")
	}
	if options.Clock().IsZero() {
		return nil, fmt.Errorf("execution clock returned zero time")
	}
	return &Service{
		dependencies:  dependencies,
		runnerID:      options.RunnerID,
		leaseDuration: options.LeaseDuration, heartbeatInterval: options.HeartbeatInterval, finalizeTimeout: options.FinalizeTimeout,
		clock: options.Clock,
	}, nil
}

// Submit accepts only a signed ActionEnvelope. Queue classification and target
// serialization are derived from trusted state and cannot be supplied by a caller.
func (service *Service) Submit(ctx context.Context, envelope action.Envelope) (executionlease.Execution, error) {
	if err := ctx.Err(); err != nil {
		return executionlease.Execution{}, err
	}
	now, err := service.now()
	if err != nil {
		return executionlease.Execution{}, err
	}
	if err := action.Verify(ctx, envelope, service.dependencies.Keys, now); err != nil {
		return executionlease.Execution{}, fmt.Errorf("%w: %v", ErrInvalidAction, err)
	}
	runnerScope, err := service.resolveRunnerScope(ctx)
	if err != nil {
		return executionlease.Execution{}, err
	}
	if !runnerScope.allows(envelope.WorkspaceID, envelope.Target.EnvironmentID) {
		return executionlease.Execution{}, ErrEnvironmentNotAllowed
	}
	environment, err := service.resolveEnvironment(ctx, envelope)
	if err != nil {
		return executionlease.Execution{}, err
	}
	targetKey, err := deriveTargetKey(envelope)
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("%w: %v", ErrInvalidAction, err)
	}
	return service.dependencies.Queue.Submit(ctx, ActionSubmission{
		Envelope: envelope, PlanHash: envelope.PlanHash, TargetKey: targetKey,
		EnvironmentRevision: environment.Revision, Production: environment.Production, Pool: executionlease.PoolWrite,
	})
}

// RunNext runs one write job. ClaimsEnabled, queue pool, target key, and the
// production bit are all internal values derived from trusted dependencies.
func (service *Service) RunNext(ctx context.Context) (executionlease.Execution, error) {
	runnerScope, err := service.resolveRunnerScope(ctx)
	if err != nil {
		return executionlease.Execution{}, err
	}
	if _, err := service.checkSafety(ctx, SafetyRequest{
		Phase: SafetyPhaseClaim, Pool: executionlease.PoolWrite, RunnerID: runnerScope.runnerID,
	}); err != nil {
		return executionlease.Execution{}, err
	}
	claimed, err := service.dependencies.Queue.Claim(ctx, ActionClaimRequest{
		Scope: runnerScope, LeaseDuration: service.leaseDuration,
	})
	if err != nil {
		return executionlease.Execution{}, err
	}
	leased := claimed.Execution
	envelope := claimed.Envelope
	// A Claim response is not trusted merely because it came from the queue.
	// Fail closed before parsing or verifying its envelope, and do not Reject or
	// Nack it here: either operation would release a target fence selected by
	// unverified metadata. Expiry recovery owns that decision.
	if leased.ExecutionID != envelope.ActionID || leased.TargetKey != claimed.TargetKey ||
		leased.Pool != executionlease.PoolWrite || leased.Production != claimed.Production ||
		claimed.PlanHash != envelope.PlanHash || leased.Production || leased.RunnerID != runnerScope.runnerID ||
		leased.RunnerTenantID != runnerScope.tenantID || leased.RunnerWorkspaceID != envelope.WorkspaceID ||
		leased.RunnerEnvironmentID != envelope.Target.EnvironmentID || leased.ScopeRevision != runnerScope.scopeRevision ||
		!runnerScope.allows(envelope.WorkspaceID, envelope.Target.EnvironmentID) {
		return redactActionExecution(leased), ErrJobConflict
	}
	leaseFence := leased.Fence()
	now, err := service.now()
	if err != nil {
		return service.nackClaim(ctx, claimed, "CLOCK_TEMPORARILY_UNAVAILABLE", err)
	}
	if err := action.Verify(ctx, envelope, service.dependencies.Keys, now); err != nil {
		return service.rejectClaim(ctx, claimed, "INVALID_VERIFIED_ACTION", fmt.Errorf("%w: %v", ErrInvalidAction, err))
	}
	if leased.ExecutionID != envelope.ActionID || leased.TargetKey != claimed.TargetKey || leased.Pool != executionlease.PoolWrite ||
		leased.Production != claimed.Production || claimed.PlanHash != envelope.PlanHash {
		return service.rejectClaim(ctx, claimed, "QUEUE_METADATA_CONFLICT", ErrJobConflict)
	}
	environment, err := service.resolveEnvironment(ctx, envelope)
	if err != nil {
		return service.nackClaim(ctx, claimed, "ENVIRONMENT_TEMPORARILY_UNAVAILABLE", err)
	}
	if environment.Revision != claimed.EnvironmentRevision || environment.Production != claimed.Production {
		return service.rejectClaim(ctx, claimed, "ENVIRONMENT_DRIFT", ErrEnvironmentDrift)
	}

	credentialDecision, err := service.dependencies.Policy.EvaluateCredentialIssue(ctx, envelope)
	if err != nil {
		if ctx.Err() != nil {
			return service.nackClaim(ctx, claimed, "CREDENTIAL_POLICY_CANCELLED", ctx.Err())
		}
		return service.nackClaim(ctx, claimed, "CREDENTIAL_POLICY_TEMPORARILY_UNAVAILABLE", ErrCredentialDenied)
	}
	now, err = service.now()
	if err != nil {
		return service.nackClaim(ctx, claimed, "CLOCK_TEMPORARILY_UNAVAILABLE", err)
	}
	if !validCredentialIssueDecision(credentialDecision, envelope, now) {
		return service.rejectClaim(ctx, claimed, "CREDENTIAL_POLICY_DENIED", ErrCredentialDenied)
	}

	decision, err := service.dependencies.Policy.EvaluatePreExecution(ctx, envelope)
	if err != nil {
		if ctx.Err() != nil {
			return service.nackClaim(ctx, claimed, "PRE_EXECUTION_CANCELLED", ctx.Err())
		}
		return service.nackClaim(ctx, claimed, "POLICY_TEMPORARILY_UNAVAILABLE", ErrPreExecutionDenied)
	}
	now, err = service.now()
	if err != nil {
		return service.nackClaim(ctx, claimed, "CLOCK_TEMPORARILY_UNAVAILABLE", err)
	}
	if !validPreExecutionDecision(decision, envelope, now) || !samePolicySnapshot(credentialDecision, decision) {
		return service.rejectClaim(ctx, claimed, "PRE_EXECUTION_POLICY_DENIED", ErrPreExecutionDenied)
	}
	startSafety, err := service.checkSafety(ctx, SafetyRequest{
		Phase: SafetyPhaseStart, Pool: executionlease.PoolWrite, RunnerID: runnerScope.runnerID,
		WorkspaceID: envelope.WorkspaceID, EnvironmentID: envelope.Target.EnvironmentID,
		ConnectorID: envelope.CredentialScope.ConnectorID, ActionType: envelope.ActionType,
	})
	if err != nil || startSafety.Revision != decision.SafetyRevision || startSafety.Revision != credentialDecision.SafetyRevision {
		if err == nil {
			err = ErrClaimsDisabled
		}
		return service.nackClaim(ctx, claimed, "SAFETY_TEMPORARILY_DISABLED", err)
	}
	finalEnvironment, err := service.resolveEnvironment(ctx, envelope)
	if err != nil {
		return service.nackClaim(ctx, claimed, "ENVIRONMENT_TEMPORARILY_UNAVAILABLE", err)
	}
	if finalEnvironment.Revision != claimed.EnvironmentRevision || finalEnvironment.Production != claimed.Production {
		return service.rejectClaim(ctx, claimed, "ENVIRONMENT_DRIFT", ErrEnvironmentDrift)
	}
	now, err = service.now()
	if err != nil {
		return service.nackClaim(ctx, claimed, "CLOCK_TEMPORARILY_UNAVAILABLE", err)
	}
	if !fresh(now, startSafety.ObservedAt, MaxSafetySnapshotAge) ||
		!validPreExecutionDecision(decision, envelope, now) ||
		!validCredentialIssueDecision(credentialDecision, envelope, now) || !samePolicySnapshot(credentialDecision, decision) {
		return service.nackClaim(ctx, claimed, "PRE_START_STATE_EXPIRED", ErrClaimsDisabled)
	}
	executorDeadline, err := boundedExecutionDeadline(ctx, envelope, credentialDecision.CredentialExpiresAt, now)
	if err != nil {
		return service.rejectClaim(ctx, claimed, "EXECUTION_DEADLINE_EXPIRED", ErrPreExecutionDenied)
	}
	credentialFence := credential.ActionFence{
		ActionID: leaseFence.ExecutionID, RunnerID: leaseFence.RunnerID, Token: leaseFence.Token, Epoch: leaseFence.Epoch,
	}
	prepared, err := service.dependencies.Credentials.Prepare(ctx, credential.PrepareDurableCredentialRequest{
		Fence: credentialFence,
		Selection: credential.DurableIssuerResolveRequest{
			TenantID: runnerScope.tenantID, WorkspaceID: envelope.WorkspaceID,
			EnvironmentID: envelope.Target.EnvironmentID, Production: claimed.Production,
			ActionType: string(envelope.ActionType), ConnectorID: envelope.CredentialScope.ConnectorID,
			Permission: envelope.CredentialScope.Permission, Resource: envelope.CredentialScope.Resource,
		},
		RequestedTTL:    time.Duration(envelope.CredentialScope.TTLSeconds) * time.Second,
		PolicyExpiresAt: credentialDecision.CredentialExpiresAt,
	})
	if err != nil {
		// Prepare may have committed even when its response was lost. Never release
		// the target fence on an ambiguous durable-authorization boundary.
		return redactActionExecution(leased), errors.Join(ErrCredentialDenied, err)
	}
	started, err := service.dependencies.Queue.Start(ctx, leaseFence)
	if err != nil {
		noCredentialErr := service.recordNoCredential(ctx, prepared)
		return redactActionExecution(leased), errors.Join(err, noCredentialErr)
	}
	if heartbeatErr := service.heartbeatOnce(ctx, runnerScope, leaseFence, 1); heartbeatErr != nil {
		noCredentialErr := service.recordNoCredential(ctx, prepared)
		return redactActionExecution(started), errors.Join(ErrExecutionUncertain, heartbeatErr, noCredentialErr)
	}

	// Convert the trusted wall-clock deadline to a duration before handing it to
	// context, whose timer is based on the process clock. This keeps injected
	// clocks deterministic and avoids treating a valid simulated deadline as
	// already expired in real wall time.
	localExecutorObservedAt := time.Now()
	now, err = service.now()
	if err != nil || !executorDeadline.After(now) {
		noCredentialErr := service.recordNoCredential(ctx, prepared)
		if err == nil {
			err = ErrPreExecutionDenied
		}
		return redactActionExecution(started), errors.Join(ErrExecutionUncertain, err, noCredentialErr)
	}
	localExecutorDeadline, validExecutorDeadline := mappedExecutionDeadline(
		executorDeadline, now, localExecutorObservedAt,
	)
	if !validExecutorDeadline {
		noCredentialErr := service.recordNoCredential(ctx, prepared)
		return redactActionExecution(started), errors.Join(ErrExecutionUncertain, ErrPreExecutionDenied, noCredentialErr)
	}
	executorContext, cancelExecutor := context.WithDeadline(ctx, localExecutorDeadline)
	defer cancelExecutor()
	heartbeats := service.startHeartbeatSession(executorContext, cancelExecutor, runnerScope, leaseFence, 2)

	var executionCredential credential.DurableCredential
	credentialIssued := false
	revocationAttempted := false
	requestRevocation := func() (credential.Revocation, error) {
		if !credentialIssued {
			return credential.Revocation{}, nil
		}
		revocationAttempted = true
		finalizeContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), service.finalizeTimeout)
		defer cancel()
		revocation, requestErr := service.dependencies.Credentials.RequestRevocation(finalizeContext, executionCredential)
		executionCredential.Destroy()
		return revocation, requestErr
	}
	defer func() {
		if credentialIssued && !revocationAttempted {
			_, _ = requestRevocation()
		}
		executionCredential.Destroy()
	}()

	executionCredential, err = service.dependencies.Credentials.Issue(executorContext, prepared)
	if err == nil {
		credentialIssued = true
	}
	executionContext := executorContext
	var executorResult ExecutorResult
	var executorErr error
	if err != nil {
		executorErr = ErrCredentialDenied
	} else {
		localIssueObservedAt := time.Now()
		issueNow, clockErr := service.now()
		if clockErr != nil || !validDurableCredential(
			executionCredential, envelope, credentialDecision.CredentialExpiresAt, issueNow,
		) {
			executorErr = ErrCredentialDenied
		} else if localCredentialDeadline, validCredentialDeadline := mappedExecutionDeadline(
			executionCredential.ExpiresAt(), issueNow, localIssueObservedAt,
		); !validCredentialDeadline {
			executorErr = ErrCredentialDenied
		} else {
			credentialExecutionContext, cancelCredentialDeadline := context.WithDeadline(
				executorContext, localCredentialDeadline,
			)
			executionContext = credentialExecutionContext
			defer cancelCredentialDeadline()
			// Keep the original supervisor and sequence alive through Complete, but
			// cancel it if the shorter dynamic credential lifetime expires first.
			stopCredentialDeadline := context.AfterFunc(executionContext, cancelExecutor)
			defer stopCredentialDeadline()
			if heartbeatErr := heartbeats.Checkpoint(executionContext); heartbeatErr != nil {
				executorErr = heartbeatErr
			} else {
				executorResult, executorErr = service.dispatchWithHeartbeat(
					executionContext, heartbeats, envelope, executionCredential,
				)
			}
		}
	}
	// Keep the session alive after the executor returns. This checkpoint
	// linearizes lease validity before the result receipt, while periodic
	// heartbeats continue until Complete is acknowledged.
	if heartbeatErr := heartbeats.Checkpoint(executionContext); heartbeatErr != nil {
		executorResult = ExecutorResult{}
		executorErr = heartbeatErr
	}
	_, summary := classifyResult(executorResult, executorErr)
	completeContext, cancelComplete := context.WithTimeout(context.WithoutCancel(ctx), service.finalizeTimeout)
	finalizing, completeErr := service.dependencies.Queue.Complete(completeContext, ActionCompleteRequest{
		Lease: leaseFence, Summary: summary,
	})
	cancelComplete()
	if completeErr == nil {
		heartbeats.AcknowledgeComplete()
	}
	heartbeatErr := heartbeats.Stop()
	if completeErr != nil {
		_, cleanupErr := requestRevocation()
		return redactActionExecution(started), errors.Join(ErrExecutionUncertain, completeErr, heartbeatErr, cleanupErr)
	}
	revocation, cleanupErr := requestRevocation()
	if cleanupErr != nil {
		return finalizing, errors.Join(ErrCredentialCleanupPending, cleanupErr)
	}
	completionStatus, _ := ResultSummaryStatus(summary)
	if completionStatus != executionlease.StatusUncertain && credentialIssued && !revocation.Terminal() {
		return finalizing, ErrCredentialCleanupPending
	}
	finalizeContext, cancelFinalize := context.WithTimeout(context.WithoutCancel(ctx), service.finalizeTimeout)
	completed, finalizeErr := service.dependencies.Queue.Finalize(finalizeContext, leaseFence)
	cancelFinalize()
	if finalizeErr != nil {
		if errors.Is(finalizeErr, ErrCredentialCleanupPending) {
			return finalizing, ErrCredentialCleanupPending
		}
		return finalizing, errors.Join(ErrExecutionUncertain, finalizeErr)
	}
	switch completed.Status {
	case executionlease.StatusFailed:
		return completed, ErrExecutionFailed
	case executionlease.StatusUncertain:
		return completed, ErrExecutionUncertain
	default:
		return completed, nil
	}
}

func (service *Service) checkSafety(ctx context.Context, request SafetyRequest) (ClaimSafetySnapshot, error) {
	snapshot, err := service.dependencies.Safety.Evaluate(ctx, request)
	if err != nil {
		return ClaimSafetySnapshot{}, ErrClaimsDisabled
	}
	now, err := service.now()
	if err != nil || !snapshot.Enabled || !validIdentifier(snapshot.Revision, 256) ||
		!fresh(now, snapshot.ObservedAt, MaxSafetySnapshotAge) || snapshot.Pool != request.Pool || snapshot.RunnerID != request.RunnerID {
		return ClaimSafetySnapshot{}, ErrClaimsDisabled
	}
	if request.Phase == SafetyPhaseClaim {
		if snapshot.WorkspaceID != "" || snapshot.EnvironmentID != "" || snapshot.ConnectorID != "" || snapshot.ActionType != "" {
			return ClaimSafetySnapshot{}, ErrClaimsDisabled
		}
		return snapshot, nil
	}
	if request.Phase != SafetyPhaseStart || snapshot.WorkspaceID != request.WorkspaceID || snapshot.EnvironmentID != request.EnvironmentID ||
		snapshot.ConnectorID != request.ConnectorID || snapshot.ActionType != request.ActionType {
		return ClaimSafetySnapshot{}, ErrClaimsDisabled
	}
	return snapshot, nil
}

func (service *Service) resolveEnvironment(ctx context.Context, envelope action.Envelope) (EnvironmentSnapshot, error) {
	snapshot, err := service.dependencies.Environments.Resolve(ctx, envelope.WorkspaceID, envelope.Target.EnvironmentID)
	if err != nil {
		return EnvironmentSnapshot{}, ErrEnvironmentUnavailable
	}
	now, clockErr := service.now()
	if clockErr != nil || snapshot.WorkspaceID != envelope.WorkspaceID || snapshot.EnvironmentID != envelope.Target.EnvironmentID ||
		!validIdentifier(snapshot.Revision, 256) || !fresh(now, snapshot.ObservedAt, MaxEnvironmentSnapshotAge) {
		return EnvironmentSnapshot{}, ErrEnvironmentUnavailable
	}
	return snapshot, nil
}

func (service *Service) resolveRunnerScope(ctx context.Context) (RunnerScope, error) {
	registration, err := service.dependencies.RunnerRegistrations.Resolve(ctx, service.runnerID)
	if err != nil {
		return RunnerScope{}, ErrClaimsDisabled
	}
	scope, err := registration.Scope()
	if err != nil || scope.pool != executionlease.PoolWrite || scope.runnerID != service.runnerID {
		return RunnerScope{}, ErrClaimsDisabled
	}
	return scope, nil
}

func (service *Service) rejectClaim(ctx context.Context, claimed ClaimedAction, code string, cause error) (executionlease.Execution, error) {
	finalizeContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), service.finalizeTimeout)
	defer cancel()
	rejected, err := service.dependencies.Queue.Reject(finalizeContext, ActionRejectRequest{
		Lease: claimed.Execution.Fence(), Reason: queueReason(code),
	})
	if err != nil {
		return redactActionExecution(claimed.Execution), err
	}
	return rejected, cause
}

func (service *Service) nackClaim(ctx context.Context, claimed ClaimedAction, code string, cause error) (executionlease.Execution, error) {
	finalizeContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), service.finalizeTimeout)
	defer cancel()
	released, err := service.dependencies.Queue.Nack(finalizeContext, ActionNackRequest{
		Lease: claimed.Execution.Fence(), Reason: queueReason(code), RetryAfter: 15 * time.Second,
	})
	if err != nil {
		return redactActionExecution(claimed.Execution), err
	}
	return released, cause
}

func (service *Service) recordNoCredential(
	ctx context.Context,
	prepared credential.PreparedDurableCredential,
) error {
	finalizeContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), service.finalizeTimeout)
	defer cancel()
	revocation, err := service.dependencies.Credentials.RecordNoCredential(finalizeContext, prepared)
	if err != nil {
		return err
	}
	if revocation.Status != credential.StatusNoCredential || !revocation.Terminal() {
		return ErrCredentialCleanupPending
	}
	return nil
}

func queueReason(code string) ActionQueueReason {
	digest := sha256.Sum256([]byte("aiops-action-queue-reason-detail.v1\x00" + code))
	return ActionQueueReason{Code: code, DetailHash: hex.EncodeToString(digest[:])}
}

func (service *Service) now() (time.Time, error) {
	now := service.clock().UTC()
	if now.IsZero() {
		return time.Time{}, fmt.Errorf("execution clock returned zero time")
	}
	return now, nil
}

func deriveTargetKey(envelope action.Envelope) (string, error) {
	if err := envelope.Validate(); err != nil {
		return "", err
	}
	var kind string
	var identity any
	switch envelope.ActionType {
	case action.ActionKubernetesRolloutRestart, action.ActionKubernetesScale:
		target := envelope.Target.KubernetesDeployment
		kind = "k8s-deployment"
		identity = struct {
			WorkspaceID, EnvironmentID, ClusterID, Namespace, Name, UID string
		}{envelope.WorkspaceID, envelope.Target.EnvironmentID, target.ClusterID, target.Namespace, target.Name, target.UID}
	case action.ActionGitOpsRevert:
		target := envelope.Target.GitOpsApplication
		kind = "gitops-application-path"
		identity = struct {
			WorkspaceID, EnvironmentID, RepositoryID, Application, Path string
		}{envelope.WorkspaceID, envelope.Target.EnvironmentID, target.RepositoryID, target.Application, target.Path}
	case action.ActionAWXServiceRestart:
		kind = "awx-inventory"
		identity = struct {
			WorkspaceID, EnvironmentID string
			InventoryID                int64
		}{envelope.WorkspaceID, envelope.Target.EnvironmentID, envelope.Target.AWXHosts.InventoryID}
	default:
		return "", fmt.Errorf("unsupported action type %q", envelope.ActionType)
	}
	encoded, err := json.Marshal(identity)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte("aiops-target-lock.v1\x00"+kind+"\x00"), encoded...))
	return kind + ":sha256:" + hex.EncodeToString(digest[:]), nil
}

func (service *Service) dispatchSafely(
	ctx context.Context,
	envelope action.Envelope,
	executionCredential credential.DurableCredential,
	dispatchEntered chan<- struct{},
) (result ExecutorResult, err error) {
	defer func() {
		if recover() != nil {
			result = ExecutorResult{}
			err = errors.New("typed executor panicked")
		}
	}()
	identity := CommandIdentity{
		ActionID: envelope.ActionID, WorkspaceID: envelope.WorkspaceID, IncidentID: envelope.IncidentID,
		ServiceID: envelope.Target.ServiceID, EnvironmentID: envelope.Target.EnvironmentID, TraceID: envelope.TraceID,
	}
	if dispatchEntered != nil {
		close(dispatchEntered)
	}
	switch envelope.ActionType {
	case action.ActionKubernetesRolloutRestart:
		return service.dependencies.Executors.KubernetesRolloutRestart.ExecuteRolloutRestart(ctx, KubernetesRolloutRestartCommand{
			Identity: identity, Target: *envelope.Target.KubernetesDeployment,
			Parameters: *envelope.Parameters.KubernetesRolloutRestart, ObservedState: *envelope.ObservedState.KubernetesDeployment,
			Preconditions: envelope.Preconditions, Verification: envelope.Verification,
		}, executionCredential)
	case action.ActionKubernetesScale:
		return service.dependencies.Executors.KubernetesScale.ExecuteScale(ctx, KubernetesScaleCommand{
			Identity: identity, Target: *envelope.Target.KubernetesDeployment,
			Parameters: *envelope.Parameters.KubernetesScale, ObservedState: *envelope.ObservedState.KubernetesDeployment,
			Preconditions: envelope.Preconditions, Verification: envelope.Verification,
		}, executionCredential)
	case action.ActionGitOpsRevert:
		return service.dependencies.Executors.GitOpsRevert.ExecuteGitOpsRevert(ctx, GitOpsRevertCommand{
			Identity: identity, Target: *envelope.Target.GitOpsApplication,
			Parameters: *envelope.Parameters.GitOpsRevert, ObservedState: *envelope.ObservedState.GitOpsApplication,
			Preconditions: envelope.Preconditions, Verification: envelope.Verification,
		}, executionCredential)
	case action.ActionAWXServiceRestart:
		target := *envelope.Target.AWXHosts
		target.HostIDs = slices.Clone(target.HostIDs)
		return service.dependencies.Executors.AWXServiceRestart.ExecuteAWXServiceRestart(ctx, AWXServiceRestartCommand{
			Identity: identity, Target: target,
			Parameters: *envelope.Parameters.AWXServiceRestart, ObservedState: *envelope.ObservedState.AWXService,
			Preconditions: envelope.Preconditions, Verification: envelope.Verification,
		}, executionCredential)
	default:
		return ExecutorResult{}, errors.New("unsupported typed action")
	}
}

func (service *Service) dispatchWithHeartbeat(
	ctx context.Context,
	heartbeats *actionHeartbeatSession,
	envelope action.Envelope,
	executionCredential credential.DurableCredential,
) (ExecutorResult, error) {
	type executorCompletion struct {
		result ExecutorResult
		err    error
	}
	executorDone := make(chan executorCompletion, 1)
	dispatchEntered := make(chan struct{})
	// Serialize the final failure check with every heartbeat checkpoint. Once
	// dispatchSafely signals entry, a later heartbeat loss cancels an execution
	// that was legitimately started; an already-observed loss can never race
	// through this gate and start the executor.
	heartbeats.beatMu.Lock()
	if dispatchErr := heartbeats.DispatchError(ctx); dispatchErr != nil {
		heartbeats.beatMu.Unlock()
		return ExecutorResult{}, dispatchErr
	}
	go func() {
		result, err := service.dispatchSafely(ctx, envelope, executionCredential, dispatchEntered)
		executorDone <- executorCompletion{result: result, err: err}
	}()
	<-dispatchEntered
	heartbeats.beatMu.Unlock()

	select {
	case completed := <-executorDone:
		if deadlineErr := ctx.Err(); deadlineErr != nil {
			return ExecutorResult{}, deadlineErr
		}
		if heartbeatErr := heartbeats.Failure(); heartbeatErr != nil {
			return ExecutorResult{}, heartbeatErr
		}
		return completed.result, completed.err
	case <-heartbeats.Done():
		heartbeatErr := heartbeats.Failure()
		if heartbeatErr == nil {
			heartbeatErr = ctx.Err()
		}
		if heartbeatErr == nil {
			heartbeatErr = ErrExecutionUncertain
		}
		return ExecutorResult{}, heartbeatErr
	case <-ctx.Done():
		return ExecutorResult{}, errors.Join(ctx.Err(), heartbeats.Failure())
	}
}

type actionHeartbeatSession struct {
	mu              sync.Mutex
	beatMu          sync.Mutex
	stop            context.CancelFunc
	cancelExecution context.CancelFunc
	done            chan struct{}
	failure         error
	completeAcked   bool
	service         *Service
	claimedScope    RunnerScope
	lease           executionlease.LeaseIdentity
	nextSequence    int64
}

func (service *Service) startHeartbeatSession(
	ctx context.Context,
	cancelExecution context.CancelFunc,
	claimedScope RunnerScope,
	lease executionlease.LeaseIdentity,
	firstSequence int64,
) *actionHeartbeatSession {
	heartbeatContext, stop := context.WithCancel(ctx)
	session := &actionHeartbeatSession{
		stop: stop, cancelExecution: cancelExecution, done: make(chan struct{}),
		service: service, claimedScope: claimedScope, lease: lease, nextSequence: firstSequence,
	}
	go service.heartbeatLoop(heartbeatContext, session)
	return session
}

func (service *Service) heartbeatLoop(
	ctx context.Context,
	session *actionHeartbeatSession,
) {
	defer close(session.done)
	ticker := time.NewTicker(service.heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := session.checkpoint(ctx); err != nil {
				if ctx.Err() != nil {
					return
				}
				return
			}
		}
	}
}

func (service *Service) heartbeatOnce(
	ctx context.Context,
	claimedScope RunnerScope,
	lease executionlease.LeaseIdentity,
	sequence int64,
) error {
	timeout := service.heartbeatInterval
	if timeout > service.finalizeTimeout {
		timeout = service.finalizeTimeout
	}
	heartbeatContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	currentScope, scopeErr := service.resolveRunnerScope(heartbeatContext)
	if scopeErr != nil {
		if heartbeatContext.Err() != nil {
			return heartbeatContext.Err()
		}
		return ErrExecutionUncertain
	}
	if currentScope.runnerID != claimedScope.runnerID || currentScope.tenantID != claimedScope.tenantID ||
		currentScope.pool != claimedScope.pool || currentScope.scopeRevision != claimedScope.scopeRevision {
		return ErrExecutionUncertain
	}
	response, err := service.dependencies.Queue.Heartbeat(heartbeatContext, ActionHeartbeatRequest{
		Lease: lease, Sequence: sequence, Extension: service.leaseDuration,
	})
	if err != nil {
		return err
	}
	if response.Directive != HeartbeatContinue || response.Execution.ExecutionID != lease.ExecutionID ||
		response.Execution.RunnerID != lease.RunnerID || response.Execution.LeaseEpoch != lease.Epoch ||
		response.Execution.ScopeRevision != claimedScope.scopeRevision || response.Execution.Status != executionlease.StatusRunning {
		return ErrExecutionUncertain
	}
	return nil
}

func (session *actionHeartbeatSession) fail(err error) {
	if err == nil {
		err = ErrExecutionUncertain
	}
	session.mu.Lock()
	if session.failure == nil && !session.completeAcked {
		session.failure = err
		session.cancelExecution()
	}
	session.mu.Unlock()
}

func (session *actionHeartbeatSession) checkpoint(ctx context.Context) error {
	session.beatMu.Lock()
	defer session.beatMu.Unlock()
	if err := session.DispatchError(ctx); err != nil {
		return err
	}
	sequence := session.nextSequence
	if err := session.service.heartbeatOnce(ctx, session.claimedScope, session.lease, sequence); err != nil {
		if ctx.Err() == nil {
			session.fail(err)
		}
		return err
	}
	session.mu.Lock()
	session.nextSequence++
	session.mu.Unlock()
	return nil
}

func (session *actionHeartbeatSession) Checkpoint(ctx context.Context) error {
	return session.checkpoint(ctx)
}

func (session *actionHeartbeatSession) DispatchError(ctx context.Context) error {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.failure != nil {
		return session.failure
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func (session *actionHeartbeatSession) Failure() error {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.failure
}

func (session *actionHeartbeatSession) AcknowledgeComplete() {
	session.mu.Lock()
	session.completeAcked = true
	// A successful Complete ACK is the authoritative fence/result decision.
	// Ignore a heartbeat that raced with the RUNNING -> FINALIZING commit.
	session.failure = nil
	session.mu.Unlock()
}

func (session *actionHeartbeatSession) Done() <-chan struct{} { return session.done }

func (session *actionHeartbeatSession) Stop() error {
	session.stop()
	<-session.done
	return session.Failure()
}

func classifyResult(result ExecutorResult, executorErr error) (executionlease.Status, ExecutorResult) {
	if executorErr != nil {
		return executionlease.StatusUncertain, ExecutorResult{Outcome: ExecutorUncertain, Code: "EXECUTOR_OUTCOME_UNKNOWN", Verification: VerificationUnknown}
	}
	if !validExecutorResult(result) {
		return executionlease.StatusUncertain, ExecutorResult{Outcome: ExecutorUncertain, Code: "INVALID_EXECUTOR_RESULT", Verification: VerificationUnknown}
	}
	switch result.Outcome {
	case ExecutorSucceeded:
		return executionlease.StatusSucceeded, result
	case ExecutorFailed:
		return executionlease.StatusFailed, result
	default:
		return executionlease.StatusUncertain, result
	}
}

var (
	resultCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]*\z`)
)

func validExecutorResult(result ExecutorResult) bool {
	if !resultCodePattern.MatchString(result.Code) ||
		(result.ExternalOperationRefHash != "" && !actionQueueSHA256Pattern.MatchString(result.ExternalOperationRefHash)) {
		return false
	}
	switch result.Outcome {
	case ExecutorSucceeded:
		return result.Verification == VerificationPassed
	case ExecutorFailed:
		return result.Verification == VerificationFailed
	case ExecutorUncertain:
		return result.Verification == VerificationUnknown
	default:
		return false
	}
}

func boundedExecutionDeadline(ctx context.Context, envelope action.Envelope, credentialExpiresAt time.Time, now time.Time) (time.Time, error) {
	deadline := now.Add(time.Duration(envelope.Verification.TimeoutSeconds) * time.Second)
	for _, candidate := range []time.Time{envelope.ExpiresAt, credentialExpiresAt} {
		if candidate.Before(deadline) {
			deadline = candidate
		}
	}
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if !deadline.After(now) {
		return time.Time{}, ErrPreExecutionDenied
	}
	return deadline, nil
}

// mappedExecutionDeadline maps a trusted logical deadline onto an already
// observed local monotonic instant. Capturing localObservedAt before reading the
// logical clock makes clock-read latency conservative, and WithDeadline cannot
// move the resulting boundary later after a scheduler or GC pause. Production
// uses time.Now for both clocks; tests may supply a coherent simulated logical
// clock without turning a valid simulated deadline into an already-expired wall
// timestamp.
func mappedExecutionDeadline(deadline, logicalObservedAt, localObservedAt time.Time) (time.Time, bool) {
	if deadline.IsZero() || logicalObservedAt.IsZero() || localObservedAt.IsZero() {
		return time.Time{}, false
	}
	remaining := deadline.Sub(logicalObservedAt)
	if remaining <= 0 {
		return time.Time{}, false
	}
	return localObservedAt.Add(remaining), true
}

func validDurableCredential(
	value credential.DurableCredential,
	envelope action.Envelope,
	policyExpiresAt time.Time,
	now time.Time,
) bool {
	secret := value.Secret()
	defer clear(secret)
	expiresAt := value.ExpiresAt()
	return credential.ValidRevocationID(value.RevocationID()) && len(secret) > 0 && len(secret) <= credential.MaxSensitiveValueSize &&
		expiresAt.After(now) && !expiresAt.After(policyExpiresAt) && !expiresAt.After(envelope.ExpiresAt)
}

func validCredentialIssueDecision(decision policy.Decision, envelope action.Envelope, now time.Time) bool {
	requestedTTL := time.Duration(envelope.CredentialScope.TTLSeconds) * time.Second
	signedCredentialDeadline := decision.EvaluatedAt.Add(requestedTTL)
	if envelope.ExpiresAt.Before(signedCredentialDeadline) {
		signedCredentialDeadline = envelope.ExpiresAt
	}
	return decision.Outcome == policy.OutcomeAllow && decision.Stage == policy.StageCredentialIssue &&
		decision.PolicyVersion == envelope.PolicyVersion && decision.PlanHash == envelope.PlanHash &&
		decision.SafetyRevision != "" && decision.TargetRevision != "" && decision.RiskRevision != "" &&
		decision.LimitsRevision != "" && !decision.EvaluatedAt.IsZero() &&
		!decision.EvaluatedAt.After(now.Add(maximumClockSkew)) && now.Sub(decision.EvaluatedAt) <= MaxPreExecutionDecisionAge &&
		decision.CredentialExpiresAt.After(now) && !decision.CredentialExpiresAt.After(signedCredentialDeadline)
}

func samePolicySnapshot(credentialDecision, preExecutionDecision policy.Decision) bool {
	return credentialDecision.PolicyVersion == preExecutionDecision.PolicyVersion &&
		credentialDecision.PlanHash == preExecutionDecision.PlanHash &&
		credentialDecision.SafetyRevision == preExecutionDecision.SafetyRevision &&
		credentialDecision.TargetRevision == preExecutionDecision.TargetRevision &&
		credentialDecision.RiskRevision == preExecutionDecision.RiskRevision &&
		credentialDecision.LimitsRevision == preExecutionDecision.LimitsRevision
}

func validPreExecutionDecision(decision policy.Decision, envelope action.Envelope, now time.Time) bool {
	return decision.Outcome == policy.OutcomeAllow && decision.Stage == policy.StagePreExecution &&
		decision.PolicyVersion == envelope.PolicyVersion && decision.PlanHash == envelope.PlanHash &&
		decision.SafetyRevision != "" && decision.TargetRevision != "" && decision.RiskRevision != "" && decision.LimitsRevision != "" &&
		!decision.EvaluatedAt.IsZero() && !decision.EvaluatedAt.After(now.Add(maximumClockSkew)) &&
		now.Sub(decision.EvaluatedAt) <= MaxPreExecutionDecisionAge && envelope.ValidateAt(now) == nil
}

func fresh(now, observedAt time.Time, maximumAge time.Duration) bool {
	return !observedAt.IsZero() && !observedAt.After(now.Add(maximumClockSkew)) && now.Sub(observedAt) <= maximumAge
}

func validIdentifier(value string, maximumBytes int) bool {
	return len(value) <= maximumBytes && identifierPattern.MatchString(value)
}

func cloneEnvelope(envelope action.Envelope) action.Envelope {
	cloned := envelope
	cloned.Risk.ReasonCodes = slices.Clone(envelope.Risk.ReasonCodes)
	if envelope.Target.KubernetesDeployment != nil {
		value := *envelope.Target.KubernetesDeployment
		cloned.Target.KubernetesDeployment = &value
	}
	if envelope.Target.GitOpsApplication != nil {
		value := *envelope.Target.GitOpsApplication
		cloned.Target.GitOpsApplication = &value
	}
	if envelope.Target.AWXHosts != nil {
		value := *envelope.Target.AWXHosts
		value.HostIDs = slices.Clone(envelope.Target.AWXHosts.HostIDs)
		cloned.Target.AWXHosts = &value
	}
	if envelope.Parameters.KubernetesRolloutRestart != nil {
		value := *envelope.Parameters.KubernetesRolloutRestart
		cloned.Parameters.KubernetesRolloutRestart = &value
	}
	if envelope.Parameters.KubernetesScale != nil {
		value := *envelope.Parameters.KubernetesScale
		cloned.Parameters.KubernetesScale = &value
	}
	if envelope.Parameters.GitOpsRevert != nil {
		value := *envelope.Parameters.GitOpsRevert
		cloned.Parameters.GitOpsRevert = &value
	}
	if envelope.Parameters.AWXServiceRestart != nil {
		value := *envelope.Parameters.AWXServiceRestart
		cloned.Parameters.AWXServiceRestart = &value
	}
	if envelope.ObservedState.KubernetesDeployment != nil {
		value := *envelope.ObservedState.KubernetesDeployment
		cloned.ObservedState.KubernetesDeployment = &value
	}
	if envelope.ObservedState.GitOpsApplication != nil {
		value := *envelope.ObservedState.GitOpsApplication
		cloned.ObservedState.GitOpsApplication = &value
	}
	if envelope.ObservedState.AWXService != nil {
		value := *envelope.ObservedState.AWXService
		cloned.ObservedState.AWXService = &value
	}
	return cloned
}
