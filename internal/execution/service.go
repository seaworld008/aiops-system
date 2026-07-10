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
	ErrCredentialRevokeFailed = errors.New("execution credential revocation failed")
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
	Issue(context.Context, action.Envelope) (credential.Credential, error)
	Revoke(context.Context, *credential.Credential) error
}

type PreExecutionPolicy interface {
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
	ExecuteRolloutRestart(context.Context, KubernetesRolloutRestartCommand, *credential.Credential) (ExecutorResult, error)
}

type KubernetesScaleExecutor interface {
	ExecuteScale(context.Context, KubernetesScaleCommand, *credential.Credential) (ExecutorResult, error)
}

type GitOpsRevertExecutor interface {
	ExecuteGitOpsRevert(context.Context, GitOpsRevertCommand, *credential.Credential) (ExecutorResult, error)
}

type AWXServiceRestartExecutor interface {
	ExecuteAWXServiceRestart(context.Context, AWXServiceRestartCommand, *credential.Credential) (ExecutorResult, error)
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
func (service *Service) RunNext(ctx context.Context) (result executionlease.Execution, runErr error) {
	var executionCredential credential.Credential
	credentialIssued := false
	revokeCredential := func() error {
		if !credentialIssued {
			return nil
		}
		credentialIssued = false
		finalizeContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), service.finalizeTimeout)
		defer cancel()
		revokeErr := service.dependencies.Credentials.Revoke(finalizeContext, &executionCredential)
		executionCredential.Destroy()
		if revokeErr != nil {
			return fmt.Errorf("%w: %v", ErrCredentialRevokeFailed, revokeErr)
		}
		return nil
	}
	defer func() {
		if revokeErr := revokeCredential(); revokeErr != nil {
			if runErr == nil {
				runErr = revokeErr
			} else {
				runErr = errors.Join(runErr, revokeErr)
			}
		}
	}()
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
	leaseFence := leased.Fence()
	envelope := claimed.Envelope
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

	executionCredential, err = service.dependencies.Credentials.Issue(ctx, envelope)
	if err != nil {
		if errors.Is(err, credential.ErrCredentialDenied) {
			return service.rejectClaim(ctx, claimed, "CREDENTIAL_POLICY_DENIED", ErrCredentialDenied)
		}
		if errors.Is(err, credential.ErrUnsafeCredentialLease) {
			return service.rejectClaim(ctx, claimed, "CREDENTIAL_LEASE_UNSAFE", ErrCredentialDenied)
		}
		return service.nackClaim(ctx, claimed, "CREDENTIAL_TEMPORARILY_UNAVAILABLE", ErrCredentialDenied)
	}
	credentialIssued = true
	if !validCredential(executionCredential, envelope, now) {
		return service.nackClaim(ctx, claimed, "CREDENTIAL_INVALID", ErrCredentialDenied)
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
	if !validPreExecutionDecision(decision, envelope, now) || !executionCredential.ExpiresAt.After(now) {
		return service.rejectClaim(ctx, claimed, "PRE_EXECUTION_POLICY_DENIED", ErrPreExecutionDenied)
	}
	startSafety, err := service.checkSafety(ctx, SafetyRequest{
		Phase: SafetyPhaseStart, Pool: executionlease.PoolWrite, RunnerID: runnerScope.runnerID,
		WorkspaceID: envelope.WorkspaceID, EnvironmentID: envelope.Target.EnvironmentID,
		ConnectorID: envelope.CredentialScope.ConnectorID, ActionType: envelope.ActionType,
	})
	if err != nil || startSafety.Revision != decision.SafetyRevision {
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
		!validPreExecutionDecision(decision, envelope, now) || !executionCredential.ExpiresAt.After(now) {
		return service.nackClaim(ctx, claimed, "PRE_START_STATE_EXPIRED", ErrClaimsDisabled)
	}
	executorDeadline, err := boundedExecutionDeadline(ctx, envelope, executionCredential, now)
	if err != nil {
		return service.rejectClaim(ctx, claimed, "EXECUTION_DEADLINE_EXPIRED", ErrPreExecutionDenied)
	}
	started, err := service.dependencies.Queue.Start(ctx, leaseFence)
	if err != nil {
		return redactActionExecution(leased), err
	}

	// Convert the trusted wall-clock deadline to a duration before handing it to
	// context, whose timer is based on the process clock. This keeps injected
	// clocks deterministic and avoids treating a valid simulated deadline as
	// already expired in real wall time.
	executorContext, cancelExecutor := context.WithTimeout(ctx, executorDeadline.Sub(now))
	defer cancelExecutor()
	executorCredential := executionCredential
	executorResult, executorErr, heartbeatErr := service.dispatchWithHeartbeat(executorContext, runnerScope, leaseFence, envelope, &executorCredential)
	if heartbeatErr != nil {
		executorResult = ExecutorResult{}
		executorErr = heartbeatErr
	}
	_, summary := classifyResult(executorResult, executorErr)
	completeContext, cancelComplete := context.WithTimeout(context.WithoutCancel(ctx), service.finalizeTimeout)
	finalizing, completeErr := service.dependencies.Queue.Complete(completeContext, ActionCompleteRequest{
		Lease: leaseFence, Summary: summary,
	})
	cancelComplete()
	if completeErr != nil {
		return redactActionExecution(started), errors.Join(ErrExecutionUncertain, completeErr)
	}
	if revokeErr := revokeCredential(); revokeErr != nil {
		return finalizing, revokeErr
	}
	finalizeContext, cancelFinalize := context.WithTimeout(context.WithoutCancel(ctx), service.finalizeTimeout)
	completed, finalizeErr := service.dependencies.Queue.Finalize(finalizeContext, leaseFence)
	cancelFinalize()
	if finalizeErr != nil {
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

func (service *Service) dispatchSafely(ctx context.Context, envelope action.Envelope, executionCredential *credential.Credential) (result ExecutorResult, err error) {
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

func (service *Service) dispatchWithHeartbeat(ctx context.Context, runnerScope RunnerScope, leaseFence executionlease.LeaseIdentity, envelope action.Envelope, executionCredential *credential.Credential) (ExecutorResult, error, error) {
	executorContext, cancelExecutor := context.WithCancel(ctx)
	defer cancelExecutor()
	heartbeatContext, stopHeartbeat := context.WithCancel(context.WithoutCancel(ctx))
	defer stopHeartbeat()
	heartbeatDone := make(chan error, 1)
	go service.heartbeatLoop(heartbeatContext, cancelExecutor, runnerScope, leaseFence, heartbeatDone)
	type executorCompletion struct {
		result ExecutorResult
		err    error
	}
	executorDone := make(chan executorCompletion, 1)
	go func() {
		result, err := service.dispatchSafely(executorContext, envelope, executionCredential)
		executorDone <- executorCompletion{result: result, err: err}
	}()

	select {
	case completed := <-executorDone:
		stopHeartbeat()
		heartbeatErr := <-heartbeatDone
		if deadlineErr := ctx.Err(); deadlineErr != nil {
			return ExecutorResult{}, deadlineErr, heartbeatErr
		}
		return completed.result, completed.err, heartbeatErr
	case heartbeatErr := <-heartbeatDone:
		cancelExecutor()
		if heartbeatErr == nil {
			heartbeatErr = ErrExecutionUncertain
		}
		return ExecutorResult{}, heartbeatErr, heartbeatErr
	case <-ctx.Done():
		cancelExecutor()
		stopHeartbeat()
		<-heartbeatDone
		return ExecutorResult{}, ctx.Err(), nil
	}
}

func (service *Service) heartbeatLoop(ctx context.Context, cancelExecutor context.CancelFunc, claimedScope RunnerScope, lease executionlease.LeaseIdentity, done chan<- error) {
	ticker := time.NewTicker(service.heartbeatInterval)
	defer ticker.Stop()
	sequence := int64(1)
	for {
		select {
		case <-ctx.Done():
			done <- nil
			return
		case <-ticker.C:
			currentScope, scopeErr := service.resolveRunnerScope(ctx)
			if scopeErr != nil && ctx.Err() != nil {
				done <- nil
				return
			}
			if scopeErr != nil || currentScope.runnerID != claimedScope.runnerID ||
				currentScope.tenantID != claimedScope.tenantID || currentScope.pool != claimedScope.pool ||
				currentScope.scopeRevision != claimedScope.scopeRevision {
				cancelExecutor()
				done <- ErrExecutionUncertain
				return
			}
			timeout := service.heartbeatInterval
			if timeout > service.finalizeTimeout {
				timeout = service.finalizeTimeout
			}
			heartbeatContext, cancel := context.WithTimeout(ctx, timeout)
			response, err := service.dependencies.Queue.Heartbeat(heartbeatContext, ActionHeartbeatRequest{
				Lease: lease, Sequence: sequence, Extension: service.leaseDuration,
			})
			cancel()
			if err != nil {
				if ctx.Err() != nil {
					done <- nil
					return
				}
				cancelExecutor()
				done <- err
				return
			}
			if response.Directive == HeartbeatTerminate {
				cancelExecutor()
				done <- ErrExecutionUncertain
				return
			}
			sequence++
		}
	}
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
	if !resultCodePattern.MatchString(result.Code) {
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

func boundedExecutionDeadline(ctx context.Context, envelope action.Envelope, executionCredential credential.Credential, now time.Time) (time.Time, error) {
	deadline := now.Add(time.Duration(envelope.Verification.TimeoutSeconds) * time.Second)
	for _, candidate := range []time.Time{envelope.ExpiresAt, executionCredential.ExpiresAt} {
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

func validCredential(value credential.Credential, envelope action.Envelope, now time.Time) bool {
	secret := value.Secret()
	defer clear(secret)
	return validIdentifier(value.LeaseID, 256) && len(secret) > 0 && len(secret) <= 64<<10 &&
		value.ExpiresAt.After(now) && !value.ExpiresAt.After(envelope.ExpiresAt)
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
