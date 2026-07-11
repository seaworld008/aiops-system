package execution

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/seaworld008/aiops-system/internal/action"
	"github.com/seaworld008/aiops-system/internal/executionlease"
)

const (
	minimumActionLease = time.Second
	maximumActionLease = 30 * time.Minute
)

var ErrCredentialCleanupPending = errors.New("action credential cleanup is not terminal")

// ActionSubmission is the immutable, verified action record atomically bound
// to its execution lease. PlanHash is duplicated deliberately so queue
// implementations can enforce the binding without interpreting signatures.
type ActionSubmission struct {
	Envelope            action.Envelope
	PlanHash            string
	TargetKey           string
	EnvironmentRevision string
	Production          bool
	Pool                executionlease.Pool
}

// RunnerScopeBinding grants one exact workspace/environment pair. Keeping the
// pair intact prevents independently supplied allowlists from authorizing their
// Cartesian product.
type RunnerScopeBinding struct {
	WorkspaceID   string
	EnvironmentID string
}

// RunnerRegistration is trusted runner-registry state. M3 will bind this
// snapshot to an mTLS identity; M1 deliberately prevents queue callers from
// constructing RunnerScope directly from request data.
type RunnerRegistration struct {
	RunnerID       string
	TenantID       string
	Pool           executionlease.Pool
	Enabled        bool
	ScopeRevision  int64
	MaxConcurrency int
	ScopeBindings  []RunnerScopeBinding
}

type RunnerRegistrationRepository interface {
	Resolve(context.Context, string) (RunnerRegistration, error)
}

// RunnerScope can only be obtained from a validated registration snapshot.
// Its fields remain private so a job request cannot smuggle its own scope.
type RunnerScope struct {
	runnerID       string
	tenantID       string
	pool           executionlease.Pool
	scopeRevision  int64
	maxConcurrency int
	bindings       []RunnerScopeBinding
}

func (registration RunnerRegistration) Scope() (RunnerScope, error) {
	if !registration.Enabled || !validIdentifier(registration.RunnerID, 256) || !validIdentifier(registration.TenantID, 256) ||
		(registration.Pool != executionlease.PoolRead && registration.Pool != executionlease.PoolWrite) ||
		registration.ScopeRevision <= 0 || registration.MaxConcurrency < 1 || registration.MaxConcurrency > 1024 ||
		len(registration.ScopeBindings) == 0 {
		return RunnerScope{}, executionlease.ErrInvalidRequest
	}
	bindings := make([]RunnerScopeBinding, len(registration.ScopeBindings))
	seen := make(map[string]struct{}, len(bindings))
	for index, binding := range registration.ScopeBindings {
		if !validIdentifier(binding.WorkspaceID, 256) || !validIdentifier(binding.EnvironmentID, 256) {
			return RunnerScope{}, executionlease.ErrInvalidRequest
		}
		key := scopeBindingKey(binding.WorkspaceID, binding.EnvironmentID)
		if _, duplicate := seen[key]; duplicate {
			return RunnerScope{}, executionlease.ErrInvalidRequest
		}
		seen[key] = struct{}{}
		bindings[index] = binding
	}
	return RunnerScope{
		runnerID: registration.RunnerID, tenantID: registration.TenantID, pool: registration.Pool,
		scopeRevision: registration.ScopeRevision, maxConcurrency: registration.MaxConcurrency, bindings: bindings,
	}, nil
}

func (scope RunnerScope) RunnerID() string          { return scope.runnerID }
func (scope RunnerScope) TenantID() string          { return scope.tenantID }
func (scope RunnerScope) Pool() executionlease.Pool { return scope.pool }
func (scope RunnerScope) ScopeRevision() int64      { return scope.scopeRevision }
func (scope RunnerScope) MaxConcurrency() int       { return scope.maxConcurrency }
func (scope RunnerScope) Bindings() []RunnerScopeBinding {
	return append([]RunnerScopeBinding(nil), scope.bindings...)
}

func (scope RunnerScope) allows(workspaceID, environmentID string) bool {
	for _, binding := range scope.bindings {
		if binding.WorkspaceID == workspaceID && binding.EnvironmentID == environmentID {
			return true
		}
	}
	return false
}

func scopeBindingKey(workspaceID, environmentID string) string {
	return workspaceID + "\x00" + environmentID
}

type ActionClaimRequest struct {
	Scope         RunnerScope
	LeaseDuration time.Duration
}

type ClaimedAction struct {
	Execution           executionlease.Execution
	Envelope            action.Envelope
	PlanHash            string
	TargetKey           string
	EnvironmentRevision string
	Production          bool
}

type ActionQueueReason struct {
	Code       string
	DetailHash string
}

type ActionRejectRequest struct {
	Lease  executionlease.LeaseIdentity
	Reason ActionQueueReason
}

type ActionNackRequest struct {
	Lease      executionlease.LeaseIdentity
	Reason     ActionQueueReason
	RetryAfter time.Duration
}

type HeartbeatDirective string

const (
	HeartbeatContinue  HeartbeatDirective = "CONTINUE"
	HeartbeatTerminate HeartbeatDirective = "TERMINATE"
)

type ActionHeartbeatRequest struct {
	Lease     executionlease.LeaseIdentity
	Sequence  int64
	Extension time.Duration
}

type ActionHeartbeatResult struct {
	Execution executionlease.Execution
	Directive HeartbeatDirective
}

type ActionCompleteRequest struct {
	Lease   executionlease.LeaseIdentity
	Summary ExecutorResult
}

type RunnerResultReceipt struct {
	ActionID         string
	TenantID         string
	WorkspaceID      string
	EnvironmentID    string
	PlanHash         string
	RunnerID         string
	LeaseEpoch       int64
	ScopeRevision    int64
	CompletionStatus executionlease.Status
	Summary          ExecutorResult
	ResultHash       string
	ReceivedAt       time.Time
}

// ActionQueue owns the atomic relationship between immutable action metadata
// and lease state. Service implementations must never keep a shadow job map.
type ActionQueue interface {
	Submit(context.Context, ActionSubmission) (executionlease.Execution, error)
	Claim(context.Context, ActionClaimRequest) (ClaimedAction, error)
	Start(context.Context, executionlease.LeaseIdentity) (executionlease.Execution, error)
	Heartbeat(context.Context, ActionHeartbeatRequest) (ActionHeartbeatResult, error)
	Complete(context.Context, ActionCompleteRequest) (executionlease.Execution, error)
	Finalize(context.Context, executionlease.LeaseIdentity) (executionlease.Execution, error)
	Reject(context.Context, ActionRejectRequest) (executionlease.Execution, error)
	Nack(context.Context, ActionNackRequest) (executionlease.Execution, error)
	Reconcile(context.Context, executionlease.ReconcileRequest) (executionlease.Execution, error)
	Cancel(context.Context, string) (executionlease.Execution, error)
	SweepExpired(context.Context) error
	Get(context.Context, string) (executionlease.Execution, error)
}

// CredentialFinalizationGate is called while the in-memory queue lock is held.
// Implementations must not call back into the queue. The lock order is action
// queue first, credential repository second, matching durable repositories.
type CredentialFinalizationGate interface {
	InspectCleanup(context.Context, string, int64) (present bool, terminal bool, err error)
}

type MemoryActionQueueOptions struct {
	Clock                      func() time.Time
	TokenSource                func() (string, error)
	CredentialFinalizationGate CredentialFinalizationGate
}

type memoryActionRecord struct {
	submission         ActionSubmission
	requestHash        string
	receipt            *RunnerResultReceipt
	completedTokenHash string
	completedEpoch     int64
	execution          executionlease.Execution
	notBefore          time.Time
	lastNackHash       string
}

// MemoryActionQueue is a process-local reference implementation. Queue state
// and immutable metadata are protected by the same mutex, making Submit and
// Claim atomic at the queue boundary.
type MemoryActionQueue struct {
	mu                         sync.Mutex
	records                    map[string]memoryActionRecord
	idempotency                map[string]string
	order                      []string
	clock                      func() time.Time
	tokenSource                func() (string, error)
	credentialFinalizationGate CredentialFinalizationGate
}

var _ ActionQueue = (*MemoryActionQueue)(nil)

func NewMemoryActionQueue(options MemoryActionQueueOptions) (*MemoryActionQueue, error) {
	if options.Clock == nil {
		options.Clock = time.Now
	}
	if options.TokenSource == nil {
		options.TokenSource = randomActionLeaseToken
	}
	if options.Clock().IsZero() {
		return nil, fmt.Errorf("execution queue clock returned zero time")
	}
	return &MemoryActionQueue{
		records: make(map[string]memoryActionRecord), idempotency: make(map[string]string),
		clock: options.Clock, tokenSource: options.TokenSource,
		credentialFinalizationGate: options.CredentialFinalizationGate,
	}, nil
}

func (queue *MemoryActionQueue) Submit(ctx context.Context, submission ActionSubmission) (executionlease.Execution, error) {
	if err := ctx.Err(); err != nil {
		return executionlease.Execution{}, err
	}
	if err := validateActionSubmission(submission); err != nil {
		return executionlease.Execution{}, err
	}
	now, err := queue.now()
	if err != nil {
		return executionlease.Execution{}, err
	}
	submission.Envelope = cloneEnvelope(submission.Envelope)
	requestHash, err := RequestSemanticHash(submission)
	if err != nil {
		return executionlease.Execution{}, err
	}

	queue.mu.Lock()
	defer queue.mu.Unlock()
	if existing, exists := queue.records[submission.Envelope.ActionID]; exists {
		if existing.requestHash == requestHash {
			return redactActionExecution(existing.execution), nil
		}
		return executionlease.Execution{}, ErrJobConflict
	}
	idempotencyKey := scopeBindingKey(submission.Envelope.WorkspaceID, submission.Envelope.IdempotencyKey)
	if existingID, exists := queue.idempotency[idempotencyKey]; exists {
		existing := queue.records[existingID]
		if existing.requestHash == requestHash {
			return redactActionExecution(existing.execution), nil
		}
		return executionlease.Execution{}, ErrIdempotencyConflict
	}
	execution := executionlease.Execution{
		ExecutionID: submission.Envelope.ActionID,
		TargetKey:   submission.TargetKey,
		Pool:        submission.Pool,
		Production:  submission.Production,
		Status:      executionlease.StatusQueued,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	queue.records[execution.ExecutionID] = memoryActionRecord{submission: submission, requestHash: requestHash, execution: execution}
	queue.idempotency[idempotencyKey] = execution.ExecutionID
	queue.order = append(queue.order, execution.ExecutionID)
	return execution, nil
}

func (queue *MemoryActionQueue) Claim(ctx context.Context, request ActionClaimRequest) (ClaimedAction, error) {
	if err := ctx.Err(); err != nil {
		return ClaimedAction{}, err
	}
	if err := validateRunnerScope(request); err != nil {
		return ClaimedAction{}, err
	}
	now, err := queue.now()
	if err != nil {
		return ClaimedAction{}, err
	}

	queue.mu.Lock()
	defer queue.mu.Unlock()
	queue.expireLocked(ctx, now)
	if queue.runnerActive(request.Scope.runnerID) >= request.Scope.maxConcurrency {
		return ClaimedAction{}, executionlease.ErrNoLeaseAvailable
	}
	for _, executionID := range queue.order {
		record := queue.records[executionID]
		if record.execution.Status != executionlease.StatusQueued || record.execution.Pool != request.Scope.pool {
			continue
		}
		if record.execution.Pool == executionlease.PoolWrite && record.execution.Production {
			continue
		}
		if record.notBefore.After(now) {
			continue
		}
		if !record.submission.Envelope.ExpiresAt.After(now) {
			continue
		}
		if !request.Scope.allows(record.submission.Envelope.WorkspaceID, record.submission.Envelope.Target.EnvironmentID) {
			continue
		}
		if queue.targetActive(record.execution.TargetKey, record.execution.ExecutionID) {
			continue
		}
		if record.execution.LeaseEpoch == math.MaxInt64 {
			return ClaimedAction{}, fmt.Errorf("%w: lease epoch exhausted", executionlease.ErrInvalidTransition)
		}
		token, err := queue.tokenSource()
		if err != nil {
			return ClaimedAction{}, fmt.Errorf("generate execution queue lease token: %w", err)
		}
		if !validIdentifier(token, 256) {
			return ClaimedAction{}, fmt.Errorf("%w: invalid lease token", executionlease.ErrInvalidRequest)
		}
		now, err = queue.now()
		if err != nil {
			return ClaimedAction{}, err
		}
		if !record.submission.Envelope.ExpiresAt.After(now) {
			continue
		}
		record.execution.Status = executionlease.StatusLeased
		record.execution.RunnerID = request.Scope.runnerID
		record.execution.RunnerTenantID = request.Scope.tenantID
		record.execution.RunnerWorkspaceID = record.submission.Envelope.WorkspaceID
		record.execution.RunnerEnvironmentID = record.submission.Envelope.Target.EnvironmentID
		record.execution.ScopeRevision = request.Scope.scopeRevision
		record.execution.LeaseToken = token
		record.execution.LeaseEpoch++
		record.execution.HeartbeatSeq = 0
		record.execution.CancelRequestedAt = time.Time{}
		record.execution.CancelReasonHash = ""
		record.execution.LeaseAcquiredAt = now
		record.execution.LastHeartbeatAt = now
		record.execution.LeaseExpiresAt = now.Add(request.LeaseDuration)
		if record.submission.Envelope.ExpiresAt.Before(record.execution.LeaseExpiresAt) {
			record.execution.LeaseExpiresAt = record.submission.Envelope.ExpiresAt
		}
		record.execution.UpdatedAt = now
		queue.records[executionID] = record
		return claimedAction(record), nil
	}
	return ClaimedAction{}, executionlease.ErrNoLeaseAvailable
}

func (queue *MemoryActionQueue) Start(ctx context.Context, fence executionlease.LeaseIdentity) (executionlease.Execution, error) {
	if err := ctx.Err(); err != nil {
		return executionlease.Execution{}, err
	}
	if !validActionFence(fence) {
		return executionlease.Execution{}, executionlease.ErrInvalidRequest
	}
	now, err := queue.now()
	if err != nil {
		return executionlease.Execution{}, err
	}
	queue.mu.Lock()
	defer queue.mu.Unlock()
	record, exists := queue.records[fence.ExecutionID]
	if !exists {
		return executionlease.Execution{}, executionlease.ErrNotFound
	}
	if !record.submission.Envelope.ExpiresAt.After(now) {
		return executionlease.Execution{}, executionlease.ErrStaleLease
	}
	if !currentActionFence(record.execution, fence, now) {
		return executionlease.Execution{}, executionlease.ErrStaleLease
	}
	switch record.execution.Status {
	case executionlease.StatusLeased:
		record.execution.Status = executionlease.StatusRunning
		record.execution.StartedAt = now
		record.execution.UpdatedAt = now
		queue.records[fence.ExecutionID] = record
	case executionlease.StatusRunning:
	default:
		return executionlease.Execution{}, executionlease.ErrInvalidTransition
	}
	return redactActionExecution(record.execution), nil
}

func (queue *MemoryActionQueue) Heartbeat(ctx context.Context, request ActionHeartbeatRequest) (ActionHeartbeatResult, error) {
	if err := ctx.Err(); err != nil {
		return ActionHeartbeatResult{}, err
	}
	if !validActionFence(request.Lease) || request.Extension < minimumActionLease || request.Extension > maximumActionLease {
		return ActionHeartbeatResult{}, executionlease.ErrInvalidRequest
	}
	if request.Sequence <= 0 {
		return ActionHeartbeatResult{}, ErrHeartbeatSequence
	}
	now, err := queue.now()
	if err != nil {
		return ActionHeartbeatResult{}, err
	}
	queue.mu.Lock()
	defer queue.mu.Unlock()
	record, exists := queue.records[request.Lease.ExecutionID]
	if !exists {
		return ActionHeartbeatResult{}, executionlease.ErrNotFound
	}
	if !sameActionFence(record.execution, request.Lease) {
		return ActionHeartbeatResult{}, executionlease.ErrStaleLease
	}
	if record.execution.Status != executionlease.StatusLeased && record.execution.Status != executionlease.StatusRunning {
		return ActionHeartbeatResult{}, executionlease.ErrInvalidTransition
	}
	if !record.submission.Envelope.ExpiresAt.After(now) {
		return ActionHeartbeatResult{Execution: redactActionExecution(record.execution), Directive: HeartbeatTerminate}, nil
	}
	if !record.execution.LeaseExpiresAt.After(now) {
		return ActionHeartbeatResult{}, executionlease.ErrStaleLease
	}
	if request.Sequence == record.execution.HeartbeatSeq {
		return actionHeartbeatResult(record.execution), nil
	}
	if request.Sequence != record.execution.HeartbeatSeq+1 {
		return ActionHeartbeatResult{}, ErrHeartbeatSequence
	}
	record.execution.HeartbeatSeq = request.Sequence
	if record.execution.CancelRequestedAt.IsZero() {
		leaseExpiresAt := now.Add(request.Extension)
		if record.submission.Envelope.ExpiresAt.Before(leaseExpiresAt) {
			leaseExpiresAt = record.submission.Envelope.ExpiresAt
		}
		record.execution.LeaseExpiresAt = leaseExpiresAt
		record.execution.LastHeartbeatAt = now
	}
	record.execution.UpdatedAt = now
	queue.records[request.Lease.ExecutionID] = record
	return actionHeartbeatResult(record.execution), nil
}

func actionHeartbeatResult(value executionlease.Execution) ActionHeartbeatResult {
	directive := HeartbeatContinue
	if !value.CancelRequestedAt.IsZero() {
		directive = HeartbeatTerminate
	}
	return ActionHeartbeatResult{Execution: redactActionExecution(value), Directive: directive}
}

func (queue *MemoryActionQueue) Complete(ctx context.Context, request ActionCompleteRequest) (executionlease.Execution, error) {
	if err := ctx.Err(); err != nil {
		return executionlease.Execution{}, err
	}
	completionStatus, err := ResultSummaryStatus(request.Summary)
	if !validActionFence(request.Lease) || err != nil {
		return executionlease.Execution{}, executionlease.ErrInvalidRequest
	}
	now, err := queue.now()
	if err != nil {
		return executionlease.Execution{}, err
	}
	queue.mu.Lock()
	defer queue.mu.Unlock()
	record, exists := queue.records[request.Lease.ExecutionID]
	if !exists {
		return executionlease.Execution{}, executionlease.ErrNotFound
	}
	receipt, err := BuildRunnerResultReceipt(claimedAction(record), request, completionStatus, now)
	if err != nil {
		return executionlease.Execution{}, err
	}
	requestTokenHash := hashLeaseToken(request.Lease.Token)
	if record.execution.Status == executionlease.StatusFinalizing || record.execution.Terminal() {
		if record.execution.ReconciliationID != "" || record.execution.RunnerID != request.Lease.RunnerID ||
			record.completedEpoch != request.Lease.Epoch || record.completedTokenHash != requestTokenHash {
			return executionlease.Execution{}, executionlease.ErrStaleLease
		}
		if record.receipt != nil && record.receipt.ResultHash == receipt.ResultHash && record.execution.CompletionStatus == completionStatus {
			return redactActionExecution(record.execution), nil
		}
		return executionlease.Execution{}, executionlease.ErrCompletionConflict
	}
	if !currentActionFence(record.execution, request.Lease, now) {
		return executionlease.Execution{}, executionlease.ErrStaleLease
	}
	if record.execution.Status != executionlease.StatusRunning {
		return executionlease.Execution{}, executionlease.ErrInvalidTransition
	}
	record.execution.Status = executionlease.StatusFinalizing
	record.execution.CompletionStatus = completionStatus
	record.execution.ResultHash = receipt.ResultHash
	record.execution.LeaseExpiresAt = time.Time{}
	record.execution.LeaseToken = ""
	record.execution.UpdatedAt = now
	record.receipt = &receipt
	record.completedTokenHash = requestTokenHash
	record.completedEpoch = request.Lease.Epoch
	queue.records[request.Lease.ExecutionID] = record
	return redactActionExecution(record.execution), nil
}

func (queue *MemoryActionQueue) Finalize(ctx context.Context, fence executionlease.LeaseIdentity) (executionlease.Execution, error) {
	if err := ctx.Err(); err != nil {
		return executionlease.Execution{}, err
	}
	if !validActionFence(fence) {
		return executionlease.Execution{}, executionlease.ErrInvalidRequest
	}
	now, err := queue.now()
	if err != nil {
		return executionlease.Execution{}, err
	}
	queue.mu.Lock()
	defer queue.mu.Unlock()
	record, exists := queue.records[fence.ExecutionID]
	if !exists {
		return executionlease.Execution{}, executionlease.ErrNotFound
	}
	if record.execution.ReconciliationID != "" || record.execution.RunnerID != fence.RunnerID ||
		record.completedEpoch != fence.Epoch || record.completedTokenHash != hashLeaseToken(fence.Token) {
		return executionlease.Execution{}, executionlease.ErrStaleLease
	}
	if record.execution.Terminal() {
		return redactActionExecution(record.execution), nil
	}
	if record.execution.Status != executionlease.StatusFinalizing || record.receipt == nil ||
		record.execution.CompletionStatus != record.receipt.CompletionStatus {
		return executionlease.Execution{}, executionlease.ErrInvalidTransition
	}
	if releasesTargetLock(record.execution.CompletionStatus) {
		if err := queue.requireCredentialTerminal(ctx, record, false); err != nil {
			return executionlease.Execution{}, err
		}
	}
	record.execution.Status = record.execution.CompletionStatus
	record.execution.CompletedAt = now
	record.execution.UpdatedAt = now
	queue.records[fence.ExecutionID] = record
	return redactActionExecution(record.execution), nil
}

func (queue *MemoryActionQueue) Reject(ctx context.Context, request ActionRejectRequest) (executionlease.Execution, error) {
	if err := ctx.Err(); err != nil {
		return executionlease.Execution{}, err
	}
	if !validActionFence(request.Lease) || !validActionQueueReason(request.Reason) {
		return executionlease.Execution{}, executionlease.ErrInvalidRequest
	}
	reasonHash, err := hashActionQueueReason(request.Reason)
	if err != nil {
		return executionlease.Execution{}, err
	}
	now, err := queue.now()
	if err != nil {
		return executionlease.Execution{}, err
	}
	queue.mu.Lock()
	defer queue.mu.Unlock()
	record, exists := queue.records[request.Lease.ExecutionID]
	if !exists {
		return executionlease.Execution{}, executionlease.ErrNotFound
	}
	requestTokenHash := hashLeaseToken(request.Lease.Token)
	if record.execution.Status == executionlease.StatusFailed {
		if record.execution.ReconciliationID != "" || record.execution.RunnerID != request.Lease.RunnerID ||
			record.completedEpoch != request.Lease.Epoch || record.completedTokenHash != requestTokenHash {
			return executionlease.Execution{}, executionlease.ErrStaleLease
		}
		if record.execution.ResultHash != reasonHash {
			return executionlease.Execution{}, executionlease.ErrCompletionConflict
		}
		return redactActionExecution(record.execution), nil
	}
	if !currentActionFence(record.execution, request.Lease, now) {
		return executionlease.Execution{}, executionlease.ErrStaleLease
	}
	if record.execution.Status != executionlease.StatusLeased {
		return executionlease.Execution{}, executionlease.ErrInvalidTransition
	}
	if err := queue.requireCredentialTerminal(ctx, record, true); err != nil {
		return executionlease.Execution{}, err
	}
	record.execution.Status = executionlease.StatusFailed
	record.execution.CompletionStatus = executionlease.StatusFailed
	record.execution.ResultHash = reasonHash
	record.execution.CompletedAt = now
	record.execution.LeaseExpiresAt = time.Time{}
	record.execution.LeaseToken = ""
	record.execution.UpdatedAt = now
	record.completedTokenHash = requestTokenHash
	record.completedEpoch = request.Lease.Epoch
	queue.records[request.Lease.ExecutionID] = record
	return redactActionExecution(record.execution), nil
}

func (queue *MemoryActionQueue) Nack(ctx context.Context, request ActionNackRequest) (executionlease.Execution, error) {
	if err := ctx.Err(); err != nil {
		return executionlease.Execution{}, err
	}
	if !validActionFence(request.Lease) || !validActionQueueReason(request.Reason) ||
		request.RetryAfter < time.Second || request.RetryAfter > maximumActionLease {
		return executionlease.Execution{}, executionlease.ErrInvalidRequest
	}
	reasonHash, err := hashActionQueueReason(request.Reason)
	if err != nil {
		return executionlease.Execution{}, err
	}
	now, err := queue.now()
	if err != nil {
		return executionlease.Execution{}, err
	}
	queue.mu.Lock()
	defer queue.mu.Unlock()
	record, exists := queue.records[request.Lease.ExecutionID]
	if !exists {
		return executionlease.Execution{}, executionlease.ErrNotFound
	}
	if !currentActionFence(record.execution, request.Lease, now) {
		return executionlease.Execution{}, executionlease.ErrStaleLease
	}
	if record.execution.Status != executionlease.StatusLeased {
		return executionlease.Execution{}, executionlease.ErrInvalidTransition
	}
	if err := queue.requireCredentialTerminal(ctx, record, true); err != nil {
		return executionlease.Execution{}, err
	}
	record.execution.Status = executionlease.StatusQueued
	record.execution.RunnerID = ""
	record.execution.RunnerTenantID = ""
	record.execution.RunnerWorkspaceID = ""
	record.execution.RunnerEnvironmentID = ""
	record.execution.LeaseToken = ""
	record.execution.LeaseExpiresAt = time.Time{}
	record.execution.LeaseAcquiredAt = time.Time{}
	record.execution.LastHeartbeatAt = time.Time{}
	record.execution.ScopeRevision = 0
	record.execution.HeartbeatSeq = 0
	record.execution.CancelRequestedAt = time.Time{}
	record.execution.CancelReasonHash = ""
	record.execution.UpdatedAt = now
	record.notBefore = now.Add(request.RetryAfter)
	record.lastNackHash = reasonHash
	queue.records[request.Lease.ExecutionID] = record
	return record.execution, nil
}

func (queue *MemoryActionQueue) Reconcile(ctx context.Context, request executionlease.ReconcileRequest) (executionlease.Execution, error) {
	if err := ctx.Err(); err != nil {
		return executionlease.Execution{}, err
	}
	if !validIdentifier(request.ExecutionID, 256) || !validIdentifier(request.ReconciliationID, 256) ||
		!validIdentifier(request.ActorID, 256) ||
		(request.Status != executionlease.StatusSucceeded && request.Status != executionlease.StatusFailed) ||
		!actionQueueSHA256Pattern.MatchString(request.ResultHash) {
		return executionlease.Execution{}, executionlease.ErrInvalidRequest
	}
	now, err := queue.now()
	if err != nil {
		return executionlease.Execution{}, err
	}
	queue.mu.Lock()
	defer queue.mu.Unlock()
	queue.expireLocked(ctx, now)
	record, exists := queue.records[request.ExecutionID]
	if !exists {
		return executionlease.Execution{}, executionlease.ErrNotFound
	}
	if record.execution.ReconciliationID != "" {
		if record.execution.ReconciliationID == request.ReconciliationID &&
			record.execution.ReconciliationActor == request.ActorID && record.execution.Status == request.Status &&
			record.execution.ReconciliationResultHash == request.ResultHash {
			return redactActionExecution(record.execution), nil
		}
		return executionlease.Execution{}, executionlease.ErrReconciliationConflict
	}
	if record.execution.Status != executionlease.StatusUncertain {
		return executionlease.Execution{}, executionlease.ErrInvalidTransition
	}
	if err := queue.requireCredentialTerminal(ctx, record, false); err != nil {
		return executionlease.Execution{}, err
	}
	for executionID, existing := range queue.records {
		if executionID != request.ExecutionID && existing.execution.ReconciliationID == request.ReconciliationID {
			return executionlease.Execution{}, executionlease.ErrReconciliationConflict
		}
	}
	record.execution.Status = request.Status
	record.execution.ReconciliationID = request.ReconciliationID
	record.execution.ReconciliationActor = request.ActorID
	record.execution.ReconciliationResultHash = request.ResultHash
	record.execution.ReconciledAt = now
	record.execution.UpdatedAt = now
	queue.records[request.ExecutionID] = record
	return redactActionExecution(record.execution), nil
}

func (queue *MemoryActionQueue) Cancel(ctx context.Context, executionID string) (executionlease.Execution, error) {
	if err := ctx.Err(); err != nil {
		return executionlease.Execution{}, err
	}
	if !validIdentifier(executionID, 256) {
		return executionlease.Execution{}, executionlease.ErrInvalidRequest
	}
	now, err := queue.now()
	if err != nil {
		return executionlease.Execution{}, err
	}
	queue.mu.Lock()
	defer queue.mu.Unlock()
	queue.expireLocked(ctx, now)
	record, exists := queue.records[executionID]
	if !exists {
		return executionlease.Execution{}, executionlease.ErrNotFound
	}
	if record.execution.Terminal() {
		return redactActionExecution(record.execution), nil
	}
	if record.execution.Status == executionlease.StatusFinalizing {
		return executionlease.Execution{}, executionlease.ErrInvalidTransition
	}
	if record.execution.Status == executionlease.StatusRunning {
		if record.execution.CancelRequestedAt.IsZero() {
			record.execution.CancelRequestedAt = now
			record.execution.CancelReasonHash = CancellationIntentHash()
			record.execution.UpdatedAt = now
			queue.records[executionID] = record
		}
		return redactActionExecution(record.execution), nil
	}
	if record.execution.Status == executionlease.StatusLeased {
		if err := queue.requireCredentialTerminal(ctx, record, true); err != nil {
			return executionlease.Execution{}, err
		}
	}
	record.execution.Status = executionlease.StatusCancelled
	record.execution.RunnerID = ""
	record.execution.RunnerTenantID = ""
	record.execution.RunnerWorkspaceID = ""
	record.execution.RunnerEnvironmentID = ""
	record.execution.LeaseToken = ""
	record.execution.LeaseExpiresAt = time.Time{}
	record.execution.CompletedAt = now
	record.execution.UpdatedAt = now
	queue.records[executionID] = record
	return redactActionExecution(record.execution), nil
}

func (queue *MemoryActionQueue) SweepExpired(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	now, err := queue.now()
	if err != nil {
		return err
	}
	queue.mu.Lock()
	queue.expireLocked(ctx, now)
	queue.mu.Unlock()
	return nil
}

func (queue *MemoryActionQueue) Get(ctx context.Context, executionID string) (executionlease.Execution, error) {
	if err := ctx.Err(); err != nil {
		return executionlease.Execution{}, err
	}
	if !validIdentifier(executionID, 256) {
		return executionlease.Execution{}, executionlease.ErrInvalidRequest
	}
	now, err := queue.now()
	if err != nil {
		return executionlease.Execution{}, err
	}
	queue.mu.Lock()
	defer queue.mu.Unlock()
	queue.expireLocked(ctx, now)
	record, exists := queue.records[executionID]
	if !exists {
		return executionlease.Execution{}, executionlease.ErrNotFound
	}
	return redactActionExecution(record.execution), nil
}

func (queue *MemoryActionQueue) expireLocked(ctx context.Context, now time.Time) {
	for executionID, record := range queue.records {
		if record.execution.Status == executionlease.StatusFinalizing {
			if record.receipt == nil || record.submission.Envelope.ExpiresAt.After(now) ||
				record.execution.CompletionStatus != record.receipt.CompletionStatus {
				continue
			}
			if releasesTargetLock(record.execution.CompletionStatus) &&
				queue.requireCredentialTerminal(ctx, record, false) != nil {
				continue
			}
			record.execution.Status = record.execution.CompletionStatus
			record.execution.CompletedAt = now
			record.execution.UpdatedAt = now
			queue.records[executionID] = record
			continue
		}
		if record.execution.LeaseExpiresAt.IsZero() || record.execution.LeaseExpiresAt.After(now) {
			continue
		}
		switch record.execution.Status {
		case executionlease.StatusLeased:
			if queue.requireCredentialTerminal(ctx, record, true) != nil {
				continue
			}
			record.execution.Status = executionlease.StatusQueued
			record.execution.RunnerID = ""
			record.execution.RunnerTenantID = ""
			record.execution.RunnerWorkspaceID = ""
			record.execution.RunnerEnvironmentID = ""
			record.execution.ScopeRevision = 0
			record.execution.LeaseToken = ""
			record.execution.HeartbeatSeq = 0
			record.execution.CancelRequestedAt = time.Time{}
			record.execution.CancelReasonHash = ""
			record.execution.LeaseExpiresAt = time.Time{}
			record.execution.LeaseAcquiredAt = time.Time{}
			record.execution.LastHeartbeatAt = time.Time{}
			record.notBefore = time.Time{}
		case executionlease.StatusRunning:
			record.execution.Status = executionlease.StatusUncertain
			record.execution.CompletionStatus = executionlease.StatusUncertain
			record.execution.ResultHash = expiredRunningResultHash()
			record.execution.CompletedAt = now
			record.execution.LeaseToken = ""
			record.execution.LeaseExpiresAt = time.Time{}
		default:
			continue
		}
		record.execution.UpdatedAt = now
		queue.records[executionID] = record
	}
}

func releasesTargetLock(status executionlease.Status) bool {
	return status == executionlease.StatusSucceeded || status == executionlease.StatusFailed ||
		status == executionlease.StatusCancelled || status == executionlease.StatusQueued
}

func (queue *MemoryActionQueue) requireCredentialTerminal(
	ctx context.Context,
	record memoryActionRecord,
	allowMissing bool,
) error {
	if record.execution.Pool != executionlease.PoolWrite {
		return nil
	}
	if queue.credentialFinalizationGate == nil {
		return ErrCredentialCleanupPending
	}
	present, terminal, err := queue.credentialFinalizationGate.InspectCleanup(
		ctx, record.execution.ExecutionID, record.execution.LeaseEpoch,
	)
	if err != nil || present && !terminal || !present && !allowMissing {
		return ErrCredentialCleanupPending
	}
	return nil
}

func expiredRunningResultHash() string {
	value, err := hashActionQueueReason(ActionQueueReason{
		Code: "RUNNING_LEASE_EXPIRED", DetailHash: hex.EncodeToString(make([]byte, sha256.Size)),
	})
	if err != nil {
		panic(err)
	}
	return value
}

func CancellationIntentHash() string {
	digest := sha256.Sum256([]byte("action-queue-cancel-intent.v1\x00REQUESTED"))
	return hex.EncodeToString(digest[:])
}

func validateActionSubmission(submission ActionSubmission) error {
	if err := submission.Envelope.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidAction, err)
	}
	if submission.PlanHash == "" || submission.PlanHash != submission.Envelope.PlanHash ||
		!validIdentifier(submission.TargetKey, 512) || !validIdentifier(submission.EnvironmentRevision, 256) ||
		(submission.Pool != executionlease.PoolRead && submission.Pool != executionlease.PoolWrite) {
		return executionlease.ErrInvalidRequest
	}
	return nil
}

func validateRunnerScope(request ActionClaimRequest) error {
	if !validIdentifier(request.Scope.runnerID, 256) || !validIdentifier(request.Scope.tenantID, 256) ||
		(request.Scope.pool != executionlease.PoolRead && request.Scope.pool != executionlease.PoolWrite) ||
		request.Scope.scopeRevision <= 0 || len(request.Scope.bindings) == 0 ||
		request.LeaseDuration < minimumActionLease || request.LeaseDuration > maximumActionLease {
		return executionlease.ErrInvalidRequest
	}
	seen := make(map[string]struct{}, len(request.Scope.bindings))
	for _, binding := range request.Scope.bindings {
		if !validIdentifier(binding.WorkspaceID, 256) || !validIdentifier(binding.EnvironmentID, 256) {
			return executionlease.ErrInvalidRequest
		}
		key := scopeBindingKey(binding.WorkspaceID, binding.EnvironmentID)
		if _, duplicate := seen[key]; duplicate {
			return executionlease.ErrInvalidRequest
		}
		seen[key] = struct{}{}
	}
	return nil
}

var actionQueueSHA256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func validActionQueueReason(reason ActionQueueReason) bool {
	return resultCodePattern.MatchString(reason.Code) && actionQueueSHA256Pattern.MatchString(reason.DetailHash)
}

func hashActionQueueReason(reason ActionQueueReason) (string, error) {
	encoded, err := json.Marshal(struct {
		SchemaVersion string `json:"schema_version"`
		Code          string `json:"code"`
		DetailHash    string `json:"detail_hash"`
	}{SchemaVersion: "action-queue-reason.v1", Code: reason.Code, DetailHash: reason.DetailHash})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func RequestSemanticHash(submission ActionSubmission) (string, error) {
	envelope := cloneEnvelope(submission.Envelope)
	envelope.ActionID = ""
	envelope.PlanHash = ""
	envelope.TraceID = ""
	envelope.Signature = action.Signature{}
	encoded, err := json.Marshal(struct {
		SchemaVersion       string              `json:"schema_version"`
		Envelope            action.Envelope     `json:"envelope"`
		TargetKey           string              `json:"target_key"`
		EnvironmentRevision string              `json:"environment_revision"`
		Production          bool                `json:"production"`
		Pool                executionlease.Pool `json:"pool"`
	}{
		SchemaVersion: "action-request.v1", Envelope: envelope, TargetKey: submission.TargetKey,
		EnvironmentRevision: submission.EnvironmentRevision, Production: submission.Production, Pool: submission.Pool,
	})
	if err != nil {
		return "", fmt.Errorf("marshal action request semantics: %w", err)
	}
	canonical, err := jsoncanonicalizer.Transform(encoded)
	if err != nil {
		return "", fmt.Errorf("canonicalize action request semantics: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func ResultSummaryStatus(summary ExecutorResult) (executionlease.Status, error) {
	if !validExecutorResult(summary) {
		return "", executionlease.ErrInvalidRequest
	}
	switch summary.Outcome {
	case ExecutorSucceeded:
		return executionlease.StatusSucceeded, nil
	case ExecutorFailed:
		return executionlease.StatusFailed, nil
	case ExecutorUncertain:
		return executionlease.StatusUncertain, nil
	default:
		return "", executionlease.ErrInvalidRequest
	}
}

func BuildRunnerResultReceipt(claimed ClaimedAction, request ActionCompleteRequest, completionStatus executionlease.Status, receivedAt time.Time) (RunnerResultReceipt, error) {
	receipt := RunnerResultReceipt{
		ActionID: claimed.Execution.ExecutionID, TenantID: claimed.Execution.RunnerTenantID,
		WorkspaceID: claimed.Execution.RunnerWorkspaceID, EnvironmentID: claimed.Execution.RunnerEnvironmentID,
		PlanHash: claimed.PlanHash,
		RunnerID: request.Lease.RunnerID, LeaseEpoch: request.Lease.Epoch,
		ScopeRevision: claimed.Execution.ScopeRevision, CompletionStatus: completionStatus,
		Summary: request.Summary, ReceivedAt: receivedAt,
	}
	encoded, err := json.Marshal(struct {
		SchemaVersion    string                `json:"schema_version"`
		ActionID         string                `json:"action_id"`
		TenantID         string                `json:"tenant_id"`
		WorkspaceID      string                `json:"workspace_id"`
		EnvironmentID    string                `json:"environment_id"`
		PlanHash         string                `json:"plan_hash"`
		RunnerID         string                `json:"runner_id"`
		LeaseEpoch       string                `json:"lease_epoch"`
		ScopeRevision    string                `json:"scope_revision"`
		CompletionStatus executionlease.Status `json:"completion_status"`
		Outcome          ExecutorOutcome       `json:"outcome"`
		Code             string                `json:"code"`
		Verification     Verification          `json:"verification"`
		Changed          bool                  `json:"changed"`
		ExternalRefHash  string                `json:"external_operation_ref_hash,omitempty"`
	}{
		SchemaVersion: "runner-result.v1", ActionID: receipt.ActionID, TenantID: receipt.TenantID, WorkspaceID: receipt.WorkspaceID,
		EnvironmentID: receipt.EnvironmentID, PlanHash: receipt.PlanHash, RunnerID: receipt.RunnerID,
		LeaseEpoch: strconv.FormatInt(receipt.LeaseEpoch, 10), ScopeRevision: strconv.FormatInt(receipt.ScopeRevision, 10), CompletionStatus: receipt.CompletionStatus,
		Outcome: receipt.Summary.Outcome, Code: receipt.Summary.Code, Verification: receipt.Summary.Verification,
		Changed: receipt.Summary.Changed, ExternalRefHash: receipt.Summary.ExternalOperationRefHash,
	})
	if err != nil {
		return RunnerResultReceipt{}, fmt.Errorf("marshal runner result receipt: %w", err)
	}
	if len(encoded) > 16<<10 {
		return RunnerResultReceipt{}, executionlease.ErrInvalidRequest
	}
	canonical, err := jsoncanonicalizer.Transform(encoded)
	if err != nil {
		return RunnerResultReceipt{}, fmt.Errorf("canonicalize runner result receipt: %w", err)
	}
	digest := sha256.Sum256(append([]byte("runner-result.v1\x00"), canonical...))
	receipt.ResultHash = hex.EncodeToString(digest[:])
	return receipt, nil
}

func hashLeaseToken(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

func claimedAction(record memoryActionRecord) ClaimedAction {
	return ClaimedAction{
		Execution: record.execution, Envelope: cloneEnvelope(record.submission.Envelope),
		PlanHash: record.submission.PlanHash, TargetKey: record.submission.TargetKey,
		EnvironmentRevision: record.submission.EnvironmentRevision, Production: record.submission.Production,
	}
}

func (queue *MemoryActionQueue) targetActive(targetKey, excludingID string) bool {
	for executionID, record := range queue.records {
		if executionID != excludingID && record.execution.TargetKey == targetKey && actionLeaseActive(record.execution.Status) {
			return true
		}
	}
	return false
}

func (queue *MemoryActionQueue) runnerActive(runnerID string) int {
	active := 0
	for _, record := range queue.records {
		if record.execution.RunnerID == runnerID && actionLeaseActive(record.execution.Status) {
			active++
		}
	}
	return active
}

func actionLeaseActive(status executionlease.Status) bool {
	return status == executionlease.StatusLeased || status == executionlease.StatusRunning ||
		status == executionlease.StatusFinalizing || status == executionlease.StatusUncertain
}

func validActionFence(fence executionlease.LeaseIdentity) bool {
	return validIdentifier(fence.ExecutionID, 256) && validIdentifier(fence.RunnerID, 256) &&
		validIdentifier(fence.Token, 256) && fence.Epoch > 0
}

func sameActionFence(execution executionlease.Execution, fence executionlease.LeaseIdentity) bool {
	return execution.ExecutionID == fence.ExecutionID && execution.RunnerID == fence.RunnerID &&
		execution.LeaseToken == fence.Token && execution.LeaseEpoch == fence.Epoch
}

func currentActionFence(execution executionlease.Execution, fence executionlease.LeaseIdentity, now time.Time) bool {
	return sameActionFence(execution, fence) && execution.LeaseExpiresAt.After(now)
}

func redactActionExecution(execution executionlease.Execution) executionlease.Execution {
	execution.LeaseToken = ""
	return execution
}

func (queue *MemoryActionQueue) now() (time.Time, error) {
	now := queue.clock().UTC()
	if now.IsZero() {
		return time.Time{}, fmt.Errorf("execution queue clock returned zero time")
	}
	return now, nil
}

func randomActionLeaseToken() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}
