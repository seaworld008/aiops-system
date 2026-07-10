package execution

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"sync"
	"time"

	"github.com/aiops-system/control-plane/internal/action"
	"github.com/aiops-system/control-plane/internal/executionlease"
)

const (
	minimumActionLease = time.Second
	maximumActionLease = 30 * time.Minute
)

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

// RunnerScope is authenticated gateway state, not caller-controlled job data.
// A queue must filter by this scope before acquiring a target or production
// write lease.
type RunnerScope struct {
	RunnerID              string
	Pool                  executionlease.Pool
	AllowedWorkspaceIDs   []string
	AllowedEnvironmentIDs []string
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

// ActionQueue owns the atomic relationship between immutable action metadata
// and lease state. Service implementations must never keep a shadow job map.
type ActionQueue interface {
	Submit(context.Context, ActionSubmission) (executionlease.Execution, error)
	Claim(context.Context, ActionClaimRequest) (ClaimedAction, error)
	Start(context.Context, executionlease.LeaseIdentity) (executionlease.Execution, error)
	Heartbeat(context.Context, executionlease.HeartbeatRequest) (executionlease.Execution, error)
	Complete(context.Context, executionlease.CompleteRequest) (executionlease.Execution, error)
	Reject(context.Context, ActionRejectRequest) (executionlease.Execution, error)
	Nack(context.Context, ActionNackRequest) (executionlease.Execution, error)
	Reconcile(context.Context, executionlease.ReconcileRequest) (executionlease.Execution, error)
	Cancel(context.Context, string) (executionlease.Execution, error)
	SweepExpired(context.Context) error
	Get(context.Context, string) (executionlease.Execution, error)
}

type MemoryActionQueueOptions struct {
	Clock       func() time.Time
	TokenSource func() (string, error)
}

type memoryActionRecord struct {
	submission   ActionSubmission
	execution    executionlease.Execution
	notBefore    time.Time
	lastNackHash string
}

// MemoryActionQueue is a process-local reference implementation. Queue state
// and immutable metadata are protected by the same mutex, making Submit and
// Claim atomic at the queue boundary.
type MemoryActionQueue struct {
	mu          sync.Mutex
	records     map[string]memoryActionRecord
	order       []string
	clock       func() time.Time
	tokenSource func() (string, error)
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
		records: make(map[string]memoryActionRecord), clock: options.Clock, tokenSource: options.TokenSource,
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

	queue.mu.Lock()
	defer queue.mu.Unlock()
	if existing, exists := queue.records[submission.Envelope.ActionID]; exists {
		if sameActionSubmission(existing.submission, submission) {
			return redactActionExecution(existing.execution), nil
		}
		return executionlease.Execution{}, ErrJobConflict
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
	queue.records[execution.ExecutionID] = memoryActionRecord{submission: submission, execution: execution}
	queue.order = append(queue.order, execution.ExecutionID)
	return execution, nil
}

func (queue *MemoryActionQueue) Claim(ctx context.Context, request ActionClaimRequest) (ClaimedAction, error) {
	if err := ctx.Err(); err != nil {
		return ClaimedAction{}, err
	}
	workspaceIDs, environmentIDs, err := validateRunnerScope(request)
	if err != nil {
		return ClaimedAction{}, err
	}
	now, err := queue.now()
	if err != nil {
		return ClaimedAction{}, err
	}

	queue.mu.Lock()
	defer queue.mu.Unlock()
	queue.expireLocked(now)
	for _, executionID := range queue.order {
		record := queue.records[executionID]
		if record.execution.Status != executionlease.StatusQueued || record.execution.Pool != request.Scope.Pool {
			continue
		}
		if record.notBefore.After(now) {
			continue
		}
		if _, allowed := workspaceIDs[record.submission.Envelope.WorkspaceID]; !allowed {
			continue
		}
		if _, allowed := environmentIDs[record.submission.Envelope.Target.EnvironmentID]; !allowed {
			continue
		}
		if queue.targetActive(record.execution.TargetKey, record.execution.ExecutionID) {
			continue
		}
		if record.execution.Pool == executionlease.PoolWrite && record.execution.Production && queue.productionWriteActive(record.execution.ExecutionID) {
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
		record.execution.Status = executionlease.StatusLeased
		record.execution.RunnerID = request.Scope.RunnerID
		record.execution.LeaseToken = token
		record.execution.LeaseEpoch++
		record.execution.LeaseAcquiredAt = now
		record.execution.LastHeartbeatAt = now
		record.execution.LeaseExpiresAt = now.Add(request.LeaseDuration)
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

func (queue *MemoryActionQueue) Heartbeat(ctx context.Context, request executionlease.HeartbeatRequest) (executionlease.Execution, error) {
	if err := ctx.Err(); err != nil {
		return executionlease.Execution{}, err
	}
	if !validActionFence(request.Lease) || request.Extension < minimumActionLease || request.Extension > maximumActionLease {
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
	if !currentActionFence(record.execution, request.Lease, now) {
		return executionlease.Execution{}, executionlease.ErrStaleLease
	}
	if record.execution.Status != executionlease.StatusLeased && record.execution.Status != executionlease.StatusRunning {
		return executionlease.Execution{}, executionlease.ErrInvalidTransition
	}
	record.execution.LeaseExpiresAt = now.Add(request.Extension)
	record.execution.LastHeartbeatAt = now
	record.execution.UpdatedAt = now
	queue.records[request.Lease.ExecutionID] = record
	return redactActionExecution(record.execution), nil
}

func (queue *MemoryActionQueue) Complete(ctx context.Context, request executionlease.CompleteRequest) (executionlease.Execution, error) {
	if err := ctx.Err(); err != nil {
		return executionlease.Execution{}, err
	}
	if !validActionFence(request.Lease) ||
		(request.Status != executionlease.StatusSucceeded && request.Status != executionlease.StatusFailed && request.Status != executionlease.StatusUncertain) ||
		!actionQueueSHA256Pattern.MatchString(request.ResultHash) {
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
	if record.execution.Status == executionlease.StatusSucceeded || record.execution.Status == executionlease.StatusFailed ||
		record.execution.Status == executionlease.StatusUncertain {
		if !sameActionFence(record.execution, request.Lease) {
			return executionlease.Execution{}, executionlease.ErrStaleLease
		}
		if record.execution.Status == request.Status && record.execution.ResultHash == request.ResultHash {
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
	record.execution.Status = request.Status
	record.execution.ResultHash = request.ResultHash
	record.execution.CompletedAt = now
	record.execution.LeaseExpiresAt = time.Time{}
	record.execution.UpdatedAt = now
	queue.records[request.Lease.ExecutionID] = record
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
	if record.execution.Status == executionlease.StatusFailed {
		if sameActionFence(record.execution, request.Lease) && record.execution.ResultHash == reasonHash {
			return redactActionExecution(record.execution), nil
		}
		return executionlease.Execution{}, executionlease.ErrCompletionConflict
	}
	if !currentActionFence(record.execution, request.Lease, now) {
		return executionlease.Execution{}, executionlease.ErrStaleLease
	}
	if record.execution.Status != executionlease.StatusLeased {
		return executionlease.Execution{}, executionlease.ErrInvalidTransition
	}
	record.execution.Status = executionlease.StatusFailed
	record.execution.ResultHash = reasonHash
	record.execution.CompletedAt = now
	record.execution.LeaseExpiresAt = time.Time{}
	record.execution.UpdatedAt = now
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
	record.execution.Status = executionlease.StatusQueued
	record.execution.RunnerID = ""
	record.execution.LeaseToken = ""
	record.execution.LeaseExpiresAt = time.Time{}
	record.execution.LeaseAcquiredAt = time.Time{}
	record.execution.LastHeartbeatAt = time.Time{}
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
	queue.expireLocked(now)
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
	queue.expireLocked(now)
	record, exists := queue.records[executionID]
	if !exists {
		return executionlease.Execution{}, executionlease.ErrNotFound
	}
	if record.execution.Terminal() {
		return redactActionExecution(record.execution), nil
	}
	if record.execution.Status == executionlease.StatusRunning {
		record.execution.Status = executionlease.StatusUncertain
		record.execution.ResultHash = cancellationUncertainResultHash()
	} else {
		record.execution.Status = executionlease.StatusCancelled
		record.execution.RunnerID = ""
	}
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
	queue.expireLocked(now)
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
	queue.expireLocked(now)
	record, exists := queue.records[executionID]
	if !exists {
		return executionlease.Execution{}, executionlease.ErrNotFound
	}
	return redactActionExecution(record.execution), nil
}

func (queue *MemoryActionQueue) expireLocked(now time.Time) {
	for executionID, record := range queue.records {
		if record.execution.LeaseExpiresAt.IsZero() || record.execution.LeaseExpiresAt.After(now) {
			continue
		}
		switch record.execution.Status {
		case executionlease.StatusLeased:
			record.execution.Status = executionlease.StatusQueued
			record.execution.RunnerID = ""
			record.execution.LeaseToken = ""
			record.execution.LeaseExpiresAt = time.Time{}
			record.execution.LeaseAcquiredAt = time.Time{}
			record.execution.LastHeartbeatAt = time.Time{}
			record.notBefore = time.Time{}
		case executionlease.StatusRunning:
			record.execution.Status = executionlease.StatusUncertain
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

func expiredRunningResultHash() string {
	value, err := hashActionQueueReason(ActionQueueReason{
		Code: "RUNNING_LEASE_EXPIRED", DetailHash: hex.EncodeToString(make([]byte, sha256.Size)),
	})
	if err != nil {
		panic(err)
	}
	return value
}

func cancellationUncertainResultHash() string {
	value, err := hashActionQueueReason(ActionQueueReason{
		Code: "RUNNING_CANCELLED", DetailHash: hex.EncodeToString(make([]byte, sha256.Size)),
	})
	if err != nil {
		panic(err)
	}
	return value
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

func validateRunnerScope(request ActionClaimRequest) (map[string]struct{}, map[string]struct{}, error) {
	if !validIdentifier(request.Scope.RunnerID, 256) ||
		(request.Scope.Pool != executionlease.PoolRead && request.Scope.Pool != executionlease.PoolWrite) ||
		request.LeaseDuration < minimumActionLease || request.LeaseDuration > maximumActionLease {
		return nil, nil, executionlease.ErrInvalidRequest
	}
	workspaces, err := identifierSet(request.Scope.AllowedWorkspaceIDs)
	if err != nil {
		return nil, nil, err
	}
	environments, err := identifierSet(request.Scope.AllowedEnvironmentIDs)
	if err != nil {
		return nil, nil, err
	}
	return workspaces, environments, nil
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

func identifierSet(values []string) (map[string]struct{}, error) {
	if len(values) == 0 {
		return nil, executionlease.ErrInvalidRequest
	}
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validIdentifier(value, 256) {
			return nil, executionlease.ErrInvalidRequest
		}
		if _, duplicate := result[value]; duplicate {
			return nil, executionlease.ErrInvalidRequest
		}
		result[value] = struct{}{}
	}
	return result, nil
}

func sameActionSubmission(first, second ActionSubmission) bool {
	return first.PlanHash == second.PlanHash && first.TargetKey == second.TargetKey &&
		first.EnvironmentRevision == second.EnvironmentRevision && first.Production == second.Production &&
		first.Pool == second.Pool && reflect.DeepEqual(first.Envelope, second.Envelope)
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

func (queue *MemoryActionQueue) productionWriteActive(excludingID string) bool {
	for executionID, record := range queue.records {
		if executionID != excludingID && record.execution.Pool == executionlease.PoolWrite &&
			record.execution.Production && actionLeaseActive(record.execution.Status) {
			return true
		}
	}
	return false
}

func actionLeaseActive(status executionlease.Status) bool {
	return status == executionlease.StatusLeased || status == executionlease.StatusRunning || status == executionlease.StatusUncertain
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
