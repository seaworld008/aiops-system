package executionlease

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"sync"
	"time"
)

const (
	minLeaseDuration = time.Second
	maxLeaseDuration = 30 * time.Minute
)

var (
	resultHashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]*$`)
)

type MemoryOptions struct {
	Clock       func() time.Time
	TokenSource func() (string, error)
}

type MemoryRepository struct {
	mu          sync.Mutex
	executions  map[string]Execution
	order       []string
	clock       func() time.Time
	tokenSource func() (string, error)
}

var _ Repository = (*MemoryRepository)(nil)

func NewMemory(options MemoryOptions) (*MemoryRepository, error) {
	if options.Clock == nil {
		options.Clock = time.Now
	}
	if options.TokenSource == nil {
		options.TokenSource = randomToken
	}
	if options.Clock().IsZero() {
		return nil, fmt.Errorf("%w: clock returned zero time", ErrInvalidRequest)
	}
	return &MemoryRepository{
		executions:  make(map[string]Execution),
		clock:       options.Clock,
		tokenSource: options.TokenSource,
	}, nil
}

func (repository *MemoryRepository) Enqueue(ctx context.Context, request EnqueueRequest) (Execution, error) {
	if err := ctx.Err(); err != nil {
		return Execution{}, err
	}
	if !validIdentifier(request.ExecutionID, 256) || !validIdentifier(request.TargetKey, 512) || !validPool(request.Pool) {
		return Execution{}, ErrInvalidRequest
	}
	now, err := repository.now()
	if err != nil {
		return Execution{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if _, exists := repository.executions[request.ExecutionID]; exists {
		return Execution{}, ErrAlreadyExists
	}
	execution := Execution{
		ExecutionID: request.ExecutionID,
		TargetKey:   request.TargetKey,
		Pool:        request.Pool,
		Production:  request.Production,
		Status:      StatusQueued,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	repository.executions[execution.ExecutionID] = execution
	repository.order = append(repository.order, execution.ExecutionID)
	return execution, nil
}

func (repository *MemoryRepository) Claim(ctx context.Context, request ClaimRequest) (Execution, error) {
	if err := ctx.Err(); err != nil {
		return Execution{}, err
	}
	if !validPool(request.Pool) || !validIdentifier(request.RunnerID, 256) ||
		request.LeaseDuration < minLeaseDuration || request.LeaseDuration > maxLeaseDuration {
		return Execution{}, ErrInvalidRequest
	}
	now, err := repository.now()
	if err != nil {
		return Execution{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.expireLeases(now)
	if !request.ClaimsEnabled {
		return Execution{}, ErrClaimBlocked
	}

	for _, executionID := range repository.order {
		execution := repository.executions[executionID]
		if execution.Status != StatusQueued || execution.Pool != request.Pool {
			continue
		}
		if repository.targetUnavailable(execution.TargetKey, execution.ExecutionID) {
			continue
		}
		if execution.Pool == PoolWrite && execution.Production && repository.productionWriteActive(execution.ExecutionID) {
			continue
		}
		if execution.LeaseEpoch == math.MaxInt64 {
			return Execution{}, fmt.Errorf("%w: lease epoch exhausted", ErrInvalidTransition)
		}
		token, err := repository.tokenSource()
		if err != nil {
			return Execution{}, fmt.Errorf("generate execution lease token: %w", err)
		}
		if !validIdentifier(token, 256) {
			return Execution{}, fmt.Errorf("%w: token source returned an invalid token", ErrInvalidRequest)
		}
		execution.Status = StatusLeased
		execution.RunnerID = request.RunnerID
		execution.LeaseToken = token
		execution.LeaseEpoch++
		execution.LeaseAcquiredAt = now
		execution.LastHeartbeatAt = now
		execution.LeaseExpiresAt = now.Add(request.LeaseDuration)
		execution.UpdatedAt = now
		repository.executions[executionID] = execution
		return execution, nil
	}
	return Execution{}, ErrNoLeaseAvailable
}

func (repository *MemoryRepository) Start(ctx context.Context, lease LeaseIdentity) (Execution, error) {
	if err := ctx.Err(); err != nil {
		return Execution{}, err
	}
	if !validLease(lease) {
		return Execution{}, ErrInvalidRequest
	}
	now, err := repository.now()
	if err != nil {
		return Execution{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	execution, exists := repository.executions[lease.ExecutionID]
	if !exists {
		return Execution{}, ErrNotFound
	}
	if !currentLease(execution, lease, now) {
		return Execution{}, ErrStaleLease
	}
	switch execution.Status {
	case StatusLeased:
		execution.Status = StatusRunning
		execution.StartedAt = now
		execution.UpdatedAt = now
		repository.executions[execution.ExecutionID] = execution
	case StatusRunning:
	default:
		return Execution{}, ErrInvalidTransition
	}
	return execution, nil
}

func (repository *MemoryRepository) Heartbeat(ctx context.Context, request HeartbeatRequest) (Execution, error) {
	if err := ctx.Err(); err != nil {
		return Execution{}, err
	}
	if !validLease(request.Lease) || request.Extension < minLeaseDuration || request.Extension > maxLeaseDuration {
		return Execution{}, ErrInvalidRequest
	}
	now, err := repository.now()
	if err != nil {
		return Execution{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	execution, exists := repository.executions[request.Lease.ExecutionID]
	if !exists {
		return Execution{}, ErrNotFound
	}
	if !currentLease(execution, request.Lease, now) {
		return Execution{}, ErrStaleLease
	}
	execution.LeaseExpiresAt = now.Add(request.Extension)
	execution.LastHeartbeatAt = now
	execution.UpdatedAt = now
	repository.executions[execution.ExecutionID] = execution
	return execution, nil
}

func (repository *MemoryRepository) Complete(ctx context.Context, request CompleteRequest) (Execution, error) {
	if err := ctx.Err(); err != nil {
		return Execution{}, err
	}
	if !validLease(request.Lease) ||
		(request.Status != StatusSucceeded && request.Status != StatusFailed && request.Status != StatusUncertain) ||
		!resultHashPattern.MatchString(request.ResultHash) {
		return Execution{}, ErrInvalidRequest
	}
	now, err := repository.now()
	if err != nil {
		return Execution{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	execution, exists := repository.executions[request.Lease.ExecutionID]
	if !exists {
		return Execution{}, ErrNotFound
	}
	if terminalStatus(execution.Status) {
		if execution.ReconciliationID != "" {
			return Execution{}, ErrStaleLease
		}
		if execution.RunnerID != request.Lease.RunnerID || execution.LeaseToken != request.Lease.Token ||
			execution.LeaseEpoch != request.Lease.Epoch {
			return Execution{}, ErrStaleLease
		}
		if execution.Status == request.Status && execution.ResultHash == request.ResultHash {
			return redactedExecution(execution), nil
		}
		return Execution{}, ErrCompletionConflict
	}
	if !currentLease(execution, request.Lease, now) {
		return Execution{}, ErrStaleLease
	}
	if execution.Status != StatusRunning {
		return Execution{}, ErrInvalidTransition
	}
	execution.Status = request.Status
	execution.ResultHash = request.ResultHash
	execution.CompletedAt = now
	execution.LeaseExpiresAt = time.Time{}
	execution.UpdatedAt = now
	repository.executions[execution.ExecutionID] = execution
	return redactedExecution(execution), nil
}

func (repository *MemoryRepository) Reconcile(ctx context.Context, request ReconcileRequest) (Execution, error) {
	if err := ctx.Err(); err != nil {
		return Execution{}, err
	}
	if !validIdentifier(request.ExecutionID, 256) ||
		!validIdentifier(request.ReconciliationID, 256) ||
		!validIdentifier(request.ActorID, 256) ||
		(request.Status != StatusSucceeded && request.Status != StatusFailed) ||
		!resultHashPattern.MatchString(request.ResultHash) {
		return Execution{}, ErrInvalidRequest
	}
	now, err := repository.now()
	if err != nil {
		return Execution{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.expireLeases(now)
	execution, exists := repository.executions[request.ExecutionID]
	if !exists {
		return Execution{}, ErrNotFound
	}
	if execution.ReconciliationID != "" {
		if execution.ReconciliationID == request.ReconciliationID &&
			execution.ReconciliationActor == request.ActorID &&
			execution.Status == request.Status && execution.ReconciliationResultHash == request.ResultHash {
			return redactedExecution(execution), nil
		}
		return Execution{}, ErrReconciliationConflict
	}
	if execution.Status != StatusUncertain {
		return Execution{}, ErrInvalidTransition
	}
	for executionID, existing := range repository.executions {
		if executionID != execution.ExecutionID && existing.ReconciliationID == request.ReconciliationID {
			return Execution{}, ErrReconciliationConflict
		}
	}
	execution.Status = request.Status
	execution.ReconciliationResultHash = request.ResultHash
	execution.ReconciliationID = request.ReconciliationID
	execution.ReconciliationActor = request.ActorID
	execution.ReconciledAt = now
	execution.UpdatedAt = now
	repository.executions[execution.ExecutionID] = execution
	return redactedExecution(execution), nil
}

func (repository *MemoryRepository) SweepExpired(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	now, err := repository.now()
	if err != nil {
		return err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.expireLeases(now)
	return nil
}

func (repository *MemoryRepository) Cancel(ctx context.Context, executionID string) (Execution, error) {
	if err := ctx.Err(); err != nil {
		return Execution{}, err
	}
	if !validIdentifier(executionID, 256) {
		return Execution{}, ErrInvalidRequest
	}
	now, err := repository.now()
	if err != nil {
		return Execution{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	execution, exists := repository.executions[executionID]
	if !exists {
		return Execution{}, ErrNotFound
	}
	if terminalStatus(execution.Status) {
		return redactedExecution(execution), nil
	}
	wasRunning := execution.Status == StatusRunning
	if wasRunning {
		execution.Status = StatusUncertain
	} else {
		execution.Status = StatusCancelled
		execution.RunnerID = ""
	}
	execution.LeaseToken = ""
	execution.LeaseExpiresAt = time.Time{}
	execution.CompletedAt = now
	execution.UpdatedAt = now
	repository.executions[execution.ExecutionID] = execution
	return redactedExecution(execution), nil
}

func (repository *MemoryRepository) Get(ctx context.Context, executionID string) (Execution, error) {
	if err := ctx.Err(); err != nil {
		return Execution{}, err
	}
	if !validIdentifier(executionID, 256) {
		return Execution{}, ErrInvalidRequest
	}
	now, err := repository.now()
	if err != nil {
		return Execution{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.expireLeases(now)
	execution, exists := repository.executions[executionID]
	if !exists {
		return Execution{}, ErrNotFound
	}
	return redactedExecution(execution), nil
}

func (repository *MemoryRepository) expireLeases(now time.Time) {
	for executionID, execution := range repository.executions {
		if execution.LeaseExpiresAt.IsZero() || now.Before(execution.LeaseExpiresAt) {
			continue
		}
		switch execution.Status {
		case StatusLeased:
			execution.Status = StatusQueued
			execution.RunnerID = ""
			execution.LeaseToken = ""
			execution.LeaseAcquiredAt = time.Time{}
			execution.LastHeartbeatAt = time.Time{}
			execution.LeaseExpiresAt = time.Time{}
			execution.UpdatedAt = now
		case StatusRunning:
			execution.Status = StatusUncertain
			execution.LeaseToken = ""
			execution.LeaseExpiresAt = time.Time{}
			execution.CompletedAt = now
			execution.UpdatedAt = now
		default:
			continue
		}
		repository.executions[executionID] = execution
	}
}

func (repository *MemoryRepository) targetUnavailable(targetKey, candidateID string) bool {
	for executionID, execution := range repository.executions {
		if executionID == candidateID || execution.TargetKey != targetKey {
			continue
		}
		if execution.Status == StatusLeased || execution.Status == StatusRunning || execution.Status == StatusUncertain {
			return true
		}
	}
	return false
}

func (repository *MemoryRepository) productionWriteActive(candidateID string) bool {
	for executionID, execution := range repository.executions {
		if executionID != candidateID && execution.Pool == PoolWrite && execution.Production &&
			(execution.Status == StatusLeased || execution.Status == StatusRunning || execution.Status == StatusUncertain) {
			return true
		}
	}
	return false
}

func (repository *MemoryRepository) now() (time.Time, error) {
	now := repository.clock().UTC()
	if now.IsZero() {
		return time.Time{}, fmt.Errorf("%w: clock returned zero time", ErrInvalidRequest)
	}
	return now, nil
}

func currentLease(execution Execution, lease LeaseIdentity, now time.Time) bool {
	return lease.ExecutionID == execution.ExecutionID && lease.RunnerID == execution.RunnerID &&
		lease.Token == execution.LeaseToken &&
		lease.Epoch > 0 && lease.Epoch == execution.LeaseEpoch &&
		(execution.Status == StatusLeased || execution.Status == StatusRunning) && now.Before(execution.LeaseExpiresAt)
}

func validPool(pool Pool) bool {
	return pool == PoolRead || pool == PoolWrite
}

func validLease(lease LeaseIdentity) bool {
	return validIdentifier(lease.ExecutionID, 256) && validIdentifier(lease.RunnerID, 256) &&
		validIdentifier(lease.Token, 256) && lease.Epoch > 0
}

func validIdentifier(value string, maxBytes int) bool {
	return len(value) <= maxBytes && identifierPattern.MatchString(value)
}

func redactedExecution(execution Execution) Execution {
	execution.LeaseToken = ""
	return execution
}

func randomToken() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
