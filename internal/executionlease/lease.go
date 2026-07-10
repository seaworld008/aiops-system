package executionlease

import (
	"context"
	"errors"
	"time"
)

var (
	ErrAlreadyExists          = errors.New("execution already exists")
	ErrNotFound               = errors.New("execution not found")
	ErrNoLeaseAvailable       = errors.New("no execution lease available")
	ErrStaleLease             = errors.New("stale execution lease")
	ErrInvalidTransition      = errors.New("invalid execution state transition")
	ErrCompletionConflict     = errors.New("execution completion conflicts with recorded result")
	ErrReconciliationConflict = errors.New("execution reconciliation conflicts with recorded decision")
	ErrClaimBlocked           = errors.New("execution claims are disabled")
	ErrInvalidRequest         = errors.New("invalid execution lease request")
)

type Pool string

const (
	PoolRead  Pool = "READ"
	PoolWrite Pool = "WRITE"
)

type Status string

const (
	StatusQueued     Status = "QUEUED"
	StatusLeased     Status = "LEASED"
	StatusRunning    Status = "RUNNING"
	StatusFinalizing Status = "FINALIZING"
	StatusSucceeded  Status = "SUCCEEDED"
	StatusFailed     Status = "FAILED"
	StatusCancelled  Status = "CANCELLED"
	StatusUncertain  Status = "UNCERTAIN"
)

type Execution struct {
	ExecutionID              string
	TargetKey                string
	Pool                     Pool
	Production               bool
	Status                   Status
	CompletionStatus         Status
	RunnerID                 string
	ScopeRevision            int64
	LeaseToken               string
	LeaseEpoch               int64
	LeaseExpiresAt           time.Time
	LeaseAcquiredAt          time.Time
	LastHeartbeatAt          time.Time
	HeartbeatSeq             int64
	CancelRequestedAt        time.Time
	CancelReasonHash         string
	StartedAt                time.Time
	CompletedAt              time.Time
	ResultHash               string
	ReconciliationResultHash string
	ReconciliationID         string
	ReconciliationActor      string
	ReconciledAt             time.Time
	CreatedAt                time.Time
	UpdatedAt                time.Time
}

func (execution Execution) Fence() LeaseIdentity {
	return LeaseIdentity{
		ExecutionID: execution.ExecutionID,
		RunnerID:    execution.RunnerID,
		Token:       execution.LeaseToken,
		Epoch:       execution.LeaseEpoch,
	}
}

func (execution Execution) Terminal() bool {
	return terminalStatus(execution.Status)
}

type LeaseIdentity struct {
	ExecutionID string
	RunnerID    string
	Token       string
	Epoch       int64
}

type EnqueueRequest struct {
	ExecutionID string
	TargetKey   string
	Pool        Pool
	Production  bool
}

type ClaimRequest struct {
	Pool          Pool
	RunnerID      string
	LeaseDuration time.Duration
	ClaimsEnabled bool
}

type HeartbeatRequest struct {
	Lease     LeaseIdentity
	Extension time.Duration
}

type CompleteRequest struct {
	Lease      LeaseIdentity
	Status     Status
	ResultHash string
}

type ReconcileRequest struct {
	ExecutionID      string
	ReconciliationID string
	ActorID          string
	Status           Status
	ResultHash       string
}

type Repository interface {
	Enqueue(context.Context, EnqueueRequest) (Execution, error)
	Claim(context.Context, ClaimRequest) (Execution, error)
	Start(context.Context, LeaseIdentity) (Execution, error)
	Heartbeat(context.Context, HeartbeatRequest) (Execution, error)
	Complete(context.Context, CompleteRequest) (Execution, error)
	Reconcile(context.Context, ReconcileRequest) (Execution, error)
	SweepExpired(context.Context) error
	Cancel(context.Context, string) (Execution, error)
	Get(context.Context, string) (Execution, error)
}

func terminalStatus(status Status) bool {
	return status == StatusSucceeded || status == StatusFailed || status == StatusCancelled || status == StatusUncertain
}
