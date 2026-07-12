// Package readrunnerclient implements the outbound-only, READ-pool subset of
// the Runner Gateway v1 protocol. It intentionally contains no WRITE job,
// credential, revocation, action, or arbitrary command API.
package readrunnerclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/readtask"
	"github.com/seaworld008/aiops-system/internal/runneridentity"
)

var (
	ErrInvalidConfiguration = errors.New("invalid READ Runner Gateway client configuration")
	ErrInvalidExpectedTask  = errors.New("invalid expected READ task")
	ErrInvalidResponse      = errors.New("invalid READ Runner Gateway response")
	ErrInvalidLease         = errors.New("invalid READ task lease")
	ErrInvalidCompletion    = errors.New("invalid READ task completion")
	ErrRedirectRejected     = errors.New("READ Runner Gateway redirects are forbidden")
)

// Options names dedicated Runner Gateway trust material. ExpectedPool must be
// READ; keeping it explicit prevents configuration intended for a WRITE trust
// domain from being silently accepted by this process.
type Options struct {
	BaseURL               string
	ServerName            string
	TrustDomain           string
	ExpectedPool          runneridentity.Pool
	RootCAFile            string
	ClientCertificateFile string
	ClientPrivateKeyFile  string
}

// ExpectedTask is the trusted scheduler-owned identity for one exact task.
// Facts absent from the Gateway wire are used to recompute and verify the
// server-owned runtime digest before a lease is accepted.
type ExpectedTask struct {
	TenantID        string
	WorkspaceID     string
	EnvironmentID   string
	ServiceID       string
	IncidentID      string
	InvestigationID string
	TaskID          string
	Position        int
	PlanBinding     domain.InvestigationPlanBinding
}

// HeartbeatResult is a bounded, secret-free lease update.
type HeartbeatResult struct {
	AcceptedSequence      int64
	Directive             readtask.HeartbeatDirective
	LeaseExpiresAt        time.Time
	HeartbeatAfterSeconds int
}

// CompletionReceipt contains only the bounded identifiers and hashes returned
// after the Gateway has durably projected a completion.
type CompletionReceipt struct {
	TaskID      string
	LeaseEpoch  int64
	TaskStatus  string
	EvidenceID  string
	ContentHash string
	ReceiptID   string
	ReceiptHash string
	Replayed    bool
}

// Completion is the secret-free executor outcome accepted by Complete. It
// deliberately has no Fence, token, task, runner, scope, connector, target,
// certificate, or caller-supplied hash field; those are bound from Lease and
// StartCapability or recomputed by the Gateway.
type Completion struct {
	Outcome     readtask.CompletionOutcome
	Evidence    *readtask.EvidenceCompletion
	FailureCode readtask.FailureCode
}

func (completion Completion) String() string   { return "ReadTaskCompletion{Security:[REDACTED]}" }
func (completion Completion) GoString() string { return completion.String() }
func (completion Completion) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, completion.String())
}
func (Completion) MarshalJSON() ([]byte, error) { return marshalRedacted() }
func (*Completion) UnmarshalJSON([]byte) error  { return ErrInvalidCompletion }

func cloneEvidence(source *readtask.EvidenceCompletion) *readtask.EvidenceCompletion {
	if source == nil {
		return nil
	}
	cloned := &readtask.EvidenceCompletion{CollectedAt: source.CollectedAt}
	if source.Items != nil {
		cloned.Items = make([]json.RawMessage, len(source.Items))
		for index := range source.Items {
			cloned.Items[index] = append(json.RawMessage(nil), source.Items[index]...)
		}
	}
	return cloned
}

// ProblemError is the validated, bounded RFC 9457 subset safe for control
// flow and logs. Remote detail is validated but deliberately discarded.
type ProblemError struct {
	Type     string
	Status   int
	Code     string
	Instance string
}

func (problem ProblemError) String() string   { return (&problem).Error() }
func (problem ProblemError) GoString() string { return (&problem).Error() }
func (problem ProblemError) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, (&problem).Error())
}
func (ProblemError) MarshalJSON() ([]byte, error) { return marshalRedacted() }
func (*ProblemError) UnmarshalJSON([]byte) error  { return ErrInvalidResponse }

func (problem *ProblemError) Error() string {
	if problem == nil {
		return "READ Runner Gateway request rejected"
	}
	return fmt.Sprintf("READ Runner Gateway request rejected: status=%d code=%s", problem.Status, problem.Code)
}

type leasePhase uint8

const (
	leasePhaseClaimed leasePhase = iota + 1
	leasePhaseRunning
	leasePhaseTerminal
	leasePhaseInvalid
)

type leaseSeal struct{ value byte }
type startSeal struct{ value byte }

var (
	trustedLeaseSeal = &leaseSeal{value: 1}
	trustedStartSeal = &startSeal{value: 1}
)

// Lease is the sole owner of a raw lease bearer. It has no token accessor,
// rejects value copies, and becomes unusable after a terminal or ambiguous
// operation.
type Lease struct {
	state *leaseState
	seal  *leaseSeal
	self  *Lease
}

func (lease *Lease) Descriptor() readtask.Descriptor {
	if !lease.ready() {
		return readtask.Descriptor{}
	}
	lease.state.mu.Lock()
	defer lease.state.mu.Unlock()
	return cloneDescriptor(lease.state.descriptor)
}

func (lease *Lease) TaskID() string {
	if !lease.ready() {
		return ""
	}
	return lease.state.taskID
}

func (lease *Lease) LeaseEpoch() int64 {
	if !lease.ready() {
		return 0
	}
	return lease.state.leaseEpoch
}

func (lease *Lease) ScopeRevision() int64 {
	if !lease.ready() {
		return 0
	}
	return lease.state.scopeRevision
}

func (lease *Lease) LeaseExpiresAt() time.Time {
	if !lease.ready() {
		return time.Time{}
	}
	lease.state.mu.Lock()
	defer lease.state.mu.Unlock()
	return lease.state.leaseExpiresAt
}

func (lease *Lease) HeartbeatAfterSeconds() int {
	if !lease.ready() {
		return 0
	}
	return lease.state.heartbeatAfterSeconds
}

func (lease *Lease) Destroy() {
	if lease == nil || lease.self != lease || lease.seal != trustedLeaseSeal || lease.state == nil {
		return
	}
	lease.state.destroy()
}

func (Lease) String() string   { return "ReadTaskLease{Security:[REDACTED]}" }
func (Lease) GoString() string { return "ReadTaskLease{Security:[REDACTED]}" }
func (Lease) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "ReadTaskLease{Security:[REDACTED]}")
}
func (Lease) MarshalJSON() ([]byte, error) { return marshalRedacted() }
func (*Lease) UnmarshalJSON([]byte) error  { return ErrInvalidLease }

// StartCapability is the opaque, non-copyable proof of a successful
// authenticated start. It carries no bearer and has no public constructor.
type StartCapability struct {
	taskID        string
	leaseEpoch    int64
	scopeRevision int64
	startedAt     time.Time
	lease         *leaseState
	seal          *startSeal
	self          *StartCapability
}

func (capability *StartCapability) TaskID() string {
	if !capability.ready() {
		return ""
	}
	return capability.taskID
}

func (capability *StartCapability) LeaseEpoch() int64 {
	if !capability.ready() {
		return 0
	}
	return capability.leaseEpoch
}

func (capability *StartCapability) ScopeRevision() int64 {
	if !capability.ready() {
		return 0
	}
	return capability.scopeRevision
}

func (capability *StartCapability) StartedAt() time.Time {
	if !capability.ready() {
		return time.Time{}
	}
	return capability.startedAt
}

func (StartCapability) String() string   { return "ReadTaskStartCapability{Security:[REDACTED]}" }
func (StartCapability) GoString() string { return "ReadTaskStartCapability{Security:[REDACTED]}" }
func (StartCapability) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "ReadTaskStartCapability{Security:[REDACTED]}")
}
func (StartCapability) MarshalJSON() ([]byte, error) { return marshalRedacted() }
func (*StartCapability) UnmarshalJSON([]byte) error  { return ErrInvalidResponse }
