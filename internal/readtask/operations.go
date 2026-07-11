package readtask

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"regexp"
	"time"
)

var idempotencyKeyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]{0,127}$`)

type Start struct {
	Fence Fence
}

func (start Start) ValidateAgainst(descriptor Descriptor, attempt Attempt) error {
	if (attempt.Status != AttemptLeased && attempt.Status != AttemptRunning) ||
		!fenceMatches(start.Fence, descriptor, attempt) {
		return ErrInvalidRequest
	}
	return nil
}

func (Start) MarshalJSON() ([]byte, error)         { return []byte(`{"redacted":true}`), nil }
func (*Start) UnmarshalJSON([]byte) error          { return ErrInvalidRequest }
func (start Start) String() string                 { return sensitiveOperationString("Start", start.Fence) }
func (start Start) GoString() string               { return start.String() }
func (start Start) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, start.String()) }

type Heartbeat struct {
	Fence    Fence
	Sequence int64
}

func (heartbeat Heartbeat) ValidateAgainst(descriptor Descriptor, attempt Attempt) error {
	if attempt.Status != AttemptRunning || attempt.HeartbeatSequence == math.MaxInt64 ||
		heartbeat.Sequence != attempt.HeartbeatSequence+1 ||
		!fenceMatches(heartbeat.Fence, descriptor, attempt) {
		return ErrInvalidRequest
	}
	return nil
}

type HeartbeatDirective string

const (
	HeartbeatContinue  HeartbeatDirective = "CONTINUE"
	HeartbeatTerminate HeartbeatDirective = "TERMINATE"
)

type HeartbeatResult struct {
	Attempt          Attempt
	AcceptedSequence int64
	Directive        HeartbeatDirective
	LeaseExpiresAt   time.Time
}

func (result HeartbeatResult) ValidateAgainst(descriptor Descriptor) error {
	if result.Attempt.ValidateAgainst(descriptor) != nil || result.AcceptedSequence <= 0 ||
		result.AcceptedSequence != result.Attempt.HeartbeatSequence ||
		!result.LeaseExpiresAt.Equal(result.Attempt.LeaseExpiresAt) {
		return ErrInvalidRequest
	}
	if result.Directive == HeartbeatContinue && result.Attempt.Status == AttemptRunning {
		return nil
	}
	if result.Directive == HeartbeatTerminate && result.Attempt.Status == AttemptCancelled {
		return nil
	}
	return ErrInvalidRequest
}

func (Heartbeat) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*Heartbeat) UnmarshalJSON([]byte) error  { return ErrInvalidRequest }
func (heartbeat Heartbeat) String() string {
	return sensitiveOperationString("Heartbeat", heartbeat.Fence)
}
func (heartbeat Heartbeat) GoString() string { return heartbeat.String() }
func (heartbeat Heartbeat) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, heartbeat.String())
}

type ReleaseReason string

const (
	ReleaseLocalCapacityUnavailable ReleaseReason = "LOCAL_CAPACITY_UNAVAILABLE"
	ReleaseConnectorNotReady        ReleaseReason = "CONNECTOR_NOT_READY"
	ReleaseTransientRunnerFailure   ReleaseReason = "TRANSIENT_RUNNER_FAILURE"
)

type Release struct {
	Fence      Fence
	ReasonCode ReleaseReason
}

func (release Release) ValidateAgainst(descriptor Descriptor, attempt Attempt) error {
	if attempt.Status != AttemptLeased || !fenceMatches(release.Fence, descriptor, attempt) {
		return ErrInvalidRequest
	}
	switch release.ReasonCode {
	case ReleaseLocalCapacityUnavailable, ReleaseConnectorNotReady, ReleaseTransientRunnerFailure:
		return nil
	default:
		return ErrInvalidRequest
	}
}

func (Release) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*Release) UnmarshalJSON([]byte) error  { return ErrInvalidRequest }
func (release Release) String() string       { return sensitiveOperationString("Release", release.Fence) }
func (release Release) GoString() string     { return release.String() }
func (release Release) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, release.String())
}

type CompletionOutcome string

const (
	CompletionEvidence  CompletionOutcome = "EVIDENCE"
	CompletionFailed    CompletionOutcome = "FAILED"
	CompletionCancelled CompletionOutcome = "CANCELLED"
)

type FailureCode string

const (
	FailureConnectorUnavailable FailureCode = "connector_unavailable"
	FailureRateLimited          FailureCode = "rate_limited"
	FailureTimeout              FailureCode = "timeout"
	FailureAuthentication       FailureCode = "authentication_failed"
	FailurePermissionDenied     FailureCode = "permission_denied"
	FailureInvalidResponse      FailureCode = "invalid_response"
	FailureResultRejected       FailureCode = "result_rejected"
	FailureCancelled            FailureCode = "cancelled"
	FailureUnknown              FailureCode = "unknown"
)

type EvidenceCompletion struct {
	CollectedAt time.Time
	Items       []json.RawMessage
}

// Completion has no field for raw errors, identity, certificate, scope,
// connector, operation, target, or credential. Those facts are server-owned.
type Completion struct {
	Fence       Fence
	Outcome     CompletionOutcome
	Evidence    *EvidenceCompletion
	FailureCode FailureCode
}

func (completion Completion) ValidateAgainst(descriptor Descriptor, attempt Attempt) error {
	if (attempt.Status != AttemptRunning && attempt.Status != AttemptCompleted) ||
		!fenceMatches(completion.Fence, descriptor, attempt) {
		return ErrInvalidRequest
	}
	switch completion.Outcome {
	case CompletionEvidence:
		if completion.Evidence == nil || completion.FailureCode != "" {
			return ErrInvalidRequest
		}
	case CompletionFailed:
		if completion.Evidence != nil || !validFailureCode(completion.FailureCode) || completion.FailureCode == FailureCancelled {
			return ErrInvalidRequest
		}
	case CompletionCancelled:
		if completion.Evidence != nil || completion.FailureCode != FailureCancelled {
			return ErrInvalidRequest
		}
	default:
		return ErrInvalidRequest
	}
	return nil
}

func (Completion) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*Completion) UnmarshalJSON([]byte) error  { return ErrInvalidRequest }
func (completion Completion) String() string {
	return sensitiveOperationString("Completion", completion.Fence)
}
func (completion Completion) GoString() string { return completion.String() }
func (completion Completion) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, completion.String())
}

type CompletionResult struct {
	Attempt    Attempt
	Projection ProjectedCompletion
	EvidenceID string
	ReceiptID  string
	Replayed   bool
}

func (result CompletionResult) ValidateAgainst(descriptor Descriptor) error {
	if result.Attempt.Status != AttemptCompleted || result.Attempt.ValidateAgainst(descriptor) != nil ||
		result.Projection.ValidateAgainst(descriptor, result.Attempt) != nil || !validPersistentUUID(result.ReceiptID) {
		return ErrInvalidRequest
	}
	if result.Projection.Outcome() == CompletionEvidence {
		if !validPersistentUUID(result.EvidenceID) {
			return ErrInvalidRequest
		}
	} else if result.EvidenceID != "" {
		return ErrInvalidRequest
	}
	return nil
}

func (result CompletionResult) String() string {
	return fmt.Sprintf("ReadTaskCompletionResult{TaskID:%q Outcome:%q Replayed:%t Security:[REDACTED]}",
		result.Attempt.TaskID, result.Projection.Outcome(), result.Replayed)
}
func (result CompletionResult) GoString() string { return result.String() }
func (result CompletionResult) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, result.String())
}
func (CompletionResult) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*CompletionResult) UnmarshalJSON([]byte) error  { return ErrInvalidRequest }

func validFailureCode(code FailureCode) bool {
	switch code {
	case FailureConnectorUnavailable, FailureRateLimited, FailureTimeout, FailureAuthentication,
		FailurePermissionDenied, FailureInvalidResponse, FailureResultRejected, FailureCancelled, FailureUnknown:
		return true
	default:
		return false
	}
}

func fenceMatches(fence Fence, descriptor Descriptor, attempt Attempt) bool {
	return descriptor.Validate() == nil && attempt.ValidateAgainst(descriptor) == nil && fence.Valid() &&
		fence.TaskID() == descriptor.TaskID && fence.TaskID() == attempt.TaskID &&
		fence.RunnerID() == attempt.RunnerID && fence.Epoch() == attempt.Epoch &&
		fence.MatchesTokenSHA256(attempt.TokenSHA256)
}

func sensitiveOperationString(name string, fence Fence) string {
	return fmt.Sprintf("ReadTask%s{TaskID:%q Epoch:%d Security:[REDACTED]}", name, fence.TaskID(), fence.Epoch())
}
