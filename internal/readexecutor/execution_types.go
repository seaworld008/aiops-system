package readexecutor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/seaworld008/aiops-system/internal/readtask"
)

var (
	ErrExecutionRejected = errors.New("READ execution rejected")
	ErrStartRejected     = errors.New("READ execution start rejected")

	persistentTaskIDPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)
)

type executionStartSeal struct{ value byte }

var trustedExecutionStartSeal = &executionStartSeal{value: 1}

// ExecutionStart is an opaque projection of the authenticated Gateway start
// response. It carries no bearer and cannot be decoded from task payload JSON.
type ExecutionStart struct {
	taskID        string
	leaseEpoch    int64
	scopeRevision int64
	startedAt     time.Time
	seal          *executionStartSeal
	self          *ExecutionStart
}

func NewExecutionStart(
	taskID string,
	leaseEpoch int64,
	scopeRevision int64,
	startedAt time.Time,
) (*ExecutionStart, error) {
	if !persistentTaskIDPattern.MatchString(taskID) || leaseEpoch <= 0 || scopeRevision <= 0 ||
		!validExecutionTime(startedAt) || startedAt.Location() != time.UTC {
		return nil, ErrStartRejected
	}
	created := &ExecutionStart{
		taskID: taskID, leaseEpoch: leaseEpoch, scopeRevision: scopeRevision,
		startedAt: stripMonotonic(startedAt), seal: trustedExecutionStartSeal,
	}
	created.self = created
	return created, nil
}

func (start *ExecutionStart) ready() bool {
	return start != nil && start.self == start && start.seal == trustedExecutionStartSeal &&
		persistentTaskIDPattern.MatchString(start.taskID) && start.leaseEpoch > 0 && start.scopeRevision > 0 &&
		validExecutionTime(start.startedAt) && start.startedAt.Location() == time.UTC
}

func (ExecutionStart) String() string   { return "<aiops-read-execution-start>" }
func (ExecutionStart) GoString() string { return "<aiops-read-execution-start>" }
func (ExecutionStart) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "<aiops-read-execution-start>")
}
func (ExecutionStart) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*ExecutionStart) UnmarshalJSON([]byte) error  { return ErrStartRejected }

type preparedSeal struct{ value byte }

var trustedPreparedSeal = &preparedSeal{value: 1}

const (
	preparedReady uint32 = iota
	preparedConsumed
)

type preparedState struct{ status atomic.Uint32 }

// Prepared is a one-shot, secret-free execution capability. Its operational
// fields remain private so target, query and policy material cannot be logged.
type Prepared struct {
	taskID string
	seal   *preparedSeal
	self   *Prepared
	state  *preparedState

	// The concrete execution facts are declared in executor.go.
	values preparedValues
}

func (prepared *Prepared) ready() bool {
	return prepared != nil && prepared.self == prepared && prepared.seal == trustedPreparedSeal &&
		prepared.state != nil && prepared.state.status.Load() == preparedReady &&
		persistentTaskIDPattern.MatchString(prepared.taskID)
}

func (prepared *Prepared) consume() bool {
	return prepared != nil && prepared.self == prepared && prepared.seal == trustedPreparedSeal &&
		prepared.state != nil && prepared.state.status.CompareAndSwap(preparedReady, preparedConsumed)
}

func (Prepared) String() string   { return "<aiops-prepared-read-execution>" }
func (Prepared) GoString() string { return "<aiops-prepared-read-execution>" }
func (Prepared) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "<aiops-prepared-read-execution>")
}
func (Prepared) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*Prepared) UnmarshalJSON([]byte) error  { return ErrExecutionRejected }

// BearerSource obtains one short-lived bearer for the server-owned role ref.
// It must invoke use synchronously at most once, clear its byte slice before
// returning, stop no later than ctx.Done, and return only a low-cardinality
// failure code. Any remote provider call needs its own shorter timeout. Go
// cannot terminate an arbitrary blocked function, so C2-4 may install only a
// trusted, context-compliant adapter. The executor never returns or logs
// provider diagnostics.
type BearerSource func(
	context.Context,
	string,
	func([]byte),
) readtask.FailureCode

// Result is either complete evidence, a bounded failure, or control-plane
// cancellation. It contains no raw upstream error, body, headers or target.
type Result struct {
	outcome       readtask.CompletionOutcome
	evidence      *readtask.EvidenceCompletion
	failureCode   readtask.FailureCode
	taskID        string
	leaseEpoch    int64
	scopeRevision int64
}

func newEvidenceResult(evidence readtask.EvidenceCompletion) Result {
	return Result{outcome: readtask.CompletionEvidence, evidence: cloneEvidence(evidence)}
}

func newFailureResult(code readtask.FailureCode) Result {
	outcome := readtask.CompletionFailed
	if code == readtask.FailureCancelled {
		outcome = readtask.CompletionCancelled
	}
	return Result{outcome: outcome, failureCode: code}
}

func (result Result) Valid() bool {
	if !result.validBinding() {
		return false
	}
	switch result.outcome {
	case readtask.CompletionEvidence:
		return result.evidence != nil && result.evidence.Items != nil && result.failureCode == "" &&
			validExecutionTime(result.evidence.CollectedAt)
	case readtask.CompletionFailed:
		return result.evidence == nil && validExecutionFailure(result.failureCode) &&
			result.failureCode != readtask.FailureCancelled
	case readtask.CompletionCancelled:
		return result.evidence == nil && result.failureCode == readtask.FailureCancelled
	default:
		return false
	}
}

func (result Result) validBinding() bool {
	unbound := result.taskID == "" && result.leaseEpoch == 0 && result.scopeRevision == 0
	bound := persistentTaskIDPattern.MatchString(result.taskID) && result.leaseEpoch > 0 && result.scopeRevision > 0
	return unbound || bound
}

func bindResult(result Result, start *ExecutionStart) Result {
	if !result.Valid() || start == nil || !start.ready() {
		return Result{}
	}
	result.taskID = start.taskID
	result.leaseEpoch = start.leaseEpoch
	result.scopeRevision = start.scopeRevision
	return result
}

func (result Result) boundTo(start *ExecutionStart) bool {
	return result.Valid() && start != nil && start.ready() &&
		result.taskID == start.taskID && result.leaseEpoch == start.leaseEpoch &&
		result.scopeRevision == start.scopeRevision
}

func (result Result) Outcome() readtask.CompletionOutcome { return result.outcome }
func (result Result) FailureCode() readtask.FailureCode   { return result.failureCode }
func (result Result) Evidence() (readtask.EvidenceCompletion, bool) {
	if result.outcome != readtask.CompletionEvidence || result.evidence == nil {
		return readtask.EvidenceCompletion{}, false
	}
	return *cloneEvidence(*result.evidence), true
}

func (result Result) Completion(start *ExecutionStart, fence readtask.Fence) (readtask.Completion, error) {
	if !result.boundTo(start) || !fence.Valid() || fence.TaskID() != result.taskID ||
		fence.Epoch() != result.leaseEpoch {
		return readtask.Completion{}, ErrExecutionRejected
	}
	completion := readtask.Completion{Fence: fence, Outcome: result.outcome, FailureCode: result.failureCode}
	if result.outcome == readtask.CompletionEvidence {
		completion.Evidence = cloneEvidence(*result.evidence)
	}
	return completion, nil
}

func (Result) String() string   { return "<aiops-read-execution-result>" }
func (Result) GoString() string { return "<aiops-read-execution-result>" }
func (Result) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "<aiops-read-execution-result>")
}
func (Result) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*Result) UnmarshalJSON([]byte) error  { return ErrExecutionRejected }

func cloneEvidence(source readtask.EvidenceCompletion) *readtask.EvidenceCompletion {
	cloned := &readtask.EvidenceCompletion{CollectedAt: source.CollectedAt}
	if source.Items != nil {
		cloned.Items = make([]json.RawMessage, len(source.Items))
		for index := range source.Items {
			cloned.Items[index] = bytes.Clone(source.Items[index])
		}
	}
	return cloned
}

func validExecutionFailure(code readtask.FailureCode) bool {
	switch code {
	case readtask.FailureConnectorUnavailable, readtask.FailureRateLimited, readtask.FailureTimeout,
		readtask.FailureAuthentication, readtask.FailurePermissionDenied, readtask.FailureInvalidResponse,
		readtask.FailureResultRejected, readtask.FailureCancelled, readtask.FailureUnknown:
		return true
	default:
		return false
	}
}

func executionContextError(ctx context.Context) (returnedErr error) {
	defer func() {
		if recover() != nil {
			returnedErr = ErrExecutionRejected
		}
	}()
	if ctx == nil {
		return ErrExecutionRejected
	}
	value := reflect.ValueOf(ctx)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return ErrExecutionRejected
		}
	}
	return ctx.Err()
}

func validExecutionTime(value time.Time) bool {
	return !value.IsZero() && value.Year() >= 1 && value.Year() <= 9999
}

func stripMonotonic(value time.Time) time.Time {
	return value.Round(0).UTC()
}
