package readtask

import (
	"fmt"
	"io"

	"github.com/seaworld008/aiops-system/internal/domain"
)

// RecoveryRequest is the server-owned identity required to resolve one
// durable READ task result. TenantID is comparison-only and is never part of
// a recovery response.
type RecoveryRequest struct {
	TenantID        string
	WorkspaceID     string
	IncidentID      string
	InvestigationID string
	TaskID          string
	Position        int
	PlanBinding     domain.InvestigationPlanBinding
}

func (request RecoveryRequest) Validate() error {
	for _, identifier := range []string{
		request.TenantID, request.WorkspaceID, request.IncidentID,
		request.InvestigationID, request.TaskID,
	} {
		if !validPersistentUUID(identifier) {
			return ErrInvalidRequest
		}
	}
	if request.Position < 1 || request.Position > 12 || request.PlanBinding.Validate() != nil {
		return ErrInvalidRequest
	}
	return nil
}

func (request RecoveryRequest) String() string {
	return fmt.Sprintf("ReadTaskRecoveryRequest{TaskID:%q Security:[REDACTED]}", request.TaskID)
}
func (request RecoveryRequest) GoString() string { return request.String() }
func (request RecoveryRequest) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, request.String())
}
func (RecoveryRequest) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*RecoveryRequest) UnmarshalJSON([]byte) error  { return ErrInvalidRequest }

// CommittedResult is a receipt-only reconstruction of an immutable v3 READ
// completion. It deliberately carries no original completion body.
type CommittedResult struct {
	Attempt    Attempt
	Receipt    Receipt
	TaskStatus domain.ReadTaskStatus
	EvidenceID string
	ReceiptID  string
}

func (result CommittedResult) ValidateAgainst(descriptor Descriptor) error {
	if result.Attempt.Status != AttemptCompleted || result.Attempt.ValidateAgainst(descriptor) != nil ||
		result.Receipt.ValidateAgainst(descriptor, result.Attempt) != nil ||
		!validPersistentUUID(result.ReceiptID) {
		return ErrInvalidRequest
	}
	switch result.TaskStatus {
	case domain.ReadTaskEvidence:
		if result.Receipt.Outcome != CompletionEvidence || !validPersistentUUID(result.EvidenceID) {
			return ErrInvalidRequest
		}
	case domain.ReadTaskFailed:
		if result.Receipt.Outcome != CompletionFailed || result.EvidenceID != "" {
			return ErrInvalidRequest
		}
	case domain.ReadTaskCancelled:
		if result.Receipt.Outcome != CompletionCancelled || result.EvidenceID != "" {
			return ErrInvalidRequest
		}
	default:
		return ErrInvalidRequest
	}
	return nil
}

func (result CommittedResult) String() string {
	return fmt.Sprintf("ReadTaskCommittedResult{TaskID:%q TaskStatus:%q Security:[REDACTED]}",
		result.Attempt.TaskID, result.TaskStatus)
}
func (result CommittedResult) GoString() string { return result.String() }
func (result CommittedResult) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, result.String())
}
func (CommittedResult) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*CommittedResult) UnmarshalJSON([]byte) error  { return ErrInvalidRequest }

type RecoveryState string

const (
	RecoveryPending          RecoveryState = "PENDING"
	RecoveryCommitted        RecoveryState = "COMMITTED"
	RecoveryControlCancelled RecoveryState = "CONTROL_CANCELLED"
)

// RecoveryResult is the task-level, secret-free result returned to trusted
// control-plane/Temporal recovery. Original attempt identity is intentionally
// absent.
type RecoveryResult struct {
	State           RecoveryState
	InvestigationID string
	TaskID          string
	Position        int
	TaskStatus      domain.ReadTaskStatus
	EvidenceID      string
	ContentHash     string
	ReceiptID       string
	ReceiptHash     string
}

func (result RecoveryResult) ValidateAgainst(request RecoveryRequest) error {
	if request.Validate() != nil || result.InvestigationID != request.InvestigationID ||
		result.TaskID != request.TaskID || result.Position != request.Position {
		return ErrInvalidRequest
	}
	switch result.State {
	case RecoveryPending:
		if (result.TaskStatus != domain.ReadTaskQueued && result.TaskStatus != domain.ReadTaskRunning) ||
			result.EvidenceID != "" || result.ContentHash != "" || result.ReceiptID != "" || result.ReceiptHash != "" {
			return ErrInvalidRequest
		}
	case RecoveryCommitted:
		if !validPersistentUUID(result.ReceiptID) || !validSHA256(result.ReceiptHash) {
			return ErrInvalidRequest
		}
		switch result.TaskStatus {
		case domain.ReadTaskEvidence:
			if !validPersistentUUID(result.EvidenceID) || !validSHA256(result.ContentHash) {
				return ErrInvalidRequest
			}
		case domain.ReadTaskFailed, domain.ReadTaskCancelled:
			if result.EvidenceID != "" || result.ContentHash != "" {
				return ErrInvalidRequest
			}
		default:
			return ErrInvalidRequest
		}
	case RecoveryControlCancelled:
		if result.TaskStatus != domain.ReadTaskCancelled || result.EvidenceID != "" ||
			result.ContentHash != "" || result.ReceiptID != "" || result.ReceiptHash != "" {
			return ErrInvalidRequest
		}
	default:
		return ErrInvalidRequest
	}
	return nil
}

func (result RecoveryResult) String() string {
	return fmt.Sprintf("ReadTaskRecoveryResult{TaskID:%q State:%q TaskStatus:%q Security:[REDACTED]}",
		result.TaskID, result.State, result.TaskStatus)
}
func (result RecoveryResult) GoString() string { return result.String() }
func (result RecoveryResult) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, result.String())
}
func (RecoveryResult) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*RecoveryResult) UnmarshalJSON([]byte) error  { return ErrInvalidRequest }
