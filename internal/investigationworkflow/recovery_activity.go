package investigationworkflow

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/readtask"
	"go.temporal.io/sdk/temporal"
)

const RecoveryActivitySchemaVersion = 1

const (
	recoveryInputInvalidErrorType      = "READ_RESULT_RECOVERY_INPUT_INVALID"
	recoveryNotFoundErrorType          = "READ_RESULT_RECOVERY_NOT_FOUND"
	recoveryIntegrityRejectedErrorType = "READ_RESULT_RECOVERY_INTEGRITY_REJECTED"
	recoveryResultInvalidErrorType     = "READ_RESULT_RECOVERY_RESULT_INVALID"
	recoveryDependencyErrorType        = "READ_RESULT_RECOVERY_DEPENDENCY_UNAVAILABLE"
)

var (
	ErrInvalidRecoveryInput  = errors.New("investigation READ result recovery input rejected")
	ErrInvalidRecoveryResult = errors.New("investigation READ result recovery result rejected")
)

// RecoveryActivityInput contains only the durable IDs and four Plan digests
// already present in trusted preparation History. The Plan schema is fixed by
// this v1 DTO and therefore cannot be supplied by an Activity caller.
type RecoveryActivityInput struct {
	Version         int    `json:"version"`
	TenantID        string `json:"tenant_id"`
	WorkspaceID     string `json:"workspace_id"`
	IncidentID      string `json:"incident_id"`
	InvestigationID string `json:"investigation_id"`
	TaskID          string `json:"task_id"`
	Position        int    `json:"position"`
	ManifestDigest  string `json:"manifest_digest"`
	RegistryDigest  string `json:"registry_digest"`
	ProfileDigest   string `json:"profile_digest"`
	TasksHash       string `json:"tasks_hash"`
}

func (input *RecoveryActivityInput) UnmarshalJSON(data []byte) error {
	if input == nil {
		return ErrInvalidRecoveryInput
	}
	var decoded RecoveryActivityInput
	err := decodeExactObject(data, ErrInvalidRecoveryInput, map[string]func(*json.Decoder) error{
		"version":          func(decoder *json.Decoder) error { return decoder.Decode(&decoded.Version) },
		"tenant_id":        func(decoder *json.Decoder) error { return decoder.Decode(&decoded.TenantID) },
		"workspace_id":     func(decoder *json.Decoder) error { return decoder.Decode(&decoded.WorkspaceID) },
		"incident_id":      func(decoder *json.Decoder) error { return decoder.Decode(&decoded.IncidentID) },
		"investigation_id": func(decoder *json.Decoder) error { return decoder.Decode(&decoded.InvestigationID) },
		"task_id":          func(decoder *json.Decoder) error { return decoder.Decode(&decoded.TaskID) },
		"position":         func(decoder *json.Decoder) error { return decoder.Decode(&decoded.Position) },
		"manifest_digest":  func(decoder *json.Decoder) error { return decoder.Decode(&decoded.ManifestDigest) },
		"registry_digest":  func(decoder *json.Decoder) error { return decoder.Decode(&decoded.RegistryDigest) },
		"profile_digest":   func(decoder *json.Decoder) error { return decoder.Decode(&decoded.ProfileDigest) },
		"tasks_hash":       func(decoder *json.Decoder) error { return decoder.Decode(&decoded.TasksHash) },
	})
	if err != nil {
		return ErrInvalidRecoveryInput
	}
	if _, err := decoded.recoveryRequest(); err != nil {
		return ErrInvalidRecoveryInput
	}
	*input = decoded
	return nil
}

func (input RecoveryActivityInput) recoveryRequest() (readtask.RecoveryRequest, error) {
	request := readtask.RecoveryRequest{
		TenantID: input.TenantID, WorkspaceID: input.WorkspaceID, IncidentID: input.IncidentID,
		InvestigationID: input.InvestigationID, TaskID: input.TaskID, Position: input.Position,
		PlanBinding: domain.InvestigationPlanBinding{
			SchemaVersion:  domain.InvestigationPlanBindingSchemaVersion,
			ManifestDigest: input.ManifestDigest, RegistryDigest: input.RegistryDigest,
			ProfileDigest: input.ProfileDigest, TasksHash: input.TasksHash,
		},
	}
	if input.Version != RecoveryActivitySchemaVersion || request.Validate() != nil {
		return readtask.RecoveryRequest{}, ErrInvalidRecoveryInput
	}
	return request, nil
}

// RecoveryActivityOutput deliberately omits receipt, Runner, certificate,
// scope, runtime binding, task input and Evidence payload provenance.
type RecoveryActivityOutput struct {
	Version         int                    `json:"version"`
	State           readtask.RecoveryState `json:"state"`
	InvestigationID string                 `json:"investigation_id"`
	TaskID          string                 `json:"task_id"`
	Position        int                    `json:"position"`
	TaskStatus      domain.ReadTaskStatus  `json:"task_status"`
	EvidenceID      string                 `json:"evidence_id,omitempty"`
	ContentHash     string                 `json:"content_hash,omitempty"`
}

func (output *RecoveryActivityOutput) UnmarshalJSON(data []byte) error {
	if output == nil {
		return ErrInvalidRecoveryResult
	}
	var decoded RecoveryActivityOutput
	err := decodeExactObject(data, ErrInvalidRecoveryResult, map[string]func(*json.Decoder) error{
		"version":          func(decoder *json.Decoder) error { return decoder.Decode(&decoded.Version) },
		"state":            func(decoder *json.Decoder) error { return decoder.Decode(&decoded.State) },
		"investigation_id": func(decoder *json.Decoder) error { return decoder.Decode(&decoded.InvestigationID) },
		"task_id":          func(decoder *json.Decoder) error { return decoder.Decode(&decoded.TaskID) },
		"position":         func(decoder *json.Decoder) error { return decoder.Decode(&decoded.Position) },
		"task_status":      func(decoder *json.Decoder) error { return decoder.Decode(&decoded.TaskStatus) },
		"evidence_id":      func(decoder *json.Decoder) error { return decoder.Decode(&decoded.EvidenceID) },
		"content_hash":     func(decoder *json.Decoder) error { return decoder.Decode(&decoded.ContentHash) },
	})
	if err != nil || decoded.validateShape() != nil {
		return ErrInvalidRecoveryResult
	}
	*output = decoded
	return nil
}

func (output RecoveryActivityOutput) validateShape() error {
	if output.Version != RecoveryActivitySchemaVersion || !workflowUUID.MatchString(output.InvestigationID) ||
		!workflowUUID.MatchString(output.TaskID) || output.Position < 1 || output.Position > 12 {
		return ErrInvalidRecoveryResult
	}
	switch output.State {
	case readtask.RecoveryPending:
		if (output.TaskStatus != domain.ReadTaskQueued && output.TaskStatus != domain.ReadTaskRunning) ||
			output.EvidenceID != "" || output.ContentHash != "" {
			return ErrInvalidRecoveryResult
		}
	case readtask.RecoveryCommitted:
		switch output.TaskStatus {
		case domain.ReadTaskEvidence:
			if !workflowUUID.MatchString(output.EvidenceID) || !domain.ValidSHA256Hex(output.ContentHash) {
				return ErrInvalidRecoveryResult
			}
		case domain.ReadTaskFailed, domain.ReadTaskCancelled:
			if output.EvidenceID != "" || output.ContentHash != "" {
				return ErrInvalidRecoveryResult
			}
		default:
			return ErrInvalidRecoveryResult
		}
	case readtask.RecoveryControlCancelled:
		if output.TaskStatus != domain.ReadTaskCancelled || output.EvidenceID != "" || output.ContentHash != "" {
			return ErrInvalidRecoveryResult
		}
	default:
		return ErrInvalidRecoveryResult
	}
	return nil
}

func (output RecoveryActivityOutput) validateAgainst(input RecoveryActivityInput) error {
	if output.validateShape() != nil || output.InvestigationID != input.InvestigationID ||
		output.TaskID != input.TaskID || output.Position != input.Position {
		return ErrInvalidRecoveryResult
	}
	return nil
}

type RecoveryReader interface {
	Recover(context.Context, readtask.RecoveryRequest) (readtask.RecoveryResult, error)
}

// RecoveryActivities is intentionally not registered with Temporal in this
// milestone. C2-4 owns Workflow v2 naming, task queues and live assembly.
type RecoveryActivities struct {
	reader RecoveryReader
}

func NewRecoveryActivities(reader RecoveryReader) (*RecoveryActivities, error) {
	if nilInterface(reader) {
		return nil, ErrInvalidRecoveryInput
	}
	return &RecoveryActivities{reader: reader}, nil
}

func (activities *RecoveryActivities) recoverActivity(
	ctx context.Context,
	input RecoveryActivityInput,
) (output RecoveryActivityOutput, returnedErr error) {
	defer func() {
		if recover() != nil {
			output = RecoveryActivityOutput{}
			returnedErr = recoveryDependencyError()
		}
	}()
	if ctx == nil || activities == nil || nilInterface(activities.reader) {
		return RecoveryActivityOutput{}, recoveryNonRetryableError(
			recoveryInputInvalidErrorType, ErrInvalidRecoveryInput.Error(),
		)
	}
	if err := ctx.Err(); err != nil {
		return RecoveryActivityOutput{}, err
	}
	request, err := input.recoveryRequest()
	if err != nil {
		return RecoveryActivityOutput{}, recoveryNonRetryableError(
			recoveryInputInvalidErrorType, ErrInvalidRecoveryInput.Error(),
		)
	}
	result, err := activities.reader.Recover(ctx, request)
	if err != nil {
		return RecoveryActivityOutput{}, mapRecoveryActivityError(ctx, err)
	}
	if result.ValidateAgainst(request) != nil {
		return RecoveryActivityOutput{}, recoveryNonRetryableError(
			recoveryResultInvalidErrorType, ErrInvalidRecoveryResult.Error(),
		)
	}
	output = RecoveryActivityOutput{
		Version: RecoveryActivitySchemaVersion, State: result.State,
		InvestigationID: result.InvestigationID, TaskID: result.TaskID,
		Position: result.Position, TaskStatus: result.TaskStatus,
		EvidenceID: result.EvidenceID, ContentHash: result.ContentHash,
	}
	if output.validateAgainst(input) != nil {
		return RecoveryActivityOutput{}, recoveryNonRetryableError(
			recoveryResultInvalidErrorType, ErrInvalidRecoveryResult.Error(),
		)
	}
	return output, nil
}

func mapRecoveryActivityError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	switch {
	case errors.Is(err, readtask.ErrIntegrity):
		return recoveryNonRetryableError(
			recoveryIntegrityRejectedErrorType, "investigation READ result recovery integrity rejected",
		)
	case errors.Is(err, readtask.ErrNotFound):
		return recoveryNonRetryableError(
			recoveryNotFoundErrorType, "investigation READ result recovery fact not found",
		)
	case errors.Is(err, readtask.ErrInvalidRequest):
		return recoveryNonRetryableError(
			recoveryInputInvalidErrorType, ErrInvalidRecoveryInput.Error(),
		)
	default:
		return recoveryDependencyError()
	}
}

func recoveryNonRetryableError(errorType, message string) error {
	return temporal.NewNonRetryableApplicationError(message, errorType, nil)
}

func recoveryDependencyError() error {
	return temporal.NewApplicationError(
		"investigation READ result recovery dependency unavailable", recoveryDependencyErrorType,
	)
}
