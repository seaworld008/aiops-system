package investigationworkflow

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/readtask"
)

const (
	RuntimeV2SchemaVersion        = 2
	ReadTaskActivitySchemaVersion = 1

	WorkflowNameV2         = "aiops.investigation.read.v2"
	PrepareActivityNameV2  = "aiops.investigation.prepare.activity.v2"
	RecoveryActivityNameV1 = "aiops.investigation.read-result.recover.activity.v1"
	ExecuteActivityNameV1  = "aiops.investigation.read-task.execute.activity.v1"

	RuntimeStateNoActiveIncident  = "NO_ACTIVE_INCIDENT"
	RuntimeStateReadTasksTerminal = "READ_TASKS_TERMINAL"

	ReadTaskActivityNotClaimed           = "NOT_CLAIMED"
	ReadTaskActivityCompleteAcknowledged = "COMPLETE_ACKNOWLEDGED"
	ReadTaskActivityRecoveryRequired     = "RECOVERY_REQUIRED"
	ReadTaskPendingErrorType             = "READ_TASK_PENDING"

	MaximumReadTaskRounds = 3

	RunnerActivityScheduleToCloseTimeout = 2 * time.Minute
	RunnerActivityStartToCloseTimeout    = 2 * time.Minute
	RunnerActivityHeartbeatTimeout       = 15 * time.Second
	ReadTaskRecoveryWait                 = 35 * time.Second

	controlTaskQueuePrefixV2      = "aiops-investigation-read-v2"
	runnerTaskQueuePrefixV2       = "aiops-investigation-read-task-v2"
	runnerTaskQueueHashDomainV2   = "aiops.investigation.read-task-queue.v2\x00"
	maximumTemporalTaskQueueBytes = 255
)

var (
	ErrInvalidRuntimeV2Input  = errors.New("investigation READ workflow input rejected")
	ErrInvalidRuntimeV2Result = errors.New("investigation READ workflow result rejected")
	ErrReadTaskPending        = errors.New("investigation READ task remains pending")
)

// WorkflowInputV2 is the complete secret-free start contract for the v2
// orchestration. Signal bodies, Task specs, runtime targets and credentials
// are deliberately recovered from durable trusted facts instead of History.
type WorkflowInputV2 struct {
	Version          int    `json:"version"`
	OutboxEventID    string `json:"outbox_event_id"`
	TenantID         string `json:"tenant_id"`
	WorkspaceID      string `json:"workspace_id"`
	SignalID         string `json:"signal_id"`
	AggregateVersion int64  `json:"aggregate_version"`
	ManifestDigest   string `json:"manifest_digest"`
	RegistryDigest   string `json:"registry_digest"`
	BundleDigest     string `json:"bundle_digest"`
}

func (input WorkflowInputV2) Validate() error {
	if input.Version != RuntimeV2SchemaVersion || input.AggregateVersion != 1 ||
		!workflowUUID.MatchString(input.OutboxEventID) || !workflowUUID.MatchString(input.TenantID) ||
		!workflowUUID.MatchString(input.WorkspaceID) || !workflowUUID.MatchString(input.SignalID) ||
		!domain.ValidSHA256Hex(input.ManifestDigest) || !domain.ValidSHA256Hex(input.RegistryDigest) ||
		!domain.ValidSHA256Hex(input.BundleDigest) {
		return ErrInvalidRuntimeV2Input
	}
	return nil
}

func (input *WorkflowInputV2) UnmarshalJSON(data []byte) error {
	if input == nil || len(data) == 0 || len(data) > maximumHistoryDTOBytes {
		return ErrInvalidRuntimeV2Input
	}
	var decoded WorkflowInputV2
	err := decodeExactObject(data, ErrInvalidRuntimeV2Input, map[string]func(*json.Decoder) error{
		"version":           func(decoder *json.Decoder) error { return decoder.Decode(&decoded.Version) },
		"outbox_event_id":   func(decoder *json.Decoder) error { return decoder.Decode(&decoded.OutboxEventID) },
		"tenant_id":         func(decoder *json.Decoder) error { return decoder.Decode(&decoded.TenantID) },
		"workspace_id":      func(decoder *json.Decoder) error { return decoder.Decode(&decoded.WorkspaceID) },
		"signal_id":         func(decoder *json.Decoder) error { return decoder.Decode(&decoded.SignalID) },
		"aggregate_version": func(decoder *json.Decoder) error { return decoder.Decode(&decoded.AggregateVersion) },
		"manifest_digest":   func(decoder *json.Decoder) error { return decoder.Decode(&decoded.ManifestDigest) },
		"registry_digest":   func(decoder *json.Decoder) error { return decoder.Decode(&decoded.RegistryDigest) },
		"bundle_digest":     func(decoder *json.Decoder) error { return decoder.Decode(&decoded.BundleDigest) },
	})
	if err != nil || decoded.Validate() != nil {
		return ErrInvalidRuntimeV2Input
	}
	*input = decoded
	return nil
}

// ReadTaskReferenceV2 is the only Task projection emitted by PREPARE into
// History. The Task body and every runtime component remain in PostgreSQL.
type ReadTaskReferenceV2 struct {
	TaskID   string `json:"task_id"`
	Position int    `json:"position"`
}

func (reference ReadTaskReferenceV2) Validate() error {
	if !workflowUUID.MatchString(reference.TaskID) || reference.Position < 1 || reference.Position > 12 {
		return ErrInvalidRuntimeV2Result
	}
	return nil
}

func (reference *ReadTaskReferenceV2) UnmarshalJSON(data []byte) error {
	if reference == nil || len(data) == 0 || len(data) > maximumHistoryDTOBytes {
		return ErrInvalidRuntimeV2Result
	}
	var decoded ReadTaskReferenceV2
	err := decodeExactObject(data, ErrInvalidRuntimeV2Result, map[string]func(*json.Decoder) error{
		"task_id":  func(decoder *json.Decoder) error { return decoder.Decode(&decoded.TaskID) },
		"position": func(decoder *json.Decoder) error { return decoder.Decode(&decoded.Position) },
	})
	if err != nil || decoded.Validate() != nil {
		return ErrInvalidRuntimeV2Result
	}
	*reference = decoded
	return nil
}

// PreparationReceiptV2 extends the v1 durable preparation receipt with the
// trusted Environment/Service pair and consecutive Task references needed for
// exact Runner task-queue routing.
type PreparationReceiptV2 struct {
	Version         int                   `json:"version"`
	State           string                `json:"state"`
	OutboxEventID   string                `json:"outbox_event_id"`
	TenantID        string                `json:"tenant_id"`
	WorkspaceID     string                `json:"workspace_id"`
	SignalID        string                `json:"signal_id"`
	IncidentID      string                `json:"incident_id,omitempty"`
	EnvironmentID   string                `json:"environment_id,omitempty"`
	ServiceID       string                `json:"service_id,omitempty"`
	InvestigationID string                `json:"investigation_id,omitempty"`
	Tasks           []ReadTaskReferenceV2 `json:"tasks,omitempty"`
	ManifestDigest  string                `json:"manifest_digest"`
	RegistryDigest  string                `json:"registry_digest"`
	BundleDigest    string                `json:"bundle_digest"`
	ProfileDigest   string                `json:"profile_digest"`
	TasksHash       string                `json:"tasks_hash"`
}

func (receipt PreparationReceiptV2) ValidateAgainst(input WorkflowInputV2) error {
	if input.Validate() != nil || receipt.validateShape() != nil ||
		receipt.OutboxEventID != input.OutboxEventID || receipt.TenantID != input.TenantID ||
		receipt.WorkspaceID != input.WorkspaceID || receipt.SignalID != input.SignalID ||
		receipt.ManifestDigest != input.ManifestDigest || receipt.RegistryDigest != input.RegistryDigest ||
		receipt.BundleDigest != input.BundleDigest {
		return ErrInvalidRuntimeV2Result
	}
	return nil
}

func (receipt PreparationReceiptV2) validateShape() error {
	if receipt.Version != RuntimeV2SchemaVersion || !workflowUUID.MatchString(receipt.OutboxEventID) ||
		!workflowUUID.MatchString(receipt.TenantID) || !workflowUUID.MatchString(receipt.WorkspaceID) ||
		!workflowUUID.MatchString(receipt.SignalID) || !domain.ValidSHA256Hex(receipt.ManifestDigest) ||
		!domain.ValidSHA256Hex(receipt.RegistryDigest) || !domain.ValidSHA256Hex(receipt.BundleDigest) ||
		!domain.ValidSHA256Hex(receipt.ProfileDigest) || !domain.ValidSHA256Hex(receipt.TasksHash) {
		return ErrInvalidRuntimeV2Result
	}
	switch receipt.State {
	case StateNoActiveIncident:
		if receipt.IncidentID != "" || receipt.EnvironmentID != "" || receipt.ServiceID != "" ||
			receipt.InvestigationID != "" || len(receipt.Tasks) != 0 {
			return ErrInvalidRuntimeV2Result
		}
	case StatePrepared:
		if !workflowUUID.MatchString(receipt.IncidentID) || !workflowUUID.MatchString(receipt.EnvironmentID) ||
			!workflowUUID.MatchString(receipt.ServiceID) || !workflowUUID.MatchString(receipt.InvestigationID) ||
			len(receipt.Tasks) < 1 || len(receipt.Tasks) > 12 {
			return ErrInvalidRuntimeV2Result
		}
		seen := make(map[string]struct{}, len(receipt.Tasks))
		for index, reference := range receipt.Tasks {
			if reference.Validate() != nil || reference.Position != index+1 {
				return ErrInvalidRuntimeV2Result
			}
			if _, duplicate := seen[reference.TaskID]; duplicate {
				return ErrInvalidRuntimeV2Result
			}
			seen[reference.TaskID] = struct{}{}
		}
	default:
		return ErrInvalidRuntimeV2Result
	}
	return nil
}

func (receipt *PreparationReceiptV2) UnmarshalJSON(data []byte) error {
	if receipt == nil || len(data) == 0 || len(data) > maximumHistoryDTOBytes {
		return ErrInvalidRuntimeV2Result
	}
	var decoded PreparationReceiptV2
	err := decodeExactObject(data, ErrInvalidRuntimeV2Result, map[string]func(*json.Decoder) error{
		"version":          func(decoder *json.Decoder) error { return decoder.Decode(&decoded.Version) },
		"state":            func(decoder *json.Decoder) error { return decoder.Decode(&decoded.State) },
		"outbox_event_id":  func(decoder *json.Decoder) error { return decoder.Decode(&decoded.OutboxEventID) },
		"tenant_id":        func(decoder *json.Decoder) error { return decoder.Decode(&decoded.TenantID) },
		"workspace_id":     func(decoder *json.Decoder) error { return decoder.Decode(&decoded.WorkspaceID) },
		"signal_id":        func(decoder *json.Decoder) error { return decoder.Decode(&decoded.SignalID) },
		"incident_id":      func(decoder *json.Decoder) error { return decoder.Decode(&decoded.IncidentID) },
		"environment_id":   func(decoder *json.Decoder) error { return decoder.Decode(&decoded.EnvironmentID) },
		"service_id":       func(decoder *json.Decoder) error { return decoder.Decode(&decoded.ServiceID) },
		"investigation_id": func(decoder *json.Decoder) error { return decoder.Decode(&decoded.InvestigationID) },
		"tasks":            func(decoder *json.Decoder) error { return decoder.Decode(&decoded.Tasks) },
		"manifest_digest":  func(decoder *json.Decoder) error { return decoder.Decode(&decoded.ManifestDigest) },
		"registry_digest":  func(decoder *json.Decoder) error { return decoder.Decode(&decoded.RegistryDigest) },
		"bundle_digest":    func(decoder *json.Decoder) error { return decoder.Decode(&decoded.BundleDigest) },
		"profile_digest":   func(decoder *json.Decoder) error { return decoder.Decode(&decoded.ProfileDigest) },
		"tasks_hash":       func(decoder *json.Decoder) error { return decoder.Decode(&decoded.TasksHash) },
	})
	if err != nil || decoded.validateShape() != nil {
		return ErrInvalidRuntimeV2Result
	}
	*receipt = decoded
	return nil
}

// ReadTaskActivityInputV1 is scheduler-owned. A Runner uses it only as the
// expected identity against which the mTLS Gateway response is reconstructed.
type ReadTaskActivityInputV1 struct {
	Version         int    `json:"version"`
	OutboxEventID   string `json:"outbox_event_id"`
	TenantID        string `json:"tenant_id"`
	WorkspaceID     string `json:"workspace_id"`
	EnvironmentID   string `json:"environment_id"`
	ServiceID       string `json:"service_id"`
	IncidentID      string `json:"incident_id"`
	InvestigationID string `json:"investigation_id"`
	TaskID          string `json:"task_id"`
	Position        int    `json:"position"`
	ManifestDigest  string `json:"manifest_digest"`
	RegistryDigest  string `json:"registry_digest"`
	BundleDigest    string `json:"bundle_digest"`
	ProfileDigest   string `json:"profile_digest"`
	TasksHash       string `json:"tasks_hash"`
	Round           int    `json:"round"`
}

func (input ReadTaskActivityInputV1) Validate() error {
	for _, identifier := range []string{
		input.OutboxEventID, input.TenantID, input.WorkspaceID, input.EnvironmentID, input.ServiceID,
		input.IncidentID, input.InvestigationID, input.TaskID,
	} {
		if !workflowUUID.MatchString(identifier) {
			return ErrInvalidRuntimeV2Input
		}
	}
	if input.Version != ReadTaskActivitySchemaVersion || input.Position < 1 || input.Position > 12 ||
		input.Round < 1 || input.Round > MaximumReadTaskRounds ||
		!domain.ValidSHA256Hex(input.ManifestDigest) || !domain.ValidSHA256Hex(input.RegistryDigest) ||
		!domain.ValidSHA256Hex(input.BundleDigest) ||
		!domain.ValidSHA256Hex(input.ProfileDigest) || !domain.ValidSHA256Hex(input.TasksHash) {
		return ErrInvalidRuntimeV2Input
	}
	return nil
}

func (input *ReadTaskActivityInputV1) UnmarshalJSON(data []byte) error {
	if input == nil || len(data) == 0 || len(data) > maximumHistoryDTOBytes {
		return ErrInvalidRuntimeV2Input
	}
	var decoded ReadTaskActivityInputV1
	err := decodeExactObject(data, ErrInvalidRuntimeV2Input, map[string]func(*json.Decoder) error{
		"version":          func(decoder *json.Decoder) error { return decoder.Decode(&decoded.Version) },
		"outbox_event_id":  func(decoder *json.Decoder) error { return decoder.Decode(&decoded.OutboxEventID) },
		"tenant_id":        func(decoder *json.Decoder) error { return decoder.Decode(&decoded.TenantID) },
		"workspace_id":     func(decoder *json.Decoder) error { return decoder.Decode(&decoded.WorkspaceID) },
		"environment_id":   func(decoder *json.Decoder) error { return decoder.Decode(&decoded.EnvironmentID) },
		"service_id":       func(decoder *json.Decoder) error { return decoder.Decode(&decoded.ServiceID) },
		"incident_id":      func(decoder *json.Decoder) error { return decoder.Decode(&decoded.IncidentID) },
		"investigation_id": func(decoder *json.Decoder) error { return decoder.Decode(&decoded.InvestigationID) },
		"task_id":          func(decoder *json.Decoder) error { return decoder.Decode(&decoded.TaskID) },
		"position":         func(decoder *json.Decoder) error { return decoder.Decode(&decoded.Position) },
		"manifest_digest":  func(decoder *json.Decoder) error { return decoder.Decode(&decoded.ManifestDigest) },
		"registry_digest":  func(decoder *json.Decoder) error { return decoder.Decode(&decoded.RegistryDigest) },
		"bundle_digest":    func(decoder *json.Decoder) error { return decoder.Decode(&decoded.BundleDigest) },
		"profile_digest":   func(decoder *json.Decoder) error { return decoder.Decode(&decoded.ProfileDigest) },
		"tasks_hash":       func(decoder *json.Decoder) error { return decoder.Decode(&decoded.TasksHash) },
		"round":            func(decoder *json.Decoder) error { return decoder.Decode(&decoded.Round) },
	})
	if err != nil || decoded.Validate() != nil {
		return ErrInvalidRuntimeV2Input
	}
	*input = decoded
	return nil
}

type ReadTaskActivityOutputV1 struct {
	Version         int    `json:"version"`
	State           string `json:"state"`
	InvestigationID string `json:"investigation_id"`
	TaskID          string `json:"task_id"`
	Position        int    `json:"position"`
	Round           int    `json:"round"`
}

func (output ReadTaskActivityOutputV1) Validate() error {
	if output.Version != ReadTaskActivitySchemaVersion || !workflowUUID.MatchString(output.InvestigationID) ||
		!workflowUUID.MatchString(output.TaskID) || output.Position < 1 || output.Position > 12 ||
		output.Round < 1 || output.Round > MaximumReadTaskRounds {
		return ErrInvalidRuntimeV2Result
	}
	switch output.State {
	case ReadTaskActivityNotClaimed, ReadTaskActivityCompleteAcknowledged, ReadTaskActivityRecoveryRequired:
		return nil
	default:
		return ErrInvalidRuntimeV2Result
	}
}

func (output ReadTaskActivityOutputV1) ValidateAgainst(input ReadTaskActivityInputV1) error {
	if input.Validate() != nil || output.Validate() != nil || output.InvestigationID != input.InvestigationID ||
		output.TaskID != input.TaskID || output.Position != input.Position || output.Round != input.Round {
		return ErrInvalidRuntimeV2Result
	}
	return nil
}

func (output *ReadTaskActivityOutputV1) UnmarshalJSON(data []byte) error {
	if output == nil || len(data) == 0 || len(data) > maximumHistoryDTOBytes {
		return ErrInvalidRuntimeV2Result
	}
	var decoded ReadTaskActivityOutputV1
	err := decodeExactObject(data, ErrInvalidRuntimeV2Result, map[string]func(*json.Decoder) error{
		"version":          func(decoder *json.Decoder) error { return decoder.Decode(&decoded.Version) },
		"state":            func(decoder *json.Decoder) error { return decoder.Decode(&decoded.State) },
		"investigation_id": func(decoder *json.Decoder) error { return decoder.Decode(&decoded.InvestigationID) },
		"task_id":          func(decoder *json.Decoder) error { return decoder.Decode(&decoded.TaskID) },
		"position":         func(decoder *json.Decoder) error { return decoder.Decode(&decoded.Position) },
		"round":            func(decoder *json.Decoder) error { return decoder.Decode(&decoded.Round) },
	})
	if err != nil || decoded.Validate() != nil {
		return ErrInvalidRuntimeV2Result
	}
	*output = decoded
	return nil
}

// TerminalReadTaskV2 is the receipt-free final projection returned by the
// Workflow. It cannot carry Runner, certificate, target or raw Evidence data.
type TerminalReadTaskV2 struct {
	TaskID      string                `json:"task_id"`
	Position    int                   `json:"position"`
	TaskStatus  domain.ReadTaskStatus `json:"task_status"`
	EvidenceID  string                `json:"evidence_id,omitempty"`
	ContentHash string                `json:"content_hash,omitempty"`
}

func (result TerminalReadTaskV2) Validate() error {
	if !workflowUUID.MatchString(result.TaskID) || result.Position < 1 || result.Position > 12 {
		return ErrInvalidRuntimeV2Result
	}
	switch result.TaskStatus {
	case domain.ReadTaskEvidence:
		if !workflowUUID.MatchString(result.EvidenceID) || !domain.ValidSHA256Hex(result.ContentHash) {
			return ErrInvalidRuntimeV2Result
		}
	case domain.ReadTaskFailed, domain.ReadTaskCancelled:
		if result.EvidenceID != "" || result.ContentHash != "" {
			return ErrInvalidRuntimeV2Result
		}
	default:
		return ErrInvalidRuntimeV2Result
	}
	return nil
}

func (result *TerminalReadTaskV2) UnmarshalJSON(data []byte) error {
	if result == nil || len(data) == 0 || len(data) > maximumHistoryDTOBytes {
		return ErrInvalidRuntimeV2Result
	}
	var decoded TerminalReadTaskV2
	err := decodeExactObject(data, ErrInvalidRuntimeV2Result, map[string]func(*json.Decoder) error{
		"task_id":      func(decoder *json.Decoder) error { return decoder.Decode(&decoded.TaskID) },
		"position":     func(decoder *json.Decoder) error { return decoder.Decode(&decoded.Position) },
		"task_status":  func(decoder *json.Decoder) error { return decoder.Decode(&decoded.TaskStatus) },
		"evidence_id":  func(decoder *json.Decoder) error { return decoder.Decode(&decoded.EvidenceID) },
		"content_hash": func(decoder *json.Decoder) error { return decoder.Decode(&decoded.ContentHash) },
	})
	if err != nil || decoded.Validate() != nil {
		return ErrInvalidRuntimeV2Result
	}
	*result = decoded
	return nil
}

type WorkflowResultV2 struct {
	Version         int                  `json:"version"`
	State           string               `json:"state"`
	OutboxEventID   string               `json:"outbox_event_id"`
	TenantID        string               `json:"tenant_id"`
	WorkspaceID     string               `json:"workspace_id"`
	SignalID        string               `json:"signal_id"`
	IncidentID      string               `json:"incident_id,omitempty"`
	InvestigationID string               `json:"investigation_id,omitempty"`
	Tasks           []TerminalReadTaskV2 `json:"tasks,omitempty"`
	ManifestDigest  string               `json:"manifest_digest"`
	RegistryDigest  string               `json:"registry_digest"`
	BundleDigest    string               `json:"bundle_digest"`
	ProfileDigest   string               `json:"profile_digest"`
	TasksHash       string               `json:"tasks_hash"`
}

func (result WorkflowResultV2) ValidateAgainst(input WorkflowInputV2) error {
	if input.Validate() != nil || result.validateShape() != nil ||
		result.OutboxEventID != input.OutboxEventID || result.TenantID != input.TenantID ||
		result.WorkspaceID != input.WorkspaceID || result.SignalID != input.SignalID ||
		result.ManifestDigest != input.ManifestDigest || result.RegistryDigest != input.RegistryDigest ||
		result.BundleDigest != input.BundleDigest {
		return ErrInvalidRuntimeV2Result
	}
	return nil
}

func (result WorkflowResultV2) validateShape() error {
	if result.Version != RuntimeV2SchemaVersion || !workflowUUID.MatchString(result.OutboxEventID) ||
		!workflowUUID.MatchString(result.TenantID) || !workflowUUID.MatchString(result.WorkspaceID) ||
		!workflowUUID.MatchString(result.SignalID) || !domain.ValidSHA256Hex(result.ManifestDigest) ||
		!domain.ValidSHA256Hex(result.RegistryDigest) || !domain.ValidSHA256Hex(result.BundleDigest) ||
		!domain.ValidSHA256Hex(result.ProfileDigest) || !domain.ValidSHA256Hex(result.TasksHash) {
		return ErrInvalidRuntimeV2Result
	}
	switch result.State {
	case RuntimeStateNoActiveIncident:
		if result.IncidentID != "" || result.InvestigationID != "" || len(result.Tasks) != 0 {
			return ErrInvalidRuntimeV2Result
		}
	case RuntimeStateReadTasksTerminal:
		if !workflowUUID.MatchString(result.IncidentID) || !workflowUUID.MatchString(result.InvestigationID) ||
			len(result.Tasks) < 1 || len(result.Tasks) > 12 {
			return ErrInvalidRuntimeV2Result
		}
		seen := make(map[string]struct{}, len(result.Tasks))
		for index, task := range result.Tasks {
			if task.Validate() != nil || task.Position != index+1 {
				return ErrInvalidRuntimeV2Result
			}
			if _, duplicate := seen[task.TaskID]; duplicate {
				return ErrInvalidRuntimeV2Result
			}
			seen[task.TaskID] = struct{}{}
		}
	default:
		return ErrInvalidRuntimeV2Result
	}
	return nil
}

func (result *WorkflowResultV2) UnmarshalJSON(data []byte) error {
	if result == nil || len(data) == 0 || len(data) > maximumHistoryDTOBytes {
		return ErrInvalidRuntimeV2Result
	}
	var decoded WorkflowResultV2
	err := decodeExactObject(data, ErrInvalidRuntimeV2Result, map[string]func(*json.Decoder) error{
		"version":          func(decoder *json.Decoder) error { return decoder.Decode(&decoded.Version) },
		"state":            func(decoder *json.Decoder) error { return decoder.Decode(&decoded.State) },
		"outbox_event_id":  func(decoder *json.Decoder) error { return decoder.Decode(&decoded.OutboxEventID) },
		"tenant_id":        func(decoder *json.Decoder) error { return decoder.Decode(&decoded.TenantID) },
		"workspace_id":     func(decoder *json.Decoder) error { return decoder.Decode(&decoded.WorkspaceID) },
		"signal_id":        func(decoder *json.Decoder) error { return decoder.Decode(&decoded.SignalID) },
		"incident_id":      func(decoder *json.Decoder) error { return decoder.Decode(&decoded.IncidentID) },
		"investigation_id": func(decoder *json.Decoder) error { return decoder.Decode(&decoded.InvestigationID) },
		"tasks":            func(decoder *json.Decoder) error { return decoder.Decode(&decoded.Tasks) },
		"manifest_digest":  func(decoder *json.Decoder) error { return decoder.Decode(&decoded.ManifestDigest) },
		"registry_digest":  func(decoder *json.Decoder) error { return decoder.Decode(&decoded.RegistryDigest) },
		"bundle_digest":    func(decoder *json.Decoder) error { return decoder.Decode(&decoded.BundleDigest) },
		"profile_digest":   func(decoder *json.Decoder) error { return decoder.Decode(&decoded.ProfileDigest) },
		"tasks_hash":       func(decoder *json.Decoder) error { return decoder.Decode(&decoded.TasksHash) },
	})
	if err != nil || decoded.validateShape() != nil {
		return ErrInvalidRuntimeV2Result
	}
	*result = decoded
	return nil
}

func ControlTaskQueue(manifestDigest, registryDigest, bundleDigest string) (string, error) {
	if !domain.ValidSHA256Hex(manifestDigest) || !domain.ValidSHA256Hex(registryDigest) ||
		!domain.ValidSHA256Hex(bundleDigest) {
		return "", ErrInvalidRuntimeV2Input
	}
	queue := fmt.Sprintf("%s-%s-%s-%s", controlTaskQueuePrefixV2, manifestDigest, registryDigest, bundleDigest)
	if len(queue) > maximumTemporalTaskQueueBytes {
		return "", ErrInvalidRuntimeV2Input
	}
	return queue, nil
}

func RunnerTaskQueue(
	environmentID string,
	manifestDigest string,
	registryDigest string,
	bundleDigest string,
) (string, error) {
	if !workflowUUID.MatchString(environmentID) || !domain.ValidSHA256Hex(manifestDigest) ||
		!domain.ValidSHA256Hex(registryDigest) || !domain.ValidSHA256Hex(bundleDigest) {
		return "", ErrInvalidRuntimeV2Input
	}
	identity := sha256.Sum256([]byte(
		runnerTaskQueueHashDomainV2 + manifestDigest + "\x00" + registryDigest + "\x00" + bundleDigest,
	))
	queue := fmt.Sprintf("%s-%s-%x", runnerTaskQueuePrefixV2, environmentID, identity)
	if len(queue) > maximumTemporalTaskQueueBytes {
		return "", ErrInvalidRuntimeV2Input
	}
	return queue, nil
}

func ReadTaskActivityID(round, position int, taskID string) (string, error) {
	if round < 1 || round > MaximumReadTaskRounds || position < 1 || position > 12 || !workflowUUID.MatchString(taskID) {
		return "", ErrInvalidRuntimeV2Input
	}
	return fmt.Sprintf("read-execute-r%d-p%d-%s", round, position, taskID), nil
}

func RecoveryActivityID(round, check, position int, taskID string) (string, error) {
	if round < 1 || round > MaximumReadTaskRounds || check < 1 || check > 2 ||
		position < 1 || position > 12 || !workflowUUID.MatchString(taskID) {
		return "", ErrInvalidRuntimeV2Input
	}
	return fmt.Sprintf("read-recover-r%d-c%d-p%d-%s", round, check, position, taskID), nil
}

func readTaskActivityInput(receipt PreparationReceiptV2, reference ReadTaskReferenceV2, round int) ReadTaskActivityInputV1 {
	return ReadTaskActivityInputV1{
		Version: ReadTaskActivitySchemaVersion, OutboxEventID: receipt.OutboxEventID,
		TenantID: receipt.TenantID, WorkspaceID: receipt.WorkspaceID,
		EnvironmentID: receipt.EnvironmentID, ServiceID: receipt.ServiceID,
		IncidentID: receipt.IncidentID, InvestigationID: receipt.InvestigationID,
		TaskID: reference.TaskID, Position: reference.Position,
		ManifestDigest: receipt.ManifestDigest, RegistryDigest: receipt.RegistryDigest,
		BundleDigest:  receipt.BundleDigest,
		ProfileDigest: receipt.ProfileDigest, TasksHash: receipt.TasksHash, Round: round,
	}
}

func ValidTemporalNamespace(namespace string) bool {
	return temporalNamespacePattern.MatchString(namespace)
}

func recoveryInputFromReadTask(input ReadTaskActivityInputV1) RecoveryActivityInput {
	return RecoveryActivityInput{
		Version:  RecoveryActivitySchemaVersion,
		TenantID: input.TenantID, WorkspaceID: input.WorkspaceID,
		IncidentID: input.IncidentID, InvestigationID: input.InvestigationID,
		TaskID: input.TaskID, Position: input.Position,
		ManifestDigest: input.ManifestDigest, RegistryDigest: input.RegistryDigest,
		ProfileDigest: input.ProfileDigest, TasksHash: input.TasksHash,
	}
}

func terminalReadTask(output RecoveryActivityOutput) (TerminalReadTaskV2, error) {
	if output.validateShape() != nil || output.State == readtask.RecoveryPending {
		return TerminalReadTaskV2{}, ErrInvalidRuntimeV2Result
	}
	result := TerminalReadTaskV2{
		TaskID: output.TaskID, Position: output.Position, TaskStatus: output.TaskStatus,
		EvidenceID: output.EvidenceID, ContentHash: output.ContentHash,
	}
	if result.Validate() != nil {
		return TerminalReadTaskV2{}, ErrInvalidRuntimeV2Result
	}
	return result, nil
}
