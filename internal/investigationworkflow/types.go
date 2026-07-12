// Package investigationworkflow contains the unassembled, digest-bound
// Temporal preparation runtime for investigation facts.
package investigationworkflow

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/seaworld008/aiops-system/internal/domain"
)

const (
	SchemaVersion = 1
	WorkflowName  = "aiops.investigation.prepare.v1"
	ActivityName  = "aiops.investigation.prepare.activity.v1"

	StatePrepared         = "PREPARED"
	StateNoActiveIncident = "NO_ACTIVE_INCIDENT"

	taskQueuePrefix = "aiops-investigation-prepare-v1"
)

var (
	ErrInvalidInput   = errors.New("investigation preparation input rejected")
	ErrInvalidReceipt = errors.New("investigation preparation receipt rejected")
	workflowUUID      = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)
)

type WorkflowInput struct {
	Version          int    `json:"version"`
	OutboxEventID    string `json:"outbox_event_id"`
	TenantID         string `json:"tenant_id"`
	WorkspaceID      string `json:"workspace_id"`
	SignalID         string `json:"signal_id"`
	AggregateVersion int64  `json:"aggregate_version"`
	ManifestDigest   string `json:"manifest_digest"`
	RegistryDigest   string `json:"registry_digest"`
}

type PreparationReceipt struct {
	Version         int      `json:"version"`
	State           string   `json:"state"`
	OutboxEventID   string   `json:"outbox_event_id"`
	TenantID        string   `json:"tenant_id"`
	WorkspaceID     string   `json:"workspace_id"`
	SignalID        string   `json:"signal_id"`
	IncidentID      string   `json:"incident_id,omitempty"`
	InvestigationID string   `json:"investigation_id,omitempty"`
	TaskIDs         []string `json:"task_ids,omitempty"`
	TaskCount       int      `json:"task_count"`
	ManifestDigest  string   `json:"manifest_digest"`
	RegistryDigest  string   `json:"registry_digest"`
	ProfileDigest   string   `json:"profile_digest"`
	TasksHash       string   `json:"tasks_hash"`
}

func TaskQueue(manifestDigest, registryDigest string) (string, error) {
	if !domain.ValidSHA256Hex(manifestDigest) || !domain.ValidSHA256Hex(registryDigest) {
		return "", ErrInvalidInput
	}
	return fmt.Sprintf("%s-%s-%s", taskQueuePrefix, manifestDigest, registryDigest), nil
}

func validateInput(input WorkflowInput) error {
	if input.Version != SchemaVersion || input.AggregateVersion != 1 ||
		!workflowUUID.MatchString(input.OutboxEventID) || !workflowUUID.MatchString(input.TenantID) ||
		!workflowUUID.MatchString(input.WorkspaceID) || !workflowUUID.MatchString(input.SignalID) ||
		!domain.ValidSHA256Hex(input.ManifestDigest) || !domain.ValidSHA256Hex(input.RegistryDigest) {
		return ErrInvalidInput
	}
	return nil
}

func validateReceipt(input WorkflowInput, receipt PreparationReceipt) error {
	if receipt.Version != SchemaVersion || receipt.OutboxEventID != input.OutboxEventID || receipt.TenantID != input.TenantID ||
		receipt.WorkspaceID != input.WorkspaceID || receipt.SignalID != input.SignalID ||
		receipt.ManifestDigest != input.ManifestDigest || receipt.RegistryDigest != input.RegistryDigest ||
		!domain.ValidSHA256Hex(receipt.ProfileDigest) || !domain.ValidSHA256Hex(receipt.TasksHash) {
		return ErrInvalidReceipt
	}
	switch receipt.State {
	case StatePrepared:
		if !workflowUUID.MatchString(receipt.IncidentID) || !workflowUUID.MatchString(receipt.InvestigationID) ||
			receipt.TaskCount < 1 || receipt.TaskCount > 12 || receipt.TaskCount != len(receipt.TaskIDs) {
			return ErrInvalidReceipt
		}
		seen := make(map[string]struct{}, len(receipt.TaskIDs))
		for _, taskID := range receipt.TaskIDs {
			if !workflowUUID.MatchString(taskID) {
				return ErrInvalidReceipt
			}
			if _, duplicate := seen[taskID]; duplicate {
				return ErrInvalidReceipt
			}
			seen[taskID] = struct{}{}
		}
	case StateNoActiveIncident:
		if receipt.IncidentID != "" || receipt.InvestigationID != "" || receipt.TaskCount != 0 || len(receipt.TaskIDs) != 0 {
			return ErrInvalidReceipt
		}
	default:
		return ErrInvalidReceipt
	}
	return nil
}
