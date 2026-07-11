package domain

import (
	"encoding/json"
	"fmt"
	"time"
)

type Evidence struct {
	ID              string
	WorkspaceID     string
	IncidentID      string
	InvestigationID string
	TaskID          string
	ConnectorID     string
	ContentHash     string
	Payload         json.RawMessage
	Attributes      map[string]string
	CollectedAt     time.Time
	CreatedAt       time.Time
}

func (evidence Evidence) Validate() error {
	if !validIdentifier(evidence.ID, 256) || !validIdentifier(evidence.WorkspaceID, 256) ||
		!validIdentifier(evidence.IncidentID, 256) || !validIdentifier(evidence.InvestigationID, 256) ||
		!validIdentifier(evidence.TaskID, 256) || !ValidConnectorID(evidence.ConnectorID) {
		return fmt.Errorf("evidence identifiers are invalid")
	}
	if err := validateHashedJSONObject(evidence.Payload, evidence.ContentHash); err != nil {
		return fmt.Errorf("evidence payload: %w", err)
	}
	if err := ValidateSafeAttributes(evidence.Attributes); err != nil {
		return err
	}
	if evidence.CollectedAt.IsZero() || evidence.CreatedAt.IsZero() || evidence.CollectedAt.After(evidence.CreatedAt) {
		return fmt.Errorf("evidence timestamps are invalid")
	}
	return nil
}

type RunnerEvidenceReceipt struct {
	ID              string
	WorkspaceID     string
	InvestigationID string
	TaskID          string
	RunnerID        string
	ConnectorID     string
	EvidenceID      string
	ContentHash     string
	FailureCode     string
	IdempotencyKey  string
	ReceivedAt      time.Time
}

func (receipt RunnerEvidenceReceipt) Validate() error {
	if !validIdentifier(receipt.ID, 256) || !validIdentifier(receipt.WorkspaceID, 256) ||
		!validIdentifier(receipt.InvestigationID, 256) || !validIdentifier(receipt.TaskID, 256) ||
		!validIdentifier(receipt.RunnerID, 256) || !ValidConnectorID(receipt.ConnectorID) ||
		!ValidIdempotencyKey(receipt.IdempotencyKey) {
		return fmt.Errorf("runner evidence receipt identifiers are invalid")
	}
	success := validIdentifier(receipt.EvidenceID, 256) && ValidSHA256Hex(receipt.ContentHash) && receipt.FailureCode == ""
	failure := receipt.EvidenceID == "" && receipt.ContentHash == "" && ValidFailureCode(receipt.FailureCode)
	if success == failure {
		return fmt.Errorf("runner evidence receipt must contain exactly one bounded result")
	}
	if receipt.ReceivedAt.IsZero() {
		return fmt.Errorf("runner evidence receipt time is required")
	}
	return nil
}
