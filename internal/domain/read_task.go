package domain

import (
	"encoding/json"
	"fmt"
	"time"
)

type ReadTaskStatus string

const (
	ReadTaskQueued    ReadTaskStatus = "QUEUED"
	ReadTaskRunning   ReadTaskStatus = "RUNNING"
	ReadTaskEvidence  ReadTaskStatus = "EVIDENCE"
	ReadTaskFailed    ReadTaskStatus = "FAILED"
	ReadTaskCancelled ReadTaskStatus = "CANCELLED"
)

type ReadTask struct {
	ID              string
	WorkspaceID     string
	IncidentID      string
	InvestigationID string
	Key             string
	Position        int
	ConnectorID     string
	Operation       string
	Input           json.RawMessage
	InputHash       string
	Status          ReadTaskStatus
	EvidenceID      string
	FailureCode     string
	CreatedAt       time.Time
	StartedAt       time.Time
	CompletedAt     time.Time
	UpdatedAt       time.Time
}

func (task ReadTask) Validate() error {
	if !validIdentifier(task.ID, 256) || !validIdentifier(task.WorkspaceID, 256) ||
		!validIdentifier(task.IncidentID, 256) || !validIdentifier(task.InvestigationID, 256) {
		return fmt.Errorf("read task identifiers are invalid")
	}
	if task.Position <= 0 || task.Position > 12 {
		return fmt.Errorf("read task position must be between 1 and 12")
	}
	if !lowCardinalityPattern.MatchString(task.Key) || len(task.Key) > 64 {
		return fmt.Errorf("read task key is invalid")
	}
	if !ValidConnectorID(task.ConnectorID) || !ValidOperation(task.Operation) {
		return fmt.Errorf("read task connector or operation is invalid")
	}
	if err := validateHashedJSONObject(task.Input, task.InputHash); err != nil {
		return fmt.Errorf("read task input: %w", err)
	}
	switch task.Status {
	case ReadTaskQueued, ReadTaskRunning, ReadTaskEvidence, ReadTaskFailed, ReadTaskCancelled:
	default:
		return fmt.Errorf("invalid read task status %q", task.Status)
	}
	if task.FailureCode != "" && !ValidFailureCode(task.FailureCode) {
		return fmt.Errorf("read task failure code is invalid")
	}
	if task.CreatedAt.IsZero() || task.UpdatedAt.IsZero() || task.UpdatedAt.Before(task.CreatedAt) ||
		!timeWithin(task.StartedAt, task.CreatedAt, task.UpdatedAt) ||
		!timeWithin(task.CompletedAt, task.CreatedAt, task.UpdatedAt) ||
		(!task.StartedAt.IsZero() && !task.CompletedAt.IsZero() && task.CompletedAt.Before(task.StartedAt)) {
		return fmt.Errorf("read task timestamps are invalid")
	}
	switch task.Status {
	case ReadTaskQueued:
		if !task.StartedAt.IsZero() || !task.CompletedAt.IsZero() || task.EvidenceID != "" || task.FailureCode != "" {
			return fmt.Errorf("queued read task lifecycle is inconsistent")
		}
	case ReadTaskRunning:
		if task.StartedAt.IsZero() || !task.CompletedAt.IsZero() || task.EvidenceID != "" || task.FailureCode != "" {
			return fmt.Errorf("running read task lifecycle is inconsistent")
		}
	case ReadTaskEvidence:
		if task.StartedAt.IsZero() || task.CompletedAt.IsZero() || !validIdentifier(task.EvidenceID, 256) || task.FailureCode != "" {
			return fmt.Errorf("evidence read task lifecycle is inconsistent")
		}
	case ReadTaskFailed:
		if task.StartedAt.IsZero() || task.CompletedAt.IsZero() || task.EvidenceID != "" || !ValidFailureCode(task.FailureCode) {
			return fmt.Errorf("failed read task lifecycle is inconsistent")
		}
	case ReadTaskCancelled:
		if task.CompletedAt.IsZero() || task.EvidenceID != "" || !ValidFailureCode(task.FailureCode) {
			return fmt.Errorf("cancelled read task lifecycle is inconsistent")
		}
	}
	return nil
}
