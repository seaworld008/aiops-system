package readrunnerclient

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/readtask"
)

// decimalInt64 preserves PostgreSQL bigint fences beyond the I-JSON integer
// range and rejects every non-canonical decimal representation.
type decimalInt64 int64

func (value decimalInt64) Int64() int64 { return int64(value) }

func (value decimalInt64) MarshalJSON() ([]byte, error) {
	if value < 0 {
		return nil, ErrInvalidResponse
	}
	return []byte(`"` + strconv.FormatInt(int64(value), 10) + `"`), nil
}

func (value *decimalInt64) UnmarshalJSON(encoded []byte) error {
	if value == nil || len(encoded) < 3 || encoded[0] != '"' || encoded[len(encoded)-1] != '"' {
		return ErrInvalidResponse
	}
	decimal := string(encoded[1 : len(encoded)-1])
	if decimal == "" || len(decimal) > 19 || (decimal != "0" && decimal[0] == '0') {
		return ErrInvalidResponse
	}
	for _, character := range decimal {
		if character < '0' || character > '9' {
			return ErrInvalidResponse
		}
	}
	parsed, err := strconv.ParseInt(decimal, 10, 64)
	if err != nil || parsed < 0 {
		return fmt.Errorf("%w: decimal int64", ErrInvalidResponse)
	}
	*value = decimalInt64(parsed)
	return nil
}

type claimRequestWire struct {
	SchemaVersion string `json:"schema_version"`
}

type taskDescriptorWire struct {
	ID             string                          `json:"id"`
	Key            string                          `json:"key"`
	Position       int                             `json:"position"`
	ConnectorID    string                          `json:"connector_id"`
	Operation      string                          `json:"operation"`
	Input          json.RawMessage                 `json:"input"`
	InputHash      string                          `json:"input_hash"`
	PlanBinding    domain.InvestigationPlanBinding `json:"plan_binding"`
	RuntimeBinding domain.ReadTaskRuntimeBinding   `json:"runtime_binding"`
}

type claimResponseWire struct {
	SchemaVersion         string             `json:"schema_version"`
	Task                  taskDescriptorWire `json:"task"`
	LeaseToken            sensitiveASCII     `json:"lease_token"`
	LeaseEpoch            decimalInt64       `json:"lease_epoch"`
	ScopeRevision         decimalInt64       `json:"scope_revision"`
	LeaseExpiresAt        time.Time          `json:"lease_expires_at"`
	HeartbeatAfterSeconds int                `json:"heartbeat_after_seconds"`
}

type startRequestWire struct {
	SchemaVersion string       `json:"schema_version"`
	LeaseEpoch    decimalInt64 `json:"lease_epoch"`
}

type startResponseWire struct {
	SchemaVersion string       `json:"schema_version"`
	TaskID        string       `json:"task_id"`
	AttemptStatus string       `json:"attempt_status"`
	LeaseEpoch    decimalInt64 `json:"lease_epoch"`
	ScopeRevision decimalInt64 `json:"scope_revision"`
	StartedAt     time.Time    `json:"started_at"`
}

type heartbeatRequestWire struct {
	SchemaVersion string       `json:"schema_version"`
	LeaseEpoch    decimalInt64 `json:"lease_epoch"`
	Sequence      decimalInt64 `json:"sequence"`
}

type heartbeatResponseWire struct {
	SchemaVersion         string       `json:"schema_version"`
	TaskID                string       `json:"task_id"`
	LeaseEpoch            decimalInt64 `json:"lease_epoch"`
	AcceptedSequence      decimalInt64 `json:"accepted_sequence"`
	Directive             string       `json:"directive"`
	LeaseExpiresAt        time.Time    `json:"lease_expires_at"`
	HeartbeatAfterSeconds int          `json:"heartbeat_after_seconds"`
}

type releaseRequestWire struct {
	SchemaVersion string       `json:"schema_version"`
	LeaseEpoch    decimalInt64 `json:"lease_epoch"`
	ReasonCode    string       `json:"reason_code"`
}

type releaseResponseWire struct {
	SchemaVersion string       `json:"schema_version"`
	TaskID        string       `json:"task_id"`
	AttemptStatus string       `json:"attempt_status"`
	LeaseEpoch    decimalInt64 `json:"lease_epoch"`
}

type evidenceCompletionWire struct {
	CollectedAt time.Time         `json:"collected_at"`
	Items       []json.RawMessage `json:"items"`
}

type completeRequestWire struct {
	SchemaVersion string                     `json:"schema_version"`
	LeaseEpoch    decimalInt64               `json:"lease_epoch"`
	Outcome       readtask.CompletionOutcome `json:"outcome"`
	Evidence      *evidenceCompletionWire    `json:"evidence,omitempty"`
	FailureCode   readtask.FailureCode       `json:"failure_code,omitempty"`
}

type completeResponseWire struct {
	SchemaVersion string       `json:"schema_version"`
	TaskID        string       `json:"task_id"`
	LeaseEpoch    decimalInt64 `json:"lease_epoch"`
	AttemptStatus string       `json:"attempt_status"`
	TaskStatus    string       `json:"task_status"`
	EvidenceID    string       `json:"evidence_id,omitempty"`
	ContentHash   string       `json:"content_hash,omitempty"`
	ReceiptID     string       `json:"receipt_id"`
	ReceiptHash   string       `json:"receipt_hash"`
	Replayed      bool         `json:"replayed"`
}
