package runnergateway

import (
	"context"
	"encoding/json"
	"time"

	"github.com/seaworld008/aiops-system/internal/readgateway"
	"github.com/seaworld008/aiops-system/internal/readtask"
	"github.com/seaworld008/aiops-system/internal/runneridentity"
)

// ReadTaskBackend is the stateful boundary for the READ-only investigation
// protocol. Implementations must re-authenticate identity and mutate the task
// in one transaction; the Router's outer authentication is only an early
// per-request rejection boundary.
type ReadTaskBackend interface {
	Claim(context.Context, runneridentity.Identity, string) (readtask.Claim, readgateway.ResponseBinding, error)
	Start(context.Context, runneridentity.Identity, readtask.Start) (readtask.Attempt, readgateway.ResponseBinding, error)
	Heartbeat(context.Context, runneridentity.Identity, readtask.Heartbeat) (readtask.HeartbeatResult, readgateway.ResponseBinding, error)
	Release(context.Context, runneridentity.Identity, readtask.Release) (readtask.Attempt, readgateway.ResponseBinding, error)
	Complete(context.Context, runneridentity.Identity, readtask.Completion) (readtask.CompletionResult, readgateway.ResponseBinding, error)
}

type ReadTaskClaimRequest struct {
	SchemaVersion string `json:"schema_version"`
}

type ReadTaskDescriptor struct {
	ID             string                 `json:"id"`
	Key            string                 `json:"key"`
	Position       int                    `json:"position"`
	ConnectorID    string                 `json:"connector_id"`
	Operation      string                 `json:"operation"`
	Input          json.RawMessage        `json:"input"`
	InputHash      string                 `json:"input_hash"`
	PlanBinding    ReadTaskPlanBinding    `json:"plan_binding"`
	RuntimeBinding ReadTaskRuntimeBinding `json:"runtime_binding"`
}

type ReadTaskPlanBinding struct {
	SchemaVersion  string `json:"schema_version"`
	ManifestDigest string `json:"manifest_digest"`
	RegistryDigest string `json:"registry_digest"`
	ProfileDigest  string `json:"profile_digest"`
	TasksHash      string `json:"tasks_hash"`
}

type ReadTaskRuntimeBinding struct {
	SchemaVersion   string    `json:"schema_version"`
	ConnectorDigest string    `json:"connector_digest"`
	TargetDigest    string    `json:"target_digest"`
	ExecutorDigest  string    `json:"executor_digest"`
	RuntimeDigest   string    `json:"runtime_digest"`
	BoundAt         time.Time `json:"bound_at"`
}

type ReadTaskClaimResponse struct {
	SchemaVersion         string             `json:"schema_version"`
	Task                  ReadTaskDescriptor `json:"task"`
	LeaseToken            string             `json:"lease_token"`
	LeaseEpoch            DecimalInt64       `json:"lease_epoch"`
	ScopeRevision         DecimalInt64       `json:"scope_revision"`
	LeaseExpiresAt        time.Time          `json:"lease_expires_at"`
	HeartbeatAfterSeconds int                `json:"heartbeat_after_seconds"`
}

type ReadTaskStartRequest struct {
	SchemaVersion string       `json:"schema_version"`
	LeaseEpoch    DecimalInt64 `json:"lease_epoch"`
}

type ReadTaskStartResponse struct {
	SchemaVersion string       `json:"schema_version"`
	TaskID        string       `json:"task_id"`
	AttemptStatus string       `json:"attempt_status"`
	LeaseEpoch    DecimalInt64 `json:"lease_epoch"`
	ScopeRevision DecimalInt64 `json:"scope_revision"`
	StartedAt     time.Time    `json:"started_at"`
}

type ReadTaskHeartbeatRequest struct {
	SchemaVersion string       `json:"schema_version"`
	LeaseEpoch    DecimalInt64 `json:"lease_epoch"`
	Sequence      DecimalInt64 `json:"sequence"`
}

type ReadTaskHeartbeatResponse struct {
	SchemaVersion         string       `json:"schema_version"`
	TaskID                string       `json:"task_id"`
	LeaseEpoch            DecimalInt64 `json:"lease_epoch"`
	AcceptedSequence      DecimalInt64 `json:"accepted_sequence"`
	Directive             string       `json:"directive"`
	LeaseExpiresAt        time.Time    `json:"lease_expires_at"`
	HeartbeatAfterSeconds int          `json:"heartbeat_after_seconds"`
}

type ReadTaskReleaseRequest struct {
	SchemaVersion string       `json:"schema_version"`
	LeaseEpoch    DecimalInt64 `json:"lease_epoch"`
	ReasonCode    string       `json:"reason_code"`
}

type ReadTaskReleaseResponse struct {
	SchemaVersion string       `json:"schema_version"`
	TaskID        string       `json:"task_id"`
	AttemptStatus string       `json:"attempt_status"`
	LeaseEpoch    DecimalInt64 `json:"lease_epoch"`
}

type ReadTaskEvidenceCompletion struct {
	CollectedAt time.Time         `json:"collected_at"`
	Items       []json.RawMessage `json:"items"`
}

type ReadTaskCompleteRequest struct {
	SchemaVersion string                      `json:"schema_version"`
	LeaseEpoch    DecimalInt64                `json:"lease_epoch"`
	Outcome       readtask.CompletionOutcome  `json:"outcome"`
	Evidence      *ReadTaskEvidenceCompletion `json:"evidence,omitempty"`
	FailureCode   readtask.FailureCode        `json:"failure_code,omitempty"`
}

type ReadTaskCompleteResponse struct {
	SchemaVersion string       `json:"schema_version"`
	TaskID        string       `json:"task_id"`
	LeaseEpoch    DecimalInt64 `json:"lease_epoch"`
	AttemptStatus string       `json:"attempt_status"`
	TaskStatus    string       `json:"task_status"`
	EvidenceID    string       `json:"evidence_id,omitempty"`
	ContentHash   string       `json:"content_hash,omitempty"`
	ReceiptID     string       `json:"receipt_id"`
	ReceiptHash   string       `json:"receipt_hash"`
	Replayed      bool         `json:"replayed"`
}
