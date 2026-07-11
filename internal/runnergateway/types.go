package runnergateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/seaworld008/aiops-system/internal/action"
	"github.com/seaworld008/aiops-system/internal/execution"
	"github.com/seaworld008/aiops-system/internal/runneridentity"
)

// DecimalInt64 is encoded as a canonical decimal JSON string so PostgreSQL
// bigint fences retain full precision beyond the I-JSON safe integer range.
type DecimalInt64 int64

func (value DecimalInt64) Int64() int64 { return int64(value) }

func (value DecimalInt64) MarshalJSON() ([]byte, error) {
	if value < 0 {
		return nil, ErrInvalidRequest
	}
	return []byte(`"` + strconv.FormatInt(int64(value), 10) + `"`), nil
}

func (value *DecimalInt64) UnmarshalJSON(encoded []byte) error {
	if value == nil || len(encoded) < 3 || encoded[0] != '"' || encoded[len(encoded)-1] != '"' {
		return ErrInvalidRequest
	}
	decimal := string(encoded[1 : len(encoded)-1])
	if decimal == "" || len(decimal) > 19 || (decimal != "0" && decimal[0] == '0') {
		return ErrInvalidRequest
	}
	for _, character := range decimal {
		if character < '0' || character > '9' {
			return ErrInvalidRequest
		}
	}
	parsed, err := strconv.ParseInt(decimal, 10, 64)
	if err != nil || parsed < 0 {
		return fmt.Errorf("%w: decimal int64", ErrInvalidRequest)
	}
	*value = DecimalInt64(parsed)
	return nil
}

const (
	leaseBodyLimit   int64 = 256 << 10
	defaultBodyLimit int64 = 64 << 10
)

var (
	ErrInvalidRequest      = errors.New("invalid runner request")
	ErrLeaseAuthentication = errors.New("runner lease authentication failed")
	ErrForbidden           = errors.New("runner identity is forbidden")
	ErrNotFound            = errors.New("runner resource not found")
	ErrStaleLease          = errors.New("stale runner lease")
	ErrStateConflict       = errors.New("runner state conflict")
	ErrHeartbeatConflict   = errors.New("runner heartbeat sequence conflict")
	ErrCredentialConflict  = errors.New("runner credential anchor conflict")
	ErrResultConflict      = errors.New("runner result conflict")
	ErrRateLimited         = errors.New("runner rate limited")
	ErrClaimsDisabled      = errors.New("runner claims disabled")
	ErrUnavailable         = errors.New("runner dependency unavailable")
)

type IdentityVerifier interface {
	IdentityFromConnectionState(state tls.ConnectionState) (runneridentity.Identity, error)
}

// RequestPrincipal is the opaque, server-side registration snapshot produced
// by per-request database authentication. The Router uses it only for
// pre-dispatch pool/capability gates and response binding; every state-changing
// backend method must authenticate again inside its own transaction.
type RequestPrincipal interface {
	Valid() bool
	RunnerID() string
	TenantID() string
	Pool() runneridentity.Pool
	ScopeRevision() int64
	MaxConcurrency() int
	CredentialRevocationCapable() bool
	CertificateSHA256() string
	CertificateNotAfter() time.Time
	Allows(workspaceID, environmentID string) bool
}

// Backend is the only stateful dependency of the Runner listener. Every method
// receives the certificate-derived identity; request bodies never contain a
// Runner ID, pool, scope, certificate fingerprint, or capability.
type Backend interface {
	AuthenticateRequest(context.Context, runneridentity.Identity) (RequestPrincipal, error)
	Identity(context.Context, runneridentity.Identity) (RunnerIdentityResponse, error)
	LeaseJob(context.Context, runneridentity.Identity, JobLeaseRequest) (*JobLeaseResponse, error)
	AnchorCredential(context.Context, runneridentity.Identity, string, string, CredentialAnchorRequest) (CredentialAnchorResponse, error)
	StartJob(context.Context, runneridentity.Identity, string, string, JobStartRequest) (JobStartResponse, error)
	HeartbeatJob(context.Context, runneridentity.Identity, string, string, JobHeartbeatRequest) (JobHeartbeatResponse, error)
	ReleaseJob(context.Context, runneridentity.Identity, string, string, JobReleaseRequest) (JobStateResponse, error)
	CompleteJob(context.Context, runneridentity.Identity, string, string, JobCompleteRequest) (JobCompletionResponse, error)
	LeaseRevocation(context.Context, runneridentity.Identity, RevocationLeaseRequest) (*RevocationLeaseResponse, error)
	HeartbeatRevocation(context.Context, runneridentity.Identity, string, string, RevocationHeartbeatRequest) (RevocationHeartbeatResponse, error)
	CompleteRevocation(context.Context, runneridentity.Identity, string, string, RevocationCompleteRequest) (RevocationCompletionResponse, error)
}

type RunnerIdentityResponse struct {
	SchemaVersion       string       `json:"schema_version"`
	RunnerID            string       `json:"runner_id"`
	Pool                string       `json:"pool"`
	ScopeRevision       DecimalInt64 `json:"scope_revision"`
	MaxConcurrency      int          `json:"max_concurrency"`
	Capabilities        []string     `json:"capabilities"`
	CertificateSHA256   string       `json:"certificate_sha256"`
	CertificateNotAfter time.Time    `json:"certificate_not_after"`
}

type JobLeaseRequest struct {
	SchemaVersion string `json:"schema_version"`
}

type JobDescriptor struct {
	ID                  string          `json:"id"`
	Kind                string          `json:"kind"`
	Payload             action.Envelope `json:"payload"`
	PlanHash            string          `json:"plan_hash"`
	EnvironmentRevision string          `json:"environment_revision"`
	Production          bool            `json:"production"`
}

type JobLeaseResponse struct {
	SchemaVersion         string        `json:"schema_version"`
	Job                   JobDescriptor `json:"job"`
	LeaseToken            string        `json:"lease_token"`
	LeaseEpoch            DecimalInt64  `json:"lease_epoch"`
	ScopeRevision         DecimalInt64  `json:"scope_revision"`
	LeaseExpiresAt        time.Time     `json:"lease_expires_at"`
	HeartbeatAfterSeconds int           `json:"heartbeat_after_seconds"`
}

type CredentialAnchorRequest struct {
	SchemaVersion      string       `json:"schema_version"`
	Phase              string       `json:"phase"`
	LeaseEpoch         DecimalInt64 `json:"lease_epoch"`
	RevocationID       string       `json:"revocation_id"`
	ChildCreatePermit  string       `json:"child_create_permit,omitempty"`
	RevokeAccessorB64U string       `json:"revoke_accessor_b64u,omitempty"`
}

type CredentialAnchorResponse struct {
	SchemaVersion        string     `json:"schema_version"`
	JobID                string     `json:"job_id"`
	RevocationID         string     `json:"revocation_id"`
	Status               string     `json:"status"`
	DatabaseAuthorizedAt *time.Time `json:"database_authorized_at,omitempty"`
	ChildTTLSeconds      int        `json:"child_ttl_seconds,omitempty"`
	CredentialExpiresAt  *time.Time `json:"credential_expires_at,omitempty"`
}

type JobStartRequest struct {
	SchemaVersion string       `json:"schema_version"`
	LeaseEpoch    DecimalInt64 `json:"lease_epoch"`
}

type CredentialPrepare struct {
	RevocationID        string    `json:"revocation_id"`
	ChildCreatePermit   string    `json:"child_create_permit"`
	IssuerID            string    `json:"issuer_id"`
	IssuerRevision      string    `json:"issuer_revision"`
	CredentialExpiresAt time.Time `json:"credential_expires_at"`
}

type JobStartResponse struct {
	SchemaVersion     string            `json:"schema_version"`
	JobID             string            `json:"job_id"`
	Status            string            `json:"status"`
	LeaseEpoch        DecimalInt64      `json:"lease_epoch"`
	ScopeRevision     DecimalInt64      `json:"scope_revision"`
	StartedAt         time.Time         `json:"started_at"`
	CredentialPrepare CredentialPrepare `json:"credential_prepare"`
}

type JobHeartbeatRequest struct {
	SchemaVersion string       `json:"schema_version"`
	LeaseEpoch    DecimalInt64 `json:"lease_epoch"`
	Sequence      DecimalInt64 `json:"sequence"`
}

type JobHeartbeatResponse struct {
	SchemaVersion         string       `json:"schema_version"`
	JobID                 string       `json:"job_id"`
	AcceptedSequence      DecimalInt64 `json:"accepted_sequence"`
	Directive             string       `json:"directive"`
	LeaseExpiresAt        time.Time    `json:"lease_expires_at"`
	HeartbeatAfterSeconds int          `json:"heartbeat_after_seconds"`
}

type JobReleaseRequest struct {
	SchemaVersion string       `json:"schema_version"`
	LeaseEpoch    DecimalInt64 `json:"lease_epoch"`
	ReasonCode    string       `json:"reason_code"`
}

type JobStateResponse struct {
	SchemaVersion string       `json:"schema_version"`
	JobID         string       `json:"job_id"`
	Status        string       `json:"status"`
	LeaseEpoch    DecimalInt64 `json:"lease_epoch"`
}

type JobCompleteRequest struct {
	SchemaVersion string                   `json:"schema_version"`
	LeaseEpoch    DecimalInt64             `json:"lease_epoch"`
	Result        execution.ExecutorResult `json:"result"`
}

type JobCompletionResponse struct {
	SchemaVersion           string `json:"schema_version"`
	JobID                   string `json:"job_id"`
	Status                  string `json:"status"`
	CompletionStatus        string `json:"completion_status"`
	ReceiptHash             string `json:"receipt_hash"`
	CredentialCleanupStatus string `json:"credential_cleanup_status"`
}

type RevocationLeaseRequest struct {
	SchemaVersion string `json:"schema_version"`
}

type RevocationLeaseResponse struct {
	SchemaVersion         string       `json:"schema_version"`
	RevocationID          string       `json:"revocation_id"`
	ClaimToken            string       `json:"claim_token"`
	ClaimEpoch            DecimalInt64 `json:"claim_epoch"`
	ClaimExpiresAt        time.Time    `json:"claim_expires_at"`
	HeartbeatAfterSeconds int          `json:"heartbeat_after_seconds"`
	TenantID              string       `json:"tenant_id"`
	WorkspaceID           string       `json:"workspace_id"`
	EnvironmentID         string       `json:"environment_id"`
	IssuerID              string       `json:"issuer_id"`
	IssuerRevision        string       `json:"issuer_revision"`
	RevokeAccessorB64U    string       `json:"revoke_accessor_b64u"`
}

type RevocationHeartbeatRequest struct {
	SchemaVersion string       `json:"schema_version"`
	ClaimEpoch    DecimalInt64 `json:"claim_epoch"`
	Sequence      DecimalInt64 `json:"sequence"`
}

type RevocationHeartbeatResponse struct {
	SchemaVersion         string       `json:"schema_version"`
	RevocationID          string       `json:"revocation_id"`
	AcceptedSequence      DecimalInt64 `json:"accepted_sequence"`
	Directive             string       `json:"directive"`
	ClaimExpiresAt        time.Time    `json:"claim_expires_at"`
	HeartbeatAfterSeconds int          `json:"heartbeat_after_seconds"`
}

type RevocationCompleteRequest struct {
	SchemaVersion string       `json:"schema_version"`
	ClaimEpoch    DecimalInt64 `json:"claim_epoch"`
	Outcome       string       `json:"outcome"`
	FailureCode   string       `json:"failure_code,omitempty"`
}

type RevocationCompletionResponse struct {
	SchemaVersion string       `json:"schema_version"`
	RevocationID  string       `json:"revocation_id"`
	Status        string       `json:"status"`
	ClaimEpoch    DecimalInt64 `json:"claim_epoch"`
	AvailableAt   *time.Time   `json:"available_at,omitempty"`
}
