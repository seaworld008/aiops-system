// Package runnerclient implements the outbound-only Runner Gateway v1 client.
package runnerclient

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/seaworld008/aiops-system/internal/credential"
	"github.com/seaworld008/aiops-system/internal/runnergateway"
	"github.com/seaworld008/aiops-system/internal/runneridentity"
)

var (
	ErrInvalidConfiguration = errors.New("invalid Runner Gateway client configuration")
	ErrInvalidResponse      = errors.New("invalid Runner Gateway response")
	ErrRedirectRejected     = errors.New("Runner Gateway redirects are forbidden")
	ErrSensitiveDestroyed   = errors.New("Runner Gateway sensitive handle is destroyed")
)

// Options names the dedicated Runner Gateway trust material. All files are
// loaded directly from clean absolute paths; system roots and proxy state are
// never consulted.
type Options struct {
	BaseURL               string
	ServerName            string
	TrustDomain           string
	ExpectedPool          runneridentity.Pool
	RootCAFile            string
	ClientCertificateFile string
	ClientPrivateKeyFile  string
}

// Identity is the server-side registration snapshot bound to the configured
// client certificate. It deliberately contains no reusable bearer material.
type Identity struct {
	RunnerID            string
	Pool                runneridentity.Pool
	ScopeRevision       int64
	MaxConcurrency      int
	Capabilities        []string
	CertificateSHA256   string
	CertificateNotAfter time.Time
}

type jobLeaseBinding struct {
	runtimeMu             sync.Mutex
	owner                 *Client
	token                 *bearer
	jobID                 string
	planHash              string
	leaseEpoch            int64
	scopeRevision         int64
	leaseExpiresAt        time.Time
	payloadExpiresAt      time.Time
	descriptorSHA256      [32]byte
	heartbeatAfterSeconds int
	runtimeLeaseExpiresAt time.Time
	terminationRequested  bool
	updates               chan struct{}
}

// ProblemError is the bounded RFC 9457 subset safe for control flow and logs.
// The remote detail field is validated but deliberately not retained.
type ProblemError struct {
	Type     string
	Title    string
	Status   int
	Code     string
	Instance string
}

func (problem *ProblemError) Error() string {
	if problem == nil {
		return "Runner Gateway request rejected"
	}
	return fmt.Sprintf("Runner Gateway request rejected: status=%d code=%s", problem.Status, problem.Code)
}

type JobReleaseReason string

const (
	ReleaseExecutorNotReady         JobReleaseReason = "EXECUTOR_NOT_READY"
	ReleaseLocalCapacityUnavailable JobReleaseReason = "LOCAL_CAPACITY_UNAVAILABLE"
	ReleaseTransientRunnerFailure   JobReleaseReason = "TRANSIENT_RUNNER_FAILURE"
)

// JobLease owns the sole raw job lease token returned by the Gateway. The
// token is intentionally inaccessible and shared only by Client methods.
type JobLease struct {
	Job                   runnergateway.JobDescriptor
	LeaseEpoch            int64
	ScopeRevision         int64
	LeaseExpiresAt        time.Time
	HeartbeatAfterSeconds int
	binding               *jobLeaseBinding
}

func (lease *JobLease) Destroy() {
	if lease != nil && lease.binding != nil && lease.binding.token != nil {
		lease.binding.terminate()
		lease.binding.token.Destroy()
	}
}

func (lease *JobLease) String() string {
	if lease == nil {
		return "JobLease{Invalid:true Security:[REDACTED]}"
	}
	if lease.binding == nil {
		return "JobLease{Invalid:true Security:[REDACTED]}"
	}
	return fmt.Sprintf("JobLease{JobID:%q Epoch:%d Security:[REDACTED]}", lease.binding.jobID, lease.binding.leaseEpoch)
}

func (lease *JobLease) GoString() string { return lease.String() }

func (lease *JobLease) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, lease.String())
}

func (lease *JobLease) MarshalJSON() ([]byte, error) {
	if lease == nil {
		return []byte(`{"redacted":true,"invalid":true}`), nil
	}
	return marshalRedacted()
}

func (*JobLease) UnmarshalJSON([]byte) error { return ErrInvalidResponse }

// JobStart is the non-secret RUNNING snapshot returned after the Gateway's
// final authorization. Credential owns the one-shot child-create permit.
type JobStart struct {
	JobID         string
	Status        string
	LeaseEpoch    int64
	ScopeRevision int64
	StartedAt     time.Time
	Credential    *CredentialPreparation
	Grant         *ExecutionGrant
}

type credentialPhase uint8

const (
	credentialPhasePrepared credentialPhase = iota + 1
	credentialPhaseAuthorized
	credentialPhaseAnchored
	credentialPhaseActive
	credentialPhaseNoCredential
	credentialPhaseRevocationRequested
)

type credentialPreparationState struct {
	mu                  sync.Mutex
	lease               *jobLeaseBinding
	revocationID        string
	issuerID            string
	issuerRevision      string
	credentialExpiresAt time.Time
	phase               credentialPhase
}

type CredentialPreparation struct {
	state  *credentialPreparationState
	permit *bearer
}

func (preparation *CredentialPreparation) RevocationID() string {
	if preparation == nil || preparation.state == nil {
		return ""
	}
	return preparation.state.revocationID
}

func (preparation *CredentialPreparation) IssuerID() string {
	if preparation == nil || preparation.state == nil {
		return ""
	}
	return preparation.state.issuerID
}

func (preparation *CredentialPreparation) IssuerRevision() string {
	if preparation == nil || preparation.state == nil {
		return ""
	}
	return preparation.state.issuerRevision
}

func (preparation *CredentialPreparation) CredentialExpiresAt() time.Time {
	if preparation == nil || preparation.state == nil {
		return time.Time{}
	}
	return preparation.state.credentialExpiresAt
}

func (preparation *CredentialPreparation) Destroy() {
	if preparation != nil && preparation.permit != nil {
		preparation.permit.Destroy()
	}
}

func (preparation *CredentialPreparation) String() string {
	if preparation == nil {
		return "CredentialPreparation{Invalid:true Security:[REDACTED]}"
	}
	return fmt.Sprintf("CredentialPreparation{RevocationID:%q Security:[REDACTED]}", preparation.RevocationID())
}

func (preparation *CredentialPreparation) GoString() string { return preparation.String() }

func (preparation *CredentialPreparation) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, preparation.String())
}

func (preparation *CredentialPreparation) MarshalJSON() ([]byte, error) { return marshalRedacted() }
func (*CredentialPreparation) UnmarshalJSON([]byte) error               { return ErrInvalidResponse }

// ExecutionGrant is a server-authorized, credential-state-bound capability
// required to cross the GO barrier. It has no public constructor.
type executionGrantState struct {
	mu         sync.Mutex
	credential *credentialPreparationState
	consumed   bool
}

type ExecutionGrant struct{ state *executionGrantState }

func (grant *ExecutionGrant) String() string   { return "ExecutionGrant{Security:[REDACTED]}" }
func (grant *ExecutionGrant) GoString() string { return grant.String() }
func (grant *ExecutionGrant) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, grant.String())
}
func (*ExecutionGrant) MarshalJSON() ([]byte, error) { return marshalRedacted() }
func (*ExecutionGrant) UnmarshalJSON([]byte) error   { return ErrInvalidResponse }

type revocationLeaseState struct {
	runtimeMu             sync.Mutex
	owner                 *Client
	revocationID          string
	claimEpoch            int64
	runtimeClaimExpiresAt time.Time
	terminationRequested  bool
	heartbeatAfterSeconds int
	tenantID              string
	workspaceID           string
	environmentID         string
	issuerID              string
	issuerRevision        string
	revokeAccessor        *credential.SensitiveReference
	token                 *bearer
}

// RevocationLease is an immutable claim capability. The revoke-only accessor
// can only be borrowed through WithRevokeAccessor, which clears its temporary
// byte copy immediately after the callback returns.
type RevocationLease struct{ state *revocationLeaseState }

func (lease *RevocationLease) RevocationID() string {
	if lease == nil || lease.state == nil {
		return ""
	}
	return lease.state.revocationID
}

func (lease *RevocationLease) ClaimEpoch() int64 {
	if lease == nil || lease.state == nil {
		return 0
	}
	return lease.state.claimEpoch
}

func (lease *RevocationLease) ClaimExpiresAt() time.Time {
	if lease == nil || lease.state == nil {
		return time.Time{}
	}
	lease.state.runtimeMu.Lock()
	defer lease.state.runtimeMu.Unlock()
	return lease.state.runtimeClaimExpiresAt
}

func (lease *RevocationLease) TerminationRequested() bool {
	if lease == nil || lease.state == nil {
		return true
	}
	lease.state.runtimeMu.Lock()
	defer lease.state.runtimeMu.Unlock()
	return lease.state.terminationRequested
}

func (lease *RevocationLease) HeartbeatAfterSeconds() int {
	if lease == nil || lease.state == nil {
		return 0
	}
	return lease.state.heartbeatAfterSeconds
}

func (lease *RevocationLease) TenantID() string {
	if lease == nil || lease.state == nil {
		return ""
	}
	return lease.state.tenantID
}

func (lease *RevocationLease) WorkspaceID() string {
	if lease == nil || lease.state == nil {
		return ""
	}
	return lease.state.workspaceID
}

func (lease *RevocationLease) EnvironmentID() string {
	if lease == nil || lease.state == nil {
		return ""
	}
	return lease.state.environmentID
}

func (lease *RevocationLease) IssuerID() string {
	if lease == nil || lease.state == nil {
		return ""
	}
	return lease.state.issuerID
}

func (lease *RevocationLease) IssuerRevision() string {
	if lease == nil || lease.state == nil {
		return ""
	}
	return lease.state.issuerRevision
}

func (lease *RevocationLease) WithRevokeAccessor(operation func([]byte) error) error {
	if lease == nil || lease.state == nil || lease.state.revokeAccessor == nil || operation == nil {
		return ErrSensitiveDestroyed
	}
	value := lease.state.revokeAccessor.Bytes()
	if len(value) == 0 {
		return ErrSensitiveDestroyed
	}
	defer clear(value)
	return operation(value)
}

func (lease *RevocationLease) Destroy() {
	if lease == nil {
		return
	}
	if lease.state == nil {
		return
	}
	lease.state.runtimeMu.Lock()
	lease.state.terminationRequested = true
	lease.state.runtimeMu.Unlock()
	if lease.state.token != nil {
		lease.state.token.Destroy()
	}
	if lease.state.revokeAccessor != nil {
		lease.state.revokeAccessor.Destroy()
	}
}

func (lease *RevocationLease) String() string {
	if lease == nil {
		return "RevocationLease{Invalid:true Security:[REDACTED]}"
	}
	return fmt.Sprintf("RevocationLease{RevocationID:%q Epoch:%d Security:[REDACTED]}", lease.RevocationID(), lease.ClaimEpoch())
}

func (lease *RevocationLease) GoString() string { return lease.String() }

func (lease *RevocationLease) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, lease.String())
}

func (lease *RevocationLease) MarshalJSON() ([]byte, error) { return marshalRedacted() }
func (*RevocationLease) UnmarshalJSON([]byte) error         { return ErrInvalidResponse }
