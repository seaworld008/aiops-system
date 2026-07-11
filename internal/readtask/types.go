// Package readtask defines the secret-safe domain contract for authenticated
// READ Runner investigation attempts. It contains no transport or persistence
// implementation.
package readtask

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sync"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
)

var (
	ErrInvalidRequest     = errors.New("invalid read task request")
	ErrNotFound           = errors.New("read task not found")
	ErrNoClaimAvailable   = errors.New("no read task claim available")
	ErrClaimsDisabled     = errors.New("read task claims are disabled")
	ErrStaleFence         = errors.New("stale read task fence")
	ErrInvalidTransition  = errors.New("invalid read task transition")
	ErrHeartbeatConflict  = errors.New("read task heartbeat conflict")
	ErrCompletionConflict = errors.New("read task completion conflict")
	ErrProjectionRejected = errors.New("read task completion projection rejected")
	ErrPersistence        = errors.New("read task persistence failed")
	ErrSensitiveDestroyed = errors.New("read task sensitive value is destroyed")
)

var (
	persistentUUIDPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)
	runnerIDPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$`)
	sha256Pattern         = regexp.MustCompile(`^[a-f0-9]{64}$`)
	lowCardinalityPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]*$`)
)

// Descriptor is the immutable, server-persisted task description. It carries
// no target URL, credential, command, environment variable, or Runner identity.
type Descriptor struct {
	TenantID        string
	WorkspaceID     string
	EnvironmentID   string
	IncidentID      string
	InvestigationID string
	TaskID          string
	TaskKey         string
	Position        int
	ConnectorID     string
	Operation       string
	Input           json.RawMessage
	InputHash       string
}

func (descriptor Descriptor) Validate() error {
	for _, identifier := range []string{
		descriptor.TenantID, descriptor.WorkspaceID, descriptor.EnvironmentID,
		descriptor.IncidentID, descriptor.InvestigationID, descriptor.TaskID,
	} {
		if !validPersistentUUID(identifier) {
			return ErrInvalidRequest
		}
	}
	if len(descriptor.TaskKey) > 64 || !lowCardinalityPattern.MatchString(descriptor.TaskKey) ||
		descriptor.Position < 1 || descriptor.Position > 12 ||
		len(descriptor.ConnectorID) > 128 || !lowCardinalityPattern.MatchString(descriptor.ConnectorID) ||
		len(descriptor.Operation) > 64 || !lowCardinalityPattern.MatchString(descriptor.Operation) ||
		!validSHA256(descriptor.InputHash) || domain.ValidateSafeJSONObject(descriptor.Input) != nil {
		return ErrInvalidRequest
	}
	digest := sha256.Sum256(descriptor.Input)
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(digest[:])), []byte(descriptor.InputHash)) != 1 {
		return ErrInvalidRequest
	}
	return nil
}

func cloneDescriptor(descriptor Descriptor) Descriptor {
	descriptor.Input = bytes.Clone(descriptor.Input)
	return descriptor
}

// CertificateBinding is the authenticated server-side leaf-certificate
// evidence bound to an attempt. NotAfter is also the hard upper bound for its
// lease; this type is never populated from a Runner request body.
type CertificateBinding struct {
	SHA256   string
	NotAfter time.Time
}

func (binding CertificateBinding) Validate() error {
	if !validSHA256(binding.SHA256) || !validTime(binding.NotAfter) {
		return ErrInvalidRequest
	}
	return nil
}

type AttemptStatus string

const (
	AttemptLeased    AttemptStatus = "LEASED"
	AttemptRunning   AttemptStatus = "RUNNING"
	AttemptCompleted AttemptStatus = "COMPLETED"
	AttemptReleased  AttemptStatus = "RELEASED"
	AttemptExpired   AttemptStatus = "EXPIRED"
	AttemptCancelled AttemptStatus = "CANCELLED"
)

// Attempt is a secret-free durable lease snapshot. Only TokenSHA256 may be
// persisted; the raw bearer exists solely in Claim/Fence.
type Attempt struct {
	TaskID            string
	RunnerID          string
	ScopeRevision     int64
	Certificate       CertificateBinding
	TokenSHA256       string
	Epoch             int64
	Status            AttemptStatus
	HeartbeatSequence int64
	LeaseAcquiredAt   time.Time
	LeaseExpiresAt    time.Time
	LastHeartbeatAt   time.Time
	StartedAt         time.Time
	TerminalAt        time.Time
	RequestHash       string
	ReceiptHash       string
	UpdatedAt         time.Time
}

func (attempt Attempt) ValidateAgainst(descriptor Descriptor) error {
	if descriptor.Validate() != nil || attempt.TaskID != descriptor.TaskID || !validRunnerID(attempt.RunnerID) ||
		attempt.ScopeRevision <= 0 || attempt.Certificate.Validate() != nil || !validSHA256(attempt.TokenSHA256) ||
		attempt.Epoch <= 0 || attempt.HeartbeatSequence < 0 || !validTime(attempt.LeaseAcquiredAt) ||
		!validTime(attempt.LastHeartbeatAt) || !validTime(attempt.LeaseExpiresAt) || !validTime(attempt.UpdatedAt) ||
		attempt.LastHeartbeatAt.Before(attempt.LeaseAcquiredAt) || !attempt.LeaseExpiresAt.After(attempt.LastHeartbeatAt) ||
		attempt.LeaseExpiresAt.After(attempt.Certificate.NotAfter) || attempt.UpdatedAt.Before(attempt.LastHeartbeatAt) {
		return ErrInvalidRequest
	}
	switch attempt.Status {
	case AttemptLeased, AttemptRunning, AttemptCompleted, AttemptReleased, AttemptExpired, AttemptCancelled:
	default:
		return ErrInvalidRequest
	}
	if (!attempt.StartedAt.IsZero() && (!validTime(attempt.StartedAt) || attempt.StartedAt.Before(attempt.LeaseAcquiredAt) || attempt.StartedAt.After(attempt.UpdatedAt))) ||
		(!attempt.TerminalAt.IsZero() && (!validTime(attempt.TerminalAt) || attempt.TerminalAt.Before(attempt.LeaseAcquiredAt) || attempt.TerminalAt.After(attempt.UpdatedAt))) ||
		(!attempt.StartedAt.IsZero() && !attempt.TerminalAt.IsZero() && attempt.TerminalAt.Before(attempt.StartedAt)) {
		return ErrInvalidRequest
	}
	switch attempt.Status {
	case AttemptLeased:
		if !attempt.StartedAt.IsZero() || !attempt.TerminalAt.IsZero() {
			return ErrInvalidRequest
		}
	case AttemptRunning:
		if attempt.StartedAt.IsZero() || !attempt.TerminalAt.IsZero() {
			return ErrInvalidRequest
		}
	case AttemptCompleted:
		if attempt.StartedAt.IsZero() || attempt.TerminalAt.IsZero() || !attempt.TerminalAt.Before(attempt.LeaseExpiresAt) ||
			!validSHA256(attempt.RequestHash) || !validSHA256(attempt.ReceiptHash) {
			return ErrInvalidRequest
		}
	case AttemptReleased:
		if !attempt.StartedAt.IsZero() || attempt.TerminalAt.IsZero() {
			return ErrInvalidRequest
		}
	case AttemptExpired, AttemptCancelled:
		if attempt.TerminalAt.IsZero() {
			return ErrInvalidRequest
		}
	}
	if attempt.Status != AttemptCompleted && (attempt.RequestHash != "" || attempt.ReceiptHash != "") {
		return ErrInvalidRequest
	}
	return nil
}

// Claim is the sole domain object allowed to own the raw token returned by a
// successful claim. All accessors detach caller-owned mutable data.
type Claim struct {
	descriptor Descriptor
	attempt    Attempt
	fence      Fence
}

func NewClaim(descriptor Descriptor, attempt Attempt, token []byte) (Claim, error) {
	if attempt.Status != AttemptLeased || attempt.ValidateAgainst(descriptor) != nil {
		return Claim{}, ErrInvalidRequest
	}
	fence, err := NewFence(attempt.TaskID, attempt.RunnerID, token, attempt.Epoch)
	if err != nil || !fence.MatchesTokenSHA256(attempt.TokenSHA256) {
		fence.Destroy()
		return Claim{}, ErrInvalidRequest
	}
	return Claim{descriptor: cloneDescriptor(descriptor), attempt: attempt, fence: fence}, nil
}

func (claim Claim) Valid() bool {
	return claim.fence.Valid() && claim.attempt.ValidateAgainst(claim.descriptor) == nil &&
		claim.attempt.Status == AttemptLeased && claim.fence.TaskID() == claim.attempt.TaskID &&
		claim.fence.RunnerID() == claim.attempt.RunnerID && claim.fence.Epoch() == claim.attempt.Epoch &&
		claim.fence.MatchesTokenSHA256(claim.attempt.TokenSHA256)
}

func (claim Claim) Descriptor() Descriptor      { return cloneDescriptor(claim.descriptor) }
func (claim Claim) Attempt() Attempt            { return claim.attempt }
func (claim Claim) Fence() Fence                { return claim.fence }
func (claim Claim) TokenSHA256() string         { return claim.fence.TokenSHA256() }
func (claim Claim) TokenBytes() ([]byte, error) { return claim.fence.TokenBytes() }
func (claim *Claim) Destroy() {
	if claim != nil {
		claim.fence.Destroy()
	}
}
func (claim Claim) String() string {
	return fmt.Sprintf("ReadTaskClaim{TaskID:%q Epoch:%d Security:[REDACTED]}", claim.attempt.TaskID, claim.attempt.Epoch)
}
func (claim Claim) GoString() string               { return claim.String() }
func (claim Claim) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, claim.String()) }
func (Claim) MarshalJSON() ([]byte, error)         { return []byte(`{"redacted":true}`), nil }
func (*Claim) UnmarshalJSON([]byte) error          { return ErrInvalidRequest }

type tokenState struct {
	mu    sync.Mutex
	value []byte
}

// Fence is a short-lived bearer fence. Its raw token is never serializable or
// directly exposed as a string; TokenBytes returns a caller-owned copy.
type Fence struct {
	taskID   string
	runnerID string
	epoch    int64
	token    *tokenState
}

func NewFence(taskID, runnerID string, token []byte, epoch int64) (Fence, error) {
	if !validPersistentUUID(taskID) || !validRunnerID(runnerID) || epoch <= 0 || !validToken(token) {
		return Fence{}, ErrInvalidRequest
	}
	return Fence{
		taskID: taskID, runnerID: runnerID, epoch: epoch,
		token: &tokenState{value: append([]byte(nil), token...)},
	}, nil
}

func (fence Fence) TaskID() string   { return fence.taskID }
func (fence Fence) RunnerID() string { return fence.runnerID }
func (fence Fence) Epoch() int64     { return fence.epoch }

func (fence Fence) Valid() bool {
	if !validPersistentUUID(fence.taskID) || !validRunnerID(fence.runnerID) || fence.epoch <= 0 || fence.token == nil {
		return false
	}
	fence.token.mu.Lock()
	defer fence.token.mu.Unlock()
	return validToken(fence.token.value)
}

func (fence Fence) TokenBytes() ([]byte, error) {
	if fence.token == nil {
		return nil, ErrSensitiveDestroyed
	}
	fence.token.mu.Lock()
	defer fence.token.mu.Unlock()
	if !validToken(fence.token.value) {
		return nil, ErrSensitiveDestroyed
	}
	return append([]byte(nil), fence.token.value...), nil
}

func (fence Fence) TokenSHA256() string {
	if fence.token == nil {
		return ""
	}
	fence.token.mu.Lock()
	defer fence.token.mu.Unlock()
	if !validToken(fence.token.value) {
		return ""
	}
	digest := sha256.Sum256(fence.token.value)
	return hex.EncodeToString(digest[:])
}

func (fence Fence) MatchesTokenSHA256(expected string) bool {
	actual := fence.TokenSHA256()
	if !validSHA256(actual) || !validSHA256(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) == 1
}

func (fence *Fence) Destroy() {
	if fence == nil || fence.token == nil {
		return
	}
	fence.token.mu.Lock()
	for index := range fence.token.value {
		fence.token.value[index] = 0
	}
	fence.token.value = nil
	fence.token.mu.Unlock()
}

func (fence Fence) String() string {
	return fmt.Sprintf("ReadTaskFence{TaskID:%q Epoch:%d Security:[REDACTED]}", fence.taskID, fence.epoch)
}

func (fence Fence) GoString() string { return fence.String() }

func (fence Fence) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, fence.String())
}

func (Fence) MarshalJSON() ([]byte, error) {
	return []byte(`{"redacted":true}`), nil
}

func (*Fence) UnmarshalJSON([]byte) error { return ErrInvalidRequest }

func validPersistentUUID(value string) bool { return persistentUUIDPattern.MatchString(value) }
func validRunnerID(value string) bool       { return runnerIDPattern.MatchString(value) }
func validSHA256(value string) bool         { return sha256Pattern.MatchString(value) }
func validTime(value time.Time) bool {
	return !value.IsZero() && value.Year() >= 1 && value.Year() <= 9999
}

func validToken(value []byte) bool {
	// A lease bearer is always the unpadded base64url encoding of exactly
	// 32 random bytes. Fixing both representations avoids accepting a token
	// that merely looks long enough while carrying materially less entropy.
	if len(value) != base64.RawURLEncoding.EncodedLen(32) {
		return false
	}
	decoded := make([]byte, base64.RawURLEncoding.DecodedLen(len(value)))
	decodedLength, err := base64.RawURLEncoding.Decode(decoded, value)
	defer clear(decoded)
	if err != nil {
		return false
	}
	return decodedLength == 32
}

var _ json.Marshaler = Fence{}
