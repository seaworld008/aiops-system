package credential

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
)

const (
	MinRevocationClaimLease           = time.Second
	MaxRevocationClaimLease           = 30 * time.Second
	MaxRevocationClaimBatch           = 100
	RevocationClaimLease              = 30 * time.Second
	RevocationHeartbeatInterval       = 10 * time.Second
	RevocationRemoteTimeout           = 20 * time.Second
	MinRevocationRetryDelay           = 5 * time.Second
	MaxRevocationRetryDelay           = 15 * time.Minute
	MaxRevocationAttempts             = 12
	MaxRevocationElapsed              = 2 * time.Hour
	ManagedAnchorRecoveryGrace        = 2 * time.Minute
	FailureDetailExhaustedWithoutAck  = "credential.revocation.exhausted_without_ack.v1"
	FailureDetailProtectedRefInvalid  = "credential.revocation.protected_reference_invalid.v1"
	MaxCredentialTTL                  = 15 * time.Minute
	MinPrepareFenceWindow             = time.Second
	MinPostChildFenceWindow           = time.Second
	VaultChildCreateServerMaxDuration = 10 * time.Second
	MaxChildCreateDBCommitLatency     = time.Second
	MaxChildCreateVaultIngressLatency = 2 * time.Second
	MaxVaultAheadOfDatabaseClock      = time.Second
	VaultTTLQuantum                   = time.Second
	ChildCreateExpiryReserve          = MaxChildCreateDBCommitLatency + MaxChildCreateVaultIngressLatency +
		VaultChildCreateServerMaxDuration + MaxVaultAheadOfDatabaseClock + VaultTTLQuantum
	ChildCreateVaultCallBudget = MaxChildCreateVaultIngressLatency + VaultChildCreateServerMaxDuration
	MinChildCreateTTL          = time.Second
	// PreparedRecoveryGrace is only the bounded DB/Broker/Vault clock and
	// expiration-propagation allowance. It is not extra credential lifetime.
	PreparedRecoveryGrace = time.Minute
)

// CanonicalCredentialExpiry matches PostgreSQL timestamptz microsecond
// precision so in-memory and durable idempotency compare the same instant.
func CanonicalCredentialExpiry(value time.Time) time.Time {
	if value.IsZero() {
		return time.Time{}
	}
	return time.UnixMicro(value.UnixMicro()).UTC()
}

type RevocationStatus string

const (
	StatusPrepared          RevocationStatus = "PREPARED"
	StatusAnchored          RevocationStatus = "ANCHORED"
	StatusActive            RevocationStatus = "ACTIVE"
	StatusRevocationPending RevocationStatus = "REVOCATION_PENDING"
	StatusRevoking          RevocationStatus = "REVOKING"
	StatusRevoked           RevocationStatus = "REVOKED"
	StatusManualRequired    RevocationStatus = "MANUAL_REQUIRED"
	StatusNoCredential      RevocationStatus = "NO_CREDENTIAL"
)

type FailureCode string

const (
	FailureIssuerUnavailable FailureCode = "ISSUER_UNAVAILABLE"
	FailureRateLimited       FailureCode = "RATE_LIMITED"
	FailureTimeout           FailureCode = "TIMEOUT"
	FailureAuthentication    FailureCode = "AUTHENTICATION_FAILED"
	FailurePermissionDenied  FailureCode = "PERMISSION_DENIED"
	FailureReferenceMissing  FailureCode = "REFERENCE_NOT_FOUND"
	FailureInvalidReference  FailureCode = "INVALID_REFERENCE"
	FailureUnknown           FailureCode = "UNKNOWN"
)

var (
	ErrInvalidRevocationRequest     = errors.New("invalid credential revocation request")
	ErrRevocationNotFound           = errors.New("credential revocation not found")
	ErrIdempotencyConflict          = errors.New("credential revocation idempotency conflict")
	ErrInvalidTransition            = errors.New("invalid credential revocation transition")
	ErrStaleActionFence             = errors.New("stale credential revocation action fence")
	ErrStaleClaim                   = errors.New("stale credential revocation claim")
	ErrCompletionConflict           = errors.New("credential revocation completion conflict")
	ErrEvidenceConflict             = errors.New("credential revocation evidence conflict")
	ErrPlatformAdminRequired        = errors.New("credential revocation requires a platform administrator confirmation")
	ErrReferenceProtection          = errors.New("credential reference protection failed")
	ErrRevocationPersistence        = errors.New("credential revocation persistence failed")
	ErrAtomicActionSourceRequired   = errors.New("credential operation requires an atomic action source")
	ErrChildCreateAlreadyAuthorized = errors.New("credential child creation already authorized")
	ErrChildCreateWindowExpired     = errors.New("credential child creation window expired")
	ErrStaleChildCreatePermit       = errors.New("stale credential child creation permit")
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]*\z`)
	uuidPattern       = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)
	hashPattern       = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

// ActionFence is a short-lived bearer fence. Repositories must hash Token
// before comparing it with durable state and must never persist or render it.
type ActionFence struct {
	ActionID string `json:"action_id"`
	RunnerID string `json:"runner_id"`
	Token    string `json:"-"`
	Epoch    int64  `json:"epoch"`
}

func (fence ActionFence) String() string {
	return fmt.Sprintf("ActionFence{ActionID:%q RunnerID:%q Token:[REDACTED] Epoch:%d}",
		fence.ActionID, fence.RunnerID, fence.Epoch)
}

func (fence ActionFence) GoString() string { return fence.String() }

type ActionStatus string

const (
	ActionStatusQueued  ActionStatus = "QUEUED"
	ActionStatusLeased  ActionStatus = "LEASED"
	ActionStatusRunning ActionStatus = "RUNNING"
)

// ActionMetadata is a trusted snapshot returned after the source validates the
// action bearer and epoch. Runner registration and exact-scope fields are
// authorizing only while delivered by AtomicActionFenceSource under its locks.
type ActionMetadata struct {
	ActionID               string
	TenantID               string
	WorkspaceID            string
	EnvironmentID          string
	TargetKey              string
	Production             bool
	RunnerID               string
	LeaseEpoch             int64
	Status                 ActionStatus
	LeaseExpiresAt         time.Time
	AuthorizationExpiresAt time.Time
	CancelRequestedAt      time.Time
	RunnerEnabled          bool
	RunnerPool             string
	// ScopeRevision is the revision frozen on the action lease;
	// RunnerScopeRevision is the current trusted registration revision.
	ScopeRevision        int64
	RunnerScopeRevision  int64
	ExactScopeAuthorized bool
	ConnectorID          string
	Permission           string
	Resource             string
}

type ActionFenceSource interface {
	ResolveActionFence(context.Context, ActionFence) (ActionMetadata, error)
	InspectAction(context.Context, string) (ActionInspection, error)
}

// AtomicActionFenceSource invokes operation exactly once, synchronously, while
// keeping its action, runner registration, and exact scope-binding locks held.
// It must not retain the callback and must return the callback's error without
// substituting a successful result. The callback may acquire the credential
// repository lock, so implementations and callers must preserve the global
// lock order: action source first, credential repository second. Code holding a
// credential repository lock must never enter this callback API.
type AtomicActionFenceSource interface {
	ActionFenceSource
	WithLockedActionInspection(context.Context, string, func(ActionInspection) error) error
}

// ActionInspection contains no reusable bearer. A value returned by the plain
// InspectAction method is non-authorizing. Only a snapshot passed synchronously
// by AtomicActionFenceSource while all source locks remain held may authorize
// child creation; both forms may decide that an anchor must be revoked.
type ActionInspection struct {
	Metadata         ActionMetadata
	LeaseTokenSHA256 string `json:"-"`
}

type PrepareRequest struct {
	RevocationID string
	Fence        ActionFence
	Issuer       string
	// IssuerRevision freezes the exact non-secret revocation profile revision
	// selected by the trusted server registry for this action lease epoch.
	IssuerRevision string
	// CredentialExpiresAt is the absolute child-credential deadline persisted
	// before issuance. A caller must cap the issuer TTL to the remaining time
	// before this instant; it must never start a fresh MaxCredentialTTL window.
	CredentialExpiresAt time.Time
}

// PrepareResult tells an issuer whether this call inserted the durable parent
// record. A caller may create a child credential only after an error-free
// response with Created=true. Created=false and every error, including an
// ambiguous commit/response-loss error, prohibit child creation; a retry after
// a committed-but-lost response observes the existing row with Created=false.
// Created=true authorizes exactly one immediate, non-retried issuer call only
// when the caller can enforce the returned Revocation.CredentialExpiresAt as
// the child's absolute upper bound using a trusted database-time budget.
type PrepareResult struct {
	Revocation Revocation
	Created    bool
	Permit     *ChildCreatePermit `json:"-"`
}

// ChildCreatePermit is a single-use capability returned only to the unique
// Prepare creator. Only its SHA-256 digest may be persisted.
type ChildCreatePermit struct {
	RevocationID string `json:"revocation_id"`
	Token        string `json:"-"`
}

func (permit ChildCreatePermit) String() string {
	return fmt.Sprintf("ChildCreatePermit{RevocationID:%q Token:[REDACTED]}", permit.RevocationID)
}

func (permit ChildCreatePermit) GoString() string { return permit.String() }

func (permit ChildCreatePermit) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RevocationID string `json:"revocation_id"`
		Redacted     bool   `json:"redacted"`
	}{RevocationID: permit.RevocationID, Redacted: true})
}

type AuthorizeChildCreateRequest struct {
	Permit ChildCreatePermit
	Fence  ActionFence
}

func (request AuthorizeChildCreateRequest) String() string {
	return fmt.Sprintf("AuthorizeChildCreateRequest{Permit:%s Fence:%s}", request.Permit.String(), request.Fence.String())
}

func (request AuthorizeChildCreateRequest) GoString() string { return request.String() }

func (request AuthorizeChildCreateRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Permit ChildCreatePermit `json:"permit"`
		Fence  struct {
			ActionID string `json:"action_id"`
			RunnerID string `json:"runner_id"`
			Epoch    int64  `json:"epoch"`
			Redacted bool   `json:"redacted"`
		} `json:"fence"`
	}{
		Permit: request.Permit,
		Fence: struct {
			ActionID string `json:"action_id"`
			RunnerID string `json:"runner_id"`
			Epoch    int64  `json:"epoch"`
			Redacted bool   `json:"redacted"`
		}{
			ActionID: request.Fence.ActionID, RunnerID: request.Fence.RunnerID,
			Epoch: request.Fence.Epoch, Redacted: true,
		},
	})
}

type ChildCreateAuthorization struct {
	Revocation           Revocation
	DatabaseAuthorizedAt time.Time
	CredentialExpiresAt  time.Time
	TTL                  time.Duration
	VaultCallBudget      time.Duration
}

type RecordAnchorRequest struct {
	RevocationID string
	Fence        ActionFence
	Accessor     *SensitiveReference
}

type ActionTransitionRequest struct {
	RevocationID string
	Fence        ActionFence
}

type ClaimRevocationsRequest struct {
	WorkerID      string
	Limit         int
	LeaseDuration time.Duration
}

type RecoverPreparedRequest struct {
	Limit int
}

type RecoverManagedRequest struct {
	Limit int
}

type RecoverExhaustedRequest struct {
	Limit int
}

type ClaimFence struct {
	RevocationID string `json:"revocation_id"`
	WorkerID     string `json:"worker_id"`
	Token        string `json:"-"`
	Epoch        int64  `json:"epoch"`
}

func (fence ClaimFence) String() string {
	return fmt.Sprintf("ClaimFence{RevocationID:%q WorkerID:%q Token:[REDACTED] Epoch:%d}",
		fence.RevocationID, fence.WorkerID, fence.Epoch)
}

func (fence ClaimFence) GoString() string { return fence.String() }

type HeartbeatRequest struct {
	Fence     ClaimFence
	Extension time.Duration
}

type CompleteRevocationRequest struct {
	Fence ClaimFence
}

type RetryRevocationRequest struct {
	Fence         ClaimFence
	Delay         time.Duration
	FailureCode   FailureCode
	FailureDetail []byte `json:"-"`
}

func (request RetryRevocationRequest) String() string {
	return fmt.Sprintf("RetryRevocationRequest{Fence:%s Delay:%s FailureCode:%q FailureDetail:[REDACTED]}",
		request.Fence.String(), request.Delay, request.FailureCode)
}

func (request RetryRevocationRequest) GoString() string { return request.String() }

type RequireManualRequest struct {
	Fence         ClaimFence
	FailureCode   FailureCode
	FailureDetail []byte `json:"-"`
}

func (request RequireManualRequest) String() string {
	return fmt.Sprintf("RequireManualRequest{Fence:%s FailureCode:%q FailureDetail:[REDACTED]}",
		request.Fence.String(), request.FailureCode)
}

func (request RequireManualRequest) GoString() string { return request.String() }

type RequeueManualRequest struct {
	RevocationID string
	// ActorSubject is a canonical OIDC principal derived by the trusted M2D
	// authentication/RBAC boundary, never copied from an untrusted request body.
	ActorSubject string
}

type ExternalConfirmationRequest struct {
	RevocationID string
	// Subject and PlatformAdmin are trusted identity assertions supplied by the
	// M2D authentication/RBAC boundary. This repository only enforces their
	// transactional distinct-subject/evidence semantics.
	Subject       string
	EvidenceHash  string
	PlatformAdmin bool
}

type ListFilter struct {
	WorkspaceID string
	Status      RevocationStatus
	Limit       int
}

// Revocation deliberately contains no ciphertext or plaintext accessor. The
// action token digest is an internal scan field and is always removed before a
// record leaves a repository.
type Revocation struct {
	ID               string `json:"id"`
	TenantID         string `json:"tenant_id"`
	WorkspaceID      string `json:"workspace_id"`
	EnvironmentID    string `json:"environment_id"`
	ActionID         string `json:"action_id"`
	TargetKey        string `json:"target_key"`
	Production       bool   `json:"production"`
	RunnerID         string `json:"runner_id"`
	ActionLeaseEpoch int64  `json:"action_lease_epoch"`
	Issuer           string `json:"issuer"`
	IssuerRevision   string `json:"issuer_revision"`
	ConnectorID      string `json:"connector_id"`
	Permission       string `json:"permission"`
	Resource         string `json:"resource"`
	// CredentialExpiresAt is the durable absolute upper bound for the external
	// child credential, not a relative TTL that restarts when issuance begins.
	CredentialExpiresAt   time.Time        `json:"credential_expires_at"`
	Status                RevocationStatus `json:"status"`
	AccessorPresent       bool             `json:"accessor_present"`
	AccessorHMAC          string           `json:"accessor_hmac,omitempty"`
	EncryptionKeyID       string           `json:"encryption_key_id,omitempty"`
	ClaimEpoch            int64            `json:"claim_epoch"`
	ClaimedBy             string           `json:"claimed_by,omitempty"`
	ClaimedAt             time.Time        `json:"claimed_at,omitempty"`
	ClaimExpiresAt        time.Time        `json:"claim_expires_at,omitempty"`
	LastHeartbeatAt       time.Time        `json:"last_heartbeat_at,omitempty"`
	Attempt               int              `json:"attempt"`
	FailureCount          int              `json:"failure_count"`
	FailureCode           FailureCode      `json:"failure_code,omitempty"`
	FailureDetailSHA256   string           `json:"failure_detail_sha256,omitempty"`
	AvailableAt           time.Time        `json:"available_at"`
	EvidenceHash          string           `json:"evidence_hash,omitempty"`
	CreatedAt             time.Time        `json:"created_at"`
	UpdatedAt             time.Time        `json:"updated_at"`
	AnchoredAt            time.Time        `json:"anchored_at,omitempty"`
	ActivatedAt           time.Time        `json:"activated_at,omitempty"`
	RevocationRequestedAt time.Time        `json:"revocation_requested_at,omitempty"`
	ManualRequiredAt      time.Time        `json:"manual_required_at,omitempty"`
	RevokedAt             time.Time        `json:"revoked_at,omitempty"`
	Version               int64            `json:"version"`
}

func (revocation Revocation) Terminal() bool {
	return revocation.Status == StatusRevoked || revocation.Status == StatusNoCredential
}

type ClaimedRevocation struct {
	Revocation Revocation          `json:"revocation"`
	Fence      ClaimFence          `json:"-"`
	Accessor   *SensitiveReference `json:"-"`
}

func (claim ClaimedRevocation) String() string {
	return fmt.Sprintf("ClaimedRevocation{RevocationID:%q Fence:%s Accessor:[REDACTED]}",
		claim.Revocation.ID, claim.Fence.String())
}

func (claim ClaimedRevocation) GoString() string { return claim.String() }

type ExternalConfirmation struct {
	Subject       string    `json:"subject"`
	EvidenceHash  string    `json:"evidence_hash"`
	PlatformAdmin bool      `json:"platform_admin"`
	CreatedAt     time.Time `json:"created_at"`
}

type ConfirmationResult struct {
	Revocation    Revocation             `json:"revocation"`
	Confirmations []ExternalConfirmation `json:"confirmations"`
}

// CleanupInspector exposes only the credential cleanup fact required by an
// execution finalization gate. It deliberately does not expose revocation
// records or protected credential references.
type CleanupInspector interface {
	InspectCleanup(context.Context, string, int64) (present bool, terminal bool, err error)
}

// Repository is intentionally credential-domain-local. It is not part of the
// broad store.Store interface and never exposes protected reference storage.
type Repository interface {
	Prepare(context.Context, PrepareRequest) (PrepareResult, error)
	AuthorizeChildCreate(context.Context, AuthorizeChildCreateRequest) (ChildCreateAuthorization, error)
	RecordAnchor(context.Context, RecordAnchorRequest) (Revocation, error)
	Activate(context.Context, ActionTransitionRequest) (Revocation, error)
	RecordNoCredential(context.Context, ActionTransitionRequest) (Revocation, error)
	RecoverPrepared(context.Context, RecoverPreparedRequest) ([]Revocation, error)
	RecoverManaged(context.Context, RecoverManagedRequest) ([]Revocation, error)
	RecoverExhausted(context.Context, RecoverExhaustedRequest) ([]Revocation, error)
	RequestRevocation(context.Context, ActionTransitionRequest) (Revocation, error)
	ClaimRevocations(context.Context, ClaimRevocationsRequest) ([]ClaimedRevocation, error)
	Heartbeat(context.Context, HeartbeatRequest) (Revocation, error)
	CompleteRevocation(context.Context, CompleteRevocationRequest) (Revocation, error)
	RetryRevocation(context.Context, RetryRevocationRequest) (Revocation, error)
	RequireManual(context.Context, RequireManualRequest) (Revocation, error)
	RequeueManual(context.Context, RequeueManualRequest) (Revocation, error)
	SubmitExternalConfirmation(context.Context, ExternalConfirmationRequest) (ConfirmationResult, error)
	Get(context.Context, string) (Revocation, error)
	List(context.Context, ListFilter) ([]Revocation, error)
}

func ValidRevocationStatus(status RevocationStatus) bool {
	switch status {
	case StatusPrepared, StatusAnchored, StatusActive, StatusRevocationPending,
		StatusRevoking, StatusRevoked, StatusManualRequired, StatusNoCredential:
		return true
	default:
		return false
	}
}

func ValidFailureCode(code FailureCode) bool {
	switch code {
	case FailureIssuerUnavailable, FailureRateLimited, FailureTimeout, FailureAuthentication,
		FailurePermissionDenied, FailureReferenceMissing, FailureInvalidReference, FailureUnknown:
		return true
	default:
		return false
	}
}

func ValidRevocationID(id string) bool { return uuidPattern.MatchString(id) }

func ValidIdentifier(value string, maximum int) bool {
	return len(value) >= 1 && len(value) <= maximum && identifierPattern.MatchString(value)
}

func ValidOpaqueText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value &&
		!strings.ContainsFunc(value, unicode.IsControl)
}

func ValidSHA256(value string) bool { return hashPattern.MatchString(value) }

func ValidActionFence(fence ActionFence) bool { return validActionFence(fence) }

func ValidClaimFence(fence ClaimFence) bool { return validClaimFence(fence) }

func ValidClaimDuration(duration time.Duration) bool { return validClaimDuration(duration) }

func ValidFailure(code FailureCode, detail []byte) bool { return validFailure(code, detail) }

func ValidConfirmationSubject(subject string) bool { return validSubject(subject) }

func SHA256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func validActionFence(fence ActionFence) bool {
	return ValidIdentifier(fence.ActionID, 256) && ValidIdentifier(fence.RunnerID, 256) &&
		ValidOpaqueText(fence.Token, 4096) && fence.Epoch > 0
}

func validClaimFence(fence ClaimFence) bool {
	return ValidRevocationID(fence.RevocationID) && ValidIdentifier(fence.WorkerID, 256) &&
		ValidOpaqueText(fence.Token, 4096) && fence.Epoch > 0
}

func validClaimDuration(duration time.Duration) bool {
	return duration >= MinRevocationClaimLease && duration <= MaxRevocationClaimLease
}

func validFailure(code FailureCode, detail []byte) bool {
	return ValidFailureCode(code) && len(detail) > 0 && len(detail) <= 1<<20
}

func validSubject(subject string) bool {
	return len(subject) > len("oidc:") && strings.HasPrefix(subject, "oidc:") && ValidOpaqueText(subject, 512)
}

func ValidSensitiveReference(reference *SensitiveReference) bool {
	if reference == nil {
		return false
	}
	value := reference.Bytes()
	defer clear(value)
	return len(value) > 0
}

func redactedRevocation(revocation Revocation) Revocation {
	return revocation
}
