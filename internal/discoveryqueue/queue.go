// Package discoveryqueue defines the closed, process-local handoff between a
// discovery worker and the durable source-run queue.
package discoveryqueue

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"slices"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
)

const (
	ClaimResultRedaction  = "[REDACTED_QUEUE_CLAIM_RESULT]"
	cleanupProofRedaction = "[REDACTED_CLEANUP_PROOF]"
	MaxLeaseExtension     = 30 * time.Second
)

var (
	ErrInvalidRequest         = errors.New("discovery queue request invalid")
	ErrNoWork                 = errors.New("discovery queue has no eligible work")
	ErrNotFound               = errors.New("discovery queue run not found")
	ErrStaleFence             = errors.New("discovery queue lease fence stale")
	ErrIneligible             = errors.New("discovery queue run ineligible")
	ErrStateConflict          = errors.New("discovery queue state conflict")
	ErrIdempotency            = errors.New("discovery queue idempotency conflict")
	ErrUnavailable            = errors.New("discovery queue unavailable")
	ErrCleanupProof           = errors.New("discovery queue cleanup proof invalid")
	ErrSensitiveSerialization = errors.New("discovery queue process value is not serializable")

	uuidPattern     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	ownerPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$`)
	providerPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	codePattern     = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
)

// Queue owns source-run lifecycle mutations. A LeaseFence is always a
// separate process-local argument and is never part of a durable command.
type Queue interface {
	Claim(context.Context, ClaimCommand) (ClaimResult, error)
	Reclaim(context.Context, ReclaimCommand) (ClaimResult, error)
	ReclaimFinalizing(context.Context, ReclaimCommand) (ClaimResult, error)
	ReapDrifted(context.Context, ReapCommand) (ClaimResult, error)
	CancelIneligible(context.Context, CancelCommand) (CancelResult, error)

	Heartbeat(context.Context, assetcatalog.LeaseFence, HeartbeatCommand) (HeartbeatResult, error)
	AdvanceStage(context.Context, assetcatalog.LeaseFence, AdvanceStageCommand) (assetcatalog.SourceRun, error)
	ReserveCleanupAttempt(context.Context, assetcatalog.LeaseFence, RunCommand) (CleanupAttempt, error)
	RecordCleanup(context.Context, assetcatalog.LeaseFence, CleanupProof) (CleanupResult, error)
	Delay(context.Context, assetcatalog.LeaseFence, DelayCommand) (assetcatalog.SourceRun, error)
	ProposeValidationResult(context.Context, assetcatalog.LeaseFence, ValidationResultCommand) (WorkResult, error)
	PrepareFailureIntent(context.Context, assetcatalog.LeaseFence, FailureIntentCommand) (WorkResult, error)
	BeginCheckpointLineageRollover(context.Context, assetcatalog.LeaseFence, RolloverCommand) (RolloverResult, error)
	Complete(context.Context, assetcatalog.LeaseFence, TerminalCommand) (TerminalResult, error)
	Fail(context.Context, assetcatalog.LeaseFence, TerminalCommand) (TerminalResult, error)
}

type RunCoordinates struct {
	Scope assetcatalog.SourceScope
	RunID string
}

func (value RunCoordinates) Valid() bool {
	return value.Scope.Valid() && uuidPattern.MatchString(value.RunID)
}

type RunCommand struct{ Coordinates RunCoordinates }

func (command RunCommand) Validate() error {
	if !command.Coordinates.Valid() {
		return ErrInvalidRequest
	}
	return nil
}

type ClaimCommand struct {
	Owner         string
	LeaseDuration time.Duration
	ProviderKinds []string
}

func (command ClaimCommand) Validate() error {
	if !ownerPattern.MatchString(command.Owner) || command.LeaseDuration <= 0 ||
		command.LeaseDuration > MaxLeaseExtension || command.LeaseDuration%time.Microsecond != 0 ||
		!validProviderKinds(command.ProviderKinds) {
		return ErrInvalidRequest
	}
	return nil
}

func (command ClaimCommand) Clone() ClaimCommand {
	command.ProviderKinds = slices.Clone(command.ProviderKinds)
	return command
}

type ReclaimCommand = ClaimCommand

type ReapCommand struct {
	Owner         string
	LeaseDuration time.Duration
	ProviderKinds []string
	FailureCode   string
}

func (command ReapCommand) Validate() error {
	claim := ClaimCommand{
		Owner: command.Owner, LeaseDuration: command.LeaseDuration,
		ProviderKinds: command.ProviderKinds,
	}
	if claim.Validate() != nil || !codePattern.MatchString(command.FailureCode) {
		return ErrInvalidRequest
	}
	return nil
}

type CancelCommand struct {
	ProviderKinds []string
}

func (command CancelCommand) Validate() error {
	if !validProviderKinds(command.ProviderKinds) {
		return ErrInvalidRequest
	}
	return nil
}

type ClaimMode string

const (
	ClaimModeProvider    ClaimMode = "PROVIDER"
	ClaimModeCleanupOnly ClaimMode = "CLEANUP_ONLY"
	ClaimModeTerminal    ClaimMode = "TERMINAL"
)

func (mode ClaimMode) Valid() bool {
	return mode == ClaimModeProvider || mode == ClaimModeCleanupOnly || mode == ClaimModeTerminal
}

// ClaimResult is the sole Queue value allowed to carry a sealed LeaseFence.
// The complete value is process-local and deliberately rejects every common
// serialization and logging surface.
type ClaimResult struct {
	Run            assetcatalog.SourceRun
	ProviderKind   string
	ProfileCode    assetcatalog.ProfileCode
	Mode           ClaimMode
	CleanupAttempt *CleanupAttempt
	PersistedDelay *PersistedDelay
	Fence          assetcatalog.LeaseFence
}

func (result *ClaimResult) Destroy() {
	if result == nil {
		return
	}
	result.Fence.Destroy()
	result.CleanupAttempt = nil
	result.PersistedDelay = nil
}

func (ClaimResult) MarshalJSON() ([]byte, error)   { return nil, ErrSensitiveSerialization }
func (*ClaimResult) UnmarshalJSON([]byte) error    { return ErrSensitiveSerialization }
func (ClaimResult) MarshalText() ([]byte, error)   { return nil, ErrSensitiveSerialization }
func (*ClaimResult) UnmarshalText([]byte) error    { return ErrSensitiveSerialization }
func (ClaimResult) MarshalBinary() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (*ClaimResult) UnmarshalBinary([]byte) error  { return ErrSensitiveSerialization }
func (ClaimResult) String() string                 { return ClaimResultRedaction }
func (ClaimResult) GoString() string               { return ClaimResultRedaction }
func (ClaimResult) LogValue() slog.Value           { return slog.StringValue(ClaimResultRedaction) }
func (ClaimResult) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, ClaimResultRedaction)
}

type HeartbeatCommand struct {
	Coordinates RunCoordinates
	Sequence    int64
	Extension   time.Duration
}

func (command HeartbeatCommand) Validate() error {
	if !command.Coordinates.Valid() || command.Sequence <= 0 || command.Extension <= 0 ||
		command.Extension > MaxLeaseExtension || command.Extension%time.Microsecond != 0 {
		return ErrInvalidRequest
	}
	return nil
}

type HeartbeatResult struct {
	Run            assetcatalog.SourceRun
	LeaseExpiresAt time.Time
}

type DelayReason string

const (
	DelayReasonProviderRetryAfter DelayReason = "PROVIDER_RETRY_AFTER"
	DelayReasonTransportBackoff   DelayReason = "TRANSPORT_BACKOFF"
)

func (reason DelayReason) Valid() bool {
	return reason == DelayReasonProviderRetryAfter || reason == DelayReasonTransportBackoff
}

type DelayIntent struct {
	Reason    DelayReason
	NotBefore time.Time
}

func (intent DelayIntent) Validate() error {
	if !intent.Reason.Valid() || !validTimestamp(intent.NotBefore) {
		return ErrInvalidRequest
	}
	return nil
}

type PersistedDelay struct {
	Reason       DelayReason
	NotBefore    time.Time
	DigestSHA256 string
}

type AdvanceStageCommand struct {
	Coordinates RunCoordinates
	From, To    assetcatalog.RunStage
	Delay       *DelayIntent
}

func (command AdvanceStageCommand) Validate() error {
	if !command.Coordinates.Valid() || !command.From.Valid() || !command.To.Valid() || command.From == command.To {
		return ErrInvalidRequest
	}
	if command.Delay != nil && command.Delay.Validate() != nil {
		return ErrInvalidRequest
	}
	return nil
}

type CleanupAttempt struct {
	RunID        string
	AttemptID    string
	AttemptEpoch int64
}

func (attempt CleanupAttempt) Valid() bool {
	return uuidPattern.MatchString(attempt.RunID) && uuidPattern.MatchString(attempt.AttemptID) && attempt.AttemptEpoch > 0
}

// CleanupProof is a bounded, process-local authentication envelope. Its safe
// coordinates and digest are not trusted until CleanupProofVerifier accepts
// the bounded authentication bytes. It does not define Broker transport.
type CleanupProof struct {
	coordinates    RunCoordinates
	attempt        CleanupAttempt
	status         assetcatalog.CredentialCleanupStatus
	digestSHA256   string
	authentication []byte
}

func NewCleanupProof(
	coordinates RunCoordinates,
	attempt CleanupAttempt,
	status assetcatalog.CredentialCleanupStatus,
	digestSHA256 string,
	authentication []byte,
) (CleanupProof, error) {
	proof := CleanupProof{
		coordinates:    coordinates,
		attempt:        attempt,
		status:         status,
		digestSHA256:   digestSHA256,
		authentication: slices.Clone(authentication),
	}
	if proof.Validate() != nil {
		clear(proof.authentication)
		return CleanupProof{}, ErrInvalidRequest
	}
	return proof, nil
}

func (proof CleanupProof) Validate() error {
	if !proof.coordinates.Valid() || !proof.attempt.Valid() || proof.attempt.RunID != proof.coordinates.RunID ||
		(proof.status != assetcatalog.CredentialCleanupRevoked &&
			proof.status != assetcatalog.CredentialCleanupUncertain) ||
		!digestPattern.MatchString(proof.digestSHA256) ||
		len(proof.authentication) < 32 || len(proof.authentication) > 4096 {
		return ErrInvalidRequest
	}
	return nil
}

func (proof CleanupProof) Coordinates() RunCoordinates                  { return proof.coordinates }
func (proof CleanupProof) Attempt() CleanupAttempt                      { return proof.attempt }
func (proof CleanupProof) Status() assetcatalog.CredentialCleanupStatus { return proof.status }
func (proof CleanupProof) DigestSHA256() string                         { return proof.digestSHA256 }
func (proof CleanupProof) Authentication() []byte                       { return slices.Clone(proof.authentication) }

func (proof CleanupProof) Clone() CleanupProof {
	proof.authentication = slices.Clone(proof.authentication)
	return proof
}

func (proof *CleanupProof) Destroy() {
	if proof == nil {
		return
	}
	clear(proof.authentication)
	*proof = CleanupProof{}
}

func (CleanupProof) MarshalJSON() ([]byte, error)   { return nil, ErrSensitiveSerialization }
func (*CleanupProof) UnmarshalJSON([]byte) error    { return ErrSensitiveSerialization }
func (CleanupProof) MarshalText() ([]byte, error)   { return nil, ErrSensitiveSerialization }
func (*CleanupProof) UnmarshalText([]byte) error    { return ErrSensitiveSerialization }
func (CleanupProof) MarshalBinary() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (*CleanupProof) UnmarshalBinary([]byte) error  { return ErrSensitiveSerialization }
func (CleanupProof) String() string                 { return cleanupProofRedaction }
func (CleanupProof) GoString() string               { return cleanupProofRedaction }
func (CleanupProof) LogValue() slog.Value           { return slog.StringValue(cleanupProofRedaction) }
func (CleanupProof) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, cleanupProofRedaction)
}

type CleanupProofVerifier interface {
	VerifyCleanupProof(context.Context, CleanupProof) error
}

type CleanupResult struct {
	Attempt      CleanupAttempt
	Status       assetcatalog.CredentialCleanupStatus
	DigestSHA256 string
	Replayed     bool
}

type DelayCommand struct {
	Coordinates RunCoordinates
	Intent      DelayIntent
}

func (command DelayCommand) Validate() error {
	if !command.Coordinates.Valid() || command.Intent.Validate() != nil {
		return ErrInvalidRequest
	}
	return nil
}

type ValidationResultCommand struct {
	Coordinates RunCoordinates
	Proof       discoverysource.ValidationProof
}

func (command ValidationResultCommand) Validate() error {
	if !command.Coordinates.Valid() {
		return ErrInvalidRequest
	}
	return nil
}

type FailureIntentCommand struct {
	Coordinates    RunCoordinates
	FailureCode    string
	EvidenceDigest string
}

func (command FailureIntentCommand) Validate() error {
	if !command.Coordinates.Valid() || !codePattern.MatchString(command.FailureCode) ||
		!digestPattern.MatchString(command.EvidenceDigest) {
		return ErrInvalidRequest
	}
	return nil
}

type WorkResult struct {
	Kind         assetcatalog.WorkResultKind
	Status       assetcatalog.WorkResultStatus
	DigestSHA256 string
	FailureCode  string
	Replayed     bool
}

type RolloverCommand struct {
	Coordinates    RunCoordinates
	ReasonCode     string
	EvidenceDigest string
}

func (command RolloverCommand) Validate() error {
	if !command.Coordinates.Valid() || !codePattern.MatchString(command.ReasonCode) ||
		!digestPattern.MatchString(command.EvidenceDigest) {
		return ErrInvalidRequest
	}
	return nil
}

// CheckpointLineageRolloverRequest contains only safe, locked PostgreSQL facts
// presented to a deterministic Profile/Adapter verifier.
type CheckpointLineageRolloverRequest struct {
	Coordinates            RunCoordinates
	SourceID, ProviderKind string
	SourceRevision         int64
	SourceRevisionDigest   string
	SourceDefinitionDigest string
	ProfileCode            assetcatalog.ProfileCode
	CheckpointVersion      int64
	CheckpointSHA256       string
	ReasonCode             string
	EvidenceDigest         string
}

type CheckpointLineageRolloverVerifier interface {
	VerifyCheckpointLineageRollover(context.Context, CheckpointLineageRolloverRequest) error
}

type RolloverResult struct {
	ReasonCode, EvidenceDigest string
	GateRevision               int64
	Replayed                   bool
}

type TerminalCommand struct {
	Coordinates      RunCoordinates
	DesiredStatus    assetcatalog.RunStatus
	WorkResultDigest string
	CleanupStatus    assetcatalog.CredentialCleanupStatus
	CleanupDigest    string
	FailureCode      string
}

func (command TerminalCommand) Validate() error {
	if !command.Coordinates.Valid() || !digestPattern.MatchString(command.WorkResultDigest) {
		return ErrInvalidRequest
	}
	if command.DesiredStatus != assetcatalog.RunStatusSucceeded &&
		command.DesiredStatus != assetcatalog.RunStatusPartial &&
		command.DesiredStatus != assetcatalog.RunStatusFailed {
		return ErrInvalidRequest
	}
	if command.CleanupStatus == assetcatalog.CredentialCleanupNotOpened {
		if command.CleanupDigest != "" || command.DesiredStatus != assetcatalog.RunStatusFailed {
			return ErrInvalidRequest
		}
	} else if command.CleanupStatus != assetcatalog.CredentialCleanupRevoked &&
		command.CleanupStatus != assetcatalog.CredentialCleanupUncertain {
		return ErrInvalidRequest
	} else if !digestPattern.MatchString(command.CleanupDigest) {
		return ErrInvalidRequest
	}
	if command.DesiredStatus == assetcatalog.RunStatusFailed {
		if !codePattern.MatchString(command.FailureCode) {
			return ErrInvalidRequest
		}
	} else if command.FailureCode != "" || command.CleanupStatus == assetcatalog.CredentialCleanupUncertain {
		return ErrInvalidRequest
	}
	return nil
}

type TerminalResult struct {
	RunID         string
	Status        assetcatalog.RunStatus
	CommandDigest string
	CompletedAt   time.Time
	Replayed      bool
}

type CancelResult struct {
	Run      assetcatalog.SourceRun
	Replayed bool
}

func validProviderKinds(values []string) bool {
	if len(values) == 0 || len(values) > 128 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !providerPattern.MatchString(value) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validTimestamp(value time.Time) bool {
	return !value.IsZero() && value.Year() >= 1 && value.Year() <= 9999 &&
		value.Equal(value.Truncate(time.Microsecond))
}
