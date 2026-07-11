package credential

import (
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"strconv"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const runnerRevocationReceiptSchemaV1 = "credential-revocation-result.v1"

// RunnerRevocationOutcome is the bounded result a revocation-capable WRITE
// Runner may report. The server derives all failure evidence other than the
// allowlisted code.
type RunnerRevocationOutcome string

const (
	RunnerRevocationRevoked RunnerRevocationOutcome = "REVOKED"
	RunnerRevocationFailed  RunnerRevocationOutcome = "FAILED"
)

// RunnerRevocationHeartbeatDirective tells a Runner whether its current
// revocation claim remains authoritative.
type RunnerRevocationHeartbeatDirective string

const (
	RunnerRevocationContinue  RunnerRevocationHeartbeatDirective = "CONTINUE"
	RunnerRevocationTerminate RunnerRevocationHeartbeatDirective = "TERMINATE"
)

// RunnerRevocationHeartbeat contains only the monotonic client evidence. The
// server chooses the claim extension and never accepts one from the Runner.
type RunnerRevocationHeartbeat struct {
	ClaimEpoch int64
	Sequence   int64
}

type RunnerRevocationHeartbeatResult struct {
	RevocationID     string
	ClaimEpoch       int64
	AcceptedSequence int64
	Directive        RunnerRevocationHeartbeatDirective
	ClaimExpiresAt   time.Time
}

// RunnerRevocationCompletion is the complete bounded result supplied by a
// Runner. Failure counts and failure details are deliberately server-derived.
type RunnerRevocationCompletion struct {
	ClaimEpoch  int64
	Outcome     RunnerRevocationOutcome
	FailureCode FailureCode
}

// RunnerRevocationClaim is the trusted, secret-free snapshot used to build an
// immutable receipt. ClaimTokenSHA256 is a digest of the bearer; this type has
// no field capable of carrying the raw claim token or revoke accessor.
type RunnerRevocationClaim struct {
	Revocation        Revocation
	RunnerID          string
	ScopeRevision     int64
	CertificateSHA256 string
	ClaimTokenSHA256  string
	HeartbeatSequence int64
}

// RunnerRevocationReceipt is safe to persist, audit, and serialize. ReceivedAt
// is database evidence and is intentionally excluded from ReceiptHash.
type RunnerRevocationReceipt struct {
	SchemaVersion       string                  `json:"schema_version"`
	RevocationID        string                  `json:"revocation_id"`
	TenantID            string                  `json:"tenant_id"`
	WorkspaceID         string                  `json:"workspace_id"`
	EnvironmentID       string                  `json:"environment_id"`
	ActionID            string                  `json:"action_id"`
	Issuer              string                  `json:"issuer"`
	IssuerRevision      string                  `json:"issuer_revision"`
	RunnerID            string                  `json:"runner_id"`
	ScopeRevision       int64                   `json:"scope_revision"`
	CertificateSHA256   string                  `json:"certificate_sha256"`
	ClaimEpoch          int64                   `json:"claim_epoch"`
	HeartbeatSequence   int64                   `json:"heartbeat_seq"`
	ClaimTokenSHA256    string                  `json:"claim_token_sha256"`
	Outcome             RunnerRevocationOutcome `json:"outcome"`
	FailureCount        int                     `json:"failure_count,omitempty"`
	FailureCode         FailureCode             `json:"failure_code,omitempty"`
	FailureDetailSHA256 string                  `json:"failure_detail_sha256,omitempty"`
	ReceiptHash         string                  `json:"receipt_hash"`
	ReceivedAt          time.Time               `json:"received_at"`
}

// MarshalJSON preserves all bigint fences as canonical decimal strings. This
// is the same I-JSON-safe representation used by the receipt hash payload.
func (receipt RunnerRevocationReceipt) MarshalJSON() ([]byte, error) {
	if receipt.ScopeRevision <= 0 || receipt.ClaimEpoch <= 0 || receipt.HeartbeatSequence < 0 {
		return nil, ErrInvalidRevocationRequest
	}
	return json.Marshal(struct {
		SchemaVersion       string                  `json:"schema_version"`
		RevocationID        string                  `json:"revocation_id"`
		TenantID            string                  `json:"tenant_id"`
		WorkspaceID         string                  `json:"workspace_id"`
		EnvironmentID       string                  `json:"environment_id"`
		ActionID            string                  `json:"action_id"`
		Issuer              string                  `json:"issuer"`
		IssuerRevision      string                  `json:"issuer_revision"`
		RunnerID            string                  `json:"runner_id"`
		ScopeRevision       string                  `json:"scope_revision"`
		CertificateSHA256   string                  `json:"certificate_sha256"`
		ClaimEpoch          string                  `json:"claim_epoch"`
		HeartbeatSequence   string                  `json:"heartbeat_seq"`
		ClaimTokenSHA256    string                  `json:"claim_token_sha256"`
		Outcome             RunnerRevocationOutcome `json:"outcome"`
		FailureCount        int                     `json:"failure_count,omitempty"`
		FailureCode         FailureCode             `json:"failure_code,omitempty"`
		FailureDetailSHA256 string                  `json:"failure_detail_sha256,omitempty"`
		ReceiptHash         string                  `json:"receipt_hash"`
		ReceivedAt          time.Time               `json:"received_at"`
	}{
		SchemaVersion: receipt.SchemaVersion, RevocationID: receipt.RevocationID,
		TenantID: receipt.TenantID, WorkspaceID: receipt.WorkspaceID,
		EnvironmentID: receipt.EnvironmentID, ActionID: receipt.ActionID,
		Issuer: receipt.Issuer, IssuerRevision: receipt.IssuerRevision, RunnerID: receipt.RunnerID,
		ScopeRevision:     strconv.FormatInt(receipt.ScopeRevision, 10),
		CertificateSHA256: receipt.CertificateSHA256,
		ClaimEpoch:        strconv.FormatInt(receipt.ClaimEpoch, 10),
		HeartbeatSequence: strconv.FormatInt(receipt.HeartbeatSequence, 10),
		ClaimTokenSHA256:  receipt.ClaimTokenSHA256, Outcome: receipt.Outcome,
		FailureCount: receipt.FailureCount, FailureCode: receipt.FailureCode,
		FailureDetailSHA256: receipt.FailureDetailSHA256, ReceiptHash: receipt.ReceiptHash,
		ReceivedAt: receipt.ReceivedAt,
	})
}

// RunnerRevocationCompletionResult is the durable state returned after a
// completion receipt and its parent transition commit atomically.
type RunnerRevocationCompletionResult struct {
	Revocation Revocation
	Receipt    RunnerRevocationReceipt
	RetryDelay time.Duration
}

// BuildRunnerRevocationReceiptV1 creates the server-owned JCS/SHA-256 proof.
// Bigint fences are encoded as decimal strings so adjacent values beyond the
// I-JSON safe integer range cannot collapse in a JSON-number conversion.
func BuildRunnerRevocationReceiptV1(
	claim RunnerRevocationClaim,
	completion RunnerRevocationCompletion,
	receivedAt time.Time,
) (RunnerRevocationReceipt, error) {
	if !validRunnerRevocationClaim(claim) || completion.ClaimEpoch != claim.Revocation.ClaimEpoch {
		return RunnerRevocationReceipt{}, ErrInvalidRevocationRequest
	}

	receipt := RunnerRevocationReceipt{
		SchemaVersion: runnerRevocationReceiptSchemaV1,
		RevocationID:  claim.Revocation.ID, TenantID: claim.Revocation.TenantID,
		WorkspaceID: claim.Revocation.WorkspaceID, EnvironmentID: claim.Revocation.EnvironmentID,
		ActionID: claim.Revocation.ActionID, Issuer: claim.Revocation.Issuer,
		IssuerRevision: claim.Revocation.IssuerRevision, RunnerID: claim.RunnerID,
		ScopeRevision: claim.ScopeRevision, CertificateSHA256: claim.CertificateSHA256,
		ClaimEpoch: claim.Revocation.ClaimEpoch, HeartbeatSequence: claim.HeartbeatSequence,
		ClaimTokenSHA256: claim.ClaimTokenSHA256, Outcome: completion.Outcome,
		ReceivedAt: receivedAt.UTC(),
	}

	switch completion.Outcome {
	case RunnerRevocationRevoked:
		if completion.FailureCode != "" {
			return RunnerRevocationReceipt{}, ErrInvalidRevocationRequest
		}
	case RunnerRevocationFailed:
		if !ValidFailureCode(completion.FailureCode) || claim.Revocation.FailureCount == math.MaxInt {
			return RunnerRevocationReceipt{}, ErrInvalidRevocationRequest
		}
		detail, err := CanonicalRunnerFailureDetail(completion.FailureCode)
		if err != nil {
			return RunnerRevocationReceipt{}, err
		}
		receipt.FailureCount = claim.Revocation.FailureCount + 1
		receipt.FailureCode = completion.FailureCode
		receipt.FailureDetailSHA256 = SHA256Hex(detail)
		clear(detail)
	default:
		return RunnerRevocationReceipt{}, ErrInvalidRevocationRequest
	}

	encoded, err := json.Marshal(struct {
		SchemaVersion       string                  `json:"schema_version"`
		RevocationID        string                  `json:"revocation_id"`
		TenantID            string                  `json:"tenant_id"`
		WorkspaceID         string                  `json:"workspace_id"`
		EnvironmentID       string                  `json:"environment_id"`
		ActionID            string                  `json:"action_id"`
		Issuer              string                  `json:"issuer"`
		IssuerRevision      string                  `json:"issuer_revision"`
		RunnerID            string                  `json:"runner_id"`
		ScopeRevision       string                  `json:"scope_revision"`
		CertificateSHA256   string                  `json:"certificate_sha256"`
		ClaimEpoch          string                  `json:"claim_epoch"`
		HeartbeatSequence   string                  `json:"heartbeat_seq"`
		ClaimTokenSHA256    string                  `json:"claim_token_sha256"`
		Outcome             RunnerRevocationOutcome `json:"outcome"`
		FailureCount        int                     `json:"failure_count,omitempty"`
		FailureCode         FailureCode             `json:"failure_code,omitempty"`
		FailureDetailSHA256 string                  `json:"failure_detail_sha256,omitempty"`
	}{
		SchemaVersion: receipt.SchemaVersion, RevocationID: receipt.RevocationID,
		TenantID: receipt.TenantID, WorkspaceID: receipt.WorkspaceID,
		EnvironmentID: receipt.EnvironmentID, ActionID: receipt.ActionID,
		Issuer: receipt.Issuer, IssuerRevision: receipt.IssuerRevision,
		RunnerID: receipt.RunnerID, ScopeRevision: strconv.FormatInt(receipt.ScopeRevision, 10),
		CertificateSHA256: receipt.CertificateSHA256,
		ClaimEpoch:        strconv.FormatInt(receipt.ClaimEpoch, 10),
		HeartbeatSequence: strconv.FormatInt(receipt.HeartbeatSequence, 10),
		ClaimTokenSHA256:  receipt.ClaimTokenSHA256, Outcome: receipt.Outcome,
		FailureCount: receipt.FailureCount, FailureCode: receipt.FailureCode,
		FailureDetailSHA256: receipt.FailureDetailSHA256,
	})
	if err != nil {
		return RunnerRevocationReceipt{}, fmt.Errorf("marshal runner revocation receipt: %w", err)
	}
	if len(encoded) > 16<<10 {
		return RunnerRevocationReceipt{}, ErrInvalidRevocationRequest
	}
	canonical, err := jsoncanonicalizer.Transform(encoded)
	if err != nil {
		return RunnerRevocationReceipt{}, fmt.Errorf("canonicalize runner revocation receipt: %w", err)
	}
	digest := sha256.Sum256(append([]byte(runnerRevocationReceiptSchemaV1+"\x00"), canonical...))
	receipt.ReceiptHash = hex.EncodeToString(digest[:])
	return receipt, nil
}

// CanonicalRunnerFailureDetail returns a new copy of fixed, redacted server
// evidence. An invalid code never falls through to the UNKNOWN mapping.
func CanonicalRunnerFailureDetail(code FailureCode) ([]byte, error) {
	var detail string
	switch code {
	case FailureIssuerUnavailable:
		detail = "credential.revocation.runner.issuer_unavailable.v1"
	case FailureRateLimited:
		detail = "credential.revocation.runner.rate_limited.v1"
	case FailureTimeout:
		detail = "credential.revocation.runner.timeout.v1"
	case FailureAuthentication:
		detail = "credential.revocation.runner.authentication_failed.v1"
	case FailurePermissionDenied:
		detail = "credential.revocation.runner.permission_denied.v1"
	case FailureReferenceMissing:
		detail = "credential.revocation.runner.reference_not_found.v1"
	case FailureInvalidReference:
		detail = "credential.revocation.runner.invalid_reference.v1"
	case FailureUnknown:
		detail = "credential.revocation.runner.unknown.v1"
	default:
		return nil, ErrInvalidRevocationRequest
	}
	return []byte(detail), nil
}

// FullJitterRevocationRetryDelay returns a cryptographically sampled duration
// in [5s, min(5s*2^(attempt-1), 15m)]. Entropy failure is fail-safe and uses
// the minimum delay; the capped loop cannot overflow for a hostile attempt.
func FullJitterRevocationRetryDelay(attempt int, random io.Reader) time.Duration {
	upper := revocationRetryUpperBound(attempt)
	if upper <= MinRevocationRetryDelay || random == nil {
		return MinRevocationRetryDelay
	}
	span := int64(upper-MinRevocationRetryDelay) + 1
	offset, err := cryptorand.Int(random, big.NewInt(span))
	if err != nil {
		return MinRevocationRetryDelay
	}
	return MinRevocationRetryDelay + time.Duration(offset.Int64())
}

func revocationRetryUpperBound(attempt int) time.Duration {
	if attempt <= 1 {
		return MinRevocationRetryDelay
	}
	upper := MinRevocationRetryDelay
	for current := 1; current < attempt && upper < MaxRevocationRetryDelay; current++ {
		if upper > MaxRevocationRetryDelay/2 {
			return MaxRevocationRetryDelay
		}
		upper *= 2
	}
	if upper > MaxRevocationRetryDelay {
		return MaxRevocationRetryDelay
	}
	return upper
}

func validRunnerRevocationClaim(claim RunnerRevocationClaim) bool {
	revocation := claim.Revocation
	return ValidRevocationID(revocation.ID) && ValidRevocationID(revocation.TenantID) &&
		ValidRevocationID(revocation.WorkspaceID) && ValidRevocationID(revocation.EnvironmentID) &&
		ValidIdentifier(revocation.ActionID, 256) && ValidOpaqueText(revocation.Issuer, 256) &&
		ValidIdentifier(revocation.IssuerRevision, 256) && revocation.Status == StatusRevoking &&
		revocation.ClaimEpoch > 0 && revocation.FailureCount >= 0 &&
		ValidIdentifier(claim.RunnerID, 256) && revocation.ClaimedBy == claim.RunnerID &&
		claim.ScopeRevision > 0 && ValidSHA256(claim.CertificateSHA256) &&
		ValidSHA256(claim.ClaimTokenSHA256) && claim.HeartbeatSequence >= 0
}
