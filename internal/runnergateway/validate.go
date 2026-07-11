package runnergateway

import (
	"encoding/base64"
	"regexp"
	"strings"

	"github.com/seaworld008/aiops-system/internal/action"
	"github.com/seaworld008/aiops-system/internal/execution"
	"github.com/seaworld008/aiops-system/internal/runneridentity"
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$`)
	pathIDPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,255}$`)
	uuidPattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	tokenPattern      = regexp.MustCompile(`^[A-Za-z0-9_-]{32,256}$`)
	resultCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	hashPattern       = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

func (request JobLeaseRequest) valid() bool {
	return request.SchemaVersion == "runner-job-lease-request.v1"
}

func (request JobStartRequest) valid() bool {
	return request.SchemaVersion == "runner-job-start-request.v1" && request.LeaseEpoch > 0
}

func (request JobHeartbeatRequest) valid() bool {
	return request.SchemaVersion == "runner-job-heartbeat-request.v1" && request.LeaseEpoch > 0 && request.Sequence > 0
}

func (request JobReleaseRequest) valid() bool {
	return request.SchemaVersion == "runner-job-release-request.v1" && request.LeaseEpoch > 0 &&
		(request.ReasonCode == "EXECUTOR_NOT_READY" || request.ReasonCode == "LOCAL_CAPACITY_UNAVAILABLE" ||
			request.ReasonCode == "TRANSIENT_RUNNER_FAILURE")
}

func (request JobCompleteRequest) valid() bool {
	if request.SchemaVersion != "runner-job-complete-request.v1" || request.LeaseEpoch <= 0 ||
		!resultCodePattern.MatchString(request.Result.Code) ||
		(request.Result.ExternalOperationRefHash != "" && !hashPattern.MatchString(request.Result.ExternalOperationRefHash)) {
		return false
	}
	switch request.Result.Outcome {
	case execution.ExecutorSucceeded:
		return request.Result.Verification == execution.VerificationPassed
	case execution.ExecutorFailed:
		return request.Result.Verification == execution.VerificationFailed
	case execution.ExecutorUncertain:
		return request.Result.Verification == execution.VerificationUnknown
	default:
		return false
	}
}

func (request CredentialAnchorRequest) valid() bool {
	if request.SchemaVersion != "runner-credential-anchor-request.v1" || request.LeaseEpoch <= 0 ||
		!uuidPattern.MatchString(request.RevocationID) {
		return false
	}
	switch request.Phase {
	case "AUTHORIZE_CHILD_CREATE":
		return tokenPattern.MatchString(request.ChildCreatePermit) && request.RevokeAccessorB64U == ""
	case "RECORD_ANCHOR":
		if request.ChildCreatePermit != "" || len(request.RevokeAccessorB64U) < 1 || len(request.RevokeAccessorB64U) > 5462 ||
			strings.Contains(request.RevokeAccessorB64U, "=") {
			return false
		}
		decoded, err := base64.RawURLEncoding.DecodeString(request.RevokeAccessorB64U)
		return err == nil && len(decoded) >= 1 && len(decoded) <= 4096
	case "ACTIVATE", "NO_CREDENTIAL", "REQUEST_REVOCATION":
		return request.ChildCreatePermit == "" && request.RevokeAccessorB64U == ""
	default:
		return false
	}
}

func (request RevocationLeaseRequest) valid() bool {
	return request.SchemaVersion == "runner-revocation-lease-request.v1"
}

func (request RevocationHeartbeatRequest) valid() bool {
	return request.SchemaVersion == "runner-revocation-heartbeat-request.v1" && request.ClaimEpoch > 0 && request.Sequence > 0
}

func (request RevocationCompleteRequest) valid() bool {
	if request.SchemaVersion != "runner-revocation-complete-request.v1" || request.ClaimEpoch <= 0 {
		return false
	}
	if request.Outcome == "REVOKED" {
		return request.FailureCode == ""
	}
	if request.Outcome != "FAILED" {
		return false
	}
	switch request.FailureCode {
	case "ISSUER_UNAVAILABLE", "RATE_LIMITED", "TIMEOUT", "AUTHENTICATION_FAILED", "PERMISSION_DENIED",
		"REFERENCE_NOT_FOUND", "INVALID_REFERENCE", "UNKNOWN":
		return true
	default:
		return false
	}
}

func validResourceID(value string) bool {
	return identifierPattern.MatchString(value)
}

func validPathResourceID(value string) bool {
	return pathIDPattern.MatchString(value)
}

type backendResponseBinding struct {
	identity          runneridentity.Identity
	principal         RequestPrincipal
	jobID             string
	revocationID      string
	epoch             DecimalInt64
	sequence          DecimalInt64
	credentialPhase   string
	resultOutcome     execution.ExecutorOutcome
	revocationOutcome string
}

func validBackendResponse(value any, binding backendResponseBinding) bool {
	switch response := value.(type) {
	case RunnerIdentityResponse:
		return response.valid() && principalIdentity(binding) && response.RunnerID == binding.principal.RunnerID() &&
			response.Pool == string(binding.principal.Pool()) &&
			response.ScopeRevision.Int64() == binding.principal.ScopeRevision() &&
			response.MaxConcurrency == binding.principal.MaxConcurrency() &&
			response.CertificateSHA256 == binding.principal.CertificateSHA256() &&
			response.CertificateNotAfter.Equal(binding.principal.CertificateNotAfter()) &&
			capabilitiesMatchPrincipal(response.Capabilities, binding.principal)
	case *JobLeaseResponse:
		return response != nil && response.valid() && writeIdentity(binding) &&
			response.ScopeRevision.Int64() == binding.principal.ScopeRevision() &&
			binding.principal.Allows(response.Job.Payload.WorkspaceID, response.Job.Payload.Target.EnvironmentID)
	case CredentialAnchorResponse:
		return response.valid() && writeIdentity(binding) && response.JobID == binding.jobID && response.RevocationID == binding.revocationID &&
			credentialStatusMatchesPhase(response.Status, binding.credentialPhase)
	case JobStartResponse:
		return response.valid() && writeIdentity(binding) && response.JobID == binding.jobID && response.LeaseEpoch == binding.epoch &&
			response.ScopeRevision.Int64() == binding.principal.ScopeRevision()
	case JobHeartbeatResponse:
		return response.valid() && writeIdentity(binding) && response.JobID == binding.jobID && response.AcceptedSequence == binding.sequence
	case JobStateResponse:
		return response.valid() && writeIdentity(binding) && response.JobID == binding.jobID && response.LeaseEpoch == binding.epoch && response.Status == "QUEUED"
	case JobCompletionResponse:
		return response.valid() && writeIdentity(binding) && response.JobID == binding.jobID && response.CompletionStatus == string(binding.resultOutcome)
	case *RevocationLeaseResponse:
		return response != nil && response.valid() && revocationIdentity(binding) &&
			response.TenantID == binding.principal.TenantID() &&
			binding.principal.Allows(response.WorkspaceID, response.EnvironmentID)
	case RevocationHeartbeatResponse:
		return response.valid() && revocationIdentity(binding) && response.RevocationID == binding.revocationID && response.AcceptedSequence == binding.sequence
	case RevocationCompletionResponse:
		return response.valid() && revocationIdentity(binding) && response.RevocationID == binding.revocationID && response.ClaimEpoch == binding.epoch &&
			revocationStatusMatchesOutcome(response.Status, binding.revocationOutcome)
	default:
		return false
	}
}

func writeIdentity(binding backendResponseBinding) bool {
	return principalIdentity(binding) && writePrincipal(binding.principal)
}

func revocationIdentity(binding backendResponseBinding) bool {
	return principalIdentity(binding) && revocationPrincipal(binding.principal)
}

func principalIdentity(binding backendResponseBinding) bool {
	return validRequestPrincipal(binding.identity, binding.principal)
}

func capabilitiesMatchPrincipal(capabilities []string, principal RequestPrincipal) bool {
	if principal.CredentialRevocationCapable() {
		return len(capabilities) == 1 && capabilities[0] == "CREDENTIAL_REVOCATION"
	}
	return len(capabilities) == 0
}

func credentialStatusMatchesPhase(status, phase string) bool {
	switch phase {
	case "AUTHORIZE_CHILD_CREATE":
		return status == "PREPARED"
	case "RECORD_ANCHOR":
		return status == "ANCHORED"
	case "ACTIVATE":
		return status == "ACTIVE"
	case "NO_CREDENTIAL":
		return status == "NO_CREDENTIAL"
	case "REQUEST_REVOCATION":
		return status == "REVOCATION_PENDING" || status == "REVOKING" || status == "REVOKED" || status == "MANUAL_REQUIRED"
	default:
		return false
	}
}

func revocationStatusMatchesOutcome(status, outcome string) bool {
	if outcome == "REVOKED" {
		return status == "REVOKED"
	}
	return outcome == "FAILED" && (status == "REVOCATION_PENDING" || status == "MANUAL_REQUIRED")
}

func (response RunnerIdentityResponse) valid() bool {
	if response.SchemaVersion != "runner-identity-response.v1" || !validResourceID(response.RunnerID) ||
		response.ScopeRevision <= 0 || response.MaxConcurrency < 1 || response.MaxConcurrency > 1024 ||
		!hashPattern.MatchString(response.CertificateSHA256) || response.CertificateNotAfter.IsZero() || response.Capabilities == nil {
		return false
	}
	if response.Pool == "READ" {
		return len(response.Capabilities) == 0
	}
	if response.Pool != "WRITE" || len(response.Capabilities) > 1 {
		return false
	}
	return len(response.Capabilities) == 0 || response.Capabilities[0] == "CREDENTIAL_REVOCATION"
}

func (response JobLeaseResponse) valid() bool {
	return response.SchemaVersion == "runner-job-lease-response.v1" && response.Job.valid() &&
		tokenPattern.MatchString(response.LeaseToken) && response.LeaseEpoch > 0 && response.ScopeRevision > 0 &&
		!response.LeaseExpiresAt.IsZero() && response.HeartbeatAfterSeconds >= 1 && response.HeartbeatAfterSeconds <= 600
}

func (response JobDescriptor) valid() bool {
	return validPathResourceID(response.ID) && response.Kind == "WRITE_ACTION" && !response.Production &&
		response.ID == response.Payload.ActionID && hashPattern.MatchString(response.PlanHash) && response.PlanHash == response.Payload.PlanHash &&
		validResourceID(response.EnvironmentRevision) && response.Payload.Signature != (action.Signature{}) && response.Payload.Validate() == nil
}

func (response CredentialAnchorResponse) valid() bool {
	if response.SchemaVersion != "runner-credential-anchor-response.v1" || !validResourceID(response.JobID) ||
		!uuidPattern.MatchString(response.RevocationID) {
		return false
	}
	if response.Status == "PREPARED" {
		return response.DatabaseAuthorizedAt != nil && !response.DatabaseAuthorizedAt.IsZero() &&
			response.ChildTTLSeconds >= 1 && response.ChildTTLSeconds <= 900 &&
			response.CredentialExpiresAt != nil && !response.CredentialExpiresAt.IsZero()
	}
	if response.DatabaseAuthorizedAt != nil || response.ChildTTLSeconds != 0 || response.CredentialExpiresAt != nil {
		return false
	}
	switch response.Status {
	case "ANCHORED", "ACTIVE", "NO_CREDENTIAL", "REVOCATION_PENDING", "REVOKING", "REVOKED", "MANUAL_REQUIRED":
		return true
	default:
		return false
	}
}

func (response CredentialPrepare) valid() bool {
	return uuidPattern.MatchString(response.RevocationID) && tokenPattern.MatchString(response.ChildCreatePermit) &&
		validResourceID(response.IssuerID) && validResourceID(response.IssuerRevision) &&
		!response.CredentialExpiresAt.IsZero()
}

func (response JobStartResponse) valid() bool {
	return response.SchemaVersion == "runner-job-start-response.v1" && validResourceID(response.JobID) &&
		response.Status == "RUNNING" && response.LeaseEpoch > 0 && response.ScopeRevision > 0 &&
		!response.StartedAt.IsZero() && response.CredentialPrepare.valid()
}

func (response JobHeartbeatResponse) valid() bool {
	return response.SchemaVersion == "runner-job-heartbeat-response.v1" && validResourceID(response.JobID) &&
		response.AcceptedSequence > 0 && (response.Directive == "CONTINUE" || response.Directive == "TERMINATE") &&
		!response.LeaseExpiresAt.IsZero() && response.HeartbeatAfterSeconds >= 1 && response.HeartbeatAfterSeconds <= 600
}

func (response JobStateResponse) valid() bool {
	if response.SchemaVersion != "runner-job-state-response.v1" || !validResourceID(response.JobID) || response.LeaseEpoch < 0 {
		return false
	}
	switch response.Status {
	case "QUEUED", "LEASED", "RUNNING", "FINALIZING", "UNCERTAIN", "SUCCEEDED", "FAILED", "CANCELLED":
		return true
	default:
		return false
	}
}

func (response JobCompletionResponse) valid() bool {
	if response.SchemaVersion != "runner-job-completion-response.v1" || !validResourceID(response.JobID) ||
		!hashPattern.MatchString(response.ReceiptHash) {
		return false
	}
	switch response.Status {
	case "FINALIZING", "UNCERTAIN", "SUCCEEDED", "FAILED":
	default:
		return false
	}
	if response.CompletionStatus != "SUCCEEDED" && response.CompletionStatus != "FAILED" && response.CompletionStatus != "UNCERTAIN" {
		return false
	}
	if response.Status != "FINALIZING" && response.Status != response.CompletionStatus {
		return false
	}
	switch response.CredentialCleanupStatus {
	case "NOT_REQUIRED", "PENDING", "TERMINAL", "MANUAL_REQUIRED":
		if response.Status == "SUCCEEDED" || response.Status == "FAILED" {
			return response.CredentialCleanupStatus == "NOT_REQUIRED" || response.CredentialCleanupStatus == "TERMINAL"
		}
		return true
	default:
		return false
	}
}

func (response RevocationLeaseResponse) valid() bool {
	return response.SchemaVersion == "runner-revocation-lease-response.v1" && uuidPattern.MatchString(response.RevocationID) &&
		tokenPattern.MatchString(response.ClaimToken) && response.ClaimEpoch > 0 && !response.ClaimExpiresAt.IsZero() &&
		response.HeartbeatAfterSeconds == 10 && uuidPattern.MatchString(response.TenantID) &&
		uuidPattern.MatchString(response.WorkspaceID) && uuidPattern.MatchString(response.EnvironmentID) &&
		validResourceID(response.IssuerID) && validResourceID(response.IssuerRevision) && validAccessor(response.RevokeAccessorB64U)
}

func validAccessor(value string) bool {
	if len(value) < 1 || len(value) > 5462 || strings.Contains(value, "=") {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) >= 1 && len(decoded) <= 4096
}

func (response RevocationHeartbeatResponse) valid() bool {
	return response.SchemaVersion == "runner-revocation-heartbeat-response.v1" && uuidPattern.MatchString(response.RevocationID) &&
		response.AcceptedSequence > 0 && (response.Directive == "CONTINUE" || response.Directive == "TERMINATE") &&
		!response.ClaimExpiresAt.IsZero() && response.HeartbeatAfterSeconds == 10
}

func (response RevocationCompletionResponse) valid() bool {
	if response.SchemaVersion != "runner-revocation-completion-response.v1" || !uuidPattern.MatchString(response.RevocationID) ||
		response.ClaimEpoch <= 0 {
		return false
	}
	if response.Status == "REVOCATION_PENDING" {
		return response.AvailableAt != nil && !response.AvailableAt.IsZero()
	}
	return (response.Status == "REVOKED" || response.Status == "MANUAL_REQUIRED") && response.AvailableAt == nil
}
