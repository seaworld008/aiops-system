package runnergateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/readtask"
)

const (
	readTaskHeartbeatAfterSeconds = 10
	readTaskLeaseScheme           = "AIOPS-Read-Task-Lease "
)

var readTaskTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$`)

func (request ReadTaskClaimRequest) valid() bool {
	return request.SchemaVersion == "runner-read-task-claim-request.v1"
}

func (request ReadTaskStartRequest) valid() bool {
	return request.SchemaVersion == "runner-read-task-start-request.v1" && request.LeaseEpoch > 0
}

func (request ReadTaskHeartbeatRequest) valid() bool {
	return request.SchemaVersion == "runner-read-task-heartbeat-request.v1" &&
		request.LeaseEpoch > 0 && request.Sequence > 0
}

func (request ReadTaskReleaseRequest) valid() bool {
	if request.SchemaVersion != "runner-read-task-release-request.v1" || request.LeaseEpoch <= 0 {
		return false
	}
	switch readtask.ReleaseReason(request.ReasonCode) {
	case readtask.ReleaseLocalCapacityUnavailable, readtask.ReleaseConnectorNotReady,
		readtask.ReleaseTransientRunnerFailure:
		return true
	default:
		return false
	}
}

func (request ReadTaskCompleteRequest) valid() bool {
	if request.SchemaVersion != "runner-read-task-complete-request.v1" || request.LeaseEpoch <= 0 {
		return false
	}
	switch request.Outcome {
	case readtask.CompletionEvidence:
		if request.Evidence == nil || request.FailureCode != "" || request.Evidence.Items == nil ||
			!validReadTaskTime(request.Evidence.CollectedAt) || len(request.Evidence.Items) > readtask.MaxEvidenceItems {
			return false
		}
		total := 0
		for _, item := range request.Evidence.Items {
			total += len(item)
			if total > readtask.MaxEvidencePayloadBytes || domain.ValidateSafeJSONObject(item) != nil ||
				readTaskJSONDepth(item) > readtask.MaxEvidenceJSONDepth || !readTaskEvidenceFieldsSafe(item) {
				return false
			}
		}
		return true
	case readtask.CompletionFailed:
		return request.Evidence == nil && validReadTaskFailureCode(request.FailureCode) &&
			request.FailureCode != readtask.FailureCancelled
	case readtask.CompletionCancelled:
		return request.Evidence == nil && request.FailureCode == readtask.FailureCancelled
	default:
		return false
	}
}

func (request ReadTaskCompleteRequest) completion(fence readtask.Fence) readtask.Completion {
	completion := readtask.Completion{Fence: fence, Outcome: request.Outcome, FailureCode: request.FailureCode}
	if request.Evidence != nil {
		items := make([]json.RawMessage, len(request.Evidence.Items))
		for index := range request.Evidence.Items {
			items[index] = append([]byte(nil), request.Evidence.Items[index]...)
		}
		completion.Evidence = &readtask.EvidenceCompletion{
			CollectedAt: request.Evidence.CollectedAt,
			Items:       items,
		}
	}
	return completion
}

func validReadTaskFailureCode(value readtask.FailureCode) bool {
	switch value {
	case readtask.FailureConnectorUnavailable, readtask.FailureRateLimited, readtask.FailureTimeout,
		readtask.FailureAuthentication, readtask.FailurePermissionDenied, readtask.FailureInvalidResponse,
		readtask.FailureResultRejected, readtask.FailureCancelled, readtask.FailureUnknown:
		return true
	default:
		return false
	}
}

func (response ReadTaskDescriptor) valid() bool {
	if !uuidPattern.MatchString(response.ID) || len(response.Key) == 0 || len(response.Key) > 64 ||
		response.Position < 1 || response.Position > 12 || !domain.ValidConnectorID(response.ConnectorID) ||
		!domain.ValidOperation(response.Operation) || !hashPattern.MatchString(response.InputHash) ||
		domain.ValidateSafeJSONObject(response.Input) != nil || !response.PlanBinding.valid() ||
		!response.RuntimeBinding.valid() ||
		!domain.ConnectorDigestMatchesID(response.ConnectorID, response.RuntimeBinding.ConnectorDigest) {
		return false
	}
	digest := sha256.Sum256(response.Input)
	return hex.EncodeToString(digest[:]) == response.InputHash
}

func (response ReadTaskPlanBinding) valid() bool {
	return (domain.InvestigationPlanBinding{
		SchemaVersion: response.SchemaVersion, ManifestDigest: response.ManifestDigest,
		RegistryDigest: response.RegistryDigest, ProfileDigest: response.ProfileDigest,
		TasksHash: response.TasksHash,
	}).Validate() == nil
}

func (response ReadTaskRuntimeBinding) valid() bool {
	return (domain.ReadTaskRuntimeBinding{
		SchemaVersion: response.SchemaVersion, ConnectorDigest: response.ConnectorDigest,
		TargetDigest: response.TargetDigest, ExecutorDigest: response.ExecutorDigest,
		RuntimeDigest: response.RuntimeDigest, BoundAt: response.BoundAt,
	}).Validate() == nil
}

func (response ReadTaskClaimResponse) valid() bool {
	return response.SchemaVersion == "runner-read-task-claim-response.v2" && response.Task.valid() &&
		readTaskTokenPattern.MatchString(response.LeaseToken) && response.LeaseEpoch > 0 &&
		response.ScopeRevision > 0 && validReadTaskTime(response.LeaseExpiresAt) &&
		response.HeartbeatAfterSeconds == readTaskHeartbeatAfterSeconds
}

func (response ReadTaskStartResponse) valid() bool {
	return response.SchemaVersion == "runner-read-task-start-response.v1" &&
		uuidPattern.MatchString(response.TaskID) && response.AttemptStatus == string(readtask.AttemptRunning) &&
		response.LeaseEpoch > 0 && response.ScopeRevision > 0 && validReadTaskTime(response.StartedAt)
}

func (response ReadTaskHeartbeatResponse) valid() bool {
	return response.SchemaVersion == "runner-read-task-heartbeat-response.v1" &&
		uuidPattern.MatchString(response.TaskID) && response.LeaseEpoch > 0 && response.AcceptedSequence > 0 &&
		(response.Directive == string(readtask.HeartbeatContinue) || response.Directive == string(readtask.HeartbeatTerminate)) &&
		validReadTaskTime(response.LeaseExpiresAt) && response.HeartbeatAfterSeconds == readTaskHeartbeatAfterSeconds
}

func (response ReadTaskReleaseResponse) valid() bool {
	return response.SchemaVersion == "runner-read-task-release-response.v1" &&
		uuidPattern.MatchString(response.TaskID) && response.AttemptStatus == string(readtask.AttemptReleased) &&
		response.LeaseEpoch > 0
}

func (response ReadTaskCompleteResponse) valid() bool {
	if response.SchemaVersion != "runner-read-task-complete-response.v2" ||
		!uuidPattern.MatchString(response.TaskID) || response.LeaseEpoch <= 0 ||
		response.AttemptStatus != string(readtask.AttemptCompleted) || !uuidPattern.MatchString(response.ReceiptID) ||
		!hashPattern.MatchString(response.ReceiptHash) {
		return false
	}
	switch response.TaskStatus {
	case "EVIDENCE":
		return uuidPattern.MatchString(response.EvidenceID) && hashPattern.MatchString(response.ContentHash)
	case "FAILED", "CANCELLED":
		return response.EvidenceID == "" && response.ContentHash == ""
	default:
		return false
	}
}

func validReadTaskTime(value time.Time) bool {
	return !value.IsZero() && value.Year() >= 1 && value.Year() <= 9999
}

func readTaskJSONDepth(document []byte) int {
	var value any
	if json.Unmarshal(document, &value) != nil {
		return readtask.MaxEvidenceJSONDepth + 1
	}
	return readTaskValueDepth(value, 1)
}

func readTaskValueDepth(value any, depth int) int {
	maximum := depth
	switch typed := value.(type) {
	case map[string]any:
		for _, child := range typed {
			if childDepth := readTaskValueDepth(child, depth+1); childDepth > maximum {
				maximum = childDepth
			}
		}
	case []any:
		for _, child := range typed {
			if childDepth := readTaskValueDepth(child, depth+1); childDepth > maximum {
				maximum = childDepth
			}
		}
	}
	return maximum
}

func readTaskEvidenceFieldsSafe(document []byte) bool {
	var value any
	if json.Unmarshal(document, &value) != nil {
		return false
	}
	return !containsReservedReadTaskEvidenceField(value)
}

func containsReservedReadTaskEvidenceField(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for name, child := range typed {
			if readtask.EvidenceFieldReserved(name) {
				return true
			}
			if text, ok := child.(string); ok && readtask.EvidenceFieldValueReserved(name, text) {
				return true
			}
			if containsReservedReadTaskEvidenceField(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsReservedReadTaskEvidenceField(child) {
				return true
			}
		}
	}
	return false
}
