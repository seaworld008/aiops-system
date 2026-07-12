package runnergateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"time"
	"unicode"

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
		domain.ValidateSafeJSONObject(response.Input) != nil {
		return false
	}
	digest := sha256.Sum256(response.Input)
	return hex.EncodeToString(digest[:]) == response.InputHash
}

func (response ReadTaskClaimResponse) valid() bool {
	return response.SchemaVersion == "runner-read-task-claim-response.v1" && response.Task.valid() &&
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
	if response.SchemaVersion != "runner-read-task-complete-response.v1" ||
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
			if readTaskEvidenceFieldReserved(name) {
				return true
			}
			normalizedName := readTaskEvidenceFieldSkeleton(name)
			if normalizedName == "name" || normalizedName == "key" {
				if text, ok := child.(string); ok && readTaskEvidenceFieldReserved(text) {
					return true
				}
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

func readTaskEvidenceFieldReserved(value string) bool {
	normalized := readTaskEvidenceFieldSkeleton(value)
	tokens := readTaskEvidenceFieldTokens(value)
	for _, token := range tokens {
		switch token {
		case "source", "connector", "operation", "workspace", "environment", "runner",
			"certificate", "cert", "truncated", "target", "url", "uri", "endpoint",
			"header", "credential", "hash", "sha256":
			return true
		}
	}
	if readTaskEvidenceTokensContain(tokens, "scope", "revision") ||
		readTaskEvidenceTokensContain(tokens, "item", "count") ||
		readTaskEvidenceTokensContain(tokens, "idempotency", "key") ||
		readTaskEvidenceTokensContain(tokens, "raw", "error") ||
		readTaskEvidenceTokensContain(tokens, "error", "body") {
		return true
	}
	for _, reserved := range []string{
		"source", "connector", "connectorid", "operation", "workspace", "workspaceid",
		"environment", "environmentid", "runner", "runnerid", "scoperevision",
		"certificate", "certificatesha256", "itemcount", "idempotencykey", "truncated",
		"target", "url", "uri", "endpoint", "header", "headers", "credential",
		"rawerror", "errorbody", "sourceurl", "sourceuri", "sourceendpoint", "datasource",
		"targeturl", "targeturi", "targetendpoint", "requestheader", "requestheaders",
		"connectorname", "rawerrormessage", "sources", "credentials", "targeturls",
		"scoperevisions", "rawerrors", "errorbodies", "urls", "contenthash", "requesthash",
		"receipthash", "inputhash", "tokenhash", "certificatehash", "sha256",
	} {
		if normalized == reserved {
			return true
		}
	}
	return false
}

func readTaskEvidenceFieldTokens(value string) []string {
	runes := []rune(value)
	tokens := make([]string, 0, 4)
	current := make([]rune, 0, len(runes))
	flush := func() {
		if len(current) == 0 {
			return
		}
		tokens = append(tokens, string(current))
		current = current[:0]
	}
	for index, character := range runes {
		if !unicode.IsLetter(character) && !unicode.IsDigit(character) {
			flush()
			continue
		}
		if len(current) != 0 && unicode.IsUpper(character) {
			previous := runes[index-1]
			nextIsLower := index+1 < len(runes) && unicode.IsLower(runes[index+1])
			acronymPlural := nextIsLower && runes[index+1] == 's' &&
				(index+2 == len(runes) || !unicode.IsLetter(runes[index+2]) && !unicode.IsDigit(runes[index+2]))
			if unicode.IsLower(previous) || unicode.IsDigit(previous) || unicode.IsUpper(previous) && nextIsLower && !acronymPlural {
				flush()
			}
		}
		current = append(current, unicode.ToLower(character))
	}
	flush()
	for index := range tokens {
		tokens[index] = readTaskEvidenceSingularToken(tokens[index])
	}
	return tokens
}

func readTaskEvidenceSingularToken(token string) string {
	switch token {
	case "sources":
		return "source"
	case "connectors":
		return "connector"
	case "operations":
		return "operation"
	case "workspaces":
		return "workspace"
	case "environments":
		return "environment"
	case "runners":
		return "runner"
	case "certificates":
		return "certificate"
	case "certs":
		return "cert"
	case "targets":
		return "target"
	case "urls":
		return "url"
	case "uris":
		return "uri"
	case "endpoints":
		return "endpoint"
	case "headers":
		return "header"
	case "credentials":
		return "credential"
	case "hashes":
		return "hash"
	case "scopes":
		return "scope"
	case "revisions":
		return "revision"
	case "items":
		return "item"
	case "counts":
		return "count"
	case "keys":
		return "key"
	case "errors":
		return "error"
	case "bodies":
		return "body"
	default:
		return token
	}
}

func readTaskEvidenceTokensContain(tokens []string, required ...string) bool {
	for _, want := range required {
		found := false
		for _, token := range tokens {
			if token == want {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func readTaskEvidenceFieldSkeleton(value string) string {
	var normalized strings.Builder
	for _, character := range value {
		if unicode.IsLetter(character) || unicode.IsDigit(character) {
			normalized.WriteRune(unicode.ToLower(character))
		}
	}
	return normalized.String()
}
