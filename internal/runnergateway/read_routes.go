package runnergateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/go-chi/chi/v5"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/readgateway"
	"github.com/seaworld008/aiops-system/internal/readtask"
	"github.com/seaworld008/aiops-system/internal/runneridentity"
)

type readTaskOperation uint8

const (
	readTaskClaimOperation readTaskOperation = iota
	readTaskStartOperation
	readTaskHeartbeatOperation
	readTaskReleaseOperation
	readTaskCompleteOperation
)

func registerReadTaskRoutes(router chi.Router, backend ReadTaskBackend) {
	router.Post("/runner/v1/read-tasks/{task_id}:claim", func(writer http.ResponseWriter, request *http.Request) {
		if !readPrincipal(principalFromContext(request.Context())) {
			writeProtocolProblem(writer, request, identityRejectedProblem())
			return
		}
		taskID := chi.URLParam(request, "task_id")
		if !uuidPattern.MatchString(taskID) {
			writeProtocolProblem(writer, request, notFoundProblem())
			return
		}
		unexpectedAuthorization := len(request.Header.Values("Authorization")) != 0
		request.Header.Del("Authorization")
		if unexpectedAuthorization || !validReadOnlyRequestHeaders(request.Header) {
			writeProtocolProblem(writer, request, invalidRequestProblem())
			return
		}
		var input ReadTaskClaimRequest
		if !decodeRequest(writer, request, leaseBodyLimit, &input) {
			return
		}
		if !input.valid() {
			writeProtocolProblem(writer, request, invalidRequestProblem())
			return
		}
		identity := identityFromContext(request.Context())
		claim, binding, err := backend.Claim(request.Context(), identity, taskID)
		defer claim.Destroy()
		if errors.Is(err, readtask.ErrNoClaimAvailable) {
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		if err != nil {
			writeReadTaskBackendProblem(writer, request, readTaskClaimOperation, err)
			return
		}
		response, responseErr := readTaskClaimResponse(claim)
		if responseErr != nil || !validReadTaskClaimBinding(response, claim, identity, binding) {
			writeProtocolProblem(writer, request, internalProblem())
			return
		}
		defer func() { response.LeaseToken = "" }()
		writeReadTaskJSON(writer, request, http.StatusOK, leaseBodyLimit, response)
	})

	router.Post("/runner/v1/read-tasks/{task_id}:start", readTaskLeaseHandler(func(
		ctx context.Context, identity runneridentity.Identity, principal RequestPrincipal,
		taskID string, token []byte, writer http.ResponseWriter, request *http.Request,
	) {
		var input ReadTaskStartRequest
		if !decodeRequest(writer, request, defaultBodyLimit, &input) {
			return
		}
		if !input.valid() {
			writeProtocolProblem(writer, request, invalidRequestProblem())
			return
		}
		fence, err := readtask.NewFence(taskID, principal.RunnerID(), token, input.LeaseEpoch.Int64())
		if err != nil {
			writeProtocolProblem(writer, request, invalidRequestProblem())
			return
		}
		defer fence.Destroy()
		attempt, binding, err := backend.Start(ctx, identity, readtask.Start{Fence: fence})
		if err != nil {
			writeReadTaskBackendProblem(writer, request, readTaskStartOperation, err)
			return
		}
		response := ReadTaskStartResponse{
			SchemaVersion: "runner-read-task-start-response.v1", TaskID: attempt.TaskID,
			AttemptStatus: string(attempt.Status), LeaseEpoch: DecimalInt64(attempt.Epoch),
			ScopeRevision: DecimalInt64(attempt.ScopeRevision), StartedAt: attempt.StartedAt.UTC(),
		}
		if !validReadTaskAttemptBinding(attempt, fence, identity, binding, readtask.AttemptRunning) || !response.valid() {
			writeProtocolProblem(writer, request, internalProblem())
			return
		}
		writeReadTaskJSON(writer, request, http.StatusOK, defaultBodyLimit, response)
	}))

	router.Post("/runner/v1/read-tasks/{task_id}:heartbeat", readTaskLeaseHandler(func(
		ctx context.Context, identity runneridentity.Identity, principal RequestPrincipal,
		taskID string, token []byte, writer http.ResponseWriter, request *http.Request,
	) {
		var input ReadTaskHeartbeatRequest
		if !decodeRequest(writer, request, defaultBodyLimit, &input) {
			return
		}
		if !input.valid() {
			writeProtocolProblem(writer, request, invalidRequestProblem())
			return
		}
		fence, err := readtask.NewFence(taskID, principal.RunnerID(), token, input.LeaseEpoch.Int64())
		if err != nil {
			writeProtocolProblem(writer, request, invalidRequestProblem())
			return
		}
		defer fence.Destroy()
		result, binding, err := backend.Heartbeat(ctx, identity, readtask.Heartbeat{Fence: fence, Sequence: input.Sequence.Int64()})
		if err != nil {
			writeReadTaskBackendProblem(writer, request, readTaskHeartbeatOperation, err)
			return
		}
		response := ReadTaskHeartbeatResponse{
			SchemaVersion: "runner-read-task-heartbeat-response.v1", TaskID: result.Attempt.TaskID,
			LeaseEpoch: DecimalInt64(result.Attempt.Epoch), AcceptedSequence: DecimalInt64(result.AcceptedSequence),
			Directive: string(result.Directive), LeaseExpiresAt: result.LeaseExpiresAt.UTC(),
			HeartbeatAfterSeconds: readTaskHeartbeatAfterSeconds,
		}
		if !validReadTaskHeartbeatBinding(result, fence, input.Sequence.Int64(), identity, binding) || !response.valid() {
			writeProtocolProblem(writer, request, internalProblem())
			return
		}
		writeReadTaskJSON(writer, request, http.StatusOK, defaultBodyLimit, response)
	}))

	router.Post("/runner/v1/read-tasks/{task_id}:release", readTaskLeaseHandler(func(
		ctx context.Context, identity runneridentity.Identity, principal RequestPrincipal,
		taskID string, token []byte, writer http.ResponseWriter, request *http.Request,
	) {
		var input ReadTaskReleaseRequest
		if !decodeRequest(writer, request, defaultBodyLimit, &input) {
			return
		}
		if !input.valid() {
			writeProtocolProblem(writer, request, invalidRequestProblem())
			return
		}
		fence, err := readtask.NewFence(taskID, principal.RunnerID(), token, input.LeaseEpoch.Int64())
		if err != nil {
			writeProtocolProblem(writer, request, invalidRequestProblem())
			return
		}
		defer fence.Destroy()
		attempt, binding, err := backend.Release(ctx, identity, readtask.Release{
			Fence: fence, ReasonCode: readtask.ReleaseReason(input.ReasonCode),
		})
		if err != nil {
			writeReadTaskBackendProblem(writer, request, readTaskReleaseOperation, err)
			return
		}
		response := ReadTaskReleaseResponse{
			SchemaVersion: "runner-read-task-release-response.v1", TaskID: attempt.TaskID,
			AttemptStatus: string(attempt.Status), LeaseEpoch: DecimalInt64(attempt.Epoch),
		}
		if !validReadTaskAttemptBinding(attempt, fence, identity, binding, readtask.AttemptReleased) || !response.valid() {
			writeProtocolProblem(writer, request, internalProblem())
			return
		}
		writeReadTaskJSON(writer, request, http.StatusOK, defaultBodyLimit, response)
	}))

	router.Post("/runner/v1/read-tasks/{task_id}:complete", readTaskLeaseHandler(func(
		ctx context.Context, identity runneridentity.Identity, principal RequestPrincipal,
		taskID string, token []byte, writer http.ResponseWriter, request *http.Request,
	) {
		var input ReadTaskCompleteRequest
		if !decodeRequest(writer, request, defaultBodyLimit, &input) {
			return
		}
		if !input.valid() {
			writeProtocolProblem(writer, request, invalidRequestProblem())
			return
		}
		fence, err := readtask.NewFence(taskID, principal.RunnerID(), token, input.LeaseEpoch.Int64())
		if err != nil {
			writeProtocolProblem(writer, request, invalidRequestProblem())
			return
		}
		defer fence.Destroy()
		result, binding, err := backend.Complete(ctx, identity, input.completion(fence))
		if err != nil {
			writeReadTaskBackendProblem(writer, request, readTaskCompleteOperation, err)
			return
		}
		response := readTaskCompletionResponse(result)
		if !validReadTaskCompletionBinding(
			result, fence, input.Outcome, input.FailureCode, identity, binding,
		) || !response.valid() {
			writeProtocolProblem(writer, request, internalProblem())
			return
		}
		writeReadTaskJSON(writer, request, http.StatusOK, defaultBodyLimit, response)
	}))
}

type readTaskLeasedHandler func(
	context.Context, runneridentity.Identity, RequestPrincipal, string, []byte,
	http.ResponseWriter, *http.Request,
)

func readTaskLeaseHandler(next readTaskLeasedHandler) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		principal := principalFromContext(request.Context())
		if !readPrincipal(principal) {
			writeProtocolProblem(writer, request, identityRejectedProblem())
			return
		}
		taskID := chi.URLParam(request, "task_id")
		if !uuidPattern.MatchString(taskID) {
			writeProtocolProblem(writer, request, notFoundProblem())
			return
		}
		token, ok := readTaskLeaseAuthorization(request)
		request.Header.Del("Authorization")
		if !validReadOnlyRequestHeaders(request.Header) {
			clear(token)
			writeProtocolProblem(writer, request, invalidRequestProblem())
			return
		}
		if !ok {
			clear(token)
			writeProtocolProblem(writer, request, leaseAuthenticationProblem())
			return
		}
		defer clear(token)
		next(request.Context(), identityFromContext(request.Context()), principal, taskID, token, writer, request)
	}
}

func readTaskLeaseAuthorization(request *http.Request) ([]byte, bool) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || len(values[0]) <= len(readTaskLeaseScheme) ||
		values[0][:len(readTaskLeaseScheme)] != readTaskLeaseScheme {
		return nil, false
	}
	encoded := values[0][len(readTaskLeaseScheme):]
	if !readTaskTokenPattern.MatchString(encoded) {
		return nil, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if decoded != nil {
		defer clear(decoded)
	}
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return nil, false
	}
	return []byte(encoded), true
}

func validReadOnlyRequestHeaders(header http.Header) bool {
	return len(header.Values("Cookie")) == 0 && len(header.Values("Idempotency-Key")) == 0
}

func readPrincipal(principal RequestPrincipal) bool {
	return !nilInterface(principal) && principal.Valid() && principal.Pool() == runneridentity.PoolRead &&
		!principal.CredentialRevocationCapable()
}

func readTaskClaimResponse(claim readtask.Claim) (ReadTaskClaimResponse, error) {
	if !claim.Valid() {
		return ReadTaskClaimResponse{}, errors.New("invalid READ task claim")
	}
	descriptor := claim.Descriptor()
	attempt := claim.Attempt()
	token, err := claim.TokenBytes()
	if err != nil {
		return ReadTaskClaimResponse{}, err
	}
	defer clear(token)
	return ReadTaskClaimResponse{
		SchemaVersion: "runner-read-task-claim-response.v2",
		Task: ReadTaskDescriptor{
			ID: descriptor.TaskID, Key: descriptor.TaskKey, Position: descriptor.Position,
			ConnectorID: descriptor.ConnectorID, Operation: descriptor.Operation,
			Input: append(json.RawMessage(nil), descriptor.Input...), InputHash: descriptor.InputHash,
			PlanBinding:    readTaskPlanBinding(descriptor.PlanBinding),
			RuntimeBinding: readTaskRuntimeBinding(descriptor.RuntimeBinding),
		},
		LeaseToken: string(token), LeaseEpoch: DecimalInt64(attempt.Epoch),
		ScopeRevision: DecimalInt64(attempt.ScopeRevision), LeaseExpiresAt: attempt.LeaseExpiresAt.UTC(),
		HeartbeatAfterSeconds: readTaskHeartbeatAfterSeconds,
	}, nil
}

func validReadTaskClaimBinding(
	response ReadTaskClaimResponse,
	claim readtask.Claim,
	identity runneridentity.Identity,
	principal RequestPrincipal,
) bool {
	if !response.valid() || !claim.Valid() || !readIdentityBinding(identity, principal) {
		return false
	}
	descriptor := claim.Descriptor()
	attempt := claim.Attempt()
	if descriptor.Validate() != nil || attempt.ValidateAgainst(descriptor) != nil ||
		!principal.Allows(descriptor.WorkspaceID, descriptor.EnvironmentID) ||
		!validReadTaskAttemptBinding(attempt, claim.Fence(), identity, principal, readtask.AttemptLeased) ||
		response.Task.ID != descriptor.TaskID || response.Task.Key != descriptor.TaskKey ||
		response.Task.Position != descriptor.Position || response.Task.ConnectorID != descriptor.ConnectorID ||
		response.Task.Operation != descriptor.Operation || !bytes.Equal(response.Task.Input, descriptor.Input) ||
		response.Task.InputHash != descriptor.InputHash || response.LeaseEpoch.Int64() != attempt.Epoch ||
		response.ScopeRevision.Int64() != attempt.ScopeRevision ||
		!response.LeaseExpiresAt.Equal(attempt.LeaseExpiresAt) ||
		!validReadTaskClaimSnapshotBinding(response.Task, descriptor, attempt) {
		return false
	}
	token, err := claim.TokenBytes()
	if token != nil {
		defer clear(token)
	}
	responseToken := []byte(response.LeaseToken)
	defer clear(responseToken)
	return err == nil && bytes.Equal(token, responseToken)
}

func readTaskPlanBinding(binding domain.InvestigationPlanBinding) ReadTaskPlanBinding {
	return ReadTaskPlanBinding{
		SchemaVersion: binding.SchemaVersion, ManifestDigest: binding.ManifestDigest,
		RegistryDigest: binding.RegistryDigest, ProfileDigest: binding.ProfileDigest,
		TasksHash: binding.TasksHash,
	}
}

func readTaskRuntimeBinding(binding domain.ReadTaskRuntimeBinding) ReadTaskRuntimeBinding {
	return ReadTaskRuntimeBinding{
		SchemaVersion: binding.SchemaVersion, ConnectorDigest: binding.ConnectorDigest,
		TargetDigest: binding.TargetDigest, ExecutorDigest: binding.ExecutorDigest,
		RuntimeDigest: binding.RuntimeDigest, BoundAt: binding.BoundAt.UTC(),
	}
}

func validReadTaskClaimSnapshotBinding(
	wire ReadTaskDescriptor,
	descriptor readtask.Descriptor,
	attempt readtask.Attempt,
) bool {
	return wire.PlanBinding.valid() && wire.RuntimeBinding.valid() &&
		readTaskWirePlanBindingEqual(wire.PlanBinding, descriptor.PlanBinding) &&
		readTaskWireRuntimeBindingEqual(wire.RuntimeBinding, descriptor.RuntimeBinding) &&
		readTaskPlanBindingsEqual(descriptor.PlanBinding, attempt.PlanBinding) &&
		readTaskRuntimeBindingsEqual(descriptor.RuntimeBinding, attempt.RuntimeBinding)
}

func readTaskWirePlanBindingEqual(wire ReadTaskPlanBinding, binding domain.InvestigationPlanBinding) bool {
	return wire.valid() && binding.Validate() == nil &&
		wire.SchemaVersion == binding.SchemaVersion && wire.ManifestDigest == binding.ManifestDigest &&
		wire.RegistryDigest == binding.RegistryDigest && wire.ProfileDigest == binding.ProfileDigest &&
		wire.TasksHash == binding.TasksHash
}

func readTaskWireRuntimeBindingEqual(wire ReadTaskRuntimeBinding, binding domain.ReadTaskRuntimeBinding) bool {
	return wire.valid() && binding.Validate() == nil &&
		wire.SchemaVersion == binding.SchemaVersion && wire.ConnectorDigest == binding.ConnectorDigest &&
		wire.TargetDigest == binding.TargetDigest && wire.ExecutorDigest == binding.ExecutorDigest &&
		wire.RuntimeDigest == binding.RuntimeDigest && wire.BoundAt.Equal(binding.BoundAt)
}

func readTaskPlanBindingsEqual(left, right domain.InvestigationPlanBinding) bool {
	return left.Validate() == nil && right.Validate() == nil &&
		left.SchemaVersion == right.SchemaVersion && left.ManifestDigest == right.ManifestDigest &&
		left.RegistryDigest == right.RegistryDigest && left.ProfileDigest == right.ProfileDigest &&
		left.TasksHash == right.TasksHash
}

func readTaskRuntimeBindingsEqual(left, right domain.ReadTaskRuntimeBinding) bool {
	return left.Validate() == nil && right.Validate() == nil &&
		left.SchemaVersion == right.SchemaVersion && left.ConnectorDigest == right.ConnectorDigest &&
		left.TargetDigest == right.TargetDigest && left.ExecutorDigest == right.ExecutorDigest &&
		left.RuntimeDigest == right.RuntimeDigest && left.BoundAt.Equal(right.BoundAt)
}

func validReadTaskAttemptBinding(
	attempt readtask.Attempt,
	fence readtask.Fence,
	identity runneridentity.Identity,
	principal RequestPrincipal,
	status readtask.AttemptStatus,
) bool {
	if !readIdentityBinding(identity, principal) || !validReadTaskAttemptShape(attempt, status) ||
		!fence.Valid() || attempt.TaskID != fence.TaskID() || attempt.RunnerID != fence.RunnerID() ||
		attempt.RunnerID != principal.RunnerID() ||
		attempt.ScopeRevision != principal.ScopeRevision() || attempt.Certificate.SHA256 != principal.CertificateSHA256() ||
		!attempt.Certificate.NotAfter.Equal(principal.CertificateNotAfter()) || attempt.Epoch != fence.Epoch() ||
		!fence.MatchesTokenSHA256(attempt.TokenSHA256) {
		return false
	}
	return true
}

func validReadTaskAttemptShape(attempt readtask.Attempt, status readtask.AttemptStatus) bool {
	if !uuidPattern.MatchString(attempt.TaskID) || !validResourceID(attempt.RunnerID) || attempt.ScopeRevision <= 0 ||
		attempt.Certificate.Validate() != nil || !hashPattern.MatchString(attempt.TokenSHA256) || attempt.Epoch <= 0 ||
		attempt.PlanBinding.Validate() != nil || attempt.RuntimeBinding.Validate() != nil ||
		attempt.Status != status || attempt.HeartbeatSequence < 0 || !validReadTaskTime(attempt.LeaseAcquiredAt) ||
		!validReadTaskTime(attempt.LastHeartbeatAt) || !validReadTaskTime(attempt.LeaseExpiresAt) ||
		!validReadTaskTime(attempt.UpdatedAt) || attempt.LastHeartbeatAt.Before(attempt.LeaseAcquiredAt) ||
		!attempt.LeaseExpiresAt.After(attempt.LastHeartbeatAt) || attempt.LeaseExpiresAt.After(attempt.Certificate.NotAfter) ||
		attempt.UpdatedAt.Before(attempt.LastHeartbeatAt) ||
		(!attempt.StartedAt.IsZero() && (!validReadTaskTime(attempt.StartedAt) ||
			attempt.StartedAt.Before(attempt.LeaseAcquiredAt) || attempt.StartedAt.After(attempt.UpdatedAt))) ||
		(!attempt.TerminalAt.IsZero() && (!validReadTaskTime(attempt.TerminalAt) ||
			attempt.TerminalAt.Before(attempt.LeaseAcquiredAt) || attempt.TerminalAt.After(attempt.UpdatedAt))) ||
		(!attempt.StartedAt.IsZero() && !attempt.TerminalAt.IsZero() && attempt.TerminalAt.Before(attempt.StartedAt)) {
		return false
	}
	switch status {
	case readtask.AttemptLeased:
		return attempt.StartedAt.IsZero() && attempt.TerminalAt.IsZero() && readTaskAttemptHasNoCompletionHashes(attempt)
	case readtask.AttemptRunning:
		return validReadTaskTime(attempt.StartedAt) && attempt.TerminalAt.IsZero() &&
			readTaskAttemptHasNoCompletionHashes(attempt)
	case readtask.AttemptReleased:
		return attempt.StartedAt.IsZero() && validReadTaskTime(attempt.TerminalAt) &&
			readTaskAttemptHasNoCompletionHashes(attempt)
	case readtask.AttemptCompleted:
		return validReadTaskTime(attempt.StartedAt) && validReadTaskTime(attempt.TerminalAt) &&
			attempt.TerminalAt.Before(attempt.LeaseExpiresAt) &&
			hashPattern.MatchString(attempt.RequestHash) && hashPattern.MatchString(attempt.ReceiptHash) &&
			attempt.RequestHashVersion == readtask.CompletionRequestHashVersionV3 &&
			attempt.ReceiptHashVersion == readtask.CompletionReceiptHashVersionV3
	case readtask.AttemptCancelled:
		return validReadTaskTime(attempt.TerminalAt) && readTaskAttemptHasNoCompletionHashes(attempt)
	default:
		return false
	}
}

func readTaskAttemptHasNoCompletionHashes(attempt readtask.Attempt) bool {
	return attempt.RequestHash == "" && attempt.ReceiptHash == "" &&
		attempt.RequestHashVersion == "" && attempt.ReceiptHashVersion == ""
}

func validReadTaskHeartbeatBinding(
	result readtask.HeartbeatResult,
	fence readtask.Fence,
	sequence int64,
	identity runneridentity.Identity,
	principal RequestPrincipal,
) bool {
	if !readIdentityBinding(identity, principal) || !fence.Valid() ||
		result.Attempt.TaskID != fence.TaskID() || result.Attempt.RunnerID != fence.RunnerID() ||
		result.Attempt.RunnerID != principal.RunnerID() || result.Attempt.Epoch != fence.Epoch() ||
		!fence.MatchesTokenSHA256(result.Attempt.TokenSHA256) ||
		result.AcceptedSequence != sequence || result.AcceptedSequence != result.Attempt.HeartbeatSequence ||
		!result.LeaseExpiresAt.Equal(result.Attempt.LeaseExpiresAt) {
		return false
	}
	if result.Directive == readtask.HeartbeatContinue {
		return validReadTaskAttemptBinding(
			result.Attempt, fence, identity, principal, readtask.AttemptRunning,
		)
	}
	return result.Directive == readtask.HeartbeatTerminate && result.Attempt.Status == readtask.AttemptCancelled &&
		validReadTaskAttemptShape(result.Attempt, readtask.AttemptCancelled)
}

func readTaskCompletionResponse(result readtask.CompletionResult) ReadTaskCompleteResponse {
	receipt := result.Projection.Receipt()
	taskStatus := ""
	switch receipt.Outcome {
	case readtask.CompletionEvidence:
		taskStatus = "EVIDENCE"
	case readtask.CompletionFailed:
		taskStatus = "FAILED"
	case readtask.CompletionCancelled:
		taskStatus = "CANCELLED"
	}
	return ReadTaskCompleteResponse{
		SchemaVersion: "runner-read-task-complete-response.v2", TaskID: result.Attempt.TaskID,
		LeaseEpoch: DecimalInt64(result.Attempt.Epoch), AttemptStatus: string(result.Attempt.Status),
		TaskStatus: taskStatus, EvidenceID: result.EvidenceID, ContentHash: result.Projection.ContentHash(),
		ReceiptID: result.ReceiptID, ReceiptHash: result.Projection.ReceiptHash(), Replayed: result.Replayed,
	}
}

func validReadTaskCompletionBinding(
	result readtask.CompletionResult,
	fence readtask.Fence,
	outcome readtask.CompletionOutcome,
	failureCode readtask.FailureCode,
	identity runneridentity.Identity,
	principal RequestPrincipal,
) bool {
	if !validReadTaskAttemptBinding(result.Attempt, fence, identity, principal, readtask.AttemptCompleted) ||
		!uuidPattern.MatchString(result.ReceiptID) {
		return false
	}
	receipt := result.Projection.Receipt()
	if receipt.SchemaVersion != readtask.RunnerEvidenceSchemaVersionV3 ||
		receipt.RequestHashVersion != readtask.CompletionRequestHashVersionV3 ||
		receipt.ReceiptHashVersion != readtask.CompletionReceiptHashVersionV3 ||
		receipt.RequestHashVersion != result.Attempt.RequestHashVersion ||
		receipt.ReceiptHashVersion != result.Attempt.ReceiptHashVersion ||
		receipt.TaskID != fence.TaskID() || receipt.RunnerID != principal.RunnerID() ||
		receipt.TenantID != principal.TenantID() || !principal.Allows(receipt.WorkspaceID, receipt.EnvironmentID) ||
		!uuidPattern.MatchString(receipt.ServiceID) ||
		receipt.ScopeRevision != principal.ScopeRevision() || receipt.CertificateSHA256 != principal.CertificateSHA256() ||
		receipt.LeaseEpoch != fence.Epoch() || receipt.Outcome != outcome || result.Projection.Outcome() != outcome ||
		receipt.RequestHash != result.Attempt.RequestHash || receipt.ReceiptHash != result.Attempt.ReceiptHash ||
		result.Projection.RequestHash() != receipt.RequestHash || result.Projection.ReceiptHash() != receipt.ReceiptHash ||
		!validReadTaskTime(receipt.ReceivedAt) ||
		!readTaskPlanBindingsEqual(result.Attempt.PlanBinding, receipt.PlanBinding) ||
		!readTaskRuntimeBindingsEqual(result.Attempt.RuntimeBinding, receipt.RuntimeBinding) {
		return false
	}
	if outcome == readtask.CompletionEvidence {
		return uuidPattern.MatchString(result.EvidenceID) && hashPattern.MatchString(result.Projection.ContentHash()) &&
			receipt.ContentHash == result.Projection.ContentHash() && receipt.FailureCode == "" && failureCode == ""
	}
	return result.EvidenceID == "" && result.Projection.ContentHash() == "" && receipt.ContentHash == "" &&
		receipt.FailureCode == failureCode
}

func readIdentityBinding(identity runneridentity.Identity, principal RequestPrincipal) bool {
	return validRequestPrincipal(identity, principal) && readPrincipal(principal)
}

func writeReadTaskJSON(
	writer http.ResponseWriter,
	request *http.Request,
	status int,
	limit int64,
	value any,
) {
	marshaled, err := json.Marshal(value)
	if marshaled != nil {
		defer clear(marshaled)
	}
	if err != nil {
		writeProtocolProblem(writer, request, internalProblem())
		return
	}
	// Canonicalizing the full envelope reverses encoding/json's HTML and
	// U+2028/U+2029 escapes. Task input is already JCS in durable state, so its
	// exact wire bytes continue to match input_hash after nesting in a response.
	encoded, err := jsoncanonicalizer.Transform(marshaled)
	if encoded != nil {
		defer clear(encoded)
	}
	if err != nil || int64(len(encoded)) > limit {
		writeProtocolProblem(writer, request, internalProblem())
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(encoded)
}

func writeReadTaskBackendProblem(
	writer http.ResponseWriter,
	request *http.Request,
	operation readTaskOperation,
	err error,
) {
	value := readTaskBackendProblem(err)
	if !readTaskOperationAllowsProblem(operation, value) {
		value = internalProblem()
	}
	writeProtocolProblem(writer, request, value)
}

func readTaskOperationAllowsProblem(operation readTaskOperation, problem protocolProblem) bool {
	switch problem.status {
	case http.StatusBadRequest:
		return problem.code == "invalid_runner_request"
	case http.StatusForbidden:
		return problem.code == "runner_identity_rejected"
	case http.StatusNotFound:
		return problem.code == "runner_resource_not_found"
	case http.StatusServiceUnavailable:
		if problem.code == "runner_dependency_unavailable" {
			return true
		}
		return problem.code == "runner_claims_disabled" &&
			(operation == readTaskClaimOperation || operation == readTaskStartOperation || operation == readTaskCompleteOperation)
	case http.StatusInternalServerError:
		return problem.code == "runner_internal_error"
	}
	switch operation {
	case readTaskClaimOperation:
		return false
	case readTaskStartOperation, readTaskReleaseOperation:
		return problem.status == http.StatusConflict &&
			(problem.code == "runner_stale_lease" || problem.code == "runner_state_conflict")
	case readTaskHeartbeatOperation:
		return problem.status == http.StatusConflict &&
			(problem.code == "runner_stale_lease" || problem.code == "runner_state_conflict" ||
				problem.code == "runner_heartbeat_sequence_conflict")
	case readTaskCompleteOperation:
		return problem.status == http.StatusConflict &&
			(problem.code == "runner_stale_lease" || problem.code == "runner_state_conflict" ||
				problem.code == "runner_result_conflict") ||
			problem.status == http.StatusUnprocessableEntity && problem.code == "runner_result_rejected"
	default:
		return false
	}
}

func readTaskBackendProblem(err error) protocolProblem {
	switch {
	case errors.Is(err, readtask.ErrInvalidRequest):
		return invalidRequestProblem()
	case errors.Is(err, readgateway.ErrForbidden):
		return identityRejectedProblem()
	case errors.Is(err, readtask.ErrNotFound):
		return notFoundProblem()
	case errors.Is(err, readtask.ErrStaleFence):
		return protocolProblem{409, "urn:aiops:problem:runner:stale-lease", "runner_stale_lease", "Stale lease", "The lease fence is no longer current"}
	case errors.Is(err, readtask.ErrHeartbeatConflict):
		return protocolProblem{409, "urn:aiops:problem:runner:heartbeat-sequence-conflict", "runner_heartbeat_sequence_conflict", "Heartbeat conflict", "The heartbeat sequence is not current"}
	case errors.Is(err, readtask.ErrCompletionConflict):
		return protocolProblem{409, "urn:aiops:problem:runner:result-conflict", "runner_result_conflict", "Result conflict", "The result conflicts with the durable receipt"}
	case errors.Is(err, readtask.ErrInvalidTransition):
		return protocolProblem{409, "urn:aiops:problem:runner:state-conflict", "runner_state_conflict", "State conflict", "The resource is not in the required state"}
	case errors.Is(err, readtask.ErrProjectionRejected):
		return protocolProblem{422, "urn:aiops:problem:runner:result-rejected", "runner_result_rejected", "Result rejected", "The structured result does not satisfy the registered READ contract"}
	case errors.Is(err, readtask.ErrClaimsDisabled):
		return protocolProblem{503, "urn:aiops:problem:runner:claims-disabled", "runner_claims_disabled", "Claims disabled", "Runner claims are disabled"}
	case errors.Is(err, readgateway.ErrUnavailable):
		return protocolProblem{503, "urn:aiops:problem:runner:dependency-unavailable", "runner_dependency_unavailable", "Dependency unavailable", "A required dependency is unavailable"}
	default:
		return internalProblem()
	}
}
