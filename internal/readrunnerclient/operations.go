package readrunnerclient

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/readtask"
)

const readTaskLeaseScheme = "AIOPS-Read-Task-Lease "

func (client *Client) Start(ctx context.Context, lease *Lease) (*StartCapability, error) {
	if !validContext(ctx) {
		return nil, ErrInvalidConfiguration
	}
	state, err := client.beginLeaseOperation(lease, nil, leasePhaseClaimed)
	if err != nil {
		return nil, err
	}
	state.mu.Lock()
	usable := !state.leaseExpiresAt.Before(time.Now().UTC().Add(minimumLeaseRemaining))
	state.mu.Unlock()
	if !usable {
		client.cancelLeaseOperation(state)
		return nil, ErrInvalidLease
	}
	body, err := json.Marshal(startRequestWire{
		SchemaVersion: "runner-read-task-start-request.v1", LeaseEpoch: decimalInt64(state.leaseEpoch),
	})
	if err != nil {
		client.failLeaseOperation(state)
		return nil, ErrInvalidConfiguration
	}
	response, err := client.doLeaseRequest(ctx, state, ":start", body)
	clear(body)
	if err != nil {
		client.failLeaseOperation(state)
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		err := decodeProblem(response)
		client.failLeaseOperation(state)
		return nil, err
	}
	var wire startResponseWire
	if err := decodeJSONResponse(response, defaultResponseLimit, &wire); err != nil ||
		!validStartResponse(client, state, wire, time.Now().UTC()) {
		client.failLeaseOperation(state)
		return nil, ErrInvalidResponse
	}
	state.mu.Lock()
	if !state.busy || state.phase != leasePhaseClaimed {
		state.mu.Unlock()
		client.failLeaseOperation(state)
		return nil, ErrInvalidLease
	}
	state.phase = leasePhaseRunning
	state.busy = false
	state.mu.Unlock()
	capability := &StartCapability{
		taskID: wire.TaskID, leaseEpoch: wire.LeaseEpoch.Int64(), scopeRevision: wire.ScopeRevision.Int64(),
		startedAt: stripMonotonic(wire.StartedAt), lease: state, seal: trustedStartSeal,
	}
	capability.self = capability
	return capability, nil
}

func (client *Client) Heartbeat(
	ctx context.Context,
	lease *Lease,
	start *StartCapability,
	sequence int64,
) (HeartbeatResult, error) {
	if !validContext(ctx) || sequence <= 0 {
		return HeartbeatResult{}, ErrInvalidLease
	}
	state, err := client.beginLeaseOperation(lease, start, leasePhaseRunning)
	if err != nil {
		return HeartbeatResult{}, err
	}
	state.mu.Lock()
	expectedSequence := state.heartbeatSequence + 1
	state.mu.Unlock()
	if expectedSequence <= 0 || expectedSequence == math.MinInt64 || sequence != expectedSequence {
		client.cancelLeaseOperation(state)
		return HeartbeatResult{}, ErrInvalidLease
	}
	body, err := json.Marshal(heartbeatRequestWire{
		SchemaVersion: "runner-read-task-heartbeat-request.v1", LeaseEpoch: decimalInt64(state.leaseEpoch),
		Sequence: decimalInt64(sequence),
	})
	if err != nil {
		client.failLeaseOperation(state)
		return HeartbeatResult{}, ErrInvalidConfiguration
	}
	response, err := client.doLeaseRequest(ctx, state, ":heartbeat", body)
	clear(body)
	if err != nil {
		client.failLeaseOperation(state)
		return HeartbeatResult{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		err := decodeProblem(response)
		client.failLeaseOperation(state)
		return HeartbeatResult{}, err
	}
	var wire heartbeatResponseWire
	if err := decodeJSONResponse(response, defaultResponseLimit, &wire); err != nil ||
		!validHeartbeatResponse(client, state, wire, sequence, time.Now().UTC()) {
		client.failLeaseOperation(state)
		return HeartbeatResult{}, ErrInvalidResponse
	}
	result := HeartbeatResult{
		AcceptedSequence: wire.AcceptedSequence.Int64(), Directive: readtask.HeartbeatDirective(wire.Directive),
		LeaseExpiresAt: stripMonotonic(wire.LeaseExpiresAt), HeartbeatAfterSeconds: wire.HeartbeatAfterSeconds,
	}
	state.mu.Lock()
	if !state.busy || state.phase != leasePhaseRunning {
		state.mu.Unlock()
		client.failLeaseOperation(state)
		return HeartbeatResult{}, ErrInvalidLease
	}
	state.heartbeatSequence = sequence
	state.leaseExpiresAt = result.LeaseExpiresAt
	if result.Directive == readtask.HeartbeatContinue {
		state.busy = false
		state.mu.Unlock()
		return result, nil
	}
	state.phase = leasePhaseTerminal
	state.busy = false
	token := state.token
	state.token = nil
	state.mu.Unlock()
	if token != nil {
		token.destroy()
	}
	return result, nil
}

// Release returns a task that has not crossed the start barrier. Once a
// release request is attempted the local lease is terminal even if transport
// outcome is ambiguous, preventing accidental execution under a stale fence.
func (client *Client) Release(ctx context.Context, lease *Lease, reason readtask.ReleaseReason) error {
	if !validContext(ctx) || !validReleaseReason(reason) {
		return ErrInvalidLease
	}
	state, err := client.beginLeaseOperation(lease, nil, leasePhaseClaimed)
	if err != nil {
		return err
	}
	body, err := json.Marshal(releaseRequestWire{
		SchemaVersion: "runner-read-task-release-request.v1", LeaseEpoch: decimalInt64(state.leaseEpoch),
		ReasonCode: string(reason),
	})
	if err != nil {
		client.failLeaseOperation(state)
		return ErrInvalidConfiguration
	}
	response, err := client.doLeaseRequest(ctx, state, ":release", body)
	clear(body)
	if err != nil {
		client.failLeaseOperation(state)
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		err := decodeProblem(response)
		client.failLeaseOperation(state)
		return err
	}
	var wire releaseResponseWire
	if err := decodeJSONResponse(response, defaultResponseLimit, &wire); err != nil ||
		wire.SchemaVersion != "runner-read-task-release-response.v1" || wire.TaskID != state.taskID ||
		wire.AttemptStatus != string(readtask.AttemptReleased) || wire.LeaseEpoch.Int64() != state.leaseEpoch {
		client.failLeaseOperation(state)
		return ErrInvalidResponse
	}
	client.finishLeaseOperation(state)
	return nil
}

func (client *Client) Complete(
	ctx context.Context,
	lease *Lease,
	start *StartCapability,
	completion Completion,
) (CompletionReceipt, error) {
	if !validContext(ctx) || !validCompletion(completion) || !completionBoundToStart(completion, start) {
		return CompletionReceipt{}, ErrInvalidCompletion
	}
	state, err := client.beginLeaseOperation(lease, start, leasePhaseRunning)
	if err != nil {
		return CompletionReceipt{}, err
	}
	request := completeRequestWire{
		SchemaVersion: "runner-read-task-complete-request.v1", LeaseEpoch: decimalInt64(state.leaseEpoch),
		Outcome: completion.Outcome, FailureCode: completion.FailureCode,
	}
	if completion.Evidence != nil {
		evidence := cloneEvidence(completion.Evidence)
		request.Evidence = &evidenceCompletionWire{CollectedAt: evidence.CollectedAt, Items: evidence.Items}
	}
	body, err := json.Marshal(request)
	if err != nil || int64(len(body)) > defaultResponseLimit {
		clear(body)
		client.cancelLeaseOperation(state)
		return CompletionReceipt{}, ErrInvalidCompletion
	}
	response, err := client.doLeaseRequest(ctx, state, ":complete", body)
	clear(body)
	if err != nil {
		client.failLeaseOperation(state)
		return CompletionReceipt{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		err := decodeProblem(response)
		client.failLeaseOperation(state)
		return CompletionReceipt{}, err
	}
	var wire completeResponseWire
	if err := decodeJSONResponse(response, defaultResponseLimit, &wire); err != nil ||
		!validCompleteResponse(state, completion, wire) {
		client.failLeaseOperation(state)
		return CompletionReceipt{}, ErrInvalidResponse
	}
	receipt := CompletionReceipt{
		TaskID: wire.TaskID, LeaseEpoch: wire.LeaseEpoch.Int64(), TaskStatus: wire.TaskStatus,
		EvidenceID: wire.EvidenceID, ContentHash: wire.ContentHash, ReceiptID: wire.ReceiptID,
		ReceiptHash: wire.ReceiptHash, Replayed: wire.Replayed,
	}
	client.finishLeaseOperation(state)
	return receipt, nil
}

func (client *Client) beginLeaseOperation(
	lease *Lease,
	start *StartCapability,
	phase leasePhase,
) (*leaseState, error) {
	if client == nil || client.httpClient == nil || lease == nil || lease.self != lease ||
		lease.seal != trustedLeaseSeal || lease.state == nil {
		return nil, ErrInvalidLease
	}
	state := lease.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.owner != client || state.token == nil || state.phase != phase || state.busy ||
		state.taskID == "" || state.leaseEpoch <= 0 || state.scopeRevision <= 0 ||
		!state.leaseExpiresAt.After(time.Now().UTC()) {
		return nil, ErrInvalidLease
	}
	if start != nil && (start.self != start || start.seal != trustedStartSeal || start.lease != state ||
		start.taskID != state.taskID || start.leaseEpoch != state.leaseEpoch ||
		start.scopeRevision != state.scopeRevision || start.startedAt.IsZero()) {
		return nil, ErrInvalidLease
	}
	state.busy = true
	return state, nil
}

func (client *Client) doLeaseRequest(
	ctx context.Context,
	state *leaseState,
	suffix string,
	body []byte,
) (*http.Response, error) {
	if !validContext(ctx) || state == nil {
		return nil, ErrInvalidLease
	}
	state.mu.Lock()
	if !state.busy || state.token == nil {
		state.mu.Unlock()
		return nil, ErrInvalidLease
	}
	tokenHandle := state.token
	taskID := state.taskID
	state.mu.Unlock()
	var response *http.Response
	err := tokenHandle.borrow(func(token []byte) error {
		request, err := client.newRequest(ctx, http.MethodPost, "/runner/v1/read-tasks/"+taskID+suffix, body)
		if err != nil {
			return err
		}
		request.Header["Authorization"] = []string{readTaskLeaseScheme + string(token)}
		response, err = client.httpClient.Do(request)
		request.Header.Del("Authorization")
		if err != nil {
			closeErroredResponse(&response)
			return boundedTransportError(err)
		}
		return nil
	})
	return response, err
}

func (client *Client) cancelLeaseOperation(state *leaseState) {
	if state == nil {
		return
	}
	state.mu.Lock()
	state.busy = false
	state.mu.Unlock()
}

func (client *Client) failLeaseOperation(state *leaseState) {
	if state == nil {
		return
	}
	state.destroy()
}

func (client *Client) finishLeaseOperation(state *leaseState) {
	if state == nil {
		return
	}
	state.mu.Lock()
	state.phase = leasePhaseTerminal
	state.busy = false
	token := state.token
	state.token = nil
	state.mu.Unlock()
	if token != nil {
		token.destroy()
	}
}

func validStartResponse(client *Client, state *leaseState, response startResponseWire, now time.Time) bool {
	return client != nil && state != nil && response.SchemaVersion == "runner-read-task-start-response.v1" &&
		response.TaskID == state.taskID && response.AttemptStatus == string(readtask.AttemptRunning) &&
		response.LeaseEpoch.Int64() == state.leaseEpoch && response.ScopeRevision.Int64() == state.scopeRevision &&
		validProtocolTime(response.StartedAt) && !response.StartedAt.Before(now.Add(-requestTimeout)) &&
		!response.StartedAt.After(now.Add(protocolClockSkew)) &&
		!state.leaseExpiresAt.Before(now.Add(minimumLeaseRemaining)) &&
		response.StartedAt.Before(state.leaseExpiresAt) && response.StartedAt.Before(client.certificateNotAfter)
}

func validHeartbeatResponse(
	client *Client,
	state *leaseState,
	response heartbeatResponseWire,
	sequence int64,
	now time.Time,
) bool {
	if client == nil || state == nil || response.SchemaVersion != "runner-read-task-heartbeat-response.v1" ||
		response.TaskID != state.taskID || response.LeaseEpoch.Int64() != state.leaseEpoch ||
		response.AcceptedSequence.Int64() != sequence || !validProtocolTime(response.LeaseExpiresAt) ||
		response.LeaseExpiresAt.After(now.Add(maximumLeaseLifetime+protocolClockSkew)) ||
		response.LeaseExpiresAt.After(client.certificateNotAfter) || response.HeartbeatAfterSeconds != 10 {
		return false
	}
	switch readtask.HeartbeatDirective(response.Directive) {
	case readtask.HeartbeatContinue:
		return !response.LeaseExpiresAt.Before(now.Add(minimumLeaseRemaining))
	case readtask.HeartbeatTerminate:
		return true
	default:
		return false
	}
}

func validCompletion(completion Completion) bool {
	switch completion.Outcome {
	case readtask.CompletionEvidence:
		if completion.Evidence == nil || completion.FailureCode != "" || completion.Evidence.Items == nil ||
			!validProtocolTime(completion.Evidence.CollectedAt) ||
			len(completion.Evidence.Items) > readtask.MaxEvidenceItems {
			return false
		}
		total := 0
		for _, item := range completion.Evidence.Items {
			if len(item) > readtask.MaxEvidencePayloadBytes-total || domain.ValidateSafeJSONObject(item) != nil ||
				jsonDocumentDepth(item) > readtask.MaxEvidenceJSONDepth || evidenceContainsReservedField(item) {
				return false
			}
			total += len(item)
		}
		return true
	case readtask.CompletionFailed:
		return completion.Evidence == nil && validFailureCode(completion.FailureCode) &&
			completion.FailureCode != readtask.FailureCancelled
	case readtask.CompletionCancelled:
		return completion.Evidence == nil && completion.FailureCode == readtask.FailureCancelled
	default:
		return false
	}
}

func completionBoundToStart(completion Completion, start *StartCapability) bool {
	if start == nil || !start.ready() {
		return false
	}
	return completion.Outcome != readtask.CompletionEvidence ||
		(completion.Evidence != nil && completion.Evidence.CollectedAt.Equal(start.startedAt))
}

func validCompleteResponse(state *leaseState, completion Completion, response completeResponseWire) bool {
	if state == nil || response.SchemaVersion != "runner-read-task-complete-response.v2" ||
		response.TaskID != state.taskID || response.LeaseEpoch.Int64() != state.leaseEpoch ||
		response.AttemptStatus != string(readtask.AttemptCompleted) || !uuidPattern.MatchString(response.ReceiptID) ||
		!hashPattern.MatchString(response.ReceiptHash) {
		return false
	}
	switch completion.Outcome {
	case readtask.CompletionEvidence:
		return response.TaskStatus == "EVIDENCE" && uuidPattern.MatchString(response.EvidenceID) &&
			hashPattern.MatchString(response.ContentHash)
	case readtask.CompletionFailed:
		return response.TaskStatus == "FAILED" && response.EvidenceID == "" && response.ContentHash == ""
	case readtask.CompletionCancelled:
		return response.TaskStatus == "CANCELLED" && response.EvidenceID == "" && response.ContentHash == ""
	default:
		return false
	}
}

func validFailureCode(code readtask.FailureCode) bool {
	switch code {
	case readtask.FailureConnectorUnavailable, readtask.FailureRateLimited, readtask.FailureTimeout,
		readtask.FailureAuthentication, readtask.FailurePermissionDenied, readtask.FailureInvalidResponse,
		readtask.FailureResultRejected, readtask.FailureCancelled, readtask.FailureUnknown:
		return true
	default:
		return false
	}
}

func validReleaseReason(reason readtask.ReleaseReason) bool {
	switch reason {
	case readtask.ReleaseLocalCapacityUnavailable, readtask.ReleaseConnectorNotReady,
		readtask.ReleaseTransientRunnerFailure:
		return true
	default:
		return false
	}
}

func validProtocolTime(value time.Time) bool {
	return !value.IsZero() && value.Year() >= 1 && value.Year() <= 9999 && value.Location() == time.UTC &&
		value.Equal(value.Truncate(time.Microsecond))
}

func stripMonotonic(value time.Time) time.Time { return value.Round(0).UTC() }

func jsonDocumentDepth(document []byte) int {
	var value any
	if json.Unmarshal(document, &value) != nil {
		return readtask.MaxEvidenceJSONDepth + 1
	}
	return jsonValueDepth(value, 1)
}

func jsonValueDepth(value any, depth int) int {
	maximum := depth
	switch typed := value.(type) {
	case map[string]any:
		for _, child := range typed {
			if childDepth := jsonValueDepth(child, depth+1); childDepth > maximum {
				maximum = childDepth
			}
		}
	case []any:
		for _, child := range typed {
			if childDepth := jsonValueDepth(child, depth+1); childDepth > maximum {
				maximum = childDepth
			}
		}
	}
	return maximum
}

func evidenceContainsReservedField(document []byte) bool {
	var value any
	return json.Unmarshal(document, &value) != nil || containsReservedEvidenceField(value)
}

func containsReservedEvidenceField(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for name, child := range typed {
			if readtask.EvidenceFieldReserved(name) {
				return true
			}
			if text, ok := child.(string); ok && readtask.EvidenceFieldValueReserved(name, text) {
				return true
			}
			if containsReservedEvidenceField(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsReservedEvidenceField(child) {
				return true
			}
		}
	}
	return false
}
