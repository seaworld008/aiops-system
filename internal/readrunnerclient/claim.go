package readrunnerclient

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/seaworld008/aiops-system/internal/readtask"
)

// Claim requests one exact scheduler-owned task. A 204 response means the
// task is not currently claimable and returns (nil, nil).
func (client *Client) Claim(ctx context.Context, expected ExpectedTask) (*Lease, error) {
	if !client.Ready() {
		return nil, ErrInvalidConfiguration
	}
	if !validContext(ctx) || !validExpectedTask(expected) {
		return nil, ErrInvalidExpectedTask
	}
	body, err := json.Marshal(claimRequestWire{SchemaVersion: "runner-read-task-claim-request.v1"})
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	request, err := client.newRequest(ctx, http.MethodPost, "/runner/v1/read-tasks/"+expected.TaskID+":claim", body)
	clear(body)
	if err != nil {
		return nil, err
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		closeErroredResponse(&response)
		return nil, boundedTransportError(err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNoContent {
		if err := validateEmptyResponse(response); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if response.StatusCode != http.StatusOK {
		return nil, decodeProblem(response)
	}
	var wire claimResponseWire
	defer wire.LeaseToken.clear()
	if err := decodeJSONResponse(response, claimResponseLimit, &wire); err != nil {
		return nil, err
	}
	descriptor, err := descriptorFromClaim(expected, wire.Task)
	if err != nil || !validClaimResponse(client, expected, descriptor, wire, time.Now().UTC()) {
		return nil, ErrInvalidResponse
	}
	token := newBearer(wire.LeaseToken.take())
	state := &leaseState{
		owner: client, token: token, descriptor: descriptor, taskID: descriptor.TaskID,
		leaseEpoch: wire.LeaseEpoch.Int64(), scopeRevision: wire.ScopeRevision.Int64(),
		leaseExpiresAt: wire.LeaseExpiresAt.UTC(), heartbeatAfterSeconds: wire.HeartbeatAfterSeconds,
		phase: leasePhaseClaimed,
	}
	lease := &Lease{state: state, seal: trustedLeaseSeal}
	lease.self = lease
	return lease, nil
}

func validExpectedTask(expected ExpectedTask) bool {
	for _, identifier := range []string{
		expected.TenantID, expected.WorkspaceID, expected.EnvironmentID, expected.ServiceID,
		expected.IncidentID, expected.InvestigationID, expected.TaskID,
	} {
		if !uuidPattern.MatchString(identifier) {
			return false
		}
	}
	return expected.Position >= 1 && expected.Position <= 12 && expected.PlanBinding.Validate() == nil
}

func descriptorFromClaim(expected ExpectedTask, wire taskDescriptorWire) (readtask.Descriptor, error) {
	if wire.ID != expected.TaskID || wire.Position != expected.Position ||
		!wire.PlanBinding.Equal(expected.PlanBinding) {
		return readtask.Descriptor{}, ErrInvalidResponse
	}
	descriptor := readtask.Descriptor{
		TenantID: expected.TenantID, WorkspaceID: expected.WorkspaceID,
		EnvironmentID: expected.EnvironmentID, ServiceID: expected.ServiceID,
		IncidentID: expected.IncidentID, InvestigationID: expected.InvestigationID,
		TaskID: wire.ID, TaskKey: wire.Key, Position: wire.Position, ConnectorID: wire.ConnectorID,
		Operation: wire.Operation, Input: append(json.RawMessage(nil), wire.Input...), InputHash: wire.InputHash,
		PlanBinding: wire.PlanBinding, RuntimeBinding: wire.RuntimeBinding,
	}
	if descriptor.Validate() != nil {
		return readtask.Descriptor{}, ErrInvalidResponse
	}
	return descriptor, nil
}

func validClaimResponse(
	client *Client,
	expected ExpectedTask,
	descriptor readtask.Descriptor,
	response claimResponseWire,
	now time.Time,
) bool {
	return client != nil && validExpectedTask(expected) && descriptor.Validate() == nil &&
		response.SchemaVersion == "runner-read-task-claim-response.v2" && response.Task.ID == expected.TaskID &&
		response.Task.Position == expected.Position && response.Task.PlanBinding.Equal(expected.PlanBinding) &&
		validLeaseToken(response.LeaseToken.value) && response.LeaseEpoch.Int64() > 0 &&
		response.ScopeRevision.Int64() > 0 && !response.LeaseExpiresAt.Before(now.Add(minimumLeaseRemaining)) &&
		!response.LeaseExpiresAt.After(now.Add(maximumLeaseLifetime+protocolClockSkew)) &&
		!response.LeaseExpiresAt.After(client.certificateNotAfter) && response.LeaseExpiresAt.Location() == time.UTC &&
		response.HeartbeatAfterSeconds == 10
}
