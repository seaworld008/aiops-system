package runnerclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/seaworld008/aiops-system/internal/credential"
	"github.com/seaworld008/aiops-system/internal/runnergateway"
	"github.com/seaworld008/aiops-system/internal/runneridentity"
)

func (client *Client) LeaseRevocation(ctx context.Context) (*RevocationLease, error) {
	if client == nil || client.httpClient == nil || client.expectedPool != runneridentity.PoolWrite || ctx == nil {
		return nil, ErrInvalidConfiguration
	}
	body, err := json.Marshal(runnergateway.RevocationLeaseRequest{SchemaVersion: "runner-revocation-lease-request.v1"})
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	request, err := client.newRequest(ctx, http.MethodPost, "/runner/v1/revocations:lease", body)
	clear(body)
	if err != nil {
		return nil, err
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
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
	var wire revocationLeaseWire
	defer wire.ClaimToken.clear()
	defer wire.RevokeAccessorB64U.clear()
	if err := decodeJSONResponse(response, leaseResponseLimit, &wire); err != nil {
		return nil, err
	}
	accessorBytes := make([]byte, base64.RawURLEncoding.DecodedLen(len(wire.RevokeAccessorB64U.value)))
	decoded, decodeErr := base64.RawURLEncoding.Decode(accessorBytes, wire.RevokeAccessorB64U.value)
	accessorBytes = accessorBytes[:decoded]
	if decodeErr != nil || !validRevocationLeaseResponse(wire, accessorBytes, time.Now().UTC(), client.certificateNotAfter) {
		clear(accessorBytes)
		return nil, ErrInvalidResponse
	}
	accessor, err := credential.NewSensitiveReference(accessorBytes)
	clear(accessorBytes)
	if err != nil {
		return nil, ErrInvalidResponse
	}
	token := newBearer(wire.ClaimToken.take())
	return &RevocationLease{state: &revocationLeaseState{
		owner: client, revocationID: wire.RevocationID, claimEpoch: wire.ClaimEpoch.Int64(),
		runtimeClaimExpiresAt: wire.ClaimExpiresAt.UTC(),
		heartbeatAfterSeconds: wire.HeartbeatAfterSeconds,
		tenantID:              wire.TenantID, workspaceID: wire.WorkspaceID, environmentID: wire.EnvironmentID,
		issuerID: wire.IssuerID, issuerRevision: wire.IssuerRevision, revokeAccessor: accessor, token: token,
	}}, nil
}

func validRevocationLeaseResponse(response revocationLeaseWire, accessor []byte, now, certificateNotAfter time.Time) bool {
	return response.SchemaVersion == "runner-revocation-lease-response.v1" && uuidPattern.MatchString(response.RevocationID) &&
		bearerPattern.Match(response.ClaimToken.value) && response.ClaimEpoch.Int64() > 0 && response.ClaimExpiresAt.After(now) &&
		!response.ClaimExpiresAt.After(certificateNotAfter) &&
		response.HeartbeatAfterSeconds == 10 && uuidPattern.MatchString(response.TenantID) &&
		uuidPattern.MatchString(response.WorkspaceID) && uuidPattern.MatchString(response.EnvironmentID) &&
		identifierPattern.MatchString(response.IssuerID) && identifierPattern.MatchString(response.IssuerRevision) &&
		len(accessor) >= 1 && len(accessor) <= 4096
}

func (client *Client) HeartbeatRevocation(
	ctx context.Context,
	lease *RevocationLease,
	sequence int64,
) (runnergateway.RevocationHeartbeatResponse, error) {
	if sequence <= 0 {
		return runnergateway.RevocationHeartbeatResponse{}, ErrInvalidResponse
	}
	var response runnergateway.RevocationHeartbeatResponse
	if err := client.revocationOperation(ctx, lease, ":heartbeat", runnergateway.RevocationHeartbeatRequest{
		SchemaVersion: "runner-revocation-heartbeat-request.v1", ClaimEpoch: runnergateway.DecimalInt64(revocationEpoch(lease)),
		Sequence: runnergateway.DecimalInt64(sequence),
	}, &response); err != nil {
		return runnergateway.RevocationHeartbeatResponse{}, err
	}
	if response.SchemaVersion != "runner-revocation-heartbeat-response.v1" || response.RevocationID != lease.RevocationID() ||
		response.AcceptedSequence.Int64() != sequence ||
		(response.Directive != "CONTINUE" && response.Directive != "TERMINATE") ||
		response.ClaimExpiresAt.IsZero() || response.ClaimExpiresAt.After(client.certificateNotAfter) || response.HeartbeatAfterSeconds != 10 {
		return runnergateway.RevocationHeartbeatResponse{}, ErrInvalidResponse
	}
	if !lease.state.updateHeartbeat(response.Directive, response.ClaimExpiresAt.UTC()) {
		return runnergateway.RevocationHeartbeatResponse{}, ErrInvalidResponse
	}
	return response, nil
}

func (state *revocationLeaseState) updateHeartbeat(directive string, expiresAt time.Time) bool {
	if state == nil || expiresAt.IsZero() {
		return false
	}
	state.runtimeMu.Lock()
	defer state.runtimeMu.Unlock()
	if state.terminationRequested {
		return directive == "TERMINATE"
	}
	switch directive {
	case "TERMINATE":
		state.terminationRequested = true
	case "CONTINUE":
		if !expiresAt.After(time.Now().UTC()) {
			return false
		}
		state.runtimeClaimExpiresAt = expiresAt
	default:
		return false
	}
	return true
}

func (client *Client) CompleteRevocation(
	ctx context.Context,
	lease *RevocationLease,
	outcome credential.RunnerRevocationOutcome,
	failureCode credential.FailureCode,
) (runnergateway.RevocationCompletionResponse, error) {
	if outcome == credential.RunnerRevocationRevoked && failureCode != "" ||
		outcome == credential.RunnerRevocationFailed && !credential.ValidFailureCode(failureCode) ||
		outcome != credential.RunnerRevocationRevoked && outcome != credential.RunnerRevocationFailed {
		return runnergateway.RevocationCompletionResponse{}, ErrInvalidResponse
	}
	var response runnergateway.RevocationCompletionResponse
	if err := client.revocationOperation(ctx, lease, ":complete", runnergateway.RevocationCompleteRequest{
		SchemaVersion: "runner-revocation-complete-request.v1", ClaimEpoch: runnergateway.DecimalInt64(revocationEpoch(lease)),
		Outcome: string(outcome), FailureCode: string(failureCode),
	}, &response); err != nil {
		return runnergateway.RevocationCompletionResponse{}, err
	}
	if response.SchemaVersion != "runner-revocation-completion-response.v1" || response.RevocationID != lease.RevocationID() ||
		response.ClaimEpoch.Int64() != lease.ClaimEpoch() || !validRevocationCompletionStatus(response, outcome) {
		return runnergateway.RevocationCompletionResponse{}, ErrInvalidResponse
	}
	lease.Destroy()
	return response, nil
}

func validRevocationCompletionStatus(
	response runnergateway.RevocationCompletionResponse,
	outcome credential.RunnerRevocationOutcome,
) bool {
	if outcome == credential.RunnerRevocationRevoked {
		return response.Status == "REVOKED" && response.AvailableAt == nil
	}
	if response.Status == "REVOCATION_PENDING" {
		return response.AvailableAt != nil && !response.AvailableAt.IsZero()
	}
	return response.Status == "MANUAL_REQUIRED" && response.AvailableAt == nil
}

func (client *Client) revocationOperation(
	ctx context.Context,
	lease *RevocationLease,
	suffix string,
	requestValue any,
	responseValue any,
) error {
	if !validRevocationOwner(client, lease) || ctx == nil || responseValue == nil {
		return ErrInvalidResponse
	}
	body, err := json.Marshal(requestValue)
	if err != nil || len(body) == 0 || int64(len(body)) > defaultResponseLimit {
		clear(body)
		return ErrInvalidResponse
	}
	request, err := client.newRequest(ctx, http.MethodPost, "/runner/v1/revocations/"+lease.RevocationID()+suffix, body)
	clear(body)
	if err != nil {
		return err
	}
	var response *http.Response
	err = lease.state.token.withValue(func(token []byte) error {
		request.Header.Set("Authorization", "AIOPS-Revocation-Lease "+string(token))
		var requestErr error
		response, requestErr = client.httpClient.Do(request)
		request.Header.Del("Authorization")
		if requestErr != nil {
			return boundedTransportError(requestErr)
		}
		return nil
	})
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return decodeProblem(response)
	}
	return decodeJSONResponse(response, defaultResponseLimit, responseValue)
}

func validRevocationOwner(client *Client, lease *RevocationLease) bool {
	return client != nil && client.httpClient != nil && client.expectedPool == runneridentity.PoolWrite &&
		lease != nil && lease.state != nil && lease.state.owner == client && lease.state.token != nil && lease.state.token.alive() &&
		uuidPattern.MatchString(lease.RevocationID()) && lease.ClaimEpoch() > 0 && lease.ClaimExpiresAt().After(time.Now().UTC()) &&
		lease.HeartbeatAfterSeconds() == 10 && uuidPattern.MatchString(lease.TenantID()) &&
		uuidPattern.MatchString(lease.WorkspaceID()) && uuidPattern.MatchString(lease.EnvironmentID()) &&
		identifierPattern.MatchString(lease.IssuerID()) && identifierPattern.MatchString(lease.IssuerRevision()) &&
		lease.state.revokeAccessor != nil
}

func revocationEpoch(lease *RevocationLease) int64 {
	if lease == nil {
		return 0
	}
	return lease.ClaimEpoch()
}
