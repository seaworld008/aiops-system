package runnerclient

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"time"

	"github.com/seaworld008/aiops-system/internal/credential"
	"github.com/seaworld008/aiops-system/internal/execution"
	"github.com/seaworld008/aiops-system/internal/runnergateway"
)

func (client *Client) StartJob(ctx context.Context, lease *JobLease) (JobStart, error) {
	var response jobStartWire
	defer response.CredentialPrepare.ChildCreatePermit.clear()
	err := client.jobOperation(ctx, lease, ":start", runnergateway.JobStartRequest{
		SchemaVersion: "runner-job-start-request.v1", LeaseEpoch: runnergateway.DecimalInt64(leaseEpoch(lease)),
	}, []int{http.StatusOK}, &response)
	if err != nil {
		return JobStart{}, err
	}
	binding := lease.binding
	if response.SchemaVersion != "runner-job-start-response.v1" || response.JobID != binding.jobID ||
		response.Status != "RUNNING" || response.LeaseEpoch.Int64() != binding.leaseEpoch ||
		response.ScopeRevision.Int64() != binding.scopeRevision || response.StartedAt.IsZero() ||
		!bearerPattern.Match(response.CredentialPrepare.ChildCreatePermit.value) ||
		!uuidPattern.MatchString(response.CredentialPrepare.RevocationID) ||
		!identifierPattern.MatchString(response.CredentialPrepare.IssuerID) ||
		!identifierPattern.MatchString(response.CredentialPrepare.IssuerRevision) ||
		!response.CredentialPrepare.CredentialExpiresAt.After(time.Now().UTC()) ||
		response.CredentialPrepare.CredentialExpiresAt.After(binding.payloadExpiresAt) ||
		response.CredentialPrepare.CredentialExpiresAt.After(client.certificateNotAfter) {
		return JobStart{}, ErrInvalidResponse
	}
	permit := newBearer(response.CredentialPrepare.ChildCreatePermit.take())
	preparation := &CredentialPreparation{
		state: &credentialPreparationState{
			lease: binding, revocationID: response.CredentialPrepare.RevocationID,
			issuerID: response.CredentialPrepare.IssuerID, issuerRevision: response.CredentialPrepare.IssuerRevision,
			credentialExpiresAt: response.CredentialPrepare.CredentialExpiresAt.UTC(), phase: credentialPhasePrepared,
		},
		permit: permit,
	}
	return JobStart{
		JobID: response.JobID, Status: response.Status, LeaseEpoch: response.LeaseEpoch.Int64(),
		ScopeRevision: response.ScopeRevision.Int64(), StartedAt: response.StartedAt.UTC(), Credential: preparation,
		Grant: &ExecutionGrant{state: preparation.state},
	}, nil
}

func (client *Client) AuthorizeChildCreate(
	ctx context.Context,
	lease *JobLease,
	preparation *CredentialPreparation,
) (runnergateway.CredentialAnchorResponse, error) {
	if !validCredentialPreparation(client, lease, preparation) || !preparation.permit.alive() {
		return runnergateway.CredentialAnchorResponse{}, ErrInvalidResponse
	}
	permit, err := preparation.permit.take()
	if err != nil {
		return runnergateway.CredentialAnchorResponse{}, err
	}
	defer clear(permit)
	body, err := encodeSensitiveCredentialRequest(
		"AUTHORIZE_CHILD_CREATE", leaseEpoch(lease), preparation.RevocationID(), permit,
	)
	if err != nil {
		return runnergateway.CredentialAnchorResponse{}, err
	}
	defer clear(body)
	response, err := client.credentialOperationBody(ctx, lease, preparation.RevocationID(), body, "PREPARED")
	if err != nil {
		return runnergateway.CredentialAnchorResponse{}, err
	}
	now := time.Now().UTC()
	if response.DatabaseAuthorizedAt == nil || response.DatabaseAuthorizedAt.IsZero() ||
		response.ChildTTLSeconds < 1 || response.ChildTTLSeconds > 900 || response.CredentialExpiresAt == nil ||
		!response.CredentialExpiresAt.Equal(preparation.CredentialExpiresAt()) ||
		response.DatabaseAuthorizedAt.Before(now.Add(-requestTimeout)) || response.DatabaseAuthorizedAt.After(now.Add(time.Second)) ||
		response.DatabaseAuthorizedAt.Add(time.Duration(response.ChildTTLSeconds)*time.Second).After(*response.CredentialExpiresAt) {
		return runnergateway.CredentialAnchorResponse{}, ErrInvalidResponse
	}
	if !preparation.state.transition([]credentialPhase{credentialPhasePrepared}, credentialPhaseAuthorized) {
		return runnergateway.CredentialAnchorResponse{}, ErrInvalidResponse
	}
	return response, nil
}

func (client *Client) RecordCredentialAnchor(
	ctx context.Context,
	lease *JobLease,
	preparation *CredentialPreparation,
	accessor *credential.SensitiveReference,
) (runnergateway.CredentialAnchorResponse, error) {
	if !validCredentialPreparation(client, lease, preparation) ||
		preparation.state.currentPhase() != credentialPhaseAuthorized || accessor == nil {
		return runnergateway.CredentialAnchorResponse{}, ErrInvalidResponse
	}
	value := accessor.Bytes()
	if len(value) == 0 || len(value) > 4096 {
		clear(value)
		return runnergateway.CredentialAnchorResponse{}, ErrInvalidResponse
	}
	encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(value)))
	base64.RawURLEncoding.Encode(encoded, value)
	clear(value)
	body, err := encodeSensitiveCredentialRequest("RECORD_ANCHOR", leaseEpoch(lease), preparation.RevocationID(), encoded)
	clear(encoded)
	if err != nil {
		return runnergateway.CredentialAnchorResponse{}, err
	}
	defer clear(body)
	response, err := client.credentialOperationBody(ctx, lease, preparation.RevocationID(), body, "ANCHORED")
	if err == nil && !preparation.state.transition([]credentialPhase{credentialPhaseAuthorized}, credentialPhaseAnchored) {
		return runnergateway.CredentialAnchorResponse{}, ErrInvalidResponse
	}
	return response, err
}

func (client *Client) ActivateCredential(
	ctx context.Context,
	lease *JobLease,
	preparation *CredentialPreparation,
) (runnergateway.CredentialAnchorResponse, error) {
	if !validCredentialPreparation(client, lease, preparation) || preparation.state.currentPhase() != credentialPhaseAnchored {
		return runnergateway.CredentialAnchorResponse{}, ErrInvalidResponse
	}
	response, err := client.simpleCredentialTransition(ctx, lease, preparation, "ACTIVATE", "ACTIVE")
	if err == nil && !preparation.state.transition([]credentialPhase{credentialPhaseAnchored}, credentialPhaseActive) {
		return runnergateway.CredentialAnchorResponse{}, ErrInvalidResponse
	}
	return response, err
}

func (client *Client) RecordNoCredential(
	ctx context.Context,
	lease *JobLease,
	preparation *CredentialPreparation,
) (runnergateway.CredentialAnchorResponse, error) {
	if !validCredentialPreparation(client, lease, preparation) || preparation.state.currentPhase() != credentialPhasePrepared {
		return runnergateway.CredentialAnchorResponse{}, ErrInvalidResponse
	}
	response, err := client.simpleCredentialTransition(ctx, lease, preparation, "NO_CREDENTIAL", "NO_CREDENTIAL")
	if err == nil && !preparation.state.transition(
		[]credentialPhase{credentialPhasePrepared}, credentialPhaseNoCredential,
	) {
		return runnergateway.CredentialAnchorResponse{}, ErrInvalidResponse
	}
	return response, err
}

func (client *Client) RequestCredentialRevocation(
	ctx context.Context,
	lease *JobLease,
	preparation *CredentialPreparation,
) (runnergateway.CredentialAnchorResponse, error) {
	if !validCredentialPreparation(client, lease, preparation) {
		return runnergateway.CredentialAnchorResponse{}, ErrInvalidResponse
	}
	switch preparation.state.currentPhase() {
	case credentialPhaseAuthorized, credentialPhaseAnchored, credentialPhaseActive:
	default:
		return runnergateway.CredentialAnchorResponse{}, ErrInvalidResponse
	}
	request := runnergateway.CredentialAnchorRequest{
		SchemaVersion: "runner-credential-anchor-request.v1", Phase: "REQUEST_REVOCATION",
		LeaseEpoch: runnergateway.DecimalInt64(leaseEpoch(lease)), RevocationID: preparation.RevocationID(),
	}
	var response runnergateway.CredentialAnchorResponse
	if err := client.jobOperation(ctx, lease, ":credential-anchor", request, []int{http.StatusOK}, &response); err != nil {
		return runnergateway.CredentialAnchorResponse{}, err
	}
	if !validCredentialResponse(response, lease, preparation.RevocationID()) || !slices.Contains(
		[]string{"REVOCATION_PENDING", "REVOKING", "REVOKED", "MANUAL_REQUIRED"}, response.Status,
	) {
		return runnergateway.CredentialAnchorResponse{}, ErrInvalidResponse
	}
	if !preparation.state.transition(
		[]credentialPhase{credentialPhaseAuthorized, credentialPhaseAnchored, credentialPhaseActive},
		credentialPhaseRevocationRequested,
	) {
		return runnergateway.CredentialAnchorResponse{}, ErrInvalidResponse
	}
	preparation.state.lease.terminate()
	return response, nil
}

func (client *Client) simpleCredentialTransition(
	ctx context.Context,
	lease *JobLease,
	preparation *CredentialPreparation,
	phase, status string,
) (runnergateway.CredentialAnchorResponse, error) {
	if !validCredentialPreparation(client, lease, preparation) {
		return runnergateway.CredentialAnchorResponse{}, ErrInvalidResponse
	}
	return client.credentialOperation(ctx, lease, runnergateway.CredentialAnchorRequest{
		SchemaVersion: "runner-credential-anchor-request.v1", Phase: phase,
		LeaseEpoch: runnergateway.DecimalInt64(leaseEpoch(lease)), RevocationID: preparation.RevocationID(),
	}, status)
}

func (client *Client) credentialOperation(
	ctx context.Context,
	lease *JobLease,
	request runnergateway.CredentialAnchorRequest,
	expectedStatus string,
) (runnergateway.CredentialAnchorResponse, error) {
	body, err := json.Marshal(request)
	if err != nil {
		clear(body)
		return runnergateway.CredentialAnchorResponse{}, ErrInvalidResponse
	}
	defer clear(body)
	return client.credentialOperationBody(ctx, lease, request.RevocationID, body, expectedStatus)
}

func (client *Client) credentialOperationBody(
	ctx context.Context,
	lease *JobLease,
	revocationID string,
	body []byte,
	expectedStatus string,
) (runnergateway.CredentialAnchorResponse, error) {
	var response runnergateway.CredentialAnchorResponse
	if err := client.jobOperationBody(ctx, lease, ":credential-anchor", body, []int{http.StatusOK}, &response); err != nil {
		return runnergateway.CredentialAnchorResponse{}, err
	}
	if !validCredentialResponse(response, lease, revocationID) || response.Status != expectedStatus {
		return runnergateway.CredentialAnchorResponse{}, ErrInvalidResponse
	}
	if expectedStatus != "PREPARED" && (response.DatabaseAuthorizedAt != nil || response.ChildTTLSeconds != 0 || response.CredentialExpiresAt != nil) {
		return runnergateway.CredentialAnchorResponse{}, ErrInvalidResponse
	}
	return response, nil
}

func validCredentialResponse(response runnergateway.CredentialAnchorResponse, lease *JobLease, revocationID string) bool {
	return response.SchemaVersion == "runner-credential-anchor-response.v1" && lease != nil &&
		response.JobID == leaseJobID(lease) && response.RevocationID == revocationID && uuidPattern.MatchString(revocationID)
}

func validCredentialPreparation(client *Client, lease *JobLease, preparation *CredentialPreparation) bool {
	return validLeaseOwner(client, lease) && preparation != nil && preparation.state != nil &&
		preparation.state.lease == lease.binding && uuidPattern.MatchString(preparation.RevocationID()) &&
		identifierPattern.MatchString(preparation.IssuerID()) && identifierPattern.MatchString(preparation.IssuerRevision()) &&
		!preparation.CredentialExpiresAt().IsZero() && preparation.permit != nil
}

func (client *Client) HeartbeatJob(
	ctx context.Context,
	lease *JobLease,
	sequence int64,
) (runnergateway.JobHeartbeatResponse, error) {
	if sequence <= 0 {
		return runnergateway.JobHeartbeatResponse{}, ErrInvalidResponse
	}
	var response runnergateway.JobHeartbeatResponse
	if err := client.jobOperation(ctx, lease, ":heartbeat", runnergateway.JobHeartbeatRequest{
		SchemaVersion: "runner-job-heartbeat-request.v1", LeaseEpoch: runnergateway.DecimalInt64(leaseEpoch(lease)),
		Sequence: runnergateway.DecimalInt64(sequence),
	}, []int{http.StatusOK}, &response); err != nil {
		return runnergateway.JobHeartbeatResponse{}, err
	}
	if response.SchemaVersion != "runner-job-heartbeat-response.v1" || response.JobID != leaseJobID(lease) ||
		response.AcceptedSequence.Int64() != sequence ||
		(response.Directive != "CONTINUE" && response.Directive != "TERMINATE") || response.LeaseExpiresAt.IsZero() ||
		response.LeaseExpiresAt.After(client.certificateNotAfter) || response.LeaseExpiresAt.After(lease.binding.payloadExpiresAt) ||
		response.HeartbeatAfterSeconds < 1 || response.HeartbeatAfterSeconds > 600 {
		return runnergateway.JobHeartbeatResponse{}, ErrInvalidResponse
	}
	if !lease.binding.updateHeartbeat(response.Directive, response.LeaseExpiresAt.UTC()) {
		return runnergateway.JobHeartbeatResponse{}, ErrInvalidResponse
	}
	return response, nil
}

func (client *Client) ReleaseJob(
	ctx context.Context,
	lease *JobLease,
	reason JobReleaseReason,
) (runnergateway.JobStateResponse, error) {
	if reason != ReleaseExecutorNotReady && reason != ReleaseLocalCapacityUnavailable && reason != ReleaseTransientRunnerFailure {
		return runnergateway.JobStateResponse{}, ErrInvalidResponse
	}
	var response runnergateway.JobStateResponse
	if err := client.jobOperation(ctx, lease, ":release", runnergateway.JobReleaseRequest{
		SchemaVersion: "runner-job-release-request.v1", LeaseEpoch: runnergateway.DecimalInt64(leaseEpoch(lease)),
		ReasonCode: string(reason),
	}, []int{http.StatusOK}, &response); err != nil {
		return runnergateway.JobStateResponse{}, err
	}
	if response.SchemaVersion != "runner-job-state-response.v1" || response.JobID != leaseJobID(lease) ||
		response.Status != "QUEUED" || response.LeaseEpoch.Int64() != leaseEpoch(lease) {
		return runnergateway.JobStateResponse{}, ErrInvalidResponse
	}
	lease.Destroy()
	return response, nil
}

func (client *Client) CompleteJob(
	ctx context.Context,
	lease *JobLease,
	result execution.ExecutorResult,
) (runnergateway.JobCompletionResponse, error) {
	if _, err := execution.ResultSummaryStatus(result); err != nil {
		return runnergateway.JobCompletionResponse{}, ErrInvalidResponse
	}
	var response runnergateway.JobCompletionResponse
	if err := client.jobOperation(ctx, lease, ":complete", runnergateway.JobCompleteRequest{
		SchemaVersion: "runner-job-complete-request.v1", LeaseEpoch: runnergateway.DecimalInt64(leaseEpoch(lease)), Result: result,
	}, []int{http.StatusOK, http.StatusAccepted}, &response); err != nil {
		return runnergateway.JobCompletionResponse{}, err
	}
	if !validCompletionResponse(response, lease, result) {
		return runnergateway.JobCompletionResponse{}, ErrInvalidResponse
	}
	lease.Destroy()
	return response, nil
}

func validCompletionResponse(
	response runnergateway.JobCompletionResponse,
	lease *JobLease,
	result execution.ExecutorResult,
) bool {
	if response.SchemaVersion != "runner-job-completion-response.v1" || lease == nil || response.JobID != leaseJobID(lease) ||
		!hashPattern.MatchString(response.ReceiptHash) || response.CompletionStatus != string(result.Outcome) {
		return false
	}
	if response.Status != "FINALIZING" && response.Status != response.CompletionStatus {
		return false
	}
	return slices.Contains([]string{"NOT_REQUIRED", "PENDING", "TERMINAL", "MANUAL_REQUIRED"}, response.CredentialCleanupStatus)
}

func (client *Client) jobOperation(
	ctx context.Context,
	lease *JobLease,
	suffix string,
	requestValue any,
	allowedStatuses []int,
	responseValue any,
) error {
	if lease != nil && lease.binding != nil && lease.binding.owner == client && lease.binding.token != nil &&
		!lease.binding.token.alive() {
		return ErrSensitiveDestroyed
	}
	if !validLeaseOwner(client, lease) || ctx == nil || responseValue == nil {
		return ErrInvalidResponse
	}
	body, err := json.Marshal(requestValue)
	if err != nil || len(body) == 0 || int64(len(body)) > defaultResponseLimit {
		clear(body)
		return ErrInvalidResponse
	}
	defer clear(body)
	return client.jobOperationBody(ctx, lease, suffix, body, allowedStatuses, responseValue)
}

func (client *Client) jobOperationBody(
	ctx context.Context,
	lease *JobLease,
	suffix string,
	body []byte,
	allowedStatuses []int,
	responseValue any,
) error {
	if !validLeaseOwner(client, lease) || ctx == nil || responseValue == nil || len(body) == 0 || int64(len(body)) > defaultResponseLimit {
		return ErrInvalidResponse
	}
	request, err := client.newRequest(ctx, http.MethodPost, "/runner/v1/jobs/"+leaseJobID(lease)+suffix, body)
	if err != nil {
		return err
	}
	var response *http.Response
	err = lease.binding.token.withValue(func(token []byte) error {
		authorization := "AIOPS-Job-Lease " + string(token)
		request.Header.Set("Authorization", authorization)
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
	if !slices.Contains(allowedStatuses, response.StatusCode) {
		return decodeProblem(response)
	}
	return decodeJSONResponse(response, defaultResponseLimit, responseValue)
}

func validLeaseOwner(client *Client, lease *JobLease) bool {
	if client == nil || client.httpClient == nil || lease == nil || lease.binding == nil || lease.binding.owner != client ||
		lease.binding.token == nil || !lease.binding.token.alive() || !jobPathIDPattern.MatchString(lease.binding.jobID) ||
		lease.binding.leaseEpoch <= 0 || lease.binding.scopeRevision <= 0 || lease.Job.ID != lease.binding.jobID ||
		lease.Job.PlanHash != lease.binding.planHash || lease.LeaseEpoch != lease.binding.leaseEpoch ||
		lease.ScopeRevision != lease.binding.scopeRevision || !lease.LeaseExpiresAt.Equal(lease.binding.leaseExpiresAt) ||
		lease.HeartbeatAfterSeconds != lease.binding.heartbeatAfterSeconds {
		return false
	}
	descriptorJSON, err := json.Marshal(lease.Job)
	if err != nil {
		return false
	}
	digest := sha256.Sum256(descriptorJSON)
	clear(descriptorJSON)
	return digest == lease.binding.descriptorSHA256
}

func leaseEpoch(lease *JobLease) int64 {
	if lease == nil {
		return 0
	}
	if lease.binding == nil {
		return 0
	}
	return lease.binding.leaseEpoch
}

func leaseJobID(lease *JobLease) string {
	if lease == nil {
		return ""
	}
	if lease.binding == nil {
		return ""
	}
	return lease.binding.jobID
}
