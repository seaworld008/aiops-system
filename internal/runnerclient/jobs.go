package runnerclient

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/seaworld008/aiops-system/internal/action"
	"github.com/seaworld008/aiops-system/internal/runnergateway"
	"github.com/seaworld008/aiops-system/internal/runneridentity"
)

const leaseResponseLimit = int64(256 << 10)

var (
	jobPathIDPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,255}$`)
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$`)
	hashPattern       = regexp.MustCompile(`^[a-f0-9]{64}$`)
	bearerPattern     = regexp.MustCompile(`^[A-Za-z0-9_-]{32,256}$`)
	uuidPattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

func (client *Client) LeaseJob(ctx context.Context) (*JobLease, error) {
	if client == nil || client.httpClient == nil || ctx == nil {
		return nil, ErrInvalidConfiguration
	}
	body, err := json.Marshal(runnergateway.JobLeaseRequest{SchemaVersion: "runner-job-lease-request.v1"})
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	request, err := client.newRequest(ctx, http.MethodPost, "/runner/v1/jobs:lease", body)
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
	var wire jobLeaseWire
	defer wire.LeaseToken.clear()
	if err := decodeJSONResponse(response, leaseResponseLimit, &wire); err != nil {
		return nil, err
	}
	if !client.validJobLease(wire, time.Now().UTC()) {
		return nil, ErrInvalidResponse
	}
	token := newBearer(wire.LeaseToken.take())
	descriptorJSON, err := json.Marshal(wire.Job)
	if err != nil {
		token.Destroy()
		return nil, ErrInvalidResponse
	}
	descriptorSHA256 := sha256.Sum256(descriptorJSON)
	clear(descriptorJSON)
	binding := &jobLeaseBinding{
		owner: client, token: token, jobID: wire.Job.ID, planHash: wire.Job.PlanHash,
		leaseEpoch: wire.LeaseEpoch.Int64(), scopeRevision: wire.ScopeRevision.Int64(),
		leaseExpiresAt: wire.LeaseExpiresAt.UTC(), payloadExpiresAt: wire.Job.Payload.ExpiresAt.UTC(),
		descriptorSHA256: descriptorSHA256, heartbeatAfterSeconds: wire.HeartbeatAfterSeconds,
		runtimeLeaseExpiresAt: wire.LeaseExpiresAt.UTC(), updates: make(chan struct{}, 1),
	}
	return &JobLease{
		Job: wire.Job, LeaseEpoch: wire.LeaseEpoch.Int64(), ScopeRevision: wire.ScopeRevision.Int64(),
		LeaseExpiresAt: wire.LeaseExpiresAt.UTC(), HeartbeatAfterSeconds: wire.HeartbeatAfterSeconds, binding: binding,
	}, nil
}

func (client *Client) validJobLease(response jobLeaseWire, now time.Time) bool {
	job := response.Job
	return client.expectedPool == runneridentity.PoolWrite && response.SchemaVersion == "runner-job-lease-response.v1" &&
		jobPathIDPattern.MatchString(job.ID) && job.Kind == "WRITE_ACTION" && !job.Production &&
		job.ID == job.Payload.ActionID && hashPattern.MatchString(job.PlanHash) && job.PlanHash == job.Payload.PlanHash &&
		identifierPattern.MatchString(job.EnvironmentRevision) && job.Payload.Signature != (action.Signature{}) &&
		job.Payload.ValidateAt(now) == nil && bearerPattern.Match(response.LeaseToken.value) &&
		response.LeaseEpoch.Int64() > 0 && response.ScopeRevision.Int64() > 0 && response.LeaseExpiresAt.After(now) &&
		!response.LeaseExpiresAt.After(job.Payload.ExpiresAt) && !response.LeaseExpiresAt.After(client.certificateNotAfter) &&
		response.HeartbeatAfterSeconds >= 1 && response.HeartbeatAfterSeconds <= 600
}

func validateEmptyResponse(response *http.Response) error {
	if response == nil || response.Body == nil || response.ProtoMajor != 1 || response.TLS == nil ||
		response.TLS.Version != tls.VersionTLS13 || len(response.Header.Values("Cache-Control")) != 1 ||
		response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Content-Type") != "" ||
		response.Header.Get("Content-Encoding") != "" || response.ContentLength > 0 ||
		len(response.Header.Values("X-Content-Type-Options")) != 1 || response.Header.Get("X-Content-Type-Options") != "nosniff" {
		return ErrInvalidResponse
	}
	body, err := readBoundedBodyAllowEmpty(response.Body, 1)
	if err != nil || len(body) != 0 {
		clear(body)
		return ErrInvalidResponse
	}
	return nil
}

func readBoundedBodyAllowEmpty(body io.Reader, limit int64) ([]byte, error) {
	// Keep the empty-response boundary separate from JSON responses: a 204 is
	// valid only when it carries no representation at all.
	if body == nil || limit <= 0 {
		return nil, ErrInvalidResponse
	}
	contents, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil || int64(len(contents)) > limit {
		clear(contents)
		return nil, ErrInvalidResponse
	}
	return contents, nil
}
