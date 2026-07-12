package readrunnerclient

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/readtask"
)

type closeCanaryBody struct{ closes int }

func (*closeCanaryBody) Read([]byte) (int, error) { return 0, io.EOF }
func (body *closeCanaryBody) Close() error {
	body.closes++
	return nil
}

func TestErroredHTTPResponseCleanupClosesBodyAndDropsReference(t *testing.T) {
	body := &closeCanaryBody{}
	response := &http.Response{Body: body}
	closeErroredResponse(&response)
	if response != nil || body.closes != 1 {
		t.Fatalf("closeErroredResponse() response=%#v closes=%d", response, body.closes)
	}
	closeErroredResponse(&response)
	if body.closes != 1 {
		t.Fatalf("second cleanup closed body %d times", body.closes)
	}
}

func TestStartResponseAndCapabilityFailClosedAfterLocalLeaseExpiry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	client := &Client{certificateNotAfter: now.Add(time.Hour)}
	state := &leaseState{
		taskID: "70000000-0000-4000-8000-000000000007", leaseEpoch: 3, scopeRevision: 7,
		leaseExpiresAt: now.Add(-time.Microsecond), phase: leasePhaseRunning,
	}
	response := startResponseWire{
		SchemaVersion: "runner-read-task-start-response.v1", TaskID: state.taskID,
		AttemptStatus: string(readtask.AttemptRunning), LeaseEpoch: 3, ScopeRevision: 7,
		StartedAt: now.Add(-time.Second),
	}
	if validStartResponse(client, state, response, now) {
		t.Fatal("validStartResponse accepted a response after local lease expiry")
	}
	capability := &StartCapability{
		taskID: state.taskID, leaseEpoch: state.leaseEpoch, scopeRevision: state.scopeRevision,
		startedAt: response.StartedAt, lease: state, seal: trustedStartSeal,
	}
	capability.self = capability
	if capability.TaskID() != "" || capability.LeaseEpoch() != 0 || capability.ScopeRevision() != 0 ||
		!capability.StartedAt().IsZero() {
		t.Fatal("expired StartCapability retained usable accessors")
	}
	state.leaseExpiresAt = now.Add(minimumLeaseRemaining - time.Microsecond)
	response.StartedAt = now
	if validStartResponse(client, state, response, now) {
		t.Fatal("validStartResponse accepted a lease below the minimum usable window")
	}
	if capability.TaskID() != "" || capability.LeaseEpoch() != 0 || capability.ScopeRevision() != 0 ||
		!capability.StartedAt().IsZero() {
		t.Fatal("near-expiry StartCapability retained usable accessors")
	}
}

func TestProblemTypeHasA64KiBBoundaryIndependentLengthCap(t *testing.T) {
	wire := problemWire{
		Type: "urn:aiops:problem:runner:" + strings.Repeat("a", 257), Title: "Rejected",
		Status: 400, Code: "invalid_runner_request", Detail: "Rejected",
		Instance: "urn:aiops:request:123e4567-e89b-42d3-a456-426614174000",
	}
	if validProblemWire(wire, 400) {
		t.Fatal("validProblemWire accepted an oversized type")
	}
}

func TestOpaqueValuesStayRedactedWhenCallersDereferencePointers(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32))
	taskID := "70000000-0000-4000-8000-000000000007"
	client := &Client{
		baseURL:    url.URL{Scheme: "https", Host: "gateway-copy-canary.invalid:8443"},
		httpClient: &http.Client{}, runnerInstance: "runner-copy-canary",
		certificateSHA256: strings.Repeat("a", 64), certificateNotAfter: time.Now().UTC().Add(time.Hour),
	}
	state := &leaseState{
		owner: client, token: newBearer([]byte(token)), taskID: taskID, leaseEpoch: 3, scopeRevision: 7,
		leaseExpiresAt: time.Now().UTC().Add(maximumLeaseLifetime), phase: leasePhaseRunning,
	}
	lease := &Lease{state: state, seal: trustedLeaseSeal}
	lease.self = lease
	capability := &StartCapability{
		taskID: taskID, leaseEpoch: 3, scopeRevision: 7, startedAt: time.Now().UTC(),
		lease: state, seal: trustedStartSeal,
	}
	capability.self = capability
	problem := &ProblemError{
		Type: "urn:aiops:problem:runner:request-rejected", Status: http.StatusForbidden,
		Code: "runner_request_rejected", Instance: "urn:aiops:request:123e4567-e89b-42d3-a456-426614174000",
	}
	t.Cleanup(lease.Destroy)

	for name, value := range map[string]any{
		"client": *client, "lease": *lease, "start capability": *capability, "problem": *problem,
	} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("json.Marshal(%s) error = %v", name, err)
		}
		rendered := fmt.Sprintf("%s|%v|%+v|%#v|%s", encoded, value, value, value, value)
		for _, forbidden := range []string{
			token, fmt.Sprint([]byte(token)), taskID, "gateway-copy-canary", "runner-copy-canary", strings.Repeat("a", 64),
		} {
			if strings.Contains(rendered, forbidden) {
				t.Fatalf("dereferenced %s rendering leaked %q: %s", name, forbidden, rendered)
			}
		}
	}
}

func TestTrustFileFIFOIsRejectedWithoutBlockingStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client-key.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		opened, err := openTrustFile(path, true)
		if opened != nil && opened.file != nil {
			_ = opened.file.Close()
		}
		result <- err
	}()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("openTrustFile accepted a FIFO")
		}
	case <-time.After(time.Second):
		t.Fatal("openTrustFile blocked on a FIFO")
	}
}
