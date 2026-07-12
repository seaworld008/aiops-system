package readrunnerclient_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/readrunnerclient"
	"github.com/seaworld008/aiops-system/internal/readtask"
	"github.com/seaworld008/aiops-system/internal/runneridentity"
	"github.com/seaworld008/aiops-system/internal/runneridentity/testpki"
)

const (
	fixtureRunnerInstance = "runner-read-01"
	requestTimeoutForTest = 30 * time.Second
)

func TestClientRejectsWriteCNFallbackAndAmbiguousReadCertificateSANs(t *testing.T) {
	readURI, _ := url.Parse("spiffe://aiops.test/runner/read/replacement-read-runner")
	writeURI, _ := url.Parse("spiffe://aiops.test/runner/write/replacement-write-runner")
	otherReadURI, _ := url.Parse("spiffe://aiops.test/runner/read/second-read-runner")
	for name, options := range map[string]testpki.ClientOptions{
		"write SAN":             {URIs: []*url.URL{writeURI}},
		"CN fallback":           {CommonName: "spiffe://aiops.test/runner/read/cn-only-runner"},
		"multiple URI SANs":     {URIs: []*url.URL{readURI, otherReadURI}},
		"DNS SAN alongside URI": {URIs: []*url.URL{readURI}, DNSNames: []string{"runner.invalid"}},
		"server auth EKU":       {URIs: []*url.URL{readURI}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newGatewayFixture(t, runneridentity.PoolRead, func(http.ResponseWriter, *http.Request) {})
			replaceFixtureClientCertificate(t, fixture, options)
			client, err := readrunnerclient.New(fixture.options)
			if client != nil || !errors.Is(err, readrunnerclient.ErrInvalidConfiguration) {
				t.Fatalf("New(%s) = %#v, %v; want invalid configuration", name, client, err)
			}
		})
	}
}

func TestClientRejectsCertificateWithoutEnoughLifetimeForANewClaim(t *testing.T) {
	readURI, err := url.Parse("spiffe://aiops.test/runner/read/replacement-read-runner")
	if err != nil {
		t.Fatal(err)
	}
	fixture := newGatewayFixture(t, runneridentity.PoolRead, func(http.ResponseWriter, *http.Request) {})
	replaceFixtureClientCertificate(t, fixture, testpki.ClientOptions{
		URIs: []*url.URL{readURI}, NotAfter: time.Now().UTC().Add(requestTimeoutForTest),
	})
	client, err := readrunnerclient.New(fixture.options)
	if client != nil || !errors.Is(err, readrunnerclient.ErrInvalidConfiguration) {
		t.Fatalf("New(short-lived certificate) = %#v, %v; want invalid configuration", client, err)
	}
}

func TestClientRejectsUnsafeEndpointAndTrustFileConfigurations(t *testing.T) {
	for name, mutate := range map[string]func(*testing.T, *gatewayFixture){
		"HTTP base URL": func(_ *testing.T, fixture *gatewayFixture) {
			fixture.options.BaseURL = strings.Replace(fixture.options.BaseURL, "https://", "http://", 1)
		},
		"base URL query": func(_ *testing.T, fixture *gatewayFixture) { fixture.options.BaseURL += "?scope=forged" },
		"base URL path":  func(_ *testing.T, fixture *gatewayFixture) { fixture.options.BaseURL += "/runner" },
		"base URL userinfo": func(_ *testing.T, fixture *gatewayFixture) {
			fixture.options.BaseURL = strings.Replace(fixture.options.BaseURL, "https://", "https://user@", 1)
		},
		"wildcard server name": func(_ *testing.T, fixture *gatewayFixture) { fixture.options.ServerName = "*.test" },
		"uppercase trust domain": func(_ *testing.T, fixture *gatewayFixture) {
			fixture.options.TrustDomain = "AIOPS.test"
		},
		"duplicate trust paths": func(_ *testing.T, fixture *gatewayFixture) {
			fixture.options.ClientCertificateFile = fixture.options.RootCAFile
		},
		"group readable private key": func(t *testing.T, fixture *gatewayFixture) {
			if err := os.Chmod(fixture.options.ClientPrivateKeyFile, 0o640); err != nil {
				t.Fatal(err)
			}
		},
		"group writable certificate": func(t *testing.T, fixture *gatewayFixture) {
			if err := os.Chmod(fixture.options.ClientCertificateFile, 0o620); err != nil {
				t.Fatal(err)
			}
		},
		"symlink trust root": func(t *testing.T, fixture *gatewayFixture) {
			link := filepath.Join(t.TempDir(), "root-link.pem")
			if err := os.Symlink(fixture.options.RootCAFile, link); err != nil {
				t.Fatal(err)
			}
			fixture.options.RootCAFile = link
		},
		"hard linked certificate": func(t *testing.T, fixture *gatewayFixture) {
			link := filepath.Join(t.TempDir(), "chain-hardlink.pem")
			if err := os.Link(fixture.options.ClientCertificateFile, link); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newGatewayFixture(t, runneridentity.PoolRead, func(http.ResponseWriter, *http.Request) {})
			mutate(t, fixture)
			client, err := readrunnerclient.New(fixture.options)
			if client != nil || !errors.Is(err, readrunnerclient.ErrInvalidConfiguration) {
				t.Fatalf("New(%s) = %#v, %v", name, client, err)
			}
		})
	}
}

func TestClaimAcceptsOnlyTheExactTrustedTaskOverStrictReadMTLS(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	expected, descriptor := validExpectedTaskAndDescriptor(t, now)
	leaseToken := base64.RawURLEncoding.EncodeToString(bytesOf(0x5a, 32))
	var fixture *gatewayFixture
	fixture = newGatewayFixture(t, runneridentity.PoolRead, func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/runner/v1/read-tasks/"+expected.TaskID+":claim" ||
			request.URL.RawQuery != "" {
			t.Fatalf("request = %s %s", request.Method, request.URL.String())
		}
		if request.ProtoMajor != 1 || request.TLS == nil || request.TLS.Version != tls.VersionTLS13 {
			t.Fatalf("transport = %s TLS=%#v", request.Proto, request.TLS)
		}
		if request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" ||
			request.Header.Get("Idempotency-Key") != "" {
			t.Fatalf("claim headers contained forbidden identity material: %#v", request.Header)
		}
		var body map[string]string
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil || len(body) != 1 ||
			body["schema_version"] != "runner-read-task-claim-request.v1" {
			t.Fatalf("claim body = %#v, %v", body, err)
		}
		writeJSON(t, writer, http.StatusOK, claimResponse(
			descriptor, leaseToken, 3, 7, now.Add(30*time.Second),
		))
	})

	client, err := readrunnerclient.New(fixture.options)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(client.CloseIdleConnections)
	lease, err := client.Claim(context.Background(), expected)
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if lease == nil || lease.TaskID() != expected.TaskID || lease.LeaseEpoch() != 3 ||
		lease.ScopeRevision() != 7 || lease.HeartbeatAfterSeconds() != 10 {
		t.Fatalf("Claim() = %#v", lease)
	}
	got := lease.Descriptor()
	if got.Validate() != nil || got.TenantID != expected.TenantID || got.WorkspaceID != expected.WorkspaceID ||
		got.EnvironmentID != expected.EnvironmentID || got.ServiceID != expected.ServiceID ||
		got.IncidentID != expected.IncidentID || got.InvestigationID != expected.InvestigationID ||
		!got.PlanBinding.Equal(expected.PlanBinding) || !got.RuntimeBinding.Equal(descriptor.RuntimeBinding) {
		t.Fatalf("lease descriptor = %#v", got)
	}
	encoded, marshalErr := json.Marshal(lease)
	if marshalErr != nil {
		t.Fatalf("Marshal(lease) error = %v", marshalErr)
	}
	for _, rendered := range []string{string(encoded), fmt.Sprint(lease), fmt.Sprintf("%#v", lease), fmt.Sprintf("%+v", client)} {
		if strings.Contains(rendered, leaseToken) {
			t.Fatalf("rendering leaked lease token: %s", rendered)
		}
	}
	lease.Destroy()
}

func TestClientRunsExactStartHeartbeatAndCompletionWithOpaqueCapabilities(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	expected, descriptor := validExpectedTaskAndDescriptor(t, now)
	leaseToken := base64.RawURLEncoding.EncodeToString(bytesOf(0x42, 32))
	evidenceID := "80000000-0000-4000-8000-000000000008"
	receiptID := "90000000-0000-4000-8000-000000000009"
	step := 0
	fixture := newGatewayFixture(t, runneridentity.PoolRead, func(writer http.ResponseWriter, request *http.Request) {
		step++
		if step == 1 {
			writeJSON(t, writer, http.StatusOK, claimResponse(descriptor, leaseToken, 3, 7, now.Add(30*time.Second)))
			return
		}
		if request.Header.Get("Authorization") != "AIOPS-Read-Task-Lease "+leaseToken {
			t.Fatalf("step %d did not use the private lease bearer", step)
		}
		if strings.Contains(request.URL.String(), leaseToken) {
			t.Fatalf("step %d URL leaked token", step)
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatalf("step %d decode request: %v", step, err)
		}
		encodedBody, _ := json.Marshal(body)
		if strings.Contains(string(encodedBody), leaseToken) {
			t.Fatalf("step %d body leaked token", step)
		}
		switch step {
		case 2:
			if request.URL.Path != "/runner/v1/read-tasks/"+expected.TaskID+":start" ||
				body["schema_version"] != "runner-read-task-start-request.v1" || body["lease_epoch"] != "3" {
				t.Fatalf("start request = %s %#v", request.URL.Path, body)
			}
			writeJSON(t, writer, http.StatusOK, map[string]any{
				"schema_version": "runner-read-task-start-response.v1", "task_id": expected.TaskID,
				"attempt_status": "RUNNING", "lease_epoch": "3", "scope_revision": "7", "started_at": now,
			})
		case 3:
			if request.URL.Path != "/runner/v1/read-tasks/"+expected.TaskID+":heartbeat" ||
				body["schema_version"] != "runner-read-task-heartbeat-request.v1" ||
				body["lease_epoch"] != "3" || body["sequence"] != "1" {
				t.Fatalf("heartbeat request = %s %#v", request.URL.Path, body)
			}
			writeJSON(t, writer, http.StatusOK, map[string]any{
				"schema_version": "runner-read-task-heartbeat-response.v1", "task_id": expected.TaskID,
				"lease_epoch": "3", "accepted_sequence": "1", "directive": "CONTINUE",
				"lease_expires_at": now.Add(25 * time.Second), "heartbeat_after_seconds": 10,
			})
		case 4:
			if request.URL.Path != "/runner/v1/read-tasks/"+expected.TaskID+":complete" ||
				body["schema_version"] != "runner-read-task-complete-request.v1" ||
				body["lease_epoch"] != "3" || body["outcome"] != "EVIDENCE" || body["failure_code"] != nil {
				t.Fatalf("complete request = %s %#v", request.URL.Path, body)
			}
			writeJSON(t, writer, http.StatusOK, map[string]any{
				"schema_version": "runner-read-task-complete-response.v2", "task_id": expected.TaskID,
				"lease_epoch": "3", "attempt_status": "COMPLETED", "task_status": "EVIDENCE",
				"evidence_id": evidenceID, "content_hash": strings.Repeat("2", 64),
				"receipt_id": receiptID, "receipt_hash": strings.Repeat("3", 64), "replayed": false,
			})
		default:
			t.Fatalf("unexpected request step %d", step)
		}
	})
	client, err := readrunnerclient.New(fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	lease, err := client.Claim(context.Background(), expected)
	if err != nil {
		t.Fatal(err)
	}
	var traceObservedSecret atomic.Bool
	tracedContext := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		WroteHeaderField: func(key string, values []string) {
			if strings.EqualFold(key, "Authorization") || strings.Contains(strings.Join(values, ""), leaseToken) {
				traceObservedSecret.Store(true)
			}
		},
	})
	start, err := client.Start(tracedContext, lease)
	if err != nil || start == nil || start.TaskID() != expected.TaskID || start.LeaseEpoch() != 3 ||
		start.ScopeRevision() != 7 || !start.StartedAt().Equal(now) {
		t.Fatalf("Start() = %#v, %v", start, err)
	}
	if traceObservedSecret.Load() {
		t.Fatal("caller httptrace observed the private lease Authorization header")
	}
	copyCapability := *start
	if copyCapability.TaskID() != "" || copyCapability.LeaseEpoch() != 0 || !copyCapability.StartedAt().IsZero() {
		t.Fatal("copied start capability remained usable")
	}
	if _, copyErr := client.Complete(context.Background(), lease, &copyCapability, readrunnerclient.Completion{
		Outcome: readtask.CompletionFailed, FailureCode: readtask.FailureUnknown,
	}); copyErr == nil || step != 2 {
		t.Fatalf("Complete(copied capability) error = %v, requests=%d", copyErr, step)
	}
	if _, timeErr := client.Complete(context.Background(), lease, start, readrunnerclient.Completion{
		Outcome: readtask.CompletionEvidence,
		Evidence: &readtask.EvidenceCompletion{
			CollectedAt: now.Add(time.Microsecond), Items: []json.RawMessage{json.RawMessage(`{"value":1}`)},
		},
	}); !errors.Is(timeErr, readrunnerclient.ErrInvalidCompletion) || step != 2 || lease.TaskID() == "" {
		t.Fatalf("Complete(mismatched collection time) error=%v requests=%d lease=%s", timeErr, step, lease)
	}
	tooManyItems := make([]json.RawMessage, readtask.MaxEvidenceItems+1)
	for index := range tooManyItems {
		tooManyItems[index] = json.RawMessage(`{}`)
	}
	largeItem := json.RawMessage(`{"value":"` + strings.Repeat("x", readtask.MaxEvidencePayloadBytes-32) + `"}`)
	for name, invalid := range map[string]readrunnerclient.Completion{
		"unknown outcome": {Outcome: "FORGED"},
		"evidence and failure": {
			Outcome:     readtask.CompletionEvidence,
			Evidence:    &readtask.EvidenceCompletion{CollectedAt: now, Items: []json.RawMessage{json.RawMessage(`{}`)}},
			FailureCode: readtask.FailureUnknown,
		},
		"reserved evidence field": {
			Outcome: readtask.CompletionEvidence,
			Evidence: &readtask.EvidenceCompletion{CollectedAt: now,
				Items: []json.RawMessage{json.RawMessage(`{"authorization":"redacted"}`)}},
		},
		"too many evidence items": {
			Outcome:  readtask.CompletionEvidence,
			Evidence: &readtask.EvidenceCompletion{CollectedAt: now, Items: tooManyItems},
		},
		"encoded request over 64KiB": {
			Outcome:  readtask.CompletionEvidence,
			Evidence: &readtask.EvidenceCompletion{CollectedAt: now, Items: []json.RawMessage{largeItem}},
		},
		"cancelled as failed": {Outcome: readtask.CompletionFailed, FailureCode: readtask.FailureCancelled},
	} {
		if _, invalidErr := client.Complete(context.Background(), lease, start, invalid); !errors.Is(invalidErr, readrunnerclient.ErrInvalidCompletion) || step != 2 || lease.TaskID() == "" {
			t.Fatalf("Complete(%s) error=%v requests=%d lease=%s", name, invalidErr, step, lease)
		}
	}
	heartbeat, err := client.Heartbeat(context.Background(), lease, start, 1)
	if err != nil || heartbeat.AcceptedSequence != 1 || heartbeat.Directive != readtask.HeartbeatContinue ||
		!heartbeat.LeaseExpiresAt.Equal(now.Add(25*time.Second)) {
		t.Fatalf("Heartbeat() = %#v, %v", heartbeat, err)
	}
	receipt, err := client.Complete(context.Background(), lease, start, readrunnerclient.Completion{
		Outcome:  readtask.CompletionEvidence,
		Evidence: &readtask.EvidenceCompletion{CollectedAt: now, Items: []json.RawMessage{json.RawMessage(`{"value":1}`)}},
	})
	if err != nil || receipt.TaskID != expected.TaskID || receipt.LeaseEpoch != 3 || receipt.TaskStatus != "EVIDENCE" ||
		receipt.EvidenceID != evidenceID || receipt.ReceiptID != receiptID {
		t.Fatalf("Complete() = %#v, %v", receipt, err)
	}
	if lease.TaskID() != "" || start.TaskID() != "" || step != 4 {
		t.Fatalf("terminal handles remained usable or wrong requests: lease=%s start=%s step=%d", lease, start, step)
	}
}

func TestReleaseIsClaimedOnlyTerminalAndRejectsCopiedLeaseWithoutNetwork(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	expected, descriptor := validExpectedTaskAndDescriptor(t, now)
	leaseToken := base64.RawURLEncoding.EncodeToString(bytesOf(0x24, 32))
	step := 0
	fixture := newGatewayFixture(t, runneridentity.PoolRead, func(writer http.ResponseWriter, request *http.Request) {
		step++
		if step == 1 {
			writeJSON(t, writer, http.StatusOK, claimResponse(descriptor, leaseToken, 5, 9, now.Add(30*time.Second)))
			return
		}
		if request.URL.Path != "/runner/v1/read-tasks/"+expected.TaskID+":release" ||
			request.Header.Get("Authorization") != "AIOPS-Read-Task-Lease "+leaseToken {
			t.Fatalf("release request = %s %#v", request.URL.Path, request.Header)
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil ||
			body["schema_version"] != "runner-read-task-release-request.v1" || body["lease_epoch"] != "5" ||
			body["reason_code"] != "CONNECTOR_NOT_READY" {
			t.Fatalf("release body = %#v, %v", body, err)
		}
		writeJSON(t, writer, http.StatusOK, map[string]any{
			"schema_version": "runner-read-task-release-response.v1", "task_id": expected.TaskID,
			"attempt_status": "RELEASED", "lease_epoch": "5",
		})
	})
	client, err := readrunnerclient.New(fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := client.Claim(context.Background(), expected)
	if err != nil {
		t.Fatal(err)
	}
	copyLease := *lease
	if err := client.Release(context.Background(), &copyLease, readtask.ReleaseConnectorNotReady); err == nil || step != 1 {
		t.Fatalf("Release(copy) error=%v requests=%d", err, step)
	}
	if err := client.Release(context.Background(), lease, readtask.ReleaseConnectorNotReady); err != nil {
		t.Fatalf("Release() error = %v", err)
	}
	if lease.TaskID() != "" || step != 2 {
		t.Fatalf("released lease remained usable or wrong requests: %s step=%d", lease, step)
	}
}

func TestClaimRejectsForgedScopePlanRuntimeAndStrictJSONViolations(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	expected, validDescriptor := validExpectedTaskAndDescriptor(t, now)
	validToken := base64.RawURLEncoding.EncodeToString(bytesOf(0x36, 32))
	wrongScopeDescriptor := validDescriptor
	wrongScopeDigest, err := investigation.ReadTaskRuntimeDigest(
		investigation.TaskSpecScope{
			TenantID: expected.TenantID, WorkspaceID: "20000000-0000-4000-8000-000000000099",
			EnvironmentID: expected.EnvironmentID, ServiceID: expected.ServiceID, MappingStatus: domain.MappingExact,
		},
		expected.PlanBinding,
		investigation.TaskSpec{Key: validDescriptor.Key, ConnectorID: validDescriptor.ConnectorID,
			Operation: validDescriptor.Operation, Input: validDescriptor.Input},
		expected.Position,
		investigation.TaskRuntimeComponents{
			ConnectorDigest: validDescriptor.RuntimeBinding.ConnectorDigest,
			TargetDigest:    validDescriptor.RuntimeBinding.TargetDigest, ExecutorDigest: validDescriptor.RuntimeBinding.ExecutorDigest,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	wrongScopeDescriptor.RuntimeBinding.RuntimeDigest = wrongScopeDigest

	type testCase struct {
		name       string
		descriptor descriptorWire
		response   func([]byte) []byte
		headers    func(http.Header)
	}
	identity := func(value []byte) []byte { return value }
	cases := []testCase{
		{name: "trusted scope digest mismatch", descriptor: wrongScopeDescriptor, response: identity},
		{name: "task id", descriptor: mutateDescriptor(validDescriptor, func(value *descriptorWire) {
			value.ID = "70000000-0000-4000-8000-000000000099"
		}), response: identity},
		{name: "position", descriptor: mutateDescriptor(validDescriptor, func(value *descriptorWire) { value.Position = 2 }), response: identity},
		{name: "plan manifest", descriptor: mutateDescriptor(validDescriptor, func(value *descriptorWire) {
			value.PlanBinding.ManifestDigest = strings.Repeat("9", 64)
		}), response: identity},
		{name: "plan registry", descriptor: mutateDescriptor(validDescriptor, func(value *descriptorWire) {
			value.PlanBinding.RegistryDigest = strings.Repeat("9", 64)
		}), response: identity},
		{name: "plan profile", descriptor: mutateDescriptor(validDescriptor, func(value *descriptorWire) {
			value.PlanBinding.ProfileDigest = strings.Repeat("9", 64)
		}), response: identity},
		{name: "plan tasks", descriptor: mutateDescriptor(validDescriptor, func(value *descriptorWire) {
			value.PlanBinding.TasksHash = strings.Repeat("9", 64)
		}), response: identity},
		{name: "runtime digest", descriptor: mutateDescriptor(validDescriptor, func(value *descriptorWire) {
			value.RuntimeBinding.RuntimeDigest = strings.Repeat("9", 64)
		}), response: identity},
		{name: "input hash", descriptor: mutateDescriptor(validDescriptor, func(value *descriptorWire) {
			value.InputHash = strings.Repeat("9", 64)
		}), response: identity},
		{name: "unknown field", descriptor: validDescriptor, response: func(value []byte) []byte {
			return append(value[:len(value)-1], []byte(`,"unexpected":true}`)...)
		}},
		{name: "duplicate field", descriptor: validDescriptor, response: func(value []byte) []byte {
			return append(value[:len(value)-1], []byte(`,"schema_version":"runner-read-task-claim-response.v2"}`)...)
		}},
		{name: "trailing document", descriptor: validDescriptor, response: func(value []byte) []byte {
			return append(value, []byte(` {}`)...)
		}},
		{name: "case folded field", descriptor: validDescriptor, response: func(value []byte) []byte {
			return []byte(strings.Replace(string(value), `"schema_version"`, `"Schema_version"`, 1))
		}},
		{name: "numeric epoch", descriptor: validDescriptor, response: func(value []byte) []byte {
			return []byte(strings.Replace(string(value), `"lease_epoch":"3"`, `"lease_epoch":3`, 1))
		}},
		{name: "missing no-store", descriptor: validDescriptor, response: identity, headers: func(header http.Header) {
			header.Del("Cache-Control")
		}},
		{name: "duplicate no-store", descriptor: validDescriptor, response: identity, headers: func(header http.Header) {
			header.Add("Cache-Control", "no-store")
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGatewayFixture(t, runneridentity.PoolRead, func(writer http.ResponseWriter, _ *http.Request) {
				encoded, marshalErr := json.Marshal(claimResponse(
					test.descriptor, validToken, 3, 7, now.Add(30*time.Second),
				))
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				writer.Header().Set("Cache-Control", "no-store")
				writer.Header().Set("Content-Type", "application/json")
				writer.Header().Set("X-Content-Type-Options", "nosniff")
				if test.headers != nil {
					test.headers(writer.Header())
				}
				writer.WriteHeader(http.StatusOK)
				_, _ = writer.Write(test.response(encoded))
			})
			client, newErr := readrunnerclient.New(fixture.options)
			if newErr != nil {
				t.Fatal(newErr)
			}
			lease, claimErr := client.Claim(context.Background(), expected)
			if lease != nil || !errors.Is(claimErr, readrunnerclient.ErrInvalidResponse) {
				t.Fatalf("Claim(%s) = %#v, %v; want invalid response", test.name, lease, claimErr)
			}
		})
	}
}

func TestClientRejectsOverlongClaimHeartbeatAndStaleStartWindows(t *testing.T) {
	for _, test := range []struct {
		name      string
		startedAt time.Duration
		heartbeat time.Duration
		claim     time.Duration
		wantStep  int
	}{
		{name: "claim lease over 30 seconds", claim: 2 * time.Minute, wantStep: 1},
		{name: "claim lease below usable window", claim: 10 * time.Second, wantStep: 1},
		{name: "stale start timestamp", claim: 30 * time.Second, startedAt: -requestTimeoutForTest - time.Second, wantStep: 2},
		{name: "heartbeat lease over 30 seconds", claim: 30 * time.Second, heartbeat: 2 * time.Minute, wantStep: 3},
		{name: "heartbeat lease below usable window", claim: 30 * time.Second, heartbeat: 10 * time.Second, wantStep: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Microsecond)
			expected, descriptor := validExpectedTaskAndDescriptor(t, now)
			token := base64.RawURLEncoding.EncodeToString(bytesOf(0x73, 32))
			step := 0
			fixture := newGatewayFixture(t, runneridentity.PoolRead, func(writer http.ResponseWriter, _ *http.Request) {
				step++
				switch step {
				case 1:
					writeJSON(t, writer, http.StatusOK, claimResponse(descriptor, token, 3, 7, now.Add(test.claim)))
				case 2:
					writeJSON(t, writer, http.StatusOK, map[string]any{
						"schema_version": "runner-read-task-start-response.v1", "task_id": expected.TaskID,
						"attempt_status": "RUNNING", "lease_epoch": "3", "scope_revision": "7",
						"started_at": now.Add(test.startedAt),
					})
				case 3:
					writeJSON(t, writer, http.StatusOK, map[string]any{
						"schema_version": "runner-read-task-heartbeat-response.v1", "task_id": expected.TaskID,
						"lease_epoch": "3", "accepted_sequence": "1", "directive": "CONTINUE",
						"lease_expires_at": now.Add(test.heartbeat), "heartbeat_after_seconds": 10,
					})
				}
			})
			client, err := readrunnerclient.New(fixture.options)
			if err != nil {
				t.Fatal(err)
			}
			lease, err := client.Claim(context.Background(), expected)
			if test.wantStep == 1 {
				if lease != nil || !errors.Is(err, readrunnerclient.ErrInvalidResponse) || step != 1 {
					t.Fatalf("Claim() = %#v, %v step=%d", lease, err, step)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			start, err := client.Start(context.Background(), lease)
			if test.wantStep == 2 {
				if start != nil || !errors.Is(err, readrunnerclient.ErrInvalidResponse) || step != 2 {
					t.Fatalf("Start() = %#v, %v step=%d", start, err, step)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Heartbeat(context.Background(), lease, start, 1); !errors.Is(err, readrunnerclient.ErrInvalidResponse) || step != 3 {
				t.Fatalf("Heartbeat() error=%v step=%d", err, step)
			}
		})
	}
}

func TestClaimRejectsTypedNilContextWithoutCallingGateway(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	expected, _ := validExpectedTaskAndDescriptor(t, now)
	requests := 0
	fixture := newGatewayFixture(t, runneridentity.PoolRead, func(http.ResponseWriter, *http.Request) { requests++ })
	client, err := readrunnerclient.New(fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	var typedNil *typedNilContext
	lease, err := client.Claim(typedNil, expected)
	if lease != nil || err == nil || requests != 0 {
		t.Fatalf("Claim(typed nil) = %#v, %v requests=%d", lease, err, requests)
	}
}

func TestClaimHandlesNoContentProblemRedirectAndBoundedResponseWithoutSecretLeakage(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	expected, _ := validExpectedTaskAndDescriptor(t, now)
	const reflectedCanary = "remote-detail-token-canary-must-not-reach-error"
	for _, test := range []struct {
		name  string
		serve func(*testing.T, *gatewayFixture, http.ResponseWriter, *http.Request)
		check func(*testing.T, *readrunnerclient.Lease, error, int)
	}{
		{name: "no claim", serve: func(_ *testing.T, _ *gatewayFixture, writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Cache-Control", "no-store")
			writer.Header().Set("X-Content-Type-Options", "nosniff")
			writer.WriteHeader(http.StatusNoContent)
		}, check: func(t *testing.T, lease *readrunnerclient.Lease, err error, requests int) {
			if lease != nil || err != nil || requests != 1 {
				t.Fatalf("Claim(no content) = %#v, %v requests=%d", lease, err, requests)
			}
		}},
		{name: "bounded RFC9457", serve: func(t *testing.T, _ *gatewayFixture, writer http.ResponseWriter, _ *http.Request) {
			writeProblem(t, writer, http.StatusForbidden, map[string]any{
				"type": "urn:aiops:problem:runner:identity-rejected", "title": reflectedCanary,
				"status": http.StatusForbidden, "code": "runner_identity_rejected", "detail": reflectedCanary,
				"instance": "urn:aiops:request:123e4567-e89b-42d3-a456-426614174000",
			})
		}, check: func(t *testing.T, lease *readrunnerclient.Lease, err error, requests int) {
			var problem *readrunnerclient.ProblemError
			if !errors.As(err, &problem) {
				t.Fatalf("Claim(problem) error = %#v", err)
			}
			encoded, _ := json.Marshal(problem)
			if lease != nil || problem.Status != http.StatusForbidden ||
				strings.Contains(fmt.Sprint(err), reflectedCanary) || strings.Contains(fmt.Sprintf("%#v", problem), reflectedCanary) ||
				strings.Contains(string(encoded), reflectedCanary) || requests != 1 {
				t.Fatalf("Claim(problem) = %#v, %#v requests=%d", lease, err, requests)
			}
		}},
		{name: "redirect", serve: func(_ *testing.T, fixture *gatewayFixture, writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Location", fixture.server.URL+"/runner/v1/read-tasks/70000000-0000-4000-8000-000000000099:claim")
			writer.WriteHeader(http.StatusTemporaryRedirect)
		}, check: func(t *testing.T, lease *readrunnerclient.Lease, err error, requests int) {
			if lease != nil || err == nil || requests != 1 || strings.Contains(fmt.Sprint(err), "70000000") {
				t.Fatalf("Claim(redirect) = %#v, %v requests=%d", lease, err, requests)
			}
		}},
		{name: "response above 256KiB", serve: func(_ *testing.T, _ *gatewayFixture, writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Cache-Control", "no-store")
			writer.Header().Set("Content-Type", "application/json")
			writer.Header().Set("X-Content-Type-Options", "nosniff")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write(append([]byte(`{}`), bytesOf(' ', (256<<10)+1)...))
		}, check: func(t *testing.T, lease *readrunnerclient.Lease, err error, requests int) {
			if lease != nil || !errors.Is(err, readrunnerclient.ErrInvalidResponse) || requests != 1 {
				t.Fatalf("Claim(oversized) = %#v, %v requests=%d", lease, err, requests)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests := 0
			var fixture *gatewayFixture
			fixture = newGatewayFixture(t, runneridentity.PoolRead, func(writer http.ResponseWriter, request *http.Request) {
				requests++
				test.serve(t, fixture, writer, request)
			})
			client, err := readrunnerclient.New(fixture.options)
			if err != nil {
				t.Fatal(err)
			}
			lease, claimErr := client.Claim(context.Background(), expected)
			test.check(t, lease, claimErr, requests)
		})
	}
}

func TestConcurrentHeartbeatUsesOneSequenceAndOneNetworkOperation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	expected, descriptor := validExpectedTaskAndDescriptor(t, now)
	token := base64.RawURLEncoding.EncodeToString(bytesOf(0x18, 32))
	entered := make(chan struct{})
	release := make(chan struct{})
	var step atomic.Int32
	fixture := newGatewayFixture(t, runneridentity.PoolRead, func(writer http.ResponseWriter, _ *http.Request) {
		current := step.Add(1)
		switch current {
		case 1:
			writeJSON(t, writer, http.StatusOK, claimResponse(descriptor, token, 3, 7, now.Add(30*time.Second)))
		case 2:
			writeJSON(t, writer, http.StatusOK, map[string]any{
				"schema_version": "runner-read-task-start-response.v1", "task_id": expected.TaskID,
				"attempt_status": "RUNNING", "lease_epoch": "3", "scope_revision": "7", "started_at": now,
			})
		case 3:
			close(entered)
			<-release
			writeJSON(t, writer, http.StatusOK, map[string]any{
				"schema_version": "runner-read-task-heartbeat-response.v1", "task_id": expected.TaskID,
				"lease_epoch": "3", "accepted_sequence": "1", "directive": "CONTINUE",
				"lease_expires_at": now.Add(25 * time.Second), "heartbeat_after_seconds": 10,
			})
		default:
			t.Fatalf("unexpected request %d", current)
		}
	})
	client, err := readrunnerclient.New(fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := client.Claim(context.Background(), expected)
	if err != nil {
		t.Fatal(err)
	}
	start, err := client.Start(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	firstResult := make(chan error, 1)
	go func() {
		_, heartbeatErr := client.Heartbeat(context.Background(), lease, start, 1)
		firstResult <- heartbeatErr
	}()
	<-entered
	if _, err := client.Heartbeat(context.Background(), lease, start, 1); !errors.Is(err, readrunnerclient.ErrInvalidLease) {
		t.Fatalf("concurrent Heartbeat() error = %v", err)
	}
	close(release)
	if err := <-firstResult; err != nil {
		t.Fatalf("first Heartbeat() error = %v", err)
	}
	if step.Load() != 3 {
		t.Fatalf("heartbeat issued %d total requests; want 3", step.Load())
	}
	lease.Destroy()
}

type typedNilContext struct{}

func (*typedNilContext) Deadline() (time.Time, bool) { panic("typed nil context used") }
func (*typedNilContext) Done() <-chan struct{}       { panic("typed nil context used") }
func (*typedNilContext) Err() error                  { panic("typed nil context used") }
func (*typedNilContext) Value(any) any               { panic("typed nil context used") }

type gatewayFixture struct {
	options readrunnerclient.Options
	server  *httptest.Server
}

func newGatewayFixture(t *testing.T, certificatePool runneridentity.Pool, handler http.HandlerFunc) *gatewayFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	serverAuthority, err := testpki.NewAuthority("read-runner-gateway-server-root", now)
	if err != nil {
		t.Fatal(err)
	}
	clientAuthority, err := testpki.NewAuthority("read-runner-client-root", now)
	if err != nil {
		t.Fatal(err)
	}
	serverCertificate, err := serverAuthority.IssueServer("read-runner-gateway.test", now)
	if err != nil {
		t.Fatal(err)
	}
	segment := "read"
	if certificatePool == runneridentity.PoolWrite {
		segment = "write"
	}
	spiffe, err := url.Parse("spiffe://aiops.test/runner/" + segment + "/" + fixtureRunnerInstance)
	if err != nil {
		t.Fatal(err)
	}
	clientCertificate, err := clientAuthority.IssueClient(testpki.ClientOptions{URIs: []*url.URL{spiffe}}, now)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = false
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientAuthority.CertPool(),
		Certificates: []tls.Certificate{serverCertificate.TLS}, NextProtos: []string{"http/1.1"},
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	directory := t.TempDir()
	rootCAFile := filepath.Join(directory, "server-root.pem")
	clientCertificateFile := filepath.Join(directory, "read-runner-chain.pem")
	clientPrivateKeyFile := filepath.Join(directory, "read-runner-key.pem")
	writePEMFile(t, rootCAFile, "CERTIFICATE", serverAuthority.Certificate.Raw, 0o600)
	writeCertificateChain(t, clientCertificateFile, clientCertificate.TLS.Certificate)
	privateKey, ok := clientCertificate.TLS.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("private key type = %T", clientCertificate.TLS.PrivateKey)
	}
	encodedKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEMFile(t, clientPrivateKeyFile, "PRIVATE KEY", encodedKey, 0o600)
	return &gatewayFixture{options: readrunnerclient.Options{
		BaseURL: server.URL, ServerName: "read-runner-gateway.test", TrustDomain: "aiops.test",
		ExpectedPool: runneridentity.PoolRead, RootCAFile: rootCAFile,
		ClientCertificateFile: clientCertificateFile, ClientPrivateKeyFile: clientPrivateKeyFile,
	}, server: server}
}

func replaceFixtureClientCertificate(t *testing.T, fixture *gatewayFixture, options testpki.ClientOptions) {
	t.Helper()
	if fixture == nil {
		t.Fatal("fixture is nil")
	}
	now := time.Now().UTC().Truncate(time.Second)
	authority, err := testpki.NewAuthority("replacement-read-runner-client-root", now)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := authority.IssueClient(options, now)
	if err != nil {
		t.Fatal(err)
	}
	writeCertificateChain(t, fixture.options.ClientCertificateFile, certificate.TLS.Certificate)
	privateKey, ok := certificate.TLS.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("replacement key type = %T", certificate.TLS.PrivateKey)
	}
	encodedKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEMFile(t, fixture.options.ClientPrivateKeyFile, "PRIVATE KEY", encodedKey, 0o600)
}

func validExpectedTaskAndDescriptor(t *testing.T, now time.Time) (readrunnerclient.ExpectedTask, descriptorWire) {
	t.Helper()
	plan := domain.InvestigationPlanBinding{
		SchemaVersion: domain.InvestigationPlanBindingSchemaVersion, ManifestDigest: strings.Repeat("a", 64),
		RegistryDigest: strings.Repeat("b", 64), ProfileDigest: strings.Repeat("c", 64),
		TasksHash: strings.Repeat("d", 64),
	}
	expected := readrunnerclient.ExpectedTask{
		TenantID: "10000000-0000-4000-8000-000000000001", WorkspaceID: "20000000-0000-4000-8000-000000000002",
		EnvironmentID: "30000000-0000-4000-8000-000000000003", ServiceID: "40000000-0000-4000-8000-000000000004",
		IncidentID: "50000000-0000-4000-8000-000000000005", InvestigationID: "60000000-0000-4000-8000-000000000006",
		TaskID: "70000000-0000-4000-8000-000000000007", Position: 1, PlanBinding: plan,
	}
	input := json.RawMessage(`{"query":"up"}`)
	inputDigest := sha256.Sum256(input)
	connectorDigest := strings.Repeat("e", 64)
	spec := investigation.TaskSpec{
		Key: "metrics", ConnectorID: "prometheus-v1-" + connectorDigest,
		Operation: "query_range", Input: input,
	}
	runtimeBinding, err := investigation.BuildReadTaskRuntimeBinding(
		investigation.TaskSpecScope{TenantID: expected.TenantID, WorkspaceID: expected.WorkspaceID,
			EnvironmentID: expected.EnvironmentID, ServiceID: expected.ServiceID, MappingStatus: domain.MappingExact},
		plan, spec, expected.Position, investigation.TaskRuntimeComponents{ConnectorDigest: connectorDigest,
			TargetDigest: strings.Repeat("f", 64), ExecutorDigest: strings.Repeat("1", 64)}, now,
	)
	if err != nil {
		t.Fatalf("BuildReadTaskRuntimeBinding() error = %v", err)
	}
	return expected, descriptorWire{
		ID: expected.TaskID, Key: spec.Key, Position: expected.Position, ConnectorID: spec.ConnectorID,
		Operation: spec.Operation, Input: input, InputHash: hex.EncodeToString(inputDigest[:]),
		PlanBinding: plan, RuntimeBinding: runtimeBinding,
	}
}

type descriptorWire struct {
	ID             string                          `json:"id"`
	Key            string                          `json:"key"`
	Position       int                             `json:"position"`
	ConnectorID    string                          `json:"connector_id"`
	Operation      string                          `json:"operation"`
	Input          json.RawMessage                 `json:"input"`
	InputHash      string                          `json:"input_hash"`
	PlanBinding    domain.InvestigationPlanBinding `json:"plan_binding"`
	RuntimeBinding domain.ReadTaskRuntimeBinding   `json:"runtime_binding"`
}

func claimResponse(descriptor descriptorWire, token string, epoch, scope int64, expires time.Time) map[string]any {
	return map[string]any{
		"schema_version": "runner-read-task-claim-response.v2", "task": descriptor,
		"lease_token": token, "lease_epoch": fmt.Sprint(epoch), "scope_revision": fmt.Sprint(scope),
		"lease_expires_at": expires, "heartbeat_after_seconds": 10,
	}
}

func mutateDescriptor(source descriptorWire, mutate func(*descriptorWire)) descriptorWire {
	cloned := source
	cloned.Input = append(json.RawMessage(nil), source.Input...)
	mutate(&cloned)
	return cloned
}

func writeJSON(t *testing.T, writer http.ResponseWriter, status int, value any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_, _ = writer.Write(encoded)
}

func writeProblem(t *testing.T, writer http.ResponseWriter, status int, value any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/problem+json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_, _ = writer.Write(encoded)
}

func writeCertificateChain(t *testing.T, path string, chain [][]byte) {
	t.Helper()
	var contents []byte
	for _, certificate := range chain {
		contents = append(contents, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})...)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writePEMFile(t *testing.T, path, blockType string, contents []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: contents}), mode); err != nil {
		t.Fatal(err)
	}
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}
