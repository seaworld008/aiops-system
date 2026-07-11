package runnerclient_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
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
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/seaworld008/aiops-system/internal/action"
	"github.com/seaworld008/aiops-system/internal/credential"
	"github.com/seaworld008/aiops-system/internal/execution"
	"github.com/seaworld008/aiops-system/internal/runnerclient"
	"github.com/seaworld008/aiops-system/internal/runneridentity"
	"github.com/seaworld008/aiops-system/internal/runneridentity/testpki"
)

func TestClientReadsCertificateBoundIdentityOverStrictMTLS(t *testing.T) {
	const registeredRunnerID = "registered-write-runner-01"
	var fixture *gatewayFixture
	fixture = newGatewayFixture(t, runneridentity.PoolWrite, func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/runner/v1/identity" {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		if request.ProtoMajor != 1 || request.TLS == nil || request.TLS.Version != tls.VersionTLS13 {
			t.Fatalf("transport = proto %s TLS %#v", request.Proto, request.TLS)
		}
		if request.Header.Get("Authorization") != "" {
			t.Fatal("identity request carried Authorization")
		}
		writeJSON(t, writer, http.StatusOK, map[string]any{
			"schema_version":        "runner-identity-response.v1",
			"runner_id":             registeredRunnerID,
			"pool":                  "WRITE",
			"scope_revision":        "7",
			"max_concurrency":       2,
			"capabilities":          []string{"CREDENTIAL_REVOCATION"},
			"certificate_sha256":    fixture.clientFingerprint,
			"certificate_not_after": fixture.clientNotAfter,
		})
	})

	client, err := runnerclient.New(fixture.options)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(client.CloseIdleConnections)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	identity, err := client.Identity(ctx)
	if err != nil {
		t.Fatalf("Identity() error = %v", err)
	}
	if identity.RunnerID != registeredRunnerID || identity.Pool != runneridentity.PoolWrite || identity.ScopeRevision != 7 ||
		identity.MaxConcurrency != 2 || identity.CertificateSHA256 != fixture.clientFingerprint ||
		!identity.CertificateNotAfter.Equal(fixture.clientNotAfter) {
		t.Fatalf("Identity() = %#v", identity)
	}
}

func TestClientRejectsRunnerCertificateOutsideConfiguredTrustDomain(t *testing.T) {
	fixture := newGatewayFixture(t, runneridentity.PoolWrite, func(http.ResponseWriter, *http.Request) {})
	fixture.options.TrustDomain = "other-aiops.test"
	client, err := runnerclient.New(fixture.options)
	if !errors.Is(err, runnerclient.ErrInvalidConfiguration) || client != nil {
		t.Fatalf("New(wrong trust domain) = %#v, %v; want invalid configuration", client, err)
	}
}

func TestClientRejectsTrustFilesWithExtendedAccessMetadata(t *testing.T) {
	fixture := newGatewayFixture(t, runneridentity.PoolWrite, func(http.ResponseWriter, *http.Request) {})
	file, err := os.Open(fixture.options.RootCAFile)
	if err != nil {
		t.Fatalf("Open(root CA) error = %v", err)
	}
	defer file.Close()
	name, err := syscall.BytePtrFromString("user.aiops-runner-client-test")
	if err != nil {
		t.Fatalf("BytePtrFromString(xattr) error = %v", err)
	}
	value := []byte("present")
	_, _, errno := syscall.Syscall6(
		syscall.SYS_FSETXATTR,
		file.Fd(),
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(&value[0])),
		uintptr(len(value)),
		0,
		0,
	)
	runtime.KeepAlive(name)
	runtime.KeepAlive(value)
	if errno != 0 {
		t.Fatalf("fsetxattr() error = %v", errno)
	}
	client, err := runnerclient.New(fixture.options)
	if !errors.Is(err, runnerclient.ErrInvalidConfiguration) || client != nil {
		t.Fatalf("New(xattr trust file) = %#v, %v; want invalid configuration", client, err)
	}
}

func TestClientRejectsNonStrictCertificateAndPrivateKeyPEM(t *testing.T) {
	for name, mutate := range map[string]func(t *testing.T, fixture *gatewayFixture){
		"root leading garbage": func(t *testing.T, fixture *gatewayFixture) {
			contents, err := os.ReadFile(fixture.options.RootCAFile)
			if err != nil {
				t.Fatal(err)
			}
			contents = append([]byte("ignored-prefix\n"), contents...)
			if err := os.WriteFile(fixture.options.RootCAFile, contents, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"client certificate trailing garbage": func(t *testing.T, fixture *gatewayFixture) {
			file, err := os.OpenFile(fixture.options.ClientCertificateFile, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.WriteString("ignored-suffix"); err != nil {
				file.Close()
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
		},
		"private key trailing certificate": func(t *testing.T, fixture *gatewayFixture) {
			certificate, err := os.ReadFile(fixture.options.ClientCertificateFile)
			if err != nil {
				t.Fatal(err)
			}
			file, err := os.OpenFile(fixture.options.ClientPrivateKeyFile, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.Write(certificate); err != nil {
				file.Close()
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newGatewayFixture(t, runneridentity.PoolWrite, func(http.ResponseWriter, *http.Request) {})
			mutate(t, fixture)
			client, err := runnerclient.New(fixture.options)
			if !errors.Is(err, runnerclient.ErrInvalidConfiguration) || client != nil {
				t.Fatalf("New(%s) = %#v, %v; want invalid configuration", name, client, err)
			}
		})
	}
}

func TestLeaseJobReturnsOnlyValidatedNonProductionActionAndRedactsToken(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	envelope := sealedRestartEnvelope(t, now)
	const token = "job-lease-token-canary-0123456789abcdef"
	fixture := newGatewayFixture(t, runneridentity.PoolWrite, func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/runner/v1/jobs:lease" {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		var body map[string]string
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatalf("decode lease request: %v", err)
		}
		if len(body) != 1 || body["schema_version"] != "runner-job-lease-request.v1" {
			t.Fatalf("lease body = %#v", body)
		}
		writeJSON(t, writer, http.StatusOK, map[string]any{
			"schema_version": "runner-job-lease-response.v1",
			"job": map[string]any{
				"id": envelope.ActionID, "kind": "WRITE_ACTION", "payload": envelope,
				"plan_hash": envelope.PlanHash, "environment_revision": "environment-revision-7", "production": false,
			},
			"lease_token": token, "lease_epoch": "3", "scope_revision": "7",
			"lease_expires_at": now.Add(30 * time.Second), "heartbeat_after_seconds": 10,
		})
	})
	client, err := runnerclient.New(fixture.options)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(client.CloseIdleConnections)

	lease, err := client.LeaseJob(context.Background())
	if err != nil {
		t.Fatalf("LeaseJob() error = %v", err)
	}
	if lease == nil || lease.Job.ID != envelope.ActionID || lease.Job.Production || lease.LeaseEpoch != 3 || lease.ScopeRevision != 7 {
		t.Fatalf("LeaseJob() = %#v", lease)
	}
	encoded, err := json.Marshal(lease)
	if err != nil {
		t.Fatalf("Marshal(lease) error = %v", err)
	}
	for _, rendering := range []string{string(encoded), fmt.Sprint(lease), fmt.Sprintf("%#v", lease)} {
		if strings.Contains(rendering, token) {
			t.Fatalf("lease rendering leaked raw token: %s", rendering)
		}
	}
	lease.Destroy()
}

func TestClientRunsSegmentedJobProtocolWithPrivateBearerHandles(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	envelope := sealedRestartEnvelope(t, now)
	const (
		leaseToken = "job-lease-token-canary-0123456789abcdef"
		permit     = "child-create-permit-canary-0123456789abcdef"
		revocation = "123e4567-e89b-42d3-a456-426614174000"
		issuerID   = "vault-staging"
		issuerRev  = "revision-7"
	)
	accessorBytes := []byte("revoke-accessor-canary")
	step := 0
	fixture := newGatewayFixture(t, runneridentity.PoolWrite, func(writer http.ResponseWriter, request *http.Request) {
		step++
		if step == 1 {
			writeJSON(t, writer, http.StatusOK, map[string]any{
				"schema_version": "runner-job-lease-response.v1",
				"job": map[string]any{"id": envelope.ActionID, "kind": "WRITE_ACTION", "payload": envelope,
					"plan_hash": envelope.PlanHash, "environment_revision": "environment-revision-7", "production": false},
				"lease_token": leaseToken, "lease_epoch": "3", "scope_revision": "7",
				"lease_expires_at": now.Add(30 * time.Second), "heartbeat_after_seconds": 10,
			})
			return
		}
		if request.Header.Get("Authorization") != "AIOPS-Job-Lease "+leaseToken {
			t.Fatalf("step %d Authorization was not the private job lease", step)
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatalf("step %d decode body: %v", step, err)
		}
		switch step {
		case 2:
			if request.URL.Path != "/runner/v1/jobs/"+envelope.ActionID+":start" {
				t.Fatalf("start path = %s", request.URL.Path)
			}
			writeJSON(t, writer, http.StatusOK, map[string]any{
				"schema_version": "runner-job-start-response.v1", "job_id": envelope.ActionID,
				"status": "RUNNING", "lease_epoch": "3", "scope_revision": "7", "started_at": now,
				"credential_prepare": map[string]any{
					"revocation_id": revocation, "child_create_permit": permit,
					"issuer_id": issuerID, "issuer_revision": issuerRev,
					"credential_expires_at": now.Add(10 * time.Minute),
				},
			})
		case 3:
			if body["phase"] != "AUTHORIZE_CHILD_CREATE" || body["child_create_permit"] != permit {
				t.Fatalf("authorize body = %#v", body)
			}
			writeJSON(t, writer, http.StatusOK, map[string]any{
				"schema_version": "runner-credential-anchor-response.v1", "job_id": envelope.ActionID,
				"revocation_id": revocation, "status": "PREPARED", "database_authorized_at": now,
				"child_ttl_seconds": 300, "credential_expires_at": now.Add(10 * time.Minute),
			})
		case 4:
			if body["phase"] != "RECORD_ANCHOR" || body["revoke_accessor_b64u"] != base64.RawURLEncoding.EncodeToString(accessorBytes) {
				t.Fatalf("record anchor body = %#v", body)
			}
			writeJSON(t, writer, http.StatusOK, credentialStateResponse(envelope.ActionID, revocation, "ANCHORED"))
		case 5:
			if body["phase"] != "ACTIVATE" {
				t.Fatalf("activate body = %#v", body)
			}
			writeJSON(t, writer, http.StatusOK, credentialStateResponse(envelope.ActionID, revocation, "ACTIVE"))
		case 6:
			if request.URL.Path != "/runner/v1/jobs/"+envelope.ActionID+":heartbeat" || body["sequence"] != "1" {
				t.Fatalf("heartbeat = %s %#v", request.URL.Path, body)
			}
			writeJSON(t, writer, http.StatusOK, map[string]any{
				"schema_version": "runner-job-heartbeat-response.v1", "job_id": envelope.ActionID,
				"accepted_sequence": "1", "directive": "CONTINUE", "lease_expires_at": now.Add(30 * time.Second),
				"heartbeat_after_seconds": 10,
			})
		case 7:
			if request.URL.Path != "/runner/v1/jobs/"+envelope.ActionID+":complete" {
				t.Fatalf("complete path = %s", request.URL.Path)
			}
			writeJSON(t, writer, http.StatusAccepted, map[string]any{
				"schema_version": "runner-job-completion-response.v1", "job_id": envelope.ActionID,
				"status": "FINALIZING", "completion_status": "SUCCEEDED", "receipt_hash": strings.Repeat("b", 64),
				"credential_cleanup_status": "PENDING",
			})
		default:
			t.Fatalf("unexpected protocol step %d", step)
		}
	})
	client, err := runnerclient.New(fixture.options)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(client.CloseIdleConnections)
	lease, err := client.LeaseJob(context.Background())
	if err != nil {
		t.Fatalf("LeaseJob() error = %v", err)
	}
	defer lease.Destroy()
	started, err := client.StartJob(context.Background(), lease)
	if err != nil {
		t.Fatalf("StartJob() error = %v", err)
	}
	if started.Credential.IssuerID() != issuerID || started.Credential.IssuerRevision() != issuerRev {
		t.Fatalf("StartJob() credential issuer = %q/%q", started.Credential.IssuerID(), started.Credential.IssuerRevision())
	}
	defer started.Credential.Destroy()
	executorBinding := runnerclient.ExecutorBinding{
		JobID: envelope.ActionID, PlanHash: envelope.PlanHash, EnvironmentRevision: "environment-revision-7",
		LeaseEpoch: 3, ScopeRevision: 7, Production: false, Payload: envelope,
	}
	if _, cancel, err := started.Grant.BindExecutor(context.Background(), executorBinding); !errors.Is(err, runnerclient.ErrInvalidResponse) || cancel != nil {
		t.Fatalf("BindExecutor(before ACTIVE) = cancel=%#v, error=%v", cancel, err)
	}
	lease.Job.ID = "mutated-job-id"
	if _, err := client.AuthorizeChildCreate(context.Background(), lease, started.Credential); !errors.Is(err, runnerclient.ErrInvalidResponse) {
		t.Fatalf("AuthorizeChildCreate(mutated lease) error = %v, want invalid response", err)
	}
	lease.Job.ID = envelope.ActionID
	authorized, err := client.AuthorizeChildCreate(context.Background(), lease, started.Credential)
	if err != nil || authorized.Status != "PREPARED" || authorized.ChildTTLSeconds != 300 {
		t.Fatalf("AuthorizeChildCreate() = %#v, %v", authorized, err)
	}
	accessor, err := credential.NewSensitiveReference(accessorBytes)
	if err != nil {
		t.Fatalf("NewSensitiveReference() error = %v", err)
	}
	defer accessor.Destroy()
	if anchored, err := client.RecordCredentialAnchor(context.Background(), lease, started.Credential, accessor); err != nil || anchored.Status != "ANCHORED" {
		t.Fatalf("RecordCredentialAnchor() = %#v, %v", anchored, err)
	}
	if active, err := client.ActivateCredential(context.Background(), lease, started.Credential); err != nil || active.Status != "ACTIVE" {
		t.Fatalf("ActivateCredential() = %#v, %v", active, err)
	}
	mismatched := executorBinding
	mismatched.JobID = "different-ready-action"
	if _, cancel, err := started.Grant.BindExecutor(context.Background(), mismatched); !errors.Is(err, runnerclient.ErrInvalidResponse) || cancel != nil {
		t.Fatalf("BindExecutor(cross-job) = cancel=%#v, error=%v", cancel, err)
	}
	grantContext, grantCancel, err := started.Grant.BindExecutor(context.Background(), executorBinding)
	if err != nil || grantContext == nil || grantCancel == nil {
		t.Fatalf("BindExecutor(ACTIVE) = %#v, %#v, %v", grantContext, grantCancel, err)
	}
	grantCancel()
	heartbeat, err := client.HeartbeatJob(context.Background(), lease, 1)
	if err != nil || heartbeat.Directive != "CONTINUE" || heartbeat.AcceptedSequence.Int64() != 1 {
		t.Fatalf("HeartbeatJob() = %#v, %v", heartbeat, err)
	}
	completed, err := client.CompleteJob(context.Background(), lease, execution.ExecutorResult{
		Outcome: execution.ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: execution.VerificationPassed, Changed: true,
	})
	if err != nil || completed.Status != "FINALIZING" || completed.CompletionStatus != "SUCCEEDED" {
		t.Fatalf("CompleteJob() = %#v, %v", completed, err)
	}
	if step != 7 {
		t.Fatalf("protocol steps = %d, want 7", step)
	}
}

func TestClientRunsRevocationProtocolWithoutRenderingClaimSecrets(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	const (
		claimToken  = "revocation-claim-token-canary-0123456789abcdef"
		revocation  = "123e4567-e89b-42d3-a456-426614174001"
		tenantID    = "123e4567-e89b-42d3-a456-426614174002"
		workspaceID = "123e4567-e89b-42d3-a456-426614174003"
		environment = "123e4567-e89b-42d3-a456-426614174004"
	)
	accessorBytes := []byte("revocation-accessor-canary")
	step := 0
	fixture := newGatewayFixture(t, runneridentity.PoolWrite, func(writer http.ResponseWriter, request *http.Request) {
		step++
		if step == 1 {
			if request.URL.Path != "/runner/v1/revocations:lease" || request.Header.Get("Authorization") != "" {
				t.Fatalf("revocation lease request = %s auth=%q", request.URL.Path, request.Header.Get("Authorization"))
			}
			writeJSON(t, writer, http.StatusOK, map[string]any{
				"schema_version": "runner-revocation-lease-response.v1", "revocation_id": revocation,
				"claim_token": claimToken, "claim_epoch": "2", "claim_expires_at": now.Add(30 * time.Second),
				"heartbeat_after_seconds": 10, "tenant_id": tenantID, "workspace_id": workspaceID,
				"environment_id": environment, "issuer_id": "vault-staging", "issuer_revision": "revision-7",
				"revoke_accessor_b64u": base64.RawURLEncoding.EncodeToString(accessorBytes),
			})
			return
		}
		if request.Header.Get("Authorization") != "AIOPS-Revocation-Lease "+claimToken {
			t.Fatalf("step %d Authorization was not the private revocation claim", step)
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatalf("decode revocation body: %v", err)
		}
		switch step {
		case 2:
			if body["sequence"] != "1" {
				t.Fatalf("revocation heartbeat body = %#v", body)
			}
			writeJSON(t, writer, http.StatusOK, map[string]any{
				"schema_version": "runner-revocation-heartbeat-response.v1", "revocation_id": revocation,
				"accepted_sequence": "1", "directive": "CONTINUE", "claim_expires_at": now.Add(30 * time.Second),
				"heartbeat_after_seconds": 10,
			})
		case 3:
			if body["outcome"] != "REVOKED" {
				t.Fatalf("revocation completion body = %#v", body)
			}
			writeJSON(t, writer, http.StatusOK, map[string]any{
				"schema_version": "runner-revocation-completion-response.v1", "revocation_id": revocation,
				"status": "REVOKED", "claim_epoch": "2",
			})
		default:
			t.Fatalf("unexpected revocation step %d", step)
		}
	})
	client, err := runnerclient.New(fixture.options)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(client.CloseIdleConnections)
	claim, err := client.LeaseRevocation(context.Background())
	if err != nil {
		t.Fatalf("LeaseRevocation() error = %v", err)
	}
	accessorMatched := false
	if claim != nil {
		if err := claim.WithRevokeAccessor(func(value []byte) error {
			accessorMatched = bytes.Equal(value, accessorBytes)
			return nil
		}); err != nil {
			t.Fatalf("WithRevokeAccessor() error = %v", err)
		}
	}
	if claim == nil || claim.RevocationID() != revocation || claim.ClaimEpoch() != 2 || !accessorMatched {
		t.Fatalf("LeaseRevocation() = %#v", claim)
	}
	encoded, err := json.Marshal(claim)
	if err != nil {
		t.Fatalf("Marshal(claim) error = %v", err)
	}
	for _, rendering := range []string{string(encoded), fmt.Sprint(claim), fmt.Sprintf("%#v", claim)} {
		if strings.Contains(rendering, claimToken) || strings.Contains(rendering, string(accessorBytes)) {
			t.Fatalf("revocation rendering leaked secret: %s", rendering)
		}
	}
	if heartbeat, err := client.HeartbeatRevocation(context.Background(), claim, 1); err != nil || heartbeat.Directive != "CONTINUE" {
		t.Fatalf("HeartbeatRevocation() = %#v, %v", heartbeat, err)
	}
	if completed, err := client.CompleteRevocation(
		context.Background(), claim, credential.RunnerRevocationRevoked, "",
	); err != nil || completed.Status != "REVOKED" {
		t.Fatalf("CompleteRevocation() = %#v, %v", completed, err)
	}
	claim.Destroy()
}

func TestReleaseJobConsumesLeaseAndAcceptsOnlyFixedPreStartReason(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	envelope := sealedRestartEnvelope(t, now)
	const token = "job-release-token-canary-0123456789abcdef"
	step := 0
	fixture := newGatewayFixture(t, runneridentity.PoolWrite, func(writer http.ResponseWriter, request *http.Request) {
		step++
		if step == 1 {
			writeJSON(t, writer, http.StatusOK, map[string]any{
				"schema_version": "runner-job-lease-response.v1",
				"job": map[string]any{"id": envelope.ActionID, "kind": "WRITE_ACTION", "payload": envelope,
					"plan_hash": envelope.PlanHash, "environment_revision": "environment-revision-7", "production": false},
				"lease_token": token, "lease_epoch": "4", "scope_revision": "7",
				"lease_expires_at": now.Add(30 * time.Second), "heartbeat_after_seconds": 10,
			})
			return
		}
		if step != 2 || request.URL.Path != "/runner/v1/jobs/"+envelope.ActionID+":release" ||
			request.Header.Get("Authorization") != "AIOPS-Job-Lease "+token {
			t.Fatalf("release request step=%d path=%s", step, request.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body["reason_code"] != "EXECUTOR_NOT_READY" {
			t.Fatalf("release body = %#v, %v", body, err)
		}
		writeJSON(t, writer, http.StatusOK, map[string]any{
			"schema_version": "runner-job-state-response.v1", "job_id": envelope.ActionID,
			"status": "QUEUED", "lease_epoch": "4",
		})
	})
	client, err := runnerclient.New(fixture.options)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(client.CloseIdleConnections)
	lease, err := client.LeaseJob(context.Background())
	if err != nil {
		t.Fatalf("LeaseJob() error = %v", err)
	}
	if state, err := client.ReleaseJob(context.Background(), lease, runnerclient.ReleaseExecutorNotReady); err != nil || state.Status != "QUEUED" {
		t.Fatalf("ReleaseJob() = %#v, %v", state, err)
	}
	if _, err := client.HeartbeatJob(context.Background(), lease, 1); !errors.Is(err, runnerclient.ErrSensitiveDestroyed) {
		t.Fatalf("HeartbeatJob(after release) error = %v", err)
	}
	if step != 2 {
		t.Fatalf("requests = %d, want 2", step)
	}
}

func TestIdentityRejectsNonCanonicalOrUnboundedGatewayResponses(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(http.ResponseWriter, []byte)
	}{
		{name: "duplicate field", mutate: func(writer http.ResponseWriter, body []byte) {
			body = bytes.Replace(body, []byte(`"runner_id":"`), []byte(`"runner_id":"duplicate","runner_id":"`), 1)
			writeRawGatewayResponse(writer, "application/json", body, true)
		}},
		{name: "unknown field", mutate: func(writer http.ResponseWriter, body []byte) {
			body[len(body)-1] = ','
			body = append(body, []byte(`"unexpected":true}`)...)
			writeRawGatewayResponse(writer, "application/json", body, true)
		}},
		{name: "trailing JSON", mutate: func(writer http.ResponseWriter, body []byte) {
			writeRawGatewayResponse(writer, "application/json", append(body, []byte(`{}`)...), true)
		}},
		{name: "missing no-store", mutate: func(writer http.ResponseWriter, body []byte) {
			writeRawGatewayResponse(writer, "application/json", body, false)
		}},
		{name: "content type parameter", mutate: func(writer http.ResponseWriter, body []byte) {
			writeRawGatewayResponse(writer, "application/json; charset=utf-8", body, true)
		}},
		{name: "oversized", mutate: func(writer http.ResponseWriter, body []byte) {
			body[len(body)-1] = ','
			body = append(body, []byte(`"padding":"`)...)
			body = append(body, bytes.Repeat([]byte("a"), 64<<10)...)
			body = append(body, []byte(`"}`)...)
			writeRawGatewayResponse(writer, "application/json", body, true)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var fixture *gatewayFixture
			fixture = newGatewayFixture(t, runneridentity.PoolWrite, func(writer http.ResponseWriter, _ *http.Request) {
				body, err := json.Marshal(map[string]any{
					"schema_version": "runner-identity-response.v1", "runner_id": fixtureRunnerID, "pool": "WRITE",
					"scope_revision": "7", "max_concurrency": 2, "capabilities": []string{},
					"certificate_sha256": fixture.clientFingerprint, "certificate_not_after": fixture.clientNotAfter,
				})
				if err != nil {
					t.Fatalf("Marshal(identity) error = %v", err)
				}
				test.mutate(writer, body)
			})
			client, err := runnerclient.New(fixture.options)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			t.Cleanup(client.CloseIdleConnections)
			if _, err := client.Identity(context.Background()); !errors.Is(err, runnerclient.ErrInvalidResponse) {
				t.Fatalf("Identity() error = %v, want ErrInvalidResponse", err)
			}
		})
	}
}

const fixtureRunnerID = "runner-write-01"

type gatewayFixture struct {
	options           runnerclient.Options
	server            *httptest.Server
	clientFingerprint string
	clientNotAfter    time.Time
}

func newGatewayFixture(t *testing.T, pool runneridentity.Pool, handler http.HandlerFunc) *gatewayFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	serverAuthority, err := testpki.NewAuthority("runner-gateway-server-root", now)
	if err != nil {
		t.Fatalf("NewAuthority(server) error = %v", err)
	}
	clientAuthority, err := testpki.NewAuthority("runner-client-root", now)
	if err != nil {
		t.Fatalf("NewAuthority(client) error = %v", err)
	}
	serverCertificate, err := serverAuthority.IssueServer("runner-gateway.test", now)
	if err != nil {
		t.Fatalf("IssueServer() error = %v", err)
	}
	poolSegment := "read"
	if pool == runneridentity.PoolWrite {
		poolSegment = "write"
	}
	spiffe, err := url.Parse("spiffe://aiops.test/runner/" + poolSegment + "/" + fixtureRunnerID)
	if err != nil {
		t.Fatalf("parse SPIFFE URI: %v", err)
	}
	clientCertificate, err := clientAuthority.IssueClient(testpki.ClientOptions{URIs: []*url.URL{spiffe}}, now)
	if err != nil {
		t.Fatalf("IssueClient() error = %v", err)
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

	root := t.TempDir()
	rootCAFile := filepath.Join(root, "server-root.pem")
	clientCertificateFile := filepath.Join(root, "runner-chain.pem")
	clientPrivateKeyFile := filepath.Join(root, "runner-key.pem")
	writePEMFile(t, rootCAFile, "CERTIFICATE", serverAuthority.Certificate.Raw, 0o600)
	writeCertificateChain(t, clientCertificateFile, clientCertificate.TLS.Certificate)
	privateKey, ok := clientCertificate.TLS.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("client private key type = %T", clientCertificate.TLS.PrivateKey)
	}
	encodedKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}
	writePEMFile(t, clientPrivateKeyFile, "PRIVATE KEY", encodedKey, 0o600)

	fingerprint := x509SHA256(clientCertificate.Leaf.Raw)
	return &gatewayFixture{
		options: runnerclient.Options{
			BaseURL: server.URL, ServerName: "runner-gateway.test", TrustDomain: "aiops.test", ExpectedPool: pool,
			RootCAFile: rootCAFile, ClientCertificateFile: clientCertificateFile, ClientPrivateKeyFile: clientPrivateKeyFile,
		},
		server: server, clientFingerprint: fingerprint, clientNotAfter: clientCertificate.Leaf.NotAfter.UTC(),
	}
}

func writeJSON(t *testing.T, writer http.ResponseWriter, status int, value any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	if _, err := writer.Write(encoded); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
}

func credentialStateResponse(jobID, revocationID, status string) map[string]any {
	return map[string]any{
		"schema_version": "runner-credential-anchor-response.v1", "job_id": jobID,
		"revocation_id": revocationID, "status": status,
	}
}

func writeRawGatewayResponse(writer http.ResponseWriter, contentType string, body []byte, noStore bool) {
	if noStore {
		writer.Header().Set("Cache-Control", "no-store")
	}
	writer.Header().Set("Content-Type", contentType)
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(body)
}

func writeCertificateChain(t *testing.T, path string, chain [][]byte) {
	t.Helper()
	contents := make([]byte, 0)
	for _, certificate := range chain {
		contents = append(contents, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})...)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write certificate chain: %v", err)
	}
}

func writePEMFile(t *testing.T, path, blockType string, contents []byte, mode os.FileMode) {
	t.Helper()
	encoded := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: contents})
	if err := os.WriteFile(path, encoded, mode); err != nil {
		t.Fatalf("write PEM file: %v", err)
	}
}

func x509SHA256(value []byte) string {
	hash := sha256.Sum256(value)
	return hex.EncodeToString(hash[:])
}

func sealedRestartEnvelope(t *testing.T, now time.Time) action.Envelope {
	t.Helper()
	envelope := action.Envelope{
		SchemaVersion: action.SchemaVersionV1, ActionID: "action-runner-client-01", WorkspaceID: "workspace-01",
		IncidentID: "incident-01", RequestedBy: "requester-01", ActionType: action.ActionKubernetesRolloutRestart,
		Target: action.TargetRef{ServiceID: "service-payments", EnvironmentID: "staging", KubernetesDeployment: &action.KubernetesDeploymentTarget{
			ClusterID: "cluster-a", Namespace: "payments", Name: "payments-api", UID: "uid-01", ResourceVersion: "83",
		}},
		Parameters: action.ActionParameters{KubernetesRolloutRestart: &action.KubernetesRolloutRestartParameters{Reason: "recover from deadlock"}},
		ObservedState: action.ObservedState{KubernetesDeployment: &action.KubernetesDeploymentObservedState{
			Generation: 17, Replicas: 3, AvailableReplicas: 3, UpdatedReplicas: 3,
		}},
		Preconditions: action.Preconditions{MappingResult: "EXACT", ExpectedResourceVersion: "83", RequireWhitelist: true},
		Verification:  action.VerificationPlan{Mode: "KUBERNETES_ROLLOUT", TimeoutSeconds: 300},
		Compensation:  action.CompensationPlan{Mode: "MANUAL_ONLY", Summary: "stop and follow the runbook"},
		Risk:          action.RiskAssessment{Level: "MEDIUM", ReasonCodes: []string{"NON_PRODUCTION", "RESTART"}},
		PolicyVersion: "policy.v1",
		CredentialScope: action.CredentialScope{
			ConnectorID: "kubernetes-staging", Permission: "PATCH_DEPLOYMENT_RESTART",
			Resource: "cluster-a/payments/deployment/payments-api", TTLSeconds: 600,
		},
		IdempotencyKey: "idem-runner-client-01", NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(15 * time.Minute),
		TraceID: strings.Repeat("a", 32),
	}
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	signer, err := action.NewEd25519Signer("runner-client-test-key", privateKey)
	if err != nil {
		t.Fatalf("NewEd25519Signer() error = %v", err)
	}
	sealed, err := action.Seal(context.Background(), envelope, envelope.RequestedBy, signer)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	return sealed
}
