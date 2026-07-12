package readtask_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/readtask"
)

const (
	testTaskID   = "11111111-1111-4111-8111-111111111111"
	testRunnerID = "read/pool.runner-1"
	testToken    = "abcdefghijklmnopqrstuvwxyz_ABCDE-0123456789"
)

func TestFenceKeepsBearerOpaqueAndDestroyable(t *testing.T) {
	fence, err := readtask.NewFence(testTaskID, testRunnerID, []byte(testToken), 7)
	if err != nil {
		t.Fatalf("NewFence() error = %v", err)
	}
	if fence.TaskID() != testTaskID || fence.RunnerID() != testRunnerID || fence.Epoch() != 7 ||
		!fence.MatchesTokenSHA256(fence.TokenSHA256()) {
		t.Fatalf("Fence binding is invalid: task=%q runner=%q epoch=%d", fence.TaskID(), fence.RunnerID(), fence.Epoch())
	}
	copyOfToken, err := fence.TokenBytes()
	if err != nil || string(copyOfToken) != testToken {
		t.Fatalf("TokenBytes() = %q, %v", copyOfToken, err)
	}
	copyOfToken[0] = 'X'
	secondCopy, err := fence.TokenBytes()
	if err != nil || string(secondCopy) != testToken {
		t.Fatal("TokenBytes() exposed shared mutable bearer state")
	}

	encoded, err := json.Marshal(fence)
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	for _, rendered := range [][]byte{encoded, []byte(fence.String()), []byte(fmt.Sprintf("%#v", fence))} {
		if bytes.Contains(rendered, []byte(testToken)) || bytes.Contains(rendered, secondCopy) {
			t.Fatalf("Fence rendering leaked bearer: %s", rendered)
		}
	}

	fence.Destroy()
	if _, err := fence.TokenBytes(); err == nil || fence.Valid() {
		t.Fatal("destroyed Fence remained usable")
	}
}

func TestClaimBindsValidatedDescriptorAttemptCertificateAndBearer(t *testing.T) {
	now := time.Date(2026, 7, 12, 8, 0, 0, 0, time.UTC)
	descriptor := validDescriptor(t)
	tokenDigest := sha256.Sum256([]byte(testToken))
	attempt := readtask.Attempt{
		TaskID: descriptor.TaskID, RunnerID: testRunnerID, ScopeRevision: 3,
		Certificate: readtask.CertificateBinding{SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte("certificate"))), NotAfter: now.Add(time.Minute)},
		TokenSHA256: fmt.Sprintf("%x", tokenDigest), Epoch: 7, Status: readtask.AttemptLeased,
		LeaseAcquiredAt: now, LastHeartbeatAt: now, LeaseExpiresAt: now.Add(30 * time.Second), UpdatedAt: now,
	}
	claim, err := readtask.NewClaim(descriptor, attempt, []byte(testToken))
	if err != nil {
		t.Fatalf("NewClaim() error = %v", err)
	}
	if !claim.Valid() || claim.TokenSHA256() != attempt.TokenSHA256 || claim.Attempt().Epoch != attempt.Epoch {
		t.Fatalf("Claim is not bound to attempt: %#v", claim.Attempt())
	}
	claimedDescriptor := claim.Descriptor()
	claimedDescriptor.Input[1] = 'X'
	if bytes.Equal(claim.Descriptor().Input, claimedDescriptor.Input) {
		t.Fatal("Descriptor() exposed shared input bytes")
	}
	fence := claim.Fence()
	if !fence.Valid() || fence.TaskID() != descriptor.TaskID || fence.RunnerID() != attempt.RunnerID {
		t.Fatal("Claim.Fence() lost the trusted binding")
	}
	encoded, err := json.Marshal(claim)
	if err != nil || bytes.Contains(encoded, []byte(testToken)) {
		t.Fatalf("Claim JSON leaked bearer: %s, %v", encoded, err)
	}

	attempt.LeaseExpiresAt = attempt.Certificate.NotAfter.Add(time.Nanosecond)
	if _, err := readtask.NewClaim(descriptor, attempt, []byte(testToken)); err == nil {
		t.Fatal("NewClaim() accepted lease beyond certificate expiry")
	}
}

func TestDescriptorAttemptAndFenceRejectUntrustedPersistentFacts(t *testing.T) {
	descriptor := validDescriptor(t)
	for name, mutate := range map[string]func(*readtask.Descriptor){
		"non persistent UUID": func(value *readtask.Descriptor) { value.TaskID = "TASK-1" },
		"input hash mismatch": func(value *readtask.Descriptor) { value.InputHash = fmt.Sprintf("%x", sha256.Sum256([]byte("other"))) },
		"non canonical input with matching raw hash": func(value *readtask.Descriptor) {
			value.Input = json.RawMessage(`{"window_seconds":300,"query":"health"}`)
			value.InputHash = fmt.Sprintf("%x", sha256.Sum256(value.Input))
		},
		"sensitive input": func(value *readtask.Descriptor) {
			value.Input = json.RawMessage(`{"authorization":"Bearer raw-secret"}`)
			digest := sha256.Sum256(value.Input)
			value.InputHash = fmt.Sprintf("%x", digest)
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutated := descriptor
			mutate(&mutated)
			if err := mutated.Validate(); err == nil {
				t.Fatal("Descriptor.Validate() accepted untrusted fact")
			}
		})
	}
	if _, err := readtask.NewFence(testTaskID, testRunnerID, []byte("short"), 1); err == nil {
		t.Fatal("NewFence() accepted a weak bearer")
	}
	for name, token := range map[string]string{
		"only 192 bits when base64url decoded": "abcdefghijklmnopqrstuvwxyz_ABCDE",
		"padded encoding":                      testToken + "=",
		"invalid alphabet":                     testToken[:42] + "+",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readtask.NewFence(testTaskID, testRunnerID, []byte(token), 1); err == nil {
				t.Fatal("NewFence() accepted a non-canonical 256-bit bearer")
			}
		})
	}
}

func validDescriptor(t *testing.T) readtask.Descriptor {
	t.Helper()
	input := json.RawMessage(`{"query":"health","window_seconds":300}`)
	digest := sha256.Sum256(input)
	descriptor := readtask.Descriptor{
		TenantID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", WorkspaceID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		EnvironmentID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", IncidentID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
		InvestigationID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", TaskID: testTaskID,
		TaskKey: "service.health", Position: 1, ConnectorID: "prometheus", Operation: "query_range",
		Input: input, InputHash: fmt.Sprintf("%x", digest),
	}
	if err := descriptor.Validate(); err != nil {
		t.Fatalf("valid Descriptor.Validate() error = %v", err)
	}
	return descriptor
}
