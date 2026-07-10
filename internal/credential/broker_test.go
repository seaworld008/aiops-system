package credential

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aiops-system/control-plane/internal/action"
	"github.com/aiops-system/control-plane/internal/policy"
)

func TestBrokerReevaluatesPolicyAndCapsCredentialAtEnvelopeExpiry(t *testing.T) {
	t.Parallel()

	notBefore := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := sealedEnvelope(t, notBefore)
	now := envelope.ExpiresAt.Add(-time.Minute)
	gate := &fakeGate{decision: allowDecision(envelope, now)}
	issuer := &fakeIssuer{secret: []byte("ephemeral-secret"), expiresAt: envelope.ExpiresAt}
	broker, err := NewBroker(gate, issuer, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewBroker() error = %v", err)
	}

	credential, err := broker.Issue(context.Background(), envelope)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if gate.calls != 1 || issuer.request.TTL != time.Minute || !credential.ExpiresAt.Equal(envelope.ExpiresAt) {
		t.Fatalf("gate/issuer/credential = %d/%#v/%#v", gate.calls, issuer.request, credential)
	}
	if issuer.request.Permission != "PATCH_DEPLOYMENT_RESTART" || issuer.request.Resource != "cluster-a/payments/deployment/payments-api" {
		t.Fatalf("issuer scope = %#v", issuer.request)
	}
	if got := string(credential.Secret()); got != "ephemeral-secret" {
		t.Fatalf("Secret() = %q", got)
	}
	encoded, err := json.Marshal(credential)
	if err != nil {
		t.Fatalf("marshal credential metadata: %v", err)
	}
	if strings.Contains(string(encoded), "ephemeral") {
		t.Fatalf("credential JSON leaked secret: %s", encoded)
	}
	credential.Destroy()
	if len(credential.Secret()) != 0 {
		t.Fatal("Destroy() retained credential secret")
	}
}

func TestBrokerRejectsStaleOrMismatchedPolicyDecision(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := sealedEnvelope(t, now)
	tests := map[string]func(*policy.Decision){
		"deny":       func(decision *policy.Decision) { decision.Outcome = policy.OutcomeDeny },
		"wrong gate": func(decision *policy.Decision) { decision.Stage = policy.StagePlanSubmission },
		"wrong plan": func(decision *policy.Decision) { decision.PlanHash = strings.Repeat("0", 64) },
		"stale": func(decision *policy.Decision) {
			decision.EvaluatedAt = now.Add(-MaxPolicyDecisionAge - time.Nanosecond)
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			decision := allowDecision(envelope, now)
			mutate(&decision)
			issuer := &fakeIssuer{secret: []byte("secret"), expiresAt: decision.CredentialExpiresAt}
			broker, err := NewBroker(&fakeGate{decision: decision}, issuer, func() time.Time { return now })
			if err != nil {
				t.Fatalf("NewBroker() error = %v", err)
			}
			if _, err := broker.Issue(context.Background(), envelope); !errors.Is(err, ErrCredentialDenied) {
				t.Fatalf("Issue() error = %v, want ErrCredentialDenied", err)
			}
			if issuer.calls != 0 {
				t.Fatal("issuer called after invalid policy decision")
			}
		})
	}
}

func TestBrokerClassifiesPolicyAndIssuerOutagesAsUnavailable(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := sealedEnvelope(t, now)
	outage := errors.New("vault control plane unavailable")
	tests := map[string]struct {
		gate   *fakeGate
		issuer *fakeIssuer
	}{
		"policy evaluator outage": {
			gate:   &fakeGate{err: outage},
			issuer: &fakeIssuer{},
		},
		"dynamic issuer outage": {
			gate:   &fakeGate{decision: allowDecision(envelope, now)},
			issuer: &fakeIssuer{issueErr: outage},
		},
	}
	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			broker, err := NewBroker(test.gate, test.issuer, func() time.Time { return now })
			if err != nil {
				t.Fatalf("NewBroker() error = %v", err)
			}
			_, issueErr := broker.Issue(context.Background(), envelope)
			if !errors.Is(issueErr, ErrCredentialUnavailable) || errors.Is(issueErr, ErrCredentialDenied) {
				t.Fatalf("Issue() error = %v, want only ErrCredentialUnavailable", issueErr)
			}
		})
	}
}

func TestBrokerRevokesIssuerLeaseThatOutlivesRequestedBoundary(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := sealedEnvelope(t, now)
	decision := allowDecision(envelope, now)
	issuer := &fakeIssuer{secret: []byte("secret"), expiresAt: decision.CredentialExpiresAt.Add(time.Second)}
	broker, err := NewBroker(&fakeGate{decision: decision}, issuer, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewBroker() error = %v", err)
	}
	if _, err := broker.Issue(context.Background(), envelope); !errors.Is(err, ErrUnsafeCredentialLease) {
		t.Fatalf("Issue() error = %v, want ErrUnsafeCredentialLease", err)
	}
	if issuer.revokedLeaseID != "lease-1" {
		t.Fatalf("revoked lease = %q", issuer.revokedLeaseID)
	}
}

func TestBrokerRejectsIssuerLeaseIDContainingControlCharacters(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := sealedEnvelope(t, now)
	decision := allowDecision(envelope, now)
	issuer := &fakeIssuer{
		leaseID:   "lease-1\nforged-audit-line",
		secret:    []byte("secret"),
		expiresAt: decision.CredentialExpiresAt,
	}
	broker, err := NewBroker(&fakeGate{decision: decision}, issuer, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewBroker() error = %v", err)
	}
	if _, err := broker.Issue(context.Background(), envelope); !errors.Is(err, ErrUnsafeCredentialLease) {
		t.Fatalf("Issue() error = %v, want ErrUnsafeCredentialLease", err)
	}
	if issuer.revokedLeaseID != issuer.leaseID {
		t.Fatalf("revoked lease = %q, want %q", issuer.revokedLeaseID, issuer.leaseID)
	}
}

func TestBrokerRevokeClearsSecretBeforeRemoteCallAndIsIdempotent(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := sealedEnvelope(t, now)
	issuer := &fakeIssuer{secret: []byte("ephemeral-secret"), expiresAt: allowDecision(envelope, now).CredentialExpiresAt}
	broker, err := NewBroker(&fakeGate{decision: allowDecision(envelope, now)}, issuer, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewBroker() error = %v", err)
	}
	credential, err := broker.Issue(context.Background(), envelope)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	issuer.onRevoke = func() {
		if got := credential.Secret(); len(got) != 0 {
			t.Errorf("secret was still available during remote revoke: %q", got)
		}
	}

	if err := broker.Revoke(context.Background(), &credential); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if err := broker.Revoke(context.Background(), &credential); err != nil {
		t.Fatalf("second Revoke() error = %v", err)
	}
	if got := issuer.revokeCallCount(); got != 1 {
		t.Fatalf("remote revoke calls = %d, want 1", got)
	}
	if got := credential.Secret(); len(got) != 0 {
		t.Fatalf("Revoke() retained local secret: %q", got)
	}
}

func TestBrokerRevokeFailureClearsSecretAndCanBeRetriedSafely(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := sealedEnvelope(t, now)
	issuer := &fakeIssuer{
		secret:    []byte("ephemeral-secret"),
		expiresAt: allowDecision(envelope, now).CredentialExpiresAt,
		revokeErr: errors.New("vault unavailable"),
	}
	broker, err := NewBroker(&fakeGate{decision: allowDecision(envelope, now)}, issuer, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewBroker() error = %v", err)
	}
	credential, err := broker.Issue(context.Background(), envelope)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	if err := broker.Revoke(context.Background(), &credential); err == nil || !strings.Contains(err.Error(), "vault unavailable") {
		t.Fatalf("Revoke() error = %v, want issuer failure", err)
	}
	if got := credential.Secret(); len(got) != 0 {
		t.Fatalf("failed Revoke() retained local secret: %q", got)
	}
	if got := issuer.revokeCallCount(); got != 1 {
		t.Fatalf("remote revoke calls = %d, want 1", got)
	}

	issuer.setRevokeError(nil)
	if err := broker.Revoke(context.Background(), &credential); err != nil {
		t.Fatalf("retry Revoke() error = %v", err)
	}
	if err := broker.Revoke(context.Background(), &credential); err != nil {
		t.Fatalf("post-success Revoke() error = %v", err)
	}
	if got := issuer.revokeCallCount(); got != 2 {
		t.Fatalf("remote revoke calls after retry = %d, want 2", got)
	}
}

func TestBrokerRevokeCanRetryWithIndependentFinalizeContext(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := sealedEnvelope(t, now)
	issuer := &fakeIssuer{
		secret:         []byte("ephemeral-secret"),
		expiresAt:      allowDecision(envelope, now).CredentialExpiresAt,
		respectContext: true,
	}
	broker, err := NewBroker(&fakeGate{decision: allowDecision(envelope, now)}, issuer, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewBroker() error = %v", err)
	}
	credential, err := broker.Issue(context.Background(), envelope)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	if err := broker.Revoke(cancelled, &credential); !errors.Is(err, context.Canceled) {
		t.Fatalf("Revoke(cancelled) error = %v, want context.Canceled", err)
	}
	if err := broker.Revoke(context.Background(), &credential); err != nil {
		t.Fatalf("Revoke(finalize context) error = %v", err)
	}
	if got := issuer.revokeCallCount(); got != 2 {
		t.Fatalf("remote revoke calls = %d, want cancelled attempt plus retry", got)
	}
}

func TestBrokerRevokeRejectsUnmanagedAndTamperedCredentialsFailClosed(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := sealedEnvelope(t, now)
	issuer := &fakeIssuer{secret: []byte("ephemeral-secret"), expiresAt: allowDecision(envelope, now).CredentialExpiresAt}
	broker, err := NewBroker(&fakeGate{decision: allowDecision(envelope, now)}, issuer, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewBroker() error = %v", err)
	}

	invalid := []*Credential{
		nil,
		{},
		{LeaseID: "forged-lease", ExpiresAt: now.Add(time.Minute)},
	}
	for index, credential := range invalid {
		if err := broker.Revoke(context.Background(), credential); !errors.Is(err, ErrInvalidCredential) {
			t.Errorf("Revoke(invalid[%d]) error = %v, want ErrInvalidCredential", index, err)
		}
	}
	if got := issuer.revokeCallCount(); got != 0 {
		t.Fatalf("issuer called for unmanaged credential %d times", got)
	}

	credential, err := broker.Issue(context.Background(), envelope)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	credential.LeaseID = "tampered-lease"
	if err := broker.Revoke(context.Background(), &credential); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("Revoke(tampered) error = %v, want ErrInvalidCredential", err)
	}
	if got := credential.Secret(); len(got) != 0 {
		t.Fatalf("tampered credential retained local secret: %q", got)
	}
	if got := issuer.revokeCallCount(); got != 0 {
		t.Fatalf("issuer called for tampered credential %d times", got)
	}
}

func TestBrokerConcurrentRevokeUsesOneRemoteCallAcrossCredentialCopies(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := sealedEnvelope(t, now)
	issuer := &fakeIssuer{secret: []byte("ephemeral-secret"), expiresAt: allowDecision(envelope, now).CredentialExpiresAt}
	broker, err := NewBroker(&fakeGate{decision: allowDecision(envelope, now)}, issuer, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewBroker() error = %v", err)
	}
	credential, err := broker.Issue(context.Background(), envelope)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	const callers = 16
	start := make(chan struct{})
	errorsByCaller := make(chan error, callers)
	var waitGroup sync.WaitGroup
	for range callers {
		waitGroup.Add(1)
		credentialCopy := credential
		go func() {
			defer waitGroup.Done()
			<-start
			errorsByCaller <- broker.Revoke(context.Background(), &credentialCopy)
		}()
	}
	close(start)
	waitGroup.Wait()
	close(errorsByCaller)
	for err := range errorsByCaller {
		if err != nil {
			t.Errorf("concurrent Revoke() error = %v", err)
		}
	}
	if got := issuer.revokeCallCount(); got != 1 {
		t.Fatalf("remote revoke calls = %d, want 1", got)
	}
}

type fakeGate struct {
	decision policy.Decision
	err      error
	calls    int
}

func (gate *fakeGate) EvaluateCredentialIssue(context.Context, action.Envelope) (policy.Decision, error) {
	gate.calls++
	return gate.decision, gate.err
}

type fakeIssuer struct {
	mu             sync.Mutex
	request        IssueRequest
	leaseID        string
	secret         []byte
	expiresAt      time.Time
	revokedLeaseID string
	revokeCalls    int
	revokeErr      error
	onRevoke       func()
	respectContext bool
	calls          int
	issueErr       error
}

func (issuer *fakeIssuer) Issue(_ context.Context, request IssueRequest) (IssuedLease, error) {
	issuer.calls++
	issuer.request = request
	if issuer.issueErr != nil {
		return IssuedLease{}, issuer.issueErr
	}
	leaseID := issuer.leaseID
	if leaseID == "" {
		leaseID = "lease-1"
	}
	return IssuedLease{LeaseID: leaseID, Secret: append([]byte(nil), issuer.secret...), ExpiresAt: issuer.expiresAt}, nil
}

func (issuer *fakeIssuer) Revoke(ctx context.Context, leaseID string) error {
	issuer.mu.Lock()
	issuer.revokedLeaseID = leaseID
	issuer.revokeCalls++
	onRevoke := issuer.onRevoke
	revokeErr := issuer.revokeErr
	respectContext := issuer.respectContext
	issuer.mu.Unlock()
	if onRevoke != nil {
		onRevoke()
	}
	if respectContext && ctx.Err() != nil {
		return ctx.Err()
	}
	return revokeErr
}

func (issuer *fakeIssuer) revokeCallCount() int {
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	return issuer.revokeCalls
}

func (issuer *fakeIssuer) setRevokeError(err error) {
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	issuer.revokeErr = err
}

func allowDecision(envelope action.Envelope, now time.Time) policy.Decision {
	expiresAt := now.Add(time.Duration(envelope.CredentialScope.TTLSeconds) * time.Second)
	if expiresAt.After(envelope.ExpiresAt) {
		expiresAt = envelope.ExpiresAt
	}
	return policy.Decision{
		Outcome: policy.OutcomeAllow, Stage: policy.StageCredentialIssue,
		PolicyVersion: envelope.PolicyVersion, PlanHash: envelope.PlanHash,
		SafetyRevision: "safety-1", TargetRevision: "target-1", RiskRevision: "risk-1", LimitsRevision: "limits-1",
		EvaluatedAt: now, CredentialExpiresAt: expiresAt,
	}
}

func sealedEnvelope(t *testing.T, now time.Time) action.Envelope {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := action.NewEd25519Signer("credential-test-key", privateKey)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	envelope := action.Envelope{
		SchemaVersion: action.SchemaVersionV1, ActionID: "action-1", WorkspaceID: "workspace-1", IncidentID: "incident-1", RequestedBy: "requester-1",
		ActionType: action.ActionKubernetesRolloutRestart,
		Target: action.TargetRef{ServiceID: "service-payments", EnvironmentID: "PROD", KubernetesDeployment: &action.KubernetesDeploymentTarget{
			ClusterID: "cluster-a", Namespace: "payments", Name: "payments-api", UID: "uid-1", ResourceVersion: "83",
		}},
		Parameters:    action.ActionParameters{KubernetesRolloutRestart: &action.KubernetesRolloutRestartParameters{Reason: "confirmed deadlock"}},
		ObservedState: action.ObservedState{KubernetesDeployment: &action.KubernetesDeploymentObservedState{Generation: 4, Replicas: 3, AvailableReplicas: 3, UpdatedReplicas: 3}},
		Preconditions: action.Preconditions{MappingResult: "EXACT", ExpectedResourceVersion: "83", RequireWhitelist: true},
		Verification:  action.VerificationPlan{Mode: "KUBERNETES_ROLLOUT", TimeoutSeconds: 300},
		Compensation:  action.CompensationPlan{Mode: "MANUAL_ONLY", Summary: "follow runbook"},
		Risk:          action.RiskAssessment{Level: "MEDIUM", ReasonCodes: []string{"PRODUCTION_CHANGE", "RESTART"}},
		PolicyVersion: "policy.v1", CredentialScope: action.CredentialScope{
			ConnectorID: "kubernetes-prod", Permission: "PATCH_DEPLOYMENT_RESTART", Resource: "cluster-a/payments/deployment/payments-api", TTLSeconds: 600,
		},
		IdempotencyKey: "idem-action-1", NotBefore: now, ExpiresAt: now.Add(30 * time.Minute), TraceID: strings.Repeat("a", 32),
	}
	sealed, err := action.Seal(context.Background(), envelope, envelope.RequestedBy, signer)
	if err != nil {
		t.Fatalf("seal envelope: %v", err)
	}
	return sealed
}
