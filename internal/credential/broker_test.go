package credential

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
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
	request        IssueRequest
	leaseID        string
	secret         []byte
	expiresAt      time.Time
	revokedLeaseID string
	calls          int
}

func (issuer *fakeIssuer) Issue(_ context.Context, request IssueRequest) (IssuedLease, error) {
	issuer.calls++
	issuer.request = request
	leaseID := issuer.leaseID
	if leaseID == "" {
		leaseID = "lease-1"
	}
	return IssuedLease{LeaseID: leaseID, Secret: append([]byte(nil), issuer.secret...), ExpiresAt: issuer.expiresAt}, nil
}

func (issuer *fakeIssuer) Revoke(_ context.Context, leaseID string) error {
	issuer.revokedLeaseID = leaseID
	return nil
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
