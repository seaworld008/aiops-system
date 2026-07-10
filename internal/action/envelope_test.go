package action

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSealAndVerifyDetectsPlanTampering(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := NewEd25519Signer("control-plane-2026-07", privateKey)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	keys := StaticKeySet{
		"control-plane-2026-07": {PublicKey: publicKey},
	}
	now := time.Date(2026, 7, 10, 8, 0, 0, 0, time.UTC)

	sealed, err := Seal(context.Background(), validRestartEnvelope(now), signer)
	if err != nil {
		t.Fatalf("seal envelope: %v", err)
	}
	if len(sealed.PlanHash) != 64 {
		t.Fatalf("plan hash length = %d, want 64", len(sealed.PlanHash))
	}
	if sealed.Signature.Algorithm != SignatureEd25519 || sealed.Signature.KeyID != "control-plane-2026-07" || sealed.Signature.Value == "" {
		t.Fatalf("unexpected signature metadata: %+v", sealed.Signature)
	}
	if err := Verify(context.Background(), sealed, keys, now); err != nil {
		t.Fatalf("verify sealed envelope: %v", err)
	}

	tests := map[string]func(*Envelope){
		"target resource version": func(envelope *Envelope) {
			envelope.Target.KubernetesDeployment.ResourceVersion = "84"
		},
		"parameter": func(envelope *Envelope) {
			envelope.Parameters.KubernetesRolloutRestart.Reason = "different reason"
		},
		"observed state": func(envelope *Envelope) {
			envelope.ObservedState.KubernetesDeployment.AvailableReplicas = 1
		},
		"policy version": func(envelope *Envelope) {
			envelope.PolicyVersion = "policy.v2"
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			tampered, err := Seal(context.Background(), validRestartEnvelope(now), signer)
			if err != nil {
				t.Fatalf("seal tamper candidate: %v", err)
			}
			mutate(&tampered)
			if err := Verify(context.Background(), tampered, keys, now); !errors.Is(err, ErrPlanHashMismatch) {
				t.Fatalf("verify error = %v, want ErrPlanHashMismatch", err)
			}
		})
	}
}

func TestSealIsDeterministicForSameEnvelopeAndKey(t *testing.T) {
	t.Parallel()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := NewEd25519Signer("key-1", privateKey)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	now := time.Date(2026, 7, 10, 8, 0, 0, 0, time.UTC)

	first, err := Seal(context.Background(), validRestartEnvelope(now), signer)
	if err != nil {
		t.Fatalf("first seal: %v", err)
	}
	second, err := Seal(context.Background(), validRestartEnvelope(now), signer)
	if err != nil {
		t.Fatalf("second seal: %v", err)
	}
	if first.PlanHash != second.PlanHash || first.Signature != second.Signature {
		t.Fatalf("sealing was not deterministic:\nfirst=%+v\nsecond=%+v", first, second)
	}
}

func TestVerifyRejectsExpiredUnknownAndRevokedKeys(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := NewEd25519Signer("key-1", privateKey)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	now := time.Date(2026, 7, 10, 8, 0, 0, 0, time.UTC)
	sealed, err := Seal(context.Background(), validRestartEnvelope(now), signer)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	if err := Verify(context.Background(), sealed, StaticKeySet{"key-1": {PublicKey: publicKey}}, sealed.ExpiresAt); !errors.Is(err, ErrEnvelopeExpired) {
		t.Fatalf("expired verify error = %v, want ErrEnvelopeExpired", err)
	}
	if err := Verify(context.Background(), sealed, StaticKeySet{}, now); !errors.Is(err, ErrUnknownSigningKey) {
		t.Fatalf("unknown key error = %v, want ErrUnknownSigningKey", err)
	}
	if err := Verify(context.Background(), sealed, StaticKeySet{"key-1": {PublicKey: publicKey, Revoked: true}}, now); !errors.Is(err, ErrSigningKeyRevoked) {
		t.Fatalf("revoked key error = %v, want ErrSigningKeyRevoked", err)
	}
}

func TestValidateRejectsUnsafeOrMismatchedActions(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 8, 0, 0, 0, time.UTC)
	tests := map[string]struct {
		mutate func(*Envelope)
		want   string
	}{
		"unknown action type": {
			mutate: func(envelope *Envelope) { envelope.ActionType = ActionType("ARBITRARY_SHELL") },
			want:   "unsupported action type",
		},
		"mismatched parameter union": {
			mutate: func(envelope *Envelope) {
				envelope.Parameters.KubernetesRolloutRestart = nil
				envelope.Parameters.KubernetesScale = &KubernetesScaleParameters{Replicas: 3, Minimum: 1, Maximum: 5}
			},
			want: "parameters do not match action type",
		},
		"multiple targets": {
			mutate: func(envelope *Envelope) {
				envelope.Target.GitOpsApplication = &GitOpsTarget{RepositoryID: "repo-1", Application: "payments"}
			},
			want: "exactly one target",
		},
		"approval window too long": {
			mutate: func(envelope *Envelope) { envelope.ExpiresAt = envelope.NotBefore.Add(31 * time.Minute) },
			want:   "validity window",
		},
		"credential ttl too long": {
			mutate: func(envelope *Envelope) { envelope.CredentialScope.TTLSeconds = 901 },
			want:   "credential ttl",
		},
	}

	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			envelope := validRestartEnvelope(now)
			test.mutate(&envelope)
			if err := envelope.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestGitOpsRevertBindsImmutableRevisions(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 8, 0, 0, 0, time.UTC)
	envelope := validRestartEnvelope(now)
	envelope.ActionType = ActionGitOpsRevert
	envelope.Target = TargetRef{ServiceID: "service-payments", EnvironmentID: "PROD", GitOpsApplication: &GitOpsTarget{
		RepositoryID: "gitops-prod", Application: "payments", Path: "apps/payments",
	}}
	envelope.Parameters = ActionParameters{GitOpsRevert: &GitOpsRevertParameters{
		Provider: "GITLAB", BaseCommit: strings.Repeat("a", 40), HeadCommit: strings.Repeat("b", 40),
		RevertCommit: strings.Repeat("c", 40), DiffSHA256: strings.Repeat("d", 64), TreeSHA256: strings.Repeat("e", 64),
	}}
	envelope.ObservedState = ObservedState{GitOpsApplication: &GitOpsObservedState{
		LiveRevision: strings.Repeat("b", 40), DesiredRevision: strings.Repeat("b", 40), SyncStatus: "SYNCED", HealthStatus: "HEALTHY",
	}}
	envelope.Preconditions.ExpectedResourceVersion = ""
	envelope.Preconditions.ExpectedGitHeadCommit = strings.Repeat("b", 40)
	envelope.Verification = VerificationPlan{Mode: "ARGO_CD_HEALTH", TimeoutSeconds: 300}
	envelope.CredentialScope = CredentialScope{ConnectorID: "gitlab-prod", Permission: "CREATE_REVERT_MR", Resource: "gitops-prod", TTLSeconds: 600}

	if err := envelope.Validate(); err != nil {
		t.Fatalf("valid GitOps envelope: %v", err)
	}
	for _, field := range []string{"base", "head", "revert", "diff", "tree"} {
		candidate := envelope
		parameters := *candidate.Parameters.GitOpsRevert
		candidate.Parameters.GitOpsRevert = &parameters
		switch field {
		case "base":
			parameters.BaseCommit = ""
		case "head":
			parameters.HeadCommit = ""
		case "revert":
			parameters.RevertCommit = ""
		case "diff":
			parameters.DiffSHA256 = ""
		case "tree":
			parameters.TreeSHA256 = ""
		}
		if err := candidate.Validate(); err == nil {
			t.Fatalf("missing %s revision binding was accepted", field)
		}
	}
}

func TestKubernetesScaleRequiresNoHPAAndBoundedSafetyChecks(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 8, 0, 0, 0, time.UTC)
	envelope := validRestartEnvelope(now)
	envelope.ActionType = ActionKubernetesScale
	envelope.Parameters = ActionParameters{KubernetesScale: &KubernetesScaleParameters{
		Replicas: 5, Minimum: 2, Maximum: 8, HPAAbsent: true, PDBChecked: true, QuotaChecked: true,
	}}
	if err := envelope.Validate(); err != nil {
		t.Fatalf("valid Kubernetes scale envelope: %v", err)
	}

	tests := map[string]func(*KubernetesScaleParameters){
		"HPA present":        func(parameters *KubernetesScaleParameters) { parameters.HPAAbsent = false },
		"PDB unchecked":      func(parameters *KubernetesScaleParameters) { parameters.PDBChecked = false },
		"quota unchecked":    func(parameters *KubernetesScaleParameters) { parameters.QuotaChecked = false },
		"below signed bound": func(parameters *KubernetesScaleParameters) { parameters.Replicas = 1 },
		"above signed bound": func(parameters *KubernetesScaleParameters) { parameters.Replicas = 9 },
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			candidate := envelope
			parameters := *candidate.Parameters.KubernetesScale
			candidate.Parameters.KubernetesScale = &parameters
			mutate(&parameters)
			if err := candidate.Validate(); err == nil {
				t.Fatal("unsafe scale plan was accepted")
			}
		})
	}
}

func TestAWXRestartAllowsOnlyTypedLinuxOrWindowsService(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 8, 0, 0, 0, time.UTC)
	for _, osFamily := range []string{"LINUX_SYSTEMD", "WINDOWS_SERVICE"} {
		envelope := validRestartEnvelope(now)
		envelope.ActionType = ActionAWXServiceRestart
		envelope.Target = TargetRef{ServiceID: "service-payments", EnvironmentID: "PROD", AWXHosts: &AWXTarget{
			InventoryID: 42, HostIDs: []int64{101, 102}, InventorySnapshotSHA256: strings.Repeat("f", 64),
		}}
		envelope.Parameters = ActionParameters{AWXServiceRestart: &AWXServiceRestartParameters{
			JobTemplateID: 81, ServiceName: "payments-api", OSFamily: osFamily, Serial: 1,
		}}
		envelope.ObservedState = ObservedState{AWXService: &AWXServiceObservedState{
			HostCount: 2, ServiceState: "RUNNING", InventorySnapshotSHA256: strings.Repeat("f", 64),
		}}
		envelope.Preconditions.ExpectedResourceVersion = ""
		envelope.Verification = VerificationPlan{Mode: "AWX_SERVICE_HEALTH", TimeoutSeconds: 300}
		envelope.CredentialScope = CredentialScope{ConnectorID: "awx-prod", Permission: "LAUNCH_SERVICE_RESTART_TEMPLATE", Resource: "inventory/42", TTLSeconds: 600}
		if err := envelope.Validate(); err != nil {
			t.Fatalf("valid %s AWX envelope: %v", osFamily, err)
		}
	}

	envelope := validRestartEnvelope(now)
	envelope.ActionType = ActionAWXServiceRestart
	envelope.Target = TargetRef{ServiceID: "service-payments", EnvironmentID: "PROD", AWXHosts: &AWXTarget{
		InventoryID: 42, HostIDs: []int64{101}, InventorySnapshotSHA256: strings.Repeat("f", 64),
	}}
	envelope.Parameters = ActionParameters{AWXServiceRestart: &AWXServiceRestartParameters{
		JobTemplateID: 81, ServiceName: "payments-api; rm -rf /", OSFamily: "SHELL", Serial: 1,
	}}
	envelope.ObservedState = ObservedState{AWXService: &AWXServiceObservedState{
		HostCount: 1, ServiceState: "RUNNING", InventorySnapshotSHA256: strings.Repeat("f", 64),
	}}
	envelope.Verification = VerificationPlan{Mode: "AWX_SERVICE_HEALTH", TimeoutSeconds: 300}
	if err := envelope.Validate(); err == nil {
		t.Fatal("unsafe AWX service action was accepted")
	}

	missingSnapshot := envelope
	missingSnapshot.Parameters.AWXServiceRestart = &AWXServiceRestartParameters{
		JobTemplateID: 81, ServiceName: "payments-api", OSFamily: "LINUX_SYSTEMD", Serial: 1,
	}
	missingSnapshot.Target.AWXHosts.InventorySnapshotSHA256 = ""
	if err := missingSnapshot.Validate(); err == nil {
		t.Fatal("AWX action without an immutable inventory snapshot was accepted")
	}
}

func validRestartEnvelope(now time.Time) Envelope {
	return Envelope{
		SchemaVersion: SchemaVersionV1,
		ActionID:      "action-01",
		WorkspaceID:   "workspace-01",
		IncidentID:    "incident-01",
		ActionType:    ActionKubernetesRolloutRestart,
		Target: TargetRef{ServiceID: "service-payments", EnvironmentID: "PROD", KubernetesDeployment: &KubernetesDeploymentTarget{
			ClusterID: "cluster-a",
			Namespace: "payments", Name: "payments-api", UID: "uid-01", ResourceVersion: "83",
		}},
		Parameters: ActionParameters{KubernetesRolloutRestart: &KubernetesRolloutRestartParameters{
			Reason: "recover from confirmed deadlock",
		}},
		ObservedState: ObservedState{KubernetesDeployment: &KubernetesDeploymentObservedState{
			Generation: 17, Replicas: 3, AvailableReplicas: 3, UpdatedReplicas: 3,
		}},
		Preconditions: Preconditions{
			MappingResult: "EXACT", ExpectedResourceVersion: "83", RequireWhitelist: true,
		},
		Verification:  VerificationPlan{Mode: "KUBERNETES_ROLLOUT", TimeoutSeconds: 300},
		Compensation:  CompensationPlan{Mode: "MANUAL_ONLY", Summary: "stop and follow the service runbook"},
		Risk:          RiskAssessment{Level: "MEDIUM", ReasonCodes: []string{"PRODUCTION_CHANGE", "RESTART"}},
		PolicyVersion: "policy.v1",
		CredentialScope: CredentialScope{
			ConnectorID: "kubernetes-prod", Permission: "PATCH_DEPLOYMENT_RESTART",
			Resource: "cluster-a/payments/deployment/payments-api", TTLSeconds: 600,
		},
		IdempotencyKey: "idem-action-01",
		NotBefore:      now,
		ExpiresAt:      now.Add(30 * time.Minute),
		TraceID:        strings.Repeat("a", 32),
	}
}
