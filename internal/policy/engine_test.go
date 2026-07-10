package policy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/aiops-system/control-plane/internal/action"
)

func TestEvaluateRechecksPolicyApprovalAndTargetAtEveryGate(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, keys := sealedRestartEnvelope(t, now)
	engine := newTestEngine(t, "policy.v1", `environment == "PROD" && service_id.startsWith("service-")`, keys)
	input := validInput(envelope, now)

	decision, err := engine.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("evaluate plan submission: %v", err)
	}
	if decision.Outcome != OutcomeRequireApproval || !contains(decision.ReasonCodes, ReasonApprovalRequired) {
		t.Fatalf("plan decision = %+v, want approval required", decision)
	}

	input.Approvals = []Approval{validApproval(envelope, "approver-1", []Role{RoleSRE}, "83", now.Add(20*time.Minute))}
	for _, stage := range []Stage{StagePlanSubmission, StageCredentialIssue, StagePreExecution} {
		candidate := input
		candidate.Stage = stage
		decision, err := engine.Evaluate(context.Background(), candidate)
		if err != nil {
			t.Fatalf("evaluate %s: %v", stage, err)
		}
		if decision.Outcome != OutcomeAllow {
			t.Fatalf("%s outcome = %s, reasons = %v", stage, decision.Outcome, decision.ReasonCodes)
		}
	}

	drifted := input
	drifted.Stage = StagePreExecution
	drifted.CurrentTargetVersion = "84"
	decision, err = engine.Evaluate(context.Background(), drifted)
	if err != nil {
		t.Fatalf("evaluate drifted target: %v", err)
	}
	if decision.Outcome != OutcomeDeny || !contains(decision.ReasonCodes, ReasonTargetStateDrift) {
		t.Fatalf("drift decision = %+v", decision)
	}

	expired := input
	expired.Stage = StageCredentialIssue
	expired.Now = now.Add(21 * time.Minute)
	decision, err = engine.Evaluate(context.Background(), expired)
	if err != nil {
		t.Fatalf("evaluate expired approval: %v", err)
	}
	if decision.Outcome != OutcomeDeny || !contains(decision.ReasonCodes, ReasonApprovalExpired) {
		t.Fatalf("expired approval decision = %+v", decision)
	}

	upgraded := newTestEngine(t, "policy.v2", `true`, keys)
	decision, err = upgraded.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("evaluate upgraded policy: %v", err)
	}
	if decision.Outcome != OutcomeDeny || !contains(decision.ReasonCodes, ReasonPolicyVersionMismatch) {
		t.Fatalf("upgraded policy decision = %+v", decision)
	}
}

func TestEvaluateFailsClosedForEveryKillSwitch(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, keys := sealedRestartEnvelope(t, now)
	engine := newTestEngine(t, "policy.v1", `true`, keys)
	base := validInput(envelope, now)
	base.Approvals = []Approval{validApproval(envelope, "approver-1", []Role{RoleApprover}, "83", now.Add(20*time.Minute))}

	tests := map[string]func(*SwitchState){
		"global":      func(state *SwitchState) { state.GlobalEnabled = false },
		"environment": func(state *SwitchState) { state.EnvironmentEnabled = false },
		"connector":   func(state *SwitchState) { state.ConnectorEnabled = false },
		"action":      func(state *SwitchState) { state.ActionEnabled = false },
	}
	for name, disable := range tests {
		name, disable := name, disable
		t.Run(name, func(t *testing.T) {
			input := base
			disable(&input.Switches)
			decision, err := engine.Evaluate(context.Background(), input)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if decision.Outcome != OutcomeDeny || !contains(decision.ReasonCodes, ReasonKillSwitchDisabled) {
				t.Fatalf("decision = %+v, want kill-switch deny", decision)
			}
		})
	}
}

func TestGitOpsRevertRequiresTwoDistinctRoleBoundApprovers(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, keys := sealedGitOpsEnvelope(t, now)
	engine := newTestEngine(t, "policy.v1", `true`, keys)
	input := validInput(envelope, now)
	input.CurrentTargetVersion = strings.Repeat("b", 40)

	sre := validApproval(envelope, "sre-1", []Role{RoleSRE}, input.CurrentTargetVersion, now.Add(20*time.Minute))
	owner := validApproval(envelope, "owner-1", []Role{RoleServiceOwner}, input.CurrentTargetVersion, now.Add(20*time.Minute))
	input.Approvals = []Approval{sre}
	decision, err := engine.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("evaluate one approver: %v", err)
	}
	if decision.Outcome != OutcomeRequireApproval {
		t.Fatalf("one approver outcome = %s, want REQUIRE_APPROVAL", decision.Outcome)
	}

	input.Approvals = []Approval{sre, owner}
	decision, err = engine.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("evaluate two approvers: %v", err)
	}
	if decision.Outcome != OutcomeAllow {
		t.Fatalf("two approvers decision = %+v", decision)
	}

	owner.SubjectID = input.RequesterID
	input.Approvals = []Approval{sre, owner}
	decision, err = engine.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("evaluate requester approval: %v", err)
	}
	if decision.Outcome != OutcomeRequireApproval || !contains(decision.ReasonCodes, ReasonSeparationOfDuties) {
		t.Fatalf("requester approval decision = %+v", decision)
	}

	bothRoles := validApproval(envelope, "one-person", []Role{RoleSRE, RoleServiceOwner}, input.CurrentTargetVersion, now.Add(20*time.Minute))
	input.Approvals = []Approval{bothRoles}
	decision, err = engine.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("evaluate one dual-role approver: %v", err)
	}
	if decision.Outcome != OutcomeRequireApproval {
		t.Fatalf("one person satisfied dual approval: %+v", decision)
	}
}

func TestCELCanOnlyNarrowHardSafetyGates(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, keys := sealedRestartEnvelope(t, now)
	input := validInput(envelope, now)
	input.Approvals = []Approval{validApproval(envelope, "approver-1", []Role{RoleSRE}, "83", now.Add(20*time.Minute))}

	denyEngine := newTestEngine(t, "policy.v1", `service_id == "a-service-that-is-not-allowed"`, keys)
	decision, err := denyEngine.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("evaluate CEL deny: %v", err)
	}
	if decision.Outcome != OutcomeDeny || !contains(decision.ReasonCodes, ReasonCELPolicyDenied) {
		t.Fatalf("CEL deny decision = %+v", decision)
	}

	allowEngine := newTestEngine(t, "policy.v1", `true`, keys)
	input.Switches.GlobalEnabled = false
	decision, err = allowEngine.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("evaluate hard gate: %v", err)
	}
	if decision.Outcome != OutcomeDeny || !contains(decision.ReasonCodes, ReasonKillSwitchDisabled) {
		t.Fatalf("CEL bypassed hard gate: %+v", decision)
	}
}

func TestCompileRejectsUnsafeOrNonBooleanPolicy(t *testing.T) {
	t.Parallel()

	_, _, keys := testSigningKey(t)
	for name, expression := range map[string]string{
		"non boolean": `"ALLOW"`,
		"undeclared":  `llm_risk == "LOW"`,
		"oversized":   strings.Repeat("true || ", 600) + "true",
	} {
		name, expression := name, expression
		t.Run(name, func(t *testing.T) {
			if _, err := NewEngine(Definition{Version: "policy.v1", Expression: expression}, keys); err == nil {
				t.Fatal("unsafe policy compiled successfully")
			}
		})
	}
}

func validInput(envelope action.Envelope, now time.Time) Input {
	return Input{
		Stage: StagePlanSubmission, Envelope: envelope, RequesterID: "requester-1",
		Environment: "PROD", ServiceID: "service-payments", CurrentTargetVersion: "83",
		Switches: SwitchState{GlobalEnabled: true, EnvironmentEnabled: true, ConnectorEnabled: true, ActionEnabled: true},
		Now:      now,
	}
}

func validApproval(envelope action.Envelope, subject string, roles []Role, targetVersion string, expiresAt time.Time) Approval {
	return Approval{
		SubjectID: subject, Roles: roles, Decision: ApprovalApproved,
		ActionID: envelope.ActionID, PlanHash: envelope.PlanHash, PolicyVersion: envelope.PolicyVersion,
		TargetVersion: targetVersion, ExpiresAt: expiresAt,
	}
}

func sealedRestartEnvelope(t *testing.T, now time.Time) (action.Envelope, action.StaticKeySet) {
	t.Helper()
	_, signer, keys := testSigningKey(t)
	envelope := action.Envelope{
		SchemaVersion: action.SchemaVersionV1, ActionID: "action-1", WorkspaceID: "workspace-1", IncidentID: "incident-1",
		ActionType: action.ActionKubernetesRolloutRestart,
		Target: action.TargetRef{ServiceID: "service-payments", EnvironmentID: "PROD", KubernetesDeployment: &action.KubernetesDeploymentTarget{
			ClusterID: "cluster-a", Namespace: "payments",
			Name: "payments-api", UID: "uid-1", ResourceVersion: "83",
		}},
		Parameters:      action.ActionParameters{KubernetesRolloutRestart: &action.KubernetesRolloutRestartParameters{Reason: "confirmed deadlock"}},
		ObservedState:   action.ObservedState{KubernetesDeployment: &action.KubernetesDeploymentObservedState{Generation: 4, Replicas: 3, AvailableReplicas: 3, UpdatedReplicas: 3}},
		Preconditions:   action.Preconditions{MappingResult: "EXACT", ExpectedResourceVersion: "83", RequireWhitelist: true},
		Verification:    action.VerificationPlan{Mode: "KUBERNETES_ROLLOUT", TimeoutSeconds: 300},
		Compensation:    action.CompensationPlan{Mode: "MANUAL_ONLY", Summary: "follow runbook"},
		Risk:            action.RiskAssessment{Level: "MEDIUM", ReasonCodes: []string{"PRODUCTION_CHANGE", "RESTART"}},
		PolicyVersion:   "policy.v1",
		CredentialScope: action.CredentialScope{ConnectorID: "kubernetes-prod", Permission: "PATCH_DEPLOYMENT_RESTART", Resource: "cluster-a/payments/deployment/payments-api", TTLSeconds: 600},
		IdempotencyKey:  "idem-action-1", NotBefore: now, ExpiresAt: now.Add(30 * time.Minute), TraceID: strings.Repeat("a", 32),
	}
	sealed, err := action.Seal(context.Background(), envelope, signer)
	if err != nil {
		t.Fatalf("seal restart envelope: %v", err)
	}
	return sealed, keys
}

func sealedGitOpsEnvelope(t *testing.T, now time.Time) (action.Envelope, action.StaticKeySet) {
	t.Helper()
	_, signer, keys := testSigningKey(t)
	head := strings.Repeat("b", 40)
	envelope := action.Envelope{
		SchemaVersion: action.SchemaVersionV1, ActionID: "action-gitops", WorkspaceID: "workspace-1", IncidentID: "incident-1",
		ActionType: action.ActionGitOpsRevert,
		Target:     action.TargetRef{ServiceID: "service-payments", EnvironmentID: "PROD", GitOpsApplication: &action.GitOpsTarget{RepositoryID: "gitops-prod", Application: "payments", Path: "apps/payments"}},
		Parameters: action.ActionParameters{GitOpsRevert: &action.GitOpsRevertParameters{
			Provider: "GITLAB", BaseCommit: strings.Repeat("a", 40), HeadCommit: head, RevertCommit: strings.Repeat("c", 40),
			DiffSHA256: strings.Repeat("d", 64), TreeSHA256: strings.Repeat("e", 64),
		}},
		ObservedState:   action.ObservedState{GitOpsApplication: &action.GitOpsObservedState{LiveRevision: head, DesiredRevision: head, SyncStatus: "SYNCED", HealthStatus: "HEALTHY"}},
		Preconditions:   action.Preconditions{MappingResult: "EXACT", ExpectedGitHeadCommit: head, RequireWhitelist: true},
		Verification:    action.VerificationPlan{Mode: "ARGO_CD_HEALTH", TimeoutSeconds: 300},
		Compensation:    action.CompensationPlan{Mode: "MANUAL_ONLY", Summary: "stop sync and follow runbook"},
		Risk:            action.RiskAssessment{Level: "HIGH", ReasonCodes: []string{"GITOPS_REVERT", "PRODUCTION_CHANGE"}},
		PolicyVersion:   "policy.v1",
		CredentialScope: action.CredentialScope{ConnectorID: "gitlab-prod", Permission: "CREATE_REVERT_MR", Resource: "gitops-prod", TTLSeconds: 600},
		IdempotencyKey:  "idem-action-gitops", NotBefore: now, ExpiresAt: now.Add(30 * time.Minute), TraceID: strings.Repeat("b", 32),
	}
	sealed, err := action.Seal(context.Background(), envelope, signer)
	if err != nil {
		t.Fatalf("seal GitOps envelope: %v", err)
	}
	return sealed, keys
}

func testSigningKey(t *testing.T) (ed25519.PublicKey, *action.Ed25519Signer, action.StaticKeySet) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := action.NewEd25519Signer("policy-test-key", privateKey)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return publicKey, signer, action.StaticKeySet{"policy-test-key": {PublicKey: publicKey}}
}

func newTestEngine(t *testing.T, version, expression string, keys action.StaticKeySet) *Engine {
	t.Helper()
	engine, err := NewEngine(Definition{Version: version, Expression: expression}, keys)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	return engine
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
