package policy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aiops-system/control-plane/internal/action"
)

const standardExpression = `environment == "PROD" && service_id.startsWith("service-") && mapping_exact && whitelisted`

func TestEveryGateRechecksTrustedApprovalAndTargetState(t *testing.T) {
	fixture := newKubernetesFixture(t, standardExpression)

	decision, err := fixture.engine.EvaluatePlanSubmission(context.Background(), fixture.envelope)
	if err != nil {
		t.Fatalf("evaluate plan: %v", err)
	}
	if decision.Outcome != OutcomeRequireApproval || !contains(decision.ReasonCodes, ReasonApprovalRequired) {
		t.Fatalf("plan decision = %+v", decision)
	}

	fixture.approvals.records = []Approval{fixture.approval("approver-1", ApprovalApproved, fixture.envelope.ExpiresAt)}
	for name, evaluate := range map[string]func(context.Context, action.Envelope) (Decision, error){
		"plan":       fixture.engine.EvaluatePlanSubmission,
		"credential": fixture.engine.EvaluateCredentialIssue,
		"execution":  fixture.engine.EvaluatePreExecution,
	} {
		decision, err := evaluate(context.Background(), fixture.envelope)
		if err != nil {
			t.Fatalf("evaluate %s: %v", name, err)
		}
		if decision.Outcome != OutcomeAllow {
			t.Fatalf("%s decision = %+v", name, decision)
		}
	}

	fixture.targets.snapshot.TargetVersion = "84"
	decision, err = fixture.engine.EvaluatePreExecution(context.Background(), fixture.envelope)
	if err != nil {
		t.Fatalf("evaluate drift: %v", err)
	}
	if decision.Outcome != OutcomeDeny || !contains(decision.ReasonCodes, ReasonTargetStateDrift) {
		t.Fatalf("drift decision = %+v", decision)
	}

	fixture.targets.snapshot.TargetVersion = "83"
	fixture.targets.snapshot.Whitelisted = false
	decision, err = fixture.engine.EvaluatePreExecution(context.Background(), fixture.envelope)
	if err != nil {
		t.Fatalf("evaluate removed whitelist: %v", err)
	}
	if decision.Outcome != OutcomeDeny || !contains(decision.ReasonCodes, ReasonTargetNotWhitelisted) {
		t.Fatalf("whitelist decision = %+v", decision)
	}
}

func TestKillSwitchesAreScopedFreshAndGlobalCheckPrecedesKeyResolution(t *testing.T) {
	fixture := newKubernetesFixture(t, `true`)
	fixture.approvals.records = []Approval{fixture.approval("approver-1", ApprovalApproved, fixture.envelope.ExpiresAt)}

	fixture.safety.global.Enabled = false
	decision, err := fixture.engine.EvaluatePreExecution(context.Background(), fixture.envelope)
	if err != nil {
		t.Fatalf("evaluate global switch: %v", err)
	}
	if decision.Outcome != OutcomeDeny || !contains(decision.ReasonCodes, ReasonKillSwitchDisabled) || fixture.keys.calls != 0 {
		t.Fatalf("global switch decision/key calls = %+v/%d", decision, fixture.keys.calls)
	}

	fixture.safety.global.Enabled = true
	tests := map[string]func(*ScopedSwitchSnapshot){
		"environment": func(snapshot *ScopedSwitchSnapshot) { snapshot.EnvironmentEnabled = false },
		"connector":   func(snapshot *ScopedSwitchSnapshot) { snapshot.ConnectorEnabled = false },
		"action":      func(snapshot *ScopedSwitchSnapshot) { snapshot.ActionEnabled = false },
		"wrong scope": func(snapshot *ScopedSwitchSnapshot) { snapshot.EnvironmentID = "STAGING" },
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			original := fixture.safety.scoped
			mutate(&fixture.safety.scoped)
			decision, err := fixture.engine.EvaluatePreExecution(context.Background(), fixture.envelope)
			fixture.safety.scoped = original
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if decision.Outcome != OutcomeDeny || !contains(decision.ReasonCodes, ReasonKillSwitchDisabled) {
				t.Fatalf("decision = %+v", decision)
			}
		})
	}

	fixture.safety.global.ObservedAt = fixture.clock.now.Add(-MaxSafetySnapshotAge - time.Nanosecond)
	decision, err = fixture.engine.EvaluatePreExecution(context.Background(), fixture.envelope)
	if err != nil {
		t.Fatalf("evaluate stale global switch: %v", err)
	}
	if decision.Outcome != OutcomeDeny || !contains(decision.ReasonCodes, ReasonSafetyStateStale) {
		t.Fatalf("stale decision = %+v", decision)
	}
}

func TestRejectedApprovalVetoesAndIdentityComesFromTrustedResolver(t *testing.T) {
	fixture := newKubernetesFixture(t, `true`)
	approved := fixture.approval("approver-1", ApprovalApproved, fixture.envelope.ExpiresAt)
	rejected := fixture.approval("owner-1", ApprovalRejected, fixture.envelope.ExpiresAt)
	fixture.approvals.records = []Approval{approved, rejected}

	decision, err := fixture.engine.EvaluatePlanSubmission(context.Background(), fixture.envelope)
	if err != nil {
		t.Fatalf("evaluate rejected approval: %v", err)
	}
	if decision.Outcome != OutcomeDeny || !contains(decision.ReasonCodes, ReasonApprovalRejected) {
		t.Fatalf("rejected approval decision = %+v", decision)
	}

	fixture.approvals.records = []Approval{fixture.approval("requester-alias", ApprovalApproved, fixture.envelope.ExpiresAt)}
	fixture.principals.values["requester-alias"] = Principal{CanonicalID: "requester-1", Active: true, Roles: []Role{RoleSRE}}
	decision, err = fixture.engine.EvaluatePlanSubmission(context.Background(), fixture.envelope)
	if err != nil {
		t.Fatalf("evaluate requester alias: %v", err)
	}
	if decision.Outcome != OutcomeRequireApproval || !contains(decision.ReasonCodes, ReasonSeparationOfDuties) {
		t.Fatalf("requester alias decision = %+v", decision)
	}

	fixture.approvals.records = []Approval{approved}
	fixture.principals.values["approver-1"] = Principal{CanonicalID: "approver-1", Active: true, Roles: []Role{"UNTRUSTED_ROLE"}}
	decision, err = fixture.engine.EvaluateCredentialIssue(context.Background(), fixture.envelope)
	if err != nil {
		t.Fatalf("evaluate unauthorized role: %v", err)
	}
	if decision.Outcome != OutcomeDeny || !contains(decision.ReasonCodes, ReasonApprovalRoleInvalid) {
		t.Fatalf("role decision = %+v", decision)
	}
}

func TestGitOpsRequiresDistinctSREAndOwnerAndFullFactBinding(t *testing.T) {
	fixture := newGitOpsFixture(t, `true`)
	fixture.principals.values["dual-role"] = Principal{CanonicalID: "dual-role", Active: true, Roles: []Role{RoleSRE, RoleServiceOwner}}
	fixture.principals.values["ordinary"] = Principal{CanonicalID: "ordinary", Active: true, Roles: []Role{RoleApprover}}
	fixture.approvals.records = []Approval{
		fixture.approval("dual-role", ApprovalApproved, fixture.envelope.ExpiresAt),
		fixture.approval("ordinary", ApprovalApproved, fixture.envelope.ExpiresAt),
	}

	decision, err := fixture.engine.EvaluatePlanSubmission(context.Background(), fixture.envelope)
	if err != nil {
		t.Fatalf("evaluate dual role: %v", err)
	}
	if decision.Outcome != OutcomeRequireApproval {
		t.Fatalf("one person supplied both mandatory roles: %+v", decision)
	}

	fixture.principals.values["dual-role"] = Principal{CanonicalID: "dual-role", Active: true, Roles: []Role{RoleSRE}}
	fixture.principals.values["ordinary"] = Principal{CanonicalID: "ordinary", Active: true, Roles: []Role{RoleServiceOwner}}
	decision, err = fixture.engine.EvaluatePlanSubmission(context.Background(), fixture.envelope)
	if err != nil {
		t.Fatalf("evaluate distinct roles: %v", err)
	}
	if decision.Outcome != OutcomeAllow {
		t.Fatalf("distinct role decision = %+v", decision)
	}

	for name, mutate := range map[string]func(*GitOpsFacts){
		"base": func(facts *GitOpsFacts) { facts.BaseCommit = strings.Repeat("9", 40) },
		"diff": func(facts *GitOpsFacts) { facts.DiffSHA256 = strings.Repeat("9", 64) },
		"tree": func(facts *GitOpsFacts) { facts.ResultTreeSHA256 = strings.Repeat("9", 64) },
		"path": func(facts *GitOpsFacts) { facts.Path = "apps/other" },
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			facts := *fixture.targets.snapshot.GitOps
			mutate(&facts)
			fixture.targets.snapshot.GitOps = &facts
			decision, err := fixture.engine.EvaluatePreExecution(context.Background(), fixture.envelope)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if decision.Outcome != OutcomeDeny || !contains(decision.ReasonCodes, ReasonTargetStateDrift) {
				t.Fatalf("decision = %+v", decision)
			}
			fixture.targets.snapshot.GitOps = fixture.gitOpsFacts()
		})
	}
}

func TestPolicyVersionIsContentAddressedAndCELCanOnlyNarrow(t *testing.T) {
	fixture := newKubernetesFixture(t, standardExpression)
	fixture.approvals.records = []Approval{fixture.approval("approver-1", ApprovalApproved, fixture.envelope.ExpiresAt)}

	tampered := fixture.definition
	tampered.Expression = `true`
	if _, err := NewEngine(tampered, fixture.dependencies()); err == nil {
		t.Fatal("same policy version accepted different CEL source")
	}
	if _, err := NewDefinition("policy.prod", `"ALLOW"`); err == nil {
		t.Fatal("non-boolean policy definition was accepted")
	}

	denyFixture := newKubernetesFixture(t, `service_id == "not-allowed"`)
	denyFixture.approvals.records = []Approval{denyFixture.approval("approver-1", ApprovalApproved, denyFixture.envelope.ExpiresAt)}
	decision, err := denyFixture.engine.EvaluatePreExecution(context.Background(), denyFixture.envelope)
	if err != nil {
		t.Fatalf("evaluate CEL deny: %v", err)
	}
	if decision.Outcome != OutcomeDeny || !contains(decision.ReasonCodes, ReasonCELPolicyDenied) {
		t.Fatalf("CEL deny decision = %+v", decision)
	}
}

func TestTrustedClockControlsExpiryAndCredentialExpiryIsCapped(t *testing.T) {
	fixture := newKubernetesFixture(t, `true`)
	fixture.approvals.records = []Approval{fixture.approval("approver-1", ApprovalApproved, fixture.envelope.ExpiresAt)}
	fixture.clock.now = fixture.envelope.ExpiresAt.Add(-time.Minute)
	fixture.refreshSnapshots()

	decision, err := fixture.engine.EvaluateCredentialIssue(context.Background(), fixture.envelope)
	if err != nil {
		t.Fatalf("evaluate credential: %v", err)
	}
	if decision.Outcome != OutcomeAllow || !decision.CredentialExpiresAt.Equal(fixture.envelope.ExpiresAt) {
		t.Fatalf("credential decision = %+v", decision)
	}

	fixture.clock.now = fixture.envelope.ExpiresAt
	fixture.refreshSnapshots()
	decision, err = fixture.engine.EvaluatePreExecution(context.Background(), fixture.envelope)
	if err != nil {
		t.Fatalf("evaluate expired envelope: %v", err)
	}
	if decision.Outcome != OutcomeDeny || !contains(decision.ReasonCodes, ReasonInvalidEnvelope) {
		t.Fatalf("expired decision = %+v", decision)
	}
}

type testFixture struct {
	t                *testing.T
	definition       Definition
	envelope         action.Envelope
	engine           *Engine
	clock            *fixedClock
	keys             *countingKeyResolver
	approvals        *fakeApprovalReader
	principals       *fakePrincipalResolver
	safety           *fakeSafetyReader
	targets          *fakeTargetReader
	underlyingKeySet action.KeyResolver
}

func newKubernetesFixture(t *testing.T, expression string) *testFixture {
	t.Helper()
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	definition := mustDefinition(t, expression)
	envelope, keySet := sealEnvelope(t, kubernetesEnvelope(now, definition.Version))
	fixture := baseFixture(t, now, definition, envelope, keySet)
	fixture.targets.snapshot.TargetVersion = "83"
	fixture.principals.values["approver-1"] = Principal{CanonicalID: "approver-1", Active: true, Roles: []Role{RoleSRE}}
	fixture.principals.values["owner-1"] = Principal{CanonicalID: "owner-1", Active: true, Roles: []Role{RoleServiceOwner}}
	fixture.installEngine()
	return fixture
}

func newGitOpsFixture(t *testing.T, expression string) *testFixture {
	t.Helper()
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	definition := mustDefinition(t, expression)
	envelope, keySet := sealEnvelope(t, gitOpsEnvelope(now, definition.Version))
	fixture := baseFixture(t, now, definition, envelope, keySet)
	fixture.targets.snapshot.TargetVersion = ""
	fixture.targets.snapshot.GitOps = fixture.gitOpsFacts()
	fixture.installEngine()
	return fixture
}

func baseFixture(t *testing.T, now time.Time, definition Definition, envelope action.Envelope, keySet action.KeyResolver) *testFixture {
	clock := &fixedClock{now: now}
	return &testFixture{
		t: t, definition: definition, envelope: envelope, clock: clock, underlyingKeySet: keySet,
		keys:       &countingKeyResolver{delegate: keySet},
		approvals:  &fakeApprovalReader{},
		principals: &fakePrincipalResolver{values: map[string]Principal{"requester-1": {CanonicalID: "requester-1", Active: true}}},
		safety: &fakeSafetyReader{
			global: GlobalSwitchSnapshot{Enabled: true, Revision: "global-1", ObservedAt: now},
			scoped: ScopedSwitchSnapshot{
				WorkspaceID: envelope.WorkspaceID, EnvironmentID: envelope.Target.EnvironmentID,
				ConnectorID: envelope.CredentialScope.ConnectorID, ActionType: envelope.ActionType,
				EnvironmentEnabled: true, ConnectorEnabled: true, ActionEnabled: true,
				Revision: "scoped-1", ObservedAt: now,
			},
		},
		targets: &fakeTargetReader{snapshot: TargetSnapshot{
			WorkspaceID: envelope.WorkspaceID, ServiceID: envelope.Target.ServiceID,
			EnvironmentID: envelope.Target.EnvironmentID, ConnectorID: envelope.CredentialScope.ConnectorID,
			ActionType: envelope.ActionType, MappingResult: "EXACT", Whitelisted: true,
			Revision: "target-1", ObservedAt: now,
		}},
	}
}

func (fixture *testFixture) installEngine() {
	fixture.t.Helper()
	engine, err := NewEngine(fixture.definition, fixture.dependencies())
	if err != nil {
		fixture.t.Fatalf("NewEngine() error = %v", err)
	}
	fixture.engine = engine
}

func (fixture *testFixture) dependencies() Dependencies {
	return Dependencies{
		Keys: fixture.keys, Approvals: fixture.approvals, Principals: fixture.principals,
		Safety: fixture.safety, Targets: fixture.targets, Clock: fixture.clock,
	}
}

func (fixture *testFixture) approval(subject string, decision ApprovalDecision, expiresAt time.Time) Approval {
	fixture.t.Helper()
	digest, err := TargetDigest(fixture.envelope)
	if err != nil {
		fixture.t.Fatalf("TargetDigest() error = %v", err)
	}
	return Approval{
		SubjectID: subject, Decision: decision, WorkspaceID: fixture.envelope.WorkspaceID, ActionID: fixture.envelope.ActionID,
		PlanHash: fixture.envelope.PlanHash, PolicyVersion: fixture.envelope.PolicyVersion,
		TargetDigest: digest, DecidedAt: fixture.clock.now, ExpiresAt: expiresAt,
	}
}

func (fixture *testFixture) gitOpsFacts() *GitOpsFacts {
	parameters := fixture.envelope.Parameters.GitOpsRevert
	target := fixture.envelope.Target.GitOpsApplication
	return &GitOpsFacts{
		RepositoryID: target.RepositoryID, Application: target.Application, Path: target.Path,
		BaseCommit: parameters.BaseCommit, HeadCommit: parameters.HeadCommit, RevertCommit: parameters.RevertCommit,
		DiffSHA256: parameters.DiffSHA256, ResultTreeSHA256: parameters.TreeSHA256,
		HeadTreeSHA256: fixture.envelope.ObservedState.GitOpsApplication.HeadTreeSHA256,
	}
}

func (fixture *testFixture) refreshSnapshots() {
	fixture.safety.global.ObservedAt = fixture.clock.now
	fixture.safety.scoped.ObservedAt = fixture.clock.now
	fixture.targets.snapshot.ObservedAt = fixture.clock.now
}

type fixedClock struct{ now time.Time }

func (clock *fixedClock) Now() time.Time { return clock.now }

type countingKeyResolver struct {
	delegate action.KeyResolver
	calls    int
}

func (resolver *countingKeyResolver) Resolve(ctx context.Context, keyID string) (action.KeyRecord, error) {
	resolver.calls++
	return resolver.delegate.Resolve(ctx, keyID)
}

type fakeApprovalReader struct {
	records []Approval
	err     error
}

func (reader *fakeApprovalReader) List(context.Context, string, string, string) ([]Approval, error) {
	return append([]Approval(nil), reader.records...), reader.err
}

type fakePrincipalResolver struct {
	values map[string]Principal
	err    error
}

func (resolver *fakePrincipalResolver) Resolve(_ context.Context, subjectID, _, _, _ string) (Principal, error) {
	if resolver.err != nil {
		return Principal{}, resolver.err
	}
	principal, exists := resolver.values[subjectID]
	if !exists {
		return Principal{}, errors.New("principal not found")
	}
	return principal, nil
}

type fakeSafetyReader struct {
	global GlobalSwitchSnapshot
	scoped ScopedSwitchSnapshot
	err    error
}

func (reader *fakeSafetyReader) Global(context.Context) (GlobalSwitchSnapshot, error) {
	return reader.global, reader.err
}

func (reader *fakeSafetyReader) Scoped(context.Context, action.Envelope) (ScopedSwitchSnapshot, error) {
	return reader.scoped, reader.err
}

type fakeTargetReader struct {
	snapshot TargetSnapshot
	err      error
}

func (reader *fakeTargetReader) Resolve(context.Context, action.Envelope) (TargetSnapshot, error) {
	return reader.snapshot, reader.err
}

func mustDefinition(t *testing.T, expression string) Definition {
	t.Helper()
	definition, err := NewDefinition("policy.prod.v1", expression)
	if err != nil {
		t.Fatalf("NewDefinition() error = %v", err)
	}
	return definition
}

func sealEnvelope(t *testing.T, envelope action.Envelope) (action.Envelope, action.KeyResolver) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := action.NewEd25519Signer("policy-test-key", privateKey)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	sealed, err := action.Seal(context.Background(), envelope, signer)
	if err != nil {
		t.Fatalf("seal envelope: %v", err)
	}
	keys, err := action.NewStaticKeySet(map[string]action.KeyRecord{"policy-test-key": {PublicKey: publicKey}})
	if err != nil {
		t.Fatalf("new key set: %v", err)
	}
	return sealed, keys
}

func kubernetesEnvelope(now time.Time, policyVersion string) action.Envelope {
	return action.Envelope{
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
		PolicyVersion: policyVersion,
		CredentialScope: action.CredentialScope{ConnectorID: "kubernetes-prod", Permission: "PATCH_DEPLOYMENT_RESTART",
			Resource: "cluster-a/payments/deployment/payments-api", TTLSeconds: 600},
		IdempotencyKey: "idem-action-1", NotBefore: now, ExpiresAt: now.Add(30 * time.Minute), TraceID: strings.Repeat("a", 32),
	}
}

func gitOpsEnvelope(now time.Time, policyVersion string) action.Envelope {
	head := strings.Repeat("b", 40)
	return action.Envelope{
		SchemaVersion: action.SchemaVersionV1, ActionID: "action-gitops", WorkspaceID: "workspace-1", IncidentID: "incident-1", RequestedBy: "requester-1",
		ActionType: action.ActionGitOpsRevert,
		Target:     action.TargetRef{ServiceID: "service-payments", EnvironmentID: "PROD", GitOpsApplication: &action.GitOpsTarget{RepositoryID: "gitops-prod", Application: "payments", Path: "apps/payments"}},
		Parameters: action.ActionParameters{GitOpsRevert: &action.GitOpsRevertParameters{
			Provider: "GITLAB", BaseCommit: strings.Repeat("a", 40), HeadCommit: head, RevertCommit: strings.Repeat("c", 40),
			DiffSHA256: strings.Repeat("d", 64), TreeSHA256: strings.Repeat("e", 64),
		}},
		ObservedState: action.ObservedState{GitOpsApplication: &action.GitOpsObservedState{
			LiveRevision: head, DesiredRevision: head, HeadTreeSHA256: strings.Repeat("f", 64), SyncStatus: "SYNCED", HealthStatus: "HEALTHY",
		}},
		Preconditions: action.Preconditions{MappingResult: "EXACT", ExpectedGitHeadCommit: head, RequireWhitelist: true},
		Verification:  action.VerificationPlan{Mode: "ARGO_CD_HEALTH", TimeoutSeconds: 300},
		Compensation:  action.CompensationPlan{Mode: "MANUAL_ONLY", Summary: "stop sync and follow runbook"},
		Risk:          action.RiskAssessment{Level: "HIGH", ReasonCodes: []string{"GITOPS_REVERT", "PRODUCTION_CHANGE"}},
		PolicyVersion: policyVersion,
		CredentialScope: action.CredentialScope{ConnectorID: "gitlab-prod", Permission: "CREATE_REVERT_MR",
			Resource: "gitops-prod", TTLSeconds: 600},
		IdempotencyKey: "idem-action-gitops", NotBefore: now, ExpiresAt: now.Add(30 * time.Minute), TraceID: strings.Repeat("b", 32),
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
