package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/seaworld008/aiops-system/internal/action"
)

type Stage string

const (
	StagePlanSubmission  Stage = "PLAN_SUBMISSION"
	StageCredentialIssue Stage = "CREDENTIAL_ISSUE"
	StagePreExecution    Stage = "PRE_EXECUTION"
)

type Outcome string

const (
	OutcomeAllow           Outcome = "ALLOW"
	OutcomeDeny            Outcome = "DENY"
	OutcomeRequireApproval Outcome = "REQUIRE_APPROVAL"
)

const (
	ReasonApprovalRequired        = "APPROVAL_REQUIRED"
	ReasonApprovalExpired         = "APPROVAL_EXPIRED"
	ReasonApprovalBindingMismatch = "APPROVAL_BINDING_MISMATCH"
	ReasonApprovalRejected        = "APPROVAL_REJECTED"
	ReasonApprovalRoleInvalid     = "APPROVAL_ROLE_INVALID"
	ReasonSeparationOfDuties      = "SEPARATION_OF_DUTIES"
	ReasonTargetStateDrift        = "TARGET_STATE_DRIFT"
	ReasonTargetStateStale        = "TARGET_STATE_STALE"
	ReasonTargetNotWhitelisted    = "TARGET_NOT_WHITELISTED"
	ReasonMappingNotExact         = "MAPPING_NOT_EXACT"
	ReasonKillSwitchDisabled      = "KILL_SWITCH_DISABLED"
	ReasonSafetyStateStale        = "SAFETY_STATE_STALE"
	ReasonSafetyStateUnavailable  = "SAFETY_STATE_UNAVAILABLE"
	ReasonCELPolicyDenied         = "CEL_POLICY_DENIED"
	ReasonInvalidEnvelope         = "INVALID_ACTION_ENVELOPE"
	ReasonIdentityUnavailable     = "IDENTITY_UNAVAILABLE"
	ReasonRiskAssessmentDrift     = "RISK_ASSESSMENT_DRIFT"
	ReasonActionLimitsDrift       = "ACTION_LIMITS_DRIFT"
)

const (
	MaxSafetySnapshotAge = 5 * time.Second
	MaxTargetSnapshotAge = 15 * time.Second
	maxClockSkew         = time.Second
)

type Role string

const (
	RoleSRE          Role = "SRE"
	RoleServiceOwner Role = "SERVICE_OWNER"
	RoleApprover     Role = "APPROVER"
)

type ApprovalDecision string

const (
	ApprovalApproved ApprovalDecision = "APPROVED"
	ApprovalRejected ApprovalDecision = "REJECTED"
)

type Definition struct {
	Label      string
	Version    string
	Expression string
}

type Approval struct {
	SubjectID     string
	Decision      ApprovalDecision
	WorkspaceID   string
	ActionID      string
	PlanHash      string
	PolicyVersion string
	TargetDigest  string
	DecidedAt     time.Time
	ExpiresAt     time.Time
}

type Principal struct {
	CanonicalID string
	Active      bool
	Roles       []Role
}

type GlobalSwitchSnapshot struct {
	Enabled    bool
	Revision   string
	ObservedAt time.Time
}

type ScopedSwitchSnapshot struct {
	WorkspaceID        string
	EnvironmentID      string
	ConnectorID        string
	ActionType         action.ActionType
	EnvironmentEnabled bool
	ConnectorEnabled   bool
	ActionEnabled      bool
	Revision           string
	ObservedAt         time.Time
}

type GitOpsFacts struct {
	Provider         string
	RepositoryID     string
	Application      string
	Path             string
	BaseCommit       string
	HeadCommit       string
	RevertCommit     string
	DiffSHA256       string
	ResultTreeSHA256 string
	HeadTreeSHA256   string
	LiveRevision     string
	DesiredRevision  string
	SyncStatus       string
	HealthStatus     string
}

type KubernetesFacts struct {
	ClusterID         string
	Namespace         string
	Name              string
	UID               string
	ResourceVersion   string
	Generation        int64
	Replicas          int32
	AvailableReplicas int32
	UpdatedReplicas   int32
	HPAAbsent         bool
	PDBChecked        bool
	QuotaChecked      bool
}

type AWXFacts struct {
	InventoryID                int64
	HostIDs                    []int64
	InventorySnapshotSHA256    string
	JobTemplateID              int64
	JobTemplateSnapshotSHA256  string
	ServiceName                string
	OSFamily                   string
	ServiceState               string
	ServiceStateSnapshotSHA256 string
}

type TargetSnapshot struct {
	WorkspaceID   string
	ServiceID     string
	EnvironmentID string
	ConnectorID   string
	ActionType    action.ActionType
	MappingResult string
	Whitelisted   bool
	TargetVersion string
	Kubernetes    *KubernetesFacts
	GitOps        *GitOpsFacts
	AWX           *AWXFacts
	Revision      string
	ObservedAt    time.Time
}

type RiskSnapshot struct {
	WorkspaceID   string
	ActionID      string
	PlanHash      string
	TargetDigest  string
	PolicyVersion string
	Level         string
	ReasonCodes   []string
	Revision      string
	ObservedAt    time.Time
}

type ActionLimitsSnapshot struct {
	WorkspaceID     string
	ServiceID       string
	EnvironmentID   string
	ActionType      action.ActionType
	MinimumReplicas int32
	MaximumReplicas int32
	MaxAWXHosts     int
	Revision        string
	ObservedAt      time.Time
}

type ApprovalReader interface {
	List(context.Context, string, string, string) ([]Approval, error)
}

type PrincipalResolver interface {
	Resolve(context.Context, string, string, string, string) (Principal, error)
}

type SafetyStateReader interface {
	Global(context.Context) (GlobalSwitchSnapshot, error)
	Scoped(context.Context, action.Envelope) (ScopedSwitchSnapshot, error)
}

type TargetStateReader interface {
	Resolve(context.Context, action.Envelope) (TargetSnapshot, error)
}

type RiskStateReader interface {
	Resolve(context.Context, action.Envelope) (RiskSnapshot, error)
}

type ActionLimitsReader interface {
	Resolve(context.Context, action.Envelope) (ActionLimitsSnapshot, error)
}

type Clock interface {
	Now() time.Time
}

type Dependencies struct {
	Keys       action.KeyResolver
	Approvals  ApprovalReader
	Principals PrincipalResolver
	Safety     SafetyStateReader
	Targets    TargetStateReader
	Risk       RiskStateReader
	Limits     ActionLimitsReader
	Clock      Clock
}

type Decision struct {
	Outcome             Outcome
	PolicyVersion       string
	Stage               Stage
	PlanHash            string
	ReasonCodes         []string
	SafetyRevision      string
	TargetRevision      string
	RiskRevision        string
	LimitsRevision      string
	EvaluatedAt         time.Time
	CredentialExpiresAt time.Time
}

type Engine struct {
	definition Definition
	program    cel.Program
	deps       Dependencies
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

var definitionLabelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,119}$`)

func NewDefinition(label, expression string) (Definition, error) {
	if !definitionLabelPattern.MatchString(label) {
		return Definition{}, fmt.Errorf("valid policy label is required")
	}
	normalized, err := normalizeExpression(expression)
	if err != nil {
		return Definition{}, err
	}
	if _, err := compileProgram(normalized); err != nil {
		return Definition{}, err
	}
	digest := sha256.Sum256([]byte("aiops-cel-policy.v1\x00" + normalized))
	version := label + "@sha256:" + hex.EncodeToString(digest[:])
	return Definition{Label: label, Version: version, Expression: normalized}, nil
}

func NewEngine(definition Definition, dependencies Dependencies) (*Engine, error) {
	expected, err := NewDefinition(definition.Label, definition.Expression)
	if err != nil {
		return nil, err
	}
	if definition.Version != expected.Version {
		return nil, fmt.Errorf("policy version does not match its immutable CEL source")
	}
	if dependencies.Keys == nil || dependencies.Approvals == nil || dependencies.Principals == nil || dependencies.Safety == nil || dependencies.Targets == nil || dependencies.Risk == nil || dependencies.Limits == nil {
		return nil, fmt.Errorf("all trusted policy dependencies are required")
	}
	if dependencies.Clock == nil {
		dependencies.Clock = systemClock{}
	}
	program, err := compileProgram(expected.Expression)
	if err != nil {
		return nil, err
	}
	return &Engine{definition: expected, program: program, deps: dependencies}, nil
}

func (engine *Engine) EvaluatePlanSubmission(ctx context.Context, envelope action.Envelope) (Decision, error) {
	return engine.evaluate(ctx, StagePlanSubmission, envelope)
}

func (engine *Engine) EvaluateCredentialIssue(ctx context.Context, envelope action.Envelope) (Decision, error) {
	return engine.evaluate(ctx, StageCredentialIssue, envelope)
}

func (engine *Engine) EvaluatePreExecution(ctx context.Context, envelope action.Envelope) (Decision, error) {
	return engine.evaluate(ctx, StagePreExecution, envelope)
}

func (engine *Engine) evaluate(ctx context.Context, stage Stage, envelope action.Envelope) (Decision, error) {
	now := engine.deps.Clock.Now().UTC()
	decision := Decision{
		Outcome: OutcomeDeny, PolicyVersion: engine.definition.Version, Stage: stage,
		PlanHash: envelope.PlanHash, EvaluatedAt: now,
	}
	if err := ctx.Err(); err != nil {
		return decision, err
	}

	global, err := engine.deps.Safety.Global(ctx)
	if err != nil || global.Revision == "" {
		return withReasons(decision, OutcomeDeny, ReasonSafetyStateUnavailable), nil
	}
	decision.SafetyRevision = global.Revision
	if !fresh(now, global.ObservedAt, MaxSafetySnapshotAge) {
		return withReasons(decision, OutcomeDeny, ReasonSafetyStateStale), nil
	}
	if !global.Enabled {
		return withReasons(decision, OutcomeDeny, ReasonKillSwitchDisabled), nil
	}
	if envelope.PolicyVersion != engine.definition.Version {
		return withReasons(decision, OutcomeDeny, ReasonInvalidEnvelope), nil
	}
	if err := action.Verify(ctx, envelope, engine.deps.Keys, now); err != nil {
		return withReasons(decision, OutcomeDeny, ReasonInvalidEnvelope), nil
	}

	scoped, err := engine.deps.Safety.Scoped(ctx, envelope)
	if err != nil || scoped.Revision == "" {
		return withReasons(decision, OutcomeDeny, ReasonSafetyStateUnavailable), nil
	}
	decision.SafetyRevision = global.Revision + "/" + scoped.Revision
	if !fresh(now, scoped.ObservedAt, MaxSafetySnapshotAge) {
		return withReasons(decision, OutcomeDeny, ReasonSafetyStateStale), nil
	}
	if scoped.WorkspaceID != envelope.WorkspaceID || scoped.EnvironmentID != envelope.Target.EnvironmentID || scoped.ConnectorID != envelope.CredentialScope.ConnectorID || scoped.ActionType != envelope.ActionType {
		return withReasons(decision, OutcomeDeny, ReasonKillSwitchDisabled), nil
	}
	if !scoped.EnvironmentEnabled || !scoped.ConnectorEnabled || !scoped.ActionEnabled {
		return withReasons(decision, OutcomeDeny, ReasonKillSwitchDisabled), nil
	}

	target, err := engine.deps.Targets.Resolve(ctx, envelope)
	if err != nil || target.Revision == "" {
		return withReasons(decision, OutcomeDeny, ReasonTargetStateDrift), nil
	}
	decision.TargetRevision = target.Revision
	if !fresh(now, target.ObservedAt, MaxTargetSnapshotAge) {
		return withReasons(decision, OutcomeDeny, ReasonTargetStateStale), nil
	}
	if target.WorkspaceID != envelope.WorkspaceID || target.ServiceID != envelope.Target.ServiceID || target.EnvironmentID != envelope.Target.EnvironmentID || target.ConnectorID != envelope.CredentialScope.ConnectorID || target.ActionType != envelope.ActionType {
		return withReasons(decision, OutcomeDeny, ReasonTargetStateDrift), nil
	}
	if target.MappingResult != "EXACT" {
		return withReasons(decision, OutcomeDeny, ReasonMappingNotExact), nil
	}
	if !target.Whitelisted {
		return withReasons(decision, OutcomeDeny, ReasonTargetNotWhitelisted), nil
	}
	if !targetMatchesEnvelope(target, envelope) {
		return withReasons(decision, OutcomeDeny, ReasonTargetStateDrift), nil
	}
	targetDigest, digestErr := TargetDigest(envelope)
	risk, err := engine.deps.Risk.Resolve(ctx, envelope)
	if err != nil || risk.Revision == "" || !fresh(now, risk.ObservedAt, MaxTargetSnapshotAge) ||
		digestErr != nil || risk.WorkspaceID != envelope.WorkspaceID || risk.ActionID != envelope.ActionID ||
		risk.PlanHash != envelope.PlanHash || risk.TargetDigest != targetDigest || risk.PolicyVersion != envelope.PolicyVersion ||
		risk.Level != envelope.Risk.Level || !slices.Equal(risk.ReasonCodes, envelope.Risk.ReasonCodes) {
		return withReasons(decision, OutcomeDeny, ReasonRiskAssessmentDrift), nil
	}
	decision.RiskRevision = risk.Revision
	limits, err := engine.deps.Limits.Resolve(ctx, envelope)
	if err != nil || limits.Revision == "" || !fresh(now, limits.ObservedAt, MaxTargetSnapshotAge) ||
		limits.WorkspaceID != envelope.WorkspaceID || limits.ServiceID != envelope.Target.ServiceID ||
		limits.EnvironmentID != envelope.Target.EnvironmentID || limits.ActionType != envelope.ActionType ||
		!limitsMatchEnvelope(limits, envelope) {
		return withReasons(decision, OutcomeDeny, ReasonActionLimitsDrift), nil
	}
	decision.LimitsRevision = limits.Revision

	result, _, err := engine.program.ContextEval(ctx, map[string]any{
		"action_type":           string(envelope.ActionType),
		"stage":                 string(stage),
		"environment":           target.EnvironmentID,
		"service_id":            target.ServiceID,
		"workspace_id":          target.WorkspaceID,
		"risk_level":            risk.Level,
		"connector_id":          target.ConnectorID,
		"credential_permission": envelope.CredentialScope.Permission,
		"mapping_exact":         target.MappingResult == "EXACT",
		"whitelisted":           target.Whitelisted,
	})
	if err != nil {
		return withReasons(decision, OutcomeDeny, ReasonCELPolicyDenied), fmt.Errorf("evaluate CEL policy: %w", err)
	}
	allowed, ok := result.(types.Bool)
	if !ok || !bool(allowed) {
		return withReasons(decision, OutcomeDeny, ReasonCELPolicyDenied), nil
	}

	approvalResult := engine.evaluateApprovals(ctx, envelope, now)
	if approvalResult.rejected {
		return withReasons(decision, OutcomeDeny, append(approvalResult.reasons, ReasonApprovalRejected)...), nil
	}
	if !approvalResult.satisfied {
		outcome := OutcomeDeny
		if stage == StagePlanSubmission {
			outcome = OutcomeRequireApproval
		}
		return withReasons(decision, outcome, append(approvalResult.reasons, ReasonApprovalRequired)...), nil
	}

	decision.Outcome = OutcomeAllow
	if stage == StageCredentialIssue {
		credentialExpiry := now.Add(time.Duration(envelope.CredentialScope.TTLSeconds) * time.Second)
		if credentialExpiry.After(envelope.ExpiresAt) {
			credentialExpiry = envelope.ExpiresAt
		}
		decision.CredentialExpiresAt = credentialExpiry
	}
	return decision, nil
}

type approvalEvaluation struct {
	satisfied bool
	rejected  bool
	reasons   []string
}

func (engine *Engine) evaluateApprovals(ctx context.Context, envelope action.Envelope, now time.Time) approvalEvaluation {
	digest, err := TargetDigest(envelope)
	if err != nil {
		return approvalEvaluation{reasons: []string{ReasonApprovalBindingMismatch}}
	}
	records, err := engine.deps.Approvals.List(ctx, envelope.WorkspaceID, envelope.ActionID, envelope.PlanHash)
	if err != nil {
		return approvalEvaluation{reasons: []string{ReasonApprovalBindingMismatch}}
	}
	requester, err := engine.deps.Principals.Resolve(ctx, envelope.RequestedBy, envelope.WorkspaceID, envelope.Target.EnvironmentID, envelope.Target.ServiceID)
	if err != nil || !requester.Active || requester.CanonicalID == "" {
		return approvalEvaluation{reasons: []string{ReasonIdentityUnavailable}}
	}

	valid := make(map[string]Principal)
	reasons := make([]string, 0, 4)
	rejected := false
	for _, approval := range records {
		if !approvalBindingValid(approval, envelope, digest, now) {
			if !now.Before(approval.ExpiresAt) {
				reasons = append(reasons, ReasonApprovalExpired)
			} else {
				reasons = append(reasons, ReasonApprovalBindingMismatch)
			}
			continue
		}
		principal, err := engine.deps.Principals.Resolve(ctx, approval.SubjectID, envelope.WorkspaceID, envelope.Target.EnvironmentID, envelope.Target.ServiceID)
		if err != nil || !principal.Active || principal.CanonicalID == "" {
			reasons = append(reasons, ReasonIdentityUnavailable)
			continue
		}
		if principal.CanonicalID == requester.CanonicalID {
			reasons = append(reasons, ReasonSeparationOfDuties)
			continue
		}
		if !validRoles(principal.Roles) || !hasAnyRole(principal.Roles, RoleSRE, RoleServiceOwner, RoleApprover) {
			reasons = append(reasons, ReasonApprovalRoleInvalid)
			continue
		}
		if approval.Decision == ApprovalRejected {
			rejected = true
			continue
		}
		if approval.Decision != ApprovalApproved {
			reasons = append(reasons, ReasonApprovalBindingMismatch)
			continue
		}
		if _, duplicate := valid[principal.CanonicalID]; duplicate {
			reasons = append(reasons, ReasonApprovalBindingMismatch)
			continue
		}
		valid[principal.CanonicalID] = principal
	}
	if rejected {
		return approvalEvaluation{rejected: true, reasons: reasons}
	}
	if envelope.ActionType != action.ActionGitOpsRevert {
		return approvalEvaluation{satisfied: len(valid) >= 1, reasons: reasons}
	}
	for sreID, principal := range valid {
		if !hasAnyRole(principal.Roles, RoleSRE) {
			continue
		}
		for ownerID, candidate := range valid {
			if sreID != ownerID && hasAnyRole(candidate.Roles, RoleServiceOwner) {
				return approvalEvaluation{satisfied: true, reasons: reasons}
			}
		}
	}
	return approvalEvaluation{reasons: reasons}
}

func approvalBindingValid(approval Approval, envelope action.Envelope, targetDigest string, now time.Time) bool {
	return (approval.Decision == ApprovalApproved || approval.Decision == ApprovalRejected) &&
		approval.WorkspaceID == envelope.WorkspaceID && approval.ActionID == envelope.ActionID && approval.PlanHash == envelope.PlanHash &&
		approval.PolicyVersion == envelope.PolicyVersion && approval.TargetDigest == targetDigest &&
		!approval.DecidedAt.Before(envelope.NotBefore) && !approval.DecidedAt.After(now) &&
		now.Before(approval.ExpiresAt) && !approval.ExpiresAt.After(envelope.ExpiresAt)
}

func TargetDigest(envelope action.Envelope) (string, error) {
	if err := envelope.Validate(); err != nil {
		return "", err
	}
	binding := struct {
		ActionType    action.ActionType       `json:"action_type"`
		Target        action.TargetRef        `json:"target"`
		Parameters    action.ActionParameters `json:"parameters"`
		ObservedState action.ObservedState    `json:"observed_state"`
	}{envelope.ActionType, envelope.Target, envelope.Parameters, envelope.ObservedState}
	encoded, err := json.Marshal(binding)
	if err != nil {
		return "", fmt.Errorf("marshal target binding: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func targetMatchesEnvelope(snapshot TargetSnapshot, envelope action.Envelope) bool {
	switch envelope.ActionType {
	case action.ActionKubernetesRolloutRestart, action.ActionKubernetesScale:
		if snapshot.Kubernetes == nil || snapshot.GitOps != nil || snapshot.AWX != nil || envelope.Target.KubernetesDeployment == nil || envelope.ObservedState.KubernetesDeployment == nil {
			return false
		}
		target := envelope.Target.KubernetesDeployment
		state := envelope.ObservedState.KubernetesDeployment
		expected := KubernetesFacts{
			ClusterID: target.ClusterID, Namespace: target.Namespace, Name: target.Name, UID: target.UID,
			ResourceVersion: target.ResourceVersion, Generation: state.Generation, Replicas: state.Replicas,
			AvailableReplicas: state.AvailableReplicas, UpdatedReplicas: state.UpdatedReplicas,
		}
		if envelope.ActionType == action.ActionKubernetesScale {
			if envelope.Parameters.KubernetesScale == nil {
				return false
			}
			expected.HPAAbsent = envelope.Parameters.KubernetesScale.HPAAbsent
			expected.PDBChecked = envelope.Parameters.KubernetesScale.PDBChecked
			expected.QuotaChecked = envelope.Parameters.KubernetesScale.QuotaChecked
		}
		return snapshot.TargetVersion == target.ResourceVersion && *snapshot.Kubernetes == expected
	case action.ActionAWXServiceRestart:
		if snapshot.AWX == nil || snapshot.GitOps != nil || snapshot.Kubernetes != nil || envelope.Target.AWXHosts == nil || envelope.Parameters.AWXServiceRestart == nil || envelope.ObservedState.AWXService == nil {
			return false
		}
		target := envelope.Target.AWXHosts
		parameters := envelope.Parameters.AWXServiceRestart
		state := envelope.ObservedState.AWXService
		facts := snapshot.AWX
		return snapshot.TargetVersion == target.InventorySnapshotSHA256 && facts.InventoryID == target.InventoryID &&
			slices.Equal(facts.HostIDs, target.HostIDs) && facts.InventorySnapshotSHA256 == target.InventorySnapshotSHA256 &&
			facts.JobTemplateID == parameters.JobTemplateID && facts.JobTemplateSnapshotSHA256 == target.JobTemplateSnapshotSHA256 &&
			facts.ServiceName == parameters.ServiceName && facts.OSFamily == parameters.OSFamily && facts.ServiceState == state.ServiceState &&
			facts.ServiceStateSnapshotSHA256 == state.ServiceStateSnapshotSHA256
	case action.ActionGitOpsRevert:
		if snapshot.GitOps == nil || snapshot.Kubernetes != nil || snapshot.AWX != nil || envelope.Target.GitOpsApplication == nil || envelope.Parameters.GitOpsRevert == nil || envelope.ObservedState.GitOpsApplication == nil {
			return false
		}
		expected := GitOpsFacts{
			Provider:         envelope.Parameters.GitOpsRevert.Provider,
			RepositoryID:     envelope.Target.GitOpsApplication.RepositoryID,
			Application:      envelope.Target.GitOpsApplication.Application,
			Path:             envelope.Target.GitOpsApplication.Path,
			BaseCommit:       envelope.Parameters.GitOpsRevert.BaseCommit,
			HeadCommit:       envelope.Parameters.GitOpsRevert.HeadCommit,
			RevertCommit:     envelope.Parameters.GitOpsRevert.RevertCommit,
			DiffSHA256:       envelope.Parameters.GitOpsRevert.DiffSHA256,
			ResultTreeSHA256: envelope.Parameters.GitOpsRevert.TreeSHA256,
			HeadTreeSHA256:   envelope.ObservedState.GitOpsApplication.HeadTreeSHA256,
			LiveRevision:     envelope.ObservedState.GitOpsApplication.LiveRevision,
			DesiredRevision:  envelope.ObservedState.GitOpsApplication.DesiredRevision,
			SyncStatus:       envelope.ObservedState.GitOpsApplication.SyncStatus,
			HealthStatus:     envelope.ObservedState.GitOpsApplication.HealthStatus,
		}
		return *snapshot.GitOps == expected
	default:
		return false
	}
}

func limitsMatchEnvelope(limits ActionLimitsSnapshot, envelope action.Envelope) bool {
	switch envelope.ActionType {
	case action.ActionKubernetesScale:
		parameters := envelope.Parameters.KubernetesScale
		return parameters != nil && limits.MinimumReplicas >= 0 && limits.MaximumReplicas >= limits.MinimumReplicas &&
			parameters.Minimum == limits.MinimumReplicas && parameters.Maximum == limits.MaximumReplicas
	case action.ActionAWXServiceRestart:
		return envelope.Target.AWXHosts != nil && limits.MaxAWXHosts > 0 && limits.MaxAWXHosts <= action.MaxAWXHosts &&
			len(envelope.Target.AWXHosts.HostIDs) <= limits.MaxAWXHosts
	default:
		return limits.MinimumReplicas == 0 && limits.MaximumReplicas == 0 && limits.MaxAWXHosts == 0
	}
}

func normalizeExpression(expression string) (string, error) {
	normalized := strings.TrimSpace(strings.ReplaceAll(expression, "\r\n", "\n"))
	if normalized == "" || len(normalized) > 4096 || strings.ContainsAny(normalized, "\r\x00") {
		return "", fmt.Errorf("policy expression must be between 1 and 4096 normalized bytes")
	}
	return normalized, nil
}

func compileProgram(expression string) (cel.Program, error) {
	environment, err := cel.NewEnv(
		cel.ClearMacros(),
		cel.ParserExpressionSizeLimit(4096),
		cel.ParserRecursionLimit(32),
		cel.Variable("action_type", cel.StringType),
		cel.Variable("stage", cel.StringType),
		cel.Variable("environment", cel.StringType),
		cel.Variable("service_id", cel.StringType),
		cel.Variable("workspace_id", cel.StringType),
		cel.Variable("risk_level", cel.StringType),
		cel.Variable("connector_id", cel.StringType),
		cel.Variable("credential_permission", cel.StringType),
		cel.Variable("mapping_exact", cel.BoolType),
		cel.Variable("whitelisted", cel.BoolType),
	)
	if err != nil {
		return nil, fmt.Errorf("create CEL environment: %w", err)
	}
	ast, issues := environment.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("compile policy expression: %w", issues.Err())
	}
	if ast.OutputType() == nil || !ast.OutputType().IsExactType(cel.BoolType) {
		return nil, fmt.Errorf("policy expression must return bool")
	}
	program, err := environment.Program(ast, cel.CostLimit(1_000), cel.InterruptCheckFrequency(100))
	if err != nil {
		return nil, fmt.Errorf("create policy program: %w", err)
	}
	return program, nil
}

func fresh(now, observedAt time.Time, maximumAge time.Duration) bool {
	if observedAt.IsZero() || observedAt.After(now.Add(maxClockSkew)) {
		return false
	}
	return now.Sub(observedAt) <= maximumAge
}

func validRoles(roles []Role) bool {
	if len(roles) == 0 || len(roles) > 3 {
		return false
	}
	seen := make(map[Role]struct{}, len(roles))
	for _, role := range roles {
		if role != RoleSRE && role != RoleServiceOwner && role != RoleApprover {
			return false
		}
		if _, duplicate := seen[role]; duplicate {
			return false
		}
		seen[role] = struct{}{}
	}
	return true
}

func hasAnyRole(roles []Role, expected ...Role) bool {
	for _, role := range roles {
		if slices.Contains(expected, role) {
			return true
		}
	}
	return false
}

func withReasons(decision Decision, outcome Outcome, reasons ...string) Decision {
	decision.Outcome = outcome
	slices.Sort(reasons)
	decision.ReasonCodes = slices.Compact(reasons)
	return decision
}
