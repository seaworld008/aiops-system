package policy

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/aiops-system/control-plane/internal/action"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
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
	ReasonSeparationOfDuties      = "SEPARATION_OF_DUTIES"
	ReasonTargetStateDrift        = "TARGET_STATE_DRIFT"
	ReasonPolicyVersionMismatch   = "POLICY_VERSION_MISMATCH"
	ReasonKillSwitchDisabled      = "KILL_SWITCH_DISABLED"
	ReasonCELPolicyDenied         = "CEL_POLICY_DENIED"
	ReasonInvalidEnvelope         = "INVALID_ACTION_ENVELOPE"
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
	Version    string
	Expression string
}

type SwitchState struct {
	GlobalEnabled      bool
	EnvironmentEnabled bool
	ConnectorEnabled   bool
	ActionEnabled      bool
}

type Approval struct {
	SubjectID     string
	Roles         []Role
	Decision      ApprovalDecision
	ActionID      string
	PlanHash      string
	PolicyVersion string
	TargetVersion string
	ExpiresAt     time.Time
}

type Input struct {
	Stage                Stage
	Envelope             action.Envelope
	RequesterID          string
	Environment          string
	ServiceID            string
	CurrentTargetVersion string
	Switches             SwitchState
	Approvals            []Approval
	Now                  time.Time
}

type Decision struct {
	Outcome       Outcome
	PolicyVersion string
	Stage         Stage
	PlanHash      string
	ReasonCodes   []string
	EvaluatedAt   time.Time
}

type Engine struct {
	definition Definition
	resolver   action.KeyResolver
	program    cel.Program
}

var definitionTokenPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$`)

func NewEngine(definition Definition, resolver action.KeyResolver) (*Engine, error) {
	if !definitionTokenPattern.MatchString(definition.Version) {
		return nil, fmt.Errorf("valid policy version is required")
	}
	if resolver == nil {
		return nil, fmt.Errorf("action envelope key resolver is required")
	}
	if strings.TrimSpace(definition.Expression) == "" || len(definition.Expression) > 4096 {
		return nil, fmt.Errorf("policy expression must be between 1 and 4096 bytes")
	}
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
		cel.Variable("mapping_exact", cel.BoolType),
		cel.Variable("whitelisted", cel.BoolType),
	)
	if err != nil {
		return nil, fmt.Errorf("create CEL environment: %w", err)
	}
	ast, issues := environment.Compile(definition.Expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("compile policy expression: %w", issues.Err())
	}
	if ast.OutputType() == nil || !ast.OutputType().IsExactType(cel.BoolType) {
		return nil, fmt.Errorf("policy expression must return bool")
	}
	program, err := environment.Program(
		ast,
		cel.CostLimit(1_000),
		cel.InterruptCheckFrequency(100),
	)
	if err != nil {
		return nil, fmt.Errorf("create policy program: %w", err)
	}
	return &Engine{definition: definition, resolver: resolver, program: program}, nil
}

func (engine *Engine) Evaluate(ctx context.Context, input Input) (Decision, error) {
	decision := Decision{
		Outcome: OutcomeDeny, PolicyVersion: engine.definition.Version, Stage: input.Stage,
		PlanHash: input.Envelope.PlanHash, EvaluatedAt: input.Now,
	}
	if err := validateInput(input); err != nil {
		return decision, err
	}
	if input.Envelope.PolicyVersion != engine.definition.Version {
		return engine.withReasons(decision, OutcomeDeny, ReasonPolicyVersionMismatch), nil
	}
	if err := action.Verify(ctx, input.Envelope, engine.resolver, input.Now); err != nil {
		return engine.withReasons(decision, OutcomeDeny, ReasonInvalidEnvelope), nil
	}
	if input.ServiceID != input.Envelope.Target.ServiceID || input.Environment != input.Envelope.Target.EnvironmentID {
		return engine.withReasons(decision, OutcomeDeny, ReasonTargetStateDrift), nil
	}
	expectedVersion, err := expectedTargetVersion(input.Envelope)
	if err != nil {
		return engine.withReasons(decision, OutcomeDeny, ReasonInvalidEnvelope), nil
	}
	if input.CurrentTargetVersion != expectedVersion {
		return engine.withReasons(decision, OutcomeDeny, ReasonTargetStateDrift), nil
	}
	if !input.Switches.GlobalEnabled || !input.Switches.EnvironmentEnabled || !input.Switches.ConnectorEnabled || !input.Switches.ActionEnabled {
		return engine.withReasons(decision, OutcomeDeny, ReasonKillSwitchDisabled), nil
	}

	result, _, err := engine.program.ContextEval(ctx, map[string]any{
		"action_type":   string(input.Envelope.ActionType),
		"stage":         string(input.Stage),
		"environment":   input.Environment,
		"service_id":    input.ServiceID,
		"workspace_id":  input.Envelope.WorkspaceID,
		"risk_level":    input.Envelope.Risk.Level,
		"connector_id":  input.Envelope.CredentialScope.ConnectorID,
		"mapping_exact": input.Envelope.Preconditions.MappingResult == "EXACT",
		"whitelisted":   input.Envelope.Preconditions.RequireWhitelist,
	})
	if err != nil {
		return engine.withReasons(decision, OutcomeDeny, ReasonCELPolicyDenied), fmt.Errorf("evaluate CEL policy: %w", err)
	}
	allowed, ok := result.(types.Bool)
	if !ok || !bool(allowed) {
		return engine.withReasons(decision, OutcomeDeny, ReasonCELPolicyDenied), nil
	}

	approvalReasons, satisfied := evaluateApprovals(input, expectedVersion)
	if !satisfied {
		outcome := OutcomeDeny
		if input.Stage == StagePlanSubmission {
			outcome = OutcomeRequireApproval
		}
		approvalReasons = append(approvalReasons, ReasonApprovalRequired)
		return engine.withReasons(decision, outcome, approvalReasons...), nil
	}
	decision.Outcome = OutcomeAllow
	return decision, nil
}

func validateInput(input Input) error {
	if input.Stage != StagePlanSubmission && input.Stage != StageCredentialIssue && input.Stage != StagePreExecution {
		return fmt.Errorf("unsupported policy evaluation stage %q", input.Stage)
	}
	if !definitionTokenPattern.MatchString(input.RequesterID) || !definitionTokenPattern.MatchString(input.Environment) || !definitionTokenPattern.MatchString(input.ServiceID) || strings.TrimSpace(input.CurrentTargetVersion) == "" {
		return fmt.Errorf("requester, environment, service, and current target version are required")
	}
	if input.Now.IsZero() {
		return fmt.Errorf("policy evaluation time is required")
	}
	return nil
}

func expectedTargetVersion(envelope action.Envelope) (string, error) {
	switch envelope.ActionType {
	case action.ActionKubernetesRolloutRestart, action.ActionKubernetesScale:
		if envelope.Target.KubernetesDeployment == nil {
			return "", fmt.Errorf("missing Kubernetes target")
		}
		return envelope.Target.KubernetesDeployment.ResourceVersion, nil
	case action.ActionGitOpsRevert:
		if envelope.Parameters.GitOpsRevert == nil {
			return "", fmt.Errorf("missing GitOps parameters")
		}
		return envelope.Parameters.GitOpsRevert.HeadCommit, nil
	case action.ActionAWXServiceRestart:
		if envelope.Target.AWXHosts == nil {
			return "", fmt.Errorf("missing AWX target")
		}
		return envelope.Target.AWXHosts.InventorySnapshotSHA256, nil
	default:
		return "", fmt.Errorf("unsupported action type")
	}
}

func evaluateApprovals(input Input, expectedTargetVersion string) ([]string, bool) {
	valid := make(map[string]Approval)
	reasons := make([]string, 0, 3)
	for _, approval := range input.Approvals {
		if approval.Decision != ApprovalApproved {
			continue
		}
		if !input.Now.Before(approval.ExpiresAt) {
			reasons = append(reasons, ReasonApprovalExpired)
			continue
		}
		if approval.ExpiresAt.After(input.Envelope.ExpiresAt) || approval.ActionID != input.Envelope.ActionID || approval.PlanHash != input.Envelope.PlanHash || approval.PolicyVersion != input.Envelope.PolicyVersion || approval.TargetVersion != expectedTargetVersion {
			reasons = append(reasons, ReasonApprovalBindingMismatch)
			continue
		}
		if !definitionTokenPattern.MatchString(approval.SubjectID) || approval.SubjectID == input.RequesterID {
			reasons = append(reasons, ReasonSeparationOfDuties)
			continue
		}
		if _, duplicate := valid[approval.SubjectID]; duplicate || !validRoles(approval.Roles) {
			reasons = append(reasons, ReasonApprovalBindingMismatch)
			continue
		}
		valid[approval.SubjectID] = approval
	}

	if input.Envelope.ActionType != action.ActionGitOpsRevert {
		for _, approval := range valid {
			if hasAnyRole(approval.Roles, RoleSRE, RoleServiceOwner, RoleApprover) {
				return reasons, true
			}
		}
		return reasons, false
	}
	if len(valid) < 2 {
		return reasons, false
	}
	hasSRE := false
	hasOwner := false
	for _, approval := range valid {
		hasSRE = hasSRE || hasAnyRole(approval.Roles, RoleSRE)
		hasOwner = hasOwner || hasAnyRole(approval.Roles, RoleServiceOwner)
	}
	return reasons, hasSRE && hasOwner
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

func (engine *Engine) withReasons(decision Decision, outcome Outcome, reasons ...string) Decision {
	decision.Outcome = outcome
	slices.Sort(reasons)
	decision.ReasonCodes = slices.Compact(reasons)
	return decision
}
