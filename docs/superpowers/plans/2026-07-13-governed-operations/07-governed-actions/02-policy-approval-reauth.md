# Governed Action Policy, Approval, and Reauthentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 immutable ActionPlan V2、实时 Policy/Kill Switch、最近 OIDC 认证和独立人工审批绑定成可在每个安全边界重放验证的 Authorization Bundle。

**Architecture:** Policy Engine 只读取受信任的 current snapshots 并为每个 stage 写 immutable Decision Snapshot；reauth 使用一次性 plan-bound challenge，数据库只保存 OIDC 认证事实哈希；Approval 是每个 Subject 的 append-only decision，Approval Set digest 与 Plan/Policy/Target/Snapshot/Runtime/Kill Switch 全绑定。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4+、OIDC authorization code + PKCE、CEL、JCS/SHA-256、pgx v5、现有 `authn/authz/policy`。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- Production Action 的 recent authentication 最大年龄固定 5 分钟；Proof 最长 10 分钟且不得超过 Plan expiry。
- 浏览器不能提交 Subject、Role、auth_time、acr、amr 或 approval binding；全部来自已验证 OIDC Principal/callback 和服务器 facts。
- requester 不能审批自己的 production Plan；LOW/MEDIUM 一名不同 qualified approver，HIGH 两名不同 qualified approver。
- ADMIN 不自动拥有业务审批或执行权限；只使用 `authz.PermissionActionApprove` / `PermissionExecutionRequest` 和 scoped Service ownership。
- Approval binds exact PlanHash、Target/Snapshot/Runtime/Policy/Kill Switch/Definition digests。任一变化使旧 approval set 永久不匹配，不“更新”审批。
- Approval and Authorization Bundle also bind Phase 6 handoff、immutable READ baseline、live READ admission snapshot and the exact ACCEPTED Phase 7 Action platform successor；任何一项 missing/closed/drifted immediately invalidates the bundle。
- Policy 与 Kill Switch 在 plan submission、approval finalization、queue submission、claim、admission、credential issue、pre-mutation、post-action verification、rollback 分别实时重评。
- Policy dependency unavailable、snapshot older than 5 seconds、Kill Switch disabled、reauth/approval expired 均 fail closed。
- Reason codes 是稳定低敏枚举；不得持久化 CEL raw input、OIDC token/claims document、endpoint、credential 或 raw target response。
- Production repository uses PostgreSQL; memory fakes only in tests。

---

### Task 1: Persist exact multi-boundary policy decisions

**Files:**
- Modify: `internal/policy/engine.go`
- Modify: `internal/policy/engine_test.go`
- Create: `internal/actionauthorization/policy.go`
- Create: `internal/actionauthorization/policy_test.go`
- Create: `internal/actionauthorization/repository.go`
- Create: `internal/actionauthorization/postgres/repository.go`
- Create: `internal/actionauthorization/postgres/repository_test.go`

**Interfaces:**
- Consumes: package 01 Plan/Catalog/Gate；Phase 1–6 current facts；existing immutable CEL `policy.Definition`。
- Produces:

```go
type Stage string

const (
    StagePlanSubmission Stage = "PLAN_SUBMISSION"
    StageApprovalFinalization Stage = "APPROVAL_FINALIZATION"
    StageQueueSubmission Stage = "QUEUE_SUBMISSION"
    StageClaim Stage = "CLAIM"
    StageAdmission Stage = "ADMISSION"
    StageCredentialIssue Stage = "CREDENTIAL_ISSUE"
    StagePreMutation Stage = "PRE_MUTATION"
    StagePostVerification Stage = "POST_VERIFICATION"
    StageRollback Stage = "ROLLBACK"
)

type Evaluator interface {
    Evaluate(
        context.Context,
        actionauthorization.Request,
    ) (actionauthorization.DecisionSnapshot, error)
}

type DecisionRepository interface {
    Append(
        context.Context,
        actionauthorization.DecisionSnapshot,
    ) error
    Get(
        context.Context,
        assetcatalog.Scope,
        string,
    ) (actionauthorization.DecisionSnapshot, error)
}
```

- [ ] **Step 1: Write failing stage/binding/drift tests**

```go
func TestEveryAuthorizationStageBindsExactPlanClosure(t *testing.T)
func TestPolicyRejectsSnapshotRuntimeDefinitionAndKillDrift(t *testing.T)
func TestPolicyRejectsClosedReadAdmissionOrPlatformSuccessorDrift(t *testing.T)
func TestPolicyRejectsStaleOrUnavailableFacts(t *testing.T)
func TestClosedOrSuspendedTypeCannotQueueClaimOrMutate(t *testing.T)
func TestNonProductionGateCannotAuthorizeProduction(t *testing.T)
func TestDecisionRepositoryIsAppendOnlyAndScoped(t *testing.T)
func TestPolicyReasonsContainNoRawFactValues(t *testing.T)
```

Run the closure mutation matrix at every Stage. Gate rules: non-production accepts `NON_PRODUCTION_READY|DRILLING|CANARY_APPROVED|CANARY_RUNNING|AVAILABLE`; production canary accepts only `CANARY_RUNNING` with matching decision/window; ordinary production accepts only `AVAILABLE`.

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
go test ./internal/policy ./internal/actionauthorization/... -run 'Policy|Authorization|Decision' -count=1
```

Expected: FAIL because stages, exact request and decision repository do not exist.

- [ ] **Step 3: Implement exact Request and DecisionSnapshot**

```go
type ExactBinding struct {
    PlanID string
    PlanHash string
    ActionType action.ActionType
    DefinitionRevision int64
    DefinitionDigest string
    AssetID string
    AssetRevision int64
    SnapshotDigest string
    TargetDigest string
    RuntimeBundleDigest string
    PolicyVersion string
    PolicyDigest string
    KillSwitchRevision string
    KillSwitchDigest string
    EvidenceDigest string
    GateRevision int64
    GateStatus actioncatalog.GateStatus
    Platform action.PlatformBinding
}

type Request struct {
    Scope assetcatalog.Scope
    Stage Stage
    Binding ExactBinding
    Production bool
    CanaryDecisionID string
    ActorSubject string
    EvaluatedAt time.Time
}

type DecisionSnapshot struct {
    ID string
    Scope assetcatalog.Scope
    Stage Stage
    Binding ExactBinding
    Outcome policy.Outcome
    ReasonCodes []string
    FactsObservedAt time.Time
    EvaluatedAt time.Time
    ExpiresAt time.Time
    InputDigest string
    DecisionDigest string
}
```

Allowed reasons are fixed: `PLAN_BINDING_DRIFT`、`PHASE6_HANDOFF_DRIFT`、`READ_BASELINE_DRIFT`、`READ_ADMISSION_CLOSED`、`ACTION_PLATFORM_NOT_ACCEPTED`、`ACTION_PLATFORM_DRIFT`、`UNAUTHORIZED_WRITE_SURFACE`、`ACTION_TYPE_CLOSED`、`CANARY_NOT_AUTHORIZED`、`ASSET_NOT_ACTIVE`、`MAPPING_NOT_EXACT`、`SNAPSHOT_DRIFT`、`TARGET_DRIFT`、`RUNTIME_DRIFT`、`POLICY_DRIFT`、`KILL_SWITCH_CLOSED`、`FACTS_STALE`、`FACTS_UNAVAILABLE`、`APPROVAL_INCOMPLETE`、`REAUTH_REQUIRED`、`REALM_MISMATCH`、`CREDENTIAL_SCOPE_DRIFT`、`ADMISSION_DENIED`。

The evaluator re-resolves current facts, compares every field, evaluates immutable CEL, sorts/deduplicates reasons, canonicalizes DecisionSnapshot and stores it. At every Stage it also re-reads the exact Phase 6 decision/handoff、current READ admission revision/state、current ACCEPTED Action successor and `UNAUTHORIZED_WRITE_SURFACE_ABSENT`; cached approval-time values are evidence to compare, never live authority. Caller-supplied `EvaluatedAt` is used only in deterministic tests; production constructor supplies server clock and rejects external time.

- [ ] **Step 4: Run policy tests**

Run:

```bash
go test ./internal/policy ./internal/actionauthorization/... -count=1
go test -race ./internal/actionauthorization/... -count=1
```

Expected: PASS；all stages, stale facts, gate modes, digests and redaction pass.

- [ ] **Step 5: Commit**

```bash
git add internal/policy internal/actionauthorization
git commit -m "feat: bind action policy to exact runtime facts"
```

### Task 2: Implement one-time plan-bound OIDC reauthentication proofs

**Files:**
- Create: `internal/actionapproval/reauth.go`
- Create: `internal/actionapproval/reauth_test.go`
- Create: `internal/actionapproval/reauth_repository.go`
- Create: `internal/actionapproval/postgres/reauth_repository.go`
- Create: `internal/actionapproval/postgres/reauth_repository_test.go`
- Modify: `internal/authn/authenticator.go`
- Modify: `internal/authn/authenticator_test.go`
- Modify: `internal/authz/authorizer.go`
- Modify: `internal/authz/authorizer_test.go`

**Interfaces:**
- Consumes: verified OIDC Principal/issuer/audience/session/auth_time/acr/amr from Phase 6；package 01 Plan。
- Produces:

```go
type ReauthService interface {
    Start(
        context.Context,
        actionapproval.StartReauthCommand,
    ) (actionapproval.ReauthChallenge, error)
    Complete(
        context.Context,
        actionapproval.CompleteReauthCommand,
    ) (actionapproval.ReauthProof, error)
    Consume(
        context.Context,
        actionapproval.ConsumeReauthCommand,
    ) (actionapproval.ReauthProof, error)
}
```

- [ ] **Step 1: Write failing challenge/replay/claim-source tests**

```go
func TestReauthChallengeBindsPlanSubjectIntentAndReturnPath(t *testing.T)
func TestReauthStartForcesPromptLoginMaxAgeZeroNonceAndPKCE(t *testing.T)
func TestReauthCompleteUsesOnlyVerifiedOIDCClaims(t *testing.T)
func TestReauthCompleteRejectsNonceIssuerAudienceOrACRMismatch(t *testing.T)
func TestReauthRejectsAuthTimeOlderThanFiveMinutes(t *testing.T)
func TestReauthProofExpiresAtTenMinutesOrPlanExpiry(t *testing.T)
func TestReauthProofCanBeConsumedExactlyOnce(t *testing.T)
func TestReauthProofCannotCrossPlanSubjectScopeOrApprovalIntent(t *testing.T)
func TestOIDCTokenAndRawClaimsAreNeverPersisted(t *testing.T)
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
go test ./internal/actionapproval/... ./internal/authn ./internal/authz -run 'Reauth|RecentAuthentication' -count=1
```

Expected: FAIL because plan-bound reauth challenge/proof does not exist.

- [ ] **Step 3: Implement exact trusted inputs and proof**

```go
type VerifiedOIDCAuthentication struct {
    Subject string
    SessionID string
    Issuer string
    Audience string
    AuthTime time.Time
    ACR string
    AMR []string
}

type ReauthProof struct {
    ID string
    Scope assetcatalog.Scope
    PlanID string
    PlanHash string
    Intent string
    Subject string
    SessionIDHash string
    IssuerHash string
    AudienceHash string
    AuthTime time.Time
    ACR string
    AMRDigest string
    CompletedAt time.Time
    ExpiresAt time.Time
    ProofDigest string
}

type CompleteReauthCommand struct {
    ChallengeID string
    OpaqueState string
    Authentication VerifiedOIDCAuthentication
}
```

Intent is one of `APPROVE_ACTION`、`REQUEST_EXECUTION`、`AUTHORIZE_CANARY`、`AUTHORIZE_ROLLBACK`. `Start` receives authenticated current Subject server-side, creates nonce/state/PKCE S256, and sends Keycloak `prompt=login&max_age=0`; the short-lived code verifier stays only in the encrypted `Secure; HttpOnly; SameSite=Lax` OIDC transaction cookie while PostgreSQL stores hashes of nonce/state/session/issuer/audience/amr. `Complete` is called only after the existing authenticator exchanges and verifies the authorization code; it validates opaque state constant-time、nonce、issuer、audience、Subject equality、required ACR/AMR、current plan hash and ≤5-minute auth age, then marks challenge consumed and appends immutable Proof in one transaction. `Consume` locks Proof and inserts one consumption record for exact intent/subject/plan.

- [ ] **Step 4: Run reauth and race tests**

Run:

```bash
go test ./internal/actionapproval/... ./internal/authn ./internal/authz -run 'Reauth|RecentAuthentication' -count=1
go test -race ./internal/actionapproval/... -count=1
```

Expected: PASS；concurrent double callback/consume has one winner；no token or raw claims reach persistence/log projection.

- [ ] **Step 5: Commit**

```bash
git add internal/actionapproval internal/authn internal/authz
git commit -m "feat: add plan-bound action reauthentication"
```

### Task 3: Implement normalized approval decisions and Authorization Bundles

**Files:**
- Create: `internal/actionapproval/approval.go`
- Create: `internal/actionapproval/approval_test.go`
- Create: `internal/actionapproval/repository.go`
- Create: `internal/actionapproval/postgres/repository.go`
- Create: `internal/actionapproval/postgres/repository_test.go`
- Create: `internal/actionapproval/service.go`
- Create: `internal/actionapproval/service_test.go`
- Create: `internal/actionauthorization/bundle.go`
- Create: `internal/actionauthorization/bundle_test.go`

**Interfaces:**
- Consumes: Task 1 evaluator/repository；Task 2 consumed Reauth Proof；package 01 immutable Plan。
- Produces:

```go
type ApprovalRepository interface {
    AppendDecision(
        context.Context,
        actionapproval.Decision,
    ) error
    ListDecisions(
        context.Context,
        assetcatalog.Scope,
        string,
        string,
    ) ([]actionapproval.Decision, error)
}

type ApprovalService interface {
    Decide(
        context.Context,
        authn.Principal,
        actionapproval.DecideCommand,
    ) (actionapproval.ApprovalSet, error)
    ResolveSet(
        context.Context,
        assetcatalog.Scope,
        string,
    ) (actionapproval.ApprovalSet, error)
}

type AuthorizationBundle struct {
    PlanID string
    PlanHash string
    Binding actionauthorization.ExactBinding
    QueueDecisionID string
    QueueDecisionDigest string
    ApprovalSetID string
    ApprovalSetDigest string
    ExecutionRequester string
    ExecutionReauthProofID string
    Phase6HandoffID string
    Phase6HandoffDigest string
    ReadBaselineDigest string
    ReadAdmissionRevision int64
    ReadAdmissionDigest string
    ActionPlatformID string
    ActionPlatformRevision int64
    ActionPlatformManifestDigest string
    ActionManifestDigest string
    ExpiresAt time.Time
    BundleDigest string
}
```

- [ ] **Step 1: Write failing separation-of-duty and concurrency tests**

```go
func TestRequesterCannotApproveOwnProductionPlan(t *testing.T)
func TestLowAndMediumRequireOneDistinctQualifiedApprover(t *testing.T)
func TestHighRequiresTwoDistinctQualifiedApprovers(t *testing.T)
func TestSameSubjectCannotCountTwiceAcrossRolesOrSessions(t *testing.T)
func TestRejectionOrRevocationPreventsApprovalSet(t *testing.T)
func TestPlanOrPolicyDriftInvalidatesOldDecisions(t *testing.T)
func TestConcurrentDuplicateDecisionCreatesOneImmutableRecord(t *testing.T)
func TestAuthorizationBundleRequiresExecutionRequesterReauth(t *testing.T)
func TestAuthorizationBundleBindsCurrentReadAdmissionAndActionPlatform(t *testing.T)
func TestAuthorizationBundleRejectsPhase6HandoffOrSuccessorDrift(t *testing.T)
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
go test ./internal/actionapproval/... ./internal/actionauthorization/... -run 'Approval|AuthorizationBundle' -count=1
```

Expected: FAIL because approval decision and bundle services do not exist.

- [ ] **Step 3: Implement immutable Decision and ApprovalSet**

```go
type DecisionValue string

const (
    DecisionApproved DecisionValue = "APPROVED"
    DecisionRejected DecisionValue = "REJECTED"
    DecisionRevoked DecisionValue = "REVOKED"
)

type Decision struct {
    ID string
    Scope assetcatalog.Scope
    PlanID string
    PlanHash string
    ApprovalRound string
    Subject string
    Value DecisionValue
    RoleAtDecision authn.Role
    ReauthProofID string
    PolicyDecisionID string
    BindingDigest string
    ReasonCode string
    DecidedAt time.Time
    ExpiresAt time.Time
    DecisionDigest string
}

type ApprovalSet struct {
    ID string
    Scope assetcatalog.Scope
    PlanID string
    PlanHash string
    RiskLevel string
    Required int
    Decisions []Decision
    PolicyDecisionID string
    BindingDigest string
    ExpiresAt time.Time
    Digest string
}
```

`Decide` authorizes `PermissionActionApprove`, consumes `APPROVE_ACTION` proof, re-evaluates `APPROVAL_FINALIZATION` policy, prevents requester self-approval and appends one decision per Subject/round. Any REJECTED or latest REVOKED makes the round non-approved. `ResolveSet` sorts Subjects, requires exact binding/current policy and computes JCS digest.

Execution request separately authorizes `PermissionExecutionRequest`, consumes `REQUEST_EXECUTION` proof, evaluates `QUEUE_SUBMISSION` and builds `AuthorizationBundle`. The bundle copies Platform fields only from the just-re-resolved trusted closure, recomputes its JCS digest, and expires no later than the earliest Plan、approval、reauth、READ admission observation or successor evidence deadline. It does not issue a credential or enqueue by itself; Package 3 persists bundle + queue atomically.

- [ ] **Step 4: Run repository, race and policy tests**

Run:

```bash
go test ./internal/actionapproval/... ./internal/actionauthorization/... ./internal/policy -count=1
go test -race ./internal/actionapproval/... ./internal/actionauthorization/... -count=1
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/actionapproval/postgres -run 'Concurrent|Scope|Immutable' -count=1
```

Expected: all PASS；self/duplicate/expired/drifted approvals fail；exact qualified sets and bundles are deterministic.

- [ ] **Step 5: Commit**

```bash
git add internal/actionapproval internal/actionauthorization internal/policy
git commit -m "feat: bind approvals to governed action plans"
```
