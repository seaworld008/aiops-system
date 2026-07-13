# Post-Action Verification, Reconciliation, and Rollback Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 WRITE credential 已请求吊销后，用独立 READ facts 验证变更；对不确定结果持久对账，只执行可证明安全的补偿，否则生成完整 Receipt 并升级人工。

**Architecture:** Mutation Receipt 只是 Runner 声明，不决定成功；`actionverification` 用 Phase 6 的真实 READ path 产生独立 Verification Run/Checks。UNKNOWN、verification failure、worker crash 进入 fenced reconciliation；只有 K8S_SCALE 且无 intervening change 时可按原批准 Compensation 自动恢复，其余动作必须新 Plan 或人工处理。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4+、Temporal、pgx v5、Phase 6 READ Runtime/Runner、JCS/SHA-256、Ed25519 Receipt signing、Prometheus metrics。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- WRITE executor/Runner output cannot mark an Action successful；only independent Verification can produce verified success。
- Verification uses READ identity、READ Realm、READ credential and published typed Capability；it never reuses WRITE credential/issuer/session。
- Mutation completes → local secret clears → durable revocation requested → only then post-action verification starts. Cleanup uncertainty blocks success。
- Verification input binds exact Action/Attempt/Plan/target and expected post-state, with bounded timeout/items/bytes and low-sensitivity checks。
- Before verification, reconciliation, rollback and Receipt finalization, workers revalidate the Phase 6 handoff/READ baseline/current READ admission and exact ACCEPTED Action platform successor；a closed or drifted closure yields INCONCLUSIVE/HUMAN_REQUIRED and never authorizes another mutation。
- UNKNOWN is never retried as a mutation. Reconciliation reads facts and classifies; it cannot infer success from timeout absence。
- Safe automatic rollback is limited to `K8S_SCALE/EXACT_SCALE_RESTORE`, original approval coverage, live rollback ALLOW, exact UID and no intervening resourceVersion/generation change。
- Rollout restart、GitOps revert and AWX restart compensation is `MANUAL_ONLY/NEW_PLAN_ONLY`；no automatic opposite mutation。
- Reconciliation/rollback use their own lease/epoch/fencing and credential Attempt；stale workers cannot decide/finalize。
- Target remains locked for `UNKNOWN/RECONCILING/ROLLING_BACK/HUMAN_REQUIRED` until signed terminal resolution。
- Receipt/audit stores digests and stable codes only, no raw target response、credential、endpoint、customer data or exception text。
- Production workers require PostgreSQL/Temporal/READ runtime/signer; no in-memory/fake fallback。

---

### Task 1: Implement independent typed post-action verification

**Files:**
- Create: `internal/actionverification/types.go`
- Create: `internal/actionverification/types_test.go`
- Create: `internal/actionverification/verifier.go`
- Create: `internal/actionverification/verifier_test.go`
- Create: `internal/actionverification/postgres/repository.go`
- Create: `internal/actionverification/postgres/repository_test.go`
- Create: `internal/actionverification/kubernetes.go`
- Create: `internal/actionverification/kubernetes_test.go`
- Create: `internal/actionverification/gitops.go`
- Create: `internal/actionverification/gitops_test.go`
- Create: `internal/actionverification/awx.go`
- Create: `internal/actionverification/awx_test.go`
- Create: `internal/actionverification/architecture_boundary_test.go`

**Interfaces:**
- Consumes: package 03 Mutation Receipt/Attempt；Phase 6 typed READ Runtime、handoff/current admission；Phase 7 Action platform successor and credential cleanup inspector。
- Produces:

```go
type FactsReader interface {
    Read(
        context.Context,
        actionverification.ReadRequest,
    ) (actionverification.ObservedFacts, error)
}

type Repository interface {
    Start(
        context.Context,
        actionverification.StartCommand,
    ) (actionverification.Run, bool, error)
    AppendCheck(
        context.Context,
        actionverification.Check,
    ) error
    Complete(
        context.Context,
        actionverification.CompleteCommand,
    ) (actionverification.Run, error)
    Get(
        context.Context,
        assetcatalog.Scope,
        string,
    ) (actionverification.Run, []actionverification.Check, error)
}

type Verifier interface {
    Verify(
        context.Context,
        actionverification.VerifyCommand,
    ) (actionverification.Run, error)
}
```

- [ ] **Step 1: Write failing independent-facts and result tests**

```go
func TestVerificationCannotUseWriteRunnerReceiptAsObservedFacts(t *testing.T)
func TestVerificationWaitsForTerminalCredentialCleanup(t *testing.T)
func TestKubernetesRestartRequiresNewTemplateGenerationAndReadyRollout(t *testing.T)
func TestKubernetesScaleRequiresExactDesiredUpdatedAndAvailableReplicas(t *testing.T)
func TestGitOpsRequiresExactMergedTreeDesiredLiveAndHealthyState(t *testing.T)
func TestAWXRequiresExactJobTemplateHostsSuccessAndServiceHealth(t *testing.T)
func TestVerificationRejectsTargetRuntimeOrPlanDrift(t *testing.T)
func TestVerificationRejectsClosedReadAdmissionOrDualPlatformDrift(t *testing.T)
func TestVerificationChecksContainOnlyBoundedSafeFields(t *testing.T)
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
go test ./internal/actionverification/... -count=1
```

Expected: FAIL because verification domain/repository/provider verifiers do not exist.

- [ ] **Step 3: Implement exact verification state and checks**

```go
type Status string

const (
    StatusQueued Status = "QUEUED"
    StatusRunning Status = "RUNNING"
    StatusVerified Status = "VERIFIED"
    StatusFailed Status = "FAILED"
    StatusInconclusive Status = "INCONCLUSIVE"
)

type Check struct {
    RunID string
    Code string
    Status string
    ExpectedDigest string
    ObservedDigest string
    ReasonCode string
    ObservedAt time.Time
    CheckDigest string
}

type Result struct {
    Status Status
    ReasonCode string
    ExpectedStateDigest string
    ObservedStateDigest string
    ChecksDigest string
    CompletedAt time.Time
}
```

Fixed check codes: `PHASE6_HANDOFF`、`READ_BASELINE`、`READ_ADMISSION`、`ACTION_PLATFORM_SUCCESSOR`、`UNAUTHORIZED_WRITE_SURFACE`、`CREDENTIAL_CLEANUP`、`PLAN_TARGET_IDENTITY`、`K8S_UID`、`K8S_GENERATION`、`K8S_DESIRED_REPLICAS`、`K8S_UPDATED_REPLICAS`、`K8S_AVAILABLE_REPLICAS`、`GIT_COMMIT_TREE`、`GIT_CHANGE_REQUEST`、`ARGO_DESIRED_LIVE`、`ARGO_HEALTH`、`AWX_JOB_TEMPLATE`、`AWX_INVENTORY_HOSTS`、`AWX_JOB_STATUS`、`SERVICE_HEALTH`、`OUTPUT_SCHEMA`、`DLP`。

Reader receives typed IDs/digests, never arbitrary query or endpoint. Verifier polls only within signed timeout (≤900s), records each bounded check, sorts codes and completes once. Timeout/inconsistent facts yield INCONCLUSIVE, not FAILED retry.

- [ ] **Step 4: Run verification, race and PostgreSQL tests**

Run:

```bash
go test ./internal/actionverification/... -count=1
go test -race ./internal/actionverification/... -count=1
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/actionverification/postgres -run 'Start|Complete|Immutable|Scope' -count=1
```

Expected: all PASS；executor claims cannot satisfy verification；all four typed paths and cleanup gate pass.

- [ ] **Step 5: Commit**

```bash
git add internal/actionverification
git commit -m "feat: independently verify governed actions"
```

### Task 2: Reconcile uncertain outcomes without mutation retry

**Files:**
- Create: `internal/actionreconciliation/types.go`
- Create: `internal/actionreconciliation/types_test.go`
- Create: `internal/actionreconciliation/reconciler.go`
- Create: `internal/actionreconciliation/reconciler_test.go`
- Create: `internal/actionreconciliation/postgres/repository.go`
- Create: `internal/actionreconciliation/postgres/repository_test.go`
- Create: `internal/actionreconciliation/worker.go`
- Create: `internal/actionreconciliation/worker_test.go`

**Interfaces:**
- Consumes: UNKNOWN Mutation Receipt、FAILED/INCONCLUSIVE Verification、typed independent FactsReader、Attempt and cleanup records。
- Produces:

```go
type Repository interface {
    Open(
        context.Context,
        actionreconciliation.OpenCommand,
    ) (actionreconciliation.Case, bool, error)
    Claim(
        context.Context,
        actionreconciliation.ClaimRequest,
    ) (actionreconciliation.Claim, error)
    Heartbeat(
        context.Context,
        actionreconciliation.HeartbeatRequest,
    ) error
    Complete(
        context.Context,
        actionreconciliation.CompleteCommand,
    ) (actionreconciliation.Case, error)
}

type Reconciler interface {
    Reconcile(
        context.Context,
        actionreconciliation.Claim,
    ) (actionreconciliation.Determination, error)
}
```

- [ ] **Step 1: Write failing uncertainty/fencing/no-retry tests**

```go
func TestUnknownMutationOpensOneDurableReconciliationCase(t *testing.T)
func TestDuplicateWorkersUseOneClaimAndMonotonicFence(t *testing.T)
func TestReconciliationNeverCallsWriteAdapter(t *testing.T)
func TestKubernetesDeterminationUsesUIDVersionMarkerAndReplicas(t *testing.T)
func TestGitOpsDeterminationUsesDeterministicBranchChangeAndTree(t *testing.T)
func TestAWXDeterminationUsesActionMarkerTemplateInventoryAndJob(t *testing.T)
func TestAmbiguousOrInterveningChangeRequiresHuman(t *testing.T)
func TestStaleReconcilerCannotCompleteOrReleaseTargetLock(t *testing.T)
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
go test ./internal/actionreconciliation/... -count=1
```

Expected: FAIL because reconciliation domain/worker do not exist.

- [ ] **Step 3: Implement exact determination contract**

```go
type Outcome string

const (
    OutcomeAppliedExpected Outcome = "APPLIED_EXPECTED"
    OutcomeNotApplied Outcome = "NOT_APPLIED"
    OutcomeAppliedUnexpected Outcome = "APPLIED_UNEXPECTED"
    OutcomeIndeterminate Outcome = "INDETERMINATE"
)

type Determination struct {
    Outcome Outcome
    ReasonCode string
    PreStateDigest string
    ExpectedStateDigest string
    ObservedStateDigest string
    ExternalOperationID string
    FactsDigest string
    ObservedAt time.Time
    DeterminationDigest string
}
```

Provider rules:

- Kubernetes restart: exact UID plus signed action-id/plan-hash annotations and changed template generation means applied; exact old template/resourceVersion with no marker means not applied; any conflicting marker or intervening update is indeterminate.
- Kubernetes scale: exact UID + expected replicas + monotonic generation means applied; exact original replicas and unchanged precondition means not applied; any third value/HPA/new writer is applied-unexpected or indeterminate.
- GitOps: deterministic branch/change-request ID/revert commit/tree proves applied; verified no branch/change and unchanged head proves not applied; different head/tree or partially created objects is indeterminate.
- AWX: exact `aiops_action_id` marker、template/inventory/host set and Job ID/status proves launch; verified no matching job proves not applied only when provider offers complete audit window; partial/unknown job is indeterminate.

APPLIED_EXPECTED enters independent Verification. NOT_APPLIED becomes failed without re-executing. APPLIED_UNEXPECTED/INDETERMINATE keeps target lock and enters rollback eligibility/human escalation.

- [ ] **Step 4: Run reconciliation, race and PostgreSQL tests**

Run:

```bash
go test ./internal/actionreconciliation/... -count=1
go test -race ./internal/actionreconciliation/... -count=1
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/actionreconciliation/postgres -run 'Claim|Fence|Complete|Scope' -count=1
```

Expected: all PASS；no code path calls mutation adapter twice；stale claim cannot decide.

- [ ] **Step 5: Commit**

```bash
git add internal/actionreconciliation
git commit -m "feat: reconcile uncertain action outcomes"
```

### Task 3: Add safe scale rollback, signed terminal Receipt, recovery, audit and metrics

**Files:**
- Create: `internal/actionrollback/service.go`
- Create: `internal/actionrollback/service_test.go`
- Create: `internal/actionrollback/postgres/repository.go`
- Create: `internal/actionrollback/postgres/repository_test.go`
- Create: `internal/actionreceipt/receipt.go`
- Create: `internal/actionreceipt/receipt_test.go`
- Create: `internal/actionreceipt/postgres/repository.go`
- Create: `internal/actionreceipt/postgres/repository_test.go`
- Create: `internal/actionrecovery/reconciler.go`
- Create: `internal/actionrecovery/reconciler_test.go`
- Create: `internal/actionobservability/metrics.go`
- Create: `internal/actionobservability/metrics_test.go`
- Modify: `internal/execution/postgres/repository.go`
- Modify: `internal/execution/postgres/repository_test.go`

**Interfaces:**
- Consumes: package 02 rollback-stage policy/reauth/approval coverage；package 03 isolated credential/adapter；Tasks 1–2 facts。
- Produces:

```go
type RollbackService interface {
    Evaluate(
        context.Context,
        actionrollback.EvaluateCommand,
    ) (actionrollback.Eligibility, error)
    Execute(
        context.Context,
        actionrollback.ExecuteCommand,
    ) (actionrollback.Attempt, error)
}

type ReceiptRepository interface {
    Append(
        context.Context,
        actionreceipt.Receipt,
    ) error
    Get(
        context.Context,
        assetcatalog.Scope,
        string,
    ) (actionreceipt.Receipt, error)
}
```

- [ ] **Step 1: Write failing compensation/receipt/recovery tests**

```go
func TestOnlyExactKubernetesScaleRestoreIsAutomaticallyEligible(t *testing.T)
func TestRollbackRequiresOriginalCoverageLivePolicyAndNoInterveningChange(t *testing.T)
func TestRollbackUsesNewAttemptCredentialAndFence(t *testing.T)
func TestRollbackVerificationMustObserveOriginalReplicaState(t *testing.T)
func TestRestartGitOpsAndAWXRequireNewPlanOrHuman(t *testing.T)
func TestReceiptBindsEveryAuthorizationExecutionVerificationAndCleanupDigest(t *testing.T)
func TestReceiptBindsPhase6HandoffReadAdmissionAndActionPlatformSuccessor(t *testing.T)
func TestReceiptIsImmutableSignedAndSecretSafe(t *testing.T)
func TestRestartedRecoveryResumesVerificationReconciliationOrRollback(t *testing.T)
func TestMetricsHaveNoTenantTargetDigestOrErrorLabels(t *testing.T)
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
go test ./internal/actionrollback/... ./internal/actionreceipt/... ./internal/actionrecovery/... ./internal/actionobservability/... -count=1
```

Expected: FAIL because rollback/receipt/recovery/metrics packages do not exist.

- [ ] **Step 3: Implement safe rollback and terminal states**

Automatic `EXACT_SCALE_RESTORE` requires original Plan approval explicitly covered Compensation, original Authorization Bundle unexpired, current Phase 6 handoff/READ baseline/admission and Action platform successor exactly match, `UNAUTHORIZED_WRITE_SURFACE_ABSENT=PASS`, rollback-stage policy ALLOW, all Kill Switches allow rollback, exact Deployment UID, observed replicas equal failed expected value, no HPA, and no intervening resourceVersion/generation/actor. It creates a new rollback Attempt、lease、single credential and one exact scale mutation to original replicas, then independently verifies.

All other cases create `HUMAN_REQUIRED` with stable reason and target lock. Human may stop containment or create a new ActionPlan; “retry original” is not an action.

Terminal public outcomes: `VERIFIED_SUCCESS`、`VERIFIED_NO_CHANGE`、`VERIFIED_ROLLED_BACK`、`FAILED_NOT_APPLIED`、`FAILED_VERIFICATION`、`HUMAN_REQUIRED`. Only first four release target lock automatically, and all require terminal credential cleanup.

- [ ] **Step 4: Build and sign complete Receipt chain**

Receipt binds Scope、Incident、Phase 6 handoff、READ baseline/admission、Action platform successor/manifest、Plan/Definition/Gate、all policy decisions、reauth/approval set、Action/Attempt/fence、Runner certificate/Realm、credential grant/revocation、fixed mutation-step ledger digest、mutation receipt、verification checks、reconciliation、rollback、terminal status、previous audit chain hash and timestamps. Canonical JCS digest is Ed25519 signed. `MarshalJSON` exposes safe IDs/digests/statuses only.

Recovery worker claims expired work with fencing and resumes only non-side-effect stages: credential cleanup、verification、fact reconciliation、eligible rollback workflow and receipt signing. It never repeats mutation send.

Metrics:

```text
aiops_governed_action_total{action_type,outcome}
aiops_governed_action_duration_seconds{action_type}
aiops_action_verification_total{action_type,outcome}
aiops_action_reconciliation_total{action_type,outcome}
aiops_action_rollback_total{action_type,outcome}
aiops_action_human_escalation_total{action_type,reason_code}
aiops_write_credential_cleanup_total{action_type,outcome}
```

- [ ] **Step 5: Run recovery, race and integration tests**

Run:

```bash
go test ./internal/actionrollback/... ./internal/actionreceipt/... ./internal/actionrecovery/... ./internal/actionobservability/... ./internal/execution/postgres -count=1
go test -race ./internal/actionrollback/... ./internal/actionrecovery/... -count=1
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/actionrollback/postgres ./internal/actionreceipt/postgres -run 'Rollback|Receipt|Immutable|Scope' -count=1
```

Expected: all PASS；only safe scale rollback executes；restart recovery never repeats original mutation；Receipt chain and metrics are safe.

- [ ] **Step 6: Commit**

```bash
git add internal/actionrollback internal/actionreceipt internal/actionrecovery internal/actionobservability internal/execution/postgres
git commit -m "feat: reconcile and prove governed action outcomes"
```
