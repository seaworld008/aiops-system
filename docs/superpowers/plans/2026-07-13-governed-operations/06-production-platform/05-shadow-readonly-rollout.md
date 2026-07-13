# Production Shadow and Read-only Rollout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 用不可跳级、证据驱动的 Preview→非生产 READ_ONLY→生产 SHADOW→受监督生产 READ_ONLY 流程控制生产 admission，交付安全 API 与高保真生产就绪控制台，并只允许三种最终 decision。

**Architecture:** `productionrollout.Manager` 重新解析当前 Platform/Policy/Runtime/Kill Switch closure，调用 Phase 4 Preview/TriggerStarter 与 Phase 6 gate collector，且把每个阶段的 proof tuple 写入 `000020`。Admission resolver 每次从当前 accepted rollout/decision 与实时 Gate/Kill Switch 导出，不缓存批准。OpenAPI 暴露 allowlist readiness/dependency/Realm/runtime/SLO/rollout projections；React 只用 generated types 和 `effective_actions`，以 stage timeline、gate matrix 和 decision drawer 呈现。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4+、Temporal SDK 1.46.0、Phase 4 Policy/Grant/Gateway、Phase 5 Receipt/Cleanup、OpenAPI 3.1、React 19.2.7、TanStack Router/Query/Table、Zod 4.4.3、CSS Modules、Vitest/MSW（单元）、Playwright/axe（真实环境）。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- Stages are exact and predecessor-bound；cannot skip, reorder, backdate or overwrite accepted evidence.
- Preview does not start Investigation/Task；production SHADOW does not resolve private Target, issue credential, claim Runner or send target request.
- Nonproduction READ_ONLY is limited to environment classification `NONPRODUCTION`; production assets are rejected even if selector includes them.
- Supervised production READ_ONLY requires explicit bounded asset/capability allowlist, supervisor session and current recent authentication；no autonomous broadening.
- Every stage pins Platform/Policy/Snapshot/Grant/Runtime/Kill Switch/Realm closure；runtime updates affect only a new rollout revision.
- Credential cleanup must be `REVOKED|NO_CREDENTIAL`; `PENDING|FAILED|UNCERTAIN` immediately closes new stage admission and gate FAIL/INCONCLUSIVE.
- Evidence tuple records digest/reference only；no Target/credential/query/result/upstream error is public or in Temporal.
- Gate collector, not browser/operator, determines PASS/FAIL/INCONCLUSIVE and sample/soak counts.
- Decisions are only `NO_GO|CONTINUE_SHADOW|APPROVE_PRODUCTION_READ_ONLY`; no free text, emergency bypass, GO or write approval.
- `APPROVE_PRODUCTION_READ_ONLY` requires all 22 current README `ApprovalGateSet` observations PASS. `CONTINUE_SHADOW` uses the documented Shadow continuation subset, and `NO_GO` requires no fabricated PASS evidence；all three still require recent auth <=5m, server `effective_actions` and strong If-Match/Idempotency-Key.
- `APPROVE_PRODUCTION_READ_ONLY` does not enable Action/WRITE；all Phase 7 surfaces remain unavailable.
- Public API never returns internal dependency endpoint、tenant、Target、Realm private policy、identity SAN、Vault refs、credential、query、raw metric/evidence/audit.
- Frontend never infers status/action from role or colors；server returns orthogonal lifecycle/gate/stage/effective actions.
- Browser token memory only, real Keycloak for E2E；production bundle cannot include MSW.
- UI follows light dense enterprise console, no AI/chat/decorative visual language；WCAG 2.2 AA at 1440/1024/390.
- 新增行为严格 TDD，每个 Task 独立 commit。

---

## Required Stage Proof Tuple

```go
type ProofTuple struct {
    PolicyRevisionDigest      string
    AssetSnapshotDigest       string
    GrantDigest               string
    RuntimeBundleDigest       string
    RealmBindingDigest        string
    CredentialCleanupDigest   string
    EvidenceDigest            string
    ReceiptDigest             string
    AuditChainDigest          string
}
```

Preview and SHADOW fields with no execution are not empty: they use domain-separated `NOT_APPLICABLE` digests plus proof that no Task/Credential/Target request existed. This prevents ambiguity between intentional absence and missing evidence.

### Task 1: Implement rollout manager, proof aggregation and admission resolution

**Files:**
- Create: `internal/productionrollout/model.go`
- Create: `internal/productionrollout/model_test.go`
- Create: `internal/productionrollout/manager.go`
- Create: `internal/productionrollout/manager_test.go`
- Create: `internal/productionrollout/proof.go`
- Create: `internal/productionrollout/proof_test.go`
- Create: `internal/productionrollout/admission.go`
- Create: `internal/productionrollout/admission_test.go`
- Create: `internal/productionrollout/postgres/reader.go`
- Create: `internal/productionrollout/postgres/reader_test.go`
- Modify: `internal/productionplatform/postgres/repository.go`
- Modify: `internal/productionplatform/postgres/repository_test.go`

**Interfaces:**
- Consumes: Platform repository/gate collector, Phase 4 policy Preview/TriggerStarter/Run/Grant/Kill Switch, Phase 5 cleanup/Receipt/Evidence/Audit readers.
- Produces: stage commands, immutable proof tuple and current production READ admission decision.
- Safety: manager never receives raw Target/credential/evidence；admission unknown is closed.

- [ ] **Step 1: Write failing transition/proof/admission tests**

```go
func TestManagerRequiresExactAcceptedPredecessorAndCurrentClosure(t *testing.T)
func TestProofTupleRequiresEveryDigestOrExplicitNotApplicableProof(t *testing.T)
func TestPreviewAndShadowProofRequireZeroTaskCredentialTargetSideEffect(t *testing.T)
func TestNonproductionStageRejectsEveryProductionAsset(t *testing.T)
func TestSupervisedStageRequiresBoundedAllowlistSupervisorAndRecentAuth(t *testing.T)
func TestAdmissionRequiresAcceptedCurrentStageAllPassAndOpenKillSwitch(t *testing.T)
func TestDecisionAllowsOnlyNoGoContinueShadowOrApproveReadOnly(t *testing.T)
func TestApprovalNeverChangesActionOrWriteAvailability(t *testing.T)
```

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/productionrollout/... ./internal/productionplatform/postgres -run 'Test(Manager|ProofTuple|PreviewAndShadow|Nonproduction|Supervised|Admission|Decision|ApprovalNever)' -count=1
```

Expected: FAIL because rollout manager/admission are absent.

- [ ] **Step 3: Implement strict commands and proof interface**

```go
type Command string

const (
    CommandStartPreview                  Command = "START_PREVIEW"
    CommandStartNonproductionReadOnly    Command = "START_NONPRODUCTION_READ_ONLY"
    CommandStartProductionShadow         Command = "START_PRODUCTION_SHADOW"
    CommandStartSupervisedReadOnly        Command = "START_SUPERVISED_PRODUCTION_READ_ONLY"
    CommandDecideNoGo                    Command = "DECIDE_NO_GO"
    CommandDecideContinueShadow           Command = "DECIDE_CONTINUE_SHADOW"
    CommandDecideApproveReadOnly          Command = "DECIDE_APPROVE_PRODUCTION_READ_ONLY"
)

type Dependencies interface {
    ResolveClosure(context.Context, assetcatalog.Scope) (Closure, error)
    Preview(context.Context, PreviewRequest) (PreviewProof, error)
    StartReadOnly(context.Context, StartRequest) (RunProof, error)
    StartShadow(context.Context, ShadowRequest) (ShadowProof, error)
    CollectGates(context.Context, RolloutRef) ([]productionplatform.GateEvidence, error)
}
```

No command includes stage string, selector body, Target, credential, runtime choice or gate result from caller. Manager derives stage and predecessor from command/current row.

- [ ] **Step 4: Implement proof aggregation and live admission**

Proof aggregator verifies referenced rows in one Scope, terminal states, digest recomputation and audit chain. `AdmissionResolver.Resolve` re-reads latest accepted stage/decision, platform current revision, the exact README `RuntimeAdmissionGateSet`, six Kill Switch levels and global security/cleanup closure on every new run；cache miss/error/stale dynamic evidence closes with low-sensitivity reason. It never treats decision-only `OIDC_RECENT_AUTH` or immutable Shadow/soak/supervision proof as a per-Runner gate.

- [ ] **Step 5: Run manager tests**

```bash
go test -race ./internal/productionrollout/... ./internal/productionplatform/postgres -count=1
```

Expected: PASS；stage skip/side effect/missing proof/WRITE availability all closed.

- [ ] **Step 6: Commit rollout core**

```bash
git add internal/productionrollout internal/productionplatform/postgres
git commit -m "feat(platform): govern production read rollout"
```

### Task 2: Execute and gate all four stages with real workflows

**Files:**
- Create: `internal/productionrollout/stage_runner.go`
- Create: `internal/productionrollout/stage_runner_test.go`
- Create: `internal/productionrollout/stage_runner_integration_test.go`
- Create: `internal/productionrollout/soak.go`
- Create: `internal/productionrollout/soak_test.go`
- Modify: `internal/proactivepolicy/service.go`
- Modify: `internal/proactivepolicy/service_test.go`
- Modify: `internal/proactiveworkflow/workflow.go`
- Modify: `internal/proactiveworkflow/workflow_test.go`
- Modify: `internal/readgateway/backend.go`
- Modify: `internal/readgateway/backend_test.go`
- Modify: `internal/readgateway/grant_gate.go`
- Modify: `internal/readgateway/backend_grant_test.go`

**Interfaces:**
- Consumes: Manager, Phase 4 real Preview/SHADOW/READ_ONLY workflows and Gateway Admission, Phase 6 SLO/security/recovery gates.
- Produces: timed/sample-counted stage execution and proof/gate rows.
- Safety: production Shadow path is architecture-separated from Investigation/Task/Runner clients.

- [ ] **Step 1: Write failing stage integration tests**

```go
func TestPreviewPersistsExactIncludedExcludedAndNoExecutionProof(t *testing.T)
func TestNonproductionReadOnlyRunsTwentyFourHoursAndAtLeastOneHundredRepresentativeRuns(t *testing.T)
func TestProductionShadowRunsSeventyTwoHoursFiveHundredEvaluationsAndZeroSideEffects(t *testing.T)
func TestSupervisedProductionReadOnlyRunsTwentyFourHoursFiftyObservedRuns(t *testing.T)
func TestEachStageCoversVictoriaHostPostgresAndAllTriggerTypes(t *testing.T)
func TestGateFailureCleanupUncertainOrKillSwitchStopsStageImmediately(t *testing.T)
func TestNewRuntimeRequiresNewRolloutAndNeverRebindsExistingRun(t *testing.T)
```

Time-based tests use controlled DB/Temporal time in unit integration and real elapsed soak evidence in E2E；production decision cannot use accelerated unit timestamps.

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/productionrollout ./internal/proactivepolicy ./internal/proactiveworkflow ./internal/readgateway -run 'Test(PreviewPersists|NonproductionReadOnly|ProductionShadow|SupervisedProduction|EachStage|GateFailure|NewRuntime)' -count=1
```

Expected: FAIL because stage runner/soak rules are absent.

- [ ] **Step 3: Implement exact soak requirements**

```go
type SoakRequirement struct {
    MinimumDuration   time.Duration
    MinimumSamples    int64
    MinimumBusyWindows int
    RequiredFamilies  []string
    RequiredTriggers  []string
    SupervisorRequired bool
}
```

Literal registry: Preview 0/1；Nonproduction 24h/100；Production Shadow 72h/500/3 busy windows；Supervised 24h/50/supervisor. Required families include VICTORIAMETRICS/LOGS/TRACES/HOST/POSTGRES when published；trigger types HUMAN/INCIDENT/SCHEDULE. Disabled family is explicit excluded reason, not silent coverage.

- [ ] **Step 4: Separate SHADOW from executable workflow path**

SHADOW calls Phase 4 `PrepareRun` shadow branch and a `ZeroSideEffectObserver`; it persists Snapshot/Grant-completed/projection/audit but imports no investigation creator, Task repository, credential issuer, private Target reader or Runner client. Architecture test enforces absent imports/calls. READ_ONLY uses normal Grant/Gateway/cleanup path and closes immediately on gate failure.

- [ ] **Step 5: Run stage tests**

```bash
go test -race ./internal/productionrollout ./internal/proactivepolicy ./internal/proactiveworkflow ./internal/readgateway -run 'Test(PreviewPersists|NonproductionReadOnly|ProductionShadow|SupervisedProduction|EachStage|GateFailure|NewRuntime)' -count=1
```

Expected: PASS with exact stage requirements and zero Shadow side effects.

- [ ] **Step 6: Commit stage execution**

```bash
git add internal/productionrollout internal/proactivepolicy internal/proactiveworkflow internal/readgateway
git commit -m "feat(platform): execute staged production read pilot"
```

### Task 3: Expose safe readiness, dependency, Realm, SLO, rollout and decision APIs

**Files:**
- Modify: `api/openapi/control-plane-v1.yaml`
- Modify: `api/openapi/control_plane_v1_test.go`
- Modify (generated): `web/src/shared/api/schema.d.ts`
- Create: `internal/httpapi/platform_readiness.go`
- Create: `internal/httpapi/platform_readiness_test.go`
- Create: `internal/httpapi/platform_rollouts.go`
- Create: `internal/httpapi/platform_rollouts_test.go`
- Create: `internal/authz/platform_permissions.go`
- Create: `internal/authz/platform_permissions_test.go`
- Modify: `cmd/control-plane/main.go`
- Modify: `cmd/control-plane/main_test.go`

**Interfaces:**
- Consumes: public safe projections from assembly/observability/platform/rollout/Realm/runtime/backup repositories.
- Produces: scoped OpenAPI operations and server-computed `effective_actions`.
- Safety: public schemas are allowlist/additionalProperties false and forbidden-field scanned.

- [ ] **Step 1: Write failing OpenAPI/auth/HTTP tests**

```go
func TestPlatformOpenAPIHasOnlyScopedSafePathsAndStableOperationIDs(t *testing.T)
func TestPlatformPublicSchemasContainNoEndpointCredentialIdentityOrRawEvidence(t *testing.T)
func TestPlatformPermissionsAreExplicitAndEffectiveActionsStateAware(t *testing.T)
func TestPlatformDecisionRequiresRecentAuthIdempotencyAndIfMatch(t *testing.T)
func TestPlatformDecisionRequestIsClosedThreeValueUnion(t *testing.T)
func TestPlatformCrossScopeReadsAndMutationsAreIndistinguishableFromUnknown(t *testing.T)
func TestControlPlaneProductionAssemblyIncludesRealPlatformManagers(t *testing.T)
```

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./api/openapi ./internal/authz ./internal/httpapi ./cmd/control-plane -run 'TestPlatform|TestControlPlaneProductionAssemblyIncludesRealPlatformManagers' -count=1
```

Expected: FAIL because platform APIs/managers are absent.

- [ ] **Step 3: Add exact paths and projections**

Under `/api/v1/workspaces/{workspace_id}/environments/{environment_id}` add GET `/platform/readiness`, `/platform/dependencies`, `/platform/realms`, `/platform/runtime`, `/platform/slo`, `/production-rollouts`, `/production-rollouts/{rollout_id}`；POST `/production-rollouts/{rollout_id}/commands` and `/production-rollouts/{rollout_id}/decisions`. DTOs expose enum status, safe name/code, revision/digest, counts/times/objective/burn, stage/gates/proof presence and `effective_actions` only.

Permissions are `PLATFORM_READ`, `PLATFORM_OPERATE_NONPRODUCTION`, `PLATFORM_OPERATE_SHADOW`, `PLATFORM_OPERATE_SUPERVISED_READ`, `PLATFORM_DECIDE_READINESS`. Decision requires last permission plus recent auth.

- [ ] **Step 4: Implement strict managers/handlers**

Handlers parse generated closed enums, UUID Scope path, 16–128 byte Idempotency-Key and strong If-Match. They call Manager only；cannot write gate/evidence/status directly. Responses use no-store and RFC 9457 stable codes. `effective_actions` lists only commands legal for current state/authz/auth-time.

- [ ] **Step 5: Generate and verify contract**

```bash
pnpm --dir web generate:api
pnpm --dir web generate:api:check
go test -race ./api/openapi ./internal/authz ./internal/httpapi ./cmd/control-plane -run 'TestPlatform|TestControlPlaneProductionAssemblyIncludesRealPlatformManagers' -count=1
```

Expected: PASS；generated `schema.d.ts` clean and forbidden projection scan empty.

- [ ] **Step 6: Commit API**

```bash
git add api/openapi/control-plane-v1.yaml api/openapi/control_plane_v1_test.go web/src/shared/api/schema.d.ts internal/httpapi/platform_readiness.go internal/httpapi/platform_readiness_test.go internal/httpapi/platform_rollouts.go internal/httpapi/platform_rollouts_test.go internal/authz/platform_permissions.go internal/authz/platform_permissions_test.go cmd/control-plane
git commit -m "feat(api): expose production read readiness"
```

### Task 4: Persist and build the enterprise production-readiness console

**Files:**
- Create: `docs/design/frontend/production-read-platform.md`
- Create: `web/src/features/platform/api/platformApi.ts`
- Create: `web/src/features/platform/api/platformApi.test.ts`
- Create: `web/src/features/platform/routes/platformRoutes.tsx`
- Create: `web/src/features/platform/components/PlatformSafetyBanner.tsx`
- Create: `web/src/features/platform/components/ReadinessOverview.tsx`
- Create: `web/src/features/platform/components/DependencyMatrix.tsx`
- Create: `web/src/features/platform/components/RealmCapacityTable.tsx`
- Create: `web/src/features/platform/components/RuntimeClosurePanel.tsx`
- Create: `web/src/features/platform/components/SLOBudgetPanel.tsx`
- Create: `web/src/features/platform/components/RolloutTimeline.tsx`
- Create: `web/src/features/platform/components/GateEvidenceTable.tsx`
- Create: `web/src/features/platform/components/ReadinessDecisionDrawer.tsx`
- Create: `web/src/features/platform/components/platform.module.css`
- Create: `web/src/features/platform/components/PlatformConsole.test.tsx`
- Modify: `web/src/app/router.tsx`
- Modify: `web/src/app/navigation.ts`
- Modify: `web/src/app/styles/tokens.css`
- Modify: `web/src/test/msw/fixtures.ts`
- Modify: `web/src/test/msw/handlers.ts`

**Interfaces:**
- Consumes: generated platform operations/types and server `effective_actions`.
- Produces: six canonical TanStack routes `/platform/readiness`、`/platform/dependencies`、`/platform/realms`、`/platform/runtime`、`/platform/slo`、`/platform/rollouts/$rolloutId`, stage/decision workflow, responsive/accessibility states and persistent design source.
- Safety: no handwritten DTO/role inference/raw evidence/secret；decision controls absent unless action returned.

- [ ] **Step 1: Persist exact design before components**

Design doc fixes: navy `#14233b` navigation；content `#f6f8fb`；cards white/1px `#d8dee8`/6px radius；primary `#2457a6`；PASS `#176b4d`、FAIL `#a4372a`、INCONCLUSIVE `#8a5a12` always with icon/text. Top safety bar always states “生产写：关闭”. No gradient/glow/chat/AI persona.

1440px uses 12 columns: readiness 8 + safety/dependency 4；1024px stacks 7+5 then full width；390px one column with stage accordion and sticky safe action footer. Loading skeleton keeps layout；dependency unknown, stale SLO, cleanup uncertain, Kill Switch closed, gate failure, forbidden and recent-auth required are distinct states. Keyboard order follows heading→scope→stage→gates→decision；44px controls, visible 2px focus, reduced motion.

- [ ] **Step 2: Write failing data/component/accessibility tests**

```tsx
it('keeps production write closed on every platform route')
it('renders dependencies realms runtime SLO and rollout from generated types')
it('shows stage predecessor gate evidence and proof presence without raw evidence')
it('uses only effective_actions and never infers from role names')
it('offers exactly three final decisions in their legal states')
it('requires recent authentication and typed confirmation for a decision')
it('restores scope filters selected rollout and panel from URL')
it('renders unknown failure and inconclusive as distinct non-color states')
it('contains no serious axe violation at 1440 1024 and 390 widths')
it('contains no forbidden keys or canaries in MSW fixtures')
```

- [ ] **Step 3: Run tests and verify failure**

```bash
pnpm --dir web test -- --run src/features/platform
```

Expected: FAIL because platform console is absent.

- [ ] **Step 4: Implement generated API/query/URL layer**

All types derive from `schema.d.ts`; query keys include Scope, route, rollout, filters and revision. Poll dependency/SLO during active rollout with server Retry-After, stop on terminal. Preserve last complete projection while showing stale/partial indicator. Mutations keep stable Idempotency-Key across retry and exact ETag.

- [ ] **Step 5: Implement routes/components/decision UX**

Readiness overview uses compact stage strip and a 22-gate table grouped as Platform/Security/Reliability/Recovery/Rollout；dependency matrix groups Data/Workflow/Identity/Security/Execution；Realm table shows family/capacity/cert/policy status；SLO shows 30d objective/budget/burn in accessible SVG+table；rollout timeline links immutable digests. Decision drawer shows evidence checklist, current platform revision, consequence text and typed confirmation；no `APPROVE_WRITE` control/string.

- [ ] **Step 6: Run frontend gate**

```bash
pnpm --dir web generate:api:check
pnpm --dir web test -- --run src/features/platform
pnpm --dir web typecheck
pnpm --dir web lint
pnpm --dir web build
```

Expected: all commands exit 0；three viewports and accessibility pass, production bundle contains no MSW.

- [ ] **Step 7: Commit platform UI/design**

```bash
git add docs/design/frontend/production-read-platform.md web/src/features/platform web/src/app/router.tsx web/src/app/navigation.ts web/src/app/styles/tokens.css web/src/test/msw/fixtures.ts web/src/test/msw/handlers.ts
git commit -m "feat(web): build production read readiness console"
```

## Pack Completion Gate

```bash
go test -race ./internal/productionrollout/... ./internal/productionplatform/... ./internal/proactivepolicy ./internal/proactiveworkflow ./internal/readgateway ./api/openapi ./internal/httpapi ./internal/authz -count=1
pnpm --dir web generate:api:check
pnpm --dir web test -- --run src/features/platform
pnpm --dir web check
git diff --check
```

Expected: all commands exit 0；stages cannot skip, Shadow has zero side effects, decisions closed to three values, API/UI safe and WRITE remains closed.
