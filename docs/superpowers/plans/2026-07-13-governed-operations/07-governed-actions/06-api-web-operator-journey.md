# Governed Action API and Operator Journey Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 发布低敏、可恢复的 Governed Action Control Plane API，并交付 evidence-first 的高保真企业操作台，完整呈现计划、审批、二次认证、执行、验证、回滚或人工升级。

**Architecture:** OpenAPI 3.1 是浏览器唯一契约；HTTP 只调用前四包的应用服务并返回 `effective_actions`。ActionPlan 创建端点接受最小 `SealIntent` 和独立 Idempotency-Key header；Service 在一个 serializable PostgreSQL transaction 内通过 Phase 4 `HandoffLoader` 重载 Proposal/Catalog/Evidence/Snapshot、解析其余可信事实并 `CreateInTx` 封存。React 使用 TanStack Router URL 状态、Query server state、generated types 和 Operation polling；复杂安全状态以结构化面板/时间线呈现，不使用聊天、终端或任意 JSON 编辑器。

**Tech Stack:** Go 1.26.5、chi v5、OIDC、OpenAPI 3.1、React 19.2.7、TypeScript 5.9.3、Vite 8.1.4、TanStack Router/Query/Table、React Hook Form、Zod、Radix UI、Lucide、CSS Variables/Modules、MSW 2.15.0、Vitest 4.1.10。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- Public API never exposes Runner lease/token、credential/issuer accessor、internal endpoint、raw Policy facts/CEL input、raw provider response、certificate body or sensitive Evidence。
- Every path contains Workspace/Environment and every service call reauthorizes current OIDC Principal；ActionPlan create additionally requires `/services/{service_id}` so Tenant/Workspace/Environment/Service authority comes only from identity plus path. 403/404 do not disclose existence。
- Every mutation uses 16–128-byte Idempotency-Key；stateful mutation uses If-Match/ETag；POST body strict JSON and ≤32 KiB unless exact schema sets lower。
- Recent auth is server-confirmed through package 02 challenge/proof; browser cannot claim that reauth occurred。
- ActionPlan POST body only accepts `proposal_id`、`expected_proposal_digest`、`expected_intent_digest`、`action_type`、typed `parameters` and `change_reason`；the Idempotency-Key remains a header and request hash is computed server-side. Principal、Scope、Evidence closure、Target、Runtime、window、verification、compensation、`idempotency_key` and `request_hash` are forbidden body fields；unknown fields fail closed。
- The handler passes verified Principal、canonical URL Scope、minimal `SealIntent` and header Idempotency-Key to package 01 only；it cannot preload or cache Proposal/Catalog/Evidence/Snapshot. Package 01 must use Phase 4 `HandoffLoader`、remaining-facts resolver and `CreateInTx` in the same serializable transaction；any drift returns no Plan/binding/idempotency success。
- UI action visibility/enabled state uses server `effective_actions` only, never role-name inference。
- Production execute/approve/rollback is desktop-only at ≥768px per approved product specification；smaller viewports can inspect、stop where safe and escalate human with explicit desktop-required explanation。
- UI distinctly displays Plan、Policy、Approval、Execution、Credential cleanup、Verification、Reconciliation、Rollback and Receipt states；no merged “overall green”。
- Copy uses “ActionPlan”“受治理动作”“WRITE Runner”“验证”“人工升级”；never “AI 已登录”“Agent 自主修复” or terminal/chat metaphors。
- MSW is test/dev-only and absent from production bundle；real OIDC/API is covered in Package 6。
- Existing visual tokens in `web/src/app/styles/tokens.css` remain authoritative；no second design system。

---

### Task 1: Publish safe OpenAPI, authorization, and HTTP handlers

**Files:**
- Modify: `internal/authz/authorizer.go`
- Modify: `internal/authz/authorizer_test.go`
- Modify: `api/openapi/control-plane-v1.yaml`
- Modify: `api/openapi/control_plane_v1_test.go`
- Create: `internal/httpapi/action_definitions.go`
- Create: `internal/httpapi/action_definitions_test.go`
- Create: `internal/httpapi/action_plans.go`
- Create: `internal/httpapi/action_plans_test.go`
- Create: `internal/httpapi/action_approvals.go`
- Create: `internal/httpapi/action_approvals_test.go`
- Create: `internal/httpapi/action_executions.go`
- Create: `internal/httpapi/action_executions_test.go`
- Create: `internal/httpapi/action_receipts.go`
- Create: `internal/httpapi/action_receipts_test.go`
- Create: `internal/httpapi/action_gates.go`
- Create: `internal/httpapi/action_gates_test.go`
- Modify: `internal/httpapi/router.go`
- Modify: `internal/httpapi/router_test.go`
- Modify: `cmd/control-plane/main.go`
- Modify: `cmd/control-plane/main_test.go`

**Interfaces:**
- Consumes: package 01 `Service.SealProposal(ctx, principal, investigationgrant.Scope, intent, idempotencyKey)` backed by exact Phase 4 `HandoffLoader.LoadTrustedForActionPlanDerivation(ctx, pgx.Tx, HandoffRequest)` and the package 01 serializable Seal UnitOfWork；package 02 Reauth/Approval/Authorization Bundle；packages 03–04 execution/read models。
- Produces: browser-safe generated contract with stable operation IDs；closed seal body and out-of-band Idempotency-Key mapping，不产生 Principal/Scope/request hash 客户端字段。

Public paths:

```text
GET  /api/v1/workspaces/{workspace_id}/environments/{environment_id}/action-definitions
GET  /api/v1/workspaces/{workspace_id}/environments/{environment_id}/action-plans
POST /api/v1/workspaces/{workspace_id}/environments/{environment_id}/services/{service_id}/action-plans
GET  /api/v1/workspaces/{workspace_id}/environments/{environment_id}/action-plans/{plan_id}
POST /api/v1/workspaces/{workspace_id}/environments/{environment_id}/action-plans/{plan_id}:reauthenticate
POST /api/v1/workspaces/{workspace_id}/environments/{environment_id}/action-plans/{plan_id}:approve
POST /api/v1/workspaces/{workspace_id}/environments/{environment_id}/action-plans/{plan_id}:reject
POST /api/v1/workspaces/{workspace_id}/environments/{environment_id}/action-plans/{plan_id}:revoke-approval
POST /api/v1/workspaces/{workspace_id}/environments/{environment_id}/action-plans/{plan_id}:execute
GET  /api/v1/workspaces/{workspace_id}/environments/{environment_id}/action-executions/{execution_id}
POST /api/v1/workspaces/{workspace_id}/environments/{environment_id}/action-executions/{execution_id}:reauthenticate-rollback
POST /api/v1/workspaces/{workspace_id}/environments/{environment_id}/action-executions/{execution_id}:authorize-rollback
POST /api/v1/workspaces/{workspace_id}/environments/{environment_id}/action-executions/{execution_id}:escalate
GET  /api/v1/workspaces/{workspace_id}/environments/{environment_id}/action-executions/{execution_id}/receipt
GET  /api/v1/workspaces/{workspace_id}/environments/{environment_id}/action-gates
GET  /api/v1/workspaces/{workspace_id}/environments/{environment_id}/action-gates/{action_type}/drills
```

OpenAPI/router contract tests assert the create operation exists only at the service-qualified POST path above. The prior T/W/E-only `POST .../environments/{environment_id}/action-plans` is absent and returns safe 404 without invoking `GovernedActionManager`；list/detail and later Plan-ID mutations retain their existing paths because the sealed Plan already carries immutable Service binding.

- [ ] **Step 1: Write failing authz/OpenAPI/redaction tests**

```go
func TestActionPlanReadReturnsSafeExactClosureAndEffectiveActions(t *testing.T)
func TestActionPlanSealPassesAuthenticatedPrincipalFullTWESURLScopeExpectedDigestsAndHeaderKey(t *testing.T)
func TestActionPlanSealRequiresServicePathAndRejectsBodyServiceID(t *testing.T)
func TestActionPlanSealBodyContainsOnlySixHumanConfirmationFields(t *testing.T)
func TestActionPlanSealRejectsCallerSuppliedPrincipalScopeTargetWindowVerificationOrCompensation(t *testing.T)
func TestActionPlanSealRejectsBodyIdempotencyKeyOrRequestHash(t *testing.T)
func TestActionPlanSealRejectsProposalCatalogEvidenceOrIntentDigestDrift(t *testing.T)
func TestActionPlanSealExpectedDigestsAreConditionsNotTrustedFacts(t *testing.T)
func TestApprovalRequiresPermissionRecentAuthAndSeparationOfDuty(t *testing.T)
func TestExecuteRequiresETagIdempotencyAndExecutionReauth(t *testing.T)
func TestRollbackAuthorizationRequiresEligibilityAndRollbackReauth(t *testing.T)
func TestActionResponsesNeverContainCredentialEndpointOrRawProviderData(t *testing.T)
func TestActionOperationIDsAndRoutesAreOneToOne(t *testing.T)
func TestActionManagersCannotFallBackToMemoryDependencies(t *testing.T)
func TestControlPlaneWiresPhase4HandoffLoaderAndSerializableSealUnitOfWork(t *testing.T)
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
go test ./internal/authz ./internal/httpapi ./api/openapi ./cmd/control-plane -run 'Action|Approval|Rollback|Receipt' -count=1
```

Expected: FAIL because permissions, schemas and handlers are absent.

- [ ] **Step 3: Add exact permissions and manager interfaces**

Add `ACTION_READ`、`ACTION_PROPOSE`、`ACTION_APPROVE`、`ACTION_EXECUTE`、`ACTION_ROLLBACK_AUTHORIZE`、`ACTION_ESCALATE`、`ACTION_GATE_READ`. Gate promotion remains Package 6 internal/admin dual-control service, not a general UI mutation here.

```go
type GovernedActionManager interface {
    ListPlans(
        context.Context,
        authn.Principal,
        actionplan.ListRequest,
    ) (actionplan.Page, error)
    GetPlan(
        context.Context,
        authn.Principal,
        assetcatalog.Scope,
        string,
    ) (httpapi.ActionPlanDetail, error)
    SealPlan(
        context.Context,
        authn.Principal,
        investigationgrant.Scope,
        actionplan.SealIntent,
        idempotencyKey string,
    ) (actionplan.Plan, error)
    DecideApproval(
        context.Context,
        authn.Principal,
        actionapproval.DecideCommand,
    ) (actionapproval.ApprovalSet, error)
    RequestExecution(
        context.Context,
        authn.Principal,
        execution.RequestCommand,
    ) (operation.Operation, error)
    GetExecution(
        context.Context,
        authn.Principal,
        assetcatalog.Scope,
        string,
    ) (httpapi.ActionExecutionDetail, error)
    AuthorizeRollback(
        context.Context,
        authn.Principal,
        actionrollback.AuthorizeCommand,
    ) (operation.Operation, error)
    Escalate(
        context.Context,
        authn.Principal,
        actionreconciliation.EscalateCommand,
    ) (operation.Operation, error)
}
```

- [ ] **Step 4: Implement safe DTOs and handler contracts**

The OpenAPI schema is `additionalProperties:false` and maps exactly to:

```go
type sealActionPlanRequest struct {
    ProposalID             string                  `json:"proposal_id"`
    ExpectedProposalDigest string                  `json:"expected_proposal_digest"`
    ExpectedIntentDigest   string                  `json:"expected_intent_digest"`
    ActionType             action.ActionType       `json:"action_type"`
    Parameters             action.ActionParameters `json:"parameters"`
    ChangeReason           string                  `json:"change_reason"`
}
```

All six properties are required；digests are lowercase 64-hex，change reason is trimmed and bounded，the typed parameter union is selected by `action_type`. `DisallowUnknownFields` rejects `tenant_id`、`workspace_id`、`environment_id`、`service_id`、`requester_id`、Target/Snapshot/Runtime、Evidence IDs/digests、authorization window、approval、verification、compensation、credential、`idempotency_key` or `request_hash` fields. The handler derives Tenant from the verified OIDC session，reads Workspace/Environment/Service only from the canonical `/workspaces/{workspace_id}/environments/{environment_id}/services/{service_id}/action-plans` path，reauthorizes that exact T/W/E/S tuple and constructs `investigationgrant.Scope` without consulting Proposal data. It then validates the 16–128-byte Idempotency-Key header, constructs `actionplan.SealIntent` from only the six body fields and calls `SealPlan(ctx, principal, scope, intent, idempotencyKey)`.

The handler never reads Phase 4 tables itself，and no manager adapter may pre-read Proposal merely to obtain ServiceID. Package 01 starts one serializable transaction, constructs `actionproposal.HandoffRequest` directly from the authenticated Principal、full T/W/E/S URL Scope、Proposal ID and expected Proposal digest，then reloads and revalidates Proposal/Catalog/Evidence/Snapshot through the Phase 4 Handoff Loader before resolving all remaining trusted facts and sealing through `CreateInTx`. Loader/Service 分别从数据库可信闭包重算 Proposal/intent digest，并以固定长度恒时比较检查两个 expected digest；`expected_proposal_digest`、`expected_intent_digest`、Action type and typed parameters are concurrency confirmation only, never a trusted replacement. Missing、stale、cross-Scope、non-`PROPOSAL_ONLY`、digest/qualification drift or later fact drift returns a stable fail-closed error and the transaction leaves no Plan/binding/idempotency/Audit success event.

`ActionPlanDetail` includes safe Evidence references/digests、typed target identity、before/after structured diff、PlanHash、Definition/Gate、Policy/Kill Switch summaries、approval subjects/roles/times、reauth required flag and effective actions. It omits full Evidence body when data classification disallows it.

`ActionExecutionDetail` includes Operation/Attempt/fenced phase、Runner safe certificate digest、credential status/expiry/cleanup only、Mutation Receipt digest/outcome、Verification checks、Reconciliation/Rollback status、human escalation and Receipt link. No lease epoch token/accessor/raw response.

All responses use `Cache-Control:no-store`, ETag, `X-Content-Type-Options:nosniff` and trace ID. 202 mutations return durable Operation + Location. 409/412/428/503 preserve stable codes and current ETag; they never echo submitted body.

- [ ] **Step 5: Run HTTP, contract and race tests**

Run:

```bash
go test ./internal/authz ./internal/httpapi ./api/openapi ./cmd/control-plane -count=1
go test -race ./internal/httpapi -count=1
```

Expected: PASS；route/operationId/authz/reauth/ETag/idempotency/redaction all pass；seal body has exactly six fields，header key remains out-of-band，production wiring supplies Phase 4 Handoff Loader plus serializable Seal UnitOfWork，all drift responses expose no partial success.

- [ ] **Step 6: Commit**

```bash
git add internal/authz internal/httpapi api/openapi/control-plane-v1.yaml api/openapi/control_plane_v1_test.go cmd/control-plane
git commit -m "feat: expose governed action control plane API"
```

### Task 2: Generate the typed browser client and safe MSW model

**Files:**
- Modify (generated): `web/src/shared/api/schema.d.ts`
- Create: `web/src/features/governed-actions/api/governedActionApi.ts`
- Create: `web/src/features/governed-actions/api/governedActionApi.test.ts`
- Create: `web/src/features/governed-actions/model/actionKeys.ts`
- Create: `web/src/features/governed-actions/model/useActionOperation.ts`
- Create: `web/src/features/governed-actions/model/useActionOperation.test.tsx`
- Create: `web/src/test/msw/fixtures/governedActions.ts`
- Create: `web/src/test/msw/handlers/governedActions.ts`
- Modify: `web/src/test/msw/handlers.ts`
- Modify: `web/src/test/msw/server.ts`

**Interfaces:**
- Consumes: Task 1 generated operation IDs and existing `controlPlaneClient`。
- Produces: typed Plan/approval/reauth/execution/rollback/escalation queries/mutations and active Operation recovery；Plan seal accepts Idempotency-Key as a required client option separate from the exact six-field generated body。

Keep the Phase 1–2 single generator contract unchanged: `openapi-typescript ../api/openapi/control-plane-v1.yaml -o src/shared/api/schema.d.ts`. Do not add another generated directory or handwritten duplicate DTOs.

- [ ] **Step 1: Write failing generated-client and redaction tests**

```ts
it("loads a plan closure without forbidden material", async () => {
  const detail = await getActionPlan({
    workspaceId,
    environmentId,
    planId,
  });
  expect(detail.plan_hash).toMatch(/^[a-f0-9]{64}$/);
  expect(JSON.stringify(detail).toLowerCase()).not.toMatch(
    /token|password|secret|private_key|vault_path|dsn|endpoint|raw_response/,
  );
});

it("sends only expected digests and human confirmation in the seal body", async () => {
  await sealActionPlan({
    workspaceId,
    environmentId,
    serviceId,
    idempotencyKey: "seal-00000000-0000-4000-8000-000000000001",
    body: {
      proposal_id: proposalId,
      expected_proposal_digest: proposalDigest,
      expected_intent_digest: intentDigest,
      action_type: "K8S_SCALE",
      parameters: { kind: "K8S_SCALE", replicas: 3 },
      change_reason: "恢复已验证的服务容量",
    },
  });
  expect(lastRequest.headers.get("Idempotency-Key")).toBe(
    "seal-00000000-0000-4000-8000-000000000001",
  );
  expect(lastRequest.url.pathname).toBe(
    `/api/v1/workspaces/${workspaceId}/environments/${environmentId}/services/${serviceId}/action-plans`,
  );
  expect(Object.keys(lastJSONBody).sort()).toEqual([
    "action_type",
    "change_reason",
    "expected_intent_digest",
    "expected_proposal_digest",
    "parameters",
    "proposal_id",
  ]);
});

it("sends If-Match and stable Idempotency-Key for execution", async () => {
  const operation = await requestActionExecution({
    workspaceId,
    environmentId,
    planId,
    version: 4,
    reauthProofId,
    idempotencyKey: "execute-00000000-0000-4000-8000-000000000001",
  });
  expect(operation.kind).toBe("ACTION_EXECUTE");
});
```

Also test seal refusal without path `serviceId` or explicit header Idempotency-Key；generated request types contain no Principal、Tenant/Workspace/Environment/Service body Scope、Target、window、verification、compensation、`idempotency_key` or `request_hash` body property；active Operation URL reload、terminal polling stop、412 refetch and no later mutation function without explicit Idempotency-Key/version/proof.

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
pnpm --dir web generate:api
pnpm --dir web test -- src/features/governed-actions/api src/features/governed-actions/model
```

Expected: generated type command succeeds; tests FAIL because client/hooks/fixtures are absent.

- [ ] **Step 3: Implement exact query keys, typed operations and MSW**

Query keys always include Workspace/Environment, then Plan/Execution ID. Mutation bodies are generated `operations[...]` types. `sealActionPlan` requires Workspace/Environment/Service as URL arguments and Idempotency-Key as an explicit transport option，calls only `/workspaces/{workspace_id}/environments/{environment_id}/services/{service_id}/action-plans`，and sends only the six confirmation properties；no browser API accepts body Scope or computes request hash. Reauth start returns same-origin authorization URL + challenge expiry; completion is handled by the existing OIDC callback/session, not a client-supplied claims object.

MSW fixture has one Plan per Action type, LOW/MEDIUM/HIGH approvals, active execution phase progression, verified success, verification failure, reconciliation, safe scale rollback and HUMAN_REQUIRED. All IDs/times/digests are deterministic; fixture keys pass the same forbidden-key scan as production DTOs. The Plan seal handler asserts exact body-key equality、both expected digests and header Idempotency-Key，and rejects body `idempotency_key/request_hash`；other handlers assert ETag、Idempotency-Key、effective action、reauth proof and Scope. Unknown requests error.

`useActionOperation` polls every 1 second for QUEUED/ADMITTING/RUNNING/FINALIZING and every 2 seconds for VERIFYING/RECONCILING/ROLLING_BACK, stops at terminal, invalidates Plan/Execution/Receipt and removes Operation ID from URL only after persistent result renders.

- [ ] **Step 4: Run generated contract and frontend data gates**

Run:

```bash
pnpm --dir web generate:api:check
pnpm --dir web typecheck
pnpm --dir web lint
pnpm --dir web test -- src/features/governed-actions/api src/features/governed-actions/model
```

Expected: all PASS；generated file clean；seal request has exactly six body fields plus header Idempotency-Key and no browser request-hash path；MSW unhandled/unsafe requests fail；terminal polling stops.

- [ ] **Step 5: Commit**

```bash
git add web/src/shared/api/schema.d.ts web/src/features/governed-actions/api web/src/features/governed-actions/model web/src/test/msw
git commit -m "feat: add typed governed action web client"
```

### Task 3: Build the evidence-first governed action operator workspace

**Files:**
- Create: `web/src/features/governed-actions/routes/actionPlansRoute.tsx`
- Create: `web/src/features/governed-actions/routes/actionPlanDetailRoute.tsx`
- Create: `web/src/features/governed-actions/components/ActionPlanListPage.tsx`
- Create: `web/src/features/governed-actions/components/ActionPlanTable.tsx`
- Create: `web/src/features/governed-actions/components/ActionPlanFilters.tsx`
- Create: `web/src/features/governed-actions/components/ActionGateStrip.tsx`
- Create: `web/src/features/governed-actions/components/ActionPlanWorkspace.tsx`
- Create: `web/src/features/governed-actions/components/EvidenceSummary.tsx`
- Create: `web/src/features/governed-actions/components/ExactTargetCard.tsx`
- Create: `web/src/features/governed-actions/components/StructuredDiff.tsx`
- Create: `web/src/features/governed-actions/components/PlanHashCard.tsx`
- Create: `web/src/features/governed-actions/components/PolicyKillSwitchPanel.tsx`
- Create: `web/src/features/governed-actions/components/ApprovalPanel.tsx`
- Create: `web/src/features/governed-actions/components/ReauthDialog.tsx`
- Create: `web/src/features/governed-actions/components/ExecutionTimeline.tsx`
- Create: `web/src/features/governed-actions/components/VerificationPanel.tsx`
- Create: `web/src/features/governed-actions/components/RollbackEscalationPanel.tsx`
- Create: `web/src/features/governed-actions/components/ReceiptPanel.tsx`
- Create: `web/src/features/governed-actions/components/governedActions.module.css`
- Create: `web/src/features/governed-actions/components/ActionPlanListPage.test.tsx`
- Create: `web/src/features/governed-actions/components/ActionPlanWorkspace.test.tsx`
- Modify: `web/src/features/incidents/routes/incidentDetailRoute.tsx`
- Modify: `web/src/app/router.tsx`
- Modify: `web/src/app/navigation.ts`
- Create: `docs/design/frontend/governed-actions.md`

**Interfaces:**
- Consumes: Task 2 data/hooks；server `effective_actions`；existing Incident workspace/AppShell/tokens。
- Produces: flat routes `/action-plans` and `/action-plans/$planId`；Workspace/Environment remain canonical URL search and Phase 1 Scope state；the existing `/incidents/$incidentId` route links to the same Plan detail without creating a nested router tree。

- [ ] **Step 1: Write failing journey, permission, responsive and accessibility tests**

```tsx
it("shows evidence exact target diff and full plan hash before governance controls")
it("persists scoped list filters sorting pagination and selection in the URL")
it("shows four independent type gates without implying inherited readiness")
it("renders policy kill switches approval subjects and expiry independently")
it("saves route before redirecting to real reauthentication")
it("uses only effective_actions for approve execute rollback and escalate")
it("tracks execution credential cleanup verification and receipt after reload")
it("shows stopped-and-human-required without a retry mutation action")
it("offers scale rollback only when server declares exact eligibility")
it("blocks high-risk mutation controls below 768px but preserves inspection")
it("contains no chat composer terminal arbitrary JSON editor or AI actor language")
it("supports keyboard focus return live regions and WCAG names")
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
pnpm --dir web test -- src/features/governed-actions/components/ActionPlanListPage.test.tsx src/features/governed-actions/components/ActionPlanWorkspace.test.tsx
```

Expected: FAIL because workspace components do not exist.

- [ ] **Step 3: Implement the persistent visual/information contract**

At ≥1440 px use 216–224 px domain navigation, 24 px page gutter and two evidence-first columns: left 40% Evidence/root-cause/current facts; right 60% immutable Plan/governance. A 440–480 px right detail drawer is reserved for digest/check/receipt drill-down, not primary approval. At 1024–1439 freeze identity/status, stack secondary panels; at 768–1023 use full detail routes; below 768 show read/stop/escalate only with 44 px targets.

The list route opens from domain navigation “Operations / Governed Actions”. Its first row is a compact four-type Gate strip showing Definition revision、Gate state、positive/verified drill counts and last decision time independently. Below it, a dense table uses columns Plan/Incident、Action type、exact Asset、Environment、risk、approval、execution/verification state、requester and updated time. URL search params own Workspace、Environment、Action type、Gate、risk、approval state、execution state、Incident、sort and cursor；default sort is updated descending. Filters never infer permissions or hide denied rows as success. The central `web/src/app/router.tsx` registers only `/action-plans` and `/action-plans/$planId`; Incident links pass `incident_id` as safe search context.

Use approved colors `#F4F6F8/#FFFFFF/#17212B/#17202A/#52606D/#D7DDE3/#1F5EA8/#287A4B/#9A5B0A/#B42318`, system UI 13–14 px body, 12–13 px tables, 22–24 px title, 4 px spacing grid, 4–6 px radius. No gradients、glow、3D、hero cards、chat bubbles or animated “AI thinking”. Digests/IDs/absolute times use monospace. Status always icon + text + structure.

Page order is fixed:

1. Incident/Scope header and stale/kill/permission banners;
2. Evidence citations and root-cause confidence;
3. exact Asset/Target/Snapshot/Runtime identities;
4. before→after typed diff with unchanged context collapsed;
5. full PlanHash + Definition/Gate/expiry/change reason;
6. Policy decision and six Kill Switch revisions;
7. approval matrix, separation of duty and reauth expiry;
8. explicit execution confirmation naming Action、Asset、Environment and consequence;
9. live structured timeline: queue→admission→credential→mutation→cleanup→verification;
10. reconciliation/rollback/human escalation;
11. signed terminal Receipt and audit chain.

- [ ] **Step 4: Implement exact interactions and failure states**

Approval/execute/rollback buttons appear only in matching `effective_actions`. Clicking starts plan-bound reauth when required, persists return URL/scroll/selected digest safely, then returns to a confirmation dialog; no token enters app state. Double click reuses Idempotency-Key.

Execution timeline is not chat: rows identify HUMAN、CONTROL_PLANE、WRITE_RUNNER、READ_VERIFIER、EXTERNAL_SYSTEM with time、phase、safe digest and audit ID. Credential displays `PREPARED/ACTIVE/REVOCATION_PENDING/REVOKED/MANUAL_REQUIRED` and expiry only.

UNKNOWN prominently says “变更结果不确定，已停止并对账；不会自动重试”. HUMAN_REQUIRED has owner、reason、containment and escalation operation, never a Retry mutation. 412 shows exact safe changed fields and requires rereview. 403/428/503, expired approval, Kill Switch, credential cleanup uncertainty and verification failure use persistent inline states, not only toast.

List/detail loading uses structure-preserving skeletons with `aria-busy`; there is no fake status progression. Empty state names the current filters and offers only “清除筛选” or a server-authorized proposal action. Errors remain inline with stable error code、trace ID and retry-read action. Browser Back restores filters/scroll/selected digest; deep links reload the same Scope and active durable Operation. Destructive confirmation never uses color alone, never prechecks consent and returns focus to the invoking control.

- [ ] **Step 5: Run component, build and design-document checks**

Run:

```bash
pnpm --dir web typecheck
pnpm --dir web lint
pnpm --dir web test -- src/features/governed-actions
pnpm --dir web build
test -f docs/design/frontend/governed-actions.md
```

Expected: all PASS；production bundle has no MSW/chat/terminal；all journeys and mobile governance restriction pass.

- [ ] **Step 6: Commit**

```bash
git add web/src/features/governed-actions web/src/features/incidents/routes/incidentDetailRoute.tsx web/src/app/router.tsx web/src/app/navigation.ts docs/design/frontend/governed-actions.md
git commit -m "feat: add governed action operator workspace"
```
