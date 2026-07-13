# Incident and Audit Workspace Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 交付生产可用的 Incident、Investigation、Evidence 与 Audit 浏览闭环，使值班人员能从事件进入调查、核对可信证据与无执行权的 ActionProposal，并沿不可篡改审计链追溯到后续 ActionPlan 和最终执行结果。

**Architecture:** PostgreSQL read model 是唯一事实源；OpenAPI 暴露低敏、Scope 强绑定的查询契约，浏览器只消费 generated types。Incident 页是后续 Governed Action 页的上游工作台；Audit 页独立展示 actor、decision、resource、digest 与链完整性，不提供原始凭据、Provider 响应或任意查询入口。

**Tech Stack:** Go 1.26.5、chi v5、PostgreSQL 18.4、OpenAPI 3.1、React 19.2.7、TypeScript 7.0.2、Vite 8.1.4、TanStack Router/Query/Table、Radix UI、Lucide、CSS Modules、Vitest、MSW、Playwright、axe。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- API path 始终包含 Workspace/Environment；服务层再次校验 Principal、Scope 与行级资源归属，403/404 不泄露存在性。
- Incident Detail 只返回安全摘要、引用与 digest；Evidence 内容按数据分类裁剪，永不返回 target URL、tenant route、query、credential、raw error/body 或 Provider 原始响应。
- Audit 是 append-only 事实浏览器；前端不能更改、补写、删除或“修复”审计记录。
- 所有分页、筛选、排序和选中项由 URL search 持久化；Scope 仍由 Phase 1 `ScopeProvider` 管理，不进入 SPA path。
- 前端路由固定为 `/incidents`、`/incidents/$incidentId`、`/audit`；不得创建第二套路由树。
- Incident 详情必须区分 Trigger、Investigation、Evidence、Proposal、Governance、Execution、Verification、Receipt；未知状态显示“已停止并升级人工处理”，不显示自动重试。
- 复用 Phase 1 tokens：220 px navigation、46 px scope bar、38–40 px desktop rows、4–6 px radius、1 px border；触屏断点交互目标至少 44 px。
- 页面无聊天框、机器人头像、渐变、发光、玻璃、卡片瀑布、任意 JSON 编辑器或终端；状态使用图标、文字和结构共同表达。
- 新增行为严格 TDD；每个 Task 独立提交。

---

### Task 1: Publish the scoped Incident, Investigation, Evidence, and Audit API

**Files:**
- Modify: `internal/authz/authorizer.go`
- Modify: `internal/authz/authorizer_test.go`
- Modify: `api/openapi/control-plane-v1.yaml`
- Modify: `api/openapi/control_plane_v1_test.go`
- Create: `internal/httpapi/incidents.go`
- Create: `internal/httpapi/incidents_test.go`
- Create: `internal/httpapi/audit_records.go`
- Create: `internal/httpapi/audit_records_test.go`
- Modify: `internal/httpapi/router.go`
- Modify: `internal/httpapi/router_test.go`
- Modify: `cmd/control-plane/main.go`
- Modify: `cmd/control-plane/main_test.go`

**Interfaces:**
- Consumes: Phase 4 Incident/Investigation/Grant/Kill Switch records；Phase 5 Evidence/Receipt；Phase 6 audit-chain verification。
- Produces: safe Incident list/detail, Evidence projection, Phase 4 ActionProposal references, Audit timeline, chain-integrity summary and stable operation IDs。

Public paths:

```text
GET /api/v1/workspaces/{workspace_id}/environments/{environment_id}/incidents
GET /api/v1/workspaces/{workspace_id}/environments/{environment_id}/incidents/{incident_id}
GET /api/v1/workspaces/{workspace_id}/environments/{environment_id}/incidents/{incident_id}/investigations
GET /api/v1/workspaces/{workspace_id}/environments/{environment_id}/investigations/{investigation_id}/evidence
GET /api/v1/workspaces/{workspace_id}/environments/{environment_id}/audit-records
GET /api/v1/workspaces/{workspace_id}/environments/{environment_id}/audit-records/{audit_id}
GET /api/v1/workspaces/{workspace_id}/environments/{environment_id}/audit-chain-status
```

- [ ] **Step 1: Write failing authorization, contract, projection, and pagination tests**

```go
func TestIncidentDetailBindsPrincipalAndExactScope(t *testing.T)
func TestIncidentDetailProjectsInvestigationEvidenceAndActionProposalClosure(t *testing.T)
func TestIncidentEvidenceRedactsTargetsQueriesCredentialsAndRawProviderData(t *testing.T)
func TestIncidentListUsesStableCursorAndAllowlistedSorts(t *testing.T)
func TestAuditListFiltersOnlyAllowlistedLowSensitivityFields(t *testing.T)
func TestAuditDetailRecomputesAndReportsChainIntegrity(t *testing.T)
func TestIncidentAndAuditOperationIDsAreUniqueAndRouted(t *testing.T)
```

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/authz ./internal/httpapi ./api/openapi ./cmd/control-plane -run 'Incident|Investigation|EvidenceProjection|AuditChain' -count=1
```

Expected: FAIL because public Incident/Audit handlers and schemas do not exist.

- [ ] **Step 3: Add permissions, exact query grammar, and safe DTOs**

Add `INCIDENT_READ`、`INVESTIGATION_READ`、`EVIDENCE_READ`、`AUDIT_READ`. `EVIDENCE_READ` does not imply unrestricted payload access；classification policy still projects fields.

```go
type IncidentQuery struct {
    Status        []string
    Severity      []string
    ServiceID     string
    TriggerType   string
    ActionState   string
    UpdatedAfter  time.Time
    Sort          string
    Cursor        string
    Limit         int
}

type IncidentDetailDTO struct {
    Incident       IncidentSummaryDTO       `json:"incident"`
    Trigger        TriggerSummaryDTO        `json:"trigger"`
    Investigations []InvestigationSummaryDTO `json:"investigations"`
    Evidence       []EvidenceReferenceDTO    `json:"evidence"`
    Proposals      []ActionProposalDTO       `json:"action_proposals"`
    ExecutionRefs []ExecutionReferenceDTO   `json:"execution_references"`
    EffectiveActions []string               `json:"effective_actions"`
}

type AuditRecordDTO struct {
    ID           string    `json:"id"`
    OccurredAt   time.Time `json:"occurred_at"`
    ActorType    string    `json:"actor_type"`
    ActorRef     string    `json:"actor_ref"`
    Action       string    `json:"action"`
    ResourceType string    `json:"resource_type"`
    ResourceID   string    `json:"resource_id"`
    Outcome      string    `json:"outcome"`
    RecordDigest string    `json:"record_digest"`
    PreviousDigest string  `json:"previous_digest"`
    TraceID      string    `json:"trace_id"`
}
```

Allowlist sort: `updated_at_desc|updated_at_asc|severity_desc`; audit filters: time range、actor type、action、resource type/ID、outcome、trace ID and cursor only. Limit is `1..100`, default 50. Incident detail uses one repeatable-read transaction and returns a `snapshot_at` watermark so mixed revisions cannot appear as one closure.

- [ ] **Step 4: Implement handlers and defensive response contract**

Require strict UUID/path parsing, normalized duplicate query handling and a server maximum 31-day audit window. Return `Cache-Control: no-store`, ETag, trace ID and RFC 9457 problem details. Evidence projection exposes schema ID、content digest、classification、collected time、check summary and a separately authorized safe preview; it never serializes artifact storage location.

Audit detail independently recomputes JCS record digest and previous-link continuity. `audit-chain-status` returns `VERIFIED|BROKEN|INCONCLUSIVE`, checked range and first safe failing record ID；`BROKEN`/`INCONCLUSIVE` closes production action admission through the existing kill-switch/readiness path.

- [ ] **Step 5: Run complete API gates**

```bash
go test ./internal/authz ./internal/httpapi ./api/openapi ./cmd/control-plane -count=1
go test -race ./internal/httpapi -run 'Incident|Audit' -count=1
go vet ./internal/authz ./internal/httpapi ./cmd/control-plane
```

Expected: PASS；cross-Scope、unsafe Evidence、unbounded audit query and broken chain all fail closed.

- [ ] **Step 6: Commit**

```bash
git add internal/authz internal/httpapi api/openapi/control-plane-v1.yaml api/openapi/control_plane_v1_test.go cmd/control-plane
git commit -m "feat: expose safe incident and audit read models"
```

### Task 2: Generate the browser contract and typed Incident/Audit data layer

**Files:**
- Modify (generated): `web/src/shared/api/schema.d.ts`
- Create: `web/src/features/incidents/api.ts`
- Create: `web/src/features/incidents/model.ts`
- Create: `web/src/features/incidents/api.test.ts`
- Create: `web/src/features/audit/api.ts`
- Create: `web/src/features/audit/model.ts`
- Create: `web/src/features/audit/api.test.ts`
- Create: `web/src/test/msw/fixtures/incidents.ts`
- Create: `web/src/test/msw/fixtures/audit.ts`
- Create: `web/src/test/msw/handlers/incidents.ts`
- Create: `web/src/test/msw/handlers/audit.ts`
- Modify: `web/src/test/msw/handlers.ts`

**Interfaces:**
- Consumes: Task 1 OpenAPI operation IDs and Phase 1 `controlPlaneClient`。
- Produces: Scope-aware query keys, URL-search codecs, typed pages/details and deterministic test fixtures。

- [ ] **Step 1: Write failing generated-type, URL-state, and forbidden-field tests**

```ts
it("round-trips incident and audit filters through canonical URL search")
it("includes workspace and environment in every query key")
it("keeps previous page only inside the same immutable scope")
it("rejects fixtures containing target query credential or raw response keys")
it("maps BROKEN and INCONCLUSIVE audit chain states to action-admission warnings")
```

- [ ] **Step 2: Generate types and verify tests fail for missing data modules**

```bash
pnpm --dir web generate:api
pnpm --dir web test -- src/features/incidents src/features/audit
```

Expected: generation succeeds；tests FAIL because typed modules are absent.

- [ ] **Step 3: Implement exact query keys and URL codecs**

```ts
export const incidentKeys = {
  all: (scope: Scope) => ["incidents", scope.workspaceId, scope.environmentId] as const,
  list: (scope: Scope, query: IncidentSearch) => [...incidentKeys.all(scope), "list", query] as const,
  detail: (scope: Scope, id: string) => [...incidentKeys.all(scope), "detail", id] as const,
};

export const auditKeys = {
  all: (scope: Scope) => ["audit", scope.workspaceId, scope.environmentId] as const,
  list: (scope: Scope, query: AuditSearch) => [...auditKeys.all(scope), "list", query] as const,
  chain: (scope: Scope) => [...auditKeys.all(scope), "chain"] as const,
};
```

Zod search schemas strip nothing silently: unknown keys fail in tests and are canonicalized away only through explicit navigation. Default list sort is `updated_at_desc`; audit default window is last 24 hours and absolute timestamps render alongside relative labels. All requests use generated operations and AbortSignal；no handwritten response DTO duplicates OpenAPI.

- [ ] **Step 4: Add deterministic MSW fixtures and run data gates**

Fixtures cover event-triggered read investigation、scheduled pre-approved inspection、no-proposal case、proposal-awaiting-governance、verified Action receipt、UNKNOWN/HUMAN_REQUIRED、audit VERIFIED/BROKEN/INCONCLUSIVE. Handlers assert Scope and allowlisted query fields；unexpected requests fail.

```bash
pnpm --dir web generate:api:check
pnpm --dir web typecheck
pnpm --dir web lint
pnpm --dir web test -- src/features/incidents src/features/audit
```

Expected: all PASS and generated schema is reproducible.

- [ ] **Step 5: Commit**

```bash
git add web/src/shared/api/schema.d.ts web/src/features/incidents web/src/features/audit web/src/test/msw
git commit -m "feat: add typed incident and audit clients"
```

### Task 3: Build the evidence-first Incident workspace

**Files:**
- Create: `web/src/features/incidents/routes/incidentsRoute.tsx`
- Create: `web/src/features/incidents/routes/incidentDetailRoute.tsx`
- Create: `web/src/features/incidents/IncidentListPage.tsx`
- Create: `web/src/features/incidents/IncidentDetailPage.tsx`
- Create: `web/src/features/incidents/IncidentTable.tsx`
- Create: `web/src/features/incidents/IncidentHeader.tsx`
- Create: `web/src/features/incidents/InvestigationRail.tsx`
- Create: `web/src/features/incidents/EvidenceLedger.tsx`
- Create: `web/src/features/incidents/ActionProposalPanel.tsx`
- Create: `web/src/features/incidents/ClosedLoopTimeline.tsx`
- Create: `web/src/features/incidents/incidents.module.css`
- Create: `web/src/features/incidents/IncidentListPage.test.tsx`
- Create: `web/src/features/incidents/IncidentDetailPage.test.tsx`
- Modify: `web/src/app/router.tsx`
- Modify: `web/src/app/navigation.ts`
- Create: `docs/design/frontend/incident-workspace.md`

**Interfaces:**
- Consumes: Task 2 typed data；server `effective_actions`；Phase 1 AppShell/Scope/tokens。
- Produces: `/incidents` and `/incidents/$incidentId` routes, plus the stable detail route extended by the next package with governed Action controls。

- [ ] **Step 1: Write failing page, state, responsive, and accessibility tests**

```tsx
it("restores scoped incident filters cursor selection and scroll from the URL")
it("shows trigger investigation evidence proposal execution verification and receipt separately")
it("never implies a proposal is approved or executable")
it("shows uncertain results as stopped and human-required without mutation retry")
it("uses only server effective_actions for links and controls")
it("supports keyboard evidence inspection and focus return")
it("keeps inspection usable while production mutations remain desktop-only")
it("contains no chat terminal AI-avatar gradient glow or arbitrary JSON editor")
```

- [ ] **Step 2: Run tests and verify failure**

```bash
pnpm --dir web test -- src/features/incidents/IncidentListPage.test.tsx src/features/incidents/IncidentDetailPage.test.tsx
```

Expected: FAIL because routes and pages are absent.

- [ ] **Step 3: Implement the locked information and visual hierarchy**

At desktop, list page uses a 40 px row table with columns Severity、Incident、Service/Asset、Trigger、Investigation、Action state、Owner、Updated；toolbar height 40 px, filters in one horizontal band, saved view and cursor count aligned right. The first column and state column remain visible at 1024–1439 px；below 1024 px rows become compact two-line records, never decorative cards.

Detail uses a 12-column grid: main evidence column spans 8, right governance rail spans 4；page gutter 24 px, panel gap 12 px, panel padding 16 px. Fixed order is Header/Scope/staleness → Trigger facts → Investigation plan and bounded READ tasks → Evidence ledger/citations → root-cause assessment → non-authoritative ActionProposal candidates → separately human-requested governed ActionPlan/governance/execution references → verification/receipt. The rail may become a full-width section below 1024 px.

Severity uses icon + label + narrow left marker；status colors are restricted to approved semantic tokens. Evidence rows show schema、classification、collected time、source Asset identity、digest and safe preview disclosure. Digest copy requires an explicit button and announces success through a polite live region. ActionProposal panel shows exact proposed Action type、Asset binding、narrow typed intent、risk hint and Proposal/Catalog/Evidence/Snapshot digests with `PROPOSAL_ONLY`；it has no PlanHash, approval, queue, credential or execution affordance. Its primary control is “查看建议证据”. A separate “发起受治理计划” control appears only from server `effective_actions`, requires an authenticated human and full T/W/E/S route, and enters the same-transaction trusted Handoff flow；never label either control “立即修复”.

- [ ] **Step 4: Implement persistent failure and reload behavior**

Loading preserves table/detail geometry with `aria-busy`. 403/404、stale Snapshot、revoked Grant、Kill Switch、audit gap、Evidence redaction and partial investigation each have persistent inline states with stable code and trace ID. Browser Back restores list filters/scroll；deep links refetch by Scope and Incident ID. UNKNOWN text is exact: “动作结果不确定，系统已停止后续写入并升级人工处理；不会自动重试。”

- [ ] **Step 5: Run component and production build gates**

```bash
pnpm --dir web typecheck
pnpm --dir web lint
pnpm --dir web test -- src/features/incidents
pnpm --dir web build
test -f docs/design/frontend/incident-workspace.md
```

Expected: all PASS；routes load on refresh, URL state survives navigation and no forbidden UI metaphor appears.

- [ ] **Step 6: Commit**

```bash
git add web/src/features/incidents web/src/app/router.tsx web/src/app/navigation.ts docs/design/frontend/incident-workspace.md
git commit -m "feat: build incident investigation workspace"
```

### Task 4: Build the immutable Audit explorer and browser acceptance

**Files:**
- Create: `web/src/features/audit/routes/auditRoute.tsx`
- Create: `web/src/features/audit/AuditExplorerPage.tsx`
- Create: `web/src/features/audit/AuditFilterBar.tsx`
- Create: `web/src/features/audit/AuditRecordTable.tsx`
- Create: `web/src/features/audit/AuditRecordDrawer.tsx`
- Create: `web/src/features/audit/ChainIntegrityBanner.tsx`
- Create: `web/src/features/audit/audit.module.css`
- Create: `web/src/features/audit/AuditExplorerPage.test.tsx`
- Create: `web/e2e/incident-audit.spec.ts`
- Modify: `web/src/app/router.tsx`
- Modify: `web/src/app/navigation.ts`
- Create: `docs/design/frontend/audit-explorer.md`

**Interfaces:**
- Consumes: Task 2 audit client and Incident deep links。
- Produces: `/audit`, resource/trace drill-through, integrity blocking state and persisted UI acceptance evidence。

- [ ] **Step 1: Write failing Audit explorer and end-to-end tests**

```tsx
it("filters by time actor action resource outcome and trace without free-form query")
it("renders record and previous digests with verified chain order")
it("opens incident plan execution verification and receipt resources in scope")
it("blocks action-admission affordances when chain is broken or inconclusive")
it("keeps raw payload credential target and provider response absent")
it("meets axe keyboard focus reduced-motion and 200-percent zoom checks")
```

- [ ] **Step 2: Run tests and verify failure**

```bash
pnpm --dir web test -- src/features/audit/AuditExplorerPage.test.tsx
pnpm --dir web exec playwright test e2e/incident-audit.spec.ts
```

Expected: FAIL because Audit UI and browser journey are absent.

- [ ] **Step 3: Implement dense audit presentation and safe drill-down**

The page starts with a full-width chain banner, then one 40 px filter bar and a 38 px row table: Time、Actor、Action、Resource、Outcome、Trace、Digest. Record drawer is 440–480 px on wide screens and a full route-height sheet below 1024 px；it shows canonical safe fields、previous/current digest、chain position and related resource links. No raw payload tab, free-form search language, export-all shortcut or mutation control exists.

VERIFIED uses calm green text/icon；BROKEN uses persistent red banner with first failing safe ID and “生产写入已关闭”；INCONCLUSIVE uses amber with “状态不确定，已停止并升级人工处理”. Color is never the sole signal. Tables support keyboard row action, visible focus, `aria-sort`, named pagination and 200% zoom without horizontal loss of Time/Action/Outcome.

- [ ] **Step 4: Register routes/navigation and run full browser acceptance**

Register flat routes in the central router and domain navigation entries “Operations / Incidents” and “Governance / Audit”. Playwright uses real Keycloak and scoped API fixture service from Phase 1 E2E；MSW is not loaded. Journey: alert Incident → bounded investigation → evidence → proposal → stable governed-plan link contract → audit resource trace. Test wrong Scope, forbidden fields, refresh, browser Back, keyboard-only and axe.

```bash
pnpm --dir web generate:api:check
pnpm --dir web typecheck
pnpm --dir web lint
pnpm --dir web test -- src/features/incidents src/features/audit
pnpm --dir web exec playwright test e2e/incident-audit.spec.ts
pnpm --dir web build
git diff --check
```

Expected: all PASS；Incident/Audit pages are reload-safe, accessible, low-sensitivity and connected to the later ActionPlan workspace through a stable route contract.

- [ ] **Step 5: Commit**

```bash
git add web/src/features/audit web/src/app/router.tsx web/src/app/navigation.ts web/e2e/incident-audit.spec.ts docs/design/frontend/audit-explorer.md
git commit -m "feat: add immutable audit explorer"
```

## Pack Completion Gate

```bash
go test -race ./internal/authz ./internal/httpapi ./api/openapi ./cmd/control-plane -count=1
go vet ./internal/authz ./internal/httpapi ./cmd/control-plane
pnpm --dir web generate:api:check
pnpm --dir web typecheck
pnpm --dir web lint
pnpm --dir web test -- src/features/incidents src/features/audit
pnpm --dir web exec playwright test e2e/incident-audit.spec.ts
pnpm --dir web build
git diff --check
```

Expected: all commands exit 0；值班人员可从 Incident 追踪到可信 Evidence/Proposal/Audit，任何 Scope、数据分类或链完整性异常都关闭危险操作并进入人工升级。
