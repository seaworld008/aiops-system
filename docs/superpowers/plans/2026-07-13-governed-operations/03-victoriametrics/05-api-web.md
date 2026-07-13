# VictoriaMetrics Ecosystem API and Web Experience Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 VictoriaMetrics 生态资产、拓扑、版本兼容、只读能力与连接发布状态安全地呈现在现有 API 和 Web 信息架构中，并提供生产级响应式、可访问交互。

**Architecture:** 后端从统一 Asset/Connection/Compatibility/Runtime 仓储组装一个显式 allowlist projection，OpenAPI 是浏览器唯一契约。前端复用 `/assets`、`/assets/$assetId`、`/connections`、`/connections/new`、`/capabilities`；`/connections/new` 只创建 server `DRAFT` 并 replace 到 canonical ID/revision route。generated TypeScript、TanStack Query 与 URL 状态构建生态保存视图；Topology、Compatibility、Capability Matrix 共享同一版本化 read model，不请求私有 Target artifact。

**Tech Stack:** Go 1.26.5、OpenAPI 3.1、现有 `internal/httpapi`/authn/authz、Node >=24 <25、pnpm 10.34.0、React 19.2.7、Vite 8.1.4、TypeScript 7.0.2、TanStack Router 1.170.17、TanStack Query 5.101.2、TanStack Table 8.21.3、React Hook Form 7.81.0、Zod 4.4.3、Radix UI 1.6.2、lucide-react 1.24.0、Vitest 4.1.10、Testing Library 16.3.2、MSW 2.15.0、Playwright、axe-core。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- 不新增含糊的 `/vm` 路由或 “VM” 标签；界面必须明确区分“虚拟机”和“VictoriaMetrics 生态”。
- 公共 API 只返回 allowlist DTO；不得 serialize 数据库 model、Kubernetes document、private Target 或 Connection Contract。
- 禁止字段和内容包括 `account_id`、`project_id`、tenant path/header、endpoint path、Secret name/data、username/password/token/bearer、credential locator、query/LogsQL、raw tags/logs/processes。
- Opaque Credential Reference 只显示 stable ID、revision、issuer kind、status、digest；UI 不提供“查看值”或复制 Secret 的交互。
- Config CRD、tool、insert/storage/agent/anomaly 的界面必须明确显示“资产可见，不具备调查能力”，不得出现误导的运行按钮。
- 未知版本显示 `UNSUPPORTED` 原因、发现版本和下一步；不得隐藏资产、猜测兼容或允许绕过。
- Tenant route 只显示 mode 和 contract/profile digest；向导没有 AccountID、ProjectID、path/header 自由输入。
- 所有 mutation 保持 Phase 2 Idempotency-Key、If-Match、Operation polling、no-store 与 same-origin 安全约束。
- 前端所有数据类型来自 generated OpenAPI；不得手写重复 DTO、使用 `any`、非空断言掩盖缺失字段或把 API fixture 当生产数据。
- 视觉状态同时使用文字、图标与形状，不只依赖颜色；键盘、屏幕阅读器、reduced motion、WCAG 2.2 AA 都纳入测试。
- 1440px、1024px、390px 必须有明确布局；loading、empty、partial、stale、unsupported、forbidden、error、ready 全部有设计。
- 新增行为严格 TDD，每个 Task 独立提交。

---

## Persistent Interface Design

### Visual language

在已有 neutral token 上增加语义 token，不覆盖品牌全局主题：

```css
:root {
  --victoria-metrics-fg: #9f2842;
  --victoria-metrics-bg: #fff0f3;
  --victoria-logs-fg: #6048b5;
  --victoria-logs-bg: #f3f0ff;
  --victoria-traces-fg: #176b57;
  --victoria-traces-bg: #eaf8f3;
  --victoria-control-fg: #475569;
  --victoria-control-bg: #f1f5f9;
  --victoria-query-ready-fg: #0f6b4f;
  --victoria-query-ready-bg: #e7f8f0;
  --victoria-closed-fg: #9a3412;
  --victoria-closed-bg: #fff7ed;
  --victoria-unsupported-fg: #854d0e;
  --victoria-unsupported-bg: #fefce8;
}
```

Family iconography: Metrics=`Activity`、Logs=`Rows3`、Traces=`Route`、Control=`ShieldCheck`。Role shape: Single=圆角方形、Cluster=双层容器、Select=向外箭头、Insert=向内箭头并带“写入端”文字、Storage=圆柱、Config=文档、Tool=扳手。颜色永远与完整标签并用。

### Asset list hierarchy

顶部保留现有页面标题与主操作；其下是保存视图 tab：“全部资产 / 服务 / 虚拟机 / VictoriaMetrics 生态”。生态 tab 的 filter bar 顺序固定为 Family、Topology、Taxonomy Class、Query Eligibility、Compatibility、Environment；筛选写入 URL，可分享和浏览器回退。结果表列为 Name、Family、Type、Topology/Role、Version、Compatibility、Query Capability、Health、Updated；桌面 sticky header，移动端改为 cards。

### Asset detail hierarchy

1. Breadcrumb 与标题：完整产品名、Kind badge、lifecycle、mapping freshness。
2. Summary strip：Family、Topology/Role、Product version、Operator version、Compatibility、Query eligibility。
3. Tabs：`概览`、`拓扑`、`版本兼容`、`连接与能力`、`安全边界`、`关系`。
4. `概览`：身份与来源、ready/desired、发现 revision、最后成功时间；不显示 raw namespace/UID。
5. `拓扑`：root→select/insert/storage→Kubernetes workload/service；query nodes 使用实线绿色边，asset-only 使用灰线，ingestion 使用橙色封闭标记。
6. `版本兼容`：当前 closure 与 profile digest，按 Target/Connector/Evidence/Executor 四行显示 exact match；unsupported 显示固定原因。
7. `连接与能力`：连接 revision、validation、runtime publication 与 18 行 capability matrix；只展示该 family 的六行，其他 family 不混入。
8. `安全边界`：Tenant mode、opaque credential summary、realm/network policy digest、blocked endpoint families；永不显示值。

拓扑节点选择打开同页右侧 inspector；URL 写入 `?node=<public-node-id>`，刷新可恢复。键盘用箭头在 node list 移动、Enter 选择、Escape 关闭 inspector。提供与图等价的“列表视图”且是屏幕阅读器默认内容。

### Responsive behavior

- 1440px：12-column grid，主内容 8 列、inspector 4 列；Topology 最低 520px 高。
- 1024px：Summary 3×2，主内容 7 列、inspector 5 列；Capability Matrix 水平可滚动但首列 sticky。
- 390px：单列，Summary 2 列，tabs 水平滚动并有当前 tab 文本；Topology 默认分层 accordion，table 变 card；底部 action bar 不遮挡内容。
- `prefers-reduced-motion` 下取消 topology transition、drawer slide 和 skeleton shimmer。

### Interaction states

- Loading：与最终布局等高的 skeleton，700ms 后才显示，避免短闪烁。
- Empty：解释未发现资产、最近 source run 状态和“查看发现源”链接；无营销插图。
- Partial discovery：amber inline notice，保留上次完整 snapshot，不显示“0 个资产”。
- Unsupported：版本 card 显示 `VICTORIAMETRICS_VERSION_UNSUPPORTED` 与 profile review 指引，发布按钮禁用。
- Closed role：能力 matrix 显示原因，如“写入组件不开放调查”，不显示 disabled action button。
- Error：页内 Error Summary 聚焦，显示 trace ID 与重试；不渲染后端 detail 原文。
- Stale/Quarantined：顶部 blocking banner，所有发布/调查入口移除并提供回资产映射链接。

### Connection wizard delta

六步保持 Phase 2 顺序：Scope/Provider → Endpoint/Trust → Credential Reference → Capabilities/Realm → Validation → Review/Publish。Victoria provider 选择 Asset 后，服务端返回 eligible target roles 与 route mode；UI 只读展示。Capabilities step 只列六个 family 能力，definition query 只显示 digest/描述，不显示表达式。Review 按 Asset、Connection、Private route mode、Compatibility closure、Capabilities、Runtime profile 六段呈现。

### Task 1: Extend OpenAPI with safe Victoria projections

**Files:**
- Modify: `api/openapi/control-plane-v1.yaml`
- Modify: `api/openapi/control_plane_v1_test.go`
- Modify (generated): `web/src/shared/api/schema.d.ts`

**Interfaces:**
- Consumes: existing scoped Asset/Connection/Capability/Runtime endpoints.
- Produces: additive query filters and allowlist Victoria schemas in the same stable endpoint set.
- Safety: forbidden field-name and example-value tests scan the complete OpenAPI and generated client.

- [ ] **Step 1: Write failing OpenAPI safety and operation tests**

```go
func TestVictoriaAssetProjectionIsCompleteAndSafe(t *testing.T)
func TestVictoriaTopologyProjectionUsesOnlyPublicNodeIDs(t *testing.T)
func TestVictoriaConnectionSummaryOmitsTenantAndCredentialMaterial(t *testing.T)
func TestVictoriaCapabilityProjectionContainsExactlyEighteenCodes(t *testing.T)
func TestVictoriaOpenAPIHasStableOperationIDsAndScopedPaths(t *testing.T)
func TestVictoriaOpenAPIExamplesContainNoSecretTenantQueryOrEndpoint(t *testing.T)
```

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./api/openapi -run 'TestVictoria' -count=1
```

Expected: FAIL because schemas and filters are absent.

- [ ] **Step 3: Add exact safe schemas**

Add these components with `additionalProperties: false`:

```yaml
VictoriaAssetProjection:
  type: object
  required: [taxonomy_class, family, role, resource_kind, api_version, product_version, operator_version, compatibility, query_eligibility]
  properties:
    taxonomy_class: {type: string, enum: [LONG_LIVED_RUNTIME, CONFIGURATION_CRD, TOOL_ARTIFACT]}
    family: {type: string, enum: [METRICS, LOGS, TRACES, CONTROL]}
    role: {type: string, enum: [SINGLE, CLUSTER, SELECT, INSERT, STORAGE, PROXY, AGENT, CONFIG, TOOL]}
    resource_kind: {type: string, maxLength: 64}
    api_version: {type: string, maxLength: 96}
    product_version: {type: string, maxLength: 64}
    operator_version: {type: string, maxLength: 64}
    compatibility: {$ref: '#/components/schemas/VictoriaCompatibilitySummary'}
    query_eligibility: {$ref: '#/components/schemas/VictoriaQueryEligibility'}
VictoriaCompatibilitySummary:
  type: object
  required: [status, reason_code]
  properties:
    status: {type: string, enum: [SUPPORTED, UNSUPPORTED, DRIFTED, REVOKED]}
    reason_code: {type: string, maxLength: 96}
    profile_digest: {type: string, pattern: '^[a-f0-9]{64}$'}
    target_schema_version: {type: string, maxLength: 96}
    connector_schema_version: {type: string, maxLength: 96}
    evidence_schema_version: {type: string, maxLength: 96}
    executor_profile_digest: {type: string, pattern: '^[a-f0-9]{64}$'}
```

Also add `VictoriaTopology{nodes,edges}`, `VictoriaTopologyNode{public_id,kind,family,role,health,version,query_eligibility}`, `VictoriaTopologyEdge{from_public_id,to_public_id,type}`, `VictoriaCapabilitySummary{code,availability,reason_code,budgets,schema_digests}`, `VictoriaSecuritySummary{tenant_route_mode,contract_digest,credential_reference,realm_digest,network_policy_digest,blocked_surfaces}`. No schema contains account/project/path/header/query/secret material.

Extend list assets query with `ecosystem_family`, `ecosystem_topology`, `ecosystem_class`, `query_eligibility`, `compatibility_status`; extend Asset detail response with optional `victoria`; return topology/capabilities/security in the same detail resource under explicit `include=victoria_topology,victoria_capabilities,victoria_security`.

- [ ] **Step 4: Generate and lock the single TypeScript contract**

Use the Phase 1 staging-independent script and the one cross-stage generated path；do not redefine `web/package.json` in this phase:

```json
{
  "scripts": {
    "generate:api": "openapi-typescript ../api/openapi/control-plane-v1.yaml -o src/shared/api/schema.d.ts",
    "generate:api:check": "sh ./scripts/check-generated-api.sh"
  }
}
```

```bash
pnpm --dir web generate:api
pnpm --dir web generate:api:check
```

Expected: generated file is deterministic and check exits 0.

- [ ] **Step 5: Run OpenAPI tests**

```bash
go test ./api/openapi -run 'TestVictoria' -count=1
```

Expected: PASS; exactly 18 capability codes and zero forbidden names/examples.

- [ ] **Step 6: Commit API contract**

```bash
git add api/openapi/control-plane-v1.yaml api/openapi/control_plane_v1_test.go web/src/shared/api/schema.d.ts
git commit -m "feat(api): project Victoria ecosystem safely"
```

### Task 2: Assemble scoped Victoria read models and HTTP handlers

**Files:**
- Create: `internal/httpapi/victoria_projection.go`
- Create: `internal/httpapi/victoria_projection_test.go`
- Modify: `internal/httpapi/assets.go`
- Modify: `internal/httpapi/assets_test.go`
- Modify: `internal/httpapi/connections.go`
- Modify: `internal/httpapi/connections_test.go`
- Modify: `internal/httpapi/capabilities.go`
- Modify: `internal/httpapi/capabilities_test.go`
- Modify: `cmd/control-plane/main.go`
- Modify: `cmd/control-plane/main_test.go`

**Interfaces:**
- Consumes: asset reader/relations, compatibility repository, public Connection Contract summary, capability definitions and runtime publication state.
- Produces: OpenAPI-conformant, authz-filtered Victoria projections and filters.
- Safety: one Scope object is passed to every repository query; projector is field-by-field and forbidden-value scanned.

- [ ] **Step 1: Write failing projection, auth and query-budget tests**

```go
func TestVictoriaProjectionMapsEveryTaxonomyClassAndRole(t *testing.T)
func TestVictoriaProjectionNeverSerializesPrivateContractOrObservationDocument(t *testing.T)
func TestVictoriaAssetFiltersRemainEnvironmentScoped(t *testing.T)
func TestVictoriaTopologyRejectsCrossScopeEdges(t *testing.T)
func TestVictoriaCapabilityReasonsMatchBackendEligibility(t *testing.T)
func TestVictoriaHandlersEnforceReadAuthorizationAndPagination(t *testing.T)
func TestControlPlaneProductionAssemblyIncludesVictoriaReaders(t *testing.T)
```

Fixture canaries include tenant numbers, Secret data, bearer, raw Kubernetes UID/namespace, generated Secret name, endpoint and raw query. Scan successful/error JSON, logs and audit payloads；a normalized Asset display name remains an intentional public field.

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/httpapi ./cmd/control-plane -run 'TestVictoria|TestControlPlaneProductionAssemblyIncludesVictoria' -count=1
```

Expected: FAIL because projector and readers are absent.

- [ ] **Step 3: Implement the allowlist projector**

```go
type VictoriaReadModelReader interface {
    GetProjection(context.Context, assetcatalog.Scope, string, IncludeSet) (VictoriaProjection, error)
    ListCapabilitySummaries(context.Context, assetcatalog.Scope, string) ([]VictoriaCapabilitySummary, error)
}

type VictoriaProjection struct {
    Asset         VictoriaAssetProjection
    Topology      *VictoriaTopology
    Capabilities  []VictoriaCapabilitySummary
    Security      *VictoriaSecuritySummary
}
```

Reader loads each dependency using the same Scope, caps topology at 500 nodes/1000 edges and capability rows at 18, sorts stable IDs/codes and returns `ErrProjectionInconsistent` if an edge/contract/profile crosses Scope or references missing data. Public node IDs are HMAC-derived from Scope+Asset ID using the API projection key, not raw UUID/UID.

- [ ] **Step 4: Extend handlers without new ambiguous routes**

Parse filters through generated enums, cap page size at 100, default includes to summary only, and require existing asset/connection/capability read actions. Detail includes are read-only and no-store. Unsupported assets return 200 with explicit status; forbidden returns generic 404/403 per existing anti-enumeration policy.

- [ ] **Step 5: Run backend and OpenAPI conformance tests**

```bash
go test -race ./internal/httpapi ./cmd/control-plane ./api/openapi -run 'TestVictoria|TestControlPlaneProductionAssemblyIncludesVictoria' -count=1
```

Expected: PASS; canary scan empty and query-count/budget assertions bounded.

- [ ] **Step 6: Commit backend projections**

```bash
git add internal/httpapi/victoria_projection.go internal/httpapi/victoria_projection_test.go internal/httpapi/assets.go internal/httpapi/assets_test.go internal/httpapi/connections.go internal/httpapi/connections_test.go internal/httpapi/capabilities.go internal/httpapi/capabilities_test.go cmd/control-plane/main.go cmd/control-plane/main_test.go
git commit -m "feat(api): serve Victoria ecosystem read models"
```

### Task 3: Build the ecosystem asset list and detail experience

**Files:**
- Create: `docs/design/frontend/victoriametrics-ecosystem.md`
- Create: `web/src/features/assets/api/victoriaAssetApi.ts`
- Create: `web/src/features/assets/api/victoriaAssetApi.test.ts`
- Create: `web/src/features/assets/components/VictoriaAssetBadge.tsx`
- Create: `web/src/features/assets/components/VictoriaEcosystemFilters.tsx`
- Create: `web/src/features/assets/components/VictoriaAssetSummary.tsx`
- Create: `web/src/features/assets/components/VictoriaTopology.tsx`
- Create: `web/src/features/assets/components/VictoriaCompatibilityCard.tsx`
- Create: `web/src/features/assets/components/VictoriaCapabilityMatrix.tsx`
- Create: `web/src/features/assets/components/VictoriaSecurityBoundary.tsx`
- Create: `web/src/features/assets/components/victoria.module.css`
- Create: `web/src/features/assets/components/VictoriaEcosystem.test.tsx`
- Modify: `web/src/features/assets/AssetCatalogPage.tsx`
- Modify: `web/src/features/assets/AssetDetailPage.tsx`
- Modify: `web/src/app/styles/tokens.css`
- Modify: `web/src/test/msw/fixtures.ts`
- Modify: `web/src/test/msw/handlers.ts`

**Interfaces:**
- Consumes: generated Asset detail/list projections and URL search params.
- Produces: accessible ecosystem saved view, detail tabs, topology/list equivalence, closure and security panels.
- Safety: MSW fixtures are allowlist-only and tested for forbidden keys/values; React never receives private contract fields.

- [ ] **Step 1: Persist the exact interaction design**

Write `docs/design/frontend/victoriametrics-ecosystem.md` with all Visual language、Asset list/detail hierarchy、responsive behavior、interaction states and wizard delta sections at the top of this plan, plus component state diagrams, keyboard table and screen acceptance checklist. This file becomes the design source of truth; implementation deviations require an ADR entry.

- [ ] **Step 2: Write failing component/API/accessibility tests**

```tsx
it('names virtual machines and VictoriaMetrics ecosystem distinctly')
it('serializes every ecosystem filter into the URL and restores it')
it('renders query-capable asset and closed insertion component accurately')
it('renders configuration and tool assets without investigation actions')
it('shows unsupported version closure and remediation')
it('keeps topology graph and accessible list selection synchronized')
it('renders opaque credential metadata without reveal or copy controls')
it('contains no serious axe violations at desktop tablet and mobile widths')
it('contains no forbidden keys or canaries in all MSW fixtures')
```

- [ ] **Step 3: Run tests and verify failure**

```bash
pnpm --dir web test -- --run src/features/assets
```

Expected: FAIL because ecosystem components are absent.

- [ ] **Step 4: Implement generated-client data access and URL state**

Extract all response types from generated `operations`/`components`. Query keys include workspace/environment, filters, page cursor and include set. On filter changes reset cursor, update search params with replace for rapid changes and push for saved-view selection. Keep last complete data during background refetch and expose partial-source notice separately.

- [ ] **Step 5: Implement components to the persisted design**

Use semantic table/list/tab/button/dialog primitives, CSS grid and the tokens above. Topology renders SVG only as `aria-hidden`; the equivalent hierarchical list owns focus and selection. Capability rows expand via buttons with `aria-expanded`; blocked roles show reason text instead of a disabled execution control. Digest displays first 12 chars with a labeled copy button for the full nonsecret digest.

- [ ] **Step 6: Run component, type and style checks**

```bash
pnpm --dir web test -- --run src/features/assets
pnpm --dir web typecheck
pnpm --dir web lint
```

Expected: PASS at all three viewport fixtures; no axe serious/critical violations and no unhandled MSW request.

- [ ] **Step 7: Commit asset experience**

```bash
git add docs/design/frontend/victoriametrics-ecosystem.md web/src/features/assets web/src/app/styles/tokens.css web/src/test/msw/fixtures.ts web/src/test/msw/handlers.ts
git commit -m "feat(web): design Victoria ecosystem assets"
```

### Task 4: Extend connection wizard and capability operations UX

**Files:**
- Modify: `web/src/features/connections/wizard/connectionWizardSchema.ts`
- Modify: `web/src/features/connections/wizard/ConnectionPublicationWizard.tsx`
- Modify: `web/src/features/connections/wizard/steps/ScopeProviderStep.tsx`
- Modify: `web/src/features/connections/wizard/steps/EndpointTrustStep.tsx`
- Modify: `web/src/features/connections/wizard/steps/CredentialReferenceStep.tsx`
- Modify: `web/src/features/connections/wizard/steps/CapabilitiesRealmStep.tsx`
- Modify: `web/src/features/connections/wizard/steps/ValidationStep.tsx`
- Modify: `web/src/features/connections/wizard/steps/ReviewPublishStep.tsx`
- Modify: `web/src/features/connections/wizard/ConnectionPublicationWizard.test.tsx`
- Modify: `web/src/features/connections/components/ConnectionDetailPanel.tsx`
- Modify: `web/src/features/connections/components/RuntimePublicationCard.tsx`
- Create: `web/src/features/capabilities/components/VictoriaCapabilityCatalog.tsx`
- Create: `web/src/features/capabilities/components/VictoriaCapabilityCatalog.test.tsx`
- Modify: `web/src/test/msw/fixtures.ts`
- Modify: `web/src/test/msw/handlers.ts`

**Interfaces:**
- Consumes: eligible targets, public contract summary, six family capabilities, validation Operation and runtime publication projection.
- Produces: server-guided Victoria connection publication and exact capability/runtime status UI.
- Safety: schema has no tenant/path/header/query fields; stale/unsupported/closed assets cannot submit validation or publication.

- [ ] **Step 1: Write failing wizard and capability tests**

```tsx
it('offers VictoriaMetrics VictoriaLogs and VictoriaTraces providers')
it('shows only server-returned eligible target roles')
it('has no tenant path header query or secret-value form control')
it('shows exactly six capabilities for the selected family')
it('blocks validation for unsupported version or nonquery role')
it('shows route mode and version closure without tenant values in review')
it('polls publication operation and distinguishes APPLIED DRIFTED and rollback')
it('renders all eighteen catalog rows with budgets schemas and reason codes')
it('preserves idempotency key across retry and sends exact If-Match')
```

- [ ] **Step 2: Run tests and verify failure**

```bash
pnpm --dir web test -- --run src/features/connections src/features/capabilities
```

Expected: FAIL because providers and catalog behavior are absent.

- [ ] **Step 3: Extend the Zod wizard schema safely**

Provider enum adds `VICTORIAMETRICS|VICTORIALOGS|VICTORIATRACES`. Victoria branch stores only `asset_id`, provider, selected server-returned `target_role`, endpoint/trust reference, opaque credential reference ID/revision, selected capability codes, realm ID and optimistic revision. Use `.strict()` at every step so injected account/project/path/header/query keys fail parse.

- [ ] **Step 4: Implement server-guided steps and review**

Selecting Asset refetches eligible target roles and compatibility. Unsupported/config/tool/insert/storage assets show reason and a link back to asset detail. Endpoint remains origin-only HTTPS; route mode is read-only. Capability definitions show human description, action class `READ`, duration/items/bytes and schema digest. Review shows the six closure sections defined above and requires acknowledgement “仅开放列出的只读查询能力”.

- [ ] **Step 5: Implement capability catalog and runtime status**

Catalog groups Metrics/Logs/Traces with six rows each, keeps full product names, supports availability/reason filters and expands a row for budgets/schema/profile. Runtime card visualizes PENDING→APPLYING→APPLIED, DRIFTED and ROLLED_BACK with timestamps and operation link; never exposes artifact content.

- [ ] **Step 6: Run frontend gate**

```bash
pnpm --dir web generate:api:check
pnpm --dir web test -- --run src/features/connections src/features/capabilities src/features/assets
pnpm --dir web typecheck
pnpm --dir web lint
pnpm --dir web build
```

Expected: all commands exit 0; no forbidden form field or fixture material, and generated client is clean.

- [ ] **Step 7: Commit wizard and catalog**

```bash
git add web/src/features/connections web/src/features/capabilities web/src/test/msw/fixtures.ts web/src/test/msw/handlers.ts
git commit -m "feat(web): publish Victoria read connections"
```

## Pack Completion Gate

```bash
go test -race ./api/openapi ./internal/httpapi ./cmd/control-plane -run 'TestVictoria|TestControlPlaneProductionAssemblyIncludesVictoria' -count=1
pnpm --dir web generate:api:check
pnpm --dir web test -- --run
pnpm --dir web typecheck
pnpm --dir web lint
pnpm --dir web build
git diff --check
```

Expected: all commands exit 0; API 和 UI 只有安全投影，18 个能力/全部 taxonomy 状态可理解，三个 viewport 可用且无严重 accessibility 问题。
