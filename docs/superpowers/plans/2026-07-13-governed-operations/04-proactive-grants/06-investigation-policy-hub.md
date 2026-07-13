# Investigation Workspace and Policy Hub Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 交付跨 Incident 的 `/investigations` 安全查询工作区和 `/governance/policies` Policy Hub，以真实 Keycloak、URL Scope、服务端 `effective_actions`、低 AI 感高保真界面及三断点 E2E 支撑生产运维。

**Architecture:** PostgreSQL read model 在 Tenant/Workspace/Environment 复合 Scope 内聚合 Investigation、Incident、Grant、Evidence 与 ActionProposal 的安全投影，并把主动策略、Kill Switch、ActionProposal Catalog 与 READ Admission 映射为可扩展 Policy Hub 条目；公共 API 仅提供 Cursor 分页只读查询。React 通过 TanStack Router/Query/Table 把 Scope、筛选、排序、分页、选中对象和 Tab 写入 URL，真实 OIDC Authorization Code + PKCE 决定会话，按钮只消费响应中的 `effective_actions`。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4+、pgx/v5、go-chi/v5、OpenAPI 3.1、RFC 9457；Node >=24 <25、pnpm 10.34.0、React 19.2.7、Vite 8.1.4、TypeScript 7.0.2、TanStack Router 1.170.17、Query 5.101.2、Table 8.21.3、Zod 4.4.3、Radix UI 1.6.2、lucide-react 1.24.0、CSS Modules、Keycloak Server 26.6.3、keycloak-js 26.2.4、Vitest 4.1.10、Testing Library 16.3.2、MSW 2.15.0、Playwright 1.61.1、@axe-core/playwright 4.12.1。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- 实现基线固定为 main@ad50d9f；开始执行时先创建独立 worktree，且该模块根下不能包含嵌套 .worktrees。
- 公共 API 唯一源为 `api/openapi/control-plane-v1.yaml`；前端唯一生成类型为 `web/src/shared/api/schema.d.ts`，不得手写重复 DTO。
- 真实登录固定为 Keycloak Server 26.6.3 与浏览器 keycloak-js 26.2.4，使用 Authorization Code + PKCE、`login-required`、内存 Token、请求前刷新；不得使用 localStorage/sessionStorage/cookie 保存 bearer token。
- Workspace/Environment 是每个 API 与页面的显式 Scope；跨 Scope 对象返回安全 403/404，不泄露存在性。
- 权限和按钮只使用 API `effective_actions`；前端不得从角色名、JWT claim 文本或资源状态自行推导授权。
- `/investigations` 是跨 Incident 只读查询入口，不创建、重跑、修改或删除 Investigation；主动运行仍走已治理的 `/proactive-policies` 与 `/proactive-runs` 流程。
- ActionProposal 恒为 `PROPOSAL_ONLY`；调查页面不得提供直接/自动转换、批准、排队、凭据或执行 ActionProposal 的控件，Phase 4 也不提供创建 ActionPlan 的 API。
- 页面可展示 Phase 7 Handoff 所需的安全来源摘要，但未来的“派生并封存 ActionPlan”只能由经认证的人明确发起；Phase 7 服务端必须开启封存事务，并在同一事务调用 Handoff Loader 锁定、重载可信 ActionProposal/Catalog/Evidence/Snapshot、复验摘要、派生并封存，不能信任浏览器回传内容。
- Policy Hub 是治理读模型，不复制策略事实或发明统一“总绿灯”；每一条展示来源类型、Scope、修订、摘要、模式、状态、Owner、证据时间和独立阻塞原因。
- Phase 4 的 Policy Hub 只聚合 Proactive Policy、Investigation Grant、六级 Kill Switch、ActionProposal Catalog 和 READ Admission；Phase 7/8 通过版本化 API 扩展 Action/Release 条目，不重写本阶段语义。
- 公开 DTO、页面、日志、Trace、错误和审计不得包含 Secret、Token、PEM、完整 DSN、Vault URL/Path、内部 endpoint、原始模型/上游响应、任意 SQL 或完整查询结果。
- 所有列表使用不透明 Cursor、稳定排序和明确 limit；时间窗、筛选、排序、分页、Tab、selected ID 均写入 URL。
- 前端使用浅色高密度运维控制台：220px 深海军蓝导航、46px Scope Bar、38–40px 桌面行、4–6px radius、克制蓝色操作色、1px 边界和白色表面。
- 禁止聊天框、AI 头像、机器人、霓虹、发光、渐变、玻璃拟态、Bento 卡片、漂浮球和无意义动效；Actor 使用结构化类型文字，不使用聊天气泡。
- 一块区域只有一个主操作；治理结果在操作附近持久显示，不用 Toast 代替关键状态。
- WCAG 2.2 AA：正文对比度至少 4.5:1、可见焦点、完整键盘路径、持久 Label、图标按钮可访问名称、状态不只靠颜色、Reduced Motion、触控目标至少 44×44px。
- 1440px、1024px、390px 三断点必须分别验收；窄屏进入独立详情路由，不把桌面侧栏压缩成不可读面板。
- fake/MSW 只能用于组件合同测试；真实 Keycloak/Scope/深链接/权限 E2E 必须访问生产装配的 Control Plane 和 PostgreSQL。

---

## Package Position

- 顺序：6 / 7；必须按 README.md 固定顺序执行。
- 前置：`04-evidence-action-proposal.md` 和 `05-web-experience.md` 已完成，OpenAPI/生成类型、ActionProposal API/Handoff Loader、App Shell、真实 OIDC 与主动策略组件均可用。
- 交付给下一包：跨 Incident Investigation API/页面、Policy Hub API/页面、ActionProposal Handoff 安全来源投影、真实 Keycloak 三断点/axe/权限 E2E 和持久化前端设计基线；不交付 Phase 4 ActionPlan mutation。

## Design Direction

- Product fit：面向 Incident Commander、SRE、平台治理人员的生产运维控制台，不是面向终端用户的 AI 助手。
- Density：桌面 operations-dense，信息以表格、摘要条、时间线和明细定义列表呈现；移动端按任务优先级分层。
- Visual language：深海军蓝固定导航、浅灰工作区、白色主表面、克制蓝色交互、绿色/琥珀/红色仅承载语义状态；无装饰性插画和大面积色块。
- Primary jobs：跨事件检索调查、核对 Evidence/Grant/ActionProposal；比较治理策略修订、定位阻塞门和进入已有治理操作。
- Risk areas：Scope 混淆、把 ActionProposal 误认为可执行或已批准计划、权限推断、状态合并、隐藏漂移、移动端误触治理动作。

### Task 14: 跨 Incident Investigation 与 Policy Hub 安全查询 API

**Files:**
- Create: internal/investigationview/types.go
- Create: internal/investigationview/types_test.go
- Create: internal/investigationview/postgres/repository.go
- Create: internal/investigationview/postgres/repository_test.go
- Create: internal/investigationview/postgres/repository_integration_test.go
- Create: internal/governanceview/types.go
- Create: internal/governanceview/types_test.go
- Create: internal/governanceview/postgres/repository.go
- Create: internal/governanceview/postgres/repository_test.go
- Create: internal/governanceview/postgres/repository_integration_test.go
- Create: internal/httpapi/investigation_views.go
- Create: internal/httpapi/investigation_views_test.go
- Create: internal/httpapi/policy_hub.go
- Create: internal/httpapi/policy_hub_test.go
- Modify: internal/httpapi/router.go
- Modify: internal/httpapi/router_test.go
- Modify: internal/authz/authorizer.go
- Modify: internal/authz/authorizer_test.go
- Modify: api/openapi/control-plane-v1.yaml
- Create: api/openapi/control-plane-v1-investigation-policy-hub_test.go
- Modify: web/src/shared/api/schema.d.ts
- Modify: cmd/control-plane/main.go
- Modify: cmd/control-plane/main_test.go

**Interfaces:**
- Consumes: Investigation/Incident/Evidence 现有 PostgreSQL 事实、Phase 4 Run/Grant/Policy/Kill Switch、Task 10 ActionProposal Reader、现有 authn/authz/Scope/Cursor/RFC 9457 约定。
- Produces: `investigationview.Reader.List/Get/EvidenceSummary`；`governanceview.Reader.List/Get`；`INVESTIGATION_READ`、`GOVERNANCE_POLICY_READ`；四条 Investigation 与两条 Policy Hub GET API。

- [ ] **Step 1: 写安全投影、排序和 Scope 失败测试**

Investigation 列表每行只返回稳定 ID、Incident 安全摘要、状态、触发类型、Service、Grant 状态、Evidence/ActionProposal 计数、开始/结束时间、failure_code 和 effective_actions。详情返回 Evidence metadata、Snapshot/Grant digest、ActionProposal safe projection、Handoff 来源摘要和审计引用，不返回模型原文、query_summary JSON、raw_ref、endpoint 或 credential。

~~~go
func TestInvestigationSummaryContainsOnlyOperationalSafeFields(t *testing.T) {
    summary := validInvestigationSummary(t)
    raw, err := json.Marshal(summary)
    if err != nil { t.Fatal(err) }
    assertJSONKeysExactly(t, raw,
        "id", "incident", "status", "trigger_type", "service", "grant_status",
        "evidence_count", "proposal_count", "started_at", "completed_at",
        "failure_code", "effective_actions")
    assertNotContains(t, raw, "secret-canary", "raw_ref", "query_summary", "prompt", "endpoint")
}

func TestInvestigationListUsesStableCrossIncidentOrder(t *testing.T) {
    page := listInvestigations(t, ListRequest{
        Scope: scopeA, Sort: SortStartedDesc, Limit: 50,
    })
    assertStableOrder(t, page.Items, "started_at DESC, id DESC")
    assertEveryItemScope(t, page.Items, scopeA)
}
~~~

Policy Hub 条目固定 discriminator：

~~~go
type PolicyKind string
const (
    PolicyProactiveInvestigation PolicyKind = "PROACTIVE_INVESTIGATION"
    PolicyInvestigationGrant PolicyKind = "INVESTIGATION_GRANT"
    PolicyKillSwitch PolicyKind = "KILL_SWITCH"
    PolicyActionProposalCatalog PolicyKind = "ACTION_PROPOSAL_CATALOG"
    PolicyReadAdmission PolicyKind = "READ_ADMISSION"
)

type PolicySummary struct {
    Key string `json:"key"`
    Kind PolicyKind `json:"kind"`
    Scope ScopeProjection `json:"scope"`
    Revision int64 `json:"revision"`
    Digest string `json:"digest"`
    Mode string `json:"mode"`
    Status string `json:"status"`
    Owner string `json:"owner"`
    EvidenceAt time.Time `json:"evidence_at"`
    BlockingReasons []string `json:"blocking_reasons"`
    EffectiveActions []string `json:"effective_actions"`
}
~~~

- [ ] **Step 2: 运行 read model 测试并确认失败**

Run: `go test ./internal/investigationview/... ./internal/governanceview/... -run 'Test(Investigation|Policy)' -count=1`

Expected: FAIL，错误包含缺少 package 或 `undefined: PolicySummary`。

- [ ] **Step 3: 实现 PostgreSQL read model 与 fail-closed 聚合**

Investigation 查询从 `investigations` 联接 `incidents`，以 scope path 中 Environment 精确匹配 `environment_id_snapshot`；Run/Grant/Evidence/ActionProposal 使用 LATERAL 聚合避免行乘积。Cursor 是带版本的 base64url JCS `{started_at,id}`，Sort 只允许 `started_at_desc|started_at_asc|status_asc`，limit 1..100；过滤只允许 status、trigger_type、incident_id、service_id、time range 和 160-byte q。

~~~sql
SELECT i.id, i.incident_id, incident.severity, incident.title, i.status,
       run.trigger_type, i.service_id_snapshot,
       grant.status AS grant_status,
       COALESCE(evidence_count.value, 0), COALESCE(proposal_count.value, 0),
       i.started_at, i.completed_at, i.failure_code
FROM investigations i
JOIN incidents incident
  ON (incident.tenant_id, incident.workspace_id, incident.environment_id, incident.id) =
     (i.tenant_id, i.workspace_id, i.environment_id_snapshot, i.incident_id)
LEFT JOIN LATERAL (
    SELECT pr.trigger_type, pr.grant_id
    FROM proactive_runs pr
    WHERE (pr.tenant_id, pr.workspace_id, pr.environment_id, pr.investigation_id) =
          (i.tenant_id, i.workspace_id, i.environment_id_snapshot, i.id)
    ORDER BY pr.created_at DESC, pr.id DESC
    LIMIT 1
) run ON true
LEFT JOIN investigation_grants grant
  ON (grant.tenant_id, grant.workspace_id, grant.environment_id, grant.id) =
     (i.tenant_id, i.workspace_id, i.environment_id_snapshot, run.grant_id)
LEFT JOIN LATERAL (
    SELECT COUNT(*)::bigint AS value FROM evidence e
    WHERE (e.tenant_id, e.workspace_id, e.investigation_id) =
          (i.tenant_id, i.workspace_id, i.id)
) evidence_count ON true
LEFT JOIN LATERAL (
    SELECT COUNT(*)::bigint AS value FROM action_proposals p
    WHERE (p.tenant_id, p.workspace_id, p.environment_id, p.investigation_id) =
          (i.tenant_id, i.workspace_id, i.environment_id_snapshot, i.id)
) proposal_count ON true
WHERE (i.tenant_id, i.workspace_id, i.environment_id_snapshot) = ($1,$2,$3);
~~~

Policy Hub 在 Repository 层以固定 UNION ALL projection 聚合五种来源；每个分支必须有 Scope predicate 和自己的状态枚举。任一来源扫描失败、未知状态、digest 非法或证据时间无效时，整个响应返回 `POLICY_HUB_INCONCLUSIVE`，不能丢掉失败分支后显示其余“正常”。`blocking_reasons` 来自固定码，不能包含数据库错误文本。

- [ ] **Step 4: 写 RBAC、OpenAPI 与 HTTP 安全合同失败测试**

公开路由固定为：

~~~text
GET /api/v1/workspaces/{workspace_id}/environments/{environment_id}/investigations
GET /api/v1/workspaces/{workspace_id}/environments/{environment_id}/investigations/{investigation_id}
GET /api/v1/workspaces/{workspace_id}/environments/{environment_id}/investigations/{investigation_id}/evidence
GET /api/v1/workspaces/{workspace_id}/environments/{environment_id}/investigations/{investigation_id}/action-proposals
GET /api/v1/workspaces/{workspace_id}/environments/{environment_id}/governance/policy-hub
GET /api/v1/workspaces/{workspace_id}/environments/{environment_id}/governance/policy-hub/items/{policy_key}
~~~

~~~go
func TestInvestigationAndPolicyHubPathsAreReadOnlyScopedAndClosed(t *testing.T) {
    document := loadControlPlaneOpenAPI(t)
    for _, path := range []string{
        "/api/v1/workspaces/{workspace_id}/environments/{environment_id}/investigations",
        "/api/v1/workspaces/{workspace_id}/environments/{environment_id}/governance/policy-hub",
    } {
        if got := methodsForPath(t, document, path); !slices.Equal(got, []string{"get"}) {
            t.Fatalf("%s methods = %v", path, got)
        }
    }
    assertEveryOperationHasScopeAndProblem(t, document)
    assertSchemaAdditionalPropertiesFalse(t, document, "InvestigationSummary", "PolicyHubItem")
}
~~~

权限矩阵显式新增 `INVESTIGATION_READ`、`GOVERNANCE_POLICY_READ`。VIEWER 可读安全摘要；OPERATOR/INCIDENT_COMMANDER 按既有矩阵获得 Incident 详情；ADMIN 不自动读取业务 Evidence。未知角色、未知 permission、缺 Environment 或跨 Scope ID fail closed。

- [ ] **Step 5: 运行 API/RBAC 测试并确认失败**

Run: `go test ./api/openapi ./internal/authz ./internal/httpapi -run 'Test(Investigation|PolicyHub)' -count=1`

Expected: FAIL，错误指出 path、schema、permission 或 Handler 缺失。

- [ ] **Step 6: 实现 Handler、OpenAPI 与生成类型**

Handler 只从认证 Principal 与 path 建 Scope。搜索参数由严格 Decoder 解析，unknown query 返回 `400 QUERY_PARAMETER_UNKNOWN`；数据库超时/聚合不完整返回 `503 VIEW_INCONCLUSIVE`。`effective_actions` 由 Authorizer 针对每个资源计算，Policy Hub 治理链接只引用已有 publish/disable/revoke/Kill Switch API，不新增通用 mutation。

~~~go
type InvestigationViewReader interface {
    List(context.Context, investigationview.ListRequest) (investigationview.Page, error)
    Get(context.Context, investigationview.GetRequest) (investigationview.Detail, error)
}

type PolicyHubReader interface {
    List(context.Context, governanceview.ListRequest) (governanceview.Page, error)
    Get(context.Context, governanceview.GetRequest) (governanceview.Detail, error)
}
~~~

OpenAPI 的 Investigation/Policy union 使用 discriminator 和 `additionalProperties:false`；digest 为 `^[0-9a-f]{64}$`，Cursor/limit/time range 有精确约束。运行：

Run: `pnpm --dir web generate:api && pnpm --dir web generate:api:check`

Expected: PASS；唯一生成文件与 OpenAPI 无漂移。

- [ ] **Step 7: 真实 PostgreSQL Scope、分页和不完整聚合验证**

Run:

~~~bash
test -n "$AIOPS_TEST_POSTGRES_DSN"
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" \
  go test -race -count=1 ./internal/investigationview/postgres ./internal/governanceview/postgres -run 'TestRepository'
~~~

Expected: PASS against PostgreSQL 18.4+ with zero required-test skips；跨 Tenant/Workspace/Environment、Cursor 篡改、未知状态、坏 digest、缺来源分支和扫描错误全部 fail closed。缺少数据库环境时 checkbox 保持未完成且不得提交。

- [ ] **Step 8: 绑定生产装配并提交 API**

`cmd/control-plane/main.go` 注入真实 PostgreSQL 两个 read model；typed nil 或缺依赖使启动失败。架构测试扫描生产包，禁止 memory repository 和测试 fixture。

~~~bash
git add internal/investigationview internal/governanceview internal/httpapi internal/authz api/openapi/control-plane-v1.yaml api/openapi/control-plane-v1-investigation-policy-hub_test.go web/src/shared/api/schema.d.ts cmd/control-plane
git commit -m "feat: add investigation and policy hub views"
~~~

### Task 15: 高保真低 AI 感页面、真实 Keycloak 与三断点 E2E

**Files:**
- Modify: web/src/app/router.tsx
- Modify: web/src/app/navigation.ts
- Create: web/src/features/investigations/routes/investigationsRoute.tsx
- Create: web/src/features/investigations/routes/investigationDetailRoute.tsx
- Create: web/src/features/investigations/routes/search.ts
- Create: web/src/features/investigations/api.ts
- Create: web/src/features/investigations/InvestigationWorkspace.tsx
- Create: web/src/features/investigations/InvestigationWorkspace.module.css
- Create: web/src/features/investigations/InvestigationTable.tsx
- Create: web/src/features/investigations/InvestigationDrawer.tsx
- Create: web/src/features/investigations/EvidencePanel.tsx
- Create: web/src/features/investigations/ProposalPanel.tsx
- Create: web/src/features/investigations/InvestigationWorkspace.test.tsx
- Create: web/src/features/policy-hub/routes/policyHubRoute.tsx
- Create: web/src/features/policy-hub/routes/search.ts
- Create: web/src/features/policy-hub/api.ts
- Create: web/src/features/policy-hub/PolicyHub.tsx
- Create: web/src/features/policy-hub/PolicyHub.module.css
- Create: web/src/features/policy-hub/PolicyTable.tsx
- Create: web/src/features/policy-hub/PolicyDetail.tsx
- Create: web/src/features/policy-hub/RevisionDigest.tsx
- Create: web/src/features/policy-hub/PolicyHub.test.tsx
- Create: web/src/test/msw/fixtures/investigationPolicyHub.ts
- Create: web/src/test/msw/handlers/investigationPolicyHub.ts
- Modify: web/src/test/msw/handlers.ts
- Create: web/e2e/investigation-policy-hub.spec.ts
- Create: web/e2e/fixtures/investigationPolicyHub.ts
- Create: web/e2e/visual/investigations-1440.png
- Create: web/e2e/visual/investigations-1024.png
- Create: web/e2e/visual/investigations-390.png
- Create: web/e2e/visual/policy-hub-1440.png
- Create: web/e2e/visual/policy-hub-1024.png
- Create: web/e2e/visual/policy-hub-390.png
- Create: docs/design/frontend/investigation-policy-hub.md

**Interfaces:**
- Consumes: Task 14 生成 API 类型、现有 `controlPlaneClient`、真实 Keycloak session、AppShell/Scope Bar、TanStack Router/Query/Table、统一状态与 RFC 9457 组件。
- Produces: `/investigations`、`/investigations/$investigationId`、`/governance/policies` 路由；可恢复 URL 状态；Investigation/Policy 高保真页面；ActionProposal/Catalog/Evidence/Snapshot digest 安全来源展示与 Phase 7 同一封存事务 Handoff 说明；真实 Keycloak/Scope/effective_actions/axe/视觉 E2E。Phase 4 的 `effective_actions` 不包含创建或派生 ActionPlan。

- [ ] **Step 1: 写 URL、权限和信息层级组件失败测试**

Investigation URL search 固定：`workspace/environment/q/status/trigger/incident/service/from/to/sort/cursor/selected/tab`。Policy Hub 固定：`workspace/environment/q/kind/status/mode/sort/cursor/selected/tab`。unknown key、无效枚举、超过 160 字节 q 和非法时间窗回落到安全默认并替换 URL，不发送宽松请求。

~~~tsx
it('restores scope filters selection and tab without inferring permissions', async () => {
  renderInvestigationRoute('/investigations?workspace=w1&environment=e1&status=PARTIAL&selected=i7&tab=evidence')
  expect(await screen.findByRole('heading', { name: '调查记录' })).toBeVisible()
  expect(screen.getByRole('row', { name: /INC-1042.*PARTIAL/ })).toHaveAttribute('aria-selected', 'true')
  expect(screen.getByRole('tab', { name: '证据' })).toHaveAttribute('aria-selected', 'true')
  expect(screen.queryByRole('button', { name: /执行|批准|派生 ActionPlan/ })).not.toBeInTheDocument()
  expect(lastRequest()).toMatchObject({ workspace: 'w1', environment: 'e1', status: 'PARTIAL' })
})

it('renders each policy dimension independently', async () => {
  renderPolicyHubRoute('/governance/policies?workspace=w1&environment=e1&kind=KILL_SWITCH&selected=ks-global')
  expect(await screen.findByText('GLOBAL Kill Switch')).toBeVisible()
  expect(screen.getByText('CLOSED')).toBeVisible()
  expect(screen.getByText('READ Admission')).toBeVisible()
  expect(screen.getByText('阻塞：KILL_SWITCH_CLOSED')).toBeVisible()
  expect(screen.queryByText('系统整体正常')).not.toBeInTheDocument()
})
~~~

- [ ] **Step 2: 运行组件测试并确认失败**

Run: `pnpm --dir web vitest run src/features/investigations src/features/policy-hub`

Expected: FAIL，错误包含 route/module 未找到。

- [ ] **Step 3: 实现路由、查询键与真实会话边界**

在中央 `router.tsx` 注册三条路由，在 `navigation.ts` 的“运行”加入“调查记录”、在“治理”加入“授权与策略”。Search 使用 Zod exact object；Query key 必须包含完整 Scope 和规范化 search。Scope 切换先取消旧 Query、清空 selected，再请求新 `effective_actions`；禁止瞬间显示旧 Scope 控件。

~~~ts
export const investigationSearchSchema = z.object({
  workspace: z.string().uuid(),
  environment: z.string().uuid(),
  q: z.string().max(160).optional(),
  status: z.enum(['QUEUED', 'RUNNING', 'PARTIAL', 'COMPLETED', 'FAILED', 'CANCELLED']).optional(),
  trigger: z.enum(['INCIDENT', 'SCHEDULE', 'MANUAL']).optional(),
  incident: z.string().uuid().optional(),
  service: z.string().uuid().optional(),
  from: z.string().datetime({ offset: true }).optional(),
  to: z.string().datetime({ offset: true }).optional(),
  sort: z.enum(['started_at_desc', 'started_at_asc', 'status_asc']).default('started_at_desc'),
  cursor: z.string().max(2048).optional(),
  selected: z.string().uuid().optional(),
  tab: z.enum(['summary', 'evidence', 'proposals', 'audit']).default('summary'),
}).strict()
~~~

OIDC 只调用既有 Keycloak `login-required` client；request interceptor 在请求前刷新 Token 并只放内存 Authorization header。401 清空内存会话并保存 same-origin return URL；403/404 保留筛选与 Trace ID，不重定向猜权限。

- [ ] **Step 4: 实现 `/investigations` 高保真工作区**

1440px 页面结构：46px Scope Bar 下是 56px 标题行；随后 48px 紧凑统计条（运行中、部分结果、近 24h 完成、预算/门禁停止），不是四个大卡。筛选条 44px；表头 36px、数据行 40px；右侧详情抽屉 460px，表格剩余宽度不小于 720px。

表格列优先级固定：Investigation/Incident、状态、触发、Service、Grant、Evidence、ActionProposal、开始时间、耗时。状态用图标+文字+浅色底，不只靠颜色。单击写 `selected`，上下键移动，Enter 打开稳定详情，Escape 关闭 drawer。Drawer Tab：概览、证据、ActionProposal、审计；ActionProposal 顶部固定显示“仅为建议，不具备执行、审批、排队或凭据权”，展示 ActionProposal/Catalog/Evidence/Snapshot digest，但 Phase 4 没有直接转换、创建 ActionPlan、批准或执行按钮。

~~~css
.workspace {
  --ops-bg: #f4f6f8;
  --ops-surface: #ffffff;
  --ops-text: #17202a;
  --ops-muted: #52606d;
  --ops-border: #d8dee6;
  --ops-action: #1f5f99;
  min-width: 0;
  background: var(--ops-bg);
  color: var(--ops-text);
}
.tableRow { min-height: 40px; border-bottom: 1px solid var(--ops-border); }
.tableRow[aria-selected='true'] { box-shadow: inset 3px 0 0 var(--ops-action); background: #eef5fb; }
.drawer { width: clamp(440px, 32vw, 480px); border-left: 1px solid var(--ops-border); background: var(--ops-surface); }
.control:focus-visible { outline: 2px solid #1f5f99; outline-offset: 2px; }
@media (prefers-reduced-motion: reduce) { .workspace * { scroll-behavior: auto; transition-duration: 0.01ms; } }
~~~

加载 Skeleton 保持列宽；空状态解释当前筛选并提供“清除筛选”；错误保留 URL 并展示 code/trace_id/重试；STALE、DLP、预算耗尽、Grant revoked、Catalog drift 分别呈现，不合并为红 Toast。

- [ ] **Step 5: 实现 `/governance/policies` Policy Hub**

标题行只有“授权与策略”和安全刷新；上方 44px 过滤条，主区为高密度表 + 460px 详情。列固定为类型、名称/Scope、Revision、Digest、Mode、Status、Owner、证据时间、阻塞数；Digest 显示前 12 位但 accessible name 和安全复制提供完整 64 位。

详情 Tab 固定：当前定义、修订历史、适用范围、阻塞与审计。Proactive Policy 显示触发/Selector/预算/SHADOW|READ_ONLY；Grant 显示有效期和五轴预算；Kill Switch 显示六级继承链；ActionProposal Catalog 显示四类型 `PROPOSAL_ONLY`；READ Admission 单独显示关闭原因。任何条目失败不能被总计状态掩盖。

治理操作只在 `effective_actions` 出现对应动作时提供，并深链到既有 `/proactive-policies/$policyId` 或已有 Kill Switch 对话框；Policy Hub 本身不发明通用 Save/Enable。操作需要最近认证时复用 same-origin return URL 与真实 Keycloak，不持久化 Token。

- [ ] **Step 6: 实现 1024px 与 390px 响应式和可访问性**

1024px：导航折叠为 64px 图标+可访问名称；Investigation/Policy 主表占 56%，详情 44%，隐藏低优先级耗时/Owner 列但保留详情。390px：列表和详情是独立路由；统计条改为可横向键盘滚动的语义列表；每行 56px、主要触控 44px；筛选进入全屏 Radix Dialog，Focus Trap/ESC/关闭后恢复焦点。高风险治理 mutation 在移动端只显示查看影响和“请在桌面完成”。

不得使用 hover 才可见控件；图标按钮都有 `aria-label`；表格排序用 `aria-sort`；相对时间同时提供带时区绝对时间；状态 Icon 不单独传义。

- [ ] **Step 7: 完成组件合同、axe 与构建绿灯**

MSW fixture 覆盖 loading、empty、PARTIAL、DLP、budget exhausted、revoked、Catalog drift、403、404、503、Cursor 下一页和无 effective_actions。它只用于组件测试。

Run: `pnpm --dir web vitest run src/features/investigations src/features/policy-hub`

Expected: PASS；键盘、URL 恢复、Scope 切换和无权限控件测试通过。

Run: `pnpm --dir web lint && pnpm --dir web typecheck && pnpm --dir web build`

Expected: PASS；无手写 DTO、无 Token storage、无路由重复。

- [ ] **Step 8: 写真实 Keycloak/Scope/响应式/视觉 E2E**

Playwright 启动真实 Keycloak Server 26.6.3、PostgreSQL、Control Plane 与 web build，浏览器使用 keycloak-js 26.2.4 完成 Authorization Code + PKCE 登录。不得启用 MSW。测试覆盖：

1. 直接打开带 Workspace/Environment/filter/selected/tab 的 `/investigations`，登录返回后完全恢复。
2. 后退/前进恢复 drawer 与分页，刷新不丢 Scope。
3. Workspace A token 访问 Workspace B Investigation 得到安全 403/404 且无存在性信息。
4. 缺 `ACTION_PROPOSAL_READ` 时 ActionProposal Tab 无内容/动作；角色名变化不改变 `effective_actions` 行为。
5. Policy Hub 的五类条目独立显示，Kill Switch CLOSED 不被其他绿色状态掩盖。
6. 1440/1024/390 无页面级水平滚动；390 详情为独立路由。
7. `axe` 在两页三断点均无 serious/critical violation；键盘顺序与可见焦点正确。
8. 截图与六个基线逐像素比较，阈值 `maxDiffPixelRatio <= 0.01`；禁止渐变、聊天气泡、AI Avatar 和 Bento 卡片。

~~~ts
test('real OIDC restores scoped investigation deep link', async ({ page }) => {
  await page.goto('/investigations?workspace=' + workspaceA + '&environment=' + environmentA + '&selected=' + investigation7 + '&tab=evidence')
  await loginThroughRealKeycloak(page, viewerUser)
  await expect(page).toHaveURL(new RegExp(`workspace=${workspaceA}.*environment=${environmentA}.*selected=${investigation7}.*tab=evidence`))
  await expect(page.getByRole('tab', { name: '证据' })).toHaveAttribute('aria-selected', 'true')
  await expect(page.getByRole('button', { name: /执行|批准|派生 ActionPlan/ })).toHaveCount(0)
  expect((await new AxeBuilder({ page }).analyze()).violations.filter(v => ['serious', 'critical'].includes(v.impact ?? ''))).toEqual([])
})
~~~

- [ ] **Step 9: 运行真实浏览器验收**

Run: `AIOPS_E2E_REAL_OIDC=1 pnpm --dir web playwright test e2e/investigation-policy-hub.spec.ts --project=chromium`

Expected: PASS；真实 Keycloak、跨 Scope、URL 恢复、三断点、axe 和视觉均通过，不出现 MSW 启动日志。

- [ ] **Step 10: 持久化设计细节并提交**

`docs/design/frontend/investigation-policy-hub.md` 必须写入本包 Design Direction、精确页面尺寸、列优先级、URL schema、状态矩阵、permission/effective_actions、键盘、响应式、错误恢复、ActionProposal-only 文案、Phase 7 人工发起/服务端同一封存事务重载复验并派生封存的 Handoff，以及六张视觉基线引用；后续实现不得另建平行设计事实源。

~~~bash
git add web/src/app web/src/features/investigations web/src/features/policy-hub web/src/test/msw web/e2e/investigation-policy-hub.spec.ts web/e2e/fixtures/investigationPolicyHub.ts web/e2e/visual docs/design/frontend/investigation-policy-hub.md
git commit -m "feat: add investigation and policy governance workspaces"
~~~

## Review Gates

- Must verify：真实 Keycloak PKCE、内存 Token、Scope 深链接、服务端 effective_actions、ActionProposal-only、跨 Incident 查询、五类 Policy 独立状态、1440/1024/390、axe、视觉与无 MSW 生产路径。
- Known tradeoff：390px 为防止误触和信息压缩，治理 mutation 只读并要求桌面完成；这是明确的生产安全约束，不是响应式能力缺失。

## Execution Handoff

本包完成后执行 `07-e2e-operations-docs.md` 的阶段级验收。只有最后阶段包把 ActionProposal/Handoff、Investigation、Policy Hub、主动运行、Grant、Gateway、审计、指标、真实浏览器和文档证据全部纳入同一 Gate 后，Phase 4 才可标记实现完成；READ/WRITE Admission 仍按独立 Go/No-Go 保持关闭。
