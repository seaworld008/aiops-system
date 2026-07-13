# Proactive Investigation Web Experience Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 交付企业运维控制台中的主动调查主从工作区、策略修订与 Preview、运行/Grant/预算/Kill Switch 详情，以及具备最近认证和 ETag 冲突恢复的治理交互。

**Architecture:** React 只消费生成的 Control Plane 安全 DTO，TanStack Router/Query 保存 Scope、筛选、选中项和 Tab；1440/1024/390 三断点使用同一信息架构，所有高风险动作依赖 effective_actions 和服务端确认。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4+、pgx/v5、go-chi/v5、Temporal Go SDK 1.46.0、OpenTelemetry Metric 1.39.0、JCS/SHA-256；Node >=24 <25、pnpm 10.34.0、React 19.2.7、Vite 8.1.4、TypeScript 7.0.2、TanStack Router 1.170.17、Query 5.101.2、Table 8.21.3、React Hook Form 7.81.0、Zod 4.4.3、radix-ui 1.6.2、lucide-react 1.24.0、CSS Modules；openapi-typescript 7.13.0、Vitest 4.1.10、Testing Library 16.3.2、MSW 2.15.0、Playwright 1.61.1、@axe-core/playwright 4.12.1。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- 实现基线固定为 main@ad50d9f；开始执行时先创建独立 worktree，且该模块根下不能包含嵌套 .worktrees。当前共享主目录会被既有架构唯一调用链测试扫描到用户 worktree，因此不得宣称其 go test ./... 基线全绿，也不得删除用户 worktree。
- 继续使用 Go 模块化单体；本阶段不新建微服务。
- PostgreSQL 是领域事实源，Temporal 只保存编排 ID、摘要和小型脱敏结果。
- 模型不是授权 Principal，不属于可信计算基，不能签发、扩大、复用或转换 Grant。
- 资产目录、浏览器、Task、事件 Payload 和模型都不能向 Runner 提交 endpoint、DSN、Secret、命令、SQL、任意 Header、任意请求体、Target、Credential、Network 或 Runner 选择。
- 只有 ACTIVE + EXACT + PUBLISHED + AVAILABLE 的资产能力可以进入实时调查；STALE、QUARANTINED、AMBIGUOUS、UNRESOLVED 必须 fail closed。
- 每次事件、定时或人工运行都创建新的不可变 Asset Snapshot 和 Grant；运行固定 Asset、Target、Capability、Runtime Bundle、Policy 和 Grant 摘要。
- Grant 只授权 READ，不能转化或复用于 WRITE；ActionPlan 仍需独立 ActionEnvelope、策略、审批和凭据链。
- SHADOW 不访问目标；READ_ONLY 不产生写执行；生产写和现有 READ Admission 均保持关闭，实施本计划不得新增配置开关绕过 Go/No-Go。
- 六级 Kill Switch 固定为 GLOBAL、WORKSPACE、ENVIRONMENT、ASSET、CONNECTION、CAPABILITY；任一级当前修订关闭都阻止新 Claim，并在 Start/Heartbeat/Complete fail closed。
- Runtime/配置更新只影响新 Grant；安全撤销、Kill Switch、资产 STALE/QUARANTINED 和身份漂移属于实时安全门禁，必须终止仍活动的授权。
- 公开 DTO、日志、Trace、Temporal History、Evidence 和审计不得包含 Secret、Token、PEM、完整 DSN、Vault URL/Path、内部 endpoint、原始上游错误、任意 SQL 或完整查询结果。
- 所有公共列表使用不透明 Cursor 与稳定排序；所有写请求要求 Idempotency-Key；发布、状态更新和撤销要求 ETag/If-Match；错误使用 RFC 9457、稳定 code 和 trace_id。
- Grant 撤销、策略发布/启停与 Kill Switch 变更要求 1–15 分钟范围内配置的最近 OIDC 认证，默认 5 分钟。
- 前端沿用唯一 web/ 工程、唯一 api/openapi/control-plane-v1.yaml 和唯一生成文件 web/src/shared/api/schema.d.ts；不引入 Redux，以 URL/Query 保存 Scope、筛选、排序、分页、Tab 和选中对象。
- 前端文案使用“主动调查”“系统调查运行”“Runner 与能力”，不得使用“Agent 已登录服务器”；不得引入聊天框、AI 头像、霓虹、发光或玻璃拟态。
- 前端满足 WCAG 2.2 AA、键盘操作、可见焦点、持久 Label、Reduced Motion 与 44px 触控目标；1440px、1024px、390px 均须验收。
- 生产级事件/定时只读调查是整个 Governed Operations Program 的中间门槛，不是终点；Program 最终必须进入固定类型化 ActionEnvelope、策略、审批、短期凭据、WRITE Runner、执行验证和不可变审计组成的受治理写闭环。
- 本阶段交付真实 PostgreSQL、Temporal、OIDC、mTLS、Runtime Publication 与 Gateway 路径上的可生产实现；fake、MSW、Temporal testsuite 和内存对象只能用于测试，绝不能成为生产装配或失败降级路径。

---

## Package Position

- 顺序：5 / 7；必须按 README.md 固定顺序执行。
- 前置：04-evidence-action-proposal.md 的 ActionProposal Catalog、append-only Repository、Handoff Loader、只读 API 与真实安全 E2E 通过；03-gateway-api.md 的 OpenAPI、生成 schema.d.ts 与 HTTP 行为测试通过。
- 交付给下一包：可由 Playwright/axe 验收的真实前端页面、MSW 合同测试夹具、ActionProposal 只读来源摘要和持久化交互细节；Phase 4 不显示创建 ActionPlan 的操作。
- 本包内仍按 Task 编号顺序执行；每个 Task 必须先看到预期失败，再写最小实现、跑通过并提交对应 commit。

### Task 12: 主动调查前端信息架构、URL 状态与主从详情

**Files:**
- Create: web/src/features/proactive-policies/model.ts
- Create: web/src/features/proactive-policies/search.ts
- Create: web/src/features/proactive-policies/api.ts
- Create: web/src/features/proactive-policies/queries.ts
- Create: web/src/features/proactive-policies/routes.tsx
- Create: web/src/features/proactive-policies/ProactivePoliciesPage.tsx
- Create: web/src/features/proactive-policies/ProactivePoliciesPage.module.css
- Create: web/src/features/proactive-policies/components/PolicySummaryStrip.tsx
- Create: web/src/features/proactive-policies/components/PolicyTable.tsx
- Create: web/src/features/proactive-policies/components/PolicyDetailPanel.tsx
- Create: web/src/features/proactive-policies/components/RunChain.tsx
- Create: web/src/features/proactive-policies/components/RunTable.tsx
- Create: web/src/features/proactive-policies/components/GrantBudgetPanel.tsx
- Create: web/src/features/proactive-policies/components/KillSwitchStack.tsx
- Create: web/src/features/proactive-policies/components/States.tsx
- Create: web/src/features/proactive-policies/ProactivePoliciesPage.test.tsx
- Create: web/src/features/proactive-policies/search.test.ts
- Modify: web/src/app/router.tsx
- Modify: web/src/app/navigation.ts
- Modify: web/src/app/styles/tokens.css

**Interfaces:**
- Consumes: web/src/shared/api/controlPlaneClient.ts、schema.d.ts、AppShell/Navigation、TanStack Router/Query/Table；Task 8 API 与 Task 10 的安全 ActionProposal projection；不消费内部 `TrustedDerivationSource`，也不直接调用 Handoff Loader。
- Produces: 已批准的 `/proactive-policies` 列表与 `/proactive-policies/$policyId` 详情路由；Workspace/Environment、筛选和选中项使用规范化 URL Search；安全只读运行/Grant/Kill Switch/ActionProposal 来源视图；持久显示“Phase 7 仅可由经认证的人发起，并在同一服务端封存事务重载复验、派生和封存”的交接说明；不产生接受 ActionProposal、创建 ActionPlan、审批、排队或执行控件。

- [ ] **Step 1: 写 URL 恢复、键盘选择和正交状态失败测试**

search.test.ts 固定默认 search，并证明未知键被移除、非法枚举回退、Cursor 不解码到 UI、scope 变化清除 selected policy/cursor。页面测试使用 MemoryHistory 与 MSW，不 mock Query hook。

~~~tsx
it('从 URL 恢复筛选、选中策略和运行 Tab', async () => {
  renderProactiveRoute(
    '/proactive-policies?workspace=ws-1&environment=env-1' +
      '&trigger=SCHEDULE&mode=SHADOW&status=SHADOW&tab=runs&policy=policy-2&cursor=cursor-v1',
  )
  expect(await screen.findByRole('heading', { name: '主动调查' })).toBeVisible()
  expect(screen.getByRole('combobox', { name: '触发方式' })).toHaveValue('SCHEDULE')
  expect(screen.getByRole('tab', { name: '运行记录' })).toHaveAttribute('aria-selected', 'true')
  expect(screen.getByRole('row', { name: /夜间容量巡检/ })).toHaveAttribute('aria-selected', 'true')
})

it('不会把正交状态合并成一个状态徽标', async () => {
  renderProactiveRoute(defaultURL)
  const row = await screen.findByRole('row', { name: /生产错误日志巡检/ })
  expect(within(row).getByText('READ_ONLY')).toBeVisible()
  expect(within(row).getByText('已发布')).toBeVisible()
  expect(within(row).getByText('预算耗尽')).toBeVisible()
})
~~~

- [ ] **Step 2: 运行前端测试并确认路由缺失**

Run: pnpm --dir web test -- proactive-policies/search.test.ts proactive-policies/ProactivePoliciesPage.test.tsx

Expected: FAIL，错误包含 Cannot find module './features/proactive-policies/routes' 或 route not found。

- [ ] **Step 3: 实现 Zod Search、稳定 Query Key 与安全 API adapter**

URL 字段固定为 trigger、mode、status、q、sort、cursor、policy、tab、run；Tab 仅 definition/runs/revisions/audit。所有查询键包含 workspaceId、environmentId 和规范化 search；切换 Scope 时 Query 不复用旧 Scope 数据。

~~~ts
export const proactiveSearchSchema = z.object({
  trigger: z.enum(['INCIDENT', 'SCHEDULE']).optional(),
  mode: z.enum(['SHADOW', 'READ_ONLY']).optional(),
  status: z.enum(['DRAFT', 'SHADOW', 'READ_ONLY', 'DISABLED', 'SUPERSEDED']).optional(),
  q: z.string().trim().max(80).optional(),
  sort: z.enum(['updated_desc', 'name_asc', 'next_run_asc']).default('updated_desc'),
  cursor: z.string().max(512).optional(),
  policy: z.string().uuid().optional(),
  tab: z.enum(['definition', 'runs', 'revisions', 'audit']).default('definition'),
  run: z.string().uuid().optional(),
})

export const proactiveKeys = {
  all: (workspaceId: string, environmentId: string) =>
    ['proactive-policies', workspaceId, environmentId] as const,
  list: (workspaceId: string, environmentId: string, search: ProactiveSearch) =>
    [...proactiveKeys.all(workspaceId, environmentId), 'list', search] as const,
  detail: (workspaceId: string, environmentId: string, policyId: string) =>
    [...proactiveKeys.all(workspaceId, environmentId), 'detail', policyId] as const,
}
~~~

api.ts 只能从生成 schema 选取响应类型，并将 Problem 规范化为 {code, traceId, status}；不得将 response body、Authorization 或原始 error 打到 console。所有请求 credentials=same-origin，Accept=application/json。

- [ ] **Step 4: 持久化页面骨架与精确视觉布局**

AppShell 顶级导航在“运行”组增加“主动调查”，图标与文字同时可见。页面使用 Breadcrumb → 标题/稳定 Scope → 1 个主操作 → 运营摘要条 → 筛选条 → 表格/详情。不要使用营销 Hero、大号渐变卡或聊天入口。

~~~css
.page {
  min-width: 0;
  padding: 20px 24px 32px;
  color: var(--color-text, #17202a);
  background: var(--color-bg, #f4f6f8);
}

.workspace {
  display: grid;
  grid-template-columns: minmax(620px, 1fr) 460px;
  min-height: 620px;
  border: 1px solid var(--color-border, #d7dde3);
  border-radius: 6px;
  background: var(--color-surface, #fff);
}

.detail {
  border-left: 1px solid var(--color-border, #d7dde3);
  overflow: auto;
}

@media (max-width: 1023px) {
  .page { padding: 16px; }
  .workspace { grid-template-columns: minmax(0, 1fr); }
  .detail { display: none; }
}

@media (max-width: 767px) {
  .page { padding: 12px; }
  .toolbar { min-height: 44px; overflow-x: auto; }
}
~~~

tokens.css 固定规范色 #F4F6F8/#FFFFFF/#17212B/#17202A/#52606D/#D7DDE3/#1F5EA8/#287A4B/#9A5B0A/#B42318；4px 间距；32px 常规控件，36–40px 桌面表格行，移动触控 44px；字体 13–14px，标题 22–24px；Focus 2px；动画 120–180ms 且 prefers-reduced-motion 下关闭。

- [ ] **Step 5: 实现摘要、表格、详情与完整运行链**

PolicySummaryStrip 是紧凑统计条，展示已发布/启用、今日运行、Shadow、平均耗时、证据量、预算拒绝，不用六张独立大卡。PolicyTable 列固定：策略/修订、触发、模式、策略状态、最近运行、下次运行、最近结果；首列与状态列在 1024–1439px sticky，次要筛选折叠。

1440px 选中行打开 440–480px 右栏并保留列表；768–1023px 导航到独立详情路由；<768px 仍可查询、筛选、查看与停止/升级人工，高风险治理按钮隐藏并显示“请在桌面端完成治理操作”。行支持 ArrowUp/ArrowDown、Enter、Space，aria-selected 和可见焦点。

PolicyDetailPanel 的 Tab 固定定义/运行记录/修订/审计。定义首屏展示 Trigger、Selector 摘要、Capability digest、模式、预算；RunChain 必须按结构展示：

~~~text
触发 → 解析资产 → 签发 Grant → Runner 调查 → Evidence → ActionProposal（PROPOSAL_ONLY）
~~~

ActionProposal 节点只展示 ActionProposal/Catalog/Evidence/Snapshot digest 与“无执行权”说明。Phase 4 不提供创建 ActionPlan 的按钮或 API；页面仅持久化未来 Phase 7 人工发起交接所需的安全来源引用。Phase 7 若开放该操作，仍必须由经认证的人明确发起；Phase 7 服务端开启封存事务，在同一事务调用 Handoff Loader 锁定并重载可信 ActionProposal/Catalog/Evidence/Snapshot、复验摘要，再派生和封存全新 ActionPlan 后原子提交，不能把浏览器 DTO 当作计划事实。

RunTable 将 Run、Grant、Snapshot、调用、Evidence、Credential revocation 和最终结果分列；PARTIAL、BUDGET_EXHAUSTED、DLP_REJECTED、DRIFTED、CREDENTIAL_REVOCATION_INCOMPLETE 使用不同图标、文字和详情，不合并成 red toast。GrantBudgetPanel 同时显示 limit/used/remaining：工具调用、单源并发、时长、Evidence bytes、模型 tokens、Credential TTL。KillSwitchStack 固定六级次序并标出 effective closed 来源和 revision。

- [ ] **Step 6: 实现 Skeleton、空、错误、陈旧和权限状态**

Skeleton 保留表格列宽和详情结构；空状态解释筛选为空或无权限，并只显示 effective_actions 允许的下一步。错误状态保留 URL/筛选和 trace_id，提供安全重试。stale、partial、forbidden、reauthentication、async、DLP、budget、kill switch、revocation uncertain 均为独立持久组件；Toast 只用于低风险完成反馈。

- [ ] **Step 7: 运行组件、类型和构建测试**

Run: pnpm --dir web typecheck && pnpm --dir web test -- proactive-policies && pnpm --dir web build

Expected: PASS；构建产物无 TypeScript 错误，页面测试不出现 act/a11y warning。

- [ ] **Step 8: 提交主动调查只读工作区**

~~~bash
git add web/src/features/proactive-policies web/src/app/router.tsx web/src/app/navigation.ts web/src/app/styles/tokens.css
git commit -m "feat: add proactive investigation workspace"
~~~

### Task 13: 策略修订、Preview、治理操作与前端合同模拟

**Files:**
- Create: web/src/features/proactive-policies/editor/policySchema.ts
- Create: web/src/features/proactive-policies/editor/PolicyRevisionForm.tsx
- Create: web/src/features/proactive-policies/editor/TriggerFields.tsx
- Create: web/src/features/proactive-policies/editor/AssetSelectorFields.tsx
- Create: web/src/features/proactive-policies/editor/CapabilityBudgetFields.tsx
- Create: web/src/features/proactive-policies/editor/PreviewPanel.tsx
- Create: web/src/features/proactive-policies/editor/PolicyRevisionForm.module.css
- Create: web/src/features/proactive-policies/actions/PublishDialog.tsx
- Create: web/src/features/proactive-policies/actions/DisableDialog.tsx
- Create: web/src/features/proactive-policies/actions/ManualRunDialog.tsx
- Create: web/src/features/proactive-policies/actions/RevokeGrantDialog.tsx
- Create: web/src/features/proactive-policies/actions/KillSwitchDialog.tsx
- Create: web/src/features/proactive-policies/actions/MutationResult.tsx
- Create: web/src/features/proactive-policies/actions/useGovernanceMutation.ts
- Create: web/src/features/proactive-policies/PolicyGovernance.test.tsx
- Create: web/src/test/msw/fixtures/proactivePolicies.ts
- Create: web/src/test/msw/handlers/proactivePolicies.ts
- Modify: web/src/test/msw/handlers.ts
- Modify: web/src/test/msw/browser.ts
- Modify: web/src/test/msw/server.ts

**Interfaces:**
- Consumes: Task 7/10 生成类型、Task 8 写 API、既有 MSW server/browser、RHF/Zod/radix-ui。
- Produces: 类型化 Policy Revision 表单、Preview、Publish/Disable/Run/Revoke/Kill Switch 操作和可恢复错误状态；安全 MSW contract fixtures。

- [ ] **Step 1: 写 Preview、ETag、最近认证与权限驱动失败测试**

~~~tsx
it('Preview 展示入选和逐类排除，不把排除资产变成可运行选择', async () => {
  renderPolicyEditor({ actions: ['PREVIEW', 'PUBLISH'] })
  await userEvent.click(screen.getByRole('button', { name: '预览资产范围' }))
  expect(await screen.findByText('入选 12')).toBeVisible()
  expect(screen.getByText('STALE · 3')).toBeVisible()
  expect(screen.getByText('MAPPING_NOT_EXACT · 2')).toBeVisible()
  expect(screen.queryByRole('checkbox', { name: /强制包含被排除资产/ })).not.toBeInTheDocument()
})

it('412 显示字段差异并阻止直接重试发布', async () => {
  server.use(publishPolicyEtagConflict)
  renderPolicyDetail({ actions: ['PUBLISH'] })
  await publishWithReason('approved rollout')
  expect(await screen.findByRole('heading', { name: '修订已发生变化' })).toBeVisible()
  expect(screen.getByText('模式：SHADOW → READ_ONLY')).toBeVisible()
  expect(screen.getByRole('button', { name: '重新载入并审阅' })).toBeVisible()
  expect(screen.queryByRole('button', { name: '仍然发布' })).not.toBeInTheDocument()
})

it('不按角色名推断操作', async () => {
  renderPolicyDetail({ role: 'ADMIN', actions: ['VIEW'] })
  expect(screen.queryByRole('button', { name: '发布修订' })).not.toBeInTheDocument()
})
~~~

- [ ] **Step 2: 运行治理组件测试并确认失败**

Run: pnpm --dir web test -- proactive-policies/PolicyGovernance.test.tsx

Expected: FAIL，错误包含 Cannot find module './editor/PolicyRevisionForm'。

- [ ] **Step 3: 实现严格判别联合表单**

表单不提供通用 JSON、Cron 自由扩展、任意 Header/Body、查询文本、endpoint 或 runtime override。Trigger 仅 incident.created.v1 或严格五段 UTC cron；Selector 仅 asset_ids/asset_kinds/service_ids；能力从服务端 PUBLISHED+AVAILABLE 列表选择。

~~~ts
const strictFiveFieldCron = z.string().regex(
  /^(?:\*\/(?:5|15) \* \* \* \*|0 \* \* \* \*|(?:[0-5]?\d) (?:[01]?\d|2[0-3]) \* \* \*)$/,
  '仅支持每 5/15 分钟、每小时或固定 UTC 每日时间',
)

const assetKindSchema = z.enum([
  'SERVICE', 'LINUX_VM', 'WINDOWS_VM', 'BARE_METAL_HOST',
  'KUBERNETES_CLUSTER', 'KUBERNETES_NAMESPACE', 'KUBERNETES_WORKLOAD',
  'DATABASE_INSTANCE', 'DATABASE', 'METRICS_SOURCE', 'LOG_SOURCE', 'TRACE_SOURCE',
  'AWX_INVENTORY', 'ARGO_APPLICATION', 'CI_PIPELINE', 'GIT_REPOSITORY', 'CLOUD_RESOURCE',
])

const assetSelectorSchema = z.object({
  asset_ids: z.array(z.string().uuid()).max(256),
  asset_kinds: z.array(assetKindSchema).max(32),
  service_ids: z.array(z.string().uuid()).max(64),
}).refine(v => v.asset_ids.length + v.asset_kinds.length + v.service_ids.length > 0, {
  message: '至少选择一个资产、资产类型或服务范围',
})

const budgetSchema = z.object({
  max_tool_calls: z.number().int().min(1).max(12),
  max_concurrency_per_source: z.number().int().min(1).max(4),
  max_duration_seconds: z.number().int().min(30).max(900),
  max_evidence_bytes: z.number().int().min(1024).max(8_388_608),
  max_model_tokens: z.number().int().min(0).max(65_536),
}).refine(v => v.max_concurrency_per_source <= v.max_tool_calls, {
  path: ['max_concurrency_per_source'],
  message: '单源并发不能超过工具调用上限',
})

export const policyRevisionSchema = z.object({
  name: z.string().trim().min(1).max(160),
  trigger: z.discriminatedUnion('type', [
    z.object({ type: z.literal('INCIDENT'), event_type: z.literal('incident.created.v1') }),
    z.object({ type: z.literal('SCHEDULE'), schedule_expression: strictFiveFieldCron }),
  ]),
  selector: assetSelectorSchema,
  capability_set_id: z.string().uuid(),
  mode: z.enum(['SHADOW', 'READ_ONLY']),
  data_classification: z.enum(['INTERNAL', 'SENSITIVE']),
  min_interval_seconds: z.number().int().min(300).max(86_400),
  budget: budgetSchema,
})
~~~

持久 Label、约束说明和 inline error 永远存在；提交后使用服务端 projection 替换本地值，不做治理状态 optimistic update。Scope 切换且表单 dirty 时显示阻止式确认；确认离开只丢本地未提交字段，不迁移到新 Scope。

- [ ] **Step 4: 实现 Preview 与 SHADOW 语义呈现**

PreviewPanel 展示 selected_count、excluded_count、按 reason 聚合、最多 100 条安全资产摘要、Capability/Runtime digest、预计硬预算；超出 100 明确“其余结果未展示”。SHADOW 以结构化说明固定“创建并立即终结审计用 Snapshot/Grant，只记录本应执行的能力与预算，不访问目标、不创建 Investigation/Task”，不得用含糊的“试运行”。

- [ ] **Step 5: 实现五类高风险治理交互**

Publish、Disable、Revoke Grant、Kill Switch close/open 都要求影响范围确认、reason、当前 ETag 和 Idempotency-Key；Manual Run 要求 service、trigger reason 但不能选择 Target/Runner/Credential。确认按钮使用动作文字，不用“确定”。

useGovernanceMutation 处理：

- 202：展示 Operation/Run ID、阶段、开始时间、最新 heartbeat，刷新后按 URL run 恢复；
- 401 reauthentication_required：先确保 Revision 已服务端保存，只向 Phase 1 `reauthenticate(returnURL)` 传递同源 return URL（它固定 `prompt:login`、`maxAge:0`），不得把草稿正文、Token 或响应写 localStorage/sessionStorage；返回后由后端重新验证 `auth_time`；
- 409：显示稳定冲突 code 与重新载入；
- 412：显示服务端 current projection 与本地审阅字段差异，必须重新审阅；
- 503：保留表单和 trace_id，允许有界重试；
- 成功：操作附近持久 MutationResult 展示 audit_id，不只 Toast。

KillSwitchDialog 固定 GLOBAL/WORKSPACE/ENVIRONMENT/ASSET/CONNECTION/CAPABILITY 六级，不允许自定义 scope；subject 由当前安全资源选择器生成，不接受任意 ID 文本。<768px 除停止/升级人工外禁用治理提交，保留原因说明。

- [ ] **Step 6: 编写安全 MSW fixtures 与真实请求断言**

fixtures 覆盖 loading、empty、success、partial、budget、DLP、drift、kill switch、revocation uncertain、403、401 recent auth、409、412、503。Fixture 中加入 canary 验证渲染层不会显示 `https://internal.invalid`、`vault://secret/path`、`Bearer canary` 或 SQL；正常 DTO 本身不得包含这些字段。

MSW handler 验证 environment_id、Idempotency-Key、If-Match、Content-Type；不满足时返回与后端相同 Problem。测试检查创建/发布/Run/Revoke/Kill Switch 请求 body exact match OpenAPI additionalProperties:false。

- [ ] **Step 7: 运行 MSW、组件、类型和构建检查**

Run: pnpm --dir web test -- proactive-policies && pnpm --dir web typecheck && pnpm --dir web build

Expected: PASS；无未处理请求、console error、secret canary 或 TypeScript 漂移。

- [ ] **Step 8: 提交策略治理交互**

~~~bash
git add web/src/features/proactive-policies web/src/test/msw
git commit -m "feat: add proactive policy governance interactions"
~~~
