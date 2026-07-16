# Proactive Investigation End-to-End Operations and Documentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 以真实后端生命周期、Evidence-backed ActionProposal、原子审计、低基数指标、Investigation/Policy Hub、Playwright/axe/视觉回归和运维文档证明本阶段完成，同时保持 READ Admission 关闭直到独立 Go/No-Go。

**Architecture:** PostgreSQL 18.4+ 与 Temporal testsuite 证明事件、定时、人工、SHADOW、预算、Kill Switch 和 ActionProposal-only/Handoff 状态一致；真实 Keycloak Server 26.6.3 与浏览器端三断点、安全 canary 验收主动策略、跨 Incident Investigation 和 Policy Hub；ADR、前端设计、运行手册与状态页成为后续受治理写闭环的持久基线。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4+、pgx/v5、go-chi/v5、Temporal Go SDK 1.46.0、OpenTelemetry Metric 1.39.0、JCS/SHA-256；Node >=24 <25、pnpm 10.34.0、React 19.2.7、Vite 8.1.4、TypeScript 5.9.3、TanStack Router 1.170.17、Query 5.101.2、Table 8.21.3、React Hook Form 7.81.0、Zod 4.4.3、radix-ui 1.6.2、lucide-react 1.24.0、CSS Modules；openapi-typescript 7.13.0、Vitest 4.1.10、Testing Library 16.3.2、MSW 2.15.0、Playwright 1.61.1、@axe-core/playwright 4.12.1。

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

- 顺序：7 / 7；必须按 README.md 固定顺序执行。
- 前置：06-investigation-policy-hub.md 完成，且前六包所有单元、race、合同、真实 PostgreSQL、真实 ActionProposal E2E 和真实 Keycloak 页面验收通过。
- 交付给下一包：端到端证据、可观测性、ADR/运行手册/前端设计、诚实状态页，以及 Phase 7 经认证的人发起、在同一封存事务重载复验后派生封存 ActionPlan 的 Handoff 接口；Phase 4 无创建 ActionPlan API。
- 本包内仍按 Task 编号顺序执行；每个 Task 必须先看到预期失败，再写最小实现、跑通过并提交对应 commit。

### Task 16: 端到端后端生命周期、审计与低基数可观测性

**Files:**
- Create: internal/proactivepolicy/telemetry.go
- Create: internal/proactivepolicy/telemetry_test.go
- Create: internal/proactivepolicy/postgres/audit.go
- Create: internal/proactivepolicy/postgres/audit_test.go
- Create: internal/proactiveworkflow/lifecycle_integration_test.go
- Create: internal/investigationgrant/postgres/lifecycle_integration_test.go
- Modify: internal/proactivepolicy/service.go
- Modify: internal/proactivepolicy/postgres/repository.go
- Modify: internal/investigationgrant/postgres/grants.go
- Modify: internal/investigationgrant/postgres/gate.go
- Modify: internal/actionproposal/generator.go
- Create: internal/actionproposal/telemetry.go
- Create: internal/actionproposal/telemetry_test.go
- Modify: cmd/control-plane/main.go
- Modify: go.mod
- Modify: go.sum
- Modify: Makefile

**Interfaces:**
- Consumes: Task 3–15 的完整服务、Repository、Outbox、Temporal test suite、Gateway、ActionProposal/Handoff Loader 与安全查询页面；调用者提供的 Phase 7 封存事务 Handoff 测试适配器、认证 Principal 和来自完整 T/W/E/S create path 的 `investigationgrant.Scope`；现有 audit_records/outbox_events；go.opentelemetry.io/otel/metric v1.39.0。
- Produces: investigation_grants_total、grant_denials_by_reason、proactive_runs_total、proactive_budget_exhaustions_total、action_proposals_total、action_proposal_findings_total 六个指标；Grant/Policy/Run/Kill Switch/ActionProposal/Finding 的原子安全审计；事件/定时/人工统一生命周期集成证明；Handoff 同一事务重载复验及漂移回滚证明。

- [ ] **Step 1: 写审计字段白名单与指标基数失败测试**

~~~go
func TestProactiveTelemetryUsesFixedLowCardinalityAttributes(t *testing.T) {
    recorder := newMetricRecorder(t)
    telemetry, err := NewTelemetry(recorder.MeterProvider())
    if err != nil {
        t.Fatal(err)
    }
    telemetry.GrantDenied(context.Background(), BoundaryHeartbeat, DenialBudgetExhausted)
    metrics := recorder.Collect(t)
    assertCounter(t, metrics, "grant_denials_by_reason", 1,
        map[string]string{"boundary": "HEARTBEAT", "reason": "BUDGET_EXHAUSTED"})
    for _, forbidden := range []string{tenantID, workspaceID, environmentID, grantID, policyID, "secret-canary"} {
        if strings.Contains(metrics.String(), forbidden) {
            t.Fatalf("metric leaks high-cardinality or sensitive value %q", forbidden)
        }
    }
}

func TestAuditDetailsAreExplicitSafeProjection(t *testing.T) {
    details := grantIssuedAudit(validGrantProjection())
    raw, err := json.Marshal(details)
    if err != nil {
        t.Fatal(err)
    }
    assertJSONKeysExactly(t, raw,
        "grant_digest", "asset_snapshot_digest", "capability_snapshot_digest",
        "runtime_bundle_digest", "trigger_type", "issuer_type", "policy_revision")
    assertNotContains(t, raw, "secret-canary", "https://internal.invalid", "vault://path", "SELECT *")
}

func TestActionProposalTelemetryUsesOnlyTypeAndFindingCode(t *testing.T) {
    recorder := newMetricRecorder(t)
    telemetry := newActionProposalTelemetry(t, recorder.MeterProvider())
    telemetry.ProposalAppended(context.Background(), actionproposal.K8SScale)
    telemetry.HumanReviewRequired(context.Background(), actionproposal.FindingModelOverreach)
    metrics := recorder.Collect(t)
    assertCounter(t, metrics, "action_proposals_total", 1, map[string]string{"action_type": "K8S_SCALE"})
    assertCounter(t, metrics, "action_proposal_findings_total", 1, map[string]string{"finding_code": "MODEL_OVERREACH"})
    assertNotContains(t, metrics.String(), workspaceID, investigationID, proposalID, "secret-canary")
}
~~~

- [ ] **Step 2: 运行 telemetry/audit 测试并确认失败**

Run: go test ./internal/proactivepolicy ./internal/proactivepolicy/postgres ./internal/actionproposal -run 'Test(ProactiveTelemetry|ActionProposalTelemetry|AuditDetails)' -count=1

Expected: FAIL，错误包含 undefined: NewTelemetry、undefined: newActionProposalTelemetry 或 undefined: grantIssuedAudit。

- [ ] **Step 3: 实现固定 OTel instruments 与属性枚举**

go.mod 将 go.opentelemetry.io/otel v1.39.0 和 go.opentelemetry.io/otel/metric v1.39.0 提升为 direct dependency。Telemetry 构造时一次创建 Counter；构造失败使 Control Plane 启动失败，不静默吞掉。属性只允许以下枚举：

~~~go
const (
    MetricInvestigationGrants = "investigation_grants_total"
    MetricGrantDenials = "grant_denials_by_reason"
    MetricProactiveRuns = "proactive_runs_total"
    MetricBudgetExhaustions = "proactive_budget_exhaustions_total"
)

type Telemetry interface {
    GrantTransition(context.Context, GrantStatus)
    GrantDenied(context.Context, Boundary, DenialReason)
    ProactiveRunTransition(context.Context, TriggerType, ProactiveMode, ProactiveRunStatus)
    BudgetExhausted(context.Context, Boundary)
}
~~~

`internal/actionproposal/telemetry.go` 单独定义 `action_proposals_total`、`action_proposal_findings_total` 与以下窄接口，避免让 Grant/Policy 包反向依赖 ActionProposal 领域：

~~~go
type Telemetry interface {
    ProposalAppended(context.Context, ActionType)
    HumanReviewRequired(context.Context, FindingCode)
}
~~~

标签仅 status、boundary、reason、trigger_type、mode、action_type、finding_code；不得添加 Tenant/Workspace/Environment/Asset/Connection/Policy/Run/Grant/ActionProposal ID、digest、subject、error text。Gate 拒绝记录稳定 reason；SQL/unknown 错误统一 GATE_UNAVAILABLE。指标失败不得改变授权或 ActionProposal-only 决策。

- [ ] **Step 4: 实现原子审计白名单**

以下事件与状态事务内 INSERT audit_records；任一审计失败使状态/Outbox 一起回滚：policy.revision.created、policy.previewed、policy.published、policy.disabled、proactive.run.requested、proactive.run.terminal、asset.snapshot.created、investigation.grant.issued/activated/completed/revoked/failed、investigation.grant.denied、kill_switch.revised、action.proposal.appended、action.proposal.human_review_required。

details 仅稳定 ID、digest、revision、计数、枚举 code、预算 limit/used 摘要、actor_type 和 workload identity digest；不得记录 selector 原始内容、Subject claims、TargetRef、Capability 输入、Evidence、Credential、endpoint 或上游 error。Gate denial 每个 Task/Boundary/Grant/Reason 用确定 idempotency key 去重，避免 Heartbeat 重放刷爆审计。

- [ ] **Step 5: 写事件、定时、人工和 SHADOW 生命周期集成测试**

lifecycle_integration_test.go 使用 PostgreSQL 18.4 和 Temporal testsuite，分别驱动：

1. incident.created.v1 → Published INCIDENT Policy → Run → Snapshot → Grant → Investigation/Task → Claim/Start/Heartbeat/Complete → Evidence → Catalog → `PROPOSAL_ONLY` ActionProposal 或 Human Review Finding → Run/Grant COMPLETED；
2. Published SCHEDULE Policy 的固定 Schedule action → 同一路径，issuer=SCHEDULER 且 workload identity digest 匹配；
3. Manual Run → 同一路径，issuer=HUMAN 且权限/Service scope 匹配；
4. SHADOW → Preview/Run COMPLETED，snapshot_count=1、grant_count=1 且 Grant COMPLETED，但 investigation_count=0、attempt_count=0；
5. 任一级 Kill Switch 在 RUNNING 后关闭 → 下一 Heartbeat TERMINATE，Run STOPPED，稳定 failure_code=KILL_SWITCH_CLOSED；
6. Evidence budget 在 Complete 超限 → 无 Evidence/Receipt 写入、Run PARTIAL 或 STOPPED，code=BUDGET_EXHAUSTED；
7. Outbox/Workflow/activity 重放 → 各资源计数仍为 1，审计 chain 不分叉；
8. Model 越权、Catalog/Asset 漂移或无匹配 → ActionProposal count=0、固定 Finding count=1，Phase 4 生成路径的 ActionPlan/Approval/queue/credential/execution count 全为 0；
9. Handoff Loader 正向路径只在经认证的人通过完整 T/W/E/S ActionPlan create path 发起后成立：Phase 7 不得预读 Proposal，必须用 Principal + URL Scope + Proposal ID/expected digest 构造 HandoffRequest 并传入其封存事务；Loader 才在该同一事务按 full Scope 锁定、从库重算并恒时比较摘要、重载并返回复验后的 `TrustedDerivationSource`，自身不创建 Plan。ActionProposal/Catalog/Evidence/Snapshot digest、Scope 或当前资格漂移时停止、记录 Human Review Finding 并回滚整笔事务。只有 Phase 7 能在该事务提交前消费可信来源、派生并封存新 ActionPlan。

~~~go
func TestReadOnlyProactiveLifecycleUsesOneFreshGrant(t *testing.T) {
    fixture := newLifecycleFixture(t, ModeReadOnly)
    fixture.DeliverIncidentCreated()
    fixture.RunTemporalUntilTasksQueued()
    claim := fixture.ClaimAndStartReadTask()
    fixture.Heartbeat(claim, readtask.HeartbeatContinue)
    fixture.CompleteWithSafeEvidence(claim)
    fixture.RunTemporalToCompletion()

    state := fixture.LoadState()
    if state.Runs != 1 || state.Snapshots != 1 || state.Grants != 1 ||
        state.GrantStatus != GrantCompleted || state.RunStatus != RunCompleted || state.Evidence != 1 {
        t.Fatalf("lifecycle state = %#v", state)
    }
    fixture.AssertAuditChainAndNoSensitiveCanary()
}
~~~

- [ ] **Step 6: 扩展 Makefile 集成边界**

test-integration 在既有包后增加 ./internal/investigationgrant/postgres ./internal/proactivepolicy/postgres ./internal/proactiveworkflow ./internal/actionproposal/postgres ./internal/investigationview/postgres ./internal/governanceview/postgres；仍要求 AIOPS_TEST_POSTGRES_DSN，不得自动启动未知数据库或跳过失败。

- [ ] **Step 7: 运行 race、Temporal 与 PostgreSQL 生命周期验证**

Run: go test -race -shuffle=on -count=1 ./internal/proactivepolicy/... ./internal/investigationgrant/... ./internal/proactiveworkflow ./internal/actionproposal/... ./internal/investigationview/... ./internal/governanceview/...

Expected: PASS；Temporal deterministic tests、metric attributes 和安全审计全部通过。

Run: AIOPS_TEST_POSTGRES_DSN='postgres://aiops:password@127.0.0.1:5432/aiops_test?sslmode=disable' make test-integration

Expected: PASS；八个 lifecycle 场景的状态、计数、审计和 Outbox 一致。

- [ ] **Step 8: 提交生命周期与可观测性**

~~~bash
git add internal/proactivepolicy internal/proactiveworkflow/lifecycle_integration_test.go internal/investigationgrant/postgres internal/actionproposal internal/investigationview internal/governanceview cmd/control-plane/main.go go.mod go.sum Makefile
git commit -m "test: prove proactive investigation lifecycle"
~~~

### Task 17: Playwright 响应式、视觉回归与 axe 验收

**Files:**
- Create: web/e2e/proactive-policies.spec.ts
- Create: web/e2e/proactive-policies.visual.spec.ts
- Create: web/e2e/proactive-policies.a11y.spec.ts
- Create: web/e2e/proactive-policies.security.spec.ts
- Create: web/e2e/phase4-operator-journey.spec.ts
- Create: web/e2e/__screenshots__/proactive-policies-1440.png
- Create: web/e2e/__screenshots__/proactive-policies-1024.png
- Create: web/e2e/__screenshots__/proactive-policies-390.png
- Modify: web/e2e/support/fixtures.ts
- Modify: web/e2e/support/accessibility.ts
- Modify: web/playwright.config.ts

**Interfaces:**
- Consumes: Task 12–15 页面、Task 13 MSW 场景、真实 Keycloak Server 26.6.3、浏览器 keycloak-js 26.2.4、Playwright 1.61.1、@axe-core/playwright 4.12.1。
- Produces: 主动策略→跨 Incident Investigation→Evidence/ActionProposal→Policy Hub 的真实操作旅程、Phase 4 无 ActionPlan mutation 证明、Phase 7 Handoff 来源摘要展示，以及 URL 恢复、键盘、三断点、治理错误、视觉和 WCAG 2.2 AA 自动验收证据。

- [ ] **Step 1: 先写端到端失败场景**

~~~ts
test('URL 刷新、后退和分享恢复同一安全投影', async ({ page }) => {
  await page.goto(proactiveURL + '?mode=SHADOW&tab=runs&policy=' + policyId + '&run=' + runId)
  await expect(page.getByRole('row', { name: /夜间容量巡检/ })).toHaveAttribute('aria-selected', 'true')
  await expect(page.getByRole('tab', { name: '运行记录' })).toHaveAttribute('aria-selected', 'true')
  await page.reload()
  await expect(page.getByText(runId)).toBeVisible()
  await page.getByRole('tab', { name: '定义' }).click()
  await page.goBack()
  await expect(page.getByRole('tab', { name: '运行记录' })).toHaveAttribute('aria-selected', 'true')
})

test('@a11y 主动调查工作区无 serious/critical axe 问题', async ({ page }) => {
  await page.goto(proactiveURL)
  await expect(page.getByRole('heading', { name: '主动调查' })).toBeVisible()
  const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag22aa']).analyze()
  expect(results.violations.filter(v => ['serious', 'critical'].includes(v.impact ?? ''))).toEqual([])
})
~~~

- [ ] **Step 2: 运行单个 E2E 并确认失败**

Run: pnpm --dir web test:e2e -- proactive-policies.spec.ts --project=chromium

Expected: FAIL，原因是测试文件/路由尚未完成或 baseline screenshot 缺失；不得用 test.skip 固化失败。

- [ ] **Step 3: 固定三断点与视觉基线**

playwright.config.ts 增加命名 project：desktop-1440 viewport 1440x1000、desktop-1024 viewport 1024x900、mobile-390 viewport 390x844；locale=zh-CN、timezoneId=Asia/Shanghai、colorScheme=light、reducedMotion=reduce、deviceScaleFactor=1。截图关闭 animation、mask 相对时间和随机 Trace ID，不 mask 布局/状态。

visual.spec.ts 对 success、detail selected、Preview、budget exhausted、kill switch closed 各取组件或整页截图。基线必须由实现者人工查看后提交；不能仅因为 diff 更新截图。

- [ ] **Step 4: 覆盖响应式与键盘交互**

1440：完整 216–224px nav、表格和 440–480px 详情并存；1024：次要筛选折叠、身份/状态列冻结、详情独立路由；390：单栏、44px 触控、可查询/筛选/查看/停止升级，Publish/Revoke/Kill Switch 治理动作不可提交并说明桌面限制。

键盘测试覆盖跳到主内容、Tab 顺序、表格 ArrowUp/Down、Enter/Space、Tab 切换、Dialog focus trap、Escape 返回触发器、关闭后焦点恢复、2px 可见 focus；reduced motion 下无 >0ms transition/animation。

- [ ] **Step 5: 覆盖治理、错误和异步恢复**

E2E 依次验证 Preview 排除原因、Publish recent auth、202 Run 刷新恢复、412 ETag diff、Grant revoke、六级 Kill Switch close/open、403 effective_actions、partial/DLP/budget/drift/revocation uncertain 独立状态；随后从 Run 深链跨 Incident Investigation，核对 Evidence、`PROPOSAL_ONLY` ActionProposal、Handoff 来源摘要、Phase 4 无创建 ActionPlan/批准/执行控件及无相关 POST，再进入 Policy Hub 核对修订/摘要/阻塞独立呈现。所有高风险成功在操作附近显示 audit_id，不只 Toast。

- [ ] **Step 6: 增加浏览器安全 canary**

security.spec.ts 捕获 DOM、console、pageerror、request URL/header/body、response body 和下载；断言不出现 fixture 中 secret-canary、Bearer、PEM、vault://、internal endpoint、DSN、SELECT。浏览器请求只发 Control Plane /api/v1，不得访问 /runner/v1 或 Temporal。

- [ ] **Step 7: 运行 Chromium、axe 与视觉回归**

Run: AIOPS_E2E_REAL_OIDC=1 pnpm --dir web test:e2e -- proactive-policies.spec.ts proactive-policies.security.spec.ts investigation-policy-hub.spec.ts phase4-operator-journey.spec.ts --project=chromium

Expected: PASS；URL、键盘、治理与安全 canary 全部通过。

Run: pnpm --dir web test:a11y -- --project=desktop-1440 && pnpm --dir web test:e2e -- proactive-policies.visual.spec.ts

Expected: PASS；无 serious/critical axe violation，三张主断点基线和状态组件截图无未审阅差异。

- [ ] **Step 8: 提交端到端验收证据**

~~~bash
git add web/e2e web/playwright.config.ts
git commit -m "test: verify proactive investigation experience"
~~~

### Task 18: ADR、前端设计持久化、运行手册与最终证据门禁

**Files:**
- Create: internal/proactivepolicy/docs_contract_test.go
- Create: docs/adr/0004-investigation-grants-and-live-kill-switches.md
- Create: docs/design/frontend/proactive-investigation.md
- Modify: docs/design/frontend/investigation-policy-hub.md
- Create: docs/operations/proactive-investigations.md
- Create: docs/operations/action-proposals.md
- Modify: docs/status/current.md
- Modify: docs/architecture/implementation-blueprint-v4.md

**Interfaces:**
- Consumes: 本计划所有已通过的迁移、领域、Gateway、API、前端、E2E 与运行证据；已确认设计 docs/superpowers/specs/2026-07-13-operational-assets-controlled-access-design.md。
- Produces: 不可变 Snapshot/Grant、实时 Kill Switch 与 ActionProposal-only/Handoff 的 ADR；主动调查和 Investigation/Policy Hub 前端唯一细节基线；事件/定时/人工运行、ActionProposal Finding 与停机处置手册；诚实状态页和 V4 架构图。

- [ ] **Step 1: 写文档合同失败测试**

docs_contract_test.go 读取五份目标文档并断言关键标题、六级顺序、四边界顺序、SHADOW 不访问目标、ActionProposal-only、Phase 7 Handoff、Admission 仍关闭、三断点、WCAG、错误停止码和回滚说明存在；不得只检查文件存在。

~~~go
func TestProactiveDocumentationPreservesSafetyDecisions(t *testing.T) {
    documents := map[string][]string{
        "../../docs/adr/0004-investigation-grants-and-live-kill-switches.md": {
            "Asset Snapshot", "InvestigationGrant", "Claim → Start → Heartbeat → Complete",
            "GLOBAL → WORKSPACE → ENVIRONMENT → ASSET → CONNECTION → CAPABILITY",
        },
        "../../docs/design/frontend/proactive-investigation.md": {
            "1440px", "1024px", "390px", "WCAG 2.2 AA", "URL 状态合同",
        },
        "../../docs/design/frontend/investigation-policy-hub.md": {
            "/investigations", "/governance/policies", "PROPOSAL_ONLY", "effective_actions",
        },
        "../../docs/operations/proactive-investigations.md": {
            "SHADOW 不访问目标", "READ Admission 保持关闭", "BUDGET_EXHAUSTED",
            "KILL_SWITCH_CLOSED", "CREDENTIAL_REVOCATION_INCOMPLETE",
        },
        "../../docs/operations/action-proposals.md": {
            "MODEL_OVERREACH", "CATALOG_DRIFT", "Human Review Finding", "Phase 7 同一封存事务",
        },
    }
    for path, fragments := range documents {
        body := readDocument(t, path)
        for _, fragment := range fragments {
            if !strings.Contains(body, fragment) {
                t.Errorf("%s missing %q", path, fragment)
            }
        }
    }
}
~~~

- [ ] **Step 2: 运行文档合同并确认失败**

Run: go test ./internal/proactivepolicy -run TestProactiveDocumentationPreservesSafetyDecisions -count=1

Expected: FAIL，错误指出 ADR、前端设计或运行手册不存在。

- [ ] **Step 3: 写不可变授权与实时覆盖 ADR**

ADR 必须包含 Context、Decision、Alternatives、Consequences、Security Invariants、Migration/Rollback。明确：

- Snapshot/Grant 固定运行语义，正常新发布不改变活动 Grant；
- Kill Switch、撤销、资产 STALE/QUARANTINED、Realm/Scope/身份漂移是实时覆盖；
- Gateway 在 Claim→Start→Heartbeat→Complete 的同一认证事务复验；
- 六级最新 revision 任一 closed 即停止，旧 revision 仅审计；
- 预算在 Grant 行锁下从事实派生，不信任 Runner/browser 计数器；
- SHADOW 创建并立即终结审计用 Snapshot/Grant，但不创建 Investigation/Task、不访问目标；READ_ONLY 不产生写执行；
- 不选择“把授权放进 Temporal History”“Environment 粗粒度即全部资源授权”“热改 Runtime”“模型签发授权”；
- 000018 down 只有七表和相关 Outbox 全空才允许，不能丢历史强回滚；
- 模型只可从服务端 Catalog 选择 action_type 与窄 intent，Scope/Actor attribution 由服务端绑定，越权/漂移/不确定只记录 Human Review Finding。

- [ ] **Step 4: 写前端唯一设计细节基线**

docs/design/frontend/proactive-investigation.md 固定以下内容，后续开发必须先更新文档再改变交互：

- 信息架构、导航文案、Breadcrumb、route 与 URL Search 字段/默认值/清除规则；
- 1440 主从双栏、1024 独立详情、390 单栏和移动治理限制；
- 页面组件树、表格列、四个详情 Tab、RunChain、GrantBudget、六级 Kill Switch；
- 创建修订、Preview、Publish、Disable、Manual Run、Grant Revoke、Kill Switch close/open 的逐步状态图；
- loading/empty/error/stale/partial/forbidden/reauth/async/DLP/budget/drift/kill-switch/revocation-uncertain 的独立文案、图标和恢复动作；
- #F4F6F8 等全部色值、4px 间距、字体、行高、边框、焦点、Reduced Motion；
- WCAG 2.2 AA、键盘顺序、44px 触控、颜色非唯一表达、相对/绝对时间、ID/Digest 安全复制；
- 明确禁止聊天框、AI 头像、霓虹/发光/玻璃、通用 JSON、Secret/endpoint/DSN/SQL、角色推断。

加入以下页面结构作为长期验收基线：

~~~text
AppShell
├── DomainNavigation（运行 / 主动调查）
├── ScopeBar（Workspace + Environment + 权限作用域）
└── ProactivePoliciesPage
    ├── Breadcrumb + Title + PrimaryAction
    ├── PolicySummaryStrip
    ├── FilterToolbar（URL）
    └── Workspace
        ├── PolicyTable
        └── PolicyDetailPanel
            ├── Definition
            ├── Runs → RunChain → GrantBudgetPanel → KillSwitchStack
            ├── Revisions
            └── Audit
~~~

同步复核 `docs/design/frontend/investigation-policy-hub.md` 已包含 `/investigations` 与 `/governance/policies` 的精确 URL schema、跨 Incident 列、Evidence/ActionProposal drawer、五类 Policy、Scope/effective_actions、三断点、键盘、WCAG、视觉 token、真实 Keycloak Server 26.6.3、浏览器 keycloak-js 26.2.4、“ActionProposal 无执行权”与 Phase 7 Handoff 文案，不得另建第二份设计文档。

- [ ] **Step 5: 写生产运行、停止与恢复手册**

运行手册覆盖：Policy Preview→非生产 READ_ONLY→生产 SHADOW→生产 READ_ONLY 顺序；事件 Dispatcher、Schedule、Manual Run 的观测点；六指标和 audit/run/grant/action-proposal/finding 关联查询；六级关闭/打开影响；Grant revoke；预算/DLP/漂移/凭据撤销不确定时停止并升级人工；Temporal/Outbox 重放；PostgreSQL/Temporal 故障恢复；不得手改状态表、不得重放副作用、不得开启 WRITE/READ Admission。`docs/operations/action-proposals.md` 另写 Catalog 无匹配、模型越权、Evidence/Catalog/Asset drift、append-only mutation 拒绝、人工复核、Phase 4 无创建 ActionPlan API，以及 Phase 7 经认证的人通过 full T/W/E/S path 发起→无 Proposal 预读地开启封存事务→用 Principal/URL Scope/Proposal ID/expected digest 构造 HandoffRequest→Handoff Loader 在同一事务锁定并重载可信 ActionProposal/Catalog/Evidence/Snapshot→从库重算/恒时比较摘要与当前门禁复验→派生封存新 ActionPlan→原子提交的唯一 Handoff；任一漂移整笔回滚并升级人工。

Go/No-Go 清单必须说明本阶段只交付实现与证据，生产 READ Admission 仍关闭。未来开启需要独立用户授权、隔离基础设施验证、真实 READ 凭据 Issuer/Revoker 证明、监控告警、演练和回滚批准，不得因本计划测试通过自动打开。

- [ ] **Step 6: 运行文档合同与链接/格式检查**

Run: go test ./internal/proactivepolicy -run TestProactiveDocumentationPreservesSafetyDecisions -count=1

Expected: PASS。

Run: git diff --check

Expected: 无 trailing whitespace、冲突标记或 malformed patch。

- [ ] **Step 7: 执行独立 worktree 全量验证并保存事实**

必须在 commit `ad50d9f`（当时的 `main` 基线）创建、且模块根下不含嵌套 `.worktrees` 的独立 worktree 执行。当前共享主目录的用户 worktree 会被架构测试扫描，不能在那里声称全绿，更不能删除它们。

~~~bash
git diff --name-only --diff-filter=ACM -z ad50d9f -- '*.go' | xargs -0 gofmt -w
go test -race -shuffle=on -count=1 ./...
go vet ./...
go build ./cmd/control-plane ./cmd/worker ./cmd/read-runner ./cmd/write-runner ./cmd/executor
AIOPS_TEST_POSTGRES_DSN='postgres://aiops:password@127.0.0.1:5432/aiops_test?sslmode=disable' make test-integration
pnpm --dir web install --frozen-lockfile
pnpm --dir web check
make test-action-proposals-e2e
AIOPS_E2E_REAL_OIDC=1 pnpm --dir web test:e2e
git diff --check
~~~

Expected: 全部退出码 0；PostgreSQL 明确为 18.4+；OpenAPI 生成零 diff；Go race/vet/build、Vitest、Playwright、axe、视觉基线均通过。任何一项失败都不得更新状态为完成。

- [ ] **Step 8: 基于证据更新 current status 与 V4 blueprint**

仅在 Step 7 全绿后更新 docs/status/current.md：记录 000018 七表、Snapshot/Grant、Policy/Run、四边界 Gate、ActionProposal/Finding、跨 Incident Investigation、Policy Hub、API、前端和测试“已实现”；同时醒目标记“READ Admission CLOSED / WRITE CLOSED / 尚未生产启用”。记录验证日期 2026-07-13、精确命令与 commit，不写“生产就绪”。

implementation-blueprint-v4.md 增加四层架构、七表归属、事件/定时统一路径、Gateway 四边界、六级 Kill Switch、Evidence→ActionProposal/Finding→Phase 7 Handoff、跨 Incident Investigation、Policy Hub、前端路由和正交状态；保留 V3 历史链接，不能覆盖或伪造旧状态。若 Step 7 未通过，仅记录 Blocked 与失败命令，不宣称完成。

- [ ] **Step 9: 再跑状态合同和最终差异审查**

Run: go test ./internal/proactivepolicy ./internal/investigationgrant/... ./internal/httpapi -count=1

Expected: PASS。

Run: git status --short && git diff --stat ad50d9f

Expected: 只有本计划列出的实现、测试、生成类型、截图与文档；无 Secret、临时文件、数据库 dump、Playwright trace/video 或未声明二进制。

- [ ] **Step 10: 提交持久化设计与完成证据**

~~~bash
git add internal/proactivepolicy/docs_contract_test.go docs/adr/0004-investigation-grants-and-live-kill-switches.md docs/design/frontend/proactive-investigation.md docs/design/frontend/investigation-policy-hub.md docs/operations/proactive-investigations.md docs/operations/action-proposals.md docs/status/current.md docs/architecture/implementation-blueprint-v4.md
git commit -m "docs: persist proactive investigation design"
~~~

---

## Execution Handoff

计划执行顺序固定为 Task 1→18。推荐使用 superpowers:subagent-driven-development 在独立 worktree 中逐任务执行并在每个 commit 后复核；如跨会话执行，使用 superpowers:executing-plans，必须从最近一个已验证 commit 恢复，不能跳过失败测试、四边界门禁、ActionProposal Overreach/Drift/Handoff、真实 Keycloak、前端 axe/视觉或最终 Go/No-Go 证据。
