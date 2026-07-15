# 04 Proactive Grants 阶段索引

> 状态：规划完成，尚未执行。实现基线固定为 `main@ad50d9f`。

本目录把 Asset Snapshot、InvestigationGrant、主动策略、Gateway 四边界、Evidence-backed ActionProposal、跨 Incident Investigation、Policy Hub 和高保真前端拆成七个可独立审查、固定顺序执行的任务包。每个包都保留 Superpowers writing-plans 的 Header、Global Constraints、Files、Interfaces、Red→Green→Refactor 检查框、验证命令和逐任务 commit；任何执行者不得跳包或把多个包压回单一巨型计划。

## Program 方向

生产级只读不是终点，而是 Governed Operations Program 的中间门槛。Program 的最终闭环固定为：

```text
Event / Schedule / Human
  → typed read-only Investigation
  → Evidence / Root Cause
  → append-only PROPOSAL_ONLY ActionProposal or Human Review Finding
  → Phase 7 human-initiated server-side derivation handoff
  → reload trusted ActionProposal / Catalog / Evidence and verify every digest
  → independently constructed and sealed immutable ActionPlan
  → typed ActionEnvelope / policy / human approval
  → short-lived single-action credential / isolated WRITE Runner
  → independent verification / reconciliation / safe rollback or escalation
  → immutable receipt and audit chain
```

本阶段交付可生产实现的事件/定时只读调查、Evidence、ActionProposal-only 建议、治理查询与前端工作区；它不执行 ActionProposal、不把 READ Grant 转为 WRITE，也不新增通用终端、任意命令、任意 SQL 或模型授权。现有 WRITE 与 READ Admission 均保持关闭，直到各自独立生产 Go/No-Go 完成。

“可生产实现”要求真实装配 PostgreSQL、Temporal、OIDC、mTLS、Runtime Publication、Runner Realm、短期 READ 凭据 Issuer/Revoker 和四边界 Gateway。fake、MSW、Temporal testsuite、内存对象只用于测试与可重复验收，不得成为生产路径、依赖失败降级或 Demo 替代实现。

## 固定执行顺序

| 顺序 | 任务包 | Tasks | 完成门槛 |
|---:|---|---:|---|
| 1 | [01-domain-schema.md](./01-domain-schema.md) | 1–2 | 领域摘要 golden、预算边界、000018 七表、真实 PostgreSQL 迁移/回滚保护通过 |
| 2 | [02-repository-policy-workflow.md](./02-repository-policy-workflow.md) | 3–5 | Snapshot/Grant/Kill Switch、Policy/Run、事件/Schedule/Manual 统一编排通过 |
| 3 | [03-gateway-api.md](./03-gateway-api.md) | 6–8 | Claim/Start/Heartbeat/Complete、并发预算、RBAC/OpenAPI/HTTP 安全合同通过 |
| 4 | [04-evidence-action-proposal.md](./04-evidence-action-proposal.md) | 9–11 | Catalog/窄 intent、append-only ActionProposal/Finding、Overreach/Drift/Mutation 与真实 E2E 通过 |
| 5 | [05-web-experience.md](./05-web-experience.md) | 12–13 | 主动策略 URL/主从详情、Preview、治理动作、MSW/组件/构建通过 |
| 6 | [06-investigation-policy-hub.md](./06-investigation-policy-hub.md) | 14–15 | 跨 Incident API、Policy Hub、低 AI 高保真页面、真实 Keycloak/Scope/axe/三断点通过 |
| 7 | [07-e2e-operations-docs.md](./07-e2e-operations-docs.md) | 16–18 | 全生命周期、六指标、真实操作旅程、ADR/设计/Runbook 与独立全量 Gate 通过 |

执行规则：

1. 必须从第 1 包开始；后一包只消费前一包明确的 Produces 接口。
2. 每个 Task 先写失败测试并保存预期失败，再实现、验证、提交；不能把失败测试和实现合并成不可审查的大提交。
3. 数据库状态机、Gateway lock order、ActionProposal Catalog/Decoder/Handoff、OpenAPI、生成类型、OIDC 和前端 Scope 必须由当前执行者统一复核。
4. 生产路径不得使用 fake、MSW 或内存 Repository；测试替身只能存在于 `*_test.go`、`test/e2e`、`web/src/test` 或 `web/e2e`。
5. 最后一包全绿不会自动打开 Admission；生产启用仍需要独立授权、真实凭据吊销证明、监控/告警、演练和回滚批准。

## 阶段生产路径

| 入口 | 真实路径 | 本阶段结果 |
|---|---|---|
| Incident | `incident.created.v1` Outbox → PolicyMatcher → RequestRun → Temporal → Snapshot/Grant → Investigation | READ Evidence + `PROPOSAL_ONLY` ActionProposal 或 Human Review Finding |
| Schedule | Temporal Schedule → deterministic occurrence → RequestRun → 同一 PrepareRun | 每次发生新的 Snapshot/Grant；不复用发布时 RunID |
| Manual | OIDC + DIAGNOSTIC_RUN → RequestRun → 同一 TriggerStarter | 同 Scope/Service 的受治理只读调查 |
| SHADOW | Policy → Snapshot/Grant → 立即终结审计记录 | 不创建 Investigation/Task，不访问目标，不生成 ActionProposal |
| ActionProposal | Evidence → 服务端 Catalog → 窄模型 Decoder → 事务重验证 → append-only row/Finding | 无 requester/approval/queue/credential/window/verification/compensation；无执行权 |
| Governance UI | 真实 Keycloak → URL Scope → Control Plane API → `effective_actions` | `/investigations` 与 `/governance/policies` 安全只读工作区 |
| Phase 7 Handoff（Program 后续） | 经认证的人通过完整 T/W/E/S create path 发起 → Phase 7 无 Proposal 预读地开启封存事务 → 用 Principal + URL Scope + Proposal ID/expected digest 构造 HandoffRequest → Handoff Loader 在同一事务按 full Scope 锁定并重载 ActionProposal/Catalog/Evidence/Snapshot → 从库重算并恒时比较 digest/复验当前门禁 → 派生并封存新 ActionPlan → 原子提交 | Phase 4 无创建 ActionPlan API；ActionProposal 不能直接/自动转换，也不能作为执行授权；漂移时整笔回滚并升级人工 |
| WRITE（Program 后续） | sealed ActionPlan → ActionEnvelope → Policy → Approval → Credential → WRITE Runner | 不属于本阶段，不能由 Grant、ActionProposal 或前端绕过 |

## 跨包不变量

- 只有 `ACTIVE + EXACT + PUBLISHED + AVAILABLE` 可进入新 Snapshot 或 proposal-safe Catalog。
- 活动调查固定旧 Snapshot/Target/Capability/Runtime；安全撤销、资产隔离、身份/Realm 漂移和实时 Kill Switch 立即覆盖。
- Gateway 在 Claim、Start、Heartbeat、Complete 的同一认证事务复验，预算由 PostgreSQL 事实派生。
- SHADOW 不访问目标；READ_ONLY 不执行写；ActionProposal 恒为 `PROPOSAL_ONLY`。
- 模型只可从服务端给定 Catalog 选择 `action_type` 与极窄 typed intent；Scope、目标绑定与 Actor attribution 由服务端补齐。
- 无匹配、不确定、越权、Catalog/Evidence/Asset 漂移只记录 Human Review Finding；Phase 4 不能猜测、排队或直接/自动创建 ActionPlan。
- ActionProposal 是 Phase 7 可重载的不可信建议来源，而不是授权来源：只有经认证的人通过 `/workspaces/{workspace_id}/environments/{environment_id}/services/{service_id}/action-plans` 明确发起，Phase 7 才能从认证 Tenant + URL Workspace/Environment/Service 构造 full Scope，且不得先读 Proposal。服务端开启封存事务后在该同一事务中通过 Handoff Loader 锁定、重新加载可信 ActionProposal、Catalog、Evidence 与 Snapshot，从库重算/恒时比较摘要并复验当前门禁，再派生并封存一个全新的 ActionPlan；任一漂移使整笔事务回滚并进入人工复核。
- 浏览器只访问 Control Plane API，不访问 Runner/Temporal，不接收 endpoint、DSN、Secret、SQL、任意运行时覆盖或原始模型响应。
- 前端按 `effective_actions` 行动，不按角色名猜权限；所有治理状态以服务端确认为准。
- 前端固定 Keycloak Server `26.6.3`、浏览器 `keycloak-js 26.2.4`、pnpm `10.34.0`、`lucide-react 1.24.0`。
- 生产 READ 是中间门槛；Program 结束条件是固定类型化受治理写闭环及其验证/审计，不是只读页面或 Demo。

## Phase Produces

- Snapshot/Grant/Budget/Kill Switch/Policy/Run 领域与 PostgreSQL Repository。
- 唯一 `000018_investigation_grants_proactive_policies` 七表迁移：`asset_snapshots`、`asset_snapshot_items`、`investigation_grants`、`kill_switch_revisions`、`proactive_policy_revisions`、`proactive_runs`、`action_proposals`。
- 事件、Schedule、Manual、SHADOW 的确定性 Temporal 编排与 Outbox 消费。
- READ Gateway Claim→Start→Heartbeat→Complete 当前授权、预算、Runtime、Realm 与 Kill Switch 原子复验。
- 服务端 ActionProposal Catalog、四种窄 typed intent、append-only ActionProposal/Human Review Finding、只读公共 API，以及供 Phase 7 在其封存事务中调用的 `HandoffLoader.LoadTrustedForActionPlanDerivation(context.Context, pgx.Tx, HandoffRequest)` 内部接口。
- `/proactive-policies`、`/investigations`、`/governance/policies` 页面与唯一生成 API 类型。
- 六个低基数指标、原子安全审计、真实 PostgreSQL/Keycloak/浏览器 E2E、ADR、V4、前端设计与 Runbook。

## 文件责任图

- `internal/investigationgrant/` 与 `internal/investigationgrant/postgres/`：Snapshot、Grant、Budget、Gate、Kill Switch 与持久化。
- `internal/proactivepolicy/`、`internal/proactivepolicy/postgres/`、`internal/proactiveworkflow/`：策略、运行与 Temporal 编排。
- `internal/actionproposal/` 与 `internal/actionproposal/postgres/`：Catalog、严格模型边界、typed intent、ActionProposal/Finding、Handoff 与 append-only Repository。
- `internal/investigationview/`、`internal/governanceview/`：跨 Incident 和 Policy Hub 安全 read model。
- `internal/httpapi/`、`internal/authn/`、`internal/authz/`、`api/openapi/control-plane-v1.yaml`：Scope、权限、最近认证、公共 API 与唯一生成类型。
- `web/src/features/proactive-policies/`、`web/src/features/investigations/`、`web/src/features/policy-hub/`：低 AI 感高保真工作区。
- `test/e2e/`、`web/e2e/`：ActionProposal/Handoff 安全、真实 OIDC、Scope、权限、三断点、视觉和 axe 验收。
- `docs/adr/0004-investigation-grants-and-live-kill-switches.md`、`docs/design/frontend/`、`docs/operations/`、`docs/status/current.md`、`docs/architecture/implementation-blueprint-v4.md`：决策、设计、运行和完成事实。

## Exit Gate

- [ ] Tasks 1→18 按顺序各自完成红灯、最小实现、绿灯、指定 commit，无跳包或弱化测试。
- [ ] 000018 恰好七表；跨 Scope FK、append-only、状态机、guarded down、Mutation/Drift 全部由 PostgreSQL 18.4+ 证明。
- [ ] Event/Schedule/Manual/SHADOW、Grant 四边界、预算/Kill Switch、Evidence→ActionProposal/Finding 真实生命周期全绿且重放不分叉。
- [ ] 模型越权、未知字段、无匹配、不确定和 Catalog/Evidence/Asset 漂移均为零 ActionProposal/一 Human Review Finding；Phase 4 生成路径无 ActionPlan/Approval/queue/credential/execution 副作用，且 OpenAPI 不存在创建 ActionPlan 的 Phase 4 mutation。
- [ ] Phase 7 Handoff 合同已锁定为“经认证的人通过完整 T/W/E/S create path 发起 → Phase 7 无 Proposal 预读地开启封存事务 → 用 Principal + URL Scope + Proposal ID/expected digest 构造 HandoffRequest → Handoff Loader 在同一事务按认证 full Scope 锁定并重载可信 ActionProposal/Catalog/Evidence/Snapshot → 从库重算并恒时比较 digest、复验当前门禁 → 从可信来源派生并封存新 ActionPlan → 原子提交”；客户端 body 提交的 Scope、Evidence、Catalog 或 Plan 内容不得成为事实源，任一漂移必须整笔回滚并升级人工。
- [ ] OpenAPI、Go HTTP、唯一 TypeScript schema、组件合同和生产装配无 drift、fake 或 typed-nil 降级。
- [ ] 真实 Keycloak Server 26.6.3 + keycloak-js 26.2.4 验证 login-required、PKCE、内存 Token、URL Scope、跨 Scope 安全 403/404 和 `effective_actions`。
- [ ] 1440/1024/390 的主动策略、Investigation、Policy Hub 通过键盘、WCAG 2.2 AA、axe、视觉、安全 canary；页面无聊天/AI Avatar/霓虹/渐变/玻璃/Bento。
- [ ] ADR、V4、两份前端设计、主动调查/ActionProposal Runbook、状态页和证据引用完成；链接、围栏、格式、占位标记、secret scan 全绿。
- [ ] `docs/status/current.md` 仅写“实现已验收、READ Admission CLOSED、WRITE CLOSED、尚未生产启用”；不得描述为完整生产闭环。

任一 Gate 失败，停在最后已验收 commit，记录稳定失败码、trace/证据摘要和 Owner，升级人工；不得通过删测试、开放开关、使用 fake 或口头确认制造绿灯。
