# Project Agent Instructions

所有回复使用中文表达。如需展示代码、命令或文件路径，保持其原始格式并用中文说明。

## 开始工作前的必读顺序

1. `docs/status/current.md`：唯一当前完成度事实源。
2. `docs/superpowers/specs/2026-07-13-operational-assets-controlled-access-design.md`：已确认产品、安全和前端设计规范。
3. `docs/superpowers/plans/2026-07-13-governed-operations-program.md`：八阶段生产闭环总计划。
4. `docs/superpowers/plans/2026-07-13-governed-operations/README.md` 与 `coverage-matrix.md`。
5. `docs/superpowers/plans/2026-07-13-governed-operations/version-baseline.md`。
6. 当前阶段 `README.md` 和正在执行的小任务包。
7. 与改动相关的 `docs/adr/`、`docs/design/frontend/`、`docs/operations/` 与 `api/openapi/control-plane-v1.yaml`；文件尚未产生时按任务包创建，不得另造平行事实源。

若规范、总计划、阶段接口或已验收 ADR 相互冲突，停止实现，先修正文档契约并取得复核，不能自行选择较宽松解释。

## 核心系统边界

AI 是受治理的可信执行者：只有在明确身份、授权范围、策略门槛、不可变计划、短期凭据、执行验证和完整审计约束下，才可自主执行已批准的运维动作；超出授权范围、发生漂移或结果不确定时必须停止并升级人工。

- 模型永远不是身份或授权主体，也不属于可信计算基。
- 只有 `ACTIVE + EXACT + PUBLISHED + AVAILABLE` 的资产能力可进入真实运行。
- Source 枚举值不等于 Provider 已受支持；除 `MANUAL` 外，每种 Source 必须具备不可变修订、真实 Adapter 验证、Opaque Credential Reference、持久 cursor/checkpoint、lease/fence、rate limit、字段 provenance、soft-stale/restore 和真实 E2E，缺一项即保持 `UNAVAILABLE`。
- 浏览器、模型、Task 和 Runner payload 不得携带 Secret、私钥、原始凭据、任意 endpoint/header/body、命令、脚本或 SQL。
- 禁止通用 shell、交互 SSH/WinRM、PTY、端口转发、SFTP、任意 SQL、通用 HTTP payload、可观测性 ingestion 和通用写代理。
- 告警、事件和已批准定时策略只可自动触发短期只读调查；写操作必须走不可变 ActionPlan、策略、重新认证、人工审批、短期 WRITE 凭据、类型化执行、独立验证、对账/安全回滚/人工升级和审计。
- 调查只能产出 append-only `PROPOSAL_ONLY` ActionProposal 或 Human Review Finding；Proposal 永无审批、排队、凭据或执行权。ActionPlan 创建只能由经认证的人通过完整 T/W/E/S path 发起；Phase 7 必须在同一 serializable PostgreSQL transaction 内调用 Phase 4 Handoff Loader 重载并验证 Proposal/Catalog/Evidence/Snapshot/intent 摘要、解析其余可信事实并 `CreateInTx` 封存；Loader 前不得预读 Proposal，任一漂移整笔回滚。
- 生产 admission 必须同时验证 Phase 6 immutable READ baseline/handoff 与 Phase 7 content-addressed Action platform successor；合法 WRITE 增量不得改写 READ 基线，未登记 WRITE surface 或任一双修订漂移立即关闭 READ/WRITE admission。
- 测试 fake、memory repository、MSW 和 loopback transport 只能存在于测试路径；生产装配缺依赖必须 fail closed。

## 实施方式

- 使用 `superpowers:subagent-driven-development`（推荐）或 `superpowers:executing-plans`，严格按任务包 checkbox 顺序执行。
- 在模块根目录不包含嵌套 `.worktrees` 的隔离 worktree 中工作；不得删除或修改用户已有 worktree 来制造绿灯。
- 每个 Task 先运行失败测试，再最小实现，再运行指定验证并按任务包提交；不得跳过失败、弱化测试或用 fake 替代生产依赖。
- 一次只推进一个已满足入口门的阶段；后续阶段不得读取未验收的内部实现，只消费前序 `Produces` 接口。
- 任何 Provider、Capability 或 Action 都按类型单独门禁；未通过的保持 `UNAVAILABLE`。
- 业务代码、迁移、OpenAPI、生成类型、前端、运维、审计、安全和 E2E 必须在同一纵向切片内完成。

## 唯一契约与版本

- 数据库迁移所有权固定：`000015` Assets、`000016` Connections/Runtime、`000017` VictoriaMetrics、`000018` Grants/Policies、`000019` Host/PostgreSQL、`000020` Production Platform、`000021` Governed Actions、`000022` Release Governance。
- 公共 API 唯一源：`api/openapi/control-plane-v1.yaml`。
- 前端唯一工程：`web/`；唯一生成类型：`web/src/shared/api/schema.d.ts`，不得手工编辑或创建重复 DTO。
- Credential Reference 与 Runner Realm 页面只展示 Opaque/safe metadata 和服务端 `effective_actions`；不得成为读取 Secret、端点、Vault 路径、PEM、DSN、Token、任意 capability binding 或扩权的入口。
- 依赖与平台基线以 `version-baseline.md` 为唯一规划版本源；前端锁定 Node 24、pnpm 10.34.0、React 19.2.7、TypeScript 7.0.2，OIDC 使用 Keycloak Server 26.6.3 + keycloak-js 26.2.4、Authorization Code + PKCE、`login-required`、内存 Token与请求前刷新。
- 权限只使用 API `effective_actions`；前端不得按角色名推断。
- 新任务包小于 900 行，阶段/根索引小于 350 行；需要增长时按稳定接口或生产门拆分。

## 完成与持久化

- 规划完成不等于业务实现或生产上线。
- 每阶段验收后更新 `docs/status/current.md`、受影响 ADR、V4 架构、前端规范、OpenAPI、Runbook 和证据引用。
- 只有独立签名的 `PRODUCTION_CLOSED_LOOP_ACCEPTED` release decision 才能将系统描述为完整生产闭环。
- 每次交付前运行任务包要求的 Go/PostgreSQL/OpenAPI/Web/E2E/安全/恢复命令，并至少执行 `git diff --check`、链接、代码围栏、占位标记、生成类型漂移和 secret scan。
