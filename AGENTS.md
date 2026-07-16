# Project Agent Instructions

所有回复使用中文表达。如需展示代码、命令或文件路径，保持其原始格式并用中文说明。

## 开始工作前的必读顺序

1. `docs/status/current.md`：唯一当前完成度事实源。
2. `docs/superpowers/specs/2026-07-13-operational-assets-controlled-access-design.md`：已确认产品、安全和前端设计规范。
3. `docs/superpowers/plans/2026-07-13-governed-operations-program.md`：八阶段生产闭环总计划。
4. `docs/superpowers/plans/2026-07-15-fast-development-validation-program.md`：快速构建、分层验证、并发与真实资格测试策略。
5. `docs/superpowers/plans/2026-07-13-governed-operations/README.md` 与 `coverage-matrix.md`。
6. `docs/superpowers/plans/2026-07-13-governed-operations/version-baseline.md`。
7. 当前阶段 `README.md` 和正在执行的小任务包。
8. 与改动相关的 `docs/adr/`、`docs/design/frontend/`、`docs/operations/` 与 `api/openapi/control-plane-v1.yaml`；文件尚未产生时按任务包创建，不得另造平行事实源。

若规范、总计划、阶段接口或已验收 ADR 相互冲突，停止实现，先修正文档契约并取得复核，不能自行选择较宽松解释。

## AI Agent 活代码地图

- [代码地图治理规范](docs/architecture/agent-code-map.md)定义权威契约与派生结构图的边界；代码地图不能替代 `docs/status/current.md`、规范、ADR、OpenAPI、迁移、任务包或验收证据，也不能证明能力已经实现或生产可用。
- 每个实现 Batch 在自己实际工作的隔离 worktree 根使用 `scripts/code-map.sh`。Batch 开始先运行仅供观察的 `status`，随后运行增量 `refresh`；不能用只比较 HEAD 的 status 证明脏工作区新鲜。以 `modules`/`processes`、`query` 和 `context` 理解入口，纯文档或无代码影响的修订可以记录人工影响分析而不重复重建地图。
- 修改入口、公共接口、Repository、Worker/Runner、生产装配或共享前端 primitive 前运行 `impact`；Batch 结束运行 `changes all`、必要的 `refresh` 和交付前 `verify`。同一 Batch 内的每个小 checkbox 不重复刷新或复核完整地图。
- `.gitnexus/` 是每个 worktree 独立的未跟踪派生缓存，禁止提交、复制或跨 worktree 共享；合并、rebase、cherry-pick、切换 HEAD 或存在未映射代码 diff 后必须重建。
- 代码地图工具不得生成或修改 `AGENTS.md`、规范、ADR、OpenAPI 或状态文档，不得索引 Secret、凭据、构建产物、依赖缓存、symlink 或其他非普通文件；`.gitnexus/` 与 operation lock 本身也禁止 symlink。同一 worktree 的全部地图命令必须先由 Linux `flock` 或 macOS `lockf` 做进程级串行，再进入内层 owner/nonce 锁。确定性结构图可进入 CI 门禁；Graphify/LLM 语义图只可辅助理解，不能作为 merge/release 真值。
- 地图刷新、解析或新鲜度验证失败时，跨模块、公共契约、生产装配和安全边界改动必须 fail closed；先修复地图或完成可审计的人工影响分析，不能继续使用旧索引。

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

- 使用 `superpowers:subagent-driven-development`（推荐）或 `superpowers:executing-plans`；实施节奏、Batch 边界和验证频率以[快速开发与真实验收计划](docs/superpowers/plans/2026-07-15-fast-development-validation-program.md)为准。
- 在模块根目录不包含嵌套 `.worktrees` 的隔离 worktree 中工作；不得删除或修改用户已有 worktree 来制造绿灯。
- 任务包 checkbox 是范围、接口和最终证据清单，不再是快速构建期必须逐项提交的通用顺序。C0 安全/公共契约和缺陷修复保留定向 RED；C1/C2 允许实现与关键行为测试同一 Batch 完成，不伪造历史 RED。
- 一个 Batch 聚合 2–4 个相关旧 Task，按 G1 快速门和 G2 批次门验收后合并；全仓 race、真实 Provider、HA、恢复、安全、浏览器和发布矩阵按 G3/G4 集中执行。
- 最多三个文件所有权不重叠的实现会话并行；后继工作只消费已合并的稳定 `Produces` 接口，不读取其他会话未提交的内部实现。迁移、OpenAPI/生成类型和 `docs/status/current.md` 同时只有一个 owner。
- 任何 Provider、Capability 或 Action 都按类型单独门禁；未通过的保持 `UNAVAILABLE`。
- 快速构建允许关闭态代码跨原阶段推进；业务代码、迁移、OpenAPI、生成类型、前端和生产装配仍须在对应纵向 Milestone 内闭合。未执行 G4 真实资格测试前只能记录 `BUILT_CLOSED`/`SYSTEM_CODE_COMPLETE_CLOSED`，不能记录可用或上线。

## 唯一契约与版本

- 数据库迁移所有权固定：`000015` Assets、`000016` Connections/Runtime、`000017` VictoriaMetrics、`000018` Grants/Policies、`000019` Host/PostgreSQL、`000020` Production Platform、`000021` Governed Actions、`000022` Release Governance。
- 公共 API 唯一源：`api/openapi/control-plane-v1.yaml`。
- 前端唯一工程：`web/`；唯一生成类型：`web/src/shared/api/schema.d.ts`，不得手工编辑或创建重复 DTO。
- Credential Reference 与 Runner Realm 页面只展示 Opaque/safe metadata 和服务端 `effective_actions`；不得成为读取 Secret、端点、Vault 路径、PEM、DSN、Token、任意 capability binding 或扩权的入口。
- 依赖与平台基线以 `version-baseline.md` 为唯一规划版本源；前端锁定 Node 24、pnpm 10.34.0、React 19.2.7、TypeScript 5.9.3，OIDC 使用 Keycloak Server 26.6.3 + keycloak-js 26.2.4、Authorization Code + PKCE、`login-required`、内存 Token与请求前刷新；Agent 代码地图固定 GitNexus 1.6.9，禁止浮动 `latest`。
- 权限只使用 API `effective_actions`；前端不得按角色名推断。
- 新任务包小于 900 行，阶段/根索引小于 350 行；需要增长时按稳定接口或生产门拆分。

## 完成与持久化

- 规划完成不等于业务实现或生产上线。
- 每个 Batch/G2、Milestone/G3 和资格门/G4 后更新 `docs/status/current.md` 及受影响的 ADR、V4 架构、前端规范、OpenAPI、Runbook 和证据引用。
- 只有独立签名的 `PRODUCTION_CLOSED_LOOP_ACCEPTED` release decision 才能将系统描述为完整生产闭环。
- 每次实现 PR 运行 G1 和受影响测试；每个 Batch 运行 G2；每个纵向 Milestone 运行 G3；系统代码完成后执行 G4 真实资格矩阵。任务包中的重型命令仍是最终证据要求，但不再在每个小 Task 后无差别重复。
