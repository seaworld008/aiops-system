# 当前项目状态

> 更新时间：2026-07-13
> 状态：`SPEC_APPROVED / IMPLEMENTATION_IN_PROGRESS`
> 实施分支：`codex/governed-operations-assets`；已验收范围以本文“当前实施进度”和任务包 checkbox 为准

## 当前结论

可运维资产、受控连接、事件/定时只读调查、受治理生产动作和生产发布运维的设计规范已经确认；八阶段实施计划已经拆成阶段索引和小任务包。新规划以完整生产闭环为终点，不以 Demo、静态页面或生产只读试点为终点。

阶段衔接固定采用不可变 Phase 6 READ baseline/handoff 加独立内容寻址的 Phase 7 Action platform successor；计划、授权、执行、验证和 Phase 8 release 都绑定同一双修订闭包。合法注册的 WRITE 增量不会篡改 READ 基线，任何未登记 WRITE surface 或闭包漂移都会关闭 admission。

调查端仅能追加 `PROPOSAL_ONLY` ActionProposal/Human Review Finding。ActionPlan 创建已锁定为经认证的人从完整 T/W/E/S URL Scope 发起，并在同一 serializable PostgreSQL transaction 内完成 Handoff Loader 可信重载、摘要/资格复验、其余事实解析和 `CreateInTx` 封存；Loader 前不得预读 Proposal，浏览器或模型提交的 Scope/授权事实不能成为真值源。

Phase 1 Task 1 的 `000015_assets_catalog` PostgreSQL 基础已经在隔离实施分支通过验收；它不等于 Phase 1 已完成，更不等于生产部署。Task 2 领域/Repository、后续 Source、API、OpenAPI、前端与真实 Provider E2E 均未实现，因此不能宣称资产控制平面、VictoriaMetrics 全家桶、主机/PostgreSQL 诊断、主动调查、受治理写操作或新前端已经上线。

## 当前实施进度

Phase 1 Task 1 已完成 Red → Green → 独立安全复核，范围严格限于生产资产目录的数据库基础：

- `000015` 只拥有九张 Asset Catalog 表，包含完整 Scope FK、不可变历史、Source Revision/Run/lease/fence/checkpoint、Observation/Relationship freshness domain、receipt/terminal closure、受保护 down 和生产 schema admission manifest。
- schema admission 固定受审 PostgreSQL 18.4 catalog 摘要；所有 32 个 owned function 固定 `search_path=pg_catalog, public`。
- 真实 PostgreSQL 18.4 TLS 普通、race、在线兼容、双实例 dump/restore、恢复后 admission 与零 Skip 门均通过；full migration runner 和 Asset harness 只接受项目专用 `aiops_test` 控制库命名族，在其中创建 128 位随机物理数据库，并只清理已确认创建的数据库，不破坏共享 `public`。
- `make test-integration` 六个 PostgreSQL 包和 `go test ./... -count=1` 全绿；独立安全与 Task 1 验收审计均无未关闭 P1/P2/P3。

Task 1 只建立后续实现所需的数据库安全底座。没有任何真实 Source Adapter、Catalog Repository/API、浏览器入口、Credential 获取或生产执行能力因此变为可用；Phase 1 继续保持 `IN_PROGRESS`，所有未逐类型验收的 Provider/Capability 继续 `UNAVAILABLE`。

## 已存在的代码事实

- Go 模块、Control Plane、Worker、READ/WRITE Runner、Executor 及调查/执行基础包已经存在。
- 生产基线迁移仍到 `000014_read_evidence_clock_skew`；隔离实施分支已验收 `000015_assets_catalog` Task 1 数据库基础，尚未部署。
- 现有架构包含 OIDC、策略、Action/Execution、credential revocation、mTLS Runner Gateway、调查 Runtime/Target/Connector/Evidence 和 Temporal 编排基础。
- `000008` 的生产 WRITE 关闭约束仍是安全基线；在 Phase 7 的逐 Action 门禁正式验收前不得移除。
- `docs/architecture/implementation-blueprint-v3.md` 仍描述现有实现；V4 将在纵向实施过程中创建并最终成为新架构入口。

## 已完成的规划事实

- 已确认规范：[可运维资产、受控连接与受治理生产闭环设计](../superpowers/specs/2026-07-13-operational-assets-controlled-access-design.md)
- 总实施计划：[Governed Operations Program](../superpowers/plans/2026-07-13-governed-operations-program.md)
- 小文档入口：[Governed Operations Production Program](../superpowers/plans/2026-07-13-governed-operations/README.md)
- 覆盖追踪：[规范到实施计划覆盖矩阵](../superpowers/plans/2026-07-13-governed-operations/coverage-matrix.md)
- 版本基线：[生产规划版本基线](../superpowers/plans/2026-07-13-governed-operations/version-baseline.md)

实施阶段固定为：

1. Asset Catalog and Discovery Control Plane
2. Connection and Runtime Publication
3. VictoriaMetrics Ecosystem
4. Investigation Grants and Proactive Policies
5. Host and PostgreSQL Read Diagnostics
6. Production Platform and Read Path
7. Governed Production Actions
8. Production Rollout and Sustained Operations

当前可执行规划共拆分为 **59 个小任务包、189 个 TDD 实施任务**：

| 阶段 | 任务包 | 实施任务 |
|---|---:|---:|
| 1 Assets / Sources / Discovery | 11 | 35 |
| 2 Connections / Runtime | 8 | 21 |
| 3 VictoriaMetrics Ecosystem | 6 | 24 |
| 4 Grants / Proactive Policies | 7 | 18 |
| 5 Host / AWX / PostgreSQL | 8 | 21 |
| 6 Production Read Platform | 6 | 24 |
| 7 Governed Actions | 7 | 22 |
| 8 Production Rollout | 6 | 24 |

规划已给出 CSV/API、外部 CMDB、vSphere、Proxmox、OpenStack、AWS、Azure、GCP、Kubernetes Operator 和 AWX Inventory 的独立 Source 生产门；覆盖 VictoriaMetrics、VictoriaLogs、VictoriaTraces 与 Operator 21 类资源；同时规划了 Overview、Assets、Sources、Connections、Credential References、Runner Realms、Victoria、Investigations/Policies、Diagnostics、Platform Readiness、Incidents/Audit、Governed Actions 和 Production Release 的持久前端设计契约。每种 Provider、Capability 和 Action 在自己的真实协议、HA、安全与 E2E 证据未通过前都保持 `UNAVAILABLE/CLOSED`。

## 当前能力状态

| 能力 | 当前状态 | 说明 |
|---|---|---|
| 现有调查/执行内核 | 基线存在 | 以现有测试、迁移和 V3 文档为准 |
| 新资产目录与发现 | IN_PROGRESS | Task 1 数据库基础已验收；Task 2 起的领域、Repository、Source、API、前端与生产门仍未完成，运行能力保持 `UNAVAILABLE` |
| Connection 修订/验证/发布 | NOT_STARTED | 等待 Phase 2 |
| VictoriaMetrics/Logs/Traces 全家桶 | NOT_STARTED | 等待 Phase 3 |
| 事件/定时主动只读调查 | NOT_STARTED | 等待 Phase 4 |
| Host/AWX/PostgreSQL 只读诊断 | NOT_STARTED | 等待 Phase 5 |
| HA 生产只读路径 | NOT_STARTED | 等待 Phase 6 |
| 四类初始受治理生产 Action | CLOSED | 等待 Phase 7 逐类型演练与 Canary |
| 生产发布与持续运维 | NOT_STARTED | 等待 Phase 8 |
| 新 React 前端 | NOT_STARTED | Phase 1 建骨架，此后随各阶段纵向交付 |

## 已知基线注意事项

当前共享主目录下存在用户拥有的嵌套 `.worktrees`；不得删除或修改。Phase 1 Task 1 已在模块根目录不包含嵌套 `.worktrees` 的外部隔离 worktree 中执行，并在那里取得完整 Go/PostgreSQL/恢复基线。

实施分支新增 `000015` 与测试基础设施，但没有修改生产部署配置，也没有把该迁移描述为已在生产执行。

## 下一步

继续执行 Phase 1 Task 2，按 [Phase 1 索引](../superpowers/plans/2026-07-13-governed-operations/01-assets/README.md) 和 [当前任务包](../superpowers/plans/2026-07-13-governed-operations/01-assets/01-schema-domain.md) 的 checkbox 顺序实现稳定领域、验证、生命周期和下游接口。每个任务包必须完成红灯、最小实现、绿灯、指定提交与阶段验收；Phase 1 未验收前不进入 Phase 2。

任何阶段出现 Scope/身份/计划/Runtime/策略/Kill Switch/credential 漂移、依赖不可用、Secret 风险或结果不确定时，保持在最后已验收状态并停止升级，不得用人工口头确认替代持久证据。
